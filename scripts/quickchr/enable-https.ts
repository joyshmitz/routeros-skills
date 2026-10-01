#!/usr/bin/env bun
// Enable HTTPS (www-ssl) and api-ssl on a running MikroTik CHR instance
// managed by quickchr, by generating a local self-signed CA plus a
// CA-signed server certificate on the router itself.
//
// Talks to RouterOS's REST *resource* endpoints rather than driving CLI
// strings through `quickchr exec` (which posts to /rest/execute). That is
// deliberate: /rest/execute flattens RouterOS command failures into
// HTTP 200 with the error text in the `ret` string, while the resource
// endpoints return a real status plus a structured body. Grounded on
// RouterOS 7.23.3 (x86 CHR) — the identical failure, both ways:
//
//   POST /rest/execute {"script":"/ip/service/set www-ssl certificate=nope"}
//     -> 200 {"ret":"input does not match any value of certificate (...; line 1)"}
//   PATCH /rest/ip/service/*6 {"certificate":"nope"}
//     -> 400 {"detail":"input does not match any value of certificate",
//             "error":400,"message":"Bad Request"}
//
// Driving REST directly therefore removes the need to sniff error text,
// and it is the connection surface quickchr documents for external tools
// (`quickchr env` / `descriptor()`).
//
// Usage: bun scripts/quickchr/enable-https.ts <instance-name> [common-name]
//   instance-name   quickchr instance name (must already be running)
//   common-name     CN for the server certificate (default: chr.local)

const CA_NAME = "chr-ca";
const LEAF_NAME = "chr-cert";

/** A failure already described well enough to show the user as-is. */
class ScriptError extends Error {}

function fail(message: string): never {
	throw new ScriptError(message);
}

const [instance, commonNameArg] = process.argv.slice(2);
if (!instance) {
	console.error("usage: enable-https.ts <instance-name> [common-name]");
	process.exit(2);
}
const commonName = commonNameArg ?? "chr.local";

// ---------------------------------------------------------------- connection

// The connection surface comes from quickchr itself rather than hardcoded
// ports, so this keeps working when the port allocator picks a different
// block (concurrent instances start at 9100, 9110, 9120, ...).
async function readQuickchrEnv(name: string): Promise<Map<string, string>> {
	const proc = Bun.spawn(["bunx", "@tikoci/quickchr", "env", name], {
		stdout: "pipe",
		stderr: "pipe",
		env: { ...process.env, PATH: `${process.env.HOME}/.bun/bin:${process.env.PATH ?? ""}` },
	});
	// Both pipes are drained concurrently with the exit wait: reading one to
	// completion first can deadlock if the child fills the other pipe's buffer
	// and then blocks instead of exiting.
	const [stdout, stderr, code] = await Promise.all([
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
		proc.exited,
	]);
	if (code !== 0) {
		fail(
			`could not read quickchr env for '${name}' (is the instance running?)\n${(stderr.trim() || stdout.trim()).replace(/^/gm, "  ")}`,
		);
	}
	return new Map(
		stdout
			.split("\n")
			.map((line) => line.match(/^([A-Z_]+)=(.*)$/))
			.filter((m): m is RegExpMatchArray => m !== null)
			.map((m) => [m[1], m[2]]),
	);
}

const envVars = await readQuickchrEnv(instance);
const base = envVars.get("QUICKCHR_REST_BASE");
const auth = envVars.get("QUICKCHR_AUTH");
if (!base || auth === undefined) {
	fail(`quickchr env for '${instance}' lacked QUICKCHR_REST_BASE / QUICKCHR_AUTH`);
}
const authHeader = `Basic ${Buffer.from(auth).toString("base64")}`;

// ---------------------------------------------------------------- REST layer

type RestResult = {
	ok: boolean;
	/** HTTP status, or 0 when the request never produced a response. */
	status: number;
	body: unknown;
	/** Set when fetch itself threw (timeout, refused, reset). */
	transportError?: string;
};

async function rest(
	method: string,
	path: string,
	body?: unknown,
	timeoutMs = 15_000,
): Promise<RestResult> {
	let res: Response;
	try {
		res = await fetch(`${base}${path}`, {
			method,
			headers: {
				Authorization: authHeader,
				...(body === undefined ? {} : { "Content-Type": "application/json" }),
			},
			// Values travel as JSON fields, so RouterOS never parses them as
			// command syntax — unlike the CLI-string approach, where a `;` in a
			// common-name would act as a command separator.
			body: body === undefined ? undefined : JSON.stringify(body),
			signal: AbortSignal.timeout(timeoutMs),
		});
	} catch (err) {
		// A timeout or connection failure would otherwise escape as a bare
		// stack trace with no indication of which call was in flight.
		const reason =
			err instanceof Error && err.name === "TimeoutError"
				? `timed out after ${timeoutMs}ms`
				: err instanceof Error
					? err.message
					: String(err);
		return { ok: false, status: 0, body: undefined, transportError: reason };
	}
	// 204 (DELETE) and any empty body must not go through .json().
	const text = await res.text();
	let parsed: unknown = text;
	if (text.length > 0) {
		try {
			parsed = JSON.parse(text);
		} catch {
			/* leave as raw text; surfaced verbatim on error */
		}
	}
	return { ok: res.ok, status: res.status, body: parsed };
}

function describe(r: RestResult): string {
	if (r.transportError) return `request failed — ${r.transportError}`;
	const b = r.body;
	const detail =
		b && typeof b === "object"
			? ((b as Record<string, unknown>).detail ?? (b as Record<string, unknown>).message)
			: undefined;
	return `HTTP ${r.status} — ${detail ?? JSON.stringify(r.body)}`;
}

async function must(
	method: string,
	path: string,
	body?: unknown,
	timeoutMs?: number,
): Promise<unknown> {
	const r = await rest(method, path, body, timeoutMs);
	if (!r.ok) fail(`${method} ${path} failed: ${describe(r)}`);
	return r.body;
}

/**
 * Reads a filtered collection that is expected to match at most one row.
 * A non-array response or multiple matches are treated as errors rather
 * than being silently reduced to "not found" / "the first one".
 */
async function findOne(path: string): Promise<Record<string, string> | undefined> {
	const rows = await must("GET", path);
	if (!Array.isArray(rows)) {
		fail(`GET ${path} returned ${typeof rows}, expected an array: ${JSON.stringify(rows)}`);
	}
	if (rows.length > 1) {
		fail(`GET ${path} matched ${rows.length} rows, expected at most one`);
	}
	return rows[0] as Record<string, string> | undefined;
}

// ------------------------------------------------------------- certificates

/**
 * Describes why an existing certificate cannot be reused, or undefined if
 * it is fit for purpose. Field semantics confirmed on 7.23.3: a signed
 * certificate carries a `fingerprint` (absent before signing) and
 * `private-key=true`; a signed CA additionally reports `authority=true`,
 * and a CA-signed leaf carries `ca=<issuer name>`.
 */
type CertCheck = (cert: Record<string, string>) => string | undefined;

const caIsUsable: CertCheck = (c) =>
	c.authority !== "true"
		? `it is not a certificate authority (authority=${c.authority})`
		: c["private-key"] !== "true"
			? "it has no private key, so it cannot sign"
			: undefined;

const leafIsUsable: CertCheck = (c) =>
	c["common-name"] !== commonName
		? `its common-name is '${c["common-name"]}', not '${commonName}'`
		: c.ca !== CA_NAME
			? `it was issued by '${c.ca || "(self/unknown)"}', not '${CA_NAME}'`
			: c["private-key"] !== "true"
				? "it has no private key, so it cannot terminate TLS"
				: undefined;

/**
 * Ensures a certificate exists, is signed, and actually matches what this
 * script would have created. A certificate object exists as soon as it is
 * created but is unusable until signed, so an interrupted previous run can
 * leave an unsigned object behind — that case is repaired by signing it.
 * A signed-but-mismatched certificate is reported instead of silently
 * reused, because the closing summary claims a specific CN and issuer.
 */
async function ensureCert(
	name: string,
	create: Record<string, string>,
	sign: Record<string, string>,
	isUsable: CertCheck,
): Promise<void> {
	const existing = await findOne(`/certificate?name=${encodeURIComponent(name)}`);
	if (existing?.fingerprint) {
		const problem = isUsable(existing);
		if (problem) {
			fail(
				`certificate '${name}' already exists and is signed, but ${problem}.\n` +
					`  Remove it on the router and re-run, e.g.:\n` +
					`    bunx @tikoci/quickchr exec ${instance} "/certificate/remove ${name}"`,
			);
		}
		console.log(`'${name}' already exists and is signed — skipping.`);
		return;
	}
	if (existing) {
		console.log(`'${name}' exists but is unsigned (interrupted previous run?) — signing it...`);
	} else {
		console.log(`Creating '${name}'...`);
		await must("PUT", "/certificate", { name, ...create });
	}
	// RSA-2048 signing on a 1-vCPU TCG guest is slow; give it room.
	await must("POST", "/certificate/sign", { ".id": name, ...sign }, 120_000);
}

// ----------------------------------------------------------------- services

/**
 * Binding a *just-signed* certificate can transiently fail with HTTP 400
 * ("input does not match any value of certificate"). Reproduced on 7.23.3
 * through both quickchr exec and direct REST (1 of 4 back-to-back REST
 * trials), so it is RouterOS behavior rather than an artifact of either
 * client path. Mechanism unconfirmed — plausibly settle time before the new
 * certificate becomes selectable as a property value.
 *
 * Only statuses that could plausibly be that transient condition are
 * retried. Authentication, authorization and not-found answers are final,
 * and retrying them would just delay the real message by 15 seconds.
 * Discriminating any harder would mean matching on error text, which is
 * exactly what using the resource endpoints set out to avoid.
 */
const RETRY_INTERVAL_MS = 1_500;
const MAX_BIND_ATTEMPTS = 10;

function isRetryable(r: RestResult): boolean {
	if (r.transportError) return true;
	return r.status === 400 || r.status >= 500;
}

async function bindCertificate(serviceName: string): Promise<void> {
	const svc = await findOne(
		`/ip/service?name=${encodeURIComponent(serviceName)}&.proplist=.id,name`,
	);
	const id = svc?.[".id"];
	if (!id) fail(`no /ip/service entry named '${serviceName}'`);

	// `disabled: "false"` is set explicitly rather than relying on the
	// service's default state: on 7.23.3 www-ssl ships disabled and api-ssl
	// ships enabled, but pinning both makes this independent of that
	// per-service, per-version default.
	const payload = { certificate: LEAF_NAME, disabled: "false" };

	let first: RestResult | undefined;
	for (let attempt = 1; attempt <= MAX_BIND_ATTEMPTS; attempt++) {
		const r = await rest("PATCH", `/ip/service/${id}`, payload);
		if (r.ok) {
			console.log(`${serviceName}: certificate=${LEAF_NAME}, enabled.`);
			return;
		}
		first ??= r;
		if (!isRetryable(r)) fail(`binding ${serviceName} failed: ${describe(r)}`);
		if (attempt === MAX_BIND_ATTEMPTS) {
			const firstNote =
				describe(first) === describe(r) ? "" : `\n  first attempt failed differently: ${describe(first)}`;
			fail(
				`binding ${serviceName} failed after ${MAX_BIND_ATTEMPTS} attempts: ${describe(r)}${firstNote}`,
			);
		}
		await Bun.sleep(RETRY_INTERVAL_MS);
	}
}

// --------------------------------------------------------------------- main

async function main(): Promise<void> {
	console.log(`== ${instance}: provisioning certificates ==`);

	await ensureCert(
		CA_NAME,
		{ "common-name": CA_NAME, "key-usage": "key-cert-sign,crl-sign" },
		{},
		caIsUsable,
	);
	await ensureCert(
		LEAF_NAME,
		{ "common-name": commonName, "key-usage": "tls-server" },
		{ ca: CA_NAME },
		leafIsUsable,
	);

	console.log("Binding certificate to www-ssl / api-ssl...");
	await bindCertificate("www-ssl");
	await bindCertificate("api-ssl");

	const services = (await must(
		"GET",
		"/ip/service?.proplist=name,port,disabled,certificate",
	)) as Record<string, string>[];
	console.log("\n== Result ==");
	for (const s of services.filter((s) => s.name === "www-ssl" || s.name === "api-ssl")) {
		console.log(
			`  ${s.name.padEnd(8)} port=${s.port} disabled=${s.disabled} certificate=${s.certificate}`,
		);
	}

	console.log(
		`\nDone. www-ssl and api-ssl now serve '${LEAF_NAME}' (CN=${commonName}), issued by the local CA '${CA_NAME}'.`,
	);
	console.log(
		"That CA is not in any client trust store, so browsers warn and curl needs -k — expected for a local dev certificate.",
	);
}

try {
	await main();
} catch (err) {
	if (err instanceof ScriptError) {
		console.error(`error: ${err.message}`);
		process.exit(1);
	}
	throw err;
}
