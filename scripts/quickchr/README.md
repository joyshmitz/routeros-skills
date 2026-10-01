# quickchr helper scripts

Fork-local tooling for grounding `routeros-*` skill content against a real
RouterOS CHR instance via [`quickchr`](https://github.com/tikoci/quickchr).
Not part of the skill set (see the repo root README's "Repository layout"
section) and not intended for upstream — these are operational helpers used
while developing and verifying this fork, not documentation content.

## `enable-https.ts`

```sh
bun scripts/quickchr/enable-https.ts <instance-name> [common-name]
```

Provisions a local self-signed CA plus a CA-signed server certificate on a
running quickchr CHR instance, then binds that certificate to `www-ssl`
and `api-ssl` and enables both.

Re-running is safe. An existing certificate is reused only when it is
signed *and* matches what this script would have created — for the CA,
that it is a certificate authority holding a private key; for the server
certificate, that its common-name and issuing CA are the expected ones. A
signed certificate of the right name but the wrong shape is reported
rather than silently reused, since the closing summary asserts a specific
common-name and issuer. A run interrupted between creating and signing a
certificate is repaired by signing the leftover object.

It drives RouterOS's REST **resource** endpoints rather than sending CLI
strings through `quickchr exec`. That choice is load-bearing, and grounded
on RouterOS 7.23.3 — the same failure, both ways:

| Call | Result |
|---|---|
| `POST /rest/execute` with a bad `certificate=` | `200` + `{"ret":"input does not match any value of certificate (…; line 1)"}` |
| `PATCH /rest/ip/service/<id>` with a bad `certificate` | `400` + `{"detail":"input does not match any value of certificate",…}` |

`/rest/execute` flattens RouterOS command failures into a success status
with the error text in a string, so a caller can only sniff for it. The
resource endpoints preserve both the status and a structured body. Going
through them means errors surface on their own, and — because values
travel as JSON fields rather than being interpolated into a command
string — a common-name containing `;` is stored as literal certificate
data instead of parsing as a second RouterOS command.

Other behavior worth knowing, all verified live rather than assumed:

- A certificate object exists as soon as it is created but is unusable
  until signed; `fingerprint` is absent before signing and populated
  after, which is what makes re-runs safe.
- Signing the CA takes no `ca=`; signing the leaf requires `ca=<CA name>`
  or it fails with `failure: CA not found`.
- Binding a *just-signed* certificate can transiently return HTTP 400
  (`input does not match any value of certificate`) and succeed moments
  later — reproduced through both `quickchr exec` and direct REST, so it
  is RouterOS behavior rather than a client artifact. The script retries
  that step up to ten times at a fixed 1.5s interval, and only for
  statuses that could plausibly be transient — an auth or not-found answer
  fails immediately rather than after fifteen wasted seconds.
- On 7.23.3 `www-ssl` ships disabled and `api-ssl` ships enabled; the
  script sets `disabled=false` on both explicitly rather than depending on
  those per-service defaults.

The CA is local to the router and in no client trust store, so browsers
warn and `curl` needs `-k`. That is expected for a lab certificate.
