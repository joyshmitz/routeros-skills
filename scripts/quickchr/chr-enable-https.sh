#!/usr/bin/env bash
# Enable HTTPS (www-ssl) and api-ssl on a running MikroTik CHR instance
# managed by quickchr, by generating a local self-signed CA + leaf
# certificate on the router itself.
#
# Grounded against RouterOS 7.23.3 (x86 CHR) via `quickchr exec`, on three
# separate fresh CHR instances — not from memory:
#   - www-ssl ships DISABLED with certificate=none on a fresh CHR.
#   - api-ssl ships ENABLED (no X flag) with certificate=none — binding a
#     certificate alone (no explicit `/ip/service/enable api-ssl`) is
#     sufficient; confirmed via a raw TLS handshake (openssl s_client)
#     against api-ssl with no enable call made.
#   - `/certificate/sign <leaf>` without `ca=` fails with
#     "failure: CA not found" on 7.23.3 — a self-signed CA certificate
#     (key-usage=key-cert-sign,crl-sign) must be created and signed first,
#     then the leaf cert is signed with ca=<that CA name>.
#   - An unsigned certificate has an empty `fingerprint` property;
#     `fingerprint` becomes non-empty only after a successful `sign`.
#     Confirmed by direct before/after check on a fresh cert object.
#
# Usage: chr-enable-https.sh <instance-name> [common-name]
#   instance-name   quickchr instance name (must already be running)
#   common-name     CN for the leaf certificate (default: chr.local)
#                    restricted to [A-Za-z0-9._:*?-] — this value is
#                    interpolated into a RouterOS CLI command string sent
#                    over quickchr's REST /execute, where RouterOS itself
#                    (not just the shell) treats `;`, quotes, and spaces as
#                    syntax. There is no general RouterOS string-escaping
#                    function here, so arbitrary CNs are simply rejected.

set -euo pipefail

INSTANCE="${1:?Usage: chr-enable-https.sh <instance-name> [common-name]}"
COMMON_NAME="${2:-chr.local}"
CA_NAME="chr-ca"
LEAF_NAME="chr-cert"
QC="bunx @tikoci/quickchr"

if [[ ! "$COMMON_NAME" =~ ^[A-Za-z0-9._:*?-]+$ ]]; then
  printf 'error: invalid common name %q — only letters, digits, and . _ : * ? - are allowed\n' "$COMMON_NAME" >&2
  exit 2
fi

# IMPORTANT: `quickchr exec` returns exit code 0 even when RouterOS itself
# rejects the command — RouterOS's REST /execute returns HTTP 200 with the
# error text as the body (confirmed live: pointing `/ip/service/set
# www-ssl certificate=` at a nonexistent certificate name exits 0 while
# printing "input does not match any value of certificate (...; line 1)").
# `set -e`
# gives NO protection against this — it only catches quickchr's own
# transport-level failures (timeout, connection refused, auth). Every
# RouterOS error message we've observed ends with a "(<path>; line N)"
# suffix, which normal command output (tables, `:put` booleans) never
# contains, so that's used as the failure signature.
# Runs one command; on failure (transport OR RouterOS-level) leaves the
# raw output in $_RUN_OUT and returns 1 instead of exiting, so callers can
# choose to retry instead of aborting immediately.
_run_once() {
  local cmd="$1" timeout="${2:-30}"
  if ! _RUN_OUT=$($QC exec "$INSTANCE" "$cmd" --timeout "$timeout" 2>&1); then
    return 1
  fi
  grep -qE '\; line [0-9]+\)' <<<"$_RUN_OUT" && return 1
  return 0
}

run() {
  if ! _run_once "$1" "${2:-30}"; then
    echo "error: command failed: '$1'" >&2
    printf '%s\n' "$_RUN_OUT" >&2
    exit 1
  fi
  # NOTE: `[[ cond ]] && cmd` must never be the last statement in a
  # function under `set -e` — when cond is false, the function's own
  # return status becomes 1 (cmd never ran), and a bare call to this
  # function elsewhere in the script then aborts the whole script even
  # though nothing actually failed. Reproduced live: every `run` call
  # whose RouterOS command succeeded with empty output (add/sign/set/
  # enable all typically do) silently killed the script right after. The
  # explicit `return 0` is load-bearing, not decorative.
  if [[ -n "$_RUN_OUT" ]]; then
    printf '%s\n' "$_RUN_OUT"
  fi
  return 0
}

# `/ip/service/set ... certificate=<name>` can transiently fail with
# "input does not match any value of certificate" immediately after
# signing that certificate — reproduced live, repeatedly: the exact same
# command failed right after `/certificate/sign` returned "done", then
# succeeded on an unmodified retry. The window is not consistently short —
# in one run 5 retries at 1s each (~5s) still wasn't enough for the second
# of two back-to-back service bindings, while a manual retry a bit later
# succeeded immediately. RouterOS appears to need some settle time to
# index a freshly-signed cert as a valid value for this property; the
# retry count below is deliberately generous (~15s budget) rather than
# tuned to a measured minimum.
run_retry() {
  local cmd="$1" timeout="${2:-30}" attempt max=10
  for ((attempt = 1; attempt <= max; attempt++)); do
    if _run_once "$cmd" "$timeout"; then
      [[ -n "$_RUN_OUT" ]] && printf '%s\n' "$_RUN_OUT"
      return 0
    fi
    if ((attempt < max)); then
      sleep 1.5
    fi
  done
  echo "error: command failed after $max attempts: '$cmd'" >&2
  printf '%s\n' "$_RUN_OUT" >&2
  exit 1
}

# Queries a boolean RouterOS expression via quickchr exec. Distinguishes
# "true" / "false" from a transport/query failure (network, timeout, an
# unexpected response shape) instead of masking the latter as "false" —
# under `set -e`, a failing pipeline inside an `if cond; then` does NOT
# abort the script, so a swallowed transport error would silently fall
# through to "doesn't exist, let's create it".
query_bool() {
  local expr="$1" out
  if ! out=$($QC exec "$INSTANCE" ":put ($expr)" --timeout 20 2>&1); then
    echo "error: quickchr exec failed evaluating '$expr' on '$INSTANCE': $out" >&2
    exit 1
  fi
  case "$out" in
    *true*) return 0 ;;
    *false*) return 1 ;;
    *)
      echo "error: unexpected response evaluating '$expr' on '$INSTANCE': $out" >&2
      exit 1
      ;;
  esac
}

cert_exists() { query_bool "[:len [/certificate/find where name=\"$1\"]] > 0"; }
cert_signed() { query_bool "[:len [/certificate/get [find name=\"$1\"] fingerprint]] > 0"; }

# Ensures a certificate exists AND is signed, creating and/or signing only
# the missing piece. This specifically covers a run interrupted between
# `/certificate/add` and `/certificate/sign`: a plain existence-by-name
# check would see the leftover unsigned object and wrongly skip signing it
# forever. This does not validate that an existing signed cert has the
# expected CN/key-usage/CA — a mismatched-but-signed cert of the same name
# is treated as valid. Re-running with different arguments does not fix
# that; remove the stale certificate on the router first.
ensure_cert() {
  local name="$1" add_cmd="$2" sign_cmd="$3"
  if cert_exists "$name"; then
    if cert_signed "$name"; then
      echo "'$name' already exists and is signed — skipping."
      return
    fi
    echo "'$name' exists but is unsigned (interrupted previous run?) — signing it..."
  else
    echo "Creating '$name'..."
    run "$add_cmd"
  fi
  run "$sign_cmd" 60
}

echo "== $INSTANCE: checking existing certificates =="

ensure_cert "$CA_NAME" \
  "/certificate/add name=$CA_NAME common-name=$CA_NAME key-usage=key-cert-sign,crl-sign" \
  "/certificate/sign $CA_NAME"

ensure_cert "$LEAF_NAME" \
  "/certificate/add name=$LEAF_NAME common-name=$COMMON_NAME key-usage=tls-server" \
  "/certificate/sign $LEAF_NAME ca=$CA_NAME"

echo "Binding '$LEAF_NAME' to www-ssl / api-ssl and enabling www-ssl..."
run_retry "/ip/service/set www-ssl certificate=$LEAF_NAME"
run "/ip/service/enable www-ssl"
run_retry "/ip/service/set api-ssl certificate=$LEAF_NAME"
# api-ssl is NOT explicitly enabled here: confirmed on 7.23.3 CHR that it
# ships enabled by default (unlike www-ssl) and a TLS handshake succeeds
# purely from setting `certificate=` — see header note.

echo
echo "== Result =="
run "/ip/service/print where name~\"www-ssl|api-ssl\""

echo
echo "Done. www-ssl and api-ssl now serve a self-signed cert (CN=$COMMON_NAME, issuer=$CA_NAME)."
echo "Browsers/curl will warn about the untrusted CA — that's expected for a local dev cert (use -k with curl)."
