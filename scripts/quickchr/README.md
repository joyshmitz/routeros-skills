# quickchr helper scripts

Fork-local tooling for grounding `routeros-*` skill content against a real
RouterOS CHR instance via [`quickchr`](https://github.com/tikoci/quickchr).
Not part of the skill set (see repo root README's "Repository layout"
section) and not intended for upstream — these are operational helpers used
while developing/verifying this fork, not documentation content.

- `chr-enable-https.sh <instance-name> [common-name]` — enables `www-ssl`
  and `api-ssl` on a running quickchr CHR instance by generating a local
  self-signed CA + leaf certificate on the router. Idempotent; see the
  script's header comments for what was empirically verified on RouterOS
  7.23.3 and why (CA-then-leaf signing requirement, a `quickchr exec`
  exit-code gotcha, a sign-then-bind race condition).
