---
packages:
  github.com/minpeter/global-egress:
    type: patch
---

## Container health check without a shell

Add a `global-egress healthcheck` subcommand that probes the control API's
`/healthz` and reports the verdict as its exit status, plus a default Docker
`HEALTHCHECK` and a Compose `healthcheck` block that use it.

The image is distroless, so there is no `curl` or `wget` to probe from a shell
and the binary probes itself. The probe is bounded by `-timeout` (2s default) so
Docker never has to kill it, and reads a bearer token from `-token-file` when the
control API requires one, keeping the secret out of the image, the Compose file,
and `docker inspect`.
