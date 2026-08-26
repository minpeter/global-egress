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

The image keeps a tokenless default probe. The Compose service passes
`-token-file` and mounts `./control-token` read-only, because the container config
example sets `access.control_token_file` and a configured token is checked on
every control request including `GET /healthz`; an unauthenticated probe would
report a healthy container as unhealthy. The Compose command and the config
example are pinned to each other by tests so they cannot drift.

The control API now always permits loopback clients through
`access.allowed_clients`: the example ACL names only remote CIDRs, and without
the exemption the in-container probe would be refused with `403` before token
auth runs. Bearer-token auth still applies to loopback requests.
