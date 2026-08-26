## github.com/minpeter/global-egress@0.0.4

### Stop recommending world-readable Docker secrets

Replace the `chmod 644` instruction in the Docker deploy guide with a least-privilege flow: uid 65532 ownership with mode `0600` on `proxy-password` and `control-token`, mode `0700` on the catalog directory, and `0600` on provider key files, plus an explanation of the host-ownership tradeoff.

### Clamp timeout-phase metrics to the closed set

`TimeoutPhase` is a string alias, so a caller can pass any value into
`ObserveRequest`. The scrape still has to emit only `acquire`, `upstream`, or
`unknown`: a free-form `phase` label would grow with whoever typed it.

The metrics boundary now switches on the closed set and records anything else
as `unknown`. Empty and omitted phases already landed there; out-of-set values
now do too. No new label was added.

## github.com/minpeter/global-egress@0.0.3

### Export the collector control token path

Pass `CONTROL_TOKEN_FILE` from the OpenRC confd into the metrics collector process so authenticated control scraping works after restart.

## github.com/minpeter/global-egress@0.0.2

### Fail closed for remote control mutations

Require bearer authentication for mutating control API requests received from
non-loopback clients, while preserving the existing read-only endpoint policy.

### Container health check without a shell

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

### Require Go 1.25.13

Raise the minimum Go toolchain to 1.25.13, which includes fixes for the reachable
standard-library and `golang.org/x/net` vulnerabilities reported by govulncheck.

### Date every exit-IP measurement, and separate slot count from measured IPs

The README, `docs/operations.md` and `docs/capacity.md` each quoted a different
"definitive" unique-IP total (456, 524, 529) for the same 532-slot bundle, with no
date, mode or device attached. They now share one measurement log in
`docs/capacity.md`, where every row carries its date, mode, bundle and run
parameters, and the surviving claim is "one measured address per reachable exit,
zero duplicates" rather than any single total.

Documents also stop standing in for the running service: slot count is a catalogue
property, while `slots_with_known_ip` and `unique_public_ips` in `/v1/stats` (plus
`/v1/ips`) are the current measured state that `uniq=` batches draw on.

### Split request timeouts by phase, and expose entry rotation health

`global_egress_request_results_total{result="timeout"}` collapsed two unrelated
faults into one number. A timeout before the upstream was ready means pool
capacity or handshake latency; a timeout after it was established means the exit
or the destination. Both arrive as `context.DeadlineExceeded`, so the single
result label could not tell an operator which half to look at.

`/v1/metrics` now also carries `global_egress_request_timeouts_total`, labelled
with a closed `phase` enum (`acquire`, `upstream`, `unknown`) alongside the
existing bounded `country` and `entry` dimensions. The SOCKS5 and HTTP listeners
report the phase from the classifier that already decided the result, so no new
error handling was introduced.

Entries were the other blind spot: they are the scarce resource — each one costs
a key association — but nothing on the scrape said how many were up, spare, or
benched. `global_egress_entry_state{state="open"|"idle"|"disabled"}` reports the
rotation breakdown, always emitting all three series so a state never vanishes
from a scrape, and `global_egress_entry_failures_total{reason="open"|"dial"}`
separates an entry that will not come up from one whose tunnel is up but no
longer carrying traffic.

Every new label is a fixed enum or an existing bounded dimension. No target,
address, session or entry-identity label was added, and slot ranking is
unchanged.

### Authenticate the metrics collector

Allow the node-exporter collector to read a protected control token file and authenticate every read-only control API request without exposing the bearer in argv, logs, or Prometheus output.

## github.com/minpeter/global-egress@0.0.1

### Container packaging and Tegami-managed releases

Add a distroless Docker image and Compose layout for unprivileged deploys.
Drive versions with Tegami (`.tegami` entries → Version Packages PR → `vX.Y.Z`
tag and GitHub Release), then attach static binaries and push multi-arch images
to GHCR as CI side artifacts.

First public tag is `v0.0.1` (no prior tags → baseline `0.0.0`, patch bump).
