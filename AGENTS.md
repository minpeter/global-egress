# PROJECT KNOWLEDGE BASE

**Generated:** 2026-08-03
**Commit:** 9938daf
**Branch:** main

## OVERVIEW

Single Go binary that turns a WireGuard provider bundle into an internal rotating
egress proxy (SOCKS5 + HTTP + control API). Userspace tunnels via wireguard-go on
gVisor netstack; no root, no `/dev/net/tun`, no host routing changes.

## STRUCTURE

```
cmd/global-egress/     # subcommands + all provider->pool wiring (see its AGENTS.md)
internal/
  pool/                # slot selection, tunnels, sessions, uniq batches (see its AGENTS.md)
  proxy/               # SOCKS5 + HTTP listeners (see its AGENTS.md)
  control/             # HTTP management API + Prometheus text at /v1/metrics
  policy/              # parses directives out of the proxy username
  catalog/             # .conf / .zip bundle -> []Slot
  wgtunnel/            # one userspace WireGuard tunnel, exposed as a dialer
  socksdial/           # minimal SOCKS5 client, chains through another dialer
  netguard/            # destination denylist (private/loopback/CGNAT) + port allowlist
  georoute/            # coarse entry<->exit geographic prior, only until measured
  mullvad/             # provider: relay list + per-relay SOCKS proxy
  nordvpn/             # provider: server list -> catalog.Slot
  config/              # TOML load + validate
deploy/                # systemd, OpenRC, Docker/Compose, collector, Grafana
docs/                  # operations.md (observed behaviour), capacity.md (measurements)
scripts/               # entry-bench.py, verify.py, tegami.mts (release manager)
.tegami/               # pending Tegami changelog entries (version bumps)
```

## WHERE TO LOOK

| Task | Location | Notes |
|---|---|---|
| Add a provider | new `internal/<provider>/` | Must produce `pool.ExitSpec` or `catalog.Slot`; the pool imports no provider package |
| Change slot selection | `internal/pool/pool.go` `pick`/`eligibleLocked` | 1475 lines; the project's centre of gravity |
| Add a client directive | `internal/policy/policy.go` | Parse + `String` round-trip + `LogString` redaction all move together |
| Add a config field | `internal/config/config.go`, then `cmd/global-egress/serve.go` `poolOptionsFrom` | `wiring_test.go` fails if a limit does not reach the pool |
| Add a control endpoint | `internal/control/control.go` | Bearer token + client ACL are enforced there |
| Change proxy wire behaviour | `internal/proxy/{http,socks5}.go` | Shared logic lives in `proxy.go` |
| Entry tunnel health/routing | `internal/pool/entry.go` | Failures blame the entry, not the exit |

## CODE MAP

Internal import graph, production code only (no cycles). `—` means the package
imports nothing internal, not that nothing uses it.

| Package | Internal imports | Imported by |
|---|---|---|
| `pool` | catalog, georoute, policy, socksdial, wgtunnel | cmd, control, proxy |
| `proxy` | netguard, policy, pool | cmd |
| `control` | pool | cmd |
| `config` | netguard | cmd |
| `nordvpn` | catalog | cmd |
| `wgtunnel` | catalog | pool |
| `catalog` | — | cmd, nordvpn, pool, wgtunnel |
| `netguard` | — | cmd, config, proxy |
| `policy` | — | pool, proxy |
| `georoute` | — | cmd, pool |
| `socksdial` | — | pool |
| `mullvad` | — | cmd |

`control` and `proxy` also import `catalog`, but only from their tests.

Key entry points: `main.go` dispatches subcommands; `serve.go` `buildSlots` decides
mode; `pool.Acquire` is the hot path; `proxy.Deps.connectUpstream` calls it.

## CONVENTIONS

- Two modes, and they are not symmetric. `relay-socks` (default) = few long-lived
  entry tunnels + one exit per Mullvad relay proxy. `wireguard` = one tunnel per
  slot, provider-neutral. Anything touching tunnels must handle both `Kind`s.
- Provider coupling is confined to `internal/mullvad` and `internal/nordvpn`.
  `cmd/global-egress/serve.go` `exitsFromRelays` is the only translation seam.
- Methods needing `Pool.mu` held by the caller carry a `Locked` suffix
  (`eligibleLocked`, `reserveBatchLocked`, ...). 18 of them; keep the suffix.
- Operational logs and error strings carry **no** network detail: `redactedError`
  renders `%T`, and provider paths use `fmt.Errorf("...failed (%T)", err)`.
  Tests assert this (`TestOperationalLogsRedactNetworkDetails`,
  `TestErrorsRedactEndpointAndSecrets`).
- Errors are `package: what` sentence-case wrapped with `%w`; exported sentinels
  (`pool.ErrBusy`, `ErrNoCandidate`, ...) are what the proxy maps to status codes.
- Godoc on every exported symbol, including struct fields, explaining *why* the
  knob exists. ~230 such comments; match that density.
- City/country are parsed from slot file names (`us-lax-wg-001.conf`); a hyphen
  inside a city name is written as `_` in the file name.
- Tests reach no external service. The mechanisms are in-process fakes, `httptest`,
  and loopback listeners (`net.Listen("tcp", "127.0.0.1:0")` in `socksdial`,
  `proxy`, `mullvad`); anything that would dial a provider is arranged to fail
  before it opens a socket. Async waits subscribe to a channel with a bounded
  timeout (`awaitTestEvent`, `internal/pool/reservation_test.go`), not sleeps.

## ANTI-PATTERNS (THIS PROJECT)

- Do not thread provider conditionals through `internal/pool`. A second provider is
  a sibling package producing the same value types.
- Do not bump `gvisor.dev/gvisor`: `wireguard-go` pins it, and newer snapshots have
  a `pkg/tcpip/stack` directory declaring two packages, so the build breaks. There
  is a comment in `go.mod` saying so.
- Do not run `go list -m -u all` (gvisor drags in containerd/k8s/gRPC). Use
  `make outdated`.
- Do not weaken the two guarantees: `sess=` returns the same exit, `uniq=` never
  repeats a public IP in a batch. Both are enforced against *measured* addresses
  with a freshness bound, never against relay names.
- Do not bulk-probe a provider with one key unpaced. That trips the per-key
  association limit and blocks the key for hours (`docs/capacity.md`).
- Never commit a bundle, `.conf`, or key. `.gitignore` covers `.secrets/`, `*.zip`,
  `*.conf`, `*.local.toml`, `.local-state/`.
- Do not add a formatter or lint config: `.golangci.yaml` owns gofumpt, goimports
  and the linter set, and CI runs the same pinned binary.

## COMMANDS

```bash
make check       # fmtcheck + vet + lint + test; run before pushing
make build       # ./bin/global-egress
make race        # go test -race ./...  (pool hands slots to concurrent requests)
make run         # serve with config.local.toml
make tools       # install pinned golangci-lint v2.12.2 into $(go env GOPATH)/bin
make outdated    # only modules actually built against
```

CI jobs: `lint`, `modules` (tidy leaves no diff + `go mod verify`), `test` on Go
1.25.x and stable including `-race`, `cross-build` (linux/amd64, linux/arm64,
darwin/arm64), `vulncheck`.

## NOTES

- Go floor is **1.25.13** and both parts are forced: minor by `golang.org/x/net`
  and `x/crypto`, patch by reachable stdlib vulnerabilities. `vulncheck` runs
  against the `go.mod` toolchain on purpose.
- Directives ride in the proxy username, so a client must send a non-empty
  password (`cc=jp:x`). Several clients silently drop credentials otherwise and the
  request succeeds from an arbitrary exit. `access.require_policy` turns that into
  a 407.
- Two independent budgets: `pool.max_active` (tunnels *up*) and
  `pool.new_tunnels_per_window` (tunnels *opened* per window). The second protects
  the provider key, not latency.
- Local dev config is `config.local.toml` (gitignored); `state_dir` is
  `.local-state/`.
- `internal/nordvpn` `List.Usable()` drops Dedicated-IP and non-standard-group
  servers: an ordinary subscription cannot use them, so they would fill the pool
  with slots that never come up.
