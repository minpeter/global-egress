# global-egress

[![ci](https://github.com/minpeter/global-egress/actions/workflows/ci.yaml/badge.svg)](https://github.com/minpeter/global-egress/actions/workflows/ci.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/minpeter/global-egress.svg)](https://pkg.go.dev/github.com/minpeter/global-egress)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Mullvad-first, WireGuard-general.** Turn a Mullvad subscription into an internal
rotating egress proxy: one endpoint, hundreds of exit addresses. Any other
WireGuard provider works too, at one exit address per tunnel.

Point it at Mullvad's "all servers" WireGuard zip and it exposes every relay's exit
address behind a single internal proxy. Clients pick a country, pin a sticky
session, demand a unique IP per request, or report a blocked IP and get rotated —
all through the proxy username or a small control API.

It also has a provider-neutral mode that needs nothing but WireGuard configs, at a
much higher cost per exit address. Which is which is spelled out under
[Provider support](#provider-support).

```text
internal client
      │  socks5://egress.example.internal:1080
      │  http://egress.example.internal:3128
      ▼
global-egress ── slot selection (country / session / unique / cooldown)
      │
      ├─ entry tunnel (Tokyo) ─┐
      ├─ entry tunnel (Singapore) ─┼─→ SOCKS proxy on any of ~530 relays
      └─ entry tunnel (Los Angeles) ─┘        │
                                              ▼
                                          internet
```

Everything runs in one process. No `wg-quick`, no network namespaces, no
`/dev/net/tun`, no changes to host routing, no root required.

## Provider support

Being honest about the coupling, because the default mode is not generic:

| | `relay-socks` (default) | `wireguard` |
|---|---|---|
| Works with | **Mullvad only** | any WireGuard provider |
| Needs | a SOCKS5 proxy on every relay, reachable inside the tunnel, plus Mullvad's relay list API | nothing but the config bundle |
| Exit addresses | one per relay (~530) | one per tunnel |

**NordVPN** ships as a second provider package, `internal/nordvpn`. It feeds
`wireguard` mode: `global-egress nordvpn` turns their server list into an ordinary
catalog, and every other subcommand treats it like any other bundle.

NordVPN does run SOCKS5 proxies, but they are not the Mullvad arrangement and do
not give `relay-socks` mode anything to work with. They are a separate pool rather
than one proxy per relay: the API lists 68 endpoints in three countries, one exit
address each. All 68 accept TCP on port 1080 and complete SOCKS5 method
negotiation, so they are running; what they then demand is RFC 1929
username/password, where Mullvad's proxies resolve only inside a tunnel and take no
credentials at all. `internal/socksdial` offers only the no-auth method today.

They also rate-limit a source address hard enough that rotation is the thing they
punish. Measured against the full list: a first sweep authenticated on 8 endpoints,
a repeat from the same address got 1, then 0, and 90 seconds of idling did not
restore it - while an endpoint that had just failed authenticated immediately from
a different network. Sixty-eight exits in three countries, gated that way, is a
poor trade against 6,886 servers in 149 countries, which is what this package
builds tunnels for instead.

```sh
# What the account can actually use, without connecting anywhere.
global-egress nordvpn

# Render a catalog. The key file holds the account's NordLynx private key, mode 0600.
global-egress nordvpn -key /etc/global-egress/nordlynx.key \
  -dir /var/lib/global-egress/nordvpn-wireguard -country jp -limit 40
```

Dedicated-IP servers are dropped: they refuse an ordinary subscription, so offering
them would fill the pool with slots that can never come up. Their WireGuard
listeners are also less reliable than Mullvad's relays, so probe before serving and
leave `pool.failure_backoff` room to do its job.

Use a dedicated directory for each generated provider catalog. The NordVPN command
marks and owns its output directory, refuses to adopt a non-empty unmarked
directory, and refuses to replace a marked directory containing files outside its
manifest. A refresh renders the complete replacement beside the live directory and
then swaps the snapshot with rollback, so another provider's files are never
deleted and a failed refresh leaves the previous catalog intact. Point
`catalog.path` at `/var/lib/global-egress/nordvpn-wireguard` when serving it.

The Mullvad-specific parts are confined to one package, `internal/mullvad`: the
relay list endpoint, its JSON schema, and the fact that each relay answers SOCKS5
on port 1080 from inside a tunnel. Everything else — tunnels, slot selection,
sessions, unique-IP batches, cooldowns, both proxy protocols — is provider
agnostic and works from any wg-quick style config.

Supporting a second provider means writing a sibling of `internal/mullvad` that
produces `pool.ExitSpec` values; the pool itself imports no provider package. If
your provider has no relay proxies, `mode: wireguard` already works today.

Two smaller conventions lean on Mullvad and degrade gracefully elsewhere: country
and city labels are parsed from file names like `us-lax-wg-001.conf`, and the
default public-IP check calls `am.i.mullvad.net`. Unparsed names simply leave
`cc=`/`city=` filters with nothing to match, and the check URL is configurable.

## Two modes, and why the default is what it is

| | `relay-socks` (default) | `wireguard` |
|---|---|---|
| A slot is | a Mullvad relay's SOCKS proxy, reached through an entry tunnel | its own userspace WireGuard tunnel |
| Exit addresses | ~530, one per relay | one per tunnel |
| Cost of rotating | one TCP connection | one WireGuard handshake |
| Key associations | 2-3 total, long-lived | one per slot |
| Memory for the whole catalog | ~20 MiB | ~850 MiB |

Providers restrict how quickly one device key may associate with new relays.
Measured on a 532-relay bundle: sweeping the catalog as WireGuard tunnels tripped
that limit after 219 relays in under three minutes and the key stopped
handshaking anywhere for hours. `relay-socks` moves rotation off that path
entirely — the key stays on two or three relays, and exits change by opening a
TCP connection to another relay's proxy from inside the tunnel. See
[docs/capacity.md](docs/capacity.md) for the numbers.

`wireguard` mode remains available: it needs no relay list and its exit addresses
are a different set, which is useful if a provider ever stops offering proxies.

## Why not an existing tool

| Tool | What it does | What is missing for this use case |
|---|---|---|
| `wireproxy` | Userspace WireGuard → SOCKS5/HTTP | One tunnel per process; no pool, no selection policy |
| `gluetun` | VPN container with built-in proxy | One tunnel per container; no central selection |
| `sing-box`, `Xray-core`, mihomo | Many WireGuard outbounds + balancing | Rule-based routing, not per-connection slot control; no sticky sessions, unique-IP batches or block reporting |
| `gost` | Upstream proxy load balancing | Does not manage the tunnels themselves |
| `rota`, `slrp` | Rotation control planes | Rotate existing proxy lists, not WireGuard tunnels |

The tunnel part is solved. The control plane — per-connection slot selection,
sticky sessions, verified-unique IPs, per-target cooldowns — is what this project
adds.

## Quick start

```sh
# 1. Import the provider bundle (the .conf files hold a private key).
global-egress import -zip ~/mullvad-all.zip -dir /var/lib/global-egress/wireguard

# 2. See what the bundle contains, without connecting anywhere.
global-egress inspect -catalog /var/lib/global-egress/wireguard

# 3. See the relay list that relay-socks mode exits through.
global-egress relays -cache /var/lib/global-egress/relays.json

# 4. Measure the exit IP of every slot and store an inventory. In relay-socks mode
#    this rides the shared entry tunnels, so a full sweep is cheap and safe.
global-egress probe -catalog /var/lib/global-egress/wireguard \
  -mode relay-socks -relay-cache /var/lib/global-egress/relays.json \
  -state /var/lib/global-egress/inventory.json -concurrency 6

#    In wireguard mode, pace it (-interval): each exit costs a key association, and
#    an unpaced sweep gets the key rate-limited part-way through.
global-egress probe -catalog /var/lib/global-egress/wireguard \
  -mode wireguard -state /var/lib/global-egress/inventory.json \
  -concurrency 2 -interval 2s

# 5. Run the service.
cp deploy/config.example.toml /etc/global-egress/config.toml
global-egress serve -config /etc/global-egress/config.toml
```

## Using the proxy

```sh
# Any healthy slot.
curl -x http://egress.example.internal:3128 https://api.example.com/

# Environment variables, which is what most tools expect.
export HTTP_PROXY=http://egress.example.internal:3128
export HTTPS_PROXY=http://egress.example.internal:3128

# SOCKS5 works for anything TCP, not just HTTP.
curl --socks5-hostname egress.example.internal:1080 https://api.example.com/
```

### Controlling the exit IP

The selection policy travels in the **proxy username**, which every HTTP and
SOCKS5 client supports:

```sh
curl -x http://egress.example.internal:3128 --proxy-user 'cc=jp:x'              https://api.example.com/
curl -x http://egress.example.internal:3128 --proxy-user 'city=us-lax:x'        https://api.example.com/
curl -x http://egress.example.internal:3128 --proxy-user 'sess=job-1;ttl=600:x' https://api.example.com/
curl -x http://egress.example.internal:3128 --proxy-user 'uniq=batch-7:x'       https://api.example.com/
curl -x http://egress.example.internal:3128 --proxy-user 'provider=external-example:x' https://api.example.com/
```

| Directive | Meaning |
|---|---|
| `any=1` | No location constraint, chosen deliberately |
| `cc=jp` | Restrict to a country. Several: `cc=jp\|us` |
| `city=us-lax` | Restrict to a city |
| `slot=us-lax-wg-001` | Pin one specific slot, mainly for debugging |
| `provider=external-example` | Select a configured provider by ID |
| `sess=name` | Sticky: reuse the same exit IP for this session |
| `ttl=600` | Session lifetime in seconds (or `10m`) |
| `uniq=batch` | Never reuse a public IP within this batch |
| `bttl=30s` | Override this `uniq=` batch lifetime within the server maximum |
| `health=scope` | Use provider/model-specific exit health and success ranking |
| `not=1.2.3.4` | Exclude specific public IPs |

Directives are separated by `;` or `,`. An empty username means "no constraints".
The password is a single optional shared secret (`access.password`), not an
identity. Provider credentials live in the same TOML file as `[[providers]]`
entries, so protect it (mode 0600): one `type = "mullvad"` provider owns
`catalog`, `relays`, and `entries`, and each optional `type = "socks5"`
provider carries its authenticated `url` plus optional `country`/`city`
labels. The external URL may use `socks5://` or `socks5h://`; its credentials
are kept in memory and are never returned by the control API.

For a provider such as Decodo whose rotating port changes the IP on every
request, one slot cannot honestly represent the remote pool. Set
`[providers.socks5] sessions = N` to create N Decodo-compatible sticky logical
sessions, each with its own measured slot and IP. `sessions = 0` (the default)
keeps one ordinary rotating endpoint slot. Choose N no higher than the number
of IPs in the provider plan: the gateway can reuse an IP across sessions, and
global-egress cannot discover the provider's remote pool size without probing.
The service probes configured direct-SOCKS slots at startup when IP checks are
enabled, so `uniq=` can use the measured sticky-session identities.

### Always give a password, even a dummy one

The directives ride in the proxy **username**, so the client has to actually send
credentials. Several clients quietly drop them when the password is empty, and the
request then succeeds from an arbitrary exit — no error, no warning, just the wrong
country. Measured against this proxy, asking three times for `cc=jp`:

| Form | curl | Python `requests` / `urllib` |
|---|---|---|
| `cc=jp:x` | Japan ×3 | Japan ×3 |
| `cc=jp:` (empty password) | Japan ×3 | **Sweden, Israel, USA** |
| `cc=jp` (no colon) | prompts for a password | **Thailand, USA, Sweden** |

So write `cc=jp:x`. Any non-empty password works; nothing checks it unless
`access.password` is set.

Two things help catch the mistake anyway:

- **`X-Egress-Policy`** reports the policy the server actually parsed on the
  successful `CONNECT` response. It is *not* copied into plain HTTP origin
  responses or the encrypted HTTPS response, so the transport must inspect the
  proxy handshake when it needs this diagnostic.
- **`access.require_policy: true`** refuses directiveless requests outright, which is
  the safeguard that works regardless of protocol:

  ```text
  407 Proxy Authentication Required
  no selection policy supplied: put the directives in the proxy username and give a
  non-empty password, e.g. "cc=jp:x". Several clients drop the credentials entirely
  when the password is empty.
  ```

  Turn it on wherever an unnoticed fallback to a random exit would be a bug.

  Callers who genuinely want any exit are not locked out: `any=1` says so
  explicitly and is accepted. That is the whole point of the directive — it
  separates "anywhere is fine" from "my directives never arrived", which behave
  identically and mean opposite things.

  ```sh
  curl -x http://egress.example.internal:3128 --proxy-user 'any=1:x'          https://…
  curl -x http://egress.example.internal:3128 --proxy-user 'any=1;sess=job-1:x' https://…
  ```

  `any=1` composes with `sess=`, `ttl=`, `uniq=` and `not=`, and is rejected
  alongside `cc=`, `city=` or `slot=`, which would contradict it. The response header
  distinguishes the two cases as well: `X-Egress-Policy: any=1` versus
  `X-Egress-Policy: (none)`.

Successful `CONNECT` responses report the egress that serves the tunnel:

```text
X-Egress-Slot: jp-tyo-wg-socks5-001
X-Egress-Country: jp
X-Egress-City: jp-tyo
X-Egress-IP: 203.0.113.7
X-Egress-Session: job-1
X-Egress-Policy: cc=jp;sess=job-1
```

Plain HTTP forwarding reserves the `X-Egress-*` namespace for proxy control
metadata: those headers are removed in both directions and are never exposed as
origin response headers.

### Distinct-exit retry chains

Keep one `uniq=` value and `bttl=` lifetime for the whole logical operation.
Use distinct `sess=` values only when the caller also needs sticky lookup:

```text
attempt 1: any=1;uniq=req-42;bttl=30s
attempt 2: any=1;uniq=req-42;bttl=30s
attempt 3: any=1;uniq=req-42;bttl=30s
```

The pool atomically reserves both the selected slot and its measured public IP
against the batch before releasing the selection lock. A failed tunnel setup
rolls that reservation back. Later attempts cannot reuse either identity, even
when requests carrying the same `uniq=` arrive concurrently.

Unknown or stale public IPs are not eligible for `uniq=` selection: the
inventory must hold a measurement newer than `pool.ip_refresh_interval`,
otherwise the request fails closed rather than weakening the distinctness
guarantee. A later IP refresh is backfilled into every live batch that consumed
the slot. Tentative reservations carry the exact batch generation so a failed,
expired request cannot roll back a newer batch with the same name. When every
eligible distinct exit has been consumed, acquisition fails with `409 Conflict`
instead of silently returning a duplicate. `not=` remains available for
callers that already hold an explicit public-IP exclusion list; it uses the
same fresh-measurement requirement.

Active unique batches are bounded by `pool.max_unique_batches` (default
`10000`). Capacity exhaustion is a temporary `503 Service Unavailable`; expired
batches are pruned before the limit is applied. Client-selected `bttl=` values
must not exceed `pool.max_batch_ttl`; omitting `bttl=` retains the configured
`pool.batch_ttl` behavior.

Sticky names are independently bounded by `pool.max_sessions`, including names
reserved by in-flight acquisitions. Client-selected `ttl=` values must not
exceed `pool.max_session_ttl`. Expired sessions are pruned before either limit
is applied.

For HTTPS, the `X-Egress-*` values are on the successful `CONNECT` response,
not the encrypted origin response. A custom proxy transport must capture those
headers before it starts TLS. It can use `X-Egress-IP` as the source-IP quota
identity without logging or forwarding it to the application response.
Operational proxy logs also omit raw client and destination addresses; failures
retain only an error type and slot identity, and HTTP error bodies are generic.

`city=`, `slot=`, `sess=`, and `uniq=` accept only ASCII letters, digits, `.`,
`_`, and `-`, up to 128 characters. Every manually serialized CONNECT value is
also checked for control characters at the final write boundary.

### Rotating when a site blocks you

Use the same non-secret `health=` value in the proxy username and feedback
body. `X-Egress-Slot` and `X-Egress-IP` from the CONNECT response identify the
measured exit. A failure is keyed by `(scope, public IP)`, so duplicate slots
cannot immediately offer the same quota-burned IP:

```sh
curl -X POST http://egress.example.internal:8080/v1/report \
  -H 'Authorization: Bearer CONTROL_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"slot":"jp-tyo-wg-001","public_ip":"203.0.113.10","scope":"opencode-zen.deepseek-v4-flash-0731","reason":"zen_free_quota","cooldown":"24h"}'
```

Report a successful measured IP to put it in the bounded, least-loaded ring:

```sh
curl -X POST http://egress.example.internal:8080/v1/prefer \
  -H 'Authorization: Bearer CONTROL_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"slot":"us-lax-wg-001","public_ip":"203.0.113.11","scope":"opencode-zen.deepseek-v4-flash-0731","ttl":"30m"}'
```

Active failures dominate later success reports until cooldown expiry. Equal-load
successes rotate instead of hot-pinning the oldest IP. Both cooldowns and
preferred rings persist with the measured-IP inventory.

## Control API

Bound to an internal address, optionally protected by a bearer token.

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness |
| `GET /v1/info` | Version, uptime, slot count |
| `GET /v1/stats` | Open tunnels, unique IPs, sessions, counters |
| `GET /v1/metrics` | Prometheus request, country, payload, and tunnel lifecycle metrics |
| `GET /v1/country-acquisitions` | Successful exit selections grouped by country |
| `GET /v1/slots` | Inventory; filters: `country`, `city`, `open`, `with_ip`, `limit` |
| `GET /v1/entries` | Entry tunnels and the latency measured through them |
| `GET /v1/ips` | Distinct measured public IPs |
| `GET /v1/whoami?sess=NAME` | Which slot and IP a session currently uses |
| `GET /v1/sessions/NAME` | Same as `whoami`, path form |
| `POST /v1/sessions/NAME/rotate` | Force the next request onto a new slot |
| `DELETE /v1/sessions/NAME` | Same as rotate |
| `POST /v1/report` | Cool one measured public IP for a health scope |
| `POST /v1/prefer` | Record a successful measured public IP for a health scope |

## Design notes

**Userspace tunnels.** Every configuration in a provider bundle claims the same
tunnel address and a default route, so several of them cannot coexist in one
network namespace without policy routing tricks. Each tunnel instead gets its own
[gVisor netstack](https://gvisor.dev/) network stack inside the process, which
sidesteps the conflict entirely and needs no privileges.

**Entries are chosen per exit, and the choice is learned.** Every request pays the
trip to its entry tunnel, so the entry matters as much as the exit. A coarse
geographic prior orders entries at startup, then each successful dial feeds a
latency average per (entry, exit country) and measurements override the prior. A
small fraction of requests deliberately try the runner-up so alternatives keep
being measured. `GET /v1/entries` shows what has been learned.

**Two budgets, not one.** `pool.max_active` caps how many tunnels are *up*;
`pool.new_tunnels_per_window` caps how many may be *opened* per window. The second
one matters because providers restrict how fast a single device key may associate
with new relays — the failure mode is the key getting blocked for hours, not a
slow request. Requests served from already-open tunnels never touch it, and
`/v1/stats` exposes `new_tunnels_used` so you can see when rotation is being
slowed down deliberately.

**Lazy tunnels with a budget.** `pool.max_active` caps how many tunnels are up at
once. Tunnels open on demand, idle ones are closed, and the least recently used
one is evicted when the budget is full. Start low, measure, then raise it.

**Slot count is not IP count — verify it.** `global-egress probe` measures the
real exit IP of each slot and stores an inventory, and `uniq=` batches are
enforced against those measured addresses rather than server names. On a 532-slot
Mullvad bundle every reachable slot turned out to have its own address (456
slots, 456 distinct IPs), but that is a property of the provider, not a promise.

**Entry failures are attributed to the entry.** A tunnel that is up but no longer
carrying traffic can only be detected by the dials riding on it. Three consecutive
failures take that entry out of rotation and drop its tunnel so the next use
re-handshakes; without this the exits behind a dead entry get blamed one by one and a
healthy catalogue slowly disables itself. Verified in place by blackholing an entry's
endpoint: one request fails, the pool moves on, and the entry rejoins by itself once
the path returns.

**Bulk probing hits provider rate limits.** Sweeping a large bundle quickly gets
the device key throttled, after which every handshake fails for a while. Use
`-interval` and low `-concurrency`, and see [docs/capacity.md](docs/capacity.md)
for the measurements. Serving traffic is unaffected, because tunnels open on
demand under the `max_active` budget.

**DNS stays in the tunnel.** Host names are resolved through the resolvers in the
slot's own configuration (`10.64.0.1` for Mullvad), so lookups never fall back to
the host resolver.

**It is an internet egress, not a pivot.** Private, loopback, link-local, CGNAT
and multicast destinations are refused by default, both before dialling and again
after resolution.

**One provider device.** A downloaded bundle usually shares a single private key
across every server; `inspect` reports how many distinct keys it found. Check
your provider's terms for how many simultaneous connections one device may make.

## Configuration

See [`deploy/config.example.toml`](deploy/config.example.toml). Every field is
documented there.

## Operations

[`docs/operations.md`](docs/operations.md) covers the parts that only show up once
this is actually running: choosing entry tunnels for your location, testing entry
failover, building the exit inventory without tripping provider limits, and the
failure modes worth recognising. [`docs/capacity.md`](docs/capacity.md) has the
measurements behind the design.

## Requirements

- Go 1.25.12 or newer (the minor version comes from `golang.org/x/net` and
  `golang.org/x/crypto`; the patch version from reachable stdlib vulnerabilities in
  earlier 1.25 releases)
- Linux for deployment; the code also compiles for darwin/arm64
- A Mullvad account and its WireGuard configuration bundle, for the default
  `relay-socks` mode. Any WireGuard bundle works in `wireguard` mode.

## Development

```sh
make build   # build ./bin/global-egress
make test    # go test ./...
make lint    # golangci-lint
make check   # formatting (gofumpt + goimports), vet, lint, tests
make run     # run with config.local.toml
```

## Monitoring

The service speaks JSON, so a small collector translates `/v1/stats` and
`/v1/entries` into Prometheus text and node_exporter serves it.

```sh
install -m 0755 deploy/collector/global-egress-collector /usr/local/bin/
install -m 0644 deploy/grafana/global-egress.json \
  /opt/monitoring/grafana/dashboards/global-egress.json
```

The shipped dashboard (**UID `global-egress`**, 12 panels) covers entry tunnel state,
request and failure rates, exit inventory coverage, sticky sessions and unique
batches, guest CPU/memory/throughput, and collector-versus-scrape freshness. Its
datasource and scrape job are dashboard variables rather than baked-in values, so it
works on any Grafana. Details and the metric list:
[`deploy/grafana/README.md`](deploy/grafana/README.md).

Traffic is counted **at the proxy**, not at the interface. Proxied bytes cross the
guest NIC twice, once from the client and once inside the tunnel, so `node_network_*`
reads roughly double and cannot say which exit or entry carried them. Proxy counters
are committed when a connection finishes, so long-lived streams appear as a step at
close rather than continuously. Both views are on the dashboard and are expected to
disagree:

```text
global_egress_bytes_sent_total / _received_total                  payload relayed
global_egress_entry_bytes_sent_total{entry,region} / _received    the same, per entry
```

The per-entry split answers a question the totals cannot: whether one entry is
carrying everything, either because it won the latency race everywhere or because
the others are failing and being skipped.

The one panel to watch over time is guest memory: userspace tunnels cost about
1.6 MiB each, so it should stay flat once the entries are up.

## Deployment

Systemd hosts use [`deploy/global-egress.service`](deploy/global-egress.service);
Alpine/OpenRC guests use [`deploy/openrc/global-egress`](deploy/openrc/global-egress)
and [`deploy/collector/global-egress-metrics.openrc`](deploy/collector/global-egress-metrics.openrc).
Containers use the root [`Dockerfile`](Dockerfile) and
[`deploy/docker`](deploy/docker) (Compose + example config).

### Cutting a release

Releases are managed with [Tegami](https://tegami.fuma-nama.dev) (same flow as
the rest of the minpeter repos):

1. Merge PRs that include a `.tegami/*.md` changelog entry.
2. CI runs `node scripts/tegami.mts ci` and opens a **Version Packages** PR.
3. Merge that PR when you intend to publish. Tegami creates a `vX.Y.Z` git tag
   and a GitHub Release with notes from the changelogs.
4. Follow-up jobs attach static binaries and push a multi-arch image to GHCR.

```sh
# interactive changelog (optional)
npm ci && npm run tegami
```

| Artifact | Where |
|---|---|
| `global-egress-linux-amd64` / `linux-arm64` / `darwin-arm64` (+ `.sha256`) | GitHub Release assets |
| `ghcr.io/minpeter/global-egress:X.Y.Z` (also `:vX.Y.Z`, `:latest`) | GHCR (after binaries succeed) |

`workflow_dispatch` on the release workflow only pushes an `edge` image so packaging
can be smoke-tested without minting a version. Do not push version tags by hand.

### Docker / Compose

Userspace tunnels need no `/dev/net/tun` and no `NET_ADMIN`, so the image runs as
an unprivileged distroless user.

```sh
cd deploy/docker
cp config.example.toml config.toml
printf 'changeme\n' > proxy-password && chmod 600 proxy-password
mkdir -p catalog   # provider .conf files or a .zip
docker compose up -d --build
```

Or pull a release image and skip the local build:

```sh
export GLOBAL_EGRESS_IMAGE=ghcr.io/minpeter/global-egress:latest
docker compose -f deploy/docker/docker-compose.yml up -d
```

Ports default to host loopback only (`127.0.0.1:1080/3128/8080`). Details and a
Kubernetes sketch are in [`deploy/docker/README.md`](deploy/docker/README.md).

### Alpine / OpenRC

Userspace tunnels need no `/dev/net/tun`, no `NET_ADMIN` and no nesting, so an
unprivileged container is enough. A 512 MB guest is comfortable.

```sh
addgroup -S egress && adduser -S -D -H -h /var/lib/global-egress \
  -s /sbin/nologin -G egress egress

install -m 0755 global-egress /usr/local/bin/
install -d -m 0750 -o root -g egress /opt/global-egress
install -m 0640 -o root -g egress bundle.zip config.toml /opt/global-egress/
install -d -m 0700 -o egress -g egress /var/lib/global-egress

install -m 0755 deploy/openrc/global-egress /etc/init.d/global-egress
rc-update add global-egress default && rc-service global-egress start
```

Updating the binary in place fails with `Text file busy` while the service runs.
Replace it by rename instead, which is atomic and needs no downtime window:

```sh
cp global-egress /usr/local/bin/global-egress.new
mv /usr/local/bin/global-egress.new /usr/local/bin/global-egress
rc-service global-egress restart
```

```sh
# Create the unprivileged account the unit runs as.
install -m 0644 deploy/global-egress.sysusers /usr/lib/sysusers.d/global-egress.conf
systemd-sysusers

install -m 0755 global-egress /usr/local/bin/
install -m 0644 deploy/global-egress.service /etc/systemd/system/
install -d -m 0750 -o root -g global-egress /etc/global-egress
install -m 0640 -o root -g global-egress deploy/config.example.toml /etc/global-egress/config.toml

systemctl daemon-reload
systemctl enable --now global-egress
```

The unit needs no capabilities: tunnels run in userspace, so there is no tun
device, no `NET_ADMIN` and no root.

## Security

Bind the listeners to an internal address and set `access.allowed_clients`. See
[SECURITY.md](SECURITY.md) for the threat model and for how key material is
handled.

## License

MIT. See [LICENSE](LICENSE).

## Limitations

- `CONNECT`/TCP only. No SOCKS5 UDP, so QUIC and HTTP/3 clients fall back to TCP.
- IP selection happens per **connection**. A client reusing one keep-alive
  connection keeps the same exit IP; make a new connection (or change `sess=`) to
  move.
- `uniq=` can only guarantee as many distinct IPs as the bundle actually has, and
  only for slots whose IP has been measured.
- Measuring a whole large bundle takes hours, because handshakes must be paced to
  stay under the provider's per-key rate limit.
- In `relay-socks` mode the destination is resolved at the exit relay, so a host
  name that resolves into private space cannot be caught locally. Literal private
  addresses are still refused before dialling.
- Not an anonymity tool. The provider still sees the tunnel, and the service logs
  which slot served which destination.
