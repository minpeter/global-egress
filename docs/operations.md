# Operations

Notes from running this in place. Everything here was observed, not assumed.

## Choosing entry tunnels

Entries are the only tunnels that stay up, and **every request pays the trip to its
entry**, so the choice matters more than which exits exist. It also cannot be derived
from the catalogue: the right entry depends on where the service runs.

`scripts/entry-bench.py` runs each candidate alone in a short-lived instance and
times a set of exit countries through it:

```sh
python3 scripts/entry-bench.py bundle.zip \
  jp-tyo-wg-001,hk-hkg-wg-201,nl-ams-wg-001,us-lax-wg-001 \
  jp,sg,au,de,gb,us,br,za
```

Run it **on the host that will serve traffic**. Measuring from a workstation that is
itself behind a VPN adds a hop to every number and reorders the result: an earlier
run from such a host picked an American entry for European exits, which the same
benchmark on the deployment host contradicted outright.

A real result, from a host in Korea on a direct internet path:

```text
entry            jp     sg     au     de     gb     us     br     za   median
jp-tyo-wg-001  1233   1304   2002   2091   1968   1697   2853   3536   1985
hk-hkg-wg-201  2012   1687   2489   1926   2058   2464   3325   3600   2261
nl-ams-wg-001  3431   3100   3704   1465   1670   2373   3007   2986   2997
us-lax-wg-001  2457   2472   2602   1884   1761   1561   2604   3272   2465
```

Three entries, one per region, each winning its own: Asia to Tokyo, Europe to
Amsterdam, the Americas to Los Angeles. The second Asian candidate never won
anything and was dropped. Note that a *nearby* entry beats a *nearer-the-exit* entry
in most rows — from Korea, Tokyo serves Australian and even American exits better
than entries closer to them, because the first hop is paid on every request.

Do not encode the result: the pool measures each dial and keeps a latency average
per (entry, exit country), so country-to-entry assignment is learned. The benchmark
only answers "which entries belong in the list".

## Testing entry failover

A tunnel that is up but no longer carrying traffic is the interesting failure, and
the only way to produce it is to break the path underneath a live device.
Blackholing the endpoint works, including inside an unprivileged container:

```sh
# inside the guest
ip route add blackhole <entry-endpoint-ip>/32
# drive some traffic, watch /v1/entries and the log
ip route del blackhole <entry-endpoint-ip>/32
```

Expected behaviour: the first request through that entry fails, three consecutive
failures take it out of rotation and drop its tunnel, later requests are served by
another entry, and the entry rejoins on its own once the path returns.

```text
WARN entry taken out of rotation entry=jp-tyo-wg-001 consecutive_failures=3 backoff=30s
```

If instead you see repeated 502s while `/v1/entries` reports that entry as healthy
with `failures=0`, the attribution is broken — the exits are being blamed for the
entry's fault. That was the behaviour before this was fixed, and it is worth
re-checking after any change to the dial path.

## Building the exit inventory

`uniq=` batches are enforced against *measured* public addresses, so the inventory is
what makes large batches trustworthy. A sweep in relay-socks mode rides the shared
entries and costs no extra key associations:

```sh
global-egress probe -catalog bundle.zip -mode relay-socks \
  -entries jp-tyo-wg-001,nl-ams-wg-001,us-lax-wg-001 \
  -relay-cache /var/lib/global-egress/relays.json \
  -state /var/lib/global-egress/inventory.json -concurrency 6
```

**Keep concurrency modest.** At 10 a single entry becomes the bottleneck and its
region fails disproportionately: one sweep lost 77 of 532 exits, concentrated in
Europe (de 13/21, nl 10/17, ch 8/11), and 69 of them succeeded on a retry at
concurrency 4. Those were contention, not dead exits.

Request-scoped retry chains should send a bounded `bttl=` with `uniq=`. Size
`pool.max_unique_batches` for the expected logical request rate multiplied by
that lifetime and operational headroom. Monitor sticky-session cardinality
separately; `pool.max_sessions` and `pool.max_session_ttl` bound retained client
state even when connection concurrency stays low.

**Stop the service first if you are writing to its state file.** The service saves
its in-memory inventory on shutdown, so a file written underneath a running instance
is overwritten when it stops:

```sh
rc-service global-egress stop     # saves what it currently knows
# merge or replace /var/lib/global-egress/inventory.json here
rc-service global-egress start    # "inventory restored slots=N"
```

Merging beats replacing. A sweep and a running service each know things the other
does not: the sweep is broader, while the service has learned exits that happened to
fail during the sweep.

Measured in place on 2026-07-28, relay-socks mode, 532-slot Mullvad bundle (device
"Fast Pike"): **529 exits, 529 distinct addresses, zero duplicates**. The
catalogue really does give one address per exit.

That 529 is one row in the log in
[docs/capacity.md](capacity.md#exit-ip-measurement-log), not a property of the
software. A single sweep of the same bundle at concurrency 10 measured 524, and a
wireguard-mode sweep measured 456, because a measurement reflects the mode, the
concurrency and the day it ran. Record the same metadata for your own sweeps: date,
mode, bundle size and device, concurrency and pacing.

For what is true right now rather than on some past date, read the service instead
of a document: `slots`, `slots_with_known_ip` and `unique_public_ips` in
`/v1/stats`, and the address list in `/v1/ips`. Slot count and measured IP count
are separate fields on purpose, and `uniq=` only ever draws on the measured ones.

## Watching it

`/v1/stats` and `/v1/entries` are the two views worth knowing:

```sh
curl -sS http://egress.example.internal:8080/v1/stats
curl -sS http://egress.example.internal:8080/v1/entries   # learned latency per country
```

In Prometheus terms, three queries answer most questions:

```promql
# memory should be flat once the entries are up: ~1.6 MiB per open tunnel
node_memory_MemAvailable_bytes{job="global-egress"}

# was an entry ever lost in the last day?
min_over_time(global_egress_entries_open{job="global-egress"}[24h])

# are exits failing, or is something systemic?
increase(global_egress_failures{job="global-egress"}[24h])
```

A dashboard covering all of it ships in [`deploy/grafana`](../deploy/grafana).

## Things that will bite

- **Empty proxy password silently disables the policy.** See the README table. The
  `X-Egress-Policy` response header exposes it for plain HTTP and on the CONNECT
  response, but not inside an HTTPS response, so `access.require_policy: true` is the
  safeguard that actually covers every client.
- **`Text file busy`** when updating the binary in place. Copy alongside and `mv`.
- **Bulk probing in `wireguard` mode gets the device key blocked**, for hours, across
  every relay. Use relay-socks, or pace with `-interval`.
- **Monitoring must stay read-only.** The control API can rotate sessions and cool
  exits down; a collector that calls those changes the thing it measures.
