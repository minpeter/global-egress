# Capacity

Every number here comes from a specific run: a date, one provider bundle, one
mode, one host. Unless a line says otherwise, it was measured on 2026-07-28 with
a 532-slot Mullvad bundle (device "Fast Pike"), Go 1.26, Linux, one
`global-egress` process.

Nothing in this file is a constant the code reads, and none of it describes your
bundle. Slot count is what the catalogue contains; measured IP count is what a
sweep proved. They are different numbers, and the second one changes as relays
come and go. For the values that are true right now, ask the running service:
`GET /v1/stats` (`slots`, `slots_with_known_ip`, `unique_public_ips`) and
`GET /v1/ips`.

## Exit-IP measurement log

Three measurements of the same 532-slot bundle, kept separate on purpose. They are
different runs, not competing versions of one truth, and the spread between them
is the point: what a measurement sees depends on the mode, the concurrency and the
day.

| Date | Mode | Bundle / device | Measurement | Measured | Unique IPs | Duplicates |
|---|---|---|---|---:|---:|---:|
| 2026-07-28 | `relay-socks` | 532 slots, "Fast Pike" | sweep at concurrency 10, plus a retry of the failures at 4 | 524 / 532 | 524 | 0 |
| 2026-07-28 | `relay-socks` | 532 slots, "Fast Pike" | in-place inventory recorded in [operations.md](operations.md) | 529 / 532 | 529 | 0 |
| 2026-07-28 | `wireguard` | 532 slots, "Fast Pike" | unpaced sweep at concurrency 8, key blocked part-way | 456 / 532 | 456 | 0 |

What holds across all three: **one measured address per reachable exit, zero
sharing.** What does not hold: the total. Quote a total only with the row it came
from.

When you record a new row, note the date, the mode, the bundle size and device,
the concurrency and pacing, and whether the figure comes from one sweep or from an
inventory that has accumulated across runs. A count without that metadata cannot
be compared against anything.

## relay-socks mode, measured

The default mode keeps a few entry tunnels up and exits through the SOCKS proxy on
each Mullvad relay. Every number below is specific to Mullvad's network and to a
measuring host in Korea that was itself behind a tunnel, so treat them as shape
rather than as absolute values.

```text
slots in the catalogue     532   (relays that are active and expose a proxy)
entry tunnels              3     (Tokyo, Singapore, Los Angeles)
WireGuard associations     3     total, long-lived
startup                    304ms to bring all three entries up
resident memory            20.4 MiB for the whole 532-slot catalog
```

Rotation throughput, each request landing on a different exit IP:

```text
concurrency  8: 20/20 distinct IPs, 6.4s ->  3.1 IPs/s
concurrency 20: 60/60 distinct IPs, 7.5s ->  8.0 IPs/s
concurrency 40: 60/60 distinct IPs, 4.2s -> 14.3 IPs/s
```

At concurrency 40 the entire 532-slot catalog can be cycled in roughly 37
seconds, with zero errors and no new key associations. Country selection was
correct for every country tested (jp, de, us, br, au, se, za), and sticky sessions
returned the same address on every request.

Added latency versus exiting directly from the entry tunnel, Singapore entry to a
German exit:

```text
direct  connect=0.365s  total=0.920s
socks   connect=0.340s  total=1.396s
```

So roughly +0.5s per new connection on a long path, and much less when entry and
exit are near each other. Existing connections are unaffected.

Entry routing is learned from real traffic. After a few dozen requests from a
Korean host:

```text
jp-tyo-wg-001   east-asia       jp=847ms  sg=839ms  hk=954ms  au=1117ms
us-lax-wg-001   north-america   us=1111ms ca=1089ms gb=1280ms se=1267ms
sg-sin-wg-001   south-asia      my=1286ms th=1584ms de=1719ms
```

The Asian entry won Asian exits and the American entry won American and European
ones, without any of that being configured.

## wireguard mode

### Memory

| State | RSS |
|---|---:|
| 532 slots parsed, 0 tunnels open | 14.8 MiB |
| 532 slots parsed, 30 tunnels open | 61.8 MiB |
| **Cost per open tunnel** | **≈1.57 MiB** |

Projection from those two points:

| Open tunnels | Projected RSS |
|---:|---:|
| 25 | ~54 MiB |
| 100 | ~171 MiB |
| 250 | ~406 MiB |
| 532 (all) | ~848 MiB |

Loading the catalog is cheap; only *open* tunnels cost memory. `pool.max_active`
is therefore the knob that decides the footprint.

## Other per-tunnel resources

With 30 tunnels open the process used:

- 50 OS threads (Go runtime plus netstack workers, grows sub-linearly)
- 159 file descriptors, i.e. roughly one UDP socket per tunnel plus listeners

Set `LimitNOFILE` generously; the shipped systemd unit uses 65535.

## Tunnel setup time

- WireGuard handshake to a reachable server: **0.3–3.0 s**, typically ~1.6 s
- 30 tunnels pre-opened concurrently: ~300 ms wall clock
- 6 slots probed with concurrency 3: 5 s total

## 2026-07-28, relay-socks, measured in place

Run from the deployment guest over three shared entry tunnels, so the whole sweep
cost three key associations rather than one per exit:

```text
probed            532 exits in 3m0s at concurrency 10
reachable         455
retry of the 77   69 more reachable at concurrency 4
------------------------------------------------------
measured          524 / 532
unique public IPs 524
duplicates        0
ratio             1.0000 unique IP per measured exit
countries         50
distinct /16      92
```

**524 distinct exit addresses, no sharing whatsoever.** That was the ceiling for
`uniq=` batches on this bundle on that day. The in-place inventory in
[operations.md](operations.md) reached 529 on the same catalogue, so read 524 as a
floor with a date attached, not as the bundle's permanent size.

The 77 first-pass failures were concentrated in Europe (de 13/21, nl 10/17, ch 8/11,
gb 9/23) and 69 of them succeeded on a retry at lower concurrency, so they were
contention on the European entry rather than dead exits. Sweep at concurrency 4-6 if
a single clean pass matters.

Contrast with the wireguard-mode run below: the same catalogue measured 456 exits,
needed 456 key associations, and got the device key blocked for hours. Same
bundle, same day, different mode, 68 fewer addresses.

## 2026-07-28, wireguard, unpaced sweep

Same 532-slot Mullvad bundle and the same device key, this time opening one tunnel
per slot at `-concurrency 8` with no pacing:

```text
probed          532 slots in 3m44s
reachable       456
failed           76
unique IPs      456      <- one distinct exit IP per reachable slot
duplicates        0
distinct /24s   227
```

Two results matter here.

**There is no IP sharing.** Every reachable slot exited from its own address:
456 slots, 456 distinct IPs, ratio 1.00, matching the relay-socks runs. The
common assumption that a provider multiplexes many servers behind one exit
address did not hold for this bundle, so `uniq=` batches can be as large as the
number of *reachable* slots.

**The 76 failures were self-inflicted, not dead servers.** Cross-checking every
slot against Mullvad's live relay list (`api.mullvad.net/www/relays/wireguard/`)
showed all 532 still active, with matching public keys and endpoint addresses.
Ordering the results by completion time explains what actually happened:

```text
failure rate by decile of completion order
  0- 40%    0/212
 40- 60%    4/107
 60- 70%   11/53   ########
 70- 80%    6/53   ####
 80- 90%   24/53   ##################
 90-100%   31/54   ######################
```

The first 219 consecutive slots succeeded, then failures grew steadily. Shortly
afterwards *every* slot failed to handshake, including ones that had just worked,
and a repeat sweep from a second host with direct internet access returned
0/532. Nothing recovered within ten minutes.

That is a **provider-side restriction applied to the device key**, not a property
of individual relays. ICMP to the affected relays kept working throughout, and
only this key was affected — a second Mullvad device on the same network kept
running normally, from the same hosts, for the whole episode.

Observed timeline for one device key ("Fast Pike", 532 configs):

```text
+00:00  sweep starts, concurrency 8, no pacing
+02:30  first failure, at completion #219
+03:44  sweep ends: 456 ok / 76 failed
+13:00  retry of the 76 from the same host:            0/76
+30:00  full sweep from a second host, direct internet: 0/532
+40:00  single canary on a slot that had just worked:   fail
+70:00  canary every 5 minutes, six attempts:          all fail
```

The key did not recover within roughly an hour of the last bulk activity, so this
behaves less like a short cooldown and more like a longer-lived block on the
device. If a key stops handshaking on every relay while another key on the same
network keeps working, check whether the device still exists in the provider
account and, if in doubt, create a fresh device and download a new bundle rather
than waiting.

### Consequences

- This run alone proves 456 distinct exit IPs. Read together with the relay-socks
  rows in the log above, the practical ceiling for this bundle is **at least 529
  and plausibly all 532**. The 76 slots that failed here stayed unverified in this
  mode: by the time they could be retried, the key was already blocked, so their
  status is unknown rather than bad.
- Verify a large catalog in small paced batches spread over hours, and stop at the
  first sign of rising failures instead of pushing through them.
- Sweep large catalogs with `-interval` (e.g. `-interval 2s -concurrency 2`),
  ideally split across several sessions, and expect a full 532-slot inventory to
  take hours rather than minutes.
- Do not treat a probe failure as evidence that a relay is dead. Re-probe later
  with `-slots-file` before writing a slot off.
- Serving traffic is unaffected by this: the pool opens a tunnel only when a
  request needs one, and `max_active` keeps the handshake rate low. The limit is
  a bulk-measurement problem, not a runtime one.

## Sizing guidance

A container with **1 vCPU and 1.5–2 GiB RAM** can hold the entire 532-slot
catalog open. There is no need for one container per exit, nor for network
namespaces: the limiting factor is memory per open tunnel, and it is small.

Start with `max_active: 25`, watch RSS and the `open_tunnels` gauge in
`/v1/stats`, then raise it. Keep in mind:

- Throughput is userspace, so a single tunnel is slower than kernel WireGuard.
  This is a trade for isolation and zero host configuration.
- CPU scales with traffic, not with idle tunnel count. Idle tunnels only send a
  keepalive every 25 s.
- The number of slots is an upper bound on distinct exit IPs, never a substitute
  for one. Run
  `global-egress probe` to measure the real number before promising `uniq=`
  batches of a given size.
