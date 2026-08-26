---
packages:
  "github.com/minpeter/global-egress": patch
---

## Date every exit-IP measurement, and separate slot count from measured IPs

The README, `docs/operations.md` and `docs/capacity.md` each quoted a different
"definitive" unique-IP total (456, 524, 529) for the same 532-slot bundle, with no
date, mode or device attached. They now share one measurement log in
`docs/capacity.md`, where every row carries its date, mode, bundle and run
parameters, and the surviving claim is "one measured address per reachable exit,
zero duplicates" rather than any single total.

Documents also stop standing in for the running service: slot count is a catalogue
property, while `slots_with_known_ip` and `unique_public_ips` in `/v1/stats` (plus
`/v1/ips`) are the current measured state that `uniq=` batches draw on.
