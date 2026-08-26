---
packages:
  "github.com/minpeter/global-egress": patch
---

## Split request timeouts by phase, and expose entry rotation health

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
