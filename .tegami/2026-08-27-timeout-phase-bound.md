---
packages:
  "github.com/minpeter/global-egress": patch
---

## Clamp timeout-phase metrics to the closed set

`TimeoutPhase` is a string alias, so a caller can pass any value into
`ObserveRequest`. The scrape still has to emit only `acquire`, `upstream`, or
`unknown`: a free-form `phase` label would grow with whoever typed it.

The metrics boundary now switches on the closed set and records anything else
as `unknown`. Empty and omitted phases already landed there; out-of-set values
now do too. No new label was added.
