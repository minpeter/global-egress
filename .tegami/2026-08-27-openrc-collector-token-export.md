---
packages:
  "github.com/minpeter/global-egress": patch
---

## Export the collector control token path

Pass `CONTROL_TOKEN_FILE` from the OpenRC confd into the metrics collector process so authenticated control scraping works after restart.
