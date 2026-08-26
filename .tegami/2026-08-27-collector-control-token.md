---
packages:
  "github.com/minpeter/global-egress": patch
---

## Authenticate the metrics collector

Allow the node-exporter collector to read a protected control token file and authenticate every read-only control API request without exposing the bearer in argv, logs, or Prometheus output.
