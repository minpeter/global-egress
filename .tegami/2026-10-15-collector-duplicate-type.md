---
packages:
  github.com/minpeter/global-egress:
    type: patch
---

## Keep the textfile collector parseable and stoppable

The collector no longer redeclares a `/v1/stats` field that `/v1/metrics`
already exports. A second `# TYPE` line made node_exporter's textfile
collector reject the whole file, so every Global Egress Proxy panel showed
No data. The daemon now exits on SIGTERM and removes its temporary output,
so `rc-service global-egress-metrics restart` replaces the running process.
