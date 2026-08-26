---
packages:
  github.com/minpeter/global-egress:
    type: patch
---

## Fail closed for remote control mutations

Require bearer authentication for mutating control API requests received from
non-loopback clients, while preserving the existing read-only endpoint policy.
