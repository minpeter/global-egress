---
packages:
  github.com/minpeter/global-egress:
    type: patch
---

## Distinguish proxy acquisition timeouts

Return HTTP 504 when proxy acquisition ends on a context deadline. Pool
exhaustion and unknown failures remain HTTP 502, so clients can rotate stalled
exits without broadening retries for ordinary upstream failures.
