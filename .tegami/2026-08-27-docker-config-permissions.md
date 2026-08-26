---
packages:
  github.com/minpeter/global-egress:
    type: patch
---

## Keep Docker configuration private and readable

Include `config.toml` in the uid 65532 ownership and mode `0600` handoff so the nonroot container can read configuration created under the restrictive umask.
