---
packages:
  "github.com/minpeter/global-egress": patch
---

## Create Docker secrets privately from the first write

Set a restrictive umask before creating Docker secrets and create the provider catalog at mode `0700` before placing key material in it, closing the exposure window before the final ownership and permission hardening commands run.
