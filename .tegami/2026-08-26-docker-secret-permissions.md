---
packages:
  "github.com/minpeter/global-egress": patch
---

## Stop recommending world-readable Docker secrets

Replace the `chmod 644` instruction in the Docker deploy guide with a least-privilege flow: uid 65532 ownership with mode `0600` on `proxy-password` and `control-token`, mode `0700` on the catalog directory, and `0600` on provider key files, plus an explanation of the host-ownership tradeoff.
