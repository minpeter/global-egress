# Docker / Compose

Unprivileged single-container deploy. Userspace WireGuard needs no
`/dev/net/tun`, no `NET_ADMIN`, and no root.

## Quick start

```sh
cd deploy/docker
cp config.example.toml config.toml
printf 'changeme\n' > proxy-password
chmod 600 proxy-password
mkdir -p catalog
# copy provider .conf files into catalog/, or drop a .zip there and set
# catalog.path under [providers.catalog] in config.toml to the zip path under /catalog/...

# build locally
docker compose up -d --build

# or pull a release image
# GLOBAL_EGRESS_IMAGE=ghcr.io/minpeter/global-egress:vX.Y.Z docker compose up -d
```

Clients (from the host):

```sh
# policy rides in the username; password is the shared secret
curl -x socks5h://cc=jp:changeme@127.0.0.1:1080 https://am.i.mullvad.net/ip
curl -x http://cc=jp:changeme@127.0.0.1:3128 https://am.i.mullvad.net/ip
```

## Layout

| Host path | Container path | Notes |
|---|---|---|
| `config.toml` | `/etc/global-egress/config.toml` | required |
| `proxy-password` | `/etc/global-egress/proxy-password` | mode 600 |
| `catalog/` | `/catalog` | WireGuard key material; keep private |
| named volume `state` | `/var/lib/global-egress` | IP inventory + relay cache |

The image user is distroless `nonroot` (uid 65532). The image seeds
`/var/lib/global-egress` with that ownership so a **named** volume copied from
the image is writable on first start. If you **bind-mount** a host directory for
state instead, `chown 65532:65532` it first.

## Image

```sh
# from repo root
docker build -t global-egress:local --build-arg VERSION=$(git describe --tags --always) .
docker run --rm global-egress:local version
```

Merge a Tegami **Version Packages** PR (see README *Cutting a release*). That
creates a `vX.Y.Z` tag, attaches static binaries to the GitHub Release, and
publishes multi-arch images:

- `ghcr.io/minpeter/global-egress:latest`
- `ghcr.io/minpeter/global-egress:X.Y.Z` (and `:vX.Y.Z`)

## Sizing

Start with `pool.max_active = 25` and about **1 GiB** RAM (compose default). A full
catalog of idle tunnels wants closer to 1.5–2 GiB; raise `mem_limit` and
`max_active` together. See [docs/capacity.md](../../docs/capacity.md).

## Kubernetes sketch

The same image runs as a Deployment with three ports, three volume mounts
(config ConfigMap/Secret, password Secret, catalog Secret or PVC, state PVC),
and no capabilities. Do not expose the Service outside a private network; set
`access.allowed_clients` to the pod/service CIDRs that should call the proxy.
