# Docker / Compose

Unprivileged single-container deploy. Userspace WireGuard needs no
`/dev/net/tun`, no `NET_ADMIN`, and no root.

## Quick start

```sh
cd deploy/docker
cp config.example.toml config.toml
printf 'changeme\n' > proxy-password
# config.example.toml sets access.control_token_file, so this file is required:
# serve refuses to start without it, and the health check authenticates with it.
openssl rand -hex 32 > control-token
# Every secret is read by uid 65532 inside the container. Hand ownership to that
# uid and strip group/other access instead of leaving files world-readable:
# mode 644 lets any local user (and any other container mounting the directory)
# read your proxy password and control token.
sudo chown 65532:65532 proxy-password control-token
sudo chmod 600 proxy-password control-token
mkdir -p catalog
# copy provider .conf files into catalog/, or drop a .zip there and set
# catalog.path under [providers.catalog] in config.toml to the zip path under /catalog/...
# The catalog holds WireGuard private keys, so lock it down the same way:
# mode 700 on the directory, 600 on every key file.
sudo chown -R 65532:65532 catalog
sudo chmod 700 catalog
sudo find catalog -type f -exec chmod 600 {} +

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
| `proxy-password` | `/etc/global-egress/proxy-password` | owned by uid 65532, mode `0600` |
| `control-token` | `/etc/global-egress/control-token` | required by `access.control_token_file`; owned by uid 65532, mode `0600` |
| `catalog/` | `/catalog` | WireGuard key material; dir mode `0700`, files `0600`, owned by uid 65532 |
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

## Health check

The image is distroless: no shell, no `curl`, no `wget`. The binary probes itself
instead, and the container health status is its exit code.

```sh
docker compose ps                     # STATUS shows (healthy) once /healthz answers
docker inspect --format '{{json .State.Health}}' <container> | jq
```

| Flag | Default | Purpose |
|---|---|---|
| `-url` | `http://127.0.0.1:8080/healthz` | endpoint to probe |
| `-timeout` | `2s` | bound the probe so Docker never has to kill it |
| `-token-file` | none | file holding the control API bearer token |

The **image** ships a tokenless default `HEALTHCHECK` against
`http://127.0.0.1:8080/healthz`, which is right for a deployment that configures
no control token.

The **compose service overrides it** to pass `-token-file`, because
`config.example.toml` sets `access.control_token_file`. A configured control token
is verified on every control request, including `GET /healthz`: the
mutating-auth policy decides when a token is *required*, not whether an existing
one is *checked*. So an unauthenticated probe against a token-configured instance
gets `401`, and Docker would report a perfectly healthy container as unhealthy
after three retries.

`access.allowed_clients` needs no loopback entry for this probe: the control
API treats loopback as inside the trust boundary, so an ACL naming only remote
CIDRs - as `config.example.toml` does with `172.16.0.0/12` - still lets the
in-container probe through. Bearer-token auth still applies to loopback
requests, which is why `-token-file` is required.

The probe reads the secret from the mounted file, never from a flag value, so it
stays out of the image, the compose file and `docker inspect`:

```yaml
    volumes:
      - ./control-token:/etc/global-egress/control-token:ro
    healthcheck:
      test:
        ["CMD", "/usr/local/bin/global-egress", "healthcheck",
         "-token-file", "/etc/global-egress/control-token"]
```

If you remove `access.control_token_file` from `config.toml`, drop the flag and
the mount together; the two are checked against each other by
`internal/config` tests, so they cannot drift apart silently.

Use the exec form (`["CMD", ...]`), not the shell form (`CMD-SHELL`): there is no
`/bin/sh` in the image to interpret it. A shell-form probe fails with
`exec: "/bin/sh": stat /bin/sh: no such file or directory` and the container is
reported unhealthy while it is serving normally. `docker run --health-cmd` always
uses the shell form, so verify health through Compose or the image default rather
than that flag.

Every mounted secret must be readable by uid `65532`. A host file at mode `600`
owned by another user makes `serve` exit with
`config: read secret ...: permission denied` before it opens a listener, and the
container restarts in a loop rather than reporting unhealthy.

The tradeoff of `chown 65532:65532` is that the files stop belonging to your host
user: reading or rotating them later needs `sudo`, and your editor or backup
tools can no longer touch them directly. That is the point. The container needs
read access and nothing else does, so owner-only `0600` is the smallest
permission that works. Don't reach for `644` just to spare yourself the
`sudo`: bind mounts share the host's uid map, so a world-readable mode
exposes the secret to every local account and every other container that mounts
the directory. If several host admins genuinely need shared read access, use a
dedicated group (`chown 65532:<group>`, mode `0640`) rather than opening the
files to everyone.

## Sizing

Start with `pool.max_active = 25` and about **1 GiB** RAM (compose default). A full
catalog of idle tunnels wants closer to 1.5–2 GiB; raise `mem_limit` and
`max_active` together. See [docs/capacity.md](../../docs/capacity.md).

## Kubernetes sketch

The same image runs as a Deployment with three ports, three volume mounts
(config ConfigMap/Secret, password Secret, catalog Secret or PVC, state PVC),
and no capabilities. Do not expose the Service outside a private network; set
`access.allowed_clients` to the pod/service CIDRs that should call the proxy.
