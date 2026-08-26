# syntax=docker/dockerfile:1

# Multi-stage build: static binary into a distroless image.
# Userspace WireGuard needs no /dev/net/tun, NET_ADMIN, or root.

ARG GO_VERSION=1.25.13

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build -trimpath \
	-ldflags "-X main.version=${VERSION} -s -w" \
	-o /out/global-egress ./cmd/global-egress

# Empty state tree owned by distroless nonroot (uid 65532) so a named volume
# seeded from the image is writable on first start.
RUN mkdir -p /out/state && chown -R 65532:65532 /out/state

# CA certs for Mullvad relay list and IP measurement; no shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="global-egress" \
	org.opencontainers.image.description="Rotating WireGuard egress proxy (SOCKS5 + HTTP)" \
	org.opencontainers.image.source="https://github.com/minpeter/global-egress" \
	org.opencontainers.image.licenses="MIT"

# Seed before USER so ownership sticks for anonymous/named volume first mounts.
COPY --from=build --chown=nonroot:nonroot /out/state /var/lib/global-egress
COPY --from=build --chown=nonroot:nonroot /out/global-egress /usr/local/bin/global-egress

USER nonroot:nonroot

EXPOSE 1080 3128 8080

ENTRYPOINT ["/usr/local/bin/global-egress"]
CMD ["serve", "-config", "/etc/global-egress/config.toml"]
