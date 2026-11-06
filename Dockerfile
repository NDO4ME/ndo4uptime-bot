# syntax=docker/dockerfile:1
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/ndo4uptime /ndo4uptime && mkdir /data

# cloudflared (optional Cloudflare Tunnel, enabled from Settings). Pinned and checksum-verified.
FROM alpine:3 AS cf
ARG TARGETARCH
ARG CF_VERSION=2026.10.7
ARG CF_SHA256_AMD64=1f99fb518b83dec2ba8d870a7cc991d82a77e6196295a3d2754ba17ab9f91872
ARG CF_SHA256_ARM64=3df43aedc9ff291d1735b5cb576cb97e0b157488796db2e32b28aecabb445775
RUN apk add --no-cache ca-certificates curl && \
    case "$TARGETARCH" in arm64) SUM=$CF_SHA256_ARM64 ;; *) TARGETARCH=amd64; SUM=$CF_SHA256_AMD64 ;; esac && \
    curl -fsSL -o /cloudflared "https://github.com/cloudflare/cloudflared/releases/download/${CF_VERSION}/cloudflared-linux-${TARGETARCH}" && \
    echo "${SUM}  /cloudflared" | sha256sum -c - && chmod 0555 /cloudflared

FROM scratch
COPY --from=build /ndo4uptime /ndo4uptime
COPY --from=cf /cloudflared /cloudflared
COPY --from=cf /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=10001:10001 /data /data
USER 10001:10001
ENV NDO4_BIND=0.0.0.0:8589 NDO4_PUBLIC_BIND=0.0.0.0:8590 NDO4_DATA=/data NDO4_CLOUDFLARED=/cloudflared
EXPOSE 8589 8590
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/ndo4uptime", "healthcheck"]
ENTRYPOINT ["/ndo4uptime"]
