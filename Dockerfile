# syntax=docker/dockerfile:1

# ---- build stage ----
FROM rust:1-bookworm@sha256:19817ead3289c8c631c73df281e18b59b172f6a31f4f563290f69cddd06c30e9 AS build
WORKDIR /src
# Whole (ignore-trimmed) workspace — needed because cargo resolves all members
# and the swift-rs [patch.crates-io] path even for `-p pds`.
COPY . .
# Bundled SQLite: LIBSQLITE3_SYS_USE_PKG_CONFIG is intentionally NOT set, so
# libsqlite3-sys compiles SQLite from source. rustls means no OpenSSL needed.
# --locked uses the committed Cargo.lock for reproducibility.
RUN cargo build --release --locked -p pds

# ---- runtime stage ----
FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716 AS runtime
# gosu: privilege-drop helper used by the entrypoint to hand off to the relay user
# after fixing /data ownership (Railway Volumes mount as root:root).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata gosu curl \
 && rm -rf /var/lib/apt/lists/*
# Non-root runtime user. Home is /home/relay (not /data) so that a root-owned
# volume mount on /data does not prevent login shell resolution.
RUN useradd --uid 10001 --user-group --create-home --home-dir /home/relay --shell /usr/sbin/nologin relay
# Litestream: continuous SQLite replication + restore-on-boot. Active only when
# LITESTREAM_REPLICA_URL is set (production); see docker-entrypoint.sh.
ARG LITESTREAM_VERSION=0.3.13
RUN curl -fsSL "https://github.com/benbjohnson/litestream/releases/download/v${LITESTREAM_VERSION}/litestream-v${LITESTREAM_VERSION}-linux-amd64.tar.gz" \
    | tar -xz -C /usr/local/bin litestream
COPY --from=build /src/target/release/pds /usr/local/bin/pds
COPY litestream.yml /etc/litestream.yml
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENV EZPDS_DATA_DIR=/data \
    RUST_LOG=info
# Documentation only; the actual listen port comes from EZPDS_PORT/$PORT at runtime.
EXPOSE 8080
# Entrypoint runs as root, chowns /data to relay, then execs the binary as relay (via gosu).
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
