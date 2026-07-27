# syntax=docker/dockerfile:1

# The notification relay. The repo-root Dockerfile builds a single binary (`-p pds`), so
# the relay ships its own image: the same builder pattern pointed at `-p notify-relay`.
#
# Build context is the REPO ROOT — cargo resolves every workspace member and the swift-rs
# [patch.crates-io] path even for a single `-p`.
#
# Deliberately absent versus the pds image: Litestream. The relay's database is
# disposable — every row in it is rebuilt when instances re-enroll — while the node secret
# key is not, since it is the relay's address. Hence the entrypoint's secret handling
# rather than a replication sidecar.
#
# Operator runbook: docs/operations/self-relay-runbook.md.

# ---- build stage ----
FROM rust:1-bookworm@sha256:19817ead3289c8c631c73df281e18b59b172f6a31f4f563290f69cddd06c30e9 AS build
# cmake: required to build aws-lc-sys, the crypto provider behind reqwest 0.13's rustls TLS
# backend (rustls is also what ALPN-negotiates h2 against api.push.apple.com).
RUN apt-get update && apt-get install -y --no-install-recommends cmake && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Bundled SQLite: LIBSQLITE3_SYS_USE_PKG_CONFIG is intentionally NOT set, so libsqlite3-sys
# compiles SQLite from source. --locked uses the committed Cargo.lock for reproducibility.
RUN cargo build --release --locked -p notify-relay

# ---- runtime stage ----
FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716 AS runtime
# ca-certificates: the APNs leg is TLS to api.push.apple.com. gosu: privilege-drop helper
# for the entrypoint, since a fresh volume mount is root-owned. sqlite3: inspecting the
# relay's own database (enrollments, handles) during troubleshooting.
# Versions are unpinned for the same reason as the pds image (Hadolint DL3008): the base
# image is digest-pinned, but apt version pins rot on every Debian point release.
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata gosu sqlite3 \
 && rm -rf /var/lib/apt/lists/*
# Non-root runtime user. Home is /home/relay so a
# root-owned /data mount cannot break user resolution.
RUN useradd --uid 10001 --user-group --create-home --home-dir /home/relay --shell /usr/sbin/nologin relay
COPY --from=build /src/target/release/notify-relay /usr/local/bin/notify-relay
COPY crates/notify-relay/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
# The database and the node secret key both live on the mounted volume. The APNs .p8 is
# written to /run/notify-relay by the entrypoint instead — container-local and ephemeral,
# so the credential is never persisted to a volume that outlives the deploy.
ENV EZPDS_NOTIFY_DATABASE_URL=/data/notify-relay.db \
    EZPDS_NOTIFY_SECRET_KEY_PATH=/data/notify-relay-node.key \
    RUST_LOG=info
# No EXPOSE and no HEALTHCHECK: the relay serves no TCP port. It speaks QUIC over iroh and
# is dialed by node id, reachable through iroh's relay servers without inbound ingress —
# so there is nothing for a port probe or an HTTP health check to talk to. Liveness is the
# process itself; supervise it with a restart policy, not a probe.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
