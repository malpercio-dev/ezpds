# syntax=docker/dockerfile:1

# ---- build stage ----
FROM rust:1-bookworm@sha256:19817ead3289c8c631c73df281e18b59b172f6a31f4f563290f69cddd06c30e9 AS build
WORKDIR /src
# Whole (ignore-trimmed) workspace — needed because cargo resolves all members
# and the swift-rs [patch.crates-io] path even for `-p relay`.
COPY . .
# Bundled SQLite: LIBSQLITE3_SYS_USE_PKG_CONFIG is intentionally NOT set, so
# libsqlite3-sys compiles SQLite from source. rustls means no OpenSSL needed.
# --locked uses the committed Cargo.lock for reproducibility.
RUN cargo build --release --locked -p relay

# ---- runtime stage ----
FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716 AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*
# Non-root runtime user; /data is the default data dir (mount a volume here).
RUN useradd --system --uid 10001 --user-group --create-home --home-dir /data relay
COPY --from=build /src/target/release/relay /usr/local/bin/relay
ENV EZPDS_DATA_DIR=/data \
    RUST_LOG=info
# Documentation only; the actual listen port comes from EZPDS_PORT/$PORT at runtime.
EXPOSE 8080
USER relay
ENTRYPOINT ["/usr/local/bin/relay"]
