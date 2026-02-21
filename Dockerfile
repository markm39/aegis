# ---------------------------------------------------------------------------
# Aegis -- multi-stage Docker build
# ---------------------------------------------------------------------------
# Build:  docker build -t aegis .
# Run:    docker run -d --name aegis \
#           -v ~/.aegis:/home/aegis/.aegis \
#           -p 8080:8080 -p 9090:9090 \
#           aegis
#
# Environment variables (all optional):
#   AEGIS_HTTP_LISTEN   HTTP control server address   (default: 0.0.0.0:8080)
#   AEGIS_API_KEY       Bearer token for HTTP auth    (default: empty/no auth)
#   AEGIS_LOG_LEVEL     Tracing filter                (default: info)
#
# Any configuration value can be overridden with AEGIS_* env vars.
# See docs or `aegis setup --help` for the full list.
# ---------------------------------------------------------------------------

# ---- Builder stage --------------------------------------------------------
FROM rust:slim-bookworm AS builder

# Install build-time dependencies (C compiler, pkg-config for native crates)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first to cache dependency compilation
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates

# Build release binary. rusqlite uses the "bundled" feature so SQLite is
# statically compiled -- no runtime libsqlite3 dependency.
RUN cargo build --release --bin aegis && \
    strip target/release/aegis

# ---- Runtime stage --------------------------------------------------------
FROM debian:bookworm-slim

# Install minimal runtime dependencies.
# ca-certificates: TLS for outbound HTTPS (Telegram, webhooks).
# curl:            used by the HEALTHCHECK directive.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user -- never run as root.
RUN groupadd --gid 1000 aegis && \
    useradd --uid 1000 --gid aegis --create-home aegis

# Copy the release binary from the builder stage.
COPY --from=builder /build/target/release/aegis /usr/local/bin/aegis

# Create the default config/data directory and make it writable by aegis.
RUN mkdir -p /home/aegis/.aegis && chown -R aegis:aegis /home/aegis/.aegis

USER aegis
WORKDIR /home/aegis

# HTTP control server and dashboard gateway.
EXPOSE 8080 9090

# Health check against the HTTP status endpoint.
# Requires AEGIS_HTTP_LISTEN to include port 8080 (the default in Docker).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8080/v1/status || exit 1

# Default: start the daemon in foreground mode.
CMD ["aegis", "daemon", "start", "--foreground"]
