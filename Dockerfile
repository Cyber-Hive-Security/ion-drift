# BUILD REQUIREMENTS: 8GB+ RAM, 4+ vCPU recommended.
# Rust release builds are memory-intensive — the compiler will be OOM-killed
# on hosts with less than 8GB of RAM. Use the pre-built image instead:
#   image: ghcr.io/cyber-hive-security/ion-drift:latest

# Stage 1: Build Rust binary
FROM rust:1-bookworm AS rust-builder
ARG VERSION=dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY data/ data/
RUN ION_DRIFT_VERSION=${VERSION} cargo build --release --bin ion-drift-web

# Stage 2: Build frontend
FROM node:22-bookworm-slim AS node-builder
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 3: Runtime
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates gosu curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r app && useradd -r -g app -d /app -s /sbin/nologin app

WORKDIR /app
COPY --from=rust-builder /build/target/release/ion-drift-web ./
COPY --from=node-builder /build/web/dist ./web/dist/
COPY docker/entrypoint.sh /entrypoint.sh

# Bundle default config — users can override via volume mount:
#   -v /path/to/server.toml:/app/config/server.toml:ro
#   -v /path/to/ca.crt:/app/certs/root_ca.crt:ro
RUN mkdir -p /app/config /app/certs /app/data/certs
COPY config/server.example.toml /app/config/server.toml
RUN chown -R app:app /app

ENV RUST_LOG=info
ENV XDG_DATA_HOME=/app/data

# Start as root; entrypoint fixes volume perms then drops to app user
ENTRYPOINT ["/entrypoint.sh"]
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1
CMD ["./ion-drift-web", "--config", "/app/config/server.toml"]
