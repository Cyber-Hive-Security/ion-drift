# Stage 1: Build Rust binary
FROM rust:1-bookworm AS rust-builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY data/ data/
RUN cargo build --release --bin ion-drift-web

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
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=rust-builder /build/target/release/ion-drift-web ./
COPY --from=node-builder /build/web/dist ./web/dist/
COPY config/production.toml ./config/server.toml
COPY docker/root_ca.crt ./certs/root_ca.crt

ENV RUST_LOG=info
ENV XDG_DATA_HOME=/app/data

EXPOSE 3000
CMD ["./ion-drift-web", "--config", "/app/config/server.toml"]
