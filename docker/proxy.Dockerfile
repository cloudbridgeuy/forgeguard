FROM lukemathwalker/cargo-chef:latest-rust-1.91.1 AS chef
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY xtask/ xtask/
RUN cargo chef prepare --recipe-path recipe.json --bin forgeguard-proxy

FROM chef AS builder
RUN apt-get update && \
    apt-get install -y --no-install-recommends cmake clang libssl-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY xtask/ xtask/
RUN cargo build --release --bin forgeguard-proxy

# Extract only the runtime SSL shared libraries (arch-agnostic via shell glob)
FROM debian:bookworm-slim AS deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN mkdir /runtime-libs && \
    cp /usr/lib/*/libssl.so.3 /runtime-libs/ && \
    cp /usr/lib/*/libcrypto.so.3 /runtime-libs/

# Distroless: ~20MB base with glibc + libgcc. Non-root user (uid 65534) built-in.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
COPY --from=deps /runtime-libs/ /usr/lib/
COPY --from=deps /etc/ssl/certs/ /etc/ssl/certs/
COPY --from=builder /app/target/release/forgeguard-proxy /usr/local/bin/

ENV LD_LIBRARY_PATH=/usr/lib
ENV FORGEGUARD_LISTEN=0.0.0.0:8080
EXPOSE 8080

# Health endpoint: GET /.well-known/forgeguard/health → 200 OK
# Distroless has no shell — configure health checks in your orchestrator:
#   Kubernetes: livenessProbe.httpGet.path: /.well-known/forgeguard/health
#   ECS: healthCheck.command: ["CMD", "/usr/local/bin/forgeguard-proxy", "..."]
#   docker-compose: healthcheck.test: ["CMD", "wget", ...] (use a sidecar)

ENTRYPOINT ["/usr/local/bin/forgeguard-proxy"]
