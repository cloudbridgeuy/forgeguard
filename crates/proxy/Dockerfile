# ForgeGuard Proxy — Multi-stage Docker build
# =============================================
# Builds a minimal container for the Pingora-based proxy.
# Pingora requires Linux — this is how macOS users run the proxy.

# --- Builder ---
FROM rust:1.82-bookworm AS builder

WORKDIR /src
COPY . .

RUN cargo build --release --bin forgeguard-proxy

# --- Runtime ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/forgeguard-proxy /usr/local/bin/forgeguard-proxy

ENTRYPOINT ["forgeguard-proxy"]
CMD ["run", "--config", "/etc/forgeguard/forgeguard.toml"]
