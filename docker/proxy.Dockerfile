FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY crates/ crates/
COPY xtask/ xtask/
RUN cargo chef prepare --recipe-path recipe.json --bin forgeguard-proxy

FROM chef AS builder
RUN apt-get update && apt-get install -y cmake clang libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY crates/ crates/
COPY xtask/ xtask/

RUN cargo build --release --bin forgeguard-proxy

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/forgeguard-proxy /usr/local/bin
ENTRYPOINT ["/usr/local/bin/forgeguard-proxy"]
