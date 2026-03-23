FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY crates/ crates/
COPY xtask/ xtask/
RUN cargo chef prepare --recipe-path recipe.json --bin forgegate-back-office

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY crates/ crates/
COPY xtask/ xtask/

RUN cargo build --release --bin forgegate-back-office

FROM debian:bookworm-slim AS runtime
WORKDIR /app
COPY --from=builder /app/target/release/forgegate-back-office /usr/local/bin
ENTRYPOINT ["/usr/local/bin/forgegate-back-office"]
