# Container Image Builds

## Overview

Each binary crate has a Dockerfile under `docker/<name>.Dockerfile`. The release workflow
builds and pushes multi-platform images (`linux/amd64`, `linux/arm64`) to GHCR on tag push.

## Proxy Image (distroless)

The proxy image uses a four-stage build:

| Stage       | Base                                          | Purpose                              |
| ----------- | --------------------------------------------- | ------------------------------------ |
| `chef`      | `cargo-chef:latest-rust-<MSRV>`               | Shared Rust toolchain                |
| `planner`   | chef                                          | `cargo chef prepare` (dep recipe)    |
| `builder`   | chef + cmake/clang/libssl-dev                 | Compile release binary               |
| `deps`      | `debian:bookworm-slim`                        | Extract `libssl3` + `libcrypto3`     |
| `runtime`   | `gcr.io/distroless/cc-debian12:nonroot`       | ~20 MB, glibc + libgcc, uid 65534   |

### Why distroless

- **~60 MB smaller** than `debian:bookworm-slim` (~20 MB vs ~80 MB base).
- **Non-root by default** — `:nonroot` tag runs as uid 65534.
- **No shell** — reduces attack surface. No `sh`, `bash`, `apt`, etc.

### SSL library strategy

Pingora depends on OpenSSL via `native-tls` → `openssl-sys` (dynamic linking on Linux).
The `deps` stage installs `libssl3` on a matching Debian release, then copies only the
two `.so` files to a staging directory using a shell glob (`/usr/lib/*/libssl.so.3`).
This works across architectures because each platform build resolves the glob independently.

`LD_LIBRARY_PATH=/usr/lib` is set so the dynamic linker finds the copied libraries.

### Health checks

Distroless has no shell, so `HEALTHCHECK` cannot use `curl`. Configure health checks in
your orchestrator instead:

```yaml
# Kubernetes
livenessProbe:
  httpGet:
    path: /.well-known/forgeguard/health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 15

# ECS task definition
"healthCheck": {
  "command": ["CMD-SHELL", "curl -fsS http://localhost:8080/.well-known/forgeguard/health || exit 1"],
  "interval": 15,
  "timeout": 3,
  "retries": 3,
  "startPeriod": 10
}
```

### Container defaults

| Env var              | Default         | Purpose                                  |
| -------------------- | --------------- | ---------------------------------------- |
| `FORGEGUARD_LISTEN`  | `0.0.0.0:8080`  | Overrides config `listen_addr` in container |

The `EXPOSE 8080` directive documents the default port.

## Build optimisation

- **`.dockerignore`** at repo root excludes `target/`, `.git/`, `infra/`, docs, and dev
  config so the build context stays small.
- **cargo-chef** splits dependency compilation from source compilation for layer caching.
- **`--no-install-recommends`** on `apt-get install` avoids pulling unnecessary packages.

## Rust version pinning

The cargo-chef base image tag is pinned to the workspace MSRV (e.g., `latest-rust-1.91.1`).
`rust-toolchain.toml` at the repo root pins the same version for local dev and CI.

## Registry

Images are pushed to GHCR:

```
ghcr.io/<owner>/forgeguard-proxy:<version>
ghcr.io/<owner>/forgeguard-proxy:latest
```

The release workflow (`.github/workflows/release.yml`) handles tagging and push.
