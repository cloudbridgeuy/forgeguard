# Dependency Constraints

## Pingora Version Pins

Pingora 0.8 transitively pins several dependencies. Upgrading these independently creates duplicate crate versions or silent runtime breakage.

| Dependency | Pinned Version | Constraint |
|---|---|---|
| `rand` | 0.8 | Pingora depends on `rand` 0.8 / `rand_core` 0.6. `ed25519-dalek` 2.x also requires `rand_core` 0.6. Upgrading `rand` to 0.10 (`rand_core` 0.10) breaks `ed25519-dalek::SigningKey::generate()` at runtime. |
| `prometheus` | 0.13 | Pingora's `PrometheusServer` scrapes from the 0.13 default registry. Upgrading to 0.14 creates a second registry — ForgeGuard metrics silently vanish from `/metrics`. |

**Resolution:** wait for Pingora to upgrade these transitives, then bump together.

## jsonwebtoken 10 Crypto Provider

`jsonwebtoken` 10 removed built-in crypto — it requires an explicit `CryptoProvider`. The workspace uses the `aws_lc_rs` feature since `aws-lc-rs` is already in the dependency tree via AWS SDKs.

```toml
jsonwebtoken = { version = "10", features = ["aws_lc_rs"] }
```

Without this feature, compilation succeeds but tests panic at runtime:

```
Could not automatically determine the process-level CryptoProvider from jsonwebtoken crate features.
```

## reqwest 0.13 TLS Backend

`reqwest` 0.13 dropped `native-tls` (OpenSSL) in favor of `rustls`. System OpenSSL certificates are no longer used — the `webpki-root-certs` bundle is used instead. This also removed `openssl`, `openssl-sys`, `hyper-tls`, and `tokio-native-tls` from the dependency tree.
