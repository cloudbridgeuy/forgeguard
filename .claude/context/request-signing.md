# Request Signing (Ed25519)

Ed25519 asymmetric signatures over outbound `X-ForgeGuard-*` identity headers. Provides cryptographic proof that a request came from the proxy — upstreams can verify signatures using the proxy's public key.

## Mechanism

```
Proxy (private key)                          Upstream (public key)
─────────────────                            ────────────────────
1. Resolve identity → X-ForgeGuard-* headers
2. Generate trace-id (UUID v7)
3. Build canonical payload (v1 format)
4. Sign(private_key, canonical) → signature
5. Inject signature headers
                                             6. Reconstruct canonical payload
                                             7. Verify(public_key, canonical, sig)
```

### Canonical Payload Format (v1)

```text
forgeguard-sig-v1\n
trace-id:{uuid}\n
timestamp:{unix_millis}\n
{header-name}:{value}\n   (sorted lexicographically by name)
```

Headers are sorted by name for determinism regardless of insertion order.

### Injected Headers

| Header | Value | Purpose |
|--------|-------|---------|
| `X-ForgeGuard-Signature` | `v1:{base64(ed25519_sig)}` | The signature |
| `X-ForgeGuard-Timestamp` | `{unix_millis}` | Replay detection |
| `X-ForgeGuard-Trace-Id` | UUID v7 | Per-request uniqueness |
| `X-ForgeGuard-Key-Id` | Configured key ID | Key rotation support |

## Crate Placement (FCIS)

### Inlined copy in xtask

The `xtask` crate carries its own copy of the narrow signing surface at
`xtask/src/signing.rs`. This keeps xtask free of a workspace path dependency on
`forgeguard_authn_core`. `xtask/tests/signing_compat.rs` signs a payload with
the inlined code and verifies it with `forgeguard_authn_core::signing::verify`
as a drift-prevention check. If the canonical payload format changes, update
both copies in the same PR.

| What | Where | Why |
|------|-------|-----|
| `KeyId`, `Timestamp`, `SigningKey`, `VerifyingKey`, `CanonicalPayload`, `SignedPayload`, `TimestampValidator`, `sign()`, `verify()`, `parse_signature_header()` | `authn-core` (pure) | No I/O, reusable by proxy and future SDK |
| `SigningConfig`, `RawSigningConfig` | `http` (pure) | Config parsing, TOML shape |
| `inject_signed_headers()` | `http` (pure) | Extends `inject_headers()` with optional signing |
| Private key loading from PEM file | `proxy` (I/O) | File I/O at startup |
| `forgeguard keygen` subcommand | `cli` (I/O) | Key generation with `rand` |

## Configuration

```toml
[signing]
key_path = "./keys/forgeguard.private.pem"   # PKCS#8 PEM
key_id = "proxy-prod-2026-04"                # identifies which key signed
```

Optional — when absent, no signing occurs and behavior is unchanged.

### Key Generation

```bash
forgeguard keygen --out-dir ./keys [--key-id ID] [--force]
```

Generates `forgeguard.private.pem` (PKCS#8) and `forgeguard.public.pem` (SPKI). Auto-generates key ID (`fg-{YYYYMMDD}-{hex}`) if not provided. Sets 0600 permissions on private key (Unix). Creates the output directory if it doesn't exist.

## Key Rotation

Upstream config accepts multiple public keys. Zero-downtime rotation:

1. Generate new keypair
2. Add new public key to upstream's trusted set
3. Switch proxy to new private key (config change + restart)
4. Retire old public key after grace period

## Upstream Verification (Python demo)

The demo app (`examples/todo-app/app.py`) verifies signatures when `FORGEGUARD_PUBLIC_KEY` env var points to the public key PEM. Uses the `cryptography` Python package. Every authenticated response includes `"signature_verified": true/false` in the identity object.

## Inbound Verification (Control Plane)

The control plane verifies signed requests from BYOC proxies using the same Ed25519 keys. See [control-plane.md](./control-plane.md) for the full flow.

`Credential::SignedRequest` (in `authn-core`) is the inbound credential type. `Ed25519SignatureResolver` (in `authn`) performs the verification using `DynamoSigningKeyStore` (in `control-plane`).

## Future Scope (deferred)

| Item | Issue | Notes |
|------|-------|-------|
| Body hashing | #34 | Canonical payload includes body hash for POST |
| SDK `verify()` wiring | #39 | Pure function exists, wiring deferred |

## Integration Tests

Two tests in `crates/proxy/tests/integration.rs`:

- `signing_injects_signature_headers` — verifies all four signature headers are present
- `signing_signature_verifies` — full round-trip: reconstructs canonical payload from echo response, verifies signature with public key
