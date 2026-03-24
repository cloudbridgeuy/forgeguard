# forgeguard_sdk

ForgeGuard SDK core library. This is a **pure crate** — no I/O dependencies. Must compile to `wasm32-unknown-unknown`.

Owns the Guard (authorization checks), WebhookHandler (signature verification), feature flag evaluation, token handling types, and retry logic. HTTP and storage are injected via traits — FFI wrappers provide platform-specific implementations.
