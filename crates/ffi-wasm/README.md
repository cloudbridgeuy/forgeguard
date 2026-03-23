# forgegate_ffi_wasm

ForgeGate TypeScript SDK via WASM bindings. This is an **I/O crate** — it wraps the pure `forgegate_sdk` crate with platform-specific I/O for browser and Node.js environments.

Built with wasm-pack. Implements the SDK's platform traits with `web-sys`/`js-sys` for HTTP.
