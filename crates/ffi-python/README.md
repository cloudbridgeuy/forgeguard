# forgegate_ffi_python

ForgeGate Python SDK via PyO3 bindings. This is an **I/O crate** — it wraps the pure `forgegate_sdk` crate with platform-specific I/O for native Python environments.

Built with maturin. Implements the SDK's platform traits with `reqwest` for HTTP.
