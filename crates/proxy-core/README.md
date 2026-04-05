# forgeguard_proxy_core

Auth pipeline types and pure logic for ForgeGuard proxy. This is a **pure crate** — no I/O dependencies.

Owns `PipelineOutcome` (the closed result enum for auth pipeline runs) and `PipelineConfig`. Protocol adapters pattern-match on `PipelineOutcome` to produce framework-specific responses. I/O concerns (upstream communication, identity resolution, authorization checks) live in the `forgeguard_proxy` and `forgeguard_proxy_saas` I/O crates.
