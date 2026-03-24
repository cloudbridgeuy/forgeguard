# forgeguard_audit

Auditing I/O layer for ForgeGuard. This is an **I/O crate** — it depends on pure crates and adds side effects.

Owns the DynamoDB event log writer (hot storage, 90 days), S3 cold storage archiver, CloudTrail integration, and metric emission via tracing.
