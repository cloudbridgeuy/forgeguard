# forgeguard_authn

Authentication I/O layer for ForgeGuard. This is an **I/O crate** — it depends on pure crates and adds side effects.

Owns the Cognito adapter (translates typestate transitions into Cognito API calls), SES/SNS side effect executor (emails, SMS), DynamoDB challenge storage, and Lambda trigger handlers.
