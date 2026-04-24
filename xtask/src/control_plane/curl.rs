//! `cargo xtask control-plane curl` — make an Ed25519-signed HTTP request to the control plane.
//!
//! Generates the required signature headers from a private key and sends the
//! request via `reqwest`. Useful for manual QA of the machine principal →
//! Verified Permissions authorization flow.

use std::time::SystemTime;

use crate::signing::{sign, CanonicalPayload, KeyId, SigningKey, Timestamp};
use clap::Args;
use color_eyre::eyre::{self, Context, Result};

/// CLI arguments for the curl subcommand.
#[derive(Args)]
pub(crate) struct CurlArgs {
    /// Ed25519 key ID (from generate-key response).
    #[arg(long)]
    key_id: String,

    /// PEM private key: inline string or @filepath.
    #[arg(long)]
    private_key: String,

    /// Organization ID for the X-ForgeGuard-Org-Id header.
    #[arg(long)]
    org_id: String,

    /// Print request headers before sending.
    #[arg(long)]
    verbose: bool,

    /// HTTP method (e.g. GET, POST, PUT, DELETE).
    method: String,

    /// Target URL.
    url: String,
}

pub(crate) async fn run(args: &CurlArgs) -> Result<()> {
    let pem = if let Some(path) = args.private_key.strip_prefix('@') {
        std::fs::read_to_string(path)
            .with_context(|| format!("failed to read private key file '{path}'"))?
    } else {
        args.private_key.clone()
    };
    // `jq -r` appends a trailing newline when writing the PEM to disk, which
    // pem-rfc7468 rejects as invalid post-encapsulation whitespace.
    let signing_key =
        SigningKey::from_pkcs8_pem(pem.trim()).context("failed to parse Ed25519 private key")?;

    let key_id = KeyId::try_from(args.key_id.clone()).context("invalid key ID")?;
    let identity_headers = vec![("x-forgeguard-org-id".to_string(), args.org_id.clone())];
    let trace_id = uuid::Uuid::now_v7().to_string();
    let timestamp = Timestamp::from_system_time(SystemTime::now());
    let payload = CanonicalPayload::new(&trace_id, timestamp, &identity_headers);
    let signed = sign(&signing_key, &key_id, &payload, timestamp, trace_id);

    let method = reqwest::Method::from_bytes(args.method.to_uppercase().as_bytes())
        .with_context(|| format!("invalid HTTP method '{}'", args.method))?;

    let client = reqwest::Client::new();
    let request = client
        .request(method, &args.url)
        .header("x-forgeguard-signature", signed.signature_header_value())
        .header("x-forgeguard-timestamp", signed.timestamp_header_value())
        .header("x-forgeguard-key-id", signed.key_id_header_value())
        .header("x-forgeguard-trace-id", signed.trace_id_header_value())
        .header("x-forgeguard-org-id", &args.org_id)
        .build()
        .context("failed to build HTTP request")?;

    if args.verbose {
        eprintln!("{} {}", request.method(), request.url());
        for (name, value) in request.headers() {
            eprintln!("{name}: {}", value.to_str().unwrap_or("<non-utf8>"));
        }
    }

    let response = client
        .execute(request)
        .await
        .with_context(|| format!("request to '{}' failed", args.url))?;

    let status = response.status();
    eprintln!("{}", status);

    let body = response
        .text()
        .await
        .context("failed to read response body")?;

    if !body.is_empty() {
        println!("{body}");
    }

    if !status.is_success() {
        return Err(eyre::eyre!("server returned {status}"));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::signing::{sign, CanonicalPayload, KeyId, SigningKey, Timestamp};

    // -----------------------------------------------------------------------
    // Test-local helpers (moved from signing.rs — not part of the public API)
    // -----------------------------------------------------------------------

    struct VerifyingKey(ed25519_dalek::VerifyingKey);

    impl From<&SigningKey> for VerifyingKey {
        fn from(sk: &SigningKey) -> Self {
            Self(sk.verifying_key())
        }
    }

    fn verify(
        key: &VerifyingKey,
        payload: &CanonicalPayload,
        signature: &ed25519_dalek::Signature,
    ) -> Result<(), &'static str> {
        use ed25519_dalek::Verifier as _;
        key.0
            .verify(payload.as_bytes(), signature)
            .map_err(|_| "signature verification failed")
    }

    fn parse_signature_header(value: &str) -> Result<ed25519_dalek::Signature, String> {
        use base64::Engine as _;
        let b64 = value
            .strip_prefix("v1:")
            .ok_or("signature header must start with 'v1:'")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("invalid base64 in signature: {e}"))?;
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| "signature must be 64 bytes".to_string())?;
        Ok(ed25519_dalek::Signature::from_bytes(&arr))
    }

    // -----------------------------------------------------------------------

    #[test]
    fn header_construction_produces_verifiable_signature() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = VerifyingKey::from(&sk);
        let key_id = KeyId::try_from("test-key".to_string()).unwrap();
        let org_id = "org-acme";
        let trace_id = "550e8400-e29b-41d4-a716-446655440000";
        let timestamp = Timestamp::from_millis(1_700_000_000_000);

        // This mirrors exactly what run() does:
        let identity_headers = vec![("x-forgeguard-org-id".to_string(), org_id.to_string())];
        let payload = CanonicalPayload::new(trace_id, timestamp, &identity_headers);
        let signed = sign(&sk, &key_id, &payload, timestamp, trace_id.into());

        // Verify the signature header round-trips
        let sig = parse_signature_header(&signed.signature_header_value()).unwrap();
        assert!(verify(&vk, &payload, &sig).is_ok());

        // Verify header values are well-formed
        assert!(signed.signature_header_value().starts_with("v1:"));
        assert_eq!(signed.timestamp_header_value(), "1700000000000");
        assert_eq!(signed.key_id_header_value(), "test-key");
        assert_eq!(signed.trace_id_header_value(), trace_id);

        // Verify canonical payload contains lowercase header name (must match
        // what the server receives — the `http` crate normalises to lowercase).
        let payload_bytes = std::str::from_utf8(payload.as_bytes()).unwrap();
        assert!(
            payload_bytes.contains("x-forgeguard-org-id:org-acme"),
            "canonical payload must use lowercase header names"
        );
    }
}
