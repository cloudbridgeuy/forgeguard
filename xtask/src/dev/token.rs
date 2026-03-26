use aws_sdk_cognitoidentityprovider::types::AuthFlowType;
use base64::Engine;
use clap::Args;
use color_eyre::eyre::{bail, Context, Result};

// ---------------------------------------------------------------------------
// Functional Core -- pure types and logic, no I/O
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct TokenArgs {
    /// Username to authenticate as
    #[arg(long)]
    pub user: String,
    /// Decode and pretty-print the JWT claims
    #[arg(long)]
    pub decode: bool,
}

/// Split a JWT on `.`, base64url-decode the payload (second segment), and
/// return it as pretty-printed JSON. No signature verification is performed.
fn decode_jwt_payload(token: &str) -> Result<String> {
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() != 3 {
        bail!(
            "invalid JWT: expected 3 dot-separated segments, got {}",
            segments.len()
        );
    }

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segments[1])
        .context("invalid base64 in JWT payload segment")?;

    let value: serde_json::Value =
        serde_json::from_slice(&payload_bytes).context("JWT payload is not valid JSON")?;

    let pretty =
        serde_json::to_string_pretty(&value).context("failed to pretty-print JWT payload")?;

    Ok(pretty)
}

// ---------------------------------------------------------------------------
// Imperative Shell -- I/O, side effects, orchestration
// ---------------------------------------------------------------------------

pub async fn run(args: &TokenArgs) -> Result<()> {
    let env_path = std::path::Path::new("infra/dev/.env");
    dotenvy::from_path(env_path).context(
        "failed to load infra/dev/.env -- have you run `cargo xtask dev setup --cognito`?",
    )?;

    let client_id = std::env::var("COGNITO_APP_CLIENT_ID").context(
        "COGNITO_APP_CLIENT_ID not set in infra/dev/.env -- run `cargo xtask dev setup --cognito`",
    )?;

    let password = std::env::var("DEV_PASSWORD").context(
        "DEV_PASSWORD not set in infra/dev/.env -- run `cargo xtask dev setup --cognito`",
    )?;

    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_cognitoidentityprovider::Client::new(&aws_config);

    let resp = client
        .initiate_auth()
        .auth_flow(AuthFlowType::UserPasswordAuth)
        .client_id(&client_id)
        .auth_parameters("USERNAME", &args.user)
        .auth_parameters("PASSWORD", &password)
        .send()
        .await
        .context("Cognito initiate_auth failed")?;

    let auth_result = resp
        .authentication_result()
        .ok_or_else(|| color_eyre::eyre::eyre!("no authentication_result in Cognito response"))?;

    let id_token = auth_result
        .id_token()
        .ok_or_else(|| color_eyre::eyre::eyre!("no IdToken in authentication result"))?;

    if args.decode {
        let decoded = decode_jwt_payload(id_token)?;
        println!("{decoded}");
    } else {
        println!("{id_token}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal JWT from a JSON object by base64url-encoding header and
    /// payload, and using a dummy signature segment.
    fn make_jwt(claims_json: &str) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = engine.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = engine.encode(claims_json);
        let signature = engine.encode(b"fakesig");
        format!("{header}.{payload}.{signature}")
    }

    #[test]
    fn decode_known_jwt_returns_correct_claims() {
        let claims = r#"{"sub":"1234567890","name":"Test User","iat":1516239022}"#;
        let token = make_jwt(claims);

        let result = decode_jwt_payload(&token).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(parsed["sub"], "1234567890");
        assert_eq!(parsed["name"], "Test User");
        assert_eq!(parsed["iat"], 1516239022);
    }

    #[test]
    fn decode_malformed_token_missing_segments_returns_error() {
        let result = decode_jwt_payload("only-one-segment");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("expected 3 dot-separated segments"));
    }

    #[test]
    fn decode_malformed_token_two_segments_returns_error() {
        let result = decode_jwt_payload("header.payload");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("expected 3 dot-separated segments"));
    }

    #[test]
    fn decode_invalid_base64_returns_error() {
        // Use characters that are invalid in base64url
        let result = decode_jwt_payload("header.!!!invalid-base64!!!.signature");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("invalid base64"));
    }
}
