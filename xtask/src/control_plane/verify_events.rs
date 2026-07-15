//! `cargo xtask control-plane verify-events` — externally verify a control
//! plane's event log (V4 / D8): fetch `GET /events` + `GET /signing-keys`
//! over HTTP, recompute each envelope's canonical bytes, and Ed25519-verify
//! its stored signature. Uses only public API surface — no store access, no
//! private keys.

use std::collections::HashMap;

use clap::Args;
use color_eyre::eyre::{eyre, Context, Result};
use forgeguard_authn_core::signing::VerifyingKey;
use forgeguard_authz_core::EventEnvelope;

use super::verify_events_core::verify_envelopes;

/// CLI arguments for the verify-events subcommand.
#[derive(Args)]
pub(crate) struct VerifyEventsArgs {
    /// Base URL of the control plane (e.g. http://127.0.0.1:3001).
    #[arg(long, default_value = "http://127.0.0.1:3001")]
    url: String,

    /// Organization ID whose log to verify.
    #[arg(long)]
    org_id: String,

    /// Replay cursor: verify events with seq > after.
    #[arg(long, default_value_t = 0)]
    after: u64,

    /// Maximum number of events to fetch.
    #[arg(long, default_value_t = 100)]
    limit: u16,
}

pub(crate) async fn run(args: &VerifyEventsArgs) -> Result<()> {
    let client = reqwest::Client::new();
    let base = args.url.trim_end_matches('/');
    let org = &args.org_id;

    let events_url = format!(
        "{base}/api/v1/organizations/{org}/events?after={}&limit={}",
        args.after, args.limit
    );
    let events_body: serde_json::Value = fetch_json(&client, &events_url).await?;
    let envelopes: Vec<EventEnvelope> = serde_json::from_value(events_body["events"].clone())
        .wrap_err("failed to parse events from response")?;

    let keys_url = format!("{base}/api/v1/organizations/{org}/signing-keys");
    let keys_body: serde_json::Value = fetch_json(&client, &keys_url).await?;
    let keys = parse_keys(&keys_body)?;

    if envelopes.is_empty() {
        println!("no events after seq {} — nothing to verify", args.after);
        return Ok(());
    }

    let outcomes = verify_envelopes(org, &envelopes, &keys);
    let mut failures = 0usize;
    for outcome in &outcomes {
        if !outcome.result.is_ok() {
            failures += 1;
        }
        println!(
            "seq={} kind={} key_id={} {}",
            outcome.seq, outcome.kind, outcome.key_id, outcome.result
        );
    }

    if failures > 0 {
        return Err(eyre!(
            "{failures}/{} envelopes failed verification",
            outcomes.len()
        ));
    }
    println!("all {} envelopes verified", outcomes.len());
    Ok(())
}

async fn fetch_json(client: &reqwest::Client, url: &str) -> Result<serde_json::Value> {
    let response = client
        .get(url)
        .send()
        .await
        .wrap_err_with(|| format!("GET {url} failed"))?;
    let status = response.status();
    let body = response.text().await.wrap_err("failed to read body")?;
    if !status.is_success() {
        return Err(eyre!("GET {url} returned {status}: {body}"));
    }
    serde_json::from_str(&body).wrap_err_with(|| format!("GET {url}: invalid JSON"))
}

fn parse_keys(body: &serde_json::Value) -> Result<HashMap<String, VerifyingKey>> {
    let entries = body["keys"]
        .as_array()
        .ok_or_else(|| eyre!("signing-keys response missing 'keys' array"))?;
    entries
        .iter()
        .map(|entry| {
            let key_id = entry["key_id"]
                .as_str()
                .ok_or_else(|| eyre!("key entry missing key_id"))?
                .to_string();
            let pem = entry["public_key"]
                .as_str()
                .ok_or_else(|| eyre!("key entry missing public_key"))?;
            let vk = VerifyingKey::from_public_key_pem(pem)
                .map_err(|e| eyre!("invalid public key PEM for '{key_id}': {e}"))?;
            Ok((key_id, vk))
        })
        .collect()
}
