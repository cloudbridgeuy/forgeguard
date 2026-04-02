//! Integration tests for the forgeguard-proxy binary.
//!
//! Each test:
//! 1. Starts an axum echo upstream on an OS-assigned port
//! 2. Writes a temp config TOML pointing at that upstream
//! 3. Spawns the proxy binary with `--config` and `--listen`
//! 4. Polls the health endpoint until ready
//! 5. Sends requests and asserts status codes + headers
//! 6. Kills the child process on drop

use std::collections::HashMap;
use std::io::Write;
use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;

use axum::extract::Request;
use axum::response::Json;
use axum::routing::any;
use axum::Router;
use serde_json::Value;
use tempfile::NamedTempFile;

use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use ed25519_dalek::SigningKey as DalekSigningKey;

// ---------------------------------------------------------------------------
// Echo upstream
// ---------------------------------------------------------------------------

/// Starts an axum server that echoes back all `X-ForgeGuard-*` headers as JSON.
/// Returns the port it bound to.
async fn start_echo_upstream() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let app = Router::new()
        .route("/{*path}", any(echo_handler))
        .route("/", any(echo_handler));

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    port
}

async fn echo_handler(req: Request) -> Json<Value> {
    let mut fg_headers: HashMap<String, String> = HashMap::new();
    for (name, value) in req.headers() {
        let name_str = name.as_str();
        if name_str.starts_with("x-forgeguard-") {
            if let Ok(v) = value.to_str() {
                fg_headers.insert(name_str.to_string(), v.to_string());
            }
        }
    }
    Json(serde_json::json!({
        "path": req.uri().path(),
        "method": req.method().as_str(),
        "forgeguard_headers": fg_headers,
    }))
}

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

fn test_config_toml(upstream_port: u16) -> String {
    format!(
        r#"project_id = "test-app"
listen_addr = "127.0.0.1:0"
upstream_url = "http://127.0.0.1:{upstream_port}"
default_policy = "deny"
client_ip_source = "peer"

[auth]
chain_order = ["api-key"]

[[api_keys]]
key = "sk-test-alice"
user_id = "alice"
tenant_id = "acme-corp"
groups = ["admin"]

[[api_keys]]
key = "sk-test-bob"
user_id = "bob"
tenant_id = "acme-corp"
groups = ["viewer"]

[[api_keys]]
key = "sk-test-dave"
user_id = "dave"
tenant_id = "initech"
groups = ["member"]

[[routes]]
method = "GET"
path = "/api/lists"
action = "todo:list:list"

[[routes]]
method = "POST"
path = "/api/lists"
action = "todo:list:create"

[[routes]]
method = "GET"
path = "/api/lists/:list_id/suggestions"
action = "todo:list:suggest"
feature_gate = "todo:ai-suggestions"

[[public_routes]]
method = "GET"
path = "/health"
auth_mode = "anonymous"

[[public_routes]]
method = "GET"
path = "/docs/:page"
auth_mode = "opportunistic"

[features]

[features.flags."todo:ai-suggestions"]
type = "boolean"
default = false
enabled = true
[[features.flags."todo:ai-suggestions".overrides]]
tenant = "acme-corp"
value = true
"#
    )
}

fn test_config_toml_with_signing(upstream_port: u16, key_path: &str, key_id: &str) -> String {
    let base = test_config_toml(upstream_port);
    format!(
        r#"{base}

[signing]
key_path = "{key_path}"
key_id = "{key_id}"
"#
    )
}

/// Generate an Ed25519 keypair and write the private key PEM to a temp file.
/// Returns (temp_file, dalek_signing_key) — keep the temp_file alive for the test.
fn generate_test_keypair() -> (NamedTempFile, DalekSigningKey) {
    let mut rng = rand::thread_rng();
    let signing_key = DalekSigningKey::generate(&mut rng);
    let pem = signing_key
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .unwrap();

    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(pem.as_bytes()).unwrap();
    key_file.flush().unwrap();

    (key_file, signing_key)
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

struct TestHarness {
    proxy_url: String,
    client: reqwest::Client,
    proxy_child: Child,
    _config_file: NamedTempFile,
    // Keep the key file alive for signing tests
    _key_file: Option<NamedTempFile>,
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        let _ = self.proxy_child.kill();
        let _ = self.proxy_child.wait();
    }
}

impl TestHarness {
    async fn start() -> Self {
        let upstream_port = start_echo_upstream().await;
        let config_str = test_config_toml(upstream_port);
        Self::start_with_config(&config_str, None).await
    }

    async fn start_with_signing() -> (Self, DalekSigningKey) {
        let upstream_port = start_echo_upstream().await;
        let (key_file, signing_key) = generate_test_keypair();
        let key_path = key_file.path().to_str().unwrap().to_string();
        let config_str = test_config_toml_with_signing(upstream_port, &key_path, "test-key-001");
        let harness = Self::start_with_config(&config_str, Some(key_file)).await;
        (harness, signing_key)
    }

    async fn start_with_config(config_str: &str, key_file: Option<NamedTempFile>) -> Self {
        let mut config_file = NamedTempFile::new().unwrap();
        config_file.write_all(config_str.as_bytes()).unwrap();

        // Find a free port for the proxy
        let proxy_port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };

        let proxy_bin = env!("CARGO_BIN_EXE_forgeguard-proxy");

        let proxy_child = Command::new(proxy_bin)
            .arg("run")
            .arg("--config")
            .arg(config_file.path())
            .arg("--listen")
            .arg(format!("127.0.0.1:{proxy_port}"))
            .env("RUST_LOG", "warn")
            .spawn()
            .unwrap();

        let proxy_url = format!("http://127.0.0.1:{proxy_port}");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();

        let mut harness = Self {
            proxy_url,
            client,
            proxy_child,
            _config_file: config_file,
            _key_file: key_file,
        };

        harness.wait_for_health().await;
        harness
    }

    async fn wait_for_health(&mut self) {
        let health_url = format!("{}/.well-known/forgeguard/health", self.proxy_url);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

        loop {
            if tokio::time::Instant::now() > deadline {
                // Check if the process exited early
                if let Some(status) = self.proxy_child.try_wait().unwrap() {
                    panic!("proxy process exited early with status: {status}");
                }
                panic!("proxy did not become healthy within 5 seconds");
            }

            match self.client.get(&health_url).send().await {
                Ok(resp) if resp.status().is_success() => return,
                _ => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.proxy_url, path)
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        self.client.get(self.url(path)).send().await.unwrap()
    }

    async fn get_with_key(&self, path: &str, key: &str) -> reqwest::Response {
        self.client
            .get(self.url(path))
            .header("x-api-key", key)
            .send()
            .await
            .unwrap()
    }

    async fn request_with_key(
        &self,
        method: reqwest::Method,
        path: &str,
        key: &str,
    ) -> reqwest::Response {
        self.client
            .request(method, self.url(path))
            .header("x-api-key", key)
            .send()
            .await
            .unwrap()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_returns_200() {
    let harness = TestHarness::start().await;

    let resp = harness.get("/.well-known/forgeguard/health").await;

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn no_credential_returns_401() {
    let harness = TestHarness::start().await;

    let resp = harness.get("/api/lists").await;

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn invalid_api_key_returns_401() {
    let harness = TestHarness::start().await;

    let resp = harness.get_with_key("/api/lists", "bad").await;

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn valid_credential_returns_200() {
    let harness = TestHarness::start().await;

    let resp = harness.get_with_key("/api/lists", "sk-test-alice").await;

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn valid_credential_injects_headers() {
    let harness = TestHarness::start().await;

    let resp = harness.get_with_key("/api/lists", "sk-test-alice").await;

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let headers = &body["forgeguard_headers"];
    assert_eq!(headers["x-forgeguard-user-id"], "alice");
    assert_eq!(headers["x-forgeguard-tenant-id"], "acme-corp");
}

#[tokio::test]
async fn unmatched_route_returns_403() {
    let harness = TestHarness::start().await;

    let resp = harness
        .request_with_key(reqwest::Method::DELETE, "/api/unknown", "sk-test-alice")
        .await;

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn anonymous_public_route_returns_200() {
    let harness = TestHarness::start().await;

    let resp = harness.get("/health").await;

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn opportunistic_without_cred() {
    let harness = TestHarness::start().await;

    let resp = harness.get("/docs/intro").await;

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn opportunistic_with_cred() {
    let harness = TestHarness::start().await;

    let resp = harness.get_with_key("/docs/intro", "sk-test-alice").await;

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let headers = &body["forgeguard_headers"];
    assert_eq!(headers["x-forgeguard-user-id"], "alice");
}

#[tokio::test]
async fn feature_gate_enabled_returns_200() {
    let harness = TestHarness::start().await;

    // alice is in acme-corp, which has the feature override enabled
    let resp = harness
        .get_with_key("/api/lists/x/suggestions", "sk-test-alice")
        .await;

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn feature_gate_disabled_returns_404() {
    let harness = TestHarness::start().await;

    // dave is in initech, which does not have the feature override — default is false
    let resp = harness
        .get_with_key("/api/lists/x/suggestions", "sk-test-dave")
        .await;

    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// Signing tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn signing_injects_signature_headers() {
    let (harness, _signing_key) = TestHarness::start_with_signing().await;

    let resp = harness.get_with_key("/api/lists", "sk-test-alice").await;

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let headers = &body["forgeguard_headers"];

    // All four signature headers must be present and non-empty
    for header_name in [
        "x-forgeguard-signature",
        "x-forgeguard-timestamp",
        "x-forgeguard-trace-id",
        "x-forgeguard-key-id",
    ] {
        let val = headers[header_name].as_str().unwrap_or("");
        assert!(!val.is_empty(), "{header_name} should be non-empty");
    }

    assert_eq!(headers["x-forgeguard-key-id"], "test-key-001");
    assert!(headers["x-forgeguard-signature"]
        .as_str()
        .unwrap()
        .starts_with("v1:"));
}

#[tokio::test]
async fn signing_signature_verifies() {
    let (harness, signing_key) = TestHarness::start_with_signing().await;

    let resp = harness.get_with_key("/api/lists", "sk-test-alice").await;

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let headers = &body["forgeguard_headers"];

    // Extract signature components from the echo response
    let sig_header = headers["x-forgeguard-signature"].as_str().unwrap();
    let timestamp_str = headers["x-forgeguard-timestamp"].as_str().unwrap();
    let trace_id = headers["x-forgeguard-trace-id"].as_str().unwrap();

    // Collect the identity headers (excluding signature-related ones)
    let identity_headers: Vec<(String, String)> = headers
        .as_object()
        .unwrap()
        .iter()
        .filter(|(k, _)| {
            k.starts_with("x-forgeguard-")
                && *k != "x-forgeguard-signature"
                && *k != "x-forgeguard-timestamp"
                && *k != "x-forgeguard-trace-id"
                && *k != "x-forgeguard-key-id"
        })
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .collect();

    // Reconstruct canonical payload
    let timestamp = forgeguard_authn_core::signing::Timestamp::from_millis(
        timestamp_str.parse::<u64>().unwrap(),
    );
    let payload = forgeguard_authn_core::signing::CanonicalPayload::new(
        trace_id,
        timestamp,
        &identity_headers,
    );

    // Parse the signature
    let signature = forgeguard_authn_core::signing::parse_signature_header(sig_header).unwrap();

    // Verify using the public key derived from the test signing key
    let verifying_key = forgeguard_authn_core::signing::VerifyingKey::from_bytes(
        signing_key.verifying_key().as_bytes(),
    )
    .unwrap();
    forgeguard_authn_core::signing::verify(&verifying_key, &payload, &signature).unwrap();
}
