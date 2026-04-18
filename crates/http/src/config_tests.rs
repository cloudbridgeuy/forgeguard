//! Tests for config parsing (extracted from config.rs for file-length compliance).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use super::*;

const MINIMAL_TOML: &str = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"
"#;

const FULL_TOML: &str = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"
default_policy = "passthrough"
client_ip_source = "x-forwarded-for"

[auth]
chain_order = ["jwt", "api-key"]

[authz]
policy_store_id = "ps-123"
cache_ttl_secs = 600
cache_max_entries = 5000

[metrics]
enabled = true
listen_addr = "127.0.0.1:9090"

[[routes]]
method = "GET"
path = "/users"
action = "todo:user:list"

[[routes]]
method = "GET"
path = "/users/{id}"
action = "todo:user:read"
resource_param = "id"

[[public_routes]]
method = "GET"
path = "/health"
auth_mode = "anonymous"
"#;

#[test]
fn parse_minimal_config() {
    let config = parse_config(MINIMAL_TOML).unwrap();
    assert_eq!(config.project_id().as_str(), "my-app");
    assert_eq!(config.listen_addr().to_string(), "127.0.0.1:8080");
    assert_eq!(config.upstream_url().as_str(), "http://localhost:3000/");
    assert_eq!(config.default_policy(), DefaultPolicy::Deny);
    assert_eq!(config.client_ip_source(), ClientIpSource::Peer);
    assert!(config.routes().is_empty());
    assert!(config.public_routes().is_empty());
}

#[test]
fn parse_full_config() {
    let config = parse_config(FULL_TOML).unwrap();
    assert_eq!(config.default_policy(), DefaultPolicy::Passthrough);
    assert_eq!(config.client_ip_source(), ClientIpSource::XForwardedFor);
    assert_eq!(config.routes().len(), 2);
    assert_eq!(config.public_routes().len(), 1);

    let authz = config.authz().unwrap();
    assert_eq!(authz.policy_store_id(), "ps-123");
    assert_eq!(authz.cache_ttl(), Duration::from_secs(600));
    assert_eq!(authz.cache_max_entries(), 5000);

    let metrics = config.metrics();
    assert!(metrics.enabled());
    assert_eq!(metrics.listen_addr().unwrap().to_string(), "127.0.0.1:9090");

    let auth = config.auth();
    assert_eq!(auth.chain_order(), &["jwt", "api-key"]);
}

#[test]
fn missing_project_id_errors() {
    let toml = r#"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"
"#;
    assert!(parse_config(toml).is_err());
}

#[test]
fn invalid_listen_addr_errors() {
    let toml = r#"
project_id = "my-app"
listen_addr = "not-an-addr"
upstream_url = "http://localhost:3000"
"#;
    let err = parse_config(toml).unwrap_err();
    assert!(err.to_string().contains("listen_addr"));
}

#[test]
fn invalid_upstream_url_errors() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "not a url"
"#;
    let err = parse_config(toml).unwrap_err();
    assert!(err.to_string().contains("upstream_url"));
}

#[test]
fn invalid_default_policy_errors() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"
default_policy = "yolo"
"#;
    let err = parse_config(toml).unwrap_err();
    assert!(err.to_string().contains("default_policy"));
}

#[test]
fn invalid_route_action_errors() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[routes]]
method = "GET"
path = "/users"
action = "bad-action"
"#;
    let err = parse_config(toml).unwrap_err();
    assert!(err.to_string().contains("routes[0].action"));
}

#[test]
fn apply_overrides_changes_listen_addr() {
    let config = parse_config(MINIMAL_TOML).unwrap();
    let overrides = ConfigOverrides::new().with_listen_addr("0.0.0.0:9999".parse().unwrap());
    let config = apply_overrides(config, &overrides).unwrap();
    assert_eq!(config.listen_addr().to_string(), "0.0.0.0:9999");
}

#[test]
fn apply_overrides_changes_default_policy() {
    let config = parse_config(MINIMAL_TOML).unwrap();
    assert_eq!(config.default_policy(), DefaultPolicy::Deny);
    let overrides = ConfigOverrides::new().with_default_policy(DefaultPolicy::Passthrough);
    let config = apply_overrides(config, &overrides).unwrap();
    assert_eq!(config.default_policy(), DefaultPolicy::Passthrough);
}

#[test]
fn apply_overrides_no_change_when_empty() {
    let config = parse_config(MINIMAL_TOML).unwrap();
    let addr_before = config.listen_addr();
    let config = apply_overrides(config, &ConfigOverrides::new()).unwrap();
    assert_eq!(config.listen_addr(), addr_before);
}

#[test]
fn parse_route_with_feature_gate() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[routes]]
method = "GET"
path = "/beta"
action = "todo:beta:read"
feature_gate = "beta-feature"
"#;
    let config = parse_config(toml).unwrap();
    let route = &config.routes()[0];
    assert!(route.feature_gate().is_some());
    assert_eq!(route.feature_gate().unwrap().to_string(), "beta-feature");
}

#[test]
fn parse_client_ip_source_variants() {
    assert_eq!(
        parse_client_ip_source("peer").unwrap(),
        ClientIpSource::Peer
    );
    assert_eq!(
        parse_client_ip_source("x-forwarded-for").unwrap(),
        ClientIpSource::XForwardedFor
    );
    assert_eq!(
        parse_client_ip_source("cf-connecting-ip").unwrap(),
        ClientIpSource::CfConnectingIp
    );
    assert!(parse_client_ip_source("unknown").is_err());
}

#[test]
fn parse_aws_config_present() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[aws]
region = "us-east-2"
profile = "admin"
"#;
    let config = parse_config(toml).unwrap();
    assert_eq!(config.aws().region(), Some("us-east-2"));
    assert_eq!(config.aws().profile(), Some("admin"));
}

#[test]
fn parse_aws_config_absent() {
    let config = parse_config(MINIMAL_TOML).unwrap();
    assert!(config.aws().region().is_none());
    assert!(config.aws().profile().is_none());
}

#[test]
fn parse_aws_config_partial() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[aws]
region = "eu-west-1"
"#;
    let config = parse_config(toml).unwrap();
    assert_eq!(config.aws().region(), Some("eu-west-1"));
    assert!(config.aws().profile().is_none());
}

#[test]
fn parse_policy_tests_present() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[policy_tests]]
name = "alice can delete"
principal = "alice"
groups = ["admin"]
tenant = "acme-corp"
action = "todo:list:delete"
expect = "allow"

[[policy_tests]]
name = "charlie denied on top-secret"
principal = "charlie"
groups = ["viewer"]
tenant = "acme-corp"
action = "todo:list:read"
resource = "todo::list::top-secret"
expect = "deny"
"#;
    let config = parse_config(toml).unwrap();
    assert_eq!(config.policy_tests().len(), 2);

    let t0 = &config.policy_tests()[0];
    assert_eq!(t0.name(), "alice can delete");
    assert_eq!(t0.principal(), "alice");
    assert_eq!(t0.groups().len(), 1);
    assert_eq!(t0.groups()[0].as_str(), "admin");
    assert_eq!(t0.tenant(), "acme-corp");
    assert_eq!(t0.action().to_string(), "todo:list:delete");
    assert!(t0.resource().is_none());
    assert_eq!(t0.expect(), PolicyTestExpect::Allow);

    let t1 = &config.policy_tests()[1];
    assert_eq!(t1.name(), "charlie denied on top-secret");
    assert!(t1.resource().is_some());
    assert_eq!(t1.resource().unwrap().to_string(), "todo::list::top-secret");
    assert_eq!(t1.expect(), PolicyTestExpect::Deny);
}

#[test]
fn parse_policy_tests_absent() {
    let config = parse_config(MINIMAL_TOML).unwrap();
    assert!(config.policy_tests().is_empty());
}

#[test]
fn parse_policy_test_invalid_action_errors() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[policy_tests]]
name = "bad test"
principal = "alice"
groups = ["admin"]
tenant = "acme-corp"
action = "invalid-action"
expect = "allow"
"#;
    let err = parse_config(toml).unwrap_err();
    assert!(err.to_string().contains("policy_tests[0].action"));
}

#[test]
fn parse_policy_test_invalid_expect_errors() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[policy_tests]]
name = "bad test"
principal = "alice"
groups = ["admin"]
tenant = "acme-corp"
action = "todo:list:read"
expect = "maybe"
"#;
    let err = parse_config(toml).unwrap_err();
    assert!(err.to_string().contains("policy_tests[0].expect"));
}

#[test]
fn parse_schema_config_absent() {
    let config = parse_config(MINIMAL_TOML).unwrap();
    assert!(config.schema().entities().is_empty());
}

#[test]
fn parse_schema_config_present() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[schema.entities.todo.list]
member_of = ["todo::project"]
"#;
    let config = parse_config(toml).unwrap();
    let entities = config.schema().entities();
    assert!(entities.contains_key("todo"));
    let todo_entities = &entities["todo"];
    assert!(todo_entities.contains_key("list"));
    let list = &todo_entities["list"];
    assert_eq!(list.member_of(), &["todo::project"]);
    assert!(list.attributes().is_empty());
}

#[test]
fn parse_jwt_config() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[authn.jwt]
jwks_url = "https://cognito-idp.us-east-2.amazonaws.com/pool/.well-known/jwks.json"
issuer = "https://cognito-idp.us-east-2.amazonaws.com/pool"
"#;
    let config = parse_config(toml).unwrap();
    let jwt = config.jwt_config().unwrap();
    assert_eq!(
        jwt.jwks_url().as_str(),
        "https://cognito-idp.us-east-2.amazonaws.com/pool/.well-known/jwks.json"
    );
    assert_eq!(
        jwt.issuer(),
        "https://cognito-idp.us-east-2.amazonaws.com/pool"
    );
    assert!(jwt.audience().is_none());
}

#[test]
fn parse_jwt_config_with_overrides() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[authn.jwt]
jwks_url = "https://cognito-idp.us-east-2.amazonaws.com/pool/.well-known/jwks.json"
issuer = "https://cognito-idp.us-east-2.amazonaws.com/pool"
audience = "my-client-id"
user_id_claim = "email"
tenant_claim = "custom:tenant"
groups_claim = "custom:roles"
cache_ttl_secs = 600
"#;
    let config = parse_config(toml).unwrap();
    let jwt = config.jwt_config().unwrap();
    assert_eq!(jwt.audience(), Some("my-client-id"));
    assert_eq!(jwt.user_id_claim(), Some("email"));
    assert_eq!(jwt.tenant_claim(), Some("custom:tenant"));
    assert_eq!(jwt.groups_claim(), Some("custom:roles"));
    assert_eq!(jwt.cache_ttl_secs(), Some(600));
}

#[test]
fn parse_jwt_config_absent() {
    let config = parse_config(MINIMAL_TOML).unwrap();
    assert!(config.jwt_config().is_none());
}

#[test]
fn parse_jwt_config_invalid_url_errors() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[authn.jwt]
jwks_url = "not a url"
issuer = "https://example.com"
"#;
    let err = parse_config(toml).unwrap_err();
    assert!(err.to_string().contains("authn.jwt.jwks_url"));
}

#[test]
fn parse_jwt_config_empty_issuer_errors() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[authn.jwt]
jwks_url = "https://example.com/.well-known/jwks.json"
issuer = ""
"#;
    let err = parse_config(toml).unwrap_err();
    assert!(err.to_string().contains("authn.jwt.issuer"));
}

#[test]
fn parse_api_keys() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[api_keys]]
key = "sk-test-alice"
user_id = "alice"
tenant_id = "acme-corp"
groups = ["admin", "top-secret-readers"]

[[api_keys]]
key = "sk-test-bob"
user_id = "bob"
tenant_id = "acme-corp"
groups = ["member"]
"#;
    let config = parse_config(toml).unwrap();
    assert_eq!(config.api_keys().len(), 2);

    let alice = &config.api_keys()[0];
    assert_eq!(alice.key(), "sk-test-alice");
    assert_eq!(alice.user_id().as_str(), "alice");
    assert_eq!(alice.tenant_id().unwrap().as_str(), "acme-corp");
    assert_eq!(alice.groups().len(), 2);

    let bob = &config.api_keys()[1];
    assert_eq!(bob.key(), "sk-test-bob");
    assert_eq!(bob.groups().len(), 1);
}

#[test]
fn parse_api_keys_absent() {
    let config = parse_config(MINIMAL_TOML).unwrap();
    assert!(config.api_keys().is_empty());
}

#[test]
fn parse_api_keys_minimal() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[api_keys]]
key = "sk-test-viewer"
user_id = "viewer-bot"
"#;
    let config = parse_config(toml).unwrap();
    assert_eq!(config.api_keys().len(), 1);
    let entry = &config.api_keys()[0];
    assert!(entry.tenant_id().is_none());
    assert!(entry.groups().is_empty());
}

#[test]
fn parse_cors_absent() {
    let config = parse_config(MINIMAL_TOML).unwrap();
    assert!(config.cors().is_none());
}

#[test]
fn parse_cors_enabled() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[cors]
enabled = true
allowed_origins = ["https://app.forgeguard.dev", "*.forgeguard.dev"]
allow_credentials = true
"#;
    let config = parse_config(toml).unwrap();
    let cors = config.cors().unwrap();
    assert_eq!(
        cors.matches_origin("https://app.forgeguard.dev"),
        Some("https://app.forgeguard.dev"),
    );
    assert_eq!(
        cors.matches_origin("https://staging.forgeguard.dev"),
        Some("https://staging.forgeguard.dev"),
    );
    assert_eq!(cors.matches_origin("https://evil.com"), None);
}

#[test]
fn parse_cors_disabled() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[cors]
enabled = false
"#;
    let config = parse_config(toml).unwrap();
    // Disabled CORS parses but matches nothing
    let cors = config.cors().unwrap();
    assert_eq!(cors.matches_origin("https://anything.com"), None);
}

#[test]
fn upstream_target_http() {
    let config = parse_config(MINIMAL_TOML).unwrap();
    let target = config.upstream_target();
    assert_eq!(target.addr(), "localhost:3000");
    assert!(!target.tls());
    assert_eq!(target.sni(), "localhost");
}

#[test]
fn upstream_target_https() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "https://api.example.com"
"#;
    let config = parse_config(toml).unwrap();
    let target = config.upstream_target();
    assert_eq!(target.addr(), "api.example.com:443");
    assert!(target.tls());
    assert_eq!(target.sni(), "api.example.com");
}

#[test]
fn upstream_target_custom_port() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "https://api.example.com:9443"
"#;
    let config = parse_config(toml).unwrap();
    let target = config.upstream_target();
    assert_eq!(target.addr(), "api.example.com:9443");
    assert!(target.tls());
}

#[test]
fn parse_cors_wildcard_credentials_rejected() {
    let toml = r#"
project_id = "my-app"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[cors]
enabled = true
allowed_origins = ["*"]
allow_credentials = true
"#;
    let err = parse_config(toml).unwrap_err();
    assert!(err.to_string().contains("validation failed"));
}

#[test]
fn apply_overrides_changes_upstream_url_recomputes_target() {
    let config = parse_config(MINIMAL_TOML).unwrap();
    assert_eq!(config.upstream_target().addr(), "localhost:3000");
    assert!(!config.upstream_target().tls());

    let new_url: url::Url = "https://api.example.com:9443".parse().unwrap();
    let overrides = ConfigOverrides::new().with_upstream_url(new_url);
    let config = apply_overrides(config, &overrides).unwrap();

    assert_eq!(config.upstream_target().addr(), "api.example.com:9443");
    assert!(config.upstream_target().tls());
    assert_eq!(config.upstream_target().sni(), "api.example.com");
}

#[test]
fn parse_cluster_config_section() {
    let toml = r#"
        project_id = "test"
        listen_addr = "127.0.0.1:8080"
        upstream_url = "http://127.0.0.1:3000"

        [cluster]
        redis_url = "redis://127.0.0.1:6379"
        instance_id = "proxy-1"
        priority = 3
        heartbeat_interval_secs = 5
        min_quorum = 2
        listen_cluster_addr = "10.0.1.1:8080"
    "#;

    let config = parse_config(toml).unwrap();
    let cluster = config.cluster().unwrap();
    assert_eq!(cluster.redis_url().host_str(), Some("127.0.0.1"));
    assert_eq!(cluster.instance_id(), "proxy-1");
    assert_eq!(cluster.priority(), 3);
    assert_eq!(cluster.heartbeat_interval(), Duration::from_secs(5));
    assert_eq!(cluster.min_quorum(), 2);
    assert_eq!(
        cluster.listen_cluster_addr().unwrap().to_string(),
        "10.0.1.1:8080"
    );
}

#[test]
fn parse_config_without_cluster_section() {
    let config = parse_config(MINIMAL_TOML).unwrap();
    assert!(config.cluster().is_none());
}

#[test]
fn parse_cluster_config_invalid_redis_url_errors() {
    let toml = r#"
        project_id = "test"
        listen_addr = "127.0.0.1:8080"
        upstream_url = "http://127.0.0.1:3000"

        [cluster]
        redis_url = "not a url"
    "#;
    let err = parse_config(toml).unwrap_err();
    assert!(err.to_string().contains("cluster.redis_url"));
}

#[test]
fn parse_cluster_config_invalid_listen_addr_errors() {
    let toml = r#"
        project_id = "test"
        listen_addr = "127.0.0.1:8080"
        upstream_url = "http://127.0.0.1:3000"

        [cluster]
        redis_url = "redis://127.0.0.1:6379"
        listen_cluster_addr = "not-an-addr"
    "#;
    let err = parse_config(toml).unwrap_err();
    assert!(err.to_string().contains("cluster.listen_cluster_addr"));
}

#[test]
fn schema_config_to_entity_config_translates_namespaced_entries() {
    use std::collections::HashMap;

    use forgeguard_core::CedarAttributeType;

    let schema_config = SchemaConfig::new(HashMap::from([(
        "todo".to_string(),
        HashMap::from([(
            "list".to_string(),
            EntitySchema::new(
                vec!["todo::project".to_string()],
                HashMap::from([("title".to_string(), "String".to_string())]),
            ),
        )]),
    )]));

    let entity_config = schema_config.to_entity_config().expect("entities present");

    assert!(entity_config.contains_key("todo__list"));
    let list_cfg = &entity_config["todo__list"];
    assert_eq!(list_cfg.member_of(), &["todo__project".to_string()]);
    assert_eq!(
        list_cfg.attributes().get("title"),
        Some(&CedarAttributeType::String)
    );
}
