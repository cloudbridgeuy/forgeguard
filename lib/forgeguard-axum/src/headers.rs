//! Pure projection of identity + decision record into `X-Fg-*` headers.
//!
//! Functional core: no clock, no randomness, no I/O — `trace_id` and `now`
//! are inputs. The middleware (imperative shell) supplies them per request.
//!
//! Resolved feature flags and client IP are deliberately omitted: the
//! embedding app already receives [`crate::ForgeGuardFlags`] via request
//! extensions, and client IP is the app's own connection info (YAGNI — a
//! later slice can add them if a real consumer needs them on the wire).
//!
//! Identity projection is a small, self-contained duplicate of
//! `forgeguard_http::headers::inject_headers` rather than a dependency on
//! it: `forgeguard_http` is `publish = false` and depending on it as a real
//! (non-dev) dependency would break `cargo publish -p forgeguard-axum`,
//! which is a published crate. `tests::identity_headers_matches_forgeguard_http`
//! guards the two against drifting apart.

use forgeguard_core::headers as hn;

/// The names this module ever writes for a resolved identity — a subset of
/// `forgeguard_http`'s `IdentityProjection` fields, since `build_fg_headers`
/// never supplies `principal_fgrn`, resolved flags, or client IP.
fn identity_headers(identity: &forgeguard_authn_core::Identity) -> Vec<(String, String)> {
    let mut headers = Vec::with_capacity(4);

    headers.push((
        hn::X_FG_USER_ID.to_string(),
        identity.user_id().as_str().to_string(),
    ));

    if let Some(tenant_id) = identity.tenant_id() {
        headers.push((
            hn::X_FG_TENANT_ID.to_string(),
            tenant_id.as_str().to_string(),
        ));
    }

    if !identity.groups().is_empty() {
        let groups = identity
            .groups()
            .iter()
            .map(forgeguard_core::GroupName::as_str)
            .collect::<Vec<_>>()
            .join(",");
        headers.push((hn::X_FG_GROUPS.to_string(), groups));
    }

    headers.push((
        hn::X_FG_AUTH_PROVIDER.to_string(),
        identity.resolver().to_string(),
    ));

    headers
}

/// Inputs to [`build_fg_headers`] — identity, decision record, and signing
/// are all optional; only `trace_id`/`now` are always required (the
/// signature, when present, needs them regardless of what else is set).
pub(crate) struct FgHeaderParams<'a> {
    pub(crate) identity: Option<&'a forgeguard_authn_core::Identity>,
    pub(crate) record: Option<&'a forgeguard_authz_core::DecisionRecord>,
    pub(crate) signing: Option<&'a crate::SigningConfig>,
    pub(crate) trace_id: &'a str,
    pub(crate) now: forgeguard_authn_core::signing::Timestamp,
}

/// Identity projection + decision projection, then (optionally) the four
/// signing headers covering ALL of the above — scope/entitlements/revision
/// are inside the canonical payload, so downstream verification covers the
/// decision context too.
///
/// Deliberately does not call `forgeguard_http::inject_signed_headers` —
/// signing here must cover the decision-projection headers too, which that
/// function can't see; this replicates its 4-header signing tail on purpose
/// (documented divergence, one place each).
pub(crate) fn build_fg_headers(params: &FgHeaderParams<'_>) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();

    if let Some(identity) = params.identity {
        headers.extend(identity_headers(identity));
    }

    if let Some(record) = params.record {
        headers.push((
            hn::X_FG_SCOPE_PATH.to_string(),
            record.scope_path().to_string(),
        ));
        let verbs: Vec<String> = record
            .entitlements()
            .iter()
            .map(ToString::to_string)
            .collect();
        if !verbs.is_empty() {
            headers.push((hn::X_FG_ENTITLEMENTS.to_string(), verbs.join(",")));
        }
        headers.push((
            hn::X_FG_REVISION.to_string(),
            record.revision().value().to_string(),
        ));
    }

    let Some(signing) = params.signing else {
        return headers;
    };
    if headers.is_empty() {
        return headers;
    }

    let payload = forgeguard_authn_core::signing::CanonicalPayload::new(
        params.trace_id,
        params.now,
        &headers,
    );
    let signed = forgeguard_authn_core::signing::sign(
        signing.key(),
        signing.key_id(),
        &payload,
        params.now,
        params.trace_id.to_string(),
    );
    headers.push((
        hn::X_FG_TRACE_ID.to_string(),
        signed.trace_id_header_value().to_string(),
    ));
    headers.push((
        hn::X_FG_TIMESTAMP.to_string(),
        signed.timestamp_header_value(),
    ));
    headers.push((hn::X_FG_KEY_ID.to_string(), signed.key_id_header_value()));
    headers.push((
        hn::X_FG_SIGNATURE.to_string(),
        signed.signature_header_value(),
    ));

    headers
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use forgeguard_authn_core::signing::{KeyId, SigningKey, Timestamp};
    use forgeguard_authn_core::{Identity, IdentityParams};
    use forgeguard_authz_core::{
        AuthzStore as _, CedarEngine, DecisionQuery, DecisionRecord, MemoryStore, ModelState,
        Snapshot, StoreWrite,
    };
    use forgeguard_core::principal::PrincipalKind as AuthzPrincipalKind;
    use forgeguard_core::{
        Fgrn, Grant, GroupName, NativeId, OrgUnit, Principal, PrincipalKind, Segment, Spine,
        TenantId, UserId,
    };

    use super::*;

    fn make_identity() -> Identity {
        Identity::new(IdentityParams {
            user_id: UserId::new("alice").unwrap(),
            tenant_id: Some(TenantId::new("acme-corp").unwrap()),
            groups: vec![GroupName::new("admin").unwrap()],
            expiry: None,
            resolver: "jwt",
            extra: None,
            principal_kind: PrincipalKind::User,
        })
    }

    fn org() -> Segment {
        Segment::try_new("acme").unwrap()
    }

    fn nid(s: &str) -> NativeId {
        NativeId::try_new(s).unwrap()
    }

    fn maria() -> Fgrn {
        Fgrn::principal(&org(), &nid("maria"))
    }

    fn doc() -> Fgrn {
        Fgrn::resource(
            &org(),
            &Segment::try_new("document").unwrap(),
            &nid("doc_1"),
        )
    }

    /// Mirrors `crates/authz-core/src/engine_cedar/engine.rs`'s
    /// `record_carries_scope_path_and_entitlements` fixture — `DecisionRecord::new`
    /// is `pub(crate)` to authz-core, so a record can only be produced here by
    /// running the real engine against a store, not constructed directly.
    async fn decision_record() -> DecisionRecord {
        let root = Fgrn::org_unit(&org(), &nid("root"));
        let spine = Spine::try_new(vec![OrgUnit::try_new(root.clone(), None).unwrap()]).unwrap();
        let mut model = ModelState::new(spine);
        model.upsert_principal(
            Principal::try_new(maria(), AuthzPrincipalKind::Human, root).unwrap(),
        );
        let store = MemoryStore::new(model);

        store
            .apply(StoreWrite::PutGrant(
                Grant::try_new(
                    doc(),
                    vec![forgeguard_core::Verb::try_new("read").unwrap()],
                    maria(),
                )
                .unwrap(),
            ))
            .await
            .unwrap();

        let engine = CedarEngine::new(
            Snapshot::from_policy_text(
                r#"permit(principal, action == Action::"unrelated-action", resource);"#,
            )
            .unwrap(),
        );
        let query = DecisionQuery::new(
            maria(),
            forgeguard_core::Verb::try_new("read").unwrap(),
            doc(),
        );

        engine.decide(&store, &query).await.unwrap()
    }

    fn test_signing_config() -> crate::SigningConfig {
        crate::SigningConfig::new(
            SigningKey::from_bytes(&[42u8; 32]),
            KeyId::try_from("test-key".to_string()).unwrap(),
        )
    }

    #[test]
    fn identity_only_projects_x_fg_identity_headers() {
        let identity = make_identity();
        let headers = build_fg_headers(&FgHeaderParams {
            identity: Some(&identity),
            record: None,
            signing: None,
            trace_id: "trace-1",
            now: Timestamp::from_millis(0),
        });

        let keys: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"x-fg-user-id"));
        assert!(!keys.contains(&"x-fg-scope-path"));
        assert!(!keys.contains(&"x-fg-signature"));
    }

    #[tokio::test]
    async fn record_projects_scope_entitlements_revision() {
        let identity = make_identity();
        let record = decision_record().await;
        let headers = build_fg_headers(&FgHeaderParams {
            identity: Some(&identity),
            record: Some(&record),
            signing: None,
            trace_id: "trace-1",
            now: Timestamp::from_millis(0),
        });

        let map: std::collections::HashMap<&str, &str> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(map["x-fg-scope-path"], "root");
        assert_eq!(map["x-fg-entitlements"], "read");
        assert!(map["x-fg-revision"].parse::<u64>().is_ok());
    }

    #[tokio::test]
    async fn signing_covers_decision_headers() {
        let identity = make_identity();
        let record = decision_record().await;
        let signing = test_signing_config();
        let now = Timestamp::from_millis(1_700_000_000_000);
        let headers = build_fg_headers(&FgHeaderParams {
            identity: Some(&identity),
            record: Some(&record),
            signing: Some(&signing),
            trace_id: "trace-1",
            now,
        });

        let signature_headers = [
            hn::X_FG_TRACE_ID,
            hn::X_FG_TIMESTAMP,
            hn::X_FG_KEY_ID,
            hn::X_FG_SIGNATURE,
        ];
        let covered: Vec<(String, String)> = headers
            .iter()
            .filter(|(k, _)| !signature_headers.contains(&k.as_str()))
            .cloned()
            .collect();
        let map: std::collections::HashMap<&str, &str> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let signature_value = map[hn::X_FG_SIGNATURE];
        let signature =
            forgeguard_authn_core::signing::parse_signature_header(signature_value).unwrap();
        let payload =
            forgeguard_authn_core::signing::CanonicalPayload::new("trace-1", now, &covered);
        let verifying_key = forgeguard_authn_core::signing::VerifyingKey::from(signing.key());
        forgeguard_authn_core::signing::verify(&verifying_key, &payload, &signature)
            .expect("signature must cover scope/entitlements/revision headers");
    }

    #[test]
    fn no_identity_no_record_yields_empty_unsigned() {
        let signing = test_signing_config();
        let headers = build_fg_headers(&FgHeaderParams {
            identity: None,
            record: None,
            signing: Some(&signing),
            trace_id: "trace-1",
            now: Timestamp::from_millis(0),
        });

        assert!(headers.is_empty());
    }

    /// `identity_headers` deliberately duplicates
    /// `forgeguard_http::headers::inject_headers` (see the module doc for
    /// why forgeguard-axum can't depend on the unpublished `forgeguard_http`
    /// crate at runtime). This dev-only test pins the two implementations
    /// together so a future change to one doesn't silently drift from the
    /// other.
    #[test]
    fn identity_headers_matches_forgeguard_http() {
        let identity = make_identity();
        let projection = forgeguard_http::IdentityProjection::new(&identity, None, None);
        let expected = forgeguard_http::inject_headers(&projection);

        assert_eq!(identity_headers(&identity), expected);
    }
}
