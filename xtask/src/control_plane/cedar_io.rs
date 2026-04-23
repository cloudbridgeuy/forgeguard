use std::path::Path;

use aws_sdk_verifiedpermissions::types::SchemaDefinition;
use color_eyre::eyre::{self, Context, Result};

use super::cedar_core::desired::DesiredState;
use super::cedar_core::{
    CedarSyncConfig, PolicyStoreId, StorePolicy, StoreState, StoreTemplate, SyncAction, SyncPlan,
    SyncResult,
};

/// Resolve a policy store ID from a raw string.
///
/// If `raw` starts with `op://`, it is resolved via `op read`. Otherwise it is
/// returned as-is. An optional 1Password account can be provided for
/// multi-account setups.
pub(crate) fn resolve_policy_store_id(
    raw: &str,
    op_account: Option<&str>,
) -> Result<PolicyStoreId> {
    if raw.starts_with("op://") {
        let mut args = vec!["read".to_string(), raw.to_string()];
        if let Some(account) = op_account {
            args.push("--account".to_string());
            args.push(account.to_string());
        }
        let output = duct::cmd("op", &args)
            .stdout_capture()
            .stderr_capture()
            .read()
            .context("failed to read policy store ID from 1Password")?;
        let trimmed = output.trim();
        if trimmed.is_empty() {
            eyre::bail!("1Password returned an empty policy store ID");
        }
        Ok(PolicyStoreId::new(trimmed))
    } else {
        Ok(PolicyStoreId::new(raw))
    }
}

/// Read the current VP policy store state via AWS SDK.
///
/// Fetches the schema, all templates (with bodies), and all static policies
/// (with bodies) from the given policy store.
pub(crate) async fn read_vp_state(
    client: &aws_sdk_verifiedpermissions::Client,
    store_id: &PolicyStoreId,
) -> Result<StoreState> {
    let schema = read_schema(client, store_id).await?;
    let templates = read_templates(client, store_id).await?;
    let policies = read_policies(client, store_id).await?;

    Ok(StoreState {
        schema,
        templates,
        policies,
    })
}

async fn read_schema(
    client: &aws_sdk_verifiedpermissions::Client,
    store_id: &PolicyStoreId,
) -> Result<Option<String>> {
    let result = client
        .get_schema()
        .policy_store_id(store_id.as_str())
        .send()
        .await;

    match result {
        Ok(resp) => {
            let schema_str = resp.schema();
            if schema_str.is_empty() {
                Ok(None)
            } else {
                Ok(Some(schema_str.to_string()))
            }
        }
        Err(err) => {
            // A store with no schema returns an error; treat as empty.
            let service_err = err.into_service_error();
            if service_err.is_resource_not_found_exception() {
                Ok(None)
            } else {
                Err(eyre::eyre!(service_err).wrap_err("GetSchema failed"))
            }
        }
    }
}

async fn read_templates(
    client: &aws_sdk_verifiedpermissions::Client,
    store_id: &PolicyStoreId,
) -> Result<Vec<StoreTemplate>> {
    let mut paginator = client
        .list_policy_templates()
        .policy_store_id(store_id.as_str())
        .into_paginator()
        .send();

    let mut summaries: Vec<(String, Option<String>, Option<String>)> = Vec::new();

    while let Some(page) = paginator.next().await {
        let page = page.context("ListPolicyTemplates failed")?;
        for item in page.policy_templates() {
            summaries.push((
                item.policy_template_id().to_string(),
                item.name().map(String::from),
                item.description().map(String::from),
            ));
        }
    }

    let mut templates = Vec::with_capacity(summaries.len());
    for (id, _sdk_name, sdk_description) in summaries {
        let detail = client
            .get_policy_template()
            .policy_store_id(store_id.as_str())
            .policy_template_id(&id)
            .send()
            .await
            .context(format!("GetPolicyTemplate {id} failed"))?;

        // Decode name from the [name] prefix in the description field.
        let (decoded_name, decoded_desc) = decode_name_from_description(sdk_description.as_deref());

        templates.push(StoreTemplate {
            id,
            name: decoded_name,
            description: decoded_desc,
            statement: detail.statement().to_string(),
        });
    }

    Ok(templates)
}

async fn read_policies(
    client: &aws_sdk_verifiedpermissions::Client,
    store_id: &PolicyStoreId,
) -> Result<Vec<StorePolicy>> {
    let mut paginator = client
        .list_policies()
        .policy_store_id(store_id.as_str())
        .into_paginator()
        .send();

    let mut policy_summaries: Vec<(String, Option<String>)> = Vec::new();

    while let Some(page) = paginator.next().await {
        let page = page.context("ListPolicies failed")?;
        for item in page.policies() {
            // Skip template-linked policies — they are managed externally
            // (created when roles are assigned to users) and should not be
            // part of the sync engine's view of state.
            if *item.policy_type() == aws_sdk_verifiedpermissions::types::PolicyType::TemplateLinked
            {
                continue;
            }
            policy_summaries.push((item.policy_id().to_string(), item.name().map(String::from)));
        }
    }

    let mut policies = Vec::with_capacity(policy_summaries.len());
    for (id, _sdk_name) in policy_summaries {
        let detail = client
            .get_policy()
            .policy_store_id(store_id.as_str())
            .policy_id(&id)
            .send()
            .await
            .context(format!("GetPolicy {id} failed"))?;

        let (statement, raw_description) = extract_static_policy_details(&detail);

        // Decode name from the [name] prefix in the description field.
        let (decoded_name, decoded_desc) = decode_name_from_description(raw_description.as_deref());

        policies.push(StorePolicy {
            id,
            name: decoded_name,
            description: decoded_desc,
            statement,
        });
    }

    Ok(policies)
}

fn extract_static_policy_details(
    detail: &aws_sdk_verifiedpermissions::operation::get_policy::GetPolicyOutput,
) -> (String, Option<String>) {
    use aws_sdk_verifiedpermissions::types::PolicyDefinitionDetail;

    match detail.definition() {
        Some(PolicyDefinitionDetail::Static(s)) => {
            (s.statement().to_string(), s.description().map(String::from))
        }
        // Template-linked policies are filtered out during listing, so we
        // should never reach this point. Treat unexpected variants as unknown.
        _ => ("(unknown policy type)".to_string(), None),
    }
}

// ---------------------------------------------------------------------------
// Config parsing + schema sync (V2)
// ---------------------------------------------------------------------------

/// Read and parse a `forgeguard.toml`-style config for Cedar sync.
///
/// Only the fields relevant to `cedar sync` are deserialized; unknown top-level
/// keys (e.g. `routes`, `features`) are silently ignored thanks to the TOML
/// parser's default behavior and serde's `#[serde(default)]` on optional fields.
pub(crate) fn parse_cedar_config(path: &Path) -> Result<CedarSyncConfig> {
    let content =
        std::fs::read_to_string(path).context(format!("failed to read {}", path.display()))?;

    // The forgeguard.toml has the policy_store_id nested under [authz].
    // CedarSyncConfig expects it at the top level. Extract it from the [authz]
    // section and inject it at the top level for deserialization.
    let raw: toml::Value =
        toml::from_str(&content).context(format!("failed to parse {}", path.display()))?;

    let table = raw
        .as_table()
        .ok_or_else(|| eyre::eyre!("config is not a TOML table"))?;

    let policy_store_id = table
        .get("authz")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("policy_store_id"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            // Also check top-level policy_store_id for simplified configs.
            table
                .get("policy_store_id")
                .and_then(|v| v.as_str())
        })
        .ok_or_else(|| {
            eyre::eyre!(
                "missing policy_store_id: expected [authz].policy_store_id or top-level policy_store_id"
            )
        })?;

    // Build a new table with the extracted fields.
    let mut sync_table = toml::map::Map::new();
    sync_table.insert(
        "policy_store_id".to_string(),
        toml::Value::String(policy_store_id.to_string()),
    );

    // Copy optional sections relevant to Cedar sync.
    for key in ["schema", "tenant", "policies", "templates"] {
        if let Some(value) = table.get(key) {
            sync_table.insert(key.to_string(), value.clone());
        }
    }

    let config: CedarSyncConfig = toml::Value::Table(sync_table)
        .try_into()
        .context("failed to deserialize Cedar sync config")?;

    Ok(config)
}

// ---------------------------------------------------------------------------
// Shared pipeline: config -> desired state + store ID
// ---------------------------------------------------------------------------

/// Intermediate result from the shared config-to-desired-state pipeline.
///
/// Both `cedar sync` and `cedar diff` run the same preflight -> parse ->
/// resolve -> schema -> desired sequence. This struct bundles the outputs
/// so callers don't duplicate the pipeline.
pub(crate) struct PreparedPipeline {
    pub(crate) store_id: PolicyStoreId,
    pub(crate) desired: DesiredState,
}

/// Run the common config-preparation pipeline shared by sync and diff.
///
/// Steps: parse config, resolve policy store ID, build desired state.
/// Schema generation (when configured) is handled internally by
/// `build_desired_state` -- no file I/O is needed.
pub(crate) fn prepare_pipeline(
    config_path: &Path,
    op_account: Option<&str>,
) -> Result<PreparedPipeline> {
    let config = parse_cedar_config(config_path)?;
    let store_id = resolve_policy_store_id(&config.policy_store_id, op_account)?;
    let desired = super::cedar_core::build_desired_state(&config)?;

    Ok(PreparedPipeline { store_id, desired })
}

/// Push a Cedar schema to a VP policy store.
///
/// Uses the `CedarJson` schema format, which is what VP's `PutSchema` API
/// accepts as JSON-encoded Cedar schema.
pub(crate) async fn put_schema(
    client: &aws_sdk_verifiedpermissions::Client,
    store_id: &PolicyStoreId,
    schema_content: &str,
) -> Result<()> {
    client
        .put_schema()
        .policy_store_id(store_id.as_str())
        .definition(SchemaDefinition::CedarJson(schema_content.to_string()))
        .send()
        .await
        .context("PutSchema failed")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Sync plan execution (V3)
// ---------------------------------------------------------------------------

/// Execute a sync plan against the VP policy store.
///
/// Iterates actions in order (the plan is pre-sorted by `compute_sync_plan`).
/// Returns outcome counters for terminal display.
///
/// **Partial failure:** If an action fails mid-plan, earlier actions have
/// already been applied to the remote store. The recovery path is to re-run
/// sync, which will converge idempotently — the plan recomputes a diff
/// against current state, so already-applied actions become no-ops.
pub(crate) async fn apply_sync_plan(
    client: &aws_sdk_verifiedpermissions::Client,
    store_id: &PolicyStoreId,
    plan: &SyncPlan,
) -> Result<SyncResult> {
    let mut result = SyncResult {
        schema_updated: false,
        created_templates: 0,
        deleted_templates: 0,
        created_policies: 0,
        deleted_policies: 0,
    };

    for action in &plan.actions {
        match action {
            SyncAction::PutSchema { new, .. } => {
                put_schema(client, store_id, new).await?;
                result.schema_updated = true;
            }
            SyncAction::CreateTemplate(t) => {
                create_policy_template(
                    client,
                    store_id,
                    &t.name,
                    t.description.as_deref(),
                    &t.statement,
                )
                .await?;
                result.created_templates += 1;
            }
            SyncAction::DeleteTemplate { id, .. } => {
                delete_policy_template(client, store_id, id).await?;
                result.deleted_templates += 1;
            }
            SyncAction::CreatePolicy(p) => {
                create_policy(
                    client,
                    store_id,
                    &p.name,
                    p.description.as_deref(),
                    &p.statement,
                )
                .await?;
                result.created_policies += 1;
            }
            SyncAction::DeletePolicy { id, .. } => {
                delete_policy(client, store_id, id).await?;
                result.deleted_policies += 1;
            }
        }
    }

    Ok(result)
}

/// Encode a resource name into the VP `description` field.
///
/// VP does not support a native `name` field on templates or policies, so we
/// encode the name as a `[name]` prefix in the description. This allows the
/// sync engine to match resources by name when reading them back.
///
/// Format: `[name] description text` or `[name]` if no description.
fn encode_name_in_description(name: &str, description: Option<&str>) -> String {
    match description {
        Some(desc) => format!("[{name}] {desc}"),
        None => format!("[{name}]"),
    }
}

/// Decode a resource name from a VP `description` field.
///
/// Returns `(name, remaining_description)`. If the description doesn't follow
/// the `[name]` encoding, returns `(None, original_description)`.
fn decode_name_from_description(description: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(desc) = description else {
        return (None, None);
    };

    if let Some(rest) = desc.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let name = &rest[..end];
            if !name.is_empty() {
                let remaining = rest[end + 1..].trim();
                let desc = if remaining.is_empty() {
                    None
                } else {
                    Some(remaining.to_string())
                };
                return (Some(name.to_string()), desc);
            }
        }
    }

    (None, Some(desc.to_string()))
}

/// Create a policy template in the VP store.
///
/// Encodes the name as a `[name]` prefix in the description field since VP
/// does not support a native `name` field on `CreatePolicyTemplate`.
async fn create_policy_template(
    client: &aws_sdk_verifiedpermissions::Client,
    store_id: &PolicyStoreId,
    name: &str,
    description: Option<&str>,
    statement: &str,
) -> Result<()> {
    let encoded_desc = encode_name_in_description(name, description);

    let resp = client
        .create_policy_template()
        .policy_store_id(store_id.as_str())
        .statement(statement)
        .description(&encoded_desc)
        .send()
        .await
        .context(format!("CreatePolicyTemplate '{name}' failed"))?;

    let template_id = resp.policy_template_id();
    println!("  Created template '{name}' (id: {template_id})");

    Ok(())
}

/// Delete a policy template from the VP store.
async fn delete_policy_template(
    client: &aws_sdk_verifiedpermissions::Client,
    store_id: &PolicyStoreId,
    template_id: &str,
) -> Result<()> {
    client
        .delete_policy_template()
        .policy_store_id(store_id.as_str())
        .policy_template_id(template_id)
        .send()
        .await
        .context(format!("DeletePolicyTemplate '{template_id}' failed"))?;

    println!("  Deleted template (id: {template_id})");

    Ok(())
}

/// Create a static policy in the VP store.
///
/// Encodes the name as a `[name]` prefix in the `StaticPolicyDefinition`
/// description field since VP does not support a native `name` field on
/// `CreatePolicy`.
async fn create_policy(
    client: &aws_sdk_verifiedpermissions::Client,
    store_id: &PolicyStoreId,
    name: &str,
    description: Option<&str>,
    statement: &str,
) -> Result<()> {
    use aws_sdk_verifiedpermissions::types::{PolicyDefinition, StaticPolicyDefinition};

    let encoded_desc = encode_name_in_description(name, description);

    let static_def = StaticPolicyDefinition::builder()
        .statement(statement)
        .description(&encoded_desc)
        .build()
        .context(format!(
            "failed to build StaticPolicyDefinition for '{name}'"
        ))?;

    let definition = PolicyDefinition::Static(static_def);

    let resp = client
        .create_policy()
        .policy_store_id(store_id.as_str())
        .definition(definition)
        .send()
        .await
        .context(format!("CreatePolicy '{name}' failed"))?;

    let policy_id = resp.policy_id();
    println!("  Created policy '{name}' (id: {policy_id})");

    Ok(())
}

/// Delete a static policy from the VP store.
async fn delete_policy(
    client: &aws_sdk_verifiedpermissions::Client,
    store_id: &PolicyStoreId,
    policy_id: &str,
) -> Result<()> {
    client
        .delete_policy()
        .policy_store_id(store_id.as_str())
        .policy_id(policy_id)
        .send()
        .await
        .context(format!("DeletePolicy '{policy_id}' failed"))?;

    println!("  Deleted policy (id: {policy_id})");

    Ok(())
}
