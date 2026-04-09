use color_eyre::eyre::{self, Context, Result};

use super::cedar_core::{PolicyStoreId, StorePolicy, StoreState, StoreTemplate};

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

    // ListPolicyTemplates does not return a name field; it only returns the
    // description. The VP API does not surface template names, so `name` is
    // always None.
    let mut summaries: Vec<(String, Option<String>)> = Vec::new();

    while let Some(page) = paginator.next().await {
        let page = page.context("ListPolicyTemplates failed")?;
        for item in page.policy_templates() {
            summaries.push((
                item.policy_template_id().to_string(),
                item.description().map(String::from),
            ));
        }
    }

    let mut templates = Vec::with_capacity(summaries.len());
    for (id, description) in summaries {
        let detail = client
            .get_policy_template()
            .policy_store_id(store_id.as_str())
            .policy_template_id(&id)
            .send()
            .await
            .context(format!("GetPolicyTemplate {id} failed"))?;

        templates.push(StoreTemplate {
            id,
            name: None,
            description,
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

    let mut policy_ids: Vec<String> = Vec::new();

    while let Some(page) = paginator.next().await {
        let page = page.context("ListPolicies failed")?;
        for item in page.policies() {
            policy_ids.push(item.policy_id().to_string());
        }
    }

    let mut policies = Vec::with_capacity(policy_ids.len());
    for id in policy_ids {
        let detail = client
            .get_policy()
            .policy_store_id(store_id.as_str())
            .policy_id(&id)
            .send()
            .await
            .context(format!("GetPolicy {id} failed"))?;

        let (statement, name, description) = extract_static_policy_details(&detail);

        policies.push(StorePolicy {
            id,
            name,
            description,
            statement,
        });
    }

    Ok(policies)
}

fn extract_static_policy_details(
    detail: &aws_sdk_verifiedpermissions::operation::get_policy::GetPolicyOutput,
) -> (String, Option<String>, Option<String>) {
    use aws_sdk_verifiedpermissions::types::PolicyDefinitionDetail;

    match detail.definition() {
        Some(PolicyDefinitionDetail::Static(s)) => (
            s.statement().to_string(),
            None,
            s.description().map(String::from),
        ),
        Some(PolicyDefinitionDetail::TemplateLinked(_)) => {
            // Template-linked policies don't have inline statements.
            ("(template-linked)".to_string(), None, None)
        }
        _ => ("(unknown policy type)".to_string(), None, None),
    }
}
