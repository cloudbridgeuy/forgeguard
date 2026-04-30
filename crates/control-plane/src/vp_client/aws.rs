//! Production [`VpClient`] backed by [`aws_sdk_verifiedpermissions::Client`].

use aws_sdk_verifiedpermissions::types::{
    PolicyDefinition, PolicyDefinitionDetail, PolicyType, StaticPolicyDefinition,
};
use aws_sdk_verifiedpermissions::Client;

use super::{decode_name_from_description, encode_name_in_description, Error, NamedPolicy, Result};

/// Wrapper around the AWS Verified Permissions SDK client.
pub(crate) struct AwsVpClient {
    client: Client,
}

impl AwsVpClient {
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }
}

impl super::VpClient for AwsVpClient {
    async fn create_policy(
        &self,
        store_id: &str,
        name: &str,
        description: Option<&str>,
        statement: &str,
    ) -> Result<String> {
        let encoded_desc = encode_name_in_description(name, description);
        let static_def = StaticPolicyDefinition::builder()
            .statement(statement)
            .description(&encoded_desc)
            .build()
            .map_err(|e| Error::Other(format!("StaticPolicyDefinition build: {e}")))?;
        let definition = PolicyDefinition::Static(static_def);

        let resp = self
            .client
            .create_policy()
            .policy_store_id(store_id)
            .definition(definition)
            .send()
            .await
            .map_err(|e| {
                let svc = e.into_service_error();
                if svc.is_conflict_exception() {
                    Error::Conflict(format!("CreatePolicy '{name}': {svc}"))
                } else if svc.is_throttling_exception() {
                    Error::Throttled(format!("CreatePolicy '{name}': {svc}"))
                } else if svc.is_resource_not_found_exception() {
                    Error::NotFound(format!("CreatePolicy '{name}': {svc}"))
                } else {
                    Error::Other(format!("CreatePolicy '{name}': {svc}"))
                }
            })?;

        Ok(resp.policy_id().to_string())
    }

    async fn delete_policy_by_name(&self, store_id: &str, name: &str) -> Result<()> {
        let policies = self.list_policy_ids(store_id).await?;
        let target = policies
            .into_iter()
            .find(|p| p.name.as_deref() == Some(name))
            .ok_or_else(|| {
                Error::NotFound(format!("policy '{name}' not found in store '{store_id}'"))
            })?;

        self.client
            .delete_policy()
            .policy_store_id(store_id)
            .policy_id(&target.policy_id)
            .send()
            .await
            .map_err(|e| {
                let svc = e.into_service_error();
                if svc.is_resource_not_found_exception() {
                    Error::NotFound(format!("DeletePolicy '{}': {svc}", target.policy_id))
                } else if svc.is_throttling_exception() {
                    Error::Throttled(format!("DeletePolicy '{}': {svc}", target.policy_id))
                } else {
                    Error::Other(format!("DeletePolicy '{}': {svc}", target.policy_id))
                }
            })?;

        Ok(())
    }

    async fn list_policy_ids(&self, store_id: &str) -> Result<Vec<NamedPolicy>> {
        let mut paginator = self
            .client
            .list_policies()
            .policy_store_id(store_id)
            .into_paginator()
            .send();

        // Collect static-policy IDs across all pages before fetching details.
        // The paginator is async and cannot be held across the `get_policy` awaits
        // below, so we drain it into a Vec first.
        let mut policy_ids: Vec<String> = Vec::new();
        while let Some(page) = paginator.next().await {
            let page = page.map_err(|e| {
                let svc = e.into_service_error();
                if svc.is_resource_not_found_exception() {
                    Error::NotFound(format!("ListPolicies store '{store_id}': {svc}"))
                } else if svc.is_throttling_exception() {
                    Error::Throttled(format!("ListPolicies store '{store_id}': {svc}"))
                } else {
                    Error::Other(format!("ListPolicies store '{store_id}': {svc}"))
                }
            })?;
            for item in page.policies() {
                if *item.policy_type() == PolicyType::TemplateLinked {
                    continue;
                }
                policy_ids.push(item.policy_id().to_string());
            }
        }

        let mut out = Vec::with_capacity(policy_ids.len());
        for id in policy_ids {
            let detail = self
                .client
                .get_policy()
                .policy_store_id(store_id)
                .policy_id(&id)
                .send()
                .await
                .map_err(|e| {
                    let svc = e.into_service_error();
                    if svc.is_resource_not_found_exception() {
                        Error::NotFound(format!("GetPolicy '{id}': {svc}"))
                    } else if svc.is_throttling_exception() {
                        Error::Throttled(format!("GetPolicy '{id}': {svc}"))
                    } else {
                        Error::Other(format!("GetPolicy '{id}': {svc}"))
                    }
                })?;

            let raw_description = match detail.definition() {
                Some(PolicyDefinitionDetail::Static(s)) => s.description().map(String::from),
                _ => None,
            };
            let (decoded_name, _) = decode_name_from_description(raw_description.as_deref());
            out.push(NamedPolicy {
                policy_id: id,
                name: decoded_name,
            });
        }

        Ok(out)
    }
}
