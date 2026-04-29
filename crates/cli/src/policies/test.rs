//! `forgeguard policies test` — test authorization decisions against AWS Verified Permissions.

use std::path::Path;

use crate::aws::{self, AwsConfigParams};
use aws_sdk_verifiedpermissions::types::{
    ActionIdentifier, EntitiesDefinition, EntityIdentifier, EntityItem,
};
use color_eyre::eyre::{bail, Result, WrapErr};
use forgeguard_core::{
    CedarEntityRef, GroupName, PrincipalRef, ProjectId, QualifiedAction, TenantId, UserId,
};
use forgeguard_http::{load_config, PolicyTest, PolicyTestExpect, ProxyConfig};

// ---------------------------------------------------------------------------
// CLI test flags
// ---------------------------------------------------------------------------

/// CLI flags that define a single inline test scenario.
pub(crate) struct CliTestFlags<'a> {
    pub(crate) principal: Option<&'a str>,
    pub(crate) groups: Option<&'a str>,
    pub(crate) tenant: Option<&'a str>,
    pub(crate) action: Option<&'a str>,
    pub(crate) resource: Option<&'a str>,
    pub(crate) expect: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Test scenario (unified representation)
// ---------------------------------------------------------------------------

/// A single test scenario to execute against VP.
#[derive(serde::Deserialize)]
struct TestScenario {
    name: String,
    principal: UserId,
    #[serde(default)]
    groups: Vec<GroupName>,
    tenant: TenantId,
    action: QualifiedAction,
    resource: Option<CedarEntityRef>,
    expect: PolicyTestExpect,
}

impl TestScenario {
    fn from_policy_test(test: &PolicyTest) -> Result<Self> {
        Ok(Self {
            name: test.name().to_owned(),
            principal: UserId::new(test.principal())
                .wrap_err("invalid principal in policy test")?,
            groups: test.groups().to_vec(),
            tenant: TenantId::new(test.tenant()).wrap_err("invalid tenant in policy test")?,
            action: test.action().clone(),
            resource: test.resource().cloned(),
            expect: test.expect(),
        })
    }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

/// Run the test subcommand.
pub(crate) async fn run(
    config_path: &Path,
    profile: Option<&str>,
    region: Option<&str>,
    _external_tests_path: Option<&str>,
    cli_flags: &CliTestFlags<'_>,
) -> Result<()> {
    let config = load_config(config_path)
        .wrap_err_with(|| format!("failed to load config from '{}'", config_path.display()))?;

    let authz = config
        .authz()
        .ok_or_else(|| color_eyre::eyre::eyre!("[authz] section missing from config"))?;
    let policy_store_id = authz.policy_store_id();

    // Collect test scenarios from all sources.
    let scenarios = collect_scenarios(&config, cli_flags)?;

    if scenarios.is_empty() {
        println!("No test scenarios found. Add [[policy_tests]] to config or use CLI flags.");
        return Ok(());
    }

    // Build AWS SDK config.
    let sdk_config = aws::build_sdk_config(&AwsConfigParams {
        config: config.aws(),
        profile,
        region,
    })
    .await;

    let client = aws_sdk_verifiedpermissions::Client::new(&sdk_config);

    let mut passed = 0usize;
    let mut failed = 0usize;

    for scenario in &scenarios {
        let result = execute_scenario(&client, policy_store_id, config.project_id(), scenario)
            .await
            .wrap_err_with(|| format!("test '{}' failed to execute", scenario.name))?;

        let expected_allow = scenario.expect == PolicyTestExpect::Allow;
        if result == expected_allow {
            println!("  PASS: {}", scenario.name);
            passed += 1;
        } else {
            let expected = if expected_allow { "allow" } else { "deny" };
            let actual = if result { "allow" } else { "deny" };
            println!(
                "  FAIL: {} (expected {expected}, got {actual})",
                scenario.name
            );
            failed += 1;
        }
    }

    println!();
    println!(
        "{passed} passed, {failed} failed, {} total",
        passed + failed
    );

    if failed > 0 {
        bail!("{failed} test(s) failed");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Collect scenarios
// ---------------------------------------------------------------------------

/// Merge test scenarios from: inline `[[policy_tests]]` in config and CLI flags.
fn collect_scenarios(
    config: &ProxyConfig,
    cli_flags: &CliTestFlags<'_>,
) -> Result<Vec<TestScenario>> {
    let mut scenarios = Vec::new();

    // Inline config tests.
    for test in config.policy_tests() {
        scenarios.push(TestScenario::from_policy_test(test)?);
    }

    // CLI flags test.
    if let Some(scenario) = build_scenario_from_flags(cli_flags)? {
        scenarios.push(scenario);
    }

    Ok(scenarios)
}

/// Build a test scenario from CLI flags, if all required flags are present.
fn build_scenario_from_flags(flags: &CliTestFlags<'_>) -> Result<Option<TestScenario>> {
    let (Some(principal), Some(action_str), Some(expect_str)) =
        (flags.principal, flags.action, flags.expect)
    else {
        // Not all required flags present — skip CLI test.
        return Ok(None);
    };

    let action = QualifiedAction::parse(action_str)
        .wrap_err_with(|| format!("invalid --action '{action_str}'"))?;

    let expect = match expect_str.to_lowercase().as_str() {
        "allow" => PolicyTestExpect::Allow,
        "deny" => PolicyTestExpect::Deny,
        other => bail!("invalid --expect '{other}': must be 'allow' or 'deny'"),
    };

    let groups = match flags.groups {
        Some(g) => g
            .split(',')
            .map(|s| GroupName::new(s.trim()).map_err(color_eyre::eyre::Error::from))
            .collect::<Result<Vec<_>>>()?,
        None => Vec::new(),
    };

    let principal =
        UserId::new(principal).wrap_err_with(|| format!("invalid --principal '{principal}'"))?;
    let tenant = TenantId::new(flags.tenant.unwrap_or("default")).wrap_err("invalid --tenant")?;

    let resource = flags
        .resource
        .map(|r| CedarEntityRef::parse(r).wrap_err_with(|| format!("invalid --resource '{r}'")))
        .transpose()?;

    Ok(Some(TestScenario {
        name: format!("cli: {principal} {action_str} -> {expect_str}"),
        principal,
        groups,
        tenant,
        action,
        resource,
        expect,
    }))
}

// ---------------------------------------------------------------------------
// Execute a single scenario
// ---------------------------------------------------------------------------

/// Execute a single test scenario against Verified Permissions.
/// Returns `true` if the decision was ALLOW, `false` if DENY.
async fn execute_scenario(
    client: &aws_sdk_verifiedpermissions::Client,
    policy_store_id: &str,
    project: &ProjectId,
    scenario: &TestScenario,
) -> Result<bool> {
    let principal_ref = PrincipalRef::new(scenario.principal.clone());

    // Build principal entity identifier.
    let principal_fgrn = principal_ref.to_fgrn(project, &scenario.tenant);
    let principal_entity = EntityIdentifier::builder()
        .entity_type(principal_ref.vp_entity_type(project))
        .entity_id(principal_fgrn.as_vp_entity_id())
        .build()
        .wrap_err("failed to build principal entity")?;

    // Build action identifier.
    let action = ActionIdentifier::builder()
        .action_type(scenario.action.vp_action_type(project))
        .action_id(scenario.action.vp_action_id())
        .build()
        .wrap_err("failed to build action identifier")?;

    // Build inline entities (user + groups).
    let entities =
        build_inline_entities(&principal_ref, &scenario.groups, project, &scenario.tenant)?;

    // Build the request.
    let mut req = client
        .is_authorized()
        .policy_store_id(policy_store_id)
        .principal(principal_entity)
        .action(action)
        .entities(entities);

    // Add resource if present.
    // The entity_id must match the Cedar policy's resource constraint, which
    // uses the raw CedarEntityRef id (e.g., "top-secret"), not the full FGRN.
    if let Some(ref resource_ref) = scenario.resource {
        let vp_ns = forgeguard_core::CedarNamespace::from_project(project);
        let entity_type = forgeguard_core::CedarEntityType::new_from_segments(
            resource_ref.namespace(),
            resource_ref.entity(),
        );
        let resource_entity = EntityIdentifier::builder()
            .entity_type(format!("{}::{}", vp_ns.as_str(), entity_type))
            .entity_id(resource_ref.id().as_str())
            .build()
            .wrap_err("failed to build resource entity")?;
        req = req.resource(resource_entity);
    }

    tracing::warn!(
        test = %scenario.name,
        principal_type = %principal_ref.vp_entity_type(project),
        principal_id = %principal_fgrn.as_vp_entity_id(),
        action_type = %scenario.action.vp_action_type(project),
        action_id = %scenario.action.vp_action_id(),
        groups = ?scenario.groups.iter().map(GroupName::as_str).collect::<Vec<_>>(),
        "sending IsAuthorized request"
    );

    let response = req.send().await.wrap_err("IsAuthorized request failed")?;

    // Log errors and determining policies for debugging.
    for err in response.errors() {
        tracing::warn!(
            test = %scenario.name,
            error = %err.error_description(),
            "VP evaluation error"
        );
    }
    for policy in response.determining_policies() {
        tracing::debug!(
            test = %scenario.name,
            policy_id = %policy.policy_id(),
            "determining policy"
        );
    }

    Ok(matches!(
        response.decision(),
        aws_sdk_verifiedpermissions::types::Decision::Allow
    ))
}

// ---------------------------------------------------------------------------
// Build inline entities
// ---------------------------------------------------------------------------

/// Build VP inline entities: user entity (with group parents) + group entities.
///
/// Note: this function assumes `principal` is always a `PrincipalKind::User`.
/// Machine principals are not yet supported in test scenarios and will produce
/// incorrect entities (group parents attached to a machine entity).
fn build_inline_entities(
    principal: &PrincipalRef,
    groups: &[GroupName],
    project: &ProjectId,
    tenant: &TenantId,
) -> Result<EntitiesDefinition> {
    let principal_fgrn = principal.to_fgrn(project, tenant);
    let group_type = PrincipalRef::vp_group_entity_type(project);

    // Build group entity identifiers using group name (not FGRN) to match
    // compiled Cedar policies which are tenant-independent.
    let group_identifiers: Vec<EntityIdentifier> = groups
        .iter()
        .map(|g| {
            EntityIdentifier::builder()
                .entity_type(group_type.as_str())
                .entity_id(g.as_str())
                .build()
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .wrap_err("failed to build group entity identifiers")?;

    // Build user entity with group parents.
    let mut user_builder = EntityItem::builder().identifier(
        EntityIdentifier::builder()
            .entity_type(principal.vp_entity_type(project))
            .entity_id(principal_fgrn.as_vp_entity_id())
            .build()
            .wrap_err("failed to build user entity identifier")?,
    );

    for parent in &group_identifiers {
        user_builder = user_builder.parents(parent.clone());
    }

    let mut entities = vec![user_builder.build()];

    // Build group entities (no parents, no attributes).
    for group_id in &group_identifiers {
        entities.push(EntityItem::builder().identifier(group_id.clone()).build());
    }

    Ok(EntitiesDefinition::EntityList(entities))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::TestScenario;

    #[test]
    fn rejects_invalid_principal_at_deserialize() {
        let toml = r#"
            name = "bad principal"
            principal = ""
            tenant = "tenant-a"
            action = "todo:list:read"
            expect = "allow"
        "#;
        let result: Result<TestScenario, _> = toml::from_str(toml);
        assert!(
            result.is_err(),
            "empty principal should fail at deserialize"
        );
    }

    #[test]
    fn accepts_valid_scenario() {
        let toml = r#"
            name = "good scenario"
            principal = "user-1"
            tenant = "tenant-a"
            action = "todo:list:read"
            expect = "allow"
        "#;
        let scenario: TestScenario =
            toml::from_str(toml).expect("valid scenario should deserialize");
        assert_eq!(scenario.principal.as_str(), "user-1");
        assert_eq!(scenario.tenant.as_str(), "tenant-a");
    }
}
