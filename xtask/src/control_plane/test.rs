use clap::Args;
use color_eyre::eyre::{Context, Result};

use super::dynamo_local::{
    detect_container_runtime, discover_port, start_container, wait_for_dynamodb, ContainerGuard,
};

/// CLI arguments for the test subcommand.
#[derive(Args)]
pub(crate) struct TestArgs {}

/// Run the DynamoDB integration tests with the endpoint set.
///
/// Two test suites share the running container: the control-plane handler
/// tests and the xtask seed-shell tests, both gated behind their own
/// `dynamodb-tests` feature.
fn run_tests(port: u16) -> Result<()> {
    let endpoint = format!("http://127.0.0.1:{port}");
    println!("Running DynamoDB integration tests (endpoint: {endpoint})...");

    for package in ["forgeguard_control_plane", "xtask"] {
        let output = duct::cmd(
            "cargo",
            ["test", "-p", package, "--features", "dynamodb-tests"],
        )
        .env("DYNAMODB_ENDPOINT", &endpoint)
        .unchecked()
        .run()
        .with_context(|| format!("failed to run cargo test for {package}"))?;

        if !output.status.success() {
            color_eyre::eyre::bail!("DynamoDB integration tests failed for {package}");
        }
    }
    Ok(())
}

/// Orchestrate: detect runtime, start container, run tests, stop container.
///
/// The `async` signature is for dispatch consistency with other subcommands.
pub(crate) async fn run(_args: &TestArgs) -> Result<()> {
    let runtime = detect_container_runtime()?;
    let container_id = start_container(runtime)?;

    println!("Container: {container_id}");

    let _guard = ContainerGuard::new(runtime, container_id.clone());

    let port = discover_port(runtime, &container_id)?;
    wait_for_dynamodb(port)?;
    run_tests(port)?;

    println!("DynamoDB integration tests passed.");
    Ok(())
}
