//! Shared DynamoDB-local container management for `test` and `dev` subcommands.

use std::net::TcpStream;
use std::time::{Duration, Instant};

use color_eyre::eyre::{self, Context, Result};

use super::op;

// ---------------------------------------------------------------------------
// Functional Core — pure types and logic, no I/O
// ---------------------------------------------------------------------------

/// Determine which container runtime to use.
///
/// Prefers docker when both are available, falls back to podman.
/// Returns an error if neither is found.
pub(crate) fn detect_runtime_pure(
    docker_exists: bool,
    podman_exists: bool,
) -> Result<&'static str> {
    if docker_exists {
        return Ok("docker");
    }
    if podman_exists {
        return Ok("podman");
    }
    eyre::bail!("neither docker nor podman found on PATH")
}

/// Parse the host port from `{runtime} port` output.
///
/// Handles both IPv4 (`0.0.0.0:49153`) and IPv6 (`[::]:49153`) formats.
/// Takes the first line only.
pub(crate) fn parse_host_port(output: &str) -> Result<u16> {
    let line = output.lines().next().unwrap_or("").trim();
    let (_host, port_str) = line
        .rsplit_once(':')
        .ok_or_else(|| eyre::eyre!("no colon in port output: {line}"))?;
    port_str
        .parse::<u16>()
        .map_err(|e| eyre::eyre!("non-numeric port in output '{line}': {e}"))
}

// ---------------------------------------------------------------------------
// Imperative Shell — I/O, side effects, orchestration
// ---------------------------------------------------------------------------

/// Detect which container runtime is available on PATH.
pub(crate) fn detect_container_runtime() -> Result<&'static str> {
    detect_runtime_pure(op::tool_exists("docker"), op::tool_exists("podman"))
}

/// Start a DynamoDB Local container and return its container ID.
pub(crate) fn start_container(runtime: &str) -> Result<String> {
    println!("Starting DynamoDB Local container via {runtime}...");
    let id = duct::cmd(
        runtime,
        [
            "run",
            "-d",
            "--rm",
            "-p",
            "0:8000",
            "amazon/dynamodb-local",
            "-jar",
            "DynamoDBLocal.jar",
            "-inMemory",
            "-sharedDb",
        ],
    )
    .read()
    .context("failed to start DynamoDB Local container")?;

    let id = id.trim().to_string();
    if id.is_empty() {
        eyre::bail!("container runtime returned empty container ID");
    }
    Ok(id)
}

/// Discover the host port mapped to container port 8000.
pub(crate) fn discover_port(runtime: &str, container_id: &str) -> Result<u16> {
    let output = duct::cmd(runtime, ["port", container_id, "8000"])
        .read()
        .context("failed to discover container port")?;
    parse_host_port(&output)
}

/// Poll until DynamoDB Local is accepting TCP connections.
pub(crate) fn wait_for_dynamodb(port: u16) -> Result<()> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let timeout = Duration::from_secs(30);
    let interval = Duration::from_millis(200);
    let start = Instant::now();

    loop {
        if TcpStream::connect_timeout(&addr, interval).is_ok() {
            return Ok(());
        }
        if start.elapsed() > timeout {
            eyre::bail!("DynamoDB Local did not become ready within {timeout:?}");
        }
        std::thread::sleep(interval);
    }
}

/// Stop a running container. Errors are swallowed — the `--rm` flag handles cleanup.
pub(crate) fn stop_container(runtime: &str, container_id: &str) {
    println!("Stopping container {container_id}...");
    let _ = duct::cmd(runtime, ["stop", container_id])
        .stdout_capture()
        .stderr_capture()
        .unchecked()
        .run();
}

/// RAII guard that stops a container on drop, guaranteeing cleanup.
pub(crate) struct ContainerGuard {
    pub(crate) runtime: &'static str,
    pub(crate) id: String,
}

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        stop_container(self.runtime, &self.id);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // --- detect_runtime_pure ---

    #[test]
    fn detect_runtime_prefers_docker_when_both_exist() {
        assert_eq!(detect_runtime_pure(true, true).unwrap(), "docker");
    }

    #[test]
    fn detect_runtime_falls_back_to_podman() {
        assert_eq!(detect_runtime_pure(false, true).unwrap(), "podman");
    }

    #[test]
    fn detect_runtime_docker_only() {
        assert_eq!(detect_runtime_pure(true, false).unwrap(), "docker");
    }

    #[test]
    fn detect_runtime_neither_fails() {
        assert!(detect_runtime_pure(false, false).is_err());
    }

    // --- parse_host_port ---

    #[test]
    fn parse_host_port_ipv4() {
        assert_eq!(parse_host_port("0.0.0.0:49153\n").unwrap(), 49153);
    }

    #[test]
    fn parse_host_port_ipv6() {
        assert_eq!(parse_host_port("[::]:49153\n").unwrap(), 49153);
    }

    #[test]
    fn parse_host_port_multiline_takes_first() {
        assert_eq!(
            parse_host_port("0.0.0.0:49153\n[::]:49153\n").unwrap(),
            49153
        );
    }

    #[test]
    fn parse_host_port_empty_fails() {
        assert!(parse_host_port("").is_err());
        assert!(parse_host_port("\n").is_err());
    }

    #[test]
    fn parse_host_port_no_colon_fails() {
        assert!(parse_host_port("49153").is_err());
    }

    #[test]
    fn parse_host_port_non_numeric_fails() {
        assert!(parse_host_port("0.0.0.0:abc\n").is_err());
    }
}
