//! `forgeguard routes` — display the route table from config.

use std::path::Path;

use color_eyre::eyre::Result;

use forgeguard_http::{ProxyConfig, PublicAuthMode};

/// Pure function: format the route table as a string.
///
/// Separates public and authenticated routes. Returns a formatted table string.
pub(crate) fn format_route_table(config: &ProxyConfig) -> String {
    let mut lines = Vec::new();

    // Header
    lines.push(format!(
        "{:<8} {:<45} {:<25} {:<15} {}",
        "METHOD", "PATH", "ACTION", "AUTH", "GATE"
    ));
    lines.push("-".repeat(110));

    // Public routes first
    for route in config.public_routes() {
        let auth = match route.auth_mode() {
            PublicAuthMode::Anonymous => "anonymous",
            PublicAuthMode::Opportunistic => "opportunistic",
        };
        lines.push(format!(
            "{:<8} {:<45} {:<25} {:<15} {}",
            route.method(),
            route.path_pattern(),
            "-",
            auth,
            "-",
        ));
    }

    // Authenticated routes
    for route in config.routes() {
        let gate = route
            .feature_gate()
            .map(std::string::ToString::to_string)
            .unwrap_or_else(|| "-".into());
        lines.push(format!(
            "{:<8} {:<45} {:<25} {:<15} {}",
            route.method(),
            route.path_pattern(),
            route.action(),
            "required",
            gate,
        ));
    }

    lines.join("\n")
}

/// I/O shell: load config and print the route table.
pub(crate) fn run(config_path: &Path) -> Result<()> {
    let config = forgeguard_http::load_config(config_path)
        .map_err(|e| color_eyre::eyre::eyre!("failed to load config: {e}"))?;

    println!("{}", format_route_table(&config));
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn format_route_table_includes_header() {
        let config = forgeguard_http::parse_config(
            r#"
project_id = "test"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"
"#,
        )
        .unwrap();
        let output = format_route_table(&config);
        assert!(output.contains("METHOD"));
        assert!(output.contains("PATH"));
        assert!(output.contains("ACTION"));
        assert!(output.contains("AUTH"));
        assert!(output.contains("GATE"));
    }

    #[test]
    fn format_route_table_shows_public_routes() {
        let config = forgeguard_http::parse_config(
            r#"
project_id = "test"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[public_routes]]
method = "GET"
path = "/health"
auth_mode = "anonymous"

[[public_routes]]
method = "GET"
path = "/docs"
auth_mode = "opportunistic"
"#,
        )
        .unwrap();
        let output = format_route_table(&config);
        assert!(output.contains("/health"));
        assert!(output.contains("anonymous"));
        assert!(output.contains("/docs"));
        assert!(output.contains("opportunistic"));
    }

    #[test]
    fn format_route_table_shows_authenticated_routes() {
        let config = forgeguard_http::parse_config(
            r#"
project_id = "test"
listen_addr = "127.0.0.1:8080"
upstream_url = "http://localhost:3000"

[[routes]]
method = "GET"
path = "/api/items"
action = "todo:item:list"

[[routes]]
method = "POST"
path = "/api/items/:id/share"
action = "todo:item:share"
feature_gate = "todo:sharing"
"#,
        )
        .unwrap();
        let output = format_route_table(&config);
        assert!(output.contains("/api/items"));
        assert!(output.contains("todo:item:list"));
        assert!(output.contains("required"));
        assert!(output.contains("todo:sharing"));
    }
}
