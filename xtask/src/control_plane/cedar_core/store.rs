use std::fmt::Write as _;

use super::PolicyStoreId;

/// A snapshot of the VP policy store state.
pub(crate) struct StoreState {
    pub(crate) schema: Option<String>,
    pub(crate) templates: Vec<StoreTemplate>,
    pub(crate) policies: Vec<StorePolicy>,
}

/// A Cedar policy template stored in VP.
pub(crate) struct StoreTemplate {
    pub(crate) id: String,
    pub(crate) name: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) statement: String,
}

/// A Cedar static policy stored in VP.
pub(crate) struct StorePolicy {
    pub(crate) id: String,
    pub(crate) name: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) statement: String,
}

/// Return the first line of `text`, truncated to at most 80 visible characters.
///
/// Truncation respects UTF-8 character boundaries so it never panics on
/// multi-byte characters.
pub(crate) fn first_line_preview(text: &str) -> String {
    let first_line = text.lines().next().unwrap_or("");
    if first_line.chars().count() <= 80 {
        return first_line.to_string();
    }
    let end = first_line
        .char_indices()
        .nth(77)
        .map_or(first_line.len(), |(i, _)| i);
    format!("{}...", &first_line[..end])
}

/// Write a single entry (template or policy) to the output buffer.
fn write_entry(out: &mut String, label: &str, description: Option<&str>, statement: &str) {
    let _ = writeln!(out, "  - {label}");
    if let Some(desc) = description {
        let _ = writeln!(out, "    {desc}");
    }
    let _ = writeln!(out, "    {}", first_line_preview(statement));
}

/// Format the VP store state for terminal display.
pub(crate) fn format_status(store_id: &PolicyStoreId, state: &StoreState) -> String {
    let mut out = format!("Policy Store: {store_id}\n");

    match &state.schema {
        Some(schema) => {
            let _ = writeln!(out, "Schema: present");
            let _ = writeln!(out, "  {}", first_line_preview(schema));
        }
        None => out.push_str("Schema: none\n"),
    }

    let _ = writeln!(out, "Templates: {}", state.templates.len());
    for t in &state.templates {
        let label = t.name.as_deref().unwrap_or(&t.id);
        write_entry(&mut out, label, t.description.as_deref(), &t.statement);
    }

    let _ = writeln!(out, "Policies: {}", state.policies.len());
    for p in &state.policies {
        let label = p.name.as_deref().unwrap_or(&p.id);
        write_entry(&mut out, label, p.description.as_deref(), &p.statement);
    }

    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // --- format_status: empty store ---

    #[test]
    fn format_status_empty_store() {
        let id = PolicyStoreId::new("ps-empty");
        let state = StoreState {
            schema: None,
            templates: vec![],
            policies: vec![],
        };
        let output = format_status(&id, &state);
        assert!(output.contains("Policy Store: ps-empty"));
        assert!(output.contains("Schema: none"));
        assert!(output.contains("Templates: 0"));
        assert!(output.contains("Policies: 0"));
    }

    // --- format_status: store with schema ---

    #[test]
    fn format_status_with_schema() {
        let id = PolicyStoreId::new("ps-schema");
        let state = StoreState {
            schema: Some("{\"Acme\":{}}".to_string()),
            templates: vec![],
            policies: vec![],
        };
        let output = format_status(&id, &state);
        assert!(output.contains("Schema: present"));
        assert!(output.contains("{\"Acme\":{}}"));
        assert!(output.contains("Templates: 0"));
        assert!(output.contains("Policies: 0"));
    }

    // --- format_status: store with templates and policies ---

    #[test]
    fn format_status_with_templates_and_policies() {
        let id = PolicyStoreId::new("ps-full");
        let state = StoreState {
            schema: Some("{\"Ns\":{}}".to_string()),
            templates: vec![StoreTemplate {
                id: "tmpl-1".to_string(),
                name: Some("ReadOnly".to_string()),
                description: Some("Read-only access template".to_string()),
                statement: "permit(principal == ?principal, action, resource);".to_string(),
            }],
            policies: vec![
                StorePolicy {
                    id: "pol-1".to_string(),
                    name: Some("AdminAccess".to_string()),
                    description: None,
                    statement: "permit(principal, action, resource);".to_string(),
                },
                StorePolicy {
                    id: "pol-2".to_string(),
                    name: None,
                    description: Some("A nameless policy".to_string()),
                    statement: "forbid(principal, action, resource);".to_string(),
                },
            ],
        };
        let output = format_status(&id, &state);
        assert!(output.contains("Policy Store: ps-full"));
        assert!(output.contains("Schema: present"));
        assert!(output.contains("Templates: 1"));
        assert!(output.contains("- ReadOnly"));
        assert!(output.contains("Read-only access template"));
        assert!(output.contains("permit(principal == ?principal"));
        assert!(output.contains("Policies: 2"));
        assert!(output.contains("- AdminAccess"));
        assert!(output.contains("permit(principal, action, resource)"));
        // pol-2 has no name, should fall back to id
        assert!(output.contains("- pol-2"));
        assert!(output.contains("A nameless policy"));
        assert!(output.contains("forbid(principal, action, resource)"));
    }
}
