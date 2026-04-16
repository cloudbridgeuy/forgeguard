//! `forgeguard policies validate` — compile and validate Cedar policies locally.

use std::path::Path;

use color_eyre::eyre::{Result, WrapErr};
use forgeguard_core::{compile_all_to_cedar, generate_cedar_schema};
use forgeguard_http::load_config;
use owo_colors::OwoColorize;

/// Run the validate subcommand.
///
/// Loads config, compiles Cedar policies and schema, prints output.
/// Pure — no AWS calls.
pub(crate) fn run(config_path: &Path, json: bool) -> Result<()> {
    let config = load_config(config_path)
        .wrap_err_with(|| format!("failed to load config from '{}'", config_path.display()))?;

    let compiled_policies =
        compile_all_to_cedar(config.policies(), config.groups(), config.project_id())
            .wrap_err("failed to compile Cedar policies")?;

    // Collect actions from route definitions.
    let actions: Vec<_> = config.routes().iter().map(|r| r.action().clone()).collect();

    let schema = generate_cedar_schema(config.policies(), &actions, config.project_id(), None);

    if json {
        print_json(&schema, &compiled_policies)?;
    } else {
        print_human(&schema, &compiled_policies);
    }

    Ok(())
}

fn print_json(schema: &str, compiled: &[String]) -> Result<()> {
    let schema_value: serde_json::Value =
        serde_json::from_str(schema).wrap_err("schema is not valid JSON")?;

    let policy_entries: Vec<serde_json::Value> = compiled
        .iter()
        .enumerate()
        .map(|(i, cedar)| {
            serde_json::json!({
                "index": i + 1,
                "cedar": cedar,
            })
        })
        .collect();

    let output = serde_json::json!({
        "schema": schema_value,
        "statements": policy_entries,
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output).wrap_err("failed to serialize JSON")?
    );
    Ok(())
}

fn print_human(schema: &str, compiled: &[String]) {
    let use_color = should_colorize();

    print_header("Cedar Schema", use_color);
    println!("{schema}");

    for (i, statement) in compiled.iter().enumerate() {
        print_header(&format!("Statement {}", i + 1), use_color);
        println!("{statement}");
    }

    if use_color {
        println!(
            "\n{}  {} statements compiled, schema generated.",
            "✓ Validation succeeded".green().bold(),
            compiled.len(),
        );
    } else {
        println!(
            "\n✓ Validation succeeded  {} statements compiled, schema generated.",
            compiled.len(),
        );
    }
}

fn print_header(title: &str, use_color: bool) {
    if use_color {
        println!("\n{}", format!("── {title} ──").cyan().bold());
    } else {
        println!("\n── {title} ──");
    }
}

/// Check whether to use color, respecting NO_COLOR (<https://no-color.org/>).
fn should_colorize() -> bool {
    std::env::var_os("NO_COLOR").is_none()
}
