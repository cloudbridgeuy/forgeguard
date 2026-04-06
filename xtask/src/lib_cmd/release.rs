use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Args;
use color_eyre::eyre::{self, Result};
use toml_edit::DocumentMut;

use super::version::{BumpLevel, Version};

/// Arguments for `cargo xtask lib release`.
#[derive(Args)]
pub struct ReleaseArgs {
    /// The lib crate to release (e.g., forgeguard-axum)
    pub crate_name: String,

    /// Version bump level (patch, minor, major)
    #[arg(long, value_parser = clap::value_parser!(BumpLevel))]
    pub bump: Option<BumpLevel>,

    /// Set an exact version instead of bumping
    #[arg(long, conflicts_with = "bump")]
    pub version: Option<String>,

    /// Run all steps except the actual publish
    #[arg(long)]
    pub dry_run: bool,
}

/// A shared dependency crate that gets lock-step version bumped alongside lib releases.
struct SharedDep {
    crate_name: &'static str,
    dir: &'static str,
}

/// Crate name and directory path for the shared deps that get lock-step bumped.
const SHARED_DEPS: &[SharedDep] = &[
    SharedDep {
        crate_name: "forgeguard_core",
        dir: "crates/core",
    },
    SharedDep {
        crate_name: "forgeguard_authn_core",
        dir: "crates/authn-core",
    },
    SharedDep {
        crate_name: "forgeguard_authz_core",
        dir: "crates/authz-core",
    },
    SharedDep {
        crate_name: "forgeguard_proxy_core",
        dir: "crates/proxy-core",
    },
];

/// Tracks old and new version for one crate.
struct VersionChange {
    crate_name: String,
    old: Version,
    new: Version,
}

// ---------------------------------------------------------------------------
// Validation (Task 22)
// ---------------------------------------------------------------------------

fn validate(args: &ReleaseArgs) -> Result<()> {
    // 1. Crate exists
    let crate_dir = workspace_root().join("lib").join(&args.crate_name);
    let cargo_toml = crate_dir.join("Cargo.toml");
    if !cargo_toml.exists() {
        eyre::bail!(
            "lib crate '{}' not found: {} does not exist",
            args.crate_name,
            cargo_toml.display()
        );
    }

    // 2. Working tree is clean
    let status = duct::cmd!("git", "status", "--porcelain").read()?;
    if !status.trim().is_empty() {
        eyre::bail!("working tree is not clean — commit or stash changes first:\n{status}");
    }

    // 3. On main branch
    let branch = duct::cmd!("git", "branch", "--show-current").read()?;
    if branch.trim() != "main" {
        eyre::bail!(
            "must be on main branch to release (currently on '{}')",
            branch.trim()
        );
    }

    // 4. Either --bump or --version is provided
    if args.bump.is_none() && args.version.is_none() {
        eyre::bail!("either --bump or --version must be provided");
    }

    // 5. Crates.io credentials available (skip for dry-run)
    if !args.dry_run {
        let has_env_token = std::env::var("CARGO_REGISTRY_TOKEN").is_ok();
        let home = std::env::var("HOME").unwrap_or_default();
        let has_credentials = !home.is_empty()
            && (std::path::Path::new(&format!("{home}/.cargo/credentials.toml")).exists()
                || std::path::Path::new(&format!("{home}/.cargo/credentials")).exists());
        if !has_env_token && !has_credentials {
            eyre::bail!(
                "no crates.io credentials found — set CARGO_REGISTRY_TOKEN or run `cargo login`"
            );
        }
    }

    // 6. Lint pipeline passes
    println!("  Running lint checks...");
    let lint_result = duct::cmd!("cargo", "xtask", "lint")
        .stderr_to_stdout()
        .stdout_capture()
        .unchecked()
        .run()?;
    if !lint_result.status.success() {
        let output = String::from_utf8_lossy(&lint_result.stdout);
        eyre::bail!("lint checks failed — fix issues before releasing:\n{output}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Version bump (Task 23)
// ---------------------------------------------------------------------------

/// Read the `[package] version` from a Cargo.toml file.
fn read_crate_version(cargo_toml: &Path) -> Result<Version> {
    let content = std::fs::read_to_string(cargo_toml)?;
    let doc: DocumentMut = content
        .parse()
        .map_err(|e| eyre::eyre!("failed to parse {}: {e}", cargo_toml.display()))?;

    let version_str = doc["package"]["version"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("no package.version in {}", cargo_toml.display()))?;

    Version::parse(version_str)
}

/// Write a new `[package] version` into a Cargo.toml file.
fn write_crate_version(cargo_toml: &Path, version: &Version) -> Result<()> {
    let content = std::fs::read_to_string(cargo_toml)?;
    let mut doc: DocumentMut = content
        .parse()
        .map_err(|e| eyre::eyre!("failed to parse {}: {e}", cargo_toml.display()))?;

    doc["package"]["version"] = toml_edit::value(version.to_string());
    std::fs::write(cargo_toml, doc.to_string())?;
    Ok(())
}

/// Update the version of a workspace dependency in the root Cargo.toml.
///
/// Handles both plain version strings and version strings with `^` prefix.
fn update_workspace_dep_version(
    root_doc: &mut DocumentMut,
    dep_name: &str,
    new_version: &Version,
) -> Result<()> {
    let dep = &mut root_doc["workspace"]["dependencies"][dep_name];
    if dep.is_none() {
        eyre::bail!("workspace dependency '{dep_name}' not found in root Cargo.toml");
    }

    // Read the old version to detect if it uses ^ prefix
    let old_version_str = dep["version"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("no version field for workspace dep '{dep_name}'"))?;

    let new_version_str = if old_version_str.starts_with('^') {
        format!("^{new_version}")
    } else {
        new_version.to_string()
    };

    dep["version"] = toml_edit::value(new_version_str);
    Ok(())
}

/// Compute all version changes: the lib crate + 4 shared deps.
fn compute_version_changes(args: &ReleaseArgs) -> Result<Vec<VersionChange>> {
    let root = workspace_root();
    let mut changes = Vec::new();

    // Determine the bump level for shared deps
    let bump_level = match (&args.bump, &args.version) {
        (Some(level), _) => *level,
        (None, Some(_)) => BumpLevel::Patch, // default for --version mode
        (None, None) => eyre::bail!("either --bump or --version must be provided"),
    };

    // 1. Lib crate version
    let lib_cargo = root.join("lib").join(&args.crate_name).join("Cargo.toml");
    let lib_old = read_crate_version(&lib_cargo)?;
    let lib_new = match &args.version {
        Some(v) => Version::parse(v)?,
        None => lib_old.apply_bump(bump_level),
    };
    changes.push(VersionChange {
        crate_name: args.crate_name.clone(),
        old: lib_old,
        new: lib_new,
    });

    // 2. Shared deps — all bumped with the same level
    for dep in SHARED_DEPS {
        let dep_cargo = root.join(dep.dir).join("Cargo.toml");
        let old = read_crate_version(&dep_cargo)?;
        let new = old.apply_bump(bump_level);
        changes.push(VersionChange {
            crate_name: dep.crate_name.to_string(),
            old,
            new,
        });
    }

    Ok(changes)
}

/// Apply all version changes to Cargo.toml files.
fn apply_version_changes(args: &ReleaseArgs, changes: &[VersionChange]) -> Result<()> {
    let root = workspace_root();

    // 1. Write lib crate version
    let lib_cargo = root.join("lib").join(&args.crate_name).join("Cargo.toml");
    write_crate_version(&lib_cargo, &changes[0].new)?;

    // 2. Write shared dep versions
    for (i, dep) in SHARED_DEPS.iter().enumerate() {
        let dep_cargo = root.join(dep.dir).join("Cargo.toml");
        write_crate_version(&dep_cargo, &changes[i + 1].new)?;
    }

    // 3. Update workspace dependency versions in root Cargo.toml
    let root_cargo = root.join("Cargo.toml");
    let content = std::fs::read_to_string(&root_cargo)?;
    let mut doc: DocumentMut = content
        .parse()
        .map_err(|e| eyre::eyre!("failed to parse root Cargo.toml: {e}"))?;

    // Update lib crate
    update_workspace_dep_version(&mut doc, &args.crate_name, &changes[0].new)?;

    // Update shared deps
    for (i, dep) in SHARED_DEPS.iter().enumerate() {
        update_workspace_dep_version(&mut doc, dep.crate_name, &changes[i + 1].new)?;
    }

    std::fs::write(&root_cargo, doc.to_string())?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Changelog (Task 24 - N23)
// ---------------------------------------------------------------------------

/// Pure: insert a changelog entry after the `# Changelog` header.
///
/// If `existing` has no `# ` header, prepends one.
fn format_changelog_entry(existing: &str, version: &str, date: &str) -> String {
    let new_entry = format!("## [{version}] - {date}\n\n- Release {version}\n");

    if existing.is_empty() {
        return format!("# Changelog\n\n{new_entry}");
    }

    // Insert the new entry after the first heading line (# Changelog)
    let mut lines = existing.lines();
    let mut output = String::new();

    // Find and keep the header
    let mut found_header = false;
    for line in &mut lines {
        output.push_str(line);
        output.push('\n');
        if line.starts_with("# ") {
            found_header = true;
            output.push('\n');
            break;
        }
    }

    if !found_header {
        // No header found — prepend header + entry to existing content
        let mut full = format!("# Changelog\n\n{new_entry}\n");
        full.push_str(existing);
        full
    } else {
        // Skip any blank lines after the header
        let rest: String = lines.map(|l| format!("{l}\n")).collect();

        output.push_str(&new_entry);
        output.push('\n');
        output.push_str(&rest);
        output
    }
}

fn update_changelog(crate_name: &str, version: &Version) -> Result<()> {
    let root = workspace_root();
    let changelog_path = root.join("lib").join(crate_name).join("CHANGELOG.md");
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();

    let existing = if changelog_path.exists() {
        std::fs::read_to_string(&changelog_path)?
    } else {
        String::new()
    };

    let content = format_changelog_entry(&existing, &version.to_string(), &today);
    std::fs::write(&changelog_path, content)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Dry-run publish (Task 24 - N24)
// ---------------------------------------------------------------------------

/// Verify the workspace still compiles after version bumps and that each crate
/// can be packaged.
///
/// Runs `cargo check --workspace` to catch compilation errors from the version
/// changes. Then runs `cargo package` for the root dependency crate (which has
/// no unpublished workspace deps) as a packaging smoke test. Dependent crates
/// cannot be fully packaged until their deps exist on crates.io, so we skip
/// per-crate packaging for them — the real `cargo publish` in dependency order
/// will catch any issues.
fn dry_run_publish(lib_crate_name: &str) -> Result<()> {
    println!("  cargo check --workspace");
    duct::cmd!("cargo", "check", "--workspace")
        .stderr_to_stdout()
        .run()?;

    // Package the root dep (forgeguard_core) as a smoke test — it has no
    // unpublished workspace deps.
    let root_dep = SHARED_DEPS[0].crate_name;
    println!("  cargo package --allow-dirty -p {root_dep}");
    duct::cmd!("cargo", "package", "--allow-dirty", "-p", root_dep)
        .stderr_to_stdout()
        .run()?;

    // List the remaining crates that would be published.
    let publish_order = build_publish_order(lib_crate_name);
    println!("\n  Publish order (skipping per-crate package for unpublished deps):");
    for (i, crate_name) in publish_order.iter().enumerate() {
        println!("    {}: {crate_name}", i + 1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Summary + confirm (Task 24 - N25)
// ---------------------------------------------------------------------------

fn print_summary(changes: &[VersionChange]) {
    println!("\nRelease summary:");

    // Find the max crate name length for alignment
    let max_name_len = changes
        .iter()
        .map(|c| c.crate_name.len())
        .max()
        .unwrap_or(0);

    for change in changes {
        let padding = " ".repeat(max_name_len - change.crate_name.len());
        println!(
            "  {}:{} {} -> {}",
            change.crate_name, padding, change.old, change.new
        );
    }
    println!();
}

fn confirm_release() -> Result<bool> {
    print!("Proceed with release? [y/N] ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

// ---------------------------------------------------------------------------
// Commit + tag (Task 24 - N26)
// ---------------------------------------------------------------------------

fn commit_and_tag(crate_name: &str, version: &Version) -> Result<()> {
    let message = format!("chore(release): {crate_name} v{version}");
    let tag = format!("{crate_name}-v{version}");

    println!("  git add -A");
    duct::cmd!("git", "add", "-A").run()?;

    println!("  git commit -m \"{message}\"");
    duct::cmd!("git", "commit", "-m", &message).run()?;

    println!("  git tag \"{tag}\"");
    duct::cmd!("git", "tag", &tag).run()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Publish (Task 24 - N27)
// ---------------------------------------------------------------------------

fn publish(lib_crate_name: &str) -> Result<()> {
    let publish_order = build_publish_order(lib_crate_name);

    for crate_name in &publish_order {
        println!("  cargo publish -p {crate_name}");
        duct::cmd!("cargo", "publish", "-p", crate_name).run()?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    // xtask is always run from the workspace root via `cargo xtask`
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Build the publish order: shared deps first (in dependency order), then the lib crate.
fn build_publish_order(lib_crate_name: &str) -> Vec<String> {
    let mut order: Vec<String> = SHARED_DEPS
        .iter()
        .map(|dep| dep.crate_name.to_string())
        .collect();
    order.push(lib_crate_name.to_string());
    order
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

pub fn run(args: &ReleaseArgs) -> Result<()> {
    println!("Validating preconditions...");
    validate(args)?;

    println!("Computing version changes...");
    let changes = compute_version_changes(args)?;

    // Validate: all shared deps' new version >= lib crate's new version
    let lib_new = &changes[0].new;
    for change in &changes[1..] {
        if change.new < *lib_new {
            eyre::bail!(
                "shared dep {} would be v{} which is less than lib crate version v{} — \
                 shared deps must be >= lib version",
                change.crate_name,
                change.new,
                lib_new
            );
        }
    }

    print_summary(&changes);

    if args.dry_run {
        println!("Dry run complete. No files were modified.");
        return Ok(());
    }

    println!("Applying version bumps...");
    apply_version_changes(args, &changes)?;

    println!("Updating changelog...");
    update_changelog(&args.crate_name, &changes[0].new)?;

    println!("Running publish verification...");
    dry_run_publish(&args.crate_name)?;

    if !confirm_release()? {
        println!(
            "Release aborted. Version bumps are still applied — use `git checkout -- .` to revert."
        );
        return Ok(());
    }

    println!("Committing and tagging...");
    commit_and_tag(&args.crate_name, &changes[0].new)?;

    println!("Publishing to crates.io...");
    publish(&args.crate_name)?;

    println!(
        "\nRelease complete: {} v{}",
        args.crate_name, changes[0].new
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // --- build_publish_order ---

    #[test]
    fn publish_order_starts_with_shared_deps() {
        let order = build_publish_order("forgeguard-axum");
        assert_eq!(order[0], "forgeguard_core");
        assert_eq!(order[1], "forgeguard_authn_core");
        assert_eq!(order[2], "forgeguard_authz_core");
        assert_eq!(order[3], "forgeguard_proxy_core");
    }

    #[test]
    fn publish_order_ends_with_lib_crate() {
        let order = build_publish_order("forgeguard-axum");
        assert_eq!(order.last().unwrap(), "forgeguard-axum");
        assert_eq!(order.len(), SHARED_DEPS.len() + 1);
    }

    // --- format_changelog_entry ---

    #[test]
    fn changelog_new_file_gets_header_and_entry() {
        let result = format_changelog_entry("", "0.2.0", "2026-04-05");
        assert!(result.starts_with("# Changelog\n\n"));
        assert!(result.contains("## [0.2.0] - 2026-04-05"));
        assert!(result.contains("- Release 0.2.0"));
    }

    #[test]
    fn changelog_existing_file_inserts_after_header() {
        let existing = "# Changelog\n\n## [0.1.0] - 2026-01-01\n\n- Initial release\n";
        let result = format_changelog_entry(existing, "0.2.0", "2026-04-05");
        // New entry should appear before the old entry
        let new_pos = result.find("## [0.2.0]").unwrap();
        let old_pos = result.find("## [0.1.0]").unwrap();
        assert!(new_pos < old_pos);
        assert!(result.starts_with("# Changelog\n"));
    }

    #[test]
    fn changelog_file_without_header_gets_header_prepended() {
        let existing = "Some random content\nwithout a header\n";
        let result = format_changelog_entry(existing, "0.2.0", "2026-04-05");
        assert!(result.starts_with("# Changelog\n\n"));
        assert!(result.contains("## [0.2.0] - 2026-04-05"));
        assert!(result.contains("Some random content"));
    }
}
