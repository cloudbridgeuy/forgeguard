use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Args;
use color_eyre::eyre::{self, Result};
use toml_edit::DocumentMut;

use super::version::Version;

/// Arguments for `cargo xtask lib release`.
#[derive(Args)]
pub struct ReleaseArgs {
    /// The lib crate to release (e.g., forgeguard-axum)
    pub crate_name: String,

    /// Version bump level
    #[arg(long, value_parser = ["patch", "minor", "major"])]
    pub bump: Option<String>,

    /// Set an exact version instead of bumping
    #[arg(long, conflicts_with = "bump")]
    pub version: Option<String>,

    /// Run all steps except the actual publish
    #[arg(long)]
    pub dry_run: bool,
}

/// Crate name and directory path for the shared deps that get lock-step bumped.
const SHARED_DEPS: &[(&str, &str)] = &[
    ("forgeguard_core", "crates/core"),
    ("forgeguard_authn_core", "crates/authn-core"),
    ("forgeguard_authz_core", "crates/authz-core"),
    ("forgeguard_proxy_core", "crates/proxy-core"),
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
fn compute_version_changes(args: &ReleaseArgs) -> Result<(Vec<VersionChange>, String)> {
    let root = workspace_root();
    let mut changes = Vec::new();

    // Determine the bump level string for shared deps
    let bump_level = match (&args.bump, &args.version) {
        (Some(level), _) => level.clone(),
        (None, Some(_)) => {
            // When --version is used, we still need a bump level for shared deps.
            // We cannot infer a bump level from an exact version, so we require --bump.
            // However, clap's conflicts_with prevents both. For --version, we bump shared
            // deps by patch as a sensible default.
            "patch".to_string()
        }
        (None, None) => unreachable!(), // validated earlier
    };

    // 1. Lib crate version
    let lib_cargo = root.join("lib").join(&args.crate_name).join("Cargo.toml");
    let lib_old = read_crate_version(&lib_cargo)?;
    let lib_new = match &args.version {
        Some(v) => Version::parse(v)?,
        None => lib_old.apply_bump(&bump_level)?,
    };
    changes.push(VersionChange {
        crate_name: args.crate_name.clone(),
        old: lib_old,
        new: lib_new,
    });

    // 2. Shared deps — all bumped with the same level
    for (dep_name, dep_dir) in SHARED_DEPS {
        let dep_cargo = root.join(dep_dir).join("Cargo.toml");
        let old = read_crate_version(&dep_cargo)?;
        let new = old.apply_bump(&bump_level)?;
        changes.push(VersionChange {
            crate_name: (*dep_name).to_string(),
            old,
            new,
        });
    }

    Ok((changes, bump_level))
}

/// Apply all version changes to Cargo.toml files.
fn apply_version_changes(args: &ReleaseArgs, changes: &[VersionChange]) -> Result<()> {
    let root = workspace_root();

    // 1. Write lib crate version
    let lib_cargo = root.join("lib").join(&args.crate_name).join("Cargo.toml");
    write_crate_version(&lib_cargo, &changes[0].new)?;

    // 2. Write shared dep versions
    for (i, (_, dep_dir)) in SHARED_DEPS.iter().enumerate() {
        let dep_cargo = root.join(dep_dir).join("Cargo.toml");
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
    for (i, (dep_name, _)) in SHARED_DEPS.iter().enumerate() {
        update_workspace_dep_version(&mut doc, dep_name, &changes[i + 1].new)?;
    }

    std::fs::write(&root_cargo, doc.to_string())?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Changelog (Task 24 - N23)
// ---------------------------------------------------------------------------

fn update_changelog(crate_name: &str, version: &Version) -> Result<()> {
    let root = workspace_root();
    let changelog_path = root.join("lib").join(crate_name).join("CHANGELOG.md");

    let today = chrono::Local::now().format("%Y-%m-%d");
    let new_entry = format!("## [{version}] - {today}\n\n- Release {version}\n");

    if changelog_path.exists() {
        let existing = std::fs::read_to_string(&changelog_path)?;
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
            full.push_str(&existing);
            std::fs::write(&changelog_path, full)?;
        } else {
            // Skip any blank lines after the header
            let rest: String = lines.map(|l| format!("{l}\n")).collect();

            output.push_str(&new_entry);
            output.push('\n');
            output.push_str(&rest);
            std::fs::write(&changelog_path, output)?;
        }
    } else {
        let content = format!("# Changelog\n\n{new_entry}");
        std::fs::write(&changelog_path, content)?;
    }

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
    let root_dep = SHARED_DEPS[0].0;
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
        .map(|(name, _)| (*name).to_string())
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
    let (changes, _bump_level) = compute_version_changes(args)?;

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
        println!("Release aborted. Version bumps are still applied — use `git checkout -- .` to revert.");
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
