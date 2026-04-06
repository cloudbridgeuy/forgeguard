pub mod hooks;

use clap::Args;
use color_eyre::eyre::{self, Result};
use duct::cmd;
use std::fs;
use std::io::Write;

// ---------------------------------------------------------------------------
// Functional Core — pure types and logic, no I/O
// ---------------------------------------------------------------------------

/// Identifier for each check, used to match skip flags and fix-mode overrides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckId {
    Fmt,
    Check,
    Clippy,
    Test,
    Rail,
    FileLength,
    PublishVersion,
    TypeScript,
}

/// A lint check to execute.
struct Check {
    id: CheckId,
    name: &'static str,
    program: &'static str,
    args: &'static [&'static str],
    optional: bool,
}

/// The outcome of running a single check.
enum CheckOutcome {
    Passed { output: String },
    Failed { output: String },
    Skipped,
}

struct CheckResult {
    name: String,
    outcome: CheckOutcome,
}

/// CLI arguments for the lint subcommand.
#[derive(Args)]
pub struct LintArgs {
    /// Print all output, not just errors
    #[arg(long)]
    pub verbose: bool,

    /// Skip cargo fmt check
    #[arg(long)]
    pub no_fmt: bool,

    /// Skip cargo check
    #[arg(long)]
    pub no_check: bool,

    /// Skip cargo clippy
    #[arg(long)]
    pub no_clippy: bool,

    /// Skip cargo test
    #[arg(long)]
    pub no_test: bool,

    /// Skip cargo rail unify check
    #[arg(long)]
    pub no_rail: bool,

    /// Skip file-length check
    #[arg(long)]
    pub no_file_length: bool,

    /// Skip publish-version invariant check
    #[arg(long)]
    pub no_publish_version: bool,

    /// Skip TypeScript compilation check (infra/dev)
    #[arg(long)]
    pub no_typescript: bool,

    /// Auto-fix where possible (fmt applies formatting, clippy applies fixes)
    #[arg(long)]
    pub fix: bool,

    /// Run in pre-commit hook mode (implies --fix, re-stages .rs files)
    #[arg(long, hide = true)]
    pub staged_only: bool,

    /// Install git pre-commit hook
    #[arg(long, conflicts_with_all = ["uninstall_hooks", "hooks_status"])]
    pub install_hooks: bool,

    /// Uninstall git pre-commit hook
    #[arg(long, conflicts_with_all = ["install_hooks", "hooks_status"])]
    pub uninstall_hooks: bool,

    /// Show git hook installation status
    #[arg(long, conflicts_with_all = ["install_hooks", "uninstall_hooks"])]
    pub hooks_status: bool,
}

/// The ordered pipeline of checks to run.
///
/// `FileLength` has a sentinel program — it is handled specially in `run()`.
const CHECKS: &[Check] = &[
    Check {
        id: CheckId::Fmt,
        name: "cargo fmt --check",
        program: "cargo",
        args: &["fmt", "--check"],
        optional: false,
    },
    Check {
        id: CheckId::Check,
        name: "cargo check --workspace --all-targets",
        program: "cargo",
        args: &["check", "--workspace", "--all-targets"],
        optional: false,
    },
    Check {
        id: CheckId::Clippy,
        name: "cargo clippy --workspace --all-targets -- -D warnings",
        program: "cargo",
        args: &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        optional: false,
    },
    Check {
        id: CheckId::Test,
        name: "cargo test --workspace --all-targets",
        program: "cargo",
        args: &["test", "--workspace", "--all-targets"],
        optional: false,
    },
    Check {
        id: CheckId::Rail,
        name: "cargo rail unify --check",
        program: "cargo",
        args: &["rail", "unify", "--check"],
        optional: true,
    },
    Check {
        id: CheckId::FileLength,
        name: "file length (<= 1000 lines)",
        program: "__builtin__",
        args: &[],
        optional: false,
    },
    Check {
        id: CheckId::PublishVersion,
        name: "publish=false => version 0.0.0",
        program: "__builtin__",
        args: &[],
        optional: false,
    },
    Check {
        id: CheckId::TypeScript,
        name: "tsc --noEmit (infra/dev)",
        program: "__builtin__",
        args: &[],
        optional: false,
    },
];

/// Determine whether a check should be skipped based on the user's skip flags.
fn should_skip(id: CheckId, args: &LintArgs) -> bool {
    match id {
        CheckId::Fmt => args.no_fmt,
        CheckId::Check => args.no_check,
        CheckId::Clippy => args.no_clippy,
        CheckId::Test => args.no_test,
        CheckId::Rail => args.no_rail,
        CheckId::FileLength => args.no_file_length,
        CheckId::PublishVersion => args.no_publish_version,
        CheckId::TypeScript => args.no_typescript,
    }
}

/// Return the effective args for a check in `--fix` mode.
///
/// - `fmt`: drops `--check` so formatting is applied directly.
/// - `clippy`: appends `--fix --allow-dirty` before the `--` separator.
/// - `rail`: drops `--check` so unification is applied directly.
/// - All others: unchanged (`None`).
fn fix_args(id: CheckId) -> Option<Vec<&'static str>> {
    match id {
        CheckId::Fmt => Some(vec!["fmt"]),
        CheckId::Clippy => Some(vec![
            "clippy",
            "--workspace",
            "--all-targets",
            "--fix",
            "--allow-dirty",
            "--",
            "-D",
            "warnings",
        ]),
        CheckId::Rail => Some(vec!["rail", "unify"]),
        _ => None,
    }
}

/// Build a display name for a check from its program and effective args.
fn check_display_name(program: &str, args: &[&str]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{program} {}", args.join(" "))
    }
}

/// Determine whether command output indicates the tool is not installed.
fn is_tool_not_found(output: &str) -> bool {
    let lower = output.to_lowercase();
    lower.contains("not found")
        || lower.contains("no such file or directory")
        || lower.contains("unrecognized subcommand")
        || lower.contains("no such command")
}

/// Determine the outcome of a check from its exit status and output.
fn determine_outcome(success: bool, output: String, optional: bool) -> CheckOutcome {
    if optional && !success && is_tool_not_found(&output) {
        return CheckOutcome::Skipped;
    }
    if success {
        CheckOutcome::Passed { output }
    } else {
        CheckOutcome::Failed { output }
    }
}

/// Format a single check result as a log entry.
fn format_log_entry(result: &CheckResult) -> String {
    match &result.outcome {
        CheckOutcome::Skipped => {
            format!("=== {} ===\n[skipped — tool not installed]\n", result.name)
        }
        CheckOutcome::Passed { output } | CheckOutcome::Failed { output } => {
            format!("=== {} ===\n{}\n", result.name, output)
        }
    }
}

/// Validate file lengths. Returns outcome with pass/fail.
///
/// Pure: takes the file list as input so globbing can be tested separately.
fn evaluate_file_lengths(files: &[(String, usize)], max_lines: usize) -> CheckOutcome {
    let violations: Vec<String> = files
        .iter()
        .filter(|(_, count)| *count > max_lines)
        .map(|(path, count)| format!("  {path} ({count} lines)"))
        .collect();

    if violations.is_empty() {
        CheckOutcome::Passed {
            output: String::new(),
        }
    } else {
        CheckOutcome::Failed {
            output: format!(
                "Files exceeding {max_lines} lines:\n{}\n",
                violations.join("\n")
            ),
        }
    }
}

/// Entry for the publish-version invariant check.
struct PublishEntry {
    path: String,
    is_unpublished: bool,
    version: String,
}

/// Validate that all crates with `publish = false` have `version = "0.0.0"`.
fn evaluate_publish_versions(entries: &[PublishEntry]) -> CheckOutcome {
    let violations: Vec<String> = entries
        .iter()
        .filter(|e| e.is_unpublished && e.version != "0.0.0")
        .map(|e| {
            format!(
                "  {}: publish = false but version = \"{}\" (expected \"0.0.0\")",
                e.path, e.version
            )
        })
        .collect();

    if violations.is_empty() {
        CheckOutcome::Passed {
            output: String::new(),
        }
    } else {
        CheckOutcome::Failed {
            output: format!(
                "Unpublished crates must use version \"0.0.0\":\n{}\n",
                violations.join("\n")
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Imperative Shell — I/O, side effects, orchestration
// ---------------------------------------------------------------------------

/// Run the full lint pipeline (or dispatch to hooks management).
pub fn run(args: &LintArgs) -> Result<()> {
    if args.install_hooks {
        return hooks::install_hooks();
    }
    if args.uninstall_hooks {
        return hooks::uninstall_hooks();
    }
    if args.hooks_status {
        return hooks::show_status();
    }

    let fix = args.fix || args.staged_only;

    // Capture staged .rs files BEFORE the pipeline runs.
    let staged_files = if args.staged_only {
        Some(collect_staged_rust_files()?)
    } else {
        None
    };

    let log_path = resolve_log_path()?;
    let mut log_file = fs::File::create(&log_path)?;

    let mut failed_check: Option<String> = None;

    for check in CHECKS {
        if should_skip(check.id, args) {
            continue;
        }

        let result = if check.id == CheckId::FileLength {
            let files = collect_file_lengths()?;
            CheckResult {
                name: check.name.to_string(),
                outcome: evaluate_file_lengths(&files, 1000),
            }
        } else if check.id == CheckId::PublishVersion {
            let entries = collect_publish_versions()?;
            CheckResult {
                name: check.name.to_string(),
                outcome: evaluate_publish_versions(&entries),
            }
        } else if check.id == CheckId::TypeScript {
            CheckResult {
                name: check.name.to_string(),
                outcome: run_typescript_check(),
            }
        } else {
            let effective_args: Option<Vec<&str>> = if fix { fix_args(check.id) } else { None };
            let effective_name = match &effective_args {
                Some(overrides) => check_display_name(check.program, overrides),
                None => check.name.to_string(),
            };
            run_check(check, effective_name, effective_args.as_deref())?
        };

        write!(log_file, "{}", format_log_entry(&result))?;

        match result.outcome {
            CheckOutcome::Skipped => {
                if args.verbose {
                    println!("[skip] {} (not installed)", result.name);
                }
            }
            CheckOutcome::Passed { ref output } => {
                if args.verbose {
                    print!("{output}");
                }
            }
            CheckOutcome::Failed { ref output } => {
                print!("{output}");
                failed_check = Some(result.name.clone());
                break;
            }
        }
    }

    if let Some(name) = failed_check {
        println!("\nlint failed at: {name}");
        println!("log: {log_path}");
        drop(log_file);
        std::process::exit(1);
    }

    // Re-stage .rs files when running from the pre-commit hook.
    if let Some(files) = staged_files {
        restage_files(&files)?;
    }

    Ok(())
}

/// Execute a single check and return its result.
fn run_check(check: &Check, name: String, override_args: Option<&[&str]>) -> Result<CheckResult> {
    let args: &[&str] = override_args.unwrap_or(check.args);

    let output = cmd(check.program, args)
        .stderr_to_stdout()
        .stdout_capture()
        .unchecked()
        .run()?;

    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let outcome = determine_outcome(output.status.success(), text, check.optional);
    Ok(CheckResult { name, outcome })
}

/// Resolve the absolute path to the log file inside `target/`.
fn resolve_log_path() -> Result<String> {
    let target_dir = std::env::current_dir()?.join("target");
    fs::create_dir_all(&target_dir)?;
    let log_path = target_dir.join("xtask-lint.log");
    Ok(log_path.to_string_lossy().into_owned())
}

/// Run `npx tsc --noEmit` in `infra/dev/` to check TypeScript compilation.
fn run_typescript_check() -> CheckOutcome {
    let output = cmd("npx", &["tsc", "--noEmit"])
        .dir("infra/dev")
        .stderr_to_stdout()
        .stdout_capture()
        .unchecked()
        .run();

    match output {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout).into_owned();
            if o.status.success() {
                CheckOutcome::Passed { output: text }
            } else {
                CheckOutcome::Failed { output: text }
            }
        }
        Err(e) => CheckOutcome::Failed {
            output: format!("failed to run npx tsc: {e}"),
        },
    }
}

/// Collect (path, line_count) for every `.rs` file under `crates/*/src/` and `lib/*/src/`.
fn collect_file_lengths() -> Result<Vec<(String, usize)>> {
    let mut results = Vec::new();
    let patterns = &["crates/*/src/**/*.rs", "lib/*/src/**/*.rs"];
    for pattern in patterns {
        for entry in glob::glob(pattern).into_iter().flatten().flatten() {
            let content = fs::read_to_string(&entry)?;
            let line_count = content.lines().count();
            results.push((entry.display().to_string(), line_count));
        }
    }
    Ok(results)
}

/// Collect publish-version entries for every crate Cargo.toml under `crates/` and `lib/`.
fn collect_publish_versions() -> Result<Vec<PublishEntry>> {
    let mut results = Vec::new();
    let patterns = &["crates/*/Cargo.toml", "lib/*/Cargo.toml"];
    for pattern in patterns {
        for entry in glob::glob(pattern).into_iter().flatten().flatten() {
            let content = fs::read_to_string(&entry)?;
            let doc: toml_edit::DocumentMut = content
                .parse()
                .map_err(|e| eyre::eyre!("failed to parse {}: {e}", entry.display()))?;
            let pkg = match doc.get("package") {
                Some(p) => p,
                None => continue,
            };
            let is_unpublished = pkg
                .get("publish")
                .and_then(|v| v.as_bool())
                .map(|b| !b)
                .unwrap_or(false);
            let version = pkg
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            results.push(PublishEntry {
                path: entry.display().to_string(),
                is_unpublished,
                version,
            });
        }
    }
    Ok(results)
}

/// Collect staged .rs files (added/copied/modified) from the git index.
fn collect_staged_rust_files() -> Result<Vec<String>> {
    let output = cmd!(
        "git",
        "diff",
        "--cached",
        "--name-only",
        "--diff-filter=ACM"
    )
    .stdout_capture()
    .run()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .filter(|l| l.ends_with(".rs"))
        .map(String::from)
        .collect())
}

/// Re-stage a pre-collected list of .rs files.
fn restage_files(files: &[String]) -> Result<()> {
    if !files.is_empty() {
        let mut args = vec!["add"];
        args.extend(files.iter().map(|s| s.as_str()));
        cmd("git", &args).run()?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // --- is_tool_not_found ---

    #[test]
    fn test_is_tool_not_found_detects_missing_tool() {
        assert!(is_tool_not_found("error: no such command: `machete`\n"));
        assert!(is_tool_not_found("bash: cargo-machete: not found\n"));
        assert!(is_tool_not_found(
            "error[E0463]: No such file or directory\n"
        ));
        assert!(is_tool_not_found(
            "error: unrecognized subcommand 'machete'\n"
        ));
    }

    #[test]
    fn test_is_tool_not_found_ignores_normal_errors() {
        assert!(!is_tool_not_found("error[E0308]: mismatched types\n"));
        assert!(!is_tool_not_found("warning: unused variable\n"));
        assert!(!is_tool_not_found(""));
    }

    // --- format_log_entry ---

    #[test]
    fn test_format_log_entry_passed() {
        let result = CheckResult {
            name: "cargo fmt --check".to_string(),
            outcome: CheckOutcome::Passed {
                output: "all good\n".to_string(),
            },
        };
        let entry = format_log_entry(&result);
        assert!(entry.contains("=== cargo fmt --check ==="));
        assert!(entry.contains("all good"));
    }

    #[test]
    fn test_format_log_entry_failed() {
        let result = CheckResult {
            name: "cargo clippy".to_string(),
            outcome: CheckOutcome::Failed {
                output: "error: something wrong\n".to_string(),
            },
        };
        let entry = format_log_entry(&result);
        assert!(entry.contains("=== cargo clippy ==="));
        assert!(entry.contains("error: something wrong"));
    }

    #[test]
    fn test_format_log_entry_skipped() {
        let result = CheckResult {
            name: "cargo machete".to_string(),
            outcome: CheckOutcome::Skipped,
        };
        let entry = format_log_entry(&result);
        assert!(entry.contains("=== cargo machete ==="));
        assert!(entry.contains("[skipped"));
    }

    // --- should_skip ---

    #[test]
    fn test_should_skip_respects_each_flag() {
        let base = default_lint_args();
        assert!(!should_skip(CheckId::Fmt, &base));
        assert!(!should_skip(CheckId::Check, &base));
        assert!(!should_skip(CheckId::Clippy, &base));
        assert!(!should_skip(CheckId::Test, &base));
        assert!(!should_skip(CheckId::Rail, &base));
        assert!(!should_skip(CheckId::FileLength, &base));
        assert!(!should_skip(CheckId::PublishVersion, &base));
        assert!(!should_skip(CheckId::TypeScript, &base));
    }

    #[test]
    fn test_should_skip_fmt() {
        let mut args = default_lint_args();
        args.no_fmt = true;
        assert!(should_skip(CheckId::Fmt, &args));
        assert!(!should_skip(CheckId::Check, &args));
    }

    // --- fix_args ---

    #[test]
    fn test_fix_args_fmt_drops_check_flag() {
        let args = fix_args(CheckId::Fmt).expect("fmt should have fix args");
        assert_eq!(args, vec!["fmt"]);
    }

    #[test]
    fn test_fix_args_clippy_adds_fix_allow_dirty() {
        let args = fix_args(CheckId::Clippy).expect("clippy should have fix args");
        assert!(args.contains(&"--fix"));
        assert!(args.contains(&"--allow-dirty"));
        assert!(args.contains(&"-D"));
        assert!(args.contains(&"warnings"));
    }

    #[test]
    fn test_fix_args_rail_drops_check_flag() {
        let args = fix_args(CheckId::Rail).expect("rail should have fix args");
        assert_eq!(args, vec!["rail", "unify"]);
        assert!(!args.contains(&"--check"));
    }

    #[test]
    fn test_fix_args_returns_none_for_unmodified_checks() {
        assert!(fix_args(CheckId::Check).is_none());
        assert!(fix_args(CheckId::Test).is_none());
        assert!(fix_args(CheckId::FileLength).is_none());
        assert!(fix_args(CheckId::PublishVersion).is_none());
        assert!(fix_args(CheckId::TypeScript).is_none());
    }

    // --- determine_outcome ---

    #[test]
    fn test_determine_outcome_passed() {
        let outcome = determine_outcome(true, "ok\n".to_string(), false);
        assert!(matches!(outcome, CheckOutcome::Passed { .. }));
    }

    #[test]
    fn test_determine_outcome_failed() {
        let outcome = determine_outcome(false, "error\n".to_string(), false);
        assert!(matches!(outcome, CheckOutcome::Failed { .. }));
    }

    #[test]
    fn test_determine_outcome_skipped_optional_tool_not_found() {
        let outcome = determine_outcome(false, "no such command\n".to_string(), true);
        assert!(matches!(outcome, CheckOutcome::Skipped));
    }

    #[test]
    fn test_determine_outcome_optional_but_real_failure() {
        let outcome =
            determine_outcome(false, "error[E0308]: mismatched types\n".to_string(), true);
        assert!(matches!(outcome, CheckOutcome::Failed { .. }));
    }

    // --- evaluate_file_lengths ---

    #[test]
    fn test_file_lengths_all_under_limit() {
        let files = vec![
            ("src/lib.rs".to_string(), 100),
            ("src/main.rs".to_string(), 999),
        ];
        assert!(matches!(
            evaluate_file_lengths(&files, 1000),
            CheckOutcome::Passed { .. }
        ));
    }

    #[test]
    fn test_file_lengths_over_limit() {
        let files = vec![
            ("src/lib.rs".to_string(), 100),
            ("src/big.rs".to_string(), 1001),
        ];
        let outcome = evaluate_file_lengths(&files, 1000);
        match outcome {
            CheckOutcome::Failed { output } => {
                assert!(output.contains("src/big.rs"));
                assert!(output.contains("1001"));
            }
            _ => panic!("expected Failed"),
        }
    }

    #[test]
    fn test_file_lengths_empty_list() {
        assert!(matches!(
            evaluate_file_lengths(&[], 1000),
            CheckOutcome::Passed { .. }
        ));
    }

    // --- check_display_name ---

    #[test]
    fn test_check_display_name() {
        assert_eq!(check_display_name("cargo", &["fmt"]), "cargo fmt");
        assert_eq!(check_display_name("typos", &[]), "typos");
    }

    // --- evaluate_publish_versions ---

    #[test]
    fn publish_version_all_compliant() {
        let entries = vec![
            PublishEntry {
                path: "crates/foo/Cargo.toml".to_string(),
                is_unpublished: true,
                version: "0.0.0".to_string(),
            },
            PublishEntry {
                path: "crates/bar/Cargo.toml".to_string(),
                is_unpublished: false,
                version: "0.1.0".to_string(),
            },
        ];
        assert!(matches!(
            evaluate_publish_versions(&entries),
            CheckOutcome::Passed { .. }
        ));
    }

    #[test]
    fn publish_version_violation() {
        let entries = vec![PublishEntry {
            path: "crates/foo/Cargo.toml".to_string(),
            is_unpublished: true,
            version: "0.1.0".to_string(),
        }];
        let outcome = evaluate_publish_versions(&entries);
        match outcome {
            CheckOutcome::Failed { output } => {
                assert!(output.contains("crates/foo/Cargo.toml"));
                assert!(output.contains("0.1.0"));
            }
            _ => panic!("expected failure"),
        }
    }

    #[test]
    fn publish_version_published_crate_any_version_ok() {
        let entries = vec![PublishEntry {
            path: "crates/core/Cargo.toml".to_string(),
            is_unpublished: false,
            version: "1.2.3".to_string(),
        }];
        assert!(matches!(
            evaluate_publish_versions(&entries),
            CheckOutcome::Passed { .. }
        ));
    }

    #[test]
    fn publish_version_empty_list() {
        assert!(matches!(
            evaluate_publish_versions(&[]),
            CheckOutcome::Passed { .. }
        ));
    }

    /// Helper: build a LintArgs with all flags defaulted to false.
    fn default_lint_args() -> LintArgs {
        LintArgs {
            verbose: false,
            no_fmt: false,
            no_check: false,
            no_clippy: false,
            no_test: false,
            no_rail: false,
            no_file_length: false,
            no_publish_version: false,
            no_typescript: false,
            fix: false,
            staged_only: false,
            install_hooks: false,
            uninstall_hooks: false,
            hooks_status: false,
        }
    }
}
