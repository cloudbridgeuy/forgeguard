//! Pure core: parse argv into a structured `Dispatch`.

use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Dispatch {
    forwarded: Vec<String>,
    force_rebuild: bool,
}

impl Dispatch {
    pub(crate) fn forwarded(&self) -> &[String] {
        &self.forwarded
    }

    pub(crate) fn force_rebuild(&self) -> bool {
        self.force_rebuild
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum ArgsError {
    InvalidDispatchToken,
}

impl fmt::Display for ArgsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDispatchToken => f.write_str(
                "cargo-xtask: missing or invalid 'xtask' dispatch token after binary name",
            ),
        }
    }
}

impl std::error::Error for ArgsError {}

pub(crate) type Result<T> = std::result::Result<T, ArgsError>;

const DISPATCH_TOKEN: &str = "xtask";
const REBUILD_FLAG: &str = "--rebuild";

/// Parse argv produced by `cargo xtask` (or direct binary invocation).
///
/// Expects `argv[0]` = binary name, `argv[1]` = `"xtask"`, `argv[2..]` = forwarded args.
/// Any `--rebuild` occurrences are filtered out and collapsed into `force_rebuild`.
pub(crate) fn dispatch(argv: &[String]) -> Result<Dispatch> {
    match argv.get(1).map(String::as_str) {
        Some(DISPATCH_TOKEN) => {}
        _ => return Err(ArgsError::InvalidDispatchToken),
    }

    let tail = &argv[2..];
    let force_rebuild = tail.iter().any(|a| a == REBUILD_FLAG);
    let forwarded: Vec<String> = tail
        .iter()
        .filter(|a| a.as_str() != REBUILD_FLAG)
        .cloned()
        .collect();

    Ok(Dispatch {
        forwarded,
        force_rebuild,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn cargo_invocation_with_subcommand_and_flags() {
        let argv = sv(&["cargo-xtask", "xtask", "lint", "--fix"]);
        let d = dispatch(&argv).unwrap();
        assert_eq!(d.forwarded(), sv(&["lint", "--fix"]));
        assert!(!d.force_rebuild());
    }

    #[test]
    fn bare_cargo_xtask_produces_empty_forwarded() {
        let argv = sv(&["cargo-xtask", "xtask"]);
        let d = dispatch(&argv).unwrap();
        assert!(d.forwarded().is_empty());
        assert!(!d.force_rebuild());
    }

    #[test]
    fn missing_dispatch_token_is_error() {
        let argv = sv(&["cargo-xtask"]);
        assert_eq!(dispatch(&argv), Err(ArgsError::InvalidDispatchToken));
    }

    #[test]
    fn wrong_dispatch_token_is_error() {
        let argv = sv(&["cargo-xtask", "not-xtask", "lint"]);
        assert_eq!(dispatch(&argv), Err(ArgsError::InvalidDispatchToken));
    }

    #[test]
    fn rebuild_flag_is_extracted_and_stripped() {
        let argv = sv(&["cargo-xtask", "xtask", "--rebuild", "lint"]);
        let d = dispatch(&argv).unwrap();
        assert!(d.force_rebuild());
        assert_eq!(d.forwarded(), sv(&["lint"]));
    }

    #[test]
    fn rebuild_flag_mid_args_is_extracted() {
        let argv = sv(&["cargo-xtask", "xtask", "lint", "--rebuild", "--fix"]);
        let d = dispatch(&argv).unwrap();
        assert!(d.force_rebuild());
        assert_eq!(d.forwarded(), sv(&["lint", "--fix"]));
    }

    #[test]
    fn direct_invocation_without_cargo_prefix_also_works() {
        let argv = sv(&["/usr/local/bin/cargo-xtask", "xtask", "lint"]);
        let d = dispatch(&argv).unwrap();
        assert_eq!(d.forwarded(), sv(&["lint"]));
    }

    #[test]
    fn multiple_rebuild_flags_collapse_to_single_bool() {
        let argv = sv(&["cargo-xtask", "xtask", "--rebuild", "lint", "--rebuild"]);
        let d = dispatch(&argv).unwrap();
        assert!(d.force_rebuild());
        assert_eq!(d.forwarded(), sv(&["lint"]));
    }
}
