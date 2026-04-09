/// A Lambda deployment target.
///
/// Each entry maps a human-friendly name to the crate, binary, and AWS
/// function name pattern needed to build and deploy it.
pub(crate) struct LambdaTarget {
    /// Human-readable name used in CLI commands (e.g. "control-plane").
    pub(crate) name: &'static str,
    /// Cargo crate name (e.g. "fg-lambdas").
    pub(crate) crate_name: &'static str,
    /// Binary target within the crate (e.g. "control_plane").
    pub(crate) binary_name: &'static str,
    /// AWS function name pattern. `{name}` is replaced with the target name,
    /// `{env}` with the deployment environment.
    ///
    /// Used by the deploy command (V3).
    pub(crate) function_name_pattern: &'static str,
}

impl LambdaTarget {
    /// Resolve the AWS function name for a given environment.
    ///
    /// Used by the deploy command (V3).
    pub(crate) fn function_name(&self, env: &str) -> String {
        self.function_name_pattern
            .replace("{name}", self.name)
            .replace("{env}", env)
    }
}

/// All registered Lambda targets.
pub(crate) static TARGETS: &[LambdaTarget] = &[
    LambdaTarget {
        name: "control-plane",
        crate_name: "fg-lambdas",
        binary_name: "control_plane",
        function_name_pattern: "forgeguard-{name}-{env}",
    },
    LambdaTarget {
        name: "saga-trigger",
        crate_name: "fg-lambdas",
        binary_name: "saga_trigger",
        function_name_pattern: "forgeguard-{name}-{env}",
    },
];

/// Find a target by name.
pub(crate) fn find_target(name: &str) -> Option<&'static LambdaTarget> {
    TARGETS.iter().find(|t| t.name == name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn find_control_plane() {
        let t = find_target("control-plane").unwrap();
        assert_eq!(t.binary_name, "control_plane");
        assert_eq!(t.crate_name, "fg-lambdas");
    }

    #[test]
    fn find_saga_trigger() {
        let t = find_target("saga-trigger").unwrap();
        assert_eq!(t.binary_name, "saga_trigger");
    }

    #[test]
    fn find_unknown_returns_none() {
        assert!(find_target("nope").is_none());
    }

    #[test]
    fn function_name_resolution() {
        let t = find_target("control-plane").unwrap();
        assert_eq!(t.function_name("prod"), "forgeguard-control-plane-prod");
        assert_eq!(t.function_name("dev"), "forgeguard-control-plane-dev");
    }
}
