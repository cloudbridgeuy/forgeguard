use serde::{Deserialize, Serialize};

/// What happens when no route matches a request.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    /// Allow the request to pass through to upstream.
    Passthrough,
    /// Deny the request.
    Deny,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn serialize_passthrough() {
        let json = serde_json::to_string(&DefaultPolicy::Passthrough).unwrap();
        assert_eq!(json, r#""passthrough""#);
    }

    #[test]
    fn serialize_deny() {
        let json = serde_json::to_string(&DefaultPolicy::Deny).unwrap();
        assert_eq!(json, r#""deny""#);
    }

    #[test]
    fn deserialize_passthrough() {
        let dp: DefaultPolicy = serde_json::from_str(r#""passthrough""#).unwrap();
        assert_eq!(dp, DefaultPolicy::Passthrough);
    }

    #[test]
    fn deserialize_deny() {
        let dp: DefaultPolicy = serde_json::from_str(r#""deny""#).unwrap();
        assert_eq!(dp, DefaultPolicy::Deny);
    }

    #[test]
    fn deserialize_invalid() {
        let result: Result<DefaultPolicy, _> = serde_json::from_str(r#""block""#);
        assert!(result.is_err());
    }
}
