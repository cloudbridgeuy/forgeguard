//! Content-addressed snapshot version: FNV-1a 64 over the compiled policy
//! text. Deterministic and stable across Rust releases so historical
//! decisions replay against the exact snapshot that decided them.

use serde::{Deserialize, Serialize};

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Version of a compiled policy snapshot (16 hex chars).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SnapshotVersion(String);

impl SnapshotVersion {
    /// Hash the compiled policy text into a version.
    pub fn of(policy_text: &str) -> Self {
        let mut hash = FNV_OFFSET;
        for byte in policy_text.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        Self(format!("{hash:016x}"))
    }

    /// The version as lowercase hex.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SnapshotVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        assert_eq!(
            SnapshotVersion::of("permit();"),
            SnapshotVersion::of("permit();")
        );
    }

    #[test]
    fn content_sensitive() {
        assert_ne!(
            SnapshotVersion::of("permit();"),
            SnapshotVersion::of("forbid();")
        );
    }

    #[test]
    fn sixteen_hex_chars() {
        let v = SnapshotVersion::of("x");
        assert_eq!(v.as_str().len(), 16);
        assert!(v.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Pins the implementation to the canonical FNV-1a 64-bit algorithm
    /// (known test vectors), guarding against an accidental switch to
    /// FNV-1 or a wrong constant.
    #[test]
    fn matches_known_fnv1a_vectors() {
        assert_eq!(SnapshotVersion::of("").as_str(), "cbf29ce484222325");
        assert_eq!(SnapshotVersion::of("a").as_str(), "af63dc4c8601ec8c");
    }
}
