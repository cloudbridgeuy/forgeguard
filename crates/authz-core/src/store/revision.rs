//! Monotonic store revision — the consistency token every write returns and
//! every decision records (brief: "one decision, one grant-store revision").

use serde::{Deserialize, Serialize};

/// A monotonically increasing store revision.
///
/// Revision `0` is the empty store; the first write produces revision `1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    /// Wrap a raw revision number.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw revision number.
    pub fn value(self) -> u64 {
        self.0
    }

    /// The revision after this one.
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl std::fmt::Display for Revision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn next_increments() {
        let r = Revision::new(0);
        assert_eq!(r.next(), Revision::new(1));
        assert_eq!(r.next().value(), 1);
    }

    #[test]
    fn ordering() {
        assert!(Revision::new(1) < Revision::new(2));
    }

    #[test]
    fn serde_transparent() {
        let r = Revision::new(42);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "42");
        let back: Revision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}
