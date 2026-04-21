//! Signing key types for organization-scoped Ed25519 keypairs.
//!
//! Pure types — no I/O. Used by both the in-memory and DynamoDB stores.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// SigningKeyStatus
// ---------------------------------------------------------------------------

/// Lifecycle status of an organization's signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub(crate) enum SigningKeyStatus {
    Active,
    Rotating { expires_at: DateTime<Utc> },
    Revoked,
}

impl fmt::Display for SigningKeyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Rotating { expires_at } => {
                write!(f, "Rotating({})", expires_at.to_rfc3339())
            }
            Self::Revoked => write!(f, "Revoked"),
        }
    }
}

impl FromStr for SigningKeyStatus {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s == "Active" {
            return Ok(Self::Active);
        }
        if s == "Revoked" {
            return Ok(Self::Revoked);
        }
        if let Some(inner) = s
            .strip_prefix("Rotating(")
            .and_then(|rest| rest.strip_suffix(')'))
        {
            let expires_at = DateTime::parse_from_rfc3339(inner)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| Error::Store(format!("invalid expires_at in Rotating: {e}")))?;
            return Ok(Self::Rotating { expires_at });
        }
        Err(Error::Store(format!("unknown SigningKeyStatus: {s}")))
    }
}

// ---------------------------------------------------------------------------
// SigningKeyEntry
// ---------------------------------------------------------------------------

/// A stored signing key record (public key only — private key is never persisted).
#[derive(Debug, Clone, Serialize)]
#[serde(into = "RawSigningKeyEntry")]
pub(crate) struct SigningKeyEntry {
    key_id: String,
    public_key_pem: String,
    status: SigningKeyStatus,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

/// Raw intermediate struct for deserialization — validated via `TryFrom`.
#[derive(Deserialize, Serialize)]
struct RawSigningKeyEntry {
    key_id: String,
    public_key_pem: String,
    status: SigningKeyStatus,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

impl TryFrom<RawSigningKeyEntry> for SigningKeyEntry {
    type Error = Error;

    fn try_from(raw: RawSigningKeyEntry) -> Result<Self> {
        Self::new(
            raw.key_id,
            raw.public_key_pem,
            raw.status,
            raw.created_at,
            raw.expires_at,
        )
    }
}

impl From<SigningKeyEntry> for RawSigningKeyEntry {
    fn from(entry: SigningKeyEntry) -> Self {
        Self {
            key_id: entry.key_id,
            public_key_pem: entry.public_key_pem,
            status: entry.status,
            created_at: entry.created_at,
            expires_at: entry.expires_at,
        }
    }
}

impl<'de> Deserialize<'de> for SigningKeyEntry {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawSigningKeyEntry::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

impl SigningKeyEntry {
    /// Create a new signing key entry.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `key_id` is empty.
    pub(crate) fn new(
        key_id: String,
        public_key_pem: String,
        status: SigningKeyStatus,
        created_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Self> {
        if key_id.is_empty() {
            return Err(Error::Store("key_id must not be empty".into()));
        }
        Ok(Self {
            key_id,
            public_key_pem,
            status,
            created_at,
            expires_at,
        })
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }

    pub(crate) fn status(&self) -> &SigningKeyStatus {
        &self.status
    }

    pub(crate) fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub(crate) fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    /// Returns `true` if the key is usable at the given time.
    ///
    /// Active keys are always usable. Rotating keys are usable until their
    /// `expires_at` timestamp. Revoked keys are never usable.
    pub(crate) fn is_active(&self, now: DateTime<Utc>) -> bool {
        match &self.status {
            SigningKeyStatus::Active => true,
            SigningKeyStatus::Rotating { expires_at } => now < *expires_at,
            SigningKeyStatus::Revoked => false,
        }
    }

    /// Transition this key to `Revoked` status.
    pub(crate) fn revoke(&mut self) {
        self.status = SigningKeyStatus::Revoked;
    }

    /// Transition this key to `Rotating { expires_at }`.
    pub(crate) fn begin_rotating(&mut self, expires_at: DateTime<Utc>) {
        self.status = SigningKeyStatus::Rotating { expires_at };
        self.expires_at = Some(expires_at);
    }
}

// ---------------------------------------------------------------------------
// GenerateKeyResult
// ---------------------------------------------------------------------------

/// Result of key generation — carries the private key (returned once, never stored).
#[derive(Debug)]
pub(crate) struct GenerateKeyResult {
    key_id: String,
    private_key_pem: String,
    public_key_pem: String,
    created_at: DateTime<Utc>,
}

impl GenerateKeyResult {
    pub(crate) fn new(
        key_id: String,
        private_key_pem: String,
        public_key_pem: String,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            key_id,
            private_key_pem,
            public_key_pem,
            created_at,
        }
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }

    pub(crate) fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }

    pub(crate) fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Build the corresponding `SigningKeyEntry` (public half, `Active` status).
    pub(crate) fn to_entry(&self) -> Result<SigningKeyEntry> {
        SigningKeyEntry::new(
            self.key_id.clone(),
            self.public_key_pem.clone(),
            SigningKeyStatus::Active,
            self.created_at,
            None,
        )
    }
}

// ---------------------------------------------------------------------------
// Rotation (pure)
// ---------------------------------------------------------------------------

/// Transition the target key to `Rotating` with a grace period, and append a
/// new `Active` entry. Pure — no I/O, no clocks other than the one passed in.
///
/// # Errors
///
/// - `Error::NotFound` if no entry matches `target_key_id`.
/// - `Error::Conflict` if the target entry's status is not `Active`.
pub(crate) fn rotate_entries(
    mut existing: Vec<SigningKeyEntry>,
    target_key_id: &str,
    new_entry: SigningKeyEntry,
    now: DateTime<Utc>,
    grace: Duration,
) -> Result<Vec<SigningKeyEntry>> {
    let idx = existing
        .iter()
        .position(|e| e.key_id() == target_key_id)
        .ok_or_else(|| Error::NotFound(format!("signing key '{target_key_id}' not found")))?;

    match existing[idx].status() {
        SigningKeyStatus::Active => {}
        SigningKeyStatus::Rotating { .. } => {
            return Err(Error::Conflict(format!(
                "signing key '{target_key_id}' is already rotating"
            )));
        }
        SigningKeyStatus::Revoked => {
            return Err(Error::Conflict(format!(
                "signing key '{target_key_id}' is revoked"
            )));
        }
    }

    let expires_at = now + grace;
    existing[idx].begin_rotating(expires_at);
    existing.push(new_entry);
    Ok(existing)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- SigningKeyStatus Display/FromStr round-trip --

    #[test]
    fn status_active_round_trip() {
        let status = SigningKeyStatus::Active;
        let s = status.to_string();
        assert_eq!(s, "Active");
        let parsed: SigningKeyStatus = s.parse().unwrap();
        assert_eq!(parsed, status);
    }

    #[test]
    fn status_revoked_round_trip() {
        let status = SigningKeyStatus::Revoked;
        let s = status.to_string();
        assert_eq!(s, "Revoked");
        let parsed: SigningKeyStatus = s.parse().unwrap();
        assert_eq!(parsed, status);
    }

    #[test]
    fn status_rotating_round_trip() {
        let expires = Utc::now() + Duration::hours(1);
        let status = SigningKeyStatus::Rotating {
            expires_at: expires,
        };
        let s = status.to_string();
        assert!(s.starts_with("Rotating("));
        let parsed: SigningKeyStatus = s.parse().unwrap();
        assert_eq!(parsed, status);
    }

    #[test]
    fn status_from_str_unknown() {
        let result = "Bogus".parse::<SigningKeyStatus>();
        assert!(result.is_err());
    }

    // -- is_active --

    #[test]
    fn is_active_active_key_returns_true() {
        let now = Utc::now();
        let entry = SigningKeyEntry::new(
            "key-1".to_string(),
            "pem-data".to_string(),
            SigningKeyStatus::Active,
            now,
            None,
        )
        .unwrap();
        assert!(entry.is_active(now));
    }

    #[test]
    fn is_active_revoked_key_returns_false() {
        let now = Utc::now();
        let entry = SigningKeyEntry::new(
            "key-1".to_string(),
            "pem-data".to_string(),
            SigningKeyStatus::Revoked,
            now,
            None,
        )
        .unwrap();
        assert!(!entry.is_active(now));
    }

    #[test]
    fn is_active_rotating_before_expiry_returns_true() {
        let now = Utc::now();
        let expires = now + Duration::hours(1);
        let entry = SigningKeyEntry::new(
            "key-1".to_string(),
            "pem-data".to_string(),
            SigningKeyStatus::Rotating {
                expires_at: expires,
            },
            now,
            Some(expires),
        )
        .unwrap();
        assert!(entry.is_active(now));
    }

    #[test]
    fn is_active_rotating_after_expiry_returns_false() {
        let now = Utc::now();
        let expired = now - Duration::hours(1);
        let entry = SigningKeyEntry::new(
            "key-1".to_string(),
            "pem-data".to_string(),
            SigningKeyStatus::Rotating {
                expires_at: expired,
            },
            now - Duration::hours(2),
            Some(expired),
        )
        .unwrap();
        assert!(!entry.is_active(now));
    }

    // -- SigningKeyEntry validation --

    #[test]
    fn empty_key_id_rejected() {
        let result = SigningKeyEntry::new(
            String::new(),
            "pem-data".to_string(),
            SigningKeyStatus::Active,
            Utc::now(),
            None,
        );
        assert!(result.is_err());
    }

    // -- Serialize/Deserialize round-trip --

    #[test]
    fn signing_key_entry_serde_round_trip() {
        let now = Utc::now();
        let entry = SigningKeyEntry::new(
            "key-abc".to_string(),
            "-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----".to_string(),
            SigningKeyStatus::Active,
            now,
            None,
        )
        .unwrap();

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: SigningKeyEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.key_id(), entry.key_id());
        assert_eq!(deserialized.public_key_pem(), entry.public_key_pem());
        assert_eq!(deserialized.status(), entry.status());
        assert_eq!(deserialized.created_at(), entry.created_at());
        assert_eq!(deserialized.expires_at(), entry.expires_at());
    }

    #[test]
    fn signing_key_entry_rotating_serde_round_trip() {
        let now = Utc::now();
        let expires = now + Duration::hours(6);
        let entry = SigningKeyEntry::new(
            "key-rot".to_string(),
            "pem-data".to_string(),
            SigningKeyStatus::Rotating {
                expires_at: expires,
            },
            now,
            Some(expires),
        )
        .unwrap();

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: SigningKeyEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.status(), entry.status());
        assert_eq!(deserialized.expires_at(), entry.expires_at());
    }

    #[test]
    fn deserialize_empty_key_id_fails() {
        let json = serde_json::json!({
            "key_id": "",
            "public_key_pem": "pem-data",
            "status": "Active",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": null
        });
        let result: std::result::Result<SigningKeyEntry, _> = serde_json::from_value(json);
        assert!(result.is_err(), "empty key_id should fail deserialization");
    }

    // -- rotate_entries --

    #[test]
    fn rotate_entries_happy_path_transitions_active_and_appends_new() {
        let now = Utc::now();
        let old = SigningKeyEntry::new(
            "key-old".into(),
            "old-pem".into(),
            SigningKeyStatus::Active,
            now - Duration::hours(1),
            None,
        )
        .unwrap();
        let new_entry = SigningKeyEntry::new(
            "key-new".into(),
            "new-pem".into(),
            SigningKeyStatus::Active,
            now,
            None,
        )
        .unwrap();

        let result =
            rotate_entries(vec![old], "key-old", new_entry, now, Duration::hours(24)).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].key_id(), "key-old");
        match result[0].status() {
            SigningKeyStatus::Rotating { expires_at } => {
                assert_eq!(*expires_at, now + Duration::hours(24));
            }
            s => panic!("expected Rotating, got {s:?}"),
        }
        assert_eq!(result[0].expires_at(), Some(now + Duration::hours(24)));
        assert_eq!(result[1].key_id(), "key-new");
        assert!(matches!(result[1].status(), SigningKeyStatus::Active));
    }

    #[test]
    fn rotate_entries_target_not_found_returns_not_found() {
        let now = Utc::now();
        let new_entry = SigningKeyEntry::new(
            "key-new".into(),
            "pem".into(),
            SigningKeyStatus::Active,
            now,
            None,
        )
        .unwrap();
        let err = rotate_entries(vec![], "key-missing", new_entry, now, Duration::hours(24))
            .expect_err("should error");
        assert!(matches!(err, Error::NotFound(_)), "got: {err:?}");
    }

    #[test]
    fn rotate_entries_target_rotating_returns_conflict() {
        let now = Utc::now();
        let rotating = SigningKeyEntry::new(
            "key-rot".into(),
            "pem".into(),
            SigningKeyStatus::Rotating {
                expires_at: now + Duration::hours(2),
            },
            now - Duration::hours(1),
            Some(now + Duration::hours(2)),
        )
        .unwrap();
        let new_entry = SigningKeyEntry::new(
            "key-new".into(),
            "pem".into(),
            SigningKeyStatus::Active,
            now,
            None,
        )
        .unwrap();
        let err = rotate_entries(
            vec![rotating],
            "key-rot",
            new_entry,
            now,
            Duration::hours(24),
        )
        .expect_err("should error");
        assert!(matches!(err, Error::Conflict(_)), "got: {err:?}");
    }

    #[test]
    fn rotate_entries_target_revoked_returns_conflict() {
        let now = Utc::now();
        let revoked = SigningKeyEntry::new(
            "key-rev".into(),
            "pem".into(),
            SigningKeyStatus::Revoked,
            now - Duration::hours(1),
            None,
        )
        .unwrap();
        let new_entry = SigningKeyEntry::new(
            "key-new".into(),
            "pem".into(),
            SigningKeyStatus::Active,
            now,
            None,
        )
        .unwrap();
        let err = rotate_entries(
            vec![revoked],
            "key-rev",
            new_entry,
            now,
            Duration::hours(24),
        )
        .expect_err("should error");
        assert!(matches!(err, Error::Conflict(_)), "got: {err:?}");
    }

    #[test]
    fn rotate_entries_leaves_other_entries_untouched() {
        let now = Utc::now();
        let other_rotating = SigningKeyEntry::new(
            "key-other".into(),
            "other-pem".into(),
            SigningKeyStatus::Rotating {
                expires_at: now + Duration::hours(6),
            },
            now - Duration::hours(2),
            Some(now + Duration::hours(6)),
        )
        .unwrap();
        let active = SigningKeyEntry::new(
            "key-active".into(),
            "active-pem".into(),
            SigningKeyStatus::Active,
            now - Duration::hours(1),
            None,
        )
        .unwrap();
        let new_entry = SigningKeyEntry::new(
            "key-new".into(),
            "new-pem".into(),
            SigningKeyStatus::Active,
            now,
            None,
        )
        .unwrap();

        let result = rotate_entries(
            vec![other_rotating, active],
            "key-active",
            new_entry,
            now,
            Duration::hours(24),
        )
        .unwrap();

        assert_eq!(result.len(), 3);
        // Other rotating entry unchanged
        assert_eq!(result[0].key_id(), "key-other");
        assert_eq!(result[0].expires_at(), Some(now + Duration::hours(6)));
    }
}
