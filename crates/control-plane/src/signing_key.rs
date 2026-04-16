//! Signing key types for organization-scoped Ed25519 keypairs.
//!
//! Pure types — no I/O. Used by both the in-memory and DynamoDB stores.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
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
    #[allow(dead_code)] // Used by proxy key verification (future slice)
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
}

// ---------------------------------------------------------------------------
// GenerateKeyResult
// ---------------------------------------------------------------------------

/// Result of key generation — carries the private key (returned once, never stored).
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
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chrono::Duration;

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
}
