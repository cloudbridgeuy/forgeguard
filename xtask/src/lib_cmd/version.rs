use std::fmt;

use color_eyre::eyre::{self, Result};

/// A simple semver version (major.minor.patch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Version {
    major: u32,
    minor: u32,
    patch: u32,
}

impl Version {
    /// Parse a version string like "1.2.3".
    pub(crate) fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            eyre::bail!("invalid version '{s}': expected MAJOR.MINOR.PATCH");
        }
        let major = parts[0]
            .parse::<u32>()
            .map_err(|_| eyre::eyre!("invalid major version in '{s}'"))?;
        let minor = parts[1]
            .parse::<u32>()
            .map_err(|_| eyre::eyre!("invalid minor version in '{s}'"))?;
        let patch = parts[2]
            .parse::<u32>()
            .map_err(|_| eyre::eyre!("invalid patch version in '{s}'"))?;
        Ok(Self {
            major,
            minor,
            patch,
        })
    }

    pub(crate) fn bump_patch(self) -> Self {
        Self {
            major: self.major,
            minor: self.minor,
            patch: self.patch + 1,
        }
    }

    pub(crate) fn bump_minor(self) -> Self {
        Self {
            major: self.major,
            minor: self.minor + 1,
            patch: 0,
        }
    }

    pub(crate) fn bump_major(self) -> Self {
        Self {
            major: self.major + 1,
            minor: 0,
            patch: 0,
        }
    }

    /// Apply a bump level string ("patch", "minor", "major") to this version.
    pub(crate) fn apply_bump(self, level: &str) -> Result<Self> {
        match level {
            "patch" => Ok(self.bump_patch()),
            "minor" => Ok(self.bump_minor()),
            "major" => Ok(self.bump_major()),
            other => eyre::bail!("unknown bump level '{other}'"),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_version() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn parse_zero_version() {
        let v = Version::parse("0.0.0").unwrap();
        assert_eq!(v.to_string(), "0.0.0");
    }

    #[test]
    fn parse_invalid_missing_part() {
        assert!(Version::parse("1.2").is_err());
    }

    #[test]
    fn parse_invalid_not_a_number() {
        assert!(Version::parse("1.x.3").is_err());
    }

    #[test]
    fn bump_patch_increments_patch() {
        let v = Version::parse("0.1.0").unwrap().bump_patch();
        assert_eq!(v.to_string(), "0.1.1");
    }

    #[test]
    fn bump_minor_resets_patch() {
        let v = Version::parse("0.1.3").unwrap().bump_minor();
        assert_eq!(v.to_string(), "0.2.0");
    }

    #[test]
    fn bump_major_resets_minor_and_patch() {
        let v = Version::parse("0.2.3").unwrap().bump_major();
        assert_eq!(v.to_string(), "1.0.0");
    }

    #[test]
    fn display_format() {
        let v = Version::parse("10.20.30").unwrap();
        assert_eq!(format!("{v}"), "10.20.30");
    }

    #[test]
    fn apply_bump_patch() {
        let v = Version::parse("1.0.0")
            .unwrap()
            .apply_bump("patch")
            .unwrap();
        assert_eq!(v.to_string(), "1.0.1");
    }

    #[test]
    fn apply_bump_minor() {
        let v = Version::parse("1.0.5")
            .unwrap()
            .apply_bump("minor")
            .unwrap();
        assert_eq!(v.to_string(), "1.1.0");
    }

    #[test]
    fn apply_bump_major() {
        let v = Version::parse("1.2.3")
            .unwrap()
            .apply_bump("major")
            .unwrap();
        assert_eq!(v.to_string(), "2.0.0");
    }

    #[test]
    fn apply_bump_invalid() {
        assert!(Version::parse("1.0.0").unwrap().apply_bump("huge").is_err());
    }
}
