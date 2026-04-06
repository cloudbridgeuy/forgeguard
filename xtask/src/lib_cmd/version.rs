use std::fmt;
use std::str::FromStr;

use color_eyre::eyre::{self, Result};

/// Semver bump level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BumpLevel {
    Patch,
    Minor,
    Major,
}

impl FromStr for BumpLevel {
    type Err = color_eyre::eyre::Report;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "patch" => Ok(Self::Patch),
            "minor" => Ok(Self::Minor),
            "major" => Ok(Self::Major),
            _ => eyre::bail!("invalid bump level '{s}': expected patch, minor, or major"),
        }
    }
}

impl fmt::Display for BumpLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Patch => write!(f, "patch"),
            Self::Minor => write!(f, "minor"),
            Self::Major => write!(f, "major"),
        }
    }
}

/// A simple semver version (major.minor.patch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

    /// Apply a bump level to this version.
    pub(crate) fn apply_bump(self, level: BumpLevel) -> Self {
        match level {
            BumpLevel::Patch => self.bump_patch(),
            BumpLevel::Minor => self.bump_minor(),
            BumpLevel::Major => self.bump_major(),
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
            .apply_bump(BumpLevel::Patch);
        assert_eq!(v.to_string(), "1.0.1");
    }

    #[test]
    fn apply_bump_minor() {
        let v = Version::parse("1.0.5")
            .unwrap()
            .apply_bump(BumpLevel::Minor);
        assert_eq!(v.to_string(), "1.1.0");
    }

    #[test]
    fn apply_bump_major() {
        let v = Version::parse("1.2.3")
            .unwrap()
            .apply_bump(BumpLevel::Major);
        assert_eq!(v.to_string(), "2.0.0");
    }

    #[test]
    fn bump_level_from_str_valid() {
        assert_eq!("patch".parse::<BumpLevel>().unwrap(), BumpLevel::Patch);
        assert_eq!("minor".parse::<BumpLevel>().unwrap(), BumpLevel::Minor);
        assert_eq!("major".parse::<BumpLevel>().unwrap(), BumpLevel::Major);
    }

    #[test]
    fn bump_level_from_str_invalid() {
        assert!("huge".parse::<BumpLevel>().is_err());
        assert!("PATCH".parse::<BumpLevel>().is_err());
        assert!("".parse::<BumpLevel>().is_err());
    }

    #[test]
    fn bump_level_display() {
        assert_eq!(BumpLevel::Patch.to_string(), "patch");
        assert_eq!(BumpLevel::Minor.to_string(), "minor");
        assert_eq!(BumpLevel::Major.to_string(), "major");
    }

    #[test]
    fn version_ordering() {
        let v010 = Version::parse("0.1.0").unwrap();
        let v020 = Version::parse("0.2.0").unwrap();
        let v011 = Version::parse("0.1.1").unwrap();
        let v001 = Version::parse("0.0.1").unwrap();
        assert!(v010 < v020);
        assert!(v010 < v011);
        assert!(v020 > v011);
        assert!(v001 < v010);
        assert_eq!(v010, Version::parse("0.1.0").unwrap());
    }
}
