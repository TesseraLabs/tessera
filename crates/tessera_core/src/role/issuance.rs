//! Explicit issuance bounds in the owner-signed role manifest.
//!
//! These bounds neither reinterpret the role's display level nor change any
//! session enforcement. A missing method is unavailable, never unlimited.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::schema::{parse_mac_mask, RoleId};
use crate::mac::IntegrityLabel;

/// Version-one issuance metadata; unknown versions, methods and fields fail.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuanceMetadata {
    /// Closed schema version (currently exactly one).
    #[serde(deserialize_with = "version_one")]
    schema_version: u32,
    /// Bounds for existing roles in the same manifest.
    roles: BTreeMap<RoleId, RoleIssuance>,
}

impl IssuanceMetadata {
    /// The validated metadata format version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Explicit role bounds, keyed by the manifest's role identifiers.
    pub fn roles(&self) -> &BTreeMap<RoleId, RoleIssuance> {
        &self.roles
    }
}

/// Independently optional bounds for the two supported issuance methods.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleIssuance {
    #[serde(default)]
    codes: Option<CodesIssuanceCap>,
    #[serde(default)]
    certificate: Option<CertificateIssuanceCap>,
}

impl RoleIssuance {
    /// Codes cap; absence means the method is unavailable for issuance.
    pub fn codes(&self) -> Option<CodesIssuanceCap> {
        self.codes
    }

    /// Certificate cap; absence means the method is unavailable for issuance.
    pub fn certificate(&self) -> Option<IntegrityLabel> {
        self.certificate.map(|cap| IntegrityLabel {
            level: cap.max_level,
            categories: cap.max_categories,
        })
    }
}

/// Catalogue v1's Control Codes bound (0..=127).
///
/// This does not narrow the frozen Codes wire contract's `Level(u32)` type.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodesIssuanceCap {
    #[serde(deserialize_with = "codes_level")]
    max_level: u8,
}

impl CodesIssuanceCap {
    /// Maximum level explicitly granted for Codes issuance.
    pub fn max_level(self) -> u8 {
        self.max_level
    }
}

/// Certificate bound in the existing `IntegrityLabel` coordinate system.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CertificateIssuanceCap {
    /// Signed linear integrity level, -128..=127.
    max_level: i8,
    /// Full 64-bit category mask, encoded as a hexadecimal or decimal string.
    #[serde(deserialize_with = "categories")]
    max_categories: u64,
}

fn version_one<'de, D: serde::Deserializer<'de>>(de: D) -> Result<u32, D::Error> {
    let version = u32::deserialize(de)?;
    if version != 1 {
        return Err(serde::de::Error::custom(
            "unsupported issuance schema_version",
        ));
    }
    Ok(version)
}

fn codes_level<'de, D: serde::Deserializer<'de>>(de: D) -> Result<u8, D::Error> {
    let level = u8::deserialize(de)?;
    if level > 127 {
        return Err(serde::de::Error::custom(
            "Codes issuance max_level exceeds 127",
        ));
    }
    Ok(level)
}

fn categories<'de, D: serde::Deserializer<'de>>(de: D) -> Result<u64, D::Error> {
    let text = String::deserialize(de)?;
    parse_mac_mask(&text).map_err(serde::de::Error::custom)
}
