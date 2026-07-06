//! Role-slice schema types and strict TOML parser.
//!
//! Every payload section parses in any build (open or commercial); the open
//! build only differs in *enforcement* (it does not apply `mac`/`selinux`
//! payloads). Parsing is strict: `deny_unknown_fields` on every struct so
//! unknown keys or wrong types are hard errors (design decision D9).

use std::sync::LazyLock;
use std::time::Duration;

/// Maximum size of a role-slice file, in bytes (64 KiB cap, spec requirement).
pub const MAX_SLICE_BYTES: usize = 64 * 1024;

/// Anchored, suffix-safe role-id pattern (no `+`): used as a `user+role`
/// login suffix, the on-disk filename, and a MAC code input.
static ROLE_ID_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    // Pattern is a compile-time constant verified by `regex_compiles_and_matches`;
    // `expect` here can only fire on a developer typo, never on input.
    #[allow(clippy::expect_used)]
    let re = regex::Regex::new(r"^[a-z][a-z0-9-]{0,15}$")
        .expect("role_id regex is a valid compile-time constant");
    re
});

/// Operating system a role slice targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoleOs {
    /// Astra Linux (МКЦ via `mac_mask`).
    Astra,
    /// Generic Linux (groups, sudo role, systemd limits, optional `SELinux`).
    Linux,
    /// Windows (payload schema TBD; see design.md Non-Goals).
    Windows,
}

impl RoleOs {
    /// Lowercase wire name of this OS (matches the TOML `os` value).
    pub fn as_str(&self) -> &'static str {
        match self {
            RoleOs::Astra => "astra",
            RoleOs::Linux => "linux",
            RoleOs::Windows => "windows",
        }
    }
}

impl std::fmt::Display for RoleOs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validated role identifier: matches `^[a-z][a-z0-9-]{0,15}$`.
///
/// Suffix-safe (contains no `+`) so it can be used as a `user+role`
/// login suffix, as the on-disk filename, and as a MAC code input
/// (design decision D4). Immutable: renaming is a new role.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoleId(String);

impl RoleId {
    /// Validate `s` against the role-id pattern, returning a `RoleId` or
    /// [`RoleSchemaError::RoleIdInvalid`].
    pub fn new(s: &str) -> Result<Self, RoleSchemaError> {
        if ROLE_ID_RE.is_match(s) {
            Ok(RoleId(s.to_owned()))
        } else {
            Err(RoleSchemaError::RoleIdInvalid {
                value: s.to_owned(),
            })
        }
    }

    /// Borrow the validated identifier as a string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Display for RoleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for RoleId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        RoleId::new(&s).map_err(|_| {
            serde::de::Error::custom(format!(
                "invalid role_id {s:?}: must match ^[a-z][a-z0-9-]{{0,15}}$"
            ))
        })
    }
}

/// systemd per-session resource limits for a Linux role (subset; YAGNI —
/// expand only when a delivery target needs more).
#[derive(Debug, Clone, serde::Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxLimits {
    /// `RLIMIT_NOFILE` (max open files).
    #[serde(default)]
    pub nofile: Option<u64>,
    /// `RLIMIT_NPROC` (max processes).
    #[serde(default)]
    pub nproc: Option<u64>,
}

/// `SELinux` security context fields for a Linux role (format only; the
/// `SELinux` enforcement adapter is a commercial extension — open build
/// parses but does not apply these).
#[derive(Debug, Clone, serde::Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelinuxSection {
    /// `SELinux` user (seuser), e.g. `staff_u`.
    #[serde(default)]
    pub user: Option<String>,
    /// `SELinux` role, e.g. `staff_r`.
    #[serde(default)]
    pub role: Option<String>,
    /// MLS/MCS range, e.g. `s0-s0:c0.c1023`.
    #[serde(default)]
    pub range: Option<String>,
}

/// Per-OS role payload. All sections are optional and every section
/// parses in any build (open or commercial); only enforcement of the
/// `mac`/`selinux` payloads is a commercial extension (design.md
/// open/commercial table). `validate_payload_for_os` rejects sections
/// that do not belong to the slice's declared OS.
#[derive(Debug, Clone, serde::Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    /// Astra МКЦ bitmask as a hex (`0x..`) or decimal string. Parse-only
    /// in the open build (no enforcement); must parse as u64.
    #[serde(default)]
    pub mac_mask: Option<String>,
    /// Linux supplementary groups.
    #[serde(default)]
    pub groups: Option<Vec<String>>,
    /// Linux sudo role name (sudoers `Role`/alias) granted in-session.
    #[serde(default)]
    pub sudo_role: Option<String>,
    /// Linux systemd per-session resource limits.
    #[serde(default)]
    pub limits: Option<LinuxLimits>,
    /// `SELinux` context (Linux only).
    #[serde(default)]
    pub selinux: Option<SelinuxSection>,
}

/// Closed whitelist of optional session limits (`[session]`). Maps to
/// systemd per-session limits applied before `pam_systemd` via
/// `pam_set_data` (see spec).
#[derive(Debug, Clone, serde::Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionLimits {
    /// Maximum session TTL in seconds. The codebase uses integer-seconds
    /// duration fields (no humantime dependency); exposed as a `Duration`
    /// via [`SessionLimits::max_ttl`].
    #[serde(default)]
    pub max_ttl_seconds: Option<u64>,
    /// systemd `MemoryMax` (e.g. `512M`); format passed through verbatim.
    #[serde(default)]
    pub memory_max: Option<String>,
    /// systemd `TasksMax`.
    #[serde(default)]
    pub tasks_max: Option<u64>,
    /// systemd `CPUWeight` (1..=10000; range not enforced here).
    #[serde(default)]
    pub cpu_weight: Option<u32>,
    /// systemd `IOWeight` (1..=10000; range not enforced here).
    #[serde(default)]
    pub io_weight: Option<u32>,
}

impl SessionLimits {
    /// The maximum session TTL as a [`Duration`], if set. Converts the
    /// integer-seconds field (the codebase's duration convention).
    pub fn max_ttl(&self) -> Option<Duration> {
        self.max_ttl_seconds.map(Duration::from_secs)
    }
}

/// A parsed, schema-valid role slice for one OS.
#[derive(Debug, Clone, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleSlice {
    /// Role identifier; must equal the filename stem.
    pub role: RoleId,
    /// Monotonic slice version.
    pub version: u32,
    /// Target OS; must equal the device OS.
    pub os: RoleOs,
    /// Human-readable name for UI / audit (single string; no localization).
    pub name: String,
    /// Display ordering hint (on Astra mirrors the МКЦ level). Roles are
    /// incomparable: the core never orders or compares `level`.
    pub level: u8,
    /// Optional free-form description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional per-OS payload.
    #[serde(default)]
    pub payload: Option<Payload>,
    /// Optional session limits.
    #[serde(default)]
    pub session: Option<SessionLimits>,
}

/// Errors from parsing or validating a role slice.
#[derive(Debug, thiserror::Error)]
pub enum RoleSchemaError {
    /// Slice file exceeds the size cap.
    #[error("role slice is {size} bytes, exceeds the {max}-byte cap")]
    Oversize {
        /// Actual byte length.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Slice bytes are not valid UTF-8.
    #[error("role slice is not valid UTF-8: {reason}")]
    NotUtf8 {
        /// Underlying decode error message.
        reason: String,
    },
    /// TOML parse / type / unknown-field error.
    #[error("role slice TOML is invalid: {reason}")]
    TomlParse {
        /// Underlying TOML error message.
        reason: String,
    },
    /// `role` field does not match the regex.
    #[error("invalid role_id {value:?}: must match ^[a-z][a-z0-9-]{{0,15}}$")]
    RoleIdInvalid {
        /// The rejected value.
        value: String,
    },
    /// `role` does not equal the expected (filename) id.
    #[error("role mismatch: file expects {expected:?} but slice declares {found:?}")]
    RoleMismatch {
        /// Id from the filename.
        expected: String,
        /// Id declared inside the slice.
        found: String,
    },
    /// Slice `os` does not match the device OS.
    #[error("foreign OS: device is {expected} but slice targets {found}")]
    ForeignOs {
        /// Device OS.
        expected: RoleOs,
        /// Slice OS.
        found: RoleOs,
    },
    /// A payload field present that does not belong to the slice's OS.
    #[error("payload field {field:?} is not valid for os {os}")]
    PayloadOsMismatch {
        /// Slice OS.
        os: RoleOs,
        /// Offending payload field name.
        field: &'static str,
    },
    /// `mac_mask` does not parse as a u64 (hex `0x..` or decimal).
    #[error("mac_mask {value:?} is not a valid hex (0x..) or decimal u64")]
    MacMaskInvalid {
        /// The rejected value.
        value: String,
    },
}

/// Parse a `mac_mask` string as a `u64`. Accepts an optional `0x`/`0X`
/// hex prefix; otherwise decimal. Underscores are not allowed.
pub fn parse_mac_mask(s: &str) -> Result<u64, RoleSchemaError> {
    let trimmed = s.trim();
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u64>()
    };
    parsed.map_err(|_| RoleSchemaError::MacMaskInvalid {
        value: s.to_owned(),
    })
}

/// Validate that a payload only carries fields belonging to `os`, and
/// that any present `mac_mask` parses. Open build parses every section;
/// this check rejects cross-OS contamination (design D2) regardless of
/// build.
///
/// - astra: only `mac_mask` allowed.
/// - linux: `groups`, `sudo_role`, `limits`, `selinux` allowed (`SELinux`
///   is a Linux LSM, so it lives under `linux`); `mac_mask` rejected.
/// - windows: no sections defined yet (design Non-Goal); any present field
///   is rejected.
pub fn validate_payload_for_os(payload: &Payload, os: RoleOs) -> Result<(), RoleSchemaError> {
    let reject = |field: &'static str| Err(RoleSchemaError::PayloadOsMismatch { os, field });
    match os {
        RoleOs::Astra => {
            if payload.groups.is_some() {
                return reject("groups");
            }
            if payload.sudo_role.is_some() {
                return reject("sudo_role");
            }
            if payload.limits.is_some() {
                return reject("limits");
            }
            if payload.selinux.is_some() {
                return reject("selinux");
            }
            if let Some(mask) = payload.mac_mask.as_deref() {
                parse_mac_mask(mask)?;
            }
        }
        RoleOs::Linux => {
            if payload.mac_mask.is_some() {
                return reject("mac_mask");
            }
            // groups/sudo_role/limits/selinux all allowed; nothing else exists.
        }
        RoleOs::Windows => {
            if payload.mac_mask.is_some() {
                return reject("mac_mask");
            }
            if payload.groups.is_some() {
                return reject("groups");
            }
            if payload.sudo_role.is_some() {
                return reject("sudo_role");
            }
            if payload.limits.is_some() {
                return reject("limits");
            }
            if payload.selinux.is_some() {
                return reject("selinux");
            }
        }
    }
    Ok(())
}

/// Parse and validate a role slice from raw file bytes.
///
/// Steps: size cap → UTF-8 → strict TOML → role==expected → os==device →
/// payload-by-os validation. Returns the validated [`RoleSlice`].
pub fn parse_slice(
    bytes: &[u8],
    expected_role_id: &str,
    device_os: RoleOs,
) -> Result<RoleSlice, RoleSchemaError> {
    if bytes.len() > MAX_SLICE_BYTES {
        return Err(RoleSchemaError::Oversize {
            size: bytes.len(),
            max: MAX_SLICE_BYTES,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|e| RoleSchemaError::NotUtf8 {
        reason: e.to_string(),
    })?;
    let slice: RoleSlice = toml::from_str(text).map_err(|e| RoleSchemaError::TomlParse {
        reason: e.to_string(),
    })?;
    if slice.role.as_str() != expected_role_id {
        return Err(RoleSchemaError::RoleMismatch {
            expected: expected_role_id.to_owned(),
            found: slice.role.as_str().to_owned(),
        });
    }
    if slice.os != device_os {
        return Err(RoleSchemaError::ForeignOs {
            expected: device_os,
            found: slice.os,
        });
    }
    if let Some(payload) = slice.payload.as_ref() {
        validate_payload_for_os(payload, slice.os)?;
    }
    Ok(slice)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_panics_doc,
        clippy::missing_docs_in_private_items,
        clippy::let_underscore_must_use,
        clippy::duration_suboptimal_units
    )]

    use super::*;

    // ---- 1.1: schema + strict parsing ------------------------------------

    #[test]
    fn regex_compiles_and_matches() {
        assert!(RoleId::new("a").is_ok());
    }

    #[test]
    fn valid_minimal_slice_parses() {
        let doc = "role = \"serv\"\nversion = 2\nos = \"linux\"\nname = \"Service\"\nlevel = 5\n";
        let slice = parse_slice(doc.as_bytes(), "serv", RoleOs::Linux).unwrap();
        assert_eq!(slice.role.as_str(), "serv");
        assert_eq!(slice.version, 2);
        assert_eq!(slice.os, RoleOs::Linux);
        assert_eq!(slice.name, "Service");
        assert_eq!(slice.level, 5);
        assert_eq!(slice.description, None);
        assert_eq!(slice.payload, None);
        assert_eq!(slice.session, None);
    }

    #[test]
    fn description_optional() {
        let without = "role = \"serv\"\nversion = 1\nos = \"linux\"\nname = \"n\"\nlevel = 0\n";
        let slice = parse_slice(without.as_bytes(), "serv", RoleOs::Linux).unwrap();
        assert_eq!(slice.description, None);

        let with = "role = \"serv\"\nversion = 1\nos = \"linux\"\nname = \"n\"\nlevel = 0\ndescription = \"hi\"\n";
        let slice = parse_slice(with.as_bytes(), "serv", RoleOs::Linux).unwrap();
        assert_eq!(slice.description.as_deref(), Some("hi"));
    }

    #[test]
    fn unknown_field_rejected() {
        let doc =
            "role = \"serv\"\nversion = 1\nos = \"linux\"\nname = \"n\"\nlevel = 0\nbogus = 1\n";
        let err = parse_slice(doc.as_bytes(), "serv", RoleOs::Linux).unwrap_err();
        assert!(matches!(err, RoleSchemaError::TomlParse { .. }));
    }

    #[test]
    fn bad_type_rejected() {
        let doc = "role = \"serv\"\nversion = \"x\"\nos = \"linux\"\nname = \"n\"\nlevel = 0\n";
        let err = parse_slice(doc.as_bytes(), "serv", RoleOs::Linux).unwrap_err();
        assert!(matches!(err, RoleSchemaError::TomlParse { .. }));
    }

    #[test]
    fn role_mismatch_rejected() {
        let doc = "role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"n\"\nlevel = 0\n";
        let err = parse_slice(doc.as_bytes(), "serv", RoleOs::Linux).unwrap_err();
        assert!(matches!(err, RoleSchemaError::RoleMismatch { .. }));
    }

    #[test]
    fn foreign_os_rejected() {
        let doc = "role = \"serv\"\nversion = 1\nos = \"windows\"\nname = \"n\"\nlevel = 0\n";
        let err = parse_slice(doc.as_bytes(), "serv", RoleOs::Linux).unwrap_err();
        assert!(matches!(err, RoleSchemaError::ForeignOs { .. }));
    }

    #[test]
    fn role_id_boundary() {
        assert!(RoleId::new("a").is_ok());

        let sixteen = format!("a{}", "a".repeat(15));
        assert_eq!(sixteen.len(), 16);
        assert!(RoleId::new(&sixteen).is_ok());

        let seventeen = format!("a{}", "a".repeat(16));
        assert_eq!(seventeen.len(), 17);
        assert!(RoleId::new(&seventeen).is_err());

        assert!(RoleId::new("Abc").is_err());
        assert!(RoleId::new("1abc").is_err());
        assert!(RoleId::new("ab+cd").is_err());
        assert!(RoleId::new("").is_err());
        assert!(RoleId::new("a-b-c").is_ok());
    }

    #[test]
    fn oversize_rejected() {
        let bytes = vec![b'#'; MAX_SLICE_BYTES + 1];
        let err = parse_slice(&bytes, "serv", RoleOs::Linux).unwrap_err();
        assert!(matches!(err, RoleSchemaError::Oversize { .. }));
    }

    #[test]
    fn session_parses_and_max_ttl() {
        let doc = "role = \"serv\"\nversion = 1\nos = \"linux\"\nname = \"n\"\nlevel = 0\n\
                   [session]\nmax_ttl_seconds = 3600\nmemory_max = \"512M\"\ntasks_max = 100\n\
                   cpu_weight = 200\nio_weight = 300\n";
        let slice = parse_slice(doc.as_bytes(), "serv", RoleOs::Linux).unwrap();
        let session = slice.session.unwrap();
        assert_eq!(session.max_ttl(), Some(Duration::from_secs(3600)));
        assert_eq!(session.memory_max.as_deref(), Some("512M"));
        assert_eq!(session.tasks_max, Some(100));
        assert_eq!(session.cpu_weight, Some(200));
        assert_eq!(session.io_weight, Some(300));

        let empty = SessionLimits::default();
        assert_eq!(empty.max_ttl(), None);
    }

    // ---- 1.3: payload-by-os validation -----------------------------------

    #[test]
    fn astra_payload_mac_mask_parses() {
        let doc = "role = \"serv\"\nversion = 1\nos = \"astra\"\nname = \"n\"\nlevel = 0\n\
                   [payload]\nmac_mask = \"0xff\"\n";
        let slice = parse_slice(doc.as_bytes(), "serv", RoleOs::Astra).unwrap();
        let payload = slice.payload.unwrap();
        assert_eq!(payload.mac_mask.as_deref(), Some("0xff"));
        assert_eq!(parse_mac_mask("0xff").unwrap(), 255);
    }

    #[test]
    fn linux_payload_groups_sudo_limits_parses() {
        let doc = "role = \"serv\"\nversion = 1\nos = \"linux\"\nname = \"n\"\nlevel = 0\n\
                   [payload]\ngroups = [\"wheel\", \"docker\"]\nsudo_role = \"ops\"\n\
                   [payload.limits]\nnofile = 1024\nnproc = 512\n";
        let slice = parse_slice(doc.as_bytes(), "serv", RoleOs::Linux).unwrap();
        let payload = slice.payload.unwrap();
        assert_eq!(
            payload.groups.as_deref(),
            Some(["wheel".to_owned(), "docker".to_owned()].as_slice())
        );
        assert_eq!(payload.sudo_role.as_deref(), Some("ops"));
        let limits = payload.limits.unwrap();
        assert_eq!(limits.nofile, Some(1024));
        assert_eq!(limits.nproc, Some(512));
    }

    #[test]
    fn selinux_under_linux_parses() {
        let doc = "role = \"serv\"\nversion = 1\nos = \"linux\"\nname = \"n\"\nlevel = 0\n\
                   [payload.selinux]\nuser = \"staff_u\"\nrole = \"staff_r\"\nrange = \"s0\"\n";
        let slice = parse_slice(doc.as_bytes(), "serv", RoleOs::Linux).unwrap();
        let selinux = slice.payload.unwrap().selinux.unwrap();
        assert_eq!(selinux.user.as_deref(), Some("staff_u"));
        assert_eq!(selinux.role.as_deref(), Some("staff_r"));
        assert_eq!(selinux.range.as_deref(), Some("s0"));
    }

    #[test]
    fn mac_mask_in_linux_rejected() {
        let doc = "role = \"serv\"\nversion = 1\nos = \"linux\"\nname = \"n\"\nlevel = 0\n\
                   [payload]\nmac_mask = \"0x1\"\n";
        let err = parse_slice(doc.as_bytes(), "serv", RoleOs::Linux).unwrap_err();
        assert!(matches!(
            err,
            RoleSchemaError::PayloadOsMismatch {
                field: "mac_mask",
                ..
            }
        ));
    }

    #[test]
    fn groups_in_astra_rejected() {
        let doc = "role = \"serv\"\nversion = 1\nos = \"astra\"\nname = \"n\"\nlevel = 0\n\
                   [payload]\ngroups = [\"wheel\"]\n";
        let err = parse_slice(doc.as_bytes(), "serv", RoleOs::Astra).unwrap_err();
        assert!(matches!(
            err,
            RoleSchemaError::PayloadOsMismatch {
                field: "groups",
                ..
            }
        ));
    }

    #[test]
    fn invalid_mac_mask_rejected() {
        let doc = "role = \"serv\"\nversion = 1\nos = \"astra\"\nname = \"n\"\nlevel = 0\n\
                   [payload]\nmac_mask = \"0xZZ\"\n";
        let err = parse_slice(doc.as_bytes(), "serv", RoleOs::Astra).unwrap_err();
        assert!(matches!(err, RoleSchemaError::MacMaskInvalid { .. }));
        assert!(parse_mac_mask("nope").is_err());
    }

    #[test]
    fn windows_payload_rejected() {
        let doc = "role = \"serv\"\nversion = 1\nos = \"windows\"\nname = \"n\"\nlevel = 0\n\
                   [payload]\ngroups = [\"Administrators\"]\n";
        let err = parse_slice(doc.as_bytes(), "serv", RoleOs::Windows).unwrap_err();
        assert!(matches!(err, RoleSchemaError::PayloadOsMismatch { .. }));
    }

    #[test]
    fn parse_mac_mask_decimal_and_hex() {
        assert_eq!(parse_mac_mask("255").unwrap(), 255);
        assert_eq!(parse_mac_mask("0xFF").unwrap(), 255);
        assert_eq!(parse_mac_mask("0X10").unwrap(), 16);
    }
}

#[cfg(test)]
mod proptests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_panics_doc,
        clippy::missing_docs_in_private_items,
        clippy::let_underscore_must_use
    )]

    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_slice_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = parse_slice(&data, "role", RoleOs::Linux);
        }

        #[test]
        fn role_id_roundtrip(id in proptest::string::string_regex(r"[a-z][a-z0-9-]{0,15}").unwrap()) {
            let parsed = RoleId::new(&id).unwrap();
            prop_assert_eq!(parsed.as_str(), id.as_str());
            prop_assert_eq!(parsed.to_string(), id.clone());
            let reparsed = RoleId::new(parsed.as_str()).unwrap();
            prop_assert_eq!(reparsed, parsed.clone());
            // round-trips through a real slice document
            let doc = format!(
                "role = \"{id}\"\nversion = 1\nos = \"linux\"\nname = \"n\"\nlevel = 0\n"
            );
            let slice = parse_slice(doc.as_bytes(), &id, RoleOs::Linux).unwrap();
            prop_assert_eq!(slice.role, parsed);
        }
    }
}
