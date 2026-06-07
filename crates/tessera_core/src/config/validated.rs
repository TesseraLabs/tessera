//! Validated config.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use crate::config::raw::{
    RawCertIntegrityMode, RawConfig, RawCryptoBackend, RawFlyDmGreeter, RawHostIdFallback,
    RawHostIdentity, RawMacPolicy, RawMacRuntimeMode, RawMode, RawMonitor, RawMonitorFailMode,
    RawOnUsbRemoved, RawPkcs11LockingMode, RawRevocationMode, RawTrust, RawTrustOverride,
    RawUserMapping,
};
use crate::error::TrustError;
use crate::hooks::{validate_hook, HookConfig};
use crate::mac::IntegrityLabel;
use crate::token::pkcs11::LockingMode as Pkcs11LockingMode;
use crate::x509::SignatureAlg;
use crate::{Error, LogLevel, SyslogFacility};

/// Validated config.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    /// Crypto backend.
    pub crypto_backend: CryptoBackend,
    /// Mode.
    pub mode: Mode,
    /// PKCS#11 module.
    pub pkcs11_module: Option<PathBuf>,
    /// Optional `CKA_LABEL` filter for the token.
    pub pkcs11_token_label: Option<String>,
    /// Optional `CKA_LABEL` filter for the on-token cert / key
    /// objects.  Defaults to `None` which means "use the first
    /// end-entity cert found".
    pub pkcs11_object_label: Option<String>,
    /// Maximum number of PIN attempts before bailing (default 3).
    pub pkcs11_max_pin_attempts: u32,
    /// PKCS#11 locking mode (default OS).
    pub pkcs11_locking_mode: Pkcs11LockingMode,
    /// Prompt string for the token PIN (default in Russian, defined at runtime).
    pub pkcs11_pin_prompt: Option<String>,
    /// Maximum time `wait_for_token` will block waiting for the user
    /// to insert the token (default 10 s).
    pub pkcs11_slot_wait: Duration,
    /// PKCS#12 path pattern.
    pub pkcs12_path_pattern: Option<String>,
    /// PIN prompt.
    pub pkcs12_pin_prompt: Option<String>,
    /// Optional path to the gost-engine `.so`.
    ///
    /// Validated to be a readable file when `Some`.  Only meaningful with
    /// [`CryptoBackend::Openssl`]; combining this field with any other backend
    /// is rejected at validation time.
    pub gost_engine_path: Option<PathBuf>,
    /// USB wait.
    pub usb_wait: Duration,
    /// Maximum number of USB partitions inspected at auth time (1..=64,
    /// default 8).  Anti-DoS guard against a physical adversary plugging
    /// in a many-partition device.
    pub max_usb_partitions: u32,
    /// USB removal action.
    pub on_usb_removed: OnUsbRemoved,
    /// USB removed grace.
    pub usb_removed_grace: Duration,
    /// Suspend grace.
    pub suspend_grace: Duration,
    /// Monitor fail mode.
    pub monitor_fail_mode: MonitorFailMode,
    /// Monitor IPC section (socket path, timeout, effective fail mode).
    pub monitor: MonitorSection,
    /// Trust section.
    pub trust: TrustSection,
    /// Trust overrides.
    pub trust_overrides: Vec<TrustOverride>,
    /// Host identity.
    pub host_identity: HostIdentitySection,
    /// User mappings.
    pub user_mappings: Vec<UserMapping>,
    /// Logging.
    pub logging: LoggingSection,
    /// Hooks.
    pub hooks: Vec<HookConfig>,
    /// MAC integrity policy (spec §2.4).
    pub mac: MacPolicy,
    /// Astra fly-dm greeter banner section.
    pub fly_dm_greeter: FlyDmGreeterSection,
}

/// Validated `[fly_dm_greeter]` section. See [`RawFlyDmGreeter`] for the
/// raw schema and motivation. Templates support `{host_id_short}` (8-char
/// SHA-256 hex prefix), `{source}` (`snake_case` source kind) and `%n`
/// (local hostname).
#[derive(Debug, Clone)]
pub struct FlyDmGreeterSection {
    /// When true, the daemon bakes the `host_id` banner into the fly-dm
    /// wallpaper on start. Default false (opt-in, Astra-specific).
    pub update_wallpaper: bool,
    /// Absolute path to the wallpaper image written by the daemon
    /// (referenced from `/etc/X11/fly-dm/fly-modern/settings.ini`
    /// `[background].path`).
    pub wallpaper_target: PathBuf,
    /// Absolute path to the preserved original wallpaper.
    pub wallpaper_backup: PathBuf,
    /// Absolute path to the TrueType font used to render the banner.
    pub wallpaper_font: PathBuf,
    /// Font size in pixels.
    pub wallpaper_font_size: u32,
    /// Text colour as RGBA.
    pub wallpaper_text_color: [u8; 4],
    /// Anchor on the image for the banner.
    pub wallpaper_gravity: Gravity,
    /// Horizontal pixel offset added to the gravity anchor.
    pub wallpaper_offset_x: i32,
    /// Vertical pixel offset added to the gravity anchor (upward for
    /// south gravity, ImageMagick-like behaviour).
    pub wallpaper_offset_y: i32,
    /// Russian-locale template.
    pub template_ru: String,
    /// Non-Russian / English template.
    pub template_en: String,
}

/// Gravity / anchor position for the wallpaper banner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gravity {
    /// Top centre.
    North,
    /// Bottom centre.
    South,
    /// Middle right.
    East,
    /// Middle left.
    West,
    /// Image centre.
    Center,
}

impl Default for FlyDmGreeterSection {
    fn default() -> Self {
        Self {
            update_wallpaper: false,
            wallpaper_target: PathBuf::from("/usr/share/wallpapers/fly-default-light.jpg"),
            wallpaper_backup: PathBuf::from("/var/lib/tessera/wallpaper.orig.jpg"),
            wallpaper_font: PathBuf::from(
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            ),
            wallpaper_font_size: 64,
            wallpaper_text_color: [0, 0, 0, 255],
            wallpaper_gravity: Gravity::South,
            wallpaper_offset_x: 0,
            wallpaper_offset_y: 120,
            template_ru: "Банкомат %n  host_id={host_id_short} ({source})".to_string(),
            template_en: "ATM %n  host_id={host_id_short} ({source})".to_string(),
        }
    }
}

/// Validated `[mac]` policy block.
#[derive(Debug, Clone)]
pub struct MacPolicy {
    /// Trinary policy for the X.509 `MAX_INTEGRITY` extension on the
    /// authenticating certificate. Default [`CertIntegrityMode::Optional`].
    pub cert_integrity: CertIntegrityMode,
    /// Fallback upper bound applied when the cert carries no extension and
    /// [`Self::cert_integrity`] is [`CertIntegrityMode::Optional`].
    pub fallback_max_integrity: Option<IntegrityLabel>,
    /// Whether to emit a warning when the resolved process label disagrees
    /// with the user's `$HOME` label at session-open time. Default `true`.
    pub warn_on_homedir_label_mismatch: bool,
    /// Runtime selection for the MAC backend. Default
    /// [`MacRuntimeMode::Auto`]. See [`MacRuntimeMode`].
    pub runtime: MacRuntimeMode,
}

impl Default for MacPolicy {
    fn default() -> Self {
        Self {
            cert_integrity: CertIntegrityMode::Optional,
            fallback_max_integrity: None,
            warn_on_homedir_label_mismatch: true,
            runtime: MacRuntimeMode::Auto,
        }
    }
}

/// Runtime selection for the MAC backend (independent of the
/// compile-time `astra-mac` feature).
///
/// - [`MacRuntimeMode::Required`] — auth fails if the МКЦ kernel
///   subsystem is not present.
/// - [`MacRuntimeMode::Auto`] — use the real backend when the kernel
///   reports МКЦ available; otherwise fall back to the no-op stub and
///   emit a `mac_runtime_fallback` audit event.
/// - [`MacRuntimeMode::Disabled`] — always use the stub backend even
///   when the binary is built with `astra-mac`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacRuntimeMode {
    /// Real backend required; fail-closed when kernel МКЦ missing.
    Required,
    /// Probe kernel; real when present, stub otherwise.
    Auto,
    /// Always use the stub backend regardless of kernel state.
    Disabled,
}

/// Trinary policy for the X.509 `MAX_INTEGRITY` extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertIntegrityMode {
    /// Extension MUST be present; missing extension fails authentication.
    Required,
    /// Extension is consulted when present; absent falls back to
    /// `fallback_max_integrity` or admin-default.
    Optional,
    /// Extension is not consulted; integrity comes from admin policy only.
    Ignore,
}

/// Crypto backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoBackend {
    /// OpenSSL.
    Openssl,
    /// Native PKCS#11.
    Pkcs11Native,
}

/// Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// PKCS#12.
    Pkcs12,
    /// PKCS#11.
    Pkcs11,
}

/// USB removed action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnUsbRemoved {
    /// Lock.
    Lock,
    /// Logout.
    Logout,
    /// Hook.
    Hook,
    /// Shutdown.
    Shutdown,
}

/// Monitor failure mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorFailMode {
    /// Strict.
    Strict,
    /// Permissive.
    Permissive,
}

/// Validated `[monitor]` section: where to talk to monitord, how long to
/// wait, and how to react to failures.
#[derive(Debug, Clone)]
pub struct MonitorSection {
    /// Absolute path to the monitord Unix socket.
    pub socket_path: PathBuf,
    /// Per-RPC connect+IO timeout.
    pub timeout: Duration,
    /// Effective fail mode (resolved from `[monitor].fail_mode` or, when
    /// absent, the top-level `monitor_fail_mode`).
    pub fail_mode: MonitorFailMode,
    /// Absolute path to the persisted session-registry JSON. Read by
    /// `tessera`.
    pub state_file_path: PathBuf,
    /// Action `tessera` should take on a confirmed USB
    /// removal past the grace window.
    pub on_usb_removed: OnUsbRemoved,
    /// Grace window between a USB removal event and the configured
    /// action.
    pub usb_removed_grace: Duration,
    /// Suspend-grace window: removals within this many seconds after a
    /// resume are ignored.
    pub suspend_grace: Duration,
    /// Absolute path to the hook executable invoked when
    /// [`MonitorSection::on_usb_removed`] is [`OnUsbRemoved::Hook`].
    /// `None` for any other mode.
    pub on_usb_removed_hook_path: Option<PathBuf>,
    /// Per-connection idle timeout for the monitord IPC server.
    pub idle_timeout: Duration,
    /// Maximum number of concurrent client connections accepted by the
    /// monitord IPC server.
    pub max_concurrent_connections: u32,
}

/// Trust section.
#[derive(Debug, Clone)]
pub struct TrustSection {
    /// Anchors.
    pub anchors: Vec<PathBuf>,
    /// Intermediates.
    pub intermediates: Vec<PathBuf>,
    /// Revocation.
    pub revocation: RevocationSection,
    /// Signature algorithms.
    pub allowed_signature_algorithms: BTreeSet<String>,
    /// Trust-anchor SPKI pinning.
    pub pinning: PinningSection,
    /// Maximum chain depth (1..=N).  Validator enforces `>= 1` and
    /// caps at the platform-reasonable upper bound.
    pub max_chain_depth: u32,
    /// PKI clock-skew tolerance in seconds.  Validator enforces
    /// `<= 600` (ten minutes).
    pub clock_skew_seconds: u64,
}

/// Validated `[trust.pinning]` section.
///
/// When [`PinningSection::enabled`] is `false` the verifier MUST NOT
/// enforce pinning, regardless of the contents of `allowed_root_spki_sha256`.
/// When `enabled = true` the verifier MUST reject any chain whose anchor's
/// SPKI SHA-256 is not in the configured set.
#[derive(Debug, Clone, Default)]
pub struct PinningSection {
    /// Enabled.
    pub enabled: bool,
    /// 32-byte SPKI SHA-256 pins (hex strings already validated as
    /// 64-char ASCII hex by [`validate_trust`]).
    pub allowed_root_spki_sha256: Vec<String>,
}

/// Revocation section.
#[derive(Debug, Clone)]
pub struct RevocationSection {
    /// Mode.
    pub mode: RevocationMode,
    /// CRL paths.
    pub crl_paths: Vec<PathBuf>,
}

/// Revocation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationMode {
    /// None.
    None,
    /// CRL.
    Crl,
    /// OCSP.
    Ocsp,
    /// CRL then OCSP.
    CrlThenOcsp,
}

/// Trust override.
#[derive(Debug, Clone)]
pub struct TrustOverride {
    /// Host ids.
    pub when_host_id_in: BTreeSet<String>,
    /// Anchors.
    pub anchors: Vec<PathBuf>,
    /// Intermediates.
    pub intermediates: Vec<PathBuf>,
}

/// Host identity section.
#[derive(Debug, Clone)]
pub struct HostIdentitySection {
    /// Sources.
    pub sources: Vec<crate::host_identity::HostIdSourceKind>,
    /// Fallback.
    pub fallback: HostIdFallback,
    /// Override.
    pub override_value: Option<String>,
    /// Custom command.
    pub custom_command: Option<PathBuf>,
    /// Custom command timeout.
    pub custom_command_timeout: Duration,
}

/// Host id fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostIdFallback {
    /// Deny.
    Deny,
    /// Warn.
    Warn,
    /// Allow.
    Allow,
}

/// User mapping.
#[derive(Debug, Clone)]
pub struct UserMapping {
    /// PAM user.
    pub pam_user: String,
    /// Criteria.
    pub criteria: UserMatchCriteria,
}

/// User match criteria.
#[derive(Debug, Clone)]
pub enum UserMatchCriteria {
    /// Subject CN.
    SubjectCn(String),
    /// SAN email.
    SanEmail(String),
    /// SAN UPN.
    SanUpn(String),
}

/// Logging section.
#[derive(Debug, Clone)]
pub struct LoggingSection {
    /// Level.
    pub level: LogLevel,
    /// Facility.
    pub syslog_facility: SyslogFacility,
    /// Journald priority.
    pub journald_priority: bool,
}

impl ValidatedConfig {
    /// Returns `true` iff the active backend is OpenSSL **and** at least one
    /// configured signature algorithm in
    /// [`TrustSection::allowed_signature_algorithms`] requires the gost-engine.
    ///
    /// PKCS#11-native does its crypto inside the token and never needs the
    /// engine, so this returns `false` for that backend regardless of the
    /// configured OID list.
    #[must_use]
    pub fn needs_gost(&self) -> bool {
        matches!(self.crypto_backend, CryptoBackend::Openssl)
            && self
                .trust
                .allowed_signature_algorithms
                .iter()
                .any(|s| SignatureAlg::from_oid_string(s).is_gost())
    }
}

impl TryFrom<&RawConfig> for ValidatedConfig {
    type Error = Error;

    fn try_from(raw: &RawConfig) -> Result<Self, Self::Error> {
        let trust = validate_trust(&raw.trust)?;
        let host_identity = validate_host_identity(&raw.host_identity)?;
        let user_mappings = validate_user_mappings(&raw.user_mapping)?;
        let logging = LoggingSection {
            level: raw.logging.level.parse()?,
            syslog_facility: raw.logging.syslog_facility.parse()?,
            journald_priority: raw.logging.journald_priority,
        };
        let hooks = raw
            .hooks
            .iter()
            .map(validate_hook)
            .collect::<Result<Vec<_>, _>>()?;
        let crypto_backend = match raw.crypto_backend {
            RawCryptoBackend::Openssl => CryptoBackend::Openssl,
            RawCryptoBackend::Pkcs11Native => CryptoBackend::Pkcs11Native,
        };
        let gost_engine_path = validate_gost_engine_path(raw, crypto_backend)?;
        let mode = match raw.mode {
            RawMode::Pkcs12 => Mode::Pkcs12,
            RawMode::Pkcs11 => Mode::Pkcs11,
        };
        validate_pkcs11_section(raw, mode)?;
        Ok(Self {
            crypto_backend,
            mode,
            pkcs11_module: raw.pkcs11_module.clone(),
            pkcs11_token_label: raw.pkcs11_token_label.clone(),
            pkcs11_object_label: raw.pkcs11_object_label.clone(),
            pkcs11_max_pin_attempts: raw.pkcs11_max_pin_attempts,
            pkcs11_locking_mode: match raw.pkcs11_locking_mode {
                RawPkcs11LockingMode::Os => Pkcs11LockingMode::Os,
                RawPkcs11LockingMode::Mutex => Pkcs11LockingMode::Mutex,
            },
            pkcs11_pin_prompt: raw.pkcs11_pin_prompt.clone(),
            pkcs11_slot_wait: Duration::from_secs(u64::from(raw.pkcs11_slot_wait_seconds)),
            pkcs12_path_pattern: validate_pkcs12_path_pattern(raw.pkcs12_path_pattern.as_deref())?,
            pkcs12_pin_prompt: raw.pkcs12_pin_prompt.clone(),
            gost_engine_path,
            usb_wait: Duration::from_secs(raw.usb_wait_seconds),
            max_usb_partitions: validate_max_usb_partitions(raw.max_usb_partitions)?,
            on_usb_removed: match raw.on_usb_removed {
                RawOnUsbRemoved::Lock => OnUsbRemoved::Lock,
                RawOnUsbRemoved::Logout => OnUsbRemoved::Logout,
                RawOnUsbRemoved::Hook => OnUsbRemoved::Hook,
                RawOnUsbRemoved::Shutdown => OnUsbRemoved::Shutdown,
            },
            usb_removed_grace: Duration::from_secs(raw.usb_removed_grace_seconds),
            suspend_grace: Duration::from_secs(raw.suspend_grace_seconds),
            monitor_fail_mode: match raw.monitor_fail_mode {
                RawMonitorFailMode::Strict => MonitorFailMode::Strict,
                RawMonitorFailMode::Permissive => MonitorFailMode::Permissive,
            },
            monitor: validate_monitor(raw, &raw.monitor, raw.monitor_fail_mode)?,
            trust,
            trust_overrides: raw
                .trust_override
                .iter()
                .map(validate_trust_override)
                .collect::<Result<Vec<_>, _>>()?,
            host_identity,
            user_mappings,
            logging,
            hooks,
            mac: validate_mac(&raw.mac)?,
            fly_dm_greeter: validate_fly_dm_greeter(raw.fly_dm_greeter.as_ref())?,
        })
    }
}

fn fly_dm_absolute_path(
    field: &str,
    value: Option<&String>,
    default: PathBuf,
) -> Result<PathBuf, Error> {
    match value {
        Some(p) => {
            let pb = PathBuf::from(p);
            if !pb.is_absolute() {
                return Err(Error::ConfigInvalid {
                    reason: format!(
                        "fly_dm_greeter.{field} must be absolute (got {})",
                        pb.display()
                    ),
                });
            }
            Ok(pb)
        }
        None => Ok(default),
    }
}

fn validate_fly_dm_greeter(raw: Option<&RawFlyDmGreeter>) -> Result<FlyDmGreeterSection, Error> {
    let defaults = FlyDmGreeterSection::default();
    let Some(raw) = raw else {
        return Ok(defaults);
    };

    let wallpaper_target = fly_dm_absolute_path(
        "wallpaper_target",
        raw.wallpaper_target.as_ref(),
        defaults.wallpaper_target,
    )?;
    let wallpaper_backup = fly_dm_absolute_path(
        "wallpaper_backup",
        raw.wallpaper_backup.as_ref(),
        defaults.wallpaper_backup,
    )?;
    let wallpaper_font = fly_dm_absolute_path(
        "wallpaper_font",
        raw.wallpaper_font.as_ref(),
        defaults.wallpaper_font,
    )?;

    let wallpaper_text_color = match raw.wallpaper_text_color.as_deref() {
        Some(s) => parse_hex_color(s).ok_or_else(|| Error::ConfigInvalid {
            reason: format!(
                "fly_dm_greeter.wallpaper_text_color must be #RRGGBB or #RRGGBBAA (got {s:?})"
            ),
        })?,
        None => defaults.wallpaper_text_color,
    };

    let wallpaper_gravity = match raw.wallpaper_gravity.as_deref() {
        Some(s) => parse_gravity(s).ok_or_else(|| Error::ConfigInvalid {
            reason: format!(
                "fly_dm_greeter.wallpaper_gravity must be one of \
                 north|south|east|west|center (got {s:?})"
            ),
        })?,
        None => defaults.wallpaper_gravity,
    };

    let wallpaper_font_size = raw
        .wallpaper_font_size
        .unwrap_or(defaults.wallpaper_font_size);
    if wallpaper_font_size == 0 {
        return Err(Error::ConfigInvalid {
            reason: "fly_dm_greeter.wallpaper_font_size must be > 0".into(),
        });
    }

    Ok(FlyDmGreeterSection {
        update_wallpaper: raw.update_wallpaper.unwrap_or(defaults.update_wallpaper),
        wallpaper_target,
        wallpaper_backup,
        wallpaper_font,
        wallpaper_font_size,
        wallpaper_text_color,
        wallpaper_gravity,
        wallpaper_offset_x: raw.wallpaper_offset_x.unwrap_or(defaults.wallpaper_offset_x),
        wallpaper_offset_y: raw.wallpaper_offset_y.unwrap_or(defaults.wallpaper_offset_y),
        template_ru: raw.template_ru.clone().unwrap_or(defaults.template_ru),
        template_en: raw.template_en.clone().unwrap_or(defaults.template_en),
    })
}

fn parse_hex_color(input: &str) -> Option<[u8; 4]> {
    let hex = input.strip_prefix('#')?;
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    match hex.len() {
        6 => {
            let red = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let green = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let blue = u8::from_str_radix(&hex[4..6], 16).ok()?;
            Some([red, green, blue, 255])
        }
        8 => {
            let red = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let green = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let blue = u8::from_str_radix(&hex[4..6], 16).ok()?;
            let alpha = u8::from_str_radix(&hex[6..8], 16).ok()?;
            Some([red, green, blue, alpha])
        }
        _ => None,
    }
}

fn parse_gravity(s: &str) -> Option<Gravity> {
    match s.to_ascii_lowercase().as_str() {
        "north" => Some(Gravity::North),
        "south" => Some(Gravity::South),
        "east" => Some(Gravity::East),
        "west" => Some(Gravity::West),
        "center" | "centre" => Some(Gravity::Center),
        _ => None,
    }
}

/// Maximum length of the hex-encoded `categories` field: 16 hex chars = 64 bits.
const MAC_CATEGORIES_HEX_MAX_LEN: usize = 16;

fn validate_mac(raw: &RawMacPolicy) -> Result<MacPolicy, Error> {
    let cert_integrity = match raw.cert_integrity {
        Some(RawCertIntegrityMode::Required) => CertIntegrityMode::Required,
        Some(RawCertIntegrityMode::Ignore) => CertIntegrityMode::Ignore,
        Some(RawCertIntegrityMode::Optional) | None => CertIntegrityMode::Optional,
    };
    let runtime = match raw.runtime {
        Some(RawMacRuntimeMode::Required) => MacRuntimeMode::Required,
        Some(RawMacRuntimeMode::Disabled) => MacRuntimeMode::Disabled,
        Some(RawMacRuntimeMode::Auto) | None => MacRuntimeMode::Auto,
    };
    // `runtime = disabled` + `cert_integrity = required` is logically
    // inconsistent: there will be no backend to read or enforce the
    // cert label, so the policy can never be satisfied. Reject early so
    // operators don't get a confusing runtime denial on every login.
    // Checked first so this clearer error wins over the stub-build
    // `cert_integrity = required` rejection below.
    if matches!(runtime, MacRuntimeMode::Disabled)
        && matches!(cert_integrity, CertIntegrityMode::Required)
    {
        return Err(Error::ConfigInvalid {
            reason:
                "[mac].runtime = \"disabled\" is incompatible with cert_integrity = \"required\" \
                     (the stub backend cannot enforce the cert label)"
                    .into(),
        });
    }
    // Fail-fast: stub builds (without `astra-mac`) cannot honour
    // `cert_integrity = "required"` because there is no real backend
    // to enforce the label.  Reject at config load so the operator sees
    // the misconfiguration immediately rather than at first session.
    #[cfg(not(feature = "astra-mac"))]
    if matches!(cert_integrity, CertIntegrityMode::Required) {
        return Err(Error::ConfigInvalid {
            reason:
                "[mac].cert_integrity = \"required\" but binary built without `astra-mac` feature"
                    .into(),
        });
    }
    // Same fail-fast for `runtime = "required"` — a stub build can never
    // satisfy a hard MAC requirement, so surface the misconfiguration at
    // config load.
    #[cfg(not(feature = "astra-mac"))]
    if matches!(runtime, MacRuntimeMode::Required) {
        return Err(Error::ConfigInvalid {
            reason: "[mac].runtime = \"required\" but binary built without `astra-mac` feature"
                .into(),
        });
    }
    let fallback_max_integrity = raw
        .fallback_max_integrity
        .as_ref()
        .map(|r| {
            let cats = if r.categories.is_empty() {
                0u64
            } else {
                if r.categories.len() > MAC_CATEGORIES_HEX_MAX_LEN {
                    return Err(Error::ConfigInvalid {
                        reason: format!(
                            "mac.fallback_max_integrity.categories must be at most {MAC_CATEGORIES_HEX_MAX_LEN} hex chars (got {})",
                            r.categories.len()
                        ),
                    });
                }
                u64::from_str_radix(&r.categories, 16).map_err(|e| Error::ConfigInvalid {
                    reason: format!(
                        "mac.fallback_max_integrity.categories must be hex: {e}"
                    ),
                })?
            };
            Ok(IntegrityLabel {
                level: r.level,
                categories: cats,
            })
        })
        .transpose()?;
    Ok(MacPolicy {
        cert_integrity,
        fallback_max_integrity,
        warn_on_homedir_label_mismatch: raw.warn_on_homedir_label_mismatch.unwrap_or(true),
        runtime,
    })
}

/// Hard cap on `max_chain_depth` to keep verifier loops bounded.
/// Range: `1..=16`; validator rejects values outside this.
const MAX_CHAIN_DEPTH_HARD_CAP: u32 = 16;

/// Default for `max_usb_partitions` when the operator did not set it.
const DEFAULT_MAX_USB_PARTITIONS: u32 = 8;
/// Hard cap on `max_usb_partitions`.
const MAX_USB_PARTITIONS_HARD_CAP: u32 = 64;

/// Validate the (optional) `max_usb_partitions` field.
fn validate_max_usb_partitions(raw: Option<u32>) -> Result<u32, Error> {
    let v = raw.unwrap_or(DEFAULT_MAX_USB_PARTITIONS);
    if v == 0 {
        return Err(Error::ConfigInvalid {
            reason: "max_usb_partitions must be >= 1".into(),
        });
    }
    if v > MAX_USB_PARTITIONS_HARD_CAP {
        return Err(Error::ConfigInvalid {
            reason: format!(
                "max_usb_partitions must be <= {MAX_USB_PARTITIONS_HARD_CAP} (got {v})"
            ),
        });
    }
    Ok(v)
}

/// Validate the (optional) `pkcs12_path_pattern` field.
///
/// Semantics: a relative path under the USB mountpoint where the
/// PKCS#12 file lives. Must not be empty, must not start with `/`,
/// and must not contain `..` or `.` segments (path-traversal guard).
/// `${user}` is the only placeholder honoured at discovery time and
/// is treated opaquely here (it does not introduce `/` segments by
/// itself; user names that contain `/` are rejected upstream by the
/// PAM user regex).
fn validate_pkcs12_path_pattern(raw: Option<&str>) -> Result<Option<String>, Error> {
    let Some(value) = raw else {
        return Ok(None);
    };
    if value.is_empty() {
        return Err(Error::ConfigInvalid {
            reason: "pkcs12_path_pattern must be non-empty when set".to_owned(),
        });
    }
    if value.starts_with('/') {
        return Err(Error::ConfigInvalid {
            reason: format!(
                "pkcs12_path_pattern must be a relative path under the USB mountpoint (got {value:?})"
            ),
        });
    }
    for segment in value.split('/') {
        if segment == ".." || segment == "." {
            return Err(Error::ConfigInvalid {
                reason: format!(
                    "pkcs12_path_pattern must not contain '..' or '.' segments (got {value:?})"
                ),
            });
        }
    }
    Ok(Some(value.to_owned()))
}

/// Safe-by-default signature algorithms applied when
/// `trust.allowed_signature_algorithms` is omitted or empty.
///
/// Entries are the OpenSSL display forms compared by `pre_validate_end_entity`
/// (exact, case-sensitive equality). The list intentionally excludes SHA-1 and
/// every other deprecated algorithm: an unconfigured deployment must still
/// reject weak signatures rather than fall through to "accept anything".
/// GOST is excluded so an unconfigured deployment does not pull in the
/// gost-engine (`needs_gost` stays `false`); operators that need GOST must opt
/// in explicitly.
const DEFAULT_SIGNATURE_ALGORITHMS: &[&str] = &[
    "sha256WithRSAEncryption",
    "sha384WithRSAEncryption",
    "sha512WithRSAEncryption",
    "ecdsa-with-SHA256",
    "ecdsa-with-SHA384",
    "ecdsa-with-SHA512",
];

fn validate_trust(raw: &RawTrust) -> Result<TrustSection, Error> {
    if raw.max_chain_depth == 0 {
        return Err(TrustError::MaxChainDepthZero.into());
    }
    if raw.max_chain_depth > MAX_CHAIN_DEPTH_HARD_CAP {
        return Err(Error::ConfigInvalid {
            reason: format!(
                "trust.max_chain_depth {} exceeds hard cap {MAX_CHAIN_DEPTH_HARD_CAP}",
                raw.max_chain_depth
            ),
        });
    }
    if raw.clock_skew_seconds > 600 {
        return Err(TrustError::ClockSkewTooLarge.into());
    }
    for path in raw.anchors.iter().chain(raw.intermediates.iter()) {
        validate_pem(path)?;
    }
    if matches!(raw.revocation.mode, RawRevocationMode::Crl) {
        for path in &raw.revocation.crl_paths {
            if !path.is_file() {
                return Err(TrustError::CrlPathMissing { path: path.clone() }.into());
            }
        }
    }
    if matches!(
        raw.revocation.mode,
        RawRevocationMode::Ocsp | RawRevocationMode::CrlThenOcsp
    ) && !raw
        .revocation
        .ocsp_responder_url
        .as_deref()
        .is_some_and(|url| url.starts_with("http://") || url.starts_with("https://"))
    {
        return Err(TrustError::OcspResponderInvalid {
            reason: "missing or non-http URL".to_string(),
        }
        .into());
    }
    if raw.pinning.enabled {
        for entry in &raw.pinning.allowed_root_spki_sha256 {
            if entry.len() != 64 || !entry.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(TrustError::PinningHashInvalid {
                    entry: entry.clone(),
                }
                .into());
            }
        }
    }
    Ok(TrustSection {
        anchors: raw.anchors.clone(),
        intermediates: raw.intermediates.clone(),
        revocation: RevocationSection {
            mode: match raw.revocation.mode {
                RawRevocationMode::None => RevocationMode::None,
                RawRevocationMode::Crl => RevocationMode::Crl,
                RawRevocationMode::Ocsp => RevocationMode::Ocsp,
                RawRevocationMode::CrlThenOcsp => RevocationMode::CrlThenOcsp,
            },
            crl_paths: raw.revocation.crl_paths.clone(),
        },
        allowed_signature_algorithms: if raw.allowed_signature_algorithms.is_empty() {
            DEFAULT_SIGNATURE_ALGORITHMS
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            raw.allowed_signature_algorithms.iter().cloned().collect()
        },
        pinning: PinningSection {
            enabled: raw.pinning.enabled,
            // Hex strings have already been validated above when
            // `pinning.enabled = true`.  We still copy the raw values
            // through unchanged so the di layer can decode them at
            // wiring time without revalidating.
            allowed_root_spki_sha256: raw.pinning.allowed_root_spki_sha256.clone(),
        },
        max_chain_depth: raw.max_chain_depth,
        clock_skew_seconds: raw.clock_skew_seconds,
    })
}

fn validate_pem(path: &PathBuf) -> Result<(), Error> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| TrustError::AnchorMissing { path: path.clone() })?;
    if !text.contains("-----BEGIN CERTIFICATE-----") {
        return Err(TrustError::AnchorNotPem { path: path.clone() }.into());
    }
    Ok(())
}

fn validate_trust_override(raw: &RawTrustOverride) -> Result<TrustOverride, Error> {
    if raw.when_host_id_in.is_empty() {
        return Err(Error::ConfigInvalid {
            reason: "trust_override.when_host_id_in must be non-empty".to_string(),
        });
    }
    for path in raw.anchors.iter().chain(raw.intermediates.iter()) {
        validate_pem(path)?;
    }
    Ok(TrustOverride {
        when_host_id_in: raw.when_host_id_in.iter().cloned().collect(),
        anchors: raw.anchors.clone(),
        intermediates: raw.intermediates.clone(),
    })
}

fn validate_host_identity(raw: &RawHostIdentity) -> Result<HostIdentitySection, Error> {
    let mut seen = BTreeSet::new();
    let mut sources = Vec::with_capacity(raw.sources.len());
    for source in &raw.sources {
        let kind = source.parse()?;
        if !seen.insert(kind) {
            return Err(Error::ConfigInvalid {
                reason: "duplicate host identity source".to_string(),
            });
        }
        sources.push(kind);
    }
    if sources.is_empty() {
        return Err(Error::ConfigInvalid {
            reason: "host_identity.sources must be non-empty".to_string(),
        });
    }
    if let Some(cmd) = raw.custom_command.as_ref() {
        if !cmd.is_absolute() {
            return Err(Error::ConfigInvalid {
                reason: format!(
                    "host_identity.custom_command must be an absolute path (got {})",
                    cmd.display()
                ),
            });
        }
    }
    Ok(HostIdentitySection {
        sources,
        fallback: match raw.fallback {
            RawHostIdFallback::Deny => HostIdFallback::Deny,
            RawHostIdFallback::Warn => HostIdFallback::Warn,
            RawHostIdFallback::Allow => HostIdFallback::Allow,
        },
        override_value: raw.override_value.clone(),
        custom_command: raw.custom_command.clone(),
        custom_command_timeout: Duration::from_secs(
            raw.custom_command_timeout_seconds.clamp(1, 30),
        ),
    })
}

fn validate_user_mappings(raw: &[RawUserMapping]) -> Result<Vec<UserMapping>, Error> {
    let re = regex::Regex::new(r"^[a-z_][a-z0-9_-]{0,31}$").map_err(|source| Error::Other {
        reason: source.to_string(),
    })?;
    let mut seen = BTreeSet::new();
    raw.iter()
        .map(|mapping| {
            if !re.is_match(&mapping.pam_user) || !seen.insert(mapping.pam_user.clone()) {
                return Err(Error::ConfigInvalid {
                    reason: "invalid or duplicate pam_user".to_string(),
                });
            }
            let mut criteria = BTreeMap::new();
            if let Some(v) = &mapping.cert_subject_cn {
                criteria.insert("cn", v.clone());
            }
            if let Some(v) = &mapping.cert_san_email {
                criteria.insert("email", v.clone());
            }
            if let Some(v) = &mapping.cert_san_upn {
                criteria.insert("upn", v.clone());
            }
            if criteria.len() != 1 {
                return Err(Error::ConfigInvalid {
                    reason: "user_mapping must set exactly one criterion".to_string(),
                });
            }
            let criteria = if let Some(v) = criteria.remove("cn") {
                UserMatchCriteria::SubjectCn(v)
            } else if let Some(v) = criteria.remove("email") {
                UserMatchCriteria::SanEmail(v)
            } else {
                UserMatchCriteria::SanUpn(criteria.remove("upn").unwrap_or_default())
            };
            Ok(UserMapping {
                pam_user: mapping.pam_user.clone(),
                criteria,
            })
        })
        .collect()
}

/// Maximum byte length of any `CKA_LABEL`-style filter accepted by the
/// validator.  PKCS#11 itself accepts up to 32 bytes for `CKA_LABEL`,
/// but we allow 64 here so operators can use Cyrillic strings (each
/// glyph is 2 UTF-8 bytes) without hitting the limit prematurely.
const PKCS11_LABEL_MAX_LEN: usize = 64;
/// Maximum length of the user-facing PIN prompt string.
const PKCS11_PROMPT_MAX_LEN: usize = 128;
/// Inclusive bounds on `pkcs11_max_pin_attempts`.
const PKCS11_MAX_PIN_ATTEMPTS_RANGE: std::ops::RangeInclusive<u32> = 1..=5;
/// Inclusive bounds on `pkcs11_slot_wait_seconds`.  A 0 disables the
/// wait entirely; > 60 s is rejected to avoid surprising deadlocks
/// inside the PAM stack.
const PKCS11_SLOT_WAIT_RANGE: std::ops::RangeInclusive<u32> = 0..=60;

fn validate_pkcs11_label(field: &str, value: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::ConfigInvalid {
            reason: format!("{field} must be non-empty when set"),
        });
    }
    if value.len() > PKCS11_LABEL_MAX_LEN {
        return Err(Error::ConfigInvalid {
            reason: format!(
                "{field} must be at most {PKCS11_LABEL_MAX_LEN} bytes (got {})",
                value.len()
            ),
        });
    }
    if value.contains('\0') {
        return Err(Error::ConfigInvalid {
            reason: format!("{field} must not contain NUL bytes"),
        });
    }
    Ok(())
}

fn validate_pkcs11_section(raw: &RawConfig, mode: Mode) -> Result<(), Error> {
    if matches!(mode, Mode::Pkcs11) && raw.pkcs11_module.is_none() {
        return Err(Error::ConfigInvalid {
            reason: "pkcs11_module is required when mode = \"pkcs11\"".to_owned(),
        });
    }
    if let Some(label) = raw.pkcs11_token_label.as_deref() {
        validate_pkcs11_label("pkcs11_token_label", label)?;
    }
    if let Some(label) = raw.pkcs11_object_label.as_deref() {
        validate_pkcs11_label("pkcs11_object_label", label)?;
    }
    if !PKCS11_MAX_PIN_ATTEMPTS_RANGE.contains(&raw.pkcs11_max_pin_attempts) {
        return Err(Error::ConfigInvalid {
            reason: format!(
                "pkcs11_max_pin_attempts must be in {:?}, got {}",
                PKCS11_MAX_PIN_ATTEMPTS_RANGE, raw.pkcs11_max_pin_attempts
            ),
        });
    }
    if !PKCS11_SLOT_WAIT_RANGE.contains(&raw.pkcs11_slot_wait_seconds) {
        return Err(Error::ConfigInvalid {
            reason: format!(
                "pkcs11_slot_wait_seconds must be in {:?}, got {}",
                PKCS11_SLOT_WAIT_RANGE, raw.pkcs11_slot_wait_seconds
            ),
        });
    }
    if let Some(prompt) = raw.pkcs11_pin_prompt.as_deref() {
        if prompt.is_empty() {
            return Err(Error::ConfigInvalid {
                reason: "pkcs11_pin_prompt must be non-empty when set".to_owned(),
            });
        }
        if prompt.len() > PKCS11_PROMPT_MAX_LEN {
            return Err(Error::ConfigInvalid {
                reason: format!(
                    "pkcs11_pin_prompt must be at most {PKCS11_PROMPT_MAX_LEN} bytes (got {})",
                    prompt.len()
                ),
            });
        }
    }
    Ok(())
}

/// Default monitord socket path when `[monitor].socket_path` is unset.
const DEFAULT_MONITORD_SOCKET: &str = "/run/tessera/monitord.sock";
/// Default monitord state-file path when `[monitor].state_file_path` is unset.
const DEFAULT_MONITORD_STATE_FILE: &str = "/run/tessera/sessions.json";
/// Default per-RPC timeout in milliseconds.
const DEFAULT_MONITORD_TIMEOUT_MS: u64 = 2000;
/// Lower bound on `timeout_ms` (100 ms).
const MONITORD_TIMEOUT_MS_MIN: u64 = 100;
/// Upper bound on `timeout_ms` (60 s).
const MONITORD_TIMEOUT_MS_MAX: u64 = 60_000;
/// Default per-connection idle timeout (seconds).
const DEFAULT_MONITORD_IDLE_TIMEOUT_SECS: u64 = 30;
/// Lower bound on idle-timeout (seconds).
const MONITORD_IDLE_TIMEOUT_MIN: u64 = 1;
/// Upper bound on idle-timeout (seconds).
const MONITORD_IDLE_TIMEOUT_MAX: u64 = 3600;
/// Default max concurrent connections.
const DEFAULT_MONITORD_MAX_CONNS: u32 = 64;
/// Hard cap on max concurrent connections.
const MONITORD_MAX_CONNS_CAP: u32 = 4096;
/// Hard cap on USB-removed grace window (seconds).
const MONITORD_USB_REMOVED_GRACE_MAX: u64 = 600;
/// Hard cap on suspend grace window (seconds).
const MONITORD_SUSPEND_GRACE_MAX: u64 = 600;

#[allow(clippy::too_many_lines)]
fn validate_monitor(
    raw_top: &RawConfig,
    raw: &RawMonitor,
    legacy_fail_mode: RawMonitorFailMode,
) -> Result<MonitorSection, Error> {
    let socket_path = raw
        .socket_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_MONITORD_SOCKET));
    if !socket_path.is_absolute() {
        return Err(Error::ConfigInvalid {
            reason: format!(
                "monitor.socket_path must be absolute (got {})",
                socket_path.display()
            ),
        });
    }
    let state_file_path = raw
        .state_file_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_MONITORD_STATE_FILE));
    if !state_file_path.is_absolute() {
        return Err(Error::ConfigInvalid {
            reason: format!(
                "monitor.state_file_path must be absolute (got {})",
                state_file_path.display()
            ),
        });
    }
    let timeout_ms = raw.timeout_ms.unwrap_or(DEFAULT_MONITORD_TIMEOUT_MS);
    if !(MONITORD_TIMEOUT_MS_MIN..=MONITORD_TIMEOUT_MS_MAX).contains(&timeout_ms) {
        return Err(Error::ConfigInvalid {
            reason: format!(
                "monitor.timeout_ms must be in {MONITORD_TIMEOUT_MS_MIN}..={MONITORD_TIMEOUT_MS_MAX} (got {timeout_ms})"
            ),
        });
    }
    let fail_mode = match raw.fail_mode.as_deref() {
        None => match legacy_fail_mode {
            RawMonitorFailMode::Strict => MonitorFailMode::Strict,
            RawMonitorFailMode::Permissive => MonitorFailMode::Permissive,
        },
        Some(s) => match s {
            "strict" => MonitorFailMode::Strict,
            "permissive" | "degraded" => MonitorFailMode::Permissive,
            other => {
                return Err(Error::ConfigInvalid {
                    reason: format!(
                        "monitor.fail_mode must be one of \"strict\", \"permissive\", \"degraded\" (got {other:?})"
                    ),
                });
            }
        },
    };

    // The `[monitor]` section's removal-policy fields fall back to the
    // top-level fields when unset, which keeps existing operator config
    // working unchanged. Operators upgrading to per-section knobs may
    // override either independently.
    let raw_action = raw.on_usb_removed.unwrap_or(raw_top.on_usb_removed);
    let on_usb_removed = match raw_action {
        RawOnUsbRemoved::Lock => OnUsbRemoved::Lock,
        RawOnUsbRemoved::Logout => OnUsbRemoved::Logout,
        RawOnUsbRemoved::Hook => OnUsbRemoved::Hook,
        RawOnUsbRemoved::Shutdown => OnUsbRemoved::Shutdown,
    };
    let on_usb_removed_hook_path = if matches!(on_usb_removed, OnUsbRemoved::Hook) {
        let path = raw
            .on_usb_removed_hook_path
            .clone()
            .ok_or_else(|| Error::ConfigInvalid {
                reason:
                    "monitor.on_usb_removed = \"hook\" requires monitor.on_usb_removed_hook_path"
                        .to_string(),
            })?;
        if !path.is_absolute() {
            return Err(Error::ConfigInvalid {
                reason: format!(
                    "monitor.on_usb_removed_hook_path must be absolute (got {})",
                    path.display()
                ),
            });
        }
        Some(path)
    } else {
        // Reject the field if it is set in a non-hook mode — it would
        // be silently ignored at runtime, which is a footgun.
        if raw.on_usb_removed_hook_path.is_some() {
            return Err(Error::ConfigInvalid {
                reason:
                    "monitor.on_usb_removed_hook_path is only valid when on_usb_removed = \"hook\""
                        .to_string(),
            });
        }
        None
    };

    let usb_removed_grace_seconds = raw
        .usb_removed_grace_seconds
        .unwrap_or(raw_top.usb_removed_grace_seconds);
    if usb_removed_grace_seconds > MONITORD_USB_REMOVED_GRACE_MAX {
        return Err(Error::ConfigInvalid {
            reason: format!(
                "monitor.usb_removed_grace_seconds must be <= {MONITORD_USB_REMOVED_GRACE_MAX} (got {usb_removed_grace_seconds})"
            ),
        });
    }
    let suspend_grace_seconds = raw
        .suspend_grace_seconds
        .unwrap_or(raw_top.suspend_grace_seconds);
    if suspend_grace_seconds > MONITORD_SUSPEND_GRACE_MAX {
        return Err(Error::ConfigInvalid {
            reason: format!(
                "monitor.suspend_grace_seconds must be <= {MONITORD_SUSPEND_GRACE_MAX} (got {suspend_grace_seconds})"
            ),
        });
    }

    let idle_timeout_seconds = raw
        .idle_timeout_seconds
        .unwrap_or(DEFAULT_MONITORD_IDLE_TIMEOUT_SECS);
    if !(MONITORD_IDLE_TIMEOUT_MIN..=MONITORD_IDLE_TIMEOUT_MAX).contains(&idle_timeout_seconds) {
        return Err(Error::ConfigInvalid {
            reason: format!(
                "monitor.idle_timeout_seconds must be in {MONITORD_IDLE_TIMEOUT_MIN}..={MONITORD_IDLE_TIMEOUT_MAX} (got {idle_timeout_seconds})"
            ),
        });
    }
    let max_concurrent_connections = raw
        .max_concurrent_connections
        .unwrap_or(DEFAULT_MONITORD_MAX_CONNS);
    if max_concurrent_connections == 0 || max_concurrent_connections > MONITORD_MAX_CONNS_CAP {
        return Err(Error::ConfigInvalid {
            reason: format!(
                "monitor.max_concurrent_connections must be in 1..={MONITORD_MAX_CONNS_CAP} (got {max_concurrent_connections})"
            ),
        });
    }

    Ok(MonitorSection {
        socket_path,
        timeout: Duration::from_millis(timeout_ms),
        fail_mode,
        state_file_path,
        on_usb_removed,
        usb_removed_grace: Duration::from_secs(usb_removed_grace_seconds),
        suspend_grace: Duration::from_secs(suspend_grace_seconds),
        on_usb_removed_hook_path,
        idle_timeout: Duration::from_secs(idle_timeout_seconds),
        max_concurrent_connections,
    })
}

fn validate_gost_engine_path(
    raw: &RawConfig,
    crypto_backend: CryptoBackend,
) -> Result<Option<PathBuf>, Error> {
    let Some(path) = raw.gost_engine_path.as_ref() else {
        return Ok(None);
    };
    if !matches!(crypto_backend, CryptoBackend::Openssl) {
        return Err(Error::GostEnginePathRequiresOpenssl);
    }
    let metadata = std::fs::metadata(path).map_err(|source| Error::GostEnginePathUnreadable {
        path: path.clone(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(Error::GostEnginePathUnreadable {
            path: path.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "gost_engine_path is not a regular file",
            ),
        });
    }
    Ok(Some(path.clone()))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn pkcs12_pattern_accepts_relative_paths() {
        assert_eq!(
            validate_pkcs12_path_pattern(Some("certs/user.p12")).unwrap(),
            Some("certs/user.p12".to_owned())
        );
        assert_eq!(
            validate_pkcs12_path_pattern(Some("service.p12")).unwrap(),
            Some("service.p12".to_owned())
        );
        assert_eq!(
            validate_pkcs12_path_pattern(Some("${user}.p12")).unwrap(),
            Some("${user}.p12".to_owned())
        );
    }

    #[test]
    fn pkcs12_pattern_unset_is_none() {
        assert_eq!(validate_pkcs12_path_pattern(None).unwrap(), None);
    }

    #[test]
    fn pkcs12_pattern_rejects_empty() {
        let err = validate_pkcs12_path_pattern(Some("")).unwrap_err();
        match err {
            Error::ConfigInvalid { reason } => assert!(reason.contains("non-empty")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn pkcs12_pattern_rejects_absolute_path() {
        let err = validate_pkcs12_path_pattern(Some("/run/cert.p12")).unwrap_err();
        match err {
            Error::ConfigInvalid { reason } => assert!(reason.contains("relative")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn pkcs12_pattern_rejects_parent_segment() {
        let err = validate_pkcs12_path_pattern(Some("certs/../etc/cert.p12")).unwrap_err();
        match err {
            Error::ConfigInvalid { reason } => assert!(reason.contains("'..'")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn pkcs12_pattern_rejects_dot_segment() {
        let err = validate_pkcs12_path_pattern(Some("./cert.p12")).unwrap_err();
        match err {
            Error::ConfigInvalid { reason } => assert!(reason.contains("'..'")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn fly_dm_greeter_defaults_when_section_absent() {
        let s = validate_fly_dm_greeter(None).expect("ok");
        assert!(!s.update_wallpaper);
        assert_eq!(
            s.wallpaper_target,
            PathBuf::from("/usr/share/wallpapers/fly-default-light.jpg")
        );
        assert_eq!(
            s.wallpaper_backup,
            PathBuf::from("/var/lib/tessera/wallpaper.orig.jpg")
        );
        assert_eq!(s.wallpaper_gravity, Gravity::South);
        assert_eq!(s.wallpaper_font_size, 64);
        assert_eq!(s.wallpaper_text_color, [0, 0, 0, 255]);
        assert_eq!(s.wallpaper_offset_y, 120);
        assert!(s.template_en.contains("{host_id_short}"));
        assert!(s.template_ru.contains("{host_id_short}"));
    }

    #[test]
    fn fly_dm_greeter_partial_section_fills_defaults() {
        let raw = RawFlyDmGreeter {
            update_wallpaper: Some(true),
            wallpaper_target: None,
            wallpaper_backup: None,
            wallpaper_font: None,
            wallpaper_font_size: Some(96),
            wallpaper_text_color: Some("#FFEEDD".to_string()),
            wallpaper_gravity: Some("center".to_string()),
            wallpaper_offset_x: Some(-10),
            wallpaper_offset_y: None,
            template_ru: Some("custom ru {host_id_short}".to_string()),
            template_en: None,
        };
        let s = validate_fly_dm_greeter(Some(&raw)).expect("ok");
        assert!(s.update_wallpaper);
        assert_eq!(s.wallpaper_font_size, 96);
        assert_eq!(s.wallpaper_text_color, [0xFF, 0xEE, 0xDD, 0xFF]);
        assert_eq!(s.wallpaper_gravity, Gravity::Center);
        assert_eq!(s.wallpaper_offset_x, -10);
        assert_eq!(s.wallpaper_offset_y, 120); // default kept
        assert!(s.template_en.contains("{host_id_short}")); // default kept
        assert_eq!(s.template_ru, "custom ru {host_id_short}");
    }

    #[test]
    fn fly_dm_greeter_rejects_relative_wallpaper_target() {
        let raw = RawFlyDmGreeter {
            update_wallpaper: Some(true),
            wallpaper_target: Some("share/wallpapers/foo.jpg".to_string()),
            ..Default::default()
        };
        let err = validate_fly_dm_greeter(Some(&raw)).unwrap_err();
        match err {
            Error::ConfigInvalid { reason } => assert!(reason.contains("absolute")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn fly_dm_greeter_rejects_invalid_hex_color() {
        let raw = RawFlyDmGreeter {
            update_wallpaper: Some(true),
            wallpaper_text_color: Some("not-a-color".to_string()),
            ..Default::default()
        };
        let err = validate_fly_dm_greeter(Some(&raw)).unwrap_err();
        match err {
            Error::ConfigInvalid { reason } => assert!(reason.contains("wallpaper_text_color")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn fly_dm_greeter_accepts_8_digit_hex_color_with_alpha() {
        let raw = RawFlyDmGreeter {
            update_wallpaper: Some(true),
            wallpaper_text_color: Some("#11223344".to_string()),
            ..Default::default()
        };
        let s = validate_fly_dm_greeter(Some(&raw)).expect("ok");
        assert_eq!(s.wallpaper_text_color, [0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn fly_dm_greeter_rejects_unknown_gravity() {
        let raw = RawFlyDmGreeter {
            update_wallpaper: Some(true),
            wallpaper_gravity: Some("upside_down".to_string()),
            ..Default::default()
        };
        let err = validate_fly_dm_greeter(Some(&raw)).unwrap_err();
        match err {
            Error::ConfigInvalid { reason } => assert!(reason.contains("wallpaper_gravity")),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
