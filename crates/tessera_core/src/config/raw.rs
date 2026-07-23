//! Raw serde config.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Raw config.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    /// Crypto backend.
    pub crypto_backend: RawCryptoBackend,
    /// Mode.
    pub mode: RawMode,
    /// PKCS#11 module.
    pub pkcs11_module: Option<PathBuf>,
    /// Optional `CKA_LABEL` filter for the token.
    #[serde(default)]
    pub pkcs11_token_label: Option<String>,
    /// Optional `CKA_LABEL` filter for the on-token certificate /
    /// private-key object.  When `None`, the first end-entity cert is
    /// used.  Validated to be ≤ 64 chars and contain no NUL bytes.
    #[serde(default)]
    pub pkcs11_object_label: Option<String>,
    /// Maximum number of PIN attempts before bailing.  Defaults to 3.
    #[serde(default = "default_pkcs11_max_pin_attempts")]
    pub pkcs11_max_pin_attempts: u32,
    /// PKCS#11 locking mode.
    #[serde(default)]
    pub pkcs11_locking_mode: RawPkcs11LockingMode,
    /// Prompt string for the token PIN (Russian by default).
    #[serde(default)]
    pub pkcs11_pin_prompt: Option<String>,
    /// Maximum time `wait_for_token` will block waiting for the user
    /// to insert the token, in seconds.  Defaults to 10.
    #[serde(default = "default_pkcs11_slot_wait_seconds")]
    pub pkcs11_slot_wait_seconds: u32,
    /// Accept private keys with `CKA_EXTRACTABLE = TRUE` (WARN instead of
    /// refusing).  Defaults to `false`: an extractable key breaks the
    /// mode-B invariant, so authentication fails closed unless the
    /// operator explicitly opts in.
    #[serde(default)]
    pub pkcs11_allow_extractable_keys: bool,
    /// PKCS#12 path pattern.
    pub pkcs12_path_pattern: Option<String>,
    /// PIN prompt.
    pub pkcs12_pin_prompt: Option<String>,
    /// Optional path to the gost-engine `.so` file.
    ///
    /// Configuration validation requires this to be set whenever the OpenSSL
    /// backend allows GOST signatures, preventing inherited engine search
    /// paths from selecting native code. When set, it must point to a readable
    /// file (validated in [`crate::config::ValidatedConfig`]).
    #[serde(default)]
    pub gost_engine_path: Option<PathBuf>,
    /// USB wait seconds.
    #[serde(default = "default_usb_wait_seconds")]
    pub usb_wait_seconds: u64,
    /// Allow-list of USB devices accepted as the PKCS#12 medium, as
    /// `"vid:pid"` hex strings in lsusb format (four hex digits each,
    /// e.g. `["0951:1666"]`).  Empty or absent = no filter: any USB
    /// block device is considered.  Validated in
    /// [`crate::config::ValidatedConfig`].
    #[serde(default)]
    pub usb_allowed_devices: Vec<String>,
    /// Maximum number of USB partitions inspected at auth time when a
    /// whole-disk has a partition table.  Defaults to 8.  Validated
    /// against the inclusive range `1..=64`.
    #[serde(default)]
    pub max_usb_partitions: Option<u32>,
    /// USB removal action.
    #[serde(default)]
    pub on_usb_removed: RawOnUsbRemoved,
    /// USB removed grace.
    #[serde(default)]
    pub usb_removed_grace_seconds: u64,
    /// Suspend grace.
    #[serde(default)]
    pub suspend_grace_seconds: u64,
    /// Monitor failure mode (top-level, deprecated in favour of `[monitor].fail_mode`
    /// but still honoured for backwards compatibility when the new section is
    /// absent).
    #[serde(default)]
    pub monitor_fail_mode: RawMonitorFailMode,
    /// Monitor IPC section (socket path, timeout, fail mode). Optional —
    /// when absent, the validated config falls back to defaults plus the
    /// top-level `monitor_fail_mode`.
    #[serde(default)]
    pub monitor: RawMonitor,
    /// Trust.
    pub trust: RawTrust,
    /// Trust overrides.
    #[serde(default)]
    pub trust_override: Vec<RawTrustOverride>,
    /// Host identity.
    pub host_identity: RawHostIdentity,
    /// User mappings.
    #[serde(default)]
    pub user_mapping: Vec<RawUserMapping>,
    /// Logging.
    pub logging: RawLogging,
    /// Hooks.
    #[serde(default)]
    pub hooks: Vec<RawHook>,
    /// MAC integrity policy section (spec §2.4 / phase 2). Optional; when
    /// absent the validated layer applies defaults (`cert_integrity` = optional,
    /// no fallback, `warn_on_homedir_label_mismatch` = true).
    #[serde(default)]
    pub mac: RawMacPolicy,
    /// Astra fly-dm greeter banner section. Optional; when absent the
    /// validated layer applies defaults (`update_greet_string = false`,
    /// stock template values).
    #[serde(default)]
    pub fly_dm_greeter: Option<RawFlyDmGreeter>,
    /// Role-format section (`[roles]`). Optional; when absent the validated
    /// layer applies defaults (`enforce = false` — pre-role behaviour,
    /// `dir = /var/lib/tessera/roles`, `default_session_ttl_seconds = 43200`).
    #[serde(default)]
    pub roles: RawRoles,
    /// Device-tags source section (`[tags]`, tags-delegation §5.2). Optional;
    /// when absent the validated layer applies fail-closed defaults — the
    /// device has NO tags (an empty set), so any group-delegation `requireTags`
    /// envelope in the chain is unsatisfiable and rejects. Per-host logins
    /// without a delegation envelope are unaffected.
    #[serde(default)]
    pub tags: RawTags,
}

/// Trust mode for the device-tags source (`[tags].mode`).
///
/// Mirrors the role-store trust split (`[roles]` standalone/managed): in
/// `managed` mode the tags ride in the SAME signed `manifest.toml` under the
/// SAME `bundle_version` anti-rollback floor as the role base; in `standalone`
/// mode a local file is trusted by filesystem permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RawTagsMode {
    /// Local file trusted by filesystem permissions (default — parity with
    /// the standalone role-store).
    #[default]
    Standalone,
    /// Tags ride in the signed `role-store` manifest (shared anti-rollback).
    Managed,
}

/// Raw `[tags]` block (tags-delegation §5.2).
///
/// All fields are optional with fail-closed defaults; `deny_unknown_fields`
/// rejects typos at parse time. When the whole section is absent the validated
/// layer treats the device as having NO tags (empty set), which is the
/// fail-closed default the configuration spec mandates ("отсутствие источника
/// тегов = «тегов нет»").
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTags {
    /// Whether to load and apply device tags from [`Self::source`]. Default
    /// `false` (pre-delegation behaviour): the device has no applied tags.
    /// Group-delegation envelopes in a chain still reject a no-tags device
    /// (fail-closed) regardless of this flag — it only governs whether a
    /// configured source is read.
    #[serde(default)]
    pub enforce: bool,
    /// Trust mode of the source. Default `standalone`.
    #[serde(default)]
    pub mode: RawTagsMode,
    /// Source path: in `standalone` mode the tags file; in `managed` mode the
    /// directory holding the signed `manifest.toml`. When absent the validated
    /// layer applies the standalone default (`/var/lib/tessera/tags.toml`); in
    /// `managed` mode the role-store directory is used.
    #[serde(default)]
    pub source: Option<PathBuf>,
}

/// Migration / enforcement mode for the `[roles]` section.
///
/// Three-stage rollout (design Migration Plan): `false` — roles are not
/// checked (v0.3.19 behaviour); `warn` — resolve + coverage are checked and
/// logged but never deny; `require` — full enforcement (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RawRolesEnforce {
    /// Roles not checked — pre-role behaviour (default for this stage).
    #[default]
    False,
    /// Checked + logged, never denies.
    Warn,
    /// Full enforcement; fail-closed.
    Require,
}

/// Raw `[roles]` block.
///
/// All fields are optional with defaults; `deny_unknown_fields` so unknown
/// keys are rejected at parse time (design Decision 9). The duration field
/// follows the codebase `*_seconds: u64` convention rather than a humantime
/// literal.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRoles {
    /// Enforcement mode. Default `false`.
    #[serde(default)]
    pub enforce: RawRolesEnforce,
    /// On-device role-store directory. Default `/var/lib/tessera/roles`.
    #[serde(default)]
    pub dir: Option<PathBuf>,
    /// Global default session TTL (seconds), used when neither the
    /// certificate nor the role sets one. Default 43200 (12h).
    #[serde(default)]
    pub default_session_ttl_seconds: Option<u64>,
}

/// Raw `[fly_dm_greeter]` block: Astra fly-dm login-screen wallpaper
/// banner integration.
///
/// On Astra МКЦ-3 (production terminal) the `fly-modern` greeter theme
/// hard-codes "Усиленный уровень защищенности" into the headline place
/// from `fly-dm_greet_modern.mo`; the `GreetString` xdmcp setting is
/// ignored. The only reliable surface for showing `host_id` to the
/// operator is the JPG/PNG file referenced by
/// `/etc/X11/fly-dm/fly-modern/settings.ini` `[background].path`.
///
/// When `update_wallpaper = true`, on each daemon start `tessera`:
///   1. If `wallpaper_backup` does not exist yet, copies `wallpaper_target`
///      → `wallpaper_backup` (one-time, preserves the stock image).
///   2. Opens the backup image as the source.
///   3. Renders a text overlay using the appropriate locale template.
///   4. Atomically writes the result to `wallpaper_target`.
///
/// `tessera` never edits `settings.ini` — that file is managed by
/// the operator / ansible (blur, color-overlay alpha, custom path).
///
/// Templates support the placeholders `{host_id_short}` (8-char hex
/// prefix of the SHA-256 `host_id`), `{source}` (`snake_case` source
/// kind such as `dmi_board_serial`), and `%n` which is substituted with
/// the local hostname at render time.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawFlyDmGreeter {
    /// When true, the daemon (on start) bakes the resolved `host_id`
    /// banner into the fly-dm background wallpaper; when false (default),
    /// the file is left untouched.
    #[serde(default)]
    pub update_wallpaper: Option<bool>,
    /// Absolute path to the wallpaper file written by the daemon (the
    /// same path that `settings.ini` `[background].path` references).
    /// Default `/usr/share/wallpapers/fly-default-light.jpg`.
    #[serde(default)]
    pub wallpaper_target: Option<String>,
    /// Absolute path to the preserved original wallpaper. The daemon
    /// copies `wallpaper_target` → `wallpaper_backup` exactly once,
    /// then always re-renders from the backup. Kept outside
    /// `/usr/share/wallpapers/` so an apt upgrade of `fly-qdm` cannot
    /// trample it. Default `/var/lib/tessera/daemon/wallpaper.orig.jpg`.
    #[serde(default)]
    pub wallpaper_backup: Option<String>,
    /// Absolute path to a TrueType font file used to render the banner.
    /// Default `/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf`.
    #[serde(default)]
    pub wallpaper_font: Option<String>,
    /// Font size in pixels. Default 64.
    #[serde(default)]
    pub wallpaper_font_size: Option<u32>,
    /// Text colour as `#RRGGBB` or `#RRGGBBAA`. Default `#000000`.
    #[serde(default)]
    pub wallpaper_text_color: Option<String>,
    /// Anchor for the text on the image: `north`, `south`, `east`,
    /// `west`, or `center`. Default `south`.
    #[serde(default)]
    pub wallpaper_gravity: Option<String>,
    /// Horizontal pixel offset added to the gravity anchor. Default 0.
    #[serde(default)]
    pub wallpaper_offset_x: Option<i32>,
    /// Vertical pixel offset added to the gravity anchor; for `south`
    /// gravity this is interpreted upward (ImageMagick-like). Default 120.
    #[serde(default)]
    pub wallpaper_offset_y: Option<i32>,
    /// Russian-locale template.
    #[serde(default)]
    pub template_ru: Option<String>,
    /// Non-Russian (default / English) template.
    #[serde(default)]
    pub template_en: Option<String>,
}

const fn default_usb_wait_seconds() -> u64 {
    10
}

const fn default_pkcs11_max_pin_attempts() -> u32 {
    3
}

const fn default_pkcs11_slot_wait_seconds() -> u32 {
    10
}

/// PKCS#11 locking mode (raw).  Mirrors
/// [`crate::token::pkcs11::LockingMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RawPkcs11LockingMode {
    /// Native OS thread locking (`CKF_OS_LOCKING_OK`).  Default.
    #[default]
    Os,
    /// User-space mutex serialization.
    Mutex,
}

/// Raw crypto backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawCryptoBackend {
    /// OpenSSL.
    Openssl,
    /// Native PKCS#11.
    Pkcs11Native,
}

/// Raw mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawMode {
    /// PKCS#12.
    Pkcs12,
    /// PKCS#11.
    Pkcs11,
}

/// Raw removal action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RawOnUsbRemoved {
    /// Lock.
    #[default]
    Lock,
    /// Logout.
    Logout,
    /// Hook.
    Hook,
    /// Shutdown.
    Shutdown,
}

/// Raw monitor fail mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RawMonitorFailMode {
    /// Strict.
    #[default]
    Strict,
    /// Permissive.
    Permissive,
}

/// Raw `[monitor]` section. All fields are optional so an empty section
/// (or no section at all) yields validator defaults.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMonitor {
    /// Path to the monitord Unix socket. Default
    /// `/run/tessera/monitord.sock`.
    #[serde(default)]
    pub socket_path: Option<PathBuf>,
    /// Per-RPC connect+IO timeout in milliseconds. Default 2000.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Per-section fail mode override. When `None`, the validated config
    /// falls back to the top-level `monitor_fail_mode`.
    #[serde(default)]
    pub fail_mode: Option<String>,
    /// Path to the session-registry JSON. Default
    /// `/run/tessera/sessions.json` (tmpfs, volatile across reboot).
    /// The registry only needs to survive daemon restarts within a boot —
    /// all userspace processes holding these sessions die on reboot, so
    /// persisting across boots would only leave stale entries. Read by
    /// `tessera`.
    #[serde(default)]
    pub state_file_path: Option<PathBuf>,
    /// Action to take when the bound USB token is removed past the
    /// configured grace window. Default `lock`. Mirrors
    /// [`RawOnUsbRemoved`].
    #[serde(default)]
    pub on_usb_removed: Option<RawOnUsbRemoved>,
    /// Grace window between USB removal event and the configured action.
    /// Default 5 s.
    #[serde(default)]
    pub usb_removed_grace_seconds: Option<u64>,
    /// Suspend-grace window: removals within this many seconds after a
    /// resume are ignored. Default 30 s.
    #[serde(default)]
    pub suspend_grace_seconds: Option<u64>,
    /// Absolute path to the hook executable invoked when
    /// `on_usb_removed = "hook"`. Required only in `hook` mode.
    #[serde(default)]
    pub on_usb_removed_hook_path: Option<PathBuf>,
    /// Per-connection idle timeout in seconds (server-side IPC). Default 30.
    #[serde(default)]
    pub idle_timeout_seconds: Option<u64>,
    /// Maximum number of concurrent client connections accepted by the
    /// monitord IPC server. Default 64.
    #[serde(default)]
    pub max_concurrent_connections: Option<u32>,
}

/// Trust section.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTrust {
    /// Anchors.
    pub anchors: Vec<PathBuf>,
    /// Intermediates.
    #[serde(default)]
    pub intermediates: Vec<PathBuf>,
    /// Max chain depth.
    #[serde(default = "default_max_chain_depth")]
    pub max_chain_depth: u32,
    /// Clock skew.
    #[serde(default)]
    pub clock_skew_seconds: u64,
    /// Signature algorithms.
    #[serde(default)]
    pub allowed_signature_algorithms: Vec<String>,
    /// Revocation. `None` means the operator omitted the whole
    /// `[trust.revocation]` section; the validated layer rejects that so an
    /// operator cannot end up with revocation checking silently disabled.
    /// Opting out is still possible, but only by writing `mode = "none"`.
    #[serde(default)]
    pub revocation: Option<RawRevocation>,
    /// Pinning.
    #[serde(default)]
    pub pinning: RawPinning,
    /// Highest `pam_cert_profile_version` this Engine understands
    /// (tags-delegation §5.2 / trust-chain-validation version-gate). Any chain
    /// cert declaring a higher version rejects the whole chain (fail-closed).
    /// When absent the validated layer applies the compiled
    /// [`crate::trust::openssl_verifier::DEFAULT_MAX_SUPPORTED_PROFILE_VERSION`].
    #[serde(default)]
    pub max_supported_profile_version: Option<u32>,
}

const fn default_max_chain_depth() -> u32 {
    5
}

/// Revocation section.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRevocation {
    /// Mode. `None` means the `mode` key was omitted; the validated layer
    /// rejects that (an absent mode would otherwise disable revocation
    /// checking silently). Opting out requires an explicit `mode = "none"`.
    #[serde(default)]
    pub mode: Option<RawRevocationMode>,
    /// CRL paths.
    #[serde(default)]
    pub crl_paths: Vec<PathBuf>,
    /// OCSP responder URL (`http://` or `https://`).  Required when
    /// `mode` is `ocsp` or `crl_then_ocsp`; rejected during validation in
    /// every other mode (a key that would be silently ignored at runtime
    /// is a footgun).  Validated in [`crate::config::ValidatedConfig`].
    #[serde(default)]
    pub ocsp_responder_url: Option<String>,
    /// CRL max age in hours (1..=8760).  `None` disables the age cap.
    #[serde(default)]
    pub crl_max_age_hours: Option<u64>,
    /// Overall deadline of one OCSP exchange in seconds (1..=30, default
    /// 5).  Only valid when `mode` is `ocsp` or `crl_then_ocsp`.
    #[serde(default)]
    pub ocsp_timeout_seconds: Option<u64>,
    /// OCSP cache-entry TTL in seconds (0..=86400, default 3600; 0
    /// disables the cache).  Only valid when `mode` is `ocsp` or
    /// `crl_then_ocsp`.
    #[serde(default)]
    pub ocsp_cache_ttl_seconds: Option<u64>,
}

/// Raw revocation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawRevocationMode {
    /// None. Revocation checking is disabled; a revoked certificate still
    /// authenticates. Valid only when written explicitly by the operator.
    None,
    /// CRL.
    Crl,
    /// OCSP.
    Ocsp,
    /// CRL then OCSP.
    CrlThenOcsp,
}

/// Pinning section.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPinning {
    /// Enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Allowed root SPKI hashes.
    #[serde(default)]
    pub allowed_root_spki_sha256: Vec<String>,
}

/// Trust override.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTrustOverride {
    /// Host ids.
    pub when_host_id_in: Vec<String>,
    /// Anchors.
    #[serde(default)]
    pub anchors: Vec<PathBuf>,
    /// Intermediates.
    #[serde(default)]
    pub intermediates: Vec<PathBuf>,
}

/// Host identity section.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHostIdentity {
    /// Sources.
    pub sources: Vec<String>,
    /// Fallback.
    #[serde(default)]
    pub fallback: RawHostIdFallback,
    /// Override value.
    #[serde(default, rename = "override")]
    pub override_value: Option<String>,
    /// Custom command.
    #[serde(default)]
    pub custom_command: Option<PathBuf>,
    /// Custom command timeout.
    #[serde(default = "default_custom_command_timeout")]
    pub custom_command_timeout_seconds: u64,
}

const fn default_custom_command_timeout() -> u64 {
    5
}

/// Host id fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RawHostIdFallback {
    /// Deny.
    #[default]
    Deny,
    /// Warn.
    Warn,
    /// Allow.
    Allow,
}

/// User mapping.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawUserMapping {
    /// PAM user.
    pub pam_user: String,
    /// Subject CN.
    #[serde(default)]
    pub cert_subject_cn: Option<String>,
    /// SAN email.
    #[serde(default)]
    pub cert_san_email: Option<String>,
    /// SAN UPN.
    #[serde(default)]
    pub cert_san_upn: Option<String>,
}

/// Logging section.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawLogging {
    /// Level.
    pub level: String,
    /// Facility.  Deprecated: accepted (and still validated against the
    /// supported facility names) for backwards compatibility, but ignored —
    /// the PAM module always logs to the `auth` facility and the daemon
    /// writes to stderr.  Presence triggers a WARN at validation time.
    #[serde(default)]
    pub syslog_facility: Option<String>,
    /// Journald priority.  Deprecated: accepted for backwards compatibility,
    /// but ignored (the daemon's stderr→journald path needs no priority
    /// re-encoding).  Presence triggers a WARN at validation time.
    #[serde(default)]
    pub journald_priority: Option<bool>,
}

/// Hook.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHook {
    /// Stage.
    pub stage: crate::hooks::HookStage,
    /// Command.
    pub command: Vec<String>,
    /// Timeout.
    #[serde(default = "default_hook_timeout")]
    pub timeout_seconds: u64,
    /// Failure mode.
    #[serde(default)]
    pub on_failure: Option<String>,
    /// Run as.
    #[serde(default)]
    pub run_as: Option<String>,
    /// Env templates.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

const fn default_hook_timeout() -> u64 {
    10
}

/// Raw `[mac]` policy block (spec §2.4). All fields optional so existing
/// configs deserialize unchanged; the validated layer applies defaults.
///
/// Uses `deny_unknown_fields` so that legacy keys like `require_mac` or
/// `cert_mac_level` are rejected at parse time (the spec deliberately
/// replaced them with the trinary `cert_integrity` model).
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMacPolicy {
    /// Trinary policy for the X.509 `MAX_INTEGRITY` extension on the
    /// authenticating certificate (`required` | `optional` | `ignore`).
    #[serde(default)]
    pub cert_integrity: Option<RawCertIntegrityMode>,
    /// Fallback upper bound applied when the cert carries no extension and
    /// policy is `optional`. Ignored when `required` (no extension is a
    /// hard failure) or `ignore` (extension is not consulted).
    #[serde(default)]
    pub fallback_max_integrity: Option<RawIntegrityLabel>,
    /// Whether to emit a warning when the resolved process label disagrees
    /// with the user's `$HOME` label at session-open time. Default `true`.
    #[serde(default)]
    pub warn_on_homedir_label_mismatch: Option<bool>,
    /// Runtime selection for the MAC backend (independent of the
    /// compile-time `astra-mac` feature). Default `auto`.
    ///
    /// - `required` — fail authentication if the kernel МКЦ subsystem is
    ///   not present. Requires the binary to be built with the
    ///   `astra-mac` feature.
    /// - `auto` — use the real `ParsecBackend` when the kernel МКЦ
    ///   subsystem is available, otherwise fall back to the no-op
    ///   `StubBackend` (with a `mac_runtime_fallback` audit event).
    /// - `disabled` — always use the no-op `StubBackend`, even when the
    ///   binary was built with the `astra-mac` feature. Used on Astra SE
    ///   hosts where МКЦ is intentionally turned off.
    #[serde(default)]
    pub runtime: Option<RawMacRuntimeMode>,
}

/// Runtime selection for the MAC backend; see [`RawMacPolicy::runtime`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RawMacRuntimeMode {
    /// Real backend required; auth fails if МКЦ ядро отсутствует.
    Required,
    /// Probe at startup; real backend when available, stub otherwise.
    #[default]
    Auto,
    /// Always use the stub backend.
    Disabled,
}

/// Trinary mode for the `[mac].cert_integrity` knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RawCertIntegrityMode {
    /// Extension MUST be present; missing extension fails authentication.
    Required,
    /// Extension is consulted when present; absent extension falls back to
    /// `fallback_max_integrity` (when set) or admin-default.
    Optional,
    /// Extension is not consulted; integrity comes from admin policy only.
    Ignore,
}

/// Raw `[mac.fallback_max_integrity]` block. `level` is an int8 enforced by
/// serde; `categories` is a hex string up to 16 chars (u64) — empty means 0.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawIntegrityLabel {
    /// Linear integrity level in `i8` (-128..=127).
    pub level: i8,
    /// Hex-encoded categories bitmap (up to 16 hex chars = 64 bits). Empty
    /// string is accepted and means "no categories" (0).
    #[serde(default)]
    pub categories: String,
}
