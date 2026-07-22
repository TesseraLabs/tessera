//! Dependency-injection (DI) wiring for the cdylib boundary.
//!
//! The cdylib `pam_sm_authenticate` entry calls [`wire`] once per
//! authentication attempt; this constructs a [`Wired`] bundle holding
//! every collaborator the [`crate::flow::authenticate`] function needs
//! (verifier, ACL signature verifier, monitor IPC client).
//!
//! # OPEN QUESTION (stage-2 acknowledged limitation)
//!
//! Today we re-load anchors / intermediates / CRLs from disk on every
//! authentication.  This is safe (always picks up edits) but inefficient.
//! A later stage will introduce an `OnceLock<Wired>` cache with an explicit
//! reload trigger (config change → `pam_sm_setcred` or signal).

use std::path::PathBuf;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tessera_core::config::validated::TrustOverride;
use tessera_core::config::ValidatedConfig;
use tessera_core::ipc::{ConnectPerCall, FailModeWrapper, MonitorClient, MonitorClientFactory};
use tessera_core::trust::openssl_verifier::{OpensslVerifier, OpensslVerifierConfig};
use tessera_core::x509::pinning::SpkiPin;
use tessera_core::x509::Certificate;

/// Wired collaborators consumed by [`crate::flow::authenticate`].
pub struct Wired {
    /// Validated config (caller continues to own; we reuse a copy).
    pub cfg: ValidatedConfig,
    /// Trust verifier.
    pub trust: OpensslVerifier,
    /// Monitor IPC client. Production path wires `FailModeWrapper<ConnectPerCall>`
    /// so monitord receives real `SessionOpen` / `SessionClose` frames.
    pub monitor: Box<dyn MonitorClient>,
}

/// Errors raised while wiring up dependencies.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// I/O failure reading anchors / intermediates / CRLs.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Trust verifier construction failed.
    #[error("trust: {0}")]
    Trust(#[from] tessera_core::x509::TrustError),
    /// `[trust.pinning] allowed_root_spki_sha256` contains a non-hex or
    /// wrong-length entry that slipped past validation.  Should be
    /// unreachable in practice — present for defensive belt-and-braces.
    #[error("invalid SPKI pin entry: {entry}")]
    PinDecode {
        /// The offending hex string.
        entry: String,
    },
    /// The configured `ocsp_responder_url` could not be parsed.
    #[error("invalid OCSP responder URL: {reason}")]
    OcspUrl {
        /// Why parsing failed.
        reason: String,
    },
    /// More than one `[[trust_override]]` matched the resolved host at wiring
    /// time. Config validation rejects overlapping overrides, so reaching this
    /// means the config changed underneath us; fail closed rather than silently
    /// pick one anchor set and widen (or misdirect) issuance authority.
    #[error("ambiguous trust override: host {host_id_hash_prefix} matched more than one entry")]
    AmbiguousTrustOverride {
        /// First 8 hex chars of the SHA-256 of the normalized host id, logged
        /// in place of the raw host id to avoid leaking identity.
        host_id_hash_prefix: String,
    },
}

/// First 8 hex chars of the SHA-256 of a normalized host id.
///
/// Mirrors the host-id hashing used elsewhere (normalize, then SHA-256) so the
/// prefix logged here lines up with the `host_id_hash_prefix` emitted by host
/// identity resolution, without ever writing the raw host id to the log.
fn host_id_hash_prefix(normalized_host: &str) -> String {
    let digest = Sha256::digest(normalized_host.as_bytes());
    hex::encode(digest).chars().take(8).collect()
}

/// Select the single `[[trust_override]]` applicable to `normalized_host`.
///
/// A host matches an override when its normalized id is a member of the
/// override's `when_host_id_in` set (each candidate normalized the same way).
/// At most one override may match: configuration validation already rejects
/// overlapping entries, but a runtime collision is treated as fail-closed
/// ([`WireError::AmbiguousTrustOverride`]) rather than resolved by guessing.
fn select_trust_override<'a>(
    overrides: &'a [TrustOverride],
    normalized_host: &str,
) -> Result<Option<&'a TrustOverride>, WireError> {
    let mut selected: Option<&TrustOverride> = None;
    for candidate in overrides {
        let matched = candidate
            .when_host_id_in
            .iter()
            .any(|h| tessera_core::host_identity::normalize_host_id(h) == normalized_host);
        if matched {
            if selected.is_some() {
                return Err(WireError::AmbiguousTrustOverride {
                    host_id_hash_prefix: host_id_hash_prefix(normalized_host),
                });
            }
            selected = Some(candidate);
        }
    }
    Ok(selected)
}

/// Decode the validated SPKI pin hex strings into raw 32-byte arrays.
///
/// Each entry has already been verified as a 64-char ASCII-hex string by
/// `validate_trust`; the decode below is therefore expected to succeed.
/// Any failure is surfaced as [`WireError::PinDecode`] rather than a
/// panic so that an unexpected runtime mismatch (e.g. a future config
/// migration that bypasses the validator) cannot crash the PAM stack.
fn decode_spki_pins(hex_entries: &[String]) -> Result<Vec<SpkiPin>, WireError> {
    let mut pins = Vec::with_capacity(hex_entries.len());
    for entry in hex_entries {
        let bytes = hex::decode(entry).map_err(|_| WireError::PinDecode {
            entry: entry.clone(),
        })?;
        let pin: SpkiPin = bytes
            .as_slice()
            .try_into()
            .map_err(|_| WireError::PinDecode {
                entry: entry.clone(),
            })?;
        pins.push(pin);
    }
    Ok(pins)
}

/// Build a [`Wired`] collaborator bundle from a validated config.
///
/// `host_id_raw` is the resolved raw host identity (before hashing). When it
/// matches a `[[trust_override]]` entry, that entry's anchors and intermediates
/// REPLACE the global `[trust]` anchors/intermediates for this host, narrowing
/// (or retargeting) which CAs the device will accept. Every other trust
/// parameter — revocation, pinning, signature allow-list, depth, clock skew —
/// stays taken from the global `[trust]` section.
///
/// # Errors
///
/// Returns [`WireError::Io`] when any configured PEM/CRL path is unreadable,
/// [`WireError::Trust`] for verifier construction failures (e.g.
/// `max_chain_depth == 0`), and [`WireError::AmbiguousTrustOverride`] when the
/// host matches more than one override (fail-closed).
pub fn wire(cfg: ValidatedConfig, host_id_raw: &str) -> Result<Wired, WireError> {
    // Resolve the applicable per-host trust override BEFORE constructing the
    // verifier: an override replaces the anchor/intermediate set for this host,
    // so a globally-trusted-but-excluded CA is rejected here rather than
    // silently accepted. Matching normalizes the host id the same way the
    // host-id hash is derived.
    let normalized_host = tessera_core::host_identity::normalize_host_id(host_id_raw);
    let selected_override = select_trust_override(&cfg.trust_overrides, &normalized_host)?;
    let (anchor_paths, intermediate_paths): (&[PathBuf], &[PathBuf]) = match selected_override {
        Some(over) => (&over.anchors, &over.intermediates),
        None => (&cfg.trust.anchors, &cfg.trust.intermediates),
    };
    if selected_override.is_some() {
        tracing::info!(
            target: "tessera.trust",
            host_id_hash_prefix = %host_id_hash_prefix(&normalized_host),
            anchor_source = "override",
            anchor_count = anchor_paths.len(),
            "trust anchors selected from per-host [[trust_override]]"
        );
    } else {
        tracing::info!(
            target: "tessera.trust",
            anchor_source = "base",
            anchor_count = anchor_paths.len(),
            "trust anchors selected from global [trust]"
        );
    }

    let mut anchors: Vec<Certificate> = Vec::with_capacity(anchor_paths.len());
    for path in anchor_paths {
        let bytes = std::fs::read(path)?;
        anchors.push(Certificate::from_pem(&bytes)?);
    }
    let mut intermediates: Vec<Certificate> = Vec::with_capacity(intermediate_paths.len());
    for path in intermediate_paths {
        let bytes = std::fs::read(path)?;
        intermediates.push(Certificate::from_pem(&bytes)?);
    }
    let mut crl_pems: Vec<Vec<u8>> = Vec::with_capacity(cfg.trust.revocation.crl_paths.len());
    for path in &cfg.trust.revocation.crl_paths {
        crl_pems.push(std::fs::read(path)?);
    }

    let signature_alg_whitelist: Vec<String> = cfg
        .trust
        .allowed_signature_algorithms
        .iter()
        .cloned()
        .collect();

    // Wire SPKI pins from `[trust.pinning]`.  When `pinning.enabled =
    // false` we deliberately pass an empty Vec so the verifier
    // short-circuits the pinning check (see `verify_pinning`), even if
    // pin entries are configured but disabled — this preserves the
    // same "config drift" tolerance as before while finally honouring
    // the operator's intent when pinning IS enabled.
    let spki_pins = if cfg.trust.pinning.enabled {
        decode_spki_pins(&cfg.trust.pinning.allowed_root_spki_sha256)?
    } else {
        Vec::new()
    };

    // Parse the OCSP responder URL once at wiring time; an invalid URL is a
    // hard error (the auth path must not silently skip revocation).  `None`
    // in the non-OCSP modes, where the config key is absent by validation.
    let ocsp_url = match &cfg.trust.revocation.ocsp_responder_url {
        Some(raw) => {
            Some(
                tessera_core::ocsp::OcspUrl::parse(raw).map_err(|e| WireError::OcspUrl {
                    reason: e.to_string(),
                })?,
            )
        }
        None => None,
    };

    let verifier = OpensslVerifier::new(OpensslVerifierConfig {
        anchors: anchors.clone(),
        intermediates,
        crl_pems,
        crl_strict: matches!(
            cfg.trust.revocation.mode,
            tessera_core::config::validated::RevocationMode::Crl
                | tessera_core::config::validated::RevocationMode::CrlThenOcsp
        ),
        crl_max_age: cfg.trust.revocation.crl_max_age,
        // Profile version-gate ceiling, from `[trust].max_supported_profile_version`
        // (absent → compiled baseline default, fail-closed).
        max_supported_profile_version: cfg.trust.max_supported_profile_version,
        // P1-B: take both knobs from the validated config rather than
        // hard-coding 60s/4. Validator caps both (`<= 600s`, `1..=16`)
        // so casts are safe.
        #[allow(clippy::duration_suboptimal_units)]
        clock_skew: Duration::from_secs(cfg.trust.clock_skew_seconds),
        signature_alg_whitelist,
        spki_pins,
        max_depth: usize::try_from(cfg.trust.max_chain_depth).unwrap_or(usize::MAX),
        gost_engine_path: cfg.gost_engine_path.clone(),
        revocation_mode: cfg.trust.revocation.mode,
        ocsp_responder_url: ocsp_url,
        ocsp_timeout: cfg.trust.revocation.ocsp_timeout,
        ocsp_cache_dir: std::path::PathBuf::from(
            tessera_core::trust::openssl_verifier::OCSP_CACHE_DIR,
        ),
        ocsp_cache_ttl: cfg.trust.revocation.ocsp_cache_ttl,
    })?;

    let _ = anchors; // kept for future use; no ACL verifier wires it any more

    // Wire the real monitord IPC client: connect-per-call wrapped in the
    // configured fail-mode policy. The production PAM stack always reaches
    // monitord through this stack; tests construct their own
    // `MonitorClient` impls (typically `StubClient`).
    let factory = MonitorClientFactory::new(cfg.monitor.socket_path.clone(), cfg.monitor.timeout);
    let connect_per_call = ConnectPerCall::new(factory);
    let monitor: Box<dyn MonitorClient> = Box::new(FailModeWrapper::new(
        connect_per_call,
        cfg.monitor.fail_mode.into(),
    ));
    Ok(Wired {
        trust: verifier,
        monitor,
        cfg,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;
    use tessera_core::config::load_validated_config;
    // Write is used below in write_min_config.

    fn fixtures_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tessera_core/tests/fixtures")
    }

    /// Minimal-but-valid config wired against real fixture anchors so
    /// `wire(...)` succeeds end-to-end.
    fn write_min_config(dir: &std::path::Path) -> std::path::PathBuf {
        let anchor = fixtures_dir().join("ca.pem");

        let cfg = dir.join("config.toml");
        let mut f = std::fs::File::create(&cfg).unwrap();
        let body = format!(
            r#"
crypto_backend = "openssl"
mode = "pkcs11"
pkcs11_module = "/bin/sh"
usb_wait_seconds = 10
on_usb_removed = "lock"
suspend_grace_seconds = 5

[monitor]
socket_path = "/run/tessera/monitord.sock"
timeout_ms = 1500
fail_mode = "strict"

[trust]
anchors = ["{}"]
intermediates = []
max_chain_depth = 5
clock_skew_seconds = 60
allowed_signature_algorithms = []

[trust.revocation]
mode = "none"
crl_paths = []

[trust.pinning]
enabled = false
allowed_root_spki_sha256 = []

[host_identity]
sources = ["machine_id"]
fallback = "warn"

[logging]
level = "info"
syslog_facility = "auth"
"#,
            anchor.display()
        );
        f.write_all(body.as_bytes()).unwrap();
        cfg
    }

    /// Regression test for P0-1: `wire(...)` must construct a real monitord
    /// IPC client (`FailModeWrapper<ConnectPerCall>`) — not a stub. We can't
    /// downcast through `dyn` cheaply, but we can confirm the boxed client
    /// is `Send + Sync` and exercise `ping()` against a non-existent
    /// socket; in `Strict` mode that propagates `IpcError::Unavailable`,
    /// proving the call reached `ConnectPerCall::ping` rather than
    /// `StubClient::ping` (which would silently return `Ok`).
    #[test]
    fn wire_constructs_real_monitor_client_strict() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg_path = write_min_config(tmp.path());
        let mut cfg = load_validated_config(&cfg_path).unwrap();
        // Override socket to a guaranteed-missing path so `connect(2)` fails.
        cfg.monitor.socket_path = tmp.path().join("nope.sock");
        cfg.monitor.fail_mode = tessera_core::config::validated::MonitorFailMode::Strict;

        let wired = wire(cfg, "test-host").unwrap();
        // In Strict + missing socket, `ping()` must surface
        // `IpcError::Unavailable`. StubClient would have returned Ok.
        let err = wired
            .monitor
            .ping()
            .expect_err("strict mode + missing socket must error");
        assert!(
            matches!(err, tessera_core::error::IpcError::Unavailable),
            "expected Unavailable, got {err:?}"
        );
    }

    #[test]
    fn wire_constructs_real_monitor_client_permissive() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg_path = write_min_config(tmp.path());
        let cfg = load_validated_config(&cfg_path).unwrap();
        let mut cfg = cfg;
        cfg.monitor.socket_path = tmp.path().join("nope.sock");
        cfg.monitor.fail_mode = tessera_core::config::validated::MonitorFailMode::Permissive;
        let wired = wire(cfg, "test-host").unwrap();
        // Permissive mode swallows transport errors → Ok.
        wired
            .monitor
            .ping()
            .expect("permissive mode swallows IO errors");
    }

    /// Host id that the site override applies to.
    const SITE_HOST_ID: &str = "ws-site.example.org";

    /// Writes a config whose global trust anchors are the main root (`ca.pem`,
    /// with `int.pem` as intermediate) and that additionally carries a
    /// `[[trust_override]]` narrowing trust for [`SITE_HOST_ID`] to the
    /// independent site root (`ca_site.pem`).
    fn write_config_with_site_override(dir: &std::path::Path) -> std::path::PathBuf {
        let anchor = fixtures_dir().join("ca.pem");
        let intermediate = fixtures_dir().join("int.pem");
        let site_anchor = fixtures_dir().join("ca_site.pem");

        let cfg = dir.join("config.toml");
        let mut f = std::fs::File::create(&cfg).unwrap();
        let body = format!(
            r#"
crypto_backend = "openssl"
mode = "pkcs11"
pkcs11_module = "/bin/sh"
usb_wait_seconds = 10
on_usb_removed = "lock"
suspend_grace_seconds = 5

[monitor]
socket_path = "/run/tessera/monitord.sock"
timeout_ms = 1500
fail_mode = "permissive"

[trust]
anchors = ["{anchor}"]
intermediates = ["{intermediate}"]
max_chain_depth = 5
clock_skew_seconds = 60
allowed_signature_algorithms = []

[trust.revocation]
mode = "none"
crl_paths = []

[trust.pinning]
enabled = false
allowed_root_spki_sha256 = []

[[trust_override]]
when_host_id_in = ["{site_host}"]
anchors = ["{site_anchor}"]
intermediates = []

[host_identity]
sources = ["machine_id"]
fallback = "warn"

[logging]
level = "info"
"#,
            anchor = anchor.display(),
            intermediate = intermediate.display(),
            site_anchor = site_anchor.display(),
            site_host = SITE_HOST_ID,
        );
        f.write_all(body.as_bytes()).unwrap();
        cfg
    }

    fn read_cert(name: &str) -> Certificate {
        let bytes = std::fs::read(fixtures_dir().join(name)).unwrap();
        Certificate::from_pem(&bytes).unwrap()
    }

    /// Core proof for the per-host trust-override fix: on a host whose override
    /// narrows trust to the site root, a leaf chaining only to the *global*
    /// root is REJECTED, while a leaf chaining to the site root is ACCEPTED.
    #[test]
    fn wire_applies_matching_trust_override() {
        use tessera_core::trust::openssl_verifier::Stage2TrustVerifier;

        let tmp = tempfile::tempdir().unwrap();
        let cfg_path = write_config_with_site_override(tmp.path());
        let cfg = load_validated_config(&cfg_path).unwrap();

        let wired = wire(cfg, SITE_HOST_ID).unwrap();

        // Leaf under the GLOBAL root must be refused: the override replaced the
        // anchors with the site root, so no chain to a trusted anchor exists.
        let global_leaf = read_cert("leaf_rsa.pem");
        let global_intermediate = vec![read_cert("int.pem")];
        let err = wired
            .trust
            .verify(&global_leaf, &global_intermediate)
            .expect_err("global-CA leaf must be rejected under the site override");
        assert!(
            matches!(err, tessera_core::x509::TrustError::PathBuild(_)),
            "expected PathBuild (no trusted anchor), got {err:?}"
        );

        // Leaf under the SITE root must be accepted.
        let site_leaf = read_cert("leaf_site.pem");
        let chain = wired
            .trust
            .verify(&site_leaf, &[])
            .expect("site-CA leaf must be accepted under the site override");
        assert_eq!(chain.anchor.subject_cn().unwrap(), "Site Test Root CA");
    }

    /// A host that matches no override keeps the global anchor set: a leaf under
    /// the global root is accepted.
    #[test]
    fn wire_uses_global_anchors_when_no_override_matches() {
        use tessera_core::trust::openssl_verifier::Stage2TrustVerifier;

        let tmp = tempfile::tempdir().unwrap();
        let cfg_path = write_config_with_site_override(tmp.path());
        let cfg = load_validated_config(&cfg_path).unwrap();

        let wired = wire(cfg, "some-other-host.example.org").unwrap();

        let global_leaf = read_cert("leaf_rsa.pem");
        let global_intermediate = vec![read_cert("int.pem")];
        let chain = wired
            .trust
            .verify(&global_leaf, &global_intermediate)
            .expect("global-CA leaf must be accepted when no override matches");
        assert_eq!(chain.anchor.subject_cn().unwrap(), "CertAuth Test Root CA");
    }
}
