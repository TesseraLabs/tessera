//! Host identity resolver chain.

use std::fmt::Write as _;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::config::validated::{HostIdFallback, HostIdentitySection};
use crate::error::HostIdentityError;
use crate::host_identity::{
    CustomCommandSource, DmiBoardSerialSource, DmiSystemSerialSource, DmiSystemUuidSource,
    HostIdSource, HostIdSourceKind, HostnameSource, MachineIdSource,
};

/// Resolved host id.
#[derive(Debug, Clone)]
pub struct ResolvedHostId {
    /// Source kind.
    pub source_kind: HostIdSourceKind,
    /// Raw value.
    pub raw: String,
    /// Normalized value.
    pub normalized: String,
    /// SHA-256 hex.
    pub hash_hex: String,
}

impl ResolvedHostId {
    /// First 8 hex chars of [`Self::hash_hex`] — short, eyeballable form
    /// suitable for `PAM_TEXT_INFO` on a small lock-screen / banking
    /// terminal. The full hash still goes to syslog.
    #[must_use]
    pub fn hash_prefix(&self) -> &str {
        let n = self.hash_hex.len().min(8);
        &self.hash_hex[..n]
    }
}

/// Outcome of probing a single configured host id source.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    /// Source that was probed.
    pub source: HostIdSourceKind,
    /// `Ok(_)` if the source produced a non-empty normalized id;
    /// `Err(reason)` otherwise.
    pub outcome: Result<ResolvedHostId, String>,
}

/// Resolver.
pub struct HostIdentityResolver {
    sources: Vec<Box<dyn HostIdSource>>,
    fallback: HostIdFallback,
    fs_root: PathBuf,
}

impl HostIdentityResolver {
    /// Build from validated config.
    pub fn from_validated(cfg: &HostIdentitySection, fs_root: PathBuf) -> Self {
        let mut sources: Vec<Box<dyn HostIdSource>> = Vec::new();
        for kind in &cfg.sources {
            match kind {
                HostIdSourceKind::MachineId => sources.push(Box::new(MachineIdSource)),
                HostIdSourceKind::DmiBoardSerial => sources.push(Box::new(DmiBoardSerialSource)),
                HostIdSourceKind::DmiSystemUuid => sources.push(Box::new(DmiSystemUuidSource)),
                HostIdSourceKind::DmiSystemSerial => sources.push(Box::new(DmiSystemSerialSource)),
                HostIdSourceKind::Hostname => sources.push(Box::new(HostnameSource)),
                HostIdSourceKind::CustomCommand => {
                    if let Some(cmd) = &cfg.custom_command {
                        sources.push(Box::new(CustomCommandSource::new(
                            cmd.clone(),
                            cfg.custom_command_timeout,
                        )));
                    }
                }
                HostIdSourceKind::Override => {}
            }
        }
        Self {
            sources,
            fallback: cfg.fallback,
            fs_root,
        }
    }

    /// Probe every configured source and return the per-source outcome.
    /// Does NOT influence selection — [`Self::resolve`] keeps its
    /// first-working-wins policy. Useful for startup diagnostics so the
    /// admin can see in one log line which sources answered and which
    /// failed.
    #[must_use]
    pub fn probe_all(&self) -> Vec<ProbeResult> {
        let mut out = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            let outcome = match source.fetch(&self.fs_root) {
                Ok(raw) => {
                    let normalized = normalize_host_id(&raw);
                    if normalized.is_empty() {
                        Err("empty after normalization".to_string())
                    } else {
                        Ok(resolved(source.kind(), raw, normalized))
                    }
                }
                Err(e) => Err(e.to_string()),
            };
            out.push(ProbeResult {
                source: source.kind(),
                outcome,
            });
        }
        out
    }

    /// Resolve the first working source.
    pub fn resolve(&self) -> Result<ResolvedHostId, HostIdentityError> {
        let mut attempts = Vec::new();
        for source in &self.sources {
            match source.fetch(&self.fs_root) {
                Ok(raw) => {
                    let normalized = normalize_host_id(&raw);
                    if normalized.is_empty() {
                        attempts.push((source.kind(), "empty after normalization".to_string()));
                        continue;
                    }
                    let r = resolved(source.kind(), raw, normalized);
                    tracing::info!(
                        target: "tessera.host_identity",
                        source = ?r.source_kind,
                        raw = %r.raw,
                        host_id_hash = %r.hash_hex,
                        "host_id resolved"
                    );
                    return Ok(r);
                }
                Err(e) => attempts.push((source.kind(), e.to_string())),
            }
        }
        match self.fallback {
            HostIdFallback::Deny => Err(HostIdentityError::AllSourcesFailed { attempts }),
            HostIdFallback::Warn | HostIdFallback::Allow => {
                let r = resolved(
                    HostIdSourceKind::Override,
                    "unknown".to_string(),
                    "unknown".to_string(),
                );
                tracing::info!(
                    target: "tessera.host_identity",
                    source = ?r.source_kind,
                    raw = %r.raw,
                    host_id_hash = %r.hash_hex,
                    fallback = ?self.fallback,
                    "host_id fallback to unknown"
                );
                Ok(r)
            }
        }
    }
}

/// Normalize a host id.
pub fn normalize_host_id(input: &str) -> String {
    input
        .trim()
        .chars()
        .filter(|c| *c != ':' && *c != ' ')
        .flat_map(char::to_lowercase)
        .collect()
}

fn resolved(source_kind: HostIdSourceKind, raw: String, normalized: String) -> ResolvedHostId {
    let hash = Sha256::digest(normalized.as_bytes());
    let mut hash_hex = String::with_capacity(64);
    for byte in hash {
        // Запись в String инфаллибельна, результат игнорируем намеренно.
        #[allow(clippy::let_underscore_must_use)]
        let _ = write!(hash_hex, "{byte:02x}");
    }
    ResolvedHostId {
        source_kind,
        raw,
        normalized,
        hash_hex,
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::config::validated::HostIdFallback;
    use std::fs;
    use std::time::Duration;

    fn cfg(sources: Vec<HostIdSourceKind>, fallback: HostIdFallback) -> HostIdentitySection {
        HostIdentitySection {
            sources,
            fallback,
            override_value: None,
            custom_command: None,
            custom_command_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn hash_prefix_returns_first_8_hex_chars() {
        let r = resolved(HostIdSourceKind::MachineId, "raw".into(), "raw".into());
        assert_eq!(r.hash_prefix().len(), 8);
        assert_eq!(r.hash_prefix(), &r.hash_hex[..8]);
    }

    #[test]
    fn hash_prefix_is_shorter_when_hash_is_shorter() {
        let r = ResolvedHostId {
            source_kind: HostIdSourceKind::MachineId,
            raw: String::new(),
            normalized: String::new(),
            hash_hex: "abc".into(),
        };
        assert_eq!(r.hash_prefix(), "abc");
    }

    fn make_fs_root_with_machine_id(value: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let etc = tmp.path().join("etc");
        fs::create_dir_all(&etc).expect("mkdir etc");
        fs::write(etc.join("machine-id"), value).expect("write machine-id");
        tmp
    }

    #[test]
    fn probe_all_returns_all_sources_with_outcomes() {
        let tmp = make_fs_root_with_machine_id("abc123\n");
        let resolver = HostIdentityResolver::from_validated(
            &cfg(
                vec![
                    HostIdSourceKind::MachineId,
                    HostIdSourceKind::DmiBoardSerial,
                ],
                HostIdFallback::Deny,
            ),
            tmp.path().to_path_buf(),
        );
        let probes = resolver.probe_all();
        assert_eq!(probes.len(), 2);
        assert_eq!(probes[0].source, HostIdSourceKind::MachineId);
        assert!(probes[0].outcome.is_ok());
        assert_eq!(probes[1].source, HostIdSourceKind::DmiBoardSerial);
        // DMI path under a tmp root doesn't exist → outcome is Err.
        assert!(probes[1].outcome.is_err());
    }

    #[test]
    fn probe_all_does_not_affect_resolve_first_working_policy() {
        // machine_id missing under tmp root; hostname populated.
        // resolve() must skip machine_id, pick hostname.
        let tmp = tempfile::tempdir().expect("tmpdir");
        let etc = tmp.path().join("etc");
        fs::create_dir_all(&etc).expect("mkdir etc");
        fs::write(etc.join("hostname"), "ironman\n").expect("write hostname");
        let resolver = HostIdentityResolver::from_validated(
            &cfg(
                vec![HostIdSourceKind::MachineId, HostIdSourceKind::Hostname],
                HostIdFallback::Deny,
            ),
            tmp.path().to_path_buf(),
        );
        let probes = resolver.probe_all();
        assert_eq!(probes.len(), 2);
        assert!(probes[0].outcome.is_err()); // machine_id missing
        assert!(probes[1].outcome.is_ok()); // hostname populated
                                            // Now `resolve()` must still pick hostname (first working), regardless
                                            // of `probe_all` having been called.
        let id = resolver.resolve().expect("hostname works");
        assert_eq!(id.source_kind, HostIdSourceKind::Hostname);
    }
}
