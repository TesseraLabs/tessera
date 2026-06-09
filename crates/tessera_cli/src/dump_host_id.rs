//! `tessera dump-host-id` subcommand.
//!
//! Loads the validated config and probes **every** canonical
//! `[host_identity]` source kind — not only the ones currently listed in
//! `[host_identity].sources`. The TSV report is written to stdout, to
//! `--output PATH`, or to a freshly mounted USB stick (`--usb`). A
//! `active_under_current_config` column flags the source that the daemon
//! would actually pick under the live config.
//!
//! Operator workflow this supports:
//!
//! 1. Boot cloned device image — `[host_identity].sources = ["override"]`
//!    keeps the bootstrap cert valid.
//! 2. Ansible flips `sources` to real values (`dmi_board_serial`,
//!    `machine_id`, …).
//! 3. `systemctl restart tessera`.
//! 4. Operator runs `sudo tessera dump-host-id --usb`.
//! 5. CA admin reads the TSV, issues a per-host cert bound to the
//!    `host_id_hash` of the first `status=ok` row.
//! 6. Operator brings the per-host USB stick back.

use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;

use tessera_core::config::validated::HostIdentitySection;
use tessera_core::host_identity::chain::{ProbeResult, ResolvedHostId};
use tessera_core::host_identity::{normalize_host_id, HostIdSourceKind, HostIdentityResolver};
use tessera_core::usb::{UdevEnumerator, UsbDevice, UsbEnumerator};
use sha2::{Digest, Sha256};

/// CLI arguments for `tessera dump-host-id`.
#[derive(Debug, Args)]
pub struct DumpHostIdArgs {
    /// Path to `config.toml`. Defaults to `/etc/tessera/config.toml`,
    /// matching the daemon and `tessera check`.
    #[arg(long, default_value = "/etc/tessera/config.toml")]
    pub config: PathBuf,

    /// Write the TSV report to PATH atomically (tmpfile + rename, mode
    /// 0644). Mutually exclusive with `--usb`.
    #[arg(long, conflicts_with = "usb")]
    pub output: Option<PathBuf>,

    /// Detect the first viable USB partition, mount it read-write under
    /// `/run/tessera/host-id-dump/`, write
    /// `host-ids-<hostname>-<UTC>.tsv` and unmount cleanly. Exits non-zero
    /// if no USB partition is attached.
    #[arg(long, default_value_t = false)]
    pub usb: bool,
}

/// Test-friendly options surface. Mirrors [`DumpHostIdArgs`] plus a
/// `fs_root` override so unit tests can pin the host-identity probes to
/// a temp tree.
#[derive(Debug, Clone)]
pub struct DumpHostIdOptions {
    /// Path to `config.toml`.
    pub config: PathBuf,
    /// Output file path (mutually exclusive with `usb`).
    pub output: Option<PathBuf>,
    /// Write to first viable USB partition.
    pub usb: bool,
    /// Optional filesystem root for host-identity probes (tests only).
    pub fs_root: Option<PathBuf>,
}

impl From<DumpHostIdArgs> for DumpHostIdOptions {
    fn from(a: DumpHostIdArgs) -> Self {
        Self {
            config: a.config,
            output: a.output,
            usb: a.usb,
            fs_root: None,
        }
    }
}

/// Where the TSV was ultimately written.
#[derive(Debug, Clone)]
pub enum DumpDestination {
    /// Printed to stdout.
    Stdout,
    /// Written to a regular file.
    File(PathBuf),
    /// Written to a freshly mounted USB partition. The mount is already
    /// undone by the time `run()` returns.
    Usb {
        /// `/dev/...` of the partition that was mounted.
        partition_devnode: String,
        /// Path of the written file *on the USB filesystem* (i.e. relative
        /// to the mount point at write time — recorded as the absolute
        /// path that was used during the write).
        written_path: PathBuf,
    },
}

/// Errors returned by [`run`].
#[derive(Debug, thiserror::Error)]
pub enum DumpError {
    /// Failed to load or validate `config.toml`.
    #[error("config load failed: {0}")]
    Config(String),
    /// All `[host_identity].sources` failed to produce a usable value.
    /// Mirrors `HostIdentityError::AllSourcesFailed`.
    #[error("no host_id could be resolved — all configured sources failed")]
    NoActiveHostId,
    /// `--output` write failed.
    #[error("output write failed: {0}")]
    Output(String),
    /// `--usb` chose but couldn't find / mount / write to a USB stick.
    #[error("USB dump failed: {0}")]
    Usb(String),
}

/// Render the TSV report (header + one row per probe).
///
/// `hostname` and `ts` are interpolated into the comment header so the
/// output is self-describing once it lands on a USB stick at the CA
/// admin's desk. `active_kind` is the source kind that the live resolver
/// (using the actual `[host_identity].sources` from `config.toml`) picks
/// — the matching row is flagged `active_under_current_config=yes`. If
/// no source resolves under the current config, all rows are flagged
/// `no`.
#[must_use]
pub fn render_tsv(
    probes: &[ProbeResult],
    hostname: &str,
    ts: &str,
    active_kind: Option<HostIdSourceKind>,
) -> String {
    let mut out = String::new();
    // Запись в String инфаллибельна, fmt::Result игнорируем намеренно.
    let _fmt = writeln!(out, "# tessera host identity probe — {hostname} — {ts}");
    out.push_str("# probes EVERY known source kind (not just [host_identity].sources).\n");
    out.push_str("# active_under_current_config=yes marks the source the daemon currently picks.\n");
    out.push_str(
        "source\tstatus\thash_hex\thash_prefix\traw\tnormalized\tactive_under_current_config\treason\n",
    );
    for p in probes {
        let source = p.source.to_string();
        let active = if active_kind == Some(p.source) { "yes" } else { "no" };
        match &p.outcome {
            Ok(r) => {
                // Запись в String инфаллибельна, fmt::Result игнорируем намеренно.
                let _fmt = writeln!(
                    out,
                    "{src}\tok\t{hash}\t{prefix}\t{raw}\t{norm}\t{active}\t-",
                    src = source,
                    hash = r.hash_hex,
                    prefix = r.hash_prefix(),
                    raw = sanitize_field(&r.raw),
                    norm = sanitize_field(&r.normalized),
                );
            }
            Err(reason) => {
                // Запись в String инфаллибельна, fmt::Result игнорируем намеренно.
                let _fmt = writeln!(
                    out,
                    "{src}\terr\t-\t-\t-\t-\t{active}\t{reason}",
                    src = source,
                    reason = sanitize_field(reason),
                );
            }
        }
    }
    out
}

/// Build a `HostIdentitySection` that fans out to every canonical kind,
/// regardless of what the operator configured in `[host_identity].sources`.
///
/// `Override` is included only when `validated.override_value` is `Some`
/// (otherwise the chain has nothing to hash). `CustomCommand` is included
/// only when `validated.custom_command` is `Some` (we need the command
/// definition to actually run it).
fn fanout_cfg(validated: &HostIdentitySection) -> HostIdentitySection {
    let mut sources = vec![
        HostIdSourceKind::MachineId,
        HostIdSourceKind::DmiBoardSerial,
        HostIdSourceKind::DmiSystemUuid,
        HostIdSourceKind::DmiSystemSerial,
        HostIdSourceKind::Hostname,
    ];
    if validated.custom_command.is_some() {
        sources.push(HostIdSourceKind::CustomCommand);
    }
    HostIdentitySection {
        sources,
        fallback: validated.fallback,
        override_value: validated.override_value.clone(),
        custom_command: validated.custom_command.clone(),
        custom_command_timeout: validated.custom_command_timeout,
    }
}

/// Synthesize a probe entry for the `override` source from the validated
/// override string. The resolver chain never actually instantiates an
/// `Override` source — `Override` only matters when the config selects
/// it via `sources = ["override"]`, in which case the chain skips it and
/// `resolve()` falls through to `override_value` only via the `Allow`/`Warn`
/// fallback path. For diagnostics we just hash `override_value` directly.
fn override_probe(override_value: Option<&str>) -> ProbeResult {
    let kind = HostIdSourceKind::Override;
    match override_value {
        None => ProbeResult {
            source: kind,
            outcome: Err("no [host_identity].override configured".to_string()),
        },
        Some(raw) => {
            let normalized = normalize_host_id(raw);
            if normalized.is_empty() {
                ProbeResult {
                    source: kind,
                    outcome: Err("empty after normalization".to_string()),
                }
            } else {
                let digest = Sha256::digest(normalized.as_bytes());
                let mut hash_hex = String::with_capacity(64);
                for byte in digest {
                    // Запись в String инфаллибельна, fmt::Result игнорируем намеренно.
                    let _fmt = write!(hash_hex, "{byte:02x}");
                }
                ProbeResult {
                    source: kind,
                    outcome: Ok(ResolvedHostId {
                        source_kind: kind,
                        raw: raw.to_string(),
                        normalized,
                        hash_hex,
                    }),
                }
            }
        }
    }
}

/// Strip control bytes (tabs, newlines, CR) from a TSV field. DMI strings
/// can legally contain tabs on quirky hardware; rather than escape we
/// drop the offending bytes so downstream parsers stay column-stable.
fn sanitize_field(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\t' | '\n' | '\r' => ' ',
            _ => c,
        })
        .collect()
}

/// Read the kernel hostname, mirroring
/// [`crate::fly_dm_wallpaper_writer`]. No `libc::gethostname` because the
/// crate denies `unsafe_code`.
fn local_hostname() -> String {
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(s) = fs::read_to_string(path) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
}

/// `YYYYMMDDTHHMMSSZ`, fully numeric so it survives FAT32 file naming.
fn utc_stamp_compact(now: std::time::SystemTime) -> String {
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (y, mo, d, h, mi, s) = epoch_to_utc(secs);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// `YYYY-MM-DDTHH:MM:SSZ` ISO 8601 (UTC), for the human comment line.
fn utc_iso8601(now: std::time::SystemTime) -> String {
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (y, mo, d, h, mi, s) = epoch_to_utc(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Pure-Rust gregorian conversion (avoids new dep on `time`/`chrono`).
/// Civil_from_days, Howard Hinnant — see <http://howardhinnant.github.io/date_algorithms.html>.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::many_single_char_names
)]
fn epoch_to_utc(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let seconds_of_day = (secs % 86_400) as u32;
    let h = seconds_of_day / 3600;
    let mi = (seconds_of_day % 3600) / 60;
    let s = seconds_of_day % 60;
    let z: i64 = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0..146_096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0..399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0..365]
    let mp = (5 * doy + 2) / 153; // [0..11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1..31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1..12]
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d, h, mi, s)
}

/// Write `content` to `path` atomically. Creates a sibling tmpfile,
/// fsyncs, then renames.
fn write_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(".tmp");
    let tmp = parent.join(&tmp_name);
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort: на FS без unix-прав (FAT32 на USB) chmod не критичен.
        drop(fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)));
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Pick the first USB block device with an allow-listed filesystem.
///
/// Reuses [`UdevEnumerator`] which already yields one record per viable
/// child partition (parents without an FS are skipped). On non-Linux
/// dev boxes this returns `None` (Udev backend is stubbed).
fn pick_usb_partition() -> Result<UsbDevice, DumpError> {
    use tessera_core::mount::usb::ALLOWED_FS;
    let dev = UdevEnumerator
        .enumerate(&[])
        .map_err(|e| DumpError::Usb(format!("udev enumerate failed: {e}")))?;
    let candidate = dev.into_iter().find(|d| {
        d.fs_type
            .as_deref()
            .is_some_and(|fs| ALLOWED_FS.contains(&fs))
    });
    candidate.ok_or_else(|| DumpError::Usb("no USB partition with writable filesystem found".into()))
}

/// Mount `dev` read-write at a unique subdirectory of
/// `/run/tessera/host-id-dump/`, write the TSV, sync, unmount.
///
/// Cleanup is best-effort but always attempted, even on partial failure,
/// so `/run` doesn't accumulate stale mountpoints.
#[cfg(target_os = "linux")]
fn write_to_usb(dev: &UsbDevice, filename: &str, content: &str) -> Result<PathBuf, DumpError> {
    use nix::mount::{mount, umount, MsFlags};

    let fs = dev
        .fs_type
        .clone()
        .ok_or_else(|| DumpError::Usb("USB partition has no fs_type".into()))?;
    let base = Path::new("/run/tessera/host-id-dump");
    fs::create_dir_all(base)
        .map_err(|e| DumpError::Usb(format!("mkdir {}: {e}", base.display())))?;
    let mp = base.join(format!("mnt-{}", std::process::id()));
    if mp.exists() {
        // Best-effort: подчищаем стухший mountpoint от прошлого запуска.
        drop(fs::remove_dir_all(&mp));
    }
    fs::create_dir_all(&mp).map_err(|e| DumpError::Usb(format!("mkdir {}: {e}", mp.display())))?;

    let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    mount(
        Some(dev.devnode.as_path()),
        &mp,
        Some(fs.as_str()),
        flags,
        None::<&str>,
    )
    .map_err(|errno| {
        // Best-effort: убираем пустой mountpoint после неудачного mount.
        drop(fs::remove_dir(&mp));
        DumpError::Usb(format!(
            "mount {} ({fs}) at {}: {errno}",
            dev.devnode.display(),
            mp.display()
        ))
    })?;

    // Anything past this point MUST unmount before returning.
    let target = mp.join(filename);
    let write_res = (|| -> Result<(), DumpError> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&target)
            .map_err(|e| DumpError::Usb(format!("open {}: {e}", target.display())))?;
        f.write_all(content.as_bytes())
            .map_err(|e| DumpError::Usb(format!("write {}: {e}", target.display())))?;
        f.sync_all()
            .map_err(|e| DumpError::Usb(format!("fsync {}: {e}", target.display())))?;
        Ok(())
    })();

    // Best-effort unmount + rmdir regardless of write outcome.
    let umount_res = umount(&mp).map_err(|e| {
        DumpError::Usb(format!("umount {}: {e}", mp.display()))
    });
    // Best-effort: rmdir после umount, чтобы /run не накапливал mountpoint'ы.
    drop(fs::remove_dir(&mp));

    write_res?;
    umount_res?;
    Ok(target)
}

#[cfg(not(target_os = "linux"))]
fn write_to_usb(_dev: &UsbDevice, _filename: &str, _content: &str) -> Result<PathBuf, DumpError> {
    Err(DumpError::Usb("USB writes are Linux-only".into()))
}

/// Execute the subcommand. Returns the chosen destination on success.
pub fn run(opts: DumpHostIdOptions) -> Result<DumpDestination, DumpError> {
    let validated = tessera_core::config::load_validated_config(&opts.config)
        .map_err(|e| DumpError::Config(format!("{}: {e}", opts.config.display())))?;
    let fs_root = opts.fs_root.unwrap_or_else(|| PathBuf::from("/"));

    // Fan-out resolver: probes EVERY canonical kind, not just configured
    // ones. The operator needs to see all possible identifiers to pick
    // the right one for the per-host cert.
    let fanout = fanout_cfg(&validated.host_identity);
    let fan_resolver = HostIdentityResolver::from_validated(&fanout, fs_root.clone());
    let mut probes = fan_resolver.probe_all();
    // Append synthetic `override` probe (chain skips Override entirely).
    probes.push(override_probe(validated.host_identity.override_value.as_deref()));

    // Determine which source the daemon would actually pick under the
    // *configured* sources list — that's the row flagged `active=yes`.
    let live_resolver =
        HostIdentityResolver::from_validated(&validated.host_identity, fs_root);
    let active_kind: Option<HostIdSourceKind> = match live_resolver.resolve() {
        Ok(r) => Some(r.source_kind),
        Err(_) => None,
    };

    let has_ok = probes.iter().any(|p| p.outcome.is_ok());
    if !has_ok {
        return Err(DumpError::NoActiveHostId);
    }
    let hostname = local_hostname();
    let now = std::time::SystemTime::now();
    let iso = utc_iso8601(now);
    let tsv = render_tsv(&probes, &hostname, &iso, active_kind);

    if let Some(path) = opts.output {
        write_atomic(&path, &tsv).map_err(|e| DumpError::Output(format!("{}: {e}", path.display())))?;
        return Ok(DumpDestination::File(path));
    }
    if opts.usb {
        let dev = pick_usb_partition()?;
        let stamp = utc_stamp_compact(now);
        let filename = format!("host-ids-{hostname}-{stamp}.tsv");
        let written = write_to_usb(&dev, &filename, &tsv)?;
        return Ok(DumpDestination::Usb {
            partition_devnode: dev.devnode.display().to_string(),
            written_path: written,
        });
    }
    print!("{tsv}");
    Ok(DumpDestination::Stdout)
}

/// CLI entry point. Translates [`DumpError`] into an exit code and a
/// stderr line, mirroring the shape of other subcommands.
#[allow(clippy::needless_pass_by_value)]
pub fn run_cli(args: DumpHostIdArgs) -> ExitCode {
    match run(args.into()) {
        Ok(DumpDestination::Stdout) => ExitCode::SUCCESS,
        Ok(DumpDestination::File(p)) => {
            eprintln!("wrote {}", p.display());
            ExitCode::SUCCESS
        }
        Ok(DumpDestination::Usb {
            partition_devnode,
            written_path,
        }) => {
            eprintln!(
                "wrote {written} on {dev}",
                written = written_path.display(),
                dev = partition_devnode
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            ExitCode::FAILURE
        }
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
    use tessera_core::host_identity::chain::{ProbeResult, ResolvedHostId};
    use tessera_core::host_identity::HostIdSourceKind;

    fn ok_probe(kind: HostIdSourceKind, raw: &str, norm: &str, hash: &str) -> ProbeResult {
        ProbeResult {
            source: kind,
            outcome: Ok(ResolvedHostId {
                source_kind: kind,
                raw: raw.to_string(),
                normalized: norm.to_string(),
                hash_hex: hash.to_string(),
            }),
        }
    }

    fn err_probe(kind: HostIdSourceKind, reason: &str) -> ProbeResult {
        ProbeResult {
            source: kind,
            outcome: Err(reason.to_string()),
        }
    }

    #[test]
    fn render_tsv_header_and_format() {
        let probes = vec![
            ok_probe(
                HostIdSourceKind::MachineId,
                "abc123",
                "abc123",
                "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9",
            ),
            err_probe(HostIdSourceKind::Hostname, "hostname source not in [host_identity].sources"),
        ];
        let tsv = render_tsv(
            &probes,
            "terminal-001",
            "2026-05-27T10:15:30Z",
            Some(HostIdSourceKind::MachineId),
        );
        let lines: Vec<&str> = tsv.lines().collect();
        assert!(lines[0].starts_with("# tessera host identity probe — terminal-001"));
        assert!(lines[0].ends_with("2026-05-27T10:15:30Z"));
        // header row
        let header_idx = lines
            .iter()
            .position(|l| l.starts_with("source\t"))
            .expect("header present");
        assert_eq!(
            lines[header_idx],
            "source\tstatus\thash_hex\thash_prefix\traw\tnormalized\tactive_under_current_config\treason"
        );
        // ok row
        let ok_row = lines[header_idx + 1];
        let cols: Vec<&str> = ok_row.split('\t').collect();
        assert_eq!(cols[0], "machine_id");
        assert_eq!(cols[1], "ok");
        assert_eq!(cols[2].len(), 64); // sha256 hex
        assert_eq!(cols[3], "5feceb66"); // prefix
        assert_eq!(cols[4], "abc123");
        assert_eq!(cols[5], "abc123");
        assert_eq!(cols[6], "yes"); // active under current config
        assert_eq!(cols[7], "-");
        // err row
        let err_row = lines[header_idx + 2];
        let cols: Vec<&str> = err_row.split('\t').collect();
        assert_eq!(cols[0], "hostname");
        assert_eq!(cols[1], "err");
        assert_eq!(cols[2], "-");
        assert_eq!(cols[6], "no");
        assert_eq!(cols[7], "hostname source not in [host_identity].sources");
    }

    #[test]
    fn render_tsv_strips_tabs_in_raw_values() {
        let probes = vec![ok_probe(
            HostIdSourceKind::DmiBoardSerial,
            "weird\traw\nvalue",
            "weirdrawvalue",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )];
        let tsv = render_tsv(&probes, "h", "t", None);
        let row = tsv
            .lines()
            .find(|l| l.starts_with("dmi_board_serial\t"))
            .expect("row");
        let cols: Vec<&str> = row.split('\t').collect();
        // Exactly 8 columns — would explode if tabs in `raw` weren't sanitized.
        assert_eq!(cols.len(), 8);
        assert_eq!(cols[4], "weird raw value");
        assert_eq!(cols[6], "no");
    }

    #[test]
    fn render_tsv_marks_active_row_yes_others_no() {
        let probes = vec![
            ok_probe(
                HostIdSourceKind::MachineId,
                "a",
                "a",
                "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            ),
            ok_probe(
                HostIdSourceKind::Hostname,
                "h",
                "h",
                "aaa8c61b5b3ea83ec4be53d3c5db96f29b067c4dca4ad81a1697b76b09a7e95c",
            ),
        ];
        let tsv = render_tsv(&probes, "h", "t", Some(HostIdSourceKind::Hostname));
        let machine_row = tsv
            .lines()
            .find(|l| l.starts_with("machine_id\t"))
            .expect("machine row");
        let hostname_row = tsv
            .lines()
            .find(|l| l.starts_with("hostname\t"))
            .expect("hostname row");
        let mc: Vec<&str> = machine_row.split('\t').collect();
        let hc: Vec<&str> = hostname_row.split('\t').collect();
        assert_eq!(mc[6], "no");
        assert_eq!(hc[6], "yes");
    }

    #[test]
    fn run_writes_to_file_when_output_set() {
        // Stage: minimal validated config with host_identity = machine_id,
        // and a temp fs_root that contains /etc/machine-id.
        let tmp = tempfile::tempdir().unwrap();
        let etc = tmp.path().join("etc");
        fs::create_dir_all(&etc).unwrap();
        fs::write(etc.join("machine-id"), "deadbeef\n").unwrap();

        let cfg_path = write_minimal_config(tmp.path(), "machine_id");

        let out_path = tmp.path().join("dump.tsv");
        let opts = DumpHostIdOptions {
            config: cfg_path,
            output: Some(out_path.clone()),
            usb: false,
            fs_root: Some(tmp.path().to_path_buf()),
        };
        let dest = run(opts).expect("run ok");
        match dest {
            DumpDestination::File(p) => assert_eq!(p, out_path),
            other => panic!("unexpected destination: {other:?}"),
        }
        let body = fs::read_to_string(&out_path).unwrap();
        assert!(body.contains("# tessera host identity probe"));
        assert!(body.contains("machine_id\tok\t"));
    }

    #[test]
    fn run_returns_stdout_when_no_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let etc = tmp.path().join("etc");
        fs::create_dir_all(&etc).unwrap();
        fs::write(etc.join("machine-id"), "abc\n").unwrap();
        let cfg_path = write_minimal_config(tmp.path(), "machine_id");
        let opts = DumpHostIdOptions {
            config: cfg_path,
            output: None,
            usb: false,
            fs_root: Some(tmp.path().to_path_buf()),
        };
        let dest = run(opts).expect("run ok");
        assert!(matches!(dest, DumpDestination::Stdout));
    }

    #[test]
    fn run_fails_when_no_source_resolves() {
        // host_identity = machine_id but the temp root has NO /etc/machine-id.
        let tmp = tempfile::tempdir().unwrap();
        let cfg_path = write_minimal_config(tmp.path(), "machine_id");
        let opts = DumpHostIdOptions {
            config: cfg_path,
            output: None,
            usb: false,
            fs_root: Some(tmp.path().to_path_buf()),
        };
        let err = run(opts).expect_err("must fail");
        assert!(matches!(err, DumpError::NoActiveHostId));
    }

    /// Write a minimal config.toml under `dir` that sets host_identity.sources
    /// to `[source_kind]` and stubs the rest with sane defaults. Returns
    /// the path.
    fn write_minimal_config(dir: &Path, source_kind: &str) -> PathBuf {
        let cfg_path = dir.join("config.toml");
        let anchor_path = dir.join("anchor.pem");
        fs::write(
            &anchor_path,
            "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let body = format!(
            r#"crypto_backend = "openssl"
mode = "pkcs11"
pkcs11_module = "/bin/sh"
usb_wait_seconds = 10
on_usb_removed = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds = 5
monitor_fail_mode = "strict"

[trust]
anchors = ["{anchor}"]
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
sources = ["{kind}"]
fallback = "deny"
custom_command_timeout_seconds = 5

[[user_mapping]]
pam_user = "alice"
cert_subject_cn = "Alice"

[logging]
level = "info"
syslog_facility = "auth"
journald_priority = true
"#,
            kind = source_kind,
            anchor = anchor_path.display(),
        );
        fs::write(&cfg_path, body).unwrap();
        cfg_path
    }

    #[test]
    fn epoch_to_utc_roundtrip_known_value() {
        // 2026-05-27T10:15:30Z = 1779876930 (verified with `date -u`).
        let (y, mo, d, h, mi, s) = epoch_to_utc(1_779_876_930);
        assert_eq!((y, mo, d, h, mi, s), (2026, 5, 27, 10, 15, 30));
        // Spot-check unix epoch.
        assert_eq!(epoch_to_utc(0), (1970, 1, 1, 0, 0, 0));
    }
}
