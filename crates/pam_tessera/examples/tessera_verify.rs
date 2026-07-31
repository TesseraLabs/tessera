//! Bench tool: check a credential on removable media from the console.
//!
//! It exists to prove one thing on a Windows machine, with nothing else in the
//! way: that media is found, the credential on it is read, and the same
//! verification core that guards a Linux login reaches a verdict. There is no
//! COM, no service, no credential provider — a failure here is a failure of
//! the certificate path itself and of nothing else.
//!
//! It is temporary by design. The service takes this role over once it exists,
//! and this tool then has no reason to remain; nothing should be built on top
//! of it in the meantime.
//!
//! What it is not:
//!
//! * **Not a login.** A verdict here opens no session and grants nothing.
//! * **Not the service's wiring.** Trust material is read straight from
//!   `[trust]`; per-host `[[trust_override]]` entries are ignored, so a device
//!   whose anchors are narrowed by an override is checked here against the
//!   wider global set. The service wires overrides properly.
//! * **Not the service.** The account class is the machine's real one — the
//!   role name is checked against this device's own principals and its local
//!   account database — but nothing else about the session is: no session is
//!   opened and no rights are granted.
//!
//! Usage:
//!
//! ```text
//! tessera_verify --role <account> [--config <path>] [--wait-seconds <n>]
//! ```

#![allow(clippy::print_stderr, clippy::print_stdout)]

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(windows)]
    {
        imp::run()
    }
    #[cfg(not(windows))]
    {
        eprintln!(
            "tessera_verify checks media through the Windows volume path and \
             has nothing to do on this platform."
        );
        ExitCode::FAILURE
    }
}

#[cfg(windows)]
mod imp {
    //! Everything below runs only where there are volumes to look at.

    use std::io::{self, BufRead as _, Write as _};
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::time::Duration;

    use secrecy::SecretString;
    use tessera_core::config::ValidatedConfig;
    use tessera_core::role::{RoleOs, RoleStore, SystemAccounts, TrustMode};
    use tessera_core::trust::openssl_verifier::{OpensslVerifier, OpensslVerifierConfig};
    use tessera_core::x509::Certificate;

    use pam_tessera::flow::{authenticate_pkcs12, Deps, FlowError, RoleStage};
    use pam_tessera::volume_flow::VolumeFlowIo;

    /// Where the bench keeps its configuration when `--config` is absent.
    const DEFAULT_CONFIG: &str = r"C:\ProgramData\Tessera\tessera.toml";

    /// Service name recorded in the audit trail for attempts made by this tool,
    /// so a bench run is never mistaken for a real login.
    const SERVICE_NAME: &str = "tessera-verify";

    /// Parsed command line.
    struct Args {
        /// Login account the attempt is made for; also the role id.
        role: String,
        /// Configuration file to read.
        config: PathBuf,
        /// How long to wait for media.
        wait: Option<Duration>,
    }

    /// Why a run could not reach a verdict at all.
    #[derive(Debug, thiserror::Error)]
    enum SetupError {
        /// The command line was not usable.
        #[error("{0}")]
        Usage(String),
        /// Configuration could not be read or validated.
        #[error("configuration: {0}")]
        Config(#[from] tessera_core::Error),
        /// The host identity could not be resolved.
        #[error("host identity: {0}")]
        HostIdentity(#[from] tessera_core::error::HostIdentityError),
        /// Trust material named by the configuration could not be read.
        #[error("trust material: {0}")]
        Io(#[from] io::Error),
        /// Trust material could not be parsed, or the verifier refused to build.
        #[error("trust: {0}")]
        Trust(#[from] tessera_core::x509::TrustError),
        /// The role store could not be loaded.
        #[error("role store: {0}")]
        RoleStore(#[from] tessera_core::role::RoleStoreError),
    }

    /// What the check concluded about the credential.
    enum Verdict {
        /// The credential was accepted.
        Admitted,
        /// The credential, the media, or the role was refused.
        Denied,
    }

    /// Run the check and report the verdict.
    pub fn run() -> ExitCode {
        match verify() {
            Ok(Verdict::Admitted) => ExitCode::SUCCESS,
            // The shell must be able to tell an admitted credential from a
            // rejected one; the reason has already been printed.
            Ok(Verdict::Denied) => ExitCode::FAILURE,
            Err(err) => {
                eprintln!("Проверка не выполнена: {err}");
                if let SetupError::Usage(_) = err {
                    eprintln!(
                        "Использование: tessera_verify --role <учётная запись> \
                         [--config <путь>] [--wait-seconds <секунды>]"
                    );
                }
                ExitCode::FAILURE
            }
        }
    }

    /// Build everything the flow needs, drive it, print the outcome.
    fn verify() -> Result<Verdict, SetupError> {
        let args = parse_args()?;

        let cfg = tessera_core::config::load_privileged_validated_config(&args.config)?;
        let (host_id_source, _host_id_raw, host_id_hash) =
            pam_tessera::resolve_host_identity(&cfg)?;
        let verifier = build_verifier(&cfg)?;
        let store = RoleStore::load_privileged(
            &cfg.roles.dir,
            RoleOs::Windows,
            TrustMode::Standalone,
            SystemAccounts::device(cfg.roles.account_lookup_timeout),
        )?;
        let monitor = tessera_core::ipc::StubClient;
        // Hooks are `fork`/`exec` on Unix and have no Windows implementation;
        // the certificate path does not depend on them.
        let hooks = tessera_core::hooks::NoopExecutor::new();
        let accounts = tessera_core::role::AccountCheck::from_store(&store);
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &hooks,
            host_id_hash: &host_id_hash,
            host_id_source,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: RoleStage {
                store: &store,
                default_session_ttl: cfg.roles.default_session_ttl,
                accounts,
            },
            device_tags: pam_tessera::flow::empty_device_tags(),
        };

        let io = VolumeFlowIo::for_removable_volumes(args.wait.unwrap_or(cfg.usb_wait));
        println!("Ожидание съёмного носителя…");
        let session_id = format!("verify-{}", uuid::Uuid::new_v4().simple());
        let outcome =
            authenticate_pkcs12(deps, &io, &args.role, SERVICE_NAME, session_id, read_pin);

        match outcome {
            Ok(out) => {
                let ctx = &out.auth_ctx;
                println!("Допуск: удостоверение принято.");
                println!("  CN:            {}", ctx.cert_cn.as_deref().unwrap_or("—"));
                println!(
                    "  Серийный:      {}",
                    ctx.cert_serial.as_deref().unwrap_or("—")
                );
                println!(
                    "  Носитель:      {} ({})",
                    ctx.usb_serial.as_deref().unwrap_or("—"),
                    ctx.usb_vid_pid.as_deref().unwrap_or("—")
                );
                match ctx.role.as_ref() {
                    Some(role) => println!(
                        "  Роль:          {} (версия {})",
                        role.role.as_str(),
                        role.role_version
                    ),
                    None => println!("  Роль:          —"),
                }
                println!("Сессия не открывается: это проверка, а не вход.");
                Ok(Verdict::Admitted)
            }
            Err(err) => {
                report_denial(&err);
                Ok(Verdict::Denied)
            }
        }
    }

    /// Print a denial with the reason and the code the PAM path would return.
    fn report_denial(err: &FlowError) {
        eprintln!("Отказ: {err}");
        eprintln!("  Код отказа (PAM): {}", err.pam_code());
        // The three ways media can fail an attempt are told apart here rather
        // than left to the reader of a single message: they call for different
        // actions at the bench.
        match err {
            FlowError::Usb(tessera_core::usb::UsbError::Timeout) => {
                eprintln!("  Съёмный том не появился за отведённое время.");
            }
            FlowError::Usb(tessera_core::usb::UsbError::WaitCancelled) => {
                eprintln!("  Ожидание носителя прервано.");
            }
            FlowError::Discovery(_) => {
                eprintln!("  Тома найдены, удостоверения нет ни на одном.");
            }
            FlowError::Mount(_) => {
                eprintln!("  Том исчез между обнаружением и чтением.");
            }
            _ => {
                eprintln!("  Удостоверение найдено, но проверку не прошло.");
            }
        }
    }

    /// Build a verifier from the global `[trust]` section.
    fn build_verifier(cfg: &ValidatedConfig) -> Result<OpensslVerifier, SetupError> {
        let mut anchors = Vec::with_capacity(cfg.trust.anchors.len());
        for path in &cfg.trust.anchors {
            anchors.push(Certificate::from_pem(&std::fs::read(path)?)?);
        }
        let mut intermediates = Vec::with_capacity(cfg.trust.intermediates.len());
        for path in &cfg.trust.intermediates {
            intermediates.push(Certificate::from_pem(&std::fs::read(path)?)?);
        }
        let mut crl_pems = Vec::with_capacity(cfg.trust.revocation.crl_paths.len());
        for path in &cfg.trust.revocation.crl_paths {
            crl_pems.push(std::fs::read(path)?);
        }
        let verifier = OpensslVerifier::new(OpensslVerifierConfig {
            anchors,
            intermediates,
            crl_pems,
            crl_strict: matches!(
                cfg.trust.revocation.mode,
                tessera_core::config::validated::RevocationMode::Crl
                    | tessera_core::config::validated::RevocationMode::CrlThenOcsp
            ),
            crl_max_age: cfg.trust.revocation.crl_max_age,
            max_supported_profile_version: cfg.trust.max_supported_profile_version,
            #[allow(clippy::duration_suboptimal_units)]
            clock_skew: Duration::from_secs(cfg.trust.clock_skew_seconds),
            signature_alg_whitelist: cfg
                .trust
                .allowed_signature_algorithms
                .iter()
                .cloned()
                .collect(),
            // Pinning is deliberately not wired: decoding the configured pins
            // belongs with the service's wiring, and a bench that silently
            // ignored a pin it could not decode would be worse than one that
            // says it does not do pinning at all.
            spki_pins: Vec::new(),
            max_depth: usize::try_from(cfg.trust.max_chain_depth).unwrap_or(usize::MAX),
            gost_engine_path: cfg.gost_engine_path.clone(),
            revocation_mode: cfg.trust.revocation.mode,
            // OCSP needs a parsed responder URL, which the service wires; a
            // configuration that asks for it is refused rather than silently
            // downgraded to no revocation check.
            ocsp_responder_url: None,
            ocsp_timeout: cfg.trust.revocation.ocsp_timeout,
            ocsp_cache_dir: PathBuf::from(tessera_core::trust::openssl_verifier::OCSP_CACHE_DIR),
            ocsp_cache_ttl: cfg.trust.revocation.ocsp_cache_ttl,
        })?;
        if cfg.trust.pinning.enabled {
            eprintln!(
                "Внимание: закрепление корней (pinning) в стендовой проверке не применяется."
            );
        }
        if cfg.trust.revocation.ocsp_responder_url.is_some() {
            eprintln!("Внимание: OCSP-респондер в стендовой проверке не опрашивается.");
        }
        Ok(verifier)
    }

    /// Parse the command line.
    fn parse_args() -> Result<Args, SetupError> {
        let mut role: Option<String> = None;
        let mut config: Option<PathBuf> = None;
        let mut wait: Option<Duration> = None;
        let mut argv = std::env::args().skip(1);
        while let Some(arg) = argv.next() {
            match arg.as_str() {
                "--role" => {
                    role = Some(next_value(&mut argv, "--role")?);
                }
                "--config" => {
                    config = Some(PathBuf::from(next_value(&mut argv, "--config")?));
                }
                "--wait-seconds" => {
                    let raw = next_value(&mut argv, "--wait-seconds")?;
                    let secs: u64 = raw.parse().map_err(|_| {
                        SetupError::Usage(format!("--wait-seconds: не число: {raw}"))
                    })?;
                    wait = Some(Duration::from_secs(secs));
                }
                other => {
                    return Err(SetupError::Usage(format!("неизвестный аргумент: {other}")));
                }
            }
        }
        let role = role.ok_or_else(|| SetupError::Usage("не указан --role".to_string()))?;
        Ok(Args {
            role,
            config: config.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG)),
            wait,
        })
    }

    /// The value following `flag`, or a usage error.
    fn next_value(
        argv: &mut impl Iterator<Item = String>,
        flag: &str,
    ) -> Result<String, SetupError> {
        argv.next()
            .ok_or_else(|| SetupError::Usage(format!("{flag}: не указано значение")))
    }

    /// Prompt for a PIN with console echo switched off.
    ///
    /// The typed value is moved into the secret without an intermediate copy,
    /// so the only buffer holding it is the one that wipes itself on drop.
    fn read_pin(prompt: &str) -> Result<SecretString, tessera_core::pam_conv::PamConvError> {
        print!("{prompt}");
        io::stdout()
            .flush()
            .map_err(|e| conv_error(&format!("stdout: {e}")))?;
        let _echo = console::EchoOff::engage();
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| conv_error(&format!("stdin: {e}")))?;
        // The newline the user typed was not echoed; put the cursor back on a
        // line of its own so the next message is readable.
        println!();
        let trimmed = line.trim_end_matches(['\r', '\n']).len();
        line.truncate(trimmed);
        Ok(SecretString::from(line))
    }

    /// Report why the prompt failed and return the error the flow expects.
    ///
    /// `PamConvError` carries no payload — on the PAM path the detail belongs
    /// in the log rather than in front of whoever is typing — so the reason is
    /// printed here instead of travelling with the error.
    fn conv_error(message: &str) -> tessera_core::pam_conv::PamConvError {
        eprintln!("Не удалось запросить PIN: {message}");
        tessera_core::pam_conv::PamConvError::ConvFailed
    }

    mod console {
        //! Console echo control.
        //!
        //! Turning the console echo off is the one Win32 call this tool makes
        //! on its own account; everything else it needs comes from the core.
        #![allow(unsafe_code)]

        use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT,
            STD_INPUT_HANDLE,
        };

        /// Restores the console mode when dropped.
        ///
        /// Restoration has to survive an error on the read, otherwise a failed
        /// prompt leaves the operator with a terminal that no longer echoes.
        pub struct EchoOff {
            /// Input handle whose mode was changed, if any.
            handle: Option<HANDLE>,
            /// Mode to restore.
            previous: CONSOLE_MODE,
        }

        impl EchoOff {
            /// Switch echo off for as long as the returned value lives.
            ///
            /// When stdin is not a console — a piped PIN at the bench — there
            /// is no echo to switch off and nothing is changed.
            pub fn engage() -> Self {
                // SAFETY: the call takes a well-known identifier and returns a
                // handle owned by the process; it is not closed here.
                let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
                if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                    return Self {
                        handle: None,
                        previous: 0,
                    };
                }
                let mut mode: CONSOLE_MODE = 0;
                // SAFETY: `handle` is a live process handle and `mode` is a
                // live local the callee writes exactly once.
                let ok = unsafe { GetConsoleMode(handle, &raw mut mode) };
                if ok == 0 {
                    return Self {
                        handle: None,
                        previous: 0,
                    };
                }
                // SAFETY: same handle, and a mode derived from the one the
                // console just reported.
                let applied = unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) };
                if applied == 0 {
                    return Self {
                        handle: None,
                        previous: 0,
                    };
                }
                Self {
                    handle: Some(handle),
                    previous: mode,
                }
            }
        }

        impl Drop for EchoOff {
            fn drop(&mut self) {
                let Some(handle) = self.handle else {
                    return;
                };
                // SAFETY: the handle and the mode are the pair this value
                // captured in `engage`.
                let _restored = unsafe { SetConsoleMode(handle, self.previous) };
            }
        }
    }
}
