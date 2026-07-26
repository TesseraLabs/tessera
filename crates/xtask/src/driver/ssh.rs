//! Драйвер профиля на живой машине: команды через системный `ssh`.
//!
//! На каждую команду поднимается отдельное соединение, мультиплексирование
//! отключено явно: Astra ограничивает число одновременных сессий, а повисший
//! мастер-канал ломает все последующие шаги прогона разом.

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use super::{process, CommandDriver, DriverError, ProcessOutcome};
use crate::stand::HostConfig;

/// Драйвер по SSH.
pub struct SshDriver {
    host: HostConfig,
    interrupt: Arc<AtomicBool>,
}

impl SshDriver {
    /// Создаёт драйвер для описанной в стенде машины.
    #[must_use]
    pub fn new(host: HostConfig, interrupt: Arc<AtomicBool>) -> Self {
        Self { host, interrupt }
    }

    /// Общие для `ssh` и `scp` опции транспорта.
    ///
    /// Флаг порта передаётся аргументом: `ssh` понимает `-p`, а `scp` — `-P`.
    /// Перепутать их — классическая ошибка, которая проявляется только на
    /// нестандартном порте, поэтому выбор сделан явным.
    fn transport_args(&self, port_flag: &str) -> Vec<String> {
        let mut args = vec![
            "-o".to_owned(),
            // Пароль спросить некому: прогон должен падать с внятной ошибкой,
            // а не висеть на приглашении.
            "BatchMode=yes".to_owned(),
            "-o".to_owned(),
            "ControlMaster=no".to_owned(),
            "-o".to_owned(),
            "ControlPath=none".to_owned(),
        ];
        if let Some(port) = self.host.port {
            args.push(port_flag.to_owned());
            args.push(port.to_string());
        }
        if let Some(identity) = &self.host.identity_file {
            args.push("-i".to_owned());
            args.push(identity.display().to_string());
        }
        for option in &self.host.ssh_options {
            args.push("-o".to_owned());
            args.push(option.clone());
        }
        args
    }

    fn base_args(&self) -> Vec<String> {
        let mut args = self.transport_args("-p");
        args.push(self.destination());
        args
    }

    fn scp_args(&self, local: &Path, remote: &str) -> Vec<String> {
        let mut args = self.transport_args("-P");
        args.push("-r".to_owned());
        args.push(local.display().to_string());
        args.push(format!("{}:{remote}", self.destination()));
        args
    }

    fn destination(&self) -> String {
        format!("{}@{}", self.host.user, self.host.address)
    }
}

impl CommandDriver for SshDriver {
    fn describe(&self) -> String {
        match self.host.port {
            Some(port) => format!("ssh://{}@{}:{port}", self.host.user, self.host.address),
            None => format!("ssh://{}@{}", self.host.user, self.host.address),
        }
    }

    fn exec(
        &self,
        command: &str,
        stdin: Option<&str>,
        timeout: Duration,
    ) -> Result<ProcessOutcome, DriverError> {
        let mut args = self.base_args();
        args.push(format!("sh -lc {}", process::shell_quote(command)));
        process::run("ssh", &args, stdin, timeout, &self.interrupt).map_err(|source| {
            DriverError::Spawn {
                command: "ssh".to_owned(),
                source,
            }
        })
    }

    fn deliver(&self, local: &Path, remote: &str, timeout: Duration) -> Result<(), DriverError> {
        super::clear_remote_path(self, remote, timeout)?;
        let args = self.scp_args(local, remote);
        let outcome =
            process::run("scp", &args, None, timeout, &self.interrupt).map_err(|source| {
                DriverError::Spawn {
                    command: "scp".to_owned(),
                    source,
                }
            })?;
        if outcome.exit_code != Some(0) {
            return Err(DriverError::Failed {
                operation: format!("scp {} → {remote}", local.display()),
                code: outcome.exit_code.unwrap_or(-1),
                detail: outcome.stderr,
            });
        }
        // `scp` кладёт файлы от имени пользователя стенда. Нормализация идёт
        // тем же путём, что и снос каталога перед доставкой, — командой в
        // окружении; права на неё у стенда те же, что и на `rm -rf` в /opt.
        super::restore_root_ownership(self, remote, timeout)
    }

    fn recreate(&self) -> Result<(), DriverError> {
        Err(DriverError::Unsupported(
            "живая машина не пересоздаётся раннером: чистота достигается идемпотентным teardown"
                .to_owned(),
        ))
    }
}

#[cfg(test)]
// Тестам разрешено падать на нарушенных инвариантах: это и есть их способ
// сообщить о проблеме.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn driver() -> SshDriver {
        SshDriver::new(
            HostConfig {
                address: "127.0.0.1".to_owned(),
                port: Some(2222),
                user: "bfs_admin".to_owned(),
                identity_file: Some("/keys/id".into()),
                ssh_options: vec!["StrictHostKeyChecking=accept-new".to_owned()],
            },
            Arc::new(AtomicBool::new(false)),
        )
    }

    #[test]
    fn multiplexing_is_disabled_explicitly() {
        let args = driver().base_args();
        assert!(args.contains(&"ControlMaster=no".to_owned()));
        assert!(args.contains(&"ControlPath=none".to_owned()));
        assert!(args.contains(&"BatchMode=yes".to_owned()));
    }

    #[test]
    fn port_key_and_extra_options_reach_the_command_line() {
        let args = driver().base_args();
        assert!(args.windows(2).any(|pair| pair == ["-p", "2222"]));
        assert!(args.windows(2).any(|pair| pair == ["-i", "/keys/id"]));
        assert!(args.contains(&"StrictHostKeyChecking=accept-new".to_owned()));
        assert_eq!(args.last().map(String::as_str), Some("bfs_admin@127.0.0.1"));
    }

    #[test]
    fn scp_uses_the_uppercase_port_flag_and_copies_recursively() {
        let driver = driver();
        let args = driver.scp_args(
            Path::new("/local/tessera.deb"),
            "/opt/tessera-e2e/pkg/tessera.deb",
        );
        // scp понимает -P, а не -p: строчная форма у него означает сохранение
        // времён файла, и на нестандартном порте копирование ушло бы в 22-й.
        assert!(args.windows(2).any(|pair| pair == ["-P", "2222"]));
        assert!(!args.iter().any(|arg| arg == "-p"));
        assert!(args.contains(&"-r".to_owned()));
        assert_eq!(
            args.last().map(String::as_str),
            Some("bfs_admin@127.0.0.1:/opt/tessera-e2e/pkg/tessera.deb")
        );
        // Мультиплексирование отключено и здесь: лимит сессий Astra общий.
        assert!(args.contains(&"ControlMaster=no".to_owned()));
    }

    #[test]
    fn ssh_keeps_the_lowercase_port_flag() {
        assert!(driver()
            .base_args()
            .windows(2)
            .any(|pair| pair == ["-p", "2222"]));
    }

    #[test]
    fn a_live_machine_is_never_recreated() {
        assert!(matches!(
            driver().recreate(),
            Err(DriverError::Unsupported(_))
        ));
        assert_eq!(driver().describe(), "ssh://bfs_admin@127.0.0.1:2222");
    }
}
