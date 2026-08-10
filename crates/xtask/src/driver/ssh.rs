//! Драйвер профиля на живой машине: команды через системный `ssh`.
//!
//! На каждую команду поднимается отдельное соединение, мультиплексирование
//! отключено явно: Astra ограничивает число одновременных сессий, а повисший
//! мастер-канал ломает все последующие шаги прогона разом.
//!
//! Кейсы ставят пакет, правят `/etc/tessera` и дёргают `systemctl`, а вход
//! root'ом по SSH на живой машине обычно закрыт, поэтому стенд может попросить
//! повышение прав (`sudo = true` у хоста). Тогда под `sudo` идут и шаги, и
//! служебные операции драйвера, а доставка едет потоком `tar`, а не `scp`:
//! `scp` повысить права нечем, и приезжающие им файлы теряют режимы.

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use super::{process, CommandDriver, DriverError, ProcessOutcome};
use crate::stand::HostConfig;

/// Драйвер по SSH.
pub struct SshDriver {
    host: HostConfig,
    workdir: Option<String>,
    interrupt: Arc<AtomicBool>,
}

impl SshDriver {
    /// Создаёт драйвер для описанной в стенде машины.
    ///
    /// `workdir` — корень стенда, откуда исполняются команды кейсов.
    #[must_use]
    pub fn new(host: HostConfig, workdir: Option<String>, interrupt: Arc<AtomicBool>) -> Self {
        Self {
            host,
            workdir,
            interrupt,
        }
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

    /// Аргументы копирования.
    ///
    /// Строчная `-p` — сохранение прав и времён, и она обязательна: хелперы
    /// лежат в git исполняемыми, а `scp` без неё создаёт файлы по umask.
    /// Приехавший без бита исполнения скрипт валит подготовку кодом 126, и
    /// выглядит это как сломанный стенд без причины. Порт при этом уходит
    /// заглавной `-P` — обе формы стоят в одной строке и означают разное.
    fn scp_args(&self, local: &Path, remote: &str) -> Vec<String> {
        let mut args = self.transport_args("-P");
        args.push("-p".to_owned());
        args.push("-r".to_owned());
        args.push(local.display().to_string());
        args.push(format!("{}:{remote}", self.destination()));
        args
    }

    fn destination(&self) -> String {
        format!("{}@{}", self.host.user, self.host.address)
    }

    /// Строка, которую разберёт шелл на той стороне.
    ///
    /// Оболочка неинтерактивная и не login: `sh -lc` читает профиль, а Astra
    /// печатает оттуда приветствие и напоминание про активацию системы. Всё
    /// это попадало в `stdout` шага, и кейс сравнивал своё ожидание с
    /// приветствием.
    ///
    /// Перед командой делается переход в корень стенда: кейсы адресуют хелперы
    /// относительно него (`helpers/config-mutate.sh …`), а `ssh` начинает в
    /// домашнем каталоге, где такого пути нет. Неудача перехода не прерывает
    /// команду — служебные операции драйвера идут до первой доставки, когда
    /// корня стенда ещё не существует, и адресуются абсолютными путями.
    ///
    /// Под `sudo` уходит вся команда шага целиком, а не первое её слово: кейсы
    /// пишут конвейеры и перенаправления, и повышение прав только у головы
    /// конвейера меняло бы смысл шага. Режим `-n` неинтерактивный: пароль на
    /// прогоне спросить некому, и зависшее приглашение выглядело бы как
    /// таймаут шага.
    fn remote_command(&self, command: &str) -> String {
        let script = match &self.workdir {
            Some(dir) => format!("cd '{dir}' 2>/dev/null; {command}"),
            None => command.to_owned(),
        };
        let shell = format!("sh -c {}", process::shell_quote(&script));
        if self.host.sudo {
            format!("sudo -n {shell}")
        } else {
            shell
        }
    }

    /// Отличает отказ повышения прав от ненулевого кода самой команды.
    ///
    /// Без этого нехватка прав приходит в отчёт как «код 1» от шага и читается
    /// как провал продукта, хотя сломан стенд.
    fn check_sudo(&self, outcome: &ProcessOutcome) -> Result<(), DriverError> {
        if !self.host.sudo || outcome.exit_code == Some(0) {
            return Ok(());
        }
        let refused = SUDO_REFUSALS
            .iter()
            .any(|marker| outcome.stderr.contains(marker));
        if !refused {
            return Ok(());
        }
        Err(DriverError::Failed {
            operation: format!(
                "повышение прав на {}: учётной записи {} нужно право sudo без пароля",
                self.host.address, self.host.user
            ),
            code: outcome.exit_code.unwrap_or(-1),
            detail: outcome.stderr.clone(),
        })
    }

    /// Доставка потоком: `tar` собирает архив здесь, `tar -x` под `sudo`
    /// раскладывает его на той стороне.
    ///
    /// `scp` для машины с повышением прав не годится по двум причинам. Он идёт
    /// от учётной записи стенда, а та не пишет в принадлежащий root каталог. И
    /// в замкнутой программной среде Astra ей вдобавок запрещено выставлять
    /// бит исполнения (`nochmodx` в parsec), поэтому даже с `-p` сервер SFTP
    /// отвечает `remote fsetstat: Permission denied`, хелперы приезжают
    /// `0644`, и подготовка падает кодом 126. Распаковка идёт от root, режимы
    /// приезжают ровно те, что лежат в рабочей копии.
    ///
    /// Архив собирается в память и уходит на ту сторону через stdin, а не
    /// конвейером двух процессов: конвейер пришлось бы отдавать локальной
    /// оболочке вместе с путями, а лишнее экранирование там, где по потокам
    /// едут байты архива, — ровно тот сорт ошибки, который проявляется на
    /// одном стенде из десяти.
    fn unpack(&self, local: &Path, remote: &str, timeout: Duration) -> Result<(), DriverError> {
        let name = local
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| {
                DriverError::Unsupported(format!(
                    "не определить имя доставляемого из {}",
                    local.display()
                ))
            })?;
        let source_dir = local.parent().unwrap_or(Path::new("."));
        let archive = self.archive(source_dir, name, timeout)?;

        let mut args = self.base_args();
        args.push(self.remote_command(&unpack_command(super::remote_parent(remote), name, remote)));
        let outcome = process::run_bytes("ssh", &args, Some(&archive), timeout, &self.interrupt)
            .map_err(|source| DriverError::Spawn {
                command: "ssh".to_owned(),
                source,
            })?
            .into_text();
        self.check_sudo(&outcome)?;
        if outcome.exit_code == Some(0) {
            return Ok(());
        }
        Err(DriverError::Failed {
            operation: format!("распаковка {} → {remote} под sudo", local.display()),
            code: outcome.exit_code.unwrap_or(-1),
            detail: outcome.stderr,
        })
    }

    /// Собирает архив доставки на машине оператора.
    fn archive(
        &self,
        source_dir: &Path,
        name: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, DriverError> {
        let args = vec![
            "-C".to_owned(),
            source_dir.display().to_string(),
            "-cf".to_owned(),
            "-".to_owned(),
            name.to_owned(),
        ];
        let outcome =
            process::run_bytes("tar", &args, None, timeout, &self.interrupt).map_err(|source| {
                DriverError::Spawn {
                    command: "tar".to_owned(),
                    source,
                }
            })?;
        if outcome.exit_code == Some(0) {
            return Ok(outcome.stdout);
        }
        Err(DriverError::Failed {
            operation: format!("сборка архива из {}/{name}", source_dir.display()),
            code: outcome.exit_code.unwrap_or(-1),
            detail: String::from_utf8_lossy(&outcome.stderr).into_owned(),
        })
    }

    fn copy(&self, local: &Path, remote: &str, timeout: Duration) -> Result<(), DriverError> {
        let args = self.scp_args(local, remote);
        let outcome =
            process::run("scp", &args, None, timeout, &self.interrupt).map_err(|source| {
                DriverError::Spawn {
                    command: "scp".to_owned(),
                    source,
                }
            })?;
        if outcome.exit_code == Some(0) {
            return Ok(());
        }
        Err(DriverError::Failed {
            operation: format!("scp {} → {remote}", local.display()),
            code: outcome.exit_code.unwrap_or(-1),
            detail: outcome.stderr,
        })
    }
}

/// Команда распаковки на целевой стороне.
///
/// Архив раскладывается в свежий каталог рядом с целью, и только потом
/// содержимое переезжает на её место. Распаковка прямо в родительский каталог
/// затёрла бы соседа, чьё имя совпало с именем источника: имя в архиве —
/// локальное, а цель доставки зовётся по-своему (`tessera_0.5.0_amd64.deb`
/// приезжает как `tessera.deb`). Временный каталог берётся там же, чтобы
/// переезд был переименованием в пределах файловой системы, и снимается
/// ловушкой — иначе оборванная распаковка оставляла бы мусор в `/opt`.
///
/// `--no-same-owner` нужен потому, что root по умолчанию восстанавливает
/// владельца из архива, а там записан пользователь машины оператора, которого
/// на стенде нет.
fn unpack_command(parent: &str, name: &str, remote: &str) -> String {
    format!(
        "set -e; d=$(mktemp -d -p '{parent}'); trap 'rm -rf \"$d\"' EXIT; \
         tar --no-same-owner -C \"$d\" -xf -; mv \"$d\"/'{name}' '{remote}'"
    )
}

/// По чему узнаётся отказ `sudo` до запуска команды.
///
/// Своего кода возврата у такого отказа нет — `sudo` выходит с единицей, той
/// же, что и большинство команд кейса, поэтому остаётся текст диагностики.
const SUDO_REFUSALS: &[&str] = &[
    "password is required",
    "no tty present",
    "a terminal is required",
    "is not in the sudoers file",
    "not allowed to execute",
];

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
        args.push(self.remote_command(command));
        // stdin шага (кейсы передают туда PIN) уходит удалённой команде: под
        // `sudo -n` поток не перехватывается, приглашения нет.
        let outcome =
            process::run("ssh", &args, stdin, timeout, &self.interrupt).map_err(|source| {
                DriverError::Spawn {
                    command: "ssh".to_owned(),
                    source,
                }
            })?;
        self.check_sudo(&outcome)?;
        Ok(outcome)
    }

    fn deliver(&self, local: &Path, remote: &str, timeout: Duration) -> Result<(), DriverError> {
        // Снос прежнего содержимого обязателен в обоих случаях: без него на
        // месте цели остались бы файлы прошлой доставки.
        super::clear_remote_path(self, remote, timeout)?;
        if self.host.sudo {
            self.unpack(local, remote, timeout)?;
        } else {
            self.copy(local, remote, timeout)?;
        }
        // `scp` кладёт файлы от имени пользователя стенда, а распаковка — от
        // root, но с правами группы и остальных из рабочей копии. Нормализация
        // идёт тем же путём, что и снос каталога перед доставкой, — командой в
        // окружении.
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

    fn host(sudo: bool) -> HostConfig {
        HostConfig {
            address: "127.0.0.1".to_owned(),
            port: Some(2222),
            user: "bfs_admin".to_owned(),
            identity_file: Some("/keys/id".into()),
            ssh_options: vec!["StrictHostKeyChecking=accept-new".to_owned()],
            sudo,
        }
    }

    /// Корень стенда: родитель того каталога, куда приезжают хелперы.
    const STAND_ROOT: &str = "/opt/tessera-e2e";

    fn driver() -> SshDriver {
        SshDriver::new(
            host(false),
            Some(STAND_ROOT.to_owned()),
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn sudo_driver() -> SshDriver {
        SshDriver::new(
            host(true),
            Some(STAND_ROOT.to_owned()),
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn outcome(code: i32, stderr: &str) -> ProcessOutcome {
        ProcessOutcome {
            exit_code: Some(code),
            stdout: String::new(),
            stderr: stderr.to_owned(),
            timed_out: false,
            interrupted: false,
        }
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
        // Порт у scp — заглавная -P: строчная форма означает у него совсем
        // другое, и на нестандартном порте копирование ушло бы в 22-й.
        assert!(args.windows(2).any(|pair| pair == ["-P", "2222"]));
        assert!(!args.windows(2).any(|pair| pair == ["-p", "2222"]));
        assert!(args.contains(&"-r".to_owned()));
        assert_eq!(
            args.last().map(String::as_str),
            Some("bfs_admin@127.0.0.1:/opt/tessera-e2e/pkg/tessera.deb")
        );
        // Мультиплексирование отключено и здесь: лимит сессий Astra общий.
        assert!(args.contains(&"ControlMaster=no".to_owned()));
    }

    #[test]
    fn a_stand_with_sudo_unpacks_a_stream_instead_of_copying() {
        // scp с -p на Astra отвечает `remote fsetstat: Permission denied`:
        // в замкнутой программной среде непривилегированной учётной записи
        // запрещено выставлять бит исполнения. Распаковка идёт от root.
        let command = unpack_command("/opt/tessera-e2e", "helpers", "/opt/tessera-e2e/helpers");
        let line = sudo_driver().remote_command(&command);
        assert!(line.starts_with("sudo -n sh -c '"), "{line}");
        assert!(line.contains("tar --no-same-owner"), "{line}");
        assert!(line.contains(" -xf -"), "{line}");
    }

    #[test]
    fn the_stream_is_unpacked_beside_the_target_and_moved_into_place() {
        // Имя в архиве локальное, а цель зовётся по-своему: распаковка прямо в
        // родительский каталог затёрла бы соседа с совпавшим именем.
        let command = unpack_command(
            "/opt/tessera-e2e/pkg",
            "tessera_0.5.0_amd64.deb",
            "/opt/tessera-e2e/pkg/tessera.deb",
        );
        assert!(
            command.contains("mktemp -d -p '/opt/tessera-e2e/pkg'"),
            "{command}"
        );
        assert!(
            command.contains(
                r#"mv "$d"/'tessera_0.5.0_amd64.deb' '/opt/tessera-e2e/pkg/tessera.deb'"#
            ),
            "{command}"
        );
        // Оборванная распаковка не должна оставлять временный каталог в /opt.
        assert!(command.contains("trap 'rm -rf \"$d\"' EXIT"), "{command}");
        assert!(command.starts_with("set -e;"), "{command}");
    }

    #[test]
    fn a_stand_without_sudo_still_delivers_by_scp() {
        let driver = driver();
        let args = driver.scp_args(
            Path::new("/repo/tests/e2e/helpers"),
            "/opt/tessera-e2e/helpers",
        );
        assert_eq!(
            args.last().map(String::as_str),
            Some("bfs_admin@127.0.0.1:/opt/tessera-e2e/helpers")
        );
        // Без повышения прав в командной строке не появляется ни sudo, ни tar.
        let line = driver.remote_command("printf hi");
        assert_eq!(
            line,
            "sh -c 'cd '\\''/opt/tessera-e2e'\\'' 2>/dev/null; printf hi'"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_archive_carries_the_execute_bit_the_working_copy_has() {
        use std::os::unix::fs::PermissionsExt as _;

        // Ради этого доставка и переехала с scp на поток: хелпер обязан
        // приехать исполняемым, иначе подготовка падает кодом 126.
        let source = tempfile::tempdir().unwrap();
        std::fs::create_dir(source.path().join("helpers")).unwrap();
        let script = source.path().join("helpers/setup.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let archive = driver()
            .archive(source.path(), "helpers", Duration::from_secs(30))
            .unwrap();
        assert!(!archive.is_empty());

        let target = tempfile::tempdir().unwrap();
        let args = vec![
            "--no-same-owner".to_owned(),
            "-C".to_owned(),
            target.path().display().to_string(),
            "-xf".to_owned(),
            "-".to_owned(),
        ];
        let outcome = process::run_bytes(
            "tar",
            &args,
            Some(&archive),
            Duration::from_secs(30),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(outcome.exit_code, Some(0), "{outcome:?}");
        let mode = std::fs::metadata(target.path().join("helpers/setup.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755, "приехал режим {mode:o}");
    }

    #[test]
    fn scp_is_asked_to_keep_the_file_modes() {
        // В git хелперы лежат исполняемыми, а scp без -p создаёт файлы по
        // umask: приехавший без бита исполнения скрипт валит подготовку кодом
        // 126, и это читается как сломанный стенд без причины.
        let driver = driver();
        let args = driver.scp_args(
            Path::new("/repo/tests/e2e/helpers"),
            "/opt/tessera-e2e/helpers",
        );
        assert!(args.contains(&"-p".to_owned()), "{args:?}");
        // Флаг должен стоять сам по себе: приклеенный к нему номер порта
        // означал бы, что перепутаны регистры.
        let port_flags: Vec<&String> = args.iter().filter(|arg| *arg == "-p").collect();
        assert_eq!(port_flags.len(), 1, "{args:?}");
        assert!(
            args.windows(2).any(|pair| pair == ["-P", "2222"]),
            "{args:?}"
        );
    }

    #[test]
    fn ssh_keeps_the_lowercase_port_flag() {
        assert!(driver()
            .base_args()
            .windows(2)
            .any(|pair| pair == ["-p", "2222"]));
    }

    #[test]
    fn a_stand_without_sudo_sends_the_command_as_it_was() {
        let line = driver().remote_command("systemctl status tessera");
        assert!(line.ends_with("systemctl status tessera'"), "{line}");
        assert!(!line.contains("sudo"), "{line}");
    }

    #[test]
    fn a_step_runs_from_the_stand_root() {
        // Кейсы адресуют хелперы относительно корня стенда, а ssh начинает в
        // домашнем каталоге: там `helpers/config-mutate.sh` даёт код 127.
        // Переписывать реестр под транспорт нельзя, значит каталог задаёт он.
        for line in [
            driver().remote_command("helpers/config-mutate.sh unknown-field"),
            sudo_driver().remote_command("helpers/config-mutate.sh unknown-field"),
        ] {
            assert!(line.contains(r"cd '\''/opt/tessera-e2e'\''"), "{line}");
            assert!(
                line.ends_with("helpers/config-mutate.sh unknown-field'"),
                "{line}"
            );
        }
    }

    #[test]
    fn a_stand_without_a_known_root_sends_the_command_untouched() {
        // Корень известен не всегда: профиль может не задать переменную с
        // каталогом хелперов, и тогда шаг уходит ровно таким, как записан.
        let rootless = SshDriver::new(host(false), None, Arc::new(AtomicBool::new(false)));
        assert_eq!(
            rootless.remote_command("systemctl status tessera"),
            "sh -c 'systemctl status tessera'"
        );
    }

    #[test]
    fn the_step_shell_is_not_a_login_shell() {
        // Профиль входа на Astra печатает приветствие и напоминание про
        // активацию системы прямо в stdout шага, и кейс сравнивал бы с ним
        // своё ожидание.
        for line in [
            driver().remote_command("cat /etc/tessera/config.toml"),
            sudo_driver().remote_command("cat /etc/tessera/config.toml"),
            sudo_driver().remote_command(&unpack_command(
                "/opt/tessera-e2e",
                "helpers",
                "/opt/tessera-e2e/helpers",
            )),
        ] {
            assert!(line.contains("sh -c "), "{line}");
            assert!(!line.contains("sh -lc"), "{line}");
        }
    }

    #[test]
    fn sudo_runs_non_interactively() {
        // Пароль на прогоне спросить некому: без -n шаг завис бы на приглашении
        // и пришёл в отчёт таймаутом.
        let line = sudo_driver().remote_command("dpkg -i /opt/tessera-e2e/pkg/tessera.deb");
        assert!(line.starts_with("sudo -n "), "{line}");
    }

    #[test]
    fn sudo_covers_the_whole_step_not_just_its_first_word() {
        // Кейсы пишут конвейеры и перенаправления; повышение прав только у
        // головы конвейера меняло бы смысл шага.
        let line =
            sudo_driver().remote_command("helpers/usb-loop.sh attach | tee /var/log/attach.log");
        assert_eq!(
            line,
            "sudo -n sh -c 'cd '\\''/opt/tessera-e2e'\\'' 2>/dev/null; \
             helpers/usb-loop.sh attach | tee /var/log/attach.log'"
        );
        // Оболочка одна: конвейер целиком исполняется под sudo, а не только
        // его голова.
        assert_eq!(line.matches("sh -c").count(), 1);
    }

    #[test]
    fn a_quote_in_the_step_survives_the_sudo_wrapping() {
        let rootless = SshDriver::new(host(true), None, Arc::new(AtomicBool::new(false)));
        assert_eq!(
            rootless.remote_command("grep 'PAM_USER' /var/log/auth.log"),
            r"sudo -n sh -c 'grep '\''PAM_USER'\'' /var/log/auth.log'"
        );
    }

    #[test]
    fn a_sudo_refusal_is_named_instead_of_arriving_as_code_one() {
        let err = sudo_driver()
            .check_sudo(&outcome(1, "sudo: a password is required\n"))
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("sudo"), "{text}");
        assert!(text.contains("bfs_admin"), "{text}");
    }

    #[test]
    fn a_failing_step_is_not_mistaken_for_a_sudo_refusal() {
        // Ненулевой код — обычный результат шага, его интерпретирует кейс.
        sudo_driver()
            .check_sudo(&outcome(1, "dpkg: ошибка обработки архива"))
            .unwrap();
        driver()
            .check_sudo(&outcome(1, "sudo: a password is required"))
            .unwrap();
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
