//! Драйверы исполнения команд в целевом окружении.
//!
//! Драйвер знает единственную вещь — как выполнить строку команды на целевой
//! стороне и вернуть её потоки. Проверки файлов и журнала строятся поверх этого
//! примитива, поэтому новый транспорт не тянет за собой новых сортов шагов.

pub mod docker;
pub mod process;
pub mod ssh;

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use crate::profile::{DriverKind, Profile};
use crate::stand::StandConfig;

pub use process::ProcessOutcome;

/// Ошибки транспорта. От провала кейса отличаются принципиально: продукт тут
/// ни при чём, сломан стенд.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// Внешнюю команду не запустить.
    #[error("не выполнить `{command}`: {source}")]
    Spawn {
        /// Что запускали.
        command: String,
        /// Причина.
        source: std::io::Error,
    },
    /// Служебная операция драйвера завершилась ошибкой.
    #[error("{operation}: код {code}\n{detail}")]
    Failed {
        /// Что делали.
        operation: String,
        /// Код возврата.
        code: i32,
        /// Диагностика.
        detail: String,
    },
    /// Операция не поддерживается этим драйвером.
    #[error("{0}")]
    Unsupported(String),
    /// Профиль ссылается на то, чего нет в стенде.
    #[error(transparent)]
    Stand(#[from] crate::stand::StandError),
}

/// Транспорт до целевого окружения.
pub trait CommandDriver {
    /// Как окружение выглядит в отчёте.
    fn describe(&self) -> String;

    /// Выполняет команду на целевой стороне.
    ///
    /// # Ошибки
    ///
    /// [`DriverError`] — если не удалось даже запустить транспорт. Ненулевой
    /// код возврата самой команды ошибкой не считается.
    fn exec(
        &self,
        command: &str,
        stdin: Option<&str>,
        timeout: Duration,
    ) -> Result<ProcessOutcome, DriverError>;

    /// Кладёт локальный файл или каталог в окружение ровно по указанному пути.
    ///
    /// Доставка нужна потому, что путь к `.deb` живёт в `stand.toml` и у каждого
    /// стенда свой, а профиль в git обязан быть безадресным; сборочный контекст
    /// репозитория для этого не годится.
    ///
    /// Реализация обязана оставить доставленное в том же виде, в каком оно
    /// лежало бы на настоящей машине: владелец `root:root`, запись только у
    /// владельца — см. [`restore_root_ownership`].
    ///
    /// # Ошибки
    ///
    /// Ошибки транспорта, ненулевой код копирования и ненулевой код
    /// нормализации владельца.
    fn deliver(&self, local: &Path, remote: &str, timeout: Duration) -> Result<(), DriverError>;

    /// Пересоздаёт окружение с нуля.
    ///
    /// # Ошибки
    ///
    /// [`DriverError::Unsupported`] для окружений, которые нельзя пересоздать
    /// автоматически, и ошибки самих операций пересоздания.
    fn recreate(&self) -> Result<(), DriverError>;
}

/// Собирает драйвер по профилю и параметрам стенда.
///
/// # Ошибки
///
/// Несогласованность профиля и стенда: объявленный транспорт без своей секции
/// или ссылка на неописанный хост.
pub fn build(
    profile: &Profile,
    stand: &StandConfig,
    repo_root: &Path,
    interrupt: Arc<AtomicBool>,
) -> Result<Box<dyn CommandDriver>, DriverError> {
    match profile.driver {
        DriverKind::Docker => {
            let mut config = profile.docker.clone().ok_or_else(|| {
                DriverError::Unsupported(format!("профиль {}: нет секции [docker]", profile.name))
            })?;
            // Пути сборки образа профиль задаёт от корня репозитория, а рабочий
            // каталог процесса задаёт тот, кто запустил `cargo xtask`; без
            // приведения к абсолютным запуск из подкаталога ломал бы сборку.
            config.dockerfile = config.dockerfile.map(|path| absolutise(repo_root, &path));
            config.context = config.context.map(|path| absolutise(repo_root, &path));
            Ok(Box::new(docker::DockerDriver::new(config, interrupt)))
        }
        DriverKind::Ssh => {
            let config = profile.ssh.clone().ok_or_else(|| {
                DriverError::Unsupported(format!("профиль {}: нет секции [ssh]", profile.name))
            })?;
            let mut host = stand.host(&config.host)?.clone();
            // `ssh` получает аргументы напрямую, без шелла, поэтому `~` в пути
            // к ключу никто не раскроет — сделаем это сами.
            host.identity_file = host.identity_file.map(|path| expand_tilde(&path));
            Ok(Box::new(ssh::SshDriver::new(host, interrupt)))
        }
    }
}

/// Готовит место под доставку: сносит прежнее содержимое и создаёт родительский
/// каталог.
///
/// Снос обязателен: и `docker cp`, и `scp` кладут каталог ВНУТРЬ цели, если та
/// уже существует, и НА место цели, если её нет. Без сноса второй прогон дал бы
/// `/opt/tessera-e2e/fixtures/fixtures`.
///
/// # Ошибки
///
/// Ошибки транспорта и ненулевой код подготовки каталога.
pub fn clear_remote_path(
    driver: &dyn CommandDriver,
    remote: &str,
    timeout: Duration,
) -> Result<(), DriverError> {
    let parent = remote_parent(remote);
    let command = format!("rm -rf '{remote}' && mkdir -p '{parent}'");
    let outcome = driver.exec(&command, None, timeout)?;
    if outcome.exit_code == Some(0) {
        return Ok(());
    }
    Err(DriverError::Failed {
        operation: format!("подготовка каталога {parent}"),
        code: outcome.exit_code.unwrap_or(-1),
        detail: outcome.stderr,
    })
}

/// Приводит доставленное к тому виду, в каком оно лежало бы на настоящей
/// машине: владелец `root:root`, запись только у владельца.
///
/// Без этого шага стенд подсовывает продукту материал доверия (якоря, CRL),
/// подконтрольный непривилегированному пользователю: `docker cp` сохраняет
/// владельца с машины оператора, `scp` — пользователя стенда. Продукт такой
/// материал отвергает, и по делу, — но отказ описывает дефект стенда, а не
/// поведение продукта.
///
/// # Ошибки
///
/// Ошибки транспорта и ненулевой код нормализации.
pub fn restore_root_ownership(
    driver: &dyn CommandDriver,
    remote: &str,
    timeout: Duration,
) -> Result<(), DriverError> {
    let command = format!("chown -R root:root '{remote}' && chmod -R go-w '{remote}'");
    let outcome = driver.exec(&command, None, timeout)?;
    if outcome.exit_code == Some(0) {
        return Ok(());
    }
    Err(DriverError::Failed {
        operation: format!("нормализация владельца {remote}"),
        code: outcome.exit_code.unwrap_or(-1),
        detail: outcome.stderr,
    })
}

/// Выставляет доставленному файлу заданные стендом права.
///
/// Отдельным шагом после доставки: транспорт переносит права с машины
/// оператора, а нормализация владельца знает только про запись группы и
/// остальных. Бинарь, приехавший без бита исполнения, провалил бы кейсы так,
/// будто продукт сломан.
///
/// # Ошибки
///
/// Ошибки транспорта и ненулевой код `chmod`.
pub fn apply_mode(
    driver: &dyn CommandDriver,
    remote: &str,
    mode: &str,
    timeout: Duration,
) -> Result<(), DriverError> {
    let command = format!("chmod {mode} '{remote}'");
    let outcome = driver.exec(&command, None, timeout)?;
    if outcome.exit_code == Some(0) {
        return Ok(());
    }
    Err(DriverError::Failed {
        operation: format!("права {mode} на {remote}"),
        code: outcome.exit_code.unwrap_or(-1),
        detail: outcome.stderr,
    })
}

/// Родительский каталог пути в целевом окружении.
#[must_use]
pub fn remote_parent(remote: &str) -> &str {
    match remote.trim_end_matches('/').rsplit_once('/') {
        Some(("", _)) | None => "/",
        Some((head, _)) => head,
    }
}

/// Приводит путь профиля к абсолютному относительно корня репозитория.
fn absolutise(repo_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root.join(path)
    }
}

/// Раскрывает ведущий `~/` в пути.
fn expand_tilde(path: &Path) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path.to_path_buf();
    };
    let Some(rest) = text.strip_prefix("~/") else {
        return path.to_path_buf();
    };
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(rest),
        None => path.to_path_buf(),
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
    use std::cell::RefCell;

    use super::*;

    /// Драйвер-заглушка: пишет команды и отвечает заданным кодом.
    struct FakeDriver {
        log: RefCell<Vec<String>>,
        code: i32,
    }

    impl CommandDriver for FakeDriver {
        fn describe(&self) -> String {
            "fake://".to_owned()
        }

        fn exec(
            &self,
            command: &str,
            _stdin: Option<&str>,
            _timeout: Duration,
        ) -> Result<ProcessOutcome, DriverError> {
            self.log.borrow_mut().push(command.to_owned());
            Ok(ProcessOutcome {
                exit_code: Some(self.code),
                stdout: String::new(),
                stderr: "нет прав".to_owned(),
                timed_out: false,
                interrupted: false,
            })
        }

        fn deliver(&self, _local: &Path, _remote: &str, _t: Duration) -> Result<(), DriverError> {
            Ok(())
        }

        fn recreate(&self) -> Result<(), DriverError> {
            Ok(())
        }
    }

    #[test]
    fn the_target_is_wiped_before_delivery() {
        let driver = FakeDriver {
            log: RefCell::new(Vec::new()),
            code: 0,
        };
        clear_remote_path(&driver, "/opt/tessera-e2e/fixtures", Duration::from_secs(1)).unwrap();
        // Без сноса второй прогон дал бы /opt/tessera-e2e/fixtures/fixtures:
        // и docker cp, и scp кладут каталог ВНУТРЬ существующей цели.
        assert_eq!(
            driver.log.borrow().as_slice(),
            ["rm -rf '/opt/tessera-e2e/fixtures' && mkdir -p '/opt/tessera-e2e'"]
        );
    }

    #[test]
    fn a_failed_wipe_is_reported_with_its_code() {
        let driver = FakeDriver {
            log: RefCell::new(Vec::new()),
            code: 1,
        };
        let err = clear_remote_path(
            &driver,
            "/opt/tessera-e2e/pkg/tessera.deb",
            Duration::from_secs(1),
        )
        .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("/opt/tessera-e2e/pkg"), "{text}");
        assert!(text.contains("нет прав"), "{text}");
    }

    #[test]
    fn delivered_material_is_handed_over_root_owned_and_not_group_writable() {
        let driver = FakeDriver {
            log: RefCell::new(Vec::new()),
            code: 0,
        };
        restore_root_ownership(&driver, "/opt/tessera-e2e/fixtures", Duration::from_secs(1))
            .unwrap();
        // Материал доверия, подконтрольный непривилегированному пользователю,
        // продукт отвергает: транспорт обязан снять и владельца, и запись.
        assert_eq!(
            driver.log.borrow().as_slice(),
            ["chown -R root:root '/opt/tessera-e2e/fixtures' \
              && chmod -R go-w '/opt/tessera-e2e/fixtures'"]
        );
    }

    #[test]
    fn a_delivered_binary_gets_the_mode_the_stand_asked_for() {
        let driver = FakeDriver {
            log: RefCell::new(Vec::new()),
            code: 0,
        };
        apply_mode(
            &driver,
            "/usr/local/bin/issuer",
            "0755",
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            driver.log.borrow().as_slice(),
            ["chmod 0755 '/usr/local/bin/issuer'"]
        );
    }

    #[test]
    fn a_failed_chmod_is_reported_as_a_stand_failure() {
        let driver = FakeDriver {
            log: RefCell::new(Vec::new()),
            code: 1,
        };
        let err = apply_mode(
            &driver,
            "/usr/local/bin/issuer",
            "0755",
            Duration::from_secs(1),
        )
        .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("/usr/local/bin/issuer"), "{text}");
        assert!(text.contains("нет прав"), "{text}");
    }

    #[test]
    fn a_failed_normalisation_is_reported_as_a_stand_failure() {
        let driver = FakeDriver {
            log: RefCell::new(Vec::new()),
            code: 1,
        };
        let err = restore_root_ownership(
            &driver,
            "/opt/tessera-e2e/pkg/tessera.deb",
            Duration::from_secs(1),
        )
        .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("/opt/tessera-e2e/pkg/tessera.deb"), "{text}");
        assert!(text.contains("нет прав"), "{text}");
    }

    #[test]
    fn profile_paths_become_absolute_against_the_repo_root() {
        let root = Path::new("/ws/tessera");
        assert_eq!(
            absolutise(root, Path::new("tests/e2e/images/ubuntu.Dockerfile")),
            PathBuf::from("/ws/tessera/tests/e2e/images/ubuntu.Dockerfile")
        );
        assert_eq!(
            absolutise(root, Path::new("/abs/path")),
            PathBuf::from("/abs/path")
        );
    }

    #[test]
    fn the_parent_of_a_remote_path_is_derived_without_touching_the_filesystem() {
        assert_eq!(
            remote_parent("/opt/tessera-e2e/pkg/tessera.deb"),
            "/opt/tessera-e2e/pkg"
        );
        assert_eq!(
            remote_parent("/opt/tessera-e2e/fixtures"),
            "/opt/tessera-e2e"
        );
        // Хвостовой слэш не должен превращать каталог в его же родителя.
        assert_eq!(
            remote_parent("/opt/tessera-e2e/fixtures/"),
            "/opt/tessera-e2e"
        );
        assert_eq!(remote_parent("/opt"), "/");
        assert_eq!(remote_parent("tessera.deb"), "/");
    }

    #[test]
    fn a_leading_tilde_in_the_key_path_is_expanded() {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let expanded = expand_tilde(Path::new("~/.ssh/tessera-lab"));
        match home {
            Some(home) => assert_eq!(expanded, home.join(".ssh/tessera-lab")),
            None => assert_eq!(expanded, PathBuf::from("~/.ssh/tessera-lab")),
        }
        assert_eq!(
            expand_tilde(Path::new("/keys/id")),
            PathBuf::from("/keys/id")
        );
        // `~user` мы не раскрываем: это отдельный синтаксис, и молча подменять
        // его домашним каталогом текущего пользователя было бы неверно.
        assert_eq!(
            expand_tilde(Path::new("~other/.ssh/id")),
            PathBuf::from("~other/.ssh/id")
        );
    }
}
