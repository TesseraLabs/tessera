//! Параметры стенда: `~/.config/tessera-e2e/stand.toml`.
//!
//! Файл живёт вне git и хранит всё, что специфично для конкретной лаборатории:
//! адреса, пользователей, ключи, путь к проверяемому `.deb` и значения
//! переменных реестра. Пароли и PIN'ы задаются ссылками `op://…`, которые
//! раннер разрешает один раз на старте прогона.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Deserializer};

use crate::vars::Vars;

/// Образец файла, который печатается, если стенд не описан.
pub const SAMPLE: &str = r#"# Параметры стенда e2e. Файл вне git: здесь адреса и ссылки на секреты.
# Разместить как ~/.config/tessera-e2e/stand.toml

[package]
# Проверяется артефакт штатного пайплайна, а не сборка изнутри прогона.
deb = "/path/to/tessera_0.4.0_amd64.deb"
# Откуда взят пакет: локальный путь или идентификатор прогона build.yml.
source = "локальная сборка"
# Коммит, из которого собран артефакт. Если подтвердить нечем — не заполнять:
# прогон будет помечен как проведённый с неустановленным провенансом.
# commit = "0000000000000000000000000000000000000000"

# Что везётся в окружение помимо пакета: собранные отдельным пайплайном бинари,
# которых нет ни в .deb, ни в репозитории. Секция необязательная.
# [[artifacts]]
# path = "/path/to/issuer"
# target = "/usr/local/bin/issuer"
# mode = "0755"

[vars]
# Подставляются в шаги реестра как {{user}}, {{fixtures}}, {{pin}}.
user = "tester"
fixtures = "/opt/e2e/fixtures"
pin = "op://Development/Tessera E2E/pin"

# Хосты для ssh-профилей; имя таблицы совпадает с полем `ssh.host` профиля.
[hosts.astra-vm]
address = "127.0.0.1"
port = 2222
user = "bfs_admin"
identity_file = "~/.ssh/id_ed25519"
"#;

/// Ошибки чтения параметров стенда.
#[derive(Debug, thiserror::Error)]
pub enum StandError {
    /// Файла нет — прогон невозможен, печатаем образец.
    #[error("нет файла параметров стенда {path}")]
    Missing {
        /// Ожидаемый путь.
        path: PathBuf,
    },
    /// Файл не читается.
    #[error("не прочитать {path}: {source}")]
    Read {
        /// Путь.
        path: PathBuf,
        /// Причина.
        source: std::io::Error,
    },
    /// Файл не разбирается.
    #[error("{path}: разбор TOML: {source}")]
    Parse {
        /// Путь.
        path: PathBuf,
        /// Причина.
        source: toml::de::Error,
    },
    /// Не определить домашний каталог.
    #[error("не определить домашний каталог: задайте XDG_CONFIG_HOME или HOME")]
    NoHome,
    /// Хост, на который ссылается профиль, в стенде не описан.
    #[error("профиль ссылается на хост `{name}`, которого нет в stand.toml")]
    UnknownHost {
        /// Имя хоста.
        name: String,
    },
}

/// Ошибки разрешения ссылок на секреты.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// Внешняя команда не запустилась.
    #[error("хранилище секретов недоступно: не выполнить `{command}`: {source}")]
    Spawn {
        /// Команда.
        command: String,
        /// Причина.
        source: std::io::Error,
    },
    /// Команда вернула ошибку.
    #[error("хранилище секретов не отдало значение по ссылке {reference}: {detail}")]
    Denied {
        /// Ссылка (не секрет сама по себе).
        reference: String,
        /// Диагностика от хранилища.
        detail: String,
    },
    /// Ссылка разрешилась в пустое значение.
    #[error("ссылка {reference} разрешилась в пустое значение")]
    Empty {
        /// Ссылка.
        reference: String,
    },
}

/// Параметры стенда целиком.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandConfig {
    /// Проверяемый пакет.
    pub package: PackageConfig,
    /// Дополнительные артефакты стенда: то, что везётся в окружение помимо
    /// пакета. Секция необязательная.
    #[serde(default)]
    pub artifacts: Vec<ArtifactConfig>,
    /// Значения переменных реестра; значения вида `op://…` — ссылки на секреты.
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
    /// Хосты для ssh-профилей.
    #[serde(default)]
    pub hosts: BTreeMap<String, HostConfig>,
}

/// Описание проверяемого пакета.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageConfig {
    /// Путь к `.deb`.
    pub deb: PathBuf,
    /// Происхождение пакета в свободной форме либо идентификатор прогона `build.yml`.
    #[serde(default)]
    pub source: Option<String>,
    /// Коммит, из которого собран артефакт, если его есть чем подтвердить.
    #[serde(default)]
    pub commit: Option<String>,
}

/// Дополнительный артефакт стенда.
///
/// Место такого артефакта именно здесь: у бинарей со своим релизным пайплайном
/// нет ни места в `.deb`, ни места в репозитории, а путь к собранному файлу
/// у каждого стенда свой — профиль в git обязан оставаться безадресным.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactConfig {
    /// Путь к файлу на машине оператора.
    pub path: PathBuf,
    /// Куда положить в окружении; путь абсолютный.
    pub target: String,
    /// Права на файл после доставки. Владельца задаёт не стенд: доставленное
    /// всегда нормализуется до `root:root`.
    #[serde(default)]
    pub mode: FileMode,
}

/// Права на доставленный файл.
///
/// Отдельный тип, а не строка: неверная запись прав должна отбиваться разбором
/// `stand.toml`, а не всплывать ненулевым кодом `chmod` посреди прогона.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMode(u32);

impl FileMode {
    /// Права по умолчанию: файл читаем всеми, пишет только владелец.
    pub const DEFAULT: Self = Self(0o644);

    /// Разбирает восьмеричную запись прав вида `0755`.
    ///
    /// # Ошибки
    ///
    /// Всё, что не является записью из трёх-четырёх восьмеричных цифр.
    pub fn parse(text: &str) -> Result<Self, ModeError> {
        let trimmed = text.trim();
        let digits = trimmed.len();
        let octal = trimmed.bytes().all(|byte| (b'0'..=b'7').contains(&byte));
        if !(3..=4).contains(&digits) || !octal {
            return Err(ModeError {
                text: text.to_owned(),
            });
        }
        u32::from_str_radix(trimmed, 8)
            .map(Self)
            .map_err(|_| ModeError {
                text: text.to_owned(),
            })
    }
}

impl Default for FileMode {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for FileMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04o}", self.0)
    }
}

impl<'de> Deserialize<'de> for FileMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Неверная запись прав в `stand.toml`.
#[derive(Debug, thiserror::Error)]
#[error("права `{text}`: ожидаются три-четыре восьмеричные цифры, например \"0755\"")]
pub struct ModeError {
    /// Что было записано.
    text: String,
}

/// Доступ к машине по SSH.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    /// Адрес или имя.
    pub address: String,
    /// Порт; по умолчанию 22.
    #[serde(default)]
    pub port: Option<u16>,
    /// Пользователь.
    pub user: String,
    /// Приватный ключ.
    #[serde(default)]
    pub identity_file: Option<PathBuf>,
    /// Дополнительные опции `-o` для `ssh`.
    #[serde(default)]
    pub ssh_options: Vec<String>,
}

impl StandConfig {
    /// Канонический путь к файлу параметров стенда.
    ///
    /// # Ошибки
    ///
    /// [`StandError::NoHome`], если не определить ни `XDG_CONFIG_HOME`, ни `HOME`.
    pub fn default_path() -> Result<PathBuf, StandError> {
        if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
            return Ok(PathBuf::from(dir).join("tessera-e2e").join("stand.toml"));
        }
        let home = std::env::var_os("HOME").ok_or(StandError::NoHome)?;
        Ok(PathBuf::from(home)
            .join(".config")
            .join("tessera-e2e")
            .join("stand.toml"))
    }

    /// Читает параметры стенда.
    ///
    /// # Ошибки
    ///
    /// [`StandError::Missing`] — файла нет; вызывающий печатает [`SAMPLE`].
    /// Прочие варианты — ошибки чтения и разбора.
    pub fn load(path: &Path) -> Result<Self, StandError> {
        if !path.exists() {
            return Err(StandError::Missing {
                path: path.to_path_buf(),
            });
        }
        let text = std::fs::read_to_string(path).map_err(|source| StandError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| StandError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Возвращает описание хоста по имени.
    ///
    /// # Ошибки
    ///
    /// [`StandError::UnknownHost`], если профиль ссылается на неописанный хост.
    pub fn host(&self, name: &str) -> Result<&HostConfig, StandError> {
        self.hosts.get(name).ok_or_else(|| StandError::UnknownHost {
            name: name.to_owned(),
        })
    }
}

/// Признак ссылки на секрет.
#[must_use]
pub fn is_secret_reference(value: &str) -> bool {
    value.starts_with("op://")
}

/// Источник секретов.
pub trait SecretResolver {
    /// Разрешает одну ссылку.
    ///
    /// # Ошибки
    ///
    /// Любая недоступность хранилища; вызывающий обязан прервать прогон до
    /// первого кейса, а не превращать её в провал аутентификации.
    fn resolve(&self, reference: &str) -> Result<SecretString, SecretError>;
}

/// Разрешение ссылок через CLI 1Password.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpCli;

impl SecretResolver for OpCli {
    fn resolve(&self, reference: &str) -> Result<SecretString, SecretError> {
        let output = std::process::Command::new("op")
            .arg("read")
            .arg("--no-newline")
            .arg(reference)
            .output()
            .map_err(|source| SecretError::Spawn {
                command: "op read".to_owned(),
                source,
            })?;
        if !output.status.success() {
            return Err(SecretError::Denied {
                reference: reference.to_owned(),
                detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        let value = String::from_utf8_lossy(&output.stdout)
            .trim_end()
            .to_owned();
        if value.is_empty() {
            return Err(SecretError::Empty {
                reference: reference.to_owned(),
            });
        }
        Ok(SecretString::from(value))
    }
}

/// Превращает сырые значения `stand.toml` в набор переменных прогона,
/// разрешая все ссылки `op://` разом.
///
/// Ленивое разрешение в момент шага запрещено сознательно: недоступность
/// хранилища выглядела бы как провал аутентификации, а не как проблема стенда.
///
/// # Ошибки
///
/// Первая же неразрешённая ссылка прекращает подготовку прогона.
pub fn resolve_vars(
    raw: &BTreeMap<String, String>,
    resolver: &dyn SecretResolver,
) -> Result<Vars, SecretError> {
    let mut vars = Vars::new();
    // Одна и та же ссылка в нескольких переменных не должна дёргать хранилище
    // дважды: лишние обращения замедляют старт и шумят в аудите 1Password.
    // Кэш держит значения в Zeroizing, чтобы они не пережили подготовку прогона.
    let mut cache: BTreeMap<&str, zeroize::Zeroizing<String>> = BTreeMap::new();
    for (name, value) in raw {
        if is_secret_reference(value) {
            if !cache.contains_key(value.as_str()) {
                let from_store = resolver.resolve(value)?;
                cache.insert(
                    value.as_str(),
                    zeroize::Zeroizing::new(from_store.expose_secret().to_owned()),
                );
            }
            let cached = cache
                .get(value.as_str())
                .ok_or_else(|| SecretError::Empty {
                    reference: value.clone(),
                })?;
            vars.insert_secret(name.clone(), SecretString::from((**cached).clone()));
        } else {
            vars.insert_plain(name.clone(), value.clone());
        }
    }
    Ok(vars)
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

    #[derive(Default)]
    struct FakeStore {
        calls: RefCell<Vec<String>>,
        fail: bool,
    }

    impl SecretResolver for FakeStore {
        fn resolve(&self, reference: &str) -> Result<SecretString, SecretError> {
            self.calls.borrow_mut().push(reference.to_owned());
            if self.fail {
                return Err(SecretError::Denied {
                    reference: reference.to_owned(),
                    detail: "не авторизовано".to_owned(),
                });
            }
            Ok(SecretString::from(format!("значение-{reference}")))
        }
    }

    fn raw() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("user".to_owned(), "tester".to_owned()),
            ("pin".to_owned(), "op://Dev/Tessera/pin".to_owned()),
            ("second_pin".to_owned(), "op://Dev/Tessera/pin".to_owned()),
        ])
    }

    #[test]
    fn sample_is_valid_toml() {
        let config: StandConfig = toml::from_str(SAMPLE).unwrap();
        assert!(config.vars.contains_key("pin"));
        assert_eq!(config.hosts["astra-vm"].port, Some(2222));
        assert!(config.package.commit.is_none());
    }

    #[test]
    fn a_stand_without_extra_artifacts_stays_valid() {
        let config: StandConfig = toml::from_str(SAMPLE).unwrap();
        assert!(config.artifacts.is_empty());
    }

    #[test]
    fn extra_artifacts_are_read_with_their_target_and_mode() {
        let config: StandConfig = toml::from_str(
            r#"
[package]
deb = "/art/tessera_0.4.0_amd64.deb"

[[artifacts]]
path = "/build/issuer"
target = "/usr/local/bin/issuer"
mode = "0755"

[[artifacts]]
path = "/build/policy.json"
target = "/etc/tessera/policy.json"
"#,
        )
        .unwrap();
        assert_eq!(config.artifacts.len(), 2);
        assert_eq!(config.artifacts[0].path, PathBuf::from("/build/issuer"));
        assert_eq!(config.artifacts[0].target, "/usr/local/bin/issuer");
        assert_eq!(config.artifacts[0].mode.to_string(), "0755");
        // Права необязательны: без них файл читаем всеми, пишет только владелец.
        assert_eq!(config.artifacts[1].mode, FileMode::DEFAULT);
        assert_eq!(config.artifacts[1].mode.to_string(), "0644");
    }

    #[test]
    fn a_malformed_mode_is_rejected_by_the_parser() {
        // Опечатка в правах обязана отбиваться разбором stand.toml: ненулевой
        // код chmod посреди прогона выглядел бы как сбой стенда без причины.
        for text in ["rwxr-xr-x", "0o755", "0778", "75", "07555", ""] {
            assert!(FileMode::parse(text).is_err(), "принято `{text}`");
        }
        assert_eq!(FileMode::parse("755").unwrap().to_string(), "0755");
        assert_eq!(FileMode::parse(" 0640 ").unwrap().to_string(), "0640");

        let err = toml::from_str::<StandConfig>(
            r#"
[package]
deb = "/art/tessera.deb"

[[artifacts]]
path = "/build/issuer"
target = "/usr/local/bin/issuer"
mode = "rwxr-xr-x"
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("восьмеричные"), "{err}");
    }

    #[test]
    fn references_are_recognised_by_scheme() {
        assert!(is_secret_reference("op://Dev/Item/field"));
        assert!(!is_secret_reference("/opt/e2e/fixtures"));
    }

    #[test]
    fn secret_references_are_resolved_once_per_reference() {
        let store = FakeStore::default();
        let vars = resolve_vars(&raw(), &store).unwrap();
        assert_eq!(store.calls.borrow().len(), 1);
        assert_eq!(vars.secret_names(), vec!["pin", "second_pin"]);
        assert_eq!(
            vars.substitute("{{user}}:{{pin}}").unwrap(),
            "tester:значение-op://Dev/Tessera/pin"
        );
    }

    #[test]
    fn store_failure_stops_preparation() {
        let store = FakeStore {
            fail: true,
            ..FakeStore::default()
        };
        let err = resolve_vars(&raw(), &store).unwrap_err();
        assert!(err.to_string().contains("хранилище секретов"), "{err}");
    }

    #[test]
    fn plain_values_do_not_touch_the_store() {
        let store = FakeStore::default();
        let raw = BTreeMap::from([("user".to_owned(), "tester".to_owned())]);
        let vars = resolve_vars(&raw, &store).unwrap();
        assert!(store.calls.borrow().is_empty());
        assert!(vars.secret_values().is_empty());
    }

    #[test]
    fn missing_file_is_reported_as_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stand.toml");
        assert!(matches!(
            StandConfig::load(&path),
            Err(StandError::Missing { .. })
        ));
    }

    #[test]
    fn unknown_host_is_reported_with_its_name() {
        let config: StandConfig = toml::from_str(SAMPLE).unwrap();
        let err = config.host("нет-такого").unwrap_err();
        assert!(err.to_string().contains("нет-такого"), "{err}");
        assert_eq!(config.host("astra-vm").unwrap().user, "bfs_admin");
    }
}
