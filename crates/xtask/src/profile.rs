//! Профили окружения и сопоставление их возможностей с требованиями кейса.
//!
//! Профиль описывает тип окружения и то, что оно умеет; какие адреса и ключи
//! за этим стоят — дело `stand.toml`. Разделение позволяет держать профили в
//! git, не раскрывая лабораторию.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Ошибки загрузки профиля.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    /// Профиля с таким именем нет.
    #[error("нет профиля {name}: ожидался файл {path}")]
    Missing {
        /// Имя профиля.
        name: String,
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
    /// Профиль неполон.
    #[error("профиль {name}: {detail}")]
    Invalid {
        /// Имя профиля.
        name: String,
        /// Что именно не так.
        detail: String,
    },
}

/// Каким транспортом раннер добирается до окружения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DriverKind {
    /// Контейнер, команды через `docker exec`.
    Docker,
    /// Машина, команды через системный `ssh`.
    Ssh,
}

/// Профиль окружения.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Имя профиля; совпадает с именем файла без расширения.
    pub name: String,
    /// Человекочитаемое описание.
    #[serde(default)]
    pub description: Option<String>,
    /// Транспорт.
    pub driver: DriverKind,
    /// Возможности окружения: `usb`, `mac`, `graphics`, `hardware-token`,
    /// `service-manager`.
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    /// Переменные, специфичные для окружения (например `fixtures`).
    /// Значения `stand.toml` их перекрывают: лаборатория всегда знает лучше.
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
    /// Таймаут шага по умолчанию, секунды.
    #[serde(default)]
    pub default_timeout: Option<u64>,
    /// Каталог с фикстурами, который раннер доставляет в окружение перед
    /// первым действием подготовки; путь от корня репозитория.
    ///
    /// Поле, а не константа: приватный реестр возит свои фикстуры, и жёстко
    /// зашитый путь закрыл бы ему дорогу.
    #[serde(default)]
    pub fixtures_source: Option<PathBuf>,
    /// Служебные коды возврата хелперов образа: такой код означает, что сломан
    /// стенд, а не продукт, и даёт шагу `ERROR` вместо `FAIL`.
    ///
    /// Набор задаётся профилем, а не кейсом: коды принадлежат хелперам образа,
    /// а образ — часть профиля. Знай о них кейс, реестр начал бы кодировать
    /// устройство стенда вместо проверяемой гарантии.
    #[serde(default)]
    pub error_exit_codes: Vec<i32>,
    /// Параметры контейнерного профиля.
    #[serde(default)]
    pub docker: Option<DockerProfile>,
    /// Параметры профиля по SSH.
    #[serde(default)]
    pub ssh: Option<SshProfile>,
}

/// Параметры контейнерного окружения.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerProfile {
    /// Имя контейнера прогона.
    pub container: String,
    /// Тег образа.
    pub image: String,
    /// Dockerfile для сборки образа при `--recreate`; путь от корня репозитория.
    #[serde(default)]
    pub dockerfile: Option<PathBuf>,
    /// Каталог сборочного контекста; путь от корня репозитория.
    #[serde(default)]
    pub context: Option<PathBuf>,
    /// Платформа образа, например `linux/amd64`.
    #[serde(default)]
    pub platform: Option<String>,
    /// Аргументы `docker run` помимо имени и образа.
    #[serde(default)]
    pub run_args: Vec<String>,
    /// Команда, успешное завершение которой означает готовность контейнера.
    #[serde(default)]
    pub ready_command: Option<String>,
}

/// Параметры окружения по SSH.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshProfile {
    /// Имя хоста в `[hosts.…]` файла `stand.toml`.
    pub host: String,
}

impl Profile {
    /// Загружает профиль по имени из каталога профилей.
    ///
    /// # Ошибки
    ///
    /// Отсутствие файла, ошибка чтения или разбора, а также несоответствие
    /// секции транспорта объявленному драйверу.
    pub fn load(dir: &Path, name: &str) -> Result<Self, ProfileError> {
        let path = dir.join(format!("{name}.toml"));
        if !path.exists() {
            return Err(ProfileError::Missing {
                name: name.to_owned(),
                path,
            });
        }
        let text = std::fs::read_to_string(&path).map_err(|source| ProfileError::Read {
            path: path.clone(),
            source,
        })?;
        let profile: Self = toml::from_str(&text).map_err(|source| ProfileError::Parse {
            path: path.clone(),
            source,
        })?;
        profile.validate()?;
        Ok(profile)
    }

    fn validate(&self) -> Result<(), ProfileError> {
        let detail = match self.driver {
            DriverKind::Docker if self.docker.is_none() => Some("нет секции [docker]"),
            DriverKind::Ssh if self.ssh.is_none() => Some("нет секции [ssh]"),
            _ => None,
        };
        match detail {
            Some(detail) => Err(ProfileError::Invalid {
                name: self.name.clone(),
                detail: detail.to_owned(),
            }),
            None => Ok(()),
        }
    }

    /// Возможности, которых профиль не даёт.
    #[must_use]
    pub fn missing_capabilities(&self, requires: &[String]) -> Vec<String> {
        missing_capabilities(requires, &self.capabilities)
    }

    /// Каталог фикстур, приведённый к абсолютному пути.
    ///
    /// По умолчанию — фикстуры ядра: те же удостоверения, на которых стоят
    /// unit-тесты, чтобы e2e и unit проверяли систему на одном материале.
    #[must_use]
    pub fn fixtures_source_path(&self, repo_root: &Path) -> PathBuf {
        let relative = self
            .fixtures_source
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_FIXTURES_SOURCE));
        if relative.is_absolute() {
            relative
        } else {
            repo_root.join(relative)
        }
    }

    /// Означает ли код возврата сбой стенда, а не вердикт продукта.
    ///
    /// Явное ожидание кейса сильнее: кейс, который проверяет сам хелпер и ждёт
    /// от него служебный код, должен проходить, а не падать с `ERROR`.
    #[must_use]
    pub fn is_stand_failure(&self, actual: Option<i32>, expected: i32) -> bool {
        actual.is_some_and(|code| code != expected && self.error_exit_codes.contains(&code))
    }
}

/// Каталог фикстур по умолчанию, если профиль не задал свой.
pub const DEFAULT_FIXTURES_SOURCE: &str = "crates/tessera_core/tests/fixtures";

/// Возможности из `requires`, которых нет в наборе профиля.
#[must_use]
pub fn missing_capabilities(requires: &[String], available: &BTreeSet<String>) -> Vec<String> {
    requires
        .iter()
        .filter(|required| !available.contains(*required))
        .cloned()
        .collect()
}

/// Причина пропуска для отчёта. Молчаливый пропуск запрещён: пропущенный кейс
/// не должен выглядеть как пройденный.
#[must_use]
pub fn skip_reason(missing: &[String]) -> String {
    format!("profile has no {}", missing.join(", "))
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

    const DOCKER_PROFILE: &str = r#"
name = "ubuntu-container"
driver = "docker"
capabilities = ["usb", "service-manager"]

[docker]
container = "tessera-e2e-ubuntu"
image = "tessera-e2e/ubuntu:24.04"
"#;

    fn caps(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    fn requires(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn satisfied_requirements_leave_nothing_missing() {
        let available = caps(&["usb", "service-manager"]);
        assert!(missing_capabilities(&requires(&["usb"]), &available).is_empty());
        assert!(missing_capabilities(&[], &available).is_empty());
    }

    #[test]
    fn missing_capability_yields_reason_naming_it() {
        let available = caps(&["usb", "service-manager"]);
        let missing = missing_capabilities(&requires(&["mac"]), &available);
        assert_eq!(missing, vec!["mac".to_owned()]);
        assert_eq!(skip_reason(&missing), "profile has no mac");
    }

    #[test]
    fn several_missing_capabilities_are_all_named() {
        let missing = missing_capabilities(&requires(&["mac", "graphics"]), &caps(&["usb"]));
        assert_eq!(skip_reason(&missing), "profile has no mac, graphics");
    }

    #[test]
    fn a_service_exit_code_of_a_helper_is_a_stand_failure() {
        // Ключ верхнего уровня вставляется перед секцией [docker]: допиши его
        // в конец, TOML отнёс бы его к этой секции.
        let text =
            DOCKER_PROFILE.replace("\n[docker]", "\nerror_exit_codes = [64, 70]\n\n[docker]");
        let profile: Profile = toml::from_str(&text).unwrap();
        // Настоящие коды PAM остаются вердиктом продукта.
        assert!(!profile.is_stand_failure(Some(7), 0));
        assert!(!profile.is_stand_failure(Some(0), 0));
        assert!(!profile.is_stand_failure(None, 0));
        // Служебные коды хелпера — сбой стенда.
        assert!(profile.is_stand_failure(Some(64), 0));
        assert!(profile.is_stand_failure(Some(70), 0));
        // Кроме случая, когда кейс проверяет сам хелпер и именно этого и ждёт.
        assert!(!profile.is_stand_failure(Some(64), 64));
    }

    #[test]
    fn fixtures_source_defaults_to_the_core_fixtures() {
        let profile: Profile = toml::from_str(DOCKER_PROFILE).unwrap();
        assert_eq!(
            profile.fixtures_source_path(Path::new("/ws/tessera")),
            PathBuf::from("/ws/tessera/crates/tessera_core/tests/fixtures")
        );
    }

    #[test]
    fn a_profile_may_bring_its_own_fixtures() {
        let text = DOCKER_PROFILE.replace(
            "\n[docker]",
            "\nfixtures_source = \"tests/e2e-private/fixtures\"\n\n[docker]",
        );
        let profile: Profile = toml::from_str(&text).unwrap();
        assert_eq!(
            profile.fixtures_source_path(Path::new("/ws/tessera")),
            PathBuf::from("/ws/tessera/tests/e2e-private/fixtures")
        );
    }

    #[test]
    fn an_absolute_fixtures_source_is_taken_as_is() {
        let text = DOCKER_PROFILE.replace(
            "\n[docker]",
            "\nfixtures_source = \"/srv/lab/fixtures\"\n\n[docker]",
        );
        let profile: Profile = toml::from_str(&text).unwrap();
        assert_eq!(
            profile.fixtures_source_path(Path::new("/ws/tessera")),
            PathBuf::from("/srv/lab/fixtures")
        );
    }

    #[test]
    fn a_profile_without_the_field_keeps_the_previous_behaviour() {
        let profile: Profile = toml::from_str(DOCKER_PROFILE).unwrap();
        assert!(profile.error_exit_codes.is_empty());
        assert!(!profile.is_stand_failure(Some(70), 0));
    }

    #[test]
    fn docker_profile_parses_and_validates() {
        let profile: Profile = toml::from_str(DOCKER_PROFILE).unwrap();
        assert_eq!(profile.driver, DriverKind::Docker);
        profile.validate().unwrap();
        assert_eq!(
            profile.missing_capabilities(&requires(&["mac"])),
            vec!["mac".to_owned()]
        );
    }

    /// Профили в репозитории — контракт между раннером и автором окружений:
    /// `deny_unknown_fields` не прощает опечатку, и ловить её нужно здесь,
    /// а не на стенде посреди прогона.
    #[test]
    fn every_profile_in_the_repository_parses() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/e2e/profiles");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            // Каталог профилей появляется вместе с образами и хелперами;
            // до этого проверять нечего.
            return;
        };
        let mut checked = 0_usize;
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if !path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
            {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            // Образцы вроде `stand.toml.example` лежат рядом, но профилями
            // не являются: у профиля имя файла — это имя профиля.
            if stem.contains('.') {
                continue;
            }
            let profile =
                Profile::load(&dir, stem).unwrap_or_else(|err| panic!("профиль {stem}: {err}"));
            assert_eq!(
                profile.name, stem,
                "имя профиля должно совпадать с именем файла"
            );
            checked += 1;
        }
        assert!(
            checked > 0,
            "в {} не нашлось ни одного профиля",
            dir.display()
        );
    }

    #[test]
    fn driver_without_its_section_is_rejected() {
        let profile: Profile = toml::from_str(
            r#"
name = "astra-vm"
driver = "ssh"
"#,
        )
        .unwrap();
        let err = profile.validate().unwrap_err().to_string();
        assert!(err.contains("[ssh]"), "{err}");
    }
}
