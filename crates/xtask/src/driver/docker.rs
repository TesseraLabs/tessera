//! Драйвер контейнерного профиля: команды через `docker exec`.
//!
//! Пересоздание контейнера — дешёвый эквивалент отката снапшота, поэтому
//! чистота контейнерного окружения достигается им, а не внешним VMM.

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use super::{process, CommandDriver, DriverError, ProcessOutcome};
use crate::profile::DockerProfile;

/// Сколько ждать служебные операции docker (build, run, проверка готовности).
const SERVICE_TIMEOUT: Duration = Duration::from_mins(10);

/// Сколько ждать проверку наличия плагина buildx: она ничего не собирает и
/// обязана отвечать сразу.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// Драйвер контейнера.
pub struct DockerDriver {
    config: DockerProfile,
    interrupt: Arc<AtomicBool>,
}

impl DockerDriver {
    /// Создаёт драйвер для описанного профилем контейнера.
    #[must_use]
    pub fn new(config: DockerProfile, interrupt: Arc<AtomicBool>) -> Self {
        Self { config, interrupt }
    }

    fn docker(
        &self,
        operation: &str,
        args: &[String],
        timeout: Duration,
    ) -> Result<ProcessOutcome, DriverError> {
        process::run("docker", args, None, timeout, &self.interrupt).map_err(|source| {
            DriverError::Spawn {
                command: format!("docker {operation}"),
                source,
            }
        })
    }

    /// Убеждается, что плагин buildx на месте, до того как что-то собирать.
    ///
    /// Проверка вынесена вперёд сознательно: без неё отсутствие плагина
    /// всплывает уже посреди прогона и в виде отказа сборки, из которого не
    /// видно, что чинить.
    fn ensure_buildx(&self) -> Result<(), DriverError> {
        let outcome = self.docker(
            "buildx version",
            &owned(&["buildx", "version"]),
            PROBE_TIMEOUT,
        )?;
        if outcome.exit_code == Some(0) {
            return Ok(());
        }
        Err(DriverError::Unsupported(format!(
            "сборка образа требует плагина docker buildx: `docker buildx version` вернул код {}. \
             Установите плагин (docker-buildx) — legacy-сборщик здесь не годится. {}",
            outcome.exit_code.unwrap_or(-1),
            outcome.stderr.trim()
        )))
    }

    fn docker_checked(&self, operation: &str, args: &[String]) -> Result<(), DriverError> {
        let outcome = self.docker(operation, args, SERVICE_TIMEOUT)?;
        if outcome.exit_code == Some(0) {
            return Ok(());
        }
        Err(DriverError::Failed {
            operation: format!("docker {operation}"),
            code: outcome.exit_code.unwrap_or(-1),
            detail: outcome.stderr,
        })
    }
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// Аргументы сборки образа.
///
/// Собирает именно `buildx build … --load`, а не `docker build`. Legacy-сборщик
/// `--platform` принимает, но игнорирует: образ выходит под архитектуру хоста,
/// и следующий же `docker run --platform` не находит нужный вариант. `--load`
/// нужен потому, что buildx по умолчанию оставляет результат в своём кэше, а
/// запускать контейнер предстоит из локального хранилища образов.
#[must_use]
fn build_args(
    image: &str,
    dockerfile: &Path,
    context: &Path,
    platform: Option<&str>,
) -> Vec<String> {
    let mut args = owned(&["buildx", "build", "--load", "-t", image, "-f"]);
    args.push(dockerfile.display().to_string());
    if let Some(platform) = platform {
        args.push("--platform".to_owned());
        args.push(platform.to_owned());
    }
    args.push(context.display().to_string());
    args
}

impl CommandDriver for DockerDriver {
    fn describe(&self) -> String {
        format!("docker://{}", self.config.container)
    }

    fn exec(
        &self,
        command: &str,
        stdin: Option<&str>,
        timeout: Duration,
    ) -> Result<ProcessOutcome, DriverError> {
        let mut args = owned(&["exec", "-i", &self.config.container, "sh", "-lc"]);
        args.push(command.to_owned());
        process::run("docker", &args, stdin, timeout, &self.interrupt).map_err(|source| {
            DriverError::Spawn {
                command: "docker exec".to_owned(),
                source,
            }
        })
    }

    fn deliver(&self, local: &Path, remote: &str, timeout: Duration) -> Result<(), DriverError> {
        super::clear_remote_path(self, remote, timeout)?;
        let args = vec![
            "cp".to_owned(),
            local.display().to_string(),
            format!("{}:{remote}", self.config.container),
        ];
        let outcome = self.docker("cp", &args, timeout)?;
        if outcome.exit_code == Some(0) {
            return Ok(());
        }
        Err(DriverError::Failed {
            operation: format!("docker cp {} → {remote}", local.display()),
            code: outcome.exit_code.unwrap_or(-1),
            detail: outcome.stderr,
        })
    }

    fn recreate(&self) -> Result<(), DriverError> {
        // Снос старого контейнера не проверяется на успех: его может не быть,
        // и это нормальное состояние первого прогона.
        let _ = self.docker(
            "rm",
            &owned(&["rm", "-f", &self.config.container]),
            SERVICE_TIMEOUT,
        )?;

        if let Some(dockerfile) = &self.config.dockerfile {
            let context = self
                .config
                .context
                .clone()
                .or_else(|| dockerfile.parent().map(std::path::Path::to_path_buf))
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            self.ensure_buildx()?;
            let args = build_args(
                &self.config.image,
                dockerfile,
                &context,
                self.config.platform.as_deref(),
            );
            self.docker_checked("buildx build", &args)?;
        }

        let mut args = owned(&["run", "-d", "--name", &self.config.container]);
        if let Some(platform) = &self.config.platform {
            args.push("--platform".to_owned());
            args.push(platform.clone());
        }
        args.extend(self.config.run_args.iter().cloned());
        args.push(self.config.image.clone());
        self.docker_checked("run", &args)?;

        if let Some(ready) = &self.config.ready_command {
            let outcome = self.exec(ready, None, SERVICE_TIMEOUT)?;
            if outcome.exit_code != Some(0) {
                return Err(DriverError::Failed {
                    operation: "проверка готовности контейнера".to_owned(),
                    code: outcome.exit_code.unwrap_or(-1),
                    detail: format!("{}{}", outcome.stdout, outcome.stderr),
                });
            }
        }
        Ok(())
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
    use std::path::PathBuf;

    use super::*;

    fn args(platform: Option<&str>) -> Vec<String> {
        build_args(
            "tessera-e2e/ubuntu:24.04",
            &PathBuf::from("/ws/tessera/tests/e2e/images/ubuntu.Dockerfile"),
            &PathBuf::from("/ws/tessera/tests/e2e/images"),
            platform,
        )
    }

    /// Регрессия, которую не видно до живого прогона: legacy-сборщик принимает
    /// `--platform`, но игнорирует его, и собранный под хост образ не запускается
    /// с той платформой, которую просил профиль.
    #[test]
    fn the_image_is_built_by_buildx_and_loaded_into_the_local_store() {
        let args = args(Some("linux/amd64"));
        assert_eq!(args[0], "buildx");
        assert_eq!(args[1], "build");
        assert!(
            args.contains(&"--load".to_owned()),
            "без --load образ остался бы в кэше buildx: {args:?}"
        );
        assert_eq!(
            args,
            [
                "buildx",
                "build",
                "--load",
                "-t",
                "tessera-e2e/ubuntu:24.04",
                "-f",
                "/ws/tessera/tests/e2e/images/ubuntu.Dockerfile",
                "--platform",
                "linux/amd64",
                "/ws/tessera/tests/e2e/images",
            ]
        );
    }

    #[test]
    fn a_profile_without_a_platform_builds_without_the_flag() {
        let args = args(None);
        assert!(!args.contains(&"--platform".to_owned()), "{args:?}");
        // Контекст остаётся последним позиционным аргументом.
        assert_eq!(args.last().unwrap(), "/ws/tessera/tests/e2e/images");
    }
}
