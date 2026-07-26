//! Результаты прогона и их сохранение.
//!
//! Пять статусов не сливаются между собой. `FAIL` — «мы знаем, что сломано»,
//! `ERROR` — «мы ничего не узнали»: у этих двух исходов разная цена, и отчёт,
//! который их путает, выдаёт непроверенный прогон за собранное evidence.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::provenance::{ArtifactProvenance, Provenance};
use crate::redact::Redactor;
use crate::registry::CaseMode;

/// Исход кейса.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    /// Гарантия проверена и выполняется.
    Pass,
    /// Продукт ведёт себя не так, как обещано.
    Fail,
    /// Сбой стенда или хелпера: о продукте ничего не известно.
    Error,
    /// Профиль не даёт нужной возможности.
    Skip,
    /// Кейсу нужен оператор, а прогон неинтерактивный.
    Blocked,
}

impl Status {
    /// Текстовое обозначение, оно же используется в `BASELINE.md`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Error => "ERROR",
            Self::Skip => "SKIP",
            Self::Blocked => "BLOCKED",
        }
    }

    /// Разбирает статус из текста baseline.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_uppercase().as_str() {
            "PASS" => Some(Self::Pass),
            "FAIL" => Some(Self::Fail),
            "ERROR" => Some(Self::Error),
            "SKIP" => Some(Self::Skip),
            "BLOCKED" => Some(Self::Blocked),
            _ => None,
        }
    }

    /// Можно ли зафиксировать такой исход в baseline.
    ///
    /// `ERROR` фиксировать нельзя: однажды записанный сломанный стенд перестал
    /// бы давать расхождение, и прогон, в котором ни одна гарантия не
    /// проверялась, выглядел бы как успешный.
    #[must_use]
    pub fn is_baselineable(self) -> bool {
        !matches!(self, Self::Error)
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Исход teardown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TeardownOutcome {
    /// Кейс не дошёл до teardown (пропущен, заблокирован).
    NotRun,
    /// Убрано.
    Ok,
    /// Teardown провалился: стенд остался грязным.
    Failed {
        /// Что именно не отработало.
        detail: String,
    },
    /// Пропущен по явному требованию оператора.
    SkippedByFlag,
}

impl TeardownOutcome {
    /// Провалился ли teardown.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// Запись об одном шаге.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepRecord {
    /// Порядковый номер в сценарии, с единицы.
    pub index: usize,
    /// Вид шага.
    pub kind: String,
    /// Описание шага после подстановки переменных.
    pub description: String,
    /// Исход шага.
    pub status: Status,
    /// Пояснение при неуспехе.
    pub detail: Option<String>,
    /// Код возврата команды, если шаг её выполнял.
    pub exit_code: Option<i32>,
    /// Стандартный вывод.
    pub stdout: String,
    /// Стандартный поток ошибок.
    pub stderr: String,
    /// Длительность в миллисекундах.
    pub duration_ms: u128,
}

/// Результат кейса.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseResult {
    /// Идентификатор кейса.
    pub id: String,
    /// Suite, к которому кейс принадлежит.
    pub suite: String,
    /// Формулировка гарантии.
    pub title: String,
    /// Ссылка на требование.
    pub requirement: String,
    /// Режим, выведенный из состава шагов.
    pub mode: CaseMode,
    /// Исход.
    pub status: Status,
    /// Причина для `SKIP`, `BLOCKED`, `FAIL` и `ERROR`.
    pub reason: Option<String>,
    /// Шаги.
    pub steps: Vec<StepRecord>,
    /// Исход уборки.
    pub teardown: TeardownOutcome,
    /// Каталог корня реестра, из которого пришёл кейс: у публичной и приватной
    /// частей разные baseline.
    pub registry_root: PathBuf,
    /// Длительность кейса в миллисекундах.
    pub duration_ms: u128,
}

/// Отчёт о прогоне.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    /// Момент старта.
    pub started_at: String,
    /// Момент завершения.
    pub finished_at: String,
    /// Профиль.
    pub profile: String,
    /// Как выглядело окружение.
    pub environment: String,
    /// Происхождение проверенного пакета.
    pub package: Provenance,
    /// Что приехало в окружение помимо пакета.
    #[serde(default)]
    pub stand_artifacts: Vec<ArtifactProvenance>,
    /// Прогон шёл без оператора.
    pub non_interactive: bool,
    /// Teardown пропускался при провале.
    pub keep_on_failure: bool,
    /// Прогон был прерван сигналом.
    pub interrupted: bool,
    /// Имена переменных, значения которых пришли по ссылке на хранилище
    /// секретов. В отчёте остаётся только факт использования ссылки.
    #[serde(default)]
    pub secret_vars: Vec<String>,
    /// Результаты кейсов.
    pub cases: Vec<CaseResult>,
}

impl RunReport {
    /// Сколько кейсов завершилось указанным статусом.
    #[must_use]
    pub fn count(&self, status: Status) -> usize {
        self.cases.iter().filter(|c| c.status == status).count()
    }

    /// Есть ли провалившийся teardown.
    #[must_use]
    pub fn has_failed_teardown(&self) -> bool {
        self.cases.iter().any(|c| c.teardown.is_failed())
    }
}

/// Каталог прогона: `runs/<дата>-<профиль>-<коммит>`.
///
/// В имя идёт коммит проверенного артефакта, а не рабочего дерева. Если
/// происхождение не установлено, это видно прямо в имени каталога.
#[must_use]
pub fn run_dir(runs_root: &Path, date: &str, profile: &str, package: &Provenance) -> PathBuf {
    let tag = package
        .short_commit()
        .unwrap_or_else(|| "noprov".to_owned());
    runs_root.join(format!("{date}-{profile}-{tag}"))
}

/// Пишет `report.json` и `report.md`.
///
/// # Ошибки
///
/// Ошибки создания каталога и записи файлов, а также сериализации отчёта.
pub fn write(dir: &Path, report: &RunReport, redactor: &Redactor) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let json = serde_json::to_string_pretty(report)
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    std::fs::write(dir.join("report.json"), redactor.apply(&json))?;
    std::fs::write(dir.join("report.md"), redactor.apply(&markdown(report)))?;
    Ok(())
}

/// Раздел отчёта о том, что приехало в окружение помимо пакета.
///
/// Молчания здесь быть не может: прогон, в котором рядом с продуктом работал
/// бинарь неизвестного происхождения, чистым не считается, а пустой раздел
/// читался бы как «ничего не везлось».
#[must_use]
#[expect(
    clippy::format_push_string,
    reason = "отчёт собирается один раз за прогон: читаемость важнее аллокации"
)]
fn stand_artifacts_section(artifacts: &[ArtifactProvenance]) -> String {
    if artifacts.is_empty() {
        return "- Помимо пакета в окружение ничего не везлось\n".to_owned();
    }
    let mut out = format!("\n## Доставлено помимо пакета ({})\n\n", artifacts.len());
    out.push_str(
        "Эти файлы собраны вне проверяемого пакета; за их происхождение отвечает стенд.\n\n",
    );
    out.push_str("| в окружении | источник | права | sha256 | байт |\n");
    out.push_str("|---|---|---|---|---|\n");
    for artifact in artifacts {
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | `{}` | {} |\n",
            artifact.target,
            artifact.path.display(),
            artifact.mode,
            artifact.sha256,
            artifact.size
        ));
    }
    out
}

/// Человекочитаемый отчёт.
#[must_use]
#[expect(
    clippy::format_push_string,
    reason = "отчёт собирается один раз за прогон: читаемость важнее аллокации"
)]
pub fn markdown(report: &RunReport) -> String {
    let mut out = String::new();
    out.push_str("# Прогон e2e\n\n");
    out.push_str(&format!("- Профиль: `{}`\n", report.profile));
    out.push_str(&format!("- Окружение: `{}`\n", report.environment));
    out.push_str(&format!(
        "- Начат: {} , завершён: {}\n",
        report.started_at, report.finished_at
    ));
    out.push_str(&format!("- Пакет: `{}`\n", report.package.path.display()));
    out.push_str(&format!("- sha256: `{}`\n", report.package.sha256));
    out.push_str(&format!("- Источник: {}\n", report.package.source));
    match &report.package.commit {
        Some(commit) => out.push_str(&format!("- Коммит сборки: `{commit}`\n")),
        None => out.push_str(
            "- **Провенанс не установлен**: коммит сборки артефакта подтвердить нечем, \
             прогон не годится как evidence релиза\n",
        ),
    }
    if report.non_interactive {
        out.push_str("- Режим: без оператора (`--non-interactive`)\n");
    }
    if report.keep_on_failure {
        out.push_str("- Teardown при провале пропускался (`--keep-on-failure`)\n");
    }
    if report.interrupted {
        out.push_str("- Прогон прерван сигналом\n");
    }
    if !report.secret_vars.is_empty() {
        out.push_str(&format!(
            "- По ссылкам на хранилище секретов получены значения: {}\n",
            report.secret_vars.join(", ")
        ));
    }

    out.push_str(&stand_artifacts_section(&report.stand_artifacts));

    out.push_str("\n## Итог\n\n");
    for status in [
        Status::Pass,
        Status::Fail,
        Status::Error,
        Status::Skip,
        Status::Blocked,
    ] {
        out.push_str(&format!(
            "- {}: {}\n",
            status.as_str(),
            report.count(status)
        ));
    }

    out.push_str("\n## Кейсы\n\n");
    out.push_str("| id | статус | режим | кейс | комментарий |\n");
    out.push_str("|---|---|---|---|---|\n");
    for case in &report.cases {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            case.id,
            case.status,
            case.mode,
            case.title,
            case.reason.as_deref().unwrap_or("")
        ));
    }

    let dirty: Vec<&CaseResult> = report
        .cases
        .iter()
        .filter(|case| case.teardown.is_failed())
        .collect();
    if !dirty.is_empty() {
        out.push_str("\n## Провалы teardown\n\n");
        out.push_str(
            "Стенд остался грязным; следующий прогон стартует с подозрительного окружения.\n\n",
        );
        for case in dirty {
            let detail = match &case.teardown {
                TeardownOutcome::Failed { detail } => detail.as_str(),
                _ => "",
            };
            out.push_str(&format!("- {}: {}\n", case.id, detail));
        }
    }

    out
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

    #[test]
    fn statuses_round_trip_through_text() {
        for status in [
            Status::Pass,
            Status::Fail,
            Status::Error,
            Status::Skip,
            Status::Blocked,
        ] {
            assert_eq!(Status::parse(status.as_str()), Some(status));
        }
        assert_eq!(Status::parse(" pass "), Some(Status::Pass));
        assert_eq!(Status::parse("сломалось"), None);
    }

    #[test]
    fn only_error_is_kept_out_of_baseline() {
        assert!(Status::Pass.is_baselineable());
        assert!(Status::Fail.is_baselineable());
        assert!(Status::Skip.is_baselineable());
        assert!(Status::Blocked.is_baselineable());
        assert!(!Status::Error.is_baselineable());
    }

    fn report_with(case: CaseResult) -> RunReport {
        RunReport {
            started_at: "2026-07-26 20:00:00+03:00".to_owned(),
            finished_at: "2026-07-26 20:01:00+03:00".to_owned(),
            profile: "ubuntu-container".to_owned(),
            environment: "docker://tessera-e2e-ubuntu".to_owned(),
            package: Provenance {
                path: PathBuf::from("/art/tessera_0.4.0_amd64.deb"),
                sha256: "ab".repeat(32),
                size: 1,
                source: "локальная сборка".to_owned(),
                commit: None,
            },
            stand_artifacts: Vec::new(),
            non_interactive: false,
            keep_on_failure: false,
            interrupted: false,
            secret_vars: vec!["pin".to_owned()],
            cases: vec![case],
        }
    }

    /// Разбирающий отчёт человек не должен гадать, почему кейс `ERROR`, а не
    /// `FAIL`: причина обязана называть служебный код хелпера прямым текстом.
    #[test]
    fn a_stand_failure_explains_itself_in_the_report() {
        let report = report_with(CaseResult {
            id: "AUTH-001".to_owned(),
            suite: "auth".to_owned(),
            title: "валидное удостоверение пускает пользователя".to_owned(),
            requirement: "specs".to_owned(),
            mode: CaseMode::Auto,
            status: Status::Error,
            reason: Some(
                "шаг 2: хелпер вернул служебный код 70: сбой стенда, а не вердикт продукта"
                    .to_owned(),
            ),
            steps: Vec::new(),
            teardown: TeardownOutcome::Ok,
            registry_root: PathBuf::from("tests/e2e/cases"),
            duration_ms: 1,
        });

        let text = markdown(&report);
        assert!(text.contains("| AUTH-001 | ERROR |"), "{text}");
        assert!(text.contains("служебный код 70"), "{text}");
        assert!(
            text.contains("сбой стенда, а не вердикт продукта"),
            "{text}"
        );
        assert!(text.contains("ERROR: 1"), "{text}");
        // Провенанс не установлен — отчёт обязан сказать это прямо.
        assert!(text.contains("Провенанс не установлен"), "{text}");
        // Использование ссылки на секрет фиксируется, само значение — нет.
        assert!(text.contains("pin"), "{text}");
    }

    fn passing_case() -> CaseResult {
        CaseResult {
            id: "ISSUER-001".to_owned(),
            suite: "issuer".to_owned(),
            title: "выпуск удостоверения".to_owned(),
            requirement: "specs".to_owned(),
            mode: CaseMode::Auto,
            status: Status::Pass,
            reason: None,
            steps: Vec::new(),
            teardown: TeardownOutcome::Ok,
            registry_root: PathBuf::from("tests/e2e/cases"),
            duration_ms: 1,
        }
    }

    /// Прогон, в котором рядом с продуктом работал бинарь неизвестного
    /// происхождения, чистым не считается: отчёт обязан назвать и файл, и сумму.
    #[test]
    fn everything_delivered_besides_the_package_is_named_in_the_report() {
        let mut report = report_with(passing_case());
        report.stand_artifacts = vec![ArtifactProvenance {
            path: PathBuf::from("/build/issuer"),
            target: "/usr/local/bin/issuer".to_owned(),
            mode: "0755".to_owned(),
            sha256: "cd".repeat(32),
            size: 4096,
        }];

        let text = markdown(&report);
        assert!(text.contains("Доставлено помимо пакета (1)"), "{text}");
        assert!(text.contains("/usr/local/bin/issuer"), "{text}");
        assert!(text.contains("/build/issuer"), "{text}");
        assert!(text.contains("0755"), "{text}");
        assert!(text.contains(&"cd".repeat(32)), "{text}");
    }

    #[test]
    fn a_run_without_extra_artifacts_says_so_outright() {
        let text = markdown(&report_with(passing_case()));
        assert!(
            text.contains("Помимо пакета в окружение ничего не везлось"),
            "{text}"
        );
        assert!(!text.contains("Доставлено помимо пакета"), "{text}");
    }

    #[test]
    fn run_dir_falls_back_to_a_marker_without_provenance() {
        let package = Provenance {
            path: PathBuf::from("/tmp/tessera.deb"),
            sha256: "ab".repeat(32),
            size: 1,
            source: "локальный путь".to_owned(),
            commit: None,
        };
        let dir = run_dir(
            Path::new("runs"),
            "2026-07-26",
            "ubuntu-container",
            &package,
        );
        assert!(dir.ends_with("2026-07-26-ubuntu-container-noprov"));

        let package = Provenance {
            commit: Some("0123456789abcdef".to_owned()),
            ..package
        };
        let dir = run_dir(
            Path::new("runs"),
            "2026-07-26",
            "ubuntu-container",
            &package,
        );
        assert!(dir.ends_with("2026-07-26-ubuntu-container-0123456"));
    }
}
