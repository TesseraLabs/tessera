//! `BASELINE.md` — известное состояние каждого кейса, под контролем версий.
//!
//! Прогон печатается расхождением к baseline, а не списком провалов: известный
//! незакрытый дефект не шумит каждый раз, но и не исчезает из виду. Обновление
//! только явной командой — автообновление превратило бы файл в зеркало
//! последнего прогона.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::report::{CaseResult, Status};

/// Заголовок таблицы baseline.
const HEADER: &str = "| id | статус | дата | версия | профиль | комментарий |";
const SEPARATOR: &str = "|---|---|---|---|---|---|";

/// Ошибки работы с baseline.
#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    /// Файл не читается.
    #[error("не прочитать {path}: {source}")]
    Read {
        /// Путь.
        path: PathBuf,
        /// Причина.
        source: std::io::Error,
    },
    /// Файл не записывается.
    #[error("не записать {path}: {source}")]
    Write {
        /// Путь.
        path: PathBuf,
        /// Причина.
        source: std::io::Error,
    },
}

/// Строка baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineEntry {
    /// Идентификатор кейса.
    pub id: String,
    /// Зафиксированный статус.
    pub status: Status,
    /// Дата фиксации.
    pub date: String,
    /// Версия пакета, на которой статус зафиксирован.
    pub version: String,
    /// Профиль.
    pub profile: String,
    /// Комментарий: обычно ссылка на дефект.
    pub comment: String,
}

/// Расхождение прогона с baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// Кейса в baseline нет.
    Unknown {
        /// Идентификатор.
        id: String,
        /// Полученный статус.
        actual: Status,
    },
    /// Статус изменился.
    Changed {
        /// Идентификатор.
        id: String,
        /// Что было зафиксировано.
        expected: Status,
        /// Что получилось.
        actual: Status,
    },
    /// Сбой стенда: в baseline не фиксируется никогда.
    StandBroken {
        /// Идентификатор.
        id: String,
        /// Что произошло.
        detail: String,
    },
}

impl Divergence {
    /// Строка для печати в консоль и отчёт.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Unknown { id, actual } => format!("{id}: нет в baseline, получено {actual}"),
            Self::Changed {
                id,
                expected,
                actual,
            } => format!("{id}: в baseline {expected}, получено {actual}"),
            Self::StandBroken { id, detail } => format!("{id}: сбой стенда — {detail}"),
        }
    }
}

/// Разобранный baseline.
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    /// Текст до таблицы: заголовок файла и пояснения, которые надо сохранить
    /// при перезаписи.
    preamble: String,
    entries: Vec<BaselineEntry>,
}

impl Baseline {
    /// Читает baseline; отсутствие файла — пустой baseline, а не ошибка:
    /// первый прогон нового реестра начинается именно с этого.
    ///
    /// # Ошибки
    ///
    /// Ошибка чтения существующего файла.
    pub fn load(path: &Path) -> Result<Self, BaselineError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path).map_err(|source| BaselineError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self::parse(&text))
    }

    /// Разбирает markdown-таблицу baseline.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut preamble = String::new();
        let mut entries = Vec::new();
        let mut table_started = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if !table_started {
                if trimmed.starts_with("| id ") || trimmed == HEADER {
                    table_started = true;
                    continue;
                }
                preamble.push_str(line);
                preamble.push('\n');
                continue;
            }
            if trimmed.starts_with("|-") || trimmed.starts_with("| -") {
                continue;
            }
            if !trimmed.starts_with('|') {
                continue;
            }
            if let Some(entry) = parse_row(trimmed) {
                entries.push(entry);
            }
        }
        Self { preamble, entries }
    }

    /// Записи baseline.
    #[cfg(test)]
    #[must_use]
    pub fn entries(&self) -> &[BaselineEntry] {
        &self.entries
    }

    /// Ищет запись по кейсу и профилю. Ключ включает профиль: один и тот же
    /// кейс на контейнере и на машине — разные ожидания.
    #[must_use]
    pub fn get(&self, id: &str, profile: &str) -> Option<&BaselineEntry> {
        self.entries
            .iter()
            .find(|entry| entry.id == id && entry.profile == profile)
    }

    /// Считает расхождения прогона с зафиксированным состоянием.
    #[must_use]
    pub fn diff(&self, results: &[CaseResult], profile: &str) -> Vec<Divergence> {
        let mut out = Vec::new();
        for case in results {
            if case.status == Status::Error {
                out.push(Divergence::StandBroken {
                    id: case.id.clone(),
                    detail: case
                        .reason
                        .clone()
                        .unwrap_or_else(|| "сбой стенда или хелпера".to_owned()),
                });
                continue;
            }
            if case.teardown.is_failed() {
                out.push(Divergence::StandBroken {
                    id: case.id.clone(),
                    detail: "teardown не отработал, окружение осталось грязным".to_owned(),
                });
            }
            match self.get(&case.id, profile) {
                None => out.push(Divergence::Unknown {
                    id: case.id.clone(),
                    actual: case.status,
                }),
                Some(entry) if entry.status != case.status => out.push(Divergence::Changed {
                    id: case.id.clone(),
                    expected: entry.status,
                    actual: case.status,
                }),
                Some(_) => {}
            }
        }
        out
    }

    /// Обновляет baseline результатами прогона.
    ///
    /// Возвращает список кейсов, которые записать отказались: `ERROR` и провал
    /// teardown зафиксировать нельзя, иначе сломанный стенд перестал бы давать
    /// расхождение.
    pub fn update(
        &mut self,
        results: &[CaseResult],
        profile: &str,
        date: &str,
        version: &str,
    ) -> Vec<String> {
        let mut refused = Vec::new();
        for case in results {
            if !case.status.is_baselineable() {
                refused.push(format!(
                    "{}: статус {} не фиксируется",
                    case.id, case.status
                ));
                continue;
            }
            if case.teardown.is_failed() {
                refused.push(format!("{}: провал teardown не фиксируется", case.id));
                continue;
            }
            let existing = self
                .entries
                .iter_mut()
                .find(|entry| entry.id == case.id && entry.profile == profile);
            match existing {
                Some(entry) => {
                    entry.status = case.status;
                    date.clone_into(&mut entry.date);
                    version.clone_into(&mut entry.version);
                }
                None => self.entries.push(BaselineEntry {
                    id: case.id.clone(),
                    status: case.status,
                    date: date.to_owned(),
                    version: version.to_owned(),
                    profile: profile.to_owned(),
                    comment: String::new(),
                }),
            }
        }
        self.entries
            .sort_by(|a, b| (&a.profile, &a.id).cmp(&(&b.profile, &b.id)));
        refused
    }

    /// Собирает текст файла.
    #[must_use]
    #[expect(
        clippy::format_push_string,
        reason = "файл собирается один раз: читаемость важнее аллокации"
    )]
    pub fn render(&self) -> String {
        let mut out = if self.preamble.trim().is_empty() {
            String::from(
                "# Baseline e2e\n\nЗафиксированное состояние кейсов. Обновляется только явной \
                 командой `--update-baseline`.\nСтатусы `ERROR` и провалы teardown здесь не \
                 фиксируются.\n\n",
            )
        } else {
            let mut preamble = self.preamble.trim_end().to_owned();
            preamble.push_str("\n\n");
            preamble
        };
        out.push_str(HEADER);
        out.push('\n');
        out.push_str(SEPARATOR);
        out.push('\n');
        for entry in &self.entries {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                entry.id, entry.status, entry.date, entry.version, entry.profile, entry.comment
            ));
        }
        out
    }

    /// Записывает baseline на диск.
    ///
    /// # Ошибки
    ///
    /// Ошибки создания каталога и записи файла.
    pub fn save(&self, path: &Path) -> Result<(), BaselineError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| BaselineError::Write {
                path: path.to_path_buf(),
                source,
            })?;
        }
        std::fs::write(path, self.render()).map_err(|source| BaselineError::Write {
            path: path.to_path_buf(),
            source,
        })
    }
}

fn parse_row(line: &str) -> Option<BaselineEntry> {
    let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
    let mut cells = cells.into_iter();
    let id = cells.next()?.to_owned();
    let status = Status::parse(cells.next()?)?;
    let date = cells.next()?.to_owned();
    let version = cells.next()?.to_owned();
    let profile = cells.next()?.to_owned();
    let comment = cells.next().unwrap_or("").to_owned();
    if id.is_empty() {
        return None;
    }
    Some(BaselineEntry {
        id,
        status,
        date,
        version,
        profile,
        comment,
    })
}

/// Собирает baseline для каждого корня реестра, встретившегося в прогоне.
///
/// # Ошибки
///
/// Ошибки чтения существующих файлов.
pub fn load_for_roots(roots: &[PathBuf]) -> Result<BTreeMap<PathBuf, Baseline>, BaselineError> {
    let mut out = BTreeMap::new();
    for root in roots {
        out.insert(root.clone(), Baseline::load(&baseline_path(root))?);
    }
    Ok(out)
}

/// Путь к baseline рядом с каталогом кейсов: у публичной и приватной частей
/// реестра он свой.
#[must_use]
pub fn baseline_path(registry_root: &Path) -> PathBuf {
    registry_root
        .parent()
        .unwrap_or(registry_root)
        .join("BASELINE.md")
}

/// Правило кода возврата.
///
/// Ненулевой код даёт расхождение с baseline, а также любой `ERROR` и любой
/// провал teardown — независимо от baseline.
#[must_use]
pub fn exit_code(results: &[CaseResult], divergences: &[Divergence]) -> i32 {
    let stand_broken = results
        .iter()
        .any(|case| case.status == Status::Error || case.teardown.is_failed());
    i32::from(stand_broken || !divergences.is_empty())
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
    use crate::registry::CaseMode;
    use crate::report::TeardownOutcome;

    const TABLE: &str = "# Baseline e2e

Пояснение, которое должно пережить перезапись.

| id | статус | дата | версия | профиль | комментарий |
|---|---|---|---|---|---|
| AUTH-001 | PASS | 2026-07-26 | 0.4.0 | ubuntu-container |  |
| AUTH-002 | FAIL | 2026-07-26 | 0.4.0 | ubuntu-container | известный дефект |
| AUTH-001 | SKIP | 2026-07-26 | 0.4.0 | astra-vm | нет носителя |
";

    fn case(id: &str, status: Status) -> CaseResult {
        CaseResult {
            id: id.to_owned(),
            suite: "auth".to_owned(),
            title: "гарантия".to_owned(),
            requirement: "specs".to_owned(),
            mode: CaseMode::Auto,
            status,
            reason: None,
            steps: Vec::new(),
            teardown: TeardownOutcome::Ok,
            registry_root: PathBuf::from("tests/e2e/cases"),
            duration_ms: 1,
        }
    }

    #[test]
    fn parses_table_and_keeps_preamble() {
        let baseline = Baseline::parse(TABLE);
        assert_eq!(baseline.entries().len(), 3);
        assert_eq!(
            baseline
                .get("AUTH-002", "ubuntu-container")
                .unwrap()
                .comment,
            "известный дефект"
        );
        assert!(baseline.render().contains("должно пережить перезапись"));
    }

    #[test]
    fn the_same_case_on_another_profile_is_a_separate_row() {
        let baseline = Baseline::parse(TABLE);
        assert_eq!(
            baseline.get("AUTH-001", "ubuntu-container").unwrap().status,
            Status::Pass
        );
        assert_eq!(
            baseline.get("AUTH-001", "astra-vm").unwrap().status,
            Status::Skip
        );
    }

    #[test]
    fn a_known_defect_is_not_a_divergence() {
        let baseline = Baseline::parse(TABLE);
        let results = vec![case("AUTH-002", Status::Fail)];
        let divergences = baseline.diff(&results, "ubuntu-container");
        assert!(divergences.is_empty());
        assert_eq!(exit_code(&results, &divergences), 0);
    }

    #[test]
    fn a_new_regression_diverges_and_fails_the_run() {
        let baseline = Baseline::parse(TABLE);
        let results = vec![case("AUTH-001", Status::Fail)];
        let divergences = baseline.diff(&results, "ubuntu-container");
        assert_eq!(
            divergences,
            vec![Divergence::Changed {
                id: "AUTH-001".to_owned(),
                expected: Status::Pass,
                actual: Status::Fail,
            }]
        );
        assert_eq!(exit_code(&results, &divergences), 1);
    }

    #[test]
    fn an_unknown_case_diverges() {
        let baseline = Baseline::parse(TABLE);
        let results = vec![case("AUTH-099", Status::Pass)];
        let divergences = baseline.diff(&results, "ubuntu-container");
        assert!(matches!(
            divergences.as_slice(),
            [Divergence::Unknown { .. }]
        ));
    }

    #[test]
    fn a_broken_stand_always_fails_the_run_even_when_recorded() {
        let mut baseline = Baseline::parse(TABLE);
        let results = vec![case("AUTH-001", Status::Error)];
        // Попытка зафиксировать сбой стенда отвергается…
        let refused = baseline.update(&results, "ubuntu-container", "2026-07-26", "0.4.0");
        assert_eq!(refused.len(), 1);
        assert_eq!(
            baseline.get("AUTH-001", "ubuntu-container").unwrap().status,
            Status::Pass
        );
        // …и повторный ERROR всё равно даёт расхождение и ненулевой код.
        let divergences = baseline.diff(&results, "ubuntu-container");
        assert!(matches!(
            divergences.as_slice(),
            [Divergence::StandBroken { .. }]
        ));
        assert_eq!(exit_code(&results, &divergences), 1);
    }

    #[test]
    fn a_failed_teardown_is_neither_recorded_nor_forgiven() {
        let mut baseline = Baseline::parse(TABLE);
        let mut result = case("AUTH-001", Status::Pass);
        result.teardown = TeardownOutcome::Failed {
            detail: "loop не отвязан".to_owned(),
        };
        let results = vec![result];

        let refused = baseline.update(&results, "ubuntu-container", "2026-07-27", "0.4.1");
        assert_eq!(refused.len(), 1);
        assert_eq!(
            baseline.get("AUTH-001", "ubuntu-container").unwrap().date,
            "2026-07-26"
        );

        let divergences = baseline.diff(&results, "ubuntu-container");
        assert!(divergences
            .iter()
            .any(|d| matches!(d, Divergence::StandBroken { .. })));
        assert_eq!(exit_code(&results, &divergences), 1);
    }

    #[test]
    fn update_rewrites_the_recorded_status_and_stays_parseable() {
        let mut baseline = Baseline::parse(TABLE);
        let results = vec![case("AUTH-002", Status::Pass)];
        let refused = baseline.update(&results, "ubuntu-container", "2026-07-27", "0.4.1");
        assert!(refused.is_empty());

        let reparsed = Baseline::parse(&baseline.render());
        let entry = reparsed.get("AUTH-002", "ubuntu-container").unwrap();
        assert_eq!(entry.status, Status::Pass);
        assert_eq!(entry.date, "2026-07-27");
        assert_eq!(entry.version, "0.4.1");
        assert_eq!(entry.comment, "известный дефект");
        assert_eq!(reparsed.entries().len(), 3);
    }

    #[test]
    fn a_missing_file_reads_as_an_empty_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let baseline = Baseline::load(&dir.path().join("BASELINE.md")).unwrap();
        assert!(baseline.entries().is_empty());
    }

    #[test]
    fn baseline_lives_next_to_its_cases_directory() {
        assert_eq!(
            baseline_path(Path::new("tests/e2e/cases")),
            PathBuf::from("tests/e2e/BASELINE.md")
        );
        assert_eq!(
            baseline_path(Path::new("/ws/tests/e2e-private/cases")),
            PathBuf::from("/ws/tests/e2e-private/BASELINE.md")
        );
    }

    #[test]
    fn a_clean_run_matching_baseline_returns_zero() {
        let baseline = Baseline::parse(TABLE);
        let results = vec![
            case("AUTH-001", Status::Pass),
            case("AUTH-002", Status::Fail),
        ];
        let divergences = baseline.diff(&results, "ubuntu-container");
        assert!(divergences.is_empty());
        assert_eq!(exit_code(&results, &divergences), 0);
    }
}
