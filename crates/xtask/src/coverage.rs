//! Сборка матрицы покрытия спек кейсами реестра.
//!
//! Единица покрытия — сценарий спеки (`#### Scenario:`), а не спека целиком;
//! связь даёт поле `requirement:` кейса. Матрица собирается из реестра и спек,
//! а не пишется руками: рукописный срез устаревает к следующему PR и начинает
//! врать в ту сторону, в которую удобно.
//!
//! Даты в генерируемом участке нет намеренно: файл, отличающийся при каждом
//! прогоне, сделал бы сверку в CI ложно-красной.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::cli::CoverageArgs;
use crate::registry::{self, Registry};

/// Начало генерируемого участка `COVERAGE.md`.
const BEGIN: &str = "<!-- BEGIN GENERATED -->";
/// Конец генерируемого участка `COVERAGE.md`.
const END: &str = "<!-- END GENERATED -->";

/// Строка, с которой начинается заголовок сценария спеки.
const SCENARIO_HEADING: &str = "#### Scenario:";

/// Ошибки сборки матрицы покрытия.
#[derive(Debug, thiserror::Error)]
pub enum CoverageError {
    /// В файле нет маркера, ограничивающего генерируемый участок.
    #[error(
        "{path}: не найдена строка-маркер `{marker}`; \
         генерируемый участок ограничивается строками `{BEGIN}` и `{END}` — \
         добавьте их вокруг сводки и таблиц, остальной текст файла не трогается"
    )]
    MarkerMissing {
        /// Файл матрицы.
        path: PathBuf,
        /// Какого маркера не хватило.
        marker: &'static str,
    },
    /// Маркеры стоят в обратном порядке.
    #[error("{path}: маркер `{END}` встречается раньше `{BEGIN}`")]
    MarkersSwapped {
        /// Файл матрицы.
        path: PathBuf,
    },
    /// Закоммиченный участок разошёлся со сгенерированным.
    #[error("{path}: закоммиченная матрица разошлась со сгенерированной")]
    Stale {
        /// Файл матрицы.
        path: PathBuf,
    },
}

/// Пересобирает `tests/e2e/COVERAGE.md` из реестра кейсов и спек.
///
/// С `--check` ничего не пишет, а сверяет закоммиченный участок со
/// сгенерированным и возвращает ненулевой код при расхождении.
///
/// # Ошибки
///
/// Нечитаемый реестр, недоступные спеки, отсутствие маркеров в файле матрицы.
pub fn e2e_coverage(args: &CoverageArgs) -> anyhow::Result<i32> {
    let repo_root = crate::repo_root();
    let e2e_root = repo_root.join("tests").join("e2e");
    // Приватная часть реестра сюда не подмешивается: файл матрицы лежит в
    // открытом репозитории, и состав закрытых кейсов в нём быть не должен.
    let registry = Registry::load_from(&[e2e_root.join("cases")], &repo_root)?;
    for warning in registry.warnings() {
        eprintln!("ВНИМАНИЕ: {warning}");
    }

    let specs = collect_specs(&repo_root.join("openspec").join("specs"))?;
    let stats = tally(&specs, &registry);
    let pending = tally_pending(&registry);
    let generated = render(&stats, &pending, registry.cases().count());

    let path = e2e_root.join("COVERAGE.md");
    let existing = std::fs::read_to_string(&path)
        .map_err(|source| anyhow::anyhow!("не прочитать {}: {source}", path.display()))?;
    let region = locate(&existing, &path)?;

    if args.check {
        let current = existing.get(region.clone()).unwrap_or_default();
        if current == generated {
            println!("{}: матрица совпадает с реестром", path.display());
            return Ok(0);
        }
        report_divergence(current, &generated);
        return Err(CoverageError::Stale { path }.into());
    }

    let mut updated = String::with_capacity(existing.len());
    updated.push_str(existing.get(..region.start).unwrap_or_default());
    updated.push_str(&generated);
    updated.push_str(existing.get(region.end..).unwrap_or_default());
    if updated == existing {
        println!("{}: без изменений", path.display());
        return Ok(0);
    }
    std::fs::write(&path, &updated)
        .map_err(|source| anyhow::anyhow!("не записать {}: {source}", path.display()))?;
    println!("{}: матрица пересобрана", path.display());
    Ok(0)
}

/// Спека и число сценариев в ней.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecStats {
    /// Имя каталога спеки в `openspec/specs/`.
    name: String,
    /// Сколько в спеке сценариев.
    scenarios: usize,
    /// Сколько кейсов реестра на неё ссылается.
    cases: usize,
}

/// Читает принятые спеки и считает в каждой сценарии.
fn collect_specs(specs_root: &Path) -> anyhow::Result<BTreeMap<String, usize>> {
    let entries = std::fs::read_dir(specs_root)
        .map_err(|source| anyhow::anyhow!("не прочитать {}: {source}", specs_root.display()))?;
    let mut specs = BTreeMap::new();
    for entry in entries {
        let path = entry
            .map_err(|source| anyhow::anyhow!("не прочитать {}: {source}", specs_root.display()))?
            .path();
        let spec = path.join("spec.md");
        if !spec.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
            continue;
        };
        let text = std::fs::read_to_string(&spec)
            .map_err(|source| anyhow::anyhow!("не прочитать {}: {source}", spec.display()))?;
        specs.insert(name.to_owned(), count_scenarios(&text));
    }
    Ok(specs)
}

/// Сколько в тексте спеки заголовков сценариев.
fn count_scenarios(text: &str) -> usize {
    text.lines()
        .filter(|line| line.trim_start().starts_with(SCENARIO_HEADING))
        .count()
}

/// Спека, ещё не синкнутая из предложения, и число смотрящих на неё кейсов.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingStats {
    /// Имя спеки.
    name: String,
    /// Предложение, внутри которого спека живёт сейчас.
    change: String,
    /// Сколько кейсов реестра на неё ссылается.
    cases: usize,
}

/// Считает кейсы, смотрящие на ещё не синкнутые спеки.
///
/// Без этого раздела сумма по таблицам не сходится с числом кейсов в сводке, и
/// разница выглядит потерянными кейсами.
fn tally_pending(registry: &Registry) -> Vec<PendingStats> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, case) in registry.cases() {
        if let Some(name) = registry::spec_name(&case.requirement) {
            *counts.entry(name).or_default() += 1;
        }
    }
    registry
        .pending_specs
        .iter()
        .map(|spec| PendingStats {
            name: spec.name.clone(),
            change: spec.change.clone(),
            cases: counts.get(spec.name.as_str()).copied().unwrap_or_default(),
        })
        .collect()
}

/// Раскладывает кейсы реестра по принятым спекам.
///
/// Кейсы, чьи спеки ещё живут в предложениях, сюда не попадают: строки в этих
/// двух таблицах у такой спеки нет. Их считает [`tally_pending`].
fn tally(specs: &BTreeMap<String, usize>, registry: &Registry) -> Vec<SpecStats> {
    let mut cases: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, case) in registry.cases() {
        if let Some(name) = registry::spec_name(&case.requirement) {
            if specs.contains_key(name) {
                *cases.entry(name).or_default() += 1;
            }
        }
    }
    specs
        .iter()
        .map(|(name, scenarios)| SpecStats {
            name: name.clone(),
            scenarios: *scenarios,
            cases: cases.get(name.as_str()).copied().unwrap_or_default(),
        })
        .collect()
}

/// Собирает текст генерируемого участка.
fn render(stats: &[SpecStats], pending: &[PendingStats], total_cases: usize) -> String {
    let mut covered: Vec<&SpecStats> = stats.iter().filter(|spec| spec.cases > 0).collect();
    // Порядок задан числом кейсов, при равенстве — числом сценариев, при
    // полном равенстве — именем. Последняя ступень обязательна: без неё срез
    // зависел бы от порядка обхода каталога, и сверка в CI краснела бы через
    // раз на неизменившемся реестре.
    covered.sort_by(|a, b| {
        b.cases
            .cmp(&a.cases)
            .then(b.scenarios.cmp(&a.scenarios))
            .then(a.name.cmp(&b.name))
    });
    let mut bare: Vec<&SpecStats> = stats.iter().filter(|spec| spec.cases == 0).collect();
    bare.sort_by(|a, b| b.scenarios.cmp(&a.scenarios).then(a.name.cmp(&b.name)));

    let scenarios: usize = stats.iter().map(|spec| spec.scenarios).sum();
    let mut lines: Vec<String> = vec![
        "## Сводка".to_owned(),
        String::new(),
        "| | |".to_owned(),
        "|---|---|".to_owned(),
        format!("| Спек в `openspec/specs/` | {} |", stats.len()),
        format!("| Сценариев в них | {scenarios} |"),
        format!("| Кейсов в реестре | {total_cases} |"),
        format!(
            "| Спек, к которым привязан хотя бы один кейс | {} |",
            covered.len()
        ),
        format!("| Спек без единого кейса | {} |", bare.len()),
        String::new(),
        "## Спеки, к которым привязаны кейсы".to_owned(),
        String::new(),
        "| Спека | Сценариев | Кейсов |".to_owned(),
        "|---|---:|---:|".to_owned(),
    ];
    lines.extend(
        covered
            .iter()
            .map(|spec| format!("| {} | {} | {} |", spec.name, spec.scenarios, spec.cases)),
    );
    lines.extend([
        String::new(),
        "## Спеки без кейсов".to_owned(),
        String::new(),
        "| Спека | Сценариев |".to_owned(),
        "|---|---:|".to_owned(),
    ]);
    lines.extend(
        bare.iter()
            .map(|spec| format!("| {} | {} |", spec.name, spec.scenarios)),
    );

    // Раздела нет вовсе, когда несинкнутых спек нет: пустая таблица хуже
    // отсутствующей — её приходится читать, чтобы понять, что читать нечего.
    if !pending.is_empty() {
        let mut pending: Vec<&PendingStats> = pending.iter().collect();
        pending.sort_by(|a, b| b.cases.cmp(&a.cases).then(a.name.cmp(&b.name)));
        let cases: usize = pending.iter().map(|spec| spec.cases).sum();
        lines.extend([
            String::new(),
            "## Спеки, ещё не синкнутые из предложений".to_owned(),
            String::new(),
            format!(
                "На них ссылается кейсов: {cases}. Именно на столько сумма по таблицам выше \
                 меньше числа кейсов в сводке: строки в тех таблицах эти спеки получат, \
                 когда переедут в `openspec/specs/`."
            ),
            String::new(),
            "| Спека | Предложение | Кейсов |".to_owned(),
            "|---|---|---:|".to_owned(),
        ]);
        lines.extend(
            pending
                .iter()
                .map(|spec| format!("| {} | {} | {} |", spec.name, spec.change, spec.cases)),
        );
    }

    // Участок кладётся между строками-маркерами, поэтому завершается переводом
    // строки: без него маркер конца уехал бы в последнюю строку таблицы.
    lines.push(String::new());
    lines.join("\n")
}

/// Находит участок между маркерами — сами строки маркеров в него не входят.
fn locate(text: &str, path: &Path) -> Result<std::ops::Range<usize>, CoverageError> {
    let mut begin: Option<usize> = None;
    let mut end: Option<usize> = None;
    let mut end_seen = false;
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed == BEGIN {
            if begin.is_none() {
                begin = Some(offset + line.len());
            }
        } else if trimmed == END {
            end_seen = true;
            if begin.is_some() && end.is_none() {
                end = Some(offset);
            }
        }
        offset += line.len();
    }
    let Some(begin) = begin else {
        return Err(CoverageError::MarkerMissing {
            path: path.to_path_buf(),
            marker: BEGIN,
        });
    };
    match end {
        Some(end) => Ok(begin..end),
        None if end_seen => Err(CoverageError::MarkersSwapped {
            path: path.to_path_buf(),
        }),
        None => Err(CoverageError::MarkerMissing {
            path: path.to_path_buf(),
            marker: END,
        }),
    }
}

/// Печатает, чем именно закоммиченный участок отличается от сгенерированного.
fn report_divergence(current: &str, generated: &str) {
    let current: Vec<&str> = current.lines().collect();
    let generated: Vec<&str> = generated.lines().collect();
    eprintln!("расхождения (строки внутри генерируемого участка):");
    for index in 0..current.len().max(generated.len()) {
        let was = current.get(index).copied();
        let now = generated.get(index).copied();
        if was == now {
            continue;
        }
        let number = index + 1;
        eprintln!("  строка {number}: в файле   {}", was.unwrap_or("<нет>"));
        eprintln!("  строка {number}: ожидалось {}", now.unwrap_or("<нет>"));
    }
    eprintln!("пересобрать: cargo xtask e2e-coverage");
}

#[cfg(test)]
// Тестам разрешено падать на нарушенных инвариантах: это и есть их способ
// сообщить о проблеме.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn scenarios_are_counted_by_their_heading() {
        let text = "## Requirement\n#### Scenario: один\ntext\n  #### Scenario: два\n\
                    ### Scenario: не тот уровень\n#### Scenarios: не тот заголовок\n";
        assert_eq!(count_scenarios(text), 2);
    }

    #[test]
    fn cases_are_tallied_per_spec() {
        let specs = BTreeMap::from([
            ("revocation".to_owned(), 19),
            ("role-store".to_owned(), 13),
            ("hooks".to_owned(), 7),
        ]);
        let mut registry = Registry::default();
        registry.suites.push(
            serde_norway::from_str(
                r"
suite: s
cases:
  - id: A-1
    title: t
    requirement: openspec/specs/revocation/spec.md
    steps: [{ run: /bin/true }]
  - id: A-2
    title: t
    requirement: openspec/specs/revocation/spec.md
    steps: [{ run: /bin/true }]
  - id: A-3
    title: t
    requirement: openspec/specs/role-store/spec.md
    steps: [{ run: /bin/true }]
  - id: A-4
    title: t
    requirement: openspec/specs/carrier-presence/spec.md
    steps: [{ run: /bin/true }]
",
            )
            .unwrap(),
        );
        registry.pending_specs = vec![registry::PendingSpec {
            name: "carrier-presence".to_owned(),
            change: "token-presence-monitor".to_owned(),
        }];
        let stats = tally(&specs, &registry);
        let by_name = |name: &str| {
            stats
                .iter()
                .find(|spec| spec.name == name)
                .expect("спека есть в срезе")
                .cases
        };
        assert_eq!(by_name("revocation"), 2);
        assert_eq!(by_name("role-store"), 1);
        // Спека, живущая ещё в предложении, строки в первых двух таблицах не
        // получает — её кейс считает отдельный раздел.
        assert_eq!(by_name("hooks"), 0);
        assert_eq!(stats.len(), 3);

        let pending = tally_pending(&registry);
        assert_eq!(
            pending,
            vec![PendingStats {
                name: "carrier-presence".to_owned(),
                change: "token-presence-monitor".to_owned(),
                cases: 1,
            }]
        );
        // Ни один кейс не потерялся между разделами.
        let counted: usize = stats.iter().map(|spec| spec.cases).sum::<usize>()
            + pending.iter().map(|spec| spec.cases).sum::<usize>();
        assert_eq!(counted, registry.cases().count());
    }

    #[test]
    fn the_rendered_block_sorts_and_sums() {
        let stats = vec![
            SpecStats {
                name: "revocation".to_owned(),
                scenarios: 19,
                cases: 6,
            },
            SpecStats {
                name: "hooks".to_owned(),
                scenarios: 7,
                cases: 0,
            },
            SpecStats {
                name: "role-store".to_owned(),
                scenarios: 13,
                cases: 1,
            },
            SpecStats {
                name: "configuration".to_owned(),
                scenarios: 19,
                cases: 0,
            },
            // Равное число кейсов с revocation, но сценариев меньше.
            SpecStats {
                name: "cert-authentication-flow".to_owned(),
                scenarios: 15,
                cases: 6,
            },
            // Полное равенство с device-tags — разводит только имя.
            SpecStats {
                name: "host-identity".to_owned(),
                scenarios: 6,
                cases: 0,
            },
            SpecStats {
                name: "device-tags".to_owned(),
                scenarios: 6,
                cases: 0,
            },
        ];
        let block = render(&stats, &[], 29);
        assert!(
            block.contains("| Спек в `openspec/specs/` | 7 |"),
            "{block}"
        );
        assert!(block.contains("| Сценариев в них | 85 |"), "{block}");
        assert!(block.contains("| Кейсов в реестре | 29 |"), "{block}");
        assert!(
            block.contains("| Спек, к которым привязан хотя бы один кейс | 3 |"),
            "{block}"
        );
        assert!(block.contains("| Спек без единого кейса | 4 |"), "{block}");

        let position = |row: &str| block.find(row).unwrap_or_else(|| panic!("{row}: {block}"));
        // Больше кейсов — выше.
        assert!(position("| revocation | 19 | 6 |") < position("| role-store | 13 | 1 |"));
        // При равенстве кейсов выше та, у которой больше сценариев.
        assert!(
            position("| revocation | 19 | 6 |") < position("| cert-authentication-flow | 15 | 6 |"),
            "{block}"
        );
        // Больше сценариев — выше, а при полном равенстве порядок задаёт имя,
        // а не порядок обхода каталога.
        assert!(position("| configuration | 19 |") < position("| hooks | 7 |"));
        assert!(
            position("| device-tags | 6 |") < position("| host-identity | 6 |"),
            "{block}"
        );

        // Несинкнутых спек нет — раздела о них тоже нет.
        assert!(!block.contains("не синкнутые"), "{block}");
        assert!(
            !block.contains("| Спека | Предложение | Кейсов |"),
            "{block}"
        );
    }

    #[test]
    fn pending_specs_get_their_own_section_that_reconciles_the_count() {
        let stats = vec![SpecStats {
            name: "revocation".to_owned(),
            scenarios: 19,
            cases: 6,
        }];
        let pending = vec![
            PendingStats {
                name: "carrier-presence".to_owned(),
                change: "token-presence-monitor".to_owned(),
                cases: 1,
            },
            PendingStats {
                name: "credential-packaging".to_owned(),
                change: "issuer-key-generation".to_owned(),
                cases: 2,
            },
        ];
        let block = render(&stats, &pending, 9);
        assert!(
            block.contains("## Спеки, ещё не синкнутые из предложений"),
            "{block}"
        );
        assert!(block.contains("На них ссылается кейсов: 3."), "{block}");
        assert!(
            block.contains("| Спека | Предложение | Кейсов |"),
            "{block}"
        );
        assert!(
            block.contains("| credential-packaging | issuer-key-generation | 2 |"),
            "{block}"
        );
        // Больше кейсов — выше; таблица идёт после «Спеки без кейсов».
        let position = |row: &str| block.find(row).unwrap_or_else(|| panic!("{row}: {block}"));
        assert!(
            position("## Спеки без кейсов") < position("## Спеки, ещё не синкнутые из предложений")
        );
        assert!(
            position("| credential-packaging | issuer-key-generation | 2 |")
                < position("| carrier-presence | token-presence-monitor | 1 |"),
            "{block}"
        );
    }

    #[test]
    fn only_the_region_between_the_markers_is_replaced() {
        let text = format!("шапка\n\n{BEGIN}\nстарое\n{END}\n\nхвост\n");
        let region = locate(&text, Path::new("COVERAGE.md")).unwrap();
        assert_eq!(text.get(region.clone()).unwrap(), "старое\n");
        let spliced = format!(
            "{}{}{}",
            text.get(..region.start).unwrap(),
            "новое\n",
            text.get(region.end..).unwrap()
        );
        assert_eq!(
            spliced,
            format!("шапка\n\n{BEGIN}\nновое\n{END}\n\nхвост\n")
        );
    }

    #[test]
    fn a_file_without_markers_is_an_error_not_a_silent_overwrite() {
        let err = locate("рукописный текст\n", Path::new("COVERAGE.md")).unwrap_err();
        let text = err.to_string();
        assert!(text.contains(BEGIN), "{text}");

        let only_begin = format!("{BEGIN}\nхвост\n");
        let err = locate(&only_begin, Path::new("COVERAGE.md")).unwrap_err();
        assert!(err.to_string().contains(END), "{err}");

        let swapped = format!("{END}\nсередина\n{BEGIN}\n");
        let err = locate(&swapped, Path::new("COVERAGE.md")).unwrap_err();
        assert!(matches!(err, CoverageError::MarkersSwapped { .. }), "{err}");
    }

    #[test]
    fn a_marker_at_the_very_start_of_the_file_is_found() {
        let text = format!("{BEGIN}\nтело\n{END}\n");
        let region = locate(&text, Path::new("COVERAGE.md")).unwrap();
        assert_eq!(text.get(region).unwrap(), "тело\n");
    }
}
