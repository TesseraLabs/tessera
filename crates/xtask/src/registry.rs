//! Модель реестра e2e-кейсов и его загрузка из YAML.
//!
//! Реестр — это набор suite-файлов `*.yaml`, каждый описывает группу кейсов.
//! Формат намеренно беден: четыре сорта шагов и три вида ожиданий. Как только
//! кейсу нужны условие или цикл, логика уезжает в хелпер, иначе реестр
//! выродится в недо-язык, который придётся сопровождать наравне с продуктом.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::de::Error as _;
use serde::{Deserialize, Serialize};

/// Ошибки загрузки и валидации реестра.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// Каталог кейсов недоступен.
    #[error("каталог кейсов {path} недоступен: {source}")]
    Dir {
        /// Путь к каталогу.
        path: PathBuf,
        /// Причина.
        source: std::io::Error,
    },
    /// Файл suite не читается.
    #[error("не прочитать {path}: {source}")]
    Read {
        /// Путь к файлу.
        path: PathBuf,
        /// Причина.
        source: std::io::Error,
    },
    /// Файл suite не разбирается.
    #[error("{path}: разбор YAML: {source}")]
    Parse {
        /// Путь к файлу.
        path: PathBuf,
        /// Причина.
        source: serde_norway::Error,
    },
    /// Реестр внутренне противоречив.
    #[error("реестр некорректен: {0}")]
    Invalid(String),
    /// Кейс ссылается на спеку, которой нет ни среди принятых, ни в предложениях.
    #[error(
        "{path}: кейс {case}: спека {requirement} не найдена — \
         ни файла в корне репозитория, ни каталога openspec/changes/*/specs/{name}/spec.md"
    )]
    MissingRequirement {
        /// Файл suite, в котором лежит кейс.
        path: PathBuf,
        /// Идентификатор кейса.
        case: String,
        /// Значение поля `requirement`, как оно записано в кейсе.
        requirement: String,
        /// Имя спеки, выведенное из пути; по нему шёл поиск в предложениях.
        name: String,
    },
    /// Из значения `requirement` не выводится имя спеки.
    #[error(
        "{path}: кейс {case}: ссылка {requirement} не ведёт на спеку; \
         ожидается путь от корня репозитория ровно вида openspec/specs/<имя>/spec.md \
         (допустим якорь #<раздел>), иначе кейс выпадает из матрицы покрытия"
    )]
    MalformedRequirement {
        /// Файл suite, в котором лежит кейс.
        path: PathBuf,
        /// Идентификатор кейса.
        case: String,
        /// Значение поля `requirement`, как оно записано в кейсе.
        requirement: String,
    },
}

/// Suite — группа кейсов, живущая в одном файле реестра.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_field_names,
    reason = "имена полей заданы форматом файла реестра"
)]
pub struct Suite {
    /// Имя suite; по нему же работает `--filter`.
    pub suite: String,
    /// Человекочитаемое описание.
    #[serde(default)]
    pub description: Option<String>,
    /// Имена подготовительных действий, выполняемых один раз перед первым
    /// кейсом suite в прогоне.
    #[serde(default)]
    pub setup: Vec<String>,
    /// Кейсы suite.
    pub cases: Vec<Case>,
    /// Корень каталога кейсов, из которого загружен файл. Заполняется
    /// загрузчиком: по нему выбирается baseline, свой у публичной и приватной
    /// частей реестра.
    #[serde(skip)]
    pub root: PathBuf,
    /// Путь к файлу suite — нужен только для сообщений об ошибках.
    #[serde(skip)]
    pub path: PathBuf,
}

/// Отдельный кейс реестра.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    /// Уникальный в пределах прогона идентификатор, например `AUTH-001`.
    pub id: String,
    /// Формулировка проверяемой гарантии.
    pub title: String,
    /// Ссылка на требование спеки, которое кейс проверяет.
    pub requirement: String,
    /// Возможности окружения, без которых кейс не имеет смысла.
    #[serde(default)]
    pub requires: Vec<String>,
    /// Сценарий.
    pub steps: Vec<Step>,
    /// Уборка; выполняется при любом исходе кейса.
    #[serde(default)]
    pub teardown: Vec<Step>,
}

/// Режим кейса. Не задаётся в YAML, а выводится из состава шагов — иначе
/// пометку можно рассинхронизировать с содержимым.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaseMode {
    /// Только автоматические шаги.
    Auto,
    /// Автоматические шаги вперемешку с паузами для оператора.
    Mixed,
    /// Только паузы: кейс целиком ручной.
    Manual,
}

impl fmt::Display for CaseMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Auto => "auto",
            Self::Mixed => "mixed",
            Self::Manual => "manual",
        };
        f.write_str(text)
    }
}

impl CaseMode {
    /// Требует ли режим присутствия оператора.
    #[must_use]
    pub fn needs_operator(self) -> bool {
        matches!(self, Self::Mixed | Self::Manual)
    }
}

impl Case {
    /// Режим кейса, выведенный из состава шагов сценария.
    ///
    /// Teardown в расчёт не берётся: он служебный и не описывает проверяемую
    /// гарантию.
    #[must_use]
    pub fn mode(&self) -> CaseMode {
        let pauses = self
            .steps
            .iter()
            .filter(|step| matches!(step, Step::Pause(_)))
            .count();
        if pauses == 0 {
            CaseMode::Auto
        } else if pauses == self.steps.len() {
            CaseMode::Manual
        } else {
            CaseMode::Mixed
        }
    }
}

/// Шаг сценария.
#[derive(Debug, Clone)]
pub enum Step {
    /// Выполнить команду в целевом окружении и сверить результат с ожиданием.
    Run(RunStep),
    /// Проверить журнал службы за время кейса.
    ExpectJournal(JournalStep),
    /// Проверить файл в целевом окружении.
    ExpectFile(FileStep),
    /// Остановиться и передать управление оператору.
    Pause(PauseStep),
}

impl Step {
    /// Короткое описание шага для отчёта.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Run(step) => format!("run: {}", step.run),
            Self::ExpectJournal(step) => format!("expect_journal: {}", step.source.value()),
            Self::ExpectFile(step) => format!("expect_file: {}", step.path),
            Self::Pause(step) => format!("pause: {}", step.pause),
        }
    }

    /// Вид шага одним словом — попадает в `report.json`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Run(_) => "run",
            Self::ExpectJournal(_) => "expect_journal",
            Self::ExpectFile(_) => "expect_file",
            Self::Pause(_) => "pause",
        }
    }
}

/// Шаг «выполнить команду».
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunStep {
    /// Команда; исполняется через `sh -lc` в целевом окружении.
    pub run: String,
    /// Что подать команде на стандартный ввод.
    #[serde(default)]
    pub stdin: Option<String>,
    /// Ожидание. По умолчанию — нулевой код возврата.
    #[serde(default)]
    pub expect: Expect,
    /// Таймаут шага в секундах.
    #[serde(default)]
    pub timeout: Option<u64>,
}

/// Ожидание от выполненной команды.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    /// Ожидаемый код возврата.
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// Регулярное выражение, которому должен удовлетворять stdout.
    #[serde(default)]
    pub stdout_matches: Option<String>,
    /// Регулярное выражение, которому должен удовлетворять stderr.
    #[serde(default)]
    pub stderr_matches: Option<String>,
}

impl Expect {
    /// Код возврата, которого ждём: явный либо нулевой по умолчанию.
    #[must_use]
    pub fn expected_exit_code(&self) -> i32 {
        self.exit_code.unwrap_or(0)
    }
}

/// Чем ограничен срез журнала.
///
/// Юнита недостаточно: PAM-модуль службой не является и пишет в журнал через
/// syslog под своим идентификатором, поэтому `-u` его записей не находит вовсе.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalSource {
    /// Systemd-юнит, отбор через `journalctl -u`.
    Unit(String),
    /// Идентификатор syslog, отбор через `journalctl -t`.
    Identifier(String),
}

impl JournalSource {
    /// Ключ `journalctl`, которым задаётся отбор.
    #[must_use]
    pub fn flag(&self) -> &'static str {
        match self {
            Self::Unit(_) => "-u",
            Self::Identifier(_) => "-t",
        }
    }

    /// Значение отбора — имя юнита либо идентификатор.
    #[must_use]
    pub fn value(&self) -> &str {
        match self {
            Self::Unit(value) | Self::Identifier(value) => value,
        }
    }

    /// Копия отбора с подставленным значением.
    #[must_use]
    pub fn with_value(&self, value: String) -> Self {
        match self {
            Self::Unit(_) => Self::Unit(value),
            Self::Identifier(_) => Self::Identifier(value),
        }
    }
}

/// Шаг «проверить журнал».
#[derive(Debug, Clone)]
pub struct JournalStep {
    /// Чем ограничен срез журнала.
    pub source: JournalSource,
    /// Регулярное выражение, которое должно найтись в срезе журнала за время кейса.
    pub matches: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalStepFields {
    #[serde(default)]
    unit: Option<String>,
    #[serde(default)]
    identifier: Option<String>,
    matches: String,
}

impl<'de> Deserialize<'de> for JournalStep {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fields = JournalStepFields::deserialize(deserializer)?;
        // Молчаливое предпочтение одного ключа другому дало бы шаг, который
        // проверяет не тот срез журнала, что написал автор кейса, — и провал
        // выглядел бы дефектом продукта.
        let source = match (fields.unit, fields.identifier) {
            (Some(unit), None) => JournalSource::Unit(unit),
            (None, Some(identifier)) => JournalSource::Identifier(identifier),
            (Some(_), Some(_)) => {
                return Err(D::Error::custom(
                    "expect_journal: unit и identifier взаимоисключающие, задайте ровно один",
                ))
            }
            (None, None) => return Err(D::Error::custom(
                "expect_journal: нужен unit (systemd-юнит) либо identifier (идентификатор syslog)",
            )),
        };
        Ok(Self {
            source,
            matches: fields.matches,
        })
    }
}

/// Шаг «проверить файл».
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileStep {
    /// Путь в целевом окружении.
    pub path: String,
    /// Ожидание существования (по умолчанию — существует).
    #[serde(default)]
    pub exists: Option<bool>,
    /// Ожидаемые права в восьмеричной записи, например `0644`.
    #[serde(default)]
    pub mode: Option<String>,
    /// Регулярное выражение по содержимому файла.
    #[serde(default)]
    pub matches: Option<String>,
}

/// Шаг «пауза для оператора».
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PauseStep {
    /// Инструкция, которую увидит оператор.
    pub pause: String,
    /// Имя переменной, в которую ляжет ответ оператора.
    #[serde(default)]
    pub capture: Option<String>,
}

impl<'de> Deserialize<'de> for Step {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Разбираем через промежуточное значение, а не через `#[serde(untagged)]`:
        // untagged на ошибке сообщает лишь «не подошёл ни один вариант», а
        // автору кейса нужно знать, какое именно поле он написал неверно.
        let value = serde_norway::Value::deserialize(deserializer)?;
        let mapping = value
            .as_mapping()
            .ok_or_else(|| D::Error::custom("шаг должен быть отображением"))?;
        let has = |key: &str| mapping.contains_key(serde_norway::Value::String(key.to_owned()));

        if has("run") {
            RunStep::deserialize(value)
                .map(Step::Run)
                .map_err(D::Error::custom)
        } else if has("expect_journal") {
            JournalWrapper::deserialize(value)
                .map(|w| Step::ExpectJournal(w.expect_journal))
                .map_err(D::Error::custom)
        } else if has("expect_file") {
            FileWrapper::deserialize(value)
                .map(|w| Step::ExpectFile(w.expect_file))
                .map_err(D::Error::custom)
        } else if has("pause") {
            PauseStep::deserialize(value)
                .map(Step::Pause)
                .map_err(D::Error::custom)
        } else {
            Err(D::Error::custom(
                "шаг должен начинаться с одного из ключей: run, expect_journal, expect_file, pause",
            ))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalWrapper {
    expect_journal: JournalStep,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileWrapper {
    expect_file: FileStep,
}

/// Спека, на которую ссылается кейс, но которая ещё не синкнута из
/// предложения в `openspec/specs/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSpec {
    /// Имя спеки — оно же имя будущего каталога в `openspec/specs/`.
    pub name: String,
    /// Предложение, внутри которого спека живёт сейчас.
    pub change: String,
}

/// Загруженный реестр — склейка одного или нескольких каталогов кейсов.
#[derive(Debug, Default)]
pub struct Registry {
    /// Suite'ы в порядке загрузки.
    pub suites: Vec<Suite>,
    /// Спеки, которые ещё не синкнуты из предложений, в порядке имени.
    pub pending_specs: Vec<PendingSpec>,
}

impl Registry {
    /// Загружает и проверяет реестр из перечисленных каталогов.
    ///
    /// Ссылки `requirement` разрешаются относительно корня репозитория, в
    /// котором собран сам раннер.
    ///
    /// # Ошибки
    ///
    /// Возвращает ошибку, если каталог недоступен, файл не разбирается или
    /// реестр не проходит проверку целостности.
    pub fn load(dirs: &[PathBuf]) -> Result<Self, RegistryError> {
        Self::load_from(dirs, &crate::repo_root())
    }

    /// То же, но с явным корнем репозитория, относительно которого
    /// разрешаются ссылки `requirement`.
    ///
    /// # Ошибки
    ///
    /// См. [`Registry::load`].
    pub fn load_from(dirs: &[PathBuf], repo_root: &Path) -> Result<Self, RegistryError> {
        let mut registry = Self::default();
        for dir in dirs {
            registry.load_dir(dir)?;
        }
        registry.validate()?;
        let pending = registry.check_requirements(repo_root)?;
        registry.pending_specs = pending;
        Ok(registry)
    }

    fn load_dir(&mut self, dir: &Path) -> Result<(), RegistryError> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .map_err(|source| RegistryError::Dir {
                path: dir.to_path_buf(),
                source,
            })?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
            })
            .collect();
        // Порядок файлов задаёт порядок прогона, поэтому он должен быть
        // предсказуемым, а не зависеть от порядка обхода каталога.
        files.sort();

        for file in files {
            let text = std::fs::read_to_string(&file).map_err(|source| RegistryError::Read {
                path: file.clone(),
                source,
            })?;
            let mut suite: Suite =
                serde_norway::from_str(&text).map_err(|source| RegistryError::Parse {
                    path: file.clone(),
                    source,
                })?;
            suite.root = dir.to_path_buf();
            suite.path = file;
            self.suites.push(suite);
        }
        Ok(())
    }

    /// Проверяет целостность: уникальность идентификаторов, непустые сценарии,
    /// компилируемость всех регулярных выражений.
    ///
    /// # Ошибки
    ///
    /// Возвращает описание первой найденной проблемы.
    pub fn validate(&self) -> Result<(), RegistryError> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for suite in &self.suites {
            for case in &suite.cases {
                if !seen.insert(case.id.as_str()) {
                    return Err(RegistryError::Invalid(format!(
                        "идентификатор кейса {} встречается дважды",
                        case.id
                    )));
                }
                if case.steps.is_empty() {
                    return Err(RegistryError::Invalid(format!(
                        "кейс {} не содержит шагов",
                        case.id
                    )));
                }
                if case.requirement.trim().is_empty() {
                    return Err(RegistryError::Invalid(format!(
                        "кейс {} не ссылается на требование",
                        case.id
                    )));
                }
                for step in case.steps.iter().chain(case.teardown.iter()) {
                    validate_patterns(&case.id, step)?;
                }
            }
        }
        Ok(())
    }

    /// Проверяет, что каждая ссылка `requirement` куда-то ведёт.
    ///
    /// Сначала проверяется форма пути, и только потом существование файла.
    /// Наоборот нельзя: любой существующий файл репозитория прошёл бы проверку,
    /// но в матрицу покрытия такой кейс всё равно не попадает — имя спеки из
    /// него не выводится. Гейт зеленел бы на кейсе без ссылки на спеку, то есть
    /// ровно на том, что обязан ловить.
    ///
    /// Спека либо уже принята и лежит по указанному пути, либо ещё живёт внутри
    /// предложения. Второе законно и правится само: кейс уже несёт канонический
    /// путь, а синк спеки создаёт ровно этот файл.
    fn check_requirements(&self, repo_root: &Path) -> Result<Vec<PendingSpec>, RegistryError> {
        let changes_root = repo_root.join("openspec").join("changes");
        let mut pending: BTreeMap<String, String> = BTreeMap::new();
        for suite in &self.suites {
            for case in &suite.cases {
                let name = spec_name(&case.requirement).ok_or_else(|| {
                    RegistryError::MalformedRequirement {
                        path: suite.path.clone(),
                        case: case.id.clone(),
                        requirement: case.requirement.clone(),
                    }
                })?;
                if repo_root.join(spec_path(case.requirement.trim())).is_file() {
                    continue;
                }
                let Some(change) = find_change_with_spec(&changes_root, name) else {
                    return Err(RegistryError::MissingRequirement {
                        path: suite.path.clone(),
                        case: case.id.clone(),
                        requirement: case.requirement.clone(),
                        name: name.to_owned(),
                    });
                };
                pending.insert(name.to_owned(), change);
            }
        }
        Ok(pending
            .into_iter()
            .map(|(name, change)| PendingSpec { name, change })
            .collect())
    }

    /// Замечания, не мешающие прогону: их печатают до первого кейса.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        self.pending_specs
            .iter()
            .map(|spec| {
                format!(
                    "спека `{}` ещё не синкнута: сейчас она живёт в предложении `{}`. \
                     Ссылка в кейсе уже каноническая и заработает сама, как только спека \
                     переедет в openspec/specs/ — менять её не надо",
                    spec.name, spec.change
                )
            })
            .collect()
    }

    /// Перебирает кейсы вместе с их suite в порядке прогона.
    pub fn cases(&self) -> impl Iterator<Item = (&Suite, &Case)> {
        self.suites
            .iter()
            .flat_map(|suite| suite.cases.iter().map(move |case| (suite, case)))
    }
}

/// Компилирует шаблон ожидания — единственное место, где это делается.
///
/// Многострочный режим включён всегда. Шаги печатают строки, и `^…$` автор
/// кейса пишет про строку, а не про весь вывод: без этого режима `^1$` не
/// совпадёт с выводом `1\n`, потому что `$` в Rust regex по умолчанию значит
/// конец текста. Ловушка опасна тем, что выглядит как дефект продукта — то
/// есть даёт ровно тот ложный сигнал, который контур обязан исключать.
///
/// Режим задаётся флагом компиляции, а не приписыванием `(?m)` к тексту:
/// подстановка исказила бы шаблон в сообщениях об ошибках и в отчёте, где
/// автор кейса должен видеть ровно то, что написал.
///
/// Хвостовой перевод строки при этом не срезается: обрезка чинила бы только
/// последнюю строку вывода и оставляла ту же ловушку для проверок в середине.
///
/// # Ошибки
///
/// Шаблон не компилируется.
pub fn compile_pattern(pattern: &str) -> Result<regex::Regex, regex::Error> {
    regex::RegexBuilder::new(pattern).multi_line(true).build()
}

/// Путь к файлу спеки из значения `requirement`: якорь на заголовок внутри
/// файла к пути не относится.
fn spec_path(requirement: &str) -> &str {
    requirement.split('#').next().unwrap_or(requirement)
}

/// Имя спеки из ссылки канонического вида `openspec/specs/<имя>/spec.md`.
///
/// Форма проверяется целиком, а не «есть ли предпоследний сегмент»: из ссылки
/// произвольного вида имя спеки не выводится, а значит, кейс с такой ссылкой
/// не попадёт в матрицу покрытия. Сегменты сравниваются как текст, а не через
/// [`Path`]: в реестре путь всегда пишется через прямой слэш, каким бы ни была
/// система, где раннер собран.
#[must_use]
pub fn spec_name(requirement: &str) -> Option<&str> {
    let mut segments = spec_path(requirement.trim()).split('/');
    if segments.next()? != "openspec" || segments.next()? != "specs" {
        return None;
    }
    let name = segments.next()?;
    if segments.next()? != "spec.md" || segments.next().is_some() {
        return None;
    }
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    Some(name)
}

/// Ищет спеку с таким именем среди незаархивированных предложений и
/// возвращает имя change'а.
fn find_change_with_spec(changes_root: &Path, name: &str) -> Option<String> {
    let mut changes: Vec<PathBuf> = std::fs::read_dir(changes_root)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    // Один и тот же реестр должен давать одно и то же сообщение независимо от
    // порядка обхода каталога.
    changes.sort();
    changes.into_iter().find_map(|change| {
        let spec = change.join("specs").join(name).join("spec.md");
        if spec.is_file() {
            change
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .map(str::to_owned)
        } else {
            None
        }
    })
}

fn validate_patterns(case_id: &str, step: &Step) -> Result<(), RegistryError> {
    // Регулярные выражения компилируются на загрузке, а не в момент шага:
    // опечатка в шаблоне должна валить прогон до того, как стенд что-то поменял.
    let patterns: Vec<&str> = match step {
        Step::Run(run) => run
            .expect
            .stdout_matches
            .iter()
            .chain(run.expect.stderr_matches.iter())
            .map(String::as_str)
            .collect(),
        Step::ExpectJournal(journal) => vec![journal.matches.as_str()],
        Step::ExpectFile(file) => file.matches.iter().map(String::as_str).collect(),
        Step::Pause(_) => Vec::new(),
    };
    for pattern in patterns {
        compile_pattern(pattern).map_err(|err| {
            RegistryError::Invalid(format!("кейс {case_id}: шаблон `{pattern}`: {err}"))
        })?;
    }
    Ok(())
}

/// Подходит ли кейс под фильтр: сравнение идёт и по идентификатору кейса,
/// и по имени suite.
#[must_use]
pub fn matches_filter(suite: &Suite, case: &Case, filter: Option<&str>) -> bool {
    match filter {
        None => true,
        Some(needle) => {
            case.id.eq_ignore_ascii_case(needle) || suite.suite.eq_ignore_ascii_case(needle)
        }
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

    const SAMPLE: &str = r#"
suite: auth
description: Аутентификация по удостоверению
setup: [install-package]
cases:
  - id: AUTH-001
    title: Валидное удостоверение пускает пользователя
    requirement: specs/tessera-platform.md#аутентификация
    requires: [service-manager, usb]
    steps:
      - run: helpers/usb-loop.sh attach {{fixtures}}/leaf.p12
      - run: helpers/pam-drive certauth {{user}} authenticate
        stdin: "{{pin}}"
        expect: { exit_code: 0, stdout_matches: "auth: PAM_SUCCESS" }
      - expect_journal: { unit: tessera, matches: "auth ok" }
      - expect_file: { path: /etc/tessera/config.toml, mode: "0644" }
    teardown:
      - run: helpers/usb-loop.sh detach
"#;

    fn parse(text: &str) -> Suite {
        serde_norway::from_str(text).unwrap()
    }

    #[test]
    fn parses_all_four_step_kinds() {
        let suite = parse(SAMPLE);
        assert_eq!(suite.suite, "auth");
        assert_eq!(suite.setup, vec!["install-package".to_owned()]);
        let case = &suite.cases[0];
        assert_eq!(case.id, "AUTH-001");
        assert_eq!(case.requires, vec!["service-manager", "usb"]);
        assert_eq!(case.steps.len(), 4);
        assert!(matches!(case.steps[0], Step::Run(_)));
        assert!(matches!(case.steps[2], Step::ExpectJournal(_)));
        assert!(matches!(case.steps[3], Step::ExpectFile(_)));
        assert_eq!(case.teardown.len(), 1);

        let Step::Run(run) = &case.steps[1] else {
            panic!("ожидался run-шаг");
        };
        assert_eq!(run.stdin.as_deref(), Some("{{pin}}"));
        assert_eq!(
            run.expect.stdout_matches.as_deref(),
            Some("auth: PAM_SUCCESS")
        );
        assert_eq!(run.expect.expected_exit_code(), 0);
    }

    fn journal_step(fields: &str) -> Result<Suite, serde_norway::Error> {
        serde_norway::from_str(&format!(
            r"
suite: s
cases:
  - id: A-1
    title: t
    requirement: r
    steps:
      - expect_journal: {{ {fields} }}
"
        ))
    }

    #[test]
    fn a_journal_step_accepts_a_syslog_identifier() {
        let suite = journal_step(r#"identifier: pam_tessera, matches: "auth failed""#).unwrap();
        let Step::ExpectJournal(journal) = &suite.cases[0].steps[0] else {
            panic!("ожидался шаг проверки журнала");
        };
        assert_eq!(
            journal.source,
            JournalSource::Identifier("pam_tessera".to_owned())
        );
        assert_eq!(journal.source.flag(), "-t");
        assert_eq!(journal.source.value(), "pam_tessera");
    }

    #[test]
    fn a_journal_step_still_accepts_a_unit() {
        let suite = journal_step(r#"unit: tessera.service, matches: "auth ok""#).unwrap();
        let Step::ExpectJournal(journal) = &suite.cases[0].steps[0] else {
            panic!("ожидался шаг проверки журнала");
        };
        assert_eq!(
            journal.source,
            JournalSource::Unit("tessera.service".to_owned())
        );
        assert_eq!(journal.source.flag(), "-u");
    }

    #[test]
    fn a_journal_step_with_both_selectors_is_rejected() {
        let err = journal_step(r#"unit: tessera, identifier: pam_tessera, matches: "x""#)
            .expect_err("два отбора сразу — неоднозначность, а не выбор по умолчанию");
        let text = err.to_string();
        assert!(
            text.contains("unit") && text.contains("identifier"),
            "{text}"
        );
    }

    #[test]
    fn a_journal_step_without_a_selector_is_rejected() {
        let err = journal_step(r#"matches: "x""#)
            .expect_err("без отбора неизвестно, какой срез журнала проверять");
        let text = err.to_string();
        assert!(
            text.contains("unit") && text.contains("identifier"),
            "{text}"
        );
    }

    #[test]
    fn unknown_step_key_is_rejected() {
        let text = r"
suite: s
cases:
  - id: A-1
    title: t
    requirement: r
    steps:
      - sing: песню
";
        assert!(serde_norway::from_str::<Suite>(text).is_err());
    }

    #[test]
    fn mode_is_derived_from_steps() {
        let auto = parse(SAMPLE);
        assert_eq!(auto.cases[0].mode(), CaseMode::Auto);

        let mixed = parse(
            r"
suite: s
cases:
  - id: A-1
    title: t
    requirement: r
    steps:
      - run: /bin/true
      - pause: извлеките носитель
",
        );
        assert_eq!(mixed.cases[0].mode(), CaseMode::Mixed);

        let manual = parse(
            r"
suite: s
cases:
  - id: A-1
    title: t
    requirement: r
    steps:
      - pause: посмотрите на экран
      - pause: и ещё раз
",
        );
        assert_eq!(manual.cases[0].mode(), CaseMode::Manual);
        assert!(manual.cases[0].mode().needs_operator());
        assert!(!CaseMode::Auto.needs_operator());
    }

    #[test]
    fn teardown_does_not_make_case_manual() {
        let suite = parse(
            r"
suite: s
cases:
  - id: A-1
    title: t
    requirement: r
    steps:
      - run: /bin/true
    teardown:
      - pause: уберите носитель
",
        );
        assert_eq!(suite.cases[0].mode(), CaseMode::Auto);
    }

    #[test]
    fn duplicate_id_fails_validation() {
        let mut registry = Registry::default();
        registry.suites.push(parse(SAMPLE));
        registry.suites.push(parse(SAMPLE));
        let err = registry.validate().unwrap_err().to_string();
        assert!(err.contains("AUTH-001"), "{err}");
    }

    #[test]
    fn broken_pattern_fails_validation() {
        let mut registry = Registry::default();
        registry.suites.push(parse(
            r#"
suite: s
cases:
  - id: A-1
    title: t
    requirement: r
    steps:
      - run: /bin/true
        expect: { stdout_matches: "([" }
"#,
        ));
        let err = registry.validate().unwrap_err().to_string();
        assert!(err.contains("A-1"), "{err}");
    }

    #[test]
    fn case_without_steps_or_requirement_is_rejected() {
        let mut registry = Registry::default();
        registry.suites.push(parse(
            r"
suite: s
cases:
  - id: A-1
    title: t
    requirement: r
    steps: []
",
        ));
        assert!(registry.validate().is_err());

        let mut registry = Registry::default();
        registry.suites.push(parse(
            r"
suite: s
cases:
  - id: A-1
    title: t
    requirement: '  '
    steps:
      - run: /bin/true
",
        ));
        assert!(registry.validate().is_err());
    }

    /// Готовит дерево с одним кейсом, ссылающимся на указанную спеку, и
    /// возвращает корень «репозитория» вместе с каталогом кейсов.
    fn tree_with_requirement(requirement: &str) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let cases = root.path().join("tests/e2e/cases");
        std::fs::create_dir_all(&cases).unwrap();
        std::fs::write(
            cases.join("auth.yaml"),
            format!(
                r"
suite: s
cases:
  - id: A-1
    title: t
    requirement: {requirement}
    steps:
      - run: /bin/true
"
            ),
        )
        .unwrap();
        (root, cases)
    }

    fn write_spec(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "#### Scenario: что-то\n").unwrap();
    }

    #[test]
    fn a_requirement_pointing_at_an_accepted_spec_loads_without_a_word() {
        let (root, cases) = tree_with_requirement("openspec/specs/revocation/spec.md");
        write_spec(&root.path().join("openspec/specs/revocation/spec.md"));
        let registry = Registry::load_from(std::slice::from_ref(&cases), root.path()).unwrap();
        assert!(registry.pending_specs.is_empty());
        assert!(registry.warnings().is_empty());
    }

    #[test]
    fn a_spec_still_living_in_a_change_loads_with_a_warning() {
        let (root, cases) = tree_with_requirement("openspec/specs/carrier-presence/spec.md");
        write_spec(
            &root
                .path()
                .join("openspec/changes/token-presence-monitor/specs/carrier-presence/spec.md"),
        );
        let registry = Registry::load_from(std::slice::from_ref(&cases), root.path()).unwrap();
        assert_eq!(
            registry.pending_specs,
            vec![PendingSpec {
                name: "carrier-presence".to_owned(),
                change: "token-presence-monitor".to_owned(),
            }]
        );
        let warnings = registry.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let warning = &warnings[0];
        assert!(warning.contains("carrier-presence"), "{warning}");
        assert!(warning.contains("token-presence-monitor"), "{warning}");
        // Ссылка в кейсе уже каноническая: синк спеки создаёт ровно тот файл,
        // на который она указывает. Совет её править увёл бы на путь внутри
        // предложения, то есть на неканонический.
        assert!(
            !warning.contains("обнов") && !warning.contains("замен"),
            "предупреждение не должно звать править ссылку: {warning}"
        );
    }

    /// Форма пути проверяется раньше существования файла: иначе кейс со
    /// ссылкой на любой существующий файл репозитория прошёл бы загрузку, но в
    /// матрицу покрытия не попал — имя спеки из такой ссылки не выводится.
    #[test]
    fn an_existing_file_that_is_not_a_spec_is_still_rejected() {
        let (root, cases) = tree_with_requirement("Cargo.toml");
        std::fs::write(root.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        let err = Registry::load_from(std::slice::from_ref(&cases), root.path())
            .expect_err("существование файла не делает ссылку ссылкой на спеку");
        assert!(
            matches!(err, RegistryError::MalformedRequirement { .. }),
            "{err}"
        );
        let text = err.to_string();
        assert!(text.contains("openspec/specs/"), "{text}");
    }

    #[test]
    fn only_the_canonical_shape_of_a_requirement_is_accepted() {
        for requirement in [
            "openspec/specs/revocation/spec.md",
            "openspec/specs/revocation/spec.md#раздел",
        ] {
            assert_eq!(spec_name(requirement), Some("revocation"), "{requirement}");
        }
        for requirement in [
            "Cargo.toml",
            "r",
            "specs/revocation/spec.md",
            "/openspec/specs/revocation/spec.md",
            "../openspec/specs/revocation/spec.md",
            "openspec/changes/token-presence-monitor/specs/carrier-presence/spec.md",
            "openspec/specs/revocation/README.md",
            "openspec/specs/revocation",
            "openspec/specs//spec.md",
        ] {
            assert_eq!(spec_name(requirement), None, "{requirement}");
        }
    }

    #[test]
    fn a_requirement_pointing_nowhere_stops_the_run() {
        let (root, cases) = tree_with_requirement("openspec/specs/выдумка/spec.md");
        std::fs::create_dir_all(root.path().join("openspec/changes")).unwrap();
        let err = Registry::load_from(std::slice::from_ref(&cases), root.path())
            .expect_err("ссылка в никуда выключает кейс из матрицы покрытия молча");
        assert!(
            matches!(err, RegistryError::MissingRequirement { .. }),
            "{err}"
        );
        let text = err.to_string();
        assert!(text.contains("A-1") && text.contains("выдумка"), "{text}");
    }

    #[test]
    fn a_requirement_without_a_spec_directory_is_rejected() {
        let (root, cases) = tree_with_requirement("r");
        let err = Registry::load_from(std::slice::from_ref(&cases), root.path())
            .expect_err("из такой ссылки не выводится имя спеки");
        assert!(
            matches!(err, RegistryError::MalformedRequirement { .. }),
            "{err}"
        );
    }

    #[test]
    fn an_anchor_does_not_break_the_lookup() {
        let (root, cases) = tree_with_requirement("openspec/specs/revocation/spec.md#отзыв");
        write_spec(&root.path().join("openspec/specs/revocation/spec.md"));
        let registry = Registry::load_from(std::slice::from_ref(&cases), root.path()).unwrap();
        assert!(registry.pending_specs.is_empty());
    }

    /// Реестр в репозитории — контракт между раннером и автором кейсов:
    /// `deny_unknown_fields` не прощает опечатку, а битый шаблон или
    /// повторённый идентификатор всплыли бы иначе только на стенде, посреди
    /// прогона и уже после того, как окружение что-то поменяло.
    #[test]
    fn the_registry_in_the_repository_loads_and_validates() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/e2e/cases");
        if !dir.is_dir() {
            // Каталог кейсов появляется вместе с образами и хелперами;
            // до этого проверять нечего.
            return;
        }
        let registry = Registry::load(std::slice::from_ref(&dir))
            .unwrap_or_else(|err| panic!("реестр {}: {err}", dir.display()));
        assert!(
            registry.cases().count() > 0,
            "в {} не нашлось ни одного кейса",
            dir.display()
        );
        for suite in &registry.suites {
            // Suite без имени не отфильтровать и не найти в отчёте.
            assert!(
                !suite.suite.trim().is_empty(),
                "{}: пустое имя suite",
                suite.path.display()
            );
            assert_eq!(
                suite.root, dir,
                "корень suite задаёт baseline и должен совпадать с каталогом загрузки"
            );
        }
    }

    #[test]
    fn an_anchored_pattern_matches_a_line_not_the_whole_output() {
        // Команда печатает `1\n`, а автор кейса пишет `^1$` про строку.
        // Без многострочного режима это не совпало бы, и сбой выглядел бы
        // как дефект продукта.
        let re = compile_pattern("^1$").unwrap();
        assert!(re.is_match("1\n"));
        assert!(re.is_match("1"));
        // Якорь по-прежнему якорь: строка целиком, а не её кусок.
        assert!(!re.is_match("21\n"));
        assert!(!re.is_match("1 2\n"));
    }

    #[test]
    fn an_anchored_pattern_matches_a_line_in_the_middle_of_the_output() {
        // Обрезка хвостового перевода строки этот случай не чинит — потому
        // её и не берём.
        let re = compile_pattern("^tessera$").unwrap();
        assert!(re.is_match("pam_unix\ntessera\npam_deny\n"));
        assert!(!re.is_match("pam_unix\ntessera-agent\npam_deny\n"));
    }

    #[test]
    fn a_multiline_pattern_with_an_explicit_newline_still_matches() {
        // Такие шаблоны в реестре уже есть, и многострочный режим их не ломает.
        let re = compile_pattern(r"auth: PAM_SUCCESS \(0\)\nacct: PAM_SUCCESS \(0\)").unwrap();
        assert!(re.is_match("auth: PAM_SUCCESS (0)\nacct: PAM_SUCCESS (0)\n"));
        assert!(!re.is_match("auth: PAM_SUCCESS (0)\nacct: PAM_AUTH_ERR (7)\n"));
    }

    #[test]
    fn a_pattern_that_should_not_match_still_does_not() {
        let re = compile_pattern("PAM_SUCCESS").unwrap();
        assert!(!re.is_match("auth: PAM_AUTH_ERR\n"));
        assert!(compile_pattern("([").is_err());
    }

    /// Побочный эффект многострочного режима, о котором должен знать автор
    /// кейса: `^$` больше не значит «поток пуст» — пустая позиция находится
    /// после любого хвостового перевода строки. Проверка на пустоту пишется
    /// якорями текста.
    #[test]
    fn an_empty_stream_is_checked_by_text_anchors_not_by_line_anchors() {
        let line_anchors = compile_pattern("^$").unwrap();
        assert!(line_anchors.is_match(""));
        assert!(line_anchors.is_match("предупреждение\n"));

        let text_anchors = compile_pattern(r"\A\z").unwrap();
        assert!(text_anchors.is_match(""));
        assert!(!text_anchors.is_match("предупреждение\n"));
    }

    #[test]
    fn filter_matches_case_and_suite() {
        let suite = parse(SAMPLE);
        let case = &suite.cases[0];
        assert!(matches_filter(&suite, case, None));
        assert!(matches_filter(&suite, case, Some("auth-001")));
        assert!(matches_filter(&suite, case, Some("auth")));
        assert!(!matches_filter(&suite, case, Some("revocation")));
    }
}
