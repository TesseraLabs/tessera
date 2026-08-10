//! Исполнитель кейса: шаги, ожидания, teardown.
//!
//! Исполнение строго последовательное. Параллелизм не вводится сознательно:
//! кейсы делят одно окружение, и гонка за `/etc/tessera` дала бы плавающие
//! провалы дороже сэкономленных минут.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::artifacts::Collector;
use crate::driver::CommandDriver;
use crate::interact::{Operator, Verdict};
use crate::profile::{skip_reason, Profile};
use crate::registry::{compile_pattern, Case, Expect, FileStep, JournalStep, RunStep, Step, Suite};
use crate::report::{CaseResult, Status, StepRecord, TeardownOutcome};
use crate::vars::Vars;

/// Таймаут шага, если его не задали ни кейс, ни профиль.
const DEFAULT_STEP_TIMEOUT: Duration = Duration::from_mins(2);

/// Таймаут доставки артефактов: `.deb` едет по сети на лабораторную машину.
const DELIVERY_TIMEOUT: Duration = Duration::from_mins(10);

/// Переменная, из которой берётся каталог хелперов в окружении.
pub const HELPERS_VAR: &str = "helpers";

/// Что доставить в окружение перед первым действием подготовки.
#[derive(Debug, Clone)]
pub struct Delivery {
    /// Как называется груз в сообщении об ошибке.
    pub what: String,
    /// Источник на машине оператора.
    pub local: PathBuf,
    /// Куда положить в окружении.
    pub remote: String,
    /// Права, которые стенд требует выставить после доставки. `None` — оставить
    /// как есть: у каталогов фикстур и у пакета своих требований нет.
    pub mode: Option<String>,
}

impl Delivery {
    /// Описывает одну доставку.
    #[must_use]
    pub fn new(what: impl Into<String>, local: PathBuf, remote: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            local,
            remote: remote.into(),
            mode: None,
        }
    }

    /// Требует выставить доставленному заданные права.
    #[must_use]
    pub fn with_mode(mut self, mode: impl Into<String>) -> Self {
        self.mode = Some(mode.into());
        self
    }
}

/// Настройки прогона, влияющие на исполнение кейса.
#[derive(Debug, Clone, Copy)]
pub struct ExecOptions {
    /// Кейсы, требующие оператора, не исполняются и получают `BLOCKED`.
    pub non_interactive: bool,
    /// При провале teardown не выполняется, окружение остаётся для разбора.
    pub keep_on_failure: bool,
}

/// Внешние зависимости исполнителя: окружение, профиль, оператор и сборщик
/// диагностики.
pub struct ExecDeps<'a> {
    /// Транспорт до целевого окружения.
    pub driver: &'a dyn CommandDriver,
    /// Профиль, чьи возможности сверяются с `requires`.
    pub profile: &'a Profile,
    /// Кто отвечает на шаги `pause`.
    pub operator: &'a mut dyn Operator,
    /// Куда складывать диагностику непрошедших кейсов.
    pub collector: &'a dyn Collector,
}

/// Исполнитель кейсов в одном окружении.
pub struct Executor<'a> {
    driver: &'a dyn CommandDriver,
    profile: &'a Profile,
    vars: Vars,
    options: ExecOptions,
    interrupt: Arc<AtomicBool>,
    operator: &'a mut dyn Operator,
    collector: &'a dyn Collector,
    deliveries: Vec<Delivery>,
    delivered: bool,
    done_setups: BTreeSet<String>,
    /// Провалившиеся действия подготовки: имя действия → причина. Держится
    /// весь прогон, чтобы каждый следующий кейс, которому нужно то же действие,
    /// получал `ERROR` сразу, а не шёл проверять продукт на неподготовленном
    /// окружении.
    failed_setups: BTreeMap<String, String>,
    /// Признак того, что прогон уже прерывали сигналом. Нужен отдельно от
    /// флага: на время teardown флаг снимается, иначе уборка была бы убита
    /// тем же сигналом, ради которого её и запускают.
    interrupt_latched: bool,
    /// Отметка времени на целевой стороне, с которой берётся срез журнала.
    journal_since: Option<String>,
}

impl<'a> Executor<'a> {
    /// Собирает исполнитель.
    pub fn new(
        deps: ExecDeps<'a>,
        vars: Vars,
        options: ExecOptions,
        deliveries: Vec<Delivery>,
        interrupt: Arc<AtomicBool>,
    ) -> Self {
        let ExecDeps {
            driver,
            profile,
            operator,
            collector,
        } = deps;
        Self {
            driver,
            profile,
            vars,
            options,
            interrupt,
            operator,
            collector,
            deliveries,
            delivered: false,
            done_setups: BTreeSet::new(),
            failed_setups: BTreeMap::new(),
            interrupt_latched: false,
            journal_since: None,
        }
    }

    /// Прогоняет кейс целиком: подготовку suite, шаги и teardown.
    pub fn run_case(&mut self, suite: &Suite, case: &Case) -> CaseResult {
        let started = Instant::now();
        let mode = case.mode();
        let mut result = CaseResult {
            id: case.id.clone(),
            suite: suite.suite.clone(),
            title: case.title.clone(),
            requirement: case.requirement.clone(),
            mode,
            status: Status::Pass,
            reason: None,
            steps: Vec::new(),
            teardown: TeardownOutcome::NotRun,
            registry_root: suite.root.clone(),
            duration_ms: 0,
        };
        self.journal_since = None;

        let missing = self.profile.missing_capabilities(&case.requires);
        if !missing.is_empty() {
            result.status = Status::Skip;
            result.reason = Some(skip_reason(&missing));
            result.duration_ms = started.elapsed().as_millis();
            return result;
        }

        if self.options.non_interactive && mode.needs_operator() {
            result.status = Status::Blocked;
            result.reason = Some(format!("needs operator ({mode})"));
            result.duration_ms = started.elapsed().as_millis();
            return result;
        }

        if let Err(detail) = self.ensure_environment(suite) {
            result.status = Status::Error;
            result.reason = Some(detail);
            result.duration_ms = started.elapsed().as_millis();
            return result;
        }

        if case
            .steps
            .iter()
            .any(|step| matches!(step, Step::ExpectJournal(_)))
        {
            self.journal_since = self.target_timestamp();
        }

        for (position, step) in case.steps.iter().enumerate() {
            if self.interrupt.load(Ordering::SeqCst) {
                self.interrupt_latched = true;
                result.status = Status::Error;
                result.reason = Some("прогон прерван сигналом".to_owned());
                break;
            }
            let record = self.run_step(position + 1, step);
            let status = record.status;
            let detail = record.detail.clone();
            result.steps.push(record);
            if status != Status::Pass {
                result.status = status;
                result.reason = Some(format!(
                    "шаг {}: {}",
                    position + 1,
                    detail.unwrap_or_else(|| status.to_string())
                ));
                break;
            }
        }

        result.duration_ms = started.elapsed().as_millis();
        // Диагностика собирается до уборки: teardown сносит `/etc/tessera` и
        // отвязывает носитель, после чего собирать было бы нечего.
        self.collector
            .collect(&result, self.journal_since.as_deref());
        result.teardown = self.run_teardown(case, result.status);
        result.duration_ms = started.elapsed().as_millis();
        result
    }

    /// Готовит окружение: доставляет артефакты, затем выполняет подготовку
    /// suite. Сбой любой из частей — сбой стенда, а не приговор продукту.
    fn ensure_environment(&mut self, suite: &Suite) -> Result<(), String> {
        self.ensure_delivery()?;
        self.ensure_setup(suite)
    }

    /// Доставляет артефакты один раз за прогон, перед первым действием
    /// подготовки.
    ///
    /// Путь к `.deb` живёт в `stand.toml` и у каждого стенда свой, поэтому
    /// ни аргументы запуска контейнера, ни сборочный контекст образа для этого
    /// не годятся: профиль в git обязан оставаться безадресным.
    fn ensure_delivery(&mut self) -> Result<(), String> {
        if self.delivered {
            return Ok(());
        }
        for delivery in &self.deliveries {
            if !delivery.local.exists() {
                return Err(format!(
                    "доставка ({}): источник {} не найден",
                    delivery.what,
                    delivery.local.display()
                ));
            }
            self.driver
                .deliver(&delivery.local, &delivery.remote, DELIVERY_TIMEOUT)
                .map_err(|err| format!("доставка ({}): {err}", delivery.what))?;
            if let Some(mode) = &delivery.mode {
                crate::driver::apply_mode(self.driver, &delivery.remote, mode, DELIVERY_TIMEOUT)
                    .map_err(|err| format!("доставка ({}): {err}", delivery.what))?;
            }
        }
        self.delivered = true;
        Ok(())
    }

    /// Выполняет подготовку suite один раз за прогон.
    ///
    /// Действие с именем `<name>` — это `<helpers>/setup/<name>.sh` в целевом
    /// окружении: реестру незачем знать, чем именно оно поднимается.
    ///
    /// Провалившееся действие не повторяется: сломанное окружение само не
    /// чинится, а повтор опасен вдвойне. Второй запуск может вернуть ноль,
    /// ничего не исправив (`dpkg -i` на уже распакованном пакете), и тогда
    /// кейсы пойдут по полуготовому окружению и отчитаются `PASS`, не проверив
    /// ничего: каталоги на месте, служба неактивна — но потому, что установка
    /// не состоялась, а не потому, что продукт ведёт себя как обещано.
    fn ensure_setup(&mut self, suite: &Suite) -> Result<(), String> {
        if suite.setup.is_empty() {
            return Ok(());
        }
        // Путь абсолютный, а не относительный: у `docker exec` рабочий каталог
        // задаёт WORKDIR образа, а у `ssh` — домашний каталог пользователя,
        // и относительный путь разрешился бы в разное или ни во что.
        let helpers = self
            .vars
            .plain(HELPERS_VAR)
            .ok_or_else(|| {
                format!("подготовка: профиль не задал переменную {{{{{HELPERS_VAR}}}}}")
            })?
            .to_owned();
        for action in &suite.setup {
            if self.done_setups.contains(action) {
                continue;
            }
            if let Some(detail) = self.failed_setups.get(action) {
                return Err(setup_failure(&format!(
                    "`{action}` провалилось раньше в этом прогоне: {detail}"
                )));
            }
            let command = setup_script_path(&helpers, action);
            let detail = match self.driver.exec(&command, None, DEFAULT_STEP_TIMEOUT) {
                Ok(outcome) if outcome.exit_code == Some(0) => {
                    self.done_setups.insert(action.clone());
                    continue;
                }
                Ok(outcome) => format!(
                    "код {}, {}",
                    outcome.exit_code.unwrap_or(-1),
                    outcome.stderr.trim()
                ),
                Err(err) => err.to_string(),
            };
            self.failed_setups.insert(action.clone(), detail.clone());
            return Err(setup_failure(&format!("`{action}`: {detail}")));
        }
        Ok(())
    }

    fn run_teardown(&mut self, case: &Case, case_status: Status) -> TeardownOutcome {
        if case.teardown.is_empty() {
            return TeardownOutcome::NotRun;
        }
        if self.options.keep_on_failure && case_status != Status::Pass {
            return TeardownOutcome::SkippedByFlag;
        }

        // Teardown выполняется при любом исходе, включая прерывание: «продукт
        // сломан» и «стенд остался грязным» — разные новости, и вторую нельзя
        // получить в нагрузку к первой. На время уборки флаг прерывания
        // снимается, иначе первая же её команда была бы убита; повторный
        // сигнал оператора снова взведёт флаг и оборвёт уборку.
        if self.interrupt.swap(false, Ordering::SeqCst) {
            self.interrupt_latched = true;
        }
        let mut failures = Vec::new();
        for (position, step) in case.teardown.iter().enumerate() {
            let record = self.run_step(position + 1, step);
            if record.status != Status::Pass {
                failures.push(format!(
                    "шаг {}: {}",
                    position + 1,
                    record.detail.unwrap_or_else(|| record.status.to_string())
                ));
            }
        }
        if self.interrupt_latched {
            self.interrupt.store(true, Ordering::SeqCst);
        }
        if failures.is_empty() {
            TeardownOutcome::Ok
        } else {
            TeardownOutcome::Failed {
                detail: failures.join("; "),
            }
        }
    }

    fn run_step(&mut self, index: usize, step: &Step) -> StepRecord {
        let started = Instant::now();
        let mut record = StepRecord {
            index,
            kind: step.kind().to_owned(),
            description: step.describe(),
            status: Status::Pass,
            detail: None,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        };

        match step {
            Step::Run(run) => self.step_run(run, &mut record),
            Step::ExpectJournal(journal) => self.step_journal(journal, &mut record),
            Step::ExpectFile(file) => self.step_file(file, &mut record),
            Step::Pause(pause) => self.step_pause(pause, &mut record),
        }

        record.duration_ms = started.elapsed().as_millis();
        record
    }

    fn step_run(&mut self, step: &RunStep, record: &mut StepRecord) {
        let command = match self.vars.substitute(&step.run) {
            Ok(command) => command,
            Err(err) => return fail_with(record, Status::Error, err.to_string()),
        };
        let stdin = match self.vars.substitute_opt(step.stdin.as_deref()) {
            Ok(stdin) => stdin,
            Err(err) => return fail_with(record, Status::Error, err.to_string()),
        };
        record.description = format!("run: {command}");

        let timeout = self.step_timeout(step.timeout);
        let outcome = match self.driver.exec(&command, stdin.as_deref(), timeout) {
            Ok(outcome) => outcome,
            Err(err) => return fail_with(record, Status::Error, err.to_string()),
        };
        record.exit_code = outcome.exit_code;
        record.stdout.clone_from(&outcome.stdout);
        record.stderr.clone_from(&outcome.stderr);

        if outcome.interrupted {
            return fail_with(record, Status::Error, "шаг прерван сигналом".to_owned());
        }
        if outcome.timed_out {
            // Таймаут — это `ERROR`, а не `FAIL`: что именно произошло за
            // истёкшее время, неизвестно, и приговор продукту выносить не на чем.
            return fail_with(
                record,
                Status::Error,
                format!("шаг не уложился в {} с", timeout.as_secs()),
            );
        }

        // Служебный код хелпера проверяется до ожиданий кейса: «хелпер не
        // отработал» и «продукт повёл себя не так» — разные новости, и вторую
        // нельзя выдавать вместо первой.
        if self
            .profile
            .is_stand_failure(outcome.exit_code, step.expect.expected_exit_code())
        {
            return fail_with(
                record,
                Status::Error,
                format!(
                    "хелпер вернул служебный код {}: сбой стенда, а не вердикт продукта",
                    outcome.exit_code.unwrap_or(-1)
                ),
            );
        }

        if let Some(detail) = check_expectations(
            &step.expect,
            &outcome.stdout,
            &outcome.stderr,
            outcome.exit_code,
        ) {
            fail_with(record, Status::Fail, detail);
        }
    }

    fn step_journal(&mut self, step: &JournalStep, record: &mut StepRecord) {
        let source = match self.vars.substitute(step.source.value()) {
            Ok(value) => step.source.with_value(value),
            Err(err) => return fail_with(record, Status::Error, err.to_string()),
        };
        let pattern = match self.vars.substitute(&step.matches) {
            Ok(pattern) => pattern,
            Err(err) => return fail_with(record, Status::Error, err.to_string()),
        };
        let since = self
            .journal_since
            .clone()
            .unwrap_or_else(|| "-10m".to_owned());
        let (flag, selector) = (source.flag(), source.value());
        let command = format!("journalctl --no-pager {flag} {selector} --since '{since}'");
        record.description = format!("expect_journal: {selector} =~ {pattern}");

        let outcome = match self.driver.exec(&command, None, self.step_timeout(None)) {
            Ok(outcome) => outcome,
            Err(err) => return fail_with(record, Status::Error, err.to_string()),
        };
        record.exit_code = outcome.exit_code;
        record.stdout.clone_from(&outcome.stdout);
        record.stderr.clone_from(&outcome.stderr);

        match compile_pattern(&pattern) {
            Err(err) => fail_with(record, Status::Error, format!("шаблон `{pattern}`: {err}")),
            Ok(re) if !re.is_match(&outcome.stdout) => fail_with(
                record,
                Status::Fail,
                format!("в журнале {selector} нет совпадения с `{pattern}`"),
            ),
            Ok(_) => {}
        }
    }

    fn step_file(&mut self, step: &FileStep, record: &mut StepRecord) {
        let path = match self.vars.substitute(&step.path) {
            Ok(path) => path,
            Err(err) => return fail_with(record, Status::Error, err.to_string()),
        };
        record.description = format!("expect_file: {path}");
        let timeout = self.step_timeout(None);

        let should_exist = step.exists.unwrap_or(true);
        let probe = match self
            .driver
            .exec(&format!("test -e '{path}'"), None, timeout)
        {
            Ok(outcome) => outcome,
            Err(err) => return fail_with(record, Status::Error, err.to_string()),
        };
        let exists = probe.exit_code == Some(0);
        record.exit_code = probe.exit_code;
        if exists != should_exist {
            let detail = if should_exist {
                format!("файла {path} нет")
            } else {
                format!("файл {path} есть, а его быть не должно")
            };
            return fail_with(record, Status::Fail, detail);
        }
        if !should_exist {
            return;
        }

        if let Some(expected_mode) = &step.mode {
            let outcome = match self
                .driver
                .exec(&format!("stat -c %a '{path}'"), None, timeout)
            {
                Ok(outcome) => outcome,
                Err(err) => return fail_with(record, Status::Error, err.to_string()),
            };
            let actual = outcome.stdout.trim().to_owned();
            record.stdout.clone_from(&outcome.stdout);
            if !modes_equal(&actual, expected_mode) {
                return fail_with(
                    record,
                    Status::Fail,
                    format!("права {path}: ожидались {expected_mode}, получены {actual}"),
                );
            }
        }

        if let Some(pattern) = &step.matches {
            let pattern = match self.vars.substitute(pattern) {
                Ok(pattern) => pattern,
                Err(err) => return fail_with(record, Status::Error, err.to_string()),
            };
            let outcome = match self.driver.exec(&format!("cat '{path}'"), None, timeout) {
                Ok(outcome) => outcome,
                Err(err) => return fail_with(record, Status::Error, err.to_string()),
            };
            record.stdout.clone_from(&outcome.stdout);
            match compile_pattern(&pattern) {
                Err(err) => fail_with(record, Status::Error, format!("шаблон `{pattern}`: {err}")),
                Ok(re) if !re.is_match(&outcome.stdout) => fail_with(
                    record,
                    Status::Fail,
                    format!("в {path} нет совпадения с `{pattern}`"),
                ),
                Ok(_) => {}
            }
        }
    }

    fn step_pause(&mut self, step: &crate::registry::PauseStep, record: &mut StepRecord) {
        let text = match self.vars.substitute(&step.pause) {
            Ok(text) => text,
            Err(err) => return fail_with(record, Status::Error, err.to_string()),
        };
        record.description = format!("pause: {text}");

        match self.operator.pause(&text, step.capture.as_deref()) {
            Err(err) => fail_with(record, Status::Error, err.to_string()),
            Ok((Verdict::Ok, captured)) => {
                if let (Some(name), Some(value)) = (step.capture.as_deref(), captured) {
                    record.stdout.clone_from(&value);
                    self.vars.insert_plain(name, value);
                }
            }
            Ok((Verdict::Fail(reason), _)) => fail_with(record, Status::Fail, reason),
            Ok((Verdict::Skip(reason), _)) => fail_with(record, Status::Skip, reason),
        }
    }

    fn step_timeout(&self, requested: Option<u64>) -> Duration {
        requested
            .or(self.profile.default_timeout)
            .map_or(DEFAULT_STEP_TIMEOUT, Duration::from_secs)
    }

    fn target_timestamp(&self) -> Option<String> {
        // Время берём на целевой стороне: расхождение часов раннера и стенда
        // сделало бы срез журнала либо пустым, либо захватившим чужие кейсы.
        let outcome = self
            .driver
            .exec(
                "date -u '+%Y-%m-%d %H:%M:%S'",
                None,
                Duration::from_secs(30),
            )
            .ok()?;
        let stamp = outcome.stdout.trim();
        if outcome.exit_code == Some(0) && !stamp.is_empty() {
            Some(stamp.to_owned())
        } else {
            None
        }
    }
}

fn fail_with(record: &mut StepRecord, status: Status, detail: String) {
    record.status = status;
    record.detail = Some(detail);
}

/// Сверяет результат команды с ожиданием; возвращает описание первого
/// расхождения.
#[must_use]
pub fn check_expectations(
    expect: &Expect,
    stdout: &str,
    stderr: &str,
    exit_code: Option<i32>,
) -> Option<String> {
    let expected = expect.expected_exit_code();
    match exit_code {
        None => return Some("команда убита сигналом, кода возврата нет".to_owned()),
        Some(actual) if actual != expected => {
            return Some(format!("ожидался код {expected}, получен {actual}"))
        }
        Some(_) => {}
    }
    if let Some(pattern) = &expect.stdout_matches {
        if let Some(detail) = mismatch(pattern, stdout, "stdout") {
            return Some(detail);
        }
    }
    if let Some(pattern) = &expect.stderr_matches {
        if let Some(detail) = mismatch(pattern, stderr, "stderr") {
            return Some(detail);
        }
    }
    None
}

fn mismatch(pattern: &str, text: &str, stream: &str) -> Option<String> {
    match compile_pattern(pattern) {
        Err(err) => Some(format!("шаблон `{pattern}`: {err}")),
        Ok(re) if !re.is_match(text) => Some(format!("{stream} не совпал с `{pattern}`")),
        Ok(_) => None,
    }
}

/// Причина отказа исполнять кейс, у которого не поднялось окружение.
///
/// Формулировка одна на все кейсы suite: разбирающему отчёт важно сразу
/// видеть, что вердикт вынесен стенду, а не продукту.
fn setup_failure(detail: &str) -> String {
    format!("подготовка suite не выполнена — {detail}")
}

/// Абсолютный путь скрипта подготовки в целевом окружении.
#[must_use]
pub fn setup_script_path(helpers_dir: &str, action: &str) -> String {
    format!("{}/setup/{action}.sh", helpers_dir.trim_end_matches('/'))
}

/// Сравнивает права, не придираясь к ведущему нулю: `0644` и `644` — одно и то же.
#[must_use]
pub fn modes_equal(actual: &str, expected: &str) -> bool {
    actual.trim_start_matches('0') == expected.trim_start_matches('0')
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

    use std::path::Path;

    use super::*;
    use crate::artifacts::Collector;
    use crate::driver::{DriverError, ProcessOutcome};
    use crate::interact::OperatorError;
    use crate::registry::Suite;
    use crate::report::CaseResult;

    /// Драйвер-заглушка: пишет все выполненные команды и валит те, что
    /// совпадают с заданной подстрокой.
    struct FakeDriver {
        log: RefCell<Vec<String>>,
        fail_on: Option<String>,
        fail_code: i32,
        delivery_fails: bool,
        /// Сколько совпавших вызовов ещё провалить. `None` — проваливать все.
        /// Нужно, чтобы воспроизвести самый опасный случай: второй запуск
        /// сломанного действия возвращает ноль, ничего не исправив.
        failures_left: Option<RefCell<usize>>,
    }

    impl FakeDriver {
        fn new(fail_on: Option<&str>) -> Self {
            Self {
                log: RefCell::new(Vec::new()),
                fail_on: fail_on.map(str::to_owned),
                fail_code: 1,
                delivery_fails: false,
                failures_left: None,
            }
        }

        fn failing_with(fail_on: &str, fail_code: i32) -> Self {
            Self {
                fail_code,
                ..Self::new(Some(fail_on))
            }
        }

        /// Проваливает совпавший вызов ровно один раз, дальше отвечает нулём.
        fn failing_once(fail_on: &str, fail_code: i32) -> Self {
            Self {
                failures_left: Some(RefCell::new(1)),
                ..Self::failing_with(fail_on, fail_code)
            }
        }

        fn commands(&self) -> Vec<String> {
            self.log.borrow().clone()
        }
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
            let matched = self
                .fail_on
                .as_ref()
                .is_some_and(|needle| command.contains(needle.as_str()));
            let failed = matched
                && match &self.failures_left {
                    None => true,
                    Some(left) => {
                        let mut left = left.borrow_mut();
                        let failing = *left > 0;
                        *left = left.saturating_sub(1);
                        failing
                    }
                };
            Ok(ProcessOutcome {
                exit_code: Some(if failed { self.fail_code } else { 0 }),
                stdout: String::new(),
                stderr: String::new(),
                timed_out: false,
                interrupted: false,
            })
        }

        fn deliver(
            &self,
            local: &Path,
            remote: &str,
            _timeout: Duration,
        ) -> Result<(), DriverError> {
            self.log
                .borrow_mut()
                .push(format!("deliver {} -> {remote}", local.display()));
            if self.delivery_fails {
                return Err(DriverError::Failed {
                    operation: "docker cp".to_owned(),
                    code: 1,
                    detail: "нет места на устройстве".to_owned(),
                });
            }
            Ok(())
        }

        fn recreate(&self) -> Result<(), DriverError> {
            Ok(())
        }
    }

    struct NoCollector;

    impl Collector for NoCollector {
        fn collect(&self, _case: &CaseResult, _journal_since: Option<&str>) {}
    }

    /// Оператор-заглушка с заранее заданным вердиктом.
    struct FakeOperator {
        verdict: Verdict,
        captured: Option<String>,
        asked: RefCell<usize>,
    }

    impl Operator for FakeOperator {
        fn pause(
            &mut self,
            _text: &str,
            _capture: Option<&str>,
        ) -> Result<(Verdict, Option<String>), OperatorError> {
            *self.asked.borrow_mut() += 1;
            Ok((self.verdict.clone(), self.captured.clone()))
        }
    }

    fn profile(capabilities: &str) -> Profile {
        toml::from_str(&format!(
            r#"
name = "fake"
driver = "docker"
capabilities = [{capabilities}]

[docker]
container = "c"
image = "i"
"#
        ))
        .unwrap()
    }

    fn suite(yaml: &str) -> Suite {
        serde_norway::from_str(yaml).unwrap()
    }

    /// Заведомо существующий локальный путь, не зависящий от рабочего каталога
    /// тестового бинаря.
    fn delivery_source() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
    }

    struct Harness {
        driver: FakeDriver,
        profile: Profile,
        options: ExecOptions,
        interrupt: Arc<AtomicBool>,
        operator: FakeOperator,
        deliveries: Vec<Delivery>,
        helpers: Option<String>,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                driver: FakeDriver::new(None),
                profile: profile(r#""usb", "service-manager""#),
                options: ExecOptions {
                    non_interactive: false,
                    keep_on_failure: false,
                },
                interrupt: Arc::new(AtomicBool::new(false)),
                operator: FakeOperator {
                    verdict: Verdict::Ok,
                    captured: None,
                    asked: RefCell::new(0),
                },
                deliveries: Vec::new(),
                helpers: Some("/opt/tessera-e2e/helpers".to_owned()),
            }
        }

        /// Доставка существующего файла: источником берётся манифест крейта,
        /// чтобы проверка существования пути была настоящей.
        fn with_delivery(mut self) -> Self {
            self.deliveries = vec![Delivery::new(
                "пакет",
                delivery_source(),
                "/opt/tessera-e2e/pkg/tessera.deb",
            )];
            self
        }

        fn run(&mut self, yaml: &str) -> (CaseResult, Vec<String>) {
            let (mut results, commands) = self.run_all(yaml);
            (results.remove(0), commands)
        }

        /// Прогоняет все кейсы suite одним исполнителем — так же, как это
        /// делает настоящий прогон. Состояние подготовки живёт между кейсами,
        /// и проверять его иначе нельзя.
        fn run_all(&mut self, yaml: &str) -> (Vec<CaseResult>, Vec<String>) {
            let suite = suite(yaml);
            let collector = NoCollector;
            let deps = ExecDeps {
                driver: &self.driver,
                profile: &self.profile,
                operator: &mut self.operator,
                collector: &collector,
            };
            let mut vars = Vars::new();
            vars.insert_plain("user", "tester");
            if let Some(helpers) = &self.helpers {
                vars.insert_plain("helpers", helpers.clone());
            }
            let mut executor = Executor::new(
                deps,
                vars,
                self.options,
                self.deliveries.clone(),
                Arc::clone(&self.interrupt),
            );
            let results = suite
                .cases
                .iter()
                .map(|case| executor.run_case(&suite, case))
                .collect();
            (results, self.driver.commands())
        }
    }

    const HAPPY: &str = r"
suite: auth
cases:
  - id: AUTH-001
    title: гарантия
    requirement: specs
    requires: [usb]
    steps:
      - run: pam-drive {{user}}
    teardown:
      - run: usb-loop detach
";

    #[test]
    fn a_passing_case_runs_its_teardown() {
        let (result, commands) = Harness::new().run(HAPPY);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.teardown, TeardownOutcome::Ok);
        assert_eq!(commands, vec!["pam-drive tester", "usb-loop detach"]);
    }

    #[test]
    fn a_failing_step_still_runs_teardown() {
        let mut harness = Harness::new();
        harness.driver = FakeDriver::new(Some("pam-drive"));
        let (result, commands) = harness.run(HAPPY);
        assert_eq!(result.status, Status::Fail);
        assert_eq!(result.teardown, TeardownOutcome::Ok);
        assert!(
            commands.contains(&"usb-loop detach".to_owned()),
            "{commands:?}"
        );
    }

    #[test]
    fn an_interrupted_run_still_runs_teardown_and_keeps_the_flag_raised() {
        let mut harness = Harness::new();
        harness.interrupt.store(true, Ordering::SeqCst);
        let (result, commands) = harness.run(HAPPY);
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.teardown, TeardownOutcome::Ok);
        assert_eq!(commands, vec!["usb-loop detach".to_owned()]);
        // Флаг восстановлен, иначе прогон продолжил бы исполнять кейсы.
        assert!(harness.interrupt.load(Ordering::SeqCst));
    }

    #[test]
    fn keep_on_failure_skips_teardown_and_says_so() {
        let mut harness = Harness::new();
        harness.driver = FakeDriver::new(Some("pam-drive"));
        harness.options.keep_on_failure = true;
        let (result, commands) = harness.run(HAPPY);
        assert_eq!(result.status, Status::Fail);
        assert_eq!(result.teardown, TeardownOutcome::SkippedByFlag);
        assert!(!commands.contains(&"usb-loop detach".to_owned()));
    }

    #[test]
    fn a_failing_teardown_is_a_separate_category_from_a_failing_case() {
        let mut harness = Harness::new();
        harness.driver = FakeDriver::new(Some("usb-loop"));
        let (result, _) = harness.run(HAPPY);
        assert_eq!(result.status, Status::Pass);
        assert!(result.teardown.is_failed(), "{:?}", result.teardown);
    }

    #[test]
    fn a_service_code_from_a_helper_gives_error_and_still_runs_teardown() {
        let mut harness = Harness::new();
        harness.profile.error_exit_codes = vec![64, 70];
        harness.driver = FakeDriver::failing_with("pam-drive", 70);
        let (result, commands) = harness.run(HAPPY);
        // Сломан хелпер, а не продукт: приговор продукту выносить не на чем.
        assert_eq!(result.status, Status::Error);
        assert!(
            result
                .reason
                .is_some_and(|r| r.contains("служебный код 70")),
            "причина должна называть код"
        );
        assert_eq!(result.teardown, TeardownOutcome::Ok);
        assert!(commands.contains(&"usb-loop detach".to_owned()));
    }

    #[test]
    fn a_real_pam_verdict_stays_a_product_failure() {
        let mut harness = Harness::new();
        harness.profile.error_exit_codes = vec![64, 70];
        harness.driver = FakeDriver::failing_with("pam-drive", 7);
        let (result, _) = harness.run(HAPPY);
        assert_eq!(result.status, Status::Fail);
    }

    #[test]
    fn a_case_that_expects_the_service_code_itself_passes() {
        let mut harness = Harness::new();
        harness.profile.error_exit_codes = vec![64];
        harness.driver = FakeDriver::failing_with("pam-drive", 64);
        let (result, _) = harness.run(
            r"
suite: helpers
cases:
  - id: HELP-001
    title: драйвер отвергает неизвестную фазу
    requirement: specs
    steps:
      - run: pam-drive неизвестная-фаза
        expect: { exit_code: 64 }
",
        );
        assert_eq!(result.status, Status::Pass);
    }

    #[test]
    fn a_case_requiring_an_absent_capability_is_skipped_with_a_reason() {
        let mut harness = Harness::new();
        let (result, commands) = harness.run(
            r"
suite: mac
cases:
  - id: MAC-001
    title: МКЦ на сессии
    requirement: specs
    requires: [mac]
    steps:
      - run: check-mac
",
        );
        assert_eq!(result.status, Status::Skip);
        assert_eq!(result.reason.as_deref(), Some("profile has no mac"));
        assert!(commands.is_empty());
    }

    const WITH_PAUSE: &str = r"
suite: desktop
cases:
  - id: DESK-001
    title: выбор роли на экране входа
    requirement: specs
    steps:
      - run: prepare
      - pause: выберите роль на экране
      - run: verify
";

    #[test]
    fn a_case_needing_an_operator_is_blocked_without_one() {
        let mut harness = Harness::new();
        harness.options.non_interactive = true;
        let (result, commands) = harness.run(WITH_PAUSE);
        assert_eq!(result.status, Status::Blocked);
        assert_eq!(result.mode, crate::registry::CaseMode::Mixed);
        assert!(result.reason.is_some_and(|r| r.contains("needs operator")));
        assert!(commands.is_empty());
    }

    #[test]
    fn an_operator_verdict_of_fail_fails_the_case_and_stops_the_scenario() {
        let mut harness = Harness::new();
        harness.operator.verdict = Verdict::Fail("экран пуст".to_owned());
        let (result, commands) = harness.run(WITH_PAUSE);
        assert_eq!(result.status, Status::Fail);
        assert!(result.reason.is_some_and(|r| r.contains("экран пуст")));
        assert_eq!(commands, vec!["prepare".to_owned()]);
    }

    #[test]
    fn a_captured_answer_becomes_a_variable_for_later_steps() {
        let mut harness = Harness::new();
        harness.operator.captured = Some("оператор-1".to_owned());
        let (result, commands) = harness.run(
            r"
suite: desktop
cases:
  - id: DESK-002
    title: оператор называет себя
    requirement: specs
    steps:
      - pause: представьтесь
        capture: who
      - run: echo {{who}}
",
        );
        assert_eq!(result.status, Status::Pass);
        assert_eq!(commands, vec!["echo оператор-1".to_owned()]);
    }

    const WITH_SETUP: &str = r"
suite: install
setup: [install-package]
cases:
  - id: INST-001
    title: раскладка пакета
    requirement: specs
    steps:
      - run: dpkg -l tessera
";

    #[test]
    fn suite_setup_runs_once_at_an_absolute_path_under_helpers() {
        let mut harness = Harness::new();
        let (result, commands) = harness.run(WITH_SETUP);
        assert_eq!(result.status, Status::Pass);
        // Путь абсолютный: рабочий каталог у docker и ssh разный, и опираться
        // на него нельзя.
        assert_eq!(
            commands,
            vec![
                "/opt/tessera-e2e/helpers/setup/install-package.sh".to_owned(),
                "dpkg -l tessera".to_owned()
            ]
        );
    }

    /// Юнит и идентификатор syslog — два разных отбора журнала. PAM-модуль
    /// службой не является, и его записи доступны только по `-t`.
    const JOURNAL_CASES: &str = r#"
suite: journal
cases:
  - id: J-1
    title: срез по юниту
    requirement: r
    steps:
      - expect_journal: { unit: tessera.service, matches: "auth ok" }
  - id: J-2
    title: срез по идентификатору syslog
    requirement: r
    steps:
      - expect_journal: { identifier: pam_tessera, matches: "auth ok" }
"#;

    #[test]
    fn a_journal_step_selects_a_unit_or_a_syslog_identifier() {
        let mut harness = Harness::new();
        let (results, commands) = harness.run_all(JOURNAL_CASES);
        let journal: Vec<String> = commands
            .into_iter()
            .filter(|command| command.starts_with("journalctl"))
            .collect();
        assert_eq!(
            journal,
            vec![
                "journalctl --no-pager -u tessera.service --since '-10m'".to_owned(),
                "journalctl --no-pager -t pam_tessera --since '-10m'".to_owned(),
            ]
        );
        // Заглушка драйвера отдаёт пустой журнал, поэтому оба шага падают;
        // важно, что причина называет именно тот отбор, который написан в кейсе.
        assert_eq!(results[1].status, Status::Fail);
        assert!(results[1].steps.iter().any(|step| step
            .detail
            .as_ref()
            .is_some_and(|d| d.contains("pam_tessera"))));
    }

    #[test]
    fn a_profile_without_the_helpers_variable_fails_loudly() {
        let mut harness = Harness::new();
        harness.helpers = None;
        let (result, commands) = harness.run(WITH_SETUP);
        assert_eq!(result.status, Status::Error);
        assert!(
            result.reason.is_some_and(|r| r.contains("helpers")),
            "причина должна называть недостающую переменную"
        );
        assert!(commands.is_empty());
    }

    #[test]
    fn a_broken_setup_is_a_stand_failure_not_a_product_failure() {
        let mut harness = Harness::new();
        harness.driver = FakeDriver::new(Some("setup/install-package"));
        let (result, _) = harness.run(WITH_SETUP);
        assert_eq!(result.status, Status::Error);
        assert!(result.reason.is_some_and(|r| r.contains("install-package")));
    }

    /// Suite из двух кейсов: один провал подготовки должен снять оба.
    const SUITE_OF_TWO: &str = r"
suite: install
setup: [install-package]
cases:
  - id: INST-001
    title: раскладка пакета
    requirement: specs
    steps:
      - run: dpkg -l tessera
  - id: INST-002
    title: каталоги на месте
    requirement: specs
    steps:
      - run: test -d /etc/tessera/ca
";

    #[test]
    fn a_failed_setup_errors_every_case_of_the_suite_and_runs_none_of_them() {
        let mut harness = Harness::new();
        // Второй запуск сломанного действия отвечает нулём, ничего не исправив:
        // ровно так `dpkg -i` ведёт себя на уже распакованном пакете. Повтори
        // раннер подготовку — кейсы пошли бы по полуустановленному окружению
        // и отчитались бы `PASS`, не проверив ничего.
        harness.driver = FakeDriver::failing_once("setup/install-package", 70);
        let (results, commands) = harness.run_all(SUITE_OF_TWO);

        assert!(
            results.iter().all(|case| case.status == Status::Error),
            "{:?}",
            results.iter().map(|c| c.status).collect::<Vec<_>>()
        );
        for case in &results {
            assert!(
                case.reason
                    .as_ref()
                    .is_some_and(|r| r.contains("подготовка suite не выполнена")),
                "{}: причина должна называть подготовку, а не продукт: {:?}",
                case.id,
                case.reason
            );
        }
        // Подготовка не повторялась, шаги кейсов не исполнялись вовсе.
        assert_eq!(
            commands,
            vec!["/opt/tessera-e2e/helpers/setup/install-package.sh".to_owned()]
        );
    }

    #[test]
    fn a_partially_completed_setup_still_errors_the_whole_suite() {
        let mut harness = Harness::new();
        harness.driver = FakeDriver::failing_once("setup/deploy-fixtures", 70);
        let (results, commands) = harness.run_all(
            r"
suite: install
setup: [install-package, deploy-fixtures]
cases:
  - id: INST-001
    title: раскладка пакета
    requirement: specs
    steps:
      - run: dpkg -l tessera
  - id: INST-002
    title: каталоги на месте
    requirement: specs
    steps:
      - run: test -d /etc/tessera/ca
",
        );

        // Первое действие прошло, второе упало: окружение готово наполовину,
        // и это ничем не лучше полностью неготового.
        assert!(
            results.iter().all(|case| case.status == Status::Error),
            "{:?}",
            results.iter().map(|c| c.status).collect::<Vec<_>>()
        );
        assert!(results.iter().all(|case| case
            .reason
            .as_ref()
            .is_some_and(|r| r.contains("подготовка suite не выполнена"))));
        // Удавшееся действие не повторяется, упавшее — тоже; кейсы не идут.
        assert_eq!(
            commands,
            vec![
                "/opt/tessera-e2e/helpers/setup/install-package.sh".to_owned(),
                "/opt/tessera-e2e/helpers/setup/deploy-fixtures.sh".to_owned(),
            ]
        );
    }

    #[test]
    fn a_healthy_setup_lets_every_case_of_the_suite_run() {
        let mut harness = Harness::new();
        let (results, commands) = harness.run_all(SUITE_OF_TWO);
        assert!(results.iter().all(|case| case.status == Status::Pass));
        // Подготовка одна на suite, дальше — шаги обоих кейсов.
        assert_eq!(
            commands,
            vec![
                "/opt/tessera-e2e/helpers/setup/install-package.sh".to_owned(),
                "dpkg -l tessera".to_owned(),
                "test -d /etc/tessera/ca".to_owned(),
            ]
        );
    }

    #[test]
    fn artifacts_are_delivered_once_before_the_first_setup_action() {
        let mut harness = Harness::new().with_delivery();
        let (result, commands) = harness.run(WITH_SETUP);
        assert_eq!(result.status, Status::Pass);
        // Доставка идёт первой, до подготовки и до сценария: и то и другое уже
        // рассчитывает на пакет и фикстуры в окружении.
        assert_eq!(
            commands,
            vec![
                format!(
                    "deliver {} -> /opt/tessera-e2e/pkg/tessera.deb",
                    delivery_source().display()
                ),
                "/opt/tessera-e2e/helpers/setup/install-package.sh".to_owned(),
                "dpkg -l tessera".to_owned(),
            ]
        );
    }

    #[test]
    fn a_delivery_with_a_mode_gets_it_set_right_after_the_transport() {
        let mut harness = Harness::new();
        harness.deliveries = vec![Delivery::new(
            "артефакт стенда /usr/local/bin/issuer",
            delivery_source(),
            "/usr/local/bin/issuer",
        )
        .with_mode("0755")];
        let (result, commands) = harness.run(WITH_SETUP);
        assert_eq!(result.status, Status::Pass);
        // Права выставляются до подготовки: бинарь без бита исполнения провалил
        // бы кейсы так, будто сломан продукт.
        assert_eq!(
            commands,
            vec![
                format!(
                    "deliver {} -> /usr/local/bin/issuer",
                    delivery_source().display()
                ),
                "chmod 0755 '/usr/local/bin/issuer'".to_owned(),
                "/opt/tessera-e2e/helpers/setup/install-package.sh".to_owned(),
                "dpkg -l tessera".to_owned(),
            ]
        );
    }

    #[test]
    fn a_failed_chmod_after_delivery_is_a_stand_failure() {
        let mut harness = Harness::new();
        harness.driver = FakeDriver::failing_with("chmod", 1);
        harness.deliveries = vec![Delivery::new(
            "артефакт стенда /usr/local/bin/issuer",
            delivery_source(),
            "/usr/local/bin/issuer",
        )
        .with_mode("0755")];
        let (result, commands) = harness.run(WITH_SETUP);
        assert_eq!(result.status, Status::Error);
        assert!(
            result
                .reason
                .is_some_and(|r| r.contains("артефакт стенда /usr/local/bin/issuer")),
            "причина должна называть груз"
        );
        assert!(!commands.iter().any(|c| c.contains("setup")));
    }

    #[test]
    fn a_failed_delivery_is_a_stand_failure() {
        let mut harness = Harness::new().with_delivery();
        harness.driver.delivery_fails = true;
        let (result, commands) = harness.run(WITH_SETUP);
        // Доставка — часть подготовки окружения: продукт тут ни при чём.
        assert_eq!(result.status, Status::Error);
        assert!(
            result
                .reason
                .is_some_and(|r| r.contains("доставка (пакет)")),
            "причина должна называть груз"
        );
        assert!(!commands.iter().any(|c| c.contains("setup")));
        assert!(!commands.contains(&"dpkg -l tessera".to_owned()));
    }

    #[test]
    fn a_missing_local_source_is_reported_before_any_transport() {
        let mut harness = Harness::new();
        harness.deliveries = vec![Delivery::new(
            "фикстуры",
            PathBuf::from("/нет/такого/каталога"),
            "/opt/tessera-e2e/fixtures",
        )];
        let (result, commands) = harness.run(WITH_SETUP);
        assert_eq!(result.status, Status::Error);
        assert!(
            result
                .reason
                .is_some_and(|r| r.contains("источник") && r.contains("не найден")),
            "причина должна называть отсутствующий источник"
        );
        assert!(
            commands.is_empty(),
            "транспорт трогать было незачем: {commands:?}"
        );
    }

    #[test]
    fn a_setup_script_path_is_absolute_and_tolerates_a_trailing_slash() {
        assert_eq!(
            setup_script_path("/opt/tessera-e2e/helpers", "install-package"),
            "/opt/tessera-e2e/helpers/setup/install-package.sh"
        );
        assert_eq!(
            setup_script_path("/opt/tessera-e2e/helpers/", "deploy-fixtures"),
            "/opt/tessera-e2e/helpers/setup/deploy-fixtures.sh"
        );
    }

    fn expect(exit_code: Option<i32>, stdout: Option<&str>, stderr: Option<&str>) -> Expect {
        Expect {
            exit_code,
            stdout_matches: stdout.map(str::to_owned),
            stderr_matches: stderr.map(str::to_owned),
        }
    }

    #[test]
    fn a_zero_exit_code_is_expected_by_default() {
        assert!(check_expectations(&expect(None, None, None), "", "", Some(0)).is_none());
        let detail = check_expectations(&expect(None, None, None), "", "", Some(1)).unwrap();
        assert!(detail.contains("ожидался код 0"), "{detail}");
    }

    #[test]
    fn a_nonzero_exit_code_can_be_the_expected_one() {
        assert!(check_expectations(&expect(Some(7), None, None), "", "", Some(7)).is_none());
    }

    #[test]
    fn stream_patterns_are_checked_against_their_own_stream() {
        let expectation = expect(Some(0), Some("PAM_SUCCESS"), Some("^$"));
        assert!(check_expectations(&expectation, "auth: PAM_SUCCESS", "", Some(0)).is_none());

        let detail = check_expectations(&expectation, "auth: PAM_AUTH_ERR", "", Some(0)).unwrap();
        assert!(detail.contains("stdout"), "{detail}");
    }

    #[test]
    fn an_anchored_expectation_matches_output_with_its_trailing_newline() {
        // `grep -c '^@include tessera$' …` печатает `1\n`; кейс ждёт `^1$`.
        let expectation = expect(Some(0), Some("^1$"), None);
        assert!(check_expectations(&expectation, "1\n", "", Some(0)).is_none());

        // Ожидание при этом не ослабло: другое число — по-прежнему провал.
        let detail = check_expectations(&expectation, "2\n", "", Some(0)).unwrap();
        assert!(detail.contains("stdout"), "{detail}");
    }

    #[test]
    fn stderr_expectations_get_the_same_treatment() {
        let expectation = expect(Some(0), None, Some("^предупреждение$"));
        assert!(check_expectations(&expectation, "", "предупреждение\n", Some(0)).is_none());
        let detail = check_expectations(&expectation, "", "ошибка\n", Some(0)).unwrap();
        assert!(detail.contains("stderr"), "{detail}");
    }

    #[test]
    fn a_signal_killed_command_is_a_mismatch() {
        let detail = check_expectations(&expect(None, None, None), "", "", None).unwrap();
        assert!(detail.contains("сигналом"), "{detail}");
    }

    #[test]
    fn file_modes_compare_without_the_leading_zero() {
        assert!(modes_equal("644", "0644"));
        assert!(modes_equal("0600", "600"));
        assert!(!modes_equal("640", "644"));
    }
}
