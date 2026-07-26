//! Сбор диагностики для провалившихся кейсов.
//!
//! Артефактов должно хватать на разбор без повторного прогона: срез журнала за
//! время кейса, конфигурация, вывод `tessera check` и потоки шагов. Всё, что
//! пишется на диск, проходит через редактор секретов.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::driver::CommandDriver;
use crate::redact::Redactor;
use crate::report::{CaseResult, Status};

/// Сколько ждать сбор диагностики: он идёт после провала и не должен
/// подвешивать прогон.
const COLLECT_TIMEOUT: Duration = Duration::from_mins(1);

/// Сборщик диагностики.
///
/// Исполнитель зовёт его до teardown: после уборки `/etc/tessera` уже снесён,
/// а эмулированный носитель отвязан — собирать было бы нечего.
pub trait Collector {
    /// Собирает диагностику по кейсу; для успешных кейсов ничего не делает.
    fn collect(&self, case: &CaseResult, journal_since: Option<&str>);
}

/// Сборщик, складывающий диагностику в каталог прогона.
pub struct FileCollector<'a> {
    dir: PathBuf,
    driver: &'a dyn CommandDriver,
    redactor: &'a Redactor,
}

impl<'a> FileCollector<'a> {
    /// Создаёт сборщик поверх каталога `artifacts/` прогона.
    #[must_use]
    pub fn new(dir: PathBuf, driver: &'a dyn CommandDriver, redactor: &'a Redactor) -> Self {
        Self {
            dir,
            driver,
            redactor,
        }
    }
}

impl Collector for FileCollector<'_> {
    fn collect(&self, case: &CaseResult, journal_since: Option<&str>) {
        if matches!(case.status, Status::Fail | Status::Error) {
            write_bundle(&self.dir, self.driver, case, journal_since, self.redactor);
        }
    }
}

/// Складывает диагностику кейса в `artifacts/<CASE-ID>/`.
///
/// Ошибки самого сбора не поднимаются наверх: провал диагностики не должен
/// подменять собой причину провала кейса. Что не удалось собрать, видно по
/// отсутствию файла и по записанной диагностике.
fn write_bundle(
    dir: &Path,
    driver: &dyn CommandDriver,
    case: &CaseResult,
    journal_since: Option<&str>,
    redactor: &Redactor,
) {
    let case_dir = dir.join(&case.id);
    if std::fs::create_dir_all(&case_dir).is_err() {
        return;
    }

    write(&case_dir, "steps.txt", &steps_dump(case), redactor);

    let journal = match journal_since {
        Some(since) => format!("journalctl --no-pager --since {since}"),
        None => "journalctl --no-pager -n 500".to_owned(),
    };
    capture(&case_dir, "journal.log", driver, &journal, redactor);
    capture(
        &case_dir,
        "etc-tessera.txt",
        driver,
        "for f in /etc/tessera/*; do echo \"=== $f\"; cat \"$f\" 2>&1; done",
        redactor,
    );
    capture(
        &case_dir,
        "tessera-check.txt",
        driver,
        "tessera check 2>&1",
        redactor,
    );
}

fn capture(dir: &Path, name: &str, driver: &dyn CommandDriver, command: &str, redactor: &Redactor) {
    let text = match driver.exec(command, None, COLLECT_TIMEOUT) {
        Ok(outcome) => format!("$ {command}\n{}{}", outcome.stdout, outcome.stderr),
        Err(err) => format!("$ {command}\nне собрано: {err}"),
    };
    write(dir, name, &text, redactor);
}

fn write(dir: &Path, name: &str, text: &str, redactor: &Redactor) {
    if let Err(err) = std::fs::write(dir.join(name), redactor.apply(text)) {
        eprintln!("не записать артефакт {name}: {err}");
    }
}

#[expect(
    clippy::format_push_string,
    reason = "дамп собирается один раз на провалившийся кейс: читаемость важнее аллокации"
)]
fn steps_dump(case: &CaseResult) -> String {
    let mut out = format!("{} — {}\nстатус: {}\n", case.id, case.title, case.status);
    if let Some(reason) = &case.reason {
        out.push_str(&format!("причина: {reason}\n"));
    }
    for step in &case.steps {
        out.push_str(&format!(
            "\n--- шаг {} [{}] {} → {}\n",
            step.index, step.kind, step.description, step.status
        ));
        if let Some(code) = step.exit_code {
            out.push_str(&format!("код возврата: {code}\n"));
        }
        if let Some(detail) = &step.detail {
            out.push_str(&format!("расхождение: {detail}\n"));
        }
        if !step.stdout.is_empty() {
            out.push_str(&format!("stdout:\n{}\n", step.stdout));
        }
        if !step.stderr.is_empty() {
            out.push_str(&format!("stderr:\n{}\n", step.stderr));
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
    use crate::registry::CaseMode;
    use crate::report::{StepRecord, TeardownOutcome};

    #[test]
    fn step_dump_carries_streams_and_the_mismatch() {
        let case = CaseResult {
            id: "AUTH-001".to_owned(),
            suite: "auth".to_owned(),
            title: "гарантия".to_owned(),
            requirement: "specs".to_owned(),
            mode: CaseMode::Auto,
            status: Status::Fail,
            reason: Some("шаг 2".to_owned()),
            steps: vec![StepRecord {
                index: 2,
                kind: "run".to_owned(),
                description: "pam-drive certauth tester authenticate".to_owned(),
                status: Status::Fail,
                detail: Some("ожидался код 0, получен 7".to_owned()),
                exit_code: Some(7),
                stdout: "auth: PAM_AUTH_ERR".to_owned(),
                stderr: String::new(),
                duration_ms: 12,
            }],
            teardown: TeardownOutcome::Ok,
            registry_root: PathBuf::from("tests/e2e/cases"),
            duration_ms: 20,
        };
        let dump = steps_dump(&case);
        assert!(dump.contains("ожидался код 0, получен 7"));
        assert!(dump.contains("PAM_AUTH_ERR"));
        assert!(dump.contains("код возврата: 7"));
    }

    #[test]
    fn secrets_never_reach_the_artifact_file() {
        let dir = tempfile::tempdir().unwrap();
        let redactor = Redactor::new(vec!["123456".to_owned()]);
        write(dir.path(), "steps.txt", "PIN=123456", &redactor);
        let text = std::fs::read_to_string(dir.path().join("steps.txt")).unwrap();
        assert!(!text.contains("123456"), "{text}");
    }
}
