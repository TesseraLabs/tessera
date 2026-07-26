//! Диалог с оператором на шаге `pause`.
//!
//! Раннер печатает инструкцию, ждёт вердикт и продолжает оставшиеся
//! автоматические шаги. Вердикт оператора — такой же результат проверки, как
//! код возврата команды, поэтому `fail` даёт кейсу `FAIL`, а не `ERROR`.

use std::io::{BufRead as _, Write as _};

/// Вердикт оператора.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Действие выполнено, ожидаемое поведение наблюдалось.
    Ok,
    /// Наблюдалось не то, что обещано.
    Fail(String),
    /// Проверить не удалось (нет железа, нет доступа).
    Skip(String),
}

/// Ошибка диалога.
#[derive(Debug, thiserror::Error)]
pub enum OperatorError {
    /// Ввод закончился, а вердикта не было.
    #[error("оператор не дал вердикт: поток ввода закрыт")]
    Eof,
    /// Ошибка ввода-вывода.
    #[error("не прочитать ответ оператора: {0}")]
    Io(#[from] std::io::Error),
}

/// Источник вердиктов.
pub trait Operator {
    /// Показывает инструкцию и возвращает вердикт вместе с захваченным
    /// значением, если кейс его просил.
    ///
    /// # Ошибки
    ///
    /// Закрытый поток ввода и ошибки ввода-вывода.
    fn pause(
        &mut self,
        text: &str,
        capture: Option<&str>,
    ) -> Result<(Verdict, Option<String>), OperatorError>;
}

/// Разбирает строку вердикта.
///
/// Понимает `ok`, `fail <причина>`, `skip <причина>`. Пустая причина
/// допускается: настаивать на формулировке в момент разбора железа —
/// верный способ получить формальную отписку.
#[must_use]
pub fn parse_verdict(line: &str) -> Option<Verdict> {
    let trimmed = line.trim();
    let (word, rest) = match trimmed.split_once(char::is_whitespace) {
        Some((word, rest)) => (word, rest.trim()),
        None => (trimmed, ""),
    };
    match word.to_ascii_lowercase().as_str() {
        "ok" | "y" | "yes" => Some(Verdict::Ok),
        "fail" | "n" | "no" => Some(Verdict::Fail(reason(rest, "оператор: поведение не то"))),
        "skip" | "s" => Some(Verdict::Skip(reason(
            rest,
            "оператор: проверить не удалось",
        ))),
        _ => None,
    }
}

fn reason(rest: &str, fallback: &str) -> String {
    if rest.is_empty() {
        fallback.to_owned()
    } else {
        rest.to_owned()
    }
}

/// Оператор за терминалом.
pub struct ConsoleOperator;

impl Operator for ConsoleOperator {
    fn pause(
        &mut self,
        text: &str,
        capture: Option<&str>,
    ) -> Result<(Verdict, Option<String>), OperatorError> {
        let mut stdout = std::io::stdout();
        writeln!(stdout, "\n--- требуется оператор ---\n{text}")?;
        writeln!(stdout, "ответьте: ok | fail <причина> | skip <причина>")?;
        stdout.flush()?;

        let stdin = std::io::stdin();
        let mut lines = stdin.lock().lines();
        let verdict = loop {
            let Some(line) = lines.next() else {
                return Err(OperatorError::Eof);
            };
            if let Some(verdict) = parse_verdict(&line?) {
                break verdict;
            }
            writeln!(
                stdout,
                "не понял; ожидается ok | fail <причина> | skip <причина>"
            )?;
            stdout.flush()?;
        };

        let captured = match (&verdict, capture) {
            (Verdict::Ok, Some(name)) => {
                writeln!(stdout, "введите значение для {{{{{name}}}}}:")?;
                stdout.flush()?;
                match lines.next() {
                    Some(line) => Some(line?.trim().to_owned()),
                    None => return Err(OperatorError::Eof),
                }
            }
            _ => None,
        };
        Ok((verdict, captured))
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

    #[test]
    fn recognises_the_three_verdicts() {
        assert_eq!(parse_verdict("ok"), Some(Verdict::Ok));
        assert_eq!(parse_verdict("  OK \n"), Some(Verdict::Ok));
        assert_eq!(
            parse_verdict("fail экран не показал выбор роли"),
            Some(Verdict::Fail("экран не показал выбор роли".to_owned()))
        );
        assert_eq!(
            parse_verdict("skip токена нет под рукой"),
            Some(Verdict::Skip("токена нет под рукой".to_owned()))
        );
    }

    #[test]
    fn a_verdict_without_a_reason_gets_a_default_one() {
        let Some(Verdict::Fail(reason)) = parse_verdict("fail") else {
            panic!("ожидался fail");
        };
        assert!(!reason.is_empty());
    }

    #[test]
    fn anything_else_is_not_a_verdict() {
        assert_eq!(parse_verdict(""), None);
        assert_eq!(parse_verdict("наверное"), None);
    }
}
