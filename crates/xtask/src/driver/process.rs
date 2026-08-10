//! Запуск системного процесса с таймаутом и реакцией на прерывание.
//!
//! Раннер не реализует ни SSH, ни docker-протокол: он оркеструет системные
//! `ssh` и `docker`. Вся общая механика — подача stdin, параллельное чтение
//! потоков, таймаут и убийство процесса — собрана здесь.

use std::io::{Read, Write as _};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Как часто опрашивается состояние процесса.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Результат запуска процесса.
#[derive(Debug, Clone)]
pub struct ProcessOutcome {
    /// Код возврата; `None`, если процесс убит сигналом.
    pub exit_code: Option<i32>,
    /// Стандартный вывод.
    pub stdout: String,
    /// Стандартный поток ошибок.
    pub stderr: String,
    /// Процесс убит по таймауту.
    pub timed_out: bool,
    /// Процесс убит из-за прерывания прогона.
    pub interrupted: bool,
}

/// Результат запуска процесса без предположений о кодировке потоков.
///
/// Нужен там, где по потокам едут не тексты: архив доставки проходит через
/// stdout и stdin процессов целиком, а приведение к `String` заменило бы
/// каждый неюникодный байт на заполнитель и испортило бы его молча.
#[derive(Debug, Clone)]
pub struct RawOutcome {
    /// Код возврата; `None`, если процесс убит сигналом.
    pub exit_code: Option<i32>,
    /// Стандартный вывод как есть.
    pub stdout: Vec<u8>,
    /// Стандартный поток ошибок как есть.
    pub stderr: Vec<u8>,
    /// Процесс убит по таймауту.
    pub timed_out: bool,
    /// Процесс убит из-за прерывания прогона.
    pub interrupted: bool,
}

impl RawOutcome {
    /// Читает потоки как текст, заменяя неюникодные байты заполнителем.
    #[must_use]
    pub fn into_text(self) -> ProcessOutcome {
        ProcessOutcome {
            exit_code: self.exit_code,
            stdout: String::from_utf8_lossy(&self.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&self.stderr).into_owned(),
            timed_out: self.timed_out,
            interrupted: self.interrupted,
        }
    }
}

/// Запускает процесс и ждёт его завершения не дольше таймаута.
///
/// # Ошибки
///
/// Ошибки запуска процесса и работы с его потоками. Ненулевой код возврата
/// ошибкой не считается: его интерпретирует кейс.
pub fn run(
    program: &str,
    args: &[String],
    stdin: Option<&str>,
    timeout: Duration,
    interrupt: &AtomicBool,
) -> std::io::Result<ProcessOutcome> {
    run_bytes(program, args, stdin.map(str::as_bytes), timeout, interrupt)
        .map(RawOutcome::into_text)
}

/// То же, но потоки остаются байтами.
///
/// # Ошибки
///
/// Ошибки запуска процесса и работы с его потоками.
pub fn run_bytes(
    program: &str,
    args: &[String],
    stdin: Option<&[u8]>,
    timeout: Duration,
    interrupt: &AtomicBool,
) -> std::io::Result<RawOutcome> {
    let started = Instant::now();
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(input) = child.stdin.take() {
        let payload = stdin.unwrap_or_default().to_vec();
        // Пишем в отдельном потоке: команда может не читать stdin вовсе,
        // и тогда синхронная запись заблокировала бы раннер до таймаута.
        std::thread::spawn(move || {
            let mut input = input;
            let _written = input.write_all(&payload);
            let _flushed = input.flush();
        });
    }

    let stdout_reader = child.stdout.take().map(spawn_reader);
    let stderr_reader = child.stderr.take().map(spawn_reader);

    let mut timed_out = false;
    let mut interrupted = false;
    let exit_code = loop {
        if let Some(status) = child.try_wait()? {
            break status.code();
        }
        if interrupt.load(Ordering::SeqCst) {
            interrupted = true;
        } else if started.elapsed() >= timeout {
            timed_out = true;
        } else {
            std::thread::sleep(POLL_INTERVAL);
            continue;
        }
        let _killed = child.kill();
        let _reaped = child.wait();
        break None;
    };

    Ok(RawOutcome {
        exit_code,
        stdout: join_reader(stdout_reader),
        stderr: join_reader(stderr_reader),
        timed_out,
        interrupted,
    })
}

fn spawn_reader<R>(mut source: R) -> std::thread::JoinHandle<Vec<u8>>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _read = source.read_to_end(&mut buffer);
        buffer
    })
}

fn join_reader(handle: Option<std::thread::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    // Поток чтения завершается вместе с процессом; паника внутри него не должна
    // валить прогон — потерянный кусок вывода менее ценен, чем отчёт целиком.
    handle
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default()
}

/// Заключает аргумент в одинарные кавычки для передачи удалённому шеллу.
///
/// `ssh` склеивает свои аргументы через пробел и отдаёт результат шеллу на той
/// стороне, поэтому команду кейса приходится цитировать самим.
#[must_use]
pub fn shell_quote(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('\'');
    for ch in text.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
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

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn quotes_plain_and_quote_bearing_text() {
        assert_eq!(shell_quote("systemctl status"), "'systemctl status'");
        assert_eq!(shell_quote("echo 'hi'"), r"'echo '\''hi'\'''");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn captures_streams_and_exit_code() {
        let interrupt = AtomicBool::new(false);
        let outcome = run(
            "sh",
            &args(&["-c", "printf out; printf err >&2; exit 3"]),
            None,
            Duration::from_secs(10),
            &interrupt,
        )
        .unwrap();
        assert_eq!(outcome.exit_code, Some(3));
        assert_eq!(outcome.stdout, "out");
        assert_eq!(outcome.stderr, "err");
        assert!(!outcome.timed_out);
    }

    #[test]
    fn feeds_stdin_to_the_process() {
        let interrupt = AtomicBool::new(false);
        let outcome = run(
            "cat",
            &[],
            Some("123456"),
            Duration::from_secs(10),
            &interrupt,
        )
        .unwrap();
        assert_eq!(outcome.stdout, "123456");
    }

    #[test]
    fn kills_the_process_on_timeout() {
        let interrupt = AtomicBool::new(false);
        let outcome = run(
            "sleep",
            &args(&["30"]),
            None,
            Duration::from_millis(200),
            &interrupt,
        )
        .unwrap();
        assert!(outcome.timed_out);
        assert!(!outcome.interrupted);
    }

    #[test]
    fn kills_the_process_when_the_run_is_interrupted() {
        let interrupt = AtomicBool::new(true);
        let outcome = run(
            "sleep",
            &args(&["30"]),
            None,
            Duration::from_secs(30),
            &interrupt,
        )
        .unwrap();
        assert!(outcome.interrupted);
    }
}
