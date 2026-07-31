//! `tessera-engine-cli`: the bench client.
//!
//! It speaks the protocol the credential provider will speak, so both service
//! commands can be driven end to end before any COM code exists. A run of
//! `roles` followed by `auth` exercises everything the tile will: the
//! handshake, the role list the service reads on the client's behalf, the
//! search for media, the verification, and the verdict.
//!
//! ```text
//! tessera-engine-cli roles [--pipe <имя>]
//! tessera-engine-cli auth --role <роль> [--pin <PIN>] [--pipe <имя>]
//! tessera-engine-cli ping [--pipe <имя>]
//! ```
//!
//! With no `--pin` the PIN is read from standard input, so it does not end up
//! in the shell history. The tool must run as `LocalSystem` — the pipe admits
//! nothing else — which at a bench means `psexec -s` or the equivalent.

#![allow(clippy::print_stderr, clippy::print_stdout)]

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(windows)]
    {
        imp::run()
    }
    #[cfg(not(windows))]
    {
        eprintln!(
            "tessera-engine-cli говорит со службой Windows: на этой платформе делать нечего."
        );
        ExitCode::FAILURE
    }
}

#[cfg(windows)]
mod imp {
    use std::io::{BufReader, Write as _};
    use std::process::ExitCode;
    use std::time::Duration;

    use tessera_proto::AuthVerdict;
    use tessera_proto::Client;
    use tessera_win_service::paths::DEFAULT_PIPE_NAME;
    use tessera_win_service::windows::overlapped::PipeConnection;

    /// How long this tool waits for a reply.
    ///
    /// This is the client's half of the two clocks the service documents: the
    /// service bounds how long it waits for a *frame*, and a client has to bound
    /// how long it waits for a *reply*. The reply to an authentication request
    /// arrives only after the service has waited for removable media, so this
    /// has to exceed the configured `usb_wait` with room to spare — a client
    /// that gives up early turns a successful login into a failed one.
    const REPLY_BUDGET: Duration = Duration::from_mins(2);

    /// How long a request may take to reach the service.
    const SEND_BUDGET: Duration = Duration::from_secs(10);

    // The command dispatch is one flat match over three commands, each with
    // its own reporting; splitting it would spread one screen of output
    // formatting over four functions.
    #[allow(clippy::too_many_lines)]
    pub fn run() -> ExitCode {
        let mut argv = std::env::args().skip(1);
        let Some(command) = argv.next() else {
            usage();
            return ExitCode::FAILURE;
        };
        let mut pipe = DEFAULT_PIPE_NAME.to_owned();
        let mut role: Option<String> = None;
        let mut pin: Option<String> = None;
        while let Some(arg) = argv.next() {
            let value = argv.next();
            match (arg.as_str(), value) {
                ("--pipe", Some(v)) => pipe = v,
                ("--role", Some(v)) => role = Some(v),
                ("--pin", Some(v)) => pin = Some(v),
                (flag, None) => {
                    eprintln!("{flag}: не указано значение");
                    return ExitCode::FAILURE;
                }
                (other, _) => {
                    eprintln!("неизвестный аргумент: {other}");
                    return ExitCode::FAILURE;
                }
            }
        }

        let stream = match PipeConnection::connect(&pipe, REPLY_BUDGET, SEND_BUDGET) {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("не удалось открыть {pipe}: {error}");
                eprintln!("Канал доступен только контексту SYSTEM; служба должна быть запущена.");
                return ExitCode::FAILURE;
            }
        };
        let writer = match stream.try_clone() {
            Ok(writer) => writer,
            Err(error) => {
                eprintln!("не удалось продублировать дескриптор канала: {error}");
                return ExitCode::FAILURE;
            }
        };
        let mut client = match Client::connect(BufReader::new(stream), writer, "tessera-engine-cli")
        {
            Ok(client) => client,
            Err(error) => {
                eprintln!("рукопожатие не выполнено: {error}");
                return ExitCode::FAILURE;
            }
        };
        println!("Служба версии {}", client.server_version());

        match command.as_str() {
            "ping" => match client.ping() {
                Ok(()) => {
                    println!("Ответ получен.");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("ping не выполнен: {error}");
                    ExitCode::FAILURE
                }
            },
            "roles" => match client.list_roles() {
                Ok(roles) if roles.is_empty() => {
                    println!("Ролей нет.");
                    ExitCode::SUCCESS
                }
                Ok(roles) => {
                    for role in roles {
                        println!("{:<16} {:<3} {}", role.id, role.level, role.name);
                    }
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("перечень ролей не получен: {error}");
                    ExitCode::FAILURE
                }
            },
            "auth" => {
                let Some(role) = role else {
                    eprintln!("не указан --role");
                    return ExitCode::FAILURE;
                };
                let pin = match pin {
                    Some(pin) => pin,
                    None => match read_pin() {
                        Ok(pin) => pin,
                        Err(error) => {
                            eprintln!("PIN не прочитан: {error}");
                            return ExitCode::FAILURE;
                        }
                    },
                };
                match client.authenticate(&role, &pin) {
                    Ok(AuthVerdict::Admitted(admission)) => {
                        println!("Допуск.");
                        println!("  Учётная запись: {}", admission.account);
                        println!(
                            "  Роль:           {} (версия {})",
                            admission.role, admission.role_version
                        );
                        println!(
                            "  CN:             {}",
                            admission.cert_cn.as_deref().unwrap_or("—")
                        );
                        println!("  Сессия:         {}", admission.session_id);
                        // The password is deliberately not printed: this tool
                        // proves the verdict travels, and a bench transcript is
                        // not a place for the account's password.
                        println!("  Пароль:         получен, не выводится");
                        ExitCode::SUCCESS
                    }
                    Ok(AuthVerdict::Denied(denial)) => {
                        println!(
                            "Отказ: {:?} (код {}). Причина целиком — в журнале службы.",
                            denial.reason, denial.code
                        );
                        ExitCode::FAILURE
                    }
                    Err(error) => {
                        eprintln!("вердикт не получен: {error}");
                        ExitCode::FAILURE
                    }
                }
            }
            other => {
                eprintln!("неизвестная команда: {other}");
                usage();
                ExitCode::FAILURE
            }
        }
    }

    /// Reads a PIN from standard input.
    ///
    /// The echo is left alone: this tool runs at a bench under `psexec -s`,
    /// where the console is frequently not a console at all, and a failed
    /// attempt to switch echo off would be worse than a visible PIN on a test
    /// credential.
    fn read_pin() -> std::io::Result<String> {
        use std::io::BufRead as _;

        print!("PIN: ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let end = line.trim_end_matches(['\r', '\n']).len();
        line.truncate(end);
        Ok(line)
    }

    fn usage() {
        eprintln!(
            "Использование:\n  \
             tessera-engine-cli roles [--pipe <имя>]\n  \
             tessera-engine-cli auth --role <роль> [--pin <PIN>] [--pipe <имя>]\n  \
             tessera-engine-cli ping [--pipe <имя>]"
        );
    }
}
