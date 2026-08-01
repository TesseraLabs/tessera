//! `tessera-engine`: the service host, its registration, and `prepare`.
//!
//! ```text
//! tessera-engine prepare   [--data-dir <путь>] [--account <имя>]
//! tessera-engine install | uninstall | start | stop
//! tessera-engine run       [--data-dir <путь>] [--account <имя>] [--pipe <имя>]
//! tessera-engine journal   [--data-dir <путь>]
//! tessera-engine service
//! ```
//!
//! `run` serves the pipe in the foreground, which is how the service is
//! exercised at a bench without registering anything. `service` is what the
//! service control manager invokes and is not meant to be typed.
//!
//! Every command needs administrative rights, and `run` needs to be
//! `LocalSystem` to be reachable through the pipe's descriptor at all — under
//! an ordinary elevated account the listener starts and no client can connect
//! to it, which is the descriptor doing its job.

#![allow(clippy::print_stderr, clippy::print_stdout)]

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(windows)]
    {
        imp::run()
    }
    #[cfg(not(windows))]
    {
        eprintln!("tessera-engine — служба Windows: на этой платформе выполнять нечего.");
        ExitCode::FAILURE
    }
}

#[cfg(windows)]
mod imp {
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use tessera_win_service::journal::{verify_lines, Journal, JournalStatus};
    use tessera_win_service::paths::{DataDir, DEFAULT_ACCOUNT_NAME, DEFAULT_PIPE_NAME};
    use tessera_win_service::windows::{prepare, run_listener, scm};

    /// Options every command shares.
    struct Options {
        data_dir: DataDir,
        account: String,
        pipe: String,
    }

    impl Default for Options {
        fn default() -> Self {
            Self {
                data_dir: DataDir::default_location(),
                account: DEFAULT_ACCOUNT_NAME.to_owned(),
                pipe: DEFAULT_PIPE_NAME.to_owned(),
            }
        }
    }

    pub fn run() -> ExitCode {
        let mut argv = std::env::args().skip(1);
        let Some(command) = argv.next() else {
            usage();
            return ExitCode::FAILURE;
        };
        let options = match parse_options(argv) {
            Ok(options) => options,
            Err(message) => {
                eprintln!("{message}");
                usage();
                return ExitCode::FAILURE;
            }
        };

        // The service's own logging goes to the console; a service started by
        // the control manager has none, and its record is the journal.
        // Best-effort: a second initialisation in one process is not a reason
        // to refuse a command.
        let _initialised = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .try_init();

        match command.as_str() {
            "prepare" => command_prepare(&options),
            "install" => command_install(),
            "uninstall" => command_uninstall(),
            "start" => command_start(),
            "stop" => command_stop(),
            "run" => command_run(options),
            "journal" => command_journal(&options),
            scm::SERVICE_ARGUMENT => command_service(),
            other => {
                eprintln!("неизвестная команда: {other}");
                usage();
                ExitCode::FAILURE
            }
        }
    }

    fn parse_options(argv: impl Iterator<Item = String>) -> Result<Options, String> {
        let mut options = Options::default();
        let mut argv = argv;
        while let Some(arg) = argv.next() {
            match arg.as_str() {
                "--data-dir" => {
                    options.data_dir = DataDir::new(PathBuf::from(value(&mut argv, &arg)?));
                }
                "--account" => options.account = value(&mut argv, &arg)?,
                "--pipe" => options.pipe = value(&mut argv, &arg)?,
                other => return Err(format!("неизвестный аргумент: {other}")),
            }
        }
        Ok(options)
    }

    fn value(argv: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
        argv.next()
            .ok_or_else(|| format!("{flag}: не указано значение"))
    }

    fn usage() {
        eprintln!(
            "Использование:\n  \
             tessera-engine prepare [--data-dir <путь>] [--account <имя>]\n  \
             tessera-engine install | uninstall | start | stop\n  \
             tessera-engine run [--data-dir <путь>] [--account <имя>] [--pipe <имя>]\n  \
             tessera-engine journal [--data-dir <путь>]"
        );
    }

    fn command_prepare(options: &Options) -> ExitCode {
        match prepare::run(&options.data_dir, &options.account) {
            Ok(report) => {
                println!("Каталог данных: {}", options.data_dir.root().display());
                println!(
                    "  создан:              {}",
                    if report.directory_created {
                        "да"
                    } else {
                        "нет"
                    }
                );
                println!("  права применены:     да (наследование отключено)");
                println!("Учётная запись: {}", options.account);
                println!(
                    "  состояние:           {}",
                    match report.account {
                        prepare::AccountOutcome::Created => "создана, пароль сохранён",
                        prepare::AccountOutcome::AlreadyPrepared =>
                            "уже подготовлена, пароль не тронут",
                        prepare::AccountOutcome::PasswordReset =>
                            "существовала без пароля — пароль задан заново",
                    }
                );
                println!(
                    "Проверить права: Get-Acl '{}' | Format-List",
                    options.data_dir.root().display()
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("prepare не выполнен: {error}");
                eprintln!(
                    "Команда требует прав администратора: создание локальной учётной записи \
                     и смена прав каталога иначе отклоняются."
                );
                ExitCode::FAILURE
            }
        }
    }

    fn command_install() -> ExitCode {
        let exe = match scm::current_exe() {
            Ok(path) => path,
            Err(error) => {
                eprintln!("не удалось определить путь к исполняемому файлу: {error}");
                return ExitCode::FAILURE;
            }
        };
        match scm::install(&exe) {
            Ok(()) => {
                println!("Служба зарегистрирована: {}", exe.display());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("регистрация не выполнена: {error}");
                ExitCode::FAILURE
            }
        }
    }

    fn command_uninstall() -> ExitCode {
        match scm::uninstall() {
            Ok(true) => {
                println!("Служба удалена.");
                ExitCode::SUCCESS
            }
            Ok(false) => {
                println!("Служба не зарегистрирована — удалять нечего.");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("удаление не выполнено: {error}");
                ExitCode::FAILURE
            }
        }
    }

    fn command_start() -> ExitCode {
        match scm::start() {
            Ok(true) => {
                println!("Служба запущена.");
                ExitCode::SUCCESS
            }
            Ok(false) => {
                eprintln!("Служба не зарегистрирована.");
                ExitCode::FAILURE
            }
            Err(error) => {
                eprintln!("запуск не выполнен: {error}");
                ExitCode::FAILURE
            }
        }
    }

    fn command_stop() -> ExitCode {
        match scm::stop() {
            Ok(true) => {
                println!("Остановка запрошена.");
                ExitCode::SUCCESS
            }
            Ok(false) => {
                eprintln!("Служба не зарегистрирована.");
                ExitCode::FAILURE
            }
            Err(error) => {
                eprintln!("остановка не выполнена: {error}");
                ExitCode::FAILURE
            }
        }
    }

    fn command_run(options: Options) -> ExitCode {
        println!("Слушаю {} (Ctrl+C — выход)", options.pipe);
        let stop = Arc::new(AtomicBool::new(false));
        match run_listener(
            options.data_dir,
            options.account,
            options.pipe,
            stop,
            || println!("Готов принимать соединения."),
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("служба остановлена с ошибкой: {error}");
                ExitCode::FAILURE
            }
        }
    }

    fn command_service() -> ExitCode {
        match scm::dispatch() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("эту команду вызывает диспетчер служб, а не человек: {error}");
                ExitCode::FAILURE
            }
        }
    }

    fn command_journal(options: &Options) -> ExitCode {
        let path = options.data_dir.journal();
        let journal = match Journal::open(&path) {
            Ok(journal) => journal,
            Err(error) => {
                eprintln!("журнал не прочитан: {error}");
                return ExitCode::FAILURE;
            }
        };
        let lines = match journal.lines() {
            Ok(lines) => lines,
            Err(error) => {
                eprintln!("журнал не прочитан: {error}");
                return ExitCode::FAILURE;
            }
        };
        match verify_lines(&lines) {
            JournalStatus::Intact { entries } => {
                println!("{}: цепочка цела, записей {entries}.", path.display());
                ExitCode::SUCCESS
            }
            JournalStatus::Broken { position } => {
                eprintln!("{}: цепочка нарушена на записи {position}.", path.display());
                ExitCode::FAILURE
            }
        }
    }
}
