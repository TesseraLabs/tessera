//! Раннер e2e-реестра Tessera.
//!
//! Инструмент разработчика: проверяет гарантии установленной системы по
//! декларативному реестру кейсов в контейнере или на живой машине. В поставку
//! не входит и в `cargo test` продукта не участвует.
//!
//! ```text
//! cargo xtask e2e --profile ubuntu-container
//! cargo xtask e2e --profile astra-vm --cases-dir ../tests/e2e-private/cases
//! ```

mod artifacts;
mod baseline;
mod cli;
mod driver;
mod exec;
mod interact;
mod profile;
mod provenance;
mod redact;
mod registry;
mod report;
mod run;
mod stand;
mod vars;

use clap::Parser as _;

fn main() -> std::process::ExitCode {
    let cli = cli::Cli::parse();
    let outcome = match &cli.command {
        cli::Command::E2e(args) => run::e2e(args),
    };
    match outcome {
        Ok(code) => std::process::ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(err) => {
            // Цепочка причин важнее одной верхней строки: раннер падает от
            // внешнего мира, и разбираться придётся именно по ней.
            eprintln!("ошибка: {err:#}");
            std::process::ExitCode::from(1)
        }
    }
}
