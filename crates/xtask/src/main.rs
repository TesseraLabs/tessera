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
mod codes_fixtures;
mod coverage;
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

use std::path::{Path, PathBuf};

use clap::Parser as _;

/// Корень репозитория, в котором собран раннер.
///
/// Реестр, спеки и профили лежат по путям от него, а не от текущего каталога:
/// раннер запускают через `cargo xtask` откуда угодно внутри дерева.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn main() -> std::process::ExitCode {
    let cli = cli::Cli::parse();
    let outcome = match &cli.command {
        cli::Command::E2e(args) => run::e2e(args),
        cli::Command::E2eCoverage(args) => coverage::e2e_coverage(args),
        cli::Command::CodesFixtures(args) => {
            // Путь по умолчанию задан от корня репозитория, а `cargo xtask`
            // запускают откуда угодно внутри дерева.
            let mut args = args.clone();
            if args.out.is_relative() {
                args.out = repo_root().join(&args.out);
            }
            codes_fixtures::check_target(&args.out)
                .and_then(|()| codes_fixtures::codes_fixtures(&args))
        }
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
