//! Разбор аргументов командной строки.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Инструменты разработчика Tessera.
#[derive(Debug, Parser)]
#[command(name = "xtask", about = "Инструменты разработчика Tessera", version)]
pub struct Cli {
    /// Что делаем.
    #[command(subcommand)]
    pub command: Command,
}

/// Доступные команды.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Прогон реестра e2e-кейсов.
    E2e(E2eArgs),
    /// Пересборка матрицы покрытия спек кейсами реестра.
    E2eCoverage(CoverageArgs),
}

/// Аргументы сборки матрицы покрытия.
#[derive(Debug, Clone, clap::Args)]
pub struct CoverageArgs {
    /// Ничего не писать: сверить файл со сгенерированным и упасть при расхождении.
    #[arg(long)]
    pub check: bool,
}

/// Аргументы прогона.
#[derive(Debug, Clone, clap::Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "это набор флагов командной строки, а не состояние"
)]
pub struct E2eArgs {
    /// Профиль окружения: `ubuntu-container`, `astra-container`, `astra-vm`.
    #[arg(long)]
    pub profile: String,

    /// Каталог кейсов; можно указать несколько, приватная часть подключается так же.
    #[arg(long = "cases-dir")]
    pub cases_dir: Vec<PathBuf>,

    /// Прогнать только кейс с этим идентификатором или весь suite с этим именем.
    #[arg(long)]
    pub filter: Option<String>,

    /// Не исполнять кейсы, требующие оператора: они получат `BLOCKED`.
    #[arg(long)]
    pub non_interactive: bool,

    /// При провале не выполнять teardown, оставив окружение для разбора.
    #[arg(long)]
    pub keep_on_failure: bool,

    /// Пересоздать окружение перед прогоном.
    #[arg(long)]
    pub recreate: bool,

    /// Записать результаты прогона в `BASELINE.md`.
    #[arg(long)]
    pub update_baseline: bool,

    /// Нестандартный путь к параметрам стенда.
    #[arg(long)]
    pub stand: Option<PathBuf>,
}
