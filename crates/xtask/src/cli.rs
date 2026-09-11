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
    /// Пересборка фикстур канала входа по коду (сюита `27-codes-server`).
    CodesFixtures(CodesFixturesArgs),
    /// Подпись challenge ключом устройства — инструмент стенда для CODE-014.
    CodesSignChallenge(CodesSignChallengeArgs),
    /// Пересборка комплекта фикстур серверного стенда: сертификат организации
    /// с потолком, её список отзыва, запись реестра инженера, его авторизация и
    /// подписанный список отзыва прав.
    CodesStandFixtures(CodesStandFixturesArgs),
    /// Сборка подписанного запроса инженера вокруг снятого challenge —
    /// инструмент стенда: на объекте это делает страница инженера.
    CodesSignRequest(CodesSignRequestArgs),
}

/// Аргументы пересборки комплекта фикстур стенда.
#[derive(Debug, Clone, clap::Args)]
pub struct CodesStandFixturesArgs {
    /// Каталог, в который кладётся комплект.
    #[arg(long)]
    pub out: PathBuf,
    /// Запись устройства, которую комплект переподписывает своей организацией.
    ///
    /// По умолчанию берётся `device-record.txt` из каталога уровнем выше
    /// `--out`: стендовый комплект лежит подкаталогом устройственного.
    #[arg(long)]
    pub device_record: Option<PathBuf>,
}

/// Аргументы сборки подписанного запроса инженера.
#[derive(Debug, Clone, clap::Args)]
pub struct CodesSignRequestArgs {
    /// Проводная форма ПОДПИСАННОГО challenge — та, что показало устройство.
    #[arg(long, conflicts_with = "challenge_file")]
    pub challenge: Option<String>,

    /// Файл с проводной формой подписанного challenge.
    #[arg(long)]
    pub challenge_file: Option<PathBuf>,

    /// Основание выдачи. Пустое значение — законный ввод: документ с ним не
    /// собирается, и отказать обязана выдача, а не этот инструмент.
    #[arg(long, default_value = "")]
    pub grounds: String,

    /// Момент, который заявляет сторона инженера, в секундах Unix.
    #[arg(long)]
    pub requested_at: Option<u64>,

    /// Приватный ключ, которым подписывается запрос, в PKCS#8 PEM.
    ///
    /// Без него запрос собирается с ЯВНЫМ вариантом «никто не подписывал» и
    /// причиной ниже. Так честнее для стенда: аутентификатора инженера на нём
    /// нет, и подпись чужим ключом выглядела бы в записи выдачи как выдача
    /// подтверждённому человеку.
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Причина, по которой запрос не подписан. Действует только без `--key`.
    #[arg(long, default_value = "stand-has-no-engineer-authenticator")]
    pub unverified_reason: String,
}

/// Аргументы подписи challenge ключом устройства.
#[derive(Debug, Clone, clap::Args)]
pub struct CodesSignChallengeArgs {
    /// Проводная форма challenge БЕЗ подписи.
    #[arg(long, conflicts_with = "challenge_file")]
    pub challenge: Option<String>,

    /// Файл с проводной формой challenge БЕЗ подписи.
    #[arg(long)]
    pub challenge_file: Option<PathBuf>,

    /// Приватный ключ устройства в PKCS#8 PEM (`device-key.pem` комплекта).
    #[arg(long)]
    pub key: PathBuf,
}

/// Аргументы генератора фикстур канала входа по коду.
#[derive(Debug, Clone, clap::Args)]
pub struct CodesFixturesArgs {
    /// Каталог комплекта. Подменяется целиком.
    #[arg(long, default_value = "crates/tessera_core/tests/fixtures/codes")]
    pub out: PathBuf,

    /// Роль-учётная запись, которую допускает билет оператора (можно повторить).
    ///
    /// По умолчанию — учётные записи профилей стенда. Задавать нужно, только
    /// если прогон идёт под другой.
    #[arg(long = "role")]
    pub roles: Vec<String>,
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
