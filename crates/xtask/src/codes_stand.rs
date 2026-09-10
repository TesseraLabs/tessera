//! Детерминированный комплект фикстур серверного стенда.
//!
//! Пять документов, которых стенду не хватало, чтобы пройти путь целиком:
//! сертификат организации с потолком делегирования, её список отзыва,
//! запись реестра инженера, его авторизация и подписанный список отзыва прав.
//!
//! # Почему отдельный комплект, а не тот, что собирает `codes-fixtures`
//!
//! Тот комплект тянет ключи из системного источника случайности — это записано
//! его же тестом «повторный прогон подменяет комплект целиком», — и заморозить
//! порождённое им нельзя ни в каком виде. Здесь зёрна фиксированы, и это
//! единственное, что делает проверку «перегенерация байт в байт» проверкой, а
//! не формальностью.
//!
//! # Почему подписи настоящие
//!
//! В крейте выпуска есть детерминированный `MockSigner`, и соблазн взять его
//! велик: он не требует ключей и всегда даёт одинаковые байты. Но фикстура,
//! подписанная не-подписью, годится ровно для стенда, который подписей не
//! проверяет, — то есть закрепляет ту самую дыру, которую стенд обязан ловить.
//! Здесь подписывает `FileSigner` на ECDSA P-256, а он детерминирован по
//! RFC 6979: те же байты выходят из каждого прогона.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};
use sha2::{Digest as _, Sha256};

use tessera_codes_contract::canon::Level;
use tessera_codes_contract::engineer::{
    AuthenticatorKey, AuthorisationFields, EngineerAuthorisation, EngineerRecord,
};
use tessera_codes_contract::revocation::{
    RevocationList, RevocationListFields, SignedRevocationList,
};
use tessera_codes_contract::signature::{PublicKey, Signature};
use tessera_codes_contract::ticket::{
    ServerTicket, SignedTicket, TicketNumber, TicketScope, TicketScopeInput,
};
use tessera_codes_contract::time::ClaimedTime;
use tessera_ext::delegation::DelegationConstraints;
use tessera_issuer::crl::{issue_crl, CrlRequest};
use tessera_issuer::journal::Journal;
use tessera_issuer::sign::{KeyId, SignatureAlgorithm};
use tessera_issuer::{issue_ca, issue_root, CaRequest, Serial, Validity};

use crate::cli::CodesStandFixturesArgs;
use crate::codes_fixtures::MemoryJournal;

/// Зерно ключа корня парка.
const ROOT_SEED: [u8; 32] = [0x11; 32];
/// Зерно ключа авторизаций парка (Р-1: он не корень и не организация).
const AUTHORISATION_SEED: [u8; 32] = [0x22; 32];
/// Зерно ключа организации-подрядчика.
const ORGANISATION_SEED: [u8; 32] = [0x33; 32];

/// Зерно ключа удостоверяющей стороны билетов.
const TICKET_AUTHORITY_SEED: [u8; 32] = [0x44; 32];
/// Зерно ключа согласования выдающей стороны — того, что несёт билет.
const AGREEMENT_SEED: [u8; 32] = [0x55; 32];
/// Зерно эфемерной пары попытки.
///
/// На живом устройстве эфемерная пара порождается заново на каждую попытку и
/// нигде не хранится. Здесь она зафиксирована ровно потому, что вектор обязан
/// быть воспроизводимым сторонним инструментом: без известной обеим сторонам
/// пары внешняя проверка ECDH невозможна в принципе.
const EPHEMERAL_SEED: [u8; 32] = [0x66; 32];

/// Идентификатор организации в документах канала.
const ORGANISATION_ID: &str = "acme";

/// Поля попытки, на которых посчитан вектор кода.
const VECTOR_DEVICE_BODY: &str = "77-000123";
/// Эпоха ключа устройства в векторе.
const VECTOR_EPOCH: u32 = 7;
/// Nonce попытки в векторе, в алфавите параметров парка.
const VECTOR_NONCE: &str = "K7Q2M9XR4T6B";
/// Ролевая учётная запись, в которую входит инженер.
const VECTOR_ROLE: &str = "serv";
/// Уровень целостности попытки.
const VECTOR_LEVEL: u32 = 1;
/// Идентификатор выдающей стороны в билете вектора.
const VECTOR_SERVER_ID: &str = "codes-core-1";
/// Номер билета вектора.
const VECTOR_TICKET_NUMBER: &str = "tk-vector-1";
/// Регион в рамках билета вектора.
const VECTOR_REGION: &str = "ru-central";
/// Метка в рамках билета вектора.
const VECTOR_TAG: &str = "dc-1";
/// Предел действия билета вектора.
const VECTOR_TICKET_NOT_AFTER: u64 = 1_924_905_600;

/// Тело личного номера инженера: сегмент организации и серийная часть.
/// Контрольный символ считает крейт контракта.
const ENGINEER_BODY: &str = "ORG1-000001";

/// Адрес страницы инженера, который «опубликовал» этот парк.
///
/// `https` и вымышленное имя: схему проверяет загрузка конфигурации, а
/// разрешимый хост в фикстуре — приглашение до него достучаться.
const PAGE_URL: &str = "https://codes.fleet.example/e";

/// Момент, с которого действительны сертификаты комплекта.
const NOT_BEFORE: u64 = 1_577_836_800;
/// Момент, до которого они действительны.
const NOT_AFTER: u64 = 1_924_905_600;
/// Потолок TTL сессии в рамках делегирования.
const MAX_TTL_SECS: u64 = 3_600;
/// Версия профиля расширений.
const PROFILE_VERSION: u32 = 1;

/// Потолок организации: роли, уровень, метки. Авторизация инженера обязана
/// лежать внутри него, и комплект это показывает своим составом.
const CEILING_ROLES: [&str; 2] = ["tester", "serv"];
/// Уровень потолка организации.
const CEILING_LEVEL: i8 = 1;
/// Метка, которую обязаны нести устройства под этой организацией.
const CEILING_TAG: (&str, &str) = ("site", "dc-1");

/// Имена файлов комплекта.
mod names {
    /// Самоподписанный сертификат корня парка.
    pub const ROOT_CERT: &str = "fleet-root.crt.pem";
    /// Сертификат организации с потолком делегирования.
    pub const ORGANISATION_CERT: &str = "organisation.crt.pem";
    /// Пустой, но подписанный список отзыва сертификатов.
    pub const ORGANISATION_CRL: &str = "organisation.crl.pem";
    /// Открытая половина ключа авторизаций — якорь для проверки авторизаций и
    /// списка отзыва прав.
    pub const AUTHORISATION_ANCHOR: &str = "authorisation-key.pub.pem";
    /// Запись реестра инженера.
    pub const ENGINEER_RECORD: &str = "engineer-record.txt";
    /// Авторизация инженера.
    pub const ENGINEER_AUTHORISATION: &str = "engineer-authorisation.txt";
    /// Подписанный список отзыва прав, пустой.
    pub const RIGHTS_REVOCATIONS: &str = "rights-revocations.txt";
    /// Приватная половина ключа согласования выдающей стороны, PKCS#8 PEM.
    pub const AGREEMENT_KEY: &str = "agreement-key.pem";
    /// Открытая половина эфемерной пары попытки, SPKI PEM.
    pub const EPHEMERAL_PUBLIC: &str = "attempt-ephemeral.pub.pem";
    /// Билет выдающей стороны, на котором посчитан вектор кода.
    pub const VECTOR_TICKET: &str = "code-vector-ticket.txt";
    /// Входы вектора кода: поля попытки и всё, что нужно стороннему инструменту.
    pub const VECTOR_INPUTS: &str = "code-vector-inputs.txt";
    /// Цепочка выдающей стороны БЕЗ единой выдачи: отказ и авторизация.
    pub const CHAIN_WITHOUT_ISSUANCES: &str = "server-chain-no-issuances.ndjson";
    /// Адреса страницы инженера, опубликованные парком.
    ///
    /// Имя обязано совпадать с `codes::store::PAGE_URLS_FILENAME` продукта:
    /// комплект кладёт файл туда, откуда его берёт проверка конфигурации.
    pub const PAGE_URLS: &str = "page-urls.txt";
    /// Опись комплекта.
    pub const README: &str = "README.md";
}

/// Собирает комплект и кладёт его в каталог.
///
/// # Errors
///
/// Не собирается документ, не подписывается сертификат, не пишется файл.
pub fn codes_stand_fixtures(args: &CodesStandFixturesArgs) -> Result<i32> {
    let bundle = build()?;
    publish(&args.out, &bundle)?;
    println!("комплект стенда: {}", args.out.display());
    Ok(0)
}

/// Ключ комплекта: детерминированная пара и подписи ею.
struct StandKey {
    secret: p256::SecretKey,
}

impl StandKey {
    /// Ключ из фиксированного зерна.
    fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            secret: p256::SecretKey::from_slice(seed).context("зерно ключа комплекта")?,
        })
    }

    /// PKCS#8 PEM приватной половины.
    ///
    /// Нужен стороннему инструменту: `openssl pkeyutl -derive` читает ключ из
    /// PEM, и вектор кода проверяется тем, что ECDH делает не этот крейт.
    fn pkcs8_pem(&self) -> Result<String> {
        Ok(self
            .secret
            .to_pkcs8_pem(LineEnding::LF)
            .context("PKCS#8 PEM ключа комплекта")?
            .to_string())
    }

    /// PKCS#8 DER приватной половины.
    fn pkcs8_der(&self) -> Result<Vec<u8>> {
        Ok(self
            .secret
            .to_pkcs8_der()
            .context("PKCS#8 ключа комплекта")?
            .as_bytes()
            .to_vec())
    }

    /// `SubjectPublicKeyInfo` в DER.
    fn spki_der(&self) -> Result<Vec<u8>> {
        Ok(self
            .secret
            .public_key()
            .to_public_key_der()
            .context("SPKI ключа комплекта")?
            .as_bytes()
            .to_vec())
    }

    /// `SubjectPublicKeyInfo` в PEM — форма якоря.
    fn spki_pem(&self) -> Result<String> {
        self.secret
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .context("SPKI PEM ключа комплекта")
    }

    /// Открытая половина в SEC1, как её несут документы канала.
    fn sec1_point(&self) -> Vec<u8> {
        self.secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Подпись документа канала: ECDSA над SHA-256, DER. Детерминирована по
    /// RFC 6979 — тем же прогоном выходят те же байты.
    fn sign(&self, message: &[u8]) -> Result<Signature> {
        let key = p256::ecdsa::SigningKey::from(&self.secret);
        let digest = Sha256::digest(message);
        let signature: p256::ecdsa::Signature =
            key.sign_prehash(&digest).context("подпись документа")?;
        Signature::new(signature.to_der().as_bytes().to_vec())
            .map_err(|error| anyhow::anyhow!("подпись пуста: {error}"))
    }
}

/// Собранный комплект: имя файла и его содержимое.
struct Bundle {
    files: Vec<(&'static str, Vec<u8>)>,
}

/// Собирает все документы комплекта.
fn build() -> Result<Bundle> {
    let root = StandKey::from_seed(&ROOT_SEED)?;
    let authorisation = StandKey::from_seed(&AUTHORISATION_SEED)?;
    let organisation = StandKey::from_seed(&ORGANISATION_SEED)?;

    let Certificates {
        root: root_cert,
        organisation: organisation_cert,
        crl,
    } = certificates(&root, &organisation)?;
    let engineer_id = engineer_number()?;
    let record = engineer_record(&organisation, &engineer_id)?;
    let authorisation_doc = engineer_authorisation(&authorisation, &engineer_id)?;
    let rights = rights_revocations(&authorisation)?;

    let ticket_authority = StandKey::from_seed(&TICKET_AUTHORITY_SEED)?;
    let agreement = StandKey::from_seed(&AGREEMENT_SEED)?;
    let ephemeral = StandKey::from_seed(&EPHEMERAL_SEED)?;
    let ticket = vector_ticket(&ticket_authority, &agreement)?;
    let inputs = vector_inputs(&ticket, &ephemeral, &engineer_id)?;

    Ok(Bundle {
        files: vec![
            (
                names::AGREEMENT_KEY,
                test_key_pem(&agreement.pkcs8_pem()?).into_bytes(),
            ),
            (
                names::EPHEMERAL_PUBLIC,
                fixture_pem(
                    "Открытая половина эфемерной пары попытки",
                    ephemeral.spki_pem()?.as_bytes(),
                )
                .into_bytes(),
            ),
            (names::VECTOR_TICKET, line(&ticket.to_wire())),
            (names::VECTOR_INPUTS, inputs.into_bytes()),
            (
                names::CHAIN_WITHOUT_ISSUANCES,
                chain_without_issuances()?.into_bytes(),
            ),
            (names::PAGE_URLS, page_urls().into_bytes()),
            (
                names::ROOT_CERT,
                fixture_pem("Корень выдуманного парка", &pem("CERTIFICATE", &root_cert))
                    .into_bytes(),
            ),
            (
                names::ORGANISATION_CERT,
                fixture_pem(
                    "Сертификат выдуманной организации",
                    &pem("CERTIFICATE", &organisation_cert),
                )
                .into_bytes(),
            ),
            (
                names::ORGANISATION_CRL,
                fixture_pem(
                    "Список отзыва выдуманной организации",
                    &pem("X509 CRL", &crl),
                )
                .into_bytes(),
            ),
            (
                names::AUTHORISATION_ANCHOR,
                fixture_pem(
                    "Якорь ключа авторизаций выдающей стороны",
                    authorisation.spki_pem()?.as_bytes(),
                )
                .into_bytes(),
            ),
            (names::ENGINEER_RECORD, line(&record.to_wire())),
            (
                names::ENGINEER_AUTHORISATION,
                line(&authorisation_doc.to_wire()),
            ),
            (names::RIGHTS_REVOCATIONS, line(&rights.to_wire())),
            (names::README, readme(&engineer_id).into_bytes()),
        ],
    })
}

/// Билет выдающей стороны, на котором посчитан вектор кода.
///
/// Билет входит в вектор не как антураж: его канонические байты хешируются в
/// контекст вывода ключа, поэтому изменить в нём хоть один байт значит получить
/// другой код. Открытая половина в билете — та самая, которой считается ECDH.
fn vector_ticket(authority: &StandKey, agreement: &StandKey) -> Result<SignedTicket> {
    let scope = TicketScope::new(TicketScopeInput {
        tags: vec![VECTOR_TAG.to_owned()],
        roles: vec![VECTOR_ROLE.to_owned()],
        region: VECTOR_REGION.to_owned(),
        max_level: Level::new(VECTOR_LEVEL),
    })
    .context("рамки билета вектора")?;

    let ticket = ServerTicket::new(
        VECTOR_SERVER_ID,
        PublicKey::new(agreement.sec1_point()).context("открытая половина ключа согласования")?,
        scope,
        ClaimedTime::new(VECTOR_TICKET_NOT_AFTER),
        TicketNumber::parse(VECTOR_TICKET_NUMBER).context("номер билета вектора")?,
    )
    .context("сборка билета вектора")?;

    let signature = authority.sign(&ticket.encode().context("канонические байты билета")?)?;
    Ok(SignedTicket::new(ticket, signature))
}

/// Входы вектора кода, по одному `ключ=значение` на строку.
///
/// Здесь НЕТ ожидаемого кода, и это не упущение. Комплект собирает тот же
/// крейт, который код и считает; впиши он сюда ответ, вектор перестал бы быть
/// внешним и сверял бы реализацию саму с собой. Ответ считает сторонний
/// инструмент — `tools/codes-golden-code.py`, — и он лежит рядом отдельным
/// файлом, который этот генератор не пишет и переписать не может.
fn vector_inputs(ticket: &SignedTicket, ephemeral: &StandKey, engineer_id: &str) -> Result<String> {
    let device =
        tessera_codes_contract::device_number::CheckedDeviceNumber::from_body(VECTOR_DEVICE_BODY)
            .map_err(|error| anyhow::anyhow!("номер устройства вектора: {error}"))?;
    let ticket_hash = ticket
        .context_hash()
        .context("хеш билета в контексте вывода ключа")?;
    let params = tessera_codes_contract::params::FleetParams::parse(
        tessera_codes_contract::params::FleetParamsInput::defaults(),
    )
    .map_err(|error| anyhow::anyhow!("параметры парка по умолчанию: {error}"))?;

    Ok(format!(
        "# Входы вектора кода. Ожидаемый код лежит отдельно и считается не этим крейтом.\n\
         device_number_significant={device_significant}\n\
         epoch={epoch}\n\
         nonce={nonce}\n\
         role_id={role}\n\
         level={level}\n\
         engineer_id={engineer}\n\
         ticket_hash_sha256={ticket_hash}\n\
         ephemeral_public_sec1={ephemeral_point}\n\
         code_len={code_len}\n\
         alphabet={alphabet}\n\
         kdf_salt={salt}\n",
        device_significant = device.significant(),
        epoch = VECTOR_EPOCH,
        nonce = VECTOR_NONCE,
        role = VECTOR_ROLE,
        level = VECTOR_LEVEL,
        engineer = engineer_id,
        ticket_hash = hex(ticket_hash.as_bytes()),
        ephemeral_point = hex(&ephemeral.sec1_point()),
        code_len = params.code_len(),
        alphabet = match params.alphabet() {
            tessera_codes_contract::code::Alphabet::Decimal => "decimal",
            tessera_codes_contract::code::Alphabet::CrockfordBase32 => "crockford-base32",
        },
        salt = "tessera-codes-contract/v1/kdf",
    ))
}

/// Цепочка выдающей стороны, в которой есть строки и нет ни одной выдачи.
///
/// Так выглядит журнал свежего узла codes-core, который пока только отказывал и
/// подписывал авторизации. Сверка обязана прочитать его как выдающую сторону с
/// нулём грантов, а не как подменённый журнал: «журнал подменили» требует
/// разбирательства, «выдач ещё не было» не требует ничего, и обвинить сторону,
/// работавшую правильно, дороже, чем кажется.
///
/// Строки пишет ТОТ ЖЕ крейт цепочки, что и продуктив. Собрать их руками
/// значило бы завести второго писателя формата — ровно то, из-за чего вторая
/// реализация однажды разойдётся с первой молча.
fn chain_without_issuances() -> Result<String> {
    use tessera_hashchain::storage::MemoryStorage;
    use tessera_hashchain::Chain;
    use tessera_issuer::codes::reconcile::{ServerLine, AUTHORISATION_OP, REFUSAL_OP};

    let mut chain: Chain<MemoryStorage, ServerLine> =
        Chain::load(MemoryStorage::new()).context("цепочка без выдач")?;
    for (op, note) in [
        (REFUSAL_OP, "the request was outside the ticket"),
        (AUTHORISATION_OP, "an authorisation was signed"),
    ] {
        let line: ServerLine = serde_json::from_value(serde_json::json!({
            "op": op,
            "note": note,
        }))
        .context("строка цепочки без выдач")?;
        // Момент фиксирован вместе с зёрнами: комплект обязан пересобираться
        // байт в байт.
        chain
            .append(&line, NOT_BEFORE)
            .context("запись строки цепочки без выдач")?;
    }
    Ok(format!("{}\n", chain.storage().lines().join("\n")))
}

/// Приватный ключ фикстуры с шапкой, объясняющей, что это за ключ.
///
/// Ключ приватный и лежит в публичном репозитории — это осознанно и безопасно
/// ровно по одной причине: он выведен из константного зерна, записанного в
/// исходниках этого же файла, поэтому секретом он не был никогда. Шапка нужна
/// человеку и сканеру секретов, которые увидят `PRIVATE KEY` и обязаны за
/// секунду понять, тревога это или нет. Всё до строки `-----BEGIN` разборщики
/// PEM пропускают, так что на чтение ключа она не влияет.
fn test_key_pem(pem: &str) -> String {
    fixture_pem(
        "Ключ согласования вектора кода серверного стенда",
        pem.as_bytes(),
    )
}

/// Любой PEM комплекта с той же шапкой.
///
/// Шапка стоит на ВСЕХ файлах комплекта, а не только на приватном ключе.
/// Сертификат и список отзыва секретом не являются, но выглядят как боевые:
/// человек, наткнувшийся на `fleet-root.crt.pem` в публичном репозитории,
/// обязан за секунду понять, что это выдумка генератора, а не корень чьего-то
/// парка. Всё до строки `-----BEGIN` разборщики PEM пропускают.
fn fixture_pem(what: &str, pem: &[u8]) -> String {
    format!(
        "# ФИКСТУРА, НЕ СЕКРЕТ. {what}.\n\
         # Выведен из константных зёрен в crates/xtask/src/codes_stand.rs и\n\
         # воспроизводится командой `cargo xtask codes-stand-fixtures`. Никакой\n\
         # парк на этом материале не работает и работать не может: зёрна\n\
         # опубликованы вместе с кодом.\n\
         {}",
        String::from_utf8_lossy(pem)
    )
}

/// Список адресов страницы инженера, как его доставляет комплект зачисления.
fn page_urls() -> String {
    format!(
        "# Адреса страницы инженера, опубликованные этим парком.\n\
         # Устройство показывает ОДИН из них перед challenge и своего не составляет:\n\
         # адрес вне этого списка отвергается при загрузке конфигурации.\n\
         {PAGE_URL}\n"
    )
}

/// Байты строчными шестнадцатеричными знаками.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ignored = write!(text, "{byte:02x}");
        text
    })
}

/// Лестница сертификатов комплекта, в DER.
///
/// Именованные поля вместо тройки: три `Vec<u8>` подряд читаются только по
/// порядку, а перепутать сертификат корня с сертификатом организации — ошибка,
/// которую компилятор на кортеже не поймает.
struct Certificates {
    /// Самоподписанный корень парка.
    root: Vec<u8>,
    /// Сертификат организации под ним.
    organisation: Vec<u8>,
    /// Пустой, но подписанный список отзыва организации.
    crl: Vec<u8>,
}

/// Корень парка, сертификат организации под ним и её пустой список отзыва.
fn certificates(root: &StandKey, organisation: &StandKey) -> Result<Certificates> {
    let root_key_id = KeyId::new("stand-root");
    let (_key_dir, signer) = file_signer(root)?;
    let mut journal = Journal::load(MemoryJournal::default()).context("журнал выпуска")?;

    let root_request = CaRequest {
        subject: "CN=tessera stand fleet root".to_owned(),
        subject_spki_der: root.spki_der()?,
        validity: Validity {
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
        },
        // Потолок корня шире потолка организации ровно настолько, чтобы тот в
        // него вкладывался: комплект показывает лестницу, а не два независимых
        // документа.
        constraints: DelegationConstraints {
            require_tags: Vec::new(),
            allow_roles: CEILING_ROLES
                .iter()
                .map(|role| (*role).to_owned())
                .collect(),
            max_level: CEILING_LEVEL,
            max_ttl: MAX_TTL_SECS,
        },
        profile_version: PROFILE_VERSION,
    };
    let root_cert = issue_root(
        &signer,
        &root_key_id,
        &root_request,
        &Serial::from_entropy(&[0x01; 16]),
        &mut journal,
        NOT_BEFORE,
    )
    .context("самоподписанный сертификат корня парка")?;

    let organisation_request = CaRequest {
        subject: format!("CN=tessera stand organisation {ORGANISATION_ID}"),
        subject_spki_der: organisation.spki_der()?,
        validity: Validity {
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
        },
        constraints: DelegationConstraints {
            require_tags: vec![(CEILING_TAG.0.to_owned(), CEILING_TAG.1.to_owned())],
            allow_roles: CEILING_ROLES
                .iter()
                .map(|role| (*role).to_owned())
                .collect(),
            max_level: CEILING_LEVEL,
            max_ttl: MAX_TTL_SECS,
        },
        profile_version: PROFILE_VERSION,
    };
    let organisation_cert = issue_ca(
        &signer,
        &root_key_id,
        &root_cert.der,
        &organisation_request,
        &Serial::from_entropy(&[0x02; 16]),
        &mut journal,
        NOT_BEFORE,
    )
    .context("сертификат организации под корнем парка")?;

    // Пустой список отзыва — документ, а не отсутствие документа: парк,
    // который никого не отозвал, говорит об этом подписью.
    let crl = issue_crl(
        &signer,
        &root_key_id,
        &root_cert.der,
        &CrlRequest {
            this_update: NOT_BEFORE,
            next_update: Some(NOT_AFTER),
            crl_number: 1,
            revoked: Vec::new(),
        },
        0,
        &mut journal,
        NOT_BEFORE,
    )
    .context("список отзыва сертификатов")?;

    Ok(Certificates {
        root: root_cert.der,
        organisation: organisation_cert.der,
        crl: crl.der,
    })
}

/// Личный номер инженера по правилу: тело и контрольный символ от крейта.
fn engineer_number() -> Result<String> {
    let check = tessera_codes_contract::device_number::check_character(ENGINEER_BODY)
        .map_err(|error| anyhow::anyhow!("контрольный символ личного номера: {error}"))?;
    Ok(format!("{ENGINEER_BODY}{check}"))
}

/// Запись реестра инженера, подписанная организацией.
///
/// Ключ аутентификатора — в варианте «не подтверждено»: настоящего провайдера в
/// MVP нет, и запись говорит об этом сама, вместо того чтобы нести заглушку,
/// которую следующий читатель примет за ключ.
fn engineer_record(organisation: &StandKey, engineer_id: &str) -> Result<EngineerRecord> {
    let unverified = AuthenticatorKey::absent("stub-provider")
        .map_err(|error| anyhow::anyhow!("вариант «не подтверждено»: {error}"))?;
    // Собирается дважды: первый раз ради байтов, которые подписывает
    // организация, второй — с подписью. Подписать нечего, пока документа нет.
    let draft = EngineerRecord::new(
        engineer_id,
        unverified.clone(),
        ORGANISATION_ID,
        Signature::new(vec![0x00]).map_err(|error| anyhow::anyhow!("черновая подпись: {error}"))?,
    )
    .map_err(|error| anyhow::anyhow!("черновая запись реестра: {error}"))?;
    let message = draft
        .organisation_message()
        .map_err(|error| anyhow::anyhow!("байты записи реестра: {error}"))?;

    EngineerRecord::new(
        engineer_id,
        unverified,
        ORGANISATION_ID,
        organisation.sign(&message)?,
    )
    .map_err(|error| anyhow::anyhow!("запись реестра инженера: {error}"))
}

/// Авторизация инженера, подписанная КЛЮЧОМ АВТОРИЗАЦИЙ парка.
///
/// Рамки вложены в потолок организации: одна её роль из двух, тот же уровень,
/// та же метка. Авторизация шире потолка была бы документом, который парк не
/// выпустил бы, и стенд, принимающий её, ничего не проверял бы.
fn engineer_authorisation(
    authorisation: &StandKey,
    engineer_id: &str,
) -> Result<EngineerAuthorisation> {
    let fields = |signature: Signature| AuthorisationFields {
        engineer_id,
        organisation_id: ORGANISATION_ID,
        // Отпечатка ключа у инженера нет: ключа нет. Нули здесь — не отпечаток
        // и не притворяются им; сама авторизация в MVP привязана к личному
        // номеру, и это записано в ADR-CODES-003 как невыполненное требование.
        key_fingerprint: [0x00; 32],
        tags: vec![CEILING_TAG.1.to_owned()],
        roles: vec![CEILING_ROLES[0].to_owned()],
        max_level: Level::new(u32::try_from(CEILING_LEVEL).unwrap_or(0)),
        not_after: ClaimedTime::new(NOT_AFTER),
        authorisation_signature: signature,
    };

    let draft = EngineerAuthorisation::new(fields(
        Signature::new(vec![0x00]).map_err(|error| anyhow::anyhow!("черновая подпись: {error}"))?,
    ))
    .map_err(|error| anyhow::anyhow!("черновая авторизация: {error}"))?;
    let message = draft
        .encode()
        .map_err(|error| anyhow::anyhow!("байты авторизации: {error}"))?;

    EngineerAuthorisation::new(fields(authorisation.sign(&message)?))
        .map_err(|error| anyhow::anyhow!("авторизация инженера: {error}"))
}

/// Пустой список отзыва прав, подписанный ключом авторизаций.
fn rights_revocations(authorisation: &StandKey) -> Result<SignedRevocationList> {
    let list = RevocationList::new(RevocationListFields {
        serial: 1,
        issued_at: ClaimedTime::new(NOT_BEFORE),
        entries: Vec::new(),
    })
    .map_err(|error| anyhow::anyhow!("список отзыва прав: {error}"))?;
    let message = list
        .encode()
        .map_err(|error| anyhow::anyhow!("байты списка отзыва: {error}"))?;
    Ok(SignedRevocationList::new(
        list,
        authorisation.sign(&message)?,
    ))
}

/// Источник пароля для ключа, у которого пароля нет.
///
/// Ключ комплекта лежит незашифрованным: это фиксированное зерно в
/// репозитории, и пароль над ним ничего не защищал бы, а делал бы вид.
fn no_passphrase() -> Result<secrecy::SecretString, tessera_issuer::file::FileSignError> {
    Err(tessera_issuer::file::FileSignError::PassphraseUnavailable(
        "the stand key carries no passphrase".to_owned(),
    ))
}

/// Подписывающий сертификаты ключ, поданный крейту выпуска.
///
/// Ключ уезжает во временный файл, потому что подписывающий крейт читает его с
/// диска и проверяет права на открытом дескрипторе — тот же путь, которым в
/// продуктиве едет ключ парка. Каталог держится живым до конца сборки: он
/// удаляется вместе с возвращаемым значением.
fn file_signer(key: &StandKey) -> Result<(tempfile::TempDir, tessera_issuer::file::FileSigner)> {
    let dir = tempfile::tempdir().context("временный каталог ключа комплекта")?;
    let path = dir.path().join("stand.key");
    fs::write(&path, key.pkcs8_der()?).context("запись ключа комплекта")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .context("права ключа комплекта")?;
    }
    let signer = tessera_issuer::file::FileSigner::open(
        tessera_issuer::file::FileConfig {
            path: path.clone(),
            key_id: KeyId::new("stand-root"),
            requested_algorithm: Some(SignatureAlgorithm::EcdsaWithSha256),
        },
        // Ключ комплекта не зашифрован: он и так фиксированное зерно в
        // репозитории, и пароль над ним не защищал бы ничего, а делал бы вид.
        &no_passphrase,
    )
    .context("подписывающий ключ комплекта")?;
    Ok((dir, signer))
}

/// Оборачивает DER в PEM.
fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut text = format!("-----BEGIN {label}-----\n");
    for chunk in body.as_bytes().chunks(64) {
        text.push_str(&String::from_utf8_lossy(chunk));
        text.push('\n');
    }
    text.push_str("-----END ");
    text.push_str(label);
    text.push_str("-----\n");
    text.into_bytes()
}

/// Документ канала одной строкой с переводом в конце.
fn line(text: &str) -> Vec<u8> {
    format!("{text}\n").into_bytes()
}

/// Опись комплекта.
fn readme(engineer_id: &str) -> String {
    format!(
        "# Комплект фикстур серверного стенда\n\
         \n\
         Собирается `cargo xtask codes-stand-fixtures --out <каталог>`. Зёрна ключей\n\
         фиксированы, подписи настоящие (ECDSA P-256, RFC 6979), поэтому повторный\n\
         прогон даёт те же байты — это проверяется тестом крейта раннера.\n\
         \n\
         - `{root}` — самоподписанный корень парка.\n\
         - `{org}` — сертификат организации `{organisation}` под корнем, с потолком\n\
           делегирования: роли {roles:?}, уровень {level}, TTL {ttl} с, метка\n\
           `{tag_key}={tag_value}`.\n\
         - `{crl}` — список отзыва сертификатов организации: ПУСТОЙ, но подписанный\n\
           корнем. Пустой список — документ, а не отсутствие документа.\n\
         - `{anchor}` — открытая половина ключа авторизаций парка. Им проверяются\n\
           авторизация инженера и список отзыва прав; корнем — сертификаты.\n\
         - `{record}` — запись реестра инженера `{engineer}`, подписанная\n\
           организацией. Ключ аутентификатора в варианте «не подтверждено» с\n\
           причиной `stub-provider`: настоящего провайдера в MVP нет.\n\
         - `{authorisation}` — авторизация того же инженера, подписанная КЛЮЧОМ\n\
           АВТОРИЗАЦИЙ парка (не организацией). Рамки вложены в потолок\n\
           организации: одна роль из двух, тот же уровень, та же метка.\n\
         - `{rights}` — подписанный список отзыва прав, пустой, серийный номер 1.\n\
         \n\
         ## Вектор кода\n\
         \n\
         Четыре файла ниже описывают одну попытку целиком, чтобы ожидаемый код\n\
         можно было посчитать СТОРОННИМ инструментом. Смысл в том, что сквозной\n\
         тест канала сравнивает две реализации одного открытого ядра и общей\n\
         ошибки в них не заметит.\n\
         \n\
         - `{agreement}` — приватная половина ключа согласования выдающей стороны,\n\
           PKCS#8 PEM. Её открытая половина лежит в билете.\n\
         - `{ephemeral}` — открытая половина эфемерной пары попытки, SPKI PEM. На\n\
           живом устройстве такая пара порождается заново на каждую попытку и\n\
           нигде не хранится; здесь она зафиксирована, иначе внешняя проверка\n\
           ECDH невозможна.\n\
         - `{ticket}` — билет выдающей стороны `{server}`. Его канонические байты\n\
           хешируются в контекст вывода ключа: другой байт — другой код.\n\
         - `{inputs}` — поля попытки и всё, что нужно стороннему инструменту.\n\
         - `{page_urls}` — адреса страницы инженера, опубликованные парком.\n\
           Устройство показывает один из них перед challenge и своего не\n\
           составляет: `[codes].page_url` вне этого списка отвергается при\n\
           загрузке конфигурации.\n\
         \n\
         ## Цепочка без выдач\n\
         \n\
         - `{no_issuances}` — журнал выдающей стороны, в котором есть строки и нет\n\
           ни одной выдачи: так выглядит свежий узел, который пока только отказывал\n\
           и подписывал авторизации. Сверка обязана прочитать его как выдающую\n\
           сторону с нулём грантов, а не как подменённый журнал.\n\
         \n\
         Ожидаемый код лежит в `code-vector-expected.txt`, и его пишет НЕ этот\n\
         генератор: `python3 tools/codes-golden-code.py <этот каталог>`. Генератор\n\
         собран тем же крейтом, который код и считает, — впиши он сюда ответ,\n\
         вектор сверял бы реализацию саму с собой.\n\
         \n\
         Личный номер инженера — `{engineer}`: сегмент организации, серийная часть\n\
         и контрольный символ, посчитанный крейтом контракта.\n",
        agreement = names::AGREEMENT_KEY,
        ephemeral = names::EPHEMERAL_PUBLIC,
        ticket = names::VECTOR_TICKET,
        inputs = names::VECTOR_INPUTS,
        page_urls = names::PAGE_URLS,
        no_issuances = names::CHAIN_WITHOUT_ISSUANCES,
        server = VECTOR_SERVER_ID,
        root = names::ROOT_CERT,
        org = names::ORGANISATION_CERT,
        crl = names::ORGANISATION_CRL,
        anchor = names::AUTHORISATION_ANCHOR,
        record = names::ENGINEER_RECORD,
        authorisation = names::ENGINEER_AUTHORISATION,
        rights = names::RIGHTS_REVOCATIONS,
        organisation = ORGANISATION_ID,
        roles = CEILING_ROLES,
        level = CEILING_LEVEL,
        ttl = MAX_TTL_SECS,
        tag_key = CEILING_TAG.0,
        tag_value = CEILING_TAG.1,
        engineer = engineer_id,
    )
}

/// Кладёт комплект в каталог.
fn publish(out: &Path, bundle: &Bundle) -> Result<()> {
    fs::create_dir_all(out).with_context(|| format!("создание {}", out.display()))?;
    for (name, bytes) in &bundle.files {
        let path: PathBuf = out.join(name);
        fs::write(&path, bytes).with_context(|| format!("запись {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "упавший шаг подготовки теста обязан ронять тест на месте"
)]
mod tests {
    use super::{build, engineer_number, names, publish};

    /// Повторная сборка даёт те же байты.
    ///
    /// Это и есть свойство, ради которого комплект собран отдельно от того, что
    /// тянет ключи из системного источника: фикстура, меняющаяся от прогона к
    /// прогону, не годится ни для сравнения, ни для отладки чужого стенда.
    #[test]
    fn a_second_build_produces_the_same_bytes() {
        let first = build().unwrap();
        let second = build().unwrap();
        assert_eq!(first.files.len(), second.files.len());
        for ((name, left), (_, right)) in first.files.iter().zip(second.files.iter()) {
            assert_eq!(left, right, "файл {name} разошёлся между двумя сборками");
        }
    }

    /// Список адресов лежит под именем, которое читает продукт.
    ///
    /// Имя записано в раннере строкой: он от `tessera_core` не зависит. Эта
    /// сверка и есть то, что не даёт двум написаниям разъехаться — иначе
    /// комплект клал бы файл, которого проверка конфигурации не видит.
    #[test]
    fn the_addresses_lie_under_the_name_the_product_reads() {
        assert_eq!(
            names::PAGE_URLS,
            tessera_core::codes::store::PAGE_URLS_FILENAME
        );

        let bundle = build().unwrap();
        let file = bundle
            .files
            .iter()
            .find(|(name, _)| *name == names::PAGE_URLS)
            .expect("комплект не несёт списка адресов");
        let text = String::from_utf8(file.1.clone()).unwrap();
        assert!(
            text.lines().any(|line| line.trim() == super::PAGE_URL),
            "в списке нет объявленного адреса: {text}"
        );
        assert!(super::PAGE_URL.starts_with("https://"));
    }

    /// КАЖДЫЙ PEM комплекта несёт шапку «фикстура, не секрет».
    ///
    /// Файл с `PRIVATE KEY` в публичном репозитории обязан объяснять себя на
    /// первой же строке — человеку и сканеру секретов, которым иначе придётся
    /// выяснять это через историю коммитов. То же и с сертификатами: секретом
    /// они не являются, но выглядят как корень и организация настоящего парка.
    ///
    /// Перечисление здесь не по именам файлов, а по расширению: новый PEM,
    /// добавленный в комплект без шапки, обязан ронять этот тест, а список
    /// имён такой файл просто не заметил бы.
    #[test]
    fn every_pem_of_the_bundle_says_it_is_a_fixture_first() {
        let bundle = build().unwrap();
        let pems: Vec<&(&str, Vec<u8>)> = bundle
            .files
            .iter()
            .filter(|(name, _)| {
                std::path::Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext == "pem")
            })
            .collect();
        assert_eq!(pems.len(), 6, "в комплекте {} PEM, а не шесть", pems.len());

        for (name, bytes) in pems {
            let text = String::from_utf8(bytes.clone()).unwrap();
            assert!(
                text.starts_with("# ФИКСТУРА, НЕ СЕКРЕТ."),
                "{name} не объясняет себя первой строкой: {}",
                text.lines().next().unwrap_or_default()
            );
            // И остаётся читаемым PEM: преамбулу разборщики пропускают.
            assert!(text.contains("-----BEGIN "), "{name} перестал быть PEM");
        }
    }

    /// Ожидаемый код комплект НЕ пишет.
    ///
    /// В этом весь смысл вектора: ответ считает сторонний инструмент, а этот
    /// генератор собран тем же крейтом, который код и вычисляет. Стоит ему
    /// начать писать ответ — и вектор превратится в сверку реализации самой с
    /// собой, причём выглядеть будет ровно так же, как настоящий.
    #[test]
    fn the_bundle_does_not_write_the_expected_code() {
        let bundle = build().unwrap();
        assert!(
            !bundle
                .files
                .iter()
                .any(|(name, _)| name.contains("expected")),
            "генератор комплекта пишет ожидаемый код — вектор перестал быть внешним"
        );
    }

    /// Билет вектора проверяется ключом удостоверяющей стороны, и его хеш —
    /// тот, что записан во входах.
    #[test]
    fn the_vector_ticket_verifies_and_its_hash_is_the_one_the_inputs_declare() {
        use tessera_codes_contract::ticket::SignedTicket;

        let bundle = build().unwrap();
        let file = |name: &str| {
            String::from_utf8(
                bundle
                    .files
                    .iter()
                    .find(|(candidate, _)| *candidate == name)
                    .expect("файл комплекта")
                    .1
                    .clone(),
            )
            .unwrap()
        };

        let ticket = SignedTicket::parse(file(names::VECTOR_TICKET).trim()).unwrap();
        let hash = super::hex(ticket.context_hash().unwrap().as_bytes());
        let declared = file(names::VECTOR_INPUTS)
            .lines()
            .find_map(|line| line.strip_prefix("ticket_hash_sha256=").map(str::to_owned))
            .expect("во входах вектора есть хеш билета");
        assert_eq!(
            hash, declared,
            "входы вектора объявляют не тот хеш билета, что даёт сам билет"
        );

        // И билет несёт открытую половину ИМЕННО того ключа согласования,
        // который лежит в комплекте: иначе ECDH сторонним инструментом дал бы
        // другой секрет, а причина выглядела бы как ошибка арифметики.
        let agreement = super::StandKey::from_seed(&super::AGREEMENT_SEED).unwrap();
        assert_eq!(
            ticket.ticket().public_key().as_bytes(),
            agreement.sec1_point().as_slice(),
            "билет вектора несёт не ту открытую половину"
        );
    }

    /// Документы канала читаются обратно и проверяются теми ключами, которыми
    /// подписаны.
    #[test]
    fn the_documents_verify_under_the_keys_that_signed_them() {
        use tessera_codes_contract::engineer::{EngineerAuthorisation, EngineerRecord};
        use tessera_codes_contract::revocation::SignedRevocationList;
        use tessera_codes_contract::signature::{SignatureError, SignatureVerifier, SignerRef};

        struct StandVerifier {
            organisation: p256::ecdsa::VerifyingKey,
            authorisation: p256::ecdsa::VerifyingKey,
        }

        impl SignatureVerifier for StandVerifier {
            fn verify(
                &self,
                signer: SignerRef<'_>,
                message: &[u8],
                signature: &tessera_codes_contract::signature::Signature,
            ) -> Result<(), SignatureError> {
                use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
                use sha2::{Digest as _, Sha256};

                let key = match signer {
                    SignerRef::Named(_) => &self.organisation,
                    SignerRef::AuthorisationKey => &self.authorisation,
                    // Ключ, который несёт сам документ, в этом комплекте не
                    // участвует: доказательства владения нет, потому что нет
                    // ключа аутентификатора.
                    SignerRef::Key(_) | SignerRef::TicketAuthority => {
                        return Err(SignatureError::UnknownSigner)
                    }
                };
                let parsed = p256::ecdsa::Signature::from_der(signature.as_bytes())
                    .map_err(|_| SignatureError::Rejected)?;
                key.verify_prehash(&Sha256::digest(message), &parsed)
                    .map_err(|_| SignatureError::Rejected)
            }
        }

        let bundle = build().unwrap();
        let file = |name: &str| {
            String::from_utf8(
                bundle
                    .files
                    .iter()
                    .find(|(candidate, _)| *candidate == name)
                    .expect("файл комплекта")
                    .1
                    .clone(),
            )
            .unwrap()
        };

        let organisation = super::StandKey::from_seed(&super::ORGANISATION_SEED).unwrap();
        let authorisation = super::StandKey::from_seed(&super::AUTHORISATION_SEED).unwrap();
        let verifier = StandVerifier {
            organisation: p256::ecdsa::VerifyingKey::from_sec1_bytes(&organisation.sec1_point())
                .unwrap(),
            authorisation: p256::ecdsa::VerifyingKey::from_sec1_bytes(&authorisation.sec1_point())
                .unwrap(),
        };

        let record = EngineerRecord::parse(file(names::ENGINEER_RECORD).trim()).unwrap();
        assert_eq!(record.verify(&verifier), Ok(()));
        // И запись прямо говорит, что личность никто не подтверждал.
        assert!(!record.identity_is_verified());

        let authorisation_doc =
            EngineerAuthorisation::parse(file(names::ENGINEER_AUTHORISATION).trim()).unwrap();
        assert_eq!(authorisation_doc.verify(&verifier), Ok(()));

        let rights = SignedRevocationList::parse(file(names::RIGHTS_REVOCATIONS).trim()).unwrap();
        assert_eq!(rights.verify(&verifier), Ok(()));
        assert!(rights.list().entries().is_empty());
    }

    /// Личный номер собран по правилу, а не написан руками.
    #[test]
    fn the_engineer_number_carries_its_check_character() {
        let number = engineer_number().unwrap();
        assert!(number.starts_with(super::ENGINEER_BODY));
        // Тот же символ, посчитанный крейтом контракта над телом номера: если
        // алгоритм переедет, комплект переедет вместе с ним, а не разойдётся.
        let check =
            tessera_codes_contract::device_number::check_character(super::ENGINEER_BODY).unwrap();
        assert!(number.ends_with(check));
    }

    /// Номер, которым представляется ХЕЛПЕР СТЕНДА, — номер по правилу.
    ///
    /// Проверяется файл хелпера, потому что проверять больше негде: значение
    /// живёт в shell, ни один тест его не читал, и подстановка `eng-1` обратно
    /// не роняла НИЧЕГО — прогон стенда упал бы на ENG-010 много позже и
    /// выглядел бы как отказ продукта. Сравнение идёт с тем же крейтом, который
    /// считает контрольный символ, а не с записанной здесь строкой.
    #[test]
    fn the_stand_helper_introduces_itself_with_a_number_of_the_format() {
        let helper =
            std::fs::read_to_string(crate::repo_root().join("tests/e2e/helpers/codes-server.sh"))
                .expect("хелпер серверного канала");

        for key in ["TESSERA_E2E_ENGINEER_ID", "TESSERA_E2E_OTHER_ENGINEER_ID"] {
            let line = helper
                .lines()
                .find(|line| line.contains(&format!("${{{key}:-")))
                .unwrap_or_else(|| panic!("в хелпере нет значения по умолчанию для {key}"));
            let default = line
                .split(":-")
                .nth(1)
                .and_then(|rest| rest.split('}').next())
                .unwrap_or_else(|| panic!("не разобрать значение по умолчанию {key}: {line}"));
            tessera_codes_contract::engineer_number::EngineerNumber::parse(default).unwrap_or_else(
                |error| {
                    panic!("{key} = {default}: номером по правилу ENG-010 не является: {error}")
                },
            );
        }
    }

    /// Комплект кладётся на диск целиком.
    #[test]
    fn the_bundle_lands_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("stand");
        publish(&out, &build().unwrap()).unwrap();
        for name in [
            names::ROOT_CERT,
            names::ORGANISATION_CERT,
            names::ORGANISATION_CRL,
            names::AUTHORISATION_ANCHOR,
            names::ENGINEER_RECORD,
            names::ENGINEER_AUTHORISATION,
            names::RIGHTS_REVOCATIONS,
            names::README,
        ] {
            assert!(out.join(name).is_file(), "нет файла {name}");
        }
    }
}
