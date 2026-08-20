//! Генератор фикстур телефонного канала для сюиты `27-codes-phone`.
//!
//! Кейсы этой сюиты требуют согласованного комплекта: ключа устройства в
//! контейнере, билета оператора, подписанной записи устройства и якорей, по
//! которым проверяются подписи. Собрать это `openssl`'ом нельзя — билет и запись
//! устройства не X.509, а документы контракта (`tessera_codes_contract`) с
//! собственной канонической формой и доменным разделением подписей. Второй
//! реализации этих форматов быть не должно: разошедшись с продуктом, она даст не
//! красный тест, а «код не подходит» у инженера на объекте.
//!
//! # Почему это xtask, а не подкоманда `issuer`
//!
//! Генератор порождает удостоверяющую сторону парка: ключ, чьей подписью
//! действителен любой билет, и организацию, чьей подписью действительна любая
//! запись устройства. Такая команда внутри поставляемого бинаря — это
//! возможность выпустить «настоящий» билет на живом парке, и никакая пометка
//! «только для тестов» этого не отменит. Здесь же она стоит в инструменте
//! разработчика, который в поставку не входит, рядом с самим прогоном реестра.
//!
//! Документы, подписи и контейнер собираются вызовами продуктовых крейтов
//! (`tessera_codes_contract`, `tessera_issuer`) — генератор решает только, какие
//! значения в них положить.
//!
//! # Связность
//!
//! Комплект осмыслен только целиком: эпоха, регион и теги обязаны совпадать в
//! записи устройства, билете и конфигурации устройства, а открытая половина
//! ключа устройства в записи — быть парной приватной в контейнере. Поэтому
//! генератор пишет всё во временный каталог рядом с целевым и подменяет его
//! одним переименованием: прерванный прогон оставляет прежний комплект целым,
//! а не половину нового.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use tessera_codes_contract::device_number::CheckedDeviceNumber;
use tessera_codes_contract::key::Epoch;
use tessera_codes_contract::registry::DeviceRecord;
use tessera_codes_contract::signature::{PublicKey, Signature};
use tessera_codes_contract::ticket::{
    OperatorTicket, SignedTicket, TicketNumber, TicketScope, TicketScopeInput,
};
use tessera_codes_contract::time::ClaimedTime;
use tessera_ext::delegation::DelegationConstraints;
use tessera_issuer::journal::{Journal, JournalError, JournalStorage};
use tessera_issuer::keygen::OsEntropy;
use tessera_issuer::pkcs12::{build_container, ContainerContents};
use tessera_issuer::sign::{KeyId, SignError, SignatureAlgorithm, SignatureBackend};
use tessera_issuer::{issue_root, CaRequest, Serial, Validity};

use crate::cli::CodesFixturesArgs;

/// Номер устройства без контрольного символа; символ считает контракт.
const DEVICE_BODY: &str = "77-000123";

/// Эпоха ключа устройства в комплекте.
const EPOCH_VALUE: u32 = 1;

/// Регион устройства и билета.
const REGION: &str = "ru-central";

/// Теги устройства. Билет достаёт устройство по общему тегу, поэтому первый из
/// них попадает и в рамки билета.
const TAGS: [&str; 2] = ["dc-1", "hq"];

/// Идентификатор оператора телефонного канала.
const OPERATOR_ID: &str = "op-e2e";

/// Номер билета оператора.
const TICKET_NUMBER: &str = "tk-e2e-1";

/// Идентификатор организации, подписывающей запись устройства.
const ORGANISATION_ID: &str = "acme";

/// PIN контейнера ключа устройства.
///
/// Не секрет: фикстурный материал, как `correct-pin` у соседних фикстур. Длина
/// взята не с потолка — сборщик контейнеров продукта не принимает пароль короче
/// [`tessera_issuer::pkcs12::MIN_PASSPHRASE_CHARS`], и фикстура, обходящая
/// собственный порог продукта, учила бы неверному.
const DEVICE_KEY_PIN: &str = "codes-e2e-device-pin";

/// Потолок уровня в билете оператора.
///
/// Единица, а не что-то выше: на этом стоит кейс CODE-006, который просит
/// уровень 2 и обязан получить отказ по рамкам билета.
const TICKET_MAX_LEVEL: u32 = 1;

/// Ролевые учётные записи прогона, которые билет допускает.
///
/// Роль в challenge — это имя ролевой учётной записи, под которой идёт вход, а
/// оно задаётся профилем стенда (`{{user}}`): контейнерные профили ходят под
/// `tester`, стенд — под `serv`. Билет называет обе, потому что список ролей —
/// это проверяемая рамка, и подменять её маркером «все роли» значило бы снять с
/// кейса CODE-001 половину того, что он стережёт.
const DEFAULT_ROLES: [&str; 2] = ["tester", "serv"];

/// Момент, после которого билет фикстуры недействителен: 2031-01-01T00:00:00Z.
///
/// Запас в годы, чтобы кейсы не начали падать по часам стенда, и всё-таки
/// конечный: бессрочный билет в фикстуре — это пример, которому потом следуют.
/// Дата продублирована в README комплекта.
const TICKET_NOT_AFTER: u64 = 1_924_905_600;

/// Начало срока действия сертификата в контейнере: 2020-01-01T00:00:00Z.
const CERT_NOT_BEFORE: u64 = 1_577_836_800;

/// Потолок TTL в конверте делегирования сертификата устройства, секунды.
const CERT_MAX_TTL_SECS: u64 = 3_600;

/// Версия профиля сертификата.
const CERT_PROFILE_VERSION: u32 = 1;

/// Имена файлов комплекта. Совпадают с тем, что читает
/// `tests/e2e/helpers/codes-phone.sh`; расхождение здесь выглядит на прогоне как
/// отказ продукта.
mod names {
    /// Манифест каталога.
    pub(super) const MANIFEST: &str = "device.env";
    /// Контейнер с приватным ключом устройства.
    pub(super) const DEVICE_CONTAINER: &str = "device.p12";
    /// Действующие билеты операторов, по документу в строке.
    pub(super) const TICKETS: &str = "tickets.txt";
    /// Якорь удостоверяющей стороны билетов.
    pub(super) const TICKET_AUTHORITY: &str = "ticket-authority.pem";
    /// Билет оператора отдельным файлом — то, что оператор предъявляет выдаче.
    pub(super) const OPERATOR_TICKET: &str = "operator-ticket.txt";
    /// Приватный ключ оператора.
    pub(super) const OPERATOR_KEY: &str = "operator-key.pem";
    /// Запись устройства.
    pub(super) const DEVICE_RECORD: &str = "device-record.txt";
    /// Якорь организации, подписавшей запись.
    pub(super) const ORGANISATION_ANCHOR: &str = "organisation-anchor.pem";
    /// Описание комплекта.
    pub(super) const README: &str = "README.md";
}

/// Собирает комплект фикстур и подменяет им прежний.
///
/// # Errors
///
/// Возвращает ошибку, если ключи, документы или контейнер не собрались, либо
/// если каталог не удалось записать. Прежний комплект в этом случае остаётся
/// нетронутым.
pub fn codes_fixtures(args: &CodesFixturesArgs) -> Result<i32> {
    let roles: Vec<String> = if args.roles.is_empty() {
        DEFAULT_ROLES
            .iter()
            .map(|role| (*role).to_owned())
            .collect()
    } else {
        args.roles.clone()
    };

    let bundle = build(&roles).context("сборка комплекта фикстур")?;
    publish(&args.out, &bundle)
        .with_context(|| format!("запись комплекта в {}", args.out.display()))?;

    println!("комплект записан в {}", args.out.display());
    println!(
        "устройство {} эпоха {EPOCH_VALUE} регион {REGION}",
        bundle.device_number
    );
    println!(
        "оператор {OPERATOR_ID} билет {TICKET_NUMBER} роли {}",
        roles.join(", ")
    );
    println!("потолок уровня {TICKET_MAX_LEVEL}, билет действителен до {TICKET_NOT_AFTER}");
    Ok(0)
}

/// Один файл готового комплекта.
struct FixtureFile {
    /// Имя внутри каталога комплекта.
    name: &'static str,
    /// Содержимое.
    bytes: Vec<u8>,
    /// Класть ли файл под права 0600.
    ///
    /// Приватный ключ оператора выкладывается закрытым — но только в том
    /// рабочем дереве, где генератор отработал. **Git режим файла не хранит**
    /// (в индексе у всех фикстур `100644`, из прав переживает только бит
    /// исполнения), поэтому в свежем клоне — то есть в CI и на любом стенде,
    /// куда репозиторий не скопировали целиком, — файл появится с 0644 по
    /// umask. Права обязан выставить тот, кто раскладывает комплект;
    /// `tests/e2e/helpers/codes-phone.sh` делает это копией под 0600, и его
    /// копия несущая, а не подстраховочная. Здесь 0600 стоит для того дерева,
    /// где ключ только что появился на диске.
    owner_only: bool,
}

/// Закрывает файл правами владельца.
fn set_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("права 0600 на {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Готовый комплект, собранный целиком в памяти.
struct Bundle {
    /// Файлы комплекта.
    files: Vec<FixtureFile>,
    /// Номер устройства с контрольным символом — он же в манифесте.
    device_number: String,
}

/// Ключ фикстуры: генерируется здесь, подписывает документы контракта.
struct FixtureKey {
    secret: p256::SecretKey,
}

impl FixtureKey {
    /// Порождает ключ из системного источника случайности.
    fn generate() -> Self {
        Self {
            secret: p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng),
        }
    }

    /// Открытая половина в SEC1, как её несут документы канала.
    fn sec1_point(&self) -> Vec<u8> {
        self.secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Открытая половина как `SubjectPublicKeyInfo` в PEM — форма якоря.
    fn spki_pem(&self) -> Result<String> {
        self.secret
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .context("кодирование открытого ключа в SPKI PEM")
    }

    /// Приватная половина в PKCS#8 PEM.
    fn pkcs8_pem(&self) -> Result<Zeroizing<String>> {
        self.secret
            .to_pkcs8_pem(LineEnding::LF)
            .context("кодирование приватного ключа в PKCS#8 PEM")
    }

    /// Приватная половина в PKCS#8 DER — то, из чего собирается контейнер.
    fn pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            self.secret
                .to_pkcs8_der()
                .context("кодирование приватного ключа в PKCS#8 DER")?
                .as_bytes()
                .to_vec(),
        ))
    }

    /// `SubjectPublicKeyInfo` в DER — то, что уходит в сертификат.
    fn spki_der(&self) -> Result<Vec<u8>> {
        Ok(self
            .secret
            .public_key()
            .to_public_key_der()
            .context("кодирование открытого ключа в SPKI DER")?
            .as_bytes()
            .to_vec())
    }

    /// Подписывает сообщение так, как подписывает парк: ECDSA над SHA-256, DER.
    ///
    /// Тот же digest на обеих сторонах: устройство проверяет билет OpenSSL'ом
    /// над SHA-256 независимо от кривой, и подпись, снятая иначе, прошла бы
    /// проверку у выдачи и провалилась на устройстве.
    fn sign(&self, message: &[u8]) -> Result<Signature> {
        let key = p256::ecdsa::SigningKey::from(&self.secret);
        let digest = Sha256::digest(message);
        let signature: p256::ecdsa::Signature = key
            .sign_prehash(&digest)
            .context("подпись документа фикстуры")?;
        Ok(Signature::new(signature.to_der().as_bytes().to_vec())?)
    }
}

/// Подписывающая сторона для выпуска сертификата устройства.
///
/// Сертификат нужен по одной причине: PKCS#12 без сертификата не открывается
/// (`LoadedKeyMaterial::from_p12` требует и ключ, и сертификат), а телефонный
/// канал берёт из контейнера только ключ. Поэтому устройство подписывает
/// сертификат само себе.
struct DeviceCertSigner<'a> {
    key: &'a FixtureKey,
    key_id: KeyId,
}

impl SignatureBackend for DeviceCertSigner<'_> {
    fn algorithm(&self, key_id: &KeyId) -> Result<SignatureAlgorithm, SignError> {
        if key_id == &self.key_id {
            Ok(SignatureAlgorithm::EcdsaWithSha256)
        } else {
            Err(SignError::UnknownKey(key_id.as_str().to_owned()))
        }
    }

    fn sign(
        &self,
        tbs_der: &[u8],
        key_id: &KeyId,
    ) -> Result<tessera_issuer::sign::Signature, SignError> {
        if key_id != &self.key_id {
            return Err(SignError::UnknownKey(key_id.as_str().to_owned()));
        }
        let signature = self
            .key
            .sign(tbs_der)
            .map_err(|error| SignError::Backend(error.to_string()))?;
        Ok(tessera_issuer::sign::Signature {
            algorithm: SignatureAlgorithm::EcdsaWithSha256,
            bytes: signature.as_bytes().to_vec(),
        })
    }
}

/// Журнал выпуска, живущий в памяти: сертификат фикстуры никуда не
/// журналируется, но ядру выпуска журнал нужен.
#[derive(Default)]
struct MemoryJournal {
    lines: Vec<String>,
}

impl JournalStorage for MemoryJournal {
    fn append(&mut self, line: &str) -> Result<(), JournalError> {
        self.lines.push(line.to_owned());
        Ok(())
    }

    fn read_lines(&self) -> Result<Vec<String>, JournalError> {
        Ok(self.lines.clone())
    }
}

/// Собирает весь комплект в памяти.
fn build(roles: &[String]) -> Result<Bundle> {
    let authority = FixtureKey::generate();
    let organisation = FixtureKey::generate();
    let device = FixtureKey::generate();
    let operator = FixtureKey::generate();

    let device_number = CheckedDeviceNumber::from_body(DEVICE_BODY)
        .context("контрольный символ номера устройства")?;
    let epoch = Epoch::new(EPOCH_VALUE);

    let ticket = signed_ticket(&authority, &operator, roles)?;
    let record = signed_record(&organisation, &device, &device_number, epoch)?;
    let container = device_container(&device, &device_number)?;

    let manifest = manifest(&device_number);
    let readme = readme(roles, &device_number);

    Ok(Bundle {
        device_number: device_number.as_str().to_owned(),
        files: vec![
            FixtureFile {
                name: names::MANIFEST,
                bytes: manifest.into_bytes(),
                owner_only: false,
            },
            FixtureFile {
                name: names::DEVICE_CONTAINER,
                bytes: container.to_vec(),
                owner_only: false,
            },
            FixtureFile {
                name: names::TICKETS,
                bytes: format!("{}\n", ticket.to_wire()).into_bytes(),
                owner_only: false,
            },
            FixtureFile {
                name: names::TICKET_AUTHORITY,
                bytes: authority.spki_pem()?.into_bytes(),
                owner_only: false,
            },
            FixtureFile {
                name: names::OPERATOR_TICKET,
                bytes: format!("{}\n", ticket.to_wire()).into_bytes(),
                owner_only: false,
            },
            FixtureFile {
                name: names::OPERATOR_KEY,
                bytes: operator.pkcs8_pem()?.as_bytes().to_vec(),
                owner_only: true,
            },
            FixtureFile {
                name: names::DEVICE_RECORD,
                bytes: format!("{}\n", record.to_wire()).into_bytes(),
                owner_only: false,
            },
            FixtureFile {
                name: names::ORGANISATION_ANCHOR,
                bytes: organisation.spki_pem()?.into_bytes(),
                owner_only: false,
            },
            FixtureFile {
                name: names::README,
                bytes: readme.into_bytes(),
                owner_only: false,
            },
        ],
    })
}

/// Собирает билет оператора и подписывает его удостоверяющей стороной.
fn signed_ticket(
    authority: &FixtureKey,
    operator: &FixtureKey,
    roles: &[String],
) -> Result<SignedTicket> {
    let scope = TicketScope::new(TicketScopeInput {
        // Билет достаёт устройство по общему тегу; хватает одного, и лишний
        // тег в рамках ничего не проверяет.
        tags: vec![TAGS[0].to_owned()],
        roles: roles.to_vec(),
        region: REGION.to_owned(),
        max_level: tessera_codes_contract::canon::Level::new(TICKET_MAX_LEVEL),
    })
    .context("рамки билета оператора")?;

    let ticket = OperatorTicket::new(
        OPERATOR_ID,
        PublicKey::new(operator.sec1_point())?,
        scope,
        ClaimedTime::new(TICKET_NOT_AFTER),
        TicketNumber::parse(TICKET_NUMBER).context("номер билета")?,
    )
    .context("сборка билета оператора")?;

    let signature = authority.sign(&ticket.encode().context("канонические байты билета")?)?;
    Ok(SignedTicket::new(ticket, signature))
}

/// Собирает запись устройства: подпись организации и `PoP` ключом устройства.
///
/// Запись собирается дважды: обе подписи снимаются с канонических байт тела, а
/// тело умеет кодировать только сама запись.
fn signed_record(
    organisation: &FixtureKey,
    device: &FixtureKey,
    device_number: &CheckedDeviceNumber,
    epoch: Epoch,
) -> Result<DeviceRecord> {
    let placeholder = Signature::new(vec![0x00])?;
    let draft = DeviceRecord::new(
        device_number.clone(),
        PublicKey::new(device.sec1_point())?,
        epoch,
        ORGANISATION_ID,
        placeholder.clone(),
        placeholder,
    )
    .context("черновик записи устройства")?;

    let organisation_signature =
        organisation.sign(&draft.encode().context("канонические байты записи")?)?;
    let possession_signature = device.sign(
        &draft
            .possession_message()
            .context("сообщение доказательства владения")?,
    )?;

    DeviceRecord::new(
        device_number.clone(),
        PublicKey::new(device.sec1_point())?,
        epoch,
        ORGANISATION_ID,
        organisation_signature,
        possession_signature,
    )
    .context("сборка записи устройства")
}

/// Собирает PKCS#12 с приватным ключом устройства под PIN.
fn device_container(
    device: &FixtureKey,
    device_number: &CheckedDeviceNumber,
) -> Result<Zeroizing<Vec<u8>>> {
    let key_id = KeyId::new("codes-fixture-device");
    let signer = DeviceCertSigner {
        key: device,
        key_id: key_id.clone(),
    };
    let mut journal = Journal::load(MemoryJournal::default()).context("журнал выпуска")?;

    let request = CaRequest {
        subject: format!("CN=tessera codes device {}", device_number.as_str()),
        subject_spki_der: device.spki_der()?,
        validity: Validity {
            not_before: CERT_NOT_BEFORE,
            not_after: TICKET_NOT_AFTER,
        },
        constraints: DelegationConstraints {
            require_tags: Vec::new(),
            allow_roles: DEFAULT_ROLES
                .iter()
                .map(|role| (*role).to_owned())
                .collect(),
            max_level: 1,
            max_ttl: CERT_MAX_TTL_SECS,
        },
        profile_version: CERT_PROFILE_VERSION,
    };
    let certificate = issue_root(
        &signer,
        &key_id,
        &request,
        &Serial::generate(),
        &mut journal,
        CERT_NOT_BEFORE,
    )
    .context("самоподписанный сертификат устройства")?;

    let key_der = device.pkcs8_der()?;
    build_container(
        &ContainerContents {
            private_key_pkcs8_der: key_der.as_slice(),
            leaf_der: &certificate.der,
            chain_der: &[],
        },
        DEVICE_KEY_PIN,
        &mut OsEntropy,
    )
    .context("контейнер ключа устройства")
}

/// Манифест каталога — то, чем хелпер узнаёт номер, эпоху и рамки.
fn manifest(device_number: &CheckedDeviceNumber) -> String {
    format!(
        "# Манифест комплекта фикстур телефонного канала.\n\
         # Сгенерирован `cargo xtask codes-fixtures`; правки руками разойдутся с ключами.\n\
         DEVICE_NUMBER={}\n\
         EPOCH={EPOCH_VALUE}\n\
         REGION={REGION}\n\
         TAGS=\"{}\"\n\
         OPERATOR_ID={OPERATOR_ID}\n\
         TICKET_NUMBER={TICKET_NUMBER}\n\
         DEVICE_KEY_PIN={DEVICE_KEY_PIN}\n\
         ORGANISATION_ID={ORGANISATION_ID}\n",
        device_number.as_str(),
        TAGS.join(" "),
    )
}

/// Описание комплекта рядом с ним самим.
fn readme(roles: &[String], device_number: &CheckedDeviceNumber) -> String {
    format!(
        "# Фикстуры телефонного канала (`27-codes-phone`)\n\
         \n\
         Комплект собран `cargo xtask codes-fixtures`. Руками его не правят: файлы связаны\n\
         подписями и общими значениями, и отредактированный файл выглядит на прогоне как\n\
         отказ продукта, а не как испорченная фикстура.\n\
         \n\
         Материал тестовый и публичный, как и соседние фикстуры этого каталога: приватные\n\
         ключи и PIN лежат здесь намеренно и никакого доступа никуда не дают.\n\
         \n\
         ## Права и владелец: из git они не приезжают\n\
         \n\
         Git хранит из прав только бит исполнения — в индексе у всех фикстур `100644`, и\n\
         владельца он не хранит вовсе. В свежем клоне (CI, стенд) файлы появятся с 0644 по\n\
         umask и с владельцем того, кто клонировал. **Права и владельца обязан выставить\n\
         тот, кто раскладывает комплект.** Генератор ставит 0600 на ключ оператора, но это\n\
         верно только для того дерева, где он отработал.\n\
         \n\
         Два файла упираются в это по-разному, и разница определяет, что именно нужно\n\
         выставить:\n\
         \n\
         - `{operator_key}` — **читается выдачей через владельческий гейт**: файл, доступный\n\
         на чтение группе или остальным, отвергается (`is readable beyond its owner`), и\n\
         выдача не состоится. Нужен режим 0600. Это самый частый способ получить красный\n\
         прогон на чистой машине.\n\
         - `{device_container}` — читается **устройством**, а там проверка другая: путь и\n\
         файл не должны быть доступны на запись группе и остальным, а владельцем компонентов\n\
         пути должен быть root (или та учётная запись, под которой идёт процесс). Режим 0644\n\
         сам по себе эту проверку проходит — но контейнер несёт приватный ключ устройства,\n\
         поэтому кладут его 0600 root:root, а не «лишь бы не писали».\n\
         \n\
         `tests/e2e/helpers/codes-phone.sh` делает и то, и другое: ключ оператора копией под\n\
         0600 в рабочий каталог прогона, артефакты устройства — `install -m 0600 -o root -g\n\
         root`. Убирать это как «лишнее» нельзя: без первого прогон встанет на первой выдаче,\n\
         без второго устройство откажется доверять своим же артефактам. Тот, кто разложит\n\
         комплект иначе, обязан сделать то же самое сам.\n\
         \n\
         ## Что с чем связано\n\
         \n\
         - `{device_container}` — приватный ключ устройства под PIN из `{manifest}`\n\
         (`DEVICE_KEY_PIN`). Открытая половина этого же ключа стоит в `{record}`; контейнер\n\
         несёт ещё и самоподписанный сертификат — PKCS#12 без сертификата не открывается,\n\
         телефонный канал его не читает.\n\
         - `{record}` — запись устройства: номер `{number}`, эпоха {EPOCH_VALUE}, подпись\n\
         организации `{ORGANISATION_ID}` и PoP ключом устройства. Проверяется якорем\n\
         `{organisation_anchor}`.\n\
         - `{tickets}` и `{operator_ticket}` — один и тот же билет оператора `{OPERATOR_ID}`\n\
         (устройство держит список, оператор предъявляет выдаче отдельный файл). Подписан\n\
         ключом, чей якорь — `{authority}`.\n\
         - `{operator_key}` — приватный ключ оператора, парный открытому в билете.\n\
         \n\
         Рамки билета: регион `{REGION}`, тег `{tag}`, роли {roles}, потолок уровня\n\
         {TICKET_MAX_LEVEL}. Потолок держит кейс CODE-006: запрос уровня 2 обязан получить\n\
         отказ по рамкам билета (`codes-refusal: ticket_scope_level`).\n\
         \n\
         Эпоха, регион и теги обязаны совпадать в записи устройства, билете и секции\n\
         `[codes]` конфигурации устройства — их пишет туда `helpers/codes-phone.sh` из\n\
         `{manifest}`.\n\
         \n\
         Списка отзыва здесь нет намеренно: прогон начинается с парка, где не отозвано\n\
         ничего, а кейс CODE-007 создаёт `tickets.revoked` сам.\n\
         \n\
         ## Срок\n\
         \n\
         Билет действителен до **2031-01-01T00:00:00Z** ({TICKET_NOT_AFTER}). После этой даты\n\
         кейсы сюиты начнут падать по сроку билета — перевыпустить комплект нужно заранее.\n\
         \n\
         ## Как перевыпустить\n\
         \n\
         ```sh\n\
         cargo xtask codes-fixtures --out crates/tessera_core/tests/fixtures/codes\n\
         ```\n\
         \n\
         Ключи каждый раз новые: комплект не детерминирован, и перевыпуск меняет все файлы\n\
         разом. Роли билета задаются `--role <имя>` (повторяемый флаг) — по умолчанию это\n\
         ролевые учётные записи профилей стенда, {roles}. Если профиль ходит под другой\n\
         учётной записью, комплект нужно перевыпустить с её именем, иначе билет не допустит\n\
         роль и кейс упадёт с `codes-refusal: ticket_scope_role`.\n",
        device_container = names::DEVICE_CONTAINER,
        manifest = names::MANIFEST,
        record = names::DEVICE_RECORD,
        organisation_anchor = names::ORGANISATION_ANCHOR,
        tickets = names::TICKETS,
        operator_ticket = names::OPERATOR_TICKET,
        authority = names::TICKET_AUTHORITY,
        operator_key = names::OPERATOR_KEY,
        number = device_number.as_str(),
        tag = TAGS[0],
        roles = roles.join(", "),
    )
}

/// Записывает комплект целиком, подменяя прежний одним переименованием.
fn publish(out: &Path, bundle: &Bundle) -> Result<()> {
    let parent = out
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    fs::create_dir_all(&parent)
        .with_context(|| format!("создание каталога {}", parent.display()))?;

    let file_name = out.file_name().map_or_else(
        || "codes".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let staging = parent.join(format!(".{file_name}.xtask-tmp"));
    if staging.exists() {
        fs::remove_dir_all(&staging).with_context(|| format!("очистка {}", staging.display()))?;
    }
    fs::create_dir(&staging).with_context(|| format!("создание {}", staging.display()))?;

    for file in &bundle.files {
        let path = staging.join(file.name);
        fs::write(&path, &file.bytes).with_context(|| format!("запись {}", path.display()))?;
        if file.owner_only {
            set_owner_only(&path)?;
        }
    }

    // Прежний комплект снимается только теперь, когда новый собран и записан
    // целиком: до этой точки любая ошибка оставляет каталог таким, каким он был.
    if out.exists() {
        let retired = parent.join(format!(".{file_name}.xtask-old"));
        if retired.exists() {
            fs::remove_dir_all(&retired)
                .with_context(|| format!("очистка {}", retired.display()))?;
        }
        fs::rename(out, &retired)
            .with_context(|| format!("перенос прежнего комплекта из {}", out.display()))?;
        let swapped = fs::rename(&staging, out);
        if swapped.is_err() {
            // Новый комплект встать не смог — возвращаем прежний на место, иначе
            // каталога не останется вовсе.
            fs::rename(&retired, out).ok();
            swapped.with_context(|| format!("подмена комплекта в {}", out.display()))?;
        }
        fs::remove_dir_all(&retired)
            .with_context(|| format!("удаление прежнего комплекта {}", retired.display()))?;
        return Ok(());
    }

    fs::rename(&staging, out).with_context(|| format!("установка комплекта в {}", out.display()))
}

/// Проверяет, что каталог назначения выглядит как каталог фикстур, а не как
/// что-то ещё, что жалко потерять.
///
/// # Errors
///
/// Возвращает ошибку, если каталог существует и не содержит ни одного файла
/// комплекта: генератор подменяет каталог целиком, и подменять чужой он не
/// должен.
pub fn check_target(out: &Path) -> Result<()> {
    if !out.exists() {
        return Ok(());
    }
    if !out.is_dir() {
        bail!("{} — не каталог", out.display());
    }
    let familiar = [names::MANIFEST, names::DEVICE_RECORD, names::TICKETS]
        .iter()
        .any(|name| out.join(name).exists());
    let empty = fs::read_dir(out)
        .with_context(|| format!("чтение {}", out.display()))?
        .next()
        .is_none();
    if familiar || empty {
        return Ok(());
    }
    bail!(
        "{} существует и не похож на каталог фикстур телефонного канала: \
         генератор подменяет каталог целиком и чужой не трогает",
        out.display()
    )
}

#[cfg(test)]
// Провалившийся шаг подготовки в тесте должен валить тест на месте: паника здесь
// — способ сообщить о проблеме, как и в остальных тестах раннера.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]
mod tests {
    use super::{build, check_target, names, publish, DEFAULT_ROLES};

    fn roles() -> Vec<String> {
        DEFAULT_ROLES
            .iter()
            .map(|role| (*role).to_owned())
            .collect()
    }

    #[test]
    fn the_bundle_carries_every_file_the_helper_reads() {
        let bundle = build(&roles()).unwrap();
        let names: Vec<&str> = bundle.files.iter().map(|file| file.name).collect();
        for expected in [
            names::MANIFEST,
            names::DEVICE_CONTAINER,
            names::TICKETS,
            names::TICKET_AUTHORITY,
            names::OPERATOR_TICKET,
            names::OPERATOR_KEY,
            names::DEVICE_RECORD,
            names::ORGANISATION_ANCHOR,
            names::README,
        ] {
            assert!(names.contains(&expected), "нет файла {expected}");
        }
        assert!(bundle.files.iter().all(|file| !file.bytes.is_empty()));
    }

    /// Комплект связен: выдача считает по нему код.
    ///
    /// Это единственная проверка, которая ловит расхождение любой из связей
    /// сразу — ключ оператора против билета, номер и эпоха против записи, якоря
    /// против подписей. Каждую из них можно было бы проверить по отдельности, но
    /// именно эта повторяет то, что делает стенд.
    #[test]
    fn the_bundle_computes_a_code_through_the_product() {
        use base64::Engine as _;
        use tessera_codes_contract::challenge::Challenge;
        use tessera_codes_contract::params::FleetParams;
        use tessera_codes_contract::registry::DeviceRecord;
        use tessera_codes_contract::ticket::SignedTicket;
        use tessera_issuer::codes::agreement::SoftwareOperatorKey;
        use tessera_issuer::codes::counter::EPOCH_INITIAL_COUNTER;
        use tessera_issuer::codes::issue::{issue, IssuanceRequest};
        use tessera_issuer::codes::scope::DeviceScope;
        use tessera_issuer::codes::trust::{AnchorKey, Anchors};
        use tessera_issuer::codes::Refusal;

        let bundle = build(&roles()).unwrap();
        let text = |name: &str| {
            String::from_utf8(
                bundle
                    .files
                    .iter()
                    .find(|file| file.name == name)
                    .map(|file| file.bytes.clone())
                    .unwrap(),
            )
            .unwrap()
        };

        let pem = |name: &str| {
            let text = text(name);
            let body: String = text
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect();
            base64::engine::general_purpose::STANDARD
                .decode(body)
                .unwrap()
        };

        let params = FleetParams::defaults();
        let record = DeviceRecord::parse(text(names::DEVICE_RECORD).trim()).unwrap();
        let ticket = SignedTicket::parse(text(names::OPERATOR_TICKET).trim()).unwrap();
        let anchors =
            Anchors::new(AnchorKey::from_spki_der(&pem(names::TICKET_AUTHORITY)).unwrap())
                .with_organisation(
                    super::ORGANISATION_ID,
                    AnchorKey::from_spki_der(&pem(names::ORGANISATION_ANCHOR)).unwrap(),
                );
        let key = SoftwareOperatorKey::from_pkcs8_der(
            &pem(names::OPERATOR_KEY),
            tessera_codes_contract::profile::AlgorithmProfile::P256,
        )
        .unwrap();
        let scope = DeviceScope {
            tags: super::TAGS.iter().map(|tag| (*tag).to_owned()).collect(),
            region: super::REGION.to_owned(),
        };
        // Момент внутри срока билета: часы стенда сюда не приходят.
        let now = tessera_codes_contract::time::ClaimedTime::new(super::CERT_NOT_BEFORE);

        let challenge = Challenge::parse(
            &format!(
                "tessera-codes/v1/challenge;device={};epoch={};nonce={:0>6}4711;role={};level=1;\
                 operator={}",
                bundle.device_number,
                super::EPOCH_VALUE,
                EPOCH_INITIAL_COUNTER,
                super::DEFAULT_ROLES[0],
                super::OPERATOR_ID,
            ),
            &params,
        )
        .unwrap();

        let request = IssuanceRequest {
            challenge: &challenge,
            record: &record,
            ticket: &ticket,
            params: &params,
            device_scope: Some(&scope),
            reason: "проверка связности комплекта",
            now,
            known_counter: None,
            history_depth: 0,
            override_decision: None,
        };
        let issuance = issue(&request, &anchors, &key).unwrap();
        assert_eq!(issuance.code.as_str().len(), usize::from(params.code_len()));

        // Потолок билета — тот, на котором стоит CODE-006: уровень 2 обязан
        // получить отказ именно по рамкам, а не по чему-то ещё.
        let above = Challenge::parse(
            &format!(
                "tessera-codes/v1/challenge;device={};epoch={};nonce={:0>6}4711;role={};level=2;\
                 operator={}",
                bundle.device_number,
                super::EPOCH_VALUE,
                EPOCH_INITIAL_COUNTER,
                super::DEFAULT_ROLES[0],
                super::OPERATOR_ID,
            ),
            &params,
        )
        .unwrap();
        let refused = issue(
            &IssuanceRequest {
                challenge: &above,
                ..request
            },
            &anchors,
            &key,
        )
        .unwrap_err();
        assert_eq!(refused.class(), "ticket_scope_level");
        assert!(matches!(refused, Refusal::ScopeLevel { ceiling: 1, .. }));
    }

    #[test]
    fn the_revocation_list_is_not_part_of_the_bundle() {
        let bundle = build(&roles()).unwrap();
        assert!(bundle
            .files
            .iter()
            .all(|file| file.name != "tickets.revoked"));
    }

    #[test]
    fn a_second_run_replaces_the_bundle_whole() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("codes");
        let bundle = build(&roles()).unwrap();
        publish(&out, &bundle).unwrap();
        let first = std::fs::read(out.join(names::DEVICE_RECORD)).unwrap();

        // Повторная публикация подменяет комплект целиком: прежних файлов не
        // остаётся, новые — все на месте.
        let second_bundle = build(&roles()).unwrap();
        publish(&out, &second_bundle).unwrap();
        let second = std::fs::read(out.join(names::DEVICE_RECORD)).unwrap();
        assert_ne!(first, second);
        assert!(out.join(names::MANIFEST).exists());
        assert!(!out.join(".codes.xtask-tmp").exists());
    }

    #[test]
    fn a_directory_that_is_not_a_fixture_set_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("не-фикстуры");
        std::fs::create_dir(&out).unwrap();
        std::fs::write(out.join("важное.txt"), b"x").unwrap();
        assert!(check_target(&out).is_err());

        let fixtures = dir.path().join("codes");
        std::fs::create_dir(&fixtures).unwrap();
        std::fs::write(fixtures.join(names::MANIFEST), b"DEVICE_NUMBER=x\n").unwrap();
        assert!(check_target(&fixtures).is_ok());
    }
}
