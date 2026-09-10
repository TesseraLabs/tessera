//! Подпись challenge ключом устройства — инструмент стенда.
//!
//! Нужен ровно одному кейсу реестра: CODE-014, где моделируется снятый диск.
//! Атакующему по условию задачи доступно всё, что лежит на устройстве, ключ
//! устройства включительно, — но не приватная половина эфемерной пары попытки,
//! потому что на момент снятия образа её не существует. Проверяемая гарантия:
//! код, посчитанный из статического ключа устройства, устройство не пускает.
//!
//! Чтобы такой код появился, подменённый challenge должен пройти выдачу, а
//! выдача с R.10 отвергает challenge, не подписанный зарегистрированным
//! прибором. Атакующий подписал бы его законно — ключ у него есть; хелпер
//! стенда написан на оболочке и подписать не может. Отсюда этот инструмент.
//!
//! Он **не** собирает подписываемое сообщение сам: канонические байты берутся у
//! крейта контракта тем же вызовом, которым их берёт устройство. Своя сборка
//! означала бы, что кейс проверяет совпадение двух написаний одного формата, а
//! не продукт.
//!
//! В поставку инструмент не входит: он живёт в раннере, как и всё остальное
//! стендовое.

use anyhow::{Context as _, Result};
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::pkcs8::DecodePrivateKey as _;
use sha2::{Digest as _, Sha256};

use tessera_codes_contract::challenge::{Challenge, SignedChallenge};
use tessera_codes_contract::params::FleetParams;
use tessera_codes_contract::signature::Signature;

use crate::cli::{CodesSignChallengeArgs, CodesSignRequestArgs};

/// Подписывает challenge и печатает подписанную проводную форму.
///
/// # Errors
///
/// Не читается ключ, не разбирается challenge, не собираются канонические
/// байты — всё это ошибки стенда, и раннер обязан отличать их от отказа
/// продукта.
pub fn codes_sign_challenge(args: &CodesSignChallengeArgs) -> Result<i32> {
    println!("{}", signed_wire(args)?);
    Ok(0)
}

/// Собирает подписанную проводную форму.
///
/// Отделено от печати, чтобы тест сверял РЕЗУЛЬТАТ, а не перехватывал вывод.
///
/// # Errors
///
/// См. [`codes_sign_challenge`].
fn signed_wire(args: &CodesSignChallengeArgs) -> Result<String> {
    let pem = std::fs::read_to_string(&args.key)
        .with_context(|| format!("чтение ключа устройства {}", args.key.display()))?;
    let secret = p256::SecretKey::from_pkcs8_pem(&pem)
        .context("ключ устройства не разобрался как PKCS#8 PEM")?;

    let text = match &args.challenge {
        Some(text) => text.clone(),
        None => std::fs::read_to_string(
            args.challenge_file
                .as_ref()
                .context("нужен один из --challenge или --challenge-file")?,
        )
        .context("чтение challenge из файла")?,
    };

    // Разбирается НЕподписанная форма: подписывают то, что напечатало
    // устройство, а не то, что уже подписано.
    let challenge = Challenge::parse(text.trim(), &FleetParams::defaults())
        .map_err(|error| anyhow::anyhow!("challenge не разобрался: {error}"))?;

    let message = challenge
        .signing_message()
        .map_err(|error| anyhow::anyhow!("канонические байты challenge: {error}"))?;

    // ECDSA над SHA-256 в DER — тем же, чем подписывает устройство и что умеет
    // проверять выдача.
    let key = p256::ecdsa::SigningKey::from(&secret);
    let digest = Sha256::digest(&message);
    let signature: p256::ecdsa::Signature = key
        .sign_prehash(&digest)
        .context("подпись challenge ключом устройства")?;
    let signature = Signature::new(signature.to_der().as_bytes().to_vec())
        .map_err(|error| anyhow::anyhow!("подпись пуста: {error}"))?;

    Ok(SignedChallenge::new(challenge, signature).to_wire())
}

/// Собирает подписанный запрос инженера и печатает его проводную форму.
///
/// На объекте это делает страница инженера: снимает challenge камерой,
/// добавляет основание и подписывает. Стенду нужна та же строка, собранная теми
/// же байтами — вторая сборка формата на языке оболочки разошлась бы с
/// продуктом молча.
///
/// Пустое основание — законный ввод: на нём стоит кейс CODE-020. Документ с ним
/// не собирается конструктором контракта, поэтому инструмент собирает годный
/// документ и затирает в нём основание — ровно то, что прислала бы сторона
/// инженера, собравшая запрос по-своему. Отказать обязана выдача, и кейс
/// проверяет именно её отказ.
///
/// # Errors
///
/// Не читается ключ, не разбирается challenge, не собирается документ.
pub fn codes_sign_request(args: &CodesSignRequestArgs) -> Result<i32> {
    println!("{}", signed_request_wire(args)?);
    Ok(0)
}

/// Собирает проводную форму подписанного запроса.
///
/// # Errors
///
/// См. [`codes_sign_request`].
fn signed_request_wire(args: &CodesSignRequestArgs) -> Result<String> {
    use tessera_codes_contract::request::{
        EngineerRequest, EngineerSignature, FourEyesDigest, RequestFields, SignedRequest,
    };
    use tessera_codes_contract::time::ClaimedTime;

    let text = match &args.challenge {
        Some(text) => text.clone(),
        None => std::fs::read_to_string(
            args.challenge_file
                .as_ref()
                .context("нужен один из --challenge или --challenge-file")?,
        )
        .context("чтение challenge из файла")?,
    };

    // Разбирается ПОДПИСАННАЯ форма: запрос собирается вокруг того challenge,
    // который показало устройство, и подпись устройства в него не входит —
    // выдаче она приезжает отдельным документом.
    let signed = SignedChallenge::parse(text.trim(), &FleetParams::defaults())
        .map_err(|error| anyhow::anyhow!("challenge не разобрался: {error}"))?;

    let requested_at = ClaimedTime::new(args.requested_at.unwrap_or_else(now_unix));
    // Основание, которым документ собирается. Пустое подставляется после
    // сборки: см. документацию функции.
    let blank = args.grounds.trim().is_empty();
    let grounds = if blank {
        PLACEHOLDER_GROUNDS
    } else {
        &args.grounds
    };
    let request = EngineerRequest::new(RequestFields {
        challenge: signed.challenge().clone(),
        grounds,
        grounds_reference: None,
        requested_at,
        // Порог четырёх глаз на стенде выключен, и запрос говорит об этом
        // прямо: digest политики — часть подписанного объекта, а не умолчание
        // читателя.
        four_eyes: FourEyesDigest::of_policy(b"off"),
    })
    .map_err(|error| anyhow::anyhow!("запрос не собрался: {error}"))?;

    // Без ключа — явный вариант «никто не подписывал». Стенд не притворяется,
    // что у него есть аутентификатор инженера: запись выдачи, помеченная как
    // подтверждённая, через полгода читается как выдача человеку, которого
    // кто-то проверил.
    let signature = match &args.key {
        Some(path) => {
            let pem = std::fs::read_to_string(path)
                .with_context(|| format!("чтение ключа подписи {}", path.display()))?;
            let secret = p256::SecretKey::from_pkcs8_pem(&pem)
                .context("ключ подписи не разобрался как PKCS#8 PEM")?;
            let message = request
                .encode()
                .map_err(|error| anyhow::anyhow!("канонические байты запроса: {error}"))?;
            let key = p256::ecdsa::SigningKey::from(&secret);
            let digest = Sha256::digest(&message);
            let signature: p256::ecdsa::Signature = key
                .sign_prehash(&digest)
                .context("подпись запроса инженера")?;
            EngineerSignature::Signed(
                Signature::new(signature.to_der().as_bytes().to_vec())
                    .map_err(|error| anyhow::anyhow!("подпись пуста: {error}"))?,
            )
        }
        None => EngineerSignature::unverified(&args.unverified_reason)
            .map_err(|error| anyhow::anyhow!("причина не годится для документа: {error}"))?,
    };

    let wire = SignedRequest::new(request, signature).to_wire();
    if !blank {
        return Ok(wire);
    }

    // Затирается только основание, внутри вложенного документа; подпись
    // инженера остаётся прежней и над этими байтами уже не сходится. Это не
    // недосмотр: выдача подпись инженера в MVP не проверяет, а проверяемая
    // кейсом ступень — отсутствие основания — стоит раньше всего остального.
    let inner = SignedRequest::parse(&wire, &FleetParams::defaults())
        .map_err(|error| anyhow::anyhow!("собранный запрос не разобрался: {error}"))?;
    let patched = inner
        .request()
        .to_wire()
        .replace(&format!("grounds={PLACEHOLDER_GROUNDS}"), "grounds=   ");
    Ok(format!(
        "tessera-codes/v1/signed-engineer-request;request={};engineer_signature={}",
        hex::encode(patched),
        inner.engineer_signature().to_wire_value()
    ))
}

/// Основание, под которым собирается документ, чьё основание потом затирается.
const PLACEHOLDER_GROUNDS: &str = "placeholder";

/// Часы стенда: момент, который сторона инженера заявляет о себе.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "упавший шаг подготовки теста обязан ронять тест на месте"
)]
mod tests {
    use super::{signed_request_wire, signed_wire};
    use crate::cli::{CodesSignChallengeArgs, CodesSignRequestArgs};
    use tessera_codes_contract::challenge::SignedChallenge;
    use tessera_codes_contract::params::FleetParams;

    /// Подписанное этим инструментом обязано проверяться ключом из записи
    /// реестра — то есть ровно тем, чем проверяет выдача.
    ///
    /// Комплект собирается настоящим генератором фикстур, а не отдельными
    /// ключами: инструмент существует ради него, и ключ, разошедшийся с
    /// записью, выглядел бы на прогоне отказом продукта.
    #[test]
    fn what_this_signs_verifies_against_the_record_of_the_bundle() {
        use tessera_codes_contract::registry::DeviceRecord;
        use tessera_codes_contract::signature::{SignatureError, SignatureVerifier, SignerRef};

        struct P256Verifier;

        impl SignatureVerifier for P256Verifier {
            fn verify(
                &self,
                signer: SignerRef<'_>,
                message: &[u8],
                signature: &tessera_codes_contract::signature::Signature,
            ) -> Result<(), SignatureError> {
                use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
                use sha2::{Digest as _, Sha256};

                let SignerRef::Key(key) = signer else {
                    return Err(SignatureError::UnknownSigner);
                };
                let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(key.as_bytes())
                    .map_err(|_| SignatureError::Rejected)?;
                let signature = p256::ecdsa::Signature::from_der(signature.as_bytes())
                    .map_err(|_| SignatureError::Rejected)?;
                verifying
                    .verify_prehash(&Sha256::digest(message), &signature)
                    .map_err(|_| SignatureError::Rejected)
            }
        }

        let dir = tempfile::tempdir().unwrap();
        crate::codes_fixtures::codes_fixtures(&crate::cli::CodesFixturesArgs {
            out: dir.path().to_path_buf(),
            roles: vec!["ops.dc.senior".to_owned()],
        })
        .unwrap();

        let record = DeviceRecord::parse(
            std::fs::read_to_string(dir.path().join("device-record.txt"))
                .unwrap()
                .trim(),
        )
        .unwrap();
        let params = FleetParams::defaults();
        let unsigned = format!(
            "tessera-codes/v1/challenge;device={};epoch={};nonce={};role=ops.dc.senior;level=1;\
             server=op-e2e;engineer=eng-1;ephemeral=04{}",
            record.device_number().as_str(),
            record.epoch().get(),
            "4".repeat(usize::from(params.nonce_width())),
            "aa".repeat(64),
        );

        let printed = signed_wire(&CodesSignChallengeArgs {
            challenge: Some(unsigned),
            challenge_file: None,
            key: dir.path().join("device-key.pem"),
        })
        .unwrap();

        let signed = SignedChallenge::parse(printed.trim(), &params).unwrap();
        assert_eq!(signed.verify(&record, &P256Verifier), Ok(()));

        // Вокруг того же challenge собирается запрос инженера, и в нём стоит
        // ТОТ ЖЕ challenge: расхождение двух документов выдача отвергает раньше
        // всего прочего, а на стенде оно выглядело бы отказом продукта.
        let request = signed_request_wire(&CodesSignRequestArgs {
            challenge: Some(printed.clone()),
            challenge_file: None,
            grounds: "наряд 42".to_owned(),
            requested_at: Some(1_800_000_000),
            key: Some(dir.path().join("device-key.pem")),
            unverified_reason: "unused".to_owned(),
        })
        .unwrap();
        let parsed =
            tessera_codes_contract::request::SignedRequest::parse(request.trim(), &params).unwrap();
        assert_eq!(parsed.request().challenge(), signed.challenge());
        assert_eq!(parsed.request().grounds(), "наряд 42");

        // Пустое основание инструмент не пропускает дальше себя не потому, что
        // проверяет его, а потому что документа с ним не существует. Отказ
        // приходит из крейта контракта — там же, где эту гарантию и держат.
        // Без ключа — явный вариант «никто не подписывал», с причиной. Стенду
        // подписывать нечем, и документ говорит об этом сам, вместо того чтобы
        // выглядеть подписанным.
        let unverified = signed_request_wire(&CodesSignRequestArgs {
            challenge: Some(printed.clone()),
            challenge_file: None,
            grounds: "наряд 42".to_owned(),
            requested_at: Some(1_800_000_000),
            key: None,
            unverified_reason: "stand-has-no-engineer-authenticator".to_owned(),
        })
        .unwrap();
        let parsed =
            tessera_codes_contract::request::SignedRequest::parse(unverified.trim(), &params)
                .unwrap();
        assert!(!parsed.engineer_signature().is_signed());
        assert_ne!(unverified, request, "оба случая собрались в одну строку");

        // Пустое основание документом контракта не является, и инструмент
        // выдаёт ровно такую строку: кейс CODE-020 обязан увидеть отказ выдачи,
        // а не отказ стенда.
        let blank = signed_request_wire(&CodesSignRequestArgs {
            challenge: Some(printed),
            challenge_file: None,
            grounds: "   ".to_owned(),
            requested_at: Some(1_800_000_000),
            key: Some(dir.path().join("device-key.pem")),
            unverified_reason: "unused".to_owned(),
        })
        .unwrap();
        assert_eq!(
            tessera_codes_contract::request::SignedRequest::parse(blank.trim(), &params),
            Err(tessera_codes_contract::request::RequestError::MissingGrounds)
        );
    }
}

/// Golden vector of the QR payload, as the device shows it.
///
/// Why it lives in the runner and not in the contract crate: the payload carries
/// a real ECDSA signature of a device, and the contract crate holds no
/// public-key arithmetic at all — by design, since it must build for
/// `wasm32-unknown-unknown` and hold no keys. The runner is the stand's device
/// side; it signs here with the same call the product signs with.
///
/// Why not the fixture bundle: the keys of the bundle are drawn fresh on every
/// run, so nothing produced with them can be a frozen vector. The seed here is
/// fixed, which is what makes "regenerate and compare" a meaningful test at all.
///
/// The vector exists because the engineer's page has to parse this payload, and
/// a page whose test vector the page's own author wrote proves only that the
/// author agrees with themselves.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed step of a golden generator must fail the test on the spot"
)]
mod golden_payload {
    use std::path::{Path, PathBuf};

    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;
    use sha2::{Digest as _, Sha256};

    use tessera_codes_contract::canon::Level;
    use tessera_codes_contract::challenge::{
        Challenge, ChallengeFields, SignedChallenge, SIGNED_CHALLENGE_PREFIX,
    };
    use tessera_codes_contract::device_number::CheckedDeviceNumber;
    use tessera_codes_contract::key::{EphemeralPublicPoint, Epoch};
    use tessera_codes_contract::nonce::Nonce;
    use tessera_codes_contract::params::FleetParams;
    use tessera_codes_contract::signature::Signature;

    /// Seed of the device key of the vector. Fixed, and it is the whole reason
    /// the vector can be regenerated byte for byte.
    const DEVICE_SEED: [u8; 32] = [0x33; 32];

    /// Seed of the ephemeral pair of the attempt. A live attempt draws its own;
    /// a vector needs the same bytes out of two runs.
    const EPHEMERAL_SEED: [u8; 32] = [0x55; 32];

    /// The personal number of the engineer in the vector.
    ///
    /// Built to the rule rather than written out: an organisation segment, a
    /// serial part, and the ISO 7064 MOD 37,36 check character over both,
    /// computed by the crate that owns the algorithm. The vector used to carry
    /// `eng-1`, which no fleet would issue — and a page tested against it would
    /// have been tested against a number the rule forbids.
    const ENGINEER_BODY: &str = "ORG1-000001";

    /// The base URL of the vector, as an allowlist entry of the fleet.
    ///
    /// A fleet's own address, not a real one: the vector states the shape, and a
    /// resolvable host in a test fixture is an invitation to reach it.
    const BASE_URL: &str = "https://codes.fleet.example/e";

    /// The budget of the whole URL, from the contract of the payload.
    const PAYLOAD_BUDGET: usize = 640;

    fn golden_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tessera_codes_contract/tests/golden/documents")
    }

    /// The personal number of the vector, check character included.
    ///
    /// The character comes from the crate that owns the algorithm, not from a
    /// constant written here: a fixture carrying a hand-copied check character
    /// would agree with itself and with nothing else.
    fn engineer_number() -> String {
        let check = tessera_codes_contract::device_number::check_character(ENGINEER_BODY)
            .expect("the engineer body is a well-formed number body");
        format!("{ENGINEER_BODY}{check}")
    }

    /// Builds the payload of the vector, exactly as a device builds one.
    fn produce() -> (SignedChallenge, String) {
        let params = FleetParams::defaults();
        let device = p256::SecretKey::from_slice(&DEVICE_SEED).unwrap();
        let ephemeral = p256::SecretKey::from_slice(&EPHEMERAL_SEED).unwrap();

        let challenge = Challenge::new(ChallengeFields {
            device_number: CheckedDeviceNumber::from_body("77-000123").unwrap(),
            epoch: Epoch::new(7),
            nonce: Nonce::parse(&"4".repeat(usize::from(params.nonce_width())), &params).unwrap(),
            role_id: "tester",
            level: Level::new(1),
            server_id: "op-e2e",
            engineer_id: &engineer_number(),
            ephemeral_point: EphemeralPublicPoint::new(
                ephemeral
                    .public_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec(),
            )
            .unwrap(),
        })
        .unwrap();

        // The signature the device makes: ECDSA over SHA-256 of the canonical
        // signing message, DER. The same call `codes-sign-challenge` makes, so
        // the vector cannot drift from the tool the stand uses.
        let key = p256::ecdsa::SigningKey::from(&device);
        let digest = Sha256::digest(challenge.signing_message().unwrap());
        let signature: p256::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
        let signed = SignedChallenge::new(
            challenge,
            Signature::new(signature.to_der().as_bytes().to_vec()).unwrap(),
        );

        // Собирает payload тот же вызов контракта, которым его собирает
        // устройство: строка, склеенная здесь руками, доказывала бы согласие
        // вектора с самим собой.
        let payload = signed.payload(Some(BASE_URL));
        (signed, payload)
    }

    /// The text file of the vector, as this code produces it.
    fn text_vector(signed: &SignedChallenge, payload: &str) -> String {
        format!(
            "# Golden-вектор QR-payload попытки, редакция 1.\n\
             #\n\
             # Порождён кодом устройства: подпись настоящая, ECDSA над SHA-256 канонического\n\
             # сообщения challenge, ключ — фиксированное зерно ниже. Файл переписывается только\n\
             # вместе с формой документа: он и есть то, что читает страница инженера.\n\
             #\n\
             # Форма: base_url \"#\" wire-форма подписанного challenge (contracts/codes/qr-payload).\n\
             # Поля попытки живут только во фрагменте — в HTTP-запросе за бандлом их нет.\n\
             device_seed_hex = {device_seed}\n\
             ephemeral_seed_hex = {ephemeral_seed}\n\
             base_url = {BASE_URL}\n\
             wire = {wire}\n\
             payload = {payload}\n\
             payload_len = {len}\n",
            device_seed = hex::encode(DEVICE_SEED),
            ephemeral_seed = hex::encode(EPHEMERAL_SEED),
            wire = signed.to_wire(),
            len = payload.len(),
        )
    }

    /// The field breakdown, for a reader that parses the payload.
    fn json_vector(signed: &SignedChallenge, payload: &str) -> String {
        let challenge = signed.challenge();
        let value = serde_json::json!({
            "base_url": BASE_URL,
            "fragment": signed.to_wire(),
            "prefix": SIGNED_CHALLENGE_PREFIX,
            "payload_len": payload.len(),
            "payload_budget": PAYLOAD_BUDGET,
            "engineer_number_rule": "organisation segment, serial part, ISO 7064 MOD 37,36 check character",
            "fields": {
                "device": challenge.device_number().as_str(),
                "epoch": challenge.epoch().get(),
                "nonce": challenge.nonce().as_str(),
                "role": challenge.role_id(),
                "level": challenge.level().get(),
                "server": challenge.server_id(),
                "engineer": challenge.engineer_id(),
                "ephemeral": hex::encode(challenge.ephemeral_point().as_bytes()),
                "signature": hex::encode(signed.signature().as_bytes()),
            },
            // The six fields of the MAC input, named here so a reader does not
            // have to infer which of the eight enter the code: the server and
            // the ephemeral point do not.
            "code_input": [
                "device", "epoch", "nonce", "role", "level", "engineer"
            ],
        });
        format!("{}\n", serde_json::to_string_pretty(&value).unwrap())
    }

    /// Записывает вектор на диск — служебный прогон для его первой сборки и
    /// для осознанного обновления после ломающего изменения формы.
    ///
    /// Под `#[ignore]`: обычный прогон ничего не переписывает, иначе тест выше
    /// сравнивал бы файл сам с собой и не значил бы ничего.
    #[test]
    #[ignore = "служебный: переписывает golden-вектор payload; запускать осознанно"]
    fn rewrite_the_payload_vector() {
        let (signed, payload) = produce();
        std::fs::write(
            golden_dir().join("qr-payload-v1.txt"),
            text_vector(&signed, &payload),
        )
        .unwrap();
        std::fs::write(
            golden_dir().join("qr-payload-v1.json"),
            json_vector(&signed, &payload),
        )
        .unwrap();
    }

    /// The committed vector is the one this code produces, byte for byte.
    ///
    /// Not "the vector parses" — a vector nobody produced parses just as well.
    /// This regenerates it and compares, so a change to the wire form, to the
    /// canonical bytes or to the signing message shows up here as a difference
    /// rather than in a page that stops reading QR codes.
    #[test]
    fn the_committed_payload_vector_is_the_one_this_code_produces() {
        let (signed, payload) = produce();

        for (name, produced) in [
            ("qr-payload-v1.txt", text_vector(&signed, &payload)),
            ("qr-payload-v1.json", json_vector(&signed, &payload)),
        ] {
            let path = golden_dir().join(name);
            let committed = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            assert_eq!(
                committed, produced,
                "вектор {name} разошёлся с тем, что порождает код; если форма менялась \
                 намеренно — это ломающее изменение контракта, а не правка файла"
            );
        }
    }

    /// The payload reads back into the challenge it was built from.
    ///
    /// The other half of the vector's promise: the fragment is not decoration
    /// beside the fields, it *is* the document, and a reader that splits on `#`
    /// gets it whole.
    #[test]
    fn the_payload_reads_back_into_the_same_challenge() {
        let (signed, payload) = produce();
        let (base, fragment) = payload.split_once('#').unwrap();
        assert_eq!(base, BASE_URL);
        assert_eq!(
            SignedChallenge::parse(fragment, &FleetParams::defaults()),
            Ok(signed)
        );
        // Никакого процентного кодирования поверх: устройство его не применяет,
        // и страница, которая бы его ждала, разобрала бы не те байты.
        assert!(!fragment.contains('%'));
    }

    /// The vector stays inside the budget the contract states.
    #[test]
    fn the_payload_of_an_ordinary_attempt_fits_the_budget() {
        let (_, payload) = produce();
        assert!(
            payload.len() <= PAYLOAD_BUDGET,
            "payload {} байт при бюджете {PAYLOAD_BUDGET}",
            payload.len()
        );
    }
}
