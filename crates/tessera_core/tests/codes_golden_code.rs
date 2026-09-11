//! Код фикстурной попытки сверяется с числом, посчитанным не этим кодом.
//!
//! Сквозной тест канала сравнивает код устройства с кодом выдающей стороны, и
//! это сравнение слабее, чем выглядит: обе стороны зовут `derive_key` и
//! `compute_code` одного открытого ядра. Ошибка внутри примитива согласованно
//! не заметится ни одной из них — две реализации, выведенные из одного кода,
//! ошибаются одинаково.
//!
//! Поэтому ожидаемый код посчитан снаружи: `tools/codes-golden-code.py` делает
//! ECDH внешним `openssl pkeyutl -derive`, а HKDF, HMAC, каноническую упаковку
//! и несмещённое усечение пишет по описанию формата, а не переводом из Rust.
//! Его ответ заморожен в `code-vector-expected.txt`, и генератор комплекта этот
//! файл не пишет.
//!
//! Что покраснеет, если тронуть формат: соль вывода ключа, порядок или рамки
//! канонических полей, ширина целых, алфавит, длина кода, состав контекста
//! вывода. Всё это молча меняет код, и молча — ровно то слово, которое здесь
//! недопустимо: заметит расхождение парк, у которого перестанут сходиться коды.
//! Проверено мутациями: смена соли и перестановка двух канонических полей
//! роняют этот тест.
//!
//! Чего вектор НЕ покрывает, и это не оплошность. Отбраковку смещённой выборки
//! при усечении он проверить не может, и никакой вектор не может: при алфавите
//! Crockford base32 число кодов — степень двойки (32⁶ = 2³⁰), она делит
//! пространство выборки нацело, и отбраковывать нечего. Ветка отбраковки живёт
//! только в десятичном алфавите, где и там срабатывает с вероятностью порядка
//! 10⁻¹¹ на выборку. Её держат юнит-тесты `accept_sample`, а не этот вектор;
//! назвать это прямо честнее, чем добавить второй вектор, который зеленел бы,
//! не заходя в проверяемую ветку.

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "a test that cannot read its own fixture should fail on the spot"
)]

use std::path::{Path, PathBuf};

use openssl::pkey::PKey;

use tessera_codes_contract::canon::{CodeInput, Level};
use tessera_codes_contract::code::compute_code;
use tessera_codes_contract::device_number::CheckedDeviceNumber;
use tessera_codes_contract::key::{derive_key, Epoch, KeyAgreement, KeyContext};
use tessera_codes_contract::params::{FleetParams, FleetParamsInput};
use tessera_codes_contract::profile::AlgorithmProfile;
use tessera_codes_contract::ticket::SignedTicket;
use tessera_core::codes::agreement::StaticKeyAgreement;

/// Каталог комплекта стенда.
fn bundle() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codes/stand")
}

/// Читает `ключ=значение` из файла входов вектора.
fn inputs() -> Vec<(String, String)> {
    let text = std::fs::read_to_string(bundle().join("code-vector-inputs.txt"))
        .expect("входы вектора кода лежат в комплекте стенда");
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            line.split_once('=')
                .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        })
        .collect()
}

fn value(pairs: &[(String, String)], key: &str) -> String {
    let Some((_, found)) = pairs.iter().find(|(name, _)| name == key) else {
        panic!("во входах вектора нет поля {key}")
    };
    found.clone()
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(
        text.len().is_multiple_of(2),
        "нечётная длина шестнадцатеричной строки"
    );
    (0..text.len() / 2)
        .map(|index| {
            let byte = text
                .get(index * 2..index * 2 + 2)
                .expect("срез внутри строки чётной длины");
            u8::from_str_radix(byte, 16).expect("шестнадцатеричный байт")
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ignored = write!(text, "{byte:02x}");
        text
    })
}

#[test]
fn the_code_of_the_fixture_attempt_is_the_number_an_outside_tool_computed() {
    let pairs = inputs();

    // Билет разбирается и хешируется продуктом, а не берётся из входов на веру:
    // иначе вектор проверял бы вывод ключа и молчал о том, что в контекст
    // попадает не тот билет.
    let ticket_wire = std::fs::read_to_string(bundle().join("code-vector-ticket.txt"))
        .expect("билет вектора лежит в комплекте стенда");
    let ticket = SignedTicket::parse(ticket_wire.trim()).expect("билет вектора разбирается");
    let ticket_hash = ticket.context_hash().expect("хеш билета");
    assert_eq!(
        hex(ticket_hash.as_bytes()),
        value(&pairs, "ticket_hash_sha256"),
        "хеш билета разошёлся с тем, на котором посчитан вектор"
    );

    // ECDH тем же путём, которым его делает выдающая сторона.
    let agreement_pem =
        std::fs::read(bundle().join("agreement-key.pem")).expect("ключ согласования");
    let agreement =
        PKey::private_key_from_pem(&agreement_pem).expect("ключ согласования разбирается");
    let ephemeral_point = unhex(&value(&pairs, "ephemeral_public_sec1"));
    let shared = StaticKeyAgreement::new(&agreement, AlgorithmProfile::P256)
        .expect("профиль ключа согласования")
        .agree(&ephemeral_point)
        .expect("общий секрет");

    let device = CheckedDeviceNumber::parse(&value(&pairs, "device_number_significant"))
        .expect("номер устройства вектора");
    let key = derive_key(&shared, &KeyContext::new(&device, ticket_hash)).expect("вывод ключа");

    let engineer_id = value(&pairs, "engineer_id");
    let nonce = value(&pairs, "nonce");
    let role_id = value(&pairs, "role_id");
    let input = CodeInput {
        device_number: &device,
        role_id: &role_id,
        nonce: &nonce,
        level: Level::new(value(&pairs, "level").parse().expect("уровень")),
        epoch: Epoch::new(value(&pairs, "epoch").parse().expect("эпоха")),
        engineer_id: &engineer_id,
    };

    let params = FleetParams::parse(FleetParamsInput::defaults()).expect("параметры парка");
    // Входы объявляют те же параметры, что и умолчания контракта. Если умолчания
    // сдвинутся, вектор обязан покраснеть здесь, с названной причиной, а не на
    // сравнении кода, где причина выглядела бы как ошибка арифметики.
    assert_eq!(
        params.code_len().to_string(),
        value(&pairs, "code_len"),
        "длина кода в параметрах разошлась с длиной, на которой посчитан вектор"
    );

    let code = compute_code(&key, &input, &params).expect("код попытки");
    let expected = std::fs::read_to_string(bundle().join("code-vector-expected.txt"))
        .expect("ожидаемый код лежит в комплекте стенда");
    assert_eq!(
        code.as_str(),
        expected.trim(),
        "код разошёлся с числом, посчитанным сторонним инструментом; \
         пересчитать: python3 tools/codes-golden-code.py crates/tessera_core/tests/fixtures/codes/stand"
    );
}
