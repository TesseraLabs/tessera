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

use crate::cli::CodesSignChallengeArgs;

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

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "упавший шаг подготовки теста обязан ронять тест на месте"
)]
mod tests {
    use super::signed_wire;
    use crate::cli::CodesSignChallengeArgs;
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
    }
}
