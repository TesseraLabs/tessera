//! Operator-surface localization for the issuer (Russian and English).
//!
//! The issuer's operator surfaces — the operation summary rendered from a TBS
//! and the CLI's own output — are localized to Russian and English through a
//! small in-crate string table.
//! There is no `fluent`/`gettext`: for two locales and a few dozen strings a
//! table keyed by an enum is smaller and has no runtime or build machinery.
//!
//! Only *captions* are translated; the data beside them never is. Technical
//! identifiers (a `role_id`, an OID, an RFC 4514 subject, a protocol field name,
//! a serial, a timestamp) are the same bytes in every locale, so a Russian
//! summary differs from an English one only in its field labels.
//!
//! The locale is resolved once, at the start of the binary, from an explicit
//! setting then the environment ([`Locale::resolve`]); it is then threaded by
//! value into rendering. The core never reads the environment on its own — a
//! [`Locale`] is always passed in.

/// A supported operator-surface locale.
///
/// English is the fallback used whenever no configured or environment locale is
/// recognized, so an unknown `LANG` never blocks or garbles an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Locale {
    /// English — the default and fallback.
    #[default]
    En,
    /// Russian.
    Ru,
}

impl Locale {
    /// Resolves the operator locale from, in order, an explicit setting (a
    /// config value or `--lang` flag), then `TESSERA_ISSUER_LANG`, then `LANG`;
    /// the first source that names a recognized locale wins, and an unrecognized
    /// value simply falls through. When none matches, [`Locale::En`] is used.
    ///
    /// A tag matches by prefix: any value beginning `ru` selects Russian and any
    /// beginning `en` selects English (case-insensitive), so `ru_RU.UTF-8` and
    /// `en_GB` both resolve.
    #[must_use]
    pub fn resolve(explicit: Option<&str>) -> Self {
        Self::resolve_from(
            explicit,
            std::env::var("TESSERA_ISSUER_LANG").ok().as_deref(),
            std::env::var("LANG").ok().as_deref(),
        )
    }

    /// Resolves the locale from the environment alone
    /// (`TESSERA_ISSUER_LANG`, then `LANG`, then the [`Locale::En`] fallback).
    #[must_use]
    pub fn from_env() -> Self {
        Self::resolve(None)
    }

    /// The pure precedence used by [`Locale::resolve`], with the two environment
    /// values passed in so it can be exercised without touching process state.
    fn resolve_from(explicit: Option<&str>, issuer_lang: Option<&str>, lang: Option<&str>) -> Self {
        explicit
            .and_then(Self::from_tag)
            .or_else(|| issuer_lang.and_then(Self::from_tag))
            .or_else(|| lang.and_then(Self::from_tag))
            .unwrap_or(Locale::En)
    }

    /// Maps a locale tag to a [`Locale`] by case-insensitive language prefix.
    fn from_tag(tag: &str) -> Option<Self> {
        let lower = tag.trim().to_ascii_lowercase();
        if lower.starts_with("ru") {
            Some(Locale::Ru)
        } else if lower.starts_with("en") {
            Some(Locale::En)
        } else {
            None
        }
    }
}

/// A caption in an operation summary: a field label or an operation-kind name.
///
/// The datum shown beside a caption (a subject, a role list, a timestamp, a
/// `crlNumber`) is technical and identical in every locale; only the caption is
/// translated. `crlNumber` is an X.509 field name and so is left untranslated on
/// purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caption {
    /// The "operation" field label.
    Operation,
    /// The "subject" field label.
    Subject,
    /// The "validity" field label.
    Validity,
    /// The allowed-roles field label.
    Roles,
    /// The envelope maximum-integrity-level field label.
    MaxLevel,
    /// The envelope maximum-TTL field label.
    MaxTtl,
    /// The envelope required-tags field label.
    RequiredTags,
    /// The host-binding field label.
    Hosts,
    /// The leaf integrity-ceiling field label.
    Integrity,
    /// The profile-version field label.
    Profile,
    /// The `crlNumber` field label (an X.509 field name, left untranslated).
    CrlNumber,
    /// The operation-kind name for an engineer shift-leaf.
    KindShiftLeaf,
    /// The operation-kind name for an organisation CA.
    KindOrgCa,
    /// The operation-kind name for a certificate revocation list.
    KindCrl,
    /// The operation-kind name for an exported device registry.
    KindDeviceRegistry,
    /// The signing-key label field.
    Key,
    /// The payload-digest field (a SHA-256 of the signed bytes).
    Digest,
    /// The payload-size field.
    Size,
}

impl Caption {
    /// The caption's text in `locale`.
    #[must_use]
    pub fn text(self, locale: Locale) -> &'static str {
        match locale {
            Locale::En => self.en(),
            Locale::Ru => self.ru(),
        }
    }

    /// The English caption.
    fn en(self) -> &'static str {
        match self {
            Caption::Operation => "operation",
            Caption::Subject => "subject",
            Caption::Validity => "validity",
            Caption::Roles => "roles",
            Caption::MaxLevel => "max level",
            Caption::MaxTtl => "max TTL",
            Caption::RequiredTags => "required tags",
            Caption::Hosts => "hosts",
            Caption::Integrity => "integrity",
            Caption::Profile => "profile",
            Caption::CrlNumber => "crlNumber",
            Caption::KindShiftLeaf => "shift-leaf certificate",
            Caption::KindOrgCa => "organisation CA certificate",
            Caption::KindCrl => "certificate revocation list",
            Caption::KindDeviceRegistry => "device registry",
            Caption::Key => "key",
            Caption::Digest => "digest",
            Caption::Size => "size",
        }
    }

    /// The Russian caption.
    fn ru(self) -> &'static str {
        match self {
            Caption::Operation => "операция",
            Caption::Subject => "субъект",
            Caption::Validity => "срок действия",
            Caption::Roles => "роли",
            Caption::MaxLevel => "макс. уровень",
            Caption::MaxTtl => "макс. TTL",
            Caption::RequiredTags => "требуемые метки",
            Caption::Hosts => "узлы",
            Caption::Integrity => "целостность",
            Caption::Profile => "профиль",
            // An X.509 field name — a technical identifier, not translated.
            Caption::CrlNumber => "crlNumber",
            Caption::KindShiftLeaf => "сертификат смены (лист)",
            Caption::KindOrgCa => "сертификат УЦ организации",
            Caption::KindCrl => "список отзыва (CRL)",
            Caption::KindDeviceRegistry => "реестр устройств",
            Caption::Key => "ключ",
            Caption::Digest => "дайджест",
            Caption::Size => "размер",
        }
    }
}

/// A localized operator/CLI message fragment.
///
/// Each variant is a caption; a caller appends the technical data (an address, a
/// path, an error, a subject) after it, so no data ever enters the table. Only
/// the CLI consumes these, so the table is compiled only when it is built.
#[cfg(feature = "cli")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Msg {
    /// CLI: a certificate was written (a path follows).
    CliCertWritten,
    /// CLI: a PKCS#12 container was written (a path follows).
    CliContainerWritten,
    /// CLI: the heading above a generated container password, warning that it
    /// is shown once and is not recoverable.
    CliContainerPassphraseHeading,
    /// CLI: a password was generated but there is no terminal to show it on.
    CliContainerPassphraseNoTerminal,
    /// CLI: the artifacts were laid out on a carrier (paths follow).
    CliCarrierWritten,
    /// CLI: the carrier already holds one of the artifacts; asks whether to
    /// replace it (a path follows).
    CliCarrierOverwriteAsk,
    /// CLI: the operator declined replacing an existing artifact (full line).
    CliCarrierOverwriteDeclined,
    /// CLI: an artifact would be replaced but nothing can ask the operator
    /// (a path follows).
    CliCarrierOverwriteNeedsConfirmation,
    /// CLI: a CRL was written (a path follows).
    CliCrlWritten,
    /// CLI: a CSR was written (a path follows).
    CliCsrWritten,
    /// CLI: the CSR's subject follows.
    CliCsrSubject,
    /// CLI: the CSR self-signature verified (full line).
    CliCsrSelfSigValid,
    /// CLI: the CSR self-signature did not verify (full line).
    CliCsrSelfSigInvalid,
    /// CLI: an issuance was refused (the core's error message follows).
    CliIssuanceRefused,
    /// CLI: the journal chain is intact and fully signed (full line).
    CliJournalIntact,
    /// CLI: the journal chain is intact with an unsigned tail (a seq follows).
    CliJournalUnsignedTail,
    /// CLI: the journal chain is broken (a position follows).
    CliJournalBroken,
    /// CLI: a usage error (a detail follows).
    CliUsage,
    /// CLI: a signing-backend error (a detail follows).
    CliBackendError,
    /// CLI: an I/O error (a detail follows).
    CliIoError,
    /// File backend: the CA key file is unencrypted (full-line warning printed
    /// once at startup, to stderr).
    FilePlaintextKeyWarning,
    /// Secret prompt caption for the PKCS#11 token PIN.
    SecretPromptTokenPin,
    /// Secret prompt caption for the PIN of the token a credential is being
    /// written to. Deliberately not the same caption as the CA token's PIN:
    /// the two are different devices with their own attempt counters.
    SecretPromptCarrierPin,
    /// Secret prompt caption for the file backend's CA key passphrase.
    SecretPromptKeyPassphrase,
    /// Secret prompt caption for the PKCS#12 container password.
    SecretPromptContainerPassphrase,
    /// Secret ladder: the value came from an environment variable (the variable
    /// name follows); printed to stderr.
    SecretEnvWarning,
    /// Secret ladder: no source produced a secret (the flags that would name one
    /// follow).
    SecretUnavailableFlags,
    /// Secret ladder: the sources needing no flag (a variable name follows).
    SecretUnavailableFallbacks,
    /// Secret ladder: the secret file is reachable beyond its owner (the path and
    /// mode follow).
    SecretFileBeyondOwner,
    /// Secret ladder: the secret file could not be read (a detail follows).
    SecretFileUnreadable,
    /// Secret ladder: this platform does not check file permissions, so the
    /// owner-only gate did not run (the path follows); printed to stderr.
    SecretFileUncheckedPlatform,
    /// CLI: a secret-source flag belongs to a backend other than the selected
    /// one (the flags and the backend follow).
    CliSecretFlagForeignBackend,
    /// Secret ladder: standard input could not be read (a detail follows).
    SecretStdinUnreadable,
    /// Secret ladder: the console prompt failed (a detail follows).
    SecretConsoleFailed,
    /// Secret ladder: the pinentry program returned nothing (its path follows).
    SecretPinentryFailed,
    /// Secret ladder: the source produced an empty value (its name follows).
    SecretEmpty,
    /// Secret ladder: the source produced no line break within the accepted
    /// length (the source and the bound follow).
    SecretTooLong,
    /// Codes: the heading above the code to read out (the grouped code follows).
    CodesCodeHeading,
    /// Codes: the receipt of the issuance was written (a path follows).
    CodesReceiptWritten,
    /// Codes: the command was refused (the refusal follows).
    ///
    /// Every command of the channel shares it, so the wording names no
    /// particular one: a reconciliation that refuses to produce a report is not
    /// an issuance that was turned away, and telling an auditor otherwise sends
    /// them looking for a code nobody asked for.
    CodesRefused,
    /// Codes: what the nonce counter said about the call (a token follows).
    /// Codes: how the operator key was held (a token follows).
    CodesKeyStorage,
    /// Codes: the site axis of the ticket was not checked (full-line warning).
    CodesSiteUndeclared,
    /// Codes: the second operator who approved an override (an identifier
    /// follows).
    /// Codes: the receipt is well formed and its name binds it to the ticket
    /// (full line).
    CodesReceiptValid,
    /// Codes: the receipt does not hold together (a detail follows).
    CodesReceiptInvalid,
    /// Codes: the ticket verified against the anchored authority (full line).
    CodesTicketVerified,
    /// Codes: no authority anchor was supplied, so the ticket was read
    /// unverified (full line).
    CodesTicketUnverified,
    /// Codes: the reconciliation found nothing (full line).
    CodesReconcileClean,
    /// Codes: the reconciliation ran without the device side (full line).
    CodesReconcileIncomplete,
}

#[cfg(feature = "cli")]
impl Msg {
    /// The message's text in `locale`.
    pub(crate) fn text(self, locale: Locale) -> &'static str {
        match locale {
            Locale::En => self.en(),
            Locale::Ru => self.ru(),
        }
    }

    /// The English message.
    fn en(self) -> &'static str {
        match self {
            Msg::CliCertWritten => "certificate written to",
            Msg::CliContainerWritten => "PKCS#12 container written to",
            Msg::CliContainerPassphraseHeading => {
                "container password — shown once, it cannot be recovered later; \
                 deliver it by a channel other than the container's:"
            }
            Msg::CliContainerPassphraseNoTerminal => {
                "a container password was generated but standard error is not a terminal; \
                 printing it would leave it in the captured output. Re-run naming a password \
                 source: --p12-passphrase-file <path>, --p12-passphrase-stdin, \
                 --p12-passphrase-prompt"
            }
            Msg::CliCarrierWritten => "carrier prepared:",
            Msg::CliCarrierOverwriteAsk => {
                "this file is already on the carrier and may belong to another engineer; \
                 replace it? [y/N]:"
            }
            Msg::CliCarrierOverwriteDeclined => "declined: the carrier was left as it was",
            Msg::CliCarrierOverwriteNeedsConfirmation => {
                "this file is already on the carrier and nothing can ask for confirmation here; \
                 re-run with --force once you have checked what it is:"
            }
            Msg::CliCrlWritten => "CRL written to",
            Msg::CliCsrWritten => "CSR written to",
            Msg::CliCsrSubject => "CSR subject:",
            Msg::CliCsrSelfSigValid => "CSR self-signature: valid",
            Msg::CliCsrSelfSigInvalid => "CSR self-signature: invalid",
            Msg::CliIssuanceRefused => "issuance refused:",
            Msg::CliJournalIntact => "journal: chain intact, tail fully signed",
            Msg::CliJournalUnsignedTail => "journal: chain intact, unsigned tail from seq",
            Msg::CliJournalBroken => "journal: chain BROKEN at position",
            Msg::CliUsage => "usage error:",
            Msg::CliBackendError => "backend error:",
            Msg::CliIoError => "I/O error:",
            Msg::FilePlaintextKeyWarning => {
                "warning: the CA key file is unencrypted; encrypt it \
                 (openssl pkcs8 -topk8) or use a PKCS#11/Vault backend in production"
            }
            Msg::SecretPromptTokenPin => "Tessera token PIN",
            Msg::SecretPromptCarrierPin => {
                "PIN of the Tessera carrier token receiving the credential"
            }
            Msg::SecretPromptKeyPassphrase => "Tessera CA key passphrase",
            Msg::SecretPromptContainerPassphrase => "Tessera credential container password",
            Msg::SecretEnvWarning => {
                "warning: the secret was read from an environment variable; its value is \
                 visible to child processes and lands in memory dumps —"
            }
            Msg::SecretUnavailableFlags => "no secret source available; pass one of",
            Msg::SecretUnavailableFallbacks => {
                "or provide a pinentry program on PATH, an interactive terminal, \
                 or the environment variable"
            }
            Msg::SecretFileBeyondOwner => {
                "the secret file is readable by group or others; restrict it to its owner \
                 (chmod 600):"
            }
            Msg::SecretFileUnreadable => "cannot read the secret file:",
            Msg::SecretFileUncheckedPlatform => {
                "warning: this platform does not check file permissions, so the secret file was \
                 accepted unchecked; keep it in a directory only its owner can enter —"
            }
            Msg::CliSecretFlagForeignBackend => {
                "this flag names a secret source for another backend and would be ignored:"
            }
            Msg::SecretStdinUnreadable => "cannot read the secret from standard input:",
            Msg::SecretConsoleFailed => "the console secret prompt failed:",
            Msg::SecretPinentryFailed => "the pinentry program returned no secret:",
            Msg::SecretEmpty => "the secret source returned an empty value:",
            Msg::SecretTooLong => {
                "the secret source gave no line break within the accepted length:"
            }
            Msg::CodesCodeHeading => "code to read out:",
            Msg::CodesReceiptWritten => "receipt written to",
            Msg::CodesRefused => "the command was refused:",
            Msg::CodesKeyStorage => "operator key held:",
            Msg::CodesSiteUndeclared => {
                "the site of the device was not declared, so the ticket's region and tags were \
                 not checked here; the device checks them itself before it accepts the code"
            }
            Msg::CodesReceiptValid => {
                "the receipt is well formed and its name binds it to the ticket"
            }
            Msg::CodesReceiptInvalid => "the receipt does not hold together:",
            Msg::CodesTicketVerified => "the ticket verified against the anchored authority",
            Msg::CodesTicketUnverified => {
                "no authority anchor was supplied: the fields below are what the document claims, \
                 not what anybody signed for"
            }
            Msg::CodesReconcileClean => "the two sides agree",
            Msg::CodesReconcileIncomplete => {
                "incomplete report: no device journal was supplied, so only the receipts were read"
            }
        }
    }

    /// The Russian message.
    fn ru(self) -> &'static str {
        match self {
            Msg::CliCertWritten => "сертификат записан в",
            Msg::CliContainerWritten => "контейнер PKCS#12 записан в",
            Msg::CliContainerPassphraseHeading => {
                "пароль контейнера — показан один раз, восстановить его позже нельзя; \
                 передайте его каналом, отличным от канала контейнера:"
            }
            Msg::CliContainerPassphraseNoTerminal => {
                "пароль контейнера порождён, но стандартный поток ошибок — не терминал; \
                 печать оставила бы пароль в перехваченном выводе. Повторите, назвав источник \
                 пароля: --p12-passphrase-file <путь>, --p12-passphrase-stdin, \
                 --p12-passphrase-prompt"
            }
            Msg::CliCarrierWritten => "носитель подготовлен:",
            Msg::CliCarrierOverwriteAsk => {
                "этот файл уже лежит на носителе, возможно от другого инженера; \
                 заменить его? [y/N]:"
            }
            Msg::CliCarrierOverwriteDeclined => "отменено: носитель оставлен как был",
            Msg::CliCarrierOverwriteNeedsConfirmation => {
                "этот файл уже лежит на носителе, а спросить подтверждение здесь не у кого; \
                 разберитесь, что это, и повторите с --force:"
            }
            Msg::CliCrlWritten => "CRL записан в",
            Msg::CliCsrWritten => "CSR записан в",
            Msg::CliCsrSubject => "субъект CSR:",
            Msg::CliCsrSelfSigValid => "самоподпись CSR: верна",
            Msg::CliCsrSelfSigInvalid => "самоподпись CSR: неверна",
            Msg::CliIssuanceRefused => "выпуск отклонён:",
            Msg::CliJournalIntact => "журнал: цепочка цела, хвост полностью подписан",
            Msg::CliJournalUnsignedTail => "журнал: цепочка цела, неподписанный хвост с seq",
            Msg::CliJournalBroken => "журнал: цепочка НАРУШЕНА в позиции",
            Msg::CliUsage => "ошибка вызова:",
            Msg::CliBackendError => "ошибка бэкенда:",
            Msg::CliIoError => "ошибка ввода-вывода:",
            Msg::FilePlaintextKeyWarning => {
                "предупреждение: файл ключа УЦ не зашифрован; зашифруйте его \
                 (openssl pkcs8 -topk8) или используйте бэкенд PKCS#11/Vault в проде"
            }
            Msg::SecretPromptTokenPin => "PIN токена Tessera",
            Msg::SecretPromptCarrierPin => {
                "PIN токена-носителя Tessera, на который пишется удостоверение"
            }
            Msg::SecretPromptKeyPassphrase => "пароль ключа УЦ Tessera",
            Msg::SecretPromptContainerPassphrase => "пароль контейнера удостоверения Tessera",
            Msg::SecretEnvWarning => {
                "предупреждение: секрет прочитан из переменной окружения; её значение \
                 видно дочерним процессам и попадает в дампы памяти —"
            }
            Msg::SecretUnavailableFlags => "нет доступного источника секрета; задайте один из",
            Msg::SecretUnavailableFallbacks => {
                "либо обеспечьте программу pinentry на PATH, интерактивный терминал \
                 или переменную окружения"
            }
            Msg::SecretFileBeyondOwner => {
                "файл секрета доступен на чтение группе или остальным; ограничьте доступ \
                 владельцем (chmod 600):"
            }
            Msg::SecretFileUnreadable => "не удалось прочитать файл секрета:",
            Msg::SecretFileUncheckedPlatform => {
                "предупреждение: на этой платформе права файла не проверяются, файл секрета принят \
                 без проверки; держите его в каталоге, доступном только владельцу —"
            }
            Msg::CliSecretFlagForeignBackend => {
                "этот флаг задаёт источник секрета для другого бэкенда и был бы проигнорирован:"
            }
            Msg::SecretStdinUnreadable => "не удалось прочитать секрет со стандартного ввода:",
            Msg::SecretConsoleFailed => "не удалось запросить секрет в консоли:",
            Msg::SecretPinentryFailed => "программа pinentry не вернула секрет:",
            Msg::SecretEmpty => "источник секрета вернул пустое значение:",
            Msg::SecretTooLong => {
                "источник секрета не дал перевода строки в пределах допустимой длины:"
            }
            Msg::CodesCodeHeading => "код для диктовки:",
            Msg::CodesReceiptWritten => "квитанция записана в",
            Msg::CodesRefused => "команда отклонена:",
            Msg::CodesKeyStorage => "ключ оператора хранится:",
            Msg::CodesSiteUndeclared => {
                "место устройства не названо, поэтому регион и метки билета здесь не проверялись; \
                 устройство проверяет их само, прежде чем принять код"
            }
            Msg::CodesReceiptValid => "квитанция целостна, имя файла связывает её с билетом",
            Msg::CodesReceiptInvalid => "квитанция не сходится:",
            Msg::CodesTicketVerified => "билет проверен по якорю удостоверяющей стороны",
            Msg::CodesTicketUnverified => {
                "якорь удостоверяющей стороны не задан: ниже то, что документ о себе заявляет, \
                 а не то, за что кто-либо подписался"
            }
            Msg::CodesReconcileClean => "стороны сходятся",
            Msg::CodesReconcileIncomplete => {
                "отчёт неполон: журналы устройств не заданы, прочитаны только квитанции"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_tag_is_none_known_tags_map_by_prefix() {
        assert_eq!(Locale::from_tag("ru_RU.UTF-8"), Some(Locale::Ru));
        assert_eq!(Locale::from_tag("RU"), Some(Locale::Ru));
        assert_eq!(Locale::from_tag("en_GB"), Some(Locale::En));
        assert_eq!(Locale::from_tag("de_DE"), None);
        assert_eq!(Locale::from_tag(""), None);
    }

    #[test]
    fn explicit_known_setting_short_circuits_the_environment() {
        // A recognized explicit tag wins before any environment variable is
        // consulted, so this holds whatever `LANG` happens to be in CI.
        assert_eq!(Locale::resolve(Some("ru")), Locale::Ru);
        assert_eq!(Locale::resolve(Some("en_US.UTF-8")), Locale::En);
    }

    /// Environment precedence: `TESSERA_ISSUER_LANG` outranks `LANG`, an
    /// unrecognized value falls through, and nothing recognized yields English.
    ///
    /// The precedence is tested through the pure `resolve_from` so no process
    /// environment is mutated (and no other test can be raced).
    #[test]
    fn environment_precedence_issuer_lang_then_lang_then_fallback() {
        // TESSERA_ISSUER_LANG outranks a conflicting LANG.
        assert_eq!(
            Locale::resolve_from(None, Some("ru_RU.UTF-8"), Some("en_US.UTF-8")),
            Locale::Ru
        );
        // An unrecognized TESSERA_ISSUER_LANG falls through to LANG.
        assert_eq!(
            Locale::resolve_from(None, Some("xx"), Some("ru_RU.UTF-8")),
            Locale::Ru
        );
        // Nothing recognized anywhere resolves to the English fallback.
        assert_eq!(
            Locale::resolve_from(None, Some("xx"), Some("de_DE.UTF-8")),
            Locale::En
        );
        // A recognized explicit setting wins over both environment values.
        assert_eq!(
            Locale::resolve_from(Some("en"), Some("ru"), Some("ru")),
            Locale::En
        );
    }

    #[test]
    fn captions_differ_by_locale_but_crl_number_is_technical() {
        assert_eq!(Caption::Roles.text(Locale::En), "roles");
        assert_eq!(Caption::Roles.text(Locale::Ru), "роли");
        // An X.509 field name is identical in both locales.
        assert_eq!(
            Caption::CrlNumber.text(Locale::En),
            Caption::CrlNumber.text(Locale::Ru)
        );
    }
}
