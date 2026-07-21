//! Operator-surface localization for the issuer (Russian and English).
//!
//! The issuer's operator surfaces — the confirmation summary shown in
//! pinentry/the terminal, the `issuer serve` messages, and the CLI's own output
//! — are localized to Russian and English through a small in-crate string table.
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
//! value into rendering and confirmation. The core never reads the environment
//! on its own — a [`Locale`] is always passed in.

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
    /// The user-binding field label (the allowed role accounts).
    Users,
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
            Caption::Users => "role accounts",
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
            Caption::Users => "ролевые УЗ",
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
/// the operator-facing surfaces (`serve`, the CLI) consume these, so the table
/// is compiled only when one of them is built.
#[cfg(any(feature = "cli", feature = "serve"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Msg {
    /// `issuer serve`: bind announcement (an `http://…` address follows).
    ServeListening,
    /// `issuer serve`: the session token follows.
    ServeSessionToken,
    /// `issuer serve`: how to stop the foreground agent (full line).
    ServeStopHint,
    /// `issuer serve`: the browser could not be opened automatically (full line).
    ServeBrowserOpenFailed,
    /// `issuer serve`: a TBS that could not be shown was refused (full line).
    ServeUnreadableTbs,
    /// `issuer serve`: the operator declined (a kind and subject follow).
    ServeOperatorDeclined,
    /// `issuer serve`: the confirmation channel failed (an error follows).
    ServeConfirmChannelFailed,
    /// `issuer serve`: pinentry unavailable, terminal used (an error follows).
    ServePinentryFellBack,
    /// Placeholder page served at `/` with no cabinet attached: heading (full
    /// line).
    CabinetNotConnectedTitle,
    /// Placeholder page served at `/` with no cabinet attached: body text (full
    /// line).
    CabinetNotConnectedBody,
    /// Terminal confirmation dialog header (full line).
    ConfirmHeader,
    /// Terminal confirmation prompt (full line).
    ConfirmPrompt,
    /// CLI: a certificate was written (a path follows).
    CliCertWritten,
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
}

#[cfg(any(feature = "cli", feature = "serve"))]
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
            Msg::ServeListening => "issuer serve: listening on",
            Msg::ServeSessionToken => "issuer serve: session token:",
            Msg::ServeStopHint => "Press Ctrl+C to stop the agent",
            Msg::ServeBrowserOpenFailed => {
                "issuer serve: could not open a browser; open the address above manually"
            }
            Msg::ServeUnreadableTbs => {
                "issuer serve: rejected sign — TBS is not a readable issuance operation"
            }
            Msg::ServeOperatorDeclined => "issuer serve: operator declined:",
            Msg::ServeConfirmChannelFailed => "issuer serve: confirmation channel failed:",
            Msg::ServePinentryFellBack => {
                "issuer serve: pinentry unavailable, using terminal prompt:"
            }
            Msg::CabinetNotConnectedTitle => "Cabinet not connected",
            Msg::CabinetNotConnectedBody => {
                "Restart issuer serve with --cabinet-dir <path> to serve the issuance \
                 cabinet from a static bundle. The signing bridge is running."
            }
            Msg::ConfirmHeader => "=== Confirm issuance operation ===",
            Msg::ConfirmPrompt => "Sign this operation? [y/N]:",
            Msg::CliCertWritten => "certificate written to",
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
        }
    }

    /// The Russian message.
    fn ru(self) -> &'static str {
        match self {
            Msg::ServeListening => "issuer serve: приём на",
            Msg::ServeSessionToken => "issuer serve: токен сессии:",
            Msg::ServeStopHint => "Остановка агента: Ctrl+C",
            Msg::ServeBrowserOpenFailed => {
                "issuer serve: не удалось открыть браузер; откройте адрес выше вручную"
            }
            Msg::ServeUnreadableTbs => {
                "issuer serve: подпись отклонена — TBS не читается как операция выпуска"
            }
            Msg::ServeOperatorDeclined => "issuer serve: оператор отклонил:",
            Msg::ServeConfirmChannelFailed => "issuer serve: канал подтверждения недоступен:",
            Msg::ServePinentryFellBack => {
                "issuer serve: pinentry недоступен, используется терминал:"
            }
            Msg::CabinetNotConnectedTitle => "Кабинет не подключён",
            Msg::CabinetNotConnectedBody => {
                "Перезапустите issuer serve с --cabinet-dir <путь>, чтобы раздавать кабинет \
                 выпуска из статического бандла. Мост подписи уже работает."
            }
            Msg::ConfirmHeader => "=== Подтверждение операции выпуска ===",
            Msg::ConfirmPrompt => "Подписать эту операцию? [y/N]:",
            Msg::CliCertWritten => "сертификат записан в",
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
