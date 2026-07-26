//! Переменные прогона и подстановка `{{…}}` в шаги реестра.
//!
//! Переменная — либо открытое значение (адрес, имя пользователя, путь к
//! фикстурам), либо секрет. Секрет живёт в [`secrecy::SecretString`] и наружу
//! отдаётся только в аргумент шага; в отчёты, логи и артефакты попадает уже
//! отредактированный текст (см. [`crate::redact`]).

use std::collections::BTreeMap;

use secrecy::{ExposeSecret as _, SecretString};

/// Ошибка подстановки.
#[derive(Debug, thiserror::Error)]
pub enum VarError {
    /// В шаблоне встретилась переменная, которой нет ни в профиле, ни в стенде.
    #[error("переменная {{{{{name}}}}} не определена ни в профиле, ни в stand.toml")]
    Unknown {
        /// Имя переменной.
        name: String,
    },
}

/// Значение переменной.
#[derive(Debug, Clone)]
pub enum VarValue {
    /// Открытое значение: его не стыдно печатать в отчёт.
    Plain(String),
    /// Секрет: подставляется в шаг, но вычищается из всего, что пишется на диск.
    Secret(SecretString),
}

impl VarValue {
    fn as_str(&self) -> &str {
        match self {
            Self::Plain(value) => value.as_str(),
            Self::Secret(value) => value.expose_secret(),
        }
    }
}

/// Набор переменных прогона.
#[derive(Debug, Clone, Default)]
pub struct Vars {
    entries: BTreeMap<String, VarValue>,
}

impl Vars {
    /// Пустой набор.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Добавляет или заменяет открытое значение.
    pub fn insert_plain(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.entries
            .insert(name.into(), VarValue::Plain(value.into()));
    }

    /// Добавляет или заменяет секрет.
    pub fn insert_secret(&mut self, name: impl Into<String>, value: SecretString) {
        self.entries.insert(name.into(), VarValue::Secret(value));
    }

    /// Вливает другой набор поверх этого: совпадающие имена заменяются.
    pub fn absorb(&mut self, other: Self) {
        self.entries.extend(other.entries);
    }

    /// Открытое значение переменной.
    ///
    /// Секреты не отдаёт: путь или имя каталога секретом быть не может, а вот
    /// утечь через такой доступ — вполне.
    #[must_use]
    pub fn plain(&self, name: &str) -> Option<&str> {
        match self.entries.get(name) {
            Some(VarValue::Plain(value)) => Some(value.as_str()),
            Some(VarValue::Secret(_)) | None => None,
        }
    }

    /// Имена переменных, чьи значения секретны.
    #[must_use]
    pub fn secret_names(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(_, value)| matches!(value, VarValue::Secret(_)))
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Секретные значения — исключительно для построения редактора вывода.
    #[must_use]
    pub fn secret_values(&self) -> Vec<String> {
        self.entries
            .values()
            .filter_map(|value| match value {
                VarValue::Secret(secret) => Some(secret.expose_secret().to_owned()),
                VarValue::Plain(_) => None,
            })
            .collect()
    }

    /// Подставляет значения переменных в шаблон.
    ///
    /// # Ошибки
    ///
    /// [`VarError::Unknown`], если в шаблоне есть неопределённая переменная:
    /// молча подставить пустую строку нельзя — шаг выполнился бы не над тем,
    /// над чем задумано, и провал выглядел бы как дефект продукта.
    pub fn substitute(&self, template: &str) -> Result<String, VarError> {
        // Разбор написан руками, а не регуляркой: подстановка — самый горячий
        // путь раннера по числу вызовов, и обойтись без статического шаблона
        // здесь дешевле, чем городить его инициализацию.
        let mut out = String::with_capacity(template.len());
        let mut rest = template;
        while let Some(open) = rest.find("{{") {
            let (before, from_open) = rest.split_at(open);
            out.push_str(before);
            let Some(inner_start) = from_open.get(2..) else {
                break;
            };
            let Some(close) = inner_start.find("}}") else {
                // Незакрытая скобка — не подстановка, а просто текст.
                out.push_str(from_open);
                return Ok(out);
            };
            let Some(name) = inner_start.get(..close) else {
                break;
            };
            let trimmed = name.trim();
            if trimmed.is_empty() || !is_var_name(trimmed) {
                out.push_str("{{");
                rest = inner_start;
                continue;
            }
            let value = self.entries.get(trimmed).ok_or_else(|| VarError::Unknown {
                name: trimmed.to_owned(),
            })?;
            out.push_str(value.as_str());
            rest = inner_start.get(close + 2..).unwrap_or("");
        }
        out.push_str(rest);
        Ok(out)
    }

    /// Подставляет значения в необязательный шаблон.
    ///
    /// # Ошибки
    ///
    /// См. [`Vars::substitute`].
    pub fn substitute_opt(&self, template: Option<&str>) -> Result<Option<String>, VarError> {
        template.map(|text| self.substitute(text)).transpose()
    }
}

fn is_var_name(text: &str) -> bool {
    text.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
}

#[cfg(test)]
// Тестам разрешено падать на нарушенных инвариантах: это и есть их способ
// сообщить о проблеме.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn vars() -> Vars {
        let mut vars = Vars::new();
        vars.insert_plain("user", "tester");
        vars.insert_plain("fixtures", "/opt/e2e/fixtures");
        vars.insert_secret("pin", SecretString::from("123456".to_owned()));
        vars
    }

    #[test]
    fn substitutes_plain_and_secret_values() {
        let vars = vars();
        assert_eq!(
            vars.substitute("pam-drive certauth {{user}} authenticate")
                .unwrap(),
            "pam-drive certauth tester authenticate"
        );
        assert_eq!(vars.substitute("{{pin}}").unwrap(), "123456");
        assert_eq!(
            vars.substitute("{{ fixtures }}/leaf.p12").unwrap(),
            "/opt/e2e/fixtures/leaf.p12"
        );
    }

    #[test]
    fn unknown_variable_is_an_error() {
        let err = vars().substitute("{{nope}}").unwrap_err();
        assert!(err.to_string().contains("nope"), "{err}");
    }

    #[test]
    fn text_without_placeholders_passes_through() {
        assert_eq!(
            vars().substitute("systemctl status tessera").unwrap(),
            "systemctl status tessera"
        );
        assert_eq!(vars().substitute("").unwrap(), "");
    }

    #[test]
    fn braces_that_are_not_placeholders_are_left_alone() {
        assert_eq!(
            vars().substitute("awk '{ print $1 }'").unwrap(),
            "awk '{ print $1 }'"
        );
    }

    #[test]
    fn secret_names_and_values_are_separated_from_plain_ones() {
        let vars = vars();
        assert_eq!(vars.secret_names(), vec!["pin"]);
        assert_eq!(vars.secret_values(), vec!["123456".to_owned()]);
        // Открытое значение доступно по имени, секретное — нет.
        assert_eq!(vars.plain("user"), Some("tester"));
        assert_eq!(vars.plain("pin"), None);
        assert_eq!(vars.plain("нет-такой"), None);
    }
}
