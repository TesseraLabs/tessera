//! Вычистка секретов из всего, что раннер пишет на диск или печатает.
//!
//! Разрешённые значения `op://` живут в памяти и подставляются в шаги, но в
//! `report.json`, `report.md`, артефакты и консоль попадать не должны. Ловим их
//! на единственном выходе: любой текст, уезжающий из процесса, проходит через
//! [`Redactor`].

use zeroize::Zeroize as _;

/// Замена, которой подменяются секреты.
pub const MASK: &str = "«секрет»";

/// Подменяет известные секретные значения в произвольном тексте.
#[derive(Debug, Default, Clone)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    /// Собирает редактор из набора секретных значений.
    ///
    /// Пустые и односимвольные значения игнорируются: они дали бы шум на любой
    /// строке отчёта, не добавив защиты.
    #[must_use]
    pub fn new(values: Vec<String>) -> Self {
        let mut secrets: Vec<String> = values.into_iter().filter(|v| v.len() > 1).collect();
        // Длинные значения заменяем первыми, иначе замена короткого могла бы
        // разрезать длинное и оставить его хвост в тексте.
        secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
        Self { secrets }
    }

    /// Возвращает текст, в котором секреты заменены на [`MASK`].
    #[must_use]
    pub fn apply(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for secret in &self.secrets {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), MASK);
            }
        }
        out
    }

    /// Есть ли что вычищать.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }
}

impl Drop for Redactor {
    fn drop(&mut self) {
        for secret in &mut self.secrets {
            secret.zeroize();
        }
    }
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

    #[test]
    fn replaces_known_secrets_everywhere_in_text() {
        let redactor = Redactor::new(vec!["123456".to_owned()]);
        assert_eq!(
            redactor.apply("PIN=123456 (повтор 123456)"),
            format!("PIN={MASK} (повтор {MASK})")
        );
    }

    #[test]
    fn longer_secrets_are_replaced_first() {
        let redactor = Redactor::new(vec!["12".to_owned(), "123456".to_owned()]);
        assert_eq!(redactor.apply("123456"), MASK);
    }

    #[test]
    fn short_and_empty_values_are_ignored() {
        let redactor = Redactor::new(vec![String::new(), "a".to_owned()]);
        assert!(redactor.is_empty());
        assert_eq!(redactor.apply("aaa"), "aaa");
    }
}
