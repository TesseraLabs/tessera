//! Происхождение проверенного пакета.
//!
//! Коммит рабочего дерева за коммит артефакта не выдаётся: версия пакета не
//! уникальна по коммиту, и `stand.toml`, годами указывающий на старый файл,
//! иначе приписал бы успех непроверенному коду. Если коммит подтвердить нечем,
//! прогон честно помечается как проведённый с неустановленным провенансом.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Сколько байт читаем за раз при подсчёте контрольной суммы.
const CHUNK: usize = 64 * 1024;

/// Ошибка установления провенанса.
#[derive(Debug, thiserror::Error)]
pub enum ProvenanceError {
    /// Пакета нет.
    #[error("проверяемый пакет {path} не найден")]
    Missing {
        /// Путь.
        path: PathBuf,
    },
    /// Пакет не прочитать.
    #[error("не прочитать {path}: {source}")]
    Read {
        /// Путь.
        path: PathBuf,
        /// Причина.
        source: std::io::Error,
    },
}

/// Происхождение `.deb`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    /// Путь к пакету.
    pub path: PathBuf,
    /// Контрольная сумма файла.
    pub sha256: String,
    /// Размер в байтах.
    pub size: u64,
    /// Источник: локальный путь либо идентификатор прогона `build.yml`.
    pub source: String,
    /// Коммит, из которого собран артефакт, если его есть чем подтвердить.
    pub commit: Option<String>,
}

impl Provenance {
    /// Установлен ли провенанс.
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.commit.is_some()
    }

    /// Короткая форма коммита для имени каталога прогона.
    #[must_use]
    pub fn short_commit(&self) -> Option<String> {
        self.commit
            .as_ref()
            .and_then(|commit| commit.get(..7).map(str::to_owned))
    }

    /// Считает контрольную сумму пакета и собирает запись о происхождении.
    ///
    /// # Ошибки
    ///
    /// Отсутствие файла и ошибки чтения.
    pub fn of_package(
        path: &Path,
        source: Option<&str>,
        commit: Option<&str>,
    ) -> Result<Self, ProvenanceError> {
        if !path.is_file() {
            return Err(ProvenanceError::Missing {
                path: path.to_path_buf(),
            });
        }
        let mut file = std::fs::File::open(path).map_err(|source| ProvenanceError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; CHUNK];
        let mut size = 0_u64;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|source| ProvenanceError::Read {
                    path: path.to_path_buf(),
                    source,
                })?;
            if read == 0 {
                break;
            }
            let Some(chunk) = buffer.get(..read) else {
                break;
            };
            hasher.update(chunk);
            size = size.saturating_add(read as u64);
        }
        Ok(Self {
            path: path.to_path_buf(),
            sha256: hex::encode(hasher.finalize()),
            size,
            source: source.map_or_else(
                || format!("локальный путь {}", path.display()),
                str::to_owned,
            ),
            commit: commit.map(str::to_owned).filter(|c| !c.trim().is_empty()),
        })
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
    fn hashes_the_package_and_records_its_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tessera.deb");
        std::fs::write(&path, b"deb").unwrap();

        let provenance = Provenance::of_package(&path, None, None).unwrap();
        assert_eq!(
            provenance.sha256,
            "9cfa1468c93fc18652e34a000f0c6614b0fa18f6f4887477ad9b0d36ca6a7eaa"
        );
        assert_eq!(provenance.size, 3);
        assert!(provenance.source.contains("tessera.deb"));
        assert!(!provenance.is_established());
        assert!(provenance.short_commit().is_none());
    }

    #[test]
    fn a_confirmed_commit_makes_provenance_established() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tessera.deb");
        std::fs::write(&path, b"deb").unwrap();

        let provenance =
            Provenance::of_package(&path, Some("build.yml run 42"), Some("0123456789ab")).unwrap();
        assert!(provenance.is_established());
        assert_eq!(provenance.short_commit().as_deref(), Some("0123456"));
        assert_eq!(provenance.source, "build.yml run 42");
    }

    #[test]
    fn a_blank_commit_does_not_count_as_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tessera.deb");
        std::fs::write(&path, b"deb").unwrap();

        let provenance = Provenance::of_package(&path, None, Some("  ")).unwrap();
        assert!(!provenance.is_established());
    }

    #[test]
    fn a_missing_package_is_reported_before_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let err = Provenance::of_package(&dir.path().join("нет.deb"), None, None).unwrap_err();
        assert!(matches!(err, ProvenanceError::Missing { .. }));
    }
}
