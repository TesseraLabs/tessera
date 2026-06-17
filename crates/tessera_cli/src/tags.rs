//! `tessera tags` subcommand: `show` and `lint` over the device-tags source.
//!
//! `show` reads the device's *applied* tags from the trusted standalone file
//! (FS-permission trust, parity with `role list`) and prints them sorted; a
//! missing file means "no applied tags" and prints an empty set (exit 0).
//!
//! `lint` validates a local tags file strictly (the `tags::schema` parser) and
//! reports OK / the exact error, exiting non-zero on any problem — mirroring
//! `role lint`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};

use tessera_core::tags::source::{load_standalone_optional, TagsSourceError, DEFAULT_TAGS_FILE};
use tessera_core::tags::{parse_tags, DeviceTags};

/// CLI arguments for `tessera tags`.
#[derive(Debug, Args)]
pub struct TagsArgs {
    /// The tags operation to run.
    #[command(subcommand)]
    pub cmd: TagsCmd,
}

/// `tessera tags` operations.
#[derive(Debug, Subcommand)]
pub enum TagsCmd {
    /// Print the device's applied tags (from the trusted standalone file).
    Show(TagsShowArgs),
    /// Strictly validate a local tags file; exit non-zero on any error.
    Lint(TagsLintArgs),
}

/// Arguments for `tags show`.
#[derive(Debug, Args)]
pub struct TagsShowArgs {
    /// Device-tags file. Defaults to the production layout.
    #[arg(long, default_value = DEFAULT_TAGS_FILE)]
    pub file: PathBuf,
}

/// Arguments for `tags lint`.
#[derive(Debug, Args)]
pub struct TagsLintArgs {
    /// Tags file to validate.
    pub file: PathBuf,
}

/// Read the device's applied tags from the trusted file. A missing file maps
/// to an empty set (the device has no applied tags). Any present-but-invalid
/// file is a hard error (fail-closed).
fn read_applied(file: &std::path::Path) -> Result<DeviceTags, TagsSourceError> {
    load_standalone_optional(file)
}

/// Run `tags show`.
fn run_show(args: &TagsShowArgs) -> ExitCode {
    match read_applied(&args.file) {
        Ok(tags) => {
            for (key, value) in tags.iter() {
                println!("{key}\t{value}");
            }
            println!("---");
            println!("summary: {} tags", tags.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Run `tags lint` over a single file.
fn run_lint(args: &TagsLintArgs) -> ExitCode {
    let bytes = match std::fs::read(&args.file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERROR: cannot read {}: {e}", args.file.display());
            return ExitCode::FAILURE;
        }
    };
    match parse_tags(&bytes) {
        Ok(tags) => {
            println!("[OK]   {} ({} tags)", args.file.display(), tags.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("[FAIL] {}: {e}", args.file.display());
            ExitCode::FAILURE
        }
    }
}

/// Dispatch `tessera tags`.
#[allow(clippy::needless_pass_by_value)]
pub fn run(args: TagsArgs) -> ExitCode {
    match args.cmd {
        TagsCmd::Show(a) => run_show(&a),
        TagsCmd::Lint(a) => run_lint(&a),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_panics_doc,
        clippy::missing_docs_in_private_items,
        clippy::let_underscore_must_use
    )]

    use super::*;
    use std::fs;

    #[test]
    fn show_reads_applied_tags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tags.toml");
        fs::write(&path, b"[tags]\nregion = \"north\"\nclass = \"atm\"\n").unwrap();
        let tags = read_applied(&path).unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags.get("region"), Some("north"));
    }

    #[test]
    fn show_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.toml");
        let tags = read_applied(&path).unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn show_malformed_file_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tags.toml");
        fs::write(&path, b"[tags]\nregion = \"north\"\nregion = \"south\"\n").unwrap();
        assert!(read_applied(&path).is_err());
    }

    #[test]
    fn lint_clean_file_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tags.toml");
        fs::write(&path, b"[tags]\nregion = \"north\"\n").unwrap();
        let code = run_lint(&TagsLintArgs { file: path });
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn lint_duplicate_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tags.toml");
        fs::write(&path, b"[tags]\nregion = \"north\"\nregion = \"south\"\n").unwrap();
        let code = run_lint(&TagsLintArgs { file: path });
        assert_eq!(code, ExitCode::FAILURE);
    }

    #[test]
    fn lint_missing_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.toml");
        let code = run_lint(&TagsLintArgs { file: path });
        assert_eq!(code, ExitCode::FAILURE);
    }
}
