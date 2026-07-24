//! Runtime loader contract against the separately built fixture cdylib.

#![allow(clippy::unwrap_used)]

use tessera_core::mac::MacRuntime;
use tessera_core::mac::{IntegrityLabel, MacError, MrdState};
use tessera_core::plugin::load_enforcement_backend_from_dir;

fn fixture_filename() -> String {
    if cfg!(target_os = "linux") {
        "tessera_backend_fixture.so".to_owned()
    } else {
        format!(
            "{}tessera_backend_fixture.{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_EXTENSION
        )
    }
}

fn load_fixture(fixture: &str) -> Box<dyn tessera_core::mac::MacBackend> {
    let temp = tempfile::tempdir().unwrap();
    let installed = temp.path().join(fixture_filename());
    std::fs::copy(fixture, &installed).unwrap();
    let source_signature = std::path::PathBuf::from(format!("{fixture}.sig"));
    if source_signature.is_file() {
        let installed_signature = std::path::PathBuf::from(format!("{}.sig", installed.display()));
        std::fs::copy(source_signature, installed_signature).unwrap();
    }
    load_enforcement_backend_from_dir(temp.path(), Some("fixture"), "")
}

#[test]
fn fixture_covers_loader_and_panic_contract() {
    let Ok(fixture) = std::env::var("TESSERA_TEST_PLUGIN") else {
        eprintln!("skipped: TESSERA_TEST_PLUGIN not set");
        return;
    };

    for mode in [
        "default",
        "null-header",
        "abi-mismatch",
        "kind-mismatch",
        "malformed-header",
        "init-error",
        "panic-init",
        "panic-apply",
    ] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "fixture_mode_child", "--nocapture"])
            .env("TESSERA_TEST_PLUGIN", &fixture)
            .env("TESSERA_TEST_PLUGIN_MODE", mode)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "fixture child failed for plugin mode {mode}"
        );
    }
}

#[test]
fn fixture_mode_child() {
    let (Ok(fixture), Ok(mode)) = (
        std::env::var("TESSERA_TEST_PLUGIN"),
        std::env::var("TESSERA_TEST_PLUGIN_MODE"),
    ) else {
        eprintln!("skipped: fixture child environment not set");
        return;
    };
    let backend = load_fixture(&fixture);
    match mode.as_str() {
        "default" => {
            assert_eq!(backend.probe(), MacRuntime::Active);
            assert_eq!(backend.probe_mrd(), MrdState::Unknown);
            backend.check_write_capability().unwrap();
            let label = backend.get_user_mnkc("alice").unwrap();
            assert_eq!(label.level, 7);
            assert_eq!(label.categories, 0xff);
            assert!(matches!(
                backend.get_user_mnkc("unknown"),
                Err(MacError::UserUnknown { user }) if user == "unknown"
            ));
        }
        "panic-apply" => {
            assert!(matches!(
                backend.apply_session(IntegrityLabel {
                    level: 1,
                    categories: 0,
                }),
                Err(MacError::Unavailable)
            ));
        }
        _ => {
            assert_eq!(
                backend.probe(),
                MacRuntime::Unavailable,
                "rejected plugin mode must fall back to StubBackend"
            );
        }
    }
}

#[test]
fn missing_selected_plugin_falls_back_to_stub() {
    let temp = tempfile::tempdir().unwrap();
    let backend = load_enforcement_backend_from_dir(temp.path(), Some("missing"), "");
    assert_eq!(backend.probe(), MacRuntime::Unavailable);
}
