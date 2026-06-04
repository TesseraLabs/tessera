//! Stage 5 smoke test: drive `flow::authenticate_pkcs12` end-to-end with
//! the real [`tessera_core::hooks::ForkExecExecutor`] and assert that
//! a configured `pre_auth` hook actually creates a marker file on disk.
//!
//! Linux-only because `fork(2)` semantics on macOS pre-Sonoma block in
//! the dynamic loader during async-signal-safe child paths; the
//! stage-5 invariants (`close_range`, `prctl(PR_SET_NO_NEW_PRIVS)`) are
//! Linux-specific anyway.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::pedantic
)]
#![cfg(target_os = "linux")]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use common::*;

use pam_tessera::flow::{authenticate, Deps, InMemoryFlowIo};
use tessera_core::config::ValidatedConfig;
use tessera_core::hooks::{ForkExecExecutor, HookConfig, HookStage, OnFailure, RunAs};
use tessera_core::host_identity::HostIdSourceKind;
use tessera_core::ipc::StubClient;
use tessera_core::x509::Certificate;
use secrecy::SecretString;

#[test]
fn pre_auth_hook_runs_and_writes_marker_file() {
    // 1. Fixture: pre-stage USB mountpoint and write a tiny pre_auth
    //    script that touches a marker file.
    let usb_tmp = stage_mount("leaf_rsa.p12", false);

    let work = tempfile::tempdir().unwrap();
    let marker = work.path().join("hook.log");
    let script = work.path().join("hook.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\necho \"hook ran\" > \"$MARKER\"\nexit 0\n",
    )
    .unwrap();
    let mut perms = std::fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&script, perms).unwrap();

    // 2. Build a minimal config and inject the hook.
    let mut cfg: ValidatedConfig = minimal_cfg();
    cfg.hooks = vec![HookConfig {
        stage: HookStage::PreAuth,
        command: vec![script.to_string_lossy().into_owned()],
        timeout: Duration::from_secs(5),
        on_failure: OnFailure::Abort,
        run_as: RunAs::Root,
        env: {
            let mut m = std::collections::BTreeMap::new();
            // No template substitution — env value is plain text. The
            // executor still inserts TESSERA_* automatically; we
            // rely on a custom MARKER var to find the temp path.
            m.insert(
                "MARKER".to_string(),
                tessera_core::hooks::Template::parse(marker.to_string_lossy().as_ref())
                    .unwrap(),
            );
            m
        },
    }];

    // 3. Wire dependencies.
    let _leaf = Certificate::from_pem(&fixture_bytes("leaf_rsa.pem")).unwrap();
    let mappings = vec![cn_mapping("alice", "alice")];

    let verifier = build_verifier(vec![]);
    let monitor = StubClient;
    let executor = ForkExecExecutor::new();
    let deps = Deps {
        cfg: &cfg,
        trust: &verifier,
        monitor: &monitor,
        hook_executor: &executor,
        host_id_hash: "host-T-hash",
        host_id_source: HostIdSourceKind::Override,
        user_mappings: &mappings,
        pam_target: tessera_proto::SessionTarget::Unknown,
    };

    // 4. Drive the flow.
    let io = InMemoryFlowIo::new(usb_tmp.path().to_path_buf());
    let _outcome = authenticate(deps, &io, "alice", "ssh", "sess-smoke".into(), |_| {
        Ok(SecretString::from("correct-pin"))
    })
    .expect("flow with real fork+execve hook");

    // 5. Assert the marker exists and contains the expected line.
    assert!(
        marker.exists(),
        "marker file should have been created by the pre_auth hook at {:?}",
        marker
    );
    let body = std::fs::read_to_string(&marker).unwrap();
    assert!(
        body.contains("hook ran"),
        "expected marker contents 'hook ran', got: {body}"
    );
}
