//! Integration tests for the `MacBackend` trait surface.
//!
//! Exercises the no-op [`StubBackend`] for the degraded path and uses the
//! `mockall`-generated `MockMacBackend` to verify the cert/MNKC intersection
//! pipeline shape.
#![cfg(feature = "mac-tests")]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use tessera_core::mac::backend::StubBackend;
use tessera_core::mac::{IntegrityLabel, MacBackend, MacRuntime};

#[test]
fn stub_probe_returns_unavailable() {
    let b = StubBackend::new();
    assert!(matches!(b.probe(), MacRuntime::Unavailable));
}

#[test]
fn stub_apply_is_noop_ok() {
    let b = StubBackend::new();
    let r = b.apply_session(IntegrityLabel {
        level: 1,
        categories: 0,
    });
    assert!(r.is_ok());
}

#[test]
fn stub_get_user_mnkc_returns_unbounded() {
    let b = StubBackend::new();
    let l = b.get_user_mnkc("alice").unwrap();
    assert_eq!(l.level, i8::MAX);
}

mod mock_pipeline {
    use mockall::predicate::*;
    use tessera_core::mac::backend::MockMacBackend;
    use tessera_core::mac::{IntegrityLabel, MacBackend, MacRuntime};

    #[test]
    fn intersect_pipeline_calls_apply_with_capped_label() {
        let mut mock = MockMacBackend::new();
        mock.expect_probe().return_const(MacRuntime::Active);
        mock.expect_get_user_mnkc()
            .with(eq("alice"))
            .return_once(|_| {
                Ok(IntegrityLabel {
                    level: 3,
                    categories: 0b11,
                })
            });
        mock.expect_apply_session()
            .with(eq(IntegrityLabel {
                level: 2,
                categories: 0b01,
            }))
            .return_once(|_| Ok(()));

        let cert_max = IntegrityLabel {
            level: 2,
            categories: 0b01,
        };
        let user = mock.get_user_mnkc("alice").unwrap();
        let eff = cert_max.intersect(&user);
        mock.apply_session(eff).unwrap();
    }
}
