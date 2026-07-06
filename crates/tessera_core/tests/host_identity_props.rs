#![allow(missing_docs)]

use proptest::prelude::*;
use tessera_core::host_identity::normalize_host_id;

proptest! {
    #[test]
    fn normalization_is_idempotent(input in "[ -~]*") {
        let once = normalize_host_id(&input);
        prop_assert_eq!(normalize_host_id(&once), once);
    }

    #[test]
    fn normalization_removes_upper_colon_and_space(input in "[ -~]*") {
        let normalized = normalize_host_id(&input);
        prop_assert!(normalized.chars().all(|c| !c.is_ascii_uppercase() && c != ':' && c != ' '));
    }
}
