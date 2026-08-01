//! The role list the tile shows.
//!
//! The service reads the store; the client never does. That is not a division
//! of labour but a trust boundary: the store lives in a directory only SYSTEM
//! and administrators may write, and a client that read it itself would be a
//! second answer to "which roles exist on this device" — one produced in a
//! process the engineer's session can reach.

use tessera_core::role::RoleStore;
use tessera_proto::RoleSummary;

/// The store's roles, ordered for display.
///
/// Ordering is by `level`, then by id. `level` is the slice's own display hint,
/// and ties broken by id keep the order stable across devices whose stores
/// happen to list the same level twice — the core never treats `level` as an
/// ordering of privilege, and neither does this.
///
/// There is no default entry and no pre-selection: the engineer chooses a role
/// explicitly, which is the invariant the whole role model rests on.
#[must_use]
pub fn summaries(store: &RoleStore) -> Vec<RoleSummary> {
    let mut roles: Vec<RoleSummary> = store
        .list()
        .map(|slice| RoleSummary {
            id: slice.role.as_str().to_owned(),
            name: slice.name.clone(),
            level: slice.level,
        })
        .collect();
    roles.sort_by(|a, b| a.level.cmp(&b.level).then_with(|| a.id.cmp(&b.id)));
    roles
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use tessera_core::role::{RoleOs, TrustMode};

    /// Writes `slices` as `<id>.toml` files and loads them as a store.
    fn store_with(dir: &std::path::Path, slices: &[(&str, &str, u8)]) -> RoleStore {
        for (id, name, level) in slices {
            let body =
                format!("role = \"{id}\"\nversion = 1\nos = \"windows\"\nname = \"{name}\"\nlevel = {level}\n");
            std::fs::write(dir.join(format!("{id}.toml")), body).unwrap();
        }
        RoleStore::load(
            dir,
            RoleOs::Windows,
            TrustMode::Standalone,
            tessera_core::role::SystemAccounts::empty(),
        )
        .unwrap()
    }

    #[test]
    fn roles_are_ordered_by_level_then_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(
            dir.path(),
            &[
                ("serv", "Service", 5),
                ("audit", "Audit", 1),
                ("admin", "Admin", 5),
            ],
        );
        let summaries = summaries(&store);
        let ids: Vec<&str> = summaries.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["audit", "admin", "serv"]);
        assert_eq!(summaries[0].name, "Audit");
        assert_eq!(summaries[0].level, 1);
    }

    /// An empty store lists nothing rather than inventing an entry: a device
    /// with no roles offers no login, and the tile must show exactly that.
    #[test]
    fn an_empty_store_lists_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with(dir.path(), &[]);
        assert!(summaries(&store).is_empty());
    }
}
