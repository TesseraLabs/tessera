//! The role accounts the device itself holds.
//!
//! A valid code proves that the backend authorised the operator to hand out
//! this role for this device. It does not prove that the device in front of the
//! engineer still defines that role, and the two can disagree — a role base
//! narrowed on the device, a code issued against what the fleet believed the
//! device held.
//!
//! The device keeps the narrower of the two. The check here is that residual
//! bound, and it is about the role and nothing else: a code that passes its MAC
//! for a role this device does not define is refused before any key is
//! derived.
//!
//! # What this deliberately does not check
//!
//! The linear level. A role slice carries no ceiling on it: its `mac_mask` is a
//! raw 64-bit mask of МКЦ **categories** (see
//! [`IntegrityLabel::from_mac_mask`](crate::mac::IntegrityLabel::from_mac_mask))
//! and its `level` field is a display ordering hint the schema states plainly
//! is not an ordering of rights. Reading either as "the levels this role
//! grants" is a category error that costs logins: the ceiling of the linear
//! level in this path is the operator ticket, checked in
//! [`super::tickets`], exactly as `MAX_INTEGRITY` bounds it in the certificate
//! path. The categories of the role reach the session later, when the session
//! label is assembled from them and that ceiling.

use std::collections::BTreeSet;

use crate::role::RoleStore;

/// The role accounts this device defines.
#[derive(Debug, Clone, Default)]
pub struct LocalRoles {
    ids: BTreeSet<String>,
}

impl LocalRoles {
    /// Reads the role identifiers out of a loaded role store.
    #[must_use]
    pub fn from_store(store: &RoleStore) -> Self {
        Self {
            ids: store
                .list()
                .map(|slice| slice.role.as_str().to_owned())
                .collect(),
        }
    }

    /// Builds the set from identifiers already in hand.
    #[must_use]
    pub fn from_ids<I, S>(ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            ids: ids.into_iter().map(Into::into).collect(),
        }
    }

    /// Reports whether this device defines `role_id`.
    #[must_use]
    pub fn holds(&self, role_id: &str) -> bool {
        self.ids.contains(role_id)
    }
}

#[cfg(test)]
mod tests {
    use super::LocalRoles;

    fn roles() -> LocalRoles {
        LocalRoles::from_ids(["oper", "guest"])
    }

    #[test]
    fn a_role_the_device_defines_is_held() {
        assert!(roles().holds("oper"));
        assert!(roles().holds("guest"));
    }

    #[test]
    fn a_role_the_device_does_not_hold_is_not_held() {
        assert!(!roles().holds("stranger"));
        assert!(!LocalRoles::default().holds("oper"));
    }
}
