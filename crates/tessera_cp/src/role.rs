//! The role list shown in the tile's second combo box.
//!
//! Roles arrive from the engine service and are never read from disk here.
//! Their `level` orders the list and nothing else: it is a display order, not a
//! comparison of rights, and the tile deliberately preselects nothing.

/// A role as the tile displays it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleChoice {
    /// Identifier the service knows the role by; travels back in the
    /// authentication request untouched.
    pub id: String,
    /// Human-readable name shown in the combo box.
    pub name: String,
    /// Ordering key. Lower levels come first.
    pub level: u32,
}

impl RoleChoice {
    /// Builds a choice from its parts.
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>, level: u32) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            level,
        }
    }
}

/// Orders roles for the combo box: by level, then by id.
///
/// The service already sends them in this order. The tile sorts anyway — a list
/// it renders is a list it is responsible for — and sorts by the same keys, so
/// that there is one order and not two that agree most of the time.
#[must_use]
pub fn ordered_for_display(mut roles: Vec<RoleChoice>) -> Vec<RoleChoice> {
    roles.sort_by(|left, right| {
        left.level
            .cmp(&right.level)
            .then_with(|| left.id.cmp(&right.id))
    });
    roles
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn names(roles: &[RoleChoice]) -> Vec<&str> {
        roles.iter().map(|role| role.name.as_str()).collect()
    }

    #[test]
    fn orders_by_level_then_id() {
        let ordered = ordered_for_display(vec![
            RoleChoice::new("c", "Дежурный", 20),
            RoleChoice::new("a", "Аудитор", 20),
            RoleChoice::new("b", "Сервис", 10),
        ]);

        assert_eq!(names(&ordered), vec!["Сервис", "Аудитор", "Дежурный"]);
    }

    #[test]
    fn ordering_is_stable_across_input_permutations() {
        let first = ordered_for_display(vec![
            RoleChoice::new("a", "Аудитор", 20),
            RoleChoice::new("b", "Сервис", 10),
        ]);
        let second = ordered_for_display(vec![
            RoleChoice::new("b", "Сервис", 10),
            RoleChoice::new("a", "Аудитор", 20),
        ]);

        assert_eq!(first, second);
    }

    #[test]
    fn an_empty_list_stays_empty() {
        assert!(ordered_for_display(Vec::new()).is_empty());
    }
}
