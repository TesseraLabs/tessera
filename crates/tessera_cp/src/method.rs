//! The authentication methods offered by the tile's first combo box.

/// A method the engineer can pick on the logon tile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginMethod {
    /// Certificate on removable media — the method this wave implements.
    Media,
    /// One-time code. The position is reserved so that the tile's shape does
    /// not change when the code path is ported; picking it is refused.
    Code,
}

impl LoginMethod {
    /// Every method in the order the combo box lists them.
    pub const ALL: [Self; 2] = [Self::Media, Self::Code];

    /// The method the tile starts on.
    ///
    /// Unlike the role, the method has a default: there is exactly one usable
    /// method, and making the engineer pick it would be ceremony without a
    /// decision behind it.
    pub const DEFAULT: Self = Self::Media;

    /// Label shown in the combo box.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Media => "Носитель (сертификат)",
            Self::Code => "Код (пока недоступен)",
        }
    }

    /// Whether the method can currently be used to log on.
    ///
    /// The Windows combo box has no per-item disabled state, so a reserved
    /// position cannot be greyed out the way the specification's wording
    /// suggests. The reservation is enforced one step later instead: selecting
    /// the item is refused and the selection stays where it was.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Media)
    }

    /// Looks a method up by its position in the combo box.
    #[must_use]
    pub fn from_index(index: usize) -> Option<Self> {
        Self::ALL.get(index).copied()
    }

    /// Position of the method in the combo box.
    #[must_use]
    pub fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|candidate| *candidate == self)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_media_method_is_the_usable_one() {
        assert!(LoginMethod::Media.is_enabled());
        assert!(!LoginMethod::Code.is_enabled());
        assert_eq!(LoginMethod::DEFAULT, LoginMethod::Media);
    }

    #[test]
    fn the_code_position_is_present_and_last() {
        assert_eq!(LoginMethod::ALL.len(), 2);
        assert_eq!(LoginMethod::from_index(1), Some(LoginMethod::Code));
        assert_eq!(LoginMethod::from_index(2), None);
    }

    #[test]
    fn index_round_trips() {
        for method in LoginMethod::ALL {
            assert_eq!(LoginMethod::from_index(method.index()), Some(method));
        }
    }
}
