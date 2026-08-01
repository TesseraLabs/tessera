//! The tile's field table.
//!
//! A credential provider does not draw anything: it declares fields, and
//! `LogonUI` renders them. This module is that declaration in platform-neutral
//! form — identifiers, kinds, labels and visibility — so the COM layer only has
//! to translate it into `CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR` and the `CPFS_*`
//! / `CPFIS_*` enumerations.
//!
//! Four of the fields carry content named by the provider's contract — method,
//! role, PIN, status. The other two are UI mechanics: a label so the tile has
//! something to show while it is not selected, and a submit button, without
//! which `LogonUI` has no way to hand the tile back for serialization.

use crate::method::LoginMethod;

/// A field of the logon tile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// Tile caption, visible in both the selected and deselected states.
    Label,
    /// Authentication method chooser.
    Method,
    /// Role chooser.
    Role,
    /// PIN of the removable credential.
    Pin,
    /// Button that hands the tile to `LogonUI` for serialization.
    Submit,
    /// Diagnostic line: why nothing happened, in terms an engineer at the
    /// console can act on.
    Status,
}

/// How `LogonUI` should render a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    /// Prominent static text.
    LargeText,
    /// Secondary static text.
    SmallText,
    /// Drop-down list.
    ComboBox,
    /// Text entry that masks what is typed.
    PasswordText,
    /// Push button that submits the tile.
    SubmitButton,
}

/// When a field is on screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    /// Shown whether or not the tile is selected.
    Both,
    /// Shown only once the engineer has selected the tile.
    SelectedOnly,
}

/// Whether the engineer can interact with a field right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interactivity {
    /// Ordinary, interactive.
    Normal,
    /// Present but not usable — for a combo box with nothing to choose from.
    Disabled,
    /// Interactive and holding the keyboard focus.
    Focused,
}

impl Field {
    /// Every field, in the order `LogonUI` lays them out.
    pub const ALL: [Self; 6] = [
        Self::Label,
        Self::Method,
        Self::Role,
        Self::Pin,
        Self::Submit,
        Self::Status,
    ];

    /// Identifier used on the COM boundary.
    #[must_use]
    pub fn id(self) -> u32 {
        u32::try_from(
            Self::ALL
                .iter()
                .position(|candidate| *candidate == self)
                .unwrap_or(0),
        )
        .unwrap_or(0)
    }

    /// Resolves a field identifier that came in from `LogonUI`.
    ///
    /// An identifier outside the table is not a field this provider declared,
    /// and the caller answers the invalid-argument error rather than guessing.
    #[must_use]
    pub fn from_id(id: u32) -> Option<Self> {
        usize::try_from(id)
            .ok()
            .and_then(|index| Self::ALL.get(index))
            .copied()
    }

    /// How the field is rendered.
    #[must_use]
    pub const fn kind(self) -> FieldKind {
        match self {
            Self::Label => FieldKind::LargeText,
            Self::Method | Self::Role => FieldKind::ComboBox,
            Self::Pin => FieldKind::PasswordText,
            Self::Submit => FieldKind::SubmitButton,
            Self::Status => FieldKind::SmallText,
        }
    }

    /// Label `LogonUI` shows next to (or inside) the field.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Label => "Tessera",
            Self::Method => "Метод входа",
            Self::Role => "Роль",
            Self::Pin => "PIN носителя",
            Self::Submit => "Войти",
            Self::Status => "",
        }
    }

    /// When the field is on screen.
    #[must_use]
    pub const fn visibility(self) -> Visibility {
        match self {
            Self::Label => Visibility::Both,
            _ => Visibility::SelectedOnly,
        }
    }
}

/// Interactivity of a field given what the tile currently holds.
///
/// The role combo box is the only field whose interactivity depends on state:
/// with no roles from the service there is nothing to choose, and an empty
/// enabled drop-down reads as "the list is genuinely empty" rather than "the
/// service did not answer".
#[must_use]
pub fn interactivity(field: Field, roles_available: bool) -> Interactivity {
    match field {
        Field::Role if !roles_available => Interactivity::Disabled,
        Field::Pin => Interactivity::Focused,
        _ => Interactivity::Normal,
    }
}

/// Labels of the method combo box, in combo-box order.
#[must_use]
pub fn method_labels() -> Vec<&'static str> {
    LoginMethod::ALL.iter().map(|m| m.label()).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn identifiers_round_trip() {
        for field in Field::ALL {
            assert_eq!(Field::from_id(field.id()), Some(field));
        }
    }

    #[test]
    fn an_unknown_identifier_resolves_to_nothing() {
        assert_eq!(
            Field::from_id(u32::try_from(Field::ALL.len()).unwrap()),
            None
        );
        assert_eq!(Field::from_id(u32::MAX), None);
    }

    #[test]
    fn the_contract_fields_are_declared_with_the_kinds_the_spec_names() {
        assert_eq!(Field::Method.kind(), FieldKind::ComboBox);
        assert_eq!(Field::Role.kind(), FieldKind::ComboBox);
        assert_eq!(Field::Pin.kind(), FieldKind::PasswordText);
        assert_eq!(Field::Status.kind(), FieldKind::SmallText);
    }

    #[test]
    fn only_the_caption_survives_deselection() {
        for field in Field::ALL {
            let expected = if field == Field::Label {
                Visibility::Both
            } else {
                Visibility::SelectedOnly
            };
            assert_eq!(field.visibility(), expected, "field {field:?}");
        }
    }

    #[test]
    fn the_role_box_is_disabled_while_the_service_has_given_nothing() {
        assert_eq!(
            interactivity(Field::Role, false),
            Interactivity::Disabled,
            "an empty role list must not look like a choice"
        );
        assert_eq!(interactivity(Field::Role, true), Interactivity::Normal);
    }

    #[test]
    fn the_method_box_lists_both_positions() {
        assert_eq!(method_labels().len(), 2);
    }
}
