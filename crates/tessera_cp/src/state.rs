//! The tile's state machine.
//!
//! Everything `LogonUI` does to the tile — selecting it, changing a combo box,
//! typing a PIN, pressing the button — lands here, and everything the tile
//! shows comes back out of here. Keeping it free of COM is what makes the
//! interesting behaviour (no default role, one status for every refusal, no
//! serialization without a grant) testable off Windows.

use zeroize::Zeroizing;

use crate::engine::{AuthRequest, DenialCode, EngineClient, EngineError, Verdict};
use crate::kerb::{self, LogonKind};
use crate::method::LoginMethod;
use crate::role::{ordered_for_display, RoleChoice};

/// The role combo box's first item: present so that the control has something
/// selected without that something being a role.
pub const ROLE_PLACEHOLDER: &str = "— выберите роль —";

/// What the tile tells the engineer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TileStatus {
    /// Nothing to report.
    Idle,
    /// The service did not answer, so no roles are known.
    ServiceUnavailable,
    /// The service accepted the connection and then went quiet past the
    /// deadline. Distinct from unavailable because the two send an engineer to
    /// different places: nothing running, versus something running and stuck.
    ServiceTimeout,
    /// The chosen method is not implemented yet.
    MethodReserved,
    /// No role has been picked.
    RoleNotChosen,
    /// No PIN has been typed.
    PinMissing,
    /// The service refused. Deliberately one message for every reason.
    Denied,
    /// Credentials could not be packed for `LogonUI`.
    SerializationFailed,
    /// A panic was contained; the tile is out of service until the screen is
    /// rebuilt.
    Faulted,
}

impl TileStatus {
    /// The line shown in the status field.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Idle => "",
            Self::ServiceUnavailable => "Служба Tessera недоступна. Вход этим методом невозможен.",
            Self::ServiceTimeout => "Служба Tessera не отвечает. Вход этим методом невозможен.",
            Self::MethodReserved => "Метод пока недоступен.",
            Self::RoleNotChosen => "Выберите роль.",
            Self::PinMissing => "Введите PIN носителя.",
            Self::Denied => "Доступ не предоставлен.",
            Self::SerializationFailed => {
                "Не удалось подготовить вход. Обратитесь к администратору."
            }
            Self::Faulted => "Тайл Tessera неисправен. Используйте другой способ входа.",
        }
    }
}

/// The outcome of pressing the tile's button.
#[derive(Debug)]
pub enum Submission {
    /// Nothing is serialised; `LogonUI` is told the tile is not finished and the
    /// status field explains why. This is the fail-closed answer for every
    /// failure: an unavailable service, a dropped pipe, a version mismatch, a
    /// refusal.
    NotFinished,
    /// Credentials are ready for `LogonUI`. The block is the packed
    /// `KERB_INTERACTIVE_UNLOCK_LOGON`; it wipes itself on drop.
    Serialize(Zeroizing<Vec<u8>>),
}

/// Live state of one logon tile.
#[derive(Debug)]
pub struct TileState<E: EngineClient> {
    engine: E,
    kind: LogonKind,
    roles: Vec<RoleChoice>,
    method: LoginMethod,
    selected_role: Option<usize>,
    pin: Zeroizing<String>,
    status: TileStatus,
}

impl<E: EngineClient> TileState<E> {
    /// Creates a tile bound to an engine client.
    pub fn new(engine: E, kind: LogonKind) -> Self {
        Self {
            engine,
            kind,
            roles: Vec::new(),
            method: LoginMethod::DEFAULT,
            selected_role: None,
            pin: Zeroizing::new(String::new()),
            status: TileStatus::Idle,
        }
    }

    /// Asks the service for the role list, unless the tile already has one.
    ///
    /// Returns whether this call is what filled the list. That answer is the
    /// whole reason the method reports anything: a Windows tile draws its combo
    /// box once and does not come back to ask again, so whoever fills the list
    /// after the tile is on screen has to tell `LogonUI` about it. A caller that
    /// gets `true` has items to push; a caller that gets `false` has nothing to
    /// say and must not push, or the screen grows a second copy of the list.
    ///
    /// Failures are not propagated: the tile has one way of reporting anything,
    /// and it is the status line.
    pub fn ensure_roles(&mut self) -> bool {
        if !self.roles.is_empty() {
            return false;
        }

        match self.engine.list_roles() {
            Ok(roles) if roles.is_empty() => {
                // A service that answers with an empty store is not the same
                // failure as one that does not answer, but it leaves the tile
                // in the same place: nothing to choose.
                tracing::warn!(target: "tessera.cp", "the service offers no roles");
                self.status = TileStatus::ServiceUnavailable;
                false
            }
            Ok(roles) => {
                self.roles = ordered_for_display(roles);
                self.selected_role = None;
                self.status = TileStatus::Idle;
                tracing::info!(
                    target: "tessera.cp",
                    roles = self.roles.len(),
                    "role list taken from the service"
                );
                true
            }
            Err(error) => {
                tracing::warn!(
                    target: "tessera.cp",
                    error = %error,
                    "role list unavailable; the tile stays fail-closed"
                );
                self.roles.clear();
                self.selected_role = None;
                self.status = engine_error_status(error);
                false
            }
        }
    }

    /// The roles currently offered, in display order.
    #[must_use]
    pub fn roles(&self) -> &[RoleChoice] {
        &self.roles
    }

    /// The selected method.
    #[must_use]
    pub fn method(&self) -> LoginMethod {
        self.method
    }

    /// Index of the selected role, if the engineer has picked one.
    #[must_use]
    pub fn selected_role(&self) -> Option<usize> {
        self.selected_role
    }

    /// The current status.
    #[must_use]
    pub fn status(&self) -> TileStatus {
        self.status
    }

    /// Records that a grant could not be turned into credentials.
    ///
    /// The packing itself is checked in [`Self::submit`]; this covers the step
    /// after it, where the platform refuses to allocate or to name the
    /// authentication package. The outcome for the engineer is identical — no
    /// logon, one status line — so it shares the status.
    pub fn fail_serialization(&mut self) {
        self.status = TileStatus::SerializationFailed;
    }

    /// Forces the tile into its out-of-service state after a contained panic.
    pub fn fault(&mut self) {
        self.status = TileStatus::Faulted;
        self.clear_pin();
    }

    /// Selects a method by its position in the combo box.
    ///
    /// Returns whether the selection took effect. A reserved position is
    /// refused and the previous selection stands, which is how the "present but
    /// unusable" position is expressed on a control that cannot grey out an
    /// item.
    pub fn select_method(&mut self, index: usize) -> bool {
        match LoginMethod::from_index(index) {
            Some(method) if method.is_enabled() => {
                self.method = method;
                if self.status == TileStatus::MethodReserved {
                    self.status = TileStatus::Idle;
                }
                true
            }
            Some(_) => {
                self.status = TileStatus::MethodReserved;
                false
            }
            None => false,
        }
    }

    /// The role combo box's items, placeholder first.
    ///
    /// A Windows combo box always has one item selected, so "no default role"
    /// cannot be expressed by selecting nothing. It is expressed by making the
    /// preselected item something that is not a role: choosing it and pressing
    /// the button gets the engineer "выберите роль", never a logon under a role
    /// nobody picked.
    #[must_use]
    pub fn role_items(&self) -> Vec<String> {
        let mut items = Vec::with_capacity(self.roles.len() + 1);
        items.push(ROLE_PLACEHOLDER.to_owned());
        items.extend(self.roles.iter().map(|role| role.name.clone()));
        items
    }

    /// Which item of the role combo box is selected — 0 while no role is.
    #[must_use]
    pub fn selected_role_item(&self) -> usize {
        self.selected_role.map_or(0, |index| index + 1)
    }

    /// Selects an item of the role combo box; item 0 clears the choice.
    pub fn select_role_item(&mut self, item: usize) -> bool {
        match item.checked_sub(1) {
            None => {
                self.selected_role = None;
                true
            }
            Some(index) => self.select_role(index),
        }
    }

    /// Selects a role by its position in the role list.
    pub fn select_role(&mut self, index: usize) -> bool {
        if index >= self.roles.len() {
            return false;
        }
        self.selected_role = Some(index);
        if matches!(self.status, TileStatus::RoleNotChosen) {
            self.status = TileStatus::Idle;
        }
        true
    }

    /// Replaces the PIN with what the engineer has typed.
    pub fn set_pin(&mut self, pin: &str) {
        self.pin = Zeroizing::new(pin.to_owned());
        if matches!(self.status, TileStatus::PinMissing) {
            self.status = TileStatus::Idle;
        }
    }

    /// Wipes the PIN.
    pub fn clear_pin(&mut self) {
        self.pin = Zeroizing::new(String::new());
    }

    /// Whether the tile is currently holding a PIN.
    ///
    /// Exists so that the wiping contract can be asserted without exposing the
    /// PIN itself.
    #[must_use]
    pub fn holds_pin(&self) -> bool {
        !self.pin.is_empty()
    }

    /// Runs one logon attempt.
    ///
    /// The order is the contract: verdict first, serialization second, never
    /// the other way round. The PIN leaves the tile at the moment it is handed
    /// to the service and is wiped whatever the answer; the granted secret
    /// exists only between the verdict and the packed block.
    pub fn submit(&mut self) -> Submission {
        if self.status == TileStatus::Faulted {
            return Submission::NotFinished;
        }
        if !self.method.is_enabled() {
            self.status = TileStatus::MethodReserved;
            return Submission::NotFinished;
        }
        let Some(role) = self.selected_role.and_then(|index| self.roles.get(index)) else {
            self.status = TileStatus::RoleNotChosen;
            return Submission::NotFinished;
        };
        if self.pin.is_empty() {
            self.status = TileStatus::PinMissing;
            return Submission::NotFinished;
        }

        let request = AuthRequest {
            role_id: role.id.clone(),
            pin: std::mem::replace(&mut self.pin, Zeroizing::new(String::new())),
        };
        let verdict = self.engine.authenticate(request);

        match verdict {
            Err(error) => {
                tracing::warn!(
                    target: "tessera.cp",
                    error = %error,
                    "authentication exchange failed; no credentials serialised"
                );
                self.status = engine_error_status(error);
                Submission::NotFinished
            }
            Ok(Verdict::Denied(code)) => {
                tracing::info!(
                    target: "tessera.cp",
                    denial = ?code,
                    "engine refused; no credentials serialised"
                );
                self.status = denial_status(code);
                Submission::NotFinished
            }
            Ok(Verdict::Granted(grant)) => {
                match kerb::pack(self.kind, &grant.account, &grant.secret) {
                    Ok(blob) => {
                        self.status = TileStatus::Idle;
                        Submission::Serialize(blob)
                    }
                    Err(error) => {
                        tracing::error!(
                            target: "tessera.cp",
                            error = %error,
                            "granted credentials could not be packed"
                        );
                        self.status = TileStatus::SerializationFailed;
                        Submission::NotFinished
                    }
                }
            }
        }
    }
}

/// Maps a transport failure to what the tile shows.
///
/// All but the deadline collapse onto one message on purpose: from the console,
/// "the service is not running", "the pipe went away" and "the versions
/// disagree" are the same fact — this method of logging on is not available
/// right now. A missed deadline is separated because it points somewhere else:
/// the service is there and is not answering.
fn engine_error_status(error: EngineError) -> TileStatus {
    match error {
        EngineError::Timeout => TileStatus::ServiceTimeout,
        EngineError::Unavailable
        | EngineError::ProtocolMismatch
        | EngineError::Disconnected
        | EngineError::Malformed
        | EngineError::Service { .. } => TileStatus::ServiceUnavailable,
    }
}

/// Maps a refusal to what the tile shows: one message, whatever the reason.
#[must_use]
pub const fn denial_status(_code: DenialCode) -> TileStatus {
    TileStatus::Denied
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::cell::RefCell;

    use super::*;
    use crate::engine::Grant;
    use crate::kerb::LogonTarget;

    /// Engine that answers whatever the test tells it to.
    struct ScriptedEngine {
        roles: Result<Vec<RoleChoice>, EngineError>,
        verdict: RefCell<Option<Result<Verdict, EngineError>>>,
        seen_pin: RefCell<Option<String>>,
        seen_role: RefCell<Option<String>>,
    }

    impl ScriptedEngine {
        fn new(
            roles: Result<Vec<RoleChoice>, EngineError>,
            verdict: Result<Verdict, EngineError>,
        ) -> Self {
            Self {
                roles,
                verdict: RefCell::new(Some(verdict)),
                seen_pin: RefCell::new(None),
                seen_role: RefCell::new(None),
            }
        }

        fn granting() -> Self {
            Self::new(
                Ok(vec![
                    RoleChoice::new("serv", "Сервис", 10),
                    RoleChoice::new("audit", "Аудитор", 20),
                ]),
                Ok(Verdict::Granted(Grant {
                    account: LogonTarget::local("tessera-session"),
                    secret: Zeroizing::new("secret".to_owned()),
                    session_id: "session-1".to_owned(),
                })),
            )
        }
    }

    impl EngineClient for ScriptedEngine {
        fn list_roles(&self) -> Result<Vec<RoleChoice>, EngineError> {
            self.roles.clone()
        }

        fn authenticate(&self, request: AuthRequest) -> Result<Verdict, EngineError> {
            *self.seen_pin.borrow_mut() = Some(request.pin.to_string());
            *self.seen_role.borrow_mut() = Some(request.role_id.clone());
            self.verdict
                .borrow_mut()
                .take()
                .unwrap_or(Err(EngineError::Disconnected))
        }
    }

    /// Engine whose answer a test can change between calls, for the case where
    /// the service comes up after the tile was built.
    struct SwitchableEngine<'a>(&'a RefCell<Result<Vec<RoleChoice>, EngineError>>);

    impl EngineClient for SwitchableEngine<'_> {
        fn list_roles(&self) -> Result<Vec<RoleChoice>, EngineError> {
            self.0.borrow().clone()
        }

        fn authenticate(&self, _request: AuthRequest) -> Result<Verdict, EngineError> {
            Err(EngineError::Disconnected)
        }
    }

    fn ready(engine: ScriptedEngine) -> TileState<ScriptedEngine> {
        let mut tile = TileState::new(engine, LogonKind::Interactive);
        assert!(tile.ensure_roles());
        assert!(tile.select_role(0));
        tile.set_pin("1234");
        tile
    }

    #[test]
    fn a_fresh_tile_preselects_no_role() {
        let mut tile = TileState::new(ScriptedEngine::granting(), LogonKind::Interactive);
        assert!(tile.ensure_roles());

        assert_eq!(tile.roles().len(), 2);
        assert_eq!(tile.selected_role(), None, "the engineer must choose");
    }

    /// The signal the COM layer keys its screen update off: exactly one call
    /// reports having filled the list. A second `true` would mean the roles are
    /// appended to the combo box twice.
    #[test]
    fn only_the_call_that_fills_the_list_says_so() {
        let mut tile = TileState::new(ScriptedEngine::granting(), LogonKind::Interactive);

        assert!(tile.ensure_roles(), "the first call fills the list");
        assert!(!tile.ensure_roles(), "the second has nothing to report");
        assert!(!tile.ensure_roles());
        assert_eq!(tile.roles().len(), 2, "and does not duplicate anything");
    }

    /// A service that was unreachable when the tile was built and answers later
    /// is the one case the late path exists for.
    #[test]
    fn a_list_that_arrives_after_the_first_attempt_is_reported_as_filled() {
        let engine = RefCell::new(Err(EngineError::Unavailable));
        let mut tile = TileState::new(SwitchableEngine(&engine), LogonKind::Interactive);

        assert!(!tile.ensure_roles(), "the service was not there");
        assert_eq!(tile.status(), TileStatus::ServiceUnavailable);

        *engine.borrow_mut() = Ok(vec![RoleChoice::new("serv", "Сервис", 10)]);
        assert!(
            tile.ensure_roles(),
            "now it is, and the screen must be told"
        );
        assert_eq!(tile.roles().len(), 1);
        assert_eq!(tile.status(), TileStatus::Idle);
    }

    /// A service answering with an empty store is not a list: nothing is put on
    /// screen, and the tile says why.
    #[test]
    fn an_empty_role_store_fills_nothing() {
        let mut tile = TileState::new(
            ScriptedEngine::new(Ok(Vec::new()), Err(EngineError::Disconnected)),
            LogonKind::Interactive,
        );

        assert!(!tile.ensure_roles());
        assert!(tile.roles().is_empty());
        assert_eq!(tile.status(), TileStatus::ServiceUnavailable);
    }

    #[test]
    fn the_role_box_preselects_an_item_that_is_not_a_role() {
        let mut tile = TileState::new(ScriptedEngine::granting(), LogonKind::Interactive);
        assert!(tile.ensure_roles());

        let items = tile.role_items();
        assert_eq!(items.len(), 3, "placeholder plus two roles");
        assert_eq!(items.first().map(String::as_str), Some(ROLE_PLACEHOLDER));
        assert_eq!(tile.selected_role_item(), 0);
        assert_eq!(tile.selected_role(), None);
    }

    #[test]
    fn selecting_the_placeholder_clears_the_role() {
        let mut tile = TileState::new(ScriptedEngine::granting(), LogonKind::Interactive);
        assert!(tile.ensure_roles());

        assert!(tile.select_role_item(2));
        assert_eq!(tile.selected_role(), Some(1));
        assert_eq!(tile.selected_role_item(), 2);

        assert!(tile.select_role_item(0));
        assert_eq!(tile.selected_role(), None, "the placeholder is not a role");
    }

    #[test]
    fn an_item_past_the_end_of_the_role_box_is_refused() {
        let mut tile = TileState::new(ScriptedEngine::granting(), LogonKind::Interactive);
        assert!(tile.ensure_roles());

        assert!(!tile.select_role_item(9));
        assert_eq!(tile.selected_role(), None);
    }

    #[test]
    fn submitting_on_the_placeholder_serialises_nothing() {
        let mut tile = TileState::new(ScriptedEngine::granting(), LogonKind::Interactive);
        assert!(tile.ensure_roles());
        assert!(tile.select_role_item(0));
        tile.set_pin("1234");

        assert!(matches!(tile.submit(), Submission::NotFinished));
        assert_eq!(tile.status(), TileStatus::RoleNotChosen);
    }

    #[test]
    fn the_reserved_method_cannot_be_selected() {
        let mut tile = TileState::new(ScriptedEngine::granting(), LogonKind::Interactive);

        assert!(!tile.select_method(1));
        assert_eq!(tile.method(), LoginMethod::Media, "selection did not move");
        assert_eq!(tile.status(), TileStatus::MethodReserved);
    }

    #[test]
    fn an_unreachable_service_leaves_no_roles_and_says_so() {
        let mut tile = TileState::new(
            ScriptedEngine::new(Err(EngineError::Unavailable), Err(EngineError::Unavailable)),
            LogonKind::Interactive,
        );
        assert!(
            !tile.ensure_roles(),
            "nothing was filled, so there is nothing to put on screen"
        );

        assert!(tile.roles().is_empty());
        assert_eq!(tile.status(), TileStatus::ServiceUnavailable);
    }

    #[test]
    fn submitting_without_a_role_serialises_nothing() {
        let mut tile = TileState::new(ScriptedEngine::granting(), LogonKind::Interactive);
        assert!(tile.ensure_roles());
        tile.set_pin("1234");

        assert!(matches!(tile.submit(), Submission::NotFinished));
        assert_eq!(tile.status(), TileStatus::RoleNotChosen);
    }

    #[test]
    fn submitting_without_a_pin_serialises_nothing() {
        let mut tile = TileState::new(ScriptedEngine::granting(), LogonKind::Interactive);
        assert!(tile.ensure_roles());
        assert!(tile.select_role(0));

        assert!(matches!(tile.submit(), Submission::NotFinished));
        assert_eq!(tile.status(), TileStatus::PinMissing);
    }

    #[test]
    fn a_grant_produces_a_block_and_clears_the_pin() {
        let mut tile = ready(ScriptedEngine::granting());

        let outcome = tile.submit();
        match outcome {
            Submission::Serialize(blob) => assert!(blob.len() > kerb::STRUCT_SIZE),
            Submission::NotFinished => panic!("a grant must serialise"),
        }
        assert!(!tile.holds_pin(), "the PIN does not outlive the exchange");
        assert_eq!(tile.status(), TileStatus::Idle);
    }

    #[test]
    fn the_pin_and_role_reach_the_service_unchanged() {
        let engine = ScriptedEngine::granting();
        {
            let mut tile = TileState::new(&engine, LogonKind::Interactive);
            assert!(tile.ensure_roles());
            assert!(tile.select_role(0));
            tile.set_pin("4321");
            let _ = tile.submit();
        }

        assert_eq!(engine.seen_pin.borrow().as_deref(), Some("4321"));
        assert_eq!(engine.seen_role.borrow().as_deref(), Some("serv"));
    }

    #[test]
    fn a_refusal_serialises_nothing_and_shows_one_message() {
        for code in [
            DenialCode::Media,
            DenialCode::Credential,
            DenialCode::Role,
            DenialCode::Internal,
        ] {
            let mut tile = ready(ScriptedEngine::new(
                Ok(vec![RoleChoice::new("serv", "Сервис", 10)]),
                Ok(Verdict::Denied(code)),
            ));

            assert!(matches!(tile.submit(), Submission::NotFinished));
            assert_eq!(
                tile.status(),
                TileStatus::Denied,
                "refusals must be indistinguishable from the console"
            );
            assert!(!tile.holds_pin());
        }
    }

    #[test]
    fn a_transport_failure_serialises_nothing() {
        for error in [
            EngineError::Unavailable,
            EngineError::ProtocolMismatch,
            EngineError::Disconnected,
            EngineError::Malformed,
        ] {
            let mut tile = ready(ScriptedEngine::new(
                Ok(vec![RoleChoice::new("serv", "Сервис", 10)]),
                Err(error),
            ));

            assert!(matches!(tile.submit(), Submission::NotFinished));
            assert_eq!(tile.status(), TileStatus::ServiceUnavailable);
            assert!(
                !tile.holds_pin(),
                "the PIN is wiped even when nothing came back"
            );
        }
    }

    #[test]
    fn a_failed_handover_reads_as_a_serialization_failure() {
        let mut tile = ready(ScriptedEngine::granting());
        tile.fail_serialization();

        assert_eq!(tile.status(), TileStatus::SerializationFailed);
        assert!(!tile.status().message().is_empty());
    }

    #[test]
    fn a_faulted_tile_never_serialises_again() {
        let mut tile = ready(ScriptedEngine::granting());
        tile.fault();

        assert!(matches!(tile.submit(), Submission::NotFinished));
        assert_eq!(tile.status(), TileStatus::Faulted);
        assert!(!tile.holds_pin());
    }

    #[test]
    fn every_status_but_idle_carries_a_message() {
        for status in [
            TileStatus::ServiceUnavailable,
            TileStatus::MethodReserved,
            TileStatus::RoleNotChosen,
            TileStatus::PinMissing,
            TileStatus::Denied,
            TileStatus::SerializationFailed,
            TileStatus::Faulted,
        ] {
            assert!(!status.message().is_empty(), "status {status:?}");
        }
        assert!(TileStatus::Idle.message().is_empty());
    }

    #[test]
    fn every_denial_maps_to_the_same_status() {
        assert_eq!(
            denial_status(DenialCode::Credential),
            denial_status(DenialCode::Role)
        );
    }
}
