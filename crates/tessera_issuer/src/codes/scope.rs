//! Whether the ticket of the operator covers the request read out to them.
//!
//! Four axes, checked apart and in a fixed order: the device, the operator, the
//! role, the level. They are orthogonal — a ceiling on the level says nothing
//! about which roles carry which rights at it — and a check that folded them
//! together would admit a request no single bound of the ticket admits.
//!
//! # What the operator side can and cannot check about the device
//!
//! The device axis splits in two. The part that is *signed* is the device
//! record: the number and the key epoch. Those are checked here against the
//! challenge, because deriving a key for another device or another epoch
//! produces a code that cannot fit and a receipt that records the wrong device.
//!
//! The part that is *not* signed is where the device stands — its region and
//! its site tags. The fleet holds that in its inventory, the record does not
//! carry it, and an operator who typed it in has not proved it. The device
//! itself checks that axis against the same ticket before it accepts a code
//! (`tessera_core::codes::tickets`), where the values are the device's own; here
//! the check runs only when the operator declares them, as a refusal that saves
//! a call rather than as the bound itself. Which of the two happened is written
//! into the receipt annex, so nobody reads a receipt as proof of a check that
//! was not made.

use tessera_codes_contract::challenge::Challenge;
use tessera_codes_contract::registry::DeviceRecord;
use tessera_codes_contract::ticket::OperatorTicket;

use crate::codes::Refusal;

/// Where a device stands, as the fleet inventory describes it.
///
/// The values are compared with the scope of the ticket the way the device
/// compares them: the region has to be the same one, and the device has to
/// carry at least one of the tags the ticket names — a ticket for `dc-1, hq`
/// covers a device in either site, not a device somehow in both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceScope {
    /// Tags the device carries.
    pub tags: Vec<String>,
    /// Region the device stands in.
    pub region: String,
}

/// One request, as the operator holds it: what was read out, what the fleet
/// signed about the device, and under which ticket the operator is working.
#[derive(Debug, Clone, Copy)]
pub struct Coverage<'a> {
    /// The challenge read out over the telephone.
    pub challenge: &'a Challenge,
    /// The signed record of the device the challenge names.
    pub record: &'a DeviceRecord,
    /// The ticket the operator is working under.
    pub ticket: &'a OperatorTicket,
    /// Where the fleet says the device stands, when the operator supplied it.
    pub device_scope: Option<&'a DeviceScope>,
}

impl Coverage<'_> {
    /// Reports whether the site axis was checked at all.
    ///
    /// A receipt records this, because "the ticket covered the site" and "the
    /// site was never named" are two different statements about one issuance.
    #[must_use]
    pub const fn site_axis_checked(&self) -> bool {
        self.device_scope.is_some()
    }
}

/// Checks that the ticket covers the request.
///
/// # Errors
///
/// The [`Refusal`] naming the first axis that did not cover the request. The
/// order is fixed — device, operator, site, role, level — so that the same
/// request refused in the cabinet and on the command line reports the same
/// axis.
pub fn check(coverage: &Coverage<'_>) -> Result<(), Refusal> {
    let challenge = coverage.challenge;
    let record = coverage.record;
    let ticket = coverage.ticket;

    // The number is compared in its significant form: two labels printing one
    // number with different separators name one device.
    if challenge.device_number().significant() != record.device_number().significant() {
        return Err(Refusal::DeviceNumber {
            challenge: challenge.device_number().as_str().to_owned(),
            record: record.device_number().as_str().to_owned(),
        });
    }
    if challenge.epoch() != record.epoch() {
        return Err(Refusal::Epoch {
            challenge: challenge.epoch().get(),
            record: record.epoch().get(),
        });
    }
    if challenge.operator_id() != ticket.operator_id() {
        return Err(Refusal::Operator {
            challenge: challenge.operator_id().to_owned(),
            ticket: ticket.operator_id().to_owned(),
        });
    }

    let scope = ticket.scope();
    if let Some(device) = coverage.device_scope {
        if scope.region() != device.region {
            return Err(Refusal::ScopeRegion {
                ticket: scope.region().to_owned(),
                device: device.region.clone(),
            });
        }
        if !scope.tags().iter().any(|tag| device.tags.contains(tag)) {
            return Err(Refusal::ScopeTags);
        }
    }

    // The role before the level, and independently of it: the ceiling of the
    // ticket is not a permission to hand out whatever role happens to sit under
    // it.
    if !scope.admits_role(challenge.role_id()) {
        return Err(Refusal::ScopeRole {
            role: challenge.role_id().to_owned(),
        });
    }
    if !scope.admits_level(challenge.level()) {
        return Err(Refusal::ScopeLevel {
            level: challenge.level().get(),
            ceiling: scope.max_level().get(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check, Coverage, DeviceScope};
    use crate::codes::tests::fixtures;
    use crate::codes::Refusal;

    #[test]
    fn a_covered_request_passes_every_axis() {
        let world = fixtures::world();
        assert_eq!(
            check(&Coverage {
                challenge: &world.challenge,
                record: &world.record,
                ticket: world.ticket.ticket(),
                device_scope: Some(&world.device_scope),
            }),
            Ok(())
        );
    }

    #[test]
    fn a_challenge_for_another_device_is_refused() {
        let world = fixtures::world();
        let challenge = fixtures::challenge_with(|input| {
            input.device_body = "77-000999".to_owned();
        });
        assert!(matches!(
            check(&Coverage {
                challenge: &challenge,
                record: &world.record,
                ticket: world.ticket.ticket(),
                device_scope: Some(&world.device_scope),
            }),
            Err(Refusal::DeviceNumber { .. })
        ));
    }

    #[test]
    fn a_challenge_of_another_epoch_is_refused() {
        let world = fixtures::world();
        let challenge = fixtures::challenge_with(|input| input.epoch = 9);
        assert!(matches!(
            check(&Coverage {
                challenge: &challenge,
                record: &world.record,
                ticket: world.ticket.ticket(),
                device_scope: Some(&world.device_scope),
            }),
            Err(Refusal::Epoch { .. })
        ));
    }

    #[test]
    fn a_challenge_naming_another_operator_is_refused() {
        let world = fixtures::world();
        let challenge = fixtures::challenge_with(|input| input.operator_id = "op-99".to_owned());
        assert!(matches!(
            check(&Coverage {
                challenge: &challenge,
                record: &world.record,
                ticket: world.ticket.ticket(),
                device_scope: Some(&world.device_scope),
            }),
            Err(Refusal::Operator { .. })
        ));
    }

    #[test]
    fn a_device_in_another_region_is_refused() {
        let world = fixtures::world();
        let elsewhere = DeviceScope {
            tags: world.device_scope.tags.clone(),
            region: "ru-north".to_owned(),
        };
        assert!(matches!(
            check(&Coverage {
                challenge: &world.challenge,
                record: &world.record,
                ticket: world.ticket.ticket(),
                device_scope: Some(&elsewhere),
            }),
            Err(Refusal::ScopeRegion { .. })
        ));
    }

    #[test]
    fn a_device_the_ticket_reaches_no_tag_of_is_refused() {
        let world = fixtures::world();
        let elsewhere = DeviceScope {
            tags: vec!["dc-7".to_owned()],
            region: world.device_scope.region.clone(),
        };
        assert_eq!(
            check(&Coverage {
                challenge: &world.challenge,
                record: &world.record,
                ticket: world.ticket.ticket(),
                device_scope: Some(&elsewhere),
            }),
            Err(Refusal::ScopeTags)
        );
    }

    #[test]
    fn an_undeclared_site_leaves_the_axis_unchecked_rather_than_admitted() {
        let world = fixtures::world();
        let coverage = Coverage {
            challenge: &world.challenge,
            record: &world.record,
            ticket: world.ticket.ticket(),
            device_scope: None,
        };
        assert_eq!(check(&coverage), Ok(()));
        assert!(!coverage.site_axis_checked());
    }

    #[test]
    fn a_role_outside_the_ticket_is_refused() {
        let world = fixtures::world();
        let challenge = fixtures::challenge_with(|input| input.role_id = "ops.dc.root".to_owned());
        assert!(matches!(
            check(&Coverage {
                challenge: &challenge,
                record: &world.record,
                ticket: world.ticket.ticket(),
                device_scope: Some(&world.device_scope),
            }),
            Err(Refusal::ScopeRole { .. })
        ));
    }

    #[test]
    fn a_level_above_the_ceiling_is_refused() {
        let world = fixtures::world();
        let challenge = fixtures::challenge_with(|input| input.level = 9);
        assert!(matches!(
            check(&Coverage {
                challenge: &challenge,
                record: &world.record,
                ticket: world.ticket.ticket(),
                device_scope: Some(&world.device_scope),
            }),
            Err(Refusal::ScopeLevel {
                level: 9,
                ceiling: 3
            })
        ));
    }
}
