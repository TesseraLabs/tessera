use super::{
    codec, domain, AuthorityError, Encoder, Reader, RecordDigestKind, RegistryHead, MAX_ENTRIES,
    MAX_ENTRY, MAX_INVENTORY,
};
use crate::device_number::CheckedDeviceNumber;

/// Canonical inventory domain.
pub const INVENTORY_DOMAIN: &str = "tessera-codes-contract/v1/registry-inventory";
/// Owner-attested state at the activation cut, not ongoing operational admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryState {
    /// Retained current signed record.
    Current(RegistryHead),
    /// Retired number with a retained last signed-record identity.
    Retired(RegistryHead),
    /// Historical occupied number whose previous record is unavailable.
    RetiredUnknown {
        /// Positive protected-index ordinal; cannot authorize automatic replacement.
        generation: u64,
    },
}
impl InventoryState {
    /// Positive generation of this inventory entry.
    #[must_use]
    pub const fn generation(self) -> u64 {
        match self {
            Self::Current(h) | Self::Retired(h) => h.generation(),
            Self::RetiredUnknown { generation } => generation,
        }
    }
}
/// Bounded immutable row of a complete historical-number inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineEntry {
    number: CheckedDeviceNumber,
    node_id: String,
    organisation_id: String,
    state: InventoryState,
}
impl BaselineEntry {
    /// Construct a row. Number identity is stored in canonical significant form.
    /// # Errors
    /// Rejects malformed scope, oversized numbers or zero generation.
    pub fn new(
        number: &CheckedDeviceNumber,
        node_id: String,
        organisation_id: String,
        state: InventoryState,
    ) -> Result<Self, AuthorityError> {
        codec::uuid(&node_id)?;
        codec::text(&organisation_id)?;
        if number.significant().len() > 32 || state.generation() == 0 {
            return Err(AuthorityError::Malformed("inventory number/generation"));
        }
        let number = CheckedDeviceNumber::parse(number.significant())
            .map_err(|_| AuthorityError::Malformed("inventory number"))?;
        Ok(Self {
            number,
            node_id,
            organisation_id,
            state,
        })
    }
    /// Canonical significant device number.
    #[must_use]
    pub const fn number(&self) -> &CheckedDeviceNumber {
        &self.number
    }
    /// Existing registration node scope.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
    /// Existing organisation scope.
    #[must_use]
    pub fn organisation_id(&self) -> &str {
        &self.organisation_id
    }
    /// State at the historical activation cut only.
    #[must_use]
    pub const fn state(&self) -> InventoryState {
        self.state
    }
    fn encode(&self) -> Result<Vec<u8>, AuthorityError> {
        let mut e = Encoder::default();
        e.push_text("number", self.number.significant())?;
        e.push_text("node", &self.node_id)?;
        e.push_text("organisation", &self.organisation_id)?;
        let (state, head) = match self.state {
            InventoryState::Current(h) => ("current", Some(h)),
            InventoryState::Retired(h) => ("retired", Some(h)),
            InventoryState::RetiredUnknown { .. } => ("retired", None),
        };
        e.push_text("state", state)?;
        e.push_u64("generation", self.state.generation())?;
        e.push_text("record_kind", head.map_or("unknown", |h| h.kind().as_str()))?;
        e.push_bytes(
            "record_digest",
            head.as_ref().map_or(&[][..], |h| &h.digest),
        )?;
        let result = e.finish();
        if result.len() > MAX_ENTRY {
            return Err(AuthorityError::Malformed("inventory entry bound"));
        }
        Ok(result)
    }
    fn parse(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let mut r = Reader::new(bytes);
        let raw_number = r.string(32)?;
        let number = CheckedDeviceNumber::parse(&raw_number)
            .map_err(|_| AuthorityError::Malformed("inventory number"))?;
        if raw_number != number.significant() {
            return Err(AuthorityError::Malformed("inventory number form"));
        }
        let node = r.string(36)?;
        let organisation = r.string(128)?;
        let state = r.string(16)?;
        let generation = r.u64()?;
        let kind = r.string(32)?;
        let digest = r.field(32)?;
        let state = match (state.as_str(), kind.as_str(), digest) {
            ("retired", "unknown", []) => InventoryState::RetiredUnknown { generation },
            ("current" | "retired", _, _) => {
                let digest = digest
                    .try_into()
                    .map_err(|_| AuthorityError::Malformed("inventory digest"))?;
                let head = RegistryHead::new(generation, RecordDigestKind::parse(&kind)?, digest)?;
                if state == "current" {
                    InventoryState::Current(head)
                } else {
                    InventoryState::Retired(head)
                }
            }
            _ => return Err(AuthorityError::Malformed("inventory state")),
        };
        r.finish()?;
        Self::new(&number, node, organisation, state)
    }
}
/// Immutable, canonical complete inventory artifact. An unsigned instance is not authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineInventory {
    entries: Vec<BaselineEntry>,
}
impl BaselineInventory {
    /// Construct strictly sorted unique rows; never sort or discard caller entries.
    /// # Errors
    /// Rejects duplicate/out-of-order numbers and aggregate bounds.
    pub fn new(entries: Vec<BaselineEntry>) -> Result<Self, AuthorityError> {
        if entries.len() > MAX_ENTRIES
            || entries.windows(2).any(
                |pair| matches!(pair, [a,b] if a.number.significant() >= b.number.significant()),
            )
        {
            return Err(AuthorityError::Malformed("inventory count/order"));
        }
        let result = Self { entries };
        result.encode()?;
        Ok(result)
    }
    /// Retained rows, which cannot be mutated after signature verification.
    #[must_use]
    pub fn entries(&self) -> &[BaselineEntry] {
        &self.entries
    }
    /// Lookup only at the historical baseline cut. None is NOT current protected absence.
    #[must_use]
    pub fn lookup_at_cut(&self, number: &CheckedDeviceNumber) -> Option<&BaselineEntry> {
        self.entries
            .binary_search_by(|e| e.number.significant().cmp(number.significant()))
            .ok()
            .and_then(|i| self.entries.get(i))
    }
    /// Encode the separate bounded binary artifact, including an explicit empty count.
    /// # Errors
    /// Rejects aggregate bounds or canonical encoding overflow.
    pub fn encode(&self) -> Result<Vec<u8>, AuthorityError> {
        let mut e = Encoder::default();
        e.push_text("domain", INVENTORY_DOMAIN)?;
        let count = u32::try_from(self.entries.len())
            .map_err(|_| AuthorityError::Malformed("inventory count"))?;
        e.push_u32("count", count)?;
        for entry in &self.entries {
            e.push_bytes("entry", &entry.encode()?)?;
        }
        let result = e.finish();
        if result.len() > MAX_INVENTORY {
            return Err(AuthorityError::Malformed("inventory bound"));
        }
        Ok(result)
    }
    /// Parse canonical bounded rows without authenticating completeness.
    /// # Errors
    /// Rejects noncanonical, duplicate, truncated, unknown or oversized data.
    pub fn parse(bytes: &[u8]) -> Result<Self, AuthorityError> {
        if bytes.len() > MAX_INVENTORY {
            return Err(AuthorityError::Malformed("inventory bound"));
        }
        let mut r = Reader::new(bytes);
        domain(&mut r, INVENTORY_DOMAIN)?;
        let count =
            usize::try_from(r.u32()?).map_err(|_| AuthorityError::Malformed("inventory count"))?;
        if count > MAX_ENTRIES {
            return Err(AuthorityError::Malformed("inventory count"));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(BaselineEntry::parse(r.field(MAX_ENTRY)?)?);
        }
        r.finish()?;
        let result = Self::new(entries)?;
        if result.encode()? != bytes {
            return Err(AuthorityError::Malformed("inventory canonical form"));
        }
        Ok(result)
    }
}
