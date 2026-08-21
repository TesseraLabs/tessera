//! Fixtures shared by the unit tests of the operator side.
//!
//! One world: a fleet whose authority signed one operator ticket, an
//! organisation that registered one device, and a challenge that device would
//! read out. Every test starts from it and edits the one thing it is about, so
//! that a refusal in a test is a refusal about that one thing.
//!
//! The keys are derived from fixed seeds rather than generated: a fixture that
//! draws randomness makes a failure reproducible only by luck.

#![expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a fixture should fail the test on the spot"
)]

pub(crate) mod fixtures {
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;
    use p256::pkcs8::EncodePrivateKey as _;
    use sha2::{Digest as _, Sha256};

    use tessera_codes_contract::canon::{CodeInput, Level};
    use tessera_codes_contract::challenge::{Challenge, ChallengeFields, SignedChallenge};
    use tessera_codes_contract::code::compute_code;
    use tessera_codes_contract::device_number::CheckedDeviceNumber;
    use tessera_codes_contract::key::{
        derive_key, EphemeralPublicPoint, Epoch, KeyAgreement as _, KeyContext,
    };
    use tessera_codes_contract::nonce::Nonce;
    use tessera_codes_contract::params::FleetParams;
    use tessera_codes_contract::profile::AlgorithmProfile;
    use tessera_codes_contract::registry::{
        AnchorKind, DeviceRecord, KeyProtection, MonotonicAnchor, PayloadFields, RecordFields,
        RecordPayload, SerialNumber,
    };
    use tessera_codes_contract::signature::{PublicKey, Signature};
    use tessera_codes_contract::ticket::{
        ServerTicket, SignedTicket, TicketNumber, TicketScope, TicketScopeInput,
    };
    use tessera_codes_contract::time::ClaimedTime;

    use crate::codes::agreement::SoftwareOperatorKey;
    use crate::codes::scope::DeviceScope;
    use crate::codes::trust::{AnchorKey, Anchors};

    /// Seed of the authority that issues operator tickets.
    pub(crate) const AUTHORITY_SEED: u8 = 0x11;
    /// Seed of the organisation that registers devices.
    pub(crate) const ORGANISATION_SEED: u8 = 0x22;
    /// Seed of the device key.
    pub(crate) const DEVICE_SEED: u8 = 0x33;
    /// Seed of the operator key.
    pub(crate) const OPERATOR_SEED: u8 = 0x44;
    /// Seed of the owner who countersigns the registry record.
    pub(crate) const OWNER_SEED: u8 = 0x66;
    /// Identifier of that owner.
    pub(crate) const OWNER_ID: &str = "owner-e2e";

    /// Seed standing in for the ephemeral pair of the fixture attempt.
    ///
    /// A real attempt draws its pair from the system generator; a fixture needs
    /// the same challenge to come out of two runs, so the pair of the world is
    /// seeded like every other key here.
    pub(crate) const EPHEMERAL_SEED: u8 = 0x55;

    /// Key epoch of the device in the fixture world.
    pub(crate) const EPOCH: u32 = 7;

    /// Moment the fixture world claims.
    pub(crate) const NOW: ClaimedTime = ClaimedTime::new(1_800_000_000);

    /// Moment the fixture ticket stops being valid.
    pub(crate) const TICKET_NOT_AFTER: u64 = 1_800_003_600;

    /// The fleet the tests work in.
    pub(crate) struct World {
        /// The challenge the device stated, signed with its own key.
        pub(crate) challenge: SignedChallenge,
        /// The signed record of that device.
        pub(crate) record: DeviceRecord,
        /// The ticket the operator works under.
        pub(crate) ticket: SignedTicket,
        /// Parameters of the fleet.
        pub(crate) params: FleetParams,
        /// Where the device stands.
        pub(crate) device_scope: DeviceScope,
        /// The anchors the operator side verifies against.
        pub(crate) anchors: Anchors,
        /// The operator key, held in software.
        pub(crate) operator_key: SoftwareOperatorKey,
    }

    /// A key that signs the documents of the fixture world.
    pub(crate) struct FixtureSigner {
        secret: p256::SecretKey,
    }

    impl FixtureSigner {
        /// The anchor this key is verified through.
        pub(crate) fn anchor(&self) -> AnchorKey {
            AnchorKey::from_sec1_point(&self.public_point()).unwrap()
        }

        /// The public half, SEC1 uncompressed.
        pub(crate) fn public_point(&self) -> Vec<u8> {
            self.secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec()
        }

        /// Signs `message` the way the fleet does: ECDSA over SHA-256, DER.
        pub(crate) fn sign(&self, message: &[u8]) -> Signature {
            let key = p256::ecdsa::SigningKey::from(&self.secret);
            let digest = Sha256::digest(message);
            let signature: p256::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
            Signature::new(signature.to_der().as_bytes().to_vec()).unwrap()
        }
    }

    /// Returns the signer of one seed.
    pub(crate) fn signer(seed: u8) -> FixtureSigner {
        FixtureSigner {
            secret: p256::SecretKey::from_slice(&[seed; 32]).unwrap(),
        }
    }

    /// Returns the PKCS#8 DER of one seed's key.
    pub(crate) fn pkcs8_of(seed: u8) -> Vec<u8> {
        signer(seed)
            .secret
            .to_pkcs8_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// Returns the `SubjectPublicKeyInfo` DER of one seed's key, as an anchor
    /// file carries it.
    ///
    /// Only the command-line tests lay anchors out as files; the library tests
    /// hold them as values.
    #[cfg(feature = "cli")]
    pub(crate) fn spki_of(seed: u8) -> Vec<u8> {
        use p256::pkcs8::EncodePublicKey as _;

        signer(seed)
            .secret
            .public_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// Returns one seed's key as a software operator key.
    pub(crate) fn software_key(seed: u8) -> SoftwareOperatorKey {
        SoftwareOperatorKey::from_pkcs8_der(&pkcs8_of(seed), AlgorithmProfile::P256).unwrap()
    }

    /// The device number of the fixture world.
    pub(crate) fn device_number() -> CheckedDeviceNumber {
        CheckedDeviceNumber::from_body("77-000123").unwrap()
    }

    /// The values a fixture challenge is built from.
    pub(crate) struct ChallengeInput {
        /// Device number without its check character.
        pub(crate) device_body: String,
        /// Key epoch.
        pub(crate) epoch: u32,
        /// Nonce of the attempt.
        pub(crate) nonce: String,
        /// Role being asked for.
        pub(crate) role_id: String,
        /// Level being asked for.
        pub(crate) level: u32,
        /// Operator handling the call.
        pub(crate) server_id: String,
        /// Personal number of the engineer at the device.
        pub(crate) engineer_id: String,
        /// Seed of the pair the attempt agrees on.
        pub(crate) ephemeral_seed: u8,
    }

    impl Default for ChallengeInput {
        fn default() -> Self {
            Self {
                device_body: "77-000123".to_owned(),
                epoch: EPOCH,
                nonce: "4".repeat(usize::from(FleetParams::defaults().nonce_width())),
                role_id: "ops.dc.senior".to_owned(),
                level: 2,
                server_id: "op-42".to_owned(),
                engineer_id: "eng-1".to_owned(),
                ephemeral_seed: EPHEMERAL_SEED,
            }
        }
    }

    /// Builds a challenge with one thing changed.
    pub(crate) fn challenge_with(edit: impl FnOnce(&mut ChallengeInput)) -> Challenge {
        let mut input = ChallengeInput::default();
        edit(&mut input);
        let params = FleetParams::defaults();
        Challenge::new(ChallengeFields {
            device_number: CheckedDeviceNumber::from_body(&input.device_body).unwrap(),
            epoch: Epoch::new(input.epoch),
            nonce: Nonce::parse(&input.nonce, &params).unwrap(),
            role_id: &input.role_id,
            level: Level::new(input.level),
            server_id: &input.server_id,
            engineer_id: &input.engineer_id,
            ephemeral_point: EphemeralPublicPoint::new(signer(input.ephemeral_seed).public_point())
                .unwrap(),
        })
        .unwrap()
    }

    /// Builds a challenge and signs it as the device of the fixture world does.
    ///
    /// The device key of the world is the one its registry record carries, so a
    /// challenge from here is one the issuing side can attribute; the tests
    /// that need the other case sign with another seed on purpose.
    pub(crate) fn signed_challenge_with(edit: impl FnOnce(&mut ChallengeInput)) -> SignedChallenge {
        signed_by(challenge_with(edit), DEVICE_SEED)
    }

    /// Signs a challenge with the key of one seed.
    pub(crate) fn signed_by(challenge: Challenge, seed: u8) -> SignedChallenge {
        let signature = signer(seed).sign(&challenge.signing_message().unwrap());
        SignedChallenge::new(challenge, signature)
    }

    /// Assembles the fixture world.
    pub(crate) fn world() -> World {
        let authority = signer(AUTHORITY_SEED);
        let organisation = signer(ORGANISATION_SEED);
        let device = signer(DEVICE_SEED);
        let operator = signer(OPERATOR_SEED);

        let scope = TicketScope::new(TicketScopeInput {
            tags: vec!["dc-1".to_owned()],
            roles: vec!["ops.dc.senior".to_owned()],
            region: "ru-central".to_owned(),
            max_level: Level::new(3),
        })
        .unwrap();
        let ticket = ServerTicket::new(
            "op-42",
            PublicKey::new(operator.public_point()).unwrap(),
            scope,
            ClaimedTime::new(TICKET_NOT_AFTER),
            TicketNumber::parse("tk-17").unwrap(),
        )
        .unwrap();
        let ticket_signature = authority.sign(&ticket.encode().unwrap());
        let ticket = SignedTicket::new(ticket, ticket_signature);

        let record = signed_record(&organisation, &device);

        World {
            challenge: signed_challenge_with(|_| {}),
            record,
            ticket,
            params: FleetParams::defaults(),
            device_scope: DeviceScope {
                tags: vec!["dc-1".to_owned()],
                region: "ru-central".to_owned(),
            },
            anchors: Anchors::new(authority.anchor())
                .with_organisation("acme", organisation.anchor())
                .with_owner(OWNER_ID, signer(OWNER_SEED).anchor()),
            operator_key: software_key(OPERATOR_SEED),
        }
    }

    /// The payload every fixture record is built on.
    ///
    /// The registry says more about a device than its number and key: which
    /// serials identify it on a shelf, what its key was observed to be kept in,
    /// whether it carries a monotonic anchor. The fixture states all of it
    /// rather than leaving defaults, because a record with unstated fields is
    /// not the document the exchange point reads.
    pub(crate) fn record_payload(device: &FixtureSigner) -> RecordPayload {
        RecordPayload::new(PayloadFields {
            device_number: device_number(),
            public_key: PublicKey::new(device.public_point()).unwrap(),
            epoch: Epoch::new(EPOCH),
            serials: vec![SerialNumber::new("chassis", "SN-E2E-1").unwrap()],
            key_protection: KeyProtection::Pkcs11ReportedNonExtractable,
            anchor: MonotonicAnchor::Present(AnchorKind::Tpm),
            batch: "batch-1",
            baseline: [0x55; 32],
        })
        .unwrap()
    }

    /// Builds a device record with the three signatures in the order they are
    /// made: possession, organisation over it, owner over the digest of both.
    ///
    /// The record is assembled step by step because each message covers the
    /// signatures before it — which is the property that makes the order part
    /// of the format rather than a habit.
    fn signed_record(organisation: &FixtureSigner, device: &FixtureSigner) -> DeviceRecord {
        let owner = signer(OWNER_SEED);
        let placeholder = Signature::new(vec![0x00]).unwrap();
        let draft = DeviceRecord::new(RecordFields {
            payload: record_payload(device),
            organisation_id: "acme",
            owner_id: OWNER_ID,
            possession_signature: placeholder.clone(),
            organisation_signature: placeholder.clone(),
            owner_signature: placeholder,
        })
        .unwrap();
        let possession_signature = device.sign(&draft.possession_message().unwrap());

        let with_possession = DeviceRecord::new(RecordFields {
            payload: record_payload(device),
            organisation_id: "acme",
            owner_id: OWNER_ID,
            possession_signature: possession_signature.clone(),
            organisation_signature: Signature::new(vec![0x00]).unwrap(),
            owner_signature: Signature::new(vec![0x00]).unwrap(),
        })
        .unwrap();
        let organisation_signature =
            organisation.sign(&with_possession.organisation_message().unwrap());

        let with_organisation = DeviceRecord::new(RecordFields {
            payload: record_payload(device),
            organisation_id: "acme",
            owner_id: OWNER_ID,
            possession_signature: possession_signature.clone(),
            organisation_signature: organisation_signature.clone(),
            owner_signature: Signature::new(vec![0x00]).unwrap(),
        })
        .unwrap();
        let owner_signature = owner.sign(&with_organisation.owner_message().unwrap());

        DeviceRecord::new(RecordFields {
            payload: record_payload(device),
            organisation_id: "acme",
            owner_id: OWNER_ID,
            possession_signature,
            organisation_signature,
            owner_signature,
        })
        .unwrap()
    }

    /// The same record with an organisation signature that does not hold.
    pub(crate) fn record_with_broken_organisation_signature(world: &World) -> DeviceRecord {
        let organisation = signer(ORGANISATION_SEED);
        DeviceRecord::new(RecordFields {
            payload: record_payload(&signer(DEVICE_SEED)),
            organisation_id: "acme",
            owner_id: OWNER_ID,
            possession_signature: world.record.possession_signature().clone(),
            organisation_signature: organisation.sign(b"some other document"),
            owner_signature: world.record.owner_signature().clone(),
        })
        .unwrap()
    }

    /// The same record whose proof of possession was made by another key.
    pub(crate) fn record_with_foreign_possession_signature(world: &World) -> DeviceRecord {
        let organisation = signer(ORGANISATION_SEED);
        let draft = DeviceRecord::new(RecordFields {
            payload: record_payload(&signer(DEVICE_SEED)),
            organisation_id: "acme",
            owner_id: OWNER_ID,
            possession_signature: Signature::new(vec![0x00]).unwrap(),
            organisation_signature: Signature::new(vec![0x00]).unwrap(),
            owner_signature: Signature::new(vec![0x00]).unwrap(),
        })
        .unwrap();
        // Signed with the organisation key: a valid signature by a key that is
        // not the device's, which is exactly what an enrolled key nobody holds
        // looks like.
        let possession_signature = organisation.sign(&draft.possession_message().unwrap());
        let with_possession = DeviceRecord::new(RecordFields {
            payload: record_payload(&signer(DEVICE_SEED)),
            organisation_id: "acme",
            owner_id: OWNER_ID,
            possession_signature: possession_signature.clone(),
            organisation_signature: Signature::new(vec![0x00]).unwrap(),
            owner_signature: Signature::new(vec![0x00]).unwrap(),
        })
        .unwrap();
        DeviceRecord::new(RecordFields {
            payload: record_payload(&signer(DEVICE_SEED)),
            organisation_id: "acme",
            owner_id: OWNER_ID,
            possession_signature,
            organisation_signature: organisation
                .sign(&with_possession.organisation_message().unwrap()),
            owner_signature: world.record.owner_signature().clone(),
        })
        .unwrap()
    }

    /// The code the device arrives at for the challenge of the world.
    ///
    /// It performs the device's half of the exchange — the pair of the attempt
    /// against the operator public half out of the ticket — and the same
    /// derivation, so a test can assert the two sides meet rather than assert
    /// against a constant. The long-lived key of the device appears nowhere in
    /// it, which is the property being pinned.
    pub(crate) fn device_side_code(world: &World) -> String {
        let attempt = software_key(EPHEMERAL_SEED);
        let secret = attempt
            .agree(world.ticket.ticket().public_key().as_bytes())
            .unwrap();
        let context = KeyContext::new(
            world.challenge.challenge().device_number(),
            world.ticket.context_hash().unwrap(),
        );
        let key = derive_key(&secret, &context).unwrap();
        let input = CodeInput {
            device_number: world.challenge.challenge().device_number(),
            nonce: world.challenge.challenge().nonce().as_str(),
            role_id: world.challenge.challenge().role_id(),
            level: world.challenge.challenge().level(),
            epoch: world.challenge.challenge().epoch(),
            engineer_id: world.challenge.challenge().engineer_id(),
        };
        compute_code(&key, &input, &world.params)
            .unwrap()
            .as_str()
            .to_owned()
    }
}
