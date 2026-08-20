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
    use tessera_codes_contract::challenge::Challenge;
    use tessera_codes_contract::code::compute_code;
    use tessera_codes_contract::device_number::CheckedDeviceNumber;
    use tessera_codes_contract::key::{derive_key, Epoch, KeyAgreement as _, KeyContext};
    use tessera_codes_contract::nonce::Nonce;
    use tessera_codes_contract::params::FleetParams;
    use tessera_codes_contract::profile::AlgorithmProfile;
    use tessera_codes_contract::registry::DeviceRecord;
    use tessera_codes_contract::signature::{PublicKey, Signature};
    use tessera_codes_contract::ticket::{
        OperatorTicket, SignedTicket, TicketNumber, TicketScope, TicketScopeInput,
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

    /// Key epoch of the device in the fixture world.
    pub(crate) const EPOCH: u32 = 7;

    /// Moment the fixture world claims.
    pub(crate) const NOW: ClaimedTime = ClaimedTime::new(1_800_000_000);

    /// Moment the fixture ticket stops being valid.
    pub(crate) const TICKET_NOT_AFTER: u64 = 1_800_003_600;

    /// The fleet the tests work in.
    pub(crate) struct World {
        /// The challenge the device reads out.
        pub(crate) challenge: Challenge,
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

    /// A device number no fixture receipt was written for.
    pub(crate) fn other_device_number() -> CheckedDeviceNumber {
        CheckedDeviceNumber::from_body("77-000999").unwrap()
    }

    /// The values a fixture challenge is built from.
    pub(crate) struct ChallengeInput {
        /// Device number without its check character.
        pub(crate) device_body: String,
        /// Key epoch.
        pub(crate) epoch: u32,
        /// Nonce counter.
        pub(crate) counter: u64,
        /// Nonce tail.
        pub(crate) tail: String,
        /// Role being asked for.
        pub(crate) role_id: String,
        /// Level being asked for.
        pub(crate) level: u32,
        /// Operator handling the call.
        pub(crate) operator_id: String,
    }

    impl Default for ChallengeInput {
        fn default() -> Self {
            Self {
                device_body: "77-000123".to_owned(),
                epoch: EPOCH,
                counter: 1,
                tail: "4711".to_owned(),
                role_id: "ops.dc.senior".to_owned(),
                level: 2,
                operator_id: "op-42".to_owned(),
            }
        }
    }

    /// Builds a challenge with one thing changed.
    pub(crate) fn challenge_with(edit: impl FnOnce(&mut ChallengeInput)) -> Challenge {
        let mut input = ChallengeInput::default();
        edit(&mut input);
        let params = FleetParams::defaults();
        Challenge::new(
            CheckedDeviceNumber::from_body(&input.device_body).unwrap(),
            Epoch::new(input.epoch),
            Nonce::new(input.counter, &input.tail, &params).unwrap(),
            &input.role_id,
            Level::new(input.level),
            &input.operator_id,
        )
        .unwrap()
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
        let ticket = OperatorTicket::new(
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
            challenge: challenge_with(|_| {}),
            record,
            ticket,
            params: FleetParams::defaults(),
            device_scope: DeviceScope {
                tags: vec!["dc-1".to_owned()],
                region: "ru-central".to_owned(),
            },
            anchors: Anchors::new(authority.anchor())
                .with_organisation("acme", organisation.anchor()),
            operator_key: software_key(OPERATOR_SEED),
        }
    }

    /// Builds a device record signed by `organisation`, with a proof of
    /// possession made by `device`.
    ///
    /// The record is assembled twice: the bytes both signatures cover are the
    /// body, which a record has to exist to encode.
    fn signed_record(organisation: &FixtureSigner, device: &FixtureSigner) -> DeviceRecord {
        let placeholder = Signature::new(vec![0x00]).unwrap();
        let draft = DeviceRecord::new(
            device_number(),
            PublicKey::new(device.public_point()).unwrap(),
            Epoch::new(EPOCH),
            "acme",
            placeholder.clone(),
            placeholder,
        )
        .unwrap();
        let organisation_signature = organisation.sign(&draft.encode().unwrap());
        let possession_signature = device.sign(&draft.possession_message().unwrap());
        DeviceRecord::new(
            device_number(),
            PublicKey::new(device.public_point()).unwrap(),
            Epoch::new(EPOCH),
            "acme",
            organisation_signature,
            possession_signature,
        )
        .unwrap()
    }

    /// The same record with an organisation signature that does not hold.
    pub(crate) fn record_with_broken_organisation_signature(world: &World) -> DeviceRecord {
        let organisation = signer(ORGANISATION_SEED);
        DeviceRecord::new(
            device_number(),
            world.record.public_key().clone(),
            Epoch::new(EPOCH),
            "acme",
            organisation.sign(b"some other document"),
            world.record.possession_signature().clone(),
        )
        .unwrap()
    }

    /// The same record whose proof of possession was made by another key.
    pub(crate) fn record_with_foreign_possession_signature(world: &World) -> DeviceRecord {
        let organisation = signer(ORGANISATION_SEED);
        let draft = DeviceRecord::new(
            device_number(),
            world.record.public_key().clone(),
            Epoch::new(EPOCH),
            "acme",
            Signature::new(vec![0x00]).unwrap(),
            Signature::new(vec![0x00]).unwrap(),
        )
        .unwrap();
        DeviceRecord::new(
            device_number(),
            world.record.public_key().clone(),
            Epoch::new(EPOCH),
            "acme",
            organisation.sign(&draft.encode().unwrap()),
            // Signed with the organisation key: a valid signature by a key that
            // is not the device's, which is exactly what an enrolled key nobody
            // holds looks like.
            organisation.sign(&draft.possession_message().unwrap()),
        )
        .unwrap()
    }

    /// The code the device arrives at for the challenge of the world.
    ///
    /// It performs the device's half of the exchange — its own key against the
    /// operator public half out of the ticket — and the same derivation, so a
    /// test can assert the two sides meet rather than assert against a constant.
    pub(crate) fn device_side_code(world: &World) -> String {
        let device = software_key(DEVICE_SEED);
        let secret = device
            .agree(world.ticket.ticket().public_key().as_bytes())
            .unwrap();
        let context = KeyContext::new(
            world.challenge.device_number(),
            world.challenge.epoch(),
            world.ticket.context_hash().unwrap(),
        );
        let key = derive_key(&secret, &context).unwrap();
        let input = CodeInput {
            device_number: world.challenge.device_number(),
            nonce: world.challenge.nonce().as_str(),
            role_id: world.challenge.role_id(),
            level: world.challenge.level(),
        };
        compute_code(&key, &input, &world.params)
            .unwrap()
            .as_str()
            .to_owned()
    }
}
