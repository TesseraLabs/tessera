//! The single canonical body layout. Counts and lengths are bounded before allocation.

use super::{
    RoleBounds, RoleBoundsFields, WorkAuthorisationError as Error, WorkIntent, WorkIntentFields,
    MAX_BODY_BYTES, MAX_ROLE_ROWS, MAX_TAGS, SIGNING_LABEL,
};
use crate::mac::IntegrityLabel;
use crate::role::{RoleId, RoleOs};
use tessera_codes_contract::device_number::CheckedDeviceNumber;
use tessera_codes_contract::engineer::{Devices, MAX_DEVICES};
use uuid::Uuid;

pub(super) fn encode(intent: &WorkIntent) -> Result<Vec<u8>, Error> {
    let fields = intent.fields();
    let mut writer = Writer(Vec::new());
    writer.bytes(SIGNING_LABEL.as_bytes())?;
    writer.bytes(&2_u32.to_be_bytes())?;
    for id in [
        fields.authorisation_id,
        fields.fleet_id,
        fields.tenant_node_id,
    ] {
        writer.bytes(id.as_bytes())?;
    }
    writer.bytes(fields.engineer.as_bytes())?;
    writer.bytes(fields.organisation.as_bytes())?;
    writer.bytes(&fields.key_fingerprint)?;
    match &fields.devices {
        Devices::Any => {
            writer.bytes(&[0])?;
            writer.count(0)?;
        }
        Devices::Only(list) => {
            writer.bytes(&[1])?;
            writer.count(list.as_slice().len())?;
            for device in list.as_slice() {
                writer.bytes(device.significant().as_bytes())?;
            }
        }
    }
    writer.count(fields.tags.len())?;
    for tag in &fields.tags {
        writer.bytes(tag.as_bytes())?;
    }
    writer.bytes(&fields.not_before.to_be_bytes())?;
    writer.bytes(&fields.not_after.to_be_bytes())?;
    writer.count(fields.roles.len())?;
    for row in &fields.roles {
        let row = row.fields();
        writer.bytes(row.role_id.as_str().as_bytes())?;
        writer.bytes(row.target_os.as_str().as_bytes())?;
        writer.bytes(row.stream_id.as_bytes())?;
        writer.bytes(&row.trust_sha256)?;
        writer.bytes(&row.bundle_version.to_be_bytes())?;
        writer.bytes(&row.manifest_sha256)?;
        writer.bytes(&row.slice_version.to_be_bytes())?;
        writer.bytes(&row.slice_sha256)?;
        writer.bytes(&[u8::from(row.codes_max_level.is_some())])?;
        if let Some(level) = row.codes_max_level {
            writer.bytes(&[level])?;
        }
        writer.bytes(&[u8::from(row.certificate.is_some())])?;
        if let Some(label) = row.certificate {
            writer.bytes(&label.level.to_be_bytes())?;
            writer.bytes(&label.categories.to_be_bytes())?;
        }
    }
    Ok(writer.0)
}

pub(super) fn decode(bytes: &[u8]) -> Result<WorkIntent, Error> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(Error::Oversize("body"));
    }
    let mut reader = Reader(bytes);
    if reader.bytes(SIGNING_LABEL.len())? != SIGNING_LABEL.as_bytes() {
        return Err(Error::Invalid("label"));
    }
    if u32::from_be_bytes(reader.array()?) != 2 {
        return Err(Error::Invalid("schema_version"));
    }
    let authorisation_id = Uuid::from_bytes(reader.array()?);
    let fleet_id = Uuid::from_bytes(reader.array()?);
    let tenant_node_id = Uuid::from_bytes(reader.array()?);
    let engineer = reader.text(128)?;
    let organisation = reader.text(128)?;
    let key_fingerprint = reader.array()?;
    let device_kind = reader.byte()?;
    let device_count = reader.count(MAX_DEVICES)?;
    let devices = match (device_kind, device_count) {
        (0, 0) => Devices::Any,
        (1, 1..=MAX_DEVICES) => {
            let mut numbers: Vec<CheckedDeviceNumber> = Vec::with_capacity(device_count);
            for _ in 0..device_count {
                let value = reader.text(64)?;
                let number =
                    CheckedDeviceNumber::parse(&value).map_err(|_| Error::Invalid("device"))?;
                if number.significant() != value
                    || numbers
                        .last()
                        .is_some_and(|old| old.significant() >= value.as_str())
                {
                    return Err(Error::Invalid("device_order_or_spelling"));
                }
                numbers.push(number);
            }
            Devices::only(&numbers).map_err(|_| Error::Invalid("devices"))?
        }
        _ => return Err(Error::Invalid("devices")),
    };
    let tag_count = reader.count(MAX_TAGS)?;
    let mut tags = Vec::with_capacity(tag_count);
    for _ in 0..tag_count {
        tags.push(reader.text(256)?);
    }
    let not_before = u64::from_be_bytes(reader.array()?);
    let not_after = u64::from_be_bytes(reader.array()?);
    let role_count = reader.count(MAX_ROLE_ROWS)?;
    let mut roles = Vec::with_capacity(role_count);
    for _ in 0..role_count {
        roles.push(read_row(&mut reader)?);
    }
    if !reader.0.is_empty() {
        return Err(Error::Invalid("trailing_body"));
    }
    WorkIntent::new(WorkIntentFields {
        authorisation_id,
        fleet_id,
        tenant_node_id,
        engineer,
        organisation,
        key_fingerprint,
        devices,
        tags,
        not_before,
        not_after,
        roles,
    })
}

fn read_row(reader: &mut Reader<'_>) -> Result<RoleBounds, Error> {
    let role_id = RoleId::new(&reader.text(16)?).map_err(|_| Error::Invalid("role_id"))?;
    let target_os = match reader.text(7)?.as_str() {
        "astra" => RoleOs::Astra,
        "linux" => RoleOs::Linux,
        "windows" => RoleOs::Windows,
        _ => return Err(Error::Invalid("target_os")),
    };
    let stream_id = reader.text(128)?;
    let trust_sha256 = reader.array()?;
    let bundle_version = u64::from_be_bytes(reader.array()?);
    let manifest_sha256 = reader.array()?;
    let slice_version = u32::from_be_bytes(reader.array()?);
    let slice_sha256 = reader.array()?;
    let codes_max_level = match reader.byte()? {
        0 => None,
        1 => Some(reader.byte()?),
        _ => return Err(Error::Invalid("codes_present")),
    };
    let certificate = match reader.byte()? {
        0 => None,
        1 => Some(IntegrityLabel {
            level: i8::from_be_bytes(reader.array()?),
            categories: u64::from_be_bytes(reader.array()?),
        }),
        _ => return Err(Error::Invalid("certificate_present")),
    };
    RoleBounds::new(RoleBoundsFields {
        role_id,
        target_os,
        stream_id,
        trust_sha256,
        bundle_version,
        manifest_sha256,
        slice_version,
        slice_sha256,
        codes_max_level,
        certificate,
    })
}

struct Writer(Vec<u8>);
impl Writer {
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let size = self
            .0
            .len()
            .checked_add(4)
            .and_then(|n| n.checked_add(bytes.len()))
            .ok_or(Error::Oversize("body"))?;
        if size > MAX_BODY_BYTES {
            return Err(Error::Oversize("body"));
        }
        let length = u32::try_from(bytes.len()).map_err(|_| Error::Oversize("field"))?;
        self.0.extend_from_slice(&length.to_be_bytes());
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn count(&mut self, count: usize) -> Result<(), Error> {
        self.bytes(
            &u32::try_from(count)
                .map_err(|_| Error::Oversize("count"))?
                .to_be_bytes(),
        )
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        let prefix: [u8; 4] = self
            .0
            .get(..4)
            .ok_or(Error::Invalid("truncated_length"))?
            .try_into()
            .map_err(|_| Error::Invalid("length"))?;
        let length =
            usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::Oversize("field"))?;
        if length > maximum {
            return Err(Error::Oversize("field"));
        }
        let remaining = self.0.get(4..).ok_or(Error::Invalid("length"))?;
        let value = remaining
            .get(..length)
            .ok_or(Error::Invalid("truncated_field"))?;
        self.0 = remaining.get(length..).ok_or(Error::Invalid("length"))?;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| Error::Invalid("field_width"))
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(u8::from_be_bytes(self.array()?))
    }
    fn text(&mut self, maximum: usize) -> Result<String, Error> {
        std::str::from_utf8(self.bytes(maximum)?)
            .map(str::to_owned)
            .map_err(|_| Error::Invalid("utf8"))
    }
    fn count(&mut self, maximum: usize) -> Result<usize, Error> {
        let count = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| Error::Oversize("count"))?;
        if count > maximum {
            return Err(Error::Oversize("count"));
        }
        Ok(count)
    }
}
