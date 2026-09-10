//! Private, bounded disk representation. Canonical domain bodies stay opaque.

use std::collections::BTreeMap;

use crate::{
    Key, Namespace, StorageError, StorageMetadata, StoredValue, Value, MAX_METADATA_ENTRIES,
    MAX_METADATA_KEY_BYTES, MAX_METADATA_VALUE_BYTES, MAX_SCAN_PAGE_VALUE_BYTES, MAX_VALUE_BYTES,
};

const RECORD_MAGIC: &[u8; 4] = b"OSV1";

pub(crate) fn namespace_prefix(namespace: &Namespace) -> Vec<u8> {
    let mut bytes = vec![1, namespace.as_str().len() as u8];
    bytes.extend_from_slice(namespace.as_str().as_bytes());
    bytes
}

pub(crate) fn encode_key(namespace: &Namespace, key: &Key) -> Vec<u8> {
    let mut bytes = namespace_prefix(namespace);
    bytes.extend_from_slice(key.as_bytes());
    bytes
}

pub(crate) fn encode_record(record: &StoredValue) -> Result<Vec<u8>, StorageError> {
    let value = record.value.as_bytes();
    let metadata_bytes = record
        .metadata
        .as_ref()
        .map_or(0, StorageMetadata::encoded_len);
    if value.len() + metadata_bytes > MAX_SCAN_PAGE_VALUE_BYTES {
        return Err(StorageError::invalid_argument(
            "stored record exceeds scan page bound",
        ));
    }
    let mut encoded = Vec::with_capacity(10 + value.len() + metadata_bytes);
    encoded.extend_from_slice(RECORD_MAGIC);
    encoded.extend_from_slice(&(value.len() as u32).to_be_bytes());
    encoded.extend_from_slice(value);
    match &record.metadata {
        None => encoded.push(0),
        Some(metadata) => {
            encoded.push(1);
            encoded.push(metadata.len() as u8);
            for (key, value) in metadata.iter() {
                encoded.push(key.len() as u8);
                encoded.extend_from_slice(key.as_bytes());
                encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
                encoded.extend_from_slice(value.as_bytes());
            }
        }
    }
    Ok(encoded)
}

pub(crate) fn decode_record(mut encoded: &[u8]) -> Result<StoredValue, StorageError> {
    if take(&mut encoded, 4)? != RECORD_MAGIC {
        return Err(corrupt("unknown record version"));
    }
    let len = u32::from_be_bytes(take(&mut encoded, 4)?.try_into().expect("four bytes")) as usize;
    if len > MAX_VALUE_BYTES {
        return Err(corrupt("value length exceeds bound"));
    }
    let value =
        Value::new(take(&mut encoded, len)?.to_vec()).map_err(|_| corrupt("invalid value"))?;
    let metadata = match take(&mut encoded, 1)?[0] {
        0 => None,
        1 => {
            let count = usize::from(take(&mut encoded, 1)?[0]);
            if count > MAX_METADATA_ENTRIES {
                return Err(corrupt("too many metadata entries"));
            }
            let mut entries = BTreeMap::new();
            let mut previous = None::<String>;
            for _ in 0..count {
                let len = usize::from(take(&mut encoded, 1)?[0]);
                if len == 0 || len > MAX_METADATA_KEY_BYTES {
                    return Err(corrupt("metadata key length"));
                }
                let key = std::str::from_utf8(take(&mut encoded, len)?)
                    .map_err(|_| corrupt("metadata key encoding"))?
                    .to_owned();
                if previous.as_ref().is_some_and(|previous| previous >= &key) {
                    return Err(corrupt("metadata keys are not strictly ordered"));
                }
                previous = Some(key.clone());
                let len = usize::from(u16::from_be_bytes(
                    take(&mut encoded, 2)?.try_into().expect("two bytes"),
                ));
                if len == 0 || len > MAX_METADATA_VALUE_BYTES {
                    return Err(corrupt("metadata value length"));
                }
                let value = std::str::from_utf8(take(&mut encoded, len)?)
                    .map_err(|_| corrupt("metadata value encoding"))?
                    .to_owned();
                entries.insert(key, value);
            }
            Some(if entries.is_empty() {
                StorageMetadata::default()
            } else {
                StorageMetadata::new(entries).map_err(|_| corrupt("invalid metadata"))?
            })
        }
        _ => return Err(corrupt("metadata presence tag")),
    };
    if !encoded.is_empty() {
        return Err(corrupt("trailing record bytes"));
    }
    if value.as_bytes().len() + metadata.as_ref().map_or(0, StorageMetadata::encoded_len)
        > MAX_SCAN_PAGE_VALUE_BYTES
    {
        return Err(corrupt("record exceeds scan page bound"));
    }
    Ok(StoredValue { value, metadata })
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], StorageError> {
    let (head, tail) = bytes
        .split_at_checked(count)
        .ok_or_else(|| corrupt("truncated record"))?;
    *bytes = tail;
    Ok(head)
}

fn corrupt(message: &str) -> StorageError {
    StorageError::Corruption(format!("RocksDB storage codec: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_codec_preserves_metadata_presence_and_opaque_bytes() {
        for metadata in [
            None,
            Some(StorageMetadata::default()),
            Some(StorageMetadata::new(BTreeMap::from([("block".into(), "42".into())])).unwrap()),
        ] {
            let record = StoredValue {
                value: Value::new(vec![0, 255, 1]).unwrap(),
                metadata,
            };
            let encoded = encode_record(&record).unwrap();
            assert_eq!(decode_record(&encoded).unwrap(), record);
            for len in 0..encoded.len() {
                assert!(decode_record(&encoded[..len]).is_err());
            }
            let mut trailing = encoded;
            trailing.push(0);
            assert!(decode_record(&trailing).is_err());
        }
    }

    #[test]
    fn malformed_lengths_versions_and_metadata_are_corruption() {
        for bytes in [
            b"OSV2\0\0\0\0\0".as_slice(),
            b"OSV1\xff\xff\xff\xff",
            b"OSV1\0\0\0\0\x02",
            b"OSV1\0\0\0\0\x01\xff",
        ] {
            assert_eq!(
                decode_record(bytes).unwrap_err().kind(),
                crate::StorageErrorKind::Corruption
            );
        }
    }
}
