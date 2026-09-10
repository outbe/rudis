use alloy_primitives::{keccak256, Address, U256};

use crate::error::Result;
use crate::storage::StorageHandle;

/// EVM-compatible dynamic bytes/string storage (Solidity layout).
///
/// - Short (<=31 bytes): data + length inline in one slot
/// - Long (>=32 bytes): length in base slot, data at keccak256(base_slot)
pub struct StorageBytes<'storage> {
    base_slot: U256,
    address: Address,
    storage: StorageHandle<'storage>,
}

impl<'storage> StorageBytes<'storage> {
    pub fn new(base_slot: U256, address: Address, storage: StorageHandle<'storage>) -> Self {
        Self {
            base_slot,
            address,
            storage,
        }
    }

    pub fn len(&self) -> Result<usize> {
        let raw = self.storage.sload(self.address, self.base_slot)?;
        Ok(decode_length(raw))
    }

    pub fn is_empty(&self) -> Result<bool> {
        self.len().map(|l| l == 0)
    }

    pub fn read(&self) -> Result<Vec<u8>> {
        let raw = self.storage.sload(self.address, self.base_slot)?;
        let length = decode_length(raw);
        if length == 0 {
            return Ok(Vec::new());
        }
        if is_short(raw) {
            let bytes = raw.to_be_bytes::<32>();
            Ok(bytes[..length].to_vec())
        } else {
            let data_start = data_slot(self.base_slot);
            let mut result = Vec::with_capacity(length);
            for i in 0..length.div_ceil(32) {
                let word = self
                    .storage
                    .sload(self.address, data_start + U256::from(i))?;
                let bytes = word.to_be_bytes::<32>();
                let take = (length - result.len()).min(32);
                result.extend_from_slice(&bytes[..take]);
            }
            Ok(result)
        }
    }

    pub fn write(&self, data: &[u8]) -> Result<()> {
        // Number of data-run slots the current value occupies (short form uses
        // none - the bytes live inline in the base slot).
        let old_len = self.len()?;
        let old_data_slots = if old_len <= 31 {
            0
        } else {
            old_len.div_ceil(32)
        };

        let length = data.len();
        let new_data_slots = if length <= 31 { 0 } else { length.div_ceil(32) };

        if length <= 31 {
            let mut word = [0u8; 32];
            word[..length].copy_from_slice(data);
            word[31] = (length * 2) as u8;
            self.storage
                .sstore(self.address, self.base_slot, U256::from_be_bytes(word))?;
        } else {
            self.storage
                .sstore(self.address, self.base_slot, U256::from(length * 2 + 1))?;
            let data_start = data_slot(self.base_slot);
            for i in 0..new_data_slots {
                let start = i * 32;
                let end = (start + 32).min(length);
                let mut word = [0u8; 32];
                word[..end - start].copy_from_slice(&data[start..end]);
                self.storage.sstore(
                    self.address,
                    data_start + U256::from(i),
                    U256::from_be_bytes(word),
                )?;
            }
        }

        // Zero any stale tail slots left by a longer previous value, so a
        // shrinking overwrite leaves no dead data in state.
        if old_data_slots > new_data_slots {
            let data_start = data_slot(self.base_slot);
            for i in new_data_slots..old_data_slots {
                self.storage
                    .sstore(self.address, data_start + U256::from(i), U256::ZERO)?;
            }
        }
        Ok(())
    }

    /// Writes only if the stored value differs from `data`. Returns `true`
    /// when a write was performed. The compare reads the current value once
    /// (SLOAD, cheap) to avoid an unnecessary full rewrite (SSTORE, ~50x the
    /// cost per slot) when the content is unchanged.
    pub fn write_if_changed(&self, data: &[u8]) -> Result<bool> {
        if self.read()? == data {
            return Ok(false);
        }
        self.write(data)?;
        Ok(true)
    }

    pub fn read_string(&self) -> Result<String> {
        self.read()
            .map(|b| String::from_utf8(b).unwrap_or_default())
    }

    pub fn write_string(&self, s: &str) -> Result<()> {
        self.write(s.as_bytes())
    }

    pub fn clear(&self) -> Result<()> {
        // Zero the data run first (long form), then the length/base slot, so no
        // dead payload slots survive a clear of a previously-long value.
        let old_len = self.len()?;
        if old_len > 31 {
            let data_start = data_slot(self.base_slot);
            for i in 0..old_len.div_ceil(32) {
                self.storage
                    .sstore(self.address, data_start + U256::from(i), U256::ZERO)?;
            }
        }
        self.storage
            .sstore(self.address, self.base_slot, U256::ZERO)
    }
}

fn decode_length(raw: U256) -> usize {
    if raw.is_zero() {
        return 0;
    }
    if is_short(raw) {
        (raw.to_be_bytes::<32>()[31] / 2) as usize
    } else {
        let len_u256: U256 = (raw - U256::from(1u64)) >> 1;
        len_u256.to::<usize>()
    }
}

fn is_short(raw: U256) -> bool {
    (raw & U256::from(1u64)).is_zero()
}

fn data_slot(base_slot: U256) -> U256 {
    U256::from_be_bytes(keccak256(base_slot.to_be_bytes::<32>()).0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::hashmap::HashMapStorageProvider;
    use crate::storage::StorageHandle;
    use alloy_primitives::address;

    fn with_storage<F: FnOnce(StorageHandle)>(f: F) {
        let mut provider = HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        f(storage);
    }

    const ADDR: Address = address!("0x0000000000000000000000000000000000001003");

    #[test]
    fn test_empty() {
        with_storage(|storage| {
            let sb = StorageBytes::new(U256::ZERO, ADDR, storage);
            assert_eq!(sb.len().unwrap(), 0);
            assert!(sb.is_empty().unwrap());
        });
    }

    #[test]
    fn test_short_string() {
        with_storage(|storage| {
            let sb = StorageBytes::new(U256::ZERO, ADDR, storage);
            sb.write_string("hello").unwrap();
            assert_eq!(sb.len().unwrap(), 5);
            assert_eq!(sb.read_string().unwrap(), "hello");
        });
    }

    #[test]
    fn test_short_31_bytes() {
        with_storage(|storage| {
            let sb = StorageBytes::new(U256::ZERO, ADDR, storage);
            let data = vec![0xABu8; 31];
            sb.write(&data).unwrap();
            assert_eq!(sb.len().unwrap(), 31);
            assert_eq!(sb.read().unwrap(), data);
        });
    }

    #[test]
    fn test_long_32_bytes() {
        with_storage(|storage| {
            let sb = StorageBytes::new(U256::ZERO, ADDR, storage);
            let data = vec![0xCDu8; 32];
            sb.write(&data).unwrap();
            assert_eq!(sb.len().unwrap(), 32);
            assert_eq!(sb.read().unwrap(), data);
        });
    }

    #[test]
    fn test_long_100_bytes() {
        with_storage(|storage| {
            let sb = StorageBytes::new(U256::ZERO, ADDR, storage);
            let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
            sb.write(&data).unwrap();
            assert_eq!(sb.len().unwrap(), 100);
            assert_eq!(sb.read().unwrap(), data);
        });
    }

    #[test]
    fn test_clear() {
        with_storage(|storage| {
            let sb = StorageBytes::new(U256::ZERO, ADDR, storage);
            sb.write_string("hello").unwrap();
            sb.clear().unwrap();
            assert!(sb.is_empty().unwrap());
        });
    }

    #[test]
    fn test_shrink_clears_stale_tail() {
        // A long value overwritten by a shorter one must leave no dead data in
        // the tail data-run slots.
        with_storage(|storage| {
            let sb = StorageBytes::new(U256::ZERO, ADDR, storage);
            let long: Vec<u8> = (0..100u16).map(|i| i as u8).collect();
            sb.write(&long).unwrap();
            let long_slots = 100usize.div_ceil(32);

            sb.write(b"short").unwrap();
            assert_eq!(sb.read().unwrap(), b"short");

            // Every former data-run slot is now zero.
            let data_start = data_slot(U256::ZERO);
            for i in 0..long_slots {
                let raw = sb.storage.sload(ADDR, data_start + U256::from(i)).unwrap();
                assert!(raw.is_zero(), "stale tail slot {i} not cleared");
            }
        });
    }

    #[test]
    fn test_long_to_shorter_long_clears_extra_tail() {
        with_storage(|storage| {
            let sb = StorageBytes::new(U256::ZERO, ADDR, storage);
            let long: Vec<u8> = (0..200u16).map(|i| i as u8).collect(); // 7 slots
            sb.write(&long).unwrap();
            let mid: Vec<u8> = (0..64u16).map(|i| i as u8).collect(); // 2 slots
            sb.write(&mid).unwrap();
            assert_eq!(sb.read().unwrap(), mid);

            let data_start = data_slot(U256::ZERO);
            for i in 2..200usize.div_ceil(32) {
                let raw = sb.storage.sload(ADDR, data_start + U256::from(i)).unwrap();
                assert!(raw.is_zero(), "stale slot {i} not cleared");
            }
        });
    }

    #[test]
    fn test_clear_zeroes_long_data_run() {
        with_storage(|storage| {
            let sb = StorageBytes::new(U256::ZERO, ADDR, storage);
            let long: Vec<u8> = vec![0xEE; 128];
            sb.write(&long).unwrap();
            sb.clear().unwrap();
            assert!(sb.is_empty().unwrap());

            let data_start = data_slot(U256::ZERO);
            for i in 0..128usize.div_ceil(32) {
                let raw = sb.storage.sload(ADDR, data_start + U256::from(i)).unwrap();
                assert!(raw.is_zero(), "clear left data slot {i} non-zero");
            }
        });
    }

    #[test]
    fn test_write_if_changed_skips_equal() {
        with_storage(|storage| {
            let sb = StorageBytes::new(U256::ZERO, ADDR, storage);
            assert!(sb.write_if_changed(b"hello").unwrap()); // first write
            assert!(!sb.write_if_changed(b"hello").unwrap()); // unchanged -> skip
            assert!(sb.write_if_changed(b"world").unwrap()); // changed -> write
            assert_eq!(sb.read().unwrap(), b"world");
        });
    }
}
