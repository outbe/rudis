//! Three-level radix-256 bitmap trie indexed by a 24-bit `id`.
//!
//! Verified against `pancakeswap/infinity-core@main` (2026-05-12):
//! - `src/pool-bin/libraries/math/TreeMath.sol`
//!
//! The Solidity API passes `level0` (bytes32, by value) plus two
//! `mapping(bytes32 => bytes32) storage` references for `level1` / `level2`.
//! The Rust analog is the [`BinTreeStorage`] trait - callers implement six
//! `read_*` / `write_*` methods over their own storage backing, and the
//! traversal helpers work in terms of the trait only.
//!
//! Each set leaf bit identifies a non-empty bin. A typical consumer walks
//! set bits in ascending order via [`find_first_left_inclusive`], processes
//! the bins at or below some threshold, then clears the bits via [`remove`].
//! Worst case per traversal step: 3 SLOAD (one per level), no loops at any
//! level - same big-O as Solidity LB.

use alloy_primitives::U256;

use crate::error::Result;
use crate::math::bit_math::{least_significant_bit, mask_from};
use crate::math::constants::MAX_BIN_ID;

// --- Address arithmetic (mirrors LB key2 = id >> 8, key1 = key2 >> 8) ------

/// Splits `id` into `(top, mid, lo)` byte indices.
/// - `top` (bits 16..24) == LB `key1` low byte == root bit index.
/// - `mid` (bits 8..16)  == LB `key2` low byte == mid bit index.
/// - `lo`  (bits 0..8)   == leaf bit index.
#[inline]
fn split(id: u32) -> (u8, u8, u8) {
    let top = ((id >> 16) & 0xFF) as u8;
    let mid = ((id >> 8) & 0xFF) as u8;
    let lo = (id & 0xFF) as u8;
    (top, mid, lo)
}

/// Leaf-map key == LB `key2 = id >> 8`. Stored as u32; the high 16 bits are
/// always zero.
#[inline]
fn leaf_key(top: u8, mid: u8) -> u32 {
    ((top as u32) << 8) | (mid as u32)
}

/// Mid-map key == top byte. Stored as u32 for storage-key uniformity.
#[inline]
fn mid_key(top: u8) -> u32 {
    top as u32
}

/// Packs `(top, mid, lo)` back into a 24-bit id.
#[inline]
fn assemble(top: u8, mid: u8, lo: u8) -> u32 {
    ((top as u32) << 16) | ((mid as u32) << 8) | (lo as u32)
}

// --- Storage abstraction ---------------------------------------------------

/// Abstraction over the three storage slots of a PancakeSwap-style bin tree.
/// Implementations expose:
/// - `root` - one `U256` word (mirrors Solidity `bytes32 level0`).
/// - `mid` - one `U256` word per top byte (mirrors `mapping level1`).
/// - `leaf` - one `U256` word per `(top, mid)` pair (mirrors `mapping level2`).
///
/// All methods take `&self`: callers typically back this with storage primitives
/// that route writes through interior-mutable handles (e.g.
/// `outbe_primitives::storage::dsl::{Value, Map}`).
pub trait BinTreeStorage {
    fn read_root(&self) -> Result<U256>;
    fn write_root(&self, value: U256) -> Result<()>;
    fn read_mid(&self, key: u32) -> Result<U256>;
    fn write_mid(&self, key: u32, value: U256) -> Result<()>;
    fn read_leaf(&self, key: u32) -> Result<U256>;
    fn write_leaf(&self, key: u32, value: U256) -> Result<()>;
}

// --- TreeMath port ---------------------------------------------------------

/// Mirrors `TreeMath.contains(level2, id)` (TreeMath.sol L11-14).
/// Returns true iff `id` is set in the leaf bitmap.
pub fn contains<S: BinTreeStorage>(s: &S, id: u32) -> Result<bool> {
    let (top, mid, lo) = split(id);
    let leaf = s.read_leaf(leaf_key(top, mid))?;
    Ok(!(leaf & (U256::ONE << (lo as usize))).is_zero())
}

/// Mirrors `TreeMath.add(level0, level1, level2, id)` (TreeMath.sol L18-39).
/// Sets the bit; cascades to mid and root if the lower-level word transitions
/// from zero. Returns `true` iff the bit transitioned 0 -> 1 (i.e., this was
/// a real insertion, not a re-insertion).
pub fn add<S: BinTreeStorage>(s: &S, id: u32) -> Result<bool> {
    let (top, mid, lo) = split(id);
    let leaf_k = leaf_key(top, mid);

    let leaves = s.read_leaf(leaf_k)?;
    let new_leaves = leaves | (U256::ONE << (lo as usize));
    if leaves == new_leaves {
        return Ok(false);
    }
    s.write_leaf(leaf_k, new_leaves)?;

    if leaves.is_zero() {
        // Leaf transitioned {} -> non-{} - propagate to mid.
        let mid_k = mid_key(top);
        let mid_word = s.read_mid(mid_k)?;
        let new_mid = mid_word | (U256::ONE << (mid as usize));
        s.write_mid(mid_k, new_mid)?;

        if mid_word.is_zero() {
            // Mid transitioned {} -> non-{} - propagate to root.
            let root = s.read_root()?;
            let new_root = root | (U256::ONE << (top as usize));
            s.write_root(new_root)?;
        }
    }
    Ok(true)
}

/// Mirrors `TreeMath.remove(level0, level1, level2, id)`
/// (TreeMath.sol L45-65). Clears the bit; cascades to mid and root if the
/// lower-level word transitions to zero. Returns `true` iff the bit
/// transitioned 1 -> 0.
pub fn remove<S: BinTreeStorage>(s: &S, id: u32) -> Result<bool> {
    let (top, mid, lo) = split(id);
    let leaf_k = leaf_key(top, mid);

    let leaves = s.read_leaf(leaf_k)?;
    let new_leaves = leaves & !(U256::ONE << (lo as usize));
    if leaves == new_leaves {
        return Ok(false);
    }
    s.write_leaf(leaf_k, new_leaves)?;

    if !new_leaves.is_zero() {
        return Ok(true);
    }
    // Leaf went to zero - clear our bit in mid.
    let mid_k = mid_key(top);
    let mid_word = s.read_mid(mid_k)?;
    let new_mid = mid_word & !(U256::ONE << (mid as usize));
    s.write_mid(mid_k, new_mid)?;

    if !new_mid.is_zero() {
        return Ok(true);
    }
    // Mid went to zero - clear our bit in root.
    let root = s.read_root()?;
    let new_root = root & !(U256::ONE << (top as usize));
    s.write_root(new_root)?;
    Ok(true)
}

/// **Inclusive variant** of `TreeMath.findFirstLeft` (TreeMath.sol L96-127).
/// Returns the smallest set `id` >= `start_id`, or `None` if no such id
/// exists.
///
/// Differs from LB exactly at the leaf level: LB clears bits `[0..lo+1)`
/// (strict-greater); we clear bits `[0..lo)`, which keeps `lo` itself as a
/// candidate. This avoids a preceding `contains(start_id)` SLOAD on every
/// iteration of a typical drain loop. The mid and root descents remain
/// strict-greater because by the time we ascend, we've already exhausted
/// the start leaf.
pub fn find_first_left_inclusive<S: BinTreeStorage>(s: &S, start_id: u32) -> Result<Option<u32>> {
    if start_id > MAX_BIN_ID {
        return Ok(None);
    }
    let (top0, mid0, lo0) = split(start_id);

    // 1. Try the leaf at (top0, mid0), inclusive of bit `lo0`.
    let leaf = s.read_leaf(leaf_key(top0, mid0))?;
    let leaf_masked = mask_from(leaf, lo0);
    if !leaf_masked.is_zero() {
        let bit = least_significant_bit(leaf_masked) as u8;
        return Ok(Some(assemble(top0, mid0, bit)));
    }

    // 2. Try the mid at top0, strict-greater than mid0.
    let mid_word = s.read_mid(mid_key(top0))?;
    let mid_threshold = mid0.saturating_add(1);
    if mid0 != u8::MAX {
        let mid_masked = mask_from(mid_word, mid_threshold);
        if !mid_masked.is_zero() {
            let mid_bit = least_significant_bit(mid_masked) as u8;
            // Descend: leaf at (top0, mid_bit) is non-empty by invariant.
            let leaf2 = s.read_leaf(leaf_key(top0, mid_bit))?;
            let lo_bit = least_significant_bit(leaf2) as u8;
            return Ok(Some(assemble(top0, mid_bit, lo_bit)));
        }
    }

    // 3. Try the root, strict-greater than top0.
    if top0 == u8::MAX {
        return Ok(None);
    }
    let top_threshold = top0.saturating_add(1);
    let root = s.read_root()?;
    let root_masked = mask_from(root, top_threshold);
    if root_masked.is_zero() {
        return Ok(None);
    }
    let top_bit = least_significant_bit(root_masked) as u8;
    let mid2 = s.read_mid(mid_key(top_bit))?;
    let mid_bit = least_significant_bit(mid2) as u8;
    let leaf3 = s.read_leaf(leaf_key(top_bit, mid_bit))?;
    let lo_bit = least_significant_bit(leaf3) as u8;
    Ok(Some(assemble(top_bit, mid_bit, lo_bit)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    /// Minimal in-memory `BinTreeStorage` backed by a `Cell<U256>` for the
    /// root and `BTreeMap<u32, U256>` for mid/leaf. Test-only.
    #[derive(Default)]
    struct TestStore {
        root: Cell<U256>,
        mid: RefCell<BTreeMap<u32, U256>>,
        leaf: RefCell<BTreeMap<u32, U256>>,
    }

    impl BinTreeStorage for TestStore {
        fn read_root(&self) -> Result<U256> {
            Ok(self.root.get())
        }
        fn write_root(&self, value: U256) -> Result<()> {
            self.root.set(value);
            Ok(())
        }
        fn read_mid(&self, key: u32) -> Result<U256> {
            Ok(self.mid.borrow().get(&key).copied().unwrap_or(U256::ZERO))
        }
        fn write_mid(&self, key: u32, value: U256) -> Result<()> {
            self.mid.borrow_mut().insert(key, value);
            Ok(())
        }
        fn read_leaf(&self, key: u32) -> Result<U256> {
            Ok(self.leaf.borrow().get(&key).copied().unwrap_or(U256::ZERO))
        }
        fn write_leaf(&self, key: u32, value: U256) -> Result<()> {
            self.leaf.borrow_mut().insert(key, value);
            Ok(())
        }
    }

    fn with_store<F: FnOnce(&TestStore)>(f: F) {
        let store = TestStore::default();
        f(&store);
    }

    #[test]
    fn empty_tree_contains_returns_false() {
        with_store(|s| {
            assert!(!contains(s, 0).unwrap());
            assert!(!contains(s, 12345).unwrap());
            assert!(!contains(s, MAX_BIN_ID).unwrap());
        });
    }

    #[test]
    fn add_then_contains_returns_true() {
        with_store(|s| {
            assert!(add(s, 100).unwrap());
            assert!(contains(s, 100).unwrap());
            assert!(!contains(s, 99).unwrap());
            assert!(!contains(s, 101).unwrap());
        });
    }

    #[test]
    fn add_idempotent() {
        with_store(|s| {
            assert!(add(s, 50).unwrap());
            assert!(!add(s, 50).unwrap());
            assert!(contains(s, 50).unwrap());
        });
    }

    #[test]
    fn remove_clears_bit() {
        with_store(|s| {
            add(s, 200).unwrap();
            assert!(remove(s, 200).unwrap());
            assert!(!contains(s, 200).unwrap());
            // Removing an unset bit is a no-op.
            assert!(!remove(s, 200).unwrap());
        });
    }

    #[test]
    fn remove_cascades_to_root_when_only_bit() {
        with_store(|s| {
            // id = 0x010203 -> top=1, mid=2, lo=3.
            add(s, 0x010203).unwrap();
            assert_eq!(s.read_root().unwrap(), U256::ONE << 1);
            remove(s, 0x010203).unwrap();
            assert_eq!(s.read_root().unwrap(), U256::ZERO);
            assert_eq!(s.read_mid(mid_key(1)).unwrap(), U256::ZERO);
            assert_eq!(s.read_leaf(leaf_key(1, 2)).unwrap(), U256::ZERO);
        });
    }

    #[test]
    fn add_does_not_disturb_neighbours_in_same_leaf() {
        with_store(|s| {
            add(s, 100).unwrap();
            add(s, 101).unwrap();
            // Both fit in leaf_key(0,0) at bits 100, 101.
            let leaf = s.read_leaf(leaf_key(0, 0)).unwrap();
            assert_eq!(leaf, (U256::ONE << 100) | (U256::ONE << 101));

            remove(s, 100).unwrap();
            assert!(contains(s, 101).unwrap());
            let leaf = s.read_leaf(leaf_key(0, 0)).unwrap();
            assert_eq!(leaf, U256::ONE << 101);
        });
    }

    #[test]
    fn find_first_empty_returns_none() {
        with_store(|s| {
            assert_eq!(find_first_left_inclusive(s, 0).unwrap(), None);
            assert_eq!(find_first_left_inclusive(s, 12345).unwrap(), None);
        });
    }

    #[test]
    fn find_first_inclusive_returns_self_when_set() {
        with_store(|s| {
            add(s, 50).unwrap();
            assert_eq!(find_first_left_inclusive(s, 50).unwrap(), Some(50));
            assert_eq!(find_first_left_inclusive(s, 49).unwrap(), Some(50));
            // Past the only set bit -> None.
            assert_eq!(find_first_left_inclusive(s, 51).unwrap(), None);
        });
    }

    #[test]
    fn find_first_within_same_leaf() {
        with_store(|s| {
            add(s, 30).unwrap();
            add(s, 70).unwrap();
            assert_eq!(find_first_left_inclusive(s, 0).unwrap(), Some(30));
            assert_eq!(find_first_left_inclusive(s, 31).unwrap(), Some(70));
            assert_eq!(find_first_left_inclusive(s, 71).unwrap(), None);
        });
    }

    #[test]
    fn find_first_crosses_mid_boundary() {
        with_store(|s| {
            // 300 = 0x12C -> top=0, mid=1, lo=44.
            // 1000 = 0x3E8 -> top=0, mid=3, lo=232.
            add(s, 300).unwrap();
            add(s, 1000).unwrap();
            assert_eq!(find_first_left_inclusive(s, 301).unwrap(), Some(1000));
        });
    }

    #[test]
    fn find_first_crosses_root_boundary() {
        with_store(|s| {
            // 0x000050 -> top=0, mid=0, lo=80.
            // 0x010001 -> top=1, mid=0, lo=1.
            add(s, 0x000050).unwrap();
            add(s, 0x010001).unwrap();
            assert_eq!(
                find_first_left_inclusive(s, 0x000051).unwrap(),
                Some(0x010001)
            );
        });
    }

    #[test]
    fn find_first_at_max_bin_id() {
        with_store(|s| {
            add(s, MAX_BIN_ID).unwrap();
            assert_eq!(
                find_first_left_inclusive(s, MAX_BIN_ID).unwrap(),
                Some(MAX_BIN_ID)
            );
            assert_eq!(find_first_left_inclusive(s, 0).unwrap(), Some(MAX_BIN_ID));
        });
    }

    #[test]
    fn find_first_above_max_returns_none() {
        with_store(|s| {
            add(s, MAX_BIN_ID).unwrap();
            assert_eq!(find_first_left_inclusive(s, MAX_BIN_ID + 1).unwrap(), None);
        });
    }

    #[test]
    fn ascending_walk_yields_sorted_sequence() {
        with_store(|s| {
            let ids = [5u32, 100, 200, 1024, 65_535, 65_536, 1_000_000];
            for &b in &ids {
                add(s, b).unwrap();
            }
            let mut cursor = 0u32;
            let mut visited = Vec::new();
            while let Some(b) = find_first_left_inclusive(s, cursor).unwrap() {
                visited.push(b);
                cursor = match b.checked_add(1) {
                    Some(c) if c <= MAX_BIN_ID => c,
                    _ => break,
                };
            }
            assert_eq!(visited, ids);
        });
    }
}
