use alloy_primitives::{address, keccak256, Address, U256};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;

use crate::status;
use crate::GovernanceContract;

const AUTH: Address = address!("0x1111111111111111111111111111111111111111");
const OTHER: Address = address!("0x2222222222222222222222222222222222222222");
const AUTHOR: Address = address!("0x3333333333333333333333333333333333333333");

fn with_governance<R>(f: impl FnOnce(&mut GovernanceContract) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut storage, |storage| {
        let mut gov = GovernanceContract::new(storage.clone());
        // Seed one authority directly (as the genesis alloc does).
        gov.authorities.write(&AUTH, true).unwrap();
        f(&mut gov)
    })
}

// ---------------------------------------------------------------- canon ---

#[test]
fn canon_roundtrip_and_versioning() {
    with_governance(|gov| {
        // empty initial state
        let (text, ver, hash) = gov.get_canon().unwrap();
        assert_eq!(text, "");
        assert_eq!(ver, 0);
        assert!(hash.is_zero());

        // first update -> version 1
        let v = gov.update_canon(AUTH, "gain takes time").unwrap();
        assert_eq!(v, 1);
        let (text, ver, hash) = gov.get_canon().unwrap();
        assert_eq!(text, "gain takes time");
        assert_eq!(ver, 1);
        assert_eq!(hash, keccak256(b"gain takes time"));
        assert_eq!(gov.canon_revision_hash(1).unwrap(), hash);

        // second update -> version 2, revision map keeps both
        let v = gov.update_canon(AUTH, "gain takes more time").unwrap();
        assert_eq!(v, 2);
        assert_eq!(
            gov.canon_revision_hash(1).unwrap(),
            keccak256(b"gain takes time")
        );
        assert_eq!(
            gov.canon_revision_hash(2).unwrap(),
            keccak256(b"gain takes more time")
        );
    });
}

#[test]
fn meta_canon_independent_from_canon() {
    with_governance(|gov| {
        gov.update_canon(AUTH, "canon v1").unwrap();
        gov.update_meta_canon(AUTH, "meta v1").unwrap();
        assert_eq!(gov.get_canon().unwrap().1, 1);
        assert_eq!(gov.get_meta_canon().unwrap().1, 1);
        assert_eq!(gov.get_canon().unwrap().0, "canon v1");
        assert_eq!(gov.get_meta_canon().unwrap().0, "meta v1");
    });
}

#[test]
fn canon_update_requires_authority() {
    with_governance(|gov| {
        assert!(gov.update_canon(OTHER, "sneaky").is_err());
        assert!(gov.update_meta_canon(OTHER, "sneaky").is_err());
        // still empty
        assert_eq!(gov.get_canon().unwrap().1, 0);
    });
}

#[test]
fn canon_overwrite_shorter_is_clean() {
    with_governance(|gov| {
        let long = "x".repeat(200);
        gov.update_canon(AUTH, &long).unwrap();
        gov.update_canon(AUTH, "short").unwrap();
        let (text, _, hash) = gov.get_canon().unwrap();
        assert_eq!(text, "short");
        assert_eq!(hash, keccak256(b"short"));
    });
}

#[test]
fn canon_64k_roundtrip() {
    with_governance(|gov| {
        let big = "a".repeat(64 * 1024);
        gov.update_canon(AUTH, &big).unwrap();
        assert_eq!(gov.get_canon().unwrap().0.len(), 64 * 1024);
    });
}

#[test]
fn canon_rejects_empty_and_oversize() {
    with_governance(|gov| {
        assert!(gov.update_canon(AUTH, "").is_err());
        let too_big = "a".repeat(crate::runtime::MAX_TEXT_BYTES + 1);
        assert!(gov.update_canon(AUTH, &too_big).is_err());
    });
}

// ------------------------------------------------------------ proposals ---

#[test]
fn oip_gip_independent_id_sequences() {
    with_governance(|gov| {
        assert_eq!(gov.submit_oip(AUTHOR, "oip one").unwrap(), U256::from(1));
        assert_eq!(gov.submit_oip(AUTHOR, "oip two").unwrap(), U256::from(2));
        assert_eq!(gov.submit_gip(AUTHOR, "gip one").unwrap(), U256::from(1));
        assert_eq!(gov.oip_count().unwrap(), 2);
        assert_eq!(gov.gip_count().unwrap(), 1);
    });
}

#[test]
fn oip_submit_get_roundtrip_text_in_record() {
    with_governance(|gov| {
        let id = gov.submit_oip(AUTHOR, "proposal body text").unwrap();
        let o = gov.get_oip(id).unwrap().unwrap();
        assert_eq!(o.author, AUTHOR);
        assert_eq!(o.status, status::DRAFT);
        assert_eq!(o.text, "proposal body text");
        assert_eq!(o.text_hash, keccak256(b"proposal body text"));
    });
}

#[test]
fn oip_text_update_author_only_and_status_gated() {
    with_governance(|gov| {
        let id = gov.submit_oip(AUTHOR, "v1").unwrap();

        // non-author cannot edit
        assert!(gov.update_oip_text(OTHER, id, "hijack").is_err());

        // author edits in Draft
        gov.update_oip_text(AUTHOR, id, "v2 longer text").unwrap();
        let o = gov.get_oip(id).unwrap().unwrap();
        assert_eq!(o.text, "v2 longer text");
        assert_eq!(o.text_hash, keccak256(b"v2 longer text"));

        // move to Approved; text no longer editable
        gov.set_oip_status(AUTH, id, status::APPROVED).unwrap();
        assert!(gov.update_oip_text(AUTHOR, id, "v3").is_err());
    });
}

#[test]
fn oip_text_update_shrink_keeps_hash_consistent() {
    with_governance(|gov| {
        let id = gov.submit_oip(AUTHOR, &"z".repeat(300)).unwrap();
        gov.update_oip_text(AUTHOR, id, "tiny").unwrap();
        let o = gov.get_oip(id).unwrap().unwrap();
        assert_eq!(o.text, "tiny");
        assert_eq!(o.text_hash, keccak256(b"tiny"));
    });
}

#[test]
fn status_change_preserves_text() {
    with_governance(|gov| {
        let id = gov.submit_oip(AUTHOR, "keep me intact").unwrap();
        gov.set_oip_status(AUTH, id, status::APPROVED).unwrap();
        gov.set_oip_status(AUTH, id, status::IMPLEMENTED).unwrap();
        let o = gov.get_oip(id).unwrap().unwrap();
        assert_eq!(o.text, "keep me intact");
        assert_eq!(o.status, status::IMPLEMENTED);
    });
}

#[test]
fn status_transitions_enforced() {
    with_governance(|gov| {
        let id = gov.submit_oip(AUTHOR, "body").unwrap();
        // invalid: Draft -> Implemented
        assert!(gov.set_oip_status(AUTH, id, status::IMPLEMENTED).is_err());
        // valid: Draft -> Approved -> Implemented
        gov.set_oip_status(AUTH, id, status::APPROVED).unwrap();
        assert!(gov.set_oip_status(AUTH, id, status::REJECTED).is_err()); // Approved -> Rejected invalid
        gov.set_oip_status(AUTH, id, status::IMPLEMENTED).unwrap();
        // Implemented is terminal
        assert!(gov.set_oip_status(AUTH, id, status::DRAFT).is_err());
    });
}

#[test]
fn status_change_requires_authority_except_author_resubmit() {
    with_governance(|gov| {
        let id = gov.submit_oip(AUTHOR, "body").unwrap();
        // non-authority cannot approve
        assert!(gov.set_oip_status(OTHER, id, status::APPROVED).is_err());

        // authority sends to Rework
        gov.set_oip_status(AUTH, id, status::REWORK).unwrap();

        // author may resubmit (Rework -> Draft) despite not being an authority
        gov.set_oip_status(AUTHOR, id, status::DRAFT).unwrap();
        assert_eq!(gov.get_oip(id).unwrap().unwrap().status, status::DRAFT);

        // a random non-author non-authority cannot do the same
        gov.set_oip_status(AUTH, id, status::REWORK).unwrap();
        assert!(gov.set_oip_status(OTHER, id, status::DRAFT).is_err());
    });
}

#[test]
fn gip_mirrors_oip_behavior() {
    with_governance(|gov| {
        let id = gov.submit_gip(AUTHOR, "gip body").unwrap();
        let g = gov.get_gip(id).unwrap().unwrap();
        assert_eq!(g.text, "gip body");
        gov.set_gip_status(AUTH, id, status::APPROVED).unwrap();
        assert_eq!(gov.get_gip(id).unwrap().unwrap().status, status::APPROVED);
    });
}

#[test]
fn missing_proposal_errors() {
    with_governance(|gov| {
        assert!(gov.get_oip(U256::from(99)).unwrap().is_none());
        assert!(gov
            .set_oip_status(AUTH, U256::from(99), status::APPROVED)
            .is_err());
        assert!(gov.update_oip_text(AUTHOR, U256::from(99), "x").is_err());
    });
}

#[test]
fn proposal_rejects_empty_and_oversize_text() {
    with_governance(|gov| {
        assert!(gov.submit_oip(AUTHOR, "").is_err());
        let too_big = "a".repeat(crate::runtime::MAX_TEXT_BYTES + 1);
        assert!(gov.submit_oip(AUTHOR, &too_big).is_err());
    });
}

// ------------------------------------------------------- storage layout ---

/// Pins the contract's slot layout, which `scripts/seed_genesis.py`
/// (`seed_governance`) hardcodes. If a field is reordered/inserted, this test
/// fails - a signal that the seeder must be updated in lockstep.
#[test]
fn storage_layout_matches_seeder() {
    with_governance(|gov| {
        assert_eq!(gov.meta_canon_version.slot(), U256::from(1));
        assert_eq!(gov.meta_canon_hash.slot(), U256::from(2));
        assert_eq!(gov.meta_canon_revisions.base_slot(), U256::from(3));
        assert_eq!(gov.canon_version.slot(), U256::from(5));
        assert_eq!(gov.canon_hash.slot(), U256::from(6));
        assert_eq!(gov.canon_revisions.base_slot(), U256::from(7));
        assert_eq!(gov.next_oip_id.slot(), U256::from(8));
        assert_eq!(gov.next_gip_id.slot(), U256::from(9));
        assert_eq!(gov.authorities.base_slot(), U256::from(10));
        // Record maps come last so growing Oip/Gip never shifts a seeded slot.
        assert_eq!(gov.oips.base_slot(), U256::from(11));
        assert_eq!(gov.gips.base_slot(), U256::from(17)); // 11 + Oip::SLOTS(6)
                                                          // Indexes are appended after gips (gips ends at 22): they never touch the
                                                          // seeded region and thus don't affect seed_genesis.py.
        assert_eq!(gov.oip_author_count.base_slot(), U256::from(23));
        assert_eq!(gov.oip_author_ids.base_slot(), U256::from(24));
        assert_eq!(gov.oip_by_status.base_slot(), U256::from(25));
        assert_eq!(gov.gip_author_count.base_slot(), U256::from(26));
        assert_eq!(gov.gip_author_ids.base_slot(), U256::from(27));
        assert_eq!(gov.gip_by_status.base_slot(), U256::from(28));
        // meta_canon text is at slot 0, canon text at slot 4 (adjacency: the
        // one-slot version field sits immediately after each text field).
    });
}

// ------------------------------------ cross-impl: seeder writes, we read ---

/// End-to-end proof that `scripts/seed_genesis.py::seed_governance` and the Rust
/// contract agree on the storage layout: these `(slot, value)` pairs are the
/// verbatim output of the Python seeder for canon="gain takes time",
/// meta="meta rules", authority=0xaaaa...0001. We load them raw and read them back
/// through `GovernanceContract`. Python computed the slots (keccak/StorageBytes);
/// Rust resolves them independently - agreement proves the seam.
#[test]
fn reads_python_seeder_output() {
    use outbe_primitives::addresses::GOVERNANCE_ADDRESS;

    // AUTO-GENERATED fixture from scripts/seed_genesis.py seed_governance()
    let seeded: &[(&str, &str)] = &[
        (
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x6d6574612072756c657300000000000000000000000000000000000000000014",
        ),
        (
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        ),
        (
            "0x0000000000000000000000000000000000000000000000000000000000000002",
            "0xa540c01c4bd1ce33fc1cb92fd109c95ec7068e456ed7e0533fd1adb7e98158c6",
        ),
        (
            "0x0000000000000000000000000000000000000000000000000000000000000004",
            "0x6761696e2074616b65732074696d65000000000000000000000000000000001e",
        ),
        (
            "0x0000000000000000000000000000000000000000000000000000000000000005",
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        ),
        (
            "0x0000000000000000000000000000000000000000000000000000000000000006",
            "0x93758306b69d86c6e2158df53b14c3847d00947f2e6ae98e7f1a6d65ee2e7afb",
        ),
        (
            "0xa15bc60c955c405d20d9149c709e2460f1c2d9a497496a7f46004d1772c3054c",
            "0xa540c01c4bd1ce33fc1cb92fd109c95ec7068e456ed7e0533fd1adb7e98158c6",
        ),
        (
            "0xb39221ace053465ec3453ce2b36430bd138b997ecea25c1043da0c366812b828",
            "0x93758306b69d86c6e2158df53b14c3847d00947f2e6ae98e7f1a6d65ee2e7afb",
        ),
        (
            "0xc798ca6b006d8eb080cc8018ae9da0e83bf1bef98af67ae90b85b808713e6e9d",
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        ),
    ];
    let authority = address!("0xaaaa000000000000000000000000000000000001");

    let mut storage = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut storage, |storage| {
        for (slot, val) in seeded {
            let slot = slot.parse::<U256>().unwrap();
            let val = val.parse::<U256>().unwrap();
            storage.sstore(GOVERNANCE_ADDRESS, slot, val).unwrap();
        }
        let gov = GovernanceContract::new(storage.clone());

        let (canon, cver, chash) = gov.get_canon().unwrap();
        assert_eq!(canon, "gain takes time");
        assert_eq!(cver, 1);
        assert_eq!(chash, keccak256(b"gain takes time"));

        let (meta, mver, mhash) = gov.get_meta_canon().unwrap();
        assert_eq!(meta, "meta rules");
        assert_eq!(mver, 1);
        assert_eq!(mhash, keccak256(b"meta rules"));

        assert_eq!(
            gov.canon_revision_hash(1).unwrap(),
            keccak256(b"gain takes time")
        );
        assert!(gov.is_authority(authority).unwrap());
        assert!(!gov.is_authority(OTHER).unwrap());
    });
}

// ------------------------------------------------- indexes: by author ---

#[test]
fn author_index_lists_own_proposals() {
    with_governance(|gov| {
        gov.submit_oip(AUTHOR, "a").unwrap(); // id 1
        gov.submit_oip(AUTHOR, "b").unwrap(); // id 2
        gov.submit_oip(OTHER, "c").unwrap(); // id 3

        let mine = gov
            .oips_by_author(AUTHOR, U256::ZERO, U256::from(1000))
            .unwrap();
        assert_eq!(mine.len(), 2);
        assert_eq!(
            mine.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![U256::from(1), U256::from(2)]
        );
        assert!(mine.iter().all(|m| m.author == AUTHOR));

        let theirs = gov
            .oips_by_author(OTHER, U256::ZERO, U256::from(1000))
            .unwrap();
        assert_eq!(theirs.len(), 1);
        assert_eq!(theirs[0].id, U256::from(3));

        // unknown author -> empty
        assert!(gov
            .oips_by_author(AUTH, U256::ZERO, U256::from(1000))
            .unwrap()
            .is_empty());
    });
}

#[test]
fn author_index_is_per_kind() {
    with_governance(|gov| {
        gov.submit_oip(AUTHOR, "oip").unwrap();
        gov.submit_gip(AUTHOR, "gip").unwrap();
        assert_eq!(
            gov.oips_by_author(AUTHOR, U256::ZERO, U256::from(1000))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            gov.gips_by_author(AUTHOR, U256::ZERO, U256::from(1000))
                .unwrap()
                .len(),
            1
        );
    });
}

// -------------------------------------------------- indexes: by status ---

fn all(g: &GovernanceContract, status: u8) -> Vec<U256> {
    g.oips_by_status(status, U256::ZERO, U256::from(1000))
        .unwrap()
        .into_iter()
        .map(|m| m.id)
        .collect()
}

#[test]
fn status_move_relocates_id_between_buckets() {
    with_governance(|gov| {
        let a = gov.submit_oip(AUTHOR, "a").unwrap();
        let b = gov.submit_oip(AUTHOR, "b").unwrap();
        let c = gov.submit_oip(AUTHOR, "c").unwrap(); // stays Draft

        gov.set_oip_status(AUTH, a, status::APPROVED).unwrap();
        gov.set_oip_status(AUTH, a, status::IMPLEMENTED).unwrap(); // Approved -> Implemented
        gov.set_oip_status(AUTH, b, status::REJECTED).unwrap();

        // each id sits in exactly its current status bucket, nowhere else
        assert_eq!(all(gov, status::DRAFT), vec![c]);
        assert!(all(gov, status::APPROVED).is_empty()); // a moved on to Implemented
        assert_eq!(all(gov, status::IMPLEMENTED), vec![a]);
        assert_eq!(all(gov, status::REJECTED), vec![b]);

        // counts, and the invariant sum = total
        assert_eq!(gov.oip_count_by_status(status::DRAFT).unwrap(), 1);
        assert_eq!(gov.oip_count_by_status(status::IMPLEMENTED).unwrap(), 1);
        assert_eq!(gov.oip_count_by_status(status::REJECTED).unwrap(), 1);
        let total: u32 = (0..=4).map(|s| gov.oip_count_by_status(s).unwrap()).sum();
        assert_eq!(total as u64, gov.oip_count().unwrap());
    });
}

#[test]
fn rework_then_approve_lands_in_approved_only() {
    with_governance(|gov| {
        let a = gov.submit_oip(AUTHOR, "a").unwrap();
        gov.set_oip_status(AUTH, a, status::REWORK).unwrap();
        gov.set_oip_status(AUTHOR, a, status::DRAFT).unwrap(); // author resubmit
        gov.set_oip_status(AUTH, a, status::APPROVED).unwrap();

        assert_eq!(all(gov, status::APPROVED), vec![a]);
        assert!(all(gov, status::DRAFT).is_empty());
        assert!(all(gov, status::REWORK).is_empty());
    });
}

#[test]
fn status_buckets_are_per_kind() {
    with_governance(|gov| {
        let o = gov.submit_oip(AUTHOR, "o").unwrap();
        let g = gov.submit_gip(AUTHOR, "g").unwrap();
        gov.set_oip_status(AUTH, o, status::APPROVED).unwrap();
        gov.set_gip_status(AUTH, g, status::REJECTED).unwrap();

        assert_eq!(gov.oip_count_by_status(status::APPROVED).unwrap(), 1);
        assert_eq!(gov.gip_count_by_status(status::APPROVED).unwrap(), 0);
        assert_eq!(gov.oip_count_by_status(status::REJECTED).unwrap(), 0);
        assert_eq!(gov.gip_count_by_status(status::REJECTED).unwrap(), 1);
    });
}

#[test]
fn out_of_range_status_query_errors() {
    with_governance(|gov| {
        assert!(gov.oip_count_by_status(5).is_err());
        assert!(gov.oips_by_status(9, U256::ZERO, U256::from(10)).is_err());
    });
}

// ------------------------------------------------------------ pagination ---

#[test]
fn author_listing_is_paginated() {
    with_governance(|gov| {
        for i in 0..5u32 {
            gov.submit_oip(AUTHOR, &format!("p{i}")).unwrap(); // ids 1..=5
        }
        assert_eq!(gov.oip_count_by_author(AUTHOR).unwrap(), 5);

        // first page of 2
        let p0 = gov
            .oips_by_author(AUTHOR, U256::ZERO, U256::from(2))
            .unwrap();
        assert_eq!(
            p0.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![U256::from(1), U256::from(2)]
        );

        // middle page
        let p1 = gov
            .oips_by_author(AUTHOR, U256::from(2), U256::from(2))
            .unwrap();
        assert_eq!(
            p1.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![U256::from(3), U256::from(4)]
        );

        // last partial page (only 1 left)
        let p2 = gov
            .oips_by_author(AUTHOR, U256::from(4), U256::from(2))
            .unwrap();
        assert_eq!(
            p2.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![U256::from(5)]
        );

        // offset past the end -> empty
        assert!(gov
            .oips_by_author(AUTHOR, U256::from(99), U256::from(2))
            .unwrap()
            .is_empty());
    });
}

#[test]
fn status_listing_is_paginated() {
    with_governance(|gov| {
        for _ in 0..4 {
            let id = gov.submit_oip(AUTHOR, "x").unwrap();
            gov.set_oip_status(AUTH, id, status::APPROVED).unwrap();
        }
        assert_eq!(gov.oip_count_by_status(status::APPROVED).unwrap(), 4);

        let page = gov
            .oips_by_status(status::APPROVED, U256::from(1), U256::from(2))
            .unwrap();
        assert_eq!(page.len(), 2); // items 2 and 3 of the bucket
        let last = gov
            .oips_by_status(status::APPROVED, U256::from(3), U256::from(10))
            .unwrap();
        assert_eq!(last.len(), 1); // clamped to what's left
    });
}

// ----------------------------------------------------------------- diff ---

#[test]
fn gip_diff_against_canon_shows_edits() {
    with_governance(|gov| {
        gov.update_canon(AUTH, "line a\nline b\nline c\n").unwrap();
        let id = gov.submit_gip(AUTHOR, "line a\nline B\nline c\n").unwrap();
        let g = gov.get_gip(id).unwrap().unwrap();
        let (canon, _, _) = gov.get_canon().unwrap();
        let d = crate::diff::unified(&canon, &g.text);
        assert!(d.contains("-line b"));
        assert!(d.contains("+line B"));
    });
}

mod vote_dispatch;
