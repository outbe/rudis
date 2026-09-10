use crate::ocomp::finality::validate_public_committee_len;

#[test]
fn public_finality_accepts_dynamic_committee_lengths_up_to_the_consensus_bound() {
    let max = usize::try_from(outbe_consensus::bls::MAX_VALIDATORS)
        .expect("consensus validator bound fits usize");

    assert!(validate_public_committee_len(5, max).is_ok());
    assert!(validate_public_committee_len(max, max).is_ok());
    assert!(validate_public_committee_len(0, max).is_err());
    assert!(validate_public_committee_len(max + 1, max).is_err());
}
