//! Proposal status model, shared by OIP and GIP.
//!
//! `Draft(0) -> Approved(1) -> Rejected(2) -> Rework(3) -> Implemented(4)`,
//! enforced as a graph (not a linear sequence):
//!
//! ```text
//! Draft       -> Approved | Rejected | Rework
//! Rework      -> Draft                       (author resubmits after edits)
//! Approved    -> Implemented
//! Rejected    -> (terminal)
//! Implemented -> (terminal)
//! ```

use crate::errors::GovernanceError;

pub const DRAFT: u8 = 0;
pub const APPROVED: u8 = 1;
pub const REJECTED: u8 = 2;
pub const REWORK: u8 = 3;
pub const IMPLEMENTED: u8 = 4;

/// Whether `s` is a defined status value.
pub fn is_valid_status(s: u8) -> bool {
    s <= IMPLEMENTED
}

/// Validates that `from -> to` is a permitted transition.
pub fn validate_transition(from: u8, to: u8) -> Result<(), GovernanceError> {
    if !is_valid_status(to) {
        return Err(GovernanceError::InvalidStatus);
    }
    let permitted = matches!(
        (from, to),
        (DRAFT, APPROVED)
            | (DRAFT, REJECTED)
            | (DRAFT, REWORK)
            | (REWORK, DRAFT)
            | (APPROVED, IMPLEMENTED)
    );
    if permitted {
        Ok(())
    } else {
        Err(GovernanceError::InvalidStatusTransition)
    }
}

/// Proposal text may be edited only while `Draft` or `Rework`.
pub fn text_editable(status: u8) -> bool {
    matches!(status, DRAFT | REWORK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_transitions_pass() {
        for (f, t) in [
            (DRAFT, APPROVED),
            (DRAFT, REJECTED),
            (DRAFT, REWORK),
            (REWORK, DRAFT),
            (APPROVED, IMPLEMENTED),
        ] {
            assert!(validate_transition(f, t).is_ok(), "{f}->{t} should pass");
        }
    }

    #[test]
    fn invalid_transitions_reject() {
        for (f, t) in [
            (DRAFT, IMPLEMENTED),
            (DRAFT, DRAFT),
            (APPROVED, REJECTED),
            (APPROVED, REWORK),
            (REJECTED, DRAFT),
            (IMPLEMENTED, DRAFT),
            (REWORK, APPROVED),
        ] {
            assert!(
                matches!(
                    validate_transition(f, t),
                    Err(GovernanceError::InvalidStatusTransition)
                ),
                "{f}->{t} should reject"
            );
        }
    }

    #[test]
    fn out_of_range_status_rejects() {
        assert!(matches!(
            validate_transition(DRAFT, 5),
            Err(GovernanceError::InvalidStatus)
        ));
    }

    #[test]
    fn text_editable_only_in_draft_rework() {
        assert!(text_editable(DRAFT));
        assert!(text_editable(REWORK));
        assert!(!text_editable(APPROVED));
        assert!(!text_editable(REJECTED));
        assert!(!text_editable(IMPLEMENTED));
    }
}
