use std::marker::PhantomData;

use alloy_primitives::B256;

use crate::error::{PrecompileError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LysisActivationCursor {
    Nod,
    Contributor,
    CarryOver,
    Tribute,
    Terminal,
    Complete,
}

/// Runtime-only authority for the fixed Lysis activation owner sequence.
///
/// This value has no public constructor, codec or clone implementation. Its
/// invariant lifetime ties it to one [`StorageHandle::with_lysis_activation_frame`]
/// closure, and its cursor can only advance through the four named owners and
/// terminal receipt in the protocol order.
///
/// [`StorageHandle::with_lysis_activation_frame`]: super::StorageHandle::with_lysis_activation_frame
pub struct CertifiedLysisActivation<'frame> {
    activation_call_id: B256,
    cursor: LysisActivationCursor,
    _frame: PhantomData<&'frame mut &'frame ()>,
}

impl<'frame> CertifiedLysisActivation<'frame> {
    pub(crate) const fn new(activation_call_id: B256) -> Self {
        Self {
            activation_call_id,
            cursor: LysisActivationCursor::Nod,
            _frame: PhantomData,
        }
    }

    #[must_use]
    pub const fn activation_call_id(&self) -> B256 {
        self.activation_call_id
    }

    pub fn authorize_nod_installation(&mut self) -> Result<()> {
        self.advance(
            LysisActivationCursor::Nod,
            LysisActivationCursor::Contributor,
            "Nod",
        )
    }

    pub fn authorize_contributor_installation(&mut self) -> Result<()> {
        self.advance(
            LysisActivationCursor::Contributor,
            LysisActivationCursor::CarryOver,
            "contributor",
        )
    }

    pub fn authorize_tribute_retirement(&mut self) -> Result<()> {
        self.advance(
            LysisActivationCursor::Tribute,
            LysisActivationCursor::Terminal,
            "Tribute",
        )
    }

    pub fn authorize_carry_over_credit(&mut self) -> Result<()> {
        self.advance(
            LysisActivationCursor::CarryOver,
            LysisActivationCursor::Tribute,
            "carry-over",
        )
    }

    /// Consumes the terminal cursor after a verified Lysis receipt set has
    /// produced the terminal permit.
    ///
    /// This method does not itself create effect authority. The private
    /// terminal permit lives in `outbe-lysis`; callers without a verified
    /// receipt set cannot construct it for the terminal owner API.
    pub fn authorize_terminal_receipt(&mut self) -> Result<()> {
        self.advance(
            LysisActivationCursor::Terminal,
            LysisActivationCursor::Complete,
            "terminal",
        )
    }

    pub(crate) const fn is_complete(&self) -> bool {
        matches!(self.cursor, LysisActivationCursor::Complete)
    }

    fn advance(
        &mut self,
        expected: LysisActivationCursor,
        next: LysisActivationCursor,
        owner: &'static str,
    ) -> Result<()> {
        if self.cursor != expected {
            return Err(PrecompileError::Fatal(format!(
                "certified Lysis activation {owner} cursor is out of order"
            )));
        }
        self.cursor = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::CertifiedLysisActivation;
    use alloy_primitives::B256;

    #[test]
    fn owner_cursor_is_fixed_and_one_shot() {
        let mut capability = CertifiedLysisActivation::new(B256::repeat_byte(1));
        assert!(capability.authorize_contributor_installation().is_err());
        capability.authorize_nod_installation().unwrap();
        assert!(capability.authorize_nod_installation().is_err());
        capability.authorize_contributor_installation().unwrap();
        capability.authorize_carry_over_credit().unwrap();
        capability.authorize_tribute_retirement().unwrap();
        capability.authorize_terminal_receipt().unwrap();
        assert!(capability.is_complete());
        assert!(capability.authorize_terminal_receipt().is_err());
    }
}
