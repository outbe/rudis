//! Vote target-module handler for materializing Approved OIP / GIP records.
//!
//! Vote JSON payload schema:
//! ```json
//! {"kind":"oip","text":"..."}
//! {"kind":"gip","text":"..."}
//! ```

use alloy_primitives::{Address, U256};
use outbe_primitives::addresses::GOVERNANCE_ADDRESS;
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::Result as PrecompileResult;
use outbe_vote::handlers::{TargetExecutionOutcome, VoteTarget, VoteTargetContext};
use outbe_vote::schema::Vote;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::GovernanceError;
use crate::runtime::MAX_TEXT_BYTES;
use crate::schema::GovernanceContract;

/// Which governance proposal kind a vote payload creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProposalKind {
    Oip,
    Gip,
}

/// JSON payload for materializing an Approved OIP/GIP via vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceVotePayload {
    pub kind: ProposalKind,
    pub text: String,
}

impl GovernanceVotePayload {
    pub fn new(kind: ProposalKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
        }
    }

    pub fn from_value(payload: &Value) -> Result<Self, GovernanceError> {
        serde_json::from_value(payload.clone()).map_err(|_| GovernanceError::InvalidPayload)
    }

    pub fn validate(&self) -> Result<(), GovernanceError> {
        if self.text.is_empty() {
            return Err(GovernanceError::EmptyText);
        }
        if self.text.len() > MAX_TEXT_BYTES {
            return Err(GovernanceError::TextTooLarge);
        }
        Ok(())
    }

    /// Encodes `kind` + `text` into a vote JSON payload string.
    pub fn encode(kind: ProposalKind, text: &str) -> String {
        serde_json::to_string(&Self::new(kind, text))
            .expect("governance vote payload JSON should serialize")
    }

    /// Validates structural vote JSON fields and text bounds.
    pub fn validate_json(payload: &Value) -> Result<(), GovernanceError> {
        Self::from_value(payload)?.validate()
    }
}

/// Vote target handler wired to the Governance precompile address.
pub struct GovernanceVoteTarget;

impl VoteTarget for GovernanceVoteTarget {
    fn target_module(&self) -> Address {
        GOVERNANCE_ADDRESS
    }

    fn validate(&self, payload: &[u8], _context: VoteTargetContext) -> PrecompileResult<()> {
        let payload: Value = serde_json::from_slice(payload).map_err(|_| {
            outbe_primitives::error::PrecompileError::Revert("invalid proposal payload".into())
        })?;
        GovernanceVotePayload::validate_json(&payload).map_err(Into::into)
    }

    fn handle_approved(
        &self,
        ctx: &BlockRuntimeContext,
        proposal_id: U256,
        payload: &[u8],
        _context: VoteTargetContext,
    ) -> PrecompileResult<TargetExecutionOutcome> {
        let payload: Value = serde_json::from_slice(payload).map_err(|_| {
            outbe_primitives::error::PrecompileError::Fatal(
                "stored Governance proposal payload is invalid".into(),
            )
        })?;
        let decoded = GovernanceVotePayload::from_value(&payload)?;
        decoded.validate()?;

        let vote = Vote::new(ctx.storage.clone());
        let proposal = vote
            .proposals
            .get(proposal_id)?
            .ok_or(GovernanceError::ProposalNotFound)?;
        let author = proposal.proposer;

        let mut gov = GovernanceContract::new(ctx.storage.clone());
        match decoded.kind {
            ProposalKind::Oip => {
                gov.create_approved_oip(author, &decoded.text)?;
            }
            ProposalKind::Gip => {
                gov.create_approved_gip(author, &decoded.text)?;
            }
        }
        Ok(TargetExecutionOutcome::Applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let json = GovernanceVotePayload::encode(ProposalKind::Oip, "body");
        assert!(json.contains(r#""kind":"oip""#), "json={json}");
        let value: Value = serde_json::from_str(&json).unwrap();
        let decoded = GovernanceVotePayload::from_value(&value).unwrap();
        assert_eq!(decoded.kind, ProposalKind::Oip);
        assert_eq!(decoded.text, "body");
        decoded.validate().unwrap();
    }

    #[test]
    fn rejects_unknown_kind() {
        let value: Value = serde_json::from_str(r#"{"kind":"xip","text":"body"}"#).unwrap();
        assert_eq!(
            GovernanceVotePayload::from_value(&value).unwrap_err(),
            GovernanceError::InvalidPayload
        );
    }

    #[test]
    fn rejects_empty_text() {
        let payload = GovernanceVotePayload::new(ProposalKind::Gip, "");
        assert_eq!(payload.validate().unwrap_err(), GovernanceError::EmptyText);
    }
}
