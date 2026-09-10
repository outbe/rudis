use outbe_primitives::error::PrecompileError;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CredisFactoryError {
    #[error("invalid asset address")]
    InvalidAsset,
    #[error("invalid smart account address")]
    InvalidSmartAccount,
    #[error("settlement amount is zero")]
    InvalidAmount,
    #[error("asset isoCode() call returned undecodable data")]
    AssetIsoUndecodable,
    #[error("caller is not a CCA in active standing")]
    CcaNotActive,
    #[error("smart account is not deployed")]
    SmartAccountNotDeployed,
    #[error("attached rudis must equal the pledged collateral exactly")]
    CcaStakeMismatch,
}

impl From<CredisFactoryError> for PrecompileError {
    fn from(err: CredisFactoryError) -> Self {
        PrecompileError::Revert(err.to_string())
    }
}
