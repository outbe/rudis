pub use outbe_ocompregistry::{
    OcompForkInstallClassification, OcompForkInstallV1, OCOMP_POC_FINAL_ACTIVATION_HEIGHT,
};

#[cfg(any(test, feature = "test-utils"))]
use outbe_ocomp_protocol::SchemaLimits;
#[cfg(any(test, feature = "test-utils"))]
use outbe_primitives::error::Result;

#[cfg(any(test, feature = "test-utils"))]
use super::activation::OcompActivationAuthorityV1;
#[cfg(any(test, feature = "test-utils"))]
use crate::{errors::storage_corruption_message, schema::MetadosisContract};

#[cfg(any(test, feature = "test-utils"))]
impl MetadosisContract<'_> {
    /// Legacy Metadosis-only fixture initializer. Production genesis installs
    /// the canonical Registry-owned authority directly in `OcompRegistry`.
    #[allow(dead_code, reason = "legacy Metadosis-only fixture initializer")]
    pub fn initialize_ocomp_fork_install(
        &mut self,
        install: &OcompForkInstallV1,
        current_height: u64,
        limits: &SchemaLimits,
    ) -> Result<()> {
        if current_height != install.activation_height {
            return Err(storage_corruption_message(
                "OCOMP fork install attempted outside its activation height",
            ));
        }
        let chain_id = self.storage.chain_id()?;
        install.validate_for_chain(chain_id, install.request_profile.genesis_hash, limits)?;
        let expected_authority = OcompActivationAuthorityV1 {
            bundle: install.protocol_bundle.clone(),
        };
        match (
            self.read_ocomp_request_profile(limits)?,
            self.read_ocomp_activation_authority(limits)?,
        ) {
            (None, None) => {}
            (Some(profile), Some(authority))
                if profile == install.request_profile && authority == expected_authority =>
            {
                return Ok(())
            }
            (Some(_), Some(_)) => {
                return Err(storage_corruption_message(
                    "OCOMP fork authority is immutable",
                ))
            }
            _ => {
                return Err(storage_corruption_message(
                    "partial OCOMP fork authority is fatal",
                ))
            }
        }

        self.initialize_ocomp_request_profile(&install.request_profile, limits)?;
        self.initialize_ocomp_activation_authority(&install.protocol_bundle, limits)
    }
}
