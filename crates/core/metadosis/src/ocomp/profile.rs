use alloy_primitives::B256;
use outbe_ocomp_protocol::SchemaLimits;
use outbe_primitives::error::Result;

pub use outbe_ocompregistry::{poc_schema_limits, OcompRequestProfile};

#[cfg(any(test, feature = "test-utils"))]
use crate::errors::storage_corruption_message;
use crate::schema::MetadosisContract;

impl MetadosisContract<'_> {
    /// Legacy fixture initializer. Production authority writes belong only to
    /// `OcompRegistry`; this remains available for pre-registry test fixtures.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn initialize_ocomp_request_profile(
        &mut self,
        profile: &OcompRequestProfile,
        limits: &SchemaLimits,
    ) -> Result<()> {
        let storage = self.storage.clone();
        (|| {
            profile.validate()?;
            if storage.chain_id()? != profile.chain_id {
                return Err(storage_corruption_message(
                    "OCOMP request profile chain id mismatch",
                ));
            }
            match self.read_ocomp_request_profile(limits)? {
                Some(existing) if existing == *profile => Ok(()),
                Some(_) => Err(storage_corruption_message(
                    "OCOMP request profile is immutable",
                )),
                None => {
                    self.ocomp_request_profile
                        .write(&profile.encode_canonical(limits)?)?;
                    if self.read_ocomp_request_profile(limits)? != Some(profile.clone()) {
                        return Err(storage_corruption_message(
                            "OCOMP request profile write/read mismatch",
                        ));
                    }
                    Ok(())
                }
            }
        })()
    }

    pub fn read_ocomp_request_profile(
        &self,
        limits: &SchemaLimits,
    ) -> Result<Option<OcompRequestProfile>> {
        if let Some(authority) = outbe_ocompregistry::OcompRegistry::new(self.storage.clone())
            .active_authority(limits)?
        {
            return Ok(Some(authority.request_profile));
        }
        #[cfg(any(test, feature = "test-utils"))]
        {
            self.read_legacy_ocomp_request_profile(limits)
        }
        #[cfg(not(any(test, feature = "test-utils")))]
        Ok(None)
    }

    pub(crate) fn read_ocomp_request_profile_for_bundle(
        &self,
        bundle_hash: B256,
        limits: &SchemaLimits,
    ) -> Result<Option<OcompRequestProfile>> {
        if let Some(authority) = outbe_ocompregistry::OcompRegistry::new(self.storage.clone())
            .authority_by_bundle_hash(bundle_hash, limits)?
        {
            return Ok(Some(authority.request_profile));
        }
        #[cfg(any(test, feature = "test-utils"))]
        {
            let legacy = self.read_legacy_ocomp_request_profile(limits)?;
            Ok(legacy.filter(|profile| profile.protocol_bundle_hash == bundle_hash))
        }
        #[cfg(not(any(test, feature = "test-utils")))]
        Ok(None)
    }

    #[cfg(any(test, feature = "test-utils"))]
    fn read_legacy_ocomp_request_profile(
        &self,
        limits: &SchemaLimits,
    ) -> Result<Option<OcompRequestProfile>> {
        let len = self.ocomp_request_profile.len()?;
        if len == 0 {
            return Ok(None);
        }
        let max = limits
            .codec
            .max_allocation_bytes
            .checked_add(outbe_ocomp_protocol::OCB1_HEADER_LEN)
            .ok_or_else(|| storage_corruption_message("OCOMP request profile byte cap overflow"))?;
        if len > max {
            return Err(storage_corruption_message(
                "OCOMP request profile exceeds byte cap",
            ));
        }
        OcompRequestProfile::decode_canonical(&self.ocomp_request_profile.read()?, limits).map(Some)
    }
}
