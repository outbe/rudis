use alloy_primitives::B256;
use outbe_primitives::error::Result;

use crate::errors::TributeFactoryError;
use crate::schema::TributeFactoryContract;

impl TributeFactoryContract<'_> {
    pub fn has_used_su_hash(&self, su_hash: B256) -> Result<bool> {
        self.used_su_hashes.read(&su_hash)
    }

    pub(crate) fn mark_su_hash_used(&mut self, su_hash: B256) -> Result<()> {
        if self.has_used_su_hash(su_hash)? {
            return Err(TributeFactoryError::SuHashAlreadyUsed.into());
        }
        self.used_su_hashes.write(&su_hash, true)
    }

    pub(crate) fn mark_su_hashes_used(&mut self, hashes: &[B256]) -> Result<()> {
        for hash in hashes {
            self.mark_su_hash_used(*hash)?;
        }
        Ok(())
    }
}
