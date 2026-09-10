use alloy_primitives::{Address, FixedBytes, B256};
use outbe_primitives::error::{PrecompileError, Result};

use crate::{errors::RadicleRegistryError, precompile::IRadicleRegistry, schema::RadicleRegistry};

pub type RepoId = FixedBytes<20>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepositoryRegistration {
    pub index: u32,
    pub generation: u64,
}

#[must_use]
pub fn repo_id_storage_key(repo_id: RepoId) -> B256 {
    let mut word = [0_u8; 32];
    word[..20].copy_from_slice(repo_id.as_slice());
    B256::from(word)
}

pub fn repo_id_from_storage_key(key: B256) -> Result<RepoId> {
    if key.as_slice()[20..] != [0_u8; 12] {
        return Err(PrecompileError::Fatal(
            "Radicle repository storage key has a non-zero tail".into(),
        ));
    }
    Ok(RepoId::from_slice(&key.as_slice()[..20]))
}

impl RadicleRegistry<'_> {
    pub fn register_repository(
        &mut self,
        repo_id: RepoId,
        registrant: Address,
    ) -> Result<RepositoryRegistration> {
        if repo_id.is_zero() {
            return Err(RadicleRegistryError::ZeroRepositoryId.into());
        }
        let key = repo_id_storage_key(repo_id);
        if self.repository_index.read(&key)? != 0 {
            return Err(RadicleRegistryError::AlreadyRegistered.into());
        }

        let count = self.repository_count.read()?;
        let maximum = self.config_max_repositories.read()?;
        if count >= maximum {
            return Err(RadicleRegistryError::CapacityReached { maximum }.into());
        }
        let next_count = count + 1;
        let generation = self.registry_generation.read()? + 1;

        let checkpoint = self.storage.checkpoint_guard();
        self.repository_by_index.write(&count, key)?;
        self.repository_index.write(&key, next_count)?;
        self.repository_registrant.write(&key, registrant)?;
        self.repository_count.write(next_count)?;
        self.registry_generation.write(generation)?;
        self.emit(IRadicleRegistry::RepositoryRegistered {
            repoId: repo_id,
            registrant,
            index: count,
            generation,
        })?;
        checkpoint.commit();
        Ok(RepositoryRegistration {
            index: count,
            generation,
        })
    }

    pub fn repository_at(&self, index: u32) -> Result<RepoId> {
        let count = self.repository_count.read()?;
        if index >= count {
            return Err(RadicleRegistryError::IndexOutOfBounds { index, count }.into());
        }
        let key = self.repository_by_index.read(&index)?;
        if key.is_zero() || self.repository_index.read(&key)? != index + 1 {
            return Err(PrecompileError::Fatal(format!(
                "Radicle repository index {index} is inconsistent"
            )));
        }
        repo_id_from_storage_key(key)
    }

    pub fn registrant_of(&self, repo_id: RepoId) -> Result<Address> {
        self.repository_registrant
            .read(&repo_id_storage_key(repo_id))
    }
}
