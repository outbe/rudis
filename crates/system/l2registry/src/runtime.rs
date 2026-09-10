use alloy_primitives::{Address, Bytes};
use commonware_codec::DecodeExt;
use commonware_cryptography::bls12381::primitives::group::G2;
use outbe_primitives::error::Result;

use crate::errors::L2RegistryError;
use crate::precompile::IL2Registry;
use crate::schema::{L2NetworkRecord, L2RegistryContract, BLS_PUBLIC_KEY_LEN};

impl L2RegistryContract<'_> {
    /// Registers an L2 network with ZK verification disabled.
    pub fn register_network(
        &mut self,
        chain_id: u64,
        l1_address: Address,
        public_key: &[u8],
    ) -> Result<()> {
        self.register_network_with_zk(chain_id, l1_address, public_key, false)
    }

    /// Atomically registers an L2 network with its approved initial ZK policy.
    pub fn register_network_with_zk(
        &mut self,
        chain_id: u64,
        l1_address: Address,
        public_key: &[u8],
        zk_enabled: bool,
    ) -> Result<()> {
        if chain_id == 0 {
            return Err(L2RegistryError::InvalidChainId.into());
        }
        if l1_address == Address::ZERO {
            return Err(L2RegistryError::InvalidL1Address.into());
        }
        let pubkey: &[u8; BLS_PUBLIC_KEY_LEN] =
            public_key
                .try_into()
                .map_err(|_| L2RegistryError::InvalidPublicKeyLength {
                    length: public_key.len(),
                })?;
        // Group check: the stored key must be a valid MinSig G2 group key so the
        // offer-time verification path can never fail on decode.
        decode_public_key(pubkey)?;

        if self.networks.exists(chain_id)? {
            return Err(L2RegistryError::NetworkAlreadyRegistered { chain_id }.into());
        }
        let existing_chain = self.l1_to_chain.read(&l1_address)?;
        if existing_chain != 0 {
            return Err(L2RegistryError::L1AddressAlreadyRegistered {
                l1_address,
                chain_id: existing_chain,
            }
            .into());
        }

        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            let (pubkey_lo, pubkey_mid, pubkey_hi) = L2NetworkRecord::split_public_key(pubkey);
            self.networks.create(&L2NetworkRecord {
                chain_id,
                l1_address,
                pubkey_lo,
                pubkey_mid,
                pubkey_hi,
                zk_enabled,
            })?;
            self.l1_to_chain.write(&l1_address, chain_id)?;

            self.emit(IL2Registry::L2NetworkRegistered {
                chainId: chain_id,
                l1Address: l1_address,
                publicKey: Bytes::copy_from_slice(public_key),
            })?;
            if zk_enabled {
                self.emit(IL2Registry::L2NetworkZkSet {
                    chainId: chain_id,
                    enabled: true,
                })?;
            }
            Ok(())
        })
    }

    /// Enables or disables ZK verification for a registered network.
    pub fn set_zk_enabled(&mut self, chain_id: u64, enabled: bool) -> Result<()> {
        let mut record = self.load_network(chain_id)?;
        record.zk_enabled = enabled;
        self.networks.update(&record)?;
        self.emit(IL2Registry::L2NetworkZkSet {
            chainId: chain_id,
            enabled,
        })?;
        Ok(())
    }

    /// Removes a registered network when `caller` is its stored L1 owner.
    pub fn remove_network(&mut self, caller: Address, chain_id: u64) -> Result<()> {
        let record = self.load_network(chain_id)?;
        if caller != record.l1_address {
            return Err(L2RegistryError::NotNetworkOwner { caller, chain_id }.into());
        }

        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.networks.delete(chain_id)?;
            self.l1_to_chain.clear(&record.l1_address)?;
            self.emit(IL2Registry::L2NetworkRemoved { chainId: chain_id })?;
            Ok(())
        })
    }

    /// Loads a registration or reverts with `NetworkNotRegistered`.
    pub fn load_network(&self, chain_id: u64) -> Result<L2NetworkRecord> {
        self.networks
            .get(chain_id)?
            .ok_or_else(|| L2RegistryError::NetworkNotRegistered { chain_id }.into())
    }

    /// Loads the registration owned by `l1_address`, if any.
    pub(crate) fn network_by_l1_address(
        &self,
        l1_address: Address,
    ) -> Result<Option<L2NetworkRecord>> {
        let chain_id = self.l1_to_chain.read(&l1_address)?;
        if chain_id == 0 {
            return Ok(None);
        }
        self.load_network(chain_id).map(Some)
    }
}

/// Decodes a 96-byte MinSig G2 group public key, performing the group check.
pub(crate) fn decode_public_key(pubkey: &[u8; BLS_PUBLIC_KEY_LEN]) -> Result<G2> {
    G2::decode(pubkey.as_slice()).map_err(|_| L2RegistryError::InvalidPublicKey.into())
}
