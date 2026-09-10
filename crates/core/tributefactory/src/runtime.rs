use alloy_primitives::{Address, Bytes, B256, U256};
use outbe_agentreward::AgentRewardContract;
use outbe_compressed_entities::{
    derive_poseidon_digest, ExecutionScope, ParentBodySource, WwdEntityId,
};
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::stablecoin::validate_currency_code;
use outbe_primitives::time::timestamp_to_date_key;
use outbe_primitives::time::WorldwideDay;
use outbe_tee::protocol::{
    EncryptedTributeOffer, TributeOfferResult, TributeOfferStatus, TributeZkContext,
};
use outbe_tribute::{TributeContract, TributeData};
use outbe_zk_backend::barretenberg::verify_circuit;
use outbe_zk_canonical::full_proof::{
    decode_public_inputs as decode_full_proof_public_inputs, PublicInputs as FullProofPublicInputs,
};
use outbe_zk_canonical::noir::full_proof::FullProof;

use crate::errors::TributeFactoryError;
use crate::schema::TributeFactoryContract;

pub(crate) struct OfferTributeInput {
    pub caller: Address,
    pub cipher_text: Bytes,
    pub nonce: Bytes,
    pub ephemeral_pubkey: U256,
    pub worldwide_day: WorldwideDay,
    pub tribute_currency: u16,
    pub reference_currency: u16,
    pub exclude_from_intex_issuance: bool,
    pub zk_proof: Bytes,
    pub zk_merkle_root: Bytes,
    pub signature: Bytes,
}

impl TributeFactoryContract<'_> {
    /// Single live offer path: an encrypted offer arrives; the host validates the
    /// cleartext day and currency, resolves the COEN price for that exact pair and
    /// day, hands offer + price to the enclave (`ProcessTributeOfferBatch`), and
    /// issues the Tribute from the returned `TributeOfferResult`. The enclave
    /// returns only what it computed - the amounts, the draft-derived fields and
    /// the Poseidon `token_id` - so everything public on the Tribute comes from
    /// this function's own inputs. The canonical identity is independently
    /// recomputed and checked before issuance.
    pub(crate) fn offer_tribute(
        &mut self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        input: OfferTributeInput,
    ) -> Result<WwdEntityId> {
        self.offer_tribute_inner(
            scope,
            parent,
            input,
            crate::enclave_offer::process_tribute_offer_batch_via_enclave,
        )
    }

    #[cfg(any(test, feature = "bench-utils"))]
    pub(crate) fn offer_tribute_with_processor(
        &mut self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        input: OfferTributeInput,
        processor: impl FnOnce(
            &[EncryptedTributeOffer],
        )
            -> core::result::Result<Vec<TributeOfferResult>, PrecompileError>,
    ) -> Result<WwdEntityId> {
        self.offer_tribute_inner(scope, parent, input, processor)
    }

    fn offer_tribute_inner(
        &mut self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        input: OfferTributeInput,
        processor: impl FnOnce(
            &[EncryptedTributeOffer],
        )
            -> core::result::Result<Vec<TributeOfferResult>, PrecompileError>,
    ) -> Result<WwdEntityId> {
        let OfferTributeInput {
            caller,
            cipher_text,
            nonce,
            ephemeral_pubkey,
            worldwide_day,
            tribute_currency,
            reference_currency,
            exclude_from_intex_issuance,
            zk_proof,
            zk_merkle_root,
            signature,
        } = input;

        validate_currency_code(tribute_currency)?;
        validate_currency_code(reference_currency)?;

        // When the caller is a registered L2 operator with ZK verification
        // enabled, the offer must carry a valid BLS MinSig signature over
        // `zkMerkleRoot` from the network's registered key. Unregistered
        // callers and zk-disabled networks pass through unchanged.
        let zk_check = outbe_l2registry::api::check_zk_merkle_root_signature(
            self.storage.clone(),
            caller,
            &zk_merkle_root,
            &signature,
        )?;
        let zk_public_inputs = match zk_check {
            outbe_l2registry::api::ZkOfferCheck::Verified { .. } => {
                if zk_proof.is_empty() {
                    return Err(TributeFactoryError::ZkProofRequired.into());
                }
                let public = decode_full_proof_public_inputs(&zk_proof)
                    .map_err(|error| TributeFactoryError::MalformedZkProof(error.to_string()))?;
                if public.merkle_root.as_slice() != zk_merkle_root.as_ref() {
                    return Err(TributeFactoryError::ZkPublicInputMismatch {
                        field: "merkle_root",
                    }
                    .into());
                }
                Some(public)
            }
            outbe_l2registry::api::ZkOfferCheck::NotRegistered
            | outbe_l2registry::api::ZkOfferCheck::Disabled { .. } => None,
        };

        // Everything below is settled from chain state before the enclave is
        // contacted, so a bad day or an unpriceable currency costs no round trip.
        if !worldwide_day.is_valid() {
            return Err(TributeFactoryError::InvalidWorldwideDay { worldwide_day }.into());
        }
        if !outbe_metadosis::api::is_offering_day(self.storage.clone(), worldwide_day)? {
            let status = outbe_metadosis::api::worldwide_day(self.storage.clone(), worldwide_day)?
                .map(|projection| projection.status);
            return Err(TributeFactoryError::WorldwideDayNotOffering {
                worldwide_day,
                // Preserve the established diagnostic byte without granting
                // TributeFactory raw Metadosis schema access.
                status: status.map_or(u8::MAX, |status| status as u8),
            }
            .into());
        }

        outbe_oracle::api::check_reference_currency_with_storage(
            self.storage.clone(),
            reference_currency,
        )?;

        // Priced against the tribute's own day, not whichever day happens to be
        // first in the OFFERING list.
        let pricing = outbe_oracle::api::tribute_pricing_inputs(
            self.storage.clone(),
            tribute_currency,
            reference_currency,
            worldwide_day,
        )?
        .ok_or(TributeFactoryError::IssuanceCurrencyNotRegistered {
            issuance_currency: tribute_currency,
        })?;
        if pricing.issuance_wwd_vwap_minor.is_zero() || pricing.reference_wwd_vwap_minor.is_zero() {
            return Err(TributeFactoryError::NominalPriceUnavailable { worldwide_day }.into());
        }

        let zk_context = match zk_public_inputs {
            Some(public) => Some(TributeZkContext {
                derived_owner: B256::from(public.derived_owner),
                chain_id: self.storage.chain_id()?,
            }),
            None => None,
        };

        // Hand the encrypted offer + exact public Oracle inputs to the enclave. It
        // decrypts, computes economics (U256) + Poseidon token_id, and returns
        // only those. The host does not recompute private economics, but it can
        // and must verify the public owner/day identity recipe.
        let offer = EncryptedTributeOffer {
            owner: caller,
            cipher_text: cipher_text.to_vec(),
            nonce: nonce.to_vec(),
            ephemeral_pubkey,
            worldwide_day,
            tribute_currency,
            reference_currency,
            exclude_from_intex_issuance,
            issuance_wwd_vwap_minor: pricing.issuance_wwd_vwap_minor,
            reference_wwd_vwap_minor: pricing.reference_wwd_vwap_minor,
            reference_scurve_minor: pricing.reference_scurve_minor,
            zk_context,
        };
        // Node-local enclave faults (dead sidecar after the session's bounded
        // reconnect+retry, non-determinism, bad attestation) are Fatal - see
        // `enclave_offer` - never a deterministic revert.
        let results = processor(&[offer])?;
        let result = results.into_iter().next().ok_or_else(|| {
            PrecompileError::Fatal("enclave returned an empty tribute offer result".into())
        })?;

        if let TributeOfferStatus::Rejected { reason } = &result.status {
            return Err(TributeFactoryError::EnclaveRejected(reason.clone()).into());
        }
        if let Some(public) = zk_public_inputs {
            validate_zk_result(&zk_proof, public, result.zk_expected_hashes.as_ref())?;
        }

        // Recomputed from this call's own inputs, so it checks the enclave's
        // Poseidon rather than the enclave's own consistency with itself.
        // The identity keeps only the digest tail, so the enclave's token id is
        // checked against the whole digest rather than against the identity.
        let expected_digest = derive_poseidon_digest(caller, worldwide_day)
            .map_err(|error| PrecompileError::Fatal(error.to_string()))?;
        if result.owner != caller || result.token_id != expected_digest {
            return Err(TributeFactoryError::InvalidCanonicalIdentity.into());
        }

        let tribute_id = WwdEntityId::from_day_and_digest(worldwide_day, expected_digest);
        let tribute = TributeContract::new(self.storage.clone());
        if tribute.get_tribute(scope, parent, tribute_id)?.is_some() {
            return Err(TributeFactoryError::TributeAlreadyExists.into());
        }

        let su_hashes = parse_su_hashes(&result.su_hashes)?;
        self.mark_su_hashes_used(&su_hashes)?;

        let (wallet_addresses, sra_addresses) =
            validate_agent_reward_addresses(&result.wallet_addresses, &result.sra_addresses)?;

        let mut tribute = TributeContract::new(self.storage.clone());
        tribute.issue(
            scope,
            parent,
            &TributeData {
                tribute_id,
                owner: caller,
                worldwide_day,
                issuance_amount_minor: result.issuance_amount_minor,
                issuance_currency: tribute_currency,
                nominal_amount_minor: result.nominal_amount_minor,
                reference_currency,
                exclude_from_intex_issuance,
                tribute_price_minor: result.effective_reference_price_minor,
            },
        )?;

        self.record_agent_reward_activity(&wallet_addresses, &sra_addresses)?;

        Ok(tribute_id)
    }

    /// Records one successful offer in the UTC reward-day bucket consumed by
    /// Cycle on the following calendar day. The Tribute target WWD deliberately
    /// does not cross this boundary: all offers executed on the same UTC day
    /// share that day's WAA and SRA pools.
    fn record_agent_reward_activity(
        &self,
        wallet_addresses: &[Address],
        sra_addresses: &[Address],
    ) -> Result<()> {
        if wallet_addresses.is_empty() {
            return Ok(());
        }

        let timestamp = u64::try_from(self.storage.timestamp()?).map_err(|_| {
            PrecompileError::Fatal("TributeFactory block timestamp exceeds u64".into())
        })?;
        let reward_utc_day = WorldwideDay::new(timestamp_to_date_key(timestamp));
        let mut agent_reward = AgentRewardContract::new(self.storage.clone());

        for address in wallet_addresses {
            agent_reward.increment_waa_tribute(reward_utc_day, *address)?;
        }
        for address in sra_addresses {
            agent_reward.increment_sra_tribute(reward_utc_day, *address)?;
        }

        Ok(())
    }
}

fn validate_zk_result(
    zk_proof: &[u8],
    public: FullProofPublicInputs,
    expected: Option<&outbe_tee::protocol::TributeZkExpectedHashes>,
) -> Result<()> {
    let expected = expected.ok_or(TributeFactoryError::ZkPublicInputMismatch {
        field: "tee_expected_hashes",
    })?;
    if public.nft_hash != expected.nft_hash.0 {
        return Err(TributeFactoryError::ZkPublicInputMismatch { field: "nft_hash" }.into());
    }
    if public.binding_hash != expected.binding_hash.0 {
        return Err(TributeFactoryError::ZkPublicInputMismatch {
            field: "binding_hash",
        }
        .into());
    }
    let verified = verify_circuit::<FullProof>(zk_proof).map_err(|error| {
        PrecompileError::Fatal(format!(
            "ZK verifier unavailable: zk verification backend failed: {error}"
        ))
    })?;
    if !verified {
        return Err(TributeFactoryError::InvalidZkProof.into());
    }
    Ok(())
}

fn parse_su_hashes(su_hashes: &[String]) -> Result<Vec<B256>> {
    su_hashes
        .iter()
        .map(|hash| {
            let hex_str = hash.strip_prefix("0x").unwrap_or(hash);
            let bytes = hex::decode(hex_str)
                .map_err(|_| TributeFactoryError::InvalidSuHashHex { hash: hash.clone() })?;
            if bytes.len() != 32 {
                return Err(TributeFactoryError::InvalidSuHashLength {
                    length: bytes.len(),
                }
                .into());
            }
            Ok(B256::from_slice(&bytes))
        })
        .collect()
}

pub(crate) fn validate_agent_reward_addresses(
    wallet_addresses: &[String],
    sra_addresses: &[String],
) -> Result<(Vec<Address>, Vec<Address>)> {
    let has_wallets = !wallet_addresses.is_empty();
    let has_sras = !sra_addresses.is_empty();

    if !has_wallets && !has_sras {
        return Ok((Vec::new(), Vec::new()));
    }
    if !has_wallets {
        return Err(TributeFactoryError::WalletAddressesRequiredWhenSraProvided.into());
    }
    if !has_sras {
        return Err(TributeFactoryError::SraAddressesRequiredWhenWalletProvided.into());
    }

    let wallets = wallet_addresses
        .iter()
        .enumerate()
        .map(|(index, address)| {
            address.parse::<Address>().map_err(|_| {
                TributeFactoryError::InvalidWalletAddressAtIndex {
                    index,
                    address: address.clone(),
                }
                .into()
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let sras = sra_addresses
        .iter()
        .enumerate()
        .map(|(index, address)| {
            address.parse::<Address>().map_err(|_| {
                TributeFactoryError::InvalidSraAddressAtIndex {
                    index,
                    address: address.clone(),
                }
                .into()
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok((wallets, sras))
}

// Amount normalization now lives in the enclave (`compute::normalize_amount`),
// which is the single producer of the canonical economics. The host no longer
// recomputes amounts.

#[cfg(test)]
mod zk_result_tests {
    use super::*;
    use outbe_tee::protocol::TributeZkExpectedHashes;
    use outbe_zk_canonical::full_proof::COMBINED_LEN as FULL_PROOF_COMBINED_LEN;

    fn public_inputs() -> FullProofPublicInputs {
        FullProofPublicInputs {
            derived_owner: [1; 32],
            nft_hash: [2; 32],
            binding_hash: [3; 32],
            merkle_root: [4; 32],
        }
    }

    fn dummy_proof(public: FullProofPublicInputs) -> Vec<u8> {
        let mut proof = Vec::with_capacity(FULL_PROOF_COMBINED_LEN);
        proof.extend_from_slice(&4u32.to_be_bytes());
        for word in [
            public.derived_owner,
            public.nft_hash,
            public.binding_hash,
            public.merkle_root,
        ] {
            proof.extend_from_slice(&word);
        }
        proof.resize(FULL_PROOF_COMBINED_LEN, 0);
        proof
    }

    #[test]
    fn rejects_nft_hash_mismatch_before_proof_verification() {
        let public = public_inputs();
        let expected = TributeZkExpectedHashes {
            nft_hash: B256::from([9; 32]),
            binding_hash: B256::from(public.binding_hash),
        };

        let error = validate_zk_result(&dummy_proof(public), public, Some(&expected)).unwrap_err();
        assert!(error.to_string().contains("nft_hash"));
    }

    #[test]
    fn rejects_binding_hash_mismatch_before_proof_verification() {
        let public = public_inputs();
        let expected = TributeZkExpectedHashes {
            nft_hash: B256::from(public.nft_hash),
            binding_hash: B256::from([9; 32]),
        };

        let error = validate_zk_result(&dummy_proof(public), public, Some(&expected)).unwrap_err();
        assert!(error.to_string().contains("binding_hash"));
    }

    #[test]
    fn treats_backend_rejection_as_fatal_after_public_inputs_match() {
        let public = public_inputs();
        let expected = TributeZkExpectedHashes {
            nft_hash: B256::from(public.nft_hash),
            binding_hash: B256::from(public.binding_hash),
        };

        let error = validate_zk_result(&dummy_proof(public), public, Some(&expected)).unwrap_err();
        assert!(
            error.to_string().contains("ZK verifier unavailable"),
            "unexpected error: {error}"
        );
    }
}
