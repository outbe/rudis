//! Node-level handler registries for vote target dispatch and upgrade migrations.
//!
//! Handler implementations live in their owning crates; this module wires them
//! into Vote and Update lifecycle at block processing time.

pub mod vote {
    use alloy_primitives::{Address, U256};
    use outbe_governance::vote_target::GovernanceVoteTarget;
    use outbe_l2registry::L2RegistryVoteTarget;
    use outbe_primitives::addresses::STABLECOIN_FACTORY_ADDRESS;
    use outbe_primitives::block::BlockRuntimeContext;
    use outbe_primitives::error::{PrecompileError, Result};
    use outbe_primitives::stablecoin::decode_canonical_stablecoin_create;
    use outbe_primitives::stablecoin_fork::STABLECOIN_CREATE_BOND;
    use outbe_primitives::storage::StorageHandle;
    use outbe_stablecoinfactory::{
        FactoryReservation, StablecoinFactoryApi, ValidatedStablecoinCreate,
    };
    use outbe_update::vote_target::UpdateVoteTarget;
    use outbe_vote::handlers::{
        TargetAdmission, TargetExecutionOutcome, VoteTarget, VoteTargetContext, VoteTargetRegistry,
    };
    use outbe_vote::schema::ProposalStatus;

    static UPDATE_VOTE_TARGET: UpdateVoteTarget = UpdateVoteTarget;
    static GOVERNANCE_VOTE_TARGET: GovernanceVoteTarget = GovernanceVoteTarget;
    static L2_REGISTRY_VOTE_TARGET: L2RegistryVoteTarget = L2RegistryVoteTarget;
    static STABLECOIN_FACTORY_VOTE_TARGET: StablecoinFactoryVoteTarget =
        StablecoinFactoryVoteTarget;
    static ACTIVE_VOTE_TARGETS: &[&dyn VoteTarget] = &[
        &UPDATE_VOTE_TARGET,
        &GOVERNANCE_VOTE_TARGET,
        &L2_REGISTRY_VOTE_TARGET,
        &STABLECOIN_FACTORY_VOTE_TARGET,
    ];
    static REGISTRY: VoteTargetRegistry = VoteTargetRegistry::new(ACTIVE_VOTE_TARGETS);

    struct StablecoinFactoryVoteTarget;

    impl StablecoinFactoryVoteTarget {
        fn validate_payload(
            payload: &[u8],
            context: VoteTargetContext,
        ) -> Result<ValidatedStablecoinCreate> {
            let decoded = decode_canonical_stablecoin_create(payload)
                .map_err(|_| PrecompileError::Revert("non-canonical stablecoin payload".into()))?;
            if decoded.issuer != context.proposer {
                return Err(PrecompileError::Revert(
                    "stablecoin proposer must equal issuer".into(),
                ));
            }
            let (token_id, token) = outbe_primitives::stablecoin::predict_stablecoin(
                context.chain_id,
                STABLECOIN_FACTORY_ADDRESS,
                decoded.issuer,
                &decoded.ticker,
                outbe_primitives::addresses::STABLECOIN_ADDRESS_PREFIX,
            )
            .map_err(|_| PrecompileError::Revert("invalid stablecoin identity".into()))?;
            Ok(ValidatedStablecoinCreate {
                payload: decoded,
                token_id,
                token,
            })
        }
    }

    impl VoteTarget for StablecoinFactoryVoteTarget {
        fn target_module(&self) -> Address {
            STABLECOIN_FACTORY_ADDRESS
        }

        fn admission(&self) -> TargetAdmission {
            TargetAdmission::PublicBonded {
                amount: STABLECOIN_CREATE_BOND,
            }
        }

        fn validate(&self, payload: &[u8], context: VoteTargetContext) -> Result<()> {
            Self::validate_payload(payload, context).map(|_| ())
        }

        fn reserve(
            &self,
            storage: StorageHandle<'_>,
            proposal_id: U256,
            payload: &[u8],
            context: VoteTargetContext,
        ) -> Result<()> {
            let validated =
                StablecoinFactoryApi::validate_create(storage.clone(), context.proposer, payload)?;
            StablecoinFactoryApi::reserve(
                storage,
                &FactoryReservation {
                    proposal_id,
                    token_id: validated.token_id,
                    ticker: validated.payload.ticker,
                    token: validated.token,
                },
            )
        }

        fn handle_approved(
            &self,
            ctx: &BlockRuntimeContext,
            proposal_id: U256,
            payload: &[u8],
            context: VoteTargetContext,
        ) -> Result<TargetExecutionOutcome> {
            match StablecoinFactoryApi::execute_approved(
                ctx.storage.clone(),
                proposal_id,
                context.proposer,
                payload,
                0,
            ) {
                Ok(_) => Ok(TargetExecutionOutcome::Applied),
                Err(error @ (PrecompileError::Revert(_) | PrecompileError::RevertBytes(_))) => {
                    Ok(TargetExecutionOutcome::Error {
                        reason: error.to_string(),
                    })
                }
                Err(error) => Err(error),
            }
        }

        fn handle_tally(
            &self,
            ctx: &BlockRuntimeContext,
            proposal_id: U256,
            payload: &[u8],
            context: VoteTargetContext,
            status: ProposalStatus,
        ) -> Result<TargetExecutionOutcome> {
            match status {
                ProposalStatus::Approved => {
                    self.handle_approved(ctx, proposal_id, payload, context)
                }
                ProposalStatus::Expired => {
                    StablecoinFactoryApi::release(ctx.storage.clone(), proposal_id)?;
                    Ok(TargetExecutionOutcome::Applied)
                }
                ProposalStatus::Pending | ProposalStatus::Rejected | ProposalStatus::Error => {
                    Ok(TargetExecutionOutcome::Applied)
                }
            }
        }
    }

    /// Returns the compile-time vote target registry for executor wiring.
    pub fn registry() -> &'static VoteTargetRegistry {
        &REGISTRY
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use alloy_sol_types::SolEvent;
        use commonware_codec::Encode;
        use commonware_cryptography::bls12381::primitives::{ops, variant::MinSig};
        use outbe_l2registry::L2RegistryContract;
        use outbe_primitives::addresses::L2_REGISTRY_ADDRESS;
        use outbe_primitives::addresses::VOTE_ADDRESS;
        use outbe_primitives::block::BlockContext;
        use outbe_primitives::stablecoin::{
            encode_canonical_stablecoin_create, StablecoinCreatePayload,
        };
        use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
        use outbe_stablecoinfactory::StablecoinFactoryContract;
        use outbe_validatorset::contract::ValidatorSet;
        use outbe_vote::constants::VOTING_WINDOW_BLOCKS;
        use outbe_vote::precompile::IVote;
        use outbe_vote::schema::{BondSettlement, Vote};

        const VALIDATOR_OWNER: Address = Address::repeat_byte(0xff);
        const VALIDATOR_A: Address = Address::repeat_byte(0xa1);
        const VALIDATOR_B: Address = Address::repeat_byte(0xa2);
        const VALIDATOR_C: Address = Address::repeat_byte(0xa3);
        const VALIDATOR_D: Address = Address::repeat_byte(0xa4);

        #[test]
        fn l2_registry_is_an_active_validator_vote_target() {
            let target = registry()
                .lookup(outbe_primitives::addresses::L2_REGISTRY_ADDRESS)
                .expect("L2Registry vote target must be active");
            assert_eq!(target.admission(), TargetAdmission::ActiveValidatorOnly);
        }

        fn payload(issuer: Address) -> Vec<u8> {
            encode_canonical_stablecoin_create(&StablecoinCreatePayload {
                issuer,
                name: "Example Dollar".into(),
                ticker: "EXUSD".into(),
                iso4217: 840,
                decimals: 6,
                supply_cap: U256::from(1_000_000u64),
                policy_id: U256::from(1u64),
            })
            .unwrap()
        }

        fn payload_with_ticker(issuer: Address, ticker: &str) -> Vec<u8> {
            encode_canonical_stablecoin_create(&StablecoinCreatePayload {
                issuer,
                name: format!("{ticker} stablecoin"),
                ticker: ticker.into(),
                iso4217: 840,
                decimals: 6,
                supply_cap: U256::from(1_000_000u64),
                policy_id: U256::from(1u64),
            })
            .unwrap()
        }

        fn l2_register_payload(chain_id: u64, l1_address: Address) -> String {
            let (_, public_key) = ops::keypair::<_, MinSig>(&mut rand_core::OsRng);
            serde_json::json!({
                "operation": "register",
                "chainId": chain_id,
                "l1Address": format!("{l1_address:#x}"),
                "publicKey": format!("0x{}", hex::encode(public_key.encode())),
                "zkEnabled": true,
            })
            .to_string()
        }

        fn context(issuer: Address) -> VoteTargetContext {
            VoteTargetContext {
                proposer: issuer,
                attached_value: STABLECOIN_CREATE_BOND,
                block_number: 7,
                chain_id: 1,
            }
        }

        fn register_active_validator(storage: StorageHandle<'_>, validator: Address, seed: u8) {
            let mut validator_set = ValidatorSet::new(storage);
            validator_set.config_owner.write(VALIDATOR_OWNER).unwrap();
            validator_set.set_config_max_validators(100).unwrap();
            let mut public_key = [0u8; 48];
            public_key[0] = seed;
            validator_set
                .register_validator(VALIDATOR_OWNER, validator, &public_key)
                .unwrap();
            validator_set
                .activate_validator_via_boundary_for_test(validator)
                .unwrap();
        }

        fn setup_active_validators(storage: StorageHandle<'_>) {
            register_active_validator(storage.clone(), VALIDATOR_A, 1);
            register_active_validator(storage.clone(), VALIDATOR_B, 2);
            register_active_validator(storage, VALIDATOR_C, 3);
        }

        fn finalize_context(
            storage: StorageHandle<'_>,
            block_number: u64,
            issuer: Address,
        ) -> BlockRuntimeContext<'_> {
            BlockRuntimeContext::new(
                BlockContext::new(block_number, 1_700_000_000, 1, issuer, vec![issuer]),
                storage,
            )
        }

        #[test]
        fn l2_registration_waits_for_deadline_then_applies_exactly_once() {
            const L2_CHAIN_ID: u64 = 4242;
            let l1_address = Address::repeat_byte(0x44);
            let payload = l2_register_payload(L2_CHAIN_ID, l1_address);
            let mut provider = HashMapStorageProvider::new(1);
            {
                let storage = StorageHandle::new(&mut provider);
                setup_active_validators(storage.clone());
                let mut vote = Vote::new(storage.clone());
                let proposal_id = vote
                    .create_proposal(VALIDATOR_A, L2_REGISTRY_ADDRESS, &payload, 7, registry())
                    .unwrap();
                vote.cast_vote_approve(proposal_id, VALIDATOR_A, true, 8)
                    .unwrap();
                vote.cast_vote_approve(proposal_id, VALIDATOR_B, true, 8)
                    .unwrap();

                let deadline = 7 + VOTING_WINDOW_BLOCKS;
                vote.process_begin_block(
                    &finalize_context(storage.clone(), deadline, VALIDATOR_A),
                    registry(),
                )
                .unwrap();
                assert_eq!(
                    vote.proposals
                        .get(proposal_id)
                        .unwrap()
                        .unwrap()
                        .proposal_status()
                        .unwrap(),
                    ProposalStatus::Pending
                );
                assert!(!L2RegistryContract::new(storage.clone())
                    .networks
                    .exists(L2_CHAIN_ID)
                    .unwrap());

                vote.process_begin_block(
                    &finalize_context(storage.clone(), deadline + 1, VALIDATOR_A),
                    registry(),
                )
                .unwrap();
                assert_eq!(
                    vote.proposals
                        .get(proposal_id)
                        .unwrap()
                        .unwrap()
                        .proposal_status()
                        .unwrap(),
                    ProposalStatus::Approved
                );
                let record = L2RegistryContract::new(storage.clone())
                    .load_network(L2_CHAIN_ID)
                    .unwrap();
                assert_eq!(record.l1_address, l1_address);
                assert!(record.zk_enabled);

                vote.process_begin_block(
                    &finalize_context(storage.clone(), deadline + 2, VALIDATOR_A),
                    registry(),
                )
                .unwrap();
                assert_eq!(
                    L2RegistryContract::new(storage)
                        .l1_to_chain
                        .read(&l1_address)
                        .unwrap(),
                    L2_CHAIN_ID
                );
            }
            assert_eq!(
                provider
                    .get_events(L2_REGISTRY_ADDRESS)
                    .iter()
                    .filter(|event| {
                        event.topics().first()
                            == Some(
                                &outbe_l2registry::precompile::IL2Registry::L2NetworkRegistered::SIGNATURE_HASH,
                            )
                    })
                    .count(),
                1
            );
        }

        #[test]
        fn conflicting_approved_l2_registration_becomes_error_without_blocking_tally() {
            const L2_CHAIN_ID: u64 = 4242;
            let l1_address = Address::repeat_byte(0x44);
            let payload = l2_register_payload(L2_CHAIN_ID, l1_address);
            let mut provider = HashMapStorageProvider::new(1);
            let storage = StorageHandle::new(&mut provider);
            setup_active_validators(storage.clone());
            let mut vote = Vote::new(storage.clone());
            let first = vote
                .create_proposal(VALIDATOR_A, L2_REGISTRY_ADDRESS, &payload, 7, registry())
                .unwrap();
            let second = vote
                .create_proposal(VALIDATOR_B, L2_REGISTRY_ADDRESS, &payload, 7, registry())
                .unwrap();
            for proposal_id in [first, second] {
                vote.cast_vote_approve(proposal_id, VALIDATOR_A, true, 8)
                    .unwrap();
                vote.cast_vote_approve(proposal_id, VALIDATOR_B, true, 8)
                    .unwrap();
            }

            let deadline = 7 + VOTING_WINDOW_BLOCKS;
            vote.process_begin_block(
                &finalize_context(storage.clone(), deadline + 1, VALIDATOR_A),
                registry(),
            )
            .unwrap();
            assert_eq!(
                vote.proposals
                    .get(first)
                    .unwrap()
                    .unwrap()
                    .proposal_status()
                    .unwrap(),
                ProposalStatus::Approved
            );
            assert_eq!(
                vote.proposals
                    .get(second)
                    .unwrap()
                    .unwrap()
                    .proposal_status()
                    .unwrap(),
                ProposalStatus::Error
            );
            assert_eq!(
                L2RegistryContract::new(storage)
                    .l1_to_chain
                    .read(&l1_address)
                    .unwrap(),
                L2_CHAIN_ID
            );
        }

        #[test]
        fn below_quorum_l2_registration_expires_without_registry_effects() {
            const L2_CHAIN_ID: u64 = 4242;
            let l1_address = Address::repeat_byte(0x44);
            let payload = l2_register_payload(L2_CHAIN_ID, l1_address);
            let mut provider = HashMapStorageProvider::new(1);
            let storage = StorageHandle::new(&mut provider);
            setup_active_validators(storage.clone());
            let mut vote = Vote::new(storage.clone());
            let proposal_id = vote
                .create_proposal(VALIDATOR_A, L2_REGISTRY_ADDRESS, &payload, 7, registry())
                .unwrap();
            vote.cast_vote_approve(proposal_id, VALIDATOR_A, true, 8)
                .unwrap();

            let deadline = 7 + VOTING_WINDOW_BLOCKS;
            vote.process_begin_block(
                &finalize_context(storage.clone(), deadline + 1, VALIDATOR_A),
                registry(),
            )
            .unwrap();
            assert_eq!(
                vote.proposals
                    .get(proposal_id)
                    .unwrap()
                    .unwrap()
                    .proposal_status()
                    .unwrap(),
                ProposalStatus::Expired
            );
            assert!(!L2RegistryContract::new(storage)
                .networks
                .exists(L2_CHAIN_ID)
                .unwrap());
        }

        #[test]
        fn factory_target_has_exact_bond_and_reserves_from_genesis() {
            let issuer = Address::repeat_byte(0x11);
            let raw = payload(issuer);
            let target = registry().lookup(STABLECOIN_FACTORY_ADDRESS).unwrap();
            assert_eq!(
                target.admission(),
                TargetAdmission::PublicBonded {
                    amount: STABLECOIN_CREATE_BOND
                }
            );
            target.validate(&raw, context(issuer)).unwrap();
            assert!(target
                .validate(&raw, context(Address::repeat_byte(0x22)))
                .is_err());

            let mut provider = HashMapStorageProvider::new(1);
            let storage = StorageHandle::new(&mut provider);
            target
                .reserve(storage.clone(), U256::from(1u64), &raw, context(issuer))
                .unwrap();
            let factory = StablecoinFactoryContract::new(storage);
            assert!(factory.reservations.exists(U256::from(1u64)).unwrap());
        }

        #[test]
        fn factory_public_admission_atomically_records_reservation_and_bond() {
            let issuer = Address::repeat_byte(0x11);
            let raw = payload(issuer);
            let raw = core::str::from_utf8(&raw).unwrap();
            let forced_surplus = U256::from(7u64);
            let mut provider = HashMapStorageProvider::new(1);
            provider.set_balance(VOTE_ADDRESS, STABLECOIN_CREATE_BOND + forced_surplus);
            {
                let storage = StorageHandle::new(&mut provider);
                let mut vote = Vote::new(storage.clone());
                let proposal_id = vote
                    .create_proposal_with_value(
                        issuer,
                        STABLECOIN_FACTORY_ADDRESS,
                        raw,
                        7,
                        STABLECOIN_CREATE_BOND,
                        registry(),
                    )
                    .unwrap();
                assert_eq!(
                    vote.proposal_bond(proposal_id).unwrap().settlement,
                    BondSettlement::Unsettled
                );
                assert_eq!(vote.bond_liabilities().unwrap(), STABLECOIN_CREATE_BOND);
                assert!(StablecoinFactoryContract::new(storage)
                    .reservations
                    .exists(proposal_id)
                    .unwrap());
            }
            assert_eq!(
                provider.get_balance(VOTE_ADDRESS),
                STABLECOIN_CREATE_BOND + forced_surplus
            );

            let mut mismatch_provider = HashMapStorageProvider::new(1);
            mismatch_provider.set_balance(VOTE_ADDRESS, STABLECOIN_CREATE_BOND);
            let mismatch_storage = StorageHandle::new(&mut mismatch_provider);
            let mut vote = Vote::new(mismatch_storage.clone());
            assert!(vote
                .create_proposal_with_value(
                    Address::repeat_byte(0x22),
                    STABLECOIN_FACTORY_ADDRESS,
                    raw,
                    7,
                    STABLECOIN_CREATE_BOND,
                    registry(),
                )
                .is_err());
            assert_eq!(vote.proposal_count.read().unwrap(), U256::ZERO);
            assert_eq!(vote.bond_liabilities().unwrap(), U256::ZERO);
            assert!(!StablecoinFactoryContract::new(mismatch_storage)
                .reservations
                .exists(U256::from(1u64))
                .unwrap());
        }

        #[test]
        fn real_factory_vote_approval_creates_token_refunds_once_and_preserves_surplus() {
            let issuer = Address::repeat_byte(0x11);
            let raw = payload(issuer);
            let raw = core::str::from_utf8(&raw).unwrap();
            let forced_surplus = U256::from(7u64);
            let issuer_start = U256::from(11u64);
            let mut provider = HashMapStorageProvider::new(1);
            provider.set_balance(VOTE_ADDRESS, STABLECOIN_CREATE_BOND + forced_surplus);
            provider.set_balance(issuer, issuer_start);
            let proposal_id;
            {
                let storage = StorageHandle::new(&mut provider);
                setup_active_validators(storage.clone());
                let mut vote = Vote::new(storage.clone());
                let factory = StablecoinFactoryContract::new(storage.clone());
                let (expected_id, expected_token) =
                    factory.predict_token_address(issuer, "EXUSD").unwrap();
                proposal_id = vote
                    .create_proposal_with_value(
                        issuer,
                        STABLECOIN_FACTORY_ADDRESS,
                        raw,
                        7,
                        STABLECOIN_CREATE_BOND,
                        registry(),
                    )
                    .unwrap();
                vote.cast_vote_approve(proposal_id, VALIDATOR_A, true, 8)
                    .unwrap();
                vote.cast_vote_approve(proposal_id, VALIDATOR_B, true, 8)
                    .unwrap();

                let deadline = 7 + VOTING_WINDOW_BLOCKS;
                vote.process_begin_block(
                    &finalize_context(storage.clone(), deadline + 1, issuer),
                    registry(),
                )
                .unwrap();

                assert_eq!(
                    vote.proposals
                        .get(proposal_id)
                        .unwrap()
                        .unwrap()
                        .proposal_status()
                        .unwrap(),
                    ProposalStatus::Approved
                );
                assert_eq!(
                    vote.proposal_bond(proposal_id).unwrap().settlement,
                    BondSettlement::Refunded
                );
                assert_eq!(vote.bond_liabilities().unwrap(), U256::ZERO);
                assert_eq!(storage.balance(VOTE_ADDRESS).unwrap(), forced_surplus);
                assert_eq!(
                    storage.balance(issuer).unwrap(),
                    issuer_start + STABLECOIN_CREATE_BOND
                );
                assert_eq!(factory.token_count().unwrap(), U256::from(1u64));
                assert_eq!(
                    factory.registered_token_id(expected_token).unwrap(),
                    Some(expected_id)
                );
                assert!(!factory.reservations.exists(proposal_id).unwrap());

                vote.process_begin_block(
                    &finalize_context(storage.clone(), deadline + 2, issuer),
                    registry(),
                )
                .unwrap();
                assert_eq!(storage.balance(VOTE_ADDRESS).unwrap(), forced_surplus);
                assert_eq!(
                    storage.balance(issuer).unwrap(),
                    issuer_start + STABLECOIN_CREATE_BOND
                );
                assert_eq!(factory.token_count().unwrap(), U256::from(1u64));
            }

            assert_eq!(
                provider
                    .get_events(VOTE_ADDRESS)
                    .iter()
                    .filter(|event| {
                        event.topics().first() == Some(&IVote::ProposalBondRefunded::SIGNATURE_HASH)
                    })
                    .count(),
                1
            );
            assert_eq!(proposal_id, U256::from(1u64));
        }

        #[test]
        fn pfs_010_05_expiry_releases_identity_and_pending_cap_and_burns_once() {
            let issuer = Address::repeat_byte(0x11);
            let raw = payload(issuer);
            let raw = core::str::from_utf8(&raw).unwrap();
            let forced_surplus = U256::from(7u64);
            let mut provider = HashMapStorageProvider::new(1);
            provider.set_block_number(8);
            provider.set_balance(VOTE_ADDRESS, STABLECOIN_CREATE_BOND + forced_surplus);
            let proposal_id;
            {
                let storage = StorageHandle::new(&mut provider);
                setup_active_validators(storage.clone());
                let mut vote = Vote::new(storage.clone());
                proposal_id = vote
                    .create_proposal_with_value(
                        issuer,
                        STABLECOIN_FACTORY_ADDRESS,
                        raw,
                        7,
                        STABLECOIN_CREATE_BOND,
                        registry(),
                    )
                    .unwrap();
                vote.cast_vote_approve(proposal_id, VALIDATOR_A, true, 8)
                    .unwrap();
                vote.cast_vote_approve(proposal_id, VALIDATOR_B, true, 8)
                    .unwrap();

                let mut validator_set = ValidatorSet::new(storage.clone());
                validator_set
                    .deactivate_validator(VALIDATOR_OWNER, VALIDATOR_B)
                    .unwrap();
                register_active_validator(storage.clone(), VALIDATOR_D, 4);

                let deadline = 7 + VOTING_WINDOW_BLOCKS;
                vote.process_begin_block(
                    &finalize_context(storage.clone(), deadline + 1, issuer),
                    registry(),
                )
                .unwrap();

                assert_eq!(
                    vote.proposals
                        .get(proposal_id)
                        .unwrap()
                        .unwrap()
                        .proposal_status()
                        .unwrap(),
                    ProposalStatus::Expired
                );
                assert_eq!(
                    vote.proposal_bond(proposal_id).unwrap().settlement,
                    BondSettlement::Burned
                );
                assert_eq!(vote.bond_liabilities().unwrap(), U256::ZERO);
                assert_eq!(storage.balance(VOTE_ADDRESS).unwrap(), forced_surplus);
                assert_eq!(storage.balance(issuer).unwrap(), U256::ZERO);
                let factory = StablecoinFactoryContract::new(storage.clone());
                assert_eq!(factory.token_count().unwrap(), U256::ZERO);
                assert!(!factory.reservations.exists(proposal_id).unwrap());

                vote.process_begin_block(
                    &finalize_context(storage.clone(), deadline + 2, issuer),
                    registry(),
                )
                .unwrap();
                assert_eq!(storage.balance(VOTE_ADDRESS).unwrap(), forced_surplus);
            }

            provider.set_balance(VOTE_ADDRESS, STABLECOIN_CREATE_BOND + forced_surplus);
            {
                let storage = StorageHandle::new(&mut provider);
                let mut vote = Vote::new(storage.clone());
                let retry_id = vote
                    .create_proposal_with_value(
                        issuer,
                        STABLECOIN_FACTORY_ADDRESS,
                        raw,
                        7 + VOTING_WINDOW_BLOCKS + 2,
                        STABLECOIN_CREATE_BOND,
                        registry(),
                    )
                    .unwrap();
                assert_eq!(retry_id, proposal_id + U256::from(1u64));
                assert_eq!(vote.pending_proposal_count_by_proposer(issuer).unwrap(), 1);
                assert!(StablecoinFactoryContract::new(storage)
                    .reservations
                    .exists(retry_id)
                    .unwrap());
            }

            assert_eq!(
                provider
                    .get_events(VOTE_ADDRESS)
                    .iter()
                    .filter(|event| {
                        event.topics().first() == Some(&IVote::ProposalBondBurned::SIGNATURE_HASH)
                    })
                    .count(),
                1
            );
            assert!(provider.get_events(STABLECOIN_FACTORY_ADDRESS).is_empty());
        }

        #[test]
        fn pfs_010_06_execution_error_retains_reservation_bond_and_pending_cap() {
            let issuer = Address::repeat_byte(0x11);
            let raw = payload(issuer);
            let raw = core::str::from_utf8(&raw).unwrap();
            let mut provider = HashMapStorageProvider::new(1);
            provider.set_balance(VOTE_ADDRESS, STABLECOIN_CREATE_BOND);
            let reserved_token;
            {
                let storage = StorageHandle::new(&mut provider);
                setup_active_validators(storage.clone());
                let mut vote = Vote::new(storage.clone());
                let proposal_id = vote
                    .create_proposal_with_value(
                        issuer,
                        STABLECOIN_FACTORY_ADDRESS,
                        raw,
                        7,
                        STABLECOIN_CREATE_BOND,
                        registry(),
                    )
                    .unwrap();
                let mut corrupted_payload = vote.proposals.get(proposal_id).unwrap().unwrap();
                corrupted_payload.payload = "{".into();
                vote.proposals.update(&corrupted_payload).unwrap();
                vote.cast_vote_approve(proposal_id, VALIDATOR_A, true, 8)
                    .unwrap();
                vote.cast_vote_approve(proposal_id, VALIDATOR_B, true, 8)
                    .unwrap();

                let deadline = 7 + VOTING_WINDOW_BLOCKS;
                vote.process_begin_block(
                    &finalize_context(storage.clone(), deadline + 1, issuer),
                    registry(),
                )
                .unwrap();

                assert_eq!(
                    vote.proposals
                        .get(proposal_id)
                        .unwrap()
                        .unwrap()
                        .proposal_status()
                        .unwrap(),
                    ProposalStatus::Error
                );
                assert_eq!(
                    vote.proposal_bond(proposal_id).unwrap().settlement,
                    BondSettlement::Unsettled
                );
                assert_eq!(vote.bond_liabilities().unwrap(), STABLECOIN_CREATE_BOND);
                assert_eq!(
                    storage.balance(VOTE_ADDRESS).unwrap(),
                    STABLECOIN_CREATE_BOND
                );
                assert_eq!(storage.balance(issuer).unwrap(), U256::ZERO);
                let factory = StablecoinFactoryContract::new(storage);
                assert_eq!(factory.token_count().unwrap(), U256::ZERO);
                let reservation = factory.reservations.get(proposal_id).unwrap().unwrap();
                reserved_token = reservation.token;
                assert_eq!(
                    factory
                        .pending_token_id
                        .read(&reservation.token_id)
                        .unwrap(),
                    proposal_id
                );
                assert_eq!(
                    factory
                        .pending_ticker
                        .read(&reservation.ticker_hash)
                        .unwrap(),
                    proposal_id
                );
                assert_eq!(
                    factory.pending_address.read(&reservation.token).unwrap(),
                    proposal_id
                );
                assert_eq!(vote.pending_proposal_count_by_proposer(issuer).unwrap(), 1);
            }
            assert_eq!(
                provider
                    .get_events(VOTE_ADDRESS)
                    .iter()
                    .filter(|event| {
                        event.topics().first() == Some(&IVote::ProposalBondRefunded::SIGNATURE_HASH)
                            || event.topics().first()
                                == Some(&IVote::ProposalBondBurned::SIGNATURE_HASH)
                    })
                    .count(),
                0
            );
            assert!(provider.get_events(STABLECOIN_FACTORY_ADDRESS).is_empty());
            assert!(provider
                .get_account_info(reserved_token)
                .is_none_or(|account| account
                    .code
                    .as_ref()
                    .is_none_or(|code| code.original_bytes().is_empty())));
        }

        #[test]
        fn real_factory_vote_rejects_global_ticker_collision_before_allocation() {
            let issuer_a = Address::repeat_byte(0x11);
            let issuer_b = Address::repeat_byte(0x22);
            let raw_a = payload_with_ticker(issuer_a, "GLB");
            let raw_b = payload_with_ticker(issuer_b, "GLB");
            let mut provider = HashMapStorageProvider::new(1);
            provider.set_balance(VOTE_ADDRESS, STABLECOIN_CREATE_BOND * U256::from(2u64));
            let storage = StorageHandle::new(&mut provider);
            let mut vote = Vote::new(storage.clone());
            let first = vote
                .create_proposal_with_value(
                    issuer_a,
                    STABLECOIN_FACTORY_ADDRESS,
                    core::str::from_utf8(&raw_a).unwrap(),
                    7,
                    STABLECOIN_CREATE_BOND,
                    registry(),
                )
                .unwrap();
            assert!(vote
                .create_proposal_with_value(
                    issuer_b,
                    STABLECOIN_FACTORY_ADDRESS,
                    core::str::from_utf8(&raw_b).unwrap(),
                    7,
                    STABLECOIN_CREATE_BOND,
                    registry(),
                )
                .is_err());
            assert_eq!(vote.proposal_count.read().unwrap(), first);
            assert_eq!(vote.bond_liabilities().unwrap(), STABLECOIN_CREATE_BOND);
            assert!(!StablecoinFactoryContract::new(storage)
                .reservations
                .exists(first + U256::from(1u64))
                .unwrap());
        }

        #[test]
        fn factory_target_approved_expired_error_and_fatal_paths_are_distinct() {
            let issuer = Address::repeat_byte(0x11);
            let raw = payload(issuer);
            let target = registry().lookup(STABLECOIN_FACTORY_ADDRESS).unwrap();

            let mut approved_provider = HashMapStorageProvider::new(1);
            let approved_storage = StorageHandle::new(&mut approved_provider);
            target
                .reserve(
                    approved_storage.clone(),
                    U256::from(1u64),
                    &raw,
                    context(issuer),
                )
                .unwrap();
            let approved_ctx = BlockRuntimeContext::new(
                BlockContext::new(7, 1_700_000_000, 1, issuer, vec![issuer]),
                approved_storage.clone(),
            );
            assert_eq!(
                target
                    .handle_tally(
                        &approved_ctx,
                        U256::from(1u64),
                        &raw,
                        context(issuer),
                        ProposalStatus::Approved,
                    )
                    .unwrap(),
                TargetExecutionOutcome::Applied
            );
            assert_eq!(
                StablecoinFactoryContract::new(approved_storage)
                    .token_count()
                    .unwrap(),
                U256::from(1u64)
            );

            let mut expired_provider = HashMapStorageProvider::new(1);
            let expired_storage = StorageHandle::new(&mut expired_provider);
            target
                .reserve(
                    expired_storage.clone(),
                    U256::from(2u64),
                    &raw,
                    context(issuer),
                )
                .unwrap();
            let expired_ctx = BlockRuntimeContext::new(
                BlockContext::new(7, 1_700_000_000, 1, issuer, vec![issuer]),
                expired_storage.clone(),
            );
            assert_eq!(
                target
                    .handle_tally(
                        &expired_ctx,
                        U256::from(2u64),
                        &raw,
                        context(issuer),
                        ProposalStatus::Expired,
                    )
                    .unwrap(),
                TargetExecutionOutcome::Applied
            );
            assert!(!StablecoinFactoryContract::new(expired_storage)
                .reservations
                .exists(U256::from(2u64))
                .unwrap());

            let mut error_provider = HashMapStorageProvider::new(1);
            let error_storage = StorageHandle::new(&mut error_provider);
            target
                .reserve(
                    error_storage.clone(),
                    U256::from(3u64),
                    &raw,
                    context(issuer),
                )
                .unwrap();
            let error_ctx = BlockRuntimeContext::new(
                BlockContext::new(7, 1_700_000_000, 1, issuer, vec![issuer]),
                error_storage.clone(),
            );
            assert!(matches!(
                target
                    .handle_tally(
                        &error_ctx,
                        U256::from(3u64),
                        b"{",
                        context(issuer),
                        ProposalStatus::Approved,
                    )
                    .unwrap(),
                TargetExecutionOutcome::Error { .. }
            ));
            assert!(StablecoinFactoryContract::new(error_storage)
                .reservations
                .exists(U256::from(3u64))
                .unwrap());

            let mut fatal_provider = HashMapStorageProvider::new(1);
            let fatal_storage = StorageHandle::new(&mut fatal_provider);
            target
                .reserve(
                    fatal_storage.clone(),
                    U256::from(4u64),
                    &raw,
                    context(issuer),
                )
                .unwrap();
            let fatal_factory = StablecoinFactoryContract::new(fatal_storage.clone());
            let fatal_reservation = fatal_factory
                .reservations
                .get(U256::from(4u64))
                .unwrap()
                .unwrap();
            fatal_factory
                .pending_address
                .clear(&fatal_reservation.token)
                .unwrap();
            let fatal_ctx = BlockRuntimeContext::new(
                BlockContext::new(7, 1_700_000_000, 1, issuer, vec![issuer]),
                fatal_storage,
            );
            assert!(matches!(
                target.handle_tally(
                    &fatal_ctx,
                    U256::from(4u64),
                    &raw,
                    context(issuer),
                    ProposalStatus::Approved,
                ),
                Err(PrecompileError::Fatal(_))
            ));
        }

        #[test]
        fn pfs_010_08_fatal_creation_rolls_back_the_containing_block() {
            let issuer = Address::repeat_byte(0x11);
            let raw = payload(issuer);
            let raw_text = core::str::from_utf8(&raw).unwrap();
            let mut provider = HashMapStorageProvider::new(1);
            provider.set_balance(VOTE_ADDRESS, STABLECOIN_CREATE_BOND);

            let (proposal_id, reservation) = {
                let storage = StorageHandle::new(&mut provider);
                setup_active_validators(storage.clone());
                let mut vote = Vote::new(storage.clone());
                let proposal_id = vote
                    .create_proposal_with_value(
                        issuer,
                        STABLECOIN_FACTORY_ADDRESS,
                        raw_text,
                        7,
                        STABLECOIN_CREATE_BOND,
                        registry(),
                    )
                    .unwrap();
                vote.cast_vote_approve(proposal_id, VALIDATOR_A, true, 8)
                    .unwrap();
                vote.cast_vote_approve(proposal_id, VALIDATOR_B, true, 8)
                    .unwrap();

                let factory = StablecoinFactoryContract::new(storage);
                let reservation = factory.reservations.get(proposal_id).unwrap().unwrap();
                factory.pending_address.clear(&reservation.token).unwrap();
                (proposal_id, reservation)
            };
            let vote_events_before = provider.get_events(VOTE_ADDRESS).len();
            let factory_events_before = provider.get_events(STABLECOIN_FACTORY_ADDRESS).len();

            {
                let storage = StorageHandle::new(&mut provider);
                let deadline = 7 + VOTING_WINDOW_BLOCKS;
                let ctx = finalize_context(storage.clone(), deadline + 1, issuer);
                let result = ctx.with_checkpoint(|| {
                    Vote::new(storage.clone()).process_begin_block(&ctx, registry())
                });
                assert!(matches!(result, Err(PrecompileError::Fatal(_))));

                let vote = Vote::new(storage.clone());
                assert_eq!(
                    vote.proposals
                        .get(proposal_id)
                        .unwrap()
                        .unwrap()
                        .proposal_status()
                        .unwrap(),
                    ProposalStatus::Pending
                );
                assert_eq!(vote.pending_proposal_count_by_proposer(issuer).unwrap(), 1);
                assert_eq!(
                    vote.proposal_bond(proposal_id).unwrap().settlement,
                    BondSettlement::Unsettled
                );
                assert_eq!(vote.bond_liabilities().unwrap(), STABLECOIN_CREATE_BOND);
                assert_eq!(
                    storage.balance(VOTE_ADDRESS).unwrap(),
                    STABLECOIN_CREATE_BOND
                );
                assert_eq!(storage.balance(issuer).unwrap(), U256::ZERO);

                let factory = StablecoinFactoryContract::new(storage.clone());
                assert_eq!(factory.token_count().unwrap(), U256::ZERO);
                assert_eq!(
                    factory
                        .pending_token_id
                        .read(&reservation.token_id)
                        .unwrap(),
                    proposal_id
                );
                assert_eq!(
                    factory
                        .pending_ticker
                        .read(&reservation.ticker_hash)
                        .unwrap(),
                    proposal_id
                );
                assert!(factory
                    .pending_address
                    .read(&reservation.token)
                    .unwrap()
                    .is_zero());
                assert_eq!(
                    factory.reservations.get(proposal_id).unwrap(),
                    Some(reservation.clone())
                );
                assert_eq!(
                    storage.sload(reservation.token, U256::ZERO).unwrap(),
                    U256::ZERO
                );
            }

            assert_eq!(provider.get_events(VOTE_ADDRESS).len(), vote_events_before);
            assert_eq!(
                provider.get_events(STABLECOIN_FACTORY_ADDRESS).len(),
                factory_events_before
            );
            assert!(provider
                .get_account_info(reservation.token)
                .is_none_or(|account| account
                    .code
                    .as_ref()
                    .is_none_or(|code| code.original_bytes().is_empty())));
        }
    }
}

pub mod update {
    use outbe_update::handlers::{UpgradeHandlerRegistry, UpgradeHandlers};

    /// Active upgrade handlers for this node binary.
    ///
    /// Append entries when a protocol version requires deterministic storage
    /// migration at activation height. Versions without a handler activate as
    /// version-only switches.
    static ACTIVE_UPGRADE_HANDLERS: UpgradeHandlers = &[];
    static REGISTRY: UpgradeHandlerRegistry = UpgradeHandlerRegistry::new(ACTIVE_UPGRADE_HANDLERS);

    /// Returns the compile-time upgrade handler registry for executor wiring.
    pub fn registry() -> &'static UpgradeHandlerRegistry {
        &REGISTRY
    }

    #[cfg(test)]
    mod tests {
        use outbe_update::ProtocolVersion;

        #[test]
        fn ocomp_genesis_activation_registers_no_generic_update_handler() {
            assert!(super::registry()
                .lookup(ProtocolVersion::from_raw(1))
                .next()
                .is_none());
        }
    }
}
