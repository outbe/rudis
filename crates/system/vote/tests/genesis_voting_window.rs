use alloy_primitives::{Address, U256};
use alloy_sol_types::SolEvent;
use outbe_primitives::{
    addresses::{UPDATE_ADDRESS, VOTE_ADDRESS},
    block::BlockRuntimeContext,
    error::Result,
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
};
use outbe_validatorset::contract::ValidatorSet;
use outbe_vote::{
    handlers::{TargetExecutionOutcome, VoteTargetContext},
    precompile::IVote,
    Vote, VoteTarget, VoteTargetRegistry,
};

struct Target;
impl VoteTarget for Target {
    fn target_module(&self) -> Address {
        UPDATE_ADDRESS
    }
    fn validate(&self, payload: &[u8], _: VoteTargetContext) -> Result<()> {
        assert_eq!(payload, b"{}");
        Ok(())
    }
    fn handle_approved(
        &self,
        _: &BlockRuntimeContext,
        _: U256,
        _: &[u8],
        _: VoteTargetContext,
    ) -> Result<TargetExecutionOutcome> {
        Ok(TargetExecutionOutcome::Applied)
    }
}
static TARGET: Target = Target;
static TARGETS: &[&dyn VoteTarget] = &[&TARGET];
static REGISTRY: VoteTargetRegistry = VoteTargetRegistry::new(TARGETS);

// Each replay gets its own immutable parameters and inherited environment.
// No process-global environment mutation races with other tests.
#[test]
fn governance_deadline_replay_ignores_local_environment() {
    if let Ok(mode) = std::env::var("OUTBE_GOVERNANCE_REPLAY_CHILD") {
        let overrides = serde_json::json!({"governance": {"votingWindowBlocks": 20}});
        let expected_window = if mode == "genesis" {
            match outbe_chain_constants::initialize(Some(&overrides)) {
                Ok(()) => 20,
                Err(outbe_chain_constants::ProtocolConstantsError::UnsupportedInProduction) => {
                    outbe_chain_constants::initialize(None).unwrap();
                    86_400
                }
                Err(error) => panic!("unexpected initialization failure: {error}"),
            }
        } else {
            outbe_chain_constants::initialize(None).unwrap();
            86_400
        };
        let proposer = Address::repeat_byte(0x11);
        let owner = Address::repeat_byte(0xff);
        let mut provider = HashMapStorageProvider::new(outbe_primitives::chain::TESTNET_CHAIN_ID);
        provider.set_block_number(100);
        {
            let storage = StorageHandle::new(&mut provider);
            let mut validators = ValidatorSet::new(storage.clone());
            validators.config_owner.write(owner).unwrap();
            validators.set_config_max_validators(4).unwrap();
            let mut key = [0u8; 48];
            key[0] = 1;
            validators
                .register_validator(owner, proposer, &key)
                .unwrap();
            validators
                .activate_validator_via_boundary_for_test(proposer)
                .unwrap();
            let mut vote = Vote::new(storage);
            let id = vote
                .create_proposal(proposer, UPDATE_ADDRESS, "{}", 100, &REGISTRY)
                .unwrap();
            let record = vote.proposals.get(id).unwrap().unwrap();
            assert_eq!(record.voting_deadline_height, 100 + expected_window);
            println!("witness:record:{record:?}");
        }
        let events = provider.get_events(VOTE_ADDRESS);
        assert_eq!(events.len(), 1);
        let event = IVote::ProposalCreated::decode_log_data(&events[0]).unwrap();
        assert_eq!(event.votingDeadlineHeight, 100 + expected_window);
        println!("witness:events:{events:?}");
        return;
    }
    for mode in ["default", "genesis"] {
        let mut baseline = None;
        for environment in [None, Some("6"), Some("17"), Some("0"), Some("invalid")] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "governance_deadline_replay_ignores_local_environment",
                    "--nocapture",
                ])
                .env("OUTBE_GOVERNANCE_REPLAY_CHILD", mode)
                .env_remove("OUTBE_TEST_VOTING_WINDOW_BLOCKS");
            if let Some(value) = environment {
                command.env("OUTBE_TEST_VOTING_WINDOW_BLOCKS", value);
            }
            let output = command.output().unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(
                output.status.success(),
                "{stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let witness = stdout
                .lines()
                .filter(|line| line.starts_with("witness:"))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(!witness.is_empty());
            if let Some(expected) = &baseline {
                assert_eq!(&witness, expected);
            } else {
                baseline = Some(witness);
            }
        }
    }
}
