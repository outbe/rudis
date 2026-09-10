use alloy_primitives::U256;
use outbe_primitives::error::{PrecompileError, Result};

/// Emission sink allocation percentages (integer, denominator = 100).
///
/// (Phase 4) replaced the legacy `(Validator 4 %, AgentReward
/// 8 %, Metadosis 88 %)` table with a four-pool split that sums to
/// 16 %, leaving 84 % for the terminal Metadosis sink. CCA is a pure
/// accumulator on a dedicated system address and only AgentReward owns
/// WAA / SRA.
pub const VALIDATOR_REWARD_PCT: u64 = 4;
pub const WAA_REWARD_PCT: u64 = 4;
pub const SRA_REWARD_PCT: u64 = 4;
pub const CCA_REWARD_PCT: u64 = 4;

pub const PERCENT_DENOMINATOR: u64 = 100;

/// Typed day-emission sinks. These are fixed, hard-fork governed
/// extension points, not dynamically registered runtime plugins.
///
/// replaced the per-block 3-sink table (`Validator 4 %`,
/// `AgentReward 8 %`, `Metadosis 88 %`) with the day 5-sink table
/// `(Validator 4 %, WAA 4 %, SRA 4 %, CCA 4 %, Metadosis terminal)`.
/// The validator pool is forwarded to `outbe-rewards::api`
/// by the Cycle handler; WAA / SRA / CCA are routed through
/// `outbe_agentreward::distribute_daily`; the residue and the terminal
/// 84 % land on Metadosis through [`crate::block::dispatch_terminal_remainder_at`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmissionSinkId {
    Validator,
    Waa,
    Sra,
    Cca,
    Metadosis,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmissionSinkSpec {
    pub id: EmissionSinkId,
    /// Fixed percentage of the day cap. `None` marks the terminal
    /// remainder sink.
    pub pct: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmissionAllocation {
    pub id: EmissionSinkId,
    pub amount: U256,
}

pub const ACTIVE_EMISSION_SINKS: [EmissionSinkSpec; 5] = [
    EmissionSinkSpec {
        id: EmissionSinkId::Validator,
        pct: Some(VALIDATOR_REWARD_PCT),
    },
    EmissionSinkSpec {
        id: EmissionSinkId::Waa,
        pct: Some(WAA_REWARD_PCT),
    },
    EmissionSinkSpec {
        id: EmissionSinkId::Sra,
        pct: Some(SRA_REWARD_PCT),
    },
    EmissionSinkSpec {
        id: EmissionSinkId::Cca,
        pct: Some(CCA_REWARD_PCT),
    },
    EmissionSinkSpec {
        id: EmissionSinkId::Metadosis,
        pct: None,
    },
];

pub fn active_emission_sinks() -> &'static [EmissionSinkSpec] {
    &ACTIVE_EMISSION_SINKS
}

/// Allocates emission across the active static sink table.
pub fn allocate_emission(total: U256) -> Result<Vec<EmissionAllocation>> {
    allocate_emission_with_specs(total, active_emission_sinks())
}

/// Allocates emission across a static sink table.
///
/// Fixed percentage sinks are rounded down with integer arithmetic. The single
/// terminal sink receives all remaining dust and unallocated percentage.
pub fn allocate_emission_with_specs(
    total: U256,
    specs: &[EmissionSinkSpec],
) -> Result<Vec<EmissionAllocation>> {
    validate_sink_specs(specs)?;

    let hundred = U256::from(PERCENT_DENOMINATOR);
    let mut fixed_total = U256::ZERO;
    let mut allocations = Vec::with_capacity(specs.len());

    for spec in specs {
        let amount = match spec.pct {
            Some(pct) => {
                let amount = total.checked_mul(U256::from(pct)).ok_or_else(|| {
                    PrecompileError::Revert("emission fixed-share multiplication overflow".into())
                })? / hundred;
                fixed_total = fixed_total.checked_add(amount).ok_or_else(|| {
                    PrecompileError::Revert("emission fixed allocation total overflow".into())
                })?;
                amount
            }
            None => total.checked_sub(fixed_total).ok_or_else(|| {
                PrecompileError::Revert("emission terminal allocation underflow".into())
            })?,
        };

        allocations.push(EmissionAllocation {
            id: spec.id,
            amount,
        });
    }

    Ok(allocations)
}

fn validate_sink_specs(specs: &[EmissionSinkSpec]) -> Result<()> {
    if specs.is_empty() {
        return Ok(());
    }

    let mut fixed_pct_sum = 0u64;
    let mut terminal_index = None;

    for (idx, spec) in specs.iter().enumerate() {
        match spec.pct {
            Some(pct) => {
                fixed_pct_sum = fixed_pct_sum.checked_add(pct).ok_or_else(|| {
                    PrecompileError::Revert("emission fixed percentage overflow".into())
                })?;
            }
            None => {
                if terminal_index.replace(idx).is_some() {
                    return Err(PrecompileError::Revert(
                        "emission sink table must have one terminal sink".into(),
                    ));
                }
            }
        }
    }

    if terminal_index != Some(specs.len() - 1) {
        return Err(PrecompileError::Revert(
            "emission terminal sink must be the final sink".into(),
        ));
    }

    if fixed_pct_sum > PERCENT_DENOMINATOR {
        return Err(PrecompileError::Revert(
            "emission fixed percentages exceed 100".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocation_invariant() {
        let total = U256::from(16384u64) * U256::from(10u64).pow(U256::from(18u64));
        let allocations = allocate_emission(total).unwrap();
        let sum = allocation_sum(&allocations);
        assert_eq!(sum, total, "allocation sum must equal total");
    }

    #[test]
    fn test_allocation_percentages() {
        // Day 5-sink table: 4x4 % + Metadosis terminal 84 %.
        let total = U256::from(10000u64);
        let allocations = allocate_emission(total).unwrap();
        for sink in [
            EmissionSinkId::Validator,
            EmissionSinkId::Waa,
            EmissionSinkId::Sra,
            EmissionSinkId::Cca,
        ] {
            assert_eq!(
                allocation_for(&allocations, sink),
                U256::from(400u64),
                "{sink:?} should be 4 % of total"
            );
        }
        assert_eq!(
            allocation_for(&allocations, EmissionSinkId::Metadosis),
            U256::from(8400u64),
            "Metadosis should receive the remaining 84 %"
        );
    }

    /// Regression: allocation must preserve invariant for values > 2^53
    /// where f64 would lose precision.
    #[test]
    fn test_allocation_invariant_large_values() {
        let boundary = U256::from(9007199254740992u64);
        for offset in [0u64, 1, 7, 999, 123456789] {
            let total = boundary + U256::from(offset);
            let allocations = allocate_emission(total).unwrap();
            assert_eq!(
                allocation_sum(&allocations),
                total,
                "allocation invariant broken for total = 2^53 + {offset}"
            );
        }

        let huge = U256::from(10u64).pow(U256::from(30u64));
        let allocations = allocate_emission(huge).unwrap();
        assert_eq!(
            allocation_sum(&allocations),
            huge,
            "allocation invariant broken for 10^30"
        );
    }

    #[test]
    fn test_allocation_deterministic_exact() {
        let total = U256::from(16384u64) * U256::from(10u64).pow(U256::from(18u64));
        let first = allocate_emission(total).unwrap();
        let second = allocate_emission(total).unwrap();
        assert_eq!(first, second, "allocation must be deterministic");
    }

    #[test]
    fn test_allocation_rejects_invalid_sink_tables() {
        assert!(allocate_emission_with_specs(U256::from(100u64), &[])
            .unwrap()
            .is_empty());

        let no_terminal = [EmissionSinkSpec {
            id: EmissionSinkId::Validator,
            pct: Some(100),
        }];
        assert!(allocate_emission_with_specs(U256::from(100u64), &no_terminal).is_err());

        let two_terminals = [
            EmissionSinkSpec {
                id: EmissionSinkId::Validator,
                pct: None,
            },
            EmissionSinkSpec {
                id: EmissionSinkId::Metadosis,
                pct: None,
            },
        ];
        assert!(allocate_emission_with_specs(U256::from(100u64), &two_terminals).is_err());

        let over_allocated = [
            EmissionSinkSpec {
                id: EmissionSinkId::Validator,
                pct: Some(80),
            },
            EmissionSinkSpec {
                id: EmissionSinkId::Waa,
                pct: Some(30),
            },
            EmissionSinkSpec {
                id: EmissionSinkId::Metadosis,
                pct: None,
            },
        ];
        assert!(allocate_emission_with_specs(U256::from(100u64), &over_allocated).is_err());
    }

    #[test]
    fn allocation_rejects_fixed_share_multiplication_overflow() {
        let specs = [
            EmissionSinkSpec {
                id: EmissionSinkId::Validator,
                pct: Some(100),
            },
            EmissionSinkSpec {
                id: EmissionSinkId::Metadosis,
                pct: None,
            },
        ];

        let error = allocate_emission_with_specs(U256::MAX, &specs).unwrap_err();
        assert!(matches!(
            error,
            PrecompileError::Revert(message)
                if message == "emission fixed-share multiplication overflow"
        ));
    }

    #[test]
    fn active_allocation_at_maximum_day_emission_is_pinned() {
        let total = crate::day_emission::day_emission_limit(1_024);
        assert_eq!(total, U256::from(581_610_154_666_666u64));

        assert_eq!(
            allocate_emission(total).unwrap(),
            vec![
                EmissionAllocation {
                    id: EmissionSinkId::Validator,
                    amount: U256::from(23_264_406_186_666u64),
                },
                EmissionAllocation {
                    id: EmissionSinkId::Waa,
                    amount: U256::from(23_264_406_186_666u64),
                },
                EmissionAllocation {
                    id: EmissionSinkId::Sra,
                    amount: U256::from(23_264_406_186_666u64),
                },
                EmissionAllocation {
                    id: EmissionSinkId::Cca,
                    amount: U256::from(23_264_406_186_666u64),
                },
                EmissionAllocation {
                    id: EmissionSinkId::Metadosis,
                    amount: U256::from(488_552_529_920_002u64),
                },
            ]
        );
    }

    #[test]
    fn test_allocation_rounding_dust_goes_to_terminal_sink() {
        // 4 x 4 % = 16 % -> each non-terminal sink gets floor(101 * 4 / 100) = 4.
        // Sum of fixed shares = 16. Metadosis terminal absorbs the
        // remainder = 85, including the rounding dust (101 - 16 = 85).
        let total = U256::from(101u64);
        let allocations = allocate_emission(total).unwrap();

        for sink in [
            EmissionSinkId::Validator,
            EmissionSinkId::Waa,
            EmissionSinkId::Sra,
            EmissionSinkId::Cca,
        ] {
            assert_eq!(
                allocation_for(&allocations, sink),
                U256::from(4u64),
                "{sink:?} should be 4 % of total"
            );
        }
        assert_eq!(
            allocation_for(&allocations, EmissionSinkId::Metadosis),
            U256::from(85u64),
            "Metadosis terminal absorbs the dust"
        );
        assert_eq!(allocation_sum(&allocations), total);
    }

    fn allocation_sum(allocations: &[EmissionAllocation]) -> U256 {
        allocations
            .iter()
            .map(|allocation| allocation.amount)
            .fold(U256::ZERO, |acc, amount| acc + amount)
    }

    fn allocation_for(allocations: &[EmissionAllocation], id: EmissionSinkId) -> U256 {
        allocations
            .iter()
            .find(|allocation| allocation.id == id)
            .map(|allocation| allocation.amount)
            .unwrap_or(U256::ZERO)
    }
}
