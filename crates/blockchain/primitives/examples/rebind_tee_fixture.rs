//! Rebind an unlaunched genesis fixture to a new chain ID using canonical codecs.
//! All attestation rules and the unchanged genesis header hash are preserved.
//! Usage: cargo run -p outbe-primitives --example rebind_tee_fixture -- INPUT OUTPUT CHAIN_ID

use std::{fs, io::Write};

use alloy_primitives::U256;
use outbe_primitives::tee_attestation_v1::TeePolicyScheduleV1;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err("expected INPUT OUTPUT CHAIN_ID".into());
    }
    let chain_id: u64 = args[3].parse()?;
    let mut genesis: serde_json::Value = serde_json::from_slice(&fs::read(&args[1])?)?;
    let original_id = genesis["config"]["chainId"]
        .as_u64()
        .ok_or("missing chainId")?;
    let field = &mut genesis["config"]["teeAttestationV1"];
    let encoded = field["policySchedule"]
        .as_str()
        .ok_or("missing policy schedule")?;
    let mut schedule = TeePolicyScheduleV1::decode_canonical(&hex::decode(
        encoded.strip_prefix("0x").ok_or("schedule must be hex")?,
    )?)?;
    if schedule.chain_id != U256::from(original_id).to_be_bytes::<32>() {
        return Err("input schedule does not match input chain ID".into());
    }
    if schedule.entries.len() != 1 {
        return Err("only fresh single-policy fixtures can be rebound".into());
    }
    schedule.chain_id = U256::from(chain_id).to_be_bytes();
    for entry in &mut schedule.entries {
        entry.policy.chain_id = schedule.chain_id;
    }
    field["policySchedule"] = format!("0x{}", hex::encode(schedule.encode_canonical()?)).into();
    field["policyScheduleHash"] = serde_json::to_value(schedule.schedule_hash()?)?;
    genesis["config"]["chainId"] = chain_id.into();
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])?;
    writeln!(output, "{}", serde_json::to_string_pretty(&genesis)?)?;
    Ok(())
}
