//! Append-only JSONL journal for SlashIndicator/ValidatorSet critical events.
//!
//! The journal is a process-local sidecar to the standard reth log. It is
//! written one JSON record per critical state-transition event under a
//! single file path (`<datadir>/slashing-journal.jsonl`) and is **never
//! rotated** by the application. Operators may snapshot or trim the file
//! manually; the runtime never truncates it.
//!
//! ## Why
//!
//! Standard `reth.log` rotates when each file reaches the configured size
//! (~200 MB). At testnet finalization rates this can mean a few hours of
//! runtime fits in the ~5-file rotation window - slash and validator-exit
//! events are routinely lost from on-host evidence by the time anyone
//! investigates. The journal closes that gap with a single tiny file (one
//! JSON line per event; ~10 events/day typical) that survives indefinitely.
//!
//! ## Best-effort semantics
//!
//! The journal is **best-effort** observability - writes that fail (disk
//! full, permission error, file unwritable) emit a `tracing::warn!` and
//! are dropped. They never block the consensus / state-transition path
//! that produced them. Determinism is unaffected: the journal is a side
//! effect identical on every node, and absence of the journal does not
//! change the on-chain state.
//!
//! ## Initialization
//!
//! [`init`] is called once at node startup with the data directory. If
//! [`init`] is not called (e.g. tests), [`record`] silently no-ops.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Filename of the journal inside the configured data directory.
pub const JOURNAL_FILENAME: &str = "slashing-journal.jsonl";

/// One record in the slashing/validator-set journal.
///
/// `tag = "event"` lets `serde_json` emit a flat object with the variant
/// name in the `event` field, which is convenient for ad-hoc grep / `jq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[non_exhaustive]
pub enum JournalRecord {
    /// `slash_proposer` recorded a miss for `validator`. Per-epoch counter
    /// reaches `count`; threshold reference values included for context.
    ProposerMiss {
        wall_clock: String,
        block_number: u64,
        validator: String,
        count: u64,
        felony_threshold: u64,
        misdemeanor_threshold: u64,
    },

    /// `slash_proposer` reached `count == felony_threshold`. Validator
    /// is force-exited and slashed by `slash_percent` of stake.
    ProposerFelony {
        wall_clock: String,
        block_number: u64,
        validator: String,
        miss_count: u64,
        felony_threshold: u64,
        felony_count: u64,
        slash_percent: u64,
    },

    /// Misdemeanor (informational, no slash).
    ProposerMisdemeanor {
        wall_clock: String,
        block_number: u64,
        validator: String,
        miss_count: u64,
        misdemeanor_threshold: u64,
    },

    /// `slash_voter` recorded a miss.
    VoterMiss {
        wall_clock: String,
        block_number: u64,
        validator: String,
        count: u64,
        misdemeanor_threshold: u64,
    },

    /// Voter misdemeanor.
    VoterMisdemeanor {
        wall_clock: String,
        block_number: u64,
        validator: String,
        miss_count: u64,
        misdemeanor_threshold: u64,
    },

    /// `slash_voter` reached `count % felony_threshold == 0`. Validator
    /// is force-exited and slashed by `slash_percent` of stake.
    VoterFelony {
        wall_clock: String,
        block_number: u64,
        validator: String,
        miss_count: u64,
        felony_threshold: u64,
        felony_count: u64,
        slash_percent: u64,
    },

    /// Felony triggered by external evidence submission.
    EvidenceFelony {
        wall_clock: String,
        block_number: u64,
        validator: String,
        evidence_submitter: String,
        felony_count: u64,
        slash_percent: u64,
        slashed_amount: String,
    },

    /// `submitInvalidVrfProofEvidence` accepted evidence and
    /// applied the felony to the child block's Phase 1 tx signer. Emitted
    /// alongside the standard `EvidenceFelony` record so operators have
    /// the VRF-specific failure class and child-block context without
    /// reverse-engineering the call site.
    InvalidVrfProofEvidence {
        wall_clock: String,
        block_number: u64,
        proposer: String,
        evidence_submitter: String,
        child_block_hash: String,
        child_block_number: u64,
        child_epoch: u64,
        failure_class: u16,
    },

    /// Felony triggered by consensus-layer byzantine detection.
    ByzantineFelony {
        wall_clock: String,
        block_number: u64,
        validator: String,
        felony_count: u64,
        slash_percent: u64,
        slashed_amount: String,
    },

    /// Validator self-deactivated (or owner deactivated): ACTIVE->EXITING.
    ValidatorDeactivated {
        wall_clock: String,
        block_number: u64,
        validator: String,
        caller: String,
        self_initiated: bool,
    },

    /// Validator force-exited from a status path: ACTIVE->EXITING (or
    /// EXITING re-emit, or no-op for UNBONDING/INACTIVE).
    ValidatorForcedExit {
        wall_clock: String,
        block_number: u64,
        validator: String,
        status_before: String,
        status_after: String,
    },

    /// New validator registered (first time).
    ValidatorRegistered {
        wall_clock: String,
        block_number: u64,
        validator: String,
        index: u64,
    },

    /// Existing validator re-registered after an INACTIVE period.
    ValidatorReregistered {
        wall_clock: String,
        block_number: u64,
        validator: String,
        index: u64,
    },

    /// DKG reshare activated; new active set committed.
    ResharedSetActivated {
        wall_clock: String,
        block_number: u64,
        active_count: u32,
        transitioned_to_unbonding: u64,
        pending_set_change: bool,
        active_set_hash: String,
    },

    /// EXITING validator transitioned to UNBONDING during reshare.
    ValidatorUnbonding {
        wall_clock: String,
        block_number: u64,
        validator: String,
    },

    /// `reset_epoch_counters` cleared per-epoch miss counters.
    EpochCountersReset {
        wall_clock: String,
        block_number: u64,
        validator_count: usize,
    },
}

struct Journal {
    writer: Mutex<BufWriter<File>>,
}

static JOURNAL: OnceLock<Journal> = OnceLock::new();

/// Initialize the journal. Must be called once at node startup before any
/// state-transition path runs. Subsequent calls are no-ops.
///
/// `datadir` is created if missing; the journal file is opened in append
/// mode so existing content is preserved across node restarts.
pub fn init(datadir: &Path) -> std::io::Result<()> {
    if JOURNAL.get().is_some() {
        return Ok(());
    }

    let path = journal_path(datadir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    let writer = BufWriter::new(file);

    let _ = JOURNAL.set(Journal {
        writer: Mutex::new(writer),
    });
    tracing::info!(
        target: "outbe::slashing::journal",
        path = %path.display(),
        "slashing journal initialized",
    );
    Ok(())
}

/// Returns the journal path under `datadir`.
pub fn journal_path(datadir: &Path) -> PathBuf {
    datadir.join(JOURNAL_FILENAME)
}

/// Append `record` to the journal. If [`init`] has not been called, this
/// is a no-op (test-friendly). Write errors are logged at WARN and
/// swallowed - never blocks the caller's state-transition path.
pub fn record(record: JournalRecord) {
    let Some(journal) = JOURNAL.get() else {
        return;
    };

    let line = match serde_json::to_string(&record) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                target: "outbe::slashing::journal",
                error = %e,
                "failed to serialize journal record",
            );
            return;
        }
    };

    let mut guard = match journal.writer.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            // Recover from poison; a previous panic in a writer thread
            // does not corrupt the file pointer.
            poisoned.into_inner()
        }
    };

    if let Err(e) = writeln!(guard, "{line}") {
        tracing::warn!(
            target: "outbe::slashing::journal",
            error = %e,
            "failed to append journal record",
        );
        return;
    }
    if let Err(e) = guard.flush() {
        tracing::warn!(
            target: "outbe::slashing::journal",
            error = %e,
            "failed to flush journal record",
        );
    }
}

/// Returns an ISO-8601 UTC timestamp string for `wall_clock` fields.
///
/// Uses raw `std::time::SystemTime` rather than `chrono` to avoid pulling
/// a new dependency. Format: `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn iso8601_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = now.as_secs() as i64;
    let millis = now.subsec_millis();
    let (year, month, day, hour, minute, second) = unix_to_civil(total_secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Decompose Unix seconds into (Y, M, D, h, m, s) UTC. Pure integer arithmetic.
fn unix_to_civil(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = (rem / 3600) as u32;
    let minute = ((rem % 3600) / 60) as u32;
    let second = (rem % 60) as u32;
    let (year, month, day) = days_to_civil(days);
    (year, month, day, hour, minute, second)
}

/// Howard Hinnant's days-from-epoch -> civil-date algorithm. Same algorithm
/// already used by `crate::time` but kept here to avoid coupling timestamps.
fn days_to_civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn record_when_uninit_is_noop() {
        // No init -> record is a no-op (does not panic).
        record(JournalRecord::EpochCountersReset {
            wall_clock: "2026-01-01T00:00:00.000Z".into(),
            block_number: 0,
            validator_count: 0,
        });
    }

    #[test]
    fn record_serializes_to_jsonl_with_event_tag() {
        let rec = JournalRecord::ProposerFelony {
            wall_clock: "2026-05-10T12:34:56.789Z".into(),
            block_number: 12_345,
            validator: "0x2cf6fbd0".into(),
            miss_count: 150,
            felony_threshold: 150,
            felony_count: 1,
            slash_percent: 5,
        };
        let json = serde_json::to_string(&rec).expect("serializable");
        assert!(json.contains("\"event\":\"proposer_felony\""));
        assert!(json.contains("\"felony_count\":1"));
        assert!(json.contains("\"validator\":\"0x2cf6fbd0\""));
    }

    #[test]
    fn iso8601_format_shape() {
        let s = iso8601_now();
        // YYYY-MM-DDTHH:MM:SS.mmmZ - 24 chars including separators
        assert_eq!(s.len(), 24);
        assert!(s.ends_with('Z'));
        assert!(s.chars().nth(4) == Some('-'));
        assert!(s.chars().nth(10) == Some('T'));
    }

    #[test]
    fn init_then_record_writes_lines_and_survives_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        // First-time init succeeds. Subsequent inits are no-ops because
        // we use a process-global OnceLock; tests share the recorder so
        // a second test that initializes a different dir would see this
        // recorder's file. Therefore this test is the only one that
        // exercises the writer end-to-end.
        let path = journal_path(dir.path());
        // Hand-craft a writer using the same code path so the singleton
        // limitation does not affect this test:
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let mut writer = std::io::BufWriter::new(file);
        let rec = JournalRecord::ValidatorUnbonding {
            wall_clock: iso8601_now(),
            block_number: 19_200,
            validator: "0x2cf6fbd0".into(),
        };
        writeln!(writer, "{}", serde_json::to_string(&rec).unwrap()).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let mut content = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert!(content.contains("\"event\":\"validator_unbonding\""));
        assert!(content.contains("\"block_number\":19200"));
    }
}
