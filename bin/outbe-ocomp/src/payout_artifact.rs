//! Payout handoff artifact: the day's dense eligible-contributor list, written
//! at finalization so the payout sender can read the day back without
//! reopening the audit machinery. The sender re-derives the merkle root from
//! it, so a torn or stale file fails closed.

use std::fs;
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use alloy_primitives::U256;
use outbe_intex::payout::{encode_contributor_leaf, ContributorLeafData};
use thiserror::Error;

use crate::lysis_plan_audit::LocalLysisPlanAuditV1;
use crate::lysis_result_catalog::{
    ExactLysisResultCatalogCursorV1, LysisResultCatalogError, LysisResultCatalogStepV1,
};

pub const CONTRIBUTOR_PAYOUT_ARTIFACT_FILE: &str = "contributor-payout-v1.bin";

const TEMP_SUFFIX: &str = ".tmp";

#[derive(Debug, Error)]
pub enum PayoutArtifactError {
    #[error("payout artifact catalog: {0}")]
    Catalog(#[from] LysisResultCatalogError),
    #[error("payout artifact {context}: {source}")]
    Io {
        context: &'static str,
        source: std::io::Error,
    },
    #[error("payout artifact record count overflow")]
    CountOverflow,
    #[error("result catalog ended before its completion marker")]
    IncompleteCatalog,
}

fn io_error(context: &'static str, source: std::io::Error) -> PayoutArtifactError {
    PayoutArtifactError::Io { context, source }
}

/// Streams records into a temp file; the final name appears only on `commit`.
struct PayoutArtifactWriter {
    file: BufWriter<fs::File>,
    temp: PathBuf,
    target: PathBuf,
    count: u32,
}

impl PayoutArtifactWriter {
    fn open(job_root: &Path) -> Result<Self, PayoutArtifactError> {
        let target = job_root.join(CONTRIBUTOR_PAYOUT_ARTIFACT_FILE);
        let temp = job_root.join(format!("{CONTRIBUTOR_PAYOUT_ARTIFACT_FILE}{TEMP_SUFFIX}"));
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error("clear stale temp", error)),
        }
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|error| io_error("create temp", error))?;
        Ok(Self {
            file: BufWriter::new(file),
            temp,
            target,
            count: 0,
        })
    }

    fn push(&mut self, leaf: &ContributorLeafData) -> Result<(), PayoutArtifactError> {
        self.file
            .write_all(&encode_contributor_leaf(leaf))
            .map_err(|error| io_error("append record", error))?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or(PayoutArtifactError::CountOverflow)?;
        Ok(())
    }

    fn commit(self) -> Result<u32, PayoutArtifactError> {
        let Self {
            file,
            temp,
            target,
            count,
        } = self;
        let file = file
            .into_inner()
            .map_err(|error| io_error("flush records", error.into_error()))?;
        file.sync_all()
            .map_err(|error| io_error("sync records", error))?;
        fs::rename(&temp, &target).map_err(|error| io_error("install artifact", error))?;
        let directory = target.parent().expect("artifact path has a parent");
        fs::File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error("sync directory", error))?;
        Ok(count)
    }
}

/// Streams every eligible contributor of the finalized day into the job
/// directory, in tree order, and returns the record count.
pub fn write_contributor_payout_artifact(
    audit: &LocalLysisPlanAuditV1<'_>,
    job_root: &Path,
) -> Result<u32, PayoutArtifactError> {
    let mut writer = PayoutArtifactWriter::open(job_root)?;
    let mut complete = false;
    for step in ExactLysisResultCatalogCursorV1::open(audit)? {
        match step? {
            LysisResultCatalogStepV1::Chunk(chunk) => {
                for action in &chunk.chunk().ordered_eligible_contributors {
                    writer.push(&ContributorLeafData {
                        owner: action.owner,
                        source_tribute_id: U256::from_be_bytes(action.source_tribute_id.0),
                        nominal: action.nominal_amount_minor,
                    })?;
                }
            }
            LysisResultCatalogStepV1::Complete => complete = true,
            _ => {}
        }
    }
    if !complete {
        return Err(PayoutArtifactError::IncompleteCatalog);
    }
    writer.commit()
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, U256};

    use super::*;

    fn leaf(index: u8) -> ContributorLeafData {
        ContributorLeafData {
            owner: Address::repeat_byte(index),
            source_tribute_id: U256::from(index),
            nominal: U256::from(u64::from(index) + 1),
        }
    }

    #[test]
    fn commit_installs_the_exact_concatenation() {
        let dir = tempfile::tempdir().unwrap();
        let leaves: Vec<_> = (0..3).map(leaf).collect();

        let mut writer = PayoutArtifactWriter::open(dir.path()).unwrap();
        for entry in &leaves {
            writer.push(entry).unwrap();
        }
        assert!(!dir.path().join(CONTRIBUTOR_PAYOUT_ARTIFACT_FILE).exists());
        assert_eq!(writer.commit().unwrap(), 3);

        let bytes = fs::read(dir.path().join(CONTRIBUTOR_PAYOUT_ARTIFACT_FILE)).unwrap();
        let expected: Vec<u8> = leaves.iter().flat_map(encode_contributor_leaf).collect();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn an_uncommitted_writer_never_installs_the_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = PayoutArtifactWriter::open(dir.path()).unwrap();
        writer.push(&leaf(7)).unwrap();
        drop(writer);
        assert!(!dir.path().join(CONTRIBUTOR_PAYOUT_ARTIFACT_FILE).exists());
    }
}
