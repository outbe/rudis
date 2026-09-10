use alloy_primitives::{keccak256, Address, B256, U256};
use outbe_primitives::error::Result;

use crate::errors::GovernanceError;
use crate::schema::{Gip, GipEntryExt, GovernanceContract, Oip, OipEntryExt};
use crate::status::is_valid_status;

/// Lightweight proposal projection for listings - every field except the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalMeta {
    pub id: U256,
    pub author: Address,
    pub status: u8,
    pub created_block: u64,
    pub updated_block: u64,
    pub text_hash: B256,
}

/// Storage key for the per-author id list: `keccak256(author || index_be)`.
/// Shared by the writer (runtime submit) and the reader (below).
pub(crate) fn author_index_key(author: Address, index: u32) -> B256 {
    let mut buf = [0u8; 24];
    buf[..20].copy_from_slice(author.as_slice());
    buf[20..].copy_from_slice(&index.to_be_bytes());
    keccak256(buf)
}

/// Hard cap on how many items a single paginated read returns, so a caller
/// cannot ask for an unbounded page.
pub const MAX_PAGE: u32 = 1000;

/// Clamp an `(offset, limit)` request against a bucket of `total` items,
/// returning the half-open `[start, end)` index range to read.
fn page_bounds(total: u32, offset: U256, limit: U256) -> (u32, u32) {
    let start = offset.min(U256::from(total)).to::<u32>();
    let take = limit.min(U256::from(MAX_PAGE)).to::<u32>();
    let end = start.saturating_add(take).min(total);
    (start, end)
}

impl GovernanceContract<'_> {
    // --- meta-canon / canon reads ---

    /// Returns `(text, version, hash)` for the meta-canon.
    pub fn get_meta_canon(&self) -> Result<(String, u64, B256)> {
        Ok((
            self.meta_canon.read_string()?,
            self.meta_canon_version.read()?,
            self.meta_canon_hash.read()?,
        ))
    }

    /// Returns `(text, version, hash)` for the canon.
    pub fn get_canon(&self) -> Result<(String, u64, B256)> {
        Ok((
            self.canon.read_string()?,
            self.canon_version.read()?,
            self.canon_hash.read()?,
        ))
    }

    /// Hash of a specific meta-canon revision (`0` if that version never existed).
    pub fn meta_canon_revision_hash(&self, version: u64) -> Result<B256> {
        self.meta_canon_revisions.read(&version)
    }

    /// Hash of a specific canon revision (`0` if that version never existed).
    pub fn canon_revision_hash(&self, version: u64) -> Result<B256> {
        self.canon_revisions.read(&version)
    }

    // --- proposal reads ---

    pub fn get_oip(&self, id: U256) -> Result<Option<Oip>> {
        self.oips.get(id)
    }

    pub fn get_gip(&self, id: U256) -> Result<Option<Gip>> {
        self.gips.get(id)
    }

    /// Number of OIPs ever submitted (ids run `1..=oip_count`).
    pub fn oip_count(&self) -> Result<u64> {
        self.next_oip_id.read()
    }

    /// Number of GIPs ever submitted (ids run `1..=gip_count`).
    pub fn gip_count(&self) -> Result<u64> {
        self.next_gip_id.read()
    }

    // --- authorities ---

    pub fn is_authority(&self, who: Address) -> Result<bool> {
        self.authorities.read(&who)
    }

    // --- proposal metadata projections (read only the fixed-width fields via the
    //     per-field accessors; never load the text data-run) ---

    fn oip_meta(&self, id: U256) -> Result<ProposalMeta> {
        let e = self.oips.entry(id);
        Ok(ProposalMeta {
            id,
            author: e.author().read()?,
            status: e.status().read()?,
            created_block: e.created_block().read()?,
            updated_block: e.updated_block().read()?,
            text_hash: e.text_hash().read()?,
        })
    }

    fn gip_meta(&self, id: U256) -> Result<ProposalMeta> {
        let e = self.gips.entry(id);
        Ok(ProposalMeta {
            id,
            author: e.author().read()?,
            status: e.status().read()?,
            created_block: e.created_block().read()?,
            updated_block: e.updated_block().read()?,
            text_hash: e.text_hash().read()?,
        })
    }

    // --- index-backed listings (paginated: read only the [offset, offset+limit)
    //     slice of the relevant bucket; counts let callers size the pages) ---

    pub fn oip_count_by_author(&self, author: Address) -> Result<u32> {
        self.oip_author_count.read(&author)
    }

    pub fn gip_count_by_author(&self, author: Address) -> Result<u32> {
        self.gip_author_count.read(&author)
    }

    pub fn oips_by_author(
        &self,
        author: Address,
        offset: U256,
        limit: U256,
    ) -> Result<Vec<ProposalMeta>> {
        let (start, end) = page_bounds(self.oip_author_count.read(&author)?, offset, limit);
        let mut out = Vec::with_capacity((end - start) as usize);
        for i in start..end {
            let id = self.oip_author_ids.read(&author_index_key(author, i))?;
            out.push(self.oip_meta(id)?);
        }
        Ok(out)
    }

    pub fn gips_by_author(
        &self,
        author: Address,
        offset: U256,
        limit: U256,
    ) -> Result<Vec<ProposalMeta>> {
        let (start, end) = page_bounds(self.gip_author_count.read(&author)?, offset, limit);
        let mut out = Vec::with_capacity((end - start) as usize);
        for i in start..end {
            let id = self.gip_author_ids.read(&author_index_key(author, i))?;
            out.push(self.gip_meta(id)?);
        }
        Ok(out)
    }

    /// Number of OIPs currently in `status` (0..=4).
    pub fn oip_count_by_status(&self, status: u8) -> Result<u32> {
        if !is_valid_status(status) {
            return Err(GovernanceError::InvalidStatus.into());
        }
        self.oip_by_status.get_set(&status).len()
    }

    /// Number of GIPs currently in `status` (0..=4).
    pub fn gip_count_by_status(&self, status: u8) -> Result<u32> {
        if !is_valid_status(status) {
            return Err(GovernanceError::InvalidStatus.into());
        }
        self.gip_by_status.get_set(&status).len()
    }

    /// OIPs currently in `status` (paginated).
    pub fn oips_by_status(
        &self,
        status: u8,
        offset: U256,
        limit: U256,
    ) -> Result<Vec<ProposalMeta>> {
        if !is_valid_status(status) {
            return Err(GovernanceError::InvalidStatus.into());
        }
        let set = self.oip_by_status.get_set(&status);
        let (start, end) = page_bounds(set.len()?, offset, limit);
        let mut out = Vec::with_capacity((end - start) as usize);
        for i in start..end {
            if let Some(id) = set.at(i)? {
                out.push(self.oip_meta(id)?);
            }
        }
        Ok(out)
    }

    /// GIPs currently in `status` (paginated).
    pub fn gips_by_status(
        &self,
        status: u8,
        offset: U256,
        limit: U256,
    ) -> Result<Vec<ProposalMeta>> {
        if !is_valid_status(status) {
            return Err(GovernanceError::InvalidStatus.into());
        }
        let set = self.gip_by_status.get_set(&status);
        let (start, end) = page_bounds(set.len()?, offset, limit);
        let mut out = Vec::with_capacity((end - start) as usize);
        for i in start..end {
            if let Some(id) = set.at(i)? {
                out.push(self.gip_meta(id)?);
            }
        }
        Ok(out)
    }
}
