//! Durable preimages for the ordered input-reference commitment.
//!
//! `InputManifestV1` remains the authority. This local catalog only makes its
//! exact `InputChunkRefV1` preimages discoverable after a cold restart without
//! scanning CAS or retaining a population-sized in-memory vector.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use alloy_primitives::{keccak256, B256};
use outbe_ocomp_protocol::{
    input::{AuthenticatedInputChunkV1, InputChunkKind, InputChunkRefV1, InputManifestV1},
    profile::ProtocolBundleV1,
    CanonicalReader, CanonicalWriter, CasObjectRefV1, ListKind, ObjectKind, OrderedListLimits,
    ProtocolError, SchemaLimits, StreamingOrderedListRoot,
};
use thiserror::Error;

use crate::{
    cas::{CasError, FilesystemCas, FilesystemCasReader},
    input_artifacts::{decode_verified_input_chunk, derive_input_chunk_ref},
};

const DIRECTORY_MODE: u32 = 0o750;
const FILE_MODE: u32 = 0o640;
const HEADER_MAGIC: [u8; 8] = *b"OUTBICH1";
const ENTRY_MAGIC: [u8; 8] = *b"OUTBICR1";
const CONFLICT_MAGIC: [u8; 8] = *b"OUTBICF1";
const STAGING_MAGIC: [u8; 8] = *b"OUTBICS1";
const HEADER_FILE: &str = "catalog.header";
const PREPARED_FILE: &str = "catalog.prepared";
const STAGING_FILE: &str = "catalog.staging";
const LOCK_FILE: &str = "catalog.lock";
const CONFLICT_FILE: &str = "catalog.abstained";
const ENTRY_SUFFIX: &str = ".input-ref";
const TEMP_SUFFIX: &str = ".tmp";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputRefAdmissionOutcome {
    NewlyAdmitted,
    ExactReplay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputRefCatalogSubjectV1 {
    pub protocol_bundle_hash: B256,
    pub job_id: B256,
    pub attempt: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputRefCatalogSummaryV1 {
    pub input_chunk_count: u32,
    pub input_chunk_list_root: B256,
    pub exact_encoded_bytes: u64,
    pub exact_record_count: u32,
    pub tribute_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InputRefCatalogHeaderV1 {
    manifest_ref: CasObjectRefV1,
    manifest_hash: B256,
    protocol_bundle_hash: B256,
    job_id: B256,
    attempt: u32,
    input_chunk_count: u32,
    input_chunk_list_root: B256,
    exact_encoded_bytes: u64,
    exact_record_count: u32,
    tribute_count: u32,
}

pub struct InputRefCatalogPublisher {
    root: PathBuf,
    limits: SchemaLimits,
    list_limits: OrderedListLimits,
    subject: InputRefCatalogSubjectV1,
    next_ordinal: u32,
    previous_kind: Option<InputChunkKind>,
    abstained: bool,
    prepared_header: Option<InputRefCatalogHeaderV1>,
    sealed_header: Option<InputRefCatalogHeaderV1>,
    lock: CatalogLock,
}

pub struct PreparedInputRefCatalogPublisher {
    root: PathBuf,
    limits: SchemaLimits,
    list_limits: OrderedListLimits,
    subject: InputRefCatalogSubjectV1,
    summary: InputRefCatalogSummaryV1,
    prepared_header: Option<InputRefCatalogHeaderV1>,
    sealed_header: Option<InputRefCatalogHeaderV1>,
    lock: CatalogLock,
}

impl InputRefCatalogPublisher {
    pub fn open_or_resume(
        root: impl AsRef<Path>,
        subject: InputRefCatalogSubjectV1,
        limits: SchemaLimits,
        list_limits: OrderedListLimits,
    ) -> Result<Self, InputRefCatalogError> {
        let root = root.as_ref().to_path_buf();
        create_private_directory(&root)?;
        let lock = CatalogLock::acquire(&root)?;
        recover_staging_temps(&root)?;
        let final_header = if path_exists(&root.join(HEADER_FILE))? {
            Some(decode_header(
                &read_bounded(&root.join(HEADER_FILE), catalog_byte_cap(&limits))?,
                &limits,
            )?)
        } else {
            None
        };
        let prepared_header = if path_exists(&root.join(PREPARED_FILE))? {
            Some(decode_header(
                &read_bounded(&root.join(PREPARED_FILE), catalog_byte_cap(&limits))?,
                &limits,
            )?)
        } else {
            None
        };
        if final_header.is_some() && prepared_header.is_none() {
            return Err(InputRefCatalogError::AuthorityMismatch);
        }
        if final_header
            .as_ref()
            .zip(prepared_header.as_ref())
            .is_some_and(|(sealed, prepared)| sealed != prepared)
        {
            return Err(InputRefCatalogError::AuthorityMismatch);
        }
        if final_header
            .as_ref()
            .or(prepared_header.as_ref())
            .is_some_and(|header| {
                header.protocol_bundle_hash != subject.protocol_bundle_hash
                    || header.job_id != subject.job_id
                    || header.attempt != subject.attempt
            })
        {
            return Err(InputRefCatalogError::AuthorityMismatch);
        }
        let staging_path = root.join(STAGING_FILE);
        if path_exists(&staging_path)? {
            if decode_staging_subject(
                &read_bounded(&staging_path, catalog_byte_cap(&limits))?,
                &limits,
            )? != subject
            {
                return Err(InputRefCatalogError::AuthorityMismatch);
            }
        } else {
            require_fresh_catalog_without_header(&root)?;
            persist_atomic(
                &root,
                &staging_path,
                &encode_staging_subject(subject, &limits)?,
            )?;
        }
        let abstained = path_exists(&root.join(CONFLICT_FILE))?;
        let (next_ordinal, previous_kind) = scan_staged_entries(&root, &limits)?;
        if let Some(header) = final_header.as_ref().or(prepared_header.as_ref()) {
            if next_ordinal > header.input_chunk_count {
                return Err(InputRefCatalogError::UnexpectedReference {
                    ordinal: header.input_chunk_count,
                });
            }
        }
        Ok(Self {
            root,
            limits,
            list_limits,
            subject,
            next_ordinal,
            previous_kind,
            abstained,
            prepared_header,
            sealed_header: final_header,
            lock,
        })
    }

    pub fn append(
        &mut self,
        reference: &InputChunkRefV1,
    ) -> Result<InputRefAdmissionOutcome, InputRefCatalogError> {
        self.require_active()?;
        let canonical = reference.encode_canonical_record(&self.limits)?;
        if reference.ordinal < self.next_ordinal {
            let existing = read_bounded(
                &entry_path(&self.root, reference.ordinal),
                catalog_byte_cap(&self.limits),
            )?;
            let candidate = encode_entry(&canonical);
            if existing == candidate {
                return Ok(InputRefAdmissionOutcome::ExactReplay);
            }
            persist_conflict(&self.root, reference.ordinal, &existing, &candidate)?;
            self.abstained = true;
            return Err(InputRefCatalogError::ConflictingReference {
                ordinal: reference.ordinal,
            });
        }
        if reference.ordinal > self.next_ordinal {
            return Err(InputRefCatalogError::OrdinalGap {
                expected: self.next_ordinal,
                actual: reference.ordinal,
            });
        }
        if self
            .sealed_header
            .as_ref()
            .or(self.prepared_header.as_ref())
            .is_some_and(|header| reference.ordinal >= header.input_chunk_count)
        {
            return Err(InputRefCatalogError::UnexpectedReference {
                ordinal: reference.ordinal,
            });
        }
        if self
            .previous_kind
            .is_some_and(|previous| previous > reference.kind)
        {
            return Err(InputRefCatalogError::KindOrder {
                ordinal: reference.ordinal,
            });
        }
        let path = entry_path(&self.root, reference.ordinal);
        persist_atomic(&self.root, &path, &encode_entry(&canonical))?;
        self.next_ordinal =
            self.next_ordinal
                .checked_add(1)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "staged input-ref ordinal",
                })?;
        self.previous_kind = Some(reference.kind);
        Ok(InputRefAdmissionOutcome::NewlyAdmitted)
    }

    pub fn prepare(
        self,
        reader: &FilesystemCasReader,
        bundle: &ProtocolBundleV1,
    ) -> Result<PreparedInputRefCatalogPublisher, InputRefCatalogError> {
        self.prepare_observing(reader, bundle, || {})
    }

    pub fn prepare_observing(
        self,
        reader: &FilesystemCasReader,
        bundle: &ProtocolBundleV1,
        on_progress: impl Fn(),
    ) -> Result<PreparedInputRefCatalogPublisher, InputRefCatalogError> {
        self.require_active()?;
        if bundle.protocol_bundle_hash(&self.limits)? != self.subject.protocol_bundle_hash {
            return Err(InputRefCatalogError::AuthorityMismatch);
        }
        let (entry_count, _) =
            scan_staged_entries_observing(&self.root, &self.limits, &on_progress)?;
        if entry_count != self.next_ordinal {
            return Err(InputRefCatalogError::MissingReference {
                ordinal: entry_count.min(self.next_ordinal),
            });
        }
        let mut root =
            StreamingOrderedListRoot::new(ListKind::InputChunkReferences, self.next_ordinal)?;
        let mut exact_encoded_bytes = 0_u64;
        let mut exact_record_count = 0_u32;
        let mut tribute_count = 0_u32;
        let mut previous_kind = None;
        for ordinal in 0..self.next_ordinal {
            let reference = read_reference(&self.root, &self.limits, ordinal)?;
            if previous_kind.is_some_and(|kind| kind > reference.kind) {
                return Err(InputRefCatalogError::KindOrder { ordinal });
            }
            previous_kind = Some(reference.kind);
            root.push(
                &reference.encode_canonical_record(&self.limits)?,
                self.limits.max_bounded_bytes,
            )?;
            exact_encoded_bytes = exact_encoded_bytes
                .checked_add(reference.encoded_bytes)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "staged input-ref encoded bytes",
                })?;
            exact_record_count = exact_record_count
                .checked_add(reference.record_count)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "staged input-ref record count",
                })?;
            if reference.kind == InputChunkKind::Tribute {
                tribute_count = tribute_count.checked_add(reference.record_count).ok_or(
                    ProtocolError::IntegerOverflow {
                        what: "staged input-ref Tribute count",
                    },
                )?;
            }
            verify_staged_reference(&reference, self.subject, reader, bundle, &self.limits)?;
            on_progress();
        }
        let summary = InputRefCatalogSummaryV1 {
            input_chunk_count: self.next_ordinal,
            input_chunk_list_root: root.finish()?,
            exact_encoded_bytes,
            exact_record_count,
            tribute_count,
        };
        if self
            .sealed_header
            .as_ref()
            .is_some_and(|header| !summary_matches_header(summary, header))
            || self
                .prepared_header
                .as_ref()
                .is_some_and(|header| !summary_matches_header(summary, header))
        {
            return Err(InputRefCatalogError::AuthorityMismatch);
        }
        Ok(PreparedInputRefCatalogPublisher {
            root: self.root,
            limits: self.limits,
            list_limits: self.list_limits,
            subject: self.subject,
            summary,
            prepared_header: self.prepared_header,
            sealed_header: self.sealed_header,
            lock: self.lock,
        })
    }

    fn require_active(&self) -> Result<(), InputRefCatalogError> {
        if self.abstained {
            Err(InputRefCatalogError::Abstained)
        } else {
            Ok(())
        }
    }
}

impl PreparedInputRefCatalogPublisher {
    #[must_use]
    pub const fn summary(&self) -> InputRefCatalogSummaryV1 {
        self.summary
    }

    pub fn seal(
        self,
        cas: &FilesystemCas,
        manifest_ref: &CasObjectRefV1,
        bundle: &ProtocolBundleV1,
    ) -> Result<VerifiedInputChunkRefCatalog, InputRefCatalogError> {
        let manifest_object = cas.read_verified(manifest_ref)?;
        let manifest = InputManifestV1::decode_canonical(manifest_object.bytes(), &self.limits)?;
        manifest.validate_against_bundle(bundle, &self.limits)?;
        if manifest.protocol_bundle_hash != self.subject.protocol_bundle_hash
            || manifest.job_id != self.subject.job_id
            || manifest.attempt != self.subject.attempt
            || manifest.input_chunk_count != self.summary.input_chunk_count
            || manifest.input_chunk_list_root != self.summary.input_chunk_list_root
            || manifest.exact_encoded_bytes != self.summary.exact_encoded_bytes
            || manifest.exact_record_count != self.summary.exact_record_count
            || manifest.tribute_count != self.summary.tribute_count
        {
            return Err(InputRefCatalogError::AuthorityMismatch);
        }
        let expected = expected_header(manifest_ref, &manifest, &self.limits)?;
        if let Some(prepared) = &self.prepared_header {
            if prepared != &expected {
                return Err(InputRefCatalogError::AuthorityMismatch);
            }
        } else {
            persist_atomic(
                &self.root,
                &self.root.join(PREPARED_FILE),
                &encode_header(&expected, &self.limits)?,
            )?;
        }
        if let Some(sealed) = &self.sealed_header {
            if sealed != &expected {
                return Err(InputRefCatalogError::AuthorityMismatch);
            }
        } else {
            persist_atomic(
                &self.root,
                &self.root.join(HEADER_FILE),
                &encode_header(&expected, &self.limits)?,
            )?;
        }
        Ok(VerifiedInputChunkRefCatalog {
            root: self.root,
            limits: self.limits,
            _list_limits: self.list_limits,
            header: expected,
            abstained: false,
            writable: true,
            _lock: self.lock,
        })
    }
}

pub struct VerifiedInputChunkRefCatalog {
    root: PathBuf,
    limits: SchemaLimits,
    _list_limits: OrderedListLimits,
    header: InputRefCatalogHeaderV1,
    abstained: bool,
    writable: bool,
    _lock: CatalogLock,
}

impl VerifiedInputChunkRefCatalog {
    pub fn open(
        root: impl AsRef<Path>,
        cas: &FilesystemCas,
        manifest_ref: &CasObjectRefV1,
        limits: SchemaLimits,
        list_limits: OrderedListLimits,
    ) -> Result<Self, InputRefCatalogError> {
        let manifest_object = cas.read_verified(manifest_ref)?;
        let manifest = InputManifestV1::decode_canonical(manifest_object.bytes(), &limits)?;
        let expected = expected_header(manifest_ref, &manifest, &limits)?;
        let root = root.as_ref().to_path_buf();
        create_private_directory(&root)?;
        let lock = CatalogLock::acquire(&root)?;
        reject_orphaned_temps(&root)?;
        let header_path = root.join(HEADER_FILE);
        if path_exists(&header_path)? {
            let actual = decode_header(
                &read_bounded(&header_path, catalog_byte_cap(&limits))?,
                &limits,
            )?;
            if actual != expected {
                return Err(InputRefCatalogError::AuthorityMismatch);
            }
        } else {
            require_fresh_catalog_without_header(&root)?;
            persist_atomic(&root, &header_path, &encode_header(&expected, &limits)?)?;
        }
        let abstained = path_exists(&root.join(CONFLICT_FILE))?;
        Ok(Self {
            root,
            limits,
            _list_limits: list_limits,
            header: expected,
            abstained,
            writable: true,
            _lock: lock,
        })
    }

    pub fn reopen(
        root: impl AsRef<Path>,
        reader: &FilesystemCasReader,
        limits: SchemaLimits,
        list_limits: OrderedListLimits,
    ) -> Result<Self, InputRefCatalogError> {
        let root = root.as_ref().to_path_buf();
        inspect_private_directory(&root)?;
        let lock = CatalogLock::acquire_shared(&root)?;
        reject_orphaned_temps(&root)?;
        let header_path = root.join(HEADER_FILE);
        if !path_exists(&header_path)? {
            return Err(InputRefCatalogError::MissingHeader);
        }
        let header = decode_header(
            &read_bounded(&header_path, catalog_byte_cap(&limits))?,
            &limits,
        )?;
        let manifest_object = reader.read_verified(&header.manifest_ref)?;
        let manifest = InputManifestV1::decode_canonical(manifest_object.bytes(), &limits)?;
        let expected = expected_header(&header.manifest_ref, &manifest, &limits)?;
        if header != expected {
            return Err(InputRefCatalogError::AuthorityMismatch);
        }
        let abstained = path_exists(&root.join(CONFLICT_FILE))?;
        Ok(Self {
            root,
            limits,
            _list_limits: list_limits,
            header,
            abstained,
            writable: false,
            _lock: lock,
        })
    }

    pub fn admit(
        &mut self,
        reference: &InputChunkRefV1,
    ) -> Result<InputRefAdmissionOutcome, InputRefCatalogError> {
        if !self.writable {
            return Err(InputRefCatalogError::ReadOnly);
        }
        self.require_active()?;
        let canonical = reference.encode_canonical_record(&self.limits)?;
        if reference.ordinal >= self.header.input_chunk_count {
            return Err(InputRefCatalogError::UnexpectedReference {
                ordinal: reference.ordinal,
            });
        }
        let path = self.entry_path(reference.ordinal);
        let encoded = encode_entry(&canonical);
        if path_exists(&path)? {
            let existing = read_bounded(&path, catalog_byte_cap(&self.limits))?;
            if existing == encoded {
                return Ok(InputRefAdmissionOutcome::ExactReplay);
            }
            self.latch_conflict(reference.ordinal, &existing, &encoded)?;
            return Err(InputRefCatalogError::ConflictingReference {
                ordinal: reference.ordinal,
            });
        }
        persist_atomic(&self.root, &path, &encoded)?;
        Ok(InputRefAdmissionOutcome::NewlyAdmitted)
    }

    pub fn exact_cursor(&self) -> Result<InputRefCursor<'_>, InputRefCatalogError> {
        self.exact_cursor_observing(|| {})
    }

    pub fn exact_cursor_observing(
        &self,
        on_progress: impl Fn(),
    ) -> Result<InputRefCursor<'_>, InputRefCatalogError> {
        self.require_active()?;
        for step in self.bounded_closure_cursor()? {
            let _ = step?;
            on_progress();
        }
        Ok(InputRefCursor {
            catalog: self,
            next_ordinal: 0,
        })
    }

    pub(crate) fn bounded_closure_cursor(
        &self,
    ) -> Result<InputRefCatalogClosureCursorV1<'_>, InputRefCatalogError> {
        self.require_active()?;
        Ok(InputRefCatalogClosureCursorV1 {
            catalog: self,
            stage: InputRefCatalogClosureStageV1::References,
            next_ordinal: 0,
            root: Some(StreamingOrderedListRoot::new(
                ListKind::InputChunkReferences,
                self.header.input_chunk_count,
            )?),
            exact_encoded_bytes: 0,
            exact_record_count: 0,
            tribute_count: 0,
            previous_kind: None,
            directory: None,
            actual_entry_count: 0,
        })
    }

    pub fn exact_verified_cursor<'a>(
        &'a self,
        reader: &'a FilesystemCasReader,
        bundle: &'a ProtocolBundleV1,
    ) -> Result<VerifiedInputRefCursor<'a>, InputRefCatalogError> {
        self.exact_verified_cursor_observing(reader, bundle, || {})
    }

    pub fn exact_verified_cursor_observing<'a>(
        &'a self,
        reader: &'a FilesystemCasReader,
        bundle: &'a ProtocolBundleV1,
        on_progress: impl Fn(),
    ) -> Result<VerifiedInputRefCursor<'a>, InputRefCatalogError> {
        Ok(VerifiedInputRefCursor {
            inner: self.exact_cursor_observing(on_progress)?,
            reader,
            bundle,
        })
    }

    pub(crate) fn require_manifest_authority(
        &self,
        manifest_ref: &CasObjectRefV1,
        manifest: &InputManifestV1,
    ) -> Result<(), InputRefCatalogError> {
        self.require_active()?;
        if expected_header(manifest_ref, manifest, &self.limits)? != self.header {
            return Err(InputRefCatalogError::AuthorityMismatch);
        }
        Ok(())
    }

    pub(crate) fn verified_reference_at(
        &self,
        ordinal: u32,
        reader: &FilesystemCasReader,
        bundle: &ProtocolBundleV1,
    ) -> Result<VerifiedInputChunkRefV1, InputRefCatalogError> {
        self.verify_reference(self.read(ordinal)?, reader, bundle)
    }

    fn read(&self, ordinal: u32) -> Result<InputChunkRefV1, InputRefCatalogError> {
        read_reference(&self.root, &self.limits, ordinal)
    }

    pub(crate) fn verify_reference(
        &self,
        reference: InputChunkRefV1,
        reader: &FilesystemCasReader,
        bundle: &ProtocolBundleV1,
    ) -> Result<VerifiedInputChunkRefV1, InputRefCatalogError> {
        let object_ref = CasObjectRefV1 {
            transport_digest: reference.transport_digest,
            encoded_bytes: reference.encoded_bytes,
            expected_ocb1_kind: Some(ObjectKind::AuthenticatedInputChunkV1.tag()),
        };
        let object = reader.read_verified(&object_ref)?;
        let derived = derive_input_chunk_ref(&object, bundle, &self.limits)
            .map_err(|_| {
                ProtocolError::InvalidInvariant("input-ref catalog CAS reference derivation")
            })?
            .reference;
        if derived != reference {
            return Err(ProtocolError::InvalidInvariant("input-ref catalog CAS preimage").into());
        }
        let chunk = decode_verified_input_chunk(&object, bundle, &self.limits)
            .map_err(|_| ProtocolError::InvalidInvariant("input-ref catalog CAS chunk decoding"))?;
        if chunk.protocol_bundle_hash != self.header.protocol_bundle_hash
            || chunk.job_id != self.header.job_id
            || chunk.kind != reference.kind
            || chunk.ordinal != reference.ordinal
        {
            return Err(
                ProtocolError::InvalidInvariant("input-ref catalog chunk authority").into(),
            );
        }
        Ok(VerifiedInputChunkRefV1 { reference, chunk })
    }

    fn entry_path(&self, ordinal: u32) -> PathBuf {
        entry_path(&self.root, ordinal)
    }

    fn require_active(&self) -> Result<(), InputRefCatalogError> {
        if self.abstained {
            Err(InputRefCatalogError::Abstained)
        } else {
            Ok(())
        }
    }

    fn latch_conflict(
        &mut self,
        ordinal: u32,
        existing: &[u8],
        candidate: &[u8],
    ) -> Result<(), InputRefCatalogError> {
        persist_conflict(&self.root, ordinal, existing, candidate)?;
        self.abstained = true;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InputRefCatalogClosureStepV1 {
    Reference(InputChunkRefV1),
    ReferencesClosed,
    DirectoryEntryChecked,
    Complete,
}

enum InputRefCatalogClosureStageV1 {
    References,
    Directory,
    Complete,
}

pub(crate) struct InputRefCatalogClosureCursorV1<'a> {
    catalog: &'a VerifiedInputChunkRefCatalog,
    stage: InputRefCatalogClosureStageV1,
    next_ordinal: u32,
    root: Option<StreamingOrderedListRoot>,
    exact_encoded_bytes: u64,
    exact_record_count: u32,
    tribute_count: u32,
    previous_kind: Option<InputChunkKind>,
    directory: Option<fs::ReadDir>,
    actual_entry_count: u32,
}

impl Iterator for InputRefCatalogClosureCursorV1<'_> {
    type Item = Result<InputRefCatalogClosureStepV1, InputRefCatalogError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.stage {
            InputRefCatalogClosureStageV1::References => {
                if self.next_ordinal < self.catalog.header.input_chunk_count {
                    let ordinal = self.next_ordinal;
                    self.next_ordinal += 1;
                    return Some((|| {
                        let reference = self.catalog.read(ordinal)?;
                        if self.previous_kind.is_some_and(|kind| kind > reference.kind) {
                            return Err(ProtocolError::InvalidInvariant(
                                "input-ref catalog kind order",
                            )
                            .into());
                        }
                        self.previous_kind = Some(reference.kind);
                        self.exact_encoded_bytes = self
                            .exact_encoded_bytes
                            .checked_add(reference.encoded_bytes)
                            .ok_or(ProtocolError::IntegerOverflow {
                                what: "input-ref encoded bytes",
                            })?;
                        self.exact_record_count = self
                            .exact_record_count
                            .checked_add(reference.record_count)
                            .ok_or(ProtocolError::IntegerOverflow {
                                what: "input-ref record count",
                            })?;
                        if reference.kind == InputChunkKind::Tribute {
                            self.tribute_count = self
                                .tribute_count
                                .checked_add(reference.record_count)
                                .ok_or(ProtocolError::IntegerOverflow {
                                    what: "input-ref Tribute count",
                                })?;
                        }
                        self.root
                            .as_mut()
                            .ok_or(ProtocolError::InvalidInvariant(
                                "input-ref closure root state",
                            ))?
                            .push(
                                &reference.encode_canonical_record(&self.catalog.limits)?,
                                self.catalog.limits.max_bounded_bytes,
                            )?;
                        Ok(InputRefCatalogClosureStepV1::Reference(reference))
                    })());
                }

                let root = match self.root.take() {
                    Some(root) => root,
                    None => {
                        return Some(Err(ProtocolError::InvalidInvariant(
                            "input-ref closure root state",
                        )
                        .into()));
                    }
                };
                let closure = root.finish().and_then(|root| {
                    if root != self.catalog.header.input_chunk_list_root
                        || self.exact_encoded_bytes != self.catalog.header.exact_encoded_bytes
                        || self.exact_record_count != self.catalog.header.exact_record_count
                        || self.tribute_count != self.catalog.header.tribute_count
                    {
                        Err(ProtocolError::InvalidInvariant(
                            "input-ref catalog manifest closure",
                        ))
                    } else {
                        Ok(())
                    }
                });
                if let Err(error) = closure {
                    self.stage = InputRefCatalogClosureStageV1::Complete;
                    return Some(Err(error.into()));
                }
                match fs::read_dir(&self.catalog.root) {
                    Ok(directory) => self.directory = Some(directory),
                    Err(source) => {
                        self.stage = InputRefCatalogClosureStageV1::Complete;
                        return Some(Err(io_error(
                            "list input-ref catalog",
                            &self.catalog.root,
                            source,
                        )));
                    }
                }
                self.stage = InputRefCatalogClosureStageV1::Directory;
                Some(Ok(InputRefCatalogClosureStepV1::ReferencesClosed))
            }
            InputRefCatalogClosureStageV1::Directory => {
                let entry = match self.directory.as_mut().and_then(Iterator::next) {
                    Some(Ok(entry)) => entry,
                    Some(Err(source)) => {
                        self.stage = InputRefCatalogClosureStageV1::Complete;
                        return Some(Err(io_error(
                            "read input-ref catalog",
                            &self.catalog.root,
                            source,
                        )));
                    }
                    None => {
                        self.stage = InputRefCatalogClosureStageV1::Complete;
                        if self.actual_entry_count != self.catalog.header.input_chunk_count {
                            return Some(Err(ProtocolError::InvalidInvariant(
                                "closed input-ref catalog count",
                            )
                            .into()));
                        }
                        return Some(Ok(InputRefCatalogClosureStepV1::Complete));
                    }
                };
                Some((|| {
                    let name = entry
                        .file_name()
                        .into_string()
                        .map_err(|_| InputRefCatalogError::UnexpectedCatalogEntry(entry.path()))?;
                    if name == HEADER_FILE
                        || name == PREPARED_FILE
                        || name == STAGING_FILE
                        || name == LOCK_FILE
                    {
                        return Ok(InputRefCatalogClosureStepV1::DirectoryEntryChecked);
                    }
                    let prefix = name.strip_suffix(ENTRY_SUFFIX).ok_or_else(|| {
                        InputRefCatalogError::UnexpectedCatalogEntry(entry.path())
                    })?;
                    let ordinal = parse_entry_ordinal(prefix).ok_or_else(|| {
                        InputRefCatalogError::UnexpectedCatalogEntry(entry.path())
                    })?;
                    if !entry
                        .file_type()
                        .map_err(|source| {
                            io_error("inspect input-ref entry", &entry.path(), source)
                        })?
                        .is_file()
                    {
                        return Err(InputRefCatalogError::UnexpectedCatalogEntry(entry.path()));
                    }
                    if ordinal >= self.catalog.header.input_chunk_count {
                        return Err(InputRefCatalogError::UnexpectedReference { ordinal });
                    }
                    self.actual_entry_count = self.actual_entry_count.checked_add(1).ok_or(
                        ProtocolError::IntegerOverflow {
                            what: "input-ref catalog count",
                        },
                    )?;
                    Ok(InputRefCatalogClosureStepV1::DirectoryEntryChecked)
                })())
            }
            InputRefCatalogClosureStageV1::Complete => None,
        }
    }
}

pub struct InputRefCursor<'a> {
    catalog: &'a VerifiedInputChunkRefCatalog,
    next_ordinal: u32,
}

impl Iterator for InputRefCursor<'_> {
    type Item = Result<InputChunkRefV1, InputRefCatalogError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_ordinal >= self.catalog.header.input_chunk_count {
            return None;
        }
        let ordinal = self.next_ordinal;
        self.next_ordinal += 1;
        Some(self.catalog.read(ordinal))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self
            .catalog
            .header
            .input_chunk_count
            .saturating_sub(self.next_ordinal);
        let remaining = usize::try_from(remaining).unwrap_or(usize::MAX);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for InputRefCursor<'_> {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedInputChunkRefV1 {
    pub reference: InputChunkRefV1,
    pub chunk: AuthenticatedInputChunkV1,
}

pub struct VerifiedInputRefCursor<'a> {
    inner: InputRefCursor<'a>,
    reader: &'a FilesystemCasReader,
    bundle: &'a ProtocolBundleV1,
}

impl Iterator for VerifiedInputRefCursor<'_> {
    type Item = Result<VerifiedInputChunkRefV1, InputRefCatalogError>;

    fn next(&mut self) -> Option<Self::Item> {
        let reference = match self.inner.next()? {
            Ok(reference) => reference,
            Err(error) => return Some(Err(error)),
        };
        Some(
            self.inner
                .catalog
                .verify_reference(reference, self.reader, self.bundle),
        )
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for VerifiedInputRefCursor<'_> {}

#[derive(Debug, Error)]
pub enum InputRefCatalogError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Cas(#[from] CasError),
    #[error("input-ref catalog authority differs from its immutable header")]
    AuthorityMismatch,
    #[error("input-ref catalog immutable header is missing")]
    MissingHeader,
    #[error("input-ref catalog is permanently abstained")]
    Abstained,
    #[error("input-ref catalog was reopened with read-only authority")]
    ReadOnly,
    #[error("input reference {ordinal} is missing")]
    MissingReference { ordinal: u32 },
    #[error("input reference {ordinal} lies outside the manifest")]
    UnexpectedReference { ordinal: u32 },
    #[error("input reference ordinal gap: expected {expected}, got {actual}")]
    OrdinalGap { expected: u32, actual: u32 },
    #[error("input reference kind regressed at ordinal {ordinal}")]
    KindOrder { ordinal: u32 },
    #[error("input reference {ordinal} conflicts with the durable admission")]
    ConflictingReference { ordinal: u32 },
    #[error("input reference ordinal mismatch: requested {requested}, encoded {encoded}")]
    OrdinalBinding { requested: u32, encoded: u32 },
    #[error("unexpected input-ref catalog entry at {0}")]
    UnexpectedCatalogEntry(PathBuf),
    #[error("unsafe input-ref catalog path at {0}")]
    UnsafePath(PathBuf),
    #[error("ambiguous temporary input-ref file remains at {0}")]
    AmbiguousTemporary(PathBuf),
    #[error("input-ref catalog lock is already held at {0}")]
    LockHeld(PathBuf),
    #[error("input-ref catalog object exceeds its bound")]
    ObjectTooLarge,
    #[error("input-ref catalog object has an invalid envelope")]
    InvalidEnvelope,
    #[error("input-ref catalog I/O failed during {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn encode_staging_subject(
    subject: InputRefCatalogSubjectV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, InputRefCatalogError> {
    let mut body = CanonicalWriter::new(limits.codec);
    body.write_b256(subject.protocol_bundle_hash)?;
    body.write_b256(subject.job_id)?;
    body.write_u32(subject.attempt)?;
    Ok(encode_envelope(STAGING_MAGIC, &body.into_bytes()))
}

fn decode_staging_subject(
    encoded: &[u8],
    limits: &SchemaLimits,
) -> Result<InputRefCatalogSubjectV1, InputRefCatalogError> {
    let body = decode_envelope(encoded, STAGING_MAGIC)?;
    let mut input = CanonicalReader::new(body, limits.codec)?;
    let subject = InputRefCatalogSubjectV1 {
        protocol_bundle_hash: input.read_b256()?,
        job_id: input.read_b256()?,
        attempt: input.read_u32()?,
    };
    input.finish()?;
    if encode_staging_subject(subject, limits)? != encoded {
        return Err(InputRefCatalogError::InvalidEnvelope);
    }
    Ok(subject)
}

fn scan_staged_entries(
    root: &Path,
    limits: &SchemaLimits,
) -> Result<(u32, Option<InputChunkKind>), InputRefCatalogError> {
    scan_staged_entries_observing(root, limits, &|| {})
}

fn scan_staged_entries_observing(
    root: &Path,
    limits: &SchemaLimits,
    on_progress: &impl Fn(),
) -> Result<(u32, Option<InputChunkKind>), InputRefCatalogError> {
    let entries =
        fs::read_dir(root).map_err(|source| io_error("list catalog directory", root, source))?;
    let mut count = 0_u32;
    for entry in entries {
        let entry = entry.map_err(|source| io_error("read catalog directory", root, source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| InputRefCatalogError::UnexpectedCatalogEntry(entry.path()))?;
        if name == HEADER_FILE
            || name == PREPARED_FILE
            || name == STAGING_FILE
            || name == LOCK_FILE
            || name == CONFLICT_FILE
        {
            continue;
        }
        let prefix = name
            .strip_suffix(ENTRY_SUFFIX)
            .ok_or_else(|| InputRefCatalogError::UnexpectedCatalogEntry(entry.path()))?;
        parse_entry_ordinal(prefix)
            .ok_or_else(|| InputRefCatalogError::UnexpectedCatalogEntry(entry.path()))?;
        if !entry
            .file_type()
            .map_err(|source| io_error("inspect input-ref entry", &entry.path(), source))?
            .is_file()
        {
            return Err(InputRefCatalogError::UnexpectedCatalogEntry(entry.path()));
        }
        count = count.checked_add(1).ok_or(ProtocolError::IntegerOverflow {
            what: "staged input-ref entry count",
        })?;
        on_progress();
    }
    let mut previous_kind = None;
    for ordinal in 0..count {
        let reference = read_reference(root, limits, ordinal)?;
        if previous_kind.is_some_and(|kind| kind > reference.kind) {
            return Err(InputRefCatalogError::KindOrder { ordinal });
        }
        previous_kind = Some(reference.kind);
        on_progress();
    }
    Ok((count, previous_kind))
}

fn read_reference(
    root: &Path,
    limits: &SchemaLimits,
    ordinal: u32,
) -> Result<InputChunkRefV1, InputRefCatalogError> {
    let path = entry_path(root, ordinal);
    if !path_exists(&path)? {
        return Err(InputRefCatalogError::MissingReference { ordinal });
    }
    let encoded = read_bounded(&path, catalog_byte_cap(limits))?;
    let reference = decode_entry(&encoded, limits)?;
    if reference.ordinal != ordinal {
        return Err(InputRefCatalogError::OrdinalBinding {
            requested: ordinal,
            encoded: reference.ordinal,
        });
    }
    Ok(reference)
}

fn verify_staged_reference(
    reference: &InputChunkRefV1,
    subject: InputRefCatalogSubjectV1,
    reader: &FilesystemCasReader,
    bundle: &ProtocolBundleV1,
    limits: &SchemaLimits,
) -> Result<(), InputRefCatalogError> {
    let object_ref = CasObjectRefV1 {
        transport_digest: reference.transport_digest,
        encoded_bytes: reference.encoded_bytes,
        expected_ocb1_kind: Some(ObjectKind::AuthenticatedInputChunkV1.tag()),
    };
    let object = reader.read_verified(&object_ref)?;
    let derived = derive_input_chunk_ref(&object, bundle, limits)
        .map_err(|_| ProtocolError::InvalidInvariant("staged input-ref CAS reference derivation"))?
        .reference;
    if &derived != reference {
        return Err(ProtocolError::InvalidInvariant("staged input-ref CAS preimage").into());
    }
    let chunk = decode_verified_input_chunk(&object, bundle, limits)
        .map_err(|_| ProtocolError::InvalidInvariant("staged input-ref chunk decoding"))?;
    if chunk.protocol_bundle_hash != subject.protocol_bundle_hash
        || chunk.job_id != subject.job_id
        || chunk.kind != reference.kind
        || chunk.ordinal != reference.ordinal
    {
        return Err(ProtocolError::InvalidInvariant("staged input-ref chunk authority").into());
    }
    Ok(())
}

fn summary_matches_header(
    summary: InputRefCatalogSummaryV1,
    header: &InputRefCatalogHeaderV1,
) -> bool {
    summary.input_chunk_count == header.input_chunk_count
        && summary.input_chunk_list_root == header.input_chunk_list_root
        && summary.exact_encoded_bytes == header.exact_encoded_bytes
        && summary.exact_record_count == header.exact_record_count
        && summary.tribute_count == header.tribute_count
}

fn entry_path(root: &Path, ordinal: u32) -> PathBuf {
    root.join(format!("{ordinal:010}{ENTRY_SUFFIX}"))
}

fn persist_conflict(
    root: &Path,
    ordinal: u32,
    existing: &[u8],
    candidate: &[u8],
) -> Result<(), InputRefCatalogError> {
    let mut marker = Vec::with_capacity(8 + 4 + 32 + 32);
    marker.extend_from_slice(&CONFLICT_MAGIC);
    marker.extend_from_slice(&ordinal.to_be_bytes());
    marker.extend_from_slice(keccak256(existing).as_slice());
    marker.extend_from_slice(keccak256(candidate).as_slice());
    persist_atomic(root, &root.join(CONFLICT_FILE), &marker)
}

fn encode_header(
    header: &InputRefCatalogHeaderV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, InputRefCatalogError> {
    let mut body = CanonicalWriter::new(limits.codec);
    encode_object_ref(&mut body, &header.manifest_ref)?;
    body.write_b256(header.manifest_hash)?;
    body.write_b256(header.protocol_bundle_hash)?;
    body.write_b256(header.job_id)?;
    body.write_u32(header.attempt)?;
    body.write_u32(header.input_chunk_count)?;
    body.write_b256(header.input_chunk_list_root)?;
    body.write_u64(header.exact_encoded_bytes)?;
    body.write_u32(header.exact_record_count)?;
    body.write_u32(header.tribute_count)?;
    Ok(encode_envelope(HEADER_MAGIC, &body.into_bytes()))
}

fn expected_header(
    manifest_ref: &CasObjectRefV1,
    manifest: &InputManifestV1,
    limits: &SchemaLimits,
) -> Result<InputRefCatalogHeaderV1, InputRefCatalogError> {
    manifest.validate_semantics(limits)?;
    if manifest_ref.expected_ocb1_kind != Some(ObjectKind::InputManifestV1.tag())
        || manifest_ref.transport_digest.is_zero()
        || manifest_ref.encoded_bytes == 0
    {
        return Err(
            ProtocolError::InvalidInvariant("input-ref catalog manifest descriptor").into(),
        );
    }
    Ok(InputRefCatalogHeaderV1 {
        manifest_ref: manifest_ref.clone(),
        manifest_hash: manifest.manifest_hash(limits)?,
        protocol_bundle_hash: manifest.protocol_bundle_hash,
        job_id: manifest.job_id,
        attempt: manifest.attempt,
        input_chunk_count: manifest.input_chunk_count,
        input_chunk_list_root: manifest.input_chunk_list_root,
        exact_encoded_bytes: manifest.exact_encoded_bytes,
        exact_record_count: manifest.exact_record_count,
        tribute_count: manifest.tribute_count,
    })
}

fn decode_header(
    encoded: &[u8],
    limits: &SchemaLimits,
) -> Result<InputRefCatalogHeaderV1, InputRefCatalogError> {
    let body = decode_envelope(encoded, HEADER_MAGIC)?;
    let mut input = CanonicalReader::new(body, limits.codec)?;
    let header = InputRefCatalogHeaderV1 {
        manifest_ref: decode_object_ref(&mut input)?,
        manifest_hash: input.read_b256()?,
        protocol_bundle_hash: input.read_b256()?,
        job_id: input.read_b256()?,
        attempt: input.read_u32()?,
        input_chunk_count: input.read_u32()?,
        input_chunk_list_root: input.read_b256()?,
        exact_encoded_bytes: input.read_u64()?,
        exact_record_count: input.read_u32()?,
        tribute_count: input.read_u32()?,
    };
    input.finish()?;
    if encode_header(&header, limits)? != encoded {
        return Err(InputRefCatalogError::InvalidEnvelope);
    }
    Ok(header)
}

fn encode_entry(canonical_reference: &[u8]) -> Vec<u8> {
    encode_envelope(ENTRY_MAGIC, canonical_reference)
}

fn decode_entry(
    encoded: &[u8],
    limits: &SchemaLimits,
) -> Result<InputChunkRefV1, InputRefCatalogError> {
    let body = decode_envelope(encoded, ENTRY_MAGIC)?;
    let reference = InputChunkRefV1::decode_canonical_record(body, limits)?;
    if encode_entry(&reference.encode_canonical_record(limits)?) != encoded {
        return Err(InputRefCatalogError::InvalidEnvelope);
    }
    Ok(reference)
}

fn encode_envelope(magic: [u8; 8], body: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(magic.len() + B256::len_bytes() + body.len());
    output.extend_from_slice(&magic);
    output.extend_from_slice(keccak256(body).as_slice());
    output.extend_from_slice(body);
    output
}

fn decode_envelope(encoded: &[u8], magic: [u8; 8]) -> Result<&[u8], InputRefCatalogError> {
    let body_offset = magic.len() + B256::len_bytes();
    if encoded.len() < body_offset || encoded[..magic.len()] != magic {
        return Err(InputRefCatalogError::InvalidEnvelope);
    }
    let expected = B256::from_slice(&encoded[magic.len()..body_offset]);
    let body = &encoded[body_offset..];
    if keccak256(body) != expected {
        return Err(InputRefCatalogError::InvalidEnvelope);
    }
    Ok(body)
}

fn encode_object_ref(
    output: &mut CanonicalWriter,
    reference: &CasObjectRefV1,
) -> Result<(), ProtocolError> {
    output.write_b256(reference.transport_digest)?;
    output.write_u64(reference.encoded_bytes)?;
    output.write_option(reference.expected_ocb1_kind.as_ref(), |writer, kind| {
        writer.write_u16(*kind)
    })
}

fn decode_object_ref(input: &mut CanonicalReader<'_>) -> Result<CasObjectRefV1, ProtocolError> {
    Ok(CasObjectRefV1 {
        transport_digest: input.read_b256()?,
        encoded_bytes: input.read_u64()?,
        expected_ocb1_kind: input.read_option(|reader| reader.read_u16())?,
    })
}

fn parse_entry_ordinal(prefix: &str) -> Option<u32> {
    if prefix.len() != 10 || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let ordinal = prefix.parse::<u32>().ok()?;
    (format!("{ordinal:010}") == prefix).then_some(ordinal)
}

fn catalog_byte_cap(limits: &SchemaLimits) -> usize {
    limits
        .codec
        .max_body_bytes
        .saturating_add(HEADER_MAGIC.len() + B256::len_bytes())
}

fn create_private_directory(path: &Path) -> Result<(), InputRefCatalogError> {
    reject_symlink_ancestors(path)?;
    fs::create_dir_all(path).map_err(|source| io_error("create directory", path, source))?;
    reject_symlink_ancestors(path)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("inspect directory", path, source))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(InputRefCatalogError::UnsafePath(path.to_path_buf()));
    }
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))
        .map_err(|source| io_error("set directory permissions", path, source))
}

fn inspect_private_directory(path: &Path) -> Result<(), InputRefCatalogError> {
    reject_symlink_ancestors(path)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("inspect directory", path, source))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(InputRefCatalogError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn reject_symlink_ancestors(path: &Path) -> Result<(), InputRefCatalogError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(InputRefCatalogError::UnsafePath(ancestor.to_path_buf()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("inspect catalog ancestor", ancestor, source)),
        }
    }
    Ok(())
}

fn reject_orphaned_temps(root: &Path) -> Result<(), InputRefCatalogError> {
    let entries =
        fs::read_dir(root).map_err(|source| io_error("list catalog directory", root, source))?;
    for entry in entries {
        let entry = entry.map_err(|source| io_error("read catalog directory", root, source))?;
        let path = entry.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(TEMP_SUFFIX))
        {
            return Err(InputRefCatalogError::AmbiguousTemporary(path));
        }
    }
    Ok(())
}

fn recover_staging_temps(root: &Path) -> Result<(), InputRefCatalogError> {
    let entries =
        fs::read_dir(root).map_err(|source| io_error("list catalog directory", root, source))?;
    let mut removed = false;
    for entry in entries {
        let entry = entry.map_err(|source| io_error("read catalog directory", root, source))?;
        let path = entry.path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(TEMP_SUFFIX))
        {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| io_error("inspect temporary catalog object", &path, source))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(InputRefCatalogError::AmbiguousTemporary(path));
        }
        fs::remove_file(&path)
            .map_err(|source| io_error("remove temporary catalog object", &path, source))?;
        removed = true;
    }
    if removed {
        sync_directory(root)?;
    }
    Ok(())
}

fn require_fresh_catalog_without_header(root: &Path) -> Result<(), InputRefCatalogError> {
    let entries =
        fs::read_dir(root).map_err(|source| io_error("list catalog directory", root, source))?;
    for entry in entries {
        let entry = entry.map_err(|source| io_error("read catalog directory", root, source))?;
        if entry.file_name() != LOCK_FILE {
            return Err(InputRefCatalogError::MissingHeader);
        }
    }
    Ok(())
}

fn persist_atomic(root: &Path, target: &Path, bytes: &[u8]) -> Result<(), InputRefCatalogError> {
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(InputRefCatalogError::InvalidEnvelope)?;
    let temp = root.join(format!("{file_name}{TEMP_SUFFIX}"));
    if path_exists(&temp)? {
        return Err(InputRefCatalogError::AmbiguousTemporary(temp));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(|source| io_error("create temporary catalog object", &temp, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write temporary catalog object", &temp, source))?;
    file.sync_all()
        .map_err(|source| io_error("fsync temporary catalog object", &temp, source))?;
    fs::rename(&temp, target)
        .map_err(|source| io_error("install catalog object", target, source))?;
    sync_directory(root)
}

fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, InputRefCatalogError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error("open catalog object", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect catalog object", path, source))?;
    if !metadata.file_type().is_file()
        || metadata.len() > u64::try_from(max_bytes).unwrap_or(u64::MAX)
    {
        return Err(InputRefCatalogError::ObjectTooLarge);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(
        u64::try_from(max_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    )
    .read_to_end(&mut bytes)
    .map_err(|source| io_error("read catalog object", path, source))?;
    if bytes.len() > max_bytes {
        return Err(InputRefCatalogError::ObjectTooLarge);
    }
    Ok(bytes)
}

fn path_exists(path: &Path) -> Result<bool, InputRefCatalogError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(InputRefCatalogError::InvalidEnvelope);
            }
            Ok(true)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("inspect path", path, source)),
    }
}

fn sync_directory(path: &Path) -> Result<(), InputRefCatalogError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("fsync catalog directory", path, source))
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> InputRefCatalogError {
    InputRefCatalogError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

struct CatalogLock {
    file: File,
}

impl CatalogLock {
    #[allow(unsafe_code)]
    fn acquire(root: &Path) -> Result<Self, InputRefCatalogError> {
        let path = root.join(LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| io_error("open catalog lock", &path, source))?;
        // SAFETY: `file` owns a live descriptor for the complete flock call.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(InputRefCatalogError::LockHeld(path));
            }
            return Err(io_error("lock catalog", &path, source));
        }
        Ok(Self { file })
    }

    #[allow(unsafe_code)]
    fn acquire_shared(root: &Path) -> Result<Self, InputRefCatalogError> {
        let path = root.join(LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| io_error("open read-only catalog lock", &path, source))?;
        // SAFETY: `file` owns a live descriptor for the complete flock call.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
        if result != 0 {
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(InputRefCatalogError::LockHeld(path));
            }
            return Err(io_error("lock read-only catalog", &path, source));
        }
        Ok(Self { file })
    }
}

impl Drop for CatalogLock {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.file` remains open for the complete flock call.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}
