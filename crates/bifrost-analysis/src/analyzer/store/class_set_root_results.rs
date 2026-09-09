//! Normalized persistence for complete finding-free RQL class-set projections.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use super::class_set_summaries::ClassSetSummaryAttachment;
use super::{AnalyzerStore, PARSED_BLOB_COMPLETE_CONDITION, Result, StoreError};
use crate::CancellationToken;
use crate::analyzer::Language;
use crate::analyzer::semantic::{SourcePosition, SourceSpan, UnknownReason, WorkspaceRelativePath};

macro_rules! generation_params {
    ($key:expr) => {
        params![
            $key.language.config_label(),
            &$key.workspace_content_digest,
            &$key.provider_behavior_digest,
            &$key.active_pack_digest,
            &$key.field_slots_digest,
            &$key.semantics_digest,
            $key.representation_version,
        ]
    };
}

macro_rules! generation_and_root_params {
    ($key:expr) => {
        params![
            $key.generation.language.config_label(),
            &$key.generation.workspace_content_digest,
            &$key.generation.provider_behavior_digest,
            &$key.generation.active_pack_digest,
            &$key.generation.field_slots_digest,
            &$key.generation.semantics_digest,
            $key.generation.representation_version,
            &$key.root_public_digest,
        ]
    };
}

pub type ClassSetRootResultDigest = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClassSetRootResultGenerationKey {
    pub language: Language,
    pub workspace_content_digest: ClassSetRootResultDigest,
    pub provider_behavior_digest: ClassSetRootResultDigest,
    pub active_pack_digest: ClassSetRootResultDigest,
    pub field_slots_digest: ClassSetRootResultDigest,
    pub semantics_digest: ClassSetRootResultDigest,
    pub representation_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FindingFreeClassSetRootKey {
    pub generation: ClassSetRootResultGenerationKey,
    pub root_public_digest: ClassSetRootResultDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PersistedClassSetStatus {
    Known,
    Partial,
    NoInformation,
    Inconclusive,
}

impl PersistedClassSetStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Known => "known",
            Self::Partial => "partial",
            Self::NoInformation => "no_information",
            Self::Inconclusive => "inconclusive",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "known" => Some(Self::Known),
            "partial" => Some(Self::Partial),
            "no_information" => Some(Self::NoInformation),
            "inconclusive" => Some(Self::Inconclusive),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PersistedClassSetAtom {
    WorkspaceClass(Box<str>),
    ExternalClass(Box<str>),
    Unknown(UnknownReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedClassSetRootRow {
    pub ordinal: u32,
    pub relative_path: PathBuf,
    pub span: SourceSpan,
    pub member: Box<str>,
    pub atom: PersistedClassSetAtom,
    pub status: PersistedClassSetStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingFreeClassSetRootResult {
    pub key: FindingFreeClassSetRootKey,
    pub attachment: ClassSetSummaryAttachment,
    pub rows: Vec<PersistedClassSetRootRow>,
    content_digest: ClassSetRootResultDigest,
    payload_text_bytes: usize,
    retained_bytes: usize,
}

impl FindingFreeClassSetRootResult {
    /// Build the canonical persisted representation from stable projected rows.
    ///
    /// Input ordinals are ignored. Rows are sorted by their complete rendered
    /// payload and assigned dense ordinals, so callers do not duplicate store
    /// ordering or digest rules.
    pub fn try_new(
        key: FindingFreeClassSetRootKey,
        attachment: ClassSetSummaryAttachment,
        mut rows: Vec<PersistedClassSetRootRow>,
    ) -> Result<Self> {
        validate_key_and_attachment(&key, &attachment)?;
        if rows.len() > MAX_CLASS_SET_ROOT_ROWS {
            return Err(StoreError::resource_bound(format!(
                "class-set root row count exceeds {MAX_CLASS_SET_ROOT_ROWS}"
            )));
        }
        for row in &rows {
            validate_row(row)?;
        }
        rows.sort_by(row_payload_order);
        if rows
            .windows(2)
            .any(|pair| row_payload_order(&pair[0], &pair[1]).is_eq())
        {
            return Err(StoreError::new(
                "class-set root result contains duplicate projected rows",
            ));
        }
        for (ordinal, row) in rows.iter_mut().enumerate() {
            row.ordinal = u32::try_from(ordinal).map_err(|_| {
                StoreError::resource_bound("class-set root result ordinal exceeds u32")
            })?;
        }
        Self::try_from_canonical_rows(key, attachment, rows, None)
    }

    pub const fn content_digest(&self) -> &ClassSetRootResultDigest {
        &self.content_digest
    }

    pub const fn payload_text_bytes(&self) -> usize {
        self.payload_text_bytes
    }

    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    fn try_from_canonical_rows(
        key: FindingFreeClassSetRootKey,
        attachment: ClassSetSummaryAttachment,
        rows: Vec<PersistedClassSetRootRow>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self> {
        ensure_optional_cancellation(cancellation)?;
        validate_key_and_attachment(&key, &attachment)?;
        if rows.len() > MAX_CLASS_SET_ROOT_ROWS {
            return Err(StoreError::resource_bound(format!(
                "class-set root row count exceeds {MAX_CLASS_SET_ROOT_ROWS}"
            )));
        }
        for (ordinal, row) in rows.iter().enumerate() {
            ensure_optional_cancellation(cancellation)?;
            validate_row(row)?;
            if usize::try_from(row.ordinal).ok() != Some(ordinal) {
                return Err(StoreError::new(
                    "class-set root result ordinals are not dense",
                ));
            }
        }
        if rows
            .windows(2)
            .any(|pair| !row_payload_order(&pair[0], &pair[1]).is_lt())
        {
            return Err(StoreError::new(
                "class-set root result rows are not canonical",
            ));
        }
        let payload_text_bytes = payload_text_bytes(&attachment, &rows, cancellation)?;
        let retained_bytes = retained_bytes(rows.len(), payload_text_bytes)?;
        let mut result = Self {
            key,
            attachment,
            rows,
            content_digest: [0; 32],
            payload_text_bytes,
            retained_bytes,
        };
        result.content_digest = result.canonical_content_digest(cancellation)?;
        Ok(result)
    }

    fn canonical_content_digest(
        &self,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ClassSetRootResultDigest> {
        let mut hash = RootResultDigest::new(b"bifrost-class-set-root-result-store-v1");
        let generation = &self.key.generation;
        hash.text(generation.language.config_label());
        hash.bytes(&generation.workspace_content_digest);
        hash.bytes(&generation.provider_behavior_digest);
        hash.bytes(&generation.active_pack_digest);
        hash.bytes(&generation.field_slots_digest);
        hash.bytes(&generation.semantics_digest);
        hash.u64(u64::from(generation.representation_version));
        hash.bytes(&self.key.root_public_digest);
        hash.text(&self.attachment.rel_path);
        hash.text(&self.attachment.blob_oid);
        hash.text(self.attachment.language.config_label());
        hash.u64(self.rows.len() as u64);
        for row in &self.rows {
            ensure_optional_cancellation(cancellation)?;
            hash.u64(u64::from(row.ordinal));
            hash.text(path_text(&row.relative_path)?);
            hash.span(row.span);
            hash.text(&row.member);
            match &row.atom {
                PersistedClassSetAtom::WorkspaceClass(class) => {
                    hash.tag(0);
                    hash.text(class);
                }
                PersistedClassSetAtom::ExternalClass(class) => {
                    hash.tag(1);
                    hash.text(class);
                }
                PersistedClassSetAtom::Unknown(reason) => {
                    hash.tag(2);
                    hash.text(&reason.to_string());
                }
            }
            hash.text(row.status.label());
        }
        Ok(hash.finish())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassSetRootResultRejection {
    Validation,
    ResourceBound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassSetRootResultLookup {
    Hit(Box<FindingFreeClassSetRootResult>),
    Miss,
    Rejected(ClassSetRootResultRejection),
}

/// Stable normalized schema-54 state for process-level integration tests.
///
/// SQLite row IDs are deliberately absent: equality compares the persisted
/// semantic keys, complete root headers and canonical children, including the
/// publication timestamps that a read-only warm hit must not refresh.
#[cfg(feature = "test-support")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetRootResultStoreSnapshot {
    pub generations: Vec<ClassSetRootResultGenerationSnapshot>,
    pub results: Vec<FindingFreeClassSetRootResultSnapshot>,
}

#[cfg(feature = "test-support")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetRootResultGenerationSnapshot {
    pub key: ClassSetRootResultGenerationKey,
    pub published_at: u64,
}

#[cfg(feature = "test-support")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingFreeClassSetRootResultSnapshot {
    pub result: FindingFreeClassSetRootResult,
    pub published_at: u64,
}

pub const MAX_CLASS_SET_ROOT_ROWS: usize = 262_144;
pub const MAX_CLASS_SET_ROOT_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const MAX_CLASS_SET_ROOT_TEXT_BYTES: usize = MAX_CLASS_SET_ROOT_RETAINED_BYTES;

pub(crate) static CLASS_SET_ROOT_RESULT_HEADER_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "SELECT results.result_id,results.completion='complete',results.finding_count,
                results.row_count,results.payload_text_bytes,
                CASE WHEN length(results.content_digest)=32 THEN results.content_digest END,
                length(CAST(results.owner_rel_path AS BLOB)),
                length(CAST(blobs.blob_oid AS BLOB)),
                results.owner_rel_path,blobs.blob_oid
         FROM class_set_root_result_generations AS generations
         JOIN class_set_finding_free_root_results AS results
           ON results.generation_id=generations.generation_id
         JOIN blobs ON blobs.id=results.owner_blob_id AND blobs.lang=results.lang
         JOIN blob_meta AS meta ON meta.blob_id=blobs.id
         WHERE generations.lang=?1 AND generations.workspace_content_digest=?2
           AND generations.provider_behavior_digest=?3 AND generations.active_pack_digest=?4
           AND generations.field_slots_digest=?5
           AND generations.root_result_semantics_digest=?6
           AND generations.representation_version=?7 AND results.root_public_digest=?8
           AND {PARSED_BLOB_COMPLETE_CONDITION}"
    )
});

pub(crate) const CLASS_SET_ROOT_RESULT_ROWS_SQL: &str =
    "SELECT length(CAST(rel_path AS BLOB)) + length(CAST(member AS BLOB))
              + length(CAST(atom_kind AS BLOB))
              + length(CAST(COALESCE(class_name,'') AS BLOB))
              + length(CAST(COALESCE(unknown_reason,'') AS BLOB))
              + length(CAST(COALESCE(guard_class,'') AS BLOB))
              + length(CAST(class_set_status AS BLOB)),
            row_ordinal,rel_path,start_byte,start_line,start_byte_column,
            end_byte,end_line,end_byte_column,member,atom_kind,class_name,
            unknown_reason,class_set_status,guard_class
     FROM class_set_finding_free_root_rows
     WHERE result_id=?1 ORDER BY row_ordinal LIMIT ?2";

pub(crate) const PRUNE_OLD_CLASS_SET_ROOT_RESULT_GENERATIONS_SQL: &str =
    "DELETE FROM class_set_root_result_generations
     WHERE lang=?1 AND generation_id NOT IN (
       SELECT generation_id FROM class_set_root_result_generations
       WHERE lang=?1 ORDER BY published_at DESC,generation_id DESC LIMIT 8
     )";

impl AnalyzerStore {
    /// Inject an operational failure at the public root-result store boundary.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn set_class_set_root_result_operational_failure_for_test(&self, fail: bool) {
        self.class_set_root_result_operational_failure
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn reject_injected_class_set_root_result_operation_for_test(&self) -> Result<()> {
        if self
            .class_set_root_result_operational_failure
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(StoreError::new(
                "injected class-set root-result operational failure",
            ));
        }
        Ok(())
    }

    pub fn finding_free_class_set_root_result(
        &self,
        key: &FindingFreeClassSetRootKey,
        max_rows: usize,
        max_retained_bytes: usize,
        cancellation: &CancellationToken,
    ) -> Result<ClassSetRootResultLookup> {
        #[cfg(any(test, feature = "test-support"))]
        self.reject_injected_class_set_root_result_operation_for_test()?;
        validate_generation_key(&key.generation)?;
        ensure_not_cancelled(cancellation)?;
        let mut conn = self.read_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let loaded = match load_result(
            &tx,
            key,
            max_rows.min(MAX_CLASS_SET_ROOT_ROWS),
            max_retained_bytes.min(MAX_CLASS_SET_ROOT_RETAINED_BYTES),
            cancellation,
        ) {
            Ok(Some(result)) => ClassSetRootResultLookup::Hit(Box::new(result)),
            Ok(None) => ClassSetRootResultLookup::Miss,
            Err(error) if error.is_resource_bound() => {
                ClassSetRootResultLookup::Rejected(ClassSetRootResultRejection::ResourceBound)
            }
            Err(error) if error.is_corrupt() => {
                ClassSetRootResultLookup::Rejected(ClassSetRootResultRejection::Validation)
            }
            Err(error) => return Err(error),
        };
        ensure_not_cancelled(cancellation)?;
        tx.commit()?;
        Ok(loaded)
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn class_set_root_result_store_snapshot_for_test(
        &self,
    ) -> Result<ClassSetRootResultStoreSnapshot> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let generations = {
            let mut statement = tx.prepare(
                "SELECT lang,workspace_content_digest,provider_behavior_digest,
                        active_pack_digest,field_slots_digest,root_result_semantics_digest,
                        representation_version,published_at
                 FROM class_set_root_result_generations
                 ORDER BY lang,workspace_content_digest,provider_behavior_digest,
                          active_pack_digest,field_slots_digest,root_result_semantics_digest,
                          representation_version",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })?;
            rows.map(|row| {
                let (lang, workspace, provider, pack, fields, semantics, version, published_at) =
                    row?;
                Ok(ClassSetRootResultGenerationSnapshot {
                    key: snapshot_generation_key(
                        lang, workspace, provider, pack, fields, semantics, version,
                    )?,
                    published_at: snapshot_published_at(published_at)?,
                })
            })
            .collect::<Result<Vec<_>>>()?
        };
        let result_keys = {
            let mut statement = tx.prepare(
                "SELECT generations.lang,generations.workspace_content_digest,
                        generations.provider_behavior_digest,generations.active_pack_digest,
                        generations.field_slots_digest,
                        generations.root_result_semantics_digest,
                        generations.representation_version,results.root_public_digest,
                        results.published_at
                 FROM class_set_root_result_generations AS generations
                 JOIN class_set_finding_free_root_results AS results
                   ON results.generation_id=generations.generation_id
                 ORDER BY generations.lang,generations.workspace_content_digest,
                          generations.provider_behavior_digest,generations.active_pack_digest,
                          generations.field_slots_digest,
                          generations.root_result_semantics_digest,
                          generations.representation_version,results.root_public_digest",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            })?;
            rows.map(|row| {
                let (
                    lang,
                    workspace,
                    provider,
                    pack,
                    fields,
                    semantics,
                    version,
                    root,
                    published_at,
                ) = row?;
                Ok((
                    FindingFreeClassSetRootKey {
                        generation: snapshot_generation_key(
                            lang, workspace, provider, pack, fields, semantics, version,
                        )?,
                        root_public_digest: digest(root, "snapshot root")?,
                    },
                    snapshot_published_at(published_at)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?
        };
        let cancellation = CancellationToken::new();
        let mut results = Vec::with_capacity(result_keys.len());
        for (key, published_at) in result_keys {
            let result = load_result(
                &tx,
                &key,
                MAX_CLASS_SET_ROOT_ROWS,
                MAX_CLASS_SET_ROOT_RETAINED_BYTES,
                &cancellation,
            )?
            .ok_or_else(|| {
                StoreError::new("class-set root-result snapshot lost a retained header")
            })?;
            results.push(FindingFreeClassSetRootResultSnapshot {
                result,
                published_at,
            });
        }
        tx.commit()?;
        Ok(ClassSetRootResultStoreSnapshot {
            generations,
            results,
        })
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn corrupt_only_class_set_root_result_content_digest_for_test(&self) -> Result<()> {
        self.conn.execute(|conn| {
            let mut statement = conn.prepare(
                "SELECT result_id,content_digest
                 FROM class_set_finding_free_root_results ORDER BY result_id LIMIT 2",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if rows.len() != 1 {
                return Err(StoreError::new(format!(
                    "expected one class-set root result to corrupt, found {}",
                    rows.len()
                )));
            }
            let (result_id, mut content_digest) = rows
                .into_iter()
                .next()
                .expect("the sole root-result row was checked above");
            if content_digest.len() != 32 {
                return Err(StoreError::corrupt(
                    "sole class-set root-result digest is already malformed",
                ));
            }
            content_digest[0] ^= u8::MAX;
            let updated = conn.execute(
                "UPDATE class_set_finding_free_root_results
                 SET content_digest=?1 WHERE result_id=?2",
                params![content_digest, result_id],
            )?;
            if updated != 1 {
                return Err(StoreError::new(format!(
                    "expected one class-set root-result digest update, changed {updated}"
                )));
            }
            Ok(())
        })
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn oversize_only_class_set_root_result_row_count_for_test(&self) -> Result<()> {
        self.conn.execute(|conn| {
            let result_ids = {
                let mut statement = conn.prepare(
                    "SELECT result_id FROM class_set_finding_free_root_results
                     ORDER BY result_id LIMIT 2",
                )?;
                statement
                    .query_map([], |row| row.get::<_, i64>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?
            };
            if result_ids.len() != 1 {
                return Err(StoreError::new(format!(
                    "expected one class-set root result to oversize, found {}",
                    result_ids.len()
                )));
            }
            let oversized = i64::try_from(MAX_CLASS_SET_ROOT_ROWS)
                .expect("the class-set root row cap fits i64")
                + 1;
            let updated = conn.execute(
                "UPDATE class_set_finding_free_root_results
                 SET row_count=?1 WHERE result_id=?2",
                params![oversized, result_ids[0]],
            )?;
            if updated != 1 {
                return Err(StoreError::new(format!(
                    "expected one class-set root-result row-count update, changed {updated}"
                )));
            }
            Ok(())
        })
    }

    pub fn publish_finding_free_class_set_root_result(
        &self,
        result: FindingFreeClassSetRootResult,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        #[cfg(any(test, feature = "test-support"))]
        self.reject_injected_class_set_root_result_operation_for_test()?;
        validate_for_publication(&result, cancellation)?;
        self.conn.execute({
            let cancellation = cancellation.clone();
            move |conn| {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                ensure_not_cancelled(&cancellation)?;
                match load_result(
                    &tx,
                    &result.key,
                    MAX_CLASS_SET_ROOT_ROWS,
                    MAX_CLASS_SET_ROOT_RETAINED_BYTES,
                    &cancellation,
                ) {
                    Ok(Some(existing)) if existing == result => {
                        ensure_not_cancelled(&cancellation)?;
                        tx.commit()?;
                        return Ok(false);
                    }
                    Ok(Some(_)) => {
                        return Err(StoreError::new(
                            "class-set root-result key names different complete content",
                        ));
                    }
                    Ok(None) => {}
                    Err(error) if error.is_corrupt() || error.is_resource_bound() => {}
                    Err(error) => return Err(error),
                }

                // A stale owner is deliberately hidden by the read query. A
                // malformed retained row may likewise be unusable. Publication
                // is the only path allowed to repair either shape.
                delete_exact_result(&tx, &result.key)?;
                let owner_blob_id = live_owner_blob_id(&tx, &result)?;
                let generation_id = find_or_insert_generation(&tx, &result.key.generation)?;
                insert_result(&tx, generation_id, owner_blob_id, &result, &cancellation)?;
                ensure_not_cancelled(&cancellation)?;
                if load_result(
                    &tx,
                    &result.key,
                    MAX_CLASS_SET_ROOT_ROWS,
                    MAX_CLASS_SET_ROOT_RETAINED_BYTES,
                    &cancellation,
                )?
                .as_ref()
                    != Some(&result)
                {
                    return Err(StoreError::new(
                        "published class-set root result failed validation",
                    ));
                }
                tx.execute(
                    PRUNE_OLD_CLASS_SET_ROOT_RESULT_GENERATIONS_SQL,
                    params![result.key.generation.language.config_label()],
                )?;
                ensure_not_cancelled(&cancellation)?;
                tx.commit()?;
                Ok(true)
            }
        })
    }
}

fn validate_for_publication(
    result: &FindingFreeClassSetRootResult,
    cancellation: &CancellationToken,
) -> Result<()> {
    let rebuilt = FindingFreeClassSetRootResult::try_from_canonical_rows(
        result.key.clone(),
        result.attachment.clone(),
        result.rows.clone(),
        Some(cancellation),
    )?;
    if rebuilt != *result {
        return Err(StoreError::new(
            "class-set root result changed after canonical construction",
        ));
    }
    Ok(())
}

fn load_result(
    conn: &rusqlite::Connection,
    key: &FindingFreeClassSetRootKey,
    max_rows: usize,
    max_retained_bytes: usize,
    cancellation: &CancellationToken,
) -> Result<Option<FindingFreeClassSetRootResult>> {
    ensure_not_cancelled(cancellation)?;
    let mut statement = conn.prepare_cached(CLASS_SET_ROOT_RESULT_HEADER_SQL.as_str())?;
    let mut query = statement.query(generation_and_root_params!(key))?;
    let Some(header) = query.next()? else {
        return Ok(None);
    };
    ensure_not_cancelled(cancellation)?;
    let result_id = header.get::<_, i64>(0)?;
    let completion = header.get::<_, bool>(1)?;
    let finding_count = header.get::<_, i64>(2)?;
    let row_count = header.get::<_, i64>(3)?;
    let text_bytes = header.get::<_, i64>(4)?;
    let content_digest = header.get::<_, Option<Vec<u8>>>(5)?;
    let owner_path_bytes = header.get::<_, i64>(6)?;
    let owner_blob_oid_bytes = header.get::<_, i64>(7)?;
    if !completion || finding_count != 0 {
        return Err(StoreError::corrupt(
            "class-set root-result completion marker is corrupt",
        ));
    }
    let row_count = bounded_count(row_count, max_rows, "row")?;
    let text_bytes = bounded_count(
        text_bytes,
        MAX_CLASS_SET_ROOT_TEXT_BYTES,
        "payload text byte",
    )?;
    let expected_retained_bytes = retained_bytes(row_count, text_bytes)?;
    if expected_retained_bytes > max_retained_bytes {
        return Err(StoreError::resource_bound(format!(
            "class-set root-result retained size exceeds {max_retained_bytes} bytes"
        )));
    }
    let owner_path_bytes = bounded_count(
        owner_path_bytes,
        MAX_CLASS_SET_ROOT_TEXT_BYTES,
        "owner path text byte",
    )?;
    let owner_blob_oid_bytes = bounded_count(
        owner_blob_oid_bytes,
        MAX_CLASS_SET_ROOT_TEXT_BYTES,
        "owner blob text byte",
    )?;
    let attachment_text_bytes = owner_path_bytes
        .checked_add(owner_blob_oid_bytes)
        .ok_or_else(|| {
            StoreError::resource_bound("class-set root-result attachment size overflows usize")
        })?;
    if attachment_text_bytes > text_bytes {
        return Err(StoreError::corrupt(
            "class-set root-result attachment text size is corrupt",
        ));
    }
    // The length columns above are decoded and admitted before either owned
    // string. This keeps a corrupt header from allocating outside the caller's
    // already-validated retained-byte envelope.
    let owner_rel_path = header.get::<_, String>(8)?;
    let owner_blob_oid = header.get::<_, String>(9)?;
    let row_text_bytes = text_bytes - attachment_text_bytes;
    let rows = load_rows(conn, result_id, row_count, row_text_bytes, cancellation)?;
    let result = FindingFreeClassSetRootResult::try_from_canonical_rows(
        key.clone(),
        ClassSetSummaryAttachment {
            rel_path: owner_rel_path,
            blob_oid: owner_blob_oid,
            language: key.generation.language,
        },
        rows,
        Some(cancellation),
    )
    .map_err(|error| {
        if cancellation.is_cancelled() || error.is_resource_bound() {
            error
        } else {
            StoreError::corrupt(format!("invalid persisted class-set root result: {error}"))
        }
    })?;
    if result.payload_text_bytes != text_bytes || result.retained_bytes != expected_retained_bytes {
        return Err(StoreError::corrupt(
            "class-set root-result payload size is corrupt",
        ));
    }
    let content_digest = content_digest.ok_or_else(|| {
        StoreError::corrupt("class-set root-result content digest size is corrupt")
    })?;
    if result.content_digest != digest(content_digest, "content")? {
        return Err(StoreError::corrupt(
            "class-set root-result content digest is corrupt",
        ));
    }
    Ok(Some(result))
}

fn load_rows(
    conn: &rusqlite::Connection,
    result_id: i64,
    expected_count: usize,
    expected_text_bytes: usize,
    cancellation: &CancellationToken,
) -> Result<Vec<PersistedClassSetRootRow>> {
    let limit = i64::try_from(expected_count.saturating_add(1))
        .map_err(|_| StoreError::resource_bound("class-set root row limit exceeds i64"))?;
    let mut statement = conn.prepare_cached(CLASS_SET_ROOT_RESULT_ROWS_SQL)?;
    let mut query = statement.query(params![result_id, limit])?;
    let mut rows = Vec::new();
    let mut actual_text_bytes = 0usize;
    while let Some(row) = query.next()? {
        ensure_not_cancelled(cancellation)?;
        admit_text_bytes(&mut actual_text_bytes, row.get(0)?, expected_text_bytes)?;
        let ordinal = u32_value(row.get(1)?, "row ordinal")?;
        if usize::try_from(ordinal).ok() != Some(rows.len()) {
            return Err(StoreError::corrupt(
                "class-set root-result row ordinals are not dense",
            ));
        }
        let relative_path = PathBuf::from(row.get::<_, String>(2)?);
        let span = SourceSpan::new(
            SourcePosition::new(
                u32_value(row.get(3)?, "start byte")?,
                u32_value(row.get(4)?, "start line")?,
                u32_value(row.get(5)?, "start byte column")?,
            ),
            SourcePosition::new(
                u32_value(row.get(6)?, "end byte")?,
                u32_value(row.get(7)?, "end line")?,
                u32_value(row.get(8)?, "end byte column")?,
            ),
        )
        .map_err(|error| {
            StoreError::corrupt(format!("invalid root-result source span: {error}"))
        })?;
        let member = row.get::<_, String>(9)?.into_boxed_str();
        let atom_kind = row.get::<_, String>(10)?;
        let class_name = row.get::<_, Option<String>>(11)?;
        let unknown_reason = row.get::<_, Option<String>>(12)?;
        let guard_class = row.get::<_, Option<String>>(14)?;
        let atom = decode_atom(&atom_kind, class_name, unknown_reason, guard_class)?;
        let status_label = row.get::<_, String>(13)?;
        let status = PersistedClassSetStatus::from_label(&status_label).ok_or_else(|| {
            StoreError::corrupt(format!(
                "class-set root-result status {status_label:?} is corrupt"
            ))
        })?;
        rows.push(PersistedClassSetRootRow {
            ordinal,
            relative_path,
            span,
            member,
            atom,
            status,
        });
    }
    if rows.len() != expected_count {
        return Err(StoreError::corrupt(
            "class-set root-result child count is corrupt",
        ));
    }
    if actual_text_bytes != expected_text_bytes {
        return Err(StoreError::corrupt(
            "class-set root-result payload text size is corrupt",
        ));
    }
    rows.shrink_to_fit();
    Ok(rows)
}

fn decode_atom(
    atom_kind: &str,
    class_name: Option<String>,
    unknown_reason: Option<String>,
    guard_class: Option<String>,
) -> Result<PersistedClassSetAtom> {
    match (
        atom_kind,
        class_name,
        unknown_reason.as_deref(),
        guard_class,
    ) {
        ("workspace", Some(class), None, None) if !class.is_empty() => Ok(
            PersistedClassSetAtom::WorkspaceClass(class.into_boxed_str()),
        ),
        ("external", Some(class), None, None) if !class.is_empty() => {
            Ok(PersistedClassSetAtom::ExternalClass(class.into_boxed_str()))
        }
        ("unknown", None, Some("unmodeled_guard"), Some(class)) if !class.is_empty() => Ok(
            PersistedClassSetAtom::Unknown(UnknownReason::UnmodeledGuard {
                class: class.into_boxed_str(),
            }),
        ),
        ("unknown", None, Some(reason), None) => UnknownReason::from_label(reason)
            .filter(|reason| {
                !matches!(
                    reason,
                    UnknownReason::UnmodeledGuard { .. } | UnknownReason::DynamicFieldWrite
                )
            })
            .map(PersistedClassSetAtom::Unknown)
            .ok_or_else(|| {
                StoreError::corrupt(format!(
                    "class-set root-result unknown reason {reason:?} is corrupt"
                ))
            }),
        _ => Err(StoreError::corrupt(
            "class-set root-result atom columns are corrupt",
        )),
    }
}

fn insert_result(
    conn: &rusqlite::Connection,
    generation_id: i64,
    owner_blob_id: i64,
    result: &FindingFreeClassSetRootResult,
    cancellation: &CancellationToken,
) -> Result<()> {
    conn.execute(
        "INSERT INTO class_set_finding_free_root_results(
           generation_id,root_public_digest,owner_rel_path,owner_blob_id,lang,
           completion,finding_count,row_count,payload_text_bytes,content_digest,published_at)
         VALUES(?1,?2,?3,?4,?5,'complete',0,?6,?7,?8,unixepoch())",
        params![
            generation_id,
            result.key.root_public_digest.as_slice(),
            &result.attachment.rel_path,
            owner_blob_id,
            result.key.generation.language.config_label(),
            result.rows.len(),
            result.payload_text_bytes,
            result.content_digest.as_slice(),
        ],
    )?;
    let result_id = conn.last_insert_rowid();
    for row in &result.rows {
        ensure_not_cancelled(cancellation)?;
        let (atom_kind, class_name, unknown_reason, guard_class) = match &row.atom {
            PersistedClassSetAtom::WorkspaceClass(class) => {
                ("workspace", Some(class.as_ref()), None, None)
            }
            PersistedClassSetAtom::ExternalClass(class) => {
                ("external", Some(class.as_ref()), None, None)
            }
            PersistedClassSetAtom::Unknown(reason @ UnknownReason::UnmodeledGuard { class }) => {
                ("unknown", None, Some(reason.label()), Some(class.as_ref()))
            }
            PersistedClassSetAtom::Unknown(reason) => ("unknown", None, Some(reason.label()), None),
        };
        conn.execute(
            "INSERT INTO class_set_finding_free_root_rows(
               result_id,row_ordinal,rel_path,start_byte,start_line,start_byte_column,
               end_byte,end_line,end_byte_column,member,atom_kind,class_name,
               unknown_reason,class_set_status,guard_class)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                result_id,
                row.ordinal,
                path_text(&row.relative_path)?,
                row.span.start().byte_offset(),
                row.span.start().line(),
                row.span.start().byte_column(),
                row.span.end().byte_offset(),
                row.span.end().line(),
                row.span.end().byte_column(),
                &row.member,
                atom_kind,
                class_name,
                unknown_reason,
                row.status.label(),
                guard_class,
            ],
        )?;
    }
    Ok(())
}

fn find_or_insert_generation(
    conn: &rusqlite::Connection,
    key: &ClassSetRootResultGenerationKey,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO class_set_root_result_generations(
           lang,workspace_content_digest,provider_behavior_digest,active_pack_digest,
           field_slots_digest,root_result_semantics_digest,representation_version,published_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,unixepoch())
         ON CONFLICT(lang,workspace_content_digest,provider_behavior_digest,active_pack_digest,
                     field_slots_digest,root_result_semantics_digest,representation_version)
         DO NOTHING",
        generation_params!(key),
    )?;
    conn.query_row(
        "SELECT generation_id FROM class_set_root_result_generations
         WHERE lang=?1 AND workspace_content_digest=?2 AND provider_behavior_digest=?3
           AND active_pack_digest=?4 AND field_slots_digest=?5
           AND root_result_semantics_digest=?6 AND representation_version=?7",
        generation_params!(key),
        |row| row.get(0),
    )
    .map_err(StoreError::from)
}

fn delete_exact_result(
    conn: &rusqlite::Connection,
    key: &FindingFreeClassSetRootKey,
) -> Result<()> {
    conn.execute(
        "DELETE FROM class_set_finding_free_root_results
         WHERE root_public_digest=?8 AND generation_id IN (
           SELECT generation_id FROM class_set_root_result_generations
           WHERE lang=?1 AND workspace_content_digest=?2 AND provider_behavior_digest=?3
             AND active_pack_digest=?4 AND field_slots_digest=?5
             AND root_result_semantics_digest=?6 AND representation_version=?7
         )",
        generation_and_root_params!(key),
    )?;
    Ok(())
}

fn live_owner_blob_id(
    conn: &rusqlite::Connection,
    result: &FindingFreeClassSetRootResult,
) -> Result<i64> {
    conn.query_row(
        &format!(
            "SELECT meta.blob_id FROM blob_meta AS meta
             JOIN blobs ON blobs.id=meta.blob_id
             WHERE blobs.blob_oid=?1 AND blobs.lang=?2
               AND {PARSED_BLOB_COMPLETE_CONDITION}"
        ),
        params![
            &result.attachment.blob_oid,
            result.key.generation.language.config_label()
        ],
        |row| row.get(0),
    )
    .optional()?
    .ok_or_else(|| {
        StoreError::new(format!(
            "class-set root-result owner blob {}/{} is absent",
            result.attachment.blob_oid,
            result.key.generation.language.config_label()
        ))
    })
}

fn validate_key_and_attachment(
    key: &FindingFreeClassSetRootKey,
    attachment: &ClassSetSummaryAttachment,
) -> Result<()> {
    validate_generation_key(&key.generation)?;
    if attachment.language != key.generation.language
        || attachment.rel_path.is_empty()
        || !valid_rel_path(Path::new(&attachment.rel_path))
        || git2::Oid::from_str(&attachment.blob_oid).is_err()
    {
        return Err(StoreError::new(
            "class-set root-result owner attachment is invalid",
        ));
    }
    let parsed_oid = git2::Oid::from_str(&attachment.blob_oid)
        .map_err(|error| StoreError::new(format!("invalid owner blob identity: {error}")))?;
    if parsed_oid.to_string() != attachment.blob_oid {
        return Err(StoreError::new(
            "class-set root-result owner blob identity is not canonical",
        ));
    }
    Ok(())
}

fn validate_generation_key(key: &ClassSetRootResultGenerationKey) -> Result<()> {
    if key.language == Language::None || key.representation_version == 0 {
        return Err(StoreError::new(
            "class-set root-result generation key is invalid",
        ));
    }
    Ok(())
}

fn validate_row(row: &PersistedClassSetRootRow) -> Result<()> {
    if !valid_rel_path(&row.relative_path) || row.member.is_empty() {
        return Err(StoreError::new("class-set root-result row is invalid"));
    }
    match &row.atom {
        PersistedClassSetAtom::Unknown(UnknownReason::DynamicFieldWrite) => Err(StoreError::new(
            "dynamic field write evidence is request-local",
        )),
        PersistedClassSetAtom::WorkspaceClass(class)
        | PersistedClassSetAtom::ExternalClass(class)
        | PersistedClassSetAtom::Unknown(UnknownReason::UnmodeledGuard { class })
            if class.is_empty() =>
        {
            Err(StoreError::new("class-set root-result class name is empty"))
        }
        _ => Ok(()),
    }
}

fn valid_rel_path(path: &Path) -> bool {
    path.to_str().is_some_and(|path_text| {
        !path_text.is_empty()
            && WorkspaceRelativePath::try_from_path(path)
                .is_ok_and(|normalized| normalized.as_str() == path_text)
    })
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .filter(|_| valid_rel_path(path))
        .ok_or_else(|| StoreError::new("class-set root-result path is not portable"))
}

fn row_payload_order(
    left: &PersistedClassSetRootRow,
    right: &PersistedClassSetRootRow,
) -> Ordering {
    left.relative_path
        .to_str()
        .expect("the left root-result path was validated")
        .cmp(
            right
                .relative_path
                .to_str()
                .expect("the right root-result path was validated"),
        )
        .then_with(|| left.span.cmp(&right.span))
        .then_with(|| left.member.cmp(&right.member))
        .then_with(|| left.atom.cmp(&right.atom))
        .then_with(|| left.status.cmp(&right.status))
}

fn payload_text_bytes(
    attachment: &ClassSetSummaryAttachment,
    rows: &[PersistedClassSetRootRow],
    cancellation: Option<&CancellationToken>,
) -> Result<usize> {
    ensure_optional_cancellation(cancellation)?;
    let attachment_bytes = attachment
        .rel_path
        .len()
        .checked_add(attachment.blob_oid.len())
        .ok_or_else(|| {
            StoreError::resource_bound("class-set root-result text size overflows usize")
        })?;
    rows.iter().try_fold(attachment_bytes, |total, row| {
        ensure_optional_cancellation(cancellation)?;
        let atom_bytes = match &row.atom {
            PersistedClassSetAtom::WorkspaceClass(class)
            | PersistedClassSetAtom::ExternalClass(class) => class.len(),
            PersistedClassSetAtom::Unknown(reason) => {
                reason.label().len()
                    + match reason {
                        UnknownReason::UnmodeledGuard { class } => class.len(),
                        _ => 0,
                    }
            }
        };
        [
            path_text(&row.relative_path)?.len(),
            row.member.len(),
            atom_kind(&row.atom).len(),
            atom_bytes,
            row.status.label().len(),
        ]
        .into_iter()
        .try_fold(total, |total, bytes| {
            total.checked_add(bytes).ok_or_else(|| {
                StoreError::resource_bound("class-set root-result text size overflows usize")
            })
        })
    })
}

fn retained_bytes(row_count: usize, text_bytes: usize) -> Result<usize> {
    if text_bytes > MAX_CLASS_SET_ROOT_TEXT_BYTES {
        return Err(StoreError::resource_bound(format!(
            "class-set root-result text exceeds {MAX_CLASS_SET_ROOT_TEXT_BYTES} bytes"
        )));
    }
    let bytes = row_count
        .checked_mul(std::mem::size_of::<PersistedClassSetRootRow>())
        .and_then(|fixed| fixed.checked_add(text_bytes))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<FindingFreeClassSetRootResult>()))
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or_else(|| {
            StoreError::resource_bound("class-set root-result retained size overflows usize")
        })?;
    if bytes > MAX_CLASS_SET_ROOT_RETAINED_BYTES {
        return Err(StoreError::resource_bound(format!(
            "class-set root-result retained size exceeds {MAX_CLASS_SET_ROOT_RETAINED_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn atom_kind(atom: &PersistedClassSetAtom) -> &'static str {
    match atom {
        PersistedClassSetAtom::WorkspaceClass(_) => "workspace",
        PersistedClassSetAtom::ExternalClass(_) => "external",
        PersistedClassSetAtom::Unknown(_) => "unknown",
    }
}

fn bounded_count(value: i64, max: usize, name: &str) -> Result<usize> {
    let value = usize::try_from(value).map_err(|_| {
        StoreError::corrupt(format!("class-set root-result {name} count is invalid"))
    })?;
    if value > max {
        return Err(StoreError::resource_bound(format!(
            "class-set root-result {name} count exceeds {max}"
        )));
    }
    Ok(value)
}

fn admit_text_bytes(total: &mut usize, row_bytes: i64, declared_text_bytes: usize) -> Result<()> {
    let row_bytes = bounded_count(
        row_bytes,
        MAX_CLASS_SET_ROOT_TEXT_BYTES,
        "payload row text byte",
    )?;
    *total = total.checked_add(row_bytes).ok_or_else(|| {
        StoreError::resource_bound("class-set root-result text size overflows usize")
    })?;
    if *total > MAX_CLASS_SET_ROOT_TEXT_BYTES {
        return Err(StoreError::resource_bound(format!(
            "class-set root-result text exceeds {MAX_CLASS_SET_ROOT_TEXT_BYTES} bytes"
        )));
    }
    if *total > declared_text_bytes {
        return Err(StoreError::corrupt(
            "class-set root-result row text exceeds its declared size",
        ));
    }
    Ok(())
}

fn u32_value(value: i64, name: &str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| StoreError::corrupt(format!("class-set root-result {name} exceeds u32")))
}

fn digest(bytes: Vec<u8>, name: &str) -> Result<ClassSetRootResultDigest> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        StoreError::corrupt(format!(
            "class-set root-result {name} digest has {} bytes",
            bytes.len()
        ))
    })
}

#[cfg(feature = "test-support")]
fn snapshot_generation_key(
    language: String,
    workspace_content_digest: Vec<u8>,
    provider_behavior_digest: Vec<u8>,
    active_pack_digest: Vec<u8>,
    field_slots_digest: Vec<u8>,
    semantics_digest: Vec<u8>,
    representation_version: i64,
) -> Result<ClassSetRootResultGenerationKey> {
    Ok(ClassSetRootResultGenerationKey {
        language: Language::from_config_label(&language)
            .filter(|candidate| {
                *candidate != Language::None && candidate.config_label() == language
            })
            .ok_or_else(|| {
                StoreError::corrupt(format!(
                    "class-set root-result snapshot language {language:?} is corrupt"
                ))
            })?,
        workspace_content_digest: digest(workspace_content_digest, "snapshot workspace")?,
        provider_behavior_digest: digest(provider_behavior_digest, "snapshot provider")?,
        active_pack_digest: digest(active_pack_digest, "snapshot pack")?,
        field_slots_digest: digest(field_slots_digest, "snapshot field slots")?,
        semantics_digest: digest(semantics_digest, "snapshot semantics")?,
        representation_version: u32_value(representation_version, "snapshot representation")?,
    })
}

#[cfg(feature = "test-support")]
fn snapshot_published_at(value: i64) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| StoreError::corrupt("class-set root-result publication time is corrupt"))
}

fn ensure_not_cancelled(cancellation: &CancellationToken) -> Result<()> {
    if cancellation.is_cancelled() {
        Err(StoreError::new("class-set root-result operation cancelled"))
    } else {
        Ok(())
    }
}

fn ensure_optional_cancellation(cancellation: Option<&CancellationToken>) -> Result<()> {
    match cancellation {
        Some(cancellation) => ensure_not_cancelled(cancellation),
        None => Ok(()),
    }
}

struct RootResultDigest(Sha256);

impl RootResultDigest {
    fn new(domain: &[u8]) -> Self {
        let mut digest = Self(Sha256::new());
        digest.bytes(domain);
        digest
    }

    fn bytes(&mut self, value: &[u8]) {
        self.0.update((value.len() as u64).to_le_bytes());
        self.0.update(value);
    }

    fn text(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn tag(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_le_bytes());
    }

    fn span(&mut self, span: SourceSpan) {
        self.u64(u64::from(span.start().byte_offset()));
        self.u64(u64::from(span.start().line()));
        self.u64(u64::from(span.start().byte_column()));
        self.u64(u64::from(span.end().byte_offset()));
        self.u64(u64::from(span.end().line()));
        self.u64(u64::from(span.end().byte_column()));
    }

    fn finish(self) -> ClassSetRootResultDigest {
        self.0.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::store::planner_statistics::tests::{explain_pin, pinned};
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use std::sync::{Arc, Barrier};

    const BLOB: &str = "1111111111111111111111111111111111111111";

    fn insert_complete_blob(store: &AnalyzerStore) {
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'python', 0)",
            params![BLOB],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blob_meta(
               blob_id, lang, contains_tests, content_package, stored_unit_count,
               range_count, signature_count, signature_metadata_count, supertype_count,
               child_count, import_statement_count, type_identifier_count, is_complete
             )
             SELECT id, lang, 0, '', 0, 0, 0, 0, 0, 0, 0, 0, 1
             FROM blobs WHERE blob_oid = ?1 AND lang = 'python'",
            params![BLOB],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blob_payload_costs(blob_id, payload_bytes)
             SELECT id, 0 FROM blobs WHERE blob_oid = ?1 AND lang = 'python'",
            params![BLOB],
        )
        .unwrap();
    }

    fn generation(seed: u8) -> ClassSetRootResultGenerationKey {
        ClassSetRootResultGenerationKey {
            language: Language::Python,
            workspace_content_digest: [seed; 32],
            provider_behavior_digest: [2; 32],
            active_pack_digest: [3; 32],
            field_slots_digest: [4; 32],
            semantics_digest: [5; 32],
            representation_version: 1,
        }
    }

    fn source_span(start: u32, end: u32) -> SourceSpan {
        SourceSpan::new(
            SourcePosition::new(start, 0, start),
            SourcePosition::new(end, 0, end),
        )
        .unwrap()
    }

    fn result(seed: u8) -> FindingFreeClassSetRootResult {
        FindingFreeClassSetRootResult::try_new(
            FindingFreeClassSetRootKey {
                generation: generation(seed),
                root_public_digest: [6; 32],
            },
            ClassSetSummaryAttachment {
                rel_path: "src/app.py".to_string(),
                blob_oid: BLOB.to_string(),
                language: Language::Python,
            },
            vec![
                PersistedClassSetRootRow {
                    ordinal: 100,
                    relative_path: PathBuf::from("src/app.py"),
                    span: source_span(40, 46),
                    member: "scalar".into(),
                    atom: PersistedClassSetAtom::Unknown(UnknownReason::ScalarReceiver),
                    status: PersistedClassSetStatus::Partial,
                },
                PersistedClassSetRootRow {
                    ordinal: 99,
                    relative_path: PathBuf::from("src/app.py"),
                    span: source_span(30, 36),
                    member: "maybe".into(),
                    atom: PersistedClassSetAtom::Unknown(UnknownReason::OpenTypeBound),
                    status: PersistedClassSetStatus::Partial,
                },
                PersistedClassSetRootRow {
                    ordinal: 88,
                    relative_path: PathBuf::from("src/app.py"),
                    span: source_span(10, 15),
                    member: "value".into(),
                    atom: PersistedClassSetAtom::WorkspaceClass("sample.Value".into()),
                    status: PersistedClassSetStatus::Known,
                },
            ],
        )
        .unwrap()
    }

    fn result_with_rows(count: u32) -> FindingFreeClassSetRootResult {
        let rows = (0..count)
            .map(|ordinal| PersistedClassSetRootRow {
                ordinal,
                relative_path: PathBuf::from("src/app.py"),
                span: source_span(ordinal.saturating_mul(2), ordinal.saturating_mul(2) + 1),
                member: format!("value_{ordinal}").into_boxed_str(),
                atom: PersistedClassSetAtom::Unknown(UnknownReason::UnresolvedCall),
                status: PersistedClassSetStatus::Partial,
            })
            .collect();
        FindingFreeClassSetRootResult::try_new(
            FindingFreeClassSetRootKey {
                generation: generation(1),
                root_public_digest: [7; 32],
            },
            ClassSetSummaryAttachment {
                rel_path: "src/app.py".to_string(),
                blob_oid: BLOB.to_string(),
                language: Language::Python,
            },
            rows,
        )
        .unwrap()
    }

    fn store_with_blob() -> AnalyzerStore {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        insert_complete_blob(&store);
        store
    }

    fn load(
        store: &AnalyzerStore,
        key: &FindingFreeClassSetRootKey,
    ) -> Result<ClassSetRootResultLookup> {
        store.finding_free_class_set_root_result(
            key,
            MAX_CLASS_SET_ROOT_ROWS,
            MAX_CLASS_SET_ROOT_RETAINED_BYTES,
            &CancellationToken::new(),
        )
    }

    #[test]
    fn named_guard_reasons_round_trip_with_separate_class_identity() {
        let store = store_with_blob();
        let base = result(1);
        let mut rows = base.rows.clone();
        rows[1].atom = PersistedClassSetAtom::Unknown(UnknownReason::UnmodeledGuard {
            class: "unknown_module.Thing".into(),
        });
        let expected =
            FindingFreeClassSetRootResult::try_new(base.key, base.attachment, rows).unwrap();
        assert!(
            store
                .publish_finding_free_class_set_root_result(
                    expected.clone(),
                    &CancellationToken::new()
                )
                .unwrap()
        );
        assert_eq!(
            load(&store, &expected.key).unwrap(),
            ClassSetRootResultLookup::Hit(Box::new(expected.clone()))
        );
        let stored: (String, String) = store
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT unknown_reason,guard_class FROM class_set_finding_free_root_rows
             WHERE unknown_reason='unmodeled_guard'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            stored,
            ("unmodeled_guard".into(), "unknown_module.Thing".into())
        );
        assert_eq!(
            store
                .finding_free_class_set_root_result(
                    &expected.key,
                    MAX_CLASS_SET_ROOT_ROWS,
                    expected.retained_bytes() - 1,
                    &CancellationToken::new()
                )
                .unwrap(),
            ClassSetRootResultLookup::Rejected(ClassSetRootResultRejection::ResourceBound)
        );
    }

    #[test]
    fn finding_free_root_results_round_trip_canonically_and_publish_idempotently() {
        let store = store_with_blob();
        let expected = result(1);
        assert_eq!(expected.rows[0].ordinal, 0);
        assert_eq!(expected.rows[0].member.as_ref(), "value");

        assert!(
            store
                .publish_finding_free_class_set_root_result(
                    expected.clone(),
                    &CancellationToken::new(),
                )
                .unwrap()
        );
        assert_eq!(
            load(&store, &expected.key).unwrap(),
            ClassSetRootResultLookup::Hit(Box::new(expected.clone()))
        );
        assert_eq!(
            store
                .finding_free_class_set_root_result(
                    &expected.key,
                    1,
                    MAX_CLASS_SET_ROOT_RETAINED_BYTES,
                    &CancellationToken::new(),
                )
                .unwrap(),
            ClassSetRootResultLookup::Rejected(ClassSetRootResultRejection::ResourceBound)
        );
        assert_eq!(
            store
                .finding_free_class_set_root_result(
                    &expected.key,
                    MAX_CLASS_SET_ROOT_ROWS,
                    expected.retained_bytes() - 1,
                    &CancellationToken::new(),
                )
                .unwrap(),
            ClassSetRootResultLookup::Rejected(ClassSetRootResultRejection::ResourceBound)
        );
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE class_set_finding_free_root_results SET published_at=7",
                [],
            )
            .unwrap();
        assert!(
            !store
                .publish_finding_free_class_set_root_result(
                    expected.clone(),
                    &CancellationToken::new(),
                )
                .unwrap()
        );
        assert_eq!(
            store
                .conn
                .lock()
                .unwrap()
                .query_row(
                    "SELECT published_at FROM class_set_finding_free_root_results",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            7,
            "an idempotent publication does not touch the stable header"
        );

        let mut miss = expected.key.clone();
        miss.generation.field_slots_digest[0] ^= 1;
        assert_eq!(load(&store, &miss).unwrap(), ClassSetRootResultLookup::Miss);
    }

    #[test]
    fn zero_row_results_round_trip_and_dto_validation_fails_closed() {
        let store = store_with_blob();
        let expected = result_with_rows(0);
        assert!(
            store
                .publish_finding_free_class_set_root_result(
                    expected.clone(),
                    &CancellationToken::new(),
                )
                .unwrap()
        );
        assert_eq!(
            load(&store, &expected.key).unwrap(),
            ClassSetRootResultLookup::Hit(Box::new(expected))
        );

        let mut duplicate = result(1);
        duplicate.rows.push(duplicate.rows[0].clone());
        assert!(
            FindingFreeClassSetRootResult::try_new(
                duplicate.key,
                duplicate.attachment,
                duplicate.rows,
            )
            .is_err()
        );
        let mut invalid_path = result(1);
        invalid_path.rows[0].relative_path = PathBuf::from("../outside.py");
        assert!(
            FindingFreeClassSetRootResult::try_new(
                invalid_path.key,
                invalid_path.attachment,
                invalid_path.rows,
            )
            .is_err()
        );
        let mut invalid_generation = result(1);
        invalid_generation.key.generation.representation_version = 0;
        assert!(
            FindingFreeClassSetRootResult::try_new(
                invalid_generation.key,
                invalid_generation.attachment,
                invalid_generation.rows,
            )
            .is_err()
        );
    }

    #[test]
    fn dynamic_write_rows_are_rejected_before_publication() {
        let mut candidate = result(1);
        candidate.rows[0].atom = PersistedClassSetAtom::Unknown(UnknownReason::DynamicFieldWrite);
        let error = FindingFreeClassSetRootResult::try_new(
            candidate.key,
            candidate.attachment,
            candidate.rows,
        )
        .unwrap_err();
        assert!(error.to_string().contains("request-local"), "{error}");
        assert!(decode_atom("unknown", None, Some("dynamic_field_write".into()), None).is_err());
    }

    #[test]
    fn root_result_collision_is_rejected_and_corruption_is_repairable() {
        let store = store_with_blob();
        let expected = result(1);
        store
            .publish_finding_free_class_set_root_result(expected.clone(), &CancellationToken::new())
            .unwrap();

        let mut collision_rows = expected.rows.clone();
        collision_rows[0].member = "different".into();
        let collision = FindingFreeClassSetRootResult::try_new(
            expected.key.clone(),
            expected.attachment.clone(),
            collision_rows,
        )
        .unwrap();
        assert!(
            store
                .publish_finding_free_class_set_root_result(collision, &CancellationToken::new(),)
                .is_err(),
            "one exact key cannot silently change its complete projection"
        );

        store
            .conn
            .lock()
            .unwrap()
            .execute_batch(
                "PRAGMA ignore_check_constraints=ON;
                 UPDATE class_set_finding_free_root_results SET content_digest=zeroblob(31);
                 PRAGMA ignore_check_constraints=OFF;",
            )
            .unwrap();
        assert_eq!(
            load(&store, &expected.key).unwrap(),
            ClassSetRootResultLookup::Rejected(ClassSetRootResultRejection::Validation)
        );
        assert!(
            store
                .publish_finding_free_class_set_root_result(
                    expected.clone(),
                    &CancellationToken::new(),
                )
                .unwrap(),
            "publication repairs only the exact invalid result"
        );
        assert_eq!(
            load(&store, &expected.key).unwrap(),
            ClassSetRootResultLookup::Hit(Box::new(expected))
        );
    }

    #[test]
    fn corrupt_declared_sizes_reject_before_invalid_header_or_child_text_is_hydrated() {
        let header_store = store_with_blob();
        let header_result = result(1);
        header_store
            .publish_finding_free_class_set_root_result(
                header_result.clone(),
                &CancellationToken::new(),
            )
            .unwrap();
        header_store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE class_set_finding_free_root_results
                 SET owner_rel_path=CAST(X'80' AS TEXT),payload_text_bytes=0",
                [],
            )
            .unwrap();
        assert_eq!(
            load(&header_store, &header_result.key).unwrap(),
            ClassSetRootResultLookup::Rejected(ClassSetRootResultRejection::Validation),
            "the owner length is rejected before rusqlite tries to decode its invalid UTF-8"
        );

        let child_store = store_with_blob();
        let child_result = result(1);
        child_store
            .publish_finding_free_class_set_root_result(
                child_result.clone(),
                &CancellationToken::new(),
            )
            .unwrap();
        child_store
            .conn
            .lock()
            .unwrap()
            .execute_batch(
                "UPDATE class_set_finding_free_root_results
                   SET payload_text_bytes=length(CAST(owner_rel_path AS BLOB)) + 40;
                 UPDATE class_set_finding_free_root_rows
                   SET member=CAST(X'80' AS TEXT) WHERE row_ordinal=0;",
            )
            .unwrap();
        assert_eq!(
            load(&child_store, &child_result.key).unwrap(),
            ClassSetRootResultLookup::Rejected(ClassSetRootResultRejection::Validation),
            "a child length beyond the declared remainder is rejected before text decoding"
        );
    }

    #[test]
    fn idempotent_publication_checks_cancellation_immediately_before_commit() {
        let store = store_with_blob();
        let expected = result(1);
        store
            .publish_finding_free_class_set_root_result(expected.clone(), &CancellationToken::new())
            .unwrap();

        // Two canonicalization passes over two rows plus the header/transaction
        // checks leave this cancellation for the idempotent commit boundary.
        let cancellation = CancellationToken::cancel_after_checks_for_test(22);
        assert!(
            store
                .publish_finding_free_class_set_root_result(expected.clone(), &cancellation)
                .is_err()
        );
        assert!(cancellation.is_cancelled());
        assert_eq!(
            load(&store, &expected.key).unwrap(),
            ClassSetRootResultLookup::Hit(Box::new(expected))
        );
    }

    #[test]
    fn owner_deletion_cascades_and_generations_are_retained_per_language() {
        let store = store_with_blob();
        let first = result(1);
        for seed in 1..=9 {
            store
                .publish_finding_free_class_set_root_result(result(seed), &CancellationToken::new())
                .unwrap();
        }
        let conn = store.conn.lock().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM class_set_root_result_generations",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            8
        );
        drop(conn);
        assert_eq!(
            load(&store, &first.key).unwrap(),
            ClassSetRootResultLookup::Miss
        );

        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM blobs WHERE blob_oid=?1 AND lang='python'",
                params![BLOB],
            )
            .unwrap();
        assert_eq!(
            load(&store, &result(9).key).unwrap(),
            ClassSetRootResultLookup::Miss
        );
    }

    #[test]
    fn operational_failures_and_cancellation_remain_distinct_from_rejections() {
        let store = store_with_blob();
        let expected = result(1);
        store.set_class_set_root_result_operational_failure_for_test(true);
        assert!(load(&store, &expected.key).is_err());
        assert!(
            store
                .publish_finding_free_class_set_root_result(
                    expected.clone(),
                    &CancellationToken::new(),
                )
                .is_err()
        );
        store.set_class_set_root_result_operational_failure_for_test(false);

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            store
                .publish_finding_free_class_set_root_result(expected, &cancelled)
                .is_err()
        );
        let conn = store.conn.lock().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM class_set_finding_free_root_results",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn cancellation_rolls_back_partial_publication_and_read_hydration() {
        let store = store_with_blob();
        let expected = result_with_rows(64);
        let cancellation = CancellationToken::cancel_after_checks_for_test(3 * 64 + 8);
        assert!(
            store
                .publish_finding_free_class_set_root_result(expected.clone(), &cancellation)
                .is_err()
        );
        assert_eq!(
            store
                .conn
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM class_set_finding_free_root_results",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "the immediate transaction rolls back its header and inserted children"
        );

        store
            .publish_finding_free_class_set_root_result(expected.clone(), &CancellationToken::new())
            .unwrap();
        let cancellation = CancellationToken::cancel_after_checks_for_test(8);
        assert!(
            store
                .finding_free_class_set_root_result(
                    &expected.key,
                    MAX_CLASS_SET_ROOT_ROWS,
                    MAX_CLASS_SET_ROOT_RETAINED_BYTES,
                    &cancellation,
                )
                .is_err()
        );
        assert_eq!(
            load(&store, &expected.key).unwrap(),
            ClassSetRootResultLookup::Hit(Box::new(expected)),
            "a cancelled read never mutates the complete row set"
        );
    }

    #[test]
    fn concurrent_same_key_publications_expose_one_complete_result() {
        let store = Arc::new(store_with_blob());
        let expected = result(1);
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let expected = expected.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                store
                    .publish_finding_free_class_set_root_result(expected, &CancellationToken::new())
                    .unwrap()
            }));
        }
        barrier.wait();
        let published = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|published| *published)
            .count();
        assert_eq!(published, 1);
        assert_eq!(
            load(&store, &expected.key).unwrap(),
            ClassSetRootResultLookup::Hit(Box::new(expected))
        );
    }

    #[test]
    fn root_result_queries_seek_persisted_indexes() {
        for state in PlannerStatisticsState::BOTH {
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().unwrap();
            state.install(&conn);
            for (name, expected) in [
                (
                    "class_set_root_result_header",
                    "sqlite_autoindex_class_set_root_result_generations_1",
                ),
                ("class_set_root_result_rows", "USING PRIMARY KEY"),
                (
                    "prune_old_class_set_root_result_generations",
                    "class_set_root_result_generations_recent",
                ),
            ] {
                let plan = explain_pin(&conn, &pinned(name));
                assert!(
                    plan.iter().any(|detail| detail.contains(expected)),
                    "{state} {name}: {plan:#?}"
                );
                assert!(
                    plan.iter().all(|detail| {
                        !detail.contains("AUTOMATIC")
                            && !detail.contains("TEMP B-TREE")
                            && !detail.contains("CO-ROUTINE")
                            && !detail.contains("SCAN ")
                    }),
                    "{state} {name}: {plan:#?}"
                );
            }
        }
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn test_support_snapshot_and_mutations_use_stable_complete_rows() {
        let store = store_with_blob();
        let expected = result(1);
        store
            .publish_finding_free_class_set_root_result(expected.clone(), &CancellationToken::new())
            .unwrap();
        let before = store
            .class_set_root_result_store_snapshot_for_test()
            .unwrap();
        assert_eq!(before.generations.len(), 1);
        assert_eq!(before.results.len(), 1);
        assert_eq!(before.results[0].result, expected);
        assert_eq!(
            before,
            store
                .class_set_root_result_store_snapshot_for_test()
                .unwrap()
        );

        store
            .corrupt_only_class_set_root_result_content_digest_for_test()
            .unwrap();
        assert_eq!(
            load(&store, &expected.key).unwrap(),
            ClassSetRootResultLookup::Rejected(ClassSetRootResultRejection::Validation)
        );

        let oversize_store = store_with_blob();
        oversize_store
            .publish_finding_free_class_set_root_result(expected.clone(), &CancellationToken::new())
            .unwrap();
        oversize_store
            .oversize_only_class_set_root_result_row_count_for_test()
            .unwrap();
        assert_eq!(
            load(&oversize_store, &expected.key).unwrap(),
            ClassSetRootResultLookup::Rejected(ClassSetRootResultRejection::ResourceBound)
        );
    }
}
