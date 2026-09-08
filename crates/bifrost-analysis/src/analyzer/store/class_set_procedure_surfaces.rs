//! Complete local structural certificates for persisted class-set summaries.
//!
//! A surface is deliberately local: it records one exact procedure's call
//! coverage, directed entered targets, lexical children, and dispatch reads,
//! but never hashes a child's surface. That makes the contract usable for
//! recursive call graphs while still letting a reader traverse and replay the
//! exact graph under its own bounds.

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use super::class_set_summaries::ClassSetSummaryDigest;
use super::read_keys::{ReadKeyColumns, decode_read_key};
use super::{AnalyzerStore, PARSED_BLOB_COMPLETE_CONDITION, Result, StoreError};
use crate::CancellationToken;
use crate::analyzer::Language;
use crate::analyzer::read_ledger::{LookupKind, LookupQuestion, ReadKey};
use crate::analyzer::semantic::{CandidateCoverage, SemanticCapability};
use crate::hash::HashSet;

pub const MAX_CLASS_SET_SURFACE_CALLS: usize = 100_000;
pub const MAX_CLASS_SET_SURFACE_BINDINGS: usize = 1_000_000;
pub const MAX_CLASS_SET_SURFACE_ENTERED: usize = 1_000_000;
pub const MAX_CLASS_SET_SURFACE_LEXICAL_CHILDREN: usize = 100_000;
pub const MAX_CLASS_SET_SURFACE_READS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetProcedureSurfaceKey {
    pub procedure_lineage: ClassSetSummaryDigest,
    pub owner_rel_path: String,
    pub language: Language,
    pub schema_version: u32,
    pub local_structure_digest: ClassSetSummaryDigest,
    pub behavior_read_digest: ClassSetSummaryDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClassSetProcedureIdentityRow {
    pub procedure_lineage: ClassSetSummaryDigest,
    pub rel_path: String,
    pub language: Language,
    pub artifact_public_identity: ClassSetSummaryDigest,
    pub artifact_content_identity: ClassSetSummaryDigest,
    pub local_structure_digest: ClassSetSummaryDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClassSetProcedureSurfaceStatusRow {
    Complete,
    Ambiguous,
    Unknown,
    Unsupported { capability: SemanticCapability },
    Unproven,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassSetProcedureSurfaceDispatchRow {
    Resolved {
        status: ClassSetProcedureSurfaceStatusRow,
        coverage: CandidateCoverage,
    },
    Unavailable {
        status: ClassSetProcedureSurfaceStatusRow,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetProcedureSurfaceCallRow {
    /// The artifact-local `CallSiteId` ordinal. Call ids are unique but need
    /// not be dense in a projected procedure surface.
    pub call_ordinal: u32,
    pub has_uncovered_boundary: bool,
    pub truncated: bool,
    pub complete_receiver_hint_refinable: bool,
    pub dispatch: ClassSetProcedureSurfaceDispatchRow,
    /// One answered status for every in-mount dispatch candidate, including
    /// candidates whose semantic outcome did not yield an available binding.
    pub binding_statuses: Vec<ClassSetProcedureSurfaceStatusRow>,
    /// Targets whose answered binding was available, in deterministic entered
    /// order. This is intentionally separate from `binding_statuses`: the two
    /// lists need not have equal length.
    pub entered: Vec<ClassSetProcedureIdentityRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetProcedureSurfaceHeaderRow {
    pub key: ClassSetProcedureSurfaceKey,
    pub owner_blob_oid: String,
    pub artifact_public_identity: ClassSetSummaryDigest,
    pub artifact_content_identity: ClassSetSummaryDigest,
    /// Exact provider behavior that produced this certificate. This is replay
    /// provenance rather than semantic surface identity: an equal canonical
    /// surface may refresh it in place when current behavior is revalidated.
    pub exact_behavior_digest: ClassSetSummaryDigest,
    pub carrier_semantics_digest: ClassSetSummaryDigest,
    /// Existing class-set procedure contract over call coverage and entered
    /// lineage identities. Replay of this opaque digest certifies consumers
    /// that still use that established key recipe.
    pub direct_calls_digest: ClassSetSummaryDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetProcedureSurfaceRow {
    pub header: ClassSetProcedureSurfaceHeaderRow,
    pub calls: Vec<ClassSetProcedureSurfaceCallRow>,
    pub lexical_children: Vec<ClassSetProcedureIdentityRow>,
    pub reads: Vec<ReadKey>,
    surface_digest: ClassSetSummaryDigest,
    exact_provenance_digest: ClassSetSummaryDigest,
}

/// Lightweight candidate returned by compatible-family discovery. Child rows
/// are loaded only after the caller has reserved validation work and selected
/// this digest for replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetProcedureSurfaceCandidateRow {
    pub surface_digest: ClassSetSummaryDigest,
    pub exact_provenance_digest: ClassSetSummaryDigest,
    pub header: ClassSetProcedureSurfaceHeaderRow,
    pub call_count: usize,
    pub binding_count: usize,
    pub entered_count: usize,
    pub lexical_child_count: usize,
    pub read_count: usize,
}

impl ClassSetProcedureSurfaceRow {
    pub fn try_new(
        header: ClassSetProcedureSurfaceHeaderRow,
        mut calls: Vec<ClassSetProcedureSurfaceCallRow>,
        mut lexical_children: Vec<ClassSetProcedureIdentityRow>,
        mut reads: Vec<ReadKey>,
    ) -> Result<Self> {
        if header.key.schema_version == 0 {
            return Err(StoreError::new(
                "class-set procedure surface schema version is zero",
            ));
        }
        require_identity_fields(
            header.key.owner_rel_path.as_str(),
            header.key.language,
            "surface owner",
        )?;
        if header.owner_blob_oid.is_empty() {
            return Err(StoreError::new(
                "class-set procedure surface owner blob is empty",
            ));
        }

        calls.sort_unstable_by_key(|call| call.call_ordinal);
        if calls
            .windows(2)
            .any(|rows| rows[0].call_ordinal == rows[1].call_ordinal)
        {
            return Err(StoreError::new(
                "class-set procedure surface duplicates a call site",
            ));
        }
        let mut binding_count = 0usize;
        let mut entered_count = 0usize;
        for call in &calls {
            if call.truncated
                || matches!(
                    call.dispatch,
                    ClassSetProcedureSurfaceDispatchRow::Resolved {
                        coverage: CandidateCoverage::Truncated,
                        ..
                    }
                )
            {
                return Err(StoreError::new(
                    "class-set procedure surface contains truncated call coverage",
                ));
            }
            if call.entered.len() > call.binding_statuses.len()
                || matches!(
                    call.dispatch,
                    ClassSetProcedureSurfaceDispatchRow::Unavailable { .. }
                ) && (!call.binding_statuses.is_empty() || !call.entered.is_empty())
            {
                return Err(StoreError::new(
                    "class-set procedure surface call binding and entered shape disagrees",
                ));
            }
            binding_count = binding_count
                .checked_add(call.binding_statuses.len())
                .ok_or_else(|| {
                    StoreError::new("class-set procedure surface binding count overflow")
                })?;
            entered_count = entered_count
                .checked_add(call.entered.len())
                .ok_or_else(|| {
                    StoreError::new("class-set procedure surface entered count overflow")
                })?;
            for entered in &call.entered {
                require_identity(entered, "entered target")?;
            }
        }

        lexical_children
            .sort_unstable_by(|left, right| semantic_identity(left).cmp(&semantic_identity(right)));
        if lexical_children
            .windows(2)
            .any(|rows| semantic_identity(&rows[0]) == semantic_identity(&rows[1]))
        {
            return Err(StoreError::new(
                "class-set procedure surface duplicates a lexical child",
            ));
        }
        for child in &lexical_children {
            require_identity(child, "lexical child")?;
        }

        reads.sort_unstable();
        let mut read_keys = HashSet::default();
        for read in &reads {
            if !matches!(
                read,
                ReadKey::Lookup {
                    kind: LookupKind::ProcedureDispatch,
                    question: LookupQuestion::ProcedureCallSite { .. },
                    ..
                }
            ) {
                return Err(StoreError::new(
                    "class-set procedure surface contains a non-procedure-dispatch read",
                ));
            }
            if !read_keys.insert(*read.canonical_digest().as_bytes()) {
                return Err(StoreError::new(
                    "class-set procedure surface duplicates a dispatch read",
                ));
            }
        }
        validate_counts(
            calls.len(),
            binding_count,
            entered_count,
            lexical_children.len(),
            reads.len(),
        )?;

        let mut row = Self {
            header,
            calls,
            lexical_children,
            reads,
            surface_digest: [0; 32],
            exact_provenance_digest: [0; 32],
        };
        row.surface_digest = row.canonical_surface_digest();
        row.exact_provenance_digest = row.canonical_exact_provenance_digest();
        Ok(row)
    }

    pub const fn surface_digest(&self) -> &ClassSetSummaryDigest {
        &self.surface_digest
    }

    pub const fn exact_provenance_digest(&self) -> &ClassSetSummaryDigest {
        &self.exact_provenance_digest
    }

    /// Validate the exact replay provenance retained at construction time.
    /// Runtime repositories call this before trusting a surface that could
    /// have been mutated after construction.
    pub fn has_valid_exact_provenance(&self) -> bool {
        self.exact_provenance_digest == self.canonical_exact_provenance_digest()
    }

    pub fn canonical_surface_digest(&self) -> ClassSetSummaryDigest {
        let mut hash = SurfaceDigest::new(b"bifrost-class-set-procedure-surface-v1");
        let key = &self.header.key;
        hash.bytes(&key.procedure_lineage);
        hash.text(&key.owner_rel_path);
        hash.text(key.language.config_label());
        hash.u64(u64::from(key.schema_version));
        hash.bytes(&key.local_structure_digest);
        hash.bytes(&key.behavior_read_digest);
        hash.bytes(&self.header.carrier_semantics_digest);
        hash.bytes(&self.header.direct_calls_digest);
        hash.u64(self.calls.len() as u64);
        for call in &self.calls {
            hash.u64(u64::from(call.call_ordinal));
            hash.tag(u8::from(call.has_uncovered_boundary));
            hash.tag(u8::from(call.truncated));
            hash.tag(u8::from(call.complete_receiver_hint_refinable));
            match call.dispatch {
                ClassSetProcedureSurfaceDispatchRow::Resolved { status, coverage } => {
                    hash.text("resolved");
                    hash.status(status);
                    hash.text(coverage.label());
                }
                ClassSetProcedureSurfaceDispatchRow::Unavailable { status } => {
                    hash.text("unavailable");
                    hash.status(status);
                }
            }
            hash.u64(call.binding_statuses.len() as u64);
            for status in &call.binding_statuses {
                hash.status(*status);
            }
            hash.u64(call.entered.len() as u64);
            for entered in &call.entered {
                hash.identity(entered);
            }
        }
        hash.u64(self.lexical_children.len() as u64);
        for child in &self.lexical_children {
            hash.identity(child);
        }
        hash.u64(self.reads.len() as u64);
        for read in &self.reads {
            hash.bytes(read.canonical_digest().as_bytes());
        }
        hash.finish()
    }

    fn canonical_exact_provenance_digest(&self) -> ClassSetSummaryDigest {
        let mut hash = SurfaceDigest::new(b"bifrost-class-set-procedure-surface-provenance-v1");
        hash.bytes(&self.canonical_surface_digest());
        hash.bytes(&self.header.exact_behavior_digest);
        hash.bytes(&self.header.artifact_public_identity);
        hash.bytes(&self.header.artifact_content_identity);
        hash.u64(self.calls.len() as u64);
        for call in &self.calls {
            hash.u64(u64::from(call.call_ordinal));
            hash.u64(call.entered.len() as u64);
            for (ordinal, entered) in call.entered.iter().enumerate() {
                hash.u64(ordinal as u64);
                hash.identity(entered);
                hash.bytes(&entered.artifact_public_identity);
                hash.bytes(&entered.artifact_content_identity);
            }
        }
        hash.u64(self.lexical_children.len() as u64);
        for (ordinal, child) in self.lexical_children.iter().enumerate() {
            hash.u64(ordinal as u64);
            hash.identity(child);
            hash.bytes(&child.artifact_public_identity);
            hash.bytes(&child.artifact_content_identity);
        }
        hash.finish()
    }

    fn has_same_semantic_surface(&self, other: &Self) -> bool {
        self.header.key == other.header.key
            && self.header.carrier_semantics_digest == other.header.carrier_semantics_digest
            && self.header.direct_calls_digest == other.header.direct_calls_digest
            && self.calls.len() == other.calls.len()
            && self.calls.iter().zip(&other.calls).all(|(left, right)| {
                left.call_ordinal == right.call_ordinal
                    && left.has_uncovered_boundary == right.has_uncovered_boundary
                    && left.truncated == right.truncated
                    && left.complete_receiver_hint_refinable
                        == right.complete_receiver_hint_refinable
                    && left.dispatch == right.dispatch
                    && left.binding_statuses == right.binding_statuses
                    && left.entered.len() == right.entered.len()
                    && left
                        .entered
                        .iter()
                        .zip(&right.entered)
                        .all(|(left, right)| semantic_identity(left) == semantic_identity(right))
            })
            && self.lexical_children.len() == other.lexical_children.len()
            && self
                .lexical_children
                .iter()
                .zip(&other.lexical_children)
                .all(|(left, right)| semantic_identity(left) == semantic_identity(right))
            && self.reads == other.reads
    }
}

fn semantic_identity(
    identity: &ClassSetProcedureIdentityRow,
) -> (&ClassSetSummaryDigest, &str, &str, &ClassSetSummaryDigest) {
    (
        &identity.procedure_lineage,
        identity.rel_path.as_str(),
        identity.language.config_label(),
        &identity.local_structure_digest,
    )
}

fn require_identity(identity: &ClassSetProcedureIdentityRow, label: &str) -> Result<()> {
    require_identity_fields(&identity.rel_path, identity.language, label)
}

fn require_identity_fields(rel_path: &str, language: Language, label: &str) -> Result<()> {
    if rel_path.is_empty() || language == Language::None {
        return Err(StoreError::new(format!(
            "class-set procedure surface {label} has an invalid path or language"
        )));
    }
    Ok(())
}

fn validate_counts(
    calls: usize,
    bindings: usize,
    entered: usize,
    lexical: usize,
    reads: usize,
) -> Result<()> {
    for (actual, limit, label) in [
        (calls, MAX_CLASS_SET_SURFACE_CALLS, "call"),
        (bindings, MAX_CLASS_SET_SURFACE_BINDINGS, "binding"),
        (entered, MAX_CLASS_SET_SURFACE_ENTERED, "entered"),
        (
            lexical,
            MAX_CLASS_SET_SURFACE_LEXICAL_CHILDREN,
            "lexical child",
        ),
        (reads, MAX_CLASS_SET_SURFACE_READS, "read"),
    ] {
        if actual > limit {
            return Err(StoreError::new(format!(
                "class-set procedure surface {label} count {actual} exceeds {limit}"
            )));
        }
    }
    Ok(())
}

struct SurfaceDigest(Sha256);

impl SurfaceDigest {
    fn new(domain: &[u8]) -> Self {
        let mut hash = Self(Sha256::new());
        hash.bytes(domain);
        hash
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
    fn status(&mut self, status: ClassSetProcedureSurfaceStatusRow) {
        let (label, capability) = status_columns(status);
        self.text(label);
        match capability {
            Some(capability) => {
                self.tag(1);
                self.text(capability);
            }
            None => self.tag(0),
        }
    }
    fn identity(&mut self, identity: &ClassSetProcedureIdentityRow) {
        self.bytes(&identity.procedure_lineage);
        self.text(&identity.rel_path);
        self.text(identity.language.config_label());
        self.bytes(&identity.local_structure_digest);
    }
    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

pub(crate) static CLASS_SET_PROCEDURE_SURFACE_FAMILY_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{} ORDER BY surfaces.surface_digest LIMIT ?7",
        surface_select_sql(
            "surfaces.procedure_lineage=?1 AND surfaces.owner_rel_path=?2 AND surfaces.lang=?3
         AND surfaces.schema_version=?4 AND surfaces.local_structure_digest=?5
         AND surfaces.behavior_read_digest=?6",
            true,
        )
    )
});

pub(crate) static CLASS_SET_PROCEDURE_SURFACE_DIGEST_SQL: LazyLock<String> =
    LazyLock::new(|| surface_select_sql("surfaces.surface_digest=?1", true));
static CLASS_SET_PROCEDURE_SURFACE_PHYSICAL_DIGEST_SQL: LazyLock<String> =
    LazyLock::new(|| surface_select_sql("surfaces.surface_digest=?1", false));

fn surface_select_sql(predicate: &str, require_complete: bool) -> String {
    let (meta_join, completion) = if require_complete {
        (
            "JOIN blob_meta AS meta ON meta.blob_id=blobs.id",
            format!(" AND {PARSED_BLOB_COMPLETE_CONDITION}"),
        )
    } else {
        ("", String::new())
    };
    format!(
        "SELECT surfaces.surface_id, surfaces.surface_digest, surfaces.procedure_lineage,
                surfaces.owner_rel_path, blobs.blob_oid, surfaces.lang,
                surfaces.artifact_public_identity, surfaces.artifact_content_identity,
                surfaces.schema_version, surfaces.local_structure_digest,
                surfaces.behavior_read_digest, surfaces.exact_behavior_digest,
                surfaces.exact_provenance_digest, surfaces.carrier_semantics_digest,
                surfaces.direct_calls_digest,
                surfaces.call_count, surfaces.binding_count, surfaces.entered_count,
                surfaces.lexical_child_count,
                surfaces.read_count
         FROM class_set_procedure_surfaces AS surfaces
         JOIN blobs ON blobs.id=surfaces.owner_blob_id AND blobs.lang=surfaces.lang
         {meta_join}
         WHERE {predicate}{completion}"
    )
}

pub(crate) const SURFACE_CALLS_SQL: &str =
    "SELECT call_ordinal,has_uncovered_boundary,truncated,complete_receiver_hint_refinable,
            dispatch_kind,dispatch_status,dispatch_capability,dispatch_coverage,
            binding_count,entered_count
     FROM class_set_procedure_surface_calls WHERE surface_id=?1 ORDER BY call_ordinal LIMIT ?2";
pub(crate) const SURFACE_BINDINGS_SQL: &str =
    "SELECT call_ordinal,binding_ordinal,binding_status,binding_capability
     FROM class_set_procedure_surface_bindings WHERE surface_id=?1
     ORDER BY call_ordinal,binding_ordinal LIMIT ?2";
pub(crate) const SURFACE_ENTERED_SQL: &str =
    "SELECT call_ordinal,entered_ordinal,target_procedure_lineage,target_rel_path,target_lang,
            target_artifact_public_identity,target_artifact_content_identity,
            target_local_structure_digest
     FROM class_set_procedure_surface_entered WHERE surface_id=?1
     ORDER BY call_ordinal,entered_ordinal LIMIT ?2";
pub(crate) const SURFACE_LEXICAL_CHILDREN_SQL: &str =
    "SELECT child_ordinal,child_procedure_lineage,child_rel_path,child_lang,
            child_artifact_public_identity,child_artifact_content_identity
            ,child_local_structure_digest
     FROM class_set_procedure_surface_lexical_children
     WHERE surface_id=?1 ORDER BY child_ordinal LIMIT ?2";
pub(crate) const SURFACE_READS_SQL: &str =
    "SELECT key_digest,kind,family,languages,rel_path,name,index_key,blob_oid,subject,
            start_byte,end_byte,digest,read_ordinal
     FROM class_set_procedure_surface_reads WHERE surface_id=?1 ORDER BY read_ordinal LIMIT ?2";

impl AnalyzerStore {
    pub fn publish_class_set_procedure_surface(
        &self,
        surface: ClassSetProcedureSurfaceRow,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        validate_surface_for_publication(&surface, cancellation)?;
        self.conn.execute({
            let cancellation = cancellation.clone();
            move |conn| {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                ensure_not_cancelled(&cancellation)?;
                let blob_id = live_owner_blob_id(&tx, &surface)?;
                if let Some(existing) =
                    load_physical_surface_for_digest(&tx, surface.surface_digest)?
                {
                    if existing == surface {
                        tx.commit()?;
                        return Ok(false);
                    }
                    if !existing.has_same_semantic_surface(&surface) {
                        return Err(StoreError::new(
                            "class-set procedure surface digest names different content",
                        ));
                    }
                    refresh_surface_provenance(&tx, &surface, blob_id, &cancellation)?;
                    tx.commit()?;
                    return Ok(false);
                }
                tx.execute(
                    "DELETE FROM class_set_procedure_surfaces WHERE surface_digest=?1",
                    params![surface.surface_digest.as_slice()],
                )?;
                insert_surface(&tx, &surface, blob_id, &cancellation)?;
                ensure_not_cancelled(&cancellation)?;
                tx.commit()?;
                Ok(true)
            }
        })
    }

    /// Load one bounded compatible family. `None` means more than `max_rows`
    /// candidates exist; callers must not treat the returned prefix as a
    /// complete set from which replay can select a current surface.
    pub fn class_set_procedure_surface_candidates(
        &self,
        key: &ClassSetProcedureSurfaceKey,
        max_rows: usize,
    ) -> Result<Option<Vec<ClassSetProcedureSurfaceCandidateRow>>> {
        let limit = i64::try_from(max_rows.saturating_add(1))
            .map_err(|_| StoreError::new("class-set procedure surface family limit exceeds i64"))?;
        let mut conn = self.read_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let raws = {
            let mut statement =
                tx.prepare_cached(CLASS_SET_PROCEDURE_SURFACE_FAMILY_SQL.as_str())?;
            let rows = statement.query_map(
                params![
                    key.procedure_lineage.as_slice(),
                    &key.owner_rel_path,
                    key.language.config_label(),
                    key.schema_version,
                    key.local_structure_digest.as_slice(),
                    key.behavior_read_digest.as_slice(),
                    limit,
                ],
                raw_surface_from_row,
            )?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        if raws.len() > max_rows {
            tx.commit()?;
            return Ok(None);
        }
        let rows = raws
            .into_iter()
            .map(surface_candidate)
            .collect::<Result<Vec<_>>>()?;
        tx.commit()?;
        Ok(Some(rows))
    }

    pub fn class_set_procedure_surface_for_digest(
        &self,
        digest: ClassSetSummaryDigest,
    ) -> Result<Option<ClassSetProcedureSurfaceRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let row = load_surface_for_digest(&tx, digest)?;
        tx.commit()?;
        Ok(row)
    }
}

fn surface_candidate(raw: RawSurface) -> Result<ClassSetProcedureSurfaceCandidateRow> {
    let (
        _,
        surface_digest,
        lineage,
        rel_path,
        blob_oid,
        lang,
        artifact_public,
        artifact_content,
        schema,
        local_structure,
        behavior,
        exact_behavior,
        exact_provenance,
        carrier_semantics,
        direct_calls,
        call_count,
        binding_count,
        entered_count,
        lexical_child_count,
        read_count,
    ) = raw;
    validate_counts(
        call_count,
        binding_count,
        entered_count,
        lexical_child_count,
        read_count,
    )?;
    Ok(ClassSetProcedureSurfaceCandidateRow {
        surface_digest: digest(surface_digest, "surface digest")?,
        exact_provenance_digest: digest(exact_provenance, "exact provenance digest")?,
        header: ClassSetProcedureSurfaceHeaderRow {
            key: ClassSetProcedureSurfaceKey {
                procedure_lineage: digest(lineage, "procedure lineage")?,
                owner_rel_path: rel_path,
                language: decode_language(&lang)?,
                schema_version: schema,
                local_structure_digest: digest(local_structure, "local structure digest")?,
                behavior_read_digest: digest(behavior, "behavior read digest")?,
            },
            owner_blob_oid: blob_oid,
            artifact_public_identity: digest(artifact_public, "artifact public identity")?,
            artifact_content_identity: digest(artifact_content, "artifact content identity")?,
            exact_behavior_digest: digest(exact_behavior, "exact behavior digest")?,
            carrier_semantics_digest: digest(carrier_semantics, "carrier semantics digest")?,
            direct_calls_digest: digest(direct_calls, "direct calls digest")?,
        },
        call_count,
        binding_count,
        entered_count,
        lexical_child_count,
        read_count,
    })
}

fn validate_surface_for_publication(
    surface: &ClassSetProcedureSurfaceRow,
    cancellation: &CancellationToken,
) -> Result<()> {
    if surface.surface_digest != surface.canonical_surface_digest() {
        return Err(StoreError::new(
            "class-set procedure surface changed after canonical construction",
        ));
    }
    if !surface.has_valid_exact_provenance() {
        return Err(StoreError::new(
            "class-set procedure surface exact provenance changed after canonical construction",
        ));
    }
    ensure_not_cancelled(cancellation)
}

fn ensure_not_cancelled(cancellation: &CancellationToken) -> Result<()> {
    if cancellation.is_cancelled() {
        Err(StoreError::new(
            "class-set procedure surface publication cancelled",
        ))
    } else {
        Ok(())
    }
}

fn live_owner_blob_id(
    conn: &rusqlite::Connection,
    surface: &ClassSetProcedureSurfaceRow,
) -> Result<i64> {
    let key = &surface.header.key;
    conn.query_row(
        &format!(
            "SELECT meta.blob_id FROM blob_meta AS meta
             JOIN blobs ON blobs.id=meta.blob_id
             WHERE blobs.blob_oid=?1 AND blobs.lang=?2 AND {PARSED_BLOB_COMPLETE_CONDITION}"
        ),
        params![surface.header.owner_blob_oid, key.language.config_label()],
        |row| row.get(0),
    )
    .optional()?
    .ok_or_else(|| StoreError::new("class-set procedure surface owner blob is absent"))
}

fn load_surface_for_digest(
    conn: &rusqlite::Connection,
    digest: ClassSetSummaryDigest,
) -> Result<Option<ClassSetProcedureSurfaceRow>> {
    let raw = load_raw_surface(
        conn,
        CLASS_SET_PROCEDURE_SURFACE_DIGEST_SQL.as_str(),
        params![digest.as_slice()],
    )?;
    raw.map(|raw| load_surface(conn, raw)).transpose()
}

fn load_physical_surface_for_digest(
    conn: &rusqlite::Connection,
    digest: ClassSetSummaryDigest,
) -> Result<Option<ClassSetProcedureSurfaceRow>> {
    let raw = load_raw_surface(
        conn,
        CLASS_SET_PROCEDURE_SURFACE_PHYSICAL_DIGEST_SQL.as_str(),
        params![digest.as_slice()],
    )?;
    raw.map(|raw| load_surface(conn, raw)).transpose()
}

type RawSurface = (
    i64,
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    u32,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    usize,
    usize,
    usize,
    usize,
    usize,
);

fn load_raw_surface(
    conn: &rusqlite::Connection,
    sql: &str,
    parameters: impl rusqlite::Params,
) -> Result<Option<RawSurface>> {
    conn.query_row(sql, parameters, raw_surface_from_row)
        .optional()
        .map_err(StoreError::from)
}

fn raw_surface_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawSurface> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
        row.get(17)?,
        row.get(18)?,
        row.get(19)?,
    ))
}

fn load_surface(
    conn: &rusqlite::Connection,
    raw: RawSurface,
) -> Result<ClassSetProcedureSurfaceRow> {
    let (
        id,
        stored_digest,
        lineage,
        rel_path,
        blob_oid,
        lang,
        artifact_public,
        artifact_content,
        schema,
        local_structure,
        behavior,
        exact_behavior,
        exact_provenance,
        carrier_semantics,
        direct_calls,
        call_count,
        binding_count,
        entered_count,
        lexical_count,
        read_count,
    ) = raw;
    validate_counts(
        call_count,
        binding_count,
        entered_count,
        lexical_count,
        read_count,
    )?;
    let language = decode_language(&lang)?;
    let mut calls = load_calls(conn, id, call_count)?;
    let bindings = load_bindings(conn, id, binding_count)?;
    for (call_ordinal, statuses) in bindings {
        let call = calls
            .iter_mut()
            .find(|call| call.row.call_ordinal == call_ordinal)
            .ok_or_else(|| {
                StoreError::new("class-set procedure surface binding row references an absent call")
            })?;
        if statuses.len() != call.expected_bindings {
            return Err(StoreError::new(
                "class-set procedure surface per-call binding count disagrees",
            ));
        }
        call.row.binding_statuses = statuses;
    }
    let entered = load_entered(conn, id, entered_count)?;
    for (call_ordinal, rows) in entered {
        let call = calls
            .iter_mut()
            .find(|call| call.row.call_ordinal == call_ordinal)
            .ok_or_else(|| {
                StoreError::new("class-set procedure surface entered row references an absent call")
            })?;
        if rows.len() != call.expected_entered {
            return Err(StoreError::new(
                "class-set procedure surface per-call entered count disagrees",
            ));
        }
        call.row.entered = rows;
    }
    if calls.iter().any(|call| {
        call.expected_bindings != call.row.binding_statuses.len()
            || call.expected_entered != call.row.entered.len()
    }) {
        return Err(StoreError::new(
            "class-set procedure surface per-call child rows are absent",
        ));
    }
    let calls = calls.into_iter().map(|call| call.row).collect::<Vec<_>>();
    let lexical = load_lexical_children(conn, id, lexical_count)?;
    let reads = load_reads(conn, id, read_count)?;
    let actual_entered = calls.iter().map(|call| call.entered.len()).sum::<usize>();
    let actual_bindings = calls
        .iter()
        .map(|call| call.binding_statuses.len())
        .sum::<usize>();
    if [
        calls.len(),
        actual_bindings,
        actual_entered,
        lexical.len(),
        reads.len(),
    ] != [
        call_count,
        binding_count,
        entered_count,
        lexical_count,
        read_count,
    ] {
        return Err(StoreError::new(
            "class-set procedure surface child counts disagree",
        ));
    }
    let row = ClassSetProcedureSurfaceRow::try_new(
        ClassSetProcedureSurfaceHeaderRow {
            key: ClassSetProcedureSurfaceKey {
                procedure_lineage: digest(lineage, "procedure lineage")?,
                owner_rel_path: rel_path,
                language,
                schema_version: schema,
                local_structure_digest: digest(local_structure, "local structure digest")?,
                behavior_read_digest: digest(behavior, "behavior read digest")?,
            },
            owner_blob_oid: blob_oid,
            artifact_public_identity: digest(artifact_public, "artifact public identity")?,
            artifact_content_identity: digest(artifact_content, "artifact content identity")?,
            exact_behavior_digest: digest(exact_behavior, "exact behavior digest")?,
            carrier_semantics_digest: digest(carrier_semantics, "carrier semantics digest")?,
            direct_calls_digest: digest(direct_calls, "direct calls digest")?,
        },
        calls,
        lexical,
        reads,
    )?;
    let stored_digest = digest(stored_digest, "surface digest")?;
    if row.surface_digest != stored_digest {
        return Err(StoreError::new(
            "class-set procedure surface digest mismatch",
        ));
    }
    let stored_exact_provenance = digest(exact_provenance, "exact provenance digest")?;
    if row.exact_provenance_digest != stored_exact_provenance {
        return Err(StoreError::new(
            "class-set procedure surface exact provenance digest mismatch",
        ));
    }
    Ok(row)
}

struct LoadedCall {
    row: ClassSetProcedureSurfaceCallRow,
    expected_bindings: usize,
    expected_entered: usize,
}

fn load_calls(conn: &rusqlite::Connection, id: i64, expected: usize) -> Result<Vec<LoadedCall>> {
    let mut statement = conn.prepare_cached(SURFACE_CALLS_SQL)?;
    let rows = statement.query_map(params![id, sql_limit(expected)?], |row| {
        Ok((
            row.get::<_, u32>(0)?,
            row.get::<_, bool>(1)?,
            row.get::<_, bool>(2)?,
            row.get::<_, bool>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, usize>(8)?,
            row.get::<_, usize>(9)?,
        ))
    })?;
    rows.map(|row| {
        let (
            ordinal,
            uncovered,
            truncated,
            refinable,
            kind,
            status,
            capability,
            coverage,
            bindings,
            entered,
        ) = row?;
        let status = decode_status(&status, capability.as_deref())?;
        let dispatch = match (kind.as_str(), coverage.as_deref()) {
            ("resolved", Some(coverage)) => ClassSetProcedureSurfaceDispatchRow::Resolved {
                status,
                coverage: decode_coverage(coverage)?,
            },
            ("unavailable", None) => ClassSetProcedureSurfaceDispatchRow::Unavailable { status },
            _ => {
                return Err(StoreError::new(
                    "class-set procedure surface dispatch shape is corrupt",
                ));
            }
        };
        Ok(LoadedCall {
            row: ClassSetProcedureSurfaceCallRow {
                call_ordinal: ordinal,
                has_uncovered_boundary: uncovered,
                truncated,
                complete_receiver_hint_refinable: refinable,
                dispatch,
                binding_statuses: Vec::new(),
                entered: Vec::new(),
            },
            expected_bindings: bindings,
            expected_entered: entered,
        })
    })
    .collect::<Result<Vec<_>>>()
    .and_then(|rows| {
        if rows.len() != expected {
            Err(StoreError::new(
                "class-set procedure surface call count disagrees",
            ))
        } else {
            Ok(rows)
        }
    })
}

fn load_bindings(
    conn: &rusqlite::Connection,
    id: i64,
    expected: usize,
) -> Result<Vec<(u32, Vec<ClassSetProcedureSurfaceStatusRow>)>> {
    let mut statement = conn.prepare_cached(SURFACE_BINDINGS_SQL)?;
    let rows = statement.query_map(params![id, sql_limit(expected)?], |row| {
        Ok((
            row.get::<_, u32>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
        ))
    })?;
    let mut grouped = Vec::<(u32, Vec<ClassSetProcedureSurfaceStatusRow>)>::new();
    for row in rows {
        let (call, ordinal, status, capability) = row?;
        let statuses = if grouped.last().is_some_and(|(current, _)| *current == call) {
            &mut grouped.last_mut().expect("group exists").1
        } else {
            grouped.push((call, Vec::new()));
            &mut grouped.last_mut().expect("group was inserted").1
        };
        if ordinal as usize != statuses.len() {
            return Err(StoreError::new(
                "class-set procedure surface binding ordinals are not dense",
            ));
        }
        statuses.push(decode_status(&status, capability.as_deref())?);
    }
    Ok(grouped)
}

fn load_entered(
    conn: &rusqlite::Connection,
    id: i64,
    expected: usize,
) -> Result<Vec<(u32, Vec<ClassSetProcedureIdentityRow>)>> {
    let mut statement = conn.prepare_cached(SURFACE_ENTERED_SQL)?;
    let rows = statement.query_map(params![id, sql_limit(expected)?], |row| {
        Ok((
            row.get::<_, u32>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, Vec<u8>>(6)?,
            row.get::<_, Vec<u8>>(7)?,
        ))
    })?;
    let mut grouped = Vec::<(u32, Vec<ClassSetProcedureIdentityRow>)>::new();
    for row in rows {
        let (call, ordinal, lineage, rel_path, lang, public, content, local) = row?;
        let rows = if grouped.last().is_some_and(|(current, _)| *current == call) {
            &mut grouped.last_mut().expect("group exists").1
        } else {
            grouped.push((call, Vec::new()));
            &mut grouped.last_mut().expect("group was inserted").1
        };
        if ordinal as usize != rows.len() {
            return Err(StoreError::new(
                "class-set procedure surface entered ordinals are not dense",
            ));
        }
        rows.push(ClassSetProcedureIdentityRow {
            procedure_lineage: digest(lineage, "entered target lineage")?,
            rel_path,
            language: decode_language(&lang)?,
            artifact_public_identity: digest(public, "entered target public identity")?,
            artifact_content_identity: digest(content, "entered target content identity")?,
            local_structure_digest: digest(local, "entered target local structure digest")?,
        });
    }
    Ok(grouped)
}

fn load_lexical_children(
    conn: &rusqlite::Connection,
    id: i64,
    expected: usize,
) -> Result<Vec<ClassSetProcedureIdentityRow>> {
    let mut statement = conn.prepare_cached(SURFACE_LEXICAL_CHILDREN_SQL)?;
    let rows = statement.query_map(params![id, sql_limit(expected)?], |row| {
        Ok((
            row.get::<_, u32>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, Vec<u8>>(6)?,
        ))
    })?;
    rows.enumerate()
        .map(|(expected, row)| {
            let (ordinal, lineage, rel_path, lang, public, content, local) = row?;
            if ordinal as usize != expected {
                return Err(StoreError::new(
                    "class-set procedure surface lexical ordinals are not dense",
                ));
            }
            Ok(ClassSetProcedureIdentityRow {
                procedure_lineage: digest(lineage, "lexical child lineage")?,
                rel_path,
                language: decode_language(&lang)?,
                artifact_public_identity: digest(public, "lexical child public identity")?,
                artifact_content_identity: digest(content, "lexical child content identity")?,
                local_structure_digest: digest(local, "lexical child local structure digest")?,
            })
        })
        .collect()
}

fn load_reads(conn: &rusqlite::Connection, id: i64, expected: usize) -> Result<Vec<ReadKey>> {
    let mut statement = conn.prepare_cached(SURFACE_READS_SQL)?;
    let mut rows = statement.query(params![id, sql_limit(expected)?])?;
    let mut reads = Vec::new();
    while let Some(row) = rows.next()? {
        let ordinal = row.get::<_, u32>(12)?;
        if ordinal as usize != reads.len() {
            return Err(StoreError::new(
                "class-set procedure surface read ordinals are not dense",
            ));
        }
        reads.push(decode_read_key(row)?);
    }
    Ok(reads)
}

fn sql_limit(expected: usize) -> Result<i64> {
    i64::try_from(expected.saturating_add(1))
        .map_err(|_| StoreError::new("class-set procedure surface child limit exceeds i64"))
}

fn insert_surface(
    conn: &rusqlite::Connection,
    surface: &ClassSetProcedureSurfaceRow,
    blob_id: i64,
    cancellation: &CancellationToken,
) -> Result<()> {
    let header = &surface.header;
    let key = &header.key;
    let entered_count = surface
        .calls
        .iter()
        .map(|call| call.entered.len())
        .sum::<usize>();
    let binding_count = surface
        .calls
        .iter()
        .map(|call| call.binding_statuses.len())
        .sum::<usize>();
    conn.execute(
        "INSERT INTO class_set_procedure_surfaces(
           surface_digest,procedure_lineage,owner_rel_path,owner_blob_id,lang,
           artifact_public_identity,artifact_content_identity,schema_version,
           local_structure_digest,behavior_read_digest,exact_behavior_digest,
           exact_provenance_digest,carrier_semantics_digest,direct_calls_digest,call_count,binding_count,
           entered_count,lexical_child_count,read_count,completion,published_at
         ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,'complete',unixepoch())",
        params![
            surface.surface_digest.as_slice(),
            key.procedure_lineage.as_slice(),
            &key.owner_rel_path,
            blob_id,
            key.language.config_label(),
            header.artifact_public_identity.as_slice(),
            header.artifact_content_identity.as_slice(),
            key.schema_version,
            key.local_structure_digest.as_slice(),
            key.behavior_read_digest.as_slice(),
            header.exact_behavior_digest.as_slice(),
            surface.exact_provenance_digest.as_slice(),
            header.carrier_semantics_digest.as_slice(),
            header.direct_calls_digest.as_slice(),
            surface.calls.len(),
            binding_count,
            entered_count,
            surface.lexical_children.len(),
            surface.reads.len()
        ],
    )?;
    let id = conn.last_insert_rowid();
    for call in &surface.calls {
        ensure_not_cancelled(cancellation)?;
        let (dispatch_kind, status, capability, coverage) = dispatch_columns(call.dispatch);
        conn.execute(
            "INSERT INTO class_set_procedure_surface_calls VALUES(
             ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                id,
                call.call_ordinal,
                call.has_uncovered_boundary,
                call.truncated,
                call.complete_receiver_hint_refinable,
                dispatch_kind,
                status,
                capability,
                coverage,
                call.binding_statuses.len(),
                call.entered.len()
            ],
        )?;
        for (ordinal, binding_status) in call.binding_statuses.iter().enumerate() {
            ensure_not_cancelled(cancellation)?;
            let (status, capability) = status_columns(*binding_status);
            conn.execute(
                "INSERT INTO class_set_procedure_surface_bindings VALUES(?1,?2,?3,?4,?5)",
                params![id, call.call_ordinal, ordinal, status, capability],
            )?;
        }
        for (ordinal, target) in call.entered.iter().enumerate() {
            ensure_not_cancelled(cancellation)?;
            conn.execute(
                "INSERT INTO class_set_procedure_surface_entered VALUES(
                   ?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    id,
                    call.call_ordinal,
                    ordinal,
                    target.procedure_lineage.as_slice(),
                    &target.rel_path,
                    target.language.config_label(),
                    target.artifact_public_identity.as_slice(),
                    target.artifact_content_identity.as_slice(),
                    target.local_structure_digest.as_slice()
                ],
            )?;
        }
    }
    for (ordinal, child) in surface.lexical_children.iter().enumerate() {
        ensure_not_cancelled(cancellation)?;
        conn.execute(
            "INSERT INTO class_set_procedure_surface_lexical_children VALUES(
               ?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                id,
                ordinal,
                child.procedure_lineage.as_slice(),
                &child.rel_path,
                child.language.config_label(),
                child.artifact_public_identity.as_slice(),
                child.artifact_content_identity.as_slice(),
                child.local_structure_digest.as_slice()
            ],
        )?;
    }
    for (ordinal, read) in surface.reads.iter().enumerate() {
        ensure_not_cancelled(cancellation)?;
        let columns = ReadKeyColumns::of(read);
        conn.execute(
            "INSERT INTO class_set_procedure_surface_reads VALUES(
               ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                id,
                ordinal,
                columns.key_digest.as_slice(),
                columns.kind,
                columns.family,
                columns.languages,
                columns.rel_path,
                columns.name,
                columns.index_key,
                columns.blob_oid,
                columns.subject,
                columns.start_byte,
                columns.end_byte,
                columns.digest
            ],
        )?;
    }
    Ok(())
}

fn refresh_surface_provenance(
    conn: &rusqlite::Connection,
    surface: &ClassSetProcedureSurfaceRow,
    blob_id: i64,
    cancellation: &CancellationToken,
) -> Result<()> {
    ensure_not_cancelled(cancellation)?;
    let changed = conn.execute(
        "UPDATE class_set_procedure_surfaces
         SET owner_blob_id=?2, artifact_public_identity=?3, artifact_content_identity=?4,
             exact_behavior_digest=?5, exact_provenance_digest=?6, published_at=unixepoch()
         WHERE surface_digest=?1",
        params![
            surface.surface_digest.as_slice(),
            blob_id,
            surface.header.artifact_public_identity.as_slice(),
            surface.header.artifact_content_identity.as_slice(),
            surface.header.exact_behavior_digest.as_slice(),
            surface.exact_provenance_digest.as_slice()
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::new(
            "class-set procedure surface provenance refresh lost its row",
        ));
    }
    for call in &surface.calls {
        for (ordinal, entered) in call.entered.iter().enumerate() {
            ensure_not_cancelled(cancellation)?;
            let changed = conn.execute(
                "UPDATE class_set_procedure_surface_entered
                 SET target_artifact_public_identity=?4,
                     target_artifact_content_identity=?5
                 WHERE surface_id=(SELECT surface_id FROM class_set_procedure_surfaces
                                   WHERE surface_digest=?1)
                   AND call_ordinal=?2 AND entered_ordinal=?3",
                params![
                    surface.surface_digest.as_slice(),
                    call.call_ordinal,
                    ordinal,
                    entered.artifact_public_identity.as_slice(),
                    entered.artifact_content_identity.as_slice()
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::new(
                    "class-set procedure surface entered provenance refresh lost its row",
                ));
            }
        }
    }
    for (ordinal, child) in surface.lexical_children.iter().enumerate() {
        ensure_not_cancelled(cancellation)?;
        let changed = conn.execute(
            "UPDATE class_set_procedure_surface_lexical_children
             SET child_artifact_public_identity=?3, child_artifact_content_identity=?4
             WHERE surface_id=(SELECT surface_id FROM class_set_procedure_surfaces
                               WHERE surface_digest=?1)
               AND child_ordinal=?2",
            params![
                surface.surface_digest.as_slice(),
                ordinal,
                child.artifact_public_identity.as_slice(),
                child.artifact_content_identity.as_slice()
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::new(
                "class-set procedure surface lexical provenance refresh lost its row",
            ));
        }
    }
    Ok(())
}

fn status_columns(
    status: ClassSetProcedureSurfaceStatusRow,
) -> (&'static str, Option<&'static str>) {
    match status {
        ClassSetProcedureSurfaceStatusRow::Complete => ("complete", None),
        ClassSetProcedureSurfaceStatusRow::Ambiguous => ("ambiguous", None),
        ClassSetProcedureSurfaceStatusRow::Unknown => ("unknown", None),
        ClassSetProcedureSurfaceStatusRow::Unsupported { capability } => {
            ("unsupported", Some(capability.label()))
        }
        ClassSetProcedureSurfaceStatusRow::Unproven => ("unproven", None),
    }
}

fn decode_status(
    kind: &str,
    capability: Option<&str>,
) -> Result<ClassSetProcedureSurfaceStatusRow> {
    match (kind, capability) {
        ("complete", None) => Ok(ClassSetProcedureSurfaceStatusRow::Complete),
        ("ambiguous", None) => Ok(ClassSetProcedureSurfaceStatusRow::Ambiguous),
        ("unknown", None) => Ok(ClassSetProcedureSurfaceStatusRow::Unknown),
        ("unproven", None) => Ok(ClassSetProcedureSurfaceStatusRow::Unproven),
        ("unsupported", Some(label)) => SemanticCapability::ALL
            .into_iter()
            .find(|capability| capability.label() == label)
            .map(|capability| ClassSetProcedureSurfaceStatusRow::Unsupported { capability })
            .ok_or_else(|| StoreError::new("class-set procedure surface has unknown capability")),
        _ => Err(StoreError::new(
            "class-set procedure surface status shape is corrupt",
        )),
    }
}

fn dispatch_columns(
    dispatch: ClassSetProcedureSurfaceDispatchRow,
) -> (
    &'static str,
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
) {
    match dispatch {
        ClassSetProcedureSurfaceDispatchRow::Resolved { status, coverage } => {
            let (status, capability) = status_columns(status);
            ("resolved", status, capability, Some(coverage.label()))
        }
        ClassSetProcedureSurfaceDispatchRow::Unavailable { status } => {
            let (status, capability) = status_columns(status);
            ("unavailable", status, capability, None)
        }
    }
}

fn decode_coverage(value: &str) -> Result<CandidateCoverage> {
    match value {
        "exhaustive" => Ok(CandidateCoverage::Exhaustive),
        "open" => Ok(CandidateCoverage::Open),
        _ => Err(StoreError::new(
            "class-set procedure surface coverage is corrupt",
        )),
    }
}

fn decode_language(label: &str) -> Result<Language> {
    Language::from_config_label(label)
        .filter(|language| language.config_label() == label && *language != Language::None)
        .ok_or_else(|| StoreError::new("class-set procedure surface language is corrupt"))
}

fn digest(bytes: Vec<u8>, field: &str) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        StoreError::new(format!(
            "class-set procedure surface {field} has {} bytes",
            bytes.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::*;
    use crate::analyzer::read_ledger::ProcedureCallSiteLocator;
    use crate::analyzer::semantic::ids::StableDigest;
    use crate::analyzer::store::planner_statistics::tests::{explain_pin, pinned};
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    const BLOB_A: &str = "1111111111111111111111111111111111111111";
    const BLOB_B: &str = "2222222222222222222222222222222222222222";

    fn bytes(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn insert_complete_blob(store: &AnalyzerStore, oid: &str, generation: i64) {
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid,lang,generation) VALUES(?1,'python',?2)",
            params![oid, generation],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blob_meta(
               blob_id,lang,contains_tests,content_package,stored_unit_count,range_count,
               signature_count,signature_metadata_count,supertype_count,child_count,
               import_statement_count,type_identifier_count,is_complete)
             SELECT id,lang,0,'',0,0,0,0,0,0,0,0,1 FROM blobs WHERE blob_oid=?1",
            params![oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blob_payload_costs(blob_id,payload_bytes)
             SELECT id,0 FROM blobs WHERE blob_oid=?1",
            params![oid],
        )
        .unwrap();
    }

    fn store() -> AnalyzerStore {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        insert_complete_blob(&store, BLOB_A, 0);
        store
    }

    fn cascade_rows(store: &AnalyzerStore, oid: &str) -> usize {
        let conn = store.conn.lock().unwrap();
        conn.query_row(
            &super::super::stored_blob_cascade_costs_sql(1),
            params![oid, "python"],
            |row| row.get(3),
        )
        .unwrap()
    }

    fn identity(lineage: u8, public: u8, content: u8, local: u8) -> ClassSetProcedureIdentityRow {
        ClassSetProcedureIdentityRow {
            procedure_lineage: bytes(lineage),
            rel_path: format!("src/{lineage}.py"),
            language: Language::Python,
            artifact_public_identity: bytes(public),
            artifact_content_identity: bytes(content),
            local_structure_digest: bytes(local),
        }
    }

    fn surface(direct_calls: u8) -> ClassSetProcedureSurfaceRow {
        ClassSetProcedureSurfaceRow::try_new(
            ClassSetProcedureSurfaceHeaderRow {
                key: ClassSetProcedureSurfaceKey {
                    procedure_lineage: bytes(1),
                    owner_rel_path: "src/app.py".to_string(),
                    language: Language::Python,
                    schema_version: 1,
                    local_structure_digest: bytes(2),
                    behavior_read_digest: bytes(3),
                },
                owner_blob_oid: BLOB_A.to_string(),
                artifact_public_identity: bytes(4),
                artifact_content_identity: bytes(5),
                exact_behavior_digest: bytes(18),
                carrier_semantics_digest: bytes(6),
                direct_calls_digest: bytes(direct_calls),
            },
            vec![ClassSetProcedureSurfaceCallRow {
                call_ordinal: 7,
                has_uncovered_boundary: false,
                truncated: false,
                complete_receiver_hint_refinable: true,
                dispatch: ClassSetProcedureSurfaceDispatchRow::Resolved {
                    status: ClassSetProcedureSurfaceStatusRow::Complete,
                    coverage: CandidateCoverage::Exhaustive,
                },
                binding_statuses: vec![
                    ClassSetProcedureSurfaceStatusRow::Complete,
                    ClassSetProcedureSurfaceStatusRow::Unknown,
                ],
                entered: vec![identity(8, 9, 10, 11)],
            }],
            vec![identity(12, 13, 14, 15)],
            vec![ReadKey::Lookup {
                kind: LookupKind::ProcedureDispatch,
                question: LookupQuestion::ProcedureCallSite {
                    rel_path: Box::from("src/app.py"),
                    procedure: StableDigest::sha256(b"caller"),
                    site: ProcedureCallSiteLocator {
                        start_byte: 12,
                        end_byte: 18,
                    },
                },
                digest: StableDigest::sha256(b"dispatch"),
            }],
        )
        .unwrap()
    }

    #[test]
    fn class_set_procedure_surface_round_trips_and_is_idempotent() {
        let store = store();
        let expected = surface(16);
        assert!(
            store
                .publish_class_set_procedure_surface(expected.clone(), &CancellationToken::new())
                .unwrap()
        );
        assert!(
            !store
                .publish_class_set_procedure_surface(expected.clone(), &CancellationToken::new())
                .unwrap()
        );
        assert_eq!(
            store
                .class_set_procedure_surface_for_digest(*expected.surface_digest())
                .unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn class_set_procedure_surface_family_preserves_a_b_a_history() {
        let store = store();
        let a = surface(16);
        let b = surface(17);
        assert_ne!(a.surface_digest(), b.surface_digest());
        for row in [a.clone(), b.clone(), a.clone()] {
            store
                .publish_class_set_procedure_surface(row, &CancellationToken::new())
                .unwrap();
        }
        assert!(
            store
                .class_set_procedure_surface_candidates(&a.header.key, 1)
                .unwrap()
                .is_none()
        );
        let candidates = store
            .class_set_procedure_surface_candidates(&a.header.key, 2)
            .unwrap()
            .unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates
                .iter()
                .map(|row| row.surface_digest)
                .collect::<HashSet<_>>(),
            [*a.surface_digest(), *b.surface_digest()]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn class_set_procedure_surface_refreshes_only_attachment_provenance_in_place() {
        let store = store();
        let original = surface(16);
        store
            .publish_class_set_procedure_surface(original.clone(), &CancellationToken::new())
            .unwrap();
        insert_complete_blob(&store, BLOB_B, 1);
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO analysis_epochs(lang,epoch,generation)
                 VALUES('python','next',1)",
                [],
            )
            .unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO class_set_summaries(
                   lookup_digest,procedure_lineage,owner_rel_path,owner_blob_id,lang,
                   artifact_public_identity,artifact_content_identity,schema_version,
                   semantics_digest,context_digest,behavior_read_digest,dependency_digest,
                   carrier_digest,field_slots_digest,entry_fact_ordinal,fact_count,exit_count,
                   reached_count,dependency_count,read_count,charge_count,completion,budget_mode,
                   output_digest,content_digest,published_at,root_surface_digest,direct_calls_digest)
                 SELECT randomblob(32),procedure_lineage,owner_rel_path,owner_blob_id,lang,
                        artifact_public_identity,artifact_content_identity,schema_version,
                        randomblob(32),randomblob(32),behavior_read_digest,randomblob(32),
                        carrier_semantics_digest,randomblob(32),0,1,1,0,0,0,1,
                        'complete','exhaustive',randomblob(32),randomblob(32),0,
                        surface_digest,direct_calls_digest
                 FROM class_set_procedure_surfaces WHERE surface_digest=?1",
                params![original.surface_digest().as_slice()],
            )
            .unwrap();
        }
        let b_rows_before_refresh = cascade_rows(&store, BLOB_B);
        let id = {
            let conn = store.conn.lock().unwrap();
            conn.query_row(
                "SELECT surface_id FROM class_set_procedure_surfaces WHERE surface_digest=?1",
                params![original.surface_digest().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        };
        let mut header = original.header.clone();
        header.owner_blob_oid = BLOB_B.to_string();
        header.artifact_public_identity = bytes(40);
        header.artifact_content_identity = bytes(41);
        header.exact_behavior_digest = bytes(46);
        let mut calls = original.calls.clone();
        calls[0].entered[0].artifact_public_identity = bytes(42);
        calls[0].entered[0].artifact_content_identity = bytes(43);
        let mut lexical = original.lexical_children.clone();
        lexical[0].artifact_public_identity = bytes(44);
        lexical[0].artifact_content_identity = bytes(45);
        let refreshed =
            ClassSetProcedureSurfaceRow::try_new(header, calls, lexical, original.reads.clone())
                .unwrap();
        assert_eq!(original.surface_digest(), refreshed.surface_digest());
        assert!(
            !store
                .publish_class_set_procedure_surface(refreshed.clone(), &CancellationToken::new())
                .unwrap()
        );
        assert_eq!(
            cascade_rows(&store, BLOB_B) - b_rows_before_refresh,
            8,
            "surface-owner mutation cost includes the surface graph and its cross-owner summary"
        );
        let conn = store.conn.lock().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT surface_id FROM class_set_procedure_surfaces WHERE surface_digest=?1",
                params![original.surface_digest().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            id
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM class_set_summaries", [], |row| {
                row.get::<_, usize>(0)
            })
            .unwrap(),
            1,
            "attachment refresh must not cascade a referencing summary"
        );
        assert_eq!(
            conn.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        drop(conn);
        assert_eq!(
            store
                .class_set_procedure_surface_for_digest(*original.surface_digest())
                .unwrap(),
            Some(refreshed)
        );
    }

    #[test]
    fn class_set_procedure_surface_fails_closed_on_corrupt_counts_and_cancellation() {
        let store = store();
        let expected = surface(16);
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            store
                .publish_class_set_procedure_surface(expected.clone(), &cancelled)
                .is_err()
        );
        assert!(
            store
                .class_set_procedure_surface_for_digest(*expected.surface_digest())
                .unwrap()
                .is_none()
        );
        store
            .publish_class_set_procedure_surface(expected.clone(), &CancellationToken::new())
            .unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE class_set_procedure_surfaces SET entered_count=0
                 WHERE surface_digest=?1",
                params![expected.surface_digest().as_slice()],
            )
            .unwrap();
        }
        assert!(
            store
                .class_set_procedure_surface_for_digest(*expected.surface_digest())
                .is_err()
        );
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE class_set_procedure_surfaces SET entered_count=1
                 WHERE surface_digest=?1",
                params![expected.surface_digest().as_slice()],
            )
            .unwrap();
            conn.execute(
                "UPDATE class_set_procedure_surface_calls SET binding_count=1",
                [],
            )
            .unwrap();
        }
        assert!(
            store
                .class_set_procedure_surface_for_digest(*expected.surface_digest())
                .is_err()
        );
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE class_set_procedure_surface_calls SET binding_count=2",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO class_set_procedure_surface_bindings
                 SELECT surface_id,call_ordinal,2,'complete',NULL
                 FROM class_set_procedure_surface_calls",
                [],
            )
            .unwrap();
        }
        assert!(
            store
                .class_set_procedure_surface_for_digest(*expected.surface_digest())
                .is_err(),
            "expected+1 child loading must expose a hidden extra row"
        );
    }

    #[test]
    fn class_set_procedure_surface_semantic_comparison_and_digest_corruption_fail_closed() {
        let store = store();
        let original = surface(16);
        let mut changed_header = original.header.clone();
        changed_header.direct_calls_digest = bytes(99);
        let changed = ClassSetProcedureSurfaceRow::try_new(
            changed_header,
            original.calls.clone(),
            original.lexical_children.clone(),
            original.reads.clone(),
        )
        .unwrap();
        assert!(!original.has_same_semantic_surface(&changed));
        store
            .publish_class_set_procedure_surface(original.clone(), &CancellationToken::new())
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE class_set_procedure_surfaces SET direct_calls_digest=?1
                 WHERE surface_digest=?2",
                params![bytes(99).as_slice(), original.surface_digest().as_slice()],
            )
            .unwrap();
        assert!(
            store
                .class_set_procedure_surface_for_digest(*original.surface_digest())
                .is_err()
        );
        let mut forced_collision = changed;
        forced_collision.surface_digest = *original.surface_digest();
        assert!(
            store
                .publish_class_set_procedure_surface(forced_collision, &CancellationToken::new())
                .is_err()
        );
    }

    #[test]
    fn class_set_procedure_surface_exact_provenance_fails_closed_on_runtime_and_store_corruption() {
        let store = store();
        let expected = surface(16);
        assert!(expected.has_valid_exact_provenance());

        let mut runtime_behavior_corruption = expected.clone();
        runtime_behavior_corruption.header.exact_behavior_digest = bytes(90);
        assert!(!runtime_behavior_corruption.has_valid_exact_provenance());
        assert!(
            store
                .publish_class_set_procedure_surface(
                    runtime_behavior_corruption,
                    &CancellationToken::new()
                )
                .is_err()
        );

        let mut runtime_child_corruption = expected.clone();
        runtime_child_corruption.calls[0].entered[0].artifact_content_identity = bytes(91);
        assert!(!runtime_child_corruption.has_valid_exact_provenance());

        store
            .publish_class_set_procedure_surface(expected.clone(), &CancellationToken::new())
            .unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE class_set_procedure_surfaces SET exact_behavior_digest=?1
                 WHERE surface_digest=?2",
                params![bytes(92).as_slice(), expected.surface_digest().as_slice()],
            )
            .unwrap();
        }
        let behavior_error = store
            .class_set_procedure_surface_for_digest(*expected.surface_digest())
            .unwrap_err();
        assert!(
            behavior_error.to_string().contains("exact provenance"),
            "{behavior_error}"
        );
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE class_set_procedure_surfaces
                 SET exact_behavior_digest=?1, exact_provenance_digest=?2
                 WHERE surface_digest=?3",
                params![
                    expected.header.exact_behavior_digest.as_slice(),
                    bytes(93).as_slice(),
                    expected.surface_digest().as_slice()
                ],
            )
            .unwrap();
        }
        let provenance_error = store
            .class_set_procedure_surface_for_digest(*expected.surface_digest())
            .unwrap_err();
        assert!(
            provenance_error.to_string().contains("exact provenance"),
            "{provenance_error}"
        );
    }

    #[test]
    fn class_set_procedure_surface_queries_seek_persisted_indexes() {
        for state in PlannerStatisticsState::BOTH {
            let store = store();
            let conn = store.conn.lock().unwrap();
            state.install(&conn);
            for (name, expected) in [
                (
                    "class_set_procedure_surface_family",
                    "class_set_procedure_surfaces_exact_family",
                ),
                (
                    "class_set_procedure_surface_digest",
                    "sqlite_autoindex_class_set_procedure_surfaces_1",
                ),
                ("class_set_procedure_surface_calls", "PRIMARY KEY"),
                ("class_set_procedure_surface_bindings", "PRIMARY KEY"),
                ("class_set_procedure_surface_entered", "PRIMARY KEY"),
                (
                    "class_set_procedure_surface_lexical_children",
                    "PRIMARY KEY",
                ),
                ("class_set_procedure_surface_reads", "PRIMARY KEY"),
            ] {
                let plan = explain_pin(&conn, &pinned(name));
                assert!(
                    plan.iter().any(|detail| detail.contains(expected)),
                    "{state} {name}: {plan:#?}"
                );
                assert!(
                    plan.iter().all(|detail| !detail.contains("AUTOMATIC")),
                    "{state} {name}: {plan:#?}"
                );
            }
        }
    }

    #[test]
    fn class_set_procedure_surface_children_cascade_with_owner_blob() {
        let store = store();
        store
            .publish_class_set_procedure_surface(surface(16), &CancellationToken::new())
            .unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM blobs WHERE blob_oid=?1 AND lang='python'",
            params![BLOB_A],
        )
        .unwrap();
        for table in [
            "class_set_procedure_surfaces",
            "class_set_procedure_surface_calls",
            "class_set_procedure_surface_bindings",
            "class_set_procedure_surface_entered",
            "class_set_procedure_surface_lexical_children",
            "class_set_procedure_surface_reads",
        ] {
            assert_eq!(
                conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, usize>(0)
                })
                .unwrap(),
                0,
                "{table} did not cascade"
            );
        }
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get::<_, usize>(0)
            })
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
    }
}
