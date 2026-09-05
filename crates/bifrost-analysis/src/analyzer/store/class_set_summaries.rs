//! Normalized persisted rows for complete class-set procedure summaries.
//!
//! These DTOs deliberately contain only store-neutral primitives. Canonical
//! event and carrier keys are producer-defined bytes, not a serialized Rust
//! object. The discriminants that make those bytes meaningful remain ordinary
//! constrained columns.

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use super::read_keys::{ReadKeyColumns, decode_read_key};
use super::{AnalyzerStore, PARSED_BLOB_COMPLETE_CONDITION, Result, StoreError};
use crate::hash::HashSet;
use crate::{CancellationToken, analyzer::Language, analyzer::read_ledger::ReadKey};

pub type ClassSetSummaryDigest = [u8; 32];

/// Digest of only the caller-visible relation published by one class-set row.
///
/// This is intentionally not interchangeable with a lookup or canonical
/// storage digest. It excludes provenance, dependencies, recorded reads, and
/// replay charges so a recomputed callee can prove that its observable output
/// stayed equal even when the inputs that produced it moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClassSetSummaryOutputDigest(ClassSetSummaryDigest);

impl ClassSetSummaryOutputDigest {
    pub const fn new(digest: ClassSetSummaryDigest) -> Self {
        Self(digest)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetSummaryRowKey {
    pub lookup_digest: ClassSetSummaryDigest,
    pub procedure_lineage: ClassSetSummaryDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetSummaryAttachment {
    pub rel_path: String,
    pub blob_oid: String,
    pub language: Language,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetSummaryHeaderRow {
    pub key: ClassSetSummaryRowKey,
    pub attachment: ClassSetSummaryAttachment,
    pub artifact_public_identity: ClassSetSummaryDigest,
    pub artifact_content_identity: ClassSetSummaryDigest,
    pub schema_version: u32,
    pub semantics_digest: ClassSetSummaryDigest,
    pub context_digest: ClassSetSummaryDigest,
    pub behavior_read_digest: ClassSetSummaryDigest,
    pub dependency_digest: ClassSetSummaryDigest,
    pub carrier_digest: ClassSetSummaryDigest,
    pub field_slots_digest: ClassSetSummaryDigest,
    pub entry_fact_ordinal: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassSetSummaryFactSourceRow {
    None,
    Entry,
    Event(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassSetSummaryFactShapeRow {
    Zero,
    Carrier {
        source: ClassSetSummaryFactSourceRow,
        carrier_key: Vec<u8>,
        uncertain: bool,
    },
    Meeting {
        source: ClassSetSummaryFactSourceRow,
        sink_event_key: Vec<u8>,
        uncertain: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetSummaryFactRow {
    pub ordinal: u32,
    pub shape: ClassSetSummaryFactShapeRow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassSetSummaryExitKindRow {
    Normal,
    Exceptional,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetSummaryExitRow {
    pub ordinal: u32,
    pub kind: ClassSetSummaryExitKindRow,
    pub fact_ordinal: u32,
    pub quality_mask: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetSummaryReachedRow {
    pub ordinal: u32,
    pub point_id: u32,
    pub fact_ordinal: u32,
    pub quality_mask: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetSummaryDependencyRow {
    pub ordinal: u32,
    pub callee_procedure_lineage: ClassSetSummaryDigest,
    pub callee_entry_selector_digest: ClassSetSummaryDigest,
    pub expected_output_digest: ClassSetSummaryOutputDigest,
    pub consumed_child_lookup_digest: ClassSetSummaryDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetSummaryReadRow {
    pub ordinal: u32,
    pub key: ReadKey,
}

/// One persisted direct dependency and the summary row that consumed it.
///
/// This is evidence for a later invalidation coordinator; returning it does
/// not mutate, evict, or otherwise apply invalidation policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetSummaryDependentRow {
    pub dependent_lookup_digest: ClassSetSummaryDigest,
    pub dependency: ClassSetSummaryDependencyRow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetSummaryChargeRow {
    pub kind: String,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassSetSummaryRow {
    pub header: ClassSetSummaryHeaderRow,
    pub facts: Vec<ClassSetSummaryFactRow>,
    pub exits: Vec<ClassSetSummaryExitRow>,
    pub reached: Vec<ClassSetSummaryReachedRow>,
    pub dependencies: Vec<ClassSetSummaryDependencyRow>,
    pub reads: Vec<ClassSetSummaryReadRow>,
    pub charges: Vec<ClassSetSummaryChargeRow>,
    content_digest: ClassSetSummaryDigest,
}

impl ClassSetSummaryRow {
    pub fn try_new(
        header: ClassSetSummaryHeaderRow,
        mut facts: Vec<ClassSetSummaryFactRow>,
        mut exits: Vec<ClassSetSummaryExitRow>,
        mut reached: Vec<ClassSetSummaryReachedRow>,
        mut dependencies: Vec<ClassSetSummaryDependencyRow>,
        mut reads: Vec<ClassSetSummaryReadRow>,
        mut charges: Vec<ClassSetSummaryChargeRow>,
    ) -> Result<Self> {
        facts.sort_unstable_by_key(|row| row.ordinal);
        exits.sort_unstable_by_key(|row| row.ordinal);
        reached.sort_unstable_by_key(|row| row.ordinal);
        dependencies.sort_unstable_by_key(|row| row.ordinal);
        reads.sort_unstable_by_key(|row| row.ordinal);
        charges.sort_unstable_by(|left, right| left.kind.cmp(&right.kind));
        require_dense("dependency", dependencies.iter().map(|row| row.ordinal))?;
        require_dense("read", reads.iter().map(|row| row.ordinal))?;
        if header.schema_version == 0 {
            return Err(StoreError::new("class-set summary schema version is zero"));
        }
        if facts.is_empty() || header.entry_fact_ordinal as usize >= facts.len() {
            return Err(StoreError::new("class-set summary entry fact is absent"));
        }
        validate_class_set_summary_relation(&facts, &exits, &reached)?;
        if charges.is_empty() {
            return Err(StoreError::new("class-set summary has no replay charges"));
        }
        let mut dependency_lookups = HashSet::default();
        if dependencies
            .iter()
            .any(|row| !dependency_lookups.insert(row.consumed_child_lookup_digest))
        {
            return Err(StoreError::new(
                "class-set dependencies duplicate a child lookup",
            ));
        }
        let mut read_keys = HashSet::default();
        if reads
            .iter()
            .any(|row| !read_keys.insert(*row.key.canonical_digest().as_bytes()))
        {
            return Err(StoreError::new("class-set reads duplicate a key"));
        }
        if charges.iter().any(|row| row.kind.is_empty())
            || charges.iter().any(|row| row.amount == 0)
            || charges.windows(2).any(|rows| rows[0].kind == rows[1].kind)
        {
            return Err(StoreError::new(
                "class-set charge kind is empty or duplicated",
            ));
        }
        let mut row = Self {
            header,
            facts,
            exits,
            reached,
            dependencies,
            reads,
            charges,
            content_digest: [0; 32],
        };
        row.content_digest = row.canonical_content_digest();
        Ok(row)
    }

    /// Hash every logical stored value except publication time and the digest
    /// itself. Length framing makes this independent of SQLite row encoding.
    pub fn canonical_content_digest(&self) -> ClassSetSummaryDigest {
        let mut hash = CanonicalDigest::new(b"bifrost-class-set-store-row-v2");
        hash.bytes(&self.header.key.lookup_digest);
        hash.bytes(&self.header.key.procedure_lineage);
        hash.text(&self.header.attachment.rel_path);
        hash.text(&self.header.attachment.blob_oid);
        hash.text(self.header.attachment.language.config_label());
        hash.bytes(&self.header.artifact_public_identity);
        hash.bytes(&self.header.artifact_content_identity);
        hash.u64(u64::from(self.header.schema_version));
        hash.bytes(&self.header.semantics_digest);
        hash.bytes(&self.header.context_digest);
        hash.bytes(&self.header.behavior_read_digest);
        hash.bytes(&self.header.dependency_digest);
        hash.bytes(&self.header.carrier_digest);
        hash.bytes(&self.header.field_slots_digest);
        hash.u64(u64::from(self.header.entry_fact_ordinal));
        hash.text("facts");
        hash.u64(self.facts.len() as u64);
        for row in &self.facts {
            hash.u64(u64::from(row.ordinal));
            match &row.shape {
                ClassSetSummaryFactShapeRow::Zero => hash.tag(0),
                ClassSetSummaryFactShapeRow::Carrier {
                    source,
                    carrier_key,
                    uncertain,
                } => {
                    hash.tag(1);
                    hash.source(source);
                    hash.bytes(carrier_key);
                    hash.tag(u8::from(*uncertain));
                }
                ClassSetSummaryFactShapeRow::Meeting {
                    source,
                    sink_event_key,
                    uncertain,
                } => {
                    hash.tag(2);
                    hash.source(source);
                    hash.bytes(sink_event_key);
                    hash.tag(u8::from(*uncertain));
                }
            }
        }
        hash.text("exits");
        hash.u64(self.exits.len() as u64);
        for row in &self.exits {
            hash.u64(u64::from(row.ordinal));
            hash.tag(match row.kind {
                ClassSetSummaryExitKindRow::Normal => 0,
                ClassSetSummaryExitKindRow::Exceptional => 1,
            });
            hash.u64(u64::from(row.fact_ordinal));
            hash.tag(row.quality_mask);
        }
        hash.text("reached");
        hash.u64(self.reached.len() as u64);
        for row in &self.reached {
            hash.u64(u64::from(row.ordinal));
            hash.u64(u64::from(row.point_id));
            hash.u64(u64::from(row.fact_ordinal));
            hash.tag(row.quality_mask);
        }
        hash.text("dependencies");
        hash.u64(self.dependencies.len() as u64);
        for row in &self.dependencies {
            hash.u64(u64::from(row.ordinal));
            hash.bytes(&row.callee_procedure_lineage);
            hash.bytes(&row.callee_entry_selector_digest);
            hash.bytes(row.expected_output_digest.as_bytes());
            hash.bytes(&row.consumed_child_lookup_digest);
        }
        hash.text("reads");
        hash.u64(self.reads.len() as u64);
        for row in &self.reads {
            hash.u64(u64::from(row.ordinal));
            hash.bytes(row.key.canonical_digest().as_bytes());
        }
        hash.text("charges");
        hash.u64(self.charges.len() as u64);
        for row in &self.charges {
            hash.text(&row.kind);
            hash.u64(row.amount);
        }
        hash.finish()
    }

    pub const fn content_digest(&self) -> &ClassSetSummaryDigest {
        &self.content_digest
    }

    /// Hash the canonical relation a caller observes from this complete row.
    ///
    /// Exit and reached ordinals are normalized storage coordinates, not
    /// semantic output. Each relation therefore hashes its referenced fact
    /// shape inline, and the resulting row digests are sorted before the final
    /// digest. This makes the answer independent of fact-table numbering and
    /// relation-row numbering while retaining duplicate rows, qualities, exit
    /// kinds, reached points, and every referenced fact field.
    pub fn output_digest(&self) -> ClassSetSummaryOutputDigest {
        class_set_summary_output_digest(&self.facts, &self.exits, &self.reached)
            .expect("constructed class-set summary relation remains valid")
    }
}

/// Hash the canonical complete, exhaustive relation visible to a caller.
///
/// The three inputs are the normalized store-neutral rows produced by the
/// class-set projection. Their ordinals must each be dense and ordered so a
/// fact reference is unambiguous. Ordinals themselves are excluded from the
/// digest: facts are hashed inline at every exit and reached observation, and
/// those relation-row digests are sorted before aggregation.
pub fn class_set_summary_output_digest(
    facts: &[ClassSetSummaryFactRow],
    exits: &[ClassSetSummaryExitRow],
    reached: &[ClassSetSummaryReachedRow],
) -> Result<ClassSetSummaryOutputDigest> {
    const OUTPUT_DOMAIN: &[u8] = b"bifrost-class-set-summary-output-v1";
    const EXIT_DOMAIN: &[u8] = b"bifrost-class-set-summary-exit-output-v1";
    const REACHED_DOMAIN: &[u8] = b"bifrost-class-set-summary-reached-output-v1";

    validate_class_set_summary_relation(facts, exits, reached)?;

    let mut exit_digests = exits
        .iter()
        .map(|row| {
            let fact = &facts[row.fact_ordinal as usize];
            let mut hash = CanonicalDigest::new(EXIT_DOMAIN);
            hash.tag(match row.kind {
                ClassSetSummaryExitKindRow::Normal => 0,
                ClassSetSummaryExitKindRow::Exceptional => 1,
            });
            hash.fact_shape(&fact.shape);
            hash.tag(row.quality_mask);
            hash.finish()
        })
        .collect::<Vec<_>>();
    exit_digests.sort_unstable();

    let mut reached_digests = reached
        .iter()
        .map(|row| {
            let fact = &facts[row.fact_ordinal as usize];
            let mut hash = CanonicalDigest::new(REACHED_DOMAIN);
            hash.u64(u64::from(row.point_id));
            hash.fact_shape(&fact.shape);
            hash.tag(row.quality_mask);
            hash.finish()
        })
        .collect::<Vec<_>>();
    reached_digests.sort_unstable();

    let mut hash = CanonicalDigest::new(OUTPUT_DOMAIN);
    // Both construction paths admit only complete, exhaustive relations. Keep
    // that represented completeness in the output identity so a future row
    // vocabulary cannot silently compare a weaker answer as equal.
    hash.text("complete");
    hash.text("exhaustive");
    hash.text("exits");
    hash.u64(exit_digests.len() as u64);
    for row in exit_digests {
        hash.bytes(&row);
    }
    hash.text("reached");
    hash.u64(reached_digests.len() as u64);
    for row in reached_digests {
        hash.bytes(&row);
    }
    Ok(ClassSetSummaryOutputDigest(hash.finish()))
}

fn validate_class_set_summary_relation(
    facts: &[ClassSetSummaryFactRow],
    exits: &[ClassSetSummaryExitRow],
    reached: &[ClassSetSummaryReachedRow],
) -> Result<()> {
    require_dense("fact", facts.iter().map(|row| row.ordinal))?;
    require_dense("exit", exits.iter().map(|row| row.ordinal))?;
    require_dense("reached", reached.iter().map(|row| row.ordinal))?;
    if facts.is_empty() {
        return Err(StoreError::new("class-set summary has no fact rows"));
    }
    if exits.is_empty() {
        return Err(StoreError::new("class-set summary has no exit rows"));
    }
    for row in facts {
        match &row.shape {
            ClassSetSummaryFactShapeRow::Zero => {}
            ClassSetSummaryFactShapeRow::Carrier {
                source,
                carrier_key,
                ..
            } => {
                require_flow_source(source)?;
                if carrier_key.len() != 32 {
                    return Err(StoreError::new("class-set carrier key is not 32 bytes"));
                }
            }
            ClassSetSummaryFactShapeRow::Meeting {
                source,
                sink_event_key,
                ..
            } => {
                require_flow_source(source)?;
                if sink_event_key.len() != 32 {
                    return Err(StoreError::new("class-set sink event key is not 32 bytes"));
                }
            }
        }
    }
    for fact in exits
        .iter()
        .map(|row| row.fact_ordinal)
        .chain(reached.iter().map(|row| row.fact_ordinal))
    {
        if fact as usize >= facts.len() {
            return Err(StoreError::new(format!(
                "class-set relation references absent fact {fact}"
            )));
        }
    }
    if exits
        .iter()
        .any(|row| !matches!(row.quality_mask, 1 | 2 | 4 | 6 | 8))
        || reached
            .iter()
            .any(|row| !matches!(row.quality_mask, 1 | 2 | 4 | 6 | 8))
    {
        return Err(StoreError::new(
            "class-set relation has an invalid quality mask",
        ));
    }
    Ok(())
}

fn require_dense(name: &str, ordinals: impl Iterator<Item = u32>) -> Result<()> {
    for (expected, actual) in ordinals.enumerate() {
        if usize::try_from(actual).ok() != Some(expected) {
            return Err(StoreError::new(format!(
                "class-set {name} ordinal {actual} is not dense at {expected}"
            )));
        }
    }
    Ok(())
}

fn require_flow_source(source: &ClassSetSummaryFactSourceRow) -> Result<()> {
    match source {
        ClassSetSummaryFactSourceRow::None => {
            Err(StoreError::new("nonzero class-set fact has no source"))
        }
        ClassSetSummaryFactSourceRow::Entry => Ok(()),
        ClassSetSummaryFactSourceRow::Event(key) if key.len() != 32 => Err(StoreError::new(
            "class-set source event key is not 32 bytes",
        )),
        ClassSetSummaryFactSourceRow::Event(_) => Ok(()),
    }
}

struct CanonicalDigest(Sha256);
impl CanonicalDigest {
    fn new(domain: &[u8]) -> Self {
        let mut value = Self(Sha256::new());
        value.bytes(domain);
        value
    }
    fn bytes(&mut self, bytes: &[u8]) {
        self.0.update((bytes.len() as u64).to_le_bytes());
        self.0.update(bytes);
    }
    fn text(&mut self, text: &str) {
        self.bytes(text.as_bytes());
    }
    fn tag(&mut self, value: u8) {
        self.bytes(&[value]);
    }
    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_le_bytes());
    }
    fn source(&mut self, source: &ClassSetSummaryFactSourceRow) {
        match source {
            ClassSetSummaryFactSourceRow::None => self.tag(0),
            ClassSetSummaryFactSourceRow::Entry => self.tag(1),
            ClassSetSummaryFactSourceRow::Event(key) => {
                self.tag(2);
                self.bytes(key);
            }
        }
    }
    fn fact_shape(&mut self, shape: &ClassSetSummaryFactShapeRow) {
        match shape {
            ClassSetSummaryFactShapeRow::Zero => self.tag(0),
            ClassSetSummaryFactShapeRow::Carrier {
                source,
                carrier_key,
                uncertain,
            } => {
                self.tag(1);
                self.source(source);
                self.bytes(carrier_key);
                self.tag(u8::from(*uncertain));
            }
            ClassSetSummaryFactShapeRow::Meeting {
                source,
                sink_event_key,
                uncertain,
            } => {
                self.tag(2);
                self.source(source);
                self.bytes(sink_event_key);
                self.tag(u8::from(*uncertain));
            }
        }
    }
    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

pub(crate) static CLASS_SET_SUMMARY_LOOKUP_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "SELECT summaries.summary_id, summaries.procedure_lineage,
            summaries.owner_rel_path, blobs.blob_oid, summaries.lang,
            artifact_public_identity, artifact_content_identity, schema_version,
            semantics_digest, context_digest, behavior_read_digest, dependency_digest,
            carrier_digest, field_slots_digest, entry_fact_ordinal, fact_count, exit_count,
            reached_count, dependency_count, read_count, charge_count, output_digest,
            content_digest
     FROM class_set_summaries AS summaries
     JOIN blobs ON blobs.id = summaries.owner_blob_id AND blobs.lang = summaries.lang
     JOIN blob_meta AS meta ON meta.blob_id = blobs.id
     WHERE summaries.lookup_digest = ?1
       AND {PARSED_BLOB_COMPLETE_CONDITION}"
    )
});

pub(crate) static CLASS_SET_SUMMARY_PROCEDURE_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "SELECT 1
     FROM class_set_summaries AS summaries
     JOIN blobs ON blobs.id = summaries.owner_blob_id AND blobs.lang = summaries.lang
     JOIN blob_meta AS meta ON meta.blob_id = blobs.id
     WHERE summaries.procedure_lineage = ?1
       AND {PARSED_BLOB_COMPLETE_CONDITION}
     LIMIT 1"
    )
});
const FACTS_SQL: &str = "SELECT fact_ordinal,fact_kind,source_kind,source_event_key,
        carrier_key,sink_event_key,uncertain
     FROM class_set_summary_facts WHERE summary_id=?1 ORDER BY fact_ordinal";
const EXITS_SQL: &str = "SELECT exit_ordinal,exit_kind,fact_ordinal,quality_mask
     FROM class_set_summary_exits WHERE summary_id=?1 ORDER BY exit_ordinal";
const REACHED_SQL: &str = "SELECT reached_ordinal,point_id,fact_ordinal,quality_mask
     FROM class_set_summary_reached WHERE summary_id=?1 ORDER BY reached_ordinal";
pub(crate) static CLASS_SET_SUMMARY_DEPENDENTS_BY_LOOKUP_SQL: LazyLock<String> =
    LazyLock::new(|| dependent_summary_sql("dependencies.consumed_child_lookup_digest = ?1"));
pub(crate) static CLASS_SET_SUMMARY_DEPENDENTS_BY_LINEAGE_ENTRY_SQL: LazyLock<String> =
    LazyLock::new(|| {
        dependent_summary_sql(
            "dependencies.callee_procedure_lineage = ?1
             AND dependencies.callee_entry_selector_digest = ?2",
        )
    });
pub(crate) static CLASS_SET_SUMMARY_DEPENDENTS_BY_READ_SQL: LazyLock<String> =
    LazyLock::new(|| {
        format!(
            "SELECT summaries.lookup_digest
         FROM class_set_summary_reads AS reads
         JOIN class_set_summaries AS summaries ON summaries.summary_id = reads.summary_id
         JOIN blobs ON blobs.id = summaries.owner_blob_id AND blobs.lang = summaries.lang
         JOIN blob_meta AS meta ON meta.blob_id = blobs.id
         WHERE reads.key_digest = ?1
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY summaries.lookup_digest"
        )
    });

fn dependent_summary_sql(predicate: &str) -> String {
    format!(
        "SELECT summaries.lookup_digest, dependencies.dependency_ordinal,
            dependencies.callee_procedure_lineage,
            dependencies.callee_entry_selector_digest,
            dependencies.expected_output_digest,
            dependencies.consumed_child_lookup_digest
         FROM class_set_summary_dependencies AS dependencies
         JOIN class_set_summaries AS summaries
           ON summaries.summary_id = dependencies.summary_id
         JOIN blobs ON blobs.id = summaries.owner_blob_id AND blobs.lang = summaries.lang
         JOIN blob_meta AS meta ON meta.blob_id = blobs.id
         WHERE {predicate}
           AND {PARSED_BLOB_COMPLETE_CONDITION}
         ORDER BY summaries.lookup_digest, dependencies.dependency_ordinal"
    )
}

const DEPENDENCIES_SQL: &str = "SELECT dependency_ordinal,callee_procedure_lineage,
        callee_entry_selector_digest,expected_output_digest,consumed_child_lookup_digest
     FROM class_set_summary_dependencies WHERE summary_id=?1 ORDER BY dependency_ordinal";
const READS_SQL: &str = "SELECT key_digest,kind,family,languages,rel_path,name,index_key,
        blob_oid,subject,start_byte,end_byte,digest,read_ordinal
     FROM class_set_summary_reads WHERE summary_id=?1 ORDER BY read_ordinal";
const CHARGES_SQL: &str = "SELECT charge_kind,amount
     FROM class_set_summary_charges WHERE summary_id=?1 ORDER BY charge_kind";

impl AnalyzerStore {
    pub fn contains_class_set_summary_procedure(
        &self,
        identity: ClassSetSummaryDigest,
    ) -> Result<bool> {
        let conn = self.read_conn()?;
        Ok(conn
            .query_row(
                CLASS_SET_SUMMARY_PROCEDURE_SQL.as_str(),
                params![identity.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn publish_class_set_summary(
        &self,
        summary: ClassSetSummaryRow,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        validate_summary_for_publication(&summary, cancellation)?;
        self.conn.execute({
            let cancellation = cancellation.clone();
            move |conn| {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                ensure_not_cancelled(&cancellation)?;
                let lang = summary.header.attachment.language.config_label();
                let blob_id = live_owner_blob_id(&tx, &summary)?;
                if let Some(existing) =
                    load_summary_for_digest(&tx, summary.header.key.lookup_digest)?
                {
                    if existing == summary {
                        tx.commit()?;
                        return Ok(false);
                    }
                    return Err(StoreError::new(
                        "class-set summary lookup digest names different content",
                    ));
                }
                // A prior language generation or an incomplete parse can leave
                // an intentionally hidden header behind. It is not reusable and
                // must not block publication under the unique lookup identity.
                tx.execute(
                    "DELETE FROM class_set_summaries WHERE lookup_digest = ?1",
                    params![summary.header.key.lookup_digest.as_slice()],
                )?;
                insert_summary(&tx, &summary, blob_id, lang, &cancellation)?;
                ensure_not_cancelled(&cancellation)?;
                tx.commit()?;
                Ok(true)
            }
        })
    }

    /// Atomically replace one current owner-local lookup after checking its
    /// complete stored content.
    ///
    /// A retry whose desired row is already current is an idempotent no-op even
    /// if it still carries the predecessor's digest. Any other stale expected
    /// digest is rejected before the old header and its children are deleted.
    pub fn replace_class_set_summary(
        &self,
        expected_current_content_digest: ClassSetSummaryDigest,
        summary: ClassSetSummaryRow,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        validate_summary_for_publication(&summary, cancellation)?;
        self.conn.execute({
            let cancellation = cancellation.clone();
            move |conn| {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                ensure_not_cancelled(&cancellation)?;
                let lang = summary.header.attachment.language.config_label();
                let blob_id = live_owner_blob_id(&tx, &summary)?;
                let Some(current) = load_summary_for_digest(&tx, summary.header.key.lookup_digest)?
                else {
                    return Err(StoreError::new(
                        "class-set summary replacement has no current row",
                    ));
                };
                if current == summary {
                    tx.commit()?;
                    return Ok(false);
                }
                if current.content_digest != expected_current_content_digest {
                    return Err(StoreError::new(
                        "class-set summary replacement expected a stale current row",
                    ));
                }
                ensure_not_cancelled(&cancellation)?;
                let deleted = tx.execute(
                    "DELETE FROM class_set_summaries
                     WHERE lookup_digest = ?1 AND content_digest = ?2",
                    params![
                        summary.header.key.lookup_digest.as_slice(),
                        expected_current_content_digest.as_slice()
                    ],
                )?;
                if deleted != 1 {
                    return Err(StoreError::new(
                        "class-set summary replacement lost its current row",
                    ));
                }
                ensure_not_cancelled(&cancellation)?;
                insert_summary(&tx, &summary, blob_id, lang, &cancellation)?;
                ensure_not_cancelled(&cancellation)?;
                tx.commit()?;
                Ok(true)
            }
        })
    }

    pub fn class_set_summary_for_digest(
        &self,
        lookup_digest: ClassSetSummaryDigest,
    ) -> Result<Option<ClassSetSummaryRow>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let summary = load_summary_for_digest(&tx, lookup_digest)?;
        tx.commit()?;
        Ok(summary)
    }

    pub fn class_set_summary_dependents_of_lookup(
        &self,
        lookup_digest: ClassSetSummaryDigest,
    ) -> Result<Vec<ClassSetSummaryDependentRow>> {
        let conn = self.read_conn()?;
        load_dependents(
            &conn,
            CLASS_SET_SUMMARY_DEPENDENTS_BY_LOOKUP_SQL.as_str(),
            params![lookup_digest.as_slice()],
        )
    }

    pub fn class_set_summary_dependents_of_lineage_entry(
        &self,
        procedure_lineage: ClassSetSummaryDigest,
        entry_selector_digest: ClassSetSummaryDigest,
    ) -> Result<Vec<ClassSetSummaryDependentRow>> {
        let conn = self.read_conn()?;
        load_dependents(
            &conn,
            CLASS_SET_SUMMARY_DEPENDENTS_BY_LINEAGE_ENTRY_SQL.as_str(),
            params![
                procedure_lineage.as_slice(),
                entry_selector_digest.as_slice()
            ],
        )
    }

    pub fn class_set_summary_dependents_of_read(
        &self,
        read: &ReadKey,
    ) -> Result<Vec<ClassSetSummaryDigest>> {
        let conn = self.read_conn()?;
        let mut statement =
            conn.prepare_cached(CLASS_SET_SUMMARY_DEPENDENTS_BY_READ_SQL.as_str())?;
        let rows = statement.query_map(
            params![read.canonical_digest().as_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        rows.map(|row| digest(row?, "read dependent lookup"))
            .collect()
    }
}

fn load_summary_for_digest(
    conn: &rusqlite::Connection,
    lookup_digest: ClassSetSummaryDigest,
) -> Result<Option<ClassSetSummaryRow>> {
    let raw = conn
        .query_row(
            CLASS_SET_SUMMARY_LOOKUP_SQL.as_str(),
            params![lookup_digest.as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, u32>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                    row.get::<_, u32>(14)?,
                    row.get::<_, usize>(15)?,
                    row.get::<_, usize>(16)?,
                    row.get::<_, usize>(17)?,
                    row.get::<_, usize>(18)?,
                    row.get::<_, usize>(19)?,
                    row.get::<_, usize>(20)?,
                    row.get::<_, Vec<u8>>(21)?,
                    row.get::<_, Vec<u8>>(22)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| load_summary(conn, lookup_digest, raw))
        .transpose()
}

fn validate_summary_for_publication(
    summary: &ClassSetSummaryRow,
    cancellation: &CancellationToken,
) -> Result<()> {
    if summary.content_digest != summary.canonical_content_digest() {
        return Err(StoreError::new(
            "class-set summary changed after canonical construction",
        ));
    }
    ensure_not_cancelled(cancellation)
}

fn live_owner_blob_id(conn: &rusqlite::Connection, summary: &ClassSetSummaryRow) -> Result<i64> {
    let lang = summary.header.attachment.language.config_label();
    conn.query_row(
        &format!(
            "SELECT meta.blob_id FROM blob_meta AS meta
             JOIN blobs ON blobs.id = meta.blob_id
             WHERE blobs.blob_oid = ?1 AND blobs.lang = ?2
               AND {PARSED_BLOB_COMPLETE_CONDITION}"
        ),
        params![&summary.header.attachment.blob_oid, lang],
        |row| row.get::<_, i64>(0),
    )
    .optional()?
    .ok_or_else(|| {
        StoreError::new(format!(
            "class-set summary owner blob {}/{} is absent",
            summary.header.attachment.blob_oid, lang
        ))
    })
}

fn ensure_not_cancelled(cancellation: &CancellationToken) -> Result<()> {
    if cancellation.is_cancelled() {
        Err(StoreError::new("class-set summary publication cancelled"))
    } else {
        Ok(())
    }
}

fn digest(bytes: Vec<u8>, field: &str) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        StoreError::new(format!(
            "class-set summary {field} has {} bytes",
            bytes.len()
        ))
    })
}

fn load_dependents(
    conn: &rusqlite::Connection,
    sql: &str,
    parameters: impl rusqlite::Params,
) -> Result<Vec<ClassSetSummaryDependentRow>> {
    let mut statement = conn.prepare_cached(sql)?;
    let rows = statement.query_map(parameters, |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
        ))
    })?;
    rows.map(|row| {
        let (dependent, ordinal, lineage, entry, output, lookup) = row?;
        Ok(ClassSetSummaryDependentRow {
            dependent_lookup_digest: digest(dependent, "dependent lookup")?,
            dependency: ClassSetSummaryDependencyRow {
                ordinal,
                callee_procedure_lineage: digest(lineage, "dependency lineage")?,
                callee_entry_selector_digest: digest(entry, "dependency entry selector")?,
                expected_output_digest: ClassSetSummaryOutputDigest::new(digest(
                    output,
                    "dependency output",
                )?),
                consumed_child_lookup_digest: digest(lookup, "dependency lookup")?,
            },
        })
    })
    .collect()
}

fn insert_summary(
    conn: &rusqlite::Connection,
    summary: &ClassSetSummaryRow,
    blob_id: i64,
    lang: &str,
    cancellation: &CancellationToken,
) -> Result<()> {
    let h = &summary.header;
    let output_digest = summary.output_digest();
    ensure_not_cancelled(cancellation)?;
    conn.execute("INSERT INTO class_set_summaries(lookup_digest, procedure_lineage, owner_rel_path, owner_blob_id, lang, artifact_public_identity, artifact_content_identity, schema_version, semantics_digest, context_digest, behavior_read_digest, dependency_digest, carrier_digest, field_slots_digest, entry_fact_ordinal, fact_count, exit_count, reached_count, dependency_count, read_count, charge_count, completion, budget_mode, output_digest, content_digest, published_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,'complete','exhaustive',?22,?23,unixepoch())", params![h.key.lookup_digest.as_slice(), h.key.procedure_lineage.as_slice(), &h.attachment.rel_path, blob_id, lang, h.artifact_public_identity.as_slice(), h.artifact_content_identity.as_slice(), h.schema_version, h.semantics_digest.as_slice(), h.context_digest.as_slice(), h.behavior_read_digest.as_slice(), h.dependency_digest.as_slice(), h.carrier_digest.as_slice(), h.field_slots_digest.as_slice(), h.entry_fact_ordinal, summary.facts.len(), summary.exits.len(), summary.reached.len(), summary.dependencies.len(), summary.reads.len(), summary.charges.len(), output_digest.as_bytes().as_slice(), summary.content_digest.as_slice()])?;
    let id = conn.last_insert_rowid();
    for row in &summary.facts {
        ensure_not_cancelled(cancellation)?;
        let (kind, source_kind, source_key, carrier, sink, uncertain) = fact_columns(&row.shape);
        conn.execute("INSERT INTO class_set_summary_facts(summary_id,fact_ordinal,fact_kind,source_kind,source_event_key,carrier_key,sink_event_key,uncertain) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", params![id,row.ordinal,kind,source_kind,source_key,carrier,sink,uncertain])?;
    }
    for row in &summary.exits {
        ensure_not_cancelled(cancellation)?;
        conn.execute(
            "INSERT INTO class_set_summary_exits VALUES(?1,?2,?3,?4,?5)",
            params![
                id,
                row.ordinal,
                match row.kind {
                    ClassSetSummaryExitKindRow::Normal => "normal",
                    ClassSetSummaryExitKindRow::Exceptional => "exceptional",
                },
                row.fact_ordinal,
                row.quality_mask
            ],
        )?;
    }
    for row in &summary.reached {
        ensure_not_cancelled(cancellation)?;
        conn.execute(
            "INSERT INTO class_set_summary_reached VALUES(?1,?2,?3,?4,?5)",
            params![
                id,
                row.ordinal,
                row.point_id,
                row.fact_ordinal,
                row.quality_mask
            ],
        )?;
    }
    for row in &summary.dependencies {
        ensure_not_cancelled(cancellation)?;
        conn.execute(
            "INSERT INTO class_set_summary_dependencies VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                id,
                row.ordinal,
                row.callee_procedure_lineage.as_slice(),
                row.callee_entry_selector_digest.as_slice(),
                row.expected_output_digest.as_bytes().as_slice(),
                row.consumed_child_lookup_digest.as_slice()
            ],
        )?;
    }
    for row in &summary.reads {
        ensure_not_cancelled(cancellation)?;
        let columns = ReadKeyColumns::of(&row.key);
        conn.execute(
            "INSERT INTO class_set_summary_reads(
                summary_id,read_ordinal,key_digest,kind,family,languages,rel_path,name,
                index_key,blob_oid,subject,start_byte,end_byte,digest
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                id,
                row.ordinal,
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
                columns.digest,
            ],
        )?;
    }
    for row in &summary.charges {
        ensure_not_cancelled(cancellation)?;
        let amount = i64::try_from(row.amount)
            .map_err(|_| StoreError::new("class-set replay charge exceeds SQLite INTEGER"))?;
        conn.execute(
            "INSERT INTO class_set_summary_charges VALUES(?1,?2,?3)",
            params![id, &row.kind, amount],
        )?;
    }
    Ok(())
}

type FactColumns<'a> = (
    &'static str,
    &'static str,
    Option<&'a [u8]>,
    Option<&'a [u8]>,
    Option<&'a [u8]>,
    bool,
);
fn fact_columns(shape: &ClassSetSummaryFactShapeRow) -> FactColumns<'_> {
    match shape {
        ClassSetSummaryFactShapeRow::Zero => ("zero", "none", None, None, None, false),
        ClassSetSummaryFactShapeRow::Carrier {
            source: s,
            carrier_key,
            uncertain,
        } => {
            let (kind, key) = source_columns(s);
            ("carrier", kind, key, Some(carrier_key), None, *uncertain)
        }
        ClassSetSummaryFactShapeRow::Meeting {
            source: s,
            sink_event_key,
            uncertain,
        } => {
            let (kind, key) = source_columns(s);
            ("meeting", kind, key, None, Some(sink_event_key), *uncertain)
        }
    }
}

fn source_columns(source: &ClassSetSummaryFactSourceRow) -> (&'static str, Option<&[u8]>) {
    match source {
        ClassSetSummaryFactSourceRow::None => ("none", None),
        ClassSetSummaryFactSourceRow::Entry => ("entry", None),
        ClassSetSummaryFactSourceRow::Event(key) => ("event", Some(key.as_slice())),
    }
}

type RawHeader = (
    i64,
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
    u32,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    Vec<u8>,
    Vec<u8>,
);
fn load_summary(
    conn: &rusqlite::Connection,
    lookup: [u8; 32],
    raw: RawHeader,
) -> Result<ClassSetSummaryRow> {
    let (
        id,
        procedure,
        rel_path,
        blob_oid,
        lang,
        artifact_public,
        artifact_content,
        schema,
        semantics,
        context,
        behavior,
        dependency_digest,
        carrier,
        fields,
        entry,
        fact_count,
        exit_count,
        reached_count,
        dependency_count,
        read_count,
        charge_count,
        stored_output,
        stored_content,
    ) = raw;
    let language = Language::from_config_label(&lang).ok_or_else(|| {
        StoreError::new(format!(
            "class-set summary records unknown language {lang:?}"
        ))
    })?;
    let facts = load_facts(conn, id)?;
    let exits = load_exits(conn, id)?;
    let reached = load_reached(conn, id)?;
    let dependencies = load_dependencies(conn, id)?;
    let reads = load_reads(conn, id)?;
    let charges = load_charges(conn, id)?;
    let actual = [
        facts.len(),
        exits.len(),
        reached.len(),
        dependencies.len(),
        reads.len(),
        charges.len(),
    ];
    let expected = [
        fact_count,
        exit_count,
        reached_count,
        dependency_count,
        read_count,
        charge_count,
    ];
    if actual != expected {
        return Err(StoreError::new(format!(
            "class-set summary child counts disagree: stored {expected:?}, found {actual:?}"
        )));
    }
    let summary = ClassSetSummaryRow::try_new(
        ClassSetSummaryHeaderRow {
            key: ClassSetSummaryRowKey {
                lookup_digest: lookup,
                procedure_lineage: digest(procedure, "procedure lineage")?,
            },
            attachment: ClassSetSummaryAttachment {
                rel_path,
                blob_oid,
                language,
            },
            artifact_public_identity: digest(artifact_public, "artifact public identity")?,
            artifact_content_identity: digest(artifact_content, "artifact content identity")?,
            schema_version: schema,
            semantics_digest: digest(semantics, "semantics digest")?,
            context_digest: digest(context, "context digest")?,
            behavior_read_digest: digest(behavior, "behavior digest")?,
            dependency_digest: digest(dependency_digest, "dependency digest")?,
            carrier_digest: digest(carrier, "carrier digest")?,
            field_slots_digest: digest(fields, "field-slots digest")?,
            entry_fact_ordinal: entry,
        },
        facts,
        exits,
        reached,
        dependencies,
        reads,
        charges,
    )?;
    let stored_content = digest(stored_content, "content digest")?;
    if summary.content_digest != stored_content {
        return Err(StoreError::new(format!(
            "class-set summary content digest mismatch: stored {stored_content:?}, computed {:?}",
            summary.content_digest
        )));
    }
    let stored_output = ClassSetSummaryOutputDigest::new(digest(stored_output, "output digest")?);
    let computed_output = summary.output_digest();
    if computed_output != stored_output {
        return Err(StoreError::new(format!(
            "class-set summary output digest mismatch: stored {stored_output:?}, computed {computed_output:?}"
        )));
    }
    Ok(summary)
}

fn load_facts(conn: &rusqlite::Connection, id: i64) -> Result<Vec<ClassSetSummaryFactRow>> {
    let mut s = conn.prepare_cached(FACTS_SQL)?;
    let rows = s.query_map(params![id], |r| {
        Ok((
            r.get::<_, u32>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<Vec<u8>>>(3)?,
            r.get::<_, Option<Vec<u8>>>(4)?,
            r.get::<_, Option<Vec<u8>>>(5)?,
            r.get::<_, bool>(6)?,
        ))
    })?;
    rows.map(|r| {
        let (ordinal, kind, source, source_key, carrier, sink, uncertain) = r?;
        let source = match (source.as_str(), source_key) {
            ("none", None) => ClassSetSummaryFactSourceRow::None,
            ("entry", None) => ClassSetSummaryFactSourceRow::Entry,
            ("event", Some(k)) => ClassSetSummaryFactSourceRow::Event(k),
            _ => return Err(StoreError::new("class-set fact source shape is corrupt")),
        };
        let shape = match (kind.as_str(), carrier, sink) {
            ("zero", None, None) => ClassSetSummaryFactShapeRow::Zero,
            ("carrier", Some(k), None) => ClassSetSummaryFactShapeRow::Carrier {
                source,
                carrier_key: k,
                uncertain,
            },
            ("meeting", None, Some(k)) => ClassSetSummaryFactShapeRow::Meeting {
                source,
                sink_event_key: k,
                uncertain,
            },
            _ => return Err(StoreError::new("class-set fact shape is corrupt")),
        };
        Ok(ClassSetSummaryFactRow { ordinal, shape })
    })
    .collect()
}
fn load_exits(conn: &rusqlite::Connection, id: i64) -> Result<Vec<ClassSetSummaryExitRow>> {
    load_rows(conn, EXITS_SQL, id, |o, k, f, q| {
        Ok(ClassSetSummaryExitRow {
            ordinal: o,
            kind: match k.as_str() {
                "normal" => ClassSetSummaryExitKindRow::Normal,
                "exceptional" => ClassSetSummaryExitKindRow::Exceptional,
                _ => return Err(StoreError::new("class-set exit kind is corrupt")),
            },
            fact_ordinal: f,
            quality_mask: q,
        })
    })
}
fn load_reached(conn: &rusqlite::Connection, id: i64) -> Result<Vec<ClassSetSummaryReachedRow>> {
    let mut s = conn.prepare_cached(REACHED_SQL)?;
    let rows = s.query_map(params![id], |r| {
        Ok((
            r.get::<_, u32>(0)?,
            r.get::<_, u32>(1)?,
            r.get::<_, u32>(2)?,
            r.get::<_, u8>(3)?,
        ))
    })?;
    rows.map(|r| {
        let (o, p, f, q) = r?;
        Ok(ClassSetSummaryReachedRow {
            ordinal: o,
            point_id: p,
            fact_ordinal: f,
            quality_mask: q,
        })
    })
    .collect()
}
fn load_dependencies(
    conn: &rusqlite::Connection,
    id: i64,
) -> Result<Vec<ClassSetSummaryDependencyRow>> {
    let mut s = conn.prepare_cached(DEPENDENCIES_SQL)?;
    let rows = s.query_map(params![id], |r| {
        Ok((
            r.get::<_, u32>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, Vec<u8>>(2)?,
            r.get::<_, Vec<u8>>(3)?,
            r.get::<_, Vec<u8>>(4)?,
        ))
    })?;
    rows.map(|r| {
        let (ordinal, lineage, entry, output, lookup) = r?;
        Ok(ClassSetSummaryDependencyRow {
            ordinal,
            callee_procedure_lineage: digest(lineage, "dependency lineage")?,
            callee_entry_selector_digest: digest(entry, "dependency entry selector")?,
            expected_output_digest: ClassSetSummaryOutputDigest::new(digest(
                output,
                "dependency output",
            )?),
            consumed_child_lookup_digest: digest(lookup, "dependency lookup")?,
        })
    })
    .collect()
}
fn load_reads(conn: &rusqlite::Connection, id: i64) -> Result<Vec<ClassSetSummaryReadRow>> {
    let mut s = conn.prepare_cached(READS_SQL)?;
    let mut rows = s.query(params![id])?;
    let mut reads = Vec::new();
    while let Some(row) = rows.next()? {
        reads.push(ClassSetSummaryReadRow {
            ordinal: row.get(12)?,
            key: decode_read_key(row)?,
        });
    }
    Ok(reads)
}
fn load_charges(conn: &rusqlite::Connection, id: i64) -> Result<Vec<ClassSetSummaryChargeRow>> {
    let mut s = conn.prepare_cached(CHARGES_SQL)?;
    let rows = s.query_map(params![id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?))
    })?;
    rows.map(|r| {
        let (kind, amount) = r?;
        Ok(ClassSetSummaryChargeRow { kind, amount })
    })
    .collect()
}
fn load_rows<T>(
    conn: &rusqlite::Connection,
    sql: &str,
    id: i64,
    decode: impl Fn(u32, String, u32, u8) -> Result<T>,
) -> Result<Vec<T>> {
    let mut s = conn.prepare_cached(sql)?;
    let rows = s.query_map(params![id], |r| {
        Ok((
            r.get::<_, u32>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, u32>(2)?,
            r.get::<_, u8>(3)?,
        ))
    })?;
    rows.map(|r| {
        let (o, k, f, q) = r?;
        decode(o, k, f, q)
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::*;
    // Every EXPLAIN QUERY PLAN pin below runs its assertions once against a
    // store with no planner statistics and once with the statistics captured
    // from real corpus stores, because production carries the latter (#3016).
    use crate::analyzer::read_ledger::{CallSiteLocator, LookupKind, LookupQuestion};
    use crate::analyzer::semantic::ids::StableDigest;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    const BLOB: &str = "1111111111111111111111111111111111111111";
    const REPLACEMENT_BLOB: &str = "2222222222222222222222222222222222222222";

    fn digest_byte(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn insert_complete_blob(store: &AnalyzerStore, oid: &str, generation: i64) {
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'python', ?2)",
            params![oid, generation],
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
            params![oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blob_payload_costs(blob_id, payload_bytes)
             SELECT id, 0 FROM blobs WHERE blob_oid = ?1 AND lang = 'python'",
            params![oid],
        )
        .unwrap();
    }

    fn store_with_blob() -> AnalyzerStore {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        insert_complete_blob(&store, BLOB, 0);
        store
    }

    fn row(lookup: u8) -> ClassSetSummaryRow {
        ClassSetSummaryRow::try_new(
            ClassSetSummaryHeaderRow {
                key: ClassSetSummaryRowKey {
                    lookup_digest: digest_byte(lookup),
                    procedure_lineage: digest_byte(2),
                },
                attachment: ClassSetSummaryAttachment {
                    rel_path: "src/app.py".to_string(),
                    blob_oid: BLOB.to_string(),
                    language: Language::Python,
                },
                artifact_public_identity: digest_byte(3),
                artifact_content_identity: digest_byte(4),
                schema_version: 1,
                semantics_digest: digest_byte(5),
                context_digest: digest_byte(6),
                behavior_read_digest: digest_byte(7),
                dependency_digest: digest_byte(8),
                carrier_digest: digest_byte(9),
                field_slots_digest: digest_byte(10),
                entry_fact_ordinal: 1,
            },
            vec![
                ClassSetSummaryFactRow {
                    ordinal: 2,
                    shape: ClassSetSummaryFactShapeRow::Meeting {
                        source: ClassSetSummaryFactSourceRow::Event(vec![33; 32]),
                        sink_event_key: vec![44; 32],
                        uncertain: true,
                    },
                },
                ClassSetSummaryFactRow {
                    ordinal: 0,
                    shape: ClassSetSummaryFactShapeRow::Zero,
                },
                ClassSetSummaryFactRow {
                    ordinal: 1,
                    shape: ClassSetSummaryFactShapeRow::Carrier {
                        source: ClassSetSummaryFactSourceRow::Entry,
                        carrier_key: vec![22; 32],
                        uncertain: false,
                    },
                },
            ],
            vec![ClassSetSummaryExitRow {
                ordinal: 0,
                kind: ClassSetSummaryExitKindRow::Normal,
                fact_ordinal: 1,
                quality_mask: 1,
            }],
            vec![ClassSetSummaryReachedRow {
                ordinal: 0,
                point_id: 7,
                fact_ordinal: 2,
                quality_mask: 6,
            }],
            vec![ClassSetSummaryDependencyRow {
                ordinal: 0,
                callee_procedure_lineage: digest_byte(11),
                callee_entry_selector_digest: digest_byte(12),
                expected_output_digest: ClassSetSummaryOutputDigest::new(digest_byte(13)),
                consumed_child_lookup_digest: digest_byte(14),
            }],
            vec![ClassSetSummaryReadRow {
                ordinal: 0,
                key: ReadKey::Lookup {
                    kind: LookupKind::Dispatch,
                    question: LookupQuestion::CallSite {
                        rel_path: Box::from("src/callee.py"),
                        artifact: StableDigest::sha256(b"callee"),
                        site: CallSiteLocator {
                            start_byte: 12,
                            end_byte: 19,
                        },
                    },
                    digest: StableDigest::sha256(b"targets"),
                },
            }],
            vec![
                ClassSetSummaryChargeRow {
                    kind: "propagated_outputs".to_string(),
                    amount: 2,
                },
                ClassSetSummaryChargeRow {
                    kind: "callback_rows".to_string(),
                    amount: 2,
                },
            ],
        )
        .unwrap()
    }

    fn relation_row(remap_ordinals: bool) -> ClassSetSummaryRow {
        let template = row(1);
        let zero = template.facts[0].shape.clone();
        let carrier = template.facts[1].shape.clone();
        let meeting = template.facts[2].shape.clone();
        let (facts, entry_fact_ordinal, carrier_fact, meeting_fact) = if remap_ordinals {
            (
                vec![
                    ClassSetSummaryFactRow {
                        ordinal: 0,
                        shape: meeting,
                    },
                    ClassSetSummaryFactRow {
                        ordinal: 1,
                        shape: zero,
                    },
                    ClassSetSummaryFactRow {
                        ordinal: 2,
                        shape: carrier,
                    },
                ],
                2,
                2,
                0,
            )
        } else {
            (template.facts.clone(), 1, 1, 2)
        };
        let (normal_ordinal, exceptional_ordinal) = if remap_ordinals { (1, 0) } else { (0, 1) };
        let (meeting_ordinal, carrier_ordinal) = if remap_ordinals { (1, 0) } else { (0, 1) };
        let mut header = template.header;
        header.entry_fact_ordinal = entry_fact_ordinal;
        ClassSetSummaryRow::try_new(
            header,
            facts,
            vec![
                ClassSetSummaryExitRow {
                    ordinal: normal_ordinal,
                    kind: ClassSetSummaryExitKindRow::Normal,
                    fact_ordinal: carrier_fact,
                    quality_mask: 1,
                },
                ClassSetSummaryExitRow {
                    ordinal: exceptional_ordinal,
                    kind: ClassSetSummaryExitKindRow::Exceptional,
                    fact_ordinal: meeting_fact,
                    quality_mask: 4,
                },
            ],
            vec![
                ClassSetSummaryReachedRow {
                    ordinal: meeting_ordinal,
                    point_id: 7,
                    fact_ordinal: meeting_fact,
                    quality_mask: 6,
                },
                ClassSetSummaryReachedRow {
                    ordinal: carrier_ordinal,
                    point_id: 9,
                    fact_ordinal: carrier_fact,
                    quality_mask: 2,
                },
            ],
            template.dependencies,
            template.reads,
            template.charges,
        )
        .unwrap()
    }

    fn replacement_row() -> ClassSetSummaryRow {
        let mut replacement = row(1);
        replacement.header.dependency_digest = digest_byte(81);
        replacement.reached[0].point_id = 8;
        replacement.dependencies[0].expected_output_digest =
            ClassSetSummaryOutputDigest::new(digest_byte(82));
        replacement.dependencies[0].consumed_child_lookup_digest = digest_byte(83);
        replacement.content_digest = replacement.canonical_content_digest();
        replacement
    }

    fn evidence_only_replacement_row() -> ClassSetSummaryRow {
        let mut replacement = row(1);
        replacement.header.dependency_digest = digest_byte(91);
        replacement.dependencies[0].expected_output_digest =
            ClassSetSummaryOutputDigest::new(digest_byte(92));
        replacement.dependencies[0].consumed_child_lookup_digest = digest_byte(93);
        replacement.content_digest = replacement.canonical_content_digest();
        replacement
    }

    #[test]
    fn output_digest_excludes_metadata_dependencies_reads_and_charges() {
        let expected = row(1);
        let mut changed = row(2);
        changed.header.key.procedure_lineage = digest_byte(21);
        changed.header.attachment.rel_path = "src/other.py".to_owned();
        changed.header.attachment.blob_oid = REPLACEMENT_BLOB.to_owned();
        changed.header.attachment.language = Language::Go;
        changed.header.artifact_public_identity = digest_byte(22);
        changed.header.artifact_content_identity = digest_byte(23);
        changed.header.schema_version = 2;
        changed.header.semantics_digest = digest_byte(24);
        changed.header.context_digest = digest_byte(25);
        changed.header.behavior_read_digest = digest_byte(26);
        changed.header.dependency_digest = digest_byte(27);
        changed.header.carrier_digest = digest_byte(28);
        changed.header.field_slots_digest = digest_byte(29);
        changed.header.entry_fact_ordinal = 0;
        changed.facts[0].shape = ClassSetSummaryFactShapeRow::Carrier {
            source: ClassSetSummaryFactSourceRow::Entry,
            carrier_key: vec![98; 32],
            uncertain: true,
        };
        changed.dependencies[0].callee_procedure_lineage = digest_byte(30);
        changed.dependencies[0].callee_entry_selector_digest = digest_byte(31);
        changed.dependencies[0].expected_output_digest =
            ClassSetSummaryOutputDigest::new(digest_byte(32));
        changed.dependencies[0].consumed_child_lookup_digest = digest_byte(33);
        changed.reads[0].key = ReadKey::Configuration(StableDigest::sha256(b"configuration"));
        changed.charges[0].amount = 99;
        changed.charges[1].amount = 100;

        assert_ne!(
            expected.canonical_content_digest(),
            changed.canonical_content_digest()
        );
        assert_eq!(expected.output_digest(), changed.output_digest());
    }

    #[test]
    fn relation_only_output_digest_matches_the_full_row_path() {
        for summary in [relation_row(false), relation_row(true)] {
            assert_eq!(
                class_set_summary_output_digest(&summary.facts, &summary.exits, &summary.reached,)
                    .unwrap(),
                summary.output_digest()
            );
        }
    }

    #[test]
    fn relation_only_output_digest_rejects_an_absent_fact_reference() {
        let summary = row(1);
        let mut exits = summary.exits.clone();
        exits[0].fact_ordinal = 99;

        let error =
            class_set_summary_output_digest(&summary.facts, &exits, &summary.reached).unwrap_err();
        assert!(error.to_string().contains("absent fact 99"), "{error}");
    }

    #[test]
    fn output_digest_changes_with_every_relation_output_dimension() {
        let expected = row(1).output_digest();
        let mut changes = Vec::new();

        let mut fact = row(1);
        fact.facts[1].shape = ClassSetSummaryFactShapeRow::Carrier {
            source: ClassSetSummaryFactSourceRow::Entry,
            carrier_key: vec![99; 32],
            uncertain: false,
        };
        changes.push(fact);

        let mut exit_kind = row(1);
        exit_kind.exits[0].kind = ClassSetSummaryExitKindRow::Exceptional;
        changes.push(exit_kind);

        let mut exit_quality = row(1);
        exit_quality.exits[0].quality_mask = 2;
        changes.push(exit_quality);

        let mut reached_point = row(1);
        reached_point.reached[0].point_id = 8;
        changes.push(reached_point);

        let mut reached_fact = row(1);
        reached_fact.reached[0].fact_ordinal = 0;
        changes.push(reached_fact);

        let mut reached_quality = row(1);
        reached_quality.reached[0].quality_mask = 4;
        changes.push(reached_quality);

        for changed in changes {
            assert_ne!(expected, changed.output_digest(), "{changed:#?}");
        }
    }

    #[test]
    fn output_digest_canonicalizes_fact_and_relation_ordinals() {
        let canonical = relation_row(false);
        let remapped = relation_row(true);

        assert_ne!(
            canonical.canonical_content_digest(),
            remapped.canonical_content_digest(),
            "storage ordinals remain part of canonical stored content"
        );
        assert_eq!(canonical.output_digest(), remapped.output_digest());
    }

    #[test]
    fn a_complete_normalized_summary_round_trips_and_republishes_as_a_noop() {
        let store = store_with_blob();
        let expected = row(1);
        assert!(
            store
                .publish_class_set_summary(expected.clone(), &CancellationToken::new())
                .unwrap()
        );
        assert!(
            !store
                .publish_class_set_summary(expected.clone(), &CancellationToken::new())
                .unwrap()
        );
        assert!(
            store
                .contains_class_set_summary_procedure(digest_byte(2))
                .unwrap()
        );
        assert_eq!(
            store.class_set_summary_for_digest(digest_byte(1)).unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn reverse_dependency_queries_return_exact_deterministic_evidence() {
        let store = store_with_blob();
        let first = row(2);
        let mut second = row(1);
        second.header.key.procedure_lineage = digest_byte(42);
        second.content_digest = second.canonical_content_digest();
        for summary in [&first, &second] {
            store
                .publish_class_set_summary(summary.clone(), &CancellationToken::new())
                .unwrap();
        }

        let expected = vec![
            ClassSetSummaryDependentRow {
                dependent_lookup_digest: digest_byte(1),
                dependency: second.dependencies[0].clone(),
            },
            ClassSetSummaryDependentRow {
                dependent_lookup_digest: digest_byte(2),
                dependency: first.dependencies[0].clone(),
            },
        ];
        assert_eq!(
            store
                .class_set_summary_dependents_of_lookup(digest_byte(14))
                .unwrap(),
            expected
        );
        assert_eq!(
            store
                .class_set_summary_dependents_of_lineage_entry(digest_byte(11), digest_byte(12),)
                .unwrap(),
            expected
        );
        assert!(
            store
                .class_set_summary_dependents_of_lookup(digest_byte(99))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .class_set_summary_dependents_of_read(&first.reads[0].key)
                .unwrap(),
            vec![digest_byte(1), digest_byte(2)]
        );
    }

    #[test]
    fn a_corrupt_stored_output_digest_fails_closed() {
        let store = store_with_blob();
        store
            .publish_class_set_summary(row(1), &CancellationToken::new())
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE class_set_summaries SET output_digest = ?1",
                params![digest_byte(99).as_slice()],
            )
            .unwrap();

        let error = store
            .class_set_summary_for_digest(digest_byte(1))
            .unwrap_err();
        assert!(
            error.to_string().contains("output digest mismatch"),
            "{error}"
        );
    }

    #[test]
    fn corrupt_structured_read_columns_fail_lossless_reconstruction() {
        let store = store_with_blob();
        store
            .publish_class_set_summary(row(1), &CancellationToken::new())
            .unwrap();
        let conn = store.conn.lock().unwrap();
        let shape_error = conn
            .execute(
                "UPDATE class_set_summary_reads SET languages = 'python'",
                [],
            )
            .unwrap_err();
        assert!(shape_error.to_string().contains("CHECK constraint failed"));
        conn.execute(
            "UPDATE class_set_summary_reads SET digest = ?1",
            params![digest_byte(99).as_slice()],
        )
        .unwrap();
        drop(conn);

        let error = store
            .class_set_summary_for_digest(digest_byte(1))
            .unwrap_err();
        assert!(error.to_string().contains("did not rebuild"), "{error}");
    }

    #[test]
    fn the_same_lookup_digest_cannot_name_different_content() {
        let store = store_with_blob();
        store
            .publish_class_set_summary(row(1), &CancellationToken::new())
            .unwrap();
        let mut changed = row(1);
        changed.reached[0].point_id = 8;
        changed.content_digest = changed.canonical_content_digest();
        let error = store
            .publish_class_set_summary(changed, &CancellationToken::new())
            .unwrap_err();
        assert!(error.to_string().contains("different content"), "{error}");
    }

    #[test]
    fn checked_replacement_changes_dependency_and_output_evidence_atomically() {
        let store = store_with_blob();
        let original = row(1);
        let replacement = replacement_row();
        assert_ne!(original.output_digest(), replacement.output_digest());
        store
            .publish_class_set_summary(original.clone(), &CancellationToken::new())
            .unwrap();

        assert!(
            store
                .replace_class_set_summary(
                    *original.content_digest(),
                    replacement.clone(),
                    &CancellationToken::new(),
                )
                .unwrap()
        );
        assert_eq!(
            store.class_set_summary_for_digest(digest_byte(1)).unwrap(),
            Some(replacement.clone())
        );
        assert!(
            store
                .class_set_summary_dependents_of_lookup(digest_byte(14))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .class_set_summary_dependents_of_lookup(digest_byte(83))
                .unwrap(),
            vec![ClassSetSummaryDependentRow {
                dependent_lookup_digest: digest_byte(1),
                dependency: replacement.dependencies[0].clone(),
            }]
        );
        let conn = store.conn.lock().unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM class_set_summaries", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            1,
            "replacement must not accumulate same-lookup history"
        );
        drop(conn);

        assert!(
            !store
                .replace_class_set_summary(
                    *original.content_digest(),
                    replacement,
                    &CancellationToken::new(),
                )
                .unwrap(),
            "retrying an already-current replacement is idempotent"
        );
    }

    #[test]
    fn checked_replacement_supports_equal_output_stabilization() {
        let store = store_with_blob();
        let original = row(1);
        let replacement = evidence_only_replacement_row();
        assert_eq!(original.output_digest(), replacement.output_digest());
        assert_ne!(original.content_digest(), replacement.content_digest());
        store
            .publish_class_set_summary(original.clone(), &CancellationToken::new())
            .unwrap();

        assert!(
            store
                .replace_class_set_summary(
                    *original.content_digest(),
                    replacement.clone(),
                    &CancellationToken::new(),
                )
                .unwrap()
        );
        assert_eq!(
            store.class_set_summary_for_digest(digest_byte(1)).unwrap(),
            Some(replacement)
        );
    }

    #[test]
    fn checked_replacement_rejects_a_stale_expected_row() {
        let store = store_with_blob();
        let original = row(1);
        let replacement = replacement_row();
        store
            .publish_class_set_summary(original.clone(), &CancellationToken::new())
            .unwrap();
        store
            .replace_class_set_summary(
                *original.content_digest(),
                replacement.clone(),
                &CancellationToken::new(),
            )
            .unwrap();
        let mut next = replacement.clone();
        next.reached[0].point_id = 9;
        next.content_digest = next.canonical_content_digest();

        let error = store
            .replace_class_set_summary(*original.content_digest(), next, &CancellationToken::new())
            .unwrap_err();
        assert!(error.to_string().contains("stale current row"), "{error}");
        assert_eq!(
            store.class_set_summary_for_digest(digest_byte(1)).unwrap(),
            Some(replacement)
        );
    }

    #[test]
    fn cancelled_replacement_rolls_back_the_delete_and_candidate() {
        let store = store_with_blob();
        let original = row(1);
        store
            .publish_class_set_summary(original.clone(), &CancellationToken::new())
            .unwrap();
        let cancellation = CancellationToken::cancel_after_checks_for_test(4);

        let error = store
            .replace_class_set_summary(*original.content_digest(), replacement_row(), &cancellation)
            .unwrap_err();
        assert!(error.to_string().contains("cancelled"), "{error}");
        assert_eq!(
            store.class_set_summary_for_digest(digest_byte(1)).unwrap(),
            Some(original)
        );
        let conn = store.conn.lock().unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM class_set_summaries", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            1
        );
    }

    #[test]
    fn cancellation_after_the_header_insert_rolls_back_every_row() {
        let store = store_with_blob();
        let cancellation = CancellationToken::cancel_after_checks_for_test(4);
        let error = store
            .publish_class_set_summary(row(1), &cancellation)
            .unwrap_err();
        assert!(error.to_string().contains("cancelled"), "{error}");
        let conn = store.conn.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM class_set_summaries", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn an_incomplete_owner_blob_cannot_publish_a_summary() {
        let store = store_with_blob();
        store
            .conn
            .lock()
            .unwrap()
            .execute("UPDATE blob_meta SET is_complete = 0", [])
            .unwrap();
        let error = store
            .publish_class_set_summary(row(1), &CancellationToken::new())
            .unwrap_err();
        assert!(error.to_string().contains("owner blob"), "{error}");
        assert_eq!(
            store.class_set_summary_for_digest(digest_byte(1)).unwrap(),
            None
        );
    }

    #[test]
    fn a_published_summary_is_hidden_when_its_owner_becomes_incomplete() {
        let store = store_with_blob();
        store
            .publish_class_set_summary(row(1), &CancellationToken::new())
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute("UPDATE blob_meta SET is_complete = 0", [])
            .unwrap();

        assert!(
            !store
                .contains_class_set_summary_procedure(digest_byte(2))
                .unwrap()
        );
        assert_eq!(
            store.class_set_summary_for_digest(digest_byte(1)).unwrap(),
            None
        );
    }

    #[test]
    fn stale_hidden_summary_does_not_block_current_generation_publication() {
        let store = store_with_blob();
        store
            .publish_class_set_summary(row(1), &CancellationToken::new())
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO analysis_epochs(lang, epoch, generation)
                 VALUES('python', 'next', 1)",
                [],
            )
            .unwrap();

        assert!(
            !store
                .contains_class_set_summary_procedure(digest_byte(2))
                .unwrap()
        );
        assert_eq!(
            store.class_set_summary_for_digest(digest_byte(1)).unwrap(),
            None
        );

        insert_complete_blob(&store, REPLACEMENT_BLOB, 1);
        let mut replacement = row(1);
        replacement.header.attachment.blob_oid = REPLACEMENT_BLOB.to_string();
        replacement.content_digest = replacement.canonical_content_digest();
        assert!(
            store
                .publish_class_set_summary(replacement.clone(), &CancellationToken::new())
                .unwrap()
        );
        assert_eq!(
            store.class_set_summary_for_digest(digest_byte(1)).unwrap(),
            Some(replacement)
        );
    }

    #[test]
    fn missing_child_rows_fail_closed() {
        let store = store_with_blob();
        store
            .publish_class_set_summary(row(1), &CancellationToken::new())
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute("DELETE FROM class_set_summary_reached", [])
            .unwrap();
        let error = store
            .class_set_summary_for_digest(digest_byte(1))
            .unwrap_err();
        assert!(error.to_string().contains("counts disagree"), "{error}");
    }

    #[test]
    fn corrupt_children_make_idempotent_republication_fail_closed() {
        let store = store_with_blob();
        let summary = row(1);
        store
            .publish_class_set_summary(summary.clone(), &CancellationToken::new())
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute("DELETE FROM class_set_summary_reached", [])
            .unwrap();

        let error = store
            .publish_class_set_summary(summary.clone(), &CancellationToken::new())
            .unwrap_err();
        assert!(error.to_string().contains("counts disagree"), "{error}");
        let error = store
            .replace_class_set_summary(
                *summary.content_digest(),
                replacement_row(),
                &CancellationToken::new(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("counts disagree"), "{error}");
    }

    fn stored_cascade_cost(store: &AnalyzerStore, oid: &str) -> (usize, usize) {
        let conn = store.conn.lock().unwrap();
        conn.query_row(
            &super::super::stored_blob_cascade_costs_sql(1),
            params![oid, "python"],
            |row| Ok((row.get(3)?, row.get::<_, Option<usize>>(4)?.unwrap())),
        )
        .unwrap()
    }

    #[test]
    fn class_set_rows_and_payload_are_charged_to_blob_replacement() {
        let store = store_with_blob();
        let original = row(1);
        let before = stored_cascade_cost(&store, BLOB);
        store
            .publish_class_set_summary(original.clone(), &CancellationToken::new())
            .unwrap();
        let after = stored_cascade_cost(&store, BLOB);

        assert_eq!(after.0 - before.0, 10);
        assert_eq!(after.1 - before.1, 834);

        store
            .replace_class_set_summary(
                *original.content_digest(),
                replacement_row(),
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(
            stored_cascade_cost(&store, BLOB),
            after,
            "same-shaped replacement remains bounded and fully accounted"
        );
    }

    #[test]
    fn class_set_cascade_costs_seek_owner_and_child_indexes() {
        for state in PlannerStatisticsState::BOTH {
            class_set_cascade_costs_seek_owner_and_child_indexes_in(state);
        }
    }

    fn class_set_cascade_costs_seek_owner_and_child_indexes_in(state: PlannerStatisticsState) {
        let store = store_with_blob();
        let conn = store.conn.lock().unwrap();
        state.install(&conn);
        let sql = super::super::stored_blob_cascade_costs_sql(1);
        let mut statement = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let plan = statement
            .query_map(params![BLOB, "python"], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        assert!(
            plan.iter().any(|detail| {
                detail.contains("SEARCH summary_cost USING COVERING INDEX")
                    && detail.contains("class_set_summaries_owner_blob")
            }),
            "{state}: {plan:#?}"
        );
        assert!(
            plan.iter()
                .filter(|detail| detail.contains("SEARCH child_cost USING PRIMARY KEY"))
                .count()
                >= 12,
            "{state}: {plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| {
                !detail.contains("SCAN summary_cost") && !detail.contains("SCAN child_cost")
            }),
            "{state}: {plan:#?}"
        );
    }

    #[test]
    fn deleting_the_owner_blob_cascades_the_whole_summary() {
        let store = store_with_blob();
        let original = row(1);
        store
            .publish_class_set_summary(original.clone(), &CancellationToken::new())
            .unwrap();
        store
            .replace_class_set_summary(
                *original.content_digest(),
                replacement_row(),
                &CancellationToken::new(),
            )
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM blobs WHERE blob_oid = ?1 AND lang = 'python'",
                params![BLOB],
            )
            .unwrap();
        assert_eq!(
            store.class_set_summary_for_digest(digest_byte(1)).unwrap(),
            None
        );
    }

    fn explain(
        store: &AnalyzerStore,
        state: PlannerStatisticsState,
        sql: &str,
        parameter: &[u8],
    ) -> Vec<String> {
        let conn = store.conn.lock().unwrap();
        state.install(&conn);
        let mut statement = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        statement
            .query_map(params![parameter], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
    }

    fn explain_two(
        store: &AnalyzerStore,
        state: PlannerStatisticsState,
        sql: &str,
        first: &[u8],
        second: &[u8],
    ) -> Vec<String> {
        let conn = store.conn.lock().unwrap();
        state.install(&conn);
        let mut statement = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        statement
            .query_map(params![first, second], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
    }

    #[test]
    fn reverse_dependency_queries_seek_the_named_indexes() {
        for state in PlannerStatisticsState::BOTH {
            reverse_dependency_queries_seek_the_named_indexes_in(state);
        }
    }

    fn reverse_dependency_queries_seek_the_named_indexes_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let by_lookup = explain(
            &store,
            state,
            CLASS_SET_SUMMARY_DEPENDENTS_BY_LOOKUP_SQL.as_str(),
            &digest_byte(14),
        );
        assert!(
            by_lookup.iter().any(|detail| {
                detail.contains("SEARCH dependencies USING INDEX")
                    && detail.contains("class_set_summary_dependencies_child_lookup")
            }),
            "{state}: {by_lookup:#?}"
        );
        assert!(
            by_lookup
                .iter()
                .all(|detail| !detail.contains("SCAN dependencies")),
            "{state}: {by_lookup:#?}"
        );

        let by_lineage = explain_two(
            &store,
            state,
            CLASS_SET_SUMMARY_DEPENDENTS_BY_LINEAGE_ENTRY_SQL.as_str(),
            &digest_byte(11),
            &digest_byte(12),
        );
        assert!(
            by_lineage.iter().any(|detail| {
                detail.contains("SEARCH dependencies USING INDEX")
                    && detail.contains("class_set_summary_dependencies_lineage_entry")
            }),
            "{state}: {by_lineage:#?}"
        );
        assert!(
            by_lineage
                .iter()
                .all(|detail| !detail.contains("SCAN dependencies")),
            "{state}: {by_lineage:#?}"
        );

        let by_read = explain(
            &store,
            state,
            CLASS_SET_SUMMARY_DEPENDENTS_BY_READ_SQL.as_str(),
            row(1).reads[0].key.canonical_digest().as_bytes(),
        );
        assert!(
            by_read.iter().any(|detail| {
                detail.contains("SEARCH reads USING")
                    && detail.contains("class_set_summary_reads_by_key")
            }),
            "{state}: {by_read:#?}"
        );
        assert!(
            by_read.iter().all(|detail| !detail.contains("SCAN reads")),
            "{state}: {by_read:#?}"
        );
    }

    #[test]
    fn exact_summary_lookups_seek_the_named_indexes() {
        for state in PlannerStatisticsState::BOTH {
            exact_summary_lookups_seek_the_named_indexes_in(state);
        }
    }

    fn exact_summary_lookups_seek_the_named_indexes_in(state: PlannerStatisticsState) {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let lookup = explain(
            &store,
            state,
            CLASS_SET_SUMMARY_LOOKUP_SQL.as_str(),
            &digest_byte(1),
        );
        assert!(
            lookup
                .iter()
                .any(|detail| detail.contains("SEARCH summaries USING INDEX")
                    && detail.contains("class_set_summaries_lookup")),
            "{state}: {lookup:#?}"
        );
        assert!(
            lookup
                .iter()
                .all(|detail| !detail.contains("SCAN summaries")),
            "{state}: {lookup:#?}"
        );
        for seek in [
            "SEARCH blobs USING INTEGER PRIMARY KEY",
            "SEARCH meta USING PRIMARY KEY",
            "SEARCH active_blob USING INTEGER PRIMARY KEY",
            "SEARCH active_epoch USING PRIMARY KEY",
        ] {
            assert!(
                lookup.iter().any(|detail| detail.contains(seek)),
                "{state}: {lookup:#?}"
            );
        }
        let procedure = explain(
            &store,
            state,
            CLASS_SET_SUMMARY_PROCEDURE_SQL.as_str(),
            &digest_byte(2),
        );
        assert!(
            procedure
                .iter()
                .any(|detail| detail.contains("SEARCH summaries USING INDEX")
                    && detail.contains("class_set_summaries_lineage")),
            "{state}: {procedure:#?}"
        );
        assert!(
            procedure
                .iter()
                .all(|detail| !detail.contains("SCAN summaries")),
            "{state}: {procedure:#?}"
        );

        for (table, sql) in [
            ("class_set_summary_facts", FACTS_SQL),
            ("class_set_summary_exits", EXITS_SQL),
            ("class_set_summary_reached", REACHED_SQL),
            ("class_set_summary_dependencies", DEPENDENCIES_SQL),
            ("class_set_summary_reads", READS_SQL),
            ("class_set_summary_charges", CHARGES_SQL),
        ] {
            let plan = explain(&store, state, sql, &[1]);
            assert!(
                plan.iter().any(|detail| detail.contains("SEARCH")
                    && detail.contains(table)
                    && detail.contains("PRIMARY KEY")),
                "{table} {state}: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains(&format!("SCAN {table}"))),
                "{table} {state}: {plan:#?}"
            );
        }
    }
}
