//! A blob's lowered semantic IR, stored as rows.
//!
//! A language adapter that lowers at parse time hands the lowered procedures
//! to [`PreparedSemanticIr::prepare`]; the blob writer inserts them with
//! [`insert_semantic_ir_tx`] in the blob's own transaction. A reader looks up
//! the head with [`AnalyzerStore::semantic_ir_publication`] and rebuilds the
//! procedures with [`AnalyzerStore::read_semantic_ir`]. The rows depend only
//! on the blob's bytes and the producer epoch, so they are unit-local facts
//! in the derivation contract's sense. Nothing here is specific to one
//! language; the schema and its conventions are described in migration
//! `0165-semantic-ir-rows.sql`.

mod codes;
mod decode;
mod encode;
#[cfg(test)]
pub(crate) mod tests;

use rusqlite::types::Value;
use rusqlite::{OptionalExtension, ToSql, TransactionBehavior, params};

use super::{AnalyzerStore, Result, StoreError};
use crate::CancellationToken;
use crate::analyzer::semantic::CallTargetObligation;
use crate::analyzer::semantic::partial_flow::fixpoint::ProcedurePartialFlows;
use crate::analyzer::semantic::service::SemanticAdapterIdentity;
use crate::analyzer::semantic::{
    ContentIdentity, LengthDelimitedDigest, ProcedureId, ProcedureSemanticsParts,
    SemanticBudgetExceeded, SemanticCapability, SemanticIrVersion, SemanticLanguage, StableDigest,
    WorkspaceMountId, WorkspaceRelativePath,
};
use crate::analyzer::semantic::{
    FOOTPRINT_COVERAGE_CONTRACT_VERSION, FootprintClass, FootprintDisposition, FootprintExclusion,
    FootprintRefusal, SemanticGapSubject,
};
use codes::RowCode;

/// The row encoding's own version, folded into the producer epoch. Bump it
/// when the encoder or decoder changes what a row means, and when the
/// partial-flow derivation changes: the port table, the kill rules, or the
/// fixpoint. Partial-flow rows are published under the same head as the IR
/// rows, so this is their only version.
///
/// Version 2: the fixpoint keeps facts on a call's result and thrown carriers
/// across the call, as the solver does (partial-flow rule 4).
/// Version 3: each flow records the call sites its paths crossed (`crossed`).
/// Version 4: each head records whether every relation of the procedure is
/// proven complete (`relations_complete`).
/// Version 6: exact Rust field member gaps retain no default memory impacts.
/// Version 7: partial-flow propagation borrows successor facts and skips
/// redundant crossed-call set reduction, processing points in reverse postorder.
/// Version 8: unseeded forward single-predecessor points consume entry state;
/// merges, retreating-edge targets and seeded points retain it. Partial-flow
/// propagation has a facts-visited traversal cap.
/// Version 9: call rows retain deferred member selection, its receiver place
/// and static pointer depth, instead of requiring a pre-resolved member kind.
/// Version 10: normal-return member content is published as Heap output ports,
/// and relation completeness also certifies boundary member port coverage.
/// Version 11 (#8940): post-call heap input ports and indirect formal-store
/// incompleteness alter the persisted partial-flow rows.
/// Version 13 (#9162): every builtin seed of one port shares one seed key, so
/// two relations naming one post-call or entry heap port publish one flow row
/// per (from, to). Version 12 is retired (coordinator ruling, 2026-11-02).
/// Version 14 (#8388, coordinator-assigned; 12 retired, 13 is #9186): a formal's direct stores are
/// separated from stores into its local copy, and post-call storage sharing
/// is asked only for members the callee writes. Both can change persisted
/// partial-flow coverage and ICFG-backed call-rule projection.
// #8386: Rust receiver mode is stored on the receiver value row.
// Version 16 (#9183): each procedure publishes a typed footprint witness.
// Version 18 was held by #9925 before later master rows landed.
// Version 19 (#9794): value-flow rows can carry the ByValueCapture kind.
// Version 20 (#10095): scoped call coverage includes identifier-receiver selectors.
// Version 21 (#10200): Rust zero-parameter callable cleanup coverage.
// Version 22 (#9925, coordinator-assigned): OwnershipUnknown follows ByValueCapture
// in the persisted ValueFlowKind tag order.
// Version 23 (#10461): a parse-time head whose candidate set was truncated by a
// constant limit is stored as Truncated instead of Complete.
// Version 24 (#10466): a rejected return member is a content gap (coverage Open),
// so its head is stored Complete and open, not Truncated.
// Version 25 (#10539): the parse-time fixpoint joins the alternatives of one
// event instead of letting each kill the last, so stored heads gain flows.
// Version 26 (#10582): scalar static classes and relational declared result classes
// (above #10539, which takes 25).
// Version 27 (#10563): stored partial-flow heads change for a procedure with a store
// through a reference prefix followed by a read through that cell (above #10582, which
// takes 26).
// Version 28 (#10683): a procedure whose initialized let copies a nested initializer
// stored a Truncated head; an identity prefix store no longer cycles, so the head is
// Complete with its flows (above #10563, which takes 27).
const SEMANTIC_IR_ROWS_VERSION: u32 = 28;

/// What a parse-time lowerer produced for one blob.
#[derive(Debug)]
#[doc(hidden)]
pub enum SemanticIrLoweringOutcome {
    /// The validated procedures. Go predeclared-builtin assumptions travel
    /// inside the parts.
    Complete {
        parts: Vec<ProcedureSemanticsParts>,
    },
    ExceededBudget(SemanticBudgetExceeded),
    Unsupported(SemanticCapability),
    /// Ambiguous, unknown, or cancelled with a partial result.
    Incomplete {
        label: &'static str,
    },
    Error(String),
    Panicked(String),
}

/// The head values and encoded child rows of one blob, ready to insert.
#[derive(Debug, PartialEq)]
#[doc(hidden)]
pub struct PreparedSemanticIr {
    producer_epoch: String,
    content: ContentIdentity,
    source_bytes: usize,
    outcome: i64,
    detail: Option<String>,
    budget: Option<SemanticBudgetExceeded>,
    procedure_count: usize,
    /// JSON array of builtin names, stored as JSONB.
    go_predeclared_builtins: String,
    rows: encode::EncodedRows,
}

impl PreparedSemanticIr {
    /// `partial_flows` holds one entry per procedure of a complete outcome.
    /// Its rows are encoded in the same pass as the IR, because the flows name
    /// locators and texts that the IR's own interning assigns.
    #[doc(hidden)]
    pub fn prepare(
        outcome: SemanticIrLoweringOutcome,
        partial_flows: Option<&[ProcedurePartialFlows]>,
        producer_epoch: &str,
        content: ContentIdentity,
        source_bytes: usize,
    ) -> Self {
        assert!(!producer_epoch.is_empty());
        assert!(
            partial_flows.is_none()
                || matches!(outcome, SemanticIrLoweringOutcome::Complete { .. }),
            "partial flows accompany a complete outcome only"
        );
        let code = codes::OutcomeTag::of(&outcome).code();
        let mut detail = None;
        let mut budget = None;
        let mut procedure_count = 0;
        let mut go_predeclared_builtins = "[]".to_owned();
        let mut rows = encode::EncodedRows::default();
        match outcome {
            SemanticIrLoweringOutcome::Complete { mut parts } => {
                for procedure in &mut parts {
                    refuse_contradictory_footprint_rows(procedure);
                    let coverage = &procedure.footprint_coverage;
                    assert_eq!(
                        coverage.contract_version,
                        FOOTPRINT_COVERAGE_CONTRACT_VERSION
                    );
                    for obligation in &coverage.call_target_obligations {
                        let call = procedure.call_sites.get(obligation.call.index());
                        let gap = procedure.gaps.get(obligation.gap.index());
                        assert_eq!(call.map(|call| call.id), Some(obligation.call));
                        assert_eq!(gap.map(|gap| gap.id), Some(obligation.gap));
                        let gap = gap.expect("footprint obligation gap exists");
                        assert_eq!(gap.subject, SemanticGapSubject::CallSite(obligation.call));
                        assert_eq!(gap.impacts, obligation.impacts);
                        // No assertion on the CallTarget disposition: a target
                        // gap stays an obligation for its call until dispatch
                        // closes it, whether the class is Represented or
                        // Refused, and refuse_contradictory_footprint_rows
                        // refuses the boundary of an Excluded class with calls.
                    }
                }
                procedure_count = parts.len();
                let encoded = encode::encode(&parts, partial_flows, content);
                go_predeclared_builtins = encoded.go_predeclared_builtins;
                rows = encoded.rows;
            }
            SemanticIrLoweringOutcome::ExceededBudget(exceeded) => budget = Some(exceeded),
            SemanticIrLoweringOutcome::Unsupported(capability) => {
                detail = Some(capability.label().to_owned());
            }
            SemanticIrLoweringOutcome::Incomplete { label } => detail = Some(label.to_owned()),
            SemanticIrLoweringOutcome::Error(message)
            | SemanticIrLoweringOutcome::Panicked(message) => detail = Some(message),
        }
        Self {
            producer_epoch: producer_epoch.to_owned(),
            content,
            source_bytes,
            outcome: code,
            detail,
            budget,
            procedure_count,
            go_predeclared_builtins,
            rows,
        }
    }

    /// The producer epoch the rows were prepared under.
    pub(crate) fn producer_epoch(&self) -> &str {
        &self.producer_epoch
    }

    /// The head row plus every child row.
    #[doc(hidden)]
    pub fn logical_rows(&self) -> usize {
        1 + self.rows.row_count()
    }

    /// An estimate: 4 bytes per integer cell plus the bytes of every text
    /// and blob cell, over the head and the child rows.
    #[doc(hidden)]
    pub fn payload_bytes(&self) -> usize {
        let head = 4 * 8
            + self.producer_epoch.len()
            + self.content.as_bytes().len()
            + self.detail.as_ref().map_or(0, String::len)
            + self.go_predeclared_builtins.len();
        head + self.rows.payload_bytes()
    }

    /// Rows and estimated payload bytes per child table.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn table_census(&self) -> Vec<(&'static str, usize, usize)> {
        Table::ALL
            .iter()
            .map(|table| {
                (
                    table.spec().name,
                    self.rows.rows(*table),
                    self.rows.table_payload_bytes(*table),
                )
            })
            .collect()
    }
}

/// A class assertion cannot prove source exhaustiveness here, but it must
/// agree with the corresponding IR row family before its witness is stored.
fn refuse_contradictory_footprint_rows(procedure: &mut ProcedureSemanticsParts) {
    let present = crate::analyzer::semantic::present_footprint_classes(procedure);
    let coverage = &mut procedure.footprint_coverage;
    let contradiction = FootprintClass::ALL.into_iter().any(|class| {
        let index = (class.code() - 1) as usize;
        if !matches!(
            class,
            FootprintClass::MemoryWrite
                | FootprintClass::MemoryRead
                | FootprintClass::PublicationEscape
                | FootprintClass::StaticGlobal
                | FootprintClass::Capture
                | FootprintClass::NestedCall
                | FootprintClass::CallTarget
                | FootprintClass::NormalExit
                | FootprintClass::ExceptionalExit
                | FootprintClass::DeferredExecution
        ) {
            return false;
        }
        match coverage.classes[index] {
            // Represented means every encountered instance was handled; a class
            // with no instances satisfies that claim.
            FootprintDisposition::Represented => false,
            FootprintDisposition::Excluded(FootprintExclusion::NoInstance) => {
                present.contains(&class)
            }
            FootprintDisposition::Excluded(_) | FootprintDisposition::Refused(_) => false,
        }
    });
    if contradiction {
        coverage.boundary = Err(FootprintRefusal::ContradictoryOwnership);
        debug_assert!(matches!(
            coverage.boundary,
            Err(FootprintRefusal::ContradictoryOwnership)
        ));
    }
}

/// Insert one blob's head as `building`, its child rows, then seal the head
/// `complete`. Returns false when cancelled; the caller rolls back.
#[doc(hidden)]
pub fn insert_semantic_ir_tx(
    tx: &rusqlite::Transaction<'_>,
    blob_id: i64,
    lang: &str,
    prepared: &PreparedSemanticIr,
    cancellation: &CancellationToken,
) -> Result<bool> {
    if cancellation.is_cancelled() {
        return Ok(false);
    }
    let budget = prepared.budget;
    tx.prepare_cached(
        "INSERT INTO semantic_ir_publications(
           blob_id, lang, producer_epoch, content_digest, source_bytes, outcome, detail,
           budget_dimension, budget_limit, budget_attempted, procedure_count, logical_rows,
           payload_bytes, go_predeclared_builtins, publication_state
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, jsonb(?14), 'building')",
    )?
    .execute(params![
        blob_id,
        lang,
        prepared.producer_epoch,
        prepared.content.as_bytes().as_slice(),
        usize_to_i64(prepared.source_bytes),
        prepared.outcome,
        prepared.detail,
        budget.map(|budget| budget.dimension().code()),
        budget.map(|budget| usize_to_i64(budget.limit())),
        budget.map(|budget| usize_to_i64(budget.attempted())),
        usize_to_i64(prepared.procedure_count),
        usize_to_i64(prepared.logical_rows()),
        usize_to_i64(prepared.payload_bytes()),
        prepared.go_predeclared_builtins,
    ])?;
    for &table in Table::ALL {
        let spec = table.spec();
        let cells = prepared.rows.cells(table);
        if cells.is_empty() {
            continue;
        }
        let blob = Value::Integer(blob_id);
        let arity = spec.columns.len() + 1;
        let mut values = Vec::<&dyn ToSql>::with_capacity(cells.len() / spec.columns.len() * arity);
        for row in cells.chunks_exact(spec.columns.len()) {
            values.push(&blob);
            values.extend(row.iter().map(|value| value as &dyn ToSql));
        }
        if !super::row_batch::insert_rows(
            tx,
            &spec.insert_prefix(),
            &spec.row_sql(),
            arity,
            &values,
            cancellation,
        )? {
            return Ok(false);
        }
    }
    if cancellation.is_cancelled() {
        return Ok(false);
    }
    // The digest is taken before the seal, so the head is sealed and digested
    // by one UPDATE and a complete head never has a NULL digest.
    let row_digest = sealed_publication_digest(tx, blob_id)?;
    super::publication::seal(
        tx,
        "semantic_ir_publications",
        "blob_id",
        blob_id,
        &[("row_digest", &row_digest.as_bytes().as_slice())],
    )?;
    Ok(true)
}

/// Recompute a test-mutated publication with the production sealing digest.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn reseal_publication_for_test(conn: &mut rusqlite::Connection, blob_id: i64) -> Result<()> {
    let tx = conn.transaction()?;
    let row_digest = sealed_publication_digest(&tx, blob_id)?;
    tx.execute(
        "UPDATE semantic_ir_publications SET row_digest = ?2 WHERE blob_id = ?1",
        params![blob_id, row_digest.as_bytes().as_slice()],
    )?;
    tx.commit()?;
    Ok(())
}

/// Hash SQLite's final values, including JSONB after `jsonb(?)` and the
/// derived counts written to the sealed head. Each table is read in primary
/// key order; the blob id is deliberately omitted because identical blobs
/// can have different local row ids after replacement.
///
/// A table contributes its column names once and then one digest update per
/// row. Per-cell updates made sealing a large share of parse-time
/// publication: a corpus of a few hundred million cells became billions of
/// tiny SHA-256 updates (#10379).
fn sealed_publication_digest(tx: &rusqlite::Transaction<'_>, blob_id: i64) -> Result<StableDigest> {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-semantic-ir-sealed-publication-rows-v2");
    let head_columns = [
        "lang",
        "producer_epoch",
        "content_digest",
        "source_bytes",
        "outcome",
        "detail",
        "budget_dimension",
        "budget_limit",
        "budget_attempted",
        "procedure_count",
        "logical_rows",
        "payload_bytes",
        "go_predeclared_builtins",
        "publication_state",
    ];
    // The digest describes the sealed head, so it hashes the state the seal
    // writes rather than the stored one. The seal computes it while the head
    // is still building and writes both in one UPDATE.
    let (stored_columns, state_column) = head_columns.split_at(head_columns.len() - 1);
    assert_eq!(state_column, ["publication_state"]);
    let head_sql = format!(
        "SELECT {}, '{}' FROM semantic_ir_publications WHERE blob_id = ?1",
        stored_columns.join(", "),
        super::publication::PublicationState::Complete.as_sql()
    );
    digest.push(b"semantic_ir_publications");
    hash_stored_rows(tx, &head_sql, blob_id, &head_columns, &mut digest)?;
    for &table in Table::ALL {
        let spec = table.spec();
        digest.push(spec.name.as_bytes());
        let sql = format!(
            "SELECT {} FROM {} WHERE blob_id = ?1 ORDER BY {}",
            spec.columns.join(", "),
            spec.name,
            spec.order_by
        );
        hash_stored_rows(tx, &sql, blob_id, spec.columns, &mut digest)?;
    }
    Ok(digest.finish())
}

fn hash_stored_rows(
    tx: &rusqlite::Transaction<'_>,
    sql: &str,
    blob_id: i64,
    columns: &[&str],
    digest: &mut LengthDelimitedDigest,
) -> Result<()> {
    for column in columns {
        digest.push(column.as_bytes());
    }
    let mut statement = tx.prepare_cached(sql)?;
    let mut rows = statement.query([blob_id])?;
    // The column count is fixed and every variable-length value carries its
    // length, so one row's encoding is unambiguous within the table.
    let mut encoded = Vec::new();
    while let Some(row) = rows.next()? {
        encoded.clear();
        for index in 0..columns.len() {
            match row.get_ref(index)? {
                rusqlite::types::ValueRef::Null => encoded.push(0),
                rusqlite::types::ValueRef::Integer(value) => {
                    encoded.push(1);
                    encoded.extend_from_slice(&value.to_le_bytes());
                }
                rusqlite::types::ValueRef::Real(value) => {
                    encoded.push(2);
                    encoded.extend_from_slice(&value.to_bits().to_le_bytes());
                }
                rusqlite::types::ValueRef::Text(value) => {
                    encoded.push(3);
                    encoded.extend_from_slice(&(value.len() as u64).to_le_bytes());
                    encoded.extend_from_slice(value);
                }
                rusqlite::types::ValueRef::Blob(value) => {
                    encoded.push(4);
                    encoded.extend_from_slice(&(value.len() as u64).to_le_bytes());
                    encoded.extend_from_slice(value);
                }
            }
        }
        digest.push(&encoded);
    }
    digest.push(b"end-table");
    Ok(())
}

/// The producer epoch of a lowerer's stored rows: the adapter, the IR
/// schema, the configuration and the row encoding. The dependency
/// fingerprint is deliberately absent, because a parse-time lowerer's output
/// depends on nothing but the file.
#[doc(hidden)]
pub fn semantic_ir_producer_epoch(identity: &SemanticAdapterIdentity) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-semantic-ir-rows-producer-epoch");
    digest.push(identity.adapter.name().as_bytes());
    digest.push(identity.adapter.fingerprint().as_bytes());
    digest.push(SemanticIrVersion::current().as_bytes());
    digest.push(identity.configuration.as_bytes());
    digest.push(&SEMANTIC_IR_ROWS_VERSION.to_le_bytes());
    digest.finish().to_string()
}

/// A valid head: complete and written under the language's active epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct SemanticIrPublication {
    #[doc(hidden)]
    pub blob_id: i64,
    #[doc(hidden)]
    pub content: ContentIdentity,
    #[doc(hidden)]
    pub source_bytes: usize,
    #[doc(hidden)]
    pub outcome: SemanticIrPublicationOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum SemanticIrPublicationOutcome {
    Complete,
    ExceededBudget(SemanticBudgetExceeded),
    Unsupported(SemanticCapability),
    Incomplete(String),
    Error(String),
    Panicked(String),
}

/// Unfiltered state of an exact stored publication key. A non-Present result
/// is not evidence of absence for a reusable semantic answer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum SemanticIrHeadObservation {
    Missing,
    StaleEpoch,
    NotComplete,
    LegacyNoDigest,
    Present {
        blob_id: i64,
        active_epoch: String,
        row_digest: StableDigest,
        content: ContentIdentity,
        source_bytes: usize,
    },
}

fn observe_semantic_ir_head(
    tx: &rusqlite::Connection,
    key: &super::BlobKey,
) -> Result<SemanticIrHeadObservation> {
    let head = tx
        .query_row(
            "SELECT publications.blob_id, publications.producer_epoch,
                publications.publication_state, publications.outcome, publications.row_digest,
                publications.content_digest, epochs.producer_epoch, publications.source_bytes
           FROM blobs
           JOIN semantic_ir_publications AS publications ON publications.blob_id = blobs.id
           LEFT JOIN semantic_ir_producer_epochs AS epochs ON epochs.lang = publications.lang
          WHERE blobs.blob_oid = ?1 AND blobs.lang = ?2 AND blobs.parse_variant = ?3",
            params![key.oid.to_string(), key.lang, key.variant],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((
        blob_id,
        producer_epoch,
        state,
        outcome,
        row_digest,
        content,
        active_epoch,
        source_bytes,
    )) = head
    else {
        return Ok(SemanticIrHeadObservation::Missing);
    };
    let Some(active_epoch) = active_epoch else {
        return Ok(SemanticIrHeadObservation::StaleEpoch);
    };
    if producer_epoch != active_epoch {
        return Ok(SemanticIrHeadObservation::StaleEpoch);
    }
    if super::publication::PublicationState::from_sql(&state)?
        != super::publication::PublicationState::Complete
        || outcome != 0
    {
        return Ok(SemanticIrHeadObservation::NotComplete);
    }
    let Some(row_digest) = row_digest else {
        return Ok(SemanticIrHeadObservation::LegacyNoDigest);
    };
    let row_digest: [u8; 32] = row_digest.try_into().map_err(|value: Vec<u8>| {
        StoreError::new(format!("semantic IR row digest has {} bytes", value.len()))
    })?;
    let content: [u8; 32] = content.try_into().map_err(|value: Vec<u8>| {
        StoreError::new(format!(
            "semantic IR source digest has {} bytes",
            value.len()
        ))
    })?;
    Ok(SemanticIrHeadObservation::Present {
        blob_id,
        active_epoch,
        row_digest: StableDigest::from_array(row_digest),
        content: ContentIdentity::from_digest(StableDigest::from_array(content)),
        source_bytes: i64_to_usize(source_bytes),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum StoredFootprintRefusal {
    CoverageUnavailable,
    OldContract,
    UnknownCode,
    DuplicateClass,
    MissingClass,
    RefusedCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum StoredFootprintCoverage {
    Admitted {
        call_target_obligations: Vec<CallTargetObligation>,
    },
    Refused(StoredFootprintRefusal),
}

/// The mount a reader serves the rows under. Stored locators carry no mount
/// or language, and no path when it is the blob's own; the decoder takes
/// them from here.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct SemanticIrMountScope {
    #[doc(hidden)]
    pub mount: WorkspaceMountId,
    #[doc(hidden)]
    pub path: WorkspaceRelativePath,
    #[doc(hidden)]
    pub language: SemanticLanguage,
    #[doc(hidden)]
    pub content: ContentIdentity,
}

/// Locator fields known before the publication's source identity is observed.
#[derive(Clone, Debug)]
pub struct SemanticIrMountFields {
    pub mount: WorkspaceMountId,
    pub path: WorkspaceRelativePath,
    pub language: SemanticLanguage,
}

impl SemanticIrMountFields {
    fn with_content(&self, content: ContentIdentity) -> SemanticIrMountScope {
        SemanticIrMountScope {
            mount: self.mount,
            path: self.path.clone(),
            language: self.language,
            content,
        }
    }
}

impl SemanticIrMountScope {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new(
        mount: WorkspaceMountId,
        path: WorkspaceRelativePath,
        language: SemanticLanguage,
        content: ContentIdentity,
    ) -> Self {
        Self {
            mount,
            path,
            language,
            content,
        }
    }
}

/// The head lookup. Its validity rule is the one the missing-analysis
/// predicate uses: complete, and written under the active producer epoch.
pub(super) const SEMANTIC_IR_PUBLICATION_SQL: &str = "SELECT publications.blob_id,
       publications.content_digest, publications.source_bytes, publications.outcome,
       publications.detail, publications.budget_dimension, publications.budget_limit,
       publications.budget_attempted
  FROM blobs
  JOIN semantic_ir_publications AS publications ON publications.blob_id = blobs.id
  JOIN semantic_ir_producer_epochs AS epochs ON epochs.lang = publications.lang
 WHERE blobs.blob_oid = ?1 AND blobs.lang = ?2 AND blobs.parse_variant = ?3
   AND publications.publication_state = 'complete'
   AND publications.producer_epoch = epochs.producer_epoch";

impl AnalyzerStore {
    /// Decode a whole publication under the content observed in this snapshot.
    #[doc(hidden)]
    pub fn read_semantic_ir_with_observed_scope(
        &self,
        key: &super::BlobKey,
        fields: &SemanticIrMountFields,
    ) -> Result<(
        SemanticIrHeadObservation,
        Option<Vec<ProcedureSemanticsParts>>,
    )> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let observation = observe_semantic_ir_head(&tx, key)?;
        let parts = match &observation {
            SemanticIrHeadObservation::Present {
                blob_id, content, ..
            } => decode::read_and_decode(&tx, *blob_id, &fields.with_content(*content))?,
            _ => None,
        };
        tx.commit()?;
        Ok((observation, parts))
    }

    /// Decode one procedure's flows under the content observed in this snapshot.
    #[doc(hidden)]
    pub fn read_partial_flows_with_observed_scope(
        &self,
        key: &super::BlobKey,
        fields: &SemanticIrMountFields,
        procedure: ProcedureId,
    ) -> Result<(SemanticIrHeadObservation, Option<ProcedurePartialFlows>)> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let observation = observe_semantic_ir_head(&tx, key)?;
        let flows = match &observation {
            SemanticIrHeadObservation::Present {
                blob_id, content, ..
            } => decode::read_partial_flows(
                &tx,
                *blob_id,
                &fields.with_content(*content),
                procedure.get(),
            )?,
            _ => None,
        };
        tx.commit()?;
        Ok((observation, flows))
    }

    /// Decode one procedure under the content observed in this snapshot.
    #[doc(hidden)]
    pub fn read_semantic_ir_procedure_with_observed_scope(
        &self,
        key: &super::BlobKey,
        fields: &SemanticIrMountFields,
        procedure: ProcedureId,
    ) -> Result<(SemanticIrHeadObservation, Option<ProcedureSemanticsParts>)> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let observation = observe_semantic_ir_head(&tx, key)?;
        let parts = match &observation {
            SemanticIrHeadObservation::Present {
                blob_id, content, ..
            } => decode::read_one_procedure(
                &tx,
                *blob_id,
                &fields.with_content(*content),
                procedure.get(),
            )?,
            _ => None,
        };
        tx.commit()?;
        Ok((observation, parts))
    }

    /// Observe an exact head and active epoch in one SQLite snapshot, without
    /// decoding its children. The lookup has no validity filter.
    #[doc(hidden)]
    pub fn semantic_ir_head_observation(
        &self,
        key: &super::BlobKey,
    ) -> Result<SemanticIrHeadObservation> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let observation = observe_semantic_ir_head(&tx, key)?;
        tx.commit()?;
        Ok(observation)
    }

    /// Observe the head and decode its complete child set from one snapshot.
    /// The caller binds its selected file and variant to `key` before use.
    #[doc(hidden)]
    pub fn read_semantic_ir_with_observation(
        &self,
        key: &super::BlobKey,
        scope: &SemanticIrMountScope,
    ) -> Result<(
        SemanticIrHeadObservation,
        Option<Vec<ProcedureSemanticsParts>>,
    )> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let observation = observe_semantic_ir_head(&tx, key)?;
        let parts = match &observation {
            SemanticIrHeadObservation::Present { blob_id, .. } => {
                decode::read_and_decode(&tx, *blob_id, scope)?
            }
            _ => None,
        };
        tx.commit()?;
        Ok((observation, parts))
    }

    /// Observe and decode one procedure's partial flows in the same snapshot.
    #[doc(hidden)]
    pub fn read_partial_flows_with_observation(
        &self,
        key: &super::BlobKey,
        scope: &SemanticIrMountScope,
        procedure: ProcedureId,
    ) -> Result<(SemanticIrHeadObservation, Option<ProcedurePartialFlows>)> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let observation = observe_semantic_ir_head(&tx, key)?;
        let flows = match &observation {
            SemanticIrHeadObservation::Present { blob_id, .. } => {
                decode::read_partial_flows(&tx, *blob_id, scope, procedure.get())?
            }
            _ => None,
        };
        tx.commit()?;
        Ok((observation, flows))
    }

    /// Observe and decode one procedure's semantic parts in the same snapshot.
    #[doc(hidden)]
    pub fn read_semantic_ir_procedure_with_observation(
        &self,
        key: &super::BlobKey,
        scope: &SemanticIrMountScope,
        procedure: ProcedureId,
    ) -> Result<(SemanticIrHeadObservation, Option<ProcedureSemanticsParts>)> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let observation = observe_semantic_ir_head(&tx, key)?;
        let parts = match &observation {
            SemanticIrHeadObservation::Present { blob_id, .. } => {
                decode::read_one_procedure(&tx, *blob_id, scope, procedure.get())?
            }
            _ => None,
        };
        tx.commit()?;
        Ok((observation, parts))
    }

    /// Read one selected complete publication and its footprint in one snapshot.
    #[doc(hidden)]
    pub fn read_footprint_coverage(
        &self,
        key: &super::BlobKey,
        content: ContentIdentity,
        procedure: ProcedureId,
    ) -> Result<StoredFootprintCoverage> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let result = decode::read_footprint_coverage(&tx, key, content, procedure)?;
        tx.commit()?;
        Ok(result)
    }

    /// Observe the selected head and read its footprint in the same snapshot.
    /// A replaced or absent head cannot supply coverage for this observation.
    #[doc(hidden)]
    pub fn read_footprint_coverage_with_observation(
        &self,
        key: &super::BlobKey,
        content: ContentIdentity,
        procedure: ProcedureId,
    ) -> Result<(SemanticIrHeadObservation, Option<StoredFootprintCoverage>)> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let observation = observe_semantic_ir_head(&tx, key)?;
        let coverage = match &observation {
            SemanticIrHeadObservation::Present {
                content: observed, ..
            } if *observed == content => Some(decode::read_footprint_coverage(
                &tx, key, content, procedure,
            )?),
            _ => None,
        };
        tx.commit()?;
        Ok((observation, coverage))
    }

    /// Read the independent scoped call/control claim from one complete publication.
    #[doc(hidden)]
    pub fn read_call_control_coverage(
        &self,
        key: &super::BlobKey,
        content: ContentIdentity,
        procedure: ProcedureId,
    ) -> Result<StoredFootprintCoverage> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let result = decode::read_call_control_coverage(&tx, key, content, procedure)?;
        tx.commit()?;
        Ok(result)
    }

    /// Install the active producer epoch for one storage language. Returns
    /// whether it changed. Heads written under another epoch stop being
    /// valid; replacing their blob removes them.
    #[doc(hidden)]
    pub fn ensure_semantic_ir_producer_epoch(
        &self,
        storage_language: &str,
        producer_epoch: &str,
    ) -> Result<bool> {
        assert!(!storage_language.is_empty());
        assert!(!producer_epoch.is_empty());
        let storage_language = storage_language.to_owned();
        let producer_epoch = producer_epoch.to_owned();
        self.conn.execute(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let previous = tx
                .query_row(
                    "SELECT producer_epoch FROM semantic_ir_producer_epochs WHERE lang = ?1",
                    [&storage_language],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if previous.as_deref() == Some(producer_epoch.as_str()) {
                tx.commit()?;
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO semantic_ir_producer_epochs(lang, producer_epoch)
                 VALUES(?1, ?2)
                 ON CONFLICT(lang) DO UPDATE SET producer_epoch = excluded.producer_epoch",
                params![storage_language, producer_epoch],
            )?;
            tx.commit()?;
            Ok(true)
        })
    }

    /// The valid head of one blob, or `None` when there is no head or it was
    /// written under another producer epoch.
    #[doc(hidden)]
    pub fn semantic_ir_publication(
        &self,
        key: &super::BlobKey,
    ) -> Result<Option<SemanticIrPublication>> {
        let conn = self.read_conn()?;
        let mut statement = conn.prepare_cached(SEMANTIC_IR_PUBLICATION_SQL)?;
        let publication = statement
            .query_row(params![key.oid.to_string(), key.lang, key.variant], |row| {
                let blob_id: i64 = row.get(0)?;
                let digest: Vec<u8> = row.get(1)?;
                let source_bytes: i64 = row.get(2)?;
                let outcome: i64 = row.get(3)?;
                let detail: Option<String> = row.get(4)?;
                let budget: (Option<i64>, Option<i64>, Option<i64>) =
                    (row.get(5)?, row.get(6)?, row.get(7)?);
                Ok((blob_id, digest, source_bytes, outcome, detail, budget))
            })
            .optional()?;
        Ok(
            publication.map(|(blob_id, digest, source_bytes, outcome, detail, budget)| {
                let digest: [u8; 32] = digest.try_into().unwrap_or_else(|digest: Vec<u8>| {
                    panic!(
                        "semantic_ir_publications blob {blob_id}: content digest has {} bytes",
                        digest.len()
                    )
                });
                SemanticIrPublication {
                    blob_id,
                    content: ContentIdentity::from_digest(StableDigest::from_array(digest)),
                    source_bytes: i64_to_usize(source_bytes),
                    outcome: decode::publication_outcome(blob_id, outcome, detail, budget),
                }
            }),
        )
    }

    /// One procedure's partial flows, read in one transaction, or `None` when
    /// the procedure has no head row. `scope` is the mount the locators of the
    /// blob are rebuilt under, as for [`Self::read_semantic_ir`].
    #[doc(hidden)]
    pub fn read_partial_flows(
        &self,
        blob_id: i64,
        procedure: ProcedureId,
        scope: &SemanticIrMountScope,
    ) -> Result<Option<ProcedurePartialFlows>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let flows = decode::read_partial_flows(&tx, blob_id, scope, procedure.get())?;
        tx.commit()?;
        Ok(flows)
    }

    /// Every procedure's partial flows of one blob in procedure order, read in
    /// one transaction. Use it to read a whole blob's flows: unlike one
    /// [`Self::read_partial_flows`] call per procedure, it decodes the blob's
    /// identities once.
    #[doc(hidden)]
    pub fn read_blob_partial_flows(
        &self,
        blob_id: i64,
        scope: &SemanticIrMountScope,
    ) -> Result<Vec<(ProcedureId, ProcedurePartialFlows)>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let flows = decode::read_blob_partial_flows(&tx, blob_id, scope)?;
        tx.commit()?;
        Ok(flows
            .into_iter()
            .map(|(procedure, flows)| (ProcedureId::new(procedure), flows))
            .collect())
    }

    /// Decode one procedure from its rows in a single read transaction.
    #[doc(hidden)]
    pub fn read_semantic_ir_procedure(
        &self,
        blob_id: i64,
        scope: &SemanticIrMountScope,
        procedure: ProcedureId,
    ) -> Result<ProcedureSemanticsParts> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let parts = decode::read_one_procedure(&tx, blob_id, scope, procedure.get())?;
        tx.commit()?;
        parts.ok_or_else(|| {
            StoreError::new(format!(
                "semantic IR rows of blob {blob_id} are no longer published"
            ))
        })
    }

    /// Every row of one blob, read in one transaction and decoded into the
    /// procedures the lowerer produced. Go builtin assumptions are restored
    /// onto procedure 0.
    #[doc(hidden)]
    pub fn read_semantic_ir(
        &self,
        blob_id: i64,
        scope: &SemanticIrMountScope,
    ) -> Result<Vec<ProcedureSemanticsParts>> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let parts = decode::read_and_decode(&tx, blob_id, scope)?;
        tx.commit()?;
        parts.ok_or_else(|| {
            StoreError::new(format!(
                "semantic IR rows of blob {blob_id} are no longer published"
            ))
        })
    }
}

/// One child table: its name, its columns after `blob_id` in row order, the
/// columns stored as JSONB, and its primary-key order.
#[derive(Debug, Clone, Copy)]
pub(super) struct TableSpec {
    pub(super) name: &'static str,
    pub(super) columns: &'static [&'static str],
    pub(super) jsonb: &'static [&'static str],
    pub(super) order_by: &'static str,
}

impl TableSpec {
    fn insert_prefix(&self) -> String {
        format!(
            "INSERT INTO {}(blob_id, {}) VALUES",
            self.name,
            self.columns.join(", ")
        )
    }

    /// One row's values: the blob id, then each column, JSONB-encoded where
    /// the column is.
    fn row_sql(&self) -> String {
        let cells = self
            .columns
            .iter()
            .map(|column| {
                if self.jsonb.contains(column) {
                    "jsonb(?)"
                } else {
                    "?"
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("(?, {cells})")
    }

    fn select_columns(&self) -> String {
        self.columns
            .iter()
            .map(|column| {
                if self.jsonb.contains(column) {
                    format!("json({column})")
                } else {
                    (*column).to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn select_sql(&self) -> String {
        format!(
            "SELECT {} FROM {} WHERE blob_id = ?1 ORDER BY {}",
            self.select_columns(),
            self.name,
            self.order_by
        )
    }

    /// The rows of one procedure. Only tables with a `procedure` column use it.
    fn select_procedure_sql(&self) -> String {
        assert!(self.columns.first() == Some(&"procedure"));
        format!(
            "SELECT {} FROM {} WHERE blob_id = ?1 AND procedure = ?2 ORDER BY {}",
            self.select_columns(),
            self.name,
            self.order_by
        )
    }
}

macro_rules! tables {
    ($($variant:ident => $name:literal [$($column:literal),+ $(,)?] jsonb [$($jsonb:literal),*] order $order:literal;)+) => {
        /// Every child table of a blob's semantic IR.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(super) enum Table {
            $($variant),+
        }

        impl Table {
            pub(super) const ALL: &'static [Table] = &[$(Table::$variant),+];
            pub(super) const COUNT: usize = Self::ALL.len();

            pub(super) const fn spec(self) -> TableSpec {
                match self {
                    $(Table::$variant => TableSpec {
                        name: $name,
                        columns: &[$($column),+],
                        jsonb: &[$($jsonb),*],
                        order_by: $order,
                    }),+
                }
            }
        }
    };
}

tables! {
    Texts => "semantic_ir_texts" ["text_id", "text"] jsonb [] order "text_id";
    DeclarationSegments => "semantic_ir_declaration_segments" [
        "declaration", "ordinal", "kind", "name", "start_byte", "start_line", "start_column",
        "end_byte", "end_line", "end_column", "occurrence", "sibling_ordinal",
    ] jsonb [] order "declaration, ordinal";
    Locators => "semantic_ir_locators" [
        "locator", "path", "declaration", "role", "start_byte", "start_line", "start_column", "end_byte",
        "end_line", "end_column", "occurrence",
    ] jsonb [] order "locator";
    Procedures => "semantic_ir_procedures" [
        "procedure", "locator", "lexical_parent", "kind", "is_async", "is_generator",
        "is_static", "is_synthetic", "invocation", "dispatch_extensibility", "call_boundary",
        "receiver_binding", "construction_return", "source", "evidence", "has_declared_results",
    ] jsonb [] order "procedure";
    ResultTypeClasses => "semantic_ir_result_type_classes" [
        "procedure", "ordinal", "class",
    ] jsonb [] order "procedure, ordinal";
    Values => "semantic_ir_values" [
        "procedure", "value", "kind", "ordinal", "multiplicity", "rest_domain",
        "rest_domain_text", "name", "passing_mode", "flag", "magnitude", "float_bits", "text",
        "source", "evidence", "static_type_class", "static_origin_call", "static_origin_ordinal",
    ] jsonb [] order "procedure, value";
    Allocations => "semantic_ir_allocations" [
        "procedure", "allocation", "point", "result", "kind", "kind_text", "source", "evidence",
    ] jsonb [] order "procedure, allocation";
    MemoryLocations => "semantic_ir_memory_locations" [
        "procedure", "location", "kind", "base", "member", "property_key", "index_value",
        "constant_index", "index_identity", "lexical_parent", "binding", "value_copy",
        "value_copy_identity", "source", "evidence",
    ] jsonb [] order "procedure, location";
    Captures => "semantic_ir_captures" [
        "procedure", "capture", "point", "callable", "target", "environment", "captured_kind",
        "captured", "destination", "mode", "mode_text", "source", "evidence",
    ] jsonb [] order "procedure, capture";
    CallSites => "semantic_ir_call_sites" [
        "procedure", "call_site", "point", "invocation_mode", "execution_timing", "callee",
        "receiver", "result", "thrown", "normal_results", "target_resolution", "targets",
        "target_evidence", "normal_continuation", "normal_target", "exceptional_continuation",
        "exceptional_target", "source", "evidence", "member", "receiver_place_kind",
        "receiver_place_locator", "receiver_place_location", "receiver_pointer_depth",
    ] jsonb ["normal_results"] order "procedure, call_site";
    CallArguments => "semantic_ir_call_arguments" [
        "procedure", "call_site", "ordinal", "value", "expansion", "domain", "domain_text",
        "keyword",
    ] jsonb [] order "procedure, call_site, ordinal";
    CallableTargets => "semantic_ir_callable_targets" [
        "procedure", "targets", "ordinal", "kind", "local_procedure", "locator",
        "artifact_identity",
    ] jsonb ["artifact_identity"] order "procedure, targets, ordinal";
    SourceMappings => "semantic_ir_source_mappings" [
        "procedure", "mapping", "locator", "kind", "ast_node",
    ] jsonb [] order "procedure, mapping";
    StatementEntries => "semantic_ir_statement_entries" [
        "procedure", "ordinal", "source", "evidence", "point",
    ] jsonb [] order "procedure, ordinal";
    LoopSites => "semantic_ir_loop_sites" [
        "procedure", "ordinal", "source", "evidence", "header", "body",
    ] jsonb [] order "procedure, ordinal";
    Evidence => "semantic_ir_evidence" [
        "procedure", "evidence", "proof", "proof_reason", "completeness",
        "completeness_reason", "sources",
    ] jsonb ["sources"] order "procedure, evidence";
    Gaps => "semantic_ir_gaps" [
        "procedure", "gap", "point", "subject", "subject_a", "subject_b", "capability",
        "impacts", "kind", "budget_dimension", "budget_limit", "budget_attempted", "discharge",
        "detail", "source", "evidence",
    ] jsonb [] order "procedure, gap";
    Blocks => "semantic_ir_blocks" [
        "procedure", "block", "points", "source", "evidence",
    ] jsonb ["points"] order "procedure, block";
    Points => "semantic_ir_points" [
        "procedure", "point", "block", "source", "evidence",
    ] jsonb [] order "procedure, point";
    Events => "semantic_ir_events" [
        "procedure", "point", "ordinal", "effect", "sub_kind", "value_a", "value_b", "value_c",
        "location", "allocation", "call_site", "capture", "gap", "locator", "suspend_point",
        "source", "evidence",
    ] jsonb [] order "procedure, point, ordinal";
    EventTransfers => "semantic_ir_event_transfers" [
        "procedure", "point", "ordinal", "transfer_kind", "transfer_detail", "operation",
        "call_site", "digest",
    ] jsonb [] order "procedure, point, ordinal";
    EventOffsets => "semantic_ir_event_offsets" [
        "procedure", "point", "ordinal", "offset_kind", "magnitude", "offset_value", "negative",
        "allocation", "return_ordinal",
    ] jsonb [] order "procedure, point, ordinal";
    EventCallables => "semantic_ir_event_callables" [
        "procedure", "point", "ordinal", "target_resolution", "targets", "target_evidence",
    ] jsonb [] order "procedure, point, ordinal";
    EventSynchronizations => "semantic_ir_event_synchronizations" [
        "procedure", "point", "ordinal", "payload_kind", "value", "copy_kind", "copy_identity",
    ] jsonb [] order "procedure, point, ordinal";
    EventAsyncSuspends => "semantic_ir_event_async_suspends" [
        "procedure", "point", "ordinal", "normal_continuation", "normal_target",
        "exceptional_continuation", "exceptional_target",
    ] jsonb [] order "procedure, point, ordinal";
    ControlEdges => "semantic_ir_control_edges" [
        "procedure", "ordinal", "source_point", "target_point", "kind", "source", "evidence",
    ] jsonb [] order "procedure, ordinal";
    GuardFacts => "semantic_ir_guard_facts" [
        "procedure", "guard", "point", "subject", "predicate", "flag", "relation", "constant",
        "operand_a", "operand_b", "digest", "true_target", "true_kind", "false_target",
        "false_kind", "source", "evidence",
    ] jsonb [] order "procedure, guard";
    SwitchFacts => "semantic_ir_switch_facts" [
        "procedure", "switch", "kind", "point", "selector", "selector_domain",
        "default_present", "default_source_point", "default_target", "default_kind", "source",
        "evidence",
    ] jsonb [] order "procedure, switch";
    SwitchCases => "semantic_ir_switch_cases" [
        "procedure", "switch", "ordinal", "value", "source_point", "target_point", "edge_kind",
    ] jsonb [] order "procedure, switch, ordinal";
    Drops => "semantic_ir_drops" [
        "procedure", "ordinal", "place_kind", "place_locator", "place_location", "point",
        "behavior", "destructor_resolution", "destructor_targets", "source", "evidence",
    ] jsonb [] order "procedure, ordinal";
    MoveOuts => "semantic_ir_move_outs" [
        "procedure", "ordinal", "place_kind", "place_locator", "place_location", "point",
        "source_value", "target_value", "state_after", "source", "evidence",
    ] jsonb [] order "procedure, ordinal";
    ScopeEnds => "semantic_ir_scope_ends" [
        "procedure", "ordinal", "place_kind", "place_locator", "place_location", "at_kind",
        "at_point", "edge_source", "edge_target", "edge_kind", "source", "evidence",
    ] jsonb [] order "procedure, ordinal";
    PointerOrigins => "semantic_ir_pointer_origins" [
        "procedure", "origin", "point", "kind", "place_kind", "place_locator", "place_location",
        "allocation", "byte_extent", "source", "evidence",
    ] jsonb [] order "procedure, origin";
    PointerAliases => "semantic_ir_pointer_aliases" [
        "procedure", "ordinal", "point", "pointer", "origin", "offset_kind", "offset_exact",
        "offset_value", "offset_min", "offset_max", "strength", "source", "evidence",
    ] jsonb [] order "procedure, ordinal";
    PointerAccesses => "semantic_ir_pointer_accesses" [
        "procedure", "ordinal", "point", "pointer", "kind", "width_kind", "width_exact",
        "width_value", "width_multiplier", "source", "evidence",
    ] jsonb [] order "procedure, ordinal";
    PointerInvalidations => "semantic_ir_pointer_invalidations" [
        "procedure", "ordinal", "point", "target_kind", "target_value", "target_origin", "cause",
        "strength", "source", "evidence",
    ] jsonb [] order "procedure, ordinal";
    IncompleteFacts => "semantic_ir_incomplete_facts" [
        "procedure", "ordinal", "point", "subject", "place_kind", "place_locator",
        "place_location", "value", "origin", "reason_domain", "reason", "source", "evidence",
    ] jsonb [] order "procedure, ordinal";
    ReceiverTypeFacts => "semantic_ir_receiver_type_facts" [
        "procedure", "call_site", "member", "receiver_type",
    ] jsonb ["receiver_type"] order "procedure, call_site";
    GuardedPatternProjections => "semantic_ir_guarded_pattern_projections" [
        "procedure", "ordinal", "point", "whole_value", "binder", "pattern_source",
        "binder_source", "path_len", "status",
    ] jsonb [] order "procedure, ordinal";
    GuardedPatternSteps => "semantic_ir_guarded_pattern_steps" [
        "procedure", "candidate", "step", "kind", "tuple_ordinal", "named_text",
    ] jsonb [] order "procedure, candidate, step";
    PartialPorts => "semantic_ir_ports" [
        "procedure", "port", "kind", "a", "b", "root", "selectors", "tail",
    ] jsonb ["selectors"] order "procedure, port";
    PartialFlows => "semantic_ir_partial_flows" [
        "procedure", "from_port", "to_port", "uncertain", "crossed",
    ] jsonb ["crossed"] order "procedure, from_port, to_port";
    PartialFlowHeads => "semantic_ir_partial_flow_heads" [
        "procedure", "outcome", "detail", "open", "relations_complete", "port_count", "flow_count",
        "discharged_gaps",
    ] jsonb ["discharged_gaps"] order "procedure";
    FootprintCoverage => "semantic_ir_footprint_coverage" [
        "procedure", "contract_version", "boundary_disposition", "boundary_reason",
    ] jsonb [] order "procedure";
    FootprintCoverageClasses => "semantic_ir_footprint_coverage_classes" [
        "procedure", "class", "disposition", "reason",
    ] jsonb [] order "procedure, class";
    FootprintCallTargetObligations => "semantic_ir_footprint_call_target_obligations" [
        "procedure", "call_site", "gap", "impacts",
    ] jsonb [] order "procedure, call_site, gap";
    CallControlCoverage => "semantic_ir_call_control_coverage" [
        "procedure", "contract_version", "source_boundary", "source_reason", "admission", "admission_reason", "obligation_count",
    ] jsonb [] order "procedure";
    CallControlClasses => "semantic_ir_call_control_classes" [
        "procedure", "class", "disposition", "reason",
    ] jsonb [] order "procedure, class";
    CallControlObligations => "semantic_ir_call_control_obligations" [
        "procedure", "call_site", "gap", "impacts",
    ] jsonb [] order "procedure, call_site, gap";
}

fn usize_to_i64(value: usize) -> i64 {
    i64::try_from(value).expect("semantic IR count fits i64")
}

fn i64_to_usize(value: i64) -> usize {
    usize::try_from(value).expect("stored semantic IR count is non-negative")
}
