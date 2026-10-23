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

use git2::Oid;
use rusqlite::types::Value;
use rusqlite::{OptionalExtension, ToSql, TransactionBehavior, params};

use super::{AnalyzerStore, Result, StoreError};
use crate::CancellationToken;
use crate::analyzer::semantic::partial_flow::fixpoint::ProcedurePartialFlows;
use crate::analyzer::semantic::service::SemanticAdapterIdentity;
use crate::analyzer::semantic::{
    ContentIdentity, LengthDelimitedDigest, ProcedureId, ProcedureSemanticsParts,
    SemanticBudgetExceeded, SemanticCapability, SemanticIrVersion, SemanticLanguage, StableDigest,
    WorkspaceMountId, WorkspaceRelativePath,
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
const SEMANTIC_IR_ROWS_VERSION: u32 = 8;

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
#[derive(Debug)]
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
            SemanticIrLoweringOutcome::Complete { parts } => {
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
    let sealed = tx
        .prepare_cached(
            "UPDATE semantic_ir_publications SET publication_state = 'complete'
             WHERE blob_id = ?1 AND publication_state = 'building'",
        )?
        .execute([blob_id])?;
    assert_eq!(
        sealed, 1,
        "semantic IR head for blob {blob_id} was not building"
    );
    Ok(true)
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
 WHERE blobs.blob_oid = ?1 AND blobs.lang = ?2
   AND publications.publication_state = 'complete'
   AND publications.producer_epoch = epochs.producer_epoch";

impl AnalyzerStore {
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
        oid: Oid,
        lang: &str,
    ) -> Result<Option<SemanticIrPublication>> {
        let conn = self.read_conn()?;
        let mut statement = conn.prepare_cached(SEMANTIC_IR_PUBLICATION_SQL)?;
        let publication = statement
            .query_row(params![oid.to_string(), lang], |row| {
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
        "receiver_binding", "construction_return", "source", "evidence",
    ] jsonb [] order "procedure";
    Values => "semantic_ir_values" [
        "procedure", "value", "kind", "ordinal", "multiplicity", "rest_domain",
        "rest_domain_text", "name", "passing_mode", "flag", "magnitude", "float_bits", "text",
        "source", "evidence",
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
        "exceptional_target", "source", "evidence",
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
}

fn usize_to_i64(value: usize) -> i64 {
    i64::try_from(value).expect("semantic IR count fits i64")
}

fn i64_to_usize(value: i64) -> usize {
    usize::try_from(value).expect("stored semantic IR count is non-negative")
}
