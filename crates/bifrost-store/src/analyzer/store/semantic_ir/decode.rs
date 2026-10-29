//! Rows back to lowered procedures.
//!
//! The rows were written by this module's encoder in one transaction and
//! checked by the schema, so a row that does not decode is corruption: the
//! decoder panics and names the table, the blob, the row's key and the
//! column.

use rusqlite::Transaction;

use super::codes::{
    AllocationKindTag, ArgumentDomainTag, BackingStoreOffsetTag, CallableReferenceKindTag,
    CallableTargetTag, CaptureModeTag, CaptureSourceTag, CompletenessTag, ContinuationTag,
    DropBehaviorTag, EffectTag, ExpansionTag, GapSubjectTag, GuardPredicateTag,
    IncompleteReasonTag, IncompleteSubjectTag, MemoryLocationKindTag, MemoryValueCopyTag,
    MultiplicityTag, OutcomeTag, PartialPortTag, PlaceTag, PointerAccessWidthTag,
    PointerByteOffsetTag, PointerInvalidationTargetTag, PointerOriginKindTag, ProofTag, RowCode,
    ScopeEndAtTag, SynchronizationPayloadCopyTag, SynchronizationPayloadTag, TargetResolutionTag,
    TransferKindTag, TransferOperationTag, ValueFlowKindTag, ValueKindTag,
};
use super::{SemanticIrMountScope, SemanticIrPublicationOutcome, Table};
use crate::analyzer::semantic::partial_flow::fixpoint::{
    PartialFlow, PartialFlowOutcome, ProcedurePartialFlows,
};
use crate::analyzer::semantic::partial_flow::ports::{HeapSelector, PartialFlowPort, PortId};
use crate::analyzer::semantic::{
    AccessPathTail, AllocationId, AllocationKind, AllocationSite, ArgumentDomain,
    ArtifactCallableTarget, BackingStoreOffset, BasicBlock, BlockId, CallArgumentExpansion,
    CallReceiverTypeFact, CallSiteId, CallableReferenceKind, CallableTarget,
    CallableTargetResolution, CallableValue, CaptureBinding, CaptureId, CaptureMode, CaptureSource,
    ControlContinuation, ControlEdge, DeclarationLocator, DeclarationSegment,
    DeferredMemberSelection, DropBehavior, DropFact, Evidence, EvidenceCompleteness, EvidenceId,
    FormalMultiplicity, GoPredeclaredBuiltin, GuardArm, GuardConditionDigest, GuardFactParts,
    GuardId, GuardPredicate, LoopSite, MemoryLocation, MemoryLocationId, MemoryLocationKind,
    MemoryValueCopy, MoveOutFact, PointerAccess, PointerAccessWidth, PointerAlias,
    PointerByteOffset, PointerInvalidation, PointerInvalidationTarget, PointerOrigin,
    PointerOriginId, PointerOriginKind, ProcedureId, ProcedureProperties, ProcedureSemanticsParts,
    ProgramPoint, ProgramPointId, ProofStatus, ScopeEndAt, ScopeEndFact, SemanticBudgetExceeded,
    SemanticCallArgument, SemanticCallSite, SemanticCapability, SemanticEffect, SemanticEvent,
    SemanticGap, SemanticGapId, SemanticGapImpact, SemanticGapImpacts, SemanticGapSubject,
    SemanticIncompleteFact, SemanticIncompleteReason, SemanticIncompleteSubject, SemanticLocator,
    SemanticPlace, SemanticValue, SemanticValueKind, SignedIntegerMagnitude, SourceAnchor,
    SourceMapping, SourceMappingId, SourcePosition, SourceSpan, StableDigest, StatementEntrySite,
    StructuralNodeIdentity, SwitchCaseFactParts, SwitchEdgeParts, SwitchFactId, SwitchFactParts,
    SynchronizationPayload, SynchronizationPayloadCopy, TransferKind, TransferOperation,
    ValueFlowKind, ValueId, ValueTransfer, WorkspaceRelativePath,
};
use crate::analyzer::store::Result;
use crate::hash::HashMap;

/// The procedure-local id types a row column can hold.
trait LocalId: Copy {
    fn from_raw(raw: u32) -> Self;
}

macro_rules! local_ids {
    ($($id:ident),+ $(,)?) => {
        $(impl LocalId for $id {
            fn from_raw(raw: u32) -> Self {
                $id::new(raw)
            }
        })+
    };
}

local_ids! {
    ProcedureId, BlockId, ProgramPointId, ValueId, AllocationId, CallSiteId, MemoryLocationId,
    CaptureId, SourceMappingId, EvidenceId, SemanticGapId, GuardId, SwitchFactId,
    PointerOriginId,
}

/// Sequential access to one row's columns, in the table's column order.
struct Cells<'r, 's> {
    row: &'r rusqlite::Row<'s>,
    table: Table,
    blob_id: i64,
    next: usize,
    key: [i64; 4],
    key_len: usize,
}

impl Cells<'_, '_> {
    fn fail(&self, column: usize, problem: &str) -> ! {
        let spec = self.table.spec();
        panic!(
            "{} row of blob {} with key {:?} does not decode: column {} {problem}",
            spec.name,
            self.blob_id,
            &self.key[..self.key_len],
            spec.columns.get(column).copied().unwrap_or("<none>"),
        )
    }

    /// A failure of the row as a whole, not of one column.
    fn fail_row(&self, problem: &str) -> ! {
        panic!(
            "{} row of blob {} with key {:?} does not decode: {problem}",
            self.table.spec().name,
            self.blob_id,
            &self.key[..self.key_len],
        )
    }

    fn fail_at(&self, column: &str, problem: &str) -> ! {
        let index = self
            .table
            .spec()
            .columns
            .iter()
            .position(|candidate| *candidate == column)
            .expect("named column exists");
        self.fail(index, problem)
    }

    fn take<T: rusqlite::types::FromSql>(&mut self) -> (usize, T) {
        let column = self.next;
        self.next += 1;
        let value = self
            .row
            .get::<_, T>(column)
            .unwrap_or_else(|error| self.fail(column, &error.to_string()));
        (column, value)
    }

    /// One key column; it is reported in every later failure of this row.
    fn key(&mut self) -> i64 {
        let value = self.int();
        assert!(
            self.key_len < self.key.len(),
            "a key has at most four columns"
        );
        self.key[self.key_len] = value;
        self.key_len += 1;
        value
    }

    fn key_u32(&mut self) -> u32 {
        let column = self.next;
        let value = self.key();
        u32::try_from(value).unwrap_or_else(|_| self.fail(column, "is not a u32"))
    }

    fn opt(&mut self) -> Option<i64> {
        self.take::<Option<i64>>().1
    }

    fn int(&mut self) -> i64 {
        let (column, value) = self.take::<Option<i64>>();
        value.unwrap_or_else(|| self.fail(column, "is NULL"))
    }

    fn opt_u32(&mut self) -> Option<u32> {
        let (column, value) = self.take::<Option<i64>>();
        value
            .map(|value| u32::try_from(value).unwrap_or_else(|_| self.fail(column, "is not a u32")))
    }

    fn u32(&mut self) -> u32 {
        let column = self.next;
        self.opt_u32()
            .unwrap_or_else(|| self.fail(column, "is NULL"))
    }

    fn opt_id<T: LocalId>(&mut self) -> Option<T> {
        self.opt_u32().map(T::from_raw)
    }

    fn id<T: LocalId>(&mut self) -> T {
        T::from_raw(self.u32())
    }

    fn opt_code<T: RowCode>(&mut self) -> Option<T> {
        let (column, value) = self.take::<Option<i64>>();
        value.map(|code| {
            T::try_from_code(code).unwrap_or_else(|| {
                self.fail(
                    column,
                    &format!("holds {code}, not a {}", std::any::type_name::<T>()),
                )
            })
        })
    }

    fn code<T: RowCode>(&mut self) -> T {
        let column = self.next;
        self.opt_code()
            .unwrap_or_else(|| self.fail(column, "is NULL"))
    }

    fn opt_flag(&mut self) -> Option<bool> {
        let (column, value) = self.take::<Option<i64>>();
        value.map(|value| match value {
            0 => false,
            1 => true,
            _ => self.fail(column, "is not a Boolean"),
        })
    }

    fn flag(&mut self) -> bool {
        let column = self.next;
        self.opt_flag()
            .unwrap_or_else(|| self.fail(column, "is NULL"))
    }

    fn opt_text(&mut self) -> Option<String> {
        self.take::<Option<String>>().1
    }

    fn opt_u128(&mut self) -> Option<u128> {
        let (column, value) = self.take::<Option<String>>();
        value.map(|text| {
            text.parse()
                .unwrap_or_else(|_| self.fail(column, "is not a u128 magnitude"))
        })
    }

    fn opt_i128(&mut self) -> Option<i128> {
        let (column, value) = self.take::<Option<String>>();
        value.map(|text| {
            text.parse()
                .unwrap_or_else(|_| self.fail(column, "is not an i128 magnitude"))
        })
    }

    fn opt_digest(&mut self) -> Option<StableDigest> {
        let (column, value) = self.take::<Option<Vec<u8>>>();
        value.map(|bytes| {
            let bytes: [u8; 32] = bytes
                .try_into()
                .unwrap_or_else(|_| self.fail(column, "is not 32 bytes"));
            StableDigest::from_array(bytes)
        })
    }

    fn opt_json_ids(&mut self) -> Option<Vec<i64>> {
        let (column, value) = self.take::<Option<String>>();
        value.map(|text| {
            serde_json::from_str(&text)
                .unwrap_or_else(|error| self.fail(column, &format!("is not an id array: {error}")))
        })
    }

    fn opt_local_ids<T: LocalId>(&mut self) -> Option<Vec<T>> {
        let column = self.next;
        self.opt_json_ids().map(|ids| {
            ids.into_iter()
                .map(|id| {
                    T::from_raw(
                        u32::try_from(id)
                            .unwrap_or_else(|_| self.fail(column, "holds a non-u32 id")),
                    )
                })
                .collect()
        })
    }

    fn local_ids<T: LocalId>(&mut self) -> Vec<T> {
        let column = self.next;
        self.opt_local_ids()
            .unwrap_or_else(|| self.fail(column, "is NULL"))
    }

    /// A value a column must hold for this row's variant.
    fn need<T>(&self, value: Option<T>, column: &str) -> T {
        value.unwrap_or_else(|| self.fail_at(column, "is NULL but the row's variant requires it"))
    }

    fn anchor(&mut self) -> SourceAnchor {
        let start = SourcePosition::new(self.u32(), self.u32(), self.u32());
        let end = SourcePosition::new(self.u32(), self.u32(), self.u32());
        let column = self.next;
        let occurrence = self.u32();
        let span = SourceSpan::new(start, end)
            .unwrap_or_else(|error| self.fail(column, &format!("ends an invalid span: {error}")));
        SourceAnchor::new(span, occurrence)
    }
}

fn each_row(
    tx: &Transaction<'_>,
    blob_id: i64,
    table: Table,
    decode: impl FnMut(&mut Cells<'_, '_>),
) -> Result<()> {
    each_selected_row(
        tx,
        blob_id,
        table,
        &table.spec().select_sql(),
        [blob_id],
        decode,
    )
}

/// The rows of one procedure, for a table with a `procedure` column.
fn each_procedure_row(
    tx: &Transaction<'_>,
    blob_id: i64,
    procedure: u32,
    table: Table,
    decode: impl FnMut(&mut Cells<'_, '_>),
) -> Result<()> {
    each_selected_row(
        tx,
        blob_id,
        table,
        &table.spec().select_procedure_sql(),
        rusqlite::params![blob_id, procedure],
        decode,
    )
}

fn each_selected_row(
    tx: &Transaction<'_>,
    blob_id: i64,
    table: Table,
    sql: &str,
    params: impl rusqlite::Params,
    mut decode: impl FnMut(&mut Cells<'_, '_>),
) -> Result<()> {
    let spec = table.spec();
    let mut statement = tx.prepare_cached(sql)?;
    let mut rows = statement.query(params)?;
    while let Some(row) = rows.next()? {
        let mut cells = Cells {
            row,
            table,
            blob_id,
            next: 0,
            key: [0; 4],
            key_len: 0,
        };
        decode(&mut cells);
        assert_eq!(
            cells.next,
            spec.columns.len(),
            "{} decoder read {} of its columns {:?}",
            spec.name,
            cells.next,
            spec.columns
        );
    }
    Ok(())
}

/// Assert that a dense table's row carries the next id.
fn dense(cells: &Cells<'_, '_>, id: usize, expected: usize) {
    if id != expected {
        cells.fail(
            cells.key_len.saturating_sub(1),
            &format!("is {id}; expected the dense id {expected}"),
        );
    }
}

type EventKey = (u32, u32, u32);

struct Decoder<'a> {
    blob_id: i64,
    scope: &'a SemanticIrMountScope,
    texts: Vec<String>,
    declarations: Vec<Vec<DeclarationSegment>>,
    locators: Vec<SemanticLocator>,
    parts: Vec<ProcedureSemanticsParts>,
    /// Callable target groups per procedure; each is taken by its one owner.
    groups: Vec<Vec<Vec<CallableTarget>>>,
    /// Call arguments per procedure and call site.
    arguments: Vec<Vec<Vec<SemanticCallArgument>>>,
    /// Events per procedure and point.
    events: Vec<Vec<Vec<SemanticEvent>>>,
    transfers: HashMap<EventKey, ValueTransfer>,
    offsets: HashMap<EventKey, OffsetRow>,
    callables: HashMap<EventKey, (CallableTargetResolution, EvidenceId)>,
    synchronizations: HashMap<EventKey, SynchronizationPayload>,
    suspends: HashMap<EventKey, (ControlContinuation, ControlContinuation)>,
}

impl<'a> Decoder<'a> {
    fn new(blob_id: i64, scope: &'a SemanticIrMountScope) -> Self {
        Self {
            blob_id,
            scope,
            texts: Vec::new(),
            declarations: Vec::new(),
            locators: Vec::new(),
            parts: Vec::new(),
            groups: Vec::new(),
            arguments: Vec::new(),
            events: Vec::new(),
            transfers: HashMap::default(),
            offsets: HashMap::default(),
            callables: HashMap::default(),
            synchronizations: HashMap::default(),
            suspends: HashMap::default(),
        }
    }
}

struct OffsetRow {
    kind: Option<BackingStoreOffsetTag>,
    magnitude: Option<u128>,
    value: Option<ValueId>,
    negative: Option<bool>,
    allocation: Option<AllocationId>,
    return_ordinal: Option<u32>,
}

/// Read and decode every row of one blob inside `tx`, or `None` when the
/// blob has no head.
pub(super) fn read_and_decode(
    tx: &Transaction<'_>,
    blob_id: i64,
    scope: &SemanticIrMountScope,
) -> Result<Option<Vec<ProcedureSemanticsParts>>> {
    use rusqlite::OptionalExtension;
    let head = tx
        .prepare_cached(
            "SELECT outcome, publication_state, procedure_count, json(go_predeclared_builtins),
                    content_digest
             FROM semantic_ir_publications WHERE blob_id = ?1",
        )?
        .query_row([blob_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })
        .optional()?;
    let Some((outcome, state, procedure_count, builtins, digest)) = head else {
        return Ok(None);
    };
    assert!(
        outcome == 0 && state == "complete",
        "semantic IR rows of blob {blob_id} are read but the head has outcome {outcome} in state {state}"
    );
    assert_eq!(
        digest.as_slice(),
        scope.content.as_bytes(),
        "semantic IR rows of blob {blob_id} are read for another content"
    );
    let mut decoder = Decoder::new(blob_id, scope);
    decoder.read(tx)?;
    let mut parts = decoder.finish();
    assert_eq!(
        i64::try_from(parts.len()).expect("procedure count fits i64"),
        procedure_count,
        "semantic IR blob {blob_id} head counts {procedure_count} procedures"
    );
    let builtins: Vec<String> = serde_json::from_str(&builtins).unwrap_or_else(|error| {
        panic!("semantic_ir_publications blob {blob_id}: go_predeclared_builtins: {error}")
    });
    if !builtins.is_empty() {
        let first = parts.first_mut().unwrap_or_else(|| {
            panic!("semantic IR blob {blob_id} has Go builtin assumptions but no procedure")
        });
        first.go_predeclared_builtin_assumptions = builtins
            .iter()
            .map(|name| {
                GoPredeclaredBuiltin::from_name(name).unwrap_or_else(|| {
                    panic!("semantic IR blob {blob_id} stores unknown Go builtin {name:?}")
                })
            })
            .collect();
    }
    Ok(Some(parts))
}

/// Decode one head's outcome columns.
/// One procedure's partial flows, or `None` when the procedure has no head
/// row. The locators and texts the ports name are rebuilt under `scope`.
pub(super) fn read_partial_flows(
    tx: &Transaction<'_>,
    blob_id: i64,
    scope: &SemanticIrMountScope,
    procedure: u32,
) -> Result<Option<ProcedurePartialFlows>> {
    use rusqlite::OptionalExtension;
    let head = tx
        .prepare_cached(
            "SELECT outcome, detail, open, relations_complete, port_count, flow_count,
                    json(discharged_gaps)
             FROM semantic_ir_partial_flow_heads WHERE blob_id = ?1 AND procedure = ?2",
        )?
        .query_row(rusqlite::params![blob_id, procedure], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .optional()?;
    let Some((outcome, detail, open, relations_complete, port_count, flow_count, gaps)) = head
    else {
        return Ok(None);
    };
    let outcome = PartialFlowOutcome::try_from_code(outcome).unwrap_or_else(|| {
        panic!(
            "semantic IR partial-flow head of blob {blob_id} procedure {procedure} has outcome {outcome}"
        )
    });
    let open = match open {
        0 => false,
        1 => true,
        other => panic!("semantic IR partial-flow head of blob {blob_id} has open {other}"),
    };
    let relations_complete = match relations_complete {
        0 => false,
        1 => true,
        other => {
            panic!("semantic IR partial-flow head of blob {blob_id} has relations_complete {other}")
        }
    };
    let mut decoder = Decoder::new(blob_id, scope);
    decoder.read_identities(tx)?;
    let detail = detail.map(|id| {
        usize::try_from(id)
            .ok()
            .and_then(|index| decoder.texts.get(index))
            .cloned()
            .unwrap_or_else(|| {
                panic!("semantic IR partial-flow head of blob {blob_id} names missing text {id}")
            })
    });
    // An error head carries its message; a complete head carries the label of
    // a projection outcome that was not complete, and only that.
    match outcome {
        PartialFlowOutcome::Error => assert!(
            detail.is_some(),
            "semantic IR partial-flow head of blob {blob_id} procedure {procedure} is an error without a message"
        ),
        PartialFlowOutcome::Complete => {}
        PartialFlowOutcome::Truncated | PartialFlowOutcome::ExceededBudget => assert!(
            detail.is_none(),
            "semantic IR partial-flow head of blob {blob_id} procedure {procedure} carries text it cannot have"
        ),
    }
    let mut ports = Vec::<PartialFlowPort>::new();
    each_procedure_row(tx, blob_id, procedure, Table::PartialPorts, |cells| {
        cells.key();
        let port = cells.key_u32();
        dense(cells, port as usize, ports.len());
        let kind = cells.code::<PartialPortTag>();
        let a = cells.opt();
        let b = cells.opt();
        let root = cells.opt();
        let selectors = cells.opt_text();
        let tail = cells.opt();
        let decoded = match kind {
            PartialPortTag::Receiver => PartialFlowPort::Receiver,
            PartialPortTag::Parameter => PartialFlowPort::Parameter {
                ordinal: required_u32(cells, a, "ordinal"),
            },
            PartialPortTag::NormalReturn => PartialFlowPort::NormalReturn,
            PartialPortTag::IndexedNormalReturn => PartialFlowPort::IndexedNormalReturn {
                ordinal: required_u32(cells, a, "ordinal"),
            },
            PartialPortTag::ExceptionalReturn => PartialFlowPort::ExceptionalReturn,
            PartialPortTag::CallReceiver => PartialFlowPort::CallReceiver {
                call: CallSiteId::new(required_u32(cells, a, "call site")),
            },
            PartialPortTag::CallArgument => PartialFlowPort::CallArgument {
                call: CallSiteId::new(required_u32(cells, a, "call site")),
                ordinal: required_u32(cells, b, "argument ordinal"),
            },
            PartialPortTag::CallResult => PartialFlowPort::CallResult {
                call: CallSiteId::new(required_u32(cells, a, "call site")),
                ordinal: b.map(|ordinal| {
                    u32::try_from(ordinal)
                        .unwrap_or_else(|_| cells.fail_row("has a negative result ordinal"))
                }),
            },
            PartialPortTag::CallThrown => PartialFlowPort::CallThrown {
                call: CallSiteId::new(required_u32(cells, a, "call site")),
            },
            PartialPortTag::Capture => PartialFlowPort::Capture {
                slot: MemoryLocationId::new(required_u32(cells, a, "capture slot")),
            },
            PartialPortTag::CaptureOut => PartialFlowPort::CaptureOut {
                target: ProcedureId::new(required_u32(cells, a, "target procedure")),
                destination: MemoryLocationId::new(required_u32(cells, b, "destination location")),
            },
            PartialPortTag::Heap => {
                let root = usize::try_from(root.unwrap_or(-1))
                    .ok()
                    .filter(|root| *root < ports.len())
                    .unwrap_or_else(|| {
                        cells.fail_row("is a heap port whose root is not an earlier port")
                    });
                let text =
                    selectors.unwrap_or_else(|| cells.fail_row("is a heap port without selectors"));
                let tail = match tail {
                    Some(0) => AccessPathTail::Exact,
                    Some(1) => AccessPathTail::Summary,
                    _ => cells.fail_row("is a heap port without a valid tail"),
                };
                PartialFlowPort::Heap {
                    root: Box::new(ports[root].clone()),
                    selectors: heap_selectors(cells, &decoder, &text),
                    tail,
                }
            }
        };
        ports.push(decoded);
    })?;
    let mut flows = Vec::<PartialFlow>::new();
    each_procedure_row(tx, blob_id, procedure, Table::PartialFlows, |cells| {
        cells.key();
        let from = cells.key_u32();
        let to = cells.key_u32();
        let uncertain = cells.flag();
        let crossed = cells
            .opt_text()
            .unwrap_or_else(|| cells.fail_row("has no crossed calls"));
        let crossed: Vec<Vec<u32>> = serde_json::from_str(&crossed).unwrap_or_else(|error| {
            cells.fail_row(&format!("has malformed crossed calls: {error}"))
        });
        for port in [from, to] {
            assert!(
                (port as usize) < ports.len(),
                "semantic IR partial flow of blob {blob_id} names missing port {port}"
            );
        }
        flows.push(PartialFlow {
            from: PortId::new(from),
            to: PortId::new(to),
            uncertain,
            crossed: crossed
                .into_iter()
                .map(|set| set.into_iter().map(CallSiteId::new).collect())
                .collect(),
        });
    })?;
    assert_eq!(
        i64::try_from(ports.len()).expect("port count fits i64"),
        port_count,
        "semantic IR partial-flow head of blob {blob_id} procedure {procedure} counts ports"
    );
    assert_eq!(
        i64::try_from(flows.len()).expect("flow count fits i64"),
        flow_count,
        "semantic IR partial-flow head of blob {blob_id} procedure {procedure} counts flows"
    );
    let gaps: Vec<u32> = serde_json::from_str(&gaps).unwrap_or_else(|error| {
        panic!("semantic IR partial-flow head of blob {blob_id}: discharged_gaps: {error}")
    });
    Ok(Some(ProcedurePartialFlows {
        outcome,
        detail,
        ports,
        flows,
        open,
        relations_complete,
        discharged_gaps: gaps.into_iter().map(SemanticGapId::new).collect(),
    }))
}

fn required_u32(cells: &Cells<'_, '_>, value: Option<i64>, name: &str) -> u32 {
    value
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or_else(|| cells.fail_row(&format!("has no valid {name}")))
}

/// The selector tokens of a heap port: `[kind, operand]` pairs in order.
fn heap_selectors(cells: &Cells<'_, '_>, decoder: &Decoder<'_>, text: &str) -> Box<[HeapSelector]> {
    let tokens: Vec<(i64, Option<i64>)> = serde_json::from_str(text)
        .unwrap_or_else(|error| cells.fail_row(&format!("has malformed selectors: {error}")));
    tokens
        .into_iter()
        .map(|token| match token {
            (0, Some(locator)) => HeapSelector::Field(decoder.locator(cells, locator)),
            (1, Some(text)) => HeapSelector::Property(decoder.boxed_text(cells, text)),
            (2, Some(text)) => HeapSelector::ConstantIndex(decoder.boxed_text(cells, text)),
            (3, Some(value)) => HeapSelector::ExactIndex(ValueId::from_raw(
                u32::try_from(value).unwrap_or_else(|_| cells.fail_row("has a negative index")),
            )),
            (4, None) => HeapSelector::AnyIndex,
            other => cells.fail_row(&format!("has the selector token {other:?}")),
        })
        .collect()
}

pub(super) fn publication_outcome(
    blob_id: i64,
    outcome: i64,
    detail: Option<String>,
    budget: (Option<i64>, Option<i64>, Option<i64>),
) -> SemanticIrPublicationOutcome {
    let tag = OutcomeTag::try_from_code(outcome).unwrap_or_else(|| {
        panic!("semantic_ir_publications blob {blob_id}: outcome {outcome} is unknown")
    });
    let detail = || {
        detail.clone().unwrap_or_else(|| {
            panic!("semantic_ir_publications blob {blob_id}: outcome {outcome} has no detail")
        })
    };
    match tag {
        OutcomeTag::Complete => SemanticIrPublicationOutcome::Complete,
        OutcomeTag::ExceededBudget => {
            let (Some(dimension), Some(limit), Some(attempted)) = budget else {
                panic!("semantic_ir_publications blob {blob_id}: exceeded budget {budget:?}")
            };
            SemanticIrPublicationOutcome::ExceededBudget(budget_exceeded(
                blob_id, dimension, limit, attempted,
            ))
        }
        OutcomeTag::Unsupported => {
            let label = detail();
            let capability = SemanticCapability::ALL
                .into_iter()
                .find(|capability| capability.label() == label)
                .unwrap_or_else(|| {
                    panic!("semantic_ir_publications blob {blob_id}: unknown capability {label:?}")
                });
            SemanticIrPublicationOutcome::Unsupported(capability)
        }
        OutcomeTag::Incomplete => SemanticIrPublicationOutcome::Incomplete(detail()),
        OutcomeTag::Error => SemanticIrPublicationOutcome::Error(detail()),
        OutcomeTag::Panicked => SemanticIrPublicationOutcome::Panicked(detail()),
    }
}

fn budget_exceeded(
    blob_id: i64,
    dimension: i64,
    limit: i64,
    attempted: i64,
) -> SemanticBudgetExceeded {
    let decoded = (
        RowCode::try_from_code(dimension),
        usize::try_from(limit).ok(),
        usize::try_from(attempted).ok(),
    );
    let (Some(dimension), Some(limit), Some(attempted)) = decoded else {
        panic!("semantic IR blob {blob_id}: invalid budget ({dimension}, {limit}, {attempted})")
    };
    SemanticBudgetExceeded::new(dimension, limit, attempted)
}

/// Candidates of one resolution, checked against its variant.
fn resolution(
    cells: &Cells<'_, '_>,
    tag: TargetResolutionTag,
    mut candidates: Vec<CallableTarget>,
) -> CallableTargetResolution {
    match tag {
        TargetResolutionTag::Proven => {
            if candidates.len() != 1 {
                cells.fail_row(&format!("proves {} targets", candidates.len()));
            }
            CallableTargetResolution::Proven(candidates.pop().expect("one candidate"))
        }
        TargetResolutionTag::Ambiguous => CallableTargetResolution::Ambiguous(candidates.into()),
        TargetResolutionTag::Unknown | TargetResolutionTag::Unsupported => {
            if !candidates.is_empty() {
                cells.fail_row("carries candidates for a resolution without any");
            }
            if tag == TargetResolutionTag::Unknown {
                CallableTargetResolution::Unknown
            } else {
                CallableTargetResolution::Unsupported
            }
        }
        TargetResolutionTag::Unproven => CallableTargetResolution::Unproven(candidates.into()),
        TargetResolutionTag::ExceededBudget => {
            CallableTargetResolution::ExceededBudget(candidates.into())
        }
    }
}

fn continuation(
    cells: &Cells<'_, '_>,
    tag: ContinuationTag,
    target: Option<ProgramPointId>,
    column: &str,
) -> ControlContinuation {
    match tag {
        ContinuationTag::Target => ControlContinuation::Target(cells.need(target, column)),
        ContinuationTag::Absent => ControlContinuation::Absent,
        ContinuationTag::Unknown => ControlContinuation::Unknown,
        ContinuationTag::Unsupported => ControlContinuation::Unsupported,
        ContinuationTag::Unproven => ControlContinuation::Unproven,
        ContinuationTag::ExceededBudget => ControlContinuation::ExceededBudget,
    }
}

impl Decoder<'_> {
    fn text(&self, cells: &Cells<'_, '_>, id: i64) -> &str {
        usize::try_from(id)
            .ok()
            .and_then(|index| self.texts.get(index))
            .unwrap_or_else(|| cells.fail_row(&format!("names missing text {id}")))
    }

    fn boxed_text(&self, cells: &Cells<'_, '_>, id: i64) -> Box<str> {
        self.text(cells, id).into()
    }

    fn locator(&self, cells: &Cells<'_, '_>, id: i64) -> SemanticLocator {
        usize::try_from(id)
            .ok()
            .and_then(|index| self.locators.get(index))
            .unwrap_or_else(|| cells.fail_row(&format!("names missing locator {id}")))
            .clone()
    }

    fn procedure(&mut self, cells: &Cells<'_, '_>, procedure: u32) -> &mut ProcedureSemanticsParts {
        let count = self.parts.len();
        self.parts
            .get_mut(procedure as usize)
            .unwrap_or_else(|| cells.fail_row(&format!("names procedure {procedure} of {count}")))
    }

    fn group(
        &mut self,
        cells: &Cells<'_, '_>,
        procedure: u32,
        group: Option<i64>,
    ) -> Vec<CallableTarget> {
        let Some(group) = group else {
            return Vec::new();
        };
        let taken = usize::try_from(group)
            .ok()
            .and_then(|group| self.groups[procedure as usize].get_mut(group))
            .map(std::mem::take)
            .unwrap_or_else(|| cells.fail_row(&format!("names missing target group {group}")));
        if taken.is_empty() {
            cells.fail_row(&format!("takes target group {group} a second time"));
        }
        taken
    }

    fn argument_domain(
        &self,
        cells: &Cells<'_, '_>,
        tag: ArgumentDomainTag,
        text: Option<i64>,
        column: &str,
    ) -> ArgumentDomain {
        match tag {
            ArgumentDomainTag::Positional => ArgumentDomain::Positional,
            ArgumentDomainTag::Keyword => ArgumentDomain::Keyword,
            ArgumentDomainTag::PositionalOrKeyword => ArgumentDomain::PositionalOrKeyword,
            ArgumentDomainTag::LanguageDefined => {
                ArgumentDomain::LanguageDefined(self.boxed_text(cells, cells.need(text, column)))
            }
        }
    }

    fn place(
        &self,
        cells: &Cells<'_, '_>,
        kind: Option<PlaceTag>,
        locator: Option<i64>,
        location: Option<MemoryLocationId>,
    ) -> SemanticPlace {
        match cells.need(kind, "place_kind") {
            PlaceTag::LocalBinding => SemanticPlace::LocalBinding(
                self.locator(cells, cells.need(locator, "place_locator")),
            ),
            PlaceTag::MemoryLocation => {
                SemanticPlace::MemoryLocation(cells.need(location, "place_location"))
            }
        }
    }

    fn read(&mut self, tx: &Transaction<'_>) -> Result<()> {
        self.read_identities(tx)?;
        self.read_procedures(tx)
    }

    /// The texts, declarations and locators the rows name. A partial-flow
    /// read needs only these, so they are a unit of their own.
    fn read_identities(&mut self, tx: &Transaction<'_>) -> Result<()> {
        let blob_id = self.blob_id;
        each_row(tx, blob_id, Table::Texts, |cells| {
            let id = cells.key();
            dense(cells, id as usize, self.texts.len());
            let column = cells.next;
            let text = cells
                .opt_text()
                .unwrap_or_else(|| cells.fail(column, "is NULL"));
            self.texts.push(text);
        })?;
        each_row(tx, blob_id, Table::DeclarationSegments, |cells| {
            let declaration = cells.key() as usize;
            let ordinal = cells.key() as usize;
            if ordinal == 0 {
                dense(cells, declaration, self.declarations.len());
                self.declarations.push(Vec::new());
            } else if declaration + 1 != self.declarations.len() {
                cells.fail_at(
                    "ordinal",
                    "continues a declaration that is not the current one",
                );
            }
            let kind = cells.code();
            let name = cells.opt();
            let anchor = cells.anchor();
            let sibling = cells.u32();
            let segment = match name {
                Some(name) => {
                    DeclarationSegment::named(kind, self.text(cells, name), anchor, sibling)
                        .unwrap_or_else(|error| cells.fail_at("name", &error.to_string()))
                }
                None => DeclarationSegment::anonymous(kind, anchor, sibling),
            };
            let segments = self.declarations.last_mut().expect("declaration started");
            dense(cells, ordinal, segments.len());
            segments.push(segment);
        })?;
        let declarations = std::mem::take(&mut self.declarations)
            .into_iter()
            .map(|segments| {
                DeclarationLocator::new(segments).unwrap_or_else(|error| {
                    panic!("semantic IR blob {blob_id} stores an invalid declaration: {error}")
                })
            })
            .collect::<Vec<_>>();
        each_row(tx, blob_id, Table::Locators, |cells| {
            let id = cells.key() as usize;
            dense(cells, id, self.locators.len());
            let path = cells.opt();
            let declaration = cells.int();
            let role = cells.code();
            let anchor = cells.anchor();
            let declaration = usize::try_from(declaration)
                .ok()
                .and_then(|index| declarations.get(index))
                .unwrap_or_else(|| cells.fail_at("declaration", "names a missing declaration"))
                .clone();
            let path = match path {
                None => self.scope.path.clone(),
                Some(path) => WorkspaceRelativePath::new(self.text(cells, path))
                    .unwrap_or_else(|error| cells.fail_at("path", &error.to_string())),
            };
            self.locators.push(SemanticLocator::new(
                self.scope.mount,
                path,
                self.scope.language,
                declaration,
                role,
                anchor,
            ));
        })?;
        Ok(())
    }

    fn read_procedures(&mut self, tx: &Transaction<'_>) -> Result<()> {
        let blob_id = self.blob_id;
        each_row(tx, blob_id, Table::Procedures, |cells| {
            let id = cells.key_u32();
            dense(cells, id as usize, self.parts.len());
            let locator = cells.int();
            let locator = self.locator(cells, locator);
            let lexical_parent = cells.opt_id();
            let kind = cells.code();
            let properties = ProcedureProperties {
                is_async: cells.flag(),
                is_generator: cells.flag(),
                is_static: cells.flag(),
                is_synthetic: cells.flag(),
                invocation: cells.code(),
                dispatch_extensibility: cells.code(),
                call_boundary: cells.code(),
                receiver_binding: cells.code(),
                construction_return: cells.code(),
            };
            let source = cells.id();
            let evidence = cells.id();
            let mut parts =
                ProcedureSemanticsParts::new(ProcedureId::new(id), locator, kind, source, evidence);
            parts.lexical_parent = lexical_parent;
            parts.properties = properties;
            self.parts.push(parts);
            self.groups.push(Vec::new());
            self.arguments.push(Vec::new());
            self.events.push(Vec::new());
        })?;
        each_row(tx, blob_id, Table::CallableTargets, |cells| {
            let procedure = cells.key_u32();
            let group = cells.key() as usize;
            let ordinal = cells.key() as usize;
            self.procedure(cells, procedure);
            let kind: CallableTargetTag = cells.code();
            let local = cells.opt_id::<ProcedureId>();
            let locator = cells.opt();
            let artifact = cells.opt_text();
            let target = match kind {
                CallableTargetTag::Local => {
                    CallableTarget::Local(cells.need(local, "local_procedure"))
                }
                CallableTargetTag::Unmaterialized => CallableTarget::Unmaterialized(
                    self.locator(cells, cells.need(locator, "locator")),
                ),
                CallableTargetTag::External => {
                    CallableTarget::External(self.locator(cells, cells.need(locator, "locator")))
                }
                CallableTargetTag::Artifact => {
                    let json = cells.need(artifact, "artifact_identity");
                    CallableTarget::Artifact(ArtifactCallableTarget::from_bound_identity(
                        serde_json::from_str(&json).unwrap_or_else(|error| {
                            cells.fail_at("artifact_identity", &error.to_string())
                        }),
                    ))
                }
            };
            let groups = &mut self.groups[procedure as usize];
            if ordinal == 0 {
                dense(cells, group, groups.len());
                groups.push(Vec::new());
            } else if group + 1 != groups.len() {
                cells.fail_at("targets", "continues a group that is not the current one");
            }
            let candidates = groups.last_mut().expect("group started");
            dense(cells, ordinal, candidates.len());
            candidates.push(target);
        })?;
        self.read_values_and_memory(tx)?;
        self.read_calls(tx)?;
        self.read_mappings_and_evidence(tx)?;
        self.read_points(tx)?;
        self.read_edges_and_decisions(tx)?;
        self.read_lifecycle_and_pointers(tx)?;
        Ok(())
    }

    fn read_values_and_memory(&mut self, tx: &Transaction<'_>) -> Result<()> {
        let blob_id = self.blob_id;
        each_row(tx, blob_id, Table::Values, |cells| {
            let procedure = cells.key_u32();
            let id = cells.key_u32();
            let expected = self.procedure(cells, procedure).values.len();
            dense(cells, id as usize, expected);
            let tag: ValueKindTag = cells.code();
            let ordinal = cells.opt_u32();
            let multiplicity: Option<MultiplicityTag> = cells.opt_code();
            let rest_domain: Option<ArgumentDomainTag> = cells.opt_code();
            let rest_domain_text = cells.opt();
            let name = cells.opt();
            let passing_mode = cells.opt_code();
            let value_flag = cells.opt_flag();
            let magnitude = cells.opt_text();
            let float_bits = cells.opt();
            let text = cells.opt();
            let source = cells.id();
            let evidence = cells.id();
            let kind = match tag {
                ValueKindTag::Local => SemanticValueKind::Local,
                ValueKindTag::Parameter => SemanticValueKind::Parameter {
                    ordinal: cells.need(ordinal, "ordinal"),
                    multiplicity: match cells.need(multiplicity, "multiplicity") {
                        MultiplicityTag::One => FormalMultiplicity::One,
                        MultiplicityTag::Rest => FormalMultiplicity::Rest(self.argument_domain(
                            cells,
                            cells.need(rest_domain, "rest_domain"),
                            rest_domain_text,
                            "rest_domain_text",
                        )),
                    },
                    name: name.map(|name| self.boxed_text(cells, name)),
                    passing_mode: cells.need(passing_mode, "passing_mode"),
                },
                ValueKindTag::DefaultArgument => SemanticValueKind::DefaultArgument {
                    ordinal: cells.need(ordinal, "ordinal"),
                },
                ValueKindTag::Receiver => SemanticValueKind::Receiver {
                    dispatch: cells.need(value_flag, "flag"),
                },
                ValueKindTag::Return => SemanticValueKind::Return,
                ValueKindTag::Temporary => SemanticValueKind::Temporary,
                ValueKindTag::Address => SemanticValueKind::Address,
                ValueKindTag::Null => SemanticValueKind::Null,
                ValueKindTag::Boolean => SemanticValueKind::Boolean(cells.need(value_flag, "flag")),
                ValueKindTag::UnsignedInteger => SemanticValueKind::UnsignedInteger(
                    cells
                        .need(magnitude, "magnitude")
                        .parse()
                        .unwrap_or_else(|_| cells.fail_at("magnitude", "is not a u128 magnitude")),
                ),
                ValueKindTag::SignedInteger => SemanticValueKind::SignedInteger(
                    cells
                        .need(magnitude, "magnitude")
                        .parse()
                        .unwrap_or_else(|_| cells.fail_at("magnitude", "is not an i128 magnitude")),
                ),
                ValueKindTag::FloatingPoint => SemanticValueKind::FloatingPoint {
                    bits: u64::from_ne_bytes(cells.need(float_bits, "float_bits").to_ne_bytes()),
                },
                ValueKindTag::Constant => SemanticValueKind::Constant,
                ValueKindTag::ConstantString => SemanticValueKind::ConstantString(
                    self.boxed_text(cells, cells.need(text, "text")),
                ),
                ValueKindTag::Exception => SemanticValueKind::Exception,
                ValueKindTag::Callable => SemanticValueKind::Callable,
                ValueKindTag::AwaitResult => SemanticValueKind::AwaitResult,
                ValueKindTag::LanguageDefined => SemanticValueKind::LanguageDefined(
                    self.boxed_text(cells, cells.need(text, "text")),
                ),
            };
            self.parts[procedure as usize].values.push(SemanticValue {
                id: ValueId::new(id),
                kind,
                source,
                evidence,
            });
        })?;
        each_row(tx, blob_id, Table::Allocations, |cells| {
            let procedure = cells.key_u32();
            let id = cells.key_u32();
            let expected = self.procedure(cells, procedure).allocations.len();
            dense(cells, id as usize, expected);
            let point = cells.id();
            let result = cells.id();
            let tag: AllocationKindTag = cells.code();
            let kind_text = cells.opt();
            let source = cells.id();
            let evidence = cells.id();
            let kind = match tag {
                AllocationKindTag::Object => AllocationKind::Object,
                AllocationKindTag::Array => AllocationKind::Array,
                AllocationKindTag::Slice => AllocationKind::Slice,
                AllocationKindTag::Callable => AllocationKind::Callable,
                AllocationKindTag::ClosureEnvironment => AllocationKind::ClosureEnvironment,
                AllocationKindTag::SharedCell => AllocationKind::SharedCell,
                AllocationKindTag::LanguageDefined => AllocationKind::LanguageDefined(
                    self.boxed_text(cells, cells.need(kind_text, "kind_text")),
                ),
            };
            self.parts[procedure as usize]
                .allocations
                .push(AllocationSite {
                    id: AllocationId::new(id),
                    point,
                    result,
                    kind,
                    source,
                    evidence,
                });
        })?;
        each_row(tx, blob_id, Table::MemoryLocations, |cells| {
            let procedure = cells.key_u32();
            let id = cells.key_u32();
            let expected = self.procedure(cells, procedure).memory_locations.len();
            dense(cells, id as usize, expected);
            let tag: MemoryLocationKindTag = cells.code();
            let base = cells.opt_id::<ValueId>();
            let member = cells.opt();
            let property_key = cells.opt();
            let index_value = cells.opt_id();
            let constant_index = cells.opt_u128();
            let index_identity = cells.opt_code();
            let lexical_parent = cells.opt_id();
            let binding = cells.opt_id();
            let copy_tag: MemoryValueCopyTag = cells.code();
            let copy_identity = cells.opt_code();
            let source = cells.id();
            let evidence = cells.id();
            let kind = match tag {
                MemoryLocationKindTag::Field => MemoryLocationKind::Field {
                    base: cells.need(base, "base"),
                    member: self.locator(cells, cells.need(member, "member")),
                },
                MemoryLocationKindTag::Property => MemoryLocationKind::Property {
                    base: cells.need(base, "base"),
                    key: self
                        .text(cells, cells.need(property_key, "property_key"))
                        .to_owned(),
                },
                MemoryLocationKindTag::Static => MemoryLocationKind::Static {
                    member: self.locator(cells, cells.need(member, "member")),
                },
                MemoryLocationKindTag::Index => MemoryLocationKind::Index {
                    base: cells.need(base, "base"),
                    index: index_value,
                    constant_index,
                    identity: cells.need(index_identity, "index_identity"),
                },
                MemoryLocationKindTag::Dereference => MemoryLocationKind::Dereference {
                    address: cells.need(base, "base"),
                },
                MemoryLocationKindTag::LexicalCell => MemoryLocationKind::LexicalCell {
                    binding: cells.need(binding, "binding"),
                },
                MemoryLocationKindTag::Capture => MemoryLocationKind::Capture {
                    lexical_parent: cells.need(lexical_parent, "lexical_parent"),
                    binding,
                },
            };
            let value_copy = match copy_tag {
                MemoryValueCopyTag::Unknown => MemoryValueCopy::Unknown,
                MemoryValueCopyTag::Value => MemoryValueCopy::Value,
                MemoryValueCopyTag::Reference => MemoryValueCopy::Reference,
                MemoryValueCopyTag::BackingStore => MemoryValueCopy::BackingStore {
                    identity: cells.need(copy_identity, "value_copy_identity"),
                },
            };
            self.parts[procedure as usize]
                .memory_locations
                .push(MemoryLocation {
                    id: MemoryLocationId::new(id),
                    kind,
                    value_copy,
                    source,
                    evidence,
                });
        })?;
        each_row(tx, blob_id, Table::Captures, |cells| {
            let procedure = cells.key_u32();
            let id = cells.key_u32();
            let expected = self.procedure(cells, procedure).captures.len();
            dense(cells, id as usize, expected);
            let point = cells.id();
            let callable = cells.id();
            let target = cells.id();
            let environment = cells.id();
            let captured_kind: CaptureSourceTag = cells.code();
            let captured = cells.u32();
            let destination = cells.id();
            let mode_tag: CaptureModeTag = cells.code();
            let mode_text = cells.opt();
            let source = cells.id();
            let evidence = cells.id();
            let captured = match captured_kind {
                CaptureSourceTag::Value => CaptureSource::Value(ValueId::new(captured)),
                CaptureSourceTag::Location => {
                    CaptureSource::Location(MemoryLocationId::new(captured))
                }
            };
            let mode = match mode_tag {
                CaptureModeTag::Value => CaptureMode::Value,
                CaptureModeTag::Move => CaptureMode::Move,
                CaptureModeTag::SharedCell => CaptureMode::SharedCell,
                CaptureModeTag::MutableCell => CaptureMode::MutableCell,
                CaptureModeTag::Receiver => CaptureMode::Receiver,
                CaptureModeTag::LanguageDefined => CaptureMode::LanguageDefined(
                    self.boxed_text(cells, cells.need(mode_text, "mode_text")),
                ),
                CaptureModeTag::Unknown => CaptureMode::Unknown,
            };
            self.parts[procedure as usize]
                .captures
                .push(CaptureBinding {
                    id: CaptureId::new(id),
                    point,
                    callable,
                    target,
                    environment,
                    captured,
                    destination,
                    mode,
                    source,
                    evidence,
                });
        })?;
        Ok(())
    }

    fn read_calls(&mut self, tx: &Transaction<'_>) -> Result<()> {
        let blob_id = self.blob_id;
        each_row(tx, blob_id, Table::CallSites, |cells| {
            let procedure = cells.key_u32();
            let id = cells.key_u32();
            let expected = self.procedure(cells, procedure).call_sites.len();
            dense(cells, id as usize, expected);
            let point = cells.id();
            let invocation_mode = cells.code();
            let execution_timing = cells.code();
            let callee = cells.id();
            let receiver = cells.opt_id();
            let result = cells.opt_id();
            let thrown = cells.opt_id();
            let normal_results = cells.opt_local_ids::<ValueId>().unwrap_or_default();
            let resolution_tag = cells.code();
            let targets = cells.opt();
            let target_evidence = cells.id();
            let normal_tag = cells.code();
            let normal_target = cells.opt_id();
            let exceptional_tag = cells.code();
            let exceptional_target = cells.opt_id();
            let source = cells.id();
            let evidence = cells.id();
            let member = cells.opt();
            let place_kind = cells.opt_code::<PlaceTag>();
            let place_locator = cells.opt();
            let place_location = cells.opt_id();
            let receiver_pointer_depth = cells.opt_u32();
            let member_selection = member.map(|member| {
                Box::new(DeferredMemberSelection {
                    member: self.boxed_text(cells, member),
                    receiver_place: place_kind
                        .map(|_| self.place(cells, place_kind, place_locator, place_location)),
                    receiver_pointer_depth,
                })
            });
            let candidates = self.group(cells, procedure, targets);
            self.parts[procedure as usize]
                .call_sites
                .push(SemanticCallSite {
                    id: CallSiteId::new(id),
                    point,
                    invocation_mode,
                    execution_timing,
                    callee,
                    receiver,
                    member_selection,
                    arguments: Box::new([]),
                    normal_results: normal_results.into(),
                    result,
                    thrown,
                    declared_targets: resolution(cells, resolution_tag, candidates),
                    target_evidence,
                    normal_continuation: continuation(
                        cells,
                        normal_tag,
                        normal_target,
                        "normal_target",
                    ),
                    exceptional_continuation: continuation(
                        cells,
                        exceptional_tag,
                        exceptional_target,
                        "exceptional_target",
                    ),
                    source,
                    evidence,
                });
            self.arguments[procedure as usize].push(Vec::new());
        })?;
        each_row(tx, blob_id, Table::CallArguments, |cells| {
            let procedure = cells.key_u32();
            let call_site = cells.key() as usize;
            let ordinal = cells.key() as usize;
            self.procedure(cells, procedure);
            let value = cells.id();
            let expansion: ExpansionTag = cells.code();
            let domain = cells.opt_code();
            let domain_text = cells.opt();
            let keyword = cells.opt();
            let expansion = match expansion {
                ExpansionTag::Unclassified => CallArgumentExpansion::Unclassified,
                ExpansionTag::Direct => CallArgumentExpansion::Direct(self.argument_domain(
                    cells,
                    cells.need(domain, "domain"),
                    domain_text,
                    "domain_text",
                )),
                ExpansionTag::Spread => CallArgumentExpansion::Spread(self.argument_domain(
                    cells,
                    cells.need(domain, "domain"),
                    domain_text,
                    "domain_text",
                )),
            };
            let keyword = keyword.map(|keyword| self.boxed_text(cells, keyword));
            let arguments = self.arguments[procedure as usize]
                .get_mut(call_site)
                .unwrap_or_else(|| cells.fail_at("call_site", "names a missing call site"));
            dense(cells, ordinal, arguments.len());
            arguments.push(SemanticCallArgument {
                value,
                expansion,
                keyword,
            });
        })?;
        Ok(())
    }

    fn read_mappings_and_evidence(&mut self, tx: &Transaction<'_>) -> Result<()> {
        let blob_id = self.blob_id;
        let content = self.scope.content;
        each_row(tx, blob_id, Table::SourceMappings, |cells| {
            let procedure = cells.key_u32();
            let id = cells.key_u32();
            let expected = self.procedure(cells, procedure).source_mappings.len();
            dense(cells, id as usize, expected);
            let locator = cells.int();
            let locator = self.locator(cells, locator);
            let kind = cells.code();
            let ast_node = cells.opt_u32();
            self.parts[procedure as usize]
                .source_mappings
                .push(SourceMapping {
                    id: SourceMappingId::new(id),
                    locator,
                    kind,
                    ast_identity: ast_node.map(|node| StructuralNodeIdentity::new(content, node)),
                });
        })?;
        each_row(tx, blob_id, Table::StatementEntries, |cells| {
            let procedure = cells.key_u32();
            let ordinal = cells.key() as usize;
            let expected = self.procedure(cells, procedure).statement_entries.len();
            dense(cells, ordinal, expected);
            let entry = StatementEntrySite {
                source: cells.id(),
                evidence: cells.id(),
                point: cells.id(),
            };
            self.parts[procedure as usize].statement_entries.push(entry);
        })?;
        each_row(tx, blob_id, Table::LoopSites, |cells| {
            let procedure = cells.key_u32();
            let ordinal = cells.key() as usize;
            let expected = self.procedure(cells, procedure).loop_sites.len();
            dense(cells, ordinal, expected);
            let site = LoopSite {
                source: cells.id(),
                evidence: cells.id(),
                header: cells.id(),
                body: cells.id(),
            };
            self.parts[procedure as usize].loop_sites.push(site);
        })?;
        each_row(tx, blob_id, Table::Evidence, |cells| {
            let procedure = cells.key_u32();
            let id = cells.key_u32();
            let expected = self.procedure(cells, procedure).evidence_rows.len();
            dense(cells, id as usize, expected);
            let proof: ProofTag = cells.code();
            let proof_reason = cells.opt();
            let completeness: CompletenessTag = cells.code();
            let completeness_reason = cells.opt();
            let sources = cells.local_ids::<SourceMappingId>();
            let proof = match proof {
                ProofTag::Proven => ProofStatus::Proven,
                ProofTag::Unproven => ProofStatus::Unproven(
                    self.boxed_text(cells, cells.need(proof_reason, "proof_reason")),
                ),
            };
            let completeness = match completeness {
                CompletenessTag::Complete => EvidenceCompleteness::Complete,
                CompletenessTag::Partial => EvidenceCompleteness::Partial(self.boxed_text(
                    cells,
                    cells.need(completeness_reason, "completeness_reason"),
                )),
            };
            self.parts[procedure as usize].evidence_rows.push(Evidence {
                id: EvidenceId::new(id),
                proof,
                completeness,
                sources: sources.into(),
            });
        })?;
        each_row(tx, blob_id, Table::Gaps, |cells| {
            let procedure = cells.key_u32();
            let id = cells.key_u32();
            let expected = self.procedure(cells, procedure).gaps.len();
            dense(cells, id as usize, expected);
            let point = cells.id();
            let subject: GapSubjectTag = cells.code();
            let subject_a = cells.opt_u32();
            let subject_b = cells.opt();
            let capability = cells.code();
            let bits = cells.int();
            let kind = cells.code();
            let budget_dimension = cells.opt();
            let budget_limit = cells.opt();
            let budget_attempted = cells.opt();
            let discharge = cells.code();
            let detail = cells.int();
            let source = cells.id();
            let evidence = cells.id();
            let subject_a = |cells: &Cells<'_, '_>| cells.need(subject_a, "subject_a");
            let subject_b = |cells: &Cells<'_, '_>| cells.need(subject_b, "subject_b");
            let subject = match subject {
                GapSubjectTag::Procedure => SemanticGapSubject::Procedure,
                GapSubjectTag::Point => SemanticGapSubject::Point,
                GapSubjectTag::Value => SemanticGapSubject::Value(ValueId::new(subject_a(cells))),
                GapSubjectTag::MemoryLocation => {
                    SemanticGapSubject::MemoryLocation(MemoryLocationId::new(subject_a(cells)))
                }
                GapSubjectTag::Capture => {
                    SemanticGapSubject::Capture(CaptureId::new(subject_a(cells)))
                }
                GapSubjectTag::CallSite => {
                    SemanticGapSubject::CallSite(CallSiteId::new(subject_a(cells)))
                }
                GapSubjectTag::CallContinuation => SemanticGapSubject::CallContinuation {
                    call_site: CallSiteId::new(subject_a(cells)),
                    kind: RowCode::try_from_code(subject_b(cells)).unwrap_or_else(|| {
                        cells.fail_at("subject_b", "is not a continuation kind")
                    }),
                },
                GapSubjectTag::AsyncContinuation => SemanticGapSubject::AsyncContinuation {
                    suspend: ProgramPointId::new(subject_a(cells)),
                    kind: RowCode::try_from_code(subject_b(cells))
                        .unwrap_or_else(|| cells.fail_at("subject_b", "is not a resume kind")),
                },
            };
            let mut impacts = SemanticGapImpacts::NONE;
            let mut rebuilt = 0_i64;
            for impact in SemanticGapImpact::ALL {
                let bit = 1_i64 << (impact as u8);
                if bits & bit != 0 {
                    impacts = impacts.with(impact);
                    rebuilt |= bit;
                }
            }
            if rebuilt != bits {
                cells.fail_at("impacts", &format!("holds unknown impact bits {bits:#b}"));
            }
            let budget = match (budget_dimension, budget_limit, budget_attempted) {
                (None, None, None) => None,
                (Some(dimension), Some(limit), Some(attempted)) => {
                    Some(budget_exceeded(blob_id, dimension, limit, attempted))
                }
                _ => cells.fail_at("budget_dimension", "holds a partial budget"),
            };
            let detail = self.boxed_text(cells, detail);
            self.parts[procedure as usize].gaps.push(SemanticGap {
                id: SemanticGapId::new(id),
                point,
                subject,
                capability,
                impacts,
                kind,
                budget,
                discharge,
                detail,
                source,
                evidence,
            });
        })?;
        Ok(())
    }

    fn read_points(&mut self, tx: &Transaction<'_>) -> Result<()> {
        let blob_id = self.blob_id;
        each_row(tx, blob_id, Table::Blocks, |cells| {
            let procedure = cells.key_u32();
            let id = cells.key_u32();
            let expected = self.procedure(cells, procedure).blocks.len();
            dense(cells, id as usize, expected);
            let points = cells.local_ids::<ProgramPointId>();
            let source = cells.id();
            let evidence = cells.id();
            self.parts[procedure as usize].blocks.push(BasicBlock {
                id: BlockId::new(id),
                points: points.into(),
                source,
                evidence,
            });
        })?;
        each_row(tx, blob_id, Table::Points, |cells| {
            let procedure = cells.key_u32();
            let id = cells.key_u32();
            let expected = self.procedure(cells, procedure).points.len();
            dense(cells, id as usize, expected);
            let block = cells.id();
            let source = cells.id();
            let evidence = cells.id();
            self.parts[procedure as usize].points.push(ProgramPoint {
                id: ProgramPointId::new(id),
                block,
                events: Box::new([]),
                source,
                evidence,
            });
            self.events[procedure as usize].push(Vec::new());
        })?;
        each_row(tx, blob_id, Table::EventTransfers, |cells| {
            let key = (cells.key_u32(), cells.key_u32(), cells.key_u32());
            let kind: TransferKindTag = cells.code();
            let detail = cells.opt();
            let operation: TransferOperationTag = cells.code();
            let call_site = cells.opt_id();
            let digest = cells.opt_digest();
            let detail = |cells: &Cells<'_, '_>| cells.need(detail, "transfer_detail");
            let kind = match kind {
                TransferKindTag::Copy => TransferKind::Copy,
                TransferKindTag::AggregateCopy => TransferKind::AggregateCopy,
                TransferKindTag::Move => TransferKind::Move {
                    invalidation: RowCode::try_from_code(detail(cells)).unwrap_or_else(|| {
                        cells.fail_at("transfer_detail", "is not a move invalidation")
                    }),
                },
                TransferKindTag::Conversion => TransferKind::Conversion {
                    preservation: RowCode::try_from_code(detail(cells)).unwrap_or_else(|| {
                        cells.fail_at("transfer_detail", "is not a value preservation")
                    }),
                },
                TransferKindTag::Boxing => TransferKind::Boxing,
                TransferKindTag::Unboxing => TransferKind::Unboxing,
            };
            let operation = match operation {
                TransferOperationTag::None => TransferOperation::None,
                TransferOperationTag::CallSite => {
                    TransferOperation::CallSite(cells.need(call_site, "call_site"))
                }
                TransferOperationTag::CallArgumentConversion => {
                    TransferOperation::CallArgumentConversion(cells.need(digest, "digest"))
                }
                TransferOperationTag::ValueCarrierAdaptation => {
                    TransferOperation::ValueCarrierAdaptation(cells.need(digest, "digest"))
                }
                TransferOperationTag::Unknown => TransferOperation::Unknown,
            };
            self.transfers
                .insert(key, ValueTransfer { kind, operation });
        })?;
        each_row(tx, blob_id, Table::EventOffsets, |cells| {
            let key = (cells.key_u32(), cells.key_u32(), cells.key_u32());
            let row = OffsetRow {
                kind: cells.opt_code(),
                magnitude: cells.opt_u128(),
                value: cells.opt_id(),
                negative: cells.opt_flag(),
                allocation: cells.opt_id(),
                return_ordinal: cells.opt_u32(),
            };
            self.offsets.insert(key, row);
        })?;
        each_row(tx, blob_id, Table::EventCallables, |cells| {
            let key = (cells.key_u32(), cells.key_u32(), cells.key_u32());
            self.procedure(cells, key.0);
            let tag = cells.code();
            let group = cells.opt();
            let evidence = cells.id();
            let candidates = self.group(cells, key.0, group);
            self.callables
                .insert(key, (resolution(cells, tag, candidates), evidence));
        })?;
        each_row(tx, blob_id, Table::EventSynchronizations, |cells| {
            let key = (cells.key_u32(), cells.key_u32(), cells.key_u32());
            let kind: SynchronizationPayloadTag = cells.code();
            let value = cells.id();
            let copy_kind: Option<SynchronizationPayloadCopyTag> = cells.opt_code();
            let copy_identity = cells.opt_code();
            let payload = match kind {
                SynchronizationPayloadTag::Send => SynchronizationPayload::Send {
                    value,
                    copy: match cells.need(copy_kind, "copy_kind") {
                        SynchronizationPayloadCopyTag::Unknown => {
                            SynchronizationPayloadCopy::Unknown
                        }
                        SynchronizationPayloadCopyTag::Reference => {
                            SynchronizationPayloadCopy::Reference
                        }
                        SynchronizationPayloadCopyTag::BackingStore => {
                            SynchronizationPayloadCopy::BackingStore {
                                identity: cells.need(copy_identity, "copy_identity"),
                            }
                        }
                    },
                },
                SynchronizationPayloadTag::Receive => {
                    SynchronizationPayload::Receive { result: value }
                }
            };
            self.synchronizations.insert(key, payload);
        })?;
        each_row(tx, blob_id, Table::EventAsyncSuspends, |cells| {
            let key = (cells.key_u32(), cells.key_u32(), cells.key_u32());
            let normal = cells.code();
            let normal_target = cells.opt_id();
            let exceptional = cells.code();
            let exceptional_target = cells.opt_id();
            self.suspends.insert(
                key,
                (
                    continuation(cells, normal, normal_target, "normal_target"),
                    continuation(cells, exceptional, exceptional_target, "exceptional_target"),
                ),
            );
        })?;
        each_row(tx, blob_id, Table::Events, |cells| {
            let procedure = cells.key_u32();
            let point = cells.key_u32();
            let ordinal = cells.key_u32();
            self.procedure(cells, procedure);
            let effect: EffectTag = cells.code();
            let sub_kind = cells.opt();
            let value_a = cells.opt_id::<ValueId>();
            let value_b = cells.opt_id::<ValueId>();
            let value_c = cells.opt_id::<ValueId>();
            let location = cells.opt_id();
            let allocation = cells.opt_id();
            let call_site = cells.opt_id();
            let capture = cells.opt_id();
            let gap = cells.opt_id();
            let locator = cells.opt();
            let suspend_point = cells.opt_id();
            let source = cells.id();
            let evidence = cells.id();
            let key = (procedure, point, ordinal);
            let sub_kind_code = |cells: &Cells<'_, '_>| cells.need(sub_kind, "sub_kind");
            fn sub<T: RowCode>(cells: &Cells<'_, '_>, code: i64) -> T {
                T::try_from_code(code).unwrap_or_else(|| {
                    cells.fail_at(
                        "sub_kind",
                        &format!("holds {code}, not a {}", std::any::type_name::<T>()),
                    )
                })
            }
            let effect = match effect {
                EffectTag::Entry => SemanticEffect::Entry,
                EffectTag::NormalExit => SemanticEffect::NormalExit,
                EffectTag::ExceptionalExit => SemanticEffect::ExceptionalExit,
                EffectTag::Assignment => SemanticEffect::Assignment {
                    target: cells.need(value_a, "value_a"),
                    value: cells.need(value_b, "value_b"),
                },
                EffectTag::AggregateInitializer => SemanticEffect::AggregateInitializer {
                    aggregate: cells.need(value_a, "value_a"),
                    selector: self.locator(cells, cells.need(locator, "locator")),
                    value: cells.need(value_b, "value_b"),
                },
                EffectTag::ValueFlow => {
                    let tag: ValueFlowKindTag = sub(cells, sub_kind_code(cells));
                    let kind = self.value_flow_kind(cells, key, tag);
                    SemanticEffect::ValueFlow {
                        kind,
                        source: cells.need(value_a, "value_a"),
                        target: cells.need(value_b, "value_b"),
                    }
                }
                EffectTag::ValueUse => SemanticEffect::ValueUse {
                    kind: sub(cells, sub_kind_code(cells)),
                    value: cells.need(value_a, "value_a"),
                },
                EffectTag::Allocation => SemanticEffect::Allocation {
                    allocation: cells.need(allocation, "allocation"),
                },
                EffectTag::MemoryLoad => SemanticEffect::MemoryLoad {
                    kind: sub(cells, sub_kind_code(cells)),
                    location: cells.need(location, "location"),
                    result: cells.need(value_a, "value_a"),
                },
                EffectTag::MemoryStore => SemanticEffect::MemoryStore {
                    kind: sub(cells, sub_kind_code(cells)),
                    location: cells.need(location, "location"),
                    value: cells.need(value_a, "value_a"),
                },
                EffectTag::Synchronization => SemanticEffect::Synchronization {
                    operation: sub(cells, sub_kind_code(cells)),
                    subject: cells.need(value_a, "value_a"),
                    payload: self.synchronizations.remove(&key),
                },
                EffectTag::CallableCreation | EffectTag::CallableReference => {
                    let tag: CallableReferenceKindTag = sub(cells, sub_kind_code(cells));
                    let kind = match tag {
                        CallableReferenceKindTag::Lambda => CallableReferenceKind::Lambda,
                        CallableReferenceKindTag::Function => CallableReferenceKind::Function,
                        CallableReferenceKindTag::BoundMethod => CallableReferenceKind::BoundMethod,
                        CallableReferenceKindTag::UnboundMethod => {
                            CallableReferenceKind::UnboundMethod
                        }
                        CallableReferenceKindTag::ModuleQualified => {
                            CallableReferenceKind::ModuleQualified {
                                qualifier: cells.need(value_b, "value_b"),
                            }
                        }
                        CallableReferenceKindTag::TypeQualifiedMethod => {
                            CallableReferenceKind::TypeQualifiedMethod {
                                qualifier: cells.need(value_b, "value_b"),
                            }
                        }
                        CallableReferenceKindTag::StaticMethod => {
                            CallableReferenceKind::StaticMethod
                        }
                        CallableReferenceKindTag::Constructor => CallableReferenceKind::Constructor,
                    };
                    let (targets, target_evidence) = self
                        .callables
                        .remove(&key)
                        .unwrap_or_else(|| cells.fail_row("has no callable target row"));
                    let callable = CallableValue {
                        kind,
                        targets,
                        target_evidence,
                        bound_receiver: value_c,
                        environment: allocation,
                    };
                    let result = cells.need(value_a, "value_a");
                    if effect == EffectTag::CallableCreation {
                        SemanticEffect::CallableCreation { result, callable }
                    } else {
                        SemanticEffect::CallableReference { result, callable }
                    }
                }
                EffectTag::CaptureBind => SemanticEffect::CaptureBind {
                    capture: cells.need(capture, "capture"),
                },
                EffectTag::Invoke => SemanticEffect::Invoke {
                    call_site: cells.need(call_site, "call_site"),
                },
                EffectTag::CallContinuation => SemanticEffect::CallContinuation {
                    call_site: cells.need(call_site, "call_site"),
                    kind: sub(cells, sub_kind_code(cells)),
                },
                EffectTag::ProcedureReturn => SemanticEffect::ProcedureReturn { value: value_a },
                EffectTag::Throw => SemanticEffect::Throw { value: value_a },
                EffectTag::AsyncSuspend => {
                    let (normal_resume, exceptional_resume) = self
                        .suspends
                        .remove(&key)
                        .unwrap_or_else(|| cells.fail_row("has no async suspend row"));
                    SemanticEffect::AsyncSuspend {
                        awaited: value_a,
                        normal_resume,
                        exceptional_resume,
                    }
                }
                EffectTag::AsyncResume => SemanticEffect::AsyncResume {
                    suspend: cells.need(suspend_point, "suspend_point"),
                    kind: sub(cells, sub_kind_code(cells)),
                    result: value_a,
                },
                EffectTag::Gap => SemanticEffect::Gap {
                    gap: cells.need(gap, "gap"),
                },
            };
            let events = self.events[procedure as usize]
                .get_mut(point as usize)
                .unwrap_or_else(|| cells.fail_at("point", "names a missing point"));
            dense(cells, ordinal as usize, events.len());
            events.push(SemanticEvent::new(effect, source, evidence));
        })?;
        for (table, unclaimed) in [
            ("semantic_ir_event_transfers", self.transfers.len()),
            ("semantic_ir_event_offsets", self.offsets.len()),
            ("semantic_ir_event_callables", self.callables.len()),
            (
                "semantic_ir_event_synchronizations",
                self.synchronizations.len(),
            ),
            ("semantic_ir_event_async_suspends", self.suspends.len()),
        ] {
            assert_eq!(
                unclaimed, 0,
                "semantic IR blob {blob_id}: {table} has rows for no matching event"
            );
        }
        Ok(())
    }

    fn value_flow_kind(
        &mut self,
        cells: &Cells<'_, '_>,
        key: EventKey,
        tag: ValueFlowKindTag,
    ) -> ValueFlowKind {
        let mut offset = || {
            self.offsets
                .remove(&key)
                .unwrap_or_else(|| cells.fail_row("has no offset row"))
        };
        let backing_store_offset = |row: &OffsetRow| match cells.need(row.kind, "offset_kind") {
            BackingStoreOffsetTag::Zero => BackingStoreOffset::Zero,
            BackingStoreOffsetTag::Constant => {
                BackingStoreOffset::Constant(cells.need(row.magnitude, "magnitude"))
            }
            BackingStoreOffsetTag::Value => {
                BackingStoreOffset::Value(cells.need(row.value, "offset_value"))
            }
        };
        match tag {
            ValueFlowKindTag::Local => ValueFlowKind::Local,
            ValueFlowKindTag::Transfer => ValueFlowKind::Transfer(
                self.transfers
                    .remove(&key)
                    .unwrap_or_else(|| cells.fail_row("has no transfer row")),
            ),
            ValueFlowKindTag::BackingStore => {
                let row = offset();
                ValueFlowKind::BackingStore {
                    offset: backing_store_offset(&row),
                }
            }
            ValueFlowKindTag::IntegerOffset => {
                let row = offset();
                ValueFlowKind::IntegerOffset {
                    offset: SignedIntegerMagnitude::new(
                        cells.need(row.negative, "negative"),
                        cells.need(row.magnitude, "magnitude"),
                    ),
                }
            }
            ValueFlowKindTag::BackingStoreAlternative => {
                let row = offset();
                ValueFlowKind::BackingStoreAlternative {
                    offset: backing_store_offset(&row),
                    allocation: cells.need(row.allocation, "allocation"),
                }
            }
            ValueFlowKindTag::Parameter => ValueFlowKind::Parameter,
            ValueFlowKindTag::Receiver => ValueFlowKind::Receiver,
            ValueFlowKindTag::Return => ValueFlowKind::Return,
            ValueFlowKindTag::IndexedReturn => {
                let row = offset();
                ValueFlowKind::IndexedReturn {
                    ordinal: cells.need(row.return_ordinal, "return_ordinal"),
                }
            }
            ValueFlowKindTag::ReferenceBoxing => ValueFlowKind::ReferenceBoxing,
            ValueFlowKindTag::ReferenceUnboxing => ValueFlowKind::ReferenceUnboxing,
            ValueFlowKindTag::LanguageDefined => ValueFlowKind::LanguageDefined,
        }
    }

    fn read_edges_and_decisions(&mut self, tx: &Transaction<'_>) -> Result<()> {
        let blob_id = self.blob_id;
        each_row(tx, blob_id, Table::ControlEdges, |cells| {
            let procedure = cells.key_u32();
            let ordinal = cells.key() as usize;
            let expected = self.procedure(cells, procedure).control_edges.len();
            dense(cells, ordinal, expected);
            let edge = ControlEdge {
                source_point: cells.id(),
                target_point: cells.id(),
                kind: cells.code(),
                source: cells.id(),
                evidence: cells.id(),
            };
            self.parts[procedure as usize].control_edges.push(edge);
        })?;
        each_row(tx, blob_id, Table::GuardFacts, |cells| {
            let procedure = cells.key_u32();
            let id = cells.key_u32();
            let expected = self.procedure(cells, procedure).guard_facts.len();
            dense(cells, id as usize, expected);
            let point = cells.id();
            let subject = cells.opt_id();
            let predicate: GuardPredicateTag = cells.code();
            let guard_flag = cells.opt_flag();
            let relation = cells.opt_code();
            let constant = cells.opt_id::<ValueId>();
            let operand_a = cells.opt_id::<ValueId>();
            let operand_b = cells.opt_id::<ValueId>();
            let digest = cells.opt();
            let true_target = cells.opt_id();
            let true_kind = cells.opt_code();
            let false_target = cells.opt_id();
            let false_kind = cells.opt_code();
            let source = cells.id();
            let evidence = cells.id();
            let flag = |cells: &Cells<'_, '_>| cells.need(guard_flag, "flag");
            let predicate = match predicate {
                GuardPredicateTag::ConstantBoolean => {
                    GuardPredicate::ConstantBoolean { value: flag(cells) }
                }
                GuardPredicateTag::NullComparison => GuardPredicate::NullComparison {
                    null_on_true: flag(cells),
                },
                GuardPredicateTag::ConstantEquality => GuardPredicate::ConstantEquality {
                    negated: flag(cells),
                    constant: cells.need(constant, "constant"),
                },
                GuardPredicateTag::OrderedIntegerComparison => {
                    GuardPredicate::OrderedIntegerComparison {
                        relation: cells.need(relation, "relation"),
                        constant: cells.need(constant, "constant"),
                    }
                }
                GuardPredicateTag::OrderedFloatComparison => {
                    GuardPredicate::OrderedFloatComparison {
                        relation: cells.need(relation, "relation"),
                        constant: cells.need(constant, "constant"),
                    }
                }
                GuardPredicateTag::NanComparison => GuardPredicate::NanComparison {
                    nan_on_true: flag(cells),
                },
                GuardPredicateTag::InstanceOf => GuardPredicate::InstanceOf {
                    value: cells.need(operand_a, "operand_a"),
                    classes: cells.need(operand_b, "operand_b"),
                },
                GuardPredicateTag::ExactClass => GuardPredicate::ExactClass {
                    value: cells.need(operand_a, "operand_a"),
                    classes: cells.need(operand_b, "operand_b"),
                    exact_on_true: flag(cells),
                },
                GuardPredicateTag::HasMember => GuardPredicate::HasMember {
                    value: cells.need(operand_a, "operand_a"),
                    member: cells.need(operand_b, "operand_b"),
                },
                GuardPredicateTag::Truthy => GuardPredicate::Truthy {
                    value: cells.need(operand_a, "operand_a"),
                },
                GuardPredicateTag::Opaque => GuardPredicate::Opaque {
                    digest: GuardConditionDigest::from_bits(u64::from_ne_bytes(
                        cells.need(digest, "digest").to_ne_bytes(),
                    )),
                },
            };
            let arm = |target: Option<ProgramPointId>, kind| match (target, kind) {
                (Some(target_point), Some(kind)) => Some(GuardArm { target_point, kind }),
                (None, None) => None,
                _ => cells.fail_at("true_target", "holds half of a guard arm"),
            };
            let guard = GuardFactParts {
                id: GuardId::new(id),
                point,
                subject,
                predicate,
                true_arm: arm(true_target, true_kind),
                false_arm: arm(false_target, false_kind),
                source,
                evidence,
            };
            self.parts[procedure as usize].guard_facts.push(guard);
        })?;
        each_row(tx, blob_id, Table::SwitchFacts, |cells| {
            let procedure = cells.key_u32();
            let id = cells.key_u32();
            let expected = self.procedure(cells, procedure).switch_facts.len();
            dense(cells, id as usize, expected);
            let kind = cells.code();
            let point = cells.id();
            let selector = cells.opt_id();
            let selector_domain = cells.code();
            let default_present = cells.flag();
            let default_source = cells.opt_id();
            let default_target = cells.opt_id();
            let default_kind = cells.opt_code();
            let source = cells.id();
            let evidence = cells.id();
            let default_edge = match (default_source, default_target, default_kind) {
                (Some(source_point), Some(target_point), Some(kind)) => Some(SwitchEdgeParts {
                    source_point,
                    arm: GuardArm { target_point, kind },
                }),
                (None, None, None) => None,
                _ => cells.fail_at("default_source_point", "holds part of a default edge"),
            };
            self.parts[procedure as usize]
                .switch_facts
                .push(SwitchFactParts {
                    id: SwitchFactId::new(id),
                    kind,
                    point,
                    selector,
                    selector_domain,
                    cases: Vec::new(),
                    default_edge,
                    default_present,
                    source,
                    evidence,
                });
        })?;
        each_row(tx, blob_id, Table::SwitchCases, |cells| {
            let procedure = cells.key_u32();
            let switch = cells.key() as usize;
            let ordinal = cells.key() as usize;
            self.procedure(cells, procedure);
            let case = SwitchCaseFactParts {
                value: cells.id(),
                edge: SwitchEdgeParts {
                    source_point: cells.id(),
                    arm: GuardArm {
                        target_point: cells.id(),
                        kind: cells.code(),
                    },
                },
            };
            let cases = &mut self.parts[procedure as usize]
                .switch_facts
                .get_mut(switch)
                .unwrap_or_else(|| cells.fail_at("switch", "names a missing switch"))
                .cases;
            dense(cells, ordinal, cases.len());
            cases.push(case);
        })?;
        Ok(())
    }

    fn read_lifecycle_and_pointers(&mut self, tx: &Transaction<'_>) -> Result<()> {
        let blob_id = self.blob_id;
        each_row(tx, blob_id, Table::Drops, |cells| {
            let procedure = cells.key_u32();
            let ordinal = cells.key() as usize;
            let expected = self.procedure(cells, procedure).drops.len();
            dense(cells, ordinal, expected);
            let place_kind = cells.opt_code();
            let place_locator = cells.opt();
            let place_location = cells.opt_id();
            let point = cells.id();
            let behavior: DropBehaviorTag = cells.code();
            let resolution_tag = cells.opt_code();
            let targets = cells.opt();
            let source = cells.id();
            let evidence = cells.id();
            let place = self.place(cells, place_kind, place_locator, place_location);
            let behavior = match behavior {
                DropBehaviorTag::Trivial => DropBehavior::Trivial,
                DropBehaviorTag::Destructor => {
                    let candidates = self.group(cells, procedure, targets);
                    DropBehavior::Destructor(resolution(
                        cells,
                        cells.need(resolution_tag, "destructor_resolution"),
                        candidates,
                    ))
                }
            };
            self.parts[procedure as usize].drops.push(DropFact {
                place,
                point,
                behavior,
                source,
                evidence,
            });
        })?;
        each_row(tx, blob_id, Table::MoveOuts, |cells| {
            let procedure = cells.key_u32();
            let ordinal = cells.key() as usize;
            let expected = self.procedure(cells, procedure).move_outs.len();
            dense(cells, ordinal, expected);
            let place_kind = cells.opt_code();
            let place_locator = cells.opt();
            let place_location = cells.opt_id();
            let fact = MoveOutFact {
                place: self.place(cells, place_kind, place_locator, place_location),
                point: cells.id(),
                source_value: cells.id(),
                target_value: cells.id(),
                state_after: cells.code(),
                source: cells.id(),
                evidence: cells.id(),
            };
            self.parts[procedure as usize].move_outs.push(fact);
        })?;
        each_row(tx, blob_id, Table::ScopeEnds, |cells| {
            let procedure = cells.key_u32();
            let ordinal = cells.key() as usize;
            let expected = self.procedure(cells, procedure).scope_ends.len();
            dense(cells, ordinal, expected);
            let place_kind = cells.opt_code();
            let place_locator = cells.opt();
            let place_location = cells.opt_id();
            let at_kind: ScopeEndAtTag = cells.code();
            let at_point = cells.opt_id();
            let edge_source = cells.opt_id();
            let edge_target = cells.opt_id();
            let edge_kind = cells.opt_code();
            let source = cells.id();
            let evidence = cells.id();
            let at = match at_kind {
                ScopeEndAtTag::Point => ScopeEndAt::Point(cells.need(at_point, "at_point")),
                ScopeEndAtTag::Edge => ScopeEndAt::Edge {
                    source_point: cells.need(edge_source, "edge_source"),
                    target_point: cells.need(edge_target, "edge_target"),
                    kind: cells.need(edge_kind, "edge_kind"),
                },
            };
            let fact = ScopeEndFact {
                place: self.place(cells, place_kind, place_locator, place_location),
                at,
                source,
                evidence,
            };
            self.parts[procedure as usize].scope_ends.push(fact);
        })?;
        each_row(tx, blob_id, Table::PointerOrigins, |cells| {
            let procedure = cells.key_u32();
            let id = cells.key_u32();
            let expected = self.procedure(cells, procedure).pointer_origins.len();
            dense(cells, id as usize, expected);
            let point = cells.id();
            let kind: PointerOriginKindTag = cells.code();
            let place_kind = cells.opt_code();
            let place_locator = cells.opt();
            let place_location = cells.opt_id();
            let allocation = cells.opt_id();
            let byte_extent = cells.opt_u128();
            let source = cells.id();
            let evidence = cells.id();
            let kind = match kind {
                PointerOriginKindTag::StackPlace => PointerOriginKind::StackPlace {
                    place: self.place(cells, place_kind, place_locator, place_location),
                },
                PointerOriginKindTag::Allocation => PointerOriginKind::Allocation {
                    allocation: cells.need(allocation, "allocation"),
                },
            };
            self.parts[procedure as usize]
                .pointer_origins
                .push(PointerOrigin {
                    id: PointerOriginId::new(id),
                    point,
                    kind,
                    byte_extent,
                    source,
                    evidence,
                });
        })?;
        each_row(tx, blob_id, Table::PointerAliases, |cells| {
            let procedure = cells.key_u32();
            let ordinal = cells.key() as usize;
            let expected = self.procedure(cells, procedure).pointer_aliases.len();
            dense(cells, ordinal, expected);
            let point = cells.id();
            let pointer = cells.id();
            let origin = cells.id();
            let offset_kind: PointerByteOffsetTag = cells.code();
            let exact = cells.opt_i128();
            let value = cells.opt_id();
            let minimum = cells.opt_i128();
            let maximum = cells.opt_i128();
            let strength = cells.code();
            let source = cells.id();
            let evidence = cells.id();
            let byte_offset = match offset_kind {
                PointerByteOffsetTag::Exact => {
                    PointerByteOffset::Exact(cells.need(exact, "offset_exact"))
                }
                PointerByteOffsetTag::Value => {
                    PointerByteOffset::Value(cells.need(value, "offset_value"))
                }
                PointerByteOffsetTag::Range => PointerByteOffset::Range {
                    minimum: cells.need(minimum, "offset_min"),
                    maximum: cells.need(maximum, "offset_max"),
                },
                PointerByteOffsetTag::Unknown => PointerByteOffset::Unknown,
            };
            self.parts[procedure as usize]
                .pointer_aliases
                .push(PointerAlias {
                    point,
                    pointer,
                    origin,
                    byte_offset,
                    strength,
                    source,
                    evidence,
                });
        })?;
        each_row(tx, blob_id, Table::PointerAccesses, |cells| {
            let procedure = cells.key_u32();
            let ordinal = cells.key() as usize;
            let expected = self.procedure(cells, procedure).pointer_accesses.len();
            dense(cells, ordinal, expected);
            let point = cells.id();
            let pointer = cells.id();
            let kind = cells.code();
            let width_kind: PointerAccessWidthTag = cells.code();
            let exact = cells.opt_u128();
            let value = cells.opt_id();
            let multiplier = cells.opt_u128();
            let source = cells.id();
            let evidence = cells.id();
            let width = match width_kind {
                PointerAccessWidthTag::Exact => {
                    PointerAccessWidth::Exact(cells.need(exact, "width_exact"))
                }
                PointerAccessWidthTag::ValueTimes => PointerAccessWidth::ValueTimes {
                    value: cells.need(value, "width_value"),
                    multiplier: cells.need(multiplier, "width_multiplier"),
                },
                PointerAccessWidthTag::Unknown => PointerAccessWidth::Unknown,
            };
            self.parts[procedure as usize]
                .pointer_accesses
                .push(PointerAccess {
                    point,
                    pointer,
                    kind,
                    width,
                    source,
                    evidence,
                });
        })?;
        each_row(tx, blob_id, Table::PointerInvalidations, |cells| {
            let procedure = cells.key_u32();
            let ordinal = cells.key() as usize;
            let expected = self.procedure(cells, procedure).pointer_invalidations.len();
            dense(cells, ordinal, expected);
            let point = cells.id();
            let target_kind: PointerInvalidationTargetTag = cells.code();
            let target_value = cells.opt_id();
            let target_origin = cells.opt_id();
            let cause = cells.code();
            let strength = cells.code();
            let source = cells.id();
            let evidence = cells.id();
            let target = match target_kind {
                PointerInvalidationTargetTag::Pointer => {
                    PointerInvalidationTarget::Pointer(cells.need(target_value, "target_value"))
                }
                PointerInvalidationTargetTag::Origin => {
                    PointerInvalidationTarget::Origin(cells.need(target_origin, "target_origin"))
                }
            };
            self.parts[procedure as usize]
                .pointer_invalidations
                .push(PointerInvalidation {
                    point,
                    target,
                    cause,
                    strength,
                    source,
                    evidence,
                });
        })?;
        each_row(tx, blob_id, Table::IncompleteFacts, |cells| {
            let procedure = cells.key_u32();
            let ordinal = cells.key() as usize;
            let expected = self.procedure(cells, procedure).incomplete_facts.len();
            dense(cells, ordinal, expected);
            let point = cells.id();
            let subject: IncompleteSubjectTag = cells.code();
            let place_kind = cells.opt_code();
            let place_locator = cells.opt();
            let place_location = cells.opt_id();
            let value = cells.opt_id();
            let origin = cells.opt_id();
            let reason_domain: IncompleteReasonTag = cells.code();
            let reason = cells.int();
            let source = cells.id();
            let evidence = cells.id();
            let subject = match subject {
                IncompleteSubjectTag::Procedure => SemanticIncompleteSubject::Procedure,
                IncompleteSubjectTag::Place => SemanticIncompleteSubject::Place(self.place(
                    cells,
                    place_kind,
                    place_locator,
                    place_location,
                )),
                IncompleteSubjectTag::Value => {
                    SemanticIncompleteSubject::Value(cells.need(value, "value"))
                }
                IncompleteSubjectTag::PointerOrigin => {
                    SemanticIncompleteSubject::PointerOrigin(cells.need(origin, "origin"))
                }
            };
            let reason = match reason_domain {
                IncompleteReasonTag::Lifecycle => SemanticIncompleteReason::Lifecycle(
                    RowCode::try_from_code(reason)
                        .unwrap_or_else(|| cells.fail_at("reason", "is not a lifecycle reason")),
                ),
                IncompleteReasonTag::Pointer => SemanticIncompleteReason::Pointer(
                    RowCode::try_from_code(reason)
                        .unwrap_or_else(|| cells.fail_at("reason", "is not a pointer reason")),
                ),
            };
            self.parts[procedure as usize]
                .incomplete_facts
                .push(SemanticIncompleteFact {
                    point,
                    subject,
                    reason,
                    source,
                    evidence,
                });
        })?;
        each_row(tx, blob_id, Table::ReceiverTypeFacts, |cells| {
            let procedure = cells.key_u32();
            let call_site = cells.key_u32();
            self.procedure(cells, procedure);
            let member = cells.int();
            let column = cells.next;
            let segments = cells
                .opt_json_ids()
                .unwrap_or_else(|| cells.fail(column, "is NULL"));
            let fact = CallReceiverTypeFact {
                call_site: CallSiteId::new(call_site),
                receiver_type: segments
                    .into_iter()
                    .map(|segment| self.boxed_text(cells, segment))
                    .collect(),
                member: self.boxed_text(cells, member),
            };
            self.parts[procedure as usize]
                .receiver_type_facts
                .push(fact);
        })?;
        Ok(())
    }

    /// Move the grouped rows into their owners and check that every target
    /// group was claimed.
    fn finish(self) -> Vec<ProcedureSemanticsParts> {
        let Decoder {
            blob_id,
            mut parts,
            groups,
            arguments,
            events,
            ..
        } = self;
        for (procedure, groups) in groups.iter().enumerate() {
            assert!(
                groups.iter().all(Vec::is_empty),
                "semantic IR blob {blob_id} procedure {procedure} has unclaimed target groups"
            );
        }
        for ((parts, arguments), events) in parts.iter_mut().zip(arguments).zip(events) {
            for (call, arguments) in parts.call_sites.iter_mut().zip(arguments) {
                call.arguments = arguments.into();
            }
            for (point, events) in parts.points.iter_mut().zip(events) {
                point.events = events.into();
            }
        }
        parts
    }
}
