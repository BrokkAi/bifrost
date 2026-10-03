//! Integer JSON codecs for one private stage path, completion or request.
//!
//! The body has eleven positions, as in the durable structural layout:
//! `[start_symbols, start_symbol_tail, start_scopes, start_scope_tail,
//! end_symbols, end_symbol_tail, end_scopes, end_scope_tail, precedence,
//! witness, completion]`. Identity cells have different authority here:
//! non-shared cells retain the full tagged runtime integer, and negative
//! semantic cells are minus a request SharedNameId. The universal root keeps
//! its full Reserved integer. Nothing consults a durable identity catalog.
//!
//! Completion is null for Complete or an array of reason arrays for Incomplete.
//! This preserves even raw empty, repeated or ordered incomplete reasons.
//! Symbol-attached stacks contain nodes, not further symbols, so the structural
//! walks below have fixed nesting depth. All variable numbering is per value.

use brokk_bifrost_core::analyzer::structural::resolution::{
    ALL_BOUNDARY_STATUSES, ALL_PRECEDENCE_TIERS, ALL_REJECTION_REASONS, CandidateOutcome,
};
use serde_json::{Value, json};

use crate::CancellationToken;
use crate::analyzer::resolution::{
    BatchCandidateRequest, BindingFragmentId, BindingNodeId, EndpointSignature, PartialPath,
    PartialPathId, PartialScopedSymbol, PrecedenceStep, ResolutionCompletion,
    ResolutionIncompleteReason, SemanticId, SharedNameId, StackPattern, StackVariableId,
    WitnessStep,
};
use crate::analyzer::store::resolution_prepare::resolution_rows::{
    RootKeyBuilder, candidate_outcome_code, code, from_code,
};
use crate::hash::HashMap;

// The existing runtime model's layout. Decoding reconstructs through its
// validated constructors; it never manufactures an ID from unchecked bits.
const KIND_SHIFT: u32 = 61;
const PAYLOAD_MASK: u64 = (1 << KIND_SHIFT) - 1;
const CONTEXT_BASE: u64 = 1 << 60;

fn runtime_parts(cell: i64) -> (u64, u64) {
    let value = u64::try_from(cell).expect("a stage runtime coordinate is nonnegative");
    (value >> KIND_SHIFT, value & PAYLOAD_MASK)
}

fn local_parts(payload: u64) -> (u32, u32) {
    let ordinal = u32::try_from(payload >> 32).expect("a runtime mount ordinal fits u32");
    assert!(
        ordinal < BindingFragmentId::unmounted().ordinal(),
        "a stage coordinate belongs to a mounted fragment: {ordinal}"
    );
    let key = u32::try_from(payload & u64::from(u32::MAX)).expect("a runtime local key fits u32");
    (ordinal, key)
}

pub(in crate::analyzer::store) fn encode_semantic(semantic: SemanticId) -> i64 {
    let cell = if let Some(shared) = semantic.shared_name_id() {
        assert!(shared.get() > 0, "a signed stage shared name is positive");
        -i64::from(shared.get())
    } else {
        i64::try_from(semantic.get()).expect("a runtime semantic fits a SQLite integer")
    };
    assert_eq!(decode_semantic(cell), semantic);
    cell
}

pub(in crate::analyzer::store) fn decode_semantic(cell: i64) -> SemanticId {
    if cell < 0 {
        let shared = u32::try_from(cell.unsigned_abs())
            .expect("a stage shared name fits the request SharedNameId domain");
        let shared = if shared < SharedNameId::PER_REQUEST_BASE {
            SharedNameId::interned(i64::from(shared))
        } else {
            SharedNameId::per_request(shared - SharedNameId::PER_REQUEST_BASE)
        };
        return SemanticId::shared_name(shared);
    }
    let (kind, payload) = runtime_parts(cell);
    match kind {
        0 => {
            let (ordinal, key) = local_parts(payload);
            SemanticId::local(ordinal, key)
        }
        2 if payload < CONTEXT_BASE => SemanticId::operation_local(payload),
        2 => SemanticId::context_local(payload - CONTEXT_BASE),
        other => panic!("a non-shared stage semantic has Local or Operation kind: {other}"),
    }
}

pub(in crate::analyzer::store) fn encode_node(node: BindingNodeId) -> i64 {
    let cell = i64::try_from(node.get()).expect("a runtime node fits a SQLite integer");
    assert_eq!(decode_node(cell), node);
    cell
}

pub(in crate::analyzer::store) fn decode_node(cell: i64) -> BindingNodeId {
    let (kind, payload) = runtime_parts(cell);
    match kind {
        0 => {
            let (ordinal, key) = local_parts(payload);
            BindingNodeId::local(ordinal, key)
        }
        2 if payload < CONTEXT_BASE => BindingNodeId::operation_local(payload),
        2 => BindingNodeId::context_local(payload - CONTEXT_BASE),
        3 if payload == 0 => BindingNodeId::universal_root(),
        other => panic!(
            "a stage node has Local, Operation or universal-root coordinates: {other}, {payload}"
        ),
    }
}

pub(in crate::analyzer::store) fn encode_path_id(path: PartialPathId) -> i64 {
    let cell = i64::try_from(path.get()).expect("a runtime path fits a SQLite integer");
    assert_eq!(decode_path_id(cell), path);
    cell
}

pub(in crate::analyzer::store) fn decode_path_id(cell: i64) -> PartialPathId {
    let (kind, payload) = runtime_parts(cell);
    match kind {
        0 => {
            let (ordinal, key) = local_parts(payload);
            PartialPathId::local(ordinal, key)
        }
        2 if payload < CONTEXT_BASE => PartialPathId::operation_local(payload),
        2 => PartialPathId::context_local(payload - CONTEXT_BASE),
        other => panic!("a stage path has Local or Operation kind: {other}"),
    }
}

fn array<'a>(value: &'a Value, what: &str) -> &'a [Value] {
    value
        .as_array()
        .unwrap_or_else(|| panic!("stage {what} is an array: {value}"))
}

fn integer(value: &Value, what: &str) -> i64 {
    value
        .as_i64()
        .unwrap_or_else(|| panic!("stage {what} is an integer: {value}"))
}

fn variable_cell(
    variables: &mut HashMap<StackVariableId, i64>,
    variable: Option<StackVariableId>,
) -> Value {
    variable.map_or(Value::Null, |variable| {
        let next = i64::try_from(variables.len()).expect("one path's variables fit an integer");
        Value::from(*variables.entry(variable).or_insert(next))
    })
}

fn decode_variable(cell: &Value) -> Option<StackVariableId> {
    if cell.is_null() {
        return None;
    }
    let number = u64::try_from(integer(cell, "stack variable"))
        .expect("a path-local stack variable is nonnegative");
    Some(StackVariableId::operation_local(number))
}

fn endpoint_cells(
    endpoint: &EndpointSignature,
    variables: &mut HashMap<StackVariableId, i64>,
) -> Vec<Value> {
    // The endpoint node lives in a keyed column rather than these four cells.
    encode_node(endpoint.node());
    let symbols = endpoint
        .symbols()
        .fixed()
        .iter()
        .map(|symbol| {
            let semantic = encode_semantic(symbol.symbol());
            match symbol.scopes() {
                None => Value::from(semantic),
                Some(scopes) => json!([
                    semantic,
                    scopes
                        .fixed()
                        .iter()
                        .copied()
                        .map(encode_node)
                        .collect::<Vec<_>>(),
                    variable_cell(variables, scopes.tail()),
                ]),
            }
        })
        .collect::<Vec<_>>();
    vec![
        Value::Array(symbols),
        variable_cell(variables, endpoint.symbols().tail()),
        json!(
            endpoint
                .scopes()
                .fixed()
                .iter()
                .copied()
                .map(encode_node)
                .collect::<Vec<_>>()
        ),
        variable_cell(variables, endpoint.scopes().tail()),
    ]
}

/// A standalone candidate endpoint. Its variables are independent of other
/// candidate rows; whole paths instead number both endpoints together.
#[cfg(test)]
pub(in crate::analyzer::store) fn encode_endpoint(endpoint: &EndpointSignature) -> String {
    serde_json::to_string(&endpoint_cells(endpoint, &mut HashMap::default()))
        .expect("a structured stage endpoint serializes to JSON")
}

pub(in crate::analyzer::store) fn decode_endpoint(node: i64, cells: &str) -> EndpointSignature {
    let document: Value = serde_json::from_str(cells).expect("a stage endpoint is valid JSON");
    endpoint_from_cells(decode_node(node), array(&document, "endpoint"))
}

fn endpoint_from_cells(node: BindingNodeId, cells: &[Value]) -> EndpointSignature {
    assert_eq!(cells.len(), 4, "a stage endpoint has four positions");
    let symbols = array(&cells[0], "symbols")
        .iter()
        .map(|symbol| {
            if let Some(semantic) = symbol.as_i64() {
                return PartialScopedSymbol::unscoped(decode_semantic(semantic));
            }
            let symbol = array(symbol, "scoped symbol");
            assert_eq!(symbol.len(), 3, "a scoped symbol has three positions");
            PartialScopedSymbol::scoped(
                decode_semantic(integer(&symbol[0], "symbol semantic")),
                StackPattern::new(
                    array(&symbol[1], "attached scopes")
                        .iter()
                        .map(|scope| decode_node(integer(scope, "attached scope")))
                        .collect::<Vec<_>>(),
                    decode_variable(&symbol[2]),
                ),
            )
        })
        .collect::<Vec<_>>();
    EndpointSignature::new_scoped(
        node,
        StackPattern::new(symbols, decode_variable(&cells[1])),
        StackPattern::new(
            array(&cells[2], "scopes")
                .iter()
                .map(|scope| decode_node(integer(scope, "scope")))
                .collect::<Vec<_>>(),
            decode_variable(&cells[3]),
        ),
    )
}

pub(in crate::analyzer::store) fn encode_path(path: &PartialPath) -> String {
    let mut variables = HashMap::default();
    let mut cells = endpoint_cells(path.start(), &mut variables);
    cells.extend(endpoint_cells(path.end(), &mut variables));
    cells.push(json!(
        path.precedence()
            .iter()
            .map(|step| (
                code(ALL_PRECEDENCE_TIERS, step.tier),
                step.ordinal,
                encode_semantic(step.semantic),
            ))
            .collect::<Vec<_>>()
    ));
    cells.push(Value::Array(
        path.witness()
            .iter()
            .map(|step| match step {
                WitnessStep::Node(node) => Value::from(encode_node(*node)),
                WitnessStep::Candidate { semantic, outcome } => json!([
                    1,
                    encode_semantic(*semantic),
                    candidate_outcome_code(*outcome),
                ]),
                WitnessStep::Boundary { semantic, status } => json!([
                    2,
                    encode_semantic(*semantic),
                    code(ALL_BOUNDARY_STATUSES, *status),
                ]),
            })
            .collect(),
    ));
    cells.push(completion_cell(path.completion()));
    serde_json::to_string(&cells).expect("a structured stage path serializes to JSON")
}

pub(in crate::analyzer::store) fn decode_path(start: i64, end: i64, body: &str) -> PartialPath {
    let document: Value = serde_json::from_str(body).expect("a stage path body is valid JSON");
    let cells = array(&document, "path body");
    assert_eq!(cells.len(), 11, "a stage path body has eleven positions");
    let precedence = array(&cells[8], "precedence")
        .iter()
        .map(|step| {
            let step = array(step, "precedence step");
            assert_eq!(step.len(), 3, "a precedence step has three positions");
            PrecedenceStep {
                tier: from_code(
                    ALL_PRECEDENCE_TIERS,
                    integer(&step[0], "precedence tier"),
                    "precedence tier",
                ),
                ordinal: u32::try_from(integer(&step[1], "precedence ordinal"))
                    .expect("a precedence ordinal fits u32"),
                semantic: decode_semantic(integer(&step[2], "precedence semantic")),
            }
        })
        .collect::<Vec<_>>();
    let witness = array(&cells[9], "witness")
        .iter()
        .map(|step| {
            if let Some(node) = step.as_i64() {
                return WitnessStep::Node(decode_node(node));
            }
            let step = array(step, "witness step");
            assert_eq!(step.len(), 3, "a keyed witness step has three positions");
            let semantic = decode_semantic(integer(&step[1], "witness semantic"));
            match integer(&step[0], "witness tag") {
                1 => {
                    let outcome = integer(&step[2], "candidate outcome");
                    assert!(outcome >= 0, "a stage candidate outcome is nonnegative");
                    WitnessStep::Candidate {
                        semantic,
                        outcome: if outcome == 0 {
                            CandidateOutcome::Selected
                        } else {
                            CandidateOutcome::Rejected(from_code(
                                ALL_REJECTION_REASONS,
                                outcome - 1,
                                "candidate rejection reason",
                            ))
                        },
                    }
                }
                2 => WitnessStep::Boundary {
                    semantic,
                    status: from_code(
                        ALL_BOUNDARY_STATUSES,
                        integer(&step[2], "boundary status"),
                        "boundary status",
                    ),
                },
                other => panic!("unknown stage witness tag: {other}"),
            }
        })
        .collect::<Vec<_>>();
    PartialPath::new(
        endpoint_from_cells(decode_node(start), &cells[..4]),
        endpoint_from_cells(decode_node(end), &cells[4..8]),
        precedence,
        witness,
        completion_from_cell(&cells[10]),
    )
}

// Tags 0..=3 retain the durable reason vocabulary's order. The three additional
// tags are private stage vocabulary, not new durable completion kinds.
fn completion_cell(completion: &ResolutionCompletion) -> Value {
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return Value::Null;
    };
    Value::Array(
        reasons
            .iter()
            .map(|reason| match reason {
                ResolutionIncompleteReason::Cancelled => {
                    panic!("cancellation is not publishable stage completion")
                }
                ResolutionIncompleteReason::CyclicExpansion(path) => {
                    json!([0, encode_path_id(*path)])
                }
                ResolutionIncompleteReason::InconsistentPrecedence(semantic) => {
                    json!([1, encode_semantic(*semantic)])
                }
                ResolutionIncompleteReason::OpenBoundary { semantic, status } => json!([
                    2,
                    encode_semantic(*semantic),
                    code(ALL_BOUNDARY_STATUSES, *status)
                ]),
                ResolutionIncompleteReason::UnsupportedSemantic(semantic) => {
                    json!([3, encode_semantic(*semantic)])
                }
                ResolutionIncompleteReason::CyclicPrefixDependency(semantic) => {
                    json!([4, encode_semantic(*semantic)])
                }
                ResolutionIncompleteReason::ReceiverBudgetExhausted(semantic) => {
                    json!([5, encode_semantic(*semantic)])
                }
                ResolutionIncompleteReason::TimeBudgetExceeded(_) => {
                    panic!("a request-local time budget is not publishable stage completion")
                }
                ResolutionIncompleteReason::UnmountedFile { fragment } => {
                    assert!(
                        fragment.ordinal() < BindingFragmentId::unmounted().ordinal(),
                        "an unmounted-file reason identifies a selected fragment"
                    );
                    json!([6, fragment.ordinal()])
                }
            })
            .collect(),
    )
}

fn completion_from_cell(cell: &Value) -> ResolutionCompletion {
    if cell.is_null() {
        return ResolutionCompletion::Complete;
    }
    let reasons = array(cell, "completion")
        .iter()
        .map(|reason| {
            let reason = array(reason, "completion reason");
            assert!(!reason.is_empty(), "a stage completion reason has a tag");
            let tag = integer(&reason[0], "completion reason tag");
            assert_eq!(
                reason.len(),
                if tag == 2 { 3 } else { 2 },
                "a stage completion reason has its tag's payload shape"
            );
            let payload = integer(&reason[1], "completion payload");
            match tag {
                0 => ResolutionIncompleteReason::CyclicExpansion(decode_path_id(payload)),
                1 => ResolutionIncompleteReason::InconsistentPrecedence(decode_semantic(payload)),
                2 => ResolutionIncompleteReason::OpenBoundary {
                    semantic: decode_semantic(payload),
                    status: from_code(
                        ALL_BOUNDARY_STATUSES,
                        integer(&reason[2], "open boundary status"),
                        "boundary status",
                    ),
                },
                3 => ResolutionIncompleteReason::UnsupportedSemantic(decode_semantic(payload)),
                4 => ResolutionIncompleteReason::CyclicPrefixDependency(decode_semantic(payload)),
                5 => ResolutionIncompleteReason::ReceiverBudgetExhausted(decode_semantic(payload)),
                6 => {
                    let ordinal = u32::try_from(payload)
                        .expect("a stage completion fragment ordinal fits u32");
                    assert!(
                        ordinal < BindingFragmentId::unmounted().ordinal(),
                        "an unmounted-file reason identifies a selected fragment"
                    );
                    ResolutionIncompleteReason::UnmountedFile {
                        fragment: BindingFragmentId::at_ordinal(ordinal),
                    }
                }
                other => panic!("unknown stage completion tag: {other}"),
            }
        })
        .collect::<Vec<_>>();
    ResolutionCompletion::Incomplete(reasons.into())
}

pub(in crate::analyzer::store) fn encode_completion(
    completion: &ResolutionCompletion,
) -> Option<String> {
    let cell = completion_cell(completion);
    if cell.is_null() {
        return None;
    }
    Some(serde_json::to_string(&cell).expect("a structured stage completion serializes to JSON"))
}

pub(in crate::analyzer::store) fn decode_completion(body: Option<&str>) -> ResolutionCompletion {
    let Some(body) = body else {
        return ResolutionCompletion::Complete;
    };
    let cell: Value = serde_json::from_str(body).expect("a stage completion is valid JSON");
    assert!(
        cell.is_array(),
        "a nonnull stage completion column contains a reason array"
    );
    completion_from_cell(&cell)
}

/// Every valid stage symbol is representable, including foreign mounted and
/// operation/context symbols. Boundaries include only proper prefixes, exactly
/// as for a fully represented ordinary request. SQL keeps the tail predicate.
pub(in crate::analyzer::store) fn root_candidate_request(
    ordinal: usize,
    request: &BatchCandidateRequest,
    cancellation: &CancellationToken,
) -> Option<String> {
    let mut key = RootKeyBuilder::default();
    for symbol in request.endpoint().symbols().fixed() {
        if cancellation.is_cancelled() {
            return None;
        }
        let semantic = encode_semantic(symbol.symbol());
        if semantic < 0 {
            key.push(None, Some(-semantic), symbol.scopes().is_some());
        } else {
            key.push(Some(semantic), None, symbol.scopes().is_some());
        }
    }
    if cancellation.is_cancelled() {
        return None;
    }
    let (key, mut boundaries) = key.finish();
    boundaries
        .pop()
        .expect("every root key has its final boundary");
    Some(
        serde_json::to_string(&(
            ordinal,
            key,
            i64::from(request.endpoint().symbols().tail().is_some()),
            1,
            boundaries,
        ))
        .expect("a structured stage root request serializes to JSON"),
    )
}

/// Decode the checked structured node tag shared by ordinary and stage rows.
pub(in crate::analyzer::store) fn decode_node_kind(
    kind: i64,
    semantic: Option<SemanticId>,
    target: Option<BindingNodeId>,
) -> crate::analyzer::resolution::BindingNodeKind {
    use crate::analyzer::resolution::BindingNodeKind;
    match kind {
        0 => BindingNodeKind::Root,
        1 => BindingNodeKind::Scope,
        2 => BindingNodeKind::PushSymbol(semantic.expect("push node semantic")),
        3 => BindingNodeKind::PopSymbol(semantic.expect("pop node semantic")),
        4 => BindingNodeKind::PushScopedSymbol(semantic.expect("scoped push node semantic")),
        5 => BindingNodeKind::PopScopedSymbol(semantic.expect("scoped pop node semantic")),
        6 => BindingNodeKind::DropScopes,
        7 => BindingNodeKind::JumpToScope(target.expect("jump node target")),
        8 => BindingNodeKind::Reference(semantic.expect("reference node semantic")),
        9 => BindingNodeKind::Definition(semantic.expect("definition node semantic")),
        kind => panic!("invalid checked node kind: {kind}"),
    }
}

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
