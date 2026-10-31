//! Query-local Rust pointer findings projected from the shared provenance solver.

use super::{DerivationExecutionCause, Incompleteness};
use std::path::PathBuf;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::CodeQueryRustPointerFinding;
use crate::analyzer::semantic::{
    AllocationId, IcfgProvider, IcfgSnapshotLimits, OracleLimits, PointerAccessWidth, PointerAlias,
    PointerByteOffset, PointerInvalidation, PointerInvalidationCause, PointerInvalidationTarget,
    PointerOrigin, PointerOriginId, PointerOriginKind, PointerRelationStrength, SemanticBudget,
    SemanticRequest, ValueFlowEndpoint, ValueFlowRelationKind, ValueFlowSnapshot, ValueId,
    WorkspaceIcfgProvider,
};
use crate::analyzer::semantic_model::{
    ActiveSemanticModelSnapshot, SemanticModelCallApplication, SemanticModelCallableDisposition,
    SemanticModelCallableKey, SemanticModelCompleteness, SemanticModelOverlay,
    SemanticModelOverlayDisposition, SemanticModelSymbol, SemanticModelSymbolKind, TypeRef,
};
use crate::analyzer::{Language, ProjectFile, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::text_utils::compute_line_starts;
use brokk_bifrost_flow::dataflow::{DataflowRequest, IcfgSolveInput, SolverBudget};
use brokk_bifrost_flow::value_flow::{
    ClosureLimits, PointerBounds, PointerProvenanceAdditionalFacts, PointerProvenancePlan,
    ValueFlowCache, ValueFlowInput, ValueFlowMayStatus, WorkspaceValueFlowProvider,
    discover_closure_with, solve_pointer_provenance_on_snapshot,
};

const MAX_CLOSURE_PROCEDURES: usize = 512;

#[derive(Debug, Clone)]
pub(super) struct RustPointerFindingValue {
    pub(super) file: ProjectFile,
    pub(super) byte_span: std::ops::Range<usize>,
    pub(super) row: CodeQueryRustPointerFinding,
}

pub(super) struct RustPointerFindings {
    pub(super) incompleteness: Incompleteness,
    pub(super) rows: Vec<RustPointerFindingValue>,
    pub(super) complete: bool,
    pub(super) reasons: Vec<String>,
}

fn modeled_call_return_owner(
    overlay: &SemanticModelOverlay,
    owner: &str,
    member: &str,
    has_receiver: bool,
    parameter_count: usize,
) -> Option<String> {
    let callable = unique_modeled_callable(overlay, owner, member, has_receiver, parameter_count)?;
    model_type_ref_owner(overlay, callable.structured_signature()?.returns.as_ref()?)
}

fn unique_modeled_callable(
    overlay: &SemanticModelOverlay,
    owner: &str,
    member: &str,
    has_receiver: bool,
    parameter_count: usize,
) -> Option<Arc<SemanticModelSymbol>> {
    let parameter_count = u32::try_from(parameter_count).ok()?;
    let application = SemanticModelCallApplication::positional(parameter_count);
    let matched = overlay.callable_for_application(
        SemanticModelCallableKey::new(
            Language::Rust.config_label(),
            owner,
            member,
            has_receiver,
            parameter_count,
        ),
        &application,
    );
    if matched.disposition != SemanticModelCallableDisposition::Unique {
        return None;
    }
    let [callable] = matched.records.as_slice() else {
        return None;
    };
    if !callable.externally_visible()
        || callable.provenance.ambiguous
        || callable.provenance.completeness != SemanticModelCompleteness::Complete
    {
        return None;
    }
    Some(callable.clone())
}

fn model_type_ref_owner(overlay: &SemanticModelOverlay, mut reference: &TypeRef) -> Option<String> {
    loop {
        match reference {
            TypeRef::ByRef { element, .. } | TypeRef::Pointer { element } => {
                reference = element;
            }
            TypeRef::Declared { id, .. } => {
                let matched = overlay.symbols_with_id(id);
                if matched.disposition != SemanticModelOverlayDisposition::Unique {
                    return None;
                }
                let [symbol] = matched.records.as_slice() else {
                    return None;
                };
                return is_complete_rust_nominal_type(symbol)
                    .then(|| symbol.qualified_name.clone());
            }
            TypeRef::Named { name, .. } => {
                let symbol = unique_rust_nominal_type(overlay, name)?;
                return Some(symbol.qualified_name.clone());
            }
            _ => return None,
        }
    }
}

fn unique_rust_nominal_type(
    overlay: &SemanticModelOverlay,
    identity: &str,
) -> Option<Arc<SemanticModelSymbol>> {
    let mut matches = overlay
        .symbols_named(identity)
        .records
        .into_iter()
        .filter(|symbol| {
            symbol.qualified_name == identity && is_complete_rust_nominal_type(symbol)
        });
    let symbol = matches.next()?;
    matches.next().is_none().then_some(symbol.clone())
}

fn is_complete_rust_nominal_type(symbol: &SemanticModelSymbol) -> bool {
    symbol.owner_id.is_none()
        && symbol.language == Language::Rust.config_label()
        && symbol.externally_visible()
        && !symbol.provenance.ambiguous
        && symbol.provenance.completeness == SemanticModelCompleteness::Complete
        && matches!(
            symbol.kind,
            SemanticModelSymbolKind::Struct
                | SemanticModelSymbolKind::Enum
                | SemanticModelSymbolKind::Union
        )
}

fn merge_modeled_owner(
    owners: &mut std::collections::HashMap<crate::analyzer::semantic::ValueId, Box<str>>,
    ambiguous: &mut std::collections::HashSet<crate::analyzer::semantic::ValueId>,
    value: crate::analyzer::semantic::ValueId,
    owner: &str,
) -> bool {
    if ambiguous.contains(&value) {
        return false;
    }
    match owners.get(&value) {
        Some(existing) if existing.as_ref() == owner => false,
        Some(_) => {
            owners.remove(&value);
            ambiguous.insert(value);
            true
        }
        None => {
            owners.insert(value, owner.into());
            true
        }
    }
}

fn runtime_identity_sources(
    snapshot: &ValueFlowSnapshot,
) -> std::collections::HashMap<ValueId, Vec<ValueId>> {
    let mut sources_by_target = std::collections::HashMap::<ValueId, Vec<ValueId>>::new();
    for relation in snapshot.relations() {
        if relation.kind != ValueFlowRelationKind::Assignment
            || !relation.is_proven_complete()
            || relation
                .transfer
                .is_some_and(|transfer| !transfer.preserves_runtime_class())
        {
            continue;
        }
        let (ValueFlowEndpoint::Value(source), ValueFlowEndpoint::Value(target)) =
            (&relation.source, &relation.target)
        else {
            continue;
        };
        sources_by_target
            .entry(target.id())
            .or_default()
            .push(source.id());
    }
    for sources in sources_by_target.values_mut() {
        sources.sort_unstable_by_key(|value| value.index());
        sources.dedup();
    }
    sources_by_target
}

fn runtime_identity_roots(
    value: ValueId,
    sources_by_target: &std::collections::HashMap<ValueId, Vec<ValueId>>,
) -> Vec<ValueId> {
    let mut pending = vec![value];
    let mut visited = std::collections::HashSet::new();
    let mut roots = Vec::new();
    while let Some(target) = pending.pop() {
        if !visited.insert(target) {
            continue;
        }
        if let Some(sources) = sources_by_target.get(&target) {
            pending.extend(sources.iter().copied());
        } else {
            roots.push(target);
        }
    }
    if roots.is_empty() {
        roots.extend(visited);
    }
    roots.sort_unstable_by_key(|value| value.index());
    roots.dedup();
    roots
}

fn modeled_value_owners(
    snapshot: &ValueFlowSnapshot,
    overlay: &SemanticModelOverlay,
) -> (
    std::collections::HashMap<crate::analyzer::semantic::ValueId, Box<str>>,
    std::collections::HashSet<crate::analyzer::semantic::ValueId>,
) {
    let procedure = snapshot.procedure();
    let semantics = procedure.semantics();
    let mut owners = std::collections::HashMap::new();
    let mut ambiguous = std::collections::HashSet::new();
    for fact in semantics.receiver_type_facts() {
        let Some(call) = semantics.call_site(fact.call_site) else {
            unreachable!("validated receiver type fact names a live call site");
        };
        let Some(result) = call.result else {
            continue;
        };
        let owner = fact
            .receiver_type
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<&str>>()
            .join(".");
        if let Some(return_owner) = modeled_call_return_owner(
            overlay,
            &owner,
            &fact.member,
            call.receiver.is_some(),
            call.arguments.len(),
        ) {
            merge_modeled_owner(&mut owners, &mut ambiguous, result, &return_owner);
        }
    }
    loop {
        let mut changed = false;
        for relation in snapshot.relations() {
            if relation.kind != ValueFlowRelationKind::Assignment
                || relation
                    .transfer
                    .is_some_and(|transfer| !transfer.preserves_runtime_class())
            {
                continue;
            }
            let (ValueFlowEndpoint::Value(source), ValueFlowEndpoint::Value(target)) =
                (&relation.source, &relation.target)
            else {
                continue;
            };
            let source = source.id();
            let target = target.id();
            if ambiguous.contains(&source) {
                changed |= ambiguous.insert(target);
                owners.remove(&target);
                continue;
            }
            let Some(owner) = owners.get(&source).cloned() else {
                continue;
            };
            changed |= merge_modeled_owner(&mut owners, &mut ambiguous, target, &owner);
        }
        if !changed {
            break;
        }
    }
    (owners, ambiguous)
}

fn modeled_vec_pointer_facts(
    snapshots: &[ValueFlowInput<ValueFlowSnapshot>],
    overlay: &SemanticModelOverlay,
) -> PointerProvenanceAdditionalFacts {
    let mut facts = PointerProvenanceAdditionalFacts::default();
    for input in snapshots {
        let snapshot = input.value();
        let procedure = snapshot.procedure();
        let semantics = procedure.semantics();
        let (owners, ambiguous_owners) = modeled_value_owners(snapshot, overlay);
        let identity_sources = runtime_identity_sources(snapshot);
        let mut origins_by_owner = std::collections::HashMap::<ValueId, PointerOriginId>::new();
        let mut next_origin = semantics.pointer_origins().len();
        let mut next_allocation = semantics.allocations().len();

        for fact in semantics.receiver_type_facts() {
            let Some(call) = semantics.call_site(fact.call_site) else {
                unreachable!("validated receiver type fact names a live call site");
            };
            let Some(receiver) = call.receiver else {
                continue;
            };
            let owner = fact
                .receiver_type
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<&str>>()
                .join(".");
            if !matches!(owner.as_str(), "std.vec.Vec" | "alloc.vec.Vec")
                || unique_rust_nominal_type(overlay, &owner).is_none()
                || ambiguous_owners.contains(&receiver)
                || owners
                    .get(&receiver)
                    .is_some_and(|inferred| inferred.as_ref() != owner)
            {
                continue;
            }
            if unique_modeled_callable(overlay, &owner, &fact.member, true, call.arguments.len())
                .is_none()
            {
                continue;
            };

            match fact.member.as_ref() {
                "as_ptr" | "as_mut_ptr" => {
                    let Some(pointer) = call.result else {
                        continue;
                    };
                    if semantics
                        .pointer_aliases()
                        .iter()
                        .any(|alias| alias.point == call.point && alias.pointer == pointer)
                    {
                        continue;
                    }
                    for owner_identity in runtime_identity_roots(receiver, &identity_sources) {
                        let origin = if let Some(origin) =
                            origins_by_owner.get(&owner_identity).copied()
                        {
                            origin
                        } else {
                            let origin = PointerOriginId::try_from_index(next_origin).expect(
                                "query-local Rust pointer origin IDs fit the dense ID domain",
                            );
                            next_origin += 1;
                            let allocation = AllocationId::try_from_index(next_allocation)
                                .expect("query-local Rust allocation IDs fit the dense ID domain");
                            next_allocation += 1;
                            facts.origins.push((
                                procedure.clone(),
                                PointerOrigin {
                                    id: origin,
                                    point: call.point,
                                    kind: PointerOriginKind::Allocation { allocation },
                                    byte_extent: None,
                                    source: call.source,
                                    evidence: call.evidence,
                                },
                            ));
                            origins_by_owner.insert(owner_identity, origin);
                            origin
                        };
                        facts.aliases.push((
                            procedure.clone(),
                            PointerAlias {
                                point: call.point,
                                pointer,
                                origin,
                                byte_offset: PointerByteOffset::Exact(0),
                                strength: PointerRelationStrength::Must,
                                source: call.source,
                                evidence: call.evidence,
                            },
                        ));
                    }
                }
                "push" => {
                    for origin in runtime_identity_roots(receiver, &identity_sources)
                        .iter()
                        .filter_map(|owner_identity| origins_by_owner.get(owner_identity))
                        .copied()
                    {
                        facts.invalidations.push((
                            procedure.clone(),
                            PointerInvalidation {
                                point: call.point,
                                target: PointerInvalidationTarget::Origin(origin),
                                cause: PointerInvalidationCause::PossibleReallocation,
                                strength: PointerRelationStrength::May,
                                source: call.source,
                                evidence: call.evidence,
                            },
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    facts
}

pub(super) fn analyze(
    workspace: &WorkspaceAnalyzer,
    root: &crate::analyzer::semantic::ProcedureHandle,
    active_models: Option<std::sync::Arc<ActiveSemanticModelSnapshot>>,
    semantic_budget: &mut SemanticBudget,
    solver_work: brokk_bifrost_flow::dataflow::SolverWork,
    cancellation: &CancellationToken,
) -> Result<RustPointerFindings, String> {
    let icfg_provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
        workspace,
        active_models.clone(),
    );
    let value_flow_provider = WorkspaceValueFlowProvider::with_oracle(
        icfg_provider.oracle().clone(),
        icfg_provider.behavior_identity(),
        ValueFlowCache::default(),
    );
    let closure = discover_closure_with(
        &value_flow_provider,
        root,
        ClosureLimits {
            max_procedures: MAX_CLOSURE_PROCEDURES,
        },
        semantic_budget,
        cancellation,
    )
    .map_err(|error| format!("pointer procedure closure failed: {error}"))?;
    let from_status = |status| {
        use brokk_bifrost_flow::dataflow::SemanticInputStatus;
        match status {
            SemanticInputStatus::Cancelled => {
                Incompleteness::Operational(DerivationExecutionCause::Cancelled)
            }
            SemanticInputStatus::ExceededBudget { .. } => {
                Incompleteness::Operational(DerivationExecutionCause::Budget)
            }
            SemanticInputStatus::Complete
            | SemanticInputStatus::Ambiguous
            | SemanticInputStatus::Unknown
            | SemanticInputStatus::Unsupported { .. }
            | SemanticInputStatus::Unproven => Incompleteness::Content,
        }
    };
    let mut incompleteness = if closure.truncated {
        Incompleteness::Operational(DerivationExecutionCause::Budget)
    } else {
        Incompleteness::Content
    };
    for status in closure
        .snapshots
        .iter()
        .map(|input| input.status())
        .chain(closure.bindings.iter().map(|input| input.status()))
    {
        incompleteness = incompleteness.combine(from_status(status));
    }
    for (_, reason) in &closure.skipped {
        use brokk_bifrost_flow::dataflow::SemanticInputStatus;
        use brokk_bifrost_flow::value_flow::SkipReason;
        incompleteness = incompleteness.combine(match reason {
            SkipReason::ProviderError { .. } => {
                Incompleteness::Operational(DerivationExecutionCause::Provider)
            }
            SkipReason::RelationsUnavailable { status } => match status {
                SemanticInputStatus::Cancelled => {
                    Incompleteness::Operational(DerivationExecutionCause::Cancelled)
                }
                SemanticInputStatus::ExceededBudget { .. } => {
                    Incompleteness::Operational(DerivationExecutionCause::Budget)
                }
                SemanticInputStatus::Complete
                | SemanticInputStatus::Ambiguous
                | SemanticInputStatus::Unknown
                | SemanticInputStatus::Unsupported { .. }
                | SemanticInputStatus::Unproven => Incompleteness::Content,
            },
        });
    }
    let mut reasons = closure
        .skipped
        .iter()
        .map(|skipped| format!("skipped procedure: {skipped:#?}"))
        .collect::<Vec<_>>();
    let additional_pointer_facts = active_models
        .as_deref()
        .and_then(ActiveSemanticModelSnapshot::semantic_model_overlay)
        .map(|overlay| modeled_vec_pointer_facts(&closure.snapshots, overlay))
        .unwrap_or_default();
    let plan = PointerProvenancePlan::try_new_with_additional_facts(
        root.clone(),
        closure.snapshots,
        closure.bindings,
        additional_pointer_facts,
    )
    .map_err(|error| format!("pointer provenance plan failed: {error}"))?;
    let icfg = icfg_provider
        .snapshot(
            root,
            IcfgSnapshotLimits::default(),
            &mut SemanticRequest::new(semantic_budget, cancellation),
        )
        .map_err(|error| format!("pointer ICFG snapshot failed: {error}"))?;
    let input = IcfgSolveInput::from_outcome(&icfg)
        .map_err(|error| format!("pointer ICFG snapshot has no solve input: {error}"))?;
    incompleteness = incompleteness.combine(from_status(input.status()));
    let mut solver_budget = SolverBudget::new(solver_work);
    let result = solve_pointer_provenance_on_snapshot(
        &icfg_provider,
        &plan,
        input,
        OracleLimits::default(),
        semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, cancellation),
    )
    .map_err(|error| format!("pointer provenance solver failed: {error}"))?;

    incompleteness = incompleteness.combine(match result.value_flow().result().termination() {
        brokk_bifrost_flow::dataflow::SolverTermination::Cancelled => {
            Incompleteness::Operational(DerivationExecutionCause::Cancelled)
        }
        brokk_bifrost_flow::dataflow::SolverTermination::ExceededBudget(_) => {
            Incompleteness::Operational(DerivationExecutionCause::Budget)
        }
        brokk_bifrost_flow::dataflow::SolverTermination::FixedPoint => Incompleteness::Content,
    });
    if !result.value_flow().is_complete() && incompleteness == Incompleteness::Content {
        // The composed value-flow result no longer exposes which discovery
        // input remained open. Do not infer content from its rendered reasons.
        incompleteness = Incompleteness::Operational(DerivationExecutionCause::Provider);
    }
    if !result.is_complete() {
        reasons.push("value-flow discovery is incomplete".to_owned());
    }
    let global_reasons = reasons.clone();
    let mut rows = Vec::new();
    for access in result.accesses() {
        if !access.is_complete() {
            reasons.push(format!(
                "access {:?} has incomplete pointer evidence: {:#?}",
                access.access, access.incomplete_reasons
            ));
        }
        for origin in &access.origins {
            let origin_id = stable_origin_id(&origin.procedure, origin.origin.id.index());
            let mut local_rows = Vec::new();
            if matches!(&origin.origin.kind, PointerOriginKind::StackPlace { .. }) {
                for witness in &origin.scope_ends_before {
                    let path_proven = witness.path_status == ValueFlowMayStatus::Proven;
                    let strength = effective_strength(origin.strength, None, path_proven);
                    local_rows.push((
                        "access_after_lifetime_ended",
                        None,
                        strength,
                        path_proven,
                        witness.scope_end.source.index(),
                    ));
                }
            }
            for witness in &origin.invalidations_before {
                let path_proven = witness.path_status == ValueFlowMayStatus::Proven;
                let strength = effective_strength(
                    origin.strength,
                    Some(witness.invalidation.strength),
                    path_proven,
                );
                local_rows.push((
                    "access_invalid_pointer",
                    Some(witness.invalidation.cause.label()),
                    strength,
                    path_proven,
                    witness.invalidation.source.index(),
                ));
            }
            if matches!(
                origin.bounds,
                PointerBounds::OutOfBounds | PointerBounds::MayBeOutOfBounds
            ) {
                let bounds_may = origin.bounds == PointerBounds::MayBeOutOfBounds;
                let strength = if bounds_may {
                    PointerRelationStrength::May
                } else {
                    origin.strength
                };
                local_rows.push((
                    "access_invalid_pointer",
                    None,
                    strength,
                    true,
                    access.access.point.index(),
                ));
            }
            for (relation, invalidation_cause, strength, path_proven, witness_identity) in
                local_rows
            {
                let mapping = access
                    .procedure
                    .semantics()
                    .source_mapping(access.access.source)
                    .expect("validated pointer access retains its source mapping");
                let path = mapping.locator.path().as_str();
                let file = ProjectFile::new(
                    workspace.analyzer().project().root().to_path_buf(),
                    PathBuf::from(path),
                );
                let Some(source) = workspace.analyzer().indexed_source(&file) else {
                    reasons.push(format!(
                        "source text is unavailable for pointer access at {path}"
                    ));
                    continue;
                };
                let span = mapping.locator.anchor().span();
                let start = usize::try_from(span.start_byte())
                    .expect("validated semantic source offsets fit usize");
                let end = usize::try_from(span.end_byte())
                    .expect("validated semantic source offsets fit usize");
                let line_starts = compute_line_starts(&source);
                let range = super::render::range_for_offsets(&source, &line_starts, start, end);
                let proof = if path_proven { "proven" } else { "unproven" };
                let completeness = if access.is_complete() && result.is_complete() {
                    "complete"
                } else {
                    "partial"
                };
                let reason = (completeness == "partial").then(|| {
                    global_reasons
                        .iter()
                        .cloned()
                        .chain(
                            access
                                .incomplete_reasons
                                .iter()
                                .map(|reason| format!("{reason:?}")),
                        )
                        .collect::<Vec<_>>()
                        .join(", ")
                });
                let id = stable_finding_id(
                    relation,
                    &access.procedure,
                    access.access.point.index(),
                    &origin_id,
                    witness_identity,
                    invalidation_cause,
                );
                rows.push(RustPointerFindingValue {
                    file: file.clone(),
                    byte_span: start..end,
                    row: CodeQueryRustPointerFinding {
                        id,
                        path: path.to_string(),
                        language: "rust",
                        range,
                        relation,
                        origin_id: origin_id.clone(),
                        origin_kind: match &origin.origin.kind {
                            PointerOriginKind::StackPlace { .. } => "stack_place",
                            PointerOriginKind::Allocation { .. } => "allocation",
                        },
                        invalidation_cause,
                        access_kind: access.access.kind.label(),
                        strength: strength.label(),
                        path_proven,
                        bounds: bounds_label(origin.bounds),
                        byte_offset: offset_label(origin.byte_offset),
                        byte_extent: origin.origin.byte_extent.map(|extent| extent.to_string()),
                        access_width: width_label(access.access.width),
                        proof,
                        completeness,
                        reason: reason.filter(|reason| !reason.is_empty()),
                    },
                });
            }
        }
    }
    rows.sort_unstable_by(|left, right| {
        (
            &left.row.path,
            left.row.range.start_line,
            left.row.range.start_column,
            left.row.relation,
            &left.row.id,
        )
            .cmp(&(
                &right.row.path,
                right.row.range.start_line,
                right.row.range.start_column,
                right.row.relation,
                &right.row.id,
            ))
    });
    reasons.sort_unstable();
    reasons.dedup();
    Ok(RustPointerFindings {
        incompleteness,
        rows,
        complete: reasons.is_empty(),
        reasons,
    })
}

fn effective_strength(
    alias: PointerRelationStrength,
    event: Option<PointerRelationStrength>,
    path_proven: bool,
) -> PointerRelationStrength {
    if alias == PointerRelationStrength::Must
        && event.is_none_or(|strength| strength == PointerRelationStrength::Must)
        && path_proven
    {
        PointerRelationStrength::Must
    } else {
        PointerRelationStrength::May
    }
}

fn bounds_label(bounds: PointerBounds) -> &'static str {
    match bounds {
        PointerBounds::InBounds => "in_bounds",
        PointerBounds::OutOfBounds => "out_of_bounds",
        PointerBounds::MayBeOutOfBounds => "may_be_out_of_bounds",
        PointerBounds::Incomplete(_) => "incomplete",
    }
}

fn offset_label(offset: PointerByteOffset) -> Option<String> {
    match offset {
        PointerByteOffset::Exact(value) => Some(value.to_string()),
        PointerByteOffset::Range { minimum, maximum } => Some(format!("{minimum}..{maximum}")),
        PointerByteOffset::Value(_) | PointerByteOffset::Unknown => None,
    }
}

fn width_label(width: PointerAccessWidth) -> Option<String> {
    match width {
        PointerAccessWidth::Exact(value) => Some(value.to_string()),
        PointerAccessWidth::ValueTimes { value, multiplier } => {
            Some(format!("value:{}*{multiplier}", value.index()))
        }
        PointerAccessWidth::Unknown => None,
    }
}

fn stable_origin_id(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    origin_index: usize,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"bifrost.rust.pointer_origin.v1\0");
    digest.update(brokk_bifrost_flow::flow_state::procedure_wire_id(procedure).as_bytes());
    digest.update((origin_index as u64).to_le_bytes());
    format!("{:x}", digest.finalize())
}

fn stable_finding_id(
    relation: &str,
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    point: usize,
    origin_id: &str,
    witness_identity: usize,
    cause: Option<&str>,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"bifrost.rust.pointer_finding.v1\0");
    digest.update(relation.as_bytes());
    digest.update(brokk_bifrost_flow::flow_state::procedure_wire_id(procedure).as_bytes());
    digest.update((point as u64).to_le_bytes());
    digest.update(origin_id.as_bytes());
    digest.update((witness_identity as u64).to_le_bytes());
    if let Some(cause) = cause {
        digest.update(cause.as_bytes());
    }
    format!("{:x}", digest.finalize())
}
