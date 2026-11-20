//! Query-local Rust pointer findings projected from the shared provenance solver.

use super::{DerivationExecutionCause, Incompleteness};
use std::path::PathBuf;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::{CodeQueryRustPointerFinding, CodeQuerySourceSpan};
use crate::analyzer::semantic::{
    AllocationId, IcfgProvider, IcfgSnapshotLimits, OracleLimits, PointerAccessWidth, PointerAlias,
    PointerByteOffset, PointerInvalidation, PointerInvalidationCause, PointerInvalidationTarget,
    PointerOrigin, PointerOriginId, PointerOriginKind, PointerRelationStrength, ProcedureHandle,
    SemanticBudget, SemanticRequest, SemanticWork, SourceMappingId, ValueFlowEndpoint,
    ValueFlowRelationKind, ValueFlowSnapshot, ValueId, WorkspaceIcfgProvider,
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
    ClosureLimits, PointerBounds, PointerProvenanceAccess, PointerProvenanceAdditionalFacts,
    PointerProvenanceOrigin, PointerProvenancePlan, ValueFlowCache, ValueFlowInput,
    ValueFlowMayStatus, WorkspaceValueFlowProvider, discover_closure_with,
    solve_pointer_provenance_on_snapshot,
};

fn from_status(status: brokk_bifrost_flow::dataflow::SemanticInputStatus) -> Incompleteness {
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
}

fn skip_incompleteness(reason: &brokk_bifrost_flow::value_flow::SkipReason) -> Incompleteness {
    use brokk_bifrost_flow::value_flow::SkipReason;
    match reason {
        SkipReason::ProviderError { .. } => {
            Incompleteness::Operational(DerivationExecutionCause::Provider)
        }
        SkipReason::RelationsUnavailable { status } => from_status(*status),
    }
}

fn combine_discovery_incompleteness(
    prior: Incompleteness,
    status: brokk_bifrost_flow::value_flow::ValueFlowDiscoveryStatus,
) -> Incompleteness {
    match status.execution_cause() {
        Some(cause) => prior.combine(Incompleteness::Operational(cause)),
        None => prior,
    }
}

const MAX_CLOSURE_PROCEDURES: usize = 512;

#[derive(Debug, Clone)]
pub(super) struct RustPointerFindingValue {
    pub(super) file: ProjectFile,
    pub(super) byte_span: std::ops::Range<usize>,
    pub(super) row: CodeQueryRustPointerFinding,
    incomplete_reasons: Vec<String>,
    source_ranges_omitted: usize,
    alternative_states_omitted: usize,
    offset: PointerByteOffset,
    bounds: PointerBounds,
}

pub(super) struct RustPointerFindings {
    pub(super) incompleteness: Incompleteness,
    pub(super) rows: Vec<RustPointerFindingValue>,
    pub(super) complete: bool,
    pub(super) reasons: Vec<String>,
    pub(super) retained_source_bytes: usize,
}

pub(super) fn incomplete_diagnostic_message(reasons: &[String]) -> String {
    brokk_bifrost_core::bounded_output::bounded_diagnostic_items(
        format_args!("Rust pointer provenance is incomplete: {reasons:#?}"),
        format_args!("Rust pointer provenance is incomplete"),
        reasons,
    )
}

#[derive(Clone, Copy)]
struct PointerSourceLimits {
    max_ranges: usize,
    max_bytes: usize,
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
                let matched = overlay.symbols_with_id_for(id, "rust");
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
        .symbols_named_for(identity, "rust")
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

#[allow(clippy::too_many_arguments)]
pub(super) fn analyze(
    workspace: &WorkspaceAnalyzer,
    root: &crate::analyzer::semantic::ProcedureHandle,
    active_models: Option<std::sync::Arc<ActiveSemanticModelSnapshot>>,
    _guards: Option<&brokk_bifrost_analysis::analyzer::semantic::partial_flow::guard_bindings::CompiledGuardBindings>,
    semantic_budget: &mut SemanticBudget,
    solver_work: brokk_bifrost_flow::dataflow::SolverWork,
    max_source_bytes: usize,
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
        incompleteness = incompleteness.combine(skip_incompleteness(reason));
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

    incompleteness =
        combine_discovery_incompleteness(incompleteness, result.value_flow().discovery_status());
    if !result.is_complete() {
        reasons.push("value-flow discovery is incomplete".to_owned());
    }
    let global_reasons = reasons.clone();
    let available = semantic_budget.remaining();
    let source_limits = PointerSourceLimits {
        max_ranges: available.nested_entries,
        max_bytes: max_source_bytes.min(available.owned_text_bytes),
    };
    let mut collecting_sources = source_limits;
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
            for PointerFindingWitness {
                relation,
                invalidation_cause,
                strength,
                path_proven,
                identity: witness_identity,
                source_procedure,
                source_mapping,
            } in pointer_finding_witnesses(access, origin)
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
                let source_mapping = source_procedure
                    .semantics()
                    .source_mapping(source_mapping)
                    .expect("validated pointer provenance retains its source mapping");
                let source_path = source_mapping.locator.path().as_str();
                let collected = collect_pointer_source(
                    &mut collecting_sources,
                    source_path,
                    || {
                        let source_file = ProjectFile::new(
                            workspace.analyzer().project().root().to_path_buf(),
                            PathBuf::from(source_path),
                        );
                        let source_text = workspace.analyzer().indexed_source(&source_file).ok_or_else(|| {
                        format!("source text is unavailable for pointer provenance at {source_path}")
                    })?;
                        let source_span = source_mapping.locator.anchor().span();
                        let start_byte = usize::try_from(source_span.start_byte())
                            .expect("validated semantic source offsets fit usize");
                        let end_byte = usize::try_from(source_span.end_byte())
                            .expect("validated semantic source offsets fit usize");
                        Ok(CodeQuerySourceSpan {
                            path: source_path.to_owned(),
                            range: super::render::range_for_offsets(
                                &source_text,
                                &compute_line_starts(&source_text),
                                start_byte,
                                end_byte,
                            ),
                            start_byte,
                            end_byte,
                        })
                    },
                );
                let (source_ranges, unavailable_source, source_ranges_omitted) = match collected {
                    CollectedPointerSource::Range(source) => (vec![source], None, 0),
                    CollectedPointerSource::Unavailable(reason) => {
                        reasons.push(reason.clone());
                        (Vec::new(), Some(reason), 0)
                    }
                    CollectedPointerSource::Omitted => (Vec::new(), None, 1),
                };
                let proof = if path_proven { "proven" } else { "unproven" };
                let completeness =
                    if access.is_complete() && result.is_complete() && unavailable_source.is_none()
                    {
                        "complete"
                    } else {
                        "partial"
                    };
                let incomplete_reasons = if completeness == "partial" {
                    global_reasons
                        .iter()
                        .cloned()
                        .chain(
                            access
                                .incomplete_reasons
                                .iter()
                                .map(|reason| format!("{reason:?}")),
                        )
                        .chain(unavailable_source)
                        .collect()
                } else {
                    Vec::new()
                };
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
                    incomplete_reasons,
                    source_ranges_omitted,
                    alternative_states_omitted: 0,
                    offset: origin.byte_offset,
                    bounds: origin.bounds,
                    row: CodeQueryRustPointerFinding {
                        id,
                        path: path.to_string(),
                        language: "rust",
                        range,
                        relation,
                        source_ranges,
                        source_ranges_omitted: Default::default(),
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
                        reason: None,
                    },
                });
            }
        }
    }
    let retained_source_bytes = consolidate_pointer_findings(&mut rows, source_limits);
    // Revisit only borrowed solver facts. A dropped witness occurrence may
    // duplicate a retained location, so it is not a distinct-location count.
    // Sorting the bounded output in place avoids an additional path/ID set.
    rows.sort_unstable_by(|left, right| left.row.id.cmp(&right.row.id));
    for access in result.accesses() {
        for origin in &access.origins {
            let origin_id = stable_origin_id(&origin.procedure, origin.origin.id.index());
            for witness in pointer_finding_witnesses(access, origin) {
                semantic_budget.record_performed_work(SemanticWork {
                    nested_entries: 1,
                    ..SemanticWork::default()
                });
                let id = stable_finding_id(
                    witness.relation,
                    &access.procedure,
                    access.access.point.index(),
                    &origin_id,
                    witness.identity,
                    witness.invalidation_cause,
                );
                let Ok(index) = rows.binary_search_by(|row| row.row.id.cmp(&id)) else {
                    // The primary access itself may have unavailable source.
                    continue;
                };
                let row = &mut rows[index].row;
                let mapping = witness
                    .source_procedure
                    .semantics()
                    .source_mapping(witness.source_mapping)
                    .expect("validated pointer provenance retains its source mapping");
                record_missing_pointer_source(
                    row,
                    mapping.locator.path().as_str(),
                    mapping.locator.anchor().span().start_byte(),
                    mapping.locator.anchor().span().end_byte(),
                );
            }
        }
    }
    sort_pointer_findings(&mut rows);
    let mut source_work = SemanticWork::default();
    let mut omitted = 0usize;
    let mut alternative_states_omitted = 0usize;
    for row in &rows {
        source_work.nested_entries += row.row.source_ranges.len();
        source_work.owned_text_bytes += row
            .row
            .source_ranges
            .iter()
            .map(|s| s.path.len())
            .sum::<usize>();
        omitted = omitted.saturating_add(row.source_ranges_omitted);
        alternative_states_omitted =
            alternative_states_omitted.saturating_add(row.alternative_states_omitted);
    }
    semantic_budget
        .admit(source_work)
        .expect("source projection fits the remaining semantic grant");
    if omitted > 0 {
        incompleteness = incompleteness.combine(Incompleteness::Operational(
            DerivationExecutionCause::Budget,
        ));
        reasons.push(format!("pointer source evidence retention limits omitted at least {omitted} witness occurrence(s)"));
    }
    if alternative_states_omitted > 0 {
        reasons.push(format!("source evidence from {alternative_states_omitted} alternative pointer state(s) omitted under unchanged finding IDs"));
    }
    reasons.sort_unstable();
    reasons.dedup();
    Ok(RustPointerFindings {
        incompleteness,
        rows,
        complete: reasons.is_empty(),
        reasons,
        retained_source_bytes,
    })
}

enum CollectedPointerSource {
    Range(CodeQuerySourceSpan),
    Unavailable(String),
    Omitted,
}

fn collect_pointer_source(
    remaining: &mut PointerSourceLimits,
    path: &str,
    project: impl FnOnce() -> Result<CodeQuerySourceSpan, String>,
) -> CollectedPointerSource {
    // Check the shared grant before materializing a source path, file or span.
    let minimum_bytes = size_of::<CodeQuerySourceSpan>()
        .saturating_mul(4)
        .saturating_add(path.len());
    if remaining.max_ranges == 0 || minimum_bytes > remaining.max_bytes {
        return CollectedPointerSource::Omitted;
    }
    let projected = project();
    let bytes = match &projected {
        Ok(source) => source_range_bytes(source),
        // Retain both the row reason and its run diagnostic within this grant.
        Err(reason) => minimum_bytes.max(
            reason
                .capacity()
                .saturating_mul(2)
                .saturating_add(size_of::<String>().saturating_mul(8)),
        ),
    };
    if bytes > remaining.max_bytes {
        return CollectedPointerSource::Omitted;
    }
    remaining.max_ranges -= 1;
    remaining.max_bytes -= bytes;
    match projected {
        Ok(source) => CollectedPointerSource::Range(source),
        Err(reason) => CollectedPointerSource::Unavailable(reason),
    }
}

fn source_range_bytes(source: &CodeQuerySourceSpan) -> usize {
    // Cover the serialized terminal and owned vector/path allocations,
    // including Vec's minimum capacity of four entries for a short prefix.
    brokk_bifrost_analysis::analyzer::common::serialized_json_len(source).max(
        size_of::<CodeQuerySourceSpan>()
            .saturating_mul(4)
            .saturating_add(source.path.capacity()),
    )
}

fn bound_source_ranges(row: &mut RustPointerFindingValue, limits: PointerSourceLimits) -> usize {
    row.row.source_ranges.sort_by(|left, right| {
        (&left.path, left.start_byte, left.end_byte, left.range).cmp(&(
            &right.path,
            right.start_byte,
            right.end_byte,
            right.range,
        ))
    });
    row.row.source_ranges.dedup();
    let (retained, bytes, omitted) = super::witness_projection::retain_prefix_by_bytes(
        std::mem::take(&mut row.row.source_ranges),
        limits.max_ranges,
        limits.max_bytes,
        source_range_bytes,
    );
    row.row.source_ranges = retained;
    row.source_ranges_omitted = row.source_ranges_omitted.saturating_add(omitted);
    bytes
}

fn consolidate_pointer_findings(
    rows: &mut Vec<RustPointerFindingValue>,
    limits: PointerSourceLimits,
) -> usize {
    // These fields describe one coherent access alternative. They are not a
    // new public identity: the existing ID still chooses one representative.
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    struct State<'a> {
        path: &'a str,
        range: super::CodeQueryRange,
        relation: &'a str,
        origin_id: &'a str,
        origin_kind: &'a str,
        cause: Option<&'a str>,
        access_kind: &'a str,
        offset: (u8, i128, i128),
        bounds: (u8, Option<u8>),
        byte_extent: Option<&'a str>,
        access_width: Option<&'a str>,
    }
    impl<'a> From<&'a RustPointerFindingValue> for State<'a> {
        fn from(finding: &'a RustPointerFindingValue) -> Self {
            let row = &finding.row;
            let offset = match finding.offset {
                PointerByteOffset::Exact(value) => (0, value, 0),
                PointerByteOffset::Value(value) => (
                    1,
                    i128::try_from(value.index()).expect("semantic value IDs fit i128"),
                    0,
                ),
                PointerByteOffset::Range { minimum, maximum } => (2, minimum, maximum),
                PointerByteOffset::Unknown => (3, 0, 0),
            };
            let bounds = match finding.bounds {
                PointerBounds::InBounds => (0, None),
                PointerBounds::OutOfBounds => (1, None),
                PointerBounds::MayBeOutOfBounds => (2, None),
                PointerBounds::Incomplete(reason) => (3, Some(reason as u8)),
            };
            Self {
                path: &row.path,
                range: row.range,
                relation: row.relation,
                origin_id: &row.origin_id,
                origin_kind: row.origin_kind,
                cause: row.invalidation_cause,
                access_kind: row.access_kind,
                offset,
                bounds,
                byte_extent: row.byte_extent.as_deref(),
                access_width: row.access_width.as_deref(),
            }
        }
    }
    for row in rows.iter_mut() {
        bound_source_ranges(row, limits);
        debug_assert_eq!(row.row.byte_offset, offset_label(row.offset));
        debug_assert_eq!(row.row.bounds, bounds_label(row.bounds));
        if !row.incomplete_reasons.is_empty() {
            row.row.completeness = "partial";
        }
    }
    rows.sort_unstable_by(|left, right| {
        (&left.row.id, State::from(left))
            .cmp(&(&right.row.id, State::from(right)))
            .then_with(|| {
                left.row
                    .source_ranges
                    .iter()
                    .map(|s| (&s.path, s.start_byte, s.end_byte, s.range))
                    .cmp(
                        right
                            .row
                            .source_ranges
                            .iter()
                            .map(|s| (&s.path, s.start_byte, s.end_byte, s.range)),
                    )
            })
    });
    // Source mapping IDs are procedure-local. Distinct witness procedures can
    // share an existing row ID; retain all their evidence without rekeying it.
    rows.dedup_by(|later, earlier| {
        if later.row.id != earlier.row.id || State::from(&*later) != State::from(&*earlier) {
            return false;
        }
        // The row states existence of an invalidation before this access.
        // Keep the strongest known witness; an open alternative cannot erase it.
        // A must witness is always path-proven (see effective_strength).
        debug_assert!(earlier.row.strength != "must" || earlier.row.path_proven);
        debug_assert!(later.row.strength != "must" || later.row.path_proven);
        earlier.row.path_proven |= later.row.path_proven;
        earlier.row.proof = if earlier.row.path_proven {
            "proven"
        } else {
            "unproven"
        };
        if later.row.strength == "must" {
            earlier.row.strength = "must";
        }
        if later.row.completeness == "partial" {
            earlier.row.completeness = "partial";
        }
        earlier
            .incomplete_reasons
            .append(&mut later.incomplete_reasons);
        earlier
            .row
            .source_ranges
            .append(&mut later.row.source_ranges);
        earlier.source_ranges_omitted = earlier
            .source_ranges_omitted
            .saturating_add(later.source_ranges_omitted);
        // Each input was bounded; trim every merge before the next witness.
        bound_source_ranges(earlier, limits);
        true
    });
    // The legacy ID does not distinguish offsets. Keep a complete, coherent
    // actual record rather than manufacturing fields across alternatives.
    // Quality ranks proof first; completeness breaks a quality tie. The state
    // ordering above deterministically breaks remaining ties.
    rows.dedup_by(|later, earlier| {
        if later.row.id != earlier.row.id {
            return false;
        }
        let quality = |row: &RustPointerFindingValue| {
            (
                row.row.path_proven,
                row.row.strength == "must",
                row.row.completeness == "complete",
            )
        };
        if quality(later) > quality(earlier) {
            std::mem::swap(later, earlier);
        }
        // Losing state attributes and source ranges never join the survivor,
        // but their omitted evidence and unavailable-source reasons must stay visible.
        earlier.source_ranges_omitted = earlier
            .source_ranges_omitted
            .saturating_add(later.source_ranges_omitted);
        earlier.alternative_states_omitted = earlier
            .alternative_states_omitted
            .saturating_add(later.alternative_states_omitted)
            .saturating_add(1);
        earlier
            .incomplete_reasons
            .append(&mut later.incomplete_reasons);
        true
    });
    let mut remaining = limits;
    for row in rows.iter_mut() {
        let bytes = bound_source_ranges(row, remaining);
        remaining.max_ranges -= row.row.source_ranges.len();
        remaining.max_bytes -= bytes;
        if row.source_ranges_omitted > 0 {
            row.incomplete_reasons.push(format!(
                "pointer source evidence retention limits omitted at least {} witness occurrence(s)",
                row.source_ranges_omitted,
            ));
        }
        if row.alternative_states_omitted > 0 {
            row.incomplete_reasons.push(format!(
                "source evidence from {} alternative pointer state(s) omitted",
                row.alternative_states_omitted,
            ));
        }
        row.incomplete_reasons.sort();
        row.incomplete_reasons.dedup();
        if !row.incomplete_reasons.is_empty() {
            row.row.completeness = "partial";
            row.row.reason = Some(std::mem::take(&mut row.incomplete_reasons).join(", "));
        }
    }
    sort_pointer_findings(rows);
    limits.max_bytes - remaining.max_bytes
}

fn sort_pointer_findings(rows: &mut [RustPointerFindingValue]) {
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
}

fn record_missing_pointer_source(
    row: &mut CodeQueryRustPointerFinding,
    path: &str,
    start: u32,
    end: u32,
) {
    if !row.source_ranges_omitted.is_empty() {
        return;
    }
    // Consolidation sorts by path, byte offsets, then display range. A source
    // locator's first three keys identify its presence without rendering it.
    let start = usize::try_from(start).expect("validated semantic source offsets fit usize");
    let end = usize::try_from(end).expect("validated semantic source offsets fit usize");
    let retained = row
        .source_ranges
        .binary_search_by(|source| {
            (source.path.as_str(), source.start_byte, source.end_byte).cmp(&(path, start, end))
        })
        .is_ok();
    if !retained {
        row.source_ranges_omitted = brokk_bifrost_core::omission::OmissionCount::lower_bound(1);
    }
}

struct PointerFindingWitness<'a> {
    relation: &'static str,
    invalidation_cause: Option<&'static str>,
    strength: PointerRelationStrength,
    path_proven: bool,
    identity: usize,
    source_procedure: &'a ProcedureHandle,
    source_mapping: SourceMappingId,
}

fn pointer_finding_witnesses<'a>(
    access: &'a PointerProvenanceAccess,
    origin: &'a PointerProvenanceOrigin,
) -> impl Iterator<Item = PointerFindingWitness<'a>> {
    let scope_ends = origin
        .scope_ends_before
        .iter()
        .filter(|_| matches!(&origin.origin.kind, PointerOriginKind::StackPlace { .. }))
        .map(|witness| {
            let path_proven = witness.path_status == ValueFlowMayStatus::Proven;
            PointerFindingWitness {
                relation: "access_after_lifetime_ended",
                invalidation_cause: None,
                strength: effective_strength(origin.strength, None, path_proven),
                path_proven,
                identity: witness.scope_end.source.index(),
                source_procedure: &origin.procedure,
                source_mapping: origin.origin.source,
            }
        });
    let invalidations = origin.invalidations_before.iter().map(|witness| {
        let path_proven = witness.path_status == ValueFlowMayStatus::Proven;
        PointerFindingWitness {
            relation: "access_invalid_pointer",
            invalidation_cause: Some(witness.invalidation.cause.label()),
            strength: effective_strength(
                origin.strength,
                Some(witness.invalidation.strength),
                path_proven,
            ),
            path_proven,
            identity: witness.invalidation.source.index(),
            source_procedure: &witness.procedure,
            source_mapping: witness.invalidation.source,
        }
    });
    let bounds = matches!(
        origin.bounds,
        PointerBounds::OutOfBounds | PointerBounds::MayBeOutOfBounds
    )
    .then_some(PointerFindingWitness {
        relation: "access_invalid_pointer",
        invalidation_cause: None,
        strength: if origin.bounds == PointerBounds::MayBeOutOfBounds {
            PointerRelationStrength::May
        } else {
            origin.strength
        },
        path_proven: true,
        identity: access.access.point.index(),
        source_procedure: &origin.procedure,
        source_mapping: origin.origin.source,
    });
    scope_ends.chain(invalidations).chain(bounds)
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
    brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string(&digest.finalize().into())
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
    brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string(&digest.finalize().into())
}

#[cfg(test)]
mod tests {

    use super::super::CodeQueryRange;
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#12430: semantic-only fixed points invented Provider while real closure failures must remain operational"
    )]
    fn pointer_content_gaps_do_not_hide_provider_cancel_or_budget_failures() {
        use brokk_bifrost_flow::dataflow::SemanticInputStatus;
        use brokk_bifrost_flow::value_flow::{SkipReason, ValueFlowDiscoveryStatus};
        assert_eq!(
            combine_discovery_incompleteness(
                Incompleteness::Content,
                ValueFlowDiscoveryStatus::Content
            ),
            Incompleteness::Content
        );
        let actual_failure = SkipReason::ProviderError {
            detail: "injected procedure snapshot failure".to_owned(),
        };
        assert_eq!(
            combine_discovery_incompleteness(
                skip_incompleteness(&actual_failure),
                ValueFlowDiscoveryStatus::Content
            ),
            Incompleteness::Operational(DerivationExecutionCause::Provider)
        );
        let cancellation = SkipReason::RelationsUnavailable {
            status: SemanticInputStatus::Cancelled,
        };
        assert_eq!(
            combine_discovery_incompleteness(
                skip_incompleteness(&cancellation),
                ValueFlowDiscoveryStatus::Content
            ),
            Incompleteness::Operational(DerivationExecutionCause::Cancelled)
        );
        assert_eq!(
            combine_discovery_incompleteness(
                Incompleteness::Content,
                ValueFlowDiscoveryStatus::Operational(DerivationExecutionCause::Budget)
            ),
            Incompleteness::Operational(DerivationExecutionCause::Budget)
        );
    }

    const SOURCE_LIMITS: PointerSourceLimits = PointerSourceLimits {
        max_ranges: usize::MAX,
        max_bytes: usize::MAX,
    };

    #[test]
    #[hardwon("#12312: 110 pointer reasons made a 30,152-byte diagnostic fail adaptation")]
    fn pointer_provenance_diagnostic_bounds_the_observed_30152_byte_shape() {
        const OBSERVED_BYTES: usize = 30_152;
        let mut reasons = (0..110)
            .map(|index| {
                format!(
                    "access PointerAccess {{ point: ProgramPointId({index}), pointer: ValueId({index}), \
                     kind: Read, width: Exact(8), source: SourceMappingId({index}), \
                     evidence: EvidenceId({index}) }} has incomplete pointer evidence"
                )
            })
            .collect::<Vec<_>>();
        let initial = format!("Rust pointer provenance is incomplete: {reasons:#?}");
        assert!(initial.len() < OBSERVED_BYTES);
        let padding = OBSERVED_BYTES - initial.len();
        let count = reasons.len();
        for (index, reason) in reasons.iter_mut().enumerate() {
            reason.push_str(&"x".repeat(padding / count + usize::from(index < padding % count)));
        }
        assert_eq!(
            format!("Rust pointer provenance is incomplete: {reasons:#?}").len(),
            OBSERVED_BYTES
        );

        let message = incomplete_diagnostic_message(&reasons);
        assert_eq!(
            brokk_bifrost_core::bounded_output::MAX_DIAGNOSTIC_MESSAGE_BYTES,
            4_096
        );
        assert!(message.len() <= 4_096);
        let detail = message
            .strip_prefix("Rust pointer provenance is incomplete; total_items=110, retained_items=")
            .unwrap();
        let (retained, omitted) = detail.rsplit_once(", omitted_items=").unwrap();
        let retained: Vec<String> = serde_json::from_str(retained).unwrap();
        assert!(!retained.is_empty());
        assert!(retained.len() < count);
        assert_eq!(retained, reasons[..retained.len()]);
        assert_eq!(omitted.parse::<usize>().unwrap(), count - retained.len());
    }

    fn pointer_finding() -> RustPointerFindingValue {
        let range = CodeQueryRange {
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 2,
        };
        RustPointerFindingValue {
            file: ProjectFile::new(
                std::env::current_dir().unwrap(),
                PathBuf::from("fixture.rs"),
            ),
            byte_span: 0..1,
            incomplete_reasons: Vec::new(),
            source_ranges_omitted: 0,
            alternative_states_omitted: 0,
            offset: PointerByteOffset::Unknown,
            bounds: PointerBounds::Incomplete(
                crate::analyzer::semantic::PointerIncompleteReason::UnknownAllocationExtent,
            ),
            row: CodeQueryRustPointerFinding {
                id: "same-row".into(),
                path: "fixture.rs".into(),
                language: "rust",
                range,
                source_ranges: vec![CodeQuerySourceSpan {
                    path: "a.rs".into(),
                    range,
                    start_byte: 0,
                    end_byte: 1,
                }],
                source_ranges_omitted: Default::default(),
                relation: "access_invalid_pointer",
                origin_id: "same-origin".into(),
                origin_kind: "allocation",
                invalidation_cause: Some("deallocated"),
                access_kind: "read",
                strength: "may",
                path_proven: false,
                bounds: "incomplete",
                byte_offset: None,
                byte_extent: None,
                access_width: None,
                proof: "unproven",
                completeness: "partial",
                reason: None,
            },
        }
    }

    #[test]
    #[hardwon("#11267: clipped source witnesses lacked a sound distinct-location omission count")]
    fn pointer_source_omissions_count_distinct_missing_locations_conservatively() {
        use brokk_bifrost_core::omission::OmissionCount;
        let mut row = pointer_finding().row;
        let id = row.id.clone();
        let mut second = row.source_ranges[0].clone();
        second.path = "b.rs".into();
        row.source_ranges.push(second);
        for _ in 0..128 {
            record_missing_pointer_source(&mut row, "a.rs", 0, 1);
            record_missing_pointer_source(&mut row, "b.rs", 0, 1);
        }
        assert_eq!(row.source_ranges_omitted, OmissionCount::exact(0));
        record_missing_pointer_source(&mut row, "c.rs", 0, 1);
        record_missing_pointer_source(&mut row, "c.rs", 0, 1);
        record_missing_pointer_source(&mut row, "d.rs", 0, 1);
        assert_eq!(row.source_ranges_omitted, OmissionCount::lower_bound(1));
        assert_eq!(row.id, id);
    }

    #[test]
    #[hardwon(
        "#11267: colliding pointer witnesses retained unbounded source evidence before policy caps"
    )]
    fn pointer_source_evidence_respects_entry_and_byte_grants() {
        let mut inputs = Vec::new();
        for index in 0..128 {
            let mut row = pointer_finding();
            row.row.source_ranges[0].path = format!("witness-{index:03}.rs");
            row.row.completeness = "complete";
            inputs.push(row);
        }
        let first_bytes = source_range_bytes(&inputs[0].row.source_ranges[0].clone());
        for (limits, retained) in [
            (
                PointerSourceLimits {
                    max_ranges: 0,
                    max_bytes: usize::MAX,
                },
                0,
            ),
            (
                PointerSourceLimits {
                    max_ranges: 2,
                    max_bytes: usize::MAX,
                },
                2,
            ),
            (
                PointerSourceLimits {
                    max_ranges: 128,
                    max_bytes: first_bytes - 1,
                },
                0,
            ),
            (
                PointerSourceLimits {
                    max_ranges: 128,
                    max_bytes: first_bytes,
                },
                1,
            ),
        ] {
            for reversed in [false, true] {
                let mut rows = inputs.clone();
                if reversed {
                    rows.reverse();
                }
                let bytes = consolidate_pointer_findings(&mut rows, limits);
                assert!(bytes <= limits.max_bytes);
                assert_eq!(rows.len(), 1);
                let row = &rows[0];
                assert_eq!(row.row.id, "same-row");
                assert_eq!(row.row.source_ranges.len(), retained);
                let allocated = row.row.source_ranges.capacity() * size_of::<CodeQuerySourceSpan>()
                    + row
                        .row
                        .source_ranges
                        .iter()
                        .map(|s| s.path.capacity())
                        .sum::<usize>();
                assert!(allocated <= bytes);
                assert_eq!(row.source_ranges_omitted, 128 - retained);
                assert_eq!(row.row.completeness, "partial");
                assert!(row.row.reason.as_ref().unwrap().contains(&format!(
                    "at least {} witness occurrence(s)",
                    128 - retained
                )));
                for (index, source) in row.row.source_ranges.iter().enumerate() {
                    assert_eq!(source.path, format!("witness-{index:03}.rs"));
                }
            }
        }
        let mut other = inputs[0].clone();
        other.row.id = "z-other-finding".into();
        inputs.push(other);
        consolidate_pointer_findings(
            &mut inputs,
            PointerSourceLimits {
                max_ranges: 2,
                max_bytes: usize::MAX,
            },
        );
        assert_eq!(inputs.len(), 2);
        assert_eq!(
            inputs
                .iter()
                .map(|r| r.row.source_ranges.len())
                .sum::<usize>(),
            2
        );
        assert!(inputs.iter().all(|r| r.row.completeness == "partial"));
        assert_eq!(inputs[1].row.id, "z-other-finding");
        assert_eq!(inputs[1].source_ranges_omitted, 1);
    }

    #[test]
    #[hardwon("#11267: source paths were allocated for every witness before enforcing the grant")]
    fn pointer_source_collection_is_bounded_before_projection() {
        let source = pointer_finding().row.source_ranges.pop().unwrap();
        let bytes = source_range_bytes(&source.clone());
        for (mut remaining, expected) in [
            (
                PointerSourceLimits {
                    max_ranges: 0,
                    max_bytes: usize::MAX,
                },
                0,
            ),
            (
                PointerSourceLimits {
                    max_ranges: 128,
                    max_bytes: 0,
                },
                0,
            ),
            (
                PointerSourceLimits {
                    max_ranges: 2,
                    max_bytes: usize::MAX,
                },
                2,
            ),
            (
                PointerSourceLimits {
                    max_ranges: 128,
                    max_bytes: bytes,
                },
                1,
            ),
        ] {
            let mut projected = 0;
            let mut retained = Vec::new();
            let mut omitted = 0;
            for _ in 0..128 {
                match collect_pointer_source(&mut remaining, &source.path, || {
                    projected += 1;
                    Ok(source.clone())
                }) {
                    CollectedPointerSource::Range(source) => retained.push(source),
                    CollectedPointerSource::Omitted => omitted += 1,
                    CollectedPointerSource::Unavailable(_) => panic!("source is available"),
                }
            }
            assert_eq!(projected, expected);
            assert_eq!(retained.len(), expected);
            assert_eq!(omitted, 128 - expected);
        }
        let mut remaining = PointerSourceLimits {
            max_ranges: 1,
            max_bytes: usize::MAX,
        };
        assert!(matches!(
            collect_pointer_source(&mut remaining, "missing.rs", || Err(
                "unavailable at missing.rs".into()
            )),
            CollectedPointerSource::Unavailable(_)
        ));
        assert!(matches!(
            collect_pointer_source(&mut remaining, "missing.rs", || panic!(
                "exhausted source grant must not project"
            )),
            CollectedPointerSource::Omitted
        ));
    }

    #[test]
    #[hardwon(
        "#11267: selecting an offset alternative hid omitted and unavailable source evidence"
    )]
    fn omitted_pointer_states_keep_their_evidence_incompleteness() {
        let mut selected = pointer_finding();
        selected.offset = PointerByteOffset::Exact(8);
        selected.row.byte_offset = offset_label(selected.offset);
        selected.row.path_proven = true;
        selected.row.proof = "proven";
        selected.row.strength = "must";
        selected.row.completeness = "complete";
        selected.row.source_ranges[0].path = "kept.rs".into();
        let mut missing = pointer_finding();
        missing.offset = PointerByteOffset::Exact(4);
        missing.row.byte_offset = offset_label(missing.offset);
        missing.row.source_ranges.clear();
        missing.source_ranges_omitted = 2;
        missing
            .incomplete_reasons
            .push("source text is unavailable at missing.rs".into());
        let mut other = pointer_finding();
        other.offset = PointerByteOffset::Exact(12);
        other.row.byte_offset = offset_label(other.offset);
        other.row.source_ranges[0].path = "omitted.rs".into();
        for inputs in [
            vec![selected.clone(), missing.clone(), other.clone()],
            vec![other, missing, selected],
        ] {
            let mut rows = inputs;
            consolidate_pointer_findings(&mut rows, SOURCE_LIMITS);
            assert_eq!(rows.len(), 1);
            let actual = &rows[0];
            assert_eq!(actual.row.id, "same-row");
            assert_eq!(actual.offset, PointerByteOffset::Exact(8));
            assert!(actual.row.path_proven);
            assert_eq!(actual.row.strength, "must");
            assert_eq!(
                actual
                    .row
                    .source_ranges
                    .iter()
                    .map(|s| s.path.as_str())
                    .collect::<Vec<_>>(),
                ["kept.rs"]
            );
            assert_eq!(actual.source_ranges_omitted, 2);
            assert_eq!(actual.alternative_states_omitted, 2);
            assert_eq!(actual.row.completeness, "partial");
            let reason = actual.row.reason.as_ref().unwrap();
            assert!(reason.contains("missing.rs"));
            assert!(reason.contains("2 alternative pointer state(s) omitted"));
            assert!(reason.contains("2 witness occurrence(s)"));
        }
    }

    #[test]
    #[hardwon("#11267: colliding witness ordinals lost stronger path evidence")]
    fn colliding_pointer_witnesses_keep_the_strongest_evidence_in_any_order() {
        let row = pointer_finding();
        for (path_proven, strength) in [(false, "may"), (true, "may"), (true, "must")] {
            for reversed in [false, true] {
                let mut second = row.clone();
                second.row.source_ranges[0].path = "b.rs".into();
                second.row.path_proven = path_proven;
                second.row.proof = if path_proven { "proven" } else { "unproven" };
                second.row.strength = strength;
                let mut rows = vec![row.clone(), second];
                if reversed {
                    rows.reverse();
                }
                consolidate_pointer_findings(&mut rows, SOURCE_LIMITS);
                assert_eq!(rows.len(), 1);
                let actual = &rows[0].row;
                assert_eq!(actual.id, "same-row");
                assert_eq!(actual.origin_id, "same-origin");
                assert_eq!(actual.path_proven, path_proven);
                assert_eq!(
                    actual.proof,
                    if path_proven { "proven" } else { "unproven" }
                );
                assert_eq!(actual.strength, strength);
                assert_eq!(
                    actual
                        .source_ranges
                        .iter()
                        .map(|s| s.path.as_str())
                        .collect::<Vec<_>>(),
                    ["a.rs", "b.rs"]
                );
            }
        }
    }

    #[test]
    #[hardwon("#11267: an unavailable source was omitted without marking its row partial")]
    fn unavailable_pointer_source_stays_partial_after_witness_consolidation() {
        let mut missing = pointer_finding();
        missing.row.source_ranges.clear();
        missing.row.completeness = "complete";
        missing
            .incomplete_reasons
            .push("source text is unavailable for pointer provenance at missing.rs".into());
        let mut known = pointer_finding();
        known.row.completeness = "complete";
        for mut rows in [
            vec![missing.clone()],
            vec![missing.clone(), known.clone()],
            vec![known.clone(), missing.clone()],
        ] {
            let mut unrelated = known.clone();
            unrelated.row.id = "unrelated".into();
            rows.push(unrelated);
            consolidate_pointer_findings(&mut rows, SOURCE_LIMITS);
            let missing = rows.iter().find(|r| r.row.id == "same-row").unwrap();
            assert_eq!(missing.row.completeness, "partial");
            assert!(
                missing
                    .row
                    .reason
                    .as_deref()
                    .unwrap()
                    .contains("missing.rs")
            );
            let unrelated = rows.iter().find(|r| r.row.id == "unrelated").unwrap();
            assert_eq!(unrelated.row.completeness, "complete");
            assert_eq!(unrelated.row.reason, None);
        }
    }

    #[test]
    #[hardwon("#11267: witness consolidation fabricated proof and strength across pointer offsets")]
    fn offset_alternatives_keep_a_coherent_actual_representative() {
        use crate::analyzer::semantic::PointerIncompleteReason;
        for (weak_offset, strong_offset, weak_bounds, strong_bounds) in [
            (
                PointerByteOffset::Exact(4),
                PointerByteOffset::Exact(8),
                PointerBounds::MayBeOutOfBounds,
                PointerBounds::OutOfBounds,
            ),
            (
                PointerByteOffset::Value(ValueId::try_from_index(0).unwrap()),
                PointerByteOffset::Value(ValueId::try_from_index(1).unwrap()),
                PointerBounds::Incomplete(PointerIncompleteReason::UnknownLayout),
                PointerBounds::Incomplete(PointerIncompleteReason::UnknownLayout),
            ),
            (
                PointerByteOffset::Unknown,
                PointerByteOffset::Unknown,
                PointerBounds::Incomplete(PointerIncompleteReason::MissingType),
                PointerBounds::Incomplete(PointerIncompleteReason::UnknownLayout),
            ),
        ] {
            let mut weak = pointer_finding();
            weak.offset = weak_offset;
            weak.bounds = weak_bounds;
            weak.row.byte_offset = offset_label(weak_offset);
            weak.row.bounds = bounds_label(weak_bounds);
            let mut strong = pointer_finding();
            strong.offset = strong_offset;
            strong.bounds = strong_bounds;
            strong.row.byte_offset = offset_label(strong_offset);
            strong.row.bounds = bounds_label(strong_bounds);
            strong.row.path_proven = true;
            strong.row.proof = "proven";
            strong.row.strength = "must";
            strong.row.source_ranges[0].path = "b.rs".into();
            let mut other_weak = weak.clone();
            other_weak.row.path_proven = true;
            other_weak.row.proof = "proven";
            other_weak.row.source_ranges[0].path = "c.rs".into();
            let mut same_offset = strong.clone();
            same_offset.row.path_proven = false;
            same_offset.row.proof = "unproven";
            same_offset.row.strength = "may";
            same_offset.row.source_ranges[0].path = "d.rs".into();
            let inputs = vec![weak, strong, other_weak, same_offset];
            for rotation in 0..inputs.len() {
                for reversed in [false, true] {
                    let mut rows = inputs.clone();
                    rows.rotate_left(rotation);
                    if reversed {
                        rows.reverse();
                    }
                    consolidate_pointer_findings(&mut rows, SOURCE_LIMITS);
                    assert_eq!(rows.len(), 1);
                    let actual = &rows[0];
                    let row = &actual.row;
                    assert_eq!(row.id, "same-row");
                    assert_eq!(row.origin_id, "same-origin");
                    assert_eq!(actual.offset, strong_offset);
                    assert_eq!(actual.bounds, strong_bounds);
                    assert_eq!(row.byte_offset, offset_label(strong_offset));
                    assert_eq!(row.bounds, bounds_label(strong_bounds));
                    assert_eq!(row.strength, "must");
                    assert!(row.path_proven);
                    assert_eq!(row.proof, "proven");
                    assert_eq!(
                        row.source_ranges
                            .iter()
                            .map(|s| s.path.as_str())
                            .collect::<Vec<_>>(),
                        ["b.rs", "d.rs"]
                    );
                }
            }
        }
    }
}
