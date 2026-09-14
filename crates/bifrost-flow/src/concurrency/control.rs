//! Callable-input control summaries, computed before caller effects.

use super::*;
use crate::analyzer::semantic::{
    SemanticCallSite, SemanticCapability, SemanticValueKind, ValueFlowKind,
};
use crate::flow_state::ProcedureContinuationProjection;
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct CallableContext {
    procedure: ProcedureHandle,
    inputs: Vec<(ValueId, ProcedureHandle)>,
}

// These are control dependencies, not runtime invocations or heap aliases.
struct ControlNode {
    context: CallableContext,
    projection: Rc<ProcedureContinuationProjection>,
    calls: Vec<(CallSiteHandle, Vec<CallableContext>)>,
}

fn charge(request: &mut SolveRequest<'_, '_>, work: usize) -> Option<()> {
    match charge_concurrency_work(request, work) {
        Ok(()) => Some(()),
        Err(reason) => {
            request.control_reasons.push(reason);
            None
        }
    }
}

/// Interpret an exact lexical read, never a source-name or heap-alias guess.
fn callable_at(
    procedure: &ProcedureHandle,
    inputs: &HashMap<ValueId, ProcedureHandle>,
    mut value: ValueId,
    call: &SemanticCallSite,
    request: &mut SolveRequest<'_, '_>,
) -> Option<ProcedureHandle> {
    let semantics = procedure.semantics();
    if !reference_control_is_complete(procedure)
        || semantics.gaps().iter().any(|gap| {
            gap.capability == SemanticCapability::Captures
                || (gap.capability == SemanticCapability::Assignments
                    && gap.impacts.contains(SemanticGapImpact::HeapWrite))
        })
    {
        return None;
    }
    let mut use_point = call.point;
    let mut use_event = semantics.point(call.point).expect("owned point").events.iter()
        .position(|event| matches!(event.effect, SemanticEffect::Invoke { call_site } if call_site == call.id))
        .expect("owned invocation event");
    let mut visited = HashSet::default();
    loop {
        charge(
            request,
            semantics.values().len()
                + semantics
                    .points()
                    .iter()
                    .map(|point| point.events.len())
                    .sum::<usize>()
                + 1,
        )?;
        if !visited.insert(value) {
            return None;
        }
        let location = semantics.binding_memory_location(value);
        if !crate::flow_state::address_alias_values(semantics, &HashSet::from_iter([value]))
            .is_empty()
        {
            return None;
        }
        match reference_captures_are_read_only(procedure, value, request) {
            Ok(true) => {}
            Ok(false) => return None,
            Err(reason) => {
                request.control_reasons.push(reason);
                return None;
            }
        }
        let mut flow = None;
        let mut origin = None;
        for point in semantics.points() {
            for (position, event) in point.events.iter().enumerate() {
                match &event.effect {
                    SemanticEffect::Assignment { target, .. } if *target == value => return None,
                    SemanticEffect::MemoryStore {
                        location: target, ..
                    } if Some(*target) == location => return None,
                    SemanticEffect::MemoryLoad { result, .. } if *result == value => return None,
                    SemanticEffect::ValueFlow {
                        source,
                        target,
                        kind,
                    } if *target == value => {
                        if flow.is_some()
                            || !matches!(
                                kind,
                                ValueFlowKind::Local
                                    | ValueFlowKind::Parameter
                                    | ValueFlowKind::Receiver
                            )
                            || !reference_evidence_is_complete(semantics, event.evidence)
                        {
                            return None;
                        }
                        flow = Some((*source, point.id, position));
                    }
                    SemanticEffect::CallableReference { result, callable }
                    | SemanticEffect::CallableCreation { result, callable }
                        if *result == value =>
                    {
                        if let CallableTargetResolution::Proven(CallableTarget::Local(target)) =
                            callable.targets
                        {
                            if !reference_evidence_is_complete(semantics, event.evidence) {
                                return None;
                            }
                            let target = procedure
                                .artifact()
                                .procedure_handle(target)
                                .expect("validated callable");
                            if origin
                                .as_ref()
                                .is_some_and(|(previous, _, _)| previous != &target)
                            {
                                return None;
                            }
                            origin = Some((target, point.id, position));
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some(target) = inputs.get(&value) {
            return Some(target.clone());
        }
        let (next, definition, position) = if let Some((source, point, position)) = flow {
            (Some(source), point, position)
        } else if let Some((_, point, position)) = &origin {
            (None, *point, *position)
        } else {
            return None;
        };
        let precedes = if definition == use_point {
            position < use_event
        } else {
            match projected_point_dominates(procedure, definition, use_point, request) {
                Ok(precedes) => precedes,
                Err(reason) => {
                    request.control_reasons.push(reason);
                    return None;
                }
            }
        };
        if !precedes {
            return None;
        }
        if let Some(next) = next {
            value = next;
            use_point = definition;
            use_event = position;
        } else {
            return origin.map(|(target, _, _)| target);
        }
    }
}

fn callee_context(
    caller: &ProcedureHandle,
    call: &SemanticCallSite,
    inputs: &HashMap<ValueId, ProcedureHandle>,
    target: &ProcedureHandle,
    request: &mut SolveRequest<'_, '_>,
) -> CallableContext {
    let mut bindings = Vec::new();
    if charge(request, target.semantics().values().len() + 1).is_none() {
        return CallableContext {
            procedure: target.clone(),
            inputs: bindings,
        };
    }
    for formal in target.semantics().values() {
        let SemanticValueKind::Parameter { ordinal, .. } = formal.kind else {
            continue;
        };
        let Some(actual) = call.arguments.get(ordinal as usize) else {
            continue;
        };
        if let Some(callable) = callable_at(caller, inputs, actual.value, call, request) {
            bindings.push((formal.id, callable));
        }
    }
    bindings.sort_unstable_by_key(|(value, _)| *value);
    CallableContext {
        procedure: target.clone(),
        inputs: bindings,
    }
}

pub(super) fn target_projection(
    provider: &impl ConcurrencyProvider,
    caller: &ProcedureHandle,
    call: &SemanticCallSite,
    inputs: &HashMap<ValueId, ProcedureHandle>,
    target: &ProcedureHandle,
    request: &mut SolveRequest<'_, '_>,
) -> Result<Option<Rc<ProcedureContinuationProjection>>, SemanticProviderError> {
    let root = callee_context(caller, call, inputs, target, request);
    if root.inputs.is_empty() {
        return Ok(request.projection(target));
    }
    if let Some(cached) = request.callable_projections.get(&root) {
        return Ok(Some(cached.clone()));
    }
    let mut pending = vec![root.clone()];
    let mut seen = HashSet::default();
    let mut nodes = Vec::new();
    let mut projections = HashMap::default();
    while let Some(context) = pending.pop() {
        if !seen.insert(context.clone()) {
            continue;
        }
        if charge(
            request,
            context.inputs.len() + context.procedure.semantics().call_sites().len() + 1,
        )
        .is_none()
        {
            return Ok(None);
        }
        let Some(base) = request.projection(&context.procedure) else {
            return Ok(None);
        };
        if let Some(cached) = request.callable_projections.get(&context) {
            projections.insert(context, cached.clone());
            continue;
        }
        projections.insert(context.clone(), base.clone());
        if context.inputs.is_empty() || base.normal_return_is_absent() {
            continue;
        }
        let inputs = context.inputs.iter().cloned().collect::<HashMap<_, _>>();
        let mut calls = Vec::new();
        for call in context
            .procedure
            .semantics()
            .call_sites()
            .iter()
            .filter(|call| {
                call.invocation_mode == CallInvocationMode::Ordinary
                    && call.execution_timing == ExecutionTiming::SameEvaluation
            })
        {
            let handle = context
                .procedure
                .call_site_handle(call.id)
                .expect("owned call");
            let answer = if let Some(target) =
                callable_at(&context.procedure, &inputs, call.callee, call, request)
            {
                ConcurrencyAnswer::Proven(vec![target])
            } else if let Some(targets) =
                provider.complete_call_targets(&context.procedure, call.id)
            {
                ConcurrencyAnswer::Proven(targets.to_vec())
            } else {
                provider.resolve_call(&handle, request)?
            };
            let ConcurrencyAnswer::Proven(targets) = answer else {
                continue;
            };
            let targets = targets
                .iter()
                .map(|target| callee_context(&context.procedure, call, &inputs, target, request))
                .collect::<Vec<_>>();
            pending.extend(targets.iter().cloned());
            calls.push((handle, targets));
        }
        nodes.push(ControlNode {
            context,
            projection: base,
            calls,
        });
    }
    // Monotone positive certificates: an unresolved cycle cannot acquire proof
    // merely because it was discovered. Source-wide cycles use source proofs.
    loop {
        let mut changed = false;
        for node in &mut nodes {
            if node.projection.normal_return_is_absent() {
                continue;
            }
            if charge(
                request,
                node.calls.len()
                    + node.context.procedure.semantics().control_edges().len()
                    + node.projection.reasons().len()
                    + 1,
            )
            .is_none()
            {
                return Ok(None);
            }
            let mut projection = (*node.projection).clone();
            for (call, targets) in &node.calls {
                let proofs = targets
                    .iter()
                    .map(|target| {
                        projections
                            .get(target)
                            .expect("discovered control context")
                            .as_ref()
                    })
                    .collect::<Vec<_>>();
                match projection.with_nonreturning_source_call(call, &proofs, request) {
                    Ok(Some(specialized)) => projection = specialized,
                    Ok(None) => {}
                    Err(reason) => {
                        request
                            .control_reasons
                            .push(ConcurrencyOpenReason::IncompleteControlFlow(
                                format!("{reason:?}").into(),
                            ));
                        return Ok(None);
                    }
                }
            }
            let exact_calls = node
                .calls
                .iter()
                .map(|(call, _)| call.clone())
                .collect::<Vec<_>>();
            match projection.certify_normal_return_absence(&exact_calls, request) {
                Ok(certified) => changed |= certified,
                Err(reason) => {
                    request
                        .control_reasons
                        .push(ConcurrencyOpenReason::IncompleteControlFlow(
                            format!("{reason:?}").into(),
                        ));
                    return Ok(None);
                }
            }
            node.projection = Rc::new(projection);
            projections.insert(node.context.clone(), node.projection.clone());
        }
        if !changed {
            break;
        }
    }
    let result = projections.get(&root).cloned();
    request.callable_projections.extend(projections);
    Ok(result)
}
