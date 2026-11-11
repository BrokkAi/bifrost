//! Key-precise container cells for closed local containers (#10989).
//!
//! A container created in this procedure by an argument-free constructor,
//! whose every other use is the receiver of a call with a complete pack
//! collection-flow contract, is fully described by those contracts. Each Keyed
//! contract transfer that names one entry by a constant key then becomes a
//! store into, or a load from, that key's `Property` cell on the container's
//! allocation, published at the call's normal continuation. The plan then
//! drops the call's summary transfers into and out of the receiver there,
//! which would collapse every entry back onto the container object.
//!
//! The proof fails closed: any other reference to the container, a call
//! without a contract, a contract with a callback, a used result the contract
//! does not write, a transfer this binder does not understand, or a key that
//! is not a constant leaves every call on that container to its summary.
//!
//! This is the Milestone 0 prototype of the shared closed-container proof:
//! it handles Keyed entry values with constant string keys only.

use super::*;

use brokk_bifrost_core::hash::HashSet;

use crate::analyzer::semantic::ir::AllocationKind;
use crate::analyzer::semantic::ir::CallContinuationKind;
use crate::analyzer::semantic::{CollectionCellBinding, CollectionCellTransfer};
use crate::analyzer::semantic_model::CollectionFlowContract;
use crate::analyzer::semantic_model::csmi::{
    CsmiInputBoundaryRoot, CsmiOutputBoundaryRoot, CsmiProjection,
};

/// Bind every closed local container of `procedure` whose calls all carry a
/// complete Keyed contract. Calls on other containers are left alone.
pub(super) fn closed_container_cells(
    host: &dyn RelationProjectionHost,
    procedure: &ProcedureHandle,
    limits: crate::analyzer::semantic::OracleLimits,
    request: &mut SemanticRequest<'_>,
) -> Result<Vec<CollectionCellBinding>, SemanticProviderError> {
    // The proof exists to bind complete collection-flow contracts. Without
    // one there is nothing to bind, and resolving every allocation's calls
    // merely to discover that would charge work that cannot change the answer
    // (#11092).
    if !host.may_have_complete_collection_flow_contracts() {
        return Ok(Vec::new());
    }
    let semantics = procedure.semantics();
    let language = procedure.artifact().key().language().language();
    let Some(knowledge) = crate::analyzer::semantic::languages::language_knowledge(language) else {
        return Ok(Vec::new());
    };
    let mut bindings = Vec::new();
    'allocations: for allocation in semantics.allocations() {
        if allocation.kind != AllocationKind::Object {
            continue;
        }
        // The allocation's own constructor fixes the receiver's exact runtime
        // class, which is what lets one member be selected below. Only an
        // argument-free constructor is admitted: any argument could seed
        // entries the cells would not hold.
        let constructors = semantics
            .call_sites()
            .iter()
            .filter(|call| call.receiver.is_none() && call.result == Some(allocation.result))
            .collect::<Vec<_>>();
        let [constructor] = constructors.as_slice() else {
            continue;
        };
        if !constructor.arguments.is_empty() {
            continue;
        }
        let aliases = local_aliases(semantics, allocation.result);
        let receiver_calls = semantics
            .call_sites()
            .iter()
            .filter(|call| {
                call.receiver
                    .is_some_and(|receiver| aliases.contains(&receiver))
            })
            .collect::<Vec<_>>();
        if escapes(semantics, &aliases, constructor.id, &receiver_calls) {
            continue;
        }
        let constructor = procedure
            .call_site_handle(constructor.id)
            .expect("a projected call exists");
        let Some(class) = host.constructed_class(&constructor, request)? else {
            continue;
        };
        let mut calls = Vec::new();
        for call in receiver_calls {
            let handle = procedure
                .call_site_handle(call.id)
                .expect("a projected call exists");
            let Some(contract) = host.collection_flow_contract(&handle, &class, request)? else {
                continue 'allocations;
            };
            let Some(transfers) =
                bind_keyed_transfers(procedure, call, allocation.id, &contract, knowledge, limits)?
            else {
                continue 'allocations;
            };
            calls.push(CollectionCellBinding::new(handle, transfers));
        }
        bindings.extend(calls);
    }
    Ok(bindings)
}

/// The values that hold the allocation: its result and every value an
/// ordinary local copy or a receiver write-back derives from one of them.
fn local_aliases(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    root: ValueId,
) -> HashSet<ValueId> {
    let mut aliases = HashSet::from_iter([root]);
    loop {
        let before = aliases.len();
        for point in semantics.points() {
            for event in &point.events {
                if let Some((source, target)) = alias_flow(&event.effect)
                    && aliases.contains(&source)
                {
                    aliases.insert(target);
                }
            }
        }
        if aliases.len() == before {
            return aliases;
        }
    }
}

/// A flow that copies a reference without creating a new object.
fn alias_flow(effect: &SemanticEffect) -> Option<(ValueId, ValueId)> {
    match effect {
        SemanticEffect::Assignment { target, value } => Some((*value, *target)),
        SemanticEffect::ValueFlow {
            kind: ValueFlowKind::Local | ValueFlowKind::LanguageDefined,
            source,
            target,
        } => Some((*source, *target)),
        _ => None,
    }
}

/// Whether any reference to the aliases is something other than a local copy
/// among themselves, the allocation's constructor call, the receiver of a call
/// on them, or the bound-method selection that produces such a call's callee.
///
/// This is an allow-list: every other event that names an alias, as
/// `heap::effect_names_any` sees it, is an escape. That predicate matches
/// every effect kind exhaustively, so a new kind cannot be missed here.
fn escapes(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    aliases: &HashSet<ValueId>,
    constructor: crate::analyzer::semantic::CallSiteId,
    receiver_calls: &[&crate::analyzer::semantic::SemanticCallSite],
) -> bool {
    // A receiver call may name the aliases only as its receiver.
    if receiver_calls.iter().any(|call| {
        aliases.contains(&call.callee)
            || call
                .arguments
                .iter()
                .any(|argument| aliases.contains(&argument.value))
    }) {
        return true;
    }
    // Java selects `map.put` as a bound method of the map, producing the
    // call's callee. That callee must reach nothing but its own call, or the
    // bound method (and the map with it) is published like `map::get`.
    let callees = receiver_calls
        .iter()
        .map(|call| call.callee)
        .collect::<HashSet<_>>();
    let allowed_call = |call_site: crate::analyzer::semantic::CallSiteId| {
        call_site == constructor || receiver_calls.iter().any(|call| call.id == call_site)
    };
    semantics.points().iter().any(|point| {
        point.events.iter().any(|event| match &event.effect {
            effect if alias_flow(effect).is_some() => {
                // The closure put every copy target from an alias into the
                // set, so a copy into an alias from outside it means the
                // local may hold another object.
                let (source, target) = alias_flow(effect).expect("matched an alias flow");
                (aliases.contains(&target) && !aliases.contains(&source))
                    || callees.contains(&source)
                    || callees.contains(&target)
            }
            SemanticEffect::CallableReference { result, callable }
                if callees.contains(result)
                    && callable
                        .bound_receiver
                        .is_some_and(|receiver| aliases.contains(&receiver)) =>
            {
                false
            }
            SemanticEffect::Invoke { call_site }
            | SemanticEffect::CallContinuation { call_site, .. }
                if allowed_call(*call_site) =>
            {
                false
            }
            effect => {
                super::super::heap::effect_names_any(semantics, effect, aliases)
                    || super::super::heap::effect_names_any(semantics, effect, &callees)
            }
        })
    })
}

/// Whether anything other than `call`'s own events reads `value`.
fn value_is_used(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    call: crate::analyzer::semantic::CallSiteId,
    value: ValueId,
) -> bool {
    let names = HashSet::from_iter([value]);
    semantics.points().iter().any(|point| {
        point.events.iter().any(|event| match &event.effect {
            SemanticEffect::Invoke { call_site }
            | SemanticEffect::CallContinuation { call_site, .. }
                if *call_site == call =>
            {
                false
            }
            effect => super::super::heap::effect_names_any(semantics, effect, &names),
        })
    })
}

/// The cell stores and loads one call's Keyed contract describes, or `None`
/// when any transfer names something other than one constant key's value.
fn bind_keyed_transfers(
    procedure: &ProcedureHandle,
    call: &crate::analyzer::semantic::SemanticCallSite,
    allocation: crate::analyzer::semantic::AllocationId,
    contract: &CollectionFlowContract,
    knowledge: &dyn brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge,
    limits: crate::analyzer::semantic::OracleLimits,
) -> Result<Option<Vec<CollectionCellTransfer>>, SemanticProviderError> {
    // The plan drops the summary's receiver transfers for a bound call, so
    // the contract must describe everything the call does: no callback, and
    // a result that is either unused or written by the contract.
    if !contract.payload.invocations.is_empty() || !call.normal_results.is_empty() {
        return Ok(None);
    }
    let writes_result = contract
        .payload
        .transfers
        .iter()
        .any(|transfer| matches!(transfer.destination.root, CsmiOutputBoundaryRoot::Result(_)));
    if !writes_result
        && call
            .result
            .is_some_and(|result| value_is_used(procedure.semantics(), call.id, result))
    {
        return Ok(None);
    }
    let Some(normal) = call.normal_continuation.target() else {
        return Ok(None);
    };
    let point = procedure
        .point_handle(normal)
        .expect("a normal continuation exists");
    let event_index = procedure
        .semantics()
        .point(normal)
        .expect("a normal continuation exists")
        .events
        .iter()
        .position(|event| {
            matches!(event.effect, SemanticEffect::CallContinuation {
                call_site,
                kind: CallContinuationKind::Normal,
            } if call_site == call.id)
        });
    let Some(event_index) = event_index else {
        return Ok(None);
    };
    let event_index = u32::try_from(event_index).expect("an event index fits u32");
    let cell = |key_position: u32| -> Result<Option<ValueFlowEndpoint>, SemanticProviderError> {
        let Some(argument) = call.arguments.get(key_position as usize) else {
            return Ok(None);
        };
        let Some(key) = constant_string(procedure.semantics(), argument.value, knowledge) else {
            return Ok(None);
        };
        let (location, summary) = materialize_abstract_location(
            procedure,
            AccessPathDraft {
                original_cell: None,
                root: AccessPathRootDraft::Allocation(allocation),
                selectors: vec![AccessSelectorDraft::Property(key)],
                tail: AccessPathTail::Exact,
                opaque_prefix: false,
            },
            limits,
        )?;
        assert!(!summary, "a one-selector allocation path is exact");
        Ok(Some(ValueFlowEndpoint::Location(Box::new(location))))
    };
    let mut transfers = Vec::new();
    for transfer in &contract.payload.transfers {
        let (source, target) = match (
            &transfer.source.root,
            transfer.source.projection.as_ref(),
            &transfer.destination.root,
            transfer.destination.projection.as_ref(),
        ) {
            // value -> receiver.entry{key: parameter n}.entry-value
            (
                CsmiInputBoundaryRoot::Parameter(parameter),
                None,
                CsmiOutputBoundaryRoot::Receiver(_),
                Some(projection),
            ) => {
                let Some(key) = entry_value_key(projection) else {
                    return Ok(None);
                };
                let Some(value) = call.arguments.get(parameter.position as usize) else {
                    return Ok(None);
                };
                let Some(cell) = cell(key)? else {
                    return Ok(None);
                };
                (
                    ValueFlowEndpoint::for_value(value_handle(procedure, value.value)?),
                    cell,
                )
            }
            // receiver.entry{key: parameter n}.entry-value -> result
            (
                CsmiInputBoundaryRoot::Receiver(_),
                Some(projection),
                CsmiOutputBoundaryRoot::Result(result),
                None,
            ) if result.position == 0 => {
                let Some(key) = entry_value_key(projection) else {
                    return Ok(None);
                };
                let Some(value) = call.result else {
                    return Ok(None);
                };
                let Some(cell) = cell(key)? else {
                    return Ok(None);
                };
                (
                    cell,
                    ValueFlowEndpoint::for_value(value_handle(procedure, value)?),
                )
            }
            _ => return Ok(None),
        };
        transfers.push(CollectionCellTransfer {
            point: point.clone(),
            event_index,
            source,
            target,
        });
    }
    Ok(Some(transfers))
}

/// The parameter position of `entry{key: parameter n} . entry-value`.
fn entry_value_key(projection: &CsmiProjection) -> Option<u32> {
    let [entry, component] = projection.steps.as_slice() else {
        return None;
    };
    if entry.kind != "entry" || component.kind != "entry-value" {
        return None;
    }
    let key = entry.key_selector()?;
    if key.get("kind")?.as_str()? != "parameter" {
        return None;
    }
    u32::try_from(key.get("position")?.as_u64()?).ok()
}

/// The decoded value of a compile-time string constant.
fn constant_string(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    value: ValueId,
    knowledge: &dyn brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge,
) -> Option<String> {
    match &semantics.value(value)?.kind {
        SemanticValueKind::ConstantString(payload) => {
            knowledge.semantic_string_constant_value(payload)
        }
        _ => None,
    }
}
