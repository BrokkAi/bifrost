//! Source applicability only. Shared access/prefix cursors own all waits.
use super::*;
use crate::analyzer::store::python_member_rows::{
    DIRECT_MEMBER_WRITES_SQL, LATE_OPERATIONS_SQL, OWNER_OPERATIONS_SQL,
};
use rusqlite::ToSql;

pub(in crate::analyzer::store::resolution_operation) struct OperationRow {
    mount: u32,
    site: u32,
    form: u8,
    callee: Option<SemanticId>,
    receiver: Option<SemanticId>,
    owners: std::rc::Rc<[SemanticId]>,
}
impl OperationRow {
    // Receiver disjointness is enough for universe exclusion. Demanding the
    // builtin setter while proving that same builtin would create a cycle.
    // Unresolved candidates stay open; member rows also prove API authority.
    pub fn universe_prerequisites(&self) -> impl Iterator<Item = SemanticId> {
        self.receiver.into_iter()
    }
}

fn fixed_owner(ready: &ReadySelectedResolution<'_, '_>, owner: SemanticId) -> bool {
    if owner.shared_name_id().is_none() {
        return false;
    }
    brokk_bifrost_python::intrinsics::BUILTINS
        .iter()
        .any(|entry| {
            brokk_bifrost_python::intrinsics::has_fixed_value_class_surface(entry.qualified_name)
                && builtin(ready, entry.name) == Some(owner)
        })
}

/// All rows die with the member/root request. No solved-owner index is built.
pub(in crate::analyzer::store::resolution_operation) fn source_rows(
    rules: &super::super::python_demand::PythonRules<'_, '_, '_>,
    reference: SemanticId,
    spelling: &str,
    owners: &[SemanticId],
    queries: &[&str],
) -> Result<Read<Vec<OperationRow>>> {
    super::super::super::resolution::with_resolution_read_progress_handler(
        rules.ready.inventory.connection(),
        rules.cancellation,
        |connection| {
            // Every candidate in this read has the same selected owners.
            // Share that query-local snapshot instead of multiplying its heap.
            let owners = std::rc::Rc::<[SemanticId]>::from(owners);
            let mut operations = Vec::new();
            for sql in queries {
                let mut statement = connection.prepare_cached(sql)?;
                let format = crate::analyzer::store::python_binding_rows::NATIVE_SOURCE_FORMAT;
                let callable_result=crate::analyzer::store::resolution_prepare::resolution_rows::code(
                    brokk_bifrost_core::analyzer::resolution_facts::ALL_BINDING_PROJECTION_KINDS,
                    brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind::TargetCallableResultType);
                let arguments: [&dyn ToSql; 4] =
                    [&format, &spelling, &rules.summary, &callable_result];
                let count = statement.parameter_count();
                assert!(
                    count <= arguments.len(),
                    "operation reader parameters match SQL"
                );
                for row in statement.query_map(&arguments[..count], |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, u8>(2)?,
                        row.get::<_, Option<u32>>(3)?,
                        row.get::<_, Option<u32>>(4)?,
                    ))
                })? {
                    if !rules.session.scope_step() || rules.cancellation.is_cancelled() {
                        return Ok(Read::Cancelled(if rules.cancellation.is_cancelled() {
                            super::super::cancelled_completion()
                        } else {
                            ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::TimeBudgetExceeded(reference),
                            ])
                        }));
                    }
                    let (mount, site, form, callee, receiver) = row?;
                    operations.push(OperationRow {
                        mount,
                        site,
                        form,
                        callee: callee.map(|key| SemanticId::local(mount, key)),
                        receiver: receiver.map(|key| SemanticId::local(mount, key)),
                        owners: std::rc::Rc::clone(&owners),
                    });
                }
            }
            rules.observations.borrow_mut().push(format!(
                "dynamic SQL name={spelling:?} statements={} rows={} owners={owners:?}",
                queries.len(),
                operations.len()
            ));
            Ok(Read::ready(operations))
        },
    )
}

pub(super) fn owner_rows(
    half: &PythonMemberContext<'_, '_, '_>,
    spelling: &str,
    owner: SemanticId,
) -> Result<Read<Vec<OperationRow>>> {
    if fixed_owner(half.rules.ready, owner) {
        return Ok(Read::ready(Vec::new()));
    }
    Ok(
        match source_rows(
            half.rules,
            half.reference,
            spelling,
            &[owner],
            &[OWNER_OPERATIONS_SQL, DIRECT_MEMBER_WRITES_SQL],
        )? {
            Read::Ready {
                mut value,
                completion,
            } => {
                value.retain(|row| row.receiver.is_some());
                Read::Ready { value, completion }
            }
            Read::Cancelled(completion) => Read::Cancelled(completion),
            Read::Unavailable { reason, completion } => Read::Unavailable { reason, completion },
        },
    )
}

pub(in crate::analyzer::store::resolution_operation) fn universe_rows(
    rules: &super::super::python_demand::PythonRules<'_, '_, '_>,
    reference: SemanticId,
    spelling: &str,
) -> Result<Read<Vec<OperationRow>>> {
    source_rows(
        rules,
        reference,
        spelling,
        &[],
        &[LATE_OPERATIONS_SQL, DIRECT_MEMBER_WRITES_SQL],
    )
}

pub(super) fn late_inventory(
    half: &PythonMemberContext<'_, '_, '_>,
    context: &MemberAccessContext<'_>,
    owners: &[SemanticId],
    name: SemanticId,
) -> Result<Read<Vec<PythonMemberRow>>> {
    let owners = owners
        .iter()
        .copied()
        .filter(|owner| !fixed_owner(half.rules.ready, *owner))
        .collect::<Vec<_>>();
    if owners.is_empty() {
        return Ok(Read::ready(Vec::new()));
    }
    let Some(identity) = name
        .shared_name_id()
        .and_then(|id| half.rules.ready.shared_names().to_persisted(id))
    else {
        return Ok(Read::Ready {
            value: Vec::new(),
            completion: ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(context.reference),
            ]),
        });
    };
    let spelling: String = half.rules.ready.inventory.connection().query_row(
        "SELECT spelling FROM resolution_identities WHERE id=?1",
        [identity.get()],
        |row| row.get(0),
    )?;
    Ok(
        match source_rows(
            half.rules,
            context.reference,
            &spelling,
            &owners,
            &[LATE_OPERATIONS_SQL, DIRECT_MEMBER_WRITES_SQL],
        )? {
            Read::Ready { value, completion } => Read::Ready {
                value: value.into_iter().map(PythonMemberRow::Operation).collect(),
                completion,
            },
            Read::Cancelled(completion) => Read::Cancelled(completion),
            Read::Unavailable { reason, completion } => Read::Unavailable { reason, completion },
        },
    )
}

pub(in crate::analyzer::store::resolution_operation) enum OperationProof {
    Reference(DemandReferenceKey),
    NoEffect,
    Instance(ResolutionCompletion),
    Possible {
        class_object: bool,
        completion: ResolutionCompletion,
    },
}

/// A selected declaration or a complete TypeObject frontier proves a class
/// object. Runtime(C) never proves a write to C's class dictionary.
pub(in crate::analyzer::store::resolution_operation) fn prove(
    rules: &super::super::python_demand::PythonRules<'_, '_, '_>,
    row: &OperationRow,
    answers: &[(DemandReferenceKey, &FactResolutionAnswer)],
) -> Result<OperationProof> {
    let answer = |reference| {
        answers
            .iter()
            .find(|(key, _)| key.reference == reference)
            .map(|(_, answer)| *answer)
    };
    let mut completion = ResolutionCompletion::Complete;
    let mut class_object = false;
    if let Some(receiver) = row.receiver {
        let Some(selected) = answer(receiver) else {
            return Ok(OperationProof::Reference(DemandReferenceKey::caller(
                receiver,
            )));
        };
        completion = completion.combine(selected.completion());
        let mut values = Vec::new();
        let mut complete = true;
        for projection in selected
            .projections()
            .iter()
            .filter(|projection| projection.reference() == receiver)
        {
            for frontier in selected
                .projected_frontiers()
                .iter()
                .filter(|frontier| frontier.slot() == projection.output_slot())
            {
                complete &= frontier.completion() == &ResolutionCompletion::Complete;
                values.extend(frontier.possible_values().iter().copied());
            }
        }
        rules.observations.borrow_mut().push(format!(
            "dynamic receiver site={} reference={receiver:?} binding-complete={} frontier-complete={complete} targets={:?} values={values:?} completion={:?}",
            row.site, selected.binding().completion() == &ResolutionCompletion::Complete,
            selected.binding().targets(), selected.completion()));
        if selected.completion() != &ResolutionCompletion::Complete {
            return Ok(OperationProof::Possible {
                class_object: false,
                completion,
            });
        }
        if complete && !values.is_empty() {
            if values.iter().all(|value|matches!(value,ResolutionSlotValue::TypeObject(ty, None) if fixed_owner(rules.ready,ty.identity())))
                || (row.owners.is_empty() && values.iter().all(|value|matches!(value,ResolutionSlotValue::TypeObject(_, None)))) {
                return Ok(OperationProof::NoEffect);
            }

            if values
                .iter()
                .all(|value| matches!(value, ResolutionSlotValue::Runtime { .. }))
            {
                // A proved runtime value never changes a class dictionary.
                // Its unknown instance inventory is handled by the late path.
                return Ok(OperationProof::Instance(completion));
            }
            class_object=values.iter().all(|value|matches!(value,ResolutionSlotValue::TypeObject(ty, None) if row.owners.contains(&ty.identity())));
            if !row.owners.is_empty()
                && values
                    .iter()
                    .all(|value| !row.owners.contains(&value.ty().identity()))
            {
                return Ok(OperationProof::NoEffect);
            }
        }
        if selected.binding().completion() == &ResolutionCompletion::Complete
            && let [target] = selected.binding().targets()
            && values.iter().all(|value| value.obligation().is_none())
            && is_class(rules.ready, *target)?
        {
            if row.owners.is_empty() || !row.owners.contains(target) {
                return Ok(OperationProof::NoEffect);
            }
            class_object = true;
        }
    }
    if let Some(callee) = row.callee {
        let Some(selected) = answer(callee) else {
            return Ok(OperationProof::Reference(DemandReferenceKey::caller(
                callee,
            )));
        };
        completion = completion.combine(selected.completion());
        if selected.completion() != &ResolutionCompletion::Complete {
            return Ok(OperationProof::Possible {
                class_object: false,
                completion,
            });
        }
        let expected = match row.form {
            1 => builtin(rules.ready, "setattr"),
            2 => builtin(rules.ready, "delattr"),
            _ => None,
        };
        if selected.binding().completion() == &ResolutionCompletion::Complete
            && let [target] = selected.binding().targets()
            && let Some(expected) = expected
            && *target != expected
        {
            return Ok(OperationProof::NoEffect);
        }
    }
    Ok(OperationProof::Possible {
        // The class-object coordinate is proved. An unresolved candidate API
        // can replace this binding, so retain its target with Unknown binding.
        // A proved shadowed builtin callee was excluded above. API confirmation
        // and certain/potential assembly belong to the later confirmation step.
        class_object,
        completion,
    })
}

pub(super) fn replies(
    input: AccessRowInput<'_>,
) -> Vec<(DemandReferenceKey, &FactResolutionAnswer)> {
    match input {
        AccessRowInput::Start => Vec::new(),
        AccessRowInput::Replies(replies) => replies
            .iter()
            .filter_map(|reply| match reply {
                AccessPrerequisiteReply::Reference { key, answer } => Some((*key, answer.as_ref())),
                _ => None,
            })
            .collect(),
    }
}

pub(super) fn classify(
    half: &PythonMemberContext<'_, '_, '_>,
    context: &MemberAccessContext<'_>,
    row: &OperationRow,
    input: AccessRowInput<'_>,
) -> Result<AccessRowPoll> {
    let completion = match prove(half.rules, row, &replies(input))? {
        OperationProof::Reference(key) => return Ok(AccessRowPoll::Reference(key)),
        OperationProof::NoEffect => {
            return Ok(AccessRowPoll::Observed(ResolutionCompletion::Complete));
        }
        OperationProof::Instance(completion) | OperationProof::Possible { completion, .. } => {
            completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(
                    row.receiver.or(row.callee).unwrap_or(context.reference),
                ),
            ]))
        }
    };
    for owner in row.owners.iter() {
        half.member_observations
            .borrow_mut()
            .push(HierarchyProviderObservation {
                provider: HierarchyProviderKey::source(
                    *owner,
                    context.lookup,
                    context.namespace,
                    HierarchyProviderAuthority::Context {
                        mount: row.mount,
                        version: crate::analyzer::store::python_binding_rows::NATIVE_SOURCE_FORMAT,
                        order: row.site,
                        blob: None,
                    },
                    HierarchyProviderOperand::CandidateInventory,
                    half.reference,
                    context.step as u32,
                ),
                visit: HierarchyProviderVisit::Observed,
                completion: completion.clone(),
                inventory_complete: Some(false),
            });
    }
    receipt(half.rules, row, false);
    Ok(AccessRowPoll::Observed(completion))
}

pub(super) fn observe_access(
    half: &PythonMemberContext<'_, '_, '_>,
    context: &MemberAccessContext<'_>,
    row: &OperationRow,
    owner: SemanticId,
    target: SemanticId,
    completion: &ResolutionCompletion,
) {
    half.member_observations
        .borrow_mut()
        .push(HierarchyProviderObservation {
            provider: HierarchyProviderKey::source(
                owner,
                context.lookup,
                context.namespace,
                HierarchyProviderAuthority::Context {
                    mount: row.mount,
                    version: crate::analyzer::store::python_binding_rows::NATIVE_SOURCE_FORMAT,
                    order: row.site,
                    blob: None,
                },
                HierarchyProviderOperand::Access { target },
                context.reference,
                context.step as u32,
            ),
            visit: HierarchyProviderVisit::Observed,
            completion: completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(
                    row.receiver.or(row.callee).unwrap_or(context.reference),
                ),
            ])),
            inventory_complete: None,
        });
}

pub(in crate::analyzer::store::resolution_operation) fn receipt(
    rules: &super::super::python_demand::PythonRules<'_, '_, '_>,
    row: &OperationRow,
    confirmed: bool,
) {
    rules.observations.borrow_mut().push(format!("dynamic operation mount={} site={} receiver={:?} possible-replacement=true class-object-confirmed={confirmed} target-retained=true",row.mount,row.site,row.receiver));
}
