//! Source applicability only. Shared access/prefix cursors own all waits.
use super::*;
use crate::analyzer::store::StoreError;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

pub(in crate::analyzer::store::resolution_operation) struct OperationRow {
    mount: u32,
    structural: bool,
    site: u32,
    form: u8,
    pub(super) callee: Option<SemanticId>,
    pub(super) receiver: Option<SemanticId>,
    owners: std::rc::Rc<[SemanticId]>,
}
impl OperationRow {
    // Receiver disjointness is enough for universe exclusion. Demanding the
    // builtin setter while proving that same builtin would create a cycle.
    // Unresolved candidates stay open; member rows also prove API authority.
    pub fn module_receiver(
        &self,
        rules: &PythonRules<'_, '_, '_>,
        answers: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<Option<ModuleMutation>> {
        if self.structural {
            return Ok(Some(ModuleMutation::structurally_selected()));
        }
        let Some(receiver) = self.receiver else {
            return Ok(None);
        };
        let mut mutation = ModuleMutation {
            targets: Vec::new(),
            complete: false,
        };
        let Some((_, answer)) = answers.iter().find(|(key, _)| key.reference == receiver) else {
            return Ok(Some(mutation));
        };
        if answer.binding().completion() != &ResolutionCompletion::Complete {
            return Ok(Some(mutation));
        }
        // A module declaration denotes the module object. An ordinary variable
        // declaration denotes a cell and cannot prove receiver disjointness.
        let mut modules = !answer.binding().targets().is_empty();
        for target in answer.binding().targets() {
            let Some(ordinal) = target.ordinal() else {
                modules = false;
                break;
            };
            let mount = super::super::SelectedMountTable::new(&rules.ready.inventory)
                .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
            let blob = rules
                .ready
                .inventory
                .mount_record_by_ordinal(mount.ordinal())?
                .blob_id();
            let module = super::super::python_demand::module_declaration_site(
                rules.ready.inventory.connection(),
                blob,
            )?
            .map(|site| crate::analyzer::resolution::mounted_site_semantic(mount.fragment(), site));
            modules &= module == Some(*target);
        }
        if modules {
            mutation.targets = answer.binding().targets().to_vec();
            mutation.complete = true;
            return Ok(Some(mutation));
        }
        let frontiers = answer
            .projections()
            .iter()
            .filter(|projection| projection.reference() == receiver)
            .flat_map(|projection| {
                answer
                    .projected_frontiers()
                    .iter()
                    .filter(move |frontier| frontier.slot() == projection.output_slot())
            })
            .collect::<Vec<_>>();
        mutation.complete = !frontiers.is_empty();
        for frontier in frontiers {
            mutation.complete &= frontier.completion() == &ResolutionCompletion::Complete
                && !frontier.possible_values().is_empty();
            for value in frontier.possible_values() {
                if let ResolutionSlotValue::TypeObject(ty, None) = value {
                    mutation.targets.push(ty.identity());
                } else {
                    // A runtime nominal type alone does not identify a module
                    // object, and can include unmodeled aliases/subclasses.
                    mutation.complete = false;
                }
            }
        }
        Ok(Some(mutation))
    }

    pub fn universe_prerequisites(&self) -> impl Iterator<Item = SemanticId> {
        self.receiver.into_iter()
    }
}

// A source close keeps only the receiver's identity proof, never all forward
// answers or a workspace owner index. Applicability cannot change this owner.
#[derive(Clone)]
pub(in crate::analyzer::store::resolution_operation) struct ModuleMutation {
    targets: Vec<SemanticId>,
    complete: bool,
}
impl ModuleMutation {
    pub fn structurally_selected() -> Self {
        Self {
            targets: Vec::new(),
            complete: false,
        }
    }

    pub fn namespace_completion(&self, reason: SemanticId) -> ResolutionCompletion {
        if self.complete && !self.targets.is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                reason,
            )])
        }
    }

    pub fn completion(&self, owner: SemanticId) -> ResolutionCompletion {
        if self.complete && !self.targets.is_empty() && !self.targets.contains(&owner) {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                owner,
            )])
        }
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
    spelling: &str,
    owners: &[SemanticId],
) -> Result<Read<Vec<OperationRow>>> {
    let inventory = rules.structural_inventory()?;
    // A full result of this query, bounded by environment operations, lives
    // only with PythonRules. Per-read selection never evaluates receivers.
    let mut indices = Vec::new();
    for owner in owners {
        let space = Some(*owner);
        let cached = rules.structural_spaces.borrow().get(&space).cloned();
        let selected = if let Some(cached) = cached {
            cached
        } else {
            let mut containers = Vec::new();
            if let Some(ordinal) = owner.ordinal() {
                let selected_mount = super::super::SelectedMountTable::new(&rules.ready.inventory)
                    .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                let mount = rules
                    .ready
                    .inventory
                    .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                if super::super::python_demand::module_declaration_site(
                    rules.ready.inventory.connection(),
                    mount.blob_id(),
                )?
                .is_some_and(|site| {
                    crate::analyzer::resolution::mounted_site_semantic(
                        selected_mount.fragment(),
                        site,
                    ) == *owner
                }) {
                    containers=rules.ready.inventory.connection().prepare_cached(
                        "SELECT provider.container_path FROM python_unit_summary_providers provider
                         JOIN resolution_unit_summary_members member ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal
                         WHERE provider.summary_id=?1 AND member.blob_id=?2 AND provider.state IN ('selected','alternative')")?
                        .query_map(rusqlite::params![rules.summary,mount.blob_id()],|row|row.get::<_,String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                }
            }
            let selected = inventory
                .iter()
                .enumerate()
                .filter(|(_, mutation)| {
                    mutation.classes.contains(owner)
                        || mutation
                            .containers
                            .iter()
                            .any(|container| containers.contains(container))
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            rules
                .structural_spaces
                .borrow_mut()
                .insert(space, selected.clone());
            selected
        };
        indices.extend(selected);
    }
    indices.sort_unstable();
    indices.dedup();
    let operations = indices
        .into_iter()
        .map(|index| &inventory[index])
        .filter(|mutation| mutation.matches_name(spelling))
        .map(|mutation| mutation.operation(owners))
        .collect::<Vec<_>>();
    rules.observations.borrow_mut().push(format!(
        "dynamic structural name={spelling:?} rows={} owners={owners:?}",
        operations.len()
    ));
    Ok(Read::ready(operations))
}

pub(super) fn lookup_spelling(rules: &PythonRules<'_, '_, '_>, name: SemanticId) -> Result<String> {
    let identity = name
        .shared_name_id()
        .and_then(|id| rules.ready.shared_names().to_persisted(id))
        .expect("selected member name is persisted");
    Ok(rules.ready.inventory.connection().query_row(
        "SELECT spelling FROM resolution_identities WHERE id=?1",
        [identity.get()],
        |row| row.get(0),
    )?)
}

/// Only mutations of this owner and the requested spelling affect this read.
/// The shared MRO cursor applies this at every visited ancestor.
pub(super) fn attribute_rows(
    half: &PythonMemberContext<'_, '_, '_>,
    owner: SemanticId,
    spelling: &str,
) -> Result<Read<Vec<OperationRow>>> {
    if fixed_owner(half.rules.ready, owner) {
        return Ok(Read::ready(Vec::new()));
    }
    half.rules
        .record_dynamic_receiver_scope(half.reference, half.query_obligations)?;
    source_rows(half.rules, spelling, &[owner])
}

pub(in crate::analyzer::store::resolution_operation) fn import_rows(
    rules: &PythonRules<'_, '_, '_>,
    blob: i64,
    site: u32,
) -> Result<Read<Vec<OperationRow>>> {
    let imports=rules.ready.inventory.connection().prepare_cached(
        "SELECT imported.target_container,coalesce(imported.requested_name,'') FROM python_unit_summary_imports imported
         JOIN resolution_unit_summary_members member ON member.summary_id=imported.summary_id AND member.member_ordinal=imported.member_ordinal
         WHERE imported.summary_id=?1 AND member.blob_id=?2 AND imported.import_site=?3")?
        .query_map(rusqlite::params![rules.summary,blob,site], |row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let inventory = rules.structural_inventory()?;
    let operations = inventory
        .iter()
        .filter(|mutation| {
            imports.iter().any(|(container, name)| {
                if name.is_empty() || name == "*" {
                    mutation.containers.contains(container)
                } else {
                    mutation.can_write(container, name)
                }
            })
        })
        .map(|mutation| mutation.operation(&[]))
        .collect();
    Ok(Read::ready(operations))
}

pub(super) fn owner_rows(
    half: &PythonMemberContext<'_, '_, '_>,
    spelling: &str,
    owner: SemanticId,
) -> Result<Read<Vec<OperationRow>>> {
    if fixed_owner(half.rules.ready, owner) {
        return Ok(Read::ready(Vec::new()));
    }
    half.rules
        .record_dynamic_receiver_scope(half.reference, half.query_obligations)?;
    Ok(match source_rows(half.rules, spelling, &[owner])? {
        Read::Ready {
            mut value,
            completion,
        } => {
            value.retain(|row| row.structural || row.receiver.is_some());
            Read::Ready { value, completion }
        }
        Read::Cancelled(completion) => Read::Cancelled(completion),
        Read::Unavailable { reason, completion } => Read::Unavailable { reason, completion },
    })
}

pub(in crate::analyzer::store::resolution_operation) fn universe_rows(
    rules: &super::super::python_demand::PythonRules<'_, '_, '_>,
    reference: SemanticId,
    spelling: &str,
) -> Result<Read<Vec<OperationRow>>> {
    let inventory = rules.structural_inventory()?;
    if !rules.structural_spaces.borrow().contains_key(&None) {
        let indices = inventory
            .iter()
            .enumerate()
            .filter(|(_, mutation)| mutation.builtins)
            .map(|(index, _)| index)
            .collect();
        rules.structural_spaces.borrow_mut().insert(None, indices);
    }
    let spaces = rules.structural_spaces.borrow();
    let operations = spaces[&None]
        .iter()
        .map(|index| &inventory[*index])
        .filter(|mutation| mutation.matches_name(spelling))
        .map(|mutation| mutation.operation(&[]))
        .collect::<Vec<_>>();
    rules.observations.borrow_mut().push(format!(
        "universe structural name={spelling:?} operations={}",
        operations.len()
    ));
    let _ = reference;
    Ok(Read::ready(operations))
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
    Ok(match source_rows(half.rules, &spelling, &owners)? {
        Read::Ready { value, completion } => Read::Ready {
            value: value.into_iter().map(PythonMemberRow::Operation).collect(),
            completion,
        },
        Read::Cancelled(completion) => Read::Cancelled(completion),
        Read::Unavailable { reason, completion } => Read::Unavailable { reason, completion },
    })
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
    if row.structural {
        return Ok(OperationProof::Possible {
            class_object: true,
            completion: ResolutionCompletion::Complete,
        });
    }
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
        completion = completion.combine(selected.binding().completion());
        if selected.binding().completion() != &ResolutionCompletion::Complete {
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

/// One query's retained reflective writes. Binding selection, rather than typed
/// evaluation, identifies imports and direct assignment aliases of module objects.
/// Nothing in this inventory survives the request.
pub(in crate::analyzer::store::resolution_operation) struct StructuralMutation {
    pub containers: Vec<String>,
    classes: Vec<SemanticId>,
    builtins: bool,
    open_receiver: bool,
    mount: u32,
    site: u32,
    form: u8,
    pub receiver_kind: &'static str,
    names: Vec<String>,
    name_kind: u8,
}
impl StructuralMutation {
    fn operation(&self, owners: &[SemanticId]) -> OperationRow {
        OperationRow {
            mount: self.mount,
            site: self.site,
            form: self.form,
            structural: true,
            callee: None,
            receiver: None,
            owners: std::rc::Rc::from(owners),
        }
    }

    pub fn can_write(&self, container: &str, name: &str) -> bool {
        self.containers
            .iter()
            .any(|candidate| candidate == container)
            && self.matches_name(name)
    }
    fn matches_name(&self, name: &str) -> bool {
        self.name_kind == 2
            || self.names.iter().any(|candidate| {
                if self.name_kind == 1 {
                    name.starts_with(candidate)
                } else {
                    name == candidate
                }
            })
    }
}

// Alternatives join by openness, independent of the alias worklist order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum StructuralReceiverKind {
    MethodReceiver,
    Parameter,
    Attribute,
    UnresolvedName,
}

impl StructuralReceiverKind {
    fn label(self) -> &'static str {
        match self {
            Self::MethodReceiver => "method_receiver",
            Self::Parameter => "parameter",
            Self::Attribute => "attribute",
            Self::UnresolvedName => "unresolved_name",
        }
    }
}

// Both authored references and imported module cells use the same bounded
// binding-row walk. A module cell must select its reaching bindings too: an
// old class declaration alone does not identify a subsequently rebound import.
#[derive(Clone, PartialEq, Eq, Hash)]
enum StructuralAlias {
    Reference(i64, u32, u32),
    ModuleCell(i64, u32, String),
}

pub(in crate::analyzer::store::resolution_operation) fn structural_mutations(
    ready: &ReadySelectedResolution<'_, '_>,
    summary: i64,
    profile: super::super::python_lexical::PythonBindingProfile,
    session: &ResolutionSession,
    cancellation: &CancellationToken,
) -> Result<Vec<StructuralMutation>> {
    use super::super::python_lexical::{self, PythonBindingProofs};
    use crate::analyzer::resolution::temporal_binding::SessionBudget;
    use crate::analyzer::store::python_binding_rows::PythonBindingRows;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionBindingEventKind;
    crate::analyzer::store::resolution::with_resolution_read_progress_handler(
        ready.inventory.connection(),
        cancellation,
        |connection| {
            let rows = connection.prepare_cached(
        "SELECT mounts.blob_id,op.receiver_reference,op.receiver_slot,op.name_kind,
                (SELECT json_group_array(spelling) FROM python_member_operation_names WHERE operation=op.id),
                mounts.mount_ordinal,op.site,op.form
         FROM temp.selected_resolution_mounts mounts
         JOIN resolution_unit_summary_members member ON member.summary_id=?1
          AND member.blob_id=mounts.blob_id AND member.rel_path=mounts.persisted_relative_path
         JOIN python_binding_source source ON source.blob_id=mounts.blob_id AND source.format=?2
         JOIN python_member_operations op ON op.blob_id=mounts.blob_id AND op.effect IN (1,2)
         WHERE mounts.storage_language='python'
         UNION
         SELECT mounts.blob_id,receiver.source_site,writes.receiver,0,json_array(name.spelling),mounts.mount_ordinal,writes.site,7
         FROM temp.selected_resolution_mounts mounts
         JOIN resolution_unit_summary_members member ON member.summary_id=?1 AND member.blob_id=mounts.blob_id AND member.rel_path=mounts.persisted_relative_path
         JOIN python_binding_source source ON source.blob_id=mounts.blob_id AND source.format=?2
         JOIN python_member_receiver_writes writes ON writes.blob_id=mounts.blob_id
         JOIN resolution_semantic_sites target ON target.blob_id=writes.blob_id AND target.source_site=writes.site AND target.semantic_role='reference'
         JOIN resolution_reference_lookup_identities lookup ON lookup.blob_id=target.blob_id AND lookup.semantic_key=target.semantic_key
         JOIN resolution_identities name ON name.id=lookup.identity_id
         JOIN resolution_qualified_routes qualified ON qualified.blob_id=target.blob_id AND qualified.reference=target.semantic_key
         LEFT JOIN resolution_binding_projections projection ON projection.blob_id=qualified.blob_id AND projection.output_slot=qualified.qualifier_slot AND projection.kind<>2
         LEFT JOIN resolution_semantic_sites receiver ON receiver.blob_id=projection.blob_id AND receiver.semantic_key=projection.reference AND receiver.semantic_role='reference'
         WHERE mounts.storage_language='python'
         ORDER BY 6,7,8"
    )?.query_map(rusqlite::params![summary, crate::analyzer::store::python_binding_rows::NATIVE_SOURCE_FORMAT], |row| {
        Ok((row.get::<_,i64>(0)?,row.get::<_,Option<u32>>(1)?,row.get::<_,Option<u32>>(2)?,row.get::<_,u8>(3)?,row.get::<_,String>(4)?,row.get::<_,u32>(5)?,row.get::<_,u32>(6)?,row.get::<_,u8>(7)?))
    })?.collect::<rusqlite::Result<Vec<_>>>()?;
            let mut result = Vec::new();
            // Full results of binding-row reads are held for this scan only.
            let mut bindings = HashMap::default();
            let mut parameter_owners = HashMap::default();
            let mut parameter_classes = |blob: i64,
                                         mount: u32,
                                         parameter: u32|
             -> Result<Vec<SemanticId>> {
                let key = (blob, mount, parameter);
                if let std::collections::hash_map::Entry::Vacant(entry) =
                    parameter_owners.entry(key)
                {
                    // kind=2 is StaticMethodCandidate: its first argument is not self/cls.
                    let owners=connection.prepare_cached(
                        "SELECT owner.semantic_key FROM python_member_member_roles role
                         JOIN resolution_semantic_sites owner ON owner.blob_id=role.blob_id AND owner.source_site=role.owner AND owner.semantic_role='definition'
                         WHERE role.blob_id=?1 AND role.receiver_parameter=?2 AND role.kind<>2")?
                        .query_map(rusqlite::params![blob,parameter],|row|Ok(SemanticId::local(mount,row.get(0)?)))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    entry.insert(owners);
                }
                Ok(parameter_owners[&key].clone())
            };

            for (blob, receiver, slot, name_kind, names, mount, site, form) in rows {
                if cancellation.is_cancelled() {
                    return Err(StoreError::cancelled("module mutation scan cancelled"));
                }
                let mut containers = Vec::new();
                let mut classes = Vec::new();
                let mut builtins = false;
                let mut open_receiver = false;
                let mut receiver_kind = None;
                if let Some(receiver) = receiver {
                    let mut pending = vec![StructuralAlias::Reference(blob, mount, receiver)];
                    let mut visited = HashSet::default();
                    while let Some(alias) = pending.pop() {
                        // Bound alias traversal independently of the evaluator's round budget.
                        if visited.len() >= 64 || !visited.insert(alias.clone()) {
                            receiver_kind =
                                receiver_kind.max(Some(StructuralReceiverKind::UnresolvedName));
                            open_receiver = true;
                            continue;
                        }
                        let (blob, mount, reference, cell) = match alias {
                            StructuralAlias::Reference(blob, mount, reference) => {
                                (blob, mount, Some(reference), None)
                            }
                            StructuralAlias::ModuleCell(blob, mount, name) => {
                                (blob, mount, None, Some(name))
                            }
                        };
                        let lookup = if let Some(name) = &cell {
                            Some((name.clone(), false))
                        } else {
                            connection.query_row(
                    "SELECT name.spelling, EXISTS(SELECT 1 FROM resolution_qualified_routes q
                      WHERE q.blob_id=site.blob_id AND q.reference=site.semantic_key)
                     FROM resolution_semantic_sites site
                     JOIN resolution_reference_lookup_identities lookup ON lookup.blob_id=site.blob_id AND lookup.semantic_key=site.semantic_key
                     JOIN resolution_identities name ON name.id=lookup.identity_id
                     WHERE site.blob_id=?1 AND site.source_site=?2 AND site.semantic_role='reference'",
                    rusqlite::params![blob, reference], |row| Ok((row.get::<_,String>(0)?,row.get::<_,bool>(1)?))
                ).optional()?
                        };
                        let Some((name, qualified)) = lookup else {
                            receiver_kind =
                                receiver_kind.max(Some(StructuralReceiverKind::UnresolvedName));
                            open_receiver = true;
                            continue;
                        };
                        if qualified {
                            receiver_kind =
                                receiver_kind.max(Some(StructuralReceiverKind::Attribute));
                            open_receiver = true;
                            continue;
                        }
                        if let std::collections::hash_map::Entry::Vacant(entry) =
                            bindings.entry(blob)
                        {
                            let Some(rows) = PythonBindingRows::load(
                                connection,
                                &ready.store.cache_budget,
                                blob,
                                None,
                                cancellation,
                            )?
                            else {
                                return Err(StoreError::cancelled(
                                    "module mutation binding read cancelled",
                                ));
                            };
                            entry.insert(rows);
                        }
                        let rows = &bindings[&blob];
                        let proofs = PythonBindingProofs {
                            conditional_imports: rows
                                .imports
                                .iter()
                                .map(|import| import.import_site.get())
                                .collect(),
                            ..Default::default()
                        };
                        if let Some(parameter) = reference
                            .and_then(|reference| {
                                python_lexical::fixed_parameter(rows, reference, &name, &proofs)
                            })
                            .and_then(|event| event.authored)
                        {
                            let owners = parameter_classes(blob, mount, parameter)?;
                            open_receiver |= owners.is_empty();
                            receiver_kind = receiver_kind.max(Some(if owners.is_empty() {
                                StructuralReceiverKind::Parameter
                            } else {
                                StructuralReceiverKind::MethodReceiver
                            }));
                            classes.extend(owners);
                            continue;
                        }
                        let mut state = if let Some(reference) = reference {
                            let Some(state) = python_lexical::lexical_selection(
                                rows, reference, &name, profile, proofs,
                            ) else {
                                receiver_kind =
                                    receiver_kind.max(Some(StructuralReceiverKind::UnresolvedName));
                                open_receiver = true;
                                continue;
                            };
                            state
                        } else {
                            let scope = rows
                                .scopes
                                .iter()
                                .find(|scope| scope.parent.is_none())
                                .expect("module root")
                                .scope;
                            python_lexical::module_selection(rows, scope, &name, profile, proofs)
                        };
                        let mut budget = SessionBudget {
                            session,
                            cancellation,
                        };
                        if cell.is_some() {
                            let scope = rows
                                .scopes
                                .iter()
                                .find(|scope| scope.parent.is_none())
                                .expect("module root")
                                .scope;
                            python_lexical::lexical_tier(&mut state, rows, scope, &mut budget);
                        } else {
                            python_lexical::select_lexical(
                                &mut state,
                                rows,
                                &mut budget,
                                cancellation,
                            )?;
                        }
                        if state.selection.stopped.is_some() {
                            receiver_kind =
                                receiver_kind.max(Some(StructuralReceiverKind::UnresolvedName));
                            open_receiver = true;
                            continue;
                        }
                        if state.selection.selected.is_empty() {
                            if name == "__builtins__" {
                                builtins = true;
                            } else {
                                receiver_kind =
                                    receiver_kind.max(Some(StructuralReceiverKind::UnresolvedName));
                                open_receiver = true;
                            }
                        }
                        if state.selection.open {
                            receiver_kind =
                                receiver_kind.max(Some(StructuralReceiverKind::UnresolvedName));
                            open_receiver = true;
                        }
                        for selected in &state.selection.selected {
                            let Some(event) = rows
                                .events
                                .iter()
                                .find(|event| event.event == selected.occurrence)
                            else {
                                receiver_kind =
                                    receiver_kind.max(Some(StructuralReceiverKind::UnresolvedName));
                                open_receiver = true;
                                continue;
                            };
                            match event.kind {
                        ResolutionBindingEventKind::Import => {
                            for import in rows.imports.iter().filter(|import| import.binding_event == Some(event.event)) {
                                let selected = connection.prepare_cached(
                                    "SELECT DISTINCT provider.container_path FROM python_unit_summary_imports imported
                                     JOIN resolution_unit_summary_members member ON member.summary_id=imported.summary_id AND member.member_ordinal=imported.member_ordinal
                                     JOIN python_binding_imports authored ON authored.blob_id=member.blob_id AND authored.import_site=imported.import_site
                                     JOIN resolution_import_selectors selector ON selector.blob_id=authored.blob_id AND selector.site=authored.import_site
                                     JOIN python_unit_summary_providers provider ON provider.summary_id=imported.summary_id AND provider.state IN ('selected','alternative')
                                     WHERE imported.summary_id=?1 AND member.blob_id=?2 AND imported.import_site=?3 AND (
                                      (authored.form=0 AND provider.module_name=CASE WHEN EXISTS(SELECT 1 FROM resolution_root_import_segments prefix WHERE prefix.blob_id=authored.blob_id AND prefix.import_site=authored.import_site) THEN imported.module_name ELSE selector.source_name END)
                                      OR (authored.form=1 AND provider.module_name=imported.module_name || '.' || imported.requested_name))"
                                )?.query_map(rusqlite::params![summary,blob,import.import_site.get()], |row| row.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                                let has_containers = !selected.is_empty();
                                containers.extend(selected);
                                let imported_builtins = connection.query_row(
                                    "SELECT EXISTS(SELECT 1 FROM python_unit_summary_imports imported
                                     JOIN resolution_unit_summary_members member ON member.summary_id=imported.summary_id AND member.member_ordinal=imported.member_ordinal
                                     WHERE imported.summary_id=?1 AND member.blob_id=?2 AND imported.import_site=?3 AND imported.module_name='builtins' AND imported.form='module')",
                                    rusqlite::params![summary,blob,import.import_site.get()], |row|row.get::<_,bool>(0))?;
                                let cells=connection.prepare_cached(
                                    "SELECT DISTINCT mounted.blob_id,mounted.mount_ordinal,imported.requested_name
                                     FROM python_unit_summary_imports imported
                                     JOIN resolution_unit_summary_members importer ON importer.summary_id=imported.summary_id AND importer.member_ordinal=imported.member_ordinal
                                     JOIN python_unit_summary_providers provider ON provider.summary_id=imported.summary_id AND provider.container_path=imported.target_container AND provider.state IN ('selected','alternative')
                                     JOIN resolution_unit_summary_members member ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal
                                     JOIN temp.selected_resolution_mounts mounted ON mounted.blob_id=member.blob_id AND mounted.persisted_relative_path=member.rel_path
                                     WHERE imported.summary_id=?1 AND importer.blob_id=?2 AND imported.import_site=?3 AND imported.form='from'")?
                                    .query_map(rusqlite::params![summary,blob,import.import_site.get()],|row|Ok(StructuralAlias::ModuleCell(row.get(0)?,row.get(1)?,row.get(2)?)))?
                                    .collect::<rusqlite::Result<Vec<_>>>()?;
                                if !has_containers && !imported_builtins && cells.is_empty() {
                                    receiver_kind = receiver_kind.max(Some(StructuralReceiverKind::UnresolvedName));
                                    open_receiver = true;
                                }
                                builtins |= imported_builtins;
                                pending.extend(cells);
                            }
                        }
                        ResolutionBindingEventKind::Assign => {
                            if let Some(source) = connection.query_row(
                                "SELECT source_reference FROM resolution_binding_events WHERE blob_id=?1 AND event=?2",
                                rusqlite::params![blob,event.event], |row| row.get::<_,Option<u32>>(0)
                            )? { pending.push(StructuralAlias::Reference(blob,mount,source)); }
                            else {
                                receiver_kind = receiver_kind.max(Some(StructuralReceiverKind::UnresolvedName));
                                open_receiver = true;
                            }
                        }
                        ResolutionBindingEventKind::Class => {
                            if let Some(authored)=event.authored
                                && let Some(key)=connection.query_row(
                                    "SELECT semantic_key FROM resolution_semantic_sites WHERE blob_id=?1 AND source_site=?2 AND semantic_role='definition'",
                                    rusqlite::params![blob,authored],|row|row.get::<_,u32>(0)).optional()? {
                                classes.push(SemanticId::local(mount,key));
                            } else {
                                receiver_kind = receiver_kind.max(Some(StructuralReceiverKind::UnresolvedName));
                                open_receiver = true;
                            }
                        }
                        ResolutionBindingEventKind::Parameter => {
                            let owners = if let Some(authored) = event.authored {
                                parameter_classes(blob, mount, authored)?
                            } else {
                                Vec::new()
                            };
                            open_receiver |= owners.is_empty();
                            receiver_kind = receiver_kind.max(Some(if owners.is_empty() {
                                StructuralReceiverKind::Parameter
                            } else {
                                StructuralReceiverKind::MethodReceiver
                            }));
                            classes.extend(owners);
                        },
                        _ => {
                            receiver_kind = receiver_kind.max(Some(StructuralReceiverKind::UnresolvedName));
                            open_receiver = true;
                        }
                    }
                        }
                    }
                }
                containers.sort();
                containers.dedup();
                result.push(StructuralMutation {
                    containers,
                    classes,
                    builtins,
                    open_receiver,
                    mount,
                    site,
                    form,
                    receiver_kind: receiver_kind.map(StructuralReceiverKind::label).unwrap_or(
                        if receiver.is_some() {
                            "unresolved_name"
                        } else if slot.is_some() {
                            "expression"
                        } else {
                            "missing"
                        },
                    ),
                    names: serde_json::from_str(&names).map_err(|error| {
                        StoreError::corrupt(format!("invalid mutation names: {error}"))
                    })?,
                    name_kind,
                });
            }
            Ok(result)
        },
    )
}

pub(in crate::analyzer::store::resolution_operation) fn dynamic_receiver_query_obligation(
    mutations: &[StructuralMutation],
) -> Option<crate::analyzer::resolution::QueryObligation> {
    let mut count = 0;
    let mut kinds = std::collections::BTreeSet::new();
    for mutation in mutations.iter().filter(|mutation| {
        (mutation.containers.is_empty() && mutation.classes.is_empty() && !mutation.builtins)
            || mutation.open_receiver
            || mutation.receiver_kind == "method_receiver"
    }) {
        count += 1;
        kinds.insert(mutation.receiver_kind);
    }
    (count != 0).then(|| {
        crate::analyzer::resolution::QueryObligation::new(
            "python_dynamic_receiver_mutation_open",
            format!("operations={count}"),
            format!("receiver_kinds={kinds:?}"),
        )
    })
}

pub(in crate::analyzer::store::resolution_operation) fn dynamic_receiver_obligation(
    mutations: &[StructuralMutation],
) -> Option<String> {
    dynamic_receiver_query_obligation(mutations).map(|obligation| obligation.to_string())
}
