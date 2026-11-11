//! Python supplies collection and C3 rules; shared cursors own every walk.
#![allow(dead_code)] // Dormant until the member source rules opt into these policies.
pub(super) mod operations;
use crate::CancellationToken;
use crate::analyzer::Language;
use crate::analyzer::resolution::*;
use crate::analyzer::store::Result;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use std::cmp::Ordering;

#[derive(Debug)]
pub(super) struct OrdinaryClassCreation {
    pub allocator: OrdinaryAllocator,
    pub completion: ResolutionCompletion,
}

#[derive(Debug)]
pub(super) enum OrdinaryAllocator {
    RuntimeBuiltin,
    InheritedObject {
        owners: Vec<SemanticId>,
        object: SemanticId,
    },
}

pub(super) enum ClassCreation {
    Ordinary(OrdinaryClassCreation),
    /// Not proven ordinary, and only because the C3 order is open: every class
    /// in it has ordinary, undecorated creation inputs, and the order's own
    /// incompleteness comes only from unresolved bases (see
    /// `UnresolvedBases::discharge`), so its metaclass is unknown only through
    /// them. Anything else open in the order is `Unproven`.
    OpenOrder(UnresolvedBases),
    Unproven,
}

/// The bases of a C3 order that are not known classes, as far as the order
/// itself shows: the classes in it, and the owners that are not classes.
#[derive(Debug)]
pub(super) struct UnresolvedBases {
    owners: Vec<SemanticId>,
    non_class_owners: Vec<SemanticId>,
}

impl UnresolvedBases {
    /// Whether every reason in `completion` only records that a base of a class
    /// in this order names no known class, so the order's metaclass is unknown
    /// and nothing else is open. A reason is discharged by provenance, never by
    /// variant alone. The allowed provenances are:
    /// - the `unresolved-supertype-edge` service reason of an edge whose class
    ///   is in the order (its base reference resolved to no target);
    /// - the base reference of such an edge, which carries its own
    ///   `UnsupportedSemantic` residual beside that service reason;
    /// - a non-class owner in the order (a rebound name used as a base), whose
    ///   implicit base is unavailable.
    ///
    /// Typed fixed-point cycles and every other service kind, budget stops,
    /// cancellation, open boundaries and producer gap reasons keep the reply open.
    pub(super) fn discharge(
        &self,
        provenance: HierarchyProvenanceView<'_>,
        completion: &ResolutionCompletion,
    ) -> bool {
        let ResolutionCompletion::Incomplete(reasons) = completion else {
            return true;
        };
        let unresolved_edge = |reason: &ResolutionIncompleteReason| {
            let ResolutionIncompleteReason::UnsupportedSemantic(reason) = reason else {
                return None;
            };
            let (kind, operands) = provenance.service_reason(*reason)?;
            // Operands are the edge's definition, reference and frontier.
            (kind == "unresolved-supertype-edge" && self.owners.contains(&operands[0]))
                .then(|| operands[1])
        };
        let edge_references = reasons
            .iter()
            .filter_map(unresolved_edge)
            .collect::<Vec<_>>();
        reasons.iter().all(|reason| {
            let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason else {
                return false;
            };
            unresolved_edge(reason).is_some()
                || edge_references.contains(semantic)
                || self.non_class_owners.contains(semantic)
        })
    }
}

// Shared Python authority for ordinary class construction and class-valued
// dictionary entries. Allocator behavior is checked separately by construction.
pub(super) fn ordinary_class_creation(
    rules: &PythonRules<'_, '_, '_>,
    typed: &dyn SelectedTypedFactSource,
    target: SemanticId,
    provenance: HierarchyProvenanceView<'_>,
    order: Option<HierarchyOrderOutcomeId>,
) -> Result<std::ops::ControlFlow<ResolutionCompletion, ClassCreation>> {
    // The selected runtime supplies builtin metaclass/allocator authority.
    // Its result identity does not depend on having an acquired member MRO.
    if builtin_class(rules, target)?.is_some() {
        return Ok(std::ops::ControlFlow::Continue(ClassCreation::Ordinary(
            OrdinaryClassCreation {
                allocator: OrdinaryAllocator::RuntimeBuiltin,
                completion: ResolutionCompletion::Complete,
            },
        )));
    }
    let Some(order) = order else {
        return Ok(std::ops::ControlFlow::Continue(ClassCreation::Unproven));
    };
    let only_decorators = |completion: &ResolutionCompletion| match completion {
        ResolutionCompletion::Complete => true,
        ResolutionCompletion::Incomplete(reasons) => reasons.iter().all(|reason| {
            let (ResolutionIncompleteReason::UnsupportedSemantic(reason)
            | ResolutionIncompleteReason::ReceiverSubclassObligation(reason)) = reason
            else {
                return false;
            };
            rules
                .ready
                .context_identities
                .named_reason(*reason)
                .is_some_and(|(name, _)| name == "python_class_decorator_unproven")
        }),
    };
    let status = provenance.order_status(order);
    // Only the shared C3 order and class headers establish this authority;
    // applicability of the lookup used to request that order is independent.
    let mut construction_completion = status.completion.clone();
    let Some(object) = super::python_members::builtin(rules.ready, "object") else {
        return Ok(std::ops::ControlFlow::Continue(ClassCreation::Unproven));
    };
    // Default class creation uses the language's intrinsic type;
    // a source binding with that spelling cannot replace it.
    if super::python_members::builtin(rules.ready, "type").is_none() {
        return Ok(std::ops::ControlFlow::Continue(ClassCreation::Unproven));
    }
    let mut owners = Vec::new();
    let mut decorated_creation = false;
    let mut non_class_owners = Vec::new();
    let mut budget_stopped = false;
    if !provenance.visit_order(
        order,
        &mut || rules.cancellation.is_cancelled(),
        &mut |entry| {
            if !rules.session.scope_step() {
                budget_stopped = true;
                return Ok(());
            }
            owners.push(entry.owner);
            Ok(())
        },
    )? || budget_stopped
        || rules.cancellation.is_cancelled()
        || !rules.session.observe_cancellation()
    {
        return Ok(std::ops::ControlFlow::Break(cancelled_completion()));
    }
    owners.sort_unstable();
    owners.dedup();
    if !owners.contains(&target) {
        return Ok(std::ops::ControlFlow::Continue(ClassCreation::Unproven));
    }
    for &owner in &owners {
        if owner == object {
            continue;
        }
        if !rules.session.scope_step() || rules.cancellation.is_cancelled() {
            return Ok(std::ops::ControlFlow::Break(cancelled_completion()));
        }
        let Some(header) = typed.implicit_base_inputs(owner, rules.cancellation)? else {
            // A base that names a non-class value (a rebound name) leaves the
            // metaclass unknown, as an unresolved base does.
            if is_class(rules.ready, owner)? {
                return Ok(std::ops::ControlFlow::Continue(ClassCreation::Unproven));
            }
            non_class_owners.push(owner);
            continue;
        };
        crate::profiling::note_with(|| {
            format!(
                "resolution::python_construction_header owner={owner:?} creation={:?} complete={:?} inventory={}",
                header.creation, header.completion, header.written_inventory_complete,
            )
        });
        if header.creation != ClassCreationKind::Ordinary
            || !header.written_inventory_complete
            || !only_decorators(&header.completion)
        {
            // Expanded bases and any
            // unproved metaclass remain explicit open construction.
            return Ok(std::ops::ControlFlow::Continue(ClassCreation::Unproven));
        }
        decorated_creation |= header.completion != ResolutionCompletion::Complete;
        construction_completion = construction_completion.combine(&header.completion);
    }
    // A decorated ordinary source class still supplies a candidate.
    // C3 records that its implicit inventory is open; preserve that
    // evidence and the class header's named decorator reason.
    // An unresolved base contributes no owner, so its order can be marked
    // complete and still lack `object`.
    let non_class_base = !non_class_owners.is_empty();
    if !decorated_creation && (non_class_base || !status.complete || !owners.contains(&object)) {
        let bases = UnresolvedBases {
            owners,
            non_class_owners,
        };
        return Ok(std::ops::ControlFlow::Continue(
            if bases.discharge(provenance, status.completion) {
                ClassCreation::OpenOrder(bases)
            } else {
                ClassCreation::Unproven
            },
        ));
    }
    if non_class_base || !owners.contains(&object) {
        return Ok(std::ops::ControlFlow::Continue(ClassCreation::Unproven));
    }

    Ok(std::ops::ControlFlow::Continue(ClassCreation::Ordinary(
        OrdinaryClassCreation {
            allocator: OrdinaryAllocator::InheritedObject { owners, object },
            completion: construction_completion,
        },
    )))
}

#[derive(Debug)]
pub(super) struct PythonHierarchy;
pub(super) static PYTHON_HIERARCHY: PythonHierarchy = PythonHierarchy;
impl HierarchyPolicy for PythonHierarchy {
    fn identity(&self) -> HierarchyPolicyId {
        HierarchyPolicyId(0x5059_0001)
    }
    fn compare_distance(&self, _: HierarchyLookupShape, _: u32, _: u32) -> Ordering {
        Ordering::Equal
    }
    fn retain_owner(&self, _: bool) -> bool {
        true
    }
    fn direct_hit_stops(&self, _: HierarchyLookupShape) -> bool {
        false
    }
    fn evidence_cutoff(&self, _: HierarchyLookupShape, _: Option<u32>) -> Option<u32> {
        None
    }
    fn edge_provider(&self) -> &'static dyn HierarchyEdgeProvider {
        &PYTHON_HIERARCHY
    }
}
impl HierarchyEdgeProvider for PythonHierarchy {
    fn implicit_base(
        &self,
        owner: SemanticId,
        source: &dyn SelectedTypedFactSource,
        cancellation: &CancellationToken,
    ) -> Result<Option<ImplicitBaseRead>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let inputs = source.implicit_base_inputs(owner, cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(inputs) = inputs else {
            return Ok(Some(ImplicitBaseRead {
                base: None,
                observations: Box::new([]),
                completion: ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(owner),
                ]),
            }));
        };
        let ordinary =
            inputs.creation == ClassCreationKind::Ordinary && inputs.written_inventory_complete;
        let completion = inputs.completion;
        let provider = HierarchyProviderKey::source(
            owner,
            owner,
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type,
            implicit_authority(inputs.authority),
            HierarchyProviderOperand::SupertypeInventory,
            owner,
            0,
        );
        let observation = HierarchyProviderObservation {
            provider: provider.clone(),
            visit: HierarchyProviderVisit::Observed,
            completion: completion.clone(),
            inventory_complete: Some(ordinary),
        };
        let base = if ordinary && inputs.written_base_count == 0 {
            inputs
                .root_object
                .filter(|root| root.identity != owner)
                .map(|root| {
                    let provider = HierarchyProviderKey::source(
                        owner,
                        owner,
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type,
                        implicit_authority(root.authority),
                        HierarchyProviderOperand::SupertypeEdge {
                            reference: root.occurrence,
                            ordinal: 0,
                        },
                        root.occurrence,
                        0,
                    );
                    ImplicitBaseFact {
                        target: root.identity,
                        ordinal: 0,
                        occurrence: root.occurrence,
                        provider,
                    }
                })
        } else {
            None
        };
        Ok(Some(ImplicitBaseRead {
            base,
            observations: Box::new([observation]),
            completion,
        }))
    }
}

#[derive(Debug)]
pub(super) struct PythonC3;
pub(super) static PYTHON_C3: PythonC3 = PythonC3;
impl HierarchyLinearizationPolicy for PythonC3 {
    fn identity(&self) -> HierarchyOrderPolicyId {
        HierarchyOrderPolicyId(0x5059_0001)
    }
    fn next(
        &self,
        frontier: &HierarchyOrderFrontier<'_>,
        budget: &mut HierarchyOrderBudget<'_>,
    ) -> Result<HierarchyOrderDecision> {
        let first = frontier
            .heads
            .first()
            .expect("shared driver supplies a merge frontier");
        // The shared frontier retains base-operand order, with the direct-base
        // sequence last. A legal head is absent from every remaining tail.
        for candidate in frontier.heads {
            let mut blocked = false;
            for sequence in frontier.heads {
                if !budget.step() {
                    return Ok(HierarchyOrderDecision::Incomplete {
                        completion: ResolutionCompletion::Complete,
                        provenance: candidate.provenance,
                    });
                }
                match frontier.tail_contains(sequence.sequence, candidate.owner, budget) {
                    HierarchyTailMembership::Present => {
                        blocked = true;
                        break;
                    }
                    // The shared cursor marks an unsearched suffix incomplete.
                    // Retain the C3 order of written classes for observations;
                    // no access exclusion uses an incomplete order.
                    HierarchyTailMembership::Unknown => {}
                    HierarchyTailMembership::Absent => {}
                }
            }
            if blocked {
                continue;
            }
            return Ok(HierarchyOrderDecision::Emit {
                owner: candidate.owner,
                advance: frontier
                    .heads
                    .iter()
                    .filter(|head| head.owner == candidate.owner)
                    .map(|head| head.sequence)
                    .collect(),
                provenance: candidate.provenance,
            });
        }
        Ok(HierarchyOrderDecision::Incomplete {
            completion: ResolutionCompletion::Complete,
            provenance: first.provenance,
        })
    }
}

use super::demand_closure::*;
use super::member_access::*;
use super::python_demand::{PythonHalf, PythonRules};
use super::{FactPageVisitor, ReadySelectedResolution, SelectedResolutionMountOrdinal};
use rusqlite::OptionalExtension;

/// Borrowed data shared by ROOT and typed member requests. The provider owns
/// these inputs for one query; this view performs no expression evaluation.
pub(super) struct PythonMemberContext<'a, 'store, 'input> {
    pub rules: &'a PythonRules<'a, 'store, 'input>,
    pub reference: SemanticId,
    pub query_obligations: &'a std::cell::RefCell<
        crate::analyzer::resolution::query_obligations::NodeQueryObligations,
    >,
    pub environment: crate::analyzer::resolution::EnvironmentId,
    pub rows: &'a crate::analyzer::store::python_binding_rows::PythonBindingRows,
    pub blob: i64,
    pub member_values: &'a [ResolutionSlotValue],
    pub super_cursor: Option<&'a super::python_demand::super_context::SuperCursor>,
    pub member_observations: &'a std::cell::RefCell<Vec<HierarchyProviderObservation>>,
    pub rendered_order: &'a std::cell::Cell<bool>,
}

pub(super) struct PythonMemberRoute<'a> {
    pub lookup: &'a super::ResolutionLookupSemanticRecipe,
    pub namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
    pub step: usize,
    pub selection: &'a DemandMemberSelection,
    pub provenance: HierarchyProvenanceView<'a>,
}

pub(super) enum PythonMemberRow {
    Model(Box<super::python_models::ModelMemberRow>),
    Declared(Box<PythonDeclaredMemberRow>),
    Operation(operations::OperationRow),
    AttributeSpace {
        owner: SemanticId,
        metaclass: Option<SemanticId>,
        operations: Vec<operations::OperationRow>,
    },
}

pub(super) struct PythonDeclaredMemberRow {
    pub(super) property: LoweredMemberOwnerProperty,
    keyword_parameter: bool,
    provider: HierarchyProviderKey,
    kind: u32,
    receiver: ResolutionSlotValue,
    parameter: Option<SemanticId>,
    role_inputs: Option<std::rc::Rc<PythonMemberRoleInputs>>,
    operations: std::rc::Rc<[operations::OperationRow]>,
    pub(super) completion: ResolutionCompletion,
}

fn authored_name(
    ready: &ReadySelectedResolution<'_, '_>,
    definition: SemanticId,
) -> Result<String> {
    let (Some(ordinal), Some(key)) = (definition.ordinal(), definition.local_key()) else {
        return Ok(format!("{definition:?}"));
    };
    let mount = ready
        .inventory
        .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    let name = ready.inventory.connection().prepare_cached("SELECT slot.name FROM resolution_semantic_sites semantic
         JOIN resolution_binding_events event ON event.blob_id=semantic.blob_id AND event.authored=semantic.source_site
         JOIN resolution_binding_slots slot ON slot.blob_id=event.blob_id AND slot.slot=event.slot
         WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2 AND semantic.semantic_role='definition'
         ORDER BY event.event LIMIT 1")?.query_row(
        rusqlite::params![mount.blob_id(), key], |row| row.get::<_, String>(0),
    ).optional()?;
    Ok(name.unwrap_or_else(|| format!("{definition:?}")))
}

// Classification follows the same shared identities and versioned intrinsic
// table as predeclared symbols; source spelling alone has no authority here.
pub(super) fn builtin_class(
    rules: &PythonRules<'_, '_, '_>,
    definition: SemanticId,
) -> Result<Option<crate::analyzer::resolution::universe::UniverseEntry>> {
    use brokk_bifrost_python::intrinsics::{self, Availability, BuiltinKind};
    let Some(entry) = crate::analyzer::resolution::universe_entry_for_identity(
        &rules.ready.lexical_source(),
        definition,
        rules.cancellation,
    )?
    else {
        return Ok(None);
    };
    if entry.language != Language::Python {
        return Ok(None);
    }
    let Some(builtin) = intrinsics::builtin(entry.spelling) else {
        return Ok(None);
    };
    Ok((matches!(builtin.kind, BuiltinKind::Type)
        && builtin.versions.availability(rules.python_version) == Availability::Present)
        .then_some(entry))
}

/// Source-backed value members of the possible callee classes for an open keyword.
/// Query results live only for this reference projection.
pub(super) fn class_attribute_candidates<P: DemandRootProvider + ?Sized>(
    ready: &ReadySelectedResolution<'_, '_>,
    operation: &mut FactResolutionOperation<'_>,
    provider: &mut P,
    reference: SemanticId,
    classes: &[SemanticId],
    label: &str,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<SemanticId>>> {
    let Some(ordinal) = reference.ordinal() else {
        return Ok(None);
    };
    let mount = ready
        .inventory
        .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    let lookup =
        ResolutionLookupSemanticRecipe::new(Language::Python, ResolutionNamespace::Value, label)
            .semantic(&ready.shared_names());
    let mut candidates = Vec::new();
    for &class in classes {
        let Some(selected) = operation.resolve_member_by_demand(
            QualifiedMemberInput {
                reference: DemandReferenceKey::caller(reference),
                route_ordinal: 0,
                precedence: 0,
                fragment: mount.fragment_id(),
                source_lookup: lookup,
                lookup,
                namespace: ResolutionNamespace::Value,
                values: vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    class, 0,
                ))],
                completion: ResolutionCompletion::Complete,
                registration: QualifiedMemberRegistration {
                    language: Language::Python,
                    hierarchy_identity: PYTHON_HIERARCHY.identity().0,
                    member_access: true,
                },
            },
            provider,
        )?
        else {
            return Ok(None);
        };
        if super::native_units::ordered_member_binding_completion(
            ready,
            operation,
            &selected.access,
            selected.order,
            class,
            lookup,
            cancellation,
        )? != ResolutionCompletion::Complete
        {
            return Ok(None);
        }
        candidates.extend(
            selected
                .access
                .targets
                .iter()
                .map(|target| target.target.token),
        );
    }
    candidates.sort_unstable();
    candidates.dedup();
    Ok(Some(candidates))
}

pub(super) fn is_class(
    ready: &ReadySelectedResolution<'_, '_>,
    definition: SemanticId,
) -> Result<bool> {
    #[cfg(test)]
    if crate::analyzer::resolution::fact_resolution::demand_scheduler::is_python_constructor_order_test_root(definition) {
        return Ok(true);
    }
    if let Some(reference) = ready.context_identities.model_member_identity(definition)
        && let Some(analyzer) = ready.analyzer
        && let (Some(authority), Some(active)) =
            (analyzer.model_authority(), analyzer.active_models())
    {
        return Ok(super::python_models::declaration(
            &*authority,
            &active,
            &reference,
            &crate::CancellationToken::new(),
        )?
        .is_some_and(|owner| {
            owner.declaration.kind
                == crate::analyzer::semantic_model::SemanticModelSymbolKind::Class
        }));
    }
    let (Some(ordinal), Some(key)) = (definition.ordinal(), definition.local_key()) else {
        return Ok(false);
    };
    let mount = ready
        .inventory
        .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    Ok(ready.inventory.connection().prepare_cached("SELECT EXISTS(SELECT 1 FROM resolution_semantic_sites semantic JOIN python_member_classes class ON class.blob_id=semantic.blob_id AND class.class=semantic.source_site WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2 AND semantic.semantic_role='definition')")?.query_row(
        rusqlite::params![mount.blob_id(),key],|row| row.get(0))?)
}

// object implements the ordinary dictionary lookup itself. Only a custom
// __getattribute__ can replace a declared value; __getattr__ handles misses.
fn dynamic_attribute_hook(
    property: &LoweredMemberOwnerProperty,
    object: Option<SemanticId>,
) -> bool {
    property.member_name() == "__getattribute__" && Some(property.owner_definition()) != object
}

pub(super) fn member_rows(
    half: &PythonMemberContext<'_, '_, '_>,
    route: &PythonMemberRoute<'_>,
    owner: SemanticId,
) -> Result<Read<Vec<PythonMemberRow>>> {
    if let Some(rows) = super::python_models::member_rows(half, route, owner)? {
        return Ok(rows);
    }
    // A keyword label navigates to a declaration, independently of the
    // attribute value that normal reads would load. PythonNamedArguments
    // proves ordinary dataclass construction before requesting this lookup.
    let keyword_label = if let (Some(ordinal), Some(key)) =
        (half.reference.ordinal(), half.reference.local_key())
    {
        let mount = half
            .rules
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        half.rules.ready.inventory.connection().prepare_cached("SELECT EXISTS(SELECT 1 FROM resolution_named_argument_labels label
             JOIN resolution_semantic_sites reference ON reference.blob_id=label.blob_id AND reference.source_site=label.reference_site AND reference.semantic_role='reference'
             WHERE label.blob_id=?1 AND reference.semantic_key=?2 AND label.label=?3)")?.query_row(
            rusqlite::params![mount.blob_id(),key,route.lookup.spelling()], |row| row.get::<_,bool>(0),
        )?
    } else {
        false
    };
    let mut rows = Vec::new();
    let cached_hooks = half.rules.attribute_hooks.borrow().get(&owner).cloned();
    let mut hooks = cached_hooks
        .clone()
        .unwrap_or(ResolutionCompletion::Complete);
    let object = builtin(half.rules.ready, "object");
    let read = half.rules.visit_member_owners(
        &[owner],
        &mut FactPageVisitor::new(&mut |page| {
            for row in page {
                if !half.rules.session.scope_step() || half.rules.cancellation.is_cancelled() {
                    return Ok(false);
                }
                if cached_hooks.is_none() && dynamic_attribute_hook(row.row(), object) {
                    hooks = hooks.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(owner),
                    ]));
                }
                if row.row().member_name() == route.lookup.spelling() {
                    rows.push((row.row().clone(), row.identity().clone()));
                }
            }
            Ok(true)
        }),
    )?;
    if read.is_cancelled() {
        return Ok(Read::Cancelled(read.evidence().clone()));
    }
    if cached_hooks.is_none() && read.is_exhausted() {
        half.rules
            .attribute_hooks
            .borrow_mut()
            .insert(owner, hooks.clone());
    }
    let mut dictionary_completion = read.evidence().clone();
    // Interception affects both hits and misses. Fallback hooks contribute
    // only after the shared lookup has exhausted the ordinary member route.
    if half
        .member_values
        .iter()
        .any(|value| matches!(value, ResolutionSlotValue::Runtime { .. }))
    {
        dictionary_completion = dictionary_completion.combine(&hooks);
        // Interception precedes dictionary lookup, including a hit before the
        // hook's owner in C3. Inspect the whole selected order before closing.
        if let Some(order) = route.selection.order {
            let mut owners = Vec::new();
            route.provenance.visit_order(
                order,
                &mut || half.rules.cancellation.is_cancelled(),
                &mut |entry| {
                    owners.push(entry.owner);
                    Ok(())
                },
            )?;
            owners.sort_unstable();
            owners.dedup();
            for owners in owners.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
                let read = half.rules.visit_member_owners(
                    owners,
                    &mut FactPageVisitor::new(&mut |page| {
                        for row in page {
                            if !half.rules.session.scope_step() {
                                return Ok(false);
                            }
                            if dynamic_attribute_hook(row.row(), object) {
                                dictionary_completion = dictionary_completion.combine(
                                    &ResolutionCompletion::incomplete([
                                        ResolutionIncompleteReason::UnsupportedSemantic(
                                            row.row().owner_definition(),
                                        ),
                                    ]),
                                );
                            }
                        }
                        Ok(true)
                    }),
                )?;
                dictionary_completion = dictionary_completion.combine(read.evidence());
                if read.is_cancelled() {
                    return Ok(Read::Cancelled(dictionary_completion));
                }
            }
        }
    }
    let mut reaching = None;
    let mut annotation_only = Vec::new();
    if let (Some(ordinal), Some(key)) = (owner.ordinal(), owner.local_key()) {
        let mount = half
            .rules
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let scope:Option<u32>=half.rules.ready.inventory.connection().prepare_cached("SELECT node.source_scope FROM resolution_member_scope_properties scope JOIN resolution_node_catalog node ON node.blob_id=scope.blob_id AND node.local_key=scope.scope_head_node_key WHERE scope.blob_id=?1 AND scope.definition_semantic_key=?2 AND scope.scope_kind='type_body'")?.query_row(rusqlite::params![mount.blob_id(),key],|row|row.get(0)).optional()?.flatten();
        if let Some(scope) = scope {
            let owned;
            let bindings = if mount.blob_id() == half.blob {
                half.rows
            } else {
                let Some(loaded) = half
                    .rules
                    .load_binding_rows(mount.blob_id(), Some(mount.blob_oid()))?
                else {
                    return Ok(Read::Cancelled(dictionary_completion));
                };
                owned = loaded;
                &owned
            };
            annotation_only.extend(bindings.events.iter().filter(|event| {
                event.execution_scope == scope
                    && event.kind == brokk_bifrost_core::analyzer::resolution_facts::ResolutionBindingEventKind::Annotation
                    && event.value_slot.is_none()
            }).filter_map(|event| event.authored));
            let mut state = super::python_lexical::class_selection(
                bindings,
                scope,
                route.lookup.spelling(),
                half.rules.profile,
                super::python_lexical::PythonBindingProofs {
                    completed_scopes: vec![scope],
                    ..Default::default()
                },
            );
            super::python_lexical::lexical_tier(
                &mut state,
                bindings,
                scope,
                &mut crate::analyzer::resolution::temporal_binding::SessionBudget {
                    session: half.rules.session,
                    cancellation: half.rules.cancellation,
                },
            );
            if let Some(stop) = state.selection.stopped {
                let reason = match stop {
                    crate::analyzer::resolution::temporal_binding::Stop::Cancelled => {
                        super::cancelled_completion()
                    }
                    crate::analyzer::resolution::temporal_binding::Stop::Budget => {
                        ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::TimeBudgetExceeded(owner),
                        ])
                    }
                };
                return Ok(Read::Cancelled(dictionary_completion.combine(&reason)));
            }
            dictionary_completion = dictionary_completion.combine(&state.selection.completion);
            if state.selection.open {
                dictionary_completion =
                    dictionary_completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(owner),
                    ]));
            }
            reaching = Some(
                state
                    .selection
                    .selected
                    .iter()
                    .filter_map(|selected| {
                        bindings
                            .events
                            .iter()
                            .find(|event| event.event == selected.occurrence)
                    })
                    .map(|event| event.authored)
                    .collect::<Vec<_>>(),
            );
        }
    }
    let lookup = route.lookup.semantic(&half.rules.ready.shared_names());
    let provider = HierarchyProviderKey::source(
        owner,
        lookup,
        route.namespace,
        HierarchyProviderAuthority::Declaration(owner),
        HierarchyProviderOperand::CandidateInventory,
        half.reference,
        route.step as u32,
    );
    half.member_observations
        .borrow_mut()
        .push(HierarchyProviderObservation {
            provider: provider.clone(),
            visit: HierarchyProviderVisit::Observed,
            completion: dictionary_completion.clone(),
            inventory_complete: Some(read.is_exhausted()),
        });
    if !half.rendered_order.replace(true)
        && let Some(order) = route.selection.order
    {
        let mut written = Vec::new();
        route.provenance.visit_order(
            order,
            &mut || half.rules.cancellation.is_cancelled(),
            &mut |entry| {
                written.push(authored_name(half.rules.ready, entry.owner)?);
                Ok(())
            },
        )?;
        half.rules.observations.borrow_mut().push(format!(
            "c3 written-order={written:?} complete={} builtin-authority-gap={} exclusion=false",
            route.provenance.order_status(order).complete,
            builtin(half.rules.ready, "object").is_none()
        ));
    }
    let mut receivers = Vec::new();
    if let Some(order) = route.selection.order {
        route.provenance.visit_order(
            order,
            &mut || half.rules.cancellation.is_cancelled(),
            &mut |entry| {
                if entry.owner == owner {
                    let values = half
                        .member_values
                        .iter()
                        .filter(|value| value.ty().identity() == entry.root)
                        .copied()
                        .collect::<Vec<_>>();
                    receivers.extend(values);
                }
                Ok(())
            },
        )?;
    }
    if receivers.is_empty() {
        receivers.extend(half.member_values.iter().copied());
        assert!(
            !receivers.is_empty(),
            "member rows retain their selected root even without an order witness"
        );
    }
    receivers.sort_unstable();
    receivers.dedup();
    // Each MRO owner contributes mutations for the requested name. Retain a
    // prerequisite row even on a dictionary miss: an owned write may add that
    // name and shadow a later ancestor's declaration.
    let mut attribute_rows = Vec::new();
    let mutations = half
        .rules
        .attribute_mutations
        .borrow()
        .get(&(owner, lookup))
        .cloned();
    let operations = if let Some(mutations) = &mutations {
        dictionary_completion = dictionary_completion.combine(mutations);
        Vec::new()
    } else {
        match operations::attribute_rows(half, owner, route.lookup.spelling())? {
            Read::Ready { value, completion } => {
                dictionary_completion = dictionary_completion.combine(&completion);
                value
            }
            Read::Cancelled(completion) => {
                return Ok(Read::Cancelled(dictionary_completion.combine(&completion)));
            }
            Read::Unavailable { reason, completion } => {
                return Ok(Read::Unavailable {
                    reason,
                    completion: dictionary_completion.combine(&completion),
                });
            }
        }
    };
    let class_object = half
        .member_values
        .iter()
        .any(|value| matches!(value, ResolutionSlotValue::TypeObject(_, _)));
    let cached_metaclass = half
        .rules
        .attribute_metaclasses
        .borrow()
        .get(&(owner, lookup))
        .cloned();
    let metaclass = if class_object {
        if let Some(cached) = &cached_metaclass {
            dictionary_completion = dictionary_completion.combine(cached);
            None
        } else if let (Some(ordinal), Some(key)) = (owner.ordinal(), owner.local_key()) {
            let mount = half
                .rules
                .ready
                .inventory
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
            half.rules.ready.inventory.connection().prepare_cached("SELECT reference.semantic_key FROM resolution_semantic_sites definition
                 JOIN python_member_classes class ON class.blob_id=definition.blob_id AND class.class=definition.source_site
                 LEFT JOIN resolution_semantic_sites reference ON reference.blob_id=class.blob_id AND reference.source_site=class.metaclass AND reference.semantic_role='reference'
                 WHERE definition.blob_id=?1 AND definition.semantic_key=?2 AND definition.semantic_role='definition' AND class.metaclass IS NOT NULL")?.query_row(
                rusqlite::params![mount.blob_id(), key], |row| row.get::<_, Option<u32>>(0),
            ).optional()?.map(|reference| reference.map(|key| SemanticId::local(ordinal, key)))
        } else {
            None
        }
    } else {
        None
    };
    if class_object && cached_metaclass.is_none() && metaclass.is_none() {
        half.rules
            .attribute_metaclasses
            .borrow_mut()
            .insert((owner, lookup), ResolutionCompletion::Complete);
    }
    if metaclass == Some(None) {
        let completion =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                owner,
            )]);
        half.rules
            .attribute_metaclasses
            .borrow_mut()
            .insert((owner, lookup), completion.clone());
        dictionary_completion = dictionary_completion.combine(&completion);
    }
    if operations.is_empty() && mutations.is_none() {
        half.rules
            .attribute_mutations
            .borrow_mut()
            .insert((owner, lookup), ResolutionCompletion::Complete);
    }
    if !operations.is_empty() || metaclass.flatten().is_some() {
        attribute_rows.push(PythonMemberRow::AttributeSpace {
            owner,
            metaclass: metaclass.flatten(),
            operations,
        });
    }
    if rows.is_empty() {
        return Ok(Read::Ready {
            value: attribute_rows,
            completion: dictionary_completion,
        });
    }
    let (effects, effects_completion) =
        match operations::owner_rows(half, route.lookup.spelling(), owner)? {
            Read::Ready { value, completion } => (
                std::rc::Rc::<[operations::OperationRow]>::from(value),
                completion,
            ),
            Read::Cancelled(completion) => {
                return Ok(Read::Cancelled(dictionary_completion.combine(&completion)));
            }
            Read::Unavailable { reason, completion } => {
                return Ok(Read::Unavailable {
                    reason,
                    completion: dictionary_completion.combine(&completion),
                });
            }
        };
    dictionary_completion = dictionary_completion.combine(&effects_completion);
    let mut selected = Vec::with_capacity(rows.len());
    for (property, _) in rows {
        if !half.rules.session.scope_step() || half.rules.cancellation.is_cancelled() {
            return Ok(Read::Cancelled(read.evidence().clone()));
        }
        let instance_field = property.kind()
            == brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind::Field
            && property.access()
                == brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberAccess::Instance;
        let definition = property.definition();
        let Some(ordinal) = definition.ordinal() else {
            // The intrinsic inventory may be complete while its callable/body
            // projection is outside this authored-method binding slice.
            for receiver in &receivers {
                if instance_field && !matches!(receiver, ResolutionSlotValue::Runtime { .. }) {
                    continue;
                }
                selected.push(PythonDeclaredMemberRow {
                    property: property.clone(),
                    keyword_parameter: false,
                    provider: provider.clone(),
                    kind: 6,
                    receiver: *receiver,
                    parameter: None,
                    role_inputs: None,
                    operations: std::rc::Rc::clone(&effects),
                    completion: dictionary_completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(definition),
                    ])),
                });
            }
            continue;
        };
        let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
        let metadata = member_role_inputs(half.rules, definition)?;
        let (kind, parameter, site) = metadata
            .as_ref()
            .map(|input| (input.kind, input.parameter, input.site))
            .unwrap_or((6, None, 0));
        // Value properties identify authored writes, not every write to the
        // same dictionary slot. An older initializer must not survive rebinding.
        let missing_runtime_binding = !instance_field
            && reaching
                .as_ref()
                .is_some_and(|events| !events.contains(&Some(site)));
        if missing_runtime_binding && !annotation_only.contains(&site) {
            continue;
        }
        let keyword_parameter = keyword_label
            && property.kind()
                == brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind::Field;
        let mut row_completion = dictionary_completion.clone();
        if missing_runtime_binding && !keyword_parameter {
            let mut digest = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
                b"bifrost-python-missing-runtime-binding:v1",
            );
            digest.field(
                "definition",
                &half.rules.ready.identity_content_digest(
                    ResolutionIdentityDigestKey::Semantic(definition),
                    half.rules.cancellation,
                )?,
            );
            let reason = half.rules.ready.context_identities.named_semantic(
                digest.finish(),
                "missing-runtime-binding",
                "An annotation describes an instance field but supplies no runtime binding",
            );
            row_completion = row_completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(reason),
            ]));
        }
        let parameter = parameter.map(|key| SemanticId::local(ordinal.get(), key));
        for receiver in &receivers {
            if (instance_field || missing_runtime_binding)
                && !keyword_parameter
                && !matches!(receiver, ResolutionSlotValue::Runtime { .. })
            {
                continue;
            }
            selected.push(PythonDeclaredMemberRow {
                property: property.clone(),
                keyword_parameter,
                provider: provider.clone(),
                kind,
                receiver: *receiver,
                parameter,
                role_inputs: metadata.clone(),
                operations: std::rc::Rc::clone(&effects),
                completion: row_completion.clone(),
            });
        }
    }
    Ok(Read::Ready {
        value: selected
            .into_iter()
            .map(|row| PythonMemberRow::Declared(Box::new(row)))
            .chain(attribute_rows)
            .collect(),
        completion: dictionary_completion,
    })
}

impl std::fmt::Debug for PythonMemberContext<'_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PythonMemberAccess")
            .field("reference", &self.reference)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PythonAccessRole {
    Function,
    ClassMethod,
    StaticMethod,
    Property,
    Value,
    Unknown,
}

// Immutable inputs are shared only within this forward query. The existing
// request cache bounds admission and keeps repeated prerequisite polls off SQL.
#[derive(Debug)]
pub(super) struct PythonMemberRoleInputs {
    kind: u32,
    parameter: Option<u32>,
    site: u32,
    owner: u32,
    scope: u32,
    start: usize,
    function: bool,
    decorators: Vec<PythonDecoratorInput>,
}

#[derive(Clone, Copy, Debug)]
enum PythonDecoratorInput {
    Reference(u32),
    PropertyAccessor(Option<u32>),
}

fn member_role_inputs(
    rules: &PythonRules<'_, '_, '_>,
    definition: SemanticId,
) -> Result<Option<std::rc::Rc<PythonMemberRoleInputs>>> {
    let (Some(ordinal), Some(key)) = (definition.ordinal(), definition.local_key()) else {
        return Ok(None);
    };
    let mount = rules
        .ready
        .inventory
        .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    let cache_key = (mount.blob_id(), key);
    if let Some(input) = rules.member_role_rows.borrow().get(&cache_key) {
        return Ok(input.clone());
    }
    let conn = rules.ready.inventory.connection();
    let metadata = conn.prepare_cached(
        "SELECT role.kind,param.semantic_key,role.member,role.owner,site.scope,site.start_byte,role.callable IS NOT NULL
         FROM resolution_semantic_sites semantic
         JOIN python_member_member_roles role ON role.blob_id=semantic.blob_id AND role.member=semantic.source_site
         JOIN python_member_sites site ON site.blob_id=role.blob_id AND site.site=role.member
         LEFT JOIN resolution_semantic_sites param ON param.blob_id=role.blob_id
          AND param.source_site=role.receiver_parameter AND param.semantic_role='definition'
         WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2 AND semantic.semantic_role='definition'"
    )?.query_row(rusqlite::params![mount.blob_id(),key], |row| Ok(PythonMemberRoleInputs {
        kind: row.get(0)?, parameter: row.get(1)?, site: row.get(2)?, owner: row.get(3)?,
        scope: row.get(4)?, start: row.get(5)?, function: row.get(6)?, decorators: Vec::new(),
    })).optional()?;
    let input = if let Some(mut input) = metadata {
        use crate::analyzer::store::python_member_rows::decorator_role_code;
        use brokk_bifrost_core::analyzer::resolution_facts::{
            PythonNativeDecoratorRole, ResolutionSiteKind,
        };
        let value_reference =
            crate::analyzer::store::resolution_prepare::resolution_rows::site_kind_code(
                ResolutionSiteKind::ValueReference,
            );
        input.decorators = conn.prepare_cached(
            "SELECT reference.semantic_key,
                    decorator.role IN (?3,?4,?5) AND receiver.receiver IS NOT NULL,
                    bare.semantic_key
             FROM python_member_decorators decorator
             JOIN resolution_semantic_sites reference ON reference.blob_id=decorator.blob_id
              AND reference.source_site=decorator.expression_site AND reference.semantic_role='reference'
             LEFT JOIN python_member_decorator_receivers receiver ON receiver.blob_id=decorator.blob_id
              AND receiver.declaration=decorator.declaration AND receiver.ordinal=decorator.ordinal
             LEFT JOIN python_member_sites location ON location.blob_id=receiver.blob_id AND location.site=receiver.receiver
             LEFT JOIN resolution_sites syntax ON syntax.blob_id=receiver.blob_id AND syntax.site=receiver.receiver AND syntax.site_kind=?6
             LEFT JOIN resolution_semantic_sites bare ON bare.blob_id=syntax.blob_id AND bare.source_site=syntax.site
              AND bare.semantic_role='reference' AND location.scope=?7
              AND NOT EXISTS(SELECT 1 FROM resolution_qualified_routes qualified WHERE qualified.blob_id=bare.blob_id AND qualified.reference=bare.semantic_key)
             WHERE decorator.blob_id=?1 AND decorator.declaration=?2 ORDER BY decorator.ordinal"
        )?.query_map(rusqlite::params![mount.blob_id(),input.site,
            decorator_role_code(PythonNativeDecoratorRole::PropertyGetter),
            decorator_role_code(PythonNativeDecoratorRole::PropertySetter),
            decorator_role_code(PythonNativeDecoratorRole::PropertyDeleter),value_reference,input.scope], |row| {
                if row.get::<_,bool>(1)? { Ok(PythonDecoratorInput::PropertyAccessor(row.get(2)?)) }
                else { Ok(PythonDecoratorInput::Reference(row.get(0)?)) }
        })?.collect::<std::result::Result<Vec<_>,_>>()?;
        Some(std::rc::Rc::new(input))
    } else {
        None
    };
    assert!(
        rules
            .member_role_rows
            .borrow_mut()
            .insert(cache_key, input.clone())
            .is_none()
    );
    Ok(input)
}

#[derive(Clone, Debug)]
struct DecoratorRoleProof {
    role: PythonAccessRole,
    completion: ResolutionCompletion,
}
#[derive(Debug)]
enum DecoratorRolePoll {
    Reference(DemandReferenceKey),
    Ready(DecoratorRoleProof),
    Cancelled,
}

impl PythonMemberContext<'_, '_, '_> {
    fn decorator_role(
        &self,
        definition: SemanticId,
        inputs: &std::rc::Rc<PythonMemberRoleInputs>,
        replies: &[AccessPrerequisiteReply],
    ) -> Result<DecoratorRolePoll> {
        #[derive(Debug)]
        struct Frame {
            definition: SemanticId,
            inputs: std::rc::Rc<PythonMemberRoleInputs>,
            remaining: usize,
            proof: DecoratorRoleProof,
        }
        let frame = |definition, inputs: std::rc::Rc<PythonMemberRoleInputs>| Frame {
            definition,
            remaining: inputs.decorators.len(),
            proof: DecoratorRoleProof {
                role: if inputs.function {
                    PythonAccessRole::Function
                } else {
                    PythonAccessRole::Value
                },
                completion: ResolutionCompletion::Complete,
            },
            inputs,
        };
        let mut stack = vec![frame(definition, std::rc::Rc::clone(inputs))];
        let mut proven = crate::hash::HashMap::<SemanticId, DecoratorRoleProof>::default();
        while !stack.is_empty() {
            if !self.rules.session.scope_step() || self.rules.cancellation.is_cancelled() {
                return Ok(DecoratorRolePoll::Cancelled);
            }
            let current = stack.last_mut().expect("a role frame is pending");
            let Some(ordinal) = current.remaining.checked_sub(1) else {
                let current = stack.pop().expect("completed role frame");
                if stack.is_empty() {
                    return Ok(DecoratorRolePoll::Ready(current.proof));
                }
                proven.insert(current.definition, current.proof);
                continue;
            };
            // Decorators apply inside out. Only retained structural accessor
            // receivers bypass the ordinary decorator-identity prerequisite.
            let decorator = current.inputs.decorators[ordinal];
            let reference = match decorator {
                PythonDecoratorInput::Reference(reference)
                | PythonDecoratorInput::PropertyAccessor(Some(reference)) => reference,
                PythonDecoratorInput::PropertyAccessor(None) => {
                    current.proof.role = PythonAccessRole::Unknown;
                    current.remaining -= 1;
                    continue;
                }
            };
            let key = DemandReferenceKey {
                reference: SemanticId::local(
                    current.definition.ordinal().expect("source member mount"),
                    reference,
                ),
                environment: self.environment,
            };
            let Some(answer) = replies.iter().find_map(|reply| match reply {
                AccessPrerequisiteReply::Reference {
                    key: answered,
                    answer,
                } if *answered == key => Some(answer),
                _ => None,
            }) else {
                return Ok(DecoratorRolePoll::Reference(key));
            };
            let binding = answer.binding();
            current.proof.completion = current.proof.completion.combine(binding.completion());
            let selected = (binding.completion() == &ResolutionCompletion::Complete
                && binding.targets().len() == 1)
                .then(|| binding.targets()[0]);
            if matches!(decorator, PythonDecoratorInput::PropertyAccessor(_)) {
                let prior = if let Some(target) =
                    selected.filter(|target| target.ordinal() == current.definition.ordinal())
                {
                    member_role_inputs(self.rules, target)?
                        .filter(|prior| {
                            prior.owner == current.inputs.owner
                                && prior.scope == current.inputs.scope
                                && prior.start < current.inputs.start
                        })
                        .map(|input| (target, input))
                } else {
                    None
                };
                let Some((target, input)) = prior else {
                    current.proof.role = PythonAccessRole::Unknown;
                    current.remaining -= 1;
                    continue;
                };
                if let Some(proof) = proven.get(&target) {
                    current.proof.completion = current.proof.completion.combine(&proof.completion);
                    current.proof.role = if proof.role == PythonAccessRole::Property {
                        PythonAccessRole::Property
                    } else {
                        PythonAccessRole::Unknown
                    };
                    current.remaining -= 1;
                } else {
                    stack.push(frame(target, input));
                }
            } else {
                current.proof.role = match (current.proof.role, selected) {
                    (PythonAccessRole::Function, Some(target))
                        if builtin(self.rules.ready, "classmethod") == Some(target) =>
                    {
                        PythonAccessRole::ClassMethod
                    }
                    (PythonAccessRole::Function, Some(target))
                        if builtin(self.rules.ready, "staticmethod") == Some(target) =>
                    {
                        PythonAccessRole::StaticMethod
                    }
                    (PythonAccessRole::Function, Some(target))
                        if builtin(self.rules.ready, "property") == Some(target) =>
                    {
                        PythonAccessRole::Property
                    }
                    _ => PythonAccessRole::Unknown,
                };
                current.remaining -= 1;
            }
        }
        unreachable!("root role frame returns its proof")
    }
}

/// Identities come from the shared language universe, never source spelling.
/// These four entries are common to the full Python-3 interval; M4-2c supplies
/// the versioned table and the ordinary lexical selection of their references.
pub(super) fn builtin(ready: &ReadySelectedResolution<'_, '_>, name: &str) -> Option<SemanticId> {
    use crate::analyzer::resolution::universe;
    universe::lookup(
        crate::analyzer::Language::Python,
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::TypeOrValue,
        name,
    )
    .map(|entry| {
        SemanticId::shared_name(
            ready
                .shared_names()
                .intern(universe::identity_digest(entry)),
        )
    })
}

impl PythonMemberContext<'_, '_, '_> {
    pub fn member_request(
        &self,
        reference: SemanticId,
        values: Vec<ResolutionSlotValue>,
        lookup: SemanticId,
        namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
    ) -> DemandMemberSelectionRequest {
        DemandMemberSelectionRequest {
            policy: &PYTHON_HIERARCHY,
            order: Some(HierarchyOrderRequest {
                policy: &PYTHON_C3,
                start_after: self
                    .super_cursor
                    .filter(|cursor| values.contains(&cursor.receiver))
                    .map(|cursor| cursor.start_after),
            }),
            reference,
            values,
            lookup,
            namespace,
            language: Language::Python,
        }
    }

    pub fn member_target(
        &self,
        lookup: &super::ResolutionLookupSemanticRecipe,
        namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
        row: &PythonMemberRow,
    ) -> Result<Read<Option<SelectedMemberRouteTarget>>> {
        if let PythonMemberRow::Model(row) = row {
            let token = self.rules.model_token(&row.symbol);
            let fragment = self
                .rules
                .ready
                .inventory
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(
                    self.reference.ordinal().expect("selected member reference"),
                ))?
                .fragment_id();
            return Ok(Read::ready(Some(SelectedMemberRouteTarget {
                target: self.rules.model_target(token, lookup, fragment),
                location: RouteLocation::Owner {
                    definition: token,
                    scope: None,
                },
                namespace,
                material: BridgeMaterial::same_language(Language::Python),
            })));
        }
        let PythonMemberRow::Declared(row) = row else {
            return Ok(Read::ready(None));
        };
        let definition = row.property.definition();
        let paths = self.rules.ready.lexical_source();
        let Some(SelectedSemanticProvenance::FragmentLocal(local)) =
            paths.semantic_provenance(definition, self.rules.cancellation)?
        else {
            return Ok(Read::ready(None));
        };
        let Some(node) = paths.lookup_definition_node(definition, self.rules.cancellation)? else {
            return Ok(Read::ready(None));
        };
        Ok(Read::ready(Some(SelectedMemberRouteTarget {
            target: SelectedMemberTarget {
                fragment: local.mount().fragment(),
                token: definition,
                definition: node,
                lookup: lookup.clone(),
                completion: row.completion.clone(),
            },
            location: RouteLocation::Owner {
                definition,
                scope: None,
            },
            namespace,
            material: BridgeMaterial::same_language(Language::Python),
        })))
    }

    fn attribute_mutations(
        &self,
        owner: SemanticId,
        lookup: SemanticId,
        operations: &[operations::OperationRow],
        answers: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<std::ops::ControlFlow<DemandReferenceKey, ResolutionCompletion>> {
        let cached = self
            .rules
            .attribute_mutations
            .borrow()
            .get(&(owner, lookup))
            .cloned();
        self.rules
            .record_dynamic_receiver_scope(self.reference, self.query_obligations)?;
        if let Some(cached) = cached {
            return Ok(std::ops::ControlFlow::Continue(cached));
        }
        let mut completion = ResolutionCompletion::Complete;
        for operation in operations {
            match operations::prove(self.rules, operation, answers)? {
                operations::OperationProof::Reference(key) => {
                    return Ok(std::ops::ControlFlow::Break(key));
                }
                operations::OperationProof::NoEffect | operations::OperationProof::Instance(_) => {}
                operations::OperationProof::Possible {
                    completion: evidence,
                    ..
                } => {
                    completion =
                        completion
                            .combine(&evidence)
                            .combine(&ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(owner),
                            ]));
                }
            }
        }
        self.rules
            .attribute_mutations
            .borrow_mut()
            .insert((owner, lookup), completion.clone());
        Ok(std::ops::ControlFlow::Continue(completion))
    }

    fn attribute_space(
        &self,
        context: &MemberAccessContext<'_>,
        owner: SemanticId,
        metaclass: Option<SemanticId>,
        operations: &[operations::OperationRow],
        input: AccessRowInput<'_>,
    ) -> Result<AccessRowPoll> {
        let replies = match input {
            AccessRowInput::Start => &[][..],
            AccessRowInput::Replies(replies) => replies,
        };
        let answers = operations::replies(AccessRowInput::Replies(replies));
        let mut completion =
            match self.attribute_mutations(owner, context.lookup, operations, &answers)? {
                std::ops::ControlFlow::Break(key) => return Ok(AccessRowPoll::Reference(key)),
                std::ops::ControlFlow::Continue(completion) => completion,
            };
        if let Some(reference) = metaclass {
            if let Some(cached) = self
                .rules
                .attribute_metaclasses
                .borrow()
                .get(&(owner, context.lookup))
            {
                return Ok(AccessRowPoll::Observed(completion.combine(cached)));
            }
            let Some((_, answer)) = answers.iter().find(|(key, _)| key.reference == reference)
            else {
                return Ok(AccessRowPoll::Reference(DemandReferenceKey::caller(
                    reference,
                )));
            };
            let binding = answer.binding();
            completion = completion.combine(answer.completion());
            let [target] = binding.targets() else {
                return Ok(AccessRowPoll::Observed(completion.combine(
                    &ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(owner),
                    ]),
                )));
            };
            let request = self.member_request(
                reference,
                vec![
                    ResolutionSlotValue::type_object(ResolutionTypeRef::new(*target, 0))
                        .constructed_instance(),
                ],
                context.lookup,
                context.namespace,
            );
            let selected = replies.iter().find_map(|reply| match reply {
                AccessPrerequisiteReply::Members {
                    reference,
                    lookup,
                    selection,
                } if *reference == request.reference && *lookup == request.lookup => {
                    Some(selection)
                }
                _ => None,
            });
            let Some(selected) = selected else {
                return Ok(AccessRowPoll::Members(request));
            };
            completion = completion.combine(&selected.completion);
            let object = builtin(self.rules.ready, "object");
            let mut fallback = ResolutionCompletion::Complete;
            let read = self.rules.visit_member_owners(
                &selected.owners,
                &mut FactPageVisitor::new(&mut |page| {
                    for row in page {
                        if !self.rules.session.scope_step()
                            || self.rules.cancellation.is_cancelled()
                        {
                            return Ok(false);
                        }
                        if dynamic_attribute_hook(row.row(), object) {
                            completion = completion.combine(&ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(owner),
                            ]));
                        }
                        if row.row().member_name() == "__getattr__" {
                            fallback = fallback.combine(&ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(owner),
                            ]));
                        }
                    }
                    Ok(true)
                }),
            )?;
            completion = completion.combine(read.evidence());
            if read.is_cancelled() {
                return Ok(AccessRowPoll::Ready(Read::Cancelled(completion)));
            }
            for meta_owner in &selected.owners {
                let cached = self
                    .rules
                    .attribute_mutations
                    .borrow()
                    .get(&(*meta_owner, context.lookup))
                    .cloned();
                let mutations = if let Some(cached) = cached {
                    cached
                } else {
                    let operations = match operations::attribute_rows(
                        self,
                        *meta_owner,
                        &operations::lookup_spelling(self.rules, context.lookup)?,
                    )? {
                        Read::Ready {
                            value,
                            completion: read_completion,
                        } => {
                            completion = completion.combine(&read_completion);
                            value
                        }
                        Read::Cancelled(evidence) => {
                            return Ok(AccessRowPoll::Ready(Read::Cancelled(
                                completion.combine(&evidence),
                            )));
                        }
                        Read::Unavailable {
                            reason,
                            completion: evidence,
                        } => {
                            return Ok(AccessRowPoll::Ready(Read::Unavailable {
                                reason,
                                completion: completion.combine(&evidence),
                            }));
                        }
                    };
                    match self.attribute_mutations(
                        *meta_owner,
                        context.lookup,
                        &operations,
                        &answers,
                    )? {
                        std::ops::ControlFlow::Break(key) => {
                            return Ok(AccessRowPoll::Reference(key));
                        }
                        std::ops::ControlFlow::Continue(completion) => completion,
                    }
                };
                completion = completion.combine(&mutations);
            }
            self.rules
                .attribute_metaclass_fallbacks
                .borrow_mut()
                .insert((owner, context.lookup), fallback);
            self.rules
                .attribute_metaclasses
                .borrow_mut()
                .insert((owner, context.lookup), completion.clone());
        }
        Ok(AccessRowPoll::Observed(completion))
    }
}

impl MemberAccessRules<PythonMemberRow> for PythonMemberContext<'_, '_, '_> {
    fn late_inventory(
        &self,
        context: &MemberAccessContext<'_>,
        owners: &[SemanticId],
        name: SemanticId,
    ) -> Result<Read<Vec<PythonMemberRow>>> {
        let inventory = operations::late_inventory(self, context, owners, name)?;
        let Read::Ready {
            value,
            mut completion,
        } = inventory
        else {
            return Ok(inventory);
        };
        // A class-object miss can invoke its metaclass's fallback hook. The
        // access continuation records that evidence separately from interception.
        for owner in owners {
            if let Some(fallback) = self
                .rules
                .attribute_metaclass_fallbacks
                .borrow()
                .get(&(*owner, context.lookup))
            {
                completion = completion.combine(fallback);
            }
        }
        if !self
            .member_values
            .iter()
            .any(|value| matches!(value, ResolutionSlotValue::Runtime { .. }))
        {
            return Ok(Read::Ready { value, completion });
        }
        let read = self.rules.visit_member_owners(
            owners,
            &mut FactPageVisitor::new(&mut |page| {
                for row in page {
                    if !self.rules.session.scope_step() || self.rules.cancellation.is_cancelled() {
                        return Ok(false);
                    }
                    if row.row().member_name() == "__getattr__" {
                        completion = completion.combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(
                                row.row().owner_definition(),
                            ),
                        ]));
                    }
                }
                Ok(true)
            }),
        )?;
        completion = completion.combine(read.evidence());
        if read.is_cancelled() {
            return Ok(Read::Cancelled(completion));
        }
        Ok(Read::Ready { value, completion })
    }
    fn classify_row(
        &self,
        context: &MemberAccessContext<'_>,
        row: &PythonMemberRow,
        target: Option<&SelectedMemberRouteTarget>,
        input: AccessRowInput<'_>,
    ) -> Result<AccessRowPoll> {
        let row = match row {
            PythonMemberRow::Model(row) => {
                return super::python_models::classify(self, context, row);
            }
            PythonMemberRow::Declared(row) => row,
            PythonMemberRow::Operation(operation) => {
                return operations::classify(self, context, operation, input);
            }
            PythonMemberRow::AttributeSpace {
                owner,
                metaclass,
                operations,
            } => {
                return self.attribute_space(context, *owner, *metaclass, operations, input);
            }
        };
        let replies = match input {
            AccessRowInput::Start => &[][..],
            AccessRowInput::Replies(replies) => replies,
        };
        let mut completion = row.completion.clone();
        if self
            .super_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.receiver.obligation().is_some())
        {
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(self.reference),
            ]));
        }
        // Only the nested class's own creation can open this row: the owner's
        // lookup and the row itself have no gap, and nothing may write the member.
        let creation_is_only_gap = completion == ResolutionCompletion::Complete
            && *context.input_completion == ResolutionCompletion::Complete
            && context.selection.completion == ResolutionCompletion::Complete
            && row.operations.is_empty();
        let mut role = if row.property.kind()
            == brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind::Method
        {
            PythonAccessRole::Function
        } else {
            PythonAccessRole::Value
        };
        let nested_class = row.property.kind()
            == brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind::NestedType
            && is_class(self.rules.ready, row.property.definition())?;
        let mut ordinary_nested_class = false;
        // The reasons of a nested class whose creation is unproven only because
        // unresolved bases leave its metaclass unknown.
        let mut open_order_reasons = None;
        if nested_class {
            // Reuse this access's lookup for the C3 prerequisite. Requesting
            // an allocator would add unrelated intrinsic applicability gaps.
            let request = self.member_request(
                row.property.definition(),
                vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    row.property.definition(),
                    0,
                ))],
                context.lookup,
                context.namespace,
            );
            let selection = replies.iter().find_map(|reply| match reply {
                AccessPrerequisiteReply::Members {
                    reference,
                    lookup,
                    selection,
                } if *reference == request.reference && *lookup == request.lookup => {
                    Some(selection)
                }
                _ => None,
            });
            let Some(selection) = selection else {
                return Ok(AccessRowPoll::Members(request));
            };
            if let Some(order) = selection.order {
                match ordinary_class_creation(
                    self.rules,
                    self.rules.typed,
                    row.property.definition(),
                    context.provenance,
                    Some(order),
                )? {
                    std::ops::ControlFlow::Break(completion) => {
                        return Ok(AccessRowPoll::Ready(Read::Cancelled(completion)));
                    }
                    std::ops::ControlFlow::Continue(ClassCreation::Ordinary(creation)) => {
                        ordinary_nested_class =
                            creation.completion == ResolutionCompletion::Complete;
                        completion = completion.combine(&creation.completion);
                    }
                    std::ops::ControlFlow::Continue(ClassCreation::OpenOrder(bases)) => {
                        open_order_reasons = Some(selection.completion.clone()).filter(|reasons| {
                            *reasons != ResolutionCompletion::Complete
                                && bases.discharge(context.provenance, reasons)
                        });
                    }
                    std::ops::ControlFlow::Continue(ClassCreation::Unproven) => {}
                }
            }
        }
        if !nested_class
            && !row.keyword_parameter
            && let Some(inputs) = &row.role_inputs
        {
            match self.decorator_role(row.property.definition(), inputs, replies)? {
                DecoratorRolePoll::Reference(key) => return Ok(AccessRowPoll::Reference(key)),
                DecoratorRolePoll::Ready(proof) => {
                    role = proof.role;
                    completion = completion.combine(&proof.completion);
                }
                DecoratorRolePoll::Cancelled => {
                    return Ok(AccessRowPoll::Ready(Read::Cancelled(
                        ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
                    )));
                }
            }
        }
        let instance_field = row.property.kind()
            == brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind::Field
            && row.property.access()
                == brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberAccess::Instance;
        let mut binding = match (role, row.receiver, row.parameter) {
            (_, _, _) if row.keyword_parameter => MemberBinding::Unchanged,
            (PythonAccessRole::Value, _, _) if ordinary_nested_class => MemberBinding::Unchanged,
            (PythonAccessRole::Value, ResolutionSlotValue::Runtime { .. }, _) if instance_field => {
                MemberBinding::Unchanged
            }
            (
                PythonAccessRole::Function,
                value @ ResolutionSlotValue::Runtime { .. },
                Some(parameter),
            ) => MemberBinding::Receiver { parameter, value },
            (PythonAccessRole::ClassMethod, value, Some(parameter)) => MemberBinding::Receiver {
                parameter,
                value: ResolutionSlotValue::type_object(value.ty()).inherit_obligation(value),
            },
            (
                PythonAccessRole::Property,
                value @ ResolutionSlotValue::Runtime { .. },
                Some(parameter),
            ) => MemberBinding::Receiver { parameter, value },
            (PythonAccessRole::Function, ResolutionSlotValue::TypeObject(_, _), _)
            | (PythonAccessRole::Property, ResolutionSlotValue::TypeObject(_, _), _)
            | (PythonAccessRole::StaticMethod, _, _) => MemberBinding::Unchanged,
            _ => MemberBinding::Unknown,
        };
        let answers = replies
            .iter()
            .filter_map(|reply| match reply {
                AccessPrerequisiteReply::Reference { key, answer } => Some((*key, answer.as_ref())),
                _ => None,
            })
            .collect::<Vec<_>>();
        for operation in row.operations.iter() {
            for (key, answer) in &answers {
                if Some(key.reference) == operation.receiver
                    || Some(key.reference) == operation.callee
                {
                    completion = completion.combine(answer.completion());
                }
            }
            match operations::prove(self.rules, operation, &answers)? {
                operations::OperationProof::Reference(key) => {
                    return Ok(AccessRowPoll::Reference(key));
                }
                operations::OperationProof::Instance(effect)
                    if matches!(row.receiver, ResolutionSlotValue::Runtime { .. })
                        && role != PythonAccessRole::Property =>
                {
                    // The selected MRO owner can mutate this instance's dictionary,
                    // including when the receiver is an instance of a subclass.
                    // Keep class-dictionary proof independent of instance shadowing.
                    operations::receipt(self.rules, operation, false)?;
                    operations::observe_access(
                        self,
                        context,
                        operation,
                        row.property.owner_definition(),
                        row.property.definition(),
                        &effect,
                    )?;
                    binding = MemberBinding::Unknown;
                    completion = completion.combine(&effect);
                }
                operations::OperationProof::NoEffect | operations::OperationProof::Instance(_) => {}
                operations::OperationProof::Possible {
                    class_object,
                    completion: effect,
                } => {
                    operations::receipt(self.rules, operation, class_object)?;
                    operations::observe_access(
                        self,
                        context,
                        operation,
                        row.property.owner_definition(),
                        row.property.definition(),
                        &effect,
                    )?;
                    completion = completion.combine(&effect);
                    if class_object {
                        binding = MemberBinding::Unknown;
                        completion =
                            completion
                                .combine(&effect)
                                .combine(&ResolutionCompletion::incomplete([
                                    ResolutionIncompleteReason::UnsupportedSemantic(
                                        row.property.definition(),
                                    ),
                                ]));
                    }
                }
            }
        }
        let coverage = vec![row.provider.clone()];
        let unknown_binding_reason =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                row.property.definition(),
            )]);
        if matches!(binding, MemberBinding::Unknown) {
            completion = completion.combine(&unknown_binding_reason);
        }
        // A definition-only reply may report this class when these reasons are
        // the whole answer. The value keeps its Unknown binding and reasons.
        let unproven_creation = open_order_reasons
            .filter(|_| creation_is_only_gap && matches!(binding, MemberBinding::Unknown))
            .map(|reasons| reasons.combine(&unknown_binding_reason));
        let root = row.receiver.ty().identity();
        let member_owner = if let (Some(target), Some(order)) = (target, context.selection.order) {
            let status = context.provenance.order_status(order);
            if status.complete
                && status.required_base.is_none()
                && *status.completion == ResolutionCompletion::Complete
            {
                let mut path = Vec::new();
                let owner = row.property.owner_definition();
                let visited = context.provenance.visit_order(
                    order,
                    &mut || self.rules.cancellation.is_cancelled(),
                    &mut |entry| {
                        if entry.root == root && path.last().copied() != Some(owner) {
                            path.push(entry.owner);
                        }
                        Ok(())
                    },
                )?;
                (visited && path.first() == Some(&root) && path.last() == Some(&owner)).then(|| {
                    let route =
                        crate::analyzer::resolution::fact_resolution::FactMemberOwner::proven_route(
                            target.target.token,
                            row.property.kind(),
                            path.into_boxed_slice(),
                        );
                    match unproven_creation {
                        Some(reasons) => route.with_unproven_class_creation(reasons),
                        None => route,
                    }
                })
            } else {
                None
            }
        } else {
            None
        };
        let key = context
            .selection
            .order
            .map_or(AccessKey::Unknown, |order| AccessKey::Owner {
                order,
                root,
                owner: row.property.owner_definition(),
            });
        self.rules.observations.borrow_mut().push(format!(
            "member candidate={} owner={} role-candidate={} binding={binding:?} exclusion=false",
            authored_name(self.rules.ready, row.property.definition())?,
            authored_name(self.rules.ready, row.property.owner_definition())?,
            row.kind
        ));
        // Python instance lookup prefers data descriptors, then instance
        // fields, then ordinary class dictionary entries. Each category uses
        // the shared MRO ordering within it; class-object rows omit fields.
        let category = if role == PythonAccessRole::Property
            && matches!(row.receiver, ResolutionSlotValue::Runtime { .. })
        {
            0
        } else if instance_field {
            1
        } else {
            2
        };
        Ok(AccessRowPoll::Ready(Read::ready(Box::new(AccessFacts {
            member_owner,
            ordered_range: self.super_cursor.as_ref().and_then(|cursor| {
                context
                    .selection
                    .order
                    .map(|order| super::member_access::AccessOrderedRange {
                        order,
                        root,
                        start_after: cursor.start_after,
                    })
            }),
            alternative: AccessAlternativeId(root),
            group: AccessGroupId(category),
            within_group: Box::new([key]),
            between_groups: Box::new([AccessKey::Fixed(category)]),
            provider: row.provider.clone(),
            occurrence: row.provider.occurrence(),
            binding,
            completion,
            coverage: coverage.into_boxed_slice(),
            witnesses: Box::new([]),
        }))))
    }
}

impl std::fmt::Debug for PythonHalf<'_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.member_context().fmt(f)
    }
}
impl MemberAccessRules<PythonMemberRow> for PythonHalf<'_, '_, '_> {
    fn late_inventory(
        &self,
        context: &MemberAccessContext<'_>,
        owners: &[SemanticId],
        name: SemanticId,
    ) -> Result<Read<Vec<PythonMemberRow>>> {
        self.member_context().late_inventory(context, owners, name)
    }
    fn classify_row(
        &self,
        context: &MemberAccessContext<'_>,
        row: &PythonMemberRow,
        target: Option<&SelectedMemberRouteTarget>,
        input: AccessRowInput<'_>,
    ) -> Result<AccessRowPoll> {
        self.member_context()
            .classify_row(context, row, target, input)
    }
}

fn implicit_authority(
    authority: crate::analyzer::resolution::ImplicitBaseAuthority,
) -> HierarchyProviderAuthority {
    match authority {
        crate::analyzer::resolution::ImplicitBaseAuthority::Selected(row) => {
            HierarchyProviderAuthority::Typed(row)
        }
        crate::analyzer::resolution::ImplicitBaseAuthority::Intrinsic { descriptor } => {
            HierarchyProviderAuthority::Intrinsic { descriptor }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The full path (a C3 order stopped by its budget, or hitting a typed
    // fixed-point cycle, then a nested class reply) has no source construct in
    // the corpus: mutually recursive nested bases, a self base, an alias to a
    // later attribute and an alias cycle all resolve without a cycle reason.
    // The reply's discharge is gated by this predicate on the order's and the
    // selection's reasons.
    #[test]
    fn unresolved_bases_discharge_only_unresolved_base_provenance() {
        let nested = SemanticId::for_test("nested-class");
        let other_class = SemanticId::for_test("other-class");
        let base_field = SemanticId::for_test("rebound-base-field");
        let reference = SemanticId::for_test("base-reference");
        let frontier = SemanticId::for_test("frontier");
        let edge = SemanticId::for_test("edge-reason");
        let foreign_edge = SemanticId::for_test("foreign-edge-reason");
        let cycle = SemanticId::for_test("cycle-reason");
        let node_cycle = SemanticId::for_test("node-cycle-reason");
        let unsupported = ResolutionIncompleteReason::UnsupportedSemantic;
        let bases = UnresolvedBases {
            owners: vec![nested],
            non_class_owners: vec![base_field],
        };
        let services = [
            (
                edge,
                "unresolved-supertype-edge",
                vec![nested, reference, frontier],
            ),
            (
                foreign_edge,
                "unresolved-supertype-edge",
                vec![other_class, reference, frontier],
            ),
            (cycle, "typed-fixed-point-cycle", vec![nested]),
            (
                node_cycle,
                "typed-fixed-point-node-obligation-cycle",
                vec![nested],
            ),
        ];
        crate::analyzer::resolution::fact_resolution::with_service_reasons_view_for_test(
            &services,
            |provenance| {
                let discharges = |reasons: &[ResolutionIncompleteReason]| {
                    bases.discharge(
                        provenance,
                        &ResolutionCompletion::incomplete(reasons.iter().copied()),
                    )
                };
                assert!(bases.discharge(provenance, &ResolutionCompletion::Complete));
                // The positive cases: an unresolved edge with its base
                // reference residual, and a non-class owner.
                assert!(discharges(&[unsupported(edge), unsupported(reference)]));
                assert!(discharges(&[unsupported(base_field)]));
                // The reference residual alone has no unresolved edge naming it.
                assert!(!discharges(&[unsupported(reference)]));
                // An edge of a class outside the order, a class owner and a
                // cycle are other provenance.
                assert!(!discharges(&[unsupported(foreign_edge)]));
                assert!(!discharges(&[unsupported(edge), unsupported(other_class)]));
                for open in [cycle, node_cycle] {
                    assert!(
                        !discharges(&[unsupported(edge), unsupported(open)]),
                        "{open:?} must keep the reply open"
                    );
                }
                for other in [
                    ResolutionIncompleteReason::ReceiverBudgetExhausted(nested),
                    ResolutionIncompleteReason::TimeBudgetExceeded(nested),
                    ResolutionIncompleteReason::Cancelled,
                ] {
                    assert!(
                        !discharges(&[unsupported(edge), other]),
                        "{other:?} must keep the reply open"
                    );
                }
            },
        );
    }
}
