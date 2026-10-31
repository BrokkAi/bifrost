//! Python supplies collection and C3 rules; shared cursors own every walk.
#![allow(dead_code)] // Dormant until the member source rules opt into these policies.
pub(super) mod operations;
use crate::CancellationToken;
use crate::analyzer::Language;
use crate::analyzer::resolution::*;
use crate::analyzer::store::Result;
use std::cmp::Ordering;

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
    provider: HierarchyProviderKey,
    kind: u32,
    receiver: ResolutionSlotValue,
    parameter: Option<SemanticId>,
    decorators: Vec<DemandReferenceKey>,
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
    let name = ready.inventory.connection().query_row(
        "SELECT slot.name FROM resolution_semantic_sites semantic
         JOIN resolution_binding_events event ON event.blob_id=semantic.blob_id AND event.authored=semantic.source_site
         JOIN resolution_binding_slots slot ON slot.blob_id=event.blob_id AND slot.slot=event.slot
         WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2 AND semantic.semantic_role='definition'
         ORDER BY event.event LIMIT 1",
        rusqlite::params![mount.blob_id(), key], |row| row.get::<_, String>(0),
    ).optional()?;
    Ok(name.unwrap_or_else(|| format!("{definition:?}")))
}

pub(super) fn is_class(
    ready: &ReadySelectedResolution<'_, '_>,
    definition: SemanticId,
) -> Result<bool> {
    let (Some(ordinal), Some(key)) = (definition.ordinal(), definition.local_key()) else {
        return Ok(false);
    };
    let mount = ready
        .inventory
        .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    Ok(ready.inventory.connection().query_row(
        "SELECT EXISTS(SELECT 1 FROM resolution_semantic_sites semantic JOIN python_member_classes class ON class.blob_id=semantic.blob_id AND class.class=semantic.source_site WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2 AND semantic.semantic_role='definition')",
        rusqlite::params![mount.blob_id(),key],|row| row.get(0))?)
}

// object implements the ordinary dictionary lookup itself; a source hook can
// supply an undeclared name or replace the value of a declared name (#6509).
fn dynamic_attribute_hook(
    property: &LoweredMemberOwnerProperty,
    object: Option<SemanticId>,
) -> bool {
    property.member_name() == "__getattr__"
        || (property.member_name() == "__getattribute__"
            && Some(property.owner_definition()) != object)
}

pub(super) fn member_rows(
    half: &PythonMemberContext<'_, '_, '_>,
    route: &PythonMemberRoute<'_>,
    owner: SemanticId,
) -> Result<Read<Vec<PythonMemberRow>>> {
    let mut rows = Vec::new();
    let cached_hooks = half.rules.attribute_hooks.borrow().get(&owner).cloned();
    let mut hooks = cached_hooks
        .clone()
        .unwrap_or(ResolutionCompletion::Complete);
    let object = builtin(half.rules.ready, "object");
    let typed = half.rules.ready.typed_source();
    let read = typed.visit_member_owner_pages_for_owners(
        TypedFactRequest::new(&[owner]),
        half.rules.cancellation,
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
    // Every owner in the shared MRO walk contributes even on a dictionary
    // miss. Runtime hooks can supply a missing name or replace a declared one.
    if half
        .member_values
        .iter()
        .any(|value| matches!(value, ResolutionSlotValue::Runtime { .. }))
    {
        dictionary_completion = dictionary_completion.combine(&hooks);
    }
    let mut reaching = None;
    let mut annotation_only = Vec::new();
    if let (Some(ordinal), Some(key)) = (owner.ordinal(), owner.local_key()) {
        let mount = half
            .rules
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let scope:Option<u32>=half.rules.ready.inventory.connection().query_row(
            "SELECT node.source_scope FROM resolution_member_scope_properties scope JOIN resolution_node_catalog node ON node.blob_id=scope.blob_id AND node.local_key=scope.scope_head_node_key WHERE scope.blob_id=?1 AND scope.definition_semantic_key=?2 AND scope.scope_kind='type_body'",rusqlite::params![mount.blob_id(),key],|row|row.get(0)).optional()?.flatten();
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
            half.rules.ready.inventory.connection().query_row(
                "SELECT reference.semantic_key FROM resolution_semantic_sites definition
                 JOIN python_member_classes class ON class.blob_id=definition.blob_id AND class.class=definition.source_site
                 LEFT JOIN resolution_semantic_sites reference ON reference.blob_id=class.blob_id AND reference.source_site=class.metaclass AND reference.semantic_role='reference'
                 WHERE definition.blob_id=?1 AND definition.semantic_key=?2 AND definition.semantic_role='definition' AND class.metaclass IS NOT NULL",
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
        let definition = property.definition();
        let Some(ordinal) = definition.ordinal() else {
            // The intrinsic inventory may be complete while its callable/body
            // projection is outside this authored-method binding slice.
            for receiver in &receivers {
                selected.push(PythonDeclaredMemberRow {
                    property: property.clone(),
                    provider: provider.clone(),
                    kind: 6,
                    receiver: *receiver,
                    parameter: None,
                    decorators: Vec::new(),
                    operations: std::rc::Rc::clone(&effects),
                    completion: dictionary_completion.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(definition),
                    ])),
                });
            }
            continue;
        };
        let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
        let mount = half
            .rules
            .ready
            .inventory
            .mount_record_by_ordinal(ordinal)?;
        let role_key = (
            mount.blob_id(),
            definition.local_key().expect("authored member key"),
        );
        let cached = half.rules.member_role_rows.borrow().get(&role_key).copied();
        let metadata = if let Some(metadata) = cached {
            metadata
        } else {
            let metadata:Option<(u32,Option<u32>,u32)> = half.rules.ready.inventory.connection().query_row(
            "SELECT role.kind,param.semantic_key,role.member FROM resolution_semantic_sites semantic JOIN python_member_member_roles role ON role.blob_id=semantic.blob_id AND role.member=semantic.source_site LEFT JOIN resolution_semantic_sites param ON param.blob_id=role.blob_id AND param.source_site=role.receiver_parameter AND param.semantic_role='definition' WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2 AND semantic.semantic_role='definition'",
            rusqlite::params![mount.blob_id(),definition.local_key().expect("authored member key")],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))) .optional()?;
            assert!(
                half.rules
                    .member_role_rows
                    .borrow_mut()
                    .insert(role_key, metadata)
                    .is_none()
            );
            metadata
        };
        let (kind, parameter, site) = metadata.unwrap_or((6, None, 0));
        // Value properties identify authored writes, not every write to the
        // same dictionary slot. An older initializer must not survive rebinding.
        let missing_runtime_binding = reaching
            .as_ref()
            .is_some_and(|events| !events.contains(&Some(site)));
        if missing_runtime_binding && !annotation_only.contains(&site) {
            continue;
        }
        let mut row_completion = dictionary_completion.clone();
        if missing_runtime_binding {
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
        let decorators = if metadata.is_some() {
            let mut statement=half.rules.ready.inventory.connection().prepare_cached(
                "SELECT reference.semantic_key FROM python_member_decorators decorator JOIN resolution_semantic_sites reference ON reference.blob_id=decorator.blob_id AND reference.source_site=decorator.expression_site AND reference.semantic_role='reference' WHERE decorator.blob_id=?1 AND decorator.declaration=?2 ORDER BY decorator.ordinal")?;
            statement
                .query_map(rusqlite::params![mount.blob_id(), site], |row| {
                    row.get::<_, u32>(0)
                })?
                .map(|row| {
                    row.map(|key| DemandReferenceKey {
                        reference: SemanticId::local(ordinal.get(), key),
                        environment: half.environment,
                    })
                })
                .collect::<std::result::Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        for receiver in &receivers {
            if missing_runtime_binding && !matches!(receiver, ResolutionSlotValue::Runtime { .. }) {
                continue;
            }
            selected.push(PythonDeclaredMemberRow {
                property: property.clone(),
                provider: provider.clone(),
                kind,
                receiver: *receiver,
                parameter,
                decorators: decorators.clone(),
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
            let read = self
                .rules
                .ready
                .typed_source()
                .visit_member_owner_pages_for_owners(
                    TypedFactRequest::new(&selected.owners),
                    self.rules.cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        for row in page {
                            if !self.rules.session.scope_step()
                                || self.rules.cancellation.is_cancelled()
                            {
                                return Ok(false);
                            }
                            if dynamic_attribute_hook(row.row(), object) {
                                completion =
                                    completion.combine(&ResolutionCompletion::incomplete([
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
        operations::late_inventory(self, context, owners, name)
    }
    fn classify_row(
        &self,
        context: &MemberAccessContext<'_>,
        row: &PythonMemberRow,
        _: Option<&SelectedMemberRouteTarget>,
        input: AccessRowInput<'_>,
    ) -> Result<AccessRowPoll> {
        let row = match row {
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
        let mut role = if row.property.kind()
            == brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind::Method
        {
            PythonAccessRole::Function
        } else {
            PythonAccessRole::Value
        };
        // Decorators apply inside out. Consult accumulated replies before every
        // yield, including two syntactic sites that share one demand key.
        for key in row.decorators.iter().rev() {
            let reply = replies.iter().find_map(|reply| match reply {
                AccessPrerequisiteReply::Reference {
                    key: answered,
                    answer,
                } if key == answered => Some(answer),
                _ => None,
            });
            let Some(answer) = reply else {
                return Ok(AccessRowPoll::Reference(*key));
            };
            let binding = answer.binding();
            completion = completion.combine(binding.completion());
            let selected = if binding.completion() == &ResolutionCompletion::Complete
                && binding.targets().len() == 1
            {
                Some(binding.targets()[0])
            } else {
                None
            };
            role = match (role, selected) {
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
        }
        let mut binding = match (role, row.receiver, row.parameter) {
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
                operations::OperationProof::NoEffect | operations::OperationProof::Instance(_) => {}
                operations::OperationProof::Possible {
                    class_object,
                    completion: effect,
                } => {
                    operations::receipt(self.rules, operation, class_object);
                    operations::observe_access(
                        self,
                        context,
                        operation,
                        row.property.owner_definition(),
                        row.property.definition(),
                        &effect,
                    );
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
        if matches!(binding, MemberBinding::Unknown) {
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(row.property.definition()),
            ]));
        }
        let root = row.receiver.ty().identity();
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
        Ok(AccessRowPoll::Ready(Read::ready(Box::new(AccessFacts {
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
            group: AccessGroupId(0),
            within_group: Box::new([key]),
            between_groups: Box::new([AccessKey::Fixed(
                if role == PythonAccessRole::Property
                    && matches!(row.receiver, ResolutionSlotValue::Runtime { .. })
                {
                    0
                } else {
                    2
                },
            )]),
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
