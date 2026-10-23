//! Dormant Python source rules. Environment containers describe imports; they
//! never become lexical parents or merge the globals of namespace portions.
pub(super) mod super_context;

use super::demand_closure::*;
use super::python_lexical::{self, PythonBindingProfile, PythonBindingProofs, PythonLexical};
use super::*;
use crate::analyzer::resolution::temporal_binding::{SessionBudget, Stop};
use crate::analyzer::resolution::{DemandReferenceKey, EndpointSignature};
use crate::analyzer::store::python_binding_rows::{BindingEvent, PythonBindingRows};

/// Survivors receive a cohort only after temporal reduction. Origin and source
/// byte position are deliberately absent from the ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PythonRank {
    pub cohort: u32,
}

/// A selected environment's identity is request-owned. The caller validates its
/// snapshot, profile and output digest before constructing the rules.
pub(super) struct PythonRules<'a, 'store, 'input> {
    pub ready: &'a ReadySelectedResolution<'store, 'input>,
    pub summary: i64,
    pub profile: PythonBindingProfile,
    /// Declared minimum Python version, not an exact interpreter version. None means undeclared.
    pub python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
    pub cancellation: &'a CancellationToken,
    pub session: &'a ResolutionSession,
    pub observations: &'a RefCell<Vec<String>>,
    arena: &'a RefCell<ClosedRelations>,
    // One suspended source close owns these inputs. Remove them at publication;
    // rebuilding its borrowed Half view must perform no context/prefix SQL.
    source_inputs: RefCell<HashMap<CandidatePathIdentity, PythonHalfInputs>>,
    qualified_members: HashMap<
        crate::analyzer::resolution::QualifiedMemberId,
        super::member_access::QualifiedMemberSlot<
            PythonQualifiedInputs,
            super::python_members::PythonMemberRow,
        >,
    >,
    prepared_references: RefCell<HashMap<CandidatePathIdentity, SemanticId>>,
    universe_mutations: RefCell<HashMap<CandidatePathIdentity, UniverseMutationInputs>>,
}

/// One source closure's selected mutation candidates. The shared prefix pump
/// supplies every Reference answer; publication drops this inventory.
struct UniverseMutationInputs {
    operations: Vec<super::python_members::operations::OperationRow>,
    completion: ResolutionCompletion,
}

/// Owned data for one suspended typed group. The rules borrow it only while
/// polling; no context borrows its containing provider.
struct PythonQualifiedInputs {
    rows: PythonBindingRows,
    blob: i64,
    lookup: ResolutionLookupSemanticRecipe,
    values: Vec<ResolutionSlotValue>,
    super_context: Option<super_context::SuperContext>,
    references: super::member_access::QualifiedReferenceInputs,
    super_cursor: Option<super_context::SuperCursor>,
    observations: RefCell<Vec<crate::analyzer::resolution::HierarchyProviderObservation>>,
    rendered_order: std::cell::Cell<bool>,
}
impl PythonQualifiedInputs {
    fn view<'a, 'store, 'input>(
        &'a self,
        rules: &'a PythonRules<'a, 'store, 'input>,
        reference: DemandReferenceKey,
    ) -> super::python_members::PythonMemberContext<'a, 'store, 'input> {
        super::python_members::PythonMemberContext {
            rules,
            reference: reference.reference,
            environment: reference.environment,
            rows: &self.rows,
            blob: self.blob,
            member_values: &self.values,
            super_cursor: self.super_cursor.as_ref(),
            member_observations: &self.observations,
            rendered_order: &self.rendered_order,
        }
    }
}

impl crate::analyzer::resolution::QualifiedMemberProvider for PythonRules<'_, '_, '_> {
    fn poll_construction(
        &mut self,
        input: &crate::analyzer::resolution::TypedConstructionInput,
        provenance: crate::analyzer::resolution::HierarchyProvenanceView<'_>,
        resume: crate::analyzer::resolution::CloseResume<'_>,
    ) -> Result<crate::analyzer::resolution::CloseProgress<Option<ResolutionSlotValue>>> {
        use crate::analyzer::resolution::{
            ClassCreationKind, CloseContinuationId, CloseProgress, CloseResume,
            HierarchyOrderRequest, ResolutionTypeRef, SelectedTypedFactSource, SharedNameInterner,
            TypedFactRequest,
        };
        assert_eq!(input.language, Language::Python);
        crate::profiling::note_with(|| {
            format!(
                "resolution::python_construction reference={:?} targets={:?} complete={}",
                input.reference,
                input.binding.targets(),
                input.binding.completion() == &ResolutionCompletion::Complete,
            )
        });
        let [target] = input.binding.targets() else {
            return Ok(CloseProgress::Ready(None));
        };
        if !super::python_members::is_class(self.ready, *target)? {
            return Ok(CloseProgress::Ready(None));
        }
        let lookup = ResolutionLookupSemanticRecipe::new(
            Language::Python,
            ResolutionNamespace::Value,
            "__new__",
        )
        .semantic(&self.ready.shared_names());
        match resume {
            CloseResume::Start => Ok(CloseProgress::Members {
                continuation: CloseContinuationId::issue(provenance),
                request: crate::analyzer::resolution::DemandMemberSelectionRequest {
                    policy: &super::python_members::PYTHON_HIERARCHY,
                    order: Some(HierarchyOrderRequest {
                        policy: &super::python_members::PYTHON_C3,
                        start_after: None,
                    }),
                    reference: input.reference.reference,
                    values: vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                        *target, 0,
                    ))],
                    lookup,
                    namespace: ResolutionNamespace::Value,
                    language: Language::Python,
                },
                completion: input.binding.completion().clone(),
            }),
            CloseResume::Reference { .. } => {
                unreachable!("construction requests its shared C3 proof")
            }
            CloseResume::Members {
                continuation,
                selection,
            } => {
                continuation.assert_current(provenance);
                let Some(order) = selection.order else {
                    return Ok(CloseProgress::Ready(None));
                };
                crate::profiling::note_with(|| {
                    format!(
                        "resolution::python_construction_order target={target:?} complete={} owners={:?}",
                        provenance.order_status(order).complete,
                        selection.owners,
                    )
                });
                if !provenance.order_status(order).complete {
                    return Ok(CloseProgress::Ready(None));
                }
                let Some(object) = super::python_members::builtin(self.ready, "object") else {
                    return Ok(CloseProgress::Ready(None));
                };
                // Default class creation uses the language's intrinsic type;
                // a source binding with that spelling cannot replace it.
                if super::python_members::builtin(self.ready, "type").is_none() {
                    return Ok(CloseProgress::Ready(None));
                }
                let typed = self.ready.typed_source().with_implicit_environment(
                    self.summary,
                    self.python_version
                        .map(|version| (version.major, version.minor)),
                );
                let mut owners = Vec::new();
                let mut budget_stopped = false;
                if !provenance.visit_order(
                    order,
                    &mut || self.cancellation.is_cancelled(),
                    &mut |entry| {
                        if !self.session.scope_step() {
                            budget_stopped = true;
                            return Ok(());
                        }
                        owners.push(entry.owner);
                        Ok(())
                    },
                )? || budget_stopped
                    || self.cancellation.is_cancelled()
                    || !self.session.observe_cancellation()
                {
                    return Ok(CloseProgress::Cancelled(cancelled_completion()));
                }
                owners.sort_unstable();
                owners.dedup();
                if !owners.contains(&object) || !owners.contains(target) {
                    return Ok(CloseProgress::Ready(None));
                }
                for &owner in &owners {
                    if owner == object {
                        continue;
                    }
                    if !self.session.scope_step() || self.cancellation.is_cancelled() {
                        return Ok(CloseProgress::Cancelled(cancelled_completion()));
                    }
                    let Some(header) = typed.implicit_base_inputs(owner, self.cancellation)? else {
                        return Ok(CloseProgress::Ready(None));
                    };
                    crate::profiling::note_with(|| {
                        format!(
                            "resolution::python_construction_header owner={owner:?} creation={:?} complete={:?} inventory={}",
                            header.creation, header.completion, header.written_inventory_complete,
                        )
                    });
                    if header.creation != ClassCreationKind::Ordinary
                        || !header.written_inventory_complete
                        || header.completion != ResolutionCompletion::Complete
                    {
                        // Expanded bases, replacement decorators and any
                        // unproved metaclass remain explicit open construction.
                        return Ok(CloseProgress::Ready(None));
                    }
                }
                let Some(inventory) =
                    typed.intrinsic_member_inventory(object, self.cancellation)?
                else {
                    return Ok(CloseProgress::Ready(None));
                };
                let digest = self
                    .ready
                    .shared_names()
                    .digest_for_id(lookup.shared_name_id().expect("intrinsic lookup"))
                    .expect("selected intrinsic lookup digest");
                if inventory.presence(digest, ResolutionNamespace::Value)
                    != crate::analyzer::resolution::universe::IntrinsicMemberPresence::Present
                {
                    return Ok(CloseProgress::Ready(None));
                }
                let mut custom_allocator = false;
                for owners in
                    owners.chunks(crate::analyzer::resolution::MAX_TYPED_FACT_REQUESTS_PER_BATCH)
                {
                    let read = typed.visit_member_owner_pages_for_owners(
                        TypedFactRequest::new(owners),
                        self.cancellation,
                        &mut FactPageVisitor::new(&mut |page| {
                            for property in page {
                                if !self.session.scope_step() || self.cancellation.is_cancelled() {
                                    return Ok(false);
                                }
                                custom_allocator |= property.row().member_name() == "__new__"
                                    && property.row().owner_definition() != object;
                            }
                            Ok(true)
                        }),
                    )?;
                    if read.is_cancelled() || self.cancellation.is_cancelled() {
                        return Ok(CloseProgress::Cancelled(read.evidence().clone()));
                    }
                    if custom_allocator
                        || !read.is_exhausted()
                        || read.evidence() != &ResolutionCompletion::Complete
                    {
                        return Ok(CloseProgress::Ready(None));
                    }
                }
                Ok(CloseProgress::Ready(Some(
                    ResolutionSlotValue::type_object(ResolutionTypeRef::new(*target, 0))
                        .constructed_instance(),
                )))
            }
        }
    }

    fn prepare_qualified_member(
        &mut self,
        id: crate::analyzer::resolution::QualifiedMemberId,
        input: &crate::analyzer::resolution::QualifiedMemberInput,
        provenance: crate::analyzer::resolution::HierarchyProvenanceView<'_>,
        resume: crate::analyzer::resolution::CloseResume<'_>,
    ) -> Result<
        crate::analyzer::resolution::CloseProgress<
            crate::analyzer::resolution::DemandMemberSelectionOutcome,
        >,
    > {
        use crate::analyzer::resolution::{
            CloseProgress, CloseResume, DemandMemberSelectionOutcome as Outcome,
        };
        if matches!(resume, CloseResume::Start) {
            assert_eq!(input.registration.language, Language::Python);
            assert!(input.registration.member_access);
            assert!(!self.qualified_members.contains_key(&id));
            let mount = self.ready.inventory.mount_record_by_ordinal(
                SelectedResolutionMountOrdinal::new(input.fragment.ordinal()),
            )?;
            let Some(rows) = PythonBindingRows::load(
                self.ready.inventory.connection(),
                mount.blob_id(),
                self.cancellation,
            )?
            else {
                return Ok(CloseProgress::Cancelled(cancelled_completion()));
            };
            let SelectedLookupRecipeReadOutcome::Ready(recipes) =
                self.ready.lexical_source().lookup_semantic_recipes(
                    &[SelectedLookupRecipeRequest {
                        fragment: input.fragment,
                        semantic: input.source_lookup,
                    }],
                    self.cancellation,
                    None,
                )?
            else {
                return Ok(CloseProgress::Cancelled(cancelled_completion()));
            };
            let lookup = recipes.into_iter().next().flatten().ok_or_else(|| {
                StoreError::corrupt("typed Python member lacks its selected lookup recipe")
            })?;
            let super_context = super_context::SuperContext::read(self, input.reference.reference)?;
            let references = super::member_access::QualifiedReferenceInputs::new(
                super_context
                    .iter()
                    .flat_map(|context| context.prerequisites())
                    .map(|reference| DemandReferenceKey {
                        reference,
                        environment: input.reference.environment,
                    }),
            );
            let context = PythonQualifiedInputs {
                rows,
                blob: mount.blob_id(),
                lookup,
                values: input.values.clone(),
                super_context,
                references,
                super_cursor: None,
                observations: RefCell::new(Vec::new()),
                rendered_order: std::cell::Cell::new(false),
            };
            // Application projections use a Callable query route, but Python
            // selects the callable from its existing Value binding. Normalize
            // only this query-local member input; published reference and route
            // identities retain their original namespaces.
            let mut member_input = input.clone();
            if member_input.namespace == ResolutionNamespace::Callable {
                assert_eq!(context.lookup.namespace, ResolutionNamespace::Value);
                member_input.namespace = ResolutionNamespace::Value;
                member_input.lookup = context.lookup.semantic(&self.ready.shared_names());
            }
            self.qualified_members.insert(
                id,
                super::member_access::QualifiedMemberSlot::new(context, member_input),
            );
        }
        let mut slot = self
            .qualified_members
            .remove(&id)
            .expect("prepared typed Python slot");
        let progress =
            slot.context
                .references
                .poll(provenance, resume, self.session, self.cancellation)?;
        let completion = slot.context.references.completion.clone();
        let result = match progress {
            CloseProgress::Reference {
                continuation,
                key,
                completion,
            } => CloseProgress::Reference {
                continuation,
                key,
                completion,
            },
            CloseProgress::Cancelled(completion) => CloseProgress::Cancelled(completion),
            CloseProgress::Members { .. } => {
                unreachable!("reference inventory requests no members")
            }
            CloseProgress::Ready(()) => {
                if let Some(context) = &slot.context.super_context {
                    slot.context.super_cursor = context
                        .selected(self, &slot.context.references.answers().collect::<Vec<_>>())?;
                    if let Some(cursor) = &slot.context.super_cursor {
                        slot.context.values = vec![cursor.receiver];
                    }
                    // Every call has a retained possible-super context. If its
                    // callee is not proven builtin super, keep the real typed
                    // call-result values rather than treating it as a failed
                    // proxy. Unknown calls still have no invented receiver.
                }
                if slot.context.values.is_empty() {
                    CloseProgress::Ready(Outcome::Unavailable(
                        completion.combine(&open(input.reference.reference)),
                    ))
                } else {
                    CloseProgress::Ready(Outcome::Ready {
                        request: Some(slot.context.view(self, input.reference).member_request(
                            input.reference.reference,
                            slot.context.values.clone(),
                            slot.access.input.lookup,
                            slot.access.input.namespace,
                        )),
                        completion,
                    })
                }
            }
        };
        self.qualified_members.insert(id, slot);
        Ok(result)
    }
    fn poll_qualified_member(
        &mut self,
        id: crate::analyzer::resolution::QualifiedMemberId,
        selection: &crate::analyzer::resolution::DemandMemberSelection,
        provenance: crate::analyzer::resolution::HierarchyProvenanceView<'_>,
        resume: crate::analyzer::resolution::CloseResume<'_>,
    ) -> Result<
        crate::analyzer::resolution::CloseProgress<Read<super::member_access::MemberAccessResult>>,
    > {
        let mut slot = self
            .qualified_members
            .remove(&id)
            .expect("prepared typed Python slot");
        let input = &slot.access.input;
        let context = slot.context.view(self, input.reference);
        let route = super::python_members::PythonMemberRoute {
            lookup: &slot.context.lookup,
            namespace: input.namespace,
            step: input.route_ordinal,
            selection,
            provenance,
        };
        let progress = slot.access.poll(
            id,
            selection,
            provenance,
            resume,
            self.session,
            self.cancellation,
            &context,
            |owner| super::python_members::member_rows(&context, &route, owner),
            |row| context.member_target(route.lookup, route.namespace, row),
            || {
                Ok(Read::ready(std::mem::take(
                    &mut *slot.context.observations.borrow_mut(),
                )))
            },
        )?;
        self.qualified_members.insert(id, slot);
        Ok(progress)
    }
    fn cancel_qualified_member(&mut self, id: crate::analyzer::resolution::QualifiedMemberId) {
        self.qualified_members.remove(&id);
    }
}

pub(super) struct PythonPlacement {
    container: String,
    universe: std::cell::Cell<Option<crate::analyzer::resolution::UniverseEntry>>,
    lexical: RefCell<Option<PythonLexical>>,
    stars: RefCell<HashMap<u32, Vec<(RouteLocation, ResolutionLookupSemanticRecipe)>>>,
}

#[derive(Clone)]
pub(super) struct PythonTarget {
    location: RouteLocation,
    rank: Option<PythonRank>,
    scope: Option<ResolutionScopeId>,
}

pub(super) struct PythonHalf<'a, 'store, 'input> {
    pub(super) rules: &'a PythonRules<'a, 'store, 'input>,
    pub(super) source: &'a SourceHalf,
    placements: Vec<PythonPlacement>,
    import_site: Option<u32>,
    import_name: Option<String>,
    pub(super) rows: std::rc::Rc<PythonBindingRows>,
    fragment: BindingFragmentId,
    pub(super) blob: i64,
    reference_site: Option<u32>,
    universe_unmutated: bool,
    completion: ResolutionCompletion,
    stopped: std::cell::Cell<bool>,
    pub(super) member_observations:
        RefCell<Vec<crate::analyzer::resolution::HierarchyProviderObservation>>,
    pub(super) rendered_order: std::rc::Rc<std::cell::Cell<bool>>,
}

struct PythonHalfInputs {
    containers: Vec<String>,
    import_site: Option<u32>,
    import_name: Option<String>,
    rows: std::rc::Rc<PythonBindingRows>,
    fragment: BindingFragmentId,
    blob: i64,
    reference_site: Option<u32>,
    universe_unmutated: bool,
    rendered_order: std::rc::Rc<std::cell::Cell<bool>>,
}
impl PythonHalfInputs {
    fn view<'a, 'store, 'input>(
        &self,
        rules: &'a PythonRules<'a, 'store, 'input>,
        source: &'a SourceHalf,
        completion: ResolutionCompletion,
    ) -> PythonHalf<'a, 'store, 'input> {
        PythonHalf {
            rules,
            source,
            placements: self
                .containers
                .iter()
                .map(|container| PythonPlacement {
                    container: container.clone(),
                    lexical: RefCell::new(None),
                    stars: RefCell::new(HashMap::default()),
                    universe: std::cell::Cell::new(None),
                })
                .collect(),
            import_site: self.import_site,
            import_name: self.import_name.clone(),
            rows: std::rc::Rc::clone(&self.rows),
            fragment: self.fragment,
            blob: self.blob,
            reference_site: self.reference_site,
            universe_unmutated: self.universe_unmutated,
            completion,
            stopped: std::cell::Cell::new(false),
            member_observations: RefCell::new(Vec::new()),
            rendered_order: std::rc::Rc::clone(&self.rendered_order),
        }
    }
}

fn open(semantic: SemanticId) -> ResolutionCompletion {
    ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(semantic)])
}

impl<'a, 'store, 'input> DemandRules for PythonRules<'a, 'store, 'input> {
    fn qualified_members(&mut self) -> Option<QualifiedMembers<'_>> {
        Some(QualifiedMembers(self))
    }

    type Placement = PythonPlacement;
    type Target = PythonTarget;
    type Member = ();
    type Provider = ();
    type MemberRow = super::python_members::PythonMemberRow;
    type PlacementObservations = CollectedPlacementObservations;
    type Rank = PythonRank;
    type Half<'b>
        = PythonHalf<'b, 'store, 'input>
    where
        Self: 'b;
    type PreparationKey = ();
    type Certificate = ();

    fn admit_endpoint(
        &mut self,
        endpoint: &EndpointSignature,
        already_published: bool,
    ) -> Result<Read<EndpointAdmission>> {
        if already_published {
            return Ok(Read::ready(EndpointAdmission::Ready(
                ResolutionCompletion::Complete,
            )));
        }
        if endpoint.node() != BindingNodeId::universal_root()
            && endpoint.symbols().fixed().is_empty()
        {
            return Ok(Read::ready(EndpointAdmission::Ready(
                ResolutionCompletion::Complete,
            )));
        }
        if endpoint.node() != BindingNodeId::universal_root() {
            let completion = endpoint
                .symbols()
                .fixed()
                .first()
                .map_or(ResolutionCompletion::Complete, |symbol| {
                    open(symbol.symbol())
                });
            return Ok(Read::ready(EndpointAdmission::Context(
                Admission::BaseOwned {
                    completion,
                    base: BaseEligibility::Exclude,
                },
            )));
        }
        let selected = self
            .arena
            .borrow()
            .selected_universe_continuation_completion(endpoint);
        if self.cancellation.is_cancelled() || !self.session.observe_cancellation() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        if let Some(completion) = selected {
            return Ok(Read::ready(EndpointAdmission::Context(
                Admission::BaseOwned {
                    completion,
                    base: BaseEligibility::Exclude,
                },
            )));
        }
        Ok(Read::ready(EndpointAdmission::Discover))
    }
    fn describe_source(
        &mut self,
        endpoint: &EndpointSignature,
        source: Option<super::source_demand::SourceDemandKey>,
        halves: Vec<SelectedRootPathHalf>,
        completion: ResolutionCompletion,
    ) -> Result<Read<Admission>> {
        let Some(source) = source else {
            return Ok(Read::Unavailable {
                reason: crate::analyzer::resolution::DemandRootUnavailableReason::MissingSourceProvenance,
                completion,
            });
        };
        let mut frame = RootFrame::positioned(endpoint, source, halves);
        frame.context = Some(ContextId(0));
        frame.completion = completion;
        Ok(Read::ready(Admission::SourceOwned(frame)))
    }
    fn derive_context(
        &mut self,
        key: ContextId,
        _: &RootFrame,
    ) -> Result<Read<Option<SelectedResolutionContextSet>>> {
        assert_eq!(key, ContextId(0));
        if self.cancellation.is_cancelled() || !self.session.observe_cancellation() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        Ok(Read::ready(None))
    }
    fn resolve_prefix_operands(
        &mut self,
        frame: &mut RootFrame,
        _: Option<&SelectedResolutionContextSet>,
    ) -> Result<Read<Vec<ResolvedPrefixOperand>>> {
        for half in &frame.halves {
            let SelectedRootPathHalf::Reference {
                identity,
                source_reference,
                ..
            } = half
            else {
                continue;
            };
            let cached = self.prepared_references.borrow().get(identity).copied();
            let reference = if let Some(reference) = cached {
                reference
            } else {
                if self.cancellation.is_cancelled() || !self.session.scope_step() {
                    return Ok(Read::Cancelled(cancelled_completion()));
                }
                // The route token names a root continuation. Its source node
                // supplies the canonical reference used by typed input rows.
                let classified = self
                    .ready
                    .lexical_source()
                    .classify_endpoint_nodes(&[*source_reference], self.cancellation)?;
                if self.cancellation.is_cancelled() {
                    return Ok(Read::Cancelled(cancelled_completion()));
                }
                let [classification] = classified.as_slice() else {
                    panic!("one selected source node has one classification: {classified:?}");
                };
                assert_eq!(classification.node(), *source_reference);
                let reference = classification
                    .reference()
                    .expect("a source-reference half starts at a reference node");
                assert!(
                    self.prepared_references
                        .borrow_mut()
                        .insert(*identity, reference)
                        .is_none()
                );
                reference
            };
            if !self.universe_mutations.borrow().contains_key(identity) {
                let ordinal = reference.ordinal().expect("source reference mount");
                let mount = self
                    .ready
                    .inventory
                    .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                let spelling: Option<(String, u32)> = self
                    .ready
                    .inventory
                    .connection()
                    .query_row(
                        crate::analyzer::store::python_member_rows::UNIVERSE_REFERENCE_NAME_SQL,
                        rusqlite::params![mount.blob_id(), reference.local_key()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let read = if let Some((spelling, site)) = spelling.filter(|(spelling, _)| {
                    brokk_bifrost_python::intrinsics::builtin(spelling).is_some()
                }) {
                    let Some(rows) = PythonBindingRows::load(
                        self.ready.inventory.connection(),
                        mount.blob_id(),
                        self.cancellation,
                    )?
                    else {
                        return Ok(if self.cancellation.is_cancelled() {
                            Read::Cancelled(cancelled_completion())
                        } else {
                            Read::Unavailable {
                                reason: crate::analyzer::resolution::DemandRootUnavailableReason::MissingSourceProvenance,
                                completion: open(reference),
                            }
                        });
                    };
                    // Builtins-module effects cannot replace a lexical binding.
                    // Use the existing shared lexical selector before installing
                    // universe-only waits: an unanswered receiver must never
                    // prevent that binding from being selected at all (#6384).
                    let mut lexical = python_lexical::lexical_selection(
                        &rows,
                        site,
                        &spelling,
                        self.profile,
                        PythonBindingProofs::default(),
                    );
                    if let Some(state) = &mut lexical {
                        python_lexical::select_lexical(
                            state,
                            &rows,
                            &mut SessionBudget {
                                session: self.session,
                                cancellation: self.cancellation,
                            },
                            self.cancellation,
                        )?;
                    }
                    if lexical
                        .as_ref()
                        .is_some_and(|state| !state.selection.selected.is_empty())
                    {
                        self.observations.borrow_mut().push(format!(
                            "universe lexical-hit name={spelling:?} retained=true"
                        ));
                        Read::ready(Vec::new())
                    } else {
                        super::python_members::operations::universe_rows(
                            self, reference, &spelling,
                        )?
                    }
                } else {
                    Read::ready(Vec::new())
                };
                match read {
                    Read::Ready { value, completion } => {
                        self.universe_mutations.borrow_mut().insert(
                            *identity,
                            UniverseMutationInputs {
                                operations: value,
                                completion,
                            },
                        );
                    }
                    Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                    Read::Unavailable { reason, completion } => {
                        return Ok(Read::Unavailable { reason, completion });
                    }
                }
            }
        }
        Ok(Read::ready(Vec::new()))
    }
    fn prefix_operands(&self, frame: &RootFrame, caller: EnvironmentId) -> Vec<PrefixOperand> {
        let mut operands = default_prefix_operands(frame, caller);
        for (index, half) in frame.halves.iter().enumerate() {
            let SelectedRootPathHalf::Reference { identity, .. } = half else {
                continue;
            };
            if let Some(mutations) = self.universe_mutations.borrow().get(identity) {
                operands.extend(
                    mutations
                        .operations
                        .iter()
                        .flat_map(|operation| operation.universe_prerequisites())
                        .map(|reference| PrefixOperand {
                            key: DemandReferenceKey {
                                reference,
                                environment: caller,
                            },
                            source_halves: Box::new([HalfId(index)]),
                        }),
                );
            }
        }
        operands
    }
    fn admit_candidate(
        &self,
        frame: &RootFrame,
        cursor: &RouteCursor,
        _: &ExportCandidate,
    ) -> CandidateDecision {
        self.activation(frame, cursor.half)
    }
    fn half_rows<'b>(
        &'b self,
        source: &'b SourceHalf,
        frame: &'b RootFrame,
        _: &'b crate::analyzer::store::resolution_lexical::NodeSourceScopes,
        _: &'b dyn HalfSource,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<Option<Self::Half<'b>>> {
        if let Some(inputs) = self.source_inputs.borrow().get(&source.identity) {
            return Ok(Some(inputs.view(self, source, frame.completion.clone())));
        }
        let Some(mount) = SelectedMountTable::new(&self.ready.inventory)
            .mount_for_fragment(source.identity.fragment())?
        else {
            return Ok(None);
        };
        let blob = self
            .ready
            .inventory
            .mount_record_by_ordinal(mount.ordinal())?
            .blob_id();
        let placements = self.ready.inventory.connection().prepare_cached(
            "SELECT providers.container_path
             FROM main.python_unit_summary_providers providers
             JOIN main.resolution_unit_summary_members members
               ON members.summary_id=providers.summary_id
              AND members.member_ordinal=providers.member_ordinal
             JOIN temp.selected_resolution_mounts mounted
               ON mounted.blob_id=members.blob_id AND mounted.persisted_relative_path=members.rel_path
             WHERE providers.summary_id=?1 AND mounted.mount_ordinal=?2
               AND providers.state IN ('selected','alternative')",
        )?.query_map(rusqlite::params![self.summary, mount.ordinal().get()], |row| {
            Ok(PythonPlacement { container: row.get(0)?, universe: std::cell::Cell::new(None), lexical: RefCell::new(None), stars: RefCell::new(HashMap::default()) })
        })?.collect::<rusqlite::Result<Vec<_>>>()?;
        let import_site = self
            .ready
            .inventory
            .connection()
            .query_row(
                "SELECT import_site FROM main.resolution_root_import_demands
             WHERE blob_id=?1 AND target_reference=(
               SELECT reference_source_site FROM main.resolution_root_route_segments
               WHERE blob_id=?1 AND path_key=?2 AND reference_source_site IS NOT NULL)
             UNION
             SELECT import_source_site FROM main.resolution_semantic_catalog
             WHERE blob_id=?1 AND local_key=?3 AND import_source_site IS NOT NULL",
                rusqlite::params![
                    blob,
                    source.identity.path().local_key(),
                    source.token.local_key()
                ],
                |row| row.get(0),
            )
            .optional()?;
        let import_name = match import_site {
            Some(site) => self.ready.inventory.connection().query_row(
                "SELECT source_name FROM main.resolution_import_selectors WHERE blob_id=?1 AND site=?2",
                rusqlite::params![blob, site],
                |row| row.get::<_, Option<String>>(0),
            ).optional()?.flatten(),
            None => None,
        };
        let Some(rows) =
            PythonBindingRows::load(self.ready.inventory.connection(), blob, self.cancellation)?
        else {
            return Ok(None);
        };
        let reference_site = self.ready.inventory.connection().query_row(
            "SELECT reference_source_site FROM resolution_root_route_segments WHERE blob_id=?1 AND path_key=?2 AND reference_source_site IS NOT NULL
             UNION SELECT source_site FROM resolution_semantic_sites WHERE blob_id=?1 AND semantic_key=?3 AND semantic_role='reference'",
            rusqlite::params![blob, source.identity.path().local_key(), source.token.local_key()], |row| row.get(0),
        ).optional()?;
        assert!(
            source.prefix.is_none(),
            "Python member receivers enter through the typed qualified-member bridge (QualifiedMemberRegistration); a source half never carries a member receiver here"
        );
        let mut universe_unmutated = false;
        if let Some(mutations) = self.universe_mutations.borrow().get(&source.identity) {
            universe_unmutated = mutations.completion == ResolutionCompletion::Complete;
            for operation in &mutations.operations {
                match super::python_members::operations::prove(self, operation, inputs)? {
                    super::python_members::operations::OperationProof::NoEffect => {}
                    super::python_members::operations::OperationProof::Reference(_)
                    | super::python_members::operations::OperationProof::Instance(_)
                    | super::python_members::operations::OperationProof::Possible { .. } => {
                        universe_unmutated = false;
                        super::python_members::operations::receipt(self, operation, false);
                    }
                }
            }
            self.observations.borrow_mut().push(format!(
                "universe inventory unmutated={universe_unmutated} operations={}",
                mutations.operations.len()
            ));
        }
        if universe_unmutated
            && brokk_bifrost_python::intrinsics::builtin(source.demand.spelling()).is_some()
        {
            let origin=crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
                crate::analyzer::resolution::LoweringGapOrigin::Extracted(brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedRoute));
            universe_unmutated = if let Some(site) = reference_site {
                self.ready.inventory.connection().query_row(
                    crate::analyzer::store::python_member_rows::BUILTIN_NAMESPACE_CLOSED_SQL,
                    rusqlite::params![blob, site, origin],
                    |row| row.get(0),
                )?
            } else {
                false
            };
            self.observations.borrow_mut().push(format!(
                "universe lexical-namespace closed={universe_unmutated} statements=1"
            ));
        }
        let prepared = PythonHalfInputs {
            containers: placements
                .into_iter()
                .map(|placement| placement.container)
                .collect(),
            import_site,
            import_name,
            rows: std::rc::Rc::new(rows),
            fragment: mount.fragment(),
            blob,
            reference_site,
            universe_unmutated,
            rendered_order: std::rc::Rc::new(std::cell::Cell::new(false)),
        };
        let view = prepared.view(self, source, frame.completion.clone());
        assert!(
            self.source_inputs
                .borrow_mut()
                .insert(source.identity, prepared)
                .is_none()
        );
        Ok(Some(view))
    }
    fn activation(&self, frame: &RootFrame, half: HalfId) -> CandidateDecision {
        let semantic = match &frame.halves[half.0] {
            SelectedRootPathHalf::Import { token, .. }
            | SelectedRootPathHalf::Reference { token, .. } => *token,
            _ => unreachable!("source admission contains source halves"),
        };
        if matches!(frame.halves[half.0], SelectedRootPathHalf::Import { .. }) {
            CandidateDecision::Open(open(semantic))
        } else {
            CandidateDecision::Open(frame.completion.clone())
        }
    }
    fn closure_policy(
        &self,
        frame: &RootFrame,
        facts: &ClosureFacts<'_>,
    ) -> Result<Read<ClosurePolicy>> {
        for half in &frame.halves {
            match half {
                SelectedRootPathHalf::Reference { identity, .. }
                | SelectedRootPathHalf::Import { identity, .. } => {
                    self.source_inputs.borrow_mut().remove(identity);
                    self.prepared_references.borrow_mut().remove(identity);
                    self.universe_mutations.borrow_mut().remove(identity);
                }
                SelectedRootPathHalf::Export { .. } => unreachable!("source frame"),
            }
        }
        Ok(Read::ready(ClosurePolicy::new(
            ResolutionCompletion::Complete,
            BaseEligibility::Exclude,
            DemandClosureDischarges::default(),
            facts
                .generated
                .iter()
                .map(|(candidate, source)| GeneratedContinuation {
                    candidate: *candidate,
                    source: *source,
                    base: BaseEligibility::Exclude,
                })
                .collect(),
        )))
    }
}

impl PythonHalf<'_, '_, '_> {
    fn authored(&self, fragment: BindingFragmentId, event: &BindingEvent) -> Option<RouteLocation> {
        // Imports select their routed target, never the authored local alias as
        // a substitute for the imported definition. Activation remains open.
        if event.kind
            == brokk_bifrost_core::analyzer::resolution_facts::ResolutionBindingEventKind::Import
        {
            return None;
        }
        event.authored.map(|site| RouteLocation::Owner {
            definition: crate::analyzer::resolution::mounted_site_semantic(
                fragment,
                ResolutionSiteId::new(site),
            ),
            scope: None,
        })
    }
    fn import_starts(
        &self,
        placement: &PythonPlacement,
        site: u32,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Vec<(RouteLocation, Option<ResolutionLookupSemanticRecipe>)>> {
        let destinations = self.rules.ready.inventory.connection().prepare_cached(
            "WITH routes AS (
               SELECT imports.*,NOT EXISTS(SELECT 1 FROM resolution_root_import_segments prefix WHERE prefix.blob_id=?4 AND prefix.import_site=imports.import_site) AS binds_head
               FROM python_unit_summary_imports imports
               WHERE imports.summary_id=?1 AND imports.importer_container=?2 AND imports.import_site=?3
             ) SELECT CASE WHEN routes.form='module' AND routes.binds_head THEN coalesce(binding.container_path,'') ELSE routes.target_container END,routes.form,routes.requested_name
             FROM routes
             LEFT JOIN resolution_import_selectors selector ON selector.blob_id=?4 AND selector.site=routes.import_site
             LEFT JOIN python_unit_summary_providers loaded ON loaded.summary_id=routes.summary_id AND loaded.container_path=routes.target_container
             LEFT JOIN python_unit_summary_providers binding ON routes.form='module' AND routes.binds_head
               AND binding.summary_id=routes.summary_id AND binding.module_name=selector.source_name
               AND binding.root_slot=loaded.root_slot AND binding.state IN ('selected','alternative')",
        )?.query_map(rusqlite::params![self.rules.summary,placement.container,site,self.blob], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(destinations
            .into_iter()
            .map(|(container, form, name)| {
                let head = (form != "module").then(|| {
                    ResolutionLookupSemanticRecipe::new(
                        Language::Python,
                        lookup.namespace(),
                        if form == "star" {
                            lookup.spelling()
                        } else {
                            &name
                        },
                    )
                });
                (
                    RouteLocation::Container {
                        unit: self.rules.summary,
                        container,
                    },
                    head,
                )
            })
            .collect())
    }
    fn binding_proofs(
        &self,
        placement: &PythonPlacement,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<PythonBindingProofs> {
        let mut proofs = PythonBindingProofs {
            source_completion: Some(self.completion.clone()),
            ..Default::default()
        };
        // An empty module cell has no initialization order to prove. Admit
        // that fact only for this builtin name and current mutation-free source.
        if brokk_bifrost_python::intrinsics::builtin(lookup.spelling()).is_some_and(|entry|
            entry.versions.availability(self.rules.python_version)
                == brokk_bifrost_python::intrinsics::Availability::Present)
            && let Some(module) = self.rows.scopes.iter().find(|scope| scope.parent.is_none())
            && !self.rows.slots.iter().any(|slot| slot.scope == module.scope && slot.name == lookup.spelling())
            && !self.rows.import_positions.iter().any(|(site,scope,_)|
                *scope == module.scope && self.rows.imports.iter().any(|import|
                    import.import_site.get() == *site && import.form == brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Star))
            && self.builtin_inventory_closed()
        {
            proofs.absent_scopes.push(module.scope);
        }
        placement.stars.borrow_mut().clear();
        let mut occurrence = self
            .rows
            .events
            .iter()
            .map(|event| event.event)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .expect("event occurrence capacity");
        for import in &self.rows.imports {
            if import.form
                != brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Star
            {
                continue;
            }
            let site = import.import_site.get();
            let mut starts = Vec::new();
            for (location, head) in self.import_starts(placement, site, lookup)? {
                let RouteLocation::Container { ref container, .. } = location else {
                    unreachable!()
                };
                let present: bool = self.rules.ready.inventory.connection().query_row(
                    "SELECT EXISTS(SELECT 1 FROM python_unit_summary_export_names WHERE summary_id=?1 AND container_path=?2 AND surface='wildcard' AND name=?3)",
                    rusqlite::params![self.rules.summary,container,lookup.spelling()], |row|row.get(0),
                )?;
                if present {
                    starts.push((location, head.expect("star attribute head")));
                }
            }
            if !starts.is_empty() {
                proofs
                    .route_bindings
                    .push(python_lexical::PythonRouteBinding {
                        occurrence,
                        import_site: site,
                        name: lookup.spelling().to_owned(),
                        certain: false,
                        completion: open(self.source.token),
                    });
                placement.stars.borrow_mut().insert(occurrence, starts);
                occurrence = occurrence.checked_add(1).expect("star occurrence capacity");
            }
        }
        Ok(proofs)
    }
    fn module_locations(&self, container: &str, name: &str) -> Result<Read<Vec<RouteLocation>>> {
        let selected = self.rules.ready.inventory.connection().query_row(
            "SELECT mounted.mount_ordinal,mounted.blob_id FROM python_unit_summary_providers provider
             JOIN resolution_unit_summary_members member ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal
             JOIN selected_resolution_mounts mounted ON mounted.blob_id=member.blob_id AND mounted.persisted_relative_path=member.rel_path
             WHERE provider.summary_id=?1 AND provider.container_path=?2 AND provider.state IN ('selected','alternative')",
            rusqlite::params![self.rules.summary, container], |row| Ok((row.get::<_,u32>(0)?,row.get::<_,i64>(1)?)),
        ).optional()?;
        let Some((ordinal, blob)) = selected else {
            return Ok(Read::Ready {
                value: Vec::new(),
                completion: open(self.source.token),
            });
        };
        let Some(rows) = PythonBindingRows::load(
            self.rules.ready.inventory.connection(),
            blob,
            self.rules.cancellation,
        )?
        else {
            return Ok(if self.rules.cancellation.is_cancelled() {
                Read::Cancelled(cancelled_completion())
            } else {
                Read::Unavailable { reason: crate::analyzer::resolution::DemandRootUnavailableReason::MissingSourceProvenance, completion:open(self.source.token) }
            });
        };
        let Some(root) = rows.scopes.iter().find(|scope| scope.parent.is_none()) else {
            return Ok(Read::Ready {
                value: Vec::new(),
                completion: open(self.source.token),
            });
        };
        let mut state = python_lexical::module_selection(
            &rows,
            root.scope,
            name,
            self.rules.profile,
            PythonBindingProofs::default(),
        );
        python_lexical::lexical_tier(
            &mut state,
            &rows,
            root.scope,
            &mut SessionBudget {
                session: self.rules.session,
                cancellation: self.rules.cancellation,
            },
        );
        let completion = self.selection_completion(&state);
        let mount = SelectedMountTable::new(&self.rules.ready.inventory)
            .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let value = if state.selection.stopped.is_some() {
            Vec::new()
        } else {
            state
                .selection
                .selected
                .iter()
                .filter_map(|selected| {
                    rows.events
                        .iter()
                        .find(|event| event.event == selected.occurrence)
                })
                .filter_map(|event| self.authored(mount.fragment(), event))
                .collect()
        };
        Ok(Read::Ready { value, completion })
    }
    /// Mutation authority is the retained operation inventory, confirmed only
    /// through the shared prefix prerequisites. Lexical source events remain
    /// the authority for local/module shadowing; no source is reparsed here.
    fn builtin_inventory_closed(&self) -> bool {
        let Some(site) = self.reference_site else {
            return false;
        };
        self.universe_unmutated && self.import_site.is_none()
            && !self.rules.cancellation.is_cancelled()
            && !self.rows.events.iter().any(|event|event.target==site && event.kind!=brokk_bifrost_core::analyzer::resolution_facts::ResolutionBindingEventKind::Augment)
    }

    fn selection_completion(&self, state: &PythonLexical) -> ResolutionCompletion {
        let mut completion = state.selection.completion.clone();
        if state.selection.open
            || !state.selection.residual.is_empty()
            || !state.selection.unbound.is_empty()
        {
            completion = completion.combine(&open(self.source.token));
        }
        if let Some(stop) = state.selection.stopped {
            completion = completion.combine(&match stop {
                Stop::Cancelled => cancelled_completion(),
                Stop::Budget => ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::TimeBudgetExceeded(self.source.token),
                ]),
            });
        }
        completion
    }
}

impl PythonHalf<'_, '_, '_> {
    pub(super) fn member_context(&self) -> super::python_members::PythonMemberContext<'_, '_, '_> {
        super::python_members::PythonMemberContext {
            rules: self.rules,
            reference: self.source.token,
            environment: crate::analyzer::resolution::CALLER_ENVIRONMENT,
            rows: &self.rows,
            blob: self.blob,
            member_values: &[],
            super_cursor: None,
            member_observations: &self.member_observations,
            rendered_order: &self.rendered_order,
        }
    }

    fn member_request(
        &self,
        reference: SemanticId,
        values: Vec<ResolutionSlotValue>,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> crate::analyzer::resolution::DemandMemberSelectionRequest {
        self.member_context().member_request(
            reference,
            values,
            lookup.semantic(&self.rules.ready.shared_names()),
            ResolutionNamespace::Value,
        )
    }
    fn owner_request(
        &self,
        location: &RouteLocation,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Option<crate::analyzer::resolution::DemandMemberSelectionRequest>> {
        let RouteLocation::Owner { definition, .. } = location else {
            return Ok(None);
        };
        if !super::python_members::is_class(self.rules.ready, *definition)? {
            return Ok(None);
        }
        Ok(Some(self.member_request(
            self.source.token,
            vec![ResolutionSlotValue::type_object(
                crate::analyzer::resolution::ResolutionTypeRef::new(*definition, 0),
            )],
            lookup,
        )))
    }
}

impl HalfRules for PythonHalf<'_, '_, '_> {
    fn member_access(
        &self,
    ) -> Option<&dyn super::member_access::MemberAccessRules<Self::MemberRow>> {
        Some(self)
    }
    fn provider_observations(
        &self,
    ) -> Result<Read<Vec<crate::analyzer::resolution::HierarchyProviderObservation>>> {
        Ok(Read::ready(std::mem::take(
            &mut *self.member_observations.borrow_mut(),
        )))
    }
    fn terminal_member_request(
        &self,
        _: &PythonPlacement,
        target: &SourceTargetContext<'_, PythonRank>,
    ) -> Result<Read<Option<crate::analyzer::resolution::DemandMemberSelectionRequest>>> {
        // With no qualifier the lexical tier already selected the declaration
        // named by the terminal lookup. A class binding is then a value, not
        // a second lookup of that same name inside the selected class.
        if self.source.route.is_empty() {
            return Ok(Read::ready(None));
        }
        Ok(Read::ready(
            self.owner_request(&target.cursor.location, target.lookup)?,
        ))
    }
    fn member_rows(
        &self,
        _: &PythonPlacement,
        route: &MemberRouteContext<'_, PythonRank>,
        owner: SemanticId,
    ) -> Result<Read<Vec<Self::MemberRow>>> {
        let context = self.member_context();
        super::python_members::member_rows(
            &context,
            &super::python_members::PythonMemberRoute {
                lookup: route.lookup,
                namespace: route.namespace,
                step: route.cursor.consumed_prefix_segments,
                selection: route.selection,
                provenance: route.provenance,
            },
            owner,
        )
    }
    fn member_target(
        &self,
        _: &PythonPlacement,
        route: &MemberRouteContext<'_, PythonRank>,
        row: &Self::MemberRow,
    ) -> Result<Read<Option<SelectedMemberRouteTarget>>> {
        self.member_context()
            .member_target(route.lookup, route.namespace, row)
    }
    type Placement = PythonPlacement;
    type Target = PythonTarget;
    type Member = ();
    type Provider = ();
    type MemberRow = super::python_members::PythonMemberRow;
    type Rank = PythonRank;
    type LexicalTiers = Vec<LexicalStartTier<PythonRank, ()>>;
    fn selected_universe(
        &self,
        placement: &PythonPlacement,
    ) -> Option<(
        SemanticId,
        Option<crate::analyzer::resolution::UniverseEntry>,
    )> {
        self.reference_site.map(|site| {
            (
                crate::analyzer::resolution::mounted_site_semantic(
                    self.fragment,
                    ResolutionSiteId::new(site),
                ),
                placement.universe.get(),
            )
        })
    }
    fn language(&self) -> Language {
        Language::Python
    }
    fn placements(&mut self) -> Vec<PythonPlacement> {
        std::mem::take(&mut self.placements)
    }
    fn initial_completion(&self) -> ResolutionCompletion {
        self.completion.clone()
    }
    fn placement(
        &self,
        _: &PythonPlacement,
        tag: ClosureTag,
    ) -> Option<PlacementFacts<PythonTarget>> {
        Some(PlacementFacts {
            tag,
            completion: self.completion.clone(),
            targets: Vec::new(),
            members: Vec::new(),
        })
    }
    fn root_starts(
        &mut self,
        _: &PythonPlacement,
        facts: &mut PlacementFacts<PythonTarget>,
    ) -> Result<Vec<PlacementStart<(), PythonRank>>> {
        let mut cursor = WalkCursor::container(facts.tag, self.rules.summary, String::new(), 0);
        cursor.namespace = self.source.demand.namespace();
        Ok(vec![PlacementStart::Route {
            cursor,
            anchor: self.source.anchor,
            rank: Some(PythonRank { cohort: 0 }),
            scope: None,
        }])
    }
    fn route_rules<'a>(
        &'a self,
        placement: &'a PythonPlacement,
        _: ResolutionRootImportAnchor,
        _: &'a [ResolutionLookupSemanticRecipe],
    ) -> impl RouteRules<ClosureTag> + 'a {
        PythonRoute {
            half: self,
            placement,
        }
    }
    fn prefix_starts(
        &mut self,
        _: &PythonPlacement,
        selection: StartSelection<PythonRank, ()>,
        facts: &mut PlacementFacts<PythonTarget>,
    ) -> Result<Vec<PlacementStart<(), PythonRank>>> {
        Ok(selection
            .locations
            .into_iter()
            .map(|start| PlacementStart::Route {
                cursor: WalkCursor {
                    tag: facts.tag,
                    location: start.location,
                    consumed_prefix_segments: 0,
                    start_step: 0,
                    namespace: self.source.demand.namespace(),
                },
                anchor: self.source.anchor,
                rank: start.rank,
                scope: start.scope,
            })
            .collect())
    }
    fn lexical_selection(
        &self,
        placement: &PythonPlacement,
        facts: &mut PlacementFacts<PythonTarget>,
    ) -> Result<Option<StartSelection<PythonRank, ()>>> {
        if self.source.anchor != ResolutionRootImportAnchor::Lexical || self.source.is_import {
            return Ok(None);
        }
        let lookup = self
            .source
            .route
            .first()
            .unwrap_or(&self.source.demand)
            .clone();
        let proofs = self.binding_proofs(placement, &lookup)?;
        let state = self.reference_site.and_then(|site| {
            python_lexical::lexical_selection(
                &self.rows,
                site,
                lookup.spelling(),
                self.rules.profile,
                proofs,
            )
        });
        let request = state.as_ref().map(|state| LexicalStartRequest {
            scope: ResolutionScopeId::new(state.start_scope),
            lookup,
        });
        if state.is_none() {
            facts.completion = facts.completion.combine(&open(self.source.token));
        }
        // Each borrowed view is reconstructed from the current J3 proof inputs;
        // an earlier survivor set is never promoted after prerequisite refinement.
        *placement.lexical.borrow_mut() = state;
        Ok(Some(StartSelection {
            lexical: request,
            locations: Vec::new(),
            scopes: Vec::new(),
            blocks_fallback: true,
            head: None,
            providers: Vec::new(),
        }))
    }
    fn lexical_parent(
        &self,
        placement: &PythonPlacement,
        scope: ResolutionScopeId,
    ) -> Result<Option<ResolutionScopeId>> {
        let state = placement.lexical.borrow();
        Ok(python_lexical::lexical_parent(
            state.as_ref().expect("selected lexical state"),
            &self.rows,
            scope.get(),
        )
        .map(ResolutionScopeId::new))
    }
    fn lexical_tier(
        &self,
        placement: &PythonPlacement,
        scope: ResolutionScopeId,
        _: u32,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Self::LexicalTiers> {
        let mut state = placement.lexical.borrow_mut();
        let state = state.as_mut().expect("selected lexical state");
        let before = state.selection.selected.len();
        python_lexical::lexical_tier(
            state,
            &self.rows,
            scope.get(),
            &mut SessionBudget {
                session: self.rules.session,
                cancellation: self.rules.cancellation,
            },
        );
        if self.source.route.len() <= 1
            && lookup.spelling() == self.source.demand.spelling()
            && python_lexical::lexical_parent(state, &self.rows, scope.get()).is_none()
            && !state.selection.open
            && state.selection.stopped.is_none()
            && state.selection.unbound.is_empty()
            && state.selection.selected.is_empty()
            && !state.selection.residual.is_empty()
            && state.selection.completion == ResolutionCompletion::Complete
            && let Some(builtin) = brokk_bifrost_python::intrinsics::builtin(lookup.spelling())
            && builtin.versions.availability(self.rules.python_version)
                == brokk_bifrost_python::intrinsics::Availability::Present
            && self.builtin_inventory_closed()
        {
            let entry = crate::analyzer::resolution::universe_lookup(
                Language::Python,
                ResolutionNamespace::Value,
                builtin.name,
            )
            .expect("Python builtin table is registered in the universe");
            placement.universe.set(Some(entry));
            state.selection.residual.clear();
            self.rules.observations.borrow_mut().push(format!(
                "universe={} identity={} predeclared=true version={:?}",
                builtin.qualified_name,
                brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string(
                    &crate::analyzer::resolution::universe::identity_digest(entry)
                ),
                self.rules.python_version,
            ));
        }
        self.stopped.set(state.selection.stopped.is_some());
        let mut coverage = self.selection_completion(state);
        // A residual carried to a known semantic parent is not missing evidence.
        // Only an uncovered region at the end of traversal stays open.
        if !state.selection.open
            && state.selection.unbound.is_empty()
            && state.selection.stopped.is_none()
            && python_lexical::lexical_parent(state, &self.rows, scope.get()).is_some()
        {
            coverage = state.selection.completion.clone();
        }
        let mut tiers = Vec::new();
        if state.selection.stopped.is_none() {
            for selected in &state.selection.selected[before..] {
                if let Some(starts) = placement.stars.borrow().get(&selected.occurrence) {
                    for (location, head) in starts {
                        tiers.push(LexicalStartTier {
                            ranked: RankedLexicalTier {
                                rank: PythonRank { cohort: 0 },
                                tier: RouteEdgeTier {
                                    coverage: coverage.clone(),
                                    blocks_fallback: true,
                                    ..Default::default()
                                },
                                providers: Vec::new(),
                            },
                            head: Some((location.clone(), head.clone())),
                        });
                    }
                } else if let Some(event) = self
                    .rows
                    .events
                    .iter()
                    .find(|event| event.event == selected.occurrence)
                {
                    if let Some(import) = self
                        .rows
                        .imports
                        .iter()
                        .find(|import| import.binding_event == Some(event.event))
                    {
                        for (location, head) in
                            self.import_starts(placement, import.import_site.get(), lookup)?
                        {
                            let mut tier = RouteEdgeTier {
                                coverage: coverage.combine(&open(self.source.token)),
                                blocks_fallback: true,
                                ..Default::default()
                            };
                            let head = if let Some(head) = head {
                                Some((location, head))
                            } else {
                                tier.edges.push(location);
                                None
                            };
                            tiers.push(LexicalStartTier {
                                ranked: RankedLexicalTier {
                                    rank: PythonRank { cohort: 0 },
                                    tier,
                                    providers: Vec::new(),
                                },
                                head,
                            });
                        }
                    } else if let Some(location) = self.authored(self.fragment, event) {
                        tiers.push(LexicalStartTier {
                            ranked: RankedLexicalTier {
                                rank: PythonRank { cohort: 0 },
                                tier: RouteEdgeTier {
                                    edges: vec![location],
                                    coverage: coverage.clone(),
                                    blocks_fallback: true,
                                    ..Default::default()
                                },
                                providers: Vec::new(),
                            },
                            head: None,
                        });
                    }
                }
            }
        }
        self.rules.observations.borrow_mut().push(format!(
            "lexical scope={} selected={:?} residual={:?} unbound={:?} open={} stopped={:?}",
            scope.get(),
            state.selection.selected,
            state.selection.residual,
            state.selection.unbound,
            state.selection.open,
            state.selection.stopped
        ));
        // Retain blockers even when no selected write can produce a target.
        tiers.push(LexicalStartTier {
            ranked: RankedLexicalTier {
                rank: PythonRank { cohort: 0 },
                tier: RouteEdgeTier {
                    coverage,
                    blocks_fallback: true,
                    ..Default::default()
                },
                providers: Vec::new(),
            },
            head: None,
        });
        Ok(tiers)
    }

    fn outer_can_compete(
        &self,
        placement: &PythonPlacement,
        _: Option<&PythonRank>,
        _: u32,
    ) -> bool {
        python_lexical::outer_can_compete(
            placement
                .lexical
                .borrow()
                .as_ref()
                .expect("selected lexical state"),
        )
    }
    fn lexical_starts(
        &self,
        selection: StartSelection<PythonRank, ()>,
        facts: &PlacementFacts<PythonTarget>,
    ) -> Vec<PlacementStart<(), PythonRank>> {
        if self.stopped.get() {
            return Vec::new();
        }
        let consumed = usize::from(!self.source.route.is_empty());
        selection
            .locations
            .into_iter()
            .map(|start| PlacementStart::Route {
                cursor: WalkCursor {
                    tag: facts.tag,
                    location: start.location,
                    consumed_prefix_segments: consumed,
                    start_step: consumed,
                    namespace: self.source.demand.namespace(),
                },
                anchor: ResolutionRootImportAnchor::Lexical,
                rank: start.rank,
                scope: start.scope,
            })
            .collect()
    }
    fn route_target(
        &self,
        location: RouteLocation,
        rank: Option<&PythonRank>,
        scope: Option<ResolutionScopeId>,
    ) -> PythonTarget {
        PythonTarget {
            location,
            rank: rank.copied(),
            scope,
        }
    }
    fn target_location(&self, target: &PythonTarget) -> RouteLocation {
        target.location.clone()
    }
    fn exports(
        &self,
        placement: &PythonPlacement,
        target: PythonTarget,
        completion: &ResolutionCompletion,
    ) -> Result<Option<ExportHydration>> {
        let target = target.location;
        if let RouteLocation::Container {
            unit,
            ref container,
        } = target
        {
            // Import endpoints bind a local alias. The selected source name
            // remains the module attribute (or terminal module segment).
            let lookup = self.import_name.as_ref().map_or_else(
                || self.source.demand.clone(),
                |name| {
                    ResolutionLookupSemanticRecipe::new(
                        Language::Python,
                        self.source.demand.namespace(),
                        name.as_str(),
                    )
                },
            );
            let cursor = WalkCursor {
                tag: (),
                location: RouteLocation::Container {
                    unit,
                    container: container.clone(),
                },
                consumed_prefix_segments: self.source.route.len(),
                start_step: 0,
                namespace: self.source.demand.namespace(),
            };
            // Python's terminal attribute can also name a child module. Read
            // that one segment, independently of the file's attribute surface.
            let _child_module = PythonRoute {
                half: self,
                placement,
            }
            .route_tier(&cursor, &lookup, 0)?;
            let star = match self.import_site {
                Some(site) if self.source.is_import => self.rules.ready.inventory.connection().query_row(
                    "SELECT EXISTS(SELECT 1 FROM python_unit_summary_imports WHERE summary_id=?1 AND import_site=?2 AND importer_container=?3 AND form='star')",
                    rusqlite::params![unit, site, placement.container], |row| row.get::<_, bool>(0),
                )?,
                _ => false,
            };
            let surface = if star { "wildcard" } else { "module" };
            let membership: Option<Option<u32>> = self
                .rules
                .ready
                .inventory
                .connection()
                .query_row(
                    "SELECT slot_site FROM python_unit_summary_export_names
                 WHERE summary_id=?1 AND container_path=?2 AND surface=?3 AND name=?4",
                    rusqlite::params![unit, container, surface, lookup.spelling()],
                    |row| row.get(0),
                )
                .optional()?;
            let policy: Option<String> = self.rules.ready.inventory.connection().query_row(
                "SELECT policy FROM python_unit_summary_surfaces WHERE summary_id=?1 AND container_path=?2 AND surface=?3",
                rusqlite::params![unit,container,surface], |row| row.get(0),
            ).optional()?;
            self.rules.observations.borrow_mut().push(format!(
                "surface={surface} policy={policy:?} name={} member={}",
                lookup.spelling(),
                membership.is_some()
            ));
        }
        // Canonical export slots describe inventory only. Authored reaching
        // definitions require M4-3a's retained event reader, never hydration of
        // the slot as an ordinary root export.
        Ok(Some(ExportHydration {
            exports: Vec::new(),
            blockers: Vec::new(),
            unstaged: if matches!(target, RouteLocation::Owner { .. }) {
                completion.clone()
            } else {
                completion.combine(&open(self.source.token))
            },
            coverage: ExportCoverage::default(),
        }))
    }
    fn proven_targets(
        &self,
        placement: &PythonPlacement,
        target: &PythonTarget,
        completion: &ResolutionCompletion,
    ) -> Result<Read<Vec<ProvenTarget>>> {
        self.rules.observations.borrow_mut().push(format!(
            "target cohort={:?} declaring-scope={:?}",
            target.rank, target.scope
        ));
        let (locations, mut evidence) = match &target.location {
            RouteLocation::Owner { .. } => (vec![target.location.clone()], completion.clone()),
            RouteLocation::Container { container, .. } => {
                let name = self
                    .import_name
                    .as_deref()
                    .unwrap_or(self.source.demand.spelling());
                let star = match self.import_site {
                    Some(site) if self.source.is_import => self.rules.ready.inventory.connection().query_row(
                        "SELECT EXISTS(SELECT 1 FROM python_unit_summary_imports WHERE summary_id=?1 AND importer_container=?2 AND import_site=?3 AND form='star')",
                        rusqlite::params![self.rules.summary,placement.container,site],|row|row.get::<_,bool>(0),
                    )?,
                    _ => false,
                };
                if star && !self.rules.ready.inventory.connection().query_row(
                    "SELECT EXISTS(SELECT 1 FROM python_unit_summary_export_names WHERE summary_id=?1 AND container_path=?2 AND surface='wildcard' AND name=?3)",
                    rusqlite::params![self.rules.summary,container,name], |row|row.get::<_,bool>(0),
                )? {
                    return Ok(Read::Ready {value:Vec::new(),completion:completion.combine(&open(self.source.token))});
                }
                match self.module_locations(container, name)? {
                    Read::Ready {
                        value,
                        completion: read,
                    } => (value, completion.combine(&read)),
                    Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                    Read::Unavailable { reason, completion } => {
                        return Ok(Read::Unavailable { reason, completion });
                    }
                }
            }
        };
        let mut targets = Vec::new();
        for location in locations {
            let RouteLocation::Owner { definition, .. } = location else {
                unreachable!("module attribute projection emits authored definitions")
            };
            match self.proven_owner(definition, &evidence)? {
                Read::Ready { value, completion } => {
                    evidence = evidence.combine(&completion);
                    targets.extend(value);
                }
                Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                Read::Unavailable { reason, completion } => {
                    return Ok(Read::Unavailable { reason, completion });
                }
            }
        }
        Ok(Read::Ready {
            value: targets,
            completion: evidence,
        })
    }
    fn empty_target(
        &self,
        _: &PythonPlacement,
        target: &PythonTarget,
    ) -> Result<ResolutionCompletion> {
        Ok(if matches!(target.location, RouteLocation::Owner { .. }) {
            ResolutionCompletion::Complete
        } else {
            open(self.source.token)
        })
    }
}

impl PythonHalf<'_, '_, '_> {
    fn proven_owner(
        &self,
        definition: SemanticId,
        completion: &ResolutionCompletion,
    ) -> Result<Read<Vec<ProvenTarget>>> {
        let paths = self.rules.ready.lexical_source();
        let Some(SelectedSemanticProvenance::FragmentLocal(provenance)) =
            paths.semantic_provenance(definition, self.rules.cancellation)?
        else {
            return Ok(Read::Ready {
                value: Vec::new(),
                completion: open(definition),
            });
        };
        let Some(node) = paths.lookup_definition_node(definition, self.rules.cancellation)? else {
            return Ok(Read::Ready {
                value: Vec::new(),
                completion: open(definition),
            });
        };
        Ok(Read::ready(vec![ProvenTarget {
            target: SelectedMemberTarget {
                fragment: provenance.mount().fragment(),
                token: definition,
                definition: node,
                lookup: self.source.demand.clone(),
                completion: completion.clone(),
            },
            material: BridgeMaterial::same_language(Language::Python),
        }]))
    }
}

struct PythonRoute<'a, 'store, 'input> {
    half: &'a PythonHalf<'a, 'store, 'input>,
    placement: &'a PythonPlacement,
}
impl<T: Clone + Eq + std::hash::Hash> RouteRules<T> for PythonRoute<'_, '_, '_> {
    fn member_request(
        &self,
        cursor: &WalkCursor<T>,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Read<Option<crate::analyzer::resolution::DemandMemberSelectionRequest>>> {
        Ok(Read::ready(
            self.half.owner_request(&cursor.location, lookup)?,
        ))
    }
    fn root_starts(
        &self,
        start: &WalkCursor<T>,
        completion: &mut ResolutionCompletion,
    ) -> Result<RouteStarts> {
        if self.half.source.is_import || matches!(start.location, RouteLocation::Container { .. }) {
            *completion = completion.combine(&open(self.half.source.token));
        }
        if let Some(site) = self.half.import_site {
            let destinations = self
                .half
                .rules
                .ready
                .inventory
                .connection()
                .prepare_cached(
                    "SELECT imports.target_container,imports.form,imports.module_name,coalesce(provider.rel_path,'')
                 FROM main.python_unit_summary_imports imports
                 LEFT JOIN main.python_unit_summary_providers provider
                   ON provider.summary_id=imports.summary_id AND provider.container_path=imports.target_container
                 WHERE imports.summary_id=?1 AND imports.importer_container=?2 AND imports.import_site=?3",
                )?
                .query_map(
                    rusqlite::params![self.half.rules.summary, self.placement.container, site],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            self.half.rules.observations.borrow_mut().push(format!(
                "import-site={site} destinations={:?}",
                destinations
                    .iter()
                    .map(|(_, form, module, path)| (form, module, path))
                    .collect::<Vec<_>>()
            ));
            if destinations.iter().any(|(_, form, _, _)| form != "module") {
                return Ok(RouteStarts {
                    locations: destinations
                        .into_iter()
                        .filter(|(container, _, _, _)| !container.is_empty())
                        .map(|(container, _, _, _)| RouteLocation::Container {
                            unit: self.half.rules.summary,
                            container,
                        })
                        .collect(),
                    consumed: self.half.source.route.len(),
                });
            }
        }
        if self.half.source.anchor == ResolutionRootImportAnchor::Lexical {
            return Ok(RouteStarts {
                locations: vec![start.location.clone()],
                consumed: 0,
            });
        }
        Ok(RouteStarts {
            locations: vec![start.location.clone()],
            consumed: 0,
        })
    }
    fn route_tier(
        &self,
        cursor: &WalkCursor<T>,
        segment: &ResolutionLookupSemanticRecipe,
        tier: usize,
    ) -> Result<Option<RouteEdgeTier>> {
        if tier != 0 {
            return Ok(None);
        }
        let RouteLocation::Container { unit, container } = &cursor.location else {
            return Ok(Some(RouteEdgeTier {
                blockers: open(self.half.source.token),
                blocks_fallback: true,
                ..Default::default()
            }));
        };
        assert_eq!(*unit, self.half.rules.summary);
        let providers = self
            .half
            .rules
            .ready
            .inventory
            .connection()
            .prepare_cached(
                "SELECT child.container_path,child.module_name,child.root_slot,child.kind,child.rel_path,child.state FROM main.python_unit_summary_providers child
             WHERE child.summary_id=?1 AND child.state IN ('selected','alternative')
               AND child.module_name=CASE WHEN ?2='' THEN ?3 ELSE
                   (SELECT parent.module_name FROM main.python_unit_summary_providers parent
                    WHERE parent.summary_id=?1 AND parent.container_path=?2) || '.' || ?3 END
               AND (?2='' OR EXISTS(
                   SELECT 1 FROM main.python_unit_summary_providers parent
                   WHERE parent.summary_id=?1 AND parent.container_path=?2
                     AND parent.kind IN ('package','namespace')
                     AND parent.root_slot=child.root_slot))",
            )?
            .query_map(
                rusqlite::params![unit, container, segment.spelling()],
                |row| {
                    Ok((row.get::<_, String>(0)?,row.get::<_, String>(1)?,row.get::<_, i64>(2)?,row.get::<_, String>(3)?,row.get::<_, String>(4)?,row.get::<_, String>(5)?))
            })?.collect::<rusqlite::Result<Vec<_>>>()?;
        self.half.rules.observations.borrow_mut().push(format!(
            "segment={} providers={:?}",
            segment.spelling(),
            providers
                .iter()
                .map(|(_, module, root, kind, path, state)| (module, root, kind, path, state))
                .collect::<Vec<_>>()
        ));
        let mut edges: Vec<_> = providers
            .into_iter()
            .map(|(container, ..)| RouteLocation::Container {
                unit: *unit,
                container,
            })
            .collect();
        let mut coverage = open(self.half.source.token);
        if !container.is_empty() {
            match self.half.module_locations(container, segment.spelling())? {
                Read::Ready { value, completion } => {
                    edges.extend(value);
                    coverage = coverage.combine(&completion);
                }
                Read::Cancelled(completion) | Read::Unavailable { completion, .. } => {
                    coverage = coverage.combine(&completion);
                }
            }
        }
        Ok(Some(RouteEdgeTier {
            edges,
            coverage,
            independent: true,
            ..Default::default()
        }))
    }
    fn dead_end(
        &self,
        _: &WalkCursor<T>,
        _: &ResolutionLookupSemanticRecipe,
    ) -> Result<ResolutionCompletion> {
        let _ = &self.placement;
        Ok(open(self.half.source.token))
    }
}

impl SelectedResolutionOperation<'_, '_> {
    /// Read the real selected hierarchy inputs and intrinsic inventory through
    /// their ordinary hooks; class-route evaluation remains a separate bridge.
    #[doc(hidden)]
    pub fn python_native_builtin_hierarchy_probe(
        &self,
        summary: i64,
        python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
        cancellation: &CancellationToken,
    ) -> Result<String> {
        use crate::analyzer::resolution::{SelectedTypedFactSource, SharedNameInterner, universe};
        use std::fmt::Write;
        let typed = self.ready.typed_source().with_implicit_environment(
            summary,
            python_version.map(|version| (version.major, version.minor)),
        );
        let typed = crate::analyzer::resolution::seam_profile::SeamProfiled::observing(&typed);
        let classes = self.ready.inventory.connection().prepare_cached(
            "SELECT mounted.mount_ordinal,mounted.persisted_relative_path,semantic.semantic_key,class.class
             FROM temp.selected_resolution_mounts mounted
             JOIN python_member_classes class ON class.blob_id=mounted.blob_id
             JOIN resolution_semantic_sites semantic ON semantic.blob_id=class.blob_id
              AND semantic.source_site=class.class AND semantic.semantic_role='definition'
             WHERE mounted.semantic_language='python'
             ORDER BY mounted.persisted_relative_path,class.class",
        )?.query_map([], |row| Ok((row.get::<_,u32>(0)?,row.get::<_,String>(1)?,row.get::<_,u32>(2)?,row.get::<_,u32>(3)?)))?
         .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut output = String::new();
        for (ordinal, path, key, site) in classes {
            let owner = SemanticId::local(ordinal, key);
            let inputs = typed
                .implicit_base_inputs(owner, cancellation)?
                .expect("selected class inputs");
            let root = inputs.root_object.as_ref().map(|root| {
                assert!(matches!(root.authority,crate::analyzer::resolution::ImplicitBaseAuthority::Intrinsic { descriptor } if descriptor==root.identity));
                let id=root.identity.shared_name_id().expect("intrinsic root identity");
                universe::entry_for_digest(self.ready.shared_names().digest_for_id(id).expect("selected root digest"))
                    .expect("selected intrinsic root").identity_spelling
            });
            writeln!(output,"hierarchy {path}:site={site} creation={:?} written={} inventory={} implicit={root:?} complete={}",
                inputs.creation,inputs.written_base_count,inputs.written_inventory_complete,inputs.completion==ResolutionCompletion::Complete).expect("String write");
        }
        if let Some(root) = brokk_bifrost_python::intrinsics::implicit_base(python_version) {
            let entry = universe::lookup(
                Language::Python,
                ResolutionNamespace::TypeOrValue,
                root.name,
            )
            .expect("root universe entry");
            let owner = SemanticId::shared_name(
                self.ready
                    .shared_names()
                    .intern(universe::identity_digest(entry)),
            );
            let inputs = typed
                .implicit_base_inputs(owner, cancellation)?
                .expect("intrinsic root inputs");
            assert!(
                matches!(inputs.authority,crate::analyzer::resolution::ImplicitBaseAuthority::Intrinsic { descriptor } if descriptor==owner)
            );
            writeln!(
                output,
                "intrinsic-root {} self-base={} complete={}",
                root.qualified_name,
                inputs.root_object.is_some(),
                inputs.completion == ResolutionCompletion::Complete
            )
            .expect("String write");
            for name in ["__repr__", "__getstate__", "not_an_object_member"] {
                let lookup = super::ResolutionLookupSemanticRecipe::new(
                    Language::Python,
                    ResolutionNamespace::Value,
                    name,
                )
                .semantic(&self.ready.shared_names());
                let present =
                    typed
                        .intrinsic_member_inventory(owner, cancellation)?
                        .map(|inventory| {
                            inventory.presence(
                                self.ready
                                    .shared_names()
                                    .digest_for_id(
                                        lookup.shared_name_id().expect("lookup shared name"),
                                    )
                                    .expect("lookup digest"),
                                ResolutionNamespace::Value,
                            ) != universe::IntrinsicMemberPresence::Absent
                        });
                writeln!(output, "intrinsic-inventory {name} may-contain={present:?}")
                    .expect("String write");
            }
        }
        Ok(output)
    }

    /// Explicit dormant validation assembly. No production query calls this.
    #[doc(hidden)]
    pub fn python_native_route_probe(
        &self,
        summary: i64,
        python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
        cancellation: &CancellationToken,
    ) -> Result<String> {
        let observation: String = self.ready.inventory.connection().query_row(
            "SELECT observation FROM python_unit_summary_roots WHERE summary_id=?1 LIMIT 1",
            [summary],
            |row| row.get(0),
        )?;
        let profile = match observation.as_str() {
            "runtime" => PythonBindingProfile::Runtime,
            "typing" => PythonBindingProfile::Typing,
            _ => return Err(StoreError::corrupt("invalid Python observation profile")),
        };
        let session = ResolutionSession::unbounded();
        let paths = self.ready.lexical_source();
        let typed = self.ready.typed_source().with_implicit_environment(
            summary,
            python_version.map(|version| (version.major, version.minor)),
        );
        let context = empty_contexts_for(
            self.mount_table(),
            &ResolutionCompletion::Complete,
            &selected_mount_lookup(self.mount_table()),
            self.ready.context_identities.clone(),
        )?;
        let Some(blueprint) = self.prepare_prefix_blueprint(context, cancellation)? else {
            return Err(StoreError::new("cancelled preparing Python route probe"));
        };
        let base = blueprint.path_fragment_source(&paths, &paths, Some(&session));
        let arena = RefCell::new(ClosedRelations::default());
        let observations = RefCell::new(Vec::new());
        let source = ClosedForwardSource::new(&base, &paths, &arena, &session, CALLER_ENVIRONMENT);
        let mut provider = DemandProvider::new(SharedDemand {
            source_closures: HashMap::default(),
            rules: PythonRules {
                ready: &self.ready,
                summary,
                profile,
                python_version,
                cancellation,
                session: &session,
                observations: &observations,
                arena: &arena,
                source_inputs: RefCell::new(HashMap::default()),
                qualified_members: HashMap::default(),
                prepared_references: RefCell::new(HashMap::default()),
                universe_mutations: RefCell::new(HashMap::default()),
            },
            arena: &arena,
            paths: &paths,
            ready: &self.ready,
            base: &paths,
            session: &session,
            cancellation,
            completion: &ResolutionCompletion::Complete,
        });
        let mut roots = Vec::new();
        let outcome = visit_selected_root_import_half_pages(
            &self.ready.context_identities,
            &paths,
            &paths,
            None,
            cancellation,
            &mut FactPageVisitor::new(&mut |halves| {
                roots.extend(halves.iter().filter_map(|half| match half {
                    SelectedRootPathHalf::Import {
                        identity, token, ..
                    } => Some((*identity, *token)),
                    SelectedRootPathHalf::Reference { .. } => None,
                    SelectedRootPathHalf::Export { .. } => unreachable!("root import inventory"),
                }));
                Ok(true)
            }),
        )?;
        if outcome.is_cancelled() {
            return Err(StoreError::new("cancelled reading Python route roots"));
        }
        let root_paths = paths.hydrate_candidate_paths(
            &roots.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            cancellation,
        )?;
        let references = self.ready.inventory.connection().prepare_cached(
            "SELECT mounted.mount_ordinal, mounted.persisted_relative_path, sites.source_site,
                    reference.start_byte,reference.end_byte
             FROM temp.selected_resolution_mounts mounted
             JOIN resolution_semantic_sites sites ON sites.blob_id=mounted.blob_id AND sites.semantic_role='reference'
             JOIN resolution_sites reference ON reference.blob_id=sites.blob_id AND reference.site=sites.source_site
             WHERE mounted.semantic_language='python'
             ORDER BY mounted.persisted_relative_path,reference.start_byte,sites.source_site",
        )?.query_map([], |row| Ok((
            row.get::<_, u32>(0)?, row.get::<_, String>(1)?, row.get::<_, u32>(2)?,
            row.get::<_, usize>(3)?, row.get::<_, usize>(4)?,
        )))?.collect::<rusqlite::Result<Vec<_>>>()?;
        blueprint.with_forward_operation_in_session(
            &source,
            &paths,
            &typed,
            cancellation,
            &session,
            |operation| {
                let mut output = String::new();
                for (identity, path) in root_paths {
                    let token = roots
                        .iter()
                        .find(|(id, _)| *id == identity)
                        .expect("root source token")
                        .1;
                    let completion =
                        operation.prepare_relation_for_test(path.end(), token, &mut provider)?;
                    use std::fmt::Write;
                    let mount = self
                        .mount_table()
                        .mount_for_fragment(identity.fragment())?
                        .expect("root source mount");
                    writeln!(
                        output,
                        "import-root {} complete={} reasons={:?}",
                        mount.persisted_relative_path(),
                        completion == ResolutionCompletion::Complete,
                        named_reason_details(&self.ready, &completion)?,
                    )
                    .expect("String write");
                    for observation in observations.borrow_mut().drain(..) {
                        writeln!(output, "  {observation}").expect("String write");
                    }
                }
                for (ordinal, path, site, start, end) in references {
                    let mount = self
                        .mount_table()
                        .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                    let reference = crate::analyzer::resolution::mounted_site_semantic(
                        mount.fragment(),
                        ResolutionSiteId::new(site),
                    );
                    // Exercise standalone lexical prerequisites without any
                    // requested-root finalization. Invoking references also
                    // depend on argument/runtime inputs outside this proof.
                    let standalone = paths.reference_seed(ResolutionQuery::new(reference), cancellation)?
                        .and_then(|seed| seed.site_metadata())
                        .is_some_and(|metadata| !metadata.is_callable_reference());
                    if standalone {
                        let prerequisite = operation.resolve_prerequisite_for_test(reference, &mut provider)?;
                        if let Some((_, _, Some(entry))) = arena.borrow().selected_universe.get(&reference) {
                            assert!(prerequisite.as_ref().is_some_and(|answer|
                                answer.binding().completion() == &ResolutionCompletion::Complete
                                    && !answer.binding().targets().is_empty()),
                                "selected universe prerequisite must reach Ready: {path}:{start}..{end} {reference:?}; answer={:?}; certificate={:?}", prerequisite.as_ref().map(|answer| answer.binding()), arena.borrow().selected_universe.get(&reference));
                            use std::fmt::Write;
                            writeln!(output, "prerequisite-ready {} {path}:{start}..{end}", entry.identity_spelling).expect("String write");
                        }
                    }
                    let answer =
                        match operation.resolve_reference_by_demand(reference, &mut provider)? {
                            FactDemandResolution::Ready(answer) => answer,
                            FactDemandResolution::Cancelled(completion) => {
                                return Err(StoreError::new(format!(
                                    "Python reference probe cancelled at {path}:{start}..{end} ({reference:?}): {completion:?}; observations={:?}", observations.borrow()
                                )));
                            }
                        };
                    if let Some((owner, _, Some(entry))) = arena.borrow().selected_universe.get(&reference) {
                        use std::fmt::Write;
                        writeln!(output, "universe-certificate {} published={}",
                            entry.identity_spelling,
                            arena.borrow().endpoints.contains_key(owner)).expect("String write");
                    }
                    let mut selected = Vec::new();
                    for target in answer.binding().targets() {
                        if let Some(entry) = crate::analyzer::resolution::universe_entry_for_identity(&paths, *target, cancellation)? {
                            selected.push(format!("predeclared:{}", entry.identity_spelling));
                            continue;
                        }
                        let Some(SelectedSemanticProvenance::FragmentLocal(provenance)) = paths.semantic_provenance(*target, cancellation)? else {
                            return Err(StoreError::corrupt("Python target has no authored provenance"));
                        };
                        let target_mount = self.mount_table().mount_for_fragment(provenance.mount().fragment())?.expect("selected target mount");
                        let node = paths.lookup_definition_node(*target, cancellation)?.expect("selected target definition");
                        let site = paths.definition_source_site(target_mount.ordinal(), node, cancellation)?.flatten().expect("authored target site");
                        let (begin, finish): (usize,usize) = self.ready.inventory.connection().query_row(
                            "SELECT declaration.name_start_byte,declaration.name_end_byte
                             FROM source_native_declaration_bridges bridge
                             JOIN source_declarations declaration ON declaration.blob_id=bridge.blob_id AND declaration.declaration_id=bridge.declaration_id
                             WHERE bridge.blob_id=?1 AND bridge.source_site=?2",
                            rusqlite::params![self.ready.inventory.mount_record_by_ordinal(target_mount.ordinal())?.blob_id(),site.get()], |row| Ok((row.get(0)?,row.get(1)?)),
                        )?;
                        selected.push(format!("{}:{begin}..{finish}",target_mount.persisted_relative_path()));
                    }
                    selected.sort();
                    selected.dedup();
                    // Render the operation's actual reason labels, not a
                    // policy-derived guess. Service reasons have no persisted
                    // source gap row for named_reason_details to read.
                    let mut service_reasons = Vec::new();
                    if let ResolutionCompletion::Incomplete(reasons) = answer.binding().completion() {
                        for reason in reasons.iter() {
                            if let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason
                                && let Some((name, _)) = operation.service_reason_details(*semantic)
                            {
                                service_reasons.push(name);
                            }
                        }
                    }
                    service_reasons.sort_unstable();
                    service_reasons.dedup();
                    let service_reasons = if service_reasons.is_empty() {
                        String::new()
                    } else {
                        format!(" service-reasons={service_reasons:?}")
                    };
                    use std::fmt::Write;
                    writeln!(
                        output,
                        "{path}:{start}..{end} targets={} complete={} reasons={:?}{service_reasons} selected={selected:?}",
                        answer.binding().targets().len(),
                        answer.binding().completion() == &ResolutionCompletion::Complete,
                        named_reason_details(&self.ready, answer.binding().completion())?,
                    )
                    .expect("String write");
                    for observation in observations.borrow_mut().drain(..) {
                        writeln!(output, "  {observation}").expect("String write");
                    }
                }
                Ok(output)
            },
        )
    }
}
