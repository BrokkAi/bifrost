//! Source-owned demand discovery and closure over persisted crate rows.
//!
//! Preparation is an inventory-free handle. Discovery reads the requested
//! endpoint's source halves and row routes; closure reads their exports and
//! reachable re-export relation and publishes one immutable query relation.
//! The eager topology compiler remains only as an independent test oracle.

use super::super::source_demand::{SourceDemandKey as RustSourceDemandKey, root_source_key};
use super::super::*;
use super::relations::{ClosedEndpointRegistration, ClosedRelations};
use crate::analyzer::resolution::{
    BatchCandidateRequest, DemandRootDiscovery, DemandRootPlan, DemandRootProvider,
    DemandRootUnavailableReason, DemandSelectedOverlayBlueprint, EndpointSignature,
    FactResolutionAnswer, SelectedContextPathSource,
};

/// A demand handle retains no file, crate, profile, or endpoint inventory.
pub(crate) struct RustDemandPreparation {
    pub(crate) completion: ResolutionCompletion,
    /// The Cargo topologies the request is made on behalf of, in topology
    /// order, or empty when it names no crate.
    ///
    /// A file compiled by two Cargo targets has one
    /// `rust_crate_container_sources` row per owning target, and the root
    /// anchor is followed once per row. Without this, a request rooted at one
    /// target still followed `crate::` into the other, so `crate::error` in a
    /// dual-owned module named both the library's `mod error;` and the
    /// binary's, and the reverse could prove neither.
    pub(crate) topologies: Box<[i64]>,
}

impl RustDemandPreparation {
    pub(crate) fn new(topologies: Box<[i64]>) -> Self {
        Self {
            completion: ResolutionCompletion::Complete,
            topologies,
        }
    }
}

/// One request's view of a retained preparation.
///
/// The source borrows the ready selection, caller preparation, and explicit
/// base/context readers after the operation has been consumed by value.
pub(crate) struct PreparedForwardSource<'a, 'store, 'input> {
    pub(crate) ready: &'a ReadySelectedResolution<'store, 'input>,
    pub(crate) demand: &'a RustDemandPreparation,
    pub(crate) base: &'a dyn BatchResolutionFragmentSource,
    pub(crate) paths: &'a dyn SelectedContextPathSource,
}

impl<'a, 'store, 'input> PreparedForwardSource<'a, 'store, 'input> {
    pub(crate) fn mount_table(&self) -> SelectedMountTable<'a, 'store> {
        SelectedMountTable::new(&self.ready.inventory)
    }

    pub(crate) fn new(
        ready: &'a ReadySelectedResolution<'store, 'input>,
        demand: &'a RustDemandPreparation,
        base: &'a dyn BatchResolutionFragmentSource,
        paths: &'a dyn SelectedContextPathSource,
    ) -> Self {
        Self {
            ready,
            demand,
            base,
            paths,
        }
    }

    pub(crate) fn generated_base_endings(
        &self,
        paths: &[(
            CandidatePathIdentity,
            crate::analyzer::resolution::PartialPath,
        )],
        halves: &[SelectedRootPathHalf],
    ) -> Vec<(CandidatePathIdentity, RustSourceDemandKey)> {
        paths
            .iter()
            .filter_map(|(id, path)| {
                if path.end().node() != BindingNodeId::universal_root() {
                    return None;
                }
                // A root terminal the overlay compiler issued for one of this
                // relation's own source halves. Three conditions identify it,
                // and they are conditions rather than assertions because an
                // added path can also end at the universal root as an ordinary
                // bridge continuation: the canonical two-cell (demand, token)
                // terminal shape, a token that belongs to a sealed source half,
                // and a token that is not an Export half's, because no selected
                // bridge starts with this terminal lookup and token.
                //
                // The path's completion is deliberately not one of them. An
                // unresolved route says `UnsupportedSemantic(token)` and a route
                // whose prefix resolved exactly to a module-owned non-module
                // declaration is a complete negative continuation, and both are
                // root terminals of this relation. Whether the endpoint may then
                // read the base relation or is a closed empty is decided by
                // `generated_base_suppressed` from the prefix answers, which is
                // the only place that knows whether authority was established.
                let fixed = path.end().symbols().fixed();
                let [demand, token] = fixed else {
                    return None;
                };
                let source = RustSourceDemandKey {
                    fragment: id.fragment(),
                    demand: demand.symbol(),
                    token: token.symbol(),
                };
                if !halves.iter().any(|half| match half {
                    SelectedRootPathHalf::Import {
                        identity,
                        token,
                        demand,
                        ..
                    }
                    | SelectedRootPathHalf::Reference {
                        identity,
                        token,
                        demand,
                        ..
                    } => {
                        identity.fragment() == source.fragment
                            && *token == source.token
                            && *demand == source.demand
                    }
                    SelectedRootPathHalf::Export { .. } => false,
                }) {
                    return None;
                }
                Some((*id, source))
            })
            .collect()
    }
}

pub(crate) struct ForwardProvider<'a, 'store, 'input> {
    pub(crate) prepared: &'a PreparedForwardSource<'a, 'store, 'input>,
    pub(crate) arena: &'a RefCell<ClosedRelations>,
    pub(crate) session: &'a ResolutionSession,
    pub(crate) cancellation: &'a CancellationToken,
    pub(crate) plans: HashMap<EndpointSignature, super::rows::RowRootPlan>,
    pub(crate) prefix_inputs: Vec<SemanticId>,
}

impl<'a, 'store, 'input> ForwardProvider<'a, 'store, 'input> {
    pub(crate) fn new(
        prepared: &'a PreparedForwardSource<'a, 'store, 'input>,
        arena: &'a RefCell<ClosedRelations>,
        session: &'a ResolutionSession,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            prepared,
            arena,
            session,
            cancellation,
            plans: HashMap::default(),
            prefix_inputs: Vec::new(),
        }
    }
}

impl ForwardProvider<'_, '_, '_> {
    fn stopped(&self, evidence: &ResolutionCompletion) -> ResolutionCompletion {
        evidence.combine(&ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::Cancelled,
        ]))
    }
}

impl DemandRootProvider for ForwardProvider<'_, '_, '_> {
    fn reverse_dependencies(
        &mut self,
        endpoint: &EndpointSignature,
    ) -> Result<Vec<EndpointSignature>> {
        let mut identities = Vec::new();
        let mut terminals = Vec::new();
        let provenance = self
            .prepared
            .ready
            .inventory
            .mount_rebaser()
            .borrow()
            .node_mount(endpoint.node());
        // Ordinary selected mounts carry canonical declaration authority,
        // including replacement content that has no persisted crate exports.
        let selected_mount = match provenance {
            Some(crate::analyzer::resolution::SelectedNodeMount::FragmentLocal(mount)) => self
                .prepared
                .ready
                .inventory
                .persisted_mount_record(mount.ordinal())?
                .map(|record| (mount.ordinal(), record.blob_id())),
            _ => None,
        };
        if let Some((mount, blob_id)) = selected_mount {
            // The declaration's source site and the export namespaces it is
            // reachable under come from its selected canonical root halves.
            let source = self.prepared.ready.lexical_source();
            let Some(site) =
                source.definition_source_site(mount, endpoint.node(), self.cancellation)?
            else {
                return Err(StoreError::new("cancelled reading reverse export names"));
            };
            let (site, halves) = match site {
                Some(site) => (
                    i64::from(site.get()),
                    source
                        .root_export_halves(mount, site, self.cancellation)?
                        .ok_or_else(|| StoreError::new("cancelled reading reverse export names"))?,
                ),
                None => (0, Vec::new()),
            };
            let mut export_namespaces = halves
                .iter()
                .filter(|half| half.canonical_export_shape)
                .map(|half| match half.recipe.namespace() {
                    ResolutionNamespace::Type => "type",
                    ResolutionNamespace::Macro => "macro",
                    _ => "value",
                })
                .collect::<Vec<_>>();
            export_namespaces.sort_unstable();
            export_namespaces.dedup();
            for export_namespace in export_namespaces {
                for row in self
                    .prepared
                    .ready
                    .inventory
                    .connection()
                    .prepare_cached(super::rows::REVERSE_EXPORTED_NAMES)?
                    .query_map(
                        rusqlite::params![blob_id, site, export_namespace, mount.get()],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )?
                {
                    let (namespace, name) = row?;
                    // Crate rows use Rust's three export namespaces. Native
                    // callable and constructor demands refine the value
                    // namespace; nominate each refinement and let forward
                    // closure certify it.
                    let namespaces: &[ResolutionNamespace] = match namespace.as_str() {
                        "type" => &[ResolutionNamespace::Type],
                        "value" => &[
                            ResolutionNamespace::Value,
                            ResolutionNamespace::Callable,
                            ResolutionNamespace::Constructor,
                        ],
                        "macro" => &[ResolutionNamespace::Macro],
                        _ => unreachable!("crate export namespace constraint"),
                    };
                    for &namespace in namespaces {
                        let recipe =
                            ResolutionLookupSemanticRecipe::new(Language::Rust, namespace, &name);
                        terminals.push(
                            self.prepared
                                .ready
                                .inventory
                                .mount_rebaser()
                                .borrow_mut()
                                .register_shared_semantic(
                                    recipe.identity(&self.prepared.ready.shared_names()),
                                ),
                        );
                    }
                }
            }
        }
        if endpoint.node() == BindingNodeId::universal_root()
            && let Some(symbol) = endpoint.symbols().fixed().first()
            && matches!(
                self.prepared
                    .ready
                    .inventory
                    .mount_rebaser()
                    .borrow()
                    .semantic_mount(symbol.symbol()),
                crate::analyzer::resolution::SelectedSemanticMount::Shared(_)
            )
        {
            terminals.push(symbol.symbol());
        }
        // Declarations without a crate placement can still supply a
        // source-issued lookup identity through their native export half.
        if terminals.is_empty() {
            let anchors = self.prepared.ready.lexical_source();
            self.prepared.base.visit_reverse_candidate_match_pages(
                &[BatchCandidateRequest::new(0, endpoint.clone())],
                self.cancellation,
                &mut |page| {
                    let ids = page.iter().map(|row| row.candidate()).collect::<Vec<_>>();
                    for (identity, path) in self
                        .prepared
                        .base
                        .hydrate_candidate_paths(&ids, self.cancellation)?
                    {
                        if let Some(SelectedRootPathHalf::Export { demand, .. }) =
                            classify_selected_root_path_half(
                                &anchors,
                                identity,
                                &path,
                                self.cancellation,
                            )?
                        {
                            terminals.push(demand);
                        }
                    }
                    Ok(!self.cancellation.is_cancelled())
                },
            )?;
        }
        terminals.sort_unstable();
        terminals.dedup();
        for page in terminals.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            identities.extend(super::inventory::terminal_halves(
                self.prepared.ready,
                page,
                self.cancellation,
            )?);
        }
        identities.sort_unstable();
        identities.dedup();
        let mut endpoints = Vec::with_capacity(identities.len());
        for page in identities.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            let paths = self
                .prepared
                .base
                .hydrate_candidate_paths(page, self.cancellation)?;
            if self.cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            endpoints.extend(paths.into_iter().map(|(_, path)| path.end().clone()));
        }
        Ok(endpoints)
    }

    fn close_reverse(&mut self, endpoint: &EndpointSignature) {
        if !self.cancellation.is_cancelled() {
            self.arena
                .borrow_mut()
                .reverse_endpoints
                .insert(endpoint.clone());
        }
    }

    fn discover(&mut self, endpoint: &EndpointSignature) -> Result<DemandRootDiscovery> {
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(DemandRootDiscovery::Cancelled(
                self.stopped(&self.prepared.demand.completion),
            ));
        }
        {
            let arena = self.arena.borrow();
            if let Some(retained) = arena.registrations.get(endpoint) {
                assert!(arena.endpoints.contains_key(endpoint));
                if matches!(
                    self.prepared.ready.register_context_in_session(
                        &retained.blueprint,
                        self.cancellation,
                        self.session,
                    )?,
                    ContextRegistrationOutcome::Cancelled
                ) {
                    return Ok(DemandRootDiscovery::Cancelled(
                        self.stopped(&retained.completion),
                    ));
                }
                return Ok(DemandRootDiscovery::AlreadyReady {
                    completion: retained.completion.clone(),
                });
            }
        }
        if endpoint.node() != BindingNodeId::universal_root() {
            // Local candidate relations are already immutable, but only a
            // node actually issued by this selected base owns that authority.
            let known_local = matches!(
                self.prepared
                    .ready
                    .inventory
                    .mount_rebaser()
                    .borrow()
                    .node_mount(endpoint.node()),
                Some(crate::analyzer::resolution::SelectedNodeMount::FragmentLocal(_))
            );
            return Ok(if known_local {
                DemandRootDiscovery::AlreadyReady {
                    completion: self.prepared.demand.completion.clone(),
                }
            } else {
                DemandRootDiscovery::Unavailable {
                    reason: DemandRootUnavailableReason::MissingSourceProvenance,
                    completion: self.prepared.demand.completion.clone(),
                }
            });
        }
        let generated = self
            .arena
            .borrow()
            .generated_base_completion(endpoint, self.session);
        if self.cancellation.is_cancelled() || !self.session.observe_cancellation() {
            return Ok(DemandRootDiscovery::Cancelled(
                self.stopped(&self.prepared.demand.completion),
            ));
        }
        if let Some((completion, use_base)) = generated {
            if use_base {
                self.arena.borrow_mut().base_ready.insert(endpoint.clone());
            } else {
                self.arena.borrow_mut().empty_ready.insert(endpoint.clone());
            }
            return Ok(DemandRootDiscovery::AlreadyReady { completion });
        }
        note_rust_point_work("demand_discover_generated", self.session);
        if let Some(plan) = self.plans.get(endpoint) {
            return Ok(DemandRootDiscovery::Ready(DemandRootPlan {
                prefixes: plan
                    .prefixes
                    .iter()
                    .map(|operand| operand.reference)
                    .collect(),
                completion: plan.completion.clone(),
            }));
        }
        let key = root_source_key(
            self.prepared.ready,
            self.prepared.base,
            endpoint,
            self.session,
            self.cancellation,
        )?;
        note_rust_point_work("demand_discover_source_key", self.session);
        let Some(source) = key else {
            if self.cancellation.is_cancelled() || !self.session.observe_cancellation() {
                return Ok(DemandRootDiscovery::Cancelled(
                    self.stopped(&self.prepared.demand.completion),
                ));
            }
            return Ok(DemandRootDiscovery::Unavailable {
                reason: DemandRootUnavailableReason::MissingSourceProvenance,
                completion: self.prepared.demand.completion.clone(),
            });
        };
        let mut halves = Vec::new();
        let anchors = self.prepared.ready.lexical_source();
        let coverage = self
            .prepared
            .base
            .visit_reverse_root_candidate_match_pages(
                &[BatchCandidateRequest::new(0, endpoint.clone())],
                None,
                self.cancellation,
                &mut |page| {
                    let ids = page.iter().map(|row| row.candidate()).collect::<Vec<_>>();
                    for (id, path) in self
                        .prepared
                        .base
                        .hydrate_candidate_paths(&ids, self.cancellation)?
                    {
                        let Some(half) = classify_selected_root_path_half(
                            &anchors,
                            id,
                            &path,
                            self.cancellation,
                        )?
                        else {
                            continue;
                        };
                        let key = match &half {
                            SelectedRootPathHalf::Import {
                                identity,
                                token,
                                demand,
                                ..
                            }
                            | SelectedRootPathHalf::Reference {
                                identity,
                                token,
                                demand,
                                ..
                            } => RustSourceDemandKey {
                                fragment: identity.fragment(),
                                token: *token,
                                demand: *demand,
                            },
                            _ => continue,
                        };
                        if key == source {
                            // The evaluator owns a source path's provisional
                            // evidence and may discharge it using typed facts.
                            // The route must not copy it into its new bridge.
                            halves.push(half);
                        }
                    }
                    Ok(!self.cancellation.is_cancelled() && self.session.scope_step())
                },
            )?;
        if self.cancellation.is_cancelled()
            || coverage
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        {
            return Ok(DemandRootDiscovery::Cancelled(
                self.stopped(coverage.unconditional_completion()),
            ));
        }
        let plan = super::rows::RowRootPlan {
            prefixes: halves
                .iter()
                .filter_map(super::super::rust_prefix::rust_qualified_prefix)
                .collect(),
            halves,
            // The base reader owns its candidate coverage. This relation
            // contributes only the evidence established by its crate rows.
            completion: ResolutionCompletion::Complete,
        };
        let prefixes = plan
            .prefixes
            .iter()
            .map(|operand| operand.reference)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let completion = plan.completion.clone();
        note_rust_point_work("demand_discover_plan", self.session);
        assert!(self.plans.insert(endpoint.clone(), plan).is_none());
        Ok(DemandRootDiscovery::Ready(DemandRootPlan {
            prefixes,
            completion,
        }))
    }

    fn close(
        &mut self,
        endpoint: &EndpointSignature,
        inputs: &[(SemanticId, &FactResolutionAnswer)],
    ) -> Result<ResolutionCompletion> {
        if let Some(retained) = self.arena.borrow().registrations.get(endpoint) {
            return Ok(retained.completion.clone());
        }
        let plan = self
            .plans
            .get(endpoint)
            .expect("only discovered relations may close");
        let expected = plan
            .prefixes
            .iter()
            .map(|operand| operand.reference)
            .collect::<BTreeSet<_>>();
        let actual = inputs
            .iter()
            .map(|(reference, _)| *reference)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            expected, actual,
            "materialization requires every full prefix answer"
        );
        assert_eq!(
            inputs.len(),
            actual.len(),
            "prefix operands form an exact bijection"
        );
        let mut evidence = plan.completion.clone();
        for (_, answer) in inputs {
            evidence = evidence.combine(answer.completion());
        }
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(self.stopped(&evidence));
        }
        let rows = super::rows::EndpointRows {
            ready: self.prepared.ready,
            base: self.prepared.base,
            cancellation: self.cancellation,
            topologies: &self.prepared.demand.topologies,
        };
        let Some(descriptors) = rows.close(plan, inputs)? else {
            return Ok(self.stopped(&evidence));
        };
        for descriptor in &descriptors {
            evidence = evidence.combine(descriptor.completion());
        }
        note_rust_point_work("demand_close_prefix_bridges", self.session);
        // Register with the existing selected owner, including exact local
        // anchor keys. Build the readable overlay and retained registration
        // once; subsequent requests reuse the closed endpoint relation.
        // Crate gap evidence is issued by this endpoint's row reader. Register
        // those identities with the context, just as the crate point reader
        // does; they have no persisted fragment-local semantic coordinate.
        let mut inventory_completion = self.prepared.demand.completion.clone();
        let mut owned_reasons = BTreeSet::new();
        for descriptor in &descriptors {
            if let ResolutionCompletion::Incomplete(reasons) = descriptor.completion() {
                for reason in reasons.iter() {
                    if let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason
                        && !self
                            .prepared
                            .ready
                            .inventory
                            .mount_rebaser()
                            .borrow()
                            .issued_semantic(*semantic)
                    {
                        owned_reasons.insert(*semantic);
                        inventory_completion = inventory_completion
                            .combine(&ResolutionCompletion::incomplete([*reason]));
                    }
                }
            }
        }
        let selected_mount_of = selected_mount_lookup(self.prepared.mount_table());
        let mut contexts = empty_contexts_for(
            self.prepared.mount_table(),
            &inventory_completion,
            &selected_mount_of,
            self.prepared.ready.context_identities.clone(),
        )?;
        for reason in owned_reasons {
            contexts = contexts.with_context_owned_inventory_reason(reason);
        }
        let contexts = contexts.extend_root_bridges(
            descriptors,
            self.cancellation,
            Some(self.session),
            &selected_mount_of,
        )?;
        let Some(contexts) = contexts else {
            return Ok(self.stopped(&evidence));
        };
        let SelectedResolutionContextValidationOutcome::Ready(contexts) = contexts
            .validate_exact_mounts_in_session(
                self.prepared.mount_table().mount_count(),
                &selected_mount_lookup(self.prepared.mount_table()),
                self.cancellation,
                self.session,
            )?
        else {
            return Ok(self.stopped(&evidence));
        };
        let SelectedFactOperationBlueprintConstruction::Ready(registration) =
            self.prepared.ready.collect_blueprint_in_session(
                contexts,
                self.cancellation,
                self.session,
            )?
        else {
            return Ok(self.stopped(&evidence));
        };
        if matches!(
            self.prepared.ready.register_context_in_session(
                &registration,
                self.cancellation,
                self.session
            )?,
            ContextRegistrationOutcome::Cancelled
        ) {
            return Ok(self.stopped(&evidence));
        }
        note_rust_point_work("demand_close_register_context", self.session);
        let relation = DemandSelectedOverlayBlueprint::new(registration.context_token());
        let Some(paths) = relation.added_candidate_paths(self.prepared.paths, self.cancellation)?
        else {
            return Ok(self.stopped(&evidence));
        };
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(self.stopped(&evidence));
        }
        let generated = self.prepared.generated_base_endings(&paths, &plan.halves);
        let prefix_has_target = inputs
            .iter()
            .map(|(reference, answer)| (*reference, !answer.binding().targets().is_empty()))
            .collect::<HashMap<_, _>>();
        {
            let mut arena = self.arena.borrow_mut();
            assert!(!evidence.contains_reason(ResolutionIncompleteReason::Cancelled));
            arena.publish(endpoint.clone(), relation, paths);
            assert!(
                arena
                    .registrations
                    .insert(
                        endpoint.clone(),
                        ClosedEndpointRegistration {
                            blueprint: registration,
                            completion: evidence.clone(),
                        }
                    )
                    .is_none(),
                "one endpoint closes once per retained selection"
            );
            for (id, source) in generated {
                let plan = self.plans.get(endpoint).unwrap();
                let matching_prefixes = plan.halves.iter().filter_map(|half| {
                    let SelectedRootPathHalf::Reference {
                        identity,
                        token,
                        demand,
                        prefix_reference,
                        ..
                    } = half
                    else {
                        return None;
                    };
                    (RustSourceDemandKey {
                        fragment: identity.fragment(),
                        token: *token,
                        demand: *demand,
                    } == source)
                        .then_some(*prefix_reference)
                        .flatten()
                });
                if matching_prefixes
                    .into_iter()
                    .any(|prefix| prefix_has_target[&prefix])
                {
                    arena.generated_base_suppressed.insert(id);
                }
                let fixed = arena.paths[&id].end().symbols().fixed();
                let key = (fixed[0].symbol(), fixed[1].symbol());
                let bucket = arena.generated_base_endings.entry(key).or_default();
                if !bucket.contains(&id) {
                    bucket.push(id);
                }
            }
        }
        note_rust_point_work("demand_close_published", self.session);
        self.prefix_inputs
            .extend(inputs.iter().map(|(reference, _)| *reference));
        Ok(evidence)
    }
}
