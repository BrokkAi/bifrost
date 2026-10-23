//! Source-owned demand discovery and closure over persisted crate rows.
//!
//! Preparation is an inventory-free handle. Discovery reads the requested
//! endpoint's source halves and row routes; closure reads their exports and
//! reachable re-export relation and publishes one immutable query relation.
//! Outgoing and graph-stage operations share these published binding readers.

use super::super::demand_closure::{
    Admission, DemandRules, EndpointAdmission, Read, RootFrame, SharedDemand,
};
use super::super::source_demand::SourceDemandKey as RustSourceDemandKey;
use super::super::*;
use super::relations::ClosedRelations;
use crate::analyzer::resolution::DemandReferenceKey;
use crate::analyzer::resolution::DemandRelationKey;
use crate::analyzer::resolution::{
    BatchCandidateRequest, DemandRootUnavailableReason, EndpointSignature, FactResolutionAnswer,
    SelectedContextPathSource,
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
}

pub(crate) struct RustRules<'a, 'store, 'input> {
    pub(crate) prepared: &'a PreparedForwardSource<'a, 'store, 'input>,
    pub(crate) arena: &'a RefCell<ClosedRelations>,
    pub(crate) session: &'a ResolutionSession,
    pub(crate) cancellation: &'a CancellationToken,
}

pub(crate) type ForwardProvider<'a, 'store, 'input> =
    SharedDemand<'a, 'store, 'input, RustRules<'a, 'store, 'input>>;

impl<'a, 'store, 'input> ForwardProvider<'a, 'store, 'input> {
    pub(crate) fn new(
        prepared: &'a PreparedForwardSource<'a, 'store, 'input>,
        arena: &'a RefCell<ClosedRelations>,
        session: &'a ResolutionSession,
        cancellation: &'a CancellationToken,
    ) -> Self {
        SharedDemand {
            source_closures: HashMap::default(),
            rules: RustRules {
                prepared,
                arena,
                session,
                cancellation,
            },
            arena,
            paths: prepared.paths,
            ready: prepared.ready,
            base: prepared.base,
            session,
            cancellation,
            completion: &prepared.demand.completion,
        }
    }
}

impl RustRules<'_, '_, '_> {
    pub(super) fn stopped(&self, evidence: &ResolutionCompletion) -> ResolutionCompletion {
        evidence.combine(&crate::analyzer::resolution::cancelled_completion())
    }
}

impl<'a, 'store, 'input> DemandRules for RustRules<'a, 'store, 'input> {
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
                .insert(DemandRelationKey::caller(endpoint.clone()));
        }
    }

    type Placement = crate::analyzer::store::resolution_operation::rust_crate_context::Module;
    type Target = (i64, String, String);
    type Member = (i64, u32, String);
    type Provider = ();
    type MemberRow = ();
    type PlacementObservations = crate::analyzer::store::resolution_operation::demand_closure::CollectedPlacementObservations;
    type Rank = (u32, u32);
    type Half<'b>
        = super::rows::RustHalfRows<'b, 'store, 'input>
    where
        Self: 'b;

    fn half_rows<'b>(
        &'b self,
        source: &'b super::super::demand_closure::SourceHalf,
        frame: &'b RootFrame,
        scopes: &'b crate::analyzer::store::resolution_lexical::NodeSourceScopes,
        lexical: &'b dyn super::super::demand_closure::HalfSource,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<Option<Self::Half<'b>>> {
        super::rows::EndpointRows {
            ready: self.prepared.ready,
            base: self.prepared.base,
            cancellation: self.cancellation,
            session: self.session,
            topologies: &self.prepared.demand.topologies,
        }
        .half(source, frame, scopes, lexical, inputs)
        .map(Some)
    }
    type PreparationKey = ();
    type Certificate = ();
    fn note_closure_work(&self, milestone: &'static str) {
        note_rust_point_work(milestone, self.session);
    }

    fn commit_associations(
        &self,
        associations: &[super::super::demand_closure::ContextAssociation],
    ) {
        use super::super::demand_closure::ContextAssociation;
        for association in associations {
            match association {
                ContextAssociation::ExternalTypeImport { boundary, paths } => self
                    .prepared
                    .ready
                    .context_identities
                    .record_rust_external_type_import_paths(*boundary, paths.iter().cloned()),
                ContextAssociation::PreludeReference {
                    reference,
                    boundary,
                } => self
                    .prepared
                    .ready
                    .context_identities
                    .record_rust_prelude_reference(*reference, *boundary),
            }
        }
    }

    fn closure_policy(
        &self,
        frame: &RootFrame,
        facts: &super::super::demand_closure::ClosureFacts<'_>,
    ) -> Result<Read<super::super::demand_closure::ClosurePolicy>> {
        debug_assert!(facts.halves.iter().all(|half| {
            half.placements
                .iter()
                .all(|placement| half.answered_placements.contains(&placement.placement))
        }));
        use super::super::demand_closure::{BaseEligibility, ClosurePolicy, GeneratedContinuation};
        let generated = facts
            .generated
            .iter()
            .map(|(candidate, source)| {
                let suppress = frame.halves.iter().any(|half| {
                    let SelectedRootPathHalf::Reference {
                        identity,
                        token,
                        demand,
                        prefix_reference: Some(prefix),
                        ..
                    } = half
                    else {
                        return false;
                    };
                    identity.fragment() == source.fragment
                        && *token == source.token
                        && *demand == source.demand
                        && facts.prefixes.entries.iter().any(|answer| {
                            answer.key == DemandReferenceKey::caller(*prefix)
                                && !answer.answer.binding().targets().is_empty()
                        })
                });
                GeneratedContinuation {
                    candidate: *candidate,
                    source: *source,
                    base: if suppress {
                        BaseEligibility::Exclude
                    } else {
                        BaseEligibility::Retain
                    },
                }
            })
            .collect();
        let mut policy = ClosurePolicy::new(
            ResolutionCompletion::Complete,
            BaseEligibility::Retain,
            crate::analyzer::resolution::DemandClosureDischarges::default(),
            generated,
        );
        policy.associations = facts.associations.to_vec();
        Ok(Read::ready(policy))
    }

    fn admit_endpoint(
        &mut self,
        endpoint: &EndpointSignature,
        _already_published: bool,
    ) -> Result<Read<EndpointAdmission>> {
        {
            let arena = self.arena.borrow();
            if let Some(retained) = arena
                .registrations
                .get(&DemandRelationKey::caller(endpoint.clone()))
            {
                assert!(
                    arena
                        .endpoints
                        .contains_key(&DemandRelationKey::caller(endpoint.clone()))
                );
                if matches!(
                    self.prepared.ready.register_context_in_session(
                        &retained.blueprint,
                        self.cancellation,
                        self.session,
                    )?,
                    ContextRegistrationOutcome::Cancelled
                ) {
                    return Ok(Read::Cancelled(self.stopped(&retained.completion)));
                }
                return Ok(Read::ready(EndpointAdmission::Ready(
                    retained.completion.clone(),
                )));
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
                Read::ready(EndpointAdmission::Ready(
                    self.prepared.demand.completion.clone(),
                ))
            } else {
                Read::Unavailable {
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
            return Ok(Read::Cancelled(
                self.stopped(&self.prepared.demand.completion),
            ));
        }
        if let Some((completion, use_base)) = generated {
            if use_base {
                self.arena
                    .borrow_mut()
                    .base_ready
                    .insert(DemandRelationKey::caller(endpoint.clone()));
            } else {
                self.arena
                    .borrow_mut()
                    .excluded_base
                    .insert(DemandRelationKey::caller(endpoint.clone()));
            }
            return Ok(Read::ready(EndpointAdmission::Ready(completion)));
        }
        Ok(Read::ready(EndpointAdmission::Discover))
    }
    fn describe_source(
        &mut self,
        endpoint: &EndpointSignature,
        source: Option<RustSourceDemandKey>,
        halves: Vec<SelectedRootPathHalf>,
        _completion: ResolutionCompletion,
    ) -> Result<Read<Admission>> {
        let Some(source) = source else {
            return Ok(Read::Unavailable {
                reason: DemandRootUnavailableReason::MissingSourceProvenance,
                completion: _completion,
            });
        };
        // Provisional path evidence stays with the base evaluator, which may
        // discharge it using typed facts. Crate rows own closure evidence.
        Ok(Read::ready(Admission::SourceOwned(RootFrame::positioned(
            endpoint, source, halves,
        ))))
    }
    fn root_starts<'b>(
        &self,
        rules: &mut Self::Half<'b>,
        owner: &<Self::Half<'b> as super::super::demand_closure::HalfRules>::Placement,
        facts: &mut super::super::demand_closure::PlacementFacts<
            <Self::Half<'b> as super::super::demand_closure::HalfRules>::Target,
        >,
    ) -> Result<
        Vec<
            super::super::demand_closure::PlacementStart<
                <Self::Half<'b> as super::super::demand_closure::HalfRules>::Member,
            >,
        >,
    >
    where
        Self: 'b,
    {
        super::super::demand_closure::HalfRules::root_starts(rules, owner, facts)
    }
    fn prefix_operands(
        &self,
        frame: &RootFrame,
        caller: super::super::demand_closure::EnvironmentId,
    ) -> Vec<super::super::demand_closure::PrefixOperand> {
        super::super::rust_prefix::rust_prefix_operands(frame, caller)
    }
}
