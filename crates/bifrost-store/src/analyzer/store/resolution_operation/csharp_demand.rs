//! Point-owned source type lookup through the shared demand closer.
use super::csharp_imports::CSharpImportPrecedence as Rank;
use super::csharp_namespaces::{CSharpNamespaceLevel, namespace_members};
use super::csharp_units::{CSharpUnitPlacement, CSharpUnitReader};
use super::demand_closure::*;
use super::package_context::SelectedPackageRows;
use super::*;
use crate::analyzer::resolution::{
    DemandReferenceKey, DemandRootUnavailableReason, EndpointSignature, FactResolutionAnswer,
    LoweredPackageReference,
};
use crate::analyzer::store::WorkspaceSnapshotId;
use crate::analyzer::store::resolution_lexical::NodeSourceScopes;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

// A package scope has a route row: the global namespace yields one NULL
// segment through the LEFT JOIN. No route row means a type or block scope.
pub const NAMESPACE_ROUTE: &str = "SELECT s.spelling FROM main.resolution_package_routes r
 LEFT JOIN main.resolution_package_route_segments s ON s.blob_id=r.blob_id AND s.package_scope_node_key=r.package_scope_node_key
 WHERE r.blob_id=?1 AND r.package_scope_node_key=?2 ORDER BY s.ordinal";

// C1-3 records each using directive at its declaration's scope.
pub const HAS_USING_DIRECTIVES: &str = "SELECT EXISTS(SELECT 1 FROM main.resolution_root_imports
 INDEXED BY resolution_root_imports_binding WHERE blob_id=?1 AND root_scope=?2)";

// The declaration extractor records only authored base-list entries here.
pub const TYPE_WITH_EXPLICIT_BASES: &str = "SELECT unit.identifier
 FROM main.resolution_member_scope_properties AS scope
 CROSS JOIN main.resolution_semantic_sites AS semantic
 ON semantic.blob_id=scope.blob_id AND semantic.semantic_key=scope.definition_semantic_key AND semantic.semantic_role='definition'
 CROSS JOIN main.source_native_declaration_bridges AS native
 ON native.blob_id=semantic.blob_id AND native.source_site=semantic.source_site
 CROSS JOIN main.source_declaration_units AS mapping
 ON mapping.blob_id=native.blob_id AND mapping.declaration_id=native.declaration_id
 CROSS JOIN main.code_units AS unit ON unit.blob_id=mapping.blob_id AND unit.unit_key=mapping.unit_key
 WHERE scope.blob_id=?1 AND scope.scope_head_node_key=?2 AND scope.scope_kind='type_body'
 AND EXISTS(SELECT 1 FROM main.unit_supertypes AS base
 WHERE base.blob_id=unit.blob_id AND base.unit_key=unit.unit_key)";

/// One unmodeled lookup tier, retained with its structured level for C1-4d.
#[derive(Clone, Debug)]
pub struct CSharpUsingTierGap {
    pub reason: SemanticId,
    pub source: BindingFragmentId,
    pub source_half: CandidatePathIdentity,
    pub scope: ResolutionScopeId,
    pub compilation_id: i64,
    /// None denotes the compilation unit; Some contains namespace segments.
    pub namespace: Option<Vec<String>>,
}

struct CSharpCallerDemand;
struct CSharpDemandInstaller;

/// Point-owned C# construction over the selected compilation and held connection.
pub const CSHARP_DEMAND_INSTALLER: NativeDemandInstaller =
    NativeDemandInstaller(&CSharpDemandInstaller);

impl DemandInstall for CSharpDemandInstaller {
    fn prepare_caller(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        caller: &Path,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
    ) -> Result<NativeDemandPreparationOutcome> {
        if cancellation.is_cancelled() || session.is_some_and(|session| !session.scope_step()) {
            return Ok(NativeDemandPreparationOutcome::Cancelled);
        }
        let ready = &operation.ready;
        let available = match ready.snapshot("csharp") {
            Some(snapshot) => {
                match super::super::csharp_compilation::CSharpCompilationView::selected(
                    ready.inventory.connection(),
                    snapshot,
                )? {
                    Some(view) => view
                        .compilations_of(
                            caller.to_str().expect("persisted caller paths are UTF-8"),
                        )?
                        .is_some(),
                    None => false,
                }
            }
            None => false,
        };
        if cancellation.is_cancelled() || session.is_some_and(|session| !session.scope_step()) {
            return Ok(NativeDemandPreparationOutcome::Cancelled);
        }
        // Some(empty) membership is proven and remains ready. Retain no rows.
        Ok(if available {
            NativeDemandPreparationOutcome::Ready(Arc::new(CSharpCallerDemand))
        } else {
            NativeDemandPreparationOutcome::Unavailable
        })
    }

    fn run_point(
        &self,
        preparation: &dyn std::any::Any,
        request: NativeDemandPointRequest<'_, '_, '_>,
        run: &mut NativeDemandCallback<'_>,
    ) -> Result<()> {
        use super::demand::{ClosedForwardSource, ClosedRelations, DemandProvider};
        assert!(
            preparation.is::<CSharpCallerDemand>(),
            "C# owns its caller preparation"
        );
        let NativeDemandPointRequest {
            ready,
            blueprint,
            lexical,
            paths,
            typed,
            cancellation,
            session,
            artifacts,
        } = request;
        let snapshot = ready
            .snapshot("csharp")
            .expect("caller preparation selected C# metadata");
        let arena = RefCell::new(ClosedRelations::default());
        let source = ClosedForwardSource::new(
            lexical,
            paths,
            &arena,
            session,
            crate::analyzer::resolution::CALLER_ENVIRONMENT,
        );
        let using_gaps = RefCell::new(Vec::new());
        let external_gaps = RefCell::new(Vec::new());
        #[cfg(any(test, feature = "test-support"))]
        let visited = RefCell::new(Vec::new());
        let rules = CSharpRules {
            ready,
            snapshot,
            base: lexical,
            cancellation,
            session,
            using_gaps: &using_gaps,
            external_gaps: &external_gaps,
            arena: &arena,
            #[cfg(any(test, feature = "test-support"))]
            visited: &visited,
        };
        let shared = SharedDemand {
            source_closures: HashMap::default(),
            rules,
            arena: &arena,
            paths,
            ready,
            projection_memo: None,
            base: lexical,
            session,
            cancellation,
            completion: &ResolutionCompletion::Complete,
        };
        let mut provider = DemandProvider::new(shared);
        match artifacts {
            Some(artifacts) => blueprint.with_forward_operation_in_session_using_artifacts(
                &source,
                paths,
                typed,
                ForwardOperationArtifactContext {
                    cancellation,
                    session,
                    artifacts,
                },
                |operation| run(operation, &mut provider),
            ),
            None => blueprint.with_forward_operation_in_session(
                &source,
                paths,
                typed,
                cancellation,
                session,
                |operation| run(operation, &mut provider),
            ),
        }
    }
}

struct CSharpRules<'a, 'store, 'input> {
    ready: &'a ReadySelectedResolution<'store, 'input>,
    snapshot: &'a WorkspaceSnapshotId,
    base: &'a dyn BatchResolutionFragmentSource,
    cancellation: &'a CancellationToken,
    session: &'a ResolutionSession,
    using_gaps: &'a RefCell<Vec<CSharpUsingTierGap>>,
    external_gaps: &'a RefCell<Vec<(CandidatePathIdentity, SemanticId)>>,
    arena: &'a RefCell<super::demand::ClosedRelations>,
    #[cfg(any(test, feature = "test-support"))]
    visited: &'a RefCell<Vec<Option<Vec<String>>>>,
}
struct CSharpHalf<'a, 'store, 'input> {
    rules: &'a CSharpRules<'a, 'store, 'input>,
    source: &'a SourceHalf,
    fragment: BindingFragmentId,
    scope: ResolutionScopeId,
    placements: Vec<CSharpUnitPlacement>,
    units: RefCell<CSharpUnitReader<'a, 'store>>,
    references: Vec<LoweredPackageReference>,
}
impl<'store, 'input> DemandRules for CSharpRules<'_, 'store, 'input> {
    type Placement = CSharpUnitPlacement;
    type Target = RouteLocation;
    type Member = ();
    type Provider = ();
    type MemberRow = ();
    type PlacementObservations = CollectedPlacementObservations;
    type Rank = Rank;
    type Half<'a>
        = CSharpHalf<'a, 'store, 'input>
    where
        Self: 'a;
    type PreparationKey = ();
    type Certificate = ();
    fn describe_source(
        &mut self,
        endpoint: &EndpointSignature,
        source: Option<super::source_demand::SourceDemandKey>,
        halves: Vec<SelectedRootPathHalf>,
        completion: ResolutionCompletion,
    ) -> Result<Read<Admission>> {
        Ok(match source {
            Some(source) => Read::ready(Admission::SourceOwned(RootFrame::positioned(
                endpoint, source, halves,
            ))),
            None => Read::Unavailable {
                reason: DemandRootUnavailableReason::MissingSourceProvenance,
                completion,
            },
        })
    }
    fn admit_endpoint(
        &mut self,
        endpoint: &EndpointSignature,
        retained_completion: Option<&ResolutionCompletion>,
    ) -> Result<Read<EndpointAdmission>> {
        if let Some(completion) = retained_completion {
            return Ok(Read::ready(EndpointAdmission::Ready(completion.clone())));
        }
        if endpoint.node() != BindingNodeId::universal_root() {
            return Ok(Read::ready(EndpointAdmission::Ready(
                ResolutionCompletion::Complete,
            )));
        }
        let generated = self
            .arena
            .borrow()
            .generated_base_completion(endpoint, self.session);
        if self.cancellation.is_cancelled() || !self.session.observe_cancellation() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        // A generated terminal reuses its owning source route's coverage.
        Ok(Read::ready(match generated {
            Some((completion, use_base)) => EndpointAdmission::Context(Admission::BaseOwned {
                completion,
                base: if use_base {
                    BaseEligibility::Retain
                } else {
                    BaseEligibility::Exclude
                },
            }),
            None => EndpointAdmission::Discover,
        }))
    }
    fn closure_policy(
        &self,
        _: &RootFrame,
        facts: &ClosureFacts<'_>,
    ) -> Result<Read<ClosurePolicy>> {
        let mut policy = candidate_closure_policy(facts);
        // Every targetless C# route is open: boundary always supplies a named
        // reason. Excluding a generated terminal's base therefore cannot turn
        // an open terminal into a complete negative. C1-4d must re-check this
        // invariant when narrowing the using barrier.
        policy.generated = facts
            .generated
            .iter()
            .map(|(candidate, source)| GeneratedContinuation {
                candidate: *candidate,
                source: *source,
                base: BaseEligibility::Exclude,
            })
            .collect();
        Ok(Read::ready(policy))
    }
    fn half_rows<'a>(
        &'a self,
        source: &'a SourceHalf,
        _frame: &'a RootFrame,
        scopes: &'a NodeSourceScopes,
        _lexical: &'a dyn HalfSource,
        _inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<Option<Self::Half<'a>>> {
        if source.anchor != ResolutionRootImportAnchor::Lexical
            || source.prefix.is_some()
            || source.is_import
            || !source.route.is_empty()
            || source.demand.namespace() != ResolutionNamespace::Type
        {
            return Ok(None);
        }
        let Some(Some((fragment, scope))) = scopes.get(&source.scope) else {
            return Ok(None);
        };
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(fragment.ordinal()))?;
        let mut units = CSharpUnitReader::new(
            &self.ready.inventory,
            self.snapshot,
            &self.ready.context_identities,
        )?;
        let Some(placements) = units.placements(record.persisted_relative_path())? else {
            return Ok(None);
        };
        // Root and package tokens have distinct identity domains. Read the
        // package metadata through the root half's structured reference site.
        let Some((_, path)) = self
            .base
            .hydrate_candidate_paths(&[source.identity], self.cancellation)?
            .pop()
        else {
            return Ok(None);
        };
        let Some(reference) = self
            .base
            .classify_endpoint_nodes(&[path.start().node()], self.cancellation)?
            .into_iter()
            .find_map(|row| row.reference())
        else {
            return Ok(None);
        };
        let SelectedPackageRows::Ready(references) = self
            .ready
            .selected_package_reference_for_site(record.ordinal(), reference, self.cancellation)?
        else {
            return Ok(None);
        };
        Ok(Some(CSharpHalf {
            rules: self,
            source,
            fragment: *fragment,
            scope: *scope,
            placements,
            units: RefCell::new(units),
            references: references
                .into_iter()
                .filter(|reference| reference.namespace == source.demand.namespace())
                .collect(),
        }))
    }
}
impl HalfRules for CSharpHalf<'_, '_, '_> {
    type Placement = CSharpUnitPlacement;
    type Target = RouteLocation;
    type Member = ();
    type Provider = ();
    type MemberRow = ();
    type Rank = Rank;
    type LexicalTiers = Vec<LexicalStartTier<Rank, ()>>;
    fn language(&self) -> Language {
        Language::CSharp
    }
    fn placements(&mut self) -> Vec<Self::Placement> {
        std::mem::take(&mut self.placements)
    }
    fn source_endpoint_completion(
        &self,
        source: &SourceHalf,
        _: &EndpointSignature,
        _: &ReadySelectedResolution<'_, '_>,
    ) -> Option<ResolutionCompletion> {
        let mut reasons = self
            .rules
            .using_gaps
            .borrow()
            .iter()
            .filter(|gap| gap.source_half == source.identity)
            .map(|gap| ResolutionIncompleteReason::UnsupportedSemantic(gap.reason))
            .collect::<Vec<_>>();
        reasons.extend(
            self.rules
                .external_gaps
                .borrow()
                .iter()
                .filter(|(half, _)| *half == source.identity)
                .map(|(_, reason)| ResolutionIncompleteReason::UnsupportedSemantic(*reason)),
        );
        (!reasons.is_empty()).then(|| ResolutionCompletion::incomplete(reasons))
    }
    fn placement(
        &self,
        _: &Self::Placement,
        tag: ClosureTag,
    ) -> Option<PlacementFacts<Self::Target>> {
        Some(PlacementFacts {
            tag,
            completion: ResolutionCompletion::Complete,
            targets: Vec::new(),
            members: Vec::new(),
        })
    }
    fn root_starts(
        &mut self,
        _: &Self::Placement,
        _: &mut PlacementFacts<Self::Target>,
    ) -> Result<Vec<PlacementStart<(), Rank>>> {
        Ok(Vec::new())
    }
    fn lexical_parent(
        &self,
        _: &Self::Placement,
        scope: ResolutionScopeId,
    ) -> Result<Option<ResolutionScopeId>> {
        self.rules.ready.lexical_source().lookup_scope_parent(
            self.fragment,
            scope,
            self.rules.cancellation,
        )
    }
    fn lexical_tier(
        &self,
        placement: &Self::Placement,
        scope: ResolutionScopeId,
        depth: u32,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Read<Self::LexicalTiers>> {
        let rules = self.rules;
        let lexical = rules.ready.lexical_source();
        let Some(head) = lexical.scope_head_node_of(self.fragment, scope, rules.cancellation)?
        else {
            return Ok(Read::Cancelled(cancelled_completion()));
        };
        let mount =
            rules
                .ready
                .inventory
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(
                    self.fragment.ordinal(),
                ))?;
        let path = rules
            .ready
            .inventory
            .connection()
            .prepare_cached(NAMESPACE_ROUTE)?
            .query_map(
                rusqlite::params![mount.blob_id(), head.local_key()],
                |row| row.get::<_, Option<String>>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut tier = RouteEdgeTier::default();
        if !path.is_empty() {
            let path = path.into_iter().flatten().collect::<Vec<_>>();
            #[cfg(any(test, feature = "test-support"))]
            rules.visited.borrow_mut().push(Some(path.clone()));
            let sources = [CSharpNamespaceLevel {
                caller: placement.clone(),
                path: path.clone(),
            }];
            let SelectedPackageRows::Ready(targets) = namespace_members(
                rules.ready,
                &self.units,
                self.fragment,
                &sources,
                &self.references,
                rules.cancellation,
            )?
            else {
                return Ok(Read::Cancelled(cancelled_completion()));
            };
            for target in targets {
                tier.coverage = tier.coverage.combine(&target.completion);
                tier.edges.push(RouteLocation::Owner {
                    definition: target.member.definition,
                    scope: None,
                });
            }
            if tier.edges.is_empty() {
                // A namespace miss cannot exclude a type in an unindexed
                // assembly. Keep searching outward, retaining this obligation.
                // A source match stays closed: it wins over an imported type
                // with warning CS0436.
                self.record_obligation(
                    scope,
                    "csharp_external_unindexed",
                    &format!(
                        "{}: {} is not declared in source {}",
                        mount.persisted_relative_path(),
                        self.source.demand.spelling(),
                        if path.is_empty() {
                            "the global namespace".to_owned()
                        } else {
                            format!("namespace {}", path.join("."))
                        },
                    ),
                );
            }
            if tier.edges.is_empty()
                && (path.is_empty()
                    || rules
                        .ready
                        .inventory
                        .connection()
                        .prepare_cached(HAS_USING_DIRECTIVES)?
                        .query_row(rusqlite::params![mount.blob_id(), scope.get()], |row| {
                            row.get::<_, bool>(0)
                        })?)
            {
                // No indexed authored-global-using extent exists by compilation.
                // Until C1-4d, every empty compilation-unit tier remains open.
                // Extern aliases introduce namespace aliases, not type binders.
                // Do not open inner tiers for arbitrary UnknownBinder gaps:
                // an outer extern alias cannot outrank an inner member. The
                // open compilation-unit tier also covers a same-named extern;
                // namespace-body extern syntax awaits tree-sitter-c-sharp#5.
                let namespace = (!path.is_empty()).then_some(path);
                let evidence = format!("{}:{namespace:?}", mount.persisted_relative_path());
                let mut hash = CanonicalHasher::new(b"csharp-using-tier-unmodeled:v1");
                hash.field("scope", evidence.as_bytes());
                hash.field("source_scope", &scope.get().to_le_bytes());
                hash.field("compilation", &placement.compilation_id.to_le_bytes());
                let reason = rules.ready.context_identities.named_semantic(
                    hash.finish(),
                    "csharp_using_tier_unmodeled",
                    &evidence,
                );
                rules.using_gaps.borrow_mut().push(CSharpUsingTierGap {
                    reason,
                    source: self.fragment,
                    source_half: self.source.identity,
                    scope,
                    compilation_id: placement.compilation_id,
                    namespace,
                });
                tier.coverage = tier.coverage.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(reason),
                ]));
            }
        } else {
            #[cfg(any(test, feature = "test-support"))]
            rules.visited.borrow_mut().push(None);
            let semantic = lookup.semantic(&rules.ready.shared_names());
            let Some((paths, completion)) =
                scope_binding_paths(rules.base, head, semantic, rules.cancellation)?
            else {
                return Ok(Read::Cancelled(cancelled_completion()));
            };
            tier.coverage = completion;
            for path in paths {
                if !path.end().symbols().fixed().is_empty() {
                    continue;
                }
                for row in rules
                    .base
                    .classify_endpoint_nodes(&[path.end().node()], rules.cancellation)?
                {
                    if let Some(definition) = row.definition() {
                        tier.coverage = tier.coverage.combine(path.completion());
                        tier.edges.push(RouteLocation::Owner {
                            definition,
                            scope: Some(path.end().node()),
                        });
                    }
                }
            }
            if tier.edges.is_empty() {
                let mut statement = rules
                    .ready
                    .inventory
                    .connection()
                    .prepare_cached(TYPE_WITH_EXPLICIT_BASES)?;
                let types = statement.query_map(
                    rusqlite::params![mount.blob_id(), head.local_key()],
                    |row| row.get::<_, String>(0),
                )?;
                for name in types {
                    // Inherited nested types are M6, including source bases.
                    // Without an explicit base list the implicit System.Object,
                    // System.ValueType or System.Enum base has no nested types.
                    self.record_obligation(
                        scope,
                        "csharp_inherited_types_unmodeled",
                        &format!(
                            "{}: {} may be inherited by type {}",
                            mount.persisted_relative_path(),
                            self.source.demand.spelling(),
                            name?
                        ),
                    );
                }
            }
        }
        if rules.cancellation.is_cancelled() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        tier.blocks_fallback =
            !tier.edges.is_empty() || tier.coverage != ResolutionCompletion::Complete;
        Ok(Read::ready(vec![LexicalStartTier {
            ranked: RankedLexicalTier {
                rank: Rank { depth, rank: 0 },
                tier,
                providers: Vec::new(),
            },
            head: None,
        }]))
    }
    fn lexical_selection(
        &self,
        _: &Self::Placement,
        _: &mut PlacementFacts<Self::Target>,
    ) -> Result<Option<StartSelection<Rank>>> {
        Ok(Some(StartSelection {
            lexical: Some(LexicalStartRequest {
                scope: self.scope,
                lookup: self.source.demand.clone(),
            }),
            locations: Vec::new(),
            scopes: Vec::new(),
            blocks_fallback: false,
            head: None,
            providers: Vec::new(),
        }))
    }
    fn lexical_starts(
        &self,
        selected: StartSelection<Rank>,
        facts: &PlacementFacts<Self::Target>,
    ) -> Vec<PlacementStart<(), Rank>> {
        selected
            .locations
            .into_iter()
            .map(|start| PlacementStart::Route {
                rank: start.rank,
                scope: start.scope,
                cursor: WalkCursor {
                    tag: facts.tag,
                    location: start.location,
                    consumed_prefix_segments: self.source.route.len(),
                    start_step: self.source.route.len(),
                    namespace: ResolutionNamespace::Type,
                },
                anchor: ResolutionRootImportAnchor::Lexical,
            })
            .collect()
    }
    fn route_rules<'a>(
        &'a self,
        _: &'a Self::Placement,
        _: ResolutionRootImportAnchor,
        _: &'a [ResolutionLookupSemanticRecipe],
    ) -> impl RouteRules<ClosureTag> + 'a {
        CSharpRouteRules
    }
    fn route_target(
        &self,
        location: RouteLocation,
        _: Option<&Rank>,
        _: Option<ResolutionScopeId>,
    ) -> RouteLocation {
        location
    }
    fn target_location(&self, target: &RouteLocation) -> RouteLocation {
        target.clone()
    }
    fn proven_targets(
        &self,
        _: &Self::Placement,
        target: &RouteLocation,
        completion: &ResolutionCompletion,
    ) -> Result<Read<Vec<ProvenTarget>>> {
        Ok(Read::ready(match target {
            RouteLocation::Owner {
                definition,
                scope: Some(node),
            } => vec![ProvenTarget {
                target: SelectedMemberTarget {
                    fragment: self.fragment,
                    token: *definition,
                    definition: *node,
                    lookup: self.source.demand.clone(),
                    completion: completion.clone(),
                },
                material: BridgeMaterial::same_language(Language::CSharp),
            }],
            _ => Vec::new(),
        }))
    }
    fn exports(
        &self,
        _: &Self::Placement,
        target: RouteLocation,
        completion: &ResolutionCompletion,
    ) -> Result<Option<ExportHydration>> {
        match target {
            RouteLocation::Owner {
                definition,
                scope: None,
            } => {
                let node = self
                    .rules
                    .base
                    .lookup_definition_node(definition, self.rules.cancellation)?
                    .ok_or_else(|| {
                        StoreError::corrupt("admitted C# declaration has no definition node")
                    })?;
                hydrate_exports(
                    self.rules.session,
                    self.rules.ready,
                    self.rules.base,
                    self.rules.cancellation,
                    vec![node],
                    ResolutionNamespace::Type,
                    completion,
                    ResolutionCompletion::Complete,
                )
            }
            _ => Ok(Some(ExportHydration {
                exports: Vec::new(),
                blockers: Vec::new(),
                unstaged: completion.clone(),
                coverage: ExportCoverage::default(),
            })),
        }
    }
    fn boundary(&mut self, observation: &HalfObservation) -> Result<Option<HalfBoundary>> {
        if self.rules.cancellation.is_cancelled() {
            return Ok(None);
        }
        let mut completion = observation.completion.clone();
        let has_external_gap = self
            .rules
            .external_gaps
            .borrow()
            .iter()
            .any(|(half, _)| *half == self.source.identity);
        if !observation.route_reached_a_target && !has_external_gap {
            let mount = self.rules.ready.inventory.mount_record_by_ordinal(
                SelectedResolutionMountOrdinal::new(self.fragment.ordinal()),
            )?;
            let evidence = format!(
                "{}: {}",
                mount.persisted_relative_path(),
                self.source.demand.spelling()
            );
            let mut hash = CanonicalHasher::new(b"csharp-external-unindexed:v1");
            hash.field("source", &self.source.token.get().to_le_bytes());
            hash.field("scope", &self.scope.get().to_le_bytes());
            let reason = self.rules.ready.context_identities.named_semantic(
                hash.finish(),
                "csharp_external_unindexed",
                &evidence,
            );
            self.rules
                .external_gaps
                .borrow_mut()
                .push((self.source.identity, reason));
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(reason),
            ]));
        }
        Ok(Some(HalfBoundary {
            completion,
            associations: Vec::new(),
        }))
    }
    fn empty_placement(
        &mut self,
        facts: &PlacementFacts<Self::Target>,
        observation: &mut HalfObservation,
    ) -> Result<()> {
        observation.completion = observation.completion.combine(&facts.completion);
        Ok(())
    }
    fn empty_target(&self, _: &Self::Placement, _: &RouteLocation) -> Result<ResolutionCompletion> {
        Ok(ResolutionCompletion::Complete)
    }
}

impl CSharpHalf<'_, '_, '_> {
    fn record_obligation(&self, scope: ResolutionScopeId, label: &'static str, evidence: &str) {
        let mut hash = CanonicalHasher::new(b"csharp-lookup-obligation:v1");
        hash.field("label", label.as_bytes());
        hash.field("source", &self.source.token.get().to_le_bytes());
        hash.field("scope", &scope.get().to_le_bytes());
        let reason =
            self.rules
                .ready
                .context_identities
                .named_semantic(hash.finish(), label, evidence);
        let gap = (self.source.identity, reason);
        let mut gaps = self.rules.external_gaps.borrow_mut();
        if !gaps.contains(&gap) {
            gaps.push(gap);
        }
    }
}

struct CSharpRouteRules;
impl RouteRules<ClosureTag> for CSharpRouteRules {
    fn root_starts(
        &self,
        start: &WalkCursor<ClosureTag>,
        _: &mut ResolutionCompletion,
    ) -> Result<RouteStarts> {
        Ok(RouteStarts {
            locations: vec![start.location.clone()],
            consumed: 0,
        })
    }
    fn route_tier(
        &self,
        _: &WalkCursor<ClosureTag>,
        _: &ResolutionLookupSemanticRecipe,
        _: usize,
    ) -> Result<Option<RouteEdgeTier>> {
        unreachable!("unqualified C# starts consume the entire route")
    }
    fn dead_end(
        &self,
        _: &WalkCursor<ClosureTag>,
        _: &ResolutionLookupSemanticRecipe,
    ) -> Result<ResolutionCompletion> {
        unreachable!("unqualified C# starts have no residual segments")
    }
}

/// Selected declarations and the scope visits of the dormant probe.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct CSharpDemandProbe {
    pub using_gaps: Vec<CSharpUsingTierGap>,
    pub completion: ResolutionCompletion,
    pub named_reasons: Vec<(&'static str, String)>,
    pub targets: Vec<(String, String)>,
    pub visited: Vec<Option<Vec<String>>>,
}

/// Test-only entry through the shared forward provider, closer and projection.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn probe_type(
    operation: &SelectedResolutionOperation<'_, '_>,
    snapshot: &WorkspaceSnapshotId,
    locator: &SelectedSemanticLocator,
    cancellation: &CancellationToken,
) -> Result<Option<CSharpDemandProbe>> {
    use super::demand::{ClosedForwardSource, ClosedRelations};
    let ready = &operation.ready;
    let lexical = ready.lexical_source();
    let LocatedSemantic::Found(reference) =
        ready.lookup_locator(&lexical, locator, cancellation)?
    else {
        return Ok(None);
    };
    let context = operation.empty_contexts(&ResolutionCompletion::Complete)?;
    let SelectedResolutionContextValidationOutcome::Ready(inputs) =
        operation.prepare_context(context, cancellation, &SelectedResolutionContextMetrics)?
    else {
        return Ok(None);
    };
    let SelectedFactOperationBlueprintConstruction::Ready(blueprint) =
        ready.collect_blueprint(inputs, cancellation)?
    else {
        return Ok(None);
    };
    let arena = RefCell::new(ClosedRelations::default());
    let session = ResolutionSession::unbounded();
    let source = ClosedForwardSource::new(
        &lexical,
        &lexical,
        &arena,
        &session,
        crate::analyzer::resolution::CALLER_ENVIRONMENT,
    );
    let visited = RefCell::new(Vec::new());
    let using_gaps = RefCell::new(Vec::new());
    let external_gaps = RefCell::new(Vec::new());
    let rules = CSharpRules {
        ready,
        snapshot,
        base: &lexical,
        cancellation,
        session: &session,
        using_gaps: &using_gaps,
        external_gaps: &external_gaps,
        arena: &arena,
        visited: &visited,
    };
    let shared = SharedDemand {
        source_closures: HashMap::default(),
        rules,
        arena: &arena,
        paths: &lexical,
        ready,
        projection_memo: None,
        base: &lexical,
        session: &session,
        cancellation,
        completion: &ResolutionCompletion::Complete,
    };
    let mut provider = super::demand::DemandProvider::new(shared);
    {
        blueprint.with_forward_operation_in_session(
            &source,
            &lexical,
            &ready.typed_source(),
            cancellation,
            &session,
            |facts| {
                let crate::analyzer::resolution::FactDemandResolution::Ready(answer) =
                    facts.resolve_reference_by_demand(reference, &mut provider)?
                else {
                    return Ok(None);
                };
                assert!(
                    !visited.borrow().is_empty(),
                    "probe visited a C# source half"
                );
                let SelectedNativeDefinitions::Ready(projected) =
                    native_units::project_native_definition_units(
                        ready,
                        answer.binding().targets(),
                        cancellation,
                        &session,
                    )?
                else {
                    return Ok(None);
                };
                let mut targets = Vec::new();
                for (_, target) in projected {
                    let SelectedNativeDefinition::Unit(unit) = target else {
                        return Err(StoreError::corrupt("C# source target has no unit"));
                    };
                    targets.push((
                        brokk_bifrost_core::path_utils::rel_path_string(unit.source()),
                        unit.fq_name_str().to_owned(),
                    ));
                }
                targets.sort_unstable();
                targets.dedup();
                let mut named_reasons = named_reason_details(ready, answer.binding().completion())?;
                // Level obligations accompany the binding as structured C# gaps.
                // Their names belong to those records, even when the generic
                // binding channel reports only the enclosing boundary.
                for gap in using_gaps.borrow().iter() {
                    let (name, evidence) = ready
                        .context_identities
                        .named_reason(gap.reason)
                        .expect("a C# using-tier gap has named evidence");
                    named_reasons.push((name, evidence.to_string()));
                }
                named_reasons.sort_unstable();
                named_reasons.dedup();
                Ok(Some(CSharpDemandProbe {
                    using_gaps: using_gaps.borrow().clone(),
                    completion: answer.binding().completion().clone(),
                    named_reasons,
                    targets,
                    visited: visited.borrow().clone(),
                }))
            },
        )
    }
}
