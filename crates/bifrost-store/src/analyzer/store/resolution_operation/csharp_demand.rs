//! Point-owned source type lookup through the shared demand closer.
use super::super::csharp_compilation::SelectedCSharpMembership;
use super::csharp_imports::CSharpImportPrecedence as Rank;
use super::csharp_namespaces::{
    CSharpNamespaceLevel, NAMESPACE_CANDIDATES, namespace_types_for_lookup,
};
use super::csharp_units::{CSharpUnitPlacement, CSharpUnitReader};
use super::demand_closure::*;
use super::package_context::SelectedPackageRows;
use super::*;
use crate::analyzer::resolution::{
    DemandReferenceKey, DemandRootUnavailableReason, EndpointSignature, FactResolutionAnswer,
    SharedNameInterner,
};
use crate::analyzer::store::WorkspaceSnapshotId;
use crate::analyzer::store::resolution_lexical::NodeSourceScopes;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

// A package scope has a route row: the global namespace yields one NULL
// segment through the LEFT JOIN. No route row means a type or block scope.
pub const NAMESPACE_ROUTE: &str = "SELECT s.spelling FROM main.resolution_package_routes r
 LEFT JOIN main.resolution_package_route_segments s ON s.blob_id=r.blob_id AND s.package_scope_node_key=r.package_scope_node_key
 WHERE r.blob_id=?1 AND r.package_scope_node_key=?2 ORDER BY s.ordinal";

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

const METHOD_OWNER_HEAD: &str = "SELECT member_name, owner_scope_head_node_key
 FROM main.resolution_member_owner_properties
 WHERE blob_id=?1 AND definition_semantic_key=?2 AND member_kind IN ('method', 'constructor')";

const TYPE_EXPLICIT_BASE_LIST: &str = "SELECT base.raw
 FROM main.resolution_member_scope_properties AS scope
 JOIN main.resolution_semantic_sites AS semantic
 ON semantic.blob_id=scope.blob_id AND semantic.semantic_key=scope.definition_semantic_key AND semantic.semantic_role='definition'
 JOIN main.source_native_declaration_bridges AS native
 ON native.blob_id=semantic.blob_id AND native.source_site=semantic.source_site
 JOIN main.source_declaration_units AS mapping
 ON mapping.blob_id=native.blob_id AND mapping.declaration_id=native.declaration_id
 JOIN main.unit_supertypes AS base ON base.blob_id=mapping.blob_id AND base.unit_key=mapping.unit_key
 WHERE scope.blob_id=?1 AND scope.scope_head_node_key=?2 AND scope.scope_kind='type_body'
 ORDER BY base.ordinal";

/// One open using-tier obligation, retained with its structured lookup level.
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
    fn selected_target_completion(
        &self,
        preparation: &dyn std::any::Any,
        ready: &ReadySelectedResolution<'_, '_>,
        answer: &FactResolutionAnswer,
    ) -> Result<ResolutionCompletion> {
        assert!(preparation.is::<CSharpCallerDemand>());
        let connection = ready.inventory.connection();
        let mut groups = std::collections::BTreeSet::new();
        let mut bases = std::collections::BTreeSet::new();
        for &definition in answer.binding().targets() {
            // If #7314 M7 mints non-Local C# targets, classify them here: skipping one
            // could certify an unclassified method group as complete.
            let ordinal = definition.ordinal().expect(
                "C# selected targets are mounted source definitions; external members are obligations",
            );
            let mount = ready
                .inventory
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
            let rows = connection
                .prepare_cached(METHOD_OWNER_HEAD)?
                .query_map(
                    rusqlite::params![mount.blob_id(), definition.local_key()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            // C# publishes member rows for methods and constructors. A local
            // function is a callable binder without an owner row; its lexical
            // name stops lookup and it cannot form an overload set.
            for (name, head) in rows {
                groups.insert(name);
                for base in connection
                    .prepare_cached(TYPE_EXPLICIT_BASE_LIST)?
                    .query_map(rusqlite::params![mount.blob_id(), head], |row| {
                        row.get::<_, String>(0)
                    })?
                {
                    bases.insert(base?);
                }
            }
        }
        if groups.is_empty() {
            return Ok(ResolutionCompletion::Complete);
        }
        let evidence = format!("method group {groups:?}; explicit base list {bases:?}");
        let mut hash = CanonicalHasher::new(b"csharp-method-applicability:v1");
        hash.field("evidence", evidence.as_bytes());
        let reason = ready.context_identities.named_semantic(
            hash.finish(),
            "csharp_method_applicability_unmodeled",
            &evidence,
        );
        Ok(ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::UnsupportedSemantic(reason),
        ]))
    }

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
                    Some(view) => match view.selected_compilations_of(
                        &ready.inventory,
                        caller.to_str().expect("persisted caller paths are UTF-8"),
                    )? {
                        SelectedCSharpMembership::Proven(_) => true,
                        // The closer retains the named obligation without a placement.
                        SelectedCSharpMembership::Unproven { .. } => true,
                        SelectedCSharpMembership::NotSelected => false,
                    },
                    None => false,
                }
            }
            None => false,
        };
        if cancellation.is_cancelled() || session.is_some_and(|session| !session.scope_step()) {
            return Ok(NativeDemandPreparationOutcome::Cancelled);
        }
        // Proven(empty) membership is proven and remains ready. Retain no rows.
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
            external_observations: std::cell::Cell::new(0),
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
    // Query-local observation history, not authority or a cross-request cache.
    // Count attempts too: distinct directives can share a deduplicated reason.
    external_observations: std::cell::Cell<u64>,
    arena: &'a RefCell<super::demand::ClosedRelations>,
    #[cfg(any(test, feature = "test-support"))]
    visited: &'a RefCell<Vec<Option<Vec<String>>>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum CSharpImportKey {
    Authored(BindingFragmentId, u32, i64),
    Metadata {
        compilation: i64,
        ordinal: usize,
        origin: [u8; 32],
    },
}

// One authored route, evaluated only in this point request and placement.
struct CSharpImportTarget {
    metadata_key: Option<CSharpImportKey>,
    fragment: BindingFragmentId,
    compilation_id: i64,
    site: u32,
    scope: ResolutionScopeId,
    absolute: bool,
    route: Vec<ResolutionLookupSemanticRecipe>,
}
impl CSharpImportTarget {
    fn key(&self) -> CSharpImportKey {
        self.metadata_key.unwrap_or(CSharpImportKey::Authored(
            self.fragment,
            self.site,
            self.compilation_id,
        ))
    }
    fn metadata(
        fragment: BindingFragmentId,
        placement: &CSharpUnitPlacement,
        ordinal: usize,
        entry: &super::super::csharp_compilation::CSharpGlobalUsing,
    ) -> Result<Self> {
        if entry.1.is_empty() {
            return Err(StoreError::corrupt("C# metadata using has no segments"));
        }
        let mut hash = CanonicalHasher::new(b"csharp-metadata-using-origin:v1");
        hash.field("origin", entry.3.as_bytes());
        Ok(Self {
            metadata_key: Some(CSharpImportKey::Metadata {
                compilation: placement.compilation_id,
                ordinal,
                origin: hash.finish(),
            }),
            fragment,
            compilation_id: placement.compilation_id,
            site: 0,
            scope: ResolutionScopeId::new(1),
            absolute: true,
            route: entry
                .1
                .iter()
                .map(|name| {
                    ResolutionLookupSemanticRecipe::new(
                        Language::CSharp,
                        ResolutionNamespace::Type,
                        name,
                    )
                })
                .collect(),
        })
    }
    fn from_route(
        fragment: BindingFragmentId,
        compilation_id: i64,
        route: &super::imports::ImportRoute,
    ) -> Result<Self> {
        let terminal = route
            .demands
            .iter()
            .find(|demand| demand.0 == ResolutionNamespace::Type as i64 && !demand.1.is_empty())
            .ok_or_else(|| StoreError::corrupt("C# alias route lacks its Type demand"))?;
        if route.kind != "named" {
            return Err(StoreError::corrupt(
                "C# alias selector has a non-named route",
            ));
        }
        Self::new(
            fragment,
            compilation_id,
            route,
            route
                .segments
                .iter()
                .map(String::as_str)
                .chain([terminal.1.as_str()]),
        )
    }
    fn using(
        fragment: BindingFragmentId,
        compilation_id: i64,
        route: &super::imports::ImportRoute,
    ) -> Result<Self> {
        if route.kind != "glob" {
            return Err(StoreError::corrupt("C# using has a non-glob root route"));
        }
        Self::new(
            fragment,
            compilation_id,
            route,
            route.segments.iter().map(String::as_str),
        )
    }
    fn new<'a>(
        fragment: BindingFragmentId,
        compilation_id: i64,
        route: &super::imports::ImportRoute,
        names: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self> {
        let absolute = match route.anchor.as_str() {
            "absolute" => true,
            "lexical" => false,
            _ => return Err(StoreError::corrupt("C# alias route has an invalid anchor")),
        };
        let target = Self {
            metadata_key: None,
            fragment,
            compilation_id,
            site: route.site,
            scope: ResolutionScopeId::new(route.scope),
            absolute,
            route: names
                .into_iter()
                .map(|name| {
                    ResolutionLookupSemanticRecipe::new(
                        Language::CSharp,
                        ResolutionNamespace::Type,
                        name,
                    )
                })
                .collect(),
        };
        if target.route.is_empty() {
            return Err(StoreError::corrupt("C# using target has no segments"));
        }
        Ok(target)
    }
}
struct CSharpHalf<'a, 'store, 'input> {
    rules: &'a CSharpRules<'a, 'store, 'input>,
    source: &'a SourceHalf,
    fragment: BindingFragmentId,
    scope: ResolutionScopeId,
    placements: Vec<CSharpUnitPlacement>,
    // Derived results for this source-half query only, never authority or a
    // cross-request memo. Empty placements participate in agreement too.
    answers: RefCell<HashMap<i64, (String, HashSet<SemanticId>)>>,
    units: RefCell<CSharpUnitReader<'a, 'store>>,
    open: Option<OpenHalf>,
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
        // Namespace misses remain open. A type miss without publishing gaps or
        // explicit bases is a proven absence (CS0426). Excluding a generated
        // terminal base preserves negatives, open using tiers and selected import targets.
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
    fn prefix_operands(&self, _: &RootFrame, _: EnvironmentId) -> Vec<PrefixOperand> {
        // C# routes retain every structured segment, including the lexical head.
        // A namespace prefix is a location, not a source definition target.
        Vec::new()
    }
    fn half_rows<'a>(
        &'a self,
        source: &'a SourceHalf,
        _frame: &'a RootFrame,
        scopes: &'a NodeSourceScopes,
        _lexical: &'a dyn HalfSource,
        _inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<HalfRowsOutcome<Self::Half<'a>>> {
        if self.cancellation.is_cancelled() {
            return Ok(HalfRowsOutcome::Stopped);
        }
        let lookup_scope = source.prefix_scope_head.unwrap_or(source.scope);
        let Some(Some((fragment, scope))) = scopes.get(&lookup_scope) else {
            return Err(StoreError::corrupt(
                "C# source half has no selected scope mapping",
            ));
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
        if let SelectedCSharpMembership::Proven(membership) =
            units.compilation_membership(record.persisted_relative_path())?
        {
            for open in membership.open {
                let mut hash = CanonicalHasher::new(b"csharp-open-membership:v1");
                hash.field("source", &source.token.get().to_le_bytes());
                hash.field("selection", &self.ready.inventory.scope_identity());
                hash.field("compilation", &open.compilation_id.to_le_bytes());
                let mut evidence = Vec::new();
                for region in open.regions {
                    hash.field("kind", region.kind.as_bytes());
                    hash.field("region", region.rel_path.as_bytes());
                    for gap in region.gaps {
                        hash.field("gap_code", gap.code.as_bytes());
                        hash.field("gap_path", gap.path.as_bytes());
                        evidence.push(format!(
                            "{} {}: {} at {} ({})",
                            region.kind, region.rel_path, gap.code, gap.path, gap.evidence
                        ));
                    }
                }
                let evidence = format!(
                    "membership_unproven: compilation {:?}: {}; caller: {}",
                    open.project_path,
                    evidence.join("; "),
                    record.persisted_relative_path()
                );
                let reason = self.ready.context_identities.named_semantic(
                    hash.finish(),
                    "csharp_compilation_usings_incomplete",
                    &evidence,
                );
                self.external_gaps
                    .borrow_mut()
                    .push((source.identity, reason));
            }
        }
        let placements = match units.placements(record.persisted_relative_path())? {
            Some(placements) => placements,
            None => {
                // Unknown membership cannot certify an empty import inventory.
                // Retain the obligation even when no placement can be walked.
                let mut hash = CanonicalHasher::new(b"csharp-unknown-membership:v1");
                hash.field("source", &source.token.get().to_le_bytes());
                hash.field("selection", &self.ready.inventory.scope_identity());
                let (code, gaps, evidence) =
                    match units.compilation_membership(record.persisted_relative_path())? {
                        SelectedCSharpMembership::Unproven {
                            code,
                            gaps,
                            evidence,
                        } => (code, gaps, evidence),
                        SelectedCSharpMembership::Proven(_) => (
                            "placement_unavailable",
                            Vec::new(),
                            format!(
                                "selected placement rows are unavailable for {}",
                                record.persisted_relative_path()
                            ),
                        ),
                        SelectedCSharpMembership::NotSelected => (
                            "not_selected",
                            Vec::new(),
                            format!(
                                "source is not selected for {}",
                                record.persisted_relative_path()
                            ),
                        ),
                    };
                hash.field("code", code.as_bytes());
                // Display formatting is not semantic identity. Keep the stored gap order.
                for gap in &gaps {
                    hash.field("gap_code", gap.code.as_bytes());
                    hash.field("gap_path", gap.path.as_bytes());
                }
                let reason = self.ready.context_identities.named_semantic(
                    hash.finish(),
                    "csharp_compilation_usings_incomplete",
                    &evidence,
                );
                self.external_gaps
                    .borrow_mut()
                    .push((source.identity, reason));
                Vec::new()
            }
        };
        for placement in &placements {
            for inventory in units.open_inventories(placement)? {
                for (index, gap) in inventory.gaps.iter().enumerate() {
                    let mut hash = CanonicalHasher::new(b"csharp-open-inventory:v1");
                    hash.field("source", &source.token.get().to_le_bytes());
                    hash.field("selection", &self.ready.inventory.scope_identity());
                    hash.field("compilation", &inventory.compilation_id.to_le_bytes());
                    hash.field("gap_ordinal", &(index as u64).to_le_bytes());
                    hash.field("gap_code", gap.code.as_bytes());
                    hash.field("gap_path", gap.path.as_bytes());
                    let evidence = format!(
                        "compilation {:?} inventory is open: {} at {}: {}",
                        inventory.project_path, gap.code, gap.path, gap.evidence
                    );
                    let reason = self.ready.context_identities.named_semantic(
                        hash.finish(),
                        "csharp_compilation_usings_incomplete",
                        &evidence,
                    );
                    self.external_gaps
                        .borrow_mut()
                        .push((source.identity, reason));
                }
            }
        }
        let open_label = if !matches!(
            source.anchor,
            ResolutionRootImportAnchor::Lexical | ResolutionRootImportAnchor::Absolute
        ) {
            Some("csharp_source_anchor_unmodeled")
        } else if source.is_import {
            Some("csharp_source_import_unmodeled")
        } else if source.demand.namespace() != ResolutionNamespace::Type {
            Some("csharp_member_access_unmodeled")
        } else {
            None
        };
        let open = open_label.map(|label| {
            let mut hash = CanonicalHasher::new(b"csharp-open-source-half:v1");
            hash.field("source", &source.token.get().to_le_bytes());
            hash.field(
                "namespace",
                format!("{:?}", source.demand.namespace()).as_bytes(),
            );
            hash.field("spelling", source.demand.spelling().as_bytes());
            let evidence = format!(
                "C# source half {:?} import={} namespace={:?} spelling={}",
                source.anchor,
                source.is_import,
                source.demand.namespace(),
                source.demand.spelling()
            );
            let reason =
                self.ready
                    .context_identities
                    .named_semantic(hash.finish(), label, &evidence);
            OpenHalf::new(ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(reason),
            ]))
        });
        Ok(HalfRowsOutcome::Rows(CSharpHalf {
            rules: self,
            source,
            fragment: *fragment,
            scope: *scope,
            placements: if open.is_some() {
                Vec::new()
            } else {
                placements
            },
            answers: RefCell::new(HashMap::default()),
            units: RefCell::new(units),
            open,
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
    fn initial_completion(&self) -> ResolutionCompletion {
        self.open
            .as_ref()
            .map_or(ResolutionCompletion::Complete, |open| {
                open.completion().clone()
            })
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
        // This hook runs after every placement, including successful halves.
        // boundary() is only called when a half produced no authority.
        reasons.extend(
            self.placement_disagreement()
                .map(ResolutionIncompleteReason::UnsupportedSemantic),
        );
        (!reasons.is_empty()).then(|| ResolutionCompletion::incomplete(reasons))
    }
    fn placement(
        &self,
        placement: &Self::Placement,
        tag: ClosureTag,
    ) -> Option<PlacementFacts<Self::Target>> {
        self.answers
            .borrow_mut()
            .entry(placement.compilation_id)
            .or_insert_with(|| {
                (
                    placement.project_path.clone().unwrap_or_else(|| {
                        format!("implicit compilation {}", placement.compilation_id)
                    }),
                    HashSet::default(),
                )
            });
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
        let mut resolved = HashMap::default();
        let mut stack = Vec::new();
        loop {
            let mut pending = Vec::new();
            let tier = self.lookup_tiers(
                self.fragment,
                placement,
                scope,
                depth,
                lookup,
                None,
                &resolved,
                &mut pending,
            )?;
            if pending.is_empty() {
                return Ok(tier);
            }
            stack.extend(pending);
            while let Some(alias) = stack.last() {
                if resolved.contains_key(&alias.key()) {
                    stack.pop();
                    continue;
                }
                let mut dependencies = Vec::new();
                let result = self.import_target(placement, alias, &resolved, &mut dependencies)?;
                if !dependencies.is_empty() {
                    // Own-declaration exclusion makes every dependency strictly
                    // outer. Defend the active stack without claiming absence.
                    if dependencies
                        .iter()
                        .any(|next| stack.iter().any(|active| active.key() == next.key()))
                    {
                        let mut hash = CanonicalHasher::new(b"csharp-alias-cycle:v1");
                        hash.field("import", &alias.site.to_le_bytes());
                        hash.field("mount", &alias.fragment.ordinal().to_le_bytes());
                        hash.field("compilation", &alias.compilation_id.to_le_bytes());
                        hash.field("source", &self.source.token.get().to_le_bytes());
                        let reason = self.rules.ready.context_identities.named_semantic(
                            hash.finish(),
                            "csharp_alias_cycle",
                            "cyclic using alias target",
                        );
                        resolved.insert(
                            alias.key(),
                            (
                                Vec::new(),
                                ResolutionCompletion::incomplete([
                                    ResolutionIncompleteReason::UnsupportedSemantic(reason),
                                ]),
                            ),
                        );
                    } else {
                        stack.extend(dependencies);
                    }
                    continue;
                }
                match result {
                    Read::Ready { value, completion } => {
                        resolved.insert(alias.key(), (value, completion));
                    }
                    Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                    Read::Unavailable { .. } => unreachable!("C# alias routes do not suspend"),
                }
                stack.pop();
            }
        }
    }
    fn lexical_selection(
        &self,
        placement: &Self::Placement,
        _: &mut PlacementFacts<Self::Target>,
    ) -> Result<Option<StartSelection<Rank>>> {
        if self.source.anchor == ResolutionRootImportAnchor::Absolute {
            return Ok(Some(StartSelection {
                lexical: None,
                locations: vec![RankedStart {
                    rank: Some(Rank { depth: 0, rank: 0 }),
                    scope: None,
                    location: RouteLocation::Container {
                        unit: placement.compilation_id,
                        container: "[]".into(),
                    },
                }],
                scopes: Vec::new(),
                blocks_fallback: true,
                head: None,
                providers: Vec::new(),
            }));
        }
        Ok(Some(StartSelection {
            lexical: Some(LexicalStartRequest {
                scope: self.scope,
                lookup: self
                    .source
                    .route
                    .first()
                    .unwrap_or(&self.source.demand)
                    .clone(),
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
                    consumed_prefix_segments: usize::from(
                        self.source.anchor != ResolutionRootImportAnchor::Absolute
                            && !self.source.route.is_empty(),
                    ),
                    start_step: usize::from(
                        self.source.anchor != ResolutionRootImportAnchor::Absolute
                            && !self.source.route.is_empty(),
                    ),
                    namespace: ResolutionNamespace::Type,
                },
                anchor: ResolutionRootImportAnchor::Lexical,
            })
            .collect()
    }
    fn route_rules<'a>(
        &'a self,
        placement: &'a Self::Placement,
        _: ResolutionRootImportAnchor,
        _: &'a [ResolutionLookupSemanticRecipe],
    ) -> impl RouteRules<ClosureTag> + 'a {
        CSharpRouteRules {
            half: self,
            fragment: self.fragment,
            placement,
        }
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
        placement: &Self::Placement,
        target: &RouteLocation,
        completion: &ResolutionCompletion,
    ) -> Result<Read<Vec<ProvenTarget>>> {
        if !self.source.route.is_empty()
            || self.source.anchor == ResolutionRootImportAnchor::Absolute
        {
            let route = CSharpRouteRules {
                half: self,
                fragment: self.fragment,
                placement,
            };
            let tier = match route.step(target, &self.source.demand)? {
                Read::Ready {
                    mut value,
                    completion,
                } => {
                    value.coverage = value.coverage.combine(&completion);
                    value
                }
                Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                Read::Unavailable { reason, completion } => {
                    return Ok(Read::Unavailable { reason, completion });
                }
            };
            let mut coverage = completion.combine(&tier.coverage);
            if tier.edges.is_empty() {
                coverage = coverage.combine(&route.missing(target, &self.source.demand)?);
            }
            if coverage.contains_reason(ResolutionIncompleteReason::Cancelled) {
                return Ok(Read::Cancelled(coverage));
            }
            let mut targets = Vec::new();
            for target in tier.edges {
                if let RouteLocation::Owner { definition, .. } = target {
                    self.record_target(placement, definition);
                    let node = self
                        .rules
                        .base
                        .lookup_definition_node(definition, self.rules.cancellation)?
                        .ok_or_else(|| {
                            StoreError::corrupt("admitted C# declaration has no definition node")
                        })?;
                    targets.push(ProvenTarget {
                        target: SelectedMemberTarget {
                            fragment: BindingFragmentId::at_ordinal(
                                definition.ordinal().expect("mounted C# declaration"),
                            ),
                            token: definition,
                            definition: node,
                            lookup: self.source.demand.clone(),
                            completion: coverage.clone(),
                        },
                        material: BridgeMaterial::same_language(Language::CSharp),
                    });
                }
            }
            return Ok(Read::Ready {
                value: targets,
                completion: coverage,
            });
        }
        Ok(Read::ready(match target {
            RouteLocation::Owner {
                definition,
                scope: Some(node),
            } => {
                self.record_target(placement, *definition);
                vec![ProvenTarget {
                    target: SelectedMemberTarget {
                        fragment: BindingFragmentId::at_ordinal(
                            definition.ordinal().expect("mounted C# declaration"),
                        ),
                        token: *definition,
                        definition: *node,
                        lookup: self.source.demand.clone(),
                        completion: completion.clone(),
                    },
                    material: BridgeMaterial::same_language(Language::CSharp),
                }]
            }
            _ => Vec::new(),
        }))
    }
    fn exports(
        &self,
        placement: &Self::Placement,
        target: RouteLocation,
        completion: &ResolutionCompletion,
    ) -> Result<Option<ExportHydration>> {
        if !self.source.route.is_empty()
            || self.source.anchor == ResolutionRootImportAnchor::Absolute
        {
            return Ok(Some(ExportHydration {
                exports: Vec::new(),
                blockers: Vec::new(),
                unstaged: completion.clone(),
                coverage: ExportCoverage::default(),
            }));
        }
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
                self.record_target(placement, definition);
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
        if !observation.route_reached_a_target
            && !has_external_gap
            && self.source.route.is_empty()
            && self.source.anchor != ResolutionRootImportAnchor::Absolute
        {
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
    fn placement_disagreement(&self) -> Option<SemanticId> {
        let answers = self.answers.borrow();
        let (_, first) = answers.values().next()?;
        if answers.values().all(|(_, selected)| selected == first) {
            return None;
        }
        let mut ordered = answers
            .iter()
            .map(|(id, (name, selected))| {
                let mut targets = selected.iter().copied().collect::<Vec<_>>();
                targets.sort_unstable();
                (*id, name.as_str(), targets)
            })
            .collect::<Vec<_>>();
        ordered.sort_by_key(|(id, _, _)| *id);
        let mut hash = CanonicalHasher::new(b"csharp-placement-answers:v1");
        hash.field("source", &self.source.token.get().to_le_bytes());
        for (id, _, targets) in &ordered {
            hash.field("compilation", &id.to_le_bytes());
            for target in targets {
                hash.field("target", &target.get().to_le_bytes());
            }
        }
        let reason = self.rules.ready.context_identities.named_semantic(
            hash.finish(),
            "csharp_compilation_usings_incomplete",
            &format!("compilation answers disagree: {ordered:?}"),
        );
        Some(reason)
    }
    fn record_target(&self, placement: &CSharpUnitPlacement, definition: SemanticId) {
        self.answers
            .borrow_mut()
            .get_mut(&placement.compilation_id)
            .expect("placement registered before reading its targets")
            .1
            .insert(definition);
    }
    fn import_target(
        &self,
        placement: &CSharpUnitPlacement,
        alias: &CSharpImportTarget,
        resolved: &HashMap<CSharpImportKey, (Vec<RouteLocation>, ResolutionCompletion)>,
        pending: &mut Vec<CSharpImportTarget>,
    ) -> Result<Read<Vec<RouteLocation>>> {
        if !self.rules.session.scope_step() || self.rules.cancellation.is_cancelled() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        let external_before = self.rules.external_observations.get();
        let mut completion = ResolutionCompletion::Complete;
        let (starts, residual) = if alias.absolute {
            (
                vec![RouteLocation::Container {
                    unit: placement.compilation_id,
                    container: "[]".into(),
                }],
                alias.route.as_slice(),
            )
        } else {
            let selected = select_lexical_route_starts(
                alias.scope,
                |scope| {
                    self.rules.ready.lexical_source().lookup_scope_parent(
                        alias.fragment,
                        scope,
                        self.rules.cancellation,
                    )
                },
                |scope, depth| match self.lookup_tiers(
                    alias.fragment,
                    placement,
                    scope,
                    depth,
                    &alias.route[0],
                    Some(alias.scope),
                    resolved,
                    pending,
                )? {
                    Read::Ready { value, completion } => Ok(Read::Ready {
                        value: value
                            .into_iter()
                            .map(|tier| Ok(tier.ranked))
                            .collect::<Vec<_>>(),
                        completion,
                    }),
                    Read::Cancelled(completion) => Ok(Read::Cancelled(completion)),
                    Read::Unavailable { reason, completion } => {
                        Ok(Read::Unavailable { reason, completion })
                    }
                },
                |_, _| false,
                |_, _| false,
                &mut completion,
                self.rules.cancellation,
            )?;
            match selected {
                Read::Ready {
                    value,
                    completion: read,
                } => {
                    completion = completion.combine(&read);
                    (
                        value
                            .starts
                            .into_iter()
                            .map(|start| start.location)
                            .collect(),
                        &alias.route[1..],
                    )
                }
                Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                Read::Unavailable { .. } => unreachable!("C# alias lookup does not suspend"),
            }
        };
        // Unresolved alias dependencies are settled by the caller's explicit
        // stack before replaying selection. Never walk a placeholder target.
        let mut locations = Vec::new();
        if pending.is_empty() {
            for location in starts {
                locations.extend(
                    walk_residual_route(
                        &CSharpRouteRules {
                            half: self,
                            fragment: alias.fragment,
                            placement,
                        },
                        WalkCursor {
                            tag: alias.key(),
                            location,
                            consumed_prefix_segments: 0,
                            start_step: 0,
                            namespace: ResolutionNamespace::Type,
                        },
                        residual,
                        &mut completion,
                        self.rules.cancellation,
                    )?
                    .into_iter()
                    .map(|cursor| cursor.location),
                );
            }
        }
        if completion.contains_reason(ResolutionIncompleteReason::Cancelled)
            || self.rules.cancellation.is_cancelled()
        {
            return Ok(Read::Cancelled(completion.combine(&cancelled_completion())));
        }
        let mut seen = HashSet::default();
        locations.retain(|location| seen.insert(location.clone()));
        if pending.is_empty()
            && (locations.len() > 1
                || (locations.is_empty()
                    && completion == ResolutionCompletion::Complete
                    && self.rules.external_observations.get() == external_before))
        {
            // A complete owner-member miss proves CS0426, but an invalid using
            // directive still cannot certify this import tier. Likewise a
            // namespace/type target ambiguity must survive a later member join.
            let mut hash = CanonicalHasher::new(b"csharp-using-target-unsettled:v1");
            hash.field("source", &self.source.token.get().to_le_bytes());
            hash.field("compilation", &placement.compilation_id.to_le_bytes());
            match alias.key() {
                CSharpImportKey::Authored(fragment, site, _) => {
                    hash.field("mount", &fragment.ordinal().to_le_bytes());
                    hash.field("site", &site.to_le_bytes());
                }
                CSharpImportKey::Metadata {
                    ordinal, origin, ..
                } => {
                    hash.field("ordinal", &(ordinal as u64).to_le_bytes());
                    hash.field("origin", &origin);
                }
            }
            for segment in &alias.route {
                hash.field("segment", &segment.name_digest());
            }
            let route = alias
                .route
                .iter()
                .map(|segment| segment.spelling())
                .collect::<Vec<_>>()
                .join(".");
            let reason = self.rules.ready.context_identities.named_semantic(
                hash.finish(),
                "csharp_compilation_usings_incomplete",
                &format!(
                    "using target {route} does not settle to one namespace or type: {locations:?}"
                ),
            );
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(reason),
            ]));
        }
        Ok(Read::Ready {
            value: locations,
            completion,
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn lookup_tiers(
        &self,
        fragment: BindingFragmentId,
        placement: &CSharpUnitPlacement,
        scope: ResolutionScopeId,
        depth: u32,
        lookup: &ResolutionLookupSemanticRecipe,
        excluded: Option<ResolutionScopeId>,
        resolved: &HashMap<CSharpImportKey, (Vec<RouteLocation>, ResolutionCompletion)>,
        pending: &mut Vec<CSharpImportTarget>,
    ) -> Result<Read<Vec<LexicalStartTier<Rank, ()>>>> {
        let rules = self.rules;
        if !rules.session.scope_step() || rules.cancellation.is_cancelled() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        let mount = rules
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(fragment.ordinal()))?;
        let mut aliases = if excluded == Some(scope) {
            Vec::new()
        } else {
            let Some(routes) = super::imports::scope_named_routes(
                rules.ready.inventory.connection(),
                mount.blob_id(),
                scope.get(),
                lookup.spelling(),
                rules.cancellation,
            )?
            else {
                return Ok(Read::Cancelled(cancelled_completion()));
            };
            routes
                .into_iter()
                .map(|route| (fragment, route))
                .collect::<Vec<_>>()
        };
        let lexical = rules.ready.lexical_source();
        let Some(head) = lexical.scope_head_node_of(fragment, scope, rules.cancellation)? else {
            return Ok(Read::Cancelled(cancelled_completion()));
        };
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
        let namespace_level = !path.is_empty();
        let namespace_path = path.into_iter().flatten().collect::<Vec<_>>();
        if namespace_level && namespace_path.is_empty() && excluded != Some(scope) {
            let Some(globals) = self.units.borrow_mut().global_usings(
                rules.snapshot,
                placement,
                rules.cancellation,
                rules.session,
            )?
            else {
                return Ok(Read::Cancelled(cancelled_completion()));
            };
            tier.coverage = tier.coverage.combine(&globals.completion);
            aliases.extend(
                globals
                    .routes
                    .into_iter()
                    .filter(|global| {
                        global.route.kind == "named"
                            && global.alias.as_deref() == Some(lookup.spelling())
                    })
                    .map(|global| (global.fragment, global.route)),
            );
            let mut seen = HashSet::default();
            aliases.retain(|(origin, route)| {
                seen.insert((*origin, route.site, placement.compilation_id))
            });
        }
        let inventory_coverage = tier.coverage.clone();
        if namespace_level {
            let path = &namespace_path;
            #[cfg(any(test, feature = "test-support"))]
            rules.visited.borrow_mut().push(Some(path.clone()));
            let route = CSharpRouteRules {
                half: self,
                fragment,
                placement,
            };
            let location = RouteLocation::Container {
                unit: placement.compilation_id,
                container: serde_json::to_string(&path).expect("namespace segments serialize"),
            };
            tier = match route.step(&location, lookup)? {
                Read::Ready {
                    mut value,
                    completion,
                } => {
                    value.coverage = value
                        .coverage
                        .combine(&completion)
                        .combine(&inventory_coverage);
                    value
                }
                Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                Read::Unavailable { reason, completion } => {
                    return Ok(Read::Unavailable { reason, completion });
                }
            };
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
                            lookup.spelling(),
                            name?
                        ),
                    );
                }
            }
        }
        for (origin, alias) in &aliases {
            let key = CSharpImportKey::Authored(*origin, alias.site, placement.compilation_id);
            if let Some((locations, completion)) = resolved.get(&key) {
                tier.edges.extend(locations.iter().cloned());
                tier.coverage = tier.coverage.combine(completion);
            } else {
                pending.push(CSharpImportTarget::from_route(
                    *origin,
                    placement.compilation_id,
                    alias,
                )?);
            }
        }
        for (origin, alias) in &aliases {
            if namespace_level && namespace_path.is_empty() {
                // The compilation-root publisher gap represents implicit/global
                // using discovery, not the syntax of an exact alias. Inventory
                // coverage above settles source globals; rank one keeps M2 open.
                // Preserve only this alias's own producer gaps (e.g. generics).
                let Some(reasons) = lexical.site_gap_reasons(
                    SelectedResolutionMountOrdinal::new(origin.ordinal()),
                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(
                        alias.site,
                    ),
                    rules.cancellation,
                )?
                else {
                    return Ok(Read::Cancelled(cancelled_completion()));
                };
                if !reasons.is_empty() {
                    tier.coverage = tier.coverage.combine(&ResolutionCompletion::incomplete(
                        reasons
                            .into_iter()
                            .map(ResolutionIncompleteReason::UnsupportedSemantic),
                    ));
                }
            } else {
                let Some(alias_head) = lexical.scope_head_node_of(
                    *origin,
                    ResolutionScopeId::new(alias.scope),
                    rules.cancellation,
                )?
                else {
                    return Ok(Read::Cancelled(cancelled_completion()));
                };
                // The import path retains producer gaps, including unsupported
                // constructed generic syntax, even when navigation finds a head.
                let Some((paths, completion)) = scope_binding_paths(
                    rules.base,
                    alias_head,
                    lookup.semantic(&rules.ready.shared_names()),
                    rules.cancellation,
                )?
                else {
                    return Ok(Read::Cancelled(cancelled_completion()));
                };
                tier.coverage = tier.coverage.combine(&completion);
                for path in paths {
                    tier.coverage = tier.coverage.combine(path.completion());
                }
            }
        }
        if rules.cancellation.is_cancelled() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        let mut has_metadata_alias = false;
        if namespace_level && namespace_path.is_empty() && excluded != Some(scope) {
            let metadata = self.units.borrow().using_metadata(placement)?;
            if let Some(metadata) = metadata {
                if !metadata.global_usings_complete {
                    tier.coverage = tier.coverage.combine(&self.using_obligation(
                        placement,
                        scope,
                        &namespace_path,
                        lookup,
                        "csharp_compilation_usings_incomplete",
                        "compilation metadata using inventory is incomplete",
                    ));
                }
                for (ordinal, entry) in metadata
                    .global_usings
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| entry.2.as_deref() == Some(lookup.spelling()))
                {
                    has_metadata_alias = true;
                    let target = CSharpImportTarget::metadata(fragment, placement, ordinal, entry)?;
                    if let Some((locations, completion)) = resolved.get(&target.key()) {
                        tier.edges.extend(locations.iter().cloned());
                        tier.coverage = tier.coverage.combine(completion);
                    } else {
                        pending.push(target);
                    }
                }
            } else {
                tier.coverage = tier.coverage.combine(&self.using_obligation(
                    placement,
                    scope,
                    &namespace_path,
                    lookup,
                    "csharp_compilation_usings_incomplete",
                    "compilation metadata using inventory is unavailable",
                ));
            }
        }
        if namespace_level && tier.edges.is_empty() && aliases.is_empty() && !has_metadata_alias {
            // A namespace miss cannot exclude a type in an unindexed
            // assembly. Keep searching outward, retaining this obligation.
            // A source match stays closed: it wins over an imported type
            // with warning CS0436.
            self.record_obligation(
                scope,
                "csharp_external_unindexed",
                &format!(
                    "{}: {} is not declared in {}",
                    mount.persisted_relative_path(),
                    lookup.spelling(),
                    if namespace_path.is_empty() {
                        "the global namespace".to_owned()
                    } else {
                        format!("source namespace {}", namespace_path.join("."))
                    },
                ),
            );
        }
        tier.blocks_fallback = has_metadata_alias
            || !aliases.is_empty()
            || !tier.edges.is_empty()
            || (namespace_level && tier.coverage != ResolutionCompletion::Complete);
        let mut tiers = Vec::new();
        if namespace_level && !tier.blocks_fallback && excluded != Some(scope) {
            match self.using_tier(
                fragment,
                placement,
                scope,
                &namespace_path,
                lookup,
                resolved,
                pending,
            )? {
                Read::Ready {
                    value: Some(imported),
                    completion,
                } => {
                    tier.coverage = tier.coverage.combine(&completion);
                    tiers.push(LexicalStartTier {
                        ranked: RankedLexicalTier {
                            rank: Rank { depth, rank: 1 },
                            tier: imported,
                            providers: Vec::new(),
                        },
                        head: None,
                    });
                }
                Read::Ready { value: None, .. } => {}
                Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                Read::Unavailable { .. } => unreachable!("C# using reads do not suspend"),
            }
        }
        tiers.insert(
            0,
            LexicalStartTier {
                ranked: RankedLexicalTier {
                    rank: Rank { depth, rank: 0 },
                    tier,
                    providers: Vec::new(),
                },
                head: None,
            },
        );
        Ok(Read::ready(tiers))
    }
    #[allow(clippy::too_many_arguments)]
    fn using_tier(
        &self,
        fragment: BindingFragmentId,
        placement: &CSharpUnitPlacement,
        scope: ResolutionScopeId,
        namespace: &[String],
        lookup: &ResolutionLookupSemanticRecipe,
        resolved: &HashMap<CSharpImportKey, (Vec<RouteLocation>, ResolutionCompletion)>,
        pending: &mut Vec<CSharpImportTarget>,
    ) -> Result<Read<Option<RouteEdgeTier>>> {
        let rules = self.rules;
        let mount = rules
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(fragment.ordinal()))?;
        let Some(routes) = super::imports::scope_routes(
            rules.ready.inventory.connection(),
            mount.blob_id(),
            scope.get(),
            rules.cancellation,
        )?
        else {
            return Ok(Read::Cancelled(cancelled_completion()));
        };
        let mut tier = RouteEdgeTier::default();
        let mut imports = routes
            .into_iter()
            .filter(|route| route.kind == "glob")
            .map(|route| CSharpImportTarget::using(fragment, placement.compilation_id, &route))
            .collect::<Result<Vec<_>>>()?;
        if namespace.is_empty() {
            let Some(globals) = self.units.borrow_mut().global_usings(
                rules.snapshot,
                placement,
                rules.cancellation,
                rules.session,
            )?
            else {
                return Ok(Read::Cancelled(cancelled_completion()));
            };
            tier.coverage = tier.coverage.combine(&globals.completion);
            for global in globals
                .routes
                .into_iter()
                .filter(|global| global.route.kind == "glob")
            {
                imports.push(CSharpImportTarget::using(
                    global.fragment,
                    placement.compilation_id,
                    &global.route,
                )?);
            }
            if let Some(metadata) = self.units.borrow().using_metadata(placement)? {
                if !metadata.global_usings_complete {
                    tier.coverage = tier.coverage.combine(&self.using_obligation(
                        placement,
                        scope,
                        namespace,
                        lookup,
                        "csharp_compilation_usings_incomplete",
                        "compilation metadata using inventory is incomplete",
                    ));
                }
                for (ordinal, entry) in metadata
                    .global_usings
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| entry.2.is_none())
                {
                    imports.push(CSharpImportTarget::metadata(
                        fragment, placement, ordinal, entry,
                    )?);
                }
            }
        }
        let mut seen = HashSet::default();
        imports.retain(|import| seen.insert(import.key()));
        let has_using = !imports.is_empty();
        let walker = CSharpRouteRules {
            half: self,
            fragment,
            placement,
        };
        // bifrost-csharp resolution/imports.rs collapses TypeOnDemand and
        // StaticOnDemand to Glob. Authored target kinds are not validated;
        // invalid using N.Outer imports nested types, invalid using static N
        // imports namespace types, each under the external glob obligation.
        // Retaining authored kind requires a producer slice and bundle bump.
        for import in imports {
            if !rules.session.scope_step() || rules.cancellation.is_cancelled() {
                return Ok(Read::Cancelled(cancelled_completion()));
            }
            let Some((locations, completion)) = resolved.get(&import.key()) else {
                pending.push(import);
                continue;
            };
            tier.coverage = tier.coverage.combine(completion);
            for location in locations {
                // Both glob directive forms import the types directly in their
                // resolved target: namespace types or an owner's nested types.
                let next = match walker.step(location, lookup)? {
                    Read::Ready { value, completion } => {
                        tier.coverage = tier.coverage.combine(&completion).combine(&value.coverage);
                        value
                    }
                    Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                    Read::Unavailable { .. } => unreachable!("C# using steps do not suspend"),
                };
                // Using namespace imports types, never nested namespaces.
                let mut members = next
                    .edges
                    .into_iter()
                    .filter(|edge| matches!(edge, RouteLocation::Owner { .. }))
                    .peekable();
                if members.peek().is_none() {
                    tier.coverage = tier.coverage.combine(&walker.missing(location, lookup)?);
                }
                tier.edges.extend(members);
            }
        }
        if has_using {
            tier.coverage = tier.coverage.combine(&self.using_obligation(
                placement,
                scope,
                namespace,
                lookup,
                "csharp_external_unindexed",
                "using imports may have unindexed competing types",
            ));
        }
        if tier
            .coverage
            .contains_reason(ResolutionIncompleteReason::Cancelled)
            || rules.cancellation.is_cancelled()
        {
            return Ok(Read::Cancelled(
                tier.coverage.combine(&cancelled_completion()),
            ));
        }
        tier.blocks_fallback = has_using || tier.coverage != ResolutionCompletion::Complete;
        Ok(Read::ready(tier.blocks_fallback.then_some(tier)))
    }
    fn using_obligation(
        &self,
        placement: &CSharpUnitPlacement,
        scope: ResolutionScopeId,
        namespace: &[String],
        lookup: &ResolutionLookupSemanticRecipe,
        label: &'static str,
        detail: &str,
    ) -> ResolutionCompletion {
        let mut hash = CanonicalHasher::new(b"csharp-using-obligation:v1");
        hash.field("source", &self.source.token.get().to_le_bytes());
        hash.field("scope", &scope.get().to_le_bytes());
        hash.field("compilation", &placement.compilation_id.to_le_bytes());
        hash.field("lookup", &lookup.name_digest());
        hash.field("label", label.as_bytes());
        let evidence = format!(
            "{} for {} at {}",
            detail,
            lookup.spelling(),
            if namespace.is_empty() {
                "the compilation unit".into()
            } else {
                format!("namespace {}", namespace.join("."))
            }
        );
        let reason =
            self.rules
                .ready
                .context_identities
                .named_semantic(hash.finish(), label, &evidence);
        let mut gaps = self.rules.using_gaps.borrow_mut();
        if !gaps
            .iter()
            .any(|gap| gap.reason == reason && gap.source_half == self.source.identity)
        {
            gaps.push(CSharpUsingTierGap {
                reason,
                source: self.fragment,
                source_half: self.source.identity,
                scope,
                compilation_id: placement.compilation_id,
                namespace: (!namespace.is_empty()).then(|| namespace.to_vec()),
            });
        }
        ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(reason)])
    }
    fn record_obligation(&self, scope: ResolutionScopeId, label: &'static str, evidence: &str) {
        if label == "csharp_external_unindexed" {
            self.rules
                .external_observations
                .set(self.rules.external_observations.get() + 1);
        }
        let mut hash = CanonicalHasher::new(b"csharp-lookup-obligation:v1");
        hash.field("label", label.as_bytes());
        hash.field("source", &self.source.token.get().to_le_bytes());
        hash.field("scope", &scope.get().to_le_bytes());
        hash.field("evidence", evidence.as_bytes());
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

struct CSharpRouteRules<'a, 'half, 'store, 'input> {
    half: &'a CSharpHalf<'half, 'store, 'input>,
    fragment: BindingFragmentId,
    placement: &'a CSharpUnitPlacement,
}
impl<T: Clone + Eq + std::hash::Hash> RouteRules<T> for CSharpRouteRules<'_, '_, '_, '_> {
    fn root_starts(
        &self,
        start: &WalkCursor<T>,
        _: &mut ResolutionCompletion,
    ) -> Result<RouteStarts> {
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
        Ok(Some(match self.step(&cursor.location, segment)? {
            Read::Ready {
                mut value,
                completion,
            } => {
                value.coverage = value.coverage.combine(&completion);
                value
            }
            Read::Cancelled(completion) => RouteEdgeTier {
                coverage: completion,
                blocks_fallback: true,
                ..Default::default()
            },
            Read::Unavailable { .. } => unreachable!("C# steps are ready or cancelled"),
        }))
    }
    fn dead_end(
        &self,
        cursor: &WalkCursor<T>,
        segment: &ResolutionLookupSemanticRecipe,
    ) -> Result<ResolutionCompletion> {
        self.missing(&cursor.location, segment)
    }
}

impl CSharpRouteRules<'_, '_, '_, '_> {
    fn step(
        &self,
        location: &RouteLocation,
        segment: &ResolutionLookupSemanticRecipe,
    ) -> Result<Read<RouteEdgeTier>> {
        if self.half.rules.cancellation.is_cancelled() || !self.half.rules.session.scope_step() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        let half = self.half;
        let rules = half.rules;
        let mut result = RouteEdgeTier::default();
        match location {
            RouteLocation::Container { unit, container } => {
                assert_eq!(*unit, self.placement.compilation_id);
                let mut path: Vec<String> = serde_json::from_str(container)
                    .expect("C# namespace locations contain segment arrays");
                let SelectedPackageRows::Ready(targets) = namespace_types_for_lookup(
                    rules.ready,
                    &half.units,
                    self.fragment,
                    &CSharpNamespaceLevel {
                        caller: self.placement.clone(),
                        path: path.clone(),
                    },
                    segment.semantic(&rules.ready.shared_names()),
                    rules.cancellation,
                )?
                else {
                    return Ok(Read::Cancelled(cancelled_completion()));
                };
                for target in targets {
                    result.coverage = result.coverage.combine(&target.completion);
                    result.edges.push(RouteLocation::Owner {
                        definition: target.member.definition,
                        scope: None,
                    });
                }
                path.push(segment.spelling().to_owned());
                let segments = serde_json::to_string(&path).expect("namespace segments serialize");
                // Namespace declarations span mounts. Admit their merged location only
                // after a structured namespace row and compilation access agree.
                let names = rules.ready.shared_names();
                let lookup = segment
                    .semantic(&names)
                    .shared_name_id()
                    .expect("namespace lookup is shared");
                let mounts = if let Some(persisted) = names.to_persisted(lookup) {
                    let mut statement = rules
                        .ready
                        .inventory
                        .connection()
                        .prepare_cached(NAMESPACE_CANDIDATES)?;
                    statement.query_map(rusqlite::named_params! { ":lookup": persisted.get(), ":segments": segments },
                        |row| row.get::<_, u32>(0))?.collect::<rusqlite::Result<Vec<_>>>()?
                } else {
                    Vec::new()
                };
                for ordinal in mounts {
                    if rules.cancellation.is_cancelled() {
                        return Ok(Read::Cancelled(cancelled_completion()));
                    }
                    let mount = rules
                        .ready
                        .inventory
                        .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                    let mut units = half.units.borrow_mut();
                    let placements = units.placements(mount.persisted_relative_path())?;
                    if let Some(completion) = units
                        .read_access(
                            Some(std::slice::from_ref(self.placement)),
                            placements.as_deref(),
                        )?
                        .completion(&ResolutionCompletion::Complete)
                    {
                        result.coverage = result.coverage.combine(&completion);
                        result.edges.push(RouteLocation::Container {
                            unit: *unit,
                            container: segments.clone(),
                        });
                        break;
                    }
                }
            }
            RouteLocation::Owner { definition, .. } => {
                let heads = match self.owner_heads(*definition)? {
                    Read::Ready { value, completion } => {
                        result.coverage = result.coverage.combine(&completion);
                        value
                    }
                    Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                    Read::Unavailable { .. } => {
                        unreachable!("C# owner scopes are ready or cancelled")
                    }
                };
                for head in heads {
                    let Some((paths, completion)) = scope_binding_paths(
                        rules.base,
                        head,
                        segment.semantic(&rules.ready.shared_names()),
                        rules.cancellation,
                    )?
                    else {
                        return Ok(Read::Cancelled(cancelled_completion()));
                    };
                    result.coverage = result.coverage.combine(&completion);
                    for path in paths {
                        result.coverage = result.coverage.combine(path.completion());
                        if !path.end().symbols().fixed().is_empty() {
                            continue;
                        }
                        for row in rules
                            .base
                            .classify_endpoint_nodes(&[path.end().node()], rules.cancellation)?
                        {
                            if let Some(definition) = row.definition() {
                                result.edges.push(RouteLocation::Owner {
                                    definition,
                                    // Nested types are direct definitions, not root
                                    // exports. Retain their endpoint for rank-one
                                    // unqualified selection as lexical tiers do.
                                    scope: Some(path.end().node()),
                                });
                            }
                        }
                    }
                }
            }
        }
        if rules.cancellation.is_cancelled() {
            return Ok(Read::Cancelled(
                result.coverage.combine(&cancelled_completion()),
            ));
        }
        Ok(Read::ready(result))
    }

    fn owner_heads(&self, definition: SemanticId) -> Result<Read<Vec<BindingNodeId>>> {
        let rules = self.half.rules;
        use crate::analyzer::resolution::{FactPageVisitor, TypedFactRequest};
        let typed = rules.ready.typed_source();
        let mut heads = Vec::new();
        let outcome = typed.visit_member_scope_pages_for_definitions(
            TypedFactRequest::new(&[definition]),
            rules.cancellation,
            &mut FactPageVisitor::new(&mut |rows| {
                for row in rows {
                    heads.push(row.row().scope_head());
                }
                Ok(!rules.cancellation.is_cancelled())
            }),
        )?;
        if outcome.is_cancelled() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        // The visitor stops only on cancellation, and a cancellation outranks a
        // stop, so any other terminal must be Exhausted: only then do the rows
        // read prove which member scopes the owner has.
        assert!(
            outcome.is_exhausted(),
            "C# owner scope read ended without exhausting: {outcome:?}"
        );
        let mut completion = outcome.evidence().clone();
        if heads.is_empty() {
            // An owner without a member scope row (a delegate, for example)
            // proves nothing about its members.
            let caller = rules.ready.inventory.mount_record_by_ordinal(
                SelectedResolutionMountOrdinal::new(self.fragment.ordinal()),
            )?;
            let mut hash = CanonicalHasher::new(b"csharp-owner-scope-inventory:v1");
            hash.field("owner", &definition.get().to_le_bytes());
            hash.field("compilation", &self.placement.compilation_id.to_le_bytes());
            let reason = rules.ready.context_identities.named_semantic(
                hash.finish(),
                "OwnerInventoryOpen",
                &format!(
                    "{}: the owner has no member scope to read",
                    caller.persisted_relative_path()
                ),
            );
            completion = completion.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(reason),
            ]));
        }
        Ok(Read::Ready {
            value: heads,
            completion,
        })
    }

    fn missing(
        &self,
        location: &RouteLocation,
        segment: &ResolutionLookupSemanticRecipe,
    ) -> Result<ResolutionCompletion> {
        let rules = self.half.rules;
        if rules.cancellation.is_cancelled() || !rules.session.observe_cancellation() {
            return Ok(cancelled_completion());
        }
        if let RouteLocation::Owner { definition, .. } = location {
            // Absence is provable only from an exhausted read of the owner's
            // member scopes; its evidence opens the answer otherwise.
            let (heads, mut coverage) = match self.owner_heads(*definition)? {
                Read::Ready { value, completion } => (value, completion),
                Read::Cancelled(completion) => return Ok(completion),
                Read::Unavailable { .. } => unreachable!("C# owner scopes are ready or cancelled"),
            };
            for head in &heads {
                let Some((_, completion)) = scope_binding_paths(
                    rules.base,
                    *head,
                    segment.semantic(&rules.ready.shared_names()),
                    rules.cancellation,
                )?
                else {
                    return Ok(cancelled_completion());
                };
                coverage = coverage.combine(&completion);
            }
            if coverage != ResolutionCompletion::Complete {
                return Ok(coverage);
            }
            let mount = rules.ready.inventory.mount_record_by_ordinal(
                SelectedResolutionMountOrdinal::new(
                    definition.ordinal().expect("mounted C# owner"),
                ),
            )?;
            let caller = rules.ready.inventory.mount_record_by_ordinal(
                SelectedResolutionMountOrdinal::new(self.fragment.ordinal()),
            )?;
            for head in heads {
                let names = rules
                    .ready
                    .inventory
                    .connection()
                    .prepare_cached(TYPE_WITH_EXPLICIT_BASES)?
                    .query_map(
                        rusqlite::params![mount.blob_id(), head.local_key()],
                        |row| row.get::<_, String>(0),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                for name in names {
                    let mut hash = CanonicalHasher::new(b"csharp-route-inherited-types:v1");
                    hash.field("owner", &definition.get().to_le_bytes());
                    hash.field("compilation", &self.placement.compilation_id.to_le_bytes());
                    hash.field("caller", caller.persisted_relative_path().as_bytes());
                    hash.field("segment", &segment.name_digest());
                    let reason = rules.ready.context_identities.named_semantic(
                        hash.finish(),
                        "csharp_inherited_types_unmodeled",
                        &format!(
                            "{}: {} may be inherited by type {}",
                            caller.persisted_relative_path(),
                            segment.spelling(),
                            name
                        ),
                    );
                    coverage = coverage.combine(&ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(reason),
                    ]));
                }
            }
            return Ok(coverage);
        }
        let mut hash = CanonicalHasher::new(b"csharp-route-external-unindexed:v2");
        hash.field("compilation", &self.placement.compilation_id.to_le_bytes());
        hash.field("segment_semantic", &segment.name_digest());
        let owner = match location {
            RouteLocation::Container { unit, container } => {
                assert_eq!(*unit, self.placement.compilation_id);
                let path: Vec<String> = serde_json::from_str(container)
                    .expect("C# namespace locations contain segment arrays");
                hash.field("kind", b"namespace");
                hash.field("segment_count", &(path.len() as u64).to_le_bytes());
                for part in &path {
                    hash.field("namespace_segment", part.as_bytes());
                }
                path.join(".")
            }
            RouteLocation::Owner { .. } => unreachable!("owner misses handled above"),
        };
        let mount =
            rules
                .ready
                .inventory
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(
                    self.fragment.ordinal(),
                ))?;
        hash.field("caller", mount.persisted_relative_path().as_bytes());
        let qualified = if owner.is_empty() {
            segment.spelling().to_owned()
        } else {
            format!("{owner}.{}", segment.spelling())
        };
        let evidence = format!("{}: {qualified}", mount.persisted_relative_path());
        let reason = rules.ready.context_identities.named_semantic(
            hash.finish(),
            "csharp_external_unindexed",
            &evidence,
        );
        rules
            .external_observations
            .set(rules.external_observations.get() + 1);
        rules
            .external_gaps
            .borrow_mut()
            .push((self.half.source.identity, reason));
        Ok(ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::UnsupportedSemantic(reason),
        ]))
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
        external_observations: std::cell::Cell::new(0),
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
                assert!(
                    !visited.borrow().is_empty()
                        || named_reasons.iter().any(|(name, evidence)| *name
                            == "csharp_compilation_usings_incomplete"
                            && (evidence.starts_with("membership_unproven:")
                                || evidence.starts_with("configuration_replaced:"))),
                    "probe reached a C# source half or its membership refusal"
                );
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
