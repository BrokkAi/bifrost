//! Query-owned file-context derivation and scheduling-bound publication.

use super::context_preparation::{ContextPlanMemo, ContextProjectionKey, ContextProjectionMemo};
use super::*;
use crate::analyzer::resolution::{
    FactReadOutcome, LoweredPackageMember, SelectedPackageBridgeDescriptor,
    visit_selected_root_export_half_pages,
};

/// Exact source facts for one selected request, independent of batch layout.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ContextRecipeKey {
    fragment: BindingFragmentId,
    semantic: SemanticId,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

pub(super) enum RootHalfRequest<'a> {
    Imports(&'a [SelectedResolutionMountOrdinal]),
    Exports(&'a [SelectedResolutionMountOrdinal]),
}

/// The existing Go package/role authority, also the exact peer-plan key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct PeerSelection {
    pub(super) context_id: i64,
    pub(super) package: i64,
    pub(super) source_role: String,
}

/// The concrete memo key owns its relation and every ordered SQL binding.
pub(super) trait PackagePeerRelation {
    const RELATION: &'static str;

    fn params(&self) -> impl rusqlite::Params;
}

type PreparedPackageMembers = Arc<HashMap<SemanticId, Vec<LoweredPackageMember>>>;

#[derive(Default)]
pub(super) struct FileContextReadMemos {
    recipes: ContextPlanMemo<ContextRecipeKey, ResolutionLookupSemanticRecipe>,
    peer_plans: RefCell<FileContextPeerPlans>,
}

#[derive(Default)]
struct FileContextPeerPlans {
    peers: ContextPlanMemo<PeerSelection, Vec<SelectedResolutionMountOrdinal>>,
    members:
        ContextPlanMemo<(PeerSelection, SelectedResolutionMountOrdinal), PreparedPackageMembers>,
    // The graph adapter's existing peer/member hit count, not new telemetry.
    memo_hits: std::cell::Cell<u64>,
}

/// Preserve a graph unit's existing helper lifetime while using the same
/// read-plan implementation as an ordinary selected operation.
#[doc(hidden)]
pub struct FileContextPeerMemoGuard<'operation> {
    memos: &'operation FileContextReadMemos,
    previous: Option<FileContextPeerPlans>,
}

impl Drop for FileContextPeerMemoGuard<'_> {
    fn drop(&mut self) {
        *self.memos.peer_plans.borrow_mut() = self
            .previous
            .take()
            .expect("peer memo scope restores its prior owner");
    }
}

impl super::graph_stage::GraphStageHelperTables for FileContextPeerMemoGuard<'_> {
    fn memo_stats(&self) -> super::graph_stage::GraphStageMemoStats {
        let plans = self.memos.peer_plans.borrow();
        super::graph_stage::GraphStageMemoStats {
            hits: plans.memo_hits.get(),
            distinct_keys: plans.peers.len() + plans.members.len(),
        }
    }
}

impl SelectedResolutionOperation<'_, '_> {
    #[doc(hidden)]
    pub fn file_context_peer_memo_scope(&self) -> FileContextPeerMemoGuard<'_> {
        let previous = self
            .file_context_reads
            .peer_plans
            .replace(FileContextPeerPlans::default());
        FileContextPeerMemoGuard {
            memos: &self.file_context_reads,
            previous: Some(previous),
        }
    }

    pub(super) fn clear_file_context_recipe_memo(&self) {
        self.file_context_reads.recipes.clear();
    }

    pub(super) fn read_root_inventory(
        &self,
        request: RootHalfRequest<'_>,
        cancellation: &CancellationToken,
    ) -> Result<(Vec<SelectedRootPathHalf>, FactReadOutcome)> {
        let lexical = self.ready.lexical_source();
        let mut halves = Vec::new();
        let mut collect = |page: &[SelectedRootPathHalf]| {
            halves.extend_from_slice(page);
            Ok(true)
        };
        let mut visitor = FactPageVisitor::new(&mut collect);
        let outcome = match request {
            RootHalfRequest::Imports(mounts) => visit_selected_root_import_half_pages(
                &self.ready.context_identities,
                &lexical,
                &lexical,
                Some(mounts),
                cancellation,
                &mut visitor,
            )?,
            RootHalfRequest::Exports(mounts) => visit_selected_root_export_half_pages(
                &self.ready.context_identities,
                &lexical,
                &lexical,
                Some(mounts),
                cancellation,
                &mut visitor,
            )?,
        };
        Ok((halves, outcome))
    }

    pub(super) fn read_package_peers(
        &self,
        request: &PeerSelection,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<SelectedResolutionMountOrdinal>>> {
        {
            let plans = self.file_context_reads.peer_plans.borrow();
            if let Some(peers) = plans.peers.get(request) {
                plans.memo_hits.set(plans.memo_hits.get() + 1);
                return Ok(Some(peers));
            }
        }
        let mut statement = self
            .ready
            .inventory
            .connection()
            .prepare_cached(PeerSelection::RELATION)?;
        let mut rows = statement.query(request.params())?;
        let mut peers = Vec::new();
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            peers.push(SelectedResolutionMountOrdinal::new(row.get(0)?));
        }
        self.file_context_reads
            .peer_plans
            .borrow()
            .peers
            .insert(request.clone(), peers.clone());
        Ok(Some(peers))
    }

    pub(super) fn read_package_peer_members(
        &self,
        request: &PeerSelection,
        peer: SelectedResolutionMountOrdinal,
        cancellation: &CancellationToken,
    ) -> Result<Option<PreparedPackageMembers>> {
        let key = (request.clone(), peer);
        {
            let plans = self.file_context_reads.peer_plans.borrow();
            if let Some(members) = plans.members.get(&key) {
                plans.memo_hits.set(plans.memo_hits.get() + 1);
                return Ok(Some(members));
            }
        }
        let super::package_context::SelectedPackageRows::Ready(members) = self
            .ready
            .selected_package_members_by_lookup(peer, cancellation)?
        else {
            return Ok(None);
        };
        let members = Arc::new(members);
        self.file_context_reads
            .peer_plans
            .borrow()
            .members
            .insert(key, Arc::clone(&members));
        Ok(Some(members))
    }

    fn context_recipe_key(&self, request: &SelectedLookupRecipeRequest) -> ContextRecipeKey {
        ContextRecipeKey {
            fragment: request.fragment,
            semantic: request.semantic,
            scope: self.ready.inventory.scope_identity(),
            stage_epoch: self.ready.inventory.staged_read_epoch(),
        }
    }

    /// Read missing recipes once, retaining caller order and repetitions. A
    /// missing row is returned to the language: Rust tolerates one, whereas
    /// a Go or JVM import with no recipe is corrupt. Do not negative-cache it.
    /// The observer only preserves existing page-local read profiling.
    pub(super) fn read_context_recipes(
        &self,
        source: &SelectedResolutionLexicalSource<'_, '_>,
        requests: &[SelectedLookupRecipeRequest],
        cancellation: &CancellationToken,
        observe_read: impl Fn(&SelectedLookupRecipeRequest),
    ) -> Result<Option<Vec<Option<ResolutionLookupSemanticRecipe>>>> {
        let mut seen = HashSet::default();
        let missing = requests
            .iter()
            .filter(|request| {
                let key = self.context_recipe_key(request);
                seen.insert(key) && !self.file_context_reads.recipes.contains_key(&key)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut computed = Vec::new();
        for page in missing.chunks(crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH) {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            for request in page {
                observe_read(request);
            }
            let SelectedLookupRecipeReadOutcome::Ready(rows) =
                source.lookup_semantic_recipes(page, cancellation, None)?
            else {
                return Ok(None);
            };
            assert_eq!(rows.len(), page.len(), "one recipe result per request");
            for (request, recipe) in page.iter().zip(rows) {
                if let Some(recipe) = recipe {
                    computed.push((self.context_recipe_key(request), recipe));
                }
            }
        }
        for (key, recipe) in computed {
            self.file_context_reads.recipes.insert(key, recipe);
        }
        Ok(Some(
            requests
                .iter()
                .map(|request| {
                    self.file_context_reads
                        .recipes
                        .get(&self.context_recipe_key(request))
                })
                .collect(),
        ))
    }
}

#[doc(hidden)]
#[derive(Default)]
pub struct ContextBlueprintMemo {
    roots: ContextProjectionMemo<
        ContextProjectionKey<SelectedRootBridgeDescriptor>,
        crate::analyzer::resolution::SelectedRootBridgeProjection,
    >,
    packages: ContextProjectionMemo<
        ContextProjectionKey<SelectedPackageBridgeDescriptor>,
        (
            CandidatePathIdentity,
            crate::analyzer::resolution::PartialPath,
        ),
    >,
}

impl ReadySelectedResolution<'_, '_> {
    fn profile_context_read(&self, kind: &'static str, key: impl std::fmt::Debug) {
        if let Some(profile) = self.jvm_context_profile.borrow_mut().as_mut() {
            *profile.calls.entry((kind, format!("{key:?}"))).or_default() += 1;
        }
    }

    #[doc(hidden)]
    pub fn publish_context_paths(
        &self,
        context: SelectedResolutionContextInputs,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<crate::analyzer::resolution::SelectedContextPathPublicationOutcome> {
        self.publish_context_paths_with_projection_memo(context, None, cancellation, session)
    }

    pub(super) fn publish_context_paths_with_projection_memo(
        &self,
        context: SelectedResolutionContextInputs,
        memo: Option<&ContextBlueprintMemo>,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<crate::analyzer::resolution::SelectedContextPathPublicationOutcome> {
        let scope = self.inventory.scope_identity();
        let stage_epoch = self.inventory.staged_read_epoch();
        let names = self.shared_names();
        let mut root_keys = Vec::new();
        let mut package_keys = Vec::new();
        let publication = self.publish_context_paths_with_compilers(
            context,
            cancellation,
            session,
            |identities, bridge| {
                let key = ContextProjectionKey {
                    derivation: bridge.clone(),
                    scope,
                    stage_epoch,
                };
                let compile = || {
                    self.profile_context_read(
                        "compile_root_context_cell",
                        bridge.source_fragment(),
                    );
                    crate::analyzer::resolution::compile_selected_root_bridge(
                        &self.lexical_source(),
                        identities,
                        bridge,
                        &names,
                        cancellation,
                        session,
                    )
                };
                let projected = match memo {
                    Some(memo) => memo.roots.project(&key, compile)?,
                    None => compile()?.map(|value| SelectedContextCellProjection {
                        value: Arc::new(value),
                        published: None,
                    }),
                };
                if projected.is_some() {
                    root_keys.push(key);
                }
                Ok(projected)
            },
            |identities, bridge| {
                let key = ContextProjectionKey {
                    derivation: bridge.clone(),
                    scope,
                    stage_epoch,
                };
                let compile = || {
                    self.profile_context_read("compile_package_context_cell", scope);
                    bridge.compile(identities, &self.lexical_source(), cancellation, session)
                };
                let projected = match memo {
                    Some(memo) => memo.packages.project(&key, compile)?,
                    None => compile()?.map(|value| SelectedContextCellProjection {
                        value: Arc::new(value),
                        published: None,
                    }),
                };
                if projected.is_some() {
                    package_keys.push(key);
                }
                Ok(projected)
            },
        )?;
        if let Some(memo) = memo
            && let crate::analyzer::resolution::SelectedContextPathPublicationOutcome::Ready(
                publication,
            ) = &publication
        {
            memo.roots.publish(root_keys, publication.token);
            memo.packages.publish(package_keys, publication.token);
        }
        Ok(publication)
    }

    /// Publish only at the consumer's scheduling boundary. Registration rules
    /// retain provider-ledger deltas and Rust's independent receiver charges.
    #[doc(hidden)]
    pub fn publish_prepared_context(
        &self,
        context: SelectedResolutionContextInputs,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
        memo: Option<&ContextBlueprintMemo>,
        register: impl FnOnce(&SelectedFactOperationBlueprint) -> Result<ContextRegistrationOutcome>,
    ) -> Result<Option<SelectedFactOperationBlueprint>> {
        let SelectedFactOperationBlueprintConstruction::Ready(blueprint) =
            self.collect_blueprint_with_projection_memo(context, memo, cancellation, session)?
        else {
            return Ok(None);
        };
        Ok(match register(&blueprint)? {
            ContextRegistrationOutcome::Ready => Some(blueprint),
            ContextRegistrationOutcome::Cancelled => None,
        })
    }
}
