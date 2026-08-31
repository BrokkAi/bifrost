//! File-level test-scope evidence derived from a source diff.

use crate::CancellationToken;
use crate::analyzer::usages::workspace_graph::{UsageEcosystem, WorkspaceUsageRankingGraph};
use crate::analyzer::{AnalyzerQueryScope, IAnalyzer, Language, ProjectFile, QueryScope};
use crate::diff_analysis::{
    CommitSymbol, DiffAnalysisOptions, DiffEndpointParams, PairedSymbolChanges, PreparedDiff,
    RevisionAnalyzer, RevisionImage, Snapshot, analyze_prepared_symbol_changes,
    build_file_dependency_analyzer,
};
use crate::relevance::{Cancellable, acquire_file_usage_graph_with_cancellation};
use crate::searchtools_render::{RenderOptions, RenderText};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use std::path::{Component, Path};
use std::sync::Arc;

mod missing_tests;

pub use missing_tests::*;

pub const DEFAULT_MAX_SCOPES: usize = 100;
pub const MAX_SCOPES: usize = 1_000;

fn default_max_scopes() -> usize {
    DEFAULT_MAX_SCOPES
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlastRadiusParams {
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default = "default_max_scopes")]
    pub max_scopes: usize,
}

impl Default for BlastRadiusParams {
    fn default() -> Self {
        Self {
            base: None,
            target: None,
            max_scopes: DEFAULT_MAX_SCOPES,
        }
    }
}

impl BlastRadiusParams {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=MAX_SCOPES).contains(&self.max_scopes) {
            return Err(format!(
                "max_scopes must be between 1 and {MAX_SCOPES}, inclusive"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct BlastRadiusResult {
    pub endpoints: BlastRadiusEndpoints,
    pub analysis: BlastRadiusAnalysis,
    pub changed_callables: Vec<ChangedCallable>,
    pub test_scopes: Vec<TestScope>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct BlastRadiusEndpoints {
    pub base: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct BlastRadiusAnalysis {
    /// Evidence model used to reach test files.
    pub mode: BlastRadiusMode,
    /// Whether construction and traversal of the selected structured file
    /// dependency graphs completed. This does not claim complete knowledge of
    /// runtime test impact.
    pub graph_completion: FileGraphCompletion,
    pub base_recovery: BaseRecoveryState,
    /// Exact number of test-containing files reached through the structured
    /// file graph before presentation scopes are coalesced.
    pub reached_test_file_count: usize,
    /// Changed paths whose file type is outside Bifrost's analyzer-backed file
    /// graph. These paths may still drive tests through build, data, or workflow
    /// conventions that this evidence model cannot observe.
    pub paths_outside_file_graph: Vec<String>,
    /// Changed target files that the target analyzer structurally classifies
    /// as containing test code. Every path is seeded at dependency distance
    /// zero independently of presentation-scope coalescing.
    pub analyzer_changed_test_paths: Vec<String>,
    pub unresolved_changed_paths: Vec<String>,
    pub unavailable_removed_test_count: usize,
    pub incomplete_reasons: Vec<BlastRadiusIncompleteReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlastRadiusMode {
    FileImports,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileGraphCompletion {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BaseRecoveryState {
    NotNeeded,
    Complete,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlastRadiusIncompleteReason {
    TargetGraphCancelled,
    BaseGraphCancelled,
    CompilationScopeUnresolved,
    UnresolvedChangedPaths,
    UnresolvedBasePaths,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ChangedCallable {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<BlastRadiusCallableSymbol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<BlastRadiusCallableSymbol>,
    pub changes: Vec<CallableChangeTag>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct BlastRadiusCallableSymbol {
    pub fqn: String,
    pub name: String,
    pub kind: String,
    pub signature: String,
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub language: String,
    /// The declaration is structurally nested in test code or lives under a
    /// language-recognized test-tree path. This is contextual evidence, not a
    /// claim that the declaration is an individually runnable test.
    pub in_test_context: bool,
}

impl From<&CommitSymbol> for BlastRadiusCallableSymbol {
    fn from(symbol: &CommitSymbol) -> Self {
        Self {
            fqn: symbol.fqn.clone(),
            name: symbol.name.clone(),
            kind: symbol.kind.clone(),
            signature: symbol.signature.clone(),
            path: symbol.path.clone(),
            start_line: symbol.start_line,
            end_line: symbol.end_line,
            language: symbol.language.clone(),
            in_test_context: symbol.is_test,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CallableChangeTag {
    Edited,
    Introduced,
    Deleted,
    Moved,
    SignatureChanged,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct TestScope {
    pub path: String,
    pub kind: TestScopeKind,
    pub reached_file_count: usize,
    pub covered_analyzable_file_count: usize,
    pub minimum_dependency_distance: usize,
    pub maximum_dependency_distance: usize,
    pub sample_reached_files: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TestScopeKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Copy)]
struct DistanceRange {
    minimum: usize,
    maximum: usize,
}

impl DistanceRange {
    fn include(&mut self, distance: usize) {
        self.minimum = self.minimum.min(distance);
        self.maximum = self.maximum.max(distance);
    }
}

struct TargetEvidence {
    affected: BTreeMap<String, DistanceRange>,
    analyzer_changed_test_paths: Vec<String>,
    target_nodes: BTreeSet<String>,
    unresolved: Vec<String>,
    graph_cancelled: bool,
    graph_incomplete: bool,
    graph: Option<Arc<WorkspaceUsageRankingGraph>>,
}

enum TargetFileDependencyAnalyzer<'a> {
    Live(&'a dyn IAnalyzer),
    Revision {
        analyzer: RevisionAnalyzer,
        // Keep the materialized tree alive until every analyzer query ends.
        _image: RevisionImage,
    },
}

impl TargetFileDependencyAnalyzer<'_> {
    fn analyzer(&self) -> &dyn IAnalyzer {
        match self {
            Self::Live(analyzer) => *analyzer,
            Self::Revision { analyzer, .. } => analyzer.analyzer(),
        }
    }
}

fn target_diff_paths(prepared: &PreparedDiff) -> BTreeSet<String> {
    prepared
        .file_changes
        .iter()
        .filter(|change| change.is_parseable && change.status != "deleted")
        .filter_map(|change| change.path.clone())
        .collect()
}

fn revision_graph_paths(prepared: &PreparedDiff) -> BTreeSet<String> {
    prepared
        .file_changes
        .iter()
        .filter(|change| change.is_parseable)
        .flat_map(|change| change.old_path.iter().chain(change.path.iter()))
        .cloned()
        .collect()
}

fn build_target_file_dependency_analyzer<'a>(
    prepared: &PreparedDiff,
    live_target_analyzer: Option<&'a dyn IAnalyzer>,
) -> Result<TargetFileDependencyAnalyzer<'a>, String> {
    if prepared.target == Snapshot::Worktree {
        return live_target_analyzer
            .map(TargetFileDependencyAnalyzer::Live)
            .ok_or_else(|| {
                "diff file-dependency analysis requires the current workspace snapshot for a worktree target"
                    .to_string()
            });
    }

    let target_languages = graph_languages_for_paths(&revision_graph_paths(prepared));
    let image = prepared.materialize_file_dependencies(prepared.target, &target_languages)?;
    let analyzer =
        build_file_dependency_analyzer(&image, prepared.shared_cache(), &target_languages)?;
    Ok(TargetFileDependencyAnalyzer::Revision {
        analyzer,
        _image: image,
    })
}

/// Compute file-dependency blast-radius evidence for a diff.
///
/// `live_target_analyzer` is required only when the resolved target is the
/// worktree. An immutable target is analyzed from its own revision image,
/// whose facts come from the repository's shared content-addressed analyzer
/// cache: a fact is keyed by Git blob id, language storage key and the
/// language's current generation, so a blob the cache already holds is read
/// rather than parsed, and the blobs parsed here are left behind for every
/// later consumer -- the live worktree, a linked worktree, or another
/// revision. The build holds the per-cache build lock for its whole
/// reconciliation, exactly as a worktree build does. When the host has no
/// usable persisted cache the same full build runs against an ephemeral
/// store, which changes the parse bill and nothing about the answer.
pub fn blast_radius_at_root(
    root: &Path,
    live_target_analyzer: Option<&dyn IAnalyzer>,
    params: BlastRadiusParams,
    options: &DiffAnalysisOptions,
    cancellation: &CancellationToken,
) -> Result<BlastRadiusResult, String> {
    params.validate()?;
    let prepared = PreparedDiff::at_root(
        root,
        DiffEndpointParams {
            base: params.base.clone(),
            target: params.target.clone(),
        },
        options,
    )?;

    let target_paths = target_diff_paths(&prepared);
    // A deleted or renamed-away seed still needs its ecosystem in the target
    // image: base recovery maps surviving downstream tests back into that
    // target graph. Selecting from both sides retains that mapping without
    // parsing any unrelated ecosystem.
    let target_context = build_target_file_dependency_analyzer(&prepared, live_target_analyzer)?;
    let target_analyzer = target_context.analyzer();

    let paths_outside_file_graph = prepared
        .file_changes
        .iter()
        .filter(|change| !change.is_parseable)
        .filter_map(|change| change.path.as_ref().or(change.old_path.as_ref()).cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut target_evidence = collect_target_evidence(target_analyzer, &target_paths, cancellation);
    let rename_targets: BTreeMap<_, _> = prepared
        .file_changes
        .iter()
        .filter_map(|change| Some((change.old_path.clone()?, change.path.clone()?)))
        .collect();

    let mut base_paths = BTreeSet::new();
    for change in &prepared.file_changes {
        if !change.is_parseable {
            continue;
        }
        let preimage = change.old_path.as_ref().or(change.path.as_ref());
        let Some(preimage) = preimage else {
            continue;
        };
        if change.status == "deleted"
            || change.old_path.is_some()
            || !target_evidence.target_nodes.contains(preimage)
        {
            base_paths.insert(preimage.clone());
        }
    }

    let mut reasons = BTreeSet::new();
    if target_evidence.graph_cancelled {
        reasons.insert(BlastRadiusIncompleteReason::TargetGraphCancelled);
    }
    if target_evidence.graph_incomplete {
        reasons.insert(BlastRadiusIncompleteReason::CompilationScopeUnresolved);
    }
    if !target_evidence.unresolved.is_empty() {
        reasons.insert(BlastRadiusIncompleteReason::UnresolvedChangedPaths);
    }

    let mut base_recovery = BaseRecoveryState::NotNeeded;
    let mut unavailable_removed_tests = BTreeSet::new();
    if !base_paths.is_empty() {
        base_recovery = BaseRecoveryState::Complete;
        let base_languages = graph_languages_for_paths(&base_paths);
        let base_image = prepared.materialize_file_dependencies(prepared.base, &base_languages)?;
        let base_workspace =
            build_file_dependency_analyzer(&base_image, prepared.shared_cache(), &base_languages)?;
        let base_analyzer = base_workspace.analyzer();
        let base_scope = AnalyzerQueryScope::new(base_analyzer);
        let base_files = resolve_seed_files(base_analyzer, &base_paths);
        let unresolved_base = base_paths
            .iter()
            .filter(|path| !base_files.contains_key(*path))
            .cloned()
            .collect::<Vec<_>>();
        if !unresolved_base.is_empty() {
            reasons.insert(BlastRadiusIncompleteReason::UnresolvedBasePaths);
        }
        let ecosystems = ecosystems_for_files(base_files.values());
        let base_graph = match acquire_file_usage_graph_with_cancellation(
            base_analyzer,
            base_scope.token(),
            &ecosystems,
            cancellation,
        ) {
            Cancellable::Complete(graph) => Some(graph),
            Cancellable::Incomplete(graph) => {
                reasons.insert(BlastRadiusIncompleteReason::CompilationScopeUnresolved);
                Some(graph)
            }
            Cancellable::Cancelled => {
                base_recovery = BaseRecoveryState::Cancelled;
                reasons.insert(BlastRadiusIncompleteReason::BaseGraphCancelled);
                None
            }
        };
        if let Some(graph) = base_graph {
            let reached = reverse_walk(&graph, base_files.values());
            for (base_test, distance) in reached {
                let target_path = rename_targets
                    .get(&base_test)
                    .cloned()
                    .unwrap_or_else(|| base_test.clone());
                let Some(target_file) = target_analyzer
                    .project()
                    .file_by_rel_path(Path::new(&target_path))
                else {
                    unavailable_removed_tests.insert(base_test);
                    continue;
                };
                if !target_analyzer.contains_tests(&target_file) {
                    unavailable_removed_tests.insert(base_test);
                    continue;
                }
                target_evidence
                    .affected
                    .entry(target_path)
                    .and_modify(|range| range.include(distance))
                    .or_insert(DistanceRange {
                        minimum: distance,
                        maximum: distance,
                    });
            }
        }
    }

    let symbol_changes = analyze_prepared_symbol_changes(&prepared, true)?.into_symbol_changes();
    let changed_callables = changed_callables(&symbol_changes);
    let analyzer_paths = target_analyzer
        .analyzed_files()
        .into_iter()
        .map(|file| normalized_path(file.rel_path()))
        .collect::<BTreeSet<_>>();
    let test_scopes = coalesce_scopes(
        &target_evidence.affected,
        &analyzer_paths,
        params.max_scopes,
    );
    let incomplete_reasons = reasons.into_iter().collect::<Vec<_>>();
    let graph_completion = if incomplete_reasons.is_empty() {
        FileGraphCompletion::Complete
    } else {
        FileGraphCompletion::Incomplete
    };

    Ok(BlastRadiusResult {
        endpoints: BlastRadiusEndpoints {
            base: prepared.base.label(),
            target: prepared.target.label(),
        },
        analysis: BlastRadiusAnalysis {
            mode: BlastRadiusMode::FileImports,
            graph_completion,
            base_recovery,
            reached_test_file_count: target_evidence.affected.len(),
            paths_outside_file_graph,
            analyzer_changed_test_paths: target_evidence.analyzer_changed_test_paths,
            unresolved_changed_paths: target_evidence.unresolved,
            unavailable_removed_test_count: unavailable_removed_tests.len(),
            incomplete_reasons,
        },
        changed_callables,
        test_scopes,
    })
}

fn collect_target_evidence(
    analyzer: &dyn IAnalyzer,
    paths: &BTreeSet<String>,
    cancellation: &CancellationToken,
) -> TargetEvidence {
    let seed_files = resolve_seed_files(analyzer, paths);
    let analyzer_changed_test_paths = seed_files
        .iter()
        .filter(|(_, file)| analyzer.contains_tests_for_changed_file(file))
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    let mut affected = BTreeMap::new();
    for path in &analyzer_changed_test_paths {
        affected.insert(
            path.clone(),
            DistanceRange {
                minimum: 0,
                maximum: 0,
            },
        );
    }
    let mut unresolved = paths
        .iter()
        .filter(|path| !seed_files.contains_key(*path))
        .cloned()
        .collect::<Vec<_>>();
    let ecosystems = ecosystems_for_files(seed_files.values());
    let scope = AnalyzerQueryScope::new(analyzer);
    let (graph, graph_incomplete) = match acquire_file_usage_graph_with_cancellation(
        analyzer,
        scope.token(),
        &ecosystems,
        cancellation,
    ) {
        Cancellable::Complete(graph) => (graph, false),
        Cancellable::Incomplete(graph) => (graph, true),
        Cancellable::Cancelled => {
            return TargetEvidence {
                affected,
                analyzer_changed_test_paths,
                target_nodes: seed_files.keys().cloned().collect(),
                unresolved,
                graph_cancelled: true,
                graph_incomplete: false,
                graph: None,
            };
        }
    };
    let graph_paths = graph
        .node_indices_by_file
        .keys()
        .map(|file| normalized_path(file.rel_path()))
        .collect::<BTreeSet<_>>();
    for (path, file) in &seed_files {
        if !graph.node_indices_by_file.contains_key(file) {
            unresolved.push(path.clone());
        }
    }
    let reached = reverse_walk(&graph, seed_files.values());
    for (path, distance) in reached {
        affected
            .entry(path)
            .and_modify(|range| range.include(distance))
            .or_insert(DistanceRange {
                minimum: distance,
                maximum: distance,
            });
    }
    unresolved.sort();
    unresolved.dedup();
    TargetEvidence {
        affected,
        analyzer_changed_test_paths,
        target_nodes: graph_paths,
        unresolved,
        graph_cancelled: false,
        graph_incomplete,
        graph: Some(graph),
    }
}

fn resolve_seed_files(
    analyzer: &dyn IAnalyzer,
    paths: &BTreeSet<String>,
) -> BTreeMap<String, ProjectFile> {
    paths
        .iter()
        .filter_map(|path| {
            analyzer
                .project()
                .file_by_rel_path(Path::new(path))
                .map(|file| (path.clone(), file))
        })
        .collect()
}

fn ecosystems_for_files<'a>(
    files: impl IntoIterator<Item = &'a ProjectFile>,
) -> BTreeSet<UsageEcosystem> {
    files
        .into_iter()
        .map(|file| UsageEcosystem::of(crate::analyzer::common::language_for_file(file)))
        .collect()
}

fn graph_languages_for_paths(paths: &BTreeSet<String>) -> BTreeSet<Language> {
    let ecosystems = paths
        .iter()
        .filter_map(|path| Path::new(path).extension().and_then(|value| value.to_str()))
        .map(Language::from_extension)
        .filter(|language| *language != Language::None)
        .map(UsageEcosystem::of)
        .collect::<BTreeSet<_>>();
    Language::ANALYZABLE
        .into_iter()
        .filter(|language| ecosystems.contains(&UsageEcosystem::of(*language)))
        .collect()
}

fn reverse_walk<'a>(
    graph: &WorkspaceUsageRankingGraph,
    seeds: impl IntoIterator<Item = &'a ProjectFile>,
) -> BTreeMap<String, usize> {
    let distances = reverse_distances(graph, seeds);
    let mut reached = BTreeMap::new();
    for (index, distance) in distances.into_iter().enumerate() {
        let Some(distance) = distance else {
            continue;
        };
        let node = &graph.nodes[index];
        if node
            .contains_tests
            .expect("file-dependency graph nodes carry test classification")
        {
            let file = &node.primary_file;
            reached.insert(normalized_path(file.rel_path()), distance);
        }
    }
    reached
}

fn reverse_reachable_files<'a>(
    graph: &WorkspaceUsageRankingGraph,
    seeds: impl IntoIterator<Item = &'a ProjectFile>,
) -> BTreeSet<ProjectFile> {
    reverse_distances(graph, seeds)
        .into_iter()
        .enumerate()
        .filter_map(|(index, distance)| distance.map(|_| graph.nodes[index].primary_file.clone()))
        .collect()
}

fn reverse_distances<'a>(
    graph: &WorkspaceUsageRankingGraph,
    seeds: impl IntoIterator<Item = &'a ProjectFile>,
) -> Vec<Option<usize>> {
    let mut incoming = vec![Vec::new(); graph.nodes.len()];
    for edge in &graph.edges {
        incoming[edge.to].push(edge.from);
    }
    for neighbors in &mut incoming {
        neighbors.sort_unstable();
        neighbors.dedup();
    }

    let mut distances = vec![None; graph.nodes.len()];
    let mut queue = VecDeque::new();
    for seed in seeds {
        if let Some(indices) = graph.node_indices_by_file.get(seed) {
            for &index in indices {
                if distances[index].is_none() {
                    distances[index] = Some(0);
                    queue.push_back(index);
                }
            }
        }
    }
    while let Some(node) = queue.pop_front() {
        let next_distance = distances[node].expect("queued nodes have a distance") + 1;
        for &importer in &incoming[node] {
            if distances[importer].is_none() {
                distances[importer] = Some(next_distance);
                queue.push_back(importer);
            }
        }
    }
    distances
}

fn changed_callables(changes: &PairedSymbolChanges) -> Vec<ChangedCallable> {
    #[derive(Default)]
    struct Builder {
        before: Option<BlastRadiusCallableSymbol>,
        after: Option<BlastRadiusCallableSymbol>,
        changes: BTreeSet<CallableChangeTag>,
    }

    fn symbol_key(symbol: &CommitSymbol) -> String {
        format!(
            "{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}",
            symbol.path, symbol.fqn, symbol.kind, symbol.start_line, symbol.end_line
        )
    }

    fn pair_key(before: Option<&CommitSymbol>, after: Option<&CommitSymbol>) -> String {
        format!(
            "{}\u{1}{}",
            before.map(symbol_key).unwrap_or_default(),
            after.map(symbol_key).unwrap_or_default()
        )
    }

    fn record(
        builders: &mut BTreeMap<String, Builder>,
        before: Option<&CommitSymbol>,
        after: Option<&CommitSymbol>,
        tag: CallableChangeTag,
    ) {
        if !before
            .into_iter()
            .chain(after)
            .any(|symbol| symbol.kind == "function")
        {
            return;
        }
        let builder = builders.entry(pair_key(before, after)).or_default();
        if builder.before.is_none() {
            builder.before = before.map(BlastRadiusCallableSymbol::from);
        }
        if builder.after.is_none() {
            builder.after = after.map(BlastRadiusCallableSymbol::from);
        }
        builder.changes.insert(tag);
    }

    let mut builders = BTreeMap::new();
    for item in &changes.edited {
        record(
            &mut builders,
            Some(&item.before),
            Some(&item.after),
            CallableChangeTag::Edited,
        );
    }
    for item in &changes.introduced {
        record(
            &mut builders,
            None,
            Some(&item.after),
            CallableChangeTag::Introduced,
        );
    }
    for item in &changes.deleted {
        record(
            &mut builders,
            Some(&item.before),
            None,
            CallableChangeTag::Deleted,
        );
    }
    for item in &changes.moved {
        record(
            &mut builders,
            Some(&item.before),
            Some(&item.after),
            CallableChangeTag::Moved,
        );
    }
    for item in &changes.signature_changes {
        record(
            &mut builders,
            Some(&item.before),
            Some(&item.after),
            CallableChangeTag::SignatureChanged,
        );
    }
    builders
        .into_values()
        .map(|builder| ChangedCallable {
            before: builder.before,
            after: builder.after,
            changes: builder.changes.into_iter().collect(),
        })
        .collect()
}

fn coalesce_scopes(
    affected: &BTreeMap<String, DistanceRange>,
    analyzer_paths: &BTreeSet<String>,
    max_scopes: usize,
) -> Vec<TestScope> {
    let mut directories = BTreeSet::from([".".to_string()]);
    for path in affected.keys() {
        directories.extend(parent_directories(path));
    }
    let directory_ids = directories
        .iter()
        .cloned()
        .enumerate()
        .map(|(id, path)| (path, id))
        .collect::<BTreeMap<_, _>>();
    let mut directory_states = directories
        .into_iter()
        .map(|path| DirectoryCollapseState {
            parent: (path != ".").then(|| directory_ids[&parent_directory(&path)]),
            depth: usize::from(path != ".") * path_components(&path).len(),
            path,
            affected_count: 0,
            sample_affected: Vec::new(),
            directory_coverage: 0,
            frontier_count: 0,
            frontier_coverage: 0,
            distances: None,
            selected: false,
            revision: 0,
        })
        .collect::<Vec<_>>();
    for (path, distances) in affected {
        for directory in parent_directories(path) {
            let state = &mut directory_states[directory_ids[&directory]];
            state.affected_count += 1;
            state.frontier_count += 1;
            state.frontier_coverage += 1;
            if state.sample_affected.len() < 5 {
                state.sample_affected.push(path.clone());
            }
            state.distances = Some(match state.distances {
                Some(current) => DistanceRange {
                    minimum: current.minimum.min(distances.minimum),
                    maximum: current.maximum.max(distances.maximum),
                },
                None => *distances,
            });
        }
    }
    for path in analyzer_paths {
        for directory in parent_directories(path) {
            if let Some(id) = directory_ids.get(&directory) {
                directory_states[*id].directory_coverage += 1;
            }
        }
    }
    let mut collapse_candidates = directory_states
        .iter()
        .enumerate()
        .filter_map(|(id, state)| CollapseCandidate::from_state(id, state))
        .collect::<BinaryHeap<_>>();
    let mut scope_count = affected.len();

    while scope_count > max_scopes {
        let selected_id = loop {
            let candidate = collapse_candidates
                .pop()
                .expect("more than one scope always has a common root collapse");
            let state = &directory_states[candidate.directory];
            if state.revision == candidate.revision
                && state.frontier_count >= 2
                && !has_selected_ancestor(candidate.directory, &directory_states)
            {
                break candidate.directory;
            }
        };
        let (removed_scopes, previous_coverage, directory_coverage, mut ancestor) = {
            let selected = &mut directory_states[selected_id];
            let removed_scopes = selected.frontier_count - 1;
            let previous_coverage = selected.frontier_coverage;
            selected.frontier_count = 1;
            selected.frontier_coverage = selected.directory_coverage;
            selected.selected = true;
            selected.revision += 1;
            (
                removed_scopes,
                previous_coverage,
                selected.directory_coverage,
                selected.parent,
            )
        };
        scope_count -= removed_scopes;
        while let Some(ancestor_id) = ancestor {
            let state = &mut directory_states[ancestor_id];
            state.frontier_count -= removed_scopes;
            state.frontier_coverage = state
                .frontier_coverage
                .saturating_sub(previous_coverage)
                .saturating_add(directory_coverage);
            state.revision += 1;
            let candidate = CollapseCandidate::from_state(ancestor_id, state);
            ancestor = state.parent;
            if let Some(candidate) = candidate {
                collapse_candidates.push(candidate);
            }
        }
    }

    let mut scopes = directory_states
        .iter()
        .enumerate()
        .filter(|(id, state)| state.selected && !has_selected_ancestor(*id, &directory_states))
        .map(|(_, state)| {
            let distances = state
                .distances
                .expect("a selected directory contains affected files");
            TestScope {
                path: state.path.clone(),
                kind: TestScopeKind::Directory,
                reached_file_count: state.affected_count,
                covered_analyzable_file_count: state.directory_coverage,
                minimum_dependency_distance: distances.minimum,
                maximum_dependency_distance: distances.maximum,
                sample_reached_files: state.sample_affected.clone(),
            }
        })
        .collect::<Vec<_>>();
    scopes.extend(
        affected
            .iter()
            .filter(|(path, _)| {
                parent_directories(path)
                    .into_iter()
                    .all(|directory| !directory_states[directory_ids[&directory]].selected)
            })
            .map(|(path, distances)| TestScope {
                path: path.clone(),
                kind: TestScopeKind::File,
                reached_file_count: 1,
                covered_analyzable_file_count: 1,
                minimum_dependency_distance: distances.minimum,
                maximum_dependency_distance: distances.maximum,
                sample_reached_files: Vec::new(),
            }),
    );
    scopes.sort_by(|left, right| left.path.cmp(&right.path));
    debug_assert_eq!(scope_count, scopes.len());
    debug_assert_eq!(
        affected.len(),
        scopes
            .iter()
            .map(|scope| scope.reached_file_count)
            .sum::<usize>()
    );
    scopes
}

struct DirectoryCollapseState {
    path: String,
    parent: Option<usize>,
    depth: usize,
    affected_count: usize,
    sample_affected: Vec<String>,
    directory_coverage: usize,
    frontier_count: usize,
    frontier_coverage: usize,
    distances: Option<DistanceRange>,
    selected: bool,
    revision: usize,
}

impl DirectoryCollapseState {
    fn scopes_removed(&self) -> usize {
        self.frontier_count - 1
    }

    fn additional_coverage(&self) -> usize {
        self.directory_coverage
            .saturating_sub(self.frontier_coverage)
    }

    fn spill(&self) -> usize {
        self.directory_coverage.saturating_sub(self.affected_count)
    }
}

fn has_selected_ancestor(directory: usize, directory_states: &[DirectoryCollapseState]) -> bool {
    let mut ancestor = directory_states[directory].parent;
    while let Some(ancestor_id) = ancestor {
        let state = &directory_states[ancestor_id];
        if state.selected {
            return true;
        }
        ancestor = state.parent;
    }
    false
}

#[derive(Clone, Eq, PartialEq)]
struct CollapseCandidate {
    directory: usize,
    lexical_rank: usize,
    depth: usize,
    scopes_removed: usize,
    additional_coverage: usize,
    spill: usize,
    revision: usize,
}

impl CollapseCandidate {
    fn from_state(directory: usize, state: &DirectoryCollapseState) -> Option<Self> {
        (!state.selected && state.frontier_count >= 2).then(|| Self {
            directory,
            lexical_rank: directory,
            depth: state.depth,
            scopes_removed: state.scopes_removed(),
            additional_coverage: state.additional_coverage(),
            spill: state.spill(),
            revision: state.revision,
        })
    }
}

impl Ord for CollapseCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_collapse_candidates(other, self).then_with(|| self.revision.cmp(&other.revision))
    }
}

impl PartialOrd for CollapseCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_collapse_candidates(left: &CollapseCandidate, right: &CollapseCandidate) -> Ordering {
    let left_ratio = left.additional_coverage as u128 * right.scopes_removed as u128;
    let right_ratio = right.additional_coverage as u128 * left.scopes_removed as u128;
    left_ratio
        .cmp(&right_ratio)
        .then_with(|| left.spill.cmp(&right.spill))
        .then_with(|| right.depth.cmp(&left.depth))
        .then_with(|| left.lexical_rank.cmp(&right.lexical_rank))
}

fn parent_directories(path: &str) -> Vec<String> {
    let components = path_components(path);
    let mut directories = Vec::with_capacity(components.len());
    directories.push(".".to_string());
    for end in 1..components.len() {
        directories.push(components[..end].join("/"));
    }
    directories
}

fn parent_directory(directory: &str) -> String {
    directory
        .rsplit_once('/')
        .map(|(parent, _)| parent.to_string())
        .unwrap_or_else(|| ".".to_string())
}

fn path_components(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|component| !component.is_empty())
        .collect()
}

fn normalized_path(path: &Path) -> String {
    let parts = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            Component::CurDir => None,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                debug_assert!(
                    false,
                    "project-relative paths contain only normal components"
                );
                None
            }
        })
        .collect::<Vec<_>>();
    if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}

impl RenderText for BlastRadiusResult {
    fn render_text(&self, _options: RenderOptions) -> String {
        let mut lines = vec![
            "# Test blast radius (structured file-dependency evidence)".to_string(),
            String::new(),
            "This is not a method call graph or runtime coverage report.".to_string(),
            String::new(),
            format!(
                "- Endpoints: `{}` -> `{}`",
                self.endpoints.base, self.endpoints.target
            ),
            format!(
                "- File-graph completion: `{:?}`",
                self.analysis.graph_completion
            ),
            format!(
                "- Test files reached through structured file dependencies: {}",
                self.analysis.reached_test_file_count
            ),
            format!("- Changed callables: {}", self.changed_callables.len()),
        ];
        if !self.analysis.incomplete_reasons.is_empty() {
            lines.push(format!(
                "- Incomplete reasons: `{:?}`",
                self.analysis.incomplete_reasons
            ));
        }
        if !self.analysis.paths_outside_file_graph.is_empty() {
            lines.push(format!(
                "- Changed paths outside the file graph: `{:?}`",
                self.analysis.paths_outside_file_graph
            ));
            lines.push(
                "  These paths may require build, data, or workflow validation that this graph cannot infer."
                    .to_string(),
            );
        }
        if !self.analysis.analyzer_changed_test_paths.is_empty() {
            lines.push(format!(
                "- Changed target files structurally classified as tests: `{:?}`",
                self.analysis.analyzer_changed_test_paths
            ));
        }
        if self.test_scopes.is_empty() {
            lines.push(String::new());
            lines.push(
                "No test files were reached through structured file dependencies.".to_string(),
            );
        } else {
            lines.push(String::new());
            lines.push("## Suggested scopes".to_string());
            lines.push(String::new());
            for scope in &self.test_scopes {
                lines.push(format!(
                    "- `{}` ({:?}, {} reached, {} analyzable covered, distance {}..={})",
                    scope.path,
                    scope.kind,
                    scope.reached_file_count,
                    scope.covered_analyzable_file_count,
                    scope.minimum_dependency_distance,
                    scope.maximum_dependency_distance
                ));
            }
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnalyzerConfig, FilesystemProject, WorkspaceAnalyzer};
    use git2::{IndexAddOption, Repository, Signature};
    use std::fs;
    use std::sync::Arc;

    fn commit_all(repo: &Repository, message: &str) -> git2::Oid {
        let mut index = repo.index().expect("repository index");
        index
            .add_all(["*"], IndexAddOption::DEFAULT, None)
            .expect("stage fixture");
        index.write().expect("write fixture index");
        let tree = repo
            .find_tree(index.write_tree().expect("fixture tree oid"))
            .expect("fixture tree");
        let signature = Signature::now("Tester", "tester@example.com").expect("signature");
        let parent = repo
            .head()
            .ok()
            .and_then(|head| head.target())
            .map(|oid| repo.find_commit(oid).expect("fixture parent"));
        let parents = parent.iter().collect::<Vec<_>>();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &parents,
        )
        .expect("fixture commit")
    }

    #[test]
    fn immutable_graph_language_selection_keeps_complete_ecosystems_only() {
        assert_eq!(
            BTreeSet::from([Language::Cpp]),
            graph_languages_for_paths(&BTreeSet::from(["src/value.cpp".to_string()]))
        );
        assert_eq!(
            BTreeSet::from([Language::Java, Language::Scala, Language::Kotlin]),
            graph_languages_for_paths(&BTreeSet::from(["src/Value.java".to_string()]))
        );
        assert_eq!(
            BTreeSet::from([Language::JavaScript, Language::TypeScript]),
            graph_languages_for_paths(&BTreeSet::from(["src/value.ts".to_string()]))
        );
    }

    #[test]
    fn target_reverse_imports_include_direct_transitive_and_distance_zero_tests() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::create_dir_all(root.join("tests")).expect("test directory");
        fs::write(root.join("src/__init__.py"), "").expect("source package");
        fs::write(root.join("src/service.py"), "def run():\n    return 1\n")
            .expect("service source");
        fs::write(root.join("tests/__init__.py"), "").expect("test package");
        fs::write(
            root.join("tests/support.py"),
            "from src.service import run\n\ndef helper():\n    return run()\n",
        )
        .expect("test support");
        fs::write(
            root.join("tests/test_service.py"),
            "from tests.support import helper\n\ndef test_run():\n    assert helper() == 2\n",
        )
        .expect("dependent test");
        fs::write(
            root.join("tests/test_unrelated.py"),
            "def test_unrelated():\n    assert True\n",
        )
        .expect("unrelated test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");

        fs::write(root.join("src/service.py"), "def run():\n    return 2\n").expect("edit service");
        fs::write(
            root.join("tests/test_changed.py"),
            "def test_changed():\n    assert True\n",
        )
        .expect("changed test");
        let project = Arc::new(FilesystemProject::new(root).expect("filesystem project"));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("workspace analyzer");

        let result = blast_radius_at_root(
            root,
            Some(workspace.analyzer()),
            BlastRadiusParams::default(),
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("blast radius");

        let scopes = result
            .test_scopes
            .iter()
            .map(|scope| (scope.path.as_str(), scope.minimum_dependency_distance))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(Some(&2), scopes.get("tests/test_service.py"));
        assert_eq!(Some(&0), scopes.get("tests/test_changed.py"));
        assert!(!scopes.contains_key("tests/test_unrelated.py"));
        assert_eq!(2, result.analysis.reached_test_file_count);
        assert_eq!(
            FileGraphCompletion::Complete,
            result.analysis.graph_completion
        );
        assert!(
            result
                .changed_callables
                .iter()
                .any(|callable| callable.changes.contains(&CallableChangeTag::Edited))
        );
    }

    #[test]
    fn immutable_csharp_custom_xunit_test_is_a_distance_zero_scope() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src/Servers/Kestrel/test")).expect("C# test directory");
        let path = root.join("src/Servers/Kestrel/test/Http3RequestTests.cs");
        fs::write(
            &path,
            "public class Http3RequestTests {\n\
             [ConditionalTheory]\n\
             [InlineData(3)]\n\
             public void RequestAbortRaised(int protocol) { }\n\
             }\n",
        )
        .expect("base C# test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");

        fs::write(
            &path,
            "public class Http3RequestTests {\n\
             [ConditionalTheory]\n\
             [InlineData(3)]\n\
             [QuarantinedTest(\"https://example.invalid/issue\")]\n\
             public void RequestAbortRaised(int protocol) { }\n\
             }\n",
        )
        .expect("changed C# test");
        let target = commit_all(&repo, "target");

        let result = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                max_scopes: 1_000,
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("immutable blast radius");

        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!(1, result.test_scopes.len());
        assert_eq!(
            "src/Servers/Kestrel/test/Http3RequestTests.cs",
            result.test_scopes[0].path
        );
        assert_eq!(0, result.test_scopes[0].minimum_dependency_distance);
        assert_eq!(
            FileGraphCompletion::Complete,
            result.analysis.graph_completion
        );
        assert!(result.analysis.incomplete_reasons.is_empty());
        assert!(result.analysis.unresolved_changed_paths.is_empty());
    }

    #[test]
    fn immutable_csharp_inherited_test_is_a_distance_zero_scope() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("Specs")).expect("C# base directory");
        fs::create_dir_all(root.join("Provider")).expect("C# provider directory");
        fs::write(
            root.join("Specs/Base.cs"),
            "namespace Specs;\n\
             public abstract class BaseSpec {\n\
             [Fact] public virtual void Inherited() { }\n\
             }\n\
             public class HelperBase { }\n",
        )
        .expect("base test source");
        fs::write(
            root.join("Provider/Derived.cs"),
            "namespace Provider;\n\
             using Specs;\n\
             public class DerivedSpec : BaseSpec {\n\
             public override void Inherited() { }\n\
             }\n",
        )
        .expect("derived test source");
        fs::write(
            root.join("Provider/Helper.cs"),
            "namespace Provider;\n\
             using Specs;\n\
             public class DerivedHelper : HelperBase {\n\
             public void Changed() { }\n\
             }\n",
        )
        .expect("derived helper source");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");

        fs::write(
            root.join("Provider/Derived.cs"),
            "namespace Provider;\n\
             using Specs;\n\
             public class DerivedSpec : BaseSpec {\n\
             public override void Inherited() { var changed = true; }\n\
             }\n",
        )
        .expect("changed derived test");
        fs::write(
            root.join("Provider/Helper.cs"),
            "namespace Provider;\n\
             using Specs;\n\
             public class DerivedHelper : HelperBase {\n\
             public void Changed() { var changed = true; }\n\
             }\n",
        )
        .expect("changed derived helper");
        let target = commit_all(&repo, "target");

        let result = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                max_scopes: 1_000,
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("immutable blast radius");

        assert_eq!(
            FileGraphCompletion::Complete,
            result.analysis.graph_completion
        );
        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!(1, result.test_scopes.len());
        assert_eq!("Provider/Derived.cs", result.test_scopes[0].path);
        assert_eq!(0, result.test_scopes[0].minimum_dependency_distance);
    }

    #[test]
    fn immutable_csharp_global_usings_stay_inside_their_declared_project() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("A")).expect("project A directory");
        fs::create_dir_all(root.join("B")).expect("project B directory");
        fs::write(
            root.join("A/A.CSPROJ"),
            "<Project Sdk=\"Microsoft.NET.Sdk\" />\n",
        )
        .expect("project A file");
        fs::write(
            root.join("B/B.CSPROJ"),
            "<Project Sdk=\"Microsoft.NET.Sdk\" />\n",
        )
        .expect("project B file");
        fs::write(root.join("A/GlobalUsings.cs"), "global using Shared;\n")
            .expect("project A globals");
        fs::write(
            root.join("A/Shared.cs"),
            "namespace Shared; public class Value { public int Get() => 1; }\n",
        )
        .expect("changed library source");
        fs::write(
            root.join("A/ProjectATest.cs"),
            "public class ProjectATest { [Fact] public void Runs() { } }\n",
        )
        .expect("project A test");
        fs::write(
            root.join("B/ProjectBTest.cs"),
            "public class ProjectBTest { [Fact] public void Runs() { } }\n",
        )
        .expect("project B test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");

        fs::write(
            root.join("A/Shared.cs"),
            "namespace Shared; public class Value { public int Get() => 2; }\n",
        )
        .expect("edit library source");
        let target = commit_all(&repo, "target");

        let result = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                max_scopes: 1_000,
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("immutable blast radius");

        assert_eq!(
            FileGraphCompletion::Incomplete,
            result.analysis.graph_completion
        );
        assert_eq!(
            vec![BlastRadiusIncompleteReason::CompilationScopeUnresolved],
            result.analysis.incomplete_reasons
        );
        assert!(result.analysis.analyzer_changed_test_paths.is_empty());
        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!(1, result.test_scopes.len());
        assert_eq!("A/ProjectATest.cs", result.test_scopes[0].path);
        assert_eq!(2, result.test_scopes[0].minimum_dependency_distance);
    }

    #[test]
    fn immutable_csharp_multi_project_without_globals_is_honestly_incomplete() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("A")).expect("project A directory");
        fs::create_dir_all(root.join("B")).expect("project B directory");
        fs::write(
            root.join("A/A.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\" />\n",
        )
        .expect("project A file");
        fs::write(
            root.join("B/B.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\" />\n",
        )
        .expect("project B file");
        fs::write(
            root.join("A/ChangedTest.cs"),
            "public class ChangedTest { [Fact] public int Runs() => 1; }\n",
        )
        .expect("changed test source");
        fs::write(
            root.join("B/Other.cs"),
            "namespace B; public class Other { }\n",
        )
        .expect("project B source");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");

        fs::write(
            root.join("A/ChangedTest.cs"),
            "public class ChangedTest { [Fact] public int Runs() => 2; }\n",
        )
        .expect("edit test source");
        let target = commit_all(&repo, "target");

        let result = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                max_scopes: 1_000,
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("immutable blast radius");

        assert_eq!(
            FileGraphCompletion::Incomplete,
            result.analysis.graph_completion
        );
        assert_eq!(
            vec![BlastRadiusIncompleteReason::CompilationScopeUnresolved],
            result.analysis.incomplete_reasons
        );
        assert_eq!(
            vec!["A/ChangedTest.cs"],
            result.analysis.analyzer_changed_test_paths
        );
        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!(1, result.test_scopes.len());
        assert_eq!("A/ChangedTest.cs", result.test_scopes[0].path);
        assert_eq!(0, result.test_scopes[0].minimum_dependency_distance);
    }

    #[test]
    fn immutable_javascript_rule_tester_tests_are_reached_at_the_right_distances() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("lib/rules")).expect("rule directory");
        fs::create_dir_all(root.join("lib/rule-tester")).expect("tester directory");
        fs::create_dir_all(root.join("tests/lib/rules")).expect("test directory");
        fs::write(
            root.join("lib/rules/prefer-template.js"),
            "module.exports = function preferTemplate() { return 1; };\n",
        )
        .expect("rule source");
        fs::write(
            root.join("lib/rule-tester/rule-tester.js"),
            "module.exports = class RuleTester {};\n",
        )
        .expect("rule tester source");
        let rule_test = r#"const RuleTester = require("../../../lib/rule-tester/rule-tester");
const rule = require("../../../lib/rules/prefer-template");
const ruleTester = new RuleTester({});
ruleTester.run("prefer-template", rule, { valid: [], invalid: [] });
"#;
        fs::write(root.join("tests/lib/rules/prefer-template.js"), rule_test)
            .expect("changed rule test");
        fs::write(root.join("tests/lib/rules/other.js"), rule_test)
            .expect("directly importing rule test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");

        fs::write(
            root.join("lib/rules/prefer-template.js"),
            "module.exports = function preferTemplate() { return 2; };\n",
        )
        .expect("changed rule source");
        fs::write(
            root.join("tests/lib/rules/prefer-template.js"),
            format!("{rule_test}\n// regression case added by target\n"),
        )
        .expect("changed rule test");
        let target = commit_all(&repo, "target");

        // No workspace analyzer is supplied: the immutable target forces the
        // revision-image build that historical blast-radius calls take.
        let result = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                max_scopes: 1_000,
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("immutable blast radius");

        let scopes = result
            .test_scopes
            .iter()
            .map(|scope| (scope.path.as_str(), scope.minimum_dependency_distance))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(Some(&0), scopes.get("tests/lib/rules/prefer-template.js"));
        assert_eq!(Some(&1), scopes.get("tests/lib/rules/other.js"));
        assert_eq!(2, result.analysis.reached_test_file_count);
        assert_eq!(
            FileGraphCompletion::Complete,
            result.analysis.graph_completion
        );
        assert!(result.analysis.unresolved_changed_paths.is_empty());
    }

    #[test]
    fn immutable_node_test_paths_are_scopes_without_classifying_production_callees() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("lib")).expect("source directory");
        fs::create_dir_all(root.join("test/parallel")).expect("test directory");
        fs::write(
            root.join("lib/runtime.js"),
            "module.exports = function runtime() { return 1; };\n",
        )
        .expect("runtime source");
        fs::write(
            root.join("lib/consumer.js"),
            r#"const runtime = require("./runtime");
function emit(value, callback) { callback(value); }
emit(runtime(), () => {});
"#,
        )
        .expect("production consumer");
        fs::write(
            root.join("test/parallel/test-runtime.js"),
            r#"const assert = require("assert");
const runtime = require("../../lib/runtime");
assert.strictEqual(runtime(), 1);
"#,
        )
        .expect("node test");
        fs::write(
            root.join("test/parallel/test-unrelated.js"),
            "require(\"assert\").strictEqual(1, 1);\n",
        )
        .expect("unrelated node test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");

        fs::write(
            root.join("lib/runtime.js"),
            "module.exports = function runtime() { return 2; };\n",
        )
        .expect("changed runtime source");
        fs::write(
            root.join("test/parallel/test-runtime.js"),
            r#"const assert = require("assert");
const runtime = require("../../lib/runtime");
assert.strictEqual(runtime(), 2);
"#,
        )
        .expect("changed node test");
        let target = commit_all(&repo, "target");

        let result = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                max_scopes: 1_000,
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("immutable blast radius");

        let scopes = result
            .test_scopes
            .iter()
            .map(|scope| (scope.path.as_str(), scope.minimum_dependency_distance))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(Some(&0), scopes.get("test/parallel/test-runtime.js"));
        assert!(!scopes.contains_key("lib/consumer.js"));
        assert!(!scopes.contains_key("test/parallel/test-unrelated.js"));
        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!(
            FileGraphCompletion::Complete,
            result.analysis.graph_completion
        );
        assert!(result.analysis.unresolved_changed_paths.is_empty());
    }

    #[test]
    fn immutable_kotlin_test_context_needs_runnable_test_shape_for_distance_zero() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src/main/kotlin/example")).expect("source directory");
        fs::create_dir_all(root.join("compiler/testData/codegen/box"))
            .expect("test-data directory");
        fs::write(
            root.join("src/main/kotlin/example/Value.kt"),
            "package example\n\nfun value(): String = \"before\"\n",
        )
        .expect("Kotlin source");
        fs::write(
            root.join("compiler/testData/codegen/box/changedBox.kt"),
            "import example.value\n\nfun box(): String = value()\n",
        )
        .expect("box test");
        fs::write(
            root.join("compiler/testData/codegen/box/ordinaryTestCall.kt"),
            "import example.value\n\nfun test(value: String) = value\nfun helper() = test(value())\n",
        )
        .expect("ordinary test call fixture");
        fs::write(
            root.join("compiler/testData/codegen/box/ordinaryItCall.kt"),
            "import example.value\n\nfun helper(): String {\n    val it = { value() }\n    return it()\n}\n",
        )
        .expect("ordinary it call fixture");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");

        fs::write(
            root.join("src/main/kotlin/example/Value.kt"),
            "package example\n\nfun value(): String = \"after\"\n",
        )
        .expect("changed Kotlin source");
        fs::write(
            root.join("compiler/testData/codegen/box/changedBox.kt"),
            "// changed regression\nimport example.value\n\nfun box(): String = value()\n",
        )
        .expect("changed box test");
        fs::write(
            root.join("compiler/testData/codegen/box/ordinaryTestCall.kt"),
            "import example.value\n\nfun test(value: String) = value\nfun helper() = test(value() + \"changed\")\n",
        )
        .expect("changed ordinary test-context fixture");
        let target = commit_all(&repo, "target");

        let result = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                max_scopes: 1_000,
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("immutable blast radius");

        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!(1, result.test_scopes.len());
        assert_eq!(
            "compiler/testData/codegen/box/changedBox.kt",
            result.test_scopes[0].path
        );
        assert_eq!(0, result.test_scopes[0].minimum_dependency_distance);
        let ordinary_fixture = result
            .changed_callables
            .iter()
            .filter_map(|callable| callable.after.as_ref())
            .find(|symbol| symbol.path == "compiler/testData/codegen/box/ordinaryTestCall.kt")
            .expect("changed fixture callable");
        assert!(ordinary_fixture.in_test_context);
        assert!(
            result
                .test_scopes
                .iter()
                .all(|scope| scope.path != ordinary_fixture.path),
            "test-tree context alone must not advertise a runnable test scope"
        );
        assert_eq!(
            FileGraphCompletion::Complete,
            result.analysis.graph_completion
        );
        assert!(result.analysis.unresolved_changed_paths.is_empty());
    }

    #[test]
    fn immutable_java_static_qualifiers_reach_framework_testcase_subclasses() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        let package = root.join("src/org/example");
        fs::create_dir_all(&package).expect("Java package");
        fs::write(
            package.join("TlsStrategyBuilder.java"),
            "package org.example; class TlsStrategyBuilder { static final TlsStrategyBuilder INSTANCE = new TlsStrategyBuilder(); int build() { return 1; } }\n",
        )
        .expect("builder source");
        fs::write(
            package.join("SSLService.java"),
            "package org.example; class SSLService { int build() { return TlsStrategyBuilder.INSTANCE.build(); } }\n",
        )
        .expect("same-package consumer");
        fs::write(
            package.join("SSLServiceTests.java"),
            "package org.example; class SSLServiceTests extends ESTestCase { void testBuild() { new SSLService().build(); } }\n",
        )
        .expect("framework test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        fs::write(
            package.join("TlsStrategyBuilder.java"),
            "package org.example; class TlsStrategyBuilder { static final TlsStrategyBuilder INSTANCE = new TlsStrategyBuilder(); int build() { return 2; } }\n",
        )
        .expect("changed builder");
        let target = commit_all(&repo, "target");

        let result = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("blast radius");

        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!(
            "src/org/example/SSLServiceTests.java",
            result.test_scopes[0].path
        );
        assert_eq!(2, result.test_scopes[0].minimum_dependency_distance);
        assert_eq!(
            FileGraphCompletion::Complete,
            result.analysis.graph_completion
        );
    }

    #[test]
    fn immutable_scala_exports_and_imports_reach_tests_without_unrelated_files() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src/lib")).expect("library package");
        fs::create_dir_all(root.join("src/app")).expect("application package");
        fs::create_dir_all(root.join("src/other")).expect("other package");
        fs::create_dir_all(root.join("tests")).expect("test package");
        fs::write(
            root.join("src/lib/Core.scala"),
            "package lib\nobject Core { def value: Int = 1 }\n",
        )
        .expect("core source");
        fs::write(
            root.join("src/lib/Facade.scala"),
            "package lib\nobject Facade { export Core.value }\n",
        )
        .expect("exporting facade");
        fs::write(
            root.join("src/app/Service.scala"),
            "package app\nimport lib.Facade.*\nobject Service { def run: Int = value }\n",
        )
        .expect("service source");
        fs::write(
            root.join("src/app/Runner.scala"),
            "package app\nobject Runner { def run: Int = Service.run }\n",
        )
        .expect("same-package consumer");
        fs::write(
            root.join("src/other/ExplicitService.scala"),
            "package other\nimport lib.Core.value\nobject ExplicitService { def run: Int = value }\n",
        )
        .expect("explicit member consumer");
        fs::write(
            root.join("tests/ServiceSpec.scala"),
            "package tests\nimport app.Runner\nobject ServiceSpec { test(\"run\") { assert(Runner.run == 2) } }\n",
        )
        .expect("dependent test");
        fs::write(
            root.join("tests/ExplicitSpec.scala"),
            "package tests\nimport other.ExplicitService\nobject ExplicitSpec { test(\"explicit\") { assert(ExplicitService.run == 2) } }\n",
        )
        .expect("explicit import test");
        fs::write(
            root.join("tests/UnrelatedSpec.scala"),
            "package tests\nobject UnrelatedSpec { test(\"other\") { assert(1 == 1) } }\n",
        )
        .expect("unrelated test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        fs::write(
            root.join("src/lib/Core.scala"),
            "package lib\nobject Core { def value: Int = 2 }\n",
        )
        .expect("changed core source");
        let target = commit_all(&repo, "target");

        let result = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("blast radius");

        let scopes = result
            .test_scopes
            .iter()
            .map(|scope| (scope.path.as_str(), scope.minimum_dependency_distance))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(2, result.analysis.reached_test_file_count);
        assert_eq!(Some(&2), scopes.get("tests/ExplicitSpec.scala"));
        assert_eq!(Some(&4), scopes.get("tests/ServiceSpec.scala"));
        assert!(!scopes.contains_key("tests/UnrelatedSpec.scala"));
        assert_eq!(
            FileGraphCompletion::Complete,
            result.analysis.graph_completion
        );
    }

    #[test]
    fn deleted_dependency_recovers_surviving_tests_from_the_base_graph() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::create_dir_all(root.join("tests")).expect("test directory");
        fs::write(root.join("src/__init__.py"), "").expect("source package");
        fs::write(root.join("src/service.py"), "def run():\n    return 1\n")
            .expect("service source");
        fs::write(root.join("tests/__init__.py"), "").expect("test package");
        fs::write(
            root.join("tests/test_service.py"),
            "from src.service import run\n\ndef test_run():\n    assert run() == 1\n",
        )
        .expect("dependent test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        fs::remove_file(root.join("src/service.py")).expect("delete dependency");
        let project = Arc::new(FilesystemProject::new(root).expect("filesystem project"));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("workspace analyzer");

        let result = blast_radius_at_root(
            root,
            Some(workspace.analyzer()),
            BlastRadiusParams::default(),
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("blast radius");

        assert_eq!(BaseRecoveryState::Complete, result.analysis.base_recovery);
        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!(0, result.analysis.unavailable_removed_test_count);
        assert_eq!("tests/test_service.py", result.test_scopes[0].path);
        assert_eq!(1, result.test_scopes[0].minimum_dependency_distance);
        assert!(result.analysis.unresolved_changed_paths.is_empty());
    }

    #[test]
    fn immutable_deleted_dependency_keeps_target_ecosystem_for_surviving_tests() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::create_dir_all(root.join("tests")).expect("test directory");
        fs::write(root.join("src/__init__.py"), "").expect("source package");
        fs::write(root.join("src/service.py"), "def run():\n    return 1\n")
            .expect("deleted dependency");
        fs::write(root.join("tests/__init__.py"), "").expect("test package");
        fs::write(
            root.join("tests/test_service.py"),
            "from src.service import run\n\ndef test_run():\n    assert run() == 1\n",
        )
        .expect("surviving test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        fs::remove_file(root.join("src/service.py")).expect("delete dependency");
        let target = commit_all(&repo, "target");

        let result = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("immutable deletion recovery");

        assert_eq!(BaseRecoveryState::Complete, result.analysis.base_recovery);
        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!("tests/test_service.py", result.test_scopes[0].path);
        assert_eq!(1, result.test_scopes[0].minimum_dependency_distance);
        assert!(result.analysis.unresolved_changed_paths.is_empty());
    }

    /// A setuptools `src` layout has no `__init__.py` package markers; module
    /// identity comes entirely from `pyproject.toml`'s
    /// `[tool.setuptools.packages.find] where = ["src"]`. An immutable
    /// revision image must export that manifest with real bytes, or
    /// `parse_setuptools_where_entries` (`brokk_bifrost_python::declarations`)
    /// reads nothing, module identity falls back to the path-derived
    /// `src.mypkg.service`, and the import edge to the test that names
    /// `mypkg.service` never forms.
    #[test]
    fn immutable_setuptools_where_entries_resolve_the_src_layout_import() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src/mypkg")).expect("src package directory");
        fs::create_dir_all(root.join("tests")).expect("test directory");
        fs::write(
            root.join("pyproject.toml"),
            "[tool.setuptools.packages.find]\nwhere = [\"src\"]\n",
        )
        .expect("setuptools manifest");
        fs::write(
            root.join("src/mypkg/service.py"),
            "def run():\n    return 1\n",
        )
        .expect("src-layout module");
        fs::write(
            root.join("tests/test_service.py"),
            "from mypkg.service import run\n\ndef test_run():\n    assert run() == 1\n",
        )
        .expect("importing test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        fs::write(
            root.join("src/mypkg/service.py"),
            "def run():\n    return 2\n",
        )
        .expect("changed dependency");
        let target = commit_all(&repo, "target");

        let result = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("immutable blast radius");

        assert_eq!(
            1, result.analysis.reached_test_file_count,
            "the setuptools where-entry must resolve mypkg.service to src/mypkg/service.py: {result:?}"
        );
        assert_eq!("tests/test_service.py", result.test_scopes[0].path);
        assert_eq!(1, result.test_scopes[0].minimum_dependency_distance);
    }

    #[test]
    fn rust_inline_tests_are_distance_zero_candidates() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::write(root.join("src/lib.rs"), "pub fn value() -> u8 { 1 }\n").expect("base source");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        fs::write(
            root.join("src/lib.rs"),
            r#"pub fn value() -> u8 { 2 }

#[cfg(test)]
mod tests {
    #[test]
    fn value_is_two() {
        assert_eq!(super::value(), 2);
    }
}
"#,
        )
        .expect("source with inline test");
        let project = Arc::new(FilesystemProject::new(root).expect("filesystem project"));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("workspace analyzer");

        let result = blast_radius_at_root(
            root,
            Some(workspace.analyzer()),
            BlastRadiusParams::default(),
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("blast radius");

        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!("src/lib.rs", result.test_scopes[0].path);
        assert_eq!(0, result.test_scopes[0].minimum_dependency_distance);
    }

    #[test]
    fn rust_external_modules_reach_tests_through_nested_module_ownership() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src/api")).expect("source directory");
        fs::create_dir_all(root.join("tests")).expect("test directory");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        fs::write(root.join("src/lib.rs"), "pub mod api;\n").expect("crate root");
        fs::write(root.join("src/api/mod.rs"), "pub mod nested;\n").expect("api module");
        fs::write(
            root.join("src/api/nested.rs"),
            "pub fn value() -> u8 { 1 }\n",
        )
        .expect("nested implementation");
        fs::write(
            root.join("tests/public_api.rs"),
            "use fixture::api;\n\n#[test]\nfn public_api_works() { assert_eq!(api::nested::value(), 2); }\n",
        )
        .expect("integration test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        fs::write(
            root.join("src/api/nested.rs"),
            "pub fn value() -> u8 { 2 }\n",
        )
        .expect("edit nested implementation");
        let target = commit_all(&repo, "target");

        let result = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("blast radius");

        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!("tests/public_api.rs", result.test_scopes[0].path);
        assert_eq!(2, result.test_scopes[0].minimum_dependency_distance);
    }

    #[test]
    fn rust_module_routes_cover_path_attributes_shared_files_and_test_only_children() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src/tests")).expect("source directory");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        fs::write(
            root.join("src/lib.rs"),
            r#"#[path = "shared.rs"]
mod left;
#[path = "shared.rs"]
mod right;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod inline_tests {
    #[test]
    fn shared_value_works() {
        assert_eq!(super::left::value(), 2);
    }
}
"#,
        )
        .expect("crate root");
        fs::write(root.join("src/shared.rs"), "pub fn value() -> u8 { 1 }\n")
            .expect("shared module");
        fs::write(
            root.join("src/tests.rs"),
            "mod helper;\n\n#[test]\nfn helper_works() { assert_eq!(helper::value(), 2); }\n",
        )
        .expect("test module");
        fs::write(
            root.join("src/tests/helper.rs"),
            "pub fn value() -> u8 { 1 }\n",
        )
        .expect("test helper");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        fs::write(root.join("src/shared.rs"), "pub fn value() -> u8 { 2 }\n")
            .expect("edit shared module");
        fs::write(
            root.join("src/tests/helper.rs"),
            "pub fn value() -> u8 { 2 }\n",
        )
        .expect("edit test helper");
        let project = Arc::new(FilesystemProject::new(root).expect("filesystem project"));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("workspace analyzer");

        let result = blast_radius_at_root(
            root,
            Some(workspace.analyzer()),
            BlastRadiusParams::default(),
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("blast radius");

        let scopes = result
            .test_scopes
            .iter()
            .map(|scope| (scope.path.as_str(), scope.minimum_dependency_distance))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(Some(&1), scopes.get("src/lib.rs"));
        assert_eq!(Some(&1), scopes.get("src/tests.rs"));
        assert!(!scopes.contains_key("src/tests/helper.rs"));
        assert_eq!(2, result.analysis.reached_test_file_count);
    }

    #[test]
    fn paths_outside_the_file_graph_are_explicit_and_zero_is_rendered_as_reachability() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::write(root.join("src/lib.rs"), "pub fn value() -> u8 { 1 }\n").expect("base source");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        fs::write(
            root.join("validation-manifest.tsv"),
            "private\t.audit/report.md\n",
        )
        .expect("non-source change");
        let project = Arc::new(FilesystemProject::new(root).expect("filesystem project"));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("workspace analyzer");

        let result = blast_radius_at_root(
            root,
            Some(workspace.analyzer()),
            BlastRadiusParams::default(),
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("blast radius");

        assert_eq!(
            FileGraphCompletion::Complete,
            result.analysis.graph_completion
        );
        assert_eq!(0, result.analysis.reached_test_file_count);
        assert_eq!(
            vec!["validation-manifest.tsv"],
            result.analysis.paths_outside_file_graph
        );
        let rendered = result.render_text(RenderOptions::default());
        assert!(rendered.contains("No test files were reached"));
        assert!(rendered.contains("may require build, data, or workflow validation"));
        assert!(!rendered.contains("No affected test"));
    }

    #[test]
    fn cancelled_target_graph_preserves_distance_zero_evidence() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::write(root.join("src/lib.rs"), "pub fn value() -> u8 { 1 }\n").expect("base source");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        fs::write(
            root.join("src/lib.rs"),
            "pub fn value() -> u8 { 2 }\n#[test]\nfn inline_test() { assert_eq!(value(), 2); }\n",
        )
        .expect("changed source");
        let project = Arc::new(FilesystemProject::new(root).expect("filesystem project"));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("workspace analyzer");
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        let result = blast_radius_at_root(
            root,
            Some(workspace.analyzer()),
            BlastRadiusParams::default(),
            &DiffAnalysisOptions::default(),
            &cancellation,
        )
        .expect("partial blast radius");

        assert_eq!(
            FileGraphCompletion::Incomplete,
            result.analysis.graph_completion
        );
        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!("src/lib.rs", result.test_scopes[0].path);
        assert!(
            result
                .analysis
                .incomplete_reasons
                .contains(&BlastRadiusIncompleteReason::TargetGraphCancelled)
        );
    }

    #[test]
    fn removed_import_between_surviving_files_uses_only_target_state() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::create_dir_all(root.join("tests")).expect("test directory");
        fs::write(root.join("src/__init__.py"), "").expect("source package");
        fs::write(root.join("src/service.py"), "def run():\n    return 1\n")
            .expect("service source");
        fs::write(root.join("tests/__init__.py"), "").expect("test package");
        fs::write(
            root.join("tests/test_service.py"),
            "from src.service import run\n\ndef test_run():\n    assert run() == 1\n",
        )
        .expect("dependent test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        fs::write(root.join("src/service.py"), "def run():\n    return 2\n")
            .expect("changed service");
        fs::write(
            root.join("tests/test_service.py"),
            "def test_run():\n    assert True\n",
        )
        .expect("test without the old import");
        let project = Arc::new(FilesystemProject::new(root).expect("filesystem project"));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("workspace analyzer");

        let result = blast_radius_at_root(
            root,
            Some(workspace.analyzer()),
            BlastRadiusParams::default(),
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("blast radius");

        assert_eq!(BaseRecoveryState::NotNeeded, result.analysis.base_recovery);
        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!("tests/test_service.py", result.test_scopes[0].path);
        assert_eq!(0, result.test_scopes[0].minimum_dependency_distance);
    }

    #[test]
    fn immutable_commit_and_tree_targets_use_the_same_revision_contents() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::create_dir_all(root.join("tests")).expect("test directory");
        fs::write(root.join("src/__init__.py"), "").expect("source package");
        fs::write(root.join("src/service.py"), "def run():\n    return 1\n")
            .expect("service source");
        fs::write(root.join("tests/__init__.py"), "").expect("test package");
        fs::write(
            root.join("tests/test_service.py"),
            "from src.service import run\n\ndef test_run():\n    assert run() == 2\n",
        )
        .expect("dependent test");
        let repo = Repository::init(root).expect("initialize repository");
        let base = commit_all(&repo, "base");
        fs::write(root.join("src/service.py"), "def run():\n    return 2\n")
            .expect("changed service");
        let target = commit_all(&repo, "target");
        let target_tree = repo.find_commit(target).expect("target commit").tree_id();
        fs::write(root.join("src/service.py"), "def run():\n    return 99\n")
            .expect("checkout diverges from immutable target");

        let by_commit = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("commit blast radius");
        let by_tree = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                base: Some(base.to_string()),
                target: Some(target_tree.to_string()),
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("tree blast radius");

        assert_eq!(target.to_string(), by_commit.endpoints.target);
        assert_eq!(format!("tree:{target_tree}"), by_tree.endpoints.target);
        assert_eq!(1, by_commit.analysis.reached_test_file_count);
        assert_eq!(
            by_commit
                .test_scopes
                .iter()
                .map(|scope| (&scope.path, scope.minimum_dependency_distance))
                .collect::<Vec<_>>(),
            by_tree
                .test_scopes
                .iter()
                .map(|scope| (&scope.path, scope.minimum_dependency_distance))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn immutable_graph_export_reads_host_trusted_snapshot_objects() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::create_dir_all(root.join("tests")).expect("test directory");
        fs::write(root.join("src/__init__.py"), "").expect("source package");
        fs::write(root.join("src/service.py"), "def run():\n    return 1\n").expect("base source");
        fs::write(root.join("tests/__init__.py"), "").expect("test package");
        fs::write(
            root.join("tests/test_service.py"),
            "from src.service import run\n\ndef test_run():\n    assert run() == 2\n",
        )
        .expect("dependent test");
        let repo = Repository::init(root).expect("initialize repository");
        let base = commit_all(&repo, "base");

        // The target tree exists only in the host-configured object database,
        // not in the workspace repository. This pins the bulk exporter to the
        // same trusted alternate set used by libgit2 endpoint resolution.
        let snapshot_path = root.join("snapshot.git");
        let snapshot = Repository::init_bare(&snapshot_path).expect("snapshot repository");
        let source_package = snapshot.blob(b"").expect("source package blob");
        let changed_source = snapshot
            .blob(b"def run():\n    return 2\n")
            .expect("changed source blob");
        let test_package = snapshot.blob(b"").expect("test package blob");
        let dependent_test = snapshot
            .blob(b"from src.service import run\n\ndef test_run():\n    assert run() == 2\n")
            .expect("dependent test blob");
        let mut source_tree = snapshot.treebuilder(None).expect("source tree builder");
        source_tree
            .insert("__init__.py", source_package, 0o100644)
            .expect("source package entry");
        source_tree
            .insert("service.py", changed_source, 0o100644)
            .expect("changed source entry");
        let source_tree = source_tree.write().expect("source tree");
        let mut test_tree = snapshot.treebuilder(None).expect("test tree builder");
        test_tree
            .insert("__init__.py", test_package, 0o100644)
            .expect("test package entry");
        test_tree
            .insert("test_service.py", dependent_test, 0o100644)
            .expect("dependent test entry");
        let test_tree = test_tree.write().expect("test tree");
        let mut target_tree = snapshot.treebuilder(None).expect("target tree builder");
        target_tree
            .insert("src", source_tree, 0o040000)
            .expect("source directory entry");
        target_tree
            .insert("tests", test_tree, 0o040000)
            .expect("test directory entry");
        let target_tree = target_tree.write().expect("target tree");

        let result = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                base: Some(base.to_string()),
                target: Some(target_tree.to_string()),
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions {
                snapshot_object_dir: Some(snapshot_path.join("objects")),
            },
            &CancellationToken::default(),
        )
        .expect("snapshot-backed blast radius");

        assert_eq!(
            FileGraphCompletion::Complete,
            result.analysis.graph_completion
        );
        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!("tests/test_service.py", result.test_scopes[0].path);
        assert_eq!(1, result.test_scopes[0].minimum_dependency_distance);
        assert!(result.analysis.unresolved_changed_paths.is_empty());
    }

    #[test]
    fn renamed_test_is_recovered_from_the_base_graph() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::create_dir_all(root.join("tests")).expect("test directory");
        fs::write(root.join("src/__init__.py"), "").expect("source package");
        fs::write(root.join("src/service.py"), "def run():\n    return 1\n")
            .expect("service source");
        fs::write(root.join("tests/__init__.py"), "").expect("test package");
        fs::write(
            root.join("tests/test_service.py"),
            "from src.service import run\n\ndef test_run():\n    assert run() == 1\n",
        )
        .expect("dependent test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        fs::remove_file(root.join("src/service.py")).expect("delete dependency");
        fs::rename(
            root.join("tests/test_service.py"),
            root.join("tests/test_core.py"),
        )
        .expect("rename test");
        let mut index = repo.index().expect("repository index");
        index
            .remove_path(Path::new("src/service.py"))
            .expect("stage dependency deletion");
        index
            .remove_path(Path::new("tests/test_service.py"))
            .expect("stage old test path");
        index
            .add_path(Path::new("tests/test_core.py"))
            .expect("stage renamed test path");
        index.write().expect("write staged rename");
        let project = Arc::new(FilesystemProject::new(root).expect("filesystem project"));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("workspace analyzer");

        let result = blast_radius_at_root(
            root,
            Some(workspace.analyzer()),
            BlastRadiusParams::default(),
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("renamed-test blast radius");

        assert_eq!(BaseRecoveryState::Complete, result.analysis.base_recovery);
        assert_eq!(1, result.analysis.reached_test_file_count);
        assert_eq!("tests/test_core.py", result.test_scopes[0].path);
        assert_eq!(0, result.analysis.unavailable_removed_test_count);
    }

    #[test]
    fn removed_tests_are_omitted_and_counted_unavailable() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::create_dir_all(root.join("tests")).expect("test directory");
        fs::write(root.join("src/__init__.py"), "").expect("source package");
        fs::write(root.join("src/service.py"), "def run():\n    return 1\n")
            .expect("service source");
        fs::write(root.join("src/keep.py"), "def keep():\n    return 1\n")
            .expect("surviving source");
        fs::write(root.join("tests/__init__.py"), "").expect("test package");
        fs::write(
            root.join("tests/test_service.py"),
            "from src.service import run\n\ndef test_run():\n    assert run() == 1\n",
        )
        .expect("dependent test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        fs::remove_file(root.join("src/service.py")).expect("delete dependency");
        fs::remove_file(root.join("tests/test_service.py")).expect("delete test");
        let project = Arc::new(FilesystemProject::new(root).expect("filesystem project"));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("workspace analyzer");

        let result = blast_radius_at_root(
            root,
            Some(workspace.analyzer()),
            BlastRadiusParams::default(),
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("removed-test blast radius");

        assert_eq!(0, result.analysis.reached_test_file_count);
        assert_eq!(1, result.analysis.unavailable_removed_test_count);
        assert!(result.test_scopes.is_empty());
    }

    #[test]
    fn max_scopes_validation_rejects_values_outside_the_public_range() {
        for max_scopes in [0, MAX_SCOPES + 1] {
            let error = BlastRadiusParams {
                max_scopes,
                ..BlastRadiusParams::default()
            }
            .validate()
            .expect_err("out-of-range max_scopes must fail");
            assert!(error.contains("between 1 and 1000"));
        }
    }

    #[derive(Clone)]
    struct ReferenceScopeState {
        path: String,
        affected: BTreeSet<String>,
        covered: usize,
        distances: DistanceRange,
        kind: TestScopeKind,
    }

    struct ReferenceCollapseCandidate {
        path: String,
        descendant_scopes: Vec<String>,
        affected: BTreeSet<String>,
        directory_coverage: usize,
        previous_coverage: usize,
        distances: DistanceRange,
    }

    fn reference_coalesce_scopes(
        affected: &BTreeMap<String, DistanceRange>,
        analyzer_paths: &BTreeSet<String>,
        max_scopes: usize,
    ) -> Vec<TestScope> {
        let mut scopes = affected
            .iter()
            .map(|(path, distances)| {
                (
                    path.clone(),
                    ReferenceScopeState {
                        path: path.clone(),
                        affected: BTreeSet::from([path.clone()]),
                        covered: 1,
                        distances: *distances,
                        kind: TestScopeKind::File,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut directories = BTreeSet::from([".".to_string()]);
        for path in affected.keys() {
            directories.extend(parent_directories(path));
        }
        let mut directory_coverage = directories
            .iter()
            .map(|path| (path.clone(), 0usize))
            .collect::<BTreeMap<_, _>>();
        for path in analyzer_paths {
            for directory in parent_directories(path) {
                if let Some(coverage) = directory_coverage.get_mut(&directory) {
                    *coverage += 1;
                }
            }
        }

        while scopes.len() > max_scopes {
            let selected = directories
                .iter()
                .filter_map(|directory| {
                    let descendant_scopes = scopes
                        .keys()
                        .filter(|path| {
                            directory.as_str() == "."
                                || Path::new(path.as_str()).starts_with(Path::new(directory))
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    if descendant_scopes.len() < 2 {
                        return None;
                    }
                    let mut reached = BTreeSet::new();
                    let mut previous_coverage = 0;
                    let mut distances: Option<DistanceRange> = None;
                    for path in &descendant_scopes {
                        let scope = &scopes[path];
                        reached.extend(scope.affected.iter().cloned());
                        previous_coverage += scope.covered;
                        distances = Some(match distances {
                            Some(current) => DistanceRange {
                                minimum: current.minimum.min(scope.distances.minimum),
                                maximum: current.maximum.max(scope.distances.maximum),
                            },
                            None => scope.distances,
                        });
                    }
                    Some(ReferenceCollapseCandidate {
                        path: directory.clone(),
                        descendant_scopes,
                        affected: reached,
                        directory_coverage: directory_coverage[directory],
                        previous_coverage,
                        distances: distances.expect("candidate contains scopes"),
                    })
                })
                .min_by(|left, right| {
                    let left_removed = left.descendant_scopes.len() - 1;
                    let right_removed = right.descendant_scopes.len() - 1;
                    let left_additional = left
                        .directory_coverage
                        .saturating_sub(left.previous_coverage);
                    let right_additional = right
                        .directory_coverage
                        .saturating_sub(right.previous_coverage);
                    (left_additional as u128 * right_removed as u128)
                        .cmp(&(right_additional as u128 * left_removed as u128))
                        .then_with(|| {
                            left.directory_coverage
                                .saturating_sub(left.affected.len())
                                .cmp(
                                    &right
                                        .directory_coverage
                                        .saturating_sub(right.affected.len()),
                                )
                        })
                        .then_with(|| {
                            let left_depth =
                                usize::from(left.path != ".") * path_components(&left.path).len();
                            let right_depth =
                                usize::from(right.path != ".") * path_components(&right.path).len();
                            right_depth.cmp(&left_depth)
                        })
                        .then_with(|| left.path.cmp(&right.path))
                })
                .expect("multiple scopes have a common root");
            for path in &selected.descendant_scopes {
                scopes.remove(path);
            }
            scopes.insert(
                selected.path.clone(),
                ReferenceScopeState {
                    path: selected.path,
                    affected: selected.affected,
                    covered: selected.directory_coverage,
                    distances: selected.distances,
                    kind: TestScopeKind::Directory,
                },
            );
        }

        scopes
            .into_values()
            .map(|scope| {
                let sample_reached_files = if scope.kind == TestScopeKind::Directory {
                    scope.affected.iter().take(5).cloned().collect()
                } else {
                    Vec::new()
                };
                TestScope {
                    path: scope.path,
                    kind: scope.kind,
                    reached_file_count: scope.affected.len(),
                    covered_analyzable_file_count: scope.covered,
                    minimum_dependency_distance: scope.distances.minimum,
                    maximum_dependency_distance: scope.distances.maximum,
                    sample_reached_files,
                }
            })
            .collect()
    }

    type ScopeRow = (
        String,
        TestScopeKind,
        usize,
        usize,
        usize,
        usize,
        Vec<String>,
    );

    fn scope_rows(scopes: Vec<TestScope>) -> Vec<ScopeRow> {
        scopes
            .into_iter()
            .map(|scope| {
                (
                    scope.path,
                    scope.kind,
                    scope.reached_file_count,
                    scope.covered_analyzable_file_count,
                    scope.minimum_dependency_distance,
                    scope.maximum_dependency_distance,
                    scope.sample_reached_files,
                )
            })
            .collect()
    }

    #[test]
    fn arena_coalescing_matches_independent_reference_ordering() {
        for seed in 0..12 {
            let affected = (0..40)
                .map(|index| {
                    (
                        format!(
                            "root_{}/suite_{}/layer_{}/case_{index:02}.cs",
                            (index + seed) % 3,
                            (index * 7 + seed) % 9,
                            (index * 5 + seed) % 13
                        ),
                        DistanceRange {
                            minimum: (index + seed) % 5,
                            maximum: (index + seed) % 5 + index % 3,
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let mut analyzable = affected.keys().cloned().collect::<BTreeSet<_>>();
            analyzable.extend((0..40).flat_map(|index| {
                let prefix = format!(
                    "root_{}/suite_{}/layer_{}",
                    (index + seed) % 3,
                    (index * 7 + seed) % 9,
                    (index * 5 + seed) % 13
                );
                [
                    format!("{prefix}/support_{index}.cs"),
                    format!("{prefix}/fixture_{index}.cs"),
                ]
            }));
            for max_scopes in [1, 2, 3, 5, 8, 13, 21, 40] {
                assert_eq!(
                    scope_rows(reference_coalesce_scopes(
                        &affected,
                        &analyzable,
                        max_scopes,
                    )),
                    scope_rows(coalesce_scopes(&affected, &analyzable, max_scopes)),
                    "seed={seed}, max_scopes={max_scopes}"
                );
            }
        }
    }

    #[test]
    fn coalescing_prefers_deep_low_spill_directories_and_preserves_distances() {
        let affected = BTreeMap::from([
            (
                "tests/a/one.py".to_string(),
                DistanceRange {
                    minimum: 1,
                    maximum: 1,
                },
            ),
            (
                "tests/a/two.py".to_string(),
                DistanceRange {
                    minimum: 2,
                    maximum: 3,
                },
            ),
            (
                "tests/b/three.py".to_string(),
                DistanceRange {
                    minimum: 4,
                    maximum: 4,
                },
            ),
        ]);
        let analyzable = BTreeSet::from([
            "src/main.py".to_string(),
            "tests/a/one.py".to_string(),
            "tests/a/two.py".to_string(),
            "tests/a/helper.py".to_string(),
            "tests/b/three.py".to_string(),
            "tests/common.py".to_string(),
        ]);

        let scopes = coalesce_scopes(&affected, &analyzable, 2);

        assert_eq!(2, scopes.len());
        assert_eq!("tests/a", scopes[0].path);
        assert_eq!(TestScopeKind::Directory, scopes[0].kind);
        assert_eq!(2, scopes[0].reached_file_count);
        assert_eq!(3, scopes[0].covered_analyzable_file_count);
        assert_eq!(1, scopes[0].minimum_dependency_distance);
        assert_eq!(3, scopes[0].maximum_dependency_distance);
        assert_eq!("tests/b/three.py", scopes[1].path);
    }

    #[test]
    fn coalescing_uses_root_as_the_final_lossless_fallback() {
        let affected = BTreeMap::from([
            (
                "a/test_one.rs".to_string(),
                DistanceRange {
                    minimum: 0,
                    maximum: 0,
                },
            ),
            (
                "b/test_two.rs".to_string(),
                DistanceRange {
                    minimum: 7,
                    maximum: 7,
                },
            ),
        ]);
        let analyzable = affected.keys().cloned().collect();

        let scopes = coalesce_scopes(&affected, &analyzable, 1);

        assert_eq!(1, scopes.len());
        assert_eq!(".", scopes[0].path);
        assert_eq!(2, scopes[0].reached_file_count);
        assert_eq!(0, scopes[0].minimum_dependency_distance);
        assert_eq!(7, scopes[0].maximum_dependency_distance);
    }

    #[test]
    fn coalescing_frozen_scale_deep_scope_sets_preserve_the_exact_affected_count() {
        let affected = (0..12_000)
            .map(|index| {
                (
                    format!(
                        "src/product_{}/component_{}/feature_{}/tests/case_{index}.cs",
                        index % 24,
                        index % 400,
                        index % 2_000
                    ),
                    DistanceRange {
                        minimum: index % 4,
                        maximum: index % 4 + 2,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut analyzable = affected.keys().cloned().collect::<BTreeSet<_>>();
        analyzable.extend((0..12_000).flat_map(|index| {
            let prefix = format!(
                "src/product_{}/component_{}/feature_{}",
                index % 24,
                index % 400,
                index % 2_000
            );
            [
                format!("{prefix}/support_{index}.cs"),
                format!("{prefix}/tests/support_{index}.cs"),
            ]
        }));

        let scopes = coalesce_scopes(&affected, &analyzable, MAX_SCOPES);

        assert!(scopes.len() <= MAX_SCOPES);
        assert_eq!(
            affected.len(),
            scopes
                .iter()
                .map(|scope| scope.reached_file_count)
                .sum::<usize>()
        );
    }

    /// A small Python repository whose target commit edits one dependency that
    /// a test file imports. The returned id is the target commit.
    fn shared_cache_fixture(root: &Path) -> git2::Oid {
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::create_dir_all(root.join("tests")).expect("test directory");
        fs::write(root.join("src/__init__.py"), "").expect("source package");
        fs::write(root.join("src/service.py"), "def run():\n    return 1\n")
            .expect("changed dependency");
        fs::write(root.join("tests/__init__.py"), "").expect("test package");
        fs::write(
            root.join("tests/test_service.py"),
            "from src.service import run\n\ndef test_run():\n    assert run() == 1\n",
        )
        .expect("importing test");
        let repo = Repository::init(root).expect("initialize repository");
        commit_all(&repo, "base");
        fs::write(root.join("src/service.py"), "def run():\n    return 2\n")
            .expect("edit dependency");
        commit_all(&repo, "target")
    }

    fn immutable_blast_radius(root: &Path, target: git2::Oid) -> BlastRadiusResult {
        blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect("immutable blast radius")
    }

    fn shared_cache_connection(root: &Path) -> rusqlite::Connection {
        rusqlite::Connection::open(crate::analyzer::store::analyzer_db_path(root))
            .expect("open the shared analyzer cache")
    }

    fn row_count(connection: &rusqlite::Connection, table: &str) -> i64 {
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("count cache rows")
    }

    fn published_blob_oids(connection: &rusqlite::Connection) -> BTreeSet<String> {
        let mut statement = connection
            .prepare("SELECT blob_oid FROM blobs")
            .expect("prepare blob listing");
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query blob listing");
        rows.map(|row| row.expect("read blob oid")).collect()
    }

    fn tree_blob_oids(repo: &Repository, commit: git2::Oid) -> BTreeSet<String> {
        let tree = repo
            .find_commit(commit)
            .expect("fixture commit")
            .tree()
            .expect("fixture tree");
        let mut oids = BTreeSet::new();
        tree.walk(git2::TreeWalkMode::PreOrder, |_, entry| {
            if entry.kind() == Some(git2::ObjectType::Blob) {
                oids.insert(entry.id().to_string());
            }
            git2::TreeWalkResult::Ok
        })
        .expect("walk fixture tree");
        oids
    }

    #[test]
    fn repeated_immutable_requests_parse_nothing_the_second_time() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        let target = shared_cache_fixture(root);

        let cold = immutable_blast_radius(root, target);
        let after_cold = {
            let connection = shared_cache_connection(root);
            row_count(&connection, "blobs")
        };
        let warm = immutable_blast_radius(root, target);
        let after_warm = {
            let connection = shared_cache_connection(root);
            row_count(&connection, "blobs")
        };

        assert!(
            after_cold > 0,
            "a cold immutable request publishes the revision's parsed blobs"
        );
        assert_eq!(
            after_cold, after_warm,
            "a warm immutable request must publish no new blobs"
        );
        assert_eq!(
            serde_json::to_value(&cold).expect("cold result json"),
            serde_json::to_value(&warm).expect("warm result json"),
        );
    }

    #[test]
    fn an_immutable_request_after_a_worktree_build_parses_only_revision_only_blobs() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        let target = shared_cache_fixture(root);
        let repo = Repository::open(root).expect("fixture repository");
        let base = repo
            .find_commit(target)
            .expect("target commit")
            .parent_id(0)
            .expect("base commit");

        let project = Arc::new(FilesystemProject::new(root).expect("filesystem project"));
        let worktree = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
            project,
            AnalyzerConfig::default(),
        )
        .expect("persisted worktree analyzer");
        let after_worktree_build = published_blob_oids(&shared_cache_connection(root));
        drop(worktree);

        immutable_blast_radius(root, target);
        let after_request = published_blob_oids(&shared_cache_connection(root));

        let newly_parsed = after_request
            .difference(&after_worktree_build)
            .cloned()
            .collect::<BTreeSet<_>>();
        let base_oids = tree_blob_oids(&repo, base);
        let target_oids = tree_blob_oids(&repo, target);
        assert!(
            !newly_parsed.is_empty(),
            "the base revision's own version of the edited file is not in the worktree"
        );
        assert!(
            newly_parsed
                .iter()
                .all(|oid| base_oids.contains(oid) && !target_oids.contains(oid)),
            "the request must parse only blobs the warm cache had never seen: {newly_parsed:?}"
        );
    }

    #[test]
    fn an_immutable_request_leaves_no_workspace_projection_rows() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        let target = shared_cache_fixture(root);

        immutable_blast_radius(root, target);

        let connection = shared_cache_connection(root);
        // Every workspace identity this request could have published names a
        // revision export directory, so any surviving row is a leak.
        assert_eq!(0, row_count(&connection, "workspace_heads"));
        assert_eq!(0, row_count(&connection, "workspace_revisions"));
        assert_eq!(0, row_count(&connection, "workspace_file_versions"));
        assert!(row_count(&connection, "blobs") > 0);
    }

    #[test]
    fn an_immutable_request_and_a_worktree_build_share_one_cache_without_deadlock() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path().to_path_buf();
        let target = shared_cache_fixture(&root);

        let request_root = root.clone();
        let (done, finished) = std::sync::mpsc::channel();
        let request_done = done.clone();
        let request = std::thread::spawn(move || {
            let result = immutable_blast_radius(&request_root, target);
            request_done.send("request").expect("report request");
            result
        });
        let build_root = root.clone();
        let build = std::thread::spawn(move || {
            let project = Arc::new(FilesystemProject::new(&build_root).expect("project"));
            let workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
                project,
                AnalyzerConfig::default(),
            )
            .expect("persisted worktree analyzer");
            done.send("build").expect("report build");
            workspace.analyzer().analyzed_files().len()
        });

        for _ in 0..2 {
            finished
                .recv_timeout(std::time::Duration::from_secs(120))
                .expect("both the immutable request and the worktree build must finish");
        }
        let result = request.join().expect("immutable request thread");
        let analyzed = build.join().expect("worktree build thread");

        assert_eq!(1, result.analysis.reached_test_file_count);
        assert!(analyzed > 0);

        let connection = shared_cache_connection(&root);
        // Only the live worktree keeps a mounted workspace; the request's
        // export directory left nothing behind.
        let workspaces: BTreeSet<String> = {
            let mut statement = connection
                .prepare("SELECT DISTINCT workspace_id FROM workspace_heads")
                .expect("prepare workspace listing");
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .expect("query workspace listing");
            rows.map(|row| row.expect("read workspace id")).collect()
        };
        assert_eq!(
            BTreeSet::from([brokk_bifrost_core::gitblob::workspace_cache_identity(&root)]),
            workspaces
        );
    }

    /// An immutable request that cannot open the repository's shared cache is a
    /// hard error, not a silently slower ephemeral rebuild. The equality this
    /// test used to assert -- that a warm run answers like a cold one -- is
    /// pinned by `repeated_immutable_requests_parse_nothing_the_second_time`.
    #[test]
    fn an_immutable_request_fails_when_the_shared_cache_cannot_be_opened() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        let target = shared_cache_fixture(root);

        // Occupying the cache file's path with a directory is the portable way
        // to make the store refuse to open, which is what a read-only or
        // network cache location does in production.
        let db_path = crate::analyzer::store::analyzer_db_path(root);
        fs::create_dir_all(&db_path).expect("block the cache path");

        let error = blast_radius_at_root(
            root,
            None,
            BlastRadiusParams {
                target: Some(target.to_string()),
                ..BlastRadiusParams::default()
            },
            &DiffAnalysisOptions::default(),
            &CancellationToken::default(),
        )
        .expect_err("a blocked shared cache must fail the request, not downgrade it");

        assert!(
            error.contains(&db_path.display().to_string()),
            "the error must name the cache it could not open: {error}"
        );
    }
}
