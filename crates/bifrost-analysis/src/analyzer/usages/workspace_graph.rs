//! Compact exact-identity usage graph shared by relevance ranking and graph APIs.

use super::common::{language_for_file, language_for_target};
use super::inverted_edges::{UsageNodeKey, UsageReferenceCounts};
use crate::analyzer::languages::{
    EdgeWeightScanCtx, LanguageEdgeWeights, LanguageSupport, edge_passes, language_support,
};
use crate::analyzer::{CodeUnit, DeclarationId, IAnalyzer, Language, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::collections::BTreeSet;
use std::ffi::OsStr;

type CatalogDeclaration = (CodeUnit, Option<Range>);

/// The name universe a declaration's identity belongs to.
///
/// One ecosystem is one candidate space: a reference resolved anywhere in the
/// ecosystem can land on any declaration in it. Exact declaration identity is
/// carried separately by [`WorkspaceUsageNodeKey::id`]; equal names never
/// collapse overloads or duplicate declarations.
///
/// Java, Scala, and Kotlin share a single `Jvm` ecosystem because they compile
/// to one classpath and can name one another's types directly. Sharing the
/// candidate space is not the same as collapsing source-language identity:
/// every node still knows the language it was declared in (see
/// [`WorkspaceUsageNode::source_language`]), and each language keeps its own
/// resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum UsageEcosystem {
    JavaScriptTypeScript,
    Python,
    Go,
    Rust,
    Jvm,
    CSharp,
    Cpp,
    Php,
    Ruby,
    Unknown,
}

impl UsageEcosystem {
    /// The registry is the single owner of this mapping. An unregistered language --
    /// only `Language::None` -- is `Unknown`, whose declarations become graph nodes with
    /// no edges because no pass ever claims that ecosystem.
    pub(crate) fn of(language: Language) -> Self {
        language_support(language).map_or(Self::Unknown, LanguageSupport::ecosystem)
    }

    pub(crate) fn is_module_scoped(self) -> bool {
        matches!(self, Self::JavaScriptTypeScript)
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::JavaScriptTypeScript => "js_ts",
            Self::Python => "python",
            Self::Go => "go",
            Self::Rust => "rust",
            Self::Jvm => "jvm",
            Self::CSharp => "csharp",
            Self::Cpp => "cpp",
            Self::Php => "php",
            Self::Ruby => "ruby",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct WorkspaceUsageNodeKey {
    pub(crate) id: DeclarationId,
    pub(crate) ecosystem: UsageEcosystem,
    pub(crate) fqn: String,
    pub(crate) defining_file: Option<ProjectFile>,
}

impl WorkspaceUsageNodeKey {
    /// The node key for a declaration whose identity the caller already holds.
    ///
    /// `CodeUnit::declaration_id` is a SHA-256 over every identity field and
    /// `fq_name` is an owned copy of the rendered name. The catalog computes
    /// both once per inventory row while grouping, so it passes them in here
    /// rather than paying for either a second time.
    fn with_identity(
        unit: &CodeUnit,
        ecosystem: UsageEcosystem,
        id: DeclarationId,
        fqn: String,
    ) -> Self {
        Self {
            id,
            ecosystem,
            fqn,
            defining_file: ecosystem.is_module_scoped().then(|| unit.source().clone()),
        }
    }
}

#[derive(Clone)]
pub(crate) struct WorkspaceUsageNode {
    pub(crate) key: WorkspaceUsageNodeKey,
    pub(crate) primary: CodeUnit,
    pub(crate) primary_range: Option<Range>,
    pub(crate) declaration_files: Vec<ProjectFile>,
    pub(crate) declaration_ids: Vec<DeclarationId>,
    pub(crate) truncated_inbound: Option<usize>,
    pub(crate) unproven_inbound: usize,
}

impl WorkspaceUsageNode {
    /// The language this node's declaration was written in.
    ///
    /// Distinct from its ecosystem: a Java, a Scala, and a Kotlin declaration
    /// all live in the `Jvm` candidate space, but a consumer still needs to
    /// know which one it is looking at.
    pub(crate) fn source_language(&self) -> Language {
        language_for_target(&self.primary)
    }

    /// A stable label naming what this node is, for reporting.
    ///
    /// JVM nodes report their own language rather than the shared realm, so
    /// sharing a candidate space never costs a consumer the ability to tell
    /// Java from Scala from Kotlin.
    pub(crate) fn language_label(&self) -> &'static str {
        match self.key.ecosystem {
            UsageEcosystem::Jvm => match self.source_language() {
                Language::Java => "java",
                Language::Scala => "scala",
                Language::Kotlin => "kotlin",
                _ => UsageEcosystem::Jvm.as_str(),
            },
            ecosystem => ecosystem.as_str(),
        }
    }
}

pub(crate) struct WorkspaceUsageCatalog {
    pub(crate) nodes: Vec<WorkspaceUsageNode>,
    indices_by_id: HashMap<DeclarationId, usize>,
}

impl WorkspaceUsageCatalog {
    pub(crate) fn build(analyzer: &dyn IAnalyzer) -> Self {
        Self::build_with_cancellation(analyzer, &CancellationToken::default())
            .expect("uncancelled workspace usage catalog construction")
    }

    /// Enumerate one file's graph declarations through its persisted summary
    /// projection. Each lookup is bounded to one live analyzed file and is
    /// independent of every other file, so the unrooted builder can distribute
    /// them across Rayon without materializing an analyzer generation.
    ///
    /// The inventory comes from `projection.declarations`, never from
    /// `top_level_declarations` plus `children`: that pair is the rendering
    /// hierarchy, and the Scala and Kotlin wrappers prune synthetic entries
    /// from it, which hides every named method declared inside an anonymous
    /// class (#2992).
    fn declarations_for_file(
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        cancellation: &CancellationToken,
    ) -> Option<Vec<CatalogDeclaration>> {
        if cancellation.is_cancelled() {
            return None;
        }
        #[cfg(test)]
        let catalog_file_sequence =
            CATALOG_FILES_ENUMERATED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;

        let mut declarations = Vec::new();
        if let Some(projection) = analyzer.summary_file_projection(file) {
            for unit in &projection.declarations {
                if cancellation.is_cancelled() {
                    return None;
                }
                if is_graph_declaration(unit) {
                    declarations.push((
                        unit.clone(),
                        projection
                            .ranges
                            .get(unit)
                            .and_then(|ranges| primary_range(ranges)),
                    ));
                }
            }
        } else {
            for unit in analyzer.declarations(file) {
                if cancellation.is_cancelled() {
                    return None;
                }
                if is_graph_declaration(&unit) {
                    let range = analyzer.ranges(&unit).into_iter().min_by_key(range_key);
                    declarations.push((unit, range));
                }
            }
        }

        // The public declaration inventory intentionally excludes synthetic
        // file scopes. Java module descriptors need one graph caller, however,
        // so add the existing `module-info.java` file scope through this
        // graph-only catalog path. This avoids turning the named module into a
        // package Module CodeUnit, which can collide with a package of the same
        // name.
        if is_java_module_descriptor_file(file) {
            let file_scope = CodeUnit::file_scope(file.clone());
            let range = analyzer
                .ranges(&file_scope)
                .into_iter()
                .min_by_key(range_key);
            declarations.push((file_scope, range));
        }
        #[cfg(test)]
        if catalog_file_sequence
            == CATALOG_CANCEL_AFTER_FILE.load(std::sync::atomic::Ordering::Relaxed)
        {
            cancellation.cancel();
        }
        (!cancellation.is_cancelled()).then_some(declarations)
    }

    pub(crate) fn build_with_cancellation(
        analyzer: &dyn IAnalyzer,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        if cancellation.is_cancelled() {
            return None;
        }
        let files = analyzer.analyzed_files();
        let declaration_batches: Option<Vec<Vec<CatalogDeclaration>>> = {
            let _scope = crate::profiling::scope("workspace_graph::parallel_catalog_enumeration");
            files
                .par_iter()
                .map(|file| Self::declarations_for_file(analyzer, file, cancellation))
                .collect()
        };
        let declarations = declaration_batches?.into_iter().flatten().collect();
        if cancellation.is_cancelled() {
            return None;
        }

        let _scope = crate::profiling::scope("workspace_graph::catalog_grouping");
        Self::from_declarations(declarations, cancellation)
    }

    /// Build a graph-node catalog from only `files`, using one persisted summary
    /// projection per file. This is the rooted `usage_graph` path: it must not
    /// enumerate every declaration in a long-lived workspace cache before it can
    /// answer a handful of changed-file roots.
    pub(crate) fn build_for_files(analyzer: &dyn IAnalyzer, files: &[ProjectFile]) -> Self {
        let cancellation = CancellationToken::default();
        let declarations = files
            .iter()
            .flat_map(|file| {
                Self::declarations_for_file(analyzer, file, &cancellation)
                    .expect("uncancelled rooted file declaration enumeration")
            })
            .collect();
        Self::from_declarations(declarations, &CancellationToken::default())
            .expect("uncancelled rooted workspace usage catalog construction")
    }

    /// Group an enumerated declaration inventory into graph nodes.
    ///
    /// The whole-workspace inventory is hundreds of thousands of rows on a
    /// monorepo, and each row's `declaration_id` is a SHA-256 over every
    /// identity field. This makes one identity pass over the row set and
    /// carries the result through the group key, the node key, and the node's
    /// identity list, where the ordered-map grouping it replaces hashed each
    /// row roughly three times, copied each rendered name twice, and allocated
    /// one `Vec` per group -- almost every group on a real workspace holds one
    /// row, because only C++ and C# omit the exact identity from the key
    /// (#2935).
    ///
    /// This stays sequential deliberately. The phase is allocation-bound, not
    /// hash-bound: a Rayon version of exactly this grouping, measured on the
    /// pinned 205,209-row Kubernetes inventory, spent 72 s of CPU to produce
    /// the same catalog in 1.42 s of wall time that the sequential pass
    /// produces in 1.28 s using 1.31 s of CPU. Distributing per-node
    /// allocation across 120 threads buys contention, not throughput.
    ///
    /// The result is identical to the ordered-map grouping, not merely
    /// equivalent: `sort_by` is stable, so rows sharing one group key keep the
    /// enumeration order the map gave them, groups are visited in group-key
    /// order, and `min_by` returns the first minimal element, which is what
    /// sorting a group and taking its head selected.
    pub(crate) fn from_declarations(
        declarations: Vec<CatalogDeclaration>,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
        struct GroupKey {
            ecosystem: UsageEcosystem,
            fqn: String,
            kind: crate::analyzer::CodeUnitType,
            signature: Option<String>,
            exact_declaration: Option<DeclarationId>,
        }

        /// One inventory row with its group key and declaration identity
        /// already computed, so no later pass has to hash it again.
        ///
        /// The identity is an `Option` because node construction moves it into
        /// the node's identity list rather than cloning a second 64-character
        /// digest per row.
        struct KeyedDeclaration {
            key: GroupKey,
            id: Option<DeclarationId>,
            unit: CodeUnit,
            range: Option<Range>,
        }

        let mut keyed: Vec<KeyedDeclaration> = Vec::with_capacity(declarations.len());
        for (unit, range) in declarations {
            if cancellation.is_cancelled() {
                return None;
            }
            if !is_graph_declaration(&unit) {
                continue;
            }
            let ecosystem = UsageEcosystem::of(language_for_target(&unit));
            let id = declaration_identity(&unit);
            // C++ and C# merge redeclarations of one entity, so their group key
            // deliberately omits the exact declaration identity.
            let exact_declaration =
                (!matches!(ecosystem, UsageEcosystem::Cpp | UsageEcosystem::CSharp))
                    .then(|| id.clone());
            keyed.push(KeyedDeclaration {
                key: GroupKey {
                    ecosystem,
                    fqn: unit.fq_name_str().to_string(),
                    kind: unit.kind(),
                    signature: unit.signature().map(str::to_string),
                    exact_declaration,
                },
                id: Some(id),
                unit,
                range,
            });
        }
        keyed.sort_by(|left, right| left.key.cmp(&right.key));

        let mut nodes: Vec<WorkspaceUsageNode> = Vec::new();
        for group in keyed.chunk_by_mut(|left, right| left.key == right.key) {
            if cancellation.is_cancelled() {
                return None;
            }
            let primary_index = group
                .iter()
                .enumerate()
                .min_by(|(_, left), (_, right)| {
                    left.unit
                        .source()
                        .cmp(right.unit.source())
                        .then_with(|| {
                            left.range
                                .map(|range| range.start_line)
                                .cmp(&right.range.map(|range| range.start_line))
                        })
                        .then_with(|| left.unit.signature().cmp(&right.unit.signature()))
                })
                .map(|(index, _)| index)
                .expect("catalog groups are never empty");
            let mut declaration_files: Vec<_> = group
                .iter()
                .map(|declaration| declaration.unit.source().clone())
                .collect();
            declaration_files.sort();
            declaration_files.dedup();
            let primary = group[primary_index].unit.clone();
            let primary_range = group[primary_index].range;
            let ecosystem = group[primary_index].key.ecosystem;
            let fqn = std::mem::take(&mut group[primary_index].key.fqn);
            let primary_id = group[primary_index]
                .id
                .take()
                .expect("a row's identity is taken once");
            let mut declaration_ids = Vec::with_capacity(group.len());
            declaration_ids.push(primary_id.clone());
            for declaration in group.iter_mut() {
                if let Some(id) = declaration.id.take() {
                    declaration_ids.push(id);
                }
            }
            declaration_ids.sort();
            declaration_ids.dedup();
            nodes.push(WorkspaceUsageNode {
                key: WorkspaceUsageNodeKey::with_identity(&primary, ecosystem, primary_id, fqn),
                primary,
                primary_range,
                declaration_files,
                declaration_ids,
                truncated_inbound: None,
                unproven_inbound: 0,
            });
        }
        nodes.sort_by(|left, right| left.key.id.cmp(&right.key.id));
        let mut indices_by_id = HashMap::default();
        for (index, node) in nodes.iter().enumerate() {
            for id in &node.declaration_ids {
                let previous = indices_by_id.insert(id.clone(), index);
                assert!(
                    previous.is_none(),
                    "one declaration ID belongs to one graph node"
                );
            }
        }
        Some(Self {
            nodes,
            indices_by_id,
        })
    }

    #[cfg(test)]
    pub(crate) fn ecosystems(&self) -> BTreeSet<UsageEcosystem> {
        self.nodes.iter().map(|node| node.key.ecosystem).collect()
    }

    pub(crate) fn ecosystems_for_files<'a>(
        &self,
        files: impl IntoIterator<Item = &'a ProjectFile>,
    ) -> BTreeSet<UsageEcosystem> {
        let files: HashSet<_> = files.into_iter().collect();
        self.nodes
            .iter()
            .filter(|node| {
                node.declaration_files
                    .iter()
                    .any(|file| files.contains(file))
            })
            .map(|node| node.key.ecosystem)
            .collect()
    }

    pub(crate) fn index_for_id(&self, id: &DeclarationId) -> Option<usize> {
        self.indices_by_id.get(id).copied()
    }

    fn indices_for_fqn(&self, ecosystem: UsageEcosystem, fqn: &str) -> Vec<usize> {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node.key.ecosystem == ecosystem && node.key.fqn == fqn)
            .map(|(index, _)| index)
            .collect()
    }

    fn indices_for_scoped(&self, ecosystem: UsageEcosystem, key: &UsageNodeKey) -> Vec<usize> {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| {
                node.key.ecosystem == ecosystem
                    && node.key.fqn == key.fqn
                    && node.key.defining_file.as_ref() == Some(&key.file)
            })
            .map(|(index, _)| index)
            .collect()
    }
}

#[cfg(test)]
static CATALOG_FILES_ENUMERATED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static CATALOG_CANCEL_AFTER_FILE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);
/// Declaration identities computed while building a catalog.
///
/// `CodeUnit::declaration_id` is a SHA-256 over every identity field, and the
/// grouping used to compute one per row for each place the identity was
/// needed. This is the cost shape the catalog pins: one identity per inventory
/// row, not one per row per use of that identity.
#[cfg(test)]
static CATALOG_DECLARATION_IDENTITIES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// The declaration identity of `unit`, counted for the cost-shape pin.
fn declaration_identity(unit: &CodeUnit) -> DeclarationId {
    #[cfg(test)]
    CATALOG_DECLARATION_IDENTITIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    unit.declaration_id()
}

fn primary_range(ranges: &[Range]) -> Option<Range> {
    ranges.iter().copied().min_by_key(range_key)
}

fn range_key(range: &Range) -> (usize, usize) {
    (range.start_line, range.start_byte)
}

pub(crate) fn is_graph_declaration(unit: &CodeUnit) -> bool {
    let is_java_module_descriptor_scope = unit.is_file_scope()
        && language_for_target(unit) == Language::Java
        && unit.source().rel_path().file_name() == Some(OsStr::new("module-info.java"));
    (!unit.is_synthetic() || is_java_module_descriptor_scope)
        && (unit.is_class() || unit.is_callable() || is_java_module_descriptor_scope)
}

fn is_java_module_descriptor_file(file: &ProjectFile) -> bool {
    language_for_file(file) == Language::Java
        && file.rel_path().file_name() == Some(OsStr::new("module-info.java"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkspaceUsageEdge {
    pub(crate) from: usize,
    pub(crate) to: usize,
    pub(crate) counts: UsageReferenceCounts,
}

pub(crate) struct WorkspaceUsageGraph {
    pub(crate) nodes: Vec<WorkspaceUsageNode>,
    pub(crate) edges: Vec<WorkspaceUsageEdge>,
    #[cfg(test)]
    pub(crate) resolved_ecosystems: Vec<UsageEcosystem>,
}

pub(crate) struct WorkspaceUsageRankingNode {
    pub(crate) primary_file: ProjectFile,
    pub(crate) seed_files: Vec<ProjectFile>,
    pub(crate) incomplete: bool,
    /// Present on the coarse file-dependency graph, whose bulk file-fact read
    /// already knows whether each file contains tests. Exact symbol graphs do
    /// not currently consume this classification.
    pub(crate) contains_tests: Option<bool>,
}

pub(crate) struct WorkspaceUsageRankingGraph {
    pub(crate) nodes: Vec<WorkspaceUsageRankingNode>,
    pub(crate) edges: Vec<WorkspaceUsageEdge>,
    pub(crate) node_indices_by_file: HashMap<ProjectFile, Vec<usize>>,
    #[cfg(test)]
    pub(crate) resolved_ecosystems: Vec<UsageEcosystem>,
}

impl WorkspaceUsageRankingGraph {
    pub(crate) fn from_exact(graph: WorkspaceUsageGraph) -> Self {
        let mut node_indices_by_file: HashMap<ProjectFile, Vec<usize>> = HashMap::default();
        let nodes = graph
            .nodes
            .into_iter()
            .enumerate()
            .map(|(index, node)| {
                for file in &node.declaration_files {
                    node_indices_by_file
                        .entry(file.clone())
                        .or_default()
                        .push(index);
                }
                WorkspaceUsageRankingNode {
                    primary_file: node.primary.source().clone(),
                    seed_files: node.declaration_files,
                    incomplete: node.truncated_inbound.is_some() || node.unproven_inbound > 0,
                    contains_tests: None,
                }
            })
            .collect();
        Self {
            nodes,
            edges: graph.edges,
            node_indices_by_file,
            #[cfg(test)]
            resolved_ecosystems: graph.resolved_ecosystems,
        }
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        let mut retained = std::mem::size_of::<Self>()
            .saturating_add(
                self.nodes
                    .capacity()
                    .saturating_mul(std::mem::size_of::<WorkspaceUsageRankingNode>()),
            )
            .saturating_add(
                self.edges
                    .capacity()
                    .saturating_mul(std::mem::size_of::<WorkspaceUsageEdge>()),
            )
            .saturating_add(
                self.node_indices_by_file
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(ProjectFile, Vec<usize>)>()),
            );
        for node in &self.nodes {
            retained = retained
                .saturating_add(project_file_retained_bytes(&node.primary_file))
                .saturating_add(
                    node.seed_files
                        .capacity()
                        .saturating_mul(std::mem::size_of::<ProjectFile>()),
                );
            for file in &node.seed_files {
                retained = retained.saturating_add(project_file_retained_bytes(file));
            }
        }
        for (file, indices) in &self.node_indices_by_file {
            retained = retained
                .saturating_add(project_file_retained_bytes(file))
                .saturating_add(
                    indices
                        .capacity()
                        .saturating_mul(std::mem::size_of::<usize>()),
                );
        }
        retained
    }
}

fn project_file_retained_bytes(file: &ProjectFile) -> usize {
    std::mem::size_of::<ProjectFile>()
        .saturating_add(file.root().as_os_str().len())
        .saturating_add(file.rel_path().as_os_str().len())
}

pub(crate) enum WorkspaceUsageGraphBuildOutcome {
    Complete(WorkspaceUsageGraph),
    Cancelled,
}

pub(crate) fn build_workspace_usage_graph_with_cancellation(
    analyzer: &dyn IAnalyzer,
    catalog: WorkspaceUsageCatalog,
    selected_ecosystems: &BTreeSet<UsageEcosystem>,
    cancellation: &CancellationToken,
) -> WorkspaceUsageGraphBuildOutcome {
    let mut nodes = catalog.nodes.clone();
    let mut edges = Vec::new();
    #[cfg(test)]
    let mut resolved_ecosystems = Vec::new();
    let keep_file = |_: &ProjectFile| !cancellation.is_cancelled();
    for entry in edge_passes() {
        if !selected_ecosystems.contains(&entry.ecosystem) {
            continue;
        }
        if cancellation.is_cancelled() {
            return WorkspaceUsageGraphBuildOutcome::Cancelled;
        }
        let _scope = crate::profiling::scope(format!(
            "workspace_usage_graph::resolve_{}",
            entry.id.as_str()
        ));
        let fqns = catalog
            .nodes
            .iter()
            .filter(|node| node.key.ecosystem == entry.ecosystem)
            .map(|node| node.key.fqn.clone())
            .collect::<HashSet<_>>();
        let scoped_nodes = catalog
            .nodes
            .iter()
            .filter(|node| node.key.ecosystem == entry.ecosystem)
            .filter_map(|node| {
                node.key
                    .defining_file
                    .clone()
                    .map(|file| UsageNodeKey::new(file, node.key.fqn.clone()))
            })
            .collect::<HashSet<_>>();
        if fqns.is_empty() {
            continue;
        }
        #[cfg(test)]
        resolved_ecosystems.push(entry.ecosystem);
        let ctx = EdgeWeightScanCtx {
            analyzer,
            fqns: &fqns,
            scoped_nodes: &scoped_nodes,
            keep_file: &keep_file,
        };
        match entry.pass.edge_weights(&ctx) {
            Some(LanguageEdgeWeights::Fqn(result)) => {
                record_fqn_weights_exact(entry.ecosystem, result, &catalog, &mut nodes, &mut edges)
            }
            Some(LanguageEdgeWeights::Scoped(result)) => record_scoped_weights_exact(
                entry.ecosystem,
                result.edges,
                &catalog,
                &mut nodes,
                &mut edges,
            ),
            None => {}
        }
    }
    edges.sort_by_key(|edge| (edge.from, edge.to));
    #[cfg(test)]
    resolved_ecosystems.dedup();
    WorkspaceUsageGraphBuildOutcome::Complete(WorkspaceUsageGraph {
        nodes,
        edges,
        #[cfg(test)]
        resolved_ecosystems,
    })
}

fn record_fqn_weights_exact(
    ecosystem: UsageEcosystem,
    result: super::inverted_edges::UsageEdgeWeights,
    catalog: &WorkspaceUsageCatalog,
    nodes: &mut [WorkspaceUsageNode],
    edges: &mut Vec<WorkspaceUsageEdge>,
) {
    for ((from, to), counts) in result.edges {
        let from = catalog.indices_for_fqn(ecosystem, &from);
        let to = catalog.indices_for_fqn(ecosystem, &to);
        if let ([from], [to]) = (from.as_slice(), to.as_slice()) {
            if from != to {
                edges.push(WorkspaceUsageEdge {
                    from: *from,
                    to: *to,
                    counts,
                });
            }
        } else {
            for to in to {
                nodes[to].unproven_inbound =
                    nodes[to].unproven_inbound.saturating_add(counts.total());
            }
        }
    }
    for (fqn, total) in result.truncated {
        for index in catalog.indices_for_fqn(ecosystem, &fqn) {
            nodes[index].truncated_inbound = Some(total);
        }
    }
    for (fqn, total) in result.unproven_inbound {
        for index in catalog.indices_for_fqn(ecosystem, &fqn) {
            nodes[index].unproven_inbound = nodes[index].unproven_inbound.saturating_add(total);
        }
    }
}

fn record_scoped_weights_exact(
    ecosystem: UsageEcosystem,
    result: super::inverted_edges::UsageEdgeWeights<UsageNodeKey>,
    catalog: &WorkspaceUsageCatalog,
    nodes: &mut [WorkspaceUsageNode],
    edges: &mut Vec<WorkspaceUsageEdge>,
) {
    for ((from, to), counts) in result.edges {
        let from = catalog.indices_for_scoped(ecosystem, &from);
        let to = catalog.indices_for_scoped(ecosystem, &to);
        if let ([from], [to]) = (from.as_slice(), to.as_slice()) {
            if from != to {
                edges.push(WorkspaceUsageEdge {
                    from: *from,
                    to: *to,
                    counts,
                });
            }
        } else {
            for to in to {
                nodes[to].unproven_inbound =
                    nodes[to].unproven_inbound.saturating_add(counts.total());
            }
        }
    }
    for (key, total) in result.truncated {
        for index in catalog.indices_for_scoped(ecosystem, &key) {
            nodes[index].truncated_inbound = Some(total);
        }
    }
    for (key, total) in result.unproven_inbound {
        for index in catalog.indices_for_scoped(ecosystem, &key) {
            nodes[index].unproven_inbound = nodes[index].unproven_inbound.saturating_add(total);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::CodeUnitIndex;
    use crate::analyzer::{
        AnalyzerDelegate, JavaAnalyzer, KotlinAnalyzer, MultiAnalyzer, ScalaAnalyzer, TestProject,
    };
    use std::collections::BTreeMap;
    use std::sync::Arc;

    static CATALOG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The `Jvm` realm is resolved once even though three builders run over it.
    ///
    /// `resolved_ecosystems` is what a consumer reads to know which realms a
    /// graph actually covers, and it is deduplicated with `Vec::dedup`, which
    /// only collapses *consecutive* duplicates. With one JVM builder that was
    /// vacuously true; with three it is a real invariant, and a future reordering
    /// that interleaved another ecosystem between them would silently start
    /// reporting `Jvm` twice.
    #[test]
    fn the_jvm_realm_is_resolved_once_across_its_three_builders() {
        let _guard = CATALOG_TEST_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        ProjectFile::new(root.clone(), "app/Greeter.java")
            .write(
                "package app;\n\npublic class Greeter {\n    public String greet() { return \"hi\"; }\n}\n",
            )
            .unwrap();
        ProjectFile::new(root.clone(), "app/Service.scala")
            .write("package app\n\nclass Service {\n  def run(): String = \"scala\"\n}\n")
            .unwrap();
        ProjectFile::new(root.clone(), "app/Caller.kt")
            .write(
                "package app\n\nclass Caller {\n\n    fun call(): String {\n        val greeter = Greeter()\n        return greeter.greet()\n    }\n}\n",
            )
            .unwrap();

        let project = TestProject::new(root, Language::Java);
        let analyzer = MultiAnalyzer::new(BTreeMap::from([
            (
                Language::Java,
                AnalyzerDelegate::Java(JavaAnalyzer::new(Arc::new(project.clone()))),
            ),
            (
                Language::Scala,
                AnalyzerDelegate::Scala(ScalaAnalyzer::new(Arc::new(project.clone()))),
            ),
            (
                Language::Kotlin,
                AnalyzerDelegate::Kotlin(KotlinAnalyzer::new(Arc::new(project))),
            ),
        ]));

        let catalog = WorkspaceUsageCatalog::build(&analyzer);
        let selected = BTreeSet::from([UsageEcosystem::Jvm]);
        let WorkspaceUsageGraphBuildOutcome::Complete(graph) =
            build_workspace_usage_graph_with_cancellation(
                &analyzer,
                catalog,
                &selected,
                &CancellationToken::default(),
            )
        else {
            panic!("uncancelled workspace usage graph build");
        };

        assert_eq!(
            graph.resolved_ecosystems,
            vec![UsageEcosystem::Jvm],
            "three JVM builders must still resolve one realm"
        );
        // Measured on a real Kotlin -> Java edge, so a graph that resolved the
        // realm once but produced nothing would not pass.
        assert!(
            graph.edges.iter().any(|edge| {
                graph.nodes[edge.from].key.fqn == "app.Caller.call"
                    && graph.nodes[edge.to].key.fqn == "app.Greeter"
            }),
            "expected the Kotlin -> Java edge the shared realm exists to provide; edges={:?}",
            graph
                .edges
                .iter()
                .map(|edge| (
                    graph.nodes[edge.from].key.fqn.as_str(),
                    graph.nodes[edge.to].key.fqn.as_str(),
                    edge.counts,
                ))
                .collect::<Vec<_>>()
        );
    }

    /// A persisted multi-language workspace, analyzed twice so the second
    /// analyzer reads the same cache-backed summary projections a warm real
    /// workspace reads.
    fn persisted_multilanguage_analyzer(root: std::path::PathBuf) -> MultiAnalyzer {
        ProjectFile::new(root.clone(), "module-info.java")
            .write("module example.module {}\n")
            .unwrap();
        ProjectFile::new(root.clone(), "app/Greeter.java")
            .write(
                "package app;\n\npublic class Greeter {\n    public String greet() { return \"hi\"; }\n}\n",
            )
            .unwrap();
        // Scala indexes the anonymous class as a synthetic owner and its `run`
        // as an ordinary declaration, and the Scala summary wrapper prunes
        // synthetic entries out of `children`. So `run` is reachable only
        // through the persisted declaration inventory (#2992).
        ProjectFile::new(root.clone(), "app/Service.scala")
            .write(
                "package app\n\nclass Service {\n  def task(): Runnable = new Runnable {\n    def run(): Unit = println(\"scala\")\n  }\n}\n",
            )
            .unwrap();
        // The Kotlin declaration tier deliberately does not index members of an
        // anonymous object, so this file has no equivalent hidden `run`. It is
        // here so the Kotlin summary wrapper's synthetic pruning is covered by
        // the exact-equality check below.
        ProjectFile::new(root.clone(), "app/Task.kt")
            .write(
                "package app\n\nclass Task(private val label: String) {\n    fun make(): Runnable = object : Runnable {\n        override fun run() {}\n    }\n}\n",
            )
            .unwrap();
        ProjectFile::new(root.clone(), "app/Caller.kt")
            .write("package app\n\nclass Caller {\n    fun call(): String = Greeter().greet()\n}\n")
            .unwrap();

        let project = TestProject::new(root, Language::Java);
        let make_analyzer = || {
            MultiAnalyzer::new(BTreeMap::from([
                (
                    Language::Java,
                    AnalyzerDelegate::Java(JavaAnalyzer::new(Arc::new(project.clone()))),
                ),
                (
                    Language::Scala,
                    AnalyzerDelegate::Scala(ScalaAnalyzer::new(Arc::new(project.clone()))),
                ),
                (
                    Language::Kotlin,
                    AnalyzerDelegate::Kotlin(KotlinAnalyzer::new(Arc::new(project.clone()))),
                ),
            ]))
        };
        // The first generation persists the fixture. The second exercises the
        // same cache-backed summary projections used by a warm real workspace.
        drop(make_analyzer());
        make_analyzer()
    }

    /// Every catalog field a graph consumer can observe on one node.
    type CatalogNodeFields = (
        WorkspaceUsageNodeKey,
        CodeUnit,
        Option<Range>,
        Vec<ProjectFile>,
        Vec<DeclarationId>,
    );

    fn catalog_node_fields(catalog: &WorkspaceUsageCatalog) -> Vec<CatalogNodeFields> {
        catalog
            .nodes
            .iter()
            .map(|node| {
                (
                    node.key.clone(),
                    node.primary.clone(),
                    node.primary_range,
                    node.declaration_files.clone(),
                    node.declaration_ids.clone(),
                )
            })
            .collect()
    }

    #[test]
    fn parallel_catalog_enumeration_matches_authoritative_inventory_in_file_sized_work_units() {
        let _guard = CATALOG_TEST_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let analyzer = persisted_multilanguage_analyzer(root);

        let mut authoritative = analyzer.all_declarations_with_primary_ranges();
        for file in analyzer.analyzed_files() {
            if is_java_module_descriptor_file(&file) {
                let file_scope = CodeUnit::file_scope(file.clone());
                let range = analyzer
                    .ranges(&file_scope)
                    .into_iter()
                    .min_by_key(range_key);
                authoritative.push((file_scope, range));
            }
        }
        let expected =
            WorkspaceUsageCatalog::from_declarations(authoritative, &CancellationToken::default())
                .expect("uncancelled authoritative catalog");

        CATALOG_FILES_ENUMERATED.store(0, std::sync::atomic::Ordering::Relaxed);
        let actual = WorkspaceUsageCatalog::build(&analyzer);
        let expected_nodes = catalog_node_fields(&expected);
        let actual_nodes = catalog_node_fields(&actual);
        assert_eq!(
            actual_nodes, expected_nodes,
            "per-file enumeration must preserve exact catalog identity, ranges, duplicates, and order"
        );
        assert!(
            actual.nodes.iter().any(|node| {
                node.primary.identifier() == "run"
                    && node.primary.source().rel_path().file_name()
                        == Some(OsStr::new("Service.scala"))
            }),
            "per-file enumeration must retain the `run` method declared inside \
             Service.scala's anonymous class: {:?}",
            actual
                .nodes
                .iter()
                .map(|node| node.primary.clone())
                .collect::<Vec<_>>()
        );

        assert_eq!(
            CATALOG_FILES_ENUMERATED.load(std::sync::atomic::Ordering::Relaxed),
            analyzer.analyzed_files().len(),
            "catalog work must be exactly one bounded projection per analyzed file"
        );

        assert!(
            actual.nodes.iter().any(|node| {
                node.primary.is_file_scope()
                    && node.primary.source().rel_path() == std::path::Path::new("module-info.java")
            }),
            "parallel declaration enumeration must retain the graph-only Java module descriptor"
        );

        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert!(
            WorkspaceUsageCatalog::build_with_cancellation(&analyzer, &cancelled).is_none(),
            "a cancelled inventory must not publish a partial catalog"
        );

        CATALOG_FILES_ENUMERATED.store(0, std::sync::atomic::Ordering::Relaxed);
        CATALOG_CANCEL_AFTER_FILE.store(1, std::sync::atomic::Ordering::Relaxed);
        let cancelled_during_enumeration = CancellationToken::default();
        assert!(
            WorkspaceUsageCatalog::build_with_cancellation(
                &analyzer,
                &cancelled_during_enumeration
            )
            .is_none(),
            "cancellation after one completed file must discard every parallel batch"
        );
        CATALOG_CANCEL_AFTER_FILE.store(usize::MAX, std::sync::atomic::Ordering::Relaxed);
    }

    /// The grouping this file replaced, written out as an independent oracle.
    ///
    /// This is the sequential `BTreeMap` walk `from_declarations` used before
    /// #2935: one ordered map keyed by ecosystem, rendered name, kind,
    /// signature, and exact declaration identity; each group sorted by source
    /// file, primary start line, and signature; the head of that sort as the
    /// node's primary; nodes ordered by declaration identity.
    fn reference_catalog_nodes(declarations: Vec<CatalogDeclaration>) -> Vec<CatalogNodeFields> {
        #[derive(PartialEq, Eq, PartialOrd, Ord)]
        struct ReferenceGroupKey {
            ecosystem: UsageEcosystem,
            fqn: String,
            kind: crate::analyzer::CodeUnitType,
            signature: Option<String>,
            exact_declaration: Option<DeclarationId>,
        }

        let mut grouped: BTreeMap<ReferenceGroupKey, Vec<CatalogDeclaration>> = BTreeMap::new();
        for (unit, range) in declarations {
            if !is_graph_declaration(&unit) {
                continue;
            }
            let ecosystem = UsageEcosystem::of(language_for_target(&unit));
            let exact_declaration =
                (!matches!(ecosystem, UsageEcosystem::Cpp | UsageEcosystem::CSharp))
                    .then(|| unit.declaration_id());
            grouped
                .entry(ReferenceGroupKey {
                    ecosystem,
                    fqn: unit.fq_name(),
                    kind: unit.kind(),
                    signature: unit.signature().map(str::to_string),
                    exact_declaration,
                })
                .or_default()
                .push((unit, range));
        }

        let mut nodes = Vec::with_capacity(grouped.len());
        for (_, mut declarations) in grouped {
            declarations.sort_by(|(left, left_range), (right, right_range)| {
                left.source()
                    .cmp(right.source())
                    .then_with(|| {
                        left_range
                            .map(|range| range.start_line)
                            .cmp(&right_range.map(|range| range.start_line))
                    })
                    .then_with(|| left.signature().cmp(&right.signature()))
            });
            let (primary, primary_range) = declarations.first().expect("non-empty group").clone();
            let ecosystem = UsageEcosystem::of(language_for_target(&primary));
            let key = WorkspaceUsageNodeKey {
                id: primary.declaration_id(),
                ecosystem,
                fqn: primary.fq_name(),
                defining_file: ecosystem
                    .is_module_scoped()
                    .then(|| primary.source().clone()),
            };
            let mut declaration_files: Vec<_> = declarations
                .iter()
                .map(|(unit, _)| unit.source().clone())
                .collect();
            declaration_files.sort();
            declaration_files.dedup();
            let mut declaration_ids: Vec<_> = declarations
                .iter()
                .map(|(unit, _)| unit.declaration_id())
                .collect();
            declaration_ids.sort();
            declaration_ids.dedup();
            nodes.push((
                key,
                primary,
                primary_range,
                declaration_files,
                declaration_ids,
            ));
        }
        nodes.sort_by(|left, right| left.0.id.cmp(&right.0.id));
        nodes
    }

    /// Two C++ declarations of one entity, in a header and its translation
    /// unit.
    ///
    /// C++ and C# omit the exact declaration identity from the group key, so
    /// these land in one node. That is the only shape that exercises duplicate
    /// grouping, primary selection among several rows, and the file/identity
    /// deduplication -- the JVM fixture's rows are all exact identities, so
    /// every one of its groups holds exactly one row.
    fn cpp_redeclaration_pair(root: &std::path::Path) -> Vec<CatalogDeclaration> {
        let signature = Some("void Widget::draw()".to_string());
        let declaration = |rel_path: &str, start_line: usize| {
            (
                CodeUnit::with_signature(
                    ProjectFile::new(root.to_path_buf(), rel_path),
                    crate::analyzer::CodeUnitType::Function,
                    "widgets",
                    "Widget.draw",
                    signature.clone(),
                    false,
                ),
                Some(Range {
                    start_byte: start_line * 40,
                    end_byte: start_line * 40 + 20,
                    start_line,
                    end_line: start_line,
                }),
            )
        };
        // Deliberately enumerated header first while `lib/widget.cpp` sorts
        // first, so primary selection is decided by source order and not by
        // the order the rows arrived in.
        vec![
            declaration("lib/widget.h", 4),
            declaration("lib/widget.cpp", 12),
        ]
    }

    /// The inventory the parity and cost-shape tests group: every persisted
    /// declaration of the multi-language fixture, its Java module descriptor,
    /// and one C++ redeclaration pair.
    fn parity_inventory(
        analyzer: &MultiAnalyzer,
        root: &std::path::Path,
    ) -> Vec<CatalogDeclaration> {
        let mut declarations = analyzer.all_declarations_with_primary_ranges();
        for file in analyzer.analyzed_files() {
            if is_java_module_descriptor_file(&file) {
                let file_scope = CodeUnit::file_scope(file.clone());
                let range = analyzer
                    .ranges(&file_scope)
                    .into_iter()
                    .min_by_key(range_key);
                declarations.push((file_scope, range));
            }
        }
        declarations.extend(cpp_redeclaration_pair(root));
        declarations
    }

    #[test]
    fn catalog_grouping_matches_the_ordered_map_reference_grouping() {
        let _guard = CATALOG_TEST_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let analyzer = persisted_multilanguage_analyzer(root.clone());
        let declarations = parity_inventory(&analyzer, &root);
        assert!(
            declarations.len() > 8,
            "the parity fixture must carry enough rows to exercise grouping: {declarations:?}"
        );

        let expected = reference_catalog_nodes(declarations.clone());
        let actual =
            WorkspaceUsageCatalog::from_declarations(declarations, &CancellationToken::default())
                .expect("uncancelled catalog");

        assert_eq!(
            catalog_node_fields(&actual),
            expected,
            "the grouping rewrite must reproduce the ordered-map grouping exactly: identity, \
             primary, primary range, duplicate files, duplicate identities, and node order"
        );

        // The C++ redeclarations are one node whose primary is the header, and
        // the node is reachable by either declaration identity.
        let merged = actual
            .nodes
            .iter()
            .find(|node| node.declaration_files.len() == 2)
            .expect("the C++ redeclaration pair must group into one node");
        assert_eq!(
            merged.primary.source().rel_path(),
            std::path::Path::new("lib/widget.cpp"),
            "primary selection must take the first declaration in source order, not enumeration \
             order: {files:?}",
            files = merged.declaration_files
        );
        assert_eq!(merged.declaration_ids.len(), 2, "{:?}", merged.primary);
        for id in &merged.declaration_ids {
            assert_eq!(
                actual.index_for_id(id),
                actual.index_for_id(&merged.key.id),
                "every identity in a merged node must index that node"
            );
        }
    }

    /// The cost shape the parallel grouping exists to fix.
    ///
    /// The ordered-map grouping hashed each row's declaration identity about
    /// three times -- once for the group key, once for the node key, once for
    /// the node's identity list -- and `declaration_id` is a SHA-256 over
    /// every identity field. Grouping now makes one identity pass over the row
    /// set and carries the result through, so this pins one identity per graph
    /// declaration and no more.
    #[test]
    fn catalog_grouping_makes_one_identity_pass_over_the_row_set() {
        let _guard = CATALOG_TEST_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let analyzer = persisted_multilanguage_analyzer(root.clone());
        let declarations = parity_inventory(&analyzer, &root);
        let graph_rows = declarations
            .iter()
            .filter(|(unit, _)| is_graph_declaration(unit))
            .count();
        assert!(graph_rows > 0, "the fixture must produce graph rows");

        CATALOG_DECLARATION_IDENTITIES.store(0, std::sync::atomic::Ordering::Relaxed);
        let catalog =
            WorkspaceUsageCatalog::from_declarations(declarations, &CancellationToken::default())
                .expect("uncancelled catalog");
        assert_eq!(
            CATALOG_DECLARATION_IDENTITIES.load(std::sync::atomic::Ordering::Relaxed),
            graph_rows,
            "grouping {} rows into {} nodes must compute exactly one declaration identity per row",
            graph_rows,
            catalog.nodes.len()
        );
    }

    /// Grouping is complete-or-nothing, like enumeration.
    ///
    /// The token trips after a fixed number of checks, so it cancels while
    /// grouping is partway through the row set.
    #[test]
    fn catalog_grouping_publishes_nothing_when_the_token_trips_partway() {
        let _guard = CATALOG_TEST_LOCK.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let analyzer = persisted_multilanguage_analyzer(root.clone());
        let declarations = parity_inventory(&analyzer, &root);

        let token = CancellationToken::cancel_after_checks_for_test(3);
        assert!(
            WorkspaceUsageCatalog::from_declarations(declarations.clone(), &token).is_none(),
            "a token that trips partway through grouping must discard the whole catalog"
        );

        // The same rows still build a complete catalog once nothing cancels,
        // so the check above failed on cancellation and not on the fixture.
        assert!(
            WorkspaceUsageCatalog::from_declarations(declarations, &CancellationToken::default())
                .is_some()
        );
    }
}
