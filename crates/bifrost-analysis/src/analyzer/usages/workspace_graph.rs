//! Compact exact-identity usage graph shared by relevance ranking and graph APIs.

#[path = "canonical_workspace_graph.rs"]
#[doc(hidden)]
pub mod canonical_workspace_graph;
pub(crate) use canonical_workspace_graph::SelectedWorkspaceUsageGraphProjectionOutcome;
#[cfg(any(test, feature = "test-support"))]
pub use canonical_workspace_graph::{
    SelectedWorkspaceUsageRankingBuildOutcome, SelectedWorkspaceUsageRankingGraph,
    build_selected_workspace_usage_ranking_graph,
};

use super::common::language_for_target;
use super::inverted_edges::{UsageEdgeWeights, UsageNodeKey, UsageReferenceCounts};
use crate::analyzer::common::is_java_module_descriptor_file;
use crate::analyzer::languages::{
    EdgeWeightScanCtx, LanguageEdgeWeights, LanguageGraphBackend, LanguageSupport, edge_passes,
    language_support,
};
use crate::analyzer::primary_range;
use crate::analyzer::store::StoreError;
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, DeclarationId, IAnalyzer, Language, ProjectFile, Range,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;

#[doc(hidden)]
pub type CatalogDeclaration = (CodeUnit, Option<Range>);

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
///
/// This is also the registry a consumer outside this crate asks when it needs
/// to know whether two files' declarations can name one another: the honesty
/// checker in `brokk-bifrost` scopes an identity match to the claim's candidate
/// space (#3391) rather than re-deriving the language families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UsageEcosystem {
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
    pub fn of(language: Language) -> Self {
        language_support(language).map_or(Self::Unknown, LanguageSupport::ecosystem)
    }

    #[doc(hidden)]
    pub fn is_module_scoped(self) -> bool {
        matches!(self, Self::JavaScriptTypeScript)
    }

    #[doc(hidden)]
    pub fn as_str(self) -> &'static str {
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
#[doc(hidden)]
pub struct WorkspaceUsageNodeKey {
    #[doc(hidden)]
    pub id: DeclarationId,
    #[doc(hidden)]
    pub ecosystem: UsageEcosystem,
    #[doc(hidden)]
    pub fqn: String,
    #[doc(hidden)]
    pub defining_file: Option<ProjectFile>,
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
#[doc(hidden)]
pub struct WorkspaceUsageNode {
    #[doc(hidden)]
    pub key: WorkspaceUsageNodeKey,
    #[doc(hidden)]
    pub primary: CodeUnit,
    #[doc(hidden)]
    pub primary_range: Option<Range>,
    #[doc(hidden)]
    pub declaration_files: Vec<ProjectFile>,
    #[doc(hidden)]
    pub declaration_ids: Vec<DeclarationId>,
    #[doc(hidden)]
    pub truncated_inbound: Option<usize>,
    #[doc(hidden)]
    pub unproven_inbound: usize,
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
    #[doc(hidden)]
    pub fn language_label(&self) -> &'static str {
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

#[doc(hidden)]
pub struct WorkspaceUsageCatalog {
    #[doc(hidden)]
    pub nodes: Vec<WorkspaceUsageNode>,
    indices_by_id: HashMap<DeclarationId, usize>,
}

impl WorkspaceUsageCatalog {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn build(analyzer: &dyn IAnalyzer) -> Self {
        Self::build_with_cancellation(analyzer, &CancellationToken::default())
            .expect("uncancelled workspace usage catalog construction")
    }

    /// Enumerate one file's graph declarations through its persisted summary
    /// projection. Each lookup is bounded to one live analyzed file; the rooted
    /// builder uses it so a small supplied root set never materializes an
    /// analyzer generation.
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
        if !graph_file_is_selected(analyzer, file) {
            return Some(Vec::new());
        }
        #[cfg(any(test, feature = "test-support"))]
        CATALOG_FILES_ENUMERATED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

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
        (!cancellation.is_cancelled()).then_some(declarations)
    }

    #[doc(hidden)]
    pub fn build_with_cancellation(
        analyzer: &dyn IAnalyzer,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let declarations = {
            let _scope = crate::profiling::scope("workspace_graph::batched_catalog_enumeration");
            if cancellation.is_cancelled() {
                return None;
            }
            let declarations = analyzer.workspace_declarations_with_primary_ranges(cancellation)?;
            if cancellation.is_cancelled() {
                return None;
            }
            let mut declarations: Vec<CatalogDeclaration> = declarations
                .into_iter()
                .filter(|(unit, _)| graph_file_is_selected(analyzer, unit.source()))
                .collect();
            let files = analyzer.analyzed_files();
            for (index, file) in files.into_iter().enumerate() {
                if index.is_multiple_of(512) && cancellation.is_cancelled() {
                    return None;
                }
                if is_java_module_descriptor_file(&file) {
                    let file_scope = CodeUnit::file_scope(file.clone());
                    let range = analyzer
                        .ranges(&file_scope)
                        .into_iter()
                        .min_by_key(range_key);
                    declarations.push((file_scope, range));
                }
            }
            declarations
                .into_iter()
                .filter(|(unit, _)| is_graph_declaration(unit))
                .collect()
        };
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
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn build_for_files(analyzer: &dyn IAnalyzer, files: &[ProjectFile]) -> Self {
        Self::build_for_files_with_cancellation(analyzer, files, &CancellationToken::default())
            .expect("uncancelled rooted workspace usage catalog construction")
    }

    #[doc(hidden)]
    pub fn build_for_files_with_cancellation(
        analyzer: &dyn IAnalyzer,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let mut declarations = Vec::new();
        for file in files {
            if cancellation.is_cancelled() {
                return None;
            }
            declarations.extend(Self::declarations_for_file(analyzer, file, cancellation)?);
        }
        Self::from_declarations(declarations, cancellation)
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
    #[doc(hidden)]
    pub fn from_declarations(
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

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn ecosystems(&self) -> BTreeSet<UsageEcosystem> {
        self.nodes.iter().map(|node| node.key.ecosystem).collect()
    }

    #[doc(hidden)]
    pub fn ecosystems_for_files<'a>(
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

    #[doc(hidden)]
    pub fn index_for_id(&self, id: &DeclarationId) -> Option<usize> {
        self.indices_by_id.get(id).copied()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn from_reduced_nodes(
        nodes: Vec<WorkspaceUsageNode>,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let mut indices_by_id = HashMap::default();
        for (index, node) in nodes.iter().enumerate() {
            if cancellation.is_cancelled() {
                return None;
            }
            for id in &node.declaration_ids {
                if cancellation.is_cancelled() {
                    return None;
                }
                let previous = indices_by_id.insert(id.clone(), index);
                assert!(
                    previous.is_none(),
                    "one reduced declaration ID belongs to one graph node"
                );
            }
        }
        Some(Self {
            nodes,
            indices_by_id,
        })
    }

    /// Join each non-primary member of a merged node to the cataloged node its
    /// primary heads, keyed `member id -> node id`.
    ///
    /// A catalog grouped from node primaries alone knows only primary ids, but
    /// a C++ or C# node merges redeclarations across files: a header prototype
    /// is the primary of its `.cpp` definition, whose body holds the sites. A
    /// site inside that definition must still join to the node (#3671).
    #[doc(hidden)]
    pub fn join_members(&mut self, members: &HashMap<DeclarationId, DeclarationId>) {
        for (member, node_id) in members {
            let index = self.index_for_id(node_id).unwrap_or_else(|| {
                panic!("merged member {member:?} names uncataloged node {node_id:?}")
            });
            let previous = self.indices_by_id.insert(member.clone(), index);
            assert!(
                previous.is_none_or(|previous| previous == index),
                "one declaration ID belongs to one graph node: {member:?}"
            );
            if previous.is_none() {
                self.nodes[index].declaration_ids.push(member.clone());
            }
        }
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

fn graph_file_is_selected(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> bool {
    language_support(crate::analyzer::common::language_for_file(file)).is_none_or(|support| {
        support
            .unnamed_module_root_for_file(analyzer, file)
            .is_none()
    })
}

#[cfg(any(test, feature = "test-support"))]
static CATALOG_FILES_ENUMERATED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// Declaration identities computed while building a catalog.
///
/// `CodeUnit::declaration_id` is a SHA-256 over every identity field, and the
/// grouping used to compute one per row for each place the identity was
/// needed. This is the cost shape the catalog pins: one identity per inventory
/// row, not one per row per use of that identity.
#[cfg(any(test, feature = "test-support"))]
static CATALOG_DECLARATION_IDENTITIES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// The declaration identity of `unit`, counted for the cost-shape pin.
fn declaration_identity(unit: &CodeUnit) -> DeclarationId {
    #[cfg(any(test, feature = "test-support"))]
    CATALOG_DECLARATION_IDENTITIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    unit.declaration_id()
}

fn range_key(range: &Range) -> (usize, usize) {
    (range.start_line, range.start_byte)
}

#[doc(hidden)]
pub fn is_graph_declaration(unit: &CodeUnit) -> bool {
    let is_java_module_descriptor_scope =
        unit.is_file_scope() && is_java_module_descriptor_file(unit.source());
    (!unit.is_synthetic() || is_java_module_descriptor_scope)
        && (unit.is_class() || unit.is_callable() || is_java_module_descriptor_scope)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct WorkspaceUsageEdge {
    #[doc(hidden)]
    pub from: usize,
    #[doc(hidden)]
    pub to: usize,
    #[doc(hidden)]
    pub counts: UsageReferenceCounts,
}

#[doc(hidden)]
pub struct WorkspaceUsageGraph {
    #[doc(hidden)]
    pub nodes: Vec<WorkspaceUsageNode>,
    #[doc(hidden)]
    pub edges: Vec<WorkspaceUsageEdge>,
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub resolved_ecosystems: Vec<UsageEcosystem>,
}

#[doc(hidden)]
pub struct WorkspaceUsageRankingNode {
    #[doc(hidden)]
    pub primary_file: ProjectFile,
    #[doc(hidden)]
    pub seed_files: Vec<ProjectFile>,
    #[doc(hidden)]
    pub incomplete: bool,
    /// Present on the coarse file-dependency graph, whose bulk file-fact read
    /// already knows whether each file contains tests. Exact symbol graphs do
    /// not currently consume this classification.
    #[doc(hidden)]
    pub contains_tests: Option<bool>,
}

#[doc(hidden)]
pub struct WorkspaceUsageRankingGraph {
    #[doc(hidden)]
    pub nodes: Vec<WorkspaceUsageRankingNode>,
    #[doc(hidden)]
    pub edges: Vec<WorkspaceUsageEdge>,
    #[doc(hidden)]
    pub node_indices_by_file: HashMap<ProjectFile, Vec<usize>>,
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub resolved_ecosystems: Vec<UsageEcosystem>,
}

impl WorkspaceUsageRankingGraph {
    #[doc(hidden)]
    pub fn from_exact(graph: WorkspaceUsageGraph) -> Self {
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
            #[cfg(any(test, feature = "test-support"))]
            resolved_ecosystems: graph.resolved_ecosystems,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn from_exact_with_cancellation(
        graph: WorkspaceUsageGraph,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let WorkspaceUsageGraph {
            nodes: exact_nodes,
            edges,
            #[cfg(any(test, feature = "test-support"))]
            resolved_ecosystems,
        } = graph;
        let mut node_indices_by_file: HashMap<ProjectFile, Vec<usize>> = HashMap::default();
        let mut nodes = Vec::with_capacity(exact_nodes.len());
        for (index, node) in exact_nodes.into_iter().enumerate() {
            if cancellation.is_cancelled() {
                return None;
            }
            for file in &node.declaration_files {
                if cancellation.is_cancelled() {
                    return None;
                }
                node_indices_by_file
                    .entry(file.clone())
                    .or_default()
                    .push(index);
            }
            nodes.push(WorkspaceUsageRankingNode {
                primary_file: node.primary.source().clone(),
                seed_files: node.declaration_files,
                incomplete: node.truncated_inbound.is_some() || node.unproven_inbound > 0,
                contains_tests: None,
            });
        }
        if cancellation.is_cancelled() {
            return None;
        }
        let graph = Self {
            nodes,
            edges,
            node_indices_by_file,
            #[cfg(any(test, feature = "test-support"))]
            resolved_ecosystems,
        };
        (!cancellation.is_cancelled()).then_some(graph)
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

#[doc(hidden)]
pub enum WorkspaceUsageGraphBuildOutcome {
    Complete(WorkspaceUsageGraph),
    Incomplete(WorkspaceUsageGraph),
    Cancelled,
    Stale,
    Unavailable(String),
    Failed(StoreError),
}

#[doc(hidden)]
pub fn build_workspace_usage_graph_with_cancellation(
    analyzer: &dyn IAnalyzer,
    catalog: WorkspaceUsageCatalog,
    selected_ecosystems: &BTreeSet<UsageEcosystem>,
    cancellation: &CancellationToken,
) -> WorkspaceUsageGraphBuildOutcome {
    build_workspace_usage_graph_with_passes(
        analyzer,
        catalog,
        selected_ecosystems,
        cancellation,
        &edge_passes(),
    )
}

#[doc(hidden)]
pub fn build_workspace_usage_graph_with_passes(
    analyzer: &dyn IAnalyzer,
    catalog: WorkspaceUsageCatalog,
    selected_ecosystems: &BTreeSet<UsageEcosystem>,
    cancellation: &CancellationToken,
    passes: &[crate::analyzer::languages::EdgePassEntry],
) -> WorkspaceUsageGraphBuildOutcome {
    let scope = AnalyzerQueryScope::with_cancellation(analyzer, cancellation);
    let generation = analyzer.project().analysis_generation();
    let mut native_projections = Vec::new();
    let mut nodes = catalog.nodes.clone();
    let mut edges = Vec::new();
    let mut passes_complete = true;
    #[cfg(any(test, feature = "test-support"))]
    let mut resolved_ecosystems = Vec::new();
    let keep_file = |_: &ProjectFile| !cancellation.is_cancelled();
    // This consumer's request is the whole workspace, so the preflight's file
    // set is every *analyzable* file. It cannot be `analyzed_files`:
    // publication readiness is part of the analyzed-file predicate, so a file
    // whose canonical facts were never published is missing from that listing
    // for exactly the reason the preflight exists to report.
    // `source_file_inventory` is the listing that keeps such a file, and it
    // reads the project's shared file listing rather than the store.
    let analyzable_files = analyzer.source_file_inventory().rows;
    for entry in passes {
        if !selected_ecosystems.contains(&entry.ecosystem) {
            continue;
        }
        if cancellation.is_cancelled() {
            return WorkspaceUsageGraphBuildOutcome::Cancelled;
        }
        // Input authority is the backend's question, asked before any caller
        // admission: a pass whose canonical facts cannot be read admits every
        // file and reports a complete graph with no edges for them.
        if entry
            .backend
            .input_failure(analyzer, &analyzable_files)
            .is_some()
        {
            passes_complete = false;
            continue;
        }
        let pass = match entry.backend {
            LanguageGraphBackend::Legacy(pass) => pass,
            LanguageGraphBackend::Native(provider) => {
                // Admission is the analyzed listing, not the analyzable one:
                // only a published file can contribute an edge, and the
                // preflight above has already reported any that cannot.
                let mut admitted_callers = Vec::new();
                for file in analyzer.analyzed_files() {
                    if cancellation.is_cancelled() {
                        return WorkspaceUsageGraphBuildOutcome::Cancelled;
                    }
                    if entry
                        .languages
                        .contains(&super::common::language_for_file(&file))
                    {
                        admitted_callers.push(file);
                    }
                }
                let projection = match provider.project(analyzer, &admitted_callers, cancellation) {
                    Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Complete(projection)) => {
                        projection
                    }
                    Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(projection)) => {
                        passes_complete = false;
                        projection
                    }
                    Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled) => {
                        return WorkspaceUsageGraphBuildOutcome::Cancelled;
                    }
                    Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale) => {
                        return WorkspaceUsageGraphBuildOutcome::Stale;
                    }
                    Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason)) => {
                        return WorkspaceUsageGraphBuildOutcome::Unavailable(reason);
                    }
                    Err(error) => return WorkspaceUsageGraphBuildOutcome::Failed(error),
                };
                projection.certify_callers(&admitted_callers.into_iter().collect());
                native_projections.push(projection);
                continue;
            }
        };
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
        #[cfg(any(test, feature = "test-support"))]
        resolved_ecosystems.push(entry.ecosystem);
        let ctx = EdgeWeightScanCtx {
            analyzer,
            fqns: &fqns,
            scoped_nodes: &scoped_nodes,
            keep_file: &keep_file,
        };
        match pass.edge_weights(&ctx) {
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
            Some(LanguageEdgeWeights::Unavailable(_failure)) => {
                // This consumer returns completeness, not per-file diagnostics;
                // its partial graph must not be cached as a complete result.
                passes_complete = false;
            }
            None => {}
        }
    }
    edges.sort_by_key(|edge| (edge.from, edge.to));
    #[cfg(any(test, feature = "test-support"))]
    resolved_ecosystems.dedup();
    let graph = WorkspaceUsageGraph {
        nodes,
        edges,
        #[cfg(any(test, feature = "test-support"))]
        resolved_ecosystems,
    };
    if cancellation.is_cancelled() {
        return WorkspaceUsageGraphBuildOutcome::Cancelled;
    }
    if analyzer.project().analysis_generation() != generation {
        return WorkspaceUsageGraphBuildOutcome::Stale;
    }
    let graph = match canonical_workspace_graph::merge_workspace_usage_graph_projections(
        graph,
        &native_projections,
        generation,
        cancellation,
    ) {
        WorkspaceUsageGraphBuildOutcome::Complete(graph) => graph,
        WorkspaceUsageGraphBuildOutcome::Incomplete(graph) => {
            passes_complete = false;
            graph
        }
        terminal => return terminal,
    };
    if cancellation.is_cancelled() {
        return WorkspaceUsageGraphBuildOutcome::Cancelled;
    }
    if analyzer.project().analysis_generation() != generation {
        return WorkspaceUsageGraphBuildOutcome::Stale;
    }
    if let Some(error) = scope.store_error() {
        return WorkspaceUsageGraphBuildOutcome::Failed(error);
    }
    if !passes_complete {
        return WorkspaceUsageGraphBuildOutcome::Incomplete(graph);
    }
    WorkspaceUsageGraphBuildOutcome::Complete(graph)
}

fn record_fqn_weights_exact(
    ecosystem: UsageEcosystem,
    result: UsageEdgeWeights,
    catalog: &WorkspaceUsageCatalog,
    nodes: &mut [WorkspaceUsageNode],
    edges: &mut Vec<WorkspaceUsageEdge>,
) {
    record_exact_weights(result, nodes, edges, |fqn| {
        catalog.indices_for_fqn(ecosystem, fqn)
    });
}

fn record_scoped_weights_exact(
    ecosystem: UsageEcosystem,
    result: UsageEdgeWeights<UsageNodeKey>,
    catalog: &WorkspaceUsageCatalog,
    nodes: &mut [WorkspaceUsageNode],
    edges: &mut Vec<WorkspaceUsageEdge>,
) {
    record_exact_weights(result, nodes, edges, |key| {
        catalog.indices_for_scoped(ecosystem, key)
    });
}

fn record_exact_weights<K>(
    result: UsageEdgeWeights<K>,
    nodes: &mut [WorkspaceUsageNode],
    edges: &mut Vec<WorkspaceUsageEdge>,
    indices_for_key: impl Fn(&K) -> Vec<usize>,
) {
    for ((from, to), counts) in result.edges {
        let from = indices_for_key(&from);
        let to = indices_for_key(&to);
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
        for index in indices_for_key(&key) {
            nodes[index].truncated_inbound = Some(total);
        }
    }
    for (key, total) in result.unproven_inbound {
        for index in indices_for_key(&key) {
            nodes[index].unproven_inbound = nodes[index].unproven_inbound.saturating_add(total);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::CodeUnitIndex;
    use crate::analyzer::usages::workspace_graph::cpp_test_support::*;

    use brokk_bifrost_test_macros::hardwon;

    use std::ffi::OsStr;

    #[test]
    fn batched_catalog_enumeration_matches_authoritative_inventory_without_file_projections() {
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
            "batched enumeration must preserve exact catalog identity, ranges, duplicates, and order"
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
            0,
            "unrooted catalog construction must not open any per-file summary projection"
        );

        let rooted_files = analyzer
            .analyzed_files()
            .into_iter()
            .take(2)
            .collect::<Vec<_>>();
        CATALOG_FILES_ENUMERATED.store(0, std::sync::atomic::Ordering::Relaxed);
        let rooted = WorkspaceUsageCatalog::build_for_files(&analyzer, &rooted_files);
        assert!(!rooted.nodes.is_empty());
        assert_eq!(
            CATALOG_FILES_ENUMERATED.load(std::sync::atomic::Ordering::Relaxed),
            rooted_files.len(),
            "rooted catalog construction must remain bounded to its supplied files"
        );

        assert!(
            actual.nodes.iter().any(|node| {
                node.primary.is_file_scope()
                    && node.primary.source().rel_path() == std::path::Path::new("module-info.java")
            }),
            "batched declaration enumeration must retain the graph-only Java module descriptor"
        );

        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert!(
            WorkspaceUsageCatalog::build_with_cancellation(&analyzer, &cancelled).is_none(),
            "a cancelled inventory must not publish a partial catalog"
        );

        // Five checks let the first delegate enter its store query and read its
        // mounted rows, then cancel before hydration can publish that batch.
        let cancelled_during_enumeration = CancellationToken::cancel_after_checks_for_test(5);
        assert!(
            WorkspaceUsageCatalog::build_with_cancellation(
                &analyzer,
                &cancelled_during_enumeration
            )
            .is_none(),
            "cancellation after reading a mounted batch must discard the whole inventory"
        );
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
    #[hardwon(
        "2d6e0d05e77f: The analyzer-backed catalog build checks one identity calculation per persisted graph declaration"
    )]
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
    #[hardwon(
        "2d6e0d05e77f: Cancellation midway through grouping discards the partial catalog, and the identical rows succeed on retry"
    )]
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod cpp_test_support;
