//! Compact exact-identity usage graph shared by relevance ranking and graph APIs.

use super::common::{language_for_file, language_for_target};
use super::inverted_edges::{UsageNodeKey, UsageReferenceCounts};
use crate::analyzer::languages::{
    EdgeWeightScanCtx, LanguageEdgeWeights, LanguageSupport, edge_passes, language_support,
};
use crate::analyzer::{CodeUnit, DeclarationId, IAnalyzer, Language, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;

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
    pub(crate) fn for_declaration(unit: &CodeUnit) -> Self {
        let ecosystem = UsageEcosystem::of(language_for_target(unit));
        Self {
            id: unit.declaration_id(),
            ecosystem,
            fqn: unit.fq_name(),
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

    pub(crate) fn build_with_cancellation(
        analyzer: &dyn IAnalyzer,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let mut declarations = Vec::new();
        for (unit, range) in analyzer.all_declarations_with_primary_ranges() {
            if cancellation.is_cancelled() {
                return None;
            }
            if is_graph_declaration(&unit) {
                declarations.push((unit, range));
            }
        }

        // The public declaration inventory intentionally excludes synthetic
        // file scopes. Java module descriptors need one graph caller, however,
        // so add the existing `module-info.java` file scope through this
        // graph-only catalog path. This avoids turning the named module into a
        // package Module CodeUnit, which can collide with a package of the same
        // name.
        for file in analyzer.analyzed_files() {
            if cancellation.is_cancelled() {
                return None;
            }
            if !is_java_module_descriptor_file(&file) {
                continue;
            }
            let file_scope = CodeUnit::file_scope(file.clone());
            let range = analyzer
                .ranges(&file_scope)
                .into_iter()
                .min_by_key(|range| (range.start_line, range.start_byte));
            declarations.push((file_scope, range));
        }

        Self::from_declarations(declarations, cancellation)
    }

    /// Build a graph-node catalog from only `files`, using one persisted summary
    /// projection per file. This is the rooted `usage_graph` path: it must not
    /// enumerate every declaration in a long-lived workspace cache before it can
    /// answer a handful of changed-file roots.
    pub(crate) fn build_for_files(analyzer: &dyn IAnalyzer, files: &[ProjectFile]) -> Self {
        let mut declarations = Vec::new();
        for file in files {
            if let Some(projection) = analyzer.summary_file_projection(file) {
                let mut stack = projection.top_level_declarations.clone();
                let mut seen = HashSet::default();
                while let Some(unit) = stack.pop() {
                    if !seen.insert(unit.clone()) {
                        continue;
                    }
                    if let Some(children) = projection.children.get(&unit) {
                        stack.extend(children.iter().cloned());
                    }
                    if is_graph_declaration(&unit) {
                        declarations.push((
                            unit.clone(),
                            projection
                                .ranges
                                .get(&unit)
                                .and_then(|ranges| primary_range(ranges)),
                        ));
                    }
                }
            } else {
                for unit in analyzer.declarations(file) {
                    if is_graph_declaration(&unit) {
                        let range = analyzer.ranges(&unit).into_iter().min_by_key(range_key);
                        declarations.push((unit, range));
                    }
                }
            }
            if is_java_module_descriptor_file(file) {
                let file_scope = CodeUnit::file_scope(file.clone());
                let range = analyzer
                    .ranges(&file_scope)
                    .into_iter()
                    .min_by_key(range_key);
                declarations.push((file_scope, range));
            }
        }
        Self::from_declarations(declarations, &CancellationToken::default())
            .expect("uncancelled rooted workspace usage catalog construction")
    }

    pub(crate) fn from_declarations(
        declarations: Vec<(CodeUnit, Option<Range>)>,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
        struct GroupKey {
            ecosystem: UsageEcosystem,
            fqn: String,
            kind: crate::analyzer::CodeUnitType,
            signature: Option<String>,
            exact_declaration: Option<DeclarationId>,
        }

        let mut grouped: BTreeMap<GroupKey, Vec<(CodeUnit, Option<Range>)>> = BTreeMap::new();
        for (unit, range) in declarations {
            if cancellation.is_cancelled() {
                return None;
            }
            if is_graph_declaration(&unit) {
                let ecosystem = UsageEcosystem::of(language_for_target(&unit));
                let exact_declaration =
                    (!matches!(ecosystem, UsageEcosystem::Cpp | UsageEcosystem::CSharp))
                        .then(|| unit.declaration_id());
                grouped
                    .entry(GroupKey {
                        ecosystem,
                        fqn: unit.fq_name(),
                        kind: unit.kind(),
                        signature: unit.signature().map(str::to_string),
                        exact_declaration,
                    })
                    .or_default()
                    .push((unit, range));
            }
        }

        let mut nodes = Vec::with_capacity(grouped.len());
        for (_, mut declarations) in grouped {
            if cancellation.is_cancelled() {
                return None;
            }
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
            let (primary, primary_range) = declarations
                .first()
                .expect("catalog groups are never empty")
                .clone();
            let key = WorkspaceUsageNodeKey::for_declaration(&primary);
            let mut declaration_files: Vec<_> = declarations
                .iter()
                .map(|(unit, _)| unit.source().clone())
                .collect();
            declaration_files.sort();
            declaration_files.dedup();
            let mut declaration_ids = declarations
                .iter()
                .map(|(unit, _)| unit.declaration_id())
                .collect::<Vec<_>>();
            declaration_ids.sort();
            declaration_ids.dedup();
            nodes.push(WorkspaceUsageNode {
                key,
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
    use crate::analyzer::{
        AnalyzerDelegate, JavaAnalyzer, KotlinAnalyzer, MultiAnalyzer, ScalaAnalyzer, TestProject,
    };
    use std::sync::Arc;

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
}
