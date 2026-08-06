//! Compact exact-identity usage graph shared by relevance ranking and graph APIs.

use super::common::language_for_target;
use super::inverted_edges::{UsageEdgeWeights, UsageNodeKey, UsageReferenceCounts};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use std::collections::{BTreeMap, BTreeSet};

/// The name universe a declaration's identity belongs to.
///
/// One ecosystem is one candidate space: two declarations in the same
/// ecosystem with the same fully-qualified name are the same node, and a
/// reference resolved anywhere in the ecosystem can land on any of its nodes.
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
    pub(crate) fn of(language: Language) -> Self {
        match language {
            Language::JavaScript | Language::TypeScript => Self::JavaScriptTypeScript,
            Language::Python => Self::Python,
            Language::Go => Self::Go,
            Language::Rust => Self::Rust,
            Language::Java | Language::Scala | Language::Kotlin => Self::Jvm,
            Language::CSharp => Self::CSharp,
            Language::Cpp => Self::Cpp,
            Language::Php => Self::Php,
            Language::Ruby => Self::Ruby,
            Language::None => Self::Unknown,
        }
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
    pub(crate) ecosystem: UsageEcosystem,
    pub(crate) fqn: String,
    pub(crate) defining_file: Option<ProjectFile>,
}

impl WorkspaceUsageNodeKey {
    fn for_declaration(unit: &CodeUnit) -> Self {
        let ecosystem = UsageEcosystem::of(language_for_target(unit));
        Self {
            ecosystem,
            fqn: unit.fq_name(),
            defining_file: ecosystem.is_module_scoped().then(|| unit.source().clone()),
        }
    }

    fn package_scoped(ecosystem: UsageEcosystem, fqn: String) -> Self {
        Self {
            ecosystem,
            fqn,
            defining_file: None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct WorkspaceUsageNode {
    pub(crate) key: WorkspaceUsageNodeKey,
    pub(crate) primary: CodeUnit,
    pub(crate) primary_range: Option<Range>,
    pub(crate) declaration_files: Vec<ProjectFile>,
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
    indices: HashMap<WorkspaceUsageNodeKey, usize>,
    fqns_by_ecosystem: HashMap<UsageEcosystem, HashSet<String>>,
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
        let mut declarations: BTreeMap<WorkspaceUsageNodeKey, Vec<(CodeUnit, Option<Range>)>> =
            BTreeMap::new();
        for (unit, range) in analyzer.all_declarations_with_primary_ranges() {
            if cancellation.is_cancelled() {
                return None;
            }
            if unit.is_synthetic() || !(unit.is_class() || unit.is_callable()) {
                continue;
            }
            declarations
                .entry(WorkspaceUsageNodeKey::for_declaration(&unit))
                .or_default()
                .push((unit, range));
        }

        let mut nodes = Vec::with_capacity(declarations.len());
        let mut indices = HashMap::default();
        let mut fqns_by_ecosystem: HashMap<UsageEcosystem, HashSet<String>> = HashMap::default();
        for (key, mut declarations) in declarations {
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
            let mut declaration_files: Vec<_> = declarations
                .iter()
                .map(|(unit, _)| unit.source().clone())
                .collect();
            declaration_files.sort();
            declaration_files.dedup();
            let index = nodes.len();
            indices.insert(key.clone(), index);
            fqns_by_ecosystem
                .entry(key.ecosystem)
                .or_default()
                .insert(key.fqn.clone());
            nodes.push(WorkspaceUsageNode {
                key,
                primary,
                primary_range,
                declaration_files,
                truncated_inbound: None,
                unproven_inbound: 0,
            });
        }
        Some(Self {
            nodes,
            indices,
            fqns_by_ecosystem,
        })
    }

    pub(crate) fn fqns(&self, ecosystem: UsageEcosystem) -> &HashSet<String> {
        static EMPTY: std::sync::OnceLock<HashSet<String>> = std::sync::OnceLock::new();
        self.fqns_by_ecosystem
            .get(&ecosystem)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::default))
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

    fn index_of(&self, key: &WorkspaceUsageNodeKey) -> Option<usize> {
        self.indices.get(key).copied()
    }
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
                    incomplete: node.truncated_inbound.is_some(),
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

    macro_rules! record_package_edges {
        ($scope:literal, $ecosystem:expr, $builder:path) => {{
            if selected_ecosystems.contains(&$ecosystem) {
                if cancellation.is_cancelled() {
                    return WorkspaceUsageGraphBuildOutcome::Cancelled;
                }
                let _scope = crate::profiling::scope($scope);
                let fqns = catalog.fqns($ecosystem);
                if !fqns.is_empty() {
                    #[cfg(test)]
                    resolved_ecosystems.push($ecosystem);
                    if let Some(result) = $builder(analyzer, fqns, |_| !cancellation.is_cancelled())
                    {
                        record_weighted_edges($ecosystem, result, &catalog, &mut nodes, &mut edges);
                    }
                }
                if cancellation.is_cancelled() {
                    return WorkspaceUsageGraphBuildOutcome::Cancelled;
                }
            }
        }};
    }

    record_package_edges!(
        "workspace_usage_graph::resolve_go",
        UsageEcosystem::Go,
        super::go_graph::build_go_usage_edge_weights
    );
    record_package_edges!(
        "workspace_usage_graph::resolve_python",
        UsageEcosystem::Python,
        super::python_graph::build_python_usage_edge_weights
    );
    record_package_edges!(
        "workspace_usage_graph::resolve_rust",
        UsageEcosystem::Rust,
        super::rust_graph::build_rust_usage_edge_weights
    );
    // One JVM realm, three resolvers. Java, Scala, and Kotlin declarations share
    // one node space, so all three builders run over the *same* candidate set
    // and merge into it. There is no double counting: each resolver only scans
    // files of its own language, so the three passes cover disjoint call sites.
    // The realm is symmetric — a reference resolved in any of the three can land
    // on a declaration from any of them — which is what makes a mixed
    // Java/Kotlin workspace report call relationships in both directions.
    record_package_edges!(
        "workspace_usage_graph::resolve_jvm_java",
        UsageEcosystem::Jvm,
        super::java_graph::build_java_usage_edge_weights
    );
    record_package_edges!(
        "workspace_usage_graph::resolve_jvm_scala",
        UsageEcosystem::Jvm,
        super::scala_graph::build_scala_usage_edge_weights
    );
    record_package_edges!(
        "workspace_usage_graph::resolve_jvm_kotlin",
        UsageEcosystem::Jvm,
        super::kotlin_graph::build_kotlin_usage_edge_weights
    );
    record_package_edges!(
        "workspace_usage_graph::resolve_csharp",
        UsageEcosystem::CSharp,
        super::csharp_graph::build_csharp_usage_edge_weights
    );
    record_package_edges!(
        "workspace_usage_graph::resolve_cpp",
        UsageEcosystem::Cpp,
        super::cpp_graph::build_cpp_usage_edge_weights
    );
    record_package_edges!(
        "workspace_usage_graph::resolve_php",
        UsageEcosystem::Php,
        super::php_graph::build_php_usage_edge_weights
    );
    record_package_edges!(
        "workspace_usage_graph::resolve_ruby",
        UsageEcosystem::Ruby,
        super::ruby_graph::build_ruby_usage_edge_weights
    );
    // Scala's builder is not invoked separately here: it runs above over the
    // shared `Jvm` candidate set, alongside Java's.
    if selected_ecosystems.contains(&UsageEcosystem::JavaScriptTypeScript) {
        let _jsts_scope = crate::profiling::scope("workspace_usage_graph::resolve_jsts");
        if cancellation.is_cancelled() {
            return WorkspaceUsageGraphBuildOutcome::Cancelled;
        }
        let scoped_nodes: HashSet<_> = catalog
            .nodes
            .iter()
            .filter(|node| node.key.ecosystem == UsageEcosystem::JavaScriptTypeScript)
            .map(|node| {
                UsageNodeKey::new(
                    node.key
                        .defining_file
                        .clone()
                        .expect("JS/TS catalog keys are file scoped"),
                    node.key.fqn.clone(),
                )
            })
            .collect();
        if !scoped_nodes.is_empty() {
            #[cfg(test)]
            resolved_ecosystems.push(UsageEcosystem::JavaScriptTypeScript);
            if let Some(result) =
                super::js_ts_graph::build_jsts_scoped_usage_edges(analyzer, &scoped_nodes, |_| {
                    !cancellation.is_cancelled()
                })
            {
                let convert = |key: UsageNodeKey| WorkspaceUsageNodeKey {
                    ecosystem: UsageEcosystem::JavaScriptTypeScript,
                    fqn: key.fqn,
                    defining_file: Some(key.file),
                };
                for ((from, to), counts) in result.edges.edges {
                    let (Some(from), Some(to)) = (
                        catalog.index_of(&convert(from)),
                        catalog.index_of(&convert(to)),
                    ) else {
                        continue;
                    };
                    edges.push(WorkspaceUsageEdge { from, to, counts });
                }
                for (key, total) in result.edges.truncated {
                    if let Some(index) = catalog.index_of(&convert(key)) {
                        nodes[index].truncated_inbound = Some(total);
                    }
                }
                for (key, total) in result.edges.unproven_inbound {
                    if let Some(index) = catalog.index_of(&convert(key)) {
                        nodes[index].unproven_inbound += total;
                    }
                }
            }
        }

        if cancellation.is_cancelled() {
            return WorkspaceUsageGraphBuildOutcome::Cancelled;
        }
    }

    if cancellation.is_cancelled() {
        return WorkspaceUsageGraphBuildOutcome::Cancelled;
    }

    edges.sort_by_key(|edge| (edge.from, edge.to));
    // The JVM realm runs two builders over one ecosystem, so it would otherwise
    // be recorded twice; this reports which ecosystems were resolved, not how
    // many passes each took.
    #[cfg(test)]
    resolved_ecosystems.dedup();
    WorkspaceUsageGraphBuildOutcome::Complete(WorkspaceUsageGraph {
        nodes,
        edges,
        #[cfg(test)]
        resolved_ecosystems,
    })
}

fn record_weighted_edges(
    ecosystem: UsageEcosystem,
    result: UsageEdgeWeights,
    catalog: &WorkspaceUsageCatalog,
    nodes: &mut [WorkspaceUsageNode],
    edges: &mut Vec<WorkspaceUsageEdge>,
) {
    for ((from, to), counts) in result.edges {
        let (Some(from), Some(to)) = (
            catalog.index_of(&WorkspaceUsageNodeKey::package_scoped(ecosystem, from)),
            catalog.index_of(&WorkspaceUsageNodeKey::package_scoped(ecosystem, to)),
        ) else {
            continue;
        };
        edges.push(WorkspaceUsageEdge { from, to, counts });
    }
    for (fqn, total) in result.truncated {
        if let Some(index) =
            catalog.index_of(&WorkspaceUsageNodeKey::package_scoped(ecosystem, fqn))
        {
            nodes[index].truncated_inbound = Some(total);
        }
    }
    for (fqn, total) in result.unproven_inbound {
        if let Some(index) =
            catalog.index_of(&WorkspaceUsageNodeKey::package_scoped(ecosystem, fqn))
        {
            nodes[index].unproven_inbound += total;
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
            "expected the Kotlin -> Java edge the shared realm exists to provide"
        );
    }
}
