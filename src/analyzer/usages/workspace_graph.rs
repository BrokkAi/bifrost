//! Compact exact-identity usage graph shared by relevance ranking and graph APIs.

use super::common::language_for_target;
use super::inverted_edges::{UsageEdgeWeights, UsageNodeKey};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum UsageEcosystem {
    JavaScriptTypeScript,
    Python,
    Go,
    Rust,
    Java,
    CSharp,
    Cpp,
    Php,
    Ruby,
    Scala,
    Unknown,
}

impl UsageEcosystem {
    pub(crate) fn of(language: Language) -> Self {
        match language {
            Language::JavaScript | Language::TypeScript => Self::JavaScriptTypeScript,
            Language::Python => Self::Python,
            Language::Go => Self::Go,
            Language::Rust => Self::Rust,
            Language::Java => Self::Java,
            Language::CSharp => Self::CSharp,
            Language::Cpp => Self::Cpp,
            Language::Php => Self::Php,
            Language::Ruby => Self::Ruby,
            Language::Scala => Self::Scala,
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
            Self::Java => "java",
            Self::CSharp => "csharp",
            Self::Cpp => "cpp",
            Self::Php => "php",
            Self::Ruby => "ruby",
            Self::Scala => "scala",
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

pub(crate) struct WorkspaceUsageCatalog {
    pub(crate) nodes: Vec<WorkspaceUsageNode>,
    indices: HashMap<WorkspaceUsageNodeKey, usize>,
    fqns_by_ecosystem: HashMap<UsageEcosystem, HashSet<String>>,
}

impl WorkspaceUsageCatalog {
    pub(crate) fn build(analyzer: &dyn IAnalyzer) -> Self {
        let mut declarations: BTreeMap<WorkspaceUsageNodeKey, Vec<(CodeUnit, Option<Range>)>> =
            BTreeMap::new();
        for (unit, range) in analyzer.all_declarations_with_primary_ranges() {
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
        Self {
            nodes,
            indices,
            fqns_by_ecosystem,
        }
    }

    pub(crate) fn fqns(&self, ecosystem: UsageEcosystem) -> &HashSet<String> {
        static EMPTY: std::sync::OnceLock<HashSet<String>> = std::sync::OnceLock::new();
        self.fqns_by_ecosystem
            .get(&ecosystem)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::default))
    }

    fn index_of(&self, key: &WorkspaceUsageNodeKey) -> Option<usize> {
        self.indices.get(key).copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkspaceUsageEdge {
    pub(crate) from: usize,
    pub(crate) to: usize,
    pub(crate) weight: usize,
}

pub(crate) struct WorkspaceUsageGraph {
    pub(crate) nodes: Vec<WorkspaceUsageNode>,
    pub(crate) edges: Vec<WorkspaceUsageEdge>,
}

pub(crate) fn build_workspace_usage_graph(
    analyzer: &dyn IAnalyzer,
    catalog: WorkspaceUsageCatalog,
) -> WorkspaceUsageGraph {
    let mut nodes = catalog.nodes.clone();
    let mut edges = Vec::new();

    macro_rules! record_package_edges {
        ($ecosystem:expr, $builder:path) => {{
            if let Some(result) = $builder(analyzer, catalog.fqns($ecosystem), |_| true) {
                record_weighted_edges($ecosystem, result, &catalog, &mut nodes, &mut edges);
            }
        }};
    }

    record_package_edges!(
        UsageEcosystem::Go,
        super::go_graph::build_go_usage_edge_weights
    );
    record_package_edges!(
        UsageEcosystem::Python,
        super::python_graph::build_python_usage_edge_weights
    );
    record_package_edges!(
        UsageEcosystem::Rust,
        super::rust_graph::build_rust_usage_edge_weights
    );
    record_package_edges!(
        UsageEcosystem::Java,
        super::java_graph::build_java_usage_edge_weights
    );
    record_package_edges!(
        UsageEcosystem::CSharp,
        super::csharp_graph::build_csharp_usage_edge_weights
    );
    record_package_edges!(
        UsageEcosystem::Cpp,
        super::cpp_graph::build_cpp_usage_edge_weights
    );
    record_package_edges!(
        UsageEcosystem::Php,
        super::php_graph::build_php_usage_edge_weights
    );
    record_package_edges!(
        UsageEcosystem::Ruby,
        super::ruby_graph::build_ruby_usage_edge_weights
    );
    record_package_edges!(
        UsageEcosystem::Scala,
        super::scala_graph::build_scala_usage_edge_weights
    );

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
    if let Some(result) =
        super::js_ts_graph::build_jsts_scoped_usage_edges(analyzer, &scoped_nodes, |_| true)
    {
        let convert = |key: UsageNodeKey| WorkspaceUsageNodeKey {
            ecosystem: UsageEcosystem::JavaScriptTypeScript,
            fqn: key.fqn,
            defining_file: Some(key.file),
        };
        for ((from, to), weight) in result.edges.edges {
            let (Some(from), Some(to)) = (
                catalog.index_of(&convert(from)),
                catalog.index_of(&convert(to)),
            ) else {
                continue;
            };
            edges.push(WorkspaceUsageEdge { from, to, weight });
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

    edges.sort_by_key(|edge| (edge.from, edge.to));
    WorkspaceUsageGraph { nodes, edges }
}

fn record_weighted_edges(
    ecosystem: UsageEcosystem,
    result: UsageEdgeWeights,
    catalog: &WorkspaceUsageCatalog,
    nodes: &mut [WorkspaceUsageNode],
    edges: &mut Vec<WorkspaceUsageEdge>,
) {
    for ((from, to), weight) in result.edges {
        let (Some(from), Some(to)) = (
            catalog.index_of(&WorkspaceUsageNodeKey::package_scoped(ecosystem, from)),
            catalog.index_of(&WorkspaceUsageNodeKey::package_scoped(ecosystem, to)),
        ) else {
            continue;
        };
        edges.push(WorkspaceUsageEdge { from, to, weight });
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
