use super::super::workspace_graph::{UsageEcosystem, WorkspaceUsageRankingGraph};
use super::{
    WorkspaceFileUsageGraphBuildOutcome, build_workspace_file_usage_graph_with_cancellation,
};
use crate::analyzer::capabilities::{
    AdditionalFileDependencies, FileDependencyFacts, ImportAnalysisProvider,
};
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, CodeUnitIndex, CppAnalyzer, DeclarationInfo, IAnalyzer,
    ImportInfo, Language, Project, ProjectFile, QueryBatch, QueryScope,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy)]
enum AdditionalDependencies {
    Complete,
    Unavailable,
}

struct TestImportProvider {
    facts: Option<HashMap<ProjectFile, FileDependencyFacts>>,
    edges: HashMap<ProjectFile, HashSet<ProjectFile>>,
    additional_dependencies: AdditionalDependencies,
    forbidden_import_info_file: Option<ProjectFile>,
    import_info_calls: Arc<AtomicUsize>,
    prefetch_calls: Arc<AtomicUsize>,
}

impl TestImportProvider {
    fn new(
        facts: Option<HashMap<ProjectFile, FileDependencyFacts>>,
        edges: HashMap<ProjectFile, HashSet<ProjectFile>>,
        additional_dependencies: AdditionalDependencies,
        forbidden_import_info_file: Option<ProjectFile>,
    ) -> Arc<Self> {
        Arc::new(Self {
            facts,
            edges,
            additional_dependencies,
            forbidden_import_info_file,
            import_info_calls: Arc::new(AtomicUsize::new(0)),
            prefetch_calls: Arc::new(AtomicUsize::new(0)),
        })
    }
}

impl ImportAnalysisProvider for TestImportProvider {
    fn imported_code_units_of(&self, _file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        Arc::new(HashSet::default())
    }

    fn referencing_files_of(&self, _file: &ProjectFile) -> HashSet<ProjectFile> {
        HashSet::default()
    }

    fn file_dependency_facts_for_files(
        &self,
        _files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, FileDependencyFacts>> {
        self.facts.clone()
    }

    fn import_info_of(&self, _token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        assert_ne!(
            self.forbidden_import_info_file.as_ref(),
            Some(file),
            "legacy import hydration must not run for a missing authoritative fact"
        );
        self.import_info_calls.fetch_add(1, Ordering::AcqRel);
        Vec::new()
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        _imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        Some(self.edges.get(file).cloned().unwrap_or_default())
    }

    fn prefetch_file_dependency_targets(
        &self,
        _files: &[ProjectFile],
        _import_infos: Option<&HashMap<ProjectFile, Vec<ImportInfo>>>,
        _cancellation: &CancellationToken,
    ) {
        self.prefetch_calls.fetch_add(1, Ordering::AcqRel);
    }

    fn additional_direct_file_dependencies(
        &self,
        _files: &[ProjectFile],
        _cancellation: &CancellationToken,
    ) -> Option<AdditionalFileDependencies> {
        match self.additional_dependencies {
            AdditionalDependencies::Complete => {
                Some(AdditionalFileDependencies::complete(HashMap::default()))
            }
            AdditionalDependencies::Unavailable => None,
        }
    }
}

#[derive(Clone)]
struct TestAnalyzer {
    project: Arc<dyn Project>,
    files: Vec<ProjectFile>,
    provider: Arc<TestImportProvider>,
    contains_tests_calls: Arc<AtomicUsize>,
    forbidden_contains_tests_file: Option<ProjectFile>,
    source_inventory_complete: bool,
    use_project_source_inventory: bool,
}

impl TestAnalyzer {
    fn new(
        built: &BuiltInlineTestProject,
        files: Vec<ProjectFile>,
        provider: Arc<TestImportProvider>,
        forbidden_contains_tests_file: Option<ProjectFile>,
    ) -> Self {
        Self {
            project: built.project_dyn(),
            files,
            provider,
            contains_tests_calls: Arc::new(AtomicUsize::new(0)),
            forbidden_contains_tests_file,
            source_inventory_complete: true,
            use_project_source_inventory: false,
        }
    }

    fn with_incomplete_source_inventory(mut self) -> Self {
        self.source_inventory_complete = false;
        self
    }

    fn with_project_source_inventory(mut self) -> Self {
        self.use_project_source_inventory = true;
        self
    }
}

impl CodeUnitIndex for TestAnalyzer {
    fn project(&self) -> &dyn Project {
        self.project.as_ref()
    }

    fn languages(&self) -> BTreeSet<Language> {
        [Language::Rust].into_iter().collect()
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        self.files.clone()
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        Box::new(std::iter::empty())
    }

    fn search_definitions(&self, _pattern: &str, _case_sensitive: bool) -> BTreeSet<CodeUnit> {
        unimplemented!("coarse file graphs do not search declarations")
    }

    fn enclosing_code_unit(
        &self,
        _file: &ProjectFile,
        _range: &crate::analyzer::Range,
    ) -> Option<CodeUnit> {
        unimplemented!("coarse file graphs do not locate declarations")
    }

    fn enclosing_code_unit_for_lines(
        &self,
        _file: &ProjectFile,
        _start_line: usize,
        _end_line: usize,
    ) -> Option<CodeUnit> {
        unimplemented!("coarse file graphs do not locate declarations")
    }

    fn get_skeleton(&self, _unit: &CodeUnit) -> Option<String> {
        unimplemented!("coarse file graphs do not render declarations")
    }

    fn get_skeleton_header(&self, _unit: &CodeUnit) -> Option<String> {
        unimplemented!("coarse file graphs do not render declarations")
    }

    fn get_source(&self, _unit: &CodeUnit, _include_comments: bool) -> Option<String> {
        unimplemented!("coarse file graphs do not read source")
    }

    fn get_sources(&self, _unit: &CodeUnit, _include_comments: bool) -> BTreeSet<String> {
        unimplemented!("coarse file graphs do not read source")
    }
}

impl IAnalyzer for TestAnalyzer {
    fn source_file_inventory(&self) -> QueryBatch<ProjectFile> {
        if self.use_project_source_inventory {
            return crate::analyzer::i_analyzer::project_source_file_inventory(self);
        }
        if self.source_inventory_complete {
            QueryBatch::complete(self.files.clone(), self.files.len())
        } else {
            QueryBatch::incomplete(self.files.clone(), self.files.len())
        }
    }

    fn update(&self, _changed_files: &BTreeSet<ProjectFile>) -> Self
    where
        Self: Sized,
    {
        self.clone()
    }

    fn update_all(&self) -> Self
    where
        Self: Sized,
    {
        self.clone()
    }

    fn extract_call_receiver(&self, _reference: &str) -> Option<String> {
        None
    }

    fn is_access_expression(
        &self,
        _file: &ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
    ) -> bool {
        false
    }

    fn find_nearest_declaration(
        &self,
        _file: &ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
        _ident: &str,
    ) -> Option<DeclarationInfo> {
        None
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self.provider.as_ref())
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        assert_ne!(
            self.forbidden_contains_tests_file.as_ref(),
            Some(file),
            "per-file test classification must not run for a missing authoritative fact"
        );
        self.contains_tests_calls.fetch_add(1, Ordering::AcqRel);
        false
    }
}

fn selected_rust_ecosystem() -> BTreeSet<UsageEcosystem> {
    [UsageEcosystem::Rust].into_iter().collect()
}

fn inline_rust_project() -> BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Rust)
        .file("a.rs", "fn a() {}")
        .file("b.rs", "fn b() {}")
        .file("c.rs", "fn c() {}")
        .build()
}

fn empty_facts(files: &[ProjectFile]) -> HashMap<ProjectFile, FileDependencyFacts> {
    files
        .iter()
        .cloned()
        .map(|file| {
            (
                file,
                FileDependencyFacts {
                    imports: Vec::new(),
                    contains_tests: Some(false),
                },
            )
        })
        .collect()
}

fn direct_edge(
    source: &ProjectFile,
    target: &ProjectFile,
) -> HashMap<ProjectFile, HashSet<ProjectFile>> {
    [(source.clone(), [target.clone()].into_iter().collect())]
        .into_iter()
        .collect()
}

fn graph_node<'a>(
    graph: &'a WorkspaceUsageRankingGraph,
    file: &ProjectFile,
) -> &'a super::super::workspace_graph::WorkspaceUsageRankingNode {
    graph
        .nodes
        .iter()
        .find(|node| node.primary_file == *file)
        .unwrap_or_else(|| panic!("graph is missing node for {file:?}"))
}

fn assert_edge(graph: &WorkspaceUsageRankingGraph, source: &ProjectFile, target: &ProjectFile) {
    let source_index = graph
        .nodes
        .iter()
        .position(|node| node.primary_file == *source)
        .unwrap();
    let target_index = graph
        .nodes
        .iter()
        .position(|node| node.primary_file == *target)
        .unwrap();
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.from == source_index && edge.to == target_index)
    );
}

#[test]
fn partial_bulk_facts_are_authoritative_and_preserve_available_edges() {
    let built = inline_rust_project();
    let files = [built.file("a.rs"), built.file("b.rs"), built.file("c.rs")];
    let available_facts = empty_facts(&files[..2]);
    let provider = TestImportProvider::new(
        Some(available_facts),
        direct_edge(&files[0], &files[1]),
        AdditionalDependencies::Complete,
        Some(files[2].clone()),
    );
    let analyzer = TestAnalyzer::new(
        &built,
        files.to_vec(),
        Arc::clone(&provider),
        Some(files[2].clone()),
    );
    let cancellation = CancellationToken::new();
    let scope = AnalyzerQueryScope::new(&analyzer);
    let outcome = build_workspace_file_usage_graph_with_cancellation(
        &analyzer,
        scope.token(),
        &selected_rust_ecosystem(),
        &cancellation,
    );

    let graph = match outcome {
        WorkspaceFileUsageGraphBuildOutcome::Incomplete(graph) => graph,
        WorkspaceFileUsageGraphBuildOutcome::Complete(_) => {
            panic!("a bulk map missing a requested file is incomplete")
        }
        WorkspaceFileUsageGraphBuildOutcome::Cancelled => panic!("unexpected cancellation"),
    };
    assert_eq!(Some(false), graph_node(&graph, &files[0]).contains_tests);
    assert_eq!(Some(false), graph_node(&graph, &files[1]).contains_tests);
    assert_eq!(None, graph_node(&graph, &files[2]).contains_tests);
    assert!(graph_node(&graph, &files[2]).incomplete);
    assert_edge(&graph, &files[0], &files[1]);
    assert_eq!(0, provider.import_info_calls.load(Ordering::Acquire));
    assert_eq!(0, analyzer.contains_tests_calls.load(Ordering::Acquire));
    assert_eq!(0, provider.prefetch_calls.load(Ordering::Acquire));
}

#[test]
fn complete_bulk_map_with_known_empty_entries_is_complete() {
    let built = inline_rust_project();
    let files = [built.file("a.rs"), built.file("b.rs"), built.file("c.rs")];
    let provider = TestImportProvider::new(
        Some(empty_facts(&files)),
        HashMap::default(),
        AdditionalDependencies::Complete,
        None,
    );
    let analyzer = TestAnalyzer::new(&built, files.to_vec(), Arc::clone(&provider), None);
    let cancellation = CancellationToken::new();
    let scope = AnalyzerQueryScope::new(&analyzer);
    let outcome = build_workspace_file_usage_graph_with_cancellation(
        &analyzer,
        scope.token(),
        &selected_rust_ecosystem(),
        &cancellation,
    );

    let graph = match outcome {
        WorkspaceFileUsageGraphBuildOutcome::Complete(graph) => graph,
        WorkspaceFileUsageGraphBuildOutcome::Incomplete(_) => {
            panic!("a complete bulk map with empty entries must be complete")
        }
        WorkspaceFileUsageGraphBuildOutcome::Cancelled => panic!("unexpected cancellation"),
    };
    assert!(
        graph
            .nodes
            .iter()
            .all(|node| node.contains_tests == Some(false) && !node.incomplete)
    );
    assert_eq!(0, analyzer.contains_tests_calls.load(Ordering::Acquire));
}

#[test]
fn absent_bulk_facts_keep_legacy_per_file_reads_supported() {
    let built = inline_rust_project();
    let files = [built.file("a.rs"), built.file("b.rs"), built.file("c.rs")];
    let provider = TestImportProvider::new(
        None,
        direct_edge(&files[0], &files[1]),
        AdditionalDependencies::Complete,
        None,
    );
    let analyzer = TestAnalyzer::new(&built, files.to_vec(), Arc::clone(&provider), None);
    let cancellation = CancellationToken::new();
    let scope = AnalyzerQueryScope::new(&analyzer);
    let outcome = build_workspace_file_usage_graph_with_cancellation(
        &analyzer,
        scope.token(),
        &selected_rust_ecosystem(),
        &cancellation,
    );

    let graph = match outcome {
        WorkspaceFileUsageGraphBuildOutcome::Complete(graph) => graph,
        WorkspaceFileUsageGraphBuildOutcome::Incomplete(_) => {
            panic!("legacy per-file facts should remain complete")
        }
        WorkspaceFileUsageGraphBuildOutcome::Cancelled => panic!("unexpected cancellation"),
    };
    assert_edge(&graph, &files[0], &files[1]);
    assert_eq!(
        files.len(),
        provider.import_info_calls.load(Ordering::Acquire)
    );
    assert_eq!(
        files.len(),
        analyzer.contains_tests_calls.load(Ordering::Acquire)
    );
}

#[test]
fn cancellation_before_bulk_reads_returns_cancelled() {
    let built = inline_rust_project();
    let files = [built.file("a.rs"), built.file("b.rs"), built.file("c.rs")];
    let provider = TestImportProvider::new(
        Some(empty_facts(&files)),
        HashMap::default(),
        AdditionalDependencies::Complete,
        None,
    );
    let analyzer = TestAnalyzer::new(&built, files.to_vec(), Arc::clone(&provider), None);
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let scope = AnalyzerQueryScope::new(&analyzer);
    let outcome = build_workspace_file_usage_graph_with_cancellation(
        &analyzer,
        scope.token(),
        &selected_rust_ecosystem(),
        &cancellation,
    );

    assert!(matches!(
        outcome,
        WorkspaceFileUsageGraphBuildOutcome::Cancelled
    ));
    assert_eq!(0, provider.import_info_calls.load(Ordering::Acquire));
    assert_eq!(0, analyzer.contains_tests_calls.load(Ordering::Acquire));
}

#[test]
fn unavailable_additional_dependencies_keep_import_edges_and_mark_incomplete() {
    let built = inline_rust_project();
    let files = [built.file("a.rs"), built.file("b.rs"), built.file("c.rs")];
    let provider = TestImportProvider::new(
        Some(empty_facts(&files)),
        direct_edge(&files[0], &files[1]),
        AdditionalDependencies::Unavailable,
        None,
    );
    let analyzer = TestAnalyzer::new(&built, files.to_vec(), Arc::clone(&provider), None);
    let cancellation = CancellationToken::new();
    let scope = AnalyzerQueryScope::new(&analyzer);
    let outcome = build_workspace_file_usage_graph_with_cancellation(
        &analyzer,
        scope.token(),
        &selected_rust_ecosystem(),
        &cancellation,
    );

    let graph = match outcome {
        WorkspaceFileUsageGraphBuildOutcome::Incomplete(graph) => graph,
        WorkspaceFileUsageGraphBuildOutcome::Complete(_) => {
            panic!("unavailable additional dependencies must be incomplete")
        }
        WorkspaceFileUsageGraphBuildOutcome::Cancelled => panic!("unexpected cancellation"),
    };
    assert_edge(&graph, &files[0], &files[1]);
    assert!(
        graph
            .nodes
            .iter()
            .all(|node| node.contains_tests == Some(false))
    );
}

#[test]
fn incomplete_source_inventory_preserves_known_bulk_edges() {
    let built = inline_rust_project();
    let files = [built.file("a.rs"), built.file("b.rs"), built.file("c.rs")];
    let provider = TestImportProvider::new(
        Some(empty_facts(&files)),
        direct_edge(&files[0], &files[1]),
        AdditionalDependencies::Complete,
        None,
    );
    let analyzer = TestAnalyzer::new(&built, files.to_vec(), Arc::clone(&provider), None)
        .with_incomplete_source_inventory();
    let cancellation = CancellationToken::new();
    let scope = AnalyzerQueryScope::new(&analyzer);
    let outcome = build_workspace_file_usage_graph_with_cancellation(
        &analyzer,
        scope.token(),
        &selected_rust_ecosystem(),
        &cancellation,
    );

    let graph = match outcome {
        WorkspaceFileUsageGraphBuildOutcome::Incomplete(graph) => graph,
        WorkspaceFileUsageGraphBuildOutcome::Complete(_) => {
            panic!("an incomplete source inventory cannot publish a complete graph")
        }
        WorkspaceFileUsageGraphBuildOutcome::Cancelled => panic!("unexpected cancellation"),
    };
    assert_edge(&graph, &files[0], &files[1]);
    assert_eq!(files.len(), graph.nodes.len());
    assert_eq!(0, provider.prefetch_calls.load(Ordering::Acquire));
}

#[test]
fn inactive_project_language_is_not_a_coarse_graph_node() {
    let built = InlineTestProject::with_language(Language::Rust)
        .file("main.rs", "fn main() {}")
        .file("inactive.py", "class Inactive: pass")
        .build();
    let rust_file = built.file("main.rs");
    let inactive_file = built.file("inactive.py");
    let provider = TestImportProvider::new(
        Some(empty_facts(std::slice::from_ref(&rust_file))),
        direct_edge(&rust_file, &inactive_file),
        AdditionalDependencies::Complete,
        None,
    );
    let analyzer = TestAnalyzer::new(
        &built,
        vec![rust_file.clone(), inactive_file.clone()],
        Arc::clone(&provider),
        None,
    )
    .with_project_source_inventory();
    let cancellation = CancellationToken::new();
    let scope = AnalyzerQueryScope::new(&analyzer);
    let outcome = build_workspace_file_usage_graph_with_cancellation(
        &analyzer,
        scope.token(),
        &[UsageEcosystem::Rust, UsageEcosystem::Python]
            .into_iter()
            .collect(),
        &cancellation,
    );

    let graph = match outcome {
        WorkspaceFileUsageGraphBuildOutcome::Complete(graph) => graph,
        WorkspaceFileUsageGraphBuildOutcome::Incomplete(_) => {
            panic!("the complete active-language project inventory should be complete")
        }
        WorkspaceFileUsageGraphBuildOutcome::Cancelled => panic!("unexpected cancellation"),
    };
    assert!(
        graph
            .nodes
            .iter()
            .any(|node| node.primary_file == rust_file)
    );
    assert!(
        !graph
            .nodes
            .iter()
            .any(|node| node.primary_file == inactive_file)
    );
}

#[test]
fn cpp_inventory_keeps_adopted_inc_edges_and_excludes_unowned_files() {
    let built = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.cpp",
            "#include \"adopted.inc\"\n#include \"reference_only.vue\"\nint main() { return 0; }\n",
        )
        .file("adopted.inc", "struct Adopted { int value; };\n")
        .file("unadopted.inc", "struct Orphan { int value; };\n")
        .file(
            "reference_only.vue",
            "<template><p>reference only</p></template>\n",
        )
        .file("inactive.py", "class Inactive: pass\n")
        .build();
    let analyzer = CppAnalyzer::from_project(built.project().clone());
    let main = built.file("main.cpp");
    let adopted = built.file("adopted.inc");
    let unadopted = built.file("unadopted.inc");
    let inactive = built.file("inactive.py");
    let reference_only = built.file("reference_only.vue");
    let cancellation = CancellationToken::new();
    let scope = AnalyzerQueryScope::new(&analyzer);
    let outcome = build_workspace_file_usage_graph_with_cancellation(
        &analyzer,
        scope.token(),
        &[UsageEcosystem::Cpp].into_iter().collect(),
        &cancellation,
    );

    let graph = match outcome {
        WorkspaceFileUsageGraphBuildOutcome::Complete(graph)
        | WorkspaceFileUsageGraphBuildOutcome::Incomplete(graph) => graph,
        WorkspaceFileUsageGraphBuildOutcome::Cancelled => panic!("unexpected cancellation"),
    };
    assert!(graph.nodes.iter().any(|node| node.primary_file == main));
    assert!(graph.nodes.iter().any(|node| node.primary_file == adopted));
    assert!(
        !graph
            .nodes
            .iter()
            .any(|node| node.primary_file == unadopted)
    );
    assert!(!graph.nodes.iter().any(|node| node.primary_file == inactive));
    assert!(
        !graph
            .nodes
            .iter()
            .any(|node| node.primary_file == reference_only)
    );
    assert_edge(&graph, &main, &adopted);
}
