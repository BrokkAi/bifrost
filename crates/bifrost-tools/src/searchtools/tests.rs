use crate::searchtools::navigation::SearchSymbolsParams;

use crate::searchtools::navigation::search_symbols_with_cancellation;

use crate::searchtools::navigation::search_symbols_with_cap;

use crate::searchtools::scan_usages::render_symbol_usages;

use crate::searchtools::scan_usages::usage_failure_hint;

use crate::searchtools::summaries::SummariesParams;

use crate::searchtools::selectors::DefinitionCandidateRenderCache;

use crate::searchtools::scan_usages::ScanUsageRequest;

use crate::searchtools::scan_usages::ScanUsagesAbsenceCaveat;

use crate::searchtools::scan_usages::ScanUsagesByLocationParams;

use crate::searchtools::scan_usages::ScanUsagesCandidateFilesSample;

use crate::searchtools::scan_usages::ScanUsagesExecutionContext;

use crate::searchtools::scan_usages::ScanUsagesIncompleteReason;

use crate::searchtools::scan_usages::ScanUsagesStatus;

use crate::searchtools::scan_usages::ScanUsagesSurface;

use crate::searchtools::scan_usages::ScanUsagesTarget;

use crate::searchtools::scan_usages::ScanUsagesWorkEntry;

use crate::searchtools::navigation::SymbolLookupParams;

use crate::searchtools::sources::SymbolSourcesResult;

use crate::searchtools::scan_usages::SymbolUsageRenderState;

use crate::searchtools::scan_usages::UsageFailureInfo;

use brokk_bifrost_core::analyzer::usages::model::UsageHitKind;

use crate::searchtools::scan_usages::UsageHitRow;

use crate::searchtools::scan_usages::UsageRendering;

use crate::searchtools::scan_usages::classify_scan_usages_entry;

use crate::searchtools::selectors::definition_candidate_from_range;

use crate::searchtools::summaries::get_summaries;

use crate::searchtools::sources::get_symbol_sources;

use crate::searchtools::resolve_file_patterns;

use crate::searchtools::scan_usages::scan_usages_by_location_with_context;

use crate::searchtools::sources::symbol_source_candidate_files;

use crate::searchtools::scan_usages::function_like_macro_query;

use crate::searchtools::summaries::route_summary_targets;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::CodeUnitType;

use brokk_bifrost_core::analyzer::model::DeclarationInfo;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;

use crate::searchtools_render::RenderOptions;

use crate::searchtools_render::RenderText;

use brokk_bifrost_analysis::test_support::rel_paths;
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[derive(Debug)]
struct CountingProject {
    root: PathBuf,
    files: BTreeSet<ProjectFile>,
}

impl CountingProject {
    fn new(root: PathBuf, files: BTreeSet<ProjectFile>) -> Self {
        Self { root, files }
    }
}

impl Project for CountingProject {
    fn root(&self) -> &Path {
        &self.root
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        BTreeSet::from([Language::Java])
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        Ok(self.files.clone())
    }

    fn analyzable_files(&self, _language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        Ok(self.files.clone())
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        self.files.contains(&file).then_some(file)
    }
}

struct CountingAnalyzer {
    project: CountingProject,
    /// Workspace files this analyzer has NOT analyzed. They stay in the
    /// project listing, which is what a real workspace looks like: the listing
    /// is every git-visible file, the analyzed set is the subset the store
    /// holds parsed declarations for.
    unanalyzed: BTreeSet<ProjectFile>,
    analyzed_files_calls: AtomicUsize,
    /// Files offered to `retain_analyzed`, summed over calls. This is the
    /// complexity signal for #1738: a glob request must offer only the files
    /// its pattern matched, never the workspace.
    retain_analyzed_candidates: AtomicUsize,
    retain_analyzed_calls: AtomicUsize,
    search_definitions_calls: AtomicUsize,
    /// Declarations `search_definitions` reports, which the default
    /// `IAnalyzer::search_symbol_candidates` turns into search candidates.
    /// Empty unless a test asks for them, so every other test is unaffected.
    search_definition_results: BTreeSet<CodeUnit>,
}

impl CountingAnalyzer {
    fn new(root: PathBuf, rel_paths: &[&str]) -> Self {
        let files = rel_paths
            .iter()
            .map(|rel_path| ProjectFile::new(root.clone(), *rel_path))
            .collect();
        Self {
            project: CountingProject::new(root, files),
            unanalyzed: BTreeSet::new(),
            analyzed_files_calls: AtomicUsize::new(0),
            retain_analyzed_candidates: AtomicUsize::new(0),
            retain_analyzed_calls: AtomicUsize::new(0),
            search_definitions_calls: AtomicUsize::new(0),
            search_definition_results: BTreeSet::new(),
        }
    }

    /// Add workspace files the listing shows but the analyzer never indexed.
    fn with_unanalyzed(mut self, rel_paths: &[&str]) -> Self {
        for rel_path in rel_paths {
            let file = ProjectFile::new(self.project.root.clone(), *rel_path);
            self.project.files.insert(file.clone());
            self.unanalyzed.insert(file);
        }
        self
    }

    fn with_search_definitions(mut self, code_units: impl IntoIterator<Item = CodeUnit>) -> Self {
        self.search_definition_results = code_units.into_iter().collect();
        self
    }

    fn analyzed_files_calls(&self) -> usize {
        self.analyzed_files_calls.load(Ordering::Relaxed)
    }

    fn retain_analyzed_candidates(&self) -> usize {
        self.retain_analyzed_candidates.load(Ordering::Relaxed)
    }

    fn retain_analyzed_calls(&self) -> usize {
        self.retain_analyzed_calls.load(Ordering::Relaxed)
    }

    fn search_definitions_calls(&self) -> usize {
        self.search_definitions_calls.load(Ordering::Relaxed)
    }
}

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

impl CodeUnitIndex for CountingAnalyzer {
    fn enclosing_code_unit(&self, _file: &ProjectFile, _range: &Range) -> Option<CodeUnit> {
        None
    }

    fn enclosing_code_unit_for_lines(
        &self,
        _file: &ProjectFile,
        _start_line: usize,
        _end_line: usize,
    ) -> Option<CodeUnit> {
        None
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        self.analyzed_files_calls.fetch_add(1, Ordering::Relaxed);
        self.project
            .files
            .iter()
            .filter(|file| !self.unanalyzed.contains(*file))
            .cloned()
            .collect()
    }

    /// Answers from the same set `analyzed_files` reports, but counts the
    /// candidates it was offered instead of reporting the whole workspace.
    /// A real persisted analyzer settles these with one store query; the fake
    /// only has to charge for the size of the question.
    fn retain_analyzed(&self, candidates: &[ProjectFile]) -> Vec<ProjectFile> {
        self.retain_analyzed_calls.fetch_add(1, Ordering::Relaxed);
        self.retain_analyzed_candidates
            .fetch_add(candidates.len(), Ordering::Relaxed);
        let mut retained: Vec<_> = candidates
            .iter()
            .filter(|file| self.project.files.contains(*file) && !self.unanalyzed.contains(*file))
            .cloned()
            .collect();
        retained.sort();
        retained
    }

    fn languages(&self) -> BTreeSet<Language> {
        BTreeSet::from([Language::Java])
    }

    fn project(&self) -> &dyn Project {
        &self.project
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        Box::new(std::iter::empty())
    }

    fn get_declarations(&self, _file: &ProjectFile) -> BTreeSet<CodeUnit> {
        BTreeSet::new()
    }

    fn get_definitions(&self, _fq_name: &str) -> Vec<CodeUnit> {
        Vec::new()
    }

    fn get_direct_children(&self, _code_unit: &CodeUnit) -> Vec<CodeUnit> {
        Vec::new()
    }

    // `ranges_of` defaults to this, so overriding `ranges` alone keeps the two
    // consistent for every caller.
    fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        if !self.search_definition_results.contains(code_unit) {
            return Vec::new();
        }
        vec![Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
        }]
    }

    fn get_skeleton(&self, _code_unit: &CodeUnit) -> Option<String> {
        None
    }

    fn get_skeleton_header(&self, _code_unit: &CodeUnit) -> Option<String> {
        None
    }

    fn get_source(&self, _code_unit: &CodeUnit, _include_comments: bool) -> Option<String> {
        None
    }

    fn get_sources(&self, _code_unit: &CodeUnit, _include_comments: bool) -> BTreeSet<String> {
        BTreeSet::new()
    }

    fn search_definitions(&self, _pattern: &str, _auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.search_definitions_calls
            .fetch_add(1, Ordering::Relaxed);
        self.search_definition_results.clone()
    }

    fn has_complete_symbol_lookup_index(&self) -> bool {
        true
    }
}

impl IAnalyzer for CountingAnalyzer {
    fn update(&self, _changed_files: &BTreeSet<ProjectFile>) -> Self {
        Self {
            project: CountingProject::new(self.project.root.clone(), self.project.files.clone()),
            unanalyzed: self.unanalyzed.clone(),
            analyzed_files_calls: AtomicUsize::new(self.analyzed_files_calls()),
            retain_analyzed_candidates: AtomicUsize::new(self.retain_analyzed_candidates()),
            retain_analyzed_calls: AtomicUsize::new(self.retain_analyzed_calls()),
            search_definitions_calls: AtomicUsize::new(self.search_definitions_calls()),
            search_definition_results: self.search_definition_results.clone(),
        }
    }

    fn update_all(&self) -> Self {
        self.update(&BTreeSet::new())
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

    fn list_symbols(&self, file: &ProjectFile) -> String {
        format!(
            "- {}",
            brokk_bifrost_core::path_utils::rel_path_string(file).replace('/', "_")
        )
    }
}

#[test]
fn broad_navigation_fallback_omits_unproven_columns() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let file = ProjectFile::new(root.clone(), "Broken.java");
    file.write("???\n").unwrap();
    let analyzer = CountingAnalyzer::new(root, &["Broken.java"]);
    let code_unit = CodeUnit::new(file, CodeUnitType::Function, "", "missing");
    let declaration_range = Range {
        start_byte: 0,
        end_byte: 3,
        start_line: 1,
        end_line: 1,
    };
    let target = brokk_bifrost_analysis::analyzer::usages::get_definition::NavigationTarget {
        code_unit,
        declaration_range: Some(declaration_range),
    };

    let (range, columns) = DefinitionCandidateRenderCache::default()
        .navigation_display_range(&analyzer, &target)
        .expect("broad fallback range");
    assert_eq!(range, declaration_range);
    assert_eq!(columns, None);

    let candidate = definition_candidate_from_range(&analyzer, &target.code_unit, range, columns);
    let value = serde_json::to_value(candidate).unwrap();
    assert!(value.get("start_column").is_none(), "{value}");
    assert!(value.get("end_column").is_none(), "{value}");
}

#[test]
fn complete_symbol_index_skips_enclosing_owner_regex_scan() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let analyzer = CountingAnalyzer::new(root, &["Broken.java"]);
    let result = SymbolSourcesResult {
        sources: Vec::new(),
        not_found: vec![crate::searchtools::selectors::NotFoundInput {
            input: "missing.Owner.member".to_string(),
            note: None,
        }],
        ambiguous: Vec::new(),
        ambiguous_paths: Vec::new(),
        too_broad: Vec::new(),
        complete: true,
        incomplete: Vec::new(),
    };

    let files = symbol_source_candidate_files(&analyzer, &result);

    assert!(files.is_empty());
    assert_eq!(analyzer.search_definitions_calls(), 0);
}

#[brokk_bifrost_test_macros::hardwon(
    "#1707: Runs a real Rust declaration through semantic outcome-key generation twice and verifies cached declaration context is reused once"
)]
#[test]
fn definition_outcome_key_reuses_declaration_context() {
    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    let fixture =
        AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", "pub fn target() {}\n")]);
    let analyzer = fixture.analyzer.analyzer();
    let unit = analyzer
        .search_definitions("target", false)
        .into_iter()
        .next()
        .expect("target declaration");
    let outcome = DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status: DefinitionLookupStatus::Resolved,
        reference: None,
        definitions: vec![unit],
        lexical_definition: None,
        diagnostics: Vec::new(),
    };
    let mut render_cache = DefinitionCandidateRenderCache::default();

    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let first = crate::searchtools::definitions::semantic_outcome_key(
        analyzer,
        token,
        &outcome,
        &mut render_cache,
    );
    let second = crate::searchtools::definitions::semantic_outcome_key(
        analyzer,
        token,
        &outcome,
        &mut render_cache,
    );

    assert_eq!(first, second);
    assert_eq!(render_cache.declaration_context_count(), 1);
}

#[brokk_bifrost_test_macros::hardwon(
    "0f945d6a0f14: Python file summaries emitted module functions twice through top-level and synthetic-module ownership"
)]
#[test]
fn python_module_functions_are_not_duplicated_in_file_summary() {
    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_python_analysis::analyzer::python::PythonAnalyzer;

    use brokk_bifrost_core::analyzer::project::TestProject;

    // Module-level Python defs are registered both as their own top-level
    // declarations and as children of the synthetic module unit (which is
    // itself top-level), so the file-summary recursion previously emitted each
    // one twice. The file summary must list each declaration exactly once.
    let source = "\
def alpha(x):
return x

def beta(y):
return y + 1

def gamma():
return 0
";
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let file = ProjectFile::new(root.clone(), std::path::PathBuf::from("mod.py"));
    file.write(source).unwrap();
    let analyzer = PythonAnalyzer::from_project(TestProject::new(root, Language::Python));

    let result = crate::searchtools::summaries::summarize_files(&analyzer, vec![file]);
    let block = result.summaries.first().expect("one file summary");
    let names: Vec<&str> = block.elements.iter().map(|e| e.symbol.as_str()).collect();
    let mut unique = names.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        names.len(),
        unique.len(),
        "each module-level function must appear once, got {names:?}"
    );
    assert_eq!(
        unique.len(),
        3,
        "expected alpha/beta/gamma once each, got {names:?}"
    );
}

#[brokk_bifrost_test_macros::hardwon(
    "#1431: Fix regression #1431: a Java source block using CR-only line endings must report the same multi-line span as its content"
)]
#[test]
fn issue_1431_source_block_end_line_counts_cr_only_terminators() {
    use brokk_bifrost_analysis::analyzer::java::JavaAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::TestProject;

    // CR-only line endings (\r with no \n, classic Mac convention) surfaced the
    // text.lines() undercount in SourceBlock end_line: lines() splits on \n
    // alone, so a multi-row declaration read as one line and end_line collapsed
    // onto start_line (#1431).
    let source = "public class A {\r    @Deprecated\r    public void m() {\r    }\r}\r";
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), std::path::PathBuf::from("A.java"))
        .write(source)
        .unwrap();
    let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));

    let unit = analyzer
        .search_definitions("m", false)
        .into_iter()
        .find(|unit| unit.fq_name().contains(".m"))
        .expect("method unit");
    let blocks = get_symbol_sources(
        &analyzer,
        SymbolLookupParams {
            symbols: vec![unit.fq_name()],
        },
    )
    .sources;
    let block = blocks
        .iter()
        .find(|block| block.text.contains("public void m"))
        .expect("source block for m");

    assert!(block.text.contains('\r'), "{block:#?}");
    let expected_rows = block.text.trim_end_matches('\r').split('\r').count();
    assert!(
        expected_rows > 1,
        "test needs a multi-row declaration, got {block:#?}"
    );
    assert_eq!(
        block.end_line - block.start_line + 1,
        expected_rows,
        "end_line must count CR-only terminators like start_line does: {block:#?}"
    );
}

#[test]
fn missing_explicit_source_paths_skip_fuzzy_symbol_resolution() {
    let root = std::env::current_dir().unwrap();
    let analyzer = CountingAnalyzer::new(root, &["src/Present.java"]);
    let targets = [
        "src/analyzer/semantic_model/overlay.rs",
        r"src\analyzer\semantic_model\overlay.rs",
        "web/components/App.vue",
        r"views\Home.cshtml",
    ];

    let sources = get_symbol_sources(
        &analyzer,
        SymbolLookupParams {
            symbols: targets.iter().map(|target| target.to_string()).collect(),
        },
    );
    assert_eq!(targets.len(), sources.not_found.len(), "{sources:#?}");
    assert!(sources.sources.is_empty(), "{sources:#?}");

    let summaries = get_summaries(
        &analyzer,
        SummariesParams {
            targets: targets.iter().map(|target| target.to_string()).collect(),
        },
    );
    assert_eq!(targets.len(), summaries.not_found.len(), "{summaries:#?}");
    assert!(summaries.summaries.is_empty(), "{summaries:#?}");
    assert_eq!(
        0,
        analyzer.search_definitions_calls(),
        "explicit missing source paths must not enter fuzzy symbol resolution"
    );
    assert_eq!(
        0,
        analyzer.analyzed_files_calls(),
        "explicit missing source paths must not enumerate files for nonexistent directories"
    );
}

#[test]
fn complete_symbol_index_miss_skips_broad_fuzzy_scan() {
    let root = std::env::current_dir().unwrap();
    let analyzer = CountingAnalyzer::new(root, &["src/Present.java"]);

    let sources = get_symbol_sources(
        &analyzer,
        SymbolLookupParams {
            symbols: vec!["org.example.MissingType".to_string()],
        },
    );

    assert_eq!(1, sources.not_found.len(), "{sources:#?}");
    assert!(sources.sources.is_empty(), "{sources:#?}");
    assert_eq!(
        0,
        analyzer.search_definitions_calls(),
        "a complete index makes a qualified miss conclusive"
    );
}

#[test]
fn missing_extensionless_directory_paths_skip_package_and_fuzzy_resolution() {
    let root = std::env::current_dir().unwrap();
    let analyzer = CountingAnalyzer::new(root, &["src/Present.java"]);
    let summaries = get_summaries(
        &analyzer,
        SummariesParams {
            targets: vec!["pkg/admission/plugin/webhook".to_string()],
        },
    );

    assert_eq!(1, summaries.not_found.len(), "{summaries:#?}");
    assert!(summaries.summaries.is_empty(), "{summaries:#?}");
    assert_eq!(
        0,
        analyzer.search_definitions_calls(),
        "missing relative directory paths must not enter fuzzy symbol resolution"
    );
    assert_eq!(
        0,
        analyzer.analyzed_files_calls(),
        "missing relative directory paths must not enumerate analyzed files"
    );
}

/// A glob resolves against the workspace listing and validates only what it
/// matched. It must never enumerate the analyzed set, which on a large
/// workspace is a live-filesystem scan plus a whole-workspace store query per
/// language, per request (#1738).
#[test]
fn glob_file_pattern_validates_only_matched_files() {
    let root = std::env::current_dir().unwrap();
    let mut workspace: Vec<_> = (0..200)
        .map(|index| format!("wide/W{index:03}.java"))
        .collect();
    workspace.push("nested/B.java".to_string());
    workspace.push("notes.txt".to_string());
    let rel_path_refs: Vec<_> = workspace.iter().map(String::as_str).collect();
    let analyzer = CountingAnalyzer::new(root, &rel_path_refs);

    let files = resolve_file_patterns(&analyzer, &["nested/*.java".to_string()], None);

    assert_eq!(vec!["nested/B.java"], rel_paths(&files.files));
    assert!(files.ambiguous_paths.is_empty());
    assert_eq!(
        0,
        analyzer.analyzed_files_calls(),
        "a glob must not enumerate the analyzed universe"
    );
    assert_eq!(
        1,
        analyzer.retain_analyzed_candidates(),
        "only the matched file may be validated, not the 202-file workspace"
    );
}

/// The listing is a superset of the analyzed set, so validation is what keeps a
/// listed-but-unindexed file out of a glob result. Without it a `.java` file the
/// store never parsed would come back as a summary built from a raw excerpt.
#[test]
fn glob_target_excludes_listed_but_unanalyzed_file() {
    let root = std::env::current_dir().unwrap();
    let analyzer =
        CountingAnalyzer::new(root, &["nested/B.java"]).with_unanalyzed(&["nested/Ghost.java"]);

    let files = resolve_file_patterns(&analyzer, &["nested/*.java".to_string()], None);

    assert_eq!(vec!["nested/B.java"], rel_paths(&files.files));
    assert_eq!(
        2,
        analyzer.retain_analyzed_candidates(),
        "both listed files are candidates; validation is what rejects one"
    );
}

/// The fan-out cap decides on the match count alone. A target the tool is going
/// to skip must not first be validated file by file: that is what made a 1.3 KB
/// `too_broad` reply cost 248 s on the Firefox tree (#1738).
#[test]
fn too_broad_glob_reports_before_validating_any_file() {
    let root = std::env::current_dir().unwrap();
    let workspace: Vec<_> = (0..25)
        .map(|index| format!("src/File{index:02}.java"))
        .collect();
    let rel_path_refs: Vec<_> = workspace.iter().map(String::as_str).collect();
    let analyzer = CountingAnalyzer::new(root, &rel_path_refs);

    let targets = route_summary_targets(&analyzer, &["src/*.java".to_string()]);

    assert_eq!(1, targets.too_broad.len(), "{targets:#?}");
    let too_broad = &targets.too_broad[0];
    assert_eq!("src/*.java", too_broad.target);
    assert_eq!(25, too_broad.matched);
    assert_eq!(
        crate::searchtools::GET_SUMMARIES_MAX_FILES_PER_TARGET,
        too_broad.cap
    );
    assert_eq!(
        vec![
            "src/File00.java",
            "src/File01.java",
            "src/File02.java",
            "src/File03.java",
            "src/File04.java",
            "src/File05.java",
            "src/File06.java",
            "src/File07.java",
            "src/File08.java",
            "src/File09.java",
        ],
        too_broad.sample
    );
    assert!(targets.file_targets.is_empty(), "{targets:#?}");
    assert_eq!(
        0,
        analyzer.retain_analyzed_calls(),
        "a rejected target must cost the match count and nothing else"
    );
    assert_eq!(0, analyzer.analyzed_files_calls());
}

#[test]
fn no_graph_seed_hint_uses_reference_arguments_for_symbol_queries() {
    let anchored = usage_failure_hint(
        ScanUsagesSurface::Reference,
        "no_graph_seed",
        None,
        true,
        false,
    )
    .unwrap();
    assert!(
        !anchored.contains("`targets`") && !anchored.contains("`symbols`"),
        "anchored query must not suggest another selector re-call: {anchored}"
    );

    let unanchored = usage_failure_hint(
        ScanUsagesSurface::Reference,
        "no_graph_seed",
        None,
        false,
        false,
    )
    .unwrap();
    assert!(
        unanchored.contains("scan_usages_by_reference")
            && unanchored.contains("symbol")
            && !unanchored.contains("`targets`"),
        "unanchored reference query should suggest a symbolic retry: {unanchored}"
    );
}

#[test]
fn function_like_macro_guidance_escapes_identifier_for_query_code() {
    let query = function_like_macro_query(Language::Cpp, r"\U000003B1");
    let value: serde_json::Value = serde_json::from_str(&query).expect("valid query_code JSON");
    assert_eq!(r"\U000003B1", value["match"]["callee"]["name"]);
}

fn scan_usage_request(symbol: &str) -> ScanUsageRequest {
    ScanUsageRequest::symbol(0, symbol.to_string())
}

fn usage_row(path: &str, line: usize) -> UsageHitRow {
    UsageHitRow {
        path: path.to_string(),
        line,
        column: Some(1),
        end_line: Some(line),
        end_column: Some(2),
        start_offset: line.saturating_sub(1),
        end_offset: line,
        enclosing: "Caller.run".to_string(),
        kind: UsageHitKind::Reference,
        reason_kind: None,
        snippet: "target();".to_string(),
        confidence: 1.0,
    }
}

fn usage_work_entry(
    symbol: &str,
    proven: Vec<UsageHitRow>,
    unproven_hits: usize,
    unproven_rows: Vec<UsageHitRow>,
    candidate_files_truncated: bool,
    reference_only_absence_note: Option<String>,
) -> ScanUsagesWorkEntry {
    ScanUsagesWorkEntry::Usage {
        request: scan_usage_request(symbol),
        state: SymbolUsageRenderState::new(
            symbol.to_string(),
            None,
            candidate_files_truncated,
            0,
            proven,
            unproven_hits,
            unproven_rows,
            None,
            reference_only_absence_note,
            Vec::new(),
            false,
        ),
        candidate_files_sample: Some(ScanUsagesCandidateFilesSample {
            scanned: vec!["scanned.rs".to_string()],
            omitted: vec!["omitted.rs".to_string()],
            omitted_count: 1,
        }),
        target_is_method: false,
        incomplete_reason: candidate_files_truncated
            .then_some(ScanUsagesIncompleteReason::CandidateFiles),
    }
}

#[test]
fn scan_usages_classification_matrix_keeps_status_and_completeness_separate() {
    let found_full = classify_scan_usages_entry(&usage_work_entry(
        "target",
        vec![usage_row("caller.rs", 1)],
        0,
        Vec::new(),
        false,
        None,
    ));
    assert_eq!(ScanUsagesStatus::Found, found_full.status);
    assert!(found_full.complete);

    let found_truncated = classify_scan_usages_entry(&usage_work_entry(
        "target",
        vec![usage_row("caller.rs", 1)],
        0,
        Vec::new(),
        true,
        None,
    ));
    assert_eq!(ScanUsagesStatus::Found, found_truncated.status);
    assert!(!found_truncated.complete);
    assert_eq!(
        Some(ScanUsagesIncompleteReason::CandidateFiles),
        found_truncated.incomplete_reason
    );
    assert!(found_truncated.absence_caveats.is_empty());
    assert!(found_truncated.candidate_files_sample.is_some());

    let found_with_unproven = classify_scan_usages_entry(&usage_work_entry(
        "target",
        vec![usage_row("caller.rs", 1)],
        1,
        vec![usage_row("maybe.rs", 2)],
        false,
        None,
    ));
    assert_eq!(ScanUsagesStatus::Found, found_with_unproven.status);
    assert!(found_with_unproven.complete);
    assert!(found_with_unproven.absence_caveats.is_empty());

    let found_lines_entry = usage_work_entry(
        "target",
        (0..11)
            .map(|line| usage_row("caller.rs", line + 1))
            .collect(),
        0,
        Vec::new(),
        false,
        None,
    );
    let ScanUsagesWorkEntry::Usage { state, .. } = &found_lines_entry else {
        panic!("expected usage entry");
    };
    let rendered_lines = render_symbol_usages(state);
    assert_eq!(11, rendered_lines.files[0].hits.len());
    assert!(
        rendered_lines.files[0]
            .hits
            .iter()
            .all(|hit| hit.column.is_some()
                && hit.end_line.is_some()
                && hit.end_column.is_some()
                && hit.snippet.is_none())
    );
    let found_lines = classify_scan_usages_entry(&found_lines_entry);
    assert_eq!(ScanUsagesStatus::Found, found_lines.status);
    assert_eq!(Some(UsageRendering::Lines), found_lines.rendering);
    assert!(found_lines.complete);
    assert!(
        !crate::searchtools::scan_usages::build_scan_usages_summary(std::slice::from_ref(
            &found_lines
        ))
        .partial
    );

    let verified_absent = classify_scan_usages_entry(&usage_work_entry(
        "target",
        Vec::new(),
        0,
        Vec::new(),
        false,
        None,
    ));
    assert_eq!(ScanUsagesStatus::VerifiedAbsent, verified_absent.status);
    assert!(verified_absent.complete);

    let unproven_absent = classify_scan_usages_entry(&usage_work_entry(
        "target",
        Vec::new(),
        1,
        vec![usage_row("caller.rs", 2)],
        false,
        None,
    ));
    assert_eq!(ScanUsagesStatus::UnverifiedAbsent, unproven_absent.status);
    assert!(unproven_absent.complete);
    assert!(
        unproven_absent
            .absence_caveats
            .contains(&ScanUsagesAbsenceCaveat::UnprovenMatches)
    );

    let truncated_absent = classify_scan_usages_entry(&usage_work_entry(
        "target",
        Vec::new(),
        0,
        Vec::new(),
        true,
        None,
    ));
    assert_eq!(ScanUsagesStatus::UnverifiedAbsent, truncated_absent.status);
    assert!(!truncated_absent.complete);
    assert_eq!(
        Some(ScanUsagesIncompleteReason::CandidateFiles),
        truncated_absent.incomplete_reason
    );
    assert!(
        truncated_absent
            .absence_caveats
            .contains(&ScanUsagesAbsenceCaveat::CandidateFilesTruncated)
    );
    assert!(truncated_absent.candidate_files_sample.is_some());

    let sibling_absent = classify_scan_usages_entry(&usage_work_entry(
        "target",
        Vec::new(),
        0,
        Vec::new(),
        false,
        Some("workspace contains .razor files; absence not verified".to_string()),
    ));
    assert_eq!(ScanUsagesStatus::UnverifiedAbsent, sibling_absent.status);
    assert!(sibling_absent.complete);
    assert!(
        sibling_absent
            .absence_caveats
            .contains(&ScanUsagesAbsenceCaveat::ReferenceOnlySiblings)
    );

    let unproven_sibling_absent = classify_scan_usages_entry(&usage_work_entry(
        "target",
        Vec::new(),
        1,
        vec![usage_row("maybe.rs", 2)],
        false,
        Some("workspace contains .razor files; absence not verified".to_string()),
    ));
    assert_eq!(
        ScanUsagesStatus::UnverifiedAbsent,
        unproven_sibling_absent.status
    );
    assert!(unproven_sibling_absent.complete);
    assert!(
        unproven_sibling_absent
            .absence_caveats
            .contains(&ScanUsagesAbsenceCaveat::UnprovenMatches)
    );
    assert!(
        unproven_sibling_absent
            .absence_caveats
            .contains(&ScanUsagesAbsenceCaveat::ReferenceOnlySiblings)
    );

    let truncated_sibling_absent = classify_scan_usages_entry(&usage_work_entry(
        "target",
        Vec::new(),
        0,
        Vec::new(),
        true,
        Some("workspace contains .razor files; absence not verified".to_string()),
    ));
    assert_eq!(
        ScanUsagesStatus::UnverifiedAbsent,
        truncated_sibling_absent.status
    );
    assert!(!truncated_sibling_absent.complete);
    assert!(
        truncated_sibling_absent
            .absence_caveats
            .contains(&ScanUsagesAbsenceCaveat::CandidateFilesTruncated)
    );
    assert!(
        truncated_sibling_absent
            .absence_caveats
            .contains(&ScanUsagesAbsenceCaveat::ReferenceOnlySiblings)
    );
}

#[test]
fn scan_usages_classifies_callsite_cap_and_graph_failure_rows() {
    let too_many = classify_scan_usages_entry(&ScanUsagesWorkEntry::TooManyCallsites {
        request: scan_usage_request("target"),
        state: SymbolUsageRenderState::partial_summary(
            "target".to_string(),
            None,
            1001,
            false,
            0,
            vec![usage_row("caller.rs", 1)],
            0,
            Vec::new(),
            None,
            None,
            Vec::new(),
            false,
        ),
        short_name: "target".to_string(),
        total_callsites: 1001,
        limit: 1000,
        target_is_method: false,
    });
    assert_eq!(ScanUsagesStatus::TooManyCallsites, too_many.status);
    assert!(!too_many.complete);
    assert_eq!(
        Some(ScanUsagesIncompleteReason::Callsites),
        too_many.incomplete_reason
    );
    assert_eq!(Some(1001), too_many.total_callsites);

    let failure = classify_scan_usages_entry(&ScanUsagesWorkEntry::Failure {
        request: scan_usage_request("target"),
        failure: UsageFailureInfo {
            symbol: "target".to_string(),
            fq_name: "target".to_string(),
            reason_kind: "no_graph_seed".to_string(),
            reason: "no graph seed".to_string(),
            candidate_files_truncated: true,
            candidate_files_sample: None,
            hint: None,
        },
        incomplete_reason: Some(ScanUsagesIncompleteReason::CandidateFiles),
    });
    assert_eq!(ScanUsagesStatus::Failure, failure.status);
    assert!(!failure.complete);
    assert_eq!(Some("no_graph_seed"), failure.reason_kind.as_deref());
}

#[brokk_bifrost_test_macros::hardwon(
    "#1228: Uses a zero source-byte budget on a real Rust location scan and ensures an unscanned target is partial, not verified absent"
)]
#[test]
fn issue_1228_source_budget_never_reports_verified_absence() {
    use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

    use brokk_bifrost_core::analyzer::project::TestProject;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "lib.rs")
        .write("pub fn target() {}\npub fn caller() { target(); }\n")
        .unwrap();
    let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
    let context = ScanUsagesExecutionContext::with_limits(
        brokk_bifrost_core::cancellation::CancellationToken::default(),
        1_000,
        10_000,
        0,
        1_000,
    );

    let scope = AnalyzerQueryScope::new(&analyzer);
    let token = scope.token();
    let result = scan_usages_by_location_with_context(
        &analyzer,
        token,
        ScanUsagesByLocationParams {
            targets: vec![ScanUsagesTarget {
                path: "lib.rs".to_string(),
                line: 1,
                column: None,
                symbol: None,
            }],
            include_tests: true,
            paths: None,
            include_same_owner: true,
        },
        &context,
    );

    assert!(result.summary.partial, "{result:#?}");
    assert_eq!(result.summary.verified_absent, 0, "{result:#?}");
    assert_eq!(result.results.len(), 1, "{result:#?}");
    assert!(!result.results[0].complete, "{result:#?}");
    assert_eq!(
        result.results[0].incomplete_reason,
        Some(ScanUsagesIncompleteReason::SourceBytes),
        "{result:#?}"
    );
    assert_ne!(
        result.results[0].status,
        ScanUsagesStatus::VerifiedAbsent,
        "{result:#?}"
    );
}

#[brokk_bifrost_test_macros::hardwon(
    "#3041: Exercises C label lookup with zero source budget and a one-callsite cap, verifying the distinct failure and TooManyCallsites outcomes"
)]
#[test]
fn issue_3041_c_label_usage_respects_source_and_callsite_budgets() {
    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    let source = "void f(void) { goto end; goto end; end: return; }\n";
    let fixture = AnalyzerFixture::new_for_language(Language::Cpp, &[("labels.c", source)]);
    let label_column = source.rfind("end:").expect("label") + 1;
    let params = || ScanUsagesByLocationParams {
        targets: vec![ScanUsagesTarget {
            path: "labels.c".to_string(),
            line: 1,
            column: Some(label_column),
            symbol: None,
        }],
        include_tests: true,
        paths: None,
        include_same_owner: true,
    };

    let source_budget = ScanUsagesExecutionContext::with_limits(
        brokk_bifrost_core::cancellation::CancellationToken::default(),
        1_000,
        10_000,
        0,
        1_000,
    );
    let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
    let result = scan_usages_by_location_with_context(
        fixture.analyzer.analyzer(),
        scope.token(),
        params(),
        &source_budget,
    );
    assert!(result.summary.partial, "{result:#?}");
    assert_eq!(result.results[0].status, ScanUsagesStatus::Failure);
    assert_eq!(
        result.results[0].incomplete_reason,
        Some(ScanUsagesIncompleteReason::SourceBytes),
        "{result:#?}"
    );
    drop(scope);

    let callsite_budget = ScanUsagesExecutionContext::with_limits(
        brokk_bifrost_core::cancellation::CancellationToken::default(),
        1_000,
        10_000,
        usize::MAX,
        1,
    );
    let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
    let result = scan_usages_by_location_with_context(
        fixture.analyzer.analyzer(),
        scope.token(),
        params(),
        &callsite_budget,
    );
    assert!(result.summary.partial, "{result:#?}");
    assert_eq!(
        result.results[0].status,
        ScanUsagesStatus::TooManyCallsites,
        "{result:#?}"
    );
    assert_eq!(result.results[0].total_callsites, Some(2));
    assert_eq!(result.results[0].limit, Some(1));
}

#[brokk_bifrost_test_macros::hardwon(
    "#1228: Uses a zero wall-clock budget on a Rust scan and checks explicit time-budget diagnostics and serialized reason without claiming absence"
)]
#[test]
fn issue_1228_time_budget_is_explicit_and_never_reports_verified_absence() {
    use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

    use brokk_bifrost_core::analyzer::project::TestProject;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "lib.rs")
        .write("pub fn target() {}\npub fn caller() { target(); }\n")
        .unwrap();
    let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
    let context = ScanUsagesExecutionContext::with_limits(
        brokk_bifrost_core::cancellation::CancellationToken::default().with_timeout(Duration::ZERO),
        1_000,
        10_000,
        usize::MAX,
        1_000,
    );

    let scope = AnalyzerQueryScope::new(&analyzer);
    let token = scope.token();
    let result = scan_usages_by_location_with_context(
        &analyzer,
        token,
        ScanUsagesByLocationParams {
            targets: vec![ScanUsagesTarget {
                path: "lib.rs".to_string(),
                line: 1,
                column: None,
                symbol: None,
            }],
            include_tests: true,
            paths: None,
            include_same_owner: true,
        },
        &context,
    );

    assert!(result.summary.partial, "{result:#?}");
    assert_eq!(result.summary.verified_absent, 0, "{result:#?}");
    assert_eq!(result.results.len(), 1, "{result:#?}");
    assert!(!result.results[0].complete, "{result:#?}");
    assert_eq!(
        result.results[0].incomplete_reason,
        Some(ScanUsagesIncompleteReason::TimeBudget),
        "{result:#?}"
    );
    assert_eq!(
        result.results[0].reason_kind.as_deref(),
        Some("time_budget"),
        "{result:#?}"
    );
    assert_ne!(
        result.results[0].status,
        ScanUsagesStatus::VerifiedAbsent,
        "{result:#?}"
    );
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["results"][0]["incomplete_reason"], "time_budget");
    assert_eq!(json["results"][0]["reason_kind"], "time_budget");
}

#[test]
fn issue_1228_symbol_lookup_batches_have_count_and_byte_limits() {
    let too_many = serde_json::json!({
        "symbols": vec!["symbol"; super::SYMBOL_LOOKUP_MAX_SYMBOLS + 1]
    });
    let error = serde_json::from_value::<SymbolLookupParams>(too_many)
        .expect_err("oversized symbol batch must be rejected");
    assert!(error.to_string().contains("at most"), "{error}");

    let oversized_symbol = serde_json::json!({
        "symbols": ["x".repeat(super::SYMBOL_LOOKUP_MAX_SYMBOL_BYTES + 1)]
    });
    let error = serde_json::from_value::<SymbolLookupParams>(oversized_symbol)
        .expect_err("oversized symbol selector must be rejected");
    assert!(error.to_string().contains("each symbol"), "{error}");
}

#[brokk_bifrost_test_macros::hardwon(
    "#1228: Runs location navigation through Rust resolution with a controlled cancellation point and verifies cancellation reaches the result diagnostics"
)]
#[test]
fn issue_1228_navigation_cancellation_reaches_rust_resolution() {
    use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

    use brokk_bifrost_core::analyzer::project::TestProject;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "lib.rs")
        .write("pub fn target() {}\npub fn caller() { target(); }\n")
        .unwrap();
    let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
    let cancellation =
        brokk_bifrost_core::cancellation::CancellationToken::cancel_after_checks_for_test(5);

    let result = crate::searchtools::navigation::get_definitions_by_location_with_cancellation(
        &analyzer,
        crate::searchtools::navigation::GetDefinitionParams {
            references: vec![crate::searchtools::navigation::DefinitionReferenceQuery {
                path: "lib.rs".to_string(),
                line: Some(2),
                column: Some(19),
            }],
        },
        Some(&cancellation),
    );

    assert!(cancellation.is_cancelled());
    assert_eq!(result.results.len(), 1, "{result:#?}");
    assert!(
        result.results[0]
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "cancelled"),
        "{result:#?}"
    );
}

#[test]
fn terminal_navigation_status_cannot_be_resolved_by_semantic_overlay() {
    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCoordinate;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::CompilerOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelActivationControl;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelActivationEvidence;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelActivationRequest;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelControlAction;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelControlScope;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelPackSelector;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelRuntimeLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelRuntimeOutcome;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SessionPackSource;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SessionPackSourceKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::source::SourceFormat;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::acquire_active_semantic_models;

    use brokk_bifrost_analysis::analyzer::semantic_model::compiler::compile_source;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::NavigationLookupOutcome;

    use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    use brokk_bifrost_analysis::navigation::NavigationOperation;

    let fixture = brokk_bifrost_analysis::test_support::AnalyzerFixture::new_for_language(
        Language::Go,
        &[
            ("go.mod", "module example.com/app\n"),
            ("main.go", "package main\n\nfunc main() {}\n"),
        ],
    );
    let source = serde_json::to_vec(&serde_json::json!({
        "schema_version": 2,
        "pack_id": "fixture.navigation-terminal-rendering",
        "version": "1.0.0",
        "producer": { "name": "navigation-test", "version": "1.0.0" },
        "language": "go",
        "ecosystem": "go-module",
        "compatibility": { "bifrost": "*", "toolchains": [] },
        "provenance": { "source": "fixture" },
        "license": "NOASSERTION",
        "completeness": "complete",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "declarations.fixture.navigation-terminal-rendering",
            "activation": [{ "module": { "name": "example.com/mod" } }],
            "payload": {
                "kind": "declaration_facts",
                "types": [{
                    "id": "type.fixture.navigation-terminal-rendering",
                    "name": "example.com/mod.External",
                    "type_kind": "struct",
                    "visibility": "public",
                    "locator": {
                        "kind": "artifact",
                        "path": "api.go",
                        "symbol": "example.com/mod.External"
                    }
                }],
                "members": [],
                "relations": []
            }
        }]
    }))
    .expect("serialize semantic-model fixture");
    let pack = compile_source(SourceFormat::Json, &source, &CompilerOptions::default())
        .unwrap_or_else(|diagnostics| {
            panic!("semantic-model fixture must compile: {diagnostics:#?}")
        });
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .expect("open semantic-pack catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "fixture.navigation-terminal-rendering".to_owned(),
            },
        )
        .expect("register semantic-model fixture");
    let request = SemanticModelActivationRequest {
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
            .expect("crate version parses"),
        evidence: vec![SemanticModelActivationEvidence {
            language: "go".to_owned(),
            ecosystem: "go-module".to_owned(),
            package: None,
            module: Some(CatalogCoordinate {
                name: "example.com/mod".to_owned(),
                version: None,
            }),
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
        }],
        controls: vec![SemanticModelActivationControl {
            scope: SemanticModelControlScope::Workspace,
            action: SemanticModelControlAction::Enable,
            selector: SemanticModelPackSelector {
                pack_id: "fixture.navigation-terminal-rendering".to_owned(),
                version: None,
                manifest_digest: None,
            },
        }],
        limits: SemanticModelRuntimeLimits::default(),
    };
    let SemanticModelRuntimeOutcome::Ready { .. } = acquire_active_semantic_models(
        fixture.analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &brokk_bifrost_core::cancellation::CancellationToken::new(),
    ) else {
        panic!("semantic-model fixture must activate");
    };
    assert!(
        fixture
            .analyzer
            .analyzer()
            .semantic_model_overlay()
            .is_some()
    );

    let file = ProjectFile::new(fixture.project_root(), "main.go");
    let outcome = NavigationLookupOutcome {
        modeled_definitions: Vec::new(),
        evidence: Default::default(),
        status: DefinitionLookupStatus::Cancelled,
        reference: Some(ResolvedReferenceSite {
            path: "main.go".to_owned(),
            text: "example.com/mod.External".to_owned(),
            range: Range {
                start_byte: 0,
                end_byte: 1,
                start_line: 0,
                end_line: 0,
            },
            focus_start_byte: 0,
            focus_end_byte: 1,
        }),
        targets: Vec::new(),
        lexical_definition: None,
        diagnostics: Vec::new(),
        structure_unavailable: false,
        unproven_link_unit: false,
        truncated: false,
    };
    let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
    let mut render_cache = DefinitionCandidateRenderCache::default();
    let result = crate::searchtools::navigation::render_definition_lookup(
        fixture.analyzer.analyzer(),
        scope.token(),
        crate::searchtools::navigation::DefinitionReferenceQuery {
            path: "main.go".to_owned(),
            line: None,
            column: None,
        },
        &file,
        outcome,
        NavigationOperation::Definition,
        &mut render_cache,
    );

    assert_eq!(result.status, "cancelled", "{result:#?}");
    assert!(result.definitions.is_empty(), "{result:#?}");
    assert!(!result.complete, "{result:#?}");
}

/// A refusal must never read as a proved absence. `complete: true` with no
/// `incomplete_reason` is the shape a consumer reads as "the resolver looked
/// and there is nothing there", so a status that says the resolver produced no
/// answer has to carry a reason even when the diagnostic kind that carried the
/// refusal is outside the public vocabulary.
#[test]
fn a_refusing_definition_status_is_never_reported_as_complete() {
    use crate::searchtools::selectors::DefinitionLookupIncompleteReason;

    let unknown_kind = [crate::searchtools::selectors::DefinitionDiagnostic {
        claim: None,
        kind: "a_resolver_specific_refusal".to_string(),
        message: "the selected caller profile is not supported".to_string(),
    }];
    for (status, expected) in [
        (
            "unavailable",
            DefinitionLookupIncompleteReason::StructureUnavailable,
        ),
        (
            "incomplete",
            DefinitionLookupIncompleteReason::StructureUnavailable,
        ),
        ("cancelled", DefinitionLookupIncompleteReason::Cancelled),
        (
            "exceeded_budget",
            DefinitionLookupIncompleteReason::ResolutionBudget,
        ),
    ] {
        assert_eq!(
            crate::searchtools::definitions::definition_result_completion(status, &unknown_kind),
            (false, Some(expected)),
            "{status}"
        );
    }

    // An answer about the request itself stays complete: the tool did finish.
    for status in ["resolved", "no_definition", "not_found", "invalid_location"] {
        assert_eq!(
            crate::searchtools::definitions::definition_result_completion(status, &[]),
            (true, None),
            "{status}"
        );
    }

    // A diagnostic the vocabulary knows still names the more specific reason.
    let cancelled = [crate::searchtools::selectors::DefinitionDiagnostic {
        claim: None,
        kind: "cancelled".to_string(),
        message: "resolution was cancelled".to_string(),
    }];
    assert_eq!(
        crate::searchtools::definitions::definition_result_completion("unavailable", &cancelled),
        (false, Some(DefinitionLookupIncompleteReason::Cancelled))
    );
}

#[brokk_bifrost_test_macros::hardwon(
    "#1228: Retains the ignored #1228 live Rust navigation witness, which compares uncancelled MCP semantics with direct results across imports, calls, fields, macros, and associated types"
)]
#[test]
#[ignore = "finds real bugs: six of twelve definition queries fail for reasons measured to be independent of the qualified type (removing only the `<Service as Runner>::Output` line and its row reproduces the same six): `no_indexed_definition` for the aliased import, the glob import, the trait-receiver method and the `Service` type annotation, and `incomplete_binding` for `Service::new` and `crate::api::helper`. The projection member `Output` additionally has no declaration at all, because trait and inherent impl associated types are skipped as `UnsupportedMemberScope`. The qualified-type poison itself is fixed: the head lowers as ordinary type references and the member as a qualified reference carrying a type-shaped `UnsupportedTypeSyntax` gap, with no `MalformedSyntax` recorded for valid syntax. Measured 2026-09-12 on lane B R2.B Rust reference lowering"]
fn issue_1228_uncancelled_mcp_rust_navigation_matches_direct_semantics() {
    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    fn query_at(
        source: &str,
        path: &str,
        snippet: &str,
        focus: &str,
    ) -> crate::searchtools::navigation::DefinitionReferenceQuery {
        let snippet_start = source
            .find(snippet)
            .unwrap_or_else(|| panic!("missing `{snippet}`"));
        let focus_start = snippet
            .find(focus)
            .unwrap_or_else(|| panic!("missing `{focus}` in `{snippet}`"));
        let byte = snippet_start + focus_start;
        let line_start = source[..byte].rfind('\n').map_or(0, |newline| newline + 1);
        crate::searchtools::navigation::DefinitionReferenceQuery {
            path: path.to_string(),
            line: Some(
                source[..byte]
                    .bytes()
                    .filter(|value| *value == b'\n')
                    .count()
                    + 1,
            ),
            column: Some(byte - line_start + 1),
        }
    }

    let main = r#"
use crate::api::{helper as aliased_helper, Runner, Service};
use crate::prelude::*;

macro_rules! local_macro {
    () => {};
}

fn same_file() {}

struct Local {
    field: i32,
}

impl Local {
    fn associated() {}

    fn exercise(&self) {
        Self::associated();
        let _ = self.field;
    }
}

fn caller(service: Service, local: Local) {
    same_file();
    aliased_helper();
    globbed();
    Service::new();
    service.run();
    let _: Service = Service::new();
    crate::api::helper();
    let _ = local.field;
    local_macro!();
    let shadowed = 1;
    let _ = shadowed;
}

type ResultType = <Service as Runner>::Output;
"#;
    let fixture = AnalyzerFixture::new_for_language(
        Language::Rust,
        &[
            (
                "src/lib.rs",
                "pub mod api;\npub mod prelude;\npub mod main;\n",
            ),
            (
                "src/api.rs",
                r#"
pub trait Runner {
    type Output;
    fn run(&self);
}

pub struct Service {
    pub value: i32,
}

impl Runner for Service {
    type Output = i32;
    fn run(&self) {}
}

impl Service {
    pub fn new() -> Self {
        Self { value: 0 }
    }
}

pub fn helper( token: QueryToken<'_>) {}
"#,
            ),
            ("src/prelude.rs", "pub fn globbed() {}\n"),
            ("src/main.rs", main),
        ],
    );
    let analyzer = fixture.analyzer.analyzer();
    let references = vec![
        (
            "same-file call",
            query_at(main, "src/main.rs", "same_file();", "same_file"),
            "resolved",
            None::<&str>,
        ),
        (
            "aliased import",
            query_at(main, "src/main.rs", "aliased_helper();", "aliased_helper"),
            "resolved",
            None,
        ),
        // `use crate::prelude::*;` reaching `pub fn globbed` in the
        // `pub mod prelude;` submodule. This expected `no_definition` while
        // `is_module_export_candidate` dropped every submodule free function
        // from the export index, so glob expansion had no name to find; #1341
        // restored the candidate and it now resolves to prelude.globbed.
        (
            "glob import",
            query_at(main, "src/main.rs", "globbed();", "globbed"),
            "resolved",
            None,
        ),
        (
            "scoped constructor",
            query_at(main, "src/main.rs", "Service::new();", "new"),
            "resolved",
            None,
        ),
        (
            "trait receiver method",
            query_at(main, "src/main.rs", "service.run();", "run"),
            "resolved",
            None,
        ),
        (
            "type reference",
            query_at(
                main,
                "src/main.rs",
                "let _: Service = Service::new();",
                "Service",
            ),
            "resolved",
            None,
        ),
        (
            "crate scoped call",
            query_at(main, "src/main.rs", "crate::api::helper();", "helper"),
            "resolved",
            None,
        ),
        (
            "field",
            query_at(main, "src/main.rs", "let _ = local.field;", "field"),
            "resolved",
            None,
        ),
        (
            "Self associated call",
            query_at(main, "src/main.rs", "Self::associated();", "associated"),
            "resolved",
            None,
        ),
        (
            "macro",
            query_at(main, "src/main.rs", "local_macro!();", "local_macro"),
            "resolved",
            None,
        ),
        // A shadowed read resolves lexically to the `let` binder (#1569), so
        // it reports a resolved local-variable candidate rather than a
        // `local_binding` diagnostic.
        (
            "local binding",
            query_at(main, "src/main.rs", "let _ = shadowed;", "shadowed"),
            "resolved",
            None,
        ),
        (
            "associated type",
            query_at(main, "src/main.rs", "<Service as Runner>::Output", "Output"),
            "resolved",
            None,
        ),
    ];
    let params = crate::searchtools::navigation::GetDefinitionParams {
        references: references
            .iter()
            .map(|(_, query, _, _)| query.clone())
            .collect(),
    };
    let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();

    let direct_definitions =
        crate::searchtools::navigation::get_definitions_by_location(analyzer, params.clone());
    let cancellable_definitions =
        crate::searchtools::navigation::get_definitions_by_location_with_cancellation(
            analyzer,
            params.clone(),
            Some(&cancellation),
        );
    assert_eq!(
        serde_json::to_value(&direct_definitions).unwrap(),
        serde_json::to_value(&cancellable_definitions).unwrap(),
        "an uncancelled MCP token must not select reduced Rust definition semantics"
    );

    let direct_declarations =
        crate::searchtools::navigation::get_declarations_by_location(analyzer, params.clone());
    let cancellable_declarations =
        crate::searchtools::navigation::get_declarations_by_location_with_cancellation(
            analyzer,
            params,
            Some(&cancellation),
        );
    assert_eq!(
        serde_json::to_value(&direct_declarations).unwrap(),
        serde_json::to_value(&cancellable_declarations).unwrap(),
        "an uncancelled MCP token must not select reduced Rust declaration semantics"
    );

    let mut expectation_failures = Vec::new();
    for ((label, _, expected_status, expected_diagnostic), result) in
        references.iter().zip(&direct_definitions.results)
    {
        if result.status != *expected_status {
            expectation_failures.push(format!(
                "{label}: expected status {expected_status}, got {}",
                result.status
            ));
        }
        if *expected_status == "resolved" && result.definitions.is_empty() {
            expectation_failures.push(format!("{label}: resolved without a definition"));
        }
        if let Some(expected_diagnostic) = expected_diagnostic
            && !result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == *expected_diagnostic)
        {
            expectation_failures.push(format!("{label}: missing diagnostic {expected_diagnostic}"));
        }
    }
    assert!(
        expectation_failures.is_empty(),
        "{}\n{direct_definitions:#?}",
        expectation_failures.join("\n")
    );
    assert!(!cancellation.is_cancelled());
}

/// `count` distinct class declarations in one file, all reported by
/// `CountingAnalyzer::search_definitions` regardless of the pattern, so a test
/// controls the candidate count exactly.
fn widget_declarations(root: &Path, count: usize) -> Vec<CodeUnit> {
    let file = ProjectFile::new(root.to_path_buf(), "src/Widget.java");
    (0..count)
        .map(|index| {
            CodeUnit::new(
                file.clone(),
                CodeUnitType::Class,
                "app",
                format!("Widget{index}"),
            )
        })
        .collect()
}

fn widget_search_params(limit: usize) -> SearchSymbolsParams {
    SearchSymbolsParams {
        patterns: vec!["Widget".to_string()],
        include_tests: false,
        limit,
    }
}

#[test]
fn search_symbols_over_candidate_cap_skips_ranking_and_reports_the_totals() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let analyzer = CountingAnalyzer::new(root.clone(), &["src/Widget.java"])
        .with_search_definitions(widget_declarations(&root, 5));

    let result = search_symbols_with_cap(&analyzer, widget_search_params(100), 3, None);

    let too_many = result
        .too_many_matches
        .as_ref()
        .expect("five candidates over a cap of three must report the overload");
    assert_eq!(5, too_many.total_candidates);
    assert_eq!(3, too_many.cap);
    assert!(result.truncated);
    assert!(result.files.is_empty(), "{:?}", result.files);
    assert_eq!(0, result.total_files);

    let rendered = result.render_text(RenderOptions::default());
    assert!(rendered.contains('5'), "{rendered}");
    assert!(rendered.contains('3'), "{rendered}");
    assert!(rendered.contains("Widget"), "{rendered}");
    assert!(rendered.contains("more specific"), "{rendered}");
}

#[test]
fn search_symbols_under_candidate_cap_ranks_and_reports_files_as_before() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let analyzer = CountingAnalyzer::new(root.clone(), &["src/Widget.java"])
        .with_search_definitions(widget_declarations(&root, 5));

    let result = search_symbols_with_cap(&analyzer, widget_search_params(100), 10, None);

    assert!(result.too_many_matches.is_none());
    assert_eq!(1, result.total_files);
    assert_eq!(1, result.files.len(), "{:?}", result.files);
    assert_eq!(5, result.files[0].classes.len(), "{:?}", result.files[0]);
}

/// #3279: the issue's discovery request spelled its patterns as globs
/// (`*Capability*`, `*Language*`, ...), which are invalid regex -- a leading
/// repetition operator has nothing to repeat -- and compile dropped them
/// silently, so search_symbols answered "No files matched" on a workspace
/// full of matching symbols. The declarations here go through the real
/// store-backed candidate path, so the glob interpretation and its
/// required-literal prefilter are both exercised.
#[brokk_bifrost_test_macros::hardwon(
    "#3279: Fix regression #3279: leading-wildcard patterns are parsed as globs, return matching store-backed declarations, and do not become invalid regexes"
)]
#[test]
fn search_symbols_matches_leading_wildcard_patterns_as_globs() {
    use brokk_bifrost_analysis::analyzer::java::JavaAnalyzer;

    use brokk_bifrost_core::analyzer::project::TestProject;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), std::path::PathBuf::from("Capability.java"))
        .write(
            "public class LanguageRegistry {}\n\
             public class PolicyDefinition {}\n\
             public class Unrelated {}\n",
        )
        .unwrap();
    let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));

    let result = search_symbols_with_cancellation(
        &analyzer,
        SearchSymbolsParams {
            patterns: vec![
                "*Capability*".to_string(),
                "*Language*".to_string(),
                "*PolicyDefinition*".to_string(),
                "*Query*Domain*".to_string(),
            ],
            include_tests: true,
            limit: 100,
        },
        None,
    );

    assert!(
        result.invalid_patterns.is_empty(),
        "{:?}",
        result.invalid_patterns
    );
    assert!(result.too_many_matches.is_none());
    assert_eq!(1, result.total_files, "{result:?}");
    let classes = &result.files[0].classes;
    assert_eq!(2, classes.len(), "{classes:?}");
    let names: Vec<&str> = classes.iter().map(|hit| hit.symbol.as_str()).collect();
    assert!(
        names.iter().any(|name| name.contains("LanguageRegistry")),
        "{names:?}"
    );
    assert!(
        names.iter().any(|name| name.contains("PolicyDefinition")),
        "{names:?}"
    );
}

/// A pattern that is neither regex nor glob is a malformed request, and the
/// answer must say so instead of reporting the absence of symbols (#3279).
#[brokk_bifrost_test_macros::hardwon(
    "#3279: Checks a pattern that is neither valid regex nor glob is reported as invalid while another valid pattern still returns symbols"
)]
#[test]
fn search_symbols_reports_uninterpretable_patterns_instead_of_matching_nothing() {
    use brokk_bifrost_analysis::analyzer::java::JavaAnalyzer;

    use brokk_bifrost_core::analyzer::project::TestProject;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), std::path::PathBuf::from("Language.java"))
        .write("public class LanguageRegistry {}\n")
        .unwrap();
    let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));

    let result = search_symbols_with_cancellation(
        &analyzer,
        SearchSymbolsParams {
            patterns: vec!["foo(bar".to_string(), "Language".to_string()],
            include_tests: false,
            limit: 100,
        },
        None,
    );

    assert_eq!(result.invalid_patterns, vec!["foo(bar".to_string()]);
    assert_eq!(1, result.total_files, "{result:?}");
    let note = result
        .note
        .as_deref()
        .expect("the invalid pattern must be said");
    assert!(
        note.contains("could not be interpreted as regex or wildcard"),
        "{note}"
    );
    assert!(note.contains("`foo(bar`"), "{note}");
    let rendered = result.render_text(RenderOptions::default());
    assert!(rendered.contains("could not be interpreted"), "{rendered}");
}

/// #1775: boost's preprocessor limit headers write their preamble as null
/// directives (`# /* Copyright ... */`, bare `#`) and their bodies as spaced
/// directives (`# define BOOST_PP_BOOL_176 1`). Reading every `# ` line as a
/// comment ran the attached-comment walk from any one macro back to line 1, so
/// a one-line macro's `SourceBlock` reported `start_line: 1` and carried the
/// whole preamble as its text.
#[brokk_bifrost_test_macros::hardwon(
    "#1775: Fix regression #1775: C++ preprocessor directives stay outside macro source blocks while an actual null-directive comment remains attached"
)]
#[test]
fn issue_1775_cpp_directive_lines_do_not_join_a_macros_comment_block() {
    use brokk_bifrost_cpp_analysis::analyzer::cpp::CppAnalyzer;

    use brokk_bifrost_core::analyzer::project::TestProject;

    let source = "\
# /* Copyright (C) 2001
#  * Housemarque Oy
#  */
#
# ifndef GUARD_HPP
# define GUARD_HPP
#
# define BOOST_PP_BOOL_0 0
# define BOOST_PP_BOOL_1 1
# define BOOST_PP_BOOL_2 1

# /* Fast path toggle. */
# define BOOST_PP_FAST 1
#
# endif
";
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), std::path::PathBuf::from("bool_limits.hpp"))
        .write(source)
        .unwrap();
    let analyzer = CppAnalyzer::from_project(TestProject::new(root, Language::Cpp));

    let block = |symbol: &str| {
        let result = get_symbol_sources(
            &analyzer,
            SymbolLookupParams {
                symbols: vec![symbol.to_string()],
            },
        );
        assert_eq!(1, result.sources.len(), "{symbol}: {result:#?}");
        result.sources.into_iter().next().unwrap()
    };
    // The block's text must be the file's own content over the lines it
    // reports -- the I1(c) contract the fuzzer checks.
    let lines: Vec<&str> = source.split_inclusive('\n').collect();
    let reported_lines = |block: &crate::searchtools::sources::SourceBlock| -> String {
        lines[block.start_line - 1..block.end_line].concat()
    };

    let bool_2 = block("BOOST_PP_BOOL_2");
    assert_eq!(
        "# define BOOST_PP_BOOL_2 1\n", bool_2.text,
        "a spaced `# define` above the macro is a directive, not its docstring: {bool_2:#?}"
    );
    assert_eq!(10, bool_2.start_line, "{bool_2:#?}");
    assert_eq!(reported_lines(&bool_2), bool_2.text, "{bool_2:#?}");

    // A null directive carrying nothing but comment text is still the macro's
    // attached comment, which is the idiom the preamble itself uses.
    let fast = block("BOOST_PP_FAST");
    assert_eq!(
        "# /* Fast path toggle. */\n# define BOOST_PP_FAST 1\n", fast.text,
        "{fast:#?}"
    );
    assert_eq!(12, fast.start_line, "{fast:#?}");
    assert_eq!(reported_lines(&fast), fast.text, "{fast:#?}");
}

#[test]
fn preferred_definition_stays_within_the_requested_overload_ranges() {
    use brokk_bifrost_analysis::analyzer::languages::DeclarationNavigationOccurrence;

    use brokk_bifrost_analysis::analyzer::languages::DeclarationNavigationRole;
    let other_definition = Range {
        start_byte: 0,
        end_byte: 10,
        start_line: 0,
        end_line: 0,
    };
    let declaration = Range {
        start_byte: 20,
        end_byte: 30,
        start_line: 2,
        end_line: 2,
    };
    let definition = Range {
        start_byte: 40,
        end_byte: 50,
        start_line: 4,
        end_line: 4,
    };
    let occurrences = [
        DeclarationNavigationOccurrence {
            range: other_definition,
            role: DeclarationNavigationRole::Definition,
        },
        DeclarationNavigationOccurrence {
            range: declaration,
            role: DeclarationNavigationRole::Declaration,
        },
        DeclarationNavigationOccurrence {
            range: definition,
            role: DeclarationNavigationRole::Definition,
        },
    ];
    assert_eq!(
        crate::searchtools::primary_range_from_ranges(
            vec![declaration, definition],
            Some(&occurrences)
        ),
        Some(definition)
    );
    assert_eq!(
        crate::searchtools::primary_range_from_ranges(vec![declaration], Some(&occurrences)),
        Some(declaration)
    );
}

/// Cost pin for #2880: a module target's outline must ask the index for the
/// module's own name, not scan and hydrate every declaration in the workspace.
///
/// The behavior the seek has to keep is the multi-file answer. A Java package
/// is declared once per file in it, and the outline lists every defining file,
/// which is why `definitions` cannot answer this: its definition ordering
/// keeps one module per name on purpose.
#[brokk_bifrost_test_macros::hardwon(
    "#2880: Checks a Java package outline lists all three defining files through indexed lookup without hydrating the workspace declaration inventory"
)]
#[test]
fn module_outline_lists_defining_files_without_a_workspace_declaration_scan() {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/main/java/org/example/Alpha.java",
            "package org.example;\nclass Alpha {}\n",
        )
        .file(
            "src/main/java/org/example/Beta.java",
            "package org.example;\nclass Beta {}\n",
        )
        .file(
            "src/main/java/org/example/Gamma.java",
            "package org.example;\nclass Gamma {}\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    analyzer
        .test_hooks()
        .reset_full_declaration_scan_count_for_test();

    let result = get_symbol_sources(
        analyzer,
        SymbolLookupParams {
            symbols: vec!["org.example".to_string()],
        },
    );

    let paths: Vec<&str> = result
        .sources
        .iter()
        .map(|block| block.path.as_str())
        .collect();
    assert_eq!(
        paths,
        vec![
            "src/main/java/org/example/Alpha.java",
            "src/main/java/org/example/Beta.java",
            "src/main/java/org/example/Gamma.java",
        ],
        "{result:#?}"
    );
    assert!(
        result
            .sources
            .iter()
            .all(|block| block.presentation.as_deref() == Some("file_listing")),
        "{result:#?}"
    );
    assert_eq!(
        analyzer.test_hooks().full_declaration_scan_count_for_test(),
        0,
        "the module outline must resolve its defining files by name, not by scanning the workspace"
    );
}
