use super::SearchSymbolsParams;
use super::navigation::search_symbols_with_cap;
use super::scan_usages::render_symbol_usages;
use super::summaries::SummariesParams;
use super::{
    ContainerListingEntry, DefinitionCandidateRenderCache, ScanUsageRequest,
    ScanUsagesAbsenceCaveat, ScanUsagesByLocationParams, ScanUsagesCandidateFilesSample,
    ScanUsagesExecutionContext, ScanUsagesIncompleteReason, ScanUsagesStatus, ScanUsagesSurface,
    ScanUsagesTarget, ScanUsagesWorkEntry, SymbolLookupParams, SymbolSourcesResult,
    SymbolUsageRenderState, UsageFailureInfo, UsageHitKind, UsageHitRow, UsageRendering,
    classify_scan_usages_entry, definition_candidate_from_range, get_summaries, get_symbol_sources,
    list_symbols, resolve_file_patterns, scan_usages_by_location_with_context,
    symbol_source_candidate_files, trim_summary_signature,
};
use super::{function_like_macro_query, route_summary_targets, usage_failure_hint};
use crate::analyzer::{
    CodeUnit, CodeUnitType, DeclarationInfo, IAnalyzer, Language, Project, ProjectFile, Range,
};
use crate::searchtools_render::{RenderOptions, RenderText};
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

use crate::analyzer::CodeUnitIndex;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};

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

    fn indexed_source(&self, _file: &ProjectFile) -> Option<String> {
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

    fn extract_call_receiver(&self, _reference: &str) -> Option<String> {
        None
    }

    fn import_statements_of(&self, _file: &ProjectFile) -> Vec<String> {
        Vec::new()
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
        format!("- {}", super::rel_path_string(file).replace('/', "_"))
    }
}

#[test]
fn trims_synthetic_summary_lines() {
    assert_eq!(trim_summary_signature("class A {\n}\n"), "class A");
    assert_eq!(trim_summary_signature("[...]\n"), "");
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
    let target = crate::analyzer::usages::get_definition::NavigationTarget {
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
        not_found: vec![super::NotFoundInput {
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

#[test]
fn definition_outcome_key_reuses_declaration_context() {
    use crate::analyzer::usages::get_definition::{
        DefinitionLookupOutcome, DefinitionLookupStatus,
    };
    use crate::test_support::AnalyzerFixture;

    let fixture =
        AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", "pub fn target() {}\n")]);
    let analyzer = fixture.analyzer.analyzer();
    let unit = analyzer
        .search_definitions("target", false)
        .into_iter()
        .next()
        .expect("target declaration");
    let outcome = DefinitionLookupOutcome {
        status: DefinitionLookupStatus::Resolved,
        reference: None,
        definitions: vec![unit],
        lexical_definition: None,
        diagnostics: Vec::new(),
    };
    let mut render_cache = DefinitionCandidateRenderCache::default();

    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let first =
        super::definitions::semantic_outcome_key(analyzer, token, &outcome, &mut render_cache);
    let second =
        super::definitions::semantic_outcome_key(analyzer, token, &outcome, &mut render_cache);

    assert_eq!(first, second);
    assert_eq!(render_cache.declaration_context_count(), 1);
}

#[test]
fn python_module_functions_are_not_duplicated_in_file_summary() {
    use crate::analyzer::{Language, PythonAnalyzer, TestProject};

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

    let result = super::summarize_files(&analyzer, vec![file]);
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

#[test]
fn issue_1431_source_block_end_line_counts_cr_only_terminators() {
    use crate::analyzer::{JavaAnalyzer, Language, TestProject};

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
fn literal_file_pattern_uses_project_lookup_without_scanning_analyzed_files() {
    let root = std::env::current_dir().unwrap();
    let analyzer = CountingAnalyzer::new(root, &["A.java", "nested/B.java"]);
    let files = resolve_file_patterns(&analyzer, &["nested/B.java".to_string()], None);

    assert_eq!(vec!["nested/B.java"], rel_paths(&files.files));
    assert!(files.ambiguous_paths.is_empty());
    assert_eq!(0, analyzer.analyzed_files_calls());
}

#[test]
fn summary_literal_file_target_avoids_directory_scan() {
    let root = std::env::current_dir().unwrap();
    let analyzer = CountingAnalyzer::new(root, &["A.java", "nested/B.java"]);

    let targets = route_summary_targets(&analyzer, &["nested/B.java".to_string()]);

    assert_eq!(vec!["nested/B.java"], rel_paths(&targets.file_targets));
    assert!(targets.listings.is_empty());
    assert_eq!(0, analyzer.analyzed_files_calls());
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

#[test]
fn file_pattern_resolution_deduplicates_literal_and_glob_matches() {
    let root = std::env::current_dir().unwrap();
    let analyzer = CountingAnalyzer::new(root, &["A.java", "nested/B.java"]);
    let files = resolve_file_patterns(
        &analyzer,
        &[
            "nested/B.java".to_string(),
            "nested/*.java".to_string(),
            "nested/B.java".to_string(),
        ],
        None,
    );

    assert_eq!(vec!["nested/B.java"], rel_paths(&files.files));
    assert!(files.ambiguous_paths.is_empty());
    assert_eq!(0, analyzer.analyzed_files_calls());
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
    assert_eq!(super::GET_SUMMARIES_MAX_FILES_PER_TARGET, too_broad.cap);
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
fn bare_filename_repairs_uniquely_without_scanning_analyzed_files() {
    let root = std::env::current_dir().unwrap();
    let analyzer = CountingAnalyzer::new(root, &["nested/B.java", "other/C.java"]);
    let files = resolve_file_patterns(&analyzer, &["B.java".to_string()], None);

    assert_eq!(vec!["nested/B.java"], rel_paths(&files.files));
    assert!(files.ambiguous_paths.is_empty());
    assert_eq!(0, analyzer.analyzed_files_calls());
}

#[test]
fn bare_filename_reports_ambiguity_without_guessing() {
    let root = std::env::current_dir().unwrap();
    let analyzer = CountingAnalyzer::new(root, &["src/B.java", "nested/B.java"]);
    let files = resolve_file_patterns(&analyzer, &["B.java".to_string()], None);

    assert!(files.files.is_empty());
    assert_eq!(1, files.ambiguous_paths.len());
    assert_eq!("B.java", files.ambiguous_paths[0].input);
    assert_eq!(
        vec!["nested/B.java".to_string(), "src/B.java".to_string()],
        files.ambiguous_paths[0].matches
    );
    assert_eq!(0, analyzer.analyzed_files_calls());
}

#[test]
fn list_symbols_uses_fast_literal_resolution() {
    let root = std::env::current_dir().unwrap();
    let analyzer = CountingAnalyzer::new(root, &["A.java"]);

    let _ = list_symbols(
        &analyzer,
        super::FilePatternsParams {
            file_patterns: vec!["A.java".to_string()],
        },
    );

    assert_eq!(0, analyzer.analyzed_files_calls());
}

#[test]
fn directory_targets_return_immediate_file_listings() {
    let root = std::env::current_dir().unwrap();
    let rel_paths: Vec<_> = (0..25)
        .map(|index| format!("src/File{index}.java"))
        .collect();
    let rel_path_refs: Vec<_> = rel_paths.iter().map(String::as_str).collect();
    let analyzer = CountingAnalyzer::new(root, &rel_path_refs);

    let result = super::get_summaries(
        &analyzer,
        super::SummariesParams {
            targets: vec!["src".to_string()],
        },
    );

    assert!(result.summaries.is_empty());
    assert!(result.not_found.is_empty());
    assert_eq!(1, result.listings.len());
    assert_eq!(25, result.listings[0].entries.len());
    assert!(result.listings[0].entries.iter().all(|entry| matches!(
        entry,
        ContainerListingEntry::File { path, .. } if path.starts_with("src/File")
    )));
}

fn rel_paths(files: &[ProjectFile]) -> Vec<String> {
    files
        .iter()
        .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
        .collect()
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
    assert!(!super::build_scan_usages_summary(std::slice::from_ref(&found_lines)).partial);

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

#[test]
fn issue_1228_source_budget_never_reports_verified_absence() {
    use crate::analyzer::{RustAnalyzer, TestProject};

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "lib.rs")
        .write("pub fn target() {}\npub fn caller() { target(); }\n")
        .unwrap();
    let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
    let context = ScanUsagesExecutionContext::with_limits(
        crate::CancellationToken::default(),
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

#[test]
fn issue_1228_time_budget_is_explicit_and_never_reports_verified_absence() {
    use crate::analyzer::{RustAnalyzer, TestProject};

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "lib.rs")
        .write("pub fn target() {}\npub fn caller() { target(); }\n")
        .unwrap();
    let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
    let context = ScanUsagesExecutionContext::with_limits(
        crate::CancellationToken::default().with_timeout(Duration::ZERO),
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

/// #1100: `TestFileExclusion` decides membership from paths alone instead of
/// hydrating every file's FileState. This pins the equivalence argument: the
/// path-only predicate must produce exactly the set the full classification
/// would exclude (Test and TestSupport are both excluded and both require
/// `test_like`; Production/Ambiguous are never test_like), across fixtures
/// covering all classification shapes.
#[test]
fn test_file_exclusion_path_predicate_matches_full_classification() {
    let temp = tempfile::TempDir::new().unwrap();
    let root = temp.path();
    for (path, content) in [
        ("src/prod.ts", "export function prod() { return 1; }\n"),
        (
            "tests/spec.test.ts",
            "import { prod } from '../src/prod';\ntest('t', () => { prod(); });\n",
        ),
        (
            "tests/helper.ts",
            "import { prod } from '../src/prod';\nexport const h = prod();\n",
        ),
        (
            "src/thing.test.ts",
            "import { prod } from './prod';\ntest('u', () => { prod(); });\n",
        ),
        ("src/other.ts", "export const o = 2;\n"),
    ] {
        let full = root.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, content).unwrap();
    }
    let project = crate::analyzer::TestProject::new(root.to_path_buf(), Language::TypeScript);
    let analyzer = crate::analyzer::TypescriptAnalyzer::from_project(project);

    let exclusion =
        super::scan_usages::test_file_exclusion(&analyzer, false).expect("an exclusion");
    let by_path: crate::hash::HashSet<ProjectFile> = analyzer
        .analyzed_files()
        .into_iter()
        .filter(|file| exclusion.excludes(file))
        .collect();
    let by_classification: crate::hash::HashSet<ProjectFile> = analyzer
        .analyzed_files()
        .into_iter()
        .filter(|file| {
            matches!(
                super::scan_usages::classify_resolved_test_file(&analyzer, file).kind,
                super::scan_usages::TestFileKind::Test
                    | super::scan_usages::TestFileKind::TestSupport
            )
        })
        .collect();
    assert_eq!(
        by_path, by_classification,
        "path-only exclusion must equal full-classification exclusion"
    );
    assert!(
        !by_path.is_empty(),
        "fixture must actually produce excluded files or the equivalence is vacuous"
    );
}

/// The scan prologue must not pre-classify the workspace. `excluded_test_files`
/// used to build its exclusion set by asking `is_test_like_file` about every
/// analyzed file before any symbol work: 29,748 files and 2.30-2.78 s of a 3 s
/// budget on the rustc tree, with `file_is_test_only` pulling the Rust
/// cargo-route index in behind it
/// (`.agents/docs/gate-cell-overhead-2026-08.md`). The classification is now
/// driven by the candidate filter, so a scan whose target has a handful of
/// candidate files classifies a handful of files.
///
/// The pin is the ratio, not a constant: the fixture's workspace is an order of
/// magnitude larger than the candidate set, and the count has to track the
/// candidates. Under the pre-classifying shape this assertion reads the
/// workspace size and fails.
#[test]
fn a_scan_classifies_its_candidate_files_not_its_workspace() {
    let temp = tempfile::TempDir::new().unwrap();
    let root = temp.path();
    // One production file the scan resolves in, one caller that references it,
    // and a large unrelated remainder — half of it under `tests/`, so the
    // eager set-build had real work to do on every one of them.
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::write(
        root.join("src/target.ts"),
        "export function scanned_target() { return 1; }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/caller.ts"),
        "import { scanned_target } from './target';\nexport const used = scanned_target();\n",
    )
    .unwrap();
    const UNRELATED: usize = 200;
    for index in 0..UNRELATED {
        std::fs::write(
            root.join(format!("src/unrelated_{index}.ts")),
            format!("export function unrelated_{index}() {{ return {index}; }}\n"),
        )
        .unwrap();
        std::fs::write(
            root.join(format!("tests/unrelated_{index}.test.ts")),
            format!("test('u{index}', () => {{ expect({index}).toBe({index}); }});\n"),
        )
        .unwrap();
    }
    let project = crate::analyzer::TestProject::new(root.to_path_buf(), Language::TypeScript);
    let analyzer = crate::analyzer::TypescriptAnalyzer::from_project(project);
    let workspace_files = analyzer.analyzed_files().len();
    assert!(
        workspace_files >= 2 * UNRELATED,
        "fixture must be workspace-scale: {workspace_files} files"
    );

    let exclusion =
        super::scan_usages::test_file_exclusion(&analyzer, false).expect("an exclusion");
    assert_eq!(
        0,
        exclusion.classified_count(),
        "building the exclusion must classify nothing"
    );

    let overloads: Vec<CodeUnit> = analyzer.definitions("scanned_target").collect();
    assert!(!overloads.is_empty(), "fixture target must resolve");
    let query = super::scan_usages::scoped_usage_finder(Some(&exclusion), None).query(
        &analyzer,
        &overloads,
        crate::analyzer::usages::DEFAULT_MAX_FILES,
        crate::analyzer::usages::DEFAULT_MAX_USAGES,
    );
    assert!(
        !query.candidate_files.is_empty(),
        "the scan must have read candidate files: {:?}",
        query.candidate_files
    );
    let classified = exclusion.classified_count();
    assert!(
        classified <= 4 * query.candidate_files.len(),
        "classification must track the candidate set ({} files), not the workspace \
         ({workspace_files} files): {classified} classified",
        query.candidate_files.len()
    );
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

#[test]
fn issue_1228_navigation_cancellation_reaches_rust_resolution() {
    use crate::analyzer::{RustAnalyzer, TestProject};

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "lib.rs")
        .write("pub fn target() {}\npub fn caller() { target(); }\n")
        .unwrap();
    let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
    let cancellation = crate::CancellationToken::cancel_after_checks_for_test(5);

    let result = super::get_definitions_by_location_with_cancellation(
        &analyzer,
        super::GetDefinitionParams {
            references: vec![super::DefinitionReferenceQuery {
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
fn issue_1228_uncancelled_mcp_rust_navigation_matches_direct_semantics() {
    use crate::analyzer::Language;
    use crate::test_support::AnalyzerFixture;

    fn query_at(
        source: &str,
        path: &str,
        snippet: &str,
        focus: &str,
    ) -> super::DefinitionReferenceQuery {
        let snippet_start = source
            .find(snippet)
            .unwrap_or_else(|| panic!("missing `{snippet}`"));
        let focus_start = snippet
            .find(focus)
            .unwrap_or_else(|| panic!("missing `{focus}` in `{snippet}`"));
        let byte = snippet_start + focus_start;
        let line_start = source[..byte].rfind('\n').map_or(0, |newline| newline + 1);
        super::DefinitionReferenceQuery {
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
    let params = super::GetDefinitionParams {
        references: references
            .iter()
            .map(|(_, query, _, _)| query.clone())
            .collect(),
    };
    let cancellation = crate::CancellationToken::new();

    let direct_definitions = super::get_definitions_by_location(analyzer, params.clone());
    let cancellable_definitions = super::get_definitions_by_location_with_cancellation(
        analyzer,
        params.clone(),
        Some(&cancellation),
    );
    assert_eq!(
        serde_json::to_value(&direct_definitions).unwrap(),
        serde_json::to_value(&cancellable_definitions).unwrap(),
        "an uncancelled MCP token must not select reduced Rust definition semantics"
    );

    let direct_declarations = super::get_declarations_by_location(analyzer, params.clone());
    let cancellable_declarations = super::get_declarations_by_location_with_cancellation(
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

/// #1775: boost's preprocessor limit headers write their preamble as null
/// directives (`# /* Copyright ... */`, bare `#`) and their bodies as spaced
/// directives (`# define BOOST_PP_BOOL_176 1`). Reading every `# ` line as a
/// comment ran the attached-comment walk from any one macro back to line 1, so
/// a one-line macro's `SourceBlock` reported `start_line: 1` and carried the
/// whole preamble as its text.
#[test]
fn issue_1775_cpp_directive_lines_do_not_join_a_macros_comment_block() {
    use crate::analyzer::{CppAnalyzer, TestProject};

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
    let reported_lines = |block: &super::SourceBlock| -> String {
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
