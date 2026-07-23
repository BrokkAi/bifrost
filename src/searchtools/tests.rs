use super::{
    ContainerListingEntry, DefinitionCandidateRenderCache, ScanUsageRequest,
    ScanUsagesAbsenceCaveat, ScanUsagesCandidateFilesSample, ScanUsagesStatus, ScanUsagesSurface,
    ScanUsagesWorkEntry, SourceBlock, SummaryElement, SymbolUsageRenderState, UsageFailureInfo,
    UsageHitKind, UsageHitRow, UsageRendering, classify_scan_usages_entry,
    definition_candidate_from_range, list_symbols, resolve_file_patterns, trim_summary_signature,
};
use super::{function_like_macro_query, route_summary_targets, usage_failure_hint};
use crate::analyzer::{
    CodeUnit, CodeUnitType, DeclarationInfo, IAnalyzer, Language, Project, ProjectFile, Range,
};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

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
    analyzed_files_calls: AtomicUsize,
}

impl CountingAnalyzer {
    fn new(root: PathBuf, rel_paths: &[&str]) -> Self {
        let files = rel_paths
            .iter()
            .map(|rel_path| ProjectFile::new(root.clone(), *rel_path))
            .collect();
        Self {
            project: CountingProject::new(root, files),
            analyzed_files_calls: AtomicUsize::new(0),
        }
    }

    fn analyzed_files_calls(&self) -> usize {
        self.analyzed_files_calls.load(Ordering::Relaxed)
    }
}

impl IAnalyzer for CountingAnalyzer {
    fn indexed_source(&self, _file: &ProjectFile) -> Option<String> {
        None
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        self.analyzed_files_calls.fetch_add(1, Ordering::Relaxed);
        self.project.files.iter().cloned().collect()
    }

    fn languages(&self) -> BTreeSet<Language> {
        BTreeSet::from([Language::Java])
    }

    fn update(&self, _changed_files: &BTreeSet<ProjectFile>) -> Self {
        Self {
            project: CountingProject::new(self.project.root.clone(), self.project.files.clone()),
            analyzed_files_calls: AtomicUsize::new(self.analyzed_files_calls()),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            project: CountingProject::new(self.project.root.clone(), self.project.files.clone()),
            analyzed_files_calls: AtomicUsize::new(self.analyzed_files_calls()),
        }
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

    fn extract_call_receiver(&self, _reference: &str) -> Option<String> {
        None
    }

    fn import_statements_of(&self, _file: &ProjectFile) -> Vec<String> {
        Vec::new()
    }

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

    fn ranges_of(&self, _code_unit: &CodeUnit) -> Vec<Range> {
        Vec::new()
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
        BTreeSet::new()
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
fn split_logical_lines_handles_crlf_lf_and_lone_cr() {
    assert_eq!(
        super::split_logical_lines("a\r\nb\r\nc"),
        vec!["a", "b", "c"]
    );
    assert_eq!(super::split_logical_lines("a\nb\nc"), vec!["a", "b", "c"]);
    assert_eq!(super::split_logical_lines("a\rb\rc"), vec!["a", "b", "c"]);
    assert_eq!(super::split_logical_lines("a\r\n"), vec!["a"]);
    assert_eq!(super::split_logical_lines(""), Vec::<&str>::new());
}

#[test]
fn source_block_fields_are_publicly_constructible() {
    let _block = SourceBlock {
        label: "A".to_string(),
        path: "A.java".to_string(),
        start_line: 10,
        end_line: 12,
        text: "class A {}".to_string(),
        presentation: None,
        note: None,
    };
    let _element = SummaryElement {
        path: "A.java".to_string(),
        symbol: "A".to_string(),
        kind: "class".to_string(),
        start_line: 10,
        end_line: 10,
        text: "class A {".to_string(),
        parent_symbol: None,
        presentation: None,
    };
}

#[test]
fn literal_file_pattern_uses_project_lookup_without_scanning_analyzed_files() {
    let root = std::env::current_dir().unwrap();
    let analyzer = CountingAnalyzer::new(root, &["A.java", "nested/B.java"]);
    let files = resolve_file_patterns(&analyzer, &["nested/B.java".to_string()]);

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
fn glob_file_pattern_scans_analyzed_files() {
    let root = std::env::current_dir().unwrap();
    let analyzer = CountingAnalyzer::new(root, &["A.java", "nested/B.java", "notes.txt"]);
    let files = resolve_file_patterns(&analyzer, &["nested/*.java".to_string()]);

    assert_eq!(vec!["nested/B.java"], rel_paths(&files.files));
    assert!(files.ambiguous_paths.is_empty());
    assert_eq!(1, analyzer.analyzed_files_calls());
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
    );

    assert_eq!(vec!["nested/B.java"], rel_paths(&files.files));
    assert!(files.ambiguous_paths.is_empty());
    assert_eq!(1, analyzer.analyzed_files_calls());
}

#[test]
fn bare_filename_repairs_uniquely_without_scanning_analyzed_files() {
    let root = std::env::current_dir().unwrap();
    let analyzer = CountingAnalyzer::new(root, &["nested/B.java", "other/C.java"]);
    let files = resolve_file_patterns(&analyzer, &["B.java".to_string()]);

    assert_eq!(vec!["nested/B.java"], rel_paths(&files.files));
    assert!(files.ambiguous_paths.is_empty());
    assert_eq!(0, analyzer.analyzed_files_calls());
}

#[test]
fn bare_filename_reports_ambiguity_without_guessing() {
    let root = std::env::current_dir().unwrap();
    let analyzer = CountingAnalyzer::new(root, &["src/B.java", "nested/B.java"]);
    let files = resolve_file_patterns(&analyzer, &["B.java".to_string()]);

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
        ),
        candidate_files_sample: Some(ScanUsagesCandidateFilesSample {
            scanned: vec!["scanned.rs".to_string()],
            omitted: vec!["omitted.rs".to_string()],
            omitted_count: 1,
        }),
        target_is_method: false,
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

    let found_lines = classify_scan_usages_entry(&usage_work_entry(
        "target",
        (0..11)
            .map(|line| usage_row("caller.rs", line + 1))
            .collect(),
        0,
        Vec::new(),
        false,
        None,
    ));
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
        ),
        short_name: "target".to_string(),
        total_callsites: 1001,
        limit: 1000,
        target_is_method: false,
    });
    assert_eq!(ScanUsagesStatus::TooManyCallsites, too_many.status);
    assert!(!too_many.complete);
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
    });
    assert_eq!(ScanUsagesStatus::Failure, failure.status);
    assert!(!failure.complete);
    assert_eq!(Some("no_graph_seed"), failure.reason_kind.as_deref());
}

/// #1100: `excluded_test_files` decides membership from paths alone instead of
/// hydrating every file's FileState. This pins the equivalence argument: the
/// path-only predicate must produce exactly the set the full classification
/// would exclude (Test and TestSupport are both excluded and both require
/// `test_like`; Production/Ambiguous are never test_like), across fixtures
/// covering all classification shapes.
#[test]
fn excluded_test_files_path_predicate_matches_full_classification() {
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

    let by_path = super::scan_usages::excluded_test_files(&analyzer, false).expect("excluded set");
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
        *by_path, by_classification,
        "path-only exclusion must equal full-classification exclusion"
    );
    assert!(
        !by_path.is_empty(),
        "fixture must actually produce excluded files or the equivalence is vacuous"
    );
}
