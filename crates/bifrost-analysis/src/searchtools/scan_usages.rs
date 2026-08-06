use super::selectors::*;
use super::*;
use crate::cancellation::CancellationToken;
use std::time::Duration;

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanUsagesByReferenceParams {
    pub symbols: Vec<String>,
    #[serde(default)]
    pub include_tests: bool,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    /// List the same-owner usage sites (self/this receiver and own-type static
    /// calls) that are otherwise only counted, not shown. Default false: these
    /// sites are excluded from external usage counts but reported as
    /// `same_owner_sites`. See #1014 facet B.
    #[serde(default)]
    pub include_same_owner: bool,
    /// Override the default wall-clock budget for this call. Interactive callers should leave this
    /// unset; a batch/background caller issuing one scan per checkout rather than serving
    /// keystrokes can request more time for a large workspace. Clamped to
    /// [`SCAN_USAGES_MAX_DURATION_CEILING`].
    #[serde(default)]
    pub max_duration_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanUsagesByLocationParams {
    pub targets: Vec<ScanUsagesTarget>,
    #[serde(default)]
    pub include_tests: bool,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    /// See [`ScanUsagesByReferenceParams::include_same_owner`].
    #[serde(default)]
    pub include_same_owner: bool,
    /// See [`ScanUsagesByReferenceParams::max_duration_secs`].
    #[serde(default)]
    pub max_duration_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanUsagesTarget {
    pub path: String,
    pub line: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    /// Optional exact declaration selector used to disambiguate overlapping
    /// declaration ranges at this location. The selector must name a declaration
    /// in `path` that contains the requested location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

/// Parameters for [`usage_graph`].
///
/// These fields mirror the scope controls on the scan-usage APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageGraphParams {
    /// Include references that live in detected test files.
    #[serde(default)]
    pub include_tests: bool,
    /// Optional project-relative file paths or globs that bound where references
    /// are searched. `None` searches the whole workspace.
    #[serde(default)]
    pub paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesResult {
    #[serde(skip)]
    pub(crate) surface: ScanUsagesSurface,
    pub scope: ScanUsagesScope,
    pub summary: ScanUsagesSummary,
    pub results: Vec<ScanUsagesEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanUsagesSurface {
    Reference,
    Location,
}

impl ScanUsagesSurface {
    pub(crate) fn tool_name(self) -> &'static str {
        match self {
            Self::Reference => "scan_usages_by_reference",
            Self::Location => "scan_usages_by_location",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesScope {
    pub include_tests: bool,
    pub whole_workspace: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths_omitted: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignored_paths: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesSummary {
    pub requested: usize,
    pub resolved: usize,
    pub total_hits: usize,
    pub partial: bool,
    pub found: usize,
    pub verified_absent: usize,
    pub no_external_usages: usize,
    pub unverified_absent: usize,
    pub not_found: usize,
    pub ambiguous: usize,
    pub failure: usize,
    pub too_many_callsites: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ScanUsagesInput {
    Symbol(String),
    Target(ScanUsagesTarget),
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanUsagesInputKind {
    Symbol,
    Target,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanUsagesStatus {
    Found,
    VerifiedAbsent,
    /// Resolved with zero external usage sites, but one or more same-owner
    /// (self/this receiver or own-type static) sites exist within the declaring
    /// container. Distinct from `verified_absent` so the caller never reads a
    /// confident "no callers" claim when internal callers exist (#1014 facet B).
    NoExternalUsages,
    UnverifiedAbsent,
    NotFound,
    Ambiguous,
    Failure,
    TooManyCallsites,
}

impl ScanUsagesStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Found => "found",
            Self::VerifiedAbsent => "verified_absent",
            Self::NoExternalUsages => "no_external_usages",
            Self::UnverifiedAbsent => "unverified_absent",
            Self::NotFound => "not_found",
            Self::Ambiguous => "ambiguous",
            Self::Failure => "failure",
            Self::TooManyCallsites => "too_many_callsites",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanUsagesAbsenceCaveat {
    UnprovenMatches,
    CandidateFilesTruncated,
    ReferenceOnlySiblings,
    ScanIncomplete,
}

impl ScanUsagesAbsenceCaveat {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::UnprovenMatches => "unproven_matches",
            Self::CandidateFilesTruncated => "candidate_files_truncated",
            Self::ReferenceOnlySiblings => "reference_only_siblings",
            Self::ScanIncomplete => "scan_incomplete",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanUsagesIncompleteReason {
    Cancelled,
    TimeBudget,
    CandidateFiles,
    SourceBytes,
    Callsites,
    ResponseBudget,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesEntry {
    pub input: ScanUsagesInput,
    pub input_kind: ScanUsagesInputKind,
    pub status: ScanUsagesStatus,
    #[serde(skip_serializing_if = "is_true")]
    pub complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete_reason: Option<ScanUsagesIncompleteReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_hits: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unproven_hits: Option<usize>,
    /// Count of usage sites within the declaring container (self/this receiver
    /// and own-type static calls) that are excluded from external usage counts.
    /// Omitted when zero. Set `include_same_owner` to list them in
    /// `same_owner_files`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_owner_sites: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendering: Option<UsageRendering>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub files: Vec<UsageFileGroup>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub same_owner_files: Vec<UsageFileGroup>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub unproven_files: Vec<UsageFileGroup>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub model_relations: Vec<crate::analyzer::semantic_model::SemanticModelRelation>,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub model_relations_omitted: usize,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub top_enclosing: Vec<UsageEnclosingCount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_sites_excluded: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_truncated: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub absence_caveats: Vec<ScanUsagesAbsenceCaveat>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub candidate_targets: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub candidate_details: Vec<AmbiguousUsageCandidateDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_details_total: Option<usize>,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub candidate_details_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub candidates: Vec<AmbiguousUsageCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fq_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_files_sample: Option<ScanUsagesCandidateFilesSample>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_callsites: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum UsageRendering {
    Full,
    Lines,
    Summary,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolUsages {
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fq_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_line: Option<usize>,
    pub total_hits: usize,
    pub unproven_hits: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_owner_sites: Option<usize>,
    pub rendering: UsageRendering,
    /// True when the candidate file set exceeded the analyzer's per-query cap
    /// and an arbitrary subset was scanned. Results are partial when set.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub candidate_files_truncated: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub reference_only_siblings: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_sites_excluded: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_truncated: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub top_enclosing: Vec<UsageEnclosingCount>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub files: Vec<UsageFileGroup>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub same_owner_files: Vec<UsageFileGroup>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub unproven_files: Vec<UsageFileGroup>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub model_relations: Vec<crate::analyzer::semantic_model::SemanticModelRelation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageFileGroup {
    pub path: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hits: Vec<UsageLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageLocation {
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<usize>,
    pub enclosing: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(skip_serializing_if = "is_full_confidence")]
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AmbiguousUsageSymbol {
    pub symbol: String,
    pub short_name: String,
    pub candidate_targets: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub candidate_details: Vec<AmbiguousUsageCandidateDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_details_total: Option<usize>,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub candidate_details_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub candidates: Vec<AmbiguousUsageCandidate>,
    /// True when the candidate file set exceeded the analyzer's per-query cap
    /// and an arbitrary subset was scanned. Results are partial when set.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub candidate_files_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_sites_excluded: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AmbiguousUsageCandidate {
    pub target: String,
    pub total_hits: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AmbiguousUsageCandidateDetail {
    pub target: String,
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub scan_usages_by_location_target: ScanUsagesTargetSuggestion,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesTargetSuggestion {
    pub path: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageEnclosingCount {
    pub enclosing: String,
    pub hits: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageFailureInfo {
    /// Symbol requested by the caller.
    pub symbol: String,
    /// Fully qualified symbol reported by the analyzer failure, when available.
    pub fq_name: String,
    /// Stable machine-readable failure category, when available.
    pub reason_kind: String,
    /// Analyzer-provided reason. This is separate from `not_found` because the symbol
    /// resolved, but usage analysis could not produce a trustworthy answer.
    pub reason: String,
    /// True when the candidate file set exceeded the analyzer's per-query cap
    /// and an arbitrary subset was scanned before the failure was produced.
    pub candidate_files_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_files_sample: Option<ScanUsagesCandidateFilesSample>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesCandidateFilesSample {
    pub scanned: Vec<String>,
    pub omitted: Vec<String>,
    pub omitted_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TooManyCallsitesInfo {
    pub symbol: String,
    pub short_name: String,
    pub total_callsites: usize,
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Pre-compute the set of detected test files to exclude, or `None` when test
/// files should be kept. Both `scan_usages` and `usage_graph` filter at the
/// source (before the regex scan and the call-site cap) rather than dropping
/// test hits after the fact: filtering post-hoc would let test hits eat into
/// the cap and turn production-only queries into `TooManyCallsites` errors.
pub(super) fn excluded_test_files(
    analyzer: &dyn IAnalyzer,
    include_tests: bool,
) -> Option<Arc<HashSet<ProjectFile>>> {
    if include_tests {
        return None;
    }
    // A file is excluded from a non-test scan exactly when its classification is
    // `Test` or `TestSupport`. Both kinds require — and are fully determined by —
    // the `test_like` predicate in `classify_resolved_test_file`: a `Test` file
    // is `test_like && contains_test_code`, a `TestSupport` file is
    // `test_like && !contains_test_code`, and every non-`test_like` file lands in
    // `Production`/`Ambiguous`. So membership here is decided by `test_like`
    // alone; the `contains_test_code` signal only splits `Test` from
    // `TestSupport`, and both are excluded. That still avoids hydrating every
    // workspace file's `FileState` (a full store read + decode of all
    // declarations) solely to read a boolean that cannot change the set — the
    // dominant per-call cost of a scan on a large workspace.
    let set: HashSet<ProjectFile> = analyzer
        .analyzed_files()
        .into_iter()
        .filter(|file| {
            is_test_like_file(
                analyzer,
                file,
                &rel_path_string(file),
                language_for_file(file),
            )
        })
        .collect();
    Some(Arc::new(set))
}

/// The `test_like` predicate shared by [`classify_resolved_test_file`] and
/// [`excluded_test_files`]: a file rooted under a test directory, carrying a
/// test filename convention, or reachable only from test-gated code.
///
/// The third disjunct is the structural one (#1546): Rust's sibling test module
/// is declared `#[cfg(test)] mod tests;` by its parent, so neither path rule
/// fires. It is a lookup into the per-language module index rather than a
/// per-file hydration, so it keeps the membership set cheap to build.
fn is_test_like_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    path: &str,
    language: Language,
) -> bool {
    test_paths::path_test_verdict(path) == test_paths::PathTestVerdict::TestRoot
        || test_paths::has_test_filename_convention(path, language)
        || analyzer.file_is_test_only(file)
}

/// Build a [`UsageFinder`] whose file filter drops the excluded test files and
/// applies the optional path filter — the workspace scoping that both
/// `scan_usages` and `usage_graph` run before querying call sites.
pub(super) fn scoped_usage_finder(
    test_files: Option<&Arc<HashSet<ProjectFile>>>,
    path_filter: Option<&Arc<ScanUsagesPathFilter>>,
) -> UsageFinder {
    let mut finder = UsageFinder::new();
    if let Some(test_files) = test_files {
        let test_files = Arc::clone(test_files);
        let path_filter = path_filter.map(Arc::clone);
        finder = finder.with_file_filter(move |file| {
            !test_files.contains(file)
                && path_filter
                    .as_ref()
                    .map(|filter| filter.matches(file))
                    .unwrap_or(true)
        });
    } else if let Some(path_filter) = path_filter.map(Arc::clone) {
        finder = finder.with_file_filter(move |file| path_filter.matches(file));
    }
    finder.with_authoritative_scope(path_filter.is_some())
}

pub(super) fn ambiguous_usage_symbol_from_groups(
    analyzer: &dyn IAnalyzer,
    surface: ScanUsagesSurface,
    symbol: String,
    short_name: String,
    groups: Vec<(String, Vec<CodeUnit>)>,
    note: impl Into<String>,
) -> AmbiguousUsageSymbol {
    let note = note.into();
    let total = groups.len();
    let candidate_targets: Vec<String> = groups
        .iter()
        .map(|(selector, _)| selector.clone())
        .collect();
    let candidate_details: Vec<AmbiguousUsageCandidateDetail> =
        if surface == ScanUsagesSurface::Location {
            groups
                .iter()
                .take(SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT)
                .filter_map(|(selector, units)| {
                    let unit = units.first()?;
                    // `unit` and `range` below both come from the analyzer's
                    // own declaration data, so read the same analyzed
                    // snapshot rather than the live file on disk.
                    let source = analyzer.indexed_source(unit.source())?;
                    let range =
                        code_unit_declaration_name_range(analyzer, unit.source(), &source, unit)?;
                    let path = rel_path_string(unit.source());
                    let line = range.start_line + 1;
                    let column = character_column_for_byte(&source, line, range.start_byte);
                    Some(AmbiguousUsageCandidateDetail {
                        target: selector.clone(),
                        path: path.clone(),
                        start_line: line,
                        end_line: range.end_line + 1,
                        scan_usages_by_location_target: ScanUsagesTargetSuggestion {
                            path,
                            line,
                            column,
                        },
                    })
                })
                .collect()
        } else {
            Vec::new()
        };

    let has_candidate_details = !candidate_details.is_empty();
    AmbiguousUsageSymbol {
        symbol,
        short_name,
        candidate_targets,
        candidate_details,
        candidate_details_total: has_candidate_details.then_some(total),
        candidate_details_truncated: has_candidate_details
            && total > SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT,
        candidates: Vec::new(),
        candidate_files_truncated: false,
        definition_sites_excluded: None,
        note: Some(
            if surface == ScanUsagesSurface::Location && total > SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT
            {
                format!(
                    "{} Showing first {} of {total} candidate locations.",
                    note, SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT
                )
            } else {
                note
            },
        ),
    }
}

pub(super) fn scan_usages_ambiguity_note(surface: ScanUsagesSurface) -> &'static str {
    match surface {
        ScanUsagesSurface::Reference => {
            "Ambiguous; re-call scan_usages_by_reference with one symbol from candidate_targets."
        }
        ScanUsagesSurface::Location => {
            "Ambiguous location; refine the line/column target and re-call scan_usages_by_location."
        }
    }
}

pub(super) enum ScanUsageTargetResolution {
    Resolved {
        symbol: String,
        overloads: Vec<CodeUnit>,
    },
    Modeled {
        symbol: String,
        definition: ResolvedUsageDefinition,
    },
    NotFound(NotFoundInput),
    Ambiguous(AmbiguousUsageSymbol),
    Failure(UsageFailureInfo),
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ScanUsagesLocationSelection {
    Point(usize),
    Line(usize),
}

#[derive(Debug, Clone)]
pub(super) struct ScanUsageRequest {
    index: usize,
    input: ScanUsagesInput,
    input_kind: ScanUsagesInputKind,
    label: String,
    surface: ScanUsagesSurface,
}

impl ScanUsageRequest {
    pub(super) fn symbol(index: usize, symbol: String) -> Self {
        Self {
            index,
            input: ScanUsagesInput::Symbol(symbol.clone()),
            input_kind: ScanUsagesInputKind::Symbol,
            label: symbol,
            surface: ScanUsagesSurface::Reference,
        }
    }

    fn target(index: usize, target: ScanUsagesTarget) -> Self {
        let label = scan_usages_target_label(&target);
        Self {
            index,
            input: ScanUsagesInput::Target(target),
            input_kind: ScanUsagesInputKind::Target,
            label,
            surface: ScanUsagesSurface::Location,
        }
    }
}

#[derive(Debug)]
pub(super) struct ScanUsagesQueryScope {
    path_filter: Option<Arc<ScanUsagesPathFilter>>,
    include_tests: bool,
    ignored_paths: usize,
}

impl ScanUsagesQueryScope {
    fn new(analyzer: &dyn IAnalyzer, paths: Option<&[String]>, include_tests: bool) -> Self {
        let built = build_scan_usages_path_filter(analyzer, paths);
        Self {
            path_filter: built.filter,
            include_tests,
            ignored_paths: built.ignored_paths,
        }
    }

    fn whole_workspace(&self) -> bool {
        self.path_filter.is_none()
    }

    fn result_scope(&self) -> ScanUsagesScope {
        let (paths, paths_omitted) = self
            .path_filter
            .as_deref()
            .map(ScanUsagesPathFilter::summarized_paths)
            .unwrap_or_default();
        ScanUsagesScope {
            include_tests: self.include_tests,
            whole_workspace: self.whole_workspace(),
            paths,
            paths_omitted,
            ignored_paths: some_if_nonzero(self.ignored_paths),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct IndexedResolvedScanTarget {
    request: ScanUsageRequest,
    symbol: String,
    overloads: Vec<CodeUnit>,
    location_selected: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ScanUsagesExecutionContext {
    cancellation: CancellationToken,
    max_candidate_files: usize,
    max_path_scoped_candidate_files: usize,
    max_source_bytes: usize,
    max_callsites: usize,
}

// Leave two seconds of the five-second product envelope for cooperative
// shutdown, rendering, response delivery, and short non-interruptible cache
// lookups that may already be in flight when the deadline is observed.
//
// This default bounds interactive work. Batch callers that need a more complete
// large-workspace scan can use the explicit max_duration_secs override.
const SCAN_USAGES_MAX_DURATION: Duration = Duration::from_secs(3);

/// Upper bound on a caller-requested `max_duration_secs` override (see
/// [`ScanUsagesByReferenceParams::max_duration_secs`]). Keeps a budget override an escape hatch for
/// large-workspace batch callers, not a way to opt out of bounded execution entirely.
pub(crate) const SCAN_USAGES_MAX_DURATION_CEILING: Duration = Duration::from_secs(300);

// #1337: tests that pin the *count/byte*-based budget behavior (demote-to-summary,
// candidate-file truncation, too-many-callsites) go through the public service surface,
// which always applies the real [`SCAN_USAGES_MAX_DURATION`] wall-clock deadline. Under
// box load, real elapsed time can cross that deadline before the count/byte limit the
// test actually means to exercise is reached, flipping the observed `incomplete_reason`
// (or completeness) out from under the assertions -- flaky, not a real product bug. This
// flag lets such tests disable the wall-clock deadline deterministically (no `Instant`
// reads involved at all, so no amount of real elapsed time can trip it) while leaving
// every other budget -- candidate files, source bytes, callsites, response bytes -- fully
// enforced. It never affects a call that supplies an explicit `max_duration_secs`
// (production behavior, and any test that deliberately exercises the ceiling clamp).
#[cfg(any(test, feature = "test-support"))]
static SCAN_USAGES_TIME_BUDGET_DISABLED_FOR_TEST: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(any(test, feature = "test-support"))]
fn scan_usages_time_budget_test_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

/// RAII guard returned by [`disable_time_budget_for_test`]; restores the real wall-clock
/// budget on drop.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct ScanUsagesTimeBudgetGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for ScanUsagesTimeBudgetGuard {
    fn drop(&mut self) {
        SCAN_USAGES_TIME_BUDGET_DISABLED_FOR_TEST
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Deterministically disables the [`SCAN_USAGES_MAX_DURATION`] wall-clock deadline for the
/// lifetime of the returned guard, for calls that leave `max_duration_secs` unset. Production
/// code never calls this -- the real deadline always applies outside tests. See #1337.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn disable_time_budget_for_test() -> ScanUsagesTimeBudgetGuard {
    let lock = scan_usages_time_budget_test_lock()
        .lock()
        .expect("scan_usages time-budget test mutex poisoned");
    SCAN_USAGES_TIME_BUDGET_DISABLED_FOR_TEST.store(true, std::sync::atomic::Ordering::Release);
    ScanUsagesTimeBudgetGuard { _lock: lock }
}

impl ScanUsagesExecutionContext {
    /// `max_duration`, when `Some`, overrides [`SCAN_USAGES_MAX_DURATION`] for this call (clamped to
    /// [`SCAN_USAGES_MAX_DURATION_CEILING`]) -- see `max_duration_secs` on the request params.
    pub(crate) fn with_cancellation_and_max_duration(
        cancellation: CancellationToken,
        max_duration: Option<Duration>,
    ) -> Self {
        #[cfg(any(test, feature = "test-support"))]
        if max_duration.is_none()
            && SCAN_USAGES_TIME_BUDGET_DISABLED_FOR_TEST.load(std::sync::atomic::Ordering::Acquire)
        {
            // No `.with_timeout(..)` call: the token's deadline stays `None`, so
            // `is_cancelled`/`is_timed_out` never consult the wall clock at all.
            return Self {
                cancellation,
                ..Self::default()
            };
        }
        let max_duration = max_duration
            .unwrap_or(SCAN_USAGES_MAX_DURATION)
            .min(SCAN_USAGES_MAX_DURATION_CEILING);
        Self {
            cancellation: cancellation.with_timeout(max_duration),
            ..Self::default()
        }
    }

    fn interruption_reason(&self) -> ScanUsagesIncompleteReason {
        if self.cancellation.is_timed_out() {
            ScanUsagesIncompleteReason::TimeBudget
        } else {
            ScanUsagesIncompleteReason::Cancelled
        }
    }

    #[cfg(test)]
    pub(crate) fn with_limits(
        cancellation: CancellationToken,
        max_candidate_files: usize,
        max_path_scoped_candidate_files: usize,
        max_source_bytes: usize,
        max_callsites: usize,
    ) -> Self {
        Self {
            cancellation,
            max_candidate_files,
            max_path_scoped_candidate_files,
            max_source_bytes,
            max_callsites,
        }
    }
}

impl Default for ScanUsagesExecutionContext {
    fn default() -> Self {
        Self {
            cancellation: CancellationToken::default().with_timeout(SCAN_USAGES_MAX_DURATION),
            max_candidate_files: DEFAULT_MAX_FILES,
            max_path_scoped_candidate_files: SCAN_USAGES_PATH_SCOPED_MAX_FILES,
            max_source_bytes: SCAN_USAGES_MAX_SOURCE_BYTES,
            max_callsites: SCAN_USAGES_MAX_CALLSITES,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) enum ScanUsagesWorkEntry {
    Usage {
        request: ScanUsageRequest,
        state: SymbolUsageRenderState,
        candidate_files_sample: Option<ScanUsagesCandidateFilesSample>,
        target_is_method: bool,
        incomplete_reason: Option<ScanUsagesIncompleteReason>,
    },
    NotFound {
        request: ScanUsageRequest,
        item: NotFoundInput,
    },
    Ambiguous {
        request: ScanUsageRequest,
        item: AmbiguousUsageSymbol,
        incomplete_reason: Option<ScanUsagesIncompleteReason>,
    },
    Failure {
        request: ScanUsageRequest,
        failure: UsageFailureInfo,
        incomplete_reason: Option<ScanUsagesIncompleteReason>,
    },
    Incomplete {
        request: ScanUsageRequest,
        symbol: Option<String>,
        reason: ScanUsagesIncompleteReason,
        message: String,
    },
    TooManyCallsites {
        request: ScanUsageRequest,
        state: SymbolUsageRenderState,
        short_name: String,
        total_callsites: usize,
        limit: usize,
        target_is_method: bool,
    },
}

impl ScanUsagesWorkEntry {
    fn index(&self) -> usize {
        match self {
            ScanUsagesWorkEntry::Usage { request, .. }
            | ScanUsagesWorkEntry::NotFound { request, .. }
            | ScanUsagesWorkEntry::Ambiguous { request, .. }
            | ScanUsagesWorkEntry::Failure { request, .. }
            | ScanUsagesWorkEntry::Incomplete { request, .. }
            | ScanUsagesWorkEntry::TooManyCallsites { request, .. } => request.index,
        }
    }
}

/// Whether an interrupted query still carries sites worth reporting.
fn fuzzy_result_has_hits(result: &FuzzyResult) -> bool {
    match result {
        FuzzyResult::Success {
            hits_by_overload, ..
        }
        | FuzzyResult::Ambiguous {
            hits_by_overload, ..
        } => hits_by_overload.values().any(|hits| !hits.is_empty()),
        FuzzyResult::TooManyCallsites { sample_hits, .. } => !sample_hits.is_empty(),
        FuzzyResult::Failure { .. } => false,
    }
}

fn query_incomplete_reason(
    completion: UsageQueryCompletion,
    interruption_reason: ScanUsagesIncompleteReason,
) -> Option<ScanUsagesIncompleteReason> {
    match completion {
        UsageQueryCompletion::Complete => None,
        UsageQueryCompletion::Cancelled => Some(interruption_reason),
        UsageQueryCompletion::CandidateFilesBudgetExhausted => {
            Some(ScanUsagesIncompleteReason::CandidateFiles)
        }
        UsageQueryCompletion::SourceBytesBudgetExhausted => {
            Some(ScanUsagesIncompleteReason::SourceBytes)
        }
    }
}

fn incomplete_recovery_message(
    reason: ScanUsagesIncompleteReason,
    surface: ScanUsagesSurface,
) -> String {
    match reason {
        ScanUsagesIncompleteReason::Cancelled => format!(
            "usage analysis was cancelled; after cancellation clears, re-call {}",
            surface.tool_name()
        ),
        ScanUsagesIncompleteReason::TimeBudget => {
            format!(
                "usage analysis exhausted its wall-clock time budget; narrow `paths` or use a more specific selector, then re-call {}",
                surface.tool_name()
            )
        }
        ScanUsagesIncompleteReason::CandidateFiles => {
            format!(
                "usage analysis exhausted its candidate-file budget; narrow `paths`, then re-call {}",
                surface.tool_name()
            )
        }
        ScanUsagesIncompleteReason::SourceBytes => {
            format!(
                "usage analysis exhausted its source-byte budget; narrow `paths`, then re-call {}",
                surface.tool_name()
            )
        }
        ScanUsagesIncompleteReason::Callsites => format!(
            "usage analysis exhausted its callsite budget; narrow `paths` or use a more specific selector, then re-call {}",
            surface.tool_name()
        ),
        ScanUsagesIncompleteReason::ResponseBudget => format!(
            "usage results were summarized to fit the response budget; re-call {} with one target to maximize retained detail, but exhaustive modeled relation retrieval is unavailable",
            surface.tool_name()
        ),
    }
}

fn mark_incomplete(
    entry: &mut ScanUsagesEntry,
    reason: ScanUsagesIncompleteReason,
    surface: ScanUsagesSurface,
) -> bool {
    let mut changed = entry.complete || entry.incomplete_reason != Some(reason);
    entry.complete = false;
    entry.incomplete_reason = Some(reason);
    let recovery = incomplete_recovery_message(reason, surface);
    if entry.message.is_none() {
        entry.message = Some(recovery);
        changed = true;
    } else if entry.message.as_deref() != Some(recovery.as_str())
        && !entry.notes.contains(&recovery)
    {
        entry.notes.push(recovery);
        changed = true;
    }
    changed
}

fn incomplete_work_entry(
    request: ScanUsageRequest,
    symbol: Option<String>,
    reason: ScanUsagesIncompleteReason,
) -> ScanUsagesWorkEntry {
    let message = incomplete_recovery_message(reason, request.surface);
    ScanUsagesWorkEntry::Incomplete {
        request,
        symbol,
        reason,
        message,
    }
}

fn incomplete_requests(
    symbols: Vec<ScanUsageRequest>,
    targets: Vec<ScanUsageRequest>,
    reason: ScanUsagesIncompleteReason,
) -> Vec<ScanUsagesWorkEntry> {
    targets
        .into_iter()
        .chain(symbols)
        .map(|request| {
            let symbol = matches!(request.input_kind, ScanUsagesInputKind::Symbol)
                .then(|| request.label.clone());
            incomplete_work_entry(request, symbol, reason)
        })
        .collect()
}

pub fn scan_usages_target_label(target: &ScanUsagesTarget) -> String {
    match target.column {
        Some(column) => format!("{}:{}:{column}", target.path, target.line),
        None => format!("{}:{}", target.path, target.line),
    }
}

pub(super) fn location_selector_failure(
    target: &ScanUsagesTarget,
    reason_kind: &str,
    reason: impl Into<String>,
) -> ScanUsageTargetResolution {
    let hint = usage_failure_hint(ScanUsagesSurface::Location, reason_kind, None, true, false);
    ScanUsageTargetResolution::Failure(UsageFailureInfo {
        symbol: scan_usages_target_label(target),
        fq_name: String::new(),
        reason_kind: reason_kind.to_string(),
        reason: reason.into(),
        candidate_files_truncated: false,
        candidate_files_sample: None,
        hint,
    })
}

pub(super) fn usage_failure_hint(
    surface: ScanUsagesSurface,
    reason_kind: &str,
    target: Option<&CodeUnit>,
    location_selected: bool,
    candidate_files_truncated: bool,
) -> Option<String> {
    if reason_kind == "unsupported_target_shape" {
        return Some(unsupported_target_shape_guidance(target));
    }

    if candidate_files_truncated {
        return Some(format!(
            "The candidate file set exceeded the per-query cap; re-call {} with narrower `paths` to reduce the scan scope.",
            surface.tool_name()
        ));
    }

    match (reason_kind, location_selected) {
        ("no_graph_seed", true) => Some(
            "No export seed was resolved for this selected definition. Use search_symbols or get_symbol_sources to choose an exported declaration, or narrow `paths` to likely callers."
                .to_string(),
        ),
        ("no_graph_seed", false) => Some(
            "No export seed was resolved for this symbol. Use search_symbols or get_symbol_sources to choose an exported declaration, then re-call scan_usages_by_reference with that symbol."
                .to_string(),
        ),
        ("unsupported_target_language", _)
        | ("missing_analyzer_capability", _)
        | ("unsupported_target_shape", _) => None,
        _ => None,
    }
}

pub(super) fn unsupported_target_shape_message(target: Option<&CodeUnit>) -> String {
    let Some(target) = target else {
        return "`scan_usages` cannot resolve this declaration kind yet".to_string();
    };
    format!(
        "`scan_usages` cannot resolve {} {} declarations yet",
        scan_usages_language_name(language_for_target(target)),
        target.kind().display_lowercase(),
    )
}

pub(super) const UNSUPPORTED_TARGET_SHAPE_GUIDANCE: &str = "Use `get_symbol_sources` to inspect the declaration, then `query_code` to find syntactic candidates; `query_code` does not resolve references.";

pub(super) fn unsupported_target_shape_guidance(target: Option<&CodeUnit>) -> String {
    let Some(target) = target else {
        return UNSUPPORTED_TARGET_SHAPE_GUIDANCE.to_string();
    };

    if target.is_macro() {
        return function_like_macro_query_guidance(
            language_for_target(target),
            target.identifier(),
        );
    }

    UNSUPPORTED_TARGET_SHAPE_GUIDANCE.to_string()
}

pub(super) fn function_like_macro_query_guidance(language: Language, identifier: &str) -> String {
    let query = function_like_macro_query(language, identifier);
    format!(
        "Use `get_symbol_sources` to inspect the macro. For a function-like macro, call `query_code` with `{query}` to find syntactic invocation candidates; `query_code` does not resolve references."
    )
}

pub(super) fn function_like_macro_query(language: Language, identifier: &str) -> String {
    serde_json::json!({
        "languages": [language.config_label()],
        "match": { "kind": "call", "callee": { "name": identifier } }
    })
    .to_string()
}

pub(super) fn scan_usages_language_name(language: Language) -> &'static str {
    match language {
        Language::None => "this language",
        Language::Java => "Java",
        Language::Go => "Go",
        Language::Cpp => "C/C++",
        Language::JavaScript => "JavaScript",
        Language::TypeScript => "TypeScript",
        Language::Python => "Python",
        Language::Rust => "Rust",
        Language::Php => "PHP",
        Language::Scala => "Scala",
        Language::CSharp => "C#",
        Language::Ruby => "Ruby",
        Language::Kotlin => "Kotlin",
    }
}

pub(super) fn scan_usages_anchor_not_found_input(
    input: impl Into<String>,
    anchor: &str,
    name: &str,
    resolved_targets: &[CodeUnit],
) -> NotFoundInput {
    if resolved_targets
        .iter()
        .all(|target| language_for_target(target) == Language::Cpp && target.is_macro())
        && !resolved_targets.is_empty()
    {
        let target = &resolved_targets[0];
        return not_found_input(
            input,
            Some(format!(
                "`{name}` has no definition in `{anchor}`. It resolves elsewhere as a C/C++ macro, which `scan_usages` cannot resolve. {}",
                unsupported_target_shape_guidance(Some(target)),
            )),
        );
    }

    anchor_not_found_input(input, anchor, name)
}

pub(super) fn character_column_for_byte(source: &str, line: usize, byte: usize) -> Option<usize> {
    if line == 0 || byte > source.len() || !source.is_char_boundary(byte) {
        return None;
    }
    let line_starts = compute_line_starts(source);
    let line_start = *line_starts.get(line - 1)?;
    let line_end = line_starts.get(line).copied().unwrap_or(source.len());
    let slice = source.get(line_start..byte.min(line_end))?;
    Some(slice.chars().count() + 1)
}

pub(super) fn resolve_scan_usages_target(
    analyzer: &dyn IAnalyzer,
    resolver: &WorkspaceFileResolver,
    target: ScanUsagesTarget,
) -> ScanUsageTargetResolution {
    let file = match resolver.resolve_literal(target.path.trim()) {
        ResolvedFileInput::File(file) => file,
        ResolvedFileInput::Ambiguous(item) => {
            return location_selector_failure(
                &target,
                "ambiguous_path",
                format!(
                    "`{}` is ambiguous; matches: {}",
                    item.input,
                    item.matches.join(", ")
                ),
            );
        }
        ResolvedFileInput::NotFound(path) => {
            return ScanUsageTargetResolution::NotFound(file_not_found_input(format!(
                "{} ({path} does not resolve to a workspace file)",
                scan_usages_target_label(&target)
            )));
        }
    };

    // The byte offset computed below from `target.line`/`target.column` is
    // matched against `analyzer.ranges_of(&unit)` further down, which is
    // itself keyed to the analyzer's indexed snapshot — so the line/column
    // must be interpreted against that same snapshot, not a fresh disk read,
    // or the two coordinate systems could disagree on a just-edited file.
    let source = match analyzer.indexed_source(&file) {
        Some(source) => source,
        None => {
            return location_selector_failure(
                &target,
                "read_failed",
                format!(
                    "failed to read `{}`: not indexed by analyzer",
                    rel_path_string(&file)
                ),
            );
        }
    };

    if target.column == Some(0) {
        return location_selector_failure(
            &target,
            "invalid_location",
            scan_usages_location_diagnostic(&target, &source, "column must be 1-based"),
        );
    }

    let line_starts = compute_line_starts(&source);
    let line = target.line;
    if line == 0 || line > line_starts.len() {
        return location_selector_failure(
            &target,
            "invalid_location",
            scan_usages_location_diagnostic(
                &target,
                &source,
                &format!(
                    "line {line} is outside 1..={} for this file",
                    line_starts.len()
                ),
            ),
        );
    }
    let selection = if let Some(column) = target.column {
        let line_start = line_starts[line - 1];
        let line_end = line_starts.get(line).copied().unwrap_or(source.len());
        match crate::analyzer::usages::get_definition::byte_offset_for_character_column(
            &source, line_start, line_end, line, column,
        ) {
            Ok(point) => ScanUsagesLocationSelection::Point(point),
            Err(reason) => {
                return location_selector_failure(
                    &target,
                    "invalid_location",
                    scan_usages_location_diagnostic(&target, &source, &reason),
                );
            }
        }
    } else {
        ScanUsagesLocationSelection::Line(line)
    };

    let selector = match target.symbol.as_deref() {
        None => None,
        Some(symbol) => match split_definition_selector_with_workspace_files(resolver, symbol) {
            DefinitionSelector::Name(name) => Some(name),
            DefinitionSelector::FileAnchored { anchor, lookup } => {
                let anchor_file = match resolver.resolve_literal(&anchor) {
                    ResolvedFileInput::File(file) => file,
                    ResolvedFileInput::Ambiguous(item) => {
                        return location_selector_failure(
                            &target,
                            "ambiguous_path",
                            format!(
                                "selector anchor `{}` is ambiguous; matches: {}",
                                item.input,
                                item.matches.join(", ")
                            ),
                        );
                    }
                    ResolvedFileInput::NotFound(path) => {
                        return ScanUsageTargetResolution::NotFound(not_found_input(
                            scan_usages_target_label(&target),
                            Some(format!(
                                "selector anchor `{path}` does not resolve to a workspace file"
                            )),
                        ));
                    }
                };
                if anchor_file != file {
                    return ScanUsageTargetResolution::NotFound(not_found_input(
                        scan_usages_target_label(&target),
                        Some(format!(
                            "selector anchor `{anchor}` does not match target path `{}`",
                            rel_path_string(&file)
                        )),
                    ));
                }
                Some(lookup)
            }
        },
    };

    let range_context = DeclarationNameRangeContext::new(&file, source);

    if let Some(overlay) = analyzer.semantic_model_overlay() {
        let path = rel_path_string(&file);
        let mut modeled = overlay
            .symbols_at_authored_path(&path)
            .records
            .into_iter()
            .filter(|symbol| {
                let crate::analyzer::semantic_model::SemanticModelLocation::Authored(anchor) =
                    &symbol.location
                else {
                    return false;
                };
                let range = crate::analyzer::Range {
                    start_byte: anchor.range.start_byte,
                    end_byte: anchor.range.end_byte,
                    start_line: anchor.range.start_line,
                    end_line: anchor.range.end_line,
                };
                scan_usages_target_matches_range(selection, range)
                    && selector.is_none_or(|requested| {
                        symbol.id == requested
                            || symbol.name == requested
                            || symbol.qualified_name == requested
                    })
            })
            .collect::<Vec<_>>();
        modeled.sort_by(|left, right| left.id.cmp(&right.id));
        modeled.dedup_by(|left, right| left.id == right.id);
        if modeled.len() == 1 && !modeled[0].provenance.ambiguous {
            let symbol = modeled[0];
            return ScanUsageTargetResolution::Modeled {
                symbol: symbol.qualified_name.clone(),
                definition: ResolvedUsageDefinition {
                    fq_name: symbol.qualified_name.clone(),
                    path,
                    line: symbol.location.range().start_line,
                },
            };
        }
        if !modeled.is_empty() {
            let candidate_targets = modeled
                .iter()
                .map(|symbol| symbol.qualified_name.clone())
                .collect::<Vec<_>>();
            return ScanUsageTargetResolution::Ambiguous(AmbiguousUsageSymbol {
                symbol: scan_usages_target_label(&target),
                short_name: target.symbol.clone().unwrap_or_default(),
                candidate_targets,
                candidate_details: Vec::new(),
                candidate_details_total: None,
                candidate_details_truncated: false,
                candidates: Vec::new(),
                candidate_files_truncated: false,
                definition_sites_excluded: None,
                note: Some(
                    "Ambiguous modeled location; provide an exact model declaration selector."
                        .to_owned(),
                ),
            });
        }
    }

    // The selector to match is an explicit parameter (not closed over) so the
    // same pool computation can be re-run with `selector_arg: None` below for
    // the not_found corrective hint, which asks "what's actually here" rather
    // than "what matches the caller's spelling".
    let location_units =
        |units: Vec<CodeUnit>,
         selector_arg: Option<&str>,
         matches_selector: &dyn Fn(&CodeUnit, &str) -> bool| {
            units
                .into_iter()
                .filter_map(|unit| {
                    let selector_matches =
                        selector_arg.is_some_and(|symbol| matches_selector(&unit, symbol));
                    let ranges = if selector_matches && unit.is_module() {
                        analyzer.location_ranges(&unit)
                    } else if selector_matches || selector_arg.is_none() {
                        range_context.location_name_ranges(analyzer, &unit)
                    } else {
                        return None;
                    };
                    let best_span = ranges
                        .into_iter()
                        .filter(|range| scan_usages_target_matches_range(selection, *range))
                        .map(|range| range.end_byte.saturating_sub(range.start_byte))
                        .min()?;
                    Some((unit, best_span))
                })
                .collect::<Vec<_>>()
        };

    // Exact selector forms (fq_name, definition_selector, and the display
    // symbol) are tried first; a bare identifier is accepted as a
    // location-pinned short name only in a second pass, and only when no
    // exact form matched anything at this location. This ordering is the
    // fix for #1231: without it, a short-name coincidence elsewhere in the
    // matching_units pool could out-narrow (or otherwise interfere with) a
    // genuine exact-selector match at the same location.
    let selector_matches_exact_form = |unit: &CodeUnit, symbol: &str| {
        unit.fq_name() == symbol
            || definition_selector(unit) == symbol
            || display_symbol_for_target(unit) == symbol
    };
    // Members' short_name is owner-qualified (`Widget.helper`), so bare-name
    // acceptance also matches the terminal segment: the location already pins
    // the target, making the bare terminal exactly as unambiguous for a method
    // as for a free function. Exact string equality on the structured
    // short_name convention's own `.` join - no source parsing.
    let selector_matches_short_name = |unit: &CodeUnit, symbol: &str| {
        let short_name = unit.short_name();
        short_name == symbol
            || short_name
                .rsplit_once('.')
                .is_some_and(|(_, terminal)| terminal == symbol)
    };

    let declarations_here = declarations_in_file(analyzer, &file);
    let mut matching_units = location_units(
        declarations_here.clone(),
        selector,
        &selector_matches_exact_form,
    );
    if matching_units.is_empty() && selector.is_some() {
        matching_units = location_units(
            declarations_here.clone(),
            selector,
            &selector_matches_short_name,
        );
    }
    if matching_units.is_empty()
        && let Some(symbol) = selector
    {
        let declarations = analyzer.location_declarations(&file);
        let lookup = AnalyzerDefinitionLookup::new(analyzer, language_for_file(&file));
        let lookup_only_candidates: Vec<CodeUnit> = lookup
            .fqn(symbol)
            .into_iter()
            .filter(|unit| {
                unit.source() == &file
                    && unit.is_field()
                    && analyzer.parent_of(unit).is_none()
                    && !declarations.contains(unit)
            })
            .collect();
        matching_units = location_units(
            lookup_only_candidates.clone(),
            selector,
            &selector_matches_exact_form,
        );
        if matching_units.is_empty() {
            matching_units = location_units(
                lookup_only_candidates,
                selector,
                &selector_matches_short_name,
            );
        }
    }

    if matching_units.is_empty() && selector.is_none() {
        return ScanUsageTargetResolution::NotFound(not_found_input(
            scan_usages_target_label(&target),
            Some(scan_usages_location_diagnostic(
                &target,
                range_context.content(),
                "no declaration at location",
            )),
        ));
    }

    if matching_units.is_empty()
        && let Some(symbol) = target.symbol.as_deref()
    {
        // The location itself resolves to a declaration, just not under this
        // spelling. Name the resolvable candidate so the corrective message
        // never reads as a bare refusal (I5-honesty, #1231): state that
        // selectors are fully-qualified, and offer what a line-only request
        // at this same location would have resolved to.
        let here = resolve_location_groups(
            analyzer,
            location_units(declarations_here, None, &selector_matches_exact_form),
            true,
        );
        let reason = match here.first() {
            Some((candidate, _)) => format!(
                "no declaration matching `{symbol}` at location; the declaration here is `{candidate}` \u{2014} selectors use fully-qualified names"
            ),
            None => format!(
                "no declaration matching `{symbol}` at location; selectors use fully-qualified names"
            ),
        };
        return ScanUsageTargetResolution::NotFound(not_found_input(
            scan_usages_target_label(&target),
            Some(scan_usages_location_diagnostic(
                &target,
                range_context.content(),
                &reason,
            )),
        ));
    }

    let groups = resolve_location_groups(analyzer, matching_units, selector.is_none());
    if groups.len() > 1 {
        let label = scan_usages_target_label(&target);
        return ScanUsageTargetResolution::Ambiguous(ambiguous_usage_symbol_from_groups(
            analyzer,
            ScanUsagesSurface::Location,
            label.clone(),
            label,
            groups,
            "Ambiguous location; refine the line/column target.",
        ));
    }

    let (_, overloads) = groups
        .into_iter()
        .next()
        .expect("non-empty target groups: matching_units was checked non-empty above");
    let symbol = definition_selector(&overloads[0]);
    ScanUsageTargetResolution::Resolved { symbol, overloads }
}

/// Narrow a location-matched pool (`CodeUnit`, byte-span-of-narrowest-matching-range)
/// to the narrowest span, optionally drop synthetic identities that share a
/// source declaration's name range (see the doc comment at the call site),
/// and partition what remains into distinct selectable definitions via
/// [`distinct_definitions`]. Shared by the main resolution path and the
/// not_found corrective hint so both report exactly the same candidate for
/// the same location.
fn resolve_location_groups(
    analyzer: &dyn IAnalyzer,
    pool: Vec<(CodeUnit, usize)>,
    filter_synthetic: bool,
) -> Vec<(String, Vec<CodeUnit>)> {
    let Some(narrowest_span) = pool.iter().map(|(_, span)| *span).min() else {
        return Vec::new();
    };
    let mut matches: Vec<CodeUnit> = pool
        .into_iter()
        .filter_map(|(unit, span)| (span == narrowest_span).then_some(unit))
        .collect();

    // A source-backed synthetic identity may intentionally share its declaration
    // name range with the source declaration that owns it. Scala primary
    // constructors are the current example: `class Service(value: String)`
    // defines both the `Service` type and a synthetic `Service.Service`
    // constructor at the `Service` token. A plain location target selects the
    // source declaration, while an explicit `symbol` selector can still request
    // the synthetic identity.
    if filter_synthetic && matches.iter().any(|unit| !unit.is_synthetic()) {
        matches.retain(|unit| !unit.is_synthetic());
    }

    matches.sort_by(|left, right| {
        primary_range(analyzer, left)
            .map(|range| (range.start_line, range.start_byte))
            .cmp(&primary_range(analyzer, right).map(|range| (range.start_line, range.start_byte)))
            .then_with(|| left.fq_name().cmp(&right.fq_name()))
    });

    distinct_definitions(analyzer, matches)
}

pub(super) fn scan_usages_location_diagnostic(
    target: &ScanUsagesTarget,
    source: &str,
    reason: &str,
) -> String {
    render_location_diagnostic(
        source,
        &target.path,
        target.line,
        target.column,
        reason,
        "move the target to a declaration name token and retry scan_usages_by_location; use get_summaries on the file or search_symbols if the declaration location is unknown.",
    )
}

pub(super) fn declarations_in_file(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Vec<CodeUnit> {
    let mut declarations: Vec<CodeUnit> = analyzer
        .location_declarations(file)
        .into_iter()
        .filter(|unit| unit.source() == file)
        .collect();
    let mut stack = declarations.clone();
    while let Some(unit) = stack.pop() {
        for child in analyzer.get_members_in_class(&unit) {
            if child.source() != file {
                continue;
            }
            stack.push(child.clone());
            declarations.push(child);
        }
    }
    declarations
}

pub(super) fn scan_usages_target_matches_range(
    selection: ScanUsagesLocationSelection,
    range: Range,
) -> bool {
    match selection {
        ScanUsagesLocationSelection::Point(point) => {
            range.start_byte <= point && range.end_byte > point
        }
        ScanUsagesLocationSelection::Line(line) => {
            let zero_based_line = line - 1;
            range.start_line <= zero_based_line && range.end_line >= zero_based_line
        }
    }
}

pub(super) fn retain_hits_resolving_to_overloads(
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    hits: Vec<UsageHit>,
    cancellation: &CancellationToken,
) -> (Vec<UsageHit>, bool) {
    if hits.is_empty() || overloads.is_empty() {
        return (hits, true);
    }

    let mut retained = Vec::new();
    // Keep the non-cancellable definition resolver slices deliberately small;
    // the shared request token is checked between slices.
    for chunk in hits.chunks(8) {
        if cancellation.is_cancelled() {
            return (retained, false);
        }
        let requests = chunk
            .iter()
            .map(
                |hit| crate::analyzer::usages::get_definition::DefinitionLookupRequest {
                    file: hit.file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(hit.start_offset),
                    end_byte: Some(hit.end_offset),
                },
            )
            .collect();
        let outcomes =
            crate::analyzer::usages::get_definition::resolve_definition_batch(analyzer, requests);
        retained.extend(
            chunk
                .iter()
                .cloned()
                .zip(outcomes)
                .filter_map(|(hit, outcome)| {
                    (!outcome.definitions.is_empty()
                        && outcome
                            .definitions
                            .iter()
                            .any(|definition| overloads.contains(definition))
                        || (outcome.definitions.is_empty()
                            && unresolved_hit_matches_target_shape(analyzer, overloads, &hit)))
                    .then_some(hit)
                }),
        );
    }
    (retained, !cancellation.is_cancelled())
}

pub(super) fn resolved_usage_definition(
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
) -> Option<ResolvedUsageDefinition> {
    overloads
        .iter()
        .filter_map(|unit| {
            let range = primary_range(analyzer, unit)?;
            Some((unit, range))
        })
        .min_by(|(left, left_range), (right, right_range)| {
            rel_path_string(left.source())
                .cmp(&rel_path_string(right.source()))
                .then_with(|| left_range.start_line.cmp(&right_range.start_line))
                .then_with(|| left_range.start_byte.cmp(&right_range.start_byte))
                .then_with(|| left.fq_name().cmp(&right.fq_name()))
        })
        .map(|(unit, range)| ResolvedUsageDefinition {
            fq_name: unit.fq_name(),
            path: rel_path_string(unit.source()),
            line: range.start_line,
        })
}

pub(super) fn unresolved_hit_matches_target_shape(
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    hit: &UsageHit,
) -> bool {
    let hit_is_member_access = usage_hit_is_member_access(analyzer, hit);
    overloads.iter().any(|unit| {
        declaration_is_member_access(analyzer, unit)
            .map(|is_member| is_member == hit_is_member_access)
            .unwrap_or(true)
    })
}

pub(super) fn usage_hit_is_member_access(analyzer: &dyn IAnalyzer, hit: &UsageHit) -> bool {
    // `hit.start_offset` was produced by the analyzer's own usage scan, so
    // it is only meaningful against the same analyzed snapshot.
    source_has_dot_before(
        analyzer.indexed_source(&hit.file).as_deref(),
        hit.start_offset,
    )
}

pub(super) fn declaration_is_member_access(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> Option<bool> {
    let range = primary_range(analyzer, unit)?;
    let source = analyzer.indexed_source(unit.source())?;
    let identifier_offset = source
        .get(range.start_byte..range.end_byte)?
        .find(unit.identifier())
        .map(|offset| range.start_byte + offset)?;
    Some(source_has_dot_before(Some(&source), identifier_offset))
}

pub(super) fn source_has_dot_before(source: Option<&str>, byte: usize) -> bool {
    let Some(source) = source else {
        return false;
    };
    source
        .get(..byte.min(source.len()))
        .and_then(|prefix| prefix.chars().rev().find(|ch| !ch.is_whitespace()))
        == Some('.')
}

pub(super) fn present_reference_only_sibling_extensions_by_language(
    analyzer: &dyn IAnalyzer,
) -> BTreeMap<Language, Vec<&'static str>> {
    let mut present = BTreeMap::new();
    let Ok(files) = analyzer.project().all_files() else {
        return present;
    };

    let mut workspace_extensions = HashSet::default();
    for file in files {
        if let Some(extension) = file
            .rel_path()
            .extension()
            .and_then(|extension| extension.to_str())
        {
            workspace_extensions.insert(extension.to_ascii_lowercase());
        }
    }

    for language in Language::ANALYZABLE {
        let language_present = language
            .reference_only_sibling_extensions()
            .iter()
            .copied()
            .filter(|extension| workspace_extensions.contains(*extension))
            .collect::<Vec<_>>();
        if !language_present.is_empty() {
            present.insert(language, language_present);
        }
    }

    present
}

pub(super) fn reference_only_absence_note(
    overloads: &[CodeUnit],
    present_by_language: &BTreeMap<Language, Vec<&'static str>>,
) -> Option<String> {
    let language = overloads.first().map(language_for_target)?;
    let extensions = present_by_language.get(&language)?;
    let extension_list = extensions
        .iter()
        .map(|extension| format!(".{extension}"))
        .collect::<Vec<_>>()
        .join("/");
    Some(format!(
        "workspace contains {extension_list} files that may reference this symbol but are not analyzed; inspect or analyze those files separately before concluding absence"
    ))
}

pub fn scan_usages_by_reference(
    analyzer: &dyn IAnalyzer,
    params: ScanUsagesByReferenceParams,
) -> ScanUsagesResult {
    scan_usages_by_reference_with_cancellation(analyzer, params, CancellationToken::default())
}

pub fn scan_usages_by_reference_with_cancellation(
    analyzer: &dyn IAnalyzer,
    params: ScanUsagesByReferenceParams,
    cancellation: CancellationToken,
) -> ScanUsagesResult {
    let max_duration = params.max_duration_secs.map(Duration::from_secs);
    scan_usages_by_reference_with_context(
        analyzer,
        params,
        &ScanUsagesExecutionContext::with_cancellation_and_max_duration(cancellation, max_duration),
    )
}

pub(crate) fn scan_usages_by_reference_with_context(
    analyzer: &dyn IAnalyzer,
    params: ScanUsagesByReferenceParams,
    context: &ScanUsagesExecutionContext,
) -> ScanUsagesResult {
    let symbols = params
        .symbols
        .into_iter()
        .enumerate()
        .map(|(index, symbol)| ScanUsageRequest::symbol(index, symbol))
        .collect();
    let mut result = scan_usages_backend(
        analyzer,
        ScanUsagesSurface::Reference,
        params.include_tests,
        params.paths.as_deref(),
        symbols,
        Vec::new(),
        params.include_same_owner,
        context,
    );
    attach_model_relations(analyzer, &mut result);
    result
}

pub fn scan_usages_by_location(
    analyzer: &dyn IAnalyzer,
    params: ScanUsagesByLocationParams,
) -> ScanUsagesResult {
    scan_usages_by_location_with_cancellation(analyzer, params, CancellationToken::default())
}

pub fn scan_usages_by_location_with_cancellation(
    analyzer: &dyn IAnalyzer,
    params: ScanUsagesByLocationParams,
    cancellation: CancellationToken,
) -> ScanUsagesResult {
    let max_duration = params.max_duration_secs.map(Duration::from_secs);
    scan_usages_by_location_with_context(
        analyzer,
        params,
        &ScanUsagesExecutionContext::with_cancellation_and_max_duration(cancellation, max_duration),
    )
}

pub(crate) fn scan_usages_by_location_with_context(
    analyzer: &dyn IAnalyzer,
    params: ScanUsagesByLocationParams,
    context: &ScanUsagesExecutionContext,
) -> ScanUsagesResult {
    let targets = params
        .targets
        .into_iter()
        .enumerate()
        .map(|(index, target)| ScanUsageRequest::target(index, target))
        .collect();
    let mut result = scan_usages_backend(
        analyzer,
        ScanUsagesSurface::Location,
        params.include_tests,
        params.paths.as_deref(),
        Vec::new(),
        targets,
        params.include_same_owner,
        context,
    );
    attach_model_relations(analyzer, &mut result);
    result
}

#[allow(clippy::too_many_arguments)]
pub(super) fn scan_usages_backend(
    analyzer: &dyn IAnalyzer,
    surface: ScanUsagesSurface,
    include_tests: bool,
    paths: Option<&[String]>,
    symbols: Vec<ScanUsageRequest>,
    targets: Vec<ScanUsageRequest>,
    include_same_owner: bool,
    context: &ScanUsagesExecutionContext,
) -> ScanUsagesResult {
    let _scope = profiling::scope("searchtools::scan_usages_backend");
    // A batch is one read-only analyzer request. Keep the read cache alive across
    // target resolution and every per-target UsageFinder query so later targets
    // reuse hydrated file states and prepared syntax from earlier targets. The
    // finder's nested query scopes remain useful for standalone callers; nested
    // scopes do not clear the cache while this outer scope is active.
    let _analyzer_query = AnalyzerQueryScope::new(analyzer);

    let query_scope = ScanUsagesQueryScope::new(analyzer, paths, include_tests);
    if context.cancellation.is_cancelled() {
        let mut entries = incomplete_requests(symbols, targets, context.interruption_reason());
        entries.sort_by_key(ScanUsagesWorkEntry::index);
        return render_scan_usages_with_budget(entries, query_scope.result_scope(), surface);
    }

    // When the caller scopes the query to `paths`, the answer can only live in those files, so
    // resolve the candidate set straight from them instead of enumerating references across the
    // whole workspace and filtering after the fact. This bounds the search by the number of
    // `paths`, not by how common the symbols are — a single high-fan-in name (`Context`, `func`)
    // no longer drags an O(workspace) reference scan behind it. The set is built once and reused
    // for every symbol; the finder's file filter still drops excluded test files on top.
    let path_scoped_candidates = query_scope.path_filter.as_ref().map(|filter| {
        let _scope = profiling::scope("searchtools::scan_usages_path_candidates");
        let mut files = HashSet::default();
        for file in analyzer.analyzed_files() {
            if context.cancellation.is_cancelled() {
                break;
            }
            if filter.matches(&file) {
                files.insert(file);
            }
        }
        ExplicitCandidateProvider::new(Arc::new(files))
    });

    if context.cancellation.is_cancelled() {
        let mut entries = incomplete_requests(symbols, targets, context.interruption_reason());
        entries.sort_by_key(ScanUsagesWorkEntry::index);
        return render_scan_usages_with_budget(entries, query_scope.result_scope(), surface);
    }

    let test_files = excluded_test_files(analyzer, include_tests);
    if context.cancellation.is_cancelled() {
        let mut entries = incomplete_requests(symbols, targets, context.interruption_reason());
        entries.sort_by_key(ScanUsagesWorkEntry::index);
        return render_scan_usages_with_budget(entries, query_scope.result_scope(), surface);
    }
    let reference_only_sibling_extensions =
        present_reference_only_sibling_extensions_by_language(analyzer);
    if context.cancellation.is_cancelled() {
        let mut entries = incomplete_requests(symbols, targets, context.interruption_reason());
        entries.sort_by_key(ScanUsagesWorkEntry::index);
        return render_scan_usages_with_budget(entries, query_scope.result_scope(), surface);
    }

    let mut work_entries = Vec::new();
    let mut resolved_targets = Vec::new();

    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);
    for request in targets {
        if context.cancellation.is_cancelled() {
            work_entries.push(incomplete_work_entry(
                request,
                None,
                context.interruption_reason(),
            ));
            continue;
        }
        let target = match &request.input {
            ScanUsagesInput::Target(target) => target.clone(),
            ScanUsagesInput::Symbol(_) => unreachable!("target request has target input"),
        };
        let resolution = {
            let _scope = profiling::scope("searchtools::scan_usages_target_resolution");
            resolve_scan_usages_target(analyzer, &resolver, target)
        };
        if context.cancellation.is_cancelled() {
            work_entries.push(incomplete_work_entry(
                request,
                None,
                context.interruption_reason(),
            ));
            continue;
        }
        match resolution {
            ScanUsageTargetResolution::Resolved { symbol, overloads } => {
                resolved_targets.push(IndexedResolvedScanTarget {
                    request,
                    symbol,
                    overloads,
                    location_selected: true,
                });
            }
            ScanUsageTargetResolution::Modeled { symbol, definition } => {
                work_entries.push(ScanUsagesWorkEntry::Usage {
                    request,
                    state: SymbolUsageRenderState::new(
                        symbol,
                        Some(definition),
                        false,
                        0,
                        Vec::new(),
                        0,
                        Vec::new(),
                        None,
                        None,
                        Vec::new(),
                        include_same_owner,
                    ),
                    candidate_files_sample: None,
                    target_is_method: false,
                    incomplete_reason: None,
                });
            }
            ScanUsageTargetResolution::NotFound(item) => {
                work_entries.push(ScanUsagesWorkEntry::NotFound { request, item });
            }
            ScanUsageTargetResolution::Ambiguous(item) => {
                work_entries.push(ScanUsagesWorkEntry::Ambiguous {
                    request,
                    item,
                    incomplete_reason: None,
                });
            }
            ScanUsageTargetResolution::Failure(failure) => {
                work_entries.push(ScanUsagesWorkEntry::Failure {
                    request,
                    failure,
                    incomplete_reason: None,
                });
            }
        }
    }

    for request in symbols {
        let symbol = request.label.clone();
        if context.cancellation.is_cancelled() {
            work_entries.push(incomplete_work_entry(
                request,
                Some(symbol),
                context.interruption_reason(),
            ));
            continue;
        }
        if symbol.trim().is_empty() {
            work_entries.push(ScanUsagesWorkEntry::NotFound {
                request,
                item: NotFoundInput {
                    input: symbol,
                    note: Some("symbol must not be empty".to_string()),
                },
            });
            continue;
        }
        let (anchor, lookup) = match split_workspace_definition_selector(analyzer, &symbol) {
            DefinitionSelector::Name(name) => (None, name),
            DefinitionSelector::FileAnchored { anchor, lookup } => (Some(anchor), lookup),
        };
        let resolution = {
            let _scope = profiling::scope("searchtools::scan_usages_symbol_resolution");
            resolve_codeunit_fuzzy(analyzer, lookup)
        };
        if context.cancellation.is_cancelled() {
            work_entries.push(incomplete_work_entry(
                request,
                Some(symbol),
                context.interruption_reason(),
            ));
            continue;
        }
        let overloads = match resolution {
            CodeUnitResolution::Resolved(overloads) => overloads,
            CodeUnitResolution::Ambiguous(candidate_targets) => {
                let groups = distinct_definitions(analyzer, candidate_targets);
                let item = ambiguous_usage_symbol_from_groups(
                    analyzer,
                    ScanUsagesSurface::Reference,
                    symbol.clone(),
                    symbol,
                    groups,
                    "Ambiguous; re-call scan_usages_by_reference with one symbol from candidate_targets.",
                );
                work_entries.push(ScanUsagesWorkEntry::Ambiguous {
                    request,
                    item,
                    incomplete_reason: None,
                });
                continue;
            }
            CodeUnitResolution::NotFound => {
                let item = unsupported_path_qualified_scan_symbol(&resolver, &symbol)
                    .unwrap_or_else(|| {
                        path_like_symbol_not_found_input(
                            symbol.clone(),
                            PathLikeSymbolGuidanceContext::ScanUsages,
                        )
                    });
                work_entries.push(ScanUsagesWorkEntry::NotFound { request, item });
                continue;
            }
        };

        let overloads = match anchor {
            // A file-anchored selector picks one definition from a prior
            // ambiguous result; narrow to that file before scanning.
            Some(anchor) => {
                let not_found =
                    scan_usages_anchor_not_found_input(symbol.clone(), &anchor, lookup, &overloads);
                let narrowed: Vec<CodeUnit> = overloads
                    .into_iter()
                    .filter(|unit| rel_path_string(unit.source()) == anchor)
                    .collect();
                let narrowed = prefer_exact_lookup_matches(narrowed, lookup);
                if narrowed.is_empty() {
                    work_entries.push(ScanUsagesWorkEntry::NotFound {
                        request,
                        item: not_found,
                    });
                    continue;
                }
                narrowed
            }
            // A bare name resolving to module-scoped definitions in different
            // files (two JS/TS files exporting `Anchor`) is several distinct
            // symbols, not one with overloads; surface them as selectable
            // candidates rather than scanning a conflation of all of them.
            None => {
                let groups = distinct_definitions(analyzer, overloads);
                if groups.len() > 1 {
                    let item = ambiguous_usage_symbol_from_groups(
                        analyzer,
                        ScanUsagesSurface::Reference,
                        symbol.clone(),
                        symbol,
                        groups,
                        "Ambiguous; re-call scan_usages_by_reference with one symbol from candidate_targets.",
                    );
                    work_entries.push(ScanUsagesWorkEntry::Ambiguous {
                        request,
                        item,
                        incomplete_reason: None,
                    });
                    continue;
                }
                groups.into_iter().flat_map(|(_, units)| units).collect()
            }
        };

        resolved_targets.push(IndexedResolvedScanTarget {
            request,
            symbol,
            overloads,
            location_selected: false,
        });
    }

    for resolved in resolved_targets {
        let IndexedResolvedScanTarget {
            request,
            symbol,
            overloads,
            location_selected,
        } = resolved;
        if context.cancellation.is_cancelled() {
            work_entries.push(incomplete_work_entry(
                request,
                Some(symbol),
                context.interruption_reason(),
            ));
            continue;
        }
        let resolved_definition = resolved_usage_definition(analyzer, &overloads);
        let target_is_method = overloads
            .iter()
            .any(|unit| unit.is_function() && display_parent_symbol_for_target(unit).is_some());
        let finder = scoped_usage_finder(test_files.as_ref(), query_scope.path_filter.as_ref())
            .with_cancellation(context.cancellation.clone());
        let max_candidate_files = if path_scoped_candidates.is_some() {
            context.max_path_scoped_candidate_files
        } else {
            context.max_candidate_files
        };
        let query = finder.query_with_provider_and_source_budget(
            analyzer,
            &overloads,
            path_scoped_candidates
                .as_ref()
                .map(|provider| provider as &dyn CandidateFileProvider),
            max_candidate_files,
            context.max_callsites,
            Some(context.max_source_bytes),
        );
        let interrupted = context.cancellation.is_cancelled();
        let interruption_reason = context.interruption_reason();
        let mut incomplete_reason = if interrupted {
            Some(interruption_reason)
        } else {
            query_incomplete_reason(query.completion, interruption_reason)
        };
        // An interrupted scan that already proved sites reports them as a
        // partial usage entry. Collapsing to an Incomplete entry here would
        // render "0 usages" for a symbol we know is referenced.
        if matches!(
            incomplete_reason,
            Some(ScanUsagesIncompleteReason::Cancelled | ScanUsagesIncompleteReason::TimeBudget)
        ) && !fuzzy_result_has_hits(&query.result)
        {
            work_entries.push(incomplete_work_entry(
                request,
                Some(symbol),
                incomplete_reason.expect("interruption reason is present"),
            ));
            continue;
        }
        let truncated = query.candidate_files_truncated;
        let candidate_files_sample =
            query
                .candidate_files_sample
                .as_ref()
                .map(|sample| ScanUsagesCandidateFilesSample {
                    scanned: sample.scanned.iter().map(rel_path_string).collect(),
                    omitted: sample.omitted.iter().map(rel_path_string).collect(),
                    omitted_count: sample.omitted_count,
                });

        match query.result {
            FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
            } => {
                let hits: Vec<UsageHit> = hits_by_overload
                    .into_values()
                    .flat_map(BTreeSet::into_iter)
                    .collect();
                let filtered = filter_and_dedupe_hits(analyzer, &overloads, hits);
                let unproven_total = unproven_total_by_overload.values().sum();
                let unproven_hits: Vec<UsageHit> = unproven_by_overload
                    .into_values()
                    .flat_map(BTreeSet::into_iter)
                    .collect();
                let filtered_unproven = filter_and_dedupe_hits(analyzer, &overloads, unproven_hits);
                let definition_sites_excluded = filtered
                    .definition_sites_excluded
                    .saturating_add(filtered_unproven.definition_sites_excluded);

                let state = SymbolUsageRenderState::new(
                    symbol,
                    resolved_definition.clone(),
                    truncated,
                    definition_sites_excluded,
                    filtered.hits,
                    unproven_total,
                    filtered_unproven.hits,
                    None,
                    reference_only_absence_note(&overloads, &reference_only_sibling_extensions),
                    filtered.same_owner,
                    include_same_owner,
                );
                work_entries.push(ScanUsagesWorkEntry::Usage {
                    request,
                    state,
                    candidate_files_sample,
                    target_is_method,
                    incomplete_reason,
                });
            }
            FuzzyResult::Ambiguous {
                short_name,
                candidate_targets,
                hits_by_overload,
            } => {
                if location_selected {
                    let hits: Vec<UsageHit> = overloads
                        .iter()
                        .flat_map(|code_unit| {
                            hits_by_overload
                                .get(code_unit)
                                .into_iter()
                                .flat_map(|hits| hits.iter().cloned())
                        })
                        .collect();
                    let (hits, resolution_complete) = retain_hits_resolving_to_overloads(
                        analyzer,
                        &overloads,
                        hits,
                        &context.cancellation,
                    );
                    if !resolution_complete {
                        incomplete_reason = Some(context.interruption_reason());
                        if hits.is_empty() {
                            work_entries.push(incomplete_work_entry(
                                request,
                                Some(symbol),
                                incomplete_reason.expect("interruption reason is present"),
                            ));
                            continue;
                        }
                    }
                    let filtered = filter_and_dedupe_hits(analyzer, &overloads, hits);
                    let state = SymbolUsageRenderState::new(
                        symbol,
                        resolved_definition.clone(),
                        truncated,
                        filtered.definition_sites_excluded,
                        filtered.hits,
                        0,
                        Vec::new(),
                        None,
                        reference_only_absence_note(&overloads, &reference_only_sibling_extensions),
                        filtered.same_owner,
                        include_same_owner,
                    );
                    work_entries.push(ScanUsagesWorkEntry::Usage {
                        request,
                        state,
                        candidate_files_sample,
                        target_is_method,
                        incomplete_reason,
                    });
                    continue;
                }
                let groups =
                    distinct_definitions(analyzer, candidate_targets.iter().cloned().collect());
                let surface = request.surface;
                let detail_source = ambiguous_usage_symbol_from_groups(
                    analyzer,
                    surface,
                    symbol.clone(),
                    short_name.clone(),
                    groups.clone(),
                    scan_usages_ambiguity_note(surface),
                );
                let deduped_targets: Vec<String> = groups
                    .iter()
                    .map(|(selector, _)| selector.clone())
                    .collect();
                let mut candidates = Vec::new();
                let mut definition_sites_excluded = 0usize;
                for (target, grouped_overloads) in groups {
                    let grouped_hits: Vec<UsageHit> = grouped_overloads
                        .iter()
                        .flat_map(|code_unit| {
                            hits_by_overload
                                .get(code_unit)
                                .into_iter()
                                .flat_map(|hits| hits.iter().cloned())
                        })
                        .filter(|hit| hit.confidence >= CONFIDENCE_THRESHOLD)
                        .collect();
                    let filtered =
                        filter_and_dedupe_hits(analyzer, &grouped_overloads, grouped_hits);
                    definition_sites_excluded += filtered.definition_sites_excluded;
                    candidates.push(AmbiguousUsageCandidate {
                        target,
                        total_hits: filtered.hits.len(),
                    });
                }
                let item = AmbiguousUsageSymbol {
                    symbol,
                    short_name,
                    candidate_targets: deduped_targets,
                    candidate_details: detail_source.candidate_details,
                    candidate_details_total: detail_source.candidate_details_total,
                    candidate_details_truncated: detail_source.candidate_details_truncated,
                    candidates,
                    candidate_files_truncated: truncated,
                    definition_sites_excluded: some_if_nonzero(definition_sites_excluded),
                    note: detail_source.note,
                };
                work_entries.push(ScanUsagesWorkEntry::Ambiguous {
                    request,
                    item,
                    incomplete_reason,
                });
            }
            FuzzyResult::Failure {
                fq_name,
                reason_kind,
                reason,
            } => {
                let reason = if reason_kind == "unsupported_target_shape" {
                    unsupported_target_shape_message(overloads.first())
                } else {
                    reason
                };
                let failure = UsageFailureInfo {
                    symbol,
                    fq_name,
                    hint: usage_failure_hint(
                        request.surface,
                        &reason_kind,
                        overloads.first(),
                        location_selected,
                        truncated,
                    ),
                    reason_kind,
                    reason,
                    candidate_files_truncated: truncated,
                    candidate_files_sample,
                };
                work_entries.push(ScanUsagesWorkEntry::Failure {
                    request,
                    failure,
                    incomplete_reason,
                });
            }
            FuzzyResult::TooManyCallsites {
                short_name,
                total_callsites,
                limit,
                sample_hits,
            } => {
                let filtered =
                    filter_and_dedupe_hits(analyzer, &overloads, sample_hits.into_iter().collect());
                let state = SymbolUsageRenderState::partial_summary(
                    symbol.clone(),
                    resolved_definition.clone(),
                    total_callsites,
                    truncated,
                    filtered.definition_sites_excluded,
                    filtered.hits,
                    0,
                    Vec::new(),
                    Some(too_many_callsites_summary_note(limit)),
                    reference_only_absence_note(&overloads, &reference_only_sibling_extensions),
                    filtered.same_owner,
                    include_same_owner,
                );
                work_entries.push(ScanUsagesWorkEntry::TooManyCallsites {
                    request,
                    state,
                    short_name,
                    total_callsites,
                    limit,
                    target_is_method,
                });
            }
        }
    }

    work_entries.sort_by_key(ScanUsagesWorkEntry::index);
    render_scan_usages_with_budget(work_entries, query_scope.result_scope(), surface)
}

/// A definition node in the workspace usage graph.
///
/// Nodes are the classes and functions (methods included) that a consumer can
/// run PageRank or another centrality analysis over. Fields, modules, and
/// macros are intentionally excluded to keep the graph focused on the
/// call/reference structure a code map cares about. `(language, fqn)` is the
/// node identity (plus `path` for file-scoped ecosystems like JS/TS), so the
/// same fqn in two languages — or two files of one module-scoped language —
/// stays distinct nodes; `fqn` matches the names returned by [`search_symbols`].
#[derive(Debug, Clone, Serialize)]
pub struct UsageGraphNode {
    pub fqn: String,
    /// The language ecosystem the node belongs to (JS and TS share one). Part of
    /// the node identity so the same fqn in two languages stays two nodes; for
    /// file-scoped ecosystems (JavaScript/TypeScript) the `path` also
    /// participates, so two files exporting the same name stay two nodes.
    pub language: String,
    pub path: String,
    pub start_line: usize,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// One concrete reference site behind a [`UsageGraphEdge`]: the workspace-relative
/// file `path` and the 1-based `line` where the reference occurs. Lines match the
/// `line` of a [`scan_usages`] hit and a node's `start_line`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct UsageGraphCallSite {
    pub path: String,
    pub line: usize,
}

/// A directed edge from a caller to a callee, aggregated across call sites.
///
/// `from` and `to` are fully qualified names: `from` is the enclosing
/// definition of each reference, `to` is the symbol being referenced. `weight`
/// is the number of distinct `(file, line, caller)` reference sites, which
/// mirrors the reference-count weighting an aider-style repo map uses (two
/// references to the same callee on one line count once).
///
/// `sites` lists those reference locations (`{path, line}`), so a consumer can
/// build a caller→callee map *with* call sites instead of re-scraping them;
/// `sites.len() == weight`. Per-site snippets remain the domain of [`scan_usages`].
#[derive(Debug, Clone, Serialize)]
pub struct UsageGraphEdge {
    pub from: String,
    pub to: String,
    /// The language ecosystem both endpoints belong to — disambiguates `from`/`to`
    /// when the same fqn exists in more than one language.
    pub language: String,
    pub weight: usize,
    /// Reference locations for this edge, sorted by `(path, line)`. One per distinct
    /// `(file, line, caller)` site, so `sites.len() == weight`.
    pub sites: Vec<UsageGraphCallSite>,
}

/// A symbol whose call sites exceeded the analyzer's enumeration guardrail.
///
/// These symbols still appear in `nodes`; only their inbound edges are omitted,
/// because the analyzer stopped before enumerating every caller. Surfacing them
/// lets a consumer decide whether to re-query the hot symbol with a narrower
/// `paths` scope. Mirrors the `too_many_callsites` signal from [`scan_usages`].
#[derive(Debug, Clone, Serialize)]
pub struct UsageGraphTruncatedSymbol {
    pub fqn: String,
    pub language: String,
    pub total_callsites: usize,
    pub limit: usize,
}

/// The resolved definition/reference graph for the whole workspace.
#[derive(Debug, Clone, Serialize)]
pub struct UsageGraphResult {
    pub nodes: Vec<UsageGraphNode>,
    pub edges: Vec<UsageGraphEdge>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub truncated_symbols: Vec<UsageGraphTruncatedSymbol>,
}

/// Build the whole-workspace resolved usage graph: classes and functions as
/// nodes, caller -> callee references as weighted edges.
///
/// This is the bulk counterpart to [`scan_usages`]. Where `scan_usages` answers
/// "who calls this one symbol" with per-call-site detail, `usage_graph` walks
/// every class and function once and returns the aggregated graph, so a consumer
/// can run PageRank (or another ranking) to build a code map without issuing one
/// `scan_usages` call per symbol.
///
/// Edges reuse the same graph-backed resolution path as `scan_usages` and the
/// same definition-site exclusion, so a
/// definition's own declaration never counts as a reference to itself. Self
/// references (a recursive call whose enclosing definition *is* the callee) are
/// dropped because they do not affect centrality ranking. Every edge endpoint
/// is guaranteed to be a node: a reference whose enclosing caller is not itself
/// a class or function (a module- or field-level call site) is dropped, so the
/// nodes and edges can be loaded into a graph library without phantom nodes.
///
/// This is a full-workspace pass and is proportional to the number of
/// definitions, so consumers are expected to cache the result and rebuild it
/// only when the workspace changes.
pub fn usage_graph(analyzer: &dyn IAnalyzer, params: UsageGraphParams) -> UsageGraphResult {
    let _scope = profiling::scope("searchtools::usage_graph");

    let path_filter = build_scan_usages_path_filter(analyzer, params.paths.as_deref()).filter;
    let test_files = excluded_test_files(analyzer, params.include_tests);

    // Build node identity once and share it with the internal relevance graph.
    // The catalog collapses overloads, keeps JS/TS declarations file-scoped, and
    // chooses deterministic primary declarations using analyzer-provided ranges.
    let catalog = WorkspaceUsageCatalog::build(analyzer);
    let mut nodes: Vec<UsageGraphNode> = catalog
        .nodes
        .iter()
        .map(|node| UsageGraphNode {
            fqn: node.key.fqn.clone(),
            // The node's own source language, not its realm: sharing a
            // candidate space must not cost a consumer the ability to tell
            // Java from Scala from Kotlin.
            language: node.language_label().to_string(),
            path: rel_path_string(node.primary.source()),
            start_line: node
                .primary_range
                .map(|range| range.start_line)
                .unwrap_or(0),
            kind: code_unit_kind_name(node.primary.kind()).to_string(),
            signature: node.primary.signature().map(str::to_string),
        })
        .collect();

    // Edges keyed by `(ecosystem, from_fqn, to_fqn)`: both endpoints share the
    // builder's ecosystem, so the ecosystem disambiguates a fqn that exists in
    // more than one language. The value is the edge's call sites; its length is the
    // edge weight (so weight and sites can never disagree).
    let mut edge_sites: BTreeMap<(UsageEcosystem, String, String), Vec<UsageGraphCallSite>> =
        BTreeMap::new();
    let mut truncated_symbols: Vec<UsageGraphTruncatedSymbol> = Vec::new();

    // Go edges in a single inverted pass over the workspace: walk each file once
    // and resolve every reference to its callee, instead of scanning every
    // symbol's candidate files (quadratic on real repos). A caller file is in
    // scope only when it survives the test / path filter, matching the per-symbol
    // candidate filter.
    let keep_file = |file: &ProjectFile| {
        test_files
            .as_ref()
            .map(|excluded| !excluded.contains(file))
            .unwrap_or(true)
            && path_filter
                .as_ref()
                .map(|filter| filter.matches(file))
                .unwrap_or(true)
    };
    // Every supported language has a whole-workspace inverted builder, so all
    // edges are produced by the passes below; merge each one's result in.
    let record_inverted =
        |ecosystem: UsageEcosystem,
         edges: Option<crate::analyzer::usages::inverted_edges::UsageEdges>,
         edge_sites: &mut BTreeMap<(UsageEcosystem, String, String), Vec<UsageGraphCallSite>>,
         truncated_symbols: &mut Vec<UsageGraphTruncatedSymbol>| {
            let Some(edges) = edges else {
                return;
            };
            for ((from, to), sites) in edges.edges {
                edge_sites
                    .entry((ecosystem, from, to))
                    .or_default()
                    .extend(sites.into_iter().map(|site| UsageGraphCallSite {
                        path: site.path,
                        line: site.line,
                    }));
            }
            for (fqn, total_callsites) in edges.truncated {
                truncated_symbols.push(UsageGraphTruncatedSymbol {
                    fqn,
                    language: ecosystem.as_str().to_string(),
                    total_callsites,
                    limit: crate::analyzer::usages::inverted_edges::MAX_CALLSITES,
                });
            }
        };
    {
        let _scope = profiling::scope("usage_graph::resolve_go");
        let go_edges = crate::analyzer::usages::go_graph::build_go_usage_edges(
            analyzer,
            catalog.fqns(UsageEcosystem::Go),
            keep_file,
        );
        record_inverted(
            UsageEcosystem::Go,
            go_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_jsts");
        let jsts_edges = crate::analyzer::usages::js_ts_graph::build_jsts_usage_edges(
            analyzer,
            catalog.fqns(UsageEcosystem::JavaScriptTypeScript),
            keep_file,
        );
        record_inverted(
            UsageEcosystem::JavaScriptTypeScript,
            jsts_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_python");
        let python_edges = crate::analyzer::usages::python_graph::build_python_usage_edges(
            analyzer,
            catalog.fqns(UsageEcosystem::Python),
            keep_file,
        );
        record_inverted(
            UsageEcosystem::Python,
            python_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_rust");
        let rust_edges = crate::analyzer::usages::rust_graph::build_rust_usage_edges(
            analyzer,
            catalog.fqns(UsageEcosystem::Rust),
            keep_file,
        );
        record_inverted(
            UsageEcosystem::Rust,
            rust_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        // One JVM realm, three resolvers: Java, Scala, and Kotlin declarations
        // share one candidate space, so all three builders run over the same fqn
        // set and merge into it. Each resolver only scans files of its own
        // language, so the passes cover disjoint call sites and cannot double
        // count.
        let _scope = profiling::scope("usage_graph::resolve_jvm");
        let java_edges = crate::analyzer::usages::java_graph::build_java_usage_edges(
            analyzer,
            catalog.fqns(UsageEcosystem::Jvm),
            keep_file,
        );
        record_inverted(
            UsageEcosystem::Jvm,
            java_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
        let scala_edges = crate::analyzer::usages::scala_graph::build_scala_usage_edges(
            analyzer,
            catalog.fqns(UsageEcosystem::Jvm),
            keep_file,
        );
        record_inverted(
            UsageEcosystem::Jvm,
            scala_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
        let kotlin_edges = crate::analyzer::usages::kotlin_graph::build_kotlin_usage_edges(
            analyzer,
            catalog.fqns(UsageEcosystem::Jvm),
            keep_file,
        );
        record_inverted(
            UsageEcosystem::Jvm,
            kotlin_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_csharp");
        let csharp_edges = crate::analyzer::usages::csharp_graph::build_csharp_usage_edges(
            analyzer,
            catalog.fqns(UsageEcosystem::CSharp),
            keep_file,
        );
        record_inverted(
            UsageEcosystem::CSharp,
            csharp_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_php");
        let php_edges = crate::analyzer::usages::php_graph::build_php_usage_edges(
            analyzer,
            catalog.fqns(UsageEcosystem::Php),
            keep_file,
        );
        record_inverted(
            UsageEcosystem::Php,
            php_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_ruby");
        let ruby_edges = crate::analyzer::usages::ruby_graph::build_ruby_usage_edges(
            analyzer,
            catalog.fqns(UsageEcosystem::Ruby),
            keep_file,
        );
        record_inverted(
            UsageEcosystem::Ruby,
            ruby_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_cpp");
        let cpp_edges = crate::analyzer::usages::cpp_graph::build_cpp_usage_edges(
            analyzer,
            catalog.fqns(UsageEcosystem::Cpp),
            keep_file,
        );
        record_inverted(
            UsageEcosystem::Cpp,
            cpp_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }

    // Deterministic output order, independent of ecosystem enum order: nodes and
    // the truncated list by (language, fqn), edges by (language, from, to).
    nodes.sort_by(|left, right| {
        left.language
            .cmp(&right.language)
            .then_with(|| left.fqn.cmp(&right.fqn))
    });
    truncated_symbols.sort_by(|left, right| {
        left.language
            .cmp(&right.language)
            .then_with(|| left.fqn.cmp(&right.fqn))
    });

    let mut edges: Vec<UsageGraphEdge> = edge_sites
        .into_iter()
        .map(|((ecosystem, from, to), sites)| {
            // Each `(ecosystem, from, to)` is produced by exactly one builder, whose
            // sites already arrive sorted; `weight` is the site count.
            UsageGraphEdge {
                from,
                to,
                language: ecosystem.as_str().to_string(),
                weight: sites.len(),
                sites,
            }
        })
        .collect();
    edges.sort_by(|left, right| {
        left.language
            .cmp(&right.language)
            .then_with(|| left.from.cmp(&right.from))
            .then_with(|| left.to.cmp(&right.to))
    });

    UsageGraphResult {
        nodes,
        edges,
        truncated_symbols,
    }
}

#[derive(Debug, Clone)]
pub(super) struct FilteredUsageHits {
    hits: Vec<UsageHitRow>,
    /// Same-owner usage sites (self/this receiver, own-type static) deduped like
    /// `hits` but excluded from the external usage surface. Counted always;
    /// listed only when the caller passes `include_same_owner`.
    same_owner: Vec<UsageHitRow>,
    definition_sites_excluded: usize,
}

#[derive(Debug, Clone)]
pub(super) struct UsageHitRow {
    pub(super) path: String,
    pub(super) line: usize,
    pub(super) column: Option<usize>,
    pub(super) end_line: Option<usize>,
    pub(super) end_column: Option<usize>,
    pub(super) start_offset: usize,
    pub(super) end_offset: usize,
    pub(super) enclosing: String,
    pub(super) kind: UsageHitKind,
    pub(super) snippet: String,
    pub(super) confidence: f64,
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedUsageDefinition {
    fq_name: String,
    path: String,
    line: usize,
}

#[derive(Debug, Clone)]
pub(super) struct SummaryFileCount {
    path: String,
    hits: usize,
}

#[derive(Debug, Clone)]
pub(super) struct SymbolUsageRenderState {
    symbol: String,
    fq_name: Option<String>,
    definition_path: Option<String>,
    definition_line: Option<usize>,
    total_hits: usize,
    unproven_hits: usize,
    same_owner_sites: usize,
    same_owner_rows: Vec<UsageHitRow>,
    include_same_owner: bool,
    candidate_files_truncated: bool,
    definition_sites_excluded: usize,
    hits: Vec<UsageHitRow>,
    unproven_rows: Vec<UsageHitRow>,
    summary_files: Vec<SummaryFileCount>,
    top_enclosing: Vec<UsageEnclosingCount>,
    base_note: Option<String>,
    reference_only_absence_note: Option<String>,
    rendering: UsageRendering,
    file_limit: Option<usize>,
    top_enclosing_limit: usize,
}

impl SymbolUsageRenderState {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        symbol: String,
        resolved_definition: Option<ResolvedUsageDefinition>,
        candidate_files_truncated: bool,
        definition_sites_excluded: usize,
        hits: Vec<UsageHitRow>,
        unproven_hits: usize,
        unproven_rows: Vec<UsageHitRow>,
        base_note: Option<String>,
        reference_only_absence_note: Option<String>,
        same_owner_rows: Vec<UsageHitRow>,
        include_same_owner: bool,
    ) -> Self {
        let total_hits = hits.len();
        let same_owner_sites = same_owner_rows.len();
        let rendering = if total_hits <= 10 {
            UsageRendering::Full
        } else if total_hits <= 100 {
            UsageRendering::Lines
        } else {
            UsageRendering::Summary
        };
        let mut file_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut enclosing_counts: BTreeMap<String, usize> = BTreeMap::new();
        for hit in &hits {
            *file_counts.entry(hit.path.clone()).or_default() += 1;
            *enclosing_counts.entry(hit.enclosing.clone()).or_default() += 1;
        }
        let mut summary_files: Vec<SummaryFileCount> = file_counts
            .into_iter()
            .map(|(path, hits)| SummaryFileCount { path, hits })
            .collect();
        summary_files.sort_by(|left, right| {
            right
                .hits
                .cmp(&left.hits)
                .then_with(|| left.path.cmp(&right.path))
        });
        let mut top_enclosing: Vec<UsageEnclosingCount> = enclosing_counts
            .into_iter()
            .map(|(enclosing, hits)| UsageEnclosingCount { enclosing, hits })
            .collect();
        top_enclosing.sort_by(|left, right| {
            right
                .hits
                .cmp(&left.hits)
                .then_with(|| left.enclosing.cmp(&right.enclosing))
        });

        let file_limit = (rendering == UsageRendering::Summary
            && summary_files.len() > SCAN_USAGES_SUMMARY_FILE_LIMIT)
            .then_some(SCAN_USAGES_SUMMARY_FILE_LIMIT);

        Self {
            symbol,
            fq_name: resolved_definition
                .as_ref()
                .map(|definition| definition.fq_name.clone()),
            definition_path: resolved_definition
                .as_ref()
                .map(|definition| definition.path.clone()),
            definition_line: resolved_definition.map(|definition| definition.line),
            total_hits,
            unproven_hits,
            same_owner_sites,
            same_owner_rows,
            include_same_owner,
            candidate_files_truncated,
            definition_sites_excluded,
            hits,
            unproven_rows,
            summary_files,
            top_enclosing,
            base_note,
            reference_only_absence_note,
            rendering,
            file_limit,
            top_enclosing_limit: SCAN_USAGES_TOP_ENCLOSING_LIMIT,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn partial_summary(
        symbol: String,
        resolved_definition: Option<ResolvedUsageDefinition>,
        total_hits: usize,
        candidate_files_truncated: bool,
        definition_sites_excluded: usize,
        hits: Vec<UsageHitRow>,
        unproven_hits: usize,
        unproven_rows: Vec<UsageHitRow>,
        base_note: Option<String>,
        reference_only_absence_note: Option<String>,
        same_owner_rows: Vec<UsageHitRow>,
        include_same_owner: bool,
    ) -> Self {
        let mut state = Self::new(
            symbol,
            resolved_definition,
            candidate_files_truncated,
            definition_sites_excluded,
            hits,
            unproven_hits,
            unproven_rows,
            base_note,
            reference_only_absence_note,
            same_owner_rows,
            include_same_owner,
        );
        state.total_hits = total_hits;
        state.rendering = UsageRendering::Summary;
        state.file_limit = (state.summary_files.len() > SCAN_USAGES_SUMMARY_FILE_LIMIT)
            .then_some(SCAN_USAGES_SUMMARY_FILE_LIMIT);
        state
    }
}

pub(super) fn filter_and_dedupe_hits(
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    hits: Vec<UsageHit>,
) -> FilteredUsageHits {
    let mut definition_ranges: BTreeMap<ProjectFile, Vec<Range>> = BTreeMap::new();
    for overload in overloads {
        definition_ranges
            .entry(overload.source().clone())
            .or_default()
            .extend(external_usage_definition_ranges(analyzer, overload));
    }

    let mut rows: BTreeMap<(String, usize, usize, String, UsageHitKind), UsageHitRow> =
        BTreeMap::new();
    // Same-owner (self/this receiver, own-type static) sites, deduped by the same
    // key. Excluded from the external usage surface (`rows`) but counted and,
    // on request, listed — the honest-reporting half of #1014 facet B.
    let mut same_owner_rows: BTreeMap<(String, usize, usize, String, UsageHitKind), UsageHitRow> =
        BTreeMap::new();
    let mut source_positions: HashMap<ProjectFile, Option<(String, Vec<usize>)>> =
        HashMap::default();
    let mut definition_sites_excluded = 0usize;
    for hit in hits {
        if hit.kind == UsageHitKind::Definition {
            definition_sites_excluded += 1;
            continue;
        }
        // Import/re-export bindings are editor-only noise dropped here. Self/this
        // receiver hits are also excluded from the external surface, but instead
        // of dropping them silently we route them to `same_owner_rows`.
        let is_same_owner = hit.kind == UsageHitKind::SelfReceiver;
        if !is_same_owner && !hit.kind.included_in(UsageHitSurface::ExternalUsages) {
            continue;
        }
        if hit.kind == UsageHitKind::Reference
            && definition_ranges
                .get(&hit.file)
                .is_some_and(|ranges| ranges.iter().any(|range| ranges_overlap(range, &hit)))
        {
            definition_sites_excluded += 1;
            continue;
        }

        let path = rel_path_string(&hit.file);
        let enclosing = hit.enclosing.fq_name();
        let exact_position = source_positions
            .entry(hit.file.clone())
            .or_insert_with(|| {
                analyzer
                    .project()
                    .read_source(&hit.file)
                    .ok()
                    .map(|source| {
                        let line_starts = compute_line_starts(&source);
                        (source, line_starts)
                    })
            })
            .as_ref()
            .and_then(|(source, line_starts)| {
                (hit.start_offset <= hit.end_offset
                    && hit.end_offset <= source.len()
                    && source.is_char_boundary(hit.start_offset)
                    && source.is_char_boundary(hit.end_offset))
                .then(|| {
                    let start = crate::text_utils::line_column_for_offset(
                        source,
                        line_starts,
                        hit.start_offset,
                    );
                    let end = crate::text_utils::line_column_for_offset(
                        source,
                        line_starts,
                        hit.end_offset,
                    );
                    (start, end)
                })
            });
        let row = UsageHitRow {
            path: path.clone(),
            line: exact_position.map_or(hit.line, |(start, _)| start.0),
            column: exact_position.map(|(start, _)| start.1),
            end_line: exact_position.map(|(_, end)| end.0),
            end_column: exact_position.map(|(_, end)| end.1),
            start_offset: hit.start_offset,
            end_offset: hit.end_offset,
            enclosing: enclosing.clone(),
            kind: hit.kind,
            snippet: hit.snippet.trim_end().to_string(),
            confidence: hit.confidence,
        };
        let key = (path, hit.start_offset, hit.end_offset, enclosing, hit.kind);
        let target_map = if is_same_owner {
            &mut same_owner_rows
        } else {
            &mut rows
        };
        target_map
            .entry(key)
            .and_modify(|existing| {
                if row.confidence > existing.confidence
                    || (row.confidence == existing.confidence
                        && row.snippet.len() > existing.snippet.len())
                {
                    *existing = row.clone();
                }
            })
            .or_insert(row);
    }

    let sort_rows = |rows: &mut Vec<UsageHitRow>| {
        rows.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.line.cmp(&right.line))
                .then_with(|| left.start_offset.cmp(&right.start_offset))
                .then_with(|| left.end_offset.cmp(&right.end_offset))
                .then_with(|| left.enclosing.cmp(&right.enclosing))
        });
    };
    let mut hits: Vec<_> = rows.into_values().collect();
    sort_rows(&mut hits);
    let mut same_owner: Vec<_> = same_owner_rows.into_values().collect();
    sort_rows(&mut same_owner);

    FilteredUsageHits {
        hits,
        same_owner,
        definition_sites_excluded,
    }
}

pub(super) fn external_usage_definition_ranges(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
) -> Vec<Range> {
    let ranges = analyzer.ranges_of(target);
    let narrow_to_name = target.is_class()
        || (language_for_file(target.source()) == Language::JavaScript
            && target.is_field()
            && analyzer.parent_of(target).is_none()
            && !analyzer.declarations(target.source()).contains(target));
    if !narrow_to_name {
        return ranges;
    }

    // `target`'s ranges above already come from the analyzer, so name-range
    // refinement must read the same analyzed snapshot to stay consistent.
    let Some(source) = analyzer.indexed_source(target.source()) else {
        return ranges;
    };
    let exact_ranges = DeclarationNameRangeContext::new(target.source(), source)
        .location_name_ranges(analyzer, target);
    if exact_ranges.is_empty() {
        ranges
    } else {
        exact_ranges
    }
}

pub(super) fn ranges_overlap(range: &Range, hit: &UsageHit) -> bool {
    range.start_byte < hit.end_offset && hit.start_offset < range.end_byte
}

pub(super) fn render_scan_usages_with_budget(
    entries: Vec<ScanUsagesWorkEntry>,
    scope: ScanUsagesScope,
    surface: ScanUsagesSurface,
) -> ScanUsagesResult {
    let mut entries = entries;
    loop {
        let results: Vec<ScanUsagesEntry> =
            entries.iter().map(classify_scan_usages_entry).collect();
        let summary = build_scan_usages_summary(&results);
        let result = ScanUsagesResult {
            surface,
            scope: scope.clone(),
            summary,
            results,
        };
        if serde_json::to_string(&result)
            .map(|text| text.len() <= SCAN_USAGES_RESPONSE_BUDGET_BYTES)
            .unwrap_or(true)
        {
            return result;
        }

        if !demote_largest_scan_usage_entry(&mut entries)
            && !truncate_largest_summary_scan_usage_entry(&mut entries)
        {
            return result;
        }
    }
}

pub(super) fn build_scan_usages_summary(results: &[ScanUsagesEntry]) -> ScanUsagesSummary {
    let requested = results.len();
    let found = scan_usages_status_count(results, ScanUsagesStatus::Found);
    let verified_absent = scan_usages_status_count(results, ScanUsagesStatus::VerifiedAbsent);
    let no_external_usages = scan_usages_status_count(results, ScanUsagesStatus::NoExternalUsages);
    let unverified_absent = scan_usages_status_count(results, ScanUsagesStatus::UnverifiedAbsent);
    let not_found = scan_usages_status_count(results, ScanUsagesStatus::NotFound);
    let ambiguous = scan_usages_status_count(results, ScanUsagesStatus::Ambiguous);
    let failure = scan_usages_status_count(results, ScanUsagesStatus::Failure);
    let too_many_callsites = scan_usages_status_count(results, ScanUsagesStatus::TooManyCallsites);
    let resolved = results
        .iter()
        .filter(|entry| {
            matches!(
                entry.status,
                ScanUsagesStatus::Found
                    | ScanUsagesStatus::VerifiedAbsent
                    | ScanUsagesStatus::NoExternalUsages
                    | ScanUsagesStatus::UnverifiedAbsent
                    | ScanUsagesStatus::TooManyCallsites
            )
        })
        .count();
    let total_hits = results
        .iter()
        .filter_map(|entry| match entry.status {
            ScanUsagesStatus::Found => entry.total_hits,
            ScanUsagesStatus::TooManyCallsites => entry.total_callsites,
            _ => None,
        })
        .sum();
    let partial = results.iter().any(|entry| !entry.complete);
    ScanUsagesSummary {
        requested,
        resolved,
        total_hits,
        partial,
        found,
        verified_absent,
        no_external_usages,
        unverified_absent,
        not_found,
        ambiguous,
        failure,
        too_many_callsites,
    }
}

pub(super) fn scan_usages_status_count(
    results: &[ScanUsagesEntry],
    status: ScanUsagesStatus,
) -> usize {
    results
        .iter()
        .filter(|entry| entry.status == status)
        .count()
}

pub(super) fn classify_scan_usages_entry(entry: &ScanUsagesWorkEntry) -> ScanUsagesEntry {
    match entry {
        ScanUsagesWorkEntry::Usage {
            request,
            state,
            candidate_files_sample,
            target_is_method,
            incomplete_reason,
        } => {
            let usage = render_symbol_usages(state);
            classify_usage_entry(
                request,
                usage,
                candidate_files_sample.clone(),
                false,
                None,
                *target_is_method,
                *incomplete_reason,
            )
        }
        ScanUsagesWorkEntry::TooManyCallsites {
            request,
            state,
            short_name,
            total_callsites,
            limit,
            target_is_method,
        } => {
            let usage = render_symbol_usages(state);
            classify_usage_entry(
                request,
                usage,
                None,
                true,
                Some((short_name.clone(), *total_callsites, *limit)),
                *target_is_method,
                Some(ScanUsagesIncompleteReason::Callsites),
            )
        }
        ScanUsagesWorkEntry::NotFound { request, item } => {
            let mut result = scan_usages_entry_base(request, ScanUsagesStatus::NotFound, true);
            result.message = Some(match item.note.as_deref() {
                Some(note) => format!("{}: {note}", item.input),
                None => item.input.clone(),
            });
            result
        }
        ScanUsagesWorkEntry::Ambiguous {
            request,
            item,
            incomplete_reason,
        } => {
            let mut result = scan_usages_entry_base(request, ScanUsagesStatus::Ambiguous, true);
            result.symbol = Some(item.symbol.clone());
            result.short_name = Some(item.short_name.clone());
            result.candidate_targets = item.candidate_targets.clone();
            result.candidate_details = item.candidate_details.clone();
            result.candidate_details_total = item.candidate_details_total;
            result.candidate_details_truncated = item.candidate_details_truncated;
            result.candidates = item.candidates.clone();
            result.definition_sites_excluded = item.definition_sites_excluded;
            result.complete = incomplete_reason.is_none() && !item.candidate_files_truncated;
            result.incomplete_reason = incomplete_reason.or_else(|| {
                item.candidate_files_truncated
                    .then_some(ScanUsagesIncompleteReason::CandidateFiles)
            });
            result.message = Some(item.note.clone().unwrap_or_else(|| {
                match request.surface {
                    ScanUsagesSurface::Reference => "Ambiguous; re-call scan_usages_by_reference with one symbol from candidate_targets.".to_string(),
                    ScanUsagesSurface::Location => "Ambiguous location; refine the line/column target and re-call scan_usages_by_location.".to_string(),
                }
            }));
            result
        }
        ScanUsagesWorkEntry::Failure {
            request,
            failure,
            incomplete_reason,
        } => {
            let mut result = scan_usages_entry_base(
                request,
                ScanUsagesStatus::Failure,
                incomplete_reason.is_none() && !failure.candidate_files_truncated,
            );
            result.incomplete_reason = incomplete_reason.or_else(|| {
                failure
                    .candidate_files_truncated
                    .then_some(ScanUsagesIncompleteReason::CandidateFiles)
            });
            result.symbol = Some(failure.symbol.clone());
            result.fq_name = Some(failure.fq_name.clone());
            result.reason_kind = Some(failure.reason_kind.clone());
            result.candidate_files_sample = failure.candidate_files_sample.clone();
            result.message = Some(match failure.hint.as_deref() {
                Some(hint) => format!("{}; {hint}", failure.reason),
                None => failure.reason.clone(),
            });
            result
        }
        ScanUsagesWorkEntry::Incomplete {
            request,
            symbol,
            reason,
            message,
        } => {
            let mut result = scan_usages_entry_base(request, ScanUsagesStatus::Failure, false);
            result.symbol.clone_from(symbol);
            result.incomplete_reason = Some(*reason);
            result.reason_kind = Some(
                match reason {
                    ScanUsagesIncompleteReason::Cancelled => "cancelled",
                    ScanUsagesIncompleteReason::TimeBudget => "time_budget",
                    ScanUsagesIncompleteReason::CandidateFiles => "candidate_files_budget",
                    ScanUsagesIncompleteReason::SourceBytes => "source_bytes_budget",
                    ScanUsagesIncompleteReason::Callsites => "callsites_budget",
                    ScanUsagesIncompleteReason::ResponseBudget => "response_budget",
                }
                .to_string(),
            );
            result.message = Some(message.clone());
            result
        }
    }
}

pub(super) fn classify_usage_entry(
    request: &ScanUsageRequest,
    usage: SymbolUsages,
    candidate_files_sample: Option<ScanUsagesCandidateFilesSample>,
    too_many_callsites: bool,
    callsite_cap: Option<(String, usize, usize)>,
    target_is_method: bool,
    incomplete_reason: Option<ScanUsagesIncompleteReason>,
) -> ScanUsagesEntry {
    let incomplete_reason = incomplete_reason.or_else(|| {
        usage
            .candidate_files_truncated
            .then_some(ScanUsagesIncompleteReason::CandidateFiles)
    });
    let incomplete_reason = incomplete_reason.or_else(|| {
        usage
            .files_truncated
            .is_some()
            .then_some(ScanUsagesIncompleteReason::ResponseBudget)
    });
    let complete = !too_many_callsites && incomplete_reason.is_none();

    if too_many_callsites {
        let (short_name, total_callsites, limit) =
            callsite_cap.expect("too_many_callsites entry includes cap details");
        let mut result = scan_usages_entry_base(request, ScanUsagesStatus::TooManyCallsites, false);
        populate_usage_payload(&mut result, usage, target_is_method, &[], request.surface);
        result.short_name = Some(short_name);
        result.total_callsites = Some(total_callsites);
        result.limit = Some(limit);
        result.message = Some(too_many_callsites_note(limit));
        mark_incomplete(
            &mut result,
            ScanUsagesIncompleteReason::Callsites,
            request.surface,
        );
        return result;
    }

    let mut caveats = Vec::new();
    if usage.unproven_hits > 0 {
        caveats.push(ScanUsagesAbsenceCaveat::UnprovenMatches);
    }
    if usage.candidate_files_truncated {
        caveats.push(ScanUsagesAbsenceCaveat::CandidateFilesTruncated);
    }
    if usage.reference_only_siblings {
        caveats.push(ScanUsagesAbsenceCaveat::ReferenceOnlySiblings);
    }
    // A scan that stopped early never proves absence, whatever stopped it.
    if incomplete_reason.is_some() {
        caveats.push(ScanUsagesAbsenceCaveat::ScanIncomplete);
    }

    // HARD RULE (#1014 facet B): never emit `verified_absent` when same-owner
    // sites exist. Zero external hits with same-owner sites present is its own
    // status, so a consumer never reads a confident "no callers" claim when
    // internal callers exist. Same-owner presence also outranks the softer
    // unverified-absence caveats.
    let status = if usage.total_hits > 0 {
        ScanUsagesStatus::Found
    } else if usage.same_owner_sites.is_some_and(|count| count > 0) {
        ScanUsagesStatus::NoExternalUsages
    } else if caveats.is_empty() {
        ScanUsagesStatus::VerifiedAbsent
    } else {
        ScanUsagesStatus::UnverifiedAbsent
    };

    let mut result = scan_usages_entry_base(request, status, complete);
    if usage.candidate_files_truncated {
        result.candidate_files_sample = candidate_files_sample;
    }
    populate_usage_payload(
        &mut result,
        usage,
        target_is_method,
        &caveats,
        request.surface,
    );
    if status == ScanUsagesStatus::UnverifiedAbsent {
        result.absence_caveats = caveats;
    }
    if let Some(reason) = incomplete_reason {
        mark_incomplete(&mut result, reason, request.surface);
    }
    result
}

pub(super) fn populate_usage_payload(
    entry: &mut ScanUsagesEntry,
    usage: SymbolUsages,
    target_is_method: bool,
    absence_caveats: &[ScanUsagesAbsenceCaveat],
    surface: ScanUsagesSurface,
) {
    let guidance = scan_usages_absence_guidance(
        entry.status,
        target_is_method,
        &usage,
        absence_caveats,
        surface,
    );
    entry.symbol = Some(usage.symbol);
    entry.fq_name = usage.fq_name;
    entry.definition_path = usage.definition_path;
    entry.definition_line = usage.definition_line;
    entry.total_hits = Some(usage.total_hits);
    entry.unproven_hits = Some(usage.unproven_hits);
    entry.same_owner_sites = usage.same_owner_sites;
    entry.rendering = Some(usage.rendering);
    entry.files = usage.files;
    entry.same_owner_files = usage.same_owner_files;
    entry.unproven_files = usage.unproven_files;
    entry.model_relations = usage.model_relations;
    entry.top_enclosing = usage.top_enclosing;
    entry.definition_sites_excluded = usage.definition_sites_excluded;
    entry.files_truncated = usage.files_truncated;
    if let Some(note) = usage.note {
        entry.notes.push(note);
    }
    if usage.candidate_files_truncated && entry.status == ScanUsagesStatus::Found {
        entry.notes.push(format!(
            "Candidate file set was truncated; additional usage sites may exist. Re-call {} with narrower `paths` for exhaustive coverage.",
            surface.tool_name()
        ));
    }
    if entry.message.is_none() {
        entry.message = guidance.message;
    }
    entry.notes.extend(guidance.notes);
}

pub(super) struct ScanUsagesAbsenceGuidance {
    message: Option<String>,
    notes: Vec<String>,
}

pub(super) fn scan_usages_absence_guidance(
    status: ScanUsagesStatus,
    target_is_method: bool,
    usage: &SymbolUsages,
    caveats: &[ScanUsagesAbsenceCaveat],
    surface: ScanUsagesSurface,
) -> ScanUsagesAbsenceGuidance {
    let notes = if matches!(
        status,
        ScanUsagesStatus::VerifiedAbsent
            | ScanUsagesStatus::NoExternalUsages
            | ScanUsagesStatus::UnverifiedAbsent
    ) && target_is_method
    {
        vec!["if this is a framework-invoked entrypoint (e.g. servlet filters, DI callbacks), direct callers may not exist: scan the enclosing type or search for its registration.".to_string()]
    } else {
        Vec::new()
    };
    let message = match status {
        ScanUsagesStatus::VerifiedAbsent => {
            Some("resolved symbol; no external usage sites found.".to_string())
        }
        ScanUsagesStatus::NoExternalUsages => Some(
            "resolved symbol; no external usage sites found, but same-owner (self/this receiver or own-type static) sites exist within the declaring container.".to_string(),
        ),
        ScanUsagesStatus::UnverifiedAbsent => {
            scan_usages_unverified_absence_message(usage, caveats, surface)
        }
        _ => None,
    };
    ScanUsagesAbsenceGuidance { message, notes }
}

pub(super) fn scan_usages_unverified_absence_message(
    usage: &SymbolUsages,
    caveats: &[ScanUsagesAbsenceCaveat],
    surface: ScanUsagesSurface,
) -> Option<String> {
    if usage.unproven_hits > 0 {
        let file_count = usage.unproven_files.len();
        let recovery = match surface {
            ScanUsagesSurface::Reference => {
                "narrow `paths` to a relevant candidate file or choose a more specific exported symbol"
            }
            ScanUsagesSurface::Location => {
                "narrow `paths` to a relevant candidate file or refine the declaration line/column"
            }
        };
        return Some(format!(
            "no PROVEN usage sites, but {} unproven candidate usage(s) found across {} file(s); inspect these before concluding absence. Next step: {recovery} and re-call {}.",
            usage.unproven_hits,
            file_count,
            surface.tool_name()
        ));
    }
    if caveats.contains(&ScanUsagesAbsenceCaveat::CandidateFilesTruncated) {
        return Some(
            "no PROVEN usage sites in the scanned candidate sample; candidate files were truncated, so narrow paths and retry before concluding absence."
                .to_string(),
        );
    }
    None
}

pub(super) fn scan_usages_entry_base(
    request: &ScanUsageRequest,
    status: ScanUsagesStatus,
    complete: bool,
) -> ScanUsagesEntry {
    ScanUsagesEntry {
        input: request.input.clone(),
        input_kind: request.input_kind,
        status,
        complete,
        incomplete_reason: None,
        symbol: None,
        short_name: None,
        total_hits: None,
        unproven_hits: None,
        same_owner_sites: None,
        rendering: None,
        files: Vec::new(),
        same_owner_files: Vec::new(),
        unproven_files: Vec::new(),
        model_relations: Vec::new(),
        model_relations_omitted: 0,
        top_enclosing: Vec::new(),
        definition_sites_excluded: None,
        files_truncated: None,
        absence_caveats: Vec::new(),
        notes: Vec::new(),
        message: None,
        candidate_targets: Vec::new(),
        candidate_details: Vec::new(),
        candidate_details_total: None,
        candidate_details_truncated: false,
        candidates: Vec::new(),
        fq_name: None,
        definition_path: None,
        definition_line: None,
        reason_kind: None,
        candidate_files_sample: None,
        total_callsites: None,
        limit: None,
    }
}

pub(super) fn entry_render_state(entry: &ScanUsagesWorkEntry) -> Option<&SymbolUsageRenderState> {
    match entry {
        ScanUsagesWorkEntry::Usage { state, .. }
        | ScanUsagesWorkEntry::TooManyCallsites { state, .. } => Some(state),
        _ => None,
    }
}

pub(super) fn entry_render_state_mut(
    entry: &mut ScanUsagesWorkEntry,
) -> Option<&mut SymbolUsageRenderState> {
    match entry {
        ScanUsagesWorkEntry::Usage { state, .. }
        | ScanUsagesWorkEntry::TooManyCallsites { state, .. } => Some(state),
        _ => None,
    }
}

pub(super) fn demote_largest_scan_usage_entry(entries: &mut [ScanUsagesWorkEntry]) -> bool {
    let any_full = entries.iter().any(|entry| {
        entry_render_state(entry).is_some_and(|state| state.rendering == UsageRendering::Full)
    });
    let mut best_index = None;
    let mut best_size = 0usize;
    for (idx, entry) in entries.iter().enumerate() {
        let Some(state) = entry_render_state(entry) else {
            continue;
        };
        let eligible = match state.rendering {
            UsageRendering::Full => true,
            UsageRendering::Lines => !any_full,
            UsageRendering::Summary => false,
        };
        if !eligible {
            continue;
        }
        let size = serialized_char_count(&render_symbol_usages(state));
        if size > best_size {
            best_size = size;
            best_index = Some(idx);
        }
    }
    let Some(idx) = best_index else {
        return false;
    };
    let state = entry_render_state_mut(&mut entries[idx]).expect("selected render state");
    state.rendering = match state.rendering {
        UsageRendering::Full => UsageRendering::Lines,
        UsageRendering::Lines => UsageRendering::Summary,
        UsageRendering::Summary => UsageRendering::Summary,
    };
    true
}

pub(super) fn truncate_largest_summary_scan_usage_entry(
    entries: &mut [ScanUsagesWorkEntry],
) -> bool {
    let mut best_index = None;
    let mut best_size = 0usize;
    for (idx, entry) in entries.iter().enumerate() {
        let Some(state) = entry_render_state(entry) else {
            continue;
        };
        if state.rendering != UsageRendering::Summary {
            continue;
        }
        let can_limit_files =
            state.summary_files.len() > state.file_limit.unwrap_or(SCAN_USAGES_SUMMARY_FILE_LIMIT);
        let can_reduce_files = state.file_limit.is_some_and(|limit| limit > 1);
        let can_reduce_enclosing = state.top_enclosing_limit > 0;
        if !(can_limit_files || can_reduce_files || can_reduce_enclosing) {
            continue;
        }
        let size = serialized_char_count(&render_symbol_usages(state));
        if size > best_size {
            best_size = size;
            best_index = Some(idx);
        }
    }
    let Some(idx) = best_index else {
        return false;
    };
    let state = entry_render_state_mut(&mut entries[idx]).expect("selected render state");
    if state.file_limit.is_none() && state.summary_files.len() > SCAN_USAGES_SUMMARY_FILE_LIMIT {
        state.file_limit = Some(SCAN_USAGES_SUMMARY_FILE_LIMIT);
        return true;
    }
    if let Some(limit) = state.file_limit
        && limit > 1
    {
        state.file_limit = Some((limit / 2).max(1));
        return true;
    }
    if state.top_enclosing_limit > 0 {
        state.top_enclosing_limit /= 2;
        return true;
    }
    false
}

pub(super) fn render_symbol_usages(state: &SymbolUsageRenderState) -> SymbolUsages {
    let (files, files_truncated, top_enclosing) = match state.rendering {
        UsageRendering::Full => (
            render_usage_file_groups(&state.hits, true),
            None,
            Vec::new(),
        ),
        UsageRendering::Lines => (
            render_usage_file_groups(&state.hits, false),
            None,
            Vec::new(),
        ),
        UsageRendering::Summary => {
            let limit = state.file_limit.unwrap_or(state.summary_files.len());
            let kept = state
                .summary_files
                .iter()
                .take(limit)
                .map(|item| UsageFileGroup {
                    path: item.path.clone(),
                    hits: Vec::new(),
                    hit_count: Some(item.hits),
                })
                .collect::<Vec<_>>();
            let truncated = state.summary_files.len().saturating_sub(kept.len());
            (
                kept,
                some_if_nonzero(truncated),
                state
                    .top_enclosing
                    .iter()
                    .take(state.top_enclosing_limit)
                    .cloned()
                    .collect(),
            )
        }
    };

    let mut notes = Vec::new();
    if let Some(base) = state.base_note.clone() {
        notes.push(base);
    }
    match state.rendering {
        UsageRendering::Full => {}
        UsageRendering::Lines => notes.push(format!(
            "{} hits; showing every exact location without snippets.",
            state.total_hits
        )),
        UsageRendering::Summary => notes.push(format!(
            "{} hits; showing bounded per-file counts instead of line-level callers. Re-call with narrower `paths` or a more specific symbol for line detail.",
            state.total_hits
        )),
    }
    if files_truncated.is_some() {
        notes.push("Summary file list truncated to fit the response budget.".to_string());
    }
    let reference_only_siblings = state.reference_only_absence_note.is_some();
    let absence_would_be_verified = !state.candidate_files_truncated
        && state.total_hits == 0
        && state.unproven_hits == 0
        && state.same_owner_sites == 0;
    if absence_would_be_verified && let Some(note) = &state.reference_only_absence_note {
        notes.push(note.clone());
    }
    if state.same_owner_sites > 0 {
        let sites = state.same_owner_sites;
        let plural = if sites == 1 { "site" } else { "sites" };
        if state.include_same_owner {
            notes.push(format!(
                "{sites} usage {plural} within the declaring container (self/this receiver or own-type static calls) are excluded from external usage counts and listed under same_owner_files."
            ));
        } else {
            notes.push(format!(
                "{sites} usage {plural} within the declaring container (self/this receiver or own-type static calls) are excluded from external usage counts. Re-call with include_same_owner: true to list them."
            ));
        }
    }

    let same_owner_files = if state.include_same_owner {
        render_same_owner_file_groups(&state.same_owner_rows)
    } else {
        Vec::new()
    };

    SymbolUsages {
        symbol: state.symbol.clone(),
        fq_name: state.fq_name.clone(),
        definition_path: state.definition_path.clone(),
        definition_line: state.definition_line,
        total_hits: state.total_hits,
        unproven_hits: state.unproven_hits,
        same_owner_sites: some_if_nonzero(state.same_owner_sites),
        rendering: state.rendering,
        candidate_files_truncated: state.candidate_files_truncated,
        reference_only_siblings,
        definition_sites_excluded: some_if_nonzero(state.definition_sites_excluded),
        files_truncated,
        note: if notes.is_empty() {
            None
        } else {
            Some(notes.join(" "))
        },
        top_enclosing,
        files,
        same_owner_files,
        unproven_files: render_usage_file_groups(&state.unproven_rows, true),
        model_relations: Vec::new(),
    }
}

fn attach_model_relations(analyzer: &dyn IAnalyzer, result: &mut ScanUsagesResult) {
    const MAX_MODEL_RELATIONS_PER_SYMBOL: usize = 256;

    let Some(overlay) = analyzer.semantic_model_overlay() else {
        return;
    };
    let whole_workspace = result.scope.whole_workspace;
    for entry in &mut result.results {
        let input = match &entry.input {
            ScanUsagesInput::Symbol(symbol) => symbol.as_str(),
            ScanUsagesInput::Target(_) => entry
                .fq_name
                .as_deref()
                .or(entry.symbol.as_deref())
                .unwrap_or_default(),
        };
        let authored_target = entry.fq_name.is_some()
            && !matches!(
                entry.status,
                ScanUsagesStatus::NotFound
                    | ScanUsagesStatus::Ambiguous
                    | ScanUsagesStatus::Failure
            );
        let mut symbol = if input.starts_with("bifrost-model://") {
            overlay.symbols_at_uri(input)
        } else {
            entry
                .fq_name
                .as_deref()
                .map(|name| overlay.symbols_named(name))
                .filter(|matched| !matched.records.is_empty())
                .unwrap_or_else(|| overlay.symbols_named(input))
        };
        if symbol.records.is_empty() {
            symbol = overlay.symbols_with_id(input);
        }
        if symbol.disposition
            != crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        {
            if symbol.disposition
                == crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Empty
                && authored_target
                && whole_workspace
            {
                let authored_name = entry.fq_name.as_deref().unwrap_or_default();
                let mut reverse_relations = overlay
                    .relations()
                    .iter()
                    .filter(|relation| {
                        relation.kind == "navigates_to" && relation.to == authored_name
                    })
                    .collect::<Vec<_>>();
                reverse_relations.sort_by(|left, right| left.id.cmp(&right.id));
                if reverse_relations
                    .iter()
                    .any(|relation| relation.provenance.ambiguous)
                {
                    entry.notes.push(
                        "Conflicting modeled relations were omitted; authored usage resolution retained precedence."
                            .to_string(),
                    );
                    continue;
                }
                let mut modeled_references = BTreeMap::<String, Vec<UsageLocation>>::new();
                for relation in &reverse_relations {
                    let source = overlay.symbols_with_id(&relation.from);
                    if source.disposition
                        != crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
                    {
                        continue;
                    }
                    for file in authored_model_references(analyzer, &overlay, source.records[0]) {
                        modeled_references
                            .entry(file.path)
                            .or_default()
                            .extend(file.hits);
                    }
                }
                let mut modeled_references = modeled_references
                    .into_iter()
                    .map(|(path, mut hits)| {
                        hits.sort_by_key(|hit| (hit.line, hit.column));
                        hits.dedup_by(|left, right| {
                            left.line == right.line && left.column == right.column
                        });
                        UsageFileGroup {
                            path,
                            hits,
                            hit_count: None,
                        }
                    })
                    .collect::<Vec<_>>();
                let authored_hits = modeled_references
                    .iter()
                    .map(|file| file.hits.len())
                    .sum::<usize>();
                if authored_hits != 0 {
                    entry.files.append(&mut modeled_references);
                    entry
                        .files
                        .sort_by(|left, right| left.path.cmp(&right.path));
                    entry.total_hits = Some(
                        entry
                            .total_hits
                            .unwrap_or_default()
                            .saturating_add(authored_hits),
                    );
                    entry.status = ScanUsagesStatus::Found;
                    entry.notes.push(
                        "Generated accessors were matched through modeled navigation relations."
                            .to_owned(),
                    );
                }
                let total_model_relations = reverse_relations.len();
                entry.model_relations = reverse_relations
                    .into_iter()
                    .take(MAX_MODEL_RELATIONS_PER_SYMBOL)
                    .cloned()
                    .collect();
                entry.model_relations_omitted =
                    total_model_relations.saturating_sub(entry.model_relations.len());
                if !entry.model_relations.is_empty() {
                    entry.total_hits = Some(
                        entry
                            .total_hits
                            .unwrap_or_default()
                            .saturating_add(entry.model_relations.len()),
                    );
                    entry.status = ScanUsagesStatus::Found;
                }
                continue;
            }
            if symbol.disposition
                == crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Conflict
            {
                if authored_target {
                    entry.notes.push(
                        "Conflicting modeled declarations were omitted; authored usage resolution retained precedence."
                            .to_string(),
                    );
                } else {
                    entry.status = ScanUsagesStatus::Ambiguous;
                    entry.message = Some(
                        "conflicting active semantic-model declarations prevent an authoritative usage target"
                            .to_string(),
                    );
                }
            }
            continue;
        }
        let model_symbol = symbol.records[0];
        if whole_workspace {
            let authored_references = authored_model_references(analyzer, &overlay, model_symbol);
            let authored_hits = authored_references
                .iter()
                .map(|file| file.hits.len())
                .sum::<usize>();
            if authored_hits != 0 {
                entry.files.extend(authored_references);
                entry
                    .files
                    .sort_by(|left, right| left.path.cmp(&right.path));
                entry.symbol = Some(model_symbol.qualified_name.clone());
                entry.fq_name = Some(model_symbol.qualified_name.clone());
                entry.total_hits = Some(
                    entry
                        .total_hits
                        .unwrap_or_default()
                        .saturating_add(authored_hits),
                );
                entry.status = ScanUsagesStatus::Found;
                entry.notes.push(
                    "Workspace references were matched through structured definition resolution."
                        .to_owned(),
                );
            }
        }
        let relations = overlay.relations_to(&model_symbol.id);
        if relations
            .records
            .iter()
            .any(|relation| relation.provenance.ambiguous)
        {
            if authored_target {
                entry.notes.push(
                    "Conflicting modeled relations were omitted; authored usage resolution retained precedence."
                        .to_string(),
                );
            } else {
                entry.status = ScanUsagesStatus::Ambiguous;
                entry.message = Some(
                    "conflicting active semantic-model relations prevent an authoritative usage result"
                        .to_string(),
                );
            }
            continue;
        }
        let total_model_relations = relations.records.len();
        entry.model_relations = relations
            .records
            .into_iter()
            .take(MAX_MODEL_RELATIONS_PER_SYMBOL)
            .cloned()
            .collect();
        entry.model_relations_omitted =
            total_model_relations.saturating_sub(entry.model_relations.len());
        if !entry.model_relations.is_empty() {
            entry.symbol = Some(model_symbol.qualified_name.clone());
            entry.fq_name = Some(model_symbol.qualified_name.clone());
            entry.total_hits = Some(
                entry
                    .total_hits
                    .unwrap_or_default()
                    .saturating_add(entry.model_relations.len()),
            );
            entry.status = ScanUsagesStatus::Found;
            entry.notes.push(
                "Model relations are semantic facts and do not claim authored source hit text."
                    .to_string(),
            );
        } else if entry.status == ScanUsagesStatus::NotFound {
            entry.status = ScanUsagesStatus::UnverifiedAbsent;
            entry.symbol = Some(model_symbol.qualified_name.clone());
            entry.fq_name = Some(model_symbol.qualified_name.clone());
            entry.message = Some(
                "the semantic-model declaration resolved, but the active packs contain no modeled inbound relation"
                    .to_string(),
            );
        }
    }
    fit_model_relations_to_response_budget(result);
    result.summary = build_scan_usages_summary(&result.results);
}

fn authored_model_references(
    analyzer: &dyn IAnalyzer,
    overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
) -> Vec<UsageFileGroup> {
    use crate::analyzer::structural::{NormalizedKind, Role};
    use crate::searchtools::navigation::{
        DefinitionReferenceQuery, GetDefinitionParams, get_definitions_by_location,
    };

    if symbol.language == "go" {
        return go_authored_model_references(analyzer, overlay, symbol);
    }
    if !symbol.externally_visible() {
        return Vec::new();
    }

    let mut grouped = BTreeMap::<String, Vec<UsageLocation>>::new();
    for provider in analyzer
        .structural_search_providers()
        .into_iter()
        .filter(|provider| provider.structural_language().config_label() == symbol.language)
    {
        let mut files = provider.structural_files();
        files.sort();
        files.dedup();
        for file in files {
            let Some(facts) = provider.structural_facts(&file) else {
                continue;
            };
            let mut spans = Vec::new();
            for (index, node) in facts.nodes().iter().enumerate() {
                if !matches!(
                    node.kind,
                    NormalizedKind::Call | NormalizedKind::FieldAccess
                ) {
                    continue;
                }
                if let Some(name) = node.name
                    && name.text(facts.source()) == symbol.name
                {
                    spans.push(name);
                }
                let node_id = u32::try_from(index).expect("structural fact IDs fit u32");
                spans.extend(
                    facts
                        .roles(node_id)
                        .iter()
                        .filter(|target| target.role == Role::Kwarg)
                        .filter_map(|target| target.keyword)
                        .filter(|keyword| keyword.text(facts.source()) == symbol.name),
                );
            }
            spans.sort_by_key(|span| (span.start_byte, span.end_byte));
            spans.dedup();
            let lines = facts.source().lines().collect::<Vec<_>>();
            for span in spans {
                let (line, column) = facts.line_column_of_byte(span.start_byte);
                let result = get_definitions_by_location(
                    analyzer,
                    GetDefinitionParams {
                        references: vec![DefinitionReferenceQuery {
                            path: file.rel_path().to_string_lossy().replace('\\', "/"),
                            line: Some(line),
                            column: Some(column),
                        }],
                    },
                );
                let resolves_to_symbol = result.results.first().is_some_and(|result| {
                    result.definitions.iter().any(|candidate| {
                        candidate
                            .semantic_model
                            .as_ref()
                            .is_some_and(|provenance| provenance.record_id == symbol.id)
                    })
                });
                if !resolves_to_symbol {
                    continue;
                }
                let range = crate::analyzer::Range {
                    start_byte: span.start_byte,
                    end_byte: span.end_byte,
                    start_line: line,
                    end_line: facts.line_of_byte(span.end_byte),
                };
                let enclosing = analyzer
                    .enclosing_code_unit(&file, &range)
                    .map(|unit| unit.fq_name())
                    .unwrap_or_default();
                grouped
                    .entry(crate::path_utils::rel_path_string(&file))
                    .or_default()
                    .push(UsageLocation {
                        line,
                        column: Some(column),
                        end_line: Some(range.end_line),
                        end_column: Some(column.saturating_add(span.end_byte - span.start_byte)),
                        enclosing,
                        kind: None,
                        snippet: lines
                            .get(line.saturating_sub(1))
                            .map(|line| (*line).to_owned()),
                        confidence: 1.0,
                    });
            }
        }
    }
    grouped
        .into_iter()
        .map(|(path, mut hits)| {
            hits.sort_by_key(|hit| (hit.line, hit.column));
            UsageFileGroup {
                path,
                hits,
                hit_count: None,
            }
        })
        .collect()
}

fn go_authored_model_references(
    analyzer: &dyn IAnalyzer,
    _overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
) -> Vec<UsageFileGroup> {
    use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
    use crate::analyzer::usages::get_definition::{
        DefinitionLookupRequest, resolve_definition_batch_with_source,
    };

    if symbol.language != "go" || !symbol.externally_visible() {
        return Vec::new();
    }
    let mut grouped = BTreeMap::<String, Vec<UsageLocation>>::new();
    let Ok(files) = analyzer.project().all_files() else {
        return Vec::new();
    };
    for file in files.into_iter().filter(|file| {
        file.rel_path()
            .extension()
            .and_then(|extension| extension.to_str())
            == Some("go")
    }) {
        let Some(source) = analyzer.indexed_source(&file) else {
            continue;
        };
        let mut parser = tree_sitter::Parser::new();
        if parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .is_err()
        {
            continue;
        }
        let Some(tree) = parser.parse(&source, None) else {
            continue;
        };
        let mut candidates = Vec::new();
        walk_named_tree_preorder(tree.root_node(), true, |node| {
            if matches!(
                node.kind(),
                "identifier" | "field_identifier" | "type_identifier"
            ) && source.get(node.byte_range()) == Some(symbol.name.as_str())
            {
                candidates.push(node.range());
            }
            WalkControl::Continue
        });
        if candidates.is_empty() {
            continue;
        }
        let requests = candidates
            .iter()
            .map(|range| DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(range.start_byte),
                end_byte: Some(range.end_byte),
            })
            .collect();
        let outcomes = resolve_definition_batch_with_source(
            analyzer,
            requests,
            file.clone(),
            std::sync::Arc::from(source.as_str()),
        );
        let lines = source.lines().collect::<Vec<_>>();
        for (tree_range, outcome) in candidates.into_iter().zip(outcomes) {
            if outcome.resolved_reference_target() != Some(symbol.qualified_name.as_str()) {
                continue;
            }
            let position = tree_range.start_point;
            let range = crate::analyzer::Range {
                start_byte: tree_range.start_byte,
                end_byte: tree_range.end_byte,
                start_line: position.row + 1,
                end_line: tree_range.end_point.row + 1,
            };
            let enclosing = analyzer
                .enclosing_code_unit(&file, &range)
                .map(|unit| unit.fq_name())
                .unwrap_or_default();
            grouped
                .entry(crate::path_utils::rel_path_string(&file))
                .or_default()
                .push(UsageLocation {
                    line: position.row + 1,
                    column: Some(position.column + 1),
                    end_line: Some(range.end_line),
                    end_column: Some(tree_range.end_point.column + 1),
                    enclosing,
                    kind: None,
                    snippet: lines.get(position.row).map(|line| (*line).to_owned()),
                    confidence: 1.0,
                });
        }
    }
    grouped
        .into_iter()
        .map(|(path, mut hits)| {
            hits.sort_by_key(|hit| (hit.line, hit.column));
            UsageFileGroup {
                path,
                hits,
                hit_count: None,
            }
        })
        .collect()
}

fn fit_model_relations_to_response_budget(result: &mut ScanUsagesResult) {
    let mut relation_sizes = result
        .results
        .iter()
        .map(|entry| {
            entry
                .model_relations
                .iter()
                .map(|relation| {
                    serde_json::to_vec(relation)
                        .expect("semantic-model relations are serializable")
                        .len()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let surface = result.surface;
    loop {
        trim_model_relations_to_serialized_budget(
            result,
            &mut relation_sizes,
            SCAN_USAGES_RESPONSE_BUDGET_BYTES,
        );
        let mut guidance_changed = false;
        for entry in result
            .results
            .iter_mut()
            .filter(|entry| entry.model_relations_omitted != 0)
        {
            guidance_changed |=
                mark_incomplete(entry, ScanUsagesIncompleteReason::ResponseBudget, surface);
        }
        if !guidance_changed {
            break;
        }
    }
}

fn trim_model_relations_to_serialized_budget(
    result: &mut ScanUsagesResult,
    relation_sizes: &mut [Vec<usize>],
    budget: usize,
) {
    let mut serialized_bytes = serde_json::to_vec(result)
        .expect("scan-usages results are serializable")
        .len();
    while serialized_bytes > budget {
        let Some((entry_index, _)) = result
            .results
            .iter()
            .enumerate()
            .filter(|(_, entry)| !entry.model_relations.is_empty())
            .max_by_key(|(_, entry)| entry.model_relations.len())
        else {
            break;
        };
        let entry = &mut result.results[entry_index];
        let relation_count = entry.model_relations.len();
        let relation_bytes = relation_sizes[entry_index]
            .pop()
            .expect("serialized relation sizes track retained relations");
        let old_omitted_digits = decimal_digits(entry.model_relations_omitted);
        entry.model_relations.pop();
        entry.model_relations_omitted = entry.model_relations_omitted.saturating_add(1);
        let new_omitted_digits = decimal_digits(entry.model_relations_omitted);
        serialized_bytes = serialized_bytes
            .saturating_sub(relation_bytes)
            .saturating_sub(usize::from(relation_count > 1))
            .saturating_add(new_omitted_digits.saturating_sub(old_omitted_digits));
    }
}

fn decimal_digits(value: usize) -> usize {
    value.checked_ilog10().unwrap_or(0) as usize + 1
}

/// Render same-owner usage sites as file groups, kind-tagged (`self_receiver`)
/// so a consumer can distinguish them from external hits. Unlike
/// [`render_usage_file_groups`], which omits the label for internal kinds, this
/// always emits the kind so the excluded-but-listed sites are unambiguous.
pub(super) fn render_same_owner_file_groups(hits: &[UsageHitRow]) -> Vec<UsageFileGroup> {
    let mut grouped: BTreeMap<String, Vec<UsageLocation>> = BTreeMap::new();
    for hit in hits {
        grouped
            .entry(hit.path.clone())
            .or_default()
            .push(UsageLocation {
                line: hit.line,
                column: hit.column,
                end_line: hit.end_line,
                end_column: hit.end_column,
                enclosing: hit.enclosing.clone(),
                kind: Some(hit.kind.wire_label().to_string()),
                snippet: Some(hit.snippet.clone()),
                confidence: hit.confidence,
            });
    }
    grouped
        .into_iter()
        .map(|(path, mut hits)| {
            hits.sort_by(|left, right| {
                left.line
                    .cmp(&right.line)
                    .then_with(|| left.enclosing.cmp(&right.enclosing))
            });
            UsageFileGroup {
                path,
                hits,
                hit_count: None,
            }
        })
        .collect()
}

pub(super) fn render_usage_file_groups(
    hits: &[UsageHitRow],
    include_snippets: bool,
) -> Vec<UsageFileGroup> {
    let mut grouped: BTreeMap<String, Vec<UsageLocation>> = BTreeMap::new();
    for hit in hits {
        grouped
            .entry(hit.path.clone())
            .or_default()
            .push(UsageLocation {
                line: hit.line,
                column: hit.column,
                end_line: hit.end_line,
                end_column: hit.end_column,
                enclosing: hit.enclosing.clone(),
                kind: hit.kind.external_label().map(str::to_string),
                snippet: include_snippets.then(|| hit.snippet.clone()),
                confidence: hit.confidence,
            });
    }
    grouped
        .into_iter()
        .map(|(path, mut hits)| {
            hits.sort_by(|left, right| {
                left.line
                    .cmp(&right.line)
                    .then_with(|| left.enclosing.cmp(&right.enclosing))
            });
            UsageFileGroup {
                path,
                hits,
                hit_count: None,
            }
        })
        .collect()
}

#[derive(Debug, Clone)]
pub(super) struct ScanUsagesPathFilter {
    rules: Vec<ScanUsagesPathRule>,
}

pub(super) struct BuiltScanUsagesPathFilter {
    filter: Option<Arc<ScanUsagesPathFilter>>,
    ignored_paths: usize,
}

#[derive(Debug, Clone)]
pub(super) enum ScanUsagesPathRule {
    Glob(Pattern),
    Exact(String),
}

impl ScanUsagesPathFilter {
    fn matches(&self, file: &ProjectFile) -> bool {
        let rel = rel_path_string(file);
        self.rules.iter().any(|rule| match rule {
            ScanUsagesPathRule::Glob(glob) => glob.matches_with(&rel, strict_separator_options()),
            ScanUsagesPathRule::Exact(path) => rel == *path,
        })
    }

    fn summarized_paths(&self) -> (Vec<String>, Option<usize>) {
        let mut seen = HashSet::default();
        let mut paths = Vec::new();
        let mut unique_count = 0usize;
        for rule in &self.rules {
            let path = match rule {
                ScanUsagesPathRule::Glob(glob) => glob.as_str(),
                ScanUsagesPathRule::Exact(path) => path.as_str(),
            };
            if !seen.insert(path) {
                continue;
            }
            unique_count += 1;
            if paths.len() < SCAN_USAGES_SCOPE_PATH_LIMIT {
                paths.push(truncate_scan_usages_scope_path(path));
            }
        }
        let paths_omitted = unique_count
            .checked_sub(paths.len())
            .and_then(some_if_nonzero);
        (paths, paths_omitted)
    }
}

pub(super) fn truncate_scan_usages_scope_path(path: &str) -> String {
    if path.len() <= SCAN_USAGES_SCOPE_PATH_MAX_BYTES {
        return path.to_string();
    }
    let mut cut = SCAN_USAGES_SCOPE_PATH_MAX_BYTES;
    while !path.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &path[..cut])
}

pub(super) fn build_scan_usages_path_filter(
    analyzer: &dyn IAnalyzer,
    paths: Option<&[String]>,
) -> BuiltScanUsagesPathFilter {
    let Some(paths) = paths else {
        return BuiltScanUsagesPathFilter {
            filter: None,
            ignored_paths: 0,
        };
    };
    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);
    let mut rules = Vec::new();
    let mut ignored_paths = 0;
    for raw in paths {
        let normalized = normalize_pattern(raw.trim());
        if normalized.is_empty() {
            ignored_paths += 1;
            continue;
        }
        if is_glob_pattern(&normalized) {
            if let Ok(glob) = Pattern::new(&normalized) {
                rules.push(ScanUsagesPathRule::Glob(glob));
            } else {
                ignored_paths += 1;
            }
            continue;
        }
        match resolver.resolve_literal(&normalized) {
            ResolvedFileInput::File(file) => {
                rules.push(ScanUsagesPathRule::Exact(rel_path_string(&file)));
            }
            ResolvedFileInput::Ambiguous(item) => {
                rules.extend(item.matches.into_iter().map(ScanUsagesPathRule::Exact));
            }
            ResolvedFileInput::NotFound(_) => {
                rules.push(ScanUsagesPathRule::Exact(normalized));
            }
        }
    }
    BuiltScanUsagesPathFilter {
        filter: (!rules.is_empty()).then(|| Arc::new(ScanUsagesPathFilter { rules })),
        ignored_paths,
    }
}

pub(super) fn strict_separator_options() -> MatchOptions {
    MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    }
}

pub(super) fn serialized_char_count<T: Serialize>(value: &T) -> usize {
    serde_json::to_string(value)
        .map(|text| text.chars().count())
        .unwrap_or(0)
}

pub(super) fn some_if_nonzero(value: usize) -> Option<usize> {
    (value > 0).then_some(value)
}

pub(super) fn is_true(value: &bool) -> bool {
    *value
}

pub(super) fn too_many_callsites_note(limit: usize) -> String {
    format!(
        "Stopped after the {limit}-callsite cap for this high-fanout symbol. Re-call with narrower `paths` or a more specific declaration; exhaustive output is intentionally suppressed for this query."
    )
}

pub(super) fn too_many_callsites_summary_note(limit: usize) -> String {
    format!(
        "Callsite cap exceeded for this high-fanout symbol (limit {limit}); this is an incomplete summary of observed hits before stopping. Re-call with `paths` from the files list for line-level detail."
    )
}

pub(super) fn is_full_confidence(confidence: &f64) -> bool {
    (*confidence - 1.0).abs() < f64::EPSILON
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClassifyTestFilesParams {
    pub file_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestFileKind {
    Test,
    TestSupport,
    Production,
    Ambiguous,
}

impl TestFileKind {
    /// The serialized spelling, for text renderings that carry the same verdict
    /// as the JSON payload.
    pub fn label(self) -> &'static str {
        match self {
            Self::Test => "test",
            Self::TestSupport => "test_support",
            Self::Production => "production",
            Self::Ambiguous => "ambiguous",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TestFileClassification {
    pub kind: TestFileKind,
    /// Semantic runnable-test detection for the same file, reported so callers
    /// can separate file-level test surface from files that contain test code.
    pub contains_test_code: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClassifyTestFilesResult {
    pub classifications: BTreeMap<String, TestFileClassification>,
    pub unresolved: Vec<String>,
}

pub fn classify_test_files(
    analyzer: &dyn IAnalyzer,
    params: ClassifyTestFilesParams,
) -> ClassifyTestFilesResult {
    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);
    let mut classifications = BTreeMap::new();
    let mut unresolved = Vec::new();
    for input in params.file_paths.iter() {
        match resolver.resolve_literal(input.trim()) {
            ResolvedFileInput::File(file) if file.exists() => {
                classifications.insert(
                    rel_path_string(&file),
                    classify_resolved_test_file(analyzer, &file),
                );
            }
            _ => unresolved.push(input.clone()),
        }
    }
    ClassifyTestFilesResult {
        classifications,
        unresolved,
    }
}

pub(super) fn classify_resolved_test_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> TestFileClassification {
    let path = rel_path_string(file);
    let language = language_for_file(file);
    let path_verdict = test_paths::path_test_verdict(&path);
    let contains_test_code = analyzer.contains_tests(file);
    let test_like = is_test_like_file(analyzer, file, &path, language);
    let kind = if test_like && contains_test_code {
        TestFileKind::Test
    } else if test_like {
        TestFileKind::TestSupport
    } else if path_verdict == test_paths::PathTestVerdict::ProductionRoot {
        TestFileKind::Production
    } else {
        TestFileKind::Ambiguous
    };
    TestFileClassification {
        kind,
        contains_test_code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{Language, RustAnalyzer, TestProject};

    /// The text rendering of a ranked file spells its verdict out by hand, so
    /// the two spellings must not drift from the JSON contract.
    #[test]
    fn test_file_kind_label_matches_its_serialized_spelling() {
        for kind in [
            TestFileKind::Test,
            TestFileKind::TestSupport,
            TestFileKind::Production,
            TestFileKind::Ambiguous,
        ] {
            assert_eq!(
                serde_json::Value::String(kind.label().to_string()),
                serde_json::to_value(kind).unwrap(),
                "{kind:?}"
            );
        }
    }

    /// A crate whose caller module holds enough proved sites that a mid-scan
    /// cancellation can land after some of them are recorded.
    fn partial_scan_fixture() -> (tempfile::TempDir, RustAnalyzer) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonicalize temp dir");
        std::fs::create_dir_all(root.join("src")).expect("create src");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"partial\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .expect("write manifest");
        std::fs::write(
            root.join("src/lib.rs"),
            "pub mod target;\npub mod caller;\n",
        )
        .expect("write lib");
        std::fs::write(
            root.join("src/target.rs"),
            "pub fn collect_it() -> i32 {\n    1\n}\n",
        )
        .expect("write target");
        let mut caller = String::from("use crate::target::collect_it;\n");
        for index in 0..60 {
            caller.push_str(&format!(
                "pub fn call_{index}() -> i32 {{\n    collect_it()\n}}\n"
            ));
        }
        std::fs::write(root.join("src/caller.rs"), caller).expect("write caller");

        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        (temp, analyzer)
    }

    fn scan_with(analyzer: &RustAnalyzer, cancellation: CancellationToken) -> ScanUsagesResult {
        scan_usages_by_reference_with_cancellation(
            analyzer,
            ScanUsagesByReferenceParams {
                symbols: vec!["collect_it".to_string()],
                include_tests: true,
                paths: None,
                include_same_owner: false,
                max_duration_secs: None,
            },
            cancellation,
        )
    }

    fn scan_location_with(
        analyzer: &RustAnalyzer,
        cancellation: CancellationToken,
    ) -> ScanUsagesResult {
        scan_usages_by_location_with_cancellation(
            analyzer,
            ScanUsagesByLocationParams {
                targets: vec![ScanUsagesTarget {
                    path: "src/target.rs".to_string(),
                    line: 1,
                    column: None,
                    symbol: None,
                }],
                include_tests: true,
                paths: None,
                include_same_owner: false,
                max_duration_secs: None,
            },
            cancellation,
        )
    }

    #[test]
    fn issue_1416_interrupted_scan_reports_the_sites_it_proved() {
        let (_temp, analyzer) = partial_scan_fixture();

        let complete = scan_with(&analyzer, CancellationToken::default());
        let complete_entry = &complete.results[0];
        assert_eq!(ScanUsagesStatus::Found, complete_entry.status);
        assert!(complete_entry.complete);
        let complete_hits = complete_entry
            .total_hits
            .expect("complete scan counts hits");
        assert!(complete_hits > 0, "fixture must produce hits");

        // The check count is deterministic for a fixed fixture, so sweeping it
        // deterministically visits the window where the scan has proved sites
        // but has not finished. That entry must show them.
        let partial = (1..=600)
            .map(|checks| {
                scan_with(
                    &analyzer,
                    CancellationToken::cancel_after_checks_for_test(checks),
                )
            })
            .find(|result| {
                let entry = &result.results[0];
                !entry.complete && entry.total_hits.is_some_and(|hits| hits > 0)
            })
            .expect("an interrupted scan must be able to report the sites it proved");

        let entry = &partial.results[0];
        assert_eq!(
            ScanUsagesStatus::Found,
            entry.status,
            "a scan holding proved sites is not a failure"
        );
        assert!(!entry.complete);
        assert_eq!(
            Some(ScanUsagesIncompleteReason::Cancelled),
            entry.incomplete_reason
        );
        assert!(
            entry
                .message
                .iter()
                .chain(&entry.notes)
                .any(|guidance| guidance.contains("scan_usages_by_reference")),
            "a partial result must give structured recovery guidance"
        );
        assert!(
            partial.summary.partial,
            "summary must mark the batch partial"
        );
        assert!(
            entry.total_hits.is_some_and(|hits| hits <= complete_hits),
            "a partial hit list cannot exceed the complete one"
        );
    }

    #[test]
    fn issue_1630_location_partial_scan_gives_structured_recovery_guidance() {
        let (_temp, analyzer) = partial_scan_fixture();

        let complete = scan_location_with(&analyzer, CancellationToken::default());
        let complete_entry = &complete.results[0];
        assert_eq!(ScanUsagesStatus::Found, complete_entry.status);
        assert!(complete_entry.complete);
        let complete_hits = complete_entry
            .total_hits
            .expect("complete location scan counts hits");
        assert!(complete_hits > 0, "fixture must produce location hits");

        let partial = (1..=600)
            .map(|checks| {
                scan_location_with(
                    &analyzer,
                    CancellationToken::cancel_after_checks_for_test(checks),
                )
            })
            .find(|result| {
                let entry = &result.results[0];
                !entry.complete && entry.total_hits.is_some_and(|hits| hits > 0)
            })
            .expect("an interrupted location scan must report the sites it proved");

        let entry = &partial.results[0];
        assert_eq!(ScanUsagesStatus::Found, entry.status);
        assert_eq!(
            Some(ScanUsagesIncompleteReason::Cancelled),
            entry.incomplete_reason
        );
        assert!(
            entry
                .message
                .iter()
                .chain(&entry.notes)
                .any(|guidance| guidance.contains("scan_usages_by_location")),
            "a partial location result must give structured recovery guidance"
        );
        assert!(
            entry.total_hits.is_some_and(|hits| hits <= complete_hits),
            "a partial location hit list cannot exceed the complete one"
        );
    }

    #[test]
    fn issue_1416_an_incomplete_scan_never_claims_proven_absence() {
        let (_temp, analyzer) = partial_scan_fixture();

        // Whatever an interrupted scan reports, it must never be the status that
        // asserts the symbol has no callers.
        for checks in 1..=600 {
            let result = scan_with(
                &analyzer,
                CancellationToken::cancel_after_checks_for_test(checks),
            );
            let entry = &result.results[0];
            if entry.complete {
                continue;
            }
            assert_ne!(
                ScanUsagesStatus::VerifiedAbsent,
                entry.status,
                "an incomplete scan claimed proven absence at checks={checks}"
            );
            if entry.status == ScanUsagesStatus::UnverifiedAbsent {
                assert!(
                    entry
                        .absence_caveats
                        .contains(&ScanUsagesAbsenceCaveat::ScanIncomplete),
                    "an incomplete absence must carry the scan_incomplete caveat at checks={checks}"
                );
            }
        }
    }
}
