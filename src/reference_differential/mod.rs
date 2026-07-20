use crate::analyzer::common::language_for_file;
use crate::analyzer::declaration_range::DeclarationNameRangeContext;
use crate::analyzer::reference_candidates::{ReferenceCandidateRanges, reference_candidate_ranges};
use crate::analyzer::test_paths;
use crate::analyzer::usages::cpp_graph::CppAuthoritativeUsageBatch;
#[cfg(test)]
use crate::analyzer::usages::cpp_graph::cpp_type_owner_for_test;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, resolve_definition_batch_with_source,
};
use crate::analyzer::usages::{
    ExplicitCandidateProvider, FuzzyResult, UsageFinder, UsageHit, UsageHitKind,
};
use crate::analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, Language, ProjectFile, Range, rust_is_field_declaration_name,
};
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

const SOURCE_EVIDENCE_MAX_BYTES: usize = 512;
const SOURCE_EVIDENCE_TRUNCATION_MARKER: &str = "...[truncated]...";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceDifferentialConfig {
    pub corpus_language: String,
    pub max_files: usize,
    pub max_sites: usize,
    pub max_candidates_per_file: usize,
    pub max_source_bytes: usize,
    pub max_targets: usize,
    pub parallelism: usize,
    pub max_usage_files: usize,
    pub max_usages: usize,
    pub seed: u64,
    pub include_tests: bool,
    pub exact_site: Option<ExactReferenceSite>,
}

impl Default for ReferenceDifferentialConfig {
    fn default() -> Self {
        Self {
            corpus_language: "java".to_string(),
            max_files: 2_000,
            max_sites: 10_000,
            max_candidates_per_file: 20_000,
            max_source_bytes: 2 * 1024 * 1024,
            max_targets: 1_000,
            parallelism: 8,
            max_usage_files: 1_000,
            max_usages: 100_000,
            seed: 0,
            include_tests: true,
            exact_site: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExactReferenceSite {
    pub path: String,
    pub start_byte: usize,
    pub end_byte: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceDifferentialReport {
    pub root: String,
    pub config: ReferenceDifferentialConfig,
    pub summary: ReferenceDifferentialSummary,
    pub sites: Vec<ReferenceDifferentialSite>,
    pub file_errors: Vec<ReferenceDifferentialFileError>,
}

impl ReferenceDifferentialReport {
    pub fn actionable_count(&self) -> usize {
        self.summary.classifications.missing
    }

    pub fn has_actionable_findings(&self) -> bool {
        self.actionable_count() != 0
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReferenceDifferentialSummary {
    pub eligible_files: usize,
    pub audited_files: usize,
    pub source_bytes: u64,
    pub structured_candidates: u64,
    pub candidate_limit_exceeded_files: usize,
    pub candidate_limit_excluded_candidates_lower_bound: u64,
    pub sampled_sites: usize,
    pub declaration_sites_excluded: u64,
    pub forward: ForwardStatusCounts,
    pub distinct_targets: usize,
    pub queried_targets: usize,
    pub skipped_targets: usize,
    pub target_truncated_sites: usize,
    pub classifications: ReferenceClassificationCounts,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForwardStatusCounts {
    pub resolved: usize,
    pub no_definition: usize,
    pub unresolvable_import_boundary: usize,
    pub ambiguous: usize,
    pub unsupported_language: usize,
    pub invalid_location: usize,
    pub not_found: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReferenceClassificationCounts {
    pub consistent: usize,
    pub editor_only: usize,
    pub unproven: usize,
    pub inconclusive: usize,
    pub missing: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceClassification {
    Consistent,
    EditorOnly,
    Unproven,
    Inconclusive,
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceDifferentialSite {
    pub path: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub line: usize,
    pub text: String,
    pub source_evidence: String,
    pub forward_status: String,
    pub targets: Vec<StableDeclarationIdentity>,
    pub classification: ReferenceClassification,
    pub note: Option<String>,
    pub inverse_hit: Option<InverseHitEvidence>,
    pub diagnostics: Vec<ReferenceDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StableDeclarationIdentity {
    pub path: String,
    pub fq_name: String,
    pub kind: String,
    pub signature: Option<String>,
    pub synthetic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InverseHitEvidence {
    pub path: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub line: usize,
    pub kind: String,
    pub exact_range: bool,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceDiagnostic {
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceDifferentialFileError {
    pub path: String,
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceDifferentialProgress {
    Inventory {
        eligible_files: usize,
        audited_files: usize,
    },
    Sampling {
        sampled_sites: usize,
        structured_candidates: u64,
    },
    ForwardResolution {
        resolved_sites: usize,
        distinct_targets: usize,
    },
    ForwardFile {
        completed: usize,
        total: usize,
        path: String,
    },
    InverseTarget {
        completed: usize,
        total: usize,
        target: String,
    },
    InverseTargetStarted {
        total: usize,
        target: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SampledSite {
    priority: [u8; 32],
    file: ProjectFile,
    range: Range,
    csharp_nameof_argument: bool,
}

impl Ord for SampledSite {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| self.file.cmp(&other.file))
            .then_with(|| self.range.cmp(&other.range))
    }
}

impl PartialOrd for SampledSite {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct ResolvedGroup {
    targets: Vec<CodeUnit>,
    site_indexes: Vec<usize>,
}

struct ResolvedSite {
    record_index: usize,
    targets: Vec<CodeUnit>,
}

struct PreparedInverseGroup {
    group: ResolvedGroup,
    candidate_files: HashSet<ProjectFile>,
}

struct ForwardFileResult {
    records: Vec<ReferenceDifferentialSite>,
    resolved: Vec<ResolvedSite>,
    forward: ForwardStatusCounts,
    file_errors: Vec<ReferenceDifferentialFileError>,
}

/// Audit structured source references against the inverse usage resolver.
///
/// The caller owns workspace construction and persistence. This function reads only
/// analyzer-generation source, performs deterministic bounded sampling, and returns
/// a serializable report without modifying the project.
pub fn run_reference_differential(
    analyzer: &dyn IAnalyzer,
    config: &ReferenceDifferentialConfig,
) -> Result<ReferenceDifferentialReport, String> {
    run_reference_differential_with_progress(analyzer, config, &|_| {})
}

pub fn run_reference_differential_with_progress(
    analyzer: &dyn IAnalyzer,
    config: &ReferenceDifferentialConfig,
    progress: &(dyn Fn(ReferenceDifferentialProgress) + Sync),
) -> Result<ReferenceDifferentialReport, String> {
    validate_config(config)?;
    let worker_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.parallelism)
        .thread_name(|index| format!("reference-differential-{index}"))
        .build()
        .map_err(|err| format!("failed to build differential worker pool: {err}"))?;
    let requested_language = corpus_language(&config.corpus_language)?;
    let mut summary = ReferenceDifferentialSummary::default();
    let mut file_errors = Vec::new();

    let eligible = eligible_files_with_inventory(analyzer, config, requested_language, || {
        analyzer.analyzed_files()
    })?;
    summary.eligible_files = eligible.len();

    let audited = select_audited_files(eligible, config);
    summary.audited_files = audited.len();
    progress(ReferenceDifferentialProgress::Inventory {
        eligible_files: summary.eligible_files,
        audited_files: summary.audited_files,
    });
    let sampled = collect_sampled_sites(
        analyzer,
        &audited,
        requested_language,
        config,
        &mut summary,
        &mut file_errors,
    )?;
    summary.sampled_sites = sampled.len();
    progress(ReferenceDifferentialProgress::Sampling {
        sampled_sites: summary.sampled_sites,
        structured_candidates: summary.structured_candidates,
    });

    let (mut records, resolved) = forward_resolve_sites(
        analyzer,
        sampled,
        &worker_pool,
        &mut summary,
        &mut file_errors,
        progress,
    );
    let groups = resolved_groups(resolved);
    summary.distinct_targets = groups.len();
    progress(ReferenceDifferentialProgress::ForwardResolution {
        resolved_sites: groups.iter().map(|group| group.site_indexes.len()).sum(),
        distinct_targets: summary.distinct_targets,
    });
    compare_inverse(
        analyzer,
        &audited,
        groups,
        config,
        &mut records,
        &mut summary,
        progress,
        &worker_pool,
    )?;
    recompute_classifications(&records, &mut summary.classifications);

    Ok(ReferenceDifferentialReport {
        root: analyzer.project().root().display().to_string(),
        config: config.clone(),
        summary,
        sites: records,
        file_errors,
    })
}

fn eligible_files_with_inventory(
    analyzer: &dyn IAnalyzer,
    config: &ReferenceDifferentialConfig,
    requested_language: Language,
    inventory: impl FnOnce() -> Vec<ProjectFile>,
) -> Result<Vec<ProjectFile>, String> {
    if let Some(exact) = &config.exact_site {
        let rel_path = exact_project_path(&exact.path)?;
        let file = analyzer
            .project()
            .file_by_rel_path(&rel_path)
            .ok_or_else(|| {
                format!(
                    "exact site path `{}` is not a project file",
                    normalize_report_path(&exact.path)
                )
            })?;
        if !corpus_file_matches(&file, &config.corpus_language, requested_language) {
            return Err(format!(
                "exact site path `{}` does not match corpus language `{}`",
                rel_path_string(&file),
                config.corpus_language
            ));
        }
        if !config.include_tests
            && test_paths::is_test_like_path(&rel_path_string(&file), language_for_file(&file))
        {
            return Err(format!(
                "exact site path `{}` is excluded because test paths are disabled",
                rel_path_string(&file)
            ));
        }
        if !analyzer.is_analyzed(&file) {
            return Err(format!(
                "exact site path `{}` is not indexed by the analyzer",
                rel_path_string(&file)
            ));
        }
        return Ok(vec![file]);
    }

    let mut eligible: Vec<ProjectFile> = inventory()
        .into_iter()
        .filter(|file| corpus_file_matches(file, &config.corpus_language, requested_language))
        .filter(|file| {
            config.include_tests
                || !test_paths::is_test_like_path(&rel_path_string(file), language_for_file(file))
        })
        .collect();
    eligible.sort();
    Ok(eligible)
}

fn exact_project_path(path: &str) -> Result<PathBuf, String> {
    let normalized = path.replace('\\', "/");
    if normalized.starts_with('/')
        || normalized
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
    {
        return Err("exact site path must be workspace-relative".to_string());
    }

    let mut rel_path = PathBuf::new();
    for component in Path::new(&normalized).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => rel_path.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err("exact site path must be workspace-relative".to_string());
            }
        }
    }
    if rel_path.as_os_str().is_empty() {
        return Err("exact site path must name a project file".to_string());
    }
    Ok(rel_path)
}

fn validate_config(config: &ReferenceDifferentialConfig) -> Result<(), String> {
    for (name, value) in [
        ("max_files", config.max_files),
        ("max_sites", config.max_sites),
        ("max_candidates_per_file", config.max_candidates_per_file),
        ("max_source_bytes", config.max_source_bytes),
        ("max_targets", config.max_targets),
        ("parallelism", config.parallelism),
        ("max_usage_files", config.max_usage_files),
        ("max_usages", config.max_usages),
    ] {
        if value == 0 {
            return Err(format!("{name} must be greater than zero"));
        }
    }
    Ok(())
}

fn corpus_language(label: &str) -> Result<Language, String> {
    match label.trim().to_ascii_lowercase().as_str() {
        "c" | "cpp" | "c++" => Ok(Language::Cpp),
        "csharp" | "c#" | "cs" => Ok(Language::CSharp),
        "go" => Ok(Language::Go),
        "java" => Ok(Language::Java),
        "js" | "javascript" => Ok(Language::JavaScript),
        "php" => Ok(Language::Php),
        "py" | "python" => Ok(Language::Python),
        "rust" => Ok(Language::Rust),
        "scala" => Ok(Language::Scala),
        "ts" | "typescript" => Ok(Language::TypeScript),
        "ruby" | "rb" => Ok(Language::Ruby),
        other => Err(format!("unsupported corpus language `{other}`")),
    }
}

fn corpus_file_matches(file: &ProjectFile, label: &str, language: Language) -> bool {
    let extension = file
        .rel_path()
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);
    let normalized = label.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "c" => extension.as_deref() == Some("c"),
        "cpp" | "c++" => extension.as_deref().is_some_and(|extension| {
            extension != "c" && Language::Cpp.extensions().contains(&extension)
        }),
        _ => language_for_file(file) == language,
    }
}

fn select_audited_files(
    mut eligible: Vec<ProjectFile>,
    config: &ReferenceDifferentialConfig,
) -> Vec<ProjectFile> {
    if let Some(exact) = &config.exact_site {
        eligible.retain(|file| rel_path_string(file) == normalize_report_path(&exact.path));
        return eligible.into_iter().take(1).collect();
    }
    eligible.sort_by_cached_key(|file| stable_hash(config.seed, rel_path_string(file).as_bytes()));
    eligible.truncate(config.max_files);
    eligible.sort();
    eligible
}

fn collect_sampled_sites(
    analyzer: &dyn IAnalyzer,
    audited: &[ProjectFile],
    language: Language,
    config: &ReferenceDifferentialConfig,
    summary: &mut ReferenceDifferentialSummary,
    file_errors: &mut Vec<ReferenceDifferentialFileError>,
) -> Result<Vec<SampledSite>, String> {
    let mut heap = BinaryHeap::with_capacity(config.max_sites);
    for file in audited {
        let path = rel_path_string(file);
        let Some(source) = analyzer.indexed_source(file) else {
            file_errors.push(file_error(
                &path,
                "indexed_source_missing",
                "analyzer has no indexed source",
            ));
            continue;
        };
        if source.len() > config.max_source_bytes {
            file_errors.push(file_error(
                &path,
                "source_too_large",
                &format!(
                    "{} bytes exceeds limit {}",
                    source.len(),
                    config.max_source_bytes
                ),
            ));
            continue;
        }
        summary.source_bytes = summary.source_bytes.saturating_add(source.len() as u64);
        let context = DeclarationNameRangeContext::new(file, source);
        let Some(root) = context.root_node() else {
            file_errors.push(file_error(
                &path,
                "parse_failed",
                "tree-sitter did not produce a tree",
            ));
            continue;
        };
        let ranges =
            match reference_candidate_ranges(root, language, config.max_candidates_per_file) {
                ReferenceCandidateRanges::Complete(ranges) => ranges,
                ReferenceCandidateRanges::LimitExceeded { limit, .. } => {
                    summary.candidate_limit_exceeded_files += 1;
                    summary.candidate_limit_excluded_candidates_lower_bound = summary
                        .candidate_limit_excluded_candidates_lower_bound
                        .saturating_add(limit.saturating_add(1) as u64);
                    file_errors.push(file_error(
                        &path,
                        "candidate_limit_exceeded",
                        &format!("more than {limit} structured identifier candidates"),
                    ));
                    continue;
                }
            };
        let declaration_ranges: HashSet<(usize, usize)> = analyzer
            .declarations(file)
            .into_iter()
            .flat_map(|unit| context.name_ranges(analyzer, &unit))
            .map(|range| (range.start_byte, range.end_byte))
            .collect();
        for range in ranges {
            summary.structured_candidates = summary.structured_candidates.saturating_add(1);
            if declaration_ranges.contains(&(range.start_byte, range.end_byte)) {
                summary.declaration_sites_excluded =
                    summary.declaration_sites_excluded.saturating_add(1);
                continue;
            }
            if language == Language::Rust
                && root
                    .descendant_for_byte_range(range.start_byte, range.end_byte)
                    .is_some_and(|node| {
                        rust_is_field_declaration_name(node, range.start_byte, range.end_byte)
                    })
            {
                summary.declaration_sites_excluded =
                    summary.declaration_sites_excluded.saturating_add(1);
                continue;
            }
            if let Some(exact) = &config.exact_site
                && !exact_range_matches(exact, &path, &range)
            {
                continue;
            }
            let csharp_nameof_argument = language == Language::CSharp
                && root
                    .descendant_for_byte_range(range.start_byte, range.end_byte)
                    .is_some_and(|node| {
                        csharp_is_nameof_argument(
                            node,
                            range.start_byte,
                            range.end_byte,
                            context.content(),
                        )
                    });
            let priority = site_priority(config.seed, &path, &range);
            push_bounded(
                &mut heap,
                SampledSite {
                    priority,
                    file: file.clone(),
                    range,
                    csharp_nameof_argument,
                },
                config.max_sites,
            );
        }
    }
    let mut sampled = heap.into_vec();
    sampled.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.range.cmp(&right.range))
    });
    if config.exact_site.is_some() && sampled.is_empty() {
        return Err("exact site did not match a structured non-declaration reference".to_string());
    }
    Ok(sampled)
}

fn forward_resolve_sites(
    analyzer: &dyn IAnalyzer,
    sampled: Vec<SampledSite>,
    worker_pool: &rayon::ThreadPool,
    summary: &mut ReferenceDifferentialSummary,
    file_errors: &mut Vec<ReferenceDifferentialFileError>,
    progress: &(dyn Fn(ReferenceDifferentialProgress) + Sync),
) -> (Vec<ReferenceDifferentialSite>, Vec<ResolvedSite>) {
    let _scope = crate::profiling::scope("reference_differential::forward_resolve_sites");
    let mut by_file: BTreeMap<ProjectFile, Vec<SampledSite>> = BTreeMap::new();
    for site in sampled {
        by_file.entry(site.file.clone()).or_default().push(site);
    }
    let by_file = by_file.into_iter().collect::<Vec<_>>();
    let total = by_file.len();
    let completed = Mutex::new(0usize);
    let file_results = worker_pool.install(|| {
        by_file
            .par_iter()
            .map(|(file, sites)| {
                let path = rel_path_string(file);
                let result = forward_resolve_file(analyzer, file, sites, &path);
                let mut completed = completed.lock().expect("forward progress lock poisoned");
                *completed += 1;
                progress(ReferenceDifferentialProgress::ForwardFile {
                    completed: *completed,
                    total,
                    path,
                });
                result
            })
            .collect::<Vec<_>>()
    });

    let mut records = Vec::new();
    let mut resolved = Vec::new();
    for result in file_results {
        let record_offset = records.len();
        summary.forward.merge(&result.forward);
        file_errors.extend(result.file_errors);
        resolved.extend(result.resolved.into_iter().map(|mut site| {
            site.record_index += record_offset;
            site
        }));
        records.extend(result.records);
    }
    (records, resolved)
}

fn forward_resolve_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    sites: &[SampledSite],
    path: &str,
) -> ForwardFileResult {
    let Some(source) = analyzer.indexed_source(file).map(Arc::new) else {
        return ForwardFileResult {
            records: Vec::new(),
            resolved: Vec::new(),
            forward: ForwardStatusCounts::default(),
            file_errors: vec![file_error(
                path,
                "indexed_source_missing",
                "source disappeared before forward lookup",
            )],
        };
    };
    let mut records = Vec::with_capacity(sites.len());
    let mut resolved = Vec::new();
    let mut forward = ForwardStatusCounts::default();
    let file_errors = Vec::new();
    let requests = sites
        .iter()
        .map(|site| DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(site.range.start_byte),
            end_byte: Some(site.range.end_byte),
        })
        .collect();
    let outcomes =
        resolve_definition_batch_with_source(analyzer, requests, file.clone(), Arc::clone(&source));
    for (site, outcome) in sites.iter().cloned().zip(outcomes) {
        forward.increment(outcome.status);
        let csharp_nameof_member = outcome.status == DefinitionLookupStatus::Resolved
            && site.csharp_nameof_argument
            && !outcome.definitions.is_empty()
            && outcome.definitions.iter().all(|target| {
                matches!(target.kind(), CodeUnitType::Field | CodeUnitType::Function)
            });
        let reference = outcome.reference.as_ref();
        let text = reference
            .map(|reference| reference.text.clone())
            .unwrap_or_else(|| source[site.range.start_byte..site.range.end_byte].to_string());
        let stable_targets = outcome
            .definitions
            .iter()
            .map(stable_declaration_identity)
            .collect();
        let diagnostics = outcome
            .diagnostics
            .into_iter()
            .map(|diagnostic| ReferenceDiagnostic {
                kind: diagnostic.kind,
                message: diagnostic.message,
            })
            .collect();
        let record_index = records.len();
        records.push(ReferenceDifferentialSite {
            path: path.to_string(),
            start_byte: site.range.start_byte,
            end_byte: site.range.end_byte,
            line: site.range.start_line + 1,
            text,
            source_evidence: source_evidence(&source, site.range.start_byte, site.range.end_byte),
            forward_status: outcome.status.as_str().to_string(),
            targets: stable_targets,
            classification: if csharp_nameof_member {
                ReferenceClassification::EditorOnly
            } else {
                ReferenceClassification::Inconclusive
            },
            note: if csharp_nameof_member {
                Some("C# nameof member navigation is excluded from runtime usage".to_string())
            } else {
                (outcome.status != DefinitionLookupStatus::Resolved)
                    .then(|| format!("forward lookup returned {}", outcome.status.as_str()))
            },
            inverse_hit: None,
            diagnostics,
        });
        if outcome.status == DefinitionLookupStatus::Resolved {
            let mut targets = outcome.definitions;
            targets.sort();
            targets.dedup();
            if targets.is_empty() {
                records[record_index].note =
                    Some("resolved forward lookup returned no targets".to_string());
            } else if csharp_nameof_member {
                continue;
            } else if analyzer
                .enclosing_code_unit(file, &site.range)
                .is_some_and(|enclosing| targets.contains(&enclosing))
            {
                records[record_index].note =
                    Some("reference is enclosed by its own target declaration".to_string());
            } else {
                resolved.push(ResolvedSite {
                    record_index,
                    targets,
                });
            }
        }
    }
    ForwardFileResult {
        records,
        resolved,
        forward,
        file_errors,
    }
}

fn csharp_is_nameof_argument(
    node: tree_sitter::Node<'_>,
    start_byte: usize,
    end_byte: usize,
    source: &str,
) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent()
        && parent.start_byte() == start_byte
        && parent.end_byte() == end_byte
    {
        current = parent;
    }
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "argument" | "argument_list" => current = parent,
            "invocation_expression" => {
                return parent
                    .child_by_field_name("function")
                    .or_else(|| parent.named_child(0))
                    .and_then(|function| source.get(function.start_byte()..function.end_byte()))
                    == Some("nameof");
            }
            "member_access_expression" if parent.child_by_field_name("name") == Some(current) => {
                current = parent;
            }
            _ if csharp_transparent_nameof_parent(current, parent) => current = parent,
            _ => return false,
        }
    }
    false
}

fn csharp_transparent_nameof_parent(
    current: tree_sitter::Node<'_>,
    parent: tree_sitter::Node<'_>,
) -> bool {
    matches!(
        parent.kind(),
        "parenthesized_expression" | "checked_expression"
    ) || (parent.kind() == "cast_expression"
        && parent.child_by_field_name("value") == Some(current))
}

fn resolved_groups(resolved: Vec<ResolvedSite>) -> Vec<ResolvedGroup> {
    let mut target_sets: BTreeMap<Vec<CodeUnit>, Vec<usize>> = BTreeMap::new();
    for site in resolved {
        target_sets
            .entry(site.targets)
            .or_default()
            .push(site.record_index);
    }
    target_sets
        .into_iter()
        .map(|(targets, site_indexes)| ResolvedGroup {
            targets,
            site_indexes,
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn compare_inverse(
    analyzer: &dyn IAnalyzer,
    audited_files: &[ProjectFile],
    mut groups: Vec<ResolvedGroup>,
    config: &ReferenceDifferentialConfig,
    records: &mut [ReferenceDifferentialSite],
    summary: &mut ReferenceDifferentialSummary,
    progress: &(dyn Fn(ReferenceDifferentialProgress) + Sync),
    worker_pool: &rayon::ThreadPool,
) -> Result<(), String> {
    let files_by_path: HashMap<String, ProjectFile> = audited_files
        .iter()
        .cloned()
        .map(|file| (rel_path_string(&file), file))
        .collect();
    groups.sort_by_cached_key(|group| target_group_priority(config.seed, &group.targets));
    let omitted = groups.split_off(groups.len().min(config.max_targets));
    for group in omitted {
        summary.skipped_targets += 1;
        summary.target_truncated_sites += group.site_indexes.len();
        set_group_inconclusive(records, &group.site_indexes, "target_truncated");
    }
    let mut prepared = Vec::with_capacity(groups.len());
    for group in groups {
        let mut paths: Vec<String> = group
            .site_indexes
            .iter()
            .map(|index| records[*index].path.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if paths.len() > config.max_usage_files {
            paths.sort_by_cached_key(|path| stable_hash(config.seed, path.as_bytes()));
            let retained: HashSet<String> =
                paths.into_iter().take(config.max_usage_files).collect();
            for index in &group.site_indexes {
                if !retained.contains(&records[*index].path) {
                    records[*index].note =
                        Some("site omitted by per-target usage file limit".to_string());
                }
            }
            paths = retained.into_iter().collect();
        }
        let candidate_files: HashSet<ProjectFile> = paths
            .iter()
            .filter_map(|path| files_by_path.get(path).cloned())
            .collect();
        if candidate_files.is_empty() {
            let target = group
                .targets
                .first()
                .map(CodeUnit::fq_name)
                .unwrap_or_else(|| "<unknown target>".to_string());
            return Err(format!(
                "audited inverse scope lost every sampled file for target `{target}`"
            ));
        }
        prepared.push(PreparedInverseGroup {
            group,
            candidate_files,
        });
    }

    summary.queried_targets += prepared.len();
    if prepared.is_empty() {
        return Ok(());
    }

    let total = prepared.len();
    let records = Mutex::new(records);
    let completed = Mutex::new(0usize);
    // Nested UsageFinder queries share this outer request context, allowing
    // immutable per-file syntax to be prepared once across target groups.
    let query_scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
    let cpp_roots: HashSet<ProjectFile> = prepared
        .iter()
        .filter(|prepared| {
            prepared
                .group
                .targets
                .first()
                .is_some_and(|target| language_for_file(target.source()) == Language::Cpp)
        })
        .flat_map(|prepared| prepared.candidate_files.iter().cloned())
        .collect();
    let cpp_batch = if cpp_roots.is_empty() {
        None
    } else {
        CppAuthoritativeUsageBatch::new(analyzer, &cpp_roots)
    };
    worker_pool.install(|| {
        prepared.par_iter().for_each(|prepared| {
            let target = prepared
                .group
                .targets
                .first()
                .map(CodeUnit::fq_name)
                .unwrap_or_else(|| "<unknown>".to_string());
            let _scope = crate::profiling::scope(format!(
                "reference_differential::inverse_target[{target}]"
            ));
            progress(ReferenceDifferentialProgress::InverseTargetStarted {
                total,
                target: target.clone(),
            });
            let result =
                if let Some(batch) =
                    cpp_batch.as_ref().filter(|_| {
                        prepared.group.targets.first().is_some_and(|target| {
                            language_for_file(target.source()) == Language::Cpp
                        })
                    })
                {
                    batch
                        .find_usages(
                            &prepared.group.targets,
                            &prepared.candidate_files,
                            config.max_usages,
                        )
                        .into_fuzzy_result()
                } else {
                    let provider =
                        ExplicitCandidateProvider::new(Arc::new(prepared.candidate_files.clone()));
                    UsageFinder::new()
                        .with_authoritative_scope(true)
                        .query_with_provider(
                            analyzer,
                            &prepared.group.targets,
                            Some(&provider),
                            prepared.candidate_files.len(),
                            config.max_usages,
                        )
                        .result
                };
            {
                // Target groups partition sampled sites, so workers update disjoint records.
                // The short lock expresses that invariant safely without retaining every
                // potentially large query result until the slowest target finishes.
                let mut records = records.lock().expect("inverse record lock poisoned");
                classify_group_result(
                    &mut records,
                    &prepared.group,
                    result,
                    &prepared.candidate_files,
                );
            }
            let mut completed = completed.lock().expect("inverse progress lock poisoned");
            *completed += 1;
            progress(ReferenceDifferentialProgress::InverseTarget {
                completed: *completed,
                total,
                target,
            });
        });
    });
    finish_inverse_query(&query_scope)
}

fn finish_inverse_query(
    query_scope: &crate::analyzer::AnalyzerQueryScope<'_>,
) -> Result<(), String> {
    match query_scope.store_error() {
        Some(error) => Err(format!("inverse analyzer query failed: {error}")),
        None => Ok(()),
    }
}

fn classify_group_result(
    records: &mut [ReferenceDifferentialSite],
    group: &ResolvedGroup,
    result: FuzzyResult,
    candidate_files: &HashSet<ProjectFile>,
) {
    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
        } => {
            let proven: Vec<UsageHit> = hits_by_overload
                .into_values()
                .flat_map(BTreeSet::into_iter)
                .collect();
            let unproven: Vec<UsageHit> = unproven_by_overload
                .into_values()
                .flat_map(BTreeSet::into_iter)
                .collect();
            let unproven_truncated =
                unproven_total_by_overload.values().sum::<usize>() > unproven.len();
            classify_complete_sites(
                records,
                &group.site_indexes,
                candidate_files,
                &proven,
                &unproven,
                unproven_truncated,
            );
        }
        FuzzyResult::Ambiguous {
            hits_by_overload, ..
        } => {
            let proven: Vec<UsageHit> = group
                .targets
                .iter()
                .flat_map(|target| hits_by_overload.get(target))
                .flat_map(BTreeSet::iter)
                .cloned()
                .collect();
            for index in &group.site_indexes {
                let record = &mut records[*index];
                if let Some(hit) = covering_hit(&proven, record) {
                    apply_proven_hit(record, hit);
                } else {
                    record.note = Some("inverse usage result was ambiguous".to_string());
                }
            }
        }
        FuzzyResult::Failure {
            fq_name, reason, ..
        } => set_group_inconclusive(
            records,
            &group.site_indexes,
            &format!("inverse failure for {fq_name}: {reason}"),
        ),
        FuzzyResult::TooManyCallsites {
            total_callsites,
            limit,
            ..
        } => set_group_inconclusive(
            records,
            &group.site_indexes,
            &format!("inverse call-site limit exceeded: {total_callsites} > {limit}"),
        ),
    }
}

fn classify_complete_sites(
    records: &mut [ReferenceDifferentialSite],
    indexes: &[usize],
    candidate_files: &HashSet<ProjectFile>,
    proven: &[UsageHit],
    unproven: &[UsageHit],
    unproven_truncated: bool,
) {
    let candidate_paths: HashSet<String> = candidate_files.iter().map(rel_path_string).collect();
    for index in indexes {
        let record = &mut records[*index];
        if record.note.as_deref() == Some("site omitted by per-target usage file limit") {
            continue;
        }
        if !candidate_paths.contains(&record.path) {
            record.note = Some("site file was not included in inverse query".to_string());
        } else if let Some(hit) = covering_hit(proven, record) {
            apply_proven_hit(record, hit);
        } else if let Some(hit) = covering_hit(unproven, record) {
            record.classification = ReferenceClassification::Unproven;
            record.note = Some("inverse resolver retained this site as unproven".to_string());
            record.inverse_hit = Some(inverse_hit_evidence(hit, record));
        } else if unproven_truncated {
            record.note = Some(
                "inverse unproven samples were truncated before this site could be disproven"
                    .to_string(),
            );
        } else {
            record.classification = ReferenceClassification::Missing;
            record.note = Some(
                "forward-resolved site is absent from the complete inverse result".to_string(),
            );
        }
    }
}

fn apply_proven_hit(record: &mut ReferenceDifferentialSite, hit: &UsageHit) {
    record.classification = match hit.kind {
        UsageHitKind::Reference | UsageHitKind::OverrideDeclaration => {
            ReferenceClassification::Consistent
        }
        UsageHitKind::Import | UsageHitKind::Reexport | UsageHitKind::SelfReceiver => {
            ReferenceClassification::EditorOnly
        }
    };
    record.note = None;
    record.inverse_hit = Some(inverse_hit_evidence(hit, record));
}

fn covering_hit<'a>(
    hits: &'a [UsageHit],
    record: &ReferenceDifferentialSite,
) -> Option<&'a UsageHit> {
    hits.iter().find(|hit| {
        rel_path_string(&hit.file) == record.path
            && hit.start_offset <= record.start_byte
            && record.end_byte <= hit.end_offset
    })
}

fn inverse_hit_evidence(hit: &UsageHit, record: &ReferenceDifferentialSite) -> InverseHitEvidence {
    InverseHitEvidence {
        path: rel_path_string(&hit.file),
        start_byte: hit.start_offset,
        end_byte: hit.end_offset,
        line: hit.line + 1,
        kind: hit.kind.wire_label().to_string(),
        exact_range: hit.start_offset == record.start_byte && hit.end_offset == record.end_byte,
        snippet: hit.snippet.clone(),
    }
}

fn set_group_inconclusive(
    records: &mut [ReferenceDifferentialSite],
    indexes: &[usize],
    note: &str,
) {
    for index in indexes {
        records[*index].classification = ReferenceClassification::Inconclusive;
        records[*index].note = Some(note.to_string());
    }
}

fn recompute_classifications(
    records: &[ReferenceDifferentialSite],
    counts: &mut ReferenceClassificationCounts,
) {
    *counts = ReferenceClassificationCounts::default();
    for record in records {
        match record.classification {
            ReferenceClassification::Consistent => counts.consistent += 1,
            ReferenceClassification::EditorOnly => counts.editor_only += 1,
            ReferenceClassification::Unproven => counts.unproven += 1,
            ReferenceClassification::Inconclusive => counts.inconclusive += 1,
            ReferenceClassification::Missing => counts.missing += 1,
        }
    }
}

impl ForwardStatusCounts {
    fn increment(&mut self, status: DefinitionLookupStatus) {
        match status {
            DefinitionLookupStatus::Resolved => self.resolved += 1,
            DefinitionLookupStatus::NoDefinition => self.no_definition += 1,
            DefinitionLookupStatus::UnresolvableImportBoundary => {
                self.unresolvable_import_boundary += 1;
            }
            DefinitionLookupStatus::Ambiguous => self.ambiguous += 1,
            DefinitionLookupStatus::UnsupportedLanguage => self.unsupported_language += 1,
            DefinitionLookupStatus::InvalidLocation => self.invalid_location += 1,
            DefinitionLookupStatus::NotFound => self.not_found += 1,
        }
    }

    fn merge(&mut self, other: &Self) {
        self.resolved += other.resolved;
        self.no_definition += other.no_definition;
        self.unresolvable_import_boundary += other.unresolvable_import_boundary;
        self.ambiguous += other.ambiguous;
        self.unsupported_language += other.unsupported_language;
        self.invalid_location += other.invalid_location;
        self.not_found += other.not_found;
    }
}

fn stable_declaration_identity(unit: &CodeUnit) -> StableDeclarationIdentity {
    StableDeclarationIdentity {
        path: rel_path_string(unit.source()),
        fq_name: unit.fq_name(),
        kind: code_unit_kind(unit.kind()).to_string(),
        signature: unit.signature().map(str::to_string),
        synthetic: unit.is_synthetic(),
    }
}

fn code_unit_kind(kind: CodeUnitType) -> &'static str {
    match kind {
        CodeUnitType::Class => "class",
        CodeUnitType::Function => "function",
        CodeUnitType::Field => "field",
        CodeUnitType::Module => "module",
        CodeUnitType::Macro => "macro",
        CodeUnitType::FileScope => "file_scope",
    }
}

fn source_evidence(source: &str, start_byte: usize, end_byte: usize) -> String {
    let line_start = source[..start_byte]
        .rfind('\n')
        .map_or(0, |index| index + 1);
    let line_end = source[start_byte..]
        .find('\n')
        .map_or(source.len(), |index| start_byte + index);
    let line = source[line_start..line_end].trim_end_matches('\r');
    if line.len() <= SOURCE_EVIDENCE_MAX_BYTES {
        return line.to_string();
    }

    let marker_bytes = SOURCE_EVIDENCE_TRUNCATION_MARKER.len();
    let content_budget = SOURCE_EVIDENCE_MAX_BYTES.saturating_sub(marker_bytes * 2);
    let focus_start = start_byte.saturating_sub(line_start).min(line.len());
    let focus_end = end_byte.saturating_sub(line_start).min(line.len());
    let focus_center = focus_start.saturating_add(focus_end.saturating_sub(focus_start) / 2);
    let mut window_start = focus_center
        .saturating_sub(content_budget / 2)
        .min(line.len().saturating_sub(content_budget));
    let mut window_end = window_start.saturating_add(content_budget).min(line.len());
    while window_start < window_end && !line.is_char_boundary(window_start) {
        window_start += 1;
    }
    while window_end > window_start && !line.is_char_boundary(window_end) {
        window_end -= 1;
    }

    let mut evidence = String::with_capacity(SOURCE_EVIDENCE_MAX_BYTES);
    if window_start != 0 {
        evidence.push_str(SOURCE_EVIDENCE_TRUNCATION_MARKER);
    }
    evidence.push_str(&line[window_start..window_end]);
    if window_end != line.len() {
        evidence.push_str(SOURCE_EVIDENCE_TRUNCATION_MARKER);
    }
    evidence
}

fn exact_range_matches(exact: &ExactReferenceSite, path: &str, range: &Range) -> bool {
    normalize_report_path(&exact.path) == path
        && exact.start_byte >= range.start_byte
        && exact.start_byte < range.end_byte
        && exact.end_byte.is_none_or(|end| end == range.end_byte)
}

fn normalize_report_path(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches("./").to_string()
}

fn push_bounded(heap: &mut BinaryHeap<SampledSite>, item: SampledSite, limit: usize) {
    if heap.len() < limit {
        heap.push(item);
    } else if heap.peek().is_some_and(|largest| item < *largest) {
        heap.pop();
        heap.push(item);
    }
}

fn site_priority(seed: u64, path: &str, range: &Range) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(path.as_bytes());
    hasher.update([0]);
    hasher.update(range.start_byte.to_le_bytes());
    hasher.update(range.end_byte.to_le_bytes());
    hasher.finalize().into()
}

fn stable_hash(seed: u64, value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(value);
    hasher.finalize().into()
}

fn target_group_priority(seed: u64, targets: &[CodeUnit]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    for target in targets {
        hasher.update(rel_path_string(target.source()).as_bytes());
        hasher.update([0]);
        hasher.update(target.fq_name().as_bytes());
        hasher.update([0]);
        hasher.update(code_unit_kind(target.kind()).as_bytes());
        hasher.update([0]);
        if let Some(signature) = target.signature() {
            hasher.update(signature.as_bytes());
        }
        hasher.update([u8::from(target.is_synthetic())]);
    }
    hasher.finalize().into()
}

fn file_error(path: &str, kind: &str, message: &str) -> ReferenceDifferentialFileError {
    ReferenceDifferentialFileError {
        path: path.to_string(),
        kind: kind.to_string(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{
        AnalyzerConfig, CppAnalyzer, TestProject, WorkspaceAnalyzer, resolve_analyzer,
    };
    use std::cell::Cell;
    use std::fs;

    #[test]
    fn inverse_query_scope_propagates_store_errors_after_the_batch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let project = Arc::new(TestProject::new(root, Language::Cpp));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let scope = crate::analyzer::AnalyzerQueryScope::new(workspace.analyzer());
        scope.record_store_error_for_test(crate::analyzer::store::StoreError::new(
            "injected inverse read failure",
        ));

        assert_eq!(
            scope.store_error().map(|error| error.to_string()),
            Some("injected inverse read failure".to_string())
        );
        assert_eq!(
            finish_inverse_query(&scope),
            Err("inverse analyzer query failed: injected inverse read failure".to_string())
        );
    }

    struct RoundTripFixture {
        corpus_language: &'static str,
        analyzer_language: Language,
        file_name: &'static str,
        source: &'static str,
        call_line: &'static str,
    }

    fn audit_fixture(fixture: &RoundTripFixture) -> ReferenceDifferentialReport {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        fs::write(root.join(fixture.file_name), fixture.source).expect("write fixture");
        let project = Arc::new(TestProject::new(&root, fixture.analyzer_language));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let config = ReferenceDifferentialConfig {
            corpus_language: fixture.corpus_language.to_string(),
            max_files: 10,
            max_sites: 100,
            max_candidates_per_file: 100,
            max_source_bytes: 10_000,
            max_targets: 100,
            max_usage_files: 10,
            max_usages: 100,
            ..ReferenceDifferentialConfig::default()
        };

        run_reference_differential(workspace.analyzer(), &config).expect("run audit")
    }

    #[test]
    fn corpus_language_references_round_trip_through_forward_and_inverse_resolution() {
        let fixtures = [
            RoundTripFixture {
                corpus_language: "c",
                analyzer_language: Language::Cpp,
                file_name: "round_trip.c",
                source: "void target(void) {}\nvoid caller(void) { target(); }\n",
                call_line: "void caller(void) { target(); }",
            },
            RoundTripFixture {
                corpus_language: "cpp",
                analyzer_language: Language::Cpp,
                file_name: "round_trip.cpp",
                source: "void target() {}\nvoid caller() { target(); }\n",
                call_line: "void caller() { target(); }",
            },
            RoundTripFixture {
                corpus_language: "csharp",
                analyzer_language: Language::CSharp,
                file_name: "RoundTrip.cs",
                source: "class Foo {\n  void target() {}\n  void caller() { this.target(); }\n}\n",
                call_line: "void caller() { this.target(); }",
            },
            RoundTripFixture {
                corpus_language: "go",
                analyzer_language: Language::Go,
                file_name: "round_trip.go",
                source: "package main\n\nfunc target() {}\nfunc caller() { target() }\n",
                call_line: "func caller() { target() }",
            },
            RoundTripFixture {
                corpus_language: "js",
                analyzer_language: Language::JavaScript,
                file_name: "round_trip.js",
                source: "function target() {}\nfunction caller() { target(); }\n",
                call_line: "function caller() { target(); }",
            },
            RoundTripFixture {
                corpus_language: "php",
                analyzer_language: Language::Php,
                file_name: "RoundTrip.php",
                source: "<?php\nfunction target(): void {}\nfunction caller(): void { target(); }\n",
                call_line: "function caller(): void { target(); }",
            },
            RoundTripFixture {
                corpus_language: "py",
                analyzer_language: Language::Python,
                file_name: "round_trip.py",
                source: "def target():\n    pass\n\ndef caller():\n    target()\n",
                call_line: "target()",
            },
            RoundTripFixture {
                corpus_language: "rust",
                analyzer_language: Language::Rust,
                file_name: "round_trip.rs",
                source: "fn target() {}\nfn caller() { target(); }\n",
                call_line: "fn caller() { target(); }",
            },
            RoundTripFixture {
                corpus_language: "scala",
                analyzer_language: Language::Scala,
                file_name: "RoundTrip.scala",
                source: "package example\nobject App {\n  def target(value: Int): Int = value\n  val result = target(1)\n}\n",
                call_line: "val result = target(1)",
            },
            RoundTripFixture {
                corpus_language: "ts",
                analyzer_language: Language::TypeScript,
                file_name: "round_trip.ts",
                source: "function target(): void {}\nfunction caller(): void { target(); }\n",
                call_line: "function caller(): void { target(); }",
            },
        ];

        for fixture in fixtures {
            let report = audit_fixture(&fixture);
            let call = report
                .sites
                .iter()
                .find(|site| {
                    site.text.ends_with("target")
                        && site.source_evidence.contains(fixture.call_line)
                })
                .unwrap_or_else(|| {
                    panic!(
                        "{} fixture did not sample its target call; sites: {:#?}",
                        fixture.corpus_language, report.sites
                    )
                });

            assert_eq!(
                call.forward_status, "resolved",
                "{} forward resolution; site: {call:#?}",
                fixture.corpus_language,
            );
            assert_eq!(
                call.classification,
                ReferenceClassification::Consistent,
                "{} inverse classification; site: {call:#?}",
                fixture.corpus_language
            );
            assert!(
                call.targets
                    .iter()
                    .any(|target| target.fq_name.ends_with("target")),
                "{} target identity: {:?}",
                fixture.corpus_language,
                call.targets
            );
            assert!(
                !report.has_actionable_findings(),
                "{} report: {report:#?}",
                fixture.corpus_language
            );
        }
    }

    #[test]
    fn cpp_inverse_target_groups_share_visibility_and_prepared_consumer_syntax() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let source = concat!(
            "void first() {}\n",
            "void second() {}\n",
            "void consumer() { first(); second(); }\n",
        );
        fs::write(root.join("multi_target.cpp"), source).expect("write fixture");
        let project = Arc::new(TestProject::new(&root, Language::Cpp));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let cpp = resolve_analyzer::<CppAnalyzer>(workspace.analyzer()).expect("C++ analyzer");
        cpp.reset_authoritative_visibility_build_count_for_test();
        let file = ProjectFile::new(&root, "multi_target.cpp");
        let config = ReferenceDifferentialConfig {
            corpus_language: "cpp".to_string(),
            max_files: 10,
            max_sites: 100,
            max_candidates_per_file: 100,
            max_source_bytes: 10_000,
            max_targets: 100,
            max_usage_files: 10,
            max_usages: 1,
            ..ReferenceDifferentialConfig::default()
        };

        let report = run_reference_differential(workspace.analyzer(), &config).expect("run audit");
        for target in ["first", "second"] {
            let site = report
                .sites
                .iter()
                .find(|site| {
                    site.text == target && site.source_evidence.contains("void consumer()")
                })
                .unwrap_or_else(|| panic!("sampled {target} call: {:#?}", report.sites));
            assert_eq!(site.forward_status, "resolved", "{site:#?}");
            assert_eq!(
                site.classification,
                ReferenceClassification::Consistent,
                "{site:#?}"
            );
        }
        assert_eq!(
            cpp.prepared_syntax_parse_count_for_test(&file),
            1,
            "both inverse target groups should reuse the same consumer syntax"
        );
        assert_eq!(
            cpp.authoritative_visibility_build_count_for_test(),
            1,
            "both inverse target groups should reuse one union visibility index"
        );
    }

    #[test]
    fn cpp_inverse_logical_type_redeclarations_share_one_target_spec_scan() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let mut consumer = String::new();
        for index in 0..32 {
            let header = format!("forward_{index}.h");
            fs::write(root.join(&header), "namespace gfx { class Size; }\n")
                .expect("write forward declaration");
            consumer.push_str(&format!("#include \"{header}\"\n"));
        }
        fs::write(
            root.join("definition.h"),
            "namespace gfx { class Size {}; }\n",
        )
        .expect("write full definition");
        consumer.push_str("namespace gfx { void consume() { Size* value; } }\n");
        fs::write(root.join("consumer.cpp"), consumer).expect("write consumer");

        let project = Arc::new(TestProject::new(&root, Language::Cpp));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let cpp = resolve_analyzer::<CppAnalyzer>(workspace.analyzer()).expect("C++ analyzer");
        let mut targets = cpp.get_definitions("gfx.Size");
        assert_eq!(
            targets.len(),
            33,
            "the regression must preserve every physical declaration in the target group"
        );
        let actual_target_paths: BTreeSet<_> = targets
            .iter()
            .map(|target| rel_path_string(target.source()))
            .collect();
        let mut expected_target_paths: BTreeSet<_> =
            (0..32).map(|index| format!("forward_{index}.h")).collect();
        expected_target_paths.insert("definition.h".to_string());
        assert_eq!(actual_target_paths, expected_target_paths);
        targets.sort_by_key(|target| target.source().rel_path() == Path::new("definition.h"));
        assert_ne!(
            targets.first().expect("first target").source().rel_path(),
            Path::new("definition.h"),
            "the retained representative must be a forward declaration"
        );
        let consumer_file = ProjectFile::new(&root, "consumer.cpp");
        let definition_file = ProjectFile::new(&root, "definition.h");
        let candidate_files = HashSet::from_iter([consumer_file.clone(), definition_file.clone()]);
        let batch = CppAuthoritativeUsageBatch::new(workspace.analyzer(), &candidate_files)
            .expect("C++ authoritative batch");
        let consumer_start = fs::read_to_string(root.join("consumer.cpp"))
            .expect("read consumer")
            .find("Size* value")
            .expect("consumer type offset");
        let assert_order = |ordered_targets: &[CodeUnit]| {
            cpp.reset_target_spec_scan_count_for_test();
            let result = batch
                .find_usages(ordered_targets, &candidate_files, 100)
                .into_fuzzy_result();
            let hits = result.all_hits_including_imports();
            assert_eq!(hits.len(), 1, "one exact consumer hit: {result:#?}");
            let hit = hits.first().expect("consumer hit");
            assert_eq!(hit.file, consumer_file, "{result:#?}");
            assert_eq!(hit.start_offset, consumer_start, "{result:#?}");
            assert_eq!(hit.end_offset, consumer_start + "Size".len(), "{result:#?}");
            assert_eq!(hit.kind, UsageHitKind::Reference, "{result:#?}");
            assert_eq!(
                cpp.target_spec_scan_count_for_test(),
                2,
                "33 logical Type declarations should scan each candidate file once"
            );
        };
        assert_order(&targets);

        targets.sort_by_key(|target| target.source().rel_path() != Path::new("definition.h"));
        assert_eq!(
            targets.first().expect("first target").source().rel_path(),
            Path::new("definition.h"),
            "the second pass must retain the full definition as representative"
        );
        assert_order(&targets);
    }

    #[test]
    fn cpp_exact_member_target_does_not_reparse_sibling_owners() {
        const SIBLING_COUNT: usize = 32;
        const TARGET_INDEX: usize = 17;
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let mut source = String::from("#pragma once\nnamespace demo {\n");
        for index in 0..SIBLING_COUNT {
            source.push_str(&format!(
                "struct Sibling{index} {{ void SetHeader() {{}} void Init() {{ SetHeader(); }} }};\n"
            ));
        }
        source.push_str("}\n");
        fs::write(root.join("siblings.h"), &source).expect("write sibling fixture");
        fs::write(
            root.join("free_control.h"),
            "namespace demo { void SetHeader() {} void FreeInit() { SetHeader(); } }\n",
        )
        .expect("write namespace-free control");
        fs::write(
            root.join("forward_owner.h"),
            "namespace demo { struct ForwardOwner { void SetHeader(); void Init(); }; }\n",
        )
        .expect("write full owner");
        fs::write(
            root.join("forward_owner_fwd.h"),
            "namespace demo { struct ForwardOwner; }\n",
        )
        .expect("write forward owner");
        fs::write(
            root.join("forward_owner.cc"),
            "#include \"forward_owner_fwd.h\"\n\
             #include \"forward_owner.h\"\n\
             namespace demo {\n\
             void ForwardOwner::SetHeader() {}\n\
             void ForwardOwner::Init() { SetHeader(); }\n\
             }\n",
        )
        .expect("write out-of-line forward-owner control");

        let project: Arc<dyn crate::analyzer::Project> =
            Arc::new(TestProject::new(&root, Language::Cpp));
        let cold =
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .expect("persisted analyzer build");
        drop(cold);
        let workspace = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
            .expect("persisted analyzer reopen");
        let cpp = resolve_analyzer::<CppAnalyzer>(workspace.analyzer()).expect("C++ analyzer");
        let target_fqn = format!("demo.Sibling{TARGET_INDEX}.SetHeader");
        let targets = cpp.get_definitions(&target_fqn);
        assert_eq!(targets.len(), 1, "one exact inline target: {targets:#?}");
        let inline_owner = cpp_type_owner_for_test(workspace.analyzer(), &targets[0])
            .expect("inline method owner");
        assert_eq!(
            inline_owner.fq_name(),
            format!("demo.Sibling{TARGET_INDEX}"),
            "persisted structural children must resolve directly to their class"
        );
        let free_controls = cpp.get_definitions("demo.SetHeader");
        assert_eq!(free_controls.len(), 1, "one namespace free control");
        assert_eq!(
            cpp_type_owner_for_test(workspace.analyzer(), &free_controls[0]),
            None,
            "namespace free functions must remain ownerless"
        );
        let forward_controls: Vec<_> = cpp
            .get_definitions("demo.ForwardOwner.SetHeader")
            .into_iter()
            .filter(|target| target.source().rel_path() == Path::new("forward_owner.cc"))
            .collect();
        assert_eq!(
            forward_controls.len(),
            1,
            "one source-backed out-of-line forward-owner control: {forward_controls:#?}"
        );
        assert!(
            cpp.structural_parent_of(&forward_controls[0])
                .is_none_or(|parent| parent.is_module()),
            "out-of-line members must retain heuristic owner fallback: {forward_controls:#?}"
        );
        assert_eq!(
            cpp_type_owner_for_test(workspace.analyzer(), &forward_controls[0])
                .map(|owner| owner.fq_name()),
            Some("demo.ForwardOwner".to_string()),
            "qualified out-of-line members must still resolve through include/forward heuristics"
        );
        let free_candidate = ProjectFile::new(&root, "free_control.h");
        let free_candidate_files = HashSet::from_iter([free_candidate]);
        let free_batch =
            CppAuthoritativeUsageBatch::new(workspace.analyzer(), &free_candidate_files)
                .expect("namespace-free authoritative control batch");
        let free_result = free_batch
            .find_usages(&targets, &free_candidate_files, 1000)
            .into_fuzzy_result();
        let FuzzyResult::Success {
            unproven_total_by_overload,
            ..
        } = &free_result
        else {
            panic!("namespace-free control must resolve successfully: {free_result:#?}");
        };
        assert_eq!(
            unproven_total_by_overload.values().sum::<usize>(),
            0,
            "same-namespace free calls must be proven negatives: {free_result:#?}"
        );
        assert_eq!(
            free_result.all_hits_including_imports().len(),
            0,
            "same-namespace free calls must not hit the member target: {free_result:#?}"
        );

        let candidate = ProjectFile::new(&root, "siblings.h");
        let candidate_files = HashSet::from_iter([candidate.clone()]);
        let batch = CppAuthoritativeUsageBatch::new(workspace.analyzer(), &candidate_files)
            .expect("C++ authoritative batch");

        cpp.reset_cpp_owner_resolution_counts_for_test();
        let result = batch
            .find_usages(&targets, &candidate_files, 1000)
            .into_fuzzy_result();
        let FuzzyResult::Success {
            unproven_total_by_overload,
            ..
        } = &result
        else {
            panic!("exact sibling target must resolve successfully: {result:#?}");
        };
        assert_eq!(
            unproven_total_by_overload.values().sum::<usize>(),
            0,
            "non-target sibling collisions must remain proven negatives: {result:#?}"
        );
        let hits = result.all_hits_including_imports();
        assert_eq!(
            hits.len(),
            1,
            "only the selected sibling may match: {result:#?}"
        );
        let hit = hits.first().expect("selected sibling hit");
        assert_eq!(hit.file, candidate, "{result:#?}");
        assert!(
            hit.snippet
                .contains(&format!("struct Sibling{TARGET_INDEX}")),
            "the selected sibling's Init call must remain proven: {result:#?}"
        );

        let parent_resolutions = cpp.cpp_parent_resolution_count_for_test();
        let class_strength_parses = cpp.cpp_class_strength_parse_count_for_test();
        assert!(
            (SIBLING_COUNT..=SIBLING_COUNT * 4 + 4).contains(&parent_resolutions),
            "the first negative must exhaust N member candidates while the cached classification and structured enclosing checks keep total owner work linear; observed {parent_resolutions} resolutions for {SIBLING_COUNT} siblings"
        );
        assert_eq!(
            class_strength_parses, 0,
            "exact structural children must not invoke class-strength parsing"
        );
    }

    #[test]
    fn cpp_alias_index_initializes_only_sources_visible_to_each_authoritative_root() {
        const UNRELATED_ALIAS_COUNT: usize = 24;
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        fs::create_dir(root.join("other")).expect("create unrelated alias directory");
        fs::write(
            root.join("target.h"),
            "namespace canonical { template <typename T> struct Target {}; }\n",
        )
        .expect("write target");
        fs::write(
            root.join("declaration_free.h"),
            "#pragma once\n// Transitively visible without analyzer declarations.\n",
        )
        .expect("write declaration-free include");
        fs::write(
            root.join("consumer_alias.h"),
            "#include \"declaration_free.h\"\n#include \"target.h\"\nnamespace demo { template <typename T> using ConsumerAlias = canonical::Target<T>; }\n",
        )
        .expect("write consumer alias");
        fs::write(
            root.join("consumer.cpp"),
            "#include \"consumer_alias.h\"\nvoid consume() { canonical::Target<int> exact; MissingType<int> ignored; }\n",
        )
        .expect("write consumer");

        let mut second_root = String::new();
        for index in 0..UNRELATED_ALIAS_COUNT {
            let header = format!("other/alias_{index}.h");
            fs::write(
                root.join(&header),
                format!(
                    "#include \"../target.h\"\nnamespace other{index} {{ template <typename T> using Alias{index} = canonical::Target<T>; }}\n"
                ),
            )
            .expect("write unrelated alias");
            second_root.push_str(&format!("#include \"{header}\"\n"));
        }
        second_root.push_str(
            "void consume_other() { canonical::Target<int> exact; MissingOther<int> ignored; }\n",
        );
        fs::write(root.join("second_root.cpp"), second_root).expect("write second root");

        let project = Arc::new(TestProject::new(&root, Language::Cpp));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let cpp = resolve_analyzer::<CppAnalyzer>(workspace.analyzer()).expect("C++ analyzer");
        let _query_scope = crate::analyzer::AnalyzerQueryScope::new(workspace.analyzer());
        let targets = cpp.get_definitions("canonical.Target");
        assert_eq!(targets.len(), 1, "one canonical target: {targets:#?}");
        let consumer = ProjectFile::new(&root, "consumer.cpp");
        let second = ProjectFile::new(&root, "second_root.cpp");
        let consumer_files = HashSet::from_iter([consumer.clone()]);
        let second_files = HashSet::from_iter([second.clone()]);
        let roots = HashSet::from_iter([consumer.clone(), second.clone()]);
        let batch = CppAuthoritativeUsageBatch::new(workspace.analyzer(), &roots)
            .expect("union authoritative batch");

        let assert_exact_type_hit = |result: FuzzyResult, expected_file: &ProjectFile| {
            let FuzzyResult::Success {
                unproven_total_by_overload,
                ..
            } = &result
            else {
                panic!("type query must resolve successfully: {result:#?}");
            };
            assert_eq!(
                unproven_total_by_overload.values().sum::<usize>(),
                0,
                "type query must remain fully proven: {result:#?}"
            );
            let hits = result.all_hits_including_imports();
            assert_eq!(hits.len(), 1, "one exact type hit: {result:#?}");
            assert_eq!(
                &hits.first().expect("exact type hit").file,
                expected_file,
                "{result:#?}"
            );
        };

        let consumer_result = batch
            .find_usages(&targets, &consumer_files, 1000)
            .into_fuzzy_result();
        assert_exact_type_hit(consumer_result, &consumer);
        let consumer_visible = batch.alias_visible_source_files_for_test(&consumer);
        let declaration_free = ProjectFile::new(&root, "declaration_free.h");
        assert!(
            consumer_visible.contains(&declaration_free),
            "exact include closure must retain declaration-free transitive sources: {consumer_visible:?}"
        );
        assert!(
            consumer_visible
                .iter()
                .all(|file| { batch.alias_source_parse_count_for_test(file) == 1 }),
            "each consumer-visible source must initialize exactly once: {:?}",
            consumer_visible
                .iter()
                .map(|file| (
                    file.rel_path().to_path_buf(),
                    batch.alias_source_parse_count_for_test(file)
                ))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            cpp.prepared_syntax_parse_count_for_test(&consumer),
            1,
            "alias fallback must reuse the consumer syntax prepared by the active scan query"
        );
        let second_visible = batch.alias_visible_source_files_for_test(&second);
        let prematurely_initialized: Vec<_> = second_visible
            .difference(&consumer_visible)
            .filter_map(|file| {
                let count = batch.alias_source_parse_count_for_test(file);
                (count != 0).then(|| (file.rel_path().to_path_buf(), count))
            })
            .collect();
        assert!(
            prematurely_initialized.is_empty(),
            "the consumer query must not initialize alias sources visible only from the other authoritative root: {prematurely_initialized:?}"
        );

        let second_result = batch
            .find_usages(&targets, &second_files, 1000)
            .into_fuzzy_result();
        assert_exact_type_hit(second_result, &second);
        assert!(
            second_visible
                .iter()
                .all(|file| { batch.alias_source_parse_count_for_test(file) == 1 }),
            "the second root's visible sources must initialize once on demand"
        );
        let counts_after_both: HashMap<_, _> = roots
            .iter()
            .chain(consumer_visible.iter())
            .chain(second_visible.iter())
            .map(|file| (file.clone(), batch.alias_source_parse_count_for_test(file)))
            .collect();
        let repeated = batch
            .find_usages(&targets, &second_files, 1000)
            .into_fuzzy_result();
        assert_exact_type_hit(repeated, &second);
        assert_eq!(
            counts_after_both,
            counts_after_both
                .keys()
                .map(|file| { (file.clone(), batch.alias_source_parse_count_for_test(file),) })
                .collect(),
            "repeated alias queries must reuse initialized per-source entries"
        );

        let concurrent_batch = CppAuthoritativeUsageBatch::new(
            workspace.analyzer(),
            &HashSet::from_iter([consumer.clone()]),
        )
        .expect("concurrent single-root batch");
        let concurrent_results = std::thread::scope(|scope| {
            (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        concurrent_batch
                            .find_usages(&targets, &consumer_files, 1000)
                            .into_fuzzy_result()
                    })
                })
                .map(|handle| handle.join().expect("concurrent type query"))
                .collect::<Vec<_>>()
        });
        for result in concurrent_results {
            assert_exact_type_hit(result, &consumer);
        }
        assert!(
            concurrent_batch
                .alias_visible_source_files_for_test(&consumer)
                .iter()
                .all(|file| concurrent_batch.alias_source_parse_count_for_test(file) == 1),
            "concurrent same-file queries must share one initialization"
        );
    }

    #[test]
    fn cpp_union_visibility_preserves_each_groups_authoritative_roots() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        fs::write(root.join("left.h"), "struct LeftOnly { void ping(); };\n").expect("left header");
        fs::write(root.join("right.h"), "struct RightOnly { void ping(); };\n")
            .expect("right header");
        fs::write(
            root.join("left.cpp"),
            "#include \"left.h\"\nvoid use_left() { LeftOnly value; value.ping(); }\n",
        )
        .expect("left consumer");
        fs::write(
            root.join("right.cpp"),
            "#include \"right.h\"\nvoid use_right() { RightOnly value; value.ping(); }\n",
        )
        .expect("right consumer");
        let project = Arc::new(TestProject::new(&root, Language::Cpp));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let cpp = resolve_analyzer::<CppAnalyzer>(workspace.analyzer()).expect("C++ analyzer");
        cpp.reset_authoritative_visibility_build_count_for_test();
        let config = ReferenceDifferentialConfig {
            corpus_language: "cpp".to_string(),
            max_files: 10,
            max_sites: 100,
            max_candidates_per_file: 100,
            max_source_bytes: 10_000,
            max_targets: 100,
            max_usage_files: 10,
            max_usages: 10,
            ..ReferenceDifferentialConfig::default()
        };

        let report = run_reference_differential(workspace.analyzer(), &config).expect("run audit");
        for (consumer, expected_target) in [
            ("use_left", "LeftOnly.ping"),
            ("use_right", "RightOnly.ping"),
        ] {
            let site = report
                .sites
                .iter()
                .find(|site| {
                    site.source_evidence.contains(consumer)
                        && site
                            .targets
                            .iter()
                            .any(|target| target.fq_name == expected_target)
                })
                .unwrap_or_else(|| panic!("sampled {consumer} call: {:#?}", report.sites));
            assert_eq!(
                site.classification,
                ReferenceClassification::Consistent,
                "{site:#?}"
            );
            assert!(
                site.targets
                    .iter()
                    .any(|target| target.fq_name == expected_target),
                "{site:#?}"
            );
            assert_eq!(
                site.inverse_hit.as_ref().map(|hit| hit.path.as_str()),
                Some(if consumer == "use_left" {
                    "left.cpp"
                } else {
                    "right.cpp"
                }),
                "the group must retain its exact authoritative consumer roots"
            );
        }
        assert_eq!(cpp.authoritative_visibility_build_count_for_test(), 1);
    }

    #[test]
    fn direct_call_round_trips_through_forward_and_inverse_resolution() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        fs::write(
            root.join("A.java"),
            "class A {\n  void target() {}\n  void caller() { target(); }\n}\n",
        )
        .expect("write fixture");
        let project = Arc::new(TestProject::new(&root, Language::Java));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let config = ReferenceDifferentialConfig {
            corpus_language: "java".to_string(),
            max_files: 10,
            max_sites: 100,
            max_candidates_per_file: 100,
            max_source_bytes: 10_000,
            max_targets: 100,
            max_usage_files: 10,
            max_usages: 100,
            ..ReferenceDifferentialConfig::default()
        };

        let report = run_reference_differential(workspace.analyzer(), &config).expect("run audit");
        let call = report
            .sites
            .iter()
            .find(|site| site.source_evidence.contains("caller() { target(); }"))
            .expect("sampled target call");

        assert_eq!(call.forward_status, "resolved");
        assert_eq!(call.classification, ReferenceClassification::Consistent);
        assert_eq!(call.targets.len(), 1);
        assert_eq!(call.targets[0].fq_name, "A.target");
        assert!(!report.has_actionable_findings());
        let encoded = serde_json::to_string(&report).expect("serialize report");
        let decoded: ReferenceDifferentialReport =
            serde_json::from_str(&encoded).expect("deserialize report");
        assert_eq!(decoded.summary.classifications.consistent, 1);

        let mut withheld = vec![call.clone()];
        let candidate_files: HashSet<ProjectFile> =
            [ProjectFile::new(&root, "A.java")].into_iter().collect();
        classify_complete_sites(&mut withheld, &[0], &candidate_files, &[], &[], false);
        assert_eq!(withheld[0].classification, ReferenceClassification::Missing);
        assert_eq!(
            withheld[0].note.as_deref(),
            Some("forward-resolved site is absent from the complete inverse result")
        );
    }

    #[test]
    fn csharp_nameof_members_are_editor_only_while_runtime_members_still_round_trip() {
        let fixture = RoundTripFixture {
            corpus_language: "csharp",
            analyzer_language: Language::CSharp,
            file_name: "NameOf.cs",
            source: r#"namespace Example;
public sealed class Model {
    private string member = "";
    private void Perform() { }
    public string BareMemberName() => nameof(member);
    public string QualifiedMemberName() => nameof(this.member);
    public string MethodName() => nameof(Perform);
    public string ReadMember() => member;
}
"#,
            call_line: "",
        };

        let report = audit_fixture(&fixture);
        let nameof_members = report
            .sites
            .iter()
            .filter(|site| {
                site.source_evidence.contains("nameof(")
                    && site
                        .targets
                        .iter()
                        .any(|target| matches!(target.kind.as_str(), "field" | "function"))
            })
            .collect::<Vec<_>>();

        assert_eq!(nameof_members.len(), 3, "{:#?}", report.sites);
        for site in nameof_members {
            assert_eq!(
                site.classification,
                ReferenceClassification::EditorOnly,
                "{site:#?}"
            );
            assert_eq!(
                site.note.as_deref(),
                Some("C# nameof member navigation is excluded from runtime usage")
            );
            assert!(site.inverse_hit.is_none(), "{site:#?}");
        }

        let runtime_member = report
            .sites
            .iter()
            .find(|site| {
                site.source_evidence.contains("ReadMember() => member")
                    && site.targets.iter().any(|target| target.kind == "field")
            })
            .expect("sampled runtime member reference");
        assert_eq!(
            runtime_member.classification,
            ReferenceClassification::Consistent,
            "runtime member references must still require inverse proof: {runtime_member:#?}"
        );
        assert_eq!(report.summary.classifications.editor_only, 3);
        assert_eq!(report.summary.classifications.missing, 0, "{report:#?}");
        assert!(!report.has_actionable_findings(), "{report:#?}");
    }

    #[test]
    fn csharp_nested_call_classifies_only_nameof_operand_as_editor_only() {
        let source = r#"namespace Example;
public sealed class EventListener {
    public void AssertObjectIsValid(string name, object value) { }
}
public sealed class Model {
    private object member = new();
    public void Validate(EventListener eventListener) {
        eventListener.AssertObjectIsValid(nameof(member), member);
    }
}
"#;
        let fixture = RoundTripFixture {
            corpus_language: "csharp",
            analyzer_language: Language::CSharp,
            file_name: "NestedNameOf.cs",
            source,
            call_line: "",
        };

        let report = audit_fixture(&fixture);
        let call = "eventListener.AssertObjectIsValid(nameof(member), member);";
        let call_start = source.find(call).expect("production-shaped outer call");
        let nameof_start =
            call_start + call.find("nameof(member)").expect("nameof operand") + "nameof(".len();
        let runtime_start = call_start + call.rfind("member").expect("runtime operand");

        let nameof_site = report
            .sites
            .iter()
            .find(|site| site.start_byte == nameof_start)
            .expect("sampled nameof member");
        assert_eq!(
            nameof_site.classification,
            ReferenceClassification::EditorOnly,
            "the nearest invocation is nameof, not the outer call: {nameof_site:#?}"
        );
        assert!(
            nameof_site
                .targets
                .iter()
                .any(|target| target.fq_name == "Example.Model.member")
        );

        let runtime_site = report
            .sites
            .iter()
            .find(|site| site.start_byte == runtime_start)
            .expect("sampled runtime member");
        assert_eq!(
            runtime_site.classification,
            ReferenceClassification::Consistent,
            "the second outer-call argument remains a runtime usage: {runtime_site:#?}"
        );
        assert!(runtime_site.inverse_hit.is_some(), "{runtime_site:#?}");
        assert_eq!(report.summary.classifications.missing, 0, "{report:#?}");
        assert!(!report.has_actionable_findings(), "{report:#?}");
    }

    #[test]
    fn exact_site_selection_does_not_enumerate_the_full_analyzed_file_inventory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        fs::write(
            root.join("Target.cs"),
            "namespace Demo { class Target { } }\n",
        )
        .expect("target fixture");
        let consumer_source =
            "namespace Demo { class Consumer { Target Make() => new Target(); } }\n";
        fs::write(root.join("Consumer.cs"), consumer_source).expect("consumer fixture");
        let project = Arc::new(TestProject::new(&root, Language::CSharp));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let inventory_calls = Cell::new(0);
        let config = ReferenceDifferentialConfig {
            corpus_language: "csharp".to_string(),
            exact_site: Some(ExactReferenceSite {
                path: "Consumer.cs".to_string(),
                start_byte: consumer_source.find("new Target").expect("reference") + 4,
                end_byte: None,
            }),
            ..ReferenceDifferentialConfig::default()
        };

        let eligible =
            eligible_files_with_inventory(workspace.analyzer(), &config, Language::CSharp, || {
                inventory_calls.set(inventory_calls.get() + 1);
                workspace.analyzer().analyzed_files()
            })
            .expect("select exact file");

        assert_eq!(
            inventory_calls.get(),
            0,
            "exact mode must use a point lookup"
        );
        assert_eq!(eligible, vec![ProjectFile::new(&root, "Consumer.cs")]);

        let report = run_reference_differential(workspace.analyzer(), &config)
            .expect("run exact differential through the full semantic pipeline");
        assert_eq!(report.summary.eligible_files, 1);
        assert_eq!(report.summary.audited_files, 1);
        assert_eq!(report.summary.sampled_sites, 1);
        assert_eq!(report.sites.len(), 1);
        assert_eq!(
            report.sites[0].classification,
            ReferenceClassification::Consistent,
            "the exact consumer reference should still resolve to the external target declaration"
        );

        let broad_config = ReferenceDifferentialConfig {
            corpus_language: "csharp".to_string(),
            ..ReferenceDifferentialConfig::default()
        };
        let broad = eligible_files_with_inventory(
            workspace.analyzer(),
            &broad_config,
            Language::CSharp,
            || {
                inventory_calls.set(inventory_calls.get() + 1);
                workspace.analyzer().analyzed_files()
            },
        )
        .expect("select broad inventory");
        assert_eq!(inventory_calls.get(), 1, "broad mode requires inventory");
        assert_eq!(broad.len(), 2);

        let unsafe_config = ReferenceDifferentialConfig {
            corpus_language: "csharp".to_string(),
            exact_site: Some(ExactReferenceSite {
                path: "../Consumer.cs".to_string(),
                start_byte: 0,
                end_byte: None,
            }),
            ..ReferenceDifferentialConfig::default()
        };
        let error = eligible_files_with_inventory(
            workspace.analyzer(),
            &unsafe_config,
            Language::CSharp,
            || panic!("unsafe exact paths must fail before inventory"),
        )
        .expect_err("parent traversal must be rejected");
        assert!(error.contains("workspace-relative"), "{error}");
    }

    #[test]
    fn excluded_test_paths_are_not_sampled_or_forward_audited() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        fs::create_dir(root.join("tests")).expect("test directory");
        fs::write(
            root.join("Production.php"),
            "<?php\nfunction target(): void {}\ntarget();\n",
        )
        .expect("production fixture");
        fs::write(
            root.join("tests/Excluded.php"),
            "<?php\nfunction excluded_target(): void {}\nexcluded_target();\n",
        )
        .expect("test fixture");
        let project = Arc::new(TestProject::new(&root, Language::Php));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let config = ReferenceDifferentialConfig {
            corpus_language: "php".to_string(),
            max_files: 10,
            max_sites: 100,
            max_candidates_per_file: 100,
            max_source_bytes: 10_000,
            max_targets: 100,
            max_usage_files: 10,
            max_usages: 100,
            include_tests: false,
            ..ReferenceDifferentialConfig::default()
        };

        let report = run_reference_differential(workspace.analyzer(), &config).expect("run audit");

        assert_eq!(report.summary.eligible_files, 1);
        assert!(
            report
                .sites
                .iter()
                .all(|site| site.path == "Production.php"),
            "{:#?}",
            report.sites
        );
    }

    #[test]
    fn source_evidence_is_utf8_safe_bounded_and_marks_truncation() {
        let prefix = "\u{e9}".repeat(SOURCE_EVIDENCE_MAX_BYTES);
        let site = "target";
        let suffix = "\u{754c}".repeat(SOURCE_EVIDENCE_MAX_BYTES);
        let source = format!("{prefix}{site}{suffix}\n");
        let start = prefix.len();
        let evidence = source_evidence(&source, start, start + site.len());

        assert!(evidence.len() <= SOURCE_EVIDENCE_MAX_BYTES);
        assert!(evidence.starts_with(SOURCE_EVIDENCE_TRUNCATION_MARKER));
        assert!(evidence.ends_with(SOURCE_EVIDENCE_TRUNCATION_MARKER));
        assert!(evidence.contains(site));
        assert!(std::str::from_utf8(evidence.as_bytes()).is_ok());
    }

    #[test]
    fn candidate_limit_reports_excluded_file_and_candidate_lower_bound() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        fs::write(
            root.join("A.java"),
            "class A { void target() {} void caller() { target(); } }\n",
        )
        .expect("write fixture");
        let project = Arc::new(TestProject::new(&root, Language::Java));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let config = ReferenceDifferentialConfig {
            corpus_language: "java".to_string(),
            max_files: 1,
            max_sites: 10,
            max_candidates_per_file: 1,
            max_source_bytes: 10_000,
            max_targets: 10,
            max_usage_files: 1,
            max_usages: 10,
            ..ReferenceDifferentialConfig::default()
        };

        let report = run_reference_differential(workspace.analyzer(), &config).expect("run audit");

        assert_eq!(report.summary.audited_files, 1);
        assert_eq!(report.summary.candidate_limit_exceeded_files, 1);
        assert_eq!(
            report
                .summary
                .candidate_limit_excluded_candidates_lower_bound,
            2
        );
        assert_eq!(report.summary.structured_candidates, 0);
        assert!(report.sites.is_empty());
        assert_eq!(report.file_errors.len(), 1);
        assert_eq!(report.file_errors[0].kind, "candidate_limit_exceeded");
    }

    #[test]
    fn rust_sampler_excludes_nested_enum_field_declaration_names() {
        let fixture = RoundTripFixture {
            corpus_language: "rust",
            analyzer_language: Language::Rust,
            file_name: "lib.rs",
            source: "enum Message { Variant { payload: usize } }\n",
            call_line: "",
        };

        let report = audit_fixture(&fixture);

        assert!(
            report.summary.declaration_sites_excluded >= 1,
            "{report:#?}"
        );
        assert!(report.sites.iter().all(|site| site.text != "payload"));
    }
}
