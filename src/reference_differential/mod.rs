use crate::analyzer::common::language_for_file;
use crate::analyzer::declaration_range::DeclarationNameRangeContext;
use crate::analyzer::reference_candidates::{ReferenceCandidateRanges, reference_candidate_ranges};
use crate::analyzer::test_paths;
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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

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

/// Audit structured source references against the inverse usage resolver.
///
/// The caller owns workspace construction and persistence. This function reads only
/// analyzer-generation source, performs deterministic bounded sampling, and returns
/// a serializable report without modifying the project.
pub fn run_reference_differential(
    analyzer: &dyn IAnalyzer,
    config: &ReferenceDifferentialConfig,
) -> Result<ReferenceDifferentialReport, String> {
    validate_config(config)?;
    let requested_language = corpus_language(&config.corpus_language)?;
    let mut summary = ReferenceDifferentialSummary::default();
    let mut file_errors = Vec::new();

    let eligible = eligible_files_with_inventory(analyzer, config, requested_language, || {
        analyzer.analyzed_files()
    })?;
    summary.eligible_files = eligible.len();

    let audited = select_audited_files(eligible, config);
    summary.audited_files = audited.len();
    let sampled = collect_sampled_sites(
        analyzer,
        &audited,
        requested_language,
        config,
        &mut summary,
        &mut file_errors,
    )?;
    summary.sampled_sites = sampled.len();

    let (mut records, resolved) =
        forward_resolve_sites(analyzer, sampled, config, &mut summary, &mut file_errors);
    let groups = resolved_groups(resolved);
    summary.distinct_targets = groups.len();
    compare_inverse(
        analyzer,
        &audited,
        groups,
        config,
        &mut records,
        &mut summary,
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
    _config: &ReferenceDifferentialConfig,
    summary: &mut ReferenceDifferentialSummary,
    file_errors: &mut Vec<ReferenceDifferentialFileError>,
) -> (Vec<ReferenceDifferentialSite>, Vec<ResolvedSite>) {
    let _scope = crate::profiling::scope("reference_differential::forward_resolve_sites");
    let mut by_file: BTreeMap<ProjectFile, Vec<SampledSite>> = BTreeMap::new();
    for site in sampled {
        by_file.entry(site.file.clone()).or_default().push(site);
    }
    let mut records = Vec::new();
    let mut resolved = Vec::new();
    for (file, sites) in by_file {
        let path = rel_path_string(&file);
        let Some(source) = analyzer.indexed_source(&file).map(Arc::new) else {
            file_errors.push(file_error(
                &path,
                "indexed_source_missing",
                "source disappeared before forward lookup",
            ));
            continue;
        };
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
        let outcomes = resolve_definition_batch_with_source(
            analyzer,
            requests,
            file.clone(),
            Arc::clone(&source),
        );
        for (site, outcome) in sites.into_iter().zip(outcomes) {
            summary.forward.increment(outcome.status);
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
                path: path.clone(),
                start_byte: site.range.start_byte,
                end_byte: site.range.end_byte,
                line: site.range.start_line + 1,
                text,
                source_evidence: source_evidence(
                    &source,
                    site.range.start_byte,
                    site.range.end_byte,
                ),
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
                    .enclosing_code_unit(&file, &site.range)
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
    }
    (records, resolved)
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

fn compare_inverse(
    analyzer: &dyn IAnalyzer,
    audited_files: &[ProjectFile],
    mut groups: Vec<ResolvedGroup>,
    config: &ReferenceDifferentialConfig,
    records: &mut [ReferenceDifferentialSite],
    summary: &mut ReferenceDifferentialSummary,
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
        summary.queried_targets += 1;
        let provider = ExplicitCandidateProvider::new(Arc::new(candidate_files.clone()));
        let query = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                analyzer,
                &group.targets,
                Some(&provider),
                candidate_files.len(),
                config.max_usages,
            );
        classify_group_result(records, &group, query.result, &candidate_files);
    }
    Ok(())
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
        FuzzyResult::Failure { fq_name, reason } => set_group_inconclusive(
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
    use crate::analyzer::{AnalyzerConfig, TestProject, WorkspaceAnalyzer};
    use std::cell::Cell;
    use std::fs;

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
