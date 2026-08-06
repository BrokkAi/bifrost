use super::navigation::deserialize_symbol_lookup_names;
use super::selectors::*;
use super::*;
use std::cell::OnceCell;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePatternsParams {
    pub file_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummariesParams {
    #[serde(deserialize_with = "deserialize_symbol_lookup_names")]
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MostRelevantFilesParams {
    pub seed_file_paths: Vec<String>,
    #[serde(default)]
    pub seed_weights: Option<Vec<f64>>,
    #[serde(default = "default_recency_half_life")]
    pub recency_half_life: Option<f64>,
    #[serde(default)]
    pub ranking_mode: MostRelevantFilesRankingMode,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryResult {
    pub summaries: Vec<SummaryBlock>,
    pub listings: Vec<ContainerListing>,
    pub not_found: Vec<NotFoundInput>,
    pub ambiguous: Vec<AmbiguousSymbol>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub too_broad: Vec<TooBroadScope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerKind {
    Directory,
    Package,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContainerListing {
    pub target: String,
    pub kind: ContainerKind,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub languages: Vec<String>,
    pub entries: Vec<ContainerListingEntry>,
    pub total_entries: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContainerListingEntry {
    Directory {
        name: String,
        path: String,
    },
    File {
        name: String,
        path: String,
    },
    Package {
        name: String,
        qualified_name: String,
        languages: Vec<String>,
    },
    Type {
        name: String,
        symbol: String,
        language: String,
        path: String,
        start_line: usize,
        end_line: usize,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryBlock {
    pub label: String,
    pub path: String,
    pub preamble: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    pub elements: Vec<SummaryElement>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryElement {
    pub path: String,
    pub symbol: String,
    pub kind: String,
    pub start_line: usize,
    pub end_line: usize,
    pub text: String,
    /// Display symbol of the enclosing scope (declaring/receiver type) for a method, else
    /// None for a top-level declaration. Lets consumers resolve a method's parent without
    /// the brittle line-span/string heuristics that break on Go/Rust/C++ method layouts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkimFilesResult {
    pub truncated: bool,
    pub total_files: usize,
    pub files: Vec<SkimFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
}

/// A ranked file plus the test classification the caller needs to apply its own
/// policy. Ranking never drops test files: the four-way verdict cannot be
/// collapsed into a boolean without lying about `Ambiguous`, and a repository
/// with no JVM-style `src/main` pair (every C project, for one) can never
/// produce `Production` at all, so a server-side "no tests" filter would have to
/// guess (#1575).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MostRelevantFile {
    pub path: String,
    pub test: TestFileKind,
}

#[derive(Debug, Clone, Serialize)]
pub struct MostRelevantFilesResult {
    pub files: Vec<MostRelevantFile>,
    pub not_found: Vec<NotFoundInput>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub duplicates: Vec<String>,
    pub complete: bool,
    pub ranking_mode_used: MostRelevantFilesRankingMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete_reason: Option<MostRelevantFilesIncompleteReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MostRelevantFilesIncompleteReason {
    Cancelled,
    TimeBudget,
    /// Ranking ran without the git co-change leg because this repository cannot
    /// supply recent history as local work. A partial clone (`--filter=blob:none`)
    /// is the case that motivated the distinction: walking its history makes Git
    /// refetch absent objects one round trip at a time (issue #1373).
    HistoryUnavailable,
}

pub(super) fn default_recency_half_life() -> Option<f64> {
    Some(DEFAULT_RECENCY_HALF_LIFE)
}

#[derive(Debug, Clone, Serialize)]
pub struct SkimFile {
    pub path: String,
    pub loc: usize,
    pub lines: Vec<String>,
}

#[derive(Debug)]
pub(super) struct SummaryTargets {
    pub(super) file_targets: Vec<ProjectFile>,
    pub(super) listings: Vec<ContainerListing>,
    pub(super) symbol_targets: Vec<String>,
    pub(super) ambiguous_paths: Vec<AmbiguousPathInput>,
    pub(super) too_broad: Vec<TooBroadScope>,
}

#[cfg(test)]
pub(super) fn route_summary_targets(
    analyzer: &dyn IAnalyzer,
    targets: &[String],
) -> SummaryTargets {
    route_summary_targets_with_cancellation(
        analyzer,
        targets,
        GET_SUMMARIES_MAX_FILES_PER_TARGET,
        None,
    )
}

/// `max_files_per_target` bounds how many files one glob target may expand to;
/// a target over the bound is reported through `too_broad` and contributes no
/// files at all, because a summary of an arbitrary subset of a huge match
/// looks complete while meaning nothing.
fn route_summary_targets_with_cancellation(
    analyzer: &dyn IAnalyzer,
    targets: &[String],
    max_files_per_target: usize,
    cancellation: Option<&crate::CancellationToken>,
) -> SummaryTargets {
    let _scope = profiling::scope("searchtools::route_summary_targets");
    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);
    // Materialized only for targets that actually name a container. Summary
    // routing used to build the whole workspace file set up front purely to ask
    // "is this target a directory?", so every `get_summaries` request — the
    // overwhelmingly common shape being a plain file path — paid a full
    // ignore-aware traversal of the repository (#1325: ~4-9s per call on a
    // 2,700-file C# tree, half the fuzzer census's tool time). The directory
    // question is now answered by a `stat` and the listing is built only when
    // that says yes.
    let workspace_files: OnceCell<Arc<BTreeSet<ProjectFile>>> = OnceCell::new();
    let mut file_targets = BTreeSet::new();
    let mut listings = Vec::new();
    let mut listed_containers = HashSet::default();
    let mut symbol_targets = Vec::new();
    let mut ambiguous_paths = Vec::new();
    let mut too_broad = Vec::new();

    for target in targets
        .iter()
        .map(|target| target.trim())
        .filter(|target| !target.is_empty())
    {
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            break;
        }
        if matches!(
            split_definition_selector_with_workspace_files(&resolver, target),
            DefinitionSelector::FileAnchored { .. }
        ) {
            symbol_targets.push(target.to_string());
            continue;
        }

        // A real filesystem directory at this workspace-relative path takes
        // precedence over any file whose *basename* merely collides with the
        // target (documented contract: "Real filesystem directories win name
        // collisions"). Check directory candidates before falling back to
        // resolver.resolve_literal's basename search, otherwise a bare name
        // that happens to collide with unrelated same-named files elsewhere
        // in the tree short-circuits into an ambiguous/file match and the
        // directory is never offered. An exact file match at this literal
        // path cannot itself collide with a directory (a path cannot be both
        // on a real filesystem), so this reordering cannot regress plain file
        // targets.
        if let Some(directory) = directory_listing_root(target)
            && analyzer.project().has_directory(&directory)
            && let Some(listing) = directory_listing(
                // `all_files_shared` hands back the project's own cached listing
                // behind an `Arc`; `all_files` would deep-clone that whole
                // `BTreeSet` on every call (#1738).
                workspace_files.get_or_init(|| {
                    analyzer
                        .project()
                        .all_files_shared()
                        .unwrap_or_else(|_| Arc::new(BTreeSet::new()))
                }),
                target,
            )
        {
            let key = (listing.kind, listing.target.clone());
            if listed_containers.insert(key) {
                listings.push(listing);
            }
            continue;
        }

        match resolver.resolve_literal(target) {
            ResolvedFileInput::File(file) => {
                file_targets.insert(file);
                continue;
            }
            ResolvedFileInput::Ambiguous(item) => {
                ambiguous_paths.push(item);
                continue;
            }
            ResolvedFileInput::NotFound(_) => {}
        }

        let matches = resolve_file_patterns(analyzer, &[target.to_string()]);
        if !matches.ambiguous_paths.is_empty() {
            ambiguous_paths.extend(matches.ambiguous_paths);
            continue;
        }
        if !matches.files.is_empty() {
            if matches.files.len() > max_files_per_target {
                too_broad.push(too_broad_scope(
                    target,
                    &matches.files,
                    max_files_per_target,
                ));
                continue;
            }
            file_targets.extend(matches.files);
            continue;
        }

        if let Some(listing) = package_listing(analyzer, target) {
            let key = (listing.kind, listing.target.clone());
            if listed_containers.insert(key) {
                listings.push(listing);
            }
            continue;
        }

        // A file-*shaped* target that matched no file is still a symbol
        // candidate: C# members legitimately end in a segment that also spells
        // a file extension (`MetadataConfiguration.Properties` vs
        // `.properties`), and short-circuiting here reported "no workspace
        // file matched" for a symbol that resolves (#1196). File shape only
        // picks the wording of the not-found note, which
        // `summarize_symbol_targets_with_cancellation` applies once symbol
        // resolution has had its say.
        symbol_targets.push(target.to_string());
    }

    SummaryTargets {
        file_targets: file_targets.into_iter().collect(),
        listings,
        symbol_targets,
        ambiguous_paths,
        too_broad,
    }
}

/// The workspace-relative directory `target` would list, if any: the empty
/// path for the workspace root, `None` for spellings that cannot name a
/// workspace directory at all (absolute, root-anchored, or `..`-escaping).
///
/// Split out of [`directory_listing`] so the cheap "is this even a directory?"
/// pre-check and the listing itself normalize the target identically.
pub(super) fn directory_listing_root(target: &str) -> Option<PathBuf> {
    let normalized = normalize_pattern(target.trim());
    let normalized = normalized.trim_end_matches('/');
    if normalized.is_empty() || normalized == "." {
        Some(PathBuf::new())
    } else {
        workspace_rel_path(normalized)
    }
}

pub(super) fn directory_listing(
    files: &BTreeSet<ProjectFile>,
    target: &str,
) -> Option<ContainerListing> {
    // Reconstructed per call: it scans every workspace file to keep the direct
    // children of one directory. Spanned so #1738 can split this cost from the
    // walk that produced `files` (`project::collect_workspace_files`) and from
    // the git-status subprocess inside it (`gitblob::dirty_worktree_paths`).
    let _scope = profiling::scope("searchtools::directory_listing");
    let directory = directory_listing_root(target)?;

    let mut entries_by_path = HashMap::default();
    for file in files {
        let Ok(remainder) = file.rel_path().strip_prefix(&directory) else {
            continue;
        };
        let mut components = remainder.components();
        let Some(first) = components.next() else {
            continue;
        };
        let first_path = directory.join(first.as_os_str());
        let path = stable_workspace_path(&first_path);
        let name = first.as_os_str().to_string_lossy().into_owned();
        let entry = if components.next().is_some() {
            ContainerListingEntry::Directory {
                name,
                path: path.clone(),
            }
        } else {
            ContainerListingEntry::File {
                name,
                path: path.clone(),
            }
        };
        entries_by_path.insert(path, entry);
    }
    if entries_by_path.is_empty() {
        return None;
    }

    let mut entries: Vec<_> = entries_by_path.into_values().collect();
    sort_container_entries(&mut entries);
    Some(ContainerListing {
        target: if directory.as_os_str().is_empty() {
            ".".to_string()
        } else {
            stable_workspace_path(&directory)
        },
        kind: ContainerKind::Directory,
        languages: Vec::new(),
        total_entries: entries.len(),
        entries,
        truncated: false,
    })
}

pub(super) fn stable_workspace_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub(super) fn package_listing(analyzer: &dyn IAnalyzer, target: &str) -> Option<ContainerListing> {
    let package = target.trim().trim_end_matches('/');
    if package.is_empty() {
        return None;
    }
    // Relative paths that are not real directories are handled as misses.
    // Import paths have a dotted first component (for example, github.com or
    // k8s.io) and remain eligible for package resolution.
    if package.contains('/')
        && !package
            .split('/')
            .next()
            .is_some_and(|component| component.contains('.'))
    {
        return None;
    }
    let index = analyzer.global_usage_definition_index();
    if !index.package_container_exists(package) {
        return None;
    }

    let mut entries = Vec::new();
    for child in index.child_packages(package) {
        let languages = package_language_labels(index.package_languages(&child));
        entries.push(ContainerListingEntry::Package {
            name: package_leaf_name(&child).to_string(),
            qualified_name: child,
            languages,
        });
    }

    let mut seen_types = HashSet::default();
    for file in index.package_files(package) {
        for unit in analyzer.top_level_declarations(&file) {
            if !unit.is_class() || unit.package_name() != package {
                continue;
            }
            let language = language_for_file(unit.source()).config_label().to_string();
            for range in analyzer.ranges(&unit) {
                let path = rel_path_string(unit.source());
                let symbol = unit.fq_name();
                if !seen_types.insert((
                    language.clone(),
                    path.clone(),
                    symbol.clone(),
                    range.start_line,
                    range.end_line,
                )) {
                    continue;
                }
                entries.push(ContainerListingEntry::Type {
                    name: display_identifier_for_target(&unit),
                    symbol,
                    language: language.clone(),
                    path,
                    start_line: range.start_line,
                    end_line: range.end_line,
                });
            }
        }
    }

    sort_container_entries(&mut entries);
    Some(ContainerListing {
        target: package.to_string(),
        kind: ContainerKind::Package,
        languages: package_language_labels(index.package_languages(package)),
        total_entries: entries.len(),
        entries,
        truncated: false,
    })
}

pub(super) fn package_language_labels(languages: Vec<Language>) -> Vec<String> {
    languages
        .into_iter()
        .filter(|language| *language != Language::None)
        .map(|language| language.config_label().to_string())
        .collect()
}

pub(super) fn package_leaf_name(package: &str) -> &str {
    package
        .rsplit_once("::")
        .or_else(|| package.rsplit_once('/'))
        .or_else(|| package.rsplit_once('.'))
        .map(|(_, leaf)| leaf)
        .unwrap_or(package)
}

pub(super) fn sort_container_entries(entries: &mut [ContainerListingEntry]) {
    entries.sort_by(|left, right| {
        container_entry_sort_key(left).cmp(&container_entry_sort_key(right))
    });
}

pub(super) fn container_entry_sort_key(entry: &ContainerListingEntry) -> (u8, &str, &str) {
    match entry {
        ContainerListingEntry::Directory { name, path } => (0, name, path),
        ContainerListingEntry::Package {
            name,
            qualified_name,
            ..
        } => (0, name, qualified_name),
        ContainerListingEntry::File { name, path } => (1, name, path),
        ContainerListingEntry::Type { name, symbol, .. } => (1, name, symbol),
    }
}

fn summarize_symbol_targets_with_cancellation(
    analyzer: &dyn IAnalyzer,
    targets: Vec<String>,
    cancellation: Option<&crate::CancellationToken>,
) -> SummaryResult {
    let _scope = profiling::scope("searchtools::summarize_symbol_targets");
    let mut summaries = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous = Vec::new();

    for target in targets {
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            break;
        }
        let _target_scope = profiling::scope(format!("summarize_symbol_target[{target}]"));
        // A slash-bearing target without a source extension is a missing
        // relative directory or package path, not a useful fuzzy symbol. Do
        // not build the workspace-wide definition index to prove that a path
        // typo is not a symbol (#1608: a 399k-row Go index added 20 seconds
        // to an ordinary directory listing request).
        if (target.contains('/') || target.contains('\\'))
            && !looks_like_explicit_source_file_target(&target)
        {
            not_found.push(file_not_found_input(target));
            continue;
        }
        if looks_like_explicit_source_file_target(&target) {
            match resolve_selectable_definitions(analyzer, &target, exact_codeunit_resolution) {
                SelectableDefinitionResolution::Resolved(code_units) => {
                    extend_symbol_summaries(
                        analyzer,
                        &target,
                        code_units,
                        &mut summaries,
                        &mut not_found,
                    );
                    continue;
                }
                SelectableDefinitionResolution::Ambiguous(item) => {
                    ambiguous.push(item);
                    continue;
                }
                SelectableDefinitionResolution::NotFound(_) => {
                    // Literal and pattern routing has already proved this is not
                    // a workspace file. Exact symbols, including slash-bearing
                    // Go names, had precedence above. Do not send an explicit
                    // missing source path through workspace-wide fuzzy lookup
                    // (#1430).
                    not_found.push(file_not_found_input(target));
                    continue;
                }
            }
        }
        match resolve_selectable_definitions(analyzer, &target, resolve_codeunit_fuzzy) {
            SelectableDefinitionResolution::Resolved(code_units) => {
                extend_symbol_summaries(
                    analyzer,
                    &target,
                    code_units,
                    &mut summaries,
                    &mut not_found,
                );
            }
            SelectableDefinitionResolution::Ambiguous(item) => ambiguous.push(item),
            // A file-shaped target that resolved to nothing keeps the
            // file-flavored note routing used to emit up front; see the
            // routing comment for why the shape check moved down here (#1196).
            SelectableDefinitionResolution::NotFound(item) => {
                not_found.push(if looks_like_file_target(&target) {
                    file_not_found_input(target)
                } else {
                    item
                });
            }
        }
    }

    SummaryResult {
        summaries,
        listings: Vec::new(),
        not_found,
        ambiguous,
        ambiguous_paths: Vec::new(),
        too_broad: Vec::new(),
    }
}

fn extend_symbol_summaries(
    analyzer: &dyn IAnalyzer,
    target: &str,
    code_units: Vec<CodeUnit>,
    summaries: &mut Vec<SummaryBlock>,
    not_found: &mut Vec<NotFoundInput>,
) {
    let start_len = summaries.len();
    for code_unit in code_units {
        if let Some(block) = summary_block_for_code_unit(analyzer, &code_unit) {
            summaries.push(block);
        }
    }
    if summaries.len() == start_len {
        not_found.push(renderable_not_found_input(target));
    }
}

pub fn get_summaries(analyzer: &dyn IAnalyzer, params: SummariesParams) -> SummaryResult {
    get_summaries_with_cancellation(analyzer, params, None)
}

pub fn get_summaries_with_cancellation(
    analyzer: &dyn IAnalyzer,
    params: SummariesParams,
    cancellation: Option<&crate::CancellationToken>,
) -> SummaryResult {
    let _scope = profiling::scope("searchtools::get_summaries");
    // Same request boundary as `get_symbol_sources`: routing builds a resolver
    // per target through `resolve_file_patterns`, so without a shared listing
    // an N-target request walked the workspace O(N) times (#1334).
    let _analyzer_query = AnalyzerQueryScope::new(analyzer);
    let targets = route_summary_targets_with_cancellation(
        analyzer,
        &params.targets,
        GET_SUMMARIES_MAX_FILES_PER_TARGET,
        cancellation,
    );
    summarize_routed_targets_with_cancellation(analyzer, &targets, cancellation)
}

pub(super) fn skim_files_for_files(
    analyzer: &dyn IAnalyzer,
    files: Vec<ProjectFile>,
) -> SkimFilesResult {
    let total_files = files.len();
    let truncated = total_files > FILE_SKIM_LIMIT;
    let selected = select_files_for_display(analyzer, files, FILE_SKIM_LIMIT);
    let mut files: Vec<_> = selected
        .into_par_iter()
        .map(|file| {
            let lines: Vec<_> = analyzer
                .list_symbols(&file)
                .lines()
                .map(str::to_string)
                .collect();
            let path = rel_path_string(&file);
            // Line count is rendering metadata alongside `list_symbols`,
            // which already reads the analyzed snapshot; use the same
            // snapshot here instead of a fresh disk read for consistency.
            let loc = analyzer
                .indexed_source(&file)
                .map(|content| line_count(&content))
                .unwrap_or(0);
            SkimFile { path, loc, lines }
        })
        .collect();
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let note = skim_files_note(truncated, files.len(), total_files);

    SkimFilesResult {
        truncated,
        total_files,
        files,
        note,
        ambiguous_paths: Vec::new(),
    }
}

pub(super) fn skim_files_note(truncated: bool, shown: usize, total: usize) -> Option<String> {
    truncated.then(|| {
        format!(
            "Showing {shown} of {total} selected files. Narrow `file_patterns` on list_symbols or `targets` on get_summaries to see the rest."
        )
    })
}

pub fn summarize_files(analyzer: &dyn IAnalyzer, files: Vec<ProjectFile>) -> SummaryResult {
    summarize_files_with_cancellation(analyzer, files, None)
}

pub fn summary_block_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<SummaryBlock> {
    summary_block_for_file_with_cancellation(analyzer, file, None)
}

fn summary_block_for_file_with_cancellation(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cancellation: Option<&crate::CancellationToken>,
) -> Option<SummaryBlock> {
    if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
        return None;
    }
    let mut elements = analyzer
        .summary_file_projection(file)
        .map(|projection| summary_elements_from_file_projection(&projection, file))
        .unwrap_or_else(|| {
            let mut elements = Vec::new();
            for code_unit in analyzer.top_level_declarations(file) {
                elements.extend(summary_elements_for_code_unit_in_file(
                    analyzer, &code_unit, file,
                ));
            }
            elements
        });

    // A module-level declaration can appear both as its own entry in
    // top_level_declarations and as a child of the synthetic module unit
    // (which is itself top-level), so the recursion above emits it twice.
    let mut seen = HashSet::default();
    elements.retain(|element| {
        seen.insert((element.symbol.clone(), element.start_line, element.end_line))
    });

    let (elements, fallback_reason) = if elements.is_empty() {
        summary_fallback_for_file(analyzer, file)?
    } else {
        (elements, None)
    };

    Some(SummaryBlock {
        label: rel_path_string(file),
        path: rel_path_string(file),
        preamble: file_preamble(analyzer, file, &elements),
        fallback_reason,
        elements,
    })
}

fn summarize_files_with_cancellation(
    analyzer: &dyn IAnalyzer,
    files: Vec<ProjectFile>,
    cancellation: Option<&crate::CancellationToken>,
) -> SummaryResult {
    let _scope = profiling::scope("searchtools::summarize_files");
    let mut summaries: Vec<_> = files
        .into_par_iter()
        .filter_map(|file| summary_block_for_file_with_cancellation(analyzer, &file, cancellation))
        .collect();
    summaries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.label.cmp(&right.label))
    });

    SummaryResult {
        summaries,
        listings: Vec::new(),
        not_found: Vec::new(),
        ambiguous: Vec::new(),
        ambiguous_paths: Vec::new(),
        too_broad: Vec::new(),
    }
}

pub(super) fn summary_fallback_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<(Vec<SummaryElement>, Option<String>)> {
    let include_elements = include_fallback_elements(analyzer, file);
    if !include_elements.is_empty() {
        return Some((
            include_elements,
            Some("no indexed declarations found; showing top-level includes".to_string()),
        ));
    }

    excerpt_fallback_elements(analyzer, file).map(|(elements, note)| (elements, Some(note)))
}

pub(super) fn include_fallback_elements(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Vec<SummaryElement> {
    let include_lines: Vec<_> = analyzer
        .import_statements(file)
        .iter()
        .filter(|statement| is_include_statement(statement))
        .cloned()
        .collect();
    if include_lines.is_empty() {
        return Vec::new();
    }

    let Ok(content) = analyzer.project().read_source(file) else {
        return Vec::new();
    };
    let path = rel_path_string(file);
    let physical_lines: Vec<&str> = content.lines().collect();
    let normalized_lines: Vec<String> = physical_lines
        .iter()
        .map(|line| normalize_include_line(line))
        .collect();

    let mut next_search_index = 0usize;
    let mut elements = Vec::new();
    for include in include_lines {
        let Some((line_index, line_text)) = normalized_lines
            .iter()
            .enumerate()
            .skip(next_search_index)
            .find_map(|(line_index, normalized)| {
                (normalized == &include).then(|| {
                    (
                        line_index,
                        physical_lines.get(line_index).copied().unwrap_or(""),
                    )
                })
            })
        else {
            continue;
        };
        next_search_index = line_index + 1;
        elements.push(SummaryElement {
            path: path.clone(),
            symbol: extract_include_target(&include),
            kind: "include".to_string(),
            start_line: line_index + 1,
            end_line: line_index + 1,
            text: line_text.trim_end().to_string(),
            parent_symbol: None,
            presentation: None,
        });
    }
    elements
}

pub(super) fn excerpt_fallback_elements(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<(Vec<SummaryElement>, String)> {
    let content = analyzer.project().read_source(file).ok()?;
    let sampled = model_context::sample(&content);
    if sampled.text.is_empty() {
        return None;
    }
    let note = sampled_excerpt_note(&sampled);
    let elements = vec![SummaryElement {
        path: rel_path_string(file),
        symbol: rel_path_string(file),
        kind: "excerpt".to_string(),
        start_line: 1,
        end_line: sampled.total_lines,
        text: sampled.text,
        parent_symbol: None,
        presentation: Some("sampled_excerpt".to_string()),
    }];
    Some((elements, note))
}

pub(super) fn sampled_excerpt_note(sampled: &model_context::HeadTail) -> String {
    if sampled.truncated {
        format!(
            "no indexed declarations or top-level includes found in this file; showing a head/tail sample with the first {} and last {} of its {} lines (the middle is omitted)",
            sampled.head_shown, sampled.tail_shown, sampled.total_lines
        )
    } else {
        format!(
            "no indexed declarations or top-level includes found in this file; showing its full text ({} lines)",
            sampled.total_lines
        )
    }
}

pub(super) fn is_include_statement(statement: &str) -> bool {
    statement.trim_start().starts_with("#include")
}

pub(super) fn normalize_include_line(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn extract_include_target(statement: &str) -> String {
    let trimmed = statement.trim();
    let rest = trimmed.strip_prefix("#include").unwrap_or(trimmed).trim();
    if rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2 {
        return rest[1..rest.len() - 1].to_string();
    }
    if rest.starts_with('<') && rest.ends_with('>') && rest.len() >= 2 {
        return rest[1..rest.len() - 1].to_string();
    }
    rest.to_string()
}

fn summarize_routed_targets_with_cancellation(
    analyzer: &dyn IAnalyzer,
    summary_targets: &SummaryTargets,
    cancellation: Option<&crate::CancellationToken>,
) -> SummaryResult {
    let mut file_output = summarize_files_with_cancellation(
        analyzer,
        summary_targets.file_targets.clone(),
        cancellation,
    );
    let symbol_output = summarize_symbol_targets_with_cancellation(
        analyzer,
        summary_targets.symbol_targets.clone(),
        cancellation,
    );

    file_output.summaries.extend(symbol_output.summaries);
    file_output.listings = summary_targets.listings.clone();
    file_output.too_broad = summary_targets.too_broad.clone();
    file_output.not_found.extend(symbol_output.not_found);
    file_output.ambiguous.extend(symbol_output.ambiguous);
    file_output
        .ambiguous_paths
        .extend(symbol_output.ambiguous_paths);
    file_output
        .ambiguous_paths
        .extend(summary_targets.ambiguous_paths.clone());
    file_output.summaries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.label.cmp(&right.label))
    });
    file_output
}

pub fn list_symbols(analyzer: &dyn IAnalyzer, params: FilePatternsParams) -> SkimFilesResult {
    let expanded = resolve_file_patterns(analyzer, &params.file_patterns);
    let mut result = skim_files_for_files(analyzer, expanded.files);
    result.ambiguous_paths = expanded.ambiguous_paths;
    result
}

pub fn most_relevant_files(
    analyzer: &dyn IAnalyzer,
    params: MostRelevantFilesParams,
) -> Result<MostRelevantFilesResult, String> {
    most_relevant_files_with_cancellation(analyzer, params, &crate::CancellationToken::default())
}

pub fn most_relevant_files_with_cancellation(
    analyzer: &dyn IAnalyzer,
    params: MostRelevantFilesParams,
    cancellation: &crate::CancellationToken,
) -> Result<MostRelevantFilesResult, String> {
    let _scope = profiling::scope("searchtools::most_relevant_files");
    validate_most_relevant_files_params(&params)?;
    if cancellation.is_cancelled() {
        return Err(most_relevant_files_cancellation_message(cancellation));
    }
    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);
    let mut seeds = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous_paths = Vec::new();
    let mut duplicates = Vec::new();
    let seed_weights = params
        .seed_weights
        .unwrap_or_else(|| vec![1.0; params.seed_file_paths.len()]);
    let recency_half_life = params.recency_half_life;
    let ranking_mode = params.ranking_mode;
    let requested_limit = params.limit;
    let mut resolved_by_file = HashMap::default();

    {
        let _scope = profiling::scope("searchtools::most_relevant_files.resolve_seeds");
        for (input, weight) in params.seed_file_paths.into_iter().zip(seed_weights) {
            if cancellation.is_cancelled() {
                return Err(most_relevant_files_cancellation_message(cancellation));
            }
            let trimmed = input.trim();
            if trimmed.is_empty() {
                continue;
            }

            match resolver.resolve_literal(trimmed) {
                ResolvedFileInput::File(file) => {
                    let display_path = rel_path_string(&file);
                    if resolved_by_file.insert(file.clone(), ()).is_some() {
                        duplicates.push(display_path);
                        continue;
                    }
                    seeds.push((file, weight));
                }
                ResolvedFileInput::Ambiguous(item) => ambiguous_paths.push(item),
                ResolvedFileInput::NotFound(item) => not_found.push(file_not_found_input(item)),
            }
        }
    }

    duplicates.sort();
    duplicates.dedup();
    if !duplicates.is_empty() {
        return Ok(MostRelevantFilesResult {
            files: Vec::new(),
            not_found,
            ambiguous_paths,
            duplicates,
            complete: true,
            ranking_mode_used: ranking_mode,
            incomplete_reason: None,
        });
    }

    let (files, complete, ranking_mode_used, incomplete_reason) = {
        let _scope = profiling::scope("searchtools::most_relevant_files.rank");
        let (ranked, complete, ranking_mode_used, incomplete_reason) =
            match most_relevant_project_files_with_ranking_mode_and_cancellation(
                analyzer,
                &seeds,
                requested_limit,
                recency_half_life,
                ranking_mode,
                cancellation,
            ) {
                MostRelevantProjectFilesOutcome::Complete(files) => {
                    (files, true, ranking_mode, None)
                }
                // The import leg still ranked these files; only the commit-history
                // leg was missing, so the ranking is served with the shortfall
                // named rather than discarded.
                MostRelevantProjectFilesOutcome::HistoryUnavailable(files) => (
                    files,
                    false,
                    ranking_mode,
                    Some(MostRelevantFilesIncompleteReason::HistoryUnavailable),
                ),
                // Issue #1304: a cancelled or over-budget usage-graph build is
                // reported by serving the deterministic history/import ranking
                // instead, not by failing the request. The same cancelled token
                // is passed on, so the fallback stays bounded rather than
                // starting the work the budget just stopped.
                MostRelevantProjectFilesOutcome::Cancelled => {
                    let reason = most_relevant_files_incomplete_reason(cancellation);
                    let (files, _) = most_relevant_project_files_with_half_life(
                        analyzer,
                        &seeds,
                        params.limit,
                        recency_half_life,
                        cancellation,
                    );
                    (
                        files,
                        false,
                        MostRelevantFilesRankingMode::HistoryImports,
                        Some(reason),
                    )
                }
            };
        (
            ranked
                .into_iter()
                // The one shared classifier, so a ranked file carries exactly
                // the verdict `classify_test_files` would give it. Bounded by
                // `limit` entries.
                .map(|file| MostRelevantFile {
                    test: super::scan_usages::classify_resolved_test_file(analyzer, &file).kind,
                    path: rel_path_string(&file),
                })
                .collect(),
            complete,
            ranking_mode_used,
            incomplete_reason,
        )
    };

    Ok(MostRelevantFilesResult {
        files,
        not_found,
        ambiguous_paths,
        duplicates,
        complete,
        ranking_mode_used,
        incomplete_reason,
    })
}

/// Rank files by recent Git co-change without expanding the import graph.
///
/// This is an internal retrieval primitive for semantic search. The public
/// `most_relevant_files` tool keeps its history-plus-import behavior.
pub fn most_relevant_files_history_only(
    analyzer: &dyn IAnalyzer,
    params: MostRelevantFilesParams,
) -> Result<MostRelevantFilesResult, String> {
    let _scope = profiling::scope("searchtools::most_relevant_files_history_only");
    validate_most_relevant_files_params(&params)?;
    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);
    let mut seeds = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous_paths = Vec::new();
    let mut duplicates = Vec::new();
    let seed_weights = params
        .seed_weights
        .unwrap_or_else(|| vec![1.0; params.seed_file_paths.len()]);
    let recency_half_life = params.recency_half_life;
    let requested_limit = params.limit;
    let mut resolved_by_file = HashMap::default();

    for (input, weight) in params.seed_file_paths.into_iter().zip(seed_weights) {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }
        match resolver.resolve_literal(trimmed) {
            ResolvedFileInput::File(file) => {
                let display_path = rel_path_string(&file);
                if resolved_by_file.insert(file.clone(), ()).is_some() {
                    duplicates.push(display_path);
                    continue;
                }
                seeds.push((file, weight));
            }
            ResolvedFileInput::Ambiguous(item) => ambiguous_paths.push(item),
            ResolvedFileInput::NotFound(item) => not_found.push(file_not_found_input(item)),
        }
    }

    duplicates.sort();
    duplicates.dedup();
    if !duplicates.is_empty() {
        return Ok(MostRelevantFilesResult {
            files: Vec::new(),
            not_found,
            ambiguous_paths,
            duplicates,
            complete: true,
            ranking_mode_used: MostRelevantFilesRankingMode::HistoryImports,
            incomplete_reason: None,
        });
    }

    let (ranked, history_status) = most_relevant_project_files_history_only(
        analyzer,
        &seeds,
        requested_limit,
        recency_half_life,
        &crate::CancellationToken::default(),
    );
    let files = ranked
        .into_iter()
        .map(|file| MostRelevantFile {
            test: super::scan_usages::classify_resolved_test_file(analyzer, &file).kind,
            path: rel_path_string(&file),
        })
        .collect();
    let (complete, incomplete_reason) = match history_status {
        crate::relevance::HistoryRankingStatus::Complete => (true, None),
        crate::relevance::HistoryRankingStatus::HistoryUnavailable => (
            false,
            Some(MostRelevantFilesIncompleteReason::HistoryUnavailable),
        ),
        crate::relevance::HistoryRankingStatus::Cancelled => {
            (false, Some(MostRelevantFilesIncompleteReason::Cancelled))
        }
    };

    Ok(MostRelevantFilesResult {
        files,
        not_found,
        ambiguous_paths,
        duplicates,
        complete,
        ranking_mode_used: MostRelevantFilesRankingMode::HistoryImports,
        incomplete_reason,
    })
}

fn most_relevant_files_cancellation_message(cancellation: &crate::CancellationToken) -> String {
    if cancellation.is_timed_out() {
        "most_relevant_files exceeded its request-wide time budget".to_string()
    } else {
        "most_relevant_files was cancelled".to_string()
    }
}

fn most_relevant_files_incomplete_reason(
    cancellation: &crate::CancellationToken,
) -> MostRelevantFilesIncompleteReason {
    if cancellation.is_timed_out() {
        MostRelevantFilesIncompleteReason::TimeBudget
    } else {
        MostRelevantFilesIncompleteReason::Cancelled
    }
}

pub(super) fn validate_most_relevant_files_params(
    params: &MostRelevantFilesParams,
) -> Result<(), String> {
    if let Some(seed_weights) = params.seed_weights.as_ref() {
        if seed_weights.len() != params.seed_file_paths.len() {
            return Err(format!(
                "seed_weights length {} must match seed_file_paths length {}",
                seed_weights.len(),
                params.seed_file_paths.len()
            ));
        }

        for (index, weight) in seed_weights.iter().enumerate() {
            if !weight.is_finite() || *weight <= 0.0 {
                return Err(format!(
                    "seed_weights[{index}] must be finite and > 0, got {weight}"
                ));
            }
        }
    }

    if let Some(half_life) = params.recency_half_life
        && (!half_life.is_finite() || half_life <= 0.0)
    {
        return Err(format!(
            "recency_half_life must be finite and > 0, got {half_life}"
        ));
    }

    Ok(())
}

pub fn summary_block_for_code_unit(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
) -> Option<SummaryBlock> {
    let elements = summary_elements_for_code_unit(analyzer, code_unit);
    if elements.is_empty() {
        return None;
    }

    Some(SummaryBlock {
        label: display_symbol_for_target(code_unit),
        path: rel_path_string(code_unit.source()),
        preamble: file_preamble(analyzer, code_unit.source(), &elements),
        fallback_reason: None,
        elements,
    })
}

pub(super) fn summary_elements_for_code_unit(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
) -> Vec<SummaryElement> {
    // getSkeleton()/getSkeletons() are opaque display strings from the analyzer layer and are not
    // suitable for ranged searchtools summaries. Searchtools needs stable per-element line ranges,
    // so it derives summary elements from signatures and source ranges instead of reverse-mapping
    // formatted skeleton text.
    let mut elements = signature_elements(analyzer, code_unit);
    if code_unit.is_class() || code_unit.is_module() {
        for child in analyzer.direct_children(code_unit) {
            if child.is_anonymous() {
                continue;
            }
            elements.extend(summary_elements_for_code_unit(analyzer, &child));
        }
    }
    elements
}

pub(super) fn summary_elements_for_code_unit_in_file(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    file: &ProjectFile,
) -> Vec<SummaryElement> {
    let mut elements = signature_elements(analyzer, code_unit);
    if code_unit.is_class() || code_unit.is_module() {
        for child in analyzer.direct_children_in_file(code_unit) {
            debug_assert_eq!(child.source(), file);
            if child.is_anonymous() {
                continue;
            }
            elements.extend(summary_elements_for_code_unit_in_file(
                analyzer, &child, file,
            ));
        }
    }
    elements
}

pub(super) fn summary_elements_from_file_projection(
    projection: &SummaryFileProjection,
    file: &ProjectFile,
) -> Vec<SummaryElement> {
    let _scope = profiling::scope("searchtools::summary_elements_from_file_projection");
    let mut elements = Vec::new();
    let mut stack: Vec<_> = projection
        .top_level_declarations
        .iter()
        .rev()
        .cloned()
        .collect();
    let mut visited = HashSet::default();

    while let Some(code_unit) = stack.pop() {
        if !visited.insert(code_unit.clone()) {
            continue;
        }
        let signatures = projection
            .signatures
            .get(&code_unit)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let ranges = projection
            .ranges
            .get(&code_unit)
            .map(Vec::as_slice)
            .unwrap_or_default();
        elements.extend(summary_elements_from_signature_data(
            &code_unit, signatures, ranges,
        ));

        if !code_unit.is_class() && !code_unit.is_module() {
            continue;
        }
        if let Some(children) = projection.children.get(&code_unit) {
            stack.extend(
                children
                    .iter()
                    .rev()
                    .filter(|child| !child.is_anonymous() && child.source() == file)
                    .cloned(),
            );
        }
    }

    elements
}

pub(super) fn display_signatures(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Vec<String> {
    let signatures: Vec<_> = analyzer
        .signatures(code_unit)
        .iter()
        .filter_map(|signature| {
            let normalized = normalize_display_signature(signature);
            (!normalized.is_empty()).then_some(normalized)
        })
        .collect();
    if !signatures.is_empty() {
        return signatures;
    }

    let fallback = match code_unit.kind() {
        CodeUnitType::Class => format!("class {}", display_identifier_for_target(code_unit)),
        CodeUnitType::Function => code_unit
            .signature()
            .map(|signature| format!("{}{}", display_identifier_for_target(code_unit), signature))
            .unwrap_or_else(|| format!("{}()", display_identifier_for_target(code_unit))),
        CodeUnitType::Field => display_identifier_for_target(code_unit),
        CodeUnitType::Module => {
            display_symbol_name(language_for_target(code_unit), code_unit.short_name())
        }
        CodeUnitType::Macro => code_unit
            .signature()
            .map(str::to_string)
            .unwrap_or_else(|| display_identifier_for_target(code_unit).to_string()),
        CodeUnitType::FileScope => display_identifier_for_target(code_unit).to_string(),
    };
    vec![fallback]
}

pub(super) fn normalize_display_signature(signature: &str) -> String {
    let mut normalized = signature
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    while normalized.ends_with('{') {
        normalized.pop();
        normalized = normalized.trim_end().to_string();
    }
    normalized
}

pub(super) fn signature_elements(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
) -> Vec<SummaryElement> {
    let signatures = analyzer.signatures(code_unit);
    let ranges = analyzer.ranges(code_unit);
    summary_elements_from_signature_data(code_unit, &signatures, &ranges)
}

pub(super) fn summary_elements_from_signature_data(
    code_unit: &CodeUnit,
    signatures: &[String],
    ranges: &[Range],
) -> Vec<SummaryElement> {
    if signatures.is_empty() {
        return Vec::new();
    }

    let mut ranges = ranges.to_vec();
    ranges.sort_by_key(|range| (range.start_line, range.start_byte));
    let path = rel_path_string(code_unit.source());
    let fallback_start = ranges.first().map(|range| range.start_line).unwrap_or(1);

    let element_count = if signatures.len() == 1 {
        ranges.len().max(1)
    } else {
        signatures.len()
    };

    (0..element_count)
        .filter_map(|index| {
            let signature = signatures
                .get(index)
                .or_else(|| signatures.first())
                .expect("signatures is not empty");
            let text = trim_summary_signature(signature);
            if text.is_empty() {
                return None;
            }

            let start_line = ranges
                .get(index)
                .map(|range| range.start_line)
                .unwrap_or(fallback_start);
            let signature_line_count = text.lines().count().max(1);
            let range_line_count = ranges
                .get(index)
                .map(|range| {
                    range
                        .end_line
                        .saturating_sub(range.start_line)
                        .saturating_add(1)
                })
                .unwrap_or(1);
            let line_count = signature_line_count.max(range_line_count);
            let end_line = start_line + line_count.saturating_sub(1);
            Some(SummaryElement {
                path: path.clone(),
                symbol: display_symbol_for_target(code_unit),
                kind: code_unit_kind_name(code_unit.kind()).to_string(),
                start_line,
                end_line,
                text,
                parent_symbol: display_parent_symbol_for_target(code_unit),
                presentation: None,
            })
        })
        .collect()
}

pub(super) fn file_preamble(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    elements: &[SummaryElement],
) -> String {
    let Some(first_start_line) = elements.iter().map(|element| element.start_line).min() else {
        return String::new();
    };
    if first_start_line <= 1 {
        return String::new();
    }
    let Ok(content) = analyzer.project().read_source(file) else {
        return String::new();
    };
    content
        .lines()
        .take(first_start_line.saturating_sub(1))
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

pub(super) fn trim_summary_signature(signature: &str) -> String {
    signature
        .lines()
        .map(str::trim_end)
        .map(|line| {
            if let Some(stripped) = line.strip_suffix('{') {
                stripped.trim_end()
            } else {
                line
            }
        })
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && trimmed != "}" && trimmed != "[...]"
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod file_local_summary_tests {
    use super::*;
    use crate::analyzer::{JavaAnalyzer, Language, TestProject};

    #[test]
    fn file_summary_fallback_does_not_expand_a_java_package() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file_a = ProjectFile::new(root.clone(), "src/p/A.java");
        let file_b = ProjectFile::new(root.clone(), "src/p/B.java");
        file_a
            .write("package p; public class A { void fromA() {} }")
            .unwrap();
        file_b
            .write("package p; public class B { void fromB() {} }")
            .unwrap();
        let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));
        let package = analyzer
            .top_level_declarations(&file_a)
            .into_iter()
            .find(CodeUnit::is_module)
            .expect("synthetic package module in A.java");

        analyzer.reset_package_declaration_scan_count_for_test();
        let elements = summary_elements_for_code_unit_in_file(&analyzer, &package, &file_a);

        assert_eq!(analyzer.package_declaration_scan_count_for_test(), 0);
        assert!(elements.iter().any(|element| element.symbol.contains("A")));
        assert!(
            elements
                .iter()
                .all(|element| element.path == "src/p/A.java")
        );
    }
}

#[cfg(test)]
mod issue_1304_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn timeout_and_explicit_cancellation_have_distinct_reasons() {
        let timed_out = crate::CancellationToken::default().with_timeout(Duration::ZERO);
        assert!(timed_out.is_cancelled());
        assert_eq!(
            most_relevant_files_incomplete_reason(&timed_out),
            MostRelevantFilesIncompleteReason::TimeBudget
        );

        let cancelled = crate::CancellationToken::default();
        cancelled.cancel();
        assert_eq!(
            most_relevant_files_incomplete_reason(&cancelled),
            MostRelevantFilesIncompleteReason::Cancelled
        );
    }
}
