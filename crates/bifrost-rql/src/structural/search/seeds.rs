use super::*;
use crate::analyzer::content_identity::WorkspaceContentIdentity;

#[derive(Clone)]
pub(super) enum SeedStructuralAccess {
    Scan,
    Indexed {
        index: Arc<SnapshotStructuralIndex>,
        candidates: Arc<StructuralCandidateSet>,
        workspace_content: WorkspaceContentIdentity,
    },
}

impl SeedStructuralAccess {
    fn index_file(&self, file: &ProjectFile) -> Option<&super::super::index::StructuralIndexFile> {
        match self {
            Self::Scan => None,
            Self::Indexed { index, .. } => index.file(file),
        }
    }

    fn candidate_facts(&self, file: &ProjectFile) -> Option<&[u32]> {
        match self {
            Self::Scan => None,
            Self::Indexed { candidates, .. } => Some(candidates.facts_for(file)),
        }
    }

    fn source_may_contain(
        &self,
        file: &ProjectFile,
        required_anchors: &[SourceAnchorGroup],
    ) -> Option<bool> {
        match self {
            Self::Scan => None,
            Self::Indexed { index, .. } => index.source_may_contain(file, required_anchors),
        }
    }

    fn workspace_content_guard(&self) -> Option<WorkspaceContentIdentity> {
        match self {
            Self::Scan => None,
            Self::Indexed {
                workspace_content, ..
            } => Some(*workspace_content),
        }
    }
}

pub(super) fn record_index_build_facts(
    profile: Option<&mut QueryCacheProfile>,
    build: StructuralIndexBuildMetrics,
) {
    let Some(profile) = profile else {
        return;
    };
    let facts = &mut profile.seed_structural_facts;
    facts.lookups = facts
        .lookups
        .saturating_add(build.memory_hits)
        .saturating_add(build.persisted_hydrations)
        .saturating_add(build.extractions)
        .saturating_add(build.unavailable)
        .saturating_add(build.unknown_outcomes);
    facts.memory_hits = facts.memory_hits.saturating_add(build.memory_hits);
    facts.persisted_hydrations = facts
        .persisted_hydrations
        .saturating_add(build.persisted_hydrations);
    facts.extractions = facts.extractions.saturating_add(build.extractions);
    facts.unavailable = facts.unavailable.saturating_add(build.unavailable);
    facts.unknown_outcomes = facts
        .unknown_outcomes
        .saturating_add(build.unknown_outcomes);
    facts.replayed_files = facts.replayed_files.saturating_add(build.memory_hits);
}

pub(super) fn record_index_build_access(
    profile: Option<&mut QueryExecutionProfile>,
    build: StructuralIndexBuildMetrics,
) {
    let Some(profile) = profile else {
        return;
    };
    let access = &mut profile.access_path;
    access.index_build_files = access.index_build_files.saturating_add(build.files);
    access.index_build_source_bytes = access
        .index_build_source_bytes
        .saturating_add(build.source_bytes);
    access.index_build_fact_nodes = access
        .index_build_fact_nodes
        .saturating_add(build.fact_nodes);
    access.index_build_facts_bytes = access
        .index_build_facts_bytes
        .saturating_add(build.facts_bytes);
    access.index_build_ns = access.index_build_ns.saturating_add(build.elapsed_ns);
}

pub(super) fn load_seed_facts(
    provider: &dyn StructuralFactProvider,
    file: &ProjectFile,
    cache_profile: Option<&mut QueryCacheProfile>,
) -> Option<Arc<FileFacts>> {
    let Some(profile) = cache_profile else {
        return provider.structural_facts(file);
    };
    let (facts, outcome) = provider.structural_facts_with_outcome(file);
    record_structural_facts_cache_outcome(profile, outcome, facts.is_some());
    facts
}

pub(super) fn record_structural_facts_cache_outcome(
    profile: &mut QueryCacheProfile,
    outcome: StructuralFactsCacheOutcome,
    available: bool,
) {
    match outcome {
        StructuralFactsCacheOutcome::MemoryHit => {
            profile.seed_structural_facts.record_memory_hit(available)
        }
        StructuralFactsCacheOutcome::PersistedHydration => {
            profile.seed_structural_facts.record_persisted_hydration()
        }
        StructuralFactsCacheOutcome::Extracted => {
            profile.seed_structural_facts.record_extraction();
        }
        StructuralFactsCacheOutcome::Unavailable => {
            profile.seed_structural_facts.record_unavailable();
        }
        StructuralFactsCacheOutcome::Unknown => {
            profile.seed_structural_facts.record_unknown();
        }
    }
}

pub(super) fn scan_access(
    state: &mut QueryExecutionState<'_>,
    scoped_files: usize,
    fallback_reason: Option<&str>,
) -> SeedStructuralAccess {
    if let Some(profile) = &mut state.profile {
        profile
            .access_path
            .record_selected(super::super::index_query::StructuralAccessPathKind::ScanOnly.label());
        profile.access_path.scoped_files = profile
            .access_path
            .scoped_files
            .saturating_add(u64::try_from(scoped_files).unwrap_or(u64::MAX));
        if fallback_reason.is_some() {
            profile.access_path.scan_fallbacks =
                profile.access_path.scan_fallbacks.saturating_add(1);
        }
    }
    if state.access_mode == StructuralAccessMode::IndexedRequired && state.access_failure.is_none()
    {
        state.access_failure = fallback_reason
            .map(str::to_string)
            .or_else(|| Some("query has no sound structural posting requirements".to_string()));
    }
    SeedStructuralAccess::Scan
}

pub(super) fn prepare_seed_access(
    provider: &dyn StructuralFactProvider,
    provider_file_count: usize,
    files: &[ProjectFile],
    plan: &QueryPlan,
    state: &mut QueryExecutionState<'_>,
) -> SeedStructuralAccess {
    if state.access_mode == StructuralAccessMode::ScanOnly {
        return scan_access(state, files.len(), None);
    }
    if plan.structural_access().terms().is_empty() {
        return scan_access(state, files.len(), None);
    }
    let Some(cache) = provider
        .snapshot_structural_index_cache()
        .map(super::super::provider::StructuralFactSnapshotCache::inner)
    else {
        return scan_access(
            state,
            files.len(),
            Some("structural provider has no snapshot index cache"),
        );
    };

    let uncancelled = CancellationToken::default();
    let cancellation = state.cancellation.unwrap_or(&uncancelled);
    let Some(content_identity) = provider.structural_content_identity() else {
        return scan_access(
            state,
            files.len(),
            Some("structural provider states no content identity for its analyzed files"),
        );
    };
    let ready_index = cache.get_ready(content_identity, cancellation);
    let cache_ready_before_lookup = ready_index.is_some();
    let auto_build_is_viable = files.len() >= MIN_AUTO_STRUCTURAL_INDEX_FILES
        && files.len().saturating_mul(4) >= provider_file_count;
    if state.access_mode.uses_auto_index_admission() && ready_index.is_none() {
        if !auto_build_is_viable {
            return scan_access(state, files.len(), None);
        }
        if state.access_mode.defers_first_snapshot_build()
            && !cache.auto_reuse_observed(content_identity)
        {
            state
                .structural_index_session
                .defer_auto_build(cache, content_identity);
            return scan_access(state, files.len(), None);
        }
        if cache.build_in_flight(content_identity) {
            // Somebody else is already building this snapshot's postings --
            // normally the host's background warm. Following it would bill
            // this request for a whole-snapshot build it did not start, and
            // the scan the index accelerates is available right now, so take
            // the scan and record the fallback (#2879).
            return scan_access(
                state,
                files.len(),
                Some("structural index build already in flight"),
            );
        }
    }
    let acquisition = ready_index.map_or_else(
        || cache.acquire(provider, cancellation),
        |index| StructuralIndexAcquisition::Ready {
            index,
            lifecycle: StructuralIndexLifecycle::Hit,
            wait: Default::default(),
            build: StructuralIndexBuildMetrics::default(),
        },
    );
    let wait = match &acquisition {
        StructuralIndexAcquisition::Ready { wait, .. }
        | StructuralIndexAcquisition::Unavailable { wait, .. }
        | StructuralIndexAcquisition::Cancelled { wait, .. } => *wait,
    };
    if wait.wait_ns > 0 {
        crate::profiling::note_with(|| {
            format!(
                "structural.complete_cache_wait waits={} wait_ns={}",
                wait.waits, wait.wait_ns
            )
        });
    }
    if let Some(profile) = &mut state.profile {
        let access = &mut profile.access_path;
        access.representation_version = STRUCTURAL_INDEX_REPRESENTATION_VERSION;
        access.index_lookups = access.index_lookups.saturating_add(1);
        access.index_waits = access.index_waits.saturating_add(wait.waits);
        access.index_wait_ns = access.index_wait_ns.saturating_add(wait.wait_ns);
    }

    match acquisition {
        StructuralIndexAcquisition::Ready {
            index,
            lifecycle,
            build,
            ..
        } => {
            if Some(index.content_identity()) != provider.structural_content_identity() {
                return scan_access(
                    state,
                    files.len(),
                    Some("structural analyzed content changed before index selection"),
                );
            }
            record_index_build_facts(state.cache_profile.as_mut(), build);
            record_index_build_access(state.profile.as_mut(), build);
            if crate::profiling::enabled() {
                let (retained, invalidated) = cache.verdicts().totals();
                crate::profiling::note(format!(
                    "structural-index cache={lifecycle:?} retained={retained} rebuilt={invalidated}"
                ));
            }
            if let Some(profile) = &mut state.profile {
                let access = &mut profile.access_path;
                match lifecycle {
                    StructuralIndexLifecycle::Hit => {
                        access.index_hits = access.index_hits.saturating_add(1)
                    }
                    StructuralIndexLifecycle::Built => {
                        access.index_misses = access.index_misses.saturating_add(1);
                        access.index_builds = access.index_builds.saturating_add(1);
                    }
                }
                let first_observation =
                    state.retained_value_census.as_ref().is_some_and(|census| {
                        census.first_observation(QueryRetainedValueKind::StructuralIndex, &index)
                    });
                if first_observation {
                    access.retained_bytes =
                        access.retained_bytes.saturating_add(index.retained_bytes());
                }
            }
            if state.analyzer.read_ledger_attached() {
                // Recorded here and nowhere earlier: this is the one point at
                // which the answer is drawn from the posting index, which is
                // derived from this language's whole analyzed file set. A seed
                // scan reads only the files it opens and records a `File` key
                // for each, so charging it the language scope would make every
                // edit anywhere invalidate every unit.
                //
                // The identity is the analyzer's own scope fold rather than
                // the index's raw key, because that is the value verification
                // recomputes on the head; an analyzer that states none has
                // nothing this read can be named by, and the unattested
                // identity says so instead of claiming a match.
                state.analyzer.record_read(
                    state
                        .analyzer
                        .workspace_scope_read_key(&[provider.structural_language()]),
                );
            }
            let selection = index.select(
                plan.structural_access(),
                files,
                plan.has_source_anchors(),
                cache_ready_before_lookup,
                cancellation,
            );
            if Some(index.content_identity()) != provider.structural_content_identity() {
                return scan_access(
                    state,
                    files.len(),
                    Some("structural analyzed content changed during index selection"),
                );
            }
            match selection {
                Ok(Some(candidates)) => {
                    let Some(workspace_content) = state.analyzer.workspace_content_identity()
                    else {
                        return scan_access(
                            state,
                            files.len(),
                            Some("analyzer states no workspace content identity"),
                        );
                    };
                    if Some(index.content_identity()) != provider.structural_content_identity()
                        || !state.analyzer.workspace_content_matches(workspace_content)
                    {
                        return scan_access(
                            state,
                            files.len(),
                            Some("structural analyzed content changed after index selection"),
                        );
                    }
                    state
                        .structural_index_session
                        .record_selection(workspace_content);
                    if let Some(profile) = &mut state.profile {
                        let access = &mut profile.access_path;
                        access.record_selected(&format!(
                            "{}:{}",
                            candidates.estimate.kind.label(),
                            candidates.selected
                        ));
                        access.scoped_files = access
                            .scoped_files
                            .saturating_add(candidates.estimate.scoped_files);
                        access.estimated_provider_files = access
                            .estimated_provider_files
                            .saturating_add(candidates.estimate.provider_files);
                        access.scoped_fact_nodes = access
                            .scoped_fact_nodes
                            .saturating_add(candidates.estimate.scoped_fact_nodes);
                        access.candidate_files = access
                            .candidate_files
                            .saturating_add(candidates.estimate.candidate_files);
                        access.candidate_facts = access
                            .candidate_facts
                            .saturating_add(candidates.estimate.candidate_facts);
                        access.selected_terms.extend(
                            candidates.estimate.selected_terms.iter().map(|term| {
                                QueryAccessPathTermProfile {
                                    label: term.label.to_string(),
                                    candidate_facts: term.candidate_facts,
                                }
                            }),
                        );
                        access.source_verification_required |=
                            candidates.estimate.source_verification_required;
                        access.cache_ready_lookups = access.cache_ready_lookups.saturating_add(
                            u64::from(candidates.estimate.cache_ready_before_lookup),
                        );
                    }
                    SeedStructuralAccess::Indexed {
                        index,
                        candidates: Arc::new(candidates),
                        workspace_content,
                    }
                }
                Ok(None) => scan_access(state, files.len(), None),
                Err(reason) => {
                    if reason.contains("cancelled")
                        && let Some(profile) = &mut state.profile
                    {
                        profile.access_path.index_cancelled =
                            profile.access_path.index_cancelled.saturating_add(1);
                    }
                    scan_access(state, files.len(), Some(reason))
                }
            }
        }
        StructuralIndexAcquisition::Unavailable { reason, build, .. } => {
            record_index_build_facts(state.cache_profile.as_mut(), build);
            record_index_build_access(state.profile.as_mut(), build);
            if let Some(profile) = &mut state.profile {
                let access = &mut profile.access_path;
                access.index_misses = access.index_misses.saturating_add(1);
                access.index_builds = access
                    .index_builds
                    .saturating_add(u64::from(build.elapsed_ns > 0));
                access.index_unavailable = access.index_unavailable.saturating_add(1);
                if reason.contains("limit") || reason.contains("retained-byte") {
                    access.index_over_budget = access.index_over_budget.saturating_add(1);
                }
            }
            scan_access(state, files.len(), Some(&reason))
        }
        StructuralIndexAcquisition::Cancelled { build, .. } => {
            record_index_build_facts(state.cache_profile.as_mut(), build);
            record_index_build_access(state.profile.as_mut(), build);
            if let Some(profile) = &mut state.profile {
                let access = &mut profile.access_path;
                access.index_misses = access.index_misses.saturating_add(1);
                access.index_cancelled = access.index_cancelled.saturating_add(1);
                if build.elapsed_ns > 0 {
                    access.index_builds = access.index_builds.saturating_add(1);
                }
            }
            scan_access(
                state,
                files.len(),
                Some("structural index acquisition cancelled"),
            )
        }
    }
}

/// The files one seed family enumerates, in the family's own `ProjectFile`
/// order.
///
/// The whole-workspace enumeration filters the analyzer's analyzed file set;
/// a narrowed execution scope filters exactly the files it was handed.
///
/// Neither records a whole-language scope key. The enumeration's dependency is
/// the files it opens, and every one of those records a `File` key when its
/// facts are hydrated. Charging a unit the language scope would make an edit
/// anywhere invalidate every unit of the workspace, which is exactly the reuse
/// the plan exists to keep; and which files a unit is seeded from is the
/// coordinator's enumeration over the head's analyzed files, not an input the
/// unit itself read.
pub(super) fn seed_scan_files(
    state: &QueryExecutionState<'_>,
    languages: &[Language],
    where_globs: &[glob::Pattern],
) -> Vec<ProjectFile> {
    let mut files: Vec<ProjectFile> = match state.scope.seed_files() {
        Some(seed_files) => seed_files
            .iter()
            .filter(|file| seed_file_in_scope(file, languages, where_globs))
            .cloned()
            .collect(),
        None => state
            .analyzer
            .analyzed_files()
            .into_iter()
            .filter(|file| seed_file_in_scope(file, languages, where_globs))
            .collect(),
    };
    files.sort();
    files
}

/// Whether one file is inside a seed's declared language and path scope.
fn seed_file_in_scope(
    file: &ProjectFile,
    languages: &[Language],
    where_globs: &[glob::Pattern],
) -> bool {
    let language = crate::analyzer::common::language_for_file(file);
    (languages.is_empty() || languages.contains(&language))
        && (where_globs.is_empty() || {
            let path = rel_path_string(file);
            where_globs.iter().any(|glob| glob.matches(&path))
        })
}

/// The whole-workspace enumeration the structural seed still needs for its
/// diagnostic-only language walk and its per-provider file counts.
///
/// A unit must see every file here even though it seeds from one: narrowing
/// this walk would change which `MissingStructuralAdapter` diagnostics a unit
/// reports, and diagnostics decide the result's completion.
pub(super) fn workspace_files_for_scope<'scope, 'owned>(
    state: &QueryExecutionState<'scope>,
    owned: &'owned mut Vec<ProjectFile>,
) -> &'owned [ProjectFile]
where
    'scope: 'owned,
{
    match state.scope.workspace_files() {
        Some(files) => files,
        None => {
            *owned = state.analyzer.analyzed_files();
            owned
        }
    }
}

/// One structural provider's seed candidates, with the provider's whole file
/// count for the index-admission rule.
///
/// The count stays whole under a narrowed scope: a unit over one seed file
/// must reach the same admission verdict the survey states it reaches (a slice
/// is never viable for an auto index build), so it takes the scan path rather
/// than building an index over its own slice.
pub(super) fn provider_scope_files(
    state: &QueryExecutionState<'_>,
    provider: &dyn StructuralFactProvider,
    language: Language,
    workspace_files: &[ProjectFile],
) -> (Vec<ProjectFile>, usize) {
    let Some(seed_files) = state.scope.seed_files() else {
        let files = provider.structural_files();
        let count = files.len();
        return (files, count);
    };
    let files = seed_files
        .iter()
        .filter(|file| crate::analyzer::common::language_for_file(file) == language)
        .cloned()
        .collect();
    let count = workspace_files
        .iter()
        .filter(|file| crate::analyzer::common::language_for_file(file) == language)
        .count();
    (files, count)
}

/// Derive occurrence rows straight from workspace facts.
///
/// Unlike the structural seed there is no pattern to prune with, so the scope
/// is exactly `where` plus `languages` and the per-file derivation itself is
/// the work. Files are charged against the scanned-file budget so an
/// unconstrained occurrence query degrades the same way an unconstrained
/// structural one does, and every file whose adapter cannot classify a role the
/// filter names contributes a capability diagnostic rather than silence.
pub(super) fn execute_occurrence_seed(
    seed: &OccurrenceSeed,
    terminal_cap: Option<usize>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    let budget_cap = limits
        .max_pipeline_rows
        .saturating_sub(state.budget.pipeline_rows);
    let desired_rows = terminal_cap.unwrap_or(budget_cap).min(budget_cap);
    if desired_rows == 0 {
        push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        return PlanExecution {
            rows: Vec::new(),
            truncated: true,
            cancelled: false,
            pipeline_halted: false,
        };
    }

    let files = seed_scan_files(state, &seed.languages, &seed.where_globs);

    let mut rows: Vec<PipelineRow> = Vec::new();
    let mut indexes: HashMap<PipelineKey, usize> = HashMap::default();
    let mut truncated = false;
    for file in files {
        if state
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return cancelled_plan_execution();
        }
        let mut projected = state.budget;
        projected.scanned_files = projected.scanned_files.saturating_add(1);
        if projected.scanned_files > limits.max_scanned_files {
            push_budget_diagnostic(diagnostics, &projected);
            truncated = true;
            break;
        }
        state.budget.scanned_files = projected.scanned_files;

        let Some(result) = state.occurrence_cache.rows_for_file(
            state.analyzer,
            &file,
            &seed.filter,
            state.cancellation,
        ) else {
            return cancelled_plan_execution();
        };
        state
            .occurrence_cache
            .report_completeness(&file, &result, &seed.filter, diagnostics);
        for row in occurrences::select_rows(&result, &seed.filter) {
            if rows.len() >= desired_rows {
                truncated = true;
                diagnostics.push(CodeQueryDiagnostic {
                    code: CodeQueryDiagnosticCode::OccurrenceRowBudgetExhausted,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: "workspace",
                    message: format!(
                        "occurrence seed reached its {desired_rows}-row cap; narrow the filter, languages, or where globs"
                    ),
                });
                break;
            }
            state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(1);
            insert_pipeline_row(
                &mut rows,
                &mut indexes,
                PipelineValue::Occurrence(OccurrenceValue {
                    row: Arc::new(row.clone()),
                }),
                Vec::new(),
                false,
            );
        }
        if truncated {
            break;
        }
    }

    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: false,
    }
}

/// Which lexical-environment row family a seed scan produces.
pub(super) enum EnvironmentSeedKind<'a> {
    Scopes(&'a ScopeFilter),
    Bindings(&'a BindingFilter),
}

/// Scan the workspace for lexical scope or binding rows (#1474).
///
/// Structurally identical to the occurrence seed scan: file selection, the
/// per-file scanned-file charge, the row cap, and per-file capability
/// diagnostics. The two families share it because they share one producer, one
/// budget and one honesty rule; only which rows are selected differs.
pub(super) fn execute_environment_seed(
    kind: EnvironmentSeedKind<'_>,
    where_globs: &[glob::Pattern],
    languages: &[Language],
    terminal_cap: Option<usize>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    let budget_cap = limits
        .max_pipeline_rows
        .saturating_sub(state.budget.pipeline_rows);
    let desired_rows = terminal_cap.unwrap_or(budget_cap).min(budget_cap);
    if desired_rows == 0 {
        push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        return PlanExecution {
            rows: Vec::new(),
            truncated: true,
            cancelled: false,
            pipeline_halted: false,
        };
    }

    let files = seed_scan_files(state, languages, where_globs);

    let required_axes = match kind {
        EnvironmentSeedKind::Scopes(_) => environment::SCOPE_QUERY_AXES,
        EnvironmentSeedKind::Bindings(_) => environment::BINDING_QUERY_AXES,
    };
    let mut rows: Vec<PipelineRow> = Vec::new();
    let mut indexes: HashMap<PipelineKey, usize> = HashMap::default();
    let mut truncated = false;
    let mut visited_rows = 0_usize;
    for file in files {
        if state
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return cancelled_plan_execution();
        }
        let mut projected = state.budget;
        projected.scanned_files = projected.scanned_files.saturating_add(1);
        if projected.scanned_files > limits.max_scanned_files {
            push_budget_diagnostic(diagnostics, &projected);
            truncated = true;
            break;
        }
        state.budget.scanned_files = projected.scanned_files;

        let result = state
            .environment_cache
            .environment_for(state.analyzer, &file);
        state
            .environment_cache
            .report_completeness(&file, &result, required_axes, diagnostics);
        let joined_scopes = state.environment_cache.joined_scopes(&file);
        let values: Vec<(PipelineValue, bool)> = match kind {
            EnvironmentSeedKind::Scopes(filter) => environment::select_scopes(&result, filter)
                .map(|index| {
                    (
                        PipelineValue::LexicalScope(ScopeValue {
                            file: file.clone(),
                            result: Arc::clone(&result),
                            index,
                        }),
                        joined_scopes
                            .as_ref()
                            .is_none_or(|joined| joined.contains(&index)),
                    )
                })
                .collect(),
            EnvironmentSeedKind::Bindings(filter) => environment::select_bindings(&result, filter)
                .map(|index| {
                    (
                        PipelineValue::Binding(BindingValue {
                            file: file.clone(),
                            result: Arc::clone(&result),
                            index,
                            shadowed: false,
                            reached_from: None,
                        }),
                        true,
                    )
                })
                .collect(),
        };
        for (value, retain) in values {
            if visited_rows >= desired_rows {
                truncated = true;
                diagnostics.push(CodeQueryDiagnostic {
                    code: CodeQueryDiagnosticCode::EnvironmentRowBudgetExhausted,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: "workspace",
                    message: format!(
                        "lexical environment seed reached its {desired_rows}-row cap; narrow the filter, languages, or where globs"
                    ),
                });
                break;
            }
            visited_rows = visited_rows.saturating_add(1);
            state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(1);
            if retain {
                insert_pipeline_row(&mut rows, &mut indexes, value, Vec::new(), false);
            }
        }
        if truncated {
            break;
        }
    }

    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: false,
    }
}

pub(super) enum MaterializationSeedKind<'a> {
    GenerationSites(&'a brokk_bifrost_rql::GenerationSiteFilter),
    Exports(&'a brokk_bifrost_rql::ExportFilter),
}

/// Scan the workspace for generation-site or export rows (#1476).
///
/// Structurally identical to the environment seed scan: file selection, the
/// per-file scanned-file charge, the row cap, and per-file capability
/// diagnostics.
pub(super) fn execute_materialization_seed(
    kind: MaterializationSeedKind<'_>,
    where_globs: &[glob::Pattern],
    languages: &[Language],
    terminal_cap: Option<usize>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    let budget_cap = limits
        .max_pipeline_rows
        .saturating_sub(state.budget.pipeline_rows);
    let desired_rows = terminal_cap.unwrap_or(budget_cap).min(budget_cap);
    if desired_rows == 0 {
        push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        return PlanExecution {
            rows: Vec::new(),
            truncated: true,
            cancelled: false,
            pipeline_halted: false,
        };
    }

    let files = seed_scan_files(state, languages, where_globs);

    let required_axes = match kind {
        MaterializationSeedKind::GenerationSites(_) => materialization::GENERATION_SITE_QUERY_AXES,
        MaterializationSeedKind::Exports(_) => materialization::EXPORT_QUERY_AXES,
    };
    let mut rows: Vec<PipelineRow> = Vec::new();
    let mut indexes: HashMap<PipelineKey, usize> = HashMap::default();
    let mut truncated = false;
    for file in files {
        if state
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return cancelled_plan_execution();
        }
        let mut projected = state.budget;
        projected.scanned_files = projected.scanned_files.saturating_add(1);
        if projected.scanned_files > limits.max_scanned_files {
            push_budget_diagnostic(diagnostics, &projected);
            truncated = true;
            break;
        }
        state.budget.scanned_files = projected.scanned_files;

        let result = state
            .materialization_cache
            .materialization_for(state.analyzer, &file);
        state
            .materialization_cache
            .report_completeness(&file, &result, required_axes, diagnostics);
        let values: Vec<PipelineValue> = match kind {
            MaterializationSeedKind::GenerationSites(filter) => {
                materialization::select_generation_sites(&result, filter)
                    .map(|index| {
                        PipelineValue::GenerationSite(materialization::GenerationSiteValue {
                            file: file.clone(),
                            result: Arc::clone(&result),
                            index,
                        })
                    })
                    .collect()
            }
            MaterializationSeedKind::Exports(filter) => {
                materialization::select_exports(&result, filter)
                    .map(|index| {
                        PipelineValue::Export(materialization::ExportValue {
                            file: file.clone(),
                            result: Arc::clone(&result),
                            index,
                        })
                    })
                    .collect()
            }
        };
        for value in values {
            if rows.len() >= desired_rows {
                truncated = true;
                diagnostics.push(CodeQueryDiagnostic {
                    code: CodeQueryDiagnosticCode::MaterializationRowBudgetExhausted,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: "workspace",
                    message: format!(
                        "materialization seed reached its {desired_rows}-row cap; narrow the filter, languages, or where globs"
                    ),
                });
                break;
            }
            state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(1);
            insert_pipeline_row(&mut rows, &mut indexes, value, Vec::new(), false);
        }
        if truncated {
            break;
        }
    }

    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: false,
    }
}

pub(super) fn execute_path_seed(
    filter: &PathFilter,
    where_globs: &[glob::Pattern],
    languages: &[Language],
    terminal_cap: Option<usize>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    let budget_cap = limits
        .max_pipeline_rows
        .saturating_sub(state.budget.pipeline_rows);
    let desired_rows = terminal_cap.unwrap_or(budget_cap).min(budget_cap);
    if desired_rows == 0 {
        push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        return PlanExecution {
            rows: Vec::new(),
            truncated: true,
            cancelled: false,
            pipeline_halted: false,
        };
    }

    let files = seed_scan_files(state, languages, where_globs);

    let mut rows: Vec<PipelineRow> = Vec::new();
    let mut indexes: HashMap<PipelineKey, usize> = HashMap::default();
    let mut truncated = false;
    for file in files {
        if state
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return cancelled_plan_execution();
        }
        let mut projected = state.budget;
        projected.scanned_files = projected.scanned_files.saturating_add(1);
        if projected.scanned_files > limits.max_scanned_files {
            push_budget_diagnostic(diagnostics, &projected);
            truncated = true;
            break;
        }
        state.budget.scanned_files = projected.scanned_files;

        let Some(result) =
            state
                .path_cache
                .paths_for(state.analyzer, &file, false, state.cancellation)
        else {
            return cancelled_plan_execution();
        };
        state
            .path_cache
            .report_completeness(&file, &result, PATH_QUERY_AXES, diagnostics);
        let values: Vec<PipelineValue> = result
            .paths
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                filter
                    .min_segments
                    .is_none_or(|minimum| row.segment_count >= minimum)
            })
            .map(|(index, _)| {
                PipelineValue::QualifiedPath(PathValue {
                    file: file.clone(),
                    result: Arc::clone(&result),
                    index,
                })
            })
            .collect();
        for value in values {
            if rows.len() >= desired_rows {
                truncated = true;
                diagnostics.push(CodeQueryDiagnostic {
                    code: CodeQueryDiagnosticCode::EnvironmentRowBudgetExhausted,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: "workspace",
                    message: format!(
                        "qualified path seed reached its {desired_rows}-row cap; narrow the filter, languages, or where globs"
                    ),
                });
                break;
            }
            state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(1);
            insert_pipeline_row(&mut rows, &mut indexes, value, Vec::new(), false);
        }
        if truncated {
            break;
        }
    }

    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: false,
    }
}
pub(super) fn execute_seed(
    seed: &CodeQuerySeed,
    terminal_cap: Option<usize>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    let cache_key = seed.canonical_cache_key();
    let parallel_budget = state.parallel_seed_budget.clone();
    if parallel_budget.is_some() {
        debug_assert!(
            state.seed_cache.is_empty(),
            "parallel seed branches start with disjoint empty request caches"
        );
    }
    let pipeline_limit = parallel_budget
        .as_ref()
        .map_or(limits.max_pipeline_rows, |lease| {
            lease.coordinator.maximum_pipeline_rows()
        });
    let budget_cap = pipeline_limit.saturating_sub(state.budget.pipeline_rows);
    let desired_rows = terminal_cap.unwrap_or(budget_cap).min(budget_cap);
    let capped_by_budget = terminal_cap.is_none_or(|cap| budget_cap <= cap);
    if let Some(cached) = state.seed_cache.get(&cache_key).cloned() {
        if let Some(profile) = &mut state.cache_profile {
            profile
                .seed_result
                .record_hit(cached.complete, cached.rows.len());
        }
        diagnostics.extend(cached.diagnostics);
        let mut rows = cached.rows;
        let locally_capped = capped_by_budget && rows.len() > desired_rows;
        let truncated = cached.truncated || locally_capped;
        rows.truncate(desired_rows);
        state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(rows.len());
        if locally_capped {
            push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        }
        return PlanExecution {
            rows,
            truncated,
            cancelled: false,
            pipeline_halted: false,
        };
    }
    if let Some(profile) = &mut state.cache_profile {
        profile.seed_result.record_miss();
    }
    if desired_rows == 0 {
        push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        return PlanExecution {
            rows: Vec::new(),
            truncated: true,
            cancelled: false,
            pipeline_halted: false,
        };
    }

    let diagnostic_start = diagnostics.len();
    let plan = QueryPlan::for_query(seed);
    let source_index = plan.build_source_index();
    let analyzer = state.analyzer;
    let mut providers = analyzer.structural_fact_providers();
    providers.sort_by_key(|provider| provider.structural_language());
    providers.retain(|provider| {
        seed.languages.is_empty() || seed.languages.contains(&provider.structural_language())
    });

    let mut owned_workspace_files = Vec::new();
    let workspace_files = workspace_files_for_scope(state, &mut owned_workspace_files);
    let mut scoped_languages = BTreeSet::new();
    for file in workspace_files {
        if state
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return PlanExecution {
                rows: Vec::new(),
                truncated: true,
                cancelled: true,
                pipeline_halted: false,
            };
        }
        let language = crate::analyzer::common::language_for_file(file);
        let requested = seed.languages.is_empty() || seed.languages.contains(&language);
        if requested && file_matches_globs(file, seed) {
            scoped_languages.insert(language);
        }
    }

    let mut supported = BTreeSet::new();
    let mut provider_scopes = Vec::new();
    for provider in providers {
        let language = provider.structural_language();
        supported.insert(language);
        let (mut files, provider_file_count) =
            provider_scope_files(state, provider, language, workspace_files);
        files.retain(|file| file_matches_globs(file, seed));
        files.sort();
        let explicitly_requested = seed.languages.contains(&language);
        if !files.is_empty() || explicitly_requested {
            diagnostics.extend(
                plan.features()
                    .unsupported_by(|feature| provider_supports_feature(provider, feature))
                    .into_diagnostics(language)
                    .into_iter()
                    .map(|diagnostic| CodeQueryDiagnostic {
                        code: CodeQueryDiagnosticCode::UnsupportedStructuralFeature,
                        impact: CodeQueryDiagnosticImpact::Incomplete,
                        branch: Vec::new(),
                        language: diagnostic.language().config_label(),
                        message: diagnostic.message(),
                    }),
            );
        }
        let access = if files.is_empty() {
            SeedStructuralAccess::Scan
        } else {
            prepare_seed_access(provider, provider_file_count, &files, &plan, state)
        };
        provider_scopes.push((language, provider, files, access));
    }
    for language in state.analyzer.languages() {
        let explicitly_requested = seed.languages.contains(&language);
        let requested = seed.languages.is_empty() || explicitly_requested;
        if requested
            && !supported.contains(&language)
            && (explicitly_requested || scoped_languages.contains(&language))
        {
            diagnostics.push(CodeQueryDiagnostic {
                code: CodeQueryDiagnosticCode::MissingStructuralAdapter,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "no structural adapter for {} yet; its files were not searched",
                    language.config_label()
                ),
            });
        }
    }

    let selected_index_content = provider_scopes
        .iter()
        .filter_map(|(_, _, _, access)| access.workspace_content_guard())
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    for (language, provider, files, access) in provider_scopes {
        candidates.extend(files.into_iter().map(|file| {
            (
                rel_path_string(&file),
                language,
                provider,
                file,
                access.clone(),
            )
        }));
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

    let probing_budget = capped_by_budget;
    let match_cap = desired_rows.saturating_add(usize::from(probing_budget));
    let mut pending: Vec<PendingMatch> = Vec::new();
    let mut truncated = false;
    let mut cache_complete = state.cache_profile.as_ref().map(|_| true);
    let signature_incomplete = super::super::matcher::CallableSignatureIncomplete::default();
    'candidates: for (_path, language, provider, file, access) in candidates {
        if state
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return PlanExecution {
                rows: Vec::new(),
                truncated: true,
                cancelled: true,
                pipeline_halted: false,
            };
        }
        let indexed_file = access.index_file(&file);
        let source_definitely_absent = source_index.requires_source()
            && access.source_may_contain(&file, source_index.required_anchors()) == Some(false);
        let source = if indexed_file.is_none()
            || (source_index.requires_source() && !source_definitely_absent)
        {
            let source = provider.structural_source(&file);
            if let (Some(source), Some(profile)) = (&source, &mut state.profile) {
                profile.access_path.inspected_source_bytes = profile
                    .access_path
                    .inspected_source_bytes
                    .saturating_add(u64::try_from(source.len()).unwrap_or(u64::MAX));
            }
            source
        } else {
            None
        };
        if source_index.requires_source() && !source_definitely_absent && source.is_none() {
            push_seed_provider_omission(diagnostics, language, &file, "indexed source snapshot");
            truncated = true;
            cache_complete = cache_complete.map(|_| false);
            continue;
        }
        let source_bytes = match (indexed_file, source.as_ref()) {
            (Some(indexed), _) => usize::try_from(indexed.source_bytes).unwrap_or(usize::MAX),
            (None, Some(source)) => source.len(),
            (None, None) => {
                push_seed_provider_omission(
                    diagnostics,
                    language,
                    &file,
                    "indexed source snapshot",
                );
                truncated = true;
                cache_complete = cache_complete.map(|_| false);
                continue;
            }
        };
        let ledger_key = (language, file.clone());
        let mut projected = state.budget;
        projected.scanned_files = projected.scanned_files.saturating_add(1);
        projected.scanned_source_bytes =
            projected.scanned_source_bytes.saturating_add(source_bytes);
        if let Some(lease) = &parallel_budget {
            match lease.admit_shared(SeedChargeLane::Scanned, &ledger_key, projected) {
                FairSeedBudgetSharedAdmission::AlreadyCharged => {}
                FairSeedBudgetSharedAdmission::Admitted => {
                    state.budget.scanned_files = projected.scanned_files;
                    state.budget.scanned_source_bytes = projected.scanned_source_bytes;
                }
                FairSeedBudgetSharedAdmission::Rejected(global_projected) => {
                    push_budget_diagnostic(diagnostics, &global_projected);
                    truncated = true;
                    cache_complete = cache_complete.map(|_| false);
                    break;
                }
                FairSeedBudgetSharedAdmission::Cancelled => {
                    return cancelled_plan_execution();
                }
            }
        } else if !state.seed_scan_ledger.scanned.contains(&ledger_key) {
            if projected.scanned_files > limits.max_scanned_files
                || projected.scanned_source_bytes > limits.max_scanned_source_bytes
            {
                push_budget_diagnostic(diagnostics, &projected);
                truncated = true;
                cache_complete = cache_complete.map(|_| false);
                break;
            }
            state.budget.scanned_files = projected.scanned_files;
            state.budget.scanned_source_bytes = projected.scanned_source_bytes;
            state.seed_scan_ledger.scanned.insert(ledger_key.clone());
        }
        if source_definitely_absent {
            continue;
        }
        if source
            .as_deref()
            .is_some_and(|source| !source_index.may_match(source))
        {
            continue;
        }
        let candidate_ids = access.candidate_facts(&file);
        // A sound candidate relation with no facts in this file means the
        // matcher will examine nothing here: skip before charging fact-node
        // budget for work that will not happen.
        if indexed_file.is_some() && candidate_ids.is_some_and(|ids| ids.is_empty()) {
            continue;
        }
        let mut facts = None;
        let fact_nodes = if let Some(indexed) = indexed_file {
            usize::try_from(indexed.fact_nodes).unwrap_or(usize::MAX)
        } else {
            let loaded = load_seed_facts(provider, &file, state.cache_profile.as_mut());
            let Some(loaded) = loaded else {
                push_seed_provider_omission(
                    diagnostics,
                    language,
                    &file,
                    "normalized structural facts",
                );
                truncated = true;
                cache_complete = cache_complete.map(|_| false);
                continue;
            };
            let count = loaded.work_item_count();
            if let Some(profile) = &mut state.profile {
                profile.access_path.materialized_files =
                    profile.access_path.materialized_files.saturating_add(1);
                profile.access_path.materialized_fact_nodes = profile
                    .access_path
                    .materialized_fact_nodes
                    .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            }
            facts = Some(loaded);
            if let Some(profile) = &mut state.profile {
                let access_profile = &mut profile.access_path;
                access_profile.candidate_files = access_profile.candidate_files.saturating_add(1);
                access_profile.candidate_facts = access_profile
                    .candidate_facts
                    .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            }
            count
        };
        let selected_facts = candidate_ids.unwrap_or(&[]);
        // Posting-based access examines only the selected candidates plus the
        // facts the verifier actually walks, so charge that work instead of
        // the whole file: the candidates now, the verifier walk after
        // matching. Scan access materializes and examines every fact, but one
        // execution charges each file's full extraction only once across
        // compatible seed scans; later scans replay the memory-cached facts.
        let charged_fact_nodes = if indexed_file.is_some() {
            selected_facts.len()
        } else if parallel_budget.is_none()
            && state.seed_scan_ledger.fully_charged.contains(&ledger_key)
        {
            0
        } else {
            fact_nodes
        };
        projected = state.budget;
        projected.fact_nodes = projected.fact_nodes.saturating_add(charged_fact_nodes);
        let mut admitted_fact_nodes = charged_fact_nodes;
        if let Some(lease) = &parallel_budget {
            if indexed_file.is_some() {
                match lease.admit(projected) {
                    FairSeedBudgetAdmission::Admitted => {}
                    FairSeedBudgetAdmission::Rejected(global_projected) => {
                        push_budget_diagnostic(diagnostics, &global_projected);
                        truncated = true;
                        cache_complete = cache_complete.map(|_| false);
                        break;
                    }
                    FairSeedBudgetAdmission::Cancelled => {
                        return cancelled_plan_execution();
                    }
                }
            } else {
                match lease.admit_shared(SeedChargeLane::FullFacts, &ledger_key, projected) {
                    FairSeedBudgetSharedAdmission::AlreadyCharged => {
                        admitted_fact_nodes = 0;
                        projected.fact_nodes = state.budget.fact_nodes;
                    }
                    FairSeedBudgetSharedAdmission::Admitted => {}
                    FairSeedBudgetSharedAdmission::Rejected(global_projected) => {
                        push_budget_diagnostic(diagnostics, &global_projected);
                        truncated = true;
                        cache_complete = cache_complete.map(|_| false);
                        break;
                    }
                    FairSeedBudgetSharedAdmission::Cancelled => {
                        return cancelled_plan_execution();
                    }
                }
            }
        } else if charged_fact_nodes > 0 {
            if projected
                .fact_nodes
                .saturating_add(projected.examined_references)
                > limits.max_fact_nodes
            {
                push_budget_diagnostic(diagnostics, &projected);
                truncated = true;
                cache_complete = cache_complete.map(|_| false);
                break;
            }
            if indexed_file.is_none() {
                state
                    .seed_scan_ledger
                    .fully_charged
                    .insert(ledger_key.clone());
            }
        }
        state.budget.fact_nodes = projected.fact_nodes;
        if let Some(profile) = &mut state.profile {
            profile.access_path.admitted_fact_nodes = profile
                .access_path
                .admitted_fact_nodes
                .saturating_add(u64::try_from(admitted_fact_nodes).unwrap_or(u64::MAX));
        }
        let facts = match facts {
            Some(facts) => facts,
            None => {
                let loaded = load_seed_facts(provider, &file, state.cache_profile.as_mut());
                let Some(loaded) = loaded else {
                    push_seed_provider_omission(
                        diagnostics,
                        language,
                        &file,
                        "normalized structural facts",
                    );
                    truncated = true;
                    cache_complete = cache_complete.map(|_| false);
                    continue;
                };
                if loaded.work_item_count() != fact_nodes
                    || selected_facts
                        .last()
                        .is_some_and(|id| (*id as usize) >= loaded.nodes().len())
                {
                    state.access_failure.get_or_insert_with(|| {
                        format!(
                            "snapshot structural index metadata changed for {}",
                            rel_path_string(&file)
                        )
                    });
                    push_seed_provider_omission(
                        diagnostics,
                        language,
                        &file,
                        "fresh snapshot structural index metadata",
                    );
                    truncated = true;
                    cache_complete = cache_complete.map(|_| false);
                    continue;
                }
                if let Some(profile) = &mut state.profile {
                    profile.access_path.materialized_files =
                        profile.access_path.materialized_files.saturating_add(1);
                    profile.access_path.materialized_fact_nodes =
                        profile.access_path.materialized_fact_nodes.saturating_add(
                            u64::try_from(loaded.work_item_count()).unwrap_or(u64::MAX),
                        );
                }
                loaded
            }
        };
        let remaining = match_cap.saturating_sub(pending.len());
        let signature_oracle = seed.constrains_callable_signature().then(|| {
            super::relations::FileCallableSignatureOracle::for_file(state.analyzer, &file)
        });
        let oracle = signature_oracle
            .as_ref()
            .map(|oracle| oracle as &dyn super::super::matcher::CallableSignatureOracle);
        let matches = if indexed_file.is_some() {
            let mut examined = 0u64;
            let matches = super::super::matcher::match_query_candidates(
                seed,
                &facts,
                selected_facts.iter().copied(),
                remaining,
                &mut examined,
                oracle,
                &signature_incomplete,
            );
            if let Some(profile) = &mut state.profile {
                profile.access_path.examined_fact_nodes = profile
                    .access_path
                    .examined_fact_nodes
                    .saturating_add(examined);
            }
            // Charge the verifier walk beyond the already-charged candidates.
            // The admission overshoot is bounded by one file's matcher work.
            let extra = usize::try_from(
                examined.saturating_sub(u64::try_from(charged_fact_nodes).unwrap_or(u64::MAX)),
            )
            .unwrap_or(usize::MAX);
            if extra > 0 {
                projected = state.budget;
                projected.fact_nodes = projected.fact_nodes.saturating_add(extra);
                if let Some(lease) = &parallel_budget {
                    match lease.admit(projected) {
                        FairSeedBudgetAdmission::Admitted => {}
                        FairSeedBudgetAdmission::Rejected(global_projected) => {
                            push_budget_diagnostic(diagnostics, &global_projected);
                            truncated = true;
                            cache_complete = cache_complete.map(|_| false);
                            break;
                        }
                        FairSeedBudgetAdmission::Cancelled => {
                            return cancelled_plan_execution();
                        }
                    }
                } else if projected
                    .fact_nodes
                    .saturating_add(projected.examined_references)
                    > limits.max_fact_nodes
                {
                    push_budget_diagnostic(diagnostics, &projected);
                    truncated = true;
                    cache_complete = cache_complete.map(|_| false);
                    break;
                }
                state.budget.fact_nodes = projected.fact_nodes;
            }
            matches
        } else {
            if let Some(profile) = &mut state.profile {
                profile.access_path.examined_fact_nodes = profile
                    .access_path
                    .examined_fact_nodes
                    .saturating_add(u64::try_from(facts.nodes().len()).unwrap_or(u64::MAX));
            }
            let mut examined = 0u64;
            super::super::matcher::match_query_candidates(
                seed,
                &facts,
                0..u32::try_from(facts.nodes().len()).expect("FileFacts node ids fit in u32"),
                remaining,
                &mut examined,
                oracle,
                &signature_incomplete,
            )
        };
        if let Some(lease) = &parallel_budget {
            for fact_match in matches {
                let mut projected = state.budget;
                projected.pipeline_rows = projected.pipeline_rows.saturating_add(1);
                match lease.admit(projected) {
                    FairSeedBudgetAdmission::Admitted => {
                        state.budget.pipeline_rows = projected.pipeline_rows;
                        pending.push((language, file.clone(), Arc::clone(&facts), fact_match));
                    }
                    FairSeedBudgetAdmission::Rejected(_) => {
                        push_pipeline_budget_diagnostic(diagnostics, &lease.budget_before_branch());
                        truncated = true;
                        cache_complete = cache_complete.map(|_| false);
                        break 'candidates;
                    }
                    FairSeedBudgetAdmission::Cancelled => {
                        return cancelled_plan_execution();
                    }
                }
            }
        } else {
            pending.extend(
                matches
                    .into_iter()
                    .map(|fact_match| (language, file.clone(), Arc::clone(&facts), fact_match)),
            );
        }
        if parallel_budget.is_none() && pending.len() >= match_cap {
            // The cap stopped the scan before the remaining candidates were
            // examined. This can be enough for a root limit probe while still
            // being unsafe to advertise as a complete reusable seed layer.
            cache_complete = cache_complete.map(|_| false);
            break;
        }
    }
    if signature_incomplete.visibility_unrecorded.get() {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UnsupportedStructuralFeature,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "workspace",
            message: "callable visibility is unrecorded for at least one declaration; results that depend on it are incomplete rather than a clean miss".to_string(),
        });
    }
    if signature_incomplete.parameter_types_unrecorded.get() {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UnsupportedStructuralFeature,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "workspace",
            message: "callable parameter types are unrecorded for at least one declaration; results that depend on them are incomplete rather than a clean miss".to_string(),
        });
    }
    if selected_index_content
        .iter()
        .any(|content| !state.analyzer.workspace_content_matches(*content))
    {
        pending.clear();
        truncated = true;
        cache_complete = cache_complete.map(|_| false);
        state.access_failure.get_or_insert_with(|| {
            "workspace content changed during structural posting replay".to_string()
        });
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "workspace",
            message: "workspace content changed during structural posting replay; retry the query for a coherent snapshot".to_string(),
        });
    }
    if pending.len() > desired_rows {
        pending.truncate(desired_rows);
        cache_complete = cache_complete.map(|_| false);
        if capped_by_budget {
            truncated = true;
            push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        }
    }
    let rows = pending
        .into_iter()
        .map(|(language, file, facts, fact_match)| {
            let seed = Arc::new(SeedMatch {
                language,
                file,
                facts,
                fact_match,
            });
            PipelineRow {
                value: PipelineValue::StructuralMatch(Arc::clone(&seed)),
                traces: vec![PipelineTrace {
                    branch: Vec::new(),
                    seed,
                    steps: Vec::new(),
                }],
                provenance_truncated: false,
            }
        })
        .collect::<Vec<_>>();
    let cache_complete = cache_complete.map(|complete| {
        complete
            && !truncated
            && !diagnostics[diagnostic_start..]
                .iter()
                .any(|diagnostic| diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete)
    });
    if parallel_budget.is_none() {
        state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(rows.len());
    }
    state.seed_cache.insert(
        cache_key,
        CachedSeedExecution {
            rows: rows.clone(),
            diagnostics: diagnostics[diagnostic_start..].to_vec(),
            truncated,
            complete: cache_complete,
        },
    );
    if let Some(profile) = &mut state.cache_profile {
        profile.seed_result.record_build(cache_complete);
    }
    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: false,
    }
}
