use super::definitions::*;
use super::selectors::*;
use super::sources::*;
use super::summaries::*;
use super::*;
use crate::analyzer::structural::{NormalizedKind, Role};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchSymbolsParams {
    #[serde(deserialize_with = "deserialize_search_symbol_patterns")]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub include_tests: bool,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn deserialize_search_symbol_patterns<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let patterns = Vec::<String>::deserialize(deserializer)?;
    if patterns.len() > SEARCH_SYMBOL_MAX_PATTERNS {
        return Err(serde::de::Error::custom(format!(
            "patterns accepts at most {SEARCH_SYMBOL_MAX_PATTERNS} entries"
        )));
    }
    let mut total_bytes = 0usize;
    for pattern in &patterns {
        if pattern.len() > SEARCH_SYMBOL_MAX_PATTERN_BYTES {
            return Err(serde::de::Error::custom(format!(
                "each search pattern must be at most {SEARCH_SYMBOL_MAX_PATTERN_BYTES} bytes"
            )));
        }
        total_bytes = total_bytes.saturating_add(pattern.len());
        if total_bytes > SEARCH_SYMBOL_MAX_TOTAL_PATTERN_BYTES {
            return Err(serde::de::Error::custom(format!(
                "search patterns must total at most {SEARCH_SYMBOL_MAX_TOTAL_PATTERN_BYTES} bytes"
            )));
        }
    }
    Ok(patterns)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolLookupParams {
    #[serde(deserialize_with = "deserialize_symbol_lookup_names")]
    pub symbols: Vec<String>,
}

pub(super) fn deserialize_symbol_lookup_names<'de, D>(
    deserializer: D,
) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let symbols = Vec::<String>::deserialize(deserializer)?;
    if symbols.len() > SYMBOL_LOOKUP_MAX_SYMBOLS {
        return Err(serde::de::Error::custom(format!(
            "symbols accepts at most {SYMBOL_LOOKUP_MAX_SYMBOLS} entries"
        )));
    }
    let mut total_bytes = 0usize;
    for symbol in &symbols {
        if symbol.len() > SYMBOL_LOOKUP_MAX_SYMBOL_BYTES {
            return Err(serde::de::Error::custom(format!(
                "each symbol must be at most {SYMBOL_LOOKUP_MAX_SYMBOL_BYTES} bytes"
            )));
        }
        total_bytes = total_bytes.saturating_add(symbol.len());
        if total_bytes > SYMBOL_LOOKUP_MAX_TOTAL_BYTES {
            return Err(serde::de::Error::custom(format!(
                "symbols must total at most {SYMBOL_LOOKUP_MAX_TOTAL_BYTES} bytes"
            )));
        }
    }
    Ok(symbols)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDefinitionParams {
    pub references: Vec<DefinitionReferenceQuery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTypeParams {
    pub references: Vec<TypeReferenceQuery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameSymbolParams {
    pub path: String,
    #[serde(default)]
    pub line: Option<usize>,
    #[serde(default)]
    pub column: Option<usize>,
    pub new_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionReferenceQuery {
    pub path: String,
    #[serde(default)]
    pub line: Option<usize>,
    #[serde(default)]
    pub column: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeReferenceQuery {
    pub path: String,
    #[serde(default)]
    pub line: Option<usize>,
    #[serde(default)]
    pub column: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenameSymbolResult {
    pub query: RenameSymbolParams,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<RenameSymbolTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_name: Option<String>,
    pub edits: Vec<RenameFileEdits>,
    pub diagnostics: Vec<DefinitionDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenameSymbolTarget {
    pub symbol: String,
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenameFileEdits {
    pub path: String,
    pub edits: Vec<RenameTextEdit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenameTextEdit {
    pub old_text: String,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub new_text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchSymbolsResult {
    pub patterns: Vec<String>,
    pub truncated: bool,
    pub total_files: usize,
    pub files: Vec<SearchSymbolsFile>,
    pub total_model_symbols: usize,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub model_symbols: Vec<crate::analyzer::semantic_model::SemanticModelSymbol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchSymbolsFile {
    pub path: String,
    pub loc: usize,
    pub classes: Vec<SearchSymbolHit>,
    pub functions: Vec<SearchSymbolHit>,
    pub fields: Vec<SearchSymbolHit>,
    pub modules: Vec<SearchSymbolHit>,
    pub macros: Vec<SearchSymbolHit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchSymbolHit {
    pub symbol: String,
    pub signature: String,
    pub line: usize,
    pub is_type_alias: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_model: Option<crate::analyzer::semantic_model::SemanticModelProvenance>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SearchPatternKind {
    LiteralIdentifier,
    LiteralQualified,
    RegexLike,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct SymbolMatchScore {
    tier: u8,
    exact_patterns: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct SymbolCandidateScore {
    match_score: SymbolMatchScore,
    path_tier: u8,
    implementation_tier: u8,
    source_quality_tier: u8,
    synthetic_tier: u8,
}

#[derive(Debug, Clone)]
pub(super) struct RankedSearchCandidate {
    code_unit: CodeUnit,
    score: SymbolCandidateScore,
    line: usize,
    primary_range: Range,
    is_type_alias: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FileRankingKey {
    top1: SymbolCandidateScore,
    cohesion_tier: u8,
    focus_tier: u8,
    top2: SymbolCandidateScore,
    top3: SymbolCandidateScore,
    git_tier: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolLocationsResult {
    pub locations: Vec<SymbolLocation>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub model_locations: Vec<crate::analyzer::semantic_model::SemanticModelSymbol>,
    pub not_found: Vec<NotFoundInput>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous: Vec<AmbiguousSymbol>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolAncestorsResult {
    pub ancestors: Vec<SymbolAncestors>,
    pub not_found: Vec<NotFoundInput>,
    pub ambiguous: Vec<AmbiguousSymbol>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolAncestors {
    pub symbol: String,
    pub ancestors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolLocation {
    pub symbol: String,
    pub path: String,
    pub loc: usize,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct GetDefinitionResult {
    pub results: Vec<DefinitionLookupResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GetDeclarationResult {
    pub results: Vec<DeclarationLookupResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GetTypeResult {
    pub results: Vec<TypeLookupResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefinitionLookupResult {
    pub query: DefinitionReferenceQuery,
    pub operation: NavigationOperation,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<DefinitionReferenceSite>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub definitions: Vec<DefinitionCandidate>,
    #[serde(default)]
    pub diagnostics: Vec<DefinitionDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeclarationLookupResult {
    pub query: DefinitionReferenceQuery,
    pub operation: NavigationOperation,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<DefinitionReferenceSite>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub declarations: Vec<DefinitionCandidate>,
    #[serde(default)]
    pub diagnostics: Vec<DefinitionDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeLookupResult {
    pub query: TypeReferenceQuery,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<DefinitionReferenceSite>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub types: Vec<TypeLookupCandidate>,
    #[serde(default)]
    pub diagnostics: Vec<DefinitionDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeLookupCandidate {
    pub fqn: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub definitions: Vec<DefinitionCandidate>,
}

pub fn search_symbols(
    analyzer: &dyn IAnalyzer,
    params: SearchSymbolsParams,
) -> SearchSymbolsResult {
    search_symbols_with_cancellation(analyzer, params, None)
}

pub fn search_symbols_with_cancellation(
    analyzer: &dyn IAnalyzer,
    params: SearchSymbolsParams,
    cancellation: Option<&crate::CancellationToken>,
) -> SearchSymbolsResult {
    let _scope = profiling::scope("searchtools::search_symbols");
    let patterns: Vec<String> = strip_params(params.patterns)
        .into_iter()
        .filter(|pattern| !pattern.trim().is_empty())
        .collect();
    let pattern_batch = SearchSymbolPatternBatch::compile(patterns.clone(), false, cancellation);

    let definitions = {
        let _scope = profiling::scope("searchtools::search_symbols.resolve");
        analyzer.search_symbol_candidates(&pattern_batch, cancellation)
    };
    let mut complete = definitions.complete;

    let filtered: Vec<_> = {
        let _scope = profiling::scope("searchtools::search_symbols.filter_ranged");
        let mut seen = HashSet::default();
        let mut filtered = Vec::new();
        for candidate in definitions.rows {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                complete = false;
                break;
            }
            // A search result is an implicit selector offer for source/location tools. Internal
            // graph identities without a unique range (for example replicated Go inline-struct
            // members) must not be advertised even when they intentionally remain resolvable.
            if !seen.insert(candidate.code_unit.clone()) {
                continue;
            }
            let Some(range) = candidate
                .primary_range
                .or_else(|| primary_range(analyzer, &candidate.code_unit))
            else {
                continue;
            };
            // Symbol-level test filtering (#1102): a declaration is treated as
            // a test symbol only when it is itself in a structurally-evidenced
            // test region, or lives under a test-tree path. The old whole-file
            // `contains_tests` gate hid the production API of any file carrying
            // an inline `#[cfg(test)] mod tests`.
            let is_test = candidate.in_test_region
                || test_paths::is_test_like_path(
                    &rel_path_string(candidate.code_unit.source()),
                    language_for_file(candidate.code_unit.source()),
                );
            if params.include_tests || !is_test {
                filtered.push((candidate.code_unit, range, is_test, candidate.is_type_alias));
            }
        }
        filtered
    };

    let (ranked, ranking_complete) = {
        let _scope = profiling::scope("searchtools::search_symbols.rank");
        rank_search_symbol_candidates(analyzer, &patterns, filtered, cancellation)
    };
    complete &= ranking_complete;

    let mut grouped: HashMap<ProjectFile, Vec<RankedSearchCandidate>> = HashMap::default();
    for candidate in ranked {
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            complete = false;
            break;
        }
        grouped
            .entry(candidate.code_unit.source().clone())
            .or_default()
            .push(candidate);
    }

    let effective_limit = params.limit.clamp(1, FILE_SEARCH_LIMIT);
    let authored_names: HashSet<String> = grouped
        .values()
        .flatten()
        .map(|candidate| candidate.code_unit.fq_name())
        .collect();
    let semantic_model_overlay = analyzer.semantic_model_overlay();
    let (model_symbols, total_model_symbols) = semantic_model_overlay
        .as_deref()
        .map(|overlay| {
            let (matched, total, model_complete) = overlay.search_with_limit_filter(
                &pattern_batch,
                effective_limit,
                cancellation,
                |symbol| !authored_names.contains(&symbol.qualified_name),
            );
            complete &= model_complete;
            let rows = matched.into_iter().cloned().collect::<Vec<_>>();
            (rows, total)
        })
        .unwrap_or_default();
    let total_files = grouped.len();
    let limit_truncated = total_files > effective_limit || total_model_symbols > effective_limit;
    let mut file_entries: Vec<_> = grouped.into_iter().collect();
    let mut history_unavailable = false;
    let git_tiers = if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
        complete = false;
        HashMap::default()
    } else {
        let (tiers, git_ranking_status) = search_symbol_git_tiers(
            analyzer,
            &file_entries
                .iter()
                .map(|(file, _)| file.clone())
                .collect::<Vec<_>>(),
            cancellation,
        );
        match git_ranking_status {
            crate::relevance::HistoryRankingStatus::Complete => {}
            crate::relevance::HistoryRankingStatus::Cancelled => complete = false,
            crate::relevance::HistoryRankingStatus::HistoryUnavailable => {
                history_unavailable = true;
            }
        }
        tiers
    };
    if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
        complete = false;
    } else {
        file_entries.sort_by(
            |(left_file, left_candidates), (right_file, right_candidates)| {
                compare_search_symbol_files(
                    left_file,
                    left_candidates,
                    right_file,
                    right_candidates,
                    &git_tiers,
                )
            },
        );
    }
    file_entries.truncate(effective_limit);

    let files: Vec<SearchSymbolsFile> = {
        let _scope = profiling::scope("searchtools::search_symbols.render");
        let mut files = Vec::new();
        for (file, code_units) in file_entries {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                complete = false;
                break;
            }
            let render_context = {
                let _scope =
                    profiling::scope("searchtools::search_symbols.render.load_declaration_context");
                load_declaration_name_context(analyzer, &file)
            };
            let render_context = render_context.as_ref();
            let (classes, functions, fields, modules, macros) = {
                let _scope = profiling::scope("searchtools::search_symbols.render.collect_hits");
                (
                    collect_ranked_kind_names(
                        analyzer,
                        &code_units,
                        CodeUnitType::Class,
                        render_context,
                        semantic_model_overlay.as_deref(),
                    ),
                    collect_callable_kind_names(
                        analyzer,
                        &code_units,
                        render_context,
                        semantic_model_overlay.as_deref(),
                    ),
                    collect_ranked_kind_names(
                        analyzer,
                        &code_units,
                        CodeUnitType::Field,
                        render_context,
                        semantic_model_overlay.as_deref(),
                    ),
                    collect_ranked_kind_names(
                        analyzer,
                        &code_units,
                        CodeUnitType::Module,
                        render_context,
                        semantic_model_overlay.as_deref(),
                    ),
                    collect_ranked_kind_names(
                        analyzer,
                        &code_units,
                        CodeUnitType::Macro,
                        render_context,
                        semantic_model_overlay.as_deref(),
                    ),
                )
            };
            files.push(SearchSymbolsFile {
                path: rel_path_string(&file),
                loc: render_context
                    .map(|context| line_count(context.content()))
                    .unwrap_or(0),
                classes,
                functions,
                fields,
                modules,
                macros,
            });
        }
        files
    };
    if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
        complete = false;
    }
    let truncated = !complete || limit_truncated;
    let mut note = search_symbols_note(
        !complete,
        limit_truncated,
        history_unavailable,
        files.len(),
        total_files,
    );
    if total_model_symbols > effective_limit {
        let model_note = format!(
            "Showing {} of {total_model_symbols} declarations from the active semantic-model overlay.",
            model_symbols.len()
        );
        note = Some(match note {
            Some(note) if total_files > effective_limit => format!("{note} {model_note}"),
            _ => model_note,
        });
    } else if total_files == 0 && total_model_symbols != 0 {
        note = Some(format!(
            "No authored files matched; showing {} of {total_model_symbols} declarations from the active semantic-model overlay.",
            model_symbols.len()
        ));
    }

    SearchSymbolsResult {
        patterns,
        truncated,
        total_files,
        files,
        total_model_symbols,
        model_symbols,
        note,
    }
}

pub(super) fn search_symbols_note(
    cancelled: bool,
    limit_truncated: bool,
    history_unavailable: bool,
    shown: usize,
    total: usize,
) -> Option<String> {
    if cancelled {
        Some(format!(
            "Search was cancelled before all matching symbols could be examined. Results are partial; showing {shown} files observed before cancellation."
        ))
    } else if limit_truncated {
        Some(format!(
            "Showing {shown} of {total} matching files. Raise `limit` or use a more specific identifier, qualified, or regex-like pattern to see the rest."
        ))
    } else if total == 0 {
        Some(
            "No files matched. Try a broader identifier, qualified, or regex-like pattern; if the symbol is itself a test (or lives under a test-tree path), set `include_tests` to true."
                .to_string(),
        )
    } else if history_unavailable {
        Some(
            "Commit-history relevance ranking was unavailable for this request; results are complete but ordered without recency weighting."
                .to_string(),
        )
    } else {
        None
    }
}

pub fn get_symbol_locations(
    analyzer: &dyn IAnalyzer,
    params: SymbolLookupParams,
) -> SymbolLocationsResult {
    get_symbol_locations_with_cancellation(analyzer, params, None)
}

pub fn get_symbol_locations_with_cancellation(
    analyzer: &dyn IAnalyzer,
    params: SymbolLookupParams,
    cancellation: Option<&crate::CancellationToken>,
) -> SymbolLocationsResult {
    let mut outcomes: Vec<_> = params
        .symbols
        .into_par_iter()
        .enumerate()
        .filter_map(|(index, symbol)| {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return None;
            }
            if symbol.trim().is_empty() {
                return None;
            }

            let code_units =
                match resolve_selectable_definitions(analyzer, &symbol, resolve_codeunit_fuzzy) {
                    SelectableDefinitionResolution::Resolved(code_units) => Some(code_units),
                    SelectableDefinitionResolution::Ambiguous(_)
                    | SelectableDefinitionResolution::NotFound(_) => None,
                };
            let Some(code_units) = code_units else {
                return Some((
                    index,
                    Err(path_like_symbol_not_found_input(
                        symbol,
                        PathLikeSymbolGuidanceContext::SymbolLookup,
                    )),
                ));
            };
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return None;
            }
            let locations: Vec<_> = code_units
                .into_iter()
                .filter_map(|code_unit| {
                    let primary_range = primary_range(analyzer, &code_unit)?;
                    // Line count is rendering metadata for an already-resolved
                    // unit; the analyzed snapshot the unit was resolved
                    // against is the consistent source, not a fresh disk read.
                    let loc = analyzer
                        .indexed_source(code_unit.source())
                        .map(|content| line_count(&content))
                        .unwrap_or(0);
                    Some(SymbolLocation {
                        symbol: display_symbol_for_target(&code_unit),
                        path: rel_path_string(code_unit.source()),
                        loc,
                        start_line: primary_range.start_line,
                        end_line: primary_range.end_line,
                    })
                })
                .collect();
            if locations.is_empty() {
                Some((index, Err(renderable_not_found_input(symbol))))
            } else {
                Some((index, Ok(locations)))
            }
        })
        .collect();
    outcomes.sort_by_key(|(index, _)| *index);

    let mut locations = Vec::new();
    let mut not_found = Vec::new();
    for (_, outcome) in outcomes {
        match outcome {
            Ok(found) => locations.extend(found),
            Err(symbol) => not_found.push(symbol),
        }
    }

    let mut model_locations = Vec::new();
    let mut model_ambiguous = Vec::new();
    if let Some(overlay) = analyzer.semantic_model_overlay() {
        not_found.retain(|missing| {
            let mut matched = if missing.input.starts_with("bifrost-model://") {
                overlay.symbols_at_uri(&missing.input).records
            } else {
                let mut records = overlay.symbols_with_id(&missing.input).records;
                if records.is_empty() {
                    records = overlay.symbols_named(&missing.input).records;
                }
                records
            };
            if matched.is_empty() {
                true
            } else if matched.iter().any(|record| record.provenance.ambiguous)
                || matched.len() > 1
            {
                model_ambiguous.push(AmbiguousSymbol {
                    target: missing.input.clone(),
                    matches: matched
                        .iter()
                        .map(|record| record.location.identity().to_string())
                        .collect(),
                    note: Some(
                        "conflicting active semantic-model declarations have no authoritative location"
                            .to_string(),
                    ),
                });
                false
            } else {
                model_locations.extend(matched.drain(..).cloned());
                false
            }
        });
    }

    SymbolLocationsResult {
        locations,
        model_locations,
        not_found,
        ambiguous: model_ambiguous,
    }
}

pub fn get_definitions_by_location(
    analyzer: &dyn IAnalyzer,
    params: GetDefinitionParams,
) -> GetDefinitionResult {
    get_definitions_by_location_with_cancellation(analyzer, params, None)
}

pub fn get_definitions_by_location_with_cancellation(
    analyzer: &dyn IAnalyzer,
    params: GetDefinitionParams,
    cancellation: Option<&crate::CancellationToken>,
) -> GetDefinitionResult {
    let _scope = profiling::scope("searchtools::get_definitions_by_location");
    GetDefinitionResult {
        results: get_navigation_by_location_with_cancellation(
            analyzer,
            params,
            NavigationOperation::Definition,
            cancellation,
        ),
    }
}

pub fn get_declarations_by_location(
    analyzer: &dyn IAnalyzer,
    params: GetDefinitionParams,
) -> GetDeclarationResult {
    get_declarations_by_location_with_cancellation(analyzer, params, None)
}

pub fn get_declarations_by_location_with_cancellation(
    analyzer: &dyn IAnalyzer,
    params: GetDefinitionParams,
    cancellation: Option<&crate::CancellationToken>,
) -> GetDeclarationResult {
    let _scope = profiling::scope("searchtools::get_declarations_by_location");
    GetDeclarationResult {
        results: get_navigation_by_location_with_cancellation(
            analyzer,
            params,
            NavigationOperation::Declaration,
            cancellation,
        )
        .into_iter()
        .map(|result| DeclarationLookupResult {
            query: result.query,
            operation: result.operation,
            status: result.status,
            reference: result.reference,
            declarations: result.definitions,
            diagnostics: result.diagnostics,
        })
        .collect(),
    }
}

fn get_navigation_by_location_with_cancellation(
    analyzer: &dyn IAnalyzer,
    params: GetDefinitionParams,
    operation: NavigationOperation,
    cancellation: Option<&crate::CancellationToken>,
) -> Vec<DefinitionLookupResult> {
    let tool_name = match operation {
        NavigationOperation::Declaration => "get_declarations_by_location",
        NavigationOperation::Definition => "get_definitions_by_location",
    };

    if params.references.len() > DEFINITION_LOOKUP_MAX_REFERENCES {
        return vec![DefinitionLookupResult {
            query: DefinitionReferenceQuery {
                path: String::new(),
                line: None,
                column: None,
            },
            operation,
            status: "invalid_location".to_string(),
            reference: None,
            definitions: Vec::new(),
            diagnostics: vec![DefinitionDiagnostic {
                kind: "too_many_references".to_string(),
                message: format!(
                    "{tool_name} accepts at most {DEFINITION_LOOKUP_MAX_REFERENCES} references per call"
                ),
            }],
        }];
    }

    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);
    let mut pending = Vec::new();
    let mut results: Vec<Option<DefinitionLookupResult>> = vec![None; params.references.len()];

    for (index, query) in params.references.into_iter().enumerate() {
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            break;
        }
        if query.path.starts_with("bifrost-model://")
            && let Some(overlay) = analyzer.semantic_model_overlay()
        {
            let matched = overlay.symbols_at_uri(&query.path);
            if !matched.records.is_empty() {
                let conflict = matched.disposition
                    == crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Conflict;
                let navigation = if conflict {
                    Ok(None)
                } else {
                    semantic_model_navigation_candidates(analyzer, &overlay, matched.records[0])
                };
                let navigation_conflict = navigation.as_ref().is_err();
                let (mut definitions, navigation_diagnostic) = match navigation {
                    Ok(Some(definitions)) => (definitions, None),
                    Ok(None) => (
                        vec![semantic_model_definition_candidate(
                            analyzer,
                            matched.records[0],
                        )],
                        None,
                    ),
                    Err(diagnostic) => (Vec::new(), Some(diagnostic)),
                };
                if conflict {
                    definitions.clear();
                }
                results[index] = Some(DefinitionLookupResult {
                    query: query.clone(),
                    operation,
                    status: if conflict || navigation_conflict {
                        "ambiguous"
                    } else {
                        "resolved"
                    }
                    .to_string(),
                    reference: Some(DefinitionReferenceSite {
                        path: query.path.clone(),
                        target: matched.records[0].qualified_name.clone(),
                    }),
                    definitions,
                    diagnostics: if conflict {
                        vec![DefinitionDiagnostic {
                            kind: "semantic_model_conflict".to_string(),
                            message: "the model URI resolves to conflicting active declarations"
                                .to_string(),
                        }]
                    } else {
                        navigation_diagnostic.into_iter().collect()
                    },
                });
                continue;
            }
        }
        match resolver.resolve_literal(&query.path) {
            ResolvedFileInput::File(file) => {
                pending.push((
                    index,
                    query.clone(),
                    crate::analyzer::usages::get_definition::DefinitionLookupRequest {
                        file,
                        line: query.line,
                        column: query.column,
                        start_byte: None,
                        end_byte: None,
                    },
                ));
            }
            ResolvedFileInput::Ambiguous(item) => {
                results[index] = Some(DefinitionLookupResult {
                    query,
                    operation,
                    status: "not_found".to_string(),
                    reference: None,
                    definitions: Vec::new(),
                    diagnostics: vec![DefinitionDiagnostic {
                        kind: "ambiguous_path".to_string(),
                        message: format!(
                            "`{}` is ambiguous; matches: {}",
                            item.input,
                            item.matches.join(", ")
                        ),
                    }],
                });
            }
            ResolvedFileInput::NotFound(path) => {
                results[index] = Some(DefinitionLookupResult {
                    query,
                    operation,
                    status: "not_found".to_string(),
                    reference: None,
                    definitions: Vec::new(),
                    diagnostics: vec![DefinitionDiagnostic {
                        kind: "path_not_found".to_string(),
                        message: format!("`{path}` does not resolve to a workspace file"),
                    }],
                });
            }
        }
    }

    let mut render_cache = DefinitionCandidateRenderCache::default();
    for chunk in pending.chunks(8) {
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            break;
        }
        let requests = chunk
            .iter()
            .map(|(_, _, request)| request.clone())
            .collect();
        let outcomes = crate::analyzer::usages::get_definition::resolve_navigation_batch(
            analyzer,
            requests,
            operation,
            cancellation,
            false,
        );
        for ((index, query, request), outcome) in chunk.iter().zip(outcomes) {
            results[*index] = Some(render_definition_lookup(
                analyzer,
                query.clone(),
                &request.file,
                outcome,
                operation,
                &mut render_cache,
            ));
        }
    }

    results.into_iter().flatten().collect()
}

fn semantic_model_navigation_candidates(
    analyzer: &dyn IAnalyzer,
    overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
) -> Result<Option<Vec<DefinitionCandidate>>, DefinitionDiagnostic> {
    let relations = overlay
        .relations_from(&symbol.id)
        .records
        .into_iter()
        .filter(|relation| relation.kind == "navigates_to")
        .collect::<Vec<_>>();
    if relations.is_empty() {
        return Ok(None);
    }
    if relations.len() != 1 || relations[0].provenance.ambiguous {
        return Err(DefinitionDiagnostic {
            kind: "semantic_model_conflict".to_string(),
            message: format!(
                "`{}` has conflicting active semantic-model navigation targets; no definition was selected",
                symbol.qualified_name
            ),
        });
    }
    let relation = relations[0];
    let mut modeled_target = overlay.symbols_with_id(&relation.to);
    if modeled_target.records.is_empty() {
        modeled_target = overlay.symbols_named(&relation.to);
    }
    match modeled_target.disposition {
        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique => {
            return Ok(Some(vec![semantic_model_definition_candidate(
                analyzer,
                modeled_target.records[0],
            )]));
        }
        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Conflict => {
            return Err(DefinitionDiagnostic {
                kind: "semantic_model_conflict".to_string(),
                message: format!(
                    "the navigation target `{}` resolves to conflicting active semantic-model declarations",
                    relation.to
                ),
            });
        }
        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Empty => {}
    }

    match exact_codeunit_resolution(analyzer, &relation.to) {
        CodeUnitResolution::Resolved(units) => {
            let mut definitions = definition_candidates(analyzer, &units);
            for definition in &mut definitions {
                definition.semantic_model = Some(relation.provenance.clone());
            }
            if definitions.is_empty() {
                Err(unresolved_semantic_model_navigation(symbol, &relation.to))
            } else {
                Ok(Some(definitions))
            }
        }
        CodeUnitResolution::Ambiguous(_) => Err(DefinitionDiagnostic {
            kind: "semantic_model_conflict".to_string(),
            message: format!(
                "the navigation target `{}` is ambiguous in authored source; no definition was selected",
                relation.to
            ),
        }),
        CodeUnitResolution::NotFound => {
            Err(unresolved_semantic_model_navigation(symbol, &relation.to))
        }
    }
}

fn unresolved_semantic_model_navigation(
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
    target: &str,
) -> DefinitionDiagnostic {
    DefinitionDiagnostic {
        kind: "semantic_model_target_not_found".to_string(),
        message: format!(
            "`{}` navigates to `{target}`, but that target is absent from authored source and the active semantic model",
            symbol.qualified_name
        ),
    }
}

pub fn get_type_by_location(analyzer: &dyn IAnalyzer, params: GetTypeParams) -> GetTypeResult {
    let _scope = profiling::scope("searchtools::get_type_by_location");

    if params.references.len() > TYPE_LOOKUP_MAX_REFERENCES {
        return GetTypeResult {
            results: vec![TypeLookupResult {
                query: TypeReferenceQuery {
                    path: String::new(),
                    line: None,
                    column: None,
                },
                status: "invalid_location".to_string(),
                reference: None,
                types: Vec::new(),
                diagnostics: vec![DefinitionDiagnostic {
                    kind: "too_many_references".to_string(),
                    message: format!(
                        "get_type_by_location accepts at most {TYPE_LOOKUP_MAX_REFERENCES} references per call"
                    ),
                }],
            }],
        };
    }

    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);
    let mut pending = Vec::new();
    let mut results: Vec<Option<TypeLookupResult>> = vec![None; params.references.len()];

    for (index, query) in params.references.into_iter().enumerate() {
        match resolver.resolve_literal(&query.path) {
            ResolvedFileInput::File(file) => {
                pending.push((
                    index,
                    query.clone(),
                    crate::analyzer::usages::get_type::TypeLookupRequest {
                        file,
                        source: None,
                        line: query.line,
                        column: query.column,
                        start_byte: None,
                        end_byte: None,
                    },
                ));
            }
            ResolvedFileInput::Ambiguous(item) => {
                results[index] = Some(TypeLookupResult {
                    query,
                    status: "not_found".to_string(),
                    reference: None,
                    types: Vec::new(),
                    diagnostics: vec![DefinitionDiagnostic {
                        kind: "ambiguous_path".to_string(),
                        message: format!(
                            "`{}` is ambiguous; matches: {}",
                            item.input,
                            item.matches.join(", ")
                        ),
                    }],
                });
            }
            ResolvedFileInput::NotFound(path) => {
                results[index] = Some(TypeLookupResult {
                    query,
                    status: "not_found".to_string(),
                    reference: None,
                    types: Vec::new(),
                    diagnostics: vec![DefinitionDiagnostic {
                        kind: "path_not_found".to_string(),
                        message: format!("`{path}` does not resolve to a workspace file"),
                    }],
                });
            }
        }
    }

    let requests: Vec<_> = pending
        .iter()
        .map(|(_, _, request)| request.clone())
        .collect();
    let outcomes = crate::analyzer::usages::get_type::resolve_type_batch(analyzer, requests);

    let mut render_cache = DefinitionCandidateRenderCache::default();
    for ((index, query, request), outcome) in pending.into_iter().zip(outcomes) {
        results[index] = Some(render_type_lookup(
            analyzer,
            query,
            &request.file,
            outcome,
            &mut render_cache,
        ));
    }

    GetTypeResult {
        results: results.into_iter().flatten().collect(),
    }
}

pub fn rename_symbol(analyzer: &dyn IAnalyzer, params: RenameSymbolParams) -> RenameSymbolResult {
    let _scope = profiling::scope("searchtools::rename_symbol");

    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);
    let file = match resolver.resolve_literal(params.path.trim()) {
        ResolvedFileInput::File(file) => file,
        ResolvedFileInput::Ambiguous(item) => {
            return rename_symbol_failure(
                params,
                "ambiguous_path",
                format!(
                    "`{}` is ambiguous; matches: {}",
                    item.input,
                    item.matches.join(", ")
                ),
            );
        }
        ResolvedFileInput::NotFound(path) => {
            return rename_symbol_failure(
                params,
                "path_not_found",
                format!("`{path}` does not resolve to a workspace file"),
            );
        }
    };

    let selection = match rename_selection_from_params(&params) {
        Ok(selection) => selection,
        Err(message) => return rename_symbol_failure(params, "invalid_location", message),
    };

    match crate::symbol_rename::rename_symbol(
        analyzer,
        analyzer.project(),
        file.clone(),
        selection,
        &params.new_name,
    ) {
        Ok(result) => render_rename_symbol_result(analyzer, params, result),
        Err(err) => {
            let message = if matches!(err.kind, "invalid_location" | "not_found") {
                location_failure_message(
                    analyzer,
                    &file,
                    &params.path,
                    params.line,
                    params.column,
                    &err.message,
                    "move the location to an identifier token and retry rename_symbol; use get_definitions_by_location first if the target is uncertain.",
                )
                .unwrap_or(err.message)
            } else {
                err.message
            };
            rename_symbol_failure(params, err.kind, message)
        }
    }
}

pub(super) fn rename_selection_from_params(
    params: &RenameSymbolParams,
) -> Result<crate::symbol_rename::RenameSelection, String> {
    match (params.line, params.column) {
        (Some(line), Some(column)) => {
            Ok(crate::symbol_rename::RenameSelection::LineColumn { line, column })
        }
        (Some(_), None) => Err("rename_symbol requires column when line is provided".to_string()),
        (None, Some(_)) => Err("rename_symbol requires line when column is provided".to_string()),
        _ => Err("rename_symbol requires line and column".to_string()),
    }
}

pub(super) fn render_rename_symbol_result(
    analyzer: &dyn IAnalyzer,
    query: RenameSymbolParams,
    result: crate::symbol_rename::RenameResult,
) -> RenameSymbolResult {
    let mut file_edits = Vec::new();
    for file_result in result.files {
        let source = match analyzer.project().read_source(&file_result.file) {
            Ok(source) => source,
            Err(err) => {
                return rename_symbol_failure(
                    query,
                    "read_failed",
                    format!(
                        "failed to read `{}` while rendering rename edits: {err}",
                        rel_path_string(&file_result.file)
                    ),
                );
            }
        };
        let line_starts = compute_line_starts(&source);
        let edits = file_result
            .edits
            .into_iter()
            .map(|edit| {
                let old_text = source
                    .get(edit.start_byte..edit.end_byte)
                    .unwrap_or_default()
                    .to_string();
                let (start_line, start_column) = crate::symbol_rename::line_column_for_byte_offset(
                    &source,
                    &line_starts,
                    edit.start_byte,
                );
                let (end_line, end_column) = crate::symbol_rename::line_column_for_byte_offset(
                    &source,
                    &line_starts,
                    edit.end_byte,
                );
                RenameTextEdit {
                    old_text,
                    start_line,
                    start_column,
                    end_line,
                    end_column,
                    new_text: edit.new_text,
                }
            })
            .collect();
        file_edits.push(RenameFileEdits {
            path: rel_path_string(&file_result.file),
            edits,
        });
    }

    RenameSymbolResult {
        query,
        status: "ok".to_string(),
        target: Some(RenameSymbolTarget {
            symbol: result.target.fq_name().to_string(),
            kind: result.target.kind().display_lowercase().to_string(),
            path: rel_path_string(result.target.source()),
        }),
        old_name: Some(result.old_name),
        edits: file_edits,
        diagnostics: Vec::new(),
    }
}

pub(super) fn rename_symbol_failure(
    query: RenameSymbolParams,
    kind: &'static str,
    message: String,
) -> RenameSymbolResult {
    RenameSymbolResult {
        query,
        status: kind.to_string(),
        target: None,
        old_name: None,
        edits: Vec::new(),
        diagnostics: vec![DefinitionDiagnostic {
            kind: kind.to_string(),
            message,
        }],
    }
}

pub(super) fn render_definition_lookup(
    analyzer: &dyn IAnalyzer,
    query: DefinitionReferenceQuery,
    file: &ProjectFile,
    outcome: crate::analyzer::usages::get_definition::NavigationLookupOutcome,
    operation: NavigationOperation,
    render_cache: &mut DefinitionCandidateRenderCache,
) -> DefinitionLookupResult {
    let mut status = if operation == NavigationOperation::Declaration
        && outcome.status
            == crate::analyzer::usages::get_definition::DefinitionLookupStatus::NoDefinition
    {
        "no_declaration".to_string()
    } else {
        outcome.status.as_str().to_string()
    };
    let mut definitions =
        navigation_candidates_with_cache(analyzer, &outcome.targets, render_cache);
    if let Some(definition) = outcome.lexical_definition.as_ref()
        && let Some(candidate) = lexical_definition_candidate(analyzer, file, definition)
    {
        definitions.push(candidate);
    }
    let reference_target = outcome.reference.as_ref().map(|site| site.text.clone());
    let imported_model_target = outcome
        .reference
        .as_ref()
        .and_then(|reference| explicit_import_model_target(analyzer, file, reference));
    let mut diagnostics: Vec<DefinitionDiagnostic> = outcome
        .diagnostics
        .into_iter()
        .map(|diagnostic| DefinitionDiagnostic {
            message: external_location_diagnostic_message(&diagnostic.kind, diagnostic.message),
            kind: diagnostic.kind,
        })
        .collect();
    if let Some(overlay) = analyzer.semantic_model_overlay() {
        if definitions.is_empty() {
            if let Some(target) = reference_target.as_deref() {
                let receiver_owner = outcome
                    .reference
                    .as_ref()
                    .and_then(|reference| structured_receiver_owner(analyzer, file, reference));
                let member_name = target
                    .rsplit(['.', '#', ':'])
                    .find(|part| !part.is_empty())
                    .unwrap_or(target);
                let mut matched = receiver_owner
                    .as_deref()
                    .map(|owner| modeled_member_named(&overlay, owner, member_name))
                    .filter(|matched| !matched.records.is_empty())
                    .or_else(|| {
                        imported_model_target
                            .as_deref()
                            .map(|target| overlay.symbols_named(target))
                    })
                    .unwrap_or_else(|| overlay.symbols_with_id(target));
                if matched.records.is_empty() {
                    matched = overlay.symbols_named(target);
                }
                if matched.records.is_empty() && target.contains("::") {
                    matched = overlay.symbols_named(&target.replace("::", "."));
                }
                if matched.records.is_empty() && target.contains('#') {
                    matched = overlay.symbols_named(&target.replace('#', "."));
                }
                if structured_reference_kind(analyzer, file, outcome.reference.as_ref())
                    == Some(NormalizedKind::FieldAccess)
                    && matched
                        .records
                        .iter()
                        .all(|record| record.language == "java")
                {
                    matched.records.retain(|record| {
                        record.provenance.rule_id.is_none()
                            || !matches!(
                                record.kind,
                                crate::analyzer::semantic_model::SemanticModelSymbolKind::Method
                                    | crate::analyzer::semantic_model::SemanticModelSymbolKind::Function
                                    | crate::analyzer::semantic_model::SemanticModelSymbolKind::Constructor
                            )
                    });
                    matched.disposition = if matched.records.is_empty() {
                        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Empty
                    } else if matched.records.len() == 1 && !matched.records[0].provenance.ambiguous
                    {
                        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
                    } else {
                        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Conflict
                    };
                }
                if let Some(arity) = outcome.reference.as_ref().and_then(|reference| {
                    structured_reference_call_arity(analyzer, file, reference)
                }) {
                    matched.records.retain(|record| {
                        record.provenance.rule_id.is_none()
                            || record
                                .structured_signature
                                .as_ref()
                                .is_none_or(|signature| {
                                    let required = signature
                                        .parameters
                                        .iter()
                                        .filter(|parameter| {
                                            !parameter.optional && !parameter.variadic
                                        })
                                        .count();
                                    let has_variadic = signature
                                        .parameters
                                        .iter()
                                        .any(|parameter| parameter.variadic);
                                    required <= arity
                                        && (has_variadic || arity <= signature.parameters.len())
                                })
                    });
                    matched.disposition = if matched.records.is_empty() {
                        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Empty
                    } else if matched.records.len() == 1 && !matched.records[0].provenance.ambiguous
                    {
                        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
                    } else {
                        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Conflict
                    };
                }
                if matched
                    .records
                    .iter()
                    .all(|record| record.language == "ruby" && record.owner_id.is_some())
                {
                    let static_reference = target.contains('.') && !target.contains('#');
                    matched
                        .records
                        .retain(|record| record.is_static == static_reference);
                    matched.disposition = if matched.records.is_empty() {
                        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Empty
                    } else if matched.records.len() == 1 && !matched.records[0].provenance.ambiguous
                    {
                        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
                    } else {
                        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Conflict
                    };
                }
                match matched.disposition {
                    crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique => {
                        definitions.push(semantic_model_definition_candidate(
                            analyzer,
                            matched.records[0],
                        ));
                        status = "resolved".to_string();
                    }
                    crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Conflict => {
                        let overload_set = matched.records.first().is_some_and(|first| {
                            let mut callable_shapes = HashSet::default();
                            first.owner_id.is_some()
                                && matched.records.iter().all(|record| {
                                    record.owner_id == first.owner_id
                                        && record.name == first.name
                                        && record.qualified_name == first.qualified_name
                                        && record.kind == first.kind
                                        && record
                                            .callable_shape
                                            .as_ref()
                                            .is_some_and(|shape| callable_shapes.insert(shape))
                                })
                        });
                        if overload_set {
                            definitions.extend(matched.records.iter().map(|record| {
                                semantic_model_definition_candidate(analyzer, record)
                            }));
                            status = "resolved".to_string();
                        } else {
                            status = "ambiguous".to_string();
                            diagnostics.push(DefinitionDiagnostic {
                                kind: "semantic_model_conflict".to_string(),
                                message: format!(
                                    "`{target}` matches conflicting active semantic-model declarations; no definition was selected"
                                ),
                            });
                        }
                    }
                    crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Empty => {}
                }
            }
        } else {
            for candidate in &mut definitions {
                let target = candidate.fqn.as_deref().unwrap_or(&candidate.name);
                let matched = overlay.symbols_named(target);
                if matched.disposition
                    == crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
                    && matches!(
                        &matched.records[0].location,
                        crate::analyzer::semantic_model::SemanticModelLocation::Authored(anchor)
                            if candidate.fqn.as_deref() == Some(anchor.symbol.as_str())
                                && candidate.path == anchor.path
                                && candidate.start_line == anchor.range.start_line
                    )
                {
                    candidate.semantic_model = Some(matched.records[0].provenance.clone());
                }
            }
        }
    }
    if matches!(
        status.as_str(),
        "invalid_location" | "not_found" | "no_definition" | "no_declaration"
    ) {
        enrich_location_diagnostics(
            analyzer,
            file,
            &query.path,
            query.line,
            query.column,
            &mut diagnostics,
            match operation {
                NavigationOperation::Declaration => {
                    "the requested location did not resolve to a declaration"
                }
                NavigationOperation::Definition => {
                    "the requested location did not resolve to a definition"
                }
            },
            match operation {
                NavigationOperation::Declaration => {
                    "move the location to the intended reference token and retry get_declarations_by_location; use get_summaries on the file or search_symbols if the target is uncertain."
                }
                NavigationOperation::Definition => {
                    "move the location to the intended reference token and retry get_definitions_by_location; use get_summaries on the file or search_symbols if the target is uncertain."
                }
            },
        );
    }
    DefinitionLookupResult {
        query,
        operation,
        status,
        reference: outcome.reference.map(|site| DefinitionReferenceSite {
            path: site.path,
            target: site.text,
        }),
        definitions,
        diagnostics,
    }
}

fn modeled_member_named<'a>(
    overlay: &'a crate::analyzer::semantic_model::SemanticModelOverlay,
    owner: &str,
    name: &str,
) -> crate::analyzer::semantic_model::SemanticModelOverlayMatch<
    'a,
    crate::analyzer::semantic_model::SemanticModelSymbol,
> {
    let records = overlay
        .members_of(owner)
        .records
        .into_iter()
        .filter(|symbol| symbol.name == name)
        .collect::<Vec<_>>();
    let disposition = if records.is_empty() {
        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Empty
    } else if records.len() == 1 && !records[0].provenance.ambiguous {
        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
    } else {
        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Conflict
    };
    crate::analyzer::semantic_model::SemanticModelOverlayMatch {
        records,
        disposition,
    }
}

fn structured_receiver_owner(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    reference: &crate::analyzer::usages::reference_site::ResolvedReferenceSite,
) -> Option<String> {
    let focus = reference.focus_start_byte;
    let receiver = analyzer
        .structural_search_providers()
        .into_iter()
        .find_map(|provider| {
            let facts = provider.structural_facts(file)?;
            facts
                .nodes()
                .iter()
                .enumerate()
                .filter(|(_, node)| {
                    matches!(
                        node.kind,
                        NormalizedKind::Call | NormalizedKind::FieldAccess
                    ) && node.range.start_byte <= focus
                        && focus < node.range.end_byte
                })
                .min_by_key(|(_, node)| node.range.end_byte - node.range.start_byte)
                .and_then(|(index, node)| {
                    let node_id = u32::try_from(index).ok()?;
                    let names_reference = node
                        .name
                        .is_some_and(|span| span.start_byte <= focus && focus < span.end_byte)
                        || facts.roles(node_id).iter().any(|target| {
                            target.role == Role::Kwarg
                                && target.keyword.is_some_and(|span| {
                                    span.start_byte <= focus && focus < span.end_byte
                                })
                        });
                    if !names_reference {
                        return None;
                    }
                    let role = if node.kind == NormalizedKind::Call {
                        Role::Receiver
                    } else {
                        Role::Object
                    };
                    let receiver_byte = facts.role_targets(node_id, role).next()?.span.start_byte;
                    Some(facts.line_column_of_byte(receiver_byte))
                })
        })?;
    let (line, column) = receiver;
    let result = get_type_by_location(
        analyzer,
        GetTypeParams {
            references: vec![TypeReferenceQuery {
                path: file.rel_path().to_string_lossy().replace('\\', "/"),
                line: Some(line),
                column: Some(column),
            }],
        },
    );
    if let [result] = result.results.as_slice()
        && let [candidate] = result.types.as_slice()
    {
        return Some(candidate.fqn.clone());
    }
    let definition = get_definitions_by_location(
        analyzer,
        GetDefinitionParams {
            references: vec![DefinitionReferenceQuery {
                path: file.rel_path().to_string_lossy().replace('\\', "/"),
                line: Some(line),
                column: Some(column),
            }],
        },
    );
    let [result] = definition.results.as_slice() else {
        return None;
    };
    let [candidate] = result.definitions.as_slice() else {
        return None;
    };
    candidate.fqn.clone()
}

fn structured_reference_call_arity(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    reference: &crate::analyzer::usages::reference_site::ResolvedReferenceSite,
) -> Option<usize> {
    let reference_range = &reference.range;
    analyzer
        .structural_search_providers()
        .into_iter()
        .find_map(|provider| {
            let facts = provider.structural_facts(file)?;
            facts
                .nodes()
                .iter()
                .enumerate()
                .filter(|(_, node)| {
                    node.kind == NormalizedKind::Call
                        && node.name.is_some_and(|name| {
                            name.start_byte < reference_range.end_byte
                                && reference_range.start_byte < name.end_byte
                        })
                        && node.range.start_byte < reference_range.end_byte
                        && reference_range.start_byte < node.range.end_byte
                })
                .min_by_key(|(_, node)| node.range.end_byte - node.range.start_byte)
                .and_then(|(index, node)| {
                    if node.construct.as_deref() == Some("java_method_reference") {
                        return None;
                    }
                    let node_id = u32::try_from(index).ok()?;
                    node.name.is_some().then(|| {
                        facts
                            .roles(node_id)
                            .iter()
                            .filter(|target| matches!(target.role, Role::Arg | Role::Kwarg))
                            .count()
                    })
                })
        })
}

fn structured_reference_kind(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    reference: Option<&crate::analyzer::usages::reference_site::ResolvedReferenceSite>,
) -> Option<NormalizedKind> {
    let reference = reference?;
    let reference_range = &reference.range;
    analyzer
        .structural_search_providers()
        .into_iter()
        .find_map(|provider| {
            let facts = provider.structural_facts(file)?;
            facts
                .nodes()
                .iter()
                .filter(|node| {
                    matches!(
                        node.kind,
                        NormalizedKind::Call | NormalizedKind::FieldAccess
                    ) && node.name.is_some_and(|name| {
                        name.start_byte < reference_range.end_byte
                            && reference_range.start_byte < name.end_byte
                    }) && node.range.start_byte < reference_range.end_byte
                        && reference_range.start_byte < node.range.end_byte
                })
                .min_by_key(|node| {
                    let named_call = node.kind == NormalizedKind::Call && node.name.is_some();
                    (!named_call, node.range.end_byte - node.range.start_byte)
                })
                .map(|node| node.kind)
        })
}

fn explicit_import_model_target(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    reference: &crate::analyzer::usages::reference_site::ResolvedReferenceSite,
) -> Option<String> {
    let language = language_for_file(file);
    if !matches!(language, Language::Java | Language::Scala) {
        return None;
    }
    let reference_name = symbol_selector_leaf(language, &reference.text)?;
    let provider = analyzer.import_analysis_provider_for_file(file)?;
    let mut targets = provider
        .import_info_of(file)
        .into_iter()
        .filter(|import| {
            !import.is_wildcard
                && (import.local_name() == Some(&reference_name)
                    || import.path.as_ref().and_then(|path| path.segments.last())
                        == Some(&reference_name))
        })
        .filter_map(|import| import.path)
        .filter(|path| {
            path.declaration_start_byte <= reference.focus_start_byte
                && path.lexical_scopes.iter().all(|scope| {
                    scope.start_byte <= reference.focus_start_byte
                        && reference.focus_start_byte < scope.end_byte
                })
        })
        .map(|path| path.render_segments("."))
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    (targets.len() == 1).then(|| targets.pop().unwrap())
}

pub(super) fn render_type_lookup(
    analyzer: &dyn IAnalyzer,
    query: TypeReferenceQuery,
    file: &ProjectFile,
    outcome: crate::analyzer::usages::get_type::TypeLookupOutcome,
    render_cache: &mut DefinitionCandidateRenderCache,
) -> TypeLookupResult {
    let status = outcome.status.as_str().to_string();
    let mut diagnostics: Vec<DefinitionDiagnostic> = outcome
        .diagnostics
        .into_iter()
        .map(|diagnostic| DefinitionDiagnostic {
            message: external_location_diagnostic_message(&diagnostic.kind, diagnostic.message),
            kind: diagnostic.kind,
        })
        .collect();
    if matches!(
        status.as_str(),
        "invalid_location" | "not_found" | "no_type"
    ) {
        enrich_location_diagnostics(
            analyzer,
            file,
            &query.path,
            query.line,
            query.column,
            &mut diagnostics,
            "the requested location did not resolve to a type",
            "move the location to the intended reference token and retry get_type_by_location; use get_definitions_by_location or get_summaries if the target is uncertain.",
        );
    }
    TypeLookupResult {
        query,
        status,
        reference: outcome.reference.map(|site| DefinitionReferenceSite {
            path: site.path,
            target: site.text,
        }),
        types: outcome
            .types
            .iter()
            .map(|item| type_lookup_candidate(analyzer, item, render_cache))
            .collect(),
        diagnostics,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn enrich_location_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    path: &str,
    line: Option<usize>,
    column: Option<usize>,
    diagnostics: &mut Vec<DefinitionDiagnostic>,
    fallback_reason: &str,
    recovery: &str,
) {
    let reason = diagnostics
        .first()
        .map(|diagnostic| diagnostic.message.as_str())
        .unwrap_or(fallback_reason);
    let Some(message) =
        location_failure_message(analyzer, file, path, line, column, reason, recovery)
    else {
        return;
    };
    if let Some(diagnostic) = diagnostics.first_mut() {
        diagnostic.message = message;
    } else {
        diagnostics.push(DefinitionDiagnostic {
            kind: "location_context".to_string(),
            message,
        });
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn location_failure_message(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    path: &str,
    line: Option<usize>,
    column: Option<usize>,
    reason: &str,
    recovery: &str,
) -> Option<String> {
    let line = line?;
    let source = analyzer.project().read_source(file).ok()?;
    Some(render_location_diagnostic(
        &source, path, line, column, reason, recovery,
    ))
}

pub(super) fn type_lookup_candidate(
    analyzer: &dyn IAnalyzer,
    item: &crate::analyzer::usages::get_type::TypeLookupType,
    render_cache: &mut DefinitionCandidateRenderCache,
) -> TypeLookupCandidate {
    let definitions = definition_candidates_with_cache(analyzer, &item.definitions, render_cache);
    let primary = definitions.first();
    TypeLookupCandidate {
        fqn: item.fqn.clone(),
        kind: primary.map(|candidate| candidate.kind.clone()),
        language: primary.map(|candidate| candidate.language.clone()),
        definitions,
    }
}

pub fn get_symbol_ancestors(
    analyzer: &dyn IAnalyzer,
    params: SymbolLookupParams,
) -> SymbolAncestorsResult {
    let Some(provider) = analyzer.type_hierarchy_provider() else {
        let mut ancestors = Vec::new();
        let mut not_found = Vec::new();
        for symbol in params
            .symbols
            .into_iter()
            .filter(|symbol| !symbol.trim().is_empty())
        {
            if let Some(model) = model_symbol_ancestors(analyzer, &symbol) {
                ancestors.push(model);
            } else {
                not_found.push(not_found_input(
                    symbol,
                    Some(
                        "no analyzer in this workspace supports ancestor (type hierarchy) queries for this symbol's language"
                            .to_string(),
                    ),
                ));
            }
        }
        return SymbolAncestorsResult {
            ancestors,
            not_found,
            ambiguous: Vec::new(),
        };
    };

    let mut ancestors = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous = Vec::new();

    for symbol in params
        .symbols
        .into_iter()
        .filter(|symbol| !symbol.trim().is_empty())
    {
        match resolve_selectable_definitions(analyzer, &symbol, resolve_codeunit_fuzzy) {
            SelectableDefinitionResolution::Resolved(code_units) => {
                let mut resolved = Vec::new();
                let mut rejected_kind = None;
                for code_unit in code_units {
                    if !is_ancestor_target(&code_unit) {
                        rejected_kind.get_or_insert(code_unit_kind_name(code_unit.kind()));
                        continue;
                    }
                    let mut ancestor_names = provider
                        .get_ancestors(&code_unit)
                        .into_iter()
                        .map(|ancestor| display_symbol_for_target(&ancestor))
                        .collect::<Vec<_>>();
                    append_active_universal_root(analyzer, &code_unit, &mut ancestor_names);
                    resolved.push(SymbolAncestors {
                        symbol: display_symbol_for_target(&code_unit),
                        ancestors: ancestor_names,
                    });
                }
                if resolved.is_empty() {
                    if let Some(model) = model_symbol_ancestors(analyzer, &symbol) {
                        ancestors.push(model);
                        continue;
                    }
                    let note = rejected_kind.map(|kind| {
                        format!(
                            "resolves to a {kind}; get_symbol_ancestors only accepts class/module/type symbols"
                        )
                    });
                    not_found.push(not_found_input(symbol, note));
                } else {
                    ancestors.extend(resolved);
                }
            }
            SelectableDefinitionResolution::Ambiguous(item) => {
                if let Some(model) = model_symbol_ancestors(analyzer, &symbol) {
                    ancestors.push(model);
                } else {
                    ambiguous.push(item);
                }
            }
            SelectableDefinitionResolution::NotFound(target) => {
                if let Some(model) = model_symbol_ancestors(analyzer, &target.input) {
                    ancestors.push(model);
                    continue;
                }
                if path_like_symbol_guidance(
                    &target.input,
                    PathLikeSymbolGuidanceContext::SymbolLookup,
                )
                .is_some()
                {
                    not_found.push(path_like_symbol_not_found_input(
                        target.input,
                        PathLikeSymbolGuidanceContext::SymbolLookup,
                    ));
                } else {
                    not_found.push(target);
                }
            }
        }
    }

    SymbolAncestorsResult {
        ancestors,
        not_found,
        ambiguous,
    }
}

fn append_active_universal_root(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    ancestors: &mut Vec<String>,
) {
    let Some(language) = code_unit
        .source()
        .rel_path()
        .extension()
        .and_then(|extension| extension.to_str())
        .and_then(|extension| match extension {
            "java" => Some("java"),
            "scala" => Some("scala"),
            _ => None,
        })
    else {
        return;
    };
    if language == "java"
        && matches!(
            analyzer.declaration_syntax_kind(code_unit),
            Some("interface_declaration" | "annotation_type_declaration")
        )
    {
        return;
    }
    let Some(overlay) = analyzer.semantic_model_overlay() else {
        return;
    };
    let root = overlay.universal_root_for_language(language);
    if root.disposition != crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
    {
        return;
    }
    let root_name = &root.records[0].qualified_name;
    if code_unit.fq_name() != *root_name && !ancestors.contains(root_name) {
        ancestors.push(root_name.clone());
    }
}

fn model_symbol_ancestors(analyzer: &dyn IAnalyzer, target: &str) -> Option<SymbolAncestors> {
    let overlay = analyzer.semantic_model_overlay()?;
    let matched = overlay.symbols_named(target);
    let model_targets = matched
        .records
        .iter()
        .copied()
        .filter(|symbol| symbol.qualified_name == target && is_model_ancestor_target(symbol));
    let mut found = false;
    let mut names = Vec::new();
    for model_symbol in model_targets {
        found = true;
        let model_ancestors = overlay.ancestors_of(model_symbol);
        names.extend(
            model_ancestors
                .records
                .into_iter()
                .map(|ancestor| ancestor.qualified_name.clone()),
        );
    }
    if !found {
        return None;
    }
    names.sort();
    names.dedup();
    Some(SymbolAncestors {
        symbol: target.to_string(),
        ancestors: names,
    })
}

fn is_model_ancestor_target(symbol: &crate::analyzer::semantic_model::SemanticModelSymbol) -> bool {
    use crate::analyzer::semantic_model::SemanticModelSymbolKind;
    matches!(
        symbol.kind,
        SemanticModelSymbolKind::Class
            | SemanticModelSymbolKind::Interface
            | SemanticModelSymbolKind::Trait
            | SemanticModelSymbolKind::Struct
            | SemanticModelSymbolKind::Enum
            | SemanticModelSymbolKind::Record
            | SemanticModelSymbolKind::Module
            | SemanticModelSymbolKind::TypeAlias
    )
}

pub(super) fn rank_search_symbol_candidates(
    analyzer: &dyn IAnalyzer,
    patterns: &[String],
    code_units: Vec<(CodeUnit, Range, bool, bool)>,
    cancellation: Option<&crate::CancellationToken>,
) -> (Vec<RankedSearchCandidate>, bool) {
    let mut ranked = Vec::new();
    let mut complete = true;
    for (code_unit, primary_range, is_test, is_type_alias) in code_units {
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            complete = false;
            break;
        }
        ranked.push(RankedSearchCandidate {
            line: primary_range.start_line,
            score: score_search_symbol_candidate(analyzer, patterns, &code_unit, is_test),
            code_unit,
            primary_range,
            is_type_alias,
        });
    }
    ranked.sort_by(compare_ranked_search_candidates);
    (ranked, complete)
}

pub(super) fn score_search_symbol_candidate(
    analyzer: &dyn IAnalyzer,
    patterns: &[String],
    code_unit: &CodeUnit,
    is_test: bool,
) -> SymbolCandidateScore {
    let mut best_match = SymbolMatchScore {
        tier: 0,
        exact_patterns: 0,
    };
    for pattern in patterns {
        let match_score = score_symbol_match(pattern, code_unit);
        if match_score > best_match {
            best_match = match_score;
        }
    }

    SymbolCandidateScore {
        match_score: best_match,
        path_tier: search_symbol_path_tier(patterns, code_unit.source()),
        implementation_tier: search_symbol_implementation_tier(analyzer, code_unit),
        source_quality_tier: search_symbol_source_quality_tier(code_unit.source(), is_test),
        synthetic_tier: u8::from(!code_unit.is_synthetic()),
    }
}

pub(super) fn score_symbol_match(pattern: &str, code_unit: &CodeUnit) -> SymbolMatchScore {
    let normalized = pattern.trim();
    if normalized.is_empty() {
        return SymbolMatchScore {
            tier: 0,
            exact_patterns: 0,
        };
    }

    let pattern_kind = classify_search_pattern(normalized);
    let query = normalized.to_ascii_lowercase();
    let identifier_raw = code_unit.identifier();
    let short_name_raw = code_unit.short_name();
    let fq_name_raw = code_unit.fq_name();
    let identifier = identifier_raw.to_ascii_lowercase();
    let short_name = short_name_raw.to_ascii_lowercase();
    let fq_name = fq_name_raw.to_ascii_lowercase();
    let normalized_short = normalize_symbol_name_for_search(code_unit.short_name());
    let normalized_fq = normalize_symbol_name_for_search(&code_unit.fq_name());

    let tier = match pattern_kind {
        SearchPatternKind::LiteralIdentifier => {
            if query == identifier {
                9
            } else if query == short_name {
                8
            } else if query == fq_name {
                7
            } else if contains_exact_symbol_component(short_name_raw, &query)
                || contains_exact_symbol_component(&fq_name_raw, &query)
            {
                6
            } else if contains_prefix_symbol_component(short_name_raw, &query)
                || contains_prefix_symbol_component(&fq_name_raw, &query)
            {
                5
            } else if short_name.contains(&query) {
                3
            } else if fq_name.contains(&query) {
                2
            } else {
                1
            }
        }
        SearchPatternKind::LiteralQualified => {
            if query == normalized_short || query == normalized_fq {
                9
            } else if normalized_short.starts_with(&query) || normalized_fq.starts_with(&query) {
                7
            } else if normalized_short.contains(&query) || normalized_fq.contains(&query) {
                5
            } else if query == identifier {
                3
            } else if identifier.starts_with(&query) {
                2
            } else {
                1
            }
        }
        SearchPatternKind::RegexLike => {
            if normalized == ".*" {
                1
            } else if short_name.contains(&query)
                || fq_name.contains(&query)
                || identifier.contains(&query)
            {
                2
            } else {
                1
            }
        }
    };

    SymbolMatchScore {
        tier,
        exact_patterns: usize::from(
            (pattern_kind == SearchPatternKind::LiteralIdentifier && query == identifier)
                || (pattern_kind == SearchPatternKind::LiteralQualified
                    && (query == normalized_short || query == normalized_fq)),
        ),
    }
}

pub(super) fn classify_search_pattern(pattern: &str) -> SearchPatternKind {
    if pattern.is_empty()
        || pattern.chars().any(|ch| {
            matches!(
                ch,
                '*' | '?' | '[' | ']' | '(' | ')' | '{' | '}' | '|' | '^' | ' '
            )
        })
    {
        return SearchPatternKind::RegexLike;
    }

    if pattern.contains("::")
        || pattern.contains('.')
        || pattern.contains('/')
        || pattern.contains('\\')
        || pattern.contains('$')
        || pattern.contains('+')
    {
        SearchPatternKind::LiteralQualified
    } else {
        SearchPatternKind::LiteralIdentifier
    }
}

pub(super) fn normalize_symbol_name_for_search(symbol: &str) -> String {
    let mut out = String::with_capacity(symbol.len());
    let mut chars = symbol.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            ':' if chars.peek() == Some(&':') => {
                chars.next();
                out.push('.');
            }
            '/' | '\\' | '$' | '+' => out.push('.'),
            _ => out.push(ch.to_ascii_lowercase()),
        }
    }
    out
}

pub(super) fn contains_exact_symbol_component(haystack: &str, query: &str) -> bool {
    symbol_components(haystack).any(|component| component == query)
}

pub(super) fn contains_prefix_symbol_component(haystack: &str, query: &str) -> bool {
    symbol_components(haystack).any(|component| component.starts_with(query))
}

pub(super) fn symbol_components(haystack: &str) -> impl Iterator<Item = String> + '_ {
    haystack
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|component| !component.is_empty())
        .flat_map(split_camel_case_component)
}

pub(super) fn split_camel_case_component(component: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0;
    let chars: Vec<_> = component.char_indices().collect();
    for window in chars.windows(2) {
        let (_, current) = window[0];
        let (next_index, next) = window[1];
        if current.is_ascii_lowercase() && next.is_ascii_uppercase() {
            parts.push(component[start..next_index].to_ascii_lowercase());
            start = next_index;
        }
    }
    parts.push(component[start..].to_ascii_lowercase());
    parts
}

pub(super) fn search_symbol_source_quality_tier(file: &ProjectFile, is_test: bool) -> u8 {
    if is_generated_like_path(file) {
        return 0;
    }
    if is_test {
        return 1;
    }
    2
}

pub(super) fn search_symbol_path_tier(patterns: &[String], file: &ProjectFile) -> u8 {
    let path = rel_path_string(file).to_ascii_lowercase();
    patterns
        .iter()
        .map(|pattern| pattern.trim())
        .filter(|pattern| !pattern.is_empty())
        .filter(|pattern| classify_search_pattern(pattern) != SearchPatternKind::RegexLike)
        .map(|pattern| pattern.to_ascii_lowercase())
        .map(|query| {
            if path.contains(&query) {
                3
            } else if path
                .split(|ch: char| !ch.is_ascii_alphanumeric())
                .any(|component| !component.is_empty() && component.eq_ignore_ascii_case(&query))
            {
                2
            } else {
                0
            }
        })
        .max()
        .unwrap_or(0)
}

pub(super) fn is_generated_like_path(file: &ProjectFile) -> bool {
    let path = rel_path_string(file).to_ascii_lowercase();
    path.split('/').any(|segment| {
        matches!(
            segment,
            "vendor"
                | "third_party"
                | "third-party"
                | "node_modules"
                | "dist"
                | "build"
                | "target"
                | "out"
                | "gen"
                | "generated"
        )
    })
}

pub(super) fn search_symbol_implementation_tier(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
) -> u8 {
    if language_for_target(code_unit) != Language::Cpp || code_unit.kind() != CodeUnitType::Function
    {
        return 1;
    }

    let signatures = display_signatures(analyzer, code_unit);
    let has_body = signatures
        .iter()
        .any(|signature| signature.ends_with("{...}"));
    let is_source_file = matches!(
        code_unit
            .source()
            .rel_path()
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.to_ascii_lowercase())
            .as_deref(),
        Some("c" | "cc" | "cpp" | "cxx" | "m" | "mm")
    );

    match (has_body, is_source_file) {
        (true, true) => 3,
        (true, false) => 2,
        (false, true) => 1,
        (false, false) => 0,
    }
}

pub(super) fn compare_ranked_search_candidates(
    left: &RankedSearchCandidate,
    right: &RankedSearchCandidate,
) -> Ordering {
    right
        .score
        .cmp(&left.score)
        .then(left.line.cmp(&right.line))
        .then_with(|| {
            left.code_unit
                .identifier()
                .cmp(right.code_unit.identifier())
        })
        .then_with(|| left.code_unit.fq_name().cmp(&right.code_unit.fq_name()))
        .then_with(|| left.code_unit.source().cmp(right.code_unit.source()))
}

pub(super) fn search_symbol_git_tiers(
    analyzer: &dyn IAnalyzer,
    files: &[ProjectFile],
    cancellation: Option<&crate::CancellationToken>,
) -> (
    HashMap<ProjectFile, usize>,
    crate::relevance::HistoryRankingStatus,
) {
    let (ranked, status) =
        most_important_project_files_with_cancellation(analyzer, files, files.len(), cancellation);
    let max_rank = ranked.len();
    (
        ranked
            .into_iter()
            .enumerate()
            .map(|(index, file)| (file, max_rank.saturating_sub(index)))
            .collect(),
        status,
    )
}

pub(super) fn compare_search_symbol_files(
    left_file: &ProjectFile,
    left_candidates: &[RankedSearchCandidate],
    right_file: &ProjectFile,
    right_candidates: &[RankedSearchCandidate],
    git_tiers: &HashMap<ProjectFile, usize>,
) -> Ordering {
    search_symbol_file_ranking_key(left_file, left_candidates, git_tiers)
        .cmp(&search_symbol_file_ranking_key(
            right_file,
            right_candidates,
            git_tiers,
        ))
        .reverse()
        .then_with(|| left_file.cmp(right_file))
}

pub(super) fn search_symbol_file_ranking_key(
    file: &ProjectFile,
    candidates: &[RankedSearchCandidate],
    git_tiers: &HashMap<ProjectFile, usize>,
) -> FileRankingKey {
    let top1 = candidates
        .first()
        .map(|candidate| candidate.score)
        .unwrap_or(SymbolCandidateScore {
            match_score: SymbolMatchScore {
                tier: 0,
                exact_patterns: 0,
            },
            path_tier: 0,
            implementation_tier: 0,
            source_quality_tier: 0,
            synthetic_tier: 0,
        });
    let top2 = candidates
        .get(1)
        .map(|candidate| candidate.score)
        .unwrap_or(top1);
    let top3 = candidates
        .get(2)
        .map(|candidate| candidate.score)
        .unwrap_or(top2);

    let cohesion_tier = if candidates.len() < 2 {
        2
    } else {
        let min_line = candidates
            .iter()
            .take(3)
            .map(|candidate| candidate.line)
            .min()
            .unwrap_or(0);
        let max_line = candidates
            .iter()
            .take(3)
            .map(|candidate| candidate.line)
            .max()
            .unwrap_or(0);
        let span = max_line.saturating_sub(min_line);
        if span <= 120 {
            2
        } else if span <= 400 {
            1
        } else {
            0
        }
    };

    let focus_tier = match candidates.len() {
        0..=4 => 2,
        5..=8 => 1,
        _ => 0,
    };

    FileRankingKey {
        top1,
        cohesion_tier,
        focus_tier,
        top2,
        top3,
        git_tier: git_tiers.get(file).copied().unwrap_or(0),
    }
}

pub(super) fn collect_ranked_kind_names(
    analyzer: &dyn IAnalyzer,
    code_units: &[RankedSearchCandidate],
    kind: CodeUnitType,
    render_context: Option<&DeclarationNameRangeContext>,
    semantic_model_overlay: Option<&crate::analyzer::semantic_model::SemanticModelOverlay>,
) -> Vec<SearchSymbolHit> {
    collect_ranked_names_by(
        analyzer,
        code_units,
        render_context,
        semantic_model_overlay,
        |unit| unit.kind() == kind,
    )
}

pub(super) fn collect_callable_kind_names(
    analyzer: &dyn IAnalyzer,
    code_units: &[RankedSearchCandidate],
    render_context: Option<&DeclarationNameRangeContext>,
    semantic_model_overlay: Option<&crate::analyzer::semantic_model::SemanticModelOverlay>,
) -> Vec<SearchSymbolHit> {
    collect_ranked_names_by(
        analyzer,
        code_units,
        render_context,
        semantic_model_overlay,
        CodeUnit::is_callable,
    )
}

pub(super) fn collect_ranked_names_by(
    analyzer: &dyn IAnalyzer,
    code_units: &[RankedSearchCandidate],
    render_context: Option<&DeclarationNameRangeContext>,
    semantic_model_overlay: Option<&crate::analyzer::semantic_model::SemanticModelOverlay>,
    matches_kind: impl Fn(&CodeUnit) -> bool,
) -> Vec<SearchSymbolHit> {
    let mut hits: Vec<_> = code_units
        .iter()
        .filter(|candidate| matches_kind(&candidate.code_unit))
        .flat_map(|candidate| {
            let semantic_model = semantic_model_overlay.and_then(|overlay| {
                let matched = overlay.symbols_named(&candidate.code_unit.fq_name());
                (matched.disposition
                    == crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique)
                    .then(|| matched.records[0].provenance.clone())
            });
            let is_type_alias = candidate.is_type_alias;
            let signatures = {
                let _scope = profiling::scope(
                    "searchtools::search_symbols.render.collect_hits.display_signatures",
                );
                display_signatures(analyzer, &candidate.code_unit)
            };
            let line = {
                let _scope = profiling::scope(
                    "searchtools::search_symbols.render.collect_hits.declaration_name_range",
                );
                search_symbol_display_range(candidate, render_context).start_line
            };
            signatures
                .into_iter()
                .map(move |signature| SearchSymbolHit {
                    symbol: display_symbol_for_target(&candidate.code_unit),
                    signature,
                    line,
                    is_type_alias,
                    semantic_model: semantic_model.clone(),
                })
        })
        .collect();
    hits.sort_by(|left, right| {
        left.line
            .cmp(&right.line)
            .then_with(|| left.symbol.cmp(&right.symbol))
            .then_with(|| left.signature.cmp(&right.signature))
    });
    hits.dedup_by(|left, right| {
        left.symbol == right.symbol && left.signature == right.signature && left.line == right.line
    });
    hits
}

pub(super) fn load_declaration_name_context(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<DeclarationNameRangeContext> {
    let content = analyzer.project().read_source(file).ok()?;
    Some(DeclarationNameRangeContext::new(file, content))
}

pub(super) fn search_symbol_display_range(
    candidate: &RankedSearchCandidate,
    render_context: Option<&DeclarationNameRangeContext>,
) -> Range {
    let name_range = render_context.and_then(|context| {
        context.name_range_for_declaration(&candidate.code_unit, candidate.primary_range)
    });
    if let Some(mut name_range) = name_range {
        name_range.start_line += 1;
        name_range.end_line += 1;
        return name_range;
    }
    candidate.primary_range
}

pub(super) fn strip_params(symbols: Vec<String>) -> Vec<String> {
    symbols
        .into_iter()
        .map(|symbol| strip_trailing_call_suffix(&symbol))
        .collect()
}
