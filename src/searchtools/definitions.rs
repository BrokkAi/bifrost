use super::selectors::*;
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDefinitionByReferenceParams {
    pub references: Vec<DefinitionContextReferenceQuery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionContextReferenceQuery {
    pub symbol: String,
    pub context: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefinitionReferenceSite {
    pub path: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GetDefinitionByReferenceResult {
    pub results: Vec<DefinitionByReferenceLookupResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefinitionByReferenceLookupResult {
    pub query: DefinitionContextReferenceQuery,
    pub status: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub definitions: Vec<DefinitionCandidate>,
    #[serde(default)]
    pub diagnostics: Vec<DefinitionDiagnostic>,
}

pub fn get_definitions_by_reference(
    analyzer: &dyn IAnalyzer,
    params: GetDefinitionByReferenceParams,
) -> GetDefinitionByReferenceResult {
    let _scope = profiling::scope("searchtools::get_definitions_by_reference");

    let mut results = Vec::with_capacity(params.references.len());

    for query in params.references {
        results.push(resolve_definition_context_query(analyzer, query));
    }

    GetDefinitionByReferenceResult { results }
}

pub(super) fn resolve_definition_context_query(
    analyzer: &dyn IAnalyzer,
    query: DefinitionContextReferenceQuery,
) -> DefinitionByReferenceLookupResult {
    let units = match resolve_definition_context_symbol(analyzer, &query.symbol) {
        Ok(units) => units,
        Err(diagnostics) => {
            return DefinitionByReferenceLookupResult {
                query,
                status: "not_found".to_string(),
                definitions: Vec::new(),
                diagnostics,
            };
        }
    };
    if query.context.is_empty() {
        return invalid_context_lookup(query, "empty_context", "context must not be empty");
    }
    if query.target.is_empty() {
        return invalid_context_lookup(query, "empty_target", "target must not be empty");
    }

    let mut requests = Vec::new();
    for unit in units {
        let Some(range) = primary_range(analyzer, &unit) else {
            continue;
        };
        let source = match unit.source().read_to_string() {
            Ok(source) => source,
            Err(err) => {
                return DefinitionByReferenceLookupResult {
                    query,
                    status: "not_found".to_string(),
                    definitions: Vec::new(),
                    diagnostics: vec![DefinitionDiagnostic {
                        kind: "read_failed".to_string(),
                        message: format!("failed to read source file: {err}"),
                    }],
                };
            }
        };
        let Some(symbol_source) = source.get(range.start_byte..range.end_byte) else {
            continue;
        };
        let language = language_for_file(unit.source());
        for (context_offset, context) in symbol_source.match_indices(&query.context) {
            for target_offset in reference_target_match_offsets(context, &query.target, language) {
                let start_byte = range.start_byte + context_offset + target_offset;
                requests.push(
                    crate::analyzer::usages::get_definition::DefinitionLookupRequest {
                        file: unit.source().clone(),
                        line: None,
                        column: None,
                        start_byte: Some(start_byte),
                        end_byte: Some(start_byte + query.target.len()),
                    },
                );
            }
        }
    }

    if requests.is_empty() {
        return invalid_context_lookup(
            query,
            "target_not_found",
            "target was not found inside any exact context match",
        );
    }

    let outcomes =
        crate::analyzer::usages::get_definition::resolve_definition_batch(analyzer, requests);
    collapse_context_outcomes(analyzer, query, outcomes)
}

/// Group a resolved candidate set for the `definitions` (reference) surface the
/// same way the anchored branch and the other symbol tools do: run
/// `distinct_definitions` and report `ambiguous_symbol` when more than one
/// distinct declaration matches. This keeps bare and fully-qualified spellings
/// symmetric with `get_symbol_sources`/`get_summaries` (#1057). The
/// `ambiguous_symbol` message format and the `symbol_not_found` shape are those
/// the MCP property fuzzer's `classify_spelling` already reads; do not change
/// the diagnostic vocabulary here.
pub(super) fn group_definition_context_symbols(
    analyzer: &dyn IAnalyzer,
    symbol: &str,
    units: Vec<CodeUnit>,
) -> Result<Vec<CodeUnit>, Vec<DefinitionDiagnostic>> {
    let groups = distinct_definitions(analyzer, units);
    match groups.as_slice() {
        [(_, _)] => Ok(groups.into_iter().flat_map(|(_, units)| units).collect()),
        [] => Err(vec![DefinitionDiagnostic {
            kind: "symbol_not_found".to_string(),
            message: format!("`{symbol}` does not resolve to a workspace symbol"),
        }]),
        _ => Err(vec![DefinitionDiagnostic {
            kind: "ambiguous_symbol".to_string(),
            message: format!(
                "`{symbol}` is ambiguous; matches: {}",
                groups
                    .into_iter()
                    .map(|(selector, _)| selector)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }]),
    }
}

pub(super) fn resolve_definition_context_symbol(
    analyzer: &dyn IAnalyzer,
    symbol: &str,
) -> Result<Vec<CodeUnit>, Vec<DefinitionDiagnostic>> {
    if symbol.trim().is_empty() {
        return Err(vec![DefinitionDiagnostic {
            kind: "empty_symbol".to_string(),
            message: "symbol must not be empty".to_string(),
        }]);
    }

    // For qualified/multi-segment names keep exact-first resolution so canonical
    // `/`- or `::`-bearing spellings (Go import paths, `fmt::formatter`) are
    // never misrouted, but route the exact result through the shared grouping
    // helper: a fully-qualified twin spelling (same FQN in two files) now
    // reports `ambiguous_symbol` instead of silently returning both twins,
    // while a unique qualified name still returns Ok. A bare name skips the
    // exact short-circuit entirely and falls through to the member-aware fuzzy
    // path, so a top-level namesake can no longer silently win over a same-named
    // member (#1057), mirroring `exact_codeunit_resolution`.
    if !is_bare_symbol_query(analyzer, symbol) {
        let exact = resolve_codeunit_exact(analyzer, symbol);
        if !exact.is_empty() {
            return group_definition_context_symbols(analyzer, symbol, exact);
        }
    }

    let anchored = match split_definition_selector(symbol) {
        DefinitionSelector::FileAnchored { anchor, lookup } => Some((anchor, lookup)),
        DefinitionSelector::Name(_) => {
            match split_path_qualified_definition_selector(analyzer, symbol) {
                Some(PathQualifiedSelector::Resolved { anchor, lookup }) => Some((anchor, lookup)),
                Some(PathQualifiedSelector::AmbiguousPath(item)) => {
                    return Err(vec![DefinitionDiagnostic {
                        kind: "ambiguous_path".to_string(),
                        message: format!(
                            "`{}` is ambiguous; matches: {}",
                            item.input,
                            item.matches.join(", ")
                        ),
                    }]);
                }
                None => None,
            }
        }
    };
    if let Some((anchor, lookup)) = anchored {
        let candidates = match anchor_scoped_codeunit_resolution(analyzer, &anchor, lookup) {
            CodeUnitResolution::Resolved(units) | CodeUnitResolution::Ambiguous(units) => units,
            CodeUnitResolution::NotFound => Vec::new(),
        };
        let narrowed: Vec<_> = candidates
            .into_iter()
            .filter(|unit| rel_path_string(unit.source()) == anchor)
            .collect();
        return group_definition_context_symbols(analyzer, symbol, narrowed);
    }

    match resolve_codeunit_fuzzy(analyzer, symbol) {
        CodeUnitResolution::Resolved(units) | CodeUnitResolution::Ambiguous(units) => {
            group_definition_context_symbols(analyzer, symbol, units)
        }
        CodeUnitResolution::NotFound => Err(vec![DefinitionDiagnostic {
            kind: "symbol_not_found".to_string(),
            message: path_like_symbol_guidance(
                symbol,
                PathLikeSymbolGuidanceContext::DefinitionByReference,
            )
            .unwrap_or_else(|| format!("`{symbol}` does not resolve to a workspace symbol")),
        }]),
    }
}

pub(super) fn invalid_context_lookup(
    query: DefinitionContextReferenceQuery,
    kind: &str,
    message: &str,
) -> DefinitionByReferenceLookupResult {
    DefinitionByReferenceLookupResult {
        query,
        status: "invalid_location".to_string(),
        definitions: Vec::new(),
        diagnostics: vec![DefinitionDiagnostic {
            kind: kind.to_string(),
            message: message.to_string(),
        }],
    }
}

pub(super) fn collapse_context_outcomes(
    analyzer: &dyn IAnalyzer,
    query: DefinitionContextReferenceQuery,
    outcomes: Vec<crate::analyzer::usages::get_definition::DefinitionLookupOutcome>,
) -> DefinitionByReferenceLookupResult {
    let Some(first) = outcomes.first() else {
        return invalid_context_lookup(query, "target_not_found", "no target candidates found");
    };
    let first_key = semantic_outcome_key(analyzer, first);
    if outcomes
        .iter()
        .all(|outcome| semantic_outcome_key(analyzer, outcome) == first_key)
    {
        return render_definition_reference_lookup(analyzer, query, first.clone());
    }

    DefinitionByReferenceLookupResult {
        query,
        status: "ambiguous".to_string(),
        definitions: Vec::new(),
        diagnostics: vec![DefinitionDiagnostic {
            kind: "ambiguous_reference_target".to_string(),
            message: "target appears multiple times in context and resolves to different semantic outcomes"
                .to_string(),
        }],
    }
}

pub(super) fn render_definition_reference_lookup(
    analyzer: &dyn IAnalyzer,
    query: DefinitionContextReferenceQuery,
    outcome: crate::analyzer::usages::get_definition::DefinitionLookupOutcome,
) -> DefinitionByReferenceLookupResult {
    if outcome.lexical_definition.is_some() {
        return DefinitionByReferenceLookupResult {
            query,
            status: "no_definition".to_string(),
            definitions: Vec::new(),
            diagnostics: vec![DefinitionDiagnostic {
                kind: "local_binding_requires_location".to_string(),
                message: "the target resolves to a lexical binding; use get_definitions_by_location with its source position"
                    .to_string(),
            }],
        };
    }
    let diagnostics = outcome
        .diagnostics
        .into_iter()
        .map(|diagnostic| definition_by_reference_diagnostic(&query, diagnostic))
        .collect();
    DefinitionByReferenceLookupResult {
        query,
        status: outcome.status.as_str().to_string(),
        definitions: definition_candidates(analyzer, &outcome.definitions),
        diagnostics,
    }
}

pub(super) fn definition_by_reference_diagnostic(
    query: &DefinitionContextReferenceQuery,
    diagnostic: crate::analyzer::usages::get_definition::DefinitionLookupDiagnostic,
) -> DefinitionDiagnostic {
    let message = match diagnostic.kind.as_str() {
        "invalid_location"
            if diagnostic.message
                == "byte range must identify a single reference token; use start_byte inside the token for qualified expressions" =>
        {
            "target must identify a single reference token; for qualified expressions, set target to the member or name token inside the expression rather than the whole qualified expression"
                .to_string()
        }
        "invalid_location" if diagnostic.message == "provide either start_byte or line/column" => {
            "provide a positive line and, when needed, a positive character column".to_string()
        }
        SCALA_UNSUPPORTED_CALL_TARGET_SHAPE => {
            format!(
                "{}. The reference tool cannot follow this Scala call target shape yet. Try search_symbols for the callable/member name or owner/member selector when known, then use get_symbol_sources on the owner or resolved member symbol.",
                diagnostic.message
            )
        }
        SCALA_UNSUPPORTED_RECEIVER => {
            let target = query.target.trim();
            format!(
                "{}. The reference tool cannot follow this Scala receiver/member shape yet. Try search_symbols for `{target}` or an owner/member selector when known, then use get_symbol_sources on the owner or resolved member symbol.",
                diagnostic.message
            )
        }
        _ => external_location_diagnostic_message(&diagnostic.kind, diagnostic.message),
    };
    DefinitionDiagnostic {
        kind: diagnostic.kind,
        message,
    }
}

pub(super) fn semantic_outcome_key(
    analyzer: &dyn IAnalyzer,
    outcome: &crate::analyzer::usages::get_definition::DefinitionLookupOutcome,
) -> DefinitionOutcomeKey {
    let definition = outcome
        .definitions
        .iter()
        .filter_map(|unit| definition_candidate(analyzer, unit))
        .map(|candidate| definition_candidate_key(&candidate))
        .collect();
    (outcome.status.as_str().to_string(), definition)
}
