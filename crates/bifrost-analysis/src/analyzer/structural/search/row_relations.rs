use super::*;

/// Expand one file's occurrence rows, optionally restricted to those lexically
/// inside `containing`.
///
/// Containment is a byte-range test against the facts arena's own ranges, not a
/// re-scan of source text: the enclosing node and the occurrence are both arena
/// nodes of the same file.
#[allow(clippy::too_many_arguments)]
/// The pre-order arena interval of one structural match, used to scope
/// `occurrences-in` by AST identity rather than by byte-range comparison.
#[derive(Debug, Clone, Copy)]
pub(super) struct OccurrenceSubtree {
    pub(super) content_identity: ContentIdentity,
    pub(super) root: u32,
    pub(super) subtree_end: u32,
}

impl OccurrenceSubtree {
    fn contains(&self, row: &OccurrenceRow) -> bool {
        assert_eq!(
            row.content_identity, self.content_identity,
            "one query execution sees one revision of a file, so arena node ids are comparable"
        );
        row.node >= self.root && row.node < self.subtree_end
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn occurrence_expansions_for_file(
    analyzer: &dyn IAnalyzer,
    cache: &mut OccurrenceTraversalCache,
    file: &ProjectFile,
    filter: &OccurrenceFilter,
    containing: Option<OccurrenceSubtree>,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    row_exhausted: &mut bool,
) -> Vec<PipelineExpansion> {
    let Some(result) = cache.rows_for_file(analyzer, file, cancellation) else {
        *row_exhausted = true;
        return Vec::new();
    };
    cache.report_completeness(file, &result, filter, diagnostics);
    occurrences::select_rows(&result, filter)
        .filter(|row| containing.is_none_or(|containing| containing.contains(row)))
        .map(|row| {
            pipeline_expansion(PipelineValue::Occurrence(OccurrenceValue {
                row: Arc::new(row.clone()),
            }))
        })
        .collect()
}

/// Every occurrence of one declaration: its own declaration-name row plus every
/// reference-class row anywhere in the workspace whose resolved target is it.
///
/// Candidate files come from the existing budgeted inbound-reference traversal
/// rather than from a fresh workspace scan, so the step inherits the reference
/// layer's budget accounting and its incompleteness diagnostics. The join
/// itself is on resolved `CodeUnit` identity, never on spelling.
#[allow(clippy::too_many_arguments)]
pub(super) fn occurrences_of_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    filter: &OccurrenceFilter,
    indexed: &mut IndexedDeclarations,
    reference_cache: &mut ReferenceTraversalCache,
    occurrence_cache: &mut OccurrenceTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    max_hits: usize,
    cancellation: Option<&CancellationToken>,
    cache_profile: &mut Option<QueryCacheProfile>,
) -> (Vec<PipelineExpansion>, bool) {
    let (reference_expansions, exhausted) = inbound_reference_expansions(
        analyzer,
        declaration,
        &QueryStep::ReferencesOf(ReferenceTraversalFilter::default()),
        &ReferenceTraversalFilter::default(),
        indexed,
        reference_cache,
        budget,
        limits,
        diagnostics,
        max_hits,
        cancellation,
        cache_profile,
    );

    let mut files = BTreeSet::new();
    files.insert(declaration.unit.source().clone());
    for expansion in &reference_expansions {
        if let PipelineValue::ReferenceSite(site) = &expansion.value {
            files.insert(site.file.clone());
        }
    }

    let mut expansions = Vec::new();
    let mut cancelled = false;
    for file in files {
        let declares_here = file == *declaration.unit.source();
        let Some(result) = occurrence_cache.rows_for_file(analyzer, &file, cancellation) else {
            cancelled = true;
            break;
        };
        occurrence_cache.report_completeness(&file, &result, filter, diagnostics);
        for row in occurrences::select_rows(&result, filter) {
            let selected = match &row.target {
                OccurrenceTarget::Resolved(units) => units.contains(&declaration.unit),
                OccurrenceTarget::None => {
                    declares_here
                        && row.class == OccurrenceClass::Declaration
                        && row.range.start_byte >= declaration.range.start_byte
                        && row.range.end_byte <= declaration.range.end_byte
                }
                OccurrenceTarget::Lexical(_) | OccurrenceTarget::Unresolved(_) => false,
            };
            if selected {
                expansions.push(pipeline_expansion(PipelineValue::Occurrence(
                    OccurrenceValue {
                        row: Arc::new(row.clone()),
                    },
                )));
            }
        }
    }
    (expansions, exhausted || cancelled)
}

/// The innermost lexical scope containing one byte position (#1474).
///
/// A position with no containing scope yields no row rather than a synthesized
/// one: every file has a file scope, so an empty answer means the file has no
/// derivable environment at all, which the completeness report already states.
pub(super) fn scope_of_position(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    file: &ProjectFile,
    position_byte: usize,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let result = environment_cache.environment_for(analyzer, file);
    environment_cache.report_completeness(
        file,
        &result,
        environment::SCOPE_QUERY_AXES,
        diagnostics,
    );
    result
        .innermost_scope(position_byte)
        .map(|index| {
            vec![pipeline_expansion(PipelineValue::LexicalScope(
                ScopeValue {
                    file: file.clone(),
                    result: Arc::clone(&result),
                    index,
                },
            ))]
        })
        .unwrap_or_default()
}

/// The binding of an occurrence's name in effect at its exact position.
///
/// `Incomplete` and `NoBinding` both yield zero rows, but only `Incomplete`
/// reports a diagnostic: "no binding of this name is in effect here" is a
/// complete answer (the name resolves to something other than a lexical
/// binding), while "this file's intervals are not stateable" is not.
pub(super) fn reaching_binding_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    row: &OccurrenceRow,
    include_shadowed: bool,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let result = environment_cache.environment_for(analyzer, &row.file);
    environment_cache.report_completeness(
        &row.file,
        &result,
        environment::BINDING_QUERY_AXES,
        diagnostics,
    );
    let outcome = super::super::lexical_environment::reaching_binding(
        &result,
        row.effective_spelling(),
        row.range.start_byte,
        Some(row.namespace),
    );
    // The occurrence's identity travels with the answer: a reaching binding is
    // an answer *about one occurrence*, and a consumer that captured that token
    // joins on this rather than guessing which returned binding is theirs.
    let reached_from = row.ast_id();
    let binding = |index: usize, shadowed: bool| {
        pipeline_expansion(PipelineValue::Binding(BindingValue {
            file: row.file.clone(),
            result: Arc::clone(&result),
            index,
            shadowed,
            reached_from: Some(reached_from.clone()),
        }))
    };
    match outcome {
        ReachingBindingOutcome::Reached(index) => vec![binding(index, false)],
        ReachingBindingOutcome::Shadowed { winner, shadowed } => {
            let mut expansions = vec![binding(winner, false)];
            if include_shadowed {
                expansions.extend(shadowed.into_iter().map(|index| binding(index, true)));
            }
            expansions
        }
        ReachingBindingOutcome::NoBinding => Vec::new(),
        ReachingBindingOutcome::Incomplete(_) => Vec::new(),
    }
}

/// The binder-class occurrence row of one binding's declaring token.
///
/// A binding whose local name is not spelled by a classified token has no
/// occurrence to return; that is the honest answer, and the binding row's
/// absent `ast_id` already says so.
pub(super) fn binding_occurrence_expansions(
    analyzer: &dyn IAnalyzer,
    occurrence_cache: &mut OccurrenceTraversalCache,
    value: &BindingValue,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    row_exhausted: &mut bool,
) -> Vec<PipelineExpansion> {
    let Some(node) = value.row().node else {
        return Vec::new();
    };
    let filter = OccurrenceFilter::default();
    let Some(result) = occurrence_cache.rows_for_file(analyzer, value.file(), cancellation) else {
        *row_exhausted = true;
        return Vec::new();
    };
    occurrence_cache.report_completeness(value.file(), &result, &filter, diagnostics);
    result
        .rows
        .iter()
        .filter(|row| row.node == node && row.class == OccurrenceClass::Binding)
        .map(|row| {
            pipeline_expansion(PipelineValue::Occurrence(OccurrenceValue {
                row: Arc::new(row.clone()),
            }))
        })
        .collect()
}

/// The candidates the resolver considered for one reference occurrence.
///
/// The trace is a second, opt-in derivation of the occurrence's file, so this
/// re-locates the reference row inside the traced result by AST identity --
/// node plus role -- rather than by position.
#[allow(clippy::too_many_arguments)]
pub(super) fn candidate_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    row: &OccurrenceRow,
    filter: &CandidateFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    row_exhausted: &mut bool,
) -> Vec<PipelineExpansion> {
    let Some(traced) = environment_cache.traced_occurrences_for(analyzer, &row.file, cancellation)
    else {
        *row_exhausted = true;
        return Vec::new();
    };
    let Some(traced_row) = traced
        .rows
        .iter()
        .find(|other| other.node == row.node && other.role == row.role)
    else {
        return Vec::new();
    };
    let Some(trace) = &traced_row.candidates else {
        return Vec::new();
    };
    environment_cache.report_trace_completeness(&row.file, trace, filter, diagnostics);
    let occurrence = Arc::new(traced_row.clone());
    trace
        .candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| {
            filter.matches(candidate.tier, candidate.outcome, candidate.boundary)
        })
        .map(|(ordinal, candidate)| {
            pipeline_expansion(PipelineValue::ResolutionCandidate(Box::new(
                CandidateValue {
                    occurrence: Arc::clone(&occurrence),
                    candidate: Arc::new(candidate.clone()),
                    ordinal,
                    completeness: trace.completeness,
                },
            )))
        })
        .collect()
}

/// The mandatory member-selection summary for one occurrence.
///
/// Exactly one row is always produced for the row the traced file can
/// re-locate: a missing candidate trace becomes an `untraced` summary rather
/// than an absent row, so a policy can never mistake a language without trace
/// support for a proven-empty candidate set. Only a file whose traced
/// derivation cannot be produced at all (budget) yields no row, and that is
/// reported through `row_exhausted`.
pub(super) fn member_selection_expansions(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    row: &OccurrenceRow,
    cancellation: Option<&CancellationToken>,
    row_exhausted: &mut bool,
) -> Vec<PipelineExpansion> {
    let Some(traced) = environment_cache.traced_occurrences_for(analyzer, &row.file, cancellation)
    else {
        *row_exhausted = true;
        return Vec::new();
    };
    let traced_row = traced
        .rows
        .iter()
        .find(|other| other.node == row.node && other.role == row.role);
    let occurrence = Arc::new(traced_row.cloned().unwrap_or_else(|| row.clone()));
    let (selected, candidates, completeness) =
        match traced_row.and_then(|row| row.candidates.as_ref()) {
            Some(trace) => (
                trace
                    .candidates
                    .iter()
                    .filter(|row| row.is_selected())
                    .count(),
                trace.candidates.len(),
                Some(trace.completeness),
            ),
            None => (0, 0, None),
        };
    vec![pipeline_expansion(PipelineValue::MemberSelection(
        MemberSelectionValue {
            occurrence,
            selected,
            candidates,
            completeness,
        },
    ))]
}

/// The canonical inverse edges of one declaration, filtered and indexed.
///
/// A row whose target cannot be located as an exact indexed declaration is
/// omitted with an `EdgeDerivationIncomplete` diagnostic rather than silently
/// dropped: the derivation asserted an edge, and losing it without a trace
/// would be the silent gap the domain exists to remove.
pub(super) fn inverse_edge_expansions(
    analyzer: &dyn IAnalyzer,
    edge_cache: &mut EdgeTraversalCache,
    indexed: &mut IndexedDeclarations,
    declaration: &DeclarationValue,
    filter: &EdgeFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let result = edge_cache.inverse_for(analyzer, &declaration.unit, cancellation);
    let language = crate::analyzer::common::language_for_file(declaration.unit.source());
    edge_cache.report_completeness(&declaration.unit.fq_name(), language, &result, diagnostics);
    edge_row_expansions(analyzer, indexed, &result, filter, None, diagnostics)
}

/// The canonical forward edges of one reference occurrence: the file's forward
/// derivation narrowed to rows whose site is that exact AST node.
#[allow(clippy::too_many_arguments)]
pub(super) fn forward_edge_expansions(
    analyzer: &dyn IAnalyzer,
    edge_cache: &mut EdgeTraversalCache,
    indexed: &mut IndexedDeclarations,
    value: &OccurrenceValue,
    filter: &EdgeFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    row_exhausted: &mut bool,
) -> Vec<PipelineExpansion> {
    let row = &value.row;
    let Some(result) = edge_cache.forward_for(analyzer, &row.file, cancellation) else {
        *row_exhausted = true;
        return Vec::new();
    };
    let language = crate::analyzer::common::language_for_file(&row.file);
    edge_cache.report_completeness(&rel_path_string(&row.file), language, &result, diagnostics);
    let site_ast_id = row.ast_id();
    edge_row_expansions(
        analyzer,
        indexed,
        &result,
        filter,
        Some(site_ast_id.as_str()),
        diagnostics,
    )
}

pub(super) fn edge_row_expansions(
    analyzer: &dyn IAnalyzer,
    indexed: &mut IndexedDeclarations,
    result: &super::super::reference_edges::EdgeDerivationResult,
    filter: &EdgeFilter,
    site_ast_id: Option<&str>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let mut expansions = Vec::new();
    let mut omitted = 0usize;
    let mut omitted_language = None;
    for row in &result.edges {
        if let Some(site_ast_id) = site_ast_id
            && row.site.ast_id.as_deref() != Some(site_ast_id)
        {
            continue;
        }
        if !filter.matches(row) {
            continue;
        }
        let Some(target) = indexed.get(analyzer, &row.target) else {
            omitted += 1;
            omitted_language
                .get_or_insert_with(|| crate::analyzer::common::language_for_file(&row.site.file));
            continue;
        };
        let enclosing = row
            .site
            .enclosing
            .as_ref()
            .and_then(|unit| indexed.get(analyzer, unit));
        expansions.push(pipeline_expansion(PipelineValue::ReferenceEdge(Box::new(
            EdgeValue {
                row: Arc::new(row.clone()),
                target,
                enclosing,
            },
        ))));
    }
    if omitted > 0 {
        let language = omitted_language.expect("an omitted edge names its language");
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::EdgeDerivationIncomplete,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "{omitted} derived reference edge{} had no exact indexed target declaration and were omitted",
                if omitted == 1 { "" } else { "s" }
            ),
        });
    }
    expansions
}
