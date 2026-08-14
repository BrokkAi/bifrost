use super::*;

fn edge_filter_matches(
    filter: &EdgeFilter,
    row: &super::super::reference_edges::ReferenceEdgeRow,
) -> bool {
    (filter.reference_kinds.is_empty()
        || row
            .reference_kind
            .is_some_and(|kind| filter.reference_kinds.contains(&kind)))
        && filter.proof.is_none_or(|proof| row.proof == proof)
        && filter
            .surface
            .is_none_or(|surface| row.included_in(surface))
        && (filter.usage_kinds.is_empty() || filter.usage_kinds.contains(&row.usage_kind))
        && (filter.relations.is_empty() || filter.relations.contains(&row.owner_relation))
        && (filter.site_classes.is_empty() || filter.site_classes.contains(&row.site_class))
}

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
pub(super) fn binding_of_expansions(
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
    let outcome = super::super::lexical_environment::binding_of(
        &result,
        row.effective_spelling(),
        row.range.start_byte,
        Some(row.namespace),
    );
    // The occurrence's identity travels with the answer: a binding-of answer is
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
        BindingOfOutcome::Reached(index) => vec![binding(index, false)],
        BindingOfOutcome::Shadowed { winner, shadowed } => {
            let mut expansions = vec![binding(winner, false)];
            if include_shadowed {
                expansions.extend(shadowed.into_iter().map(|index| binding(index, true)));
            }
            expansions
        }
        BindingOfOutcome::NoBinding => Vec::new(),
        BindingOfOutcome::Incomplete(_) => Vec::new(),
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

/// The exact hierarchy hops each traced member candidate of one reference
/// occurrence was found through.
///
/// One row is one edge the resolver's own member walk took, so a candidate
/// found at depth `n` contributes exactly `n` contiguous rows. A depth-zero
/// candidate contributes none by construction, and a candidate the resolver
/// recorded without member attribution contributes none because nothing about
/// its route is known. Neither absence is a claim, and neither is converted
/// into one here: the mandatory per-occurrence outcome row is
/// `member_selection`'s, not this step's.
pub(super) fn candidate_hierarchy_expansions(
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
    let occurrence = Arc::new(traced_row.clone());
    trace
        .candidates
        .iter()
        .enumerate()
        .flat_map(|(ordinal, candidate)| {
            candidate
                .member
                .as_deref()
                .map(|member| member.route.as_slice())
                .unwrap_or_default()
                .iter()
                .map(move |hop| (ordinal, hop))
        })
        .map(|(ordinal, hop)| {
            pipeline_expansion(PipelineValue::CandidateHop(Box::new(CandidateHopValue {
                occurrence: Arc::clone(&occurrence),
                ordinal,
                hop: Arc::new(hop.clone()),
            })))
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

/// The state events of one seed procedure.
///
/// The file's whole derivation is computed (and memoised) once; this narrows it
/// to the seed procedure and applies the author's filter. The derivation's own
/// completeness is reported *before* the filter runs, so a filter that drops
/// every row still leaves the reason the answer is partial on the response.
pub(super) fn state_event_expansions(
    workspace: &WorkspaceAnalyzer,
    flow_state_cache: &mut FlowStateTraversalCache,
    procedure: &SemanticProcedureValue,
    filter: &StateEventFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let Some((file_state, procedure_index, procedure_id, file)) = seed_derivation(
        workspace,
        flow_state_cache,
        procedure,
        cancellation,
        diagnostics,
    ) else {
        return Vec::new();
    };
    let derivation = &file_state.procedures[procedure_index];
    let mut expansions = Vec::new();
    for event in 0..derivation.events.len() {
        if !flow_state::state_event_filter_matches(filter, derivation.event(event)) {
            continue;
        }
        expansions.push(pipeline_expansion(PipelineValue::StateEvent(Box::new(
            StateEventValue {
                file_state: Arc::clone(&file_state),
                procedure_index,
                event,
                file: file.clone(),
                procedure_id: Arc::clone(&procedure_id),
            },
        ))));
    }
    expansions
}

/// The flow relations of one seed procedure.
pub(super) fn flow_relation_expansions(
    workspace: &WorkspaceAnalyzer,
    flow_state_cache: &mut FlowStateTraversalCache,
    procedure: &SemanticProcedureValue,
    filter: &FlowRelationFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let Some((file_state, procedure_index, procedure_id, file)) = seed_derivation(
        workspace,
        flow_state_cache,
        procedure,
        cancellation,
        diagnostics,
    ) else {
        return Vec::new();
    };
    relation_expansions(
        &file_state,
        procedure_index,
        &procedure_id,
        &file,
        filter,
        None,
    )
}

/// The flow relations incident to one state event: seeded from an event, an
/// author is asking what serves (or is served by) exactly that event, so both
/// ends are matched rather than the read end alone.
pub(super) fn flow_relations_of_event(
    value: &StateEventValue,
    filter: &FlowRelationFilter,
) -> Vec<PipelineExpansion> {
    relation_expansions(
        &value.file_state,
        value.procedure_index,
        &value.procedure_id,
        &value.file,
        filter,
        Some(value.event),
    )
}

fn relation_expansions(
    file_state: &Arc<super::super::flow_state::FileFlowState>,
    procedure_index: usize,
    procedure_id: &Arc<str>,
    file: &ProjectFile,
    filter: &FlowRelationFilter,
    incident_to: Option<usize>,
) -> Vec<PipelineExpansion> {
    let derivation = &file_state.procedures[procedure_index];
    let mut expansions = Vec::new();
    for relation in 0..derivation.relations.len() {
        let row = &derivation.relations[relation];
        if let Some(event) = incident_to
            && row.source_event != event
            && row.target_event != event
        {
            continue;
        }
        if !flow_state::flow_relation_filter_matches(filter, row) {
            continue;
        }
        expansions.push(pipeline_expansion(PipelineValue::FlowRelation(Box::new(
            FlowRelationValue {
                file_state: Arc::clone(file_state),
                procedure_index,
                relation,
                file: file.clone(),
                procedure_id: Arc::clone(procedure_id),
            },
        ))));
    }
    expansions
}

/// Derive one seed procedure's file, locate the seed inside it, and report the
/// derivation's completeness. `None` when the file's derivation produced no
/// procedures at all -- which the reported diagnostics already explain.
fn seed_derivation(
    workspace: &WorkspaceAnalyzer,
    flow_state_cache: &mut FlowStateTraversalCache,
    procedure: &SemanticProcedureValue,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Option<(
    Arc<super::super::flow_state::FileFlowState>,
    usize,
    Arc<str>,
    ProjectFile,
)> {
    let file = procedure.file().clone();
    let language = crate::analyzer::common::language_for_file(&file);
    let file_state = flow_state_cache.for_file(workspace, &file, cancellation);
    flow_state_cache.report_completeness(
        &rel_path_string(&file),
        language,
        &file_state.completeness,
        file_state.generation,
        diagnostics,
    );
    let wanted = procedure.handle.id();
    let procedure_index = file_state
        .procedures
        .iter()
        .position(|derivation| derivation.procedure == wanted)?;
    flow_state_cache.report_completeness(
        &rel_path_string(&file),
        language,
        &file_state.procedures[procedure_index].completeness,
        file_state.procedures[procedure_index].generation,
        diagnostics,
    );
    let procedure_id: Arc<str> = Arc::from(procedure.wire_id());
    Some((file_state, procedure_index, procedure_id, file))
}

/// The bounded rewrite paths one file engages.
///
/// The file's whole derivation is computed (and memoised) once; this applies
/// the author's filter. The derivation's completeness is reported *before* the
/// filter runs, so a filter that drops every row still leaves the reason the
/// answer is partial on the response.
pub(super) fn rewrite_path_expansions(
    analyzer: &dyn IAnalyzer,
    rewrite_path_cache: &mut RewritePathTraversalCache,
    file: &ProjectFile,
    filter: &RewritePathFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let language = crate::analyzer::common::language_for_file(file);
    let file_paths = rewrite_path_cache.for_file(analyzer, file, cancellation);
    rewrite_path_cache.report_completeness(
        &rel_path_string(file),
        language,
        &file_paths.completeness,
        file_paths.generation,
        diagnostics,
    );
    let mut expansions = Vec::new();
    for index in 0..file_paths.paths.len() {
        if !rewrite_paths::rewrite_path_filter_matches(filter, &file_paths.paths[index]) {
            continue;
        }
        expansions.push(pipeline_expansion(PipelineValue::RewritePath(Box::new(
            RewritePathValue {
                file_paths: Arc::clone(&file_paths),
                index,
                file: file.clone(),
            },
        ))));
    }
    expansions
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
        if !edge_filter_matches(filter, row) {
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
