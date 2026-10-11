use super::results::CodeQueryBindingInitializerCall;
use super::*;
use crate::analyzer::structural::OccurrenceFileResult;

fn traced_occurrences_for_row(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    row: &OccurrenceRow,
    cancellation: Option<&CancellationToken>,
    row_exhausted: &mut bool,
) -> Option<Arc<OccurrenceFileResult>> {
    let traced = environment_cache.traced_occurrences_for(analyzer, &row.file, cancellation);
    if traced.is_none() {
        *row_exhausted = true;
    }
    traced
}

fn traced_occurrence_row<'a>(
    traced: &'a OccurrenceFileResult,
    row: &OccurrenceRow,
) -> Option<&'a OccurrenceRow> {
    traced
        .rows
        .iter()
        .find(|other| other.node == row.node && other.role == row.role)
}

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
    let Some(result) = cache.rows_for_file(analyzer, file, filter, cancellation) else {
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

/// Expand occurrences whose exact innermost lexical scope is `scope`.
///
/// Scope membership is answered by the same per-file environment result that
/// produced the scope row; nested scopes are not treated as part of their
/// parent's direct membership.
#[allow(clippy::too_many_arguments)]
pub(super) fn occurrence_expansions_in_scope(
    analyzer: &dyn IAnalyzer,
    cache: &mut OccurrenceTraversalCache,
    scope: &ScopeValue,
    filter: &OccurrenceFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    row_exhausted: &mut bool,
) -> Vec<PipelineExpansion> {
    let Some(result) = cache.rows_for_file(analyzer, &scope.file, filter, cancellation) else {
        *row_exhausted = true;
        return Vec::new();
    };
    cache.report_completeness(&scope.file, &result, filter, diagnostics);
    occurrences::select_rows(&result, filter)
        .filter(|row| scope.result.innermost_scope(row.range.start_byte) == Some(scope.index))
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
        let Some(result) = occurrence_cache.rows_for_file(analyzer, &file, filter, cancellation)
        else {
            cancelled = true;
            break;
        };
        occurrence_cache.report_completeness(&file, &result, filter, diagnostics);
        let mut selected_rows = occurrences::select_rows(&result, filter)
            .cloned()
            .collect::<Vec<_>>();
        if !occurrence_cache.resolve_targets_for_rows(
            analyzer,
            &file,
            &mut selected_rows,
            cancellation,
        ) {
            cancelled = true;
            break;
        }
        for row in &selected_rows {
            let selected = match &row.target {
                OccurrenceTarget::Resolved(units) => units.contains(&declaration.unit),
                OccurrenceTarget::None => {
                    declares_here
                        && row.class == OccurrenceClass::Declaration
                        && row.range.start_byte >= declaration.range.start_byte
                        && row.range.end_byte <= declaration.range.end_byte
                }
                OccurrenceTarget::Lexical(_) | OccurrenceTarget::Unresolved(_) => false,
                // Same reasoning as the occurrence-target step: this relation
                // is a question about resolution, so a plan reaching it must
                // have asked for it.
                OccurrenceTarget::NotDerived => {
                    debug_assert!(false, "occurrences-of requires derived targets");
                    false
                }
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
    let mut binding = |index: usize, shadowed: bool| {
        environment_cache.record_joined_scope(&row.file, result.bindings[index].declaring_scope);
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

/// Resolve the lexical binding identity of one exact call argument. This is
/// deliberately a query-local join over the existing occurrence and lexical
/// environment facts; the call-binding producer does not infer identity from
/// a spelling or a rendered range.
#[allow(clippy::too_many_arguments)]
pub(super) fn binding_identity_for_range(
    analyzer: &dyn IAnalyzer,
    occurrence_cache: &mut OccurrenceTraversalCache,
    environment_cache: &mut EnvironmentTraversalCache,
    file: &ProjectFile,
    facts: &FileFacts,
    range: Range,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Option<String> {
    let filter = OccurrenceFilter {
        classes: vec![OccurrenceClass::Reference],
        roles: vec![
            OccurrenceRole::TypeOperand,
            OccurrenceRole::PathSegment,
            OccurrenceRole::ReceiverPosition,
            OccurrenceRole::ValueReference,
        ],
        ..OccurrenceFilter::default()
    };
    let result = occurrence_cache.rows_for_file(analyzer, file, &filter, cancellation)?;
    occurrence_cache.report_completeness(file, &result, &filter, diagnostics);
    let identity_for = |start_byte: usize,
                        end_byte: usize,
                        environment_cache: &mut EnvironmentTraversalCache,
                        diagnostics: &mut Vec<CodeQueryDiagnostic>| {
        let identities = result
            .rows
            .iter()
            .filter(|row| row.range.start_byte == start_byte && row.range.end_byte == end_byte)
            .flat_map(|row| {
                binding_of_expansions(analyzer, environment_cache, row, false, diagnostics)
            })
            .map(|expansion| match expansion.value {
                PipelineValue::Binding(binding) => binding.id(),
                _ => unreachable!("binding_of emits binding rows"),
            })
            .collect::<HashSet<_>>();
        (identities.len() == 1).then(|| identities.into_iter().next().unwrap())
    };
    let mut identities = HashSet::default();
    identities.extend(
        result
            .rows
            .iter()
            .filter(|row| row.range == range)
            .flat_map(|row| {
                binding_of_expansions(analyzer, environment_cache, row, false, diagnostics)
            })
            .map(|expansion| match expansion.value {
                PipelineValue::Binding(binding) => binding.id(),
                _ => unreachable!("binding_of emits binding rows"),
            }),
    );
    let identity = (identities.len() == 1).then(|| identities.into_iter().next().unwrap())?;

    let reassigned = facts
        .nodes()
        .iter()
        .enumerate()
        .filter(|(node_id, node)| {
            node.kind == NormalizedKind::Assignment
                && facts
                    .role_targets(*node_id as u32, Role::Operator)
                    .next()
                    .is_some()
        })
        .flat_map(|(node_id, _)| facts.role_targets(node_id as u32, Role::Left))
        .map(|target| target.span)
        .filter_map(|target_range| {
            identity_for(
                target_range.start_byte,
                target_range.end_byte,
                environment_cache,
                diagnostics,
            )
        })
        .any(|target_identity| target_identity == identity);
    if reassigned {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::OccurrenceResolutionIncomplete,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: crate::analyzer::common::language_for_file(file).config_label(),
            message: format!(
                "{} lexical path binding has an assignment write in its file; same-path identity is incomplete",
                super::rel_path_string(file)
            ),
            exhausted_roots: Vec::new(),
        });
        return None;
    }
    Some(identity)
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
    let filter = OccurrenceFilter {
        classes: vec![OccurrenceClass::Binding],
        ..OccurrenceFilter::default()
    };
    let Some(result) =
        occurrence_cache.rows_for_file(analyzer, value.file(), &filter, cancellation)
    else {
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

/// Reference occurrences whose exact lexical binding is `value`.
///
/// The relation is a query-local join over classified occurrences and
/// `binding-of`; it retains no workspace-sized reverse index. Member names and
/// import targets are excluded because their spelling does not name a lexical
/// value binding.
#[allow(clippy::too_many_arguments)]
pub(super) fn binding_uses_expansions(
    analyzer: &dyn IAnalyzer,
    occurrence_cache: &mut OccurrenceTraversalCache,
    environment_cache: &mut EnvironmentTraversalCache,
    value: &BindingValue,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    row_exhausted: &mut bool,
) -> Vec<PipelineExpansion> {
    let filter = OccurrenceFilter {
        classes: vec![OccurrenceClass::Reference],
        roles: vec![
            OccurrenceRole::TypeOperand,
            OccurrenceRole::PathSegment,
            OccurrenceRole::ReceiverPosition,
            OccurrenceRole::ValueReference,
        ],
        ..OccurrenceFilter::default()
    };
    let Some(result) =
        occurrence_cache.rows_for_file(analyzer, value.file(), &filter, cancellation)
    else {
        *row_exhausted = true;
        return Vec::new();
    };
    occurrence_cache.report_completeness(value.file(), &result, &filter, diagnostics);
    environment_cache.report_completeness(
        value.file(),
        &value.result,
        environment::BINDING_QUERY_AXES,
        diagnostics,
    );
    let binding_scope = value.result.scope(value.row().declaring_scope);
    let dynamic_calls = environment_cache.python_dynamic_scope_calls(analyzer, value.file());
    let contains_dynamic_call = dynamic_calls.iter().any(|call| {
        binding_scope.range.start_byte <= call.start_byte
            && call.end_byte <= binding_scope.range.end_byte
    });
    let mut unresolved_candidates = result
        .rows
        .iter()
        .filter(|occurrence| {
            binding_scope.contains(occurrence.range.start_byte)
                && matches!(
                    super::super::lexical_environment::binding_of(
                        &value.result,
                        occurrence.effective_spelling(),
                        occurrence.range.start_byte,
                        Some(occurrence.namespace),
                    ),
                    super::super::lexical_environment::BindingOfOutcome::NoBinding
                )
        })
        .cloned()
        .collect::<Vec<_>>();
    if !occurrence_cache.resolve_targets_for_rows(
        analyzer,
        value.file(),
        &mut unresolved_candidates,
        cancellation,
    ) {
        *row_exhausted = true;
        return Vec::new();
    }
    let contains_unresolved_reference = unresolved_candidates
        .iter()
        .any(|occurrence| matches!(&occurrence.target, OccurrenceTarget::Unresolved(_)));
    let scope_complete = environment::BINDING_QUERY_AXES
        .iter()
        .all(|axis| value.result.completeness.covers(*axis))
        && filter
            .required_roles()
            .iter()
            .all(|role| result.completeness.covers(*role))
        && !contains_dynamic_call
        && !contains_unresolved_reference;
    environment_cache.record_binding_use_completeness(value, scope_complete);
    if contains_dynamic_call || contains_unresolved_reference {
        let message = format!(
            "{} lexical scope {} has unresolved or dynamic references; binding uses are incomplete",
            super::rel_path_string(value.file()),
            binding_scope.index
        );
        if !diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::OccurrenceResolutionIncomplete
                && diagnostic.message == message
        }) {
            diagnostics.push(CodeQueryDiagnostic {
                code: CodeQueryDiagnosticCode::OccurrenceResolutionIncomplete,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: crate::analyzer::common::language_for_file(value.file()).config_label(),
                message,
                exhausted_roots: Vec::new(),
            });
        }
    }
    let binding_id = value.id();
    result
        .rows
        .iter()
        .filter(|occurrence| {
            binding_of_expansions(analyzer, environment_cache, occurrence, false, diagnostics)
                .into_iter()
                .any(|expansion| match expansion.value {
                    PipelineValue::Binding(binding) => binding.id() == binding_id,
                    _ => false,
                })
        })
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
    let Some(traced) = traced_occurrences_for_row(
        analyzer,
        environment_cache,
        row,
        cancellation,
        row_exhausted,
    ) else {
        return Vec::new();
    };
    let Some(traced_row) = traced_occurrence_row(&traced, row) else {
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
    let Some(traced) = traced_occurrences_for_row(
        analyzer,
        environment_cache,
        row,
        cancellation,
        row_exhausted,
    ) else {
        return Vec::new();
    };
    let Some(traced_row) = traced_occurrence_row(&traced, row) else {
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
    edge_cache.report_inverse_completeness(&declaration.unit, language, &result, diagnostics);
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
        flow_state::STATE_EVENT_AXES,
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
                procedure: procedure.handle.clone(),
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
        flow_state::FLOW_RELATION_AXES,
        cancellation,
        diagnostics,
    ) else {
        return Vec::new();
    };
    relation_expansions(
        &file_state,
        procedure_index,
        &procedure_id,
        &procedure.handle,
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
        &value.procedure,
        &value.file,
        filter,
        Some(value.event),
    )
}

fn relation_expansions(
    file_state: &Arc<super::super::flow_state::FileFlowState>,
    procedure_index: usize,
    procedure_id: &Arc<str>,
    procedure: &crate::analyzer::semantic::ProcedureHandle,
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
                procedure: procedure.clone(),
            },
        ))));
    }
    expansions
}

/// Relate one Rust binding establishment to the exact call sites in its
/// initializer result/receiver chain. The stable call AST identity is shared
/// with call-effect and dispatch-target rows.
pub(super) fn binding_initializer_call_expansions(
    workspace: &WorkspaceAnalyzer,
    event: &StateEventValue,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let state = event.row();
    if state.event_class
        != brokk_bifrost_core::analyzer::structural::flow_state::StateEventClass::Establish
        || !matches!(
            &state.subject,
            crate::structural::flow_state::FlowSubject::Binding { .. }
        )
    {
        return Vec::new();
    }

    let file = &event.file;
    let language = crate::analyzer::common::language_for_file(file);
    if language != Language::Rust {
        binding_initializer_incomplete(
            diagnostics,
            file,
            language.config_label(),
            "only Rust binding initializers have an exact structured result/receiver relation",
        );
        return Vec::new();
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        binding_initializer_incomplete(
            diagnostics,
            file,
            language.config_label(),
            "initializer projection was cancelled",
        );
        return Vec::new();
    }

    let Some(facts) = workspace
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Rust)
        .and_then(|provider| provider.structural_facts(file))
    else {
        binding_initializer_incomplete(
            diagnostics,
            file,
            language.config_label(),
            "Rust structural facts for the establishing event are unavailable",
        );
        return Vec::new();
    };

    let Some(event_ast_id) = state.site.ast_id.as_deref() else {
        binding_initializer_incomplete(
            diagnostics,
            file,
            language.config_label(),
            "establishing event has no exact structural AST identity",
        );
        return Vec::new();
    };
    let matching_nodes = (0..facts.nodes().len())
        .map(|node| node as u32)
        .filter(|node| {
            crate::analyzer::structural::occurrence_rows::ast_id(facts.source_identity(), *node)
                == event_ast_id
        })
        .collect::<Vec<_>>();
    let [establishment_node] = matching_nodes.as_slice() else {
        binding_initializer_incomplete(
            diagnostics,
            file,
            language.config_label(),
            &format!(
                "establishing AST identity matched {} structural nodes",
                matching_nodes.len()
            ),
        );
        return Vec::new();
    };
    if facts.node(*establishment_node).kind
        != brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind::Assignment
    {
        // Parameters and other non-assignment establishments have no
        // initializer call site to relate.
        return Vec::new();
    }
    let right_nodes = facts
        .role_targets(
            *establishment_node,
            brokk_bifrost_core::analyzer::structural::kinds::Role::Right,
        )
        .filter_map(|target| target.node)
        .collect::<Vec<_>>();
    let [right_node] = right_nodes.as_slice() else {
        if right_nodes.is_empty() {
            // A declaration without an initializer has no call result to link.
            return Vec::new();
        }
        binding_initializer_incomplete(
            diagnostics,
            file,
            language.config_label(),
            &format!(
                "binding assignment has {} structured right-hand sides",
                right_nodes.len()
            ),
        );
        return Vec::new();
    };
    if facts.node(*right_node).kind
        != brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind::Call
    {
        return Vec::new();
    }

    let semantics = event.procedure.semantics();
    let mut calls_by_span = crate::hash::HashMap::<
        (usize, usize),
        Vec<&crate::analyzer::semantic::SemanticCallSite>,
    >::default();
    for call in semantics.call_sites() {
        let Some(mapping) = semantics.source_mapping(call.source) else {
            continue;
        };
        if mapping.kind == crate::analyzer::semantic::SourceMappingKind::Exact {
            let span = mapping.locator.anchor().span();
            calls_by_span
                .entry((span.start_byte() as usize, span.end_byte() as usize))
                .or_default()
                .push(call);
        }
    }

    let mut initializer_calls = Vec::new();
    let mut current_node = *right_node;
    let mut current_call =
        match exact_initializer_call(&facts, current_node, &calls_by_span, state.value, None) {
            Ok(call) => call,
            Err(reason) => {
                binding_initializer_incomplete(diagnostics, file, language.config_label(), reason);
                return Vec::new();
            }
        };
    initializer_calls.push((current_node, current_call, "result"));

    loop {
        let receivers = facts
            .role_targets(
                current_node,
                brokk_bifrost_core::analyzer::structural::kinds::Role::Receiver,
            )
            .filter_map(|target| target.node)
            .filter(|node| {
                facts.node(*node).kind
                    == brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind::Call
            })
            .collect::<Vec<_>>();
        let receiver_node = match receivers.as_slice() {
            [] => break,
            [node] => *node,
            _ => {
                binding_initializer_incomplete(
                    diagnostics,
                    file,
                    language.config_label(),
                    &format!(
                        "initializer call has {} call-valued receiver roles",
                        receivers.len()
                    ),
                );
                return Vec::new();
            }
        };
        let receiver_value = current_call.receiver;
        let next_call = match exact_initializer_call(
            &facts,
            receiver_node,
            &calls_by_span,
            receiver_value.unwrap_or(state.value),
            receiver_value,
        ) {
            Ok(call) => call,
            Err(reason) => {
                binding_initializer_incomplete(diagnostics, file, language.config_label(), reason);
                return Vec::new();
            }
        };
        current_node = receiver_node;
        current_call = next_call;
        initializer_calls.push((current_node, current_call, "receiver"));
    }

    let establishment_event_id = event.id();
    let path = rel_path_string(file);
    initializer_calls
        .into_iter()
        .map(|(node, _call, initializer_role)| {
            let site_ast_id =
                crate::analyzer::structural::occurrence_rows::ast_id(facts.source_identity(), node);
            let range = facts.node(node).range;
            let row = CodeQueryBindingInitializerCall {
                id: binding_initializer_call_id(
                    &establishment_event_id,
                    &site_ast_id,
                    initializer_role,
                ),
                establishment_event_id: establishment_event_id.clone(),
                site_ast_id,
                initializer_role,
                path: path.clone(),
                language: language.config_label(),
                range: super::render::public_range(&facts, range),
                start_byte: range.start_byte,
                end_byte: range.end_byte,
            };
            pipeline_expansion(PipelineValue::BindingInitializerCall(Box::new(
                BindingInitializerCallValue {
                    row,
                    file: file.clone(),
                },
            )))
        })
        .collect()
}

fn exact_initializer_call<'a>(
    facts: &crate::analyzer::structural::FileFacts,
    node: u32,
    calls_by_span: &crate::hash::HashMap<
        (usize, usize),
        Vec<&'a crate::analyzer::semantic::SemanticCallSite>,
    >,
    expected_result: crate::analyzer::semantic::ValueId,
    receiver_result: Option<crate::analyzer::semantic::ValueId>,
) -> Result<&'a crate::analyzer::semantic::SemanticCallSite, &'static str> {
    let range = facts.node(node).range;
    let span = (range.start_byte, range.end_byte);
    let candidates = calls_by_span
        .get(&span)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let [call] = candidates else {
        return Err("initializer call AST identity has no unique exact semantic call site");
    };
    if let Some(receiver_result) = receiver_result {
        if !call
            .normal_result_values()
            .any(|value| value == receiver_result)
        {
            return Err(
                "receiver call result does not match the consuming call's semantic receiver",
            );
        }
    } else if !call
        .normal_result_values()
        .any(|value| value == expected_result)
    {
        return Err("initializer call result does not match the binding establishment value");
    }
    Ok(*call)
}

fn binding_initializer_call_id(
    establishment_event_id: &str,
    site_ast_id: &str,
    initializer_role: &str,
) -> String {
    let mut digest = crate::analyzer::semantic::LengthDelimitedDigest::new(
        b"bifrost.code_query.binding_initializer_call.v1",
    );
    digest.push(establishment_event_id.as_bytes());
    digest.push(site_ast_id.as_bytes());
    digest.push(initializer_role.as_bytes());
    digest.finish().to_string()
}

fn binding_initializer_incomplete(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    file: &ProjectFile,
    language: &'static str,
    reason: &str,
) {
    let message = format!("binding_initializer_calls_of: {reason}");
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::SemanticAnalysisPartial
            && diagnostic.language == language
            && diagnostic.message == message
    }) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language,
        message: format!("{}: {message}", rel_path_string(file)),
        exhausted_roots: Vec::new(),
    });
}

/// Derive one seed procedure's file, locate the seed inside it, and report the
/// derivation's completeness. `None` when the file's derivation produced no
/// procedures at all -- which the reported diagnostics already explain.
pub(super) fn seed_derivation(
    workspace: &WorkspaceAnalyzer,
    flow_state_cache: &mut FlowStateTraversalCache,
    procedure: &SemanticProcedureValue,
    axes: &[brokk_bifrost_core::analyzer::structural::flow_state::FlowStateAxis],
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
        axes,
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
        axes,
        file_state.procedures[procedure_index].generation,
        diagnostics,
    );
    let procedure_id: Arc<str> = Arc::from(procedure.wire_id());
    Some((file_state, procedure_index, procedure_id, file))
}

/// The control relations of one seed procedure.
///
/// The procedure's whole derivation runs (and is memoised) once; this applies
/// the author's filter. The derivation's completeness is reported *before* the
/// filter runs, so a `:relation postdominates` filter that drops every row
/// still leaves the reason the answer is partial on the response.
pub(super) fn control_relation_expansions(
    control_relation_cache: &mut ControlRelationTraversalCache,
    procedure: &SemanticProcedureValue,
    generation: u64,
    filter: &ControlRelationFilter,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let file = procedure.file().clone();
    let language = crate::analyzer::common::language_for_file(&file);
    let relations = control_relation_cache.for_procedure(procedure, generation, cancellation);
    control_relation_cache.report_completeness(
        &procedure.wire_id(),
        language,
        &relations,
        diagnostics,
    );
    let mut expansions = Vec::new();
    for index in 0..relations.rows.len() {
        if !control_relations::control_relation_filter_matches(filter, &relations.rows[index]) {
            continue;
        }
        expansions.push(pipeline_expansion(PipelineValue::ControlRelation(
            Box::new(ControlRelationValue {
                relations: Arc::clone(&relations),
                index,
                procedure: procedure.clone(),
            }),
        )));
    }
    expansions
}

/// The guard facts one seed procedure's lowerer recorded (#2443 slice 2).
///
/// Nothing is derived and nothing is filtered: the rows are already in the
/// artifact, so this reads them in the dense order the lowerer minted them. An
/// empty answer is not a diagnostic either -- the procedure's adapter states
/// whether it publishes guard facts at all through its `guard_facts`
/// capability, which is a stronger and cheaper answer than a per-query reason.
pub(super) fn guard_expansions(procedure: &SemanticProcedureValue) -> Vec<PipelineExpansion> {
    guards::guards_of_procedure(procedure)
        .into_iter()
        .map(|guard| pipeline_expansion(PipelineValue::Guard(Box::new(guard))))
        .collect()
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

/// The build target one file compiles into (#2448).
///
/// The workspace's topology is read (and memoised) once per query; this
/// projects the ownership relation for one file. The derivation's own
/// incompleteness is reported before any row is emitted, so a step that returns
/// nothing still leaves the reason on the response.
pub(super) fn build_target_expansions(
    topology_cache: &mut TopologyTraversalCache,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    topology_rows::build_targets_of_file(topology_cache, analyzer, file, diagnostics)
        .into_iter()
        .map(|value| pipeline_expansion(PipelineValue::BuildTarget(Box::new(value))))
        .collect()
}

/// The declared source set one file belongs to (#2448).
pub(super) fn source_set_expansions(
    topology_cache: &mut TopologyTraversalCache,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    topology_rows::source_sets_of_file(topology_cache, analyzer, file, diagnostics)
        .into_iter()
        .map(|value| pipeline_expansion(PipelineValue::SourceSet(Box::new(value))))
        .collect()
}

/// The dependencies one build target declares on other targets of the same
/// workspace (#2448).
pub(super) fn topology_edge_expansions(
    topology_cache: &mut TopologyTraversalCache,
    target: &TopologyEntityValue,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    topology_rows::topology_edges_of_target(topology_cache, target, diagnostics)
        .into_iter()
        .map(|value| pipeline_expansion(PipelineValue::TopologyEdge(Box::new(value))))
        .collect()
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
        exhausted_roots: Vec::new(),
        });
    }
    expansions
}
