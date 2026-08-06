use super::*;

pub(super) fn analyze_rql(source: &str) -> Analysis {
    let mut analysis = Analysis::default();
    let parsed = match parse_query_sexp(source) {
        Ok(parsed) => parsed,
        Err(error) => {
            analysis.error(error.range, "invalid-syntax", error.message);
            return analysis;
        }
    };
    let Some(expr) = parsed.expr else {
        return analysis;
    };

    let mut plan_budget = SourcePlanBudget::default();
    validate_rql_query(&expr, "", &mut analysis, 0, &mut plan_budget);
    if parsed.incomplete.is_some() || analysis.incomplete {
        analysis.diagnostics.clear();
    } else if analysis.diagnostics.is_empty() {
        match query_to_json(&expr) {
            Ok(json) => {
                if let Err(error) = CodeQuery::from_json(&json) {
                    analysis.semantic_error(error, expr.range.clone());
                }
            }
            Err(error) => analysis.error(error.range, "invalid-query", error.message),
        }
    }
    analysis
}

fn list_head(expr: &Expr) -> Option<(&str, Range<usize>, &[Expr])> {
    let ExprKind::List(items) = &expr.kind else {
        return None;
    };
    let first = items.first()?;
    let ExprKind::Symbol(label) = &first.kind else {
        return None;
    };
    Some((label, first.range.clone(), &items[1..]))
}

fn rql_query_child_path(path: &str, field: &str) -> String {
    if path.is_empty() {
        field.to_string()
    } else {
        format!("{path}.{field}")
    }
}

fn rql_query_index_path(path: &str, index: usize) -> String {
    format!("{path}[{index}]")
}

pub(super) fn validate_rql_query(
    expr: &Expr,
    path: &str,
    analysis: &mut Analysis,
    depth: usize,
    plan_budget: &mut SourcePlanBudget,
) {
    if !path.is_empty() {
        analysis.path(path, expr.range.clone());
    }
    let Some((head, head_range, args)) = list_head(expr) else {
        analysis.error(
            expr.range.clone(),
            "wrong-value-shape",
            "query must be an RQL list",
        );
        return;
    };
    if let Some(form) = RqlForm::from_label(head)
        && form.class() == RqlFormClass::Wrapper
    {
        if matches!(form, RqlForm::Union | RqlForm::Intersect | RqlForm::Except)
            && !plan_budget.enter(depth, expr.range.clone(), analysis)
        {
            return;
        }
        analysis.add_help(head_range.clone(), form.signature(), form.description());
        validate_wrapper(form, args, &head_range, path, analysis, depth, plan_budget);
    } else if NormalizedKind::from_label(head).is_none() && RqlForm::from_label(head).is_none() {
        if !plan_budget.enter(depth, expr.range.clone(), analysis) {
            return;
        }
        add_spelling_error(
            analysis,
            head_range,
            "unknown-form",
            format!("unknown RQL form '{head}'"),
            head,
            rql_query_head_candidates(),
            |suggestion| suggestion.to_string(),
        );
    } else {
        if !plan_budget.enter(depth, expr.range.clone(), analysis) {
            return;
        }
        let match_path = rql_query_child_path(path, "match");
        validate_rql_pattern(expr, &match_path, analysis);
        if rql_pattern_anchors_root(expr) == Some(false) {
            analysis.error(
                expr.range.clone(),
                "invalid-query",
                "root pattern must constrain at least one of kind, name, or text",
            );
        }
    }
}

fn rql_pattern_anchors_root(expr: &Expr) -> Option<bool> {
    let (head, _, _) = list_head(expr)?;
    if NormalizedKind::from_label(head).is_some() {
        return Some(true);
    }
    let form = RqlForm::from_label(head)?;
    if form.class() != RqlFormClass::Predicate {
        return None;
    }
    Some(matches!(
        form.property(),
        Some(RqlProperty::Name | RqlProperty::NameRegex | RqlProperty::TextRegex)
    ))
}

fn validate_wrapper(
    form: RqlForm,
    args: &[Expr],
    head_range: &Range<usize>,
    path: &str,
    analysis: &mut Analysis,
    depth: usize,
    plan_budget: &mut SourcePlanBudget,
) {
    if matches!(form, RqlForm::Explain | RqlForm::Profile) {
        let mode_path = rql_query_child_path(path, "execution_mode");
        analysis.path(&mode_path, head_range.clone());
        if !path.is_empty() {
            analysis.error(
                head_range.clone(),
                "invalid-query",
                "execution mode is allowed only on the root query",
            );
        }
        if args.len() != 1 {
            analysis.error(
                head_range.clone(),
                "wrong-value-shape",
                format!("{} expects one query", form.label()),
            );
        }
    }
    // `occurrences` is a source, not a wrapper around another query: every
    // argument is a filter option and there is no nested query to recurse into.
    if form == RqlForm::Occurrences {
        analysis.path(
            rql_query_child_path(path, "occurrences"),
            head_range.clone(),
        );
        validate_occurrence_options(form, args, analysis);
        return;
    }
    // `scopes` and `bindings` are sources for the same reason, so their whole
    // argument list is a filter block rather than a wrapped query.
    if matches!(
        form,
        RqlForm::Scopes | RqlForm::Bindings | RqlForm::GenerationSites | RqlForm::Exports
    ) {
        let (label, kind) = match form {
            RqlForm::Scopes => ("scopes", EnvironmentOptionKind::Scope),
            RqlForm::Bindings => ("bindings", EnvironmentOptionKind::Binding),
            RqlForm::GenerationSites => ("generation_sites", EnvironmentOptionKind::GenerationSite),
            _ => ("exports", EnvironmentOptionKind::Export),
        };
        analysis.path(rql_query_child_path(path, label), head_range.clone());
        validate_environment_options(form, args, kind, analysis);
        return;
    }
    // `paths` is a source too: its whole argument list is a filter block.
    if form == RqlForm::Paths {
        analysis.path(rql_query_child_path(path, "paths"), head_range.clone());
        validate_path_source_options(args, analysis);
        return;
    }
    let Some(query) = args.last() else {
        return;
    };
    match form {
        RqlForm::Where => {
            let values = &args[..args.len().saturating_sub(1)];
            if values.is_empty() {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    "where expects at least one glob and a query",
                );
            } else if values.len() > MAX_WHERE_GLOBS {
                analysis.error(
                    values[MAX_WHERE_GLOBS].range.clone(),
                    "invalid-query",
                    format!("at most {MAX_WHERE_GLOBS} globs are allowed"),
                );
            }
            let where_path = rql_query_child_path(path, "where");
            for (index, arg) in values.iter().enumerate() {
                let child = rql_query_index_path(&where_path, index);
                analysis.path(&child, arg.range.clone());
                validate_glob(arg, &child, analysis);
            }
        }
        RqlForm::Language => {
            let values = &args[..args.len().saturating_sub(1)];
            if values.is_empty() {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    "language expects at least one label and a query",
                );
            } else if values.len() > MAX_LANGUAGE_FILTERS {
                analysis.error(
                    values[MAX_LANGUAGE_FILTERS].range.clone(),
                    "invalid-query",
                    format!("at most {MAX_LANGUAGE_FILTERS} language filters are allowed"),
                );
            }
            let languages_path = rql_query_child_path(path, "languages");
            for (index, arg) in values.iter().enumerate() {
                analysis.path(
                    rql_query_index_path(&languages_path, index),
                    arg.range.clone(),
                );
                validate_language(arg, analysis);
            }
        }
        RqlForm::Limit => {
            if args.len() != 2 {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    "limit expects a count and query",
                );
            } else if !matches!(args[0].kind, ExprKind::Number(value) if value > 0) {
                analysis.error(
                    args[0].range.clone(),
                    "wrong-value-shape",
                    "expected a positive integer",
                );
            } else if matches!(args[0].kind, ExprKind::Number(value) if value > MAX_LIMIT as u64) {
                analysis.error(
                    args[0].range.clone(),
                    "invalid-query",
                    format!("limit must be at most {MAX_LIMIT}"),
                );
            }
            if let Some(value) = args.first() {
                analysis.path(rql_query_child_path(path, "limit"), value.range.clone());
            }
        }
        RqlForm::ResultDetail => {
            if args.len() != 2 {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    "result-detail expects a value and query",
                );
            } else {
                analysis.path(
                    rql_query_child_path(path, "result_detail"),
                    args[0].range.clone(),
                );
                validate_result_detail(&args[0], analysis);
            }
        }
        RqlForm::Explain | RqlForm::Profile => {}
        RqlForm::Inside | RqlForm::InsideDecl | RqlForm::NotInside => {
            if args.len() != 2 {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    "containment wrapper expects a pattern and query",
                );
            } else {
                let field = match form {
                    RqlForm::Inside => "inside",
                    RqlForm::InsideDecl => "inside_decl",
                    RqlForm::NotInside => "not_inside",
                    _ => unreachable!("containment forms were filtered above"),
                };
                let field_path = rql_query_child_path(path, field);
                validate_rql_pattern(&args[0], &field_path, analysis);
                if form == RqlForm::InsideDecl {
                    analysis.path(&field_path, head_range.clone());
                }
            }
        }
        RqlForm::Union | RqlForm::Intersect | RqlForm::Except => {
            if args.len() < 2 {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    format!("{} expects at least two queries", form.label()),
                );
            } else if args.len() > MAX_QUERY_BRANCHES {
                analysis.error(
                    args[MAX_QUERY_BRANCHES].range.clone(),
                    "invalid-query",
                    format!("at most {MAX_QUERY_BRANCHES} branches are allowed"),
                );
            }
            let operation_path = rql_query_child_path(path, form.label());
            for (index, branch) in args.iter().enumerate() {
                validate_rql_query(
                    branch,
                    &rql_query_index_path(&operation_path, index),
                    analysis,
                    depth + 1,
                    plan_budget,
                );
            }
            return;
        }
        RqlForm::EnclosingDecl
        | RqlForm::ProcedureOf
        | RqlForm::CfgEntry
        | RqlForm::CfgExits
        | RqlForm::CfgSuccessorEdges
        | RqlForm::CfgPredecessorEdges
        | RqlForm::CfgEdgeSource
        | RqlForm::CfgEdgeTarget
        | RqlForm::FileOf
        | RqlForm::ImportsOf
        | RqlForm::ImportersOf
        | RqlForm::Members
        | RqlForm::Owner => {
            if args.len() != 1 {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    format!("{} expects one query", form.label()),
                );
            }
        }
        RqlForm::Typestate => {
            let option = args
                .first()
                .and_then(Expr::as_symbol)
                .and_then(|label| QueryStepOp::Typestate.option_for_rql_label(label));
            if args.len() != 3
                || option.is_none_or(|option| option.field() != QueryStepField::ProtocolRef)
            {
                analysis.error(
                    head_range.clone(),
                    "wrong-value-shape",
                    "typestate expects :protocol-ref namespace:name followed by a query",
                );
            } else {
                analysis.add_help(
                    args[0].range.clone(),
                    ":protocol-ref namespace:name",
                    option
                        .expect("validated typestate option")
                        .field()
                        .description(),
                );
                let steps = query_to_json(query)
                    .ok()
                    .and_then(|value| value.get("steps").and_then(Value::as_array).map(Vec::len))
                    .unwrap_or(0);
                let field_path = format!(
                    "{}[{steps}].protocol_ref",
                    rql_query_child_path(path, "steps")
                );
                analysis.path(&field_path, args[1].range.clone());
                match args[1].as_symbol().or_else(|| args[1].as_string()) {
                    Some(value) => {
                        if let Err(error) =
                            value.parse::<super::super::super::analysis_context::ProtocolRef>()
                        {
                            analysis.error(
                                args[1].range.clone(),
                                "wrong-value-shape",
                                error.to_string(),
                            );
                        }
                    }
                    None => analysis.error(
                        args[1].range.clone(),
                        "wrong-value-shape",
                        "protocol_ref must be a symbol or string",
                    ),
                }
            }
        }
        RqlForm::ValueFlow => {
            let option = args
                .first()
                .and_then(Expr::as_symbol)
                .and_then(|label| QueryStepOp::ValueFlow.option_for_rql_label(label));
            if args.len() != 3
                || option.is_none_or(|option| option.field() != QueryStepField::PlanRef)
            {
                analysis.error(
                    head_range.clone(),
                    "wrong-value-shape",
                    "value-flow expects :plan-ref namespace:name followed by a query",
                );
            } else {
                analysis.add_help(
                    args[0].range.clone(),
                    ":plan-ref namespace:name",
                    option
                        .expect("validated value-flow option")
                        .field()
                        .description(),
                );
                let steps = query_to_json(query)
                    .ok()
                    .and_then(|value| value.get("steps").and_then(Value::as_array).map(Vec::len))
                    .unwrap_or(0);
                let field_path =
                    format!("{}[{steps}].plan_ref", rql_query_child_path(path, "steps"));
                analysis.path(&field_path, args[1].range.clone());
                match args[1].as_symbol().or_else(|| args[1].as_string()) {
                    Some(value) => {
                        if let Err(error) =
                            value.parse::<super::super::super::analysis_context::ValueFlowPlanRef>()
                        {
                            analysis.error(
                                args[1].range.clone(),
                                "wrong-value-shape",
                                error.to_string(),
                            );
                        }
                    }
                    None => analysis.error(
                        args[1].range.clone(),
                        "wrong-value-shape",
                        "plan_ref must be a symbol or string",
                    ),
                }
            }
        }
        RqlForm::Taint => {
            let option = args
                .first()
                .and_then(Expr::as_symbol)
                .and_then(|label| QueryStepOp::Taint.option_for_rql_label(label));
            if args.len() != 3
                || option.is_none_or(|option| option.field() != QueryStepField::TaintRef)
            {
                analysis.error(
                    head_range.clone(),
                    "wrong-value-shape",
                    "taint expects :taint-ref namespace:name followed by a query",
                );
            } else {
                analysis.add_help(
                    args[0].range.clone(),
                    ":taint-ref namespace:name",
                    option
                        .expect("validated taint option")
                        .field()
                        .description(),
                );
                let steps = query_to_json(query)
                    .ok()
                    .and_then(|value| value.get("steps").and_then(Value::as_array).map(Vec::len))
                    .unwrap_or(0);
                let field_path =
                    format!("{}[{steps}].taint_ref", rql_query_child_path(path, "steps"));
                analysis.path(&field_path, args[1].range.clone());
                match args[1].as_symbol().or_else(|| args[1].as_string()) {
                    Some(value) => {
                        if let Err(error) =
                            value.parse::<super::super::super::analysis_context::TaintResultRef>()
                        {
                            analysis.error(
                                args[1].range.clone(),
                                "wrong-value-shape",
                                error.to_string(),
                            );
                        }
                    }
                    None => analysis.error(
                        args[1].range.clone(),
                        "wrong-value-shape",
                        "taint_ref must be a symbol or string",
                    ),
                }
            }
        }
        RqlForm::Witness => {
            let options = &args[..args.len().saturating_sub(1)];
            if !options.len().is_multiple_of(2) {
                analysis.error(
                    head_range.clone(),
                    "wrong-value-shape",
                    "witness expects option/value pairs followed by a query",
                );
            }
            let steps = query_to_json(query)
                .ok()
                .and_then(|value| value.get("steps").and_then(Value::as_array).map(Vec::len))
                .unwrap_or(0);
            let step_path = format!("{}[{steps}]", rql_query_child_path(path, "steps"));
            let mut seen = std::collections::HashSet::new();
            for pair in options.chunks_exact(2) {
                let Some(option) = pair[0]
                    .as_symbol()
                    .and_then(|label| QueryStepOp::Witness.option_for_rql_label(label))
                else {
                    analysis.error(
                        pair[0].range.clone(),
                        "unknown-property",
                        "witness accepts only :max-steps and :max-bytes",
                    );
                    continue;
                };
                let field = option.field().label();
                analysis.add_help(
                    pair[0].range.clone(),
                    format!(":{} non-negative-integer", field.replace('_', "-")),
                    option.field().description(),
                );
                if !seen.insert(field) {
                    analysis.error(
                        pair[0].range.clone(),
                        "duplicate-property",
                        format!("duplicate witness option '{}'", field.replace('_', "-")),
                    );
                }
                analysis.path(format!("{step_path}.{field}"), pair[1].range.clone());
                if !matches!(pair[1].kind, ExprKind::Number(_)) {
                    analysis.error(
                        pair[1].range.clone(),
                        "wrong-value-shape",
                        "witness limit must be a non-negative integer",
                    );
                }
            }
        }
        RqlForm::Supertypes | RqlForm::Subtypes => match args {
            [_query] => {}
            [key, value, _query] => match key.as_symbol() {
                Some(":depth") => {
                    analysis.add_help(
                        key.range.clone(),
                        ":depth positive-integer",
                        QueryStepField::Depth.description(),
                    );
                    if !matches!(value.kind, ExprKind::Number(number) if number > 0) {
                        analysis.error(
                            value.range.clone(),
                            "wrong-value-shape",
                            "hierarchy depth must be a positive integer",
                        );
                    }
                }
                Some(":transitive") => {
                    analysis.add_help(
                        key.range.clone(),
                        ":transitive true",
                        QueryStepField::Transitive.description(),
                    );
                    if value.as_symbol() != Some("true") {
                        analysis.error(
                            value.range.clone(),
                            "wrong-value-shape",
                            "hierarchy transitive option must be true",
                        );
                    }
                }
                _ => analysis.error(
                    key.range.clone(),
                    "unknown-property",
                    "hierarchy traversal accepts only :depth or :transitive",
                ),
            },
            _ => analysis.error(
                query.range.clone(),
                "wrong-value-shape",
                format!(
                    "{} expects a query, optionally preceded by :depth count or :transitive true",
                    form.label()
                ),
            ),
        },
        RqlForm::ReferencesOf | RqlForm::UsedBy | RqlForm::Uses => {
            validate_reference_wrapper(form, args, query, analysis);
        }
        RqlForm::Callers | RqlForm::Callees | RqlForm::CallSitesTo | RqlForm::CallSitesFrom => {
            validate_call_wrapper(form, args, query, analysis)
        }
        RqlForm::CallInput => validate_call_input_wrapper(args, query, analysis),
        RqlForm::ReceiverTargets | RqlForm::PointsTo | RqlForm::MemberTargets => {
            validate_receiver_wrapper(form, args, query, analysis)
        }
        RqlForm::OccurrencesOf | RqlForm::OccurrencesIn => {
            validate_occurrence_options(form, &args[..args.len().saturating_sub(1)], analysis);
        }
        RqlForm::OccurrenceTarget => {
            if args.len() != 1 {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    "occurrence-target expects exactly one query",
                );
            }
        }
        RqlForm::BindingsIn => validate_environment_options(
            form,
            &args[..args.len().saturating_sub(1)],
            EnvironmentOptionKind::Binding,
            analysis,
        ),
        RqlForm::CandidatesOf => validate_environment_options(
            form,
            &args[..args.len().saturating_sub(1)],
            EnvironmentOptionKind::Candidate,
            analysis,
        ),
        RqlForm::ReachingBinding => validate_environment_options(
            form,
            &args[..args.len().saturating_sub(1)],
            EnvironmentOptionKind::ReachingBinding,
            analysis,
        ),
        RqlForm::DeclarationStateOf => validate_environment_options(
            form,
            &args[..args.len().saturating_sub(1)],
            EnvironmentOptionKind::DeclarationState,
            analysis,
        ),
        RqlForm::EdgesOf | RqlForm::EdgesFrom => {
            validate_edge_wrapper(form, args, query, analysis);
        }
        RqlForm::SegmentsOf => {
            validate_segments_of_options(&args[..args.len().saturating_sub(1)], analysis);
        }
        RqlForm::ScopeOf
        | RqlForm::ScopeAncestors
        | RqlForm::BindingOccurrence
        | RqlForm::CandidateTarget
        | RqlForm::Generates
        | RqlForm::GeneratedBy
        | RqlForm::ImplementationOf
        | RqlForm::ExportTarget
        | RqlForm::EdgeTarget
        | RqlForm::SegmentTarget
        | RqlForm::ReceiverOutcome
        | RqlForm::ReceiverEvidence
        | RqlForm::CallShape
        | RqlForm::CallArgumentGroups
        | RqlForm::CallArguments => {
            if args.len() != 1 {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    format!("{} expects exactly one query", form.label()),
                );
            }
        }
        RqlForm::Occurrences => unreachable!("the occurrence source returns above"),
        RqlForm::Scopes
        | RqlForm::Bindings
        | RqlForm::Paths
        | RqlForm::GenerationSites
        | RqlForm::Exports => {
            unreachable!("the environment sources return above")
        }
        RqlForm::Name
        | RqlForm::NameRegex
        | RqlForm::TextRegex
        | RqlForm::Capture
        | RqlForm::Has
        | RqlForm::NotHas
        | RqlForm::NotKind => unreachable!("predicate cannot be a query wrapper"),
    }
    validate_rql_query(query, path, analysis, depth, plan_budget);
}

/// Validate the option pairs of the `(paths ...)` source: only
/// `:min-segments` with a positive integer.
fn validate_path_source_options(args: &[Expr], analysis: &mut Analysis) {
    if !args.len().is_multiple_of(2) {
        if let Some(last) = args.last() {
            analysis.error(
                last.range.clone(),
                "wrong-value-shape",
                "(paths ...) filter options must be name/value pairs",
            );
        }
        return;
    }
    for pair in args.chunks_exact(2) {
        let Some(key) = pair[0].as_symbol() else {
            analysis.error(
                pair[0].range.clone(),
                "wrong-value-shape",
                "(paths ...) option names must be symbols",
            );
            continue;
        };
        if key != ":min-segments" && key != ":min_segments" {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "(paths ...) accepts only :min-segments",
            );
            continue;
        }
        analysis.add_help(
            pair[0].range.clone(),
            ":min-segments N",
            "Keep only paths with at least this many segments.",
        );
        let valid = matches!(&pair[1].kind, ExprKind::Number(count) if *count > 0);
        if !valid {
            analysis.error(
                pair[1].range.clone(),
                "wrong-value-shape",
                ":min-segments takes a positive integer",
            );
        }
    }
}

/// Validate the option pairs of `(segments-of ...)`: only `:resolved true`.
fn validate_segments_of_options(args: &[Expr], analysis: &mut Analysis) {
    if !args.len().is_multiple_of(2) {
        if let Some(last) = args.last() {
            analysis.error(
                last.range.clone(),
                "wrong-value-shape",
                "(segments-of ...) options must be name/value pairs before the query",
            );
        }
        return;
    }
    for pair in args.chunks_exact(2) {
        let Some(key) = pair[0].as_symbol() else {
            analysis.error(
                pair[0].range.clone(),
                "wrong-value-shape",
                "(segments-of ...) option names must be symbols",
            );
            continue;
        };
        if key != ":resolved" {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "(segments-of ...) accepts only :resolved",
            );
            continue;
        }
        analysis.add_help(
            pair[0].range.clone(),
            ":resolved true",
            super::schema::QueryStepField::Resolved.description(),
        );
        if !matches!(&pair[1].kind, ExprKind::Symbol(text) if text == "true") {
            analysis.error(
                pair[1].range.clone(),
                "wrong-value-shape",
                ":resolved must be true when present",
            );
        }
    }
}

fn validate_receiver_wrapper(form: RqlForm, args: &[Expr], query: &Expr, analysis: &mut Analysis) {
    match args {
        [_query] => {}
        [key, value, _query] if key.as_symbol() == Some(":capture") => {
            analysis.add_help(
                key.range.clone(),
                ":capture declared-name",
                QueryStepField::Capture.description(),
            );
            let valid = match &value.kind {
                ExprKind::String(name) | ExprKind::Symbol(name) => {
                    validate_capture_name(
                        name,
                        value.range.clone(),
                        "wrong-value-shape",
                        &format!("{} capture", form.label()),
                        analysis,
                    );
                    true
                }
                _ => false,
            };
            if !valid {
                analysis.error(
                    value.range.clone(),
                    "wrong-value-shape",
                    format!("{} capture must be a name", form.label()),
                );
            }
        }
        [key, _, _query] => analysis.error(
            key.range.clone(),
            "unknown-property",
            format!("{} accepts only :capture", form.label()),
        ),
        _ => analysis.error(
            query.range.clone(),
            "wrong-value-shape",
            format!(
                "{} expects a query, optionally preceded by :capture name",
                form.label()
            ),
        ),
    }
}

fn validate_call_wrapper(form: RqlForm, args: &[Expr], query: &Expr, analysis: &mut Analysis) {
    let options = &args[..args.len().saturating_sub(1)];
    if !options.len().is_multiple_of(2) {
        analysis.error(
            options
                .last()
                .map_or_else(|| query.range.clone(), |arg| arg.range.clone()),
            "wrong-value-shape",
            format!(
                "{} expects option/value pairs followed by a query",
                form.label()
            ),
        );
        return;
    }
    let permits_depth = matches!(form, RqlForm::Callers | RqlForm::Callees);
    let mut seen = HashSet::new();
    for pair in options.chunks_exact(2) {
        let Some(key) = pair[0].as_symbol() else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "call traversal option names must be symbols",
            );
            continue;
        };
        if !seen.insert(key) {
            analysis.error(
                pair[0].range.clone(),
                "duplicate-property",
                format!("duplicate call traversal option {key}"),
            );
        }
        match key {
            ":depth" if permits_depth => {
                analysis.add_help(
                    pair[0].range.clone(),
                    ":depth positive-integer",
                    QueryStepField::Depth.description(),
                );
                if !matches!(pair[1].kind, ExprKind::Number(number) if number > 0) {
                    analysis.error(
                        pair[1].range.clone(),
                        "wrong-value-shape",
                        "call traversal depth must be a positive integer",
                    );
                }
            }
            ":proof" => {
                analysis.add_help(
                    pair[0].range.clone(),
                    ":proof proven|unproven",
                    QueryStepField::Proof.description(),
                );
                validate_rql_reference_scalar(&pair[1], "proof", usage_proof_from_label, analysis);
            }
            _ => analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                if permits_depth {
                    "call traversal accepts only :depth and :proof"
                } else {
                    "call-site traversal accepts only :proof"
                },
            ),
        }
    }
}

/// Validate a lexical-environment filter option block against the registries
/// rather than a hand-maintained keyword list (#1474), mirroring
/// [`validate_occurrence_options`].
fn validate_environment_options(
    form: RqlForm,
    options: &[Expr],
    kind: EnvironmentOptionKind,
    analysis: &mut Analysis,
) {
    if !options.len().is_multiple_of(2) {
        analysis.error(
            options
                .last()
                .expect("an odd option count has a last element")
                .range
                .clone(),
            "wrong-value-shape",
            format!(
                "{} expects {} option/value pairs",
                form.label(),
                kind.accepted()
            ),
        );
        return;
    }
    let mut seen = HashSet::new();
    for pair in options.chunks_exact(2) {
        let Some(label) = pair[0].as_symbol() else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "filter option names must be keywords",
            );
            continue;
        };
        let Some(field) = kind.field_for(label) else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                format!("{} accepts only {}", form.label(), kind.accepted()),
            );
            continue;
        };
        if !seen.insert(field) {
            analysis.error(
                pair[0].range.clone(),
                "duplicate-property",
                format!("duplicate filter option '{label}'"),
            );
            continue;
        }
        analysis.add_help(
            pair[0].range.clone(),
            field.signature(),
            field.description(),
        );
        let values = pair[1]
            .as_sequence()
            .map_or_else(|| vec![&pair[1]], |items| items.iter().collect());
        if values.is_empty() {
            analysis.error(
                pair[1].range.clone(),
                "wrong-value-shape",
                format!("{label} must not be empty"),
            );
            continue;
        }
        for value in values {
            let text = match &value.kind {
                ExprKind::String(text) | ExprKind::Symbol(text) => text.as_str(),
                _ => {
                    analysis.error(
                        value.range.clone(),
                        "wrong-value-shape",
                        format!("{label} values must be symbols or strings"),
                    );
                    continue;
                }
            };
            match field.accepted_values() {
                Some(accepted) if !accepted.contains(&text) => {
                    analysis.error(
                        value.range.clone(),
                        "unknown-value",
                        format!("unknown {} value '{text}'", field.label()),
                    );
                }
                Some(_) => {}
                None if text.is_empty() || text.len() > MAX_BINDING_NAME_LENGTH => {
                    analysis.error(
                        value.range.clone(),
                        "wrong-value-shape",
                        format!(
                            "{label} values must be between 1 and {MAX_BINDING_NAME_LENGTH} bytes"
                        ),
                    );
                }
                None => {}
            }
        }
    }
}

fn validate_occurrence_options(form: RqlForm, options: &[Expr], analysis: &mut Analysis) {
    if !options.len().is_multiple_of(2) {
        analysis.error(
            options
                .last()
                .expect("an odd option count has a last element")
                .range
                .clone(),
            "wrong-value-shape",
            format!(
                "{} expects :class, :role, and :namespace option/value pairs",
                form.label()
            ),
        );
        return;
    }
    let mut seen = HashSet::new();
    for pair in options.chunks_exact(2) {
        let Some(label) = pair[0].as_symbol() else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "occurrence filter option names must be keywords",
            );
            continue;
        };
        let Some(option) = occurrence_option_for_rql_label(label) else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "occurrence filters accept only :class, :role, and :namespace",
            );
            continue;
        };
        let field = option.field();
        if !seen.insert(field) {
            analysis.error(
                pair[0].range.clone(),
                "duplicate-property",
                format!("duplicate occurrence filter option '{label}'"),
            );
            continue;
        }
        analysis.add_help(
            pair[0].range.clone(),
            field.signature(),
            field.description(),
        );
        let accepted = occurrence_filter_labels(field);
        let values = pair[1]
            .as_sequence()
            .map_or_else(|| vec![&pair[1]], |items| items.iter().collect());
        if values.is_empty() {
            analysis.error(
                pair[1].range.clone(),
                "wrong-value-shape",
                format!("{label} must not be empty"),
            );
            continue;
        }
        for value in values {
            let text = match &value.kind {
                ExprKind::String(text) | ExprKind::Symbol(text) => text.as_str(),
                _ => {
                    analysis.error(
                        value.range.clone(),
                        "wrong-value-shape",
                        format!("{label} values must be symbols or strings"),
                    );
                    continue;
                }
            };
            if !accepted.contains(&text) {
                analysis.error(
                    value.range.clone(),
                    "unknown-value",
                    format!("unknown {} value '{text}'", field.label()),
                );
            }
        }
    }
}

fn validate_call_input_wrapper(args: &[Expr], query: &Expr, analysis: &mut Analysis) {
    if args.len() != 3 {
        analysis.error(
            query.range.clone(),
            "wrong-value-shape",
            "call-input expects one selector option followed by a query",
        );
        return;
    }
    let Some(key) = args[0].as_symbol() else {
        analysis.error(
            args[0].range.clone(),
            "unknown-property",
            "call-input selector must be a symbol",
        );
        return;
    };
    match key {
        ":receiver" => {
            if args[1].as_symbol() != Some("true") {
                analysis.error(
                    args[1].range.clone(),
                    "wrong-value-shape",
                    "receiver selector must be true",
                );
            }
        }
        ":parameter-index" => {
            if !matches!(args[1].kind, ExprKind::Number(_)) {
                analysis.error(
                    args[1].range.clone(),
                    "wrong-value-shape",
                    "parameter index must be a non-negative integer",
                );
            }
        }
        ":parameter-name" => match &args[1].kind {
            ExprKind::String(name) | ExprKind::Symbol(name) => {
                validate_parameter_name(name, args[1].range.clone(), analysis);
            }
            _ => {
                analysis.error(
                    args[1].range.clone(),
                    "wrong-value-shape",
                    "parameter name must be a string or symbol",
                );
            }
        },
        _ => analysis.error(
            args[0].range.clone(),
            "unknown-property",
            "call-input requires :receiver, :parameter-index, or :parameter-name",
        ),
    }
}

fn validate_reference_wrapper(form: RqlForm, args: &[Expr], query: &Expr, analysis: &mut Analysis) {
    let options = &args[..args.len().saturating_sub(1)];
    if !options.len().is_multiple_of(2) {
        analysis.error(
            options
                .last()
                .map_or_else(|| query.range.clone(), |arg| arg.range.clone()),
            "wrong-value-shape",
            format!(
                "{} expects option/value pairs followed by a query",
                form.label()
            ),
        );
        return;
    }

    let mut seen = HashSet::new();
    for pair in options.chunks_exact(2) {
        let key = &pair[0];
        let value = &pair[1];
        let Some(label) = key.as_symbol().and_then(|symbol| symbol.strip_prefix(':')) else {
            analysis.error(
                key.range.clone(),
                "unknown-property",
                "reference traversal option names must be keywords",
            );
            continue;
        };
        let canonical = label.replace('-', "_");
        if !seen.insert(canonical.clone()) {
            analysis.error(
                key.range.clone(),
                "duplicate-property",
                format!("duplicate reference traversal option '{label}'"),
            );
            continue;
        }
        match canonical.as_str() {
            "reference_kinds" => {
                analysis.add_help(
                    key.range.clone(),
                    ":reference-kinds [kind ...]",
                    QueryStepField::ReferenceKinds.description(),
                );
                validate_rql_reference_kinds(value, analysis);
            }
            "proof" => {
                analysis.add_help(
                    key.range.clone(),
                    ":proof proven | unproven",
                    QueryStepField::Proof.description(),
                );
                validate_rql_reference_scalar(value, "proof", usage_proof_from_label, analysis);
            }
            "surface" => {
                analysis.add_help(
                    key.range.clone(),
                    ":surface external-usages | lsp-references",
                    QueryStepField::Surface.description(),
                );
                validate_rql_reference_scalar(value, "surface", usage_surface_from_label, analysis);
            }
            _ => analysis.error(
                key.range.clone(),
                "unknown-property",
                "reference traversal accepts only :reference-kinds, :proof, and :surface",
            ),
        }
    }
}

fn validate_edge_wrapper(form: RqlForm, args: &[Expr], query: &Expr, analysis: &mut Analysis) {
    let options = &args[..args.len().saturating_sub(1)];
    if !options.len().is_multiple_of(2) {
        analysis.error(
            options
                .last()
                .map_or_else(|| query.range.clone(), |arg| arg.range.clone()),
            "wrong-value-shape",
            format!(
                "{} expects option/value pairs followed by a query",
                form.label()
            ),
        );
        return;
    }

    let mut seen = HashSet::new();
    for pair in options.chunks_exact(2) {
        let key = &pair[0];
        let value = &pair[1];
        let Some(label) = key.as_symbol().and_then(|symbol| symbol.strip_prefix(':')) else {
            analysis.error(
                key.range.clone(),
                "unknown-property",
                "edge traversal option names must be keywords",
            );
            continue;
        };
        let canonical = label.replace('-', "_");
        if !seen.insert(canonical.clone()) {
            analysis.error(
                key.range.clone(),
                "duplicate-property",
                format!("duplicate edge traversal option '{label}'"),
            );
            continue;
        }
        match canonical.as_str() {
            "reference_kinds" => {
                analysis.add_help(
                    key.range.clone(),
                    ":reference-kinds [kind ...]",
                    QueryStepField::ReferenceKinds.description(),
                );
                validate_rql_reference_kinds(value, analysis);
            }
            "proof" => {
                analysis.add_help(
                    key.range.clone(),
                    ":proof proven | unproven",
                    QueryStepField::Proof.description(),
                );
                validate_rql_reference_scalar(value, "proof", usage_proof_from_label, analysis);
            }
            "surface" => {
                analysis.add_help(
                    key.range.clone(),
                    ":surface external-usages | lsp-references",
                    QueryStepField::Surface.description(),
                );
                validate_rql_reference_scalar(value, "surface", usage_surface_from_label, analysis);
            }
            "usage" => {
                analysis.add_help(
                    key.range.clone(),
                    ":usage [kind ...]",
                    QueryStepField::EdgeUsageKinds.description(),
                );
                validate_rql_label_vector(value, "usage kind", usage_kind_from_label, analysis);
            }
            "relation" => {
                analysis.add_help(
                    key.range.clone(),
                    ":relation [relation ...]",
                    QueryStepField::EdgeRelations.description(),
                );
                validate_rql_label_vector(
                    value,
                    "owner relation",
                    OwnerRelation::from_label,
                    analysis,
                );
            }
            "site_class" => {
                analysis.add_help(
                    key.range.clone(),
                    ":site-class [class ...]",
                    QueryStepField::EdgeSiteClasses.description(),
                );
                validate_rql_label_vector(value, "site class", SiteClass::from_label, analysis);
            }
            _ => analysis.error(
                key.range.clone(),
                "unknown-property",
                "edge traversal accepts only :reference-kinds, :proof, :surface, :usage, :relation, and :site-class",
            ),
        }
    }
}

/// Validate one vector of constrained labels against a vocabulary.
fn validate_rql_label_vector<T>(
    value: &Expr,
    noun: &str,
    parse: impl Fn(&str) -> Option<T>,
    analysis: &mut Analysis,
) {
    let ExprKind::Vector(items) = &value.kind else {
        analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            format!("{noun} list must be a non-empty vector"),
        );
        return;
    };
    if items.is_empty() {
        analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            format!("{noun} list must be a non-empty vector"),
        );
    }
    for item in items {
        let Some(label) = item.as_symbol().or_else(|| item.as_string()) else {
            analysis.error(
                item.range.clone(),
                "wrong-value-shape",
                format!("{noun} must be a symbol"),
            );
            continue;
        };
        let canonical = label.replace('-', "_");
        if parse(&canonical).is_none() {
            analysis.error(
                item.range.clone(),
                "invalid-query-step-option",
                format!("unknown {noun} '{label}'"),
            );
        }
    }
}

fn validate_rql_reference_kinds(value: &Expr, analysis: &mut Analysis) {
    let ExprKind::Vector(items) = &value.kind else {
        analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            "reference-kinds must be a non-empty vector",
        );
        return;
    };
    if items.is_empty() {
        analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            "reference-kinds must be a non-empty vector",
        );
    }
    for item in items {
        let Some(label) = item.as_symbol().or_else(|| item.as_string()) else {
            analysis.error(
                item.range.clone(),
                "wrong-value-shape",
                "reference kind must be a symbol",
            );
            continue;
        };
        let canonical = label.replace('-', "_");
        if reference_kind_from_label(&canonical).is_none() {
            analysis.error(
                item.range.clone(),
                "invalid-reference-kind",
                format!("unknown reference kind '{label}'"),
            );
        }
    }
}

fn validate_rql_reference_scalar<T>(
    value: &Expr,
    name: &str,
    parse: impl Fn(&str) -> Option<T>,
    analysis: &mut Analysis,
) {
    let Some(label) = value.as_symbol().or_else(|| value.as_string()) else {
        analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            format!("{name} must be a symbol"),
        );
        return;
    };
    let canonical = label.replace('-', "_");
    if parse(&canonical).is_none() {
        analysis.error(
            value.range.clone(),
            "invalid-query-step-option",
            format!("unknown reference traversal {name} '{label}'"),
        );
    }
}

fn validate_rql_pattern(expr: &Expr, path: &str, analysis: &mut Analysis) {
    analysis.path(path, expr.range.clone());
    let Some((head, head_range, args)) = list_head(expr) else {
        analysis.error(
            expr.range.clone(),
            "wrong-value-shape",
            "pattern must be an RQL list",
        );
        return;
    };
    if let Some(kind) = NormalizedKind::from_label(head) {
        analysis.add_help(head_range, kind.signature(), kind.description());
        let mut seen = HashSet::new();
        let mut index = 0;
        while index < args.len() {
            match &args[index].kind {
                ExprKind::Symbol(keyword) if keyword.starts_with(':') => {
                    let label = &keyword[1..];
                    let key_range = args[index].range.clone();
                    if index + 1 == args.len() {
                        add_rql_property_help(label, key_range, analysis);
                        analysis.incomplete = true;
                        return;
                    }
                    validate_rql_property(
                        label,
                        key_range,
                        &args[index + 1],
                        path,
                        kind,
                        &mut seen,
                        analysis,
                    );
                    index += 2;
                }
                ExprKind::List(_) => {
                    validate_predicate_fragment(&args[index], path, &mut seen, analysis);
                    index += 1;
                }
                _ => {
                    analysis.error(
                        args[index].range.clone(),
                        "wrong-value-shape",
                        "expected :property value or a predicate form",
                    );
                    index += 1;
                }
            }
        }
    } else if RqlForm::from_label(head).is_some_and(|form| form.class() == RqlFormClass::Predicate)
    {
        let mut seen = HashSet::new();
        validate_predicate_fragment(expr, path, &mut seen, analysis);
    } else {
        add_spelling_error(
            analysis,
            head_range,
            "unknown-form",
            format!("unknown RQL form '{head}'"),
            head,
            rql_pattern_head_candidates(),
            |suggestion| suggestion.to_string(),
        );
    }
}

fn validate_predicate_fragment(
    expr: &Expr,
    path: &str,
    seen: &mut HashSet<String>,
    analysis: &mut Analysis,
) {
    let Some((head, head_range, args)) = list_head(expr) else {
        return;
    };
    let Some(form) = RqlForm::from_label(head) else {
        add_spelling_error(
            analysis,
            head_range,
            "unknown-form",
            format!("unknown RQL form '{head}'"),
            head,
            rql_form_candidates(Some(RqlFormClass::Predicate)),
            |suggestion| suggestion.to_string(),
        );
        return;
    };
    if form.class() != RqlFormClass::Predicate {
        analysis.error(
            head_range,
            "wrong-form",
            "query wrapper cannot be nested as a predicate",
        );
        return;
    }
    analysis.add_help(head_range.clone(), form.signature(), form.description());
    if args.len() != 1 {
        analysis.error(
            head_range,
            "wrong-value-shape",
            format!("{} expects one value", form.label()),
        );
        return;
    }
    let property = form
        .property()
        .expect("predicate forms have an explicit property lowering");
    validate_property_value(property, &args[0], path, analysis);
    record_duplicate(property.label(), head_range, seen, analysis);
}

fn validate_rql_property(
    label: &str,
    range: Range<usize>,
    value: &Expr,
    path: &str,
    kind: NormalizedKind,
    seen: &mut HashSet<String>,
    analysis: &mut Analysis,
) {
    if let Some(property) = RqlProperty::from_label(label) {
        analysis.add_help(range.clone(), property.signature(), property.description());
        validate_property_value(property, value, path, analysis);
        record_duplicate(property.label(), range, seen, analysis);
    } else if let Some(role) = Role::from_label(label) {
        analysis.add_help(
            range.clone(),
            format!(":{} {}", role.label(), role.rql_signature()),
            role.description(),
        );
        let child = format!("{path}.{}", role.label());
        analysis.path(&child, value.range.clone());
        if !role.valid_for(kind) {
            analysis.error(
                range.clone(),
                "invalid-query",
                format!(
                    "role {:?} is not valid for kind {}",
                    role.label(),
                    kind.label()
                ),
            );
        }
        match role.value_shape() {
            RoleValueShape::Pattern if matches!(value.kind, ExprKind::String(_)) => {}
            RoleValueShape::Pattern => validate_rql_pattern(value, &child, analysis),
            RoleValueShape::PatternList if rql_single_pattern(value) => {
                analysis.error_with_fix(
                    value.range.clone(),
                    "wrong-value-shape",
                    "expected a list/vector of patterns",
                    QuerySourceFix {
                        title: "Wrap in a pattern list".to_string(),
                        edit: QuerySourceEdit::Surround {
                            prefix: "[".to_string(),
                            suffix: "]".to_string(),
                        },
                    },
                );
            }
            RoleValueShape::PatternList => validate_pattern_list(value, &child, analysis),
            RoleValueShape::PatternMap => validate_pattern_map(value, &child, analysis),
        }
        record_duplicate(role.label(), range, seen, analysis);
    } else {
        add_spelling_error(
            analysis,
            range,
            "unknown-property",
            format!("unknown pattern property ':{label}'"),
            label,
            rql_property_candidates(),
            |suggestion| format!(":{suggestion}"),
        );
    }
}

fn rql_single_pattern(value: &Expr) -> bool {
    let Some((head, _, _)) = list_head(value) else {
        return false;
    };
    if !matches!(value.kind, ExprKind::List(_))
        || !(NormalizedKind::from_label(head).is_some()
            || RqlForm::from_label(head)
                .is_some_and(|form| form.class() == RqlFormClass::Predicate))
    {
        return false;
    }

    let mut analysis = Analysis::default();
    validate_rql_pattern(value, "", &mut analysis);
    analysis.diagnostics.is_empty()
}

fn add_rql_property_help(label: &str, range: Range<usize>, analysis: &mut Analysis) {
    if let Some(property) = RqlProperty::from_label(label) {
        analysis.add_help(range, property.signature(), property.description());
    } else if let Some(role) = Role::from_label(label) {
        analysis.add_help(
            range,
            format!(":{} {}", role.label(), role.rql_signature()),
            role.description(),
        );
    }
}

fn record_duplicate(
    canonical: &str,
    range: Range<usize>,
    seen: &mut HashSet<String>,
    analysis: &mut Analysis,
) {
    if !seen.insert(canonical.to_string()) {
        analysis.error(
            range,
            "duplicate-property",
            format!("duplicate pattern property '{canonical}'"),
        );
    }
}

fn validate_property_value(
    property: RqlProperty,
    value: &Expr,
    path: &str,
    analysis: &mut Analysis,
) {
    let child = rql_property_path(path, property);
    analysis.path(&child, value.range.clone());
    match property.value_shape() {
        super::schema::ValueShape::String => {
            require_string(value, analysis);
            validate_plain_string(property, value, analysis);
        }
        super::schema::ValueShape::ParameterName => {
            unreachable!("parameter names are query-step values, not pattern properties")
        }
        super::schema::ValueShape::CaptureName => {
            unreachable!("capture names are query-step values, not pattern properties")
        }
        super::schema::ValueShape::RegexString => validate_rql_regex(value, &child, analysis),
        super::schema::ValueShape::KindList => validate_kind_value(value, &child, analysis),
        super::schema::ValueShape::Pattern => validate_rql_pattern(value, &child, analysis),
        super::schema::ValueShape::PatternList
        | super::schema::ValueShape::PatternMap
        | super::schema::ValueShape::Query
        | super::schema::ValueShape::QueryList
        | super::schema::ValueShape::QuerySteps
        | super::schema::ValueShape::StringList
        | super::schema::ValueShape::StringPredicate
        | super::schema::ValueShape::RegexPredicate
        | super::schema::ValueShape::LanguageList
        | super::schema::ValueShape::PositiveInteger
        | super::schema::ValueShape::NonNegativeInteger
        | super::schema::ValueShape::ResultDetail
        | super::schema::ValueShape::ExecutionMode
        | super::schema::ValueShape::ReferenceKindList
        | super::schema::ValueShape::SchemaVersion
        | super::schema::ValueShape::UsageProof
        | super::schema::ValueShape::UsageSurface
        | super::schema::ValueShape::CallTraversalCompleteness
        | super::schema::ValueShape::ProtocolRef
        | super::schema::ValueShape::ValueFlowPlanRef
        | super::schema::ValueShape::TaintResultRef
        | super::schema::ValueShape::OccurrenceFilter
        | super::schema::ValueShape::OccurrenceClassList
        | super::schema::ValueShape::OccurrenceRoleList
        | super::schema::ValueShape::NamespaceList
        | super::schema::ValueShape::UsageKindList
        | super::schema::ValueShape::OwnerRelationList
        | super::schema::ValueShape::SiteClassList
        | super::schema::ValueShape::ScopeFilter
        | super::schema::ValueShape::BindingFilter
        | super::schema::ValueShape::PathFilter
        | super::schema::ValueShape::BindingKindList
        | super::schema::ValueShape::BindingNameList
        | super::schema::ValueShape::HoistingClassList
        | super::schema::ValueShape::PrecedenceTierList
        | super::schema::ValueShape::CandidateOutcomeList
        | super::schema::ValueShape::BoundaryStatusList
        | super::schema::ValueShape::TrueBoolean
        | super::schema::ValueShape::GenerationSiteFilter
        | super::schema::ValueShape::ExportFilter
        | super::schema::ValueShape::GenerationKindList
        | super::schema::ValueShape::GenerationInputList
        | super::schema::ValueShape::ExportFormList
        | super::schema::ValueShape::ExportNameList
        | super::schema::ValueShape::DeclarationOriginList
        | super::schema::ValueShape::Boolean => {
            unreachable!("unsupported value shape for an RQL pattern property")
        }
    }
}

fn rql_property_path(path: &str, property: RqlProperty) -> String {
    let suffix = match property {
        RqlProperty::Name => "name",
        RqlProperty::NameRegex => "name.regex",
        RqlProperty::TextRegex => "text.regex",
        RqlProperty::Capture => "capture",
        RqlProperty::NotKind => "not_kind",
        RqlProperty::Has => "has",
        RqlProperty::NotHas => "not_has",
    };
    format!("{path}.{suffix}")
}

fn validate_plain_string(property: RqlProperty, value: &Expr, analysis: &mut Analysis) {
    let ExprKind::String(text) = &value.kind else {
        return;
    };
    if property == RqlProperty::Capture {
        validate_capture_name(
            text,
            value.range.clone(),
            "invalid-query",
            "capture label",
            analysis,
        );
        return;
    }
    let (label, max, reject_empty) = match property {
        RqlProperty::Name => ("exact string", MAX_STRING_PREDICATE_LENGTH, false),
        RqlProperty::Capture => unreachable!("capture handled above"),
        RqlProperty::NameRegex
        | RqlProperty::TextRegex
        | RqlProperty::NotKind
        | RqlProperty::Has
        | RqlProperty::NotHas => unreachable!("property is not a plain string"),
    };
    if reject_empty && text.is_empty() {
        analysis.error(
            value.range.clone(),
            "invalid-query",
            format!("{label} must not be empty"),
        );
    } else if text.len() > max {
        analysis.error(
            value.range.clone(),
            "invalid-query",
            format!("{label} must be at most {max} bytes"),
        );
    }
}

fn validate_rql_regex(value: &Expr, path: &str, analysis: &mut Analysis) {
    let ExprKind::String(source) = &value.kind else {
        require_string(value, analysis);
        return;
    };
    validate_regex(source, value.range.clone(), path, analysis);
}

fn validate_pattern_list(value: &Expr, path: &str, analysis: &mut Analysis) {
    let items = match &value.kind {
        ExprKind::List(items) | ExprKind::Vector(items) => items,
        _ => {
            analysis.error(
                value.range.clone(),
                "wrong-value-shape",
                "expected a list/vector of patterns",
            );
            return;
        }
    };
    if items.len() > MAX_ROLE_LIST_ENTRIES {
        analysis.error(
            items[MAX_ROLE_LIST_ENTRIES].range.clone(),
            "invalid-query",
            format!("role array may contain at most {MAX_ROLE_LIST_ENTRIES} entries"),
        );
    }
    for (index, item) in items.iter().enumerate() {
        validate_rql_pattern(item, &format!("{path}[{index}]"), analysis);
    }
}

fn validate_pattern_map(value: &Expr, path: &str, analysis: &mut Analysis) {
    let pairs = match &value.kind {
        ExprKind::List(items) | ExprKind::Vector(items) => items,
        _ => {
            analysis.error(
                value.range.clone(),
                "wrong-value-shape",
                "expected named pattern pairs",
            );
            return;
        }
    };
    if pairs.len() > MAX_KWARGS {
        analysis.error(
            pairs[MAX_KWARGS].range.clone(),
            "invalid-query",
            format!("kwargs may contain at most {MAX_KWARGS} entries"),
        );
    }
    let mut seen = HashSet::new();
    for pair in pairs {
        let ExprKind::List(items) = &pair.kind else {
            analysis.error(
                pair.range.clone(),
                "wrong-value-shape",
                "named pattern entry must be a list",
            );
            continue;
        };
        if items.len() != 2 {
            analysis.error(
                pair.range.clone(),
                "wrong-value-shape",
                "named pattern entry expects a name and pattern",
            );
        } else {
            let key = match &items[0].kind {
                ExprKind::Symbol(key) | ExprKind::String(key) => Some(key.as_str()),
                _ => {
                    analysis.error(
                        items[0].range.clone(),
                        "wrong-value-shape",
                        "keyword argument name must be a symbol or string",
                    );
                    None
                }
            };
            let child = key.map_or_else(
                || path.to_string(),
                |key| {
                    let child = format!("{path}.{key}");
                    analysis.path(&child, items[1].range.clone());
                    if key.len() > MAX_KWARG_NAME_LENGTH {
                        analysis.error(
                            items[0].range.clone(),
                            "invalid-query",
                            format!("keyword must be at most {MAX_KWARG_NAME_LENGTH} bytes"),
                        );
                    }
                    if !seen.insert(key.to_string()) {
                        analysis.error(
                            items[0].range.clone(),
                            "duplicate-property",
                            format!("duplicate keyword argument '{key}'"),
                        );
                    }
                    child
                },
            );
            validate_rql_pattern(&items[1], &child, analysis);
        }
    }
}

fn require_string(value: &Expr, analysis: &mut Analysis) {
    if !matches!(value.kind, ExprKind::String(_)) {
        analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            "expected a string",
        );
    }
}

fn validate_glob(value: &Expr, path: &str, analysis: &mut Analysis) {
    let ExprKind::String(pattern) = &value.kind else {
        require_string(value, analysis);
        return;
    };
    if pattern.len() > MAX_GLOB_LENGTH {
        analysis.error(
            value.range.clone(),
            "invalid-query",
            format!("glob must be at most {MAX_GLOB_LENGTH} bytes"),
        );
    } else if let Err(error) = glob::Pattern::new(pattern) {
        analysis.error(
            value.range.clone(),
            "invalid-query",
            format!("invalid glob: {error}"),
        );
    } else {
        analysis.path(path, value.range.clone());
    }
}

fn validate_kind_value(value: &Expr, path: &str, analysis: &mut Analysis) {
    match &value.kind {
        ExprKind::Symbol(label) => {
            if let Some(kind) = NormalizedKind::from_label(label) {
                analysis.add_help(value.range.clone(), kind.signature(), kind.description());
            } else {
                add_spelling_error(
                    analysis,
                    value.range.clone(),
                    "invalid-kind",
                    format!("unknown normalized kind '{label}'"),
                    label,
                    kind_candidates(),
                    |suggestion| replacement_for_rql_label(value, suggestion),
                );
            }
        }
        ExprKind::Vector(items) | ExprKind::List(items) => {
            if items.is_empty() {
                analysis.error(
                    value.range.clone(),
                    "wrong-value-shape",
                    "kind list must not be empty",
                );
            } else if items.len() > MAX_KIND_LIST_ENTRIES {
                analysis.error(
                    items[MAX_KIND_LIST_ENTRIES].range.clone(),
                    "invalid-query",
                    format!("kind list may contain at most {MAX_KIND_LIST_ENTRIES} entries"),
                );
            }
            for (index, item) in items.iter().enumerate() {
                let child = format!("{path}[{index}]");
                analysis.path(&child, item.range.clone());
                validate_kind_value(item, &child, analysis);
            }
        }
        ExprKind::String(label) => {
            if NormalizedKind::from_label(label).is_none() {
                add_spelling_error(
                    analysis,
                    value.range.clone(),
                    "invalid-kind",
                    format!("unknown normalized kind '{label}'"),
                    label,
                    kind_candidates(),
                    |suggestion| replacement_for_rql_label(value, suggestion),
                );
            }
        }
        _ => analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            "expected a kind or list of kinds",
        ),
    }
}

fn validate_language(value: &Expr, analysis: &mut Analysis) {
    match &value.kind {
        ExprKind::Symbol(label) => {
            if let Some(language) = Language::from_config_label(label) {
                analysis.add_help(
                    value.range.clone(),
                    language.config_label(),
                    "Restrict structural matching to this analyzer language.",
                );
            } else {
                add_spelling_error(
                    analysis,
                    value.range.clone(),
                    "invalid-language",
                    format!("unknown language label '{label}'"),
                    label,
                    language_candidates(),
                    |suggestion| replacement_for_rql_label(value, suggestion),
                );
            }
        }
        ExprKind::String(label) => {
            if Language::from_config_label(label).is_none() {
                add_spelling_error(
                    analysis,
                    value.range.clone(),
                    "invalid-language",
                    format!("unknown language label '{label}'"),
                    label,
                    language_candidates(),
                    |suggestion| replacement_for_rql_label(value, suggestion),
                );
            }
        }
        _ => analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            "expected a language label",
        ),
    }
}

fn validate_result_detail(value: &Expr, analysis: &mut Analysis) {
    let label = match &value.kind {
        ExprKind::Symbol(label) | ExprKind::String(label) => label,
        _ => {
            analysis.error(
                value.range.clone(),
                "wrong-value-shape",
                "expected compact or full",
            );
            return;
        }
    };
    if CodeQueryResultDetail::from_label(label).is_some() {
        analysis.add_help(
            value.range.clone(),
            label,
            if label == "compact" {
                "Return compact match locations."
            } else {
                "Return full capture and source details."
            },
        );
    } else {
        add_spelling_error(
            analysis,
            value.range.clone(),
            "invalid-result-detail",
            "expected compact or full",
            label,
            result_detail_candidates(),
            |suggestion| replacement_for_rql_label(value, suggestion),
        );
    }
}
