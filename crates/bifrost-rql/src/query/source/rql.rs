use super::super::ir::DeclarationModifier;
use super::super::{child_path, index_path};
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
        if matches!(
            form,
            RqlForm::Union
                | RqlForm::Intersect
                | RqlForm::Except
                | RqlForm::Correlate
                | RqlForm::RequireBoth
        ) && !plan_budget.enter(depth, expr.range.clone(), analysis)
        {
            return;
        }
        analysis.add_help(head_range.clone(), form.signature(), form.description());
        validate_wrapper(form, args, &head_range, path, analysis, depth, plan_budget);
    } else if let Some(form) = RqlForm::from_label(head)
        && form.class() == RqlFormClass::Relation
    {
        analysis.add_help(head_range.clone(), form.signature(), form.description());
        analysis.error(
            head_range,
            "invalid-query",
            format!(
                "`{head}` is a cross-domain relation, valid only as the :relation of correlate"
            ),
        );
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
        let match_path = child_path(path, "match");
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
        Some(
            RqlProperty::Name
                | RqlProperty::StringValue
                | RqlProperty::NameRegex
                | RqlProperty::TextRegex
                | RqlProperty::CommentBlockRegex
        )
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
        let mode_path = child_path(path, "execution_mode");
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
        analysis.path(child_path(path, "occurrences"), head_range.clone());
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
            RqlForm::Exports => ("exports", EnvironmentOptionKind::Export),
            _ => unreachable!("other source forms are handled separately"),
        };
        analysis.path(child_path(path, label), head_range.clone());
        validate_environment_options(form, args, kind, analysis);
        return;
    }
    // `paths` is a source too: its whole argument list is a filter block.
    if form == RqlForm::Paths {
        analysis.path(child_path(path, "paths"), head_range.clone());
        validate_path_source_options(args, analysis);
        return;
    }
    if form == RqlForm::DependencyEvidence {
        analysis.path(child_path(path, "dependency_evidence"), head_range.clone());
        for pair in args.as_chunks::<2>().0 {
            let Some(label) = pair[0].as_symbol() else {
                analysis.error(
                    pair[0].range.clone(),
                    "invalid-property",
                    "expected dependency option name",
                );
                continue;
            };
            if let Some(field) = super::schema::dependency_evidence_field_for_rql_label(label) {
                analysis.add_help(
                    pair[0].range.clone(),
                    field.signature(),
                    field.description(),
                );
                let field_path =
                    child_path(&child_path(path, "dependency_evidence"), field.label());
                analysis.path(field_path.clone(), pair[1].range.clone());
                match &pair[1].kind {
                    ExprKind::List(values) | ExprKind::Vector(values) => {
                        for (index, value) in values.iter().enumerate() {
                            analysis.path(index_path(&field_path, index), value.range.clone());
                        }
                    }
                    _ => analysis.path(index_path(&field_path, 0), pair[1].range.clone()),
                }
            } else {
                analysis.error(
                    pair[0].range.clone(),
                    "unknown-property",
                    "unknown dependency-evidence option",
                );
            }
        }
        return;
    }
    if form == RqlForm::ConfigurationFacts {
        analysis.path(child_path(path, "configuration_facts"), head_range.clone());
        validate_configuration_facts_options(form, args, analysis);
        return;
    }
    if form == RqlForm::ConfigurationAbsence {
        if args.is_empty() {
            analysis.error(
                head_range.clone(),
                "wrong-value-shape",
                "configuration-absence expects filter options followed by a query",
            );
        } else {
            analysis.path(
                child_path(path, "configuration_absence"),
                head_range.clone(),
            );
            validate_configuration_facts_options(form, &args[..args.len() - 1], analysis);
        }
    }
    // `correlate` and `require-both` are sources whose arguments are option
    // pairs: two nested queries and, for correlate, one relation form.
    if matches!(form, RqlForm::Correlate | RqlForm::RequireBoth) {
        let label = if form == RqlForm::Correlate {
            "correlate"
        } else {
            "require_both"
        };
        let operator_path = child_path(path, label);
        analysis.path(&operator_path, head_range.clone());
        validate_cross_domain_options(
            form,
            args,
            head_range,
            &operator_path,
            analysis,
            depth,
            plan_budget,
        );
        return;
    }
    let Some(query) = args.last() else {
        return;
    };
    let mut step_path = None;
    if form.query_step_op().is_some() {
        let steps = query_to_json(query)
            .ok()
            .and_then(|value| value.get("steps").and_then(Value::as_array).map(Vec::len))
            .unwrap_or(0);
        let path = format!("{}[{steps}]", child_path(path, "steps"));
        analysis.path(&path, head_range.clone());
        step_path = Some(path);
    }
    match form {
        RqlForm::DependencyEvidence => unreachable!("dependency-evidence is handled as a source"),
        RqlForm::ConfigurationFacts => unreachable!("configuration-facts is handled as a source"),
        RqlForm::ConfigurationAbsence => {
            if args.len() < 2 {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    "configuration-absence expects filter options followed by a query",
                );
            }
        }
        RqlForm::Correlate | RqlForm::RequireBoth => {
            unreachable!("cross-domain operators are handled as sources")
        }
        RqlForm::Filter | RqlForm::Project => {
            let expected = if form == RqlForm::Filter {
                ":where"
            } else {
                ":columns"
            };
            if args.len() != 3 || args[0].as_symbol() != Some(expected) {
                analysis.error(
                    head_range.clone(),
                    "wrong-value-shape",
                    format!(
                        "{} expects {expected}, a bounded value list, and a query",
                        form.label()
                    ),
                );
                return;
            }
            // Record the paths the typed validator reports against, so an
            // error in one predicate or column lands on that source range and
            // not on the step keyword.
            let step_path = step_path.expect("filter and project are query steps");
            let Some(entries) = args[1].as_list() else {
                return;
            };
            for (index, entry) in entries.iter().enumerate() {
                if form == RqlForm::Filter {
                    let predicate_path = format!("{step_path}.where[{index}]");
                    analysis.path(&predicate_path, entry.range.clone());
                    let Some(parts) = entry.as_list() else {
                        continue;
                    };
                    if let Some(field) = parts.first()
                        && let Some(name) = field.as_symbol()
                        && let Some(description) =
                            crate::structural::CodeQueryRowField::rql_help_for_name(name)
                    {
                        analysis.add_help(field.range.clone(), name, description);
                    }
                    for (part, label) in parts.iter().zip(["field", "op", "value"]) {
                        analysis.path(format!("{predicate_path}.{label}"), part.range.clone());
                    }
                    if let Some(operand) = parts.get(2) {
                        let literals: &[Expr] =
                            if parts.get(1).and_then(Expr::as_symbol) == Some("in") {
                                operand.as_sequence().unwrap_or(&[])
                            } else {
                                std::slice::from_ref(operand)
                            };
                        for literal in literals {
                            if let Some((head, range, _)) = list_head(literal)
                                && head == super::super::schema::ROW_ENUM_LITERAL.label
                            {
                                let form = &super::super::schema::ROW_ENUM_LITERAL;
                                analysis.add_help(range, form.signature, form.description);
                            }
                        }
                    }
                    if let Some(members) = parts.get(2).and_then(|value| value.as_list()) {
                        for (member_index, member) in members.iter().enumerate() {
                            analysis.path(
                                format!("{predicate_path}.values[{member_index}]"),
                                member.range.clone(),
                            );
                        }
                    }
                } else {
                    analysis.path(format!("{step_path}.columns[{index}]"), entry.range.clone());
                }
            }
        }
        RqlForm::Anchor => {
            if args.len() != 3 || args[0].as_symbol() != Some(":capture") {
                analysis.error(
                    head_range.clone(),
                    "wrong-value-shape",
                    "anchor expects :capture, a capture name, and a query",
                );
                return;
            }
            let option = QueryStepOp::CaptureAnchor
                .option_for_rql_label(":capture")
                .expect("anchor declares its capture option");
            analysis.add_help(
                args[0].range.clone(),
                option.field().signature(),
                option.field().description(),
            );
            let step_path = step_path.expect("anchor is a query step");
            analysis.path(format!("{step_path}.capture"), args[1].range.clone());
        }
        RqlForm::StatementFacts => {
            validate_statement_facts_wrapper(args, query, analysis);
        }
        RqlForm::CppFacts => validate_cpp_facts_wrapper(args, query, analysis),
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
            let where_path = child_path(path, "where");
            for (index, arg) in values.iter().enumerate() {
                let child = index_path(&where_path, index);
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
            let languages_path = child_path(path, "languages");
            for (index, arg) in values.iter().enumerate() {
                analysis.path(index_path(&languages_path, index), arg.range.clone());
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
                analysis.path(child_path(path, "limit"), value.range.clone());
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
                analysis.path(child_path(path, "result_detail"), args[0].range.clone());
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
                let field_path = child_path(path, field);
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
            let operation_path = child_path(path, form.label());
            for (index, branch) in args.iter().enumerate() {
                validate_rql_query(
                    branch,
                    &index_path(&operation_path, index),
                    analysis,
                    depth + 1,
                    plan_budget,
                );
            }
            return;
        }
        RqlForm::ProgramPointById => {
            if args.len() != 3 {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    "program-point-by-id expects :id, an id string, and a procedure query",
                );
                return;
            }
            let Some(label) = args[0].as_symbol() else {
                analysis.error(
                    args[0].range.clone(),
                    "unknown-property",
                    "program-point-by-id option names must be keywords",
                );
                return;
            };
            let Some(option) = QueryStepOp::ProgramPointById.option_for_rql_label(label) else {
                analysis.error(
                    args[0].range.clone(),
                    "unknown-property",
                    "program-point-by-id accepts only :id",
                );
                return;
            };
            analysis.add_help(
                args[0].range.clone(),
                option.field().signature(),
                option.field().description(),
            );
            let step_path = step_path.expect("program-point-by-id is a query step");
            if args[1].as_string().is_none() {
                analysis.error(
                    args[1].range.clone(),
                    "wrong-value-shape",
                    "program-point-by-id :id must be a string literal",
                );
            } else {
                analysis.path(
                    format!("{step_path}.{}", option.field().label()),
                    args[1].range.clone(),
                );
            }
        }
        RqlForm::EnclosingDecl
        | RqlForm::ProcedureOf
        | RqlForm::ProgramPointOf
        | RqlForm::CfgEntry
        | RqlForm::CfgExits
        | RqlForm::CfgSuccessorEdges
        | RqlForm::CfgPredecessorEdges
        | RqlForm::CfgEdgeSource
        | RqlForm::CfgEdgeTarget
        | RqlForm::FileOf
        | RqlForm::ImportsOf
        | RqlForm::ImportersOf
        | RqlForm::PythonImportSite
        | RqlForm::PythonImportCycles
        | RqlForm::PythonCommentedOutCode
        | RqlForm::Members
        | RqlForm::Owner
        | RqlForm::ClassHierarchy
        | RqlForm::ClassBases
        | RqlForm::ClassMro
        | RqlForm::MroMembers
        | RqlForm::PythonOverrides
        | RqlForm::PythonCallRelations
        | RqlForm::PythonOverrideSignatures
        | RqlForm::PythonDocumentation
        | RqlForm::PythonUselessClass
        | RqlForm::PythonAttributeShadowsMethod
        | RqlForm::PythonModificationOfDefaultValue
        | RqlForm::PythonOverlyComplexDelete => {
            if args.len() != 1 {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    format!("{} expects one query", form.label()),
                );
            }
        }
        RqlForm::CppExpressions => {
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
                let field_path = format!("{}[{steps}].protocol_ref", child_path(path, "steps"));
                analysis.path(&field_path, args[1].range.clone());
                match args[1].as_symbol().or_else(|| args[1].as_string()) {
                    Some(value) => {
                        if let Err(error) = value.parse::<crate::refs::ProtocolRef>() {
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
                let field_path = format!("{}[{steps}].plan_ref", child_path(path, "steps"));
                analysis.path(&field_path, args[1].range.clone());
                match args[1].as_symbol().or_else(|| args[1].as_string()) {
                    Some(value) => {
                        if let Err(error) = value.parse::<crate::refs::ValueFlowPlanRef>() {
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
                let field_path = format!("{}[{steps}].taint_ref", child_path(path, "steps"));
                analysis.path(&field_path, args[1].range.clone());
                match args[1].as_symbol().or_else(|| args[1].as_string()) {
                    Some(value) => {
                        if let Err(error) = value.parse::<crate::refs::TaintResultRef>() {
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
        RqlForm::AbsentMember => {
            let options = &args[..args.len().saturating_sub(1)];
            if !options.len().is_multiple_of(2) {
                analysis.error(
                    head_range.clone(),
                    "wrong-value-shape",
                    "absent-member expects option/value pairs followed by a query",
                );
            }
            let steps = query_to_json(query)
                .ok()
                .and_then(|value| value.get("steps").and_then(Value::as_array).map(Vec::len))
                .unwrap_or(0);
            let step_path = format!("{}[{steps}]", child_path(path, "steps"));
            let mut seen = std::collections::HashSet::new();
            for pair in options.as_chunks::<2>().0 {
                let Some(option) = pair[0]
                    .as_symbol()
                    .and_then(|label| QueryStepOp::AbsentMember.option_for_rql_label(label))
                else {
                    analysis.error(
                        pair[0].range.clone(),
                        "unknown-property",
                        "absent-member accepts only :proof",
                    );
                    continue;
                };
                let field = option.field();
                analysis.add_help(
                    pair[0].range.clone(),
                    field.signature(),
                    field.description(),
                );
                if !seen.insert(field) {
                    analysis.error(
                        pair[0].range.clone(),
                        "duplicate-property",
                        "duplicate absent-member option ':proof'",
                    );
                }
                analysis.path(
                    format!("{step_path}.{}", field.label()),
                    pair[1].range.clone(),
                );
                let allowed = constrained_step_option_labels(field);
                match pair[1].as_symbol().or_else(|| pair[1].as_string()) {
                    Some(label) if allowed.contains(&label) => {}
                    Some(label) => analysis.error(
                        pair[1].range.clone(),
                        "invalid-query-step-option",
                        format!(
                            "unknown proof tier '{label}'; expected one of {}",
                            allowed.join(", ")
                        ),
                    ),
                    None => analysis.error(
                        pair[1].range.clone(),
                        "wrong-value-shape",
                        format!("proof must be one of {}", allowed.join(", ")),
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
            let step_path = format!("{}[{steps}]", child_path(path, "steps"));
            let mut seen = std::collections::HashSet::new();
            for pair in options.as_chunks::<2>().0 {
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
        RqlForm::ResolvedCall => validate_resolved_call_wrapper(args, query, path, analysis),
        RqlForm::ResolvedValue => validate_resolved_value_wrapper(args, query, path, analysis),
        RqlForm::CallArgument => validate_call_argument_wrapper(args, query, path, analysis),
        RqlForm::JsxAttributeValue => validate_jsx_attribute_value_wrapper(args, query, analysis),
        RqlForm::ReceiverTargets | RqlForm::PointsTo | RqlForm::MemberTargets => {
            validate_receiver_wrapper(form, args, query, analysis)
        }
        RqlForm::KeyedReadValue => validate_keyed_read_value_wrapper(args, query, analysis),
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
        RqlForm::BindingOf => validate_environment_options(
            form,
            &args[..args.len().saturating_sub(1)],
            EnvironmentOptionKind::BindingOf,
            analysis,
        ),
        RqlForm::DecoratorBindings => {
            if args.is_empty() {
                analysis.error(
                    head_range.clone(),
                    "wrong-value-shape",
                    "decorator-bindings expects option/value pairs followed by a query",
                );
            }
            validate_decorator_binding_options(&args[..args.len().saturating_sub(1)], analysis);
        }
        RqlForm::DeclarationStateOf => validate_environment_options(
            form,
            &args[..args.len().saturating_sub(1)],
            EnvironmentOptionKind::DeclarationState,
            analysis,
        ),
        RqlForm::EdgesOf | RqlForm::EdgesFrom => {
            validate_edge_wrapper(form, args, query, analysis);
        }
        RqlForm::ResultContractFailureUses
        | RqlForm::StateEventsOf
        | RqlForm::FlowRelationsOf
        | RqlForm::ControlRelations
        | RqlForm::AssignmentRelations
        | RqlForm::CppProvenance
        | RqlForm::LoopRelations
        | RqlForm::StatementReachability
        | RqlForm::BranchRelations
        | RqlForm::RewritePathsOf => {
            validate_constrained_option_wrapper(form, args, query, analysis);
        }
        RqlForm::SegmentsOf => {
            validate_segments_of_options(&args[..args.len().saturating_sub(1)], analysis);
        }
        RqlForm::ScopeOf
        | RqlForm::ScopeAncestors
        | RqlForm::BindingOccurrence
        | RqlForm::BindingUses
        | RqlForm::PythonVariableOf
        | RqlForm::PythonVariableDefinitions
        | RqlForm::PythonVariableUses
        | RqlForm::PythonVariablePeers
        | RqlForm::PythonVariableNestedLoops
        | RqlForm::PythonComparisonConstants
        | RqlForm::PythonComparisonUsingIs
        | RqlForm::PythonComparisonUsingIsNonPortable
        | RqlForm::IdenticalOperands
        | RqlForm::PythonMissingSelf
        | RqlForm::CandidateTarget
        | RqlForm::Generates
        | RqlForm::GeneratedBy
        | RqlForm::ImplementationOf
        | RqlForm::StubsOf
        | RqlForm::ExportTarget
        | RqlForm::EdgeTarget
        | RqlForm::BindingInitializerCallsOf
        | RqlForm::SelectedPropertyRelationsOf
        | RqlForm::FlowSource
        | RqlForm::FlowTarget
        | RqlForm::TargetOf
        | RqlForm::SourceSetOf
        | RqlForm::TopologyEdgesOf
        | RqlForm::GuardsOf
        | RqlForm::FailureHandlerState
        | RqlForm::PendingCleanupFlows
        | RqlForm::SegmentTarget
        | RqlForm::FieldWriteValue
        | RqlForm::ReceiverOutcome
        | RqlForm::ReceiverEvidence
        | RqlForm::PointsToCandidates
        | RqlForm::CallShape
        | RqlForm::ExactExternalCallee
        | RqlForm::CallResults
        | RqlForm::CallArgumentGroups
        | RqlForm::CallArguments
        | RqlForm::CallBindings
        | RqlForm::CppBadStrncpySize
        | RqlForm::CppNetworkToHostFunctionAsArrayBound
        | RqlForm::CppNonConstantFormat
        | RqlForm::CppWrongNumberFormatArguments
        | RqlForm::CppTooManyFormatArguments
        | RqlForm::CppWrongTypeFormatArgument
        | RqlForm::CppNonPortablePrintf
        | RqlForm::CppOverflowingSnprintf
        | RqlForm::CppInconsistentLoopDirection
        | RqlForm::CppUnsafeArrayForDaysOfTheYear
        | RqlForm::CallEffects
        | RqlForm::ResultContractCalls
        | RqlForm::CallResultContracts
        | RqlForm::CallResultObligations
        | RqlForm::ProcedureReturnProfile
        | RqlForm::RustMarkerImplsOf
        | RqlForm::RustPointerFindings
        | RqlForm::PythonIteratorReturnProtocol
        | RqlForm::PythonBuiltinIdentity
        | RqlForm::PythonUninitializedVariable
        | RqlForm::PythonRaiseNotImplemented
        | RqlForm::PythonUnsafeCyclicImport
        | RqlForm::CallResultUse
        | RqlForm::PythonAssertionContext
        | RqlForm::TupleReturnAssignment
        | RqlForm::PythonImplicitStringConcatenation
        | RqlForm::TupleReturnGroups
        | RqlForm::LambdaForwarding
        | RqlForm::PythonFormatIssues
        | RqlForm::PythonUrlConstruction
        | RqlForm::PythonRaiseLegality
        | RqlForm::PythonSpecialMethodRaise
        | RqlForm::ResultContractUses
        | RqlForm::ResultSubjectUses
        | RqlForm::ResultContractOperationUses
        | RqlForm::NilnessOperations
        | RqlForm::SwitchCoverage
        | RqlForm::ClassSet
        | RqlForm::DetachedTaskTransfers
        | RqlForm::ProcedureEffects
        | RqlForm::CallableSignature
        | RqlForm::LiteralOccurrences
        | RqlForm::CallableMetrics
        | RqlForm::SignatureParameters
        | RqlForm::CallableApplicability
        | RqlForm::OverloadSelection
        | RqlForm::MemberSelection
        | RqlForm::CandidateHierarchy
        | RqlForm::DispatchOutcome
        | RqlForm::DispatchTargets
        | RqlForm::MemberFamily
        | RqlForm::FamilyEdges => {
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
        | RqlForm::StringValue
        | RqlForm::NameRegex
        | RqlForm::TextRegex
        | RqlForm::BooleanValue
        | RqlForm::DuplicateKey
        | RqlForm::Index
        | RqlForm::Async
        | RqlForm::UnsafeContext
        | RqlForm::Modifier
        | RqlForm::StringValueRegex
        | RqlForm::Not
        | RqlForm::All
        | RqlForm::Any
        | RqlForm::LocalValue
        | RqlForm::Capture
        | RqlForm::Has
        | RqlForm::NotHas
        | RqlForm::NotKind
        | RqlForm::Arity
        | RqlForm::Visibility
        | RqlForm::ParameterType
        | RqlForm::ParameterTypeRegex
        | RqlForm::Parenthesized
        | RqlForm::IntegerValue
        | RqlForm::IntegerHasAnyBits
        | RqlForm::IntegerHasAllBits
        | RqlForm::IntegerHasNoBits
        | RqlForm::AssignmentTargetKind
        | RqlForm::AssignmentValueKind
        | RqlForm::AssignmentTargetUnstarredCount
        | RqlForm::AssignmentValueUnstarredCount
        | RqlForm::AssignmentTargetStarred
        | RqlForm::AssignmentValueStarred
        | RqlForm::AssignmentUnstarredCountMismatch
        | RqlForm::BodyState
        | RqlForm::BodyOwner => {
            unreachable!("predicate cannot be a query wrapper")
        }
        RqlForm::ConfigurationKey
        | RqlForm::ConfigurationCode
        | RqlForm::DependencyConfiguration
        | RqlForm::LanguageRule => {
            unreachable!("relation forms are not query wrappers")
        }
    }
    validate_rql_query(query, path, analysis, depth, plan_budget);
}

fn validate_statement_facts_wrapper(args: &[Expr], query: &Expr, analysis: &mut Analysis) {
    if args.len() != 3 || args[0].as_symbol() != Some(":kind") {
        analysis.error(
            query.range.clone(),
            "wrong-value-shape",
            "statement-facts expects :kind RULE followed by a query",
        );
        return;
    }
    let field = QueryStepField::StatementFactKind;
    analysis.add_help(
        args[0].range.clone(),
        field.signature(),
        field.description(),
    );
    let Some(label) = args[1].as_symbol().or_else(|| args[1].as_string()) else {
        analysis.error(
            args[1].range.clone(),
            "wrong-value-shape",
            "statement-facts kind must be a rule label",
        );
        return;
    };
    let allowed = super::schema::constrained_step_option_labels(field);
    if !allowed.contains(&label) {
        analysis.error(
            args[1].range.clone(),
            "invalid-query-step-option",
            format!(
                "unknown statement fact kind '{label}'; expected one of {}",
                allowed.join(", ")
            ),
        );
    }
}

fn validate_cpp_facts_wrapper(args: &[Expr], query: &Expr, analysis: &mut Analysis) {
    if args.len() != 3 || args[0].as_symbol() != Some(":kind") {
        analysis.error(
            query.range.clone(),
            "wrong-value-shape",
            "cpp-facts expects :kind RULE followed by a query",
        );
        return;
    }
    let field = QueryStepField::CppFactKind;
    analysis.add_help(
        args[0].range.clone(),
        field.signature(),
        field.description(),
    );
    let Some(label) = args[1].as_symbol().or_else(|| args[1].as_string()) else {
        analysis.error(
            args[1].range.clone(),
            "wrong-value-shape",
            "cpp-facts kind must be a rule label",
        );
        return;
    };
    let allowed = super::schema::constrained_step_option_labels(field);
    if !allowed.contains(&label) {
        analysis.error(
            args[1].range.clone(),
            "invalid-query-step-option",
            format!(
                "unknown C++ fact kind '{label}'; expected one of {}",
                allowed.join(", ")
            ),
        );
    }
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
    for pair in args.as_chunks::<2>().0 {
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
    for pair in args.as_chunks::<2>().0 {
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

fn validate_jsx_attribute_value_wrapper(args: &[Expr], query: &Expr, analysis: &mut Analysis) {
    let options = &args[..args.len().saturating_sub(1)];
    if !options.len().is_multiple_of(2) {
        analysis.error(
            options
                .last()
                .map_or_else(|| query.range.clone(), |arg| arg.range.clone()),
            "wrong-value-shape",
            "jsx-attribute-value expects option/value pairs followed by a query",
        );
        return;
    }
    let accepted = QueryStepOp::JsxAttributeValue
        .options()
        .iter()
        .flat_map(|option| option.rql_labels().iter().copied())
        .collect::<Vec<_>>()
        .join(", ");
    let mut seen = HashSet::new();
    for pair in options.as_chunks::<2>().0 {
        let Some(label) = pair[0].as_symbol() else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "jsx-attribute-value option names must be keywords",
            );
            continue;
        };
        let Some(option) = QueryStepOp::JsxAttributeValue.option_for_rql_label(label) else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                format!("unknown jsx-attribute-value option '{label}'; expected {accepted}"),
            );
            continue;
        };
        if !seen.insert(option.field()) {
            analysis.error(
                pair[0].range.clone(),
                "duplicate-property",
                format!("duplicate property '{}'", option.field().label()),
            );
        }
        analysis.add_help(
            pair[0].range.clone(),
            option.field().signature(),
            option.field().description(),
        );
        match option.field() {
            QueryStepField::Identity => {
                let Some(label) = pair[1].as_symbol().or_else(|| pair[1].as_string()) else {
                    analysis.error(
                        pair[1].range.clone(),
                        "wrong-value-shape",
                        "identity must be intrinsic, component, or unknown",
                    );
                    continue;
                };
                if jsx_element_identity_from_label(label).is_none() {
                    analysis.error(
                        pair[1].range.clone(),
                        "unknown-value",
                        "identity must be intrinsic, component, or unknown",
                    );
                }
            }
            QueryStepField::ElementName | QueryStepField::PropertyName => {
                if pair[1]
                    .as_symbol()
                    .or_else(|| pair[1].as_string())
                    .is_none()
                {
                    analysis.error(
                        pair[1].range.clone(),
                        "wrong-value-shape",
                        format!("{} must be a name string or symbol", option.field().label()),
                    );
                }
            }
            _ => unreachable!("jsx-attribute-value registry contains only its three options"),
        }
    }
    if args.is_empty() {
        analysis.error(
            query.range.clone(),
            "wrong-value-shape",
            "jsx-attribute-value expects a query",
        );
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

fn validate_keyed_read_value_wrapper(args: &[Expr], query: &Expr, analysis: &mut Analysis) {
    let options = &args[..args.len().saturating_sub(1)];
    if !options.len().is_multiple_of(2) {
        analysis.error(
            query.range.clone(),
            "wrong-value-shape",
            "keyed-read-value expects option/value pairs followed by a query",
        );
        return;
    }
    let accepted = QueryStepOp::KeyedReadValue
        .options()
        .iter()
        .flat_map(|option| option.rql_labels().iter().copied())
        .collect::<Vec<_>>()
        .join(", ");
    let mut seen = HashSet::new();
    let mut property = false;
    let mut index = None;
    let mut key_kind = None;
    let mut index_min = None;
    let mut index_max = None;
    let mut container = None;
    let mut runtime_label = None;
    let mut global_label = None;
    for pair in options.as_chunks::<2>().0 {
        let Some(label) = pair[0].as_symbol() else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "keyed-read-value option names must be keywords",
            );
            continue;
        };
        let Some(option) = QueryStepOp::KeyedReadValue.option_for_rql_label(label) else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                format!("unknown keyed-read-value option '{label}'; expected {accepted}"),
            );
            continue;
        };
        if !seen.insert(option.field()) {
            analysis.error(
                pair[0].range.clone(),
                "duplicate-property",
                format!("duplicate property '{}'", option.field().label()),
            );
        }
        analysis.add_help(
            pair[0].range.clone(),
            option.field().signature(),
            option.field().description(),
        );
        match option.field() {
            QueryStepField::Runtime => {
                let value = pair[1].as_symbol().or_else(|| pair[1].as_string());
                if value.is_some_and(|value| {
                    super::schema::RuntimeKeyedReadRoot::family_labels().contains(&value)
                }) {
                    runtime_label = value.map(str::to_owned);
                } else {
                    analysis.error(
                        pair[1].range.clone(),
                        "unknown-value",
                        format!(
                            "runtime must be one of {}",
                            super::schema::RuntimeKeyedReadRoot::family_labels().join(", ")
                        ),
                    );
                }
            }
            QueryStepField::Global => {
                let accepted = runtime_label.as_deref().map_or_else(
                    || {
                        super::schema::RUNTIME_KEYED_READ_ROOTS
                            .iter()
                            .map(|root| root.global.label())
                            .collect::<Vec<_>>()
                    },
                    super::schema::RuntimeKeyedReadRoot::global_labels,
                );
                let value = pair[1].as_symbol().or_else(|| pair[1].as_string());
                if value.is_some_and(|value| accepted.contains(&value)) {
                    global_label = value.map(str::to_owned);
                } else {
                    analysis.error(
                        pair[1].range.clone(),
                        "unknown-value",
                        format!("global must be one of {}", accepted.join(", ")),
                    );
                }
            }
            QueryStepField::Container => {
                let accepted = match (runtime_label.as_deref(), global_label.as_deref()) {
                    (Some(runtime), Some(global)) => {
                        super::schema::RuntimeKeyedReadRoot::container_labels(runtime, global)
                    }
                    _ => super::schema::RUNTIME_KEYED_READ_ROOTS
                        .iter()
                        .map(|root| root.container.label())
                        .collect::<Vec<_>>(),
                };
                let value = pair[1].as_symbol().or_else(|| pair[1].as_string());
                if let Some(value) = value.filter(|value| accepted.contains(value)) {
                    container = Some((value.to_owned(), pair[1].range.clone()));
                } else {
                    analysis.error(
                        pair[1].range.clone(),
                        "unknown-value",
                        format!("container must be one of {}", accepted.join(", ")),
                    );
                }
            }
            QueryStepField::Property => {
                property = true;
                if pair[1]
                    .as_symbol()
                    .or_else(|| pair[1].as_string())
                    .is_none()
                {
                    analysis.error(
                        pair[1].range.clone(),
                        "wrong-value-shape",
                        "property must be a name",
                    );
                }
            }
            QueryStepField::Index => {
                if let Some(value) = pair[1].as_number() {
                    index = Some((value, pair[1].range.clone()));
                } else {
                    analysis.error(
                        pair[1].range.clone(),
                        "wrong-value-shape",
                        "index must be a non-negative integer",
                    );
                }
            }
            QueryStepField::KeyKind => {
                let Some(label) = pair[1].as_symbol().or_else(|| pair[1].as_string()) else {
                    analysis.error(
                        pair[1].range.clone(),
                        "wrong-value-shape",
                        "key-kind must be static-property or static-index",
                    );
                    continue;
                };
                let Some(kind) = super::schema::RuntimeKeyKind::from_label(label) else {
                    analysis.error(
                        pair[1].range.clone(),
                        "unknown-value",
                        "key-kind must be static-property or static-index",
                    );
                    continue;
                };
                key_kind = Some((kind, pair[1].range.clone()));
            }
            QueryStepField::IndexMin | QueryStepField::IndexMax => {
                let target = if option.field() == QueryStepField::IndexMin {
                    &mut index_min
                } else {
                    &mut index_max
                };
                if let Some(value) = pair[1].as_number() {
                    *target = Some((value, pair[1].range.clone()));
                } else {
                    analysis.error(
                        pair[1].range.clone(),
                        "wrong-value-shape",
                        "index bound must be a non-negative integer",
                    );
                }
            }
            QueryStepField::SourceOrigin => {
                if pair[1].as_symbol().or_else(|| pair[1].as_string()) != Some("pristine_input") {
                    analysis.error(
                        pair[1].range.clone(),
                        "unknown-value",
                        "source-origin must be pristine_input",
                    );
                }
            }
            _ => unreachable!("keyed-read-value registry contains only its options"),
        }
    }
    let exact_count = property as usize + index.is_some() as usize;
    if exact_count > 0 && key_kind.is_some() {
        analysis.error(
            query.range.clone(),
            "wrong-value-shape",
            "keyed-read-value accepts either :property/:index or :key-kind, not both",
        );
    }
    if exact_count == 2 || (exact_count == 0 && key_kind.is_none()) {
        analysis.error(
            query.range.clone(),
            "wrong-value-shape",
            "keyed-read-value requires exactly one exact selector or :key-kind",
        );
    }
    if let Some((kind, range)) = &key_kind {
        if *kind == super::schema::RuntimeKeyKind::StaticProperty
            && (index_min.is_some() || index_max.is_some())
        {
            analysis.error(
                range.clone(),
                "wrong-value-shape",
                "index bounds require :key-kind static-index",
            );
        }
    } else if index_min.is_some() || index_max.is_some() {
        analysis.error(
            query.range.clone(),
            "wrong-value-shape",
            "index bounds require :key-kind static-index",
        );
    }
    if let (Some((min, min_range)), Some((max, _))) = (&index_min, &index_max)
        && min > max
    {
        analysis.error(
            min_range.clone(),
            "invalid-query",
            "index-min must not exceed index-max",
        );
    }
    for required in [
        QueryStepField::Runtime,
        QueryStepField::Global,
        QueryStepField::Container,
    ] {
        if !seen.contains(&required) {
            analysis.error(
                query.range.clone(),
                "missing-property",
                format!("keyed-read-value requires {}", required.signature()),
            );
        }
    }
    // How a container's elements are addressed is a property of the reviewed
    // container, so the accepted selector comes from the vocabulary table
    // rather than from a container name spelled here.
    if let (Some(runtime), Some(global), Some((container, range))) = (
        runtime_label.as_deref(),
        global_label.as_deref(),
        container.as_ref(),
    ) && let Some(root) =
        super::schema::RuntimeKeyedReadRoot::for_labels(runtime, global, container)
    {
        let requires_property = root.key_kind == super::schema::RuntimeKeyKind::StaticProperty;
        let selects_property = key_kind.as_ref().map_or(property, |(kind, _)| {
            *kind == super::schema::RuntimeKeyKind::StaticProperty
        });
        if selects_property != requires_property {
            analysis.error(
                range.clone(),
                "wrong-value-shape",
                format!("{container} requires a {} selector", root.key_kind.label()),
            );
        }
    }
    if let Some((container, _)) = &container
        && container == "argv"
    {
        let max_index = u64::from(u32::MAX - 1);
        let out_of_range = index
            .as_ref()
            .filter(|(value, _)| *value > max_index)
            .map(|(_, range)| range.clone())
            .or_else(|| {
                index_min
                    .as_ref()
                    .filter(|(value, _)| *value > max_index)
                    .map(|(_, range)| range.clone())
            })
            .or_else(|| {
                index_max
                    .as_ref()
                    .filter(|(value, _)| *value > max_index)
                    .map(|(_, range)| range.clone())
            });
        if let Some(range) = out_of_range {
            analysis.error(
                range,
                "invalid-query",
                "argv index must be at most 4294967294",
            );
        }
    }
    if args.is_empty() {
        analysis.error(
            query.range.clone(),
            "wrong-value-shape",
            "keyed-read-value expects a query",
        );
    }
}

fn wrapper_option_pairs<'a>(
    form: RqlForm,
    args: &'a [Expr],
    query: &Expr,
    analysis: &mut Analysis,
) -> Option<&'a [Expr]> {
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
        None
    } else {
        Some(options)
    }
}

fn even_option_pairs(
    options: &[Expr],
    message: impl FnOnce() -> String,
    analysis: &mut Analysis,
) -> bool {
    if options.len().is_multiple_of(2) {
        return true;
    }
    analysis.error(
        options
            .last()
            .expect("an odd option count has a last element")
            .range
            .clone(),
        "wrong-value-shape",
        message(),
    );
    false
}

fn validate_call_wrapper(form: RqlForm, args: &[Expr], query: &Expr, analysis: &mut Analysis) {
    let Some(options) = wrapper_option_pairs(form, args, query, analysis) else {
        return;
    };
    let permits_depth = matches!(form, RqlForm::Callers | RqlForm::Callees);
    let mut seen = HashSet::new();
    for pair in options.as_chunks::<2>().0 {
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
    if !even_option_pairs(
        options,
        || {
            format!(
                "{} expects {} option/value pairs",
                form.label(),
                kind.accepted()
            )
        },
        analysis,
    ) {
        return;
    }
    let mut seen = HashSet::new();
    for pair in options.as_chunks::<2>().0 {
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

fn validate_decorator_binding_options(options: &[Expr], analysis: &mut Analysis) {
    if !even_option_pairs(
        options,
        || {
            "decorator-bindings expects :module and :imported-name option/value pairs followed by a query"
                .to_string()
        },
        analysis,
    ) {
        return;
    }
    let mut seen = HashSet::new();
    for pair in options.as_chunks::<2>().0 {
        let Some(label) = pair[0].as_symbol() else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "decorator-binding filter option names must be keywords",
            );
            continue;
        };
        let Some(option) = DECORATOR_BINDING_STEP_OPTIONS
            .iter()
            .copied()
            .find(|option| option.accepts_rql_label(label))
        else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "decorator-bindings accepts only :module and :imported-name",
            );
            continue;
        };
        let field = option.field();
        if !seen.insert(field) {
            analysis.error(
                pair[0].range.clone(),
                "duplicate-property",
                format!("duplicate decorator-binding filter option '{label}'"),
            );
            continue;
        }
        analysis.add_help(
            pair[0].range.clone(),
            field.signature(),
            field.description(),
        );
        let text = match &pair[1].kind {
            ExprKind::String(text) | ExprKind::Symbol(text) => text,
            _ => {
                analysis.error(
                    pair[1].range.clone(),
                    "wrong-value-shape",
                    format!("{label} requires an exact string value"),
                );
                continue;
            }
        };
        if text.is_empty() || text.len() > MAX_DECORATOR_BINDING_FILTER_LENGTH {
            analysis.error(
                pair[1].range.clone(),
                "wrong-value-shape",
                format!(
                    "{label} must be between 1 and {MAX_DECORATOR_BINDING_FILTER_LENGTH} bytes"
                ),
            );
        }
    }
}

fn validate_occurrence_options(form: RqlForm, options: &[Expr], analysis: &mut Analysis) {
    if !even_option_pairs(
        options,
        || {
            format!(
                "{} expects :class, :role, and :namespace option/value pairs",
                form.label()
            )
        },
        analysis,
    ) {
        return;
    }
    let mut seen = HashSet::new();
    for pair in options.as_chunks::<2>().0 {
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

fn validate_resolved_call_wrapper(
    args: &[Expr],
    query: &Expr,
    path: &str,
    analysis: &mut Analysis,
) {
    let options = &args[..args.len().saturating_sub(1)];
    if options.len() < 4 || !options.len().is_multiple_of(2) {
        analysis.error(
            query.range.clone(),
            "wrong-value-shape",
            "resolved-call expects :resolves-to, :proof, an optional :receiver-type, and a query",
        );
        return;
    }
    let steps = query_to_json(query)
        .ok()
        .and_then(|value| value.get("steps").and_then(Value::as_array).map(Vec::len))
        .unwrap_or(0);
    let step_path = format!("{}[{steps}]", child_path(path, "steps"));
    let mut seen = HashSet::new();
    for pair in options.as_chunks::<2>().0 {
        let Some(label) = pair[0].as_symbol() else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "resolved-call option names must be keywords",
            );
            continue;
        };
        let Some(option) = QueryStepOp::ResolvedCall.option_for_rql_label(label) else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "resolved-call accepts only :resolves-to, :proof, and :receiver-type",
            );
            continue;
        };
        if !seen.insert(option.field()) {
            analysis.error(
                pair[0].range.clone(),
                "duplicate-property",
                format!("duplicate resolved-call option {label}"),
            );
        }
        analysis.add_help(
            pair[0].range.clone(),
            option.field().signature(),
            option.field().description(),
        );
        analysis.path(
            format!("{step_path}.{}", option.field().label()),
            pair[1].range.clone(),
        );
        match option.field() {
            QueryStepField::ResolvesTo => {
                let valid = match &pair[1].kind {
                    ExprKind::String(value) | ExprKind::Symbol(value) => {
                        !value.is_empty() && value.len() <= MAX_STRING_PREDICATE_LENGTH
                    }
                    _ => false,
                };
                if !valid {
                    analysis.error(
                        pair[1].range.clone(),
                        "wrong-value-shape",
                        "call identity must be a non-empty bounded stable symbol or quoted qualified locator",
                    );
                }
            }
            QueryStepField::ReceiverType => match &pair[1].kind {
                ExprKind::String(value) | ExprKind::Symbol(value)
                    if !value.is_empty() && value.len() <= MAX_STRING_PREDICATE_LENGTH => {}
                ExprKind::List(items) if items.len() == 2 => {
                    let form = items[0]
                        .as_symbol()
                        .and_then(ReceiverTypeConstraintForm::from_rql_label);
                    if let Some(form) = form {
                        analysis.add_help(
                            items[0].range.clone(),
                            form.signature(),
                            form.description(),
                        );
                    } else {
                        analysis.error(
                            items[0].range.clone(),
                            "unknown-value",
                            "receiver family constraint must use assignable-to",
                        );
                    }
                    analysis.path(
                        format!("{step_path}.receiver_type.assignable_to"),
                        items[1].range.clone(),
                    );
                    if !matches!(
                        &items[1].kind,
                        ExprKind::String(value) | ExprKind::Symbol(value)
                            if !value.is_empty()
                                && value.len() <= MAX_STRING_PREDICATE_LENGTH
                    ) {
                        analysis.error(
                            items[1].range.clone(),
                            "wrong-value-shape",
                            "assignable-to root must be a non-empty bounded stable symbol or quoted qualified locator",
                        );
                    }
                }
                _ => analysis.error(
                    pair[1].range.clone(),
                    "wrong-value-shape",
                    "receiver type must be an exact call identity or (assignable-to identity)",
                ),
            },
            QueryStepField::CallProof => {
                if !matches!(pair[1].as_symbol(), Some("exact" | "declared")) {
                    analysis.error(
                        pair[1].range.clone(),
                        "unknown-value",
                        "resolved-call proof must be exact or declared",
                    );
                }
            }
            _ => unreachable!("resolved-call registry contains only its three options"),
        }
    }
    for required in [QueryStepField::ResolvesTo, QueryStepField::CallProof] {
        if !seen.contains(&required) {
            analysis.error(
                query.range.clone(),
                "missing-property",
                format!("resolved-call requires {}", required.signature()),
            );
        }
    }
}

fn validate_resolved_value_wrapper(
    args: &[Expr],
    query: &Expr,
    path: &str,
    analysis: &mut Analysis,
) {
    let options = &args[..args.len().saturating_sub(1)];
    if options.len() != 4 {
        analysis.error(
            query.range.clone(),
            "wrong-value-shape",
            "resolved-value expects :resolves-to, :proof, and a query",
        );
        return;
    }
    let steps = query_to_json(query)
        .ok()
        .and_then(|value| value.get("steps").and_then(Value::as_array).map(Vec::len))
        .unwrap_or(0);
    let step_path = format!("{}[{steps}]", child_path(path, "steps"));
    let mut seen = HashSet::new();
    for pair in options.as_chunks::<2>().0 {
        let Some(label) = pair[0].as_symbol() else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "resolved-value option names must be keywords",
            );
            continue;
        };
        let Some(option) = QueryStepOp::ResolvedValue.option_for_rql_label(label) else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "resolved-value accepts only :resolves-to and :proof",
            );
            continue;
        };
        if !seen.insert(option.field()) {
            analysis.error(
                pair[0].range.clone(),
                "duplicate-property",
                format!("duplicate resolved-value option {label}"),
            );
        }
        let (signature, description) = match option.field() {
            QueryStepField::CallProof => (
                ":proof exact",
                "Require exact identity proof for the selected value.",
            ),
            _ => (option.field().signature(), option.field().description()),
        };
        analysis.add_help(pair[0].range.clone(), signature, description);
        analysis.path(
            format!("{step_path}.{}", option.field().label()),
            pair[1].range.clone(),
        );
        match option.field() {
            QueryStepField::ResolvesTo => {
                let valid = match &pair[1].kind {
                    ExprKind::String(value) | ExprKind::Symbol(value) => {
                        !value.is_empty() && value.len() <= MAX_STRING_PREDICATE_LENGTH
                    }
                    _ => false,
                };
                if !valid {
                    analysis.error(
                        pair[1].range.clone(),
                        "wrong-value-shape",
                        "value identity must be a non-empty bounded stable symbol or quoted qualified locator",
                    );
                }
            }
            QueryStepField::CallProof => {
                if !matches!(pair[1].as_symbol(), Some("exact")) {
                    analysis.error(
                        pair[1].range.clone(),
                        "unknown-value",
                        "resolved-value proof must be exact",
                    );
                }
            }
            _ => unreachable!("resolved-value registry contains only its two options"),
        }
    }
    for required in [QueryStepField::ResolvesTo, QueryStepField::CallProof] {
        if !seen.contains(&required) {
            analysis.error(
                query.range.clone(),
                "missing-property",
                format!("resolved-value requires {}", required.signature()),
            );
        }
    }
}

fn validate_call_argument_wrapper(
    args: &[Expr],
    query: &Expr,
    path: &str,
    analysis: &mut Analysis,
) {
    if args.len() != 3 {
        analysis.error(
            query.range.clone(),
            "wrong-value-shape",
            "call-argument expects one formal selector followed by a query",
        );
        return;
    }
    let Some(label) = args[0].as_symbol() else {
        analysis.error(
            args[0].range.clone(),
            "unknown-property",
            "call-argument selector must be a keyword",
        );
        return;
    };
    let Some(option) = QueryStepOp::CallArgument.option_for_rql_label(label) else {
        analysis.error(
            args[0].range.clone(),
            "unknown-property",
            "call-argument requires :formal-name or :formal-index",
        );
        return;
    };
    let steps = query_to_json(query)
        .ok()
        .and_then(|value| value.get("steps").and_then(Value::as_array).map(Vec::len))
        .unwrap_or(0);
    analysis.path(
        format!(
            "{}[{steps}].{}",
            child_path(path, "steps"),
            option.field().label()
        ),
        args[1].range.clone(),
    );
    analysis.add_help(
        args[0].range.clone(),
        option.field().signature(),
        option.field().description(),
    );
    match option.field() {
        QueryStepField::FormalName => match &args[1].kind {
            ExprKind::String(name) | ExprKind::Symbol(name) => {
                validate_parameter_name(name, args[1].range.clone(), analysis);
            }
            _ => analysis.error(
                args[1].range.clone(),
                "wrong-value-shape",
                "formal name must be a string or symbol",
            ),
        },
        QueryStepField::FormalIndex => {
            if !matches!(args[1].kind, ExprKind::Number(_)) {
                analysis.error(
                    args[1].range.clone(),
                    "wrong-value-shape",
                    "formal index must be a non-negative integer",
                );
            }
        }
        _ => unreachable!("call-argument registry contains only its two options"),
    }
}

fn validate_reference_wrapper(form: RqlForm, args: &[Expr], query: &Expr, analysis: &mut Analysis) {
    let Some(options) = wrapper_option_pairs(form, args, query, analysis) else {
        return;
    };

    let mut seen = HashSet::new();
    for pair in options.as_chunks::<2>().0 {
        let key = &pair[0];
        let value = &pair[1];
        let Some((canonical, _)) =
            canonical_keyword_option(key, "reference traversal", &mut seen, analysis)
        else {
            continue;
        };
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
    let Some(options) = wrapper_option_pairs(form, args, query, analysis) else {
        return;
    };

    let mut seen = HashSet::new();
    for pair in options.as_chunks::<2>().0 {
        let key = &pair[0];
        let value = &pair[1];
        let Some((canonical, _)) =
            canonical_keyword_option(key, "edge traversal", &mut seen, analysis)
        else {
            continue;
        };
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

fn canonical_keyword_option<'a>(
    key: &'a Expr,
    noun: &str,
    seen: &mut HashSet<String>,
    analysis: &mut Analysis,
) -> Option<(String, &'a str)> {
    let Some(label) = key.as_symbol().and_then(|symbol| symbol.strip_prefix(':')) else {
        analysis.error(
            key.range.clone(),
            "unknown-property",
            format!("{noun} option names must be keywords"),
        );
        return None;
    };
    let canonical = label.replace('-', "_");
    if !seen.insert(canonical.clone()) {
        analysis.error(
            key.range.clone(),
            "duplicate-property",
            format!("duplicate {noun} option '{label}'"),
        );
        return None;
    }
    Some((canonical, label))
}

/// Validate the option pairs of wrappers whose options are schema-registered
/// lists of constrained labels, including flow/control relations, rewrite
/// paths, and result-contract failure uses.
///
/// Every accepted spelling, every allowed value, and every help string is read
/// from the schema registry, so a vocabulary change cannot leave the editor
/// surface behind. An unknown value reports the whole allowed set, on the
/// value's own range, which is what a validation-range diagnostic is for.
fn validate_constrained_option_wrapper(
    form: RqlForm,
    args: &[Expr],
    query: &Expr,
    analysis: &mut Analysis,
) {
    let op = form
        .query_step_op()
        .expect("constrained-option wrappers declare a query step");
    let Some(options) = wrapper_option_pairs(form, args, query, analysis) else {
        return;
    };

    let accepted = op
        .options()
        .iter()
        .flat_map(|option| option.rql_labels().iter().copied())
        .collect::<Vec<_>>()
        .join(", ");
    let mut seen = HashSet::new();
    for pair in options.as_chunks::<2>().0 {
        let key = &pair[0];
        let value = &pair[1];
        let Some(label) = key.as_symbol() else {
            analysis.error(
                key.range.clone(),
                "unknown-property",
                format!("{} option names must be keywords", form.label()),
            );
            continue;
        };
        let Some(option) = op.option_for_rql_label(label) else {
            analysis.error(
                key.range.clone(),
                "unknown-property",
                format!("{} accepts only {accepted}", form.label()),
            );
            continue;
        };
        if !seen.insert(option.field()) {
            analysis.error(
                key.range.clone(),
                "duplicate-property",
                format!("duplicate {} option '{label}'", form.label()),
            );
            continue;
        }
        let allowed = constrained_step_option_labels(option.field());
        analysis.add_help(
            key.range.clone(),
            option.field().signature(),
            option.field().description(),
        );
        validate_constrained_label_vector(value, option.field().label(), &allowed, analysis);
    }
}

/// Validate one vector of constrained labels, reporting the allowed set on the
/// offending value's own range.
fn validate_constrained_label_vector(
    value: &Expr,
    noun: &str,
    allowed: &[&'static str],
    analysis: &mut Analysis,
) {
    validate_label_vector(value, noun, analysis, |item, label, canonical, analysis| {
        if !allowed.contains(&canonical) {
            analysis.error(
                item.range.clone(),
                "invalid-query-step-option",
                format!(
                    "unknown {noun} '{label}'; expected one of {}",
                    allowed.join(", ")
                ),
            );
        }
    });
}

fn validate_rql_label_vector<T>(
    value: &Expr,
    noun: &str,
    parse: impl Fn(&str) -> Option<T>,
    analysis: &mut Analysis,
) {
    validate_label_vector(value, noun, analysis, |item, label, canonical, analysis| {
        if parse(canonical).is_none() {
            analysis.error(
                item.range.clone(),
                "invalid-query-step-option",
                format!("unknown {noun} '{label}'"),
            );
        }
    });
}

fn validate_label_vector(
    value: &Expr,
    noun: &str,
    analysis: &mut Analysis,
    mut validate_label: impl FnMut(&Expr, &str, &str, &mut Analysis),
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
        validate_label(item, label, &canonical, analysis);
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
    // Arity is the one predicate whose paren form takes more than a single
    // value: `(arity :min .. :max ..)` carries keyword bounds.
    if form == RqlForm::Arity {
        validate_arity_predicate_args(
            args,
            &head_range,
            &rql_property_path(path, RqlProperty::Arity),
            analysis,
        );
        record_duplicate(RqlProperty::Arity.label(), head_range, seen, analysis);
        return;
    }
    if matches!(form, RqlForm::All | RqlForm::Any) {
        if args.is_empty() {
            analysis.error(
                head_range.clone(),
                "wrong-value-shape",
                format!("{} expects at least one pattern", form.label()),
            );
        } else {
            let property = form
                .property()
                .expect("boolean composition forms have an explicit property lowering");
            for (index, arg) in args.iter().enumerate() {
                let child = format!("{}[{}]", rql_property_path(path, property), index);
                validate_rql_pattern(arg, &child, analysis);
            }
        }
        record_duplicate(
            form.property()
                .expect("boolean composition forms have an explicit property lowering")
                .label(),
            head_range.clone(),
            seen,
            analysis,
        );
        return;
    }
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

/// Validate the tail of an `(arity ...)` predicate: a single non-negative
/// integer (exact), or `:min`/`:max` non-negative-integer bounds. Mirrors the
/// sexp lowering so the editor rejects what the parser would.
fn validate_arity_predicate_args(
    args: &[Expr],
    head_range: &Range<usize>,
    path: &str,
    analysis: &mut Analysis,
) {
    analysis.path(path, head_range.clone());
    if let [only] = args
        && matches!(only.kind, ExprKind::Number(_))
    {
        validate_arity_scalar(only, analysis);
        return;
    }
    if args.is_empty() || !args.len().is_multiple_of(2) {
        analysis.error(
            head_range.clone(),
            "wrong-value-shape",
            "arity expects a count or :min/:max integer pairs",
        );
        return;
    }
    let mut seen_bounds = HashSet::new();
    let mut min = None;
    let mut max = None;
    for pair in args.as_chunks::<2>().0 {
        let Some(key) = pair[0].as_symbol() else {
            analysis.error(
                pair[0].range.clone(),
                "wrong-value-shape",
                "arity bound names must be :min or :max",
            );
            continue;
        };
        if key != ":min" && key != ":max" {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "arity accepts only :min and :max",
            );
            continue;
        }
        if !seen_bounds.insert(key.to_string()) {
            analysis.error(
                pair[0].range.clone(),
                "duplicate-property",
                format!("duplicate arity bound '{key}'"),
            );
        }
        if let Some(value) = validate_arity_scalar(&pair[1], analysis) {
            if key == ":min" {
                min = Some(value);
            } else {
                max = Some(value);
            }
        }
    }
    if let (Some(min), Some(max)) = (min, max)
        && min > max
    {
        analysis.error(
            head_range.clone(),
            "invalid-query",
            format!("arity :min {min} must not exceed :max {max}"),
        );
    }
}

fn is_canonical_integer_decimal(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && ((bytes[0] == b'0' && bytes.len() == 1)
            || (matches!(bytes[0], b'1'..=b'9')
                && bytes[1..].iter().all(|byte| byte.is_ascii_digit())))
}

fn validate_permission_bit_mask(value: &Expr, analysis: &mut Analysis) -> Option<u32> {
    let ExprKind::Number(mask) = value.kind else {
        analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            "permission bit mask must be a positive integer",
        );
        return None;
    };
    if mask == 0 || mask > u64::from(u32::MAX) {
        analysis.error(
            value.range.clone(),
            "invalid-query",
            format!("permission bit mask must be between 1 and {}", u32::MAX),
        );
        return None;
    }
    Some(mask as u32)
}

/// Validate one arity integer literal, returning its value when it is a valid
/// non-negative count within [`MAX_ARITY`].
fn validate_arity_scalar(value: &Expr, analysis: &mut Analysis) -> Option<u64> {
    let ExprKind::Number(count) = value.kind else {
        analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            "arity must be a non-negative integer",
        );
        return None;
    };
    if count > u64::from(MAX_ARITY) {
        analysis.error(
            value.range.clone(),
            "invalid-query",
            format!("arity must be at most {MAX_ARITY}"),
        );
        return None;
    }
    Some(count)
}

fn validate_index_scalar(value: &Expr, analysis: &mut Analysis) -> Option<u64> {
    let ExprKind::Number(index) = value.kind else {
        analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            "index must be a non-negative integer",
        );
        return None;
    };
    if index > u64::from(MAX_ARITY) {
        analysis.error(
            value.range.clone(),
            "invalid-query",
            format!("index must be at most {MAX_ARITY}"),
        );
        return None;
    }
    Some(index)
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
    let value_is_role_pattern = label == Role::Value.label() && Role::Value.valid_for(kind);
    if !value_is_role_pattern && let Some(property) = RqlProperty::from_label(label) {
        analysis.add_help(range.clone(), property.signature(), property.description());
        reject_callable_signature_property(property, kind, &range, analysis);
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
        super::schema::ValueShape::CanonicalIntegerDecimal => match &value.kind {
            ExprKind::String(text) if is_canonical_integer_decimal(text) => {
                if text.len() > super::super::ir::MAX_STRING_PREDICATE_LENGTH {
                    analysis.error(
                        value.range.clone(),
                        "invalid-query",
                        "integer_value exceeds the maximum supported string length",
                    );
                }
            }
            ExprKind::String(_) => analysis.error(
                value.range.clone(),
                "invalid-query",
                "integer_value must be a canonical non-negative decimal string",
            ),
            _ => analysis.error(
                value.range.clone(),
                "wrong-value-shape",
                "expected a quoted canonical non-negative decimal integer",
            ),
        },
        super::schema::ValueShape::PermissionBitMask => {
            validate_permission_bit_mask(value, analysis);
        }
        super::schema::ValueShape::ParameterName => {
            unreachable!("parameter names are query-step values, not pattern properties")
        }
        super::schema::ValueShape::CaptureName => {
            unreachable!("capture names are query-step values, not pattern properties")
        }
        super::schema::ValueShape::RegexString => validate_rql_regex(value, &child, analysis),
        super::schema::ValueShape::KindList => validate_kind_value(value, &child, analysis),
        super::schema::ValueShape::AssignmentSequenceKind => {
            let label = match &value.kind {
                ExprKind::Symbol(label) | ExprKind::String(label) => label.as_str(),
                _ => {
                    analysis.error(
                        value.range.clone(),
                        "wrong-value-shape",
                        "expected list or tuple",
                    );
                    return;
                }
            };
            if !matches!(label, "list" | "tuple") {
                analysis.error(
                    value.range.clone(),
                    "invalid-query",
                    "expected list or tuple",
                );
            }
        }
        super::schema::ValueShape::DeclaredVisibilityList => {
            validate_visibility_value(value, &child, analysis)
        }
        super::schema::ValueShape::Arity => {
            validate_arity_scalar(value, analysis);
        }
        super::schema::ValueShape::NonNegativeInteger => {
            validate_index_scalar(value, analysis);
        }
        super::schema::ValueShape::Boolean => match &value.kind {
            ExprKind::Symbol(label) if label == "true" || label == "false" => {}
            _ => analysis.error(
                value.range.clone(),
                "wrong-value-shape",
                "expected true or false",
            ),
        },
        super::schema::ValueShape::Pattern => validate_rql_pattern(value, &child, analysis),
        super::schema::ValueShape::PatternList => validate_pattern_list(value, &child, analysis),
        super::schema::ValueShape::PatternMap
        | super::schema::ValueShape::Query
        | super::schema::ValueShape::QueryList
        | super::schema::ValueShape::QuerySteps
        | super::schema::ValueShape::StringList
        | super::schema::ValueShape::PathScope
        | super::schema::ValueShape::StringPredicate
        | super::schema::ValueShape::RegexPredicate
        | super::schema::ValueShape::LanguageList
        | super::schema::ValueShape::PositiveInteger
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
        | super::schema::ValueShape::StateEventClassList
        | super::schema::ValueShape::StateEventReadCauseList
        | super::schema::ValueShape::FlowSubjectKindList
        | super::schema::ValueShape::FlowRelationList
        | super::schema::ValueShape::FlowCertaintyList
        | super::schema::ValueShape::FailureUseProvenanceList
        | super::schema::ValueShape::FailureUseConsumerList
        | super::schema::ValueShape::RewriteDomainList
        | super::schema::ValueShape::RewriteOutcomeList
        | super::schema::ValueShape::ControlRelationKindList
        | super::schema::ValueShape::AssignmentRelationKindList
        | super::schema::ValueShape::BranchRelationKindList
        | super::schema::ValueShape::CppProvenanceRuleList
        | super::schema::ValueShape::ControlExitPartitionList
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
        | super::schema::ValueShape::ConfigurationFormatList
        | super::schema::ValueShape::ConfigurationNodeKindList
        | super::schema::ValueShape::ConfigurationRoleList
        | super::schema::ValueShape::ConfigurationScalarKindList
        | super::schema::ValueShape::ConfigurationKeyList
        | super::schema::ValueShape::ConfigurationRouteList
        | super::schema::ValueShape::ConfigurationFactOrdinalList
        | super::schema::ValueShape::ConfigurationProvenanceList
        | super::schema::ValueShape::ConfigurationCompletenessList
        | super::schema::ValueShape::DependencyEvidenceFilter
        | super::schema::ValueShape::ConfigurationFactsFilter
        | super::schema::ValueShape::CrossDomainCorrelation
        | super::schema::ValueShape::CrossDomainRequirement
        | super::schema::ValueShape::CrossDomainRelation
        | super::schema::ValueShape::ConfigurationCodeRelation
        | super::schema::ValueShape::CorrelationDocumentList
        | super::schema::ValueShape::DependencyConfigurationRelation
        | super::schema::ValueShape::CorrelationOverrideList
        | super::schema::ValueShape::RuntimeFamily
        | super::schema::ValueShape::RuntimeGlobal
        | super::schema::ValueShape::RuntimeContainer
        | super::schema::ValueShape::RuntimeSourceOrigin
        | super::schema::ValueShape::RuntimeKeyKind
        | super::schema::ValueShape::CallIdentity
        | super::schema::ValueShape::ReceiverTypeConstraint
        | super::schema::ValueShape::CallProof
        | super::schema::ValueShape::AbsentMemberProof
        | super::schema::ValueShape::RowPredicates
        | super::schema::ValueShape::RowProjectionColumns
        | super::schema::ValueShape::JsxElementIdentity => {
            unreachable!("unsupported value shape for an RQL pattern property")
        }
    }
}

fn rql_property_path(path: &str, property: RqlProperty) -> String {
    let suffix = match property {
        RqlProperty::Name => "name",
        RqlProperty::StringValue => "string_value",
        RqlProperty::NameRegex => "name.regex",
        RqlProperty::TextRegex => "text.regex",
        RqlProperty::CommentBlockRegex => "comment_block_text.regex",
        RqlProperty::BooleanValue => "boolean_value",
        RqlProperty::Async => "async",
        RqlProperty::UnsafeContext => "unsafe_context",
        RqlProperty::Modifier => "modifier",
        RqlProperty::DuplicateKey => "duplicate_key",
        RqlProperty::Parenthesized => "parenthesized",
        RqlProperty::IntegerValue => "integer_value",
        RqlProperty::IntegerHasAnyBits => "integer_has_any_bits",
        RqlProperty::IntegerHasAllBits => "integer_has_all_bits",
        RqlProperty::IntegerHasNoBits => "integer_has_no_bits",
        RqlProperty::AssignmentTargetKind => "assignment_target_kind",
        RqlProperty::AssignmentValueKind => "assignment_value_kind",
        RqlProperty::AssignmentTargetUnstarredCount => "assignment_target_unstarred_count",
        RqlProperty::AssignmentValueUnstarredCount => "assignment_value_unstarred_count",
        RqlProperty::AssignmentTargetStarred => "assignment_target_starred",
        RqlProperty::AssignmentValueStarred => "assignment_value_starred",
        RqlProperty::AssignmentUnstarredCountMismatch => "assignment_unstarred_count_mismatch",
        RqlProperty::Index => "index",
        RqlProperty::StringValueRegex => "string_value.regex",
        RqlProperty::Not => "not",
        RqlProperty::All => "all",
        RqlProperty::Any => "any",
        RqlProperty::Capture => "capture",
        RqlProperty::NotKind => "not_kind",
        RqlProperty::Arity => "arity",
        RqlProperty::Visibility => "visibility",
        RqlProperty::ParameterType => "parameter_type",
        RqlProperty::ParameterTypeRegex => "parameter_type.regex",
        RqlProperty::LanguageRule => "language_rule",
        RqlProperty::BodyState => "body_state",
        RqlProperty::BodyOwner => "body_owner",
        RqlProperty::Has => "has",
        RqlProperty::NotHas => "not_has",
        RqlProperty::LocalValue => "local_value",
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
        RqlProperty::Name | RqlProperty::StringValue | RqlProperty::ParameterType => {
            ("exact string", MAX_STRING_PREDICATE_LENGTH, false)
        }
        RqlProperty::LanguageRule => ("language rule label", MAX_STRING_PREDICATE_LENGTH, false),
        RqlProperty::Modifier => ("modifier label", MAX_STRING_PREDICATE_LENGTH, false),
        RqlProperty::BodyState => ("body-state label", MAX_STRING_PREDICATE_LENGTH, false),
        RqlProperty::BodyOwner => ("body-owner label", MAX_STRING_PREDICATE_LENGTH, false),
        RqlProperty::Capture => unreachable!("capture handled above"),
        RqlProperty::NameRegex
        | RqlProperty::TextRegex
        | RqlProperty::CommentBlockRegex
        | RqlProperty::StringValueRegex
        | RqlProperty::ParameterTypeRegex
        | RqlProperty::BooleanValue
        | RqlProperty::DuplicateKey
        | RqlProperty::Parenthesized
        | RqlProperty::IntegerValue
        | RqlProperty::IntegerHasAnyBits
        | RqlProperty::IntegerHasAllBits
        | RqlProperty::IntegerHasNoBits
        | RqlProperty::AssignmentTargetKind
        | RqlProperty::AssignmentValueKind
        | RqlProperty::AssignmentTargetUnstarredCount
        | RqlProperty::AssignmentValueUnstarredCount
        | RqlProperty::AssignmentTargetStarred
        | RqlProperty::AssignmentValueStarred
        | RqlProperty::AssignmentUnstarredCountMismatch
        | RqlProperty::Index
        | RqlProperty::Async
        | RqlProperty::UnsafeContext
        | RqlProperty::NotKind
        | RqlProperty::Arity
        | RqlProperty::Visibility
        | RqlProperty::Has
        | RqlProperty::NotHas
        | RqlProperty::LocalValue => unreachable!("property is not a plain string"),
        RqlProperty::Not | RqlProperty::All | RqlProperty::Any => {
            unreachable!("property is not a plain string")
        }
    };
    if property == RqlProperty::LanguageRule && LanguageRule::from_label(text).is_none() {
        analysis.error(
            value.range.clone(),
            "invalid-query",
            format!("unknown language rule label {text:?}"),
        );
    } else if property == RqlProperty::BodyState
        && brokk_bifrost_core::analyzer::structural::body_relations::BodyState::from_label(text)
            .is_none()
    {
        analysis.error(
            value.range.clone(),
            "invalid-query",
            format!("unknown body-state label {text:?}"),
        );
    } else if property == RqlProperty::BodyOwner
        && brokk_bifrost_core::analyzer::structural::body_relations::BodyOwner::from_label(text)
            .is_none()
    {
        analysis.error(
            value.range.clone(),
            "invalid-query",
            format!("unknown body-owner label {text:?}"),
        );
    } else if property == RqlProperty::Modifier && DeclarationModifier::from_label(text).is_none() {
        analysis.error(
            value.range.clone(),
            "invalid-query",
            format!("unknown modifier label {text:?}"),
        );
    } else if reject_empty && text.is_empty() {
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

fn reject_callable_signature_property(
    property: RqlProperty,
    kind: NormalizedKind,
    range: &Range<usize>,
    analysis: &mut Analysis,
) {
    if property == RqlProperty::UnsafeContext {
        if !kind.satisfies(NormalizedKind::Call) {
            analysis.error(
                range.clone(),
                "invalid-query",
                "unsafe-context is only supported on call patterns".to_string(),
            );
        }
        return;
    }
    if !matches!(
        property,
        RqlProperty::Async
            | RqlProperty::Visibility
            | RqlProperty::ParameterType
            | RqlProperty::ParameterTypeRegex
    ) {
        return;
    }
    if kind.satisfies(NormalizedKind::Callable) {
        return;
    }
    analysis.error(
        range.clone(),
        "invalid-query",
        format!(
            "{} is only valid on callable kinds (function, method, constructor, lambda, callable); not valid for {}",
            property.label(),
            kind.label()
        ),
    );
}

fn validate_visibility_value(value: &Expr, path: &str, analysis: &mut Analysis) {
    match &value.kind {
        ExprKind::Symbol(label) | ExprKind::String(label) => {
            validate_visibility_label(label, value.range.clone(), analysis);
        }
        ExprKind::Vector(items) | ExprKind::List(items) => {
            if items.is_empty() {
                analysis.error(
                    value.range.clone(),
                    "wrong-value-shape",
                    "visibility list must not be empty",
                );
                return;
            }
            for (index, item) in items.iter().enumerate() {
                let child = format!("{path}[{index}]");
                analysis.path(&child, item.range.clone());
                let Some(label) = item.as_symbol().or_else(|| item.as_string()) else {
                    analysis.error(
                        item.range.clone(),
                        "wrong-value-shape",
                        "visibility must be a symbol or string label",
                    );
                    continue;
                };
                validate_visibility_label(label, item.range.clone(), analysis);
            }
        }
        _ => analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            "visibility must be a label or a non-empty vector of labels",
        ),
    }
}

fn validate_visibility_label(label: &str, range: Range<usize>, analysis: &mut Analysis) {
    let canonical = label.replace('-', "_");
    if DeclaredVisibility::from_label(&canonical).is_none() {
        analysis.error(
            range,
            "invalid-query",
            format!(
                "unknown visibility '{label}'; expected one of: {}",
                ALL_DECLARED_VISIBILITIES
                    .iter()
                    .map(|visibility| visibility.label())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
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
        ExprKind::Symbol(label) | ExprKind::String(label) => {
            if let Some(family) = super::schema::LANGUAGE_FAMILIES
                .iter()
                .find(|family| family.label == label)
            {
                analysis.add_help(value.range.clone(), family.signature, family.description);
            } else if let Some(language) = Language::from_config_label(label) {
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

fn validate_cross_domain_options(
    form: RqlForm,
    options: &[Expr],
    head_range: &Range<usize>,
    operator_path: &str,
    analysis: &mut Analysis,
    depth: usize,
    plan_budget: &mut SourcePlanBudget,
) {
    if !options.len().is_multiple_of(2) {
        analysis.error(
            options
                .last()
                .map_or_else(|| head_range.clone(), |last| last.range.clone()),
            "wrong-value-shape",
            format!(
                "{} expects :relation, :code, and :configuration option/value pairs",
                form.label()
            ),
        );
        return;
    }
    let mut seen = HashSet::new();
    for pair in options.as_chunks::<2>().0 {
        let Some(label) = pair[0].as_symbol() else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                format!("{} option names must be keywords", form.label()),
            );
            continue;
        };
        let Some(field) = schema::cross_domain_field_for_rql_label(label) else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                format!(
                    "{} accepts only :relation, :code, and :configuration",
                    form.label()
                ),
            );
            continue;
        };
        if !seen.insert(field) {
            analysis.error(
                pair[0].range.clone(),
                "duplicate-property",
                format!("duplicate {} option '{label}'", form.label()),
            );
            continue;
        }
        analysis.add_help(
            pair[0].range.clone(),
            field.signature(),
            field.description(),
        );
        let field_path = child_path(operator_path, field.label());
        match field {
            schema::CrossDomainField::Relation => {
                analysis.path(&field_path, pair[1].range.clone());
                validate_cross_domain_relation(&pair[1], &field_path, analysis);
            }
            schema::CrossDomainField::Code | schema::CrossDomainField::Configuration => {
                validate_rql_query(&pair[1], &field_path, analysis, depth + 1, plan_budget);
            }
        }
    }
}

fn validate_cross_domain_relation(expr: &Expr, relation_path: &str, analysis: &mut Analysis) {
    let Some((head, head_range, options)) = list_head(expr) else {
        analysis.error(
            expr.range.clone(),
            "wrong-value-shape",
            "a relation is one registered relation form such as (configuration-key :documents [...])",
        );
        return;
    };
    let Some(form) =
        RqlForm::from_label(head).filter(|form| form.class() == RqlFormClass::Relation)
    else {
        add_spelling_error(
            analysis,
            head_range,
            "unknown-form",
            format!("unknown cross-domain relation '{head}'"),
            head,
            rql_form_candidates(Some(RqlFormClass::Relation)),
            |suggestion| suggestion.to_string(),
        );
        return;
    };
    analysis.add_help(head_range.clone(), form.signature(), form.description());
    let body_path = match form {
        RqlForm::ConfigurationKey => child_path(relation_path, "configuration_key"),
        RqlForm::ConfigurationCode => child_path(relation_path, "configuration_code"),
        RqlForm::DependencyConfiguration => child_path(relation_path, "dependency_configuration"),
        _ => unreachable!("only relation-class forms are accepted above"),
    };
    analysis.path(&body_path, head_range.clone());
    if !options.len().is_multiple_of(2) {
        analysis.error(
            options.last().map_or(head_range, |last| last.range.clone()),
            "wrong-value-shape",
            format!("{} expects option name/value pairs", form.label()),
        );
        return;
    }
    for pair in options.as_chunks::<2>().0 {
        let field = pair[0].as_symbol().and_then(|label| match form {
            RqlForm::ConfigurationKey => {
                schema::configuration_key_relation_field_for_rql_label(label).map(|field| {
                    (
                        field.label(),
                        field.signature(),
                        field.description(),
                        field.value_shape(),
                    )
                })
            }
            RqlForm::ConfigurationCode => {
                schema::configuration_code_relation_field_for_rql_label(label).map(|field| {
                    (
                        field.label(),
                        field.signature(),
                        field.description(),
                        field.value_shape(),
                    )
                })
            }
            RqlForm::DependencyConfiguration => {
                schema::dependency_configuration_relation_field_for_rql_label(label).map(|field| {
                    (
                        field.label(),
                        field.signature(),
                        field.description(),
                        field.value_shape(),
                    )
                })
            }
            _ => unreachable!("registered relation form"),
        });
        let Some((label, signature, description, shape)) = field else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                format!("unknown {} option", form.label()),
            );
            continue;
        };
        analysis.add_help(pair[0].range.clone(), signature, description);
        let field_path = child_path(&body_path, label);
        analysis.path(&field_path, pair[1].range.clone());
        match shape {
            schema::ValueShape::ConfigurationCodeRelation => unreachable!(
                "configuration-code relation fields are decoded as individual scalar fields"
            ),
            schema::ValueShape::String => {
                if form == RqlForm::ConfigurationCode && label == "match" {
                    let Some(value) = pair[1].as_string().or_else(|| pair[1].as_symbol()) else {
                        analysis.error(
                            pair[1].range.clone(),
                            "wrong-value-shape",
                            "match requires a configuration-code match label",
                        );
                        continue;
                    };
                    if crate::query::ConfigurationCodeMatch::from_label(value).is_none() {
                        analysis.error(
                            pair[1].range.clone(),
                            "unknown-value",
                            format!("unknown configuration-code match '{value}'"),
                        );
                    }
                } else if pair[1].as_string().is_none()
                    && (label != "ecosystem" || pair[1].as_symbol().is_none())
                {
                    analysis.error(
                        pair[1].range.clone(),
                        "wrong-value-shape",
                        "expected a string",
                    );
                }
            }
            schema::ValueShape::Boolean => {
                if !matches!(&pair[1].kind, ExprKind::Symbol(value) if value == "true" || value == "false")
                {
                    analysis.error(
                        pair[1].range.clone(),
                        "wrong-value-shape",
                        "expected a boolean",
                    );
                }
            }
            schema::ValueShape::CorrelationOverrideList => {
                let Some(edges) = pair[1].as_sequence() else {
                    analysis.error(
                        pair[1].range.clone(),
                        "wrong-value-shape",
                        "overrides requires an array of document pairs",
                    );
                    continue;
                };
                for (index, edge) in edges.iter().enumerate() {
                    let edge_path = index_path(&field_path, index);
                    analysis.path(&edge_path, edge.range.clone());
                    let Some(endpoints) = edge.as_sequence().filter(|entries| entries.len() == 2)
                    else {
                        analysis.error(
                            edge.range.clone(),
                            "wrong-value-shape",
                            "override edge requires exactly two document strings",
                        );
                        continue;
                    };
                    for (endpoint, document) in endpoints.iter().enumerate() {
                        analysis.path(index_path(&edge_path, endpoint), document.range.clone());
                        if document.as_string().is_none() {
                            analysis.error(
                                document.range.clone(),
                                "wrong-value-shape",
                                "override endpoints are exact document strings",
                            );
                        }
                    }
                }
            }
            schema::ValueShape::CorrelationDocumentList | schema::ValueShape::StringList => {
                let entries = pair[1]
                    .as_sequence()
                    .map_or_else(|| vec![&pair[1]], |items| items.iter().collect());
                for (index, entry) in entries.into_iter().enumerate() {
                    analysis.path(index_path(&field_path, index), entry.range.clone());
                    if entry.as_string().is_none() {
                        analysis.error(
                            entry.range.clone(),
                            "wrong-value-shape",
                            "expected an exact string value",
                        );
                    }
                }
            }
            _ => unreachable!("registered relation field shape"),
        }
    }
}

fn validate_configuration_facts_options(form: RqlForm, options: &[Expr], analysis: &mut Analysis) {
    if !even_option_pairs(
        options,
        || {
            format!(
                "{} expects configuration axes, XML structural-relation options, same-document reference options, and peer child-set options",
                form.label()
            )
        },
        analysis,
    ) {
        return;
    }
    let mut seen = HashSet::new();
    for pair in options.as_chunks::<2>().0 {
        let Some(label) = pair[0].as_symbol() else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                "configuration-facts option names must be keywords",
            );
            continue;
        };
        let Some(field) = configuration_facts_field_for_rql_label(label) else {
            analysis.error(
                pair[0].range.clone(),
                "unknown-property",
                format!(
                    "{} accepts one configuration-facts filter axis",
                    form.label()
                ),
            );
            continue;
        };
        if !seen.insert(field) {
            analysis.error(
                pair[0].range.clone(),
                "duplicate-property",
                format!("duplicate configuration-facts filter option '{label}'"),
            );
            continue;
        }
        analysis.add_help(
            pair[0].range.clone(),
            field.signature(),
            field.description(),
        );
        if field == ConfigurationFactsFilterField::Routes {
            validate_configuration_routes(&pair[1], analysis);
            continue;
        }
        let values = pair[1]
            .as_sequence()
            .map_or_else(|| vec![&pair[1]], |items| items.iter().collect());
        for value in values {
            match field {
                ConfigurationFactsFilterField::Keys => {
                    // An empty authored key is a document state the decoder
                    // accepts, so the editor must not mark it invalid.
                    let valid = value
                        .as_string()
                        .is_some_and(|key| key.len() <= MAX_CONFIGURATION_KEY_LENGTH);
                    if !valid {
                        analysis.error(
                            value.range.clone(),
                            "wrong-value-shape",
                            format!(
                                ":key values must contain at most {MAX_CONFIGURATION_KEY_LENGTH} bytes"
                            ),
                        );
                    }
                }
                ConfigurationFactsFilterField::Values
                | ConfigurationFactsFilterField::ValuesIgnoreCase => {
                    let valid = value
                        .as_string()
                        .is_some_and(|value| value.len() <= MAX_CONFIGURATION_VALUE_LENGTH);
                    if !valid {
                        analysis.error(
                            value.range.clone(),
                            "wrong-value-shape",
                            format!(
                                ":{} values must be strings of at most {MAX_CONFIGURATION_VALUE_LENGTH} bytes",
                                field.label()
                            ),
                        );
                    }
                }
                ConfigurationFactsFilterField::XmlParentKeys
                | ConfigurationFactsFilterField::XmlPrecedingSiblingKeys
                | ConfigurationFactsFilterField::XmlSiblingAttributeKeys => {
                    let valid = value
                        .as_string()
                        .is_some_and(|key| key.len() <= MAX_CONFIGURATION_KEY_LENGTH);
                    if !valid {
                        analysis.error(
                            value.range.clone(),
                            "wrong-value-shape",
                            format!(
                                ":{} values must contain at most {MAX_CONFIGURATION_KEY_LENGTH} bytes",
                                field.label()
                            ),
                        );
                    }
                }
                ConfigurationFactsFilterField::XmlSiblingAttributeValues
                | ConfigurationFactsFilterField::XmlSiblingAttributeValuesIgnoreCase => {
                    let valid = value
                        .as_string()
                        .is_some_and(|value| value.len() <= MAX_CONFIGURATION_VALUE_LENGTH);
                    if !valid {
                        analysis.error(
                            value.range.clone(),
                            "wrong-value-shape",
                            format!(
                                ":{} values must be strings of at most {MAX_CONFIGURATION_VALUE_LENGTH} bytes",
                                field.label()
                            ),
                        );
                    }
                }
                ConfigurationFactsFilterField::XmlReferenceSourceKeys
                | ConfigurationFactsFilterField::XmlReferenceTargetKeys
                | ConfigurationFactsFilterField::XmlReferenceTargetElementKeys
                | ConfigurationFactsFilterField::XmlReferenceTargetChildKeys
                | ConfigurationFactsFilterField::XmlPeerElementKeys
                | ConfigurationFactsFilterField::XmlPeerAttributeKeys
                | ConfigurationFactsFilterField::XmlPeerChildKeys => {
                    let valid = value
                        .as_string()
                        .is_some_and(|key| key.len() <= MAX_CONFIGURATION_KEY_LENGTH);
                    if !valid {
                        analysis.error(
                            value.range.clone(),
                            "wrong-value-shape",
                            format!(
                                ":{} values must contain at most {MAX_CONFIGURATION_KEY_LENGTH} bytes",
                                field.label()
                            ),
                        );
                    }
                }
                ConfigurationFactsFilterField::XmlPeerMinSharedChildren => {
                    if !matches!(value.kind, ExprKind::Number(number) if u32::try_from(number).is_ok())
                    {
                        analysis.error(
                            value.range.clone(),
                            "wrong-value-shape",
                            ":xml-peer-min-shared-children must be a non-negative 32-bit integer",
                        );
                    }
                }
                ConfigurationFactsFilterField::ValueLt
                | ConfigurationFactsFilterField::ValueLe
                | ConfigurationFactsFilterField::ValueGt
                | ConfigurationFactsFilterField::ValueGe => {
                    let valid = value.as_string().is_some_and(|value| {
                        value.len() <= MAX_CONFIGURATION_VALUE_LENGTH
                            && value.parse::<f64>().is_ok_and(|number| number.is_finite())
                    });
                    if !valid {
                        analysis.error(
                            value.range.clone(),
                            "wrong-value-shape",
                            format!(
                                ":{} must be a finite numeric string of at most {MAX_CONFIGURATION_VALUE_LENGTH} bytes",
                                field.label()
                            ),
                        );
                    }
                }
                ConfigurationFactsFilterField::FactOrdinals => {
                    if !matches!(value.kind, ExprKind::Number(number) if u32::try_from(number).is_ok())
                    {
                        analysis.error(
                            value.range.clone(),
                            "wrong-value-shape",
                            ":fact-ordinal must be a non-negative 32-bit integer",
                        );
                    }
                }
                ConfigurationFactsFilterField::Formats
                | ConfigurationFactsFilterField::NodeKinds
                | ConfigurationFactsFilterField::Roles
                | ConfigurationFactsFilterField::ScalarKinds
                | ConfigurationFactsFilterField::Provenances
                | ConfigurationFactsFilterField::Completenesses => {
                    let Some(text) = value.as_symbol().or_else(|| value.as_string()) else {
                        analysis.error(
                            value.range.clone(),
                            "wrong-value-shape",
                            format!(":{} values must be symbols or strings", field.label()),
                        );
                        continue;
                    };
                    let known = match field {
                        ConfigurationFactsFilterField::Formats => {
                            crate::query::domain::ConfigurationFormat::from_label(text).is_some()
                        }
                        ConfigurationFactsFilterField::NodeKinds => {
                            ConfigurationNodeKindFilter::from_label(text).is_some()
                        }
                        ConfigurationFactsFilterField::Roles => {
                            configuration_member_role_from_label(text).is_some()
                        }
                        ConfigurationFactsFilterField::ScalarKinds => {
                            configuration_scalar_kind_from_label(text).is_some()
                        }
                        ConfigurationFactsFilterField::Provenances => {
                            configuration_provenance_from_label(text).is_some()
                        }
                        ConfigurationFactsFilterField::Completenesses => {
                            ConfigurationCompletenessFilter::from_label(text).is_some()
                        }
                        _ => unreachable!("only enum-like axes remain in this branch"),
                    };
                    if !known {
                        analysis.error(
                            value.range.clone(),
                            "unknown-value",
                            format!("unknown {} value '{text}'", field.label()),
                        );
                    }
                }
                ConfigurationFactsFilterField::Routes => {
                    unreachable!("handled before value decoding")
                }
            }
        }
    }
}

fn validate_configuration_routes(route: &Expr, analysis: &mut Analysis) {
    let Some(alternatives) = route.as_sequence() else {
        analysis.error(
            route.range.clone(),
            "wrong-value-shape",
            ":route must be a sequence of route alternatives",
        );
        return;
    };
    for alternative in alternatives {
        let Some(segments) = alternative.as_sequence() else {
            analysis.error(
                alternative.range.clone(),
                "wrong-value-shape",
                "each :route alternative must be a sequence of segments",
            );
            continue;
        };
        for segment in segments {
            let Some((kind, range, args)) = list_head(segment) else {
                analysis.error(
                    segment.range.clone(),
                    "wrong-value-shape",
                    "a route segment must be a key, index, or any list",
                );
                continue;
            };
            let valid = match (kind, args.len()) {
                ("key", 1) => args[0].as_string().is_some(),
                ("index", 1) => {
                    matches!(args[0].kind, ExprKind::Number(number) if u32::try_from(number).is_ok())
                }
                ("any", 0) => true,
                ("key" | "index", _) | ("any", _) => false,
                _ => false,
            };
            if !valid {
                analysis.error(
                    range,
                    "wrong-value-shape",
                    "route segments are (key \"text\"), (index ordinal), or (any)",
                );
            }
        }
    }
}
