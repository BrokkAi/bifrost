use super::*;

pub(super) fn analyze_json_with_schema_registry(
    source: &str,
    schema_versions: &SchemaVersionRegistry,
) -> Analysis {
    let mut analysis = Analysis::default();
    let parsed: spanned::Value = match json_spanned_value::from_str(source) {
        Ok(value) => value,
        Err(error) if error.classify() == serde_json::error::Category::Eof => {
            return analyze_incomplete_json(source, schema_versions);
        }
        Err(error) => {
            let offset = error.offset_within(source).unwrap_or(source.len());
            let end = source[offset..]
                .chars()
                .next()
                .map_or(offset, |ch| offset + ch.len_utf8());
            analysis.error(offset..end, "invalid-json", error.to_string());
            return analysis;
        }
    };
    let mut plan_budget = SourcePlanBudget::default();
    validate_json_query(
        &parsed,
        "",
        &mut analysis,
        0,
        &mut plan_budget,
        schema_versions,
    );
    if analysis.diagnostics.is_empty()
        && let Err(error) =
            CodeQuery::from_json_with_schema_registry(&spanned_to_json(&parsed), schema_versions)
    {
        analysis.semantic_error(error, parsed.range());
    }
    analysis
}

fn analyze_incomplete_json(source: &str, schema_versions: &SchemaVersionRegistry) -> Analysis {
    if source.len() > MAX_JSON_COMPLETION_SOURCE_BYTES {
        return Analysis::default();
    }

    // Ask the real JSON parser whether a bounded synthetic suffix completes
    // the document. This recovers spans for already-complete keys without
    // maintaining a second JSON lexer/parser in the editor path.
    let terminals = ["", "null", ":null", "\"", "\"__incomplete\":null"];
    for depth in 1..=MAX_JSON_COMPLETION_DEPTH {
        let permutations = 1usize << depth;
        for terminal in terminals {
            for mask in 0..permutations {
                let mut completed = String::with_capacity(source.len() + terminal.len() + depth);
                completed.push_str(source);
                completed.push_str(terminal);
                for index in 0..depth {
                    completed.push(if mask & (1 << index) == 0 { '}' } else { ']' });
                }
                let Ok(parsed) = json_spanned_value::from_str::<spanned::Value>(&completed) else {
                    continue;
                };
                let mut analysis = Analysis::default();
                let mut plan_budget = SourcePlanBudget::default();
                validate_json_query(
                    &parsed,
                    "",
                    &mut analysis,
                    0,
                    &mut plan_budget,
                    schema_versions,
                );
                analysis.diagnostics.clear();
                analysis.help.retain(|item| item.range.end <= source.len());
                analysis.paths.retain(|_, range| range.end <= source.len());
                analysis.incomplete = true;
                return analysis;
            }
        }
    }
    Analysis::default()
}

fn validate_json_query(
    value: &spanned::Value,
    path: &str,
    analysis: &mut Analysis,
    depth: usize,
    plan_budget: &mut SourcePlanBudget,
    schema_versions: &SchemaVersionRegistry,
) {
    analysis.path(path, value.range());
    if !plan_budget.enter(depth, value.range(), analysis) {
        return;
    }
    let Some(object) = value.as_object() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "query must be a JSON object",
        );
        return;
    };
    let mut seen = HashSet::new();
    for (key, child) in object {
        let child_path = join_path(path, key.get_ref());
        analysis.path(&child_path, child.range());
        let Some(field) = QueryField::from_label(key.get_ref()) else {
            add_spelling_error(
                analysis,
                key.range(),
                "unknown-property",
                format!("unknown query property '{key}'"),
                key.get_ref(),
                json_field_candidates(ALL_QUERY_FIELDS, QueryField::label),
                |suggestion| {
                    serde_json::to_string(suggestion).expect("suggestions are JSON strings")
                },
            );
            continue;
        };
        record_json_duplicate(field.label(), key.range(), &mut seen, analysis);
        analysis.add_help(key.range(), field.signature(), field.description());
        match field {
            QueryField::Where => validate_json_globs(child, &child_path, analysis),
            QueryField::Languages => validate_json_languages(child, &child_path, analysis),
            QueryField::Match
            | QueryField::Inside
            | QueryField::InsideDecl
            | QueryField::NotInside => {
                validate_json_pattern(child, &child_path, analysis);
                if field == QueryField::InsideDecl {
                    analysis.path(&child_path, key.range());
                }
                if field == QueryField::Match && json_pattern_anchors_root(child) == Some(false) {
                    analysis.error(
                        child.range(),
                        "invalid-query",
                        "root pattern must constrain at least one of kind, name, or text",
                    );
                } else if field != QueryField::Match
                    && child.as_object().is_some_and(|object| object.is_empty())
                {
                    analysis.error(
                        child.range(),
                        "invalid-query",
                        "containment pattern must not be empty",
                    );
                }
            }
            QueryField::Union | QueryField::Intersect | QueryField::Except => {
                let Some(branches) = child.as_array() else {
                    analysis.error(
                        child.range(),
                        "wrong-value-shape",
                        "set composition must be an array of query objects",
                    );
                    continue;
                };
                if branches.len() < 2 {
                    analysis.error(
                        child.range(),
                        "wrong-value-shape",
                        format!("{} requires at least two branches", field.label()),
                    );
                } else if branches.len() > MAX_QUERY_BRANCHES {
                    analysis.error(
                        branches[MAX_QUERY_BRANCHES].range(),
                        "invalid-query",
                        format!("at most {MAX_QUERY_BRANCHES} branches are allowed"),
                    );
                }
                for (index, branch) in branches.iter().enumerate() {
                    validate_json_query(
                        branch,
                        &format!("{child_path}[{index}]"),
                        analysis,
                        depth + 1,
                        plan_budget,
                        schema_versions,
                    );
                }
            }
            QueryField::Occurrences => {
                validate_json_occurrence_filter(child, &child_path, analysis);
            }
            QueryField::Scopes => validate_json_environment_filter(
                child,
                &child_path,
                EnvironmentOptionKind::Scope,
                analysis,
            ),
            QueryField::Bindings => validate_json_environment_filter(
                child,
                &child_path,
                EnvironmentOptionKind::Binding,
                analysis,
            ),
            QueryField::GenerationSites => validate_json_environment_filter(
                child,
                &child_path,
                EnvironmentOptionKind::GenerationSite,
                analysis,
            ),
            QueryField::Exports => validate_json_environment_filter(
                child,
                &child_path,
                EnvironmentOptionKind::Export,
                analysis,
            ),
            QueryField::Paths => validate_json_path_filter(child, &child_path, analysis),
            QueryField::Steps => validate_json_steps(child, &child_path, analysis),
            QueryField::Limit => {
                if child
                    .as_number()
                    .and_then(serde_json::Number::as_u64)
                    .is_none_or(|number| number == 0)
                {
                    analysis.error(
                        child.range(),
                        "wrong-value-shape",
                        "expected a positive integer",
                    );
                } else if child
                    .as_number()
                    .and_then(serde_json::Number::as_u64)
                    .is_some_and(|number| number > MAX_LIMIT as u64)
                {
                    analysis.error(
                        child.range(),
                        "invalid-query",
                        format!("limit must be at most {MAX_LIMIT}"),
                    );
                }
            }
            QueryField::ResultDetail => validate_json_result_detail(child, analysis),
            QueryField::ExecutionMode => {
                if path.is_empty() {
                    validate_json_execution_mode(child, analysis);
                } else {
                    analysis.error(
                        key.range(),
                        "invalid-query",
                        "execution mode is allowed only on the root query",
                    );
                }
            }
            QueryField::SchemaVersion => {
                let Some(version) = child.as_number().and_then(serde_json::Number::as_u64) else {
                    analysis.error(
                        child.range(),
                        "wrong-value-shape",
                        "expected an unsigned integer schema version",
                    );
                    continue;
                };
                let Ok(version) = u32::try_from(version) else {
                    analysis.error(
                        child.range(),
                        "wrong-value-shape",
                        "schema version must fit in an unsigned 32-bit integer",
                    );
                    continue;
                };
                if let Err(error) = schema_versions.resolve(Some(version)) {
                    analysis.error(
                        child.range(),
                        "unsupported-schema-version",
                        error.to_string(),
                    );
                }
            }
        }
    }
}

fn validate_json_pattern(value: &spanned::Value, path: &str, analysis: &mut Analysis) {
    analysis.path(path, value.range());
    let Some(object) = value.as_object() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "pattern must be a JSON object",
        );
        return;
    };
    let kind_field_present = object
        .iter()
        .any(|(key, _)| PatternField::from_label(key.get_ref()) == Some(PatternField::Kind));
    let declared_kinds = object
        .iter()
        .find(|(key, _)| PatternField::from_label(key.get_ref()) == Some(PatternField::Kind))
        .map_or_else(Vec::new, |(_, value)| collect_json_kinds(value));
    let mut seen = HashSet::new();
    for (key, child) in object {
        let child_path = join_path(path, key.get_ref());
        analysis.path(&child_path, child.range());
        if let Some(field) = PatternField::from_label(key.get_ref()) {
            record_json_duplicate(field.label(), key.range(), &mut seen, analysis);
            analysis.add_help(key.range(), field.signature(), field.description());
            match field {
                PatternField::Kind | PatternField::NotKind => {
                    validate_json_kinds(child, &child_path, analysis)
                }
                PatternField::Name => validate_string_predicate(child, &child_path, true, analysis),
                PatternField::Text => {
                    validate_string_predicate(child, &child_path, false, analysis)
                }
                PatternField::Capture => validate_json_capture(child, analysis),
                PatternField::Has | PatternField::NotHas => {
                    validate_json_pattern(child, &child_path, analysis);
                }
            }
        } else if let Some(role) = Role::from_label(key.get_ref()) {
            record_json_duplicate(role.label(), key.range(), &mut seen, analysis);
            analysis.add_help(
                key.range(),
                format!("\"{}\": {}", role.label(), role.signature()),
                role.description(),
            );
            if !kind_field_present {
                analysis.error(
                    key.range(),
                    "invalid-query",
                    format!(
                        "role {:?} requires the pattern to declare a kind",
                        role.label()
                    ),
                );
            } else if !declared_kinds.is_empty()
                && !declared_kinds.iter().any(|&kind| role.valid_for(kind))
            {
                let kinds = declared_kinds
                    .iter()
                    .map(|kind| kind.label())
                    .collect::<Vec<_>>()
                    .join(", ");
                analysis.error(
                    key.range(),
                    "invalid-query",
                    format!("role {:?} is not valid for kind(s) {kinds}", role.label()),
                );
            }
            match role.value_shape() {
                RoleValueShape::Pattern => validate_json_pattern(child, &child_path, analysis),
                RoleValueShape::PatternList => {
                    validate_json_pattern_array(child, &child_path, analysis);
                }
                RoleValueShape::PatternMap => {
                    validate_json_pattern_map(child, &child_path, analysis);
                }
            }
        } else {
            add_spelling_error(
                analysis,
                key.range(),
                "unknown-property",
                format!("unknown pattern property '{key}'"),
                key.get_ref(),
                pattern_field_candidates(),
                |suggestion| {
                    serde_json::to_string(suggestion).expect("suggestions are JSON strings")
                },
            );
        }
    }
}

fn json_pattern_anchors_root(value: &spanned::Value) -> Option<bool> {
    let object = value.as_object()?;
    if object.iter().any(|(key, _)| {
        PatternField::from_label(key.get_ref()).is_none()
            && Role::from_label(key.get_ref()).is_none()
    }) {
        return None;
    }
    Some(object.iter().any(|(key, _)| {
        matches!(
            PatternField::from_label(key.get_ref()),
            Some(PatternField::Kind | PatternField::Name | PatternField::Text)
        )
    }))
}

fn collect_json_kinds(value: &spanned::Value) -> Vec<NormalizedKind> {
    if let Some(label) = value.as_string() {
        NormalizedKind::from_label(label).into_iter().collect()
    } else if let Some(values) = value.as_array() {
        values.iter().flat_map(collect_json_kinds).collect()
    } else {
        Vec::new()
    }
}

fn validate_json_kinds(value: &spanned::Value, path: &str, analysis: &mut Analysis) {
    if let Some(label) = value.as_string() {
        if let Some(kind) = NormalizedKind::from_label(label) {
            analysis.add_help(value.range(), kind.signature(), kind.description());
        } else {
            add_spelling_error(
                analysis,
                value.range(),
                "invalid-kind",
                format!("unknown normalized kind '{label}'"),
                label,
                kind_candidates(),
                |suggestion| {
                    serde_json::to_string(suggestion).expect("suggestions are JSON strings")
                },
            );
        }
    } else if let Some(values) = value.as_array() {
        if values.is_empty() {
            analysis.error(
                value.range(),
                "wrong-value-shape",
                "kind array must not be empty",
            );
        }
        for (index, value) in values.iter().enumerate() {
            let child = format!("{path}[{index}]");
            analysis.path(&child, value.range());
            validate_json_kinds(value, &child, analysis);
        }
    } else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "expected a kind string or array of kind strings",
        );
    }
}

fn validate_string_predicate(
    value: &spanned::Value,
    path: &str,
    allow_exact: bool,
    analysis: &mut Analysis,
) {
    if let Some(exact) = value.as_string() {
        if allow_exact {
            if exact.len() > MAX_STRING_PREDICATE_LENGTH {
                analysis.error(
                    value.range(),
                    "invalid-query",
                    format!("exact string must be at most {MAX_STRING_PREDICATE_LENGTH} bytes"),
                );
            }
        } else {
            analysis.error(
                value.range(),
                "wrong-value-shape",
                "expected { \"regex\": string }",
            );
        }
        return;
    }
    let Some(object) = value.as_object() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            if allow_exact {
                "expected a string or { \"regex\": string }"
            } else {
                "expected { \"regex\": string }"
            },
        );
        return;
    };
    let mut seen = HashSet::new();
    let mut has_regex = false;
    for (key, value) in object {
        let child_path = join_path(path, key.get_ref());
        analysis.path(&child_path, value.range());
        if StringPredicateField::from_label(key.get_ref()).is_none() {
            add_spelling_error(
                analysis,
                key.range(),
                "unknown-property",
                "string predicate only accepts 'regex'",
                key.get_ref(),
                json_field_candidates(ALL_STRING_PREDICATE_FIELDS, StringPredicateField::label),
                |suggestion| {
                    serde_json::to_string(suggestion).expect("suggestions are JSON strings")
                },
            );
        } else {
            has_regex = true;
            record_json_duplicate("regex", key.range(), &mut seen, analysis);
            analysis.add_help(
                key.range(),
                "\"regex\": \"pattern\"",
                "Match the value with a regular expression.",
            );
            if let Some(source) = value.as_string() {
                validate_regex(source, value.range(), &child_path, analysis);
            } else {
                require_json_string(value, analysis);
            }
        }
    }
    if !has_regex {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "required field 'regex' is missing",
        );
    }
}

fn validate_json_pattern_array(value: &spanned::Value, path: &str, analysis: &mut Analysis) {
    let Some(values) = value.as_array() else {
        if json_single_pattern_is_recognizable(value) {
            analysis.error_with_fix(
                value.range(),
                "wrong-value-shape",
                "expected an array of patterns",
                QuerySourceFix {
                    title: "Wrap in an array".to_string(),
                    edit: QuerySourceEdit::Surround {
                        prefix: "[".to_string(),
                        suffix: "]".to_string(),
                    },
                },
            );
        } else {
            analysis.error(
                value.range(),
                "wrong-value-shape",
                "expected an array of patterns",
            );
        }
        return;
    };
    if values.len() > MAX_ROLE_LIST_ENTRIES {
        analysis.error(
            values[MAX_ROLE_LIST_ENTRIES].range(),
            "invalid-query",
            format!("role array may contain at most {MAX_ROLE_LIST_ENTRIES} entries"),
        );
    }
    for (index, value) in values.iter().enumerate() {
        validate_json_pattern(value, &format!("{path}[{index}]"), analysis);
    }
}

fn json_single_pattern_is_recognizable(value: &spanned::Value) -> bool {
    if value.as_object().is_none() {
        return false;
    }
    let mut analysis = Analysis::default();
    validate_json_pattern(value, "", &mut analysis);
    analysis.diagnostics.is_empty()
}

fn validate_json_pattern_map(value: &spanned::Value, path: &str, analysis: &mut Analysis) {
    let Some(values) = value.as_object() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "expected an object mapping names to patterns",
        );
        return;
    };
    if values.len() > MAX_KWARGS
        && let Some((key, _)) = values.iter().nth(MAX_KWARGS)
    {
        analysis.error(
            key.range(),
            "invalid-query",
            format!("kwargs may contain at most {MAX_KWARGS} entries"),
        );
    }
    for (key, value) in values {
        let child = join_path(path, key.get_ref());
        analysis.path(&child, value.range());
        if key.get_ref().len() > MAX_KWARG_NAME_LENGTH {
            analysis.error(
                key.range(),
                "invalid-query",
                format!("keyword must be at most {MAX_KWARG_NAME_LENGTH} bytes"),
            );
        }
        validate_json_pattern(value, &child, analysis);
    }
}

fn validate_json_globs(value: &spanned::Value, path: &str, analysis: &mut Analysis) {
    let Some(values) = value.as_array() else {
        if value.as_string().is_some() {
            analysis.error_with_fix(
                value.range(),
                "wrong-value-shape",
                "where must be an array of strings",
                QuerySourceFix {
                    title: "Wrap in an array".to_string(),
                    edit: QuerySourceEdit::Surround {
                        prefix: "[".to_string(),
                        suffix: "]".to_string(),
                    },
                },
            );
        } else {
            analysis.error(
                value.range(),
                "wrong-value-shape",
                "where must be an array of strings",
            );
        }
        return;
    };
    if values.len() > MAX_WHERE_GLOBS {
        analysis.error(
            values[MAX_WHERE_GLOBS].range(),
            "invalid-query",
            format!("at most {MAX_WHERE_GLOBS} globs are allowed"),
        );
    }
    for (index, value) in values.iter().enumerate() {
        let child = format!("{path}[{index}]");
        analysis.path(&child, value.range());
        let Some(pattern) = value.as_string() else {
            require_json_string(value, analysis);
            continue;
        };
        if pattern.len() > MAX_GLOB_LENGTH {
            analysis.error(
                value.range(),
                "invalid-query",
                format!("glob must be at most {MAX_GLOB_LENGTH} bytes"),
            );
        } else if let Err(error) = glob::Pattern::new(pattern) {
            analysis.error(
                value.range(),
                "invalid-query",
                format!("invalid glob: {error}"),
            );
        }
    }
}

fn validate_json_languages(value: &spanned::Value, path: &str, analysis: &mut Analysis) {
    let Some(values) = value.as_array() else {
        if value.as_string().is_some() {
            analysis.error_with_fix(
                value.range(),
                "wrong-value-shape",
                "languages must be an array of strings",
                QuerySourceFix {
                    title: "Wrap in an array".to_string(),
                    edit: QuerySourceEdit::Surround {
                        prefix: "[".to_string(),
                        suffix: "]".to_string(),
                    },
                },
            );
        } else {
            analysis.error(
                value.range(),
                "wrong-value-shape",
                "languages must be an array of strings",
            );
        }
        return;
    };
    if values.len() > MAX_LANGUAGE_FILTERS {
        analysis.error(
            values[MAX_LANGUAGE_FILTERS].range(),
            "invalid-query",
            format!("at most {MAX_LANGUAGE_FILTERS} language filters are allowed"),
        );
    }
    for (index, value) in values.iter().enumerate() {
        analysis.path(format!("{path}[{index}]"), value.range());
        let Some(label) = value.as_string() else {
            analysis.error(
                value.range(),
                "wrong-value-shape",
                "expected a language label string",
            );
            continue;
        };
        if let Some(language) = Language::from_config_label(label) {
            analysis.add_help(
                value.range(),
                language.config_label(),
                "Restrict structural matching to this analyzer language.",
            );
        } else {
            add_spelling_error(
                analysis,
                value.range(),
                "invalid-language",
                format!("unknown language '{label}'"),
                label,
                language_candidates(),
                |suggestion| {
                    serde_json::to_string(suggestion).expect("suggestions are JSON strings")
                },
            );
        }
    }
}

/// Validate one `class` / `role` / `namespace` array against its registry.
fn validate_json_occurrence_axis(
    field: QueryStepField,
    value: &spanned::Value,
    analysis: &mut Analysis,
) {
    let accepted = occurrence_filter_labels(field);
    let entries: Vec<&spanned::Value> = match value.as_array() {
        Some(entries) => entries.iter().collect(),
        None => vec![value],
    };
    if entries.is_empty() {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            format!("{} must not be empty", field.label()),
        );
        return;
    }
    for entry in entries {
        let Some(label) = entry.as_string() else {
            require_json_string(entry, analysis);
            continue;
        };
        if !accepted.contains(&label) {
            add_spelling_error(
                analysis,
                entry.range(),
                "unknown-value",
                format!("unknown {} value {label:?}", field.label()),
                label,
                accepted
                    .iter()
                    .map(|candidate| ((*candidate).to_string(), (*candidate).to_string()))
                    .collect::<Vec<_>>(),
                |suggestion| {
                    serde_json::to_string(suggestion).expect("suggestions are JSON strings")
                },
            );
        }
    }
}

/// Validate the `occurrences` seed object of a JSON query.
/// Validate one lexical-environment filter object (a `scopes`/`bindings` seed
/// body, or the option block of `bindings_in`/`candidates_of`) against the
/// registries (#1474).
/// Validate the JSON `paths` seed filter: only `min_segments` with a
/// positive integer.
fn validate_json_path_filter(value: &spanned::Value, path: &str, analysis: &mut Analysis) {
    let Some(object) = value.as_object() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "paths must be a filter object",
        );
        return;
    };
    for (key, child) in object {
        analysis.path(join_path(path, key.get_ref()), child.range());
        if key.get_ref().as_str() != "min_segments" {
            analysis.error(
                key.range(),
                "unknown-property",
                format!("unknown qualified path filter property '{key}'; paths accepts only min_segments"),
            );
            continue;
        }
        if child
            .as_number()
            .and_then(serde_json::Number::as_u64)
            .is_none_or(|count| count == 0)
        {
            analysis.error(
                child.range(),
                "wrong-value-shape",
                "min_segments must be a positive integer",
            );
        }
    }
}

fn validate_json_environment_filter(
    value: &spanned::Value,
    path: &str,
    kind: EnvironmentOptionKind,
    analysis: &mut Analysis,
) {
    let Some(object) = value.as_object() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "expected a lexical environment filter object",
        );
        return;
    };
    let accepted_keys: &[&str] = match kind {
        EnvironmentOptionKind::Scope => &["kind"],
        EnvironmentOptionKind::Binding => &["kind", "name", "hoisting"],
        EnvironmentOptionKind::Candidate => &["tier", "outcome", "boundary"],
        EnvironmentOptionKind::ReachingBinding => &["include_shadowed"],
        EnvironmentOptionKind::GenerationSite => &["kind", "input"],
        EnvironmentOptionKind::Export => &["form", "name"],
        EnvironmentOptionKind::DeclarationState => &["origin", "declaration_only", "config_gated"],
    };
    let mut seen = HashSet::new();
    for (key, child) in object {
        analysis.path(join_path(path, key.get_ref()), child.range());
        let name = key.get_ref().as_str();
        let field = match kind {
            EnvironmentOptionKind::Scope if name == "kind" => EnvironmentOptionField::ScopeKinds,
            EnvironmentOptionKind::Binding if name == "kind" => {
                EnvironmentOptionField::Step(QueryStepField::BindingKinds)
            }
            EnvironmentOptionKind::Binding if name == "name" => {
                EnvironmentOptionField::Step(QueryStepField::BindingNames)
            }
            EnvironmentOptionKind::Binding if name == "hoisting" => {
                EnvironmentOptionField::Step(QueryStepField::BindingHoisting)
            }
            EnvironmentOptionKind::Candidate if name == "tier" => {
                EnvironmentOptionField::Step(QueryStepField::CandidateTiers)
            }
            EnvironmentOptionKind::Candidate if name == "outcome" => {
                EnvironmentOptionField::Step(QueryStepField::CandidateOutcomes)
            }
            EnvironmentOptionKind::Candidate if name == "boundary" => {
                EnvironmentOptionField::Step(QueryStepField::CandidateBoundaries)
            }
            EnvironmentOptionKind::ReachingBinding if name == "include_shadowed" => {
                EnvironmentOptionField::Step(QueryStepField::IncludeShadowed)
            }
            EnvironmentOptionKind::GenerationSite if name == "kind" => {
                EnvironmentOptionField::GenerationSite(GenerationSiteFilterField::Kinds)
            }
            EnvironmentOptionKind::GenerationSite if name == "input" => {
                EnvironmentOptionField::GenerationSite(GenerationSiteFilterField::Inputs)
            }
            EnvironmentOptionKind::Export if name == "form" => {
                EnvironmentOptionField::Export(ExportFilterField::Forms)
            }
            EnvironmentOptionKind::Export if name == "name" => {
                EnvironmentOptionField::Export(ExportFilterField::Names)
            }
            EnvironmentOptionKind::DeclarationState if name == "origin" => {
                EnvironmentOptionField::Step(QueryStepField::DeclarationOrigins)
            }
            EnvironmentOptionKind::DeclarationState if name == "declaration_only" => {
                EnvironmentOptionField::Step(QueryStepField::DeclarationOnly)
            }
            EnvironmentOptionKind::DeclarationState if name == "config_gated" => {
                EnvironmentOptionField::Step(QueryStepField::ConfigGated)
            }
            _ => {
                add_spelling_error(
                    analysis,
                    key.range(),
                    "unknown-property",
                    format!("unknown lexical environment filter property '{key}'"),
                    key.get_ref(),
                    accepted_keys
                        .iter()
                        .map(|candidate| ((*candidate).to_string(), (*candidate).to_string()))
                        .collect::<Vec<_>>(),
                    |suggestion| {
                        serde_json::to_string(suggestion).expect("suggestions are JSON strings")
                    },
                );
                continue;
            }
        };
        analysis.add_help(key.range(), field.signature(), field.description());
        if !seen.insert(field) {
            analysis.error(
                key.range(),
                "duplicate-property",
                format!("duplicate property '{}'", field.label()),
            );
        }
        validate_json_environment_axis(field, child, analysis);
    }
}

/// Validate one filter axis array against its registry vocabulary.
fn validate_json_environment_axis(
    field: EnvironmentOptionField,
    value: &spanned::Value,
    analysis: &mut Analysis,
) {
    if field == EnvironmentOptionField::Step(QueryStepField::IncludeShadowed) {
        if value.as_bool() != Some(true) {
            analysis.error(
                value.range(),
                "wrong-value-shape",
                "include_shadowed must be true when present",
            );
        }
        return;
    }
    if matches!(
        field,
        EnvironmentOptionField::Step(QueryStepField::DeclarationOnly | QueryStepField::ConfigGated)
    ) {
        if value.as_bool().is_none() {
            analysis.error(
                value.range(),
                "wrong-value-shape",
                format!("{} must be a boolean", field.label()),
            );
        }
        return;
    }
    let entries: Vec<&spanned::Value> = match value.as_array() {
        Some(entries) => entries.iter().collect(),
        None => vec![value],
    };
    if entries.is_empty() {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            format!("{} must not be empty", field.label()),
        );
        return;
    }
    let accepted = field.accepted_values();
    for entry in entries {
        let Some(label) = entry.as_string() else {
            require_json_string(entry, analysis);
            continue;
        };
        let Some(accepted) = &accepted else {
            if label.is_empty() || label.len() > MAX_BINDING_NAME_LENGTH {
                analysis.error(
                    entry.range(),
                    "wrong-value-shape",
                    format!(
                        "{} values must be between 1 and {MAX_BINDING_NAME_LENGTH} bytes",
                        field.label()
                    ),
                );
            }
            continue;
        };
        if !accepted.contains(&label) {
            add_spelling_error(
                analysis,
                entry.range(),
                "unknown-value",
                format!("unknown {} value {label:?}", field.label()),
                label,
                accepted
                    .iter()
                    .map(|candidate| ((*candidate).to_string(), (*candidate).to_string()))
                    .collect::<Vec<_>>(),
                |suggestion| {
                    serde_json::to_string(suggestion).expect("suggestions are JSON strings")
                },
            );
        }
    }
}

fn validate_json_occurrence_filter(value: &spanned::Value, path: &str, analysis: &mut Analysis) {
    let Some(object) = value.as_object() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "expected an occurrence filter object",
        );
        return;
    };
    let mut seen = HashSet::new();
    for (key, child) in object {
        analysis.path(join_path(path, key.get_ref()), child.range());
        let field = match key.get_ref().as_str() {
            "class" => QueryStepField::OccurrenceClasses,
            "role" => QueryStepField::OccurrenceRoles,
            "namespace" => QueryStepField::OccurrenceNamespaces,
            _ => {
                add_spelling_error(
                    analysis,
                    key.range(),
                    "unknown-property",
                    format!("unknown occurrence filter property '{key}'"),
                    key.get_ref(),
                    ["class", "role", "namespace"]
                        .into_iter()
                        .map(|candidate| (candidate.to_string(), candidate.to_string()))
                        .collect::<Vec<_>>(),
                    |suggestion| {
                        serde_json::to_string(suggestion).expect("suggestions are JSON strings")
                    },
                );
                continue;
            }
        };
        analysis.add_help(key.range(), field.signature(), field.description());
        if !seen.insert(field) {
            analysis.error(
                key.range(),
                "duplicate-property",
                format!("duplicate property '{}'", field.label()),
            );
        }
        validate_json_occurrence_axis(field, child, analysis);
    }
}

fn validate_json_steps(value: &spanned::Value, path: &str, analysis: &mut Analysis) {
    let Some(steps) = value.as_array() else {
        if json_single_query_step_is_recognizable(value) {
            analysis.error_with_fix(
                value.range(),
                "wrong-value-shape",
                "expected an array of query step objects",
                QuerySourceFix {
                    title: "Wrap in an array".to_string(),
                    edit: QuerySourceEdit::Surround {
                        prefix: "[".to_string(),
                        suffix: "]".to_string(),
                    },
                },
            );
        } else {
            analysis.error(
                value.range(),
                "wrong-value-shape",
                "expected an array of query step objects",
            );
        }
        return;
    };
    if steps.len() > MAX_QUERY_STEPS {
        analysis.error(
            steps[MAX_QUERY_STEPS].range(),
            "invalid-query",
            format!("at most {MAX_QUERY_STEPS} query steps are allowed"),
        );
    }
    for (index, step) in steps.iter().enumerate() {
        let step_path = format!("{path}[{index}]");
        analysis.path(&step_path, step.range());
        let Some(object) = step.as_object() else {
            analysis.error(
                step.range(),
                "wrong-value-shape",
                "expected a query step object",
            );
            continue;
        };
        let op_label = object
            .iter()
            .find(|(key, _)| key.get_ref() == "op")
            .and_then(|(_, child)| child.as_string());
        let hierarchy = matches!(op_label, Some("supertypes" | "subtypes"));
        let reference_step = matches!(op_label, Some("references_of" | "used_by" | "uses"));
        let call_step = matches!(op_label, Some("callers" | "callees"));
        let call_site_step = matches!(op_label, Some("call_sites_to" | "call_sites_from"));
        let call_input_step = op_label == Some("call_input");
        let receiver_step = matches!(
            op_label,
            Some("receiver_targets" | "points_to" | "member_targets")
        );
        let typestate_step = op_label == Some("typestate");
        let value_flow_step = op_label == Some("value_flow");
        let taint_step = op_label == Some("taint");
        let witness_step = op_label == Some("witness");
        let occurrence_step = matches!(op_label, Some("occurrences_of" | "occurrences_in"));
        let binding_step = op_label == Some("bindings_in");
        let candidate_step = op_label == Some("candidates_of");
        let reaching_step = op_label == Some("reaching_binding");
        let mut seen_op = false;
        let mut seen_depth = false;
        let mut seen_transitive = false;
        let mut seen_reference_kinds = false;
        let mut seen_proof = false;
        let mut seen_surface = false;
        let mut seen_receiver = false;
        let mut seen_parameter_index = false;
        let mut seen_parameter_name = false;
        let mut seen_capture = false;
        let mut seen_protocol_ref = false;
        let mut seen_plan_ref = false;
        let mut seen_taint_ref = false;
        let mut seen_max_steps = false;
        let mut seen_max_bytes = false;
        let mut seen_occurrence_axes = HashSet::new();
        let mut seen_environment_axes = HashSet::new();
        let mut transitive_range = None;
        for (key, child) in object {
            let child_path = join_path(&step_path, key.get_ref());
            analysis.path(&child_path, child.range());
            let field = QueryStepField::from_label(key.get_ref());
            if field == Some(QueryStepField::Depth) && (hierarchy || call_step) {
                analysis.add_help(
                    key.range(),
                    QueryStepField::Depth.signature(),
                    QueryStepField::Depth.description(),
                );
                if seen_depth {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        "duplicate property 'depth'",
                    );
                }
                seen_depth = true;
                if !matches!(spanned_to_json(child), Value::Number(number) if number.as_u64().is_some_and(|value| value > 0))
                {
                    analysis.error(
                        child.range(),
                        "wrong-value-shape",
                        "traversal depth must be a positive integer",
                    );
                }
                continue;
            }
            if field == Some(QueryStepField::Transitive) && hierarchy {
                analysis.add_help(
                    key.range(),
                    QueryStepField::Transitive.signature(),
                    QueryStepField::Transitive.description(),
                );
                if seen_transitive {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        "duplicate property 'transitive'",
                    );
                }
                seen_transitive = true;
                transitive_range = Some(child.range());
                if spanned_to_json(child) != Value::Bool(true) {
                    analysis.error(
                        child.range(),
                        "wrong-value-shape",
                        "hierarchy transitive option must be true",
                    );
                }
                continue;
            }
            if field == Some(QueryStepField::ReferenceKinds) && reference_step {
                analysis.add_help(
                    key.range(),
                    QueryStepField::ReferenceKinds.signature(),
                    QueryStepField::ReferenceKinds.description(),
                );
                if seen_reference_kinds {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        "duplicate property 'reference_kinds'",
                    );
                }
                seen_reference_kinds = true;
                validate_json_reference_kinds(child, analysis);
                continue;
            }
            if field == Some(QueryStepField::Proof)
                && (reference_step || call_step || call_site_step)
            {
                analysis.add_help(
                    key.range(),
                    QueryStepField::Proof.signature(),
                    QueryStepField::Proof.description(),
                );
                if seen_proof {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        "duplicate property 'proof'",
                    );
                }
                seen_proof = true;
                validate_json_reference_scalar(child, "proof", usage_proof_from_label, analysis);
                continue;
            }
            if field == Some(QueryStepField::Receiver) && call_input_step {
                if seen_receiver {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        "duplicate property 'receiver'",
                    );
                }
                seen_receiver = true;
                if spanned_to_json(child) != Value::Bool(true) {
                    analysis.error(
                        child.range(),
                        "wrong-value-shape",
                        "receiver must be true when present",
                    );
                }
                continue;
            }
            if field == Some(QueryStepField::ParameterIndex) && call_input_step {
                if seen_parameter_index {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        "duplicate property 'parameter_index'",
                    );
                }
                seen_parameter_index = true;
                if !matches!(spanned_to_json(child), Value::Number(number) if number.as_u64().is_some())
                {
                    analysis.error(
                        child.range(),
                        "wrong-value-shape",
                        "parameter_index must be a non-negative integer",
                    );
                }
                continue;
            }
            if field == Some(QueryStepField::ParameterName) && call_input_step {
                if seen_parameter_name {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        "duplicate property 'parameter_name'",
                    );
                }
                seen_parameter_name = true;
                if let Some(name) = child.as_string() {
                    validate_parameter_name(name, child.range(), analysis);
                } else {
                    require_json_string(child, analysis);
                }
                continue;
            }
            if field == Some(QueryStepField::Capture) && receiver_step {
                analysis.add_help(
                    key.range(),
                    QueryStepField::Capture.signature(),
                    QueryStepField::Capture.description(),
                );
                if seen_capture {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        "duplicate property 'capture'",
                    );
                }
                seen_capture = true;
                if let Some(name) = child.as_string() {
                    validate_capture_name(
                        name,
                        child.range(),
                        "wrong-value-shape",
                        "capture name",
                        analysis,
                    );
                } else {
                    require_json_string(child, analysis);
                }
                continue;
            }
            if field == Some(QueryStepField::Surface) && reference_step {
                analysis.add_help(
                    key.range(),
                    QueryStepField::Surface.signature(),
                    QueryStepField::Surface.description(),
                );
                if seen_surface {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        "duplicate property 'surface'",
                    );
                }
                seen_surface = true;
                validate_json_reference_scalar(
                    child,
                    "surface",
                    usage_surface_from_label,
                    analysis,
                );
                continue;
            }
            if field == Some(QueryStepField::ProtocolRef) && typestate_step {
                analysis.add_help(
                    key.range(),
                    QueryStepField::ProtocolRef.signature(),
                    QueryStepField::ProtocolRef.description(),
                );
                if seen_protocol_ref {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        "duplicate property 'protocol_ref'",
                    );
                }
                seen_protocol_ref = true;
                match child.as_string() {
                    Some(value) => {
                        if let Err(error) =
                            value.parse::<super::super::super::analysis_context::ProtocolRef>()
                        {
                            analysis.error(child.range(), "wrong-value-shape", error.to_string());
                        }
                    }
                    None => require_json_string(child, analysis),
                }
                continue;
            }
            if field == Some(QueryStepField::PlanRef) && value_flow_step {
                analysis.add_help(
                    key.range(),
                    QueryStepField::PlanRef.signature(),
                    QueryStepField::PlanRef.description(),
                );
                if seen_plan_ref {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        "duplicate property 'plan_ref'",
                    );
                }
                seen_plan_ref = true;
                match child.as_string() {
                    Some(value) => {
                        if let Err(error) =
                            value.parse::<super::super::super::analysis_context::ValueFlowPlanRef>()
                        {
                            analysis.error(child.range(), "wrong-value-shape", error.to_string());
                        }
                    }
                    None => require_json_string(child, analysis),
                }
                continue;
            }
            if field == Some(QueryStepField::TaintRef) && taint_step {
                analysis.add_help(
                    key.range(),
                    QueryStepField::TaintRef.signature(),
                    QueryStepField::TaintRef.description(),
                );
                if seen_taint_ref {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        "duplicate property 'taint_ref'",
                    );
                }
                seen_taint_ref = true;
                match child.as_string() {
                    Some(value) => {
                        if let Err(error) =
                            value.parse::<super::super::super::analysis_context::TaintResultRef>()
                        {
                            analysis.error(child.range(), "wrong-value-shape", error.to_string());
                        }
                    }
                    None => require_json_string(child, analysis),
                }
                continue;
            }
            if matches!(
                field,
                Some(QueryStepField::MaxSteps | QueryStepField::MaxBytes)
            ) && witness_step
            {
                let field = field.expect("witness field matched above");
                analysis.add_help(key.range(), field.signature(), field.description());
                let seen = match field {
                    QueryStepField::MaxSteps => &mut seen_max_steps,
                    QueryStepField::MaxBytes => &mut seen_max_bytes,
                    _ => unreachable!("witness field matched above"),
                };
                if *seen {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        format!("duplicate property '{}'", field.label()),
                    );
                }
                *seen = true;
                if !matches!(spanned_to_json(child), Value::Number(number) if number.as_u64().is_some())
                {
                    analysis.error(
                        child.range(),
                        "wrong-value-shape",
                        "witness limit must be a non-negative integer",
                    );
                }
                continue;
            }
            let environment_field = match field {
                Some(
                    inner @ (QueryStepField::BindingKinds
                    | QueryStepField::BindingNames
                    | QueryStepField::BindingHoisting),
                ) if binding_step => Some(inner),
                Some(
                    inner @ (QueryStepField::CandidateTiers
                    | QueryStepField::CandidateOutcomes
                    | QueryStepField::CandidateBoundaries),
                ) if candidate_step => Some(inner),
                Some(inner @ QueryStepField::IncludeShadowed) if reaching_step => Some(inner),
                _ => None,
            };
            if let Some(environment_field) = environment_field {
                analysis.add_help(
                    key.range(),
                    environment_field.signature(),
                    environment_field.description(),
                );
                if !seen_environment_axes.insert(environment_field) {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        format!("duplicate property '{}'", environment_field.label()),
                    );
                }
                validate_json_environment_axis(
                    EnvironmentOptionField::Step(environment_field),
                    child,
                    analysis,
                );
                continue;
            }
            if matches!(
                field,
                Some(
                    QueryStepField::OccurrenceClasses
                        | QueryStepField::OccurrenceRoles
                        | QueryStepField::OccurrenceNamespaces
                )
            ) && occurrence_step
            {
                let field = field.expect("occurrence field matched above");
                analysis.add_help(key.range(), field.signature(), field.description());
                if !seen_occurrence_axes.insert(field) {
                    analysis.error(
                        key.range(),
                        "duplicate-property",
                        format!("duplicate property '{}'", field.label()),
                    );
                }
                validate_json_occurrence_axis(field, child, analysis);
                continue;
            }
            if field != Some(QueryStepField::Op) {
                let candidates: Vec<_> = ALL_QUERY_STEP_FIELDS
                    .iter()
                    .filter(|candidate| {
                        **candidate == QueryStepField::Op
                            || (hierarchy
                                && matches!(
                                    candidate,
                                    QueryStepField::Depth | QueryStepField::Transitive
                                ))
                            || (reference_step
                                && matches!(
                                    candidate,
                                    QueryStepField::ReferenceKinds
                                        | QueryStepField::Proof
                                        | QueryStepField::Surface
                                ))
                            || (call_step
                                && matches!(
                                    candidate,
                                    QueryStepField::Depth | QueryStepField::Proof
                                ))
                            || (call_site_step && **candidate == QueryStepField::Proof)
                            || (call_input_step
                                && matches!(
                                    candidate,
                                    QueryStepField::Receiver
                                        | QueryStepField::ParameterIndex
                                        | QueryStepField::ParameterName
                                ))
                            || (receiver_step && **candidate == QueryStepField::Capture)
                            || (typestate_step && **candidate == QueryStepField::ProtocolRef)
                            || (value_flow_step && **candidate == QueryStepField::PlanRef)
                            || (taint_step && **candidate == QueryStepField::TaintRef)
                            || (witness_step
                                && matches!(
                                    candidate,
                                    QueryStepField::MaxSteps | QueryStepField::MaxBytes
                                ))
                            || (occurrence_step
                                && matches!(
                                    candidate,
                                    QueryStepField::OccurrenceClasses
                                        | QueryStepField::OccurrenceRoles
                                        | QueryStepField::OccurrenceNamespaces
                                ))
                            || (binding_step
                                && matches!(
                                    candidate,
                                    QueryStepField::BindingKinds
                                        | QueryStepField::BindingNames
                                        | QueryStepField::BindingHoisting
                                ))
                            || (candidate_step
                                && matches!(
                                    candidate,
                                    QueryStepField::CandidateTiers
                                        | QueryStepField::CandidateOutcomes
                                        | QueryStepField::CandidateBoundaries
                                ))
                            || (reaching_step && **candidate == QueryStepField::IncludeShadowed)
                    })
                    .map(|candidate| (candidate.label().to_string(), candidate.label().to_string()))
                    .collect();
                add_spelling_error(
                    analysis,
                    key.range(),
                    "unknown-property",
                    format!("unknown query step property '{key}'"),
                    key.get_ref(),
                    candidates,
                    |suggestion| {
                        serde_json::to_string(suggestion).expect("suggestions are JSON strings")
                    },
                );
                continue;
            }
            if seen_op {
                analysis.error(key.range(), "duplicate-property", "duplicate property 'op'");
            }
            seen_op = true;
            analysis.add_help(
                key.range(),
                QueryStepField::Op.signature(),
                QueryStepField::Op.description(),
            );
            let Some(label) = child.as_string() else {
                analysis.error(
                    child.range(),
                    "wrong-value-shape",
                    "query step op must be a string",
                );
                continue;
            };
            let Some(step) = super::schema::QueryStepOp::from_label(label) else {
                add_spelling_error(
                    analysis,
                    child.range(),
                    "invalid-query-step",
                    format!("unknown query step {label:?}"),
                    label,
                    query_step_candidates(),
                    |suggestion| {
                        serde_json::to_string(suggestion).expect("suggestions are JSON strings")
                    },
                );
                continue;
            };
            analysis.add_help(child.range(), step.label(), step.description());
        }
        if seen_depth && seen_transitive {
            analysis.error(
                transitive_range.expect("seen transitive has a value range"),
                "invalid-query-step",
                "depth and transitive are mutually exclusive",
            );
        }
        if call_input_step
            && usize::from(seen_receiver)
                + usize::from(seen_parameter_index)
                + usize::from(seen_parameter_name)
                != 1
        {
            analysis.error(
                step.range(),
                "invalid-query-step",
                "call_input requires exactly one of receiver, parameter_index, or parameter_name",
            );
        }
        if typestate_step && !seen_protocol_ref {
            analysis.error(
                step.range(),
                "invalid-query-step",
                "typestate requires protocol_ref",
            );
        }
        if value_flow_step && !seen_plan_ref {
            analysis.error(
                step.range(),
                "invalid-query-step",
                "value_flow requires plan_ref",
            );
        }
        if taint_step && !seen_taint_ref {
            analysis.error(
                step.range(),
                "invalid-query-step",
                "taint requires taint_ref",
            );
        }
    }
}

fn validate_json_reference_kinds(value: &spanned::Value, analysis: &mut Analysis) {
    let Some(values) = value.as_array() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "reference_kinds must be a non-empty array of strings",
        );
        return;
    };
    if values.is_empty() {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "reference_kinds must be a non-empty array of strings",
        );
    }
    for item in values {
        let Some(label) = item.as_string() else {
            analysis.error(
                item.range(),
                "wrong-value-shape",
                "reference kind must be a string",
            );
            continue;
        };
        if reference_kind_from_label(label).is_none() {
            analysis.error(
                item.range(),
                "invalid-reference-kind",
                format!("unknown reference kind '{label}'"),
            );
        }
    }
}

fn validate_json_reference_scalar<T>(
    value: &spanned::Value,
    name: &str,
    parse: impl Fn(&str) -> Option<T>,
    analysis: &mut Analysis,
) {
    let Some(label) = value.as_string() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            format!("{name} must be a string"),
        );
        return;
    };
    if parse(label).is_none() {
        analysis.error(
            value.range(),
            "invalid-query-step-option",
            format!("unknown reference traversal {name} '{label}'"),
        );
    }
}

fn json_single_query_step_is_recognizable(value: &spanned::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.len() != 1 {
        return false;
    }
    let Some((key, value)) = object.iter().next() else {
        return false;
    };
    key.get_ref() == "op"
        && value
            .as_string()
            .is_some_and(|label| super::schema::QueryStepOp::from_label(label).is_some())
}

fn validate_json_result_detail(value: &spanned::Value, analysis: &mut Analysis) {
    let Some(label) = value.as_string() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "expected compact or full",
        );
        return;
    };
    if CodeQueryResultDetail::from_label(label).is_some() {
        analysis.add_help(
            value.range(),
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
            value.range(),
            "invalid-result-detail",
            "expected compact or full",
            label,
            result_detail_candidates(),
            |suggestion| serde_json::to_string(suggestion).expect("suggestions are JSON strings"),
        );
    }
}

fn validate_json_execution_mode(value: &spanned::Value, analysis: &mut Analysis) {
    let Some(label) = value.as_string() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "expected results, explain, or profile",
        );
        return;
    };
    if let Some(mode) = CodeQueryExecutionMode::from_label(label) {
        analysis.add_help(value.range(), mode.label(), mode.description());
    } else {
        add_spelling_error(
            analysis,
            value.range(),
            "invalid-execution-mode",
            "expected results, explain, or profile",
            label,
            execution_mode_candidates(),
            |suggestion| serde_json::to_string(suggestion).expect("suggestions are JSON strings"),
        );
    }
}

fn require_json_string(value: &spanned::Value, analysis: &mut Analysis) {
    if !value.is_string() {
        analysis.error(value.range(), "wrong-value-shape", "expected a string");
    }
}

fn validate_json_capture(value: &spanned::Value, analysis: &mut Analysis) {
    let Some(label) = value.as_string() else {
        require_json_string(value, analysis);
        return;
    };
    validate_capture_name(
        label,
        value.range(),
        "invalid-query",
        "capture label",
        analysis,
    );
}

fn record_json_duplicate(
    canonical: &str,
    range: Range<usize>,
    seen: &mut HashSet<String>,
    analysis: &mut Analysis,
) {
    if !seen.insert(canonical.to_string()) {
        analysis.error(
            range,
            "duplicate-property",
            format!("duplicate property '{canonical}'"),
        );
    }
}

fn join_path(path: &str, field: &str) -> String {
    if path.is_empty() {
        field.to_string()
    } else {
        format!("{path}.{field}")
    }
}
