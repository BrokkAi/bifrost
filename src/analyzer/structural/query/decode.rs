use super::ir::{
    CallInputSelector, CallSiteTraversalFilter, CallTraversalFilter, CodeQuery, CodeQueryPlan,
    CodeQueryPlanSource, CodeQueryResultDetail, CodeQuerySeed, DEFAULT_LIMIT, HierarchyTraversal,
    MAX_CAPTURE_LENGTH, MAX_GLOB_LENGTH, MAX_KIND_LIST_ENTRIES, MAX_KWARG_NAME_LENGTH, MAX_KWARGS,
    MAX_LANGUAGE_FILTERS, MAX_LIMIT, MAX_PATTERN_DEPTH, MAX_PATTERN_NODES, MAX_QUERY_BRANCHES,
    MAX_QUERY_PLAN_DEPTH, MAX_QUERY_PLAN_NODES, MAX_QUERY_STEPS, MAX_ROLE_LIST_ENTRIES,
    MAX_STRING_PREDICATE_LENGTH, MAX_WHERE_GLOBS, Pattern, QueryError, QueryStep,
    ReceiverTraversalFilter, ReferenceTraversalFilter, SetOperator, StringPredicate,
};
use super::schema::{
    ALL_QUERY_STEP_OPS, CodeQueryExecutionMode, PatternField, QueryField, QueryStepField,
    StringPredicateField, reference_kind_from_label, rql_schema_version_registry,
    usage_proof_from_label, usage_surface_from_label,
};
use crate::analyzer::Language;
use crate::analyzer::structural::kinds::{ALL_KINDS, NormalizedKind, Role};
use crate::schema_version::SchemaVersionRegistry;
use regex::Regex;
use serde_json::{Map, Value};
use std::num::NonZeroUsize;

impl CodeQuery {
    pub fn from_json(value: &Value) -> Result<Self, QueryError> {
        Self::from_json_with_schema_registry(value, rql_schema_version_registry())
    }

    pub(super) fn from_json_with_schema_registry(
        value: &Value,
        schema_versions: &SchemaVersionRegistry,
    ) -> Result<Self, QueryError> {
        let object = as_object(value, "")?;
        let mut budget = QueryBudget::default();
        let fields = collect_query_fields(object, "")?;
        let schema_version =
            decode_schema_version(fields.schema_version, "schema_version", schema_versions)?;

        let limit = match fields.limit {
            None => DEFAULT_LIMIT,
            Some(value) => decode_limit(value, "limit")?,
        };
        let result_detail = match fields.result_detail {
            None => CodeQueryResultDetail::Compact,
            Some(value) => decode_result_detail(value, "result_detail")?,
        };
        let execution_mode = match fields.execution_mode {
            None => CodeQueryExecutionMode::default(),
            Some(value) => decode_execution_mode(value, "execution_mode")?,
        };

        let query = Self {
            schema_version,
            plan: decode_plan(fields, "", &mut budget, true, 0)?,
            limit,
            result_detail,
            execution_mode,
        };
        query.validate_steps()?;
        Ok(query)
    }
}

#[derive(Default)]
struct QueryBudget {
    pattern_nodes: usize,
    plan_nodes: usize,
}

fn as_object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>, QueryError> {
    value.as_object().ok_or_else(|| {
        QueryError::new(
            path,
            format!("expected an object, got {}", type_name(value)),
        )
    })
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn child_path(path: &str, field: &str) -> String {
    if path.is_empty() {
        field.to_string()
    } else {
        format!("{path}.{field}")
    }
}

fn index_path(path: &str, index: usize) -> String {
    format!("{path}[{index}]")
}

#[derive(Clone, Copy, Default)]
struct QueryFields<'a> {
    where_globs: Option<&'a Value>,
    languages: Option<&'a Value>,
    root: Option<&'a Value>,
    union: Option<&'a Value>,
    intersect: Option<&'a Value>,
    except: Option<&'a Value>,
    inside: Option<&'a Value>,
    not_inside: Option<&'a Value>,
    steps: Option<&'a Value>,
    limit: Option<&'a Value>,
    result_detail: Option<&'a Value>,
    execution_mode: Option<&'a Value>,
    schema_version: Option<&'a Value>,
}

fn collect_query_fields<'a>(
    object: &'a Map<String, Value>,
    path: &str,
) -> Result<QueryFields<'a>, QueryError> {
    let mut fields = QueryFields::default();
    for (key, value) in object {
        let Some(field) = QueryField::from_label(key) else {
            return Err(QueryError::new(
                child_path(path, key),
                "unknown field in query object",
            ));
        };
        match field {
            QueryField::Where => fields.where_globs = Some(value),
            QueryField::Languages => fields.languages = Some(value),
            QueryField::Match => fields.root = Some(value),
            QueryField::Union => fields.union = Some(value),
            QueryField::Intersect => fields.intersect = Some(value),
            QueryField::Except => fields.except = Some(value),
            QueryField::Inside => fields.inside = Some(value),
            QueryField::NotInside => fields.not_inside = Some(value),
            QueryField::Steps => fields.steps = Some(value),
            QueryField::Limit => fields.limit = Some(value),
            QueryField::ResultDetail => fields.result_detail = Some(value),
            QueryField::ExecutionMode => fields.execution_mode = Some(value),
            QueryField::SchemaVersion => fields.schema_version = Some(value),
        }
    }
    Ok(fields)
}

fn decode_plan(
    fields: QueryFields<'_>,
    path: &str,
    budget: &mut QueryBudget,
    root: bool,
    depth: usize,
) -> Result<CodeQueryPlan, QueryError> {
    if depth > MAX_QUERY_PLAN_DEPTH {
        return Err(QueryError::new(
            path,
            format!("query plan depth must be at most {MAX_QUERY_PLAN_DEPTH}"),
        ));
    }
    budget.plan_nodes += 1;
    if budget.plan_nodes > MAX_QUERY_PLAN_NODES {
        return Err(QueryError::new(
            path,
            format!("query plan may contain at most {MAX_QUERY_PLAN_NODES} nodes"),
        ));
    }
    if !root {
        for (label, value) in [
            ("schema_version", fields.schema_version),
            ("limit", fields.limit),
            ("result_detail", fields.result_detail),
            ("execution_mode", fields.execution_mode),
        ] {
            if value.is_some() {
                return Err(QueryError::new(
                    child_path(path, label),
                    "field is allowed only on the root query",
                ));
            }
        }
    }

    let sources = [
        ("match", fields.root),
        ("union", fields.union),
        ("intersect", fields.intersect),
        ("except", fields.except),
    ];
    let present = sources
        .iter()
        .filter_map(|(label, value)| value.map(|value| (*label, value)))
        .collect::<Vec<_>>();
    if present.is_empty() {
        return Err(QueryError::new(
            child_path(path, "match"),
            "one of match, union, intersect, or except is required",
        ));
    }
    if present.len() > 1 {
        return Err(QueryError::new(
            child_path(path, present[1].0),
            format!(
                "query plan source is mutually exclusive with {}",
                present[0].0
            ),
        ));
    }

    let source = if let Some(value) = fields.root {
        let match_path = child_path(path, "match");
        let root_pattern = decode_pattern(value, &match_path, budget, 0)?;
        if root_pattern.kinds.is_empty()
            && root_pattern.name.is_none()
            && root_pattern.text.is_none()
        {
            return Err(QueryError::new(
                match_path,
                "root pattern must constrain at least one of \"kind\", \"name\", or \"text\"",
            ));
        }
        let inside_path = child_path(path, "inside");
        let inside = fields
            .inside
            .map(|value| decode_pattern(value, &inside_path, budget, 0))
            .transpose()?;
        if let Some(pattern) = &inside
            && pattern.is_empty()
        {
            return Err(QueryError::new(inside_path, "pattern must not be empty"));
        }
        let not_inside_path = child_path(path, "not_inside");
        let not_inside = fields
            .not_inside
            .map(|value| decode_pattern(value, &not_inside_path, budget, 0))
            .transpose()?;
        if let Some(pattern) = &not_inside
            && pattern.is_empty()
        {
            return Err(QueryError::new(
                not_inside_path,
                "pattern must not be empty",
            ));
        }
        CodeQueryPlanSource::Seed(Box::new(CodeQuerySeed {
            where_globs: fields
                .where_globs
                .map(|value| decode_globs(value, &child_path(path, "where")))
                .transpose()?
                .unwrap_or_default(),
            languages: fields
                .languages
                .map(|value| decode_languages(value, &child_path(path, "languages")))
                .transpose()?
                .unwrap_or_default(),
            root: root_pattern,
            inside,
            not_inside,
        }))
    } else {
        for (label, value) in [
            ("where", fields.where_globs),
            ("languages", fields.languages),
            ("inside", fields.inside),
            ("not_inside", fields.not_inside),
        ] {
            if value.is_some() {
                return Err(QueryError::new(
                    child_path(path, label),
                    "structural scope field requires a match source",
                ));
            }
        }
        let (op, value) = if let Some(value) = fields.union {
            (SetOperator::Union, value)
        } else if let Some(value) = fields.intersect {
            (SetOperator::Intersect, value)
        } else {
            (
                SetOperator::Except,
                fields.except.expect("set source is present"),
            )
        };
        let op_path = child_path(path, op.label());
        let entries = value.as_array().ok_or_else(|| {
            QueryError::new(&op_path, "expected an array of query branch objects")
        })?;
        if entries.len() < 2 {
            return Err(QueryError::new(
                &op_path,
                format!("{} requires at least two branches", op.label()),
            ));
        }
        if entries.len() > MAX_QUERY_BRANCHES {
            return Err(QueryError::new(
                &op_path,
                format!("at most {MAX_QUERY_BRANCHES} branches are allowed"),
            ));
        }
        let mut branches = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let branch_path = index_path(&op_path, index);
            let object = as_object(entry, &branch_path)?;
            let branch_fields = collect_query_fields(object, &branch_path)?;
            branches.push(decode_plan(
                branch_fields,
                &branch_path,
                budget,
                false,
                depth + 1,
            )?);
        }
        CodeQueryPlanSource::Set { op, branches }
    };

    let steps_path = child_path(path, "steps");
    let steps = fields
        .steps
        .map(|value| decode_steps(value, &steps_path))
        .transpose()?
        .unwrap_or_default();
    Ok(CodeQueryPlan { source, steps })
}

fn decode_globs(value: &Value, path: &str) -> Result<Vec<glob::Pattern>, QueryError> {
    let entries = value
        .as_array()
        .ok_or_else(|| QueryError::new(path, "expected an array of glob strings"))?;
    if entries.len() > MAX_WHERE_GLOBS {
        return Err(QueryError::new(
            path,
            format!("at most {MAX_WHERE_GLOBS} globs are allowed"),
        ));
    }
    let mut globs = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let entry_path = index_path(path, index);
        let text = entry
            .as_str()
            .ok_or_else(|| QueryError::new(&entry_path, "expected a glob string"))?;
        reject_too_long(text, &entry_path, MAX_GLOB_LENGTH, "glob")?;
        let compiled = glob::Pattern::new(text)
            .map_err(|error| QueryError::new(&entry_path, format!("invalid glob: {error}")))?;
        globs.push(compiled);
    }
    Ok(globs)
}

fn decode_languages(value: &Value, path: &str) -> Result<Vec<Language>, QueryError> {
    let entries = value
        .as_array()
        .ok_or_else(|| QueryError::new(path, "expected an array of language labels"))?;
    if entries.len() > MAX_LANGUAGE_FILTERS {
        return Err(QueryError::new(
            path,
            format!("at most {MAX_LANGUAGE_FILTERS} language filters are allowed"),
        ));
    }
    let mut languages = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let entry_path = index_path(path, index);
        let text = entry
            .as_str()
            .ok_or_else(|| QueryError::new(&entry_path, "expected a language label string"))?;
        let language = Language::from_config_label(text)
            .ok_or_else(|| QueryError::new(&entry_path, format!("unknown language {text:?}")))?;
        languages.push(language);
    }
    Ok(languages)
}

fn decode_limit(value: &Value, path: &str) -> Result<usize, QueryError> {
    let limit = value
        .as_u64()
        .ok_or_else(|| QueryError::new(path, "expected a positive integer"))?;
    if limit == 0 {
        return Err(QueryError::new(path, "limit must be at least 1"));
    }
    if limit > MAX_LIMIT as u64 {
        return Err(QueryError::new(
            path,
            format!("limit must be at most {MAX_LIMIT}"),
        ));
    }
    Ok(limit as usize)
}

fn decode_schema_version(
    value: Option<&Value>,
    path: &str,
    schema_versions: &SchemaVersionRegistry,
) -> Result<u64, QueryError> {
    let authored_version = value
        .map(|value| {
            let version = value.as_u64().ok_or_else(|| {
                QueryError::new(path, "expected an unsigned integer schema version")
            })?;
            u32::try_from(version).map_err(|_| {
                QueryError::new(
                    path,
                    "schema version must fit in an unsigned 32-bit integer",
                )
            })
        })
        .transpose()?;
    schema_versions
        .resolve(authored_version)
        .map(|resolution| u64::from(resolution.version))
        .map_err(|error| QueryError::new(path, error.to_string()))
}

fn decode_steps(value: &Value, path: &str) -> Result<Vec<QueryStep>, QueryError> {
    let entries = value
        .as_array()
        .ok_or_else(|| QueryError::new(path, "expected an array of step objects"))?;
    if entries.len() > MAX_QUERY_STEPS {
        return Err(QueryError::new(
            path,
            format!("at most {MAX_QUERY_STEPS} query steps are allowed"),
        ));
    }

    let mut steps = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let entry_path = index_path(path, index);
        let object = as_object(entry, &entry_path)?;
        let op_path = child_path(&entry_path, "op");
        let label = object
            .get("op")
            .ok_or_else(|| QueryError::new(&op_path, "required field is missing"))?
            .as_str()
            .ok_or_else(|| QueryError::new(&op_path, "expected a step name string"))?;
        let mut step = QueryStep::from_label(label).ok_or_else(|| {
            let expected = ALL_QUERY_STEP_OPS
                .iter()
                .map(|op| op.label())
                .collect::<Vec<_>>()
                .join(", ");
            QueryError::new(
                &op_path,
                format!("unknown query step {label:?}; expected {expected}"),
            )
        })?;
        let hierarchy = matches!(step, QueryStep::Supertypes(_) | QueryStep::Subtypes(_));
        let reference = matches!(
            step,
            QueryStep::ReferencesOf(_) | QueryStep::UsedBy(_) | QueryStep::Uses(_)
        );
        let call = matches!(step, QueryStep::Callers(_) | QueryStep::Callees(_));
        let call_site = matches!(
            step,
            QueryStep::CallSitesTo(_) | QueryStep::CallSitesFrom(_)
        );
        let call_input = matches!(step, QueryStep::CallInput(_));
        let receiver = matches!(
            step,
            QueryStep::ReceiverTargets(_) | QueryStep::PointsTo(_) | QueryStep::MemberTargets(_)
        );
        for key in object.keys() {
            match QueryStepField::from_label(key) {
                Some(QueryStepField::Op) => {}
                Some(QueryStepField::Depth | QueryStepField::Transitive) if hierarchy => {}
                Some(QueryStepField::Depth | QueryStepField::Proof) if call => {}
                Some(QueryStepField::Proof) if call_site => {}
                Some(
                    QueryStepField::Receiver
                    | QueryStepField::ParameterIndex
                    | QueryStepField::ParameterName,
                ) if call_input => {}
                Some(QueryStepField::Capture) if receiver => {}
                Some(
                    QueryStepField::ReferenceKinds
                    | QueryStepField::Proof
                    | QueryStepField::Surface,
                ) if reference => {}
                Some(
                    QueryStepField::Depth
                    | QueryStepField::Transitive
                    | QueryStepField::ReferenceKinds
                    | QueryStepField::Proof
                    | QueryStepField::Surface
                    | QueryStepField::Receiver
                    | QueryStepField::ParameterIndex
                    | QueryStepField::ParameterName
                    | QueryStepField::Capture,
                )
                | None => {
                    return Err(QueryError::new(
                        child_path(&entry_path, key),
                        "unknown field in query step object",
                    ));
                }
            }
        }
        if hierarchy {
            let depth = object.get("depth");
            let transitive = object.get("transitive");
            if depth.is_some() && transitive.is_some() {
                return Err(QueryError::new(
                    child_path(&entry_path, "transitive"),
                    "depth and transitive are mutually exclusive",
                ));
            }
            let traversal = if let Some(value) = depth {
                let raw = value.as_u64().ok_or_else(|| {
                    QueryError::new(
                        child_path(&entry_path, "depth"),
                        "expected a positive integer",
                    )
                })?;
                let depth = usize::try_from(raw)
                    .ok()
                    .and_then(NonZeroUsize::new)
                    .ok_or_else(|| {
                        QueryError::new(
                            child_path(&entry_path, "depth"),
                            "depth must be a positive platform-sized integer",
                        )
                    })?;
                HierarchyTraversal::Depth(depth)
            } else if let Some(value) = transitive {
                if value.as_bool() != Some(true) {
                    return Err(QueryError::new(
                        child_path(&entry_path, "transitive"),
                        "transitive must be true when present",
                    ));
                }
                HierarchyTraversal::Transitive
            } else {
                HierarchyTraversal::Direct
            };
            step = match step {
                QueryStep::Supertypes(_) => QueryStep::Supertypes(traversal),
                QueryStep::Subtypes(_) => QueryStep::Subtypes(traversal),
                _ => unreachable!("hierarchy step filtered above"),
            };
        } else if reference {
            let reference_kinds = match object.get("reference_kinds") {
                Some(value) => {
                    let values = value.as_array().ok_or_else(|| {
                        QueryError::new(
                            child_path(&entry_path, "reference_kinds"),
                            "expected an array of reference-kind strings",
                        )
                    })?;
                    if values.is_empty() {
                        return Err(QueryError::new(
                            child_path(&entry_path, "reference_kinds"),
                            "reference_kinds must not be empty",
                        ));
                    }
                    let mut kinds = Vec::with_capacity(values.len());
                    for (kind_index, value) in values.iter().enumerate() {
                        let path =
                            index_path(&child_path(&entry_path, "reference_kinds"), kind_index);
                        let label = value.as_str().ok_or_else(|| {
                            QueryError::new(&path, "expected a reference-kind string")
                        })?;
                        let kind = reference_kind_from_label(label).ok_or_else(|| {
                            QueryError::new(&path, format!("unknown reference kind {label:?}"))
                        })?;
                        if !kinds.contains(&kind) {
                            kinds.push(kind);
                        }
                    }
                    kinds
                }
                None => Vec::new(),
            };
            let proof = object
                .get("proof")
                .map(|value| {
                    let path = child_path(&entry_path, "proof");
                    let label = value
                        .as_str()
                        .ok_or_else(|| QueryError::new(&path, "expected proven or unproven"))?;
                    usage_proof_from_label(label)
                        .ok_or_else(|| QueryError::new(&path, "expected proven or unproven"))
                })
                .transpose()?;
            let surface = object
                .get("surface")
                .map(|value| {
                    let path = child_path(&entry_path, "surface");
                    let label = value.as_str().ok_or_else(|| {
                        QueryError::new(&path, "expected external_usages or lsp_references")
                    })?;
                    usage_surface_from_label(label).ok_or_else(|| {
                        QueryError::new(&path, "expected external_usages or lsp_references")
                    })
                })
                .transpose()?
                .unwrap_or_default();
            let filter = ReferenceTraversalFilter {
                reference_kinds,
                proof,
                surface,
            };
            step = match step {
                QueryStep::ReferencesOf(_) => QueryStep::ReferencesOf(filter),
                QueryStep::UsedBy(_) => QueryStep::UsedBy(filter),
                QueryStep::Uses(_) => QueryStep::Uses(filter),
                _ => unreachable!("reference step filtered above"),
            };
        } else if call {
            let depth = object
                .get("depth")
                .map(|value| {
                    let path = child_path(&entry_path, "depth");
                    value
                        .as_u64()
                        .and_then(|raw| usize::try_from(raw).ok())
                        .and_then(NonZeroUsize::new)
                        .ok_or_else(|| QueryError::new(path, "expected a positive integer"))
                })
                .transpose()?
                .unwrap_or(NonZeroUsize::MIN);
            let proof = decode_optional_proof(object.get("proof"), &entry_path)?;
            let filter = CallTraversalFilter { depth, proof };
            step = match step {
                QueryStep::Callers(_) => QueryStep::Callers(filter),
                QueryStep::Callees(_) => QueryStep::Callees(filter),
                _ => unreachable!("call step filtered above"),
            };
        } else if call_site {
            let filter = CallSiteTraversalFilter {
                proof: decode_optional_proof(object.get("proof"), &entry_path)?,
            };
            step = match step {
                QueryStep::CallSitesTo(_) => QueryStep::CallSitesTo(filter),
                QueryStep::CallSitesFrom(_) => QueryStep::CallSitesFrom(filter),
                _ => unreachable!("call-site step filtered above"),
            };
        } else if call_input {
            let selector_count = ["receiver", "parameter_index", "parameter_name"]
                .into_iter()
                .filter(|field| object.contains_key(*field))
                .count();
            if selector_count != 1 {
                return Err(QueryError::new(
                    &entry_path,
                    "call_input requires exactly one of receiver, parameter_index, or parameter_name",
                ));
            }
            let selector = if let Some(value) = object.get("receiver") {
                if value.as_bool() != Some(true) {
                    return Err(QueryError::new(
                        child_path(&entry_path, "receiver"),
                        "receiver must be true when present",
                    ));
                }
                CallInputSelector::Receiver
            } else if let Some(value) = object.get("parameter_index") {
                let path = child_path(&entry_path, "parameter_index");
                let index = value
                    .as_u64()
                    .and_then(|raw| usize::try_from(raw).ok())
                    .ok_or_else(|| QueryError::new(path, "expected a non-negative integer"))?;
                CallInputSelector::ParameterIndex(index)
            } else {
                let path = child_path(&entry_path, "parameter_name");
                let shape = QueryStepField::ParameterName.value_shape();
                let name = object["parameter_name"]
                    .as_str()
                    .filter(|name| shape.accepts_string(name))
                    .ok_or_else(|| {
                        let (minimum, maximum) = shape
                            .string_length_bounds()
                            .expect("parameter-name shape has string bounds");
                        QueryError::new(
                            path,
                            format!("expected a string between {minimum} and {maximum} bytes"),
                        )
                    })?;
                CallInputSelector::ParameterName(name.to_owned())
            };
            step = QueryStep::CallInput(selector);
        } else if receiver {
            let capture = object
                .get("capture")
                .map(|value| {
                    let path = child_path(&entry_path, "capture");
                    let shape = QueryStepField::Capture.value_shape();
                    value
                        .as_str()
                        .filter(|name| shape.accepts_string(name))
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            let (minimum, maximum) = shape
                                .string_length_bounds()
                                .expect("capture-name shape has string bounds");
                            QueryError::new(
                                path,
                                format!("expected a string between {minimum} and {maximum} bytes"),
                            )
                        })
                })
                .transpose()?;
            let filter = ReceiverTraversalFilter { capture };
            step = match step {
                QueryStep::ReceiverTargets(_) => QueryStep::ReceiverTargets(filter),
                QueryStep::PointsTo(_) => QueryStep::PointsTo(filter),
                QueryStep::MemberTargets(_) => QueryStep::MemberTargets(filter),
                _ => unreachable!("receiver step filtered above"),
            };
        }
        steps.push(step);
    }
    Ok(steps)
}

fn decode_optional_proof(
    value: Option<&Value>,
    path: &str,
) -> Result<Option<crate::analyzer::usages::UsageProof>, QueryError> {
    value
        .map(|value| {
            let path = child_path(path, "proof");
            let label = value
                .as_str()
                .ok_or_else(|| QueryError::new(&path, "expected proven or unproven"))?;
            usage_proof_from_label(label)
                .ok_or_else(|| QueryError::new(path, "expected proven or unproven"))
        })
        .transpose()
}

fn decode_result_detail(value: &Value, path: &str) -> Result<CodeQueryResultDetail, QueryError> {
    let label = value
        .as_str()
        .ok_or_else(|| QueryError::new(path, "expected \"compact\" or \"full\""))?;
    CodeQueryResultDetail::from_label(label).ok_or_else(|| {
        QueryError::new(
            path,
            format!("unknown result detail {label:?}; expected \"compact\" or \"full\""),
        )
    })
}

fn decode_execution_mode(value: &Value, path: &str) -> Result<CodeQueryExecutionMode, QueryError> {
    let label = value.as_str().ok_or_else(|| {
        QueryError::new(path, "expected \"results\", \"explain\", or \"profile\"")
    })?;
    CodeQueryExecutionMode::from_label(label).ok_or_else(|| {
        QueryError::new(
            path,
            format!(
                "unknown execution mode {label:?}; expected \"results\", \"explain\", or \"profile\""
            ),
        )
    })
}

fn reject_too_long(text: &str, path: &str, max_len: usize, label: &str) -> Result<(), QueryError> {
    if text.len() <= max_len {
        return Ok(());
    }
    Err(QueryError::new(
        path,
        format!("{label} must be at most {max_len} bytes"),
    ))
}

#[derive(Default)]
struct PatternFields<'a> {
    kind: Option<&'a Value>,
    not_kind: Option<&'a Value>,
    name: Option<&'a Value>,
    text: Option<&'a Value>,
    capture: Option<&'a Value>,
    has: Option<&'a Value>,
    not_has: Option<&'a Value>,
    roles: Vec<(Role, &'a Value)>,
}

fn collect_pattern_fields<'a>(
    object: &'a Map<String, Value>,
    path: &str,
) -> Result<PatternFields<'a>, QueryError> {
    let mut fields = PatternFields::default();
    for (key, value) in object {
        if let Some(field) = PatternField::from_label(key) {
            match field {
                PatternField::Kind => fields.kind = Some(value),
                PatternField::NotKind => fields.not_kind = Some(value),
                PatternField::Name => fields.name = Some(value),
                PatternField::Text => fields.text = Some(value),
                PatternField::Capture => fields.capture = Some(value),
                PatternField::Has => fields.has = Some(value),
                PatternField::NotHas => fields.not_has = Some(value),
            }
        } else if let Some(role) = Role::from_label(key) {
            fields.roles.push((role, value));
        } else {
            return Err(QueryError::new(
                child_path(path, key),
                "unknown field in pattern object",
            ));
        }
    }
    Ok(fields)
}

fn decode_pattern(
    value: &Value,
    path: &str,
    budget: &mut QueryBudget,
    depth: usize,
) -> Result<Pattern, QueryError> {
    if depth > MAX_PATTERN_DEPTH {
        return Err(QueryError::new(
            path,
            format!("pattern nesting must be at most {MAX_PATTERN_DEPTH} levels"),
        ));
    }
    budget.pattern_nodes += 1;
    if budget.pattern_nodes > MAX_PATTERN_NODES {
        return Err(QueryError::new(
            path,
            format!("query may contain at most {MAX_PATTERN_NODES} pattern nodes"),
        ));
    }
    let object = as_object(value, path)?;
    let fields = collect_pattern_fields(object, path)?;

    let kinds = match fields.kind {
        None => Vec::new(),
        Some(value) => decode_kind_list(value, &child_path(path, "kind"))?,
    };
    let not_kinds = match fields.not_kind {
        None => Vec::new(),
        Some(value) => decode_kind_list(value, &child_path(path, "not_kind"))?,
    };

    let name = fields
        .name
        .map(|value| decode_string_predicate(value, &child_path(path, "name"), true))
        .transpose()?;

    let text = fields
        .text
        .map(|value| decode_string_predicate(value, &child_path(path, "text"), false))
        .transpose()?;

    let capture = fields
        .capture
        .map(|value| {
            let capture_path = child_path(path, "capture");
            let label = value
                .as_str()
                .ok_or_else(|| QueryError::new(&capture_path, "expected a string label"))?;
            if label.is_empty() {
                return Err(QueryError::new(
                    &capture_path,
                    "capture label must not be empty",
                ));
            }
            reject_too_long(label, &capture_path, MAX_CAPTURE_LENGTH, "capture label")?;
            Ok(label.to_string())
        })
        .transpose()?;

    let has = decode_boxed_sub_pattern(fields.has, path, "has", budget, depth + 1)?;
    let not_has = decode_boxed_sub_pattern(fields.not_has, path, "not_has", budget, depth + 1)?;

    let mut pattern = Pattern {
        kinds,
        not_kinds,
        name,
        text,
        capture,
        has,
        not_has,
        ..Pattern::default()
    };

    decode_role_fields(&fields.roles, path, &mut pattern, budget, depth + 1)?;
    Ok(pattern)
}

/// Decode a `kind` / `not_kind` value: a single kind label or a non-empty
/// array of them.
fn decode_kind_list(value: &Value, path: &str) -> Result<Vec<NormalizedKind>, QueryError> {
    match value {
        Value::String(label) => Ok(vec![decode_kind_label(label, path)?]),
        Value::Array(entries) => {
            if entries.is_empty() {
                return Err(QueryError::new(path, "kind array must not be empty"));
            }
            if entries.len() > MAX_KIND_LIST_ENTRIES {
                return Err(QueryError::new(
                    path,
                    format!("kind array may contain at most {MAX_KIND_LIST_ENTRIES} entries"),
                ));
            }
            let mut kinds = Vec::with_capacity(entries.len());
            for (index, entry) in entries.iter().enumerate() {
                let entry_path = index_path(path, index);
                let label = entry
                    .as_str()
                    .ok_or_else(|| QueryError::new(&entry_path, "expected a kind label string"))?;
                kinds.push(decode_kind_label(label, &entry_path)?);
            }
            Ok(kinds)
        }
        _ => Err(QueryError::new(
            path,
            "expected a kind label string or an array of kind labels",
        )),
    }
}

fn decode_kind_label(label: &str, path: &str) -> Result<NormalizedKind, QueryError> {
    NormalizedKind::from_label(label).ok_or_else(|| {
        QueryError::new(
            path,
            format!(
                "unknown kind {label:?}; expected one of: {}",
                ALL_KINDS
                    .iter()
                    .map(|kind| kind.label())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    })
}

fn decode_string_predicate(
    value: &Value,
    path: &str,
    allow_exact_shorthand: bool,
) -> Result<StringPredicate, QueryError> {
    match value {
        Value::String(text) if allow_exact_shorthand => {
            reject_too_long(text, path, MAX_STRING_PREDICATE_LENGTH, "exact string")?;
            Ok(StringPredicate::Exact(text.clone()))
        }
        Value::Object(object) => {
            for key in object.keys() {
                let Some(field) = StringPredicateField::from_label(key) else {
                    return Err(QueryError::new(
                        child_path(path, key),
                        "unknown field in string predicate object",
                    ));
                };
                match field {
                    StringPredicateField::Regex => {}
                }
            }
            let regex_path = child_path(path, "regex");
            let source = object
                .get("regex")
                .ok_or_else(|| QueryError::new(&regex_path, "required field is missing"))?
                .as_str()
                .ok_or_else(|| QueryError::new(&regex_path, "expected a regex string"))?;
            reject_too_long(source, &regex_path, MAX_STRING_PREDICATE_LENGTH, "regex")?;
            let compiled = Regex::new(source)
                .map_err(|error| QueryError::new(&regex_path, format!("invalid regex: {error}")))?;
            Ok(StringPredicate::Regex(compiled))
        }
        _ if allow_exact_shorthand => Err(QueryError::new(
            path,
            "expected a string (exact match) or { \"regex\": ... }",
        )),
        _ => Err(QueryError::new(path, "expected { \"regex\": ... }")),
    }
}

fn decode_boxed_sub_pattern(
    value: Option<&Value>,
    path: &str,
    field: &str,
    budget: &mut QueryBudget,
    depth: usize,
) -> Result<Option<Box<Pattern>>, QueryError> {
    match value {
        None => Ok(None),
        Some(value) => {
            let field_path = child_path(path, field);
            let pattern = decode_pattern(value, &field_path, budget, depth)?;
            if pattern.is_empty() {
                return Err(QueryError::new(&field_path, "pattern must not be empty"));
            }
            Ok(Some(Box::new(pattern)))
        }
    }
}

/// Decode the role fields (`callee`, `args`, `left`, ...) into `pattern`,
/// enforcing that each present role is valid for the pattern's declared kind.
fn decode_role_fields(
    roles: &[(Role, &Value)],
    path: &str,
    pattern: &mut Pattern,
    budget: &mut QueryBudget,
    depth: usize,
) -> Result<(), QueryError> {
    let present_roles = roles.iter().map(|(role, _)| *role).collect::<Vec<_>>();
    if present_roles.is_empty() {
        return Ok(());
    }

    if pattern.kinds.is_empty() {
        return Err(QueryError::new(
            child_path(path, present_roles[0].label()),
            format!(
                "role {:?} requires the pattern to declare a \"kind\"",
                present_roles[0].label()
            ),
        ));
    }
    // A role must be satisfiable by at least one of the declared kinds;
    // otherwise the pattern is provably empty and almost certainly a mistake.
    for role in &present_roles {
        if !pattern.kinds.iter().any(|&kind| role.valid_for(kind)) {
            let kind_labels = pattern
                .kinds
                .iter()
                .map(|kind| kind.label())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(QueryError::new(
                child_path(path, role.label()),
                format!(
                    "role {:?} is not valid for kind(s) {kind_labels}",
                    role.label(),
                ),
            ));
        }
    }

    for &role in Role::single_target_roles() {
        if let Some(value) = role_value(roles, role) {
            let role_path = child_path(path, role.label());
            let sub_pattern = Box::new(decode_pattern(value, &role_path, budget, depth)?);
            match role {
                Role::Callee => pattern.callee = Some(sub_pattern),
                Role::Receiver => pattern.receiver = Some(sub_pattern),
                Role::Left => pattern.left = Some(sub_pattern),
                Role::Right => pattern.right = Some(sub_pattern),
                Role::Module => pattern.module = Some(sub_pattern),
                Role::Object => pattern.object = Some(sub_pattern),
                Role::Field => pattern.field = Some(sub_pattern),
                Role::Arg | Role::Kwarg | Role::Decorator => unreachable!("non-single role"),
            }
        }
    }

    for &role in Role::list_target_roles() {
        if let Some(value) = role_value(roles, role) {
            let role_path = child_path(path, role.label());
            let entries = value
                .as_array()
                .ok_or_else(|| QueryError::new(&role_path, "expected an array of patterns"))?;
            if entries.len() > MAX_ROLE_LIST_ENTRIES {
                return Err(QueryError::new(
                    &role_path,
                    format!("role array may contain at most {MAX_ROLE_LIST_ENTRIES} entries"),
                ));
            }
            let mut patterns = Vec::with_capacity(entries.len());
            for (index, entry) in entries.iter().enumerate() {
                patterns.push(decode_pattern(
                    entry,
                    &index_path(&role_path, index),
                    budget,
                    depth,
                )?);
            }
            match role {
                Role::Arg => pattern.args = patterns,
                Role::Decorator => pattern.decorators = patterns,
                Role::Callee
                | Role::Receiver
                | Role::Kwarg
                | Role::Left
                | Role::Right
                | Role::Module
                | Role::Object
                | Role::Field => unreachable!("non-list role"),
            }
        }
    }

    if let Some(value) = role_value(roles, Role::Kwarg) {
        let role_path = child_path(path, Role::Kwarg.label());
        let entries = as_object(value, &role_path)?;
        if entries.len() > MAX_KWARGS {
            return Err(QueryError::new(
                &role_path,
                format!("kwargs may contain at most {MAX_KWARGS} entries"),
            ));
        }
        let mut kwargs = Vec::with_capacity(entries.len());
        for (keyword, entry) in entries {
            let keyword_path = child_path(&role_path, keyword);
            reject_too_long(keyword, &keyword_path, MAX_KWARG_NAME_LENGTH, "keyword")?;
            kwargs.push((
                keyword.clone(),
                decode_pattern(entry, &keyword_path, budget, depth)?,
            ));
        }
        pattern.kwargs = kwargs;
    }

    Ok(())
}

fn role_value<'a>(roles: &[(Role, &'a Value)], expected: Role) -> Option<&'a Value> {
    roles
        .iter()
        .find_map(|(role, value)| (*role == expected).then_some(*value))
}
