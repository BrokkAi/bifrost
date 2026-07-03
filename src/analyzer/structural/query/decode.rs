use super::ir::{
    AstQuery, DEFAULT_LIMIT, MAX_CAPTURE_LENGTH, MAX_GLOB_LENGTH, MAX_KIND_LIST_ENTRIES,
    MAX_KWARG_NAME_LENGTH, MAX_KWARGS, MAX_LANGUAGE_FILTERS, MAX_LIMIT, MAX_PATTERN_DEPTH,
    MAX_PATTERN_NODES, MAX_ROLE_LIST_ENTRIES, MAX_STRING_PREDICATE_LENGTH, MAX_WHERE_GLOBS,
    Pattern, QueryError, StringPredicate,
};
use crate::analyzer::Language;
use crate::analyzer::structural::kinds::{ALL_KINDS, ALL_ROLES, NormalizedKind, Role};
use regex::Regex;
use serde_json::{Map, Value};

impl AstQuery {
    pub fn from_json(value: &Value) -> Result<Self, QueryError> {
        let object = as_object(value, "")?;
        let mut budget = QueryBudget::default();
        check_known_fields(
            object,
            "",
            &[
                "where",
                "languages",
                "match",
                "inside",
                "not_inside",
                "limit",
            ],
        )?;

        let where_globs = match object.get("where") {
            None => Vec::new(),
            Some(value) => decode_globs(value, "where")?,
        };

        let languages = match object.get("languages") {
            None => Vec::new(),
            Some(value) => decode_languages(value, "languages")?,
        };

        let root = match object.get("match") {
            Some(value) => decode_pattern(value, "match", &mut budget, 0)?,
            None => return Err(QueryError::new("match", "required field is missing")),
        };
        if root.kinds.is_empty() && root.name.is_none() && root.text.is_none() {
            // `not_kind` alone is near-wildcard, so it does not anchor a
            // root either.
            return Err(QueryError::new(
                "match",
                "root pattern must constrain at least one of \"kind\", \"name\", or \"text\"",
            ));
        }

        let inside = object
            .get("inside")
            .map(|value| decode_pattern(value, "inside", &mut budget, 0))
            .transpose()?;
        if let Some(pattern) = &inside
            && pattern.is_empty()
        {
            return Err(QueryError::new("inside", "pattern must not be empty"));
        }

        let not_inside = object
            .get("not_inside")
            .map(|value| decode_pattern(value, "not_inside", &mut budget, 0))
            .transpose()?;
        if let Some(pattern) = &not_inside
            && pattern.is_empty()
        {
            return Err(QueryError::new("not_inside", "pattern must not be empty"));
        }

        let limit = match object.get("limit") {
            None => DEFAULT_LIMIT,
            Some(value) => decode_limit(value, "limit")?,
        };

        Ok(Self {
            where_globs,
            languages,
            root,
            inside,
            not_inside,
            limit,
        })
    }
}

#[derive(Default)]
struct QueryBudget {
    pattern_nodes: usize,
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

fn check_known_fields(
    object: &Map<String, Value>,
    path: &str,
    known: &[&str],
) -> Result<(), QueryError> {
    for key in object.keys() {
        if !known.contains(&key.as_str()) {
            return Err(QueryError::new(
                child_path(path, key),
                format!("unknown field; expected one of: {}", known.join(", ")),
            ));
        }
    }
    Ok(())
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

fn reject_too_long(text: &str, path: &str, max_len: usize, label: &str) -> Result<(), QueryError> {
    if text.len() <= max_len {
        return Ok(());
    }
    Err(QueryError::new(
        path,
        format!("{label} must be at most {max_len} bytes"),
    ))
}

const BASE_PATTERN_FIELDS: &[&str] = &[
    "kind", "not_kind", "name", "text", "capture", "has", "not_has",
];

fn is_known_pattern_field(field: &str) -> bool {
    BASE_PATTERN_FIELDS.contains(&field) || Role::from_label(field).is_some()
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
    for key in object.keys() {
        if !is_known_pattern_field(key) {
            let expected = BASE_PATTERN_FIELDS
                .iter()
                .copied()
                .chain(ALL_ROLES.iter().map(|role| role.label()))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(QueryError::new(
                child_path(path, key),
                format!("unknown field; expected one of: {expected}"),
            ));
        }
    }

    let kinds = match object.get("kind") {
        None => Vec::new(),
        Some(value) => decode_kind_list(value, &child_path(path, "kind"))?,
    };
    let not_kinds = match object.get("not_kind") {
        None => Vec::new(),
        Some(value) => decode_kind_list(value, &child_path(path, "not_kind"))?,
    };

    let name = object
        .get("name")
        .map(|value| decode_string_predicate(value, &child_path(path, "name"), true))
        .transpose()?;

    let text = object
        .get("text")
        .map(|value| decode_string_predicate(value, &child_path(path, "text"), false))
        .transpose()?;

    let capture = object
        .get("capture")
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

    let has = decode_boxed_sub_pattern(object, path, "has", budget, depth + 1)?;
    let not_has = decode_boxed_sub_pattern(object, path, "not_has", budget, depth + 1)?;

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

    decode_role_fields(object, path, &mut pattern, budget, depth + 1)?;
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
            check_known_fields(object, path, &["regex"])?;
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
    object: &Map<String, Value>,
    path: &str,
    field: &str,
    budget: &mut QueryBudget,
    depth: usize,
) -> Result<Option<Box<Pattern>>, QueryError> {
    match object.get(field) {
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
    object: &Map<String, Value>,
    path: &str,
    pattern: &mut Pattern,
    budget: &mut QueryBudget,
    depth: usize,
) -> Result<(), QueryError> {
    let present_roles: Vec<Role> = Role::single_target_roles()
        .iter()
        .chain(Role::list_target_roles().iter())
        .chain(Role::map_target_roles().iter())
        .copied()
        .filter(|role| object.contains_key(role.label()))
        .collect();
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
        if let Some(value) = object.get(role.label()) {
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
        if let Some(value) = object.get(role.label()) {
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

    if let Some(value) = object.get(Role::Kwarg.label()) {
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
