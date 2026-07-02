//! The canonical typed IR for structural queries (issue #328), plus the JSON
//! frontend. JSON is the v1 external surface; a later S-expression frontend
//! must parse into this same `AstQuery` so the matcher never sees syntax.
//!
//! Decoding is hand-rolled over `serde_json::Value` rather than derived: every
//! error carries the JSON path of the offending field (e.g.
//! `match.callee.name`), which is what lets agent callers self-correct, and
//! rules like "role `callee` requires a pattern kind that supports it" are
//! validation, not shape.

use super::kinds::{NormalizedKind, Role};
use crate::analyzer::Language;
use regex::Regex;
use serde_json::{Map, Value, json};
use std::fmt;

pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 1000;
pub const MAX_WHERE_GLOBS: usize = 128;
pub const MAX_GLOB_LENGTH: usize = 1024;
pub const MAX_LANGUAGE_FILTERS: usize = 32;
pub const MAX_PATTERN_DEPTH: usize = 64;
pub const MAX_PATTERN_NODES: usize = 256;
pub const MAX_KIND_LIST_ENTRIES: usize = 32;
pub const MAX_ROLE_LIST_ENTRIES: usize = 64;
pub const MAX_KWARGS: usize = 64;
pub const MAX_STRING_PREDICATE_LENGTH: usize = 4096;
pub const MAX_CAPTURE_LENGTH: usize = 128;
pub const MAX_KWARG_NAME_LENGTH: usize = 128;

/// A structural query: one root pattern plus containment constraints and
/// workspace scoping. This is the semantic authority both syntaxes parse into.
#[derive(Debug, Clone)]
pub struct AstQuery {
    /// Path globs relative to the workspace root; empty means all files.
    pub where_globs: Vec<glob::Pattern>,
    /// Language filter; empty means all languages with structural adapters.
    pub languages: Vec<Language>,
    pub root: Pattern,
    /// The root match must be lexically contained in a node matching this.
    pub inside: Option<Pattern>,
    /// Verifier-only negative containment: never used for candidate pruning.
    pub not_inside: Option<Pattern>,
    pub limit: usize,
}

/// Predicate over a string attribute of a fact (its name or source text).
#[derive(Debug, Clone)]
pub enum StringPredicate {
    Exact(String),
    Regex(Regex),
}

impl StringPredicate {
    pub fn matches(&self, value: &str) -> bool {
        match self {
            StringPredicate::Exact(expected) => value == expected,
            StringPredicate::Regex(regex) => regex.is_match(value),
        }
    }
}

/// One node pattern. All fields optional; the *root* `match` pattern must
/// constrain at least one of kind/name/text (a wildcard root would match
/// every node in the workspace), while nested patterns may be capture-only
/// or empty (an empty `args` entry means "some argument exists").
#[derive(Debug, Clone, Default)]
pub struct Pattern {
    /// JSON `kind`: a union of kinds, each subtype-aware (`literal` matches
    /// `string_literal`; `["function", "method"]` matches either). Empty
    /// means unconstrained. There is deliberately no exact-match variant:
    /// leaf kinds are their own exact match, and "exactly an abstract kind"
    /// would only select facts from adapters too coarse to classify further —
    /// adapter precision is surfaced through diagnostics, not query
    /// semantics.
    pub kinds: Vec<NormalizedKind>,
    /// JSON `not_kind`: subtype-aware exclusion, verifier-only (never used
    /// for candidate pruning). `{"kind": "callable", "not_kind":
    /// ["constructor", "lambda"]}` matches named functions and methods.
    pub not_kinds: Vec<NormalizedKind>,
    pub name: Option<StringPredicate>,
    pub text: Option<StringPredicate>,
    pub capture: Option<String>,
    pub has: Option<Box<Pattern>>,
    /// Verifier-only: never used for candidate pruning.
    pub not_has: Option<Box<Pattern>>,
    // Role sub-patterns. Only valid when `kind` is declared and the role is
    // valid for at least one of its kinds (see `Role::valid_for`).
    pub callee: Option<Box<Pattern>>,
    pub receiver: Option<Box<Pattern>>,
    /// Each listed pattern must match some positional argument; matches must
    /// appear in argument order but need not be contiguous.
    pub args: Vec<Pattern>,
    /// Named/keyword arguments: each entry must match the value of the
    /// keyword argument with that name.
    pub kwargs: Vec<(String, Pattern)>,
    pub left: Option<Box<Pattern>>,
    pub right: Option<Box<Pattern>>,
    pub module: Option<Box<Pattern>>,
    /// Each listed pattern must match some decorator/annotation.
    pub decorators: Vec<Pattern>,
    pub object: Option<Box<Pattern>>,
    pub field: Option<Box<Pattern>>,
}

impl Pattern {
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
            && self.not_kinds.is_empty()
            && self.name.is_none()
            && self.text.is_none()
            && self.capture.is_none()
            && self.has.is_none()
            && self.not_has.is_none()
            && !self.constrains_roles()
    }

    fn constrains_roles(&self) -> bool {
        Role::single_target_roles()
            .iter()
            .any(|&role| self.single_role_pattern(role).is_some())
            || Role::list_target_roles()
                .iter()
                .any(|&role| !self.list_role_patterns(role).is_empty())
            || !self.kwargs.is_empty()
    }

    pub(crate) fn single_role_pattern(&self, role: Role) -> Option<&Pattern> {
        match role {
            Role::Callee => self.callee.as_deref(),
            Role::Receiver => self.receiver.as_deref(),
            Role::Left => self.left.as_deref(),
            Role::Right => self.right.as_deref(),
            Role::Module => self.module.as_deref(),
            Role::Object => self.object.as_deref(),
            Role::Field => self.field.as_deref(),
            Role::Arg | Role::Kwarg | Role::Decorator => None,
        }
    }

    pub(crate) fn list_role_patterns(&self, role: Role) -> &[Pattern] {
        match role {
            Role::Arg => &self.args,
            Role::Decorator => &self.decorators,
            _ => &[],
        }
    }

    pub(crate) fn has_role_constraints(&self) -> bool {
        self.constrains_roles()
    }
}

/// A query rejection, carrying the JSON path of the offending field so
/// callers (especially agents) can self-correct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryError {
    pub path: String,
    pub message: String,
}

impl QueryError {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(f, "invalid query: {}", self.message)
        } else {
            write!(f, "invalid query at {}: {}", self.path, self.message)
        }
    }
}

impl std::error::Error for QueryError {}

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

    /// The canonical JSON form of this query. Used by `--print-json` style
    /// debugging and by tests asserting that both frontends parse to the same
    /// query (`parse(json).to_canonical_json() == parse(sexp).to_canonical_json()`).
    pub fn to_canonical_json(&self) -> Value {
        let mut object = Map::new();
        if !self.where_globs.is_empty() {
            object.insert(
                "where".to_string(),
                Value::Array(
                    self.where_globs
                        .iter()
                        .map(|glob| Value::String(glob.as_str().to_string()))
                        .collect(),
                ),
            );
        }
        if !self.languages.is_empty() {
            object.insert(
                "languages".to_string(),
                Value::Array(
                    self.languages
                        .iter()
                        .map(|language| Value::String(language.config_label().to_string()))
                        .collect(),
                ),
            );
        }
        object.insert("match".to_string(), pattern_to_json(&self.root));
        if let Some(pattern) = &self.inside {
            object.insert("inside".to_string(), pattern_to_json(pattern));
        }
        if let Some(pattern) = &self.not_inside {
            object.insert("not_inside".to_string(), pattern_to_json(pattern));
        }
        object.insert("limit".to_string(), json!(self.limit));
        Value::Object(object)
    }

    pub(crate) fn referenced_kinds(&self) -> Vec<NormalizedKind> {
        let mut kinds = Vec::new();
        collect_referenced_kinds(&self.root, &mut kinds);
        if let Some(pattern) = &self.inside {
            collect_referenced_kinds(pattern, &mut kinds);
        }
        if let Some(pattern) = &self.not_inside {
            collect_referenced_kinds(pattern, &mut kinds);
        }
        kinds.sort_unstable();
        kinds.dedup();
        kinds
    }

    pub(crate) fn used_roles(&self) -> Vec<Role> {
        let mut roles = Vec::new();
        collect_used_roles(&self.root, &mut roles);
        if let Some(pattern) = &self.inside {
            collect_used_roles(pattern, &mut roles);
        }
        if let Some(pattern) = &self.not_inside {
            collect_used_roles(pattern, &mut roles);
        }
        roles.sort_unstable();
        roles.dedup();
        roles
    }
}

fn collect_referenced_kinds(pattern: &Pattern, out: &mut Vec<NormalizedKind>) {
    out.extend(pattern.kinds.iter().copied());
    out.extend(pattern.not_kinds.iter().copied());
    if let Some(pattern) = &pattern.has {
        collect_referenced_kinds(pattern, out);
    }
    if let Some(pattern) = &pattern.not_has {
        collect_referenced_kinds(pattern, out);
    }
    for &role in Role::single_target_roles() {
        if let Some(pattern) = pattern.single_role_pattern(role) {
            collect_referenced_kinds(pattern, out);
        }
    }
    for &role in Role::list_target_roles() {
        for pattern in pattern.list_role_patterns(role) {
            collect_referenced_kinds(pattern, out);
        }
    }
    for (_, pattern) in &pattern.kwargs {
        collect_referenced_kinds(pattern, out);
    }
}

#[derive(Default)]
struct QueryBudget {
    pattern_nodes: usize,
}

fn collect_used_roles(pattern: &Pattern, out: &mut Vec<Role>) {
    if let Some(pattern) = &pattern.has {
        collect_used_roles(pattern, out);
    }
    if let Some(pattern) = &pattern.not_has {
        collect_used_roles(pattern, out);
    }
    for &role in Role::single_target_roles() {
        if let Some(pattern) = pattern.single_role_pattern(role) {
            out.push(role);
            collect_used_roles(pattern, out);
        }
    }
    for &role in Role::list_target_roles() {
        for pattern in pattern.list_role_patterns(role) {
            out.push(role);
            collect_used_roles(pattern, out);
        }
    }
    for (_, pattern) in &pattern.kwargs {
        out.push(Role::Kwarg);
        collect_used_roles(pattern, out);
    }
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
                .chain(super::kinds::ALL_ROLES.iter().map(|role| role.label()))
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
                super::kinds::ALL_KINDS
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
                _ => unreachable!("non-list role"),
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

fn kind_list_to_json(kinds: &[NormalizedKind]) -> Value {
    if kinds.len() == 1 {
        json!(kinds[0].label())
    } else {
        Value::Array(kinds.iter().map(|kind| json!(kind.label())).collect())
    }
}

fn pattern_to_json(pattern: &Pattern) -> Value {
    let mut object = Map::new();
    if !pattern.kinds.is_empty() {
        object.insert("kind".to_string(), kind_list_to_json(&pattern.kinds));
    }
    if !pattern.not_kinds.is_empty() {
        object.insert(
            "not_kind".to_string(),
            kind_list_to_json(&pattern.not_kinds),
        );
    }
    if let Some(predicate) = &pattern.name {
        object.insert("name".to_string(), string_predicate_to_json(predicate));
    }
    if let Some(predicate) = &pattern.text {
        object.insert("text".to_string(), string_predicate_to_json(predicate));
    }
    if let Some(capture) = &pattern.capture {
        object.insert("capture".to_string(), json!(capture));
    }
    if let Some(sub) = &pattern.has {
        object.insert("has".to_string(), pattern_to_json(sub));
    }
    if let Some(sub) = &pattern.not_has {
        object.insert("not_has".to_string(), pattern_to_json(sub));
    }
    for &role in Role::single_target_roles() {
        if let Some(sub) = pattern.single_role_pattern(role) {
            object.insert(role.label().to_string(), pattern_to_json(sub));
        }
    }
    for &role in Role::list_target_roles() {
        let patterns = pattern.list_role_patterns(role);
        if !patterns.is_empty() {
            object.insert(
                role.label().to_string(),
                Value::Array(patterns.iter().map(pattern_to_json).collect()),
            );
        }
    }
    if !pattern.kwargs.is_empty() {
        let mut kwargs = Map::new();
        for (keyword, sub) in &pattern.kwargs {
            kwargs.insert(keyword.clone(), pattern_to_json(sub));
        }
        object.insert(Role::Kwarg.label().to_string(), Value::Object(kwargs));
    }
    Value::Object(object)
}

fn string_predicate_to_json(predicate: &StringPredicate) -> Value {
    match predicate {
        StringPredicate::Exact(text) => json!(text),
        StringPredicate::Regex(regex) => json!({ "regex": regex.as_str() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: Value) -> Result<AstQuery, QueryError> {
        AstQuery::from_json(&json)
    }

    fn parse_ok(json: Value) -> AstQuery {
        parse(json).expect("query should parse")
    }

    fn error_of(json: Value) -> QueryError {
        parse(json).expect_err("query should be rejected")
    }

    #[test]
    fn parses_the_issue_example_query() {
        let query = parse_ok(json!({
            "where": ["src/**/*.py", "src/**/*.ts"],
            "match": {
                "kind": "call",
                "callee": { "name": "eval" },
                "args": [{ "capture": "code" }]
            },
            "inside": {
                "kind": "function",
                "capture": "enclosing_function"
            },
            "limit": 100
        }));

        assert_eq!(query.where_globs.len(), 2);
        assert_eq!(query.limit, 100);
        assert_eq!(query.root.kinds, vec![NormalizedKind::Call]);
        let callee = query.root.callee.as_ref().expect("callee pattern");
        assert!(matches!(&callee.name, Some(StringPredicate::Exact(name)) if name == "eval"));
        assert_eq!(query.root.args.len(), 1);
        assert_eq!(query.root.args[0].capture.as_deref(), Some("code"));
        let inside = query.inside.as_ref().expect("inside pattern");
        assert_eq!(inside.kinds, vec![NormalizedKind::Function]);
        assert_eq!(inside.capture.as_deref(), Some("enclosing_function"));
    }

    #[test]
    fn parses_kind_unions_and_exclusions() {
        // "All named functions, but not constructors or lambdas" — both
        // spellings from the design discussion.
        let union = parse_ok(json!({
            "match": { "kind": ["function", "method"] }
        }));
        assert_eq!(
            union.root.kinds,
            vec![NormalizedKind::Function, NormalizedKind::Method]
        );

        let subtractive = parse_ok(json!({
            "match": { "kind": "callable", "not_kind": ["constructor", "lambda"] }
        }));
        assert_eq!(subtractive.root.kinds, vec![NormalizedKind::Callable]);
        assert_eq!(
            subtractive.root.not_kinds,
            vec![NormalizedKind::Constructor, NormalizedKind::Lambda]
        );

        // Roles are valid when at least one union member supports them.
        let mixed = parse_ok(json!({
            "match": { "kind": ["call", "assignment"], "callee": { "name": "eval" } }
        }));
        assert!(mixed.root.callee.is_some());
    }

    #[test]
    fn parses_receiver_kwargs_and_regex_predicates() {
        let query = parse_ok(json!({
            "languages": ["python"],
            "match": {
                "kind": "call",
                "receiver": { "name": "subprocess" },
                "callee": { "name": "run" },
                "kwargs": { "shell": { "kind": "boolean_literal" } }
            },
            "not_inside": {
                "kind": "class",
                "name": { "regex": ".*Test$" }
            }
        }));

        assert_eq!(query.languages, vec![Language::Python]);
        assert_eq!(query.limit, DEFAULT_LIMIT);
        assert_eq!(query.root.kwargs.len(), 1);
        assert_eq!(query.root.kwargs[0].0, "shell");
        let not_inside = query.not_inside.as_ref().expect("not_inside pattern");
        assert!(matches!(
            &not_inside.name,
            Some(StringPredicate::Regex(regex)) if regex.is_match("LoginTest")
        ));
    }

    #[test]
    fn canonical_json_round_trips() {
        let original = json!({
            "where": ["src/**/*.py"],
            "languages": ["python"],
            "match": {
                "kind": "call",
                "callee": { "name": "eval" },
                "args": [{ "capture": "code" }]
            },
            "inside": { "kind": ["function", "method"], "capture": "fn" },
            "not_inside": { "kind": "class", "not_kind": "declaration" },
            "limit": 50
        });
        let canonical = parse_ok(original).to_canonical_json();
        let reparsed = parse_ok(canonical.clone());
        assert_eq!(reparsed.to_canonical_json(), canonical);
    }

    #[test]
    fn rejects_unknown_top_level_and_pattern_fields() {
        let error = error_of(json!({
            "match": { "kind": "call" },
            "insde": { "kind": "function" }
        }));
        assert_eq!(error.path, "insde");

        let error = error_of(json!({
            "match": { "kind": "call", "calee": { "name": "eval" } }
        }));
        assert_eq!(error.path, "match.calee");
    }

    #[test]
    fn rejects_unknown_kind_with_suggestions() {
        let error = error_of(json!({ "match": { "kind": "method_invocation" } }));
        assert_eq!(error.path, "match.kind");
        assert!(
            error.message.contains("call"),
            "message should list valid kinds: {}",
            error.message
        );
    }

    #[test]
    fn rejects_removed_kind_exact_as_unknown_field() {
        // `kind_exact` existed briefly and was dropped in favor of kind
        // unions + not_kind; a caller using it gets the unknown-field error
        // listing the current vocabulary.
        let error = error_of(json!({
            "match": { "kind_exact": "string_literal" }
        }));
        assert_eq!(error.path, "match.kind_exact");
        assert!(error.message.contains("unknown field"));
    }

    #[test]
    fn rejects_empty_and_malformed_kind_arrays() {
        let error = error_of(json!({ "match": { "kind": [] } }));
        assert_eq!(error.path, "match.kind");

        let error = error_of(json!({ "match": { "kind": ["call", 3] } }));
        assert_eq!(error.path, "match.kind[1]");

        let error = error_of(json!({
            "match": { "kind": "call", "not_kind": ["lambada"] }
        }));
        assert_eq!(error.path, "match.not_kind[0]");
    }

    #[test]
    fn rejects_role_invalid_for_kind() {
        let error = error_of(json!({
            "match": { "kind": "assignment", "callee": { "name": "eval" } }
        }));
        assert_eq!(error.path, "match.callee");
        assert!(error.message.contains("not valid for kind"));

        // A union where no member supports the role is provably empty.
        let error = error_of(json!({
            "match": { "kind": ["assignment", "import"], "callee": { "name": "eval" } }
        }));
        assert_eq!(error.path, "match.callee");
    }

    #[test]
    fn rejects_role_without_declared_kind() {
        let error = error_of(json!({
            "match": { "name": "run", "callee": { "name": "eval" } }
        }));
        assert_eq!(error.path, "match.callee");
        assert!(error.message.contains("requires the pattern to declare"));
    }

    #[test]
    fn rejects_unconstrained_root_pattern() {
        let error = error_of(json!({ "match": { "capture": "everything" } }));
        assert_eq!(error.path, "match");
        assert!(error.message.contains("root pattern"));
    }

    #[test]
    fn allows_capture_only_and_empty_nested_patterns() {
        let query = parse_ok(json!({
            "match": { "kind": "call", "args": [{}, { "capture": "second" }] }
        }));
        assert!(query.root.args[0].is_empty());
        assert_eq!(query.root.args[1].capture.as_deref(), Some("second"));
    }

    #[test]
    fn rejects_bad_regex_bad_glob_and_unknown_language() {
        let error = error_of(json!({
            "match": { "kind": "call", "callee": { "name": { "regex": "[" } } }
        }));
        assert_eq!(error.path, "match.callee.name.regex");

        let error = error_of(json!({
            "where": ["src/[oops"],
            "match": { "kind": "call" }
        }));
        assert_eq!(error.path, "where[0]");

        let error = error_of(json!({
            "languages": ["cobol"],
            "match": { "kind": "call" }
        }));
        assert_eq!(error.path, "languages[0]");
    }

    #[test]
    fn rejects_out_of_range_limits() {
        assert_eq!(
            error_of(json!({ "match": { "kind": "call" }, "limit": 0 })).path,
            "limit"
        );
        assert_eq!(
            error_of(json!({ "match": { "kind": "call" }, "limit": 100000 })).path,
            "limit"
        );
    }

    #[test]
    fn rejects_query_budget_overruns() {
        let too_many_globs = (0..=MAX_WHERE_GLOBS)
            .map(|index| json!(format!("src/{index}.py")))
            .collect::<Vec<_>>();
        let error = error_of(json!({
            "where": too_many_globs,
            "match": { "kind": "call" }
        }));
        assert_eq!(error.path, "where");

        let mut deeply_nested = json!({ "kind": "call" });
        for _ in 0..=MAX_PATTERN_DEPTH {
            deeply_nested = json!({ "kind": "call", "has": deeply_nested });
        }
        let error = error_of(json!({ "match": deeply_nested }));
        assert!(error.message.contains("pattern nesting"), "{error}");

        let too_many_args = (0..=MAX_ROLE_LIST_ENTRIES)
            .map(|_| json!({ "capture": "arg" }))
            .collect::<Vec<_>>();
        let error = error_of(json!({
            "match": { "kind": "call", "args": too_many_args }
        }));
        assert_eq!(error.path, "match.args");

        let error = error_of(json!({
            "match": {
                "kind": "call",
                "text": { "regex": "x".repeat(MAX_STRING_PREDICATE_LENGTH + 1) }
            }
        }));
        assert_eq!(error.path, "match.text.regex");
    }

    #[test]
    fn not_kind_alone_does_not_anchor_a_root() {
        let error = error_of(json!({ "match": { "not_kind": "lambda" } }));
        assert_eq!(error.path, "match");
        assert!(error.message.contains("root pattern"));
    }
}
