//! Source-oriented parsing, validation, and help for unsaved RQL documents.

mod json;
mod rql;
mod shared;

use json::analyze_json_with_schema_registry;
use rql::{analyze_rql, validate_rql_query};
use shared::*;

use super::super::edges::{OwnerRelation, SiteClass};
use super::ir::MAX_BINDING_NAME_LENGTH;
use super::schema;
use super::schema::{
    ALL_PATTERN_FIELDS, ALL_QUERY_FIELDS, ALL_QUERY_STEP_FIELDS, ALL_QUERY_STEP_OPS, ALL_RQL_FORMS,
    ALL_RQL_PROPERTIES, ALL_STRING_PREDICATE_FIELDS, CodeQueryExecutionMode, PatternField,
    QueryField, QueryStepField, QueryStepOp, REACHING_BINDING_STEP_OPTIONS, RqlForm, RqlFormClass,
    RqlProperty, SCOPE_SEED_RQL_LABELS, ScopeFilterField, StringPredicateField,
    binding_option_for_rql_label, candidate_option_for_rql_label,
    declaration_state_option_for_rql_label, environment_filter_labels, export_field_for_rql_label,
    generation_site_field_for_rql_label, occurrence_filter_labels, occurrence_option_for_rql_label,
    reference_kind_from_label, rql_schema_version_registry, usage_kind_from_label,
    usage_proof_from_label, usage_surface_from_label,
};
use super::schema::{ExportFilterField, GenerationSiteFilterField};
use super::sexp::{parse_query_sexp, query_to_json};
use super::{
    CodeQuery, CodeQueryResultDetail, MAX_GLOB_LENGTH, MAX_KIND_LIST_ENTRIES,
    MAX_KWARG_NAME_LENGTH, MAX_KWARGS, MAX_LANGUAGE_FILTERS, MAX_LIMIT, MAX_QUERY_BRANCHES,
    MAX_QUERY_PLAN_DEPTH, MAX_QUERY_PLAN_NODES, MAX_QUERY_STEPS, MAX_ROLE_LIST_ENTRIES,
    MAX_STRING_PREDICATE_LENGTH, MAX_WHERE_GLOBS,
};
use crate::analyzer::Language;
use crate::analyzer::structural::kinds::{
    ALL_KINDS, ALL_ROLES, NormalizedKind, Role, RoleValueShape,
};
use crate::analyzer::structural::materialization::{
    ALL_EXPORT_FORMS, ALL_GENERATION_INPUT_CLASSES, ALL_GENERATION_KINDS,
};
use crate::schema_version::SchemaVersionRegistry;
use crate::sexp::{Expr, ExprKind};
use json_spanned_value::{ErrorExt, spanned};
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use strsim::damerau_levenshtein;

pub const MAX_QUERY_SOURCE_BYTES: usize = 64 * 1024;
const MAX_SOURCE_DIAGNOSTICS: usize = 100;
const MAX_SOURCE_HELP_ITEMS: usize = 1_000;
const MAX_JSON_COMPLETION_DEPTH: usize = 6;
const MAX_JSON_COMPLETION_SOURCE_BYTES: usize = 8 * 1024;

#[derive(Default)]
struct SourcePlanBudget {
    nodes: usize,
    exhausted: bool,
}

impl SourcePlanBudget {
    fn enter(&mut self, depth: usize, range: Range<usize>, analysis: &mut Analysis) -> bool {
        if self.exhausted {
            return false;
        }
        if depth > MAX_QUERY_PLAN_DEPTH {
            analysis.error(
                range,
                "invalid-query",
                format!("query plan depth must be at most {MAX_QUERY_PLAN_DEPTH}"),
            );
            self.exhausted = true;
            return false;
        }
        if self.nodes >= MAX_QUERY_PLAN_NODES {
            analysis.error(
                range,
                "invalid-query",
                format!("query plan may contain at most {MAX_QUERY_PLAN_NODES} nodes"),
            );
            self.exhausted = true;
            return false;
        }
        self.nodes += 1;
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuerySourceDiagnostic {
    pub range: Range<usize>,
    pub code: &'static str,
    pub message: String,
    pub fix: Option<QuerySourceFix>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuerySourceFix {
    pub title: String,
    pub edit: QuerySourceEdit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuerySourceEdit {
    Replace { new_text: String },
    Surround { prefix: String, suffix: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuerySourceHelp {
    pub range: Range<usize>,
    pub signature: String,
    pub description: String,
}

impl CodeQuery {
    /// Parse RQL or canonical JSON. JSON is selected only when the first
    /// non-whitespace character is an opening brace.
    pub fn from_source(source: &str) -> Result<Self, String> {
        if source.len() > MAX_QUERY_SOURCE_BYTES {
            return Err(format!(
                "query source is too large: {} bytes exceeds {}",
                source.len(),
                MAX_QUERY_SOURCE_BYTES
            ));
        }
        if is_json_source(source) {
            let parsed: spanned::Value =
                json_spanned_value::from_str(source).map_err(|error| error.to_string())?;
            Self::from_json(&spanned_to_json(&parsed)).map_err(|error| error.to_string())
        } else {
            Self::from_sexp(source)
        }
    }
}

pub fn validate_query_source(source: &str) -> Vec<QuerySourceDiagnostic> {
    if source.len() > MAX_QUERY_SOURCE_BYTES {
        return vec![QuerySourceDiagnostic {
            range: 0..source.len(),
            code: "query-too-large",
            message: format!(
                "query source is too large: {} bytes exceeds {}",
                source.len(),
                MAX_QUERY_SOURCE_BYTES
            ),
            fix: None,
        }];
    }
    analyze_source(source).diagnostics
}

pub fn query_source_help_at(source: &str, byte_offset: usize) -> Option<QuerySourceHelp> {
    if source.len() > MAX_QUERY_SOURCE_BYTES {
        return None;
    }
    analyze_source(source)
        .help
        .into_iter()
        .find(|help| help.range.start <= byte_offset && byte_offset < help.range.end)
}

fn is_json_source(source: &str) -> bool {
    source.trim_start().starts_with('{')
}

type SuggestionCandidate = (String, String);

fn best_suggestion(
    observed: &str,
    candidates: impl IntoIterator<Item = SuggestionCandidate>,
) -> Option<String> {
    let mut distances = HashMap::<String, usize>::new();
    for (canonical, accepted) in candidates {
        if accepted == observed {
            return None;
        }
        let distance = damerau_levenshtein(observed, &accepted);
        let max_length = observed.chars().count().max(accepted.chars().count());
        let threshold = if max_length <= 4 { 1 } else { 2 };
        if distance <= threshold {
            distances
                .entry(canonical)
                .and_modify(|best| *best = (*best).min(distance))
                .or_insert(distance);
        }
    }

    let best_distance = distances.values().copied().min()?;
    let mut best = distances
        .into_iter()
        .filter_map(|(candidate, distance)| (distance == best_distance).then_some(candidate));
    let suggestion = best.next()?;
    best.next().is_none().then_some(suggestion)
}

fn add_spelling_error(
    analysis: &mut Analysis,
    range: Range<usize>,
    code: &'static str,
    message: impl Into<String>,
    observed: &str,
    candidates: impl IntoIterator<Item = SuggestionCandidate>,
    replacement: impl FnOnce(&str) -> String,
) {
    let message = message.into();
    if let Some(suggestion) = best_suggestion(observed, candidates) {
        analysis.error_with_fix(
            range,
            code,
            format!("{message}. Did you mean `{suggestion}`?"),
            QuerySourceFix {
                title: format!("Replace with `{suggestion}`"),
                edit: QuerySourceEdit::Replace {
                    new_text: replacement(&suggestion),
                },
            },
        );
    } else {
        analysis.error(range, code, message);
    }
}

fn rql_form_candidates(class: Option<RqlFormClass>) -> Vec<SuggestionCandidate> {
    ALL_RQL_FORMS
        .iter()
        .copied()
        .filter(|form| class.is_none_or(|class| form.class() == class))
        .flat_map(|form| {
            form.labels()
                .iter()
                .map(move |label| (form.label().to_string(), (*label).to_string()))
        })
        .collect()
}

fn rql_pattern_head_candidates() -> Vec<SuggestionCandidate> {
    let mut candidates = rql_form_candidates(Some(RqlFormClass::Predicate));
    candidates.extend(
        ALL_KINDS
            .iter()
            .map(|kind| (kind.label().to_string(), kind.label().to_string())),
    );
    candidates
}

fn rql_query_head_candidates() -> Vec<SuggestionCandidate> {
    let mut candidates = rql_form_candidates(None);
    candidates.extend(
        ALL_KINDS
            .iter()
            .map(|kind| (kind.label().to_string(), kind.label().to_string())),
    );
    candidates
}

fn rql_property_candidates() -> Vec<SuggestionCandidate> {
    let mut candidates = ALL_RQL_PROPERTIES
        .iter()
        .copied()
        .flat_map(|property| {
            property
                .labels()
                .iter()
                .map(move |label| (property.label().to_string(), (*label).to_string()))
        })
        .collect::<Vec<_>>();
    candidates.extend(
        ALL_ROLES
            .iter()
            .map(|role| (role.label().to_string(), role.label().to_string())),
    );
    candidates
}

fn json_field_candidates<T>(
    fields: &[T],
    label: impl Fn(T) -> &'static str,
) -> Vec<SuggestionCandidate>
where
    T: Copy,
{
    fields
        .iter()
        .copied()
        .map(|field| {
            let label = label(field);
            (label.to_string(), label.to_string())
        })
        .collect()
}

fn pattern_field_candidates() -> Vec<SuggestionCandidate> {
    let mut candidates = json_field_candidates(ALL_PATTERN_FIELDS, PatternField::label);
    candidates.extend(
        ALL_ROLES
            .iter()
            .map(|role| (role.label().to_string(), role.label().to_string())),
    );
    candidates
}

fn language_candidates() -> Vec<SuggestionCandidate> {
    let mut candidates = Vec::new();
    for language in Language::ANALYZABLE {
        let canonical = language.config_label().to_string();
        candidates.push((canonical.clone(), canonical));
        candidates.extend(language.extensions().iter().map(|extension| {
            (
                language.config_label().to_string(),
                (*extension).to_string(),
            )
        }));
        candidates.extend(
            language
                .extensions()
                .iter()
                .map(|extension| (language.config_label().to_string(), format!(".{extension}"))),
        );
        candidates.extend(
            language
                .config_label_aliases()
                .iter()
                .map(|alias| (language.config_label().to_string(), (*alias).to_string())),
        );
    }
    candidates
}

fn kind_candidates() -> Vec<SuggestionCandidate> {
    ALL_KINDS
        .iter()
        .map(|kind| (kind.label().to_string(), kind.label().to_string()))
        .collect()
}

fn result_detail_candidates() -> Vec<SuggestionCandidate> {
    CodeQueryResultDetail::ALL
        .iter()
        .map(|detail| (detail.label().to_string(), detail.label().to_string()))
        .collect()
}

fn execution_mode_candidates() -> Vec<SuggestionCandidate> {
    super::schema::ALL_CODE_QUERY_EXECUTION_MODES
        .iter()
        .map(|mode| (mode.label().to_string(), mode.label().to_string()))
        .collect()
}

fn query_step_candidates() -> Vec<SuggestionCandidate> {
    ALL_QUERY_STEP_OPS
        .iter()
        .map(|op| (op.label().to_string(), op.label().to_string()))
        .collect()
}

fn replacement_for_rql_label(value: &Expr, label: &str) -> String {
    if matches!(value.kind, ExprKind::String(_)) {
        serde_json::to_string(label).expect("suggestions are valid JSON strings")
    } else {
        label.to_string()
    }
}

#[derive(Default)]
struct Analysis {
    diagnostics: Vec<QuerySourceDiagnostic>,
    help: Vec<QuerySourceHelp>,
    paths: HashMap<String, Range<usize>>,
    incomplete: bool,
}

impl Analysis {
    fn error(&mut self, range: Range<usize>, code: &'static str, message: impl Into<String>) {
        if self.diagnostics.len() >= MAX_SOURCE_DIAGNOSTICS {
            return;
        }
        self.diagnostics.push(QuerySourceDiagnostic {
            range,
            code,
            message: message.into(),
            fix: None,
        });
    }

    fn error_with_fix(
        &mut self,
        range: Range<usize>,
        code: &'static str,
        message: impl Into<String>,
        fix: QuerySourceFix,
    ) {
        if self.diagnostics.len() >= MAX_SOURCE_DIAGNOSTICS {
            return;
        }
        self.diagnostics.push(QuerySourceDiagnostic {
            range,
            code,
            message: message.into(),
            fix: Some(fix),
        });
    }

    fn add_help(
        &mut self,
        range: Range<usize>,
        signature: impl Into<String>,
        description: impl Into<String>,
    ) {
        if self.help.len() >= MAX_SOURCE_HELP_ITEMS {
            return;
        }
        self.help.push(QuerySourceHelp {
            range,
            signature: signature.into(),
            description: description.into(),
        });
    }

    fn path(&mut self, path: impl Into<String>, range: Range<usize>) {
        self.paths.insert(path.into(), range);
    }

    fn semantic_error(&mut self, error: super::QueryError, fallback: Range<usize>) {
        let range = self.range_for_path(&error.path, fallback);
        self.error(range, "invalid-query", error.message);
    }

    fn range_for_path(&self, path: &str, fallback: Range<usize>) -> Range<usize> {
        let mut path = path;
        loop {
            if let Some(range) = self.paths.get(path) {
                return range.clone();
            }
            if let Some(index) = path.rfind(['.', '[']) {
                path = &path[..index];
            } else {
                return fallback;
            }
        }
    }

    fn path_for_range(&self, target: &Range<usize>) -> Option<String> {
        self.paths
            .iter()
            .filter(|(_, range)| range.start <= target.start && target.end <= range.end)
            .min_by(|(left_path, left_range), (right_path, right_range)| {
                let left_width = left_range.end.saturating_sub(left_range.start);
                let right_width = right_range.end.saturating_sub(right_range.start);
                left_width
                    .cmp(&right_width)
                    .then_with(|| right_path.len().cmp(&left_path.len()))
                    .then_with(|| left_path.cmp(right_path))
            })
            .map(|(path, _)| path.clone())
    }
}

pub(super) fn query_expr_range_for_path(expr: &Expr, path: &str) -> Range<usize> {
    let mut analysis = Analysis::default();
    let mut plan_budget = SourcePlanBudget::default();
    validate_rql_query(expr, "", &mut analysis, 0, &mut plan_budget);
    analysis.range_for_path(path, expr.range.clone())
}

pub(super) fn query_expr_path_for_range(expr: &Expr, range: &Range<usize>) -> Option<String> {
    let mut analysis = Analysis::default();
    let mut plan_budget = SourcePlanBudget::default();
    validate_rql_query(expr, "", &mut analysis, 0, &mut plan_budget);
    analysis.path_for_range(range)
}

fn analyze_source(source: &str) -> Analysis {
    if is_json_source(source) {
        analyze_json_with_schema_registry(source, rql_schema_version_registry())
    } else {
        analyze_rql(source)
    }
}

fn spanned_to_json(value: &spanned::Value) -> Value {
    match value.get_ref() {
        json_spanned_value::Value::Null => Value::Null,
        json_spanned_value::Value::Bool(value) => Value::Bool(*value),
        json_spanned_value::Value::Number(value) => Value::Number(value.clone()),
        json_spanned_value::Value::String(value) => Value::String(value.clone()),
        json_spanned_value::Value::Array(values) => {
            Value::Array(values.iter().map(spanned_to_json).collect())
        }
        json_spanned_value::Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.get_ref().clone(), spanned_to_json(value)))
                .collect::<Map<_, _>>(),
        ),
    }
}

#[cfg(test)]
mod tests;
