//! Source-oriented parsing, validation, and help for unsaved RQL documents.

use super::schema::{
    ALL_PATTERN_FIELDS, ALL_QUERY_FIELDS, ALL_QUERY_STEP_FIELDS, ALL_QUERY_STEP_OPS, ALL_RQL_FORMS,
    ALL_RQL_PROPERTIES, ALL_STRING_PREDICATE_FIELDS, PatternField, QueryField, QueryStepField,
    RqlForm, RqlFormClass, RqlProperty, StringPredicateField, reference_kind_from_label,
    rql_schema_version_registry, usage_proof_from_label, usage_surface_from_label,
};
use super::sexp::{parse_query_sexp, query_to_json};
use super::{
    CodeQuery, CodeQueryResultDetail, MAX_GLOB_LENGTH, MAX_KIND_LIST_ENTRIES,
    MAX_KWARG_NAME_LENGTH, MAX_KWARGS, MAX_LANGUAGE_FILTERS, MAX_LIMIT, MAX_QUERY_BRANCHES,
    MAX_QUERY_PLAN_DEPTH, MAX_QUERY_PLAN_NODES, MAX_QUERY_STEPS, MAX_ROLE_LIST_ENTRIES,
    MAX_STRING_PREDICATE_LENGTH, MAX_WHERE_GLOBS, QueryStep,
};
use crate::analyzer::Language;
use crate::analyzer::structural::kinds::{
    ALL_KINDS, ALL_ROLES, NormalizedKind, Role, RoleValueShape,
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

fn analyze_rql(source: &str) -> Analysis {
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

fn validate_rql_query(
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
        analysis.add_help(head_range, form.signature(), form.description());
        validate_wrapper(form, args, path, analysis, depth, plan_budget);
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
    path: &str,
    analysis: &mut Analysis,
    depth: usize,
    plan_budget: &mut SourcePlanBudget,
) {
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
        RqlForm::Inside | RqlForm::NotInside => {
            if args.len() != 2 {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    "containment wrapper expects a pattern and query",
                );
            } else {
                let field = if form == RqlForm::Inside {
                    "inside"
                } else {
                    "not_inside"
                };
                let field_path = rql_query_child_path(path, field);
                validate_rql_pattern(&args[0], &field_path, analysis);
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
        | super::schema::ValueShape::ReferenceKindList
        | super::schema::ValueShape::SchemaVersion
        | super::schema::ValueShape::UsageProof
        | super::schema::ValueShape::UsageSurface
        | super::schema::ValueShape::TrueBoolean => {
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

fn validate_regex(source: &str, range: Range<usize>, path: &str, analysis: &mut Analysis) {
    if source.len() > MAX_STRING_PREDICATE_LENGTH {
        analysis.error(
            range,
            "invalid-query",
            format!("regex must be at most {MAX_STRING_PREDICATE_LENGTH} bytes"),
        );
    } else if let Err(error) = Regex::new(source) {
        analysis.error(range, "invalid-query", format!("invalid regex: {error}"));
    } else {
        analysis.path(path, range);
    }
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

fn analyze_json_with_schema_registry(
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
            QueryField::Match | QueryField::Inside | QueryField::NotInside => {
                validate_json_pattern(child, &child_path, analysis);
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
            let Some(step) = QueryStep::from_label(label) else {
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
            analysis.add_help(child.range(), step.label(), query_step_description(&step));
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
            .is_some_and(|label| QueryStep::from_label(label).is_some())
}

fn query_step_description(step: &QueryStep) -> &'static str {
    step.op().description()
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

fn require_json_string(value: &spanned::Value, analysis: &mut Analysis) {
    if !value.is_string() {
        analysis.error(value.range(), "wrong-value-shape", "expected a string");
    }
}

fn validate_parameter_name(name: &str, range: Range<usize>, analysis: &mut Analysis) {
    let shape = QueryStepField::ParameterName.value_shape();
    if !shape.accepts_string(name) {
        let (minimum, maximum) = shape
            .string_length_bounds()
            .expect("parameter-name shape has string bounds");
        analysis.error(
            range,
            "invalid-query",
            format!("parameter name must be between {minimum} and {maximum} bytes"),
        );
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

fn validate_capture_name(
    name: &str,
    range: Range<usize>,
    code: &'static str,
    label: &str,
    analysis: &mut Analysis,
) {
    let shape = QueryStepField::Capture.value_shape();
    if !shape.accepts_string(name) {
        let (minimum, maximum) = shape
            .string_length_bounds()
            .expect("capture-name shape has string bounds");
        analysis.error(
            range,
            code,
            format!("{label} must be between {minimum} and {maximum} bytes"),
        );
    }
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
mod tests {
    use super::*;

    #[test]
    fn quiet_for_empty_and_incomplete_sources() {
        for source in [
            "",
            "  ; comment",
            "(call",
            "(call :callee",
            "\"unfinished",
            "{\"match\":",
        ] {
            assert!(validate_query_source(source).is_empty(), "{source:?}");
        }
    }

    #[test]
    fn reports_multiple_rql_errors_at_exact_ranges() {
        let source = "(call :wat 1 :name 2 :also-nope 3)";
        let diagnostics = validate_query_source(source);
        assert_eq!(diagnostics.len(), 3);
        assert_eq!(&source[diagnostics[0].range.clone()], ":wat");
        assert_eq!(&source[diagnostics[1].range.clone()], "2");
        assert_eq!(&source[diagnostics[2].range.clone()], ":also-nope");
    }

    #[test]
    fn reports_multiple_json_errors_at_key_and_value_ranges() {
        let source = r#"{"oops": 1, "match": {"kind": "banana", "capture": 4}}"#;
        let mut diagnostics = validate_query_source(source);
        diagnostics.sort_by_key(|diagnostic| diagnostic.range.start);
        assert_eq!(diagnostics.len(), 3);
        assert_eq!(&source[diagnostics[0].range.clone()], "\"oops\"");
        assert_eq!(&source[diagnostics[1].range.clone()], "\"banana\"");
        assert_eq!(&source[diagnostics[2].range.clone()], "4");
    }

    #[test]
    fn reports_independent_semantic_errors_with_unknown_properties() {
        for source in [
            r#"(call :unknown 1 :name/regex "[")"#,
            r#"{"unknown":1,"match":{"kind":"call","name":{"regex":"["}}}"#,
        ] {
            let diagnostics = validate_query_source(source);
            assert_eq!(diagnostics.len(), 2, "{source}: {diagnostics:#?}");
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == "unknown-property")
            );
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.message.contains("invalid regex"))
            );
        }
    }

    #[test]
    fn reports_role_compatibility_without_waiting_for_typed_lowering() {
        for source in [
            r#"(assignment :unknown 1 :callee (name "run"))"#,
            r#"{"unknown":1,"match":{"kind":"assignment","callee":{"name":"run"}}}"#,
        ] {
            let diagnostics = validate_query_source(source);
            assert_eq!(diagnostics.len(), 2, "{source}: {diagnostics:#?}");
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.message.contains("not valid for kind"))
            );
        }
    }

    #[test]
    fn text_predicate_requires_regex_object_in_json() {
        let source = r#"{"match":{"text":"exact"}}"#;
        let diagnostic = validate_query_source(source).pop().expect("diagnostic");
        assert_eq!(diagnostic.code, "wrong-value-shape");
        assert_eq!(&source[diagnostic.range], "\"exact\"");
    }

    #[test]
    fn malformed_json_range_is_byte_correct_after_utf8() {
        let source = r#"{"λ": 1, ]"#;
        let diagnostic = validate_query_source(source).pop().expect("diagnostic");
        assert_eq!(diagnostic.code, "invalid-json");
        assert_eq!(&source[diagnostic.range], "]");
    }

    #[test]
    fn json_schema_validation_uses_the_compatibility_registry() {
        use crate::schema_version::{SchemaVersionDescriptor, SchemaVersionRegistry};

        let registry = SchemaVersionRegistry::new(&[
            SchemaVersionDescriptor::new(2, None, true),
            SchemaVersionDescriptor::new(3, Some(2), true),
        ])
        .unwrap();
        for source in [
            r#"{"schema_version":2,"match":{"kind":"call"}}"#,
            r#"{"match":{"kind":"call"}}"#,
        ] {
            let analysis = analyze_json_with_schema_registry(source, &registry);
            assert!(
                analysis.diagnostics.is_empty(),
                "{:?}",
                analysis.diagnostics
            );
        }

        let source = r#"{"schema_version":1,"match":{"kind":"call"}}"#;
        let analysis = analyze_json_with_schema_registry(source, &registry);
        assert_eq!(analysis.diagnostics.len(), 1);
        assert_eq!(analysis.diagnostics[0].code, "unsupported-schema-version");
        assert_eq!(&source[analysis.diagnostics[0].range.clone()], "1");
    }

    #[test]
    fn incomplete_rql_keeps_help_for_completed_tokens() {
        let source = "(call :callee";
        let offset = source.find(":callee").unwrap() + 1;
        let help = query_source_help_at(source, offset).expect("role help");
        assert_eq!(&source[help.range], ":callee");
        assert!(validate_query_source(source).is_empty());
    }

    #[test]
    fn incomplete_json_keeps_help_for_completed_keys() {
        for (source, token) in [
            (r#"{"match":"#, "match"),
            (r#"{"match":{"kind":"#, "kind"),
            (r#"{"match":{"kind":"call","callee":"#, "callee"),
        ] {
            let offset = source.find(token).unwrap();
            let help = query_source_help_at(source, offset)
                .unwrap_or_else(|| panic!("no help for {token} in {source}"));
            assert_eq!(&source[help.range], format!("\"{token}\""));
            assert!(validate_query_source(source).is_empty());
        }
    }

    #[test]
    fn source_and_diagnostic_budgets_are_bounded() {
        let oversized = " ".repeat(MAX_QUERY_SOURCE_BYTES + 1);
        let diagnostics = validate_query_source(&oversized);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "query-too-large");
        assert!(query_source_help_at(&oversized, 0).is_none());

        let mut many_errors = String::from("(call");
        for index in 0..=MAX_SOURCE_DIAGNOSTICS {
            many_errors.push_str(&format!(" :unknown-{index} 1"));
        }
        many_errors.push(')');
        assert_eq!(
            validate_query_source(&many_errors).len(),
            MAX_SOURCE_DIAGNOSTICS
        );
    }

    #[test]
    fn plan_budgets_stop_json_and_rql_source_validation_early() {
        let mut deep_json = serde_json::json!({ "match": 3 });
        let mut deep_rql = "(banana)".to_string();
        for _ in 0..=MAX_QUERY_PLAN_DEPTH {
            deep_json = serde_json::json!({
                "union": [deep_json, { "match": { "kind": "call" } }]
            });
            deep_rql = format!("(union {deep_rql} (call))");
        }
        for source in [deep_json.to_string(), deep_rql] {
            let diagnostics = validate_query_source(&source);
            assert_eq!(diagnostics.len(), 1, "{source}: {diagnostics:#?}");
            assert!(diagnostics[0].message.contains("plan depth"));
        }

        let json_groups = (0..4)
            .map(|_| {
                serde_json::json!({
                    "union": (0..16)
                        .map(|_| serde_json::json!({ "match": { "kind": "call" } }))
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let wide_json = serde_json::json!({ "union": json_groups }).to_string();
        let rql_group = format!("(union {})", vec!["(call)"; 16].join(" "));
        let wide_rql = format!("(union {})", vec![rql_group; 4].join(" "));
        for source in [wide_json, wide_rql] {
            let diagnostics = validate_query_source(&source);
            assert_eq!(diagnostics.len(), 1, "{source}: {diagnostics:#?}");
            assert!(diagnostics[0].message.contains("at most 64 nodes"));
        }
    }

    #[test]
    fn canonical_json_and_rql_execute_equivalently() {
        let rql = CodeQuery::from_source("(language rust (call :callee (name \"run\")))")
            .expect("RQL query");
        let json = CodeQuery::from_source(
            r#"{"languages":["rust"],"match":{"kind":"call","callee":{"name":"run"}}}"#,
        )
        .expect("JSON query");
        assert_eq!(rql.to_canonical_json(), json.to_canonical_json());
    }

    #[test]
    fn accepted_rql_shorthands_have_no_live_diagnostics() {
        for source in [
            r#"(call :callee "run")"#,
            r#"(import :module "os")"#,
            r#"(result-detail "full" (call))"#,
            r#"(imports-of (file-of (class)))"#,
        ] {
            CodeQuery::from_source(source)
                .unwrap_or_else(|error| panic!("{source:?} should execute: {error}"));
            assert!(
                validate_query_source(source).is_empty(),
                "{source:?} should lint cleanly"
            );
        }
    }

    #[test]
    fn help_covers_forms_properties_roles_kinds_and_values() {
        let source = "(result-detail full (call :callee (name \"run\")))";
        for (token, expected_range) in [
            ("result-detail", "result-detail"),
            ("full", "full"),
            ("call", "call"),
            ("callee", ":callee"),
            ("name", "name"),
        ] {
            let offset = source.find(token).unwrap();
            let help = query_source_help_at(source, offset)
                .unwrap_or_else(|| panic!("no help for {token}"));
            assert!(!help.description.is_empty());
            assert_eq!(&source[help.range], expected_range);
        }
        assert!(query_source_help_at(source, source.find("run").unwrap()).is_none());
    }

    #[test]
    fn typed_pipeline_help_and_json_diagnostics_use_shared_schema() {
        let rql = "(file-of (enclosing-decl (call)))";
        for token in ["file-of", "enclosing-decl"] {
            let offset = rql.find(token).unwrap();
            let help =
                query_source_help_at(rql, offset).unwrap_or_else(|| panic!("no help for {token}"));
            assert_eq!(&rql[help.range], token);
            assert!(!help.description.is_empty());
        }
        let file_of_help = query_source_help_at(rql, rql.find("file-of").unwrap()).unwrap();
        assert!(file_of_help.description.contains("reference site"));
        assert!(file_of_help.description.contains("receiver analysis"));
        assert!(validate_query_source(rql).is_empty());

        let json = r#"{"schema_version":2,"match":{"kind":"call"},"steps":[{"op":"file_of"}]}"#;
        for token in ["steps", "op", "file_of"] {
            let offset = json.find(token).unwrap();
            let help =
                query_source_help_at(json, offset).unwrap_or_else(|| panic!("no help for {token}"));
            assert!(!help.description.is_empty());
        }
        let file_of_help = query_source_help_at(json, json.find("file_of").unwrap()).unwrap();
        assert!(file_of_help.description.contains("reference sites"));
        assert!(file_of_help.description.contains("receiver analyses"));
        assert!(
            crate::analyzer::structural::query::schema::QueryStepOp::FileOf
                .signature()
                .contains("reference_site")
        );
        assert!(validate_query_source(json).is_empty());

        let invalid =
            r#"{"schema_version":2,"match":{"kind":"call"},"steps":[{"op":"imports_of"}]}"#;
        let diagnostic = validate_query_source(invalid).pop().expect("diagnostic");
        assert_eq!(diagnostic.code, "invalid-query");
        assert_eq!(&invalid[diagnostic.range], r#"{"op":"imports_of"}"#);
        assert!(diagnostic.message.contains("requires file"));
    }

    #[test]
    fn hierarchy_step_help_and_option_diagnostics_are_range_precise() {
        let rql = "(subtypes :depth 2 (enclosing-decl (class)))";
        for token in ["subtypes", ":depth"] {
            let offset = rql.find(token).unwrap();
            let help = query_source_help_at(rql, offset)
                .unwrap_or_else(|| panic!("no hierarchy help for {token}"));
            assert!(!help.description.is_empty());
        }
        assert!(validate_query_source(rql).is_empty());

        let invalid = r#"{"match":{"kind":"class"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes","depth":0}]}"#;
        let diagnostics = validate_query_source(invalid);
        assert!(diagnostics.iter().any(|diagnostic| {
            &invalid[diagnostic.range.clone()] == "0"
                && diagnostic.message.contains("positive integer")
        }));

        let conflicting = r#"{"match":{"kind":"class"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes","depth":2,"transitive":true}]}"#;
        let diagnostics = validate_query_source(conflicting);
        assert!(diagnostics.iter().any(|diagnostic| {
            &conflicting[diagnostic.range.clone()] == "true"
                && diagnostic.message.contains("mutually exclusive")
        }));
    }

    #[test]
    fn set_composition_help_and_domain_diagnostics_are_range_precise() {
        let rql = "(file-of (union (enclosing-decl (class :name \"A\")) (enclosing-decl (class :name \"B\"))))";
        for token in ["union", "file-of"] {
            let offset = rql.find(token).unwrap();
            let help = query_source_help_at(rql, offset)
                .unwrap_or_else(|| panic!("no set-composition help for {token}"));
            assert_eq!(&rql[help.range], token);
            assert!(!help.description.is_empty());
        }
        assert!(validate_query_source(rql).is_empty());

        let json = r#"{"union":[{"match":{"kind":"class"},"steps":[{"op":"enclosing_decl"}]},{"match":{"kind":"class"},"steps":[{"op":"file_of"}]}]}"#;
        let diagnostic = validate_query_source(json)
            .into_iter()
            .find(|diagnostic| diagnostic.message.contains("first branch produces"))
            .expect("typed branch diagnostic");
        assert_eq!(
            &json[diagnostic.range],
            r#"{"match":{"kind":"class"},"steps":[{"op":"file_of"}]}"#
        );

        let too_short = "(except (class))";
        let diagnostic = validate_query_source(too_short)
            .into_iter()
            .find(|diagnostic| diagnostic.message.contains("at least two"))
            .expect("branch-count diagnostic");
        assert_eq!(&too_short[diagnostic.range], "(class)");
    }

    #[test]
    fn parameter_name_constraints_are_shared_by_json_and_rql_validation() {
        let oversized = "x".repeat(MAX_KWARG_NAME_LENGTH + 1);
        let rql = format!(
            "(call-input :parameter-name \"{oversized}\" (call-sites-to (enclosing-decl (method))))"
        );
        let json = format!(
            r#"{{"match":{{"kind":"method"}},"steps":[{{"op":"enclosing_decl"}},{{"op":"call_sites_to"}},{{"op":"call_input","parameter_name":"{oversized}"}}]}}"#
        );

        for (source, expected) in [
            (rql.as_str(), format!("\"{oversized}\"")),
            (json.as_str(), format!("\"{oversized}\"")),
        ] {
            let diagnostics = validate_query_source(source);
            assert!(diagnostics.iter().any(|diagnostic| {
                source[diagnostic.range.clone()] == expected
                    && diagnostic.message.contains("parameter name")
            }));
        }

        for source in [
            r#"(call-input :parameter-name "" (call-sites-to (enclosing-decl (method))))"#,
            r#"{"match":{"kind":"method"},"steps":[{"op":"enclosing_decl"},{"op":"call_sites_to"},{"op":"call_input","parameter_name":""}]}"#,
        ] {
            assert!(validate_query_source(source).iter().any(|diagnostic| {
                &source[diagnostic.range.clone()] == "\"\""
                    && diagnostic.message.contains("parameter name")
            }));
        }
    }

    #[test]
    fn receiver_step_help_and_capture_diagnostics_are_range_precise() {
        let rql = "(points-to :capture service (call :receiver (capture \"service\")))";
        for token in ["points-to", ":capture"] {
            let offset = rql.find(token).unwrap();
            let help = query_source_help_at(rql, offset)
                .unwrap_or_else(|| panic!("no receiver traversal help for {token}"));
            assert_eq!(&rql[help.range], token);
            assert!(!help.description.is_empty());
        }
        assert!(validate_query_source(rql).is_empty());

        let json = r#"{"match":{"kind":"call","receiver":{"capture":"service"}},"steps":[{"op":"points_to","capture":"service"}]}"#;
        for token in ["points_to", "capture"] {
            let offset = json.rfind(token).unwrap();
            let help = query_source_help_at(json, offset)
                .unwrap_or_else(|| panic!("no JSON receiver traversal help for {token}"));
            assert!(!help.description.is_empty());
        }
        assert!(validate_query_source(json).is_empty());

        let missing =
            r#"{"match":{"kind":"call"},"steps":[{"op":"points_to","capture":"service"}]}"#;
        let diagnostic = validate_query_source(missing).pop().expect("diagnostic");
        assert_eq!(diagnostic.code, "invalid-query");
        assert_eq!(&missing[diagnostic.range], r#""service""#);
        assert!(
            diagnostic
                .message
                .contains("not declared by a positive pattern")
        );

        let wrong_domain = r#"{"match":{"kind":"class","capture":"service"},"steps":[{"op":"enclosing_decl"},{"op":"references_of"},{"op":"points_to","capture":"service"}]}"#;
        let diagnostic = validate_query_source(wrong_domain)
            .into_iter()
            .find(|diagnostic| diagnostic.message.contains("capture is allowed only"))
            .expect("domain diagnostic");
        assert_eq!(&wrong_domain[diagnostic.range], r#""service""#);
    }

    #[test]
    fn reference_step_help_and_option_diagnostics_are_range_precise() {
        let rql = "(references-of :surface external-usages :reference-kinds [field-write] :proof proven (enclosing-decl (class)))";
        for token in ["references-of", ":surface", ":reference-kinds", ":proof"] {
            let offset = rql.find(token).unwrap();
            let help = query_source_help_at(rql, offset)
                .unwrap_or_else(|| panic!("no reference traversal help for {token}"));
            assert_eq!(&rql[help.range], token);
            assert!(!help.description.is_empty());
        }
        assert!(validate_query_source(rql).is_empty());

        for (source, token) in [
            (
                r#"{"match":{"kind":"class"},"steps":[{"op":"enclosing_decl"},{"op":"references_of","reference_kinds":["field_guess"]}]}"#,
                "\"field_guess\"",
            ),
            (
                r#"{"match":{"kind":"class"},"steps":[{"op":"enclosing_decl"},{"op":"used_by","proof":"maybe"}]}"#,
                "\"maybe\"",
            ),
            (
                r#"{"match":{"kind":"class"},"steps":[{"op":"enclosing_decl"},{"op":"uses","surface":"all"}]}"#,
                "\"all\"",
            ),
        ] {
            let diagnostics = validate_query_source(source);
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| &source[diagnostic.range.clone()] == token),
                "{source}: {diagnostics:#?}"
            );
        }
    }

    #[test]
    fn byte_ranges_preserve_utf8_boundaries() {
        let source = "(call :unknown-λ 1)";
        let diagnostic = validate_query_source(source).pop().expect("diagnostic");
        assert_eq!(&source[diagnostic.range], ":unknown-λ");
    }

    #[test]
    fn spelling_fixes_use_unique_canonical_schema_candidates() {
        let cases = [
            (
                "(resut-detail full (call))",
                "resut-detail",
                "result-detail",
            ),
            ("(call :captur \"item\")", ":captur", ":capture"),
            ("(call :calle (call))", ":calle", ":callee"),
            ("(cal)", "cal", "call"),
            ("(language ruts (call))", "ruts", "rust"),
            ("(language .rss (call))", ".rss", "rust"),
            ("(result-detail ful (call))", "ful", "full"),
            (r#"{"matc":{"kind":"call"}}"#, "\"matc\"", "\"match\""),
            (r#"{"match":{"kind":"cal"}}"#, "\"cal\"", "\"call\""),
            (
                r#"{"match":{"kind":"call","calle":{"kind":"call"}}}"#,
                "\"calle\"",
                "\"callee\"",
            ),
            (
                r#"{"match":{"name":{"regx":"item"}}}"#,
                "\"regx\"",
                "\"regex\"",
            ),
            (
                r#"{"languages":["ruts"],"match":{"kind":"call"}}"#,
                "\"ruts\"",
                "\"rust\"",
            ),
            (
                r#"{"result_detail":"ful","match":{"kind":"call"}}"#,
                "\"ful\"",
                "\"full\"",
            ),
            (
                r#"{"steps":[{"op":"fileof"}],"match":{"kind":"call"}}"#,
                "\"fileof\"",
                "\"file_of\"",
            ),
        ];

        for (source, token, replacement) in cases {
            let diagnostic = validate_query_source(source)
                .into_iter()
                .find(|diagnostic| &source[diagnostic.range.clone()] == token)
                .unwrap_or_else(|| panic!("missing diagnostic for {token} in {source}"));
            assert!(diagnostic.message.contains("Did you mean"));
            assert_eq!(&source[diagnostic.range], token);
            assert_eq!(
                diagnostic.fix,
                Some(QuerySourceFix {
                    title: format!(
                        "Replace with `{}`",
                        replacement.trim_matches('"').trim_start_matches(':')
                    ),
                    edit: QuerySourceEdit::Replace {
                        new_text: replacement.to_string(),
                    },
                })
            );
        }

        let ambiguous = "(language .rts (call))";
        let diagnostic = validate_query_source(ambiguous)
            .into_iter()
            .find(|diagnostic| &ambiguous[diagnostic.range.clone()] == ".rts")
            .expect("language diagnostic");
        assert!(!diagnostic.message.contains("Did you mean"));
        assert_eq!(diagnostic.fix, None);
    }

    #[test]
    fn suggestion_selector_deduplicates_aliases_and_suppresses_ties_and_distant_values() {
        assert_eq!(
            best_suggestion(
                "not_haz",
                [
                    ("not-has".to_string(), "not-has".to_string()),
                    ("not-has".to_string(), "not_has".to_string()),
                ],
            ),
            Some("not-has".to_string())
        );
        assert_eq!(
            best_suggestion(
                "cot",
                [
                    ("cat".to_string(), "cat".to_string()),
                    ("cut".to_string(), "cut".to_string()),
                ],
            ),
            None
        );
        assert_eq!(
            best_suggestion("unrelated", [("call".to_string(), "call".to_string())]),
            None
        );
        assert_eq!(
            best_suggestion(
                "result_detail",
                [("result-detail".to_string(), "result_detail".to_string())],
            ),
            None
        );
    }

    #[test]
    fn safe_shape_fixes_wrap_only_recognizable_single_values() {
        let supported = [
            (
                r#"{"where":"src/**/*.rs","match":{"kind":"call"}}"#,
                "\"src/**/*.rs\"",
            ),
            (
                r#"{"languages":"rust","match":{"kind":"call"}}"#,
                "\"rust\"",
            ),
            (
                r#"{"steps":{"op":"file_of"},"match":{"kind":"call"}}"#,
                r#"{"op":"file_of"}"#,
            ),
            (
                r#"{"match":{"kind":"call","args":{"kind":"call"}}}"#,
                r#"{"kind":"call"}"#,
            ),
            ("(call :args (call))", "(call)"),
        ];
        for (source, token) in supported {
            let diagnostic = validate_query_source(source)
                .into_iter()
                .find(|diagnostic| &source[diagnostic.range.clone()] == token)
                .unwrap_or_else(|| panic!("missing wrapping diagnostic for {source}"));
            assert_eq!(
                diagnostic.fix,
                Some(QuerySourceFix {
                    title: if source.starts_with('(') {
                        "Wrap in a pattern list".to_string()
                    } else {
                        "Wrap in an array".to_string()
                    },
                    edit: QuerySourceEdit::Surround {
                        prefix: "[".to_string(),
                        suffix: "]".to_string(),
                    },
                })
            );
        }

        for source in [
            r#"{"where":1,"match":{"kind":"call"}}"#,
            r#"{"match":{"kind":"call","args":"item"}}"#,
            r#"{"match":{"kind":"call","kwargs":[]}}"#,
            r#"{"match":{"kind":"call","args":{"wat":{"kind":"call"}}}}"#,
            r#"{"steps":{"wat":"file_of"},"match":{"kind":"call"}}"#,
            r#"{"steps":{"op":"wat"},"match":{"kind":"call"}}"#,
            "(call :args \"item\")",
            "(call :args (call :wat 1))",
        ] {
            assert!(
                validate_query_source(source)
                    .into_iter()
                    .all(|diagnostic| diagnostic.fix.is_none())
            );
        }
    }

    #[test]
    fn accepted_language_aliases_do_not_produce_diagnostics() {
        for source in [
            "(language c++ (call))",
            "(language c# (call))",
            r#"{"languages":["c++","c#"],"match":{"kind":"call"}}"#,
        ] {
            assert!(
                validate_query_source(source).is_empty(),
                "accepted language alias should validate: {source}"
            );
        }
    }
}
