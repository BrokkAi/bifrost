//! Strict, bounded source decoding for RQLP policy and endpoint documents.
//!
//! This module owns only authoring-time concerns. It does not read referenced
//! files or directories: file selectors and match-directory references remain
//! typed, unresolved dependencies for the workspace loader.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::ops::Range;
use std::str::FromStr;

use crate::analyzer::semantic::WorkspaceRelativePath;
use crate::analyzer::structural::query::schema::resolve_rql_schema_version;
use crate::analyzer::structural::query::sexp::{
    code_query_from_expr, validate_policy_selector_expr,
};
use crate::schema_version::SchemaVersionResolution;
use crate::sexp::{Expr, ExprKind, SexpParseLimits, parse_sexp_with_limits};

use super::definition::*;
use super::schema::{
    AtomDomain, CollectionOrder, CvssBaseMetricSchema, CvssMetricScopeSchema, FieldPlacement,
    PolicyAnalysisKind, PolicyAtomValue, PolicyField, PolicyRecord, PolicyRecordContext,
    PolicyValueShape, RqlpDocumentKind, ValueMultiplicity, lookup_applicable_field, lookup_atom,
    lookup_cvss_base_metric, lookup_field, positional_field, records_from_label,
    required_fields_for_record, resolve_policy_schema_version,
};

pub const MAX_RQLP_SOURCE_BYTES: usize = 256 * 1024;
pub const MAX_RQLP_SEXP_DEPTH: usize = 128;
pub const MAX_RQLP_SEXP_NODES: usize = 4_096;
pub const MAX_RQLP_SOURCE_DIAGNOSTICS: usize = 64;

const MAX_HUMAN_NAME_BYTES: usize = 256;
const MAX_DISPLAY_TEXT_BYTES: usize = MAX_POLICY_DISPLAY_TEXT_BYTES;
const MAX_STRING_VECTOR_ENTRIES: usize = MAX_POLICY_SET_ITEMS;
const MAX_PREDICATE_DEPTH: usize = MAX_POLICY_PREDICATE_DEPTH;
const MAX_PREDICATE_NODES: usize = MAX_POLICY_PREDICATE_NODES;

/// Stable identity supplied by the embedding for source diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicySourceIdentity(Box<str>);

impl PolicySourceIdentity {
    pub fn new(identity: impl AsRef<str>) -> Self {
        Self(identity.as_ref().into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for PolicySourceIdentity {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for PolicySourceIdentity {
    fn from(value: String) -> Self {
        Self(value.into_boxed_str())
    }
}

impl fmt::Display for PolicySourceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySourceDiagnosticSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySourceEdit {
    pub range: Range<usize>,
    pub new_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySourceFix {
    pub title: String,
    pub edit: PolicySourceEdit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySourceRelatedDiagnostic {
    pub source: PolicySourceIdentity,
    pub range: Range<usize>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySourceDiagnostic {
    pub code: &'static str,
    pub severity: PolicySourceDiagnosticSeverity,
    pub message: String,
    pub range: Range<usize>,
    pub fix: Option<Box<PolicySourceFix>>,
    pub related: Vec<PolicySourceRelatedDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySourceError {
    pub diagnostic: PolicySourceDiagnostic,
}

impl fmt::Display for PolicySourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.diagnostic.message)
    }
}

impl std::error::Error for PolicySourceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySourceMapEntry {
    pub path: String,
    pub range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedPolicySelectorReference {
    pub path: String,
    pub authored_schema_version: Option<u32>,
    pub workspace_path: WorkspaceRelativePath,
    pub range: Range<usize>,
}

#[derive(Debug, Clone)]
pub struct ParsedRqlpDocument {
    identity: PolicySourceIdentity,
    document: RqlpDocument,
    schema_resolution: SchemaVersionResolution,
    source_map: Vec<PolicySourceMapEntry>,
    unresolved_file_selectors: Vec<UnresolvedPolicySelectorReference>,
}

impl ParsedRqlpDocument {
    pub fn identity(&self) -> &PolicySourceIdentity {
        &self.identity
    }

    pub fn document(&self) -> &RqlpDocument {
        &self.document
    }

    pub fn schema_resolution(&self) -> SchemaVersionResolution {
        self.schema_resolution
    }

    pub fn source_map(&self) -> &[PolicySourceMapEntry] {
        &self.source_map
    }

    pub fn unresolved_file_selectors(&self) -> &[UnresolvedPolicySelectorReference] {
        &self.unresolved_file_selectors
    }

    pub fn into_document(self) -> RqlpDocument {
        self.document
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySourceHelp {
    pub range: Range<usize>,
    pub signature: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicySourceCompletion {
    pub(crate) range: Range<usize>,
    pub(crate) label: &'static str,
    pub(crate) new_text: String,
    pub(crate) signature: &'static str,
    pub(crate) description: String,
}

pub fn parse_rqlp_source(
    source: &str,
    identity: PolicySourceIdentity,
) -> Result<ParsedRqlpDocument, PolicySourceError> {
    let expr = parse_rqlp_expr(source)?;
    Decoder::new(identity).decode_document(&expr)
}

fn parse_rqlp_expr(source: &str) -> Result<Expr, PolicySourceError> {
    if source.len() > MAX_RQLP_SOURCE_BYTES {
        return Err(source_error(
            "source-too-large",
            0..source.len(),
            format!(
                "RQLP source is too large: {} bytes exceeds {}",
                source.len(),
                MAX_RQLP_SOURCE_BYTES
            ),
        ));
    }
    let limits = SexpParseLimits::new(MAX_RQLP_SEXP_DEPTH, MAX_RQLP_SEXP_NODES);
    let parsed = parse_sexp_with_limits(source, limits)
        .map_err(|error| source_error("invalid-s-expression", error.range, error.message))?;
    if let Some(error) = parsed.incomplete {
        return Err(source_error(
            "incomplete-s-expression",
            error.range,
            error.message,
        ));
    }
    let expr = parsed.expr.ok_or_else(|| {
        source_error(
            "missing-document",
            source.len()..source.len(),
            "expected one `(policy ...)` or `(endpoint ...)` document",
        )
    })?;
    Ok(expr)
}

pub fn validate_rqlp_source(source: &str) -> Vec<PolicySourceDiagnostic> {
    let expr = match parse_rqlp_expr(source) {
        Ok(expr) => expr,
        Err(error) => return vec![error.diagnostic],
    };
    let mut diagnostics = collect_recoverable_schema_diagnostics(&expr);
    if let Err(error) = Decoder::new(PolicySourceIdentity::new("<buffer>")).decode_document(&expr)
        && !diagnostics.iter().any(|diagnostic| {
            diagnostic.code == error.diagnostic.code && diagnostic.range == error.diagnostic.range
        })
    {
        diagnostics.push(error.diagnostic);
    }
    diagnostics.sort_by(|left, right| {
        (left.range.start, left.range.end, left.code, &left.message).cmp(&(
            right.range.start,
            right.range.end,
            right.code,
            &right.message,
        ))
    });
    diagnostics.dedup_by(|left, right| left.code == right.code && left.range == right.range);
    diagnostics.truncate(MAX_RQLP_SOURCE_DIAGNOSTICS);
    diagnostics
}

pub fn rqlp_source_help_at(source: &str, byte_offset: usize) -> Option<PolicySourceHelp> {
    if source.len() > MAX_RQLP_SOURCE_BYTES || byte_offset > source.len() {
        return None;
    }
    let parsed = parse_sexp_with_limits(
        source,
        SexpParseLimits::new(MAX_RQLP_SEXP_DEPTH, MAX_RQLP_SEXP_NODES),
    )
    .ok()?;
    let expr = parsed.expr?;
    help_in_expr(&expr, byte_offset)
}

pub(crate) fn rqlp_source_completion_at(
    source: &str,
    byte_offset: usize,
) -> Option<PolicySourceCompletion> {
    if source.len() > MAX_RQLP_SOURCE_BYTES
        || byte_offset > source.len()
        || !source.is_char_boundary(byte_offset)
    {
        return None;
    }
    let parsed = parse_sexp_with_limits(
        source,
        SexpParseLimits::new(MAX_RQLP_SEXP_DEPTH, MAX_RQLP_SEXP_NODES),
    )
    .ok()?;
    let expr = parsed.expr?;
    completion_in_expr(&expr, byte_offset)
}

fn source_error(
    code: &'static str,
    range: Range<usize>,
    message: impl Into<String>,
) -> PolicySourceError {
    PolicySourceError {
        diagnostic: PolicySourceDiagnostic {
            code,
            severity: PolicySourceDiagnosticSeverity::Error,
            message: message.into(),
            range,
            fix: None,
            related: Vec::new(),
        },
    }
}

#[derive(Clone, Copy)]
struct RecoveryTask<'a> {
    expr: &'a Expr,
    collection_order: Option<CollectionOrder>,
}

/// Recover independent structural schema diagnostics without constructing a
/// partial typed policy. Semantic decoding remains fail-fast; this pass is
/// deliberately limited to registry-owned record fields and set-like scalar
/// collections so it cannot reinterpret nested native RQL.
fn collect_recoverable_schema_diagnostics(expr: &Expr) -> Vec<PolicySourceDiagnostic> {
    let mut diagnostics = Vec::new();
    let mut tasks = vec![RecoveryTask {
        expr,
        collection_order: None,
    }];
    while let Some(task) = tasks.pop() {
        match &task.expr.kind {
            ExprKind::Vector(values) => {
                if task.collection_order == Some(CollectionOrder::Set) {
                    let mut seen = HashSet::new();
                    for value in values {
                        let Some(key) = recovery_scalar_key(value) else {
                            continue;
                        };
                        if !seen.insert(key) {
                            diagnostics.push(
                                source_error(
                                    "duplicate-set-value",
                                    value.range.clone(),
                                    "duplicate scalar value in set-like collection",
                                )
                                .diagnostic,
                            );
                            if diagnostics.len() == MAX_RQLP_SOURCE_DIAGNOSTICS {
                                return diagnostics;
                            }
                        }
                    }
                }
                tasks.extend(values.iter().rev().map(|value| RecoveryTask {
                    expr: value,
                    collection_order: None,
                }));
            }
            ExprKind::List(items) => {
                let Some(head) = items.first().and_then(Expr::as_symbol) else {
                    continue;
                };
                let records = records_from_label(head).collect::<Vec<_>>();
                if records.is_empty() {
                    continue;
                }
                let mut children = Vec::new();
                let mut seen_labels = HashSet::new();
                let mut positional_index = 0_u8;
                let mut index = 1;
                while index < items.len() {
                    if let Some(label) = items[index]
                        .as_symbol()
                        .and_then(|symbol| symbol.strip_prefix(':'))
                    {
                        let keyword = &items[index];
                        let Some(value) = items.get(index + 1) else {
                            diagnostics.push(
                                source_error(
                                    "missing-field-value",
                                    keyword.range.clone(),
                                    format!("field `:{label}` requires a value"),
                                )
                                .diagnostic,
                            );
                            if diagnostics.len() == MAX_RQLP_SOURCE_DIAGNOSTICS {
                                return diagnostics;
                            }
                            break;
                        };
                        let descriptor = records
                            .iter()
                            .find_map(|record| lookup_field(*record, label));
                        if descriptor.is_none() {
                            diagnostics.push(
                                source_error(
                                    "unknown-field",
                                    keyword.range.clone(),
                                    format!(
                                        "unknown field `:{label}` for `{}`",
                                        records[0].label()
                                    ),
                                )
                                .diagnostic,
                            );
                        } else if !seen_labels.insert(label) {
                            diagnostics.push(
                                source_error(
                                    "duplicate-field",
                                    keyword.range.clone(),
                                    format!("duplicate field `:{label}`"),
                                )
                                .diagnostic,
                            );
                        }
                        if diagnostics.len() == MAX_RQLP_SOURCE_DIAGNOSTICS {
                            return diagnostics;
                        }
                        if let Some(descriptor) = descriptor
                            && descriptor.value_shape != PolicyValueShape::RqlQuery
                        {
                            children.push(RecoveryTask {
                                expr: value,
                                collection_order: collection_order(descriptor.multiplicity),
                            });
                        }
                        index += 2;
                    } else {
                        let descriptor = records
                            .iter()
                            .find_map(|record| positional_field(*record, positional_index));
                        if let Some(descriptor) = descriptor
                            && descriptor.value_shape != PolicyValueShape::RqlQuery
                        {
                            children.push(RecoveryTask {
                                expr: &items[index],
                                collection_order: collection_order(descriptor.multiplicity),
                            });
                        }
                        positional_index = positional_index.saturating_add(1);
                        index += 1;
                    }
                }
                tasks.extend(children.into_iter().rev());
            }
            ExprKind::String(_) | ExprKind::Symbol(_) | ExprKind::Number(_) => {}
        }
    }
    diagnostics
}

fn collection_order(multiplicity: ValueMultiplicity) -> Option<CollectionOrder> {
    match multiplicity {
        ValueMultiplicity::Scalar => None,
        ValueMultiplicity::Vector { order, .. } => Some(order),
    }
}

fn recovery_scalar_key(expr: &Expr) -> Option<String> {
    match &expr.kind {
        ExprKind::String(value) => Some(format!("string:{value}")),
        ExprKind::Symbol(value) => Some(format!("symbol:{value}")),
        ExprKind::Number(value) => Some(format!("number:{value}")),
        ExprKind::List(_) | ExprKind::Vector(_) => None,
    }
}

fn help_in_expr(expr: &Expr, byte_offset: usize) -> Option<PolicySourceHelp> {
    if !(expr.range.start <= byte_offset && byte_offset < expr.range.end) {
        return None;
    }
    let items = expr.as_list()?;
    let head = items.first()?.as_symbol()?;
    let records = records_from_label(head).collect::<Vec<_>>();
    if records.len() == 1 && items[0].range.contains(&byte_offset) {
        let record = records[0];
        return Some(PolicySourceHelp {
            range: items[0].range.clone(),
            signature: record.signature().to_string(),
            description: help_description(record.description(), record, items),
        });
    }
    let mut index = 1;
    while index < items.len() {
        let item = &items[index];
        let label = item.as_symbol().and_then(|symbol| symbol.strip_prefix(':'));
        if let Some(label) = label {
            if item.range.contains(&byte_offset) {
                let descriptor = records
                    .iter()
                    .find_map(|record| lookup_field(*record, label));
                if let Some(descriptor) = descriptor {
                    let description = if label == "schema-version" && records.len() == 1 {
                        help_description(descriptor.description, records[0], items)
                    } else {
                        descriptor.description.to_string()
                    };
                    return Some(PolicySourceHelp {
                        range: item.range.clone(),
                        signature: descriptor.signature.to_string(),
                        description,
                    });
                }
            }
            if let Some(value) = items.get(index + 1)
                && let Some(help) = help_in_expr(value, byte_offset)
            {
                return Some(help);
            }
            index += 2;
        } else {
            if let Some(help) = help_in_expr(item, byte_offset) {
                return Some(help);
            }
            index += 1;
        }
    }
    None
}

fn help_description(base_description: &str, record: PolicyRecord, items: &[Expr]) -> String {
    let Some(status) = schema_status(record, items) else {
        return base_description.to_string();
    };
    format!("{base_description}\n\n{status}")
}

fn schema_status(record: PolicyRecord, items: &[Expr]) -> Option<String> {
    let authored = authored_schema_version(items);
    match record {
        PolicyRecord::Policy | PolicyRecord::Endpoint => {
            let kind = if record == PolicyRecord::Policy {
                "policy"
            } else {
                "endpoint"
            };
            Some(match authored {
                AuthoredSchemaVersion::Omitted => {
                    let resolution = resolve_policy_schema_version(None).ok()?;
                    format!(
                        "Policy schema: `:schema-version` is omitted, so this {kind} document resolves to the latest compatible policy schema version (currently `{}`). Add `:schema-version {}` to pin it exactly.",
                        resolution.version, resolution.version
                    )
                }
                AuthoredSchemaVersion::Explicit(Some(version)) => {
                    if resolve_policy_schema_version(Some(version)).is_ok() {
                        format!(
                            "Policy schema: this {kind} document explicitly pins policy schema version `{version}`."
                        )
                    } else {
                        format!(
                            "Policy schema: this {kind} document explicitly requests unsupported policy schema version `{version}`."
                        )
                    }
                }
                AuthoredSchemaVersion::Explicit(None) => format!(
                    "Policy schema: this {kind} document has an incomplete or invalid explicit schema-version pin."
                ),
            })
        }
        PolicyRecord::Rql => Some(match authored {
            AuthoredSchemaVersion::Omitted => {
                let resolution = resolve_rql_schema_version(None).ok()?;
                format!(
                    "Selector schema: this inline RQL selector omits `:schema-version`, so it resolves to the latest compatible RQL schema version (currently `{}`). Add `:schema-version {}` to pin it exactly.",
                    resolution.version, resolution.version
                )
            }
            AuthoredSchemaVersion::Explicit(Some(version)) => {
                if resolve_rql_schema_version(Some(version)).is_ok() {
                    format!(
                        "Selector schema: this inline RQL selector explicitly pins RQL schema version `{version}`."
                    )
                } else {
                    format!(
                        "Selector schema: this inline RQL selector explicitly requests unsupported RQL schema version `{version}`."
                    )
                }
            }
            AuthoredSchemaVersion::Explicit(None) => {
                "Selector schema: this inline RQL selector has an incomplete or invalid explicit schema-version pin."
                    .to_string()
            }
        }),
        PolicyRecord::RqlFile => Some(match authored {
            AuthoredSchemaVersion::Omitted => {
                let resolution = resolve_rql_schema_version(None).ok()?;
                format!(
                    "Selector schema: this `rql-file` reference is resolved by the workspace loader, not by source-only validation. With no wrapper pin, an explicit version in the referenced `.rql` document wins; otherwise the latest compatible RQL schema version (currently `{}`) is used.",
                    resolution.version
                )
            }
            AuthoredSchemaVersion::Explicit(Some(version)) => {
                let support = if resolve_rql_schema_version(Some(version)).is_ok() {
                    ""
                } else {
                    " unsupported"
                };
                format!(
                    "Selector schema: this `rql-file` wrapper explicitly constrains deferred resolution to{support} RQL schema version `{version}`; a referenced document pin must agree. The source-only editor does not read the referenced file."
                )
            }
            AuthoredSchemaVersion::Explicit(None) => {
                "Selector schema: this `rql-file` wrapper has an incomplete or invalid explicit schema-version constraint. The source-only editor does not read the referenced file."
                    .to_string()
            }
        }),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthoredSchemaVersion {
    Omitted,
    Explicit(Option<u32>),
}

fn authored_schema_version(items: &[Expr]) -> AuthoredSchemaVersion {
    let mut index = 1;
    while index < items.len() {
        if items[index].as_symbol() == Some(":schema-version") {
            let version = items
                .get(index + 1)
                .and_then(Expr::as_number)
                .and_then(|value| u32::try_from(value).ok());
            return AuthoredSchemaVersion::Explicit(version);
        }
        index += if items[index]
            .as_symbol()
            .is_some_and(|symbol| symbol.starts_with(':'))
        {
            2
        } else {
            1
        };
    }
    AuthoredSchemaVersion::Omitted
}

fn completion_in_expr(expr: &Expr, byte_offset: usize) -> Option<PolicySourceCompletion> {
    if byte_offset < expr.range.start || byte_offset > expr.range.end {
        return None;
    }
    match &expr.kind {
        ExprKind::Vector(items) => items
            .iter()
            .find(|item| item.range.start <= byte_offset && byte_offset <= item.range.end)
            .and_then(|item| completion_in_expr(item, byte_offset)),
        ExprKind::List(items) => {
            let head = items.first()?;
            if head.range.start <= byte_offset && byte_offset <= head.range.end {
                return None;
            }
            for item in &items[1..] {
                if item.range.start <= byte_offset && byte_offset <= item.range.end {
                    if matches!(item.kind, ExprKind::List(_) | ExprKind::Vector(_)) {
                        return completion_in_expr(item, byte_offset);
                    }
                    let partial = item.as_symbol()?;
                    if !partial.starts_with(':') || !":schema-version".starts_with(partial) {
                        return None;
                    }
                    let record = single_record_for_head(head)?;
                    return schema_version_completion(record, items, item.range.clone());
                }
            }
            let record = single_record_for_head(head)?;
            schema_version_completion(record, items, byte_offset..byte_offset)
        }
        ExprKind::String(_) | ExprKind::Symbol(_) | ExprKind::Number(_) => None,
    }
}

fn single_record_for_head(head: &Expr) -> Option<PolicyRecord> {
    let mut records = records_from_label(head.as_symbol()?);
    let record = records.next()?;
    records.next().is_none().then_some(record)
}

fn schema_version_completion(
    record: PolicyRecord,
    items: &[Expr],
    range: Range<usize>,
) -> Option<PolicySourceCompletion> {
    if authored_schema_version(items) != AuthoredSchemaVersion::Omitted {
        return None;
    }
    let descriptor = lookup_field(record, "schema-version")?;
    let version = match record {
        PolicyRecord::Policy | PolicyRecord::Endpoint => {
            resolve_policy_schema_version(None).ok()?.version
        }
        PolicyRecord::Rql | PolicyRecord::RqlFile => resolve_rql_schema_version(None).ok()?.version,
        _ => return None,
    };
    Some(PolicySourceCompletion {
        range,
        label: ":schema-version",
        new_text: format!(":schema-version {version}"),
        signature: descriptor.signature,
        description: help_description(descriptor.description, record, items),
    })
}

struct Decoder {
    identity: PolicySourceIdentity,
    source_map: Vec<PolicySourceMapEntry>,
    unresolved_file_selectors: Vec<UnresolvedPolicySelectorReference>,
    local_taint_entry_ids: HashSet<String>,
    classification_combination_refs: Vec<(FindingCombinationId, Range<usize>)>,
    classification_expectation_refs: Vec<(TypestateExpectationId, Range<usize>)>,
    combination_classification_ranges: Vec<Range<usize>>,
    selector_paths: HashSet<String>,
}

impl Decoder {
    fn new(identity: PolicySourceIdentity) -> Self {
        Self {
            identity,
            source_map: Vec::new(),
            unresolved_file_selectors: Vec::new(),
            local_taint_entry_ids: HashSet::new(),
            classification_combination_refs: Vec::new(),
            classification_expectation_refs: Vec::new(),
            combination_classification_ranges: Vec::new(),
            selector_paths: HashSet::new(),
        }
    }

    fn decode_document(mut self, expr: &Expr) -> Result<ParsedRqlpDocument, PolicySourceError> {
        let (document, schema_resolution) = match select_record(
            expr,
            &[PolicyRecord::Policy, PolicyRecord::Endpoint],
            "top-level RQLP document",
        )? {
            PolicyRecord::Policy => {
                let definition = self.decode_policy(expr)?;
                let schema = definition.schema_version;
                (
                    RqlpDocument::Policy {
                        definition: Box::new(definition),
                    },
                    schema,
                )
            }
            PolicyRecord::Endpoint => {
                let definition = self.decode_endpoint(expr)?;
                let schema = definition.schema_version;
                (
                    RqlpDocument::Endpoint {
                        definition: Box::new(definition),
                    },
                    schema,
                )
            }
            record => unreachable!("document selector returned {record:?}"),
        };
        self.source_map
            .sort_by(|left, right| left.path.cmp(&right.path));
        Ok(ParsedRqlpDocument {
            identity: self.identity,
            document,
            schema_resolution,
            source_map: self.source_map,
            unresolved_file_selectors: self.unresolved_file_selectors,
        })
    }

    fn map(&mut self, path: impl Into<String>, expr: &Expr) {
        self.source_map.push(PolicySourceMapEntry {
            path: path.into(),
            range: expr.range.clone(),
        });
    }

    fn decode_policy(&mut self, expr: &Expr) -> Result<PolicyDefinition, PolicySourceError> {
        let version_expr = raw_keyword_value(expr, "schema-version")?;
        let authored_version = version_expr
            .map(|value| expect_u32(value, "policy schema version", false))
            .transpose()?;
        let schema_version = resolve_policy_schema_version(authored_version).map_err(|error| {
            source_error(
                "unsupported-policy-schema-version",
                version_expr.map_or_else(|| expr.range.clone(), |value| value.range.clone()),
                error.to_string(),
            )
        })?;
        // Top-level policy fields are common to all variants. A concrete
        // analysis context is still supplied so the applicability registry is
        // exercised consistently by RecordCursor.
        let fields = RecordCursor::parse(
            expr,
            PolicyRecord::Policy,
            DecodeContext::policy(PolicyAnalysisKind::Match),
        )?;
        self.map(
            "/schema_version",
            fields.get("schema-version").unwrap_or(expr),
        );

        let analysis = self.decode_analysis(fields.required("analysis"), "/analysis")?;
        let analysis_kind = analysis.analysis_type();
        let message = self.decode_message(fields.required("message"), analysis_kind)?;
        let severity = self.decode_severity(fields.required("severity"))?;
        let metadata = PolicyMetadata {
            id: parse_identifier(fields.required("id"), "policy ID")?,
            name: expect_string(fields.required("name"), "policy name", MAX_HUMAN_NAME_BYTES)?,
            message,
            severity,
            description: fields
                .get("description")
                .map(|value| expect_string(value, "policy description", MAX_DISPLAY_TEXT_BYTES))
                .transpose()?,
            help_uri: fields.get("help-uri").map(decode_help_uri).transpose()?,
            tags: fields
                .get("tags")
                .map(|value| decode_string_set(value, "policy tags", 0, MAX_STRING_VECTOR_ENTRIES))
                .transpose()?
                .unwrap_or_default(),
        };
        self.map("/id", fields.required("id"));
        self.map("/name", fields.required("name"));
        self.map("/message", fields.required("message"));
        self.map("/severity", fields.required("severity"));

        let classification = fields
            .get("classification")
            .map(|value| self.decode_classification(value, analysis_kind, "/classification"))
            .transpose()?;
        if classification.is_none()
            && let Some(range) = self.combination_classification_ranges.first()
        {
            return Err(source_error(
                "combination-classification-without-fallback",
                range.clone(),
                "finding-combination add-classifications requires a top-level classification fallback",
            ));
        }
        self.validate_classification_references(&analysis)?;
        let report = fields
            .get("report")
            .map(|value| self.decode_report(value))
            .transpose()?
            .unwrap_or_default();

        if matches!(metadata.severity, PolicySeveritySpec::Cvss { .. })
            && classification
                .as_ref()
                .and_then(|value| value.cvss.as_ref())
                .is_none()
        {
            return Err(source_error(
                "cvss-severity-without-cvss",
                fields.required("severity").range.clone(),
                "cvss-severity requires a classification with a CVSS policy",
            ));
        }

        Ok(PolicyDefinition {
            schema_version,
            metadata,
            analysis,
            classification,
            report,
        })
    }

    fn register_local_taint_entry<T: AsRef<str>>(
        &mut self,
        id: &T,
        id_expr: &Expr,
    ) -> Result<(), PolicySourceError> {
        if !self.local_taint_entry_ids.insert(id.as_ref().to_string()) {
            return Err(source_error(
                "duplicate-entry-id",
                id_expr.range.clone(),
                format!(
                    "duplicate policy-local taint entry ID `{}`; IDs are shared across source, sink, sanitizer, transform, and external-model sets",
                    id.as_ref()
                ),
            ));
        }
        Ok(())
    }

    fn validate_classification_references(
        &self,
        analysis: &PolicyAnalysis,
    ) -> Result<(), PolicySourceError> {
        if let PolicyAnalysis::Taint { spec } = analysis {
            let known = spec
                .finding_combinations
                .iter()
                .map(|combination| combination.id.as_str())
                .collect::<HashSet<_>>();
            if let Some((id, range)) = self
                .classification_combination_refs
                .iter()
                .find(|(id, _)| !known.contains(id.as_str()))
            {
                return Err(source_error(
                    "unknown-finding-combination",
                    range.clone(),
                    format!("classification references undeclared finding combination `{id}`"),
                ));
            }
        }
        if let PolicyAnalysis::Typestate { spec } = analysis {
            let known = spec
                .automaton
                .terminal_expectations
                .iter()
                .map(|expectation| expectation.id.as_str())
                .collect::<HashSet<_>>();
            if let Some((id, range)) = self
                .classification_expectation_refs
                .iter()
                .find(|(id, _)| !known.contains(id.as_str()))
            {
                return Err(source_error(
                    "unknown-typestate-expectation",
                    range.clone(),
                    format!("classification references undeclared terminal expectation `{id}`"),
                ));
            }
        }
        Ok(())
    }

    fn decode_endpoint(
        &mut self,
        expr: &Expr,
    ) -> Result<MatchEndpointDefinition, PolicySourceError> {
        let version_expr = raw_keyword_value(expr, "schema-version")?;
        let authored_version = version_expr
            .map(|value| expect_u32(value, "endpoint schema version", false))
            .transpose()?;
        let schema_version = resolve_policy_schema_version(authored_version).map_err(|error| {
            source_error(
                "unsupported-policy-schema-version",
                version_expr.map_or_else(|| expr.range.clone(), |value| value.range.clone()),
                error.to_string(),
            )
        })?;
        let fields = RecordCursor::parse(expr, PolicyRecord::Endpoint, DecodeContext::ENDPOINT)?;
        let role = decode_endpoint_role(fields.required("role"))?;
        let taint = fields
            .get("taint")
            .map(|value| self.decode_endpoint_taint(value, role))
            .transpose()?;
        let selector = self.decode_selector(
            fields.required("selector"),
            DecodeContext::ENDPOINT,
            "/endpoint/selector",
        )?;
        let id: EndpointId = parse_identifier(fields.required("id"), "endpoint ID")?;
        let supersedes = fields
            .get("supersedes")
            .map(|value| {
                decode_spanned_id_set::<EndpointId>(value, "superseded endpoint IDs", 0, 64)
            })
            .transpose()?
            .unwrap_or_default();
        if let Some(candidate) = supersedes.iter().find(|candidate| candidate.value == id) {
            return Err(source_error(
                "self-supersedes",
                candidate.range.clone(),
                format!("endpoint `{id}` cannot supersede itself"),
            ));
        }
        let definition = MatchEndpointDefinition {
            schema_version,
            id,
            name: expect_string(
                fields.required("name"),
                "endpoint name",
                MAX_HUMAN_NAME_BYTES,
            )?,
            display_name: expect_string(
                fields.required("display-name"),
                "endpoint display name",
                MAX_DISPLAY_TEXT_BYTES,
            )?,
            description: fields
                .get("description")
                .map(|value| expect_string(value, "endpoint description", MAX_DISPLAY_TEXT_BYTES))
                .transpose()?,
            help_uri: fields.get("help-uri").map(decode_help_uri).transpose()?,
            role,
            categories: decode_id_set(fields.required("categories"), "endpoint categories", 1, 64)?,
            selector,
            binding: self.decode_endpoint_binding(fields.required("binding"))?,
            taint,
            supersedes: supersedes
                .into_iter()
                .map(|candidate| candidate.value)
                .collect(),
        };
        self.map(
            "/schema_version",
            fields.get("schema-version").unwrap_or(expr),
        );
        self.map("/id", fields.required("id"));
        self.map("/endpoint/selector", fields.required("selector"));
        Ok(definition)
    }

    fn decode_analysis(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<PolicyAnalysis, PolicySourceError> {
        expect_record_head(expr, PolicyRecord::Analysis)?;
        let type_expr = raw_keyword_value(expr, "type")?.ok_or_else(|| {
            source_error(
                "missing-required-field",
                expr.range.clone(),
                "`analysis` is missing required field :type match|taint|typestate",
            )
        })?;
        let kind = match expect_atom(type_expr, AtomDomain::AnalysisType, "analysis type")? {
            PolicyAtomValue::AnalysisMatch => PolicyAnalysisKind::Match,
            PolicyAtomValue::AnalysisTaint => PolicyAnalysisKind::Taint,
            PolicyAtomValue::AnalysisTypestate => PolicyAnalysisKind::Typestate,
            value => unreachable!("AnalysisType registry returned {value:?}"),
        };
        let fields =
            RecordCursor::parse(expr, PolicyRecord::Analysis, DecodeContext::policy(kind))?;
        self.map(format!("{path}/type"), fields.required("type"));
        match kind {
            PolicyAnalysisKind::Match => Ok(PolicyAnalysis::Match {
                spec: MatchPolicySpec {
                    selector: self.decode_selector(
                        fields.required("selector"),
                        DecodeContext::policy(kind),
                        &format!("{path}/selector"),
                    )?,
                },
            }),
            PolicyAnalysisKind::Taint => Ok(PolicyAnalysis::Taint {
                spec: self.decode_taint_analysis(&fields, path)?,
            }),
            PolicyAnalysisKind::Typestate => Ok(PolicyAnalysis::Typestate {
                spec: self.decode_typestate_analysis(&fields, path)?,
            }),
        }
    }

    fn decode_taint_analysis(
        &mut self,
        fields: &RecordCursor<'_>,
        path: &str,
    ) -> Result<TaintPolicySpec, PolicySourceError> {
        match expect_atom(fields.required("mode"), AtomDomain::TaintMode, "taint mode")? {
            PolicyAtomValue::ModeMay => {}
            value => unreachable!("TaintMode registry returned {value:?}"),
        }
        let sources =
            self.decode_source_set(fields.required("sources"), &format!("{path}/sources"))?;
        let sinks = self.decode_sink_set(fields.required("sinks"), &format!("{path}/sinks"))?;
        let sanitizers = fields
            .get("sanitizers")
            .map(|value| self.decode_sanitizer_set(value, &format!("{path}/sanitizers")))
            .transpose()?
            .unwrap_or_default();
        let transforms = fields
            .get("transforms")
            .map(|value| self.decode_transform_set(value, &format!("{path}/transforms")))
            .transpose()?
            .unwrap_or_default();
        let external_models = fields
            .get("external-models")
            .map(|value| self.decode_external_model_set(value, &format!("{path}/external_models")))
            .transpose()?
            .unwrap_or_default();
        let finding_combinations = fields
            .get("finding-combinations")
            .map(|value| {
                self.decode_finding_combinations(value, &format!("{path}/finding_combinations"))
            })
            .transpose()?
            .unwrap_or_default();
        Ok(TaintPolicySpec {
            mode: MayMode::May,
            sources,
            sinks,
            sanitizers,
            transforms,
            external_models,
            finding_combinations,
        })
    }

    fn decode_source_set(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<TaintEndpointSet<TaintSourceSpec>, PolicySourceError> {
        let parts =
            self.decode_taint_set_parts(expr, PolicyRecordContext::TaintSources, true, path)?;
        let mut entries = Vec::with_capacity(parts.entries.len());
        let mut ids = HashSet::with_capacity(parts.entries.len());
        for entry in &parts.entries {
            let value = self.decode_taint_source(entry, path)?;
            if !ids.insert(value.id.as_str().to_string()) {
                return Err(source_error(
                    "duplicate-entry-id",
                    entry.range.clone(),
                    format!("duplicate source ID `{}`", value.id),
                ));
            }
            entries.push(value);
        }
        entries.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        Ok(TaintEndpointSet {
            include_sets: parts.include_sets,
            include_matches: parts.include_matches,
            entries,
        })
    }

    fn decode_sink_set(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<TaintEndpointSet<TaintSinkSpec>, PolicySourceError> {
        let parts =
            self.decode_taint_set_parts(expr, PolicyRecordContext::TaintSinks, true, path)?;
        let mut entries = Vec::with_capacity(parts.entries.len());
        let mut ids = HashSet::with_capacity(parts.entries.len());
        for entry in &parts.entries {
            let value = self.decode_taint_sink(entry, path)?;
            if !ids.insert(value.id.as_str().to_string()) {
                return Err(source_error(
                    "duplicate-entry-id",
                    entry.range.clone(),
                    format!("duplicate sink ID `{}`", value.id),
                ));
            }
            entries.push(value);
        }
        entries.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        Ok(TaintEndpointSet {
            include_sets: parts.include_sets,
            include_matches: parts.include_matches,
            entries,
        })
    }

    fn decode_sanitizer_set(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<TaintEndpointSet<TaintSanitizerSpec>, PolicySourceError> {
        let parts =
            self.decode_taint_set_parts(expr, PolicyRecordContext::TaintSanitizers, false, path)?;
        let mut entries = Vec::with_capacity(parts.entries.len());
        let mut ids = HashSet::with_capacity(parts.entries.len());
        for entry in &parts.entries {
            let value = self.decode_sanitizer(entry, path)?;
            if !ids.insert(value.id.as_str().to_string()) {
                return Err(source_error(
                    "duplicate-entry-id",
                    entry.range.clone(),
                    "duplicate sanitizer ID",
                ));
            }
            entries.push(value);
        }
        entries.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        Ok(TaintEndpointSet {
            include_sets: parts.include_sets,
            include_matches: parts.include_matches,
            entries,
        })
    }

    fn decode_transform_set(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<TaintEndpointSet<TaintTransformSpec>, PolicySourceError> {
        let parts =
            self.decode_taint_set_parts(expr, PolicyRecordContext::TaintTransforms, false, path)?;
        let mut entries = Vec::with_capacity(parts.entries.len());
        let mut ids = HashSet::with_capacity(parts.entries.len());
        for entry in &parts.entries {
            let value = self.decode_transform(entry, path)?;
            if !ids.insert(value.id.as_str().to_string()) {
                return Err(source_error(
                    "duplicate-entry-id",
                    entry.range.clone(),
                    "duplicate transform ID",
                ));
            }
            entries.push(value);
        }
        entries.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        Ok(TaintEndpointSet {
            include_sets: parts.include_sets,
            include_matches: parts.include_matches,
            entries,
        })
    }

    fn decode_external_model_set(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<TaintEndpointSet<TaintExternalModelSpec>, PolicySourceError> {
        let parts = self.decode_taint_set_parts(
            expr,
            PolicyRecordContext::TaintExternalModels,
            false,
            path,
        )?;
        let mut entries = Vec::with_capacity(parts.entries.len());
        let mut ids = HashSet::with_capacity(parts.entries.len());
        for entry in &parts.entries {
            let value = self.decode_external_model(entry, path)?;
            if !ids.insert(value.id.as_str().to_string()) {
                return Err(source_error(
                    "duplicate-entry-id",
                    entry.range.clone(),
                    "duplicate external-model ID",
                ));
            }
            entries.push(value);
        }
        entries.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        Ok(TaintEndpointSet {
            include_sets: parts.include_sets,
            include_matches: parts.include_matches,
            entries,
        })
    }

    fn decode_taint_set_parts<'a>(
        &mut self,
        expr: &'a Expr,
        record_context: PolicyRecordContext,
        allow_match_endpoints: bool,
        path: &str,
    ) -> Result<DecodedTaintSetParts<'a>, PolicySourceError> {
        let context = DecodeContext::policy(PolicyAnalysisKind::Taint).with_record(record_context);
        let fields = RecordCursor::parse(expr, PolicyRecord::EndpointSet, context)?;
        let include_sets = fields
            .get("include-sets")
            .map(|value| {
                decode_unique_values(
                    value,
                    "catalog references",
                    0,
                    64,
                    |item| self.decode_catalog(item, context),
                    catalog_key,
                )
            })
            .transpose()?
            .unwrap_or_default();
        let include_matches = if let Some(value) = fields.get("include-matches") {
            if !allow_match_endpoints {
                return Err(source_error(
                    "match-composition-not-allowed",
                    value.range.clone(),
                    "match endpoint composition is allowed only in taint source and sink sets",
                ));
            }
            decode_unique_values(
                value,
                "match endpoint sets",
                0,
                64,
                |item| {
                    let parsed = self.decode_match_endpoint_set(item, context)?;
                    debug_assert!(parsed.role.is_none() && parsed.phase.is_none());
                    Ok(parsed.set)
                },
                match_set_key,
            )?
        } else {
            Vec::new()
        };
        let entries = fields
            .get("entries")
            .map(|value| {
                expect_vector(value, "endpoint entries", 0, 256)
                    .map(|values| values.iter().collect::<Vec<_>>())
            })
            .transpose()?
            .unwrap_or_default();
        self.map(path, expr);
        Ok(DecodedTaintSetParts {
            include_sets,
            include_matches,
            entries,
        })
    }

    fn decode_catalog(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
    ) -> Result<CatalogRef, PolicySourceError> {
        let fields = RecordCursor::parse(expr, PolicyRecord::Catalog, context)?;
        let name = parse_identifier(fields.required("name"), "catalog name")?;
        let version = expect_u32(fields.required("version"), "catalog version", false)?;
        let sha256 = fields
            .get("sha256")
            .map(|value| {
                let token = expect_string(value, "catalog SHA-256", 64)?;
                TaintCatalogHash::from_lower_hex(&token).map_err(|error| {
                    source_error("invalid-sha256", value.range.clone(), error.to_string())
                })
            })
            .transpose()?;
        CatalogRef::new(name, version, sha256).map_err(|error| {
            source_error(
                "invalid-catalog-reference",
                expr.range.clone(),
                error.to_string(),
            )
        })
    }

    fn decode_match_endpoint_set(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
    ) -> Result<DecodedMatchEndpointSet, PolicySourceError> {
        match select_record(
            expr,
            &[PolicyRecord::MatchDirectory, PolicyRecord::MatchEndpoints],
            "match endpoint set",
        )? {
            PolicyRecord::MatchDirectory => {
                let fields = RecordCursor::parse(expr, PolicyRecord::MatchDirectory, context)?;
                let path_expr = fields.required("path");
                let raw_path =
                    expect_string(path_expr, "match directory path", MAX_DISPLAY_TEXT_BYTES)?;
                let path = WorkspaceRelativePath::new(raw_path).map_err(|error| {
                    source_error(
                        "invalid-workspace-path",
                        path_expr.range.clone(),
                        error.to_string(),
                    )
                })?;
                let manifest_sha256 = fields
                    .get("manifest-sha256")
                    .map(|value| {
                        let token = expect_string(value, "match manifest SHA-256", 64)?;
                        MatchSetManifestHash::from_lower_hex(&token).map_err(|error| {
                            source_error("invalid-sha256", value.range.clone(), error.to_string())
                        })
                    })
                    .transpose()?;
                Ok(DecodedMatchEndpointSet {
                    set: MatchEndpointSetRef::Directory {
                        reference: MatchDirectoryRef {
                            path,
                            scope: decode_directory_scope(fields.required("scope"))?,
                            categories: self.decode_category_predicate(
                                fields.required("categories"),
                                context,
                            )?,
                            manifest_sha256,
                        },
                    },
                    role: fields.get("role").map(decode_endpoint_role).transpose()?,
                    phase: fields
                        .get("phase")
                        .map(decode_observation_phase)
                        .transpose()?,
                })
            }
            PolicyRecord::MatchEndpoints => {
                let fields = RecordCursor::parse(expr, PolicyRecord::MatchEndpoints, context)?;
                Ok(DecodedMatchEndpointSet {
                    set: MatchEndpointSetRef::Exact {
                        endpoint_ids: decode_id_set(
                            fields.required("ids"),
                            "match endpoint IDs",
                            1,
                            64,
                        )?,
                    },
                    role: fields.get("role").map(decode_endpoint_role).transpose()?,
                    phase: fields
                        .get("phase")
                        .map(decode_observation_phase)
                        .transpose()?,
                })
            }
            record => unreachable!("match endpoint selector returned {record:?}"),
        }
    }

    fn decode_category_predicate(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
    ) -> Result<CategoryPredicate, PolicySourceError> {
        match select_record(
            expr,
            &[PolicyRecord::CategoryAny, PolicyRecord::CategoryAll],
            "category predicate",
        )? {
            PolicyRecord::CategoryAny => {
                let fields = RecordCursor::parse(expr, PolicyRecord::CategoryAny, context)?;
                Ok(CategoryPredicate::Any {
                    categories: decode_id_set(
                        fields.positional(0).expect("required category vector"),
                        "categories",
                        1,
                        64,
                    )?,
                })
            }
            PolicyRecord::CategoryAll => {
                let fields = RecordCursor::parse(expr, PolicyRecord::CategoryAll, context)?;
                Ok(CategoryPredicate::All {
                    categories: decode_id_set(
                        fields.positional(0).expect("required category vector"),
                        "categories",
                        1,
                        64,
                    )?,
                })
            }
            record => unreachable!("category predicate selector returned {record:?}"),
        }
    }

    fn decode_endpoint_predicate(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
    ) -> Result<EndpointPredicate, PolicySourceError> {
        match select_record(
            expr,
            &[
                PolicyRecord::CategoriesPredicate,
                PolicyRecord::EndpointsPredicate,
            ],
            "endpoint predicate",
        )? {
            PolicyRecord::CategoriesPredicate => {
                let fields = RecordCursor::parse(expr, PolicyRecord::CategoriesPredicate, context)?;
                match (fields.get("any"), fields.get("all")) {
                    (Some(value), None) => Ok(EndpointPredicate::Categories {
                        predicate: CategoryPredicate::Any {
                            categories: decode_id_set(value, "categories", 1, 64)?,
                        },
                    }),
                    (None, Some(value)) => Ok(EndpointPredicate::Categories {
                        predicate: CategoryPredicate::All {
                            categories: decode_id_set(value, "categories", 1, 64)?,
                        },
                    }),
                    (None, None) => Err(source_error(
                        "missing-predicate-variant",
                        expr.range.clone(),
                        "categories predicate requires exactly one of :any or :all",
                    )),
                    (Some(_), Some(value)) => Err(source_error(
                        "conflicting-predicate-variant",
                        value.range.clone(),
                        "categories :any and :all are mutually exclusive",
                    )),
                }
            }
            PolicyRecord::EndpointsPredicate => {
                let fields = RecordCursor::parse(expr, PolicyRecord::EndpointsPredicate, context)?;
                let endpoints = decode_unique_values(
                    fields.positional(0).expect("required endpoint vector"),
                    "endpoint references",
                    1,
                    64,
                    |value| self.decode_endpoint_ref(value, context),
                    endpoint_ref_key,
                )?;
                Ok(EndpointPredicate::Exact { endpoints })
            }
            record => unreachable!("endpoint predicate selector returned {record:?}"),
        }
    }

    fn decode_endpoint_ref(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
    ) -> Result<EndpointRef, PolicySourceError> {
        let fields = RecordCursor::parse(expr, PolicyRecord::EndpointRef, context)?;
        match (
            fields.get("local"),
            fields.get("catalog"),
            fields.get("entry"),
            fields.get("match-endpoint"),
        ) {
            (Some(local), None, None, None) => Ok(EndpointRef::Local {
                entry_id: parse_identifier(local, "local endpoint ID")?,
            }),
            (None, Some(catalog), Some(entry), None) => Ok(EndpointRef::Catalog {
                catalog: self.decode_catalog(catalog, context)?,
                entry_id: parse_identifier(entry, "catalog endpoint ID")?,
            }),
            (None, None, None, Some(endpoint)) => Ok(EndpointRef::MatchEndpoint {
                endpoint_id: parse_identifier(endpoint, "match endpoint ID")?,
            }),
            _ => Err(source_error(
                "invalid-endpoint-reference",
                expr.range.clone(),
                "endpoint-ref requires exactly :local, :catalog with :entry, or :match-endpoint",
            )),
        }
    }

    fn decode_taint_source(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<TaintSourceSpec, PolicySourceError> {
        let context = DecodeContext::policy(PolicyAnalysisKind::Taint);
        let fields = RecordCursor::parse(expr, PolicyRecord::Source, context)?;
        let id: TaintEntryId = parse_identifier(fields.required("id"), "source ID")?;
        self.register_local_taint_entry(&id, fields.required("id"))?;
        let selector_path = format!(
            "{path}/entries/{}/selector",
            json_pointer_segment(id.as_str())
        );
        Ok(TaintSourceSpec {
            id,
            display_name: expect_string(
                fields.required("display-name"),
                "source display name",
                MAX_DISPLAY_TEXT_BYTES,
            )?,
            categories: decode_id_set(fields.required("categories"), "source categories", 1, 64)?,
            selector: self.decode_selector(fields.required("selector"), context, &selector_path)?,
            bind: decoded_binding_to_port(decode_binding(
                fields.required("bind"),
                context,
                PolicyValueShape::PolicyPort,
            )?),
            labels: decode_id_set(fields.required("labels"), "source labels", 1, 64)?,
            evidence: fields
                .get("evidence")
                .map(|value| self.decode_source_evidence(value, context))
                .transpose()?,
        })
    }

    fn decode_taint_sink(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<TaintSinkSpec, PolicySourceError> {
        let context = DecodeContext::policy(PolicyAnalysisKind::Taint);
        let fields = RecordCursor::parse(expr, PolicyRecord::Sink, context)?;
        let id: TaintEntryId = parse_identifier(fields.required("id"), "sink ID")?;
        self.register_local_taint_entry(&id, fields.required("id"))?;
        let selector_path = format!(
            "{path}/entries/{}/selector",
            json_pointer_segment(id.as_str())
        );
        Ok(TaintSinkSpec {
            id,
            display_name: expect_string(
                fields.required("display-name"),
                "sink display name",
                MAX_DISPLAY_TEXT_BYTES,
            )?,
            categories: decode_id_set(fields.required("categories"), "sink categories", 1, 64)?,
            selector: self.decode_selector(fields.required("selector"), context, &selector_path)?,
            dangerous_operand: decoded_binding_to_port(decode_binding(
                fields.required("dangerous-operand"),
                context,
                PolicyValueShape::PolicyPort,
            )?),
            accepts: decode_id_set(fields.required("accepts"), "accepted labels", 1, 64)?,
            tags: fields
                .get("tags")
                .map(|value| decode_id_set(value, "sink tags", 0, 64))
                .transpose()?
                .unwrap_or_default(),
            impacts: fields
                .get("impacts")
                .map(|value| decode_id_set(value, "sink impacts", 0, 64))
                .transpose()?
                .unwrap_or_default(),
        })
    }

    fn decode_sanitizer(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<TaintSanitizerSpec, PolicySourceError> {
        let context = DecodeContext::policy(PolicyAnalysisKind::Taint);
        let fields = RecordCursor::parse(expr, PolicyRecord::Sanitizer, context)?;
        let id: TaintEntryId = parse_identifier(fields.required("id"), "sanitizer ID")?;
        self.register_local_taint_entry(&id, fields.required("id"))?;
        let selector_path = format!(
            "{path}/entries/{}/selector",
            json_pointer_segment(id.as_str())
        );
        Ok(TaintSanitizerSpec {
            id,
            selector: self.decode_selector(fields.required("selector"), context, &selector_path)?,
            input: decoded_binding_to_port(decode_binding(
                fields.required("input"),
                context,
                PolicyValueShape::PolicyPort,
            )?),
            output: decoded_binding_to_port(decode_binding(
                fields.required("output"),
                context,
                PolicyValueShape::PolicyPort,
            )?),
            removes: decode_id_set(fields.required("removes"), "removed labels", 1, 64)?,
        })
    }

    fn decode_transform(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<TaintTransformSpec, PolicySourceError> {
        let context = DecodeContext::policy(PolicyAnalysisKind::Taint);
        let fields = RecordCursor::parse(expr, PolicyRecord::TransformEntry, context)?;
        let id: TaintEntryId = parse_identifier(fields.required("id"), "transform ID")?;
        self.register_local_taint_entry(&id, fields.required("id"))?;
        let removes = fields
            .get("removes")
            .map(|value| decode_id_set(value, "removed labels", 0, 64))
            .transpose()?
            .unwrap_or_default();
        let adds = fields
            .get("adds")
            .map(|value| decode_id_set(value, "added labels", 0, 64))
            .transpose()?
            .unwrap_or_default();
        if removes.is_empty() && adds.is_empty() {
            return Err(source_error(
                "empty-transform",
                expr.range.clone(),
                "transform requires at least one removed or added label",
            ));
        }
        Ok(TaintTransformSpec {
            selector: self.decode_selector(
                fields.required("selector"),
                context,
                &format!(
                    "{path}/entries/{}/selector",
                    json_pointer_segment(id.as_str())
                ),
            )?,
            id,
            input: decoded_binding_to_port(decode_binding(
                fields.required("input"),
                context,
                PolicyValueShape::PolicyPort,
            )?),
            output: decoded_binding_to_port(decode_binding(
                fields.required("output"),
                context,
                PolicyValueShape::PolicyPort,
            )?),
            removes,
            adds,
        })
    }

    fn decode_external_model(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<TaintExternalModelSpec, PolicySourceError> {
        let context = DecodeContext::policy(PolicyAnalysisKind::Taint);
        let fields = RecordCursor::parse(expr, PolicyRecord::ExternalModel, context)?;
        let id: TaintEntryId = parse_identifier(fields.required("id"), "external-model ID")?;
        self.register_local_taint_entry(&id, fields.required("id"))?;
        let transfer_values = expect_vector(
            fields.required("transfers"),
            "external-model transfers",
            1,
            256,
        )?;
        let mut transfers = Vec::with_capacity(transfer_values.len());
        for value in transfer_values {
            let transfer = self.decode_transfer(value, context)?;
            if transfers.contains(&transfer) {
                return Err(source_error(
                    "duplicate-set-value",
                    value.range.clone(),
                    "duplicate external-model transfer",
                ));
            }
            transfers.push(transfer);
        }
        Ok(TaintExternalModelSpec {
            selector: self.decode_selector(
                fields.required("selector"),
                context,
                &format!(
                    "{path}/entries/{}/selector",
                    json_pointer_segment(id.as_str())
                ),
            )?,
            id,
            transfers,
        })
    }

    fn decode_transfer(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
    ) -> Result<TaintTransferSpec, PolicySourceError> {
        let fields = RecordCursor::parse(expr, PolicyRecord::Transfer, context)?;
        Ok(TaintTransferSpec {
            from: decoded_binding_to_port(decode_binding(
                fields.required("from"),
                context,
                PolicyValueShape::ExternalModelPort,
            )?),
            to: decoded_binding_to_port(decode_binding(
                fields.required("to"),
                context,
                PolicyValueShape::ExternalModelPort,
            )?),
            labels: decode_id_set(fields.required("labels"), "transfer labels", 1, 64)?,
            effect: self.decode_transfer_effect(fields.required("effect"), context)?,
        })
    }

    fn decode_transfer_effect(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
    ) -> Result<TaintTransferEffect, PolicySourceError> {
        if expr.as_symbol().is_some() {
            return match expect_atom(expr, AtomDomain::TransferEffect, "transfer effect")? {
                PolicyAtomValue::EffectPropagate => Ok(TaintTransferEffect::Propagate),
                value => unreachable!("TransferEffect registry returned {value:?}"),
            };
        }
        match select_record(
            expr,
            &[PolicyRecord::SanitizeEffect, PolicyRecord::TransformEffect],
            "structured transfer effect",
        )? {
            PolicyRecord::SanitizeEffect => {
                let fields = RecordCursor::parse(expr, PolicyRecord::SanitizeEffect, context)?;
                Ok(TaintTransferEffect::Sanitize {
                    removes: decode_id_set(fields.required("removes"), "removed labels", 1, 64)?,
                })
            }
            PolicyRecord::TransformEffect => {
                let fields = RecordCursor::parse(expr, PolicyRecord::TransformEffect, context)?;
                let removes = fields
                    .get("removes")
                    .map(|value| decode_id_set(value, "removed labels", 0, 64))
                    .transpose()?
                    .unwrap_or_default();
                let adds = fields
                    .get("adds")
                    .map(|value| decode_id_set(value, "added labels", 0, 64))
                    .transpose()?
                    .unwrap_or_default();
                if removes.is_empty() && adds.is_empty() {
                    return Err(source_error(
                        "empty-transform",
                        expr.range.clone(),
                        "transform effect requires at least one removed or added label",
                    ));
                }
                Ok(TaintTransferEffect::Transform { removes, adds })
            }
            record => unreachable!("transfer effect selector returned {record:?}"),
        }
    }

    fn decode_finding_combinations(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<Vec<FindingCombinationSpec>, PolicySourceError> {
        let context = DecodeContext::policy(PolicyAnalysisKind::Taint);
        let values = expect_vector(expr, "finding combinations", 0, 256)?;
        let mut result = Vec::with_capacity(values.len());
        let mut ids = HashSet::with_capacity(values.len());
        let mut graph = Vec::with_capacity(values.len());
        for value in values {
            let fields = RecordCursor::parse(value, PolicyRecord::FindingCombination, context)?;
            let id: FindingCombinationId =
                parse_identifier(fields.required("id"), "finding combination ID")?;
            if !ids.insert(id.as_str().to_string()) {
                return Err(source_error(
                    "duplicate-combination-id",
                    fields.required("id").range.clone(),
                    format!("duplicate finding-combination ID `{id}`"),
                ));
            }
            let supersedes = fields
                .get("supersedes")
                .map(|item| {
                    decode_spanned_id_set::<FindingCombinationId>(
                        item,
                        "superseded combinations",
                        0,
                        64,
                    )
                })
                .transpose()?
                .unwrap_or_default();
            graph.push(NamedGraphNode {
                id: id.as_str().to_string(),
                edges: supersedes
                    .iter()
                    .map(|target| NamedGraphEdge {
                        target: target.value.as_str().to_string(),
                        range: target.range.clone(),
                    })
                    .collect(),
            });
            let dependency_path = format!("{path}/{}", json_pointer_segment(id.as_str()));
            if let Some(item) = fields.get("add-classifications") {
                self.combination_classification_ranges
                    .push(item.range.clone());
            }
            result.push(FindingCombinationSpec {
                id,
                source: self.decode_endpoint_predicate(fields.required("source"), context)?,
                sink: self.decode_endpoint_predicate(fields.required("sink"), context)?,
                message: expect_string(
                    fields.required("message"),
                    "combination message",
                    MAX_DISPLAY_TEXT_BYTES,
                )?,
                severity: fields
                    .get("severity")
                    .map(|item| self.decode_severity(item))
                    .transpose()?,
                add_classifications: fields
                    .get("add-classifications")
                    .map(|item| {
                        decode_unique_values(
                            item,
                            "added classifications",
                            0,
                            64,
                            |entry| self.decode_taxonomy_classification(entry, context),
                            taxonomy_key,
                        )
                    })
                    .transpose()?
                    .unwrap_or_default(),
                supersedes: supersedes.into_iter().map(|target| target.value).collect(),
            });
            self.map(dependency_path, value);
        }
        validate_named_graph(&graph, "finding-combination")?;
        result.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        Ok(result)
    }

    fn decode_typestate_analysis(
        &mut self,
        fields: &RecordCursor<'_>,
        path: &str,
    ) -> Result<TypestatePolicySpec, PolicySourceError> {
        match expect_atom(
            fields.required("mode"),
            AtomDomain::TaintMode,
            "typestate mode",
        )? {
            PolicyAtomValue::ModeMay => {}
            value => unreachable!("TaintMode registry returned {value:?}"),
        }
        Ok(TypestatePolicySpec {
            mode: MayMode::May,
            subjects: self
                .decode_subject_set(fields.required("subjects"), &format!("{path}/subjects"))?,
            uncertainty: self.decode_uncertainty(fields.required("uncertainty"))?,
            automaton: self
                .decode_automaton(fields.required("automaton"), &format!("{path}/automaton"))?,
        })
    }

    fn decode_subject_set(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<TypestateSubjectSet, PolicySourceError> {
        let context = DecodeContext::policy(PolicyAnalysisKind::Typestate);
        let fields = RecordCursor::parse(expr, PolicyRecord::SubjectSet, context)?;
        let include_matches = fields
            .get("include-matches")
            .map(|value| {
                decode_unique_values(
                    value,
                    "typestate subject match sets",
                    0,
                    64,
                    |item| {
                        let parsed = self.decode_match_endpoint_set(item, context)?;
                        debug_assert!(parsed.role.is_none() && parsed.phase.is_none());
                        Ok(parsed.set)
                    },
                    match_set_key,
                )
            })
            .transpose()?
            .unwrap_or_default();
        let values = fields
            .get("entries")
            .map(|value| expect_vector(value, "typestate subjects", 0, 256))
            .transpose()?
            .unwrap_or_default();
        let mut entries = Vec::with_capacity(values.len());
        let mut ids = HashSet::with_capacity(values.len());
        for value in values {
            let record = RecordCursor::parse(value, PolicyRecord::Subject, context)?;
            let id: TaintEntryId = parse_identifier(record.required("id"), "subject ID")?;
            if !ids.insert(id.as_str().to_string()) {
                return Err(source_error(
                    "duplicate-subject-id",
                    record.required("id").range.clone(),
                    format!("duplicate subject ID `{id}`"),
                ));
            }
            let selector_path = format!(
                "{path}/entries/{}/selector",
                json_pointer_segment(id.as_str())
            );
            let selector =
                self.decode_selector(record.required("selector"), context, &selector_path)?;
            let subject = decoded_binding_to_seed(decode_binding(
                record.required("subject"),
                context,
                PolicyValueShape::TypestateBinding,
            )?);
            entries.push(TypestateSubjectSpec {
                id,
                selector,
                subject,
            });
        }
        entries.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        Ok(TypestateSubjectSet {
            include_matches,
            entries,
        })
    }

    fn decode_uncertainty(
        &mut self,
        expr: &Expr,
    ) -> Result<TypestateUncertaintySpec, PolicySourceError> {
        let context = DecodeContext::policy(PolicyAnalysisKind::Typestate);
        let fields = RecordCursor::parse(expr, PolicyRecord::Uncertainty, context)?;
        for value in [fields.required("unknown-call"), fields.required("escape")] {
            match expect_atom(value, AtomDomain::Uncertainty, "uncertainty policy")? {
                PolicyAtomValue::UncertaintyInconclusive => {}
                atom => unreachable!("Uncertainty registry returned {atom:?}"),
            }
        }
        Ok(TypestateUncertaintySpec {
            unknown_call: InconclusivePolicy::Inconclusive,
            escape: InconclusivePolicy::Inconclusive,
        })
    }

    fn decode_automaton(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<TypestateAutomatonSpec, PolicySourceError> {
        let context = DecodeContext::policy(PolicyAnalysisKind::Typestate);
        let fields = RecordCursor::parse(expr, PolicyRecord::Automaton, context)?;
        let states: Vec<TypestateStateId> =
            decode_id_set(fields.required("states"), "typestate states", 1, 256)?;
        let state_names = states
            .iter()
            .map(|value| value.as_str().to_string())
            .collect::<HashSet<_>>();
        let initial: TypestateStateId =
            parse_identifier(fields.required("initial"), "initial state")?;
        if !state_names.contains(initial.as_str()) {
            return Err(source_error(
                "unknown-typestate-state",
                fields.required("initial").range.clone(),
                format!("initial state `{initial}` is not declared in :states"),
            ));
        }
        let accepting_states_with_ranges = decode_spanned_id_set::<TypestateStateId>(
            fields.required("accepting-states"),
            "accepting states",
            1,
            256,
        )?;
        let error_states_with_ranges = decode_spanned_id_set::<TypestateStateId>(
            fields.required("error-states"),
            "error states",
            1,
            256,
        )?;
        for (kind, values) in [
            ("accepting", &accepting_states_with_ranges),
            ("error", &error_states_with_ranges),
        ] {
            for value in values {
                if !state_names.contains(value.value.as_str()) {
                    return Err(source_error(
                        "unknown-typestate-state",
                        value.range.clone(),
                        format!("{kind} state `{}` is not declared in :states", value.value),
                    ));
                }
            }
        }
        let accepting_names = accepting_states_with_ranges
            .iter()
            .map(|value| value.value.as_str())
            .collect::<HashSet<_>>();
        if let Some(overlap) = error_states_with_ranges
            .iter()
            .find(|value| accepting_names.contains(value.value.as_str()))
        {
            return Err(source_error(
                "conflicting-state-classification",
                overlap.range.clone(),
                format!(
                    "state `{}` cannot be both accepting and error",
                    overlap.value
                ),
            ));
        }
        let accepting_states = accepting_states_with_ranges
            .iter()
            .map(|value| value.value.clone())
            .collect::<Vec<_>>();
        let error_states = error_states_with_ranges
            .iter()
            .map(|value| value.value.clone())
            .collect::<Vec<_>>();

        let event_values = expect_vector(fields.required("events"), "typestate events", 1, 256)?;
        let mut events = Vec::with_capacity(event_values.len());
        let mut event_names = HashSet::with_capacity(event_values.len());
        let mut event_graph = Vec::with_capacity(event_values.len());
        for value in event_values {
            let (event, graph_node) = self.decode_typestate_event(value, path)?;
            if !event_names.insert(event.id.as_str().to_string()) {
                return Err(source_error(
                    "duplicate-event-id",
                    raw_keyword_value(value, "id")?
                        .expect("decoded event has an ID")
                        .range
                        .clone(),
                    format!("duplicate typestate event ID `{}`", event.id),
                ));
            }
            events.push(event);
            event_graph.push(graph_node);
        }
        validate_named_graph(&event_graph, "typestate event")?;

        let transition_values = expect_vector(
            fields.required("transitions"),
            "typestate transitions",
            1,
            4_096,
        )?;
        let mut transitions = Vec::with_capacity(transition_values.len());
        let mut transition_keys = HashMap::<(String, String), String>::new();
        for value in transition_values {
            let record = RecordCursor::parse(value, PolicyRecord::Transition, context)?;
            let from: TypestateStateId =
                parse_identifier(record.required("from"), "transition source state")?;
            let on: TypestateEventId = parse_identifier(record.required("on"), "transition event")?;
            let to: TypestateStateId =
                parse_identifier(record.required("to"), "transition destination state")?;
            if !state_names.contains(from.as_str()) {
                return Err(source_error(
                    "unknown-typestate-state",
                    record.required("from").range.clone(),
                    format!("transition references undeclared state `{from}`"),
                ));
            }
            if !state_names.contains(to.as_str()) {
                return Err(source_error(
                    "unknown-typestate-state",
                    record.required("to").range.clone(),
                    format!("transition references undeclared state `{to}`"),
                ));
            }
            if !event_names.contains(on.as_str()) {
                return Err(source_error(
                    "unknown-typestate-event",
                    record.required("on").range.clone(),
                    format!("transition references undeclared event `{on}`"),
                ));
            }
            let key = (from.as_str().to_string(), on.as_str().to_string());
            if let Some(previous) = transition_keys.insert(key, to.as_str().to_string()) {
                let message = if previous == to.as_str() {
                    "duplicate transition for the same state and event".to_string()
                } else {
                    format!("non-deterministic transition for state `{from}` and event `{on}`")
                };
                return Err(source_error(
                    "non-deterministic-transition",
                    record.required("on").range.clone(),
                    message,
                ));
            }
            transitions.push(TypestateTransitionSpec { from, on, to });
        }

        let expectation_values = fields
            .get("terminal-expectations")
            .map(|value| expect_vector(value, "terminal expectations", 0, 256))
            .transpose()?
            .unwrap_or_default();
        let mut terminal_expectations = Vec::with_capacity(expectation_values.len());
        let mut expectation_names = HashSet::with_capacity(expectation_values.len());
        let mut expectation_graph = Vec::with_capacity(expectation_values.len());
        for value in expectation_values {
            let (expectation, graph_node) =
                self.decode_terminal_expectation(value, &accepting_names, path)?;
            if !expectation_names.insert(expectation.id.as_str().to_string()) {
                return Err(source_error(
                    "duplicate-expectation-id",
                    raw_keyword_value(value, "id")?
                        .expect("decoded terminal expectation has an ID")
                        .range
                        .clone(),
                    format!("duplicate terminal expectation ID `{}`", expectation.id),
                ));
            }
            terminal_expectations.push(expectation);
            expectation_graph.push(graph_node);
        }
        validate_named_graph(&expectation_graph, "terminal expectation")?;
        events.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        transitions.sort_by(|left, right| {
            (left.from.as_str(), left.on.as_str(), left.to.as_str()).cmp(&(
                right.from.as_str(),
                right.on.as_str(),
                right.to.as_str(),
            ))
        });
        terminal_expectations.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        Ok(TypestateAutomatonSpec {
            states,
            initial,
            accepting_states,
            error_states,
            events,
            transitions,
            terminal_expectations,
        })
    }

    fn decode_typestate_event(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<(TypestateEventSpec, NamedGraphNode), PolicySourceError> {
        let context = DecodeContext::policy(PolicyAnalysisKind::Typestate);
        let fields = RecordCursor::parse(expr, PolicyRecord::Event, context)?;
        let id: TypestateEventId = parse_identifier(fields.required("id"), "typestate event ID")?;
        let event_path = format!("{path}/events/{}", json_pointer_segment(id.as_str()));
        self.map(event_path.clone(), expr);
        let trigger = match (fields.get("calls"), fields.get("matches"), fields.get("on")) {
            (Some(value), None, None) => self.decode_calls_trigger(value, &event_path)?,
            (None, Some(value), None) => {
                let parsed = self.decode_match_endpoint_set(
                    value,
                    context.with_record(PolicyRecordContext::TypestateTrigger),
                )?;
                let role = parsed.role.ok_or_else(|| {
                    source_error(
                        "missing-trigger-role",
                        value.range.clone(),
                        "typestate match trigger requires :role source|sink",
                    )
                })?;
                let phase = parsed.phase.ok_or_else(|| {
                    source_error(
                        "missing-trigger-phase",
                        value.range.clone(),
                        "typestate match trigger requires :phase",
                    )
                })?;
                TypestateEventTrigger::MatchEndpoints {
                    set: parsed.set,
                    role,
                    phase,
                }
            }
            (None, None, Some(value)) => TypestateEventTrigger::SemanticEvent {
                event: self.decode_semantic_event(value)?,
            },
            _ => {
                return Err(source_error(
                    "invalid-event-trigger",
                    expr.range.clone(),
                    "event requires exactly one of :calls, :matches, or :on",
                ));
            }
        };
        let supersedes = fields
            .get("supersedes")
            .map(|value| {
                decode_spanned_id_set::<TypestateEventId>(value, "superseded events", 0, 64)
            })
            .transpose()?
            .unwrap_or_default();
        let graph = NamedGraphNode {
            id: id.as_str().to_string(),
            edges: supersedes
                .iter()
                .map(|target| NamedGraphEdge {
                    target: target.value.as_str().to_string(),
                    range: target.range.clone(),
                })
                .collect(),
        };
        Ok((
            TypestateEventSpec {
                id,
                trigger,
                applies_to_subjects: fields
                    .get("applies-to-subjects")
                    .map(|value| self.decode_endpoint_predicate(value, context))
                    .transpose()?,
                supersedes: supersedes.into_iter().map(|target| target.value).collect(),
            },
            graph,
        ))
    }

    fn decode_calls_trigger(
        &mut self,
        expr: &Expr,
        path: &str,
    ) -> Result<TypestateEventTrigger, PolicySourceError> {
        let context = DecodeContext::policy(PolicyAnalysisKind::Typestate);
        let fields = RecordCursor::parse(expr, PolicyRecord::Calls, context)?;
        let subject_expr = fields.required("subject");
        let subject = decoded_binding_to_call(
            decode_binding(
                subject_expr,
                context,
                PolicyValueShape::TypestateCallBinding,
            )?,
            subject_expr.range.clone(),
        )?;
        let phase = decode_observation_phase(fields.required("phase"))?;
        if matches!(subject, TypestateCallBinding::ReturnValue)
            && matches!(
                phase,
                EndpointObservationPhase::BeforeCall
                    | EndpointObservationPhase::AfterExceptionalReturn
            )
        {
            return Err(source_error(
                "invalid-call-binding-phase",
                fields.required("phase").range.clone(),
                "return-value can be observed only after a normal return",
            ));
        }
        if phase == EndpointObservationPhase::AtMatch {
            return Err(source_error(
                "invalid-call-binding-phase",
                fields.required("phase").range.clone(),
                "calls triggers cannot use at-match phase",
            ));
        }
        Ok(TypestateEventTrigger::Calls {
            selector: self.decode_selector(
                fields.required("selector"),
                context,
                &format!("{path}/calls/selector"),
            )?,
            subject,
            phase,
        })
    }

    fn decode_terminal_expectation(
        &mut self,
        expr: &Expr,
        accepting_states: &HashSet<&str>,
        path: &str,
    ) -> Result<(TypestateTerminalExpectationSpec, NamedGraphNode), PolicySourceError> {
        let context = DecodeContext::policy(PolicyAnalysisKind::Typestate);
        let fields = RecordCursor::parse(expr, PolicyRecord::TerminalExpectation, context)?;
        let trigger = match (fields.get("matches"), fields.get("on")) {
            (Some(value), None) => {
                let parsed = self.decode_match_endpoint_set(
                    value,
                    context.with_record(PolicyRecordContext::TypestateTrigger),
                )?;
                let role = parsed.role.ok_or_else(|| {
                    source_error(
                        "missing-trigger-role",
                        value.range.clone(),
                        "terminal match trigger requires :role source|sink",
                    )
                })?;
                let phase = parsed.phase.ok_or_else(|| {
                    source_error(
                        "missing-trigger-phase",
                        value.range.clone(),
                        "terminal match trigger requires :phase",
                    )
                })?;
                TypestateTerminalTrigger::MatchEndpoints {
                    set: parsed.set,
                    role,
                    phase,
                }
            }
            (None, Some(value)) => TypestateTerminalTrigger::SemanticEvent {
                event: self.decode_semantic_event(value)?,
            },
            _ => {
                return Err(source_error(
                    "invalid-terminal-trigger",
                    expr.range.clone(),
                    "terminal-expectation requires exactly one of :matches or :on",
                ));
            }
        };
        let expected_states = decode_spanned_id_set::<TypestateStateId>(
            fields.required("expected-states"),
            "expected states",
            1,
            256,
        )?;
        if let Some(unknown) = expected_states
            .iter()
            .find(|state| !accepting_states.contains(state.value.as_str()))
        {
            return Err(source_error(
                "non-accepting-expected-state",
                unknown.range.clone(),
                format!(
                    "terminal expected state `{}` is not accepting",
                    unknown.value
                ),
            ));
        }
        let id: TypestateExpectationId =
            parse_identifier(fields.required("id"), "terminal expectation ID")?;
        self.map(
            format!(
                "{path}/terminal_expectations/{}",
                json_pointer_segment(id.as_str())
            ),
            expr,
        );
        let supersedes = fields
            .get("supersedes")
            .map(|value| {
                decode_spanned_id_set::<TypestateExpectationId>(
                    value,
                    "superseded expectations",
                    0,
                    64,
                )
            })
            .transpose()?
            .unwrap_or_default();
        let graph = NamedGraphNode {
            id: id.as_str().to_string(),
            edges: supersedes
                .iter()
                .map(|target| NamedGraphEdge {
                    target: target.value.as_str().to_string(),
                    range: target.range.clone(),
                })
                .collect(),
        };
        Ok((
            TypestateTerminalExpectationSpec {
                id,
                trigger,
                applies_to_subjects: fields
                    .get("applies-to-subjects")
                    .map(|value| self.decode_endpoint_predicate(value, context))
                    .transpose()?,
                expected_states: expected_states
                    .into_iter()
                    .map(|state| state.value)
                    .collect(),
                supersedes: supersedes.into_iter().map(|target| target.value).collect(),
            },
            graph,
        ))
    }

    fn decode_semantic_event(
        &mut self,
        expr: &Expr,
    ) -> Result<PolicySemanticEvent, PolicySourceError> {
        let context = DecodeContext::policy(PolicyAnalysisKind::Typestate);
        let (record, normal) = match select_record(
            expr,
            &[
                PolicyRecord::NormalProcedureExit,
                PolicyRecord::ExceptionalProcedureExit,
            ],
            "semantic event",
        )? {
            PolicyRecord::NormalProcedureExit => (PolicyRecord::NormalProcedureExit, true),
            PolicyRecord::ExceptionalProcedureExit => {
                (PolicyRecord::ExceptionalProcedureExit, false)
            }
            record => unreachable!("semantic event selector returned {record:?}"),
        };
        let fields = RecordCursor::parse(expr, record, context)?;
        match expect_atom(
            fields.required("scope"),
            AtomDomain::ExitScope,
            "exit scope",
        )? {
            PolicyAtomValue::ExitAnalysisRoot => {}
            value => unreachable!("ExitScope registry returned {value:?}"),
        }
        Ok(if normal {
            PolicySemanticEvent::NormalProcedureExit {
                scope: TypestateExitScope::AnalysisRoot,
            }
        } else {
            PolicySemanticEvent::ExceptionalProcedureExit {
                scope: TypestateExitScope::AnalysisRoot,
            }
        })
    }

    fn decode_classification(
        &mut self,
        expr: &Expr,
        analysis: PolicyAnalysisType,
        path: &str,
    ) -> Result<PolicyClassificationSpec, PolicySourceError> {
        let analysis_kind = schema_analysis_kind(analysis);
        let context = DecodeContext::policy(analysis_kind);
        let fields = RecordCursor::parse(expr, PolicyRecord::Classification, context)?;
        let refinement_values = fields
            .get("refinements")
            .map(|value| expect_vector(value, "classification refinements", 0, 128))
            .transpose()?
            .unwrap_or_default();
        let mut refinements = Vec::with_capacity(refinement_values.len());
        for (index, value) in refinement_values.iter().enumerate() {
            let record = RecordCursor::parse(value, PolicyRecord::Refinement, context)?;
            let mut budget = PredicateBudget::default();
            let when = self.decode_classification_predicate(
                record.required("when"),
                context,
                0,
                &mut budget,
            )?;
            let add = decode_unique_values(
                record.required("add"),
                "refinement classifications",
                1,
                64,
                |item| self.decode_taxonomy_classification(item, context),
                taxonomy_key,
            )?;
            refinements.push(ClassificationRefinementSpec { when, add });
            self.map(format!("{path}/refinements/{index}"), value);
        }
        Ok(PolicyClassificationSpec {
            fallback: self.decode_taxonomy_classification(fields.required("fallback"), context)?,
            refinements,
            cvss: fields
                .get("cvss")
                .map(|value| self.decode_cvss(value, context, &format!("{path}/cvss")))
                .transpose()?,
        })
    }

    fn decode_taxonomy_classification(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
    ) -> Result<TaxonomyClassificationSpec, PolicySourceError> {
        let fields = RecordCursor::parse(expr, PolicyRecord::ClassificationId, context)?;
        Ok(TaxonomyClassificationSpec {
            taxonomy: expect_string(
                fields.required("taxonomy"),
                "taxonomy name",
                MAX_HUMAN_NAME_BYTES,
            )?,
            identifier: expect_string(
                fields.required("id"),
                "taxonomy identifier",
                MAX_HUMAN_NAME_BYTES,
            )?,
            name: fields
                .get("name")
                .map(|value| expect_string(value, "classification name", MAX_HUMAN_NAME_BYTES))
                .transpose()?,
        })
    }

    fn decode_classification_predicate(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
        depth: usize,
        budget: &mut PredicateBudget,
    ) -> Result<ClassificationPredicate, PolicySourceError> {
        budget.enter(expr, depth)?;
        match select_record(
            expr,
            &[
                PolicyRecord::CvssPredicateAll,
                PolicyRecord::CvssPredicateAny,
                PolicyRecord::AnalysisTypePredicate,
                PolicyRecord::SourceCategoriesPredicate,
                PolicyRecord::SinkCategoriesPredicate,
                PolicyRecord::SourceLabelsPredicate,
                PolicyRecord::SinkTagsPredicate,
                PolicyRecord::SinkImpactsPredicate,
                PolicyRecord::FindingCombinationPredicate,
                PolicyRecord::TypestateExpectationPredicate,
            ],
            "classification predicate",
        )? {
            record @ (PolicyRecord::CvssPredicateAll | PolicyRecord::CvssPredicateAny) => {
                let any = record == PolicyRecord::CvssPredicateAny;
                let fields = RecordCursor::parse(expr, record, context)?;
                let values = expect_vector(
                    fields.positional(0).expect("required predicate vector"),
                    "classification predicates",
                    1,
                    256,
                )?;
                let mut predicates = Vec::with_capacity(values.len());
                for value in values {
                    let predicate =
                        self.decode_classification_predicate(value, context, depth + 1, budget)?;
                    if predicates.contains(&predicate) {
                        return Err(source_error(
                            "duplicate-set-value",
                            value.range.clone(),
                            "duplicate classification predicate",
                        ));
                    }
                    predicates.push(predicate);
                }
                if any {
                    Ok(ClassificationPredicate::Any { predicates })
                } else {
                    Ok(ClassificationPredicate::All { predicates })
                }
            }
            PolicyRecord::AnalysisTypePredicate => {
                let fields =
                    RecordCursor::parse(expr, PolicyRecord::AnalysisTypePredicate, context)?;
                Ok(ClassificationPredicate::AnalysisType {
                    analysis_type: decode_analysis_type(fields.required("is"))?,
                })
            }
            PolicyRecord::SourceCategoriesPredicate => {
                let (quantifier, values) = self.decode_quantified_values(
                    expr,
                    PolicyRecord::SourceCategoriesPredicate,
                    context,
                    "source categories",
                )?;
                Ok(ClassificationPredicate::SourceCategories { quantifier, values })
            }
            PolicyRecord::SinkCategoriesPredicate => {
                let (quantifier, values) = self.decode_quantified_values(
                    expr,
                    PolicyRecord::SinkCategoriesPredicate,
                    context,
                    "sink categories",
                )?;
                Ok(ClassificationPredicate::SinkCategories { quantifier, values })
            }
            PolicyRecord::SourceLabelsPredicate => {
                let (quantifier, values) = self.decode_quantified_values(
                    expr,
                    PolicyRecord::SourceLabelsPredicate,
                    context,
                    "source labels",
                )?;
                Ok(ClassificationPredicate::SourceLabels { quantifier, values })
            }
            PolicyRecord::SinkTagsPredicate => {
                let (quantifier, values) = self.decode_quantified_values(
                    expr,
                    PolicyRecord::SinkTagsPredicate,
                    context,
                    "sink tags",
                )?;
                Ok(ClassificationPredicate::SinkTags { quantifier, values })
            }
            PolicyRecord::SinkImpactsPredicate => {
                let (quantifier, values) = self.decode_quantified_values(
                    expr,
                    PolicyRecord::SinkImpactsPredicate,
                    context,
                    "sink impacts",
                )?;
                Ok(ClassificationPredicate::SinkImpacts { quantifier, values })
            }
            PolicyRecord::FindingCombinationPredicate => {
                let fields =
                    RecordCursor::parse(expr, PolicyRecord::FindingCombinationPredicate, context)?;
                let id_expr = fields.required("id");
                let id: FindingCombinationId = parse_identifier(id_expr, "finding-combination ID")?;
                self.classification_combination_refs
                    .push((id.clone(), id_expr.range.clone()));
                Ok(ClassificationPredicate::FindingCombination { id })
            }
            PolicyRecord::TypestateExpectationPredicate => {
                let fields = RecordCursor::parse(
                    expr,
                    PolicyRecord::TypestateExpectationPredicate,
                    context,
                )?;
                let id_expr = fields.required("id");
                let id: TypestateExpectationId =
                    parse_identifier(id_expr, "typestate expectation ID")?;
                self.classification_expectation_refs
                    .push((id.clone(), id_expr.range.clone()));
                Ok(ClassificationPredicate::TypestateExpectation { id })
            }
            record => unreachable!("classification predicate selector returned {record:?}"),
        }
    }

    fn decode_quantified_values<T>(
        &mut self,
        expr: &Expr,
        record: PolicyRecord,
        context: DecodeContext,
        what: &str,
    ) -> Result<(AnyOrAll, Vec<T>), PolicySourceError>
    where
        T: FromStr + AsRef<str>,
        T::Err: fmt::Display,
    {
        let fields = RecordCursor::parse(expr, record, context)?;
        match (fields.get("any"), fields.get("all")) {
            (Some(value), None) => Ok((
                AnyOrAll::Any,
                decode_id_set(value, what, 1, MAX_STRING_VECTOR_ENTRIES)?,
            )),
            (None, Some(value)) => Ok((
                AnyOrAll::All,
                decode_id_set(value, what, 1, MAX_STRING_VECTOR_ENTRIES)?,
            )),
            (None, None) => Err(source_error(
                "missing-predicate-variant",
                expr.range.clone(),
                format!("{what} predicate requires exactly one of :any or :all"),
            )),
            (Some(_), Some(value)) => Err(source_error(
                "conflicting-predicate-variant",
                value.range.clone(),
                format!("{what} predicate :any and :all are mutually exclusive"),
            )),
        }
    }

    fn decode_cvss(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
        path: &str,
    ) -> Result<CvssPolicySpec, PolicySourceError> {
        let fields = RecordCursor::parse(expr, PolicyRecord::Cvss, context)?;
        match expect_atom(
            fields.required("version"),
            AtomDomain::CvssVersion,
            "CVSS version",
        )? {
            PolicyAtomValue::CvssV4 => {}
            value => unreachable!("CvssVersion registry returned {value:?}"),
        }
        match expect_atom(
            fields.required("emit"),
            AtomDomain::CvssEmit,
            "CVSS emit policy",
        )? {
            PolicyAtomValue::CvssWhenComplete => {}
            value => unreachable!("CvssEmit registry returned {value:?}"),
        }
        let values = expect_vector(fields.required("metric-rules"), "CVSS metric rules", 1, 256)?;
        let mut metric_rules = Vec::with_capacity(values.len());
        for (index, value) in values.iter().enumerate() {
            let rule = self.decode_cvss_metric_rule(
                value,
                context,
                &format!("{path}/metric_rules/{index}"),
            )?;
            if metric_rules.contains(&rule) {
                return Err(source_error(
                    "duplicate-set-value",
                    value.range.clone(),
                    "duplicate CVSS metric rule",
                ));
            }
            metric_rules.push(rule);
        }
        Ok(CvssPolicySpec {
            version: CvssVersion::V4_0,
            emit: CvssEmitPolicy::WhenBaseComplete,
            metric_rules,
        })
    }

    fn decode_cvss_metric_rule(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
        path: &str,
    ) -> Result<CvssMetricRule, PolicySourceError> {
        let fields = RecordCursor::parse(expr, PolicyRecord::Metric, context)?;
        let metric_token = expect_token(fields.required("name"), "CVSS Base metric")?;
        let descriptor = lookup_cvss_base_metric(metric_token).ok_or_else(|| {
            source_error(
                "invalid-cvss-base-metric",
                fields.required("name").range.clone(),
                format!("`{metric_token}` is not an authorable CVSS v4.0 Base metric"),
            )
        })?;
        let metric = cvss_metric_from_schema(descriptor.metric);
        let value_token = expect_token(fields.required("value"), "CVSS metric value")?;
        let Some(token) = descriptor
            .legal_values
            .iter()
            .copied()
            .find(|token| token.first_label() == value_token)
        else {
            return Err(source_error(
                "invalid-cvss-metric-value",
                fields.required("value").range.clone(),
                format!("CVSS value `{value_token}` is not legal for metric `{metric_token}`"),
            ));
        };
        let value =
            CvssMetricValue::try_new(CvssMetric::Base { metric }, token).map_err(|error| {
                source_error(
                    "invalid-cvss-metric-value",
                    fields.required("value").range.clone(),
                    error.to_string(),
                )
            })?;
        let scope = decode_cvss_scope(fields.required("scope"))?;
        let expected_scope = match descriptor.scope {
            CvssMetricScopeSchema::VulnerableSystem => CvssEvidenceScope::System {
                system: CvssSystemScope::VulnerableSystem,
            },
            CvssMetricScopeSchema::SubsequentSystem => CvssEvidenceScope::System {
                system: CvssSystemScope::SubsequentSystem,
            },
        };
        if scope != expected_scope {
            return Err(source_error(
                "invalid-cvss-metric-scope",
                fields.required("scope").range.clone(),
                format!("scope does not agree with CVSS Base metric `{metric_token}`"),
            ));
        }
        match expect_atom(
            fields.required("basis"),
            AtomDomain::CvssBasis,
            "CVSS basis",
        )? {
            PolicyAtomValue::CvssPolicyAssertion => {}
            atom => unreachable!("CvssBasis registry returned {atom:?}"),
        }
        let mut budget = PredicateBudget::default();
        let when = self.decode_cvss_predicate(fields.required("when"), context, 0, &mut budget)?;
        let evidence_refs = decode_unique_values(
            fields.required("evidence-refs"),
            "CVSS evidence references",
            1,
            64,
            |item| self.decode_evidence_ref(item, context),
            evidence_ref_key,
        )?;
        let rationale = expect_string(
            fields.required("rationale"),
            "CVSS rationale",
            MAX_DISPLAY_TEXT_BYTES,
        )?;
        let assumptions = fields
            .get("assumptions")
            .map(|value| decode_string_set(value, "CVSS assumptions", 0, 64))
            .transpose()?
            .unwrap_or_default();
        self.map(path, expr);
        CvssMetricRule::try_new(
            metric,
            value,
            when,
            PolicyCvssBasis::PolicyAssertion,
            scope,
            evidence_refs,
            rationale,
            assumptions,
        )
        .map_err(|error| {
            source_error(
                "invalid-cvss-metric-rule",
                expr.range.clone(),
                error.to_string(),
            )
        })
    }

    fn decode_cvss_predicate(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
        depth: usize,
        budget: &mut PredicateBudget,
    ) -> Result<CvssEvidencePredicate, PolicySourceError> {
        budget.enter(expr, depth)?;
        match select_record(
            expr,
            &[
                PolicyRecord::PredicateAll,
                PolicyRecord::PredicateAny,
                PolicyRecord::AnalysisTypePredicate,
                PolicyRecord::SourceEvidence,
                PolicyRecord::SourceCategoriesPredicate,
                PolicyRecord::SinkCategoriesPredicate,
                PolicyRecord::SourceLabelsPredicate,
                PolicyRecord::SinkTagsPredicate,
                PolicyRecord::SinkImpactsPredicate,
            ],
            "CVSS evidence predicate",
        )? {
            record @ (PolicyRecord::PredicateAll | PolicyRecord::PredicateAny) => {
                let any = record == PolicyRecord::PredicateAny;
                let fields = RecordCursor::parse(expr, record, context)?;
                let values = expect_vector(
                    fields.positional(0).expect("required predicate vector"),
                    "CVSS predicates",
                    1,
                    256,
                )?;
                let mut predicates = Vec::with_capacity(values.len());
                for value in values {
                    let predicate =
                        self.decode_cvss_predicate(value, context, depth + 1, budget)?;
                    if predicates.contains(&predicate) {
                        return Err(source_error(
                            "duplicate-set-value",
                            value.range.clone(),
                            "duplicate CVSS evidence predicate",
                        ));
                    }
                    predicates.push(predicate);
                }
                if any {
                    Ok(CvssEvidencePredicate::Any { predicates })
                } else {
                    Ok(CvssEvidencePredicate::All { predicates })
                }
            }
            PolicyRecord::AnalysisTypePredicate => {
                let fields =
                    RecordCursor::parse(expr, PolicyRecord::AnalysisTypePredicate, context)?;
                Ok(CvssEvidencePredicate::AnalysisType {
                    analysis_type: decode_analysis_type(fields.required("is"))?,
                })
            }
            PolicyRecord::SourceEvidence => Ok(CvssEvidencePredicate::SourceEvidence {
                evidence: self.decode_source_evidence(expr, context)?,
            }),
            PolicyRecord::SourceCategoriesPredicate => {
                let (quantifier, values) = self.decode_quantified_values(
                    expr,
                    PolicyRecord::SourceCategoriesPredicate,
                    context,
                    "source categories",
                )?;
                Ok(CvssEvidencePredicate::SourceCategories { quantifier, values })
            }
            PolicyRecord::SinkCategoriesPredicate => {
                let (quantifier, values) = self.decode_quantified_values(
                    expr,
                    PolicyRecord::SinkCategoriesPredicate,
                    context,
                    "sink categories",
                )?;
                Ok(CvssEvidencePredicate::SinkCategories { quantifier, values })
            }
            PolicyRecord::SourceLabelsPredicate => {
                let (quantifier, values) = self.decode_quantified_values(
                    expr,
                    PolicyRecord::SourceLabelsPredicate,
                    context,
                    "source labels",
                )?;
                Ok(CvssEvidencePredicate::SourceLabels { quantifier, values })
            }
            PolicyRecord::SinkTagsPredicate => {
                let (quantifier, values) = self.decode_quantified_values(
                    expr,
                    PolicyRecord::SinkTagsPredicate,
                    context,
                    "sink tags",
                )?;
                Ok(CvssEvidencePredicate::SinkTags { quantifier, values })
            }
            PolicyRecord::SinkImpactsPredicate => {
                let (quantifier, values) = self.decode_quantified_values(
                    expr,
                    PolicyRecord::SinkImpactsPredicate,
                    context,
                    "sink impacts",
                )?;
                Ok(CvssEvidencePredicate::SinkImpacts { quantifier, values })
            }
            record => unreachable!("CVSS predicate selector returned {record:?}"),
        }
    }

    fn decode_evidence_ref(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
    ) -> Result<PolicyEvidenceRef, PolicySourceError> {
        if let Some(token) = expr.as_symbol().or_else(|| expr.as_string()) {
            if let Some(descriptor) = lookup_atom(AtomDomain::EvidenceRef, token) {
                return match descriptor.value {
                    PolicyAtomValue::EvidencePolicySelf => Ok(PolicyEvidenceRef::PolicySelf),
                    PolicyAtomValue::EvidenceSelector => {
                        let path = descriptor
                            .matched_suffix(token)
                            .expect("the selector evidence descriptor is prefix-matched");
                        let path = PolicySelectorPath::new(path).map_err(|error| {
                            source_error(
                                "invalid-selector-evidence-reference",
                                expr.range.clone(),
                                error.to_string(),
                            )
                        })?;
                        if !self.selector_paths.contains(path.as_str()) {
                            return Err(source_error(
                                "unknown-selector-evidence-reference",
                                expr.range.clone(),
                                format!("selector evidence reference `{path}` is not declared"),
                            ));
                        }
                        Ok(PolicyEvidenceRef::Selector { path })
                    }
                    value => unreachable!("EvidenceRef registry returned {value:?}"),
                };
            }
            return Err(source_error(
                "invalid-evidence-reference",
                expr.range.clone(),
                "evidence reference must be policy:self, selector:/path, or endpoint-ref",
            ));
        }
        Ok(PolicyEvidenceRef::Endpoint {
            endpoint: self.decode_endpoint_ref(expr, context)?,
        })
    }

    fn decode_message(
        &mut self,
        expr: &Expr,
        analysis: PolicyAnalysisType,
    ) -> Result<PolicyMessageSpec, PolicySourceError> {
        if expr.as_string().is_some() {
            return Ok(PolicyMessageSpec::Static {
                text: expect_string(expr, "policy message", MAX_DISPLAY_TEXT_BYTES)?,
            });
        }
        if analysis != PolicyAnalysisType::Taint {
            return Err(source_error(
                "message-not-allowed",
                expr.range.clone(),
                "generated-message is allowed only for taint policies",
            ));
        }
        let fields = RecordCursor::parse(
            expr,
            PolicyRecord::GeneratedMessage,
            DecodeContext::policy(PolicyAnalysisKind::Taint),
        )?;
        match expect_atom(
            fields.required("relation"),
            AtomDomain::GeneratedRelation,
            "generated message relation",
        )? {
            PolicyAtomValue::RelationCanReach => {}
            value => unreachable!("GeneratedRelation registry returned {value:?}"),
        }
        Ok(PolicyMessageSpec::Generated {
            relation: GeneratedRelation::CanReach,
        })
    }

    fn decode_severity(&mut self, expr: &Expr) -> Result<PolicySeveritySpec, PolicySourceError> {
        if let Some(token) = expr.as_symbol() {
            return match lookup_atom(AtomDomain::Severity, token).map(|value| value.value) {
                Some(PolicyAtomValue::SeverityNote) => Ok(PolicySeveritySpec::Fixed {
                    level: PolicyLevel::Note,
                }),
                Some(PolicyAtomValue::SeverityWarning) => Ok(PolicySeveritySpec::Fixed {
                    level: PolicyLevel::Warning,
                }),
                Some(PolicyAtomValue::SeverityError) => Ok(PolicySeveritySpec::Fixed {
                    level: PolicyLevel::Error,
                }),
                Some(PolicyAtomValue::SeverityUnrated) => Ok(PolicySeveritySpec::Unrated),
                Some(value) => unreachable!("Severity registry returned {value:?}"),
                None => Err(source_error(
                    "invalid-enum-value",
                    expr.range.clone(),
                    "severity must be note, warning, error, unrated, or cvss-severity",
                )),
            };
        }
        let fields = RecordCursor::parse(
            expr,
            PolicyRecord::CvssSeverity,
            DecodeContext::policy(PolicyAnalysisKind::Match),
        )?;
        Ok(PolicySeveritySpec::Cvss {
            when_unscored: decode_finding_severity(fields.required("when-unscored"))?,
        })
    }

    fn decode_selector(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
        path: &str,
    ) -> Result<PolicySelector, PolicySourceError> {
        match select_record(
            expr,
            &[PolicyRecord::Rql, PolicyRecord::RqlFile],
            "policy selector",
        )? {
            PolicyRecord::Rql => {
                let fields = RecordCursor::parse(expr, PolicyRecord::Rql, context)?;
                let authored_version = fields
                    .get("schema-version")
                    .map(|value| expect_u32(value, "RQL schema version", false))
                    .transpose()?;
                let schema = resolve_rql_schema_version(authored_version).map_err(|error| {
                    source_error(
                        "unsupported-rql-schema-version",
                        fields
                            .get("schema-version")
                            .map_or_else(|| expr.range.clone(), |value| value.range.clone()),
                        error.to_string(),
                    )
                })?;
                let query_expr = fields.positional(0).expect("required positional RQL query");
                validate_policy_selector_expr(query_expr).map_err(|error| {
                    source_error(
                        "query-output-control-not-allowed",
                        error.range,
                        error.message,
                    )
                })?;
                let query = code_query_from_expr(query_expr, schema).map_err(|error| {
                    let message = error.to_string();
                    source_error("invalid-inline-rql", error.range, message)
                })?;
                self.map(
                    format!("{path}/schema_version"),
                    fields.get("schema-version").unwrap_or(expr),
                );
                self.map(format!("{path}/query"), query_expr);
                debug_assert!(self.selector_paths.insert(path.to_string()));
                Ok(PolicySelector::Inline { schema, query })
            }
            PolicyRecord::RqlFile => {
                let fields = RecordCursor::parse(expr, PolicyRecord::RqlFile, context)?;
                let authored_schema_version = fields
                    .get("schema-version")
                    .map(|value| expect_u32(value, "RQL schema version", false))
                    .transpose()?;
                if let Some(version) = authored_schema_version {
                    resolve_rql_schema_version(Some(version)).map_err(|error| {
                        source_error(
                            "unsupported-rql-schema-version",
                            fields.required("schema-version").range.clone(),
                            error.to_string(),
                        )
                    })?;
                }
                let path_expr = fields.required("path");
                let raw_path = expect_string(path_expr, "RQL file path", MAX_DISPLAY_TEXT_BYTES)?;
                let workspace_path = WorkspaceRelativePath::new(&raw_path).map_err(|error| {
                    source_error(
                        "invalid-workspace-path",
                        path_expr.range.clone(),
                        error.to_string(),
                    )
                })?;
                if !workspace_path.as_str().ends_with(".rql") {
                    return Err(source_error(
                        "invalid-rql-file-extension",
                        path_expr.range.clone(),
                        "rql-file path must end in `.rql`",
                    ));
                }
                self.unresolved_file_selectors
                    .push(UnresolvedPolicySelectorReference {
                        path: path.to_string(),
                        authored_schema_version,
                        workspace_path: workspace_path.clone(),
                        range: expr.range.clone(),
                    });
                self.map(format!("{path}/path"), path_expr);
                debug_assert!(self.selector_paths.insert(path.to_string()));
                Ok(PolicySelector::File {
                    authored_schema_version,
                    path: workspace_path,
                })
            }
            record => unreachable!("selector returned {record:?}"),
        }
    }

    fn decode_endpoint_binding(
        &mut self,
        expr: &Expr,
    ) -> Result<PolicyEndpointBinding, PolicySourceError> {
        match decode_binding(
            expr,
            DecodeContext::ENDPOINT,
            PolicyValueShape::EndpointBinding,
        )? {
            DecodedBinding::MatchedValue => Ok(PolicyEndpointBinding::MatchedValue),
            DecodedBinding::Receiver => Ok(PolicyEndpointBinding::Receiver),
            DecodedBinding::ReturnValue => Ok(PolicyEndpointBinding::ReturnValue),
            DecodedBinding::ArgumentIndex(index) => {
                Ok(PolicyEndpointBinding::ArgumentIndex { index })
            }
            DecodedBinding::ArgumentName(name) => Ok(PolicyEndpointBinding::ArgumentName { name }),
        }
    }

    fn decode_endpoint_taint(
        &mut self,
        expr: &Expr,
        role: EndpointRole,
    ) -> Result<EndpointTaintSemantics, PolicySourceError> {
        let record = select_record(
            expr,
            &[PolicyRecord::SourceSemantics, PolicyRecord::SinkSemantics],
            "endpoint taint semantics",
        )?;
        match (role, record) {
            (EndpointRole::Source, PolicyRecord::SourceSemantics) => {
                let fields = RecordCursor::parse(
                    expr,
                    PolicyRecord::SourceSemantics,
                    DecodeContext::ENDPOINT,
                )?;
                Ok(EndpointTaintSemantics::Source {
                    labels: decode_id_set(fields.required("labels"), "source labels", 1, 64)?,
                    evidence: fields
                        .get("evidence")
                        .map(|value| self.decode_source_evidence(value, DecodeContext::ENDPOINT))
                        .transpose()?,
                })
            }
            (EndpointRole::Sink, PolicyRecord::SinkSemantics) => {
                let fields = RecordCursor::parse(
                    expr,
                    PolicyRecord::SinkSemantics,
                    DecodeContext::ENDPOINT,
                )?;
                Ok(EndpointTaintSemantics::Sink {
                    accepts: decode_id_set(fields.required("accepts"), "accepted labels", 1, 64)?,
                    tags: fields
                        .get("tags")
                        .map(|value| decode_id_set(value, "sink tags", 0, 64))
                        .transpose()?
                        .unwrap_or_default(),
                    impacts: fields
                        .get("impacts")
                        .map(|value| decode_id_set(value, "sink impacts", 0, 64))
                        .transpose()?
                        .unwrap_or_default(),
                })
            }
            (EndpointRole::Source, _) => Err(source_error(
                "endpoint-taint-role-mismatch",
                expr.range.clone(),
                "source endpoint taint semantics must use source-semantics",
            )),
            (EndpointRole::Sink, _) => Err(source_error(
                "endpoint-taint-role-mismatch",
                expr.range.clone(),
                "sink endpoint taint semantics must use sink-semantics",
            )),
        }
    }

    fn decode_source_evidence(
        &mut self,
        expr: &Expr,
        context: DecodeContext,
    ) -> Result<TaintSourceEvidence, PolicySourceError> {
        let record = select_record(
            expr,
            &[PolicyRecord::Evidence, PolicyRecord::SourceEvidence],
            "source evidence",
        )?;
        let fields = RecordCursor::parse(expr, record, context)?;
        let trust_boundary = fields
            .get("trust-boundary")
            .map(decode_trust_boundary)
            .transpose()?;
        let system_entry = fields
            .get("system-entry")
            .map(decode_system_entry)
            .transpose()?;
        if trust_boundary.is_none() && system_entry.is_none() {
            return Err(source_error(
                "empty-source-evidence",
                expr.range.clone(),
                "source evidence requires trust-boundary, system-entry, or both",
            ));
        }
        Ok(TaintSourceEvidence {
            trust_boundary,
            system_entry,
        })
    }

    fn decode_report(&mut self, expr: &Expr) -> Result<PolicyReportOptions, PolicySourceError> {
        let fields = RecordCursor::parse(
            expr,
            PolicyRecord::Report,
            DecodeContext::policy(PolicyAnalysisKind::Match),
        )?;
        Ok(PolicyReportOptions {
            witness: fields
                .get("witness")
                .map(|value| self.decode_witness(value))
                .transpose()?
                .unwrap_or_default(),
            witnesses_per_finding: fields
                .get("witnesses-per-finding")
                .map(|value| {
                    expect_usize_bounded(
                        value,
                        "witnesses per finding",
                        0,
                        MAX_WITNESSES_PER_FINDING,
                    )
                })
                .transpose()?
                .unwrap_or(DEFAULT_WITNESSES_PER_FINDING),
            origins_per_finding: fields
                .get("origins-per-finding")
                .map(|value| {
                    expect_usize_bounded(value, "origins per finding", 0, MAX_ORIGINS_PER_FINDING)
                })
                .transpose()?
                .unwrap_or(DEFAULT_ORIGINS_PER_FINDING),
        })
    }

    fn decode_witness(&mut self, expr: &Expr) -> Result<WitnessOptions, PolicySourceError> {
        let fields = RecordCursor::parse(
            expr,
            PolicyRecord::Witness,
            DecodeContext::policy(PolicyAnalysisKind::Match),
        )?;
        Ok(WitnessOptions {
            max_steps: fields
                .get("max-steps")
                .map(|value| expect_usize_bounded(value, "witness max steps", 0, MAX_WITNESS_STEPS))
                .transpose()?
                .unwrap_or(DEFAULT_WITNESS_MAX_STEPS),
            max_bytes: fields
                .get("max-bytes")
                .map(|value| expect_usize_bounded(value, "witness max bytes", 0, MAX_WITNESS_BYTES))
                .transpose()?
                .unwrap_or(DEFAULT_WITNESS_MAX_BYTES),
        })
    }
}

#[derive(Clone, Copy)]
struct DecodeContext {
    document: RqlpDocumentKind,
    analysis: Option<PolicyAnalysisKind>,
    record: PolicyRecordContext,
}

struct DecodedTaintSetParts<'a> {
    include_sets: Vec<CatalogRef>,
    include_matches: Vec<MatchEndpointSetRef>,
    entries: Vec<&'a Expr>,
}

struct DecodedMatchEndpointSet {
    set: MatchEndpointSetRef,
    role: Option<EndpointRole>,
    phase: Option<EndpointObservationPhase>,
}

struct SpannedValue<T> {
    value: T,
    range: Range<usize>,
}

struct NamedGraphEdge {
    target: String,
    range: Range<usize>,
}

struct NamedGraphNode {
    id: String,
    edges: Vec<NamedGraphEdge>,
}

struct ResolvedGraphEdge {
    destination: usize,
    range: Range<usize>,
}

#[derive(Default)]
struct PredicateBudget {
    nodes: usize,
}

impl PredicateBudget {
    fn enter(&mut self, expr: &Expr, depth: usize) -> Result<(), PolicySourceError> {
        if depth > MAX_PREDICATE_DEPTH {
            return Err(source_error(
                "predicate-depth-limit",
                expr.range.clone(),
                format!("predicate nesting depth exceeds {MAX_PREDICATE_DEPTH}"),
            ));
        }
        self.nodes += 1;
        if self.nodes > MAX_PREDICATE_NODES {
            return Err(source_error(
                "predicate-node-limit",
                expr.range.clone(),
                format!("predicate node count exceeds {MAX_PREDICATE_NODES}"),
            ));
        }
        Ok(())
    }
}

impl DecodeContext {
    const ENDPOINT: Self = Self {
        document: RqlpDocumentKind::Endpoint,
        analysis: None,
        record: PolicyRecordContext::Ordinary,
    };

    const fn policy(analysis: PolicyAnalysisKind) -> Self {
        Self {
            document: RqlpDocumentKind::Policy,
            analysis: Some(analysis),
            record: PolicyRecordContext::Ordinary,
        }
    }

    const fn with_record(self, record: PolicyRecordContext) -> Self {
        Self { record, ..self }
    }
}

struct RecordCursor<'a> {
    record: PolicyRecord,
    values: HashMap<PolicyField, &'a Expr>,
    positions: HashMap<u8, &'a Expr>,
}

impl<'a> RecordCursor<'a> {
    fn parse(
        expr: &'a Expr,
        record: PolicyRecord,
        context: DecodeContext,
    ) -> Result<Self, PolicySourceError> {
        let items = expect_record_head(expr, record)?;
        let mut values = HashMap::new();
        let mut positions = HashMap::new();
        let mut next_position = 0_u8;
        let mut index = 1;
        while index < items.len() {
            if let Some(label) = items[index]
                .as_symbol()
                .and_then(|symbol| symbol.strip_prefix(':'))
            {
                let keyword = &items[index];
                let value = items.get(index + 1).ok_or_else(|| {
                    source_error(
                        "missing-field-value",
                        keyword.range.clone(),
                        format!("field `:{label}` requires a value"),
                    )
                })?;
                let descriptor = lookup_field(record, label).ok_or_else(|| {
                    source_error(
                        "unknown-field",
                        keyword.range.clone(),
                        format!("unknown field `:{label}` for `{}`", record.label()),
                    )
                })?;
                if descriptor.placement != FieldPlacement::Keyword {
                    return Err(source_error(
                        "invalid-field-placement",
                        keyword.range.clone(),
                        format!("`:{label}` is not a keyword field of `{}`", record.label()),
                    ));
                }
                if lookup_applicable_field(
                    record,
                    label,
                    context.document,
                    context.analysis,
                    context.record,
                )
                .is_none()
                {
                    return Err(source_error(
                        "field-not-allowed",
                        keyword.range.clone(),
                        format!(
                            "field `:{label}` is not allowed for this `{}` variant",
                            record.label()
                        ),
                    ));
                }
                if values.insert(descriptor.field, value).is_some() {
                    return Err(source_error(
                        "duplicate-field",
                        keyword.range.clone(),
                        format!("duplicate field `:{label}`"),
                    ));
                }
                index += 2;
            } else {
                let descriptor = positional_field(record, next_position).ok_or_else(|| {
                    source_error(
                        "unexpected-positional-value",
                        items[index].range.clone(),
                        format!("unexpected positional value in `{}`", record.label()),
                    )
                })?;
                positions.insert(next_position, &items[index]);
                next_position += 1;
                index += 1;
                if matches!(descriptor.placement, FieldPlacement::Keyword) {
                    unreachable!("positional lookup returned a keyword field");
                }
            }
        }

        for descriptor in
            required_fields_for_record(record, context.document, context.analysis, context.record)
        {
            let present = match descriptor.placement {
                FieldPlacement::Keyword => values.contains_key(&descriptor.field),
                FieldPlacement::Positional { index } => positions.contains_key(&index),
            };
            if !present {
                return Err(source_error(
                    "missing-required-field",
                    expr.range.clone(),
                    format!(
                        "`{}` is missing required field {}",
                        record.label(),
                        descriptor.signature
                    ),
                ));
            }
        }
        Ok(Self {
            record,
            values,
            positions,
        })
    }

    fn get(&self, label: &str) -> Option<&'a Expr> {
        lookup_field(self.record, label)
            .and_then(|descriptor| self.values.get(&descriptor.field).copied())
    }

    fn required(&self, label: &str) -> &'a Expr {
        self.get(label)
            .expect("RecordCursor checked the schema-required field")
    }

    fn positional(&self, index: u8) -> Option<&'a Expr> {
        self.positions.get(&index).copied()
    }
}

fn list_head(expr: &Expr) -> Result<&str, PolicySourceError> {
    let items = expr.as_list().ok_or_else(|| {
        source_error(
            "expected-record",
            expr.range.clone(),
            "expected an S-expression record",
        )
    })?;
    let head = items.first().ok_or_else(|| {
        source_error(
            "empty-record",
            expr.range.clone(),
            "record must have a head",
        )
    })?;
    head.as_symbol().ok_or_else(|| {
        source_error(
            "invalid-record-head",
            head.range.clone(),
            "record head must be a symbol",
        )
    })
}

fn head_range(expr: &Expr) -> Range<usize> {
    expr.as_list()
        .and_then(|items| items.first())
        .map_or_else(|| expr.range.clone(), |head| head.range.clone())
}

fn expect_record_head(expr: &Expr, record: PolicyRecord) -> Result<&[Expr], PolicySourceError> {
    let head = list_head(expr)?;
    if !record.labels().contains(&head) {
        return Err(source_error(
            "wrong-record-kind",
            head_range(expr),
            format!("expected `{}`, found `{head}`", record.label()),
        ));
    }
    Ok(expr.as_list().expect("list_head proved this is a list"))
}

fn select_record(
    expr: &Expr,
    candidates: &[PolicyRecord],
    what: &str,
) -> Result<PolicyRecord, PolicySourceError> {
    let head = list_head(expr)?;
    candidates
        .iter()
        .copied()
        .find(|record| record.labels().contains(&head))
        .ok_or_else(|| {
            source_error(
                "wrong-record-kind",
                head_range(expr),
                format!(
                    "{what} must use one of the registered forms: {}",
                    candidates
                        .iter()
                        .map(|record| record.label())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        })
}

fn expect_string(expr: &Expr, what: &str, max_bytes: usize) -> Result<String, PolicySourceError> {
    let value = expr.as_string().ok_or_else(|| {
        source_error(
            "invalid-value-shape",
            expr.range.clone(),
            format!("{what} must be a string"),
        )
    })?;
    validate_text(value, max_bytes).map_err(|message| {
        source_error(
            "invalid-string",
            expr.range.clone(),
            format!("{what} {message}"),
        )
    })?;
    Ok(value.to_string())
}

fn validate_text(value: &str, max_bytes: usize) -> Result<(), String> {
    if value.len() > max_bytes {
        return Err(format!("must be at most {max_bytes} bytes"));
    }
    if value.chars().any(|ch| {
        ch.is_control()
            || matches!(
                ch,
                '\u{061c}'
                    | '\u{200e}'
                    | '\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            )
    }) {
        return Err("must not contain control or bidirectional-control characters".to_string());
    }
    Ok(())
}

fn expect_token<'a>(expr: &'a Expr, what: &str) -> Result<&'a str, PolicySourceError> {
    expr.as_symbol()
        .or_else(|| expr.as_string())
        .ok_or_else(|| {
            source_error(
                "invalid-value-shape",
                expr.range.clone(),
                format!("{what} must be a symbol or string"),
            )
        })
}

fn expect_atom(
    expr: &Expr,
    domain: AtomDomain,
    what: &str,
) -> Result<PolicyAtomValue, PolicySourceError> {
    let token = expect_token(expr, what)?;
    lookup_atom(domain, token)
        .map(|descriptor| descriptor.value)
        .ok_or_else(|| {
            source_error(
                "invalid-enum-value",
                expr.range.clone(),
                format!("invalid {what} `{token}`"),
            )
        })
}

fn expect_u32(expr: &Expr, what: &str, allow_zero: bool) -> Result<u32, PolicySourceError> {
    let value = expr.as_number().ok_or_else(|| {
        source_error(
            "invalid-value-shape",
            expr.range.clone(),
            format!("{what} must be an integer"),
        )
    })?;
    let value = u32::try_from(value).map_err(|_| {
        source_error(
            "integer-out-of-range",
            expr.range.clone(),
            format!("{what} must be at most {}", u32::MAX),
        )
    })?;
    if !allow_zero && value == 0 {
        return Err(source_error(
            "integer-out-of-range",
            expr.range.clone(),
            format!("{what} must be at least 1"),
        ));
    }
    Ok(value)
}

fn expect_usize_bounded(
    expr: &Expr,
    what: &str,
    minimum: usize,
    maximum: usize,
) -> Result<usize, PolicySourceError> {
    let value = expr.as_number().ok_or_else(|| {
        source_error(
            "invalid-value-shape",
            expr.range.clone(),
            format!("{what} must be an integer"),
        )
    })?;
    let value = usize::try_from(value).map_err(|_| {
        source_error(
            "integer-out-of-range",
            expr.range.clone(),
            format!("{what} is too large"),
        )
    })?;
    if !(minimum..=maximum).contains(&value) {
        return Err(source_error(
            "integer-out-of-range",
            expr.range.clone(),
            format!("{what} must be from {minimum} through {maximum}"),
        ));
    }
    Ok(value)
}

fn expect_vector<'a>(
    expr: &'a Expr,
    what: &str,
    min: usize,
    max: usize,
) -> Result<&'a [Expr], PolicySourceError> {
    let ExprKind::Vector(values) = &expr.kind else {
        return Err(source_error(
            "invalid-value-shape",
            expr.range.clone(),
            format!("{what} must be a vector"),
        ));
    };
    if !(min..=max).contains(&values.len()) {
        return Err(source_error(
            "collection-size",
            expr.range.clone(),
            format!("{what} must contain from {min} through {max} values"),
        ));
    }
    Ok(values)
}

fn decode_unique_values<T, F, K>(
    expr: &Expr,
    what: &str,
    min: usize,
    max: usize,
    mut decode: F,
    mut key: K,
) -> Result<Vec<T>, PolicySourceError>
where
    F: FnMut(&Expr) -> Result<T, PolicySourceError>,
    K: FnMut(&T) -> String,
{
    let values = expect_vector(expr, what, min, max)?;
    let mut decoded = Vec::with_capacity(values.len());
    let mut seen = HashSet::with_capacity(values.len());
    for value in values {
        let item = decode(value)?;
        if !seen.insert(key(&item)) {
            return Err(source_error(
                "duplicate-set-value",
                value.range.clone(),
                format!("duplicate value in {what}"),
            ));
        }
        decoded.push(item);
    }
    decoded.sort_by_key(|item| key(item));
    Ok(decoded)
}

fn parse_identifier<T>(expr: &Expr, what: &str) -> Result<T, PolicySourceError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    let token = expect_token(expr, what)?;
    token.parse().map_err(|error| {
        source_error(
            "invalid-identifier",
            expr.range.clone(),
            format!("invalid {what}: {error}"),
        )
    })
}

fn decode_help_uri(expr: &Expr) -> Result<String, PolicySourceError> {
    let uri = expect_string(expr, "help URI", MAX_DISPLAY_TEXT_BYTES)?;
    if !(uri.starts_with("https://") || uri.starts_with("http://"))
        || uri.chars().any(char::is_whitespace)
    {
        return Err(source_error(
            "invalid-help-uri",
            expr.range.clone(),
            "help URI must be an absolute HTTP or HTTPS URI",
        ));
    }
    Ok(uri)
}

fn raw_keyword_value<'a>(
    expr: &'a Expr,
    wanted: &str,
) -> Result<Option<&'a Expr>, PolicySourceError> {
    let items = expr
        .as_list()
        .ok_or_else(|| source_error("expected-record", expr.range.clone(), "expected a record"))?;
    let mut found = None;
    let mut index = 1;
    while index < items.len() {
        let Some(label) = items[index]
            .as_symbol()
            .and_then(|symbol| symbol.strip_prefix(':'))
        else {
            index += 1;
            continue;
        };
        let value = items.get(index + 1).ok_or_else(|| {
            source_error(
                "missing-field-value",
                items[index].range.clone(),
                format!("field `:{label}` requires a value"),
            )
        })?;
        if label == wanted && found.replace(value).is_some() {
            return Err(source_error(
                "duplicate-field",
                items[index].range.clone(),
                format!("duplicate field `:{wanted}`"),
            ));
        }
        index += 2;
    }
    Ok(found)
}

fn decode_string_set(
    expr: &Expr,
    what: &str,
    min: usize,
    max: usize,
) -> Result<Vec<String>, PolicySourceError> {
    decode_unique_values(
        expr,
        what,
        min,
        max,
        |value| expect_string(value, what, MAX_DISPLAY_TEXT_BYTES),
        Clone::clone,
    )
}

fn decode_id_set<T>(
    expr: &Expr,
    what: &str,
    min: usize,
    max: usize,
) -> Result<Vec<T>, PolicySourceError>
where
    T: FromStr + AsRef<str>,
    T::Err: fmt::Display,
{
    decode_unique_values(
        expr,
        what,
        min,
        max,
        |value| parse_identifier(value, what),
        |value: &T| value.as_ref().to_string(),
    )
}

fn decode_spanned_id_set<T>(
    expr: &Expr,
    what: &str,
    min: usize,
    max: usize,
) -> Result<Vec<SpannedValue<T>>, PolicySourceError>
where
    T: FromStr + AsRef<str>,
    T::Err: fmt::Display,
{
    let values = expect_vector(expr, what, min, max)?;
    let mut decoded = Vec::with_capacity(values.len());
    let mut seen = HashSet::with_capacity(values.len());
    for value_expr in values {
        let value: T = parse_identifier(value_expr, what)?;
        if !seen.insert(value.as_ref().to_string()) {
            return Err(source_error(
                "duplicate-set-value",
                value_expr.range.clone(),
                format!("duplicate value in {what}"),
            ));
        }
        decoded.push(SpannedValue {
            value,
            range: value_expr.range.clone(),
        });
    }
    decoded.sort_by(|left, right| left.value.as_ref().cmp(right.value.as_ref()));
    Ok(decoded)
}

fn decode_endpoint_role(expr: &Expr) -> Result<EndpointRole, PolicySourceError> {
    match expect_atom(expr, AtomDomain::EndpointRole, "endpoint role")? {
        PolicyAtomValue::EndpointSource => Ok(EndpointRole::Source),
        PolicyAtomValue::EndpointSink => Ok(EndpointRole::Sink),
        value => unreachable!("EndpointRole registry returned {value:?}"),
    }
}

fn decode_finding_severity(expr: &Expr) -> Result<FindingSeverity, PolicySourceError> {
    match expect_atom(expr, AtomDomain::Severity, "unscored severity")? {
        PolicyAtomValue::SeverityUnrated => Ok(FindingSeverity::Unrated),
        PolicyAtomValue::SeverityNote => Ok(FindingSeverity::Note),
        PolicyAtomValue::SeverityWarning => Ok(FindingSeverity::Warning),
        PolicyAtomValue::SeverityError => Ok(FindingSeverity::Error),
        value => unreachable!("Severity registry returned {value:?}"),
    }
}

fn decode_trust_boundary(expr: &Expr) -> Result<TaintTrustBoundary, PolicySourceError> {
    match expect_atom(expr, AtomDomain::TrustBoundary, "trust boundary")? {
        PolicyAtomValue::TrustExternal => Ok(TaintTrustBoundary::External),
        PolicyAtomValue::TrustInternal => Ok(TaintTrustBoundary::Internal),
        PolicyAtomValue::TrustSameZone => Ok(TaintTrustBoundary::SameTrustZone),
        value => unreachable!("TrustBoundary registry returned {value:?}"),
    }
}

fn decode_system_entry(expr: &Expr) -> Result<TaintSystemEntry, PolicySourceError> {
    match expect_atom(expr, AtomDomain::SystemEntry, "system entry")? {
        PolicyAtomValue::EntryNetworkStack => Ok(TaintSystemEntry::VulnerableSystemNetworkStack),
        PolicyAtomValue::EntryDownloadedArtifact => Ok(TaintSystemEntry::DownloadedArtifact),
        PolicyAtomValue::EntryLocalInput => Ok(TaintSystemEntry::LocalInput),
        PolicyAtomValue::EntryAdjacentNetwork => Ok(TaintSystemEntry::AdjacentNetwork),
        PolicyAtomValue::EntryPhysical => Ok(TaintSystemEntry::Physical),
        value => unreachable!("SystemEntry registry returned {value:?}"),
    }
}

fn decode_directory_scope(expr: &Expr) -> Result<DirectoryScope, PolicySourceError> {
    match expect_atom(expr, AtomDomain::DirectoryScope, "directory scope")? {
        PolicyAtomValue::ScopeDirect => Ok(DirectoryScope::Direct),
        PolicyAtomValue::ScopeRecursive => Ok(DirectoryScope::Recursive),
        value => unreachable!("DirectoryScope registry returned {value:?}"),
    }
}

fn decode_observation_phase(expr: &Expr) -> Result<EndpointObservationPhase, PolicySourceError> {
    match expect_atom(expr, AtomDomain::ObservationPhase, "observation phase")? {
        PolicyAtomValue::PhaseAtMatch => Ok(EndpointObservationPhase::AtMatch),
        PolicyAtomValue::PhaseBeforeCall => Ok(EndpointObservationPhase::BeforeCall),
        PolicyAtomValue::PhaseAfterNormal => Ok(EndpointObservationPhase::AfterNormalReturn),
        PolicyAtomValue::PhaseAfterExceptional => {
            Ok(EndpointObservationPhase::AfterExceptionalReturn)
        }
        value => unreachable!("ObservationPhase registry returned {value:?}"),
    }
}

enum DecodedBinding {
    MatchedValue,
    Receiver,
    ReturnValue,
    ArgumentIndex(u32),
    ArgumentName(String),
}

fn decode_binding(
    expr: &Expr,
    context: DecodeContext,
    value_shape: PolicyValueShape,
) -> Result<DecodedBinding, PolicySourceError> {
    let atom_domain = value_shape
        .atom_domain()
        .expect("binding value shapes have a registered atom domain");
    let allow_matched_value = atom_domain == AtomDomain::Port;
    if expr.as_symbol().is_some() {
        if atom_domain == AtomDomain::CallPort {
            let token = expect_token(expr, "binding")?;
            if matches!(
                lookup_atom(AtomDomain::Port, token).map(|descriptor| descriptor.value),
                Some(PolicyAtomValue::PortMatchedValue)
            ) {
                return Err(source_error(
                    "binding-not-allowed",
                    expr.range.clone(),
                    "matched-value is not allowed in this call-signature binding",
                ));
            }
        }
        return match expect_atom(expr, atom_domain, "binding")? {
            PolicyAtomValue::PortMatchedValue if allow_matched_value => {
                Ok(DecodedBinding::MatchedValue)
            }
            PolicyAtomValue::PortMatchedValue => Err(source_error(
                "binding-not-allowed",
                expr.range.clone(),
                "matched-value is not allowed in this call-signature binding",
            )),
            PolicyAtomValue::PortReceiver => Ok(DecodedBinding::Receiver),
            PolicyAtomValue::PortReturnValue => Ok(DecodedBinding::ReturnValue),
            PolicyAtomValue::CallPortReceiver => Ok(DecodedBinding::Receiver),
            PolicyAtomValue::CallPortReturnValue => Ok(DecodedBinding::ReturnValue),
            value => unreachable!("binding registry returned {value:?}"),
        };
    }
    let fields = RecordCursor::parse(expr, PolicyRecord::Argument, context)?;
    match (fields.get("index"), fields.get("name")) {
        (Some(index), None) => Ok(DecodedBinding::ArgumentIndex(expect_u32(
            index,
            "argument index",
            true,
        )?)),
        (None, Some(name)) => Ok(DecodedBinding::ArgumentName(expect_string(
            name,
            "argument name",
            MAX_HUMAN_NAME_BYTES,
        )?)),
        (None, None) => Err(source_error(
            "missing-binding-variant",
            expr.range.clone(),
            "argument requires exactly one of :index or :name",
        )),
        (Some(_), Some(name)) => Err(source_error(
            "conflicting-binding-variant",
            name.range.clone(),
            "argument :index and :name are mutually exclusive",
        )),
    }
}

fn decoded_binding_to_port(binding: DecodedBinding) -> PolicyPort {
    match binding {
        DecodedBinding::MatchedValue => PolicyPort::MatchedValue,
        DecodedBinding::Receiver => PolicyPort::Receiver,
        DecodedBinding::ReturnValue => PolicyPort::ReturnValue,
        DecodedBinding::ArgumentIndex(index) => PolicyPort::ArgumentIndex { index },
        DecodedBinding::ArgumentName(name) => PolicyPort::ArgumentName { name },
    }
}

fn decoded_binding_to_seed(binding: DecodedBinding) -> TypestateSeedBinding {
    match binding {
        DecodedBinding::MatchedValue => TypestateSeedBinding::MatchedValue,
        DecodedBinding::Receiver => TypestateSeedBinding::Receiver,
        DecodedBinding::ReturnValue => TypestateSeedBinding::ReturnValue,
        DecodedBinding::ArgumentIndex(index) => TypestateSeedBinding::ArgumentIndex { index },
        DecodedBinding::ArgumentName(name) => TypestateSeedBinding::ArgumentName { name },
    }
}

fn decoded_binding_to_call(
    binding: DecodedBinding,
    range: Range<usize>,
) -> Result<TypestateCallBinding, PolicySourceError> {
    match binding {
        DecodedBinding::MatchedValue => Err(source_error(
            "binding-not-allowed",
            range,
            "matched-value is not a valid call binding",
        )),
        DecodedBinding::Receiver => Ok(TypestateCallBinding::Receiver),
        DecodedBinding::ReturnValue => Ok(TypestateCallBinding::ReturnValue),
        DecodedBinding::ArgumentIndex(index) => Ok(TypestateCallBinding::ArgumentIndex { index }),
        DecodedBinding::ArgumentName(name) => Ok(TypestateCallBinding::ArgumentName { name }),
    }
}

fn schema_analysis_kind(analysis: PolicyAnalysisType) -> PolicyAnalysisKind {
    match analysis {
        PolicyAnalysisType::Match => PolicyAnalysisKind::Match,
        PolicyAnalysisType::Taint => PolicyAnalysisKind::Taint,
        PolicyAnalysisType::Typestate => PolicyAnalysisKind::Typestate,
    }
}

fn decode_analysis_type(expr: &Expr) -> Result<PolicyAnalysisType, PolicySourceError> {
    match expect_atom(expr, AtomDomain::AnalysisType, "analysis type")? {
        PolicyAtomValue::AnalysisMatch => Ok(PolicyAnalysisType::Match),
        PolicyAtomValue::AnalysisTaint => Ok(PolicyAnalysisType::Taint),
        PolicyAtomValue::AnalysisTypestate => Ok(PolicyAnalysisType::Typestate),
        value => unreachable!("AnalysisType registry returned {value:?}"),
    }
}

fn decode_cvss_scope(expr: &Expr) -> Result<CvssEvidenceScope, PolicySourceError> {
    match expect_atom(expr, AtomDomain::CvssScope, "CVSS evidence scope")? {
        PolicyAtomValue::CvssVulnerableSystem => Ok(CvssEvidenceScope::System {
            system: CvssSystemScope::VulnerableSystem,
        }),
        PolicyAtomValue::CvssSubsequentSystem => Ok(CvssEvidenceScope::System {
            system: CvssSystemScope::SubsequentSystem,
        }),
        PolicyAtomValue::CvssGlobal => Ok(CvssEvidenceScope::Global),
        value => unreachable!("CvssScope registry returned {value:?}"),
    }
}

fn cvss_metric_from_schema(metric: CvssBaseMetricSchema) -> CvssBaseMetric {
    match metric {
        CvssBaseMetricSchema::Av => CvssBaseMetric::Av,
        CvssBaseMetricSchema::Ac => CvssBaseMetric::Ac,
        CvssBaseMetricSchema::At => CvssBaseMetric::At,
        CvssBaseMetricSchema::Pr => CvssBaseMetric::Pr,
        CvssBaseMetricSchema::Ui => CvssBaseMetric::Ui,
        CvssBaseMetricSchema::Vc => CvssBaseMetric::Vc,
        CvssBaseMetricSchema::Vi => CvssBaseMetric::Vi,
        CvssBaseMetricSchema::Va => CvssBaseMetric::Va,
        CvssBaseMetricSchema::Sc => CvssBaseMetric::Sc,
        CvssBaseMetricSchema::Si => CvssBaseMetric::Si,
        CvssBaseMetricSchema::Sa => CvssBaseMetric::Sa,
    }
}

fn catalog_key(reference: &CatalogRef) -> String {
    format!("{}:{}", reference.name, reference.version)
}

fn match_set_key(reference: &MatchEndpointSetRef) -> String {
    match reference {
        MatchEndpointSetRef::Directory { reference } => format!(
            "directory:{}:{:?}:{:?}:{}",
            reference.path,
            reference.scope,
            reference.categories,
            reference
                .manifest_sha256
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default()
        ),
        MatchEndpointSetRef::Exact { endpoint_ids } => format!(
            "exact:{}",
            endpoint_ids
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn endpoint_ref_key(reference: &EndpointRef) -> String {
    match reference {
        EndpointRef::Local { entry_id } => format!("local:{entry_id}"),
        EndpointRef::Catalog { catalog, entry_id } => {
            format!("catalog:{}:{entry_id}", catalog_key(catalog))
        }
        EndpointRef::MatchEndpoint { endpoint_id } => format!("match:{endpoint_id}"),
    }
}

fn taxonomy_key(classification: &TaxonomyClassificationSpec) -> String {
    format!("{}:{}", classification.taxonomy, classification.identifier)
}

fn evidence_ref_key(reference: &PolicyEvidenceRef) -> String {
    match reference {
        PolicyEvidenceRef::PolicySelf => "policy:self".to_string(),
        PolicyEvidenceRef::Endpoint { endpoint } => {
            format!("endpoint:{}", endpoint_ref_key(endpoint))
        }
        PolicyEvidenceRef::Selector { path } => format!("selector:{path}"),
    }
}

fn json_pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn validate_named_graph(values: &[NamedGraphNode], what: &str) -> Result<(), PolicySourceError> {
    let indices = values
        .iter()
        .enumerate()
        .map(|(index, value)| (value.id.clone(), index))
        .collect::<HashMap<_, _>>();
    let mut edges = (0..values.len()).map(|_| Vec::new()).collect::<Vec<_>>();
    for (source, value) in values.iter().enumerate() {
        for target in &value.edges {
            let Some(&destination) = indices.get(&target.target) else {
                return Err(source_error(
                    "unknown-supersedes-target",
                    target.range.clone(),
                    format!(
                        "{what} `{}` supersedes unknown ID `{}`",
                        value.id, target.target
                    ),
                ));
            };
            if source == destination {
                return Err(source_error(
                    "self-supersedes",
                    target.range.clone(),
                    format!("{what} `{}` cannot supersede itself", value.id),
                ));
            }
            edges[source].push(ResolvedGraphEdge {
                destination,
                range: target.range.clone(),
            });
        }
    }

    let mut colors = vec![0_u8; values.len()];
    for root in 0..values.len() {
        if colors[root] != 0 {
            continue;
        }
        colors[root] = 1;
        let mut stack = vec![(root, 0_usize)];
        while let Some((source, next_edge)) = stack.last_mut() {
            if *next_edge == edges[*source].len() {
                colors[*source] = 2;
                stack.pop();
                continue;
            }
            let edge = &edges[*source][*next_edge];
            *next_edge += 1;
            match colors[edge.destination] {
                0 => {
                    colors[edge.destination] = 1;
                    stack.push((edge.destination, 0));
                }
                1 => {
                    return Err(source_error(
                        "supersedes-cycle",
                        edge.range.clone(),
                        format!(
                            "{what} supersedes graph contains a cycle through `{}`",
                            values[edge.destination].id
                        ),
                    ));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema_version::SchemaVersionOrigin;

    fn parse(source: &str) -> Result<ParsedRqlpDocument, PolicySourceError> {
        parse_rqlp_source(source, PolicySourceIdentity::new("test.rqlp"))
    }

    fn taint_policy(extra: &str) -> String {
        format!(
            r#"(policy :id "test.taint" :name "Taint" :message "M" :severity warning
                :analysis (analysis :type taint :mode may
                  :sources (endpoint-set) :sinks (endpoint-set) {extra}))"#
        )
    }

    fn assert_error_token(source: &str, code: &str, token: &str) {
        let error = parse(source).unwrap_err().diagnostic;
        assert_eq!(error.code, code);
        assert_eq!(&source[error.range], token);
    }

    #[test]
    fn decodes_exact_match_policy_and_infers_compatible_versions() {
        let parsed = parse(
            r#"(policy
              :id "bifrost.security.dynamic-eval"
              :name "No dynamic evaluation"
              :message "Dynamic evaluation is forbidden"
              :severity warning
              :analysis
                (analysis :type match :selector
                  (rql (language python (call :callee (name "eval"))))))"#,
        )
        .unwrap();
        assert_eq!(
            parsed.schema_resolution.origin,
            SchemaVersionOrigin::ImplicitCompatible
        );
        let RqlpDocument::Policy { definition } = parsed.document else {
            panic!("expected policy")
        };
        let PolicyAnalysis::Match { spec } = definition.analysis else {
            panic!("expected match policy")
        };
        let PolicySelector::Inline { schema, query } = spec.selector else {
            panic!("expected inline selector")
        };
        assert_eq!(schema.version, 2);
        assert_eq!(schema.origin, SchemaVersionOrigin::ImplicitCompatible);
        assert_eq!(query.schema_version, 2);
    }

    #[test]
    fn decodes_diagnostic_neutral_endpoint() {
        let parsed = parse(
            r#"(endpoint
              :id "bifrost.sources.http-request-parameter"
              :name "HTTP request parameter"
              :display-name "User-controlled I/O"
              :role source
              :categories [input.user-controlled io.external]
              :selector (rql (call :callee (name "requestParameter")))
              :binding return-value
              :taint
                (source-semantics
                  :labels [attacker-controlled]
                  :evidence (evidence :trust-boundary external))
              :supersedes [])"#,
        )
        .unwrap();
        let RqlpDocument::Endpoint { definition } = parsed.document else {
            panic!("expected endpoint")
        };
        assert_eq!(definition.role, EndpointRole::Source);
        assert_eq!(definition.categories.len(), 2);
        assert!(matches!(
            definition.taint,
            Some(EndpointTaintSemantics::Source { .. })
        ));
    }

    #[test]
    fn decodes_set_oriented_taint_policy_and_specific_combination() {
        let parsed = parse(
            r#"(policy
              :schema-version 1
              :id "bifrost.security.untrusted-sql"
              :name "Untrusted data reaches SQL"
              :message (generated-message :relation can-reach)
              :severity warning
              :analysis
                (analysis
                  :type taint
                  :mode may
                  :sources
                    (endpoint-set
                      :include-matches [
                        (match-directory
                          :path "policies/endpoints"
                          :scope recursive
                          :categories (all [input.user-controlled]))]
                      :entries [
                        (source
                          :id "request"
                          :display-name "User input"
                          :categories [input.user-controlled]
                          :selector (rql (call :callee (name "request")))
                          :bind return-value
                          :labels [attacker-controlled])])
                  :sinks
                    (endpoint-set
                      :entries [
                        (sink
                          :id "sql"
                          :display-name "SQL structure"
                          :categories [sql.structure]
                          :selector (rql (call :callee (name "execute")))
                          :dangerous-operand (argument :index 0)
                          :accepts [attacker-controlled])])
                  :finding-combinations [
                    (finding-combination
                      :id "input-to-sql"
                      :source (categories :all [input.user-controlled])
                      :sink (categories :all [sql.structure])
                      :message "User input can alter SQL structure")]))"#,
        )
        .unwrap();
        let RqlpDocument::Policy { definition } = parsed.document else {
            panic!("expected policy")
        };
        let PolicyAnalysis::Taint { spec } = definition.analysis else {
            panic!("expected taint policy")
        };
        assert_eq!(spec.sources.entries.len(), 1);
        assert_eq!(spec.sources.include_matches.len(), 1);
        assert_eq!(spec.sinks.entries.len(), 1);
        assert_eq!(spec.finding_combinations.len(), 1);
    }

    #[test]
    fn decodes_typestate_events_transitions_and_implicit_terminal() {
        let parsed = parse(
            r#"(policy
              :id "bifrost.test.resource-lifecycle"
              :name "Resource lifecycle"
              :message "Resource is not closed"
              :severity error
              :analysis
                (analysis
                  :type typestate
                  :mode may
                  :subjects (subject-set :entries [])
                  :uncertainty
                    (uncertainty :unknown-call inconclusive :escape inconclusive)
                  :automaton
                    (automaton
                      :states [open closed error]
                      :initial open
                      :accepting-states [closed]
                      :error-states [error]
                      :events [
                        (event
                          :id close
                          :matches
                            (match-directory
                              :path "policies/endpoints/resources"
                              :scope recursive
                              :role sink
                              :phase after-normal-return
                              :categories (all [resource.close])))]
                      :transitions [
                        (transition :from open :on close :to closed)]
                      :terminal-expectations [
                        (terminal-expectation
                          :id normal-exit-closed
                          :on (normal-procedure-exit :scope analysis-root)
                          :expected-states [closed])])))"#,
        )
        .unwrap();
        let RqlpDocument::Policy { definition } = parsed.document else {
            panic!("expected policy")
        };
        let PolicyAnalysis::Typestate { spec } = definition.analysis else {
            panic!("expected typestate policy")
        };
        assert_eq!(spec.automaton.events.len(), 1);
        assert_eq!(spec.automaton.transitions.len(), 1);
        assert_eq!(spec.automaton.terminal_expectations.len(), 1);
    }

    #[test]
    fn rejects_unknown_duplicate_variant_fields_and_output_controls() {
        let unsupported_before_unknown =
            parse(r#"(policy :schema-version 999 :unknown true)"#).unwrap_err();
        assert_eq!(
            unsupported_before_unknown.diagnostic.code,
            "unsupported-policy-schema-version"
        );

        let unknown = parse(
            r#"(policy :id "p" :name "P" :message "M" :severity warning
                :bogus true
                :analysis (analysis :type match :selector (rql (call))))"#,
        )
        .unwrap_err();
        assert_eq!(unknown.diagnostic.code, "unknown-field");

        let duplicate = parse(
            r#"(policy :id "p" :id "q" :name "P" :message "M" :severity warning
                :analysis (analysis :type match :selector (rql (call))))"#,
        )
        .unwrap_err();
        assert_eq!(duplicate.diagnostic.code, "duplicate-field");

        let wrong_variant = parse(
            r#"(policy :id "p" :name "P" :message "M" :severity warning
                :analysis (analysis :type match :mode may :selector (rql (call))))"#,
        )
        .unwrap_err();
        assert_eq!(wrong_variant.diagnostic.code, "field-not-allowed");

        let output_control = parse(
            r#"(policy :id "p" :name "P" :message "M" :severity warning
                :analysis (analysis :type match :selector (rql (limit 1 (call)))))"#,
        )
        .unwrap_err();
        assert_eq!(
            output_control.diagnostic.code,
            "query-output-control-not-allowed"
        );
    }

    #[test]
    fn keeps_file_selector_typed_and_unresolved_without_io() {
        let parsed = parse(
            r#"(policy :id "p" :name "P" :message "M" :severity warning
                :analysis
                  (analysis :type match :selector
                    (rql-file :schema-version 2 :path "queries/eval.rql")))"#,
        )
        .unwrap();
        assert_eq!(parsed.unresolved_file_selectors.len(), 1);
        assert_eq!(
            parsed.unresolved_file_selectors[0].workspace_path.as_str(),
            "queries/eval.rql"
        );
    }

    #[test]
    fn decodes_classification_refinement_and_legal_cvss_rule() {
        let parsed = parse(
            r#"(policy
              :id "bifrost.security.network-input"
              :name "Network input"
              :message "Network input reaches a sensitive operation"
              :severity (cvss-severity :when-unscored unrated)
              :analysis
                (analysis :type match :selector (rql (call)))
              :classification
                (classification
                  :fallback
                    (classification-id :taxonomy "Bifrost" :id "NETWORK-INPUT")
                  :refinements [
                    (refinement
                      :when (analysis-type :is match)
                      :add [(classification-id :taxonomy "CWE" :id "CWE-20")])]
                  :cvss
                    (cvss
                      :version "4.0"
                      :emit when-base-complete
                      :metric-rules [
                        (metric
                          :name AV
                          :value N
                          :when (analysis-type :is match)
                          :basis policy-assertion
                          :scope vulnerable-system
                          :evidence-refs [policy:self]
                          :rationale "Input reaches the vulnerable system over the network")])))"#,
        )
        .unwrap();
        let RqlpDocument::Policy { definition } = parsed.document else {
            panic!("expected policy")
        };
        let classification = definition.classification.unwrap();
        assert_eq!(classification.refinements.len(), 1);
        assert_eq!(classification.cvss.unwrap().metric_rules.len(), 1);
    }

    #[test]
    fn rejects_policy_wide_duplicate_local_taint_ids_at_the_second_id() {
        let source = r#"(policy :id "test.duplicate" :name "Duplicate" :message "M" :severity warning
          :analysis (analysis :type taint :mode may
            :sources (endpoint-set :entries [
              (source :id shared-entry :display-name "Input" :categories [input]
                :selector (rql (call)) :bind return-value :labels [untrusted])])
            :sinks (endpoint-set :entries [
              (sink :id shared-entry :display-name "Sink" :categories [sink]
                :selector (rql (call)) :dangerous-operand matched-value
                :accepts [untrusted])])))"#;
        let error = parse(source).unwrap_err().diagnostic;
        assert_eq!(error.code, "duplicate-entry-id");
        assert_eq!(&source[error.range.clone()], "shared-entry");
        assert_eq!(error.range.start, source.rfind("shared-entry").unwrap());
    }

    #[test]
    fn validates_classification_and_precedence_references_at_exact_tokens() {
        let classification_without_fallback = taint_policy(
            r#":finding-combinations [(finding-combination :id specific
              :source (categories :all [input]) :sink (categories :all [sink])
              :message "M"
              :add-classifications [(classification-id :taxonomy "CWE" :id "CWE-20")])]"#,
        );
        let error = parse(&classification_without_fallback)
            .unwrap_err()
            .diagnostic;
        assert_eq!(error.code, "combination-classification-without-fallback");
        assert_eq!(
            &classification_without_fallback[error.range],
            r#"[(classification-id :taxonomy "CWE" :id "CWE-20")]"#
        );

        let missing_combination = r#"(policy :id "test.reference" :name "Reference" :message "M"
          :severity warning :analysis (analysis :type taint :mode may
            :sources (endpoint-set) :sinks (endpoint-set))
          :classification (classification
            :fallback (classification-id :taxonomy "test" :id "fallback")
            :refinements [(refinement
              :when (finding-combination :id missing-combination)
              :add [(classification-id :taxonomy "test" :id "specific")])]))"#;
        assert_error_token(
            missing_combination,
            "unknown-finding-combination",
            "missing-combination",
        );

        let missing_expectation = r#"(policy :id "test.expectation" :name "Expectation"
          :message "M" :severity warning
          :analysis (analysis :type typestate :mode may :subjects (subject-set)
            :uncertainty (uncertainty :unknown-call inconclusive :escape inconclusive)
            :automaton (automaton :states [open closed error] :initial open
              :accepting-states [closed] :error-states [error]
              :events [(event :id finish :on (normal-procedure-exit :scope analysis-root))]
              :transitions [(transition :from open :on finish :to closed)]))
          :classification (classification
            :fallback (classification-id :taxonomy "test" :id "fallback")
            :refinements [(refinement
              :when (typestate-expectation :id missing-expectation)
              :add [(classification-id :taxonomy "test" :id "specific")])]))"#;
        assert_error_token(
            missing_expectation,
            "unknown-typestate-expectation",
            "missing-expectation",
        );

        let unknown_edge = taint_policy(
            r#":finding-combinations [(finding-combination :id broad
              :source (categories :all [input]) :sink (categories :all [sink])
              :message "M" :supersedes [missing-rule])]"#,
        );
        assert_error_token(&unknown_edge, "unknown-supersedes-target", "missing-rule");

        let self_edge = taint_policy(
            r#":finding-combinations [(finding-combination :id self-rule
              :source (categories :all [input]) :sink (categories :all [sink])
              :message "M" :supersedes [self-rule])]"#,
        );
        let error = parse(&self_edge).unwrap_err().diagnostic;
        assert_eq!(error.code, "self-supersedes");
        assert_eq!(&self_edge[error.range.clone()], "self-rule");
        assert_eq!(error.range.start, self_edge.rfind("self-rule").unwrap());

        let cycle = taint_policy(
            r#":finding-combinations [
              (finding-combination :id alpha :source (categories :all [input])
                :sink (categories :all [sink]) :message "A" :supersedes [beta])
              (finding-combination :id beta :source (categories :all [input])
                :sink (categories :all [sink]) :message "B" :supersedes [alpha])]"#,
        );
        let error = parse(&cycle).unwrap_err().diagnostic;
        assert_eq!(error.code, "supersedes-cycle");
        assert_eq!(&cycle[error.range.clone()], "alpha");
        assert_eq!(error.range.start, cycle.rfind("alpha").unwrap());
    }

    #[test]
    fn state_and_call_binding_errors_select_the_exact_token() {
        let unknown_state = r#"(policy :id "test.state" :name "State" :message "M" :severity warning
          :analysis (analysis :type typestate :mode may :subjects (subject-set)
            :uncertainty (uncertainty :unknown-call inconclusive :escape inconclusive)
            :automaton (automaton :states [open closed error] :initial open
              :accepting-states [missing-state] :error-states [error]
              :events [(event :id finish :on (normal-procedure-exit :scope analysis-root))]
              :transitions [(transition :from open :on finish :to closed)])))"#;
        assert_error_token(unknown_state, "unknown-typestate-state", "missing-state");

        let invalid_binding = r#"(policy :id "test.binding" :name "Binding" :message "M" :severity warning
          :analysis (analysis :type typestate :mode may :subjects (subject-set)
            :uncertainty (uncertainty :unknown-call inconclusive :escape inconclusive)
            :automaton (automaton :states [open closed error] :initial open
              :accepting-states [closed] :error-states [error]
              :events [(event :id finish :calls (calls :selector (rql (call))
                :subject matched-value :phase before-call))]
              :transitions [(transition :from open :on finish :to closed)])))"#;
        assert_error_token(invalid_binding, "binding-not-allowed", "matched-value");
    }

    #[test]
    fn rejects_structurally_duplicate_transfers_predicates_and_metric_rules() {
        let duplicate_transfer = taint_policy(
            r#":external-models (endpoint-set :entries [(external-model :id copy
              :selector (rql (call)) :transfers [
                (transfer :from receiver :to return-value :labels [secret] :effect propagate)
                (transfer :from receiver :to return-value :labels [secret] :effect propagate)])])"#,
        );
        let error = parse(&duplicate_transfer).unwrap_err().diagnostic;
        assert_eq!(error.code, "duplicate-set-value");
        assert!(duplicate_transfer[error.range].starts_with("(transfer"));

        let duplicate_predicate = r#"(policy :id "test.predicates" :name "Predicates" :message "M" :severity warning
          :analysis (analysis :type match :selector (rql (call)))
          :classification (classification
            :fallback (classification-id :taxonomy "test" :id "fallback")
            :refinements [(refinement :when (all [
              (analysis-type :is match) (analysis-type :is match)])
              :add [(classification-id :taxonomy "test" :id "specific")])]))"#;
        let error = parse(duplicate_predicate).unwrap_err().diagnostic;
        assert_eq!(error.code, "duplicate-set-value");
        assert_eq!(
            &duplicate_predicate[error.range],
            "(analysis-type :is match)"
        );

        let metric = r#"(metric :name AV :value N :when (analysis-type :is match)
          :basis policy-assertion :scope vulnerable-system
          :evidence-refs [policy:self] :rationale "Network")"#;
        let duplicate_metrics = format!(
            r#"(policy :id "test.metrics" :name "Metrics" :message "M" :severity warning
              :analysis (analysis :type match :selector (rql (call)))
              :classification (classification
                :fallback (classification-id :taxonomy "test" :id "fallback")
                :cvss (cvss :version "4.0" :emit when-base-complete
                  :metric-rules [{metric} {metric}])))"#
        );
        let error = parse(&duplicate_metrics).unwrap_err().diagnostic;
        assert_eq!(error.code, "duplicate-set-value");
        assert!(duplicate_metrics[error.range].starts_with("(metric"));
    }

    #[test]
    fn enforces_source_and_syntax_tree_limits() {
        let oversized = " ".repeat(MAX_RQLP_SOURCE_BYTES + 1);
        assert_eq!(
            parse(&oversized).unwrap_err().diagnostic.code,
            "source-too-large"
        );

        let many_nodes = format!(
            "(policy {})",
            (0..MAX_RQLP_SEXP_NODES)
                .map(|_| ":x 1")
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert!(matches!(
            parse(&many_nodes).unwrap_err().diagnostic.code,
            "invalid-s-expression"
        ));
    }

    #[test]
    fn source_validation_caps_recovered_diagnostics() {
        let unknown_fields = (0..MAX_RQLP_SOURCE_DIAGNOSTICS + 8)
            .map(|index| format!(":unknown-{index} {index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let source = format!("(policy {unknown_fields})");

        let diagnostics = validate_rqlp_source(&source);

        assert_eq!(diagnostics.len(), MAX_RQLP_SOURCE_DIAGNOSTICS);
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code == "unknown-field")
        );
    }

    #[test]
    fn schema_help_distinguishes_inferred_pinned_inline_and_deferred_versions() {
        let omitted_policy = r#"(policy :id "p")"#;
        let help = rqlp_source_help_at(omitted_policy, omitted_policy.find("policy").unwrap())
            .expect("policy head help");
        assert!(help.description.contains(":schema-version` is omitted"));
        assert!(help.description.contains("currently `1`"));
        assert!(help.description.contains("`:schema-version 1`"));

        let pinned_endpoint = r#"(endpoint :schema-version 1 :id "e")"#;
        let help = rqlp_source_help_at(
            pinned_endpoint,
            pinned_endpoint.find(":schema-version").unwrap(),
        )
        .expect("endpoint schema field help");
        assert!(
            help.description
                .contains("explicitly pins policy schema version `1`")
        );

        let inline = r#"(policy :analysis (analysis :selector (rql (call))))"#;
        let rql_offset = inline.find("(rql").unwrap() + 1;
        let help = rqlp_source_help_at(inline, rql_offset).expect("inline RQL help");
        assert!(help.description.contains("inline RQL selector"));
        assert!(help.description.contains("currently `2`"));

        let deferred =
            r#"(policy :analysis (analysis :selector (rql-file :path "queries/q.rql")))"#;
        let rql_file_offset = deferred.find("rql-file").unwrap();
        let help = rqlp_source_help_at(deferred, rql_file_offset).expect("deferred RQL help");
        assert!(
            help.description
                .contains("resolved by the workspace loader")
        );
        assert!(help.description.contains("source-only validation"));

        let pinned_inline =
            r#"(policy :analysis (analysis :selector (rql :schema-version 2 (call))))"#;
        let rql_offset = pinned_inline.find("(rql").unwrap() + 1;
        let help = rqlp_source_help_at(pinned_inline, rql_offset).expect("pinned RQL help");
        assert!(
            help.description
                .contains("explicitly pins RQL schema version `2`")
        );
    }

    #[test]
    fn schema_version_completion_uses_registry_versions_and_exact_partial_range() {
        let policy = r#"(policy :id "😀" :sch"#;
        let completion = rqlp_source_completion_at(policy, policy.len())
            .expect("policy schema-version completion");
        assert_eq!(&policy[completion.range], ":sch");
        assert_eq!(completion.label, ":schema-version");
        assert_eq!(completion.new_text, ":schema-version 1");

        let mid_token = "(policy :schema)";
        let cursor = mid_token.find(":schema").unwrap() + ":sch".len();
        let completion = rqlp_source_completion_at(mid_token, cursor)
            .expect("mid-token policy schema-version completion");
        assert_eq!(&mid_token[completion.range], ":schema");
        assert_eq!(completion.new_text, ":schema-version 1");

        let inline = "(policy :analysis (analysis :selector (rql ";
        let completion = rqlp_source_completion_at(inline, inline.len())
            .expect("nested RQL schema-version completion");
        assert_eq!(completion.range, inline.len()..inline.len());
        assert_eq!(completion.new_text, ":schema-version 2");

        let explicit = "(policy :schema-version 1 ";
        assert!(rqlp_source_completion_at(explicit, explicit.len()).is_none());

        let inside_query = "(policy :analysis (analysis :selector (rql (call ";
        assert!(rqlp_source_completion_at(inside_query, inside_query.len()).is_none());
    }
}
