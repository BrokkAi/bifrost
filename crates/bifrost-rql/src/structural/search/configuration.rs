//! Authored configuration-document facts as a first-class query domain.
//!
//! Configuration files are inputs, not language-analyzed files: the seed
//! enumerates the project's whole file listing through the project content
//! boundary, classifies each path with the canonical format registry, and
//! ingests adapter-supported documents on demand. A document whose adapter is
//! missing, whose source is unreadable, or whose syntax only partly recovers
//! contributes a typed incomplete diagnostic and never presents its surviving
//! rows as the whole answer.

use super::xml_relations::{
    has_xml_relation_filter, matches_xml_relations, xml_reference_coverage,
};
use super::*;
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::query::{
    ConfigurationCompletenessFilter, ConfigurationFactsFilter, ConfigurationFactsSeed,
    ConfigurationNodeKindFilter, ConfigurationRouteFilter, ConfigurationRouteSegmentFilter,
};
use brokk_bifrost_analysis::analyzer::configuration::{
    ConfigurationIngestionError, ConfigurationIngestionOutcome, ConfigurationNumber,
    ConfigurationNumberToken, decoded_hocon_scalar_value, decoded_json_scalar_value,
    decoded_properties_scalar_value, decoded_toml_scalar_value, decoded_xml_scalar_value,
    decoded_yaml_scalar_value, ingest_configuration_document, parsed_scalar_number,
};
use brokk_bifrost_analysis::analyzer::workspace_authority::{CaptureScopedMemo, memo_attribution};
use brokk_bifrost_core::analyzer::configuration::{
    ConfigurationCompleteness, ConfigurationDocumentFacts, ConfigurationFact, ConfigurationFactId,
    ConfigurationFormat, ConfigurationNodeKind, ConfigurationRouteSelector,
    ConfigurationValueProvenance,
};

/// One document snapshot travels with every row derived from it, so member
/// and value rows share the exact facts (and the exact source text) without
/// re-reading the file per row.
#[derive(Debug, Clone)]
pub(super) struct ConfigurationFactValue {
    pub(super) file: ProjectFile,
    pub(super) document: Arc<ConfigurationDocumentFacts>,
    pub(super) source: Arc<str>,
    /// Index into [`ConfigurationDocumentFacts::facts`].
    pub(super) index: usize,
}

impl ConfigurationFactValue {
    pub(super) fn fact(&self) -> &ConfigurationFact {
        self.document
            .fact(
                ConfigurationFactId::new(self.index)
                    .expect("configuration fact values index the document arena"),
            )
            .expect("configuration fact values index the document arena")
    }

    pub(super) fn format(&self) -> crate::query::domain::ConfigurationFormat {
        self.document.format().into()
    }

    /// The document-scoped stable id the core model derives from format, node
    /// kind, and route. Unrelated sibling edits cannot move it.
    pub(super) fn fact_id(&self) -> String {
        self.fact().stable_id(self.document.format()).to_string()
    }

    pub(super) fn parent_id(&self) -> Option<String> {
        let parent = self.fact().parent()?;
        Some(
            self.document
                .fact(parent)
                .expect("configuration fact parents exist in the arena")
                .stable_id(self.document.format())
                .to_string(),
        )
    }

    pub(super) fn member_value_id(&self) -> Option<String> {
        let ConfigurationNodeKind::Member { value, .. } = self.fact().kind() else {
            return None;
        };
        let value = (*value)?;
        Some(
            self.document
                .fact(value)
                .expect("configuration member values exist in the arena")
                .stable_id(self.document.format())
                .to_string(),
        )
    }

    /// Decode the authored scalar represented by this row. Member rows expose
    /// the value of their scalar child; scalar rows expose themselves. Each
    /// format-specific decoder runs only after the configuration grammar has
    /// selected the scalar fact and its exact evidence range.
    pub(super) fn scalar_value(&self) -> ScalarValue {
        let Some(scalar_id) = self.scalar_id() else {
            return ScalarValue::Absent;
        };
        let decoded = match self.document.format() {
            ConfigurationFormat::Json => {
                decoded_json_scalar_value(&self.document, &self.source, scalar_id)
            }
            ConfigurationFormat::Yaml => {
                decoded_yaml_scalar_value(&self.document, &self.source, scalar_id)
            }
            ConfigurationFormat::Toml => {
                decoded_toml_scalar_value(&self.document, &self.source, scalar_id)
            }
            ConfigurationFormat::Xml => {
                decoded_xml_scalar_value(&self.document, &self.source, scalar_id)
            }
            ConfigurationFormat::Properties => {
                decoded_properties_scalar_value(&self.document, &self.source, scalar_id)
            }
            ConfigurationFormat::Hocon => {
                decoded_hocon_scalar_value(&self.document, &self.source, scalar_id)
            }
        };
        decoded.map_or(ScalarValue::Undecodable, ScalarValue::Decoded)
    }

    /// The scalar fact this row decodes: a scalar row is its own scalar, a
    /// member row is its value's scalar (or an XML element's text header).
    fn scalar_id(&self) -> Option<ConfigurationFactId> {
        match self.fact().kind() {
            ConfigurationNodeKind::Scalar { .. } => ConfigurationFactId::new(self.index),
            ConfigurationNodeKind::Member {
                value: Some(value), ..
            } => match self.document.fact(*value).map(ConfigurationFact::kind) {
                Some(ConfigurationNodeKind::Scalar { .. }) => Some(*value),
                Some(ConfigurationNodeKind::Section {
                    header: Some(header),
                    ..
                }) => Some(*header),
                _ => None,
            },
            _ => None,
        }
    }

    /// The number this row's scalar denotes, given its decoded text: the
    /// number the format's parser reports (TOML `0x400` and `1_000`, JSON and
    /// YAML numbers), else the number a decimal spelling in the text denotes
    /// (a quoted `"-2"`, XML text).
    pub(super) fn scalar_number(&self, text: &str) -> ConfigurationNumberToken {
        let Some(scalar_id) = self.scalar_id() else {
            return ConfigurationNumberToken::NotDecimal;
        };
        match parsed_scalar_number(&self.document, &self.source, scalar_id) {
            ConfigurationNumberToken::NotDecimal => ConfigurationNumber::read(text),
            read => read,
        }
    }

    /// The workspace-scoped row id: one file spelling plus the document-scoped
    /// stable id, length-delimited so no pair can alias another.
    pub(super) fn id(&self) -> String {
        let mut digest = LengthDelimitedDigest::new(CONFIGURATION_FACT_ID_DOMAIN);
        digest.push(rel_path_string(&self.file).as_bytes());
        digest.push(self.fact().stable_id(self.document.format()).as_bytes());
        digest.finish().to_string()
    }

    pub(super) fn key(&self) -> ConfigurationFactKey {
        ConfigurationFactKey {
            file: self.file.clone(),
            fact_index: self.index,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    /// Canonical route rendering: a JSON array whose entries are key texts
    /// (with a `#<occurrence>` suffix only on duplicate occurrences) and
    /// zero-based array indexes. The `occurrence` field carries the exact
    /// number; this string is a rendering, never the identity.
    pub(super) fn route(&self) -> String {
        let mut rendered = String::from("[");
        for (position, segment) in self.fact().route().segments().iter().enumerate() {
            if position > 0 {
                rendered.push(',');
            }
            match segment.selector() {
                ConfigurationRouteSelector::Key { name, occurrence } => {
                    rendered.push_str(
                        &serde_json::to_string(&display_key_name(name, *occurrence))
                            .expect("a route segment renders as JSON"),
                    );
                }
                ConfigurationRouteSelector::Index(index) => {
                    rendered.push_str(&index.to_string());
                }
            }
        }
        rendered.push(']');
        rendered
    }

    pub(super) fn completeness(&self) -> ConfigurationCompletenessFilter {
        match self.document.completeness() {
            ConfigurationCompleteness::Complete => ConfigurationCompletenessFilter::Complete,
            ConfigurationCompleteness::Incomplete { .. } => {
                ConfigurationCompletenessFilter::Incomplete
            }
        }
    }
}

pub(super) enum ScalarValue {
    Absent,
    Decoded(String),
    Undecodable,
}

impl ScalarValue {
    pub(super) fn decoded(self) -> Option<String> {
        match self {
            Self::Decoded(value) => Some(value),
            Self::Absent | Self::Undecodable => None,
        }
    }
}

fn display_key_name(name: &str, occurrence: usize) -> String {
    if occurrence > 1 {
        format!("{name}#{occurrence}")
    } else {
        name.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ConfigurationFactKey {
    pub(super) file: ProjectFile,
    pub(super) fact_index: usize,
}

const CONFIGURATION_FACT_ID_DOMAIN: &[u8] = b"bifrost.code_query.configuration_fact.v1";

/// The maximum document one ingestion reads. A document beyond this bound is
/// a typed budget stop, never a silent skip.
pub(super) const MAX_CONFIGURATION_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;

/// One ingested document snapshot, memoized per request. `None` means the
/// document produced no fact arena (unsupported, unreadable, or entirely
/// unparseable). `diagnostics` are the incomplete diagnostics its ingest
/// reported; every replay reports them again, because a retried branch
/// replaces the diagnostics of its first attempt.
#[derive(Clone)]
pub(super) struct ConfigurationDocumentSnapshot {
    document: Option<(Arc<ConfigurationDocumentFacts>, Arc<str>)>,
    diagnostics: Arc<[CodeQueryDiagnostic]>,
}

/// The ingestion state of one document in the current request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConfigurationDocumentIngestion {
    /// No configuration input of this request read the document: it is not in
    /// the workspace listing, or the input stopped before reaching it.
    NotIngested,
    /// The document was read but produced no fact arena.
    NoFacts,
    /// The document's facts come from a partly recovered parse.
    Recovered,
    Complete,
}

/// Per-request memo of ingested configuration documents, so one file
/// ingests once per execution.
#[derive(Default)]
pub(super) struct ConfigurationFactsTraversalCache {
    documents: CaptureScopedMemo<HashMap<ProjectFile, ConfigurationDocumentSnapshot>>,
}

/// Report each incomplete diagnostic once per seed execution. What was
/// reported belongs to the attempt, not to the request: a retried branch runs
/// the seed again with a new set, and its gaps must appear again.
fn push_once(
    reported: &mut HashSet<(CodeQueryDiagnosticCode, String)>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    diagnostic: CodeQueryDiagnostic,
) {
    if reported.insert((diagnostic.code, diagnostic.message.clone())) {
        diagnostics.push(diagnostic);
    }
}

impl ConfigurationFactsTraversalCache {
    /// Full immutable facts already ingested by this request, before any row
    /// predicate. Effective resolution must not lose shadowing declarations.
    pub(super) fn ingested_document(
        &self,
        analyzer: &dyn IAnalyzer,
        path: &str,
    ) -> Option<ConfigurationFactValue> {
        self.documents
            .read(&memo_attribution(analyzer), |documents| {
                documents.iter().find_map(|(file, snapshot)| {
                    if rel_path_string(file) != path {
                        return None;
                    }
                    let (document, source) = snapshot.document.as_ref()?;
                    Some(ConfigurationFactValue {
                        file: file.clone(),
                        document: Arc::clone(document),
                        source: Arc::clone(source),
                        index: 0,
                    })
                })
            })
    }
    /// Ingest (or replay) one workspace configuration document. `None` only on
    /// cancellation; a supported-but-failed document yields `Some` with no
    /// arena. The snapshot carries the document's diagnostics, which the
    /// caller reports on every replay as well as on the first read.
    pub(super) fn document_for(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        cancellation: Option<&CancellationToken>,
    ) -> Option<ConfigurationDocumentSnapshot> {
        if let Some(cached) = self
            .documents
            .read(&memo_attribution(analyzer), |documents| {
                documents.get(file).cloned()
            })
        {
            return Some(cached);
        }
        let mut ingest_diagnostics = Vec::new();
        let project = analyzer.project();
        let snapshot = project.read_source_snapshot_limited(file, MAX_CONFIGURATION_DOCUMENT_BYTES);
        let snapshot = match snapshot {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => {
                brokk_bifrost_core::profiling::note_with(|| {
                    format!(
                        "policy.units unbounded origin={}:{} cause=provider:source_snapshot",
                        file!(),
                        line!()
                    )
                });
                analyzer.mark_execution_dependent();
                ingest_diagnostics.push(Self::file_incomplete(
                    analyzer,
                    (
                        CodeQueryDiagnosticCode::PipelineBudgetExhausted,
                        Incompleteness::Operational(DerivationExecutionCause::Budget),
                    ),
                    format!(
                        "configuration document {} exceeds the {}-byte ingestion cap; its facts are not available",
                        rel_path_string(file),
                        MAX_CONFIGURATION_DOCUMENT_BYTES
                    ),
                ));
                let snapshot = ConfigurationDocumentSnapshot {
                    document: None,
                    diagnostics: Arc::from(std::mem::take(&mut ingest_diagnostics)),
                };
                self.documents
                    .read_mut(&memo_attribution(analyzer), |documents| {
                        documents.insert(file.clone(), snapshot.clone())
                    });
                return Some(snapshot);
            }
            Err(error) => {
                brokk_bifrost_core::profiling::note_with(|| {
                    format!(
                        "policy.units unbounded origin={}:{} cause=provider:source_snapshot detail={error:?}",
                        file!(),
                        line!()
                    )
                });
                analyzer.mark_execution_dependent();
                ingest_diagnostics.push(Self::file_incomplete(
                    analyzer,
                    (
                        CodeQueryDiagnosticCode::PathDerivationIncomplete,
                        Incompleteness::Operational(DerivationExecutionCause::Provider),
                    ),
                    format!(
                        "configuration ingestion could not read {}: {error}",
                        rel_path_string(file)
                    ),
                ));
                let snapshot = ConfigurationDocumentSnapshot {
                    document: None,
                    diagnostics: Arc::from(std::mem::take(&mut ingest_diagnostics)),
                };
                self.documents
                    .read_mut(&memo_attribution(analyzer), |documents| {
                        documents.insert(file.clone(), snapshot.clone())
                    });
                return Some(snapshot);
            }
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return None;
        }
        let source: Arc<str> = snapshot.into_source();
        let outcome = ingest_configuration_document(
            std::path::Path::new(&rel_path_string(file)),
            source.as_bytes(),
        );
        let document = match outcome {
            ConfigurationIngestionOutcome::Facts(facts) => {
                if facts.completeness().is_complete() {
                    Some((Arc::new(*facts), Arc::clone(&source)))
                } else {
                    ingest_diagnostics.push(Self::file_incomplete(
                        analyzer,
                        (
                            CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                            Incompleteness::Content,
                        ),
                        format!(
                            "configuration ingestion of {} retained facts from a partly recovered document ({}); its rows are not the whole set",
                            rel_path_string(file),
                            recovery_labels(&facts)
                        ),
                    ));
                    Some((Arc::new(*facts), Arc::clone(&source)))
                }
            }
            ConfigurationIngestionOutcome::Unsupported { format } => {
                let format = format
                    .map(|format| format.to_string())
                    .unwrap_or_else(|| "unknown configuration".to_string());
                ingest_diagnostics.push(Self::file_incomplete(
                    analyzer,
                    (
                        CodeQueryDiagnosticCode::MissingStructuralAdapter,
                        Incompleteness::Content,
                    ),
                    format!(
                        "no configuration ingestion adapter for {format}: {} was not read, so the configuration facts are not the whole set",
                        rel_path_string(file)
                    ),
                ));
                None
            }
            ConfigurationIngestionOutcome::Incomplete { reason } => {
                ingest_diagnostics.push(Self::file_incomplete(
                    analyzer,
                    (
                        CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                        match reason {
                            ConfigurationIngestionError::ParserUnavailable(_) => {
                                Incompleteness::Operational(DerivationExecutionCause::Provider)
                            }
                            ConfigurationIngestionError::InvalidUtf8
                            | ConfigurationIngestionError::InvalidFactModel(_) => {
                                Incompleteness::Content
                            }
                        },
                    ),
                    format!(
                        "configuration ingestion of {} is incomplete ({}); its rows are not the whole set",
                        rel_path_string(file),
                        ingestion_reason_label(&reason)
                    ),
                ));
                None
            }
        };
        let snapshot = ConfigurationDocumentSnapshot {
            document,
            diagnostics: Arc::from(ingest_diagnostics),
        };
        self.documents
            .read_mut(&memo_attribution(analyzer), |documents| {
                documents.insert(file.clone(), snapshot.clone())
            });
        Some(snapshot)
    }

    /// How the document at one workspace-relative path fared in this request.
    /// A cross-domain relation reads this to tell a declared document whose
    /// keys are all known from one whose absence would only look clean.
    pub(super) fn ingestion_of(
        &self,
        analyzer: &dyn IAnalyzer,
        rel_path: &str,
    ) -> ConfigurationDocumentIngestion {
        self.documents
            .read(&memo_attribution(analyzer), |documents| {
                let snapshot = documents
                    .iter()
                    .find(|(file, _)| rel_path_string(file) == rel_path)
                    .map(|(_, snapshot)| snapshot);
                match snapshot.map(|snapshot| &snapshot.document) {
                    None => ConfigurationDocumentIngestion::NotIngested,
                    Some(None) => ConfigurationDocumentIngestion::NoFacts,
                    Some(Some((facts, _))) if facts.completeness().is_complete() => {
                        ConfigurationDocumentIngestion::Complete
                    }
                    Some(Some(_)) => ConfigurationDocumentIngestion::Recovered,
                }
            })
    }

    fn file_incomplete(
        analyzer: &dyn IAnalyzer,
        (code, incompleteness): (CodeQueryDiagnosticCode, Incompleteness),
        message: String,
    ) -> CodeQueryDiagnostic {
        super::QueryExecutionState::diagnostic(
            analyzer,
            CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                incompleteness,
                related: Vec::new(),
                source: None,
                code,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: "workspace",
                message,
                exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            }),
            incompleteness.execution_cause(),
        )
    }
}

fn recovery_labels(facts: &ConfigurationDocumentFacts) -> String {
    use brokk_bifrost_core::analyzer::configuration::ConfigurationCompleteness;
    match facts.completeness() {
        ConfigurationCompleteness::Complete => "complete".to_string(),
        ConfigurationCompleteness::Incomplete { recoveries } => recoveries
            .iter()
            .map(|recovery| match recovery.reason() {
                brokk_bifrost_core::analyzer::configuration::ConfigurationRecoveryReason::MalformedSyntax => {
                    "malformed syntax"
                }
                brokk_bifrost_core::analyzer::configuration::ConfigurationRecoveryReason::InvalidUtf8 => {
                    "invalid UTF-8"
                }
                brokk_bifrost_core::analyzer::configuration::ConfigurationRecoveryReason::BudgetExhausted => {
                    "ingestion budget exhausted"
                }
                brokk_bifrost_core::analyzer::configuration::ConfigurationRecoveryReason::ParserLimit => {
                    "parser limit"
                }
                brokk_bifrost_core::analyzer::configuration::ConfigurationRecoveryReason::UnsupportedScalar => {
                    "unsupported scalar"
                }
                brokk_bifrost_core::analyzer::configuration::ConfigurationRecoveryReason::UnsupportedConstruct => {
                    "unsupported construct"
                }
            })
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn ingestion_reason_label(reason: &ConfigurationIngestionError) -> String {
    reason.to_string()
}

/// Whether one fact passes the seed's constrained-value filter. Every empty
/// axis admits every value; every populated axis is an author's enumeration.
pub(super) fn fact_matches_filter(
    value: &ConfigurationFactValue,
    filter: &ConfigurationFactsFilter,
) -> Result<bool, ()> {
    let fact = value.fact();
    if !filter.formats.is_empty() && !filter.formats.contains(&value.format()) {
        return Ok(false);
    }
    if !filter.node_kinds.is_empty()
        && !filter
            .node_kinds
            .iter()
            .any(|kind| kind_matches(fact.kind(), *kind))
    {
        return Ok(false);
    }
    if !filter.roles.is_empty() {
        let ConfigurationNodeKind::Member { role, .. } = fact.kind() else {
            return Ok(false);
        };
        if !filter.roles.contains(role) {
            return Ok(false);
        }
    }
    if !filter.scalar_kinds.is_empty() {
        let scalar_kind = match fact.kind() {
            ConfigurationNodeKind::Scalar { scalar_kind } => Some(*scalar_kind),
            ConfigurationNodeKind::Member {
                value: member_value,
                ..
            } => member_value
                .as_ref()
                .and_then(|fact_id| value.document.fact(*fact_id))
                .and_then(|value_fact| match value_fact.kind() {
                    ConfigurationNodeKind::Scalar { scalar_kind } => Some(*scalar_kind),
                    _ => None,
                }),
            _ => None,
        };
        if scalar_kind.is_none_or(|scalar_kind| !filter.scalar_kinds.contains(&scalar_kind)) {
            return Ok(false);
        }
    }
    if !filter.keys.is_empty() {
        let ConfigurationNodeKind::Member { key, .. } = fact.kind() else {
            return Ok(false);
        };
        if !filter.keys.iter().any(|candidate| candidate == key.text()) {
            return Ok(false);
        }
    }
    if !filter.routes.is_empty()
        && !filter
            .routes
            .iter()
            .any(|route| route_matches(value, route))
    {
        return Ok(false);
    }
    if !filter.fact_ordinals.is_empty() {
        let ordinal = u32::try_from(value.index).unwrap_or(u32::MAX);
        if !filter.fact_ordinals.contains(&ordinal) {
            return Ok(false);
        }
    }
    if !filter.provenances.is_empty() {
        let provenance = match fact.provenance() {
            ConfigurationValueProvenance::Authored => {
                crate::query::ConfigurationValueProvenance::Authored
            }
        };
        if !filter.provenances.contains(&provenance) {
            return Ok(false);
        }
    }
    if !filter.completenesses.is_empty() && !filter.completenesses.contains(&value.completeness()) {
        return Ok(false);
    }
    if !matches_xml_relations(value, filter)? {
        return Ok(false);
    }
    // Decode the value last: an undecodable scalar must not make a query
    // incomplete when another restriction already excludes its fact.
    let has_value_filter = !filter.values.is_empty()
        || !filter.values_ignore_case.is_empty()
        || filter.value_regex.is_some()
        || filter.value_lt.is_some()
        || filter.value_le.is_some()
        || filter.value_gt.is_some()
        || filter.value_ge.is_some();
    let scalar_value = if has_value_filter {
        match value.scalar_value() {
            ScalarValue::Decoded(value) => Some(value),
            ScalarValue::Absent => None,
            ScalarValue::Undecodable => return Err(()),
        }
    } else {
        None
    };
    if !filter.values.is_empty()
        && !scalar_value
            .as_deref()
            .is_some_and(|actual| filter.values.iter().any(|expected| expected == actual))
    {
        return Ok(false);
    }
    if !filter.values_ignore_case.is_empty()
        && !scalar_value.as_deref().is_some_and(|actual| {
            filter
                .values_ignore_case
                .iter()
                .any(|expected| expected.eq_ignore_ascii_case(actual))
        })
    {
        return Ok(false);
    }
    if filter.value_regex.as_ref().is_some_and(|regex| {
        !scalar_value
            .as_deref()
            .is_some_and(|actual| regex.0.is_match(actual))
    }) {
        return Ok(false);
    }
    let has_numeric_bound = filter.value_lt.is_some()
        || filter.value_le.is_some()
        || filter.value_gt.is_some()
        || filter.value_ge.is_some();
    // The number grammar tells a decimal the comparison cannot represent,
    // which decides nothing, from a scalar that is not a number, which no
    // numeric bound matches.
    let numeric_value = match scalar_value
        .as_deref()
        .filter(|_| has_numeric_bound)
        .map(|text| value.scalar_number(text))
    {
        Some(ConfigurationNumberToken::Number(number)) => Some(number),
        Some(ConfigurationNumberToken::OutOfRange) => return Err(()),
        Some(ConfigurationNumberToken::NotDecimal) | None => None,
    };
    if !matches_numeric_bound(
        numeric_value.as_ref(),
        filter.value_lt.as_deref(),
        std::cmp::Ordering::is_lt,
    ) || !matches_numeric_bound(
        numeric_value.as_ref(),
        filter.value_le.as_deref(),
        std::cmp::Ordering::is_le,
    ) || !matches_numeric_bound(
        numeric_value.as_ref(),
        filter.value_gt.as_deref(),
        std::cmp::Ordering::is_gt,
    ) || !matches_numeric_bound(
        numeric_value.as_ref(),
        filter.value_ge.as_deref(),
        std::cmp::Ordering::is_ge,
    ) {
        return Ok(false);
    }
    Ok(true)
}

fn matches_numeric_bound(
    actual: Option<&ConfigurationNumber>,
    bound: Option<&str>,
    predicate: impl FnOnce(std::cmp::Ordering) -> bool,
) -> bool {
    let Some(bound) = bound else {
        return true;
    };
    let Some(actual) = actual else {
        return false;
    };
    let bound = ConfigurationNumber::parse(bound)
        .expect("query validation checks numeric bounds with the same grammar");
    predicate(actual.compare(&bound))
}

fn kind_matches(kind: &ConfigurationNodeKind, filter: ConfigurationNodeKindFilter) -> bool {
    matches!(
        (kind, filter),
        (
            ConfigurationNodeKind::Document { .. },
            ConfigurationNodeKindFilter::Document
        ) | (
            ConfigurationNodeKind::Object { .. },
            ConfigurationNodeKindFilter::Object
        ) | (
            ConfigurationNodeKind::Section { .. },
            ConfigurationNodeKindFilter::Section
        ) | (
            ConfigurationNodeKind::Sequence { .. },
            ConfigurationNodeKindFilter::Sequence
        ) | (
            ConfigurationNodeKind::Member { .. },
            ConfigurationNodeKindFilter::Member
        ) | (
            ConfigurationNodeKind::Scalar { .. },
            ConfigurationNodeKindFilter::Scalar
        )
    )
}

fn route_matches(value: &ConfigurationFactValue, route: &ConfigurationRouteFilter) -> bool {
    let segments = value.fact().route().segments();
    if segments.len() != route.0.len() {
        return false;
    }
    segments
        .iter()
        .zip(route.0.iter())
        .all(|(segment, filter)| match (segment.selector(), filter) {
            (
                ConfigurationRouteSelector::Key { name, .. },
                ConfigurationRouteSegmentFilter::Key(expected),
            ) => name == expected,
            (
                ConfigurationRouteSelector::Index(index),
                ConfigurationRouteSegmentFilter::Index(expected),
            ) => usize::try_from(*expected).is_ok_and(|expected| *index == expected),
            (_, ConfigurationRouteSegmentFilter::Any) => true,
            _ => false,
        })
}

/// Enumerate the workspace's configuration files in deterministic order.
///
/// Configuration files are not language-analyzed files, so the analyzer's
/// analyzed-file set cannot answer this: the seed enumerates the project's
/// whole file listing. A narrowed unit scope narrows analyzed-language files
/// only, so it cannot contain configuration files and is deliberately ignored
/// here rather than silently answered with zero rows.
pub(super) fn configuration_seed_files(
    state: &QueryExecutionState<'_>,
    formats: &[crate::query::domain::ConfigurationFormat],
    where_globs: &crate::query::QueryPathScope,
) -> Result<Vec<ProjectFile>, std::io::Error> {
    use std::ffi::OsStr;
    use std::path::Component;

    let project = state.analyzer.project();
    let mut files = Vec::new();
    for file in project.all_files()? {
        if file.rel_path().components().any(|component| {
            component
                == Component::Normal(OsStr::new(brokk_bifrost_core::gitblob::PROJECT_DIR_NAME))
        }) {
            continue;
        }
        let rel = rel_path_string(&file);
        if !where_globs.matches(&rel) {
            continue;
        }
        let Some(format) = format_for_path(file.rel_path()) else {
            continue;
        };
        if !formats.is_empty() && !formats.contains(&format) {
            continue;
        }
        files.push(file);
    }
    files.sort();
    Ok(files)
}

/// The configuration format the canonical registry assigns to one
/// workspace-relative path, if any.
pub(super) fn format_for_path(
    rel_path: &std::path::Path,
) -> Option<crate::query::domain::ConfigurationFormat> {
    use brokk_bifrost_core::analyzer::configuration::{
        ConfigurationPathClassification, classify_configuration_path,
    };
    match classify_configuration_path(rel_path) {
        ConfigurationPathClassification::Supported(format) => Some(format.into()),
        ConfigurationPathClassification::Unsupported => None,
    }
}

/// Produce the configuration-fact seed rows for one authored plan source.
pub(super) fn execute_configuration_facts_seed(
    seed: &ConfigurationFactsSeed,
    terminal_cap: Option<usize>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    let Some(desired_rows) =
        super::seeds::desired_seed_rows(terminal_cap, state, limits, diagnostics)
    else {
        return PlanExecution::truncated(Vec::new());
    };

    let files = match configuration_seed_files(state, &seed.filter.formats, &seed.where_globs) {
        Ok(files) => files,
        Err(error) => {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=provider:configuration_files detail={error:?}",
                    file!(),
                    line!()
                )
            });
            state.analyzer.mark_execution_dependent();
            diagnostics.push(super::QueryExecutionState::diagnostic(
                state.analyzer,
                CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                    incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                    related: Vec::new(),
                    source: None,
                    code: CodeQueryDiagnosticCode::PathDerivationIncomplete,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: "workspace",
                    message: format!("configuration seed could not list workspace files: {error}"),
                    exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                }),
                Some(DerivationExecutionCause::Provider),
            ));
            return PlanExecution::truncated(Vec::new());
        }
    };
    if files.is_empty() && !seed.where_globs.is_empty() {
        diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
            incompleteness: brokk_bifrost_rql::Incompleteness::Content,
            related: Vec::new(),
            source: None,
            code: CodeQueryDiagnosticCode::PathDerivationIncomplete,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "workspace",
            message: "configuration seed did not route to any workspace document for the requested path scope; absence is not provable".to_owned(),
            exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        }));
    }

    let mut rows: Vec<PipelineRow> = Vec::new();
    let mut indexes: HashMap<PipelineKey, usize> = HashMap::default();
    let mut truncated = false;
    let mut visited_rows = 0;
    let mut reported = HashSet::default();
    for file in files {
        match super::seeds::scan_seed_file(state, limits, diagnostics) {
            super::seeds::SeedFileScanStatus::Scanned => {}
            super::seeds::SeedFileScanStatus::BudgetExhausted => {
                truncated = true;
                break;
            }
            super::seeds::SeedFileScanStatus::Cancelled => {
                return PlanExecution::cancelled(Vec::new());
            }
        }

        let Some(snapshot) =
            state
                .configuration_cache
                .document_for(state.analyzer, &file, state.cancellation)
        else {
            return PlanExecution::cancelled(Vec::new());
        };
        for diagnostic in snapshot.diagnostics.iter() {
            push_once(&mut reported, diagnostics, diagnostic.clone());
        }
        let Some((document, source)) = snapshot.document else {
            continue;
        };
        let mut projected = state.budget;
        projected.scanned_source_bytes =
            projected.scanned_source_bytes.saturating_add(source.len());
        if projected.scanned_source_bytes > limits.max_scanned_source_bytes {
            push_budget_diagnostic(diagnostics, &projected);
            truncated = true;
            break;
        }
        state.budget.scanned_source_bytes = projected.scanned_source_bytes;
        projected.fact_nodes = projected.fact_nodes.saturating_add(document.facts().len());
        if projected.fact_nodes > limits.max_fact_nodes {
            push_budget_diagnostic(diagnostics, &projected);
            truncated = true;
            break;
        }
        state.budget.fact_nodes = projected.fact_nodes;

        if has_xml_relation_filter(&seed.filter) {
            let document_value = ConfigurationFactValue {
                file: file.clone(),
                document: Arc::clone(&document),
                source: Arc::clone(&source),
                index: 0,
            };
            if let Some(reason) = xml_reference_coverage(&document_value, &seed.filter) {
                push_once(
                    &mut reported,
                    diagnostics,
                    ConfigurationFactsTraversalCache::file_incomplete(
                        state.analyzer,
                        (
                            CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                            Incompleteness::Content,
                        ),
                        format!(
                            "XML configuration relation for {} is incomplete: {reason}",
                            rel_path_string(&file)
                        ),
                    ),
                );
            }
        }

        for (index, _) in document.facts().iter().enumerate() {
            let value = ConfigurationFactValue {
                file: file.clone(),
                document: Arc::clone(&document),
                source: Arc::clone(&source),
                index,
            };
            match fact_matches_filter(&value, &seed.filter) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(()) => {
                    push_once(
                        &mut reported,
                        diagnostics,
                        ConfigurationFactsTraversalCache::file_incomplete(
                            state.analyzer,
                            (
                                CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                                Incompleteness::Content,
                            ),
                            format!(
                                "configuration scalar in {} could not be decoded",
                                rel_path_string(&file)
                            ),
                        ),
                    );
                    continue;
                }
            }
            if !super::seeds::record_seed_row(
                &mut rows,
                &mut indexes,
                &mut visited_rows,
                state,
                desired_rows,
                || Some(PipelineValue::ConfigurationFact(value)),
            ) {
                truncated = true;
                diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                    incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                    related: Vec::new(),
                    source: None,
                    code: CodeQueryDiagnosticCode::EnvironmentRowBudgetExhausted,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: "workspace",
                    message: format!(
                        "configuration fact seed reached its {desired_rows}-row cap; narrow the filter, formats, or where globs"
                    ),
                    exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                }));
                break;
            }
        }
        if truncated {
            break;
        }
    }

    PlanExecution::new(rows, truncated)
}
