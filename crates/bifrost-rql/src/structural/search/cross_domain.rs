//! Registered cross-domain operators (#3284): `correlate` and `require-both`.
//!
//! Both operators read one programming-code input and one configuration input
//! that ran as independent sub-plans. `correlate` pairs a code row with a
//! configuration fact only where its typed relation holds structurally;
//! `require-both` checks boolean satisfaction and returns each contributing
//! row under its own domain without pairing anything. Every gap that could
//! hide a correlation is a typed `incomplete` diagnostic, so an empty answer
//! is never a clean negative when an input was partial.
//!
//! Unit of work: one query. The key index and the parsed sources below live
//! only for this operator invocation.

use super::configuration::{ConfigurationDocumentIngestion, format_for_path};
use super::*;
use crate::analyzer::java_plain_string_literal;
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::query::{ConfigurationFactsSeed, ConfigurationKeyRelation, CrossDomainOperatorKind};
use brokk_bifrost_core::analyzer::configuration::{
    ConfigurationNodeKind, ConfigurationRouteSelector,
};
use std::path::Path;

const CROSS_DOMAIN_ROW_ID_DOMAIN: &[u8] = b"bifrost.code_query.cross_domain.row.v1";
const CROSS_DOMAIN_CODE_ID_DOMAIN: &[u8] = b"bifrost.code_query.cross_domain.code.v1";

/// Whether a correlated key named exactly one authored fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum CrossDomainBinding {
    Unique,
    /// More than one authored fact in the declared documents has the key:
    /// a duplicate occurrence, or the same key in two declared documents.
    /// Which one is effective is an effective-configuration claim, not a
    /// correlation claim, so every candidate is returned.
    Ambiguous,
}

impl CrossDomainBinding {
    pub(super) const LABELS: &[&str] = &["unique", "ambiguous"];

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Unique => "unique",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// The published `operator`, `domain`, and `relation` vocabularies.
pub(super) const CROSS_DOMAIN_OPERATOR_LABELS: &[&str] = &["correlate", "require_both"];
pub(super) const CROSS_DOMAIN_ROW_DOMAIN_LABELS: &[&str] = &["correlated", "code", "configuration"];
pub(super) const CROSS_DOMAIN_RELATION_LABELS: &[&str] = &[
    "configuration_key",
    "configuration_code",
    "dependency_configuration",
];

/// One row of a cross-domain operator. The variant is the domain
/// discriminator: a correlated pair, or a single witness of one domain.
#[derive(Debug, Clone)]
pub(super) enum CrossDomainValue {
    DependencyConfiguration(Box<super::dependency_configuration::DependencyConfigurationValue>),
    Correlated {
        code: Box<PipelineValue>,
        configuration: ConfigurationFactValue,
        key: String,
        binding: CrossDomainBinding,
    },
    ConfigurationCode {
        code: Box<PipelineValue>,
        configuration: ConfigurationFactValue,
        key: String,
        binding: CrossDomainBinding,
    },
    ConfigurationCodeAbsent {
        configuration: ConfigurationFactValue,
        key: String,
    },
    CodeWitness(Box<PipelineValue>),
    ConfigurationWitness(ConfigurationFactValue),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum CrossDomainKey {
    DependencyConfiguration(PipelineKey, String),
    Correlated(PipelineKey, ConfigurationFactKey),
    ConfigurationCode(PipelineKey, ConfigurationFactKey),
    ConfigurationCodeAbsent(ConfigurationFactKey),
    CodeWitness(PipelineKey),
    ConfigurationWitness(ConfigurationFactKey),
}

impl CrossDomainValue {
    pub(super) fn operator(&self) -> CrossDomainOperatorKind {
        match self {
            Self::DependencyConfiguration(_) => {
                CrossDomainOperatorKind::CorrelateDependencyConfiguration
            }
            Self::Correlated { .. } => CrossDomainOperatorKind::CorrelateConfigurationKey,
            Self::ConfigurationCode { .. } | Self::ConfigurationCodeAbsent { .. } => {
                CrossDomainOperatorKind::CorrelateConfigurationCode
            }
            Self::CodeWitness(_) | Self::ConfigurationWitness(_) => {
                CrossDomainOperatorKind::RequireBoth
            }
        }
    }

    pub(super) const fn domain_label(&self) -> &'static str {
        match self {
            Self::DependencyConfiguration(value) => {
                if value.configuration.is_some() {
                    "correlated"
                } else {
                    "code"
                }
            }
            Self::Correlated { .. } => "correlated",
            Self::ConfigurationCode { .. } => "correlated",
            Self::ConfigurationCodeAbsent { .. } => "configuration",
            Self::CodeWitness(_) => "code",
            Self::ConfigurationWitness(_) => "configuration",
        }
    }

    pub(super) const fn relation_label(&self) -> Option<&'static str> {
        match self {
            Self::DependencyConfiguration(_) => Some("dependency_configuration"),
            Self::Correlated { .. } => Some("configuration_key"),
            Self::ConfigurationCode { .. } | Self::ConfigurationCodeAbsent { .. } => {
                Some("configuration_code")
            }
            Self::CodeWitness(_) | Self::ConfigurationWitness(_) => None,
        }
    }

    pub(super) fn key(&self) -> CrossDomainKey {
        match self {
            Self::DependencyConfiguration(value) => {
                CrossDomainKey::DependencyConfiguration(value.code.key(), value.mapping_id.clone())
            }
            Self::Correlated {
                code,
                configuration,
                ..
            } => CrossDomainKey::Correlated(code.key(), configuration.key()),
            Self::ConfigurationCode {
                code,
                configuration,
                ..
            } => CrossDomainKey::ConfigurationCode(code.key(), configuration.key()),
            Self::ConfigurationCodeAbsent { configuration, .. } => {
                CrossDomainKey::ConfigurationCodeAbsent(configuration.key())
            }
            Self::CodeWitness(code) => CrossDomainKey::CodeWitness(code.key()),
            Self::ConfigurationWitness(configuration) => {
                CrossDomainKey::ConfigurationWitness(configuration.key())
            }
        }
    }

    pub(super) fn code(&self) -> Option<&PipelineValue> {
        match self {
            Self::DependencyConfiguration(value) => Some(&value.code),
            Self::Correlated { code, .. } | Self::CodeWitness(code) => Some(code),
            Self::ConfigurationCode { code, .. } => Some(code),
            Self::ConfigurationCodeAbsent { .. } => None,
            Self::ConfigurationWitness(_) => None,
        }
    }

    pub(super) fn configuration(&self) -> Option<&ConfigurationFactValue> {
        match self {
            Self::DependencyConfiguration(value) => value.configuration.as_ref(),
            Self::Correlated { configuration, .. } | Self::ConfigurationWitness(configuration) => {
                Some(configuration)
            }
            Self::ConfigurationCode { configuration, .. }
            | Self::ConfigurationCodeAbsent { configuration, .. } => Some(configuration),
            Self::CodeWitness(_) => None,
        }
    }

    /// The file the row is anchored to: the code row when one is carried.
    pub(super) fn anchor_file(&self) -> &ProjectFile {
        match self {
            Self::DependencyConfiguration(value) => terminal_source_file(&value.code)
                .expect("dependency rows name their retained source file"),
            Self::Correlated { code, .. }
            | Self::CodeWitness(code)
            | Self::ConfigurationCode { code, .. } => code_row_file(code),
            Self::ConfigurationCodeAbsent { configuration, .. } => configuration.file(),
            Self::ConfigurationWitness(configuration) => configuration.file(),
        }
    }

    /// A detail-independent identity of the carried code row: its public
    /// domain, file, exact span, and typed detailed key.
    pub(super) fn code_id(&self) -> Option<String> {
        let code = self.code()?;
        if let PipelineValue::DependencyEvidence(value) = code {
            return Some(value.row.id());
        }
        let evidence = detailed_evidence_for_pipeline_value(0, code, None, None);
        let mut digest = LengthDelimitedDigest::new(CROSS_DOMAIN_CODE_ID_DOMAIN);
        digest.push(evidence.domain.label().as_bytes());
        digest.push(rel_path_string(&evidence.file).as_bytes());
        match evidence.byte_span {
            Some(span) => {
                digest.push(b"span");
                digest.push(&span.start.to_le_bytes());
                digest.push(&span.end.to_le_bytes());
            }
            None => digest.push(b"no-span"),
        }
        digest.push(
            &serde_json::to_vec(&evidence.key).expect("detailed keys serialize as JSON objects"),
        );
        Some(digest.finish().to_string())
    }

    /// The carried configuration fact's own workspace row id, so a policy can
    /// join this row to the `configuration_fact` row it came from.
    pub(super) fn configuration_id(&self) -> Option<String> {
        self.configuration().map(ConfigurationFactValue::id)
    }

    pub(super) fn id(&self) -> String {
        let mut digest = LengthDelimitedDigest::new(CROSS_DOMAIN_ROW_ID_DOMAIN);
        digest.push(self.operator().id_label().as_bytes());
        digest.push(self.domain_label().as_bytes());
        digest.push(self.relation_label().unwrap_or("").as_bytes());
        digest.push(self.code_id().unwrap_or_default().as_bytes());
        digest.push(self.configuration_id().unwrap_or_default().as_bytes());
        if let Self::DependencyConfiguration(value) = self {
            digest.push(value.mapping_id.as_bytes());
        }
        digest.finish().to_string()
    }
}

pub(super) fn plan_rows_budget(
    terminal_cap: Option<usize>,
    state: &QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
) -> usize {
    let budget_cap = limits
        .max_pipeline_rows
        .saturating_sub(state.budget.pipeline_rows);
    terminal_cap.unwrap_or(budget_cap).min(budget_cap)
}

pub(super) fn cross_domain_diagnostic(
    code: CodeQueryDiagnosticCode,
    impact: CodeQueryDiagnosticImpact,
    message: String,
) -> CodeQueryDiagnostic {
    CodeQueryDiagnostic::new(CodeQueryDiagnostic {
        incompleteness: brokk_bifrost_rql::Incompleteness::Operational(
            brokk_bifrost_rql::DiagnosticExecutionCause::Provider,
        ),
        related: Vec::new(),
        source: None,
        code,
        impact,
        branch: Vec::new(),
        language: "workspace",
        message,
        exhausted_roots: Vec::new(),
        withheld_rows_path: None,
    })
}

/// The location of a code row in diagnostics: path and exact byte span.
fn code_location(site: &ExpressionSiteValue) -> String {
    format!(
        "{}@{}..{}",
        rel_path_string(&site.call_site.0.file),
        site.range.start_byte,
        site.range.end_byte
    )
}

/// The flat key a `.properties` member fact declares: a member whose route is
/// exactly one key segment. Any other fact never correlates.
pub(super) fn single_key_member(fact: &ConfigurationFactValue) -> Option<&str> {
    let ConfigurationNodeKind::Member { .. } = fact.fact().kind() else {
        return None;
    };
    let [segment] = fact.fact().route().segments() else {
        return None;
    };
    match segment.selector() {
        ConfigurationRouteSelector::Key { name, .. } => Some(name),
        ConfigurationRouteSelector::Index(_) => None,
    }
}

fn admits_document(seed: &ConfigurationFactsSeed, document: &str) -> bool {
    seed.where_globs.matches(document)
        && format_for_path(Path::new(document)).is_some_and(|format| {
            seed.filter.formats.is_empty() || seed.filter.formats.contains(&format)
        })
}

/// Why a declared document cannot support an exhaustive correlation.
pub(super) fn declared_document_gap(
    document: &str,
    configuration_seeds: &[ConfigurationFactsSeed],
    state: &QueryExecutionState<'_>,
) -> Option<&'static str> {
    if !configuration_seeds
        .iter()
        .any(|seed| admits_document(seed, document))
    {
        return Some("is outside the configuration input's where and format scope");
    }
    match state
        .configuration_cache
        .ingestion_of(state.analyzer, document)
    {
        ConfigurationDocumentIngestion::NotIngested => Some(
            "was not ingested by the configuration input: it is absent from the workspace, or the input stopped before reaching it",
        ),
        ConfigurationDocumentIngestion::NoFacts => Some("produced no configuration facts"),
        ConfigurationDocumentIngestion::Recovered => {
            Some("was only partly recovered, so its keys are not the whole set")
        }
        ConfigurationDocumentIngestion::Complete => None,
    }
}

/// The outcome of decoding the key a bound argument supplies.
enum KeyDecoding {
    Key(String),
    NotPlainLiteral,
    SourceUnavailable,
}

/// Decode the plain string literal at the argument's exact range from the
/// tree-sitter AST. A parenthesized, concatenated, escaped, or computed
/// argument is not a plain literal and never correlates.
fn decode_java_key(
    analyzer: &dyn IAnalyzer,
    sources: &mut HashMap<ProjectFile, Option<(Arc<str>, tree_sitter::Tree)>>,
    site: &ExpressionSiteValue,
) -> KeyDecoding {
    let file = &site.call_site.0.file;
    let parsed = sources.entry(file.clone()).or_insert_with(|| {
        let source: Arc<str> = analyzer.indexed_source(file)?.into();
        let tree = parse_tree_for_language(file, Language::Java, &source)?;
        Some((source, tree))
    });
    let Some((source, tree)) = parsed.as_ref() else {
        return KeyDecoding::SourceUnavailable;
    };
    let node = tree
        .root_node()
        .descendant_for_byte_range(site.range.start_byte, site.range.end_byte)
        .filter(|node| {
            node.start_byte() == site.range.start_byte && node.end_byte() == site.range.end_byte
        });
    match node.and_then(|node| java_plain_string_literal(node, source)) {
        Some(key) => KeyDecoding::Key(key.to_owned()),
        None => KeyDecoding::NotPlainLiteral,
    }
}

/// Evaluate `correlate` with the configuration-key relation over the two
/// executed inputs. `code` rows are `expression_site` rows and
/// `configuration` rows are configuration facts; validation guarantees both.
#[allow(clippy::too_many_arguments)]
pub(super) fn execute_correlate_configuration_key(
    relation: &ConfigurationKeyRelation,
    configuration_seeds: &[ConfigurationFactsSeed],
    code: PlanExecution,
    configuration: PlanExecution,
    terminal_cap: Option<usize>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    let mut truncated = code.truncated || configuration.truncated;

    let document_gaps = relation
        .documents
        .iter()
        .filter_map(|document| {
            declared_document_gap(document, configuration_seeds, state)
                .map(|reason| (document.as_str(), reason))
        })
        .collect::<Vec<_>>();
    if !document_gaps.is_empty() {
        diagnostics.push(cross_domain_diagnostic(
            CodeQueryDiagnosticCode::CrossDomainDocumentIncomplete,
            CodeQueryDiagnosticImpact::Incomplete,
            format!(
                "configuration_key cannot read every declared document exhaustively, so a missing pair is not evidence of an unbound key: {document_gaps:?}"
            ),
        ));
    }

    // Query-lifetime index: flat key -> configuration rows in declared
    // documents that declare it.
    let mut by_key: HashMap<&str, Vec<usize>> = HashMap::default();
    for (index, row) in configuration.rows.iter().enumerate() {
        let PipelineValue::ConfigurationFact(fact) = &row.value else {
            unreachable!("validated configuration inputs produce configuration facts");
        };
        let path = rel_path_string(fact.file());
        if !relation.documents.contains(&path) {
            continue;
        }
        if let Some(key) = single_key_member(fact) {
            by_key.entry(key).or_default().push(index);
        }
    }

    let desired_rows = plan_rows_budget(terminal_cap, state, limits);
    let code_languages = CrossDomainOperatorKind::CorrelateConfigurationKey.code_languages();
    let mut sources = HashMap::default();
    let mut unsupported_languages = Vec::new();
    let mut unproven = Vec::new();
    let mut not_literal = Vec::new();
    let mut unavailable_sources = Vec::new();
    let mut ambiguous = Vec::new();
    let mut rows: Vec<PipelineRow> = Vec::new();
    let mut indexes: HashMap<PipelineKey, usize> = HashMap::default();
    'code_rows: for code_row in &code.rows {
        if state
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return cancelled_plan_execution();
        }
        let PipelineValue::ExpressionSite(site) = &code_row.value else {
            unreachable!("validated configuration_key code inputs produce expression sites");
        };
        let language = crate::analyzer::common::language_for_file(&site.call_site.0.file);
        if !code_languages.contains(&language) {
            unsupported_languages.push(format!(
                "{} ({})",
                code_location(site),
                language.config_label()
            ));
            continue;
        }
        if site.call_site.0.proof != UsageProof::Proven {
            unproven.push(code_location(site));
            continue;
        }
        if !sources.contains_key(&site.call_site.0.file) {
            let mut projected = state.budget;
            projected.scanned_files = projected.scanned_files.saturating_add(1);
            if projected.scanned_files > limits.max_scanned_files {
                push_budget_diagnostic(diagnostics, &projected);
                truncated = true;
                break;
            }
            state.budget.scanned_files = projected.scanned_files;
        }
        let key = match decode_java_key(state.analyzer, &mut sources, site) {
            KeyDecoding::Key(key) => key,
            KeyDecoding::NotPlainLiteral => {
                not_literal.push(code_location(site));
                continue;
            }
            KeyDecoding::SourceUnavailable => {
                unavailable_sources.push(code_location(site));
                continue;
            }
        };
        let Some(matches) = by_key.get(key.as_str()) else {
            continue;
        };
        let binding = if matches.len() == 1 {
            CrossDomainBinding::Unique
        } else {
            let candidates = matches
                .iter()
                .map(|&index| {
                    let PipelineValue::ConfigurationFact(fact) = &configuration.rows[index].value
                    else {
                        unreachable!("the key index holds configuration fact rows");
                    };
                    format!("{}#{}", rel_path_string(fact.file()), fact.route())
                })
                .collect::<Vec<_>>();
            ambiguous.push((code_location(site), key.clone(), candidates));
            CrossDomainBinding::Ambiguous
        };
        for &index in matches {
            if rows.len() >= desired_rows {
                push_pipeline_budget_diagnostic(diagnostics, &state.budget);
                truncated = true;
                break 'code_rows;
            }
            let configuration_row = &configuration.rows[index];
            let PipelineValue::ConfigurationFact(fact) = &configuration_row.value else {
                unreachable!("the key index holds configuration fact rows");
            };
            state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(1);
            let traces = code_row
                .traces
                .iter()
                .chain(&configuration_row.traces)
                .cloned()
                .collect();
            insert_pipeline_row(
                &mut rows,
                &mut indexes,
                PipelineValue::CrossDomain(Box::new(CrossDomainValue::Correlated {
                    code: Box::new(code_row.value.clone()),
                    configuration: fact.clone(),
                    key: key.clone(),
                    binding,
                })),
                traces,
                code_row.provenance_truncated || configuration_row.provenance_truncated,
            );
        }
    }

    for (code, locations, explanation) in [
        (
            CodeQueryDiagnosticCode::CrossDomainKeyUnsupported,
            unsupported_languages,
            "configuration_key decodes keys only from Java code; these bound arguments are in other languages",
        ),
        (
            CodeQueryDiagnosticCode::CrossDomainBindingUnproven,
            unproven,
            "configuration_key requires a resolver-proven call binding; these calls did not resolve to their callee with proof",
        ),
        (
            CodeQueryDiagnosticCode::CrossDomainKeyUnsupported,
            not_literal,
            "configuration_key decodes only plain string literals; these bound arguments are escaped, text blocks, concatenations, or computed expressions",
        ),
        (
            CodeQueryDiagnosticCode::CrossDomainKeyUnsupported,
            unavailable_sources,
            "configuration_key could not read or parse the indexed source of these bound arguments",
        ),
    ] {
        if locations.is_empty() {
            continue;
        }
        diagnostics.push(cross_domain_diagnostic(
            code,
            CodeQueryDiagnosticImpact::Incomplete,
            format!("{explanation}, so their keys may correlate unseen: {locations:?}"),
        ));
    }
    if !ambiguous.is_empty() {
        diagnostics.push(cross_domain_diagnostic(
            CodeQueryDiagnosticCode::CrossDomainCorrelationAmbiguous,
            CodeQueryDiagnosticImpact::Advisory,
            format!(
                "configuration_key paired these bound keys with more than one authored fact; every candidate is returned with binding ambiguous, and which one is effective is not claimed: {ambiguous:?}"
            ),
        ));
    }

    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: false,
    }
}

/// Evaluate `require-both`: boolean satisfaction of both inputs, with each
/// contributing row returned under its own domain and nothing paired.
pub(super) fn execute_require_both(
    code: PlanExecution,
    configuration: PlanExecution,
    terminal_cap: Option<usize>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    let mut truncated = code.truncated || configuration.truncated;
    // An unsatisfied side yields no rows. Its own diagnostics already say
    // whether that emptiness is exhaustive or incomplete.
    if code.rows.is_empty() || configuration.rows.is_empty() {
        return PlanExecution {
            rows: Vec::new(),
            truncated,
            cancelled: false,
            pipeline_halted: false,
        };
    }
    let desired_rows = plan_rows_budget(terminal_cap, state, limits);
    let witnesses = code
        .rows
        .into_iter()
        .map(|row| {
            (
                CrossDomainValue::CodeWitness(Box::new(row.value)),
                row.traces,
                row.provenance_truncated,
            )
        })
        .chain(configuration.rows.into_iter().map(|row| {
            let PipelineValue::ConfigurationFact(fact) = row.value else {
                unreachable!("validated configuration inputs produce configuration facts");
            };
            (
                CrossDomainValue::ConfigurationWitness(fact),
                row.traces,
                row.provenance_truncated,
            )
        }));
    let mut rows: Vec<PipelineRow> = Vec::new();
    let mut indexes: HashMap<PipelineKey, usize> = HashMap::default();
    for (witness, traces, provenance_truncated) in witnesses {
        if rows.len() >= desired_rows {
            push_pipeline_budget_diagnostic(diagnostics, &state.budget);
            truncated = true;
            break;
        }
        state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(1);
        insert_pipeline_row(
            &mut rows,
            &mut indexes,
            PipelineValue::CrossDomain(Box::new(witness)),
            traces,
            provenance_truncated,
        );
    }
    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: false,
    }
}
