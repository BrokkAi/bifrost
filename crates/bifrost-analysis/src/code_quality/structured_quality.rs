//! Versioned machine-readable findings shared by quality report handlers.

use super::{ReportLines, append_ambiguous_path_notes, sanitize_table_cell};
use crate::analyzer::{CodeUnitType, IAnalyzer, ProjectFile, Range, canonical_hash};
use crate::hash::HashMap;
use crate::path_utils::{AmbiguousPathInput, rel_path_string};
use crate::text_utils::{compute_line_starts, line_column_for_offset};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub const QUALITY_FINDINGS_SCHEMA_ID: &str = "bifrost.quality.findings";
pub const QUALITY_FINDINGS_SCHEMA_VERSION: u32 = 1;
pub const MAX_QUALITY_FINDINGS: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StructuredQualityFindings {
    pub schema_id: String,
    pub schema_version: u32,
    pub finding_kind: QualityFindingKind,
    pub parameters: Vec<QualityParameter>,
    pub findings: Vec<QualityFinding>,
    pub completion: QualityCompletion,
    pub truncation: QualityTruncation,
}

impl StructuredQualityFindings {
    pub(crate) fn new(
        finding_kind: QualityFindingKind,
        parameters: Vec<QualityParameter>,
        findings: Vec<QualityFinding>,
        input_complete: bool,
        analysis_complete: bool,
        requested_max_findings: usize,
        total_findings: usize,
    ) -> Self {
        assert!(findings.len() <= MAX_QUALITY_FINDINGS);
        assert!(findings.len() <= total_findings);
        assert!(
            findings
                .iter()
                .all(|finding| finding.kind() == finding_kind)
        );
        let omitted_findings = total_findings - findings.len();
        Self {
            schema_id: QUALITY_FINDINGS_SCHEMA_ID.to_string(),
            schema_version: QUALITY_FINDINGS_SCHEMA_VERSION,
            finding_kind,
            parameters,
            findings,
            completion: QualityCompletion {
                input_complete,
                analysis_complete,
                retention_complete: omitted_findings == 0,
            },
            truncation: QualityTruncation {
                requested_max_findings,
                applied_max_findings: requested_max_findings.min(MAX_QUALITY_FINDINGS),
                retained_findings: total_findings - omitted_findings,
                omitted_findings,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QualityFindingKind {
    TestAssertion,
    StructuralClone,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QualityFinding {
    TestAssertion(TestAssertionQualityFinding),
    StructuralClone(StructuralCloneQualityFinding),
}

impl QualityFinding {
    fn kind(&self) -> QualityFindingKind {
        match self {
            Self::TestAssertion(_) => QualityFindingKind::TestAssertion,
            Self::StructuralClone(_) => QualityFindingKind::StructuralClone,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QualityReason {
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TestAssertionQualityFinding {
    pub assertion_kind: String,
    pub reasons: Vec<QualityReason>,
    pub metrics: TestAssertionQualityMetrics,
    pub evidence: QualityEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TestAssertionQualityMetrics {
    pub score: i32,
    pub assertion_count: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StructuralCloneQualityFinding {
    pub reasons: Vec<QualityReason>,
    pub metrics: StructuralCloneQualityMetrics,
    pub primary: QualityEvidence,
    pub peer: QualityEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StructuralCloneQualityMetrics {
    pub score: i32,
    pub normalized_token_count: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QualityEvidence {
    pub subject: QualitySubject,
    pub source_sha256: Option<String>,
    pub excerpt: String,
    pub location: QualityLocation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QualitySubject {
    pub path: String,
    pub symbol: String,
    pub display_symbol: String,
    pub declaration_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QualityParameter {
    pub name: String,
    pub value: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QualityCompletion {
    pub input_complete: bool,
    pub analysis_complete: bool,
    pub retention_complete: bool,
}

impl QualityCompletion {
    pub fn complete(&self) -> bool {
        self.input_complete && self.analysis_complete && self.retention_complete
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QualityTruncation {
    pub requested_max_findings: usize,
    pub applied_max_findings: usize,
    pub retained_findings: usize,
    pub omitted_findings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum QualityLocation {
    Exact {
        range: QualityRange,
    },
    Unavailable {
        reason: QualityLocationUnavailableReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QualityLocationUnavailableReason {
    DeclarationProjectionUnavailable,
    DeclarationRangeUnavailable,
    AmbiguousDeclarationLocation,
    IndexedSourceUnavailable,
    SourceRangeInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct QualityRange {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub end_line: usize,
    pub start_column: usize,
    pub end_column: usize,
}

#[derive(Clone)]
struct EvidenceInputs {
    source: Option<Arc<str>>,
    declarations: Option<Vec<(String, CodeUnitType, Vec<Range>)>>,
}

pub(crate) struct QualityEvidenceCache {
    inputs: HashMap<ProjectFile, EvidenceInputs>,
}

impl QualityEvidenceCache {
    pub(crate) fn new() -> Self {
        Self {
            inputs: HashMap::default(),
        }
    }

    fn inputs(&mut self, analyzer: &dyn IAnalyzer, file: &ProjectFile) -> EvidenceInputs {
        self.inputs
            .entry(file.clone())
            .or_insert_with(|| {
                let source = analyzer
                    .indexed_source(file)
                    .filter(|source| analyzer.indexed_source_matches(file, source))
                    .map(Arc::<str>::from);
                let declarations = analyzer.summary_file_projection(file).map(|projection| {
                    projection
                        .declarations
                        .iter()
                        .map(|unit| {
                            (
                                unit.fq_name().to_string(),
                                unit.kind(),
                                projection.ranges.get(unit).cloned().unwrap_or_default(),
                            )
                        })
                        .collect()
                });
                EvidenceInputs {
                    source,
                    declarations,
                }
            })
            .clone()
    }

    pub(crate) fn evidence(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        symbol: &str,
        containing_byte: Option<usize>,
        excerpt: String,
    ) -> QualityEvidence {
        let inputs = self.inputs(analyzer, file);
        let source_sha256 = inputs.source.as_ref().map(|source| {
            canonical_hash::lower_hex_string(&canonical_hash::sha256_bytes(source.as_bytes()))
        });
        let matches: Option<Vec<&(String, CodeUnitType, Vec<Range>)>> =
            inputs.declarations.as_ref().map(|declarations| {
                if let Some(byte) = containing_byte {
                    let containing = declarations
                        .iter()
                        .filter(|(_, _, ranges)| {
                            ranges
                                .iter()
                                .any(|range| range.start_byte <= byte && byte < range.end_byte)
                        })
                        .collect::<Vec<_>>();
                    let smallest_span = containing
                        .iter()
                        .flat_map(|(_, _, ranges)| ranges)
                        .filter(|range| range.start_byte <= byte && byte < range.end_byte)
                        .map(|range| range.end_byte - range.start_byte)
                        .min();
                    containing
                        .into_iter()
                        .filter(|(_, _, ranges)| {
                            ranges.iter().any(|range| {
                                range.start_byte <= byte
                                    && byte < range.end_byte
                                    && Some(range.end_byte - range.start_byte) == smallest_span
                            })
                        })
                        .collect()
                } else {
                    declarations
                        .iter()
                        .filter(|(name, _, _)| name == symbol)
                        .collect()
                }
            });
        let declaration_kind = match matches.as_deref() {
            Some([(_, kind, _)]) => kind.display_lowercase().to_string(),
            _ => "unknown".to_string(),
        };
        let location = exact_location(
            matches.as_deref(),
            inputs.source.as_deref(),
            containing_byte,
        );
        QualityEvidence {
            subject: QualitySubject {
                path: rel_path_string(file),
                symbol: matches
                    .as_deref()
                    .and_then(|matches| matches.first())
                    .map_or_else(|| symbol.to_string(), |(name, _, _)| name.clone()),
                display_symbol: symbol.to_string(),
                declaration_kind,
            },
            source_sha256,
            excerpt,
            location,
        }
    }
}

fn exact_location(
    matches: Option<&[&(String, CodeUnitType, Vec<Range>)]>,
    source: Option<&str>,
    containing_byte: Option<usize>,
) -> QualityLocation {
    let Some(matches) = matches else {
        return QualityLocation::Unavailable {
            reason: QualityLocationUnavailableReason::DeclarationProjectionUnavailable,
        };
    };
    let ranges = matches
        .iter()
        .flat_map(|(_, _, ranges)| ranges.iter().copied())
        .filter(|range| {
            containing_byte.is_none_or(|byte| range.start_byte <= byte && byte < range.end_byte)
        })
        .collect::<Vec<_>>();
    let range = match ranges.as_slice() {
        [range] => *range,
        [] => {
            return QualityLocation::Unavailable {
                reason: QualityLocationUnavailableReason::DeclarationRangeUnavailable,
            };
        }
        _ => {
            return QualityLocation::Unavailable {
                reason: QualityLocationUnavailableReason::AmbiguousDeclarationLocation,
            };
        }
    };
    let Some(source) = source else {
        return QualityLocation::Unavailable {
            reason: QualityLocationUnavailableReason::IndexedSourceUnavailable,
        };
    };
    if range.start_byte > range.end_byte
        || range.end_byte > source.len()
        || !source.is_char_boundary(range.start_byte)
        || !source.is_char_boundary(range.end_byte)
    {
        return QualityLocation::Unavailable {
            reason: QualityLocationUnavailableReason::SourceRangeInvalid,
        };
    }
    let starts = compute_line_starts(source);
    let (start_line, start_column) = line_column_for_offset(source, &starts, range.start_byte);
    let (end_line, end_column) = line_column_for_offset(source, &starts, range.end_byte);
    QualityLocation::Exact {
        range: QualityRange {
            start_byte: range.start_byte,
            end_byte: range.end_byte,
            start_line,
            end_line,
            start_column,
            end_column,
        },
    }
}

pub(crate) fn parameters(min_score: i32, values: &[(&str, i32)]) -> Vec<QualityParameter> {
    std::iter::once(QualityParameter {
        name: "min_score".to_string(),
        value: min_score,
    })
    .chain(values.iter().map(|(name, value)| QualityParameter {
        name: (*name).to_string(),
        value: *value,
    }))
    .collect()
}

pub(crate) fn reasons(values: &[String]) -> Vec<QualityReason> {
    values
        .iter()
        .map(|code| QualityReason { code: code.clone() })
        .collect()
}

pub(crate) fn render_quality_findings(
    structured: &StructuredQualityFindings,
    ambiguous_paths: &[AmbiguousPathInput],
    empty_message: String,
) -> String {
    if structured.findings.is_empty() {
        let suffix = if structured.completion.complete() {
            ""
        } else {
            " The request or analysis was truncated before completion."
        };
        return format!("{empty_message}.{suffix}");
    }
    let heading = match structured.finding_kind {
        QualityFindingKind::TestAssertion => "Test assertion smells",
        QualityFindingKind::StructuralClone => "Structural clone smells",
    };
    let mut lines = ReportLines::with_capacity(structured.findings.len() + 10);
    lines.line(format!("## {heading}"));
    lines.blank();
    let min_score = structured
        .parameters
        .iter()
        .find(|p| p.name == "min_score")
        .map_or(0, |p| p.value);
    lines.line(format!("- Min score: {min_score}"));
    lines.line(format!(
        "- Findings shown: {} of {}",
        structured.truncation.retained_findings,
        structured.truncation.retained_findings + structured.truncation.omitted_findings
    ));
    let weights = structured
        .parameters
        .iter()
        .filter(|p| p.name != "min_score")
        .map(|p| format!("{}={}", p.name, p.value))
        .collect::<Vec<_>>()
        .join(", ");
    lines.line(format!("- Weights: {weights}"));
    append_ambiguous_path_notes(&mut lines, ambiguous_paths);
    lines.blank();
    match structured.finding_kind {
        QualityFindingKind::TestAssertion => {
            lines.line("| Score | Kind | Assertions | Symbol | File | Reasons | Excerpt |");
            lines.line("|------:|------|-----------:|--------|------|---------|---------|");
            for finding in &structured.findings {
                let QualityFinding::TestAssertion(f) = finding else {
                    unreachable!()
                };
                lines.line(format!(
                    "| {} | `{}` | {} | `{}` | `{}` | `{}` | `{}` |",
                    f.metrics.score,
                    sanitize_table_cell(&f.assertion_kind),
                    f.metrics.assertion_count,
                    sanitize_table_cell(&f.evidence.subject.display_symbol),
                    sanitize_table_cell(&f.evidence.subject.path),
                    sanitize_table_cell(
                        &f.reasons
                            .iter()
                            .map(|r| r.code.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    sanitize_table_cell(&f.evidence.excerpt)
                ));
            }
        }
        QualityFindingKind::StructuralClone => {
            lines.line("| Score | Tokens | Symbol | Peer Symbol | Reasons | Excerpt |");
            lines.line("|------:|-------:|--------|-------------|---------|---------|");
            for finding in &structured.findings {
                let QualityFinding::StructuralClone(f) = finding else {
                    unreachable!()
                };
                lines.line(format!(
                    "| {} | {} | `{}` ({}) | `{}` ({}) | `{}` | `{}` |",
                    f.metrics.score,
                    f.metrics.normalized_token_count,
                    sanitize_table_cell(&f.primary.subject.display_symbol),
                    sanitize_table_cell(&f.primary.subject.path),
                    sanitize_table_cell(&f.peer.subject.display_symbol),
                    sanitize_table_cell(&f.peer.subject.path),
                    sanitize_table_cell(
                        &f.reasons
                            .iter()
                            .map(|r| r.code.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    sanitize_table_cell(&f.primary.excerpt)
                ));
            }
        }
    }
    if !structured.completion.input_complete || !structured.completion.analysis_complete {
        lines.blank();
        lines.line("- Note: request or analysis truncated before completion.");
    } else if !structured.completion.retention_complete {
        lines.blank();
        lines.line("- Note: output truncated; increase maxFindings to see more.");
    }
    lines.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_contract_round_trips_unavailable_evidence() {
        let report = StructuredQualityFindings::new(
            QualityFindingKind::TestAssertion,
            parameters(4, &[("noAssertion", 5)]),
            vec![QualityFinding::TestAssertion(TestAssertionQualityFinding {
                assertion_kind: "none".to_string(),
                reasons: vec![QualityReason {
                    code: "no-assertion".to_string(),
                }],
                metrics: TestAssertionQualityMetrics {
                    score: 5,
                    assertion_count: 0,
                },
                evidence: QualityEvidence {
                    subject: QualitySubject {
                        path: "src/example.py".to_string(),
                        symbol: "Example.test_same".to_string(),
                        display_symbol: "Example.test_same".to_string(),
                        declaration_kind: "function".to_string(),
                    },
                    source_sha256: None,
                    excerpt: "value = `a|b`".to_string(),
                    location: QualityLocation::Unavailable {
                        reason: QualityLocationUnavailableReason::IndexedSourceUnavailable,
                    },
                },
            })],
            true,
            true,
            1,
            2,
        );
        let encoded = serde_json::to_value(&report).expect("serialize quality report");
        let decoded: StructuredQualityFindings =
            serde_json::from_value(encoded.clone()).expect("deserialize quality report");
        assert_eq!(encoded["schema_id"], QUALITY_FINDINGS_SCHEMA_ID);
        assert_eq!(encoded["schema_version"], QUALITY_FINDINGS_SCHEMA_VERSION);
        assert_eq!(encoded["findings"][0]["kind"], "test_assertion");
        assert_eq!(
            encoded["findings"][0]["evidence"]["excerpt"],
            "value = `a|b`"
        );
        assert_eq!(
            encoded["findings"][0]["evidence"]["location"]["status"],
            "unavailable"
        );
        assert_eq!(decoded.truncation.omitted_findings, 1);
        assert!(!decoded.completion.retention_complete);
    }
}
