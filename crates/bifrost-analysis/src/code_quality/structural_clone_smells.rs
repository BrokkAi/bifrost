//! MCP `report_structural_clone_smells` handler. Runs the analyzer's
//! structural-clone detection heuristic across the given files, applies
//! Brokk-compatible defaults, dedupes symmetric findings, and renders the
//! same markdown table shape as brokk-core MCP.

use super::{
    resolve_project_files,
    structured_quality::{
        MAX_QUALITY_FINDINGS, QualityEvidenceCache, QualityFinding, QualityFindingKind,
        StructuralCloneQualityFinding, StructuralCloneQualityMetrics, StructuredQualityFindings,
        parameters, reasons, render_quality_findings,
    },
};
use crate::analyzer::{CloneSmell, CloneSmellWeights, IAnalyzer};
use crate::path_utils::AmbiguousPathInput;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const DEFAULT_MAX_FINDINGS: i32 = 80;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportStructuralCloneSmellsParams {
    pub file_paths: Vec<String>,
    #[serde(default)]
    pub min_score: i32,
    #[serde(default)]
    pub min_normalized_tokens: i32,
    #[serde(default)]
    pub shingle_size: i32,
    #[serde(default)]
    pub min_shared_shingles: i32,
    #[serde(default)]
    pub ast_similarity_percent: i32,
    #[serde(default)]
    pub max_findings: i32,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ReportStructuralCloneSmellsResult {
    pub report: String,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
    pub structured: StructuredQualityFindings,
}

pub fn report_structural_clone_smells(
    analyzer: &dyn IAnalyzer,
    params: ReportStructuralCloneSmellsParams,
) -> ReportStructuralCloneSmellsResult {
    let defaults = CloneSmellWeights::defaults();
    let threshold = if params.min_score > 0 {
        params.min_score
    } else {
        defaults.min_similarity_percent
    };
    let requested_findings_cap = if params.max_findings > 0 {
        params.max_findings as usize
    } else {
        DEFAULT_MAX_FINDINGS as usize
    };
    let findings_cap = requested_findings_cap.min(MAX_QUALITY_FINDINGS);
    let weights = CloneSmellWeights {
        min_normalized_tokens: if params.min_normalized_tokens > 0 {
            params.min_normalized_tokens
        } else {
            defaults.min_normalized_tokens
        },
        min_similarity_percent: threshold,
        shingle_size: if params.shingle_size > 0 {
            params.shingle_size
        } else {
            defaults.shingle_size
        },
        min_shared_shingles: if params.min_shared_shingles > 0 {
            params.min_shared_shingles
        } else {
            defaults.min_shared_shingles
        },
        ast_similarity_percent: if params.ast_similarity_percent > 0 {
            params.ast_similarity_percent
        } else {
            defaults.ast_similarity_percent
        },
    };

    let resolved = resolve_project_files(analyzer, params.file_paths);
    let findings = analyzer.find_structural_clone_smells_for_files(&resolved.files, weights);
    let ambiguous_paths = resolved.ambiguous_paths.clone();
    let mut deduped: BTreeMap<String, CloneSmell> = BTreeMap::new();
    for finding in findings {
        let left = format!("{}#{}", finding.file, finding.enclosing_fq_name);
        let right = format!("{}#{}", finding.peer_file, finding.peer_enclosing_fq_name);
        let key = if left <= right {
            format!("{left}||{right}")
        } else {
            format!("{right}||{left}")
        };
        deduped
            .entry(key)
            .and_modify(|existing| {
                if finding.score > existing.score {
                    *existing = finding.clone();
                }
            })
            .or_insert(finding);
    }

    let mut filtered: Vec<CloneSmell> = deduped
        .into_values()
        .filter(|finding| finding.score >= threshold)
        .collect();
    filtered.sort_by(structural_clone_smell_cmp);
    let shown = findings_cap.min(filtered.len());
    let mut cache = QualityEvidenceCache::new();
    let structured_findings = filtered
        .iter()
        .take(shown)
        .map(|finding| {
            QualityFinding::StructuralClone(StructuralCloneQualityFinding {
                reasons: reasons(&finding.reasons),
                metrics: StructuralCloneQualityMetrics {
                    score: finding.score,
                    normalized_token_count: finding.normalized_token_count,
                },
                primary: cache.evidence(
                    analyzer,
                    &finding.file,
                    &finding.enclosing_fq_name,
                    None,
                    finding.excerpt.clone(),
                ),
                peer: cache.evidence(
                    analyzer,
                    &finding.peer_file,
                    &finding.peer_enclosing_fq_name,
                    None,
                    finding.peer_excerpt.clone(),
                ),
            })
        })
        .collect();
    let structured = StructuredQualityFindings::new(
        QualityFindingKind::StructuralClone,
        parameters(
            threshold,
            &[
                ("minTokens", weights.min_normalized_tokens),
                ("shingleSize", weights.shingle_size),
                ("minShared", weights.min_shared_shingles),
                ("astThreshold", weights.ast_similarity_percent),
            ],
        ),
        structured_findings,
        !resolved.input_truncated
            && resolved.skipped_inputs == 0
            && resolved.ambiguous_paths.is_empty(),
        true,
        requested_findings_cap,
        filtered.len(),
    );
    let report = render_quality_findings(
        &structured,
        &ambiguous_paths,
        format!("No structural clone smells met minScore {threshold}"),
    );
    let truncated = !structured.completion.complete();

    ReportStructuralCloneSmellsResult {
        report,
        truncated,
        ambiguous_paths,
        structured,
    }
}

fn structural_clone_smell_cmp(left: &CloneSmell, right: &CloneSmell) -> std::cmp::Ordering {
    right
        .score
        .cmp(&left.score)
        .then_with(|| left.file.to_string().cmp(&right.file.to_string()))
        .then_with(|| left.enclosing_fq_name.cmp(&right.enclosing_fq_name))
        .then_with(|| left.peer_file.to_string().cmp(&right.peer_file.to_string()))
        .then_with(|| {
            left.peer_enclosing_fq_name
                .cmp(&right.peer_enclosing_fq_name)
        })
}
