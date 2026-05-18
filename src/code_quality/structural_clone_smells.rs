//! MCP `report_structural_clone_smells` handler. Runs the analyzer's
//! structural-clone detection heuristic across the given files, applies
//! Brokk-compatible defaults, dedupes symmetric findings, and renders the
//! same markdown table shape as brokk-core MCP.

use super::{ReportLines, resolve_project_files, sanitize_table_cell};
use crate::analyzer::{CloneSmell, CloneSmellWeights, IAnalyzer};
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

#[derive(Debug, Clone, Serialize)]
pub struct ReportStructuralCloneSmellsResult {
    pub report: String,
    pub truncated: bool,
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
    let findings_cap = if params.max_findings > 0 {
        params.max_findings as usize
    } else {
        DEFAULT_MAX_FINDINGS as usize
    };
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

    let resolved = resolve_project_files(analyzer.project(), params.file_paths);
    let findings = analyzer.find_structural_clone_smells_for_files(&resolved.files, weights);
    let mut truncated = resolved.input_truncated;
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
    if filtered.is_empty() {
        return ReportStructuralCloneSmellsResult {
            report: format!("No structural clone smells met minScore {threshold}."),
            truncated,
        };
    }

    let shown = findings_cap.min(filtered.len());
    let rows_truncated = filtered.len() > shown;
    truncated |= rows_truncated;

    let mut lines = ReportLines::with_capacity(shown + 8);
    lines.line("## Structural clone smells");
    lines.blank();
    lines.line(format!("- Min score: {threshold}"));
    lines.line(format!("- Findings shown: {shown} of {}", filtered.len()));
    lines.line(format!(
        "- Weights: minTokens={}, shingleSize={}, minShared={}, astThreshold={}",
        weights.min_normalized_tokens,
        weights.shingle_size,
        weights.min_shared_shingles,
        weights.ast_similarity_percent
    ));
    lines.blank();
    lines.line("| Score | Tokens | Symbol | Peer Symbol | Reasons | Excerpt |");
    lines.line("|------:|-------:|--------|-------------|---------|---------|");
    for finding in filtered.into_iter().take(shown) {
        lines.line(format!(
            "| {} | {} | `{}` ({}) | `{}` ({}) | `{}` | `{}` |",
            finding.score,
            finding.normalized_token_count,
            sanitize_table_cell(&finding.enclosing_fq_name),
            sanitize_table_cell(&finding.file.to_string()),
            sanitize_table_cell(&finding.peer_enclosing_fq_name),
            sanitize_table_cell(&finding.peer_file.to_string()),
            sanitize_table_cell(&finding.reasons.join(", ")),
            sanitize_table_cell(&finding.excerpt),
        ));
    }
    if rows_truncated {
        lines.blank();
        lines.line("- Note: output truncated; increase maxFindings to see more.");
    }

    ReportStructuralCloneSmellsResult {
        report: lines.build(),
        truncated,
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
