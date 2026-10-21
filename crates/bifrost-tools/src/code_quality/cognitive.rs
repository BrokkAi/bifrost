//! MCP `compute_cognitive_complexity` handler. Walks the language's
//! tree-sitter AST via [`IAnalyzer::compute_cognitive_complexities`] and
//! flags functions whose score exceeds the threshold. Output format
//! mirrors brokk-core's `CodeQualityToolsMcp.computeCognitiveComplexity`
//! byte-for-byte (`- <fqName>: <complexity>`, no source-path suffix).

use crate::code_quality::MAX_REPORT_LINES;

use crate::code_quality::ReportLines;

use crate::code_quality::append_ambiguous_path_notes;

use crate::code_quality::resolve_project_files;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_analysis::path_utils::AmbiguousPathInput;
use serde::{Deserialize, Serialize};

const DEFAULT_COGNITIVE_THRESHOLD: i32 = 15;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeCognitiveComplexityParams {
    pub file_paths: Vec<String>,
    #[serde(default)]
    pub threshold: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComputeCognitiveComplexityResult {
    pub report: String,
    /// `true` when input or output was clipped: either more than
    /// `MAX_FILE_PATHS` paths were supplied, or the report hit
    /// `MAX_REPORT_LINES` flagged functions.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
}

pub fn compute_cognitive_complexity(
    analyzer: &dyn IAnalyzer,
    params: ComputeCognitiveComplexityParams,
) -> ComputeCognitiveComplexityResult {
    let limit = if params.threshold > 0 {
        params.threshold
    } else {
        DEFAULT_COGNITIVE_THRESHOLD
    };
    let resolved = resolve_project_files(analyzer, params.file_paths);
    let mut truncated = resolved.input_truncated;
    let ambiguous_paths = resolved.ambiguous_paths.clone();

    let mut lines = ReportLines::new();
    lines.line(format!("Cognitive complexity (threshold: {limit}):"));
    append_ambiguous_path_notes(&mut lines, &ambiguous_paths);
    let mut found_any = false;
    let mut report_full = false;

    'outer: for file in &resolved.files {
        for (cu, complexity) in analyzer.compute_cognitive_complexities(file) {
            if cu.is_synthetic() {
                continue;
            }
            if (complexity as i32) <= limit {
                continue;
            }
            if lines.len() > MAX_REPORT_LINES {
                truncated = true;
                report_full = true;
                break 'outer;
            }
            lines.line(format!("- {fq}: {complexity}", fq = cu.fq_name()));
            found_any = true;
        }
    }

    let report = if found_any {
        if report_full {
            lines.line(format!(
                "(report truncated at {MAX_REPORT_LINES} flagged functions)"
            ));
        }
        lines.build()
    } else {
        format!("No methods exceeded the cognitive complexity threshold of {limit}.")
    };
    ComputeCognitiveComplexityResult {
        report,
        truncated,
        ambiguous_paths,
    }
}
