//! MCP `report_long_method_and_god_object_smells` handler + the generic
//! `find_long_method_and_god_object_smells` algorithm. Ports
//! brokk-shared's `IAnalyzer.findLongMethodAndGodObjectSmells` and
//! brokk-core's `CodeQualityToolsMcp.reportLongMethodAndGodObjectSmells`
//! to bifrost. Output is byte-for-byte equivalent to brokk-core MCP.

use super::{ReportLines, cyclomatic_complexity_for, pick_positive, resolve_project_files};
use crate::analyzer::common::language_for_target;
use crate::analyzer::{
    CodeUnit, IAnalyzer, Language, MaintainabilitySizeSmell, MaintainabilitySizeSmellWeights,
    ProjectFile, Range,
};
use crate::path_utils::rel_path_string;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

const DEFAULT_LONG_METHOD_MAX_FINDINGS: i32 = 20;
const DEFAULT_LONG_METHOD_MAX_FILES: i32 = 25;
/// Per-file declaration ceiling for the maintainability-size walk. Bounds
/// the worst-case work on a single pathologically large generated file
/// (e.g. multi-megabyte UI bindings, generated protobuf). Equal to roughly
/// 50k declarations — well above any real Java source we expect.
const MAX_DECLARATIONS_PER_FILE: usize = 50_000;

/// Ports brokk-shared `IAnalyzer.findLongMethodAndGodObjectSmells` to bifrost.
/// Walks the analyzer's declaration tree for `file` iteratively (post-order
/// DFS, like [`cyclomatic_complexity_for`]'s sibling handler) and scores
/// each function / class / module against the long-method and god-object
/// thresholds in `weights`.
///
/// The algorithm is intentionally generic: any analyzer that implements the
/// trait primitives (`get_top_level_declarations`, `get_direct_children`,
/// `ranges_of`) participates. Per-function cyclomatic complexity is computed
/// via [`cyclomatic_complexity_for`] (shared with
/// `compute_cyclomatic_complexity`).
///
/// **Sort note:** findings are returned in declaration-walk order, *not* the
/// final report order. Callers that merge findings across files (e.g.
/// [`report_long_method_and_god_object_smells`]) must apply
/// [`maintainability_size_smell_cmp`] before rendering.
///
/// **Recursion bound:** the walk aborts after [`MAX_DECLARATIONS_PER_FILE`]
/// declarations have been visited, returning the partial findings collected
/// so far. Pathological generated files cannot cause unbounded work.
pub fn find_long_method_and_god_object_smells(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    weights: MaintainabilitySizeSmellWeights,
) -> Vec<MaintainabilitySizeSmell> {
    let mut findings: Vec<MaintainabilitySizeSmell> = Vec::new();
    // `visited` guards against cycles or shared sub-trees: if a CodeUnit is
    // reached via two paths, the second visit short-circuits and contributes
    // default metrics to its parent — mirroring brokk-shared
    // `IAnalyzer.collectMaintainabilitySizeSmells`'s `visited.add(cu)` guard.
    let mut visited: HashSet<CodeUnit> = HashSet::new();
    let mut metrics: HashMap<CodeUnit, MaintainabilitySizeMetrics> = HashMap::new();

    enum Frame {
        Enter(CodeUnit, bool),
        Exit(CodeUnit, bool),
    }

    let top_levels = analyzer.get_top_level_declarations(file);
    let mut stack: Vec<Frame> = Vec::with_capacity(top_levels.len() * 2);
    for cu in top_levels.into_iter().rev() {
        stack.push(Frame::Enter(cu, true));
    }

    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Enter(cu, top_level) => {
                if !visited.insert(cu.clone()) {
                    continue;
                }
                if visited.len() > MAX_DECLARATIONS_PER_FILE {
                    // Stop expanding; already-queued Exit frames will still
                    // run and produce findings for the partial subtree.
                    continue;
                }
                let children = analyzer.get_direct_children(&cu);
                stack.push(Frame::Exit(cu, top_level));
                for child in children.into_iter().rev() {
                    stack.push(Frame::Enter(child, false));
                }
            }
            Frame::Exit(cu, top_level) => {
                let cu_metrics = score_maintainability_size_unit(
                    analyzer,
                    &cu,
                    weights,
                    top_level,
                    &metrics,
                    &mut findings,
                );
                metrics.insert(cu, cu_metrics);
            }
        }
    }
    findings
}

#[derive(Debug, Clone, Copy, Default)]
struct MaintainabilitySizeMetrics {
    descendant_span_lines: u32,
    function_count: u32,
    nested_type_count: u32,
    max_function_span_lines: u32,
    max_cyclomatic_complexity: u32,
}

/// Compute scoring + metrics for a single CodeUnit using already-computed
/// child metrics from `child_metrics`. Returns the aggregate metrics that
/// the caller stores so the parent's Exit frame can roll them up.
fn score_maintainability_size_unit(
    analyzer: &dyn IAnalyzer,
    cu: &CodeUnit,
    weights: MaintainabilitySizeSmellWeights,
    top_level: bool,
    child_metrics: &HashMap<CodeUnit, MaintainabilitySizeMetrics>,
    findings: &mut Vec<MaintainabilitySizeSmell>,
) -> MaintainabilitySizeMetrics {
    let range = widest_non_empty_range_of(analyzer, cu);
    let synthetic = cu.is_synthetic();
    let own_span_lines = if synthetic { 0 } else { range.span_lines() };
    let mut max_function_span_lines = if !synthetic && cu.is_function() {
        own_span_lines
    } else {
        0
    };
    let mut max_cyclomatic_complexity = if !synthetic && cu.is_function() {
        cyclomatic_complexity_for(analyzer, cu)
    } else {
        0
    };
    let mut function_count: u32 = if !synthetic && cu.is_function() { 1 } else { 0 };
    let mut nested_type_count: u32 = if !synthetic && (cu.is_class() || cu.is_module()) {
        1
    } else {
        0
    };
    let mut descendant_span_lines = own_span_lines;

    let children = analyzer.get_direct_children(cu);
    let non_synthetic_children: Vec<CodeUnit> = children
        .iter()
        .filter(|child| !child.is_synthetic())
        .cloned()
        .collect();

    for child in &children {
        if let Some(m) = child_metrics.get(child) {
            function_count = function_count.saturating_add(m.function_count);
            nested_type_count = nested_type_count.saturating_add(m.nested_type_count);
            descendant_span_lines = descendant_span_lines.saturating_add(m.descendant_span_lines);
            max_function_span_lines = max_function_span_lines.max(m.max_function_span_lines);
            max_cyclomatic_complexity = max_cyclomatic_complexity.max(m.max_cyclomatic_complexity);
        }
    }

    if !synthetic && !range.is_empty() {
        let mut reasons: Vec<String> = Vec::new();
        let mut score: i32 = 0;
        if cu.is_function() {
            if (own_span_lines as i32) >= weights.long_method_span_lines {
                score = score.saturating_add(
                    (own_span_lines as i32).saturating_sub(weights.long_method_span_lines) + 25,
                );
                reasons.push(format!("long function spans {own_span_lines} lines"));
            }
            if (max_cyclomatic_complexity as i32) > weights.high_complexity_threshold {
                score = score.saturating_add(
                    (max_cyclomatic_complexity as i32)
                        .saturating_sub(weights.high_complexity_threshold)
                        .saturating_mul(5),
                );
                reasons.push(format!(
                    "high cyclomatic complexity {max_cyclomatic_complexity}"
                ));
            }
        } else if cu.is_class() || cu.is_module() {
            let module_leeway_multiplier = if is_file_level_module(analyzer, cu, top_level) {
                weights.file_module_leeway_multiplier
            } else {
                1
            };
            let god_object_span_lines = weights
                .god_object_span_lines
                .saturating_mul(module_leeway_multiplier);
            let god_object_direct_children = weights
                .god_object_direct_children
                .saturating_mul(module_leeway_multiplier);
            let god_object_functions = weights
                .god_object_functions
                .saturating_mul(module_leeway_multiplier);
            let helper_sprawl_functions = weights
                .helper_sprawl_functions
                .saturating_mul(module_leeway_multiplier);
            let responsibility_cluster = cu.is_class() || non_synthetic_children.len() > 1;
            let child_count = non_synthetic_children.len() as i32;

            if (own_span_lines as i32) >= god_object_span_lines {
                score = score.saturating_add(
                    ((own_span_lines as i32).saturating_sub(god_object_span_lines)) / 4 + 20,
                );
                reasons.push(format!(
                    "large {kind} spans {own_span_lines} lines",
                    kind = cu.kind().display_lowercase(),
                ));
            }
            if responsibility_cluster && child_count >= god_object_direct_children {
                score = score.saturating_add(
                    child_count
                        .saturating_sub(god_object_direct_children)
                        .saturating_mul(2)
                        + 15,
                );
                reasons.push(format!("many direct members ({child_count})"));
            }
            if responsibility_cluster && (function_count as i32) >= god_object_functions {
                score = score.saturating_add(
                    (function_count as i32)
                        .saturating_sub(god_object_functions)
                        .saturating_mul(2)
                        + 15,
                );
                reasons.push(format!(
                    "many functions in one responsibility cluster ({function_count})"
                ));
            }
            if responsibility_cluster
                && (function_count as i32) >= helper_sprawl_functions
                && (max_function_span_lines as i32) >= weights.helper_sprawl_workflow_lines
            {
                score = score.saturating_add(
                    (function_count as i32).saturating_add(max_function_span_lines as i32 / 4),
                );
                reasons.push(format!(
                    "helper sprawl around a {max_function_span_lines}-line workflow"
                ));
            }
            if (max_cyclomatic_complexity as i32) > weights.high_complexity_threshold {
                score = score.saturating_add(
                    (max_cyclomatic_complexity as i32)
                        .saturating_sub(weights.high_complexity_threshold)
                        .saturating_mul(3),
                );
                reasons.push(format!(
                    "contains high-complexity workflow (CC {max_cyclomatic_complexity})"
                ));
            }
            if score > 0 && nested_type_count > 1 {
                reasons.push(format!("nested type/module cluster ({nested_type_count})"));
            }
        }

        if score > 0 {
            findings.push(MaintainabilitySizeSmell {
                code_unit: cu.clone(),
                range,
                score,
                own_span_lines,
                descendant_span_lines,
                direct_child_count: non_synthetic_children.len() as u32,
                function_count,
                nested_type_count,
                max_function_span_lines,
                max_cyclomatic_complexity,
                reasons,
            });
        }
    }

    MaintainabilitySizeMetrics {
        descendant_span_lines,
        function_count,
        nested_type_count,
        max_function_span_lines,
        max_cyclomatic_complexity,
    }
}

/// Stable comparator for [`MaintainabilitySizeSmell`] matching brokk-shared
/// `IAnalyzer.maintainabilitySizeSmellComparator`: highest score first,
/// then case-insensitive source path, then case-insensitive fqName.
fn maintainability_size_smell_cmp(
    a: &MaintainabilitySizeSmell,
    b: &MaintainabilitySizeSmell,
) -> Ordering {
    b.score.cmp(&a.score).then_with(|| {
        rel_path_string(a.code_unit.source())
            .to_lowercase()
            .cmp(&rel_path_string(b.code_unit.source()).to_lowercase())
            .then_with(|| {
                a.code_unit
                    .fq_name()
                    .to_lowercase()
                    .cmp(&b.code_unit.fq_name().to_lowercase())
            })
    })
}

/// Widest non-empty range for `cu`, or a zero-range fallback when the
/// analyzer reports no usable ranges. Mirrors brokk-shared
/// `IAnalyzer.primaryRangeOf`. Named explicitly to distinguish from the
/// LSP-side `primary_range` helper, which selects the *first* range by
/// position rather than the widest.
fn widest_non_empty_range_of(analyzer: &dyn IAnalyzer, cu: &CodeUnit) -> Range {
    analyzer
        .ranges_of(cu)
        .into_iter()
        .filter(|range| !range.is_empty())
        .max_by_key(|range| range.span_lines())
        .unwrap_or(Range {
            start_byte: 0,
            end_byte: 0,
            start_line: 0,
            end_line: 0,
        })
}

/// True when `code_unit` is the synthetic top-level module that wraps a
/// whole source file in module-oriented languages (JS/TS, Python, Rust,
/// Go, C++ and friends). Used by the maintainability-size heuristic to
/// apply a leeway multiplier to file-wide modules.
///
/// Java is explicitly excluded: bifrost's JavaAnalyzer emits a synthetic
/// `Module` CodeUnit for each package, but those are not "file-level
/// modules" in the brokk sense — they don't span source lines and they
/// should keep the class-style scoring thresholds. brokk-shared's
/// JavaAnalyzer doesn't override `isFileLevelModule` (default = false);
/// mirroring that here keeps the heuristic byte-for-byte equivalent.
fn is_file_level_module(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit, top_level: bool) -> bool {
    if !top_level || !code_unit.is_module() || analyzer.parent_of(code_unit).is_some() {
        return false;
    }
    let language = language_for_target(code_unit);
    if matches!(language, Language::None | Language::Java) {
        return false;
    }
    analyzer
        .languages()
        .iter()
        .any(|loaded| *loaded == language)
}

/// Params for [`report_long_method_and_god_object_smells`].
///
/// Note: [`MaintainabilitySizeSmellWeights::file_module_leeway_multiplier`]
/// is deliberately NOT exposed as a tool argument. brokk-core MCP keeps
/// the leeway multiplier internal too; expanding this struct would break
/// byte-for-byte schema parity. Don't add the field without first
/// changing the brokk-core wrapper as well.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportLongMethodAndGodObjectSmellsParams {
    pub file_paths: Vec<String>,
    /// `<= 0` → default of `20`.
    #[serde(default)]
    pub max_findings: i32,
    /// `<= 0` → default of `25`.
    #[serde(default)]
    pub max_files: i32,
    /// All threshold knobs accept `<= 0` to keep the brokk default. Mirrors
    /// brokk-core MCP `pickPositive` semantics — zero is *not* an explicit
    /// override, so the natural `#[derive(Default)]` of `0` correctly picks
    /// up the brokk defaults.
    #[serde(default)]
    pub long_method_span_lines: i32,
    #[serde(default)]
    pub high_complexity_threshold: i32,
    #[serde(default)]
    pub god_object_span_lines: i32,
    #[serde(default)]
    pub god_object_direct_children: i32,
    #[serde(default)]
    pub god_object_functions: i32,
    #[serde(default)]
    pub helper_sprawl_functions: i32,
    #[serde(default)]
    pub helper_sprawl_workflow_lines: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportLongMethodAndGodObjectSmellsResult {
    pub report: String,
    /// `true` when input or output was clipped: either more than
    /// [`super::MAX_FILE_PATHS`] paths were supplied, the file list was
    /// clipped to `max_files`, or the findings list was clipped to
    /// `max_findings` rows.
    pub truncated: bool,
}

pub fn report_long_method_and_god_object_smells(
    analyzer: &dyn IAnalyzer,
    params: ReportLongMethodAndGodObjectSmellsParams,
) -> ReportLongMethodAndGodObjectSmellsResult {
    let findings_cap = if params.max_findings > 0 {
        params.max_findings as usize
    } else {
        DEFAULT_LONG_METHOD_MAX_FINDINGS as usize
    };
    let file_cap = if params.max_files > 0 {
        params.max_files as usize
    } else {
        DEFAULT_LONG_METHOD_MAX_FILES as usize
    };
    let defaults = MaintainabilitySizeSmellWeights::defaults();
    let weights = MaintainabilitySizeSmellWeights {
        long_method_span_lines: pick_positive(
            params.long_method_span_lines,
            defaults.long_method_span_lines,
        ),
        high_complexity_threshold: pick_positive(
            params.high_complexity_threshold,
            defaults.high_complexity_threshold,
        ),
        god_object_span_lines: pick_positive(
            params.god_object_span_lines,
            defaults.god_object_span_lines,
        ),
        god_object_direct_children: pick_positive(
            params.god_object_direct_children,
            defaults.god_object_direct_children,
        ),
        god_object_functions: pick_positive(
            params.god_object_functions,
            defaults.god_object_functions,
        ),
        helper_sprawl_functions: pick_positive(
            params.helper_sprawl_functions,
            defaults.helper_sprawl_functions,
        ),
        helper_sprawl_workflow_lines: pick_positive(
            params.helper_sprawl_workflow_lines,
            defaults.helper_sprawl_workflow_lines,
        ),
        // Not exposed as a tool argument — brokk-core MCP keeps the
        // file-module leeway multiplier internal too.
        file_module_leeway_multiplier: defaults.file_module_leeway_multiplier,
    };

    // Resolve files, then dedup and apply file_cap on top of the helper.
    // brokk-core's wrapper does `.limit(fileCap)` after path resolution;
    // mirror that here so the same JSON arguments select the same files.
    let resolved = resolve_project_files(analyzer.project(), params.file_paths);
    let mut input_truncated = resolved.input_truncated;
    let skipped_inputs = resolved.skipped_inputs;

    let mut selected_files: Vec<ProjectFile> = Vec::new();
    let mut seen_files: HashSet<ProjectFile> = HashSet::new();
    for file in resolved.files {
        if !seen_files.insert(file.clone()) {
            continue;
        }
        selected_files.push(file);
        if selected_files.len() >= file_cap {
            break;
        }
    }

    let mut findings: Vec<MaintainabilitySizeSmell> = Vec::new();
    for file in &selected_files {
        findings.extend(find_long_method_and_god_object_smells(
            analyzer, file, weights,
        ));
    }
    let selected_set: HashSet<ProjectFile> = selected_files.iter().cloned().collect();
    findings.retain(|smell| selected_set.contains(smell.code_unit.source()));
    findings.sort_by(maintainability_size_smell_cmp);

    let total = findings.len();
    let shown = findings_cap.min(total);
    if total > shown {
        input_truncated = true;
    }

    let mut lines = ReportLines::with_capacity(shown * 3 + 5);
    lines.line(format!(
        "Long method and god object smells (max findings: {findings_cap}):"
    ));
    lines.line(format!("- Files analyzed cap: {file_cap}"));
    lines.line(format!(
        "- Weights: {}",
        format_weights!(
            "longMethodLines" => weights.long_method_span_lines,
            "highComplexity" => weights.high_complexity_threshold,
            "godObjectLines" => weights.god_object_span_lines,
            "godObjectDirectChildren" => weights.god_object_direct_children,
            "godObjectFunctions" => weights.god_object_functions,
            "helperSprawlFunctions" => weights.helper_sprawl_functions,
            "helperSprawlWorkflowLines" => weights.helper_sprawl_workflow_lines,
            "fileModuleLeeway" => format!("{}x", weights.file_module_leeway_multiplier),
        )
    ));

    if findings.is_empty() {
        lines.blank();
        lines.line("No long method or god object smells found.");
        if skipped_inputs > 0 {
            lines.line(format!(
                "- Note: skipped {skipped_inputs} input(s) (empty, unresolvable, or missing)."
            ));
        }
        return ReportLongMethodAndGodObjectSmellsResult {
            report: lines.build(),
            truncated: input_truncated,
        };
    }
    for smell in findings.iter().take(shown) {
        let display_start_line = smell.range.start_line + 1;
        let display_end_line = smell.range.end_line + 1;
        lines.line(format!(
            "- `{fq}` in `{source}:{display_start_line}-{display_end_line}` [score {score}]",
            fq = smell.code_unit.fq_name(),
            source = rel_path_string(smell.code_unit.source()),
            score = smell.score,
        ));
        lines.line(format!(
            "  - Signals: own {own} lines, descendants {desc} lines, direct children {dc}, functions {fc}, nested types {nt}, max function {mfsl} lines, max CC {mcc}",
            own = smell.own_span_lines,
            desc = smell.descendant_span_lines,
            dc = smell.direct_child_count,
            fc = smell.function_count,
            nt = smell.nested_type_count,
            mfsl = smell.max_function_span_lines,
            mcc = smell.max_cyclomatic_complexity,
        ));
        lines.line(format!("  - Rationale: {}", smell.reasons.join("; ")));
    }
    if skipped_inputs > 0 {
        lines.line(format!(
            "- Note: skipped {skipped_inputs} input(s) (empty, unresolvable, or missing)."
        ));
    }

    ReportLongMethodAndGodObjectSmellsResult {
        report: lines.build(),
        truncated: input_truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::AnalyzerFixture;

    fn java_statements(count: usize) -> String {
        (0..count)
            .map(|i| format!("        int value{i} = {i};"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn java_helpers(count: usize) -> String {
        (0..count)
            .map(|i| {
                format!(
                    "    private int helper{i}(int value) {{\n        return value + {i};\n    }}"
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn long_method_no_files_reports_empty() {
        let fix =
            AnalyzerFixture::new(&[("Foo.java", "package com.example; public class Foo {}\n")]);
        let result = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams::default(),
        );
        assert!(
            result
                .report
                .starts_with("Long method and god object smells (max findings: 20):"),
            "report: {}",
            result.report
        );
        assert!(result.report.contains("- Files analyzed cap: 25"));
        assert!(result.report.contains("- Weights: longMethodLines=80"));
        assert!(
            result
                .report
                .contains("No long method or god object smells found.")
        );
        assert!(!result.truncated);
    }

    #[test]
    fn long_method_small_cohesive_file_reports_nothing() {
        let java = "package com.example;\npublic class Small {\n    public int add(int left, int right) {\n        return left + right;\n    }\n}\n";
        let fix = AnalyzerFixture::new(&[("com/example/Small.java", java)]);
        let result = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["com/example/Small.java".to_string()],
                ..Default::default()
            },
        );
        assert!(
            result
                .report
                .contains("No long method or god object smells found."),
            "report: {}",
            result.report
        );
        assert!(!result.truncated);
    }

    #[test]
    fn long_method_flags_oversized_function_with_rationale() {
        let java = format!(
            "package com.example;\npublic class Workflow {{\n    public void generatedWorkflow() {{\n{body}\n    }}\n}}\n",
            body = java_statements(85),
        );
        let fix = AnalyzerFixture::new(&[("com/example/Workflow.java", java.as_str())]);
        let result = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["com/example/Workflow.java".to_string()],
                ..Default::default()
            },
        );
        assert!(
            result
                .report
                .contains("`com.example.Workflow.generatedWorkflow`"),
            "report: {}",
            result.report
        );
        assert!(result.report.contains("long function spans"));
        assert!(!result.truncated);
    }

    #[test]
    fn long_method_flags_god_object_with_helper_sprawl() {
        let java = format!(
            "package com.example;\npublic class GeneratedController {{\n    public void executeWorkflow() {{\n{body}\n    }}\n{helpers}\n}}\n",
            body = java_statements(65),
            helpers = java_helpers(16),
        );
        let fix = AnalyzerFixture::new(&[("com/example/GeneratedController.java", java.as_str())]);
        let result = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["com/example/GeneratedController.java".to_string()],
                ..Default::default()
            },
        );
        assert!(
            result.report.contains("`com.example.GeneratedController`"),
            "report: {}",
            result.report
        );
        assert!(
            result.report.contains("helper sprawl"),
            "report: {}",
            result.report
        );
        // The class line must appear before any of its helper-function lines —
        // brokk-shared documents that god object ranks above its workflow helper.
        let class_pos = result
            .report
            .find("`com.example.GeneratedController` in")
            .unwrap();
        let workflow_pos = result
            .report
            .find("`com.example.GeneratedController.executeWorkflow`")
            .unwrap_or(usize::MAX);
        assert!(class_pos < workflow_pos);
    }

    #[test]
    fn long_method_custom_threshold_overrides_default() {
        // 12 statements, below the default 80-line threshold but above a
        // custom 10-line override.
        let java = format!(
            "package com.example;\npublic class Tunable {{\n    public void smallerWorkflow() {{\n{body}\n    }}\n}}\n",
            body = java_statements(12),
        );
        let fix = AnalyzerFixture::new(&[("com/example/Tunable.java", java.as_str())]);
        let permissive = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["com/example/Tunable.java".to_string()],
                long_method_span_lines: 10,
                ..Default::default()
            },
        );
        assert!(
            permissive
                .report
                .contains("`com.example.Tunable.smallerWorkflow`"),
            "permissive: {}",
            permissive.report
        );
        let strict = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["com/example/Tunable.java".to_string()],
                long_method_span_lines: 200,
                ..Default::default()
            },
        );
        assert!(
            strict
                .report
                .contains("No long method or god object smells found."),
            "strict: {}",
            strict.report
        );
    }

    #[test]
    fn long_method_zero_weight_falls_back_to_default() {
        // Zero is *not* an explicit override for this tool (pick_positive
        // semantics) — passing 0 must reproduce the default behaviour, not
        // disable the rule.
        let java = format!(
            "package com.example;\npublic class Workflow {{\n    public void generatedWorkflow() {{\n{body}\n    }}\n}}\n",
            body = java_statements(85),
        );
        let fix = AnalyzerFixture::new(&[("com/example/Workflow.java", java.as_str())]);
        let result = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["com/example/Workflow.java".to_string()],
                long_method_span_lines: 0,
                ..Default::default()
            },
        );
        assert!(
            result.report.contains("long function spans"),
            "report: {}",
            result.report
        );
        // Weights header must still print the *default* 80, not 0.
        assert!(result.report.contains("longMethodLines=80"));
    }

    #[test]
    fn long_method_max_findings_truncates_output() {
        let java = format!(
            "package com.example;\npublic class A {{\n    public void big() {{\n{body}\n    }}\n}}\nclass B {{\n    public void big() {{\n{body}\n    }}\n}}\n",
            body = java_statements(85),
        );
        let fix = AnalyzerFixture::new(&[("com/example/A.java", java.as_str())]);
        let result = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["com/example/A.java".to_string()],
                max_findings: 1,
                ..Default::default()
            },
        );
        assert!(result.truncated, "report: {}", result.report);
        assert_eq!(
            result.report.matches("[score ").count(),
            1,
            "report: {}",
            result.report
        );
    }

    #[test]
    fn long_method_missing_file_is_skipped() {
        let fix =
            AnalyzerFixture::new(&[("Foo.java", "package com.example; public class Foo {}\n")]);
        let result = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["does/not/exist.java".to_string()],
                ..Default::default()
            },
        );
        assert!(
            result
                .report
                .contains("No long method or god object smells found.")
        );
        // The skipped-inputs footer must surface the silent drop.
        assert!(
            result
                .report
                .contains("- Note: skipped 1 input(s) (empty, unresolvable, or missing)."),
            "report: {}",
            result.report
        );
        assert!(!result.truncated);
    }

    #[test]
    fn long_method_max_files_caps_analyzed_set() {
        // Two files each contain a god-object class. Cap at 1 file; only the
        // first (alphabetical-input-order) one should be analyzed.
        let java_a = format!(
            "package com.example;\npublic class AlphaController {{\n    public void run() {{\n{body}\n    }}\n{helpers}\n}}\n",
            body = java_statements(65),
            helpers = java_helpers(16),
        );
        let java_b = format!(
            "package com.example;\npublic class BetaController {{\n    public void run() {{\n{body}\n    }}\n{helpers}\n}}\n",
            body = java_statements(65),
            helpers = java_helpers(16),
        );
        let fix = AnalyzerFixture::new(&[
            ("com/example/AlphaController.java", java_a.as_str()),
            ("com/example/BetaController.java", java_b.as_str()),
        ]);
        let result = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec![
                    "com/example/AlphaController.java".to_string(),
                    "com/example/BetaController.java".to_string(),
                ],
                max_files: 1,
                ..Default::default()
            },
        );
        assert!(
            result.report.contains("`com.example.AlphaController`"),
            "report: {}",
            result.report
        );
        assert!(
            !result.report.contains("`com.example.BetaController`"),
            "Beta should have been excluded by max_files=1; report: {}",
            result.report
        );
    }

    #[test]
    fn is_file_level_module_excludes_java_package_modules() {
        // Java package modules are NOT file-level in the brokk sense; they
        // must keep class-style scoring thresholds. This test guards the
        // explicit Language::Java exclusion in is_file_level_module.
        let java = "package com.example;\npublic class Foo {}\n";
        let fix = AnalyzerFixture::new(&[("com/example/Foo.java", java)]);
        let analyzer = fix.analyzer.analyzer();
        let package_modules: Vec<_> = analyzer
            .get_top_level_declarations(
                &analyzer
                    .project()
                    .file_by_rel_path(std::path::Path::new("com/example/Foo.java"))
                    .unwrap(),
            )
            .into_iter()
            .filter(|cu| cu.is_module())
            .collect();
        for module_cu in &package_modules {
            assert!(
                !is_file_level_module(analyzer, module_cu, true),
                "Java package module should not be treated as file-level: {:?}",
                module_cu
            );
        }
    }

    #[test]
    fn is_file_level_module_rejects_non_module_and_non_top_level() {
        let java = "package com.example;\npublic class Foo { public void m() {} }\n";
        let fix = AnalyzerFixture::new(&[("com/example/Foo.java", java)]);
        let analyzer = fix.analyzer.analyzer();
        let file = analyzer
            .project()
            .file_by_rel_path(std::path::Path::new("com/example/Foo.java"))
            .unwrap();
        let class_cu = analyzer
            .get_top_level_declarations(&file)
            .into_iter()
            .find(|cu| cu.is_class())
            .expect("expected the Foo class");
        assert!(
            !is_file_level_module(analyzer, &class_cu, true),
            "non-module CU must never be flagged file-level"
        );
        for cu in analyzer.get_top_level_declarations(&file) {
            if cu.is_module() {
                assert!(
                    !is_file_level_module(analyzer, &cu, false),
                    "top_level=false must always reject"
                );
            }
        }
    }

    #[test]
    fn long_method_synthetic_constructor_does_not_inflate_god_object() {
        // brokk-shared's `ignoresSyntheticConstructorAtThresholdBoundary`
        // checks that a Java class's synthetic constructor doesn't push the
        // class over the god-object thresholds.
        let java = format!(
            "package com.example;\npublic class Boundary {{\n{helpers}\n}}\n",
            helpers = java_helpers(14),
        );
        let fix = AnalyzerFixture::new(&[("com/example/Boundary.java", java.as_str())]);
        let result = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["com/example/Boundary.java".to_string()],
                long_method_span_lines: 999,
                high_complexity_threshold: 999,
                god_object_span_lines: 999,
                god_object_direct_children: 15,
                god_object_functions: 15,
                helper_sprawl_functions: 999,
                helper_sprawl_workflow_lines: 999,
                ..Default::default()
            },
        );
        assert!(
            result
                .report
                .contains("No long method or god object smells found."),
            "synthetic constructor must not count toward direct-children / functions; report: {}",
            result.report
        );
    }
}
