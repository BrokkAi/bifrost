//! MCP `report_long_method_and_god_object_smells` handler + the generic
//! `find_long_method_and_god_object_smells` algorithm. Ports
//! brokk-shared's `IAnalyzer.findLongMethodAndGodObjectSmells` and
//! brokk-core's `CodeQualityToolsMcp.reportLongMethodAndGodObjectSmells`
//! to bifrost. Output is byte-for-byte equivalent to brokk-core MCP.

use crate::code_quality::ReportLines;

use crate::code_quality::append_ambiguous_path_notes;

use crate::code_quality::cyclomatic_complexities_from_projection;

use crate::code_quality::cyclomatic_complexity_for;

use crate::code_quality::pick_positive;

use crate::code_quality::resolve_project_files;

use brokk_bifrost_core::analyzer::common::language_for_target;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::MaintainabilitySizeSmell;

use brokk_bifrost_core::analyzer::model::MaintainabilitySizeSmellWeights;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::analyzer::model::SummaryFileProjection;

use brokk_bifrost_analysis::path_utils::AmbiguousPathInput;

use brokk_bifrost_core::path_utils::rel_path_string;
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
/// trait primitives (`top_level_declarations`, `direct_children`, `ranges`)
/// participates. Per-function cyclomatic complexity is computed
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
/// so far and whether work was omitted. Pathological generated files cannot
/// cause unbounded work.
fn find_long_method_and_god_object_smells(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    weights: MaintainabilitySizeSmellWeights,
) -> (Vec<MaintainabilitySizeSmell>, bool) {
    if let Some(projection) = analyzer.summary_file_projection(file)
        && let Some(source) = analyzer
            .indexed_source(file)
            .or_else(|| analyzer.project().read_source(file).ok())
    {
        return find_maintainability_size_smells_from_projection(&projection, &source, weights);
    }
    find_maintainability_size_smells_from_analyzer(analyzer, file, weights)
}

fn find_maintainability_size_smells_from_analyzer(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    weights: MaintainabilitySizeSmellWeights,
) -> (Vec<MaintainabilitySizeSmell>, bool) {
    let mut findings: Vec<MaintainabilitySizeSmell> = Vec::new();
    // `visited` guards against cycles or shared sub-trees: if a CodeUnit is
    // reached via two paths, the second visit short-circuits and contributes
    // default metrics to its parent — mirroring brokk-shared
    // `IAnalyzer.collectMaintainabilitySizeSmells`'s `visited.add(cu)` guard.
    let mut visited: HashSet<CodeUnit> = HashSet::new();
    let mut metrics: HashMap<CodeUnit, MaintainabilitySizeMetrics> = HashMap::new();
    let mut truncated = false;

    enum Frame {
        Enter(CodeUnit, bool),
        Exit(CodeUnit, bool),
    }

    let top_levels = analyzer.top_level_declarations(file);
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
                    truncated = true;
                    continue;
                }
                let children = analyzer.direct_children(&cu);
                stack.push(Frame::Exit(cu, top_level));
                for child in children.into_iter().rev() {
                    stack.push(Frame::Enter(child, false));
                }
            }
            Frame::Exit(cu, top_level) => {
                let range = widest_non_empty_range_of(analyzer, &cu);
                let children = analyzer.direct_children(&cu);
                let cu_metrics = score_maintainability_size_unit(
                    &cu,
                    range,
                    &children,
                    cyclomatic_complexity_for(analyzer, &cu),
                    is_file_level_module(analyzer, &cu, top_level),
                    weights,
                    &metrics,
                    &mut findings,
                );
                metrics.insert(cu, cu_metrics);
            }
        }
    }
    (findings, truncated)
}

fn find_maintainability_size_smells_from_projection(
    projection: &SummaryFileProjection,
    source: &str,
    weights: MaintainabilitySizeSmellWeights,
) -> (Vec<MaintainabilitySizeSmell>, bool) {
    let complexities: HashMap<CodeUnit, u32> =
        cyclomatic_complexities_from_projection(projection, source)
            .into_iter()
            .collect();
    let child_units: HashSet<CodeUnit> = projection
        .children
        .values()
        .flat_map(|children| children.iter().cloned())
        .collect();
    let mut findings = Vec::new();
    let mut visited = HashSet::new();
    let mut metrics = HashMap::new();
    let mut truncated = false;

    enum Frame {
        Enter(CodeUnit, bool),
        Exit(CodeUnit, bool),
    }

    let mut stack = Vec::with_capacity(projection.top_level_declarations.len() * 2);
    for code_unit in projection.top_level_declarations.iter().rev() {
        stack.push(Frame::Enter(code_unit.clone(), true));
    }
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Enter(code_unit, top_level) => {
                if !visited.insert(code_unit.clone()) {
                    continue;
                }
                if visited.len() > MAX_DECLARATIONS_PER_FILE {
                    truncated = true;
                    continue;
                }
                stack.push(Frame::Exit(code_unit.clone(), top_level));
                if let Some(children) = projection.children.get(&code_unit) {
                    for child in children.iter().rev() {
                        stack.push(Frame::Enter(child.clone(), false));
                    }
                }
            }
            Frame::Exit(code_unit, top_level) => {
                let range = widest_non_empty_projection_range(projection, &code_unit);
                let children = projection
                    .children
                    .get(&code_unit)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let language = language_for_target(&code_unit);
                let file_level_module = top_level
                    && code_unit.is_module()
                    && !child_units.contains(&code_unit)
                    && !matches!(language, Language::None | Language::Java);
                let unit_metrics = score_maintainability_size_unit(
                    &code_unit,
                    range,
                    children,
                    complexities.get(&code_unit).copied().unwrap_or_default(),
                    file_level_module,
                    weights,
                    &metrics,
                    &mut findings,
                );
                metrics.insert(code_unit, unit_metrics);
            }
        }
    }
    (findings, truncated)
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
#[allow(clippy::too_many_arguments)]
fn score_maintainability_size_unit(
    cu: &CodeUnit,
    range: Range,
    children: &[CodeUnit],
    own_cyclomatic_complexity: u32,
    file_level_module: bool,
    weights: MaintainabilitySizeSmellWeights,
    child_metrics: &HashMap<CodeUnit, MaintainabilitySizeMetrics>,
    findings: &mut Vec<MaintainabilitySizeSmell>,
) -> MaintainabilitySizeMetrics {
    let synthetic = cu.is_synthetic();
    let own_span_lines = if synthetic { 0 } else { range.span_lines() };
    let mut max_function_span_lines = if !synthetic && cu.is_function() {
        own_span_lines
    } else {
        0
    };
    let mut max_cyclomatic_complexity = if !synthetic && cu.is_function() {
        own_cyclomatic_complexity
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

    let non_synthetic_children: Vec<CodeUnit> = children
        .iter()
        .filter(|child| !child.is_synthetic())
        .cloned()
        .collect();

    for child in children {
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
            let module_leeway_multiplier = if file_level_module {
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
        .ranges(cu)
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

fn widest_non_empty_projection_range(
    projection: &SummaryFileProjection,
    code_unit: &CodeUnit,
) -> Range {
    projection
        .ranges
        .get(code_unit)
        .into_iter()
        .flatten()
        .filter(|range| !range.is_empty())
        .max_by_key(|range| range.span_lines())
        .cloned()
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
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
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
    let resolved = resolve_project_files(analyzer, params.file_paths);
    let mut input_truncated = resolved.input_truncated;
    let skipped_inputs = resolved.skipped_inputs;
    let ambiguous_paths = resolved.ambiguous_paths.clone();

    let mut selected_files: Vec<ProjectFile> = Vec::new();
    let mut seen_files: HashSet<ProjectFile> = HashSet::new();
    for file in resolved.files {
        if !seen_files.insert(file.clone()) {
            continue;
        }
        if selected_files.len() == file_cap {
            input_truncated = true;
            break;
        }
        selected_files.push(file);
    }

    let mut findings: Vec<MaintainabilitySizeSmell> = Vec::new();
    for file in &selected_files {
        let (file_findings, file_truncated) =
            find_long_method_and_god_object_smells(analyzer, file, weights);
        findings.extend(file_findings);
        input_truncated |= file_truncated;
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
        append_ambiguous_path_notes(&mut lines, &ambiguous_paths);
        return ReportLongMethodAndGodObjectSmellsResult {
            report: lines.build(),
            truncated: input_truncated,
            ambiguous_paths,
        };
    }
    for smell in findings.iter().take(shown) {
        let display_start_line = smell.range.start_line;
        let display_end_line = smell.range.end_line;
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
    append_ambiguous_path_notes(&mut lines, &ambiguous_paths);

    ReportLongMethodAndGodObjectSmellsResult {
        report: lines.build(),
        truncated: input_truncated,
        ambiguous_paths,
    }
}

#[cfg(test)]
mod tests {

    use crate::code_quality::maintainability_size::*;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;

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
    fn java_implicit_constructor_does_not_inflate_god_object() {
        // Java's compiler-provided default constructor is not an analyzer CodeUnit, so a class
        // with fourteen real methods must remain below a fifteen-child threshold.
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
            "implicit constructor must not count toward direct-children / functions; report: {}",
            result.report
        );
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
    #[hardwon(
        "f5ff17edf170: file cap hid a skipped distinct file without marking the report truncated"
    )]
    fn file_cap_reports_only_actual_cuts() {
        let fix = AnalyzerFixture::new(&[("a/A.java", "class A {}"), ("b/B.java", "class B {}")]);
        let paths = vec!["a/A.java".to_string(), "b/B.java".to_string()];
        let request = |file_paths, max_files| {
            report_long_method_and_god_object_smells(
                fix.analyzer.analyzer(),
                ReportLongMethodAndGodObjectSmellsParams {
                    file_paths,
                    max_files,
                    ..Default::default()
                },
            )
        };
        assert!(!request(paths.clone(), 2).truncated);
        assert!(request(paths.clone(), 1).truncated);
        assert!(!request(vec![paths[0].clone(), paths[0].clone()], 1).truncated);
    }

    #[test]
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[hardwon(
        "f5ff17edf170: declaration cap hid skipped declarations without marking the report truncated"
    )]
    fn declaration_cap_reports_only_actual_cuts() {
        for (methods, expected_truncated) in [(49_999, false), (50_000, true)] {
            let mut source = String::from("class Boundary {\n");
            for i in 0..methods {
                source.push_str(&format!("void m{i}() {{}}\n"));
            }
            source.push_str("}\n");
            let fix = AnalyzerFixture::new(&[("Boundary.java", source.as_str())]);
            let result = report_long_method_and_god_object_smells(
                fix.analyzer.analyzer(),
                ReportLongMethodAndGodObjectSmellsParams {
                    file_paths: vec!["Boundary.java".to_string()],
                    ..Default::default()
                },
            );
            assert_eq!(result.truncated, expected_truncated, "methods: {methods}");
        }
    }

    #[test]
    fn size_report_includes_each_top_level_declaration_at_threshold() {
        let fix = AnalyzerFixture::new(&[(
            "Both.java",
            "class Alpha { void run() {} }\nclass Beta { void run() {} }\n",
        )]);
        let result = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["Both.java".to_string()],
                long_method_span_lines: 1,
                max_findings: 2,
                ..Default::default()
            },
        );
        assert!(result.report.contains("Alpha.run"), "{}", result.report);
        assert!(result.report.contains("Beta.run"), "{}", result.report);
        assert!(!result.truncated);
    }

    #[test]
    fn size_report_exact_findings_cap_and_zero_threshold_use_defaults() {
        let fix = AnalyzerFixture::new(&[("Short.java", "class Short { void run() {} }\n")]);
        let paths = vec!["Short.java".to_string()];
        let ordinary = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: paths.clone(),
                long_method_span_lines: 0,
                ..Default::default()
            },
        );
        assert!(!ordinary.truncated);
        assert!(
            ordinary
                .report
                .contains("No long method or god object smells found.")
        );
        let exact = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: paths,
                long_method_span_lines: 1,
                max_findings: 1,
                ..Default::default()
            },
        );
        assert!(exact.report.contains("Short.run"), "{}", exact.report);
        assert!(!exact.truncated);
    }

    #[test]
    fn path_input_cap_accepts_exactly_two_hundred_valid_paths() {
        let fix = AnalyzerFixture::new(&[("A.java", "class A {}\n")]);
        let request = |count| {
            report_long_method_and_god_object_smells(
                fix.analyzer.analyzer(),
                ReportLongMethodAndGodObjectSmellsParams {
                    file_paths: vec!["A.java".to_string(); count],
                    ..Default::default()
                },
            )
        };
        assert!(!request(200).truncated);
        assert!(request(201).truncated);
    }

    #[test]
    fn ambiguous_basename_reports_the_requested_input_without_a_missing_note() {
        let fix = AnalyzerFixture::new(&[
            ("left/Same.java", "class Same {}\n"),
            ("right/Same.java", "class Same {}\n"),
        ]);
        let result = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["Same.java".to_string()],
                ..Default::default()
            },
        );
        assert_eq!(result.ambiguous_paths.len(), 1);
        assert!(
            result.report.contains("ambiguous input `Same.java`"),
            "{}",
            result.report
        );
        assert!(
            !result.report.contains("skipped 1 input"),
            "{}",
            result.report
        );
    }

    #[test]
    fn long_method_uses_its_own_threshold_when_god_object_threshold_differs() {
        let body = (0..58).map(|_| "int x = 1;\n").collect::<String>();
        let source = format!("class Tall {{ void run() {{\n{body}}} }}\n");
        let fix = AnalyzerFixture::new(&[("Tall.java", source.as_str())]);
        let result = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["Tall.java".to_string()],
                long_method_span_lines: 50,
                god_object_span_lines: 200,
                ..Default::default()
            },
        );
        assert!(result.report.contains("Tall.run"), "{}", result.report);
    }

    #[test]
    fn complexity_at_high_threshold_does_not_add_a_high_reason() {
        let source = "class Boundary { void run() { if (true) {} } }\n";
        let fix = AnalyzerFixture::new(&[("Boundary.java", source)]);
        let result = report_long_method_and_god_object_smells(
            fix.analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["Boundary.java".to_string()],
                long_method_span_lines: 1,
                high_complexity_threshold: 2,
                ..Default::default()
            },
        );
        assert!(result.report.contains("Boundary.run"), "{}", result.report);
        assert!(
            !result.report.contains("high cyclomatic complexity"),
            "{}",
            result.report
        );
    }

    #[test]
    fn cyclomatic_report_visits_both_methods_of_a_class() {
        use crate::code_quality::{
            ComputeCyclomaticComplexityParams, compute_cyclomatic_complexity,
        };

        let fix = AnalyzerFixture::new(&[(
            "Both.java",
            "class Both { void first() { if (true) {} } void second() { if (true) {} } }\n",
        )]);
        let result = compute_cyclomatic_complexity(
            fix.analyzer.analyzer(),
            ComputeCyclomaticComplexityParams {
                file_paths: vec!["Both.java".to_string()],
                threshold: 1,
            },
        );
        assert!(result.report.contains("Both.first"), "{}", result.report);
        assert!(result.report.contains("Both.second"), "{}", result.report);
    }

    #[test]
    fn explicit_zero_exception_weight_disables_generic_exception_signal() {
        use crate::code_quality::{
            ReportExceptionHandlingSmellsParams, report_exception_handling_smells,
        };

        let source = "class Catcher { void run() { try { throw new Exception(); } catch (Exception e) {} } }\n";
        let fix = AnalyzerFixture::new(&[("Catcher.java", source)]);
        let request = |weight| {
            report_exception_handling_smells(
                fix.analyzer.analyzer(),
                ReportExceptionHandlingSmellsParams {
                    file_paths: vec!["Catcher.java".to_string()],
                    min_score: 1,
                    generic_exception_weight: weight,
                    empty_body_weight: 0,
                    small_body_weight: 0,
                    ..Default::default()
                },
            )
        };
        let enabled = request(10);
        let disabled = request(0);
        assert!(
            enabled.report.contains("Catcher.java"),
            "{}",
            enabled.report
        );
        assert!(
            !disabled.report.contains("| `Catcher.java`"),
            "{}",
            disabled.report
        );
    }

    #[test]
    fn empty_dead_code_scope_discovers_a_second_analyzed_file() {
        use crate::code_quality::{
            ReportDeadCodeAndUnusedAbstractionSmellsParams,
            report_dead_code_and_unused_abstraction_smells,
        };

        let fix = AnalyzerFixture::new(&[
            (
                "Alpha.java",
                "class Alpha { private void unusedAlpha() {} }\n",
            ),
            ("Beta.java", "class Beta { private void unusedBeta() {} }\n"),
        ]);
        let result = report_dead_code_and_unused_abstraction_smells(
            fix.analyzer.analyzer(),
            ReportDeadCodeAndUnusedAbstractionSmellsParams {
                file_paths: vec![],
                min_score: 1,
                ..Default::default()
            },
        );
        assert!(result.report.contains("unusedAlpha"), "{}", result.report);
        assert!(result.report.contains("unusedBeta"), "{}", result.report);
    }

    #[test]
    fn cyclomatic_report_line_cap_counts_all_flagged_functions() {
        use crate::code_quality::{
            ComputeCognitiveComplexityParams, ComputeCyclomaticComplexityParams,
            compute_cognitive_complexity, compute_cyclomatic_complexity,
        };

        for (count, cut) in [(499, false), (501, true)] {
            let mut source = String::from("class Many {\n");
            for i in 0..count {
                source.push_str(&format!(
                    "void method{i}() {{ if (true) {{ if (true) {{}} }} }}\n"
                ));
            }
            source.push_str("}\n");
            let fix = AnalyzerFixture::new(&[("Many.java", source.as_str())]);
            let result = compute_cyclomatic_complexity(
                fix.analyzer.analyzer(),
                ComputeCyclomaticComplexityParams {
                    file_paths: vec!["Many.java".to_string()],
                    threshold: 1,
                },
            );
            assert_eq!(result.truncated, cut, "count: {count}");
            assert_eq!(
                result
                    .report
                    .lines()
                    .filter(|line| line.starts_with("- "))
                    .count(),
                count.min(500)
            );
            let cognitive = compute_cognitive_complexity(
                fix.analyzer.analyzer(),
                ComputeCognitiveComplexityParams {
                    file_paths: vec!["Many.java".to_string()],
                    threshold: 1,
                },
            );
            assert_eq!(cognitive.truncated, cut, "count: {count}");
            assert_eq!(
                cognitive
                    .report
                    .lines()
                    .filter(|line| line.starts_with("- "))
                    .count(),
                count.min(500)
            );
        }
    }

    #[test]
    fn empty_quality_report_keeps_incomplete_input_caveat() {
        use crate::code_quality::{ReportTestAssertionSmellsParams, report_test_assertion_smells};

        let fix = AnalyzerFixture::new(&[("Present.java", "class Present {}\n")]);
        let result = report_test_assertion_smells(
            fix.analyzer.analyzer(),
            ReportTestAssertionSmellsParams {
                file_paths: vec!["Missing.java".to_string()],
                ..Default::default()
            },
        );
        assert!(result.truncated);
        assert!(
            result.report.contains("truncated before completion"),
            "{}",
            result.report
        );
    }

    #[test]
    fn quality_excerpt_pipe_stays_inside_one_markdown_cell() {
        use crate::code_quality::{ReportTestAssertionSmellsParams, report_test_assertion_smells};

        let fix = AnalyzerFixture::new(&[(
            "SampleTest.java",
            "import org.junit.jupiter.api.Test; import static org.junit.jupiter.api.Assertions.assertEquals; class SampleTest { @Test void sameValue() { assertEquals(\"a|b\", \"a|b\"); } }\n",
        )]);
        let result = report_test_assertion_smells(
            fix.analyzer.analyzer(),
            ReportTestAssertionSmellsParams {
                file_paths: vec!["SampleTest.java".to_string()],
                min_score: 1,
                ..Default::default()
            },
        );
        assert!(result.report.contains("a\\|b"), "{}", result.report);
        for line in result
            .report
            .lines()
            .filter(|line| line.starts_with("| ") && line.contains("SampleTest"))
        {
            assert_eq!(line.matches(" | ").count(), 6, "{line}");
        }
    }

    #[test]
    fn cyclomatic_source_byte_cap_accepts_exact_boundary() {
        use crate::code_quality::{
            ComputeCyclomaticComplexityParams, compute_cyclomatic_complexity,
        };

        for (size, expected_finding) in [(1_000_000, true), (1_000_001, false)] {
            let mut method = String::from("void run() { if (true) {} ");
            while method.len() + 10_000 < size - 1 {
                method.push_str(&" ".repeat(9_999));
                method.push('\n');
            }
            method.push_str(&" ".repeat(size - 1 - method.len()));
            method.push('}');
            assert_eq!(method.len(), size);
            let source = format!("class Boundary {{ {method} }}\n");
            let fix = AnalyzerFixture::new(&[("Boundary.java", source.as_str())]);
            let result = compute_cyclomatic_complexity(
                fix.analyzer.analyzer(),
                ComputeCyclomaticComplexityParams {
                    file_paths: vec!["Boundary.java".to_string()],
                    threshold: 1,
                },
            );
            assert_eq!(
                result.report.contains("Boundary.run"),
                expected_finding,
                "size: {size}; report: {}",
                result.report
            );
        }
    }

    #[test]
    fn cyclomatic_report_keeps_overlay_functions_without_a_summary_projection() {
        use crate::code_quality::{
            ComputeCyclomaticComplexityParams, compute_cyclomatic_complexity,
        };
        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
        use brokk_bifrost_core::analyzer::model::Language;
        use brokk_bifrost_core::analyzer::project::{OverlayProject, Project};
        use std::sync::Arc;

        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("lib.rs", "fn branch() { if true {} }\n")
            .build();
        let base = fixture.workspace_analyzer(AnalyzerConfig::default());
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(
            fixture.root().join("lib.rs"),
            "fn branch() { if true {} }\n".to_string()
        ));
        let analyzer = base.clone_with_project(overlay as Arc<dyn Project>);
        let result = compute_cyclomatic_complexity(
            analyzer.analyzer(),
            ComputeCyclomaticComplexityParams {
                file_paths: vec!["lib.rs".to_string()],
                threshold: 1,
            },
        );
        assert!(result.report.contains("branch"), "{}", result.report);
        let size = report_long_method_and_god_object_smells(
            analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["lib.rs".to_string()],
                long_method_span_lines: 1,
                high_complexity_threshold: 1,
                ..Default::default()
            },
        );
        assert!(
            size.report.contains("high cyclomatic complexity 2"),
            "{}",
            size.report
        );
    }

    #[test]
    fn overlay_long_method_uses_method_threshold() {
        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
        use brokk_bifrost_core::analyzer::model::Language;
        use brokk_bifrost_core::analyzer::project::{OverlayProject, Project};
        use std::sync::Arc;

        let source = "fn tall() {\n let a = 1;\n let b = 2;\n let c = 3;\n}\n";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("lib.rs", source)
            .build();
        let base = fixture.workspace_analyzer(AnalyzerConfig::default());
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(fixture.root().join("lib.rs"), source.to_string()));
        let analyzer = base.clone_with_project(overlay as Arc<dyn Project>);
        let result = report_long_method_and_god_object_smells(
            analyzer.analyzer(),
            ReportLongMethodAndGodObjectSmellsParams {
                file_paths: vec!["lib.rs".to_string()],
                long_method_span_lines: 3,
                god_object_span_lines: 200,
                ..Default::default()
            },
        );
        assert!(result.report.contains("tall"), "{}", result.report);
        assert!(
            result.report.contains("long function spans 5 lines"),
            "{}",
            result.report
        );
    }
}
