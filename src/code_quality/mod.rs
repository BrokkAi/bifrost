//! MCP code-quality tools (cyclomatic + cognitive complexity, comment
//! density, exception-handling smells, long-method / god-object). Each
//! tool lives in its own submodule; shared helpers (file resolution,
//! markdown line buffer, weights formatter, sentinel weight pickers,
//! cyclomatic primitive) sit here in `mod.rs`.
//!
//! All public handler functions and their `*Params` / `*Result` types
//! are re-exported at this module's surface so the import paths in
//! `searchtools_service.rs` (and any future caller) stay flat:
//! `crate::code_quality::compute_cyclomatic_complexity` etc.

use crate::analyzer::{CodeUnit, IAnalyzer, Project, ProjectFile};
use crate::path_utils::workspace_rel_path;
use regex::Regex;
use std::sync::LazyLock;

// Bound MCP-supplied path lists so a single call cannot allocate an
// unbounded `Vec<String>` of report lines or pin the analyzer scanning
// thousands of files. Mirrors the per-tool caps already used in
// `file_tools.rs` / `git_tools.rs`.
pub(crate) const MAX_FILE_PATHS: usize = 200;

// Hard cap on report lines (one line per flagged function). Protects the
// JSON-RPC transport from megabyte-scale responses on pathological input.
pub(crate) const MAX_REPORT_LINES: usize = 500;

// Per-function source-text size cap before the regex scan. Beyond this,
// the function's complexity defaults to the base of 1 — treating an
// unanalyzably large body as opaque rather than spinning the regex engine
// over multiple megabytes per code unit.
pub(crate) const MAX_SOURCE_BYTES: usize = 1_000_000;

// Heuristic cyclomatic-complexity decision points. Mirrors brokk-shared
// `IAnalyzer.COMPLEXITY_KEYWORDS` / `COMPLEXITY_OPERATORS` exactly so the
// scores produced here match the brokk-core MCP byte-for-byte.
static COMPLEXITY_KEYWORDS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(if|while|for|switch|case|catch)\b").expect("valid regex"));
static COMPLEXITY_OPERATORS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&&|\|\||\?").expect("valid regex"));

/// Outcome of resolving a list of caller-supplied file paths against the
/// project. Shared across the per-tool handlers in this module that follow
/// the same trim → workspace_rel_path → file_by_rel_path → exists pipeline.
///
/// Note: `report_comment_density_for_files` deliberately doesn't use this
/// helper — it emits per-input "Missing file (skipped)" inline lines and
/// has its own cap accounting that wouldn't fit the silent-skip contract.
pub(crate) struct ResolvedFiles {
    pub files: Vec<ProjectFile>,
    /// Count of inputs that were silently dropped (empty / unresolvable /
    /// not in the project / missing on disk). Duplicates that pass all
    /// checks are NOT counted here — callers that want dedup can apply
    /// it after.
    pub skipped_inputs: usize,
    /// `true` when the caller supplied more than [`MAX_FILE_PATHS`] inputs.
    /// The tail beyond the cap is dropped without further inspection.
    pub input_truncated: bool,
}

/// Resolve a flat list of caller-supplied paths to [`ProjectFile`]s. Trims
/// each input, rejects empty strings, runs them through
/// [`workspace_rel_path`] (workspace-escape guard), looks them up in the
/// project, and requires `exists()` to be true. Inputs beyond
/// [`MAX_FILE_PATHS`] are dropped (sets `input_truncated`).
///
/// Caller is responsible for any further filtering (dedup, file-cap,
/// language gating).
pub(crate) fn resolve_project_files(project: &dyn Project, inputs: Vec<String>) -> ResolvedFiles {
    let input_truncated = inputs.len() > MAX_FILE_PATHS;
    let mut files: Vec<ProjectFile> = Vec::new();
    let mut skipped_inputs: usize = 0;
    for input in inputs.into_iter().take(MAX_FILE_PATHS) {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            skipped_inputs += 1;
            continue;
        }
        let Some(rel) = workspace_rel_path(trimmed) else {
            skipped_inputs += 1;
            continue;
        };
        let Some(file) = project.file_by_rel_path(&rel) else {
            skipped_inputs += 1;
            continue;
        };
        if !file.exists() {
            skipped_inputs += 1;
            continue;
        }
        files.push(file);
    }
    ResolvedFiles {
        files,
        skipped_inputs,
        input_truncated,
    }
}

/// Thin wrapper around `Vec<String>` for handlers that build markdown
/// reports line-by-line. Saves the per-handler boilerplate of forgetting
/// `String::new()` for blank lines and joining with `\n` at the end.
/// Doesn't try to be smart about structure — handlers vary too much
/// (flat lists, markdown tables, multi-line findings) for a richer
/// abstraction to pay off.
pub(crate) struct ReportLines {
    buf: Vec<String>,
}

impl ReportLines {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }
    pub fn line(&mut self, line: impl Into<String>) -> &mut Self {
        self.buf.push(line.into());
        self
    }
    pub fn blank(&mut self) -> &mut Self {
        self.buf.push(String::new());
        self
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }
    pub fn build(self) -> String {
        self.buf.join("\n")
    }
}

/// Render a list of (label, value) pairs as `label1=value1, label2=value2,
/// ...`. Used by the per-tool weights-line renderers. The labels are
/// literal strings (NOT Rust field names) because they need to match the
/// brokk-core MCP wire format verbatim — pulling them from `stringify!`
/// would silently desync if a Rust field is later renamed.
macro_rules! format_weights {
    ($($label:literal => $value:expr),+ $(,)?) => {{
        let parts: Vec<String> = vec![
            $(format!("{}={}", $label, $value)),+
        ];
        parts.join(", ")
    }};
}
// Make the macro callable as `format_weights!` from child modules. Modern
// Rust resolves macro_rules via textual scope, but the `pub(crate) use`
// hop is required for `format_weights!(...)` to be reachable from
// `super::*` imports without a per-file `use super::format_weights;`.
#[allow(unused_imports)]
pub(crate) use format_weights;

/// Heuristic cyclomatic complexity for a single function-like code unit.
/// Returns 0 for non-function units. Counts a base of 1 plus each
/// occurrence of `if/while/for/switch/case/catch` keywords and each
/// `&&`/`||`/`?` operator in the unit's source. Source bodies above
/// `MAX_SOURCE_BYTES` are treated as opaque (returns the base of 1).
pub fn cyclomatic_complexity_for(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> u32 {
    if !code_unit.is_function() {
        return 0;
    }
    let source = analyzer.get_source(code_unit, false).unwrap_or_default();
    if source.len() > MAX_SOURCE_BYTES {
        return 1;
    }
    let mut complexity: u32 = 1;
    complexity += COMPLEXITY_KEYWORDS.find_iter(&source).count() as u32;
    complexity += COMPLEXITY_OPERATORS.find_iter(&source).count() as u32;
    complexity
}

/// Pick `candidate` when non-negative, otherwise fall back to `fallback`.
/// `0` is treated as a valid explicit override (semantically: "disable this
/// rule"). Use this for the exception-handling-smells weight knobs. For
/// knobs where `0` is meaningless and should map to the brokk default,
/// use [`pick_positive`] instead.
pub(crate) fn pick_weight(candidate: i32, fallback: i32) -> i32 {
    if candidate >= 0 { candidate } else { fallback }
}

/// Pick `candidate` when strictly positive, otherwise fall back to
/// `fallback`. Use this for the maintainability-size weight knobs (and any
/// other knob where `0` is meaningless and should fall back to the brokk
/// default). For knobs where `0` is a valid explicit override (e.g.
/// exception-handling-smells weights — `0` correctly disables the rule),
/// use [`pick_weight`] instead.
pub(crate) fn pick_positive(candidate: i32, fallback: i32) -> i32 {
    if candidate > 0 { candidate } else { fallback }
}

/// Defensive replacement of markdown-breaking characters in table cells.
/// Mirrors brokk's [`CodeQualityToolsMcp.sanitizeTableCell`]: pipe characters
/// are escaped, backticks become apostrophes (so attacker-controlled paths
/// cannot break out of the inline code span and inject markdown into
/// downstream LLM consumers), and control characters collapse to a single
/// space so each row remains valid GFM.
pub(crate) fn sanitize_table_cell(value: &str) -> String {
    let escaped = value.replace('|', "\\|").replace('`', "'");
    escaped
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

mod cognitive;
mod comment_density;
mod cyclomatic;
mod exception_smells;
mod maintainability_size;

pub use cognitive::{
    ComputeCognitiveComplexityParams, ComputeCognitiveComplexityResult,
    compute_cognitive_complexity,
};
pub use comment_density::{
    ReportCommentDensityForCodeUnitParams, ReportCommentDensityForCodeUnitResult,
    ReportCommentDensityForFilesParams, ReportCommentDensityForFilesResult,
    report_comment_density_for_code_unit, report_comment_density_for_files,
};
pub use cyclomatic::{
    ComputeCyclomaticComplexityParams, ComputeCyclomaticComplexityResult,
    compute_cyclomatic_complexity,
};
pub use exception_smells::{
    ReportExceptionHandlingSmellsParams, ReportExceptionHandlingSmellsResult,
    report_exception_handling_smells,
};
pub use maintainability_size::{
    ReportLongMethodAndGodObjectSmellsParams, ReportLongMethodAndGodObjectSmellsResult,
    find_long_method_and_god_object_smells, report_long_method_and_god_object_smells,
};
