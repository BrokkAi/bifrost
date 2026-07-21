//! Oracle-free contract fuzzing of the MCP searchtools surface.
//!
//! This module implements the engine half of `bifrost_mcp_property_fuzzer`:
//! given an in-process analyzer (and, in later milestones, the service layer),
//! it generates probes from the index Bifrost itself built and checks
//! self-consistency invariants (I1..I5 in `.agents/plans/mcp_property_fuzzer.md`)
//! that need no external ground truth. Every violation is recorded with a
//! failure signature — `(invariant, language, tool, syntactic shape)` — so a
//! corpus with thousands of instances of the same bug yields one ledger entry
//! with an occurrence count, not thousands.
//!
//! M1 scope: I1 (range integrity) as a pure index walk. I1 has four parts:
//! (a) a container symbol's ranges must contain the ranges of its indexed
//! members; (b) the text at a symbol's primary range must contain the symbol's
//! terminal name token; (c) `get_symbol_sources` must return text identical to
//! the file content at the reported range; (d) a class declaration's range
//! must not end immediately before a tree-sitter ERROR node. Parts (a), (b),
//! and (d) need no tool calls and are implemented here; part (c) arrives with
//! the service-layer wiring in M2.
//!
//! Part (a) is restricted to the containment claims the index actually makes:
//! modules are excluded (packages legitimately span files), and class parents
//! in Rust, Go, and C/C++ are excluded because those languages declare type
//! members out of body (`impl` blocks, Go receiver methods, out-of-line
//! `Foo::bar` definitions). Without that gate every idiomatic Rust type with
//! an impl block reads as a violation.
//!
//! Part (d) covers the failure mode part (a) cannot see: when the parser
//! truncates a declaration so severely that its body becomes a sibling ERROR
//! node, no members are indexed at all, so containment has no children to
//! check (the original #1016 report: `JobCtrl` indexed at lines 25..26 with
//! every method silently absent). And part (b) skips auxiliary constructors:
//! Scala's `def this` is indexed under the class name by CodeUnit convention,
//! so the class identifier legitimately never appears in the range text.
//!
//! Part (d) needs tree-sitter ERROR nodes, which the analyzer retains only
//! for files parsed in the current session (`fresh_parse_errors`); files
//! served warm from the persisted blob store report `None` and are counted
//! under `skipped_parse_errors_unavailable` rather than guessed at. Fuzzer
//! runs over fresh clones — and any `--cache-mode ephemeral` run — are always
//! cold, so the check is fully live there.

use crate::analyzer::common::display_identifier_for_target;
use crate::analyzer::{CodeUnit, CodeUnitType, IAnalyzer, ParseError, ParseErrorKind, Range};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// The contract invariants the fuzzer can check. Parsing accepts all five so
/// the CLI surface is stable; the engine rejects any that are not implemented
/// yet, which keeps milestone extension a localized change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InvariantKind {
    I1,
    I2,
    I3,
    I4,
    I5,
}

impl InvariantKind {
    pub fn code(self) -> &'static str {
        match self {
            Self::I1 => "I1",
            Self::I2 => "I2",
            Self::I3 => "I3",
            Self::I4 => "I4",
            Self::I5 => "I5",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_uppercase().as_str() {
            "I1" => Ok(Self::I1),
            "I2" => Ok(Self::I2),
            "I3" => Ok(Self::I3),
            "I4" => Ok(Self::I4),
            "I5" => Ok(Self::I5),
            _ => Err(format!(
                "unknown invariant `{value}`; expected a comma-separated list drawn from I1,I2,I3,I4,I5"
            )),
        }
    }

    /// Parse a comma-separated `--invariants` value, preserving order and
    /// rejecting duplicates so a repeated invariant cannot double-count.
    pub fn parse_list(value: &str) -> Result<Vec<Self>, String> {
        let mut parsed = Vec::new();
        for part in value.split(',') {
            let invariant = Self::parse(part)?;
            if parsed.contains(&invariant) {
                return Err(format!(
                    "duplicate invariant `{}` in --invariants",
                    invariant.code()
                ));
            }
            parsed.push(invariant);
        }
        if parsed.is_empty() {
            return Err("--invariants must name at least one invariant".to_string());
        }
        Ok(parsed)
    }
}

/// Engine-side configuration. Serialized into each report and hashed into the
/// run fingerprint, so any semantic change to these fields invalidates resume
/// state exactly like FIRD's config fingerprint does.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzerConfig {
    pub corpus_language: String,
    pub invariants: Vec<InvariantKind>,
    pub max_symbols: usize,
    pub seed: u64,
}

/// One deduplicated contract violation. The first exemplar encountered
/// supplies the evidence; `occurrences` counts every instance folded into the
/// same failure signature during the run, and `exemplars` lists up to
/// [`MAX_EXEMPLARS`] distinct offending symbols for triage.
#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    /// Human-readable dedup key: `(I1, scala, index, container-range-misses-member)`.
    pub signature: String,
    pub invariant: String,
    /// MCP tool whose contract broke, or `index` for violations visible from
    /// the index alone with no tool call.
    pub tool: String,
    /// Syntactic shape of the offending construct.
    pub shape: String,
    pub language: String,
    /// Fully qualified name of the exemplar symbol.
    pub symbol: String,
    /// Project-relative path of the exemplar.
    pub path: String,
    /// Verbatim tool arguments for tool-driven invariants; absent for index
    /// walks, where the evidence stands alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<serde_json::Value>,
    pub evidence: serde_json::Value,
    /// Distinct offending symbols seen for this signature (capped), so triage
    /// can confirm whether a specific symbol (e.g. the one named in the
    /// motivating issue) is covered without a rerun.
    pub exemplars: Vec<String>,
    pub occurrences: usize,
}

/// Cap on [`Violation::exemplars`].
pub const MAX_EXEMPLARS: usize = 25;

/// Serializable copy of [`Range`] (the analyzer type does not derive serde).
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct SerRange {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub end_line: usize,
}

impl From<Range> for SerRange {
    fn from(range: Range) -> Self {
        Self {
            start_byte: range.start_byte,
            end_byte: range.end_byte,
            start_line: range.start_line,
            end_line: range.end_line,
        }
    }
}

/// Counters describing what the I1 walk saw, so a silent run is auditable
/// ("checked 12k symbols, 300 skipped because …") rather than indistinguishable
/// from a checker that never ran.
#[derive(Debug, Default, Clone, Serialize)]
pub struct I1Summary {
    pub declarations_total: usize,
    pub symbols_selected: usize,
    pub containment_checks: usize,
    pub name_token_checks: usize,
    pub skipped_synthetic: usize,
    pub skipped_anonymous: usize,
    pub skipped_no_ranges: usize,
    pub skipped_child_no_ranges: usize,
    pub skipped_cross_file_child: usize,
    /// Parents for which I1(a) does not apply: non-container kinds, modules,
    /// and class parents in languages with out-of-body member declarations
    /// (Rust `impl` blocks, Go receiver methods, out-of-line C++ definitions).
    pub skipped_containment_not_claimed: usize,
    pub skipped_non_ident_name: usize,
    pub skipped_no_source_text: usize,
    /// Callable units whose name-token check was skipped because they index as
    /// auxiliary constructors of their parent class (same display identifier).
    pub skipped_constructor_name: usize,
    /// Class declarations examined for the parse-error-boundary shape (I1d).
    pub parse_error_boundary_checks: usize,
    /// Files whose parse errors were unavailable because they were served warm
    /// from the persisted store; only freshly parsed files retain ERROR nodes.
    pub skipped_parse_errors_unavailable: usize,
}

#[derive(Debug, Serialize)]
pub struct FuzzerReport {
    pub config: FuzzerConfig,
    pub i1_summary: I1Summary,
    pub violations: Vec<Violation>,
}

impl FuzzerReport {
    pub fn violation_count(&self) -> usize {
        self.violations.iter().map(|v| v.occurrences).sum()
    }

    pub fn has_actionable_findings(&self) -> bool {
        !self.violations.is_empty()
    }
}

/// One source file's indexed text, interned so thousands of symbols from the
/// same file share one copy.
#[derive(Debug, Clone)]
pub struct I1File {
    pub path: String,
    pub text: Option<String>,
    /// Tree-sitter parse errors for this file, or `None` when the file was
    /// not freshly parsed this session (served warm from the persisted
    /// store), in which case I1(d) cannot run for its declarations.
    pub parse_errors: Option<Vec<ParseError>>,
}

/// The analyzer facts for one indexed symbol, flattened into an arena so the
/// pure checker below never touches the analyzer and can be fixture-tested
/// with fabricated inputs.
#[derive(Debug, Clone)]
pub struct SymbolFacts {
    pub fq_name: String,
    pub identifier: String,
    pub kind: CodeUnitType,
    pub file_index: usize,
    pub ranges: Vec<Range>,
    pub child_indexes: Vec<usize>,
    /// Index of the enclosing declaration in `symbols`, when both were
    /// selected and live in the same file. Used to recognize auxiliary
    /// constructors (a callable carrying its parent class's identifier).
    pub parent_index: Option<usize>,
}

/// Everything I1 needs, detached from the analyzer.
#[derive(Debug, Default, Clone)]
pub struct I1Input {
    pub files: Vec<I1File>,
    pub symbols: Vec<SymbolFacts>,
}

const SHAPE_CONTAINER_RANGE_MISSES_MEMBER: &str = "container-range-misses-member";
const SHAPE_RANGE_NAME_TOKEN_ABSENT: &str = "range-name-token-absent";
const SHAPE_RANGE_OUTSIDE_SOURCE: &str = "range-outside-source";
const SHAPE_DECLARATION_TRUNCATED_AT_PARSE_ERROR: &str = "declaration-truncated-at-parse-error";

/// I1(d) adjacency gate: the ERROR node must start within this many bytes of
/// the declaration's last byte. Near-perfect adjacency distinguishes "the
/// parser truncated this declaration and error recovery swallowed its body"
/// from an unrelated parse error elsewhere in the file. Tunable.
const PARSE_ERROR_ADJACENCY_BYTES: usize = 2;

/// I1(d) span gate: the ERROR node must span more than this many bytes,
/// filtering stray-token errors. The #1016 failure mode is an ERROR node
/// swallowing the remainder of the construct (thousands of bytes). Tunable.
const PARSE_ERROR_MIN_SPAN_BYTES: usize = 8;

/// Excerpt cap for evidence text: enough to recognize the construct, small
/// enough to keep the ledger readable.
const EVIDENCE_EXCERPT_BYTES: usize = 240;

/// Run all requested invariants over a detached I1 input. Later milestones
/// route tool-driven invariants through the service layer instead of this
/// entry point; for M1 only I1 is implemented.
pub fn run_invariants(
    analyzer: &dyn IAnalyzer,
    config: &FuzzerConfig,
) -> Result<FuzzerReport, String> {
    for invariant in &config.invariants {
        if *invariant != InvariantKind::I1 {
            return Err(format!(
                "invariant {} is not implemented yet (M1 implements I1 only)",
                invariant.code()
            ));
        }
    }
    let mut i1_summary = I1Summary::default();
    let input = collect_i1_input(analyzer, config.max_symbols, config.seed, &mut i1_summary);
    let mut violations = check_i1(&input, &config.corpus_language, &mut i1_summary);
    violations.sort_by(|left, right| {
        left.signature
            .cmp(&right.signature)
            .then_with(|| left.symbol.cmp(&right.symbol))
    });
    Ok(FuzzerReport {
        config: config.clone(),
        i1_summary,
        violations,
    })
}

/// Walk the analyzer's declaration index and detach the facts I1 needs.
///
/// Sampling is deterministic: symbols are ordered by a SHA-256 hash of
/// `(seed, fq_name, path)`, so reruns with the same seed examine the same set
/// and different seeds still correlate with identity, not iteration order.
pub fn collect_i1_input(
    analyzer: &dyn IAnalyzer,
    max_symbols: usize,
    seed: u64,
    summary: &mut I1Summary,
) -> I1Input {
    let mut selected: Vec<CodeUnit> = Vec::new();
    for unit in analyzer.all_declarations() {
        summary.declarations_total += 1;
        if unit.is_synthetic() {
            summary.skipped_synthetic += 1;
            continue;
        }
        if unit.is_anonymous() {
            summary.skipped_anonymous += 1;
            continue;
        }
        selected.push(unit);
    }
    let selected = stable_sample(selected, max_symbols, seed, |unit| {
        format!("{}\0{}", unit.fq_name(), rel_path(unit))
    });
    summary.symbols_selected = selected.len();

    let mut file_indexes: HashMap<String, usize> = HashMap::new();
    let mut input = I1Input::default();
    let mut facts_by_unit: HashMap<CodeUnit, usize> = HashMap::new();

    for unit in &selected {
        let path = rel_path(unit);
        let file_index = *file_indexes.entry(path.clone()).or_insert_with(|| {
            let parse_errors = analyzer.parse_errors(unit.source());
            if parse_errors.is_none() {
                summary.skipped_parse_errors_unavailable += 1;
            }
            input.files.push(I1File {
                text: analyzer.indexed_source(unit.source()),
                parse_errors,
                path,
            });
            input.files.len() - 1
        });
        let ranges = analyzer.ranges(unit);
        if ranges.is_empty() {
            summary.skipped_no_ranges += 1;
        }
        facts_by_unit.insert(unit.clone(), input.symbols.len());
        input.symbols.push(SymbolFacts {
            fq_name: unit.fq_name(),
            identifier: display_identifier_for_target(unit),
            kind: unit.kind(),
            file_index,
            ranges,
            child_indexes: Vec::new(),
            parent_index: None,
        });
    }

    for unit in &selected {
        let Some(&parent_index) = facts_by_unit.get(unit) else {
            continue;
        };
        for child in analyzer.direct_children(unit) {
            let Some(&child_index) = facts_by_unit.get(&child) else {
                // Child was synthetic, anonymous, or sampled out; nothing to check.
                continue;
            };
            if input.symbols[child_index].file_index != input.symbols[parent_index].file_index {
                summary.skipped_cross_file_child += 1;
                continue;
            }
            input.symbols[parent_index].child_indexes.push(child_index);
            input.symbols[child_index].parent_index = Some(parent_index);
        }
    }
    input
}

/// The pure I1 checker. Violations are deduplicated by failure signature:
/// the first exemplar supplies the evidence, later instances increment
/// `occurrences` and append their symbol to `exemplars` (capped).
pub fn check_i1(input: &I1Input, language: &str, summary: &mut I1Summary) -> Vec<Violation> {
    let mut by_signature: HashMap<String, Violation> = HashMap::new();
    let mut record = |violation: Violation| {
        by_signature
            .entry(violation.signature.clone())
            .and_modify(|existing| {
                existing.occurrences += 1;
                if existing.exemplars.len() < MAX_EXEMPLARS
                    && !existing.exemplars.contains(&violation.symbol)
                {
                    existing.exemplars.push(violation.symbol.clone());
                }
            })
            .or_insert(violation);
    };

    for symbol in input.symbols.iter() {
        if symbol.ranges.is_empty() {
            continue;
        }
        let file = &input.files[symbol.file_index];

        if containment_check_applies(symbol.kind, language) {
            for &child_index in &symbol.child_indexes {
                let child = &input.symbols[child_index];
                let Some(child_primary) = primary_range(&child.ranges) else {
                    summary.skipped_child_no_ranges += 1;
                    continue;
                };
                summary.containment_checks += 1;
                let contained = symbol.ranges.iter().any(|parent_range| {
                    parent_range.start_byte <= child_primary.start_byte
                        && child_primary.end_byte <= parent_range.end_byte
                });
                if !contained {
                    record(i1_violation(
                        language,
                        SHAPE_CONTAINER_RANGE_MISSES_MEMBER,
                        &child.fq_name,
                        &file.path,
                        serde_json::json!({
                            "parent": {
                                "fq_name": symbol.fq_name,
                                "kind": format!("{:?}", symbol.kind),
                                "ranges": ser_ranges(&symbol.ranges),
                            },
                            "child": {
                                "fq_name": child.fq_name,
                                "kind": format!("{:?}", child.kind),
                                "primary_range": SerRange::from(child_primary),
                            },
                            "expected": "some parent range contains the child's primary range",
                        }),
                    ));
                }
            }
        } else {
            summary.skipped_containment_not_claimed += 1;
        }

        if symbol.kind == CodeUnitType::Class {
            check_parse_error_boundary(symbol, file, language, summary, &mut record);
        }

        if !is_ident_like(&symbol.identifier) {
            summary.skipped_non_ident_name += 1;
            continue;
        }
        let Some(text) = file.text.as_deref() else {
            summary.skipped_no_source_text += 1;
            continue;
        };
        let primary = primary_range(&symbol.ranges).expect("ranges checked non-empty above");
        let Some(fragment) = text.get(primary.start_byte..primary.end_byte) else {
            record(i1_violation(
                language,
                SHAPE_RANGE_OUTSIDE_SOURCE,
                &symbol.fq_name,
                &file.path,
                serde_json::json!({
                    "fq_name": symbol.fq_name,
                    "primary_range": SerRange::from(primary),
                    "source_len_bytes": text.len(),
                    "expected": "primary range lies on UTF-8 boundaries inside the indexed source",
                }),
            ));
            continue;
        };
        if is_auxiliary_constructor(symbol, &input.symbols) {
            summary.skipped_constructor_name += 1;
            continue;
        }
        summary.name_token_checks += 1;
        if !fragment.contains(&symbol.identifier) {
            record(i1_violation(
                language,
                SHAPE_RANGE_NAME_TOKEN_ABSENT,
                &symbol.fq_name,
                &file.path,
                serde_json::json!({
                    "fq_name": symbol.fq_name,
                    "identifier": symbol.identifier,
                    "primary_range": SerRange::from(primary),
                    "range_text_excerpt": excerpt(fragment),
                    "expected": "text at the primary range contains the terminal name token",
                }),
            ));
        }
    }

    by_signature.into_values().collect()
}

/// I1(d): a class declaration whose last byte sits immediately before a
/// tree-sitter ERROR node was truncated by the parser; error recovery then
/// swallowed the rest of the construct, so its members vanished from the
/// index with no index-side trace. Containment cannot see this — there are
/// no indexed children left to check.
fn check_parse_error_boundary(
    symbol: &SymbolFacts,
    file: &I1File,
    language: &str,
    summary: &mut I1Summary,
    record: &mut impl FnMut(Violation),
) {
    let Some(errors) = file.parse_errors.as_deref() else {
        return; // Warm-cache file; counted at collection time.
    };
    summary.parse_error_boundary_checks += 1;
    let Some(declaration_end) = symbol.ranges.iter().map(|range| range.end_byte).max() else {
        return;
    };
    for error in errors {
        if error.kind != ParseErrorKind::Error {
            continue;
        }
        if error.range.start_byte < declaration_end {
            continue;
        }
        let gap = error.range.start_byte - declaration_end;
        if gap > PARSE_ERROR_ADJACENCY_BYTES {
            continue;
        }
        let span = error.range.end_byte.saturating_sub(error.range.start_byte);
        if span <= PARSE_ERROR_MIN_SPAN_BYTES {
            continue;
        }
        record(i1_violation(
            language,
            SHAPE_DECLARATION_TRUNCATED_AT_PARSE_ERROR,
            &symbol.fq_name,
            &file.path,
            serde_json::json!({
                "fq_name": symbol.fq_name,
                "declaration_ranges": ser_ranges(&symbol.ranges),
                "parse_error_range": SerRange::from(error.range),
                "gap_bytes": gap,
                "error_span_bytes": span,
                "expected": "no tree-sitter ERROR node immediately after the class declaration's end; adjacency means the parser truncated the declaration and its members vanished from the index",
            }),
        ));
        return; // One violation per class is enough.
    }
}

/// Auxiliary constructors index under the class name by CodeUnit convention
/// (Scala `def this`, Kotlin `constructor`), so the class identifier
/// legitimately never appears in the constructor's range text. Detected
/// structurally: a callable whose indexed parent is a class with the same
/// display identifier.
fn is_auxiliary_constructor(symbol: &SymbolFacts, symbols: &[SymbolFacts]) -> bool {
    if !symbol.kind.is_callable_kind() {
        return false;
    }
    let Some(parent_index) = symbol.parent_index else {
        return false;
    };
    let parent = &symbols[parent_index];
    parent.kind == CodeUnitType::Class && parent.identifier == symbol.identifier
}

fn i1_violation(
    language: &str,
    shape: &str,
    symbol: &str,
    path: &str,
    evidence: serde_json::Value,
) -> Violation {
    Violation {
        signature: format!("(I1, {language}, index, {shape})"),
        invariant: "I1".to_string(),
        tool: "index".to_string(),
        shape: shape.to_string(),
        language: language.to_string(),
        symbol: symbol.to_string(),
        path: path.to_string(),
        arguments: None,
        evidence,
        exemplars: vec![symbol.to_string()],
        occurrences: 1,
    }
}

/// Whether I1(a) containment applies to a parent of `kind` in `language`.
/// Beyond the container-kind gate, type parents in Rust, Go, and C/C++ are
/// excluded: those languages declare type members out of body by design
/// (`impl` blocks, Go receiver methods, out-of-line `Foo::bar` definitions),
/// so the type's declaration range legitimately does not cover its members.
/// Callable parents are always checked — nested functions and closures are
/// lexically enclosed in every corpus language.
fn containment_check_applies(kind: CodeUnitType, language: &str) -> bool {
    if !is_container_kind(kind) {
        return false;
    }
    !(kind == CodeUnitType::Class && matches!(language, "rust" | "go" | "c" | "cpp"))
}

/// I1(a) applies to symbols that can lexically contain others. Modules are
/// deliberately excluded: packages and namespaces legitimately span files and
/// discontiguous ranges, so containment is not a claim the index makes for
/// them.
fn is_container_kind(kind: CodeUnitType) -> bool {
    kind == CodeUnitType::Class || kind.is_callable_kind()
}

fn primary_range(ranges: &[Range]) -> Option<Range> {
    ranges
        .iter()
        .min_by_key(|range| (range.start_line, range.start_byte))
        .copied()
}

fn ser_ranges(ranges: &[Range]) -> Vec<SerRange> {
    ranges.iter().copied().map(SerRange::from).collect()
}

/// I1(b) only applies to identifier-shaped names. Constructors (`<init>`),
/// operators, and other symbolic names legitimately need not appear verbatim
/// at the declaration range.
fn is_ident_like(identifier: &str) -> bool {
    let mut chars = identifier.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_alphabetic() || matches!(first, '_' | '$' | '~'))
        && chars.all(|ch| ch.is_alphanumeric() || matches!(ch, '_' | '$' | '~'))
}

fn excerpt(text: &str) -> String {
    if text.len() <= EVIDENCE_EXCERPT_BYTES {
        return text.to_string();
    }
    let mut end = EVIDENCE_EXCERPT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

fn rel_path(unit: &CodeUnit) -> String {
    unit.source()
        .rel_path()
        .to_string_lossy()
        .replace('\\', "/")
}

/// Deterministically shrink `items` to at most `cap` entries by hashing
/// `(seed, key)` with SHA-256 and keeping the smallest hashes. The returned
/// order is the relative input order, so downstream output stays stable.
fn stable_sample<T>(items: Vec<T>, cap: usize, seed: u64, key: impl Fn(&T) -> String) -> Vec<T> {
    if items.len() <= cap {
        return items;
    }
    let mut keyed: Vec<(u64, usize, T)> = items
        .into_iter()
        .enumerate()
        .map(|(position, item)| (sample_hash(seed, &key(&item)), position, item))
        .collect();
    keyed.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    keyed.truncate(cap);
    keyed.sort_by_key(|(_, position, _)| *position);
    keyed.into_iter().map(|(_, _, item)| item).collect()
}

fn sample_hash(seed: u64, key: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("sha256 digest is 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_list_accepts_all_invariants_case_insensitively() {
        let parsed = InvariantKind::parse_list("i1,I3,i5").expect("parse list");
        assert_eq!(
            parsed,
            vec![InvariantKind::I1, InvariantKind::I3, InvariantKind::I5]
        );
    }

    #[test]
    fn parse_list_rejects_unknown_and_duplicates() {
        assert!(InvariantKind::parse_list("I9").is_err());
        assert!(InvariantKind::parse_list("I1,I1").is_err());
        assert!(InvariantKind::parse_list("").is_err());
    }

    #[test]
    fn stable_sample_is_deterministic_and_order_preserving() {
        let items: Vec<String> = (0..100).map(|index| format!("symbol.{index}")).collect();
        let first = stable_sample(items.clone(), 10, 7, |item| item.clone());
        let second = stable_sample(items.clone(), 10, 7, |item| item.clone());
        assert_eq!(first, second);
        assert_eq!(first.len(), 10);
        let mut sorted = first.clone();
        sorted.sort();
        assert_eq!(first, sorted, "sample preserves input order");

        let no_cap = stable_sample(items.clone(), 100, 7, |item| item.clone());
        assert_eq!(no_cap, items);
    }

    #[test]
    fn stable_sample_changes_with_seed() {
        let items: Vec<String> = (0..100).map(|index| format!("symbol.{index}")).collect();
        let first = stable_sample(items.clone(), 10, 1, |item| item.clone());
        let second = stable_sample(items, 10, 2, |item| item.clone());
        assert_ne!(first, second);
    }

    #[test]
    fn ident_like_gate() {
        assert!(is_ident_like("JobCtrl"));
        assert!(is_ident_like("_private"));
        assert!(is_ident_like("$macro$"));
        assert!(is_ident_like("~Foo"));
        assert!(!is_ident_like("<init>"));
        assert!(!is_ident_like("operator=="));
        assert!(!is_ident_like(""));
    }
}
