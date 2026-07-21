//! Service-layer probes and the I1(c)/I2–I5 checkers.
//!
//! Probe inputs derive from the same deterministic symbol sample I1 uses;
//! symbols with I1 range violations are excluded so truncated ranges cannot
//! poison derived contexts (the plan's "I1 is a prerequisite" rule). Probes
//! execute through `SearchToolsService::call_tool_output` exactly as the MCP
//! handler would — workspace-relative paths, JSON argument values — and every
//! probe except the expensive scans runs in both `render_line_numbers`
//! modes; checkers consume the structured payload and compare the mode-B
//! structured payload for drift.
//!
//! Invariants checked here (see `.agents/plans/mcp_property_fuzzer.md`):
//! - I1(c): every `SourceBlock` returned by `get_symbol_sources` must carry
//!   text identical to the file content at its reported range.
//! - I2: for each sampled symbol the selector spellings an agent plausibly
//!   writes — terminal name, fully qualified name, `path#terminal`,
//!   `path#qualified` — must resolve consistently: a strictly more specific
//!   spelling must never fail where a less specific one succeeds, and two
//!   resolved spellings must name the same declaration. Single-entry and
//!   multi-entry `get_definitions_by_reference` batches must agree.
//! - I3: (a) a symbol `get_summaries` lists under file F must resolve via
//!   `get_symbol_sources` with path F; (b) a symbol `scan_usages_by_reference`
//!   resolves must appear in `search_symbols` results for its terminal name;
//!   (c) no response may both render content for a target and report that
//!   same target in its `not_found` list. Also cross-cutting: the structured
//!   payload must not drift between render modes.
//! - I4: a failure message must not claim non-indexing ("not indexed",
//!   "outside the indexed workspace", "external crate/module") when
//!   `search_symbols` finds an in-workspace declaration with that name.
//! - I5: every failure-status response must carry actionable next-step
//!   content — a note, a candidate list, or diagnostics; an empty refusal is
//!   a violation. Probed both organically and through a small fixed set of
//!   negative shapes real agents produced in traces.

use super::{
    FuzzerConfig, I1Input, InvariantKind, SymbolFacts, Violation, ViolationSink, excerpt,
    is_ident_like, primary_range, violation,
};
use crate::analyzer::CodeUnitType;
use crate::searchtools_render::RenderOptions;
use crate::searchtools_service::{SearchToolsService, ToolOutput};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Defaults for the service-probe volume knobs in [`FuzzerConfig`]; smaller
/// than the index-walk cap because tool calls cost more than index walks.
pub const DEFAULT_MAX_SERVICE_SYMBOLS: usize = 1_000;
pub const DEFAULT_MAX_SCAN_PROBES: usize = 100;

/// Per-file cap on `get_summaries` element → `get_symbol_sources` follow-ups.
const SUMMARY_FOLLOW_UP_CAP: usize = 10;
/// How many symbols get a single-vs-batch `get_definitions_by_reference`
/// comparison probe.
const DEFINITION_BATCH_PROBES: usize = 50;
/// Failure-message phrases that claim a target is not in the workspace (I4).
const HONESTY_PHRASES: [&str; 4] = [
    "not indexed",
    "outside the indexed workspace",
    "external crate",
    "external module",
];
/// Tokens skipped when picking a reference target from a source line:
/// declaration/control-flow keywords and literals make poor references. This
/// is the union of the corpus languages' (c, cpp, csharp, go, java, js, php,
/// py, rust, scala, ts) common keywords — over-blocking is safe (it only
/// moves the probe to the next token), under-blocking produces junk probes
/// (observed: `implicit` targets on TheHive). A probe-quality heuristic, not
/// a parser.
const REFERENCE_TOKEN_STOPLIST: [&str; 172] = [
    "False",
    "None",
    "Self",
    "True",
    "abstract",
    "and",
    "as",
    "assert",
    "async",
    "await",
    "auto",
    "base",
    "bool",
    "boolean",
    "break",
    "by",
    "byte",
    "callable",
    "case",
    "catch",
    "chan",
    "char",
    "class",
    "clone",
    "companion",
    "const",
    "constructor",
    "continue",
    "crate",
    "data",
    "declare",
    "def",
    "default",
    "defer",
    "del",
    "delegate",
    "delete",
    "do",
    "double",
    "dyn",
    "dynamic",
    "echo",
    "elif",
    "else",
    "empty",
    "enum",
    "except",
    "explicit",
    "export",
    "extends",
    "extern",
    "external",
    "fallthrough",
    "false",
    "final",
    "finally",
    "float",
    "fn",
    "for",
    "foreach",
    "friend",
    "from",
    "func",
    "function",
    "get",
    "global",
    "go",
    "goto",
    "if",
    "impl",
    "implicit",
    "implements",
    "import",
    "in",
    "include",
    "init",
    "inline",
    "instanceof",
    "int",
    "interface",
    "internal",
    "is",
    "lambda",
    "lazy",
    "let",
    "lock",
    "long",
    "loop",
    "map",
    "match",
    "mixed",
    "mod",
    "move",
    "mut",
    "mutable",
    "nameof",
    "native",
    "namespace",
    "new",
    "nil",
    "noexcept",
    "nonlocal",
    "not",
    "null",
    "nullptr",
    "object",
    "of",
    "open",
    "operator",
    "or",
    "out",
    "override",
    "package",
    "params",
    "parent",
    "partial",
    "pass",
    "print",
    "private",
    "protected",
    "pub",
    "public",
    "raise",
    "range",
    "readonly",
    "record",
    "ref",
    "register",
    "require",
    "return",
    "sealed",
    "select",
    "self",
    "set",
    "short",
    "signed",
    "sizeof",
    "static",
    "string",
    "struct",
    "super",
    "suspend",
    "switch",
    "synchronized",
    "template",
    "this",
    "throw",
    "throws",
    "trait",
    "transient",
    "true",
    "try",
    "type",
    "typedef",
    "typeof",
    "undefined",
    "union",
    "unsafe",
    "unset",
    "unsigned",
    "use",
    "using",
    "val",
    "var",
    "virtual",
    "void",
    "volatile",
    "when",
    "where",
    "while",
    "with",
    "yield",
];

/// Counters describing what the service-probe phase generated, executed, and
/// checked, so a silent run is auditable per invariant rather than
/// indistinguishable from a checker that never ran.
#[derive(Debug, Default, Clone, Serialize)]
pub struct ProbeSummary {
    pub symbols_sampled: usize,
    pub symbols_excluded_range_invalid: usize,
    pub selector_probes: usize,
    pub definition_probes: usize,
    pub definition_batch_probes: usize,
    pub summary_probes: usize,
    pub scan_probes: usize,
    pub negative_probes: usize,
    pub follow_up_probes: usize,
    pub calls_executed: usize,
    pub calls_errored: usize,
    pub render_mode_comparisons: usize,
    pub i1c_source_text_checks: usize,
    pub i2_spelling_groups: usize,
    pub i3a_summary_element_checks: usize,
    pub i3b_scan_resolution_checks: usize,
    pub i3c_contradiction_checks: usize,
    pub i4_honesty_checks: usize,
    /// Failure-status entries examined for actionable content (not the count
    /// of violations found): not-found/ambiguous entries, non-resolved
    /// definition results, failed scans, and empty searches or refusals.
    pub i5_hint_checks: usize,
}

/// One tool call derived from the index, with everything a checker needs to
/// judge its outcome. Records are detached from the service so the checkers
/// are pure and fixture-testable.
#[derive(Debug, Clone)]
pub struct ProbeRecord {
    /// Stable identity, e.g. `i2:get_symbol_sources#2:a.b.Foo` (the number is
    /// the spelling's position in the specificity order).
    pub id: String,
    pub tool: &'static str,
    pub arguments: Value,
    /// Sampled symbol under test; violation exemplar.
    pub symbol_fq: String,
    /// Declaring file of the sampled symbol; violation path.
    pub symbol_path: String,
    pub kind: ProbeKind,
    pub outcome: Option<ProbeOutcome>,
}

#[derive(Debug, Clone)]
pub enum ProbeKind {
    /// I2: one spelling of the sampled symbol against a selector-taking tool;
    /// `order` ranks specificity (0 = bare terminal .. 3 = `path#qualified`).
    Spelling { order: usize, spelling: String },
    /// I2: a multi-entry `get_definitions_by_reference` batch whose per-entry
    /// outcomes must match the same entries' single-call outcomes.
    DefinitionBatch { spellings: Vec<String> },
    /// I3a: `get_summaries` on one file.
    SummaryFile,
    /// I3a follow-up: `get_symbol_sources` for one element a file summary
    /// listed, expected to resolve under `element_path`.
    SummaryElementSource { element_path: String },
    /// I3b: `scan_usages_by_reference` for one sampled symbol.
    Scan { expected_display_fq: String },
    /// I3b follow-up: `search_symbols` for the scanned symbol's terminal name.
    ScanSearch {
        expected_display_fq: String,
        expected_path: String,
    },
    /// I5: a fixed negative shape real agents produced in traces; the
    /// expectation is not resolution but a non-empty corrective hint.
    Negative { shape: &'static str },
    /// I4 follow-up: `search_symbols` for the terminal name a failure
    /// message claimed is not indexed (`disputed_name` — usually the
    /// message's backticked subject, not the failed selector).
    HonestySearch {
        failed_selector: String,
        disputed_name: String,
        claim_excerpt: String,
        origin_tool: &'static str,
    },
}

#[derive(Debug, Clone)]
pub enum ProbeOutcome {
    Structured {
        structured: Value,
        rendered_text: Option<String>,
        /// Structured payload from the same call with
        /// `render_line_numbers: false`; `None` for single-mode probes
        /// (expensive scans) and for `Text` outputs.
        mode_b_structured: Option<Value>,
    },
    /// Transport/argument error from the service layer.
    Error(String),
}

/// Run I1(c) and I2..I5 through the service layer. `invalid` carries the
/// I1-invalid symbol indexes to exclude; only invariants named in
/// `config.invariants` are checked, though cross-cutting checkers (I3c, I4,
/// I5) consume every response the requested probes produced. When
/// `probe_dump` is set, every executed record (arguments plus outcomes) is
/// written to that path as JSONL for triage; the dump is observability only
/// and does not change the run fingerprint.
pub fn run_service_invariants(
    service: &SearchToolsService,
    input: &I1Input,
    invalid: &HashSet<usize>,
    config: &FuzzerConfig,
    summary: &mut ProbeSummary,
    probe_dump: Option<&Path>,
) -> Result<Vec<Violation>, String> {
    let language = config.corpus_language.as_str();
    let mut probes = generate_probes(input, invalid, config, summary);
    execute_probes(service, &mut probes, summary);
    let mut follow_ups = derive_follow_ups(&probes, config, summary);
    execute_probes(service, &mut follow_ups, summary);
    let records: Vec<&ProbeRecord> = probes.iter().chain(follow_ups.iter()).collect();
    if let Some(path) = probe_dump {
        dump_probe_records(&records, path)?;
    }

    let mut sink = ViolationSink::default();
    check_render_mode_drift(&records, language, &mut sink);
    if config.invariants.contains(&InvariantKind::I1) {
        check_i1c(&records, input, language, &mut sink, summary);
    }
    if config.invariants.contains(&InvariantKind::I2) {
        check_i2(&records, language, &mut sink, summary);
    }
    if config.invariants.contains(&InvariantKind::I3) {
        check_i3a(&records, language, &mut sink, summary);
        check_i3b(&records, language, &mut sink, summary);
        check_i3c(&records, language, &mut sink, summary);
    }
    if config.invariants.contains(&InvariantKind::I4) {
        check_i4(&records, language, &mut sink, summary);
    }
    if config.invariants.contains(&InvariantKind::I5) {
        check_i5(&records, language, &mut sink, summary);
    }
    Ok(sink.into_sorted_vec())
}

/// Structured-payload cap per dumped record: small payloads stay verbatim so
/// triage sees exact statuses; large ones (summaries, scans) are excerpted.
const DUMP_PAYLOAD_EXCERPT_BYTES: usize = 4_096;

/// Write every executed probe record to `path` as JSONL, one line per record:
/// identity, exact arguments, kind, and the outcome (structured payload or
/// transport error, plus the mode-B payload when both render modes ran). This
/// is the triage instrument: a silent run's outcomes are invisible in the
/// ledger, and a firing one's shrunk evidence shows only the pair that fired.
pub fn dump_probe_records(records: &[&ProbeRecord], path: &Path) -> Result<(), String> {
    use std::io::Write as _;
    let mut file = std::fs::File::create(path)
        .map_err(|error| format!("failed to create probe dump `{}`: {error}", path.display()))?;
    for record in records {
        let kind = match &record.kind {
            ProbeKind::Spelling { order, spelling } => {
                json!({"kind": "spelling", "order": order, "spelling": spelling})
            }
            ProbeKind::DefinitionBatch { spellings } => {
                json!({"kind": "definition_batch", "spellings": spellings})
            }
            ProbeKind::SummaryFile => json!({"kind": "summary_file"}),
            ProbeKind::SummaryElementSource { element_path } => {
                json!({"kind": "summary_element_source", "element_path": element_path})
            }
            ProbeKind::Scan {
                expected_display_fq,
            } => {
                json!({"kind": "scan", "expected_display_fq": expected_display_fq})
            }
            ProbeKind::ScanSearch {
                expected_display_fq,
                expected_path,
            } => json!({
                "kind": "scan_search",
                "expected_display_fq": expected_display_fq,
                "expected_path": expected_path,
            }),
            ProbeKind::Negative { shape } => json!({"kind": "negative", "shape": shape}),
            ProbeKind::HonestySearch {
                failed_selector,
                disputed_name,
                origin_tool,
                ..
            } => json!({
                "kind": "honesty_search",
                "failed_selector": failed_selector,
                "disputed_name": disputed_name,
                "origin_tool": origin_tool,
            }),
        };
        let (outcome, structured, mode_b, error) = match &record.outcome {
            Some(ProbeOutcome::Structured {
                structured,
                mode_b_structured,
                ..
            }) => (
                "structured",
                dump_payload(structured),
                mode_b_structured.as_ref().map(dump_payload),
                None,
            ),
            Some(ProbeOutcome::Error(message)) => {
                ("error", Value::Null, None, Some(message.as_str()))
            }
            None => ("pending", Value::Null, None, None),
        };
        let line = json!({
            "id": record.id,
            "tool": record.tool,
            "kind": kind,
            "arguments": record.arguments,
            "symbol_fq": record.symbol_fq,
            "symbol_path": record.symbol_path,
            "outcome": outcome,
            "structured": structured,
            "mode_b_structured": mode_b,
            "error": error,
        });
        serde_json::to_writer(&mut file, &line)
            .map_err(|error| format!("failed to write probe dump `{}`: {error}", path.display()))?;
        file.write_all(b"\n")
            .map_err(|error| format!("failed to write probe dump `{}`: {error}", path.display()))?;
    }
    Ok(())
}

fn dump_payload(structured: &Value) -> Value {
    let serialized = serde_json::to_string(structured).unwrap_or_default();
    if serialized.len() <= DUMP_PAYLOAD_EXCERPT_BYTES {
        structured.clone()
    } else {
        let mut end = DUMP_PAYLOAD_EXCERPT_BYTES;
        while !serialized.is_char_boundary(end) {
            end -= 1;
        }
        json!({
            "truncated": true,
            "total_bytes": serialized.len(),
            "excerpt": &serialized[..end],
        })
    }
}

// ---------------------------------------------------------------------------
// Probe generation
// ---------------------------------------------------------------------------

fn generate_probes(
    input: &I1Input,
    invalid: &HashSet<usize>,
    config: &FuzzerConfig,
    summary: &mut ProbeSummary,
) -> Vec<ProbeRecord> {
    let mut service_symbols: Vec<usize> = Vec::new();
    for (index, symbol) in input.symbols.iter().enumerate() {
        if invalid.contains(&index) {
            summary.symbols_excluded_range_invalid += 1;
            continue;
        }
        if symbol.ranges.is_empty() || !is_ident_like(&symbol.identifier) {
            continue;
        }
        if let Some(filter) = &config.symbol_filter
            && !symbol.fq_name.contains(filter.as_str())
        {
            continue;
        }
        service_symbols.push(index);
        if service_symbols.len() >= config.max_service_symbols {
            break;
        }
    }
    summary.symbols_sampled = service_symbols.len();

    let mut probes = Vec::new();
    if config.invariants.contains(&InvariantKind::I2) {
        for &index in &service_symbols {
            let symbol = &input.symbols[index];
            let path = input.files[symbol.file_index].path.as_str();
            let spellings = spelling_set(symbol, path);
            for (order, spelling) in spellings.iter().enumerate() {
                probes.push(ProbeRecord {
                    id: format!("i2:get_symbol_sources#{order}:{}", symbol.fq_name),
                    tool: "get_symbol_sources",
                    arguments: json!({"symbols": [spelling]}),
                    symbol_fq: symbol.fq_name.clone(),
                    symbol_path: path.to_string(),
                    kind: ProbeKind::Spelling {
                        order,
                        spelling: spelling.clone(),
                    },
                    outcome: None,
                });
                summary.selector_probes += 1;
            }
            if let Some((context, target)) = definition_context(input, symbol) {
                for (order, spelling) in spellings.iter().enumerate() {
                    probes.push(ProbeRecord {
                        id: format!("i2:get_definitions_by_reference#{order}:{}", symbol.fq_name),
                        tool: "get_definitions_by_reference",
                        arguments: json!({"references": [{
                            "symbol": spelling,
                            "context": context,
                            "target": target,
                        }]}),
                        symbol_fq: symbol.fq_name.clone(),
                        symbol_path: path.to_string(),
                        kind: ProbeKind::Spelling {
                            order,
                            spelling: spelling.clone(),
                        },
                        outcome: None,
                    });
                    summary.definition_probes += 1;
                }
            }
        }
        let mut batched = 0;
        for &index in &service_symbols {
            if batched >= DEFINITION_BATCH_PROBES {
                break;
            }
            let symbol = &input.symbols[index];
            let path = input.files[symbol.file_index].path.as_str();
            let Some((context, target)) = definition_context(input, symbol) else {
                continue;
            };
            let spellings = spelling_set(symbol, path);
            // Pair the least and most specific spellings an agent would write.
            let pair = vec![spellings[0].clone(), spellings[2].clone()];
            probes.push(ProbeRecord {
                id: format!("i2:get_definitions_by_reference#batch:{}", symbol.fq_name),
                tool: "get_definitions_by_reference",
                arguments: json!({"references": pair.iter().map(|spelling| json!({
                    "symbol": spelling,
                    "context": context,
                    "target": target,
                })).collect::<Vec<_>>()}),
                symbol_fq: symbol.fq_name.clone(),
                symbol_path: path.to_string(),
                kind: ProbeKind::DefinitionBatch { spellings: pair },
                outcome: None,
            });
            batched += 1;
        }
        summary.definition_batch_probes = batched;
    }

    if config.invariants.contains(&InvariantKind::I3) {
        let mut seen_files = HashSet::new();
        for &index in &service_symbols {
            let symbol = &input.symbols[index];
            let file = &input.files[symbol.file_index];
            if seen_files.insert(file.path.clone()) {
                probes.push(ProbeRecord {
                    id: format!("i3:get_summaries:{}", file.path),
                    tool: "get_summaries",
                    arguments: json!({"targets": [file.path]}),
                    symbol_fq: symbol.fq_name.clone(),
                    symbol_path: file.path.clone(),
                    kind: ProbeKind::SummaryFile,
                    outcome: None,
                });
                summary.summary_probes += 1;
            }
        }
        for &index in service_symbols.iter().take(config.max_scan_probes) {
            let symbol = &input.symbols[index];
            let path = input.files[symbol.file_index].path.as_str();
            probes.push(ProbeRecord {
                id: format!("i3:scan_usages_by_reference:{}", symbol.fq_name),
                tool: "scan_usages_by_reference",
                arguments: json!({"symbols": [symbol.display_fq], "include_tests": false}),
                symbol_fq: symbol.fq_name.clone(),
                symbol_path: path.to_string(),
                kind: ProbeKind::Scan {
                    expected_display_fq: symbol.display_fq.clone(),
                },
                outcome: None,
            });
            summary.scan_probes += 1;
        }
    }

    if config.invariants.contains(&InvariantKind::I5) {
        let negatives = negative_probes(input, &service_symbols, &config.corpus_language);
        summary.negative_probes = negatives.len();
        probes.extend(negatives);
    }
    probes
}

/// The selector spellings an agent plausibly writes for one symbol, ordered
/// by increasing specificity: bare terminal name, fully qualified name,
/// `path#terminal`, `path#qualified`. For units whose display name collides
/// with a sibling's (a Scala companion object displays without `$`, but
/// candidate lists offer the `$`-suffixed form as the companion's unique
/// selector), the qualified spellings use the raw fq name agents would pick
/// from that candidate list; probing the companion through the stripped
/// spelling would resolve to its class — a different unit — and every
/// derived expectation would be meaningless.
fn spelling_set(symbol: &SymbolFacts, path: &str) -> Vec<String> {
    let qualified = if symbol.fq_name.ends_with('$') {
        &symbol.fq_name
    } else {
        &symbol.display_fq
    };
    vec![
        symbol.identifier.clone(),
        qualified.clone(),
        format!("{path}#{}", symbol.identifier),
        format!("{path}#{qualified}"),
    ]
}

/// Pick one real line from inside the symbol's I1-verified primary range and
/// one identifier token on it (not the symbol's own name, not a keyword) as
/// the reference target — exactly the probe shape
/// `get_definitions_by_reference` expects: verbatim context copied from the
/// symbol's body.
fn definition_context(input: &I1Input, symbol: &SymbolFacts) -> Option<(String, String)> {
    let file = &input.files[symbol.file_index];
    let text = file.text.as_deref()?;
    let primary = primary_range(&symbol.ranges)?;
    let body = text.get(primary.start_byte..primary.end_byte)?;
    for line in body.lines().skip(1) {
        if let Some(token) = first_reference_token(line, &symbol.identifier) {
            return Some((line.to_string(), token));
        }
    }
    None
}

fn first_reference_token(line: &str, own_name: &str) -> Option<String> {
    let mut token_start = None;
    for (index, ch) in line.char_indices().chain([(line.len(), ' ')]) {
        let is_token_char = ch.is_alphanumeric() || ch == '_';
        match (token_start, is_token_char) {
            (None, true) if ch.is_alphabetic() || ch == '_' => token_start = Some(index),
            (Some(start), false) => {
                let token = &line[start..index];
                if token.len() >= 2
                    && token != own_name
                    && !REFERENCE_TOKEN_STOPLIST.contains(&token)
                {
                    return Some(token.to_string());
                }
                token_start = None;
            }
            _ => {}
        }
    }
    None
}

/// The fixed negative shapes real agents produced in traces. The expectation
/// is never resolution — it is a non-empty corrective hint (I5).
fn negative_probes(input: &I1Input, service_symbols: &[usize], language: &str) -> Vec<ProbeRecord> {
    let mut probes = Vec::new();
    let first_symbol = service_symbols.first().map(|&index| &input.symbols[index]);

    // The #1019 C shape: `file::struct tag` keyword-prefixed selectors.
    if matches!(language, "c" | "cpp" | "rust")
        && let Some(symbol) = service_symbols
            .iter()
            .map(|&index| &input.symbols[index])
            .find(|symbol| symbol.kind == CodeUnitType::Class)
    {
        let path = input.files[symbol.file_index].path.as_str();
        probes.push(ProbeRecord {
            id: format!("i5:keyword-selector:{}", symbol.fq_name),
            tool: "get_symbol_sources",
            arguments: json!({"symbols": [format!("{path}::struct {}", symbol.identifier)]}),
            symbol_fq: symbol.fq_name.clone(),
            symbol_path: path.to_string(),
            kind: ProbeKind::Negative {
                shape: "keyword-prefixed-selector",
            },
            outcome: None,
        });
    }

    // The redundant `.__init__` package-suffix shape from Python traces.
    if language == "py"
        && let Some(symbol) = service_symbols
            .iter()
            .map(|&index| &input.symbols[index])
            .find(|symbol| symbol.display_fq.contains('.'))
    {
        let path = input.files[symbol.file_index].path.as_str();
        probes.push(ProbeRecord {
            id: format!("i5:redundant-init:{}", symbol.fq_name),
            tool: "get_symbol_sources",
            arguments: json!({"symbols": [format!("{}.__init__", symbol.display_fq)]}),
            symbol_fq: symbol.fq_name.clone(),
            symbol_path: path.to_string(),
            kind: ProbeKind::Negative {
                shape: "redundant-init-suffix",
            },
            outcome: None,
        });
    }

    // A file path passed where a symbol is expected.
    if let Some(symbol) = first_symbol {
        let path = input.files[symbol.file_index].path.clone();
        probes.push(ProbeRecord {
            id: format!("i5:path-as-symbol:{path}"),
            tool: "scan_usages_by_reference",
            arguments: json!({"symbols": [path]}),
            symbol_fq: symbol.fq_name.clone(),
            symbol_path: path,
            kind: ProbeKind::Negative {
                shape: "path-passed-as-symbol",
            },
            outcome: None,
        });
    }
    probes
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

fn execute_probes(
    service: &SearchToolsService,
    probes: &mut [ProbeRecord],
    summary: &mut ProbeSummary,
) {
    for probe in probes.iter_mut() {
        if probe.outcome.is_some() {
            continue;
        }
        // Scans are the expensive calls; they run single-mode.
        let run_mode_b = !matches!(probe.kind, ProbeKind::Scan { .. });
        let mut outcome = call_tool(service, probe.tool, &probe.arguments, true);
        if run_mode_b
            && let ProbeOutcome::Structured {
                mode_b_structured, ..
            } = &mut outcome
        {
            summary.render_mode_comparisons += 1;
            *mode_b_structured =
                structured_of(call_tool(service, probe.tool, &probe.arguments, false));
        }
        if matches!(outcome, ProbeOutcome::Error(_)) {
            summary.calls_errored += 1;
        }
        summary.calls_executed += 1;
        probe.outcome = Some(outcome);
    }
}

fn call_tool(
    service: &SearchToolsService,
    tool: &str,
    arguments: &Value,
    render_line_numbers: bool,
) -> ProbeOutcome {
    match service.call_tool_output(
        tool,
        arguments.clone(),
        RenderOptions {
            render_line_numbers,
        },
    ) {
        Ok(ToolOutput::Text(text)) => ProbeOutcome::Structured {
            structured: Value::String(text),
            rendered_text: None,
            mode_b_structured: None,
        },
        Ok(ToolOutput::Structured {
            structured,
            rendered_text,
        }) => ProbeOutcome::Structured {
            structured,
            rendered_text,
            mode_b_structured: None,
        },
        Err(error) => ProbeOutcome::Error(error.to_string()),
    }
}

fn structured_of(outcome: ProbeOutcome) -> Option<Value> {
    match outcome {
        ProbeOutcome::Structured { structured, .. } => Some(structured),
        ProbeOutcome::Error(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Follow-up probes (derived from first-phase outcomes)
// ---------------------------------------------------------------------------

fn derive_follow_ups(
    probes: &[ProbeRecord],
    config: &FuzzerConfig,
    summary: &mut ProbeSummary,
) -> Vec<ProbeRecord> {
    let mut follow = Vec::new();
    let want_i3 = config.invariants.contains(&InvariantKind::I3);
    let want_i4 = config.invariants.contains(&InvariantKind::I4);
    for probe in probes {
        let Some(ProbeOutcome::Structured { structured, .. }) = &probe.outcome else {
            continue;
        };
        if want_i3 {
            match &probe.kind {
                ProbeKind::SummaryFile => {
                    let mut taken = 0;
                    for block in array_field(structured, "summaries") {
                        for element in array_field(block, "elements") {
                            if taken >= SUMMARY_FOLLOW_UP_CAP {
                                break;
                            }
                            let (Some(symbol), Some(path)) = (
                                element.get("symbol").and_then(Value::as_str),
                                element.get("path").and_then(Value::as_str),
                            ) else {
                                continue;
                            };
                            follow.push(ProbeRecord {
                                id: format!(
                                    "i3a:get_symbol_sources:{}:{symbol}",
                                    probe.symbol_path
                                ),
                                tool: "get_symbol_sources",
                                arguments: json!({"symbols": [symbol]}),
                                symbol_fq: symbol.to_string(),
                                symbol_path: path.to_string(),
                                kind: ProbeKind::SummaryElementSource {
                                    element_path: path.to_string(),
                                },
                                outcome: None,
                            });
                            taken += 1;
                        }
                    }
                }
                ProbeKind::Scan {
                    expected_display_fq,
                } => {
                    if let Some(entry) = array_field(structured, "results").next() {
                        let status = entry.get("status").and_then(Value::as_str).unwrap_or("");
                        let resolved = matches!(
                            status,
                            "found"
                                | "verified_absent"
                                | "unverified_absent"
                                | "too_many_callsites"
                        );
                        let definition_path = entry.get("definition_path").and_then(Value::as_str);
                        if resolved && let Some(definition_path) = definition_path {
                            let terminal = terminal_of(expected_display_fq);
                            follow.push(ProbeRecord {
                                id: format!("i3b:search_symbols:{}", probe.symbol_fq),
                                tool: "search_symbols",
                                // Scan-resolved declarations can live in test
                                // trees; search_symbols excludes those unless
                                // asked, so ask.
                                arguments: json!({
                                    "patterns": [terminal],
                                    "include_tests": true,
                                }),
                                symbol_fq: probe.symbol_fq.clone(),
                                symbol_path: definition_path.to_string(),
                                kind: ProbeKind::ScanSearch {
                                    expected_display_fq: expected_display_fq.clone(),
                                    expected_path: definition_path.to_string(),
                                },
                                outcome: None,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        if want_i4 {
            for (failed_selector, disputed_name, claim_excerpt) in
                honesty_claims(probe.tool, structured)
            {
                follow.push(ProbeRecord {
                    id: format!("i4:search_symbols:{failed_selector}"),
                    tool: "search_symbols",
                    arguments: json!({
                        "patterns": [terminal_of(&disputed_name)],
                        "include_tests": true,
                    }),
                    symbol_fq: failed_selector.clone(),
                    symbol_path: probe.symbol_path.clone(),
                    kind: ProbeKind::HonestySearch {
                        failed_selector,
                        disputed_name,
                        claim_excerpt,
                        origin_tool: probe.tool,
                    },
                    outcome: None,
                });
            }
        }
    }
    summary.follow_up_probes = follow.len();
    follow
}

/// Find failure messages in a response that claim the target is not indexed
/// (I4's trigger family). Returns `(failed selector, disputed name, message
/// excerpt)` triples, where the disputed name is the name the message claims
/// is not indexed — see [`disputed_name`].
fn honesty_claims(tool: &str, structured: &Value) -> Vec<(String, String, String)> {
    let mut claims = Vec::new();
    let mut push = |selector: &str, message: &str| {
        if claims_non_indexed(message) {
            claims.push((
                selector.to_string(),
                disputed_name(selector, message),
                excerpt(message),
            ));
        }
    };
    match tool {
        "get_definitions_by_reference" => {
            for result in array_field(structured, "results") {
                let status = result.get("status").and_then(Value::as_str).unwrap_or("");
                if !matches!(status, "unresolvable_import_boundary" | "not_found") {
                    continue;
                }
                let selector = result
                    .pointer("/query/symbol")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                for diagnostic in array_field(result, "diagnostics") {
                    if let Some(message) = diagnostic.get("message").and_then(Value::as_str) {
                        push(&selector, message);
                    }
                }
            }
        }
        "scan_usages_by_reference" => {
            for entry in array_field(structured, "results") {
                let status = entry.get("status").and_then(Value::as_str).unwrap_or("");
                if !matches!(status, "failure" | "not_found") {
                    continue;
                }
                let Some(message) = entry.get("message").and_then(Value::as_str) else {
                    continue;
                };
                if let Some(input) = entry.get("input").and_then(Value::as_str) {
                    push(input, message);
                }
            }
        }
        "get_symbol_sources" | "get_summaries" => {
            for entry in array_field(structured, "not_found") {
                let Some(note) = entry.get("note").and_then(Value::as_str) else {
                    continue;
                };
                if let Some(input) = entry.get("input").and_then(Value::as_str) {
                    push(input, note);
                }
            }
        }
        _ => {}
    }
    claims
}

/// The name a failure message claims is not indexed: the last backticked
/// token before the honesty phrase, which is the message's subject across
/// the analyzer's claim templates — both "`` `X` `` appears to cross a …
/// boundary not indexed" and "… boundary at `` `X` `` not indexed". Type
/// arguments (`AbstractSet[A]`) are stripped. When the message names no
/// backticked subject, the claim is about the failed selector itself.
pub fn disputed_name(selector: &str, message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    let phrase_at = HONESTY_PHRASES
        .iter()
        .filter_map(|phrase| lower.find(phrase))
        .min();
    let before = phrase_at.map_or(message, |at| &message[..at]);
    let claimed = (before.matches('`').count() >= 2)
        .then(|| before.rsplit('`').nth(1))
        .flatten()
        .map(|token| token.split('[').next().unwrap_or("").trim())
        .filter(|token| !token.is_empty());
    claimed.unwrap_or(selector).to_string()
}

fn claims_non_indexed(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    HONESTY_PHRASES.iter().any(|phrase| lower.contains(phrase))
}

// ---------------------------------------------------------------------------
// Checkers (pure over detached records)
// ---------------------------------------------------------------------------

fn structured_outcome(record: &ProbeRecord) -> Option<&Value> {
    match &record.outcome {
        Some(ProbeOutcome::Structured { structured, .. }) => Some(structured),
        _ => None,
    }
}

fn array_field<'a>(value: &'a Value, field: &str) -> impl Iterator<Item = &'a Value> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn terminal_of(name: &str) -> &str {
    name.rsplit(['#', '.']).next().unwrap_or(name)
}

/// A Scala class/companion pair shares one user-level name but the two are
/// distinct declarations with distinct resolution behavior: a spelling whose
/// terminal segment ends in `$` names the companion object, stripped
/// spellings name the class. I2's consistency rules hold within each
/// declaration's spellings, not across the pair (observed: `BenchmarkConfig`
/// resolved to the case class while `BenchmarkConfig$` resolved to the
/// companion object — both correct, flagged as drift).
fn names_companion(spelling: &str) -> bool {
    terminal_of(spelling).ends_with('$')
}

/// Cross-cutting: the structured payload must not drift between
/// `render_line_numbers` modes — rendering is a presentation concern, so the
/// same call's structured result must be identical either way.
pub fn check_render_mode_drift(records: &[&ProbeRecord], language: &str, sink: &mut ViolationSink) {
    for record in records {
        let Some(ProbeOutcome::Structured {
            structured,
            mode_b_structured: Some(mode_b),
            ..
        }) = &record.outcome
        else {
            continue;
        };
        if structured != mode_b {
            sink.record(violation(
                InvariantKind::I3,
                language,
                record.tool,
                "render-mode-structured-drift",
                &record.symbol_fq,
                &record.symbol_path,
                Some(record.arguments.clone()),
                json!({
                    "probe": record.id,
                    "differing_top_level_keys": top_level_differences(structured, mode_b),
                    "expected": "identical structured payload in both render_line_numbers modes",
                }),
            ));
        }
    }
}

fn top_level_differences(left: &Value, right: &Value) -> Vec<String> {
    match (left, right) {
        (Value::Object(left), Value::Object(right)) => {
            let mut keys: Vec<&str> = left.keys().map(String::as_str).collect();
            for key in right.keys() {
                if !keys.contains(&key.as_str()) {
                    keys.push(key);
                }
            }
            keys.into_iter()
                .filter(|key| left.get(*key) != right.get(*key))
                .map(str::to_string)
                .collect()
        }
        _ if left != right => vec!["<scalar>".to_string()],
        _ => Vec::new(),
    }
}

/// I1(c): every `SourceBlock` returned by `get_symbol_sources` must carry
/// text identical to the file content at its reported range. The tool slices
/// the declaration's exact byte range (`searchtools.rs` slices
/// `content[start_byte..end_byte]`), so the first line of `text` may start
/// mid-line at the declaration's first token and the last line may end
/// mid-line; `start_line`/`end_line` merely bracket that slice. The check is
/// therefore line-anchored rather than whole-line exact (see
/// `text_matches_reported_lines`).
pub fn check_i1c(
    records: &[&ProbeRecord],
    input: &I1Input,
    language: &str,
    sink: &mut ViolationSink,
    summary: &mut ProbeSummary,
) {
    for record in records {
        if record.tool != "get_symbol_sources" {
            continue;
        }
        let Some(structured) = structured_outcome(record) else {
            continue;
        };
        for block in array_field(structured, "sources") {
            // Deliberate renderings make no whole-range claim: sampled
            // excerpts carry `presentation`; noted fallback blocks (file
            // outlines, #include listings, module file listings) carry a
            // `note` and report ranges in their own synthetic text's
            // coordinates, not the file's.
            if block.get("presentation").and_then(Value::as_str).is_some()
                || block.get("note").and_then(Value::as_str).is_some()
            {
                continue;
            }
            let (Some(path), Some(start_line), Some(end_line), Some(text)) = (
                block.get("path").and_then(Value::as_str),
                block.get("start_line").and_then(Value::as_u64),
                block.get("end_line").and_then(Value::as_u64),
                block.get("text").and_then(Value::as_str),
            ) else {
                continue;
            };
            summary.i1c_source_text_checks += 1;
            let file = input.files.iter().find(|file| file.path == path);
            let expected = file
                .and_then(|file| file.text.as_deref())
                .and_then(|file_text| {
                    line_slice(file_text, start_line as usize, end_line as usize)
                });
            let Some(expected) = expected else {
                sink.record(violation(
                    InvariantKind::I1,
                    language,
                    "get_symbol_sources",
                    "source-range-outside-sampled-source",
                    &record.symbol_fq,
                    path,
                    Some(record.arguments.clone()),
                    json!({
                        "probe": record.id,
                        "start_line": start_line,
                        "end_line": end_line,
                        "expected": "reported range lies inside the indexed source text",
                    }),
                ));
                continue;
            };
            if !text_matches_reported_lines(&expected, text) {
                sink.record(violation(
                    InvariantKind::I1,
                    language,
                    "get_symbol_sources",
                    "source-text-differs-from-range",
                    &record.symbol_fq,
                    path,
                    Some(record.arguments.clone()),
                    json!({
                        "probe": record.id,
                        "start_line": start_line,
                        "end_line": end_line,
                        "returned_excerpt": excerpt(text),
                        "expected_excerpt": excerpt(&expected.join("\n")),
                        "expected": "returned text is the file content over the reported lines, up to mid-line start/end at the declaration's byte-slice boundaries",
                    }),
                ));
            }
        }
    }
}

/// Line-anchored fidelity of a returned `SourceBlock` text against the file
/// lines its range reports (`expected`, the whole lines of the range).
/// Interior lines must match exactly; the first line may be a suffix of the
/// file line (the byte slice starts at the declaration's first token, not at
/// line start) and the last line a prefix (the slice may end mid-line). A
/// single-line block may sit anywhere inside its line. Deliberate renderings
/// stay within these affixes: comment expansion only widens the slice to
/// whole preceding lines, and Go's `type ` re-insertion restores the file's
/// own keyword. `expected` stays a line vector so a trailing blank line at
/// the range end is not lost to a join/re-split round trip.
fn text_matches_reported_lines(expected: &[&str], text: &str) -> bool {
    let text_lines: Vec<&str> = text.lines().collect();
    if text_lines.is_empty() || text_lines.len() != expected.len() {
        return false;
    }
    if expected.len() == 1 {
        return expected[0].contains(text_lines[0]);
    }
    let last = expected.len() - 1;
    expected[0].ends_with(text_lines[0])
        && expected[last].starts_with(text_lines[last])
        && (1..last).all(|index| expected[index] == text_lines[index])
}

/// 1-based inclusive line slice, mirroring the SourceBlock range convention.
fn line_slice(text: &str, start_line: usize, end_line: usize) -> Option<Vec<&str>> {
    if start_line == 0 || end_line < start_line {
        return None;
    }
    let wanted = end_line - start_line + 1;
    let lines: Vec<&str> = text.lines().skip(start_line - 1).take(wanted).collect();
    if lines.len() != wanted {
        return None;
    }
    Some(lines)
}

/// How one spelling fared, for I2 comparisons.
#[derive(Debug)]
enum SpellingOutcome {
    /// The symbol resolved; `identity` is the declaration's (path, start_line)
    /// when the response pins it down.
    Resolved {
        identity: Option<(String, u64)>,
        status: String,
    },
    Ambiguous,
    NotFound,
    Error,
}

impl SpellingOutcome {
    fn succeeded(&self) -> bool {
        matches!(self, Self::Resolved { .. } | Self::Ambiguous)
    }

    fn status_label(&self) -> &str {
        match self {
            Self::Resolved { status, .. } => status.as_str(),
            Self::Ambiguous => "ambiguous",
            Self::NotFound => "not_found",
            Self::Error => "error",
        }
    }
}

fn classify_spelling(tool: &str, record: &ProbeRecord) -> SpellingOutcome {
    let Some(structured) = structured_outcome(record) else {
        return SpellingOutcome::Error;
    };
    match tool {
        "get_symbol_sources" => {
            if array_field(structured, "sources").next().is_some() {
                let identity = array_field(structured, "sources").next().and_then(|block| {
                    Some((
                        block.get("path").and_then(Value::as_str)?.to_string(),
                        block.get("start_line").and_then(Value::as_u64)?,
                    ))
                });
                SpellingOutcome::Resolved {
                    identity,
                    status: "resolved".to_string(),
                }
            } else if array_field(structured, "ambiguous").next().is_some() {
                SpellingOutcome::Ambiguous
            } else {
                SpellingOutcome::NotFound
            }
        }
        "get_definitions_by_reference" => {
            let Some(result) = array_field(structured, "results").next() else {
                return SpellingOutcome::Error;
            };
            let status = result
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            match status.as_str() {
                "ambiguous" => SpellingOutcome::Ambiguous,
                // The definitions surface encodes ambiguity as `not_found`
                // plus an `ambiguous_symbol` diagnostic (where
                // `get_symbol_sources` uses a structured `ambiguous` array).
                // The `kind` field is structured data, not message parsing.
                "not_found" => {
                    let is_ambiguity = array_field(result, "diagnostics").any(|diagnostic| {
                        diagnostic.get("kind").and_then(Value::as_str) == Some("ambiguous_symbol")
                    });
                    if is_ambiguity {
                        SpellingOutcome::Ambiguous
                    } else {
                        SpellingOutcome::NotFound
                    }
                }
                "resolved" => {
                    let identity = array_field(result, "definitions").next().and_then(|def| {
                        Some((
                            def.get("path").and_then(Value::as_str)?.to_string(),
                            def.get("start_line").and_then(Value::as_u64)?,
                        ))
                    });
                    SpellingOutcome::Resolved { identity, status }
                }
                // invalid_location, no_definition, unresolvable_import_boundary:
                // the symbol selector itself was accepted; the rest concerns
                // context/target, which is spelling-independent.
                _ => SpellingOutcome::Resolved {
                    identity: None,
                    status,
                },
            }
        }
        _ => SpellingOutcome::Error,
    }
}

/// I2: the spelling set for one symbol must resolve consistently — a more
/// specific spelling never fails where a less specific one succeeds, resolved
/// spellings name the same declaration, and batched references behave like
/// single ones.
pub fn check_i2(
    records: &[&ProbeRecord],
    language: &str,
    sink: &mut ViolationSink,
    summary: &mut ProbeSummary,
) {
    let mut groups: HashMap<(&str, &str), Vec<&ProbeRecord>> = HashMap::new();
    for record in records {
        if matches!(record.kind, ProbeKind::Spelling { .. }) {
            groups
                .entry((record.tool, record.symbol_fq.as_str()))
                .or_default()
                .push(record);
        }
    }
    for ((tool, symbol_fq), mut group) in groups {
        group.sort_by_key(|record| match &record.kind {
            ProbeKind::Spelling { order, .. } => *order,
            _ => 0,
        });
        summary.i2_spelling_groups += 1;
        let outcomes: Vec<SpellingOutcome> = group
            .iter()
            .map(|record| classify_spelling(tool, record))
            .collect();

        // Rule 1: a strictly more specific spelling must never fail where a
        // less specific one succeeded (the #1018 shape).
        let mut reported = false;
        for (less, less_outcome) in outcomes.iter().enumerate() {
            if reported || !less_outcome.succeeded() {
                continue;
            }
            for (more, more_outcome) in outcomes.iter().enumerate().skip(less + 1) {
                if matches!(more_outcome, SpellingOutcome::NotFound) {
                    sink.record(violation(
                        InvariantKind::I2,
                        language,
                        tool,
                        "more-specific-spelling-fails",
                        symbol_fq,
                        &group[more].symbol_path,
                        Some(group[more].arguments.clone()),
                        json!({
                            "less_specific": spelling_evidence(group[less], less_outcome),
                            "more_specific": spelling_evidence(group[more], more_outcome),
                            "expected": "a strictly more specific spelling never fails where a less specific one succeeds",
                        }),
                    ));
                    reported = true;
                    break;
                }
            }
        }

        // Rule 2: resolved spellings of one declaration must name it
        // consistently. Class/companion spellings legitimately resolve to
        // their own declarations, so identities only compare within a
        // partition.
        let mut last_by_partition: [Option<(usize, &(String, u64))>; 2] = [None, None];
        for (index, outcome) in outcomes.iter().enumerate() {
            let SpellingOutcome::Resolved {
                identity: Some(identity),
                ..
            } = outcome
            else {
                continue;
            };
            let ProbeKind::Spelling { spelling, .. } = &group[index].kind else {
                continue;
            };
            let partition = names_companion(spelling) as usize;
            if let Some((first_index, first_identity)) = last_by_partition[partition]
                && first_identity != identity
            {
                sink.record(violation(
                    InvariantKind::I2,
                    language,
                    tool,
                    "spelling-resolves-to-different-declaration",
                    symbol_fq,
                    &group[index].symbol_path,
                    Some(group[index].arguments.clone()),
                    json!({
                        "first": spelling_evidence(group[first_index], &outcomes[first_index]),
                        "second": spelling_evidence(group[index], &outcomes[index]),
                        "first_identity": { "path": first_identity.0, "start_line": first_identity.1 },
                        "second_identity": { "path": identity.0, "start_line": identity.1 },
                        "expected": "all resolved spellings name the same declaration",
                    }),
                ));
                break;
            }
            last_by_partition[partition] = Some((index, identity));
        }

        // Rule 3 (get_definitions_by_reference): spellings that reach the
        // location stage must agree on the location verdict. Selector-stage
        // differences (one spelling ambiguous, another uniquely resolved)
        // reflect the uniqueness each spelling buys — that is the point of
        // qualification, not drift — so `Ambiguous` and `NotFound` outcomes
        // stay out of this comparison. Class/companion spellings name
        // distinct declarations and legitimately diverge at the location
        // stage too, so the comparison is per partition.
        if tool == "get_definitions_by_reference" {
            let mut statuses_by_partition: [Vec<&str>; 2] = [Vec::new(), Vec::new()];
            for (record, outcome) in group.iter().zip(outcomes.iter()) {
                let SpellingOutcome::Resolved { status, .. } = outcome else {
                    continue;
                };
                let ProbeKind::Spelling { spelling, .. } = &record.kind else {
                    continue;
                };
                statuses_by_partition[names_companion(spelling) as usize].push(status.as_str());
            }
            let drift = statuses_by_partition.iter_mut().any(|statuses| {
                statuses.sort_unstable();
                statuses.dedup();
                statuses.len() > 1
            });
            if drift {
                sink.record(violation(
                    InvariantKind::I2,
                    language,
                    tool,
                    "spelling-status-drift",
                    symbol_fq,
                    &group[0].symbol_path,
                    None,
                    json!({
                        "statuses_by_spelling": group.iter().zip(outcomes.iter()).map(|(record, outcome)| {
                            let ProbeKind::Spelling { spelling, .. } = &record.kind else {
                                return json!(null);
                            };
                            json!({ "spelling": spelling, "status": outcome.status_label() })
                        }).collect::<Vec<_>>(),
                        "expected": "identical status for identical context/target across spellings",
                    }),
                ));
            }
        }
    }

    // Batch asymmetry: each batched entry must behave like its single call.
    // Singles are keyed by the full reference (spelling + context + target):
    // one spelling legitimately appears in several reference probes, and
    // matching on spelling alone compares unrelated references against each
    // other (observed: `BenchmarkConfig`'s `scratchDir` entry judged against
    // the `parser` reference's single-call outcome).
    let singles: HashMap<(&str, &str, &str, &str), &ProbeRecord> = records
        .iter()
        .filter_map(|record| match &record.kind {
            ProbeKind::Spelling { spelling, .. } => {
                let reference = record.arguments.get("references")?.as_array()?.first()?;
                let context = reference.get("context")?.as_str()?;
                let target = reference.get("target")?.as_str()?;
                Some(((record.tool, spelling.as_str(), context, target), *record))
            }
            _ => None,
        })
        .collect();
    for record in records {
        let ProbeKind::DefinitionBatch { spellings } = &record.kind else {
            continue;
        };
        let Some(structured) = structured_outcome(record) else {
            continue;
        };
        let empty = Vec::new();
        let references = record
            .arguments
            .get("references")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        for ((entry, spelling), reference) in array_field(structured, "results")
            .zip(spellings.iter())
            .zip(references.iter())
        {
            let batched_status = entry.get("status").and_then(Value::as_str).unwrap_or("");
            let context = reference
                .get("context")
                .and_then(Value::as_str)
                .unwrap_or("");
            let target = reference
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or("");
            let single_status = singles
                .get(&(
                    "get_definitions_by_reference",
                    spelling.as_str(),
                    context,
                    target,
                ))
                .and_then(|single| structured_outcome(single))
                .and_then(|single| {
                    array_field(single, "results")
                        .next()
                        .and_then(|result| result.get("status").and_then(Value::as_str))
                })
                .unwrap_or("");
            if !single_status.is_empty() && batched_status != single_status {
                sink.record(violation(
                    InvariantKind::I2,
                    language,
                    record.tool,
                    "batch-outcome-differs-from-single",
                    &record.symbol_fq,
                    &record.symbol_path,
                    Some(record.arguments.clone()),
                    json!({
                        "spelling": spelling,
                        "batched_status": batched_status,
                        "single_status": single_status,
                        "expected": "identical status whether the reference is queried alone or in a batch",
                    }),
                ));
            }
        }
    }
}

fn spelling_evidence(record: &ProbeRecord, outcome: &SpellingOutcome) -> Value {
    let ProbeKind::Spelling { spelling, .. } = &record.kind else {
        return json!(null);
    };
    json!({ "spelling": spelling, "status": outcome.status_label() })
}

/// I3(a): a symbol `get_summaries` lists under file F must resolve via
/// `get_symbol_sources`, and its reported path must be F.
pub fn check_i3a(
    records: &[&ProbeRecord],
    language: &str,
    sink: &mut ViolationSink,
    summary: &mut ProbeSummary,
) {
    for record in records {
        let ProbeKind::SummaryElementSource { element_path } = &record.kind else {
            continue;
        };
        let Some(structured) = structured_outcome(record) else {
            continue;
        };
        summary.i3a_summary_element_checks += 1;
        let mut sources = array_field(structured, "sources");
        let Some(block) = sources.next() else {
            sink.record(violation(
                InvariantKind::I3,
                language,
                "get_symbol_sources",
                "summaries-listed-symbol-unresolvable",
                &record.symbol_fq,
                &record.symbol_path,
                Some(record.arguments.clone()),
                json!({
                    "listed_under": element_path,
                    "expected": "a symbol get_summaries lists resolves via get_symbol_sources",
                }),
            ));
            continue;
        };
        let reported_path = block.get("path").and_then(Value::as_str).unwrap_or("");
        if reported_path != element_path {
            sink.record(violation(
                InvariantKind::I3,
                language,
                "get_symbol_sources",
                "summaries-listed-symbol-path-mismatch",
                &record.symbol_fq,
                &record.symbol_path,
                Some(record.arguments.clone()),
                json!({
                    "listed_under": element_path,
                    "reported_path": reported_path,
                    "expected": "get_symbol_sources reports the same path get_summaries listed the symbol under",
                }),
            ));
        }
    }
}

/// I3(b): a symbol `scan_usages_by_reference` resolves must appear in
/// `search_symbols` results for its terminal name.
pub fn check_i3b(
    records: &[&ProbeRecord],
    language: &str,
    sink: &mut ViolationSink,
    summary: &mut ProbeSummary,
) {
    for record in records {
        let ProbeKind::ScanSearch {
            expected_display_fq,
            expected_path,
        } = &record.kind
        else {
            continue;
        };
        let Some(structured) = structured_outcome(record) else {
            continue;
        };
        summary.i3b_scan_resolution_checks += 1;
        let mut found = false;
        let mut inspected = 0_usize;
        for file in array_field(structured, "files") {
            let file_path = file.get("path").and_then(Value::as_str).unwrap_or("");
            for bucket in ["classes", "functions", "fields", "modules", "macros"] {
                for hit in array_field(file, bucket) {
                    inspected += 1;
                    if file_path == expected_path
                        && hit.get("symbol").and_then(Value::as_str)
                            == Some(expected_display_fq.as_str())
                    {
                        found = true;
                    }
                }
            }
        }
        if !found {
            sink.record(violation(
                InvariantKind::I3,
                language,
                "search_symbols",
                "scan-resolved-symbol-absent-from-search",
                &record.symbol_fq,
                &record.symbol_path,
                Some(record.arguments.clone()),
                json!({
                    "expected_display_fq": expected_display_fq,
                    "expected_path": expected_path,
                    "hits_inspected": inspected,
                    "expected": "a scan_usages_by_reference-resolved declaration appears in search_symbols results for its terminal name",
                }),
            ));
        }
    }
}

/// I3(c): no response may both render content for a target and report that
/// same target in its `not_found` list (the doctrine/orm contradiction that
/// sent an agent into a 483-call retry loop).
pub fn check_i3c(
    records: &[&ProbeRecord],
    language: &str,
    sink: &mut ViolationSink,
    summary: &mut ProbeSummary,
) {
    for record in records {
        let Some(structured) = structured_outcome(record) else {
            continue;
        };
        let not_found: Vec<&str> = array_field(structured, "not_found")
            .filter_map(|entry| entry.get("input").and_then(Value::as_str))
            .collect();
        if not_found.is_empty() {
            continue;
        }
        summary.i3c_contradiction_checks += 1;
        let mut content_labels: Vec<&str> = Vec::new();
        match record.tool {
            "get_symbol_sources" => {
                content_labels.extend(
                    array_field(structured, "sources")
                        .filter_map(|block| block.get("label").and_then(Value::as_str)),
                );
            }
            "get_summaries" => {
                content_labels.extend(
                    array_field(structured, "summaries")
                        .filter_map(|block| block.get("label").and_then(Value::as_str)),
                );
                content_labels.extend(
                    array_field(structured, "listings")
                        .filter_map(|listing| listing.get("target").and_then(Value::as_str)),
                );
            }
            _ => {}
        }
        for input in not_found {
            if content_labels.contains(&input) {
                sink.record(violation(
                    InvariantKind::I3,
                    language,
                    record.tool,
                    "response-renders-and-not-founds-same-target",
                    &record.symbol_fq,
                    &record.symbol_path,
                    Some(record.arguments.clone()),
                    json!({
                        "target": input,
                        "expected": "a response never both renders content for a target and lists it under not_found",
                    }),
                ));
            }
        }
    }
}

/// I4: a failure message claiming non-indexing must not contradict the
/// index — `search_symbols` for the failed selector's terminal name must not
/// find an in-workspace declaration with that name.
pub fn check_i4(
    records: &[&ProbeRecord],
    language: &str,
    sink: &mut ViolationSink,
    summary: &mut ProbeSummary,
) {
    for record in records {
        let ProbeKind::HonestySearch {
            failed_selector,
            disputed_name,
            claim_excerpt,
            origin_tool,
        } = &record.kind
        else {
            continue;
        };
        let Some(structured) = structured_outcome(record) else {
            continue;
        };
        summary.i4_honesty_checks += 1;
        // A contradiction must identify the *same* symbol the message
        // disputes, not merely share a terminal name. A qualified disputed
        // name pins the identity, so any workspace hit whose (display) fq
        // matches it as a suffix contradicts the claim. An unqualified
        // name is scope-relative — the resolver already proved it cannot
        // see the symbol from the reference's context — so only a hit in
        // the very file the failed probe was about is provably in scope
        // (observed: "`Success[_]` not indexed" is honest when
        // scala.util.Success is meant, even though JobStatus.Success exists
        // in an unrelated package).
        let qualified = disputed_name.contains('.');
        let terminal = terminal_of(disputed_name);
        let mut contradiction = None;
        for file in array_field(structured, "files") {
            let file_path = file.get("path").and_then(Value::as_str).unwrap_or("");
            for bucket in ["classes", "functions", "fields", "modules", "macros"] {
                for hit in array_field(file, bucket) {
                    let Some(symbol) = hit.get("symbol").and_then(Value::as_str) else {
                        continue;
                    };
                    let matches = if qualified {
                        let display = symbol.replace('$', "");
                        display == *disputed_name || display.ends_with(&format!(".{disputed_name}"))
                    } else {
                        file_path == record.symbol_path && terminal_of(symbol) == terminal
                    };
                    if matches {
                        contradiction = Some((file_path.to_string(), symbol.to_string()));
                    }
                }
            }
        }
        if let Some((hit_path, hit_symbol)) = contradiction {
            sink.record(violation(
                InvariantKind::I4,
                language,
                origin_tool,
                "failure-message-claims-not-indexed-but-symbol-exists",
                &record.symbol_fq,
                &record.symbol_path,
                Some(record.arguments.clone()),
                json!({
                    "failed_selector": failed_selector,
                    "disputed_name": disputed_name,
                    "claim_excerpt": claim_excerpt,
                    "contradicting_hit": { "path": hit_path, "symbol": hit_symbol },
                    "expected": "a failure message never claims non-indexing for a name the index contains",
                }),
            ));
        }
    }
}

/// I5: every failure-status response must carry actionable next-step content.
/// What counts as actionable per tool: a `note` on not-found entries, a
/// non-empty matches/candidates list on ambiguous entries, diagnostics with
/// messages on definition lookups, a message on scan failures, or a note on
/// empty searches. A response with no content and no failure payload at all
/// is an empty refusal.
pub fn check_i5(
    records: &[&ProbeRecord],
    language: &str,
    sink: &mut ViolationSink,
    summary: &mut ProbeSummary,
) {
    for record in records {
        let Some(structured) = structured_outcome(record) else {
            continue;
        };
        let mut failures: Vec<Value> = Vec::new();
        let mut examined = 0usize;
        match record.tool {
            "get_symbol_sources" | "get_summaries" => {
                let mut any_content = false;
                for field in ["sources", "summaries", "listings"] {
                    any_content |= array_field(structured, field).next().is_some();
                }
                let mut any_failure_payload = false;
                for entry in array_field(structured, "not_found") {
                    any_failure_payload = true;
                    examined += 1;
                    let note = entry.get("note").and_then(Value::as_str).unwrap_or("");
                    if note.trim().is_empty() {
                        failures.push(json!({
                            "kind": "not_found",
                            "input": entry.get("input"),
                            "problem": "missing corrective note",
                        }));
                    }
                }
                for entry in array_field(structured, "ambiguous") {
                    any_failure_payload = true;
                    examined += 1;
                    if array_field(entry, "matches").next().is_none() {
                        failures.push(json!({
                            "kind": "ambiguous",
                            "target": entry.get("target"),
                            "problem": "no candidate list",
                        }));
                    }
                }
                if !any_content && !any_failure_payload {
                    examined += 1;
                    failures.push(json!({ "kind": "empty_refusal" }));
                }
            }
            "get_definitions_by_reference" => {
                for result in array_field(structured, "results") {
                    let status = result.get("status").and_then(Value::as_str).unwrap_or("");
                    if status == "resolved" {
                        continue;
                    }
                    examined += 1;
                    let has_diagnostic = array_field(result, "diagnostics")
                        .filter_map(|diagnostic| diagnostic.get("message").and_then(Value::as_str))
                        .any(|message| !message.trim().is_empty());
                    if !has_diagnostic {
                        failures.push(json!({
                            "kind": "definition_lookup",
                            "status": status,
                            "problem": "no diagnostic message",
                        }));
                    }
                }
            }
            "scan_usages_by_reference" => {
                for entry in array_field(structured, "results") {
                    let status = entry.get("status").and_then(Value::as_str).unwrap_or("");
                    match status {
                        "not_found" | "failure" => {
                            examined += 1;
                            let message =
                                entry.get("message").and_then(Value::as_str).unwrap_or("");
                            if message.trim().is_empty() {
                                failures.push(json!({
                                    "kind": "scan",
                                    "status": status,
                                    "problem": "no message",
                                }));
                            }
                        }
                        "ambiguous" => {
                            examined += 1;
                            if array_field(entry, "candidate_targets").next().is_none() {
                                failures.push(json!({
                                    "kind": "scan",
                                    "status": status,
                                    "problem": "no candidate list",
                                }));
                            }
                        }
                        _ => {}
                    }
                }
            }
            "search_symbols" if array_field(structured, "files").next().is_none() => {
                examined += 1;
                let note = structured.get("note").and_then(Value::as_str).unwrap_or("");
                if note.trim().is_empty() {
                    failures
                        .push(json!({ "kind": "search", "problem": "empty result without note" }));
                }
            }
            _ => {}
        }
        summary.i5_hint_checks += examined;
        for failure in failures {
            sink.record(violation(
                InvariantKind::I5,
                language,
                record.tool,
                "empty-failure-hint",
                &record.symbol_fq,
                &record.symbol_path,
                Some(record.arguments.clone()),
                json!({
                    "probe": record.id,
                    "failure": failure,
                    "expected": "every failure-status response carries actionable next-step content",
                }),
            ));
        }
    }
}
