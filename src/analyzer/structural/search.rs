//! Workspace-level execution of a structural query (`query_code`): scope by
//! path globs and languages, derive the planner's positive anchors and query
//! requirements, run the matcher over deterministic candidates until `limit+1`
//! global matches prove truncation (facts come from the per-analyzer cache,
//! extraction happens on miss from in-memory source), then render the first
//! `limit` matches with captures, enclosing symbols, and capability
//! diagnostics.

use super::facts::{FileFacts, Span};
use super::kinds::Role;
use super::matcher::FactMatch;
use super::planner::QueryPlan;
use super::query::{CodeQuery, CodeQueryResultDetail, QueryStep};
use crate::analyzer::structural::capabilities::QueryFeature;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Longest match/capture snippet reported inline; full content is always
/// reachable via the returned line range.
const SNIPPET_MAX_CHARS: usize = 160;
const MAX_SCANNED_FILES: usize = 20_000;
const MAX_SCANNED_SOURCE_BYTES: usize = 128 * 1024 * 1024;
const MAX_FACT_NODES: usize = 2_000_000;
const MAX_PIPELINE_ROWS: usize = 50_000;
const MAX_PROVENANCE_TRACES: usize = 16;
const BROAD_QUERY_SCANNED_FILE_HINT_THRESHOLD: usize = 100;

#[derive(Debug, Serialize)]
pub struct CodeQueryResult {
    pub results: Vec<CodeQueryResultItem>,
    /// Kept only for Rust callers while the v2 migration lands. The canonical
    /// serialized surface contains `results`, never `matches`.
    #[serde(skip)]
    pub matches: Vec<CodeQueryMatch>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<CodeQueryDiagnostic>,
}

#[derive(Debug, Serialize)]
pub struct CodeQueryResultItem {
    #[serde(flatten)]
    pub value: CodeQueryResultValue,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<CodeQueryProvenance>,
    #[serde(skip_serializing_if = "is_false")]
    pub provenance_truncated: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "result_type", rename_all = "snake_case")]
pub enum CodeQueryResultValue {
    StructuralMatch {
        #[serde(flatten)]
        value: CodeQueryMatch,
    },
    Declaration {
        #[serde(flatten)]
        value: CodeQueryDeclaration,
    },
    File {
        #[serde(flatten)]
        value: CodeQueryFile,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryMatch {
    pub path: String,
    pub language: &'static str,
    pub kind: &'static str,
    pub start_line: usize,
    pub end_line: usize,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_range: Option<CodeQueryRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decorated_range: Option<CodeQueryRange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub decorator_ranges: Vec<CodeQueryRange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub captures: Vec<CodeQueryCapture>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryDeclaration {
    pub path: String,
    pub language: &'static str,
    pub kind: &'static str,
    pub fq_name: String,
    pub start_line: usize,
    pub end_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_range: Option<CodeQueryRange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryFile {
    pub path: String,
    pub language: &'static str,
}

#[derive(Debug, Serialize)]
pub struct CodeQueryProvenance {
    pub seed: CodeQueryResultRef,
    pub steps: Vec<CodeQueryProvenanceStep>,
}

#[derive(Debug, Serialize)]
pub struct CodeQueryProvenanceStep {
    pub op: &'static str,
    pub result: CodeQueryResultRef,
}

#[derive(Debug, Serialize)]
#[serde(tag = "result_type", rename_all = "snake_case")]
pub enum CodeQueryResultRef {
    StructuralMatch {
        path: String,
        kind: &'static str,
        start_line: usize,
        end_line: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        node_range: Option<CodeQueryRange>,
    },
    Declaration {
        path: String,
        kind: &'static str,
        fq_name: String,
        start_line: usize,
        end_line: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        node_range: Option<CodeQueryRange>,
    },
    File {
        path: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCapture {
    pub name: String,
    pub text: String,
    pub start_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<CodeQueryRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct CodeQueryRange {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Serialize)]
pub struct CodeQueryDiagnostic {
    pub language: &'static str,
    pub message: String,
}

/// A match found before rendering, held until the rendering pass (which
/// truncates at `limit` and does enclosing-symbol lookups).
type PendingMatch = (Language, ProjectFile, Arc<FileFacts>, FactMatch);

#[derive(Debug)]
struct SeedMatch {
    language: Language,
    file: ProjectFile,
    facts: Arc<FileFacts>,
    fact_match: FactMatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DeclarationValue {
    unit: CodeUnit,
    range: Range,
}

#[derive(Debug, Clone)]
enum PipelineValue {
    StructuralMatch(Arc<SeedMatch>),
    Declaration(DeclarationValue),
    File(ProjectFile),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PipelineKey {
    StructuralMatch(ProjectFile, u32),
    Declaration(DeclarationValue),
    File(ProjectFile),
}

impl PipelineValue {
    fn key(&self) -> PipelineKey {
        match self {
            Self::StructuralMatch(seed) => {
                PipelineKey::StructuralMatch(seed.file.clone(), seed.fact_match.node)
            }
            Self::Declaration(declaration) => PipelineKey::Declaration(declaration.clone()),
            Self::File(file) => PipelineKey::File(file.clone()),
        }
    }
}

#[derive(Debug, Clone)]
struct PipelineTrace {
    seed: Arc<SeedMatch>,
    steps: Vec<PipelineTraceStep>,
}

#[derive(Debug, Clone)]
struct PipelineTraceStep {
    op: QueryStep,
    value: PipelineTraceValue,
}

#[derive(Debug, Clone)]
enum PipelineTraceValue {
    Declaration(DeclarationValue),
    File(ProjectFile),
}

#[derive(Debug)]
struct PipelineRow {
    value: PipelineValue,
    traces: Vec<PipelineTrace>,
    provenance_truncated: bool,
}

#[derive(Debug, Default)]
struct DirectImportGraph {
    forward: HashMap<ProjectFile, Vec<ProjectFile>>,
    reverse: HashMap<ProjectFile, Vec<ProjectFile>>,
    unsupported: HashSet<ProjectFile>,
}

/// Run `query` across every language provider the analyzer exposes.
pub fn execute(analyzer: &dyn IAnalyzer, query: &CodeQuery) -> CodeQueryResult {
    execute_with_limits(analyzer, query, CodeQueryExecutionLimits::default())
}

#[derive(Debug, Clone, Copy)]
pub struct CodeQueryExecutionLimits {
    pub max_scanned_files: usize,
    pub max_scanned_source_bytes: usize,
    pub max_fact_nodes: usize,
    pub max_pipeline_rows: usize,
}

impl Default for CodeQueryExecutionLimits {
    fn default() -> Self {
        Self {
            max_scanned_files: MAX_SCANNED_FILES,
            max_scanned_source_bytes: MAX_SCANNED_SOURCE_BYTES,
            max_fact_nodes: MAX_FACT_NODES,
            max_pipeline_rows: MAX_PIPELINE_ROWS,
        }
    }
}

#[derive(Debug, Default)]
struct CodeQueryExecutionBudget {
    scanned_files: usize,
    scanned_source_bytes: usize,
    fact_nodes: usize,
    pipeline_rows: usize,
}

#[doc(hidden)]
pub fn execute_with_limits(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> CodeQueryResult {
    let plan = QueryPlan::for_query(query);
    let source_index = plan.build_source_index();
    let mut providers = analyzer.structural_search_providers();
    providers.sort_by_key(|provider| provider.structural_language());
    providers.retain(|provider| {
        query.languages.is_empty() || query.languages.contains(&provider.structural_language())
    });

    let mut diagnostics = Vec::new();
    let mut scoped_languages = BTreeSet::new();
    for file in analyzer.analyzed_files() {
        let language = crate::analyzer::common::language_for_file(&file);
        let requested = query.languages.is_empty() || query.languages.contains(&language);
        if requested && file_matches_globs(&file, query) {
            scoped_languages.insert(language);
        }
    }

    let mut supported = BTreeSet::new();
    let mut provider_scopes: Vec<(
        Language,
        &dyn super::StructuralSearchProvider,
        Vec<ProjectFile>,
    )> = Vec::new();

    for provider in providers {
        let language = provider.structural_language();
        supported.insert(language);
        let mut files = provider.structural_files();
        files.retain(|file| file_matches_globs(file, query));
        files.sort();

        let explicitly_requested = query.languages.contains(&language);
        if !files.is_empty() || explicitly_requested {
            diagnostics.extend(
                plan.features()
                    .unsupported_by(|feature| provider_supports_feature(provider, feature))
                    .into_diagnostics(language)
                    .into_iter()
                    .map(|diagnostic| CodeQueryDiagnostic {
                        language: diagnostic.language().config_label(),
                        message: diagnostic.message(),
                    }),
            );
        }

        provider_scopes.push((language, provider, files));
    }

    for language in analyzer.languages() {
        let explicitly_requested = query.languages.contains(&language);
        let requested = query.languages.is_empty() || explicitly_requested;
        if requested
            && !supported.contains(&language)
            && (explicitly_requested || scoped_languages.contains(&language))
        {
            diagnostics.push(CodeQueryDiagnostic {
                language: language.config_label(),
                message: format!(
                    "no structural adapter for {} yet; its files were not searched",
                    language.config_label()
                ),
            });
        }
    }

    // Deterministic candidate order: global project-relative path order, with
    // language only as a tiebreaker for providers that share a path.
    let mut candidates: Vec<(
        String,
        Language,
        &dyn super::StructuralSearchProvider,
        ProjectFile,
    )> = Vec::new();
    for (language, provider, files) in provider_scopes {
        candidates.extend(
            files
                .into_iter()
                .map(|file| (rel_path_string(&file), language, provider, file)),
        );
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

    let pipeline_query = !query.steps.is_empty();
    let global_cap = if pipeline_query {
        limits.max_pipeline_rows.saturating_add(1)
    } else {
        query.limit.saturating_add(1)
    };
    let mut pending: Vec<PendingMatch> = Vec::new();
    let mut budget = CodeQueryExecutionBudget::default();
    let mut budget_exhausted = false;
    for (_path, language, provider, file) in candidates {
        let Some(source) = provider.structural_source(&file) else {
            continue;
        };
        budget.scanned_files += 1;
        budget.scanned_source_bytes = budget.scanned_source_bytes.saturating_add(source.len());
        if budget.scanned_files > limits.max_scanned_files
            || budget.scanned_source_bytes > limits.max_scanned_source_bytes
        {
            push_budget_diagnostic(&mut diagnostics, &budget);
            budget_exhausted = true;
            break;
        }
        if !source_index.may_match(&source) {
            continue;
        }
        let Some(facts) = provider.structural_facts(&file) else {
            continue;
        };
        budget.fact_nodes = budget.fact_nodes.saturating_add(facts.nodes().len());
        if budget.fact_nodes > limits.max_fact_nodes {
            push_budget_diagnostic(&mut diagnostics, &budget);
            budget_exhausted = true;
            break;
        }
        let remaining = global_cap - pending.len();
        for fact_match in super::matcher::match_query(query, &facts, remaining) {
            pending.push((language, file.clone(), Arc::clone(&facts), fact_match));
        }
        if pending.len() >= global_cap {
            break;
        }
    }

    let match_truncated = !pipeline_query && pending.len() > query.limit;
    let seed_budget_exhausted = pipeline_query && pending.len() > limits.max_pipeline_rows;
    budget_exhausted |= seed_budget_exhausted;
    if match_truncated {
        push_truncation_diagnostic(&mut diagnostics, &budget, query.limit);
    }
    if seed_budget_exhausted {
        pending.truncate(limits.max_pipeline_rows);
        budget.pipeline_rows = pending.len();
        push_pipeline_budget_diagnostic(&mut diagnostics, &budget);
    }

    if !pipeline_query {
        let truncated = match_truncated || budget_exhausted;
        if should_report_broad_query(&plan, query, &budget, truncated) {
            push_broad_query_diagnostic(&mut diagnostics, &budget);
        }
        pending.truncate(query.limit);
        let matches: Vec<_> = pending
            .into_iter()
            .map(|(language, file, facts, fact_match)| {
                render_match(
                    analyzer,
                    language,
                    &file,
                    &facts,
                    &fact_match,
                    query.result_detail,
                )
            })
            .collect();
        let results = matches
            .iter()
            .cloned()
            .map(|value| CodeQueryResultItem {
                value: CodeQueryResultValue::StructuralMatch { value },
                provenance: Vec::new(),
                provenance_truncated: false,
            })
            .collect();
        return CodeQueryResult {
            results,
            matches,
            truncated,
            diagnostics,
        };
    }

    let mut rows = pending
        .into_iter()
        .map(|(language, file, facts, fact_match)| {
            let seed = Arc::new(SeedMatch {
                language,
                file,
                facts,
                fact_match,
            });
            PipelineRow {
                value: PipelineValue::StructuralMatch(Arc::clone(&seed)),
                traces: vec![PipelineTrace {
                    seed,
                    steps: Vec::new(),
                }],
                provenance_truncated: false,
            }
        })
        .collect::<Vec<_>>();
    budget.pipeline_rows = rows.len();

    let import_graph = query
        .steps
        .iter()
        .any(|step| matches!(step, QueryStep::ImportsOf | QueryStep::ImportersOf))
        .then(|| build_direct_import_graph(analyzer));
    for &step in &query.steps {
        let (next, exhausted) = apply_pipeline_step(
            analyzer,
            step,
            rows,
            import_graph.as_ref(),
            &mut budget,
            limits.max_pipeline_rows,
            &mut diagnostics,
        );
        rows = next;
        if exhausted {
            budget_exhausted = true;
            push_pipeline_budget_diagnostic(&mut diagnostics, &budget);
            break;
        }
    }

    let terminal_truncated = rows.len() > query.limit;
    if terminal_truncated {
        push_truncation_diagnostic(&mut diagnostics, &budget, query.limit);
        rows.truncate(query.limit);
    }
    let truncated = terminal_truncated || budget_exhausted;
    if should_report_broad_query(&plan, query, &budget, truncated) {
        push_broad_query_diagnostic(&mut diagnostics, &budget);
    }
    let results = rows
        .into_iter()
        .map(|row| render_pipeline_item(analyzer, row, query.result_detail))
        .collect();
    CodeQueryResult {
        results,
        matches: Vec::new(),
        truncated,
        diagnostics,
    }
}

fn build_direct_import_graph(analyzer: &dyn IAnalyzer) -> DirectImportGraph {
    let mut graph = DirectImportGraph::default();
    let mut files: Vec<_> = analyzer.analyzed_files().into_iter().collect();
    files.sort_by_key(rel_path_string);
    let analyzed: HashSet<_> = files.iter().cloned().collect();

    for file in &files {
        let Some(provider) = analyzer.import_analysis_provider_for_file(file) else {
            graph.unsupported.insert(file.clone());
            continue;
        };
        let imports = provider.import_info_of(file);
        let imported_files = provider
            .imported_files_from_infos(file, &imports)
            .unwrap_or_else(|| {
                provider
                    .imported_code_units_from_infos(file, &imports)
                    .unwrap_or_else(|| provider.imported_code_units_of(file))
                    .into_iter()
                    .map(|unit| unit.source().clone())
                    .collect()
            });
        let mut targets: Vec<_> = imported_files
            .into_iter()
            .filter(|target| analyzed.contains(target))
            .collect();
        targets.sort_by_key(rel_path_string);
        targets.dedup();
        graph.forward.insert(file.clone(), targets);
    }

    for (source, targets) in &graph.forward {
        for target in targets {
            graph
                .reverse
                .entry(target.clone())
                .or_default()
                .push(source.clone());
        }
    }
    for importers in graph.reverse.values_mut() {
        importers.sort_by_key(rel_path_string);
        importers.dedup();
    }
    graph
}

#[allow(clippy::too_many_arguments)]
fn apply_pipeline_step(
    analyzer: &dyn IAnalyzer,
    step: QueryStep,
    rows: Vec<PipelineRow>,
    import_graph: Option<&DirectImportGraph>,
    budget: &mut CodeQueryExecutionBudget,
    max_pipeline_rows: usize,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> (Vec<PipelineRow>, bool) {
    let mut output = Vec::new();
    let mut indexes: HashMap<PipelineKey, usize> = HashMap::default();
    let mut unsupported_languages = BTreeSet::new();
    let mut exhausted = false;

    'rows: for row in rows {
        let values = match (&row.value, step) {
            (PipelineValue::StructuralMatch(seed), QueryStep::EnclosingDecl) => {
                enclosing_declaration_value(analyzer, seed)
                    .map(PipelineValue::Declaration)
                    .into_iter()
                    .collect()
            }
            (PipelineValue::StructuralMatch(seed), QueryStep::FileOf) => {
                vec![PipelineValue::File(seed.file.clone())]
            }
            (PipelineValue::Declaration(declaration), QueryStep::FileOf) => {
                vec![PipelineValue::File(declaration.unit.source().clone())]
            }
            (PipelineValue::File(file), QueryStep::ImportsOf | QueryStep::ImportersOf) => {
                let graph = import_graph.expect("import graph exists for import steps");
                if graph.unsupported.contains(file) {
                    unsupported_languages.insert(crate::analyzer::common::language_for_file(file));
                    Vec::new()
                } else {
                    let adjacent = if step == QueryStep::ImportsOf {
                        graph.forward.get(file)
                    } else {
                        graph.reverse.get(file)
                    };
                    adjacent
                        .into_iter()
                        .flatten()
                        .cloned()
                        .map(PipelineValue::File)
                        .collect()
                }
            }
            _ => unreachable!("query step domains are validated during decoding"),
        };

        for value in values {
            if budget.pipeline_rows >= max_pipeline_rows {
                exhausted = true;
                break 'rows;
            }
            budget.pipeline_rows += 1;
            let trace_value = pipeline_trace_value(&value)
                .expect("every semantic query step produces a semantic value");
            let traces = row
                .traces
                .iter()
                .cloned()
                .map(|mut trace| {
                    trace.steps.push(PipelineTraceStep {
                        op: step,
                        value: trace_value.clone(),
                    });
                    trace
                })
                .collect();
            insert_pipeline_row(
                &mut output,
                &mut indexes,
                value,
                traces,
                row.provenance_truncated,
            );
        }
    }

    for language in unsupported_languages {
        diagnostics.push(CodeQueryDiagnostic {
            language: language.config_label(),
            message: format!(
                "{} does not provide structured import analysis; {} omitted its affected files",
                language.config_label(),
                step.label()
            ),
        });
    }
    (output, exhausted)
}

fn enclosing_declaration_value(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
) -> Option<DeclarationValue> {
    let fact = seed.facts.node(seed.fact_match.node);
    let span = fact.span();
    let seed_range = Range {
        start_byte: span.start_byte,
        end_byte: span.end_byte,
        start_line: fact.range.start_line,
        end_line: fact.range.end_line,
    };
    let unit = analyzer.enclosing_code_unit(&seed.file, &seed_range)?;
    if unit.is_synthetic() || unit.is_file_scope() {
        return None;
    }
    let range = analyzer
        .ranges_of(&unit)
        .into_iter()
        .filter(|range| {
            range.start_byte <= seed_range.start_byte && range.end_byte >= seed_range.end_byte
        })
        .min_by_key(|range| range.end_byte.saturating_sub(range.start_byte))?;
    Some(DeclarationValue { unit, range })
}

fn pipeline_trace_value(value: &PipelineValue) -> Option<PipelineTraceValue> {
    match value {
        PipelineValue::StructuralMatch(_) => None,
        PipelineValue::Declaration(declaration) => {
            Some(PipelineTraceValue::Declaration(declaration.clone()))
        }
        PipelineValue::File(file) => Some(PipelineTraceValue::File(file.clone())),
    }
}

fn insert_pipeline_row(
    rows: &mut Vec<PipelineRow>,
    indexes: &mut HashMap<PipelineKey, usize>,
    value: PipelineValue,
    mut traces: Vec<PipelineTrace>,
    provenance_truncated: bool,
) {
    let key = value.key();
    if let Some(&index) = indexes.get(&key) {
        let row = &mut rows[index];
        let remaining = MAX_PROVENANCE_TRACES.saturating_sub(row.traces.len());
        if traces.len() > remaining {
            row.provenance_truncated = true;
        }
        row.traces.extend(traces.into_iter().take(remaining));
        row.provenance_truncated |= provenance_truncated;
        return;
    }

    let truncated = provenance_truncated || traces.len() > MAX_PROVENANCE_TRACES;
    traces.truncate(MAX_PROVENANCE_TRACES);
    indexes.insert(key, rows.len());
    rows.push(PipelineRow {
        value,
        traces,
        provenance_truncated: truncated,
    });
}

fn render_pipeline_item(
    analyzer: &dyn IAnalyzer,
    row: PipelineRow,
    detail: CodeQueryResultDetail,
) -> CodeQueryResultItem {
    let provenance = row
        .traces
        .iter()
        .map(|trace| render_provenance(analyzer, trace, detail))
        .collect();
    let value = match row.value {
        PipelineValue::StructuralMatch(seed) => CodeQueryResultValue::StructuralMatch {
            value: render_match(
                analyzer,
                seed.language,
                &seed.file,
                &seed.facts,
                &seed.fact_match,
                detail,
            ),
        },
        PipelineValue::Declaration(declaration) => CodeQueryResultValue::Declaration {
            value: render_declaration(analyzer, &declaration, detail),
        },
        PipelineValue::File(file) => CodeQueryResultValue::File {
            value: render_file(&file),
        },
    };
    CodeQueryResultItem {
        value,
        provenance,
        provenance_truncated: row.provenance_truncated,
    }
}

fn render_provenance(
    analyzer: &dyn IAnalyzer,
    trace: &PipelineTrace,
    detail: CodeQueryResultDetail,
) -> CodeQueryProvenance {
    CodeQueryProvenance {
        seed: render_seed_ref(&trace.seed, detail),
        steps: trace
            .steps
            .iter()
            .map(|step| CodeQueryProvenanceStep {
                op: step.op.label(),
                result: match &step.value {
                    PipelineTraceValue::Declaration(declaration) => {
                        render_declaration_ref(analyzer, declaration, detail)
                    }
                    PipelineTraceValue::File(file) => render_file_ref(file),
                },
            })
            .collect(),
    }
}

fn render_seed_ref(seed: &SeedMatch, detail: CodeQueryResultDetail) -> CodeQueryResultRef {
    let fact = seed.facts.node(seed.fact_match.node);
    let full = !detail.is_compact();
    let path = rel_path_string(&seed.file);
    CodeQueryResultRef::StructuralMatch {
        id: full.then(|| match_id(&path, fact.kind.label(), fact.span())),
        path,
        kind: fact.kind.label(),
        start_line: fact.range.start_line,
        end_line: fact.range.end_line,
        node_range: full.then(|| range_for_span(&seed.facts, fact.span())),
    }
}

fn render_declaration_ref(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    detail: CodeQueryResultDetail,
) -> CodeQueryResultRef {
    let path = rel_path_string(declaration.unit.source());
    let fq_name = declaration.unit.fq_name();
    let kind = declaration.unit.kind().display_lowercase();
    let full = !detail.is_compact();
    CodeQueryResultRef::Declaration {
        id: full.then(|| declaration_id(&path, kind, &fq_name, declaration.range)),
        path,
        kind,
        fq_name,
        start_line: declaration.range.start_line,
        end_line: declaration.range.end_line,
        node_range: full
            .then(|| range_for_declaration(analyzer, declaration))
            .flatten(),
    }
}

fn render_file_ref(file: &ProjectFile) -> CodeQueryResultRef {
    CodeQueryResultRef::File {
        path: rel_path_string(file),
    }
}

fn render_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    detail: CodeQueryResultDetail,
) -> CodeQueryDeclaration {
    let path = rel_path_string(declaration.unit.source());
    let fq_name = declaration.unit.fq_name();
    let kind = declaration.unit.kind().display_lowercase();
    let full = !detail.is_compact();
    let signature = declaration
        .unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures_of(&declaration.unit).into_iter().next());
    CodeQueryDeclaration {
        id: full.then(|| declaration_id(&path, kind, &fq_name, declaration.range)),
        path,
        language: crate::analyzer::common::language_for_file(declaration.unit.source())
            .config_label(),
        kind,
        fq_name,
        start_line: declaration.range.start_line,
        end_line: declaration.range.end_line,
        signature,
        node_range: full
            .then(|| range_for_declaration(analyzer, declaration))
            .flatten(),
    }
}

fn render_file(file: &ProjectFile) -> CodeQueryFile {
    CodeQueryFile {
        path: rel_path_string(file),
        language: crate::analyzer::common::language_for_file(file).config_label(),
    }
}

fn declaration_id(path: &str, kind: &str, fq_name: &str, range: Range) -> String {
    format!(
        "{path}:{kind}:{fq_name}:{}-{}",
        range.start_byte, range.end_byte
    )
}

fn range_for_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
) -> Option<CodeQueryRange> {
    let source = analyzer.indexed_source(declaration.unit.source())?;
    Some(range_for_offsets(
        &source,
        declaration.range.start_byte,
        declaration.range.end_byte,
    ))
}

fn range_for_offsets(source: &str, start_byte: usize, end_byte: usize) -> CodeQueryRange {
    let (start_line, start_column) = line_column_of_byte(source, start_byte);
    let (end_line, end_column) = line_column_of_byte(source, end_byte);
    CodeQueryRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

fn line_column_of_byte(source: &str, byte: usize) -> (usize, usize) {
    let bounded = byte.min(source.len());
    let mut boundary = bounded;
    while boundary > 0 && !source.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let prefix = &source[..boundary];
    let line = prefix.bytes().filter(|&byte| byte == b'\n').count() + 1;
    let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
    let column = source[line_start..boundary].chars().count() + 1;
    (line, column)
}

fn provider_supports_feature(
    provider: &dyn super::StructuralSearchProvider,
    feature: QueryFeature,
) -> bool {
    match feature {
        QueryFeature::Kind(kind) => provider.structural_supports_kind(kind),
        QueryFeature::Role(role) => provider.structural_supports_role(role),
    }
}

fn push_budget_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
) {
    diagnostics.push(CodeQueryDiagnostic {
        language: "workspace",
        message: format!(
            "query_code execution budget exhausted after scanning {} files, {} bytes, and {} facts; refine the query with where, languages, kind/name anchors, or a narrower pattern",
            budget.scanned_files, budget.scanned_source_bytes, budget.fact_nodes
        ),
    });
}

fn push_pipeline_budget_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
) {
    diagnostics.push(CodeQueryDiagnostic {
        language: "workspace",
        message: format!(
            "query_code pipeline budget exhausted after producing {} seed and edge rows; refine the match, where, or languages filters",
            budget.pipeline_rows
        ),
    });
}

fn push_truncation_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
    limit: usize,
) {
    diagnostics.push(CodeQueryDiagnostic {
        language: "workspace",
        message: format!(
            "query_code returned the first {limit} results after scanning {} files, {} bytes, and {} facts; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern",
            budget.scanned_files, budget.scanned_source_bytes, budget.fact_nodes
        ),
    });
}

fn should_report_broad_query(
    plan: &QueryPlan,
    query: &CodeQuery,
    budget: &CodeQueryExecutionBudget,
    truncated: bool,
) -> bool {
    !plan.has_source_anchors()
        && query.where_globs.is_empty()
        && query.languages.is_empty()
        && (truncated || budget.scanned_files >= BROAD_QUERY_SCANNED_FILE_HINT_THRESHOLD)
}

fn push_broad_query_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
) {
    diagnostics.push(CodeQueryDiagnostic {
        language: "workspace",
        message: format!(
            "broad unanchored query_code query scanned {} files, {} bytes, and {} facts; add where, languages, exact name predicates, or a more specific pattern to reduce work and output",
            budget.scanned_files, budget.scanned_source_bytes, budget.fact_nodes
        ),
    });
}

fn file_matches_globs(file: &ProjectFile, query: &CodeQuery) -> bool {
    if query.where_globs.is_empty() {
        return true;
    }
    let rel_path = rel_path_string(file);
    query.where_globs.iter().any(|glob| glob.matches(&rel_path))
}

fn render_match(
    analyzer: &dyn IAnalyzer,
    language: Language,
    file: &ProjectFile,
    facts: &FileFacts,
    fact_match: &FactMatch,
    detail: CodeQueryResultDetail,
) -> CodeQueryMatch {
    let fact = facts.node(fact_match.node);
    let full_detail = matches!(detail, CodeQueryResultDetail::Full);
    let path = rel_path_string(file);
    let captures = fact_match
        .captures
        .iter()
        .map(|capture| CodeQueryCapture {
            name: capture.name.clone(),
            text: snippet(capture.span.text(facts.source())),
            start_line: facts.line_of_byte(capture.span.start_byte),
            range: full_detail.then(|| range_for_span(facts, capture.span)),
            kind: if full_detail {
                capture.kind.map(|kind| kind.label())
            } else {
                None
            },
        })
        .collect();
    let node_range = full_detail.then(|| range_for_span(facts, fact.span()));
    let decorator_spans: Vec<_> = if full_detail {
        fact.role_targets(Role::Decorator)
            .map(|target| target.span)
            .collect()
    } else {
        Vec::new()
    };
    let decorator_ranges = decorator_spans
        .iter()
        .map(|&span| range_for_span(facts, span))
        .collect::<Vec<_>>();
    let decorated_range = if full_detail && !decorator_spans.is_empty() {
        let mut decorated = fact.span();
        for span in decorator_spans {
            decorated.start_byte = decorated.start_byte.min(span.start_byte);
            decorated.end_byte = decorated.end_byte.max(span.end_byte);
        }
        Some(range_for_span(facts, decorated))
    } else {
        None
    };
    CodeQueryMatch {
        id: full_detail.then(|| match_id(&path, fact.kind.label(), fact.span())),
        path,
        language: language.config_label(),
        kind: fact.kind.label(),
        start_line: fact.range.start_line,
        end_line: fact.range.end_line,
        text: snippet(fact.span().text(facts.source())),
        node_range,
        decorated_range,
        decorator_ranges,
        captures,
        enclosing_symbol: analyzer
            .enclosing_code_unit_for_lines(file, fact.range.start_line, fact.range.end_line)
            .map(|code_unit| code_unit.fq_name()),
    }
}

fn match_id(path: &str, kind: &str, span: Span) -> String {
    format!("{path}:{kind}:{}-{}", span.start_byte, span.end_byte)
}

fn range_for_span(facts: &FileFacts, span: Span) -> CodeQueryRange {
    let (start_line, start_column) = facts.line_column_of_byte(span.start_byte);
    let (end_line, end_column) = facts.line_column_of_byte(span.end_byte);
    CodeQueryRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

/// First line of `text`, truncated to [`SNIPPET_MAX_CHARS`] on a char
/// boundary, with an ellipsis when anything was dropped.
fn snippet(text: &str) -> String {
    let first_line = text.lines().next().unwrap_or("");
    let mut end = first_line.len().min(SNIPPET_MAX_CHARS);
    while !first_line.is_char_boundary(end) {
        end -= 1;
    }
    let mut result = first_line[..end].to_string();
    if end < text.len() {
        result.push('…');
    }
    result
}

impl CodeQueryResult {
    pub fn result_count_line(&self) -> String {
        format!(
            "{} result{}{}",
            self.results.len(),
            if self.results.len() == 1 { "" } else { "s" },
            if self.truncated {
                " (truncated; refine the query or raise limit)"
            } else {
                ""
            },
        )
    }

    /// Human/agent-readable rendering following SearchTools conventions:
    /// structured JSON stays canonical, this is the display form.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        if self.results.is_empty() {
            out.push_str("No query results.\n");
        } else {
            out.push_str(&format!("{}\n", self.result_count_line()));
            for result in &self.results {
                out.push('\n');
                match &result.value {
                    CodeQueryResultValue::StructuralMatch { value: m } => {
                        let lines = m.line_span_label();
                        out.push_str(&format!("{}:{} [{}] `{}`", m.path, lines, m.kind, m.text));
                        if let Some(enclosing) = &m.enclosing_symbol {
                            out.push_str(&format!(" in {enclosing}"));
                        }
                        out.push('\n');
                        for capture in &m.captures {
                            out.push_str(&format!(
                                "  ${} = `{}` (line {})\n",
                                capture.name, capture.text, capture.start_line
                            ));
                        }
                    }
                    CodeQueryResultValue::Declaration { value } => {
                        let lines = line_span_label(value.start_line, value.end_line);
                        out.push_str(&format!(
                            "{}:{} [{}] {}",
                            value.path, lines, value.kind, value.fq_name
                        ));
                        if let Some(signature) = &value.signature {
                            out.push_str(&format!(" `{signature}`"));
                        }
                        out.push('\n');
                    }
                    CodeQueryResultValue::File { value } => {
                        out.push_str(&format!("{} [file; {}]\n", value.path, value.language));
                    }
                }
                if !result.provenance.is_empty() {
                    out.push_str(&format!(
                        "  provenance: {} path{}{}\n",
                        result.provenance.len(),
                        if result.provenance.len() == 1 {
                            ""
                        } else {
                            "s"
                        },
                        if result.provenance_truncated {
                            " (truncated)"
                        } else {
                            ""
                        }
                    ));
                }
            }
        }
        for diagnostic in &self.diagnostics {
            out.push_str(&format!("note: {}\n", diagnostic.message));
        }
        out
    }
}

impl CodeQueryMatch {
    pub fn line_span_label(&self) -> String {
        if self.start_line == self.end_line {
            self.start_line.to_string()
        } else {
            format!("{}-{}", self.start_line, self.end_line)
        }
    }
}

fn line_span_label(start_line: usize, end_line: usize) -> String {
    if start_line == end_line {
        start_line.to_string()
    } else {
        format!("{start_line}-{end_line}")
    }
}

fn is_false(value: &bool) -> bool {
    !value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::structural::CodeQuery;
    use serde_json::json;

    #[test]
    fn where_globs_match_slash_normalized_paths() {
        let query = CodeQuery::from_json(&json!({
            "where": ["src/**/*.py"],
            "match": { "kind": "call" }
        }))
        .expect("query should parse");
        let file = ProjectFile::new(
            std::env::temp_dir().join("bifrost-structural-search"),
            std::path::PathBuf::from("src\\app.py"),
        );

        assert!(file_matches_globs(&file, &query));
    }
}
