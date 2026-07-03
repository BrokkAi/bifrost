//! Workspace-level execution of a structural query (`search_ast`): scope by
//! path globs and languages, derive the planner's positive anchors and query
//! requirements, run the matcher over deterministic candidates until `limit+1`
//! global matches prove truncation (facts come from the per-analyzer cache,
//! extraction happens on miss from in-memory source), then render the first
//! `limit` matches with captures, enclosing symbols, and capability
//! diagnostics.

use super::facts::FileFacts;
use super::matcher::FactMatch;
use super::planner::QueryPlan;
use super::query::AstQuery;
use crate::analyzer::structural::capabilities::QueryFeature;
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
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

#[derive(Debug, Serialize)]
pub struct SearchAstOutput {
    pub matches: Vec<SearchAstMatch>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<SearchAstDiagnostic>,
}

#[derive(Debug, Serialize)]
pub struct SearchAstMatch {
    pub path: String,
    pub language: &'static str,
    pub kind: &'static str,
    pub start_line: usize,
    pub end_line: usize,
    pub text: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub captures: Vec<SearchAstCapture>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_symbol: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SearchAstCapture {
    pub name: String,
    pub text: String,
    pub start_line: usize,
}

#[derive(Debug, Serialize)]
pub struct SearchAstDiagnostic {
    pub language: &'static str,
    pub message: String,
}

/// A match found before rendering, held until the rendering pass (which
/// truncates at `limit` and does enclosing-symbol lookups).
type PendingMatch = (Language, ProjectFile, Arc<FileFacts>, FactMatch);

/// Run `query` across every language provider the analyzer exposes.
pub fn execute(analyzer: &dyn IAnalyzer, query: &AstQuery) -> SearchAstOutput {
    execute_with_limits(analyzer, query, SearchAstExecutionLimits::default())
}

#[derive(Debug, Clone, Copy)]
pub struct SearchAstExecutionLimits {
    pub max_scanned_files: usize,
    pub max_scanned_source_bytes: usize,
    pub max_fact_nodes: usize,
}

impl Default for SearchAstExecutionLimits {
    fn default() -> Self {
        Self {
            max_scanned_files: MAX_SCANNED_FILES,
            max_scanned_source_bytes: MAX_SCANNED_SOURCE_BYTES,
            max_fact_nodes: MAX_FACT_NODES,
        }
    }
}

#[derive(Debug, Default)]
struct SearchAstExecutionBudget {
    scanned_files: usize,
    scanned_source_bytes: usize,
    fact_nodes: usize,
}

#[doc(hidden)]
pub fn execute_with_limits(
    analyzer: &dyn IAnalyzer,
    query: &AstQuery,
    limits: SearchAstExecutionLimits,
) -> SearchAstOutput {
    let plan = QueryPlan::for_query(query);
    let mut providers = analyzer.structural_search_providers();
    providers.sort_by_key(|provider| provider.structural_language());
    providers.retain(|provider| {
        query.languages.is_empty() || query.languages.contains(&provider.structural_language())
    });

    let mut diagnostics = Vec::new();
    let mut scoped_languages = BTreeSet::new();
    for file in analyzer.analyzed_files() {
        let language = crate::analyzer::common::language_for_file(file);
        let requested = query.languages.is_empty() || query.languages.contains(&language);
        if requested && file_matches_globs(file, query) {
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
                    .map(|diagnostic| SearchAstDiagnostic {
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
            diagnostics.push(SearchAstDiagnostic {
                language: language.config_label(),
                message: format!(
                    "no structural adapter for {} yet; its files were not searched",
                    language.config_label()
                ),
            });
        }
    }

    // Deterministic candidate order: providers sorted by language above,
    // files sorted within each provider.
    let mut candidates: Vec<(Language, &dyn super::StructuralSearchProvider, ProjectFile)> =
        Vec::new();
    for (language, provider, files) in provider_scopes {
        candidates.extend(files.into_iter().map(|file| (language, provider, file)));
    }

    let global_cap = query.limit.saturating_add(1);
    let mut pending: Vec<PendingMatch> = Vec::new();
    let mut budget = SearchAstExecutionBudget::default();
    let mut budget_exhausted = false;
    for (language, provider, file) in candidates {
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
        if !plan.source_may_match(source) {
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

    let truncated = pending.len() > query.limit || budget_exhausted;
    pending.truncate(query.limit);

    // Enclosing-symbol lookups only for the matches actually returned.
    let matches = pending
        .into_iter()
        .map(|(language, file, facts, fact_match)| {
            render_match(analyzer, language, &file, &facts, &fact_match)
        })
        .collect();

    SearchAstOutput {
        matches,
        truncated,
        diagnostics,
    }
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
    diagnostics: &mut Vec<SearchAstDiagnostic>,
    budget: &SearchAstExecutionBudget,
) {
    diagnostics.push(SearchAstDiagnostic {
        language: "workspace",
        message: format!(
            "search_ast execution budget exhausted after scanning {} files, {} bytes, and {} facts; refine the query with where, languages, kind/name anchors, or a narrower pattern",
            budget.scanned_files, budget.scanned_source_bytes, budget.fact_nodes
        ),
    });
}

fn file_matches_globs(file: &ProjectFile, query: &AstQuery) -> bool {
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
) -> SearchAstMatch {
    let fact = facts.node(fact_match.node);
    let captures = fact_match
        .captures
        .iter()
        .map(|(name, span)| SearchAstCapture {
            name: name.clone(),
            text: snippet(span.text(facts.source())),
            start_line: facts.line_of_byte(span.start_byte),
        })
        .collect();
    SearchAstMatch {
        path: rel_path_string(file),
        language: language.config_label(),
        kind: fact.kind.label(),
        start_line: fact.range.start_line,
        end_line: fact.range.end_line,
        text: snippet(fact.span().text(facts.source())),
        captures,
        enclosing_symbol: analyzer
            .enclosing_code_unit_for_lines(file, fact.range.start_line, fact.range.end_line)
            .map(|code_unit| code_unit.fq_name()),
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

impl SearchAstOutput {
    /// Human/agent-readable rendering following SearchTools conventions:
    /// structured JSON stays canonical, this is the display form.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        if self.matches.is_empty() {
            out.push_str("No structural matches.\n");
        } else {
            out.push_str(&format!(
                "{} match{}{}\n",
                self.matches.len(),
                if self.matches.len() == 1 { "" } else { "es" },
                if self.truncated {
                    " (truncated; refine the query or raise limit)"
                } else {
                    ""
                },
            ));
            for m in &self.matches {
                out.push('\n');
                let lines = if m.start_line == m.end_line {
                    format!("{}", m.start_line)
                } else {
                    format!("{}-{}", m.start_line, m.end_line)
                };
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
        }
        for diagnostic in &self.diagnostics {
            out.push_str(&format!("note: {}\n", diagnostic.message));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::structural::AstQuery;
    use serde_json::json;

    #[test]
    fn where_globs_match_slash_normalized_paths() {
        let query = AstQuery::from_json(&json!({
            "where": ["src/**/*.py"],
            "match": { "kind": "call" }
        }))
        .expect("query should parse");
        let file = ProjectFile::new(
            std::path::PathBuf::from("/workspace"),
            std::path::PathBuf::from("src\\app.py"),
        );

        assert!(file_matches_globs(&file, &query));
    }
}
