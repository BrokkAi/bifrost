//! Workspace-level execution of a structural query (`search_ast`): scope by
//! path globs and languages, prune candidates with the planner's positive
//! anchors, run the matcher over deterministic candidates until `limit+1`
//! global matches prove truncation (facts come from the per-analyzer cache,
//! extraction happens on miss from in-memory source), then render the first
//! `limit` matches with captures, enclosing symbols, and capability
//! diagnostics.

use super::facts::FileFacts;
use super::matcher::FactMatch;
use super::query::AstQuery;
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Longest match/capture snippet reported inline; full content is always
/// reachable via the returned line range.
const SNIPPET_MAX_CHARS: usize = 160;

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

    let requested_kinds = query.referenced_kinds();
    let requested_roles = query.used_roles();
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
            let unsupported_kinds: Vec<&'static str> = requested_kinds
                .iter()
                .copied()
                .filter(|kind| !provider.structural_supports_kind(*kind))
                .map(|kind| kind.label())
                .collect();
            if !unsupported_kinds.is_empty() {
                diagnostics.push(SearchAstDiagnostic {
                    language: language.config_label(),
                    message: format!(
                        "structural adapter for {} does not support kind(s): {}",
                        language.config_label(),
                        unsupported_kinds.join(", ")
                    ),
                });
            }

            let unsupported_roles: Vec<&'static str> = requested_roles
                .iter()
                .copied()
                .filter(|role| !provider.structural_supports_role(*role))
                .map(|role| role.label())
                .collect();
            if !unsupported_roles.is_empty() {
                diagnostics.push(SearchAstDiagnostic {
                    language: language.config_label(),
                    message: format!(
                        "structural adapter for {} does not support role(s): {}",
                        language.config_label(),
                        unsupported_roles.join(", ")
                    ),
                });
            }
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

    let anchors = super::planner::collect_anchors(query);
    let global_cap = query.limit.saturating_add(1);
    let mut pending: Vec<PendingMatch> = Vec::new();
    for (language, provider, file) in candidates {
        let Some(source) = provider.structural_source(&file) else {
            continue;
        };
        if !super::planner::source_may_match(source, &anchors) {
            continue;
        }
        let Some(facts) = provider.structural_facts(&file) else {
            continue;
        };
        let remaining = global_cap - pending.len();
        for fact_match in super::matcher::match_query(query, &facts, remaining) {
            pending.push((language, file.clone(), Arc::clone(&facts), fact_match));
        }
        if pending.len() >= global_cap {
            break;
        }
    }

    let truncated = pending.len() > query.limit;
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

fn file_matches_globs(file: &ProjectFile, query: &AstQuery) -> bool {
    if query.where_globs.is_empty() {
        return true;
    }
    let rel_path = file.rel_path().to_string_lossy().replace('\\', "/");
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
        path: file.rel_path().display().to_string(),
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
