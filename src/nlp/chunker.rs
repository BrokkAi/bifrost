//! Chunk extraction for the semantic index.
//!
//! Per file: one chunk per function/method (source text, parent context =
//! nearest enclosing class summary, else the file's summary-or-symbols text)
//! plus one file-summary chunk encoding the summary-or-symbols text alone.
//! This is the prototype's `nearest-class-else-file-v1` parent policy with
//! the file-level parent selected by token budget: full summary if it fits
//! `MAX_SEQ_TOKENS`, else the compact symbols outline, truncated as a last
//! resort.

use std::collections::{HashMap, HashSet};

use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::path_utils::rel_path_string;
use crate::searchtools::{SummaryBlock, summarize_files, summary_block_for_code_unit};

use super::MAX_SEQ_TOKENS;
use super::keys::{Key, component_key};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkKind {
    FileSummary,
    Function,
}

impl ChunkKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChunkKind::FileSummary => "file_summary",
            ChunkKind::Function => "function",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChunkText {
    /// 0 is reserved for the file-summary chunk; functions follow in source order.
    pub ord: i64,
    pub kind: ChunkKind,
    pub symbol: Option<String>,
    pub start_line: Option<i64>,
    pub end_line: Option<i64>,
    pub text: String,
    /// Context text averaged into the chunk vector; `None` embeds the chunk alone.
    pub parent_text: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct FileChunks {
    pub file_path: String,
    /// The file's summary-or-symbols text: parent fallback, file-summary chunk
    /// body, and what `semantic_search` renders for a hit on this file.
    pub summary_text: Option<String>,
    pub chunks: Vec<ChunkText>,
}

/// Extract all chunks for `file`. `count_tokens` must be the embedding
/// model's tokenizer so budget decisions match what the model will see.
pub fn extract_file_chunks(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    count_tokens: &dyn Fn(&str) -> usize,
) -> FileChunks {
    let file_path = rel_path_string(file);
    let summary_text = file_summary_or_symbols(analyzer, file, count_tokens);

    let mut chunks = Vec::new();
    if let Some(summary) = &summary_text {
        chunks.push(ChunkText {
            ord: 0,
            kind: ChunkKind::FileSummary,
            symbol: None,
            start_line: None,
            end_line: None,
            text: summary.clone(),
            parent_text: None,
        });
    }

    let mut class_summaries: HashMap<String, Option<String>> = HashMap::new();
    let mut seen_texts: HashSet<Key> = HashSet::new();
    let mut next_ord = 1i64;
    // (unit, nearest enclosing class) work stack; functions do not nest the
    // traversal further because their source text already contains any
    // local definitions.
    let mut stack: Vec<(CodeUnit, Option<CodeUnit>)> = analyzer
        .top_level_declarations(file)
        .cloned()
        .map(|unit| (unit, None))
        .collect();
    let mut functions: Vec<(CodeUnit, Option<CodeUnit>)> = Vec::new();
    while let Some((unit, enclosing_class)) = stack.pop() {
        if unit.is_anonymous() {
            continue;
        }
        if unit.is_function() {
            functions.push((unit, enclosing_class));
            continue;
        }
        if unit.is_class() || unit.is_module() {
            let next_enclosing = if unit.is_class() {
                Some(unit.clone())
            } else {
                enclosing_class.clone()
            };
            for child in analyzer.get_direct_children(&unit) {
                if child.source() == file {
                    stack.push((child, next_enclosing.clone()));
                }
            }
        }
    }
    functions.sort_by_key(|(unit, _)| {
        analyzer
            .ranges(unit)
            .first()
            .map(|range| range.start_line)
            .unwrap_or(usize::MAX)
    });

    for (unit, enclosing_class) in functions {
        let Some(text) = analyzer.get_source(&unit, true) else {
            continue;
        };
        if text.trim().is_empty() || !seen_texts.insert(component_key(&text)) {
            continue;
        }
        let parent_text = enclosing_class
            .as_ref()
            .and_then(|class| {
                class_summaries
                    .entry(class.fq_name())
                    .or_insert_with(|| class_summary(analyzer, class, count_tokens))
                    .clone()
            })
            .or_else(|| summary_text.clone());
        let range = analyzer.ranges(&unit).first().cloned();
        chunks.push(ChunkText {
            ord: next_ord,
            kind: ChunkKind::Function,
            symbol: Some(unit.fq_name()),
            start_line: range.as_ref().map(|r| r.start_line as i64),
            end_line: range.as_ref().map(|r| r.end_line as i64),
            text,
            parent_text,
        });
        next_ord += 1;
    }

    FileChunks {
        file_path,
        summary_text,
        chunks,
    }
}

/// The file-level parent text: full summary if it fits the token budget,
/// else the compact symbols outline (truncated to the budget if needed).
fn file_summary_or_symbols(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    count_tokens: &dyn Fn(&str) -> usize,
) -> Option<String> {
    if let Some(block) = summarize_files(analyzer, vec![file.clone()])
        .summaries
        .pop()
    {
        let text = flatten_summary_block(&block);
        if !text.is_empty() && count_tokens(&text) <= MAX_SEQ_TOKENS {
            return Some(text);
        }
    }
    let symbols = analyzer.list_symbols(file);
    let symbols = symbols.trim();
    if symbols.is_empty() {
        return None;
    }
    Some(truncate_to_budget(symbols, count_tokens))
}

fn class_summary(
    analyzer: &dyn IAnalyzer,
    class: &CodeUnit,
    count_tokens: &dyn Fn(&str) -> usize,
) -> Option<String> {
    let block = summary_block_for_code_unit(analyzer, class)?;
    let text = flatten_summary_block(&block);
    (!text.is_empty() && count_tokens(&text) <= MAX_SEQ_TOKENS).then_some(text)
}

fn flatten_summary_block(block: &SummaryBlock) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(block.elements.len() + 1);
    if !block.preamble.is_empty() {
        parts.push(&block.preamble);
    }
    parts.extend(block.elements.iter().map(|element| element.text.as_str()));
    parts.join("\n").trim().to_string()
}

/// Halve the line count until the text fits the embedding budget.
fn truncate_to_budget(text: &str, count_tokens: &dyn Fn(&str) -> usize) -> String {
    if count_tokens(text) <= MAX_SEQ_TOKENS {
        return text.to_string();
    }
    let lines: Vec<&str> = text.lines().collect();
    let mut keep = lines.len();
    while keep > 1 {
        keep /= 2;
        let candidate = lines[..keep].join("\n");
        if count_tokens(&candidate) <= MAX_SEQ_TOKENS {
            return candidate;
        }
    }
    lines.first().copied().unwrap_or_default().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{JavaAnalyzer, Language, TestProject};

    fn fixture_analyzer() -> JavaAnalyzer {
        let root = std::env::current_dir()
            .unwrap()
            .join("tests/fixtures/testcode-java")
            .canonicalize()
            .unwrap();
        let project = TestProject::new(root, Language::Java);
        JavaAnalyzer::from_project(project)
    }

    fn word_count(text: &str) -> usize {
        text.split_whitespace().count()
    }

    fn chunks_for(analyzer: &dyn IAnalyzer, name: &str) -> FileChunks {
        let file = analyzer
            .analyzed_files()
            .find(|file| rel_path_string(file) == name)
            .cloned()
            .unwrap_or_else(|| panic!("fixture file {name} not analyzed"));
        extract_file_chunks(analyzer, &file, &word_count)
    }

    #[test]
    fn extracts_summary_and_function_chunks() {
        let analyzer = fixture_analyzer();
        let result = chunks_for(&analyzer, "A.java");

        let summary = &result.chunks[0];
        assert_eq!(summary.kind, ChunkKind::FileSummary);
        assert_eq!(result.summary_text.as_deref(), Some(summary.text.as_str()));
        assert!(summary.text.contains("class A"));

        let functions: Vec<_> = result
            .chunks
            .iter()
            .filter(|chunk| chunk.kind == ChunkKind::Function)
            .collect();
        assert!(!functions.is_empty(), "expected method chunks for A.java");
        let method = functions
            .iter()
            .find(|chunk| chunk.symbol.as_deref() == Some("A.method2"))
            .expect("A.method2 chunk");
        assert!(method.text.contains("method2"));
        assert!(method.start_line.is_some());
        // Parent context is the enclosing class summary, which contains the
        // signatures of sibling methods.
        let parent = method.parent_text.as_deref().expect("parent text");
        assert!(parent.contains("method1"));
    }

    #[test]
    fn function_chunks_are_ordered_and_deduped() {
        let analyzer = fixture_analyzer();
        let result = chunks_for(&analyzer, "A.java");
        let lines: Vec<i64> = result
            .chunks
            .iter()
            .filter(|chunk| chunk.kind == ChunkKind::Function)
            .filter_map(|chunk| chunk.start_line)
            .collect();
        let mut sorted = lines.clone();
        sorted.sort_unstable();
        assert_eq!(lines, sorted, "function chunks must be in source order");

        let mut texts: Vec<&str> = result.chunks.iter().map(|c| c.text.as_str()).collect();
        let before = texts.len();
        texts.sort_unstable();
        texts.dedup();
        assert_eq!(before, texts.len(), "chunk texts must be unique");
    }

    #[test]
    fn truncate_to_budget_halves_until_fit() {
        let text = (0..64)
            .map(|i| format!("line {i} with several words here"))
            .collect::<Vec<_>>()
            .join("\n");
        let tight = |t: &str| t.split_whitespace().count() * 100;
        let truncated = truncate_to_budget(&text, &tight);
        assert!(truncated.starts_with("line 0"));
        assert!(truncated.lines().count() < 64);
    }
}
