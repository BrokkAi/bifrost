//! Language-independent comment-density support for tree-sitter analyzers.
//!
//! The declaration graph is already normalized behind [`IAnalyzer`]. This
//! module parses only enough syntax to identify real comment nodes, then
//! assigns each comment to the deepest declaration that structurally contains
//! it. That keeps the metric available to every parsed language without
//! duplicating comment token handling in each language adapter.

use crate::analyzer::common::{is_unparseable_source, language_for_file};
use crate::analyzer::tree_sitter_analyzer::{
    WalkControl, expanded_comment_start, walk_tree_preorder,
};
use crate::analyzer::{
    CodeUnit, CommentDensityStats, IAnalyzer, Language, ProjectFile, parser_language_for_path,
};
use crate::hash::HashMap;
use crate::path_utils::rel_path_string;
use tree_sitter::Parser;

/// Compute density for a declaration in any language with a registered parser.
pub(crate) fn for_code_unit(
    analyzer: &(impl IAnalyzer + ?Sized),
    code_unit: &CodeUnit,
) -> Option<CommentDensityStats> {
    let file = code_unit.source();
    let source = analyzer.project().read_source(file).ok()?;
    let aggregates = collect_comment_aggregates(analyzer, file, &source)?;
    Some(build_roll_up_stats(analyzer, code_unit, &aggregates))
}

/// Compute density for every user-visible top-level declaration in `file`.
pub(crate) fn by_top_level(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
) -> Vec<CommentDensityStats> {
    let Ok(source) = analyzer.project().read_source(file) else {
        return Vec::new();
    };
    let Some(aggregates) = collect_comment_aggregates(analyzer, file, &source) else {
        return Vec::new();
    };
    analyzer
        .top_level_declarations(file)
        .into_iter()
        .filter(|code_unit| !code_unit.is_module() && !code_unit.is_synthetic())
        .map(|code_unit| build_roll_up_stats(analyzer, &code_unit, &aggregates))
        .collect()
}

fn collect_comment_aggregates(
    analyzer: &(impl IAnalyzer + ?Sized),
    file: &ProjectFile,
    source: &str,
) -> Option<HashMap<String, (u32, u32)>> {
    let language = language_for_file(file);
    if language == Language::None || is_unparseable_source(source) {
        return None;
    }
    let grammar = parser_language_for_path(language, file.rel_path())?;
    let mut parser = Parser::new();
    parser
        .set_language(&grammar)
        .expect("registered parser grammar must load");
    let tree = parser.parse(source, None)?;
    let mut comments = Vec::new();
    walk_tree_preorder(tree.root_node(), true, |node| {
        if node.kind().ends_with("comment") {
            comments.push(node);
            WalkControl::SkipChildren
        } else {
            WalkControl::Continue
        }
    });

    let mut aggregates: HashMap<String, (u32, u32)> = HashMap::default();
    for comment in comments {
        let start = comment.start_byte();
        let end = comment.end_byte();
        let Some(code_unit) = enclosing_code_unit(analyzer, source, file, start, end) else {
            continue;
        };
        let Some(range) = analyzer
            .ranges(&code_unit)
            .into_iter()
            .filter(|range| {
                let comment_start = expanded_comment_start(source, range.start_byte);
                start >= comment_start && end <= range.end_byte
            })
            .min_by_key(|range| {
                let comment_start = expanded_comment_start(source, range.start_byte);
                range.end_byte.saturating_sub(comment_start)
            })
        else {
            continue;
        };
        let lines = (comment
            .end_position()
            .row
            .saturating_sub(comment.start_position().row)
            + 1) as u32;
        let counts = aggregates.entry(code_unit.fq_name()).or_default();
        if end <= range.start_byte {
            counts.0 += lines;
        } else {
            counts.1 += lines;
        }
    }
    Some(aggregates)
}

fn enclosing_code_unit(
    analyzer: &(impl IAnalyzer + ?Sized),
    source: &str,
    file: &ProjectFile,
    start: usize,
    end: usize,
) -> Option<CodeUnit> {
    if start > end {
        return None;
    }
    let mut best = None;
    let mut pending: Vec<(CodeUnit, usize)> = analyzer
        .top_level_declarations(file)
        .into_iter()
        .map(|code_unit| (code_unit, 0))
        .collect();
    while let Some((code_unit, depth)) = pending.pop() {
        let contains = analyzer.ranges(&code_unit).iter().any(|range| {
            let comment_start = expanded_comment_start(source, range.start_byte);
            start >= comment_start && end <= range.end_byte
        });
        if !contains {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(_, best_depth)| depth > *best_depth)
        {
            best = Some((code_unit.clone(), depth));
        }
        pending.extend(
            analyzer
                .direct_children(&code_unit)
                .into_iter()
                .map(|child| (child, depth + 1)),
        );
    }
    best.map(|(code_unit, _)| code_unit)
}

fn build_roll_up_stats(
    analyzer: &(impl IAnalyzer + ?Sized),
    code_unit: &CodeUnit,
    aggregates: &HashMap<String, (u32, u32)>,
) -> CommentDensityStats {
    let (header, inline) = own_counts(code_unit, aggregates);
    let mut rolled_header = header;
    let mut rolled_inline = inline;
    let mut rolled_span = span_lines(analyzer, code_unit);

    if code_unit.is_class() {
        let mut pending = analyzer.direct_children(code_unit);
        while let Some(child) = pending.pop() {
            let (child_header, child_inline) = own_counts(&child, aggregates);
            rolled_header += child_header;
            rolled_inline += child_inline;
            rolled_span += span_lines(analyzer, &child);
            if child.is_class() {
                pending.extend(analyzer.direct_children(&child));
            }
        }
    }

    CommentDensityStats {
        fq_name: code_unit.fq_name(),
        relative_path: rel_path_string(code_unit.source()),
        header_comment_lines: header,
        inline_comment_lines: inline,
        span_lines: span_lines(analyzer, code_unit),
        rolled_up_header_comment_lines: rolled_header,
        rolled_up_inline_comment_lines: rolled_inline,
        rolled_up_span_lines: rolled_span,
    }
}

fn own_counts(code_unit: &CodeUnit, aggregates: &HashMap<String, (u32, u32)>) -> (u32, u32) {
    aggregates
        .get(&code_unit.fq_name())
        .copied()
        .unwrap_or_default()
}

fn span_lines(analyzer: &(impl IAnalyzer + ?Sized), code_unit: &CodeUnit) -> u32 {
    analyzer
        .ranges(code_unit)
        .iter()
        .map(|range| (range.end_line.saturating_sub(range.start_line) + 1) as u32)
        .sum()
}
