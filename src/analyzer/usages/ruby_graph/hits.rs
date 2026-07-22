use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{IAnalyzer, ProjectFile, Range};
use crate::text_utils::{find_line_index_for_offset, trimmed_snippet_around_line};
use std::collections::BTreeSet;
use tree_sitter::Node;

pub(super) fn record_usage_hit(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    hits: &mut BTreeSet<UsageHit>,
    node: Node<'_>,
) {
    let range = crate::analyzer::ruby::ruby_semantic_identifier_range(node, source);
    let start_byte = range.start_byte;
    let end_byte = range.end_byte;
    if start_byte >= end_byte {
        return;
    }
    let line_idx = find_line_index_for_offset(line_starts, start_byte);
    let snippet = trimmed_snippet_around_line(source, line_starts, line_idx, SNIPPET_CONTEXT_LINES);
    let enclosing_range = Range {
        start_byte,
        end_byte,
        start_line: line_idx,
        end_line: line_idx,
    };
    let Some(enclosing) = analyzer.enclosing_code_unit(file, &enclosing_range) else {
        return;
    };
    hits.insert(usage_hit(
        file, line_idx, start_byte, end_byte, enclosing, snippet,
    ));
}

pub(super) fn record_unproven_usage_hit(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    hits: &mut BTreeSet<UsageHit>,
    node: Node<'_>,
) {
    let range = crate::analyzer::ruby::ruby_semantic_identifier_range(node, source);
    let start_byte = range.start_byte;
    let end_byte = range.end_byte;
    if start_byte >= end_byte {
        return;
    }
    let line_idx = find_line_index_for_offset(line_starts, start_byte);
    let snippet = trimmed_snippet_around_line(source, line_starts, line_idx, SNIPPET_CONTEXT_LINES);
    let enclosing_range = Range {
        start_byte,
        end_byte,
        start_line: line_idx,
        end_line: line_idx,
    };
    let Some(enclosing) = analyzer.enclosing_code_unit(file, &enclosing_range) else {
        return;
    };
    hits.insert(
        usage_hit(file, line_idx, start_byte, end_byte, enclosing, snippet).into_unproven(),
    );
}
