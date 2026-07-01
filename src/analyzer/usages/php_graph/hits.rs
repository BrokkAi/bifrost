use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, reclassify_import_hit_at, usage_hit};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::php_graph::resolver::TargetSpec;
use crate::analyzer::{CodeUnit, IAnalyzer, PhpAnalyzer, ProjectFile, Range};
use crate::text_utils::{find_line_index_for_offset, snippet_around_line};
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

pub(super) fn push_hit(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    push_hit_range(
        node.start_byte(),
        node.end_byte(),
        analyzer,
        file,
        source,
        line_starts,
        spec,
        hits,
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) fn push_import_hit(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    push_hit(node, analyzer, file, source, line_starts, spec, hits);
    reclassify_import_hit_at(hits, file, node.start_byte(), node.end_byte());
}

#[allow(clippy::too_many_arguments)]
pub(super) fn push_hit_range(
    start: usize,
    end: usize,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_line: find_line_index_for_offset(line_starts, start),
        end_line: find_line_index_for_offset(line_starts, end),
    };
    let Some(enclosing) = analyzer.enclosing_code_unit(file, &range) else {
        return;
    };
    if enclosing == spec.target {
        return;
    }
    hits.insert(usage_hit(
        file,
        range.start_line,
        start,
        end,
        enclosing,
        snippet_around_line(source, line_starts, range.start_line, SNIPPET_CONTEXT_LINES),
    ));
}

pub(super) fn push_override_declaration_hit(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    declaration: &CodeUnit,
    hits: &mut BTreeSet<UsageHit>,
) {
    let file = declaration.source();
    let Ok(source) = file.read_to_string() else {
        return;
    };
    let Some((start, end)) = declaration_name_range(php, declaration, &source) else {
        return;
    };
    let line_starts = crate::text_utils::compute_line_starts(&source);
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_line: find_line_index_for_offset(&line_starts, start),
        end_line: find_line_index_for_offset(&line_starts, end),
    };
    let enclosing = analyzer
        .enclosing_code_unit(file, &range)
        .unwrap_or_else(|| declaration.clone());
    hits.insert(
        usage_hit(
            file,
            range.start_line,
            start,
            end,
            enclosing,
            snippet_around_line(
                &source,
                &line_starts,
                range.start_line,
                SNIPPET_CONTEXT_LINES,
            ),
        )
        .into_override_declaration(),
    );
}

fn declaration_name_range(
    php: &PhpAnalyzer,
    declaration: &CodeUnit,
    source: &str,
) -> Option<(usize, usize)> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    let tree = parser.parse(source, None)?;
    let ranges = php.ranges(declaration);
    let start = ranges.iter().map(|range| range.start_byte).min()?;
    let end = ranges.iter().map(|range| range.end_byte).max()?;
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "method_declaration" | "function_definition")
            && node.start_byte() >= start
            && node.end_byte() <= end
            && let Some(name) = node.child_by_field_name("name")
        {
            return Some((name.start_byte(), name.end_byte()));
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index)
                && child.end_byte() >= start
                && child.start_byte() <= end
            {
                stack.push(child);
            }
        }
    }
    None
}
