use crate::graph::PhpGraphSource;
use crate::graph::resolver::TargetSpec;
use crate::graph_support::PhpAnalysisSource;
use brokk_bifrost_core::analyzer::model::Range;
use brokk_bifrost_core::analyzer::usages::common::{
    SNIPPET_CONTEXT_LINES, reclassify_import_hit_at, reclassify_override_declaration_hit_at,
    reclassify_self_receiver_hit_at, usage_hit,
};
use brokk_bifrost_core::analyzer::usages::model::UsageHit;
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::text_utils::{find_line_index_for_offset, snippet_around_line};
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

pub fn push_hit(
    node: Node<'_>,
    analyzer: PhpGraphSource<'_>,
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
pub fn push_import_hit(
    node: Node<'_>,
    analyzer: PhpGraphSource<'_>,
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
pub fn push_hit_range(
    start: usize,
    end: usize,
    analyzer: PhpGraphSource<'_>,
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
    let Some(enclosing) = analyzer.index.enclosing_code_unit(file, &range) else {
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

/// Push a hit for `[start, end)` then reclassify it as a same-owner self/this
/// receiver hit (`$this->m()`, `self::m()`, `static::m()`) — excluded from the
/// external usage surface, counted as a same-owner site (#1014 facet B).
#[allow(clippy::too_many_arguments)]
pub fn push_self_receiver_hit_range(
    start: usize,
    end: usize,
    analyzer: PhpGraphSource<'_>,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    push_hit_range(start, end, analyzer, file, source, line_starts, spec, hits);
    reclassify_self_receiver_hit_at(hits, file, start, end);
}

pub fn push_override_declaration_hit(
    php: &dyn PhpAnalysisSource,
    analyzer: PhpGraphSource<'_>,
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
    let line_starts = brokk_bifrost_core::text_utils::compute_line_starts(&source);
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_line: find_line_index_for_offset(&line_starts, start),
        end_line: find_line_index_for_offset(&line_starts, end),
    };
    let enclosing = analyzer
        .index
        .enclosing_code_unit(file, &range)
        .unwrap_or_else(|| declaration.clone());
    hits.insert(usage_hit(
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
    ));
    reclassify_override_declaration_hit_at(hits, file, start, end);
}

fn declaration_name_range(
    php: &dyn PhpAnalysisSource,
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
