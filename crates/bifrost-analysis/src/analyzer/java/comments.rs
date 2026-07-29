use super::*;
use crate::analyzer::tree_sitter_analyzer::expanded_comment_start;
use crate::path_utils::rel_path_string;
use tree_sitter::Node;

pub(super) fn collect_java_comment_aggregates(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> HashMap<String, (u32, u32)> {
    let mut aggs: HashMap<String, (u32, u32)> = HashMap::default();
    let Some(tree) = parse_tree(source) else {
        return aggs;
    };
    let mut comments: Vec<Node<'_>> = Vec::new();
    collect_comment_nodes(tree.root_node(), &mut comments);

    for comment in comments {
        let cs = comment.start_byte();
        let ce = comment.end_byte();
        let Some(cu) = enclosing_code_unit_by_comment_bytes(analyzer, source, file, cs, ce) else {
            continue;
        };
        let ranges = analyzer.ranges(&cu);
        let Some(range) = ranges
            .iter()
            .filter(|r| {
                let cstart = expanded_comment_start(source, r.start_byte);
                cs >= cstart && ce <= r.end_byte
            })
            .min_by_key(|r| {
                let cstart = expanded_comment_start(source, r.start_byte);
                r.end_byte.saturating_sub(cstart)
            })
            .copied()
        else {
            continue;
        };
        let header = ce <= range.start_byte;
        let sr = comment.start_position().row;
        let er = comment.end_position().row;
        let lines = (er.saturating_sub(sr) + 1) as u32;
        let entry = aggs.entry(cu.fq_name()).or_default();
        if header {
            entry.0 += lines;
        } else {
            entry.1 += lines;
        }
    }

    aggs
}

fn collect_comment_nodes<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    if is_comment_node(node) {
        out.push(node);
        return;
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_comment_nodes(child, out);
        }
    }
}

fn enclosing_code_unit_by_comment_bytes(
    analyzer: &dyn IAnalyzer,
    source: &str,
    file: &ProjectFile,
    cs: usize,
    ce: usize,
) -> Option<CodeUnit> {
    if cs > ce {
        return None;
    }
    let mut best: Option<(CodeUnit, usize)> = None;
    for top in analyzer.top_level_declarations(file) {
        if let Some(cand) =
            find_deepest_enclosing_by_comment_bytes(analyzer, source, &top, cs, ce, 0)
            && best.as_ref().map(|b| cand.1 > b.1).unwrap_or(true)
        {
            best = Some(cand);
        }
    }
    best.map(|(cu, _)| cu)
}

fn find_deepest_enclosing_by_comment_bytes(
    analyzer: &dyn IAnalyzer,
    source: &str,
    cu: &CodeUnit,
    cs: usize,
    ce: usize,
    depth: usize,
) -> Option<(CodeUnit, usize)> {
    let ranges = analyzer.ranges(cu);
    let contains = ranges.iter().any(|r| {
        let cstart = expanded_comment_start(source, r.start_byte);
        cs >= cstart && ce <= r.end_byte
    });
    if !contains {
        return None;
    }
    let mut best: (CodeUnit, usize) = (cu.clone(), depth);
    for child in analyzer.direct_children(cu) {
        if let Some(cand) =
            find_deepest_enclosing_by_comment_bytes(analyzer, source, &child, cs, ce, depth + 1)
            && cand.1 > best.1
        {
            best = cand;
        }
    }
    Some(best)
}

/// Build a [`CommentDensityStats`] entry for `cu`, rolling up nested
/// declarations (class-like units only). Mirrors brokk-shared
/// `JavaAnalyzer.buildRollUpStats`.
pub(super) fn build_java_roll_up_stats(
    analyzer: &dyn IAnalyzer,
    cu: &CodeUnit,
    aggs: &HashMap<String, (u32, u32)>,
) -> CommentDensityStats {
    let own = aggs.get(&cu.fq_name()).copied().unwrap_or((0, 0));
    let span: u32 = analyzer
        .ranges(cu)
        .iter()
        .map(|r| (r.end_line.saturating_sub(r.start_line) + 1) as u32)
        .sum();
    let relative_path = rel_path_string(cu.source());
    if !cu.is_class() {
        return CommentDensityStats {
            fq_name: cu.fq_name(),
            relative_path,
            header_comment_lines: own.0,
            inline_comment_lines: own.1,
            span_lines: span,
            rolled_up_header_comment_lines: own.0,
            rolled_up_inline_comment_lines: own.1,
            rolled_up_span_lines: span,
        };
    }
    let mut rh = own.0;
    let mut ri = own.1;
    let mut rs = span;
    for child in analyzer.direct_children(cu) {
        let chs = build_java_roll_up_stats(analyzer, &child, aggs);
        rh += chs.rolled_up_header_comment_lines;
        ri += chs.rolled_up_inline_comment_lines;
        rs += chs.rolled_up_span_lines;
    }
    CommentDensityStats {
        fq_name: cu.fq_name(),
        relative_path,
        header_comment_lines: own.0,
        inline_comment_lines: own.1,
        span_lines: span,
        rolled_up_header_comment_lines: rh,
        rolled_up_inline_comment_lines: ri,
        rolled_up_span_lines: rs,
    }
}
