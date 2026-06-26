use std::collections::BTreeSet;

use lsp_types::{FoldingRange, FoldingRangeParams};

use crate::analyzer::{CodeUnit, IAnalyzer, Project, WorkspaceAnalyzer};
use crate::lsp::conversion::byte_range_to_lsp_range;
use crate::lsp::handlers::util::read_document_for_uri;

/// Build the foldingRange response for a request URI. Returns `None` when the
/// URI does not map into the active project root, or when the file cannot be
/// read. Returns `Some(empty)` when the file has no foldable blocks (LSP
/// clients treat both shapes the same, but `None` lets the dispatcher report
/// "no result" instead of "empty result" when the URI is unknown).
pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &FoldingRangeParams,
) -> Option<Vec<FoldingRange>> {
    let (project_file, content, line_starts) =
        read_document_for_uri(project, &params.text_document.uri)?;
    let analyzer = workspace.analyzer();

    // Dedup by (start_line, end_line) since overloads or nested scans can
    // legitimately produce duplicate spans, and BTreeSet also gives us a stable
    // ordering by start line in the response.
    let mut folds: BTreeSet<(u32, u32)> = BTreeSet::new();
    for cu in analyzer
        .top_level_declarations(&project_file)
        .filter(|cu| !cu.is_anonymous())
    {
        collect_folds(analyzer, cu, &content, &line_starts, &mut folds);
    }

    Some(
        folds
            .into_iter()
            .map(|(start_line, end_line)| FoldingRange {
                start_line,
                end_line,
                start_character: None,
                end_character: None,
                kind: None,
                collapsed_text: None,
            })
            .collect(),
    )
}

fn collect_folds(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    content: &str,
    line_starts: &[usize],
    out: &mut BTreeSet<(u32, u32)>,
) {
    let mut stack = vec![code_unit.clone()];
    while let Some(unit) = stack.pop() {
        for range in analyzer.ranges(&unit) {
            let lsp = byte_range_to_lsp_range(content, line_starts, range);
            // LSP foldingRange uses line numbers; single-line spans (block headers
            // like `class Foo {}` on one line) are not foldable and are dropped.
            if lsp.end.line > lsp.start.line {
                out.insert((lsp.start.line, lsp.end.line));
            }
        }
        for child in analyzer.direct_children(&unit) {
            if child.is_anonymous() {
                continue;
            }
            stack.push(child.clone());
        }
    }
}
