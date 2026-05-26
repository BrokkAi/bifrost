use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{CodeUnit, ProjectFile};

/// Graph-strategy hits land at the maximum confidence the regex analyzer also uses.
pub(super) const GRAPH_HIT_CONFIDENCE: f64 = 1.0;
/// Lines of context to include before/after a match in [`UsageHit::snippet`].
pub(super) const SNIPPET_CONTEXT_LINES: usize = 3;

pub(super) fn usage_hit(
    file: &ProjectFile,
    line_idx: usize,
    start_offset: usize,
    end_offset: usize,
    enclosing: CodeUnit,
    snippet: impl Into<String>,
) -> UsageHit {
    UsageHit::new(
        file.clone(),
        line_idx + 1,
        start_offset,
        end_offset,
        enclosing,
        GRAPH_HIT_CONFIDENCE,
        snippet,
    )
}
