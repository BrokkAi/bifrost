use crate::analyzer::Range;
use crate::analyzer::model::SemanticDiagnosticReport;
use crate::analyzer::structural::resolution::BoundaryStatus;
use crate::hash::HashSet;
use crate::text_utils::find_line_index_for_offset;
use tree_sitter::Node;

#[derive(Default)]
pub struct ScopeStack {
    scopes: Vec<HashSet<String>>,
}

impl ScopeStack {
    pub fn enter(&mut self) {
        self.scopes.push(HashSet::default());
    }

    pub fn exit(&mut self) {
        self.scopes.pop();
    }

    pub fn declare(&mut self, name: String) {
        if name.is_empty() || name == "_" {
            return;
        }
        if self.scopes.is_empty() {
            self.enter();
        }
        let scope = self.scopes.last_mut().expect("scope exists after enter");
        scope.insert(name);
    }

    pub fn contains(&self, name: &str) -> bool {
        self.scopes.iter().rev().any(|scope| scope.contains(name))
    }
}

pub fn node_range(node: Node<'_>, line_starts: &[usize]) -> Range {
    range_for_byte_span(line_starts, node.start_byte(), node.end_byte())
}

pub fn push_resolved_node(
    report: &mut SemanticDiagnosticReport,
    node: Node<'_>,
    line_starts: &[usize],
    boundary: BoundaryStatus,
) {
    report.push_resolved(node_range(node, line_starts), boundary);
}

/// Build a 1-based range from a half-open byte span, mapping
/// `end_byte.saturating_sub(1)` for the end line.
pub fn range_for_byte_span(line_starts: &[usize], start_byte: usize, end_byte: usize) -> Range {
    Range {
        start_byte,
        end_byte,
        start_line: find_line_index_for_offset(line_starts, start_byte) + 1,
        end_line: find_line_index_for_offset(line_starts, end_byte.saturating_sub(1)) + 1,
    }
}

/// Build a 1-based range by mapping both byte offsets directly to their lines.
pub fn range_for_byte_offsets(line_starts: &[usize], start_byte: usize, end_byte: usize) -> Range {
    Range {
        start_byte,
        end_byte,
        start_line: find_line_index_for_offset(line_starts, start_byte) + 1,
        end_line: find_line_index_for_offset(line_starts, end_byte) + 1,
    }
}

pub use crate::analyzer::common::node_source_text as node_text;

pub fn same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.start_byte() == right.start_byte() && left.end_byte() == right.end_byte()
}

pub fn contains_node(container: Node<'_>, node: Node<'_>) -> bool {
    container.start_byte() <= node.start_byte() && node.end_byte() <= container.end_byte()
}
