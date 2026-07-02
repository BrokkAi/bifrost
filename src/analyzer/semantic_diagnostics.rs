use crate::analyzer::Range;
use crate::hash::HashSet;
use crate::text_utils::find_line_index_for_offset;
use tree_sitter::Node;

#[derive(Default)]
pub(crate) struct ScopeStack {
    scopes: Vec<HashSet<String>>,
}

impl ScopeStack {
    pub(crate) fn enter(&mut self) {
        self.scopes.push(HashSet::default());
    }

    pub(crate) fn exit(&mut self) {
        self.scopes.pop();
    }

    pub(crate) fn declare(&mut self, name: String) {
        if name.is_empty() || name == "_" {
            return;
        }
        if self.scopes.is_empty() {
            self.enter();
        }
        let scope = self.scopes.last_mut().expect("scope exists after enter");
        scope.insert(name);
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        self.scopes.iter().rev().any(|scope| scope.contains(name))
    }
}

pub(crate) fn node_range(node: Node<'_>, line_starts: &[usize]) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: find_line_index_for_offset(line_starts, node.start_byte()) + 1,
        end_line: find_line_index_for_offset(line_starts, node.end_byte().saturating_sub(1)) + 1,
    }
}

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

pub(crate) fn same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.start_byte() == right.start_byte() && left.end_byte() == right.end_byte()
}

pub(crate) fn contains_node(container: Node<'_>, node: Node<'_>) -> bool {
    container.start_byte() <= node.start_byte() && node.end_byte() <= container.end_byte()
}
