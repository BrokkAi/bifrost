//! Pure Ruby node helpers shared by the declaration walk, the structural spec,
//! the import binder and both usage-graph scans.
//!
//! These were free functions at the top of `analyzer/ruby/mod.rs`, above the
//! `RubyAnalyzer` struct: nothing here needs an analyzer handle, only a
//! `tree_sitter::Node` and the source text it points into.

use brokk_bifrost_core::analyzer::model::Range;
use brokk_bifrost_core::analyzer::structural::callable::CalleeSpelling;
use tree_sitter::Node;

pub fn call_method_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("method")
}

/// Where a Ruby call-shaped node stands relative to an assignment that
/// dispatches through it.
///
/// Ruby compiles a write to `r.attr` into a call of `attr=` and a write to
/// `r[i]` into a call of `[]=`. The grammar reuses the reader's `call` and
/// `element_reference` nodes for those targets, so the position decides which
/// method the node calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RubyWriterPosition {
    /// Not an assignment target: the node calls its reader (`attr`, `[]`).
    Reader,
    /// The left side of a plain `=`: the right side is the writer's value.
    PlainAssignment,
    /// A parallel-assignment, `for` or `rescue =>` target. The node calls the
    /// writer, but the value it passes is assembled at runtime and has no
    /// source expression of its own.
    DestructuredAssignment,
}

pub fn ruby_writer_position(node: Node<'_>) -> RubyWriterPosition {
    let Some(parent) = node.parent() else {
        return RubyWriterPosition::Reader;
    };
    let is_field = |field: &str| {
        parent
            .child_by_field_name(field)
            .is_some_and(|child| child.id() == node.id())
    };
    match parent.kind() {
        "assignment" if is_field("left") => RubyWriterPosition::PlainAssignment,
        "left_assignment_list"
        | "destructured_left_assignment"
        | "rest_assignment"
        | "exception_variable" => RubyWriterPosition::DestructuredAssignment,
        "for" if is_field("pattern") => RubyWriterPosition::DestructuredAssignment,
        _ => RubyWriterPosition::Reader,
    }
}

/// The method a Ruby `call` or `element_reference` node calls, relative to the
/// name token it writes ([`ruby_callee_token`]).
///
/// An operator assignment (`r.attr += 1`) keeps the reader spelling: its
/// target calls both the reader and the writer, and the node records the
/// reader it writes.
pub fn ruby_callee_spelling(node: Node<'_>) -> CalleeSpelling {
    let writer = ruby_writer_position(node) != RubyWriterPosition::Reader;
    match node.kind() {
        "element_reference" if writer => CalleeSpelling::ElementAssignment,
        "element_reference" => CalleeSpelling::ElementReference,
        "call" if writer && call_method_node(node).is_some() => CalleeSpelling::AttributeWriter,
        _ => CalleeSpelling::Written,
    }
}

/// The token a Ruby call-shaped node records as its callee name: the method
/// of a `call`, or the opening bracket of an `element_reference`.
pub fn ruby_callee_token(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "element_reference" => {
            let mut cursor = node.walk();
            node.children(&mut cursor)
                .find(|child| !child.is_named() && child.kind() == "[")
        }
        _ => call_method_node(node),
    }
}

/// The receiver a Ruby call-shaped node is written against.
pub fn ruby_call_receiver(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "element_reference" => node.child_by_field_name("object"),
        _ => node.child_by_field_name("receiver"),
    }
}

/// The value a plain assignment passes to the writer this node calls.
pub fn ruby_assigned_value(node: Node<'_>) -> Option<Node<'_>> {
    (ruby_writer_position(node) == RubyWriterPosition::PlainAssignment)
        .then(|| node.parent()?.child_by_field_name("right"))
        .flatten()
}

/// The index arguments written between an element reference's brackets.
pub fn ruby_element_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    debug_assert_eq!(node.kind(), "element_reference");
    let object = node.child_by_field_name("object").map(|child| child.id());
    let block = node.child_by_field_name("block").map(|child| child.id());
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| {
            Some(child.id()) != object && Some(child.id()) != block && is_runtime_node(child.kind())
        })
        .collect()
}

/// Whether a call's receiver can select one of `Kernel`'s module functions
/// (`load`, `require`, `require_relative`, `eval`).
///
/// `module_function` makes each a private instance method of `Kernel` and a
/// public singleton method of `Kernel` itself. A private method is selected
/// only with no receiver or the literal `self`, so `Kernel` and `::Kernel` are
/// the only explicit receivers that reach these functions. Any other receiver
/// (`Marshal.load`, `JSON.load`, `loader.require`) selects its own public
/// method or raises `NoMethodError`. A constant or local that aliases the
/// `Kernel` module object is not recognized.
pub fn ruby_call_selects_kernel_function(call: Node<'_>, source: &str) -> bool {
    let Some(receiver) = call.child_by_field_name("receiver") else {
        return true;
    };
    let constant = match receiver.kind() {
        "self" => return true,
        "constant" => receiver,
        "scope_resolution" if receiver.child_by_field_name("scope").is_none() => {
            let Some(name) = receiver.child_by_field_name("name") else {
                return false;
            };
            name
        }
        _ => return false,
    };
    constant.kind() == "constant"
        && constant
            .utf8_text(source.as_bytes())
            .is_ok_and(|name| name == "Kernel")
}

/// Return only the binding-name nodes owned by a Ruby formal parameter list.
/// The callback is charged for each visited node and inspected parameter
/// child, allowing bounded callers to keep their budget at the call site.
pub fn ruby_parameter_binding_name_nodes<'tree>(
    parameters: Node<'tree>,
    mut step: impl FnMut() -> bool,
) -> Option<Vec<Node<'tree>>> {
    let mut stack = vec![parameters];
    let mut names = Vec::new();
    while let Some(current) = stack.pop() {
        if !step() {
            return None;
        }
        match current.kind() {
            "identifier" => names.push(current),
            "optional_parameter"
            | "keyword_parameter"
            | "splat_parameter"
            | "hash_splat_parameter"
            | "block_parameter" => {
                for index in 0..current.child_count() {
                    if !step() {
                        return None;
                    }
                    if current.field_name_for_child(index as u32) == Some("name")
                        && let Some(name) = current.child(index).filter(Node::is_named)
                    {
                        stack.push(name);
                    }
                }
            }
            "method_parameters"
            | "lambda_parameters"
            | "block_parameters"
            | "destructured_parameter" => {
                let mut cursor = current.walk();
                for child in current.named_children(&mut cursor) {
                    if !step() {
                        return None;
                    }
                    stack.push(child);
                }
            }
            _ => {}
        }
    }
    names.sort_unstable_by_key(Node::start_byte);
    names.dedup_by_key(|node| (node.start_byte(), node.end_byte()));
    Some(names)
}

pub fn single_static_string_content_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.named_child_count() != 1 {
        return None;
    }
    let content = node.named_child(0)?;
    (content.kind() == "string_content").then_some(content)
}

pub fn ruby_static_string_content_node(node: Node<'_>) -> Option<Node<'_>> {
    (node.kind() == "string")
        .then(|| single_static_string_content_node(node))
        .flatten()
}

pub fn ruby_call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = ruby_call_arguments_node(node) else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter(|child| is_runtime_node(child.kind()))
        .collect()
}

pub fn ruby_first_call_argument(node: Node<'_>) -> Option<Node<'_>> {
    let arguments = ruby_call_arguments_node(node)?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .find(|child| is_runtime_node(child.kind()))
}

fn ruby_call_arguments_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("arguments")
}

/// Whether an argument-list child is a runtime value rather than a parameter,
/// comment or symbol-key slot. Also read by the parked Ruby value-semantics
/// lowerer, which enumerates call arguments the same way.
pub fn is_runtime_node(kind: &str) -> bool {
    !matches!(
        kind,
        "comment"
            | "method_parameters"
            | "lambda_parameters"
            | "block_parameters"
            | "block_parameter"
            | "optional_parameter"
            | "keyword_parameter"
            | "splat_parameter"
            | "hash_splat_parameter"
            | "forward_parameter"
            | "destructured_parameter"
            | "exception_variable"
            | "hash_key_symbol"
            | "bare_symbol"
    )
}

/// Returns the source range of the semantic identifier carried by a Ruby symbol.
///
/// Tree-sitter represents an unquoted symbol such as `:audit` as one leaf
/// `simple_symbol` node, so its parser range includes the leading colon. Static
/// quoted symbols have a structured `string_content` child that excludes both
/// the colon and quote delimiters. Other nodes keep their parser range.
pub fn ruby_semantic_identifier_range(node: Node<'_>, source: &str) -> Range {
    let node_range = || Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };

    match node.kind() {
        "simple_symbol" => {
            let text = source.get(node.start_byte()..node.end_byte()).unwrap_or("");
            if text.strip_prefix(':').is_none_or(str::is_empty) {
                return node_range();
            }
            Range {
                start_byte: node.start_byte() + ':'.len_utf8(),
                end_byte: node.end_byte(),
                start_line: node.start_position().row,
                end_line: node.end_position().row,
            }
        }
        "hash_key_symbol" => {
            let text = source.get(node.start_byte()..node.end_byte()).unwrap_or("");
            if !text.ends_with(':') || text.len() == ':'.len_utf8() {
                return node_range();
            }
            Range {
                start_byte: node.start_byte(),
                end_byte: node.end_byte() - ':'.len_utf8(),
                start_line: node.start_position().row,
                end_line: node.end_position().row,
            }
        }
        "delimited_symbol" => {
            let Some(content) = single_static_string_content_node(node) else {
                return node_range();
            };
            Range {
                start_byte: content.start_byte(),
                end_byte: content.end_byte(),
                start_line: content.start_position().row,
                end_line: content.end_position().row,
            }
        }
        _ => node_range(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_comment_extras_do_not_occupy_runtime_positions() {
        let source = "sink(\n# before\n source(),\n# between\n value\n)";
        let tree = crate::declarations::parse_ruby_tree(source).unwrap();
        assert!(!tree.root_node().has_error());
        let call = tree.root_node().named_child(0).unwrap();
        let arguments = call.child_by_field_name("arguments").unwrap();
        let children = arguments
            .named_children(&mut arguments.walk())
            .map(|n| n.kind())
            .collect::<Vec<_>>();
        assert_eq!(children, ["comment", "call", "comment", "identifier"]);
        let actual = ruby_call_arguments(call);
        assert_eq!(
            actual
                .iter()
                .map(|node| &source[node.byte_range()])
                .collect::<Vec<_>>(),
            ["source()", "value"]
        );
        assert_eq!(ruby_first_call_argument(call), Some(actual[0]));
    }
}
