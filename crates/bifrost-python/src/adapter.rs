//! The Python answers behind `PythonAdapter`.
//!
//! `LanguageAdapter` is analysis-owned, so the trait impl itself stays in
//! `analyzer/python/adapter.rs`; every answer it gives comes from here or from
//! [`crate::declarations`]. `synthesize_hydrated_units` is the one exception:
//! it mutates `FileState`, an analysis type, and stays with the shell.

use brokk_bifrost_core::analyzer::cognitive_complexity;
use std::sync::LazyLock;

use crate::declarations::python_is_decorated_function_boundary;

pub const PYTHON_FILE_EXTENSION: &str = "py";

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer
/// for Python. Mirrors `ai.brokk.analyzer.python.CognitiveComplexityAnalysis`.
pub static PYTHON_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        alternate_if_types: &["elif_clause"],
        loop_types: &["for_statement", "while_statement"],
        catch_types: &["except_clause"],
        conditional_types: &["conditional_expression"],
        case_types: &["case_clause"],
        binary_types: &["boolean_operator"],
        logical_operators: &["and", "or"],
        named_function_boundary_types: &["function_definition"],
        anonymous_function_types: &["lambda"],
        named_function_boundary_predicate: Some(python_is_decorated_function_boundary),
        ..cognitive_complexity::Config::empty()
    });

pub fn python_extract_call_receiver(reference: &str) -> Option<String> {
    brokk_bifrost_core::analyzer::common::extract_call_reference_parts(reference, &["."])
        .map(|(receiver, _)| receiver.to_string())
}

/// Python data literals. Bytes and implicit concatenation use the same grammar
/// nodes; replacement fields remain executable structure.
pub const PYTHON_LINE_DATA_KINDS: brokk_bifrost_core::analyzer::tree_walk::LineDataKinds =
    brokk_bifrost_core::analyzer::tree_walk::LineDataKinds {
        literals: &["string", "concatenated_string", "integer", "float"],
        interpolations: &["interpolation"],
        composites: &[
            ("list", &["[", "]", ","]),
            ("tuple", &["(", ")", ","]),
            ("unary_operator", &["-", "+"]),
        ],
    };

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::ControlFlow;

    #[test]
    fn qs6_string_data_grammar_and_cancellation() {
        for (literal, kind, interpolations, data) in [
            ("u'caf\u{e9}'", "string", 0, true),
            ("b'bytes'", "string", 0, true),
            ("'one' 'two'", "concatenated_string", 0, true),
            ("f'plain {{braces}}'", "string", 0, true),
            ("f'{value:{width}}'", "string", 1, false),
            ("'prefix' f'{value}'", "concatenated_string", 1, false),
        ] {
            let source = format!("value = {literal}\n");
            let tree = crate::declarations::parse_python_tree(&source).unwrap();
            let root = tree.root_node();
            assert!(!root.has_error(), "{}", root.to_sexp());
            let value = root
                .named_child(0)
                .unwrap()
                .named_child(0)
                .unwrap()
                .child_by_field_name("right")
                .unwrap();
            assert_eq!(value.kind(), kind);
            let mut stack = vec![value];
            let mut count = 0;
            while let Some(node) = stack.pop() {
                assert!(!node.is_error() && !node.is_missing());
                count += usize::from(node.kind() == "interpolation");
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
            assert_eq!(count, interpolations, "{}", value.to_sexp());
            let data_subtrees = |should_stop: &mut dyn FnMut() -> bool| {
                match brokk_bifrost_core::analyzer::tree_walk::maximal_data_subtrees(
                    value,
                    &PYTHON_LINE_DATA_KINDS,
                    |_| true,
                    should_stop,
                ) {
                    ControlFlow::Continue(subtrees) => ControlFlow::Continue(
                        subtrees
                            .iter()
                            .any(|subtree| subtree.range == value.byte_range()),
                    ),
                    ControlFlow::Break(()) => ControlFlow::Break(()),
                }
            };
            assert_eq!(data_subtrees(&mut || false), ControlFlow::Continue(data));
            let mut stops = 0;
            assert_eq!(
                data_subtrees(&mut || {
                    stops += 1;
                    true
                }),
                ControlFlow::Break(())
            );
            assert_eq!(stops, 1);
        }
    }
}
