//! Token and AST-label normalization for C++ structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned and the
//! declaration source comes from the analyzer, so `analyzer/cpp/clones.rs` keeps
//! the ~12-LOC entry point; everything that knows C++ is here.

use brokk_bifrost_core::analyzer::tree_walk::push_children_reversed;
use brokk_bifrost_core::clones::{
    CloneNormalizationRules, normalize_clone_ast_label as normalize_cpp_clone_ast_label,
    normalize_clone_leaf_token as normalize_cpp_clone_leaf_token,
};
use tree_sitter::{Node, Parser};

const CPP_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &[
    "identifier",
    "field_identifier",
    "namespace_identifier",
    "type_identifier",
];
const CPP_CLONE_AST_STRING_TYPES: &[&str] = &["string_literal", "raw_string_literal"];
const CPP_CLONE_AST_NUMBER_TYPES: &[&str] = &["number_literal"];
const CPP_CLONE_NORMALIZATION_RULES: CloneNormalizationRules = CloneNormalizationRules {
    identifier_kinds: CPP_CLONE_AST_IDENTIFIER_TYPES,
    string_kinds: CPP_CLONE_AST_STRING_TYPES,
    number_kinds: CPP_CLONE_AST_NUMBER_TYPES,
    boolean_kinds: &[],
    boolean_values: &["true", "false"],
    null_kinds: &[],
    null_values: &[],
    comment_kinds: &["comment"],
    ignored_ast_kinds: &[],
};

pub fn cpp_clone_parser() -> Parser {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .expect("failed to load cpp parser");
    parser
}

/// The normalized token stream and the joined AST-label signature for one C++
/// declaration body, in a single walk.
pub fn cpp_clone_profile(parser: &mut Parser, source: &str) -> (Vec<String>, String) {
    let Some(tree) = parser.parse(source, None) else {
        return (Vec::new(), String::new());
    };
    let mut normalized_tokens = Vec::new();
    let mut ast_labels = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if cpp_is_ignorable_clone_logging_node(node, source) {
            continue;
        }
        ast_labels.push(normalize_cpp_clone_ast_label(
            node,
            source,
            CPP_CLONE_NORMALIZATION_RULES,
        ));
        if node.named_child_count() == 0 {
            let token = normalize_cpp_clone_leaf_token(node, source, CPP_CLONE_NORMALIZATION_RULES);
            if !token.is_empty() {
                normalized_tokens.push(token);
            }
        }
        push_children_reversed(node, &mut stack);
    }
    (normalized_tokens, ast_labels.join("|"))
}

fn cpp_is_ignorable_clone_logging_node(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "expression_statement" {
        return false;
    }
    let Some(mut expression) = node.named_child(0) else {
        return false;
    };
    if expression.kind() == "call_expression" {
        return expression
            .child_by_field_name("function")
            .is_some_and(|function| {
                function.kind() == "identifier"
                    && function.utf8_text(source.as_bytes()).expect("source node") == "printf"
            });
    }
    if expression.kind() != "binary_expression" {
        return false;
    }
    // Stream insertion is left associative. Only a chain rooted at a logging
    // stream is ignorable; a sink mentioned in an argument is ordinary work.
    while expression.kind() == "binary_expression" {
        if expression
            .child_by_field_name("operator")
            .is_none_or(|operator| operator.kind() != "<<")
        {
            return false;
        }
        expression = expression
            .child_by_field_name("left")
            .expect("binary expression has a left operand");
    }
    expression.kind() == "qualified_identifier"
        && expression
            .child_by_field_name("scope")
            .is_some_and(|scope| {
                scope.kind() == "namespace_identifier"
                    && scope.utf8_text(source.as_bytes()).expect("source node") == "std"
            })
        && expression.child_by_field_name("name").is_some_and(|name| {
            name.kind() == "identifier"
                && matches!(
                    name.utf8_text(source.as_bytes()).expect("source node"),
                    "cout" | "cerr" | "clog"
                )
        })
}

#[cfg(test)]
mod tests {
    mod clone_properties {
        use brokk_bifrost_test_macros::hardwon;
        use proptest::prelude::*;

        // Oracle: consistent identifier/literal renaming and inserting standalone
        // printf/std::{cout,cerr,clog} statements preserve the clone class. Adding
        // a branch or a non-logging call changes it, even when a string argument
        // spells a sink or a sink call is nested inside the new call.
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]
            #[test]
            #[hardwon("d4f00f8567e4: ordinary calls containing stream names disappeared from clone profiles")]
            fn clone_edits_obey_declared_equivalence_classes(value in 1u16..1000) {
                let mut parser = crate::clones::cpp_clone_parser();
                let original = "int sum(int n) { int total = 1; for (int i = 0; i < n; ++i) { total += i; } return total; }";
                let renamed = format!("int count(int limit) {{ int result = {value}; for (int index = 0; index < limit; ++index) {{ result += index; }} return result; }}");
                let profile = crate::clones::cpp_clone_profile(&mut parser, original);
                prop_assert_eq!(&profile, &crate::clones::cpp_clone_profile(&mut parser, &renamed));
                for log in ["printf(\"progress\");", "std::cout << total;", "std::cerr << total;", "std::clog << total;"] {
                    let edited = original.replace("return total;", &format!("{log} return total;"));
                    prop_assert_eq!(&profile, &crate::clones::cpp_clone_profile(&mut parser, &edited), "log: {}", log);
                }
                for work in ["if (n) { ++total; }", "consume(total);", "consume(\"std::cout\");", "consume(\"std::cerr\");", "consume(\"std::clog\");", "consume(\"printf(\");", "consume(printf(\"progress\"));", "consume(std::cout);"] {
                    let edited = original.replace("return total;", &format!("{work} return total;"));
                    prop_assert_ne!(&profile, &crate::clones::cpp_clone_profile(&mut parser, &edited), "work: {}", work);
                }
            }
        }
    }
}
