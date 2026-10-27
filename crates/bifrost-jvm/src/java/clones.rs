//! Token and AST-label normalization for Java structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned and the
//! declaration source comes from the analyzer, so `analyzer/java/clones.rs`
//! keeps the entry point; everything that knows Java is here. Same split as
//! [`brokk_bifrost_cpp::clones`].

use crate::java::declarations::parse_tree;
use brokk_bifrost_core::analyzer::source_content::SourceContent;
use brokk_bifrost_core::clones::{
    CloneNormalizationRules, clone_ast_signature_from_root, normalized_clone_tokens_from_root,
};
#[cfg(test)]
use brokk_bifrost_core::clones::{
    normalize_clone_ast_label as normalize_java_clone_ast_label,
    normalize_clone_leaf_token as normalize_java_clone_leaf_token,
};
#[cfg(any(test, feature = "test-support"))]
use std::cell::Cell;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static CLONE_PARSE_CALLS: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaClonePreparation {
    pub normalized_tokens: Vec<String>,
    pub ast_signature: String,
}

#[cfg(any(test, feature = "test-support"))]
pub fn reset_java_clone_parse_count_for_test() {
    CLONE_PARSE_CALLS.set(0);
}

#[cfg(any(test, feature = "test-support"))]
pub fn java_clone_parse_count_for_test() -> usize {
    CLONE_PARSE_CALLS.get()
}

fn parse_clone_tree(source: &str) -> Option<tree_sitter::Tree> {
    #[cfg(any(test, feature = "test-support"))]
    CLONE_PARSE_CALLS.set(CLONE_PARSE_CALLS.get() + 1);
    parse_tree(source)
}

const CLONE_AST_IDENTIFIER_TYPES: &[&str] = &[
    "identifier",
    "type_identifier",
    "scoped_identifier",
    "scoped_type_identifier",
];
const CLONE_AST_STRING_TYPES: &[&str] = &["string_literal", "character_literal"];
const CLONE_AST_NUMBER_TYPES: &[&str] = &[
    "decimal_integer_literal",
    "hex_integer_literal",
    "octal_integer_literal",
    "binary_integer_literal",
    "decimal_floating_point_literal",
    "hex_floating_point_literal",
];
const CLONE_AST_IGNORED_TYPES: &[&str] = &["modifiers", "type_parameters"];
const JAVA_CLONE_TOKEN_RULES: CloneNormalizationRules = CloneNormalizationRules {
    identifier_kinds: CLONE_AST_IDENTIFIER_TYPES,
    string_kinds: CLONE_AST_STRING_TYPES,
    number_kinds: CLONE_AST_NUMBER_TYPES,
    boolean_kinds: &[],
    boolean_values: &["true", "false"],
    null_kinds: &[],
    null_values: &[],
    comment_kinds: &[],
    ignored_ast_kinds: &[],
};
const JAVA_CLONE_AST_RULES: CloneNormalizationRules = CloneNormalizationRules {
    identifier_kinds: CLONE_AST_IDENTIFIER_TYPES,
    string_kinds: CLONE_AST_STRING_TYPES,
    number_kinds: CLONE_AST_NUMBER_TYPES,
    boolean_kinds: &["boolean_literal"],
    boolean_values: &["true", "false"],
    null_kinds: &[],
    null_values: &[],
    comment_kinds: &[],
    ignored_ast_kinds: CLONE_AST_IGNORED_TYPES,
};

/// Parse and prepare one Java clone candidate, stopping before AST-label work
/// when the normalized token threshold cannot be met.
pub fn prepare_java_clone(
    source: &str,
    min_normalized_tokens: usize,
) -> Option<JavaClonePreparation> {
    let Some(tree) = parse_clone_tree(source) else {
        return (min_normalized_tokens == 0).then(|| JavaClonePreparation {
            normalized_tokens: Vec::new(),
            ast_signature: String::new(),
        });
    };
    let content = SourceContent::new(source);
    let normalized_tokens = normalized_clone_tokens_from_root(
        tree.root_node(),
        content.as_str(),
        JAVA_CLONE_TOKEN_RULES,
    );
    if normalized_tokens.len() < min_normalized_tokens {
        return None;
    }

    Some(JavaClonePreparation {
        normalized_tokens,
        ast_signature: clone_ast_signature_from_root(
            tree.root_node(),
            content.as_str(),
            JAVA_CLONE_AST_RULES,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#3539: clone candidate preparation parsed the same Java/Python source repeatedly")]
    fn combined_preparation_matches_the_existing_outputs_with_one_parse() {
        let sources = [
            r#"
                class Sample {
                    public <T> boolean compare(T left, T right) {
                        String message = "same";
                        char marker = 'x';
                        int mask = 0x2A;
                        return left == right && true;
                    }
                }
            "#,
            "class Broken { // recovery\n void run( { int value = 07 + 1.5; }",
        ];

        for source in sources {
            let tree = parse_tree(source).unwrap();
            if source.contains("Broken") {
                assert!(tree.root_node().has_error());
            }
            let content = SourceContent::new(source);
            let mut expected_tokens = Vec::new();
            brokk_bifrost_core::test_support::walk_tree_preorder_reference(
                tree.root_node(),
                |node| {
                    if node.named_child_count() == 0 {
                        let token = normalize_java_clone_leaf_token(
                            node,
                            content.as_str(),
                            JAVA_CLONE_TOKEN_RULES,
                        );
                        if !token.is_empty() {
                            expected_tokens.push(token);
                        }
                    }
                },
            );
            let mut expected_labels = Vec::new();
            brokk_bifrost_core::test_support::walk_tree_preorder_reference(
                tree.root_node(),
                |node| {
                    expected_labels.push(normalize_java_clone_ast_label(
                        node,
                        content.as_str(),
                        JAVA_CLONE_AST_RULES,
                    ));
                },
            );

            reset_java_clone_parse_count_for_test();
            let preparation = prepare_java_clone(source, 0).unwrap();

            assert_eq!(preparation.normalized_tokens, expected_tokens);
            assert_eq!(preparation.ast_signature, expected_labels.join("|"));
            assert_eq!(java_clone_parse_count_for_test(), 1);
            if source.contains("compare") {
                for expected in ["STR", "NUM", "BOOL", "OP:="] {
                    assert!(
                        preparation
                            .normalized_tokens
                            .iter()
                            .any(|token| token == expected),
                        "missing normalized token {expected}"
                    );
                }
                assert!(
                    preparation
                        .ast_signature
                        .split('|')
                        .any(|label| label == "IGN")
                );
            }
        }
    }

    #[test]
    #[hardwon("#3539: clone candidate preparation parsed the same Java/Python source repeatedly")]
    fn rejected_candidate_still_uses_one_parse() {
        let token_count = prepare_java_clone("int value = 1;", 0)
            .unwrap()
            .normalized_tokens
            .len();
        reset_java_clone_parse_count_for_test();

        assert!(prepare_java_clone("int value = 1;", token_count).is_some());
        assert_eq!(java_clone_parse_count_for_test(), 1);
        reset_java_clone_parse_count_for_test();

        assert!(prepare_java_clone("int value = 1;", token_count + 1).is_none());
        assert_eq!(java_clone_parse_count_for_test(), 1);
    }

    #[test]
    #[hardwon("#3539: deeply nested Java source exceeded recursive clone-preparation depth")]
    fn deeply_nested_source_is_walked_without_recursion() {
        let depth = 2_000;
        let source = format!(
            "class Deep {{ Object value = {}0{}; }}",
            "(".repeat(depth),
            ")".repeat(depth)
        );

        let preparation = prepare_java_clone(&source, 0).unwrap();
        brokk_bifrost_core::test_support::assert_deep_clone_preparation(
            &preparation.normalized_tokens,
            &preparation.ast_signature,
            depth,
        );
    }
}
