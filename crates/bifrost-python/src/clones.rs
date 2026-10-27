//! Python's clone-detection token and AST-signature normalization.
//!
//! `analyzer/python/clones.rs` in `brokk-bifrost-analysis` keeps the entry
//! point: it reads the declaration's source through the analyzer and assembles
//! the analysis-owned `CloneCandidateData`. Everything that knows what a Python
//! token *is* lives here.

use crate::declarations::parse_python_tree;
use brokk_bifrost_core::clones::{
    CloneNormalizationRules, clone_ast_signature_from_root, normalized_clone_tokens_from_root,
};
#[cfg(test)]
use brokk_bifrost_core::clones::{
    normalize_clone_ast_label as normalize_python_clone_ast_label,
    normalize_clone_leaf_token as normalize_python_clone_leaf_token,
};
#[cfg(any(test, feature = "test-support"))]
use std::cell::Cell;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static CLONE_PARSE_CALLS: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonClonePreparation {
    pub normalized_tokens: Vec<String>,
    pub ast_signature: String,
}

#[cfg(any(test, feature = "test-support"))]
pub fn reset_python_clone_parse_count_for_test() {
    CLONE_PARSE_CALLS.set(0);
}

#[cfg(any(test, feature = "test-support"))]
pub fn python_clone_parse_count_for_test() -> usize {
    CLONE_PARSE_CALLS.get()
}

fn parse_clone_tree(source: &str) -> Option<tree_sitter::Tree> {
    #[cfg(any(test, feature = "test-support"))]
    CLONE_PARSE_CALLS.set(CLONE_PARSE_CALLS.get() + 1);
    parse_python_tree(source)
}

const PYTHON_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &["identifier", "keyword_identifier"];
const PYTHON_CLONE_AST_STRING_TYPES: &[&str] = &["string", "string_content", "interpolation"];
const PYTHON_CLONE_AST_NUMBER_TYPES: &[&str] = &["integer", "float"];
const PYTHON_CLONE_NORMALIZATION_RULES: CloneNormalizationRules = CloneNormalizationRules {
    identifier_kinds: PYTHON_CLONE_AST_IDENTIFIER_TYPES,
    string_kinds: PYTHON_CLONE_AST_STRING_TYPES,
    number_kinds: PYTHON_CLONE_AST_NUMBER_TYPES,
    boolean_kinds: &["true", "false"],
    boolean_values: &["True", "False"],
    null_kinds: &[],
    null_values: &[],
    comment_kinds: &["comment"],
    ignored_ast_kinds: &[],
};

/// Parse and prepare one Python clone candidate, stopping before AST-label work
/// when the normalized token threshold cannot be met.
pub fn prepare_python_clone(
    source: &str,
    min_normalized_tokens: usize,
) -> Option<PythonClonePreparation> {
    let Some(tree) = parse_clone_tree(source) else {
        return (min_normalized_tokens == 0).then(|| PythonClonePreparation {
            normalized_tokens: Vec::new(),
            ast_signature: String::new(),
        });
    };
    let normalized_tokens = normalized_clone_tokens_from_root(
        tree.root_node(),
        source,
        PYTHON_CLONE_NORMALIZATION_RULES,
    );
    if normalized_tokens.len() < min_normalized_tokens {
        return None;
    }

    Some(PythonClonePreparation {
        normalized_tokens,
        ast_signature: clone_ast_signature_from_root(
            tree.root_node(),
            source,
            PYTHON_CLONE_NORMALIZATION_RULES,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#3539: clone preparation changed output or parsed each candidate more than once")]
    fn combined_preparation_matches_the_existing_outputs_with_one_parse() {
        let sources = [
            r#"
def compare(left, right):
    # Keep comments in the AST signature, but not the token stream.
    message = f"same: {left}"
    ratio = 1.5 + 0x2A
    return left == right and True
"#,
            "def broken(:\n    return False + 1\n",
        ];

        for source in sources {
            let tree = parse_python_tree(source).unwrap();
            if source.contains("broken") {
                assert!(tree.root_node().has_error());
            }
            let mut expected_tokens = Vec::new();
            brokk_bifrost_core::test_support::walk_tree_preorder_reference(
                tree.root_node(),
                |node| {
                    if node.named_child_count() == 0 {
                        let token = normalize_python_clone_leaf_token(
                            node,
                            source,
                            PYTHON_CLONE_NORMALIZATION_RULES,
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
                    expected_labels.push(normalize_python_clone_ast_label(
                        node,
                        source,
                        PYTHON_CLONE_NORMALIZATION_RULES,
                    ));
                },
            );

            reset_python_clone_parse_count_for_test();
            let preparation = prepare_python_clone(source, 0).unwrap();

            assert_eq!(preparation.normalized_tokens, expected_tokens);
            assert_eq!(preparation.ast_signature, expected_labels.join("|"));
            assert_eq!(python_clone_parse_count_for_test(), 1);
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
                        .normalized_tokens
                        .iter()
                        .all(|token| token != "T:comment")
                );
                assert!(
                    preparation
                        .ast_signature
                        .split('|')
                        .any(|label| label == "N:comment")
                );
            }
        }
    }

    #[test]
    #[hardwon("#3539: rejected clone candidates repeated source parsing")]
    fn rejected_candidate_still_uses_one_parse() {
        let token_count = prepare_python_clone("value = 1", 0)
            .unwrap()
            .normalized_tokens
            .len();
        reset_python_clone_parse_count_for_test();

        assert!(prepare_python_clone("value = 1", token_count).is_some());
        assert_eq!(python_clone_parse_count_for_test(), 1);
        reset_python_clone_parse_count_for_test();

        assert!(prepare_python_clone("value = 1", token_count + 1).is_none());
        assert_eq!(python_clone_parse_count_for_test(), 1);
    }

    #[test]
    #[hardwon("#3539: clone preparation recursively overflowed on deeply nested syntax")]
    fn deeply_nested_source_is_walked_without_recursion() {
        let depth = 2_000;
        let source = format!("value = {}0{}\n", "(".repeat(depth), ")".repeat(depth));

        let preparation = prepare_python_clone(&source, 0).unwrap();
        brokk_bifrost_core::test_support::assert_deep_clone_preparation(
            &preparation.normalized_tokens,
            &preparation.ast_signature,
            depth,
        );
    }
}
