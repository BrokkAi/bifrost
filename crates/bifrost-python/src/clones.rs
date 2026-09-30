//! Python's clone-detection token and AST-signature normalization.
//!
//! `analyzer/python/clones.rs` in `brokk-bifrost-analysis` keeps the entry
//! point: it reads the declaration's source through the analyzer and assembles
//! the analysis-owned `CloneCandidateData`. Everything that knows what a Python
//! token *is* lives here.

use crate::declarations::parse_python_tree;
#[cfg(any(test, feature = "test-support"))]
use std::cell::Cell;
use tree_sitter::Node;

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

pub fn normalized_clone_tokens_python(source: &str) -> Vec<String> {
    let Some(tree) = parse_clone_tree(source) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_normalized_leaf_tokens_python(tree.root_node(), source, &mut out);
    out
}

fn collect_normalized_leaf_tokens_python(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.named_child_count() == 0 {
            let token = normalize_python_clone_leaf_token(node, source);
            if !token.is_empty() {
                out.push(token);
            }
        }
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                stack.push(child);
            }
        }
    }
}

fn normalize_python_clone_leaf_token(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let token = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if token.is_empty() || kind == "comment" {
        return String::new();
    }
    if PYTHON_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if PYTHON_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if PYTHON_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if kind == "true" || kind == "false" || token == "True" || token == "False" {
        return "BOOL".to_string();
    }
    if token.chars().count() == 1 && token.chars().all(|ch| !ch.is_alphanumeric()) {
        return format!("OP:{token}");
    }
    format!("T:{kind}")
}

pub fn build_python_clone_ast_signature(source: &str) -> String {
    let Some(tree) = parse_clone_tree(source) else {
        return String::new();
    };
    let mut labels = Vec::new();
    collect_python_clone_ast_labels(tree.root_node(), source, &mut labels);
    labels.join("|")
}

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
    let mut normalized_tokens = Vec::new();
    collect_normalized_leaf_tokens_python(tree.root_node(), source, &mut normalized_tokens);
    if normalized_tokens.len() < min_normalized_tokens {
        return None;
    }

    let mut labels = Vec::new();
    collect_python_clone_ast_labels(tree.root_node(), source, &mut labels);
    Some(PythonClonePreparation {
        normalized_tokens,
        ast_signature: labels.join("|"),
    })
}

fn collect_python_clone_ast_labels(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        out.push(normalize_python_clone_ast_label(node, source));
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                stack.push(child);
            }
        }
    }
}

fn normalize_python_clone_ast_label(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let text = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if PYTHON_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if PYTHON_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if PYTHON_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if kind == "true" || kind == "false" || text == "True" || text == "False" {
        return "BOOL".to_string();
    }
    format!("N:{kind}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_tokens(node: Node<'_>, source: &str, out: &mut Vec<String>) {
        if node.named_child_count() == 0 {
            let token = normalize_python_clone_leaf_token(node, source);
            if !token.is_empty() {
                out.push(token);
            }
        }
        for index in 0..node.child_count() {
            if let Some(child) = node.child(index) {
                legacy_tokens(child, source, out);
            }
        }
    }

    fn legacy_labels(node: Node<'_>, source: &str, out: &mut Vec<String>) {
        out.push(normalize_python_clone_ast_label(node, source));
        for index in 0..node.child_count() {
            if let Some(child) = node.child(index) {
                legacy_labels(child, source, out);
            }
        }
    }

    #[test]
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
            legacy_tokens(tree.root_node(), source, &mut expected_tokens);
            let mut expected_labels = Vec::new();
            legacy_labels(tree.root_node(), source, &mut expected_labels);

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
    fn deeply_nested_source_is_walked_without_recursion() {
        let depth = 2_000;
        let source = format!("value = {}0{}\n", "(".repeat(depth), ")".repeat(depth));

        let preparation = prepare_python_clone(&source, 0).unwrap();

        assert_eq!(
            preparation
                .normalized_tokens
                .iter()
                .filter(|token| token.as_str() == "OP:(")
                .count(),
            depth
        );
        assert_eq!(
            preparation
                .normalized_tokens
                .iter()
                .filter(|token| token.as_str() == "OP:)")
                .count(),
            depth
        );
        assert_eq!(preparation.ast_signature.matches("N:(").count(), depth);
        assert_eq!(preparation.ast_signature.matches("N:)").count(), depth);
    }
}
