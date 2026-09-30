//! Token and AST-label normalization for Java structural-clone candidates.
//!
//! `CloneCandidateData` and `compact_clone_excerpt` are analysis-owned and the
//! declaration source comes from the analyzer, so `analyzer/java/clones.rs`
//! keeps the entry point; everything that knows Java is here. Same split as
//! [`brokk_bifrost_cpp::clones`].

use crate::java::declarations::parse_tree;
use brokk_bifrost_core::analyzer::source_content::SourceContent;
use brokk_bifrost_core::hash::HashSet;
#[cfg(any(test, feature = "test-support"))]
use std::cell::Cell;
use std::sync::LazyLock;
use tree_sitter::Node;

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

static CLONE_AST_IDENTIFIER_TYPES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from_iter([
        "identifier",
        "type_identifier",
        "scoped_identifier",
        "scoped_type_identifier",
    ])
});
static CLONE_AST_STRING_TYPES: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| HashSet::from_iter(["string_literal", "character_literal"]));
static CLONE_AST_NUMBER_TYPES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from_iter([
        "decimal_integer_literal",
        "hex_integer_literal",
        "octal_integer_literal",
        "binary_integer_literal",
        "decimal_floating_point_literal",
        "hex_floating_point_literal",
    ])
});
static CLONE_AST_IGNORED_TYPES: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| HashSet::from_iter(["modifiers", "type_parameters"]));

/// The normalized leaf-token stream for `source`.
pub fn normalized_clone_tokens_java(source: &str) -> Vec<String> {
    let Some(tree) = parse_clone_tree(source) else {
        return Vec::new();
    };
    let content = SourceContent::new(source);
    let mut out = Vec::new();
    collect_normalized_leaf_tokens_java(tree.root_node(), &content, &mut out);
    out
}

fn collect_normalized_leaf_tokens_java(
    node: Node<'_>,
    source_content: &SourceContent,
    out: &mut Vec<String>,
) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.named_child_count() == 0 {
            let token = normalize_java_clone_leaf_token(node, source_content);
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

fn normalize_java_clone_leaf_token(node: Node<'_>, source_content: &SourceContent) -> String {
    let kind = node.kind();
    let token = source_content
        .as_str()
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if token.is_empty() {
        return String::new();
    }
    if CLONE_AST_IDENTIFIER_TYPES.contains(kind) {
        return "ID".to_string();
    }
    if CLONE_AST_STRING_TYPES.contains(kind) {
        return "STR".to_string();
    }
    if CLONE_AST_NUMBER_TYPES.contains(kind) {
        return "NUM".to_string();
    }
    if token == "true" || token == "false" {
        return "BOOL".to_string();
    }
    if token.chars().count() == 1 && token.chars().all(|ch| !ch.is_alphanumeric()) {
        return format!("OP:{token}");
    }
    format!("T:{kind}")
}

/// The `|`-joined AST-label signature for `source`.
pub fn build_java_clone_ast_signature(source: &str) -> String {
    let Some(tree) = parse_clone_tree(source) else {
        return String::new();
    };
    let content = SourceContent::new(source);
    let mut labels = Vec::new();
    collect_java_clone_ast_labels(tree.root_node(), &content, &mut labels);
    labels.join("|")
}

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
    let mut normalized_tokens = Vec::new();
    collect_normalized_leaf_tokens_java(tree.root_node(), &content, &mut normalized_tokens);
    if normalized_tokens.len() < min_normalized_tokens {
        return None;
    }

    let mut labels = Vec::new();
    collect_java_clone_ast_labels(tree.root_node(), &content, &mut labels);
    Some(JavaClonePreparation {
        normalized_tokens,
        ast_signature: labels.join("|"),
    })
}

fn collect_java_clone_ast_labels(
    node: Node<'_>,
    source_content: &SourceContent,
    out: &mut Vec<String>,
) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        out.push(normalize_java_clone_ast_label(node, source_content));
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                stack.push(child);
            }
        }
    }
}

fn normalize_java_clone_ast_label(node: Node<'_>, source_content: &SourceContent) -> String {
    let kind = node.kind();
    let text = source_content
        .as_str()
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if CLONE_AST_IDENTIFIER_TYPES.contains(kind) {
        return "ID".to_string();
    }
    if CLONE_AST_STRING_TYPES.contains(kind) {
        return "STR".to_string();
    }
    if CLONE_AST_NUMBER_TYPES.contains(kind) {
        return "NUM".to_string();
    }
    if kind == "boolean_literal" || text == "true" || text == "false" {
        return "BOOL".to_string();
    }
    if CLONE_AST_IGNORED_TYPES.contains(kind) {
        return "IGN".to_string();
    }
    format!("N:{kind}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_tokens(node: Node<'_>, content: &SourceContent, out: &mut Vec<String>) {
        if node.named_child_count() == 0 {
            let token = normalize_java_clone_leaf_token(node, content);
            if !token.is_empty() {
                out.push(token);
            }
        }
        for index in 0..node.child_count() {
            if let Some(child) = node.child(index) {
                legacy_tokens(child, content, out);
            }
        }
    }

    fn legacy_labels(node: Node<'_>, content: &SourceContent, out: &mut Vec<String>) {
        out.push(normalize_java_clone_ast_label(node, content));
        for index in 0..node.child_count() {
            if let Some(child) = node.child(index) {
                legacy_labels(child, content, out);
            }
        }
    }

    #[test]
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
            legacy_tokens(tree.root_node(), &content, &mut expected_tokens);
            let mut expected_labels = Vec::new();
            legacy_labels(tree.root_node(), &content, &mut expected_labels);

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
    fn deeply_nested_source_is_walked_without_recursion() {
        let depth = 2_000;
        let source = format!(
            "class Deep {{ Object value = {}0{}; }}",
            "(".repeat(depth),
            ")".repeat(depth)
        );

        let preparation = prepare_java_clone(&source, 0).unwrap();

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
