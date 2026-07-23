use super::syntax::{
    body_contains_free_this, callable_child_belongs_to_procedure, class_definition_expressions,
};
use super::*;

#[test]
fn free_this_scan_honors_cancellation() {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .expect("TypeScript grammar must load");
    let tree = parser
        .parse(
            "function value() { const first = 1; const second = 2; return this; }",
            None,
        )
        .expect("TypeScript source must parse");
    let mut body = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
        tree.root_node(),
        true,
        |node| {
            if node.kind() == "statement_block" {
                body = Some(node);
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        },
    );

    let cancellation = CancellationToken::cancel_after_checks_for_test(2);
    assert_eq!(
        body_contains_free_this(body.expect("function body"), &cancellation),
        Err(LoweringCancelled)
    );
}

#[test]
fn class_definition_expression_collection_honors_cancellation() {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .expect("TypeScript grammar must load");
    let tree = parser
        .parse(
            r#"
                class Nested extends base() {
                    [first()] = value();
                    [second()]() {}
                }
            "#,
            None,
        )
        .expect("TypeScript source must parse");
    let mut class = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
        tree.root_node(),
        true,
        |node| {
            if node.kind() == "class_declaration" {
                class = Some(node);
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        },
    );

    let cancellation = CancellationToken::cancel_after_checks_for_test(2);
    assert_eq!(
        class_definition_expressions(class.expect("class declaration"), &cancellation),
        Err(LoweringCancelled)
    );
}

#[test]
fn class_definition_collection_excludes_erased_typescript_members() {
    let source = r#"
        abstract class Nested implements Marker {
            declare [declaredKey]: string;
            abstract [abstractKey]: string;
            @decorate
            [runtimeField] = value;
            [runtimeMethod]() {}
            [overload](value: string): void;
            [overload](value: unknown) {}
        }
    "#;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .expect("TypeScript grammar must load");
    let tree = parser
        .parse(source, None)
        .expect("TypeScript source must parse");
    let mut class = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
        tree.root_node(),
        true,
        |node| {
            if node.kind() == "abstract_class_declaration" {
                class = Some(node);
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        },
    );

    let evaluation = class_definition_expressions(
        class.expect("abstract class declaration"),
        &CancellationToken::default(),
    )
    .expect("class definition collection must succeed");
    let expressions = evaluation
        .expressions
        .iter()
        .map(|node| &source[node.byte_range()])
        .collect::<Vec<_>>();

    assert!(evaluation.has_decorators);
    assert_eq!(
        expressions,
        vec!["[runtimeField]", "[runtimeMethod]", "[overload]",]
    );
}

#[test]
fn method_decorators_stay_in_the_class_definition_context() {
    let source = r#"
        class Nested {
            @decorate(() => this)
            method() {}
        }
    "#;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("JavaScript grammar must load");
    let tree = parser
        .parse(source, None)
        .expect("JavaScript source must parse");
    let mut method = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
        tree.root_node(),
        true,
        |node| {
            if node.kind() == "method_definition" {
                method = Some(node);
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        },
    );
    let method = method.expect("method definition");
    let decorator = method
        .child_by_field_name("decorator")
        .expect("method decorator");

    assert!(!callable_child_belongs_to_procedure(method, decorator));
}
