use super::syntax::{
    body_contains_free_this, java_field_access_is_type_qualifier, java_field_access_segments,
    java_type_name_prefix_len,
};
use super::*;

#[test]
fn free_this_scan_honors_cancellation() {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .expect("Java grammar must load");
    let tree = parser
        .parse(
            "class Example { Object value() { int first = 1; int second = 2; return this; } }",
            None,
        )
        .expect("Java source must parse");
    let mut body = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
        tree.root_node(),
        true,
        |node| {
            if node.kind() == "block" {
                body = Some(node);
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        },
    );

    let cancellation = CancellationToken::cancel_after_checks_for_test(2);
    assert_eq!(
        body_contains_free_this(body.expect("method body"), &cancellation),
        Err(LoweringCancelled)
    );
}

fn parse_java(source: &str) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .expect("Java grammar must load");
    parser.parse(source, None).expect("Java source must parse")
}

fn first_kind<'a>(root: tree_sitter::Node<'a>, kind: &str) -> tree_sitter::Node<'a> {
    let mut found = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(root, true, |node| {
        if node.kind() == kind && found.is_none() {
            found = Some(node);
            WalkControl::Break
        } else {
            WalkControl::Continue
        }
    });
    found.unwrap_or_else(|| panic!("missing {kind}"))
}

#[test]
fn type_name_prefix_recognizes_qualified_stdlib_types() {
    assert_eq!(java_type_name_prefix_len(&["java", "net", "URLDecoder"]), 3);
    assert_eq!(
        java_type_name_prefix_len(&["java", "net", "URLDecoder", "SOME_CONST"]),
        3
    );
    assert_eq!(java_type_name_prefix_len(&["inheritedField", "nested"]), 0);
    assert_eq!(java_type_name_prefix_len(&["Outer", "Inner"]), 2);
}

#[test]
fn qualified_stdlib_method_object_is_a_type_qualifier() {
    let source = r#"class App {
  void run(String value) {
    java.net.URLDecoder.decode(value, "UTF-8");
  }
}
"#;
    let tree = parse_java(source);
    let invocation = first_kind(tree.root_node(), "method_invocation");
    let access = invocation
        .child_by_field_name("object")
        .expect("qualified call object");
    let segments = java_field_access_segments(access, source);
    assert_eq!(segments, ["java", "net", "URLDecoder"]);
    assert!(java_field_access_is_type_qualifier(access, source, |_| {
        false
    }));
}

/// The accepted residual of the spelling-based JLS 6.5 reclassification
/// (#2363, recorded on #2452): a PascalCase field inherited from another file
/// is invisible to the intrafile `root_is_value` check, so a chain of
/// type-spelled segments through it reads as a type qualifier and its heap
/// identity is dropped. A scope that CAN name the root as a value keeps the
/// Field lowering. If the first assertion ever starts failing, the residual
/// has been fixed; retire the issue rather than this pin.
#[test]
fn pascal_case_cross_file_inherited_field_is_the_accepted_qualifier_residual() {
    let source = r#"class App {
  void run() {
    CONFIG.DEFAULTS.value();
  }
}
"#;
    let tree = parse_java(source);
    let invocation = first_kind(tree.root_node(), "method_invocation");
    let access = invocation
        .child_by_field_name("object")
        .expect("selector object");
    assert!(
        java_field_access_is_type_qualifier(access, source, |_| false),
        "a cross-file inherited PascalCase chain currently reads as a type qualifier"
    );
    assert!(
        !java_field_access_is_type_qualifier(access, source, |root| root == "CONFIG"),
        "a root the scope knows as a value must keep its Field lowering"
    );
}

#[test]
fn inherited_field_chain_is_not_a_type_qualifier() {
    let source = r#"class App {
  void run() {
    inheritedField.nested.method();
  }
}
"#;
    let tree = parse_java(source);
    let access = first_kind(tree.root_node(), "field_access");
    assert!(
        !java_field_access_is_type_qualifier(access, source, |_| false),
        "an inherited field chain must keep Field lowering"
    );
}
