use super::syntax::{
    body_contains_free_this, is_sole_initializer_fragment, java_field_access_is_type_qualifier,
    java_field_access_segments, java_type_name_prefix_len,
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
    assert!(java_field_access_is_type_qualifier(
        access,
        source,
        |_| false,
        |_| false,
    ));
}

/// #2452: an uppercase field inherited from another file is invisible to the
/// intrafile value inventory. Unknown roots must retain heap identity; positive
/// type evidence may still classify the same spelling as a qualifier.
#[test]
fn uppercase_cross_file_inherited_field_requires_positive_type_evidence() {
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
        !java_field_access_is_type_qualifier(access, source, |_| false, |_| false),
        "an unknown uppercase root must keep its Field lowering"
    );
    assert!(
        !java_field_access_is_type_qualifier(access, source, |root| root == "CONFIG", |_| false,),
        "a root the scope knows as a value must keep its Field lowering"
    );
    assert!(
        java_field_access_is_type_qualifier(access, source, |_| false, |root| root == "CONFIG",),
        "a root proven to be a type may omit qualifier-only Field lowering"
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
        !java_field_access_is_type_qualifier(access, source, |_| false, |_| false),
        "an inherited field chain must keep Field lowering"
    );
}

/// The `variable_declarator` node that declares `name`, found anywhere in
/// the tree. Distinguishes sibling field declarations by their declared
/// name, since `first_kind` alone cannot pick a specific one among several.
fn declarator_named<'a>(
    root: tree_sitter::Node<'a>,
    source: &str,
    name: &str,
) -> tree_sitter::Node<'a> {
    let mut found = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(root, true, |node| {
        if node.kind() == "variable_declarator"
            && node
                .child_by_field_name("name")
                .is_some_and(|id| &source[id.byte_range()] == name)
        {
            found = Some(node);
            WalkControl::Break
        } else {
            WalkControl::Continue
        }
    });
    found.unwrap_or_else(|| panic!("missing variable_declarator named {name}"))
}

// #2553: `is_sole_initializer_fragment` is the structural predicate that
// decides whether the whole-procedure `DeferredExecution` gap still applies
// to one initializer fragment. These cases pin its documented contract
// directly, independent of the gap-emission wiring in `control.rs`.

#[test]
fn a_lone_static_field_initializer_is_the_sole_fragment_in_its_group() {
    // The corpus's own dominant shape (#2545's census): boilerplate
    // `serialVersionUID`, nothing else in the static group.
    let source = "class App {\n  private static final long serialVersionUID = 1L;\n}\n";
    let tree = parse_java(source);
    let declarator = declarator_named(tree.root_node(), source, "serialVersionUID");
    assert!(is_sole_initializer_fragment(declarator, true));
}

#[test]
fn two_static_field_initializers_are_not_sole_in_their_shared_group() {
    // A genuine source-order-composition case: `b`'s value can depend on
    // `a` having already run. Both fragments must keep the gap.
    let source = "class App {\n  private static int a = 1;\n  private static int b = a + 1;\n}\n";
    let tree = parse_java(source);
    let a = declarator_named(tree.root_node(), source, "a");
    let b = declarator_named(tree.root_node(), source, "b");
    assert!(!is_sole_initializer_fragment(a, true));
    assert!(!is_sole_initializer_fragment(b, true));
}

#[test]
fn a_static_field_and_a_static_initializer_block_share_one_group() {
    let source = "class App {\n  private static int a = 1;\n  static { a = a + 1; }\n}\n";
    let tree = parse_java(source);
    let a = declarator_named(tree.root_node(), source, "a");
    let block = first_kind(tree.root_node(), "static_initializer");
    assert!(!is_sole_initializer_fragment(a, true));
    assert!(!is_sole_initializer_fragment(block, true));
}

#[test]
fn static_and_instance_groups_are_independent() {
    // One member in each group: neither fragment has a sibling to compose
    // with, even though the class has two initializer fragments overall.
    let source = "class App {\n  private static final long serialVersionUID = 1L;\n  private int count = 0;\n}\n";
    let tree = parse_java(source);
    let statik = declarator_named(tree.root_node(), source, "serialVersionUID");
    let instance = declarator_named(tree.root_node(), source, "count");
    assert!(is_sole_initializer_fragment(statik, true));
    assert!(is_sole_initializer_fragment(instance, false));
}

#[test]
fn two_instance_field_initializers_are_not_sole_in_their_shared_group() {
    let source = "class App {\n  private int a = 1;\n  private int b = a + 1;\n}\n";
    let tree = parse_java(source);
    let a = declarator_named(tree.root_node(), source, "a");
    let b = declarator_named(tree.root_node(), source, "b");
    assert!(!is_sole_initializer_fragment(a, false));
    assert!(!is_sole_initializer_fragment(b, false));
}

#[test]
fn an_uninitialized_sibling_field_does_not_count_as_a_fragment() {
    // `plain` has no `value`, so `callable_shape` never lowers it as an
    // Initializer procedure at all; it must not inflate the group count
    // either.
    let source = "class App {\n  private static final long serialVersionUID = 1L;\n  private static String plain;\n}\n";
    let tree = parse_java(source);
    let declarator = declarator_named(tree.root_node(), source, "serialVersionUID");
    assert!(is_sole_initializer_fragment(declarator, true));
}

#[test]
fn multiple_declarators_in_one_field_declaration_each_count() {
    // `private static int a = 1, b = 2;` is two composed fragments in JLS
    // source order, even though they share one `field_declaration`.
    let source = "class App {\n  private static int a = 1, b = 2;\n}\n";
    let tree = parse_java(source);
    let a = declarator_named(tree.root_node(), source, "a");
    let b = declarator_named(tree.root_node(), source, "b");
    assert!(!is_sole_initializer_fragment(a, true));
    assert!(!is_sole_initializer_fragment(b, true));
}
