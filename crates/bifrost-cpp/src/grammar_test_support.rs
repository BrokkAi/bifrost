//! Shared fixture and AST assertions for the pinned C++ grammar boundary tests.
use tree_sitter::{Node, Tree};

pub(crate) const SOURCE: &str = concat!(
    "// \u{3bb}: UTF-8 before every recovery span\n",
    "void fragment() { Widget(value); }\n",
    "struct Widget {\n",
    " CPPCHECKLIB static std::string toString(Yield yield);\n",
    " API ns::Widget(Value value) : item(value) {}\n",
    " MSC_WARNING(suppress : 26495) CONSTEXPR Widget(grow_fun grow) noexcept : size_(size), grow_(grow) {}\n",
    "};\n",
    "void ranges() {\n",
    " for (auto [key, value] : pairs) {}\n",
    " for (auto &same : same) {}\n",
    " for (auto *ptr : pointers) {}\n",
    " for (auto item [[maybe_unused]] : items) {}\n",
    " for (auto &\u{3bb} : values) {}\n",
    "}\n",
    "int numeric[] = {{1, -2}, {+3, 4}};\n",
    "int comment[] = {1, /* data */ 2};\n",
    "int names[] = {value};\n",
    "int calls[] = {make()};\n",
    "int broken[] = {1, @};\n",
    "int missing[] = {1 2};\n",
    "int spaced[] = {- 2, + 3};\n",
    "int missing_token[] = {call(1};\n",
);

pub(crate) fn tree(source: &str) -> Tree {
    crate::clones::cpp_clone_parser()
        .parse(source, None)
        .unwrap()
}

pub(crate) fn nodes(root: Node<'_>) -> Vec<Node<'_>> {
    let mut result = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        result.push(node);
        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    result
}

pub(crate) fn at<'tree>(
    root: Node<'tree>,
    kind: &str,
    span: std::ops::Range<usize>,
) -> Node<'tree> {
    let found: Vec<_> = nodes(root)
        .into_iter()
        .filter(|node| node.kind() == kind && node.byte_range() == span)
        .collect();
    assert_eq!(found.len(), 1, "{kind} at {span:?}: {found:?}");
    found[0]
}

pub(crate) fn field(node: Node<'_>, name: &str, kind: &str, span: std::ops::Range<usize>) {
    let child = node.child_by_field_name(name).expect(name);
    assert_eq!((child.kind(), child.byte_range()), (kind, span));
}

/// Assert the pinned grammar's reading of a class head decorated by a
/// function-like export macro, `class API(2, 0) Name ...`: a clean tree with a
/// `class_specifier` named `name` whose first decoration is a `macro_modifier`
/// carrying the invocation's `argument_list` (brokk-tree-sitter-cpp 0.24.7,
/// #6902). Fixtures written for the error geometry of older
/// grammars use this to state that the head no longer needs recovery.
pub(crate) fn assert_function_like_export_class_head(tree: &Tree, source: &str, name: &str) {
    let root = tree.root_node();
    assert!(!root.has_error(), "{name}: {}", root.to_sexp());
    assert!(
        nodes(root).into_iter().any(|node| {
            node.kind() == "class_specifier"
                && node
                    .child_by_field_name("name")
                    .and_then(|class_name| class_name.utf8_text(source.as_bytes()).ok())
                    == Some(name)
                && node.named_child(0).is_some_and(|decoration| {
                    decoration.kind() == "macro_modifier"
                        && decoration
                            .named_child(1)
                            .is_some_and(|arguments| arguments.kind() == "argument_list")
                })
        }),
        "{name}: {}",
        root.to_sexp()
    );
}
