use tree_sitter::{Node, TreeCursor};

/// Direct tuple-field types and their optional preceding visibility modifiers.
/// Other named children, including grouped attributes, are not fields.
pub(crate) struct RustPositionalFields<'tree> {
    cursor: TreeCursor<'tree>,
    pending_visibility: Option<Node<'tree>>,
    finished: bool,
}

/// Iterate only AST `type` fields in an ordered positional field list.
pub(crate) fn rust_positional_fields(body: Node<'_>) -> RustPositionalFields<'_> {
    assert_eq!(body.kind(), "ordered_field_declaration_list");
    let mut cursor = body.walk();
    let finished = !cursor.goto_first_child();
    RustPositionalFields {
        cursor,
        pending_visibility: None,
        finished,
    }
}

impl<'tree> Iterator for RustPositionalFields<'tree> {
    type Item = (Node<'tree>, Option<Node<'tree>>);

    fn next(&mut self) -> Option<Self::Item> {
        while !self.finished {
            let child = self.cursor.node();
            let field_name = self.cursor.field_name();
            if child.kind() == "visibility_modifier" {
                self.pending_visibility = Some(child);
            } else if field_name == Some("type") {
                assert!(child.is_named());
                let visibility = self.pending_visibility.take();
                if !self.cursor.goto_next_sibling() {
                    self.finished = true;
                }
                return Some((child, visibility));
            }
            if !self.cursor.goto_next_sibling() {
                self.finished = true;
            }
        }
        None
    }
}

/// Node kinds the grammar uses to attach outer attributes to an item or
/// expression. The payload is under a field, while the attributes themselves
/// are grouped under the `attributes` field.
const ATTRIBUTE_WRAPPER_KINDS: [&str; 3] = [
    "declaration_with_attribute",
    "expression_with_attribute",
    "block_expression_with_attribute",
];

/// Follow attribute wrappers to the declaration or expression they carry.
///
/// For any other node, this returns the node unchanged.
pub fn unwrap_attributes(mut node: Node<'_>) -> Node<'_> {
    while let Some(child) = attribute_payload(node) {
        node = child;
    }
    node
}

/// The direct declaration or expression carried by one attribute wrapper.
pub(crate) fn attribute_payload(node: Node<'_>) -> Option<Node<'_>> {
    if !ATTRIBUTE_WRAPPER_KINDS.contains(&node.kind()) {
        return None;
    }
    node.child_by_field_name("declaration")
        .or_else(|| node.child_by_field_name("expression"))
}

/// The containing syntax node outside an attribute wrapper owned by `node`.
/// Payload and wrapper expose the same attributes, so ancestry consumers must
/// cross that boundary once rather than applying its predicates twice.
pub fn parent_outside_attributes(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if ATTRIBUTE_WRAPPER_KINDS.contains(&parent.kind())
            && unwrap_attributes(parent) == unwrap_attributes(node)
        {
            node = parent;
        } else {
            return Some(parent);
        }
    }
    None
}

/// Return the outer `attribute_item`s attached to `node`.
///
/// `node` may be either the wrapper written by the grammar or the item returned
/// by [`unwrap_attributes`]. The grouped `attributes` field is read directly; no
/// ungrouped sibling scan or pre-0.24 fallback is involved. Inline member and
/// parameter groups follow the exact owning list production.
pub fn outer_attributes<'tree>(node: Node<'tree>) -> impl Iterator<Item = Node<'tree>> {
    let parent = (!ATTRIBUTE_WRAPPER_KINDS.contains(&node.kind()))
        .then(|| node.parent())
        .flatten();
    outer_attributes_with_parent(node, parent)
}

pub(crate) fn outer_attributes_with_parent<'tree>(
    node: Node<'tree>,
    parent: Option<Node<'tree>>,
) -> impl Iterator<Item = Node<'tree>> {
    let attributes = attached_attributes(node, parent);
    RustOuterAttributes {
        attributes,
        index: 0,
    }
}

pub(crate) fn rust_path_root(mut node: Node<'_>) -> Node<'_> {
    while matches!(node.kind(), "scoped_identifier" | "scoped_type_identifier") {
        let Some(path) = node.child_by_field_name("path") else {
            break;
        };
        node = path;
    }
    node
}

/// Indexed view over an associated `attributes` group, avoiding allocation in
/// this declaration-walk hot path.
struct RustOuterAttributes<'tree> {
    attributes: Option<Node<'tree>>,
    index: usize,
}

impl<'tree> Iterator for RustOuterAttributes<'tree> {
    type Item = Node<'tree>;

    fn next(&mut self) -> Option<Self::Item> {
        let attributes = self.attributes?;
        while self.index < attributes.child_count() {
            let attribute_item = attributes.child(self.index)?;
            self.index += 1;
            if attribute_item.kind() == "attribute_item" {
                return Some(attribute_item);
            }
        }
        None
    }
}

fn attached_attributes<'tree>(
    node: Node<'tree>,
    parent: Option<Node<'tree>>,
) -> Option<Node<'tree>> {
    // A wrapper owns its group. Payload nodes inherit only from the wrapper
    // that names them as its declaration/expression field.
    if ATTRIBUTE_WRAPPER_KINDS.contains(&node.kind()) {
        return node.child_by_field_name("attributes");
    }
    if let Some(parent) = parent
        && ATTRIBUTE_WRAPPER_KINDS.contains(&parent.kind())
        && (parent.child_by_field_name("declaration") == Some(node)
            || parent.child_by_field_name("expression") == Some(node))
    {
        return parent.child_by_field_name("attributes");
    }
    // These productions carry an unnamed attributes child on the owner.
    if matches!(
        node.kind(),
        "enum_variant"
            | "match_arm"
            | "field_initializer"
            | "shorthand_field_initializer"
            | "field_pattern"
    ) {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "attributes");
    }
    // Delimited lists put one grouped attribute node before its owned entry.
    // Require the exact list production, and never cross a comma or item.
    let parent = parent?;
    if !matches!(
        parent.kind(),
        "field_declaration_list"
            | "ordered_field_declaration_list"
            | "parameters"
            | "type_parameters"
            | "array_expression"
            | "tuple_expression"
    ) {
        return None;
    }
    let mut previous = node.prev_sibling();
    while let Some(sibling) = previous {
        match sibling.kind() {
            "attributes" => return Some(sibling),
            "line_comment" | "block_comment" => previous = sibling.prev_sibling(),
            _ => return None,
        }
    }
    None
}

/// Whether an `attribute_item`'s path is exactly `expected`.
pub fn attribute_item_has_path(attribute_item: Node<'_>, source: &str, expected: &str) -> bool {
    let Some(attribute) = attribute_item
        .named_child(0)
        .filter(|child| child.kind() == "attribute")
    else {
        return false;
    };
    let Some(path) = attribute.named_child(0) else {
        return false;
    };
    rust_attribute_path_is(path, source, expected)
}

pub(crate) fn rust_attribute_path_is(path: Node<'_>, source: &str, expected: &str) -> bool {
    source.get(path.start_byte()..path.end_byte()) == Some(expected)
}

pub(crate) fn rust_identifier_kind_like(kind: &str) -> bool {
    matches!(
        kind,
        "identifier" | "reserved_identifier" | "_reserved_identifier"
    )
}

/// Whether `node` has an attached attribute whose path is exactly `expected`.
pub fn item_has_path_attribute(node: Node<'_>, source: &str, expected: &str) -> bool {
    outer_attributes(node)
        .any(|attribute_item| attribute_item_has_path(attribute_item, source, expected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;
    use tree_sitter::{Parser, Tree};

    fn parse(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        let tree = parser.parse(source, None).expect("parse Rust source");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        tree
    }

    fn named_descendant<'tree>(root: Node<'tree>, kind: &str) -> Node<'tree> {
        brokk_bifrost_core::analyzer::tree_walk::first_named_descendant_of_kind_inclusive(
            root, kind,
        )
        .unwrap_or_else(|| panic!("expected {kind}"))
    }

    fn attribute_paths<'tree>(node: Node<'tree>, source: &str) -> Vec<String> {
        outer_attributes(node)
            .map(|item| {
                let attribute = item.named_child(0).expect("attribute");
                let path = attribute.named_child(0).expect("attribute path");
                source[path.start_byte()..path.end_byte()].to_string()
            })
            .collect()
    }

    #[test]
    fn grammar_positional_attribute_trivia_ownership() {
        let source = "struct Tuple(#[allow(dead_code)] /* attached trivia */ pub Item, Other);";
        let tree = parse(source);
        let fields = named_descendant(tree.root_node(), "ordered_field_declaration_list");
        let entries = rust_positional_fields(fields).collect::<Vec<_>>();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0.kind(), "type_identifier");
        // The visibility token follows the attributes in this production.
        let visibility = entries[0].1.unwrap();
        assert_eq!(attribute_paths(visibility, source), ["allow"]);
        assert!(attribute_paths(entries[1].0, source).is_empty());
        assert_eq!(parent_outside_attributes(entries[0].0), Some(fields));
        assert_eq!(parent_outside_attributes(fields), fields.parent());

        let tree = parse("#[marker] struct Item;");
        let wrapper = tree.root_node().named_child(0).unwrap();
        let attributes = wrapper.child_by_field_name("attributes").unwrap();
        let payload = unwrap_attributes(wrapper);
        // An attribute group is a child of the wrapper but is not its payload.
        assert_eq!(parent_outside_attributes(attributes), Some(wrapper));
        assert_eq!(parent_outside_attributes(payload), Some(tree.root_node()));
    }

    #[test]
    fn unwraps_and_reads_declaration_attributes() {
        let source = "#[first] #[cfg(test)] static ITEM: u8 = 0;";
        let tree = parse(source);
        let wrapped = named_descendant(tree.root_node(), "declaration_with_attribute");
        let item = unwrap_attributes(wrapped);
        assert_eq!(item.kind(), "static_item");
        assert_eq!(attribute_paths(item, source), ["first", "cfg"]);
    }

    #[test]
    fn nested_items_receive_only_their_nearest_wrapper_attributes() {
        let source = "#[outer] mod wrapped { #[inner] fn item() {} }";
        let tree = parse(source);
        let root_item = tree.root_node().named_child(0).expect("root item");
        let module = unwrap_attributes(root_item);
        let body = module.child_by_field_name("body").expect("module body");
        let function = body.named_child(0).expect("function");
        assert_eq!(attribute_paths(function, source), ["inner"]);
    }

    #[test]
    #[hardwon("#5133: grouped tuple-field attributes were counted as phantom native fields")]
    fn positional_fields_select_only_direct_type_fields_after_grouped_attributes() {
        let source = "struct S(#[first] pub u8, #[second] #[third] u16);";
        let tree = parse(source);
        let body = named_descendant(tree.root_node(), "ordered_field_declaration_list");
        let fields = rust_positional_fields(body)
            .enumerate()
            .map(|(ordinal, (ty, visibility))| {
                (ordinal, ty.kind(), visibility.map(|node| node.kind()))
            })
            .collect::<Vec<_>>();

        assert_eq!(
            fields,
            [
                (0, "primitive_type", Some("visibility_modifier")),
                (1, "primitive_type", None),
            ]
        );
    }

    #[test]
    fn reads_inline_grouped_member_and_parameter_attributes() {
        let source = "enum E { #[variant] A, B } struct S { #[field] value: u8, clean: u8 } fn function(#[parameter] value: u8, clean: u8) {}";
        let tree = parse(source);
        let variant = named_descendant(tree.root_node(), "enum_variant");
        let parameter = named_descendant(tree.root_node(), "parameter");
        assert_eq!(attribute_paths(variant, source), ["variant"]);
        assert_eq!(attribute_paths(parameter, source), ["parameter"]);
        let field = named_descendant(tree.root_node(), "field_declaration");
        assert_eq!(attribute_paths(field, source), ["field"]);
        for owner in [variant, parameter, field] {
            let mut next = owner.next_named_sibling();
            while let Some(node) = next {
                assert!(
                    outer_attributes(node).next().is_none(),
                    "attributes leaked to {}",
                    node.to_sexp()
                );
                next = node.next_named_sibling();
            }
        }
    }

    #[test]
    #[hardwon("deb7edda43fc: valid cfg attributes on struct-pattern fields caused parser recovery")]
    fn struct_pattern_fields_own_attributes_and_preserve_binding_fields() {
        let source = r#"fn inspect(value: Pair) {
            let Pair {
                #[cfg(test)] left,
                #[cfg(feature = "probe")] right: renamed,
                plain,
                ..
            } = value;
        }"#;
        let tree = parse(source);
        let pattern = named_descendant(tree.root_node(), "struct_pattern");
        let fields = brokk_bifrost_core::analyzer::tree_walk::named_children_iter(pattern)
            .filter(|node| node.kind() == "field_pattern")
            .collect::<Vec<_>>();
        assert_eq!(fields.len(), 3);
        for (field, expected_name, expected_kind) in [
            (fields[0], "left", "shorthand_field_identifier"),
            (fields[1], "right", "field_identifier"),
            (fields[2], "plain", "shorthand_field_identifier"),
        ] {
            let name = field
                .child_by_field_name("name")
                .expect("pattern field name");
            assert_eq!(name.kind(), expected_kind);
            assert_eq!(name.utf8_text(source.as_bytes()).unwrap(), expected_name);
            assert!(outer_attributes(name).next().is_none());
        }
        assert_eq!(attribute_paths(fields[0], source), ["cfg"]);
        assert_eq!(attribute_paths(fields[1], source), ["cfg"]);
        assert!(outer_attributes(fields[2]).next().is_none());
        let renamed = fields[1]
            .child_by_field_name("pattern")
            .expect("renamed binding");
        assert_eq!(renamed.kind(), "identifier");
        assert_eq!(renamed.utf8_text(source.as_bytes()).unwrap(), "renamed");

        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let malformed = parser
            .parse(
                "fn inspect(value: Pair) { let Pair { #[cfg(test)] left plain } = value; }",
                None,
            )
            .unwrap();
        assert!(malformed.root_node().has_error());
    }

    #[test]
    fn grammar_field_name_layout() {
        use crate::field_roles::{
            RustFieldNameRole, RustStructFieldContainer, classify_rust_field_name,
            rust_is_field_declaration_name,
        };

        let source = "// \u{e9}\nstruct S { r#type: T, caf\u{e9}: U }\nfn f() { S { r#type: value, caf\u{e9} }; let S { r#type: ref mut renamed, ref caf\u{e9} } = value; }\n";
        let tree = parse(source);
        // Original UTF-8 coordinates, independently counted from the fixture.
        // Shorthand initializers have an unnamed first child; the other names
        // are carried by the explicit grammar field listed here.
        for (kind, field, name_kind, span, owner_span, extra_field, extra_span) in [
            (
                "field_declaration",
                Some("name"),
                "field_identifier",
                17..23,
                None,
                Some("type"),
                Some(25..26),
            ),
            (
                "field_declaration",
                Some("name"),
                "field_identifier",
                28..33,
                None,
                Some("type"),
                Some(35..36),
            ),
            (
                "field_initializer",
                Some("field"),
                "field_identifier",
                52..58,
                Some(48..49),
                Some("value"),
                Some(60..65),
            ),
            (
                "shorthand_field_initializer",
                None,
                "identifier",
                67..72,
                Some(48..49),
                None,
                None,
            ),
            (
                "field_pattern",
                Some("name"),
                "field_identifier",
                84..90,
                Some(80..81),
                Some("pattern"),
                Some(92..107),
            ),
            (
                "field_pattern",
                Some("name"),
                "shorthand_field_identifier",
                113..118,
                Some(80..81),
                None,
                None,
            ),
        ] {
            let focused = tree
                .root_node()
                .descendant_for_byte_range(span.start, span.end)
                .unwrap();
            assert_eq!(focused.kind(), name_kind);
            assert_eq!(focused.byte_range(), span);
            let mut node = focused;
            while node.kind() != kind {
                node = node.parent().expect("field owner");
            }
            let name = field
                .map_or_else(
                    || node.named_child(0),
                    |field| node.child_by_field_name(field),
                )
                .unwrap();
            assert_eq!(name, focused);
            if let Some(field) = extra_field {
                assert_eq!(
                    node.child_by_field_name(field).unwrap().byte_range(),
                    extra_span.unwrap()
                );
            }
            for focus in [focused, node] {
                let declared = match classify_rust_field_name(focus) {
                    RustFieldNameRole::Declaration { name } => {
                        assert_eq!(name, focused);
                        assert!(owner_span.is_none());
                        true
                    }
                    RustFieldNameRole::Reference {
                        owner_type,
                        name,
                        container,
                    } => {
                        assert_eq!(name, focused);
                        assert_eq!(owner_type.byte_range(), owner_span.clone().unwrap());
                        assert_eq!(
                            container,
                            if kind == "field_pattern" {
                                RustStructFieldContainer::Pattern
                            } else {
                                RustStructFieldContainer::Literal
                            }
                        );
                        let owner = if kind == "field_pattern" {
                            node.parent().unwrap()
                        } else {
                            node.parent().unwrap().parent().unwrap()
                        };
                        assert_eq!(
                            owner.child_by_field_name(if kind == "field_pattern" {
                                "type"
                            } else {
                                "name"
                            }),
                            Some(owner_type)
                        );
                        if kind != "field_pattern" {
                            assert_eq!(owner.child_by_field_name("body"), node.parent());
                        }
                        false
                    }
                    RustFieldNameRole::Other => panic!("unclassified {kind}"),
                };
                assert_eq!(
                    rust_is_field_declaration_name(focus, span.start, span.end),
                    declared
                );
                assert!(!rust_is_field_declaration_name(
                    focus,
                    span.start,
                    span.end - 1
                ));
            }
        }
    }

    #[test]
    fn grammar_declaration_original_byte_ranges() {
        use crate::graph_support::inspect_rust_named_declaration_node;
        use brokk_bifrost_core::analyzer::model::CodeUnitType;
        use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, Language, ProjectFile, Range};
        use std::collections::BTreeSet;

        // The only index input used by the adapter is a navigation range.
        struct RangeIndex(Range);
        impl CodeUnitIndex for RangeIndex {
            fn project(&self) -> &dyn brokk_bifrost_core::analyzer::project::Project {
                unimplemented!()
            }
            fn languages(&self) -> BTreeSet<Language> {
                unimplemented!()
            }
            fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
                unimplemented!()
            }
            fn search_definitions(&self, _: &str, _: bool) -> BTreeSet<CodeUnit> {
                unimplemented!()
            }
            fn enclosing_code_unit(&self, _: &ProjectFile, _: &Range) -> Option<CodeUnit> {
                unimplemented!()
            }
            fn enclosing_code_unit_for_lines(
                &self,
                _: &ProjectFile,
                _: usize,
                _: usize,
            ) -> Option<CodeUnit> {
                unimplemented!()
            }
            fn get_skeleton(&self, _: &CodeUnit) -> Option<String> {
                unimplemented!()
            }
            fn get_skeleton_header(&self, _: &CodeUnit) -> Option<String> {
                unimplemented!()
            }
            fn get_sources(&self, _: &CodeUnit, _: bool) -> BTreeSet<String> {
                unimplemented!()
            }
            fn ranges(&self, _: &CodeUnit) -> Vec<Range> {
                vec![self.0]
            }
        }

        let source = "// \u{e9}\n#[tag]\nstruct Caf\u{e9} { field: u8 }\nouter! { inner! { #[tag] fn r\u{e9}sum\u{e9}() {} } }\n";
        let tree = parse(source);
        let file = ProjectFile::new(std::env::current_dir().unwrap(), "grammar.rs");
        // name, declaration/name/body/attribute byte spans and grammar kind.
        for (name, kind, declaration, name_span, body, attributes, interiors) in [
            (
                "Caf\u{e9}",
                "struct_item",
                13..39,
                20..25,
                26..39,
                6..12,
                &[][..],
            ),
            (
                "r\u{e9}sum\u{e9}",
                "function_item",
                65..81,
                68..76,
                79..81,
                58..64,
                &[48..84, 57..82][..],
            ),
        ] {
            let mut region_tree = tree.clone();
            for interior in interiors {
                let invocation = named_descendant(region_tree.root_node(), "macro_invocation");
                let arguments =
                    crate::declarations::rust_macro_invocation_arguments(invocation).unwrap();
                assert_eq!(arguments.kind(), "token_tree");
                assert_eq!(arguments.child(0).unwrap().end_byte(), interior.start);
                assert_eq!(
                    arguments
                        .child(arguments.child_count() - 1)
                        .unwrap()
                        .start_byte(),
                    interior.end
                );
                region_tree = crate::lexical_scope::parse_rust_region_tree(
                    source,
                    interior.start,
                    interior.end,
                )
                .unwrap();
                assert!(!region_tree.root_node().has_error());
            }
            let unit = CodeUnit::new(file.clone(), CodeUnitType::Class, "", name);
            // Probe even the final continuation byte of each UTF-8 name.
            for probe in [
                name_span.clone(),
                name_span.start..name_span.start + 1,
                name_span.end - 1..name_span.end,
            ] {
                let index = RangeIndex(Range {
                    start_byte: probe.start,
                    end_byte: probe.end,
                    start_line: 0,
                    end_line: 0,
                });
                let actual = inspect_rust_named_declaration_node(
                    &index,
                    &unit,
                    tree.root_node(),
                    source,
                    |node, original| {
                        assert_eq!(original, source);
                        assert_eq!(node.kind(), kind);
                        assert_eq!(node.byte_range(), declaration);
                        let name_node = node.child_by_field_name("name").unwrap();
                        assert_eq!(name_node.byte_range(), name_span);
                        assert_eq!(&original[name_node.byte_range()], name);
                        assert_eq!(node.child_by_field_name("body").unwrap().byte_range(), body);
                        let wrapper = node.parent().unwrap();
                        assert_eq!(wrapper.kind(), "declaration_with_attribute");
                        assert_eq!(wrapper.child_by_field_name("declaration"), Some(node));
                        assert_eq!(
                            wrapper
                                .child_by_field_name("attributes")
                                .unwrap()
                                .byte_range(),
                            attributes
                        );
                        node.byte_range()
                    },
                );
                assert_eq!(actual, Some(declaration.clone()));
            }
        }
        // Macro invocation names cannot be interpreted as embedded declarations.
        let unit = CodeUnit::new(file, CodeUnitType::Class, "", "r\u{e9}sum\u{e9}");
        let index = RangeIndex(Range {
            start_byte: 40,
            end_byte: 45,
            start_line: 0,
            end_line: 0,
        });
        assert!(
            inspect_rust_named_declaration_node(&index, &unit, tree.root_node(), source, |_, _| ())
                .is_none()
        );
    }
}
