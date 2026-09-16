//! Shared Java source-property construction and independent projection laws.

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::parsed_file::{ParsedFile, ParsedSourceFacts};
use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use tree_sitter::{Node, Parser, Tree};

use super::declarations::parse_java_file;

fn parse(source: &str) -> (ParsedFile, Tree) {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .expect("Java grammar is valid");
    let tree = parser.parse(source, None).expect("Java source parses");
    let file = ProjectFile::new(
        std::env::current_dir()
            .expect("current directory")
            .join("java-source-properties-tests"),
        "src/Fixture.java",
    );
    (parse_java_file(&file, source, &tree), tree)
}

fn facts(parsed: &ParsedFile) -> &ParsedSourceFacts {
    parsed
        .native_source
        .as_ref()
        .expect("Java native packet")
        .source_facts()
}

fn named_node<'tree>(root: Node<'tree>, source: &str, kind: &str, name: &str) -> Node<'tree> {
    let mut found = Vec::new();
    walk_named_tree_preorder(root, true, |node| {
        if node.kind() == kind
            && node.child_by_field_name("name").is_some_and(|name_node| {
                &source[name_node.start_byte()..name_node.end_byte()] == name
            })
        {
            found.push(node);
        }
        WalkControl::Continue
    });
    assert_eq!(found.len(), 1, "one {kind} named {name:?}");
    found[0]
}

fn source_declaration_for_node(
    parsed: &ParsedFile,
    node: Node<'_>,
) -> (SourceDeclarationId, DeclaredVisibility) {
    let facts = facts(parsed);
    let expected_name = node
        .child_by_field_name("name")
        .map(|name| (name.start_byte(), name.end_byte()));
    let matches = facts
        .declaration_visibilities
        .as_ref()
        .expect("Java visibility family is published")
        .iter()
        .filter_map(|fact| {
            let declaration = facts.occurrences.declaration(fact.declaration);
            let occurrence = facts.occurrences.occurrence(declaration.occurrence);
            if (occurrence.range.start_byte, occurrence.range.end_byte)
                != (node.start_byte(), node.end_byte())
            {
                return None;
            }
            let name_matches = match (expected_name, declaration.name) {
                (None, None) => true,
                (Some((start, end)), Some(name)) => {
                    let range = facts.occurrences.occurrence(name).range;
                    (range.start_byte, range.end_byte) == (start, end)
                }
                _ => false,
            };
            name_matches.then_some((fact.declaration, fact.visibility))
        })
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "one source property for AST node");
    matches[0]
}

fn assert_visibility(
    parsed: &ParsedFile,
    root: Node<'_>,
    source: &str,
    kind: &str,
    name: &str,
    expected: DeclaredVisibility,
) -> SourceDeclarationId {
    let node = named_node(root, source, kind, name);
    let (declaration, visibility) = source_declaration_for_node(parsed, node);
    assert_eq!(
        visibility, expected,
        "source visibility for {kind} {name:?}"
    );
    declaration
}

#[test]
fn source_visibility_captures_defaults_and_suppressed_projections() {
    let source = r#"
interface Contract {
    void run();
    private void hidden() {}
    int FIRST = 1, SECOND = 2;
    default void body() {
        class LocalInInterface { void localMember() {} }
        Object value = new Object() { int anonymousField; };
    }
}
enum Choice {
    ONE;
    Choice() {}
}
record Pair(int left, int right) {
    public Pair {}
}
class Outer {
    class Nested {}
    private int leftField, rightField;
    void host() {
        class Local {}
        Object value = new Object() {
            public void anonymousMember() {}
        };
    }
}
@interface Marker {
    String value();
}
"#;
    let (parsed, tree) = parse(source);
    let root = tree.root_node();

    assert_visibility(
        &parsed,
        root,
        source,
        "interface_declaration",
        "Contract",
        DeclaredVisibility::PackagePrivate,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "method_declaration",
        "run",
        DeclaredVisibility::Public,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "method_declaration",
        "hidden",
        DeclaredVisibility::Private,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "variable_declarator",
        "FIRST",
        DeclaredVisibility::Public,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "variable_declarator",
        "SECOND",
        DeclaredVisibility::Public,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "enum_declaration",
        "Choice",
        DeclaredVisibility::PackagePrivate,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "enum_constant",
        "ONE",
        DeclaredVisibility::Public,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "constructor_declaration",
        "Choice",
        DeclaredVisibility::Private,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "record_declaration",
        "Pair",
        DeclaredVisibility::PackagePrivate,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "formal_parameter",
        "left",
        DeclaredVisibility::Private,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "formal_parameter",
        "right",
        DeclaredVisibility::Private,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "compact_constructor_declaration",
        "Pair",
        DeclaredVisibility::Public,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "class_declaration",
        "Outer",
        DeclaredVisibility::PackagePrivate,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "class_declaration",
        "Nested",
        DeclaredVisibility::PackagePrivate,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "method_declaration",
        "host",
        DeclaredVisibility::PackagePrivate,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "class_declaration",
        "Local",
        DeclaredVisibility::Unknown,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "method_declaration",
        "anonymousMember",
        DeclaredVisibility::Public,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "annotation_type_declaration",
        "Marker",
        DeclaredVisibility::PackagePrivate,
    );
    let value = assert_visibility(
        &parsed,
        root,
        source,
        "annotation_type_element_declaration",
        "value",
        DeclaredVisibility::Public,
    );

    for name in ["leftField", "rightField"] {
        assert_visibility(
            &parsed,
            root,
            source,
            "variable_declarator",
            name,
            DeclaredVisibility::Private,
        );
    }
    assert_visibility(
        &parsed,
        root,
        source,
        "class_declaration",
        "LocalInInterface",
        DeclaredVisibility::Unknown,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "method_declaration",
        "localMember",
        DeclaredVisibility::PackagePrivate,
    );
    assert_visibility(
        &parsed,
        root,
        source,
        "variable_declarator",
        "anonymousField",
        DeclaredVisibility::PackagePrivate,
    );

    let source_facts = facts(&parsed);
    let properties = source_facts.declaration_visibilities.as_ref().unwrap();
    assert!(
        !parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .resolution_facts()
            .declaration_visibilities
            .is_empty()
    );
    for native in &parsed
        .native_source
        .as_ref()
        .expect("Java native packet")
        .resolution_facts()
        .declaration_visibilities
    {
        let (_, declaration) = source_facts
            .native_declaration_sources
            .iter()
            .find(|(site, _)| *site == native.declaration)
            .expect("native declaration has an exact source link");
        let property = properties
            .iter()
            .find(|property| property.declaration == *declaration)
            .expect("native visibility has a canonical source property");
        assert_eq!(native.visibility, property.visibility, "{native:?}");
    }
    for link in &parsed
        .native_source
        .as_ref()
        .expect("Java native packet")
        .source_facts()
        .source_declaration_metadata
    {
        let property = properties
            .iter()
            .find(|property| property.declaration == link.declaration)
            .expect("written display metadata has a canonical source property");
        let metadata = &parsed.signature_metadata[&link.unit][link.metadata_ordinal];
        if link.unit.is_function() {
            assert_eq!(
                metadata.callable_declared_visibility(),
                Some(property.visibility),
                "{link:?}"
            );
        }
    }
    for (kind, name) in [
        ("formal_parameter", "left"),
        ("enum_constant", "ONE"),
        ("class_declaration", "Local"),
        ("method_declaration", "localMember"),
        ("method_declaration", "anonymousMember"),
    ] {
        let node = named_node(root, source, kind, name);
        let (declaration, _) = source_declaration_for_node(&parsed, node);
        assert!(
            parsed
                .native_source
                .as_ref()
                .expect("Java native packet")
                .source_facts()
                .source_declaration_units
                .iter()
                .any(|(source, _)| *source == declaration)
        );
        assert!(
            source_facts
                .native_declaration_sources
                .iter()
                .all(|(_, source)| *source != declaration),
            "{kind} {name} must retain independent native suppression",
        );
    }
    assert!(
        source_facts
            .native_declaration_sources
            .iter()
            .any(|(_, source)| *source == value)
    );

    assert!(
        parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .source_facts()
            .source_declaration_metadata
            .iter()
            .all(|link| link.declaration != value),
        "annotation elements have source properties but remain native-only metadata"
    );
}

#[test]
fn duplicate_display_metadata_retains_each_source_declaration_link() {
    let source = "class Duplicate { void run() {} void run() {} }";
    let (parsed, tree) = parse(source);
    let root = tree.root_node();
    let mut run_nodes = Vec::new();
    walk_named_tree_preorder(root, true, |node| {
        if node.kind() == "method_declaration"
            && node
                .child_by_field_name("name")
                .is_some_and(|name| &source[name.start_byte()..name.end_byte()] == "run")
        {
            run_nodes.push(node);
        }
        WalkControl::Continue
    });
    assert_eq!(run_nodes.len(), 2);

    let declarations = run_nodes
        .iter()
        .map(|node| {
            let (declaration, visibility) = source_declaration_for_node(&parsed, *node);
            assert_eq!(visibility, DeclaredVisibility::PackagePrivate);
            declaration
        })
        .collect::<Vec<_>>();
    assert_ne!(declarations[0], declarations[1]);

    let links = parsed
        .native_source
        .as_ref()
        .expect("Java native packet")
        .source_facts()
        .source_declaration_metadata
        .iter()
        .filter(|link| declarations.contains(&link.declaration))
        .collect::<Vec<_>>();
    assert_eq!(links.len(), 2);
    assert_eq!(links[0].unit, links[1].unit);
    assert_eq!(links[0].metadata_ordinal, links[1].metadata_ordinal);
    let metadata = parsed
        .signature_metadata
        .get(&links[0].unit)
        .expect("duplicate methods have metadata")
        .get(links[0].metadata_ordinal)
        .expect("metadata ordinal");
    assert_eq!(
        metadata.callable_declared_visibility(),
        Some(DeclaredVisibility::PackagePrivate)
    );
}

#[test]
fn malformed_field_without_admitted_declarator_does_not_panic_or_publish_metadata() {
    let source = "class Broken { int ; void okay() {} }";
    let (parsed, tree) = parse(source);
    assert!(tree.root_node().has_error());
    assert!(
        parsed
            .declarations()
            .iter()
            .any(|unit| unit.identifier() == "okay")
    );
    assert!(
        parsed
            .signature_metadata
            .keys()
            .all(|unit| !unit.is_field())
    );
    assert!(
        parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .source_facts()
            .source_declaration_metadata
            .iter()
            .all(|link| !link.unit.is_field())
    );
}
