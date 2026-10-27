//! Shared Java source-property construction and independent projection laws.

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use brokk_bifrost_test_macros::hardwon;
use tree_sitter::{Node, Tree};

use super::declarations::parse_java_file;
use super::test_support::source_facts as facts;

fn parse(source: &str) -> (ParsedFile, Tree) {
    let tree = super::declarations::parse_tree(source).expect("Java source parses");
    let file = ProjectFile::new(
        std::env::current_dir()
            .expect("current directory")
            .join("java-source-properties-tests"),
        "src/Fixture.java",
    );
    (parse_java_file(&file, source, &tree), tree)
}

fn named_node<'tree>(root: Node<'tree>, source: &str, kind: &str, name: &str) -> Node<'tree> {
    let found = super::test_support::named_nodes(root, source, kind, name);
    assert_eq!(found.len(), 1, "one {kind} named {name:?}");
    found[0]
}

fn source_declaration_for_node(
    parsed: &ParsedFile,
    node: Node<'_>,
) -> (SourceDeclarationId, DeclaredVisibility) {
    let facts = facts(parsed);
    let visibility_facts = facts
        .declaration_visibilities
        .as_ref()
        .expect("Java visibility family is published");
    let declaration = super::test_support::source_declaration_for_node(
        parsed,
        node,
        visibility_facts.iter().map(|fact| fact.declaration),
    );
    let visibility = visibility_facts
        .iter()
        .find(|fact| fact.declaration == declaration)
        .expect("source declaration visibility")
        .visibility;
    (declaration, visibility)
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
    assert!(!parsed.resolution_facts.declaration_visibilities.is_empty());
    for native in &parsed.resolution_facts.declaration_visibilities {
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
    for link in &parsed.source_declaration_metadata {
        let property = properties
            .iter()
            .find(|property| property.declaration == link.declaration)
            .expect("written display metadata has a canonical source property");
        assert_eq!(
            parsed.signature_metadata[&link.unit][link.metadata_ordinal]
                .callable_declared_visibility(),
            Some(property.visibility),
            "{link:?}",
        );
    }
    let (kind, name) = ("formal_parameter", "left");
    let node = named_node(root, source, kind, name);
    let (declaration, _) = source_declaration_for_node(&parsed, node);
    assert!(
        parsed
            .source_declaration_units
            .iter()
            .any(|(source, _)| *source == declaration)
    );
    assert!(
        source_facts
            .native_declaration_sources
            .iter()
            .any(|(_, source)| *source == declaration),
        "{kind} {name} must publish its native record field",
    );
    for (kind, name) in [
        ("enum_constant", "ONE"),
        ("class_declaration", "Local"),
        ("method_declaration", "localMember"),
        ("method_declaration", "anonymousMember"),
    ] {
        let node = named_node(root, source, kind, name);
        let (declaration, _) = source_declaration_for_node(&parsed, node);
        assert!(
            source_facts
                .native_declaration_sources
                .iter()
                .any(|(_, source)| *source == declaration),
            "{kind} {name} must publish its native source link",
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
            .source_declaration_metadata
            .iter()
            .all(|link| link.declaration != value),
        "annotation elements have source properties but remain native-only metadata"
    );
}

#[test]
#[hardwon("43053b9ef08a: synthetic Java scopes leaked into source visibility")]
fn java_synthetic_class_scope_has_no_source_visibility_authority() {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind;

    let source = "class Owner { Object make() { return new Object() { int field; }; } }";
    let (parsed, tree) = parse(source);
    let mut synthetic_bodies = Vec::new();
    walk_named_tree_preorder(tree.root_node(), true, |node| {
        if node.kind() == "class_body"
            && node
                .parent()
                .is_some_and(|parent| parent.kind() == "object_creation_expression")
        {
            synthetic_bodies.push(node);
        }
        WalkControl::Continue
    });
    assert_eq!(synthetic_bodies.len(), 1);
    let body = synthetic_bodies[0];
    let site = parsed
        .resolution_facts
        .sites
        .iter()
        .find(|site| {
            site.kind == ResolutionSiteKind::TypeDeclaration
                && site.start_byte == body.start_byte()
                && site.end_byte == body.end_byte()
        })
        .expect("anonymous class retains its semantic owner site");
    assert!(
        parsed
            .resolution_facts
            .declaration_visibilities
            .iter()
            .all(|visibility| visibility.declaration != site.id),
        "a synthetic owner is not a source declaration with Java visibility"
    );
    assert!(
        facts(&parsed)
            .native_declaration_sources
            .iter()
            .all(|(declaration, _)| *declaration != site.id),
        "a synthetic owner does not publish a source declaration bridge"
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
            .source_declaration_metadata
            .iter()
            .all(|link| !link.unit.is_field())
    );
}

// These tables pin the released Java grammar/API boundary, independently of
// name binding and type inference. Expected spellings follow JLS source forms.
#[test]
fn java_written_declaration_grammar_boundary() {
    use super::declarations::{collect_type_identifiers, is_declaration_parent};
    use brokk_bifrost_core::hash::HashSet;
    let source = "class C<T extends Number> { java.util.List<String> values; T[] array; int primitive; void f() { int local = 0; try (Reader input = open()) { use(input); } catch (Exception caught) {} for (String item : values) {} } }";
    let tree = super::declarations::parse_tree(source).unwrap();
    assert!(!tree.root_node().has_error());
    let mut names = HashSet::default();
    collect_type_identifiers(tree.root_node(), source, &mut names);
    let mut names = names.into_iter().collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        [
            "Exception",
            "List",
            "Number",
            "Reader",
            "String",
            "T",
            "java",
            "java.util",
            "java.util.List",
            "util"
        ]
    );
    for (kind, spelling) in [
        ("variable_declarator", "local"),
        ("resource", "input"),
        ("catch_formal_parameter", "caught"),
        ("enhanced_for_statement", "item"),
    ] {
        let parent = named_node(tree.root_node(), source, kind, spelling);
        let name = parent.child_by_field_name("name").unwrap();
        assert_eq!(name.kind(), "identifier");
        assert_eq!(&source[name.byte_range()], spelling);
        assert!(is_declaration_parent(parent.kind()), "{kind}");
    }
    let uses =
        super::test_support::named_nodes(tree.root_node(), source, "method_invocation", "use");
    let argument = uses[0]
        .child_by_field_name("arguments")
        .unwrap()
        .named_child(0)
        .unwrap();
    assert_eq!(&source[argument.byte_range()], "input");
    assert!(!is_declaration_parent(argument.parent().unwrap().kind()));
}

#[test]
fn java_binary_name_boundary() {
    // JLS 13.1: member classes use a named suffix; anonymous classes a digit suffix.
    for (name, anonymous) in [
        ("p.Outer", false),
        ("p.Outer$Inner", false),
        ("p.Outer$1Local", false),
        ("p.Outer$1", true),
        ("p.Outer$12", true),
        ("p.Outer$Inner$2", true),
        ("p.Outer$anon$3", true),
    ] {
        assert_eq!(
            super::declarations::is_java_anonymous_structure(name),
            anonymous,
            "{name}"
        );
    }
}

#[test]
fn java_import_grammar_boundary() {
    use super::imports::{import_package, parse_import_info};
    // Prefixes are purely written paths: static imports include their owner.
    for (source, segments, prefix) in [
        ("import a.b.C;", vec!["a", "b", "C"], Some("a.b")),
        ("import a.b.*;", vec!["a", "b"], Some("a.b")),
        ("import C;", vec!["C"], None),
        (
            "import static a.b.C.member;",
            vec!["a", "b", "C", "member"],
            Some("a.b.C"),
        ),
        ("import static a.b.C.*;", vec!["a", "b", "C"], Some("a.b.C")),
    ] {
        let tree = super::declarations::parse_tree(source).unwrap();
        assert!(!tree.root_node().has_error());
        let node = tree.root_node().named_child(0).unwrap();
        assert_eq!(node.kind(), "import_declaration");
        let info = parse_import_info(node, source, source.to_owned());
        assert_eq!(info.path.as_ref().unwrap().segments, segments);
        assert_eq!(import_package(&info).as_deref(), prefix, "{source}");
    }
}

#[test]
fn java_receiver_and_construct_grammar_boundary() {
    use super::structural::{JAVA_STRUCTURAL_SPEC, expression_name_node};
    use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
    let source = "class C { void f() { super.run(); this.run(); other.run(); Runnable a = super::run; Runnable b = this::run; Runnable c = C::run; Object d = new C(); } }";
    let tree = super::declarations::parse_tree(source).unwrap();
    assert!(!tree.root_node().has_error());
    let mut receivers = Vec::new();
    let mut constructs = Vec::new();
    walk_named_tree_preorder(tree.root_node(), true, |node| {
        if node.kind() == "method_invocation" {
            let receiver = node.child_by_field_name("object").unwrap();
            let name = expression_name_node(receiver).unwrap();
            assert_eq!(name.byte_range(), receiver.byte_range());
            receivers.push(source[name.byte_range()].to_owned());
        }
        if matches!(
            node.kind(),
            "method_reference" | "object_creation_expression"
        ) {
            constructs.push((
                node.kind(),
                JAVA_STRUCTURAL_SPEC.generator_construct(
                    node,
                    brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind::Call,
                    source,
                ),
            ));
        }
        WalkControl::Continue
    });
    assert_eq!(receivers, ["super", "this", "other"]);
    assert_eq!(
        constructs,
        [
            ("method_reference", Some("java_method_reference")),
            ("method_reference", Some("java_method_reference")),
            ("method_reference", Some("java_method_reference")),
            ("object_creation_expression", Some("java_object_creation"))
        ]
    );
}

#[test]
fn java_switch_statement_grammar_boundary() {
    use super::structural::{
        JavaCallResultUse, java_call_result_use, java_switch_rule_value_expression_statement,
    };
    // The grammar calls both constructs switch_expression; their parent fields
    // distinguish JLS 14.11 statements from JLS 15.28 value expressions.
    let source = "class C { int f(int n) { switch(n) { case 1 -> discard(); default -> discard(); } int v = switch(n) { case 1 -> consume(); default -> consume(); }; return switch(n) { case 1 -> result(); default -> result(); }; } }";
    let tree = super::declarations::parse_tree(source).unwrap();
    assert!(!tree.root_node().has_error());
    let mut arms = Vec::new();
    walk_named_tree_preorder(tree.root_node(), true, |node| {
        if node.kind() == "expression_statement" && node.parent().unwrap().kind() == "switch_rule" {
            let call = node.named_child(0).unwrap();
            assert_eq!(call.kind(), "method_invocation");
            let name = call.child_by_field_name("name").unwrap();
            arms.push((
                source[name.byte_range()].to_owned(),
                java_switch_rule_value_expression_statement(node),
                java_call_result_use(call),
            ));
        }
        WalkControl::Continue
    });
    assert_eq!(
        arms,
        [
            (
                "discard".to_owned(),
                false,
                Some(JavaCallResultUse::Discarded)
            ),
            (
                "discard".to_owned(),
                false,
                Some(JavaCallResultUse::Discarded)
            ),
            (
                "consume".to_owned(),
                true,
                Some(JavaCallResultUse::OtherContext)
            ),
            (
                "consume".to_owned(),
                true,
                Some(JavaCallResultUse::OtherContext)
            ),
            (
                "result".to_owned(),
                true,
                Some(JavaCallResultUse::OtherContext)
            ),
            (
                "result".to_owned(),
                true,
                Some(JavaCallResultUse::OtherContext)
            )
        ]
    );
}

#[test]
fn java_pattern_binder_grammar_boundary() {
    use super::structural::java_pattern_binding_name;
    let source = "class C { int f(Object o) { if (o instanceof String text) {} return switch(o) { case String value -> 1; case Box(String outer, Box(int nested)) -> 2; default -> 0; }; } }";
    let tree = super::declarations::parse_tree(source).unwrap();
    assert!(!tree.root_node().has_error());
    let mut bindings = Vec::new();
    walk_named_tree_preorder(tree.root_node(), true, |node| {
        if matches!(
            node.kind(),
            "instanceof_expression" | "type_pattern" | "record_pattern_component"
        ) {
            let name = java_pattern_binding_name(node).expect("typed pattern carries a binder");
            assert_eq!(name.kind(), "identifier");
            assert_eq!(name.parent().unwrap().id(), node.id());
            bindings.push((node.kind(), source[name.byte_range()].to_owned()));
        }
        WalkControl::Continue
    });
    assert_eq!(
        bindings,
        [
            ("instanceof_expression", "text".to_owned()),
            ("type_pattern", "value".to_owned()),
            ("record_pattern_component", "outer".to_owned()),
            ("record_pattern_component", "nested".to_owned())
        ]
    );
}
