use brokk_bifrost_core::analyzer::model::StructuredImportPathKind;
use brokk_bifrost_core::analyzer::parsed_file::{ParsedFile, ParsedSourceFacts};
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionGapFact, ResolutionGapKind, ResolutionImportRouteKind, ResolutionSiteKind,
};
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceProvenance};
use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use brokk_bifrost_core::analyzer::{ProjectFile, Range};
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
            .join("java-coordinated-source-tests"),
        "src/Fixture.java",
    );
    let parsed = parse_java_file(&file, source, &tree);
    (parsed, tree)
}

fn source_facts(parsed: &ParsedFile) -> &ParsedSourceFacts {
    parsed
        .source_facts
        .as_ref()
        .expect("Java producer publishes coordinated source facts")
}

fn named_node<'tree>(
    root: Node<'tree>,
    source: &str,
    kind: &str,
    name: &str,
    ordinal: usize,
) -> Node<'tree> {
    let mut matches = Vec::new();
    walk_named_tree_preorder(root, true, |node| {
        if node.kind() == kind
            && node
                .child_by_field_name("name")
                .is_some_and(|name_node| super::declarations::node_text(name_node, source) == name)
        {
            matches.push(node);
        }
        WalkControl::Continue
    });
    *matches
        .get(ordinal)
        .unwrap_or_else(|| panic!("missing {kind} {name:?} occurrence {ordinal}"))
}

fn declaration_for_node(parsed: &ParsedFile, node: Node<'_>) -> SourceDeclarationId {
    let facts = source_facts(parsed);
    let expected_name = node
        .child_by_field_name("name")
        .map(|name| (name.start_byte(), name.end_byte()));
    let mut matches = parsed
        .source_declaration_units
        .iter()
        .filter_map(|(declaration, _)| {
            let row = facts.occurrences.declaration(*declaration);
            let occurrence = facts.occurrences.occurrence(row.occurrence);
            if occurrence.range.start_byte != node.start_byte()
                || occurrence.range.end_byte != node.end_byte()
            {
                return None;
            }
            let name_matches = match (expected_name, row.name) {
                (None, None) => true,
                (Some((start, end)), Some(name_occurrence)) => {
                    let range = facts.occurrences.occurrence(name_occurrence).range;
                    range.start_byte == start && range.end_byte == end
                }
                _ => false,
            };
            name_matches.then_some(*declaration)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "one display source declaration must link to the exact AST node"
    );
    matches.pop().expect("display declaration match")
}

fn assert_primary_declaration_span(parsed: &ParsedFile, node: Node<'_>) -> SourceDeclarationId {
    let declaration = declaration_for_node(parsed, node);
    let facts = source_facts(parsed);
    let row = facts.occurrences.declaration(declaration);
    let occurrence = facts.occurrences.occurrence(row.occurrence);
    assert_eq!(
        occurrence.provenance,
        SourceOccurrenceProvenance::PrimaryNode
    );
    assert_eq!(
        Range {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            start_line: node.start_position().row + 1,
            end_line: node.end_position().row + 1,
        },
        occurrence.range,
        "display declaration span must be the live AST node span"
    );
    declaration
}

fn assert_native_site_occurrences_are_dense(parsed: &ParsedFile) {
    let facts = source_facts(parsed);
    assert_eq!(
        facts.native_site_occurrences.len(),
        parsed.resolution_facts.sites.len(),
        "every native site has one canonical occurrence"
    );
    for (index, (site, occurrence_id)) in parsed
        .resolution_facts
        .sites
        .iter()
        .zip(&facts.native_site_occurrences)
        .enumerate()
    {
        assert_eq!(site.id.index(), index, "native site ids are dense");
        let occurrence = facts.occurrences.occurrence(*occurrence_id);
        assert_eq!(site.start_byte, occurrence.range.start_byte);
        assert_eq!(site.end_byte, occurrence.range.end_byte);
    }
}

#[test]
fn declarations_share_exact_source_ids_across_native_and_display_projections() {
    let source = r#"class Box {
    int first, second;
    Box() {}
    Box(int value) {}
    void run() {}
    void run(int value) {}
}
record Point(int x, String y) {}
enum Mode { FAST, SLOW { void custom() {} } }
"#;
    let (parsed, tree) = parse(source);
    let root = tree.root_node();
    let mut display_ids = Vec::new();
    for (kind, name, ordinal) in [
        ("class_declaration", "Box", 0),
        ("variable_declarator", "first", 0),
        ("variable_declarator", "second", 0),
        ("constructor_declaration", "Box", 0),
        ("constructor_declaration", "Box", 1),
        ("method_declaration", "run", 0),
        ("method_declaration", "run", 1),
        ("record_declaration", "Point", 0),
        ("formal_parameter", "x", 0),
        ("formal_parameter", "y", 0),
        ("enum_declaration", "Mode", 0),
        ("enum_constant", "FAST", 0),
        ("enum_constant", "SLOW", 0),
        ("method_declaration", "custom", 0),
    ] {
        let node = named_node(root, source, kind, name, ordinal);
        display_ids.push((kind, name, assert_primary_declaration_span(&parsed, node)));
    }

    let facts = source_facts(&parsed);
    let native_ids = facts
        .native_declaration_sources
        .iter()
        .map(|(_, declaration)| *declaration)
        .collect::<std::collections::HashSet<_>>();
    for (kind, name, declaration) in &display_ids {
        let native_expected = *kind != "formal_parameter";
        assert_eq!(
            native_ids.contains(declaration),
            native_expected,
            "native/display source-link expectation for {kind} {name}"
        );
    }
    assert_native_site_occurrences_are_dense(&parsed);
}

#[test]
fn nested_class_callables_have_captured_parameter_shapes() {
    let source = "class Sample { Object f(int x) { if (x == 1) { record R(int component) {} class Local { int local(int value) { return value; } } return new Object() { int anonymous(int value) { return value; } }; } else { enum E { A { int enumBody(int value) { return value; } } } class Local { int local(int value) { return value; } } return E.A; } } }";
    let (parsed, _) = parse(source);

    // The record component is not a callable parameter; the other five
    // parameters belong to methods the native walk enters, including local,
    // anonymous, and enum-constant class bodies in if/else arms.
    assert_eq!(parsed.resolution_facts.callable_signatures.len(), 5);
    assert_eq!(parsed.resolution_facts.callable_parameters.len(), 5);
}

#[test]
fn package_identity_shares_structured_path_with_native_segments() {
    let source = "@Anno(value=) package p /* package */ . q; class A {}";
    let (parsed, _) = parse(source);
    assert_eq!(parsed.package_name, "p.q");

    let facts = &parsed.resolution_facts;
    assert_eq!(facts.packages.len(), 1);
    let package = facts.packages[0];
    let package_declaration = package
        .declaration
        .expect("valid package path keeps its native declaration");
    let package_site = facts.sites[package_declaration.index()];
    assert_eq!(
        &source[package_site.start_byte..package_site.end_byte],
        "@Anno(value=) package p /* package */ . q;"
    );
    assert!(!facts.gaps.contains(&ResolutionGapFact {
        site: package_declaration,
        kind: ResolutionGapKind::UnsupportedRoute,
    }));
    assert_eq!(
        facts
            .package_segments
            .iter()
            .map(|segment| facts.names[segment.name.index()].spelling.as_str())
            .collect::<Vec<_>>(),
        vec!["p", "q"]
    );

    let annotation = facts
        .sites
        .iter()
        .find(|site| &source[site.start_byte..site.end_byte] == "@Anno(value=)")
        .expect("package annotation site");
    assert!(facts.gaps.contains(&ResolutionGapFact {
        site: annotation.id,
        kind: ResolutionGapKind::MalformedSyntax,
    }));
}

#[test]
fn late_and_malformed_package_admission_stays_native_only() {
    for (source, expected_package_name) in [
        ("; package p; class A {}", "p"),
        ("import q.Target; package late; class A {}", "late"),
        ("class A {} package after;", ""),
    ] {
        let (parsed, _) = parse(source);
        assert_eq!(parsed.package_name, expected_package_name);
        assert!(parsed.resolution_facts.package_segments.is_empty());
        assert!(parsed.resolution_facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedRoute
                && parsed.resolution_facts.sites[gap.site.index()].kind
                    == ResolutionSiteKind::PackageDeclaration
        }));
    }

    let (parsed, _) = parse("package broken.; class A {}");
    assert!(parsed.package_name.is_empty());
    assert!(parsed.resolution_facts.packages.is_empty());
    assert!(parsed.resolution_facts.gaps.iter().any(|gap| {
        gap.kind == ResolutionGapKind::UnsupportedRoute
            && parsed.resolution_facts.sites[gap.site.index()].kind
                == ResolutionSiteKind::PackageDeclaration
    }));
}

#[test]
fn imports_retain_each_generic_projection_across_native_prefix_gaps() {
    let source = r#"import java.util.*;
import static java.lang.Math.max;
import java.lang.String;
import broken.;
class C {}
import late.Valid;
"#;
    let (parsed, _) = parse(source);
    let facts = source_facts(&parsed);
    assert_eq!(facts.imports.len(), 5);
    assert_eq!(facts.generic_imports.len(), 5);
    for (index, import_id) in facts.generic_imports.iter().enumerate() {
        assert_eq!(import_id.index(), index);
    }
    assert_eq!(parsed.imports.len(), 5);

    let wildcard = &facts.imports[0];
    assert!(wildcard.is_wildcard);
    assert!(wildcard.target.is_none());
    assert_eq!(
        wildcard.path.as_ref().and_then(|path| path.kind),
        Some(StructuredImportPathKind::Namespace)
    );
    assert!(parsed.imports[0].binder_span.is_none());

    let static_import = &facts.imports[1];
    assert!(!static_import.is_wildcard);
    assert!(static_import.target.is_some());
    assert_eq!(
        static_import.path.as_ref().and_then(|path| path.kind),
        Some(StructuredImportPathKind::StaticMember)
    );
    assert_eq!(parsed.imports[1].identifier.as_deref(), Some("max"));
    assert!(parsed.imports[1].binder_span.is_some());

    assert_eq!(parsed.imports[2].identifier.as_deref(), Some("String"));
    assert!(facts.imports[2].target.is_some());
    assert!(facts.imports[3].path.is_none());
    assert!(facts.imports[3].target.is_none());
    assert!(parsed.imports[3].path.is_none());
    assert_eq!(parsed.imports[4].identifier.as_deref(), Some("Valid"));
    assert!(facts.imports[4].path.is_some());

    assert_eq!(
        parsed
            .resolution_facts
            .import_routes
            .iter()
            .map(|route| route.kind)
            .collect::<Vec<_>>(),
        vec![
            ResolutionImportRouteKind::TypeOnDemand,
            ResolutionImportRouteKind::SingleStatic,
            ResolutionImportRouteKind::SingleType,
        ]
    );
    let native_import_sites = parsed
        .resolution_facts
        .sites
        .iter()
        .filter(|site| site.kind == ResolutionSiteKind::ImportDeclaration)
        .collect::<Vec<_>>();
    assert_eq!(native_import_sites.len(), facts.imports.len());
    for (import, site) in facts.imports.iter().zip(native_import_sites) {
        assert_eq!(
            facts.native_site_occurrences[site.id.index()],
            import.declaration,
            "canonical and native import projections must share the declaration occurrence"
        );
    }
    let static_target = facts
        .occurrences
        .occurrence(static_import.target.expect("static import target"));
    assert_eq!(
        &source[static_target.range.start_byte..static_target.range.end_byte],
        "max"
    );

    let late_site = parsed
        .resolution_facts
        .sites
        .iter()
        .find(|site| {
            site.kind == ResolutionSiteKind::ImportDeclaration
                && &source[site.start_byte..site.end_byte] == "import late.Valid;"
        })
        .expect("late valid import native site");
    assert!(parsed.resolution_facts.gaps.contains(
        &brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapFact {
            site: late_site.id,
            kind: ResolutionGapKind::UnsupportedRoute,
        }
    ));
    let malformed_site = parsed
        .resolution_facts
        .sites
        .iter()
        .find(|site| {
            site.kind == ResolutionSiteKind::ImportDeclaration
                && &source[site.start_byte..site.end_byte] == "import broken.;"
        })
        .expect("malformed import native site");
    assert!(parsed.resolution_facts.gaps.contains(
        &brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapFact {
            site: malformed_site.id,
            kind: ResolutionGapKind::UnsupportedRoute,
        }
    ));
}

#[test]
fn structural_descendants_survive_native_unsupported_lambda_scope() {
    let source =
        "class A { Object f() { Object value = () -> { return hidden; }; return value; } }";
    let (parsed, _) = parse(source);
    let facts = source_facts(&parsed);
    let structural_ranges = facts
        .structural
        .nodes()
        .iter()
        .map(|node| {
            (
                node.kind,
                facts.occurrences.occurrence(node.occurrence).range,
            )
        })
        .collect::<Vec<_>>();
    assert!(structural_ranges.iter().any(|(kind, range)| {
        *kind == NormalizedKind::Lambda && source[range.start_byte..range.end_byte].contains("->")
    }));
    assert!(structural_ranges.iter().any(|(kind, range)| {
        *kind == NormalizedKind::Return
            && &source[range.start_byte..range.end_byte] == "return hidden;"
    }));

    let lambda_gap = parsed
        .resolution_facts
        .gaps
        .iter()
        .find(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
                && parsed.resolution_facts.sites[gap.site.index()].kind
                    == ResolutionSiteKind::UnsupportedExpression
                && source[parsed.resolution_facts.sites[gap.site.index()].start_byte
                    ..parsed.resolution_facts.sites[gap.site.index()].end_byte]
                    .contains("->")
        })
        .expect("native lambda unsupported gap");
    assert!(lambda_gap.site.index() < parsed.resolution_facts.sites.len());
}
