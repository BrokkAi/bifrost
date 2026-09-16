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
        .native_source
        .as_ref()
        .expect("Java native packet")
        .source_facts()
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
        .native_source
        .as_ref()
        .expect("Java native packet")
        .source_facts()
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
        parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .resolution_facts()
            .sites
            .len(),
        "every native site has one canonical occurrence"
    );
    for (index, (site, occurrence_id)) in parsed
        .native_source
        .as_ref()
        .expect("Java native packet")
        .resolution_facts()
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
        let native_expected =
            !matches!(*kind, "formal_parameter" | "enum_constant") && *name != "custom";
        assert_eq!(
            native_ids.contains(declaration),
            native_expected,
            "native/display source-link expectation for {kind} {name}"
        );
    }
    assert_native_site_occurrences_are_dense(&parsed);
}

#[test]
fn package_identity_shares_structured_path_with_native_segments() {
    let source = "@Anno(value=) package p /* package */ . q; class A {}";
    let (parsed, _) = parse(source);
    assert_eq!(parsed.package_name, "p.q");

    let facts = &parsed
        .native_source
        .as_ref()
        .expect("Java native packet")
        .resolution_facts();
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
        assert!(
            parsed
                .native_source
                .as_ref()
                .expect("Java native packet")
                .resolution_facts()
                .package_segments
                .is_empty()
        );
        assert!(
            parsed
                .native_source
                .as_ref()
                .expect("Java native packet")
                .resolution_facts()
                .gaps
                .iter()
                .any(|gap| {
                    gap.kind == ResolutionGapKind::UnsupportedRoute
                        && parsed
                            .native_source
                            .as_ref()
                            .expect("Java native packet")
                            .resolution_facts()
                            .sites[gap.site.index()]
                        .kind
                            == ResolutionSiteKind::PackageDeclaration
                })
        );
    }

    let (parsed, _) = parse("package broken.; class A {}");
    assert!(parsed.package_name.is_empty());
    assert!(
        parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .resolution_facts()
            .packages
            .is_empty()
    );
    assert!(
        parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .resolution_facts()
            .gaps
            .iter()
            .any(|gap| {
                gap.kind == ResolutionGapKind::UnsupportedRoute
                    && parsed
                        .native_source
                        .as_ref()
                        .expect("Java native packet")
                        .resolution_facts()
                        .sites[gap.site.index()]
                    .kind
                        == ResolutionSiteKind::PackageDeclaration
            })
    );
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
            .native_source
            .as_ref()
            .expect("Java native packet")
            .resolution_facts()
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
        .native_source
        .as_ref()
        .expect("Java native packet")
        .resolution_facts()
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
        .native_source
        .as_ref()
        .expect("Java native packet")
        .resolution_facts()
        .sites
        .iter()
        .find(|site| {
            site.kind == ResolutionSiteKind::ImportDeclaration
                && &source[site.start_byte..site.end_byte] == "import late.Valid;"
        })
        .expect("late valid import native site");
    assert!(
        parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .resolution_facts()
            .gaps
            .contains(
                &brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapFact {
                    site: late_site.id,
                    kind: ResolutionGapKind::UnsupportedRoute,
                }
            )
    );
    let malformed_site = parsed
        .native_source
        .as_ref()
        .expect("Java native packet")
        .resolution_facts()
        .sites
        .iter()
        .find(|site| {
            site.kind == ResolutionSiteKind::ImportDeclaration
                && &source[site.start_byte..site.end_byte] == "import broken.;"
        })
        .expect("malformed import native site");
    assert!(
        parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .resolution_facts()
            .gaps
            .contains(
                &brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapFact {
                    site: malformed_site.id,
                    kind: ResolutionGapKind::UnsupportedRoute,
                }
            )
    );
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
        .native_source
        .as_ref()
        .expect("Java native packet")
        .resolution_facts()
        .gaps
        .iter()
        .find(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
                && parsed
                    .native_source
                    .as_ref()
                    .expect("Java native packet")
                    .resolution_facts()
                    .sites[gap.site.index()]
                .kind
                    == ResolutionSiteKind::UnsupportedExpression
                && source[parsed
                    .native_source
                    .as_ref()
                    .expect("Java native packet")
                    .resolution_facts()
                    .sites[gap.site.index()]
                .start_byte
                    ..parsed
                        .native_source
                        .as_ref()
                        .expect("Java native packet")
                        .resolution_facts()
                        .sites[gap.site.index()]
                    .end_byte]
                    .contains("->")
        })
        .expect("native lambda unsupported gap");
    assert!(
        lambda_gap.site.index()
            < parsed
                .native_source
                .as_ref()
                .expect("Java native packet")
                .resolution_facts()
                .sites
                .len()
    );
}

#[test]
fn canonical_roles_match_legacy_spans_and_stop_evidence() {
    use super::structural::{JAVA_KIND_TABLE, JAVA_STRUCTURAL_SPEC};
    use brokk_bifrost_core::analyzer::source_facts::PrimarySourceFactCollector;
    use brokk_bifrost_core::analyzer::structural::facts::Span;
    use brokk_bifrost_core::analyzer::structural::spec::{
        CompiledKinds, RoleSink, RoleSinkStop, StructuralSpec,
    };
    use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_core::hash::HashMap;

    let text = "class Roles { int field; int call(int x, int y) { this.field = x; return Math.max(x, y); } }";
    let (parsed, tree) = parse(text);
    let root = tree.root_node();
    let parents = ParentIndex::new(root);
    let kinds = CompiledKinds::compile(&tree_sitter_java::LANGUAGE.into(), JAVA_KIND_TABLE);
    let mut nodes = Vec::new();
    walk_named_tree_preorder(root, true, |node| {
        if let Some(kind) = kinds.kind_of(&node)
            && JAVA_STRUCTURAL_SPEC.should_extract(node, kind)
        {
            nodes.push((node, kind));
        }
        WalkControl::Continue
    });
    let ids = nodes
        .iter()
        .enumerate()
        .map(|(id, (node, _))| (node.id(), u32::try_from(id).unwrap()))
        .collect::<HashMap<_, _>>();
    let canonical = &source_facts(&parsed).structural;
    assert_eq!(nodes.len(), canonical.nodes().len());
    for (id, (node, _kind)) in nodes.iter().copied().enumerate() {
        let canonical_node = canonical.node(u32::try_from(id).unwrap());
        let kind = canonical_node.kind;
        let source = &source_facts(&parsed).occurrences;
        let span = |occurrence| {
            let range = source.occurrence(occurrence).range;
            Span {
                start_byte: range.start_byte,
                end_byte: range.end_byte,
            }
        };
        assert_eq!(
            span(canonical_node.occurrence),
            Span {
                start_byte: node.start_byte(),
                end_byte: node.end_byte()
            }
        );
        for cap in [0, 1, usize::MAX] {
            for cancelled in [false, true] {
                let cancellation = CancellationToken::default();
                if cancelled {
                    cancellation.cancel();
                }
                let mut roles = Vec::new();
                let mut occurrences = Vec::new();
                let mut legacy = RoleSink::new(
                    &ids,
                    &mut roles,
                    &mut occurrences,
                    cap,
                    Some(&cancellation),
                    &parents,
                );
                JAVA_STRUCTURAL_SPEC.extract(node, kind, &mut legacy);
                let (name, stop) = legacy.into_parts();
                let mut arena = PrimarySourceFactCollector::new(text);
                let mut native =
                    RoleSink::for_source(&mut arena, cap, Some(&cancellation), &parents);
                JAVA_STRUCTURAL_SPEC.extract(node, kind, &mut native);
                let (native_name, native_roles, native_occurrences, native_stop) =
                    native.into_source_parts();
                assert_eq!(stop, native_stop);
                let source_span = |occurrence| {
                    let range = arena.occurrence(occurrence).range;
                    Span {
                        start_byte: range.start_byte,
                        end_byte: range.end_byte,
                    }
                };
                assert_eq!(name, native_name.map(source_span));
                assert_eq!(roles.len(), native_roles.len());
                for (old, new) in roles.iter().zip(&native_roles) {
                    assert_eq!(
                        (
                            old.role,
                            old.spread,
                            old.node,
                            old.span,
                            old.name,
                            old.keyword
                        ),
                        (
                            new.role,
                            new.spread,
                            ids.get(&new.target_node).copied(),
                            source_span(new.occurrence),
                            new.name.map(source_span),
                            new.keyword.map(source_span)
                        )
                    );
                }
                assert_eq!(
                    occurrences,
                    native_occurrences
                        .iter()
                        .map(|role| (ids[&role.target_node], role.role))
                        .collect::<Vec<_>>()
                );
                if cap == usize::MAX && !cancelled {
                    assert_eq!(name, canonical_node.name.map(span));
                    assert_eq!(
                        roles.len(),
                        canonical.roles(u32::try_from(id).unwrap()).len()
                    );
                    for (old, new) in roles
                        .iter()
                        .zip(canonical.roles(u32::try_from(id).unwrap()))
                    {
                        assert_eq!(
                            (
                                old.role,
                                old.spread,
                                old.node,
                                old.span,
                                old.name,
                                old.keyword
                            ),
                            (
                                new.role,
                                new.spread,
                                new.node,
                                span(new.occurrence),
                                new.name.map(span),
                                new.keyword.map(span)
                            )
                        );
                    }
                }
            }
        }
        // Once the cap stops a sink, later cancellation cannot overwrite the reason.
        let cancellation = CancellationToken::default();
        let mut roles = Vec::new();
        let mut occurrences = Vec::new();
        let mut sink = RoleSink::new(
            &ids,
            &mut roles,
            &mut occurrences,
            0,
            Some(&cancellation),
            &parents,
        );
        assert!(!sink.should_continue());
        cancellation.cancel();
        assert!(!sink.should_continue());
        assert_eq!(sink.into_parts().1, Some(RoleSinkStop::Exceeded));
        let cancellation = CancellationToken::default();
        let mut arena = PrimarySourceFactCollector::new(text);
        let mut sink = RoleSink::for_source(&mut arena, 0, Some(&cancellation), &parents);
        assert!(!sink.should_continue());
        cancellation.cancel();
        assert!(!sink.should_continue());
        assert_eq!(sink.into_source_parts().3, Some(RoleSinkStop::Exceeded));
    }
}

#[test]
fn packet_rejects_crosswalk_and_source_extent_mismatches() {
    use brokk_bifrost_core::analyzer::parsed_file::ParsedNativeSource;
    let (parsed, _) = parse("class A { int x; }");
    let packet = parsed.native_source.as_ref().unwrap().clone();
    let (facts, source) = packet.into_parts();
    let mut wrong = source.clone();
    wrong.native_site_occurrences.pop();
    assert!(
        std::panic::catch_unwind(|| ParsedNativeSource::new(facts.clone(), wrong, &parsed))
            .is_err()
    );
    let mut wrong = source.clone();
    wrong.source_bytes = 0;
    assert!(
        std::panic::catch_unwind(|| ParsedNativeSource::new(facts.clone(), wrong, &parsed))
            .is_err()
    );
    let mut wrong = source.clone();
    wrong.source_declaration_metadata[0].metadata_ordinal = usize::MAX;
    assert!(
        std::panic::catch_unwind(|| ParsedNativeSource::new(facts.clone(), wrong, &parsed))
            .is_err()
    );
    let mut wrong = source.clone();
    wrong.native_declaration_sources[0].1 = SourceDeclarationId::new(u32::MAX);
    assert!(
        std::panic::catch_unwind(|| ParsedNativeSource::new(facts.clone(), wrong, &parsed))
            .is_err()
    );
    let mut wrong = facts.clone();
    wrong.sites[0].end_byte += 1;
    assert!(
        std::panic::catch_unwind(|| ParsedNativeSource::new(wrong, source.clone(), &parsed))
            .is_err()
    );
    let mut wrong = source.clone();
    wrong.native_site_occurrences[0] =
        brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId::new(u32::MAX);
    assert!(std::panic::catch_unwind(|| ParsedNativeSource::new(facts, wrong, &parsed)).is_err());
}

#[test]
fn empty_java_is_available_with_explicit_placement_gap() {
    let (parsed, _) = parse("");
    let packet = parsed.native_source.expect("empty Java is produced");
    assert_eq!(packet.source_facts().source_bytes, 0);
    assert_eq!(
        packet.source_facts().declaration_visibilities,
        Some(Vec::new())
    );
    assert!(
        packet
            .resolution_facts()
            .gaps
            .iter()
            .any(|gap| gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary)
    );
}

#[test]
fn unsupported_kotlin_producer_keeps_packet_absent() {
    let source = "class A { fun value(): Int = 1 }";
    let mut parser = Parser::new();
    parser
        .set_language(&brokk_tree_sitter_kotlin::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(source, None).unwrap();
    let file = ProjectFile::new(std::env::temp_dir(), "Unavailable.kt");
    let parsed = crate::kotlin::declarations::parse_kotlin_file(&file, source, &tree);
    assert!(!parsed.declarations().is_empty());
    assert!(parsed.native_source.is_none());
}

#[test]
fn interrupted_java_parse_has_no_produced_packet_and_can_retry() {
    let source = format!("class A {{ {} }}", "int field; ".repeat(4096));
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .unwrap();
    let mut progress_seen = false;
    let mut progress = |_: &tree_sitter::ParseState| {
        progress_seen = true;
        true
    };
    let tree = parser.parse_with_options(
        &mut |offset, _| &source.as_bytes()[offset..],
        None,
        Some(tree_sitter::ParseOptions::new().progress_callback(&mut progress)),
    );
    assert!(progress_seen);
    assert!(tree.is_none());
    let file = ProjectFile::new(std::env::temp_dir(), "Interrupted.java");
    let packet = tree.map(|tree| parse_java_file(&file, &source, &tree));
    assert!(packet.is_none());
    parser.reset();
    let tree = parser.parse("class A {}", None).unwrap();
    assert!(
        parse_java_file(&file, "class A {}", &tree)
            .native_source
            .is_some()
    );
}

#[test]
fn native_declaration_site_uses_name_and_rejects_sibling_source_link() {
    use brokk_bifrost_core::analyzer::parsed_file::ParsedNativeSource;
    let (parsed, tree) = parse("class A { int first, second; }");
    let packet = parsed.native_source.as_ref().unwrap();
    let source = packet.source_facts();
    for &(site, declaration) in &source.native_declaration_sources {
        let declaration = source.occurrences.declaration(declaration);
        let occurrence = source.native_site_occurrences[site.index()];
        assert_eq!(Some(occurrence), declaration.name);
        assert_ne!(occurrence, declaration.occurrence);
    }
    let text = "class A { int first, second; }";
    let first = declaration_for_node(
        &parsed,
        named_node(tree.root_node(), text, "variable_declarator", "first", 0),
    );
    let second = declaration_for_node(
        &parsed,
        named_node(tree.root_node(), text, "variable_declarator", "second", 0),
    );
    let (facts, mut source) = packet.clone().into_parts();
    let (_, declaration) = source
        .native_declaration_sources
        .iter_mut()
        .find(|(_, declaration)| *declaration == first)
        .unwrap();
    *declaration = second;
    assert!(std::panic::catch_unwind(|| ParsedNativeSource::new(facts, source, &parsed)).is_err());
}
