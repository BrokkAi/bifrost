use super::{RustTypeSourceCollector, RustTypeSourceShape};
use brokk_bifrost_core::analyzer::rust_facts::RustTypeCompoundSourceKind;
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceFactRows, SourceOccurrenceId,
};
use tree_sitter::{Node, Parser, Tree};

fn parse_tree(source: &str) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("Rust grammar");
    parser.parse(source, None).expect("parse Rust source")
}

fn first_named_kind<'tree>(tree: &'tree Tree, kind: &str) -> Node<'tree> {
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if node.kind() == kind {
            return node;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                pending.push(child);
            }
        }
    }
    panic!("missing Rust node kind {kind}");
}

fn record_kind(
    source: &str,
    kind: &str,
) -> (
    brokk_bifrost_core::analyzer::rust_facts::RustTypeSourceFact,
    Vec<brokk_bifrost_core::analyzer::rust_facts::RustTypeSourceFact>,
    SourceFactRows,
    Tree,
) {
    let tree = parse_tree(source);
    let node = first_named_kind(&tree, kind);
    let mut occurrences = PrimarySourceFactCollector::new(source);
    let mut types = RustTypeSourceCollector::new();
    let fact = types.record_type(node, source, &mut occurrences).clone();
    (fact, types.into_facts(), occurrences.finish(), tree)
}

fn occurrence_text<'source>(
    source: &'source str,
    rows: &SourceFactRows,
    occurrence: SourceOccurrenceId,
) -> &'source str {
    let range = rows.occurrence(occurrence).range;
    &source[range.start_byte..range.end_byte]
}

#[test]
fn captures_compound_forms_and_preserves_structured_child_order() {
    let bounded_source = "fn make() -> First + 'a + Second {}";
    let (bounded, bounded_facts, bounded_rows, _) = record_kind(bounded_source, "bounded_type");
    let RustTypeSourceShape::Compound {
        occurrence,
        kind,
        children,
        type_parameters,
    } = &bounded.shape
    else {
        panic!("bounded type must be a compound shape");
    };
    assert_eq!(*occurrence, bounded.occurrence);
    assert_eq!(*kind, RustTypeCompoundSourceKind::Bounded);
    assert!(type_parameters.is_none());
    assert_eq!(
        children
            .iter()
            .map(|id| occurrence_text(bounded_source, &bounded_rows, *id))
            .collect::<Vec<_>>(),
        ["First + 'a", "Second"]
    );
    for child in children {
        assert!(
            bounded_facts.iter().any(|fact| fact.occurrence == *child),
            "every bounded child must retain a type fact"
        );
    }
    let inner = bounded_facts
        .iter()
        .find(|fact| fact.occurrence == children[0])
        .expect("nested bounded child fact");
    let RustTypeSourceShape::Compound {
        kind: inner_kind,
        children: inner_children,
        ..
    } = &inner.shape
    else {
        panic!("left-associated bounded child must remain compound");
    };
    assert_eq!(*inner_kind, RustTypeCompoundSourceKind::Bounded);
    assert_eq!(
        inner_children
            .iter()
            .map(|id| occurrence_text(bounded_source, &bounded_rows, *id))
            .collect::<Vec<_>>(),
        ["First", "'a"]
    );
    let lifetime = bounded_facts
        .iter()
        .find(|fact| fact.occurrence == inner_children[1])
        .expect("lifetime child fact");
    assert!(matches!(
        &lifetime.shape,
        RustTypeSourceShape::Unsupported { .. }
    ));

    for (source, node_kind, compound_kind, expected_parameters) in [
        (
            "fn make() -> impl Trait {}",
            "abstract_type",
            RustTypeCompoundSourceKind::Abstract,
            None,
        ),
        (
            "fn make() -> dyn Trait {}",
            "dynamic_type",
            RustTypeCompoundSourceKind::Dynamic,
            None,
        ),
        (
            "fn make() -> impl for<'a> Trait<'a> {}",
            "abstract_type",
            RustTypeCompoundSourceKind::Abstract,
            Some("<'a>"),
        ),
    ] {
        let (fact, facts, rows, _) = record_kind(source, node_kind);
        let RustTypeSourceShape::Compound {
            occurrence,
            kind,
            children,
            type_parameters,
        } = &fact.shape
        else {
            panic!("{node_kind} must be a compound shape");
        };
        assert_eq!(*occurrence, fact.occurrence);
        assert_eq!(*kind, compound_kind);
        assert_eq!(children.len(), 1);
        assert_eq!(
            type_parameters.map(|parameters| occurrence_text(source, &rows, parameters)),
            expected_parameters
        );
        assert!(facts.iter().any(|child| child.occurrence == children[0]));
        assert_eq!(
            occurrence_text(source, &rows, children[0]),
            if expected_parameters.is_some() {
                "Trait<'a>"
            } else {
                "Trait"
            }
        );
    }
}

#[test]
fn captures_higher_ranked_target_and_parameter_list_without_generic_duplication() {
    let source = "fn higher_ranked_factory() -> dyn for<'a> Trait<'a> { todo!() }";
    let (fact, facts, rows, _) = record_kind(source, "higher_ranked_trait_bound");
    let RustTypeSourceShape::Compound {
        occurrence,
        kind,
        children,
        type_parameters,
    } = &fact.shape
    else {
        panic!("higher-ranked bound must be a compound shape");
    };
    assert_eq!(*occurrence, fact.occurrence);
    assert_eq!(*kind, RustTypeCompoundSourceKind::HigherRanked);
    assert_eq!(children.len(), 1);
    let parameters = type_parameters.expect("higher-ranked parameter list");
    assert_ne!(parameters, fact.occurrence);
    assert_eq!(occurrence_text(source, &rows, children[0]), "Trait<'a>");
    assert!(facts.iter().any(|child| child.occurrence == children[0]));
    assert!(!facts.iter().any(|child| child.occurrence == parameters));
    assert_eq!(occurrence_text(source, &rows, parameters), "<'a>");
}

#[test]
fn nested_generic_and_wrapper_occurrences_remain_exact_and_deduplicated() {
    let source = "fn make() -> Option<Box<&Trait>> {}";
    let tree = parse_tree(source);
    let node = first_named_kind(&tree, "generic_type");
    let mut occurrences = PrimarySourceFactCollector::new(source);
    let mut types = RustTypeSourceCollector::new();
    let first = types.record_type(node, source, &mut occurrences).clone();
    let second = types.record_type(node, source, &mut occurrences).clone();
    assert_eq!(first.occurrence, second.occurrence);

    let facts = types.into_facts();
    let rows = occurrences.finish();
    let RustTypeSourceShape::Path { segments, .. } = &first.shape else {
        panic!("outer generic must retain a path shape");
    };
    let arguments = segments[0]
        .generic_arguments
        .as_ref()
        .expect("Option generic arguments");
    assert_eq!(arguments.arguments.len(), 1);
    let nested = facts
        .iter()
        .find(|fact| fact.occurrence == arguments.arguments[0])
        .expect("Box occurrence");
    assert_eq!(
        occurrence_text(source, &rows, nested.occurrence),
        "Box<&Trait>"
    );
    let nested_args = match &nested.shape {
        RustTypeSourceShape::Path { segments, .. } => segments[0]
            .generic_arguments
            .as_ref()
            .expect("Box generic arguments"),
        _ => panic!("Box must retain a path shape"),
    };
    assert_eq!(nested_args.arguments.len(), 1);
    let reference = facts
        .iter()
        .find(|fact| fact.occurrence == nested_args.arguments[0])
        .expect("reference occurrence");
    assert_eq!(reference.wrappers.len(), 1);
    assert_eq!(
        occurrence_text(source, &rows, reference.occurrence),
        "&Trait"
    );
    assert_eq!(facts.len(), 3);
}

#[test]
fn parser_recovery_without_required_compound_fields_retains_missing_shape() {
    for (source, node_kind) in [
        ("fn make() -> impl {}", "abstract_type"),
        ("fn make() -> dyn {}", "dynamic_type"),
    ] {
        let tree = parse_tree(source);
        assert!(tree.root_node().has_error());
        let node = first_named_kind(&tree, node_kind);
        let missing_child = node
            .child_by_field_name("trait")
            .expect("tree-sitter recovery child");
        assert!(missing_child.is_missing());
        let mut occurrences = PrimarySourceFactCollector::new(source);
        let mut types = RustTypeSourceCollector::new();
        let fact = types.record_type(node, source, &mut occurrences).clone();
        let RustTypeSourceShape::Compound {
            kind,
            children,
            type_parameters,
            ..
        } = fact.shape
        else {
            panic!("missing parser field must retain compound recovery shape");
        };
        assert_eq!(
            kind,
            if node_kind == "abstract_type" {
                RustTypeCompoundSourceKind::Abstract
            } else {
                RustTypeCompoundSourceKind::Dynamic
            }
        );
        assert_eq!(children.len(), 1);
        assert!(type_parameters.is_none());
    }
}

#[test]
fn deeply_nested_wrappers_are_collected_iteratively() {
    let source = format!("fn make() -> {}Type {{}}", "&".repeat(2048));
    let (fact, _, _, _) = record_kind(&source, "reference_type");
    assert_eq!(fact.wrappers.len(), 2048);
    assert!(matches!(fact.shape, RustTypeSourceShape::Path { .. }));
}
