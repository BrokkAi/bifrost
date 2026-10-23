use super::{RustTypeSourceCollector, RustTypeSourceShape};
use crate::test_helpers::parse_rust as parse_tree;
use brokk_bifrost_core::analyzer::rust_facts::RustTypeCompoundSourceKind;
use brokk_bifrost_core::analyzer::source_facts::{PrimarySourceFactCollector, SourceFactRows};
use tree_sitter::{Node, Tree};

fn occurrence_text<'source>(
    source: &'source str,
    rows: &SourceFactRows,
    occurrence: brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId,
) -> &'source str {
    let range = rows.occurrence(occurrence).range;
    &source[range.start_byte..range.end_byte]
}

fn first_named_kind<'tree>(tree: &'tree Tree, kind: &str) -> Node<'tree> {
    brokk_bifrost_core::analyzer::tree_walk::first_named_descendant_of_kind_inclusive(
        tree.root_node(),
        kind,
    )
    .unwrap_or_else(|| panic!("missing Rust node kind {kind}"))
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

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#6409: BrokkAi/tree-sitter-rust#3: `..=x` parsed as an assignment to a bare range"
)]
fn inclusive_prefix_range_is_a_call_argument() {
    let source = "fn slice(v: Vec<u8>) { v.get(..=4); }";
    let tree = parse_tree(source);
    assert!(!tree.root_node().has_error());
    let call = first_named_kind(&tree, "call_expression");
    let function = call.child_by_field_name("function").unwrap();
    assert_eq!(function.kind(), "field_expression");
    assert_eq!(
        function.child_by_field_name("value").unwrap().kind(),
        "identifier"
    );
    assert_eq!(
        function.child_by_field_name("field").unwrap().kind(),
        "field_identifier"
    );
    let arguments = call.child_by_field_name("arguments").unwrap();
    assert_eq!(arguments.kind(), "arguments");
    assert_eq!(arguments.named_child_count(), 1);
    let range = arguments.named_child(0).unwrap();
    assert_eq!(range.kind(), "range_expression");
    assert_eq!(&source[range.byte_range()], "..=4");
    assert_eq!(range.child(0).unwrap().kind(), "..=");
    assert_eq!(range.named_child_count(), 1);
    assert_eq!(range.named_child(0).unwrap().kind(), "integer_literal");
    assert!(
        brokk_bifrost_core::analyzer::tree_walk::first_named_descendant_of_kind_inclusive(
            tree.root_node(),
            "assignment_expression",
        )
        .is_none()
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "7d6cc2fc20f8: valid Vector Rust syntax was emitted as ERROR nodes by the grammar"
)]
fn valid_vector_turbofish_and_tuple_higher_ranked_bound_keep_structured_nodes() {
    let turbofish_source = "fn parse(input: &str) { let _ = char::<_, NomErrorType>('#')(input); }";
    let turbofish_tree = parse_tree(turbofish_source);
    assert!(
        !turbofish_tree.root_node().has_error(),
        "valid inferred turbofish syntax must not recover as ERROR nodes"
    );
    let generic_function = first_named_kind(&turbofish_tree, "generic_function");
    let function = generic_function
        .child_by_field_name("function")
        .expect("generic function name");
    assert_eq!(&turbofish_source[function.byte_range()], "char");
    let arguments = generic_function
        .child_by_field_name("type_arguments")
        .expect("generic function type arguments");
    assert_eq!(arguments.child_count(), 5);
    assert_eq!(arguments.child(1).unwrap().kind(), "_");
    assert_eq!(
        &turbofish_source[arguments.child(1).unwrap().byte_range()],
        "_"
    );
    assert_eq!(arguments.child(3).unwrap().kind(), "type_identifier");
    assert_eq!(
        &turbofish_source[arguments.child(3).unwrap().byte_range()],
        "NomErrorType"
    );

    let tuple_source = "fn setup() -> (impl Subscriber + for<'a> LookupSpan<'a>, ()) { todo!() }";
    let tuple_tree = parse_tree(tuple_source);
    assert!(
        !tuple_tree.root_node().has_error(),
        "valid tuple impl Trait HRTB syntax must not recover as ERROR nodes"
    );
    let bounded = first_named_kind(&tuple_tree, "bounded_type");
    assert_eq!(bounded.child_count(), 3);
    assert_eq!(bounded.child(0).unwrap().kind(), "abstract_type");
    let higher_ranked = bounded.child(2).unwrap();
    assert_eq!(higher_ranked.kind(), "higher_ranked_trait_bound");
    let parameters = higher_ranked
        .child_by_field_name("type_parameters")
        .expect("higher-ranked type parameters");
    assert_eq!(&tuple_source[parameters.byte_range()], "<'a>");
    let bound_type = higher_ranked
        .child_by_field_name("type")
        .expect("higher-ranked trait type");
    assert_eq!(bound_type.kind(), "generic_type");
    assert_eq!(&tuple_source[bound_type.byte_range()], "LookupSpan<'a>");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#6393: tree-sitter-rust rejected turbofish type paths such as expr as Box::<dyn T>"
)]
fn turbofish_type_paths_preserve_generic_type_fields() {
    for (source, owner_kind, name_kind, argument_kind) in [
        (
            "fn cast(value: Box<Logger>) { value as Box::<dyn log::Log>; }",
            "type_cast_expression",
            "type_identifier",
            "dynamic_type",
        ),
        (
            "fn local() { let x: a::b::Box::<T> = value; }",
            "let_declaration",
            "scoped_type_identifier",
            "type_identifier",
        ),
        (
            "struct Holder { value: Box::<T> }",
            "field_declaration",
            "type_identifier",
            "type_identifier",
        ),
        (
            "type Nested = Vec::<Box::<T>>;",
            "type_item",
            "type_identifier",
            "generic_type",
        ),
    ] {
        let tree = parse_tree(source);
        assert!(!tree.root_node().has_error(), "{source}");
        let owner = first_named_kind(&tree, owner_kind);
        let generic = owner.child_by_field_name("type").expect("type field");
        assert_eq!(generic.kind(), "generic_type", "{source}");
        let name = generic.child_by_field_name("type").expect("generic name");
        assert_eq!(name.kind(), name_kind, "{source}");
        let arguments = generic
            .child_by_field_name("type_arguments")
            .expect("generic arguments");
        assert_eq!(arguments.kind(), "type_arguments", "{source}");
        let argument = arguments.named_child(0).expect("first type argument");
        assert_eq!(argument.kind(), argument_kind, "{source}");
        if argument_kind == "generic_type" {
            assert_eq!(
                argument.child_by_field_name("type").unwrap().kind(),
                "type_identifier"
            );
            let inner_arguments = argument.child_by_field_name("type_arguments").unwrap();
            assert_eq!(inner_arguments.kind(), "type_arguments");
            assert_eq!(
                inner_arguments.named_child(0).unwrap().kind(),
                "type_identifier"
            );
        }
    }
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
