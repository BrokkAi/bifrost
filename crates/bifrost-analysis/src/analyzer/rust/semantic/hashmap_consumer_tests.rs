use super::*;
use crate::analyzer::semantic_model::csmi::{
    CsmiInputLocation, CsmiInputParameterRoot, CsmiInputPhase, CsmiInputReceiverRoot,
    CsmiOutputLocation, CsmiOutputPhase, CsmiOutputReceiverRoot, CsmiOutputResultRoot,
    CsmiParameterRootRole, CsmiProjectionStep, CsmiReceiverRootRole, CsmiResultRootRole,
};

fn entry_projection(
    selector_kind: &str,
    selector_position: u64,
    component: &str,
) -> CsmiProjection {
    CsmiProjection {
        scheme: "csmi.collection-flow.entry".into(),
        scheme_version: "0.1".into(),
        steps: vec![
            CsmiProjectionStep {
                kind: "entry".into(),
                args: Some(serde_json::json!({
                    "key": { "kind": selector_kind, "position": selector_position }
                })),
            },
            CsmiProjectionStep {
                kind: component.into(),
                args: None,
            },
        ],
    }
}

#[test]
fn entry_component_projection_accepts_the_producer_shape() {
    let projection = entry_projection("parameter", 0, "entry-value");
    assert!(projection_is_entry_component(
        Some(&projection),
        "parameter",
        0,
        "entry-value"
    ));
}

#[test]
fn entry_component_projection_declines_mismatched_selectors() {
    let projection = entry_projection("parameter", 0, "entry-value");
    assert!(!projection_is_entry_component(
        Some(&projection),
        "parameter",
        1,
        "entry-value"
    ));
    assert!(!projection_is_entry_component(
        Some(&projection),
        "key",
        0,
        "entry-value"
    ));
    assert!(!projection_is_entry_component(
        Some(&projection),
        "parameter",
        0,
        "entry-key"
    ));
    assert!(!projection_is_entry_component(
        None,
        "parameter",
        0,
        "entry-value"
    ));
}

fn receiver_input() -> CsmiInputLocation {
    CsmiInputLocation {
        root: CsmiInputBoundaryRoot::Receiver(CsmiInputReceiverRoot {
            phase: CsmiInputPhase::Input,
            role: CsmiReceiverRootRole::Receiver,
        }),
        projection: Some(entry_projection("parameter", 0, "entry-value")),
    }
}

fn result_output() -> CsmiOutputLocation {
    CsmiOutputLocation {
        root: CsmiOutputBoundaryRoot::Result(CsmiOutputResultRoot {
            phase: CsmiOutputPhase::Output,
            role: CsmiResultRootRole::Result,
            position: 0,
        }),
        projection: None,
    }
}

#[test]
fn keyed_entry_read_transfer_names_the_modeled_lookup() {
    let transfer = CsmiCollectionFlowTransfer {
        source: receiver_input(),
        destination: result_output(),
    };
    assert!(transfer_reads_keyed_entry_value_to_result(&transfer));
}

#[test]
fn keyed_entry_read_transfer_declines_unproven_shapes() {
    let mut projectionless_source = receiver_input();
    projectionless_source.projection = None;
    assert!(!transfer_reads_keyed_entry_value_to_result(
        &CsmiCollectionFlowTransfer {
            source: projectionless_source,
            destination: result_output(),
        }
    ));

    let mut projected_destination = result_output();
    projected_destination.projection = Some(entry_projection("parameter", 0, "entry-value"));
    assert!(!transfer_reads_keyed_entry_value_to_result(
        &CsmiCollectionFlowTransfer {
            source: receiver_input(),
            destination: projected_destination,
        }
    ));

    assert!(!transfer_reads_keyed_entry_value_to_result(
        &CsmiCollectionFlowTransfer {
            source: CsmiInputLocation {
                root: CsmiInputBoundaryRoot::Parameter(CsmiInputParameterRoot {
                    phase: CsmiInputPhase::Input,
                    role: CsmiParameterRootRole::Parameter,
                    position: 0,
                }),
                projection: Some(entry_projection("parameter", 0, "entry-value")),
            },
            destination: result_output(),
        }
    ));

    assert!(!transfer_reads_keyed_entry_value_to_result(
        &CsmiCollectionFlowTransfer {
            source: receiver_input(),
            destination: CsmiOutputLocation {
                root: CsmiOutputBoundaryRoot::Receiver(CsmiOutputReceiverRoot {
                    phase: CsmiOutputPhase::Output,
                    role: CsmiReceiverRootRole::Receiver,
                }),
                projection: None,
            },
        }
    ));
}

fn assert_use_bindings(source: &str, expected: Option<&[(&str, &[&str])]>) {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("the rust grammar loads");
    let tree = parser.parse(source, None).expect("rust source parses");
    let root = tree.root_node();
    let mut cursor = root.walk();
    let clause = root
        .children(&mut cursor)
        .find(|node| node.kind() == "use_declaration")
        .and_then(|declaration| declaration.named_child(0))
        .expect("one top-level use clause");
    let bindings = rust_use_clause_bindings(clause, source);
    let Some(expected) = expected else {
        assert!(bindings.is_none(), "unexpected bindings: {bindings:?}");
        return;
    };
    let bindings = bindings.expect("structured use bindings");
    assert_eq!(bindings.len(), expected.len(), "binding count for {source}");
    for ((terminal, segments), (expected_terminal, expected_segments)) in
        bindings.iter().zip(expected)
    {
        assert_eq!(
            terminal.as_ref(),
            *expected_terminal,
            "terminal for {source}"
        );
        let rendered = segments
            .iter()
            .map(|segment| segment.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(rendered.as_slice(), *expected_segments, "path for {source}");
    }
}

#[test]
fn use_bindings_cover_qualified_grouped_and_keyword_paths() {
    assert_use_bindings(
        "use std::collections::HashMap;\n",
        Some(&[("HashMap", &["std", "collections", "HashMap"])]),
    );
    assert_use_bindings(
        "use std::collections::{HashMap, BTreeMap};\n",
        Some(&[
            ("HashMap", &["std", "collections", "HashMap"]),
            ("BTreeMap", &["std", "collections", "BTreeMap"]),
        ]),
    );
    assert_use_bindings(
        "use a::{b::{C, D}, E};\n",
        Some(&[
            ("C", &["a", "b", "C"]),
            ("D", &["a", "b", "D"]),
            ("E", &["a", "E"]),
        ]),
    );
    assert_use_bindings(
        "use crate::collections::HashMap;\n",
        Some(&[("HashMap", &["crate", "collections", "HashMap"])]),
    );
}

#[test]
fn use_bindings_decline_unmodeled_clause_shapes() {
    assert_use_bindings("use x::Y as Z;\n", None);
    assert_use_bindings("use a::*;\n", None);
    assert_use_bindings("use std::collections::*;\n", None);
}

fn store_transfer(
    source_position: u32,
    source_projection: Option<CsmiProjection>,
    destination_projection: Option<CsmiProjection>,
) -> CsmiCollectionFlowTransfer {
    CsmiCollectionFlowTransfer {
        source: CsmiInputLocation {
            root: CsmiInputBoundaryRoot::Parameter(CsmiInputParameterRoot {
                phase: CsmiInputPhase::Input,
                role: CsmiParameterRootRole::Parameter,
                position: source_position,
            }),
            projection: source_projection,
        },
        destination: CsmiOutputLocation {
            root: CsmiOutputBoundaryRoot::Receiver(CsmiOutputReceiverRoot {
                phase: CsmiOutputPhase::Output,
                role: CsmiReceiverRootRole::Receiver,
            }),
            projection: destination_projection,
        },
    }
}

/// The exact transfer shape the rustdoc producer emits for
/// `HashMap::insert`: the stored value is parameter 1, whole, into the
/// receiver's entry value under the key parameter 0 names. No
/// receiver-to-result transfer exists on the producer side, and the
/// consumer must accept this shape alone.
#[test]
fn insert_store_transfer_accepts_the_producer_shape() {
    let transfer = store_transfer(
        1,
        None,
        Some(entry_projection("parameter", 0, "entry-value")),
    );
    assert!(transfer_stores_parameter_value_into_receiver(&transfer));
}

#[test]
fn insert_store_transfer_declines_unproven_shapes() {
    assert!(!transfer_stores_parameter_value_into_receiver(
        &store_transfer(
            0,
            None,
            Some(entry_projection("parameter", 0, "entry-value")),
        )
    ));
    assert!(!transfer_stores_parameter_value_into_receiver(
        &store_transfer(
            1,
            Some(entry_projection("parameter", 0, "entry-value")),
            Some(entry_projection("parameter", 0, "entry-value")),
        )
    ));
    assert!(!transfer_stores_parameter_value_into_receiver(
        &store_transfer(1, None, None,)
    ));
    assert!(!transfer_stores_parameter_value_into_receiver(
        &store_transfer(1, None, Some(entry_projection("parameter", 0, "entry-key")),)
    ));
}

fn first_node_of_kind<'tree>(root: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    None
}

fn assert_keyed_place_node(source: &str, expected_kind: &str) {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("the rust grammar loads");
    let tree = parser.parse(source, None).expect("rust source parses");
    let expression = first_node_of_kind(tree.root_node(), "reference_expression")
        .or_else(|| first_node_of_kind(tree.root_node(), "call_expression"))
        .expect("a keyed argument expression");
    let place = rust_keyed_place_node(expression).expect("a place candidate");
    assert_eq!(place.kind(), expected_kind, "place node for {source}");
}

/// `key` and `&key` name the same key value through the language's own
/// borrow and parentheses; a clone is a fresh value and names nothing its
/// source names.
#[test]
fn keyed_place_nodes_unwrap_borrows_and_parentheses() {
    assert_keyed_place_node("fn f(key: String) { let _ = &key; }\n", "identifier");
    assert_keyed_place_node("fn f(key: String) { let _ = &(key); }\n", "identifier");
    assert_keyed_place_node("fn f(key: String) { let _ = &(&(key)); }\n", "identifier");
    assert_keyed_place_node(
        "fn f(key: String) { let _ = key.clone(); }\n",
        "call_expression",
    );
}
