use super::control::{boolean_literal_condition, counted_for_starts_true};
use super::syntax::{
    body_contains_free_this, callable_field_belongs_to_procedure, class_definition_expressions,
    first_named_child, named_children,
};
use super::values::{
    allocation_alias_use, constant_array_index, plain_member_base_use, stable_member_key,
};
use super::*;
use crate::analyzer::tree_sitter_analyzer::{PreparedSourceOrigin, PreparedSyntaxSource};
use crate::analyzer::{Language, LanguageDialect};
use std::sync::Arc;

fn lower_javascript_source(source: &str) -> ProcedureSemanticsParts {
    lower_javascript_procedure(source, None)
}

fn lower_javascript_procedure(
    source: &str,
    procedure_name: Option<&str>,
) -> ProcedureSemanticsParts {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("JavaScript grammar must load");
    let tree = parser
        .parse(source, None)
        .expect("JavaScript source must parse");
    let prepared = PreparedSyntaxTree::new(
        PreparedSyntaxSource::Exact(Arc::from(source)),
        tree,
        crate::text_utils::compute_line_starts(source),
        LanguageDialect::Standard(Language::JavaScript),
        PreparedSourceOrigin::Disk,
        None,
    );
    let file = ProjectFile::new(std::env::temp_dir(), "semantic-expression-propagation.js");
    let outcome = JsTsSemanticLowerer::javascript()
        .lower(
            &file,
            &prepared,
            &SemanticBudget::default(),
            &CancellationToken::default(),
        )
        .expect("JavaScript semantic lowering must succeed");
    let SemanticOutcome::Complete { value, .. } = outcome else {
        panic!("JavaScript semantic lowering must complete");
    };
    value
        .into_iter()
        .find(|procedure| {
            procedure.kind == ProcedureKind::Function
                && procedure_name.is_none_or(|name| {
                    procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
        })
        .expect("function procedure must be lowered")
}

fn value_for_node(parts: &ProcedureSemanticsParts, node: tree_sitter::Node<'_>) -> ValueId {
    parts
        .values
        .iter()
        .find_map(|value| {
            let mapping = &parts.source_mappings[value.source.index()];
            let span = mapping.locator.anchor().span();
            (span.start_byte() == node.start_byte() as u32
                && span.end_byte() == node.end_byte() as u32)
                .then_some(value.id)
        })
        .unwrap_or_else(|| panic!("semantic value must cover `{}`", node.kind()))
}

fn parse_javascript_source(source: &str) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("JavaScript grammar must load");
    parser
        .parse(source, None)
        .expect("JavaScript source must parse")
}

fn local_value_flows(parts: &ProcedureSemanticsParts) -> Vec<(ValueId, ValueId)> {
    parts
        .points
        .iter()
        .flat_map(|point| point.events.iter())
        .filter_map(|event| match &event.effect {
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Local,
                source,
                target,
            } => Some((*source, *target)),
            _ => None,
        })
        .collect()
}

fn all_value_flows(parts: &ProcedureSemanticsParts) -> Vec<(ValueId, ValueId)> {
    parts
        .points
        .iter()
        .flat_map(|point| point.events.iter())
        .filter_map(|event| match &event.effect {
            SemanticEffect::ValueFlow { source, target, .. } => Some((*source, *target)),
            _ => None,
        })
        .collect()
}

fn value_flow_reaches(flows: &[(ValueId, ValueId)], source: ValueId, target: ValueId) -> bool {
    let mut pending = vec![source];
    let mut visited = Vec::new();
    while let Some(current) = pending.pop() {
        if current == target {
            return true;
        }
        if visited.contains(&current) {
            continue;
        }
        visited.push(current);
        pending.extend(
            flows
                .iter()
                .filter_map(|(from, to)| (*from == current).then_some(*to)),
        );
    }
    false
}

struct FieldMemoryEvents {
    stores: Vec<(MemoryLocationId, ValueId)>,
    loads: Vec<(MemoryLocationId, ValueId)>,
}

fn field_memory_events(parts: &ProcedureSemanticsParts) -> FieldMemoryEvents {
    parts
        .points
        .iter()
        .flat_map(|point| point.events.iter())
        .fold(
            FieldMemoryEvents {
                stores: Vec::new(),
                loads: Vec::new(),
            },
            |mut events, event| {
                match event.effect {
                    SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::Field,
                        location,
                        value,
                    } => events.stores.push((location, value)),
                    SemanticEffect::MemoryLoad {
                        kind: MemoryAccessKind::Field,
                        location,
                        result,
                    } => events.loads.push((location, result)),
                    _ => {}
                }
                events
            },
        )
}

#[test]
fn explicit_throw_flows_payload_to_catch_binder() {
    let source = r#"
        function flow() {
            const payload = 1;
            try {
                throw payload;
            } catch (caught) {
                return caught;
            }
        }
    "#;
    let parts = lower_javascript_source(source);
    let tree = parse_javascript_source(source);
    let throw_statement = first_named_kind(tree.root_node(), "throw_statement");
    let catch_clause = first_named_kind(tree.root_node(), "catch_clause");
    let argument = throw_statement
        .child_by_field_name("argument")
        .or_else(|| first_named_child(throw_statement))
        .expect("throw argument");
    let parameter = catch_clause
        .child_by_field_name("parameter")
        .expect("catch parameter");
    let argument_value = value_for_node(&parts, argument);
    let binder_value = value_for_node(&parts, parameter);
    let flows = local_value_flows(&parts);
    let carrier = flows
        .iter()
        .find_map(|(source, target)| (*source == argument_value).then_some(*target))
        .expect("throw argument must flow into an exception carrier");

    assert!(flows.contains(&(carrier, binder_value)));
    assert!(parts.points.iter().any(|point| {
        point.events.iter().any(|event| {
            matches!(
                event.effect,
                SemanticEffect::Throw {
                    value: Some(value)
                } if value == carrier
            )
        })
    }));
}

#[test]
fn explicit_throw_does_not_flow_unrelated_local_to_catch_binder() {
    let source = r#"
        function flow() {
            const ignored = 1;
            const clean = 2;
            try {
                throw clean;
            } catch (caught) {
                return caught;
            }
        }
    "#;
    let parts = lower_javascript_source(source);
    let tree = parse_javascript_source(source);
    let catch_clause = first_named_kind(tree.root_node(), "catch_clause");
    let parameter = catch_clause
        .child_by_field_name("parameter")
        .expect("catch parameter");
    let declarations = nodes_of_kind(tree.root_node(), "variable_declarator");
    let ignored = declarations
        .iter()
        .find_map(|declaration| {
            let name = declaration.child_by_field_name("name")?;
            (source.get(name.byte_range()) == Some("ignored")).then_some(name)
        })
        .expect("ignored declaration");
    let clean = declarations
        .iter()
        .find_map(|declaration| {
            let name = declaration.child_by_field_name("name")?;
            (source.get(name.byte_range()) == Some("clean")).then_some(name)
        })
        .expect("clean declaration");
    let binder_value = value_for_node(&parts, parameter);
    let ignored_value = value_for_node(&parts, ignored);
    let clean_value = value_for_node(&parts, clean);
    let flows = all_value_flows(&parts);

    assert!(value_flow_reaches(&flows, clean_value, binder_value));
    assert!(!value_flow_reaches(&flows, ignored_value, binder_value));
}

#[test]
fn binderless_catch_routes_control_without_payload_identity() {
    let source = r#"
        function flow() {
            const payload = 1;
            try {
                throw payload;
            } catch {
                return 1;
            }
        }
    "#;
    let parts = lower_javascript_source(source);
    let tree = parse_javascript_source(source);
    let throw_statement = first_named_kind(tree.root_node(), "throw_statement");
    let catch_clause = first_named_kind(tree.root_node(), "catch_clause");
    assert!(catch_clause.child_by_field_name("parameter").is_none());
    let argument = throw_statement
        .child_by_field_name("argument")
        .or_else(|| first_named_child(throw_statement))
        .expect("throw argument");
    let argument_value = value_for_node(&parts, argument);
    let flows = local_value_flows(&parts);
    let carrier = flows
        .iter()
        .find_map(|(source, target)| (*source == argument_value).then_some(*target))
        .expect("throw argument must flow into an exception carrier");

    assert!(!flows.iter().any(|(source, _)| *source == carrier));
}

#[test]
fn destructured_catch_binder_is_explicitly_incomplete() {
    let source = r#"
        function flow(payload) {
            try {
                throw payload;
            } catch ({ value }) {
                return value;
            }
        }
    "#;
    let parts = lower_javascript_source(source);

    assert!(parts.gaps.iter().any(|gap| {
        gap.capability == SemanticCapability::ExceptionalControlFlow
            && gap.kind == SemanticGapKind::Unsupported
            && gap
                .detail
                .contains("catch binders are not yet lowered with payload identity")
    }));
}

#[test]
fn thrown_error_field_reaches_catch_load() {
    let source = r#"
        function flow(source) {
            const payload = new Error("flow");
            payload.value = source;
            try {
                throw payload;
            } catch (caught) {
                return caught.value;
            }
        }
    "#;
    let parts = lower_javascript_source(source);
    let tree = parse_javascript_source(source);
    let function = first_named_kind(tree.root_node(), "function_declaration");
    let parameter = first_named_child(
        function
            .child_by_field_name("parameters")
            .expect("function parameters"),
    )
    .expect("source parameter");
    let assignment = nodes_of_kind(tree.root_node(), "assignment_expression")
        .into_iter()
        .next()
        .expect("field assignment");
    let payload_binding = nodes_of_kind(tree.root_node(), "variable_declarator")
        .into_iter()
        .find_map(|declaration| {
            let name = declaration.child_by_field_name("name")?;
            (source.get(name.byte_range()) == Some("payload")).then_some(name)
        })
        .expect("payload declaration");
    let source_reference = assignment
        .child_by_field_name("right")
        .expect("field assignment value");
    let store_property = assignment
        .child_by_field_name("left")
        .and_then(|left| left.child_by_field_name("property"))
        .expect("field assignment property");
    let throw_statement = first_named_kind(tree.root_node(), "throw_statement");
    let thrown_expression = throw_statement
        .child_by_field_name("argument")
        .or_else(|| first_named_child(throw_statement))
        .expect("throw expression");
    let catch_clause = first_named_kind(tree.root_node(), "catch_clause");
    let binder = catch_clause
        .child_by_field_name("parameter")
        .expect("catch binder");
    let load = nodes_of_kind(tree.root_node(), "member_expression")
        .into_iter()
        .find(|member| {
            member
                .child_by_field_name("object")
                .and_then(|object| source.get(object.byte_range()))
                == Some("caught")
        })
        .expect("caught field load");
    let load_property = load
        .child_by_field_name("property")
        .expect("caught field property");
    let source_value = value_for_node(&parts, parameter);
    let payload_value = value_for_node(&parts, payload_binding);
    let source_reference_value = value_for_node(&parts, source_reference);
    let thrown_value = value_for_node(&parts, thrown_expression);
    let binder_value = value_for_node(&parts, binder);
    let load_value = value_for_node(&parts, load);
    let flows = all_value_flows(&parts);
    let field_events = field_memory_events(&parts);
    assert_eq!(field_events.stores.len(), 1);
    assert_eq!(field_events.loads.len(), 1);
    let (store_location, store_value) = field_events.stores[0];
    let (load_location, load_result) = field_events.loads[0];
    let (store_base, store_member) = match &parts.memory_locations[store_location.index()].kind {
        MemoryLocationKind::Field { base, member } => (*base, member.clone()),
        _ => panic!("field store must use a field location"),
    };
    let (load_base, load_member) = match &parts.memory_locations[load_location.index()].kind {
        MemoryLocationKind::Field { base, member } => (*base, member.clone()),
        _ => panic!("field load must use a field location"),
    };

    assert_eq!(store_value, source_reference_value);
    assert_eq!(load_result, load_value);
    assert!(value_flow_reaches(&flows, payload_value, store_base));
    assert!(value_flow_reaches(&flows, payload_value, thrown_value));
    assert!(value_flow_reaches(&flows, binder_value, load_base));
    assert_eq!(store_member, load_member);
    assert_eq!(
        stable_member_key(source, store_property),
        stable_member_key(source, load_property)
    );
    let carrier = flows
        .iter()
        .find_map(|(source, target)| {
            (*source == thrown_value && *target != binder_value).then_some(*target)
        })
        .expect("thrown payload must flow into an exception carrier");
    assert!(flows.contains(&(thrown_value, carrier)));
    assert!(flows.contains(&(carrier, binder_value)));
    assert!(value_flow_reaches(&flows, source_value, store_value));
    assert!(value_flow_reaches(&flows, thrown_value, binder_value));
    assert!(!parts.gaps.iter().any(|gap| {
        matches!(
            gap.capability,
            SemanticCapability::FieldMemory | SemanticCapability::ExceptionalControlFlow
        )
    }));
}

#[test]
fn thrown_error_clean_field_does_not_reach_from_unrelated_source() {
    let source = r#"
        function flow(source) {
            const ignored = source;
            const payload = new Error("flow");
            payload.value = 0;
            try {
                throw payload;
            } catch (caught) {
                return caught.value;
            }
        }
    "#;
    let parts = lower_javascript_source(source);
    let tree = parse_javascript_source(source);
    let function = first_named_kind(tree.root_node(), "function_declaration");
    let parameter = first_named_child(
        function
            .child_by_field_name("parameters")
            .expect("function parameters"),
    )
    .expect("source parameter");
    let declarations = nodes_of_kind(tree.root_node(), "variable_declarator");
    let ignored = declarations
        .iter()
        .find_map(|declaration| {
            let name = declaration.child_by_field_name("name")?;
            (source.get(name.byte_range()) == Some("ignored")).then_some(name)
        })
        .expect("ignored local");
    let assignment = nodes_of_kind(tree.root_node(), "assignment_expression")
        .into_iter()
        .next()
        .expect("field assignment");
    let clean_value_node = assignment
        .child_by_field_name("right")
        .expect("clean field value");
    let source_value = value_for_node(&parts, parameter);
    let ignored_value = value_for_node(&parts, ignored);
    let clean_value = value_for_node(&parts, clean_value_node);
    let flows = all_value_flows(&parts);
    let field_events = field_memory_events(&parts);
    assert_eq!(field_events.stores.len(), 1);
    assert_eq!(field_events.loads.len(), 1);
    assert!(value_flow_reaches(&flows, source_value, ignored_value));
    assert!(!value_flow_reaches(&flows, source_value, clean_value));
    assert!(!parts.gaps.iter().any(|gap| {
        matches!(
            gap.capability,
            SemanticCapability::FieldMemory | SemanticCapability::ExceptionalControlFlow
        )
    }));
}

#[test]
fn thrown_error_field_with_local_calls_remains_complete() {
    let source = r#"
        function source() {
            return 1;
        }
        function sink(value) {}
        function flow() {
            try {
                const payload = new Error("flow");
                payload.value = source();
                throw payload;
            } catch (caught) {
                sink(caught.value);
            }
        }
    "#;
    let parts = lower_javascript_procedure(source, Some("flow"));
    let tree = parse_javascript_source(source);
    let assignment = nodes_of_kind(tree.root_node(), "assignment_expression")
        .into_iter()
        .next()
        .expect("field assignment");
    let payload_binding = nodes_of_kind(tree.root_node(), "variable_declarator")
        .into_iter()
        .find_map(|declaration| {
            let name = declaration.child_by_field_name("name")?;
            (source.get(name.byte_range()) == Some("payload")).then_some(name)
        })
        .expect("payload declaration");
    let source_call = assignment
        .child_by_field_name("right")
        .expect("source call");
    let store_property = assignment
        .child_by_field_name("left")
        .and_then(|left| left.child_by_field_name("property"))
        .expect("field assignment property");
    let throw_statement = first_named_kind(tree.root_node(), "throw_statement");
    let thrown_expression = throw_statement
        .child_by_field_name("argument")
        .or_else(|| first_named_child(throw_statement))
        .expect("throw expression");
    let catch_clause = first_named_kind(tree.root_node(), "catch_clause");
    let binder = catch_clause
        .child_by_field_name("parameter")
        .expect("catch binder");
    let load = nodes_of_kind(tree.root_node(), "member_expression")
        .into_iter()
        .find(|member| {
            member
                .child_by_field_name("object")
                .and_then(|object| source.get(object.byte_range()))
                == Some("caught")
        })
        .expect("caught field load");
    let load_property = load
        .child_by_field_name("property")
        .expect("caught field property");
    let payload_value = value_for_node(&parts, payload_binding);
    let source_call_value = value_for_node(&parts, source_call);
    let thrown_value = value_for_node(&parts, thrown_expression);
    let binder_value = value_for_node(&parts, binder);
    let load_value = value_for_node(&parts, load);
    let flows = all_value_flows(&parts);
    let field_events = field_memory_events(&parts);
    assert_eq!(field_events.stores.len(), 1);
    assert_eq!(field_events.loads.len(), 1);
    let (store_location, store_value) = field_events.stores[0];
    let (load_location, load_result) = field_events.loads[0];
    let (store_base, store_member) = match &parts.memory_locations[store_location.index()].kind {
        MemoryLocationKind::Field { base, member } => (*base, member.clone()),
        _ => panic!("field store must use a field location"),
    };
    let (load_base, load_member) = match &parts.memory_locations[load_location.index()].kind {
        MemoryLocationKind::Field { base, member } => (*base, member.clone()),
        _ => panic!("field load must use a field location"),
    };

    assert_eq!(store_value, source_call_value);
    assert_eq!(load_result, load_value);
    assert!(value_flow_reaches(&flows, payload_value, store_base));
    assert!(value_flow_reaches(&flows, payload_value, thrown_value));
    assert!(value_flow_reaches(&flows, binder_value, load_base));
    assert_eq!(store_member, load_member);
    assert_eq!(
        stable_member_key(source, store_property),
        stable_member_key(source, load_property)
    );
    let carrier = flows
        .iter()
        .find_map(|(source, target)| {
            (*source == thrown_value && *target != binder_value).then_some(*target)
        })
        .expect("thrown payload must flow into an exception carrier");
    assert!(flows.contains(&(thrown_value, carrier)));
    assert!(flows.contains(&(carrier, binder_value)));
    assert!(!parts.gaps.iter().any(|gap| {
        matches!(
            gap.capability,
            SemanticCapability::FieldMemory | SemanticCapability::ExceptionalControlFlow
        )
    }));
}

#[test]
fn dynamic_error_constructor_argument_keeps_field_identity_incomplete() {
    let source = r#"
        function flow(source) {
            const payload = new Error(source());
            payload.value = source;
            try {
                throw payload;
            } catch (caught) {
                return caught.value;
            }
        }
    "#;
    let parts = lower_javascript_source(source);

    assert!(parts.gaps.iter().any(|gap| {
        gap.capability == SemanticCapability::FieldMemory
            && gap.kind == SemanticGapKind::Unknown
            && gap
                .detail
                .contains("field occurrence is structured, but its declaration identity")
    }));
}

#[test]
fn shadowed_error_constructor_keeps_field_identity_incomplete() {
    let source = r#"
        function flow(source) {
            const Error = factory;
            const payload = new Error("flow");
            payload.value = source;
            try {
                throw payload;
            } catch (caught) {
                return caught.value;
            }
        }
    "#;
    let parts = lower_javascript_source(source);

    assert!(parts.gaps.iter().any(|gap| {
        gap.capability == SemanticCapability::FieldMemory
            && gap.kind == SemanticGapKind::Unknown
            && gap
                .detail
                .contains("field occurrence is structured, but its declaration identity")
    }));
}

#[test]
fn dynamic_error_field_access_remains_incomplete() {
    let source = r#"
        function flow(source, key) {
            const payload = new Error("flow");
            payload[key] = source;
            try {
                throw payload;
            } catch (caught) {
                return caught[key];
            }
        }
    "#;
    let parts = lower_javascript_source(source);

    assert!(parts.gaps.iter().any(|gap| {
        gap.capability == SemanticCapability::IndexMemory
            && gap.kind == SemanticGapKind::Unknown
            && gap.detail.contains("array index is structured")
    }));
}

#[test]
fn parenthesized_expression_preserves_value_identity_without_targeting_unrelated_literal() {
    let source = r#"
        function compute(value) {
            const computed = (value * 3) + 7;
            const unrelated = 7;
            return computed;
        }
    "#;
    let parts = lower_javascript_source(source);

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("JavaScript grammar must load");
    let tree = parser
        .parse(source, None)
        .expect("JavaScript source must parse");
    let function = named_children(tree.root_node())
        .into_iter()
        .find(|node| node.kind() == "function_declaration")
        .expect("function declaration must be present");
    let body = function
        .child_by_field_name("body")
        .expect("function must have a body");
    let declarations = named_children(body)
        .into_iter()
        .filter(|node| node.kind() == "lexical_declaration")
        .flat_map(named_children)
        .filter(|node| node.kind() == "variable_declarator")
        .collect::<Vec<_>>();
    let computed = declarations
        .first()
        .copied()
        .expect("computed declaration must be present");
    let unrelated = declarations
        .get(1)
        .copied()
        .expect("unrelated declaration must be present");
    let outer = computed
        .child_by_field_name("value")
        .expect("computed declaration must have a value");
    let parenthesized = outer
        .child_by_field_name("left")
        .expect("outer arithmetic must have a left operand");
    let inner = parenthesized
        .child_by_field_name("expression")
        .or_else(|| first_named_child(parenthesized))
        .expect("parenthesized expression must have an inner expression");
    let source_operand = inner
        .child_by_field_name("left")
        .expect("inner arithmetic must have a left operand");
    let unrelated_literal = unrelated
        .child_by_field_name("value")
        .expect("unrelated declaration must have a value");
    assert_eq!(outer.kind(), "binary_expression");
    assert_eq!(parenthesized.kind(), "parenthesized_expression");
    assert_eq!(inner.kind(), "binary_expression");
    let inner_value = value_for_node(&parts, inner);
    let parenthesized_value = value_for_node(&parts, parenthesized);
    let outer_value = value_for_node(&parts, outer);
    let source_value = value_for_node(&parts, source_operand);
    let unrelated_value = value_for_node(&parts, unrelated_literal);

    let flows = parts.points.iter().flat_map(|point| {
        point.events.iter().filter_map(|event| match &event.effect {
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Local,
                source,
                target,
            } => Some((ValueFlowKind::Local, *source, *target)),
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::LanguageDefined,
                source,
                target,
            } => Some((ValueFlowKind::LanguageDefined, *source, *target)),
            _ => None,
        })
    });
    let flows = flows.collect::<Vec<_>>();
    assert!(flows.contains(&(ValueFlowKind::LanguageDefined, source_value, inner_value)));
    assert!(flows.contains(&(ValueFlowKind::Local, inner_value, parenthesized_value)));
    assert!(flows.contains(&(
        ValueFlowKind::LanguageDefined,
        parenthesized_value,
        outer_value,
    )));
    assert!(
        !flows
            .iter()
            .any(|(_, _, target)| *target == unrelated_value)
    );
}

fn first_named_kind<'tree>(root: Node<'tree>, kind: &str) -> Node<'tree> {
    let mut found = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(root, true, |node| {
        if node.kind() == kind {
            found = Some(node);
            WalkControl::Break
        } else {
            WalkControl::Continue
        }
    });
    found.expect("expected syntax node")
}

fn counted_loop_starts_true(source: &str) -> bool {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("JavaScript grammar must load");
    let tree = parser
        .parse(source, None)
        .expect("JavaScript source must parse");
    let loop_node = first_named_kind(tree.root_node(), "for_statement");
    counted_for_starts_true(
        source,
        loop_node.child_by_field_name("initializer"),
        loop_node
            .child_by_field_name("condition")
            .expect("counted loop condition"),
        loop_node
            .child_by_field_name("increment")
            .expect("counted loop increment"),
    )
}

fn boolean_condition_value(source: &str) -> Option<bool> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("JavaScript grammar must load");
    let tree = parser
        .parse(source, None)
        .expect("JavaScript source must parse");
    let mut literal = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
        tree.root_node(),
        true,
        |node| {
            if matches!(node.kind(), "true" | "false") {
                literal = Some(node);
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        },
    );
    literal.and_then(boolean_literal_condition)
}

#[test]
fn boolean_literal_conditions_have_one_feasible_edge() {
    assert_eq!(boolean_condition_value("if (true) {}"), Some(true));
    assert_eq!(boolean_condition_value("if (false) {}"), Some(false));
}

#[test]
fn counted_for_first_iteration_requires_numeric_static_shape() {
    assert!(counted_loop_starts_true(
        "for (let iteration = 0; iteration < 3; iteration++) {}"
    ));
    assert!(!counted_loop_starts_true(
        "for (let iteration = 0; iteration < limit; iteration++) {}"
    ));
}

fn nodes_of_kind<'tree>(root: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut nodes = Vec::new();
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(root, true, |node| {
        if node.kind() == kind {
            nodes.push(node);
        }
        WalkControl::Continue
    });
    nodes
}

#[test]
fn free_this_scan_honors_cancellation() {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .expect("TypeScript grammar must load");
    let tree = parser
        .parse(
            "function value() { const first = 1; const second = 2; return this; }",
            None,
        )
        .expect("TypeScript source must parse");
    let mut body = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
        tree.root_node(),
        true,
        |node| {
            if node.kind() == "statement_block" {
                body = Some(node);
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        },
    );

    let cancellation = CancellationToken::cancel_after_checks_for_test(2);
    assert_eq!(
        body_contains_free_this(body.expect("function body"), &cancellation),
        Err(LoweringCancelled)
    );
}

#[test]
fn class_definition_expression_collection_honors_cancellation() {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .expect("TypeScript grammar must load");
    let tree = parser
        .parse(
            r#"
                class Nested extends base() {
                    [first()] = value();
                    [second()]() {}
                }
            "#,
            None,
        )
        .expect("TypeScript source must parse");
    let mut class = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
        tree.root_node(),
        true,
        |node| {
            if node.kind() == "class_declaration" {
                class = Some(node);
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        },
    );

    let cancellation = CancellationToken::cancel_after_checks_for_test(2);
    assert_eq!(
        class_definition_expressions(class.expect("class declaration"), &cancellation),
        Err(LoweringCancelled)
    );
}

#[test]
fn class_definition_collection_excludes_erased_typescript_members() {
    let source = r#"
        abstract class Nested implements Marker {
            declare [declaredKey]: string;
            abstract [abstractKey]: string;
            @decorate
            [runtimeField] = value;
            [runtimeMethod]() {}
            [overload](value: string): void;
            [overload](value: unknown) {}
        }
    "#;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .expect("TypeScript grammar must load");
    let tree = parser
        .parse(source, None)
        .expect("TypeScript source must parse");
    let mut class = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
        tree.root_node(),
        true,
        |node| {
            if node.kind() == "abstract_class_declaration" {
                class = Some(node);
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        },
    );

    let evaluation = class_definition_expressions(
        class.expect("abstract class declaration"),
        &CancellationToken::default(),
    )
    .expect("class definition collection must succeed");
    let expressions = evaluation
        .expressions
        .iter()
        .map(|node| &source[node.byte_range()])
        .collect::<Vec<_>>();

    assert!(evaluation.has_decorators);
    assert_eq!(
        expressions,
        vec!["[runtimeField]", "[runtimeMethod]", "[overload]",]
    );
}

#[test]
fn method_decorators_stay_in_the_class_definition_context() {
    let source = r#"
        class Nested {
            @decorate(() => this)
            method() {}
        }
    "#;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("JavaScript grammar must load");
    let tree = parser
        .parse(source, None)
        .expect("JavaScript source must parse");
    let mut method = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
        tree.root_node(),
        true,
        |node| {
            if node.kind() == "method_definition" {
                method = Some(node);
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        },
    );
    let method = method.expect("method definition");
    assert!(!callable_field_belongs_to_procedure(
        method.kind(),
        Some("decorator")
    ));
}

#[test]
fn numeric_index_tokens_reuse_equal_tokens_and_separate_different_tokens() {
    let source = r#"
        const values = [0, "0"];
        values[0];
        values[0];
        values[1];
        values["0"];
    "#;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("JavaScript grammar must load");
    let tree = parser
        .parse(source, None)
        .expect("JavaScript source must parse");
    let indices = nodes_of_kind(tree.root_node(), "number")
        .into_iter()
        .chain(nodes_of_kind(tree.root_node(), "string"))
        .filter(|node| {
            node.parent()
                .is_some_and(|parent| parent.kind() == "subscript_expression")
        })
        .collect::<Vec<_>>();
    assert_eq!(indices.len(), 4);

    let numeric_first = stable_member_key(source, indices[0]).expect("numeric index key");
    let numeric_second = stable_member_key(source, indices[1]).expect("numeric index key");
    let numeric_other = stable_member_key(source, indices[2]).expect("numeric index key");
    let string_index = stable_member_key(source, indices[3]);
    assert_eq!(numeric_first, numeric_second);
    assert_ne!(numeric_first, numeric_other);
    assert!(string_index.is_none());
}

#[test]
fn plain_object_field_keys_share_only_allowed_member_bases() {
    let source = r#"
        const original = { value: 0 };
        original.value;
        original.__proto__;
        original.method();
    "#;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("JavaScript grammar must load");
    let tree = parser
        .parse(source, None)
        .expect("JavaScript source must parse");
    let members = nodes_of_kind(tree.root_node(), "member_expression");
    let member = |property: &str| {
        let key = format!("property_identifier:{property}").into_boxed_str();
        members
            .iter()
            .find(|node| {
                node.child_by_field_name("property")
                    .and_then(|property_node| stable_member_key(source, property_node))
                    .is_some_and(|actual| actual == key)
            })
            .copied()
            .expect("member expression in fixture")
    };

    let value_member = member("value");
    let value_property = value_member
        .child_by_field_name("property")
        .expect("value property");
    assert_eq!(
        stable_member_key(source, value_property).as_deref(),
        Some("property_identifier:value")
    );
    assert!(plain_member_base_use(
        source,
        value_member
            .child_by_field_name("object")
            .expect("value object")
    ));

    let proto_member = member("__proto__");
    assert!(!plain_member_base_use(
        source,
        proto_member
            .child_by_field_name("object")
            .expect("proto object")
    ));

    let call_member = member("method");
    assert!(!plain_member_base_use(
        source,
        call_member
            .child_by_field_name("object")
            .expect("call object")
    ));
}

#[test]
fn direct_alias_assignment_is_structurally_identifiable() {
    let source = "const original = {}; const alias = original;";
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("JavaScript grammar must load");
    let tree = parser
        .parse(source, None)
        .expect("JavaScript source must parse");
    let alias_value = nodes_of_kind(tree.root_node(), "identifier")
        .into_iter()
        .find(|node| {
            node.parent().is_some_and(|parent| {
                parent.kind() == "variable_declarator"
                    && parent
                        .child_by_field_name("value")
                        .is_some_and(|value| value.id() == node.id())
            })
        })
        .expect("alias right-hand side");
    let (target, value) = allocation_alias_use(alias_value).expect("direct alias assignment");
    assert_eq!(source.get(target.byte_range()), Some("alias"));
    assert_eq!(source.get(value.byte_range()), Some("original"));
}

#[test]
fn array_index_keys_normalize_decimal_integer_tokens_only() {
    let source = r#"
        const values = [0];
        values[0];
        values[00];
        values[1];
        values[1.0];
        values["0"];
    "#;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("JavaScript grammar must load");
    let tree = parser
        .parse(source, None)
        .expect("JavaScript source must parse");
    let indices = nodes_of_kind(tree.root_node(), "number")
        .into_iter()
        .filter(|node| {
            node.parent()
                .is_some_and(|parent| parent.kind() == "subscript_expression")
        })
        .collect::<Vec<_>>();
    assert_eq!(indices.len(), 4);
    assert_eq!(constant_array_index(source, indices[0]), Some(0));
    assert_eq!(constant_array_index(source, indices[1]), Some(0));
    assert_eq!(constant_array_index(source, indices[2]), Some(1));
    assert_eq!(constant_array_index(source, indices[3]), None);
    assert_eq!(
        stable_member_key(source, indices[0]).as_deref(),
        Some("number:0")
    );
    assert_eq!(
        stable_member_key(source, indices[1]).as_deref(),
        Some("number:0")
    );
}
