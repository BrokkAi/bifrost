//! Query-time facts for attributes initialized on a Python superclass that
//! hide methods declared by a descendant.

use super::python_rule_facts::{
    call_name, contains_alias, direct_identifier, in_control_branch, make_row, named_children,
    node_text, parameter_name, parse_python, python_class_node_for_unit,
    python_definition_decorators, row_range, scope_nodes,
};
use super::*;
use crate::analyzer::usages::python_class_hierarchy::PythonHierarchyOutcome;
use tree_sitter::Node;

const RELATION: &str = "attribute_shadows_method";
const REASON: &str = "python_attribute_shadows_method_incomplete";

struct InitializerWrite {
    name: String,
    line: usize,
}

struct InitializerAnalysis {
    writes: Vec<InitializerWrite>,
    open_reason: Option<&'static str>,
}

pub(super) fn expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    cancellation: Option<&CancellationToken>,
) -> Vec<PipelineExpansion> {
    let unit = &declaration.unit;
    if crate::analyzer::common::language_for_file(unit.source())
        != crate::analyzer::Language::Python
        || !unit.is_class()
    {
        return Vec::new();
    }

    let file = unit.source();
    let Some(source) = analyzer.get_source(&CodeUnit::file_scope(file.clone()), false) else {
        return vec![open_fact(file, declaration, None, "source_unavailable")];
    };
    let Some(tree) = parse_python(&source) else {
        return vec![open_fact(
            file,
            declaration,
            Some(&source),
            "syntax_unavailable",
        )];
    };
    if tree.root_node().has_error() {
        return vec![open_fact(
            file,
            declaration,
            Some(&source),
            "recovered_python_syntax",
        )];
    }
    let Some(class_node) = python_class_node_for_unit(analyzer, unit, &tree) else {
        return vec![open_fact(
            file,
            declaration,
            Some(&source),
            "class_range_unavailable",
        )];
    };

    let mut eligible = Vec::new();
    for definition in direct_class_methods(class_node) {
        let Some(name_node) = definition.child_by_field_name("name") else {
            continue;
        };
        let Some(name) = node_text(&source, name_node).map(str::to_owned) else {
            continue;
        };
        let setter = is_setter(definition, &source);
        let property = brokk_bifrost_python::declarations::python_function_has_decorator(
            definition, &source, "property",
        );
        let settable = property && has_same_scope_setter(class_node, &source, &name);
        if setter || settable {
            continue;
        }
        eligible.push((name_node, name));
    }
    if eligible.is_empty() {
        return Vec::new();
    }

    let Some(provider) = analyzer.python_class_hierarchy_provider_for(unit) else {
        return vec![open_fact(
            file,
            declaration,
            Some(&source),
            "hierarchy_provider_unavailable",
        )];
    };
    let hierarchy = provider.class_hierarchy(unit, cancellation);
    if hierarchy.outcome != PythonHierarchyOutcome::Complete {
        return vec![open_fact(
            file,
            declaration,
            Some(&source),
            match hierarchy.outcome {
                PythonHierarchyOutcome::Inconsistent => "inconsistent_hierarchy",
                PythonHierarchyOutcome::Incomplete => "unknown_base_or_incomplete_hierarchy",
                PythonHierarchyOutcome::Unsupported => "unsupported_hierarchy",
                PythonHierarchyOutcome::Complete => unreachable!(),
            },
        )];
    }

    let mut expansions = Vec::new();
    let mut emitted = HashSet::default();
    for ancestor in hierarchy.mro.iter().skip(1) {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            expansions.push(open_fact(file, declaration, Some(&source), "cancelled"));
            break;
        }
        let Some(ancestor_source) =
            analyzer.get_source(&CodeUnit::file_scope(ancestor.source().clone()), false)
        else {
            expansions.push(open_fact(
                file,
                declaration,
                Some(&source),
                "initializer_source_unavailable",
            ));
            continue;
        };
        let Some(ancestor_tree) = parse_python(&ancestor_source) else {
            expansions.push(open_fact(
                file,
                declaration,
                Some(&source),
                "initializer_syntax_unavailable",
            ));
            continue;
        };
        if ancestor_tree.root_node().has_error() {
            expansions.push(open_fact(
                file,
                declaration,
                Some(&source),
                "initializer_recovered_syntax",
            ));
            continue;
        }
        let Some(ancestor_class) = python_class_node_for_unit(analyzer, ancestor, &ancestor_tree)
        else {
            expansions.push(open_fact(
                file,
                declaration,
                Some(&source),
                "ancestor_class_range_unavailable",
            ));
            continue;
        };
        let ancestor_methods = direct_class_methods(ancestor_class);
        let shadowable = eligible
            .iter()
            .filter(|(_, name)| {
                !ancestor_methods.iter().any(|method| {
                    method
                        .child_by_field_name("name")
                        .and_then(|name_node| node_text(&ancestor_source, name_node))
                        == Some(name.as_str())
                })
            })
            .collect::<Vec<_>>();
        if shadowable.is_empty() {
            continue;
        }
        let Some(initializer_node) = ancestor_methods
            .into_iter()
            .filter(|method| {
                method
                    .child_by_field_name("name")
                    .and_then(|name_node| node_text(&ancestor_source, name_node))
                    == Some("__init__")
            })
            .max_by_key(|method| method.start_byte())
        else {
            continue;
        };
        if initializer_node.kind() != "function_definition" {
            expansions.push(open_fact(
                file,
                declaration,
                Some(&source),
                "initializer_definition_unavailable",
            ));
            continue;
        }

        let analysis = initializer_writes(initializer_node, &ancestor_source);
        if let Some(reason) = analysis.open_reason {
            expansions.push(open_fact(file, declaration, Some(&source), reason));
        }
        for write in &analysis.writes {
            for (method_name, name) in &shadowable {
                if *name != write.name {
                    continue;
                }
                let method_range = method_name.start_byte()..method_name.end_byte();
                let fact = make_row(
                    RELATION,
                    file,
                    method_range.clone(),
                    row_range(&source, method_range.clone()),
                    Some(declaration.declaration_id().to_string()),
                    "issue",
                    "proven",
                    true,
                    Some(format!(
                        "initializer attribute write at {}:{}",
                        rel_path_string(ancestor.source()),
                        write.line
                    )),
                );
                if emitted.insert(fact.row.id.clone()) {
                    let mut fact = fact;
                    fact.row.target_id = Some(ancestor.declaration_id().to_string());
                    expansions.push(pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(
                        fact,
                    ))));
                }
            }
        }
    }

    expansions
}

fn direct_class_methods(class: Node<'_>) -> Vec<Node<'_>> {
    let Some(body) = class.child_by_field_name("body") else {
        return Vec::new();
    };
    named_children(body)
        .into_iter()
        .filter_map(|member| match member.kind() {
            "function_definition" => Some(member),
            "decorated_definition" => named_children(member)
                .into_iter()
                .find(|child| child.kind() == "function_definition"),
            _ => None,
        })
        .collect()
}

fn open_fact(
    file: &ProjectFile,
    declaration: &DeclarationValue,
    source: Option<&str>,
    detail: &'static str,
) -> PipelineExpansion {
    let anchor = declaration.range.start_byte..declaration.range.end_byte;
    let range = source.map_or_else(
        || row_range("", 0..0),
        |source| row_range(source, anchor.clone()),
    );
    let fact = make_row(
        RELATION,
        file,
        anchor,
        range,
        Some(declaration.declaration_id().to_string()),
        "open",
        "none",
        false,
        Some(format!("{REASON}: {detail}")),
    );
    pipeline_expansion(PipelineValue::PythonRuleFact(Box::new(fact)))
}

fn is_setter(definition: Node<'_>, source: &str) -> bool {
    python_definition_decorators(definition)
        .into_iter()
        .filter_map(|decorator| named_children(decorator).into_iter().next())
        .any(|expression| {
            expression.kind() == "attribute"
                && expression
                    .child_by_field_name("attribute")
                    .and_then(|attribute| node_text(source, attribute))
                    == Some("setter")
        })
}

fn has_same_scope_setter(class: Node<'_>, source: &str, property_name: &str) -> bool {
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    named_children(body).into_iter().any(|member| {
        let definition = if member.kind() == "decorated_definition" {
            named_children(member)
                .into_iter()
                .find(|child| child.kind() == "function_definition")
        } else {
            (member.kind() == "function_definition").then_some(member)
        };
        let Some(definition) = definition else {
            return false;
        };
        definition
            .child_by_field_name("name")
            .and_then(|name| node_text(source, name))
            == Some(property_name)
            && is_setter(definition, source)
            && python_definition_decorators(definition)
                .into_iter()
                .filter_map(|decorator| named_children(decorator).into_iter().next())
                .any(|expression| {
                    expression.kind() == "attribute"
                        && expression
                            .child_by_field_name("attribute")
                            .and_then(|attribute| node_text(source, attribute))
                            == Some("setter")
                        && expression
                            .child_by_field_name("object")
                            .and_then(|object| node_text(source, object))
                            == Some(property_name)
                })
    })
}

fn initializer_writes(definition: Node<'_>, source: &str) -> InitializerAnalysis {
    let Some(parameters) = definition.child_by_field_name("parameters") else {
        return InitializerAnalysis {
            writes: Vec::new(),
            open_reason: Some("initializer_parameters_unavailable"),
        };
    };
    let Some(first_parameter) = named_children(parameters).into_iter().next() else {
        return InitializerAnalysis {
            writes: Vec::new(),
            open_reason: Some("initializer_self_parameter_unavailable"),
        };
    };
    let Some(self_name) = parameter_name(first_parameter, source) else {
        return InitializerAnalysis {
            writes: Vec::new(),
            open_reason: Some("initializer_self_parameter_unsupported"),
        };
    };
    let Some(body) = definition.child_by_field_name("body") else {
        return InitializerAnalysis {
            writes: Vec::new(),
            open_reason: Some("initializer_body_unavailable"),
        };
    };

    let mut nodes = scope_nodes(body);
    nodes.retain(|node| {
        matches!(
            node.kind(),
            "assignment"
                | "augmented_assignment"
                | "call"
                | "return_statement"
                | "yield"
                | "function_definition"
                | "lambda"
        )
    });
    nodes.sort_by_key(|node| (node.end_byte(), node.start_byte()));

    let mut aliases = HashSet::default();
    aliases.insert(self_name);
    let mut writes = Vec::new();
    let mut open_reason = None;
    let mut globals = HashSet::default();
    for node in scope_nodes(body) {
        if node.kind() == "global_statement" || node.kind() == "nonlocal_statement" {
            globals.extend(
                named_children(node)
                    .into_iter()
                    .filter_map(|name| node_text(source, name).map(str::to_owned)),
            );
        }
    }

    for node in nodes {
        match node.kind() {
            "assignment" | "augmented_assignment" => {
                let Some(left) = node.child_by_field_name("left") else {
                    open_reason.get_or_insert("initializer_assignment_shape_unresolved");
                    continue;
                };
                if let Some(write) = attribute_write(left, source, &aliases) {
                    writes.push(write);
                }
                let right = node.child_by_field_name("right");
                let right_alias = right.and_then(|right| direct_identifier(right, source));
                let right_has_alias =
                    right.is_some_and(|right| contains_alias(right, source, &aliases));
                if left.kind() == "identifier" {
                    let Some(target) = node_text(source, left) else {
                        open_reason.get_or_insert("initializer_binding_name_unresolved");
                        continue;
                    };
                    let target = target.to_owned();
                    let source_alias = right_alias.is_some_and(|name| aliases.contains(name));
                    if globals.contains(&target) {
                        if right_has_alias {
                            open_reason.get_or_insert("initializer_self_escapes_to_outer_scope");
                        }
                        aliases.remove(&target);
                        continue;
                    }
                    if in_control_branch(node, definition)
                        && (source_alias || aliases.contains(&target))
                    {
                        if source_alias || aliases.contains(&target) {
                            aliases.insert(target);
                        }
                        open_reason.get_or_insert("initializer_conditional_local_flow");
                    } else if source_alias {
                        aliases.insert(target);
                    } else {
                        aliases.remove(&target);
                    }
                    if right_has_alias && !source_alias {
                        open_reason.get_or_insert("initializer_self_escapes_through_value");
                    }
                } else if right_has_alias {
                    open_reason.get_or_insert("initializer_self_escapes_through_store");
                }
            }
            "call" => {
                let Some(function) = node.child_by_field_name("function") else {
                    open_reason.get_or_insert("initializer_call_shape_unresolved");
                    continue;
                };
                let function_name = call_name(function, source);
                let arguments = node
                    .child_by_field_name("arguments")
                    .map(named_children)
                    .unwrap_or_default();
                if function_name == Some("setattr")
                    && arguments.first().is_some_and(|argument| {
                        direct_identifier(*argument, source)
                            .is_some_and(|name| aliases.contains(name))
                    })
                {
                    match arguments
                        .get(1)
                        .copied()
                        .filter(|name| name.kind() == "string")
                        .and_then(|name| {
                            brokk_bifrost_python::decode_python_string_value(name, source).ok()
                        }) {
                        Some(name) => writes.push(InitializerWrite {
                            name,
                            line: node.start_position().row.saturating_add(1),
                        }),
                        None => {
                            open_reason.get_or_insert("dynamic_setattr_name");
                        }
                    }
                    if arguments
                        .iter()
                        .skip(2)
                        .any(|argument| contains_alias(*argument, source, &aliases))
                    {
                        open_reason.get_or_insert("initializer_self_escapes_through_setattr_value");
                    }
                    continue;
                }
                let receiver_is_alias = function.kind() == "attribute"
                    && function
                        .child_by_field_name("object")
                        .and_then(|object| direct_identifier(object, source))
                        .is_some_and(|name| aliases.contains(name));
                if !receiver_is_alias
                    && arguments
                        .iter()
                        .any(|argument| contains_alias(*argument, source, &aliases))
                {
                    open_reason.get_or_insert("initializer_self_escapes_to_call");
                }
            }
            "return_statement" | "yield" => {
                if contains_alias(node, source, &aliases) {
                    open_reason.get_or_insert("initializer_self_escapes_from_function");
                }
            }
            "function_definition" | "lambda" => {
                if contains_alias(node, source, &aliases) {
                    open_reason.get_or_insert("initializer_self_captured_by_nested_scope");
                }
            }
            _ => unreachable!("initializer event list contains known node kinds"),
        }
    }

    InitializerAnalysis {
        writes,
        open_reason,
    }
}

fn attribute_write(
    target: Node<'_>,
    source: &str,
    aliases: &HashSet<String>,
) -> Option<InitializerWrite> {
    if target.kind() != "attribute" {
        return None;
    }
    let object = target.child_by_field_name("object")?;
    let object_name = direct_identifier(object, source)?;
    if !aliases.contains(object_name) {
        return None;
    }
    let name = target
        .child_by_field_name("attribute")
        .and_then(|name| node_text(source, name))?
        .to_owned();
    Some(InitializerWrite {
        name,
        line: target.start_position().row.saturating_add(1),
    })
}
