use crate::analyzer::tree_sitter_analyzer::ParsedFile;
use crate::analyzer::usages::{ImportBinder, ImportKind};
use crate::analyzer::{CodeUnit, ParameterMetadata, ProjectFile, Range, SignatureMetadata};
use crate::hash::{HashMap, HashSet};
use std::path::Path;
use tree_sitter::{Node, Tree};

use super::imports::rust_imports_from_use_declaration;

pub(super) fn rust_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

pub(super) fn parse_rust_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    let mut parsed = ParsedFile::new(rust_package_name(file));
    let root = tree.root_node();
    collect_rust_type_identifiers(root, source, &mut parsed.type_identifiers);
    let item_macro_definitions = rust_rules_item_macro_definitions(root, source);
    let mut impl_import_binder = ImportBinder::empty();

    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };
        if child.kind() == "use_declaration" {
            let imports = rust_imports_from_use_declaration(child, source);
            for import in &imports {
                super::lexical_scope::insert_rust_import_binding(&mut impl_import_binder, import);
            }
            parsed
                .import_statements
                .extend(imports.iter().map(|import| import.raw_snippet.clone()));
            parsed.imports.extend(imports);
        }
    }
    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };
        match child.kind() {
            "use_declaration" => {}
            "struct_item" | "enum_item" | "trait_item" => {
                visit_rust_class_like(
                    file,
                    source,
                    child,
                    None,
                    &parsed.package_name.clone(),
                    &mut parsed,
                );
            }
            "mod_item" => {
                visit_rust_module(
                    file,
                    source,
                    child,
                    None,
                    &parsed.package_name.clone(),
                    &item_macro_definitions,
                    &mut parsed,
                );
            }
            "function_item" => {
                visit_rust_function(
                    file,
                    source,
                    child,
                    None,
                    &parsed.package_name.clone(),
                    &mut parsed,
                );
            }
            "const_item" | "static_item" => {
                visit_rust_field(
                    file,
                    source,
                    child,
                    None,
                    &parsed.package_name.clone(),
                    &mut parsed,
                );
            }
            "macro_definition" => {
                visit_rust_macro(
                    file,
                    source,
                    child,
                    None,
                    &parsed.package_name.clone(),
                    &mut parsed,
                );
            }
            "macro_invocation" => {
                visit_rust_macro_invocation_definitions(
                    file,
                    source,
                    child,
                    None,
                    &parsed.package_name.clone(),
                    &item_macro_definitions,
                    &mut parsed,
                );
            }
            "type_item" => {
                visit_rust_alias(
                    file,
                    source,
                    child,
                    None,
                    &parsed.package_name.clone(),
                    &mut parsed,
                );
            }
            "impl_item" => {
                visit_rust_impl(
                    file,
                    source,
                    child,
                    &parsed.package_name.clone(),
                    &impl_import_binder,
                    &mut parsed,
                );
            }
            _ => {}
        }
    }

    parsed
}

pub(crate) fn rust_package_name(file: &ProjectFile) -> String {
    let rel = file.rel_path();
    let mut components: Vec<_> = rel
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect();

    let source_root = components.iter().rposition(|component| component == "src");
    if source_root == Some(0) {
        components.remove(0);
    }
    if components.is_empty() {
        return String::new();
    }

    let file_name = components.pop().unwrap_or_default();
    let stem = Path::new(&file_name)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();

    if stem == "lib" || stem == "main" || stem == "mod" {
        components.join(".")
    } else if source_root.is_some() {
        components
            .into_iter()
            .chain(std::iter::once(stem.to_string()))
            .filter(|component| !component.is_empty())
            .collect::<Vec<_>>()
            .join(".")
    } else {
        components.join(".")
    }
}

fn visit_rust_class_like(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Class,
        package_name.to_string(),
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );
    parsed.add_signature(
        code_unit.clone(),
        rust_type_signature(node, source, package_name.is_empty()),
    );

    if let Some(body) = node.child_by_field_name("body") {
        for index in 0..body.named_child_count() {
            let Some(child) = body.named_child(index) else {
                continue;
            };
            match child.kind() {
                "field_declaration" | "enum_variant" | "const_item" => {
                    visit_rust_field(file, source, child, Some(&code_unit), package_name, parsed);
                }
                "function_item" | "function_signature_item" => {
                    visit_rust_function(
                        file,
                        source,
                        child,
                        Some(&code_unit),
                        package_name,
                        parsed,
                    );
                }
                "associated_type" | "type_item" => {
                    visit_rust_alias(file, source, child, Some(&code_unit), package_name, parsed);
                }
                _ => {}
            }
        }
    }

    Some(code_unit)
}

fn visit_rust_module(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    item_macro_definitions: &[RustRulesItemMacroDefinition],
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Module,
        package_name.to_string(),
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );
    parsed.add_signature(code_unit.clone(), format!("mod {name} {{"));

    if let Some(body) = node.child_by_field_name("body") {
        for index in 0..body.named_child_count() {
            let Some(child) = body.named_child(index) else {
                continue;
            };
            match child.kind() {
                "function_item" => {
                    visit_rust_function(
                        file,
                        source,
                        child,
                        Some(&code_unit),
                        package_name,
                        parsed,
                    );
                }
                "struct_item" | "enum_item" | "trait_item" => {
                    visit_rust_class_like(
                        file,
                        source,
                        child,
                        Some(&code_unit),
                        package_name,
                        parsed,
                    );
                }
                "mod_item" => {
                    visit_rust_module(
                        file,
                        source,
                        child,
                        Some(&code_unit),
                        package_name,
                        item_macro_definitions,
                        parsed,
                    );
                }
                "macro_definition" => {
                    visit_rust_macro(file, source, child, Some(&code_unit), package_name, parsed);
                }
                "macro_invocation" => {
                    visit_rust_macro_invocation_definitions(
                        file,
                        source,
                        child,
                        Some(&code_unit),
                        package_name,
                        item_macro_definitions,
                        parsed,
                    );
                }
                _ => {}
            }
        }
    }

    Some(code_unit)
}

fn visit_rust_function(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let signature = rust_impl_member_identity_signature(node, source).or_else(|| {
        node.child_by_field_name("parameters")
            .map(|parameters| rust_node_text(parameters, source).trim().to_string())
    });
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::with_signature(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        package_name.to_string(),
        short_name,
        signature,
        false,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    let signature = rust_function_signature(node, source);
    parsed.add_signature_with_metadata(
        code_unit.clone(),
        rust_signature_metadata(signature, node, source),
    );
    Some(code_unit)
}

fn visit_rust_macro(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    register_rust_macro(
        file,
        name,
        package_name,
        parent,
        rust_range_from_node(node),
        rust_macro_signature(node, source),
        parsed,
    )
}

fn register_rust_macro(
    file: &ProjectFile,
    name: &str,
    package_name: &str,
    parent: Option<&CodeUnit>,
    range: Range,
    signature: String,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Macro,
        package_name.to_string(),
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit_with_range(code_unit.clone(), range, parent.cloned(), Some(top_level));
    parsed.add_signature(code_unit.clone(), signature);
    Some(code_unit)
}

fn visit_rust_macro_invocation_definitions(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    item_macro_definitions: &[RustRulesItemMacroDefinition],
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(invoked_macro) = rust_unqualified_macro_invocation_name(node, source) else {
        return;
    };
    if !rust_latest_visible_rules_item_macro(
        item_macro_definitions,
        invoked_macro,
        node.start_byte(),
    )
    .unwrap_or(false)
    {
        return;
    }

    let Some(arguments) = rust_macro_invocation_arguments(node) else {
        return;
    };

    let mut cursor = arguments.walk();
    let mut window: [Option<Node<'_>>; 4] = [None, None, None, None];
    for child in arguments.children(&mut cursor) {
        if let Some((macro_rules, name_node, body_node)) = rust_embedded_macro_match(window, source)
        {
            let end_node = if child.kind() == ";" {
                child
            } else {
                body_node
            };
            visit_rust_embedded_macro(
                file,
                source,
                macro_rules,
                name_node,
                end_node,
                parent,
                package_name,
                parsed,
            );
        }

        window.rotate_left(1);
        window[3] = Some(child);
    }

    if let Some((macro_rules, name_node, body_node)) = rust_embedded_macro_match(window, source) {
        visit_rust_embedded_macro(
            file,
            source,
            macro_rules,
            name_node,
            body_node,
            parent,
            package_name,
            parsed,
        );
    }
}

fn rust_embedded_macro_match<'tree>(
    window: [Option<Node<'tree>>; 4],
    source: &str,
) -> Option<(Node<'tree>, Node<'tree>, Node<'tree>)> {
    let [
        Some(macro_rules),
        Some(bang),
        Some(name_node),
        Some(body_node),
    ] = window
    else {
        return None;
    };
    (rust_is_macro_rules_token(macro_rules, source)
        && bang.kind() == "!"
        && rust_is_identifier_like(name_node)
        && body_node.kind() == "token_tree")
        .then_some((macro_rules, name_node, body_node))
}

pub(super) fn rust_unqualified_macro_invocation_name<'a>(
    node: Node<'_>,
    source: &'a str,
) -> Option<&'a str> {
    let macro_node = node.child_by_field_name("macro")?;
    if !rust_is_identifier_like(macro_node) {
        return None;
    }
    let name = rust_node_text(macro_node, source).trim();
    (!name.is_empty()).then_some(name)
}

pub(super) fn rust_macro_invocation_arguments(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("arguments").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "token_tree")
    })
}

fn rust_is_macro_rules_token(node: Node<'_>, source: &str) -> bool {
    node.kind() == "identifier" && rust_node_text(node, source).trim() == "macro_rules"
}

fn rust_is_identifier_like(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "reserved_identifier" | "_reserved_identifier"
    )
}

#[derive(Debug, Clone)]
pub(super) struct RustRulesItemMacroDefinition {
    pub(super) name: String,
    pub(super) visible_after: usize,
    pub(super) scope_start: usize,
    pub(super) scope_end: usize,
    pub(super) passthrough: bool,
}

pub(super) fn rust_rules_item_macro_definitions(
    root: Node<'_>,
    source: &str,
) -> Vec<RustRulesItemMacroDefinition> {
    let mut definitions = Vec::new();
    let mut pending_scopes = vec![root];
    while let Some(scope) = pending_scopes.pop() {
        let mut cursor = scope.walk();
        let mut children = scope.named_children(&mut cursor).collect::<Vec<_>>();
        children.reverse();
        for child in children {
            if child.kind() == "macro_definition" {
                if let Some(name) = rust_macro_definition_name(child, source) {
                    definitions.push((
                        RustRulesItemMacroDefinition {
                            name: name.to_string(),
                            visible_after: child.end_byte(),
                            scope_start: scope.start_byte(),
                            scope_end: scope.end_byte(),
                            passthrough: rust_macro_definition_all_rules_replay_item_parameters(
                                child, source,
                            ),
                        },
                        rust_macro_definition_item_delegate(child, source),
                    ));
                }
                continue;
            }
            if child.kind() == "mod_item"
                && let Some(body) = child.child_by_field_name("body")
            {
                pending_scopes.push(body);
            }
        }
    }
    definitions.sort_by_key(|(definition, _)| definition.visible_after);
    loop {
        let mut changed = false;
        for index in 0..definitions.len() {
            if definitions[index].0.passthrough {
                continue;
            }
            let Some(delegate) = definitions[index].1.as_deref() else {
                continue;
            };
            let wrapper = &definitions[index].0;
            let delegated = definitions[..index]
                .iter()
                .filter(|(definition, _)| {
                    definition.name == delegate
                        && definition.visible_after <= wrapper.visible_after
                        && definition.scope_start <= wrapper.visible_after
                        && wrapper.visible_after < definition.scope_end
                })
                .max_by_key(|(definition, _)| (definition.scope_start, definition.visible_after))
                .is_some_and(|(definition, _)| definition.passthrough);
            if delegated {
                definitions[index].0.passthrough = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    definitions
        .into_iter()
        .map(|(definition, _)| definition)
        .collect()
}

fn rust_macro_definition_item_delegate(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    let rules: Vec<_> = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "macro_rule")
        .collect();
    let mut delegate = None;
    for rule in rules {
        let candidate = rust_macro_rule_item_delegate(rule, source)?;
        if delegate.as_ref().is_some_and(|known| known != &candidate) {
            return None;
        }
        delegate = Some(candidate);
    }
    delegate
}

fn rust_macro_rule_item_delegate(rule: Node<'_>, source: &str) -> Option<String> {
    let pattern = rule.child_by_field_name("left")?;
    let expansion = rule.child_by_field_name("right")?;
    let item_parameters = rust_macro_rule_item_parameters(pattern, source);
    if item_parameters.is_empty()
        || !rust_macro_rule_matcher_is_item_stream(pattern, source, &item_parameters)
    {
        return None;
    }

    let mut cursor = expansion.walk();
    let children = expansion.children(&mut cursor).collect::<Vec<_>>();
    let mut index = 1;
    let end = children.len().checked_sub(1)?;
    while index + 1 < end
        && children[index].kind() == "#"
        && rust_is_conditional_attribute_token_tree(children[index + 1], source)
    {
        index += 2;
    }
    let name = *children.get(index)?;
    let bang = *children.get(index + 1)?;
    let arguments = *children.get(index + 2)?;
    if index + 3 != end
        || !rust_is_identifier_like(name)
        || bang.kind() != "!"
        || arguments.kind() != "token_tree"
        || !rust_macro_delegate_arguments_replay_items(arguments, source, &item_parameters)
    {
        return None;
    }
    Some(rust_node_text(name, source).trim().to_string())
}

fn rust_is_conditional_attribute_token_tree(node: Node<'_>, source: &str) -> bool {
    node.kind() == "token_tree"
        && node.child(0).is_some_and(|child| child.kind() == "[")
        && node
            .child(node.child_count().saturating_sub(1))
            .is_some_and(|child| child.kind() == "]")
        && node
            .named_child(0)
            .filter(|child| rust_is_identifier_like(*child))
            .map(|child| rust_node_text(child, source).trim())
            .is_some_and(|name| matches!(name, "cfg" | "cfg_attr"))
}

fn rust_macro_delegate_arguments_replay_items(
    arguments: Node<'_>,
    source: &str,
    item_parameters: &HashMap<String, usize>,
) -> bool {
    let mut cursor = arguments.walk();
    let children = arguments.children(&mut cursor).collect::<Vec<_>>();
    let Some(inner) = children.get(1..children.len().saturating_sub(1)) else {
        return false;
    };
    if inner.is_empty()
        || inner.iter().any(|child| {
            child.kind() != "token_repetition"
                || !rust_item_repetition_replays_parameters(*child, source, item_parameters)
        })
    {
        return false;
    }
    let mut seen = HashMap::default();
    for child in inner {
        let mut pending = vec![*child];
        while let Some(node) = pending.pop() {
            if node.kind() == "metavariable" {
                *seen
                    .entry(rust_node_text(node, source).trim().to_string())
                    .or_insert(0usize) += 1;
                continue;
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
    }
    item_parameters
        .keys()
        .all(|parameter| seen.get(parameter) == Some(&1))
        && seen.len() == item_parameters.len()
}

fn rust_item_repetition_replays_parameters(
    repetition: Node<'_>,
    source: &str,
    item_parameters: &HashMap<String, usize>,
) -> bool {
    let mut cursor = repetition.walk();
    repetition
        .children(&mut cursor)
        .all(|child| match child.kind() {
            "$" | "(" | ")" | "*" | "+" | "?" => true,
            "metavariable" => item_parameters.contains_key(rust_node_text(child, source).trim()),
            _ => false,
        })
}

fn rust_latest_visible_rules_item_macro(
    definitions: &[RustRulesItemMacroDefinition],
    name: &str,
    invocation_start: usize,
) -> Option<bool> {
    definitions
        .iter()
        .filter(|definition| {
            definition.name == name
                && definition.visible_after <= invocation_start
                && definition.scope_start <= invocation_start
                && invocation_start < definition.scope_end
        })
        .max_by_key(|definition| (definition.scope_start, definition.visible_after))
        .map(|definition| definition.passthrough)
}

fn rust_macro_definition_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    (!name.is_empty()).then_some(name)
}

fn rust_macro_definition_all_rules_replay_item_parameters(node: Node<'_>, source: &str) -> bool {
    let mut cursor = node.walk();
    let rules: Vec<_> = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "macro_rule")
        .collect();
    !rules.is_empty()
        && rules
            .into_iter()
            .all(|rule| rust_macro_rule_replays_item_parameters(rule, source))
}

fn rust_macro_rule_replays_item_parameters(rule: Node<'_>, source: &str) -> bool {
    let Some(pattern) = rule.child_by_field_name("left") else {
        return false;
    };
    let Some(expansion) = rule.child_by_field_name("right") else {
        return false;
    };

    let item_parameters = rust_macro_rule_item_parameters(pattern, source);
    if item_parameters.is_empty()
        || !rust_macro_rule_matcher_is_item_stream(pattern, source, &item_parameters)
    {
        return false;
    }

    let mut occurrences: HashMap<String, usize> = HashMap::default();
    let mut stack = vec![expansion];
    while let Some(node) = stack.pop() {
        if node.kind() == "metavariable" {
            let name = rust_node_text(node, source).trim();
            let Some(pattern_depth) = item_parameters.get(name) else {
                continue;
            };
            let mut repetition_depth = 0;
            let mut ancestor = node;
            loop {
                let Some(parent) = ancestor.parent() else {
                    return false;
                };
                if parent == expansion {
                    break;
                }
                if parent.kind() != "token_repetition" {
                    return false;
                }
                repetition_depth += 1;
                ancestor = parent;
            }
            if repetition_depth != *pattern_depth {
                return false;
            }
            *occurrences.entry(name.to_string()).or_default() += 1;
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    item_parameters
        .keys()
        .all(|parameter| occurrences.get(parameter) == Some(&1))
}

fn rust_macro_rule_item_parameters(pattern: Node<'_>, source: &str) -> HashMap<String, usize> {
    let mut parameters = HashMap::default();
    let mut stack = vec![(pattern, 0)];
    while let Some((node, repetition_depth)) = stack.pop() {
        if node.kind() == "token_binding_pattern"
            && rust_macro_binding_fragment(node, source) == Some("item")
            && let Some(metavariable) = node.child_by_field_name("name")
        {
            let name = rust_node_text(metavariable, source).trim();
            if !name.is_empty() {
                parameters.insert(name.to_string(), repetition_depth);
            }
        }

        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor).map(|child| {
            (
                child,
                repetition_depth + usize::from(child.kind() == "token_repetition_pattern"),
            )
        }));
    }
    parameters
}

fn rust_macro_binding_fragment<'a>(binding: Node<'_>, source: &'a str) -> Option<&'a str> {
    binding
        .child_by_field_name("type")
        .map(|fragment| rust_node_text(fragment, source).trim())
}

fn rust_macro_rule_matcher_is_item_stream(
    pattern: Node<'_>,
    source: &str,
    item_parameters: &HashMap<String, usize>,
) -> bool {
    let mut cursor = pattern.walk();
    let children = pattern.children(&mut cursor).collect::<Vec<_>>();
    let mut index = 1;
    let end = children.len().saturating_sub(1);
    while index < end {
        let child = children[index];
        match child.kind() {
            "token_binding_pattern" => {
                if rust_macro_binding_fragment(child, source) != Some("item") {
                    return false;
                }
                index += 1;
            }
            "token_repetition_pattern" => {
                if !rust_item_repetition_pattern_is_safe(child, source, item_parameters) {
                    return false;
                }
                index += 1;
            }
            "#" => {
                index += 1;
                if index < end && children[index].kind() == "!" {
                    index += 1;
                }
                if index >= end
                    || children[index].kind() != "token_tree_pattern"
                    || !rust_attribute_meta_pattern_is_safe(children[index], source)
                {
                    return false;
                }
                index += 1;
            }
            _ => return false,
        }
    }
    true
}

fn rust_item_repetition_pattern_is_safe(
    repetition: Node<'_>,
    source: &str,
    item_parameters: &HashMap<String, usize>,
) -> bool {
    let mut saw_item = false;
    let mut cursor = repetition.walk();
    for child in repetition.children(&mut cursor) {
        match child.kind() {
            "$" | "(" | ")" | "*" | "+" | "?" => {}
            "token_binding_pattern" => {
                let Some(name) = child.child_by_field_name("name") else {
                    return false;
                };
                let name = rust_node_text(name, source).trim();
                if rust_macro_binding_fragment(child, source) != Some("item")
                    || !item_parameters.contains_key(name)
                {
                    return false;
                }
                saw_item = true;
            }
            _ => return false,
        }
    }
    saw_item
}

fn rust_attribute_meta_pattern_is_safe(attribute: Node<'_>, source: &str) -> bool {
    let mut saw_meta = false;
    let mut pending = vec![attribute];
    while let Some(node) = pending.pop() {
        if node.kind() == "token_binding_pattern" {
            if rust_macro_binding_fragment(node, source) != Some("meta") {
                return false;
            }
            saw_meta = true;
            continue;
        }
        if node != attribute && node.kind() == "token_tree_pattern" {
            return false;
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    saw_meta
}

#[allow(clippy::too_many_arguments)]
fn visit_rust_embedded_macro(
    file: &ProjectFile,
    source: &str,
    start_node: Node<'_>,
    name_node: Node<'_>,
    end_node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    register_rust_macro(
        file,
        name,
        package_name,
        parent,
        rust_range_from_nodes(start_node, end_node),
        format!("macro_rules! {name}"),
        parsed,
    )
}

fn rust_range_from_node(node: Node<'_>) -> Range {
    rust_range_from_nodes(node, node)
}

fn rust_range_from_nodes(start_node: Node<'_>, end_node: Node<'_>) -> Range {
    Range {
        start_byte: start_node.start_byte(),
        end_byte: end_node.end_byte(),
        start_line: start_node.start_position().row + 1,
        end_line: end_node.end_position().row + 1,
    }
}

fn visit_rust_field(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name").unwrap_or(node);
    let name = rust_node_text(name_node, source)
        .trim()
        .trim_end_matches(',')
        .to_string();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| format!("_module_.{name}"));
    let code_unit = CodeUnit::with_signature(
        file.clone(),
        crate::analyzer::CodeUnitType::Field,
        package_name.to_string(),
        short_name,
        rust_impl_member_identity_signature(node, source),
        false,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    parsed.add_signature(
        code_unit.clone(),
        rust_node_text(node, source)
            .trim()
            .trim_end_matches(',')
            .to_string(),
    );
    Some(code_unit)
}

fn visit_rust_alias(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::with_signature(
        file.clone(),
        crate::analyzer::CodeUnitType::Field,
        package_name.to_string(),
        short_name,
        rust_impl_member_identity_signature(node, source),
        false,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    parsed.add_signature(
        code_unit.clone(),
        rust_node_text(node, source).trim().to_string(),
    );
    parsed.mark_type_alias(code_unit.clone());
    Some(code_unit)
}

fn visit_rust_impl(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    import_binder: &ImportBinder,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let Some(parent) =
        rust_impl_owner(file, source, type_node, package_name, import_binder, parsed)
    else {
        return;
    };

    let Some(body) = node.child_by_field_name("body") else {
        return;
    };
    for index in 0..body.named_child_count() {
        let Some(child) = body.named_child(index) else {
            continue;
        };
        match child.kind() {
            "function_item" => {
                visit_rust_function(
                    file,
                    source,
                    child,
                    Some(&parent),
                    parent.package_name(),
                    parsed,
                );
            }
            "const_item" => {
                visit_rust_field(
                    file,
                    source,
                    child,
                    Some(&parent),
                    parent.package_name(),
                    parsed,
                );
            }
            "type_item" => {
                visit_rust_alias(
                    file,
                    source,
                    child,
                    Some(&parent),
                    parent.package_name(),
                    parsed,
                );
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustImplOwnerIdentity {
    package_name: String,
    short_name: String,
}

fn rust_impl_owner(
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
    package_name: &str,
    import_binder: &ImportBinder,
    parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let target_path = rust_nominal_type_path(type_node, source)?;
    let local_identity = RustImplOwnerIdentity {
        package_name: package_name.to_string(),
        short_name: target_path.join("."),
    };
    if let Some(owner) = rust_declared_impl_owner(parsed, &local_identity) {
        return Some(owner);
    }

    let identity = if target_path.len() == 1 {
        let target_name = &target_path[0];
        if let Some(binding) = import_binder.bindings.get(target_name)
            && binding.kind == ImportKind::Named
        {
            let imported_name = binding.imported_name.as_ref()?;
            let resolved_package = super::imports::resolve_rust_module_path_with_crate(
                package_name,
                &super::imports::rust_crate_root_package(file),
                &binding.module_specifier,
            )?;
            RustImplOwnerIdentity {
                package_name: resolved_package,
                short_name: imported_name.clone(),
            }
        } else {
            // Generic parameters and `Self` deliberately remain member namespaces only.
            // Ordinary unresolved bare names do too: only a source declaration can publish
            // a nominal workspace type.
            local_identity
        }
    } else {
        rust_impl_owner_identity_from_path(file, package_name, &target_path, import_binder)?
    };

    rust_declared_impl_owner(parsed, &identity).or_else(|| {
        Some(CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Class,
            identity.package_name,
            identity.short_name,
        ))
    })
}

fn rust_declared_impl_owner(
    parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    identity: &RustImplOwnerIdentity,
) -> Option<CodeUnit> {
    parsed
        .declarations()
        .iter()
        .find(|unit| {
            (unit.kind() == crate::analyzer::CodeUnitType::Class
                || parsed.type_aliases.contains(*unit))
                && unit.package_name() == identity.package_name
                && unit.short_name() == identity.short_name
        })
        .cloned()
}

fn rust_impl_owner_identity_from_path(
    file: &ProjectFile,
    package_name: &str,
    path: &[String],
    import_binder: &ImportBinder,
) -> Option<RustImplOwnerIdentity> {
    let (name, module_path) = path.split_last()?;
    let crate_package = super::imports::rust_crate_root_package(file);
    let package_name = if let Some((root, remainder)) = module_path.split_first()
        && let Some(binding) = import_binder.bindings.get(root)
        && binding.kind == ImportKind::Namespace
    {
        let mut resolved = super::imports::resolve_rust_module_path_with_crate(
            package_name,
            &crate_package,
            &binding.module_specifier,
        )?;
        for component in remainder {
            if !resolved.is_empty() {
                resolved.push('.');
            }
            resolved.push_str(component);
        }
        resolved
    } else {
        let module_specifier = module_path.join("::");
        super::imports::resolve_rust_module_path_with_crate(
            package_name,
            &crate_package,
            &module_specifier,
        )?
    };

    Some(RustImplOwnerIdentity {
        package_name,
        short_name: name.clone(),
    })
}

fn rust_nominal_type_path(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut pending = vec![node];
    while let Some(candidate) = pending.pop() {
        match candidate.kind() {
            "type_identifier" | "identifier" => {
                let name = rust_node_text(candidate, source).trim();
                if !name.is_empty() {
                    return Some(vec![name.to_string()]);
                }
            }
            "scoped_type_identifier" => {
                let path = rust_path_components(candidate, source);
                if !path.is_empty() {
                    return Some(path);
                }
            }
            "generic_type" | "reference_type" | "pointer_type" | "array_type" | "slice_type" => {
                if let Some(inner) = candidate.child_by_field_name("type") {
                    pending.push(inner);
                } else {
                    for index in (0..candidate.named_child_count()).rev() {
                        if let Some(child) = candidate.named_child(index)
                            && child.kind() != "type_arguments"
                        {
                            pending.push(child);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn rust_path_components(node: Node<'_>, source: &str) -> Vec<String> {
    let mut components = Vec::new();
    let mut pending = vec![node];
    while let Some(candidate) = pending.pop() {
        match candidate.kind() {
            "crate" | "self" | "super" | "identifier" | "type_identifier" => {
                let text = rust_node_text(candidate, source).trim();
                if !text.is_empty() {
                    components.push(text.to_string());
                }
            }
            "scoped_identifier" | "scoped_type_identifier" => {
                if let Some(name) = candidate.child_by_field_name("name") {
                    pending.push(name);
                }
                if let Some(path) = candidate.child_by_field_name("path") {
                    pending.push(path);
                }
            }
            _ => {}
        }
    }
    components
}

fn rust_type_signature(node: Node<'_>, source: &str, _top_level: bool) -> String {
    let header = rust_node_text(node, source)
        .split('{')
        .next()
        .unwrap_or_else(|| rust_node_text(node, source))
        .split(';')
        .next()
        .unwrap_or_else(|| rust_node_text(node, source))
        .trim();
    format!("{header} {{")
}

fn rust_function_signature(node: Node<'_>, source: &str) -> String {
    let header = rust_node_text(node, source)
        .split('{')
        .next()
        .unwrap_or_else(|| rust_node_text(node, source))
        .trim()
        .trim_end_matches(';')
        .to_string();
    if node.kind() == "function_signature_item" {
        header
    } else {
        format!("{header} {{ ... }}")
    }
}

fn rust_impl_member_identity_signature(node: Node<'_>, source: &str) -> Option<String> {
    let impl_item = enclosing_rust_impl_item(node)?;
    let type_text = impl_item
        .child_by_field_name("type")
        .map(|node| rust_node_text(node, source).trim())?;
    let item_signature = match node.kind() {
        "function_item" | "function_signature_item" => rust_function_signature(node, source),
        "const_item" | "type_item" | "associated_type" => {
            rust_node_text(node, source).trim().to_string()
        }
        _ => return None,
    };
    if let Some(trait_node) = impl_item.child_by_field_name("trait") {
        let trait_text = rust_node_text(trait_node, source).trim();
        Some(format!(
            "impl {trait_text} for {type_text}::{item_signature}"
        ))
    } else {
        Some(format!("impl {type_text}::{item_signature}"))
    }
}

fn enclosing_rust_impl_item(node: Node<'_>) -> Option<Node<'_>> {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if candidate.kind() == "impl_item" {
            return Some(candidate);
        }
        parent = candidate.parent();
    }
    None
}

fn rust_signature_metadata(signature: String, node: Node<'_>, source: &str) -> SignatureMetadata {
    let Some(parameters_node) = node.child_by_field_name("parameters") else {
        return SignatureMetadata::new(signature, Vec::new());
    };
    let parameter_text = rust_node_text(parameters_node, source).trim();
    let Some(parameters_start) = signature.find(parameter_text) else {
        return SignatureMetadata::new(signature, Vec::new());
    };
    let parameters_end = parameters_start + parameter_text.len();
    let mut search_start = parameters_start;
    let parameters = rust_parameter_label_nodes(parameters_node)
        .into_iter()
        .filter_map(|label_node| {
            let label = rust_node_text(label_node, source).trim();
            if label.is_empty() || search_start > parameters_end {
                return None;
            }
            let haystack = signature.get(search_start..parameters_end)?;
            let relative_start = haystack.find(label)?;
            let start_byte = search_start + relative_start;
            let end_byte = start_byte + label.len();
            search_start = end_byte;
            Some(ParameterMetadata::new(label, start_byte, end_byte))
        })
        .collect();
    SignatureMetadata::new(signature, parameters)
}

fn rust_parameter_label_nodes(parameters_node: Node<'_>) -> Vec<Node<'_>> {
    let mut labels = Vec::new();
    let mut cursor = parameters_node.walk();
    for child in parameters_node.named_children(&mut cursor) {
        match child.kind() {
            "parameter" => {
                if let Some(pattern) = child.child_by_field_name("pattern") {
                    labels.push(rust_parameter_pattern_label_node(pattern).unwrap_or(pattern));
                }
            }
            "self_parameter" => labels.push(child),
            _ => {}
        }
    }
    labels
}

fn rust_parameter_pattern_label_node(pattern: Node<'_>) -> Option<Node<'_>> {
    match pattern.kind() {
        "identifier" => Some(pattern),
        "mut_pattern" | "ref_pattern" => {
            let mut cursor = pattern.walk();
            pattern
                .named_children(&mut cursor)
                .find_map(rust_parameter_pattern_label_node)
        }
        _ => None,
    }
}

fn rust_macro_signature(node: Node<'_>, source: &str) -> String {
    rust_node_text(node, source)
        .lines()
        .find(|line| line.contains("macro_rules!"))
        .map(str::trim)
        .unwrap_or("macro_rules!")
        .to_string()
}

pub(super) fn collect_rust_type_identifiers(
    node: Node<'_>,
    source: &str,
    identifiers: &mut HashSet<String>,
) {
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        match node.kind() {
            "identifier" | "type_identifier" | "field_identifier" => {
                let text = rust_node_text(node, source).trim();
                if !text.is_empty() {
                    identifiers.insert(text.to_string());
                }
            }
            _ => {}
        }

        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                pending.push(child);
            }
        }
    }
}

#[cfg(test)]
mod passthrough_macro_tests {
    use super::*;

    #[test]
    fn item_passthrough_classifier_requires_a_safe_matcher_and_faithful_replay() {
        let source = r#"
macro_rules! replay { ($($item:item)*) => { $( #[cfg(any())] $item )* }; }
macro_rules! feature { (#![$meta:meta] $($item:item)*) => { $( #[$meta] $item )* }; }
macro_rules! base { ($($item:item)*) => { $( #[cfg(any())] $item )* }; }
macro_rules! delegated { ($($item:item)*) => { #[cfg(unix)] base! { $($item)* } }; }
macro_rules! attributed_nested { ($($item:item)*) => { #[allow(dead_code)] base! { $($item)* } }; }
macro_rules! dropped { ($($left:item)* $($right:item)*) => { $($left)* }; }
macro_rules! stringified { ($($item:item)*) => { stringify!($($item)*) }; }
macro_rules! nested { ($($item:item)*) => { wrapper! { $($item)* } }; }
macro_rules! mixed { ($name:ident, $item:item) => { $item }; }
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let definitions = rust_rules_item_macro_definitions(tree.root_node(), source)
            .into_iter()
            .map(|definition| (definition.name, definition.passthrough))
            .collect::<HashMap<_, _>>();

        for name in ["replay", "feature", "base", "delegated"] {
            assert_eq!(definitions.get(name), Some(&true), "{name}");
        }
        for name in [
            "attributed_nested",
            "dropped",
            "stringified",
            "nested",
            "mixed",
        ] {
            assert_eq!(definitions.get(name), Some(&false), "{name}");
        }
    }

    #[test]
    fn declaration_expansion_uses_the_latest_visible_same_name_macro() {
        let source = r#"
macro_rules! wrapper { ($($item:item)*) => { $($item)* }; }
wrapper! { macro_rules! Before { () => {} } }
macro_rules! wrapper { (drop $name:ident) => {}; }
wrapper! { macro_rules! Phantom { () => {} } }
mod inline_scope {
    macro_rules! wrapper { ($($item:item)*) => { $($item)* }; }
    wrapper! { macro_rules! InlineGenerated { () => {} } }
}
wrapper! { macro_rules! OutsidePhantom { () => {} } }
other::wrapper! { macro_rules! QualifiedPhantom { () => {} } }
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "src/lib.rs",
        );
        let parsed = parse_rust_file(&file, source, &tree);
        let macros = parsed
            .top_level_declarations
            .iter()
            .chain(parsed.children.values().flatten())
            .filter(|unit| unit.is_macro())
            .map(|unit| unit.identifier())
            .collect::<HashSet<_>>();

        for expected in ["Before", "InlineGenerated"] {
            assert!(macros.contains(expected), "missing {expected}: {macros:?}");
        }
        for phantom in ["Phantom", "OutsidePhantom", "QualifiedPhantom"] {
            assert!(
                !macros.contains(phantom),
                "unexpected {phantom}: {macros:?}"
            );
        }
    }
}
