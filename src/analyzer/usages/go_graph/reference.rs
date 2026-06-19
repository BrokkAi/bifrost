use super::extractor::{declared_names, is_definition_identifier, parameter_names, selector_parts};
use super::resolver::GoProjectGraph;
use crate::analyzer::usages::get_definition::ResolvedReferenceSite;
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::{GoAnalyzer, ProjectFile};
use crate::hash::HashMap;
use tree_sitter::Node;

pub(in crate::analyzer::usages) struct GoReferenceResolution {
    pub fqn_candidates: Vec<String>,
    pub resolved_import_packages: Vec<String>,
    pub shadowed: bool,
}

pub(in crate::analyzer::usages) fn resolve_go_reference(
    graph: &GoProjectGraph,
    go: &GoAnalyzer,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
) -> Option<GoReferenceResolution> {
    let parsed = graph.parsed_file(file)?;
    let file_pkg = graph.package_name_of(file)?;
    let (alias_packages, dot_packages) = graph.namespace_packages(go, file);
    Some(resolve_with_namespaces(
        parsed.tree.root_node(),
        source,
        &file_pkg,
        alias_packages,
        dot_packages,
        site,
    ))
}

fn resolve_with_namespaces(
    root: Node<'_>,
    source: &str,
    file_pkg: &str,
    alias_packages: HashMap<String, Vec<String>>,
    dot_packages: Vec<String>,
    site: &ResolvedReferenceSite,
) -> GoReferenceResolution {
    let reference = site.text.as_str();
    if let Some((qualifier, name)) = reference.split_once('.') {
        let shadowed = go_name_shadowed_at(root, source, site.focus_start_byte, qualifier);
        if shadowed {
            return GoReferenceResolution {
                fqn_candidates: Vec::new(),
                resolved_import_packages: Vec::new(),
                shadowed: true,
            };
        }
        if let Some(packages) = alias_packages.get(qualifier) {
            return GoReferenceResolution {
                fqn_candidates: packages
                    .iter()
                    .map(|package| format!("{package}.{name}"))
                    .collect(),
                resolved_import_packages: packages.clone(),
                shadowed: false,
            };
        }
        return GoReferenceResolution {
            fqn_candidates: vec![format!("{file_pkg}.{qualifier}.{name}")],
            resolved_import_packages: Vec::new(),
            shadowed: false,
        };
    }

    let shadowed = go_name_shadowed_at(root, source, site.focus_start_byte, reference);
    if shadowed {
        return GoReferenceResolution {
            fqn_candidates: Vec::new(),
            resolved_import_packages: Vec::new(),
            shadowed: true,
        };
    }

    let mut fqn_candidates = Vec::with_capacity(dot_packages.len() + 1);
    fqn_candidates.push(format!("{file_pkg}.{reference}"));
    fqn_candidates.extend(
        dot_packages
            .iter()
            .map(|package| format!("{package}.{reference}")),
    );
    GoReferenceResolution {
        fqn_candidates,
        resolved_import_packages: dot_packages,
        shadowed: false,
    }
}

fn go_name_shadowed_at(root: Node<'_>, source: &str, byte: usize, name: &str) -> bool {
    let mut locals = LocalInferenceEngine::new(LocalInferenceConfig::default());
    let mut shadowed_at_lookup = None;
    seed_go_bindings_before(
        root,
        source,
        byte,
        name,
        &mut locals,
        &mut shadowed_at_lookup,
    );
    shadowed_at_lookup.unwrap_or_else(|| locals.is_shadowed(name))
}

fn seed_go_bindings_before(
    node: Node<'_>,
    source: &str,
    cutoff_start: usize,
    target_name: &str,
    locals: &mut LocalInferenceEngine<String>,
    shadowed_at_lookup: &mut Option<bool>,
) {
    if shadowed_at_lookup.is_some() {
        return;
    }
    if node.start_byte() >= cutoff_start {
        if node.start_byte() == cutoff_start {
            *shadowed_at_lookup = Some(locals.is_shadowed(target_name));
        }
        return;
    }

    match node.kind() {
        "import_declaration" => return,
        "function_declaration" | "method_declaration" => {
            if !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
                return;
            }
            locals.enter_scope();
            seed_go_parameters_before(node, source, cutoff_start, locals);
            seed_go_children_before(
                node,
                source,
                cutoff_start,
                target_name,
                locals,
                shadowed_at_lookup,
            );
            locals.exit_scope();
            return;
        }
        "block" | "block_statement" => {
            if !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
                return;
            }
            locals.enter_scope();
            seed_go_children_before(
                node,
                source,
                cutoff_start,
                target_name,
                locals,
                shadowed_at_lookup,
            );
            locals.exit_scope();
            return;
        }
        "parameter_declaration" if node.start_byte() < cutoff_start => {
            for parameter in parameter_names(node, source) {
                locals.declare_shadow(parameter);
            }
        }
        "var_declaration" | "short_var_declaration" if node.start_byte() < cutoff_start => {
            for declared in declared_names(node, source) {
                locals.declare_shadow(declared);
            }
        }
        "selector_expression" | "qualified_type" => {
            if selector_is_lookup_target(node, source, cutoff_start) {
                *shadowed_at_lookup = Some(locals.is_shadowed(target_name));
                return;
            }
        }
        "identifier" | "type_identifier" | "package_identifier"
            if node.start_byte() == cutoff_start || is_definition_identifier(node, source) =>
        {
            if node.start_byte() == cutoff_start {
                *shadowed_at_lookup = Some(locals.is_shadowed(target_name));
            }
            return;
        }
        _ => {}
    }

    seed_go_children_before(
        node,
        source,
        cutoff_start,
        target_name,
        locals,
        shadowed_at_lookup,
    );
}

fn seed_go_parameters_before(
    node: Node<'_>,
    source: &str,
    cutoff_start: usize,
    locals: &mut LocalInferenceEngine<String>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "parameter_list" || child.start_byte() >= cutoff_start {
            continue;
        }
        let mut params = child.walk();
        for parameter in child.named_children(&mut params) {
            if parameter.kind() == "parameter_declaration" && parameter.start_byte() < cutoff_start
            {
                for name in parameter_names(parameter, source) {
                    locals.declare_shadow(name);
                }
            }
        }
    }
}

fn seed_go_children_before(
    node: Node<'_>,
    source: &str,
    cutoff_start: usize,
    target_name: &str,
    locals: &mut LocalInferenceEngine<String>,
    shadowed_at_lookup: &mut Option<bool>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() > cutoff_start || shadowed_at_lookup.is_some() {
            continue;
        }
        seed_go_bindings_before(
            child,
            source,
            cutoff_start,
            target_name,
            locals,
            shadowed_at_lookup,
        );
    }
}

fn selector_is_lookup_target(node: Node<'_>, source: &str, cutoff_start: usize) -> bool {
    selector_parts(node, source)
        .map(|(_, _, field)| field.start_byte() == cutoff_start)
        .unwrap_or(false)
}
