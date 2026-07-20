use super::extractor::{declared_names, is_definition_identifier, parameter_names, selector_parts};
use crate::analyzer::usages::get_definition::{
    ResolvedReferenceSite, smallest_named_node_covering,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::hash::HashMap;
use tree_sitter::Node;

#[derive(Debug, Clone)]
pub(in crate::analyzer::usages) struct GoSelectorDescriptor<'tree> {
    pub base: Node<'tree>,
    pub members: Vec<Node<'tree>>,
    pub focus_segment: usize,
}

impl GoSelectorDescriptor<'_> {
    pub fn focused_node(&self) -> Node<'_> {
        if self.focus_segment == 0 {
            self.base
        } else {
            self.members[self.focus_segment - 1]
        }
    }

    pub fn base_identifier<'source>(&self, source: &'source str) -> Option<&'source str> {
        matches!(
            self.base.kind(),
            "identifier" | "package_identifier" | "type_identifier"
        )
        .then(|| node_text(self.base, source))
    }

    pub fn member_name<'source>(&self, source: &'source str, index: usize) -> Option<&'source str> {
        let member = *self.members.get(index)?;
        matches!(
            member.kind(),
            "field_identifier" | "type_identifier" | "identifier"
        )
        .then(|| node_text(member, source))
    }
}

pub(in crate::analyzer::usages) fn go_selector_descriptor<'tree>(
    root: Node<'tree>,
    site: &ResolvedReferenceSite,
) -> Option<GoSelectorDescriptor<'tree>> {
    let selected = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)?;
    let mut top = selected;
    while let Some(parent) = top.parent() {
        if matches!(parent.kind(), "selector_expression" | "qualified_type") {
            top = parent;
        } else {
            break;
        }
    }
    if !matches!(top.kind(), "selector_expression" | "qualified_type") {
        return None;
    }

    let mut base = top;
    let mut members = Vec::new();
    while matches!(base.kind(), "selector_expression" | "qualified_type") {
        let member = base
            .child_by_field_name("field")
            .or_else(|| base.child_by_field_name("name"))?;
        members.push(member);
        base = base
            .child_by_field_name("operand")
            .or_else(|| base.child_by_field_name("package"))?;
    }
    members.reverse();

    let contains_focus = |node: Node<'_>| {
        node.start_byte() <= site.focus_start_byte && node.end_byte() >= site.focus_end_byte
    };
    let focus_segment = if contains_focus(base)
        && matches!(
            base.kind(),
            "identifier" | "package_identifier" | "type_identifier"
        ) {
        0
    } else {
        members.iter().position(|member| contains_focus(*member))? + 1
    };

    Some(GoSelectorDescriptor {
        base,
        members,
        focus_segment,
    })
}

pub(in crate::analyzer::usages) struct GoReferenceResolution {
    pub fqn_candidates: Vec<String>,
    pub resolved_import_packages: Vec<String>,
    pub shadowed: bool,
}

pub(in crate::analyzer::usages) fn resolve_go_reference_with_namespaces(
    root: Node<'_>,
    source: &str,
    file_pkg: &str,
    alias_packages: &HashMap<String, Vec<String>>,
    dot_packages: &[String],
    site: &ResolvedReferenceSite,
    selector: Option<&GoSelectorDescriptor<'_>>,
) -> GoReferenceResolution {
    if let Some(selector) = selector
        && let Some(qualifier) = selector.base_identifier(source)
    {
        let shadowed = go_name_shadowed_at(root, source, site.focus_start_byte, qualifier);
        if shadowed {
            return GoReferenceResolution {
                fqn_candidates: Vec::new(),
                resolved_import_packages: Vec::new(),
                shadowed: true,
            };
        }
        if let Some(packages) = alias_packages.get(qualifier) {
            let fqn_candidates = (selector.focus_segment == 1)
                .then(|| selector.member_name(source, 0))
                .flatten()
                .map(|name| {
                    packages
                        .iter()
                        .map(|package| format!("{package}.{name}"))
                        .collect()
                })
                .unwrap_or_default();
            return GoReferenceResolution {
                fqn_candidates,
                resolved_import_packages: packages.clone(),
                shadowed: false,
            };
        }
        if selector.focus_segment > 0 {
            let fqn_candidates = (selector.focus_segment == 1)
                .then(|| selector.member_name(source, 0))
                .flatten()
                .map(|name| vec![format!("{file_pkg}.{qualifier}.{name}")])
                .unwrap_or_default();
            return GoReferenceResolution {
                fqn_candidates,
                resolved_import_packages: Vec::new(),
                shadowed: false,
            };
        }
    }

    let reference = selector
        .map(GoSelectorDescriptor::focused_node)
        .map(|node| node_text(node, source))
        .unwrap_or(site.text.as_str());
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
        resolved_import_packages: dot_packages.to_vec(),
        shadowed: false,
    }
}

fn node_text<'source>(node: Node<'_>, source: &'source str) -> &'source str {
    source.get(node.byte_range()).unwrap_or_default()
}

/// Whether `node` is a top-level declaration (a direct child of the source file),
/// i.e. package scope rather than a function/block-local binding.
pub(super) fn go_is_top_level_decl(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "source_file")
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
        "var_declaration" | "short_var_declaration"
            if node.start_byte() < cutoff_start && !go_is_top_level_decl(node) =>
        {
            // A *package-level* `var` is the declaration a reference resolves TO,
            // not a local shadow — only function/block-scoped `var`/`:=` bindings
            // shadow. (Top-level `const`/`func`/`type` were never seeded here, which
            // is why only package `var` references failed to resolve.)
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
