//! Python's reference resolution: export-name and seed inference, receiver-type
//! resolution, and annotation candidates.
//!
//! `index` arguments below are the *dispatching* analyzer's
//! [`CodeUnitIndex`] (see [`PythonGraphSource`]); `python` is the Python
//! analyzer's memoized products.

use crate::graph::PythonGraphSource;
use crate::graph_support::PythonUsageSource;
use crate::imports::resolve_fqn_candidates;
use crate::syntax::{
    python_deferred_annotation_identifier_ranges, python_deferred_annotation_tree,
    python_node_is_in_annotation,
};
use crate::usage_index::{
    ModuleBindingEventKind, ModuleBindingTimeline, usage_resolve_module_files, usage_seeds,
};
use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path;
use brokk_bifrost_core::analyzer::usages::model::{ExportEntry, ImportBinder, ImportKind};
use brokk_bifrost_core::analyzer::usages::{ImportEdge, ImportEdgeKind};
use brokk_bifrost_core::analyzer::{
    CodeUnit, CodeUnitIndex, DefinitionLanguageScope, Language, ProjectFile, Range,
    RelationalDefinitionQuery, RelationalDefinitionQuestion, RelationalDefinitionValue,
    RelationalName,
};
use brokk_bifrost_core::hash::HashSet;
use std::collections::BTreeSet;
use tree_sitter::Node;

const MAX_MEMBER_OWNER_FRONTIER: usize = 512;

/// Resolve the declarations selected by Python member lookup for one concrete
/// receiver type. A declaration on the receiver (or on a nearer base layer)
/// overrides every same-named declaration farther up the hierarchy.
pub(crate) fn resolved_member_declarations(
    graph: &PythonGraphSource<'_>,
    receiver: &CodeUnit,
    member: &str,
) -> Vec<CodeUnit> {
    let mut visited = HashSet::default();
    let mut frontier = vec![receiver.clone()];
    while !frontier.is_empty() && visited.len() < MAX_MEMBER_OWNER_FRONTIER {
        let mut declarations = Vec::new();
        let mut next = Vec::new();
        for owner in frontier {
            if !visited.insert(owner.clone()) {
                continue;
            }
            let fqn = format!("{}.{member}", owner.fq_name());
            declarations.extend(
                graph
                    .index
                    .definitions(&fqn)
                    .filter(|candidate| graph.index.parent_of(candidate).as_ref() == Some(&owner)),
            );
            if let Some(hierarchy) = graph.hierarchy {
                next.extend(hierarchy.get_direct_ancestors(&owner));
            }
        }
        declarations.sort();
        declarations.dedup();
        if !declarations.is_empty() {
            return declarations;
        }
        next.sort();
        next.dedup();
        frontier = next;
    }
    Vec::new()
}

pub fn infer_export_names(python: &dyn PythonUsageSource, target: &CodeUnit) -> BTreeSet<String> {
    if target_owner_code_unit(python, target).is_some() {
        let owner_name = top_level_identifier(python, target);
        let owner_exports =
            infer_export_names_for_local(python, target, target.source(), &owner_name);
        if !owner_exports.is_empty() {
            return owner_exports;
        }
    }

    infer_export_names_for_local(python, target, target.source(), target.identifier())
}

pub fn infer_usage_seeds(
    python: &dyn PythonUsageSource,
    target: &CodeUnit,
    seed_names: BTreeSet<String>,
) -> BTreeSet<(ProjectFile, String)> {
    let mut seeds = BTreeSet::new();
    for seed_name in &seed_names {
        seeds.extend(usage_seeds(python, target.source(), seed_name));
    }
    if seeds.is_empty()
        && seed_names.contains(target.identifier())
        && is_module_level_target_identifier(python, target, target.source(), target.identifier())
    {
        seeds.insert((target.source().clone(), target.identifier().to_string()));
    }
    seeds
}

fn infer_export_names_for_local(
    python: &dyn PythonUsageSource,
    target: &CodeUnit,
    file: &ProjectFile,
    local_name: &str,
) -> BTreeSet<String> {
    let index = python.export_index_of(file);
    let mut export_names = BTreeSet::new();
    if index.exports_by_name.contains_key(local_name) {
        export_names.insert(local_name.to_string());
    }
    for (export_name, entry) in &index.exports_by_name {
        if matches!(entry, ExportEntry::Local { local_name: name } if name == local_name) {
            export_names.insert(export_name.clone());
        }
    }
    if export_names.is_empty()
        && is_module_level_target_identifier(python, target, file, local_name)
    {
        export_names.insert(local_name.to_string());
    }
    export_names
}

fn is_module_level_target_identifier(
    python: &dyn PythonUsageSource,
    target: &CodeUnit,
    file: &ProjectFile,
    local_name: &str,
) -> bool {
    target.source() == file
        && target.identifier() == local_name
        && python
            .parent_of(target)
            .is_some_and(|parent| parent.is_module() && parent.source() == file)
}

pub fn top_level_identifier(index: &dyn CodeUnitIndex, target: &CodeUnit) -> String {
    let mut current = target.clone();
    while let Some(parent) = index.parent_of(&current) {
        if parent.is_module() {
            break;
        }
        current = parent;
    }
    current.identifier().to_string()
}

pub fn member_name(index: &dyn CodeUnitIndex, target: &CodeUnit) -> Option<String> {
    target_owner_code_unit(index, target).map(|_| target.identifier().to_string())
}

pub fn target_owner_code_unit(index: &dyn CodeUnitIndex, target: &CodeUnit) -> Option<CodeUnit> {
    index
        .parent_of(target)
        .filter(|parent| parent.source() == target.source() && parent.is_class())
}

pub fn resolve_receiver_type(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    raw_type: &str,
    target_self_file: bool,
) -> Option<CodeUnit> {
    let raw_type = raw_type.trim();
    if raw_type.is_empty() || raw_type.contains('|') {
        return None;
    }
    if raw_type.contains('.') {
        let candidates = resolve_fqn_candidates(python, raw_type, |name| {
            graph.index.definitions(name).collect()
        })
        .into_iter()
        .filter(CodeUnit::is_class)
        .collect::<Vec<_>>();
        return (candidates.len() == 1)
            .then(|| candidates.into_iter().next())
            .flatten();
    }

    if let Some(binding) = python.import_binder_of(file).bindings.get(raw_type)
        && binding.kind == ImportKind::Named
        && let Some(imported) = binding.imported_name.as_ref()
    {
        let fqn = format!("{}.{}", binding.module_specifier, imported);
        if let Some(class) =
            resolve_fqn_candidates(python, &fqn, |name| graph.index.definitions(name).collect())
                .into_iter()
                .find(CodeUnit::is_class)
        {
            return Some(class);
        }
    }

    if let Some(provider) = graph.imports
        && let Some(imported) = provider
            .imported_code_units_of(file)
            .iter()
            .find(|code_unit| code_unit.identifier() == raw_type && code_unit.is_class())
    {
        return Some(imported.clone());
    }

    graph
        .index
        .declarations(file)
        .into_iter()
        .find(|code_unit| code_unit.identifier() == raw_type && code_unit.is_class())
        .or_else(|| {
            if !target_self_file {
                return None;
            }
            resolve_indexed_receiver_type(graph, file, raw_type)
        })
}

fn resolve_bare_annotation_symbol(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    raw_symbol: &str,
) -> Vec<CodeUnit> {
    let raw_symbol = raw_symbol.trim();
    if raw_symbol.is_empty() {
        return Vec::new();
    }

    if let Some(owner) = annotation_scope_owner_class(graph, file, source, node) {
        let owner_candidates: Vec<_> = exact_owner_annotation_members(graph, &owner, raw_symbol)
            .into_iter()
            .filter(|candidate| !candidate.is_function())
            .collect();
        if !owner_candidates.is_empty() {
            return owner_candidates;
        }
    }

    let mut candidates = Vec::new();
    if let Some(binding) = python.import_binder_of(file).bindings.get(raw_symbol)
        && binding.kind == ImportKind::Named
        && let Some(imported) = binding.imported_name.as_ref()
    {
        let fqn = format!("{}.{}", binding.module_specifier, imported);
        let mut imported_candidates = resolve_fqn_candidates(python, &fqn, |name| {
            graph
                .index
                .definitions(name)
                .filter(|candidate| candidate.source().language() == Language::Python)
                .collect()
        });
        imported_candidates.retain(|candidate| {
            !candidate.is_module() || candidate.fq_name() != binding.module_specifier
        });
        candidates.extend(imported_candidates);
    }

    candidates.extend(
        graph
            .index
            .top_level_declarations(file)
            .into_iter()
            .filter(|code_unit| {
                !code_unit.is_module()
                    && code_unit.identifier() == raw_symbol
                    && graph
                        .index
                        .parent_of(code_unit)
                        .is_some_and(|parent| parent.is_module())
            }),
    );

    candidates.retain(|candidate| !candidate.is_function());
    candidates.sort();
    candidates.dedup();
    candidates
}

/// Resolve a structured Python annotation reference.
///
/// Only AST nodes that occur inside a function return type, parameter type, or
/// annotated-assignment type are considered. In particular, string contents are
/// accepted only in those annotation positions; arbitrary string literals are
/// never interpreted as type expressions.
pub fn annotation_reference_candidates(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    target_self_file: bool,
) -> Option<Vec<CodeUnit>> {
    if !is_annotation_reference_node(node, source) {
        return None;
    }

    let mut candidates = match node.kind() {
        "identifier" => {
            let mut candidates = resolve_bare_annotation_symbol(
                graph,
                python,
                file,
                source,
                node,
                node_text(node, source),
            );
            if candidates.is_empty() {
                candidates.extend(resolve_receiver_type(
                    graph,
                    python,
                    file,
                    node_text(node, source),
                    target_self_file,
                ));
            }
            candidates
        }
        "string_content" => {
            let Some(string) = node.parent() else {
                return Some(Vec::new());
            };
            let Some(ranges) = python_deferred_annotation_identifier_ranges(string, source, None)
            else {
                return Some(Vec::new());
            };
            let mut candidates = Vec::new();
            for range in ranges {
                let Some(symbol) = source.get(range.start_byte..range.end_byte) else {
                    continue;
                };
                let mut symbol_candidates =
                    resolve_bare_annotation_symbol(graph, python, file, source, node, symbol);
                if symbol_candidates.is_empty() {
                    symbol_candidates.extend(resolve_receiver_type(
                        graph,
                        python,
                        file,
                        symbol,
                        target_self_file,
                    ));
                }
                candidates.extend(symbol_candidates);
            }
            candidates
        }
        "attribute" => resolve_annotation_attribute_types(graph, python, file, source, node),
        _ => Vec::new(),
    };
    candidates.sort();
    candidates.dedup();
    Some(candidates)
}

/// Resolve only the annotation identifier selected by one definition request.
/// Quoted annotations are reparsed with original byte coordinates, while the
/// original syntax node remains the lexical class-scope anchor.
#[allow(clippy::too_many_arguments)]
pub fn annotation_reference_candidates_at_focus(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    focus_start: usize,
    focus_end: usize,
    target_self_file: bool,
) -> Option<Vec<CodeUnit>> {
    if !is_annotation_reference_node(node, source) {
        return None;
    }

    let deferred_tree = if node.kind() == "string_content" {
        Some(python_deferred_annotation_tree(
            node.parent()?,
            source,
            None,
        )?)
    } else {
        None
    };
    let search_root = deferred_tree.as_ref().map_or(node, |tree| tree.root_node());
    let focused = search_root.descendant_for_byte_range(focus_start, focus_end)?;
    if focused.kind() != "identifier"
        || focused.start_byte() != focus_start
        || focused.end_byte() != focus_end
    {
        return Some(Vec::new());
    }

    let mut path = focused;
    while let Some(parent) = path.parent() {
        if parent.kind() != "attribute" {
            break;
        }
        path = parent;
    }
    if path.kind() == "attribute" {
        return Some(focused_annotation_attribute_candidates(
            graph, python, file, source, node, path, focused,
        ));
    }

    let symbol = node_text(focused, source);
    let mut candidates = resolve_bare_annotation_symbol(graph, python, file, source, node, symbol);
    if candidates.is_empty() {
        candidates.extend(resolve_receiver_type(
            graph,
            python,
            file,
            symbol,
            target_self_file,
        ));
    }
    candidates.sort();
    candidates.dedup();
    Some(candidates)
}

fn focused_annotation_attribute_candidates(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    scope_node: Node<'_>,
    path: Node<'_>,
    focused: Node<'_>,
) -> Vec<CodeUnit> {
    let Some((root, attributes)) = annotation_attribute_chain(path) else {
        return Vec::new();
    };
    if root.id() == focused.id() {
        return resolve_bare_annotation_symbol(
            graph,
            python,
            file,
            source,
            scope_node,
            node_text(root, source),
        );
    }

    if attributes
        .last()
        .is_some_and(|node| node.id() == focused.id())
    {
        let candidates = namespace_qualified_declarations(graph, python, file, source, path);
        if !candidates.is_empty() {
            return candidates;
        }
    }

    let owners: Vec<_> = resolve_bare_annotation_symbol(
        graph,
        python,
        file,
        source,
        scope_node,
        node_text(root, source),
    )
    .into_iter()
    .filter(CodeUnit::is_class)
    .collect();
    let [owner] = owners.as_slice() else {
        return Vec::new();
    };
    let mut owner = owner.clone();
    for attribute in attributes {
        let candidates = exact_nested_annotation_class(graph, &owner, node_text(attribute, source));
        if attribute.id() == focused.id() {
            return candidates;
        }
        let [next] = candidates.as_slice() else {
            return Vec::new();
        };
        owner = next.clone();
    }
    Vec::new()
}

/// Return the exact qualifier token when a class target owns part of a
/// structured annotation attribute chain.
pub fn annotation_class_qualifier_site<'tree>(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    node: Node<'tree>,
    target: &CodeUnit,
) -> Option<Node<'tree>> {
    if node.kind() != "attribute"
        || !target.is_class()
        || !is_annotation_reference_node(node, source)
    {
        return None;
    }

    let (root, attributes) = annotation_attribute_chain(node)?;
    let owners: Vec<_> =
        resolve_bare_annotation_symbol(graph, python, file, source, root, node_text(root, source))
            .into_iter()
            .filter(CodeUnit::is_class)
            .collect();
    let [owner] = owners.as_slice() else {
        return None;
    };
    let mut owner = owner.clone();
    if &owner == target {
        return Some(root);
    }

    // The final attribute is the annotation declaration itself. Only the
    // preceding segments are class qualifiers.
    let qualifier_count = attributes.len().saturating_sub(1);
    for attribute in attributes.into_iter().take(qualifier_count) {
        let next_candidates =
            exact_nested_annotation_class(graph, &owner, node_text(attribute, source));
        let [next] = next_candidates.as_slice() else {
            return None;
        };
        owner = next.clone();
        if &owner == target {
            return Some(attribute);
        }
    }

    None
}

fn resolve_annotation_attribute_types(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Vec<CodeUnit> {
    // Preserve the established namespace-import path (`module.Type`) while
    // adding owner-qualified nested classes (`Outer.Inner`). The namespace walk
    // already understands module/re-export bindings; it simply cannot interpret
    // a class as the namespace for another class.
    let mut candidates = namespace_qualified_declarations(graph, python, file, source, node);
    let Some((root, attributes)) = annotation_attribute_chain(node) else {
        return candidates;
    };
    let root_text = node_text(root, source);
    let owners: Vec<_> =
        resolve_bare_annotation_symbol(graph, python, file, source, root, root_text)
            .into_iter()
            .filter(CodeUnit::is_class)
            .collect();
    let [owner] = owners.as_slice() else {
        return candidates;
    };
    let mut owner = owner.clone();

    for attribute in attributes {
        let segment = node_text(attribute, source);
        let next_candidates = exact_nested_annotation_class(graph, &owner, segment);
        let [next] = next_candidates.as_slice() else {
            return candidates;
        };
        owner = next.clone();
    }

    candidates.push(owner);
    candidates
}

fn annotation_attribute_chain(node: Node<'_>) -> Option<(Node<'_>, Vec<Node<'_>>)> {
    let mut attributes = Vec::new();
    let mut current = node;
    while current.kind() == "attribute" {
        attributes.push(current.child_by_field_name("attribute")?);
        current = current.child_by_field_name("object")?;
    }
    if current.kind() != "identifier" || attributes.is_empty() {
        return None;
    }
    attributes.reverse();
    Some((current, attributes))
}

fn exact_nested_annotation_class(
    graph: &PythonGraphSource<'_>,
    owner: &CodeUnit,
    segment: &str,
) -> Vec<CodeUnit> {
    let mut candidates: Vec<_> = exact_owner_annotation_members(graph, owner, segment)
        .into_iter()
        .filter(CodeUnit::is_class)
        .collect();
    candidates.sort();
    candidates.dedup();
    candidates
}

fn exact_owner_annotation_members(
    graph: &PythonGraphSource<'_>,
    owner: &CodeUnit,
    segment: &str,
) -> Vec<CodeUnit> {
    let mut candidates: Vec<_> = graph
        .index
        .declarations(owner.source())
        .into_iter()
        .filter(|unit| {
            unit.identifier() == segment
                && graph
                    .index
                    .parent_of(unit)
                    .is_some_and(|parent| parent.fq_name() == owner.fq_name())
        })
        .collect();
    candidates.sort();
    candidates.dedup();
    candidates
}

fn annotation_scope_owner_class(
    graph: &PythonGraphSource<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<CodeUnit> {
    if !annotation_expression_is_class_scoped(node) {
        return None;
    }
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: 0,
        end_line: 0,
    };
    if let Some(enclosing) = graph.index.enclosing_code_unit(file, &range) {
        if enclosing.is_class() {
            return Some(enclosing);
        }
        if let Some(owner) = target_owner_code_unit(graph.index, &enclosing) {
            return Some(owner);
        }
    }
    structural_annotation_owner_class(graph, file, source, node)
}

fn annotation_expression_is_class_scoped(node: Node<'_>) -> bool {
    let site_start = node.start_byte();
    let site_end = node.end_byte();
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "function_definition" | "lambda")
            && parent
                .child_by_field_name("body")
                .is_some_and(|body| body.start_byte() <= site_start && site_end <= body.end_byte())
        {
            return false;
        }
        if parent.kind() == "class_definition" {
            return true;
        }
        current = parent;
    }
    false
}

fn structural_annotation_owner_class(
    graph: &PythonGraphSource<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<CodeUnit> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "class_definition" {
            let name = node_text(parent.child_by_field_name("name")?, source).trim();
            if name.is_empty() {
                return None;
            }
            let class_range = Range {
                start_byte: parent.start_byte(),
                end_byte: parent.end_byte(),
                start_line: 0,
                end_line: 0,
            };
            let mut matches: Vec<_> = graph
                .index
                .declarations(file)
                .into_iter()
                .filter(|unit| unit.is_class() && unit.identifier() == name)
                .filter(|unit| {
                    graph
                        .index
                        .ranges(unit)
                        .into_iter()
                        .any(|range| range.contains(&class_range))
                })
                .collect();
            matches.sort();
            matches.dedup();
            let [owner] = matches.as_slice() else {
                return None;
            };
            return Some(owner.clone());
        }
        current = parent;
    }
    None
}

fn is_annotation_reference_node(node: Node<'_>, source: &str) -> bool {
    if !matches!(node.kind(), "identifier" | "attribute" | "string_content") {
        return false;
    }
    if !python_node_is_in_annotation(node) {
        return false;
    }

    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "call"
            && parent
                .child_by_field_name("arguments")
                .is_some_and(|arguments| {
                    arguments.start_byte() <= node.start_byte()
                        && node.end_byte() <= arguments.end_byte()
                })
        {
            return false;
        }
        if parent.kind() == "subscript"
            && let Some(value) = parent.child_by_field_name("value")
            && value.kind() == "identifier"
        {
            match node_text(value, source) {
                // Literal parameters are values, including invalid values a
                // type checker will diagnose. They are still ordinary Python
                // references for definition and usage resolution.
                "Literal" => return false,
                // Only Annotated's first parameter is a type. Every following
                // metadata expression is evaluated as a value.
                "Annotated" => {
                    let Some(arguments) = parent.child_by_field_name("subscript") else {
                        return false;
                    };
                    let type_argument = if arguments.kind() == "expression_list" {
                        arguments.named_child(0)
                    } else {
                        Some(arguments)
                    };
                    if !type_argument.is_some_and(|argument| {
                        argument.start_byte() <= node.start_byte()
                            && node.end_byte() <= argument.end_byte()
                    }) {
                        return false;
                    }
                }
                _ => {}
            }
        }
        if parent.kind() == "type_parameter"
            && let Some(generic) = parent
                .parent()
                .filter(|parent| parent.kind() == "generic_type")
        {
            let generic_name = generic
                .child_by_field_name("name")
                .or_else(|| generic.named_child(0))
                .map(|name| node_text(name, source));
            match generic_name {
                Some("Literal") => return false,
                Some("Annotated") => {
                    let type_argument = parent.named_child(0);
                    if !type_argument.is_some_and(|argument| {
                        argument.start_byte() <= node.start_byte()
                            && node.end_byte() <= argument.end_byte()
                    }) {
                        return false;
                    }
                }
                _ => {}
            }
        }
        current = parent;
    }
    true
}

/// Resolve every visible named-import binding for one local symbol.
///
/// The ordinary import binder intentionally stores one effective binding per
/// local name. A conditional `if TYPE_CHECKING: from .m import T; else: from m
/// import T` has two possible bindings, however, and usage resolution must keep
/// every workspace candidate rather than whichever arm the binder visited
/// last.
pub fn resolve_visible_named_import_candidates(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    timeline: &ModuleBindingTimeline,
    local: &str,
    cutoff: usize,
) -> Vec<CodeUnit> {
    let Some(events) = timeline.get(local) else {
        return Vec::new();
    };
    let visible: Vec<_> = events
        .iter()
        .filter(|event| event.visible_from <= cutoff)
        .collect();
    let start = visible
        .iter()
        .rposition(|event| !event.conditional)
        .unwrap_or(0);
    let mut candidates = Vec::new();
    for event in &visible[start..] {
        let ModuleBindingEventKind::FromImport {
            module,
            imported_name,
        } = &event.kind
        else {
            continue;
        };
        let mut resolved_module = false;
        for module_file in usage_resolve_module_files(python, file, module) {
            let Some(module_fqn) = graph
                .index
                .declarations(&module_file)
                .into_iter()
                .find(CodeUnit::is_module)
                .map(|unit| unit.fq_name())
            else {
                continue;
            };
            resolved_module = true;
            let fqn = format!("{module_fqn}.{imported_name}");
            candidates.extend(resolve_fqn_candidates(python, &fqn, |name| {
                graph.index.definitions(name).collect()
            }));
        }
        if !resolved_module {
            let fqn = if module.ends_with('.') {
                format!("{module}{imported_name}")
            } else {
                format!("{module}.{imported_name}")
            };
            candidates.extend(resolve_fqn_candidates(python, &fqn, |name| {
                graph.index.definitions(name).collect()
            }));
        }
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

/// Resolve the class constructed by a Python call callee without interpreting
/// source text. Bare callees use the import binder or same-file declarations;
/// qualified callees walk tree-sitter's `attribute` fields back to a namespace
/// import and append each attribute component structurally.
pub fn resolve_constructor_types(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
) -> Vec<CodeUnit> {
    let candidates = match function.kind() {
        "identifier" => {
            let local = node_text(function, source);
            if local.is_empty() {
                return Vec::new();
            }
            let binder = python.import_binder_of(file);
            let fqn = match binder.bindings.get(local) {
                Some(binding) if binding.kind == ImportKind::Named => binding
                    .imported_name
                    .as_ref()
                    .map(|imported| format!("{}.{}", binding.module_specifier, imported)),
                _ => graph
                    .index
                    .declarations(file)
                    .into_iter()
                    .find(|unit| unit.is_class() && unit.identifier() == local)
                    .map(|unit| unit.fq_name()),
            };
            let Some(fqn) = fqn else {
                return Vec::new();
            };
            resolve_fqn_candidates(python, &fqn, |name| graph.index.definitions(name).collect())
        }
        "attribute" => namespace_qualified_declarations(graph, python, file, source, function),
        _ => Vec::new(),
    };
    // A call callee names something constructible; an annotation does not, so
    // the kind filter belongs here rather than in the shared namespace walk.
    let mut classes: Vec<CodeUnit> = candidates.into_iter().filter(CodeUnit::is_class).collect();
    classes.sort();
    classes.dedup();
    classes
}

/// Resolve the class in the nearest enclosing callable parameter default.
///
/// For `def run(Foo: type = Foo): Foo(bar=1)`, the body binding shadows the
/// imported class name. The structured default still proves which class the
/// keyword belongs to when the default callable is used.
pub fn resolve_callable_parameter_default_types(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    reference: Node<'_>,
    local_name: &str,
) -> Vec<CodeUnit> {
    let site_start = reference.start_byte();
    let site_end = reference.end_byte();
    let mut current = reference;
    while let Some(parent) = current.parent() {
        current = parent;
        if !matches!(current.kind(), "function_definition" | "lambda") {
            continue;
        }
        if current
            .child_by_field_name("body")
            .is_none_or(|body| !(body.start_byte() <= site_start && site_end <= body.end_byte()))
        {
            continue;
        }
        let Some(parameters) = current.child_by_field_name("parameters") else {
            return Vec::new();
        };
        let mut cursor = parameters.walk();
        for parameter in parameters.named_children(&mut cursor) {
            let name = if parameter.kind() == "identifier" {
                Some(parameter)
            } else {
                parameter.child_by_field_name("name")
            };
            if name.is_none_or(|name| node_text(name, source) != local_name) {
                continue;
            }
            let Some(value) = parameter.child_by_field_name("value") else {
                return Vec::new();
            };
            return resolve_constructor_types(graph, python, file, source, value);
        }
        return Vec::new();
    }
    Vec::new()
}

/// The declarations a namespace-qualified attribute path names (`module.Name`,
/// `pkg.module.Name`), walked structurally through the import binder.
///
/// No kind filter: a Python annotation legitimately names a module-level type
/// alias, `TypeAlias`, `NewType` or `TypeVar` value, all of which the analyzer
/// models as fields (issue #1763).
fn namespace_qualified_declarations(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Vec<CodeUnit> {
    let binder = python.import_binder_of(file);
    let Some(fqn) = namespace_constructor_fqn(&binder, source, node) else {
        return Vec::new();
    };
    let mut candidates =
        resolve_fqn_candidates(python, &fqn, |name| graph.index.definitions(name).collect());
    candidates.sort();
    candidates.dedup();
    candidates
}

fn namespace_constructor_fqn(
    binder: &ImportBinder,
    source: &str,
    function: Node<'_>,
) -> Option<String> {
    let mut attributes = Vec::new();
    let mut current = function;
    while current.kind() == "attribute" {
        let attribute = current.child_by_field_name("attribute")?;
        let text = node_text(attribute, source);
        if text.is_empty() {
            return None;
        }
        attributes.push(text);
        current = current.child_by_field_name("object")?;
    }
    if current.kind() != "identifier" {
        return None;
    }
    let root = node_text(current, source);
    let binding = binder.bindings.get(root)?;
    if binding.kind != ImportKind::Namespace {
        return None;
    }
    let mut fqn = binding.module_specifier.clone();
    for attribute in attributes.into_iter().rev() {
        fqn.push('.');
        fqn.push_str(attribute);
    }
    Some(fqn)
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::node_source_text(node, source)
}

fn resolve_indexed_receiver_type(
    graph: &PythonGraphSource<'_>,
    file: &ProjectFile,
    raw_type: &str,
) -> Option<CodeUnit> {
    let package_matches = module_fq_for_file(graph.index, file).map_or_else(Vec::new, |module| {
        relational_definitions(
            graph,
            RelationalName::stable(module),
            RelationalDefinitionQuery::PackageTypes {
                simple_name: raw_type.to_string(),
            },
        )
    });
    let mut root_name = FqName::new();
    root_name.push(segment_interner().intern(raw_type, SegmentKind::Type));
    let exact_matches = relational_definitions(
        graph,
        RelationalName::stable(root_name.clone()),
        RelationalDefinitionQuery::ExactName,
    );
    let normalized_matches = relational_definitions(
        graph,
        RelationalName::stable(root_name),
        RelationalDefinitionQuery::NormalizedName,
    );
    package_matches
        .into_iter()
        .chain(exact_matches)
        .chain(normalized_matches)
        .find(|code_unit| code_unit.identifier() == raw_type && code_unit.is_class())
}

fn relational_definitions(
    graph: &PythonGraphSource<'_>,
    name: RelationalName,
    query: RelationalDefinitionQuery,
) -> Vec<CodeUnit> {
    let question = RelationalDefinitionQuestion {
        // Python's graph owns Python declarations. Cross-language interop is
        // an explicit exact-FQN decision in the dispatching definition layer;
        // a workspace-wide normalized/simple-name query here would let an
        // unresolved Python annotation borrow an unrelated declaration from
        // another language.
        language_scope: DefinitionLanguageScope::Language(Language::Python),
        name,
        query,
    };
    match graph.definitions.ask(&question) {
        RelationalDefinitionValue::Definitions(units) => units,
        _ => panic!("definition question returned the wrong result shape"),
    }
}

fn module_fq_for_file(index: &dyn CodeUnitIndex, file: &ProjectFile) -> Option<FqName> {
    index
        .declarations(file)
        .into_iter()
        .find(|code_unit| code_unit.is_module())
        .map(|code_unit| code_unit.fq().clone())
        .or_else(|| {
            index
                .declarations(file)
                .into_iter()
                .find(|code_unit| !code_unit.package_name().is_empty())
                .map(|code_unit| code_unit.package_fq())
        })
}

pub fn normalized_receiver_type(annotation: &str) -> Option<String> {
    let annotation = unwrap_python_string_annotation(annotation.trim());
    let annotation = unwrap_supported_receiver_wrapper(annotation);
    if annotation.is_empty()
        || annotation.contains('|')
        || annotation.contains('[')
        || annotation.contains(']')
        || annotation.contains(',')
        || annotation.contains('(')
        || annotation.contains(')')
        || annotation.contains('{')
        || annotation.contains('}')
        || annotation.contains(':')
    {
        return None;
    }
    Some(annotation.to_string())
}

fn unwrap_python_string_annotation(annotation: &str) -> &str {
    if annotation.len() >= 2 {
        let bytes = annotation.as_bytes();
        let first = bytes[0];
        let last = bytes[annotation.len() - 1];
        if (first == b'\'' || first == b'"') && first == last {
            return annotation[1..annotation.len() - 1].trim();
        }
    }
    annotation
}

fn unwrap_supported_receiver_wrapper(annotation: &str) -> &str {
    let mut current = annotation.trim();
    loop {
        let next = current
            .strip_prefix("Optional[")
            .or_else(|| current.strip_prefix("typing.Optional["))
            .and_then(|inner| inner.strip_suffix(']'))
            .map(str::trim);
        let Some(unwrapped) = next else {
            return current;
        };
        current = unwrapped;
    }
}

pub fn receiver_annotation_matches_target(
    annotation: &str,
    edges: &[ImportEdge],
    target_short: &str,
    target_self_file: bool,
) -> bool {
    let annotation = annotation.trim();
    if annotation.is_empty() {
        return false;
    }
    if annotation.contains('|')
        || annotation.contains('[')
        || annotation.contains(']')
        || annotation.contains(',')
        || annotation.contains('(')
        || annotation.contains(')')
    {
        return false;
    }
    if annotation == target_short {
        return target_self_file || edges.iter().any(|edge| edge.local_name == target_short);
    }

    // `annotation` was already filtered above to exclude generics/unions/calls, so
    // it is a bare dotted qualifier (Python identifiers never embed a literal
    // `.`); re-tokenizing with the shared structured splitter and rejoining
    // every part but the last with `.` reproduces `rsplit_once('.')`'s
    // (qualifier, member) split exactly.
    let segments = parse_symbol_path(Language::Python, annotation);
    let Some((member, qualifier_parts)) = segments.split_last() else {
        return false;
    };
    if qualifier_parts.is_empty() {
        return false;
    }
    let qualifier = qualifier_parts.join(".");
    let member = member.as_str();
    if member != target_short {
        return false;
    }
    edges.iter().any(|edge| {
        matches!(edge.kind, ImportEdgeKind::Namespace)
            && (edge.local_name == qualifier
                || qualifier.ends_with(&format!(".{}", edge.local_name)))
    })
}

// Python module-name and relative-import resolution were lifted to the analyzer
// (`PythonAnalyzer::python_module_name` / `resolve_module_files`, see
// `analyzer::python::usage_index`); both usage paths now resolve through there.
