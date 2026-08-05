//! Python's reference resolution: export-name and seed inference, receiver-type
//! resolution, and annotation candidates.
//!
//! `index` arguments below are the *dispatching* analyzer's
//! [`CodeUnitIndex`] (see [`PythonGraphSource`]); `python` is the Python
//! analyzer's memoized products.

use crate::graph::PythonGraphSource;
use crate::graph_support::PythonUsageSource;
use crate::imports::resolve_fqn_candidates;
use crate::syntax::{python_deferred_annotation_identifier_ranges, python_node_is_in_annotation};
use crate::usage_index::usage_seeds;
use brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path;
use brokk_bifrost_core::analyzer::usages::model::{ExportEntry, ImportBinder, ImportKind};
use brokk_bifrost_core::analyzer::usages::{ImportEdge, ImportEdgeKind};
use brokk_bifrost_core::analyzer::{
    BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, Language, ProjectFile, Range,
};
use std::collections::BTreeSet;
use tree_sitter::Node;

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
    for (export_name, entry) in index.exports_by_name {
        if matches!(entry, ExportEntry::Local { local_name: ref name } if name == local_name) {
            export_names.insert(export_name);
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
    if raw_type.is_empty() || raw_type.contains('.') || raw_type.contains('|') {
        return None;
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
            .into_iter()
            .find(|code_unit| code_unit.identifier() == raw_type && code_unit.is_class())
    {
        return Some(imported);
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
            // The only reader of the analyzer's global definition index in this
            // crate, and the reason `PythonGraphSource::definitions` is a
            // callback: the index builds on first access, so resolving it
            // eagerly per scan would pay for a build this branch usually skips.
            let mut resolved = None;
            (graph.definitions)(&mut |support| {
                resolved = resolve_indexed_receiver_type(graph.index, support, file, raw_type);
            });
            resolved
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
        let owner_candidates = exact_owner_annotation_members(graph, &owner, raw_symbol);
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
        candidates.extend(resolve_fqn_candidates(python, &fqn, |name| {
            graph.index.definitions(name).collect()
        }));
    }

    candidates.extend(
        graph
            .index
            .top_level_declarations(file)
            .into_iter()
            .filter(|code_unit| !code_unit.is_module() && code_unit.identifier() == raw_symbol),
    );

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
    if !is_annotation_reference_node(node) {
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

fn resolve_annotation_attribute_types(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Vec<CodeUnit> {
    // Preserve the established namespace-import path (`module.Type`) while
    // adding owner-qualified nested classes (`Outer.Inner`). The constructor
    // resolver already understands module/re-export bindings; it simply cannot
    // interpret a class as the namespace for another class.
    let mut candidates = resolve_constructor_types(graph, python, file, source, node);
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

fn is_annotation_reference_node(node: Node<'_>) -> bool {
    if !matches!(node.kind(), "identifier" | "attribute" | "string_content") {
        return false;
    }
    python_node_is_in_annotation(node)
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
    let binder = python.import_binder_of(file);
    let fqn = match function.kind() {
        "identifier" => {
            let local = node_text(function, source);
            if local.is_empty() {
                return Vec::new();
            }
            match binder.bindings.get(local) {
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
            }
        }
        "attribute" => namespace_constructor_fqn(&binder, source, function),
        _ => None,
    };
    let Some(fqn) = fqn else {
        return Vec::new();
    };
    let mut classes: Vec<CodeUnit> =
        resolve_fqn_candidates(python, &fqn, |name| graph.index.definitions(name).collect())
            .into_iter()
            .filter(CodeUnit::is_class)
            .collect();
    classes.sort();
    classes.dedup();
    classes
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
    index: &dyn CodeUnitIndex,
    lookup: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    raw_type: &str,
) -> Option<CodeUnit> {
    module_fqn_for_file(index, file)
        .into_iter()
        .flat_map(|module| lookup.types_in_package(&module, raw_type))
        .chain(lookup.fqn(raw_type))
        .chain(lookup.by_normalized_fqn(raw_type))
        .find(|code_unit| code_unit.identifier() == raw_type && code_unit.is_class())
}

fn module_fqn_for_file(index: &dyn CodeUnitIndex, file: &ProjectFile) -> Option<String> {
    index
        .declarations(file)
        .into_iter()
        .find(|code_unit| code_unit.is_module())
        .map(|code_unit| code_unit.fq_name())
        .or_else(|| {
            index
                .declarations(file)
                .into_iter()
                .find(|code_unit| !code_unit.package_name().is_empty())
                .map(|code_unit| code_unit.package_name().to_string())
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
