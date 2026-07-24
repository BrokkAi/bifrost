use crate::analyzer::usages::graph_core::{ImportEdge, ImportEdgeKind};
use crate::analyzer::usages::model::{ImportBinder, ImportKind};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, PythonAnalyzer};
use std::collections::BTreeSet;
use tree_sitter::Node;

pub(super) fn infer_export_names(analyzer: &PythonAnalyzer, target: &CodeUnit) -> BTreeSet<String> {
    if target_owner_code_unit(analyzer, target).is_some() {
        let owner_name = top_level_identifier(analyzer, target);
        let owner_exports =
            infer_export_names_for_local(analyzer, target, target.source(), &owner_name);
        if !owner_exports.is_empty() {
            return owner_exports;
        }
    }

    infer_export_names_for_local(analyzer, target, target.source(), target.identifier())
}

pub(super) fn infer_usage_seeds(
    analyzer: &PythonAnalyzer,
    target: &CodeUnit,
    seed_names: BTreeSet<String>,
) -> BTreeSet<(ProjectFile, String)> {
    let mut seeds = BTreeSet::new();
    for seed_name in &seed_names {
        seeds.extend(analyzer.usage_seeds(target.source(), seed_name));
    }
    if seeds.is_empty()
        && seed_names.contains(target.identifier())
        && is_module_level_target_identifier(analyzer, target, target.source(), target.identifier())
    {
        seeds.insert((target.source().clone(), target.identifier().to_string()));
    }
    seeds
}

fn infer_export_names_for_local(
    analyzer: &PythonAnalyzer,
    target: &CodeUnit,
    file: &ProjectFile,
    local_name: &str,
) -> BTreeSet<String> {
    let index = analyzer.export_index_of(file);
    let mut export_names = BTreeSet::new();
    if index.exports_by_name.contains_key(local_name) {
        export_names.insert(local_name.to_string());
    }
    for (export_name, entry) in index.exports_by_name {
        if matches!(entry, crate::analyzer::usages::ExportEntry::Local { local_name: ref name } if name == local_name)
        {
            export_names.insert(export_name);
        }
    }
    if export_names.is_empty()
        && is_module_level_target_identifier(analyzer, target, file, local_name)
    {
        export_names.insert(local_name.to_string());
    }
    export_names
}

fn is_module_level_target_identifier(
    analyzer: &PythonAnalyzer,
    target: &CodeUnit,
    file: &ProjectFile,
    local_name: &str,
) -> bool {
    target.source() == file
        && target.identifier() == local_name
        && analyzer
            .parent_of(target)
            .is_some_and(|parent| parent.is_module() && parent.source() == file)
}

pub(super) fn top_level_identifier(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> String {
    let mut current = target.clone();
    while let Some(parent) = analyzer.parent_of(&current) {
        if parent.is_module() {
            break;
        }
        current = parent;
    }
    current.identifier().to_string()
}

pub(super) fn member_name(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> Option<String> {
    target_owner_code_unit(analyzer, target).map(|_| target.identifier().to_string())
}

pub(super) fn target_owner_code_unit(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
) -> Option<CodeUnit> {
    analyzer
        .parent_of(target)
        .filter(|parent| parent.source() == target.source() && parent.is_class())
}

pub(in crate::analyzer::usages) fn resolve_receiver_type(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    file: &ProjectFile,
    raw_type: &str,
    target_self_file: bool,
) -> Option<CodeUnit> {
    let raw_type = raw_type.trim();
    if raw_type.is_empty() || raw_type.contains('.') || raw_type.contains('|') {
        return None;
    }

    if let Some(binding) = py.import_binder_of(file).bindings.get(raw_type)
        && binding.kind == ImportKind::Named
        && let Some(imported) = binding.imported_name.as_ref()
    {
        let fqn = format!("{}.{}", binding.module_specifier, imported);
        if let Some(class) = py
            .resolve_fqn_candidates(&fqn, |name| analyzer.definitions(name).collect())
            .into_iter()
            .find(CodeUnit::is_class)
        {
            return Some(class);
        }
    }

    if let Some(provider) = analyzer.import_analysis_provider()
        && let Some(imported) = provider
            .imported_code_units_of(file)
            .into_iter()
            .find(|code_unit| code_unit.identifier() == raw_type && code_unit.is_class())
    {
        return Some(imported);
    }

    analyzer
        .declarations(file)
        .into_iter()
        .find(|code_unit| code_unit.identifier() == raw_type && code_unit.is_class())
        .or_else(|| {
            if !target_self_file {
                return None;
            }
            resolve_indexed_receiver_type(analyzer, file, raw_type)
        })
}

/// Resolve a class reference written in a structured Python annotation.
///
/// Only AST nodes that occur inside a function return type, parameter type, or
/// annotated-assignment type are considered. In particular, string contents are
/// accepted only in those annotation positions; arbitrary string literals are
/// never interpreted as type expressions.
pub(in crate::analyzer::usages) fn annotation_reference_candidates(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    target_self_file: bool,
) -> Option<Vec<CodeUnit>> {
    if !is_annotation_reference_node(node) {
        return None;
    }
    eprintln!("ANNOTATION {:?} {:?}", node.kind(), node_text(node, source));

    let mut candidates = match node.kind() {
        "identifier" | "string_content" => resolve_receiver_type(
            analyzer,
            py,
            file,
            node_text(node, source),
            target_self_file,
        )
        .into_iter()
        .collect(),
        "attribute" => resolve_constructor_types(analyzer, py, file, source, node),
        _ => Vec::new(),
    };
    candidates.sort();
    candidates.dedup();
    Some(candidates)
}

fn is_annotation_reference_node(node: Node<'_>) -> bool {
    if !matches!(node.kind(), "identifier" | "attribute" | "string_content") {
        return false;
    }

    let start = node.start_byte();
    let end = node.end_byte();
    let mut current = node;
    while let Some(parent) = current.parent() {
        let annotation = match parent.kind() {
            "function_definition" => parent.child_by_field_name("return_type"),
            "typed_parameter" | "typed_default_parameter" | "assignment" => {
                parent.child_by_field_name("type")
            }
            _ => None,
        };
        if let Some(annotation) = annotation
            && annotation.start_byte() <= start
            && end <= annotation.end_byte()
        {
            return true;
        }
        current = parent;
    }
    false
}

/// Resolve the class constructed by a Python call callee without interpreting
/// source text. Bare callees use the import binder or same-file declarations;
/// qualified callees walk tree-sitter's `attribute` fields back to a namespace
/// import and append each attribute component structurally.
pub(in crate::analyzer::usages) fn resolve_constructor_types(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
) -> Vec<CodeUnit> {
    let binder = py.import_binder_of(file);
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
                _ => analyzer
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
    let mut classes: Vec<CodeUnit> = py
        .resolve_fqn_candidates(&fqn, |name| analyzer.definitions(name).collect())
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
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn resolve_indexed_receiver_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    raw_type: &str,
) -> Option<CodeUnit> {
    let index = analyzer.global_usage_definition_index();
    module_fqn_for_file(analyzer, file)
        .into_iter()
        .flat_map(|module| index.types_in_package(&module, raw_type).iter())
        .chain(index.by_fqn(raw_type).iter())
        .chain(index.by_normalized_fqn(raw_type).iter())
        .find(|code_unit| code_unit.identifier() == raw_type && code_unit.is_class())
        .cloned()
}

fn module_fqn_for_file(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Option<String> {
    analyzer
        .declarations(file)
        .into_iter()
        .find(|code_unit| code_unit.is_module())
        .map(|code_unit| code_unit.fq_name())
        .or_else(|| {
            analyzer
                .declarations(file)
                .into_iter()
                .find(|code_unit| !code_unit.package_name().is_empty())
                .map(|code_unit| code_unit.package_name().to_string())
        })
}

pub(super) fn normalized_receiver_type(annotation: &str) -> Option<String> {
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

pub(super) fn receiver_annotation_matches_target(
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

    let Some((qualifier, member)) = annotation.rsplit_once('.') else {
        return false;
    };
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
