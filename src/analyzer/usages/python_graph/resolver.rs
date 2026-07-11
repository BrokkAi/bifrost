use crate::analyzer::usages::graph_core::{ImportEdge, ImportEdgeKind};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, PythonAnalyzer};
use std::collections::BTreeSet;

pub(super) fn infer_export_names(analyzer: &PythonAnalyzer, target: &CodeUnit) -> BTreeSet<String> {
    if (target.is_function() || target.is_field())
        && let Some(owner_name) = owner_name(target)
    {
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

fn owner_name(target: &CodeUnit) -> Option<String> {
    let short_name = target.short_name();
    let last_dot = short_name.rfind('.')?;
    (last_dot > 0).then(|| short_name[..last_dot].to_string())
}

pub(super) fn top_level_identifier(target: &CodeUnit) -> &str {
    target
        .short_name()
        .split('.')
        .next()
        .unwrap_or(target.short_name())
}

pub(super) fn member_name(target: &CodeUnit) -> Option<String> {
    let parts: Vec<&str> = target.short_name().split('.').collect();
    (parts.len() > 1).then(|| parts.last().unwrap().to_string())
}

pub(super) fn target_owner_code_unit(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
) -> Option<CodeUnit> {
    let owner_name = top_level_identifier(target);
    let owner_fq = if target.package_name().is_empty() {
        owner_name.to_string()
    } else {
        format!("{}.{}", target.package_name(), owner_name)
    };
    analyzer
        .get_definitions(&owner_fq)
        .into_iter()
        .find(|code_unit| code_unit.source() == target.source() && code_unit.is_class())
}

pub(in crate::analyzer::usages) fn resolve_receiver_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    raw_type: &str,
    target_self_file: bool,
) -> Option<CodeUnit> {
    let raw_type = raw_type.trim();
    if raw_type.is_empty() || raw_type.contains('.') || raw_type.contains('|') {
        return None;
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

fn resolve_indexed_receiver_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    raw_type: &str,
) -> Option<CodeUnit> {
    let index = analyzer.definition_lookup_index();
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
