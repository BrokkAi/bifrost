use crate::analyzer::usages::graph_core::{ImportEdge, ImportEdgeKind};
use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, Language, MultiAnalyzer, ProjectFile, PythonAnalyzer,
};
use std::collections::BTreeSet;
use std::path::Path;

pub(super) fn resolve_python_analyzer(analyzer: &dyn IAnalyzer) -> Option<&PythonAnalyzer> {
    if let Some(py) = (analyzer as &dyn std::any::Any).downcast_ref::<PythonAnalyzer>() {
        return Some(py);
    }

    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Python) {
        Some(AnalyzerDelegate::Python(py)) => Some(py),
        _ => None,
    }
}

pub(super) fn infer_export_names(analyzer: &PythonAnalyzer, target: &CodeUnit) -> BTreeSet<String> {
    if (target.is_function() || target.is_field())
        && let Some(owner_name) = owner_name(target)
    {
        let owner_exports = infer_export_names_for_local(analyzer, target.source(), &owner_name);
        if !owner_exports.is_empty() {
            return owner_exports;
        }
    }

    infer_export_names_for_local(analyzer, target.source(), target.identifier())
}

fn infer_export_names_for_local(
    analyzer: &PythonAnalyzer,
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
    export_names
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

pub(super) fn resolve_receiver_type(
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
        .get_declarations(file)
        .into_iter()
        .find(|code_unit| code_unit.identifier() == raw_type && code_unit.is_class())
        .or_else(|| {
            if !target_self_file {
                return None;
            }
            analyzer
                .get_all_declarations()
                .into_iter()
                .find(|code_unit| code_unit.identifier() == raw_type && code_unit.is_class())
        })
}

pub(super) fn normalized_receiver_type(annotation: &str) -> Option<String> {
    let annotation = unwrap_supported_receiver_wrapper(annotation.trim());
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

pub(super) fn python_module_name(file: &ProjectFile) -> String {
    python_module_info(file).module_qualified_package()
}

struct PythonModuleInfo {
    package_name: String,
    module_name: String,
}

impl PythonModuleInfo {
    fn module_qualified_package(&self) -> String {
        if self.package_name.is_empty() {
            self.module_name.clone()
        } else {
            format!("{}.{}", self.package_name, self.module_name)
        }
    }
}

fn python_module_info(file: &ProjectFile) -> PythonModuleInfo {
    let raw_package = python_package_name_for_file(file);
    let module_name = file
        .rel_path()
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default()
        .to_string();

    if module_name == "__init__" && !raw_package.is_empty() {
        if let Some((package_name, last_segment)) = raw_package.rsplit_once('.') {
            return PythonModuleInfo {
                package_name: package_name.to_string(),
                module_name: last_segment.to_string(),
            };
        }
        return PythonModuleInfo {
            package_name: String::new(),
            module_name: raw_package,
        };
    }

    PythonModuleInfo {
        package_name: raw_package,
        module_name,
    }
}

fn python_package_name_for_file(file: &ProjectFile) -> String {
    let Some(parent_rel) = file.rel_path().parent() else {
        return String::new();
    };
    if parent_rel.as_os_str().is_empty() {
        return String::new();
    }

    let mut effective_package_root_rel: Option<&Path> = None;
    let mut current_rel = Some(parent_rel);
    while let Some(path) = current_rel {
        if file.root().join(path).join("__init__.py").exists() {
            effective_package_root_rel = Some(path);
        }
        current_rel = path.parent();
    }

    let Some(package_root_rel) = effective_package_root_rel else {
        return dotted_path(parent_rel);
    };

    let Some(import_root_rel) = package_root_rel.parent() else {
        return dotted_path(parent_rel);
    };

    dotted_path(
        import_root_rel
            .strip_prefix("")
            .ok()
            .and_then(|_| parent_rel.strip_prefix(import_root_rel).ok())
            .unwrap_or(parent_rel),
    )
}

fn dotted_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

pub(super) fn resolve_python_relative_module(
    source_file: &ProjectFile,
    module_expr: &str,
) -> Option<String> {
    let level = module_expr.chars().take_while(|ch| *ch == '.').count();
    let suffix = module_expr[level..].trim_matches('.');
    let current_package = python_current_package(source_file);
    let mut parts: Vec<_> = current_package
        .split('.')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect();
    if level == 0 {
        return Some(module_expr.to_string());
    }
    if level > 0 {
        if level - 1 > parts.len() {
            return None;
        }
        parts.truncate(parts.len() - (level - 1));
    }
    if !suffix.is_empty() {
        parts.extend(suffix.split('.').map(str::to_string));
    }
    Some(parts.join("."))
}

fn python_current_package(source_file: &ProjectFile) -> String {
    let module = python_module_name(source_file);
    if source_file
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
        == Some("__init__.py")
    {
        module
    } else {
        module
            .rsplit_once('.')
            .map(|(package, _)| package.to_string())
            .unwrap_or_default()
    }
}
