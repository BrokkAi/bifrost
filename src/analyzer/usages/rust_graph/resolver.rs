use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, Language, MultiAnalyzer, ProjectFile, RustAnalyzer,
};
use std::collections::BTreeSet;

pub(crate) fn resolve_rust_analyzer(analyzer: &dyn IAnalyzer) -> Option<&RustAnalyzer> {
    if let Some(rust) = (analyzer as &dyn std::any::Any).downcast_ref::<RustAnalyzer>() {
        return Some(rust);
    }

    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Rust) {
        Some(AnalyzerDelegate::Rust(rust)) => Some(rust),
        _ => None,
    }
}

pub(super) fn supports_same_file_local_scan(analyzer: &RustAnalyzer, target: &CodeUnit) -> bool {
    target.is_function() && analyzer.parent_of(target).is_none()
}

pub(super) fn is_member_target(analyzer: &RustAnalyzer, target: &CodeUnit) -> bool {
    (target.is_function() || target.is_field()) && analyzer.parent_of(target).is_some()
}

pub(super) fn is_trait_owner(rust: &RustAnalyzer, owner: &CodeUnit) -> bool {
    rust.is_rust_trait_declaration(owner)
}

fn is_public_like_declaration(rust: &RustAnalyzer, code_unit: &CodeUnit) -> bool {
    rust.is_rust_public_like_declaration(code_unit)
}

pub(super) fn is_graph_visible_member_target(rust: &RustAnalyzer, target: &CodeUnit) -> bool {
    if is_public_like_declaration(rust, target) {
        return true;
    }

    let Some(owner) = rust.parent_of(target) else {
        return false;
    };
    if !is_public_like_declaration(rust, &owner) {
        return false;
    }

    (rust.is_rust_trait_declaration(&owner) && target.is_function())
        || (rust.is_rust_enum_declaration(&owner) && target.is_field())
}

pub(super) fn infer_graph_seeds(
    analyzer: &RustAnalyzer,
    target: &CodeUnit,
) -> BTreeSet<(ProjectFile, String)> {
    let mut seeds = BTreeSet::new();
    let nested_module_target = analyzer
        .parent_of(target)
        .is_some_and(|parent| parent.is_module());
    for seed_name in infer_export_names(analyzer, target) {
        let resolved = analyzer.usage_seeds(target.source(), &seed_name);
        if resolved.is_empty() && nested_module_target {
            seeds.insert((target.source().clone(), seed_name));
        } else {
            seeds.extend(resolved);
        }
    }

    if seeds.is_empty()
        && let Some(parent) = analyzer.parent_of(target)
        && parent.is_module()
        && parent.source() != target.source()
        && is_public_like_declaration(analyzer, target)
    {
        let parent_index = analyzer.export_index_of(parent.source());
        if parent_index
            .exports_by_name
            .contains_key(target.identifier())
        {
            seeds.insert((parent.source().clone(), target.identifier().to_string()));
        }
    }

    seeds
}

fn infer_export_names(analyzer: &RustAnalyzer, target: &CodeUnit) -> BTreeSet<String> {
    if (target.is_function() || target.is_field())
        && let Some(owner) = analyzer.parent_of(target)
    {
        let owner_exports =
            infer_export_names_for_local(analyzer, owner.source(), owner.identifier());
        if !owner_exports.is_empty() {
            return owner_exports;
        }
    }

    let mut export_names =
        infer_export_names_for_local(analyzer, target.source(), target.identifier());
    if !export_names.is_empty() {
        return export_names;
    }

    if let Some(owner) = analyzer.parent_of(target)
        && owner.is_module()
        && owner.source() != target.source()
    {
        let parent_index = analyzer.export_index_of(owner.source());
        if parent_index
            .exports_by_name
            .contains_key(target.identifier())
        {
            export_names.insert(target.identifier().to_string());
        }
    }

    if target.is_function() && analyzer.parent_of(target).is_none() {
        return [target.identifier().to_string()].into_iter().collect();
    }

    BTreeSet::new()
}

fn infer_export_names_for_local(
    analyzer: &RustAnalyzer,
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

pub(super) fn unresolved_external_frontier_specifiers(
    analyzer: &RustAnalyzer,
    defining_file: &ProjectFile,
    export_name: &str,
) -> BTreeSet<String> {
    let mut frontier = BTreeSet::new();
    let index = analyzer.export_index_of(defining_file);

    if let Some(crate::analyzer::usages::ExportEntry::ReexportedNamed {
        module_specifier, ..
    }) = index.exports_by_name.get(export_name)
        && analyzer
            .resolve_module_files(defining_file, module_specifier)
            .is_empty()
        && let Some(external) = external_frontier_specifier(module_specifier)
    {
        frontier.insert(external);
    }

    for star in &index.reexport_stars {
        if analyzer
            .resolve_module_files(defining_file, &star.module_specifier)
            .is_empty()
            && let Some(external) = external_frontier_specifier(&star.module_specifier)
        {
            frontier.insert(external);
        }
    }

    frontier
}

fn external_frontier_specifier(module_specifier: &str) -> Option<String> {
    let root = module_specifier
        .split("::")
        .find(|segment| !segment.is_empty())?
        .trim();
    (!matches!(root, "crate" | "self" | "super") && !root.is_empty()).then(|| root.to_string())
}
