use crate::declarations::rust_node_text;
use crate::graph_support::{
    RustUsageSource, is_rust_enum_declaration, is_rust_struct_declaration,
    is_rust_trait_declaration, is_rust_type_alias_declaration, resolve_imported_export_from_binder,
    resolve_module_files, rust_named_declaration_node,
};
use crate::imports::{resolve_rust_module_path_with_crate, rust_crate_root_package};
use crate::lexical_scope::{parse_rust_tree, visible_import_binder_at};
use crate::usage_index::exported_targets_from_files;
use brokk_bifrost_core::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use brokk_bifrost_core::analyzer::usages::model::{ImportBinder, ImportKind};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

pub struct RustHierarchyIndex {
    pub direct_ancestors: HashMap<CodeUnit, Vec<CodeUnit>>,
    pub direct_descendants: HashMap<CodeUnit, HashSet<CodeUnit>>,
    pub relations: Vec<TypeRelation>,
}

pub fn rust_trait_for_impl_member(
    rust: &dyn RustUsageSource,
    member: &CodeUnit,
) -> Option<CodeUnit> {
    let source = rust.project().read_source(member.source()).ok()?;
    let tree = parse_rust_tree(&source)?;
    let declaration =
        rust_named_declaration_node(rust.code_units(), member, tree.root_node(), &source)?;
    let mut ancestor = declaration.parent();
    let impl_item = loop {
        let candidate = ancestor?;
        if candidate.kind() == "impl_item" {
            break candidate;
        }
        ancestor = candidate.parent();
    };
    let (trait_ref, _) = trait_impl_parts(impl_item, &source)?;
    let binder = visible_import_binder_at(&source, impl_item.start_byte());
    resolve_rust_hierarchy_trait_ref(
        rust,
        member.source(),
        &source,
        impl_item,
        &binder,
        trait_ref,
    )
}

pub fn resolve_rust_hierarchy_trait_ref(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    source: &str,
    impl_item: Node<'_>,
    binder: &ImportBinder,
    raw: &str,
) -> Option<CodeUnit> {
    resolve_rust_hierarchy_ref(rust, file, source, impl_item, binder, raw, |unit| {
        is_rust_trait_declaration(rust.code_units(), unit)
    })
}

pub fn resolve_rust_hierarchy_type_ref(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    source: &str,
    impl_item: Node<'_>,
    binder: &ImportBinder,
    raw: &str,
) -> Option<CodeUnit> {
    resolve_rust_hierarchy_ref(rust, file, source, impl_item, binder, raw, |unit| {
        is_rust_struct_declaration(rust.code_units(), unit)
            || is_rust_enum_declaration(rust.code_units(), unit)
            || is_rust_type_alias_declaration(rust.code_units(), unit)
    })
}

pub fn resolve_rust_hierarchy_ref<F>(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    source: &str,
    impl_item: Node<'_>,
    binder: &ImportBinder,
    raw: &str,
    predicate: F,
) -> Option<CodeUnit>
where
    F: Fn(&CodeUnit) -> bool,
{
    let normalized = normalize_type_ref(raw)?;
    let lexical_package = lexical_package_name(file, impl_item, source);
    let mut candidates = Vec::new();

    if let Some((module_specifier, imported_name)) = normalized.rsplit_once("::") {
        candidates.extend(resolve_units_in_module(
            rust,
            file,
            binder,
            &lexical_package,
            module_specifier,
            imported_name,
        ));
    } else {
        candidates.extend(same_module_declarations(
            rust, file, source, impl_item, normalized,
        ));
        candidates.extend(imported_units(rust, file, binder, normalized));
    }

    let mut matches = candidates.into_iter().filter(predicate);
    let resolved = matches.next()?;
    matches.next().is_none().then_some(resolved)
}

pub fn resolve_units_in_module(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    binder: &ImportBinder,
    lexical_package: &str,
    module_specifier: &str,
    name: &str,
) -> Vec<CodeUnit> {
    let Some(resolved_package) =
        resolve_scoped_module_package(file, binder, lexical_package, module_specifier)
    else {
        return Vec::new();
    };
    let fq_name = join_rust_fqn(&resolved_package, name);
    let mut candidates: Vec<_> = rust.definitions(&fq_name).collect();
    if !candidates.is_empty() {
        candidates.sort();
        candidates.dedup();
        return candidates;
    }

    let resolved_module = resolved_package.replace('.', "::");
    let mut candidates = Vec::new();
    let module_files = resolve_module_files(rust, file, &resolved_module);
    candidates.extend(units_from_export_targets(
        rust,
        exported_targets_from_files(rust, &module_files, name).into_iter(),
    ));

    if candidates.is_empty() {
        candidates.extend(module_files.iter().flat_map(|module_file| {
            rust.declarations(module_file)
                .into_iter()
                .filter(move |unit| unit.identifier() == name)
        }));
    }

    candidates.sort();
    candidates.dedup();
    candidates
}

fn resolve_scoped_module_package(
    file: &ProjectFile,
    binder: &ImportBinder,
    lexical_package: &str,
    module_specifier: &str,
) -> Option<String> {
    let expanded = if let Some((head, tail)) = module_specifier.split_once("::") {
        binder
            .bindings
            .get(head)
            .filter(|binding| matches!(binding.kind, ImportKind::Namespace))
            .map(|binding| format!("{}::{tail}", binding.module_specifier))
            .unwrap_or_else(|| module_specifier.to_string())
    } else {
        binder
            .bindings
            .get(module_specifier)
            .filter(|binding| matches!(binding.kind, ImportKind::Namespace))
            .map(|binding| binding.module_specifier.clone())
            .unwrap_or_else(|| module_specifier.to_string())
    };
    let crate_package = rust_crate_root_package(file);
    resolve_rust_module_path_with_crate(lexical_package, &crate_package, &expanded)
}

pub fn same_module_declarations(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    source: &str,
    impl_item: Node<'_>,
    name: &str,
) -> Vec<CodeUnit> {
    let short_name = module_scoped_short_name(impl_item, source, name);
    rust.declarations(file)
        .into_iter()
        .filter(|unit| unit.identifier() == name && unit.short_name() == short_name)
        .collect()
}

pub fn imported_units(
    rust: &dyn RustUsageSource,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
) -> Vec<CodeUnit> {
    let targets = resolve_imported_export_from_binder(rust, file, binder, reference);
    units_from_export_targets(rust, targets.into_iter())
}

pub fn units_from_export_targets(
    rust: &dyn RustUsageSource,
    targets: impl Iterator<Item = (ProjectFile, String)>,
) -> Vec<CodeUnit> {
    let mut units: Vec<_> = targets
        .flat_map(|(file, name)| {
            rust.declarations(&file)
                .into_iter()
                .filter(move |unit| unit.identifier() == name)
        })
        .collect();
    units.sort();
    units.dedup();
    units
}

impl RustHierarchyIndex {
    pub fn build(rust: &dyn RustUsageSource) -> Self {
        let mut direct_ancestors: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
        let mut direct_descendants: HashMap<CodeUnit, HashSet<CodeUnit>> = HashMap::default();
        let mut relations = Vec::new();

        for file in rust.get_analyzed_files() {
            let Ok(source) = rust.project().read_source(&file) else {
                continue;
            };
            let Some(tree) = parse_rust_tree(&source) else {
                continue;
            };
            for impl_item in impl_items(tree.root_node()) {
                let Some((trait_ref, implementer_ref)) = trait_impl_parts(impl_item, &source)
                else {
                    continue;
                };
                let binder = visible_import_binder_at(&source, impl_item.start_byte());
                let Some(trait_unit) = resolve_rust_hierarchy_trait_ref(
                    rust, &file, &source, impl_item, &binder, trait_ref,
                ) else {
                    continue;
                };
                let Some(implementer) = resolve_rust_hierarchy_type_ref(
                    rust,
                    &file,
                    &source,
                    impl_item,
                    &binder,
                    implementer_ref,
                )
                .and_then(|unit| canonical_rust_hierarchy_type(rust, unit)) else {
                    continue;
                };

                let ancestors = direct_ancestors.entry(implementer.clone()).or_default();
                if !ancestors.contains(&trait_unit) {
                    ancestors.push(trait_unit.clone());
                }
                direct_descendants
                    .entry(trait_unit.clone())
                    .or_default()
                    .insert(implementer.clone());
                relations.push(TypeRelation {
                    from: implementer,
                    to: trait_unit,
                    kind: TypeRelationKind::TraitImplementation,
                });
            }
        }

        Self {
            direct_ancestors,
            direct_descendants,
            relations,
        }
    }
}

pub fn canonical_rust_hierarchy_type(
    rust: &dyn RustUsageSource,
    unit: CodeUnit,
) -> Option<CodeUnit> {
    if !is_rust_type_alias_declaration(rust.code_units(), &unit) {
        return Some(unit);
    }
    let source = rust.project().read_source(unit.source()).ok()?;
    let tree = parse_rust_tree(&source)?;
    let alias_node = type_alias_node(tree.root_node(), &source, &unit)?;
    let target = type_alias_target_ref(alias_node, &source)
        .or_else(|| unit.signature().and_then(alias_target_text))?;
    let binder = visible_import_binder_at(&source, alias_node.start_byte());
    resolve_rust_hierarchy_ref(
        rust,
        unit.source(),
        &source,
        alias_node,
        &binder,
        target,
        |candidate| {
            is_rust_struct_declaration(rust.code_units(), candidate)
                || is_rust_enum_declaration(rust.code_units(), candidate)
        },
    )
}

fn impl_items(root: Node<'_>) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "impl_item" {
            out.push(node);
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    out
}

fn trait_impl_parts<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Option<(&'source str, &'source str)> {
    let trait_node = node.child_by_field_name("trait")?;
    let type_node = node.child_by_field_name("type")?;
    Some((
        rust_node_text(trait_node, source).trim(),
        rust_node_text(type_node, source).trim(),
    ))
}

fn normalize_type_ref(raw: &str) -> Option<&str> {
    let mut value = raw.trim().trim_start_matches('&').trim();
    while let Some(stripped) = value.strip_prefix("mut ") {
        value = stripped.trim();
    }
    if let Some(index) = value.find('<') {
        value = &value[..index];
    }
    if value.is_empty() { None } else { Some(value) }
}

fn alias_target_text(signature: &str) -> Option<&str> {
    let rhs = signature
        .split_once('=')?
        .1
        .trim()
        .trim_end_matches(';')
        .trim();
    normalize_type_ref(rhs)
}

fn lexical_package_name(file: &ProjectFile, impl_item: Node<'_>, source: &str) -> String {
    let file_package = crate::declarations::rust_package_name(file);
    let mut modules = inline_module_path(impl_item, source);
    if file_package.is_empty() {
        modules.join(".")
    } else if modules.is_empty() {
        file_package
    } else {
        modules.insert(0, file_package);
        modules.join(".")
    }
}

fn module_scoped_short_name(impl_item: Node<'_>, source: &str, name: &str) -> String {
    let modules = inline_module_path(impl_item, source);
    if modules.is_empty() {
        name.to_string()
    } else {
        format!("{}.{}", modules.join("."), name)
    }
}

fn inline_module_path(impl_item: Node<'_>, source: &str) -> Vec<String> {
    let mut modules = Vec::new();
    let mut current = impl_item.parent();
    while let Some(parent) = current {
        if parent.kind() == "mod_item"
            && let Some(name_node) = parent.child_by_field_name("name")
        {
            modules.push(rust_node_text(name_node, source).trim().to_string());
        }
        current = parent.parent();
    }
    modules.reverse();
    modules
}

fn join_rust_fqn(package: &str, name: &str) -> String {
    if package.is_empty() {
        name.to_string()
    } else {
        format!("{package}.{name}")
    }
}

fn type_alias_node<'tree>(
    root: Node<'tree>,
    source: &str,
    alias: &CodeUnit,
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "type_item"
            && let Some(name_node) = node.child_by_field_name("name")
        {
            let name = rust_node_text(name_node, source).trim();
            if module_scoped_short_name(node, source, name) == alias.short_name() {
                return Some(node);
            }
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    None
}

fn type_alias_target_ref<'source>(
    alias_node: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    let target_node = alias_node.child_by_field_name("type")?;
    normalize_type_ref(rust_node_text(target_node, source).trim())
}
