use super::RustAnalyzer;
use super::lexical_scope::{parse_rust_tree, visible_import_binder_at};
use crate::analyzer::usages::{ImportBinder, ImportKind};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, TypeHierarchyProvider};
use crate::hash::{HashMap, HashSet};
use tree_sitter::Node;

pub(super) struct RustHierarchyIndex {
    direct_ancestors: HashMap<String, Vec<CodeUnit>>,
    direct_descendants: HashMap<String, HashSet<CodeUnit>>,
}

impl TypeHierarchyProvider for RustAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if !self.supports_type_hierarchy(code_unit) || self.is_rust_trait_declaration(code_unit) {
            return Vec::new();
        }

        self.hierarchy_index()
            .direct_ancestors
            .get(&code_unit.fq_name())
            .cloned()
            .unwrap_or_default()
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        if !self.supports_type_hierarchy(code_unit) || !self.is_rust_trait_declaration(code_unit) {
            return HashSet::default();
        }

        self.hierarchy_index()
            .direct_descendants
            .get(&code_unit.fq_name())
            .cloned()
            .unwrap_or_default()
    }

    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        self.is_rust_trait_declaration(code_unit)
            || self.is_rust_struct_declaration(code_unit)
            || self.is_rust_enum_declaration(code_unit)
            || self.is_rust_type_alias_declaration(code_unit)
    }
}

impl RustAnalyzer {
    fn hierarchy_index(&self) -> &RustHierarchyIndex {
        self.hierarchy_index
            .get_or_init(|| RustHierarchyIndex::build(self))
    }

    fn resolve_rust_hierarchy_trait_ref(
        &self,
        file: &ProjectFile,
        source: &str,
        impl_item: Node<'_>,
        binder: &ImportBinder,
        raw: &str,
    ) -> Option<CodeUnit> {
        self.resolve_rust_hierarchy_ref(file, source, impl_item, binder, raw, |unit| {
            self.is_rust_trait_declaration(unit)
        })
    }

    fn resolve_rust_hierarchy_type_ref(
        &self,
        file: &ProjectFile,
        source: &str,
        impl_item: Node<'_>,
        binder: &ImportBinder,
        raw: &str,
    ) -> Option<CodeUnit> {
        self.resolve_rust_hierarchy_ref(file, source, impl_item, binder, raw, |unit| {
            self.is_rust_struct_declaration(unit)
                || self.is_rust_enum_declaration(unit)
                || self.is_rust_type_alias_declaration(unit)
        })
    }

    fn resolve_rust_hierarchy_ref<F>(
        &self,
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
        let mut candidates = Vec::new();

        if let Some((module_specifier, imported_name)) = normalized.rsplit_once("::") {
            candidates.extend(self.resolve_units_in_module(
                file,
                binder,
                module_specifier,
                imported_name,
            ));
        } else {
            candidates.extend(self.same_module_declarations(file, source, impl_item, normalized));
            candidates.extend(self.imported_units(file, binder, normalized));
        }

        let mut matches = candidates.into_iter().filter(predicate);
        let resolved = matches.next()?;
        matches.next().is_none().then_some(resolved)
    }

    fn resolve_units_in_module(
        &self,
        file: &ProjectFile,
        binder: &ImportBinder,
        module_specifier: &str,
        name: &str,
    ) -> Vec<CodeUnit> {
        let resolved_module = self.resolve_scoped_module_specifier(binder, module_specifier);
        let mut candidates = Vec::new();
        let module_files = self.resolve_module_files(file, &resolved_module);
        candidates.extend(
            self.units_from_export_targets(
                self.exported_targets_from_files(&module_files, name)
                    .into_iter(),
            ),
        );

        if candidates.is_empty() {
            candidates.extend(module_files.iter().flat_map(|module_file| {
                self.declarations(module_file)
                    .filter(move |unit| unit.identifier() == name)
                    .cloned()
            }));
        }

        if let Some(package) = self.resolve_module_package(file, &resolved_module) {
            let fq_name = if package.is_empty() {
                name.to_string()
            } else {
                format!("{package}.{name}")
            };
            candidates.extend(self.definitions(&fq_name).cloned());
        }

        candidates.sort();
        candidates.dedup();
        candidates
    }

    fn resolve_scoped_module_specifier(
        &self,
        binder: &ImportBinder,
        module_specifier: &str,
    ) -> String {
        let Some((head, tail)) = module_specifier.split_once("::") else {
            return binder
                .bindings
                .get(module_specifier)
                .filter(|binding| matches!(binding.kind, ImportKind::Namespace))
                .map(|binding| binding.module_specifier.clone())
                .unwrap_or_else(|| module_specifier.to_string());
        };
        binder
            .bindings
            .get(head)
            .filter(|binding| matches!(binding.kind, ImportKind::Namespace))
            .map(|binding| format!("{}::{tail}", binding.module_specifier))
            .unwrap_or_else(|| module_specifier.to_string())
    }

    fn same_module_declarations(
        &self,
        file: &ProjectFile,
        source: &str,
        impl_item: Node<'_>,
        name: &str,
    ) -> Vec<CodeUnit> {
        let short_name = module_scoped_short_name(impl_item, source, name);
        self.declarations(file)
            .filter(|unit| unit.identifier() == name && unit.short_name() == short_name)
            .cloned()
            .collect()
    }

    fn imported_units(
        &self,
        file: &ProjectFile,
        binder: &ImportBinder,
        reference: &str,
    ) -> Vec<CodeUnit> {
        let targets = self.resolve_imported_export_from_binder(file, binder, reference);
        self.units_from_export_targets(targets.into_iter())
    }

    fn units_from_export_targets(
        &self,
        targets: impl Iterator<Item = (ProjectFile, String)>,
    ) -> Vec<CodeUnit> {
        let mut units: Vec<_> = targets
            .flat_map(|(file, name)| {
                self.declarations(&file)
                    .filter(move |unit| unit.identifier() == name)
                    .cloned()
            })
            .collect();
        units.sort();
        units.dedup();
        units
    }
}

impl RustHierarchyIndex {
    fn build(analyzer: &RustAnalyzer) -> Self {
        let mut direct_ancestors: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        let mut direct_descendants: HashMap<String, HashSet<CodeUnit>> = HashMap::default();

        for file in analyzer.get_analyzed_files() {
            let Ok(source) = analyzer.project().read_source(&file) else {
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
                let Some(trait_unit) = analyzer.resolve_rust_hierarchy_trait_ref(
                    &file, &source, impl_item, &binder, trait_ref,
                ) else {
                    continue;
                };
                let Some(implementer) = analyzer.resolve_rust_hierarchy_type_ref(
                    &file,
                    &source,
                    impl_item,
                    &binder,
                    implementer_ref,
                ) else {
                    continue;
                };

                let ancestors = direct_ancestors.entry(implementer.fq_name()).or_default();
                if !ancestors.contains(&trait_unit) {
                    ancestors.push(trait_unit.clone());
                }
                direct_descendants
                    .entry(trait_unit.fq_name())
                    .or_default()
                    .insert(implementer);
            }
        }

        Self {
            direct_ancestors,
            direct_descendants,
        }
    }
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
    Some((node_text(trait_node, source), node_text(type_node, source)))
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

fn module_scoped_short_name(impl_item: Node<'_>, source: &str, name: &str) -> String {
    let mut modules = Vec::new();
    let mut current = impl_item.parent();
    while let Some(parent) = current {
        if parent.kind() == "mod_item"
            && let Some(name_node) = parent.child_by_field_name("name")
        {
            modules.push(node_text(name_node, source).to_string());
        }
        current = parent.parent();
    }
    modules.reverse();
    if modules.is_empty() {
        name.to_string()
    } else {
        format!("{}.{}", modules.join("."), name)
    }
}

fn node_text<'source>(node: Node<'_>, source: &'source str) -> &'source str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim()
}
