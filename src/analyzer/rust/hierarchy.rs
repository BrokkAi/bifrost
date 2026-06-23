use super::RustAnalyzer;
use super::lexical_scope::parse_rust_tree;
use crate::analyzer::usages::{ImportBinder, ImportKind};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, TypeHierarchyProvider};
use crate::hash::HashSet;
use tree_sitter::Node;

impl TypeHierarchyProvider for RustAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if !self.supports_type_hierarchy(code_unit) || self.is_rust_trait_declaration(code_unit) {
            return Vec::new();
        }

        let Ok(source) = self.project().read_source(code_unit.source()) else {
            return Vec::new();
        };
        let Some(tree) = parse_rust_tree(&source) else {
            return Vec::new();
        };

        let binder = self.import_binder_of(code_unit.source());
        let mut ancestors = Vec::new();
        let mut seen = HashSet::default();
        for impl_item in impl_items(tree.root_node()) {
            let Some((trait_ref, implementer_ref)) = trait_impl_parts(impl_item, &source) else {
                continue;
            };
            let Some(implementer) =
                self.resolve_rust_hierarchy_type_ref(code_unit.source(), &binder, implementer_ref)
            else {
                continue;
            };
            if implementer != *code_unit {
                continue;
            }
            let Some(trait_unit) =
                self.resolve_rust_hierarchy_trait_ref(code_unit.source(), &binder, trait_ref)
            else {
                continue;
            };
            if seen.insert(trait_unit.fq_name()) {
                ancestors.push(trait_unit);
            }
        }
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        if !self.supports_type_hierarchy(code_unit) || !self.is_rust_trait_declaration(code_unit) {
            return HashSet::default();
        }

        let mut descendants = HashSet::default();
        for file in self.get_analyzed_files() {
            let Ok(source) = self.project().read_source(&file) else {
                continue;
            };
            let Some(tree) = parse_rust_tree(&source) else {
                continue;
            };
            let binder = self.import_binder_of(&file);
            for impl_item in impl_items(tree.root_node()) {
                let Some((trait_ref, implementer_ref)) = trait_impl_parts(impl_item, &source)
                else {
                    continue;
                };
                let Some(trait_unit) =
                    self.resolve_rust_hierarchy_trait_ref(&file, &binder, trait_ref)
                else {
                    continue;
                };
                if trait_unit != *code_unit {
                    continue;
                }
                if let Some(implementer) =
                    self.resolve_rust_hierarchy_type_ref(&file, &binder, implementer_ref)
                {
                    descendants.insert(implementer);
                }
            }
        }
        descendants
    }

    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        self.is_rust_trait_declaration(code_unit)
            || self.is_rust_struct_declaration(code_unit)
            || self.is_rust_enum_declaration(code_unit)
            || self.is_rust_type_alias_declaration(code_unit)
    }
}

impl RustAnalyzer {
    fn resolve_rust_hierarchy_trait_ref(
        &self,
        file: &ProjectFile,
        binder: &ImportBinder,
        raw: &str,
    ) -> Option<CodeUnit> {
        self.resolve_rust_hierarchy_ref(file, binder, raw, |unit| {
            self.is_rust_trait_declaration(unit)
        })
    }

    fn resolve_rust_hierarchy_type_ref(
        &self,
        file: &ProjectFile,
        binder: &ImportBinder,
        raw: &str,
    ) -> Option<CodeUnit> {
        self.resolve_rust_hierarchy_ref(file, binder, raw, |unit| {
            self.is_rust_struct_declaration(unit)
                || self.is_rust_enum_declaration(unit)
                || self.is_rust_type_alias_declaration(unit)
        })
    }

    fn resolve_rust_hierarchy_ref<F>(
        &self,
        file: &ProjectFile,
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
            candidates.extend(self.resolve_units_in_module(file, module_specifier, imported_name));
        } else {
            candidates.extend(
                self.declarations(file)
                    .filter(|unit| unit.identifier() == normalized)
                    .cloned(),
            );

            if let Some(binding) = binder.bindings.get(normalized) {
                match binding.kind {
                    ImportKind::Named | ImportKind::Namespace => {
                        let imported_name = binding.imported_name.as_deref().unwrap_or(normalized);
                        candidates.extend(self.resolve_units_in_module(
                            file,
                            &binding.module_specifier,
                            imported_name,
                        ));
                    }
                    ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => {}
                }
            } else {
                for binding in binder.bindings.values() {
                    if matches!(binding.kind, ImportKind::Glob) {
                        candidates.extend(self.resolve_units_in_module(
                            file,
                            &binding.module_specifier,
                            normalized,
                        ));
                    }
                }
            }
        }

        candidates.sort();
        candidates.dedup();
        let mut matches = candidates.into_iter().filter(predicate);
        let resolved = matches.next()?;
        matches.next().is_none().then_some(resolved)
    }

    fn resolve_units_in_module(
        &self,
        file: &ProjectFile,
        module_specifier: &str,
        name: &str,
    ) -> Vec<CodeUnit> {
        let mut candidates = Vec::new();
        for module_file in self.resolve_module_files(file, module_specifier) {
            candidates.extend(
                self.declarations(&module_file)
                    .filter(|unit| unit.identifier() == name)
                    .cloned(),
            );
        }

        if let Some(package) = self.resolve_module_package(file, module_specifier) {
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

fn node_text<'source>(node: Node<'_>, source: &'source str) -> &'source str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim()
}
