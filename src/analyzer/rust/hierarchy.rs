use super::RustAnalyzer;
use super::declarations::rust_node_text;
use super::imports::{resolve_rust_module_path_with_crate, rust_crate_root_package};
use super::lexical_scope::{parse_rust_tree, visible_import_binder_at};
use crate::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use crate::analyzer::usages::{ImportBinder, ImportKind};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, TypeHierarchyProvider};
use crate::hash::{HashMap, HashSet};
use tree_sitter::Node;

pub(super) struct RustHierarchyIndex {
    direct_ancestors: HashMap<CodeUnit, Vec<CodeUnit>>,
    direct_descendants: HashMap<CodeUnit, HashSet<CodeUnit>>,
    #[allow(dead_code)]
    relations: Vec<TypeRelation>,
}

impl TypeHierarchyProvider for RustAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if !self.supports_type_hierarchy(code_unit) || self.is_rust_trait_declaration(code_unit) {
            return Vec::new();
        }

        self.hierarchy_index()
            .direct_ancestors
            .get(code_unit)
            .cloned()
            .unwrap_or_default()
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        if !self.supports_type_hierarchy(code_unit) || !self.is_rust_trait_declaration(code_unit) {
            return HashSet::default();
        }

        self.hierarchy_index()
            .direct_descendants
            .get(code_unit)
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

    #[allow(dead_code)]
    pub(crate) fn type_relations(&self) -> &[TypeRelation] {
        self.type_relations
            .get_or_init(|| self.hierarchy_index().relations.clone())
            .as_slice()
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
        let lexical_package = lexical_package_name(file, impl_item, source);
        let mut candidates = Vec::new();

        if let Some((module_specifier, imported_name)) = normalized.rsplit_once("::") {
            candidates.extend(self.resolve_units_in_module(
                file,
                binder,
                &lexical_package,
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
        lexical_package: &str,
        module_specifier: &str,
        name: &str,
    ) -> Vec<CodeUnit> {
        let Some(resolved_package) =
            self.resolve_scoped_module_package(file, binder, lexical_package, module_specifier)
        else {
            return Vec::new();
        };
        let fq_name = join_rust_fqn(&resolved_package, name);
        let mut candidates: Vec<_> = self.definitions(&fq_name).collect();
        if !candidates.is_empty() {
            candidates.sort();
            candidates.dedup();
            return candidates;
        }

        let resolved_module = resolved_package.replace('.', "::");
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
                    .into_iter()
                    .filter(move |unit| unit.identifier() == name)
            }));
        }

        candidates.sort();
        candidates.dedup();
        candidates
    }

    fn resolve_scoped_module_package(
        &self,
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

    fn same_module_declarations(
        &self,
        file: &ProjectFile,
        source: &str,
        impl_item: Node<'_>,
        name: &str,
    ) -> Vec<CodeUnit> {
        let short_name = module_scoped_short_name(impl_item, source, name);
        self.declarations(file)
            .into_iter()
            .filter(|unit| unit.identifier() == name && unit.short_name() == short_name)
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
                    .into_iter()
                    .filter(move |unit| unit.identifier() == name)
            })
            .collect();
        units.sort();
        units.dedup();
        units
    }
}

impl RustHierarchyIndex {
    fn build(analyzer: &RustAnalyzer) -> Self {
        let mut direct_ancestors: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
        let mut direct_descendants: HashMap<CodeUnit, HashSet<CodeUnit>> = HashMap::default();
        let mut relations = Vec::new();

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
                let Some(implementer) = analyzer
                    .resolve_rust_hierarchy_type_ref(
                        &file,
                        &source,
                        impl_item,
                        &binder,
                        implementer_ref,
                    )
                    .and_then(|unit| analyzer.canonical_rust_hierarchy_type(unit))
                else {
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

impl RustAnalyzer {
    pub(crate) fn canonical_rust_hierarchy_type(&self, unit: CodeUnit) -> Option<CodeUnit> {
        if !self.is_rust_type_alias_declaration(&unit) {
            return Some(unit);
        }
        let source = self.project().read_source(unit.source()).ok()?;
        let tree = parse_rust_tree(&source)?;
        let alias_node = type_alias_node(tree.root_node(), &source, &unit)?;
        let target = type_alias_target_ref(alias_node, &source)
            .or_else(|| unit.signature().and_then(alias_target_text))?;
        let binder = visible_import_binder_at(&source, alias_node.start_byte());
        self.resolve_rust_hierarchy_ref(
            unit.source(),
            &source,
            alias_node,
            &binder,
            target,
            |candidate| {
                self.is_rust_struct_declaration(candidate)
                    || self.is_rust_enum_declaration(candidate)
            },
        )
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
    let file_package = super::declarations::rust_package_name(file);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::test_support::AnalyzerFixture;

    fn analyzer_with_files(files: &[(&str, &str)]) -> (AnalyzerFixture, RustAnalyzer) {
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, files);
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        (fixture, analyzer)
    }

    fn definition(analyzer: &RustAnalyzer, fq_name: &str) -> CodeUnit {
        analyzer
            .get_definitions(fq_name)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
    }

    fn has_trait_implementation_relation(analyzer: &RustAnalyzer, from: &str, to: &str) -> bool {
        analyzer.type_relations().iter().any(|relation| {
            relation.from.fq_name() == from
                && relation.to.fq_name() == to
                && relation.kind == TypeRelationKind::TraitImplementation
        })
    }

    #[test]
    fn rust_type_relations_record_same_file_trait_implementation() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Runnable {}
struct Worker;
impl Runnable for Worker {}
"#,
        )]);

        let runnable = definition(&analyzer, "Runnable");
        let worker = definition(&analyzer, "Worker");

        assert!(has_trait_implementation_relation(
            &analyzer, "Worker", "Runnable"
        ));
        assert_eq!(
            analyzer.get_direct_ancestors(&worker),
            vec![runnable.clone()]
        );
        assert!(analyzer.get_direct_descendants(&runnable).contains(&worker));
    }

    #[test]
    fn rust_type_relations_record_imported_trait_implementation() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            ("src/contracts.rs", "pub trait Runnable {}"),
            (
                "src/worker.rs",
                r#"
use crate::contracts::Runnable;
pub struct Worker;
impl Runnable for Worker {}
"#,
            ),
        ]);

        let runnable = definition(&analyzer, "contracts.Runnable");
        let worker = definition(&analyzer, "worker.Worker");

        assert!(has_trait_implementation_relation(
            &analyzer,
            "worker.Worker",
            "contracts.Runnable"
        ));
        assert_eq!(
            analyzer.get_direct_ancestors(&worker),
            vec![runnable.clone()]
        );
        assert!(analyzer.get_direct_descendants(&runnable).contains(&worker));
    }
}
