use super::*;
use crate::analyzer::build_direct_descendant_index;

impl CppAnalyzer {
    fn resolve_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if !code_unit.is_class() || self.is_type_alias(code_unit) {
            return Vec::new();
        }

        let visible = self.visible_type_units(code_unit.source());
        let mut ancestors = Vec::new();
        for raw in self.inner.raw_supertypes_of(code_unit) {
            if let Some(ancestor) = self.resolve_base_type(code_unit, &raw, &visible)
                && !ancestors.iter().any(|existing| existing == &ancestor)
            {
                ancestors.push(ancestor);
            }
        }
        ancestors
    }

    fn visible_type_units(&self, file: &ProjectFile) -> Arc<Vec<CodeUnit>> {
        self.visible_type_units_by_file.get_with_by_ref(file, || {
            let include_targets = self.include_target_index();
            let mut visited = HashSet::default();
            let mut declarations = Vec::new();
            let mut pending = vec![file.clone()];
            visited.insert(file.clone());

            while let Some(current) = pending.pop() {
                declarations.extend(
                    self.declarations(&current)
                        .into_iter()
                        .filter(|unit| unit.is_class() || self.is_type_alias(unit)),
                );

                let imports = self.inner.import_statements(&current);
                for include in include_paths(&imports) {
                    for target in
                        resolve_include_targets_with_index(&current, &include, include_targets)
                    {
                        if visited.insert(target.clone()) {
                            pending.push(target);
                        }
                    }
                }
            }

            declarations.sort();
            declarations.dedup();
            Arc::new(declarations)
        })
    }

    fn resolve_base_type(
        &self,
        code_unit: &CodeUnit,
        raw: &str,
        visible: &[CodeUnit],
    ) -> Option<CodeUnit> {
        let normalized = normalize_cpp_type_reference(raw)?;
        let resolved = if normalized.contains("::") {
            visible
                .iter()
                .find(|candidate| cpp_name_for(candidate) == normalized)
        } else {
            self.resolve_unqualified_base(code_unit, &normalized, visible)
        }?;
        self.canonicalize_alias(resolved, visible, &mut HashSet::default())
    }

    fn resolve_unqualified_base<'a>(
        &self,
        code_unit: &CodeUnit,
        name: &str,
        visible: &'a [CodeUnit],
    ) -> Option<&'a CodeUnit> {
        for namespace in namespace_search_order(code_unit.package_name()) {
            if let Some(candidate) = visible.iter().find(|candidate| {
                candidate.identifier() == name && candidate.package_name() == namespace
            }) {
                return Some(candidate);
            }
        }

        visible
            .iter()
            .find(|candidate| candidate.identifier() == name)
    }

    fn canonicalize_alias(
        &self,
        unit: &CodeUnit,
        visible: &[CodeUnit],
        seen: &mut HashSet<String>,
    ) -> Option<CodeUnit> {
        if !self.is_type_alias(unit) {
            return Some(unit.clone());
        }
        if !seen.insert(unit.fq_name()) {
            return None;
        }
        let target = alias_target_text(unit)?;
        let resolved = if target.contains("::") {
            visible
                .iter()
                .find(|candidate| cpp_name_for(candidate) == target)
        } else {
            visible
                .iter()
                .find(|candidate| {
                    candidate.identifier() == target
                        && candidate.package_name() == unit.package_name()
                })
                .or_else(|| {
                    visible
                        .iter()
                        .find(|candidate| candidate.identifier() == target)
                })
        }?;
        self.canonicalize_alias(resolved, visible, seen)
    }
}

impl TypeHierarchyProvider for CppAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.direct_ancestors
            .get_with_by_ref(code_unit, || {
                Arc::new(self.resolve_direct_ancestors(code_unit))
            })
            .as_ref()
            .clone()
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        self.direct_descendant_index
            .get_or_init(|| build_direct_descendant_index(self, self))
            .descendants(code_unit)
    }
}

fn namespace_search_order(package_name: &str) -> Vec<&str> {
    let mut namespaces = Vec::new();
    let mut current = package_name;
    loop {
        namespaces.push(current);
        let Some((parent, _)) = current.rsplit_once("::") else {
            if !current.is_empty() {
                namespaces.push("");
            }
            return namespaces;
        };
        current = parent;
    }
}

fn alias_target_text(alias: &CodeUnit) -> Option<String> {
    let signature = alias.signature()?.trim();
    let target = signature
        .strip_prefix("using ")
        .and_then(|rest| rest.split_once('=').map(|(_, rhs)| rhs))
        .or_else(|| {
            signature
                .strip_prefix("typedef ")
                .and_then(|rest| rest.rsplit_once(' ').map(|(lhs, _)| lhs))
        })?
        .trim()
        .trim_end_matches(';');
    normalize_cpp_type_reference(target)
}

fn normalize_cpp_type_reference(value: &str) -> Option<String> {
    let mut text = normalize_cpp_whitespace(value)
        .trim_start_matches("new ")
        .trim()
        .to_string();
    if let Some(index) = text.find(['(', '{']) {
        text.truncate(index);
    }
    if let Some(index) = text.find('<') {
        text.truncate(index);
    }
    let normalized = text
        .trim()
        .trim_start_matches("const ")
        .trim_end_matches(|ch: char| ch == '*' || ch == '&' || ch.is_whitespace())
        .trim_matches(':')
        .trim();
    let normalized = normalized
        .strip_prefix("struct ")
        .or_else(|| normalized.strip_prefix("class "))
        .or_else(|| normalized.strip_prefix("enum "))
        .unwrap_or(normalized)
        .trim();
    (!normalized.is_empty()).then(|| normalized.to_string())
}

fn cpp_name_for(unit: &CodeUnit) -> String {
    let short = unit.short_name().replace(['.', '$'], "::");
    if unit.package_name().is_empty() {
        short
    } else {
        format!("{}::{}", unit.package_name(), short)
    }
}
