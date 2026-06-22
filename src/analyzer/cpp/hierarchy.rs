use super::*;
use crate::analyzer::build_direct_descendant_index;

impl CppAnalyzer {
    fn build_direct_ancestor_index(&self) -> HashMap<String, Arc<Vec<CodeUnit>>> {
        let mut visible_by_file = HashMap::default();
        let mut index = HashMap::default();

        for code_unit in self.all_declarations().filter(|unit| unit.is_class()) {
            if self.is_type_alias(code_unit) {
                continue;
            }
            let visible = self.visible_type_units(code_unit.source(), &mut visible_by_file);
            let mut ancestors = Vec::new();
            for raw in self.inner.raw_supertypes_of(code_unit) {
                if let Some(ancestor) = self.resolve_base_type(code_unit, raw, &visible)
                    && !ancestors.iter().any(|existing| existing == &ancestor)
                {
                    ancestors.push(ancestor);
                }
            }
            if !ancestors.is_empty() {
                index.insert(code_unit.fq_name(), Arc::new(ancestors));
            }
        }

        index
    }

    fn visible_type_units(
        &self,
        file: &ProjectFile,
        cache: &mut HashMap<ProjectFile, Arc<Vec<CodeUnit>>>,
    ) -> Arc<Vec<CodeUnit>> {
        if let Some(cached) = cache.get(file) {
            return cached.clone();
        }

        let mut visited = HashSet::default();
        let mut declarations = Vec::new();
        self.collect_visible_type_units(file, &mut visited, &mut declarations);
        declarations.sort();
        declarations.dedup();

        let declarations = Arc::new(declarations);
        cache.insert(file.clone(), declarations.clone());
        declarations
    }

    fn collect_visible_type_units(
        &self,
        file: &ProjectFile,
        visited: &mut HashSet<ProjectFile>,
        out: &mut Vec<CodeUnit>,
    ) {
        if !visited.insert(file.clone()) {
            return;
        }

        out.extend(
            self.get_declarations(file)
                .into_iter()
                .filter(|unit| unit.is_class() || self.is_type_alias(unit)),
        );

        for include in include_paths(self.inner.import_statements(file)) {
            for target in
                resolve_include_targets_with_unique_fallback(self.project(), file, &include)
            {
                self.collect_visible_type_units(&target, visited, out);
            }
        }
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
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors = self
            .direct_ancestor_index
            .get_or_init(|| self.build_direct_ancestor_index())
            .get(&code_unit.fq_name())
            .map(|ancestors| ancestors.as_ref().clone())
            .unwrap_or_default();
        self.direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        if let Some(cached) = self.direct_descendants.get(code_unit) {
            return (*cached).clone();
        }

        let descendants = self
            .direct_descendant_index
            .get_or_init(|| build_direct_descendant_index(self, self))
            .get(&code_unit.fq_name())
            .map(|descendants| descendants.as_ref().clone())
            .unwrap_or_default();
        self.direct_descendants
            .insert(code_unit.clone(), Arc::new(descendants.clone()));
        descendants
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
