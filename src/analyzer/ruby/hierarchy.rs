use super::*;
use crate::analyzer::build_direct_descendant_index;
use std::sync::Arc;

impl RubyAnalyzer {
    /// Resolves a raw supertype string (a superclass or an
    /// `include`/`prepend`/`extend` argument) to a declared type.
    ///
    /// Ruby supertypes are written with `::` namespaces (`A::B`); internally
    /// types are keyed with `$` separators, so we first try the direct
    /// translation and fall back to matching the trailing identifier across all
    /// declared types (covers relative references like `Comparable`).
    pub(super) fn resolve_supertype(&self, raw: &str) -> Option<CodeUnit> {
        let cleaned = raw.trim().trim_start_matches("::");
        if cleaned.is_empty() {
            return None;
        }

        let fq_candidate = cleaned.replace("::", "$");
        if let Some(found) = self.inner.definitions(&fq_candidate).next() {
            return Some(found.clone());
        }

        let last_segment = cleaned.rsplit("::").next().unwrap_or(cleaned);
        self.inner
            .all_declarations()
            .find(|code_unit| {
                (code_unit.is_class() || code_unit.is_module())
                    && code_unit.identifier() == last_segment
            })
            .cloned()
    }
}

impl TypeHierarchyProvider for RubyAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors: Vec<_> = self
            .inner
            .raw_supertypes_of(code_unit)
            .iter()
            .filter_map(|raw| self.resolve_supertype(raw))
            .collect();
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
