use super::*;
use crate::analyzer::direct_descendants_via_ancestors;
use std::sync::Arc;

impl TypeHierarchyProvider for JavaAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.memo_caches.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors: Vec<_> = self
            .inner
            .raw_supertypes_of(code_unit)
            .iter()
            .filter_map(|raw_name| self.resolve_type_name(code_unit.source(), raw_name))
            .collect();
        self.memo_caches
            .direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        if let Some(cached) = self.memo_caches.direct_descendants.get(code_unit) {
            return (*cached).clone();
        }

        let descendants = direct_descendants_via_ancestors(self, self, code_unit);
        self.memo_caches
            .direct_descendants
            .insert(code_unit.clone(), Arc::new(descendants.clone()));
        descendants
    }
}
