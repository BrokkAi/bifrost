use super::*;
use crate::analyzer::build_direct_descendant_index;
use std::sync::Arc;

impl TypeHierarchyProvider for PythonAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors: Vec<_> = self
            .inner
            .raw_supertypes_of(code_unit)
            .iter()
            .filter_map(|raw| self.resolve_base_class(code_unit, raw))
            .collect();
        self.direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        self.direct_descendant_index
            .get_or_init(|| build_direct_descendant_index(self, self))
            .descendants(code_unit)
    }
}
