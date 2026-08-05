//! Ruby's `TypeHierarchyProvider` impl: the memo shell around
//! [`brokk_bifrost_ruby::hierarchy`].

use super::*;
use crate::analyzer::build_direct_descendant_index;
use brokk_bifrost_ruby::hierarchy::{
    build_ruby_types_by_identifier, ruby_direct_ancestors, ruby_supports_type_hierarchy,
};
use std::sync::Arc;

impl RubyAnalyzer {
    pub(super) fn types_by_identifier(&self) -> &HashMap<String, Vec<CodeUnit>> {
        self.types_by_identifier
            .get_or_init(|| build_ruby_types_by_identifier(self))
    }
}

impl TypeHierarchyProvider for RubyAnalyzer {
    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        ruby_supports_type_hierarchy(code_unit)
    }

    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors = ruby_direct_ancestors(self, code_unit);
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
