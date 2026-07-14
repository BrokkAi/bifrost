use super::*;
use crate::analyzer::build_direct_descendant_index;
use std::sync::Arc;

impl RubyAnalyzer {
    /// Resolves a raw supertype name (a superclass or an
    /// `include`/`prepend`/`extend` argument) to a declared type.
    ///
    /// The visitor already renders supertype names into the internal `$`-joined
    /// key form, so a fully-qualified reference resolves directly. Relative
    /// references (e.g. `Comparable` named inside a namespace) fall back to
    /// matching the trailing identifier across all declared types.
    pub(super) fn resolve_supertype(&self, raw: &str) -> Option<CodeUnit> {
        let cleaned = raw.trim();
        if cleaned.is_empty() {
            return None;
        }

        if let Some(found) = self.inner.definitions(cleaned).next() {
            return Some(found.clone());
        }

        let last_segment = cleaned.rsplit('$').next().unwrap_or(cleaned);
        self.types_by_identifier()
            .get(last_segment)
            .and_then(|types| types.first())
            .cloned()
    }

    /// Lazily indexes class/module declarations by trailing identifier so the
    /// relative-supertype fallback is an O(1) lookup instead of a full
    /// `all_declarations` scan per unresolved supertype.
    fn types_by_identifier(&self) -> &HashMap<String, Vec<CodeUnit>> {
        self.types_by_identifier.get_or_init(|| {
            let mut index: HashMap<String, Vec<CodeUnit>> = HashMap::default();
            for code_unit in self.inner.all_declarations() {
                if code_unit.is_class() || code_unit.is_module() {
                    index
                        .entry(code_unit.identifier().to_string())
                        .or_default()
                        .push(code_unit.clone());
                }
            }
            index
        })
    }
}

impl TypeHierarchyProvider for RubyAnalyzer {
    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        code_unit.is_class() || code_unit.is_module()
    }

    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors: Vec<_> = self
            .forward_superclass_targets(code_unit)
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
            .get(code_unit)
            .map(|descendants| descendants.as_ref().clone())
            .unwrap_or_default();
        self.direct_descendants
            .insert(code_unit.clone(), Arc::new(descendants.clone()));
        descendants
    }
}
