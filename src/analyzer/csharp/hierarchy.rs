use super::*;
use crate::analyzer::build_direct_descendant_index;
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttributeClassEvidence {
    Proven,
    DefinitelyNot,
    Unknown,
}

enum AttributeTypeResolution {
    Unresolved,
    Resolved(Vec<CodeUnit>),
    Ambiguous(Vec<CodeUnit>),
}

impl CSharpAnalyzer {
    /// Resolve the two C# attribute-name forms, retaining only declarations
    /// that are proven to derive from `System.Attribute` or whose external
    /// ancestry is unavailable. Indexed declarations proven not to be
    /// attributes must not steal an attribute shorthand reference.
    pub(crate) fn attribute_type_candidates_with_ambiguity(
        &self,
        file: &ProjectFile,
        names: &[String],
    ) -> (Vec<CodeUnit>, bool) {
        match self.attribute_type_resolution(file, names) {
            AttributeTypeResolution::Unresolved => (Vec::new(), false),
            AttributeTypeResolution::Resolved(candidates) => (candidates, false),
            AttributeTypeResolution::Ambiguous(candidates) => (candidates, true),
        }
    }

    /// Inverse usage proof requires one logical attribute type. An ambiguous
    /// annotation is not a proven reference to every declaration it might name.
    pub(crate) fn unambiguous_attribute_type_candidates(
        &self,
        file: &ProjectFile,
        names: &[String],
    ) -> Vec<CodeUnit> {
        match self.attribute_type_resolution(file, names) {
            AttributeTypeResolution::Resolved(candidates) => candidates,
            AttributeTypeResolution::Unresolved | AttributeTypeResolution::Ambiguous(_) => {
                Vec::new()
            }
        }
    }

    fn attribute_type_resolution(
        &self,
        file: &ProjectFile,
        names: &[String],
    ) -> AttributeTypeResolution {
        let mut candidates = Vec::new();
        let mut successful_spellings = 0usize;
        for name in names {
            let visible = self.visible_type_candidates(file, name);
            // C# suppresses errors from each of the two attribute spellings
            // independently. An ambiguous spelling contributes no candidate;
            // the other spelling can still resolve uniquely.
            if self.logical_type_count(&visible) != 1 {
                continue;
            }
            let applicable = visible
                .into_iter()
                .filter(|candidate| {
                    self.attribute_class_evidence(candidate)
                        != AttributeClassEvidence::DefinitelyNot
                })
                .collect::<Vec<_>>();
            if !applicable.is_empty() {
                successful_spellings += 1;
                candidates.extend(applicable);
            }
        }
        self.sort_type_candidates(&mut candidates);
        candidates.dedup();
        match (successful_spellings, self.logical_type_count(&candidates)) {
            (0, _) | (_, 0) => AttributeTypeResolution::Unresolved,
            (1, 1) => AttributeTypeResolution::Resolved(candidates),
            _ => AttributeTypeResolution::Ambiguous(candidates),
        }
    }

    fn attribute_class_evidence(&self, candidate: &CodeUnit) -> AttributeClassEvidence {
        const ATTRIBUTE_FQN: &str = "System.Attribute";

        let mut stack = vec![candidate.clone()];
        let mut seen = HashSet::default();
        let mut unresolved_ancestry = false;
        let mut decisive_non_attribute_base = false;
        while let Some(current) = stack.pop() {
            let current_fqn = current.fq_name();
            if !seen.insert(current_fqn.clone()) {
                continue;
            }
            if csharp_normalize_full_name(&current_fqn) == ATTRIBUTE_FQN {
                return AttributeClassEvidence::Proven;
            }

            let mut parts = self.partial_type_parts(&current);
            if parts.is_empty() {
                parts.push(current);
            }
            for part in parts {
                for raw in self.inner.raw_supertypes_of(&part) {
                    let normalized_raw = csharp_normalize_full_name(&raw);
                    if normalized_raw == ATTRIBUTE_FQN {
                        return AttributeClassEvidence::Proven;
                    }
                    if matches!(normalized_raw.as_str(), "object" | "System.Object") {
                        decisive_non_attribute_base = true;
                        continue;
                    }
                    let ancestors = self.visible_type_candidates(part.source(), &raw);
                    if ancestors.is_empty() {
                        unresolved_ancestry = true;
                        continue;
                    }
                    if self.logical_type_count(&ancestors) > 1 {
                        unresolved_ancestry = true;
                        continue;
                    }
                    stack.extend(ancestors);
                }
            }
        }

        if decisive_non_attribute_base {
            AttributeClassEvidence::DefinitelyNot
        } else if unresolved_ancestry {
            AttributeClassEvidence::Unknown
        } else {
            AttributeClassEvidence::DefinitelyNot
        }
    }
}

impl TypeHierarchyProvider for CSharpAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.memo_caches.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors: Vec<_> = self
            .inner
            .raw_supertypes_of(code_unit)
            .iter()
            .filter_map(|raw| self.resolve_visible_type(code_unit.source(), raw))
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

        let descendants = self
            .memo_caches
            .direct_descendant_index
            .get_or_init(|| build_direct_descendant_index(self, self))
            .get(code_unit)
            .map(|descendants| descendants.as_ref().clone())
            .unwrap_or_default();
        self.memo_caches
            .direct_descendants
            .insert(code_unit.clone(), Arc::new(descendants.clone()));
        descendants
    }
}
