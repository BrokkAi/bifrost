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

    pub(crate) fn attribute_type_candidates_with_lookups<Visible, Evidence>(
        &self,
        names: &[String],
        visible_type_candidates: &mut Visible,
        attribute_class_is_applicable: &mut Evidence,
    ) -> Option<(Vec<CodeUnit>, bool)>
    where
        Visible: FnMut(&str) -> Option<Vec<CodeUnit>>,
        Evidence: FnMut(&CodeUnit) -> Option<bool>,
    {
        match self.attribute_type_resolution_with_lookups(
            names,
            visible_type_candidates,
            attribute_class_is_applicable,
        )? {
            AttributeTypeResolution::Unresolved => Some((Vec::new(), false)),
            AttributeTypeResolution::Resolved(candidates) => Some((candidates, false)),
            AttributeTypeResolution::Ambiguous(candidates) => Some((candidates, true)),
        }
    }

    /// Inverse usage proof requires one logical attribute type. An ambiguous
    /// annotation is not a proven reference to every declaration it might name.
    pub(crate) fn usage_unambiguous_attribute_type_candidates(
        &self,
        file: &ProjectFile,
        names: &[String],
    ) -> Vec<CodeUnit> {
        match self.attribute_type_resolution_inner(file, names, true) {
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
        self.attribute_type_resolution_inner(file, names, false)
    }

    fn attribute_type_resolution_inner(
        &self,
        file: &ProjectFile,
        names: &[String],
        usage: bool,
    ) -> AttributeTypeResolution {
        let mut visible_type_candidates = |name: &str| {
            Some(if usage {
                self.usage_visible_type_candidates(file, name)
            } else {
                self.visible_type_candidates(file, name)
            })
        };
        let mut attribute_class_is_applicable = |candidate: &CodeUnit| {
            Some(
                self.attribute_class_evidence(candidate, usage)
                    != AttributeClassEvidence::DefinitelyNot,
            )
        };
        self.attribute_type_resolution_with_lookups(
            names,
            &mut visible_type_candidates,
            &mut attribute_class_is_applicable,
        )
        .unwrap_or(AttributeTypeResolution::Unresolved)
    }

    fn attribute_type_resolution_with_lookups<Visible, Evidence>(
        &self,
        names: &[String],
        visible_type_candidates: &mut Visible,
        attribute_class_is_applicable: &mut Evidence,
    ) -> Option<AttributeTypeResolution>
    where
        Visible: FnMut(&str) -> Option<Vec<CodeUnit>>,
        Evidence: FnMut(&CodeUnit) -> Option<bool>,
    {
        let mut candidates = Vec::new();
        let mut successful_spellings = 0usize;
        for name in names {
            let visible = visible_type_candidates(name)?;
            // C# suppresses errors from each of the two attribute spellings
            // independently. An ambiguous spelling contributes no candidate;
            // the other spelling can still resolve uniquely.
            if self.logical_type_count(&visible) != 1 {
                continue;
            }
            let applicable = visible
                .into_iter()
                .map(|candidate| {
                    attribute_class_is_applicable(&candidate)
                        .map(|applicable| applicable.then_some(candidate))
                })
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            if !applicable.is_empty() {
                successful_spellings += 1;
                candidates.extend(applicable);
            }
        }
        self.sort_type_candidates(&mut candidates);
        candidates.dedup();
        Some(
            match (successful_spellings, self.logical_type_count(&candidates)) {
                (0, _) | (_, 0) => AttributeTypeResolution::Unresolved,
                (1, 1) => AttributeTypeResolution::Resolved(candidates),
                _ => AttributeTypeResolution::Ambiguous(candidates),
            },
        )
    }

    fn attribute_class_evidence(
        &self,
        candidate: &CodeUnit,
        usage: bool,
    ) -> AttributeClassEvidence {
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

            let mut parts = if usage {
                self.usage_partial_type_parts(&current)
            } else {
                self.partial_type_parts(&current)
            };
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
                    let ancestors = if usage {
                        self.usage_visible_type_candidates(part.source(), &raw)
                    } else {
                        self.visible_type_candidates(part.source(), &raw)
                    };
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

    pub(crate) fn usage_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.logical_direct_ancestors(code_unit, true)
    }

    fn logical_direct_ancestors(&self, code_unit: &CodeUnit, usage: bool) -> Vec<CodeUnit> {
        let mut parts = if usage {
            self.usage_partial_type_parts(code_unit)
        } else {
            self.partial_type_parts(code_unit)
        };
        if parts.is_empty() {
            parts.push(code_unit.clone());
        }

        let mut ancestors = Vec::new();
        for part in parts {
            ancestors.extend(
                self.inner
                    .raw_supertypes_of(&part)
                    .iter()
                    .filter_map(|raw| {
                        if usage {
                            self.resolve_usage_visible_type(part.source(), raw)
                        } else {
                            self.resolve_visible_type(part.source(), raw)
                        }
                    }),
            );
        }
        self.sort_dedup_type_candidates(&mut ancestors);
        ancestors
    }
}

impl TypeHierarchyProvider for CSharpAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.memo_caches.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors = self.logical_direct_ancestors(code_unit, false);
        self.memo_caches
            .direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        self.memo_caches
            .direct_descendant_index
            .get_or_init(|| build_direct_descendant_index(self, self))
            .descendants(code_unit)
    }
}
