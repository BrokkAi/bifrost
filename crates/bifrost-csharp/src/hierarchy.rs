//! C#'s attribute-type resolution and direct-ancestor walk.
//!
//! `analyzer/csharp/hierarchy_provider.rs` in `brokk-bifrost-analysis` keeps the
//! `TypeHierarchyProvider` impl and the two memo cells behind it (the
//! `direct_ancestors` moka cache and the `direct_descendant_index`
//! `OnceLock`); deciding whether a candidate really is an attribute class, and
//! which declarations a type derives from, is language knowledge and lives
//! here.

use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::HashSet;

use crate::graph_support::{
    CSharpAnalysisSource, logical_type_count, partial_type_parts, resolve_usage_visible_type,
    resolve_visible_type, sort_dedup_type_candidates, sort_type_candidates,
    usage_partial_type_parts, usage_visible_type_candidates, visible_type_candidates,
};
use crate::syntax::csharp_normalize_full_name;

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

/// Resolve the two C# attribute-name forms, retaining only declarations
/// that are proven to derive from `System.Attribute` or whose external
/// ancestry is unavailable. Indexed declarations proven not to be
/// attributes must not steal an attribute shorthand reference.
pub fn attribute_type_candidates_with_ambiguity(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
    names: &[String],
) -> (Vec<CodeUnit>, bool) {
    match attribute_type_resolution(source, file, names) {
        AttributeTypeResolution::Unresolved => (Vec::new(), false),
        AttributeTypeResolution::Resolved(candidates) => (candidates, false),
        AttributeTypeResolution::Ambiguous(candidates) => (candidates, true),
    }
}

pub fn attribute_type_candidates_with_lookups<Visible, Evidence>(
    names: &[String],
    visible_type_candidates: &mut Visible,
    attribute_class_is_applicable: &mut Evidence,
) -> Option<(Vec<CodeUnit>, bool)>
where
    Visible: FnMut(&str) -> Option<Vec<CodeUnit>>,
    Evidence: FnMut(&CodeUnit) -> Option<bool>,
{
    match attribute_type_resolution_with_lookups(
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
pub fn usage_unambiguous_attribute_type_candidates(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
    names: &[String],
) -> Vec<CodeUnit> {
    match attribute_type_resolution_inner(source, file, names, true) {
        AttributeTypeResolution::Resolved(candidates) => candidates,
        AttributeTypeResolution::Unresolved | AttributeTypeResolution::Ambiguous(_) => Vec::new(),
    }
}

fn attribute_type_resolution(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
    names: &[String],
) -> AttributeTypeResolution {
    attribute_type_resolution_inner(source, file, names, false)
}

fn attribute_type_resolution_inner(
    source: &dyn CSharpAnalysisSource,
    file: &ProjectFile,
    names: &[String],
    usage: bool,
) -> AttributeTypeResolution {
    let mut visible = |name: &str| {
        Some(if usage {
            usage_visible_type_candidates(source, file, name)
        } else {
            visible_type_candidates(source, file, name)
        })
    };
    let mut attribute_class_is_applicable = |candidate: &CodeUnit| {
        Some(
            attribute_class_evidence(source, candidate, usage)
                != AttributeClassEvidence::DefinitelyNot,
        )
    };
    attribute_type_resolution_with_lookups(names, &mut visible, &mut attribute_class_is_applicable)
        .unwrap_or(AttributeTypeResolution::Unresolved)
}

fn attribute_type_resolution_with_lookups<Visible, Evidence>(
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
        if logical_type_count(&visible) != 1 {
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
    sort_type_candidates(&mut candidates);
    candidates.dedup();
    Some(
        match (successful_spellings, logical_type_count(&candidates)) {
            (0, _) | (_, 0) => AttributeTypeResolution::Unresolved,
            (1, 1) => AttributeTypeResolution::Resolved(candidates),
            _ => AttributeTypeResolution::Ambiguous(candidates),
        },
    )
}

fn attribute_class_evidence(
    source: &dyn CSharpAnalysisSource,
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
            usage_partial_type_parts(source, &current)
        } else {
            partial_type_parts(source, &current)
        };
        if parts.is_empty() {
            parts.push(current);
        }
        for part in parts {
            for raw in source.raw_supertypes_of(&part) {
                let normalized_raw = csharp_normalize_full_name(&raw);
                if normalized_raw == ATTRIBUTE_FQN {
                    return AttributeClassEvidence::Proven;
                }
                if matches!(normalized_raw.as_str(), "object" | "System.Object") {
                    decisive_non_attribute_base = true;
                    continue;
                }
                let ancestors = if usage {
                    usage_visible_type_candidates(source, part.source(), &raw)
                } else {
                    visible_type_candidates(source, part.source(), &raw)
                };
                if ancestors.is_empty() {
                    unresolved_ancestry = true;
                    continue;
                }
                if logical_type_count(&ancestors) > 1 {
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

pub fn usage_direct_ancestors(
    source: &dyn CSharpAnalysisSource,
    code_unit: &CodeUnit,
) -> Vec<CodeUnit> {
    logical_direct_ancestors(source, code_unit, true)
}

pub fn logical_direct_ancestors(
    source: &dyn CSharpAnalysisSource,
    code_unit: &CodeUnit,
    usage: bool,
) -> Vec<CodeUnit> {
    let mut parts = if usage {
        usage_partial_type_parts(source, code_unit)
    } else {
        partial_type_parts(source, code_unit)
    };
    if parts.is_empty() {
        parts.push(code_unit.clone());
    }

    let mut ancestors = Vec::new();
    for part in parts {
        ancestors.extend(source.raw_supertypes_of(&part).iter().filter_map(|raw| {
            if usage {
                resolve_usage_visible_type(source, part.source(), raw)
            } else {
                resolve_visible_type(source, part.source(), raw)
            }
        }));
    }
    sort_dedup_type_candidates(&mut ancestors);
    ancestors
}
