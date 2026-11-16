//! C#'s attribute-type resolution and direct-ancestor walk.
//!
//! `analyzer/csharp/hierarchy_provider.rs` in `brokk-bifrost-analysis` keeps the
//! `TypeHierarchyProvider` impl and the two memo cells behind it (the
//! `direct_ancestors` moka cache and the `direct_descendant_index`
//! `OnceLock`); deciding whether a candidate really is an attribute class, and
//! which declarations a type derives from, is language knowledge and lives
//! here.

use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::hash::HashSet;

use crate::graph_support::{
    self, CSharpSource, LogicalDirectAncestors, UnindexedClause, is_csharp_object_root,
    logical_type_count, partial_type_parts, sort_type_candidates, supertype_candidates,
    usage_partial_type_parts,
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

/// Whether `candidate` may be the class an attribute name denotes: proven to
/// derive from `System.Attribute`, or with ancestry this workspace does not
/// index. Only a declaration proven not to be an attribute class is rejected,
/// so it cannot steal an attribute shorthand reference.
pub fn attribute_class_is_applicable(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    candidate: &CodeUnit,
) -> bool {
    attribute_class_evidence(source, token, candidate, false)
        != AttributeClassEvidence::DefinitelyNot
}

/// Resolve the two C# attribute-name forms, retaining only declarations
/// that are proven to derive from `System.Attribute` or whose external
/// ancestry is unavailable. Indexed declarations proven not to be
/// attributes must not steal an attribute shorthand reference.
///
/// `type_candidates` is the caller's whole C# type lookup for one spelling,
/// not merely the file-keyed visible search: an attribute name is written
/// inside a type declaration and names a type through the enclosing type and
/// namespace scopes first (#3300).
pub fn attribute_type_candidates_with_lookups<Candidates, Evidence>(
    names: &[String],
    type_candidates: &mut Candidates,
    attribute_class_is_applicable: &mut Evidence,
) -> Option<(Vec<CodeUnit>, bool)>
where
    Candidates: FnMut(&str) -> Option<Vec<CodeUnit>>,
    Evidence: FnMut(&CodeUnit) -> Option<bool>,
{
    match attribute_type_resolution_with_lookups(
        names,
        type_candidates,
        attribute_class_is_applicable,
    )? {
        AttributeTypeResolution::Unresolved => Some((Vec::new(), false)),
        AttributeTypeResolution::Resolved(candidates) => Some((candidates, false)),
        AttributeTypeResolution::Ambiguous(candidates) => Some((candidates, true)),
    }
}

/// The usage side's [`attribute_class_is_applicable`], reading ancestry
/// through the inverse pass's bounded definition lookups.
pub fn usage_attribute_class_is_applicable(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    candidate: &CodeUnit,
) -> bool {
    attribute_class_evidence(source, token, candidate, true)
        != AttributeClassEvidence::DefinitelyNot
}

/// Inverse usage proof requires one logical attribute type. An ambiguous
/// annotation is not a proven reference to every declaration it might name.
///
/// `type_candidates` is the caller's whole C# type lookup for one spelling,
/// for the reason [`attribute_type_candidates_with_lookups`] states.
pub fn usage_unambiguous_attribute_type_candidates<Candidates>(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    names: &[String],
    type_candidates: &mut Candidates,
) -> Vec<CodeUnit>
where
    Candidates: FnMut(&str) -> Option<Vec<CodeUnit>>,
{
    let mut attribute_class_is_applicable = |candidate: &CodeUnit| {
        Some(usage_attribute_class_is_applicable(
            source, token, candidate,
        ))
    };
    match attribute_type_resolution_with_lookups(
        names,
        type_candidates,
        &mut attribute_class_is_applicable,
    ) {
        Some(AttributeTypeResolution::Resolved(candidates)) => candidates,
        Some(AttributeTypeResolution::Unresolved | AttributeTypeResolution::Ambiguous(_))
        | None => Vec::new(),
    }
}

fn attribute_type_resolution_with_lookups<Candidates, Evidence>(
    names: &[String],
    type_candidates: &mut Candidates,
    attribute_class_is_applicable: &mut Evidence,
) -> Option<AttributeTypeResolution>
where
    Candidates: FnMut(&str) -> Option<Vec<CodeUnit>>,
    Evidence: FnMut(&CodeUnit) -> Option<bool>,
{
    let mut candidates = Vec::new();
    let mut successful_spellings = 0usize;
    for name in names {
        let visible = type_candidates(name)?;
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
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
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
            usage_partial_type_parts(source, token, &current)
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
                if is_csharp_object_root(&normalized_raw) {
                    decisive_non_attribute_base = true;
                    continue;
                }
                let ancestors = supertype_candidates(source, token, &part, &raw, usage);
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
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    code_unit: &CodeUnit,
) -> Vec<CodeUnit> {
    logical_direct_ancestors(source, token, code_unit, true).resolved
}

pub fn logical_direct_ancestors(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    code_unit: &CodeUnit,
    usage: bool,
) -> LogicalDirectAncestors {
    let mut parts = if usage {
        usage_partial_type_parts(source, token, code_unit)
    } else {
        partial_type_parts(source, code_unit)
    };
    if parts.is_empty() {
        parts.push(code_unit.clone());
    }
    graph_support::logical_direct_ancestors(
        parts,
        |part| Some(source.declared_raw_supertypes(part)),
        |part, raw| Some(supertype_candidates(source, token, part, raw, usage)),
        |_| Some(()),
    )
    .expect("an unbounded ancestor walk never stops")
}

/// Settle what each unresolved clause of a hierarchy answer means: drop a
/// clause that spells the imported `Object` root, and record for the rest
/// whether the clause is proven to name a type outside the index (#7363).
pub fn classify_unindexed_clauses(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    ancestors: &mut LogicalDirectAncestors,
) {
    for clause in &mut ancestors.unindexed {
        clause.may_name_indexed = clause_may_name_indexed(source, clause);
    }
    // Only a clause proven not to name an indexed type can be the root: an
    // inherited nested `Object` the lookup missed is a real indexed base.
    ancestors.unindexed.retain(|clause| {
        clause.may_name_indexed || !names_imported_object_root(source, token, clause)
    });
}

/// Whether an unresolved clause spells `Object` where `using System;` (file
/// or global) imports it and no alias rebinds it. The caller has proven that
/// no indexed type is named `Object`, and a second imported `Object` would
/// make the base ambiguous (CS0104), so the clause names the root.
fn names_imported_object_root(
    source: &dyn CSharpSource,
    token: QueryToken<'_>,
    clause: &UnindexedClause,
) -> bool {
    const SYSTEM: &str = "System";
    let file = clause.declared_by.source();
    csharp_normalize_full_name(&clause.name) == "Object"
        && !source.using_aliases_of(file).contains_key("Object")
        && (source
            .file_using_namespaces_of(token, file)
            .iter()
            .any(|namespace| namespace == SYSTEM)
            || source
                .sorted_global_using_namespaces()
                .iter()
                .any(|namespace| namespace == SYSTEM))
}

/// Whether a clause the lookup did not resolve may still name an indexed
/// type. The lookup does not search every scope C# allows (an inherited
/// nested type, for example), so a failed lookup alone proves nothing. The
/// clause is proven to name a type outside the index only when no indexed
/// type declares its identifier and the clause is not a using alias.
fn clause_may_name_indexed(source: &dyn CSharpSource, clause: &UnindexedClause) -> bool {
    let normalized = csharp_normalize_full_name(&clause.name);
    // An extern-alias qualifier (`Ext::Name`) hides the identifier from the
    // dotted form, so such a clause stays unproven.
    if normalized.contains("::") {
        return true;
    }
    let Some(identifier) = normalized.rsplit('.').next() else {
        return true;
    };
    if identifier == normalized
        && source
            .using_aliases_of(clause.declared_by.source())
            .contains_key(identifier)
    {
        return true;
    }
    let written = clause.name.rsplit('.').next().unwrap_or(identifier);
    [identifier, written].into_iter().any(|spelling| {
        source
            .declaration_candidates_by_identifier(spelling)
            .iter()
            .any(CodeUnit::is_class)
    })
}
