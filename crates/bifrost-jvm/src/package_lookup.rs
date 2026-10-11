use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, PositionedIdentifierFact, ResolutionIdentifierRole,
    ResolutionPackageReferenceFact, ResolutionScopeId, ResolutionSiteFact,
};
use brokk_bifrost_core::hash::HashSet;

/// Collect package lookup requests while leaving reference eligibility,
/// package scope, namespace, and import rules to each JVM language producer.
pub(crate) fn source_owned_package_references(
    facts: &FileResolutionFacts,
    mut include_reference: impl FnMut(&PositionedIdentifierFact, &ResolutionSiteFact) -> bool,
    mut package_scope_for: impl FnMut(
        &PositionedIdentifierFact,
        &ResolutionSiteFact,
    ) -> Option<ResolutionScopeId>,
) -> Vec<ResolutionPackageReferenceFact> {
    let rooted_references = facts
        .root_references
        .iter()
        .map(|reference| reference.reference)
        .collect::<HashSet<_>>();

    facts
        .identifiers
        .iter()
        .filter_map(|identifier| {
            if identifier.role != ResolutionIdentifierRole::Reference
                || rooted_references.contains(&identifier.site)
            {
                return None;
            }
            let site = &facts.sites[identifier.site.index()];
            if !include_reference(identifier, site) {
                return None;
            }
            package_scope_for(identifier, site).map(|root_scope| ResolutionPackageReferenceFact {
                reference: identifier.site,
                root_scope,
            })
        })
        .collect()
}
