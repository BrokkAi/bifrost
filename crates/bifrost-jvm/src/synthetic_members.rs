use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, ResolutionIdentifierRole, ResolutionNameId, ResolutionNamespace,
    ResolutionScopeId,
};

/// Whether a scope already declares a callable that replaces a synthesized
/// member of the same name and, when specified, parameter count.
pub(crate) fn declares_callable(
    facts: &FileResolutionFacts,
    scope: ResolutionScopeId,
    name: ResolutionNameId,
    parameter_count: Option<usize>,
) -> bool {
    facts.identifiers.iter().any(|identifier| {
        identifier.role == ResolutionIdentifierRole::Declaration
            && identifier.namespace == ResolutionNamespace::Callable
            && facts.sites[identifier.site.index()].scope == scope
            && identifier.name == name
            && parameter_count.is_none_or(|count| {
                facts
                    .callable_parameters
                    .iter()
                    .filter(|parameter| parameter.callable == identifier.site)
                    .count()
                    == count
            })
    })
}
