//! Resolver-owned Go result type retained until legacy resolver retirement.

/// Result assembled by the legacy Go reference resolver.
pub struct GoReferenceResolution {
    pub fqn_candidates: Vec<String>,
    pub resolved_import_packages: Vec<String>,
    pub shadowed: bool,
}
