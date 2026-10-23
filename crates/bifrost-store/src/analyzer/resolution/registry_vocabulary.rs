/// A language selection after shared traversal identifies an operand shape.
#[doc(hidden)]
pub enum TypeComponentSelection {
    Component(brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeComponentKind),
    Intrinsic(&'static str),
    /// Preserve the original operand identity, including a named slice type.
    Operand,
    /// Use the output identity and the producer's component rows for its shape.
    Constructed,
}

#[doc(hidden)]
pub struct TypeComponentProjection {
    pub selection: TypeComponentSelection,
    /// Override a runtime result's addressability. Type-object transfers keep
    /// their category and the component's own pointer depth.
    pub addressable: Option<bool>,
}

/// Package clause name and exact selected-artifact provenance for one modeled
/// external import. The language adapter decides whether its model proves this
/// identity; shared resolution carries these fields without interpreting them.
#[derive(Debug, Clone, Eq, PartialEq)]
#[doc(hidden)]
pub struct ModeledExternalPackageIdentity {
    #[doc(hidden)]
    pub package_name: String,
    #[doc(hidden)]
    pub symbol_id: String,
    #[doc(hidden)]
    pub pack_id: String,
    #[doc(hidden)]
    pub pack_digest: String,
    #[doc(hidden)]
    pub record_id: String,
}
