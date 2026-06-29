#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeLookupTargetKind {
    TypeReference,
    ValueExpression,
    MemberOwner,
}
