#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TypeLookupTargetKind {
    TypeReference,
    ValueExpression,
    MemberOwner { member_name: String },
}
