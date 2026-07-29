#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeLookupTargetKind {
    TypeReference,
    ValueExpression,
    MemberOwner { member_name: String },
}
