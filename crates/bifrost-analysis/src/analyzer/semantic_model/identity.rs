use super::{MemberKind, TypeRef};
use crate::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};

const TYPE_ID_DOMAIN: &[u8] = b"bifrost.external-declaration.type.v1";
const MEMBER_ID_DOMAIN: &[u8] = b"bifrost.external-declaration.member.v1";

/// Canonical semantic identity for a type supplied by an external artifact.
///
/// Callers must pass the ecosystem's normalized fully qualified identity. The
/// artifact path and source/binary origin are deliberately not part of the key.
#[derive(Debug, Clone, Copy)]
pub struct TypeIdentity<'a> {
    pub ecosystem: &'a str,
    pub name: &'a str,
}

/// Canonical semantic identity for a member supplied by an external artifact.
///
/// Return types and parameter names are excluded because Java and C# do not
/// overload on return type and binary parameter names are optional metadata.
#[derive(Debug, Clone, Copy)]
pub struct MemberIdentity<'a> {
    pub owner_id: &'a str,
    pub kind: MemberKind,
    pub name: &'a str,
    pub generic_arity: usize,
    pub parameter_types: &'a [TypeRef],
}

pub fn type_declaration_id(identity: TypeIdentity<'_>) -> String {
    let mut hasher = CanonicalHasher::new(TYPE_ID_DOMAIN);
    hasher.field("ecosystem", identity.ecosystem.as_bytes());
    hasher.field("name", identity.name.as_bytes());
    format!("type.{}", lower_hex_string(&hasher.finish()))
}

pub fn member_declaration_id(identity: MemberIdentity<'_>) -> String {
    let mut hasher = CanonicalHasher::new(MEMBER_ID_DOMAIN);
    hasher.field("owner", identity.owner_id.as_bytes());
    let kind = serde_json::to_vec(&identity.kind).expect("member kind is JSON serializable");
    hasher.field("kind", &kind);
    hasher.field("name", identity.name.as_bytes());
    hasher.field(
        "generic_arity",
        &u64::try_from(identity.generic_arity)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.sequence("parameter_types", identity.parameter_types, |hasher, ty| {
        let encoded = serde_json::to_vec(ty).expect("type references are JSON serializable");
        hasher.value(&encoded);
    });
    format!("member.{}", lower_hex_string(&hasher.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(name: &str) -> TypeRef {
        TypeRef::Named {
            name: name.to_owned(),
            arguments: Vec::new(),
            nullable: false,
        }
    }

    #[test]
    fn type_identity_is_deterministic() {
        let identity = TypeIdentity {
            ecosystem: "maven",
            name: "com.example.Widget`1",
        };
        assert_eq!(type_declaration_id(identity), type_declaration_id(identity));
        assert!(type_declaration_id(identity).starts_with("type."));
    }

    #[test]
    fn member_identity_tracks_overload_shape() {
        let owner_id = type_declaration_id(TypeIdentity {
            ecosystem: "nuget",
            name: "Example.Client`1",
        });
        let one = [named("System.String"), named("System.Int32")];
        let reversed = [named("System.Int32"), named("System.String")];
        let identity = |parameter_types| MemberIdentity {
            owner_id: &owner_id,
            kind: MemberKind::Method,
            name: "Send",
            generic_arity: 0,
            parameter_types,
        };

        assert_eq!(
            member_declaration_id(identity(&one)),
            member_declaration_id(identity(&one))
        );
        assert_ne!(
            member_declaration_id(identity(&one)),
            member_declaration_id(identity(&reversed))
        );
    }
}
