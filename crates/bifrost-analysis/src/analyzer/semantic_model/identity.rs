use super::{MemberKind, TypeRef};
use crate::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};

const TYPE_ID_DOMAIN: &[u8] = b"bifrost.external-declaration.type.v1";
const MEMBER_ID_DOMAIN: &[u8] = b"bifrost.external-declaration.member.v2";

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
/// Parameter names are excluded because binary names are optional metadata.
/// Return types are retained because CLI metadata and C# conversion operators
/// can distinguish members that otherwise have the same overload shape.
/// Staticness distinguishes source-level companion members, and explicit arity
/// keeps best-effort identities distinct when a parameter type is unavailable.
#[derive(Debug, Clone, Copy)]
pub struct MemberIdentity<'a> {
    pub owner_id: &'a str,
    pub kind: MemberKind,
    pub is_static: bool,
    pub parameter_arity: usize,
    pub name: &'a str,
    pub generic_arity: usize,
    pub parameter_types: &'a [TypeRef],
    pub parameter_variadics: &'a [bool],
    pub return_type: Option<&'a TypeRef>,
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
    hasher.field("is_static", &[u8::from(identity.is_static)]);
    hasher.field(
        "parameter_arity",
        &u64::try_from(identity.parameter_arity)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
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
    if identity
        .parameter_variadics
        .iter()
        .any(|variadic| *variadic)
    {
        hasher.sequence(
            "parameter_variadics",
            identity.parameter_variadics,
            |hasher, variadic| hasher.value(&[u8::from(*variadic)]),
        );
    }
    let return_type = serde_json::to_vec(&identity.return_type)
        .expect("optional return type is JSON serializable");
    hasher.field("return_type", &return_type);
    format!("member.{}", lower_hex_string(&hasher.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::TypeRefReferenceKind;

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
        fn identity<'a>(owner_id: &'a str, parameter_types: &'a [TypeRef]) -> MemberIdentity<'a> {
            MemberIdentity {
                owner_id,
                kind: MemberKind::Method,
                is_static: false,
                parameter_arity: parameter_types.len(),
                name: "Send",
                generic_arity: 0,
                parameter_types,
                parameter_variadics: &[],
                return_type: None,
            }
        }

        let owner_id = type_declaration_id(TypeIdentity {
            ecosystem: "nuget",
            name: "Example.Client`1",
        });
        let one = [named("System.String"), named("System.Int32")];
        let reversed = [named("System.Int32"), named("System.String")];
        assert_eq!(
            member_declaration_id(identity(&owner_id, &one)),
            member_declaration_id(identity(&owner_id, &one))
        );
        assert_ne!(
            member_declaration_id(identity(&owner_id, &one)),
            member_declaration_id(identity(&owner_id, &reversed))
        );
    }

    #[test]
    fn member_identity_distinguishes_lvalue_and_rvalue_references() {
        let owner_id = "type.cpp.example.Widget";
        let named_type = named("example.Widget");
        let lvalue = [TypeRef::ByRef {
            element: Box::new(named_type.clone()),
            reference_kind: TypeRefReferenceKind::Lvalue,
        }];
        let rvalue = [TypeRef::ByRef {
            element: Box::new(named_type),
            reference_kind: TypeRefReferenceKind::Rvalue,
        }];
        fn member_identity<'a>(
            owner_id: &'a str,
            parameter_types: &'a [TypeRef],
        ) -> MemberIdentity<'a> {
            MemberIdentity {
                owner_id,
                kind: MemberKind::Constructor,
                is_static: false,
                parameter_arity: parameter_types.len(),
                name: "Widget",
                generic_arity: 0,
                parameter_types,
                parameter_variadics: &[],
                return_type: None,
            }
        }

        let lvalue_id = member_declaration_id(member_identity(owner_id, &lvalue));
        let rvalue_id = member_declaration_id(member_identity(owner_id, &rvalue));
        assert_eq!(
            lvalue_id,
            member_declaration_id(member_identity(owner_id, &lvalue))
        );
        assert_eq!(
            rvalue_id,
            member_declaration_id(member_identity(owner_id, &rvalue))
        );
        assert_ne!(lvalue_id, rvalue_id);
        assert_ne!(
            serde_json::to_value(&lvalue[0]).expect("lvalue JSON"),
            serde_json::to_value(&rvalue[0]).expect("rvalue JSON")
        );
    }
}
