//! Analyzer-neutral JVM identity used by the CSMI adapter.

use super::model::{
    CsmiDescriptor, CsmiDescriptorRole, CsmiMemberRelationship, CsmiReferenceType,
    CsmiReferenceTypeKind, CsmiTypeExpression,
};
use crate::analyzer::semantic_model::{MemberFact, TypeFact, TypeRef};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// The first Bifrost JVM identity profile.  The value is deliberately a URI-like
/// reverse-DNS name, rather than a Bifrost database or pack identifier.
pub const JVM_IDENTITY_SCHEME: &str = "ai.brokk.csmi.jvm-symbol";
pub const JVM_IDENTITY_VERSION: &str = "0.1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    UnsupportedType(String),
    MissingSignature { member: String },
    InvalidName(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedType(value) => write!(formatter, "unsupported JVM type: {value}"),
            Self::MissingSignature { member } => {
                write!(formatter, "JVM callable has no signature: {member}")
            }
            Self::InvalidName(value) => write!(formatter, "invalid JVM name: {value}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Return the ordered descriptor components for a JVM binary type name.
pub fn type_descriptors(name: &str) -> Result<Vec<CsmiDescriptor>, IdentityError> {
    if name.is_empty() || name.starts_with('.') || name.ends_with('.') || name.contains("..") {
        return Err(IdentityError::InvalidName(name.to_owned()));
    }
    let parts: Vec<&str> = name.split('.').collect();
    let Some(type_name) = parts.last().copied() else {
        return Err(IdentityError::InvalidName(name.to_owned()));
    };
    if type_name.is_empty() {
        return Err(IdentityError::InvalidName(name.to_owned()));
    }
    let mut descriptors = parts[..parts.len() - 1]
        .iter()
        .map(|part| CsmiDescriptor {
            role: CsmiDescriptorRole::Namespace,
            name: Some((*part).to_owned()),
            disambiguator: None,
        })
        .collect::<Vec<_>>();
    descriptors.push(CsmiDescriptor {
        role: CsmiDescriptorRole::Type,
        name: Some(type_name.to_owned()),
        disambiguator: None,
    });
    Ok(descriptors)
}

/// Construct the profile's stable local handle. Local handles are not
/// semantic identity; the descriptors in the symbol are the identity.
pub fn type_symbol_id(name: &str) -> Result<String, IdentityError> {
    let descriptors = type_descriptors(name)?;
    Ok(format!("type.{}", digest(&descriptors)))
}

pub fn member_symbol_id(
    owner: &str,
    member: &MemberFact,
    type_names_by_id: &HashMap<String, String>,
) -> Result<String, IdentityError> {
    let disambiguator = callable_disambiguator(member, type_names_by_id)?;
    let key = format!(
        "{owner}\0{}\0{}\0{}",
        member.name, member.member_kind as u8, disambiguator
    );
    Ok(format!("member.{}", digest(&key)))
}

/// The profile uses a source-readable JVM descriptor so it remains stable for
/// source and class-file producers: `(java.lang.String)->java.lang.String`.
pub fn callable_disambiguator(
    member: &MemberFact,
    type_names_by_id: &HashMap<String, String>,
) -> Result<String, IdentityError> {
    let signature = member
        .signature
        .as_ref()
        .ok_or_else(|| IdentityError::MissingSignature {
            member: member.name.clone(),
        })?;
    let mut parameters = Vec::with_capacity(signature.parameters.len());
    for parameter in &signature.parameters {
        parameters.push(type_expression_name(&parameter.r#type, type_names_by_id)?);
    }
    let result = signature
        .returns
        .as_ref()
        .map(|value| type_expression_name(value, type_names_by_id))
        .transpose()?
        .unwrap_or_else(|| "void".to_owned());
    Ok(format!("({})->{result}", parameters.join(",")))
}

pub fn type_expression_name(
    value: &TypeRef,
    type_names_by_id: &HashMap<String, String>,
) -> Result<String, IdentityError> {
    match value {
        TypeRef::Named {
            name, arguments, ..
        } => {
            if name.is_empty() {
                return Err(IdentityError::UnsupportedType(
                    "empty named type".to_owned(),
                ));
            }
            if arguments.is_empty() {
                Ok(name.clone())
            } else {
                let args = arguments
                    .iter()
                    .map(|argument| type_expression_name(argument, type_names_by_id))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(format!("{name}<{}>", args.join(",")))
            }
        }
        TypeRef::Declared { id, .. } => type_names_by_id
            .get(id)
            .cloned()
            .ok_or_else(|| IdentityError::UnsupportedType(format!("unresolved declaration {id}"))),
        TypeRef::TypeParameter { name } => Ok(name.clone()),
        TypeRef::Array { element } => Ok(format!(
            "{}[]",
            type_expression_name(element, type_names_by_id)?
        )),
        TypeRef::ByRef { element, .. } => Ok(format!(
            "{}&",
            type_expression_name(element, type_names_by_id)?
        )),
        other => Err(IdentityError::UnsupportedType(format!("{other:?}"))),
    }
}

pub fn type_expression(
    value: &TypeRef,
    type_names_by_id: &HashMap<String, String>,
) -> Result<CsmiTypeExpression, IdentityError> {
    match value {
        TypeRef::TypeParameter { name } => Ok(CsmiTypeExpression::Parameter(
            super::model::CsmiParameterType {
                kind: super::model::CsmiParameterTypeKind::Parameter,
                symbol: format!("type-parameter.{name}"),
            },
        )),
        TypeRef::Named {
            name, arguments, ..
        } => Ok(CsmiTypeExpression::Reference(CsmiReferenceType {
            kind: CsmiReferenceTypeKind::Reference,
            symbol: type_symbol_id(name)?,
            arguments: arguments
                .iter()
                .map(|argument| type_expression(argument, type_names_by_id))
                .collect::<Result<Vec<_>, _>>()?,
        })),
        TypeRef::Declared { id, arguments, .. } => {
            Ok(CsmiTypeExpression::Reference(CsmiReferenceType {
                kind: CsmiReferenceTypeKind::Reference,
                symbol: type_symbol_id(type_names_by_id.get(id).ok_or_else(|| {
                    IdentityError::UnsupportedType(format!("unresolved declaration {id}"))
                })?)?,
                arguments: arguments
                    .iter()
                    .map(|argument| type_expression(argument, type_names_by_id))
                    .collect::<Result<Vec<_>, _>>()?,
            }))
        }
        TypeRef::Array { element } => Ok(CsmiTypeExpression::Intrinsic(
            super::model::CsmiIntrinsicType {
                kind: super::model::CsmiIntrinsicTypeKind::Intrinsic,
                vocabulary: JVM_IDENTITY_SCHEME.to_owned(),
                version: JVM_IDENTITY_VERSION.to_owned(),
                identifier: format!(
                    "array<{}>",
                    type_expression_name(element, type_names_by_id)?
                ),
            },
        )),
        TypeRef::ByRef { element, .. } => Ok(CsmiTypeExpression::Intrinsic(
            super::model::CsmiIntrinsicType {
                kind: super::model::CsmiIntrinsicTypeKind::Intrinsic,
                vocabulary: JVM_IDENTITY_SCHEME.to_owned(),
                version: JVM_IDENTITY_VERSION.to_owned(),
                identifier: format!(
                    "byref<{}>",
                    type_expression_name(element, type_names_by_id)?
                ),
            },
        )),
        other => Err(IdentityError::UnsupportedType(format!("{other:?}"))),
    }
}

pub fn type_symbol(name: &str) -> Result<super::model::CsmiSymbolDefinition, IdentityError> {
    Ok(super::model::CsmiSymbolDefinition {
        id: type_symbol_id(name)?,
        artifact_selectors: None,
        scheme: JVM_IDENTITY_SCHEME.to_owned(),
        scheme_version: JVM_IDENTITY_VERSION.to_owned(),
        stability: super::model::CsmiStability::Portable,
        descriptors: type_descriptors(name)?,
        display_name: None,
        qualified_display_name: None,
        native_signature: None,
        documentation_name: None,
        abi_name: None,
        origin: None,
        external_identities: Vec::new(),
        provenance: Vec::new(),
        extensions: Vec::new(),
    })
}

fn digest<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("identity value is serializable");
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn collect_type_names(types: &[TypeFact]) -> HashMap<String, String> {
    types
        .iter()
        .map(|fact| (fact.id.clone(), fact.name.clone()))
        .collect()
}

// Keep this import exercised by downstream code that builds relationships.
pub fn member_relationship(subject: String, object: String) -> CsmiMemberRelationship {
    CsmiMemberRelationship {
        subject,
        predicate: super::model::CsmiMemberPredicate::Implements,
        object,
        provenance: Vec::new(),
        extensions: Vec::new(),
    }
}
