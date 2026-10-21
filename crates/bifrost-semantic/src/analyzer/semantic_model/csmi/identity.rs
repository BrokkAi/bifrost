//! Analyzer-neutral JVM and provisional Go source identity mappings.

use crate::analyzer::semantic_model::csmi::model::CsmiArtifactSelector;

use crate::analyzer::semantic_model::csmi::model::CsmiCallableKind;

use crate::analyzer::semantic_model::csmi::model::CsmiCallableShape;

use crate::analyzer::semantic_model::csmi::model::CsmiDescriptor;

use crate::analyzer::semantic_model::csmi::model::CsmiDescriptorRole;

use crate::analyzer::semantic_model::csmi::model::CsmiMemberRelationship;

use crate::analyzer::semantic_model::csmi::model::CsmiParameter;

use crate::analyzer::semantic_model::csmi::model::CsmiParameterBinding;

use crate::analyzer::semantic_model::csmi::model::CsmiReferenceType;

use crate::analyzer::semantic_model::csmi::model::CsmiReferenceTypeKind;

use crate::analyzer::semantic_model::csmi::model::CsmiResult;

use crate::analyzer::semantic_model::csmi::model::CsmiStability;

use crate::analyzer::semantic_model::csmi::model::CsmiSymbolDefinition;

use crate::analyzer::semantic_model::csmi::model::CsmiSymbolOrigin;

use crate::analyzer::semantic_model::csmi::model::CsmiTypeExpression;

use crate::analyzer::semantic_model::csmi::model::CsmiUnknownType;

use crate::analyzer::semantic_model::csmi::model::CsmiUnknownTypeKind;

use crate::analyzer::semantic_model::AnonymousCallableIdentity;

use crate::analyzer::semantic_model::Locator;

use crate::analyzer::semantic_model::MemberFact;

use crate::analyzer::semantic_model::SourceAnchor;

use crate::analyzer::semantic_model::SourceCallableShape;

use crate::analyzer::semantic_model::SourceDeclarationKind;

use crate::analyzer::semantic_model::SourceTypeNode;

use crate::analyzer::semantic_model::TypeFact;

use crate::analyzer::semantic_model::TypeKind;

use crate::analyzer::semantic_model::TypeRef;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// The first Bifrost JVM identity profile.  The value is deliberately a URI-like
/// reverse-DNS name, rather than a Bifrost database or pack identifier.
pub const JVM_IDENTITY_SCHEME: &str = "ai.brokk.csmi.jvm-symbol";
pub const JVM_IDENTITY_VERSION: &str = "0.1";

/// Provisional local recipe for exact Go source identities. This is a
/// scheme-defined CSMI core identity mapping, not a claim that CSMI has
/// published or standardized a Go identity profile.
pub const GO_SOURCE_IDENTITY_SCHEME: &str = "ai.brokk.csmi.go-source-symbol";
pub const GO_SOURCE_IDENTITY_VERSION: &str = "0.1";

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
            crate::analyzer::semantic_model::csmi::model::CsmiParameterType {
                kind:
                    crate::analyzer::semantic_model::csmi::model::CsmiParameterTypeKind::Parameter,
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
            crate::analyzer::semantic_model::csmi::model::CsmiIntrinsicType {
                kind:
                    crate::analyzer::semantic_model::csmi::model::CsmiIntrinsicTypeKind::Intrinsic,
                vocabulary: JVM_IDENTITY_SCHEME.to_owned(),
                version: JVM_IDENTITY_VERSION.to_owned(),
                identifier: format!(
                    "array<{}>",
                    type_expression_name(element, type_names_by_id)?
                ),
            },
        )),
        TypeRef::ByRef { element, .. } => Ok(CsmiTypeExpression::Intrinsic(
            crate::analyzer::semantic_model::csmi::model::CsmiIntrinsicType {
                kind:
                    crate::analyzer::semantic_model::csmi::model::CsmiIntrinsicTypeKind::Intrinsic,
                vocabulary: JVM_IDENTITY_SCHEME.to_owned(),
                version: JVM_IDENTITY_VERSION.to_owned(),
                identifier: format!(
                    "byref<{}>",
                    type_expression_name(element, type_names_by_id)?
                ),
            },
        )),
        TypeRef::Unknown => Ok(CsmiTypeExpression::Unknown(CsmiUnknownType {
            kind: CsmiUnknownTypeKind::Unknown,
        })),
        other => Err(IdentityError::UnsupportedType(format!("{other:?}"))),
    }
}

pub fn type_symbol(
    name: &str,
) -> Result<crate::analyzer::semantic_model::csmi::model::CsmiSymbolDefinition, IdentityError> {
    Ok(
        crate::analyzer::semantic_model::csmi::model::CsmiSymbolDefinition {
            id: type_symbol_id(name)?,
            artifact_selectors: None,
            scheme: JVM_IDENTITY_SCHEME.to_owned(),
            scheme_version: JVM_IDENTITY_VERSION.to_owned(),
            stability: crate::analyzer::semantic_model::csmi::model::CsmiStability::Portable,
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
        },
    )
}

/// Map a source-anchored Go function literal to an artifact-local CSMI symbol.
/// The identity digest retains the exact package, file/range, lexical owners,
/// signature AST anchors, and artifact digest without inventing a name.
pub fn go_anonymous_callable_symbol(
    identity: &AnonymousCallableIdentity,
    artifact: &CsmiArtifactSelector,
) -> Result<(CsmiSymbolDefinition, CsmiCallableShape), String> {
    validate_go_anonymous_callable_identity(identity, artifact)?;
    let identity_digest = digest_json(identity)?;
    let anchor_disambiguator =
        format!("go-function-literal-{GO_SOURCE_IDENTITY_VERSION}:{identity_digest}");
    let descriptors = vec![
        CsmiDescriptor {
            role: CsmiDescriptorRole::Namespace,
            name: Some(identity.package_identity.clone()),
            disambiguator: None,
        },
        CsmiDescriptor {
            role: CsmiDescriptorRole::Meta,
            name: Some(identity.anchor.file.clone()),
            disambiguator: Some(anchor_disambiguator),
        },
        CsmiDescriptor {
            role: CsmiDescriptorRole::Callable,
            name: None,
            disambiguator: Some(format!(
                "go-anonymous-callable-{GO_SOURCE_IDENTITY_VERSION}:{identity_digest}"
            )),
        },
    ];
    let symbol = go_source_symbol(artifact, descriptors, CsmiSymbolOrigin::Local)?;
    let shape = go_callable_shape(&identity.signature)?;
    Ok((symbol, shape))
}

/// Map a Go declaration from its exact native artifact locator. All identity
/// components come from the retained artifact locator and native declaration
/// handle; no qualified name is split or reconstructed.
pub fn go_type_symbol(
    fact: &TypeFact,
    artifact: &CsmiArtifactSelector,
) -> Result<CsmiSymbolDefinition, String> {
    let (path, source_symbol) = go_artifact_locator(&fact.locator)?;
    let identity_digest = digest_json(&json!({
        "artifact": artifact,
        "nativeId": fact.id,
        "sourcePath": path,
        "sourceSymbol": source_symbol,
        "typeKind": fact.type_kind,
    }))?;
    go_source_symbol(
        artifact,
        vec![
            CsmiDescriptor {
                role: CsmiDescriptorRole::Meta,
                name: Some(path.to_owned()),
                disambiguator: None,
            },
            CsmiDescriptor {
                role: if fact.type_kind == TypeKind::Module {
                    CsmiDescriptorRole::Namespace
                } else {
                    CsmiDescriptorRole::Type
                },
                name: Some(source_symbol.to_owned()),
                disambiguator: Some(format!(
                    "go-type-{GO_SOURCE_IDENTITY_VERSION}:{identity_digest}"
                )),
            },
        ],
        CsmiSymbolOrigin::Named,
    )
}

/// Map a Go callable or value member from its exact native source locator,
/// owner declaration, kind, and signature.
pub fn go_member_symbol(
    fact: &MemberFact,
    owner: &TypeFact,
    artifact: &CsmiArtifactSelector,
    value_member: bool,
) -> Result<CsmiSymbolDefinition, String> {
    let (path, source_symbol) = go_artifact_locator(&fact.locator)?;
    let (owner_path, owner_source_symbol) = go_artifact_locator(&owner.locator)?;
    let identity_digest = digest_json(&json!({
        "artifact": artifact,
        "nativeId": fact.id,
        "ownerNativeId": fact.owner,
        "ownerSourcePath": owner_path,
        "ownerSourceSymbol": owner_source_symbol,
        "sourcePath": path,
        "sourceSymbol": source_symbol,
        "memberName": fact.name,
        "memberKind": fact.member_kind,
        "isStatic": fact.is_static,
        "receiver": fact.receiver,
        "signature": fact.signature,
    }))?;
    go_source_symbol(
        artifact,
        vec![
            CsmiDescriptor {
                role: CsmiDescriptorRole::Meta,
                name: Some(path.to_owned()),
                disambiguator: None,
            },
            CsmiDescriptor {
                role: CsmiDescriptorRole::Meta,
                name: None,
                disambiguator: Some(format!("go-owner:{owner_path}:{owner_source_symbol}")),
            },
            CsmiDescriptor {
                role: if value_member {
                    CsmiDescriptorRole::Term
                } else {
                    CsmiDescriptorRole::Callable
                },
                name: Some(fact.name.clone()),
                disambiguator: Some(format!(
                    "go-member-{GO_SOURCE_IDENTITY_VERSION}:{identity_digest}"
                )),
            },
        ],
        CsmiSymbolOrigin::Named,
    )
}

/// Recompute the local handle defined by the provisional Go source identity
/// recipe. The validator uses this to reject symbols whose handle disagrees
/// with their scheme descriptors or artifact selector.
pub(crate) fn go_source_symbol_id(
    artifact_selectors: &[CsmiArtifactSelector],
    descriptors: &[CsmiDescriptor],
) -> Result<String, String> {
    let digest = digest_json(&json!({
        "artifactSelectors": artifact_selectors,
        "scheme": GO_SOURCE_IDENTITY_SCHEME,
        "schemeVersion": GO_SOURCE_IDENTITY_VERSION,
        "descriptors": descriptors,
    }))?;
    Ok(format!("go.{digest}"))
}

fn go_source_symbol(
    artifact: &CsmiArtifactSelector,
    descriptors: Vec<CsmiDescriptor>,
    origin: CsmiSymbolOrigin,
) -> Result<CsmiSymbolDefinition, String> {
    let artifact_selectors = vec![artifact.clone()];
    Ok(CsmiSymbolDefinition {
        id: go_source_symbol_id(&artifact_selectors, &descriptors)?,
        artifact_selectors: Some(artifact_selectors),
        scheme: GO_SOURCE_IDENTITY_SCHEME.to_owned(),
        scheme_version: GO_SOURCE_IDENTITY_VERSION.to_owned(),
        stability: CsmiStability::ArtifactLocal,
        descriptors,
        display_name: None,
        qualified_display_name: None,
        native_signature: None,
        documentation_name: None,
        abi_name: None,
        origin: Some(origin),
        external_identities: Vec::new(),
        provenance: Vec::new(),
        extensions: Vec::new(),
    })
}

fn validate_go_anonymous_callable_identity(
    identity: &AnonymousCallableIdentity,
    artifact: &CsmiArtifactSelector,
) -> Result<(), String> {
    let artifact_digests = artifact
        .digests
        .iter()
        .find(|digest| {
            matches!(
                digest.algorithm,
                crate::analyzer::semantic_model::csmi::model::CsmiDigestAlgorithm::Sha256
            )
        })
        .map(|digest| digest.value.as_str());
    if identity.id.is_empty() || artifact_digests != Some(identity.artifact_sha256.as_str()) {
        return Err(
            "Go anonymous callable ID must be nonempty and match the selected artifact digest"
                .to_owned(),
        );
    }
    if identity.package_identity.is_empty() {
        return Err("Go anonymous callable package import path is empty".to_owned());
    }
    if identity.anchor.kind != SourceDeclarationKind::FunctionLiteral {
        return Err("Go anonymous callable anchor must be a function literal".to_owned());
    }
    validate_source_anchor(&identity.anchor)?;
    let mut previous_owner: Option<&SourceAnchor> = None;
    for owner in &identity.lexical_owner_chain {
        validate_source_anchor(owner)?;
        if !matches!(
            owner.kind,
            SourceDeclarationKind::Function
                | SourceDeclarationKind::Method
                | SourceDeclarationKind::FunctionLiteral
        ) || owner.file != identity.anchor.file
        {
            return Err(
                "Go lexical owner chain must contain callable anchors in the literal's file"
                    .to_owned(),
            );
        }
        if let Some(outer) = previous_owner
            && !(outer.byte_range.start <= owner.byte_range.start
                && owner.byte_range.end <= outer.byte_range.end)
        {
            return Err(
                "Go lexical owner anchors are not ordered from outermost to innermost".to_owned(),
            );
        }
        previous_owner = Some(owner);
    }
    if let Some(owner) = previous_owner
        && !(owner.byte_range.start <= identity.anchor.byte_range.start
            && identity.anchor.byte_range.end <= owner.byte_range.end)
    {
        return Err("Go function literal is outside its innermost lexical owner".to_owned());
    }
    let function_type = &identity.signature.function_type;
    validate_source_type_node(function_type)?;
    if function_type.file != identity.anchor.file
        || !(identity.anchor.byte_range.start <= function_type.byte_range.start
            && function_type.byte_range.end <= identity.anchor.byte_range.end)
    {
        return Err("Go function type anchor must be inside its function literal".to_owned());
    }
    for (kind, groups) in [
        ("parameter", identity.signature.parameters.as_slice()),
        ("result", identity.signature.results.as_slice()),
    ] {
        let mut variadic_seen = false;
        for (index, group) in groups.iter().enumerate() {
            if group.arity == 0 {
                return Err(format!("Go callable {kind} group has zero arity"));
            }
            if group.variadic {
                if kind != "parameter" || index + 1 != groups.len() || variadic_seen {
                    return Err(
                        "Go callable variadic parameter must be its single final group".to_owned(),
                    );
                }
                variadic_seen = true;
            }
            validate_source_type_node(&group.type_node)?;
        }
        let count = groups
            .iter()
            .try_fold(0usize, |total, group| total.checked_add(group.arity));
        if count.is_none_or(|count| count > u16::MAX as usize) {
            return Err(format!(
                "Go callable {kind} count exceeds callable-values profile range"
            ));
        }
    }
    for anchor in &identity.signature.declaration_chain {
        validate_source_anchor(anchor)?;
    }
    Ok(())
}

fn validate_source_anchor(anchor: &SourceAnchor) -> Result<(), String> {
    if !crate::analyzer::semantic_model::is_canonical_relative_path(&anchor.file)
        || anchor.byte_range.start >= anchor.byte_range.end
    {
        return Err(
            "Go source anchor must have a canonical relative path and nonempty byte range"
                .to_owned(),
        );
    }
    Ok(())
}

fn go_artifact_locator(locator: &Locator) -> Result<(&str, &str), String> {
    match locator {
        Locator::Artifact { path, symbol }
            if crate::analyzer::semantic_model::is_canonical_relative_path(path)
                && !symbol.is_empty() =>
        {
            Ok((path, symbol))
        }
        Locator::Artifact { .. } => {
            Err("Go artifact locator is not canonical or has an empty source symbol".to_owned())
        }
        Locator::Source { .. } | Locator::Interchange { .. } => {
            Err("Go declaration identity requires an exact native artifact locator".to_owned())
        }
    }
}

fn validate_source_type_node(node: &SourceTypeNode) -> Result<(), String> {
    if !crate::analyzer::semantic_model::is_canonical_relative_path(&node.file)
        || node.byte_range.start >= node.byte_range.end
    {
        return Err(
            "Go AST type anchor must have a canonical relative path and nonempty byte range"
                .to_owned(),
        );
    }
    Ok(())
}

fn go_callable_shape(signature: &SourceCallableShape) -> Result<CsmiCallableShape, String> {
    let mut position = 0usize;
    let mut parameters = Vec::new();
    for group in &signature.parameters {
        for index in 0..group.arity {
            let variadic = group.variadic && index + 1 == group.arity;
            parameters.push(CsmiParameter {
                position: u32::try_from(position)
                    .map_err(|_| "Go callable parameter count exceeds CSMI's position range")?,
                binding: if variadic {
                    CsmiParameterBinding::VariadicPositional
                } else {
                    CsmiParameterBinding::PositionalOnly
                },
                label: None,
                role: None,
                required: true,
                symbol: None,
                parameter_type: Some(CsmiTypeExpression::Unknown(CsmiUnknownType {
                    kind: CsmiUnknownTypeKind::Unknown,
                })),
                extensions: Vec::new(),
            });
            position += 1;
        }
    }
    let mut position = 0usize;
    let mut results = Vec::new();
    for group in &signature.results {
        for _ in 0..group.arity {
            results.push(CsmiResult {
                position: u32::try_from(position)
                    .map_err(|_| "Go callable result count exceeds CSMI's position range")?,
                label: None,
                result_type: Some(CsmiTypeExpression::Unknown(CsmiUnknownType {
                    kind: CsmiUnknownTypeKind::Unknown,
                })),
                extensions: Vec::new(),
            });
            position += 1;
        }
    }
    Ok(CsmiCallableShape {
        kind: CsmiCallableKind::Function,
        receiver: None,
        parameters,
        results,
        return_classes: Vec::new(),
        extensions: Vec::new(),
    })
}

fn digest_json(value: &impl Serialize) -> Result<String, String> {
    let bytes = crate::analyzer::semantic_model::csmi::canonical::canonical_json(value)
        .map_err(|error| format!("Go source identity canonicalization failed: {error}"))?;
    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[doc(hidden)]
pub fn digest<T: Serialize>(value: &T) -> String {
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
        predicate: crate::analyzer::semantic_model::csmi::model::CsmiMemberPredicate::Implements,
        object,
        provenance: Vec::new(),
        extensions: Vec::new(),
    }
}
