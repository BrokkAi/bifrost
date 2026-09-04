//! Translation from a verified CSMI v0.1 logical pack into Bifrost authoring
//! types. No CSMI sidecar or producer-specific metadata is consulted.

use super::canonical::{canonical_pack_manifest, sha256_hex};
use super::identity::{JVM_IDENTITY_SCHEME, JVM_IDENTITY_VERSION, type_symbol_id};
use super::model::*;
use super::pack::{CsmiLogicalPack, CsmiResourceResolver};
use super::validate::{CsmiVocabularySupport, validate_csmi_pack};
use crate::analyzer::semantic_model::{
    ActivationSelector, AuthoredPayload, AuthoredProcedureSummary, AuthoredProcedureTarget,
    AuthoredSemanticModelPack, AuthoredShard, AuthoredSummaryExitKind, AuthoredSummaryInput,
    AuthoredSummaryOutput, AuthoredSummaryTransfer, Compatibility, CompilerOptions, Completeness,
    CppArtifactDigest, CppArtifactSelector, CppCallableKind, CppCallableSignature,
    CppCanonicalType, CppDescriptorRole, CppDigestAlgorithm, CppDirectHeader,
    CppFundamentalTypeName, CppHeaderClosure, CppIdentityStability, CppLanguage,
    CppPortabilityEvidence, CppPortableSymbolKey, CppPortableSymbolRecord, CppReferenceKind,
    CppResolutionContextRecord, CppResolutionContextRef, CppSpecialMemberEvidence,
    CppSpecialMemberOperation, CppSymbolDescriptor, CppTypeAliasEvidence, CppTypeQualifier,
    ImplicitOperation, Locator, MemberFact, MemberKind, NameSelector, Parameter,
    ParameterPassingMode, Producer, Provenance, ReceiverFact, Safety, Signature,
    SummaryMoveInvalidation, SummaryValuePreservation, SummaryValueTransfer,
    SummaryValueTransferKind, SummaryValueTransferLimitation, SummaryValueTransferLimitationKind,
    SummaryValueTransferOperation, TypeCopySemantics, TypeFact, TypeKind, TypeMoveSemantics,
    TypeRef, TypeValueSemantics, Visibility, compile_pack,
};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsmiImportError {
    InvalidPack(Vec<super::validate::CsmiDiagnostic>),
    Uninterpretable(Vec<super::validate::CsmiDiagnostic>),
    MissingSemanticDocument,
    Unsupported { path: String, semantic: String },
    Identity(String),
    Selector(String),
    Compile(String),
}

impl std::fmt::Display for CsmiImportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPack(diagnostics) => {
                write!(formatter, "CSMI pack validation failed: {diagnostics:?}")
            }
            Self::Uninterpretable(diagnostics) => {
                write!(formatter, "CSMI pack is uninterpretable: {diagnostics:?}")
            }
            Self::MissingSemanticDocument => {
                formatter.write_str("CSMI pack has no semantic document")
            }
            Self::Unsupported { path, semantic } => {
                write!(formatter, "unsupported CSMI semantic at {path}: {semantic}")
            }
            Self::Identity(message) => write!(formatter, "CSMI identity mapping failed: {message}"),
            Self::Selector(message) => {
                write!(formatter, "unsupported artifact selector: {message}")
            }
            Self::Compile(message) => write!(
                formatter,
                "imported Bifrost pack did not compile: {message}"
            ),
        }
    }
}

impl std::error::Error for CsmiImportError {}

pub type CsmiImportReport = CsmiImportError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsmiImportedPack {
    pub pack: AuthoredSemanticModelPack,
    pub pack_digest: String,
    pub semantic_document_digest: String,
}

impl CsmiImportedPack {
    pub fn authored(&self) -> &AuthoredSemanticModelPack {
        &self.pack
    }

    pub fn compile(
        &self,
        options: &CompilerOptions,
    ) -> Result<crate::analyzer::semantic_model::CompiledSemanticModelPack, CsmiImportError> {
        compile_pack(&self.pack, options)
            .map_err(|diagnostics| CsmiImportError::Compile(format!("{diagnostics:?}")))
    }
}

pub fn import_csmi_pack(
    manifest_bytes: &[u8],
    resources: &dyn CsmiResourceResolver,
    support: &CsmiVocabularySupport,
    compiler_options: &CompilerOptions,
) -> Result<CsmiImportedPack, CsmiImportReport> {
    let validation = validate_csmi_pack(manifest_bytes, resources, support);
    if !validation.valid() {
        return Err(CsmiImportError::InvalidPack(validation.diagnostics));
    }
    let manifest = validation
        .manifest
        .as_ref()
        .expect("valid pack has manifest");
    let semantic = match validation.semantic_documents.as_slice() {
        [] => return Err(CsmiImportError::MissingSemanticDocument),
        [semantic] => semantic,
        documents => {
            return Err(CsmiImportError::Unsupported {
                path: "resources".to_owned(),
                semantic: format!(
                    "expected exactly one semantic document, found {}",
                    documents.len()
                ),
            });
        }
    };
    if !validation.interpretable {
        return Err(CsmiImportError::Uninterpretable(validation.diagnostics));
    }
    let pack_digest = sha256_hex(
        &canonical_pack_manifest(manifest)
            .map_err(|error| CsmiImportError::Identity(error.to_string()))?,
    );
    let semantic_document_digest = sha256_hex(
        &super::canonical::canonical_semantic_document(semantic)
            .map_err(|error| CsmiImportError::Identity(error.to_string()))?,
    );
    let pack = import_semantic_document(semantic, manifest, &pack_digest)?;
    // Compile once on the normal Bifrost path so an imported pack cannot be
    // returned with hidden invalid state. The caller may compile again with a
    // different, explicitly bounded policy.
    compile_pack(&pack, compiler_options)
        .map_err(|diagnostics| CsmiImportError::Compile(format!("{diagnostics:?}")))?;
    Ok(CsmiImportedPack {
        pack,
        pack_digest,
        semantic_document_digest,
    })
}

/// Convenience wrapper when the caller already has a logical pack value.
pub fn import_logical_csmi_pack(
    pack: &CsmiLogicalPack,
    support: &CsmiVocabularySupport,
    compiler_options: &CompilerOptions,
) -> Result<CsmiImportedPack, CsmiImportReport> {
    let manifest = pack
        .canonical_manifest_bytes()
        .map_err(|error| CsmiImportError::Identity(error.to_string()))?;
    import_csmi_pack(&manifest, &pack.resources, support, compiler_options)
}

fn import_semantic_document(
    document: &CsmiSemanticDocument,
    manifest: &CsmiPackManifest,
    pack_digest: &str,
) -> Result<AuthoredSemanticModelPack, CsmiImportError> {
    let model = match document.semantic_models.as_slice() {
        [model] => model,
        models => {
            return Err(CsmiImportError::Unsupported {
                path: "semanticModels".to_owned(),
                semantic: format!(
                    "expected exactly one semantic model, found {}",
                    models.len()
                ),
            });
        }
    };
    let cpp_identity = model.symbols.iter().all(|symbol| {
        symbol.scheme == CSMI_CPP_DECLARATION_IDENTITY_SCHEME
            && symbol.scheme_version == CSMI_CPP_DECLARATION_IDENTITY_SCHEME_VERSION
            && symbol.stability == CsmiStability::Portable
    });
    let jvm_identity = model.symbols.iter().all(|symbol| {
        symbol.scheme == JVM_IDENTITY_SCHEME && symbol.scheme_version == JVM_IDENTITY_VERSION
    });
    if !cpp_identity && !jvm_identity {
        return Err(CsmiImportError::Unsupported {
            path: "symbols".to_owned(),
            semantic: "all symbols must use one supported exact identity scheme".to_owned(),
        });
    }
    let selectors = model
        .artifact_selectors
        .iter()
        .map(selector_from_csmi)
        .collect::<Result<Vec<_>, _>>()?;
    let cpp_native_ids = if cpp_identity {
        model
            .symbols
            .iter()
            .map(|symbol| {
                Ok((
                    symbol.id.clone(),
                    cpp_native_id_from_core(symbol, &model.artifact_selectors)?,
                ))
            })
            .collect::<Result<HashMap<_, _>, CsmiImportError>>()?
    } else {
        HashMap::new()
    };
    let mut symbols = HashMap::new();
    let mut types = Vec::new();
    let mut type_ids = HashMap::new();
    for symbol in &model.symbols {
        if let Some(name) = type_name(symbol) {
            let native_id = if cpp_identity {
                cpp_native_ids[&symbol.id].clone()
            } else {
                type_symbol_id(&name)
                    .map_err(|error| CsmiImportError::Identity(error.to_string()))?
            };
            type_ids.insert(symbol.id.clone(), native_id);
            symbols.insert(symbol.id.clone(), name);
        }
    }
    for declaration in &model.declarations {
        if !matches!(
            declaration.category,
            CsmiDeclarationCategory::Type | CsmiDeclarationCategory::TypeAlias
        ) {
            continue;
        }
        let Some(symbol) = model
            .symbols
            .iter()
            .find(|symbol| symbol.id == declaration.symbol)
        else {
            return Err(CsmiImportError::Identity(format!(
                "unknown type symbol {}",
                declaration.symbol
            )));
        };
        let name = type_name(symbol).ok_or_else(|| {
            CsmiImportError::Identity(format!("symbol {} has no JVM type descriptor", symbol.id))
        })?;
        let id = type_ids
            .get(&symbol.id)
            .cloned()
            .unwrap_or_else(|| symbol.id.clone());
        types.push(TypeFact {
            id: id.clone(),
            name: name.clone(),
            type_kind: if declaration.category == CsmiDeclarationCategory::TypeAlias {
                TypeKind::TypeAlias
            } else {
                TypeKind::Class
            },
            visibility: Visibility::Public,
            is_abstract: false,
            is_sealed: false,
            has_explicit_type_terms: false,
            type_parameters: Vec::new(),
            type_parameter_constraints: Vec::new(),
            underlying_type: None,
            value_semantics: None,
            embedded_types: Vec::new(),
            hierarchy: Vec::new(),
            aliases: Vec::new(),
            extension_surfaces: Vec::new(),
            guard: None,
            locator: Locator::Artifact {
                path: format!("csmi/{pack_digest}.json"),
                symbol: name,
            },
        });
    }
    let mut members = Vec::new();
    let mut member_ids = HashMap::new();
    for declaration in &model.declarations {
        if declaration.category != CsmiDeclarationCategory::Callable {
            continue;
        }
        let shape = declaration
            .callable
            .as_ref()
            .ok_or_else(|| CsmiImportError::Unsupported {
                path: "declarations".to_owned(),
                semantic: "callable declaration has no shape".to_owned(),
            })?;
        let symbol = model
            .symbols
            .iter()
            .find(|symbol| symbol.id == declaration.symbol)
            .ok_or_else(|| {
                CsmiImportError::Identity(format!("unknown callable symbol {}", declaration.symbol))
            })?;
        let owner_symbol = declaration.owner.as_ref().ok_or_else(|| {
            CsmiImportError::Identity(format!("callable {} has no owner", declaration.symbol))
        })?;
        let owner_name = symbols.get(owner_symbol).cloned().ok_or_else(|| {
            CsmiImportError::Identity(format!("unknown owner symbol {owner_symbol}"))
        })?;
        let member_name = callable_name(symbol).ok_or_else(|| {
            CsmiImportError::Identity(format!(
                "callable symbol {} has no callable descriptor",
                symbol.id
            ))
        })?;
        let signature = signature_from_shape(shape, &symbols)?;
        let owner_id = types
            .iter()
            .find(|fact| fact.name == owner_name)
            .map(|fact| fact.id.clone())
            .unwrap_or_else(|| {
                type_symbol_id(&owner_name).unwrap_or_else(|_| owner_symbol.clone())
            });
        let member_id = if cpp_identity {
            cpp_native_ids[&declaration.symbol].clone()
        } else {
            format!("member.{}", sha256_hex(declaration.symbol.as_bytes()))
        };
        member_ids.insert(declaration.symbol.clone(), member_id.clone());
        members.push(MemberFact {
            id: member_id,
            owner: owner_id,
            name: member_name,
            member_kind: member_kind(shape.kind)?,
            visibility: Visibility::Public,
            is_static: matches!(
                shape.receiver,
                Some(CsmiReceiver {
                    kind: CsmiReceiverKind::Type,
                    ..
                })
            ),
            is_abstract: false,
            is_virtual: false,
            implicit_operation: None,
            callable_family_complete: false,
            signature: Some(signature),
            receiver: if matches!(
                shape.receiver,
                Some(CsmiReceiver {
                    kind: CsmiReceiverKind::Instance,
                    ..
                })
            ) {
                Some(ReceiverFact { pointer: false })
            } else {
                None
            },
            extension_receiver: None,
            extension_receiver_constraints: Vec::new(),
            aliases: Vec::new(),
            guard: None,
            locator: Locator::Artifact {
                path: format!("csmi/{pack_digest}.json"),
                symbol: symbol.id.clone(),
            },
        });
    }
    import_value_transfer_facts(model, &type_ids, &member_ids, &mut types, &mut members)?;
    let completeness = model
        .completeness_statements
        .iter()
        .find(|statement| {
            statement.family == "declaration-records"
                && statement.vocabulary.is_none()
                && statement.version.is_none()
                && statement.scope.get("scheme").and_then(Value::as_str)
                    == Some(if cpp_identity {
                        CSMI_CPP_DECLARATION_IDENTITY_SCHEME
                    } else {
                        JVM_IDENTITY_SCHEME
                    })
                && statement.scope.get("schemeVersion").and_then(Value::as_str)
                    == Some(if cpp_identity {
                        CSMI_CPP_DECLARATION_IDENTITY_SCHEME_VERSION
                    } else {
                        JVM_IDENTITY_VERSION
                    })
        })
        .map_or(Completeness::Partial, |statement| match statement.status {
            CsmiCoverageStatus::Complete => Completeness::Complete,
            CsmiCoverageStatus::Unknown | CsmiCoverageStatus::Partial => Completeness::Partial,
        });
    let summaries = model
        .procedure_summaries
        .iter()
        .map(|summary| summary_from_csmi(summary, model, &symbols, &member_ids))
        .collect::<Result<Vec<_>, _>>()?;
    let producer = document
        .provenance_records
        .first()
        .map(|record| Producer {
            name: record.producer.identifier.clone(),
            version: semver::Version::parse(&record.producer.version)
                .map(|_| record.producer.version.clone())
                .unwrap_or_else(|_| {
                    format!(
                        "0.1.0+csmi.{}",
                        &sha256_hex(record.producer.version.as_bytes())[..12]
                    )
                }),
        })
        .unwrap_or_else(|| Producer {
            name: "csmi".to_owned(),
            version: "0.1.0".to_owned(),
        });
    let provenance = document
        .provenance_records
        .first()
        .map(|record| Provenance {
            source: record.producer.identifier.clone(),
            revision: record
                .invocation_id
                .clone()
                .or_else(|| Some(record.producer.version.clone())),
        })
        .unwrap_or_else(|| Provenance {
            source: "csmi".to_owned(),
            revision: None,
        });
    let cpp_portability = cpp_identity
        .then(|| import_cpp_portability(model, &type_ids, &member_ids))
        .transpose()?;
    if let Some(evidence) = &cpp_portability {
        for special in &evidence.special_members {
            let member = members
                .iter_mut()
                .find(|member| member.id == special.member)
                .expect("validated C++ special member names an imported declaration");
            let operation = match special.operation {
                CppSpecialMemberOperation::CopyConstructor => ImplicitOperation::CopyConstructor,
                CppSpecialMemberOperation::CopyAssignment => ImplicitOperation::CopyAssignment,
                CppSpecialMemberOperation::MoveConstructor => ImplicitOperation::MoveConstructor,
            };
            if let Some(existing) = &member.implicit_operation
                && existing != &operation
            {
                return Err(CsmiImportError::Identity(format!(
                    "C++ special-member operation conflicts with value-transfer fact for {}",
                    member.id
                )));
            }
            member.implicit_operation = Some(operation);
        }
    }
    let (language, ecosystem) = if cpp_identity {
        ("cpp".to_owned(), "cpp-headers".to_owned())
    } else {
        ("java".to_owned(), "maven".to_owned())
    };
    let shard = AuthoredShard {
        id: format!("csmi.{pack_digest}.summaries"),
        activation: selectors,
        payload: AuthoredPayload::DeclarationFacts {
            types,
            members,
            relations: Vec::new(),
        },
    };
    let summary_shard = AuthoredShard {
        id: format!("csmi.{pack_digest}.procedure-summaries"),
        activation: shard.activation.clone(),
        payload: AuthoredPayload::ProcedureSummaries { summaries },
    };
    Ok(AuthoredSemanticModelPack {
        schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
        pack_id: format!("csmi.{pack_digest}"),
        version: format!("0.1.0+csmi.{pack_digest}"),
        producer,
        language,
        ecosystem,
        compatibility: Compatibility {
            bifrost: format!(">={}", env!("CARGO_PKG_VERSION")),
            toolchains: Vec::new(),
        },
        provenance,
        license: manifest.license.clone(),
        completeness,
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
        carried_sources: Vec::new(),
        cpp_portability,
        shards: if summaries_empty(&summary_shard) {
            vec![shard]
        } else {
            vec![shard, summary_shard]
        },
    })
}

fn summaries_empty(shard: &AuthoredShard) -> bool {
    matches!(&shard.payload, AuthoredPayload::ProcedureSummaries { summaries } if summaries.is_empty())
}

fn import_cpp_portability(
    model: &CsmiSemanticModel,
    type_ids: &HashMap<String, String>,
    member_ids: &HashMap<String, String>,
) -> Result<CppPortabilityEvidence, CsmiImportError> {
    let mut contexts = Vec::new();
    for constraint in &model.compatibility_constraints {
        if constraint.vocabulary != CSMI_C_CPP_RESOLUTION_PROFILE_ID
            || constraint.version != CSMI_C_CPP_RESOLUTION_PROFILE_VERSION
        {
            continue;
        }
        let context: CsmiResolutionContext = serde_json::from_value(constraint.value.clone())
            .map_err(|error| CsmiImportError::Identity(error.to_string()))?;
        let context_digest = sha256_hex(
            &super::canonical::canonical_json(&context)
                .map_err(|error| CsmiImportError::Identity(error.to_string()))?,
        );
        contexts.push(CppResolutionContextRecord {
            context_digest,
            language: cpp_language(context.language),
            translation_unit: context.translation_unit,
            compile_arguments_digest: context.compile_arguments_digest,
            direct_headers: context
                .direct_headers
                .into_iter()
                .map(|header| CppDirectHeader {
                    include_name: header.include_name,
                    artifact: cpp_artifact_selector(header.artifact),
                })
                .collect(),
            header_closure: CppHeaderClosure::Complete,
        });
    }
    let symbols = model
        .symbols
        .iter()
        .map(|symbol| {
            Ok(CppPortableSymbolRecord {
                native_id: type_ids
                    .get(&symbol.id)
                    .or_else(|| member_ids.get(&symbol.id))
                    .cloned()
                    .ok_or_else(|| {
                        CsmiImportError::Identity(format!(
                            "portable symbol {} has no native declaration",
                            symbol.id
                        ))
                    })?,
                key: cpp_symbol_key_from_core(symbol, &model.artifact_selectors)?,
            })
        })
        .collect::<Result<Vec<_>, CsmiImportError>>()?;
    let key_ids = model
        .symbols
        .iter()
        .map(|symbol| {
            Ok((
                cpp_symbol_key_from_core(symbol, &model.artifact_selectors)?,
                type_ids
                    .get(&symbol.id)
                    .or_else(|| member_ids.get(&symbol.id))
                    .cloned()
                    .ok_or_else(|| CsmiImportError::Identity(symbol.id.clone()))?,
            ))
        })
        .collect::<Result<Vec<_>, CsmiImportError>>()?;
    let mut type_aliases = Vec::new();
    let mut special_members = Vec::new();
    for fact in &model.extension_facts {
        if fact.vocabulary != CSMI_CPP_PROFILE_ID || fact.version != CSMI_CPP_PROFILE_VERSION {
            continue;
        }
        let payload: CsmiCppProfilePayload = serde_json::from_value(fact.payload.clone())
            .map_err(|error| CsmiImportError::Identity(error.to_string()))?;
        match payload {
            CsmiCppProfilePayload::ResolutionContext(_) => {
                return Err(CsmiImportError::Unsupported {
                    path: "extensionFacts".to_owned(),
                    semantic: "resolution contexts belong in compatibilityConstraints".to_owned(),
                });
            }
            CsmiCppProfilePayload::TypeAlias(alias) => type_aliases.push(CppTypeAliasEvidence {
                alias: type_ids.get(&alias.alias).cloned().ok_or_else(|| {
                    CsmiImportError::Identity(format!("unknown alias {}", alias.alias))
                })?,
                target: cpp_canonical_type(alias.target, &key_ids)?,
                resolution_context: cpp_context_ref(alias.resolution_context),
            }),
            CsmiCppProfilePayload::SpecialMember(member) => {
                let member = *member;
                special_members.push(CppSpecialMemberEvidence {
                    owner: type_ids.get(&member.owner).cloned().ok_or_else(|| {
                        CsmiImportError::Identity(format!("unknown owner {}", member.owner))
                    })?,
                    member: member_ids.get(&member.member).cloned().ok_or_else(|| {
                        CsmiImportError::Identity(format!("unknown member {}", member.member))
                    })?,
                    operation: match member.operation {
                        CsmiCppSpecialMemberOperation::CopyConstructor => {
                            CppSpecialMemberOperation::CopyConstructor
                        }
                        CsmiCppSpecialMemberOperation::CopyAssignment => {
                            CppSpecialMemberOperation::CopyAssignment
                        }
                        CsmiCppSpecialMemberOperation::MoveConstructor => {
                            CppSpecialMemberOperation::MoveConstructor
                        }
                    },
                    signature: CppCallableSignature {
                        callable_kind: match member.signature.callable_kind {
                            CsmiCppCallableKind::Constructor => CppCallableKind::Constructor,
                            CsmiCppCallableKind::Method => CppCallableKind::Method,
                        },
                        owner: cpp_key_native_id(&member.signature.owner, &key_ids)?,
                        receiver: member
                            .signature
                            .receiver
                            .map(|value| cpp_canonical_type(value, &key_ids))
                            .transpose()?,
                        parameters: member
                            .signature
                            .parameters
                            .into_iter()
                            .map(|value| cpp_canonical_type(value, &key_ids))
                            .collect::<Result<Vec<_>, _>>()?,
                        result: member
                            .signature
                            .result
                            .map(|value| cpp_canonical_type(value, &key_ids))
                            .transpose()?,
                    },
                    member_disambiguator: member.member_disambiguator,
                    resolution_context: cpp_context_ref(member.resolution_context),
                });
            }
        }
    }
    Ok(CppPortabilityEvidence {
        resolution_contexts: contexts,
        symbols,
        type_aliases,
        special_members,
    })
}

fn cpp_artifact_selector(selector: CsmiCppArtifactSelector) -> CppArtifactSelector {
    CppArtifactSelector {
        purl: selector.purl,
        digests: selector
            .digests
            .into_iter()
            .map(|digest| CppArtifactDigest {
                algorithm: CppDigestAlgorithm::Sha256,
                coverage: digest.coverage,
                canonicalization: digest.canonicalization,
                value: digest.value,
            })
            .collect(),
    }
}

fn cpp_language(language: CsmiCppLanguage) -> CppLanguage {
    match language {
        CsmiCppLanguage::C => CppLanguage::C,
        CsmiCppLanguage::Cpp => CppLanguage::Cpp,
    }
}

fn cpp_symbol_key_from_core(
    symbol: &CsmiSymbolDefinition,
    model_selectors: &[CsmiArtifactSelector],
) -> Result<CppPortableSymbolKey, CsmiImportError> {
    let selectors = symbol
        .artifact_selectors
        .clone()
        .unwrap_or_else(|| model_selectors.to_vec())
        .into_iter()
        .map(cpp_core_artifact_selector)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CppPortableSymbolKey {
        artifact_selectors: selectors,
        scheme: symbol.scheme.clone(),
        scheme_version: symbol.scheme_version.clone(),
        stability: CppIdentityStability::Portable,
        descriptors: symbol
            .descriptors
            .iter()
            .map(|descriptor| {
                Ok(CppSymbolDescriptor {
                    role: match descriptor.role {
                        CsmiDescriptorRole::Namespace => CppDescriptorRole::Namespace,
                        CsmiDescriptorRole::Type => CppDescriptorRole::Type,
                        CsmiDescriptorRole::Callable => CppDescriptorRole::Callable,
                        other => {
                            return Err(CsmiImportError::Identity(format!(
                                "unsupported C++ descriptor role {other:?}"
                            )));
                        }
                    },
                    name: descriptor.name.clone().ok_or_else(|| {
                        CsmiImportError::Identity("C++ descriptor has no name".to_owned())
                    })?,
                    disambiguator: descriptor.disambiguator.clone().ok_or_else(|| {
                        CsmiImportError::Identity("C++ descriptor has no disambiguator".to_owned())
                    })?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn cpp_core_artifact_selector(
    selector: CsmiArtifactSelector,
) -> Result<CppArtifactSelector, CsmiImportError> {
    let digests = selector
        .digests
        .into_iter()
        .map(|digest| {
            if digest.algorithm != CsmiDigestAlgorithm::Sha256 {
                return Err(CsmiImportError::Unsupported {
                    path: "symbols.artifactSelectors.digests.algorithm".to_owned(),
                    semantic: format!(
                        "C++ portable identity requires sha-256, found {:?}",
                        digest.algorithm
                    ),
                });
            }
            Ok(CppArtifactDigest {
                algorithm: CppDigestAlgorithm::Sha256,
                coverage: digest.coverage,
                canonicalization: digest.canonicalization,
                value: digest.value,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CppArtifactSelector {
        purl: selector.purl,
        digests,
    })
}

fn cpp_native_id_from_core(
    symbol: &CsmiSymbolDefinition,
    model_selectors: &[CsmiArtifactSelector],
) -> Result<String, CsmiImportError> {
    let key = cpp_symbol_key_from_core(symbol, model_selectors)?;
    let dto = CsmiCppSymbolKey {
        artifact_selectors: key
            .artifact_selectors
            .iter()
            .map(|selector| CsmiCppArtifactSelector {
                purl: selector.purl.clone(),
                digests: selector
                    .digests
                    .iter()
                    .map(|digest| CsmiCppArtifactDigest {
                        algorithm: CsmiCppDigestAlgorithm::Sha256,
                        coverage: digest.coverage.clone(),
                        canonicalization: digest.canonicalization.clone(),
                        value: digest.value.clone(),
                    })
                    .collect(),
            })
            .collect(),
        scheme: key.scheme,
        scheme_version: key.scheme_version,
        stability: CsmiCppIdentityStability::Portable,
        descriptors: key
            .descriptors
            .into_iter()
            .map(|descriptor| CsmiCppDescriptor {
                role: match descriptor.role {
                    CppDescriptorRole::Namespace => CsmiCppDescriptorRole::Namespace,
                    CppDescriptorRole::Type => CsmiCppDescriptorRole::Type,
                    CppDescriptorRole::Callable => CsmiCppDescriptorRole::Callable,
                },
                name: descriptor.name,
                disambiguator: descriptor.disambiguator,
            })
            .collect(),
    };
    let bytes = super::canonical::canonical_json(&dto)
        .map_err(|error| CsmiImportError::Identity(error.to_string()))?;
    Ok(format!("cpp.{}", sha256_hex(&bytes)))
}

fn cpp_key_native_id(
    key: &CsmiCppSymbolKey,
    key_ids: &[(CppPortableSymbolKey, String)],
) -> Result<String, CsmiImportError> {
    let key = CppPortableSymbolKey {
        artifact_selectors: key
            .artifact_selectors
            .clone()
            .into_iter()
            .map(cpp_artifact_selector)
            .collect(),
        scheme: key.scheme.clone(),
        scheme_version: key.scheme_version.clone(),
        stability: CppIdentityStability::Portable,
        descriptors: key
            .descriptors
            .iter()
            .map(|descriptor| CppSymbolDescriptor {
                role: match descriptor.role {
                    CsmiCppDescriptorRole::Namespace => CppDescriptorRole::Namespace,
                    CsmiCppDescriptorRole::Type => CppDescriptorRole::Type,
                    CsmiCppDescriptorRole::Callable => CppDescriptorRole::Callable,
                },
                name: descriptor.name.clone(),
                disambiguator: descriptor.disambiguator.clone(),
            })
            .collect(),
    };
    key_ids
        .iter()
        .find_map(|(candidate, native)| (candidate == &key).then(|| native.clone()))
        .ok_or_else(|| {
            CsmiImportError::Identity("C++ symbol key is not declared by the model".to_owned())
        })
}

fn cpp_canonical_type(
    value: CsmiCppCanonicalType,
    key_ids: &[(CppPortableSymbolKey, String)],
) -> Result<CppCanonicalType, CsmiImportError> {
    Ok(match value {
        CsmiCppCanonicalType::Fundamental(_) => CppCanonicalType::Fundamental {
            name: CppFundamentalTypeName::Char,
        },
        CsmiCppCanonicalType::Declared(value) => CppCanonicalType::Declared {
            symbol: cpp_key_native_id(&value.symbol, key_ids)?,
        },
        CsmiCppCanonicalType::TemplateSpecialization(value) => {
            CppCanonicalType::TemplateSpecialization {
                primary: cpp_key_native_id(&value.primary, key_ids)?,
                arguments: value
                    .arguments
                    .into_iter()
                    .map(|argument| cpp_canonical_type(argument, key_ids))
                    .collect::<Result<Vec<_>, _>>()?,
            }
        }
        CsmiCppCanonicalType::Qualified(value) => CppCanonicalType::Qualified {
            qualifiers: value
                .qualifiers
                .into_iter()
                .map(|qualifier| match qualifier {
                    CsmiCppTypeQualifier::Const => CppTypeQualifier::Const,
                    CsmiCppTypeQualifier::Volatile => CppTypeQualifier::Volatile,
                })
                .collect(),
            r#type: Box::new(cpp_canonical_type(*value.r#type, key_ids)?),
        },
        CsmiCppCanonicalType::Reference(value) => CppCanonicalType::Reference {
            reference_kind: match value.reference_kind {
                CsmiCppReferenceKind::Lvalue => CppReferenceKind::Lvalue,
                CsmiCppReferenceKind::Rvalue => CppReferenceKind::Rvalue,
            },
            referent: Box::new(cpp_canonical_type(*value.referent, key_ids)?),
        },
    })
}

fn cpp_context_ref(value: CsmiCppResolutionContext) -> CppResolutionContextRef {
    CppResolutionContextRef {
        vocabulary: CSMI_C_CPP_RESOLUTION_PROFILE_ID.to_owned(),
        version: value.version,
        context_digest: value.context_digest,
        language: CppLanguage::Cpp,
        header_closure: CppHeaderClosure::Complete,
    }
}

fn selector_from_csmi(
    selector: &CsmiArtifactSelector,
) -> Result<ActivationSelector, CsmiImportError> {
    if !selector.purl.starts_with("pkg:maven/") {
        if selector.version_range.is_some() {
            return Err(CsmiImportError::Selector(
                "portable C/C++ selectors require exact artifact bytes, not version ranges"
                    .to_owned(),
            ));
        }
        let sha256 = selector
            .digests
            .iter()
            .find(|digest| digest.algorithm == CsmiDigestAlgorithm::Sha256)
            .ok_or_else(|| {
                CsmiImportError::Selector(
                    "portable C/C++ selectors require a SHA-256 digest".to_owned(),
                )
            })?;
        return Ok(ActivationSelector {
            package: Some(NameSelector {
                name: selector.purl.clone(),
                version: None,
            }),
            module: None,
            toolchain: None,
            targets: Vec::new(),
            configurations: Vec::new(),
            artifact_sha256: Some(sha256.value.clone()),
        });
    }
    if selector.version_range.is_some() {
        return Err(CsmiImportError::Selector(
            "version ranges are not accepted for exact Maven imports".to_owned(),
        ));
    }
    let raw = selector.purl.strip_prefix("pkg:maven/").ok_or_else(|| {
        CsmiImportError::Selector(format!("expected pkg:maven PURL, got {}", selector.purl))
    })?;
    if raw.contains(['?', '#']) {
        return Err(CsmiImportError::Selector(
            "Maven qualifiers and subpaths are outside the supported exact selector subset"
                .to_owned(),
        ));
    }
    let (coordinate, version) = raw.split_once('@').ok_or_else(|| {
        CsmiImportError::Selector("Maven PURL must include an exact version".to_owned())
    })?;
    let (group, artifact) = coordinate.rsplit_once('/').ok_or_else(|| {
        CsmiImportError::Selector("Maven PURL must include group and artifact".to_owned())
    })?;
    if group.is_empty() || artifact.is_empty() || version.is_empty() {
        return Err(CsmiImportError::Selector(
            "Maven group, artifact, and version must be non-empty".to_owned(),
        ));
    }
    if selector.digests.len() != 1 || selector.digests[0].algorithm != CsmiDigestAlgorithm::Sha256 {
        return Err(CsmiImportError::Selector(
            "exact Maven selectors require exactly one sha-256 digest".to_owned(),
        ));
    }
    let digest = Some(selector.digests[0].value.clone());
    Ok(ActivationSelector {
        package: Some(NameSelector {
            name: format!("{group}:{artifact}"),
            version: Some(version.to_owned()),
        }),
        module: None,
        toolchain: None,
        targets: Vec::new(),
        configurations: Vec::new(),
        artifact_sha256: digest,
    })
}

fn type_name(symbol: &CsmiSymbolDefinition) -> Option<String> {
    let mut parts = Vec::new();
    let mut type_parts = Vec::new();
    for descriptor in &symbol.descriptors {
        if descriptor.role == CsmiDescriptorRole::Callable {
            continue;
        }
        let name = descriptor.name.as_ref()?;
        match descriptor.role {
            CsmiDescriptorRole::Namespace => parts.push(name.clone()),
            CsmiDescriptorRole::Type => type_parts.push(name.clone()),
            _ => {}
        }
    }
    parts.extend(type_parts);
    (!parts.is_empty()).then(|| parts.join("."))
}

fn callable_name(symbol: &CsmiSymbolDefinition) -> Option<String> {
    symbol
        .descriptors
        .iter()
        .rev()
        .find(|descriptor| descriptor.role == CsmiDescriptorRole::Callable)
        .and_then(|descriptor| descriptor.name.clone())
}

fn member_kind(kind: CsmiCallableKind) -> Result<MemberKind, CsmiImportError> {
    match kind {
        CsmiCallableKind::Constructor => Ok(MemberKind::Constructor),
        CsmiCallableKind::Accessor => Ok(MemberKind::Property),
        CsmiCallableKind::Function => Ok(MemberKind::Function),
        CsmiCallableKind::Method => Ok(MemberKind::Method),
        unsupported => Err(CsmiImportError::Unsupported {
            path: "declarations.callable.kind".to_owned(),
            semantic: format!("callable kind {unsupported:?} is not supported"),
        }),
    }
}

fn signature_from_shape(
    shape: &CsmiCallableShape,
    symbols: &HashMap<String, String>,
) -> Result<Signature, CsmiImportError> {
    if shape.results.len() > 1 {
        return Err(CsmiImportError::Unsupported {
            path: "declarations.callable.results".to_owned(),
            semantic: "multiple result ports are not representable in Bifrost signatures"
                .to_owned(),
        });
    }
    let parameters = shape
        .parameters
        .iter()
        .enumerate()
        .map(|(position, parameter)| {
            let parameter_type =
                parameter
                    .parameter_type
                    .as_ref()
                    .ok_or_else(|| CsmiImportError::Unsupported {
                        path: format!("declarations.callable.parameters[{position}].type"),
                        semantic: "parameter is missing its type expression".to_owned(),
                    })?;
            Ok(Parameter {
                name: parameter.label.clone(),
                r#type: type_ref(
                    parameter_type,
                    symbols,
                    &format!("declarations.callable.parameters[{position}].type"),
                )?,
                optional: !parameter.required,
                variadic: matches!(
                    parameter.binding,
                    CsmiParameterBinding::VariadicPositional | CsmiParameterBinding::VariadicNamed
                ),
                passing_mode: match parameter.binding {
                    CsmiParameterBinding::PositionalOnly => ParameterPassingMode::PositionalOnly,
                    CsmiParameterBinding::NamedOnly | CsmiParameterBinding::VariadicNamed => {
                        ParameterPassingMode::NamedOnly
                    }
                    _ => ParameterPassingMode::PositionalOrNamed,
                },
            })
        })
        .collect::<Result<Vec<_>, CsmiImportError>>()?;
    let returns = shape
        .results
        .first()
        .map(|result| {
            let result_type =
                result
                    .result_type
                    .as_ref()
                    .ok_or_else(|| CsmiImportError::Unsupported {
                        path: "declarations.callable.results[0].type".to_owned(),
                        semantic: "result is missing its type expression".to_owned(),
                    })?;
            type_ref(
                result_type,
                symbols,
                "declarations.callable.results[0].type",
            )
        })
        .transpose()?;
    Ok(Signature {
        type_parameters: Vec::new(),
        parameters,
        returns,
    })
}

fn type_ref(
    value: &CsmiTypeExpression,
    symbols: &HashMap<String, String>,
    path: &str,
) -> Result<TypeRef, CsmiImportError> {
    match value {
        CsmiTypeExpression::Reference(reference) => {
            let name = symbols.get(&reference.symbol).cloned().ok_or_else(|| {
                CsmiImportError::Identity(format!(
                    "unresolved JVM type symbol {} at {path}",
                    reference.symbol
                ))
            })?;
            let arguments = reference
                .arguments
                .iter()
                .enumerate()
                .map(|(position, argument)| {
                    type_ref(argument, symbols, &format!("{path}.arguments[{position}]"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(TypeRef::Named {
                name,
                arguments,
                nullable: false,
            })
        }
        CsmiTypeExpression::Parameter(parameter) => Ok(TypeRef::TypeParameter {
            name: parameter.symbol.clone(),
        }),
        CsmiTypeExpression::Intrinsic(intrinsic) => Err(CsmiImportError::Unsupported {
            path: path.to_owned(),
            semantic: format!(
                "intrinsic type {} from {}@{} is not supported",
                intrinsic.identifier, intrinsic.vocabulary, intrinsic.version
            ),
        }),
        CsmiTypeExpression::Unknown(_) => Err(CsmiImportError::Unsupported {
            path: path.to_owned(),
            semantic: "unknown type expressions are not supported".to_owned(),
        }),
    }
}

fn summary_from_csmi(
    summary: &CsmiProcedureSummary,
    model: &CsmiSemanticModel,
    symbols: &HashMap<String, String>,
    member_ids: &HashMap<String, String>,
) -> Result<AuthoredProcedureSummary, CsmiImportError> {
    let declaration = model
        .declarations
        .iter()
        .find(|declaration| declaration.symbol == summary.callable)
        .ok_or_else(|| {
            CsmiImportError::Identity(format!(
                "summary targets unknown callable {}",
                summary.callable
            ))
        })?;
    let shape = declaration
        .callable
        .as_ref()
        .ok_or_else(|| CsmiImportError::Identity("summary target is not callable".to_owned()))?;
    let owner = declaration
        .owner
        .as_ref()
        .and_then(|id| symbols.get(id))
        .cloned()
        .unwrap_or_default();
    let symbol = model
        .symbols
        .iter()
        .find(|symbol| symbol.id == summary.callable)
        .and_then(callable_name)
        .ok_or_else(|| CsmiImportError::Identity("summary callable has no name".to_owned()))?;
    let target = AuthoredProcedureTarget {
        path: owner,
        symbol,
        has_receiver: shape.receiver.is_some() || shape.kind == CsmiCallableKind::Constructor,
        variadic: shape.parameters.last().is_some_and(|parameter| {
            matches!(
                parameter.binding,
                CsmiParameterBinding::VariadicPositional | CsmiParameterBinding::VariadicNamed
            )
        }),
        parameter_count: shape.parameters.len() as u32,
    };
    let transfers = summary
        .transfers
        .iter()
        .map(|transfer| transfer_from_csmi(transfer, member_ids))
        .collect::<Result<Vec<_>, _>>()?;
    let completeness = model
        .completeness_statements
        .iter()
        .find(|statement| {
            statement.family == "procedure-summaries"
                && statement.scope.get("callable").and_then(Value::as_str)
                    == Some(summary.callable.as_str())
        })
        .map_or(Completeness::Partial, |statement| match statement.status {
            CsmiCoverageStatus::Complete => Completeness::Complete,
            CsmiCoverageStatus::Unknown | CsmiCoverageStatus::Partial => Completeness::Partial,
        });
    Ok(AuthoredProcedureSummary {
        id: format!("csmi-summary.{}", sha256_hex(summary.callable.as_bytes())),
        target,
        completeness,
        covers_overrides: false,
        normal_continuation_absent: false,
        normal_result_count: (!shape.results.is_empty()).then_some(shape.results.len() as u32),
        locations: Vec::new(),
        transfers,
        effects: Vec::new(),
        concurrency_effects: Vec::new(),
        declared_effects: Vec::new(),
        preconditions: None,
        result_contracts: Vec::new(),
        conditional_result_refinements: Vec::new(),
        conditional_indirect_writes: Vec::new(),
        normal_return_refinements: Vec::new(),
    })
}

fn transfer_from_csmi(
    transfer: &CsmiTransfer,
    member_ids: &HashMap<String, String>,
) -> Result<AuthoredSummaryTransfer, CsmiImportError> {
    if transfer.source.projection.is_some() || transfer.destination.projection.is_some() {
        return Err(CsmiImportError::Unsupported {
            path: "procedureSummaries.transfers".to_owned(),
            semantic: "projection steps are not representable in Bifrost summary ports".to_owned(),
        });
    }
    let input = match &transfer.source.root {
        CsmiInputBoundaryRoot::Receiver(_) => AuthoredSummaryInput::Receiver {},
        CsmiInputBoundaryRoot::Parameter(root) => AuthoredSummaryInput::Parameter {
            ordinal: root.position,
        },
        CsmiInputBoundaryRoot::Capture(_) => {
            return Err(CsmiImportError::Unsupported {
                path: "procedureSummaries.transfers.source".to_owned(),
                semantic: "capture roots are not representable without a Bifrost location"
                    .to_owned(),
            });
        }
    };
    let (output, exit_kind) = match &transfer.destination.root {
        CsmiOutputBoundaryRoot::Receiver(_) => (
            AuthoredSummaryOutput::Receiver {},
            AuthoredSummaryExitKind::Normal,
        ),
        CsmiOutputBoundaryRoot::Result(root) if root.position == 0 => (
            AuthoredSummaryOutput::NormalReturn {},
            AuthoredSummaryExitKind::Normal,
        ),
        CsmiOutputBoundaryRoot::Result(root) => (
            AuthoredSummaryOutput::IndexedNormalReturn {
                ordinal: root.position,
            },
            AuthoredSummaryExitKind::Normal,
        ),
        CsmiOutputBoundaryRoot::Exception(_) => (
            AuthoredSummaryOutput::ExceptionalReturn {},
            AuthoredSummaryExitKind::Exceptional,
        ),
        CsmiOutputBoundaryRoot::Parameter(_) => {
            return Err(CsmiImportError::Unsupported {
                path: "procedureSummaries.transfers.destination".to_owned(),
                semantic: "parameter output roots are not representable in Bifrost summaries"
                    .to_owned(),
            });
        }
        CsmiOutputBoundaryRoot::Capture(_) => {
            return Err(CsmiImportError::Unsupported {
                path: "procedureSummaries.transfers.destination".to_owned(),
                semantic: "capture roots are not representable in Bifrost summaries".to_owned(),
            });
        }
    };
    Ok(AuthoredSummaryTransfer {
        input,
        exit_kind,
        output,
        value_transfer: transfer
            .extensions
            .iter()
            .find(|extension| {
                extension.vocabulary == CSMI_VALUE_TRANSFER_PROFILE_ID
                    && extension.version == CSMI_VALUE_TRANSFER_PROFILE_VERSION
            })
            .map(|extension| value_transfer_from_csmi(&extension.payload, member_ids))
            .transpose()?,
    })
}

fn import_value_transfer_facts(
    model: &CsmiSemanticModel,
    type_ids: &HashMap<String, String>,
    member_ids: &HashMap<String, String>,
    types: &mut [TypeFact],
    members: &mut [MemberFact],
) -> Result<(), CsmiImportError> {
    for fact in &model.extension_facts {
        if fact.vocabulary != CSMI_VALUE_TRANSFER_PROFILE_ID
            || fact.version != CSMI_VALUE_TRANSFER_PROFILE_VERSION
        {
            continue;
        }
        let payload: CsmiValueTransferProfilePayload = serde_json::from_value(fact.payload.clone())
            .map_err(|error| CsmiImportError::Unsupported {
                path: "extensionFacts.payload".to_owned(),
                semantic: error.to_string(),
            })?;
        match payload {
            CsmiValueTransferProfilePayload::TypeValue(payload) => {
                let native_type = type_ids.get(&payload.r#type).ok_or_else(|| {
                    CsmiImportError::Identity(format!("unknown type symbol {}", payload.r#type))
                })?;
                let type_fact = types
                    .iter_mut()
                    .find(|fact| &fact.id == native_type)
                    .ok_or_else(|| {
                        CsmiImportError::Identity(format!("missing imported type {native_type}"))
                    })?;
                let semantics = type_fact.value_semantics.get_or_insert(TypeValueSemantics {
                    copy: None,
                    move_semantics: None,
                });
                match (payload.aspect, payload.semantics) {
                    (CsmiTypeValueSemanticsAspect::Copy, CsmiTypeSemantics::Trivial {}) => {
                        semantics.copy = Some(TypeCopySemantics::Trivial);
                    }
                    (
                        CsmiTypeValueSemanticsAspect::Copy,
                        CsmiTypeSemantics::ViaMember { member },
                    ) => {
                        let member = member_ids.get(&member).cloned().ok_or_else(|| {
                            CsmiImportError::Identity(format!("unknown implicit member {member}"))
                        })?;
                        semantics.copy = Some(TypeCopySemantics::ViaMember { member });
                    }
                    (CsmiTypeValueSemanticsAspect::Move, CsmiTypeSemantics::Invalidating {}) => {
                        semantics.move_semantics = Some(TypeMoveSemantics::Invalidating);
                    }
                    (
                        _,
                        CsmiTypeSemantics::Unknown { .. } | CsmiTypeSemantics::Unsupported { .. },
                    ) => {
                        return Err(CsmiImportError::Unsupported {
                            path: "extensionFacts.payload.semantics".to_owned(),
                            semantic: "unknown or unsupported type value semantics cannot be represented in the native closed model".to_owned(),
                        });
                    }
                    _ => {
                        return Err(CsmiImportError::Unsupported {
                            path: "extensionFacts.payload.semantics".to_owned(),
                            semantic: "type value-semantics aspect does not match its semantics"
                                .to_owned(),
                        });
                    }
                }
            }
            CsmiValueTransferProfilePayload::ImplicitOperation(payload) => {
                let native_member = member_ids.get(&payload.symbol).ok_or_else(|| {
                    CsmiImportError::Identity(format!("unknown implicit member {}", payload.symbol))
                })?;
                let member = members
                    .iter_mut()
                    .find(|fact| &fact.id == native_member)
                    .ok_or_else(|| {
                        CsmiImportError::Identity(format!(
                            "missing imported member {native_member}"
                        ))
                    })?;
                member.implicit_operation = Some(match payload.operation {
                    CsmiImplicitOperationRole::CopyConstructor => {
                        ImplicitOperation::CopyConstructor
                    }
                    CsmiImplicitOperationRole::MoveConstructor => {
                        ImplicitOperation::MoveConstructor
                    }
                    CsmiImplicitOperationRole::CopyAssignment => ImplicitOperation::CopyAssignment,
                    CsmiImplicitOperationRole::MoveAssignment => ImplicitOperation::MoveAssignment,
                    CsmiImplicitOperationRole::ConversionOperator => {
                        let target = payload
                            .target
                            .as_ref()
                            .and_then(|id| type_ids.get(id))
                            .ok_or_else(|| {
                                CsmiImportError::Identity(
                                    "conversion operator target is not a local type".to_owned(),
                                )
                            })?;
                        ImplicitOperation::ConversionOperator {
                            target: TypeRef::Declared {
                                id: target.clone(),
                                arguments: Vec::new(),
                                nullable: false,
                            },
                        }
                    }
                });
            }
            CsmiValueTransferProfilePayload::Transfer(_) => {
                return Err(CsmiImportError::Unsupported {
                    path: "extensionFacts.payload".to_owned(),
                    semantic:
                        "transfer payloads are valid only as procedure-summary transfer attachments"
                            .to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn value_transfer_from_csmi(
    value: &Value,
    member_ids: &HashMap<String, String>,
) -> Result<SummaryValueTransfer, CsmiImportError> {
    let payload: CsmiValueTransferAttachment =
        serde_json::from_value(value.clone()).map_err(|error| CsmiImportError::Unsupported {
            path: "procedureSummaries.transfers.extensions.payload".to_owned(),
            semantic: error.to_string(),
        })?;
    let kind = match payload.transfer_kind {
        CsmiValueTransferKind::Copy {} => SummaryValueTransferKind::Copy {},
        CsmiValueTransferKind::AggregateCopy {} => SummaryValueTransferKind::AggregateCopy {},
        CsmiValueTransferKind::Move { invalidation } => SummaryValueTransferKind::Move {
            invalidation: match invalidation {
                CsmiMoveInvalidation::Invalidated => SummaryMoveInvalidation::Invalidated,
                CsmiMoveInvalidation::Unknown => SummaryMoveInvalidation::Unknown,
            },
        },
        CsmiValueTransferKind::Conversion { preservation } => {
            SummaryValueTransferKind::Conversion {
                preservation: match preservation {
                    CsmiValuePreservation::Identity => SummaryValuePreservation::Identity,
                    CsmiValuePreservation::Preserving => SummaryValuePreservation::Preserving,
                    CsmiValuePreservation::Changing => SummaryValuePreservation::Changing,
                    CsmiValuePreservation::Unknown => SummaryValuePreservation::Unknown,
                },
            }
        }
        CsmiValueTransferKind::Boxing {} => SummaryValueTransferKind::Boxing {},
        CsmiValueTransferKind::Unboxing {} => SummaryValueTransferKind::Unboxing {},
    };
    let operation = match payload.operation {
        CsmiValueTransferOperation::None {} => SummaryValueTransferOperation::None {},
        CsmiValueTransferOperation::Implicit { symbol } => {
            SummaryValueTransferOperation::Implicit {
                member: member_ids.get(&symbol).cloned().ok_or_else(|| {
                    CsmiImportError::Identity(format!("unknown implicit operation symbol {symbol}"))
                })?,
            }
        }
        CsmiValueTransferOperation::Unknown { limitation } => {
            SummaryValueTransferOperation::Unknown {
                limitation: SummaryValueTransferLimitation {
                    kind: match limitation.kind {
                        CsmiProfileLimitationKind::BudgetExhausted => {
                            SummaryValueTransferLimitationKind::BudgetExhausted
                        }
                        CsmiProfileLimitationKind::Cancelled => {
                            SummaryValueTransferLimitationKind::Cancelled
                        }
                        CsmiProfileLimitationKind::Unsupported => {
                            SummaryValueTransferLimitationKind::Unsupported
                        }
                        CsmiProfileLimitationKind::UnresolvedIdentity => {
                            SummaryValueTransferLimitationKind::UnresolvedIdentity
                        }
                        CsmiProfileLimitationKind::AmbiguousIdentity => {
                            SummaryValueTransferLimitationKind::AmbiguousIdentity
                        }
                        CsmiProfileLimitationKind::IncompleteInput => {
                            SummaryValueTransferLimitationKind::IncompleteInput
                        }
                        CsmiProfileLimitationKind::Other => {
                            SummaryValueTransferLimitationKind::Other
                        }
                    },
                    message: limitation.message,
                },
            }
        }
    };
    Ok(SummaryValueTransfer { kind, operation })
}
