//! Translation from a verified CSMI v0.1 logical pack into Bifrost authoring
//! types. No CSMI sidecar or producer-specific metadata is consulted.

use crate::analyzer::semantic_model::{
    ConditionalTypeRefinementFact, ConditionalTypeRefinementsPayload, DeferredYieldFact,
    DeferredYieldsPayload,
};

use super::canonical::{canonical_pack_manifest, sha256_hex};
use super::identity::{JVM_IDENTITY_SCHEME, JVM_IDENTITY_VERSION, type_symbol_id};
use super::model::*;
use super::pack::{CsmiLogicalPack, CsmiResourceResolver};
use super::validate::{CsmiVocabularySupport, validate_csmi_pack};
use crate::analyzer::semantic_model::{
    ActivationSelector, AuthoredPayload, AuthoredProcedureSummary, AuthoredProcedureTarget,
    AuthoredSemanticModelPack, AuthoredShard, AuthoredSummaryExitKind, AuthoredSummaryInput,
    AuthoredSummaryLocation, AuthoredSummaryLocationKind, AuthoredSummaryOutput,
    AuthoredSummaryTransfer, CollectionFlowFact, CollectionFlowsPayload, Compatibility,
    CompilerOptions, Completeness, CppArtifactDigest, CppArtifactSelector, CppCallableKind,
    CppCallableSignature, CppCanonicalType, CppDescriptorRole, CppDigestAlgorithm, CppDirectHeader,
    CppFundamentalTypeName, CppHeaderClosure, CppIdentityStability, CppLanguage,
    CppPortabilityEvidence, CppPortableSymbolKey, CppPortableSymbolRecord, CppReferenceKind,
    CppResolutionContextRecord, CppResolutionContextRef, CppSpecialMemberEvidence,
    CppSpecialMemberOperation, CppSymbolDescriptor, CppTypeAliasEvidence, CppTypeQualifier,
    ImplicitOperation, KeyedReadBehavior, KeyedReadObservation, Locator, MemberFact, MemberKind,
    NameSelector, NormalResultTransferPartition, Parameter, ParameterPassingMode,
    PortableProfileEvidence, Producer, Provenance, PythonCorrespondenceEvidence,
    PythonCorrespondenceSymbol, ReceiverFact, RuntimeContractsPayload,
    RuntimeGlobalBindingEvidence, RuntimeGlobalExposure, RuntimeValueExtension,
    RuntimeValuesPayload, Safety, Signature, SummaryMoveInvalidation, SummaryValuePreservation,
    SummaryValueTransfer, SummaryValueTransferKind, SummaryValueTransferLimitation,
    SummaryValueTransferLimitationKind, SummaryValueTransferOperation, TransferPartitionLimitation,
    TransferPartitionSource, TransferPartitionStatus, TypeCopySemantics, TypeFact, TypeKind,
    TypeMoveSemantics, TypeRef, TypeValueSemantics, Visibility, compile_pack,
};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};

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
    import_csmi_pack_with_language(manifest_bytes, resources, support, compiler_options, None)
}

/// Import a CSMI pack into the one native language selected by the caller.
///
/// A CSMI runtime exposure may apply to several source languages, while one
/// Bifrost semantic-model pack has one manifest language. Runtime-only
/// documents that name more than one language therefore require this explicit
/// target instead of silently becoming a Java or C++ pack.
pub fn import_csmi_pack_for_language(
    manifest_bytes: &[u8],
    resources: &dyn CsmiResourceResolver,
    support: &CsmiVocabularySupport,
    compiler_options: &CompilerOptions,
    language: &str,
) -> Result<CsmiImportedPack, CsmiImportReport> {
    import_csmi_pack_with_language(
        manifest_bytes,
        resources,
        support,
        compiler_options,
        Some(language),
    )
}

fn import_csmi_pack_with_language(
    manifest_bytes: &[u8],
    resources: &dyn CsmiResourceResolver,
    support: &CsmiVocabularySupport,
    compiler_options: &CompilerOptions,
    requested_language: Option<&str>,
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
    let pack = import_semantic_document(semantic, manifest, &pack_digest, requested_language)?;
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
    import_logical_csmi_pack_with_language(pack, support, compiler_options, None)
}

/// Convenience wrapper for importing a multi-language runtime document into
/// one explicit native-language pack.
pub fn import_logical_csmi_pack_for_language(
    pack: &CsmiLogicalPack,
    support: &CsmiVocabularySupport,
    compiler_options: &CompilerOptions,
    language: &str,
) -> Result<CsmiImportedPack, CsmiImportReport> {
    import_logical_csmi_pack_with_language(pack, support, compiler_options, Some(language))
}

fn import_logical_csmi_pack_with_language(
    pack: &CsmiLogicalPack,
    support: &CsmiVocabularySupport,
    compiler_options: &CompilerOptions,
    requested_language: Option<&str>,
) -> Result<CsmiImportedPack, CsmiImportReport> {
    let manifest = pack
        .canonical_manifest_bytes()
        .map_err(|error| CsmiImportError::Identity(error.to_string()))?;
    import_csmi_pack_with_language(
        &manifest,
        &pack.resources,
        support,
        compiler_options,
        requested_language,
    )
}

fn import_semantic_document(
    document: &CsmiSemanticDocument,
    manifest: &CsmiPackManifest,
    pack_digest: &str,
    requested_language: Option<&str>,
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
    let runtime_values = import_runtime_values(model, document.default_provenance.as_deref())?;
    let runtime_contracts =
        import_runtime_contracts(model, document, document.default_provenance.as_deref())?;
    let collection_flows = import_collection_flows(model, document.default_provenance.as_deref())?;
    let has_declaration_identity = !model.symbols.is_empty()
        || !model.declarations.is_empty()
        || !model.procedure_summaries.is_empty();
    let runtime_only =
        (runtime_values.is_some() || runtime_contracts.is_some()) && !has_declaration_identity;
    let cpp_identity = !runtime_only
        && !model.symbols.is_empty()
        && model.symbols.iter().all(|symbol| {
            symbol.scheme == CSMI_CPP_DECLARATION_IDENTITY_SCHEME
                && symbol.scheme_version == CSMI_CPP_DECLARATION_IDENTITY_SCHEME_VERSION
                && symbol.stability == CsmiStability::Portable
        });
    let jvm_identity = !runtime_only
        && !model.symbols.is_empty()
        && model.symbols.iter().all(|symbol| {
            symbol.scheme == JVM_IDENTITY_SCHEME && symbol.scheme_version == JVM_IDENTITY_VERSION
        });
    let python_identity = !runtime_only
        && !model.symbols.is_empty()
        && model.symbols.iter().all(|symbol| {
            symbol.scheme == CSMI_PYTHON_PROFILE_ID
                && symbol.scheme_version == CSMI_PYTHON_PROFILE_VERSION
        });
    if python_identity {
        if requested_language.is_some_and(|language| language != "python") {
            return Err(CsmiImportError::Unsupported {
                path: "semanticModels[0]".to_owned(),
                semantic: "Python declaration identities cannot activate as another language"
                    .to_owned(),
            });
        }
        super::python::validate_model(model).map_err(|semantic| CsmiImportError::Unsupported {
            path: "semanticModels[0]".to_owned(),
            semantic,
        })?;
    }
    if !cpp_identity && !jvm_identity && !python_identity && !runtime_only {
        return Err(CsmiImportError::Unsupported {
            path: "symbols".to_owned(),
            semantic: "all symbols must use one supported exact identity scheme".to_owned(),
        });
    }
    let runtime_profile_digests = runtime_profile_digests(model)?;
    let selectors = model
        .artifact_selectors
        .iter()
        .map(|selector| {
            selector_from_csmi(
                selector,
                &runtime_profile_digests,
                runtime_contracts.is_some(),
            )
        })
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
    let python_keys = if python_identity {
        model
            .symbols
            .iter()
            .map(|symbol| {
                Ok((
                    symbol.id.clone(),
                    super::python::identity_from_symbol(symbol, &model.artifact_selectors)
                        .map_err(CsmiImportError::Identity)?,
                ))
            })
            .collect::<Result<HashMap<_, _>, CsmiImportError>>()?
    } else {
        HashMap::new()
    };
    let python_correspondence_facts = model.extension_facts.iter().any(|fact| {
        fact.vocabulary == CSMI_PYTHON_PROFILE_ID && fact.family == "declaration-correspondence"
    });
    let has_python_correspondence = python_identity && python_correspondence_facts;
    let python_correspondence = has_python_correspondence
        .then(|| import_python_correspondence(model, document, &python_keys))
        .transpose()?;
    let mut symbols = HashMap::new();
    let mut types = Vec::new();
    let mut type_ids = HashMap::new();
    for symbol in &model.symbols {
        let name = if let Some(key) = python_keys.get(&symbol.id) {
            key.descriptors
                .last()
                .filter(|descriptor| {
                    matches!(
                        descriptor.role,
                        CsmiDescriptorRole::Namespace | CsmiDescriptorRole::Type
                    )
                })
                .map(|_| super::python::qualified_name(key))
        } else {
            type_name(symbol)
        };
        if let Some(name) = name {
            let native_id = if let Some(key) = python_keys.get(&symbol.id) {
                super::python::native_id(key)
            } else if cpp_identity {
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
        if !(matches!(
            declaration.category,
            CsmiDeclarationCategory::Type | CsmiDeclarationCategory::TypeAlias
        ) || (python_identity && declaration.category == CsmiDeclarationCategory::Namespace))
        {
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
        let name = symbols.get(&symbol.id).cloned().ok_or_else(|| {
            CsmiImportError::Identity(format!(
                "symbol {} has no supported declaration descriptor",
                symbol.id
            ))
        })?;
        let id = type_ids
            .get(&symbol.id)
            .cloned()
            .unwrap_or_else(|| symbol.id.clone());
        types.push(TypeFact {
            ambient_use: None,
            id: id.clone(),
            name: name.clone(),
            type_kind: if python_identity
                && declaration.category == CsmiDeclarationCategory::Namespace
            {
                TypeKind::Module
            } else if declaration.category == CsmiDeclarationCategory::TypeAlias {
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
            locator: if let Some(key) = python_keys.get(&symbol.id) {
                Locator::Interchange {
                    path: format!("csmi/{pack_digest}.json"),
                    symbol: symbol.id.clone(),
                    identity: Box::new(key.clone()),
                    profile_evidence: None,
                    callable_shape_evidence: None,
                }
            } else {
                Locator::Artifact {
                    path: format!("csmi/{pack_digest}.json"),
                    symbol: name,
                }
            },
        });
    }
    let reference_types = if python_identity {
        type_ids
            .iter()
            .map(|(local, native)| {
                (
                    local.clone(),
                    TypeRef::Declared {
                        id: native.clone(),
                        arguments: Vec::new(),
                        nullable: false,
                    },
                )
            })
            .collect::<HashMap<_, _>>()
    } else {
        symbols
            .iter()
            .map(|(local, name)| {
                (
                    local.clone(),
                    TypeRef::Named {
                        name: name.clone(),
                        arguments: Vec::new(),
                        nullable: false,
                    },
                )
            })
            .collect::<HashMap<_, _>>()
    };
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
        let signature = signature_from_shape(shape, &reference_types)?;
        let owner_id = if python_identity {
            type_ids.get(owner_symbol).cloned().ok_or_else(|| {
                CsmiImportError::Identity(format!(
                    "unknown Python callable owner symbol {owner_symbol}"
                ))
            })?
        } else {
            types
                .iter()
                .find(|fact| fact.name == owner_name)
                .map(|fact| fact.id.clone())
                .unwrap_or_else(|| {
                    type_symbol_id(&owner_name).unwrap_or_else(|_| owner_symbol.clone())
                })
        };
        let member_id = if let Some(key) = python_keys.get(&declaration.symbol) {
            super::python::native_id(key)
        } else if cpp_identity {
            cpp_native_ids[&declaration.symbol].clone()
        } else {
            format!("member.{}", sha256_hex(declaration.symbol.as_bytes()))
        };
        let callable_shape_statement = model.completeness_statements.iter().find(|statement| {
            statement.vocabulary.is_none()
                && statement.version.is_none()
                && statement.family == "declaration-aspects"
                && statement.scope.get("symbol").and_then(Value::as_str)
                    == Some(declaration.symbol.as_str())
                && statement.scope.get("aspect").and_then(Value::as_str) == Some("callable-shape")
        });
        let callable_family_complete = !python_identity
            && callable_shape_statement
                .is_some_and(|statement| statement.status == CsmiCoverageStatus::Complete);
        member_ids.insert(declaration.symbol.clone(), member_id.clone());
        members.push(MemberFact {
            ambient_use: None,
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
            explicit_operation: None,
            callable_family_complete,
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
            locator: if let Some(key) = python_keys.get(&symbol.id) {
                Locator::Interchange {
                    path: format!("csmi/{pack_digest}.json"),
                    symbol: symbol.id.clone(),
                    identity: Box::new(key.clone()),
                    profile_evidence: None,
                    callable_shape_evidence: None,
                }
            } else {
                Locator::Artifact {
                    path: format!("csmi/{pack_digest}.json"),
                    symbol: symbol.id.clone(),
                }
            },
        });
        if python_identity && let Some(statement) = callable_shape_statement {
            let member = members.last_mut().expect("callable was just appended");
            let native_sha256 = super::python::native_callable_shape_digest(member);
            let provenance_records = document
                .provenance_records
                .iter()
                .filter(|record| {
                    statement.provenance.contains(&record.id)
                        || document.default_provenance.as_ref() == Some(&record.id)
                })
                .cloned()
                .collect();
            let Locator::Interchange {
                callable_shape_evidence,
                ..
            } = &mut member.locator
            else {
                unreachable!("Python callable has a portable locator");
            };
            *callable_shape_evidence = Some(Box::new(
                crate::analyzer::semantic_model::PortableCallableShapeEvidence {
                    native_sha256,
                    statement: statement.clone(),
                    provenance_records,
                    default_provenance: document.default_provenance.clone(),
                    evidence_sha256: String::new(),
                },
            ));
            if let Some(evidence) = callable_shape_evidence {
                evidence.evidence_sha256 = super::python::callable_shape_evidence_digest(evidence);
            }
        }
    }
    import_value_transfer_facts(model, &type_ids, &member_ids, &mut types, &mut members)?;
    let conditional_type_refinements = import_conditional_type_refinements(
        model,
        document.default_provenance.as_deref(),
        &type_ids,
        &member_ids,
    )?;
    let deferred_yields = import_deferred_yields(
        model,
        document.default_provenance.as_deref(),
        &type_ids,
        &member_ids,
    )?;
    let completeness = model
        .completeness_statements
        .iter()
        .find(|statement| {
            statement.family == "declaration-records"
                && statement.vocabulary.is_none()
                && statement.version.is_none()
                && statement.scope.get("scheme").and_then(Value::as_str)
                    == Some(if python_identity {
                        CSMI_PYTHON_PROFILE_ID
                    } else if cpp_identity {
                        CSMI_CPP_DECLARATION_IDENTITY_SCHEME
                    } else {
                        JVM_IDENTITY_SCHEME
                    })
                && statement.scope.get("schemeVersion").and_then(Value::as_str)
                    == Some(if python_identity {
                        CSMI_PYTHON_PROFILE_VERSION
                    } else if cpp_identity {
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
    let runtime_values_identity = runtime_values
        .as_ref()
        .map(|payload| runtime_pack_identity(payload, requested_language))
        .transpose()?;
    let runtime_contracts_identity = runtime_contracts
        .as_ref()
        .map(|carrier| runtime_contract_pack_identity(&carrier.payload, requested_language))
        .transpose()?;
    let runtime_identity = match (
        runtime_values_identity.as_ref(),
        runtime_contracts_identity.as_ref(),
    ) {
        (Some(values), Some(contracts)) if values != contracts => {
            return Err(CsmiImportError::Unsupported {
                path: "semanticModels[0].extensionFacts".to_owned(),
                semantic: format!(
                    "runtime values resolve to {}/{} but runtime contracts resolve to {}/{}",
                    values.0, values.1, contracts.0, contracts.1
                ),
            });
        }
        (Some(values), _) => Some(values.clone()),
        (_, Some(contracts)) => Some(contracts.clone()),
        (None, None) => None,
    };
    let declaration_identity = if python_identity {
        Some(("python".to_owned(), "python".to_owned()))
    } else if cpp_identity {
        Some(("cpp".to_owned(), "cpp-headers".to_owned()))
    } else if jvm_identity {
        Some(("java".to_owned(), "maven".to_owned()))
    } else {
        None
    };
    let (language, ecosystem) = match (declaration_identity, runtime_identity) {
        (Some(declaration), Some(runtime)) if declaration != runtime => {
            return Err(CsmiImportError::Unsupported {
                path: "semanticModels[0].extensionFacts".to_owned(),
                semantic: format!(
                    "runtime values resolve to {}/{} and cannot share a {}/{} declaration pack",
                    runtime.0, runtime.1, declaration.0, declaration.1
                ),
            });
        }
        (Some(declaration), _) | (None, Some(declaration)) => declaration,
        (None, None) => unreachable!("unsupported declaration identity was rejected above"),
    };
    for member in &mut members {
        if !matches!(
            &member.locator,
            Locator::Interchange {
                callable_shape_evidence: Some(_),
                ..
            }
        ) {
            continue;
        }
        let native_sha256 = super::python::native_callable_shape_digest(member);
        if let Locator::Interchange {
            callable_shape_evidence: Some(evidence),
            ..
        } = &mut member.locator
        {
            evidence.native_sha256 = native_sha256;
            evidence.evidence_sha256 = super::python::callable_shape_evidence_digest(evidence);
        }
    }
    let shards = if has_python_correspondence {
        let declaration_artifact = model
            .artifact_selectors
            .first()
            .expect("validated Python model has one declaration artifact");
        let declaration_key = super::canonical::canonical_json(declaration_artifact)
            .map_err(|error| CsmiImportError::Identity(error.to_string()))?;
        let mut artifact_facts =
            HashMap::<Vec<u8>, (ActivationSelector, Vec<TypeFact>, Vec<MemberFact>)>::new();
        for fact in types {
            let artifact = python_artifact_for_locator(&fact.locator)?.clone();
            let key = super::canonical::canonical_json(&artifact)
                .map_err(|error| CsmiImportError::Identity(error.to_string()))?;
            let selector =
                selector_for_python_artifact(&artifact, declaration_artifact, &selectors)?;
            let entry = artifact_facts
                .entry(key)
                .or_insert_with(|| (selector, Vec::new(), Vec::new()));
            entry.1.push(fact);
        }
        for fact in members {
            let artifact = python_artifact_for_locator(&fact.locator)?.clone();
            let key = super::canonical::canonical_json(&artifact)
                .map_err(|error| CsmiImportError::Identity(error.to_string()))?;
            let selector =
                selector_for_python_artifact(&artifact, declaration_artifact, &selectors)?;
            let entry = artifact_facts
                .entry(key)
                .or_insert_with(|| (selector, Vec::new(), Vec::new()));
            entry.2.push(fact);
        }

        let has_declaration_payload = runtime_values.is_some()
            || runtime_contracts.is_some()
            || collection_flows.is_some()
            || deferred_yields.is_some()
            || conditional_type_refinements.is_some();
        if has_declaration_payload {
            let selector = selector_for_python_artifact(
                declaration_artifact,
                declaration_artifact,
                &selectors,
            )?;
            artifact_facts
                .entry(declaration_key.clone())
                .or_insert_with(|| (selector, Vec::new(), Vec::new()));
        }

        let mut declaration_shards = Vec::new();
        for (key, (selector, types, members)) in artifact_facts {
            let declaration_artifact_shard = key == declaration_key;
            declaration_shards.push(AuthoredShard {
                id: format!(
                    "csmi.{pack_digest}.declarations.{}",
                    &sha256_hex(&key)[..16]
                ),
                activation: vec![selector],
                payload: AuthoredPayload::DeclarationFacts {
                    types,
                    members,
                    relations: Vec::new(),
                },
                runtime_values: declaration_artifact_shard
                    .then(|| runtime_values.clone())
                    .flatten(),
                runtime_contracts: declaration_artifact_shard
                    .then(|| runtime_contracts.clone())
                    .flatten(),
                collection_flows: declaration_artifact_shard
                    .then(|| collection_flows.clone())
                    .flatten(),
                deferred_yields: declaration_artifact_shard
                    .then(|| deferred_yields.clone())
                    .flatten(),
                conditional_type_refinements: declaration_artifact_shard
                    .then(|| conditional_type_refinements.clone())
                    .flatten(),
            });
        }
        let mut summary_artifacts =
            HashMap::<Vec<u8>, (ActivationSelector, Vec<AuthoredProcedureSummary>)>::new();
        for (source, summary) in model.procedure_summaries.iter().zip(summaries) {
            let symbol = model
                .symbols
                .iter()
                .find(|symbol| symbol.id == source.callable)
                .expect("validated Python summary names a symbol");
            let identity = python_keys
                .get(&symbol.id)
                .expect("validated Python symbol has an identity");
            let artifact = identity
                .artifact_selectors
                .first()
                .expect("Python identity has one artifact");
            let key = super::canonical::canonical_json(artifact)
                .map_err(|error| CsmiImportError::Identity(error.to_string()))?;
            let selector =
                selector_for_python_artifact(artifact, declaration_artifact, &selectors)?;
            summary_artifacts
                .entry(key)
                .or_insert_with(|| (selector, Vec::new()))
                .1
                .push(summary);
        }
        for (key, (selector, summaries)) in summary_artifacts {
            let summary_shard = AuthoredShard {
                id: format!(
                    "csmi.{pack_digest}.procedure-summaries.{}",
                    &sha256_hex(&key)[..16]
                ),
                activation: vec![selector],
                payload: AuthoredPayload::ProcedureSummaries { summaries },
                runtime_values: None,
                runtime_contracts: None,
                collection_flows: None,
                deferred_yields: None,
                conditional_type_refinements: None,
            };
            if !summaries_empty(&summary_shard) {
                declaration_shards.push(summary_shard);
            }
        }
        declaration_shards
    } else {
        let shard = AuthoredShard {
            id: format!("csmi.{pack_digest}.summaries"),
            activation: selectors,
            payload: AuthoredPayload::DeclarationFacts {
                types,
                members,
                relations: Vec::new(),
            },
            runtime_values,
            runtime_contracts,
            collection_flows,
            deferred_yields,
            conditional_type_refinements,
        };
        let summary_shard = AuthoredShard {
            id: format!("csmi.{pack_digest}.procedure-summaries"),
            activation: shard.activation.clone(),
            payload: AuthoredPayload::ProcedureSummaries { summaries },
            runtime_values: None,
            runtime_contracts: None,
            collection_flows: None,
            deferred_yields: None,
            conditional_type_refinements: None,
        };
        if summaries_empty(&summary_shard) {
            vec![shard]
        } else {
            vec![shard, summary_shard]
        }
    };
    let mut pack = AuthoredSemanticModelPack {
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
        python_correspondence: None,
        shards,
    };
    if let Some(evidence) = python_correspondence {
        pack.python_correspondence = Some(evidence);
        let native_sha256 = super::python::native_correspondence_digest(&pack);
        pack.python_correspondence
            .as_mut()
            .expect("correspondence carrier was just set")
            .native_sha256 = native_sha256;
    } else if python_identity && model.artifact_selectors[0].purl.starts_with("pkg:pypi/") {
        let native_sha256 = super::python::native_profile_digest(&pack);
        let evidence = PortableProfileEvidence {
            native_sha256,
            vocabulary_uses: model
                .vocabulary_uses
                .iter()
                .filter(|use_| use_.identifier == CSMI_PYTHON_PROFILE_ID)
                .cloned()
                .collect(),
            extension_facts: model
                .extension_facts
                .iter()
                .filter(|fact| fact.vocabulary == CSMI_PYTHON_PROFILE_ID)
                .cloned()
                .collect(),
            completeness_statements: model
                .completeness_statements
                .iter()
                .filter(|statement| statement.vocabulary.as_deref() == Some(CSMI_PYTHON_PROFILE_ID))
                .cloned()
                .collect(),
            provenance_records: document.provenance_records.clone(),
            default_provenance: document.default_provenance.clone(),
        };
        let Some(Locator::Interchange {
            profile_evidence, ..
        }) = pack
            .shards
            .iter_mut()
            .find_map(|shard| match &mut shard.payload {
                AuthoredPayload::DeclarationFacts { types, .. } => {
                    types.first_mut().map(|fact| &mut fact.locator)
                }
                _ => None,
            })
        else {
            return Err(CsmiImportError::Unsupported {
                path: "symbols".to_owned(),
                semantic: "Python distribution has no declared module to carry profile evidence"
                    .to_owned(),
            });
        };
        *profile_evidence = Some(Box::new(evidence));
    }
    Ok(pack)
}

fn import_python_correspondence(
    model: &CsmiSemanticModel,
    document: &CsmiSemanticDocument,
    python_keys: &HashMap<String, CsmiPortableSymbolIdentity>,
) -> Result<PythonCorrespondenceEvidence, CsmiImportError> {
    let declaration_artifact = model
        .artifact_selectors
        .first()
        .expect("validated Python model has one declaration artifact")
        .clone();
    let symbols = model
        .symbols
        .iter()
        .map(|symbol| PythonCorrespondenceSymbol {
            local_id: symbol.id.clone(),
            identity: python_keys[&symbol.id].clone(),
            provenance: symbol.provenance.clone(),
        })
        .collect();
    let mut mappings = Vec::new();
    for fact in model.extension_facts.iter().filter(|fact| {
        fact.vocabulary == CSMI_PYTHON_PROFILE_ID && fact.family == "declaration-correspondence"
    }) {
        let values = fact
            .payload
            .get("mappings")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CsmiImportError::Identity(
                    "validated Python correspondence fact has no mappings array".to_owned(),
                )
            })?;
        for value in values {
            mappings.push(serde_json::from_value(value.clone()).map_err(|error| {
                CsmiImportError::Unsupported {
                    path: "extensionFacts.declaration-correspondence.mappings".to_owned(),
                    semantic: error.to_string(),
                }
            })?);
        }
    }
    Ok(PythonCorrespondenceEvidence {
        native_sha256: String::new(),
        declaration_artifact,
        symbols,
        mappings,
        vocabulary_uses: model
            .vocabulary_uses
            .iter()
            .filter(|use_| use_.identifier == CSMI_PYTHON_PROFILE_ID)
            .cloned()
            .collect(),
        extension_facts: model
            .extension_facts
            .iter()
            .filter(|fact| fact.vocabulary == CSMI_PYTHON_PROFILE_ID)
            .cloned()
            .collect(),
        completeness_statements: model
            .completeness_statements
            .iter()
            .filter(|statement| statement.vocabulary.as_deref() == Some(CSMI_PYTHON_PROFILE_ID))
            .cloned()
            .collect(),
        core_completeness_statements: model
            .completeness_statements
            .iter()
            .filter(|statement| statement.vocabulary.is_none())
            .cloned()
            .collect(),
        provenance_records: document.provenance_records.clone(),
        default_provenance: document.default_provenance.clone(),
    })
}

fn python_artifact_for_locator(
    locator: &Locator,
) -> Result<&CsmiArtifactSelector, CsmiImportError> {
    let Locator::Interchange { identity, .. } = locator else {
        return Err(CsmiImportError::Identity(
            "Python declaration has no artifact-scoped interchange identity".to_owned(),
        ));
    };
    identity.artifact_selectors.first().ok_or_else(|| {
        CsmiImportError::Identity("Python identity has no exact artifact selector".to_owned())
    })
}

fn selector_for_python_artifact(
    artifact: &CsmiArtifactSelector,
    declaration_artifact: &CsmiArtifactSelector,
    declaration_selectors: &[ActivationSelector],
) -> Result<ActivationSelector, CsmiImportError> {
    if artifact == declaration_artifact {
        return Ok(declaration_selectors
            .first()
            .expect("validated Python model has one declaration selector")
            .clone());
    }
    selector_from_csmi(artifact, &[], false)
}

/// Import the four runtime-values families as one lossless native payload.
/// The profile records deliberately have the same JSON member names and enum
/// vocabulary as the native model; serde conversion keeps this boundary typed
/// without treating producer-local handles as Bifrost declaration IDs.
fn import_runtime_values(
    model: &CsmiSemanticModel,
    default_provenance: Option<&str>,
) -> Result<Option<RuntimeValuesPayload>, CsmiImportError> {
    let mut payload = RuntimeValuesPayload {
        exposures: Vec::new(),
        behaviors: Vec::new(),
        binding_evidence: Vec::new(),
        observations: Vec::new(),
    };
    for fact in &model.extension_facts {
        if fact.vocabulary != CSMI_RUNTIME_VALUES_PROFILE_ID
            || fact.version != CSMI_RUNTIME_VALUES_PROFILE_VERSION
        {
            continue;
        }
        let wire: CsmiRuntimeValuesPayload =
            serde_json::from_value(fact.payload.clone()).map_err(|error| {
                CsmiImportError::Unsupported {
                    path: format!("extensionFacts.{}.payload", fact.family),
                    semantic: error.to_string(),
                }
            })?;
        if wire.family() != fact.family {
            return Err(CsmiImportError::Unsupported {
                path: format!("extensionFacts.{}.family", fact.family),
                semantic: format!("payload kind belongs to {}", wire.family()),
            });
        }
        match wire {
            CsmiRuntimeValuesPayload::RuntimeGlobalExposure(record) => {
                let mut native: RuntimeGlobalExposure = native_runtime_record(record)?;
                native.provenance = runtime_provenance(fact, default_provenance);
                native.extensions = runtime_extensions(&fact.extensions);
                payload.exposures.push(native);
            }
            CsmiRuntimeValuesPayload::KeyedReadBehavior(record) => {
                let mut native: KeyedReadBehavior = native_runtime_record(record)?;
                native.provenance = runtime_provenance(fact, default_provenance);
                native.extensions = runtime_extensions(&fact.extensions);
                payload.behaviors.push(native);
            }
            CsmiRuntimeValuesPayload::RuntimeGlobalBindingEvidence(record) => {
                let mut native: RuntimeGlobalBindingEvidence = native_runtime_record(record)?;
                native.provenance = runtime_provenance(fact, default_provenance);
                native.extensions = runtime_extensions(&fact.extensions);
                payload.binding_evidence.push(native);
            }
            CsmiRuntimeValuesPayload::KeyedReadObservation(record) => {
                let mut native: KeyedReadObservation = native_runtime_record(record)?;
                native.provenance = runtime_provenance(fact, default_provenance);
                native.extensions = runtime_extensions(&fact.extensions);
                payload.observations.push(native);
            }
        }
    }
    Ok((payload.record_count() > 0).then_some(payload))
}

/// Import all five runtime-values 0.2 families as one native companion. The
/// complete semantic model is retained as an envelope so fields not needed by
/// native evaluation remain available for a lossless export.
fn import_runtime_contracts(
    model: &CsmiSemanticModel,
    document: &CsmiSemanticDocument,
    default_provenance: Option<&str>,
) -> Result<Option<RuntimeContractsPayload>, CsmiImportError> {
    let mut payload =
        crate::analyzer::semantic_model::runtime_contracts::RuntimeContractsPayloadV2 {
            contracts: Vec::new(),
            targets: Vec::new(),
            activations: Vec::new(),
            bindings: Vec::new(),
            observations: Vec::new(),
        };
    for fact in &model.extension_facts {
        if fact.vocabulary != CSMI_RUNTIME_VALUES_PROFILE_ID
            || fact.version
                != crate::analyzer::semantic_model::runtime_contracts::RUNTIME_VALUES_V2_VERSION
        {
            continue;
        }
        let record: crate::analyzer::semantic_model::runtime_contracts::CsmiRuntimeContractsV2Payload =
            serde_json::from_value(fact.payload.clone()).map_err(|error| CsmiImportError::Unsupported {
                path: format!("extensionFacts.{}.payload", fact.family),
                semantic: error.to_string(),
            })?;
        if record.family() != fact.family {
            return Err(CsmiImportError::Unsupported {
                path: format!("extensionFacts.{}.family", fact.family),
                semantic: format!("payload kind belongs to {}", record.family()),
            });
        }
        match record {
            CsmiRuntimeContractsV2Payload::RuntimeContract(record) => {
                payload.contracts.push(record)
            }
            CsmiRuntimeContractsV2Payload::RuntimeTarget(record) => payload.targets.push(record),
            CsmiRuntimeContractsV2Payload::RuntimeActivation(record) => {
                payload.activations.push(record)
            }
            CsmiRuntimeContractsV2Payload::RuntimeBinding(record) => payload.bindings.push(record),
            CsmiRuntimeContractsV2Payload::RuntimeObservation(record) => {
                payload.observations.push(*record)
            }
        }
    }
    if payload.is_empty() {
        return Ok(None);
    }
    let mut envelope = serde_json::to_value(document)
        .map_err(|error| CsmiImportError::Identity(error.to_string()))?;
    crate::analyzer::semantic_model::normalize_runtime_contract_envelope(&mut envelope)
        .map_err(|error| CsmiImportError::Identity(error.to_string()))?;
    let _ = default_provenance;
    Ok(Some(RuntimeContractsPayload {
        payload,
        envelope: Some(envelope),
    }))
}

fn import_collection_flows(
    model: &CsmiSemanticModel,
    default_provenance: Option<&str>,
) -> Result<Option<CollectionFlowsPayload>, CsmiImportError> {
    let mut flows = Vec::new();
    for fact in &model.extension_facts {
        if fact.vocabulary != CSMI_COLLECTION_FLOW_PROFILE_ID
            || fact.version != CSMI_COLLECTION_FLOW_PROFILE_VERSION
        {
            continue;
        }
        if fact.family != "collection-flows" {
            return Err(CsmiImportError::Unsupported {
                path: "extensionFacts.family".to_owned(),
                semantic: "collection-flow facts must use family collection-flows".to_owned(),
            });
        }
        let callable = fact
            .scope
            .get("callable")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CsmiImportError::Identity("collection-flow fact scope has no callable".to_owned())
            })?;
        let payload: CsmiCollectionFlowPayload = serde_json::from_value(fact.payload.clone())
            .map_err(|error| CsmiImportError::Unsupported {
                path: "extensionFacts.payload".to_owned(),
                semantic: error.to_string(),
            })?;
        if payload.callable != callable {
            return Err(CsmiImportError::Identity(
                "collection-flow payload callable does not match fact scope".to_owned(),
            ));
        }
        flows.push(CollectionFlowFact {
            callable: callable.to_owned(),
            payload,
            coverage: model
                .completeness_statements
                .iter()
                .find(|statement| {
                    statement.vocabulary.as_deref() == Some(CSMI_COLLECTION_FLOW_PROFILE_ID)
                        && statement.version.as_deref()
                            == Some(CSMI_COLLECTION_FLOW_PROFILE_VERSION)
                        && statement.family == "collection-flows"
                        && statement.scope.get("callable").and_then(Value::as_str) == Some(callable)
                })
                .map(|statement| match statement.status {
                    CsmiCoverageStatus::Complete => Completeness::Complete,
                    CsmiCoverageStatus::Unknown | CsmiCoverageStatus::Partial => {
                        Completeness::Partial
                    }
                }),
            provenance: if fact.provenance.is_empty() {
                default_provenance.map(str::to_owned).into_iter().collect()
            } else {
                fact.provenance.clone()
            },
        });
    }
    Ok((!flows.is_empty()).then_some(CollectionFlowsPayload { flows }))
}

fn import_conditional_type_refinements(
    model: &CsmiSemanticModel,
    default_provenance: Option<&str>,
    type_ids: &HashMap<String, String>,
    member_ids: &HashMap<String, String>,
) -> Result<Option<ConditionalTypeRefinementsPayload>, CsmiImportError> {
    let mut refinements: Vec<ConditionalTypeRefinementFact> = Vec::new();
    for (index, fact) in model
        .extension_facts
        .iter()
        .enumerate()
        .filter(|(_, fact)| fact.vocabulary == CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID)
    {
        let path = format!("extensionFacts[{index}]");
        if fact.version != CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION
            || fact.family != CSMI_CONDITIONAL_TYPE_REFINEMENT_FAMILY
        {
            return Err(CsmiImportError::Unsupported {
                path,
                semantic: "unsupported conditional refinement version or family".to_owned(),
            });
        }
        let mut payload: CsmiConditionalTypeRefinement =
            serde_json::from_value(fact.payload.clone()).map_err(|cause| {
                CsmiImportError::Unsupported {
                    path: path.clone(),
                    semantic: cause.to_string(),
                }
            })?;
        payload.remap_symbols(|symbol| member_ids.get(symbol).or_else(|| type_ids.get(symbol)).cloned()
            .ok_or_else(|| CsmiImportError::Unsupported { path: path.clone(), semantic: format!("conditional refinement identity {symbol:?} has no exact native declaration mapping") }))?;
        let coverage = model
            .completeness_statements
            .iter()
            .find(|statement| {
                statement.vocabulary.as_deref() == Some(CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID)
                    && statement.version.as_deref()
                        == Some(CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION)
                    && statement.family == CSMI_CONDITIONAL_TYPE_REFINEMENT_FAMILY
                    && statement.scope == fact.scope
            })
            .map(|statement| statement.status);
        let provenance = runtime_provenance(fact, default_provenance);
        if let Some(existing) = refinements
            .iter_mut()
            .find(|candidate| candidate.payload == payload && candidate.coverage == coverage)
        {
            existing.provenance.extend(provenance);
            existing.provenance.sort_unstable();
            existing.provenance.dedup();
        } else {
            refinements.push(ConditionalTypeRefinementFact {
                payload,
                coverage,
                provenance,
            });
        }
    }
    Ok((!refinements.is_empty()).then_some(ConditionalTypeRefinementsPayload { refinements }))
}

fn import_deferred_yields(
    model: &CsmiSemanticModel,
    default_provenance: Option<&str>,
    type_ids: &HashMap<String, String>,
    member_ids: &HashMap<String, String>,
) -> Result<Option<DeferredYieldsPayload>, CsmiImportError> {
    let mut yields: Vec<DeferredYieldFact> = Vec::new();
    for (fact_index, fact) in model.extension_facts.iter().enumerate() {
        if fact.vocabulary != CSMI_DEFERRED_YIELD_PROFILE_ID
            || fact.version != CSMI_DEFERRED_YIELD_PROFILE_VERSION
        {
            continue;
        }
        if fact.family != "deferred-yields" {
            return Err(CsmiImportError::Unsupported {
                path: "extensionFacts.family".to_owned(),
                semantic: "deferred-yield facts must use family deferred-yields".to_owned(),
            });
        }
        let object = fact.scope.as_object().ok_or_else(|| {
            CsmiImportError::Identity("deferred-yield fact scope must be an object".to_owned())
        })?;
        let factory = object
            .get("factory")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CsmiImportError::Identity("deferred-yield scope has no factory".to_owned())
            })?;
        let resume = object
            .get("resume")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CsmiImportError::Identity("deferred-yield scope has no resume".to_owned())
            })?;
        let handle_type = object
            .get("handleType")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CsmiImportError::Identity("deferred-yield scope has no handleType".to_owned())
            })?;
        let mut payload: CsmiDeferredYieldPayload = serde_json::from_value(fact.payload.clone())
            .map_err(|error| CsmiImportError::Unsupported {
                path: "extensionFacts.payload".to_owned(),
                semantic: error.to_string(),
            })?;
        if payload.factory != factory
            || payload.resume != resume
            || payload.handle_type != handle_type
        {
            return Err(CsmiImportError::Identity(
                "deferred-yield payload linked scope does not match fact scope".to_owned(),
            ));
        }
        let factory = import_deferred_member_id(
            factory,
            member_ids,
            &format!("extensionFacts[{fact_index}].scope.factory"),
        )?;
        let resume = import_deferred_member_id(
            resume,
            member_ids,
            &format!("extensionFacts[{fact_index}].scope.resume"),
        )?;
        let handle_type = import_deferred_type_id(
            handle_type,
            type_ids,
            &format!("extensionFacts[{fact_index}].scope.handleType"),
        )?;
        import_deferred_yield_payload(
            &mut payload,
            type_ids,
            member_ids,
            &format!("extensionFacts[{fact_index}].payload"),
        )?;
        let coverage = model
            .completeness_statements
            .iter()
            .find(|statement| {
                statement.vocabulary.as_deref() == Some(CSMI_DEFERRED_YIELD_PROFILE_ID)
                    && statement.version.as_deref() == Some(CSMI_DEFERRED_YIELD_PROFILE_VERSION)
                    && statement.family == "deferred-yields"
                    && statement.scope == fact.scope
            })
            .map(|statement| match statement.status {
                CsmiCoverageStatus::Complete => Completeness::Complete,
                CsmiCoverageStatus::Unknown | CsmiCoverageStatus::Partial => Completeness::Partial,
            });
        let imported = DeferredYieldFact {
            factory,
            resume,
            handle_type,
            payload,
            coverage,
            provenance: if fact.provenance.is_empty() {
                default_provenance.map(str::to_owned).into_iter().collect()
            } else {
                fact.provenance.clone()
            },
        };
        if let Some(existing) = yields.iter_mut().find(|candidate| {
            candidate.factory == imported.factory
                && candidate.resume == imported.resume
                && candidate.handle_type == imported.handle_type
                && candidate.payload == imported.payload
                && candidate.coverage == imported.coverage
        }) {
            existing.provenance.extend(imported.provenance);
            existing.provenance.sort_unstable();
            existing.provenance.dedup();
        } else {
            yields.push(imported);
        }
    }
    yields.sort_by_cached_key(|fact| {
        (
            fact.factory.clone(),
            fact.resume.clone(),
            fact.handle_type.clone(),
            serde_json::to_string(&fact.payload).expect("typed deferred-yield payload serializes"),
            fact.coverage,
        )
    });
    Ok((!yields.is_empty()).then_some(DeferredYieldsPayload { yields }))
}

fn import_deferred_member_id(
    id: &str,
    member_ids: &HashMap<String, String>,
    path: &str,
) -> Result<String, CsmiImportError> {
    member_ids.get(id).cloned().ok_or_else(|| {
        CsmiImportError::Identity(format!(
            "unresolved deferred-yield callable symbol {id} at {path}"
        ))
    })
}

fn import_deferred_type_id(
    id: &str,
    type_ids: &HashMap<String, String>,
    path: &str,
) -> Result<String, CsmiImportError> {
    type_ids.get(id).cloned().ok_or_else(|| {
        CsmiImportError::Identity(format!(
            "unresolved deferred-yield type symbol {id} at {path}"
        ))
    })
}

fn import_deferred_yield_payload(
    payload: &mut CsmiDeferredYieldPayload,
    type_ids: &HashMap<String, String>,
    member_ids: &HashMap<String, String>,
    path: &str,
) -> Result<(), CsmiImportError> {
    payload.factory =
        import_deferred_member_id(&payload.factory, member_ids, &format!("{path}.factory"))?;
    payload.resume =
        import_deferred_member_id(&payload.resume, member_ids, &format!("{path}.resume"))?;
    payload.handle_type = import_deferred_type_id(
        &payload.handle_type,
        type_ids,
        &format!("{path}.handleType"),
    )?;
    if let Some(CsmiDeferredYieldSubstitution::ReceiverArguments { declaration }) =
        &mut payload.receiver_substitution
    {
        *declaration = import_deferred_type_id(
            declaration,
            type_ids,
            &format!("{path}.receiverSubstitution.declaration"),
        )?;
    }
    for (position, root) in payload.roots.iter_mut().enumerate() {
        let root_path = format!("{path}.roots[{position}]");
        root.callable = import_deferred_member_id(
            &root.callable,
            member_ids,
            &format!("{root_path}.callable"),
        )?;
        import_deferred_yield_shape(&mut root.shape, type_ids, &format!("{root_path}.shape"))?;
    }
    import_deferred_yield_location(
        &mut payload.construction.source,
        member_ids,
        &format!("{path}.construction.source"),
    )?;
    import_deferred_yield_location(
        &mut payload.construction.handle,
        member_ids,
        &format!("{path}.construction.handle"),
    )?;
    import_deferred_yield_location(
        &mut payload.resume_contract.handle_input,
        member_ids,
        &format!("{path}.resumeContract.handleInput"),
    )?;
    import_deferred_yield_location(
        &mut payload.resume_contract.yielded_result,
        member_ids,
        &format!("{path}.resumeContract.yieldedResult"),
    )?;
    import_deferred_yield_location(
        &mut payload.resume_contract.factory_result_flow.factory_result,
        member_ids,
        &format!("{path}.resumeContract.factoryResultFlow.factoryResult"),
    )?;
    import_deferred_yield_location(
        &mut payload.resume_contract.factory_result_flow.resume_input,
        member_ids,
        &format!("{path}.resumeContract.factoryResultFlow.resumeInput"),
    )?;
    for (position, member) in payload.yield_contract.members.iter_mut().enumerate() {
        import_deferred_yield_location(
            &mut member.source,
            member_ids,
            &format!("{path}.yield.members[{position}].source"),
        )?;
    }
    Ok(())
}

fn import_deferred_yield_location(
    location: &mut CsmiDeferredYieldLocation,
    member_ids: &HashMap<String, String>,
    path: &str,
) -> Result<(), CsmiImportError> {
    location.callable =
        import_deferred_member_id(&location.callable, member_ids, &format!("{path}.callable"))?;
    Ok(())
}

fn import_deferred_yield_shape(
    shape: &mut CsmiDeferredYieldShape,
    type_ids: &HashMap<String, String>,
    path: &str,
) -> Result<(), CsmiImportError> {
    let mut stack = vec![(shape, path.to_owned())];
    while let Some((shape, path)) = stack.pop() {
        match shape {
            CsmiDeferredYieldShape::Value { r#type } => {
                import_deferred_yield_type_expression(r#type, type_ids, &format!("{path}.type"))?;
            }
            CsmiDeferredYieldShape::Product { components } => {
                for (position, component) in components.iter_mut().enumerate().rev() {
                    stack.push((component, format!("{path}.components[{position}]")));
                }
            }
            CsmiDeferredYieldShape::Keyed { key, value, .. } => {
                stack.push((value, format!("{path}.value")));
                stack.push((key, format!("{path}.key")));
            }
            CsmiDeferredYieldShape::Unknown { .. } => {}
        }
    }
    Ok(())
}

fn import_deferred_yield_type_expression(
    expression: &mut CsmiDeferredYieldTypeExpression,
    type_ids: &HashMap<String, String>,
    path: &str,
) -> Result<(), CsmiImportError> {
    let mut stack = vec![(expression, path.to_owned())];
    while let Some((expression, path)) = stack.pop() {
        if let CsmiTypeExpression::Parameter(parameter) = expression {
            return Err(CsmiImportError::Unsupported {
                path: format!("{path}.symbol"),
                semantic: format!(
                    "deferred type parameter {} requires an exact native generic binder mapping",
                    parameter.symbol
                ),
            });
        }
        if let CsmiTypeExpression::Reference(reference) = expression {
            reference.symbol =
                import_deferred_type_id(&reference.symbol, type_ids, &format!("{path}.symbol"))?;
            for (position, argument) in reference.arguments.iter_mut().enumerate().rev() {
                stack.push((argument, format!("{path}.arguments[{position}]")));
            }
        }
    }
    Ok(())
}

fn runtime_provenance(fact: &CsmiExtensionFact, default_provenance: Option<&str>) -> Vec<String> {
    if fact.provenance.is_empty() {
        default_provenance.map(str::to_owned).into_iter().collect()
    } else {
        fact.provenance.clone()
    }
}

fn runtime_pack_identity(
    payload: &RuntimeValuesPayload,
    requested_language: Option<&str>,
) -> Result<(String, String), CsmiImportError> {
    let mut languages = BTreeSet::new();
    for exposure in &payload.exposures {
        for language in &exposure.languages {
            let normalized = crate::analyzer::LanguageDialect::from_config_label(language)
                .map(|dialect| dialect.semantic_pack_label().to_owned())
                .ok_or_else(|| CsmiImportError::Unsupported {
                    path: "runtime-global-exposure.languages".to_owned(),
                    semantic: format!("unsupported Bifrost runtime language {language:?}"),
                })?;
            languages.insert(normalized);
        }
    }
    let language = match requested_language {
        Some(requested) => crate::analyzer::LanguageDialect::from_config_label(requested)
            .map(|dialect| dialect.semantic_pack_label().to_owned())
            .ok_or_else(|| CsmiImportError::Unsupported {
                path: "import.target_language".to_owned(),
                semantic: format!("unsupported Bifrost import language {requested:?}"),
            })
            .and_then(|normalized| {
                if languages.contains(&normalized) {
                    Ok(normalized)
                } else {
                    Err(CsmiImportError::Unsupported {
                        path: "import.target_language".to_owned(),
                        semantic: format!(
                            "runtime exposure does not apply to requested language {requested:?}"
                        ),
                    })
                }
            })?,
        None if languages.len() == 1 => languages
            .into_iter()
            .next()
            .expect("one runtime language exists"),
        None => {
            return Err(CsmiImportError::Unsupported {
                path: "runtime-global-exposure.languages".to_owned(),
                semantic: "a multi-language runtime document requires an explicit import target"
                    .to_owned(),
            });
        }
    };
    if payload
        .exposures
        .iter()
        .any(|exposure| exposure.runtime.runtime_family != "node")
    {
        return Err(CsmiImportError::Unsupported {
            path: "runtime-global-exposure.runtime.runtimeFamily".to_owned(),
            semantic: "runtime import currently has an explicit Node/npm activation mapping"
                .to_owned(),
        });
    }
    Ok((language, "npm".to_owned()))
}

fn runtime_contract_pack_identity(
    payload: &crate::analyzer::semantic_model::runtime_contracts::RuntimeContractsPayloadV2,
    requested_language: Option<&str>,
) -> Result<(String, String), CsmiImportError> {
    let mut languages = BTreeSet::new();
    for contract in &payload.contracts {
        for language in &contract.definition.languages {
            let normalized = crate::analyzer::LanguageDialect::from_config_label(language)
                .map(|dialect| dialect.semantic_pack_label().to_owned())
                .ok_or_else(|| CsmiImportError::Unsupported {
                    path: "runtime-contracts.contract.definition.languages".to_owned(),
                    semantic: format!("unsupported Bifrost runtime language {language:?}"),
                })?;
            languages.insert(normalized);
        }
    }
    // A binding is the most precise language claim when a producer emits a
    // contract whose language set describes several source dialects.
    for binding in &payload.bindings {
        let normalized = crate::analyzer::LanguageDialect::from_config_label(&binding.language)
            .map(|dialect| dialect.semantic_pack_label().to_owned())
            .ok_or_else(|| CsmiImportError::Unsupported {
                path: "runtime-bindings.language".to_owned(),
                semantic: format!(
                    "unsupported Bifrost runtime language {:?}",
                    binding.language
                ),
            })?;
        languages.insert(normalized);
    }
    let language = match requested_language {
        Some(requested) => crate::analyzer::LanguageDialect::from_config_label(requested)
            .map(|dialect| dialect.semantic_pack_label().to_owned())
            .ok_or_else(|| CsmiImportError::Unsupported {
                path: "import.target_language".to_owned(),
                semantic: format!("unsupported Bifrost import language {requested:?}"),
            })
            .and_then(|normalized| {
                if languages.contains(&normalized) {
                    Ok(normalized)
                } else {
                    Err(CsmiImportError::Unsupported {
                        path: "import.target_language".to_owned(),
                        semantic: format!(
                            "runtime contract does not apply to requested language {requested:?}"
                        ),
                    })
                }
            })?,
        None if languages.len() == 1 => languages
            .into_iter()
            .next()
            .expect("one runtime contract language exists"),
        None => {
            return Err(CsmiImportError::Unsupported {
                path: "runtime-contracts.contract.definition.languages".to_owned(),
                semantic: "a multi-language runtime document requires an explicit import target"
                    .to_owned(),
            });
        }
    };
    // The current runtime-contract profile's supported target is Node. Keep
    // this mapping explicit until another ecosystem has a reviewed native
    // activation contract; accepting an unknown ecosystem would make a
    // portable selector appear applicable to unrelated package managers.
    if payload.contracts.iter().any(|contract| {
        contract
            .definition
            .applicability
            .selectors
            .iter()
            .all(|selector| !selector.purl.contains("nodejs.org/node"))
    }) {
        return Err(CsmiImportError::Unsupported {
            path: "runtime-contracts.contract.definition.applicability.selectors".to_owned(),
            semantic:
                "runtime contract import currently has an explicit Node/npm activation mapping"
                    .to_owned(),
        });
    }
    Ok((language, "npm".to_owned()))
}

fn runtime_profile_digests(model: &CsmiSemanticModel) -> Result<Vec<String>, CsmiImportError> {
    let mut digests = model
        .extension_facts
        .iter()
        .filter(|fact| {
            fact.vocabulary == CSMI_RUNTIME_VALUES_PROFILE_ID
                && fact.version == CSMI_RUNTIME_VALUES_PROFILE_VERSION
                && fact.family == "runtime-global-exposures"
        })
        .map(|fact| {
            let payload: CsmiRuntimeValuesPayload = serde_json::from_value(fact.payload.clone())
                .map_err(|error| CsmiImportError::Identity(error.to_string()))?;
            let CsmiRuntimeValuesPayload::RuntimeGlobalExposure(exposure) = payload else {
                return Err(CsmiImportError::Identity(
                    "runtime exposure family payload has the wrong kind".to_owned(),
                ));
            };
            Ok(exposure.runtime_profile_digest)
        })
        .collect::<Result<Vec<_>, CsmiImportError>>()?;
    digests.sort_unstable();
    digests.dedup();
    Ok(digests)
}

fn runtime_extensions(extensions: &[CsmiExtensionAttachment]) -> Vec<RuntimeValueExtension> {
    extensions
        .iter()
        .map(|extension| RuntimeValueExtension {
            vocabulary: extension.vocabulary.clone(),
            version: extension.version.clone(),
            payload: extension.payload.clone(),
        })
        .collect()
}

fn native_runtime_record<T, W>(record: W) -> Result<T, CsmiImportError>
where
    T: serde::de::DeserializeOwned,
    W: serde::Serialize,
{
    let value = serde_json::to_value(record)
        .map_err(|error| CsmiImportError::Identity(error.to_string()))?;
    serde_json::from_value(value).map_err(|error| CsmiImportError::Identity(error.to_string()))
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
    runtime_profile_digests: &[String],
    runtime_contracts: bool,
) -> Result<ActivationSelector, CsmiImportError> {
    if runtime_contracts {
        // Preserve the outer selector's exact PURL/VERS applicability in the
        // retained envelope. Native catalog selectors cannot represent VERS;
        // an artifact digest is optional for portable runtime contracts.
        return Ok(ActivationSelector {
            package: Some(NameSelector {
                name: selector.purl.clone(),
                version: None,
            }),
            module: None,
            toolchain: None,
            targets: Vec::new(),
            configurations: runtime_profile_digests.to_vec(),
            // A portable contract's selector can be a PURL/VERS range. An
            // arbitrary digest in that outer selector is not a native exact
            // artifact claim; retain and enforce it from the CSMI envelope.
            artifact_sha256: None,
        });
    }
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
            configurations: runtime_profile_digests.to_vec(),
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
        configurations: runtime_profile_digests.to_vec(),
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
    references: &HashMap<String, TypeRef>,
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
                    references,
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
                references,
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
    references: &HashMap<String, TypeRef>,
    path: &str,
) -> Result<TypeRef, CsmiImportError> {
    match value {
        CsmiTypeExpression::Reference(reference) => {
            let mut resolved = references.get(&reference.symbol).cloned().ok_or_else(|| {
                CsmiImportError::Identity(format!(
                    "unresolved type symbol {} at {path}",
                    reference.symbol
                ))
            })?;
            let arguments = reference
                .arguments
                .iter()
                .enumerate()
                .map(|(position, argument)| {
                    type_ref(
                        argument,
                        references,
                        &format!("{path}.arguments[{position}]"),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            match &mut resolved {
                TypeRef::Named {
                    arguments: target, ..
                }
                | TypeRef::Declared {
                    arguments: target, ..
                } => *target = arguments,
                _ => unreachable!("reference map contains only named or declared types"),
            }
            Ok(resolved)
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
    let mut transfer_partitions = Vec::new();
    let mut locations = Vec::new();
    for statement in model.completeness_statements.iter().filter(|statement| {
        statement.vocabulary.as_deref() == Some(CSMI_TRANSFER_PARTITIONS_PROFILE_ID)
    }) {
        let scope: CsmiTransferPartitionScope = serde_json::from_value(statement.scope.clone())
            .map_err(|error| CsmiImportError::Unsupported {
                path: "completenessStatements.scope".to_owned(),
                semantic: error.to_string(),
            })?;
        if scope.callable != summary.callable {
            continue;
        }
        let source = match scope.source {
            CsmiTransferPartitionSource::AllInputs => TransferPartitionSource::AllInputs,
            CsmiTransferPartitionSource::InputRoot {
                root: CsmiInputBoundaryRoot::Receiver(_),
            } => TransferPartitionSource::InputReceiver,
            CsmiTransferPartitionSource::InputRoot {
                root: CsmiInputBoundaryRoot::Parameter(root),
            } => TransferPartitionSource::InputParameter {
                ordinal: root.position,
            },
            CsmiTransferPartitionSource::InputRoot {
                root: CsmiInputBoundaryRoot::Capture(root),
            } => {
                if !locations
                    .iter()
                    .any(|location: &AuthoredSummaryLocation| location.id == root.symbol)
                {
                    locations.push(AuthoredSummaryLocation {
                        id: root.symbol.clone(),
                        location_kind: AuthoredSummaryLocationKind::Capture,
                    });
                }
                TransferPartitionSource::InputCapture {
                    symbol: root.symbol,
                }
            }
        };
        transfer_partitions.push(NormalResultTransferPartition {
            source,
            normal_result: scope.destination.position,
            status: match statement.status {
                CsmiCoverageStatus::Unknown => TransferPartitionStatus::Unknown,
                CsmiCoverageStatus::Partial => TransferPartitionStatus::Partial,
                CsmiCoverageStatus::Complete => TransferPartitionStatus::Complete,
            },
            limitations: statement
                .limitations
                .iter()
                .map(|limitation| TransferPartitionLimitation {
                    kind: limitation.kind.clone(),
                    diagnostic_code: limitation
                        .diagnostic
                        .as_ref()
                        .and_then(|diagnostic| diagnostic.code.clone()),
                    diagnostic_message: limitation
                        .diagnostic
                        .as_ref()
                        .and_then(|diagnostic| diagnostic.message.clone()),
                })
                .collect(),
            provenance: statement.provenance.clone(),
        });
    }
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
        ordinary_heap_unchanged: false,
        covers_overrides: false,
        normal_continuation_absent: false,
        normal_result_count: (!shape.results.is_empty()).then_some(shape.results.len() as u32),
        locations,
        transfers,
        transfer_partitions,
        effects: Vec::new(),
        concurrency_effects: Vec::new(),
        declared_effects: Vec::new(),
        preconditions: None,
        result_contracts: Vec::new(),
        result_use_obligations: Vec::new(),
        conditional_result_refinements: Vec::new(),
        conditional_indirect_writes: Vec::new(),
        normal_return_refinements: Vec::new(),
        normal_return_type_refinements: Vec::new(),
        class_decorator_identity: None,
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
