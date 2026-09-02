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
    Locator, MemberFact, MemberKind, NameSelector, Parameter, ParameterPassingMode, Producer,
    Provenance, ReceiverFact, Safety, Signature, TypeFact, TypeKind, TypeRef, Visibility,
    compile_pack,
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
            Self::Identity(message) => write!(formatter, "JVM identity mapping failed: {message}"),
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
    let selectors = model
        .artifact_selectors
        .iter()
        .map(selector_from_csmi)
        .collect::<Result<Vec<_>, _>>()?;
    let mut symbols = HashMap::new();
    let mut types = Vec::new();
    let mut type_ids = HashMap::new();
    for symbol in &model.symbols {
        if symbol.scheme != JVM_IDENTITY_SCHEME || symbol.scheme_version != JVM_IDENTITY_VERSION {
            return Err(CsmiImportError::Unsupported {
                path: "symbols".to_owned(),
                semantic: format!(
                    "identity scheme {} {}",
                    symbol.scheme, symbol.scheme_version
                ),
            });
        }
        if let Some(name) = type_name(symbol) {
            type_ids.insert(
                symbol.id.clone(),
                type_symbol_id(&name)
                    .map_err(|error| CsmiImportError::Identity(error.to_string()))?,
            );
            symbols.insert(symbol.id.clone(), name);
        }
    }
    for declaration in &model.declarations {
        if declaration.category != CsmiDeclarationCategory::Type {
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
            type_kind: TypeKind::Class,
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
        let member_id = format!(
            "member.{}",
            sha256_hex(format!("{owner_name}\0{member_name}\0{}", declaration.symbol).as_bytes())
        );
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
    let summaries = model
        .procedure_summaries
        .iter()
        .map(|summary| summary_from_csmi(summary, model, &symbols))
        .collect::<Result<Vec<_>, _>>()?;
    let completeness = model
        .completeness_statements
        .iter()
        .find(|statement| {
            statement.family == "declaration-records"
                && statement.vocabulary.is_none()
                && statement.version.is_none()
                && statement.scope.get("scheme").and_then(Value::as_str)
                    == Some(JVM_IDENTITY_SCHEME)
                && statement.scope.get("schemeVersion").and_then(Value::as_str)
                    == Some(JVM_IDENTITY_VERSION)
        })
        .map_or(Completeness::Partial, |statement| match statement.status {
            CsmiCoverageStatus::Complete => Completeness::Complete,
            CsmiCoverageStatus::Unknown | CsmiCoverageStatus::Partial => Completeness::Partial,
        });
    let producer = document
        .provenance_records
        .first()
        .map(|record| Producer {
            name: record.producer.identifier.clone(),
            version: record.producer.version.clone(),
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
            revision: record.invocation_id.clone(),
        })
        .unwrap_or_else(|| Provenance {
            source: "csmi".to_owned(),
            revision: None,
        });
    let language = "java".to_owned();
    let ecosystem = "maven".to_owned();
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

fn selector_from_csmi(
    selector: &CsmiArtifactSelector,
) -> Result<ActivationSelector, CsmiImportError> {
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
        has_receiver: shape.receiver.is_some(),
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
        .map(transfer_from_csmi)
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
        id: format!("csmi-summary.{}", summary.callable),
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

fn transfer_from_csmi(transfer: &CsmiTransfer) -> Result<AuthoredSummaryTransfer, CsmiImportError> {
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
    })
}
