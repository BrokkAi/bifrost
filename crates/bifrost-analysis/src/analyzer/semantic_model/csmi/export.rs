//! Translation from Bifrost semantic-model packs to CSMI v0.1 documents.

use super::canonical::{canonical_json, sha256_hex};
use super::identity::{
    callable_disambiguator, member_symbol_id, type_expression, type_symbol, type_symbol_id,
};
use super::model::*;
use super::pack::{CsmiLogicalPack, InMemoryCsmiResourceResolver};
use super::validate::{CsmiVocabularySupport, validate_csmi_pack};
use crate::analyzer::semantic_model::{
    AuthoredSemanticModelPack, CompiledPayload, CompiledSemanticModelPack, CompiledShard,
    CompiledSummaryExitKind, CompiledSummaryInput, CompiledSummaryOutput, CompilerOptions,
    Completeness, DecodeLimits, MemberFact, MemberKind, TypeRef, compile_pack, decode_shard,
};
use serde_json::json;
use std::collections::{HashMap, HashSet};

pub const DEFAULT_SEMANTIC_RESOURCE_PATH: &str = "semantic-document.json";
pub const DEFAULT_ASSEMBLER_IDENTIFIER: &str = "https://bifrost.brokk.ai/csmi-export";
pub const DEFAULT_ASSEMBLER_VERSION: &str = "0.1.0";
pub const DEFAULT_PROVENANCE_ID: &str = "bifrost-export";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsmiArtifactEvidence {
    pub purl: String,
    pub sha256: String,
    pub coverage: String,
}

impl CsmiArtifactEvidence {
    pub fn new(purl: impl Into<String>, sha256: impl Into<String>) -> Self {
        Self {
            purl: purl.into(),
            sha256: sha256.into(),
            coverage: "artifact".to_owned(),
        }
    }

    pub fn with_coverage(mut self, coverage: impl Into<String>) -> Self {
        self.coverage = coverage.into();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsmiExportOptions {
    pub resource_path: String,
    pub assembler: CsmiProducerIdentity,
    pub provenance_id: String,
    pub created_at: Option<String>,
}

impl Default for CsmiExportOptions {
    fn default() -> Self {
        Self {
            resource_path: DEFAULT_SEMANTIC_RESOURCE_PATH.to_owned(),
            assembler: CsmiProducerIdentity {
                identifier: DEFAULT_ASSEMBLER_IDENTIFIER.to_owned(),
                version: DEFAULT_ASSEMBLER_VERSION.to_owned(),
            },
            provenance_id: DEFAULT_PROVENANCE_ID.to_owned(),
            created_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsmiExportError {
    InvalidEvidence(String),
    Unsupported { path: String, semantic: String },
    MissingDeclaration { path: String, target: String },
    Identity(String),
    Canonical(String),
}

impl std::fmt::Display for CsmiExportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEvidence(message) => {
                write!(formatter, "invalid artifact evidence: {message}")
            }
            Self::Unsupported { path, semantic } => {
                write!(formatter, "unsupported CSMI semantic at {path}: {semantic}")
            }
            Self::MissingDeclaration { path, target } => write!(
                formatter,
                "missing callable declaration at {path}: {target}"
            ),
            Self::Identity(message) => write!(formatter, "JVM identity mapping failed: {message}"),
            Self::Canonical(message) => {
                write!(formatter, "CSMI canonicalization failed: {message}")
            }
        }
    }
}

impl std::error::Error for CsmiExportError {}

/// Compatibility alias for callers that treat export diagnostics as a report.
pub type CsmiExportReport = CsmiExportError;

pub fn export_csmi_pack(
    pack: &CompiledSemanticModelPack,
    artifact: &CsmiArtifactEvidence,
    options: &CsmiExportOptions,
) -> Result<CsmiLogicalPack, CsmiExportReport> {
    let decoded = pack
        .shards
        .iter()
        .map(|shard| decode_shard(&shard.descriptor, &shard.bytes, &DecodeLimits::default()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
    let (semantic, provenance) = export_semantic_document(
        &pack.manifest.producer,
        &pack.manifest.provenance,
        &pack.manifest.license,
        pack.manifest.completeness,
        decoded.iter(),
        artifact,
        options,
    )?;
    logical_pack(semantic, provenance, &pack.manifest.license, options)
}

pub fn export_authored_csmi_pack(
    pack: &AuthoredSemanticModelPack,
    artifact: &CsmiArtifactEvidence,
    options: &CsmiExportOptions,
) -> Result<CsmiLogicalPack, CsmiExportReport> {
    let compiled = compile_pack(pack, &CompilerOptions::default()).map_err(|diagnostics| {
        CsmiExportError::Canonical(format!("Bifrost pack did not compile: {diagnostics:?}"))
    })?;
    export_csmi_pack(&compiled, artifact, options)
}

fn export_semantic_document<'a>(
    producer: &crate::analyzer::semantic_model::Producer,
    pack_provenance: &crate::analyzer::semantic_model::Provenance,
    _license: &str,
    pack_completeness: Completeness,
    shards: impl Iterator<Item = &'a CompiledShard>,
    artifact: &CsmiArtifactEvidence,
    options: &CsmiExportOptions,
) -> Result<(CsmiSemanticDocument, CsmiProvenanceRecord), CsmiExportError> {
    validate_maven_evidence(artifact)?;
    let mut types = Vec::new();
    let mut members = Vec::new();
    let mut relations = Vec::new();
    let mut summaries = Vec::new();
    let mut type_names_by_id = HashMap::new();
    let mut member_facts = Vec::new();
    let mut summary_shards = Vec::new();
    for shard in shards {
        match shard.payload() {
            CompiledPayload::DeclarationFacts {
                types: shard_types,
                members: shard_members,
                relations: shard_relations,
            } => {
                type_names_by_id.extend(
                    shard_types
                        .iter()
                        .map(|fact| (fact.id.clone(), fact.name.clone())),
                );
                types.extend(shard_types.iter());
                member_facts.extend(shard_members.iter());
                members.extend(shard_members.iter());
                relations.extend(shard_relations.iter());
            }
            CompiledPayload::ProcedureSummaries {
                summaries: shard_summaries,
            } => {
                summary_shards.extend(shard_summaries.iter());
            }
            CompiledPayload::GeneratorRules { .. } => {
                return Err(CsmiExportError::Unsupported {
                    path: "shards.payload".to_owned(),
                    semantic: "generator rules are not representable in CSMI core".to_owned(),
                });
            }
        }
    }
    let mut symbol_by_bifrost_id = HashMap::new();
    let mut symbols = Vec::new();
    let mut declarations = Vec::new();
    let mut seen_symbols = HashSet::new();
    fn ensure_type(
        name: &str,
        symbols: &mut Vec<CsmiSymbolDefinition>,
        seen_symbols: &mut HashSet<String>,
    ) -> Result<String, CsmiExportError> {
        let id =
            type_symbol_id(name).map_err(|error| CsmiExportError::Identity(error.to_string()))?;
        if seen_symbols.insert(id.clone()) {
            symbols.push(
                type_symbol(name).map_err(|error| CsmiExportError::Identity(error.to_string()))?,
            );
        }
        Ok(id)
    }
    for fact in &types {
        if fact.value_semantics.is_some() {
            return Err(CsmiExportError::Unsupported {
                path: format!("types.{}.valueSemantics", fact.id),
                semantic: "type-wide value semantics are not representable in CSMI 0.1".to_owned(),
            });
        }
        let id = ensure_type(&fact.name, &mut symbols, &mut seen_symbols)?;
        symbol_by_bifrost_id.insert(fact.id.clone(), id.clone());
        declarations.push(CsmiDeclaration {
            symbol: id,
            category: CsmiDeclarationCategory::Type,
            owner: None,
            generic_parameters: Vec::new(),
            callable: None,
            alias_target: None,
            provenance: vec![options.provenance_id.clone()],
            extensions: Vec::new(),
        });
    }
    for fact in &member_facts {
        if fact.implicit_operation.is_some() {
            return Err(CsmiExportError::Unsupported {
                path: format!("members.{}.implicitOperation", fact.id),
                semantic: "implicit value operations are not representable in CSMI 0.1".to_owned(),
            });
        }
        let owner_name = type_names_by_id.get(&fact.owner).cloned().ok_or_else(|| {
            CsmiExportError::MissingDeclaration {
                path: format!("members.{}", fact.id),
                target: fact.owner.clone(),
            }
        })?;
        let owner_id = ensure_type(&owner_name, &mut symbols, &mut seen_symbols)?;
        let id = member_symbol_id(&owner_name, fact, &type_names_by_id)
            .map_err(|error| CsmiExportError::Identity(error.to_string()))?;
        symbol_by_bifrost_id.insert(fact.id.clone(), id.clone());
        if seen_symbols.insert(id.clone()) {
            let mut symbol = type_symbol(&owner_name)
                .map_err(|error| CsmiExportError::Identity(error.to_string()))?;
            symbol.id = id.clone();
            symbol.descriptors.push(CsmiDescriptor {
                role: CsmiDescriptorRole::Callable,
                name: Some(fact.name.clone()),
                disambiguator: Some(
                    callable_disambiguator(fact, &type_names_by_id)
                        .map_err(|error| CsmiExportError::Identity(error.to_string()))?,
                ),
            });
            symbols.push(symbol);
        }
        declarations.push(CsmiDeclaration {
            symbol: id,
            category: CsmiDeclarationCategory::Callable,
            owner: Some(owner_id.clone()),
            generic_parameters: Vec::new(),
            callable: Some(callable_shape(fact, &type_names_by_id)?),
            alias_target: None,
            provenance: vec![options.provenance_id.clone()],
            extensions: Vec::new(),
        });
    }
    if let Some(relation) = relations.first() {
        return Err(CsmiExportError::Unsupported {
            path: format!("relations.{}", relation.id),
            semantic: "Bifrost navigation/reference relations have no CSMI core relationship"
                .to_owned(),
        });
    }
    let member_by_target: HashMap<(String, String, u32), String> = member_facts
        .iter()
        .filter_map(|fact| {
            let arity = fact.signature.as_ref()?.parameters.len() as u32;
            let id = symbol_by_bifrost_id.get(&fact.id).cloned().or_else(|| {
                let owner_name = type_names_by_id.get(&fact.owner)?;
                member_symbol_id(owner_name, fact, &type_names_by_id).ok()
            })?;
            let owner_name = type_names_by_id.get(&fact.owner)?.clone();
            Some(((owner_name, fact.name.clone(), arity), id))
        })
        .collect();
    for summary in &summary_shards {
        let target = &summary.target;
        let callable = member_by_target
            .get(&(
                target.path.clone(),
                target.symbol.clone(),
                target.parameter_count,
            ))
            .cloned()
            .ok_or_else(|| CsmiExportError::MissingDeclaration {
                path: format!("procedureSummaries.{}", summary.id),
                target: format!("{}#{}", target.path, target.symbol),
            })?;
        if !summary.locations.is_empty() {
            return Err(CsmiExportError::Unsupported {
                path: format!("procedureSummaries.{}.locations", summary.id),
                semantic: "capture and heap locations are not representable in CSMI core"
                    .to_owned(),
            });
        }
        if !summary.effects.is_empty()
            || !summary.concurrency_effects.is_empty()
            || !summary.declared_effects.is_empty()
            || summary.preconditions.is_some()
            || !summary.result_contracts.is_empty()
            || !summary.conditional_result_refinements.is_empty()
            || !summary.conditional_indirect_writes.is_empty()
            || !summary.normal_return_refinements.is_empty()
        {
            return Err(CsmiExportError::Unsupported {
                path: format!("procedureSummaries.{}", summary.id),
                semantic: "effects and result contracts are not representable in CSMI core"
                    .to_owned(),
            });
        }
        let transfers = summary
            .transfers
            .iter()
            .map(transfer_to_csmi)
            .collect::<Result<Vec<_>, _>>()?;
        summaries.push(CsmiProcedureSummary {
            callable: callable.clone(),
            transfers,
            extensions: Vec::new(),
        });
    }
    let selector = CsmiArtifactSelector {
        purl: artifact.purl.clone(),
        version_range: None,
        digests: vec![CsmiArtifactDigest {
            algorithm: CsmiDigestAlgorithm::Sha256,
            coverage: artifact.coverage.clone(),
            canonicalization: None,
            value: artifact.sha256.clone(),
        }],
    };
    let mut completeness_statements = Vec::new();
    let summary_ids: HashSet<String> = summaries
        .iter()
        .map(|summary| summary.callable.clone())
        .collect();
    for callable in summary_ids {
        let status = if summary_shards.iter().any(|summary| {
            let target = &summary.target;
            member_by_target
                .get(&(
                    target.path.clone(),
                    target.symbol.clone(),
                    target.parameter_count,
                ))
                .is_some_and(|id| id == &callable)
                && summary.completeness == Completeness::Complete
        }) {
            CsmiCoverageStatus::Complete
        } else {
            CsmiCoverageStatus::Partial
        };
        completeness_statements.push(CsmiCompletenessStatement {
            vocabulary: None,
            version: None,
            family: "procedure-summaries".to_owned(),
            scope: json!({ "callable": callable }),
            status,
            limitations: if status == CsmiCoverageStatus::Partial {
                vec![CsmiLimitation {
                    kind: "coverage-limited".to_owned(),
                    diagnostic: None,
                }]
            } else {
                Vec::new()
            },
            provenance: vec![options.provenance_id.clone()],
            extensions: Vec::new(),
        });
    }
    let declaration_status = match pack_completeness {
        Completeness::Complete => CsmiCoverageStatus::Complete,
        Completeness::Partial => CsmiCoverageStatus::Partial,
    };
    completeness_statements.push(CsmiCompletenessStatement {
        vocabulary: None,
        version: None,
        family: "declaration-records".to_owned(),
        scope: json!({
            "scheme": super::identity::JVM_IDENTITY_SCHEME,
            "schemeVersion": super::identity::JVM_IDENTITY_VERSION
        }),
        status: declaration_status,
        limitations: if declaration_status == CsmiCoverageStatus::Partial {
            vec![CsmiLimitation {
                kind: "coverage-limited".to_owned(),
                diagnostic: None,
            }]
        } else {
            Vec::new()
        },
        provenance: vec![options.provenance_id.clone()],
        extensions: Vec::new(),
    });
    let record = CsmiProvenanceRecord {
        id: options.provenance_id.clone(),
        producer: CsmiProducerIdentity {
            identifier: "https://bifrost.brokk.ai/semantic-pack-producer".to_owned(),
            version: producer.version.clone(),
        },
        generation_method: CsmiGenerationMethod::SourceAnalysis,
        inputs: vec![CsmiProvenanceInput {
            role: "target-artifact".to_owned(),
            identifier: None,
            purl: Some(artifact.purl.clone()),
            digest: Some(CsmiArtifactDigest {
                algorithm: CsmiDigestAlgorithm::Sha256,
                coverage: artifact.coverage.clone(),
                canonicalization: None,
                value: artifact.sha256.clone(),
            }),
            pack_digest: None,
            semantic_document_digest: None,
        }],
        created_at: options.created_at.clone(),
        invocation_id: pack_provenance.revision.clone(),
        diagnostic: None,
    };
    let document = CsmiSemanticDocument {
        document_type: "semantic-document".to_owned(),
        schema: CSMI_SCHEMA_URI.to_owned(),
        semantic_model_version: CSMI_SEMANTIC_MODEL_VERSION.to_owned(),
        serialization_version: CSMI_SERIALIZATION_VERSION.to_owned(),
        provenance_records: vec![record.clone()],
        default_provenance: Some(options.provenance_id.clone()),
        semantic_models: vec![CsmiSemanticModel {
            artifact_selectors: vec![selector],
            compatibility_constraints: Vec::new(),
            vocabulary_uses: Vec::new(),
            consumer_resolved_dependencies: Vec::new(),
            symbols,
            declarations,
            relationships: Vec::new(),
            procedure_summaries: summaries,
            extension_facts: Vec::new(),
            completeness_statements,
            extensions: Vec::new(),
        }],
    };
    Ok((document, record))
}

fn logical_pack(
    document: CsmiSemanticDocument,
    provenance: CsmiProvenanceRecord,
    license: &str,
    options: &CsmiExportOptions,
) -> Result<CsmiLogicalPack, CsmiExportError> {
    let semantic_bytes =
        canonical_json(&document).map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
    let digest = sha256_hex(&semantic_bytes);
    let resources = InMemoryCsmiResourceResolver::new([(
        options.resource_path.clone(),
        semantic_bytes.clone(),
    )])
    .map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
    let manifest = CsmiPackManifest {
        document_type: "pack-manifest".to_owned(),
        schema: CSMI_SCHEMA_URI.to_owned(),
        pack_format_version: CSMI_PACK_FORMAT_VERSION.to_owned(),
        assembler: options.assembler.clone(),
        license: license.to_owned(),
        created_at: options.created_at.clone(),
        resources: vec![CsmiResourceDescriptor {
            path: options.resource_path.clone(),
            role: CsmiResourceRole::SemanticDocument,
            media_type: CSMI_SEMANTIC_DOCUMENT_MEDIA_TYPE.to_owned(),
            size: semantic_bytes.len() as u64,
            digest: CsmiContentDigest {
                algorithm: CsmiContentDigestAlgorithm::Sha256,
                value: digest,
            },
            license: None,
            schema_identifier: None,
            license_reference: None,
        }],
        derived_from: Vec::new(),
    };
    let _ = provenance;
    let pack = CsmiLogicalPack::new(manifest, resources);
    let manifest_bytes = pack
        .canonical_manifest_bytes()
        .map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
    let validation = validate_csmi_pack(
        &manifest_bytes,
        &pack.resources,
        &CsmiVocabularySupport::empty(),
    );
    if !validation.usable() {
        return Err(CsmiExportError::Canonical(format!(
            "exported CSMI pack failed self-validation: {:?}",
            validation.diagnostics
        )));
    }
    Ok(pack)
}

fn validate_maven_evidence(artifact: &CsmiArtifactEvidence) -> Result<(), CsmiExportError> {
    let Some(raw) = artifact.purl.strip_prefix("pkg:maven/") else {
        return Err(CsmiExportError::InvalidEvidence(
            "exact Maven PURL with version is required".to_owned(),
        ));
    };
    if raw.contains(['?', '#']) {
        return Err(CsmiExportError::InvalidEvidence(
            "Maven qualifiers and subpaths are outside the supported exact selector subset"
                .to_owned(),
        ));
    }
    let Some((coordinate, version)) = raw.split_once('@') else {
        return Err(CsmiExportError::InvalidEvidence(
            "exact Maven PURL with version is required".to_owned(),
        ));
    };
    let Some((group, artifact_name)) = coordinate.rsplit_once('/') else {
        return Err(CsmiExportError::InvalidEvidence(
            "Maven PURL must include group and artifact".to_owned(),
        ));
    };
    if group.is_empty() || artifact_name.is_empty() || version.is_empty() || version.contains('@') {
        return Err(CsmiExportError::InvalidEvidence(
            "Maven group, artifact, and exact version must be non-empty".to_owned(),
        ));
    }
    if artifact.sha256.len() != 64
        || !artifact
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CsmiExportError::InvalidEvidence(
            "artifact SHA-256 must be lowercase hexadecimal".to_owned(),
        ));
    }
    if artifact.coverage.is_empty() {
        return Err(CsmiExportError::InvalidEvidence(
            "digest coverage is empty".to_owned(),
        ));
    }
    Ok(())
}

fn callable_shape(
    member: &MemberFact,
    type_names_by_id: &HashMap<String, String>,
) -> Result<CsmiCallableShape, CsmiExportError> {
    let signature = member
        .signature
        .as_ref()
        .ok_or_else(|| CsmiExportError::Unsupported {
            path: format!("members.{}", member.id),
            semantic: "callable declaration has no signature".to_owned(),
        })?;
    let receiver = if member.receiver.is_some() || member.extension_receiver.is_some() {
        let receiver_type = if let Some(extension) = &member.extension_receiver {
            extension
        } else {
            &TypeRef::Declared {
                id: member.owner.clone(),
                arguments: Vec::new(),
                nullable: false,
            }
        };
        Some(CsmiReceiver {
            kind: if member.extension_receiver.is_some() {
                CsmiReceiverKind::Extension
            } else {
                CsmiReceiverKind::Instance
            },
            receiver_type: Some(
                type_expression(receiver_type, type_names_by_id)
                    .map_err(|error| CsmiExportError::Identity(error.to_string()))?,
            ),
            extensions: Vec::new(),
        })
    } else {
        None
    };
    let parameters = signature
        .parameters
        .iter()
        .enumerate()
        .map(|(position, parameter)| {
            let binding = if parameter.variadic {
                CsmiParameterBinding::VariadicPositional
            } else {
                match parameter.passing_mode {
                    crate::analyzer::semantic_model::ParameterPassingMode::PositionalOnly => {
                        CsmiParameterBinding::PositionalOnly
                    }
                    crate::analyzer::semantic_model::ParameterPassingMode::NamedOnly => {
                        CsmiParameterBinding::NamedOnly
                    }
                    crate::analyzer::semantic_model::ParameterPassingMode::PositionalOrNamed => {
                        CsmiParameterBinding::PositionalOrNamed
                    }
                }
            };
            let parameter_type = type_expression(&parameter.r#type, type_names_by_id)
                .map_err(|error| CsmiExportError::Identity(error.to_string()))?;
            Ok(CsmiParameter {
                position: position as u32,
                binding,
                label: parameter.name.clone(),
                required: !parameter.optional,
                symbol: None,
                parameter_type: Some(parameter_type),
                extensions: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, CsmiExportError>>()?;
    let results = signature
        .returns
        .iter()
        .enumerate()
        .map(|(position, result)| {
            Ok(CsmiResult {
                position: position as u32,
                label: None,
                result_type: Some(
                    type_expression(result, type_names_by_id)
                        .map_err(|error| CsmiExportError::Identity(error.to_string()))?,
                ),
                extensions: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, CsmiExportError>>()?;
    let kind = match member.member_kind {
        MemberKind::Constructor => CsmiCallableKind::Constructor,
        MemberKind::Method | MemberKind::Function | MemberKind::Static => CsmiCallableKind::Method,
        MemberKind::Property
        | MemberKind::Macro
        | MemberKind::Event
        | MemberKind::Field
        | MemberKind::Constant => {
            return Err(CsmiExportError::Unsupported {
                path: format!("members.{}", member.id),
                semantic: format!(
                    "JVM profile does not map {:?} as a callable",
                    member.member_kind
                ),
            });
        }
    };
    Ok(CsmiCallableShape {
        kind,
        receiver,
        parameters,
        results,
        extensions: Vec::new(),
    })
}

fn transfer_to_csmi(
    transfer: &crate::analyzer::semantic_model::CompiledSummaryTransfer,
) -> Result<CsmiTransfer, CsmiExportError> {
    let source = input_to_csmi(&transfer.input)?;
    let destination = output_to_csmi(&transfer.output)?;
    if transfer.exit_kind == CompiledSummaryExitKind::Exceptional
        && !matches!(transfer.output, CompiledSummaryOutput::ExceptionalReturn {})
    {
        return Err(CsmiExportError::Unsupported {
            path: "procedureSummaries.transfers".to_owned(),
            semantic: "exceptional transfers must target the exception boundary".to_owned(),
        });
    }
    Ok(CsmiTransfer {
        source,
        destination,
        provenance: Vec::new(),
        extensions: Vec::new(),
    })
}

fn input_to_csmi(input: &CompiledSummaryInput) -> Result<CsmiInputLocation, CsmiExportError> {
    let root = match input {
        CompiledSummaryInput::Receiver {} => {
            CsmiInputBoundaryRoot::Receiver(CsmiInputReceiverRoot {
                phase: CsmiInputPhase::Input,
                role: CsmiReceiverRootRole::Receiver,
            })
        }
        CompiledSummaryInput::Parameter { ordinal } => {
            CsmiInputBoundaryRoot::Parameter(CsmiInputParameterRoot {
                phase: CsmiInputPhase::Input,
                role: CsmiParameterRootRole::Parameter,
                position: *ordinal,
            })
        }
    };
    Ok(CsmiInputLocation {
        root,
        projection: None,
    })
}

fn output_to_csmi(output: &CompiledSummaryOutput) -> Result<CsmiOutputLocation, CsmiExportError> {
    let root = match output {
        CompiledSummaryOutput::NormalReturn {} => {
            CsmiOutputBoundaryRoot::Result(CsmiOutputResultRoot {
                phase: CsmiOutputPhase::Output,
                role: CsmiResultRootRole::Result,
                position: 0,
            })
        }
        CompiledSummaryOutput::IndexedNormalReturn { ordinal } => {
            CsmiOutputBoundaryRoot::Result(CsmiOutputResultRoot {
                phase: CsmiOutputPhase::Output,
                role: CsmiResultRootRole::Result,
                position: *ordinal,
            })
        }
        CompiledSummaryOutput::Receiver {} => {
            CsmiOutputBoundaryRoot::Receiver(CsmiOutputReceiverRoot {
                phase: CsmiOutputPhase::Output,
                role: CsmiReceiverRootRole::Receiver,
            })
        }
        CompiledSummaryOutput::ExceptionalReturn {} => {
            CsmiOutputBoundaryRoot::Exception(CsmiOutputExceptionRoot {
                phase: CsmiOutputPhase::Output,
                role: CsmiExceptionRootRole::Exception,
            })
        }
        CompiledSummaryOutput::Capture { .. } | CompiledSummaryOutput::Heap { .. } => {
            return Err(CsmiExportError::Unsupported {
                path: "procedureSummaries.transfers.destination".to_owned(),
                semantic: "capture and heap locations are not representable in CSMI core"
                    .to_owned(),
            });
        }
    };
    Ok(CsmiOutputLocation {
        root,
        projection: None,
    })
}
