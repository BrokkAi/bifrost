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
    CompiledSummaryExitKind, CompiledSummaryInput, CompiledSummaryMoveInvalidation,
    CompiledSummaryOutput, CompiledSummaryValuePreservation, CompiledSummaryValueTransferKind,
    CompiledSummaryValueTransferLimitationKind, CompiledSummaryValueTransferOperation,
    CompilerOptions, Completeness, CppArtifactSelector, CppCanonicalType, CppDescriptorRole,
    CppDigestAlgorithm, CppHeaderClosure, CppIdentityStability, CppLanguage,
    CppPortabilityEvidence, CppPortableSymbolKey, CppReferenceKind, CppResolutionContextRef,
    CppSpecialMemberOperation, CppTypeQualifier, DecodeLimits, ImplicitOperation, MemberFact,
    MemberKind, TypeCopySemantics, TypeMoveSemantics, TypeRef, compile_pack, decode_shard,
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
            Self::Identity(message) => write!(formatter, "CSMI identity mapping failed: {message}"),
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
        pack.manifest.completeness,
        pack.manifest.cpp_portability.as_ref(),
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
    pack_completeness: Completeness,
    cpp_portability: Option<&CppPortabilityEvidence>,
    shards: impl Iterator<Item = &'a CompiledShard>,
    artifact: &CsmiArtifactEvidence,
    options: &CsmiExportOptions,
) -> Result<(CsmiSemanticDocument, CsmiProvenanceRecord), CsmiExportError> {
    if cpp_portability.is_some() {
        validate_exact_artifact_evidence(artifact)?;
    } else {
        validate_maven_evidence(artifact)?;
    }
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
        native_id: &str,
        cpp_keys: &HashMap<String, &CppPortableSymbolKey>,
        symbols: &mut Vec<CsmiSymbolDefinition>,
        seen_symbols: &mut HashSet<String>,
    ) -> Result<String, CsmiExportError> {
        let id = if cpp_keys.is_empty() {
            type_symbol_id(name).map_err(|error| CsmiExportError::Identity(error.to_string()))?
        } else {
            cpp_local_id(cpp_keys.get(native_id).copied().ok_or_else(|| {
                CsmiExportError::MissingDeclaration {
                    path: "cpp_portability.symbols".to_owned(),
                    target: native_id.to_owned(),
                }
            })?)?
        };
        if seen_symbols.insert(id.clone()) {
            symbols.push(if cpp_keys.is_empty() {
                type_symbol(name).map_err(|error| CsmiExportError::Identity(error.to_string()))?
            } else {
                cpp_symbol_definition(
                    &id,
                    cpp_keys.get(native_id).copied().ok_or_else(|| {
                        CsmiExportError::MissingDeclaration {
                            path: "cpp_portability.symbols".to_owned(),
                            target: native_id.to_owned(),
                        }
                    })?,
                )
            });
        }
        Ok(id)
    }
    let cpp_keys: HashMap<String, &CppPortableSymbolKey> = cpp_portability
        .map(|evidence| {
            evidence
                .symbols
                .iter()
                .map(|record| (record.native_id.clone(), &record.key))
                .collect()
        })
        .unwrap_or_default();
    let cpp_aliases: HashMap<String, &CppCanonicalType> = cpp_portability
        .map(|evidence| {
            evidence
                .type_aliases
                .iter()
                .map(|alias| (alias.alias.clone(), &alias.target))
                .collect()
        })
        .unwrap_or_default();
    for fact in &types {
        let id = ensure_type(
            &fact.name,
            &fact.id,
            &cpp_keys,
            &mut symbols,
            &mut seen_symbols,
        )?;
        symbol_by_bifrost_id.insert(fact.id.clone(), id.clone());
        let cpp_alias_target = if fact.type_kind
            == crate::analyzer::semantic_model::TypeKind::TypeAlias
            && !cpp_keys.is_empty()
        {
            Some(cpp_core_type_expression(
                cpp_aliases.get(&fact.id).copied().ok_or_else(|| {
                    CsmiExportError::MissingDeclaration {
                        path: "cpp_portability.type_aliases".to_owned(),
                        target: fact.id.clone(),
                    }
                })?,
                &cpp_keys,
            )?)
        } else {
            None
        };
        declarations.push(CsmiDeclaration {
            symbol: id,
            category: if cpp_alias_target.is_some() {
                CsmiDeclarationCategory::TypeAlias
            } else {
                CsmiDeclarationCategory::Type
            },
            owner: None,
            generic_parameters: Vec::new(),
            callable: None,
            alias_target: cpp_alias_target,
            provenance: vec![options.provenance_id.clone()],
            extensions: Vec::new(),
        });
    }
    for fact in &member_facts {
        let owner_name = type_names_by_id.get(&fact.owner).cloned().ok_or_else(|| {
            CsmiExportError::MissingDeclaration {
                path: format!("members.{}", fact.id),
                target: fact.owner.clone(),
            }
        })?;
        let owner_id = ensure_type(
            &owner_name,
            &fact.owner,
            &cpp_keys,
            &mut symbols,
            &mut seen_symbols,
        )?;
        let id = if cpp_keys.is_empty() {
            member_symbol_id(&owner_name, fact, &type_names_by_id)
                .map_err(|error| CsmiExportError::Identity(error.to_string()))?
        } else {
            cpp_local_id(cpp_keys.get(&fact.id).copied().ok_or_else(|| {
                CsmiExportError::MissingDeclaration {
                    path: "cpp_portability.symbols".to_owned(),
                    target: fact.id.clone(),
                }
            })?)?
        };
        symbol_by_bifrost_id.insert(fact.id.clone(), id.clone());
        if seen_symbols.insert(id.clone()) {
            symbols.push(if cpp_keys.is_empty() {
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
                symbol
            } else {
                cpp_symbol_definition(
                    &id,
                    cpp_keys.get(&fact.id).copied().ok_or_else(|| {
                        CsmiExportError::MissingDeclaration {
                            path: "cpp_portability.symbols".to_owned(),
                            target: fact.id.clone(),
                        }
                    })?,
                )
            });
        }
        declarations.push(CsmiDeclaration {
            symbol: id,
            category: CsmiDeclarationCategory::Callable,
            owner: Some(owner_id.clone()),
            generic_parameters: Vec::new(),
            callable: Some(callable_shape(
                fact,
                &type_names_by_id,
                &symbol_by_bifrost_id,
                !cpp_keys.is_empty(),
            )?),
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
    let mut extension_facts = Vec::new();
    let mut value_transfer_affects = Vec::new();
    for fact in &types {
        let Some(value_semantics) = &fact.value_semantics else {
            continue;
        };
        let type_id = symbol_by_bifrost_id.get(&fact.id).cloned().ok_or_else(|| {
            CsmiExportError::MissingDeclaration {
                path: format!("types.{}.valueSemantics", fact.id),
                target: fact.id.clone(),
            }
        })?;
        if let Some(copy) = &value_semantics.copy {
            let semantics = match copy {
                TypeCopySemantics::Trivial => CsmiTypeSemantics::Trivial {},
                TypeCopySemantics::ViaMember { member } => CsmiTypeSemantics::ViaMember {
                    member: symbol_by_bifrost_id.get(member).cloned().ok_or_else(|| {
                        CsmiExportError::MissingDeclaration {
                            path: format!("types.{}.valueSemantics.copy.member", fact.id),
                            target: member.clone(),
                        }
                    })?,
                },
            };
            push_type_value_fact(
                &mut extension_facts,
                &mut value_transfer_affects,
                &type_id,
                CsmiTypeValueSemanticsAspect::Copy,
                semantics,
                options,
            )?;
        }
        if matches!(
            value_semantics.move_semantics,
            Some(TypeMoveSemantics::Invalidating)
        ) {
            push_type_value_fact(
                &mut extension_facts,
                &mut value_transfer_affects,
                &type_id,
                CsmiTypeValueSemanticsAspect::Move,
                CsmiTypeSemantics::Invalidating {},
                options,
            )?;
        }
    }
    for fact in &member_facts {
        let Some(operation) = &fact.implicit_operation else {
            continue;
        };
        let symbol = symbol_by_bifrost_id.get(&fact.id).cloned().ok_or_else(|| {
            CsmiExportError::MissingDeclaration {
                path: format!("members.{}.implicitOperation", fact.id),
                target: fact.id.clone(),
            }
        })?;
        let owner = symbol_by_bifrost_id
            .get(&fact.owner)
            .cloned()
            .ok_or_else(|| CsmiExportError::MissingDeclaration {
                path: format!("members.{}.owner", fact.id),
                target: fact.owner.clone(),
            })?;
        let (role, target) = match operation {
            ImplicitOperation::CopyConstructor => {
                (CsmiImplicitOperationRole::CopyConstructor, None)
            }
            ImplicitOperation::MoveConstructor => {
                (CsmiImplicitOperationRole::MoveConstructor, None)
            }
            ImplicitOperation::CopyAssignment => (CsmiImplicitOperationRole::CopyAssignment, None),
            ImplicitOperation::MoveAssignment => (CsmiImplicitOperationRole::MoveAssignment, None),
            ImplicitOperation::ValuePreservingConstructor => {
                return Err(CsmiExportError::Unsupported {
                    path: format!("members.{}.implicitOperation", fact.id),
                    semantic: "value-preserving character-data construction is not an implicit-operation role in csmi.value-transfer 0.1.0".to_owned(),
                });
            }
            ImplicitOperation::ConversionOperator { target } => (
                CsmiImplicitOperationRole::ConversionOperator,
                Some(type_ref_symbol(target, &symbol_by_bifrost_id)?),
            ),
        };
        let payload = CsmiImplicitOperationFact {
            kind: CsmiImplicitOperationKind::ImplicitOperation,
            symbol: symbol.clone(),
            owner: owner.clone(),
            operation: role,
            target: target.clone(),
        };
        let scope = if let Some(target) = &target {
            json!({"owner": owner, "operation": role, "target": target})
        } else {
            json!({"owner": owner, "operation": role})
        };
        extension_facts.push(CsmiExtensionFact {
            vocabulary: CSMI_VALUE_TRANSFER_PROFILE_ID.to_owned(),
            version: CSMI_VALUE_TRANSFER_PROFILE_VERSION.to_owned(),
            family: "implicit-operations".to_owned(),
            scope: scope.clone(),
            payload: serde_json::to_value(payload)
                .map_err(|error| CsmiExportError::Canonical(error.to_string()))?,
            provenance: vec![options.provenance_id.clone()],
            extensions: Vec::new(),
        });
        value_transfer_affects.push(CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
            kind: CsmiAffectedFactFamilyKind::FactFamily,
            family: "implicit-operations".to_owned(),
            scope,
        }));
    }
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
            .map(|transfer| transfer_to_csmi(transfer, &symbol_by_bifrost_id))
            .collect::<Result<Vec<_>, _>>()?;
        if summary
            .transfers
            .iter()
            .any(|transfer| transfer.value_transfer.is_some())
        {
            value_transfer_affects.push(CsmiAffectedUnit::Attachment(CsmiAffectedAttachment {
                kind: CsmiAffectedAttachmentKind::Attachment,
                attachment_point: "procedure-summary-transfer".to_owned(),
                target: json!({"callable": callable}),
            }));
            value_transfer_affects.push(CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
                kind: CsmiAffectedFactFamilyKind::FactFamily,
                family: "identity-separating-transfers".to_owned(),
                scope: json!({"callable": callable}),
            }));
        }
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
    for (summary, compiled) in summaries.iter().zip(summary_shards.iter()) {
        let profiled: Vec<_> = compiled
            .transfers
            .iter()
            .filter_map(|transfer| transfer.value_transfer.as_ref())
            .collect();
        if profiled.is_empty() {
            continue;
        }
        let complete = profiled.iter().all(|transfer| {
            !matches!(
                transfer.operation,
                CompiledSummaryValueTransferOperation::Unknown { .. }
            ) && !matches!(
                transfer.kind,
                CompiledSummaryValueTransferKind::Move {
                    invalidation: CompiledSummaryMoveInvalidation::Unknown
                } | CompiledSummaryValueTransferKind::Conversion {
                    preservation: CompiledSummaryValuePreservation::Unknown
                }
            )
        });
        completeness_statements.push(CsmiCompletenessStatement {
            vocabulary: Some(CSMI_VALUE_TRANSFER_PROFILE_ID.to_owned()),
            version: Some(CSMI_VALUE_TRANSFER_PROFILE_VERSION.to_owned()),
            family: "identity-separating-transfers".to_owned(),
            scope: json!({"callable": summary.callable}),
            status: if complete {
                CsmiCoverageStatus::Complete
            } else {
                CsmiCoverageStatus::Partial
            },
            limitations: if complete {
                Vec::new()
            } else {
                vec![CsmiLimitation {
                    kind: "unknown-value-transfer-detail".to_owned(),
                    diagnostic: None,
                }]
            },
            provenance: vec![options.provenance_id.clone()],
            extensions: Vec::new(),
        });
    }
    for fact in &extension_facts {
        completeness_statements.push(CsmiCompletenessStatement {
            vocabulary: Some(CSMI_VALUE_TRANSFER_PROFILE_ID.to_owned()),
            version: Some(CSMI_VALUE_TRANSFER_PROFILE_VERSION.to_owned()),
            family: fact.family.clone(),
            scope: fact.scope.clone(),
            status: CsmiCoverageStatus::Complete,
            limitations: Vec::new(),
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
            "scheme": if cpp_keys.is_empty() { super::identity::JVM_IDENTITY_SCHEME } else { CSMI_CPP_DECLARATION_IDENTITY_SCHEME },
            "schemeVersion": if cpp_keys.is_empty() { super::identity::JVM_IDENTITY_VERSION } else { CSMI_CPP_DECLARATION_IDENTITY_SCHEME_VERSION }
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
    let mut cpp_affects = Vec::new();
    let mut compatibility_constraints = Vec::new();
    if let Some(evidence) = cpp_portability {
        for record in &evidence.symbols {
            let symbol = cpp_local_id(&record.key)?;
            if seen_symbols.insert(symbol.clone()) {
                symbols.push(cpp_symbol_definition(&symbol, &record.key));
            }
            cpp_affects.push(CsmiAffectedUnit::CoreSlot(CsmiAffectedCoreSlot {
                kind: CsmiAffectedCoreSlotKind::CoreSlot,
                slot: "symbol-identity-scheme".to_owned(),
                target: json!({"symbol": symbol}),
            }));
        }
        for context in &evidence.resolution_contexts {
            compatibility_constraints.push(CsmiCompatibilityConstraint {
                vocabulary: CSMI_C_CPP_RESOLUTION_PROFILE_ID.to_owned(),
                version: CSMI_C_CPP_RESOLUTION_PROFILE_VERSION.to_owned(),
                value: serde_json::to_value(csmi_resolution_context(context))
                    .map_err(|error| CsmiExportError::Canonical(error.to_string()))?,
            });
        }
        for alias in &evidence.type_aliases {
            let alias_symbol =
                symbol_by_bifrost_id
                    .get(&alias.alias)
                    .cloned()
                    .ok_or_else(|| CsmiExportError::MissingDeclaration {
                        path: "cpp_portability.type_aliases.alias".to_owned(),
                        target: alias.alias.clone(),
                    })?;
            let scope = json!({"alias": alias_symbol});
            extension_facts.push(CsmiExtensionFact {
                vocabulary: CSMI_CPP_PROFILE_ID.to_owned(),
                version: CSMI_CPP_PROFILE_VERSION.to_owned(),
                family: "type-alias".to_owned(),
                scope: scope.clone(),
                payload: serde_json::to_value(CsmiCppTypeAliasFact {
                    kind: CsmiCppTypeAliasKind::TypeAlias,
                    language: CsmiCppProfileLanguage::Cpp,
                    alias: alias_symbol,
                    target: csmi_cpp_type(&alias.target, &cpp_keys)?,
                    resolution_context: csmi_cpp_context_ref(&alias.resolution_context)?,
                })
                .map_err(|error| CsmiExportError::Canonical(error.to_string()))?,
                provenance: vec![options.provenance_id.clone()],
                extensions: Vec::new(),
            });
            cpp_affects.push(CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
                kind: CsmiAffectedFactFamilyKind::FactFamily,
                family: "type-alias".to_owned(),
                scope: scope.clone(),
            }));
            completeness_statements.push(CsmiCompletenessStatement {
                vocabulary: Some(CSMI_CPP_PROFILE_ID.to_owned()),
                version: Some(CSMI_CPP_PROFILE_VERSION.to_owned()),
                family: "type-alias".to_owned(),
                scope,
                status: CsmiCoverageStatus::Complete,
                limitations: Vec::new(),
                provenance: vec![options.provenance_id.clone()],
                extensions: Vec::new(),
            });
        }
        for member in &evidence.special_members {
            let owner_symbol = symbol_by_bifrost_id
                .get(&member.owner)
                .cloned()
                .ok_or_else(|| CsmiExportError::MissingDeclaration {
                    path: "cpp_portability.special_members.owner".to_owned(),
                    target: member.owner.clone(),
                })?;
            let member_symbol = symbol_by_bifrost_id
                .get(&member.member)
                .cloned()
                .ok_or_else(|| CsmiExportError::MissingDeclaration {
                    path: "cpp_portability.special_members.member".to_owned(),
                    target: member.member.clone(),
                })?;
            let operation = match member.operation {
                CppSpecialMemberOperation::CopyConstructor => "copy-constructor",
                CppSpecialMemberOperation::CopyAssignment => "copy-assignment",
                CppSpecialMemberOperation::MoveConstructor => "move-constructor",
            };
            let scope = json!({"owner": owner_symbol, "operation": operation});
            extension_facts.push(CsmiExtensionFact {
                vocabulary: CSMI_CPP_PROFILE_ID.to_owned(),
                version: CSMI_CPP_PROFILE_VERSION.to_owned(),
                family: "special-member".to_owned(),
                scope: scope.clone(),
                payload: serde_json::to_value(csmi_special_member(
                    member,
                    &cpp_keys,
                    &owner_symbol,
                    &member_symbol,
                )?)
                .map_err(|error| CsmiExportError::Canonical(error.to_string()))?,
                provenance: vec![options.provenance_id.clone()],
                extensions: Vec::new(),
            });
            cpp_affects.push(CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
                kind: CsmiAffectedFactFamilyKind::FactFamily,
                family: "special-member".to_owned(),
                scope: scope.clone(),
            }));
            completeness_statements.push(CsmiCompletenessStatement {
                vocabulary: Some(CSMI_CPP_PROFILE_ID.to_owned()),
                version: Some(CSMI_CPP_PROFILE_VERSION.to_owned()),
                family: "special-member".to_owned(),
                scope,
                status: CsmiCoverageStatus::Complete,
                limitations: Vec::new(),
                provenance: vec![options.provenance_id.clone()],
                extensions: Vec::new(),
            });
        }
    }
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
            compatibility_constraints,
            vocabulary_uses: {
                let mut uses = Vec::new();
                if !value_transfer_affects.is_empty() {
                    uses.push(CsmiVocabularyUse {
                        identifier: CSMI_VALUE_TRANSFER_PROFILE_ID.to_owned(),
                        version: CSMI_VALUE_TRANSFER_PROFILE_VERSION.to_owned(),
                        schema: CSMI_VALUE_TRANSFER_PROFILE_SCHEMA.to_owned(),
                        requirement: CsmiVocabularyRequirement::Required,
                        affects: value_transfer_affects,
                    });
                }
                if cpp_portability.is_some() {
                    uses.push(CsmiVocabularyUse {
                        identifier: CSMI_C_CPP_RESOLUTION_PROFILE_ID.to_owned(),
                        version: CSMI_C_CPP_RESOLUTION_PROFILE_VERSION.to_owned(),
                        schema: CSMI_CPP_PROFILE_SCHEMA.to_owned(),
                        requirement: CsmiVocabularyRequirement::Required,
                        affects: vec![CsmiAffectedUnit::CoreSlot(CsmiAffectedCoreSlot {
                            kind: CsmiAffectedCoreSlotKind::CoreSlot,
                            slot: "artifact-compatibility".to_owned(),
                            target: json!({"semanticModel": "current"}),
                        })],
                    });
                    uses.push(CsmiVocabularyUse {
                        identifier: CSMI_CPP_PROFILE_ID.to_owned(),
                        version: CSMI_CPP_PROFILE_VERSION.to_owned(),
                        schema: CSMI_CPP_PROFILE_SCHEMA.to_owned(),
                        requirement: CsmiVocabularyRequirement::Required,
                        affects: cpp_affects,
                    });
                }
                uses
            },
            consumer_resolved_dependencies: Vec::new(),
            symbols,
            declarations,
            relationships: Vec::new(),
            procedure_summaries: summaries,
            extension_facts,
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
    let mut support = CsmiVocabularySupport::empty();
    support.add(
        CSMI_VALUE_TRANSFER_PROFILE_ID,
        CSMI_VALUE_TRANSFER_PROFILE_VERSION,
        CSMI_VALUE_TRANSFER_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_C_CPP_RESOLUTION_PROFILE_ID,
        CSMI_C_CPP_RESOLUTION_PROFILE_VERSION,
        CSMI_CPP_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_CPP_PROFILE_ID,
        CSMI_CPP_PROFILE_VERSION,
        CSMI_CPP_PROFILE_SCHEMA,
    );
    let validation = validate_csmi_pack(&manifest_bytes, &pack.resources, &support);
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

fn validate_exact_artifact_evidence(
    artifact: &CsmiArtifactEvidence,
) -> Result<(), CsmiExportError> {
    if !artifact.purl.starts_with("pkg:") || !artifact.purl.contains('@') {
        return Err(CsmiExportError::InvalidEvidence(
            "portable C/C++ export requires an exact versioned PURL".to_owned(),
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

fn cpp_symbol_definition(id: &str, key: &CppPortableSymbolKey) -> CsmiSymbolDefinition {
    CsmiSymbolDefinition {
        id: id.to_owned(),
        artifact_selectors: Some(
            key.artifact_selectors
                .iter()
                .map(cpp_core_artifact_selector)
                .collect(),
        ),
        scheme: key.scheme.clone(),
        scheme_version: key.scheme_version.clone(),
        stability: match key.stability {
            CppIdentityStability::Portable => CsmiStability::Portable,
        },
        descriptors: key
            .descriptors
            .iter()
            .map(|descriptor| CsmiDescriptor {
                role: match descriptor.role {
                    CppDescriptorRole::Namespace => CsmiDescriptorRole::Namespace,
                    CppDescriptorRole::Type => CsmiDescriptorRole::Type,
                    CppDescriptorRole::Callable => CsmiDescriptorRole::Callable,
                },
                name: Some(descriptor.name.clone()),
                disambiguator: Some(descriptor.disambiguator.clone()),
            })
            .collect(),
        display_name: None,
        qualified_display_name: None,
        native_signature: None,
        documentation_name: None,
        abi_name: None,
        origin: Some(CsmiSymbolOrigin::Named),
        external_identities: Vec::new(),
        provenance: Vec::new(),
        extensions: Vec::new(),
    }
}

fn cpp_local_id(key: &CppPortableSymbolKey) -> Result<String, CsmiExportError> {
    let bytes = canonical_json(&csmi_cpp_key(key))
        .map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
    Ok(format!("cpp.{}", sha256_hex(&bytes)))
}

fn cpp_core_artifact_selector(selector: &CppArtifactSelector) -> CsmiArtifactSelector {
    CsmiArtifactSelector {
        purl: selector.purl.clone(),
        version_range: None,
        digests: selector
            .digests
            .iter()
            .map(|digest| CsmiArtifactDigest {
                algorithm: match digest.algorithm {
                    CppDigestAlgorithm::Sha256 => CsmiDigestAlgorithm::Sha256,
                },
                coverage: digest.coverage.clone(),
                canonicalization: digest.canonicalization.clone(),
                value: digest.value.clone(),
            })
            .collect(),
    }
}

fn cpp_profile_artifact_selector(selector: &CppArtifactSelector) -> CsmiCppArtifactSelector {
    CsmiCppArtifactSelector {
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
    }
}

fn csmi_cpp_key(key: &CppPortableSymbolKey) -> CsmiCppSymbolKey {
    CsmiCppSymbolKey {
        artifact_selectors: key
            .artifact_selectors
            .iter()
            .map(cpp_profile_artifact_selector)
            .collect(),
        scheme: key.scheme.clone(),
        scheme_version: key.scheme_version.clone(),
        stability: CsmiCppIdentityStability::Portable,
        descriptors: key
            .descriptors
            .iter()
            .map(|descriptor| CsmiCppDescriptor {
                role: match descriptor.role {
                    CppDescriptorRole::Namespace => CsmiCppDescriptorRole::Namespace,
                    CppDescriptorRole::Type => CsmiCppDescriptorRole::Type,
                    CppDescriptorRole::Callable => CsmiCppDescriptorRole::Callable,
                },
                name: descriptor.name.clone(),
                disambiguator: descriptor.disambiguator.clone(),
            })
            .collect(),
    }
}

pub(crate) fn csmi_resolution_context(
    context: &crate::analyzer::semantic_model::CppResolutionContextRecord,
) -> CsmiResolutionContext {
    CsmiResolutionContext {
        kind: CsmiResolutionContextKind::ResolutionContext,
        language: match context.language {
            CppLanguage::C => CsmiCppLanguage::C,
            CppLanguage::Cpp => CsmiCppLanguage::Cpp,
        },
        translation_unit: context.translation_unit.clone(),
        compile_arguments_digest: context.compile_arguments_digest.clone(),
        direct_headers: context
            .direct_headers
            .iter()
            .map(|header| CsmiCppDirectHeader {
                include_name: header.include_name.clone(),
                artifact: cpp_profile_artifact_selector(&header.artifact),
            })
            .collect(),
        header_closure: CsmiCompleteHeaderClosure::Complete,
    }
}

fn csmi_cpp_context_ref(
    context: &CppResolutionContextRef,
) -> Result<CsmiCppResolutionContext, CsmiExportError> {
    if context.vocabulary != CSMI_C_CPP_RESOLUTION_PROFILE_ID
        || context.version != CSMI_C_CPP_RESOLUTION_PROFILE_VERSION
        || context.language != CppLanguage::Cpp
        || context.header_closure != CppHeaderClosure::Complete
    {
        return Err(CsmiExportError::Unsupported {
            path: "cpp_portability.resolution_context".to_owned(),
            semantic: "C++ facts require the exact complete C/C++ resolution profile".to_owned(),
        });
    }
    Ok(CsmiCppResolutionContext {
        vocabulary: CsmiCCppResolutionVocabulary::CCppResolution,
        version: context.version.clone(),
        context_digest: context.context_digest.clone(),
        language: CsmiCppProfileLanguage::Cpp,
        header_closure: CsmiCompleteHeaderClosure::Complete,
    })
}

fn csmi_cpp_type(
    value: &CppCanonicalType,
    keys: &HashMap<String, &CppPortableSymbolKey>,
) -> Result<CsmiCppCanonicalType, CsmiExportError> {
    Ok(match value {
        CppCanonicalType::Fundamental { .. } => {
            CsmiCppCanonicalType::Fundamental(CsmiCppFundamentalType {
                kind: CsmiCppFundamentalTypeKind::Fundamental,
                name: CsmiCppFundamentalTypeName::Char,
            })
        }
        CppCanonicalType::Declared { symbol } => {
            CsmiCppCanonicalType::Declared(CsmiCppDeclaredType {
                kind: CsmiCppDeclaredTypeKind::Declared,
                symbol: csmi_cpp_key(keys.get(symbol).copied().ok_or_else(|| {
                    CsmiExportError::MissingDeclaration {
                        path: "cpp_portability.canonical_type".to_owned(),
                        target: symbol.clone(),
                    }
                })?),
            })
        }
        CppCanonicalType::TemplateSpecialization { primary, arguments } => {
            CsmiCppCanonicalType::TemplateSpecialization(CsmiCppTemplateSpecialization {
                kind: CsmiCppTemplateSpecializationKind::TemplateSpecialization,
                primary: csmi_cpp_key(keys.get(primary).copied().ok_or_else(|| {
                    CsmiExportError::MissingDeclaration {
                        path: "cpp_portability.canonical_type".to_owned(),
                        target: primary.clone(),
                    }
                })?),
                arguments: arguments
                    .iter()
                    .map(|argument| csmi_cpp_type(argument, keys))
                    .collect::<Result<Vec<_>, _>>()?,
            })
        }
        CppCanonicalType::Qualified { qualifiers, r#type } => {
            CsmiCppCanonicalType::Qualified(CsmiCppQualifiedType {
                kind: CsmiCppQualifiedTypeKind::Qualified,
                qualifiers: qualifiers
                    .iter()
                    .map(|qualifier| match qualifier {
                        CppTypeQualifier::Const => CsmiCppTypeQualifier::Const,
                        CppTypeQualifier::Volatile => CsmiCppTypeQualifier::Volatile,
                    })
                    .collect(),
                r#type: Box::new(csmi_cpp_type(r#type, keys)?),
            })
        }
        CppCanonicalType::Reference {
            reference_kind,
            referent,
        } => CsmiCppCanonicalType::Reference(CsmiCppReferenceType {
            kind: CsmiCppReferenceTypeKind::Reference,
            reference_kind: match reference_kind {
                CppReferenceKind::Lvalue => CsmiCppReferenceKind::Lvalue,
                CppReferenceKind::Rvalue => CsmiCppReferenceKind::Rvalue,
            },
            referent: Box::new(csmi_cpp_type(referent, keys)?),
        }),
    })
}

fn cpp_core_type_expression(
    value: &CppCanonicalType,
    keys: &HashMap<String, &CppPortableSymbolKey>,
) -> Result<CsmiTypeExpression, CsmiExportError> {
    Ok(match value {
        CppCanonicalType::Fundamental { name } => {
            CsmiTypeExpression::Intrinsic(CsmiIntrinsicType {
                kind: CsmiIntrinsicTypeKind::Intrinsic,
                vocabulary: CSMI_CPP_PROFILE_ID.to_owned(),
                version: CSMI_CPP_PROFILE_VERSION.to_owned(),
                identifier: match name {
                    crate::analyzer::semantic_model::CppFundamentalTypeName::Char => {
                        "char".to_owned()
                    }
                },
            })
        }
        CppCanonicalType::Declared { symbol } => CsmiTypeExpression::Reference(CsmiReferenceType {
            kind: CsmiReferenceTypeKind::Reference,
            symbol: cpp_local_id(keys.get(symbol).copied().ok_or_else(|| {
                CsmiExportError::MissingDeclaration {
                    path: "cpp_portability.type_aliases.target".to_owned(),
                    target: symbol.clone(),
                }
            })?)?,
            arguments: Vec::new(),
        }),
        CppCanonicalType::TemplateSpecialization { primary, arguments } => {
            CsmiTypeExpression::Reference(CsmiReferenceType {
                kind: CsmiReferenceTypeKind::Reference,
                symbol: cpp_local_id(keys.get(primary).copied().ok_or_else(|| {
                    CsmiExportError::MissingDeclaration {
                        path: "cpp_portability.type_aliases.target".to_owned(),
                        target: primary.clone(),
                    }
                })?)?,
                arguments: arguments
                    .iter()
                    .map(|argument| cpp_core_type_expression(argument, keys))
                    .collect::<Result<Vec<_>, _>>()?,
            })
        }
        // Core CSMI carries the referent while the required C++ profile fact
        // retains exact qualification and reference-kind semantics.
        CppCanonicalType::Qualified { r#type, .. } => cpp_core_type_expression(r#type, keys)?,
        CppCanonicalType::Reference { referent, .. } => cpp_core_type_expression(referent, keys)?,
    })
}

fn csmi_special_member(
    member: &crate::analyzer::semantic_model::CppSpecialMemberEvidence,
    keys: &HashMap<String, &CppPortableSymbolKey>,
    owner_symbol: &str,
    member_symbol: &str,
) -> Result<CsmiCppSpecialMemberFact, CsmiExportError> {
    Ok(CsmiCppSpecialMemberFact {
        kind: CsmiCppSpecialMemberKind::SpecialMember,
        language: CsmiCppProfileLanguage::Cpp,
        owner: owner_symbol.to_owned(),
        member: member_symbol.to_owned(),
        operation: match member.operation {
            CppSpecialMemberOperation::CopyConstructor => {
                CsmiCppSpecialMemberOperation::CopyConstructor
            }
            CppSpecialMemberOperation::CopyAssignment => {
                CsmiCppSpecialMemberOperation::CopyAssignment
            }
            CppSpecialMemberOperation::MoveConstructor => {
                CsmiCppSpecialMemberOperation::MoveConstructor
            }
        },
        signature: csmi_cpp_signature(&member.signature, keys)?,
        member_disambiguator: member.member_disambiguator.clone(),
        resolution_context: csmi_cpp_context_ref(&member.resolution_context)?,
    })
}

pub(crate) fn csmi_cpp_signature(
    signature: &crate::analyzer::semantic_model::CppCallableSignature,
    keys: &HashMap<String, &CppPortableSymbolKey>,
) -> Result<CsmiCppCallableSignature, CsmiExportError> {
    Ok(CsmiCppCallableSignature {
        callable_kind: match signature.callable_kind {
            crate::analyzer::semantic_model::CppCallableKind::Constructor => {
                CsmiCppCallableKind::Constructor
            }
            crate::analyzer::semantic_model::CppCallableKind::Method => CsmiCppCallableKind::Method,
        },
        owner: csmi_cpp_key(keys.get(&signature.owner).copied().ok_or_else(|| {
            CsmiExportError::MissingDeclaration {
                path: "cpp_portability.special_member.signature.owner".to_owned(),
                target: signature.owner.clone(),
            }
        })?),
        receiver: signature
            .receiver
            .as_ref()
            .map(|value| csmi_cpp_type(value, keys))
            .transpose()?,
        parameters: signature
            .parameters
            .iter()
            .map(|value| csmi_cpp_type(value, keys))
            .collect::<Result<Vec<_>, _>>()?,
        result: signature
            .result
            .as_ref()
            .map(|value| csmi_cpp_type(value, keys))
            .transpose()?,
    })
}

fn callable_shape(
    member: &MemberFact,
    type_names_by_id: &HashMap<String, String>,
    symbol_by_bifrost_id: &HashMap<String, String>,
    cpp_identity: bool,
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
            receiver_type: Some(core_type_expression(
                receiver_type,
                type_names_by_id,
                symbol_by_bifrost_id,
                cpp_identity,
            )?),
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
            let parameter_type = core_type_expression(
                &parameter.r#type,
                type_names_by_id,
                symbol_by_bifrost_id,
                cpp_identity,
            )?;
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
                result_type: Some(core_type_expression(
                    result,
                    type_names_by_id,
                    symbol_by_bifrost_id,
                    cpp_identity,
                )?),
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

fn core_type_expression(
    value: &TypeRef,
    type_names_by_id: &HashMap<String, String>,
    symbol_by_bifrost_id: &HashMap<String, String>,
    cpp_identity: bool,
) -> Result<CsmiTypeExpression, CsmiExportError> {
    if !cpp_identity {
        return type_expression(value, type_names_by_id)
            .map_err(|error| CsmiExportError::Identity(error.to_string()));
    }
    match value {
        TypeRef::ByRef { element, .. } => core_type_expression(
            element,
            type_names_by_id,
            symbol_by_bifrost_id,
            cpp_identity,
        ),
        TypeRef::Declared { id, arguments, .. } => {
            Ok(CsmiTypeExpression::Reference(CsmiReferenceType {
                kind: CsmiReferenceTypeKind::Reference,
                symbol: symbol_by_bifrost_id.get(id).cloned().ok_or_else(|| {
                    CsmiExportError::MissingDeclaration {
                        path: "declarations.callable.type".to_owned(),
                        target: id.clone(),
                    }
                })?,
                arguments: arguments
                    .iter()
                    .map(|argument| {
                        core_type_expression(
                            argument,
                            type_names_by_id,
                            symbol_by_bifrost_id,
                            cpp_identity,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            }))
        }
        TypeRef::Named {
            name, arguments, ..
        } => {
            let native_id = type_names_by_id
                .iter()
                .find_map(|(id, candidate)| (candidate == name).then_some(id))
                .ok_or_else(|| CsmiExportError::Unsupported {
                    path: "declarations.callable.type".to_owned(),
                    semantic: format!("C++ named type {name} has no exact declaration"),
                })?;
            core_type_expression(
                &TypeRef::Declared {
                    id: native_id.clone(),
                    arguments: arguments.clone(),
                    nullable: false,
                },
                type_names_by_id,
                symbol_by_bifrost_id,
                cpp_identity,
            )
        }
        TypeRef::TypeParameter { name } => Ok(CsmiTypeExpression::Parameter(CsmiParameterType {
            kind: CsmiParameterTypeKind::Parameter,
            symbol: format!("type-parameter.{name}"),
        })),
        other => Err(CsmiExportError::Unsupported {
            path: "declarations.callable.type".to_owned(),
            semantic: format!("C++ core type shape {other:?} is not representable"),
        }),
    }
}

fn transfer_to_csmi(
    transfer: &crate::analyzer::semantic_model::CompiledSummaryTransfer,
    symbol_by_bifrost_id: &HashMap<String, String>,
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
    let extensions = transfer
        .value_transfer
        .as_ref()
        .map(|value_transfer| {
            let payload = CsmiValueTransferAttachment {
                kind: CsmiValueTransferAttachmentKind::Transfer,
                transfer_kind: match value_transfer.kind {
                    CompiledSummaryValueTransferKind::Copy {} => CsmiValueTransferKind::Copy {},
                    CompiledSummaryValueTransferKind::AggregateCopy {} => {
                        CsmiValueTransferKind::AggregateCopy {}
                    }
                    CompiledSummaryValueTransferKind::Move { invalidation } => {
                        CsmiValueTransferKind::Move {
                            invalidation: match invalidation {
                                CompiledSummaryMoveInvalidation::Invalidated => CsmiMoveInvalidation::Invalidated,
                                CompiledSummaryMoveInvalidation::Unknown => CsmiMoveInvalidation::Unknown,
                            },
                        }
                    }
                    CompiledSummaryValueTransferKind::Conversion { preservation } => {
                        CsmiValueTransferKind::Conversion {
                            preservation: match preservation {
                                CompiledSummaryValuePreservation::Identity => CsmiValuePreservation::Identity,
                                CompiledSummaryValuePreservation::Preserving => CsmiValuePreservation::Preserving,
                                CompiledSummaryValuePreservation::Changing => CsmiValuePreservation::Changing,
                                CompiledSummaryValuePreservation::Unknown => CsmiValuePreservation::Unknown,
                            },
                        }
                    }
                    CompiledSummaryValueTransferKind::Boxing {} => CsmiValueTransferKind::Boxing {},
                    CompiledSummaryValueTransferKind::Unboxing {} => CsmiValueTransferKind::Unboxing {},
                },
                operation: match &value_transfer.operation {
                    CompiledSummaryValueTransferOperation::None {} => CsmiValueTransferOperation::None {},
                    CompiledSummaryValueTransferOperation::Implicit { member } => {
                        CsmiValueTransferOperation::Implicit {
                            symbol: symbol_by_bifrost_id.get(member).cloned().ok_or_else(|| {
                                CsmiExportError::MissingDeclaration {
                                    path: "procedureSummaries.transfers.valueTransfer.operation.member".to_owned(),
                                    target: member.clone(),
                                }
                            })?,
                        }
                    }
                    CompiledSummaryValueTransferOperation::Unknown { limitation } => {
                        CsmiValueTransferOperation::Unknown {
                            limitation: CsmiProfileLimitation {
                                kind: match limitation.kind {
                                    CompiledSummaryValueTransferLimitationKind::BudgetExhausted => CsmiProfileLimitationKind::BudgetExhausted,
                                    CompiledSummaryValueTransferLimitationKind::Cancelled => CsmiProfileLimitationKind::Cancelled,
                                    CompiledSummaryValueTransferLimitationKind::Unsupported => CsmiProfileLimitationKind::Unsupported,
                                    CompiledSummaryValueTransferLimitationKind::UnresolvedIdentity => CsmiProfileLimitationKind::UnresolvedIdentity,
                                    CompiledSummaryValueTransferLimitationKind::AmbiguousIdentity => CsmiProfileLimitationKind::AmbiguousIdentity,
                                    CompiledSummaryValueTransferLimitationKind::IncompleteInput => CsmiProfileLimitationKind::IncompleteInput,
                                    CompiledSummaryValueTransferLimitationKind::Other => CsmiProfileLimitationKind::Other,
                                },
                                message: limitation.message.clone(),
                            },
                        }
                    }
                },
            };
            Ok(CsmiExtensionAttachment {
                vocabulary: CSMI_VALUE_TRANSFER_PROFILE_ID.to_owned(),
                version: CSMI_VALUE_TRANSFER_PROFILE_VERSION.to_owned(),
                payload: serde_json::to_value(payload)
                    .map_err(|error| CsmiExportError::Canonical(error.to_string()))?,
            })
        })
        .transpose()?
        .into_iter()
        .collect();
    Ok(CsmiTransfer {
        source,
        destination,
        provenance: Vec::new(),
        extensions,
    })
}

fn push_type_value_fact(
    facts: &mut Vec<CsmiExtensionFact>,
    affects: &mut Vec<CsmiAffectedUnit>,
    type_id: &str,
    aspect: CsmiTypeValueSemanticsAspect,
    semantics: CsmiTypeSemantics,
    options: &CsmiExportOptions,
) -> Result<(), CsmiExportError> {
    let scope = json!({"type": type_id, "aspect": aspect});
    let payload = CsmiTypeValueSemantics {
        kind: CsmiTypeValueSemanticsKind::TypeValueSemantics,
        r#type: type_id.to_owned(),
        aspect,
        semantics,
    };
    facts.push(CsmiExtensionFact {
        vocabulary: CSMI_VALUE_TRANSFER_PROFILE_ID.to_owned(),
        version: CSMI_VALUE_TRANSFER_PROFILE_VERSION.to_owned(),
        family: "type-value-semantics".to_owned(),
        scope: scope.clone(),
        payload: serde_json::to_value(payload)
            .map_err(|error| CsmiExportError::Canonical(error.to_string()))?,
        provenance: vec![options.provenance_id.clone()],
        extensions: Vec::new(),
    });
    affects.push(CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
        kind: CsmiAffectedFactFamilyKind::FactFamily,
        family: "type-value-semantics".to_owned(),
        scope,
    }));
    Ok(())
}

fn type_ref_symbol(
    target: &TypeRef,
    symbol_by_bifrost_id: &HashMap<String, String>,
) -> Result<String, CsmiExportError> {
    let TypeRef::Declared {
        id,
        arguments,
        nullable,
    } = target
    else {
        return Err(CsmiExportError::Unsupported {
            path: "members.implicitOperation.target".to_owned(),
            semantic: "conversion target must be an exact declared type".to_owned(),
        });
    };
    if !arguments.is_empty() || *nullable {
        return Err(CsmiExportError::Unsupported {
            path: "members.implicitOperation.target".to_owned(),
            semantic: "conversion target arguments/nullability are not representable as a local type handle".to_owned(),
        });
    }
    symbol_by_bifrost_id
        .get(id)
        .cloned()
        .ok_or_else(|| CsmiExportError::MissingDeclaration {
            path: "members.implicitOperation.target".to_owned(),
            target: id.clone(),
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
