//! Translation from Bifrost semantic-model packs to CSMI 0.2 documents.

use crate::analyzer::semantic_model::ConditionalTypeRefinementsPayload;

use crate::analyzer::semantic_model::DeferredYieldsPayload;

use crate::analyzer::semantic_model::csmi::canonical::canonical_json;

use crate::analyzer::semantic_model::csmi::canonical::sha256_hex;

use crate::analyzer::semantic_model::csmi::cpp::cpp_symbol_definition;

use crate::analyzer::semantic_model::csmi::identity::callable_disambiguator;

use crate::analyzer::semantic_model::csmi::identity::go_anonymous_callable_symbol;

use crate::analyzer::semantic_model::csmi::identity::go_member_symbol;

use crate::analyzer::semantic_model::csmi::identity::go_type_symbol;

use crate::analyzer::semantic_model::csmi::identity::member_symbol_id;

use crate::analyzer::semantic_model::csmi::identity::type_expression;

use crate::analyzer::semantic_model::csmi::identity::type_symbol;

use crate::analyzer::semantic_model::csmi::identity::type_symbol_id;

use crate::analyzer::semantic_model::csmi::model::*;

use crate::analyzer::semantic_model::csmi::pack::CsmiLogicalPack;

use crate::analyzer::semantic_model::csmi::pack::InMemoryCsmiResourceResolver;

use crate::analyzer::semantic_model::csmi::validate::CsmiVocabularySupport;

use crate::analyzer::semantic_model::csmi::validate::validate_csmi_pack;

use crate::analyzer::semantic_model::AuthoredSemanticModelPack;

use crate::analyzer::semantic_model::CallableValuesFamily;

use crate::analyzer::semantic_model::CallableValuesPayload;

use crate::analyzer::semantic_model::CollectionFlowsPayload;

use crate::analyzer::semantic_model::CompiledPayload;

use crate::analyzer::semantic_model::CompiledSemanticModelPack;

use crate::analyzer::semantic_model::CompiledShard;

use crate::analyzer::semantic_model::CompiledSummaryExitKind;

use crate::analyzer::semantic_model::CompiledSummaryInput;

use crate::analyzer::semantic_model::CompiledSummaryMoveInvalidation;

use crate::analyzer::semantic_model::CompiledSummaryOutput;

use crate::analyzer::semantic_model::CompiledSummaryValuePreservation;

use crate::analyzer::semantic_model::CompiledSummaryValueTransferKind;

use crate::analyzer::semantic_model::CompiledSummaryValueTransferOperation;

use crate::analyzer::semantic_model::CompilerOptions;

use crate::analyzer::semantic_model::Completeness;

use crate::analyzer::semantic_model::CppCanonicalType;

use crate::analyzer::semantic_model::CppLanguage;

use crate::analyzer::semantic_model::CppPortabilityEvidence;

use crate::analyzer::semantic_model::CppPortableSymbolKey;

use crate::analyzer::semantic_model::CppReferenceKind;

use crate::analyzer::semantic_model::CppSpecialMemberOperation;

use crate::analyzer::semantic_model::CppTypeQualifier;

use crate::analyzer::semantic_model::DecodeLimits;

use crate::analyzer::semantic_model::ImplicitOperation;

use crate::analyzer::semantic_model::MemberFact;

use crate::analyzer::semantic_model::MemberKind;

use crate::analyzer::semantic_model::ParameterRole;

use crate::analyzer::semantic_model::RuntimeValuesPayload;

use crate::analyzer::semantic_model::TypeCopySemantics;

use crate::analyzer::semantic_model::TypeFact;

use crate::analyzer::semantic_model::TypeKind;

use crate::analyzer::semantic_model::TypeMoveSemantics;

use crate::analyzer::semantic_model::TypeRef;

use crate::analyzer::semantic_model::compile_pack;

use crate::analyzer::semantic_model::decode_shard;
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

fn reject_unmapped_callable_values(shards: &[CompiledShard]) -> Result<(), CsmiExportError> {
    if let Some(shard) = shards
        .iter()
        .find(|shard| shard.callable_values().is_some())
    {
        return Err(CsmiExportError::Unsupported {
            path: format!("shards.{}.callable_values", shard.shard_id()),
            semantic:
                "native callable-values transport is retained but has no CSMI export mapping yet"
                    .to_owned(),
        });
    }
    Ok(())
}

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
    if decoded
        .iter()
        .any(|shard| shard.runtime_contracts().is_some())
    {
        return Err(CsmiExportError::Unsupported {
            path: "shards.runtime_contracts".to_owned(),
            semantic: "portable runtime-contracts require export_runtime_contracts_csmi_pack so the retained CSMI document envelope and its PURL/VERS applicability are preserved".to_owned(),
        });
    }
    if pack.manifest.language == "python" && decoded.iter().any(|shard| matches!(shard.payload(), CompiledPayload::DeclarationFacts { types, members, .. } if !types.is_empty() || !members.is_empty())) {
        let fresh_manifest = crate::analyzer::semantic_model::decode_manifest(
            &pack.manifest_bytes,
            &DecodeLimits::default(),
        )
        .map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
        if fresh_manifest != pack.manifest
            || pack.shards.len() != pack.manifest.shards.len()
            || pack.manifest.shards.iter().any(|descriptor| {
                pack.shards
                    .iter()
                    .filter(|artifact| artifact.descriptor == *descriptor)
                    .count()
                    != 1
            })
        {
            return Err(CsmiExportError::Canonical(
                "Python compiled pack inventory disagrees with its canonical manifest".to_owned(),
            ));
        }
        let authored = crate::analyzer::semantic_model::artifact::authored_pack_from_decoded_shards(
            &pack.manifest,
            &decoded,
        );
        let mut diagnostics = crate::analyzer::semantic_model::csmi::python::validate_profile_evidence(&authored);
        diagnostics.extend(crate::analyzer::semantic_model::csmi::python::validate_native_identities(&authored));
        if !diagnostics.is_empty() {
            return Err(CsmiExportError::Canonical(format!(
                "Python compiled pack has inconsistent full-pack evidence: {diagnostics:?}"
            )));
        }
        let (semantic, provenance) = crate::analyzer::semantic_model::csmi::python::export_document(&pack.manifest, &decoded, artifact, options)?;
        return logical_pack(semantic, provenance, &pack.manifest.license, options);
    }
    let (semantic, provenance) = export_semantic_document(
        &pack.manifest.language,
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

/// Export a compiled portable runtime-contract pack without requiring an
/// artifact digest. Runtime-values 0.2 is intentionally portable: its target
/// range and complete semantic-document envelope are the applicability claim.
/// The native companion retains that envelope so this operation does not
/// project a PURL/VERS range into a language wildcard or synthesize bytes.
pub fn export_runtime_contracts_csmi_pack(
    pack: &CompiledSemanticModelPack,
    options: &CsmiExportOptions,
) -> Result<CsmiLogicalPack, CsmiExportReport> {
    let decoded = pack
        .shards
        .iter()
        .map(|shard| decode_shard(&shard.descriptor, &shard.bytes, &DecodeLimits::default()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
    reject_unmapped_callable_values(&decoded)?;
    let mut retained: Option<serde_json::Value> = None;
    for shard in &decoded {
        let Some(carrier) = shard.runtime_contracts() else {
            if shard.runtime_values().is_some()
                || shard.collection_flows().is_some()
                || shard.deferred_yields().is_some()
                || shard.conditional_type_refinements().is_some()
                || shard.payload().record_count() > 0
            {
                return Err(CsmiExportError::Unsupported {
                    path: format!("shards.{}", shard.shard_id()),
                    semantic: "portable runtime-contract export cannot drop non-runtime-contract shard facts".to_owned(),
                });
            }
            continue;
        };
        if shard.runtime_values().is_some()
            || shard.collection_flows().is_some()
            || shard.deferred_yields().is_some()
            || shard.conditional_type_refinements().is_some()
            || shard.cpp_portability().is_some()
            || shard.payload().record_count() > 0
        {
            return Err(CsmiExportError::Unsupported {
                path: format!("shards.{}", shard.shard_id()),
                semantic: "portable runtime-contract export cannot drop extra facts carried by a runtime-contract shard".to_owned(),
            });
        }
        let Some(envelope) = &carrier.envelope else {
            return Err(CsmiExportError::Unsupported {
                path: format!("shards.{}.runtime_contracts", shard.shard_id()),
                semantic:
                    "runtime-contracts export requires the retained CSMI semantic-document envelope"
                        .to_owned(),
            });
        };
        if !crate::analyzer::semantic_model::runtime_contract_envelope_matches(
            &carrier.payload,
            envelope,
        )
        .map_err(|error| CsmiExportError::Canonical(error.to_string()))?
        {
            return Err(CsmiExportError::Canonical(
                "native runtime-contract payload conflicts with its retained CSMI envelope"
                    .to_owned(),
            ));
        }
        if let Some(previous) = &retained {
            let previous =
                crate::analyzer::semantic_model::csmi::canonical::canonical_json_value(previous)
                    .map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
            let current =
                crate::analyzer::semantic_model::csmi::canonical::canonical_json_value(envelope)
                    .map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
            if previous != current {
                return Err(CsmiExportError::Canonical(
                    "runtime-contract shards retain different CSMI envelopes".to_owned(),
                ));
            }
        } else {
            retained = Some(envelope.clone());
        }
    }
    let Some(envelope) = retained else {
        return Err(CsmiExportError::Unsupported {
            path: "shards.runtime_contracts".to_owned(),
            semantic: "compiled pack has no runtime-contracts payload".to_owned(),
        });
    };
    let document: CsmiSemanticDocument = serde_json::from_value(envelope)
        .map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
    let provenance = document
        .provenance_records
        .first()
        .cloned()
        .ok_or_else(|| {
            CsmiExportError::Canonical("retained CSMI document has no provenance record".to_owned())
        })?;
    logical_pack(document, provenance, &pack.manifest.license, options)
}

/// Author and export a portable runtime-contract pack while preserving its
/// retained CSMI semantic-document envelope.
fn compile_authored_pack(
    pack: &AuthoredSemanticModelPack,
) -> Result<CompiledSemanticModelPack, CsmiExportError> {
    compile_pack(pack, &CompilerOptions::default()).map_err(|diagnostics| {
        CsmiExportError::Canonical(format!("Bifrost pack did not compile: {diagnostics:?}"))
    })
}

pub fn export_authored_runtime_contracts_csmi_pack(
    pack: &AuthoredSemanticModelPack,
    options: &CsmiExportOptions,
) -> Result<CsmiLogicalPack, CsmiExportReport> {
    let compiled = compile_authored_pack(pack)?;
    export_runtime_contracts_csmi_pack(&compiled, options)
}

pub fn export_authored_csmi_pack(
    pack: &AuthoredSemanticModelPack,
    artifact: &CsmiArtifactEvidence,
    options: &CsmiExportOptions,
) -> Result<CsmiLogicalPack, CsmiExportReport> {
    let compiled = compile_authored_pack(pack)?;
    export_csmi_pack(&compiled, artifact, options)
}

#[allow(clippy::too_many_arguments)]
fn export_semantic_document<'a>(
    language: &str,
    producer: &crate::analyzer::semantic_model::Producer,
    pack_provenance: &crate::analyzer::semantic_model::Provenance,
    pack_completeness: Completeness,
    cpp_portability: Option<&CppPortabilityEvidence>,
    shards: impl Iterator<Item = &'a CompiledShard>,
    artifact: &CsmiArtifactEvidence,
    options: &CsmiExportOptions,
) -> Result<(CsmiSemanticDocument, CsmiProvenanceRecord), CsmiExportError> {
    let shards: Vec<&CompiledShard> = shards.collect();
    let has_runtime_values = shards.iter().any(|shard| shard.runtime_values().is_some());
    let has_collection_flows = shards
        .iter()
        .any(|shard| shard.collection_flows().is_some());
    let has_deferred_yields = shards.iter().any(|shard| shard.deferred_yields().is_some());
    if cpp_portability.is_some() {
        validate_exact_artifact_evidence(artifact)?;
    } else if language == "go" {
        validate_go_artifact_evidence(artifact)?;
    } else if has_runtime_values || has_collection_flows || has_deferred_yields {
        // Runtime profiles select exact versioned runtime distributions, which
        // may use a non-Maven PURL such as pkg:generic. Keep that evidence
        // exact without forcing runtime artifacts through the declaration-pack
        // Maven policy.
        validate_exact_artifact_evidence(artifact)?;
    } else {
        validate_maven_evidence(artifact)?;
    }
    let artifact_selector = csmi_artifact_selector(artifact);
    let mut types = Vec::new();
    let mut members = Vec::new();
    let mut relations = Vec::new();
    let mut summaries = Vec::new();
    let mut type_names_by_id = HashMap::new();
    let mut member_facts = Vec::new();
    let mut summary_shards = Vec::new();
    for shard in &shards {
        match shard.payload() {
            CompiledPayload::DeclarationFacts {
                types: shard_types,
                members: shard_members,
                relations: shard_relations,
                assembly_identity,
                type_forwards,
            } => {
                if assembly_identity.is_some() || !type_forwards.is_empty() {
                    return Err(CsmiExportError::Unsupported {
                        path: "declaration_facts".to_owned(),
                        semantic:
                            "assembly identities and type forwards have no supported CSMI contract"
                                .to_owned(),
                    });
                }
                if let Some(fact) = shard_types
                    .iter()
                    .find(|fact| fact.callable_surface_complete)
                {
                    return Err(CsmiExportError::Unsupported {
                        path: format!("types.{}.callable_surface_complete", fact.id),
                        semantic:
                            "declared callable-surface coverage has no supported CSMI contract"
                                .to_owned(),
                    });
                }
                if let Some(fact) = shard_members
                    .iter()
                    .find(|fact| fact.non_overridable.is_some())
                {
                    return Err(CsmiExportError::Unsupported {
                        path: format!("members.{}.non_overridable", fact.id),
                        semantic: "selected declaration non-overridability has no CSMI contract"
                            .to_owned(),
                    });
                }
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
    let go_types_by_id: HashMap<String, &TypeFact> = types
        .iter()
        .map(|fact| (fact.id.clone(), fact.as_ref()))
        .collect();
    #[allow(clippy::too_many_arguments)]
    fn ensure_type(
        name: &str,
        native_id: &str,
        cpp_keys: &HashMap<String, &CppPortableSymbolKey>,
        go_types_by_id: &HashMap<String, &TypeFact>,
        language: &str,
        artifact_selector: &CsmiArtifactSelector,
        symbols: &mut Vec<CsmiSymbolDefinition>,
        seen_symbols: &mut HashSet<String>,
    ) -> Result<String, CsmiExportError> {
        let symbol = if language == "go" && cpp_keys.is_empty() {
            let fact = go_types_by_id.get(native_id).ok_or_else(|| {
                CsmiExportError::Unsupported {
                    path: format!("types.{native_id}"),
                    semantic: "Go source identity requires the exact native type fact and artifact locator".to_owned(),
                }
            })?;
            go_type_symbol(fact, artifact_selector).map_err(|semantic| {
                CsmiExportError::Unsupported {
                    path: format!("types.{native_id}.locator"),
                    semantic,
                }
            })?
        } else if cpp_keys.is_empty() {
            type_symbol(name).map_err(|error| CsmiExportError::Identity(error.to_string()))?
        } else {
            let id = cpp_local_id(cpp_keys.get(native_id).copied().ok_or_else(|| {
                CsmiExportError::MissingDeclaration {
                    path: "cpp_portability.symbols".to_owned(),
                    target: native_id.to_owned(),
                }
            })?)?;
            cpp_symbol_definition(
                &id,
                cpp_keys.get(native_id).copied().ok_or_else(|| {
                    CsmiExportError::MissingDeclaration {
                        path: "cpp_portability.symbols".to_owned(),
                        target: native_id.to_owned(),
                    }
                })?,
            )
        };
        let id = if cpp_keys.is_empty() && language == "go" {
            symbol.id.clone()
        } else if cpp_keys.is_empty() {
            type_symbol_id(name).map_err(|error| CsmiExportError::Identity(error.to_string()))?
        } else {
            symbol.id.clone()
        };
        if seen_symbols.insert(id.clone()) {
            symbols.push(symbol);
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
            &go_types_by_id,
            language,
            &artifact_selector,
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
        let go_alias_target = (language == "go" && fact.type_kind == TypeKind::TypeAlias)
            .then_some({
                CsmiTypeExpression::Unknown(CsmiUnknownType {
                    kind: CsmiUnknownTypeKind::Unknown,
                })
            });
        let alias_target = cpp_alias_target.or(go_alias_target);
        declarations.push(CsmiDeclaration {
            symbol: id,
            category: if language == "go" && fact.type_kind == TypeKind::Module {
                CsmiDeclarationCategory::Namespace
            } else if alias_target.is_some() {
                CsmiDeclarationCategory::TypeAlias
            } else {
                CsmiDeclarationCategory::Type
            },
            owner: None,
            generic_parameters: Vec::new(),
            callable: None,
            value_type: None,
            proxied_type: None,
            alias_target,
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
            &go_types_by_id,
            language,
            &artifact_selector,
            &mut symbols,
            &mut seen_symbols,
        )?;
        let value_member = matches!(
            fact.member_kind,
            MemberKind::Field | MemberKind::Property | MemberKind::Constant | MemberKind::Static
        );
        let go_symbol = if language == "go" && cpp_keys.is_empty() {
            let owner_fact =
                go_types_by_id
                    .get(&fact.owner)
                    .ok_or_else(|| CsmiExportError::Unsupported {
                        path: format!("members.{}.owner", fact.id),
                        semantic: "Go source identity requires the exact native owner type fact"
                            .to_owned(),
                    })?;
            Some(
                go_member_symbol(fact, owner_fact, &artifact_selector, value_member).map_err(
                    |semantic| CsmiExportError::Unsupported {
                        path: format!("members.{}.locator", fact.id),
                        semantic,
                    },
                )?,
            )
        } else {
            None
        };
        let id = if let Some(symbol) = &go_symbol {
            symbol.id.clone()
        } else if cpp_keys.is_empty() {
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
            symbols.push(if let Some(symbol) = go_symbol {
                symbol
            } else if cpp_keys.is_empty() {
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
        let category = if language == "go" && value_member {
            CsmiDeclarationCategory::Value
        } else {
            CsmiDeclarationCategory::Callable
        };
        let callable = if category == CsmiDeclarationCategory::Callable {
            Some(if language == "go" {
                go_member_callable_shape(fact, &owner_id)?
            } else {
                callable_shape(fact, &|value| {
                    core_type_expression(
                        value,
                        &type_names_by_id,
                        &symbol_by_bifrost_id,
                        !cpp_keys.is_empty(),
                    )
                })?
            })
        } else {
            None
        };
        declarations.push(CsmiDeclaration {
            symbol: id,
            category,
            owner: Some(owner_id.clone()),
            generic_parameters: Vec::new(),
            callable,
            value_type: None,
            proxied_type: None,
            alias_target: None,
            provenance: vec![options.provenance_id.clone()],
            extensions: Vec::new(),
        });
    }
    for shard in &shards {
        let Some(callable_values) = shard.callable_values() else {
            continue;
        };
        if language != "go" && !callable_values.anonymous_callables.is_empty() {
            return Err(CsmiExportError::Unsupported {
                path: format!(
                    "shards.{}.callable_values.anonymous_callables",
                    shard.shard_id()
                ),
                semantic:
                    "anonymous callable identities currently have an exact Go-source mapping only"
                        .to_owned(),
            });
        }
        for identity in &callable_values.anonymous_callables {
            let (symbol, shape) = go_anonymous_callable_symbol(identity, &artifact_selector)
                .map_err(|semantic| CsmiExportError::Unsupported {
                    path: format!(
                        "shards.{}.callable_values.anonymous_callables.{}",
                        shard.shard_id(),
                        identity.id
                    ),
                    semantic,
                })?;
            if symbol_by_bifrost_id.contains_key(&identity.id) {
                return Err(CsmiExportError::Identity(format!(
                    "Go anonymous callable ID {} collides with another declaration ID",
                    identity.id
                )));
            }
            if seen_symbols.insert(symbol.id.clone()) {
                symbols.push(symbol.clone());
                declarations.push(CsmiDeclaration {
                    symbol: symbol.id.clone(),
                    category: CsmiDeclarationCategory::Callable,
                    owner: None,
                    generic_parameters: Vec::new(),
                    callable: Some(shape),
                    value_type: None,
                    proxied_type: None,
                    alias_target: None,
                    provenance: vec![options.provenance_id.clone()],
                    extensions: Vec::new(),
                });
            }
            if symbol_by_bifrost_id
                .insert(identity.id.clone(), symbol.id.clone())
                .is_some_and(|previous| previous != symbol.id)
            {
                return Err(CsmiExportError::Identity(format!(
                    "Go anonymous callable ID {} has inconsistent source identities",
                    identity.id
                )));
            }
        }
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
    let mut runtime_values_affects = Vec::new();
    let mut runtime_values_completeness = Vec::new();
    let mut collection_flow_affects = Vec::new();
    let mut collection_flow_completeness = Vec::new();
    let mut conditional_type_affects = Vec::new();
    let mut conditional_type_completeness = Vec::new();
    let mut deferred_yield_affects = Vec::new();
    let mut deferred_yield_completeness = Vec::new();
    let mut callable_values_affects = Vec::new();
    let mut callable_values_completeness = Vec::new();
    let callable_shape_completeness: HashMap<String, bool> = member_facts
        .iter()
        .map(|member| (member.id.clone(), member.callable_family_complete))
        .collect();
    for shard in &shards {
        let Some(runtime_values) = shard.runtime_values() else {
            continue;
        };
        export_runtime_values(
            runtime_values,
            options,
            &mut extension_facts,
            &mut runtime_values_affects,
            &mut runtime_values_completeness,
        )?;
    }
    for shard in &shards {
        if let Some(refinements) = shard.conditional_type_refinements() {
            export_conditional_type_refinements(
                refinements,
                options,
                &symbol_by_bifrost_id,
                &callable_shape_completeness,
                &mut extension_facts,
                &mut conditional_type_affects,
                &mut conditional_type_completeness,
            )?;
        }
    }
    for shard in &shards {
        let Some(deferred_yields) = shard.deferred_yields() else {
            continue;
        };
        export_deferred_yields(
            deferred_yields,
            options,
            &symbol_by_bifrost_id,
            &callable_shape_completeness,
            &mut extension_facts,
            &mut deferred_yield_affects,
            &mut deferred_yield_completeness,
        )?;
    }
    for shard in &shards {
        let Some(collection_flows) = shard.collection_flows() else {
            continue;
        };
        export_collection_flows(
            collection_flows,
            options,
            &mut extension_facts,
            &mut collection_flow_affects,
            &mut collection_flow_completeness,
        )?;
    }
    for shard in &shards {
        let Some(callable_values) = shard.callable_values() else {
            continue;
        };
        export_callable_values(
            language,
            shard.shard_id(),
            callable_values,
            options,
            &symbol_by_bifrost_id,
            &mut extension_facts,
            &mut callable_values_affects,
            &mut callable_values_completeness,
        )?;
    }
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
            || summary.no_concurrency_effects
            || !summary.declared_effects.is_empty()
            || summary.preconditions.is_some()
            || !summary.result_contracts.is_empty()
            || !summary.result_use_obligations.is_empty()
            || !summary.conditional_result_refinements.is_empty()
            || !summary.conditional_indirect_writes.is_empty()
            || !summary.normal_return_refinements.is_empty()
            || !summary.normal_return_type_refinements.is_empty()
            || summary.class_decorator_identity.is_some()
        {
            return Err(CsmiExportError::Unsupported {
                path: format!("procedureSummaries.{}", summary.id),
                semantic: "effects, result contracts, normal-return type refinements, and class decorator identity are not representable in CSMI core".to_owned(),
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
    let selector = artifact_selector.clone();
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
        if fact.vocabulary != CSMI_VALUE_TRANSFER_PROFILE_ID
            || fact.version != CSMI_VALUE_TRANSFER_PROFILE_VERSION
        {
            continue;
        }
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
    completeness_statements.extend(runtime_values_completeness);
    completeness_statements.extend(collection_flow_completeness);
    completeness_statements.extend(deferred_yield_completeness);
    completeness_statements.extend(conditional_type_completeness);
    completeness_statements.extend(callable_values_completeness);
    let declaration_status = match pack_completeness {
        Completeness::Complete => CsmiCoverageStatus::Complete,
        Completeness::Partial => CsmiCoverageStatus::Partial,
    };
    completeness_statements.push(CsmiCompletenessStatement {
        vocabulary: None,
        version: None,
        family: "declaration-records".to_owned(),
        scope: json!({
            "scheme": if cpp_keys.is_empty() && language == "go" {
                super::identity::GO_SOURCE_IDENTITY_SCHEME
            } else if cpp_keys.is_empty() {
                super::identity::JVM_IDENTITY_SCHEME
            } else {
                CSMI_CPP_DECLARATION_IDENTITY_SCHEME
            },
            "schemeVersion": if cpp_keys.is_empty() && language == "go" {
                super::identity::GO_SOURCE_IDENTITY_VERSION
            } else if cpp_keys.is_empty() {
                super::identity::JVM_IDENTITY_VERSION
            } else {
                CSMI_CPP_DECLARATION_IDENTITY_SCHEME_VERSION
            }
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
                    resolution_context: CsmiCppResolutionContext::try_from(
                        &alias.resolution_context,
                    )?,
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
    let mut provenance_records = vec![record.clone()];
    let mut retained_runtime_provenance = extension_facts
        .iter()
        .filter(|fact| fact.vocabulary == CSMI_RUNTIME_VALUES_PROFILE_ID)
        .flat_map(|fact| fact.provenance.iter())
        .chain(
            completeness_statements
                .iter()
                .filter(|statement| {
                    statement.vocabulary.as_deref() == Some(CSMI_RUNTIME_VALUES_PROFILE_ID)
                })
                .flat_map(|statement| statement.provenance.iter()),
        )
        .filter(|id| id.as_str() != options.provenance_id)
        .cloned()
        .collect::<Vec<_>>();
    retained_runtime_provenance.extend(
        extension_facts
            .iter()
            .filter(|fact| {
                matches!(
                    fact.vocabulary.as_str(),
                    CSMI_COLLECTION_FLOW_PROFILE_ID | CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID
                )
            })
            .flat_map(|fact| fact.provenance.iter())
            .chain(
                completeness_statements
                    .iter()
                    .filter(|statement| {
                        matches!(
                            statement.vocabulary.as_deref(),
                            Some(
                                CSMI_COLLECTION_FLOW_PROFILE_ID
                                    | CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID
                            )
                        )
                    })
                    .flat_map(|statement| statement.provenance.iter()),
            )
            .filter(|id| id.as_str() != options.provenance_id)
            .cloned(),
    );
    retained_runtime_provenance.sort();
    retained_runtime_provenance.dedup();
    provenance_records.extend(retained_runtime_provenance.into_iter().map(|id| {
        let mut retained = record.clone();
        retained.id = id;
        retained.generation_method = CsmiGenerationMethod::Composition;
        retained
    }));
    let document = CsmiSemanticDocument {
        document_type: "semantic-document".to_owned(),
        schema: CSMI_SCHEMA_URI.to_owned(),
        semantic_model_version: CSMI_SEMANTIC_MODEL_VERSION.to_owned(),
        serialization_version: CSMI_SERIALIZATION_VERSION.to_owned(),
        provenance_records,
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
                if !runtime_values_affects.is_empty() {
                    uses.push(CsmiVocabularyUse {
                        identifier: CSMI_RUNTIME_VALUES_PROFILE_ID.to_owned(),
                        version: CSMI_RUNTIME_VALUES_PROFILE_VERSION.to_owned(),
                        schema: CSMI_RUNTIME_VALUES_PROFILE_SCHEMA.to_owned(),
                        requirement: CsmiVocabularyRequirement::Required,
                        affects: runtime_values_affects,
                    });
                }
                if !collection_flow_affects.is_empty() {
                    uses.push(CsmiVocabularyUse {
                        identifier: CSMI_COLLECTION_FLOW_PROFILE_ID.to_owned(),
                        version: CSMI_COLLECTION_FLOW_PROFILE_VERSION.to_owned(),
                        schema: CSMI_COLLECTION_FLOW_PROFILE_SCHEMA.to_owned(),
                        requirement: CsmiVocabularyRequirement::Required,
                        affects: collection_flow_affects,
                    });
                }
                if !conditional_type_affects.is_empty() {
                    uses.push(CsmiVocabularyUse {
                        identifier: CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID.to_owned(),
                        version: CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION.to_owned(),
                        schema: CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_SCHEMA.to_owned(),
                        requirement: CsmiVocabularyRequirement::Required,
                        affects: conditional_type_affects,
                    });
                }
                if !deferred_yield_affects.is_empty() {
                    uses.push(CsmiVocabularyUse {
                        identifier: CSMI_DEFERRED_YIELD_PROFILE_ID.to_owned(),
                        version: CSMI_DEFERRED_YIELD_PROFILE_VERSION.to_owned(),
                        schema: CSMI_DEFERRED_YIELD_PROFILE_SCHEMA.to_owned(),
                        requirement: CsmiVocabularyRequirement::Required,
                        affects: deferred_yield_affects,
                    });
                }
                if !callable_values_affects.is_empty() {
                    uses.push(CsmiVocabularyUse {
                        identifier: CSMI_CALLABLE_VALUES_PROFILE_ID.to_owned(),
                        version: CSMI_CALLABLE_VALUES_PROFILE_VERSION.to_owned(),
                        schema: CSMI_CALLABLE_VALUES_PROFILE_SCHEMA.to_owned(),
                        requirement: CsmiVocabularyRequirement::Required,
                        affects: callable_values_affects,
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
    mut document: CsmiSemanticDocument,
    provenance: CsmiProvenanceRecord,
    license: &str,
    options: &CsmiExportOptions,
) -> Result<CsmiLogicalPack, CsmiExportError> {
    // Reconstructed documents from native export have no source default, so
    // keep the historical exporter identity for them. A retained portable
    // envelope already has an authoritative default provenance reference;
    // preserving it is required for a lossless runtime-contract round trip.
    if document.default_provenance.is_none() {
        document.default_provenance = Some(options.provenance_id.clone());
    }
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
        CSMI_PYTHON_PROFILE_ID,
        CSMI_PYTHON_PROFILE_VERSION,
        CSMI_PYTHON_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_TRANSFER_PARTITIONS_PROFILE_ID,
        CSMI_TRANSFER_PARTITIONS_PROFILE_VERSION,
        CSMI_TRANSFER_PARTITIONS_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_VALUE_TRANSFER_PROFILE_ID,
        CSMI_VALUE_TRANSFER_PROFILE_VERSION,
        CSMI_VALUE_TRANSFER_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_RUNTIME_VALUES_PROFILE_ID,
        CSMI_RUNTIME_VALUES_PROFILE_VERSION,
        CSMI_RUNTIME_VALUES_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_RUNTIME_VALUES_PROFILE_ID,
        CSMI_RUNTIME_CONTRACTS_PROFILE_VERSION,
        CSMI_RUNTIME_CONTRACTS_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_COLLECTION_FLOW_PROFILE_ID,
        CSMI_COLLECTION_FLOW_PROFILE_VERSION,
        CSMI_COLLECTION_FLOW_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID,
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION,
        CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_DEFERRED_YIELD_PROFILE_ID,
        CSMI_DEFERRED_YIELD_PROFILE_VERSION,
        CSMI_DEFERRED_YIELD_PROFILE_SCHEMA,
    );
    support.add(
        CSMI_CALLABLE_VALUES_PROFILE_ID,
        CSMI_CALLABLE_VALUES_PROFILE_VERSION,
        CSMI_CALLABLE_VALUES_PROFILE_SCHEMA,
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
    let only_uninterpretable_callable_values = validation.valid()
        && !validation.interpretable
        && validation
            .profiles
            .iter()
            .any(|profile| !profile.semantically_supported)
        && validation.profiles.iter().all(|profile| {
            profile.semantically_supported
                || (profile.identifier == CSMI_CALLABLE_VALUES_PROFILE_ID
                    && profile.version == CSMI_CALLABLE_VALUES_PROFILE_VERSION
                    && profile.schema == CSMI_CALLABLE_VALUES_PROFILE_SCHEMA)
        });
    if !validation.usable() && !only_uninterpretable_callable_values {
        return Err(CsmiExportError::Canonical(format!(
            "exported CSMI pack failed self-validation: {:?}",
            validation.diagnostics
        )));
    }
    Ok(pack)
}

#[allow(clippy::too_many_arguments)]
fn export_callable_values(
    language: &str,
    shard_id: &str,
    native: &CallableValuesPayload,
    options: &CsmiExportOptions,
    symbol_by_bifrost_id: &HashMap<String, String>,
    facts: &mut Vec<CsmiExtensionFact>,
    affects: &mut Vec<CsmiAffectedUnit>,
    completeness: &mut Vec<CsmiCompletenessStatement>,
) -> Result<(), CsmiExportError> {
    if language != "go" && (!native.facts.is_empty() || !native.coverage.is_empty()) {
        return Err(CsmiExportError::Unsupported {
            path: format!("shards.{shard_id}.callable_values"),
            semantic: "callable-values native identity remapping is currently defined for exact Go source declarations only".to_owned(),
        });
    }
    let remap = |native_id: &str| {
        symbol_by_bifrost_id
            .get(native_id)
            .cloned()
            .ok_or_else(|| native_id.to_owned())
    };
    let mut add_affect = |family: &str, scope: serde_json::Value| {
        let affect = CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
            kind: CsmiAffectedFactFamilyKind::FactFamily,
            family: family.to_owned(),
            scope,
        });
        if !affects.contains(&affect) {
            affects.push(affect);
        }
    };
    for (index, native_fact) in native.facts.iter().enumerate() {
        let mut payload = native_fact.payload.clone();
        if let Err(error) = payload.remap_symbols(remap) {
            match error {
                CsmiCallableValuesRemapError::Symbol(native_id) => {
                    return Err(CsmiExportError::Unsupported {
                        path: format!("shards.{shard_id}.callable_values.facts[{index}]"),
                        semantic: format!(
                            "Go callable-values reference {native_id} has no exact native declaration identity mapping"
                        ),
                    });
                }
                CsmiCallableValuesRemapError::UnsupportedProjection(projection) => {
                    return Err(CsmiExportError::Unsupported {
                        path: format!("shards.{shard_id}.callable_values.facts[{index}].payload"),
                        semantic: format!(
                            "Go callable-values projection is unsupported by the pinned structured-locations mapping: {projection:?}"
                        ),
                    });
                }
            }
        }
        let (family, callable) = match &payload {
            CsmiCallableValuesPayload::ReturnedCallable { callable, .. } => (
                CSMI_CALLABLE_VALUES_RETURNED_CALLABLES_FAMILY,
                callable.as_str(),
            ),
            CsmiCallableValuesPayload::CallbackInvocation { callable, .. } => (
                CSMI_CALLABLE_VALUES_CALLBACK_INVOCATIONS_FAMILY,
                callable.as_str(),
            ),
        };
        let scope = json!({"callable": callable});
        facts.push(CsmiExtensionFact {
            vocabulary: CSMI_CALLABLE_VALUES_PROFILE_ID.to_owned(),
            version: CSMI_CALLABLE_VALUES_PROFILE_VERSION.to_owned(),
            family: family.to_owned(),
            scope: scope.clone(),
            payload: serde_json::to_value(payload)
                .map_err(|error| CsmiExportError::Canonical(error.to_string()))?,
            provenance: vec![options.provenance_id.clone()],
            extensions: Vec::new(),
        });
        add_affect(family, scope);
    }
    for (index, native_coverage) in native.coverage.iter().enumerate() {
        let callable = symbol_by_bifrost_id
            .get(&native_coverage.callable)
            .cloned()
            .ok_or_else(|| CsmiExportError::Unsupported {
                path: format!(
                    "shards.{shard_id}.callable_values.coverage[{index}].callable"
                ),
                semantic: format!(
                    "Go callable-values coverage target {} has no exact native declaration identity mapping",
                    native_coverage.callable
                ),
            })?;
        let family = match native_coverage.family {
            CallableValuesFamily::ReturnedCallables => {
                CSMI_CALLABLE_VALUES_RETURNED_CALLABLES_FAMILY
            }
            CallableValuesFamily::CallbackInvocations => {
                CSMI_CALLABLE_VALUES_CALLBACK_INVOCATIONS_FAMILY
            }
        };
        let scope = json!({"callable": callable});
        completeness.push(CsmiCompletenessStatement {
            vocabulary: Some(CSMI_CALLABLE_VALUES_PROFILE_ID.to_owned()),
            version: Some(CSMI_CALLABLE_VALUES_PROFILE_VERSION.to_owned()),
            family: family.to_owned(),
            scope: scope.clone(),
            status: native_coverage.status,
            limitations: native_coverage.limitations.clone(),
            provenance: vec![options.provenance_id.clone()],
            extensions: Vec::new(),
        });
        add_affect(family, scope);
    }
    Ok(())
}

fn export_collection_flows(
    collection_flows: &CollectionFlowsPayload,
    options: &CsmiExportOptions,
    facts: &mut Vec<CsmiExtensionFact>,
    affects: &mut Vec<CsmiAffectedUnit>,
    completeness: &mut Vec<CsmiCompletenessStatement>,
) -> Result<(), CsmiExportError> {
    for flow in &collection_flows.flows {
        let scope = json!({"callable": flow.callable});
        if flow.payload.callable != flow.callable {
            return Err(CsmiExportError::Identity(format!(
                "collection-flow payload callable {} does not match native scope {}",
                flow.payload.callable, flow.callable
            )));
        }
        facts.push(CsmiExtensionFact {
            vocabulary: CSMI_COLLECTION_FLOW_PROFILE_ID.to_owned(),
            version: CSMI_COLLECTION_FLOW_PROFILE_VERSION.to_owned(),
            family: "collection-flows".to_owned(),
            scope: scope.clone(),
            payload: serde_json::to_value(&flow.payload)
                .map_err(|error| CsmiExportError::Canonical(error.to_string()))?,
            provenance: if flow.provenance.is_empty() {
                vec![options.provenance_id.clone()]
            } else {
                flow.provenance.clone()
            },
            extensions: Vec::new(),
        });
        affects.push(CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
            kind: CsmiAffectedFactFamilyKind::FactFamily,
            family: "collection-flows".to_owned(),
            scope: scope.clone(),
        }));
        let (status, limitations) = match flow.coverage {
            Some(Completeness::Complete) => (CsmiCoverageStatus::Complete, Vec::new()),
            Some(Completeness::Partial) | None => (
                CsmiCoverageStatus::Partial,
                vec![CsmiLimitation {
                    kind: "coverage-limited".to_owned(),
                    diagnostic: None,
                }],
            ),
        };
        completeness.push(CsmiCompletenessStatement {
            vocabulary: Some(CSMI_COLLECTION_FLOW_PROFILE_ID.to_owned()),
            version: Some(CSMI_COLLECTION_FLOW_PROFILE_VERSION.to_owned()),
            family: "collection-flows".to_owned(),
            scope,
            status,
            limitations,
            provenance: if flow.provenance.is_empty() {
                vec![options.provenance_id.clone()]
            } else {
                flow.provenance.clone()
            },
            extensions: Vec::new(),
        });
    }
    Ok(())
}

pub(in crate::analyzer::semantic_model::csmi) fn export_conditional_type_refinements(
    refinements: &ConditionalTypeRefinementsPayload,
    options: &CsmiExportOptions,
    symbols: &HashMap<String, String>,
    callable_shapes: &HashMap<String, bool>,
    facts: &mut Vec<CsmiExtensionFact>,
    affects: &mut Vec<CsmiAffectedUnit>,
    completeness: &mut Vec<CsmiCompletenessStatement>,
) -> Result<(), CsmiExportError> {
    for refinement in &refinements.refinements {
        let mut payload = refinement.payload.clone();
        payload.remap_symbols(|id| {
            symbols
                .get(id)
                .cloned()
                .ok_or_else(|| CsmiExportError::MissingDeclaration {
                    path: "conditional_type_refinements".to_owned(),
                    target: id.to_owned(),
                })
        })?;
        let scope = json!({"callable": payload.callable, "subject": payload.subject});
        let provenance = if refinement.provenance.is_empty() {
            vec![options.provenance_id.clone()]
        } else {
            refinement.provenance.clone()
        };
        facts.push(CsmiExtensionFact {
            vocabulary: CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID.to_owned(),
            version: CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION.to_owned(),
            family: CSMI_CONDITIONAL_TYPE_REFINEMENT_FAMILY.to_owned(),
            scope: scope.clone(),
            payload: serde_json::to_value(&payload)
                .map_err(|error| CsmiExportError::Canonical(error.to_string()))?,
            provenance: provenance.clone(),
            extensions: Vec::new(),
        });
        affects.push(CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
            kind: CsmiAffectedFactFamilyKind::FactFamily,
            family: CSMI_CONDITIONAL_TYPE_REFINEMENT_FAMILY.to_owned(),
            scope: scope.clone(),
        }));
        for (vocabulary, version, family, scope, status) in [
            (
                Some(CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_ID.to_owned()),
                Some(CSMI_CONDITIONAL_TYPE_REFINEMENT_PROFILE_VERSION.to_owned()),
                CSMI_CONDITIONAL_TYPE_REFINEMENT_FAMILY,
                scope,
                refinement.coverage,
            ),
            (
                None,
                None,
                "declaration-aspects",
                json!({"symbol": payload.callable, "aspect": "callable-shape"}),
                Some(
                    if callable_shapes
                        .get(&refinement.payload.callable)
                        .copied()
                        .unwrap_or(false)
                    {
                        CsmiCoverageStatus::Complete
                    } else {
                        CsmiCoverageStatus::Partial
                    },
                ),
            ),
        ] {
            let Some(status) = status else {
                continue;
            };
            let statement = CsmiCompletenessStatement {
                vocabulary,
                version,
                family: family.to_owned(),
                scope,
                status,
                limitations: if status == CsmiCoverageStatus::Complete {
                    Vec::new()
                } else {
                    vec![CsmiLimitation {
                        kind: "coverage-limited".to_owned(),
                        diagnostic: None,
                    }]
                },
                provenance: provenance.clone(),
                extensions: Vec::new(),
            };
            if !completeness.contains(&statement) {
                completeness.push(statement);
            }
        }
    }
    Ok(())
}

fn export_deferred_yields(
    deferred_yields: &DeferredYieldsPayload,
    options: &CsmiExportOptions,
    symbol_by_bifrost_id: &HashMap<String, String>,
    callable_shape_completeness: &HashMap<String, bool>,
    facts: &mut Vec<CsmiExtensionFact>,
    affects: &mut Vec<CsmiAffectedUnit>,
    completeness: &mut Vec<CsmiCompletenessStatement>,
) -> Result<(), CsmiExportError> {
    for deferred_yield in &deferred_yields.yields {
        let factory = symbol_by_bifrost_id
            .get(&deferred_yield.factory)
            .ok_or_else(|| CsmiExportError::MissingDeclaration {
                path: "deferred_yields.factory".to_owned(),
                target: deferred_yield.factory.clone(),
            })?;
        let resume = symbol_by_bifrost_id
            .get(&deferred_yield.resume)
            .ok_or_else(|| CsmiExportError::MissingDeclaration {
                path: "deferred_yields.resume".to_owned(),
                target: deferred_yield.resume.clone(),
            })?;
        let handle_type = symbol_by_bifrost_id
            .get(&deferred_yield.handle_type)
            .ok_or_else(|| CsmiExportError::MissingDeclaration {
                path: "deferred_yields.handle_type".to_owned(),
                target: deferred_yield.handle_type.clone(),
            })?;
        let scope = json!({
            "factory": factory,
            "resume": resume,
            "handleType": handle_type,
        });
        let payload = &deferred_yield.payload;
        if payload.factory != deferred_yield.factory
            || payload.resume != deferred_yield.resume
            || payload.handle_type != deferred_yield.handle_type
        {
            return Err(CsmiExportError::Identity(
                "deferred-yield payload linked scope does not match native scope".to_owned(),
            ));
        }
        let mut payload = payload.clone();
        remap_deferred_yield_payload(&mut payload, symbol_by_bifrost_id)?;
        let provenance = vec![options.provenance_id.clone()];
        facts.push(CsmiExtensionFact {
            vocabulary: CSMI_DEFERRED_YIELD_PROFILE_ID.to_owned(),
            version: CSMI_DEFERRED_YIELD_PROFILE_VERSION.to_owned(),
            family: "deferred-yields".to_owned(),
            scope: scope.clone(),
            payload: serde_json::to_value(&payload)
                .map_err(|error| CsmiExportError::Canonical(error.to_string()))?,
            provenance: provenance.clone(),
            extensions: Vec::new(),
        });
        affects.push(CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
            kind: CsmiAffectedFactFamilyKind::FactFamily,
            family: "deferred-yields".to_owned(),
            scope: scope.clone(),
        }));
        let (status, limitations) = match deferred_yield.coverage {
            Some(Completeness::Complete) => (CsmiCoverageStatus::Complete, Vec::new()),
            Some(Completeness::Partial) | None => (
                CsmiCoverageStatus::Partial,
                vec![CsmiLimitation {
                    kind: "coverage-limited".to_owned(),
                    diagnostic: None,
                }],
            ),
        };
        completeness.push(CsmiCompletenessStatement {
            vocabulary: Some(CSMI_DEFERRED_YIELD_PROFILE_ID.to_owned()),
            version: Some(CSMI_DEFERRED_YIELD_PROFILE_VERSION.to_owned()),
            family: "deferred-yields".to_owned(),
            scope,
            status,
            limitations,
            provenance,
            extensions: Vec::new(),
        });
        for (native_id, role) in [
            (&deferred_yield.factory, "factory"),
            (&deferred_yield.resume, "resume"),
        ] {
            let Some(symbol) = symbol_by_bifrost_id.get(native_id) else {
                return Err(CsmiExportError::MissingDeclaration {
                    path: format!("deferred_yields.{role}"),
                    target: native_id.clone(),
                });
            };
            let status = callable_shape_completeness
                .get(native_id)
                .copied()
                .unwrap_or(false);
            completeness.push(CsmiCompletenessStatement {
                vocabulary: None,
                version: None,
                family: "declaration-aspects".to_owned(),
                scope: json!({"symbol": symbol, "aspect": "callable-shape"}),
                status: if status {
                    CsmiCoverageStatus::Complete
                } else {
                    CsmiCoverageStatus::Partial
                },
                limitations: if status {
                    Vec::new()
                } else {
                    vec![CsmiLimitation {
                        kind: "coverage-limited".to_owned(),
                        diagnostic: None,
                    }]
                },
                provenance: vec![options.provenance_id.clone()],
                extensions: Vec::new(),
            });
        }
    }
    Ok(())
}

fn remap_deferred_yield_payload(
    payload: &mut CsmiDeferredYieldPayload,
    symbols: &HashMap<String, String>,
) -> Result<(), CsmiExportError> {
    crate::analyzer::semantic_model::csmi::deferred_yield::remap_payload(
        payload,
        "payload",
        |id, path| export_deferred_id(id, symbols, path),
        |id, path| export_deferred_id(id, symbols, path),
        |location, path| remap_deferred_yield_location(location, symbols, path),
        |shape, path| remap_deferred_yield_shape(shape, symbols, path),
    )
}

fn export_deferred_id(
    id: &str,
    symbols: &HashMap<String, String>,
    path: &str,
) -> Result<String, CsmiExportError> {
    symbols
        .get(id)
        .cloned()
        .ok_or_else(|| CsmiExportError::MissingDeclaration {
            path: path.to_owned(),
            target: id.to_owned(),
        })
}

fn remap_deferred_yield_location(
    location: &mut CsmiDeferredYieldLocation,
    symbols: &HashMap<String, String>,
    path: &str,
) -> Result<(), CsmiExportError> {
    location.callable =
        export_deferred_id(&location.callable, symbols, &format!("{path}.callable"))?;
    Ok(())
}

fn remap_deferred_yield_shape(
    shape: &mut CsmiDeferredYieldShape,
    symbols: &HashMap<String, String>,
    path: &str,
) -> Result<(), CsmiExportError> {
    crate::analyzer::semantic_model::csmi::deferred_yield::visit_shape(
        shape,
        path,
        |r#type, path| remap_deferred_yield_type_expression(r#type, symbols, path),
    )
}

fn remap_deferred_yield_type_expression(
    expression: &mut CsmiDeferredYieldTypeExpression,
    symbols: &HashMap<String, String>,
    path: &str,
) -> Result<(), CsmiExportError> {
    let mut stack = vec![(expression, path.to_owned())];
    while let Some((expression, path)) = stack.pop() {
        if let CsmiTypeExpression::Reference(reference) = expression {
            reference.symbol =
                export_deferred_id(&reference.symbol, symbols, &format!("{path}.symbol"))?;
            for (position, argument) in reference.arguments.iter_mut().enumerate().rev() {
                stack.push((argument, format!("{path}.arguments[{position}]")));
            }
        }
    }
    Ok(())
}

fn export_runtime_values(
    runtime_values: &RuntimeValuesPayload,
    options: &CsmiExportOptions,
    facts: &mut Vec<CsmiExtensionFact>,
    affects: &mut Vec<CsmiAffectedUnit>,
    completeness: &mut Vec<CsmiCompletenessStatement>,
) -> Result<(), CsmiExportError> {
    for record in &runtime_values.exposures {
        append_runtime_fact(
            runtime_payload_to_csmi("runtime-global-exposure", record)?,
            "exposureId",
            &record.exposure_id,
            &record.coverage,
            &record.provenance,
            &record.extensions,
            options,
            facts,
            affects,
            completeness,
        )?;
    }
    for record in &runtime_values.behaviors {
        append_runtime_fact(
            runtime_payload_to_csmi("keyed-read-behavior", record)?,
            "behaviorId",
            &record.behavior_id,
            &record.coverage,
            &record.provenance,
            &record.extensions,
            options,
            facts,
            affects,
            completeness,
        )?;
    }
    for record in &runtime_values.binding_evidence {
        append_runtime_fact(
            runtime_payload_to_csmi("runtime-global-binding-evidence", record)?,
            "bindingEvidenceId",
            &record.binding_evidence_id,
            &record.coverage,
            &record.provenance,
            &record.extensions,
            options,
            facts,
            affects,
            completeness,
        )?;
    }
    for record in &runtime_values.observations {
        append_runtime_fact(
            runtime_payload_to_csmi("keyed-read-observation", record)?,
            "observationId",
            &record.observation_id,
            &record.coverage,
            &record.provenance,
            &record.extensions,
            options,
            facts,
            affects,
            completeness,
        )?;
    }
    Ok(())
}

fn runtime_payload_to_csmi<T: serde::Serialize>(
    kind: &str,
    record: &T,
) -> Result<CsmiRuntimeValuesPayload, CsmiExportError> {
    let mut value = serde_json::to_value(record)
        .map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        CsmiExportError::Canonical("runtime-values records must serialize as objects".to_owned())
    })?;
    object.insert(
        "kind".to_owned(),
        serde_json::Value::String(kind.to_owned()),
    );
    object.remove("provenance");
    object.remove("extensions");
    serde_json::from_value(value).map_err(|error| CsmiExportError::Canonical(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn append_runtime_fact(
    payload: CsmiRuntimeValuesPayload,
    scope_key: &str,
    record_id: &str,
    coverage: &crate::analyzer::semantic_model::RuntimeCoverage,
    provenance: &[String],
    extensions: &[crate::analyzer::semantic_model::RuntimeValueExtension],
    options: &CsmiExportOptions,
    facts: &mut Vec<CsmiExtensionFact>,
    affects: &mut Vec<CsmiAffectedUnit>,
    completeness: &mut Vec<CsmiCompletenessStatement>,
) -> Result<(), CsmiExportError> {
    let family = payload.family().to_owned();
    let scope = json!({scope_key: record_id});
    let payload_value = serde_json::to_value(&payload)
        .map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
    let provenance = if provenance.is_empty() {
        vec![options.provenance_id.clone()]
    } else {
        provenance.to_vec()
    };
    let extensions = extensions
        .iter()
        .map(|extension| CsmiExtensionAttachment {
            vocabulary: extension.vocabulary.clone(),
            version: extension.version.clone(),
            payload: extension.payload.clone(),
        })
        .collect();
    facts.push(CsmiExtensionFact {
        vocabulary: CSMI_RUNTIME_VALUES_PROFILE_ID.to_owned(),
        version: CSMI_RUNTIME_VALUES_PROFILE_VERSION.to_owned(),
        family: family.clone(),
        scope: scope.clone(),
        payload: payload_value,
        provenance: provenance.clone(),
        extensions,
    });
    affects.push(CsmiAffectedUnit::FactFamily(CsmiAffectedFactFamily {
        kind: CsmiAffectedFactFamilyKind::FactFamily,
        family: family.clone(),
        scope: scope.clone(),
    }));
    let coverage: CsmiRuntimeCoverage = serde_json::from_value(
        serde_json::to_value(coverage)
            .map_err(|error| CsmiExportError::Canonical(error.to_string()))?,
    )
    .map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
    let limitation_names = coverage
        .limitations
        .into_iter()
        .map(|limitation| csmi_runtime_limitation_name(limitation).to_owned())
        .collect::<Vec<_>>();
    completeness.push(CsmiCompletenessStatement {
        vocabulary: Some(CSMI_RUNTIME_VALUES_PROFILE_ID.to_owned()),
        version: Some(CSMI_RUNTIME_VALUES_PROFILE_VERSION.to_owned()),
        family,
        scope,
        status: match coverage.status {
            CsmiRuntimeCoverageStatus::Complete => CsmiCoverageStatus::Complete,
            CsmiRuntimeCoverageStatus::Partial => CsmiCoverageStatus::Partial,
            CsmiRuntimeCoverageStatus::Unknown => CsmiCoverageStatus::Unknown,
        },
        limitations: limitation_names
            .into_iter()
            .map(|kind| CsmiLimitation {
                kind,
                diagnostic: None,
            })
            .collect(),
        provenance,
        extensions: Vec::new(),
    });
    Ok(())
}

fn csmi_runtime_limitation_name(limitation: CsmiRuntimeCoverageLimitation) -> &'static str {
    match limitation {
        CsmiRuntimeCoverageLimitation::ActivationMissing => "activation-missing",
        CsmiRuntimeCoverageLimitation::ActivationConflict => "activation-conflict",
        CsmiRuntimeCoverageLimitation::ActivationUnsupported => "activation-unsupported",
        CsmiRuntimeCoverageLimitation::LexicalBindingIndeterminate => {
            "lexical-binding-indeterminate"
        }
        CsmiRuntimeCoverageLimitation::RebindingIndeterminate => "rebinding-indeterminate",
        CsmiRuntimeCoverageLimitation::MutationIncomplete => "mutation-incomplete",
        CsmiRuntimeCoverageLimitation::AccessorOrProxyIncomplete => "accessor-or-proxy-incomplete",
        CsmiRuntimeCoverageLimitation::MaterializationIncomplete => "materialization-incomplete",
        CsmiRuntimeCoverageLimitation::ExceptionBehaviorIndeterminate => {
            "exception-behavior-indeterminate"
        }
        CsmiRuntimeCoverageLimitation::DynamicKey => "dynamic-key",
        CsmiRuntimeCoverageLimitation::UnsupportedIndex => "unsupported-index",
        CsmiRuntimeCoverageLimitation::Cancelled => "cancelled",
        CsmiRuntimeCoverageLimitation::BudgetExhausted => "budget-exhausted",
        CsmiRuntimeCoverageLimitation::StaleEvidence => "stale-evidence",
        CsmiRuntimeCoverageLimitation::AmbiguousOwner => "ambiguous-owner",
        CsmiRuntimeCoverageLimitation::CoverageLimited => "coverage-limited",
    }
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
    validate_digest_evidence(artifact)
}

fn validate_exact_artifact_evidence(
    artifact: &CsmiArtifactEvidence,
) -> Result<(), CsmiExportError> {
    if !artifact.purl.starts_with("pkg:") || !artifact.purl.contains('@') {
        return Err(CsmiExportError::InvalidEvidence(
            "portable C/C++ export requires an exact versioned PURL".to_owned(),
        ));
    }
    validate_digest_evidence(artifact)
}

fn validate_digest_evidence(artifact: &CsmiArtifactEvidence) -> Result<(), CsmiExportError> {
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

fn validate_go_artifact_evidence(artifact: &CsmiArtifactEvidence) -> Result<(), CsmiExportError> {
    let Some(coordinate) = artifact.purl.strip_prefix("pkg:golang/") else {
        return Err(CsmiExportError::InvalidEvidence(
            "Go source identity requires an exact versioned pkg:golang PURL".to_owned(),
        ));
    };
    let Some((package, version)) = coordinate.split_once('@') else {
        return Err(CsmiExportError::InvalidEvidence(
            "Go source identity requires an exact versioned pkg:golang PURL".to_owned(),
        ));
    };
    if package.is_empty()
        || version.is_empty()
        || version.contains('@')
        || coordinate.contains(['?', '#'])
    {
        return Err(CsmiExportError::InvalidEvidence(
            "Go PURL must identify one package and exact version without qualifiers or subpath"
                .to_owned(),
        ));
    }
    validate_exact_artifact_evidence(artifact)
}

fn csmi_artifact_selector(artifact: &CsmiArtifactEvidence) -> CsmiArtifactSelector {
    CsmiArtifactSelector {
        purl: artifact.purl.clone(),
        version_range: None,
        digests: vec![CsmiArtifactDigest {
            algorithm: CsmiDigestAlgorithm::Sha256,
            coverage: artifact.coverage.clone(),
            canonicalization: None,
            value: artifact.sha256.clone(),
        }],
    }
}

fn cpp_local_id(key: &CppPortableSymbolKey) -> Result<String, CsmiExportError> {
    let bytes = canonical_json(&csmi_cpp_key(key))
        .map_err(|error| CsmiExportError::Canonical(error.to_string()))?;
    Ok(format!("cpp.{}", sha256_hex(&bytes)))
}

fn csmi_cpp_key(key: &CppPortableSymbolKey) -> CsmiCppSymbolKey {
    key.into()
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
                artifact: (&header.artifact).into(),
            })
            .collect(),
        header_closure: CsmiCompleteHeaderClosure::Complete,
    }
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
        resolution_context: CsmiCppResolutionContext::try_from(&member.resolution_context)?,
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

pub(in crate::analyzer::semantic_model::csmi) fn callable_shape(
    member: &MemberFact,
    resolve_type: &dyn Fn(&TypeRef) -> Result<CsmiTypeExpression, CsmiExportError>,
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
            receiver_type: Some(resolve_type(receiver_type)?),
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
                if parameter.passing_mode
                    == crate::analyzer::semantic_model::ParameterPassingMode::NamedOnly
                {
                    CsmiParameterBinding::VariadicNamed
                } else {
                    CsmiParameterBinding::VariadicPositional
                }
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
            let parameter_type = resolve_type(&parameter.r#type)?;
            Ok(CsmiParameter {
                position: position as u32,
                binding,
                label: parameter.name.clone(),
                role: parameter.role.map(|role| match role {
                    ParameterRole::Request => CsmiParameterRole::Request,
                }),
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
                result_type: Some(resolve_type(result)?),
                extensions: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, CsmiExportError>>()?;
    let kind = match member.member_kind {
        MemberKind::Constructor => CsmiCallableKind::Constructor,
        MemberKind::Function => CsmiCallableKind::Function,
        MemberKind::Method | MemberKind::Static => CsmiCallableKind::Method,
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
        return_classes: member
            .exact_return_classes
            .iter()
            .map(resolve_type)
            .collect::<Result<Vec<_>, _>>()?,
        extensions: Vec::new(),
    })
}

fn go_member_callable_shape(
    member: &MemberFact,
    owner_symbol: &str,
) -> Result<CsmiCallableShape, CsmiExportError> {
    let signature = member
        .signature
        .as_ref()
        .ok_or_else(|| CsmiExportError::Unsupported {
            path: format!("members.{}.signature", member.id),
            semantic: "Go callable declaration has no native signature".to_owned(),
        })?;
    let unknown_type = || {
        CsmiTypeExpression::Unknown(CsmiUnknownType {
            kind: CsmiUnknownTypeKind::Unknown,
        })
    };
    let mut parameters = Vec::with_capacity(signature.parameters.len());
    for (position, parameter) in signature.parameters.iter().enumerate() {
        parameters.push(CsmiParameter {
            position: u32::try_from(position).map_err(|_| CsmiExportError::Unsupported {
                path: format!("members.{}.signature.parameters", member.id),
                semantic: "Go callable has more parameters than CSMI can index".to_owned(),
            })?,
            binding: if parameter.variadic {
                CsmiParameterBinding::VariadicPositional
            } else {
                CsmiParameterBinding::PositionalOnly
            },
            label: None,
            role: parameter.role.map(|role| match role {
                ParameterRole::Request => CsmiParameterRole::Request,
            }),
            required: true,
            symbol: None,
            parameter_type: Some(unknown_type()),
            extensions: Vec::new(),
        });
    }
    let result_count = match signature.returns.as_ref() {
        None => 0,
        Some(TypeRef::Tuple { elements }) => elements.len(),
        Some(_) => 1,
    };
    let mut results = Vec::with_capacity(result_count);
    for position in 0..result_count {
        results.push(CsmiResult {
            position: u32::try_from(position).map_err(|_| CsmiExportError::Unsupported {
                path: format!("members.{}.signature.returns", member.id),
                semantic: "Go callable has more results than CSMI can index".to_owned(),
            })?,
            label: None,
            result_type: Some(unknown_type()),
            extensions: Vec::new(),
        });
    }
    let receiver = member.receiver.map(|receiver| CsmiReceiver {
        kind: CsmiReceiverKind::Instance,
        receiver_type: Some(if receiver.pointer {
            CsmiTypeExpression::Unknown(CsmiUnknownType {
                kind: CsmiUnknownTypeKind::Unknown,
            })
        } else {
            CsmiTypeExpression::Reference(CsmiReferenceType {
                kind: CsmiReferenceTypeKind::Reference,
                symbol: owner_symbol.to_owned(),
                arguments: Vec::new(),
            })
        }),
        extensions: Vec::new(),
    });
    Ok(CsmiCallableShape {
        kind: if receiver.is_some() {
            CsmiCallableKind::Method
        } else {
            CsmiCallableKind::Function
        },
        receiver,
        parameters,
        results,
        return_classes: Vec::new(),
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
        TypeRef::Unknown => Ok(CsmiTypeExpression::Unknown(CsmiUnknownType {
            kind: CsmiUnknownTypeKind::Unknown,
        })),
        other => Err(CsmiExportError::Unsupported {
            path: "declarations.callable.type".to_owned(),
            semantic: format!("C++ core type shape {other:?} is not representable"),
        }),
    }
}

pub(in crate::analyzer::semantic_model::csmi) fn transfer_to_csmi(
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
            let payload =
                crate::analyzer::semantic_model::csmi::value_transfer::csmi_from_compiled(
                    value_transfer,
                    |member| {
                        symbol_by_bifrost_id.get(member).cloned().ok_or_else(|| {
                            CsmiExportError::MissingDeclaration {
                                path: "procedureSummaries.transfers.valueTransfer.operation.member"
                                    .to_owned(),
                                target: member.to_owned(),
                            }
                        })
                    },
                )?;
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
