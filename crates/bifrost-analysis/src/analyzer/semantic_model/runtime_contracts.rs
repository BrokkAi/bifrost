//! Typed native companions for the CSMI runtime-values 0.2 vocabulary.
//!
//! These records preserve the normative wire payload structurally. Semantic
//! digests remain opaque SHA-256 commitments supplied by the producer; their
//! recomputation is the validator's responsibility, not the interchange
//! boundary's. Unsupported schemes and incompleteness are typed so affected
//! units fail closed without fabricating artifact digests or runtime proof.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Wire vocabulary identifier, unchanged from 0.1. The version distinguishes
/// the two wire forms.
pub const RUNTIME_VALUES_V2_VERSION: &str = "0.2.0";
pub const RUNTIME_VALUES_V2_SCHEMA: &str =
    "https://csmi.brokk.ai/schema/profiles/runtime-values/0.2/schema.json";

/// The five fact families, in normative order. Each entry preserves its
/// document-local identity and any references to other local records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeContractsPayloadV2 {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contracts: Vec<RuntimeContractV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<RuntimeTargetV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub activations: Vec<RuntimeActivationV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<RuntimeBindingV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observations: Vec<RuntimeObservationV2>,
}

impl RuntimeContractsPayloadV2 {
    pub fn record_count(&self) -> usize {
        self.contracts
            .len()
            .saturating_add(self.targets.len())
            .saturating_add(self.activations.len())
            .saturating_add(self.bindings.len())
            .saturating_add(self.observations.len())
    }

    pub fn contract(&self, id: &str) -> Option<&RuntimeContractV2> {
        self.contracts.iter().find(|r| r.contract_id == id)
    }

    pub fn target(&self, id: &str) -> Option<&RuntimeTargetV2> {
        self.targets.iter().find(|r| r.target_id == id)
    }

    pub fn activation(&self, id: &str) -> Option<&RuntimeActivationV2> {
        self.activations.iter().find(|r| r.activation_id == id)
    }

    pub fn binding(&self, id: &str) -> Option<&RuntimeBindingV2> {
        self.bindings.iter().find(|r| r.binding_id == id)
    }

    pub fn observation(&self, id: &str) -> Option<&RuntimeObservationV2> {
        self.observations.iter().find(|r| r.observation_id == id)
    }

    pub fn is_empty(&self) -> bool {
        self.record_count() == 0
    }

    /// Return the five records in the order used by the CSMI extension-fact
    /// projection. The source vectors remain independently typed; callers use
    /// this only when comparing a retained wire envelope or exporting facts.
    pub fn wire_records(&self) -> impl Iterator<Item = CsmiRuntimeContractsV2Payload> + '_ {
        self.contracts
            .iter()
            .cloned()
            .map(CsmiRuntimeContractsV2Payload::RuntimeContract)
            .chain(
                self.targets
                    .iter()
                    .cloned()
                    .map(CsmiRuntimeContractsV2Payload::RuntimeTarget),
            )
            .chain(
                self.activations
                    .iter()
                    .cloned()
                    .map(CsmiRuntimeContractsV2Payload::RuntimeActivation),
            )
            .chain(
                self.bindings
                    .iter()
                    .cloned()
                    .map(CsmiRuntimeContractsV2Payload::RuntimeBinding),
            )
            .chain(
                self.observations.iter().cloned().map(|record| {
                    CsmiRuntimeContractsV2Payload::RuntimeObservation(Box::new(record))
                }),
            )
    }
}

/// One runtime-values 0.2 extension fact. The `kind` discriminator is part of
/// the CSMI payload and is deliberately retained alongside each typed record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CsmiRuntimeContractsV2Payload {
    #[serde(rename = "runtime-contract")]
    RuntimeContract(RuntimeContractV2),
    #[serde(rename = "runtime-target")]
    RuntimeTarget(RuntimeTargetV2),
    #[serde(rename = "runtime-activation")]
    RuntimeActivation(RuntimeActivationV2),
    #[serde(rename = "runtime-binding")]
    RuntimeBinding(RuntimeBindingV2),
    #[serde(rename = "runtime-observation")]
    RuntimeObservation(Box<RuntimeObservationV2>),
}

impl CsmiRuntimeContractsV2Payload {
    pub fn family(&self) -> &'static str {
        match self {
            Self::RuntimeContract(_) => "runtime-contracts",
            Self::RuntimeTarget(_) => "runtime-targets",
            Self::RuntimeActivation(_) => "runtime-activations",
            Self::RuntimeBinding(_) => "runtime-bindings",
            Self::RuntimeObservation(_) => "runtime-observations",
        }
    }

    pub fn record_id(&self) -> &str {
        match self {
            Self::RuntimeContract(record) => &record.contract_id,
            Self::RuntimeTarget(record) => &record.target_id,
            Self::RuntimeActivation(record) => &record.activation_id,
            Self::RuntimeBinding(record) => &record.binding_id,
            Self::RuntimeObservation(record) => &record.observation_id,
        }
    }
}

/// Compare a native five-family payload with the v0.2 extension facts in a
/// retained CSMI semantic-document envelope. This is intentionally a set
/// comparison: extension-fact order is not semantic, while each record's
/// internal arrays are normalized by [`runtime_contract_canonical`].
pub fn runtime_contract_envelope_matches(
    payload: &RuntimeContractsPayloadV2,
    envelope: &Value,
) -> Result<bool, crate::analyzer::semantic_model::csmi::CsmiCanonicalError> {
    let Some(models) = envelope.get("semanticModels").and_then(Value::as_array) else {
        return Ok(false);
    };
    let [model] = models.as_slice() else {
        return Ok(false);
    };
    let Some(facts) = model.get("extensionFacts").and_then(Value::as_array) else {
        return Ok(false);
    };
    let mut wire = Vec::new();
    for fact in facts.iter().filter(|fact| {
        fact.get("vocabulary").and_then(Value::as_str) == Some("csmi.runtime-values")
            && fact.get("version").and_then(Value::as_str) == Some(RUNTIME_VALUES_V2_VERSION)
    }) {
        let Some(record) = fact.get("payload") else {
            return Ok(false);
        };
        wire.push(record.clone());
    }
    let native = payload
        .wire_records()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(runtime_contract_canonical(&wire)? == runtime_contract_canonical(&native)?)
}

/// Normalize a complete retained CSMI document for storage in a native
/// companion. Core arrays use the CSMI v0.1 canonicalizer; only runtime-values
/// 0.2 extension payloads additionally use this profile's recursive set rules.
/// This preserves ordered arrays in unrelated CSMI profiles.
pub fn normalize_runtime_contract_envelope(
    envelope: &mut Value,
) -> Result<(), crate::analyzer::semantic_model::csmi::CsmiCanonicalError> {
    if let Some(models) = envelope
        .get_mut("semanticModels")
        .and_then(Value::as_array_mut)
    {
        for model in models {
            let Some(facts) = model
                .get_mut("extensionFacts")
                .and_then(Value::as_array_mut)
            else {
                continue;
            };
            for fact in facts {
                if fact.get("vocabulary").and_then(Value::as_str) != Some("csmi.runtime-values")
                    || fact.get("version").and_then(Value::as_str)
                        != Some(RUNTIME_VALUES_V2_VERSION)
                {
                    continue;
                }
                let Some(payload) = fact.get_mut("payload") else {
                    continue;
                };
                *payload = normalize_runtime_contract_sets(payload.take())?;
            }
        }
    }
    let core = crate::analyzer::semantic_model::csmi::canonical_json_value(envelope)?;
    let normalized: Value = serde_json::from_slice(&core)?;
    *envelope = normalized;
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared evidence, identity, and applicability structures
// ---------------------------------------------------------------------------

/// Versioned scheme identity (URI + version pair).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSchemeV2 {
    pub identifier: String,
    pub version: String,
}

/// Structured evidence provenance for a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEvidenceV2 {
    pub producer: String,
    pub method: String,
    #[serde(rename = "inputsDigest")]
    pub inputs_digest: String,
}

/// An immutable source resource with its content digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeResourceV2 {
    pub resource: String,
    #[serde(rename = "resourceDigest")]
    pub resource_digest: String,
}

/// A byte range within an immutable resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRangeV2 {
    pub resource: String,
    #[serde(rename = "resourceDigest")]
    pub resource_digest: String,
    #[serde(rename = "startByte")]
    pub start_byte: u64,
    #[serde(rename = "endByte")]
    pub end_byte: u64,
}

/// A versioned program identity (scope, value, operation, point, invocation,
/// realm, or store).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIdentityV2 {
    pub scheme: RuntimeSchemeV2,
    #[serde(rename = "ownerDigest")]
    pub owner_digest: String,
    #[serde(rename = "locatorDigest")]
    pub locator_digest: String,
    pub kind: RuntimeIdentityKindV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeIdentityKindV2 {
    Scope,
    Value,
    Operation,
    Point,
    Invocation,
    Realm,
    Store,
}

/// Typed completeness, preserving supplied limitations without reinterpretation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCoverageV2 {
    pub status: RuntimeCoverageStatusV2,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<RuntimeCoverageLimitationV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeCoverageStatusV2 {
    Complete,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeCoverageLimitationV2 {
    ActivationMissing,
    ActivationConflict,
    ActivationUnsupported,
    TargetUnknown,
    ReviewMissing,
    InventoryIncomplete,
    LexicalBindingIndeterminate,
    RebindingIndeterminate,
    MutationIncomplete,
    LookupIncomplete,
    MaterializationIncomplete,
    ExceptionBehaviorIndeterminate,
    InitializationIncomplete,
    DynamicKey,
    UnsupportedKey,
    Cancelled,
    BudgetExhausted,
    StaleEvidence,
    EqualityUnknown,
    SharingUnknown,
    CoverageLimited,
}

/// An artifact digest claim, only present in artifact-specific applicability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeArtifactDigestV2 {
    pub algorithm: RuntimeDigestAlgorithmV2,
    pub coverage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonicalization: Option<String>,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeDigestAlgorithmV2 {
    #[serde(rename = "sha-256")]
    Sha256,
    #[serde(rename = "sha-384")]
    Sha384,
    #[serde(rename = "sha-512")]
    Sha512,
}

/// A PURL/VERS selector, optionally with artifact digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSelectorV2 {
    pub purl: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "versionRange")]
    pub version_range: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub digests: Vec<RuntimeArtifactDigestV2>,
}

/// Exact execution context (single values per dimension).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeExactContextV2 {
    pub scheme: RuntimeSchemeV2,
    pub platform: String,
    pub architecture: String,
    pub realm: String,
    #[serde(rename = "moduleMode")]
    pub module_mode: String,
    #[serde(rename = "launchMode")]
    pub launch_mode: String,
    #[serde(rename = "initializationBoundary")]
    pub initialization_boundary: String,
}

/// Context constraints (sets per dimension).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeContextConstraintsV2 {
    pub scheme: RuntimeSchemeV2,
    pub platform: Vec<String>,
    pub architecture: Vec<String>,
    pub realm: Vec<String>,
    #[serde(rename = "moduleMode")]
    pub module_mode: Vec<String>,
    #[serde(rename = "launchMode")]
    pub launch_mode: Vec<String>,
    #[serde(rename = "initializationBoundary")]
    pub initialization_boundary: Vec<String>,
}

/// Root/container surface roles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSurfaceV2 {
    pub root: String,
    pub container: String,
}

/// An origin for an initial store entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOriginV2 {
    pub keys: RuntimeOriginKeysV2,
    pub origin: RuntimeOriginSourceV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeOriginKeysV2 {
    #[serde(rename = "all-properties")]
    AllProperties {},
    #[serde(rename = "index-range")]
    IndexRange { minimum: u32, maximum: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeOriginSourceV2 {
    ExternalEnvironment,
    ApplicationArgument,
    ExecutablePath,
    EntryPath,
    Unknown,
}

// ---------------------------------------------------------------------------
// Contract definition behavior
// ---------------------------------------------------------------------------

/// Read semantics for a key lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReadBehaviorV2 {
    pub exceptions: RuntimeReadExceptionsV2,
    pub materialization: RuntimeMaterializationV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeReadExceptionsV2 {
    Nonthrowing,
    MayThrow,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeMaterializationV2 {
    Eager,
    Lazy,
    #[serde(rename = "host-defined")]
    HostDefined,
    Unknown,
}

/// Write semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWriteBehaviorV2 {
    pub conversion: RuntimeWriteConversionV2,
    pub normal: RuntimeWriteNormalV2,
    pub exceptional: RuntimeWriteExceptionalV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeWriteConversionV2 {
    Identity,
    #[serde(rename = "string-conversion")]
    StringConversion,
    #[serde(rename = "requires-contract")]
    RequiresContract,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeWriteNormalV2 {
    #[serde(rename = "store-converted-value")]
    StoreConvertedValue,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeWriteExceptionalV2 {
    Unchanged,
    #[serde(rename = "may-mutate")]
    MayMutate,
    Unknown,
}

/// Delete semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDeleteBehaviorV2 {
    pub normal: RuntimeDeleteNormalV2,
    pub exceptional: RuntimeDeleteExceptionalV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeDeleteNormalV2 {
    #[serde(rename = "remove-entry")]
    RemoveEntry,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeDeleteExceptionalV2 {
    Unchanged,
    #[serde(rename = "may-mutate")]
    MayMutate,
    Unknown,
}

/// The reviewed runtime value behavior contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBehaviorV2 {
    #[serde(rename = "keyDomain")]
    pub key_domain: RuntimeKeyDomainV2,
    pub lookup: RuntimeLookupKindV2,
    #[serde(rename = "presentValue")]
    pub present_value: RuntimePresentValueV2,
    pub absent: RuntimeAbsentBehaviorV2,
    #[serde(rename = "keyEquality")]
    pub key_equality: RuntimeSchemeV2,
    pub read: RuntimeReadBehaviorV2,
    pub write: RuntimeWriteBehaviorV2,
    pub delete: RuntimeDeleteBehaviorV2,
    #[serde(rename = "initialOrigins")]
    pub initial_origins: Vec<RuntimeOriginV2>,
    pub coverage: RuntimeCoverageV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeKeyDomainV2 {
    #[serde(rename = "static-property")]
    StaticProperty,
    #[serde(rename = "static-index")]
    StaticIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeLookupKindV2 {
    #[serde(rename = "own-value")]
    OwnValue,
    #[serde(rename = "mapping-entry")]
    MappingEntry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimePresentValueV2 {
    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeAbsentBehaviorV2 {
    Undefined,
    Exception,
}

/// Applicability basis for a contract definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeApplicabilityV2 {
    pub basis: RuntimeApplicabilityBasisV2,
    pub selectors: Vec<RuntimeSelectorV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeApplicabilityBasisV2 {
    Portable,
    #[serde(rename = "artifact-specific")]
    ArtifactSpecific,
}

// ---------------------------------------------------------------------------
// Contract record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeContractV2 {
    #[serde(rename = "contractId")]
    pub contract_id: String,
    pub definition: RuntimeContractDefinitionV2,
    #[serde(rename = "contractDigest")]
    pub contract_digest: String,
    pub evidence: RuntimeEvidenceV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeContractDefinitionV2 {
    pub identifier: String,
    pub version: String,
    pub applicability: RuntimeApplicabilityV2,
    pub context: RuntimeContextConstraintsV2,
    pub surface: RuntimeSurfaceV2,
    pub languages: Vec<String>,
    pub assumptions: Vec<String>,
    pub behavior: RuntimeBehaviorV2,
}

// ---------------------------------------------------------------------------
// Target record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTargetV2 {
    #[serde(rename = "targetId")]
    pub target_id: String,
    pub definition: RuntimeTargetDefinitionV2,
    #[serde(rename = "targetDigest")]
    pub target_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTargetDefinitionV2 {
    pub partition: String,
    pub resources: Vec<RuntimeResourceV2>,
    pub basis: RuntimeTargetBasisV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeSelectorV2>,
    pub context: RuntimeExactContextV2,
    pub assumptions: Vec<String>,
    pub evidence: RuntimeEvidenceV2,
    pub coverage: RuntimeCoverageV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeTargetBasisV2 {
    #[serde(rename = "declared-target")]
    DeclaredTarget,
    #[serde(rename = "deployment-observation")]
    DeploymentObservation,
    Unknown,
}

// ---------------------------------------------------------------------------
// Activation record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeActivationV2 {
    #[serde(rename = "activationId")]
    pub activation_id: String,
    #[serde(rename = "targetId")]
    pub target_id: String,
    pub surface: RuntimeSurfaceV2,
    #[serde(rename = "candidateIds")]
    pub candidate_ids: Vec<String>,
    #[serde(rename = "candidateCoverage")]
    pub candidate_coverage: RuntimeCoverageV2,
    #[serde(rename = "disabledIds")]
    pub disabled_ids: Vec<String>,
    pub reviews: Vec<RuntimeReviewV2>,
    pub policy: RuntimePolicyV2,
    pub outcome: RuntimeActivationOutcomeV2,
    #[serde(rename = "selectedIds")]
    pub selected_ids: Vec<String>,
    #[serde(rename = "activationDigest")]
    pub activation_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeActivationOutcomeV2 {
    Matched,
    #[serde(rename = "not-matched")]
    NotMatched,
    Indeterminate,
    Conflict,
    Unsupported,
    #[serde(rename = "review-required")]
    ReviewRequired,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReviewV2 {
    #[serde(rename = "contractDigest")]
    pub contract_digest: String,
    #[serde(rename = "targetDigest")]
    pub target_digest: String,
    pub purpose: String,
    pub reviewer: String,
    pub decision: RuntimeReviewDecisionV2,
    pub evidence: RuntimeEvidenceV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeReviewDecisionV2 {
    Approved,
    Denied,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicyV2 {
    pub identifier: String,
    pub version: String,
    #[serde(rename = "inputsDigest")]
    pub inputs_digest: String,
    #[serde(rename = "trustedReviewers")]
    pub trusted_reviewers: Vec<String>,
    pub purpose: String,
}

// ---------------------------------------------------------------------------
// Binding record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBindingV2 {
    #[serde(rename = "bindingId")]
    pub binding_id: String,
    #[serde(rename = "activationId")]
    pub activation_id: String,
    #[serde(rename = "activationDigest")]
    pub activation_digest: String,
    #[serde(rename = "contractId")]
    pub contract_id: String,
    pub language: String,
    pub source: RuntimeRangeV2,
    pub scope: RuntimeIdentityV2,
    pub root: RuntimeIdentityV2,
    pub container: RuntimeIdentityV2,
    #[serde(rename = "lexicalBinding")]
    pub lexical_binding: RuntimeLexicalBindingV2,
    pub rebinding: RuntimeRebindingV2,
    pub outcome: RuntimeBindingOutcomeV2,
    pub evidence: RuntimeEvidenceV2,
    pub coverage: RuntimeCoverageV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeLexicalBindingV2 {
    Absent,
    Present,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeRebindingV2 {
    Excluded,
    Present,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeBindingOutcomeV2 {
    Exact,
    Excluded,
    Indeterminate,
    Unsupported,
}

// ---------------------------------------------------------------------------
// Observation record
// ---------------------------------------------------------------------------

/// A static property name or index key, or a typed dynamic/unsupported marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeKeyV2 {
    #[serde(rename = "property")]
    Property {
        value: String,
    },
    #[serde(rename = "index")]
    Index {
        value: u32,
    },
    Dynamic {},
    Unsupported {},
}

/// How the source access is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeSourceFormV2 {
    Dot,
    #[serde(rename = "bracket-string")]
    BracketString,
    #[serde(rename = "bracket-number")]
    BracketNumber,
    Mapping,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimePhaseV2 {
    #[serde(rename = "before-effects")]
    BeforeEffects,
    #[serde(rename = "after-effects")]
    AfterEffects,
    Exceptional,
}

/// Store identity and relationship to the enclosing invocation realm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStoreV2 {
    pub invocation: RuntimeIdentityV2,
    pub realm: RuntimeIdentityV2,
    pub container: RuntimeIdentityV2,
    pub backing: RuntimeIdentityV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "copiedFrom")]
    pub copied_from: Option<RuntimeIdentityV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "copyPoint")]
    pub copy_point: Option<RuntimeIdentityV2>,
    pub relationship: RuntimeStoreRelationshipV2,
    pub evidence: RuntimeEvidenceV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeStoreRelationshipV2 {
    Isolated,
    Copied,
    Shared,
    Unknown,
}

/// Proof commitments about initialization, dependencies, and key normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProofV2 {
    #[serde(rename = "keyNormalization")]
    pub key_normalization: RuntimeKeyNormalizationV2,
    pub initialization: RuntimeProofClosednessV2,
    pub dependencies: RuntimeProofClosednessV2,
    pub mutation: RuntimeProofMutationV2,
    pub lookup: RuntimeProofLookupV2,
    pub materialization: RuntimeProofMaterializationV2,
    pub normal: RuntimeProofNormalV2,
    pub exceptional: RuntimeProofExceptionalV2,
    #[serde(rename = "closureDigest")]
    pub closure_digest: String,
    pub evidence: RuntimeEvidenceV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeKeyNormalizationV2 {
    Exact,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeProofClosednessV2 {
    Closed,
    Open,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeProofMutationV2 {
    Pristine,
    Written,
    Deleted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeProofLookupV2 {
    #[serde(rename = "own-present")]
    OwnPresent,
    #[serde(rename = "absent-no-fallback")]
    AbsentNoFallback,
    #[serde(rename = "mapping-present")]
    MappingPresent,
    #[serde(rename = "mapping-absent")]
    MappingAbsent,
    Inherited,
    Accessor,
    Proxy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeProofMaterializationV2 {
    Resolved,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeProofNormalV2 {
    Exact,
    Indeterminate,
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeProofExceptionalV2 {
    Excluded,
    Modeled,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeObservationV2 {
    #[serde(rename = "observationId")]
    pub observation_id: String,
    #[serde(rename = "bindingId")]
    pub binding_id: String,
    pub key: RuntimeKeyV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "storageKey")]
    pub storage_key: Option<RuntimeKeyV2>,
    #[serde(rename = "sourceForm")]
    pub source_form: RuntimeSourceFormV2,
    pub source: RuntimeRangeV2,
    #[serde(rename = "baseValue")]
    pub base_value: RuntimeIdentityV2,
    #[serde(rename = "loadOperation")]
    pub load_operation: RuntimeIdentityV2,
    #[serde(rename = "resultValue")]
    pub result_value: RuntimeIdentityV2,
    pub point: RuntimeIdentityV2,
    pub phase: RuntimePhaseV2,
    pub store: RuntimeStoreV2,
    pub origin: RuntimeObservationOriginV2,
    pub proof: RuntimeProofV2,
    pub coverage: RuntimeCoverageV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeObservationOriginV2 {
    #[serde(rename = "initial-if-present")]
    InitialIfPresent,
    Written,
    Deleted,
    Absent,
    Unknown,
}

// ---------------------------------------------------------------------------
// Canonicalization helpers
// ---------------------------------------------------------------------------

/// Recursively normalize set-valued arrays in a JSON value and return the
/// canonical JCS bytes. Depth is bounded by the payload's schema depth.
pub fn runtime_contract_canonical<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, crate::analyzer::semantic_model::csmi::CsmiCanonicalError> {
    let json = serde_json::to_value(value)?;
    let normalized = normalize_runtime_contract_sets(json)?;
    serde_json_canonicalizer::to_vec(&normalized).map_err(Into::into)
}

/// Compute the SHA-256 digest of a runtime contract's canonical bytes.
pub fn runtime_contract_digest<T: Serialize>(
    value: &T,
) -> Result<String, crate::analyzer::semantic_model::csmi::CsmiCanonicalError> {
    let bytes = runtime_contract_canonical(value)?;
    Ok(crate::analyzer::semantic_model::csmi::sha256_hex(&bytes))
}

/// Normalize a native payload in place using the same recursive set rules as
/// [`runtime_contract_canonical`]. This keeps compiled shard bytes stable when
/// an author supplies equivalent records in a different order.
pub fn normalize_runtime_contract_payload(
    payload: &mut RuntimeContractsPayloadV2,
) -> Result<(), crate::analyzer::semantic_model::csmi::CsmiCanonicalError> {
    let value = serde_json::to_value(&*payload)?;
    let normalized = normalize_runtime_contract_sets(value)?;
    *payload = serde_json::from_value(normalized)?;
    Ok(())
}

fn normalize_runtime_contract_sets(
    value: Value,
) -> Result<Value, crate::analyzer::semantic_model::csmi::CsmiCanonicalError> {
    match value {
        Value::Array(values) => {
            let values = values
                .into_iter()
                .map(normalize_runtime_contract_sets)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(sort_and_dedup_json_array(Value::Array(values)))
        }
        Value::Object(object) => {
            let mut result = serde_json::Map::with_capacity(object.len());
            for (key, child) in object {
                let normalized = normalize_runtime_contract_sets(child)?;
                result.insert(key, normalized);
            }
            Ok(Value::Object(result))
        }
        scalar => Ok(scalar),
    }
}

fn sort_and_dedup_json_array(value: Value) -> Value {
    let values = match value {
        Value::Array(values) => values,
        other => return other,
    };
    let mut keyed = values
        .into_iter()
        .map(|item| {
            let key = serde_json_canonicalizer::to_vec(&item)
                .expect("a serde_json value is JCS serializable");
            (key, item)
        })
        .collect::<Vec<_>>();
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.0 == right.0);
    Value::Array(keyed.into_iter().map(|(_, item)| item).collect())
}
