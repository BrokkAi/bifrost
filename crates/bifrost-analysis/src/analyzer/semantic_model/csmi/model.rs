//! CSMI v0.1 wire types.
//!
//! These types intentionally do not reuse Bifrost's authored or compiled pack
//! model.  CSMI local handles are document-local, while Bifrost IDs and runtime
//! handles are implementation details and must not leak into the interchange
//! format.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CSMI_SCHEMA_URI: &str = "https://csmi.brokk.ai/schema/0.1/schema.json";
pub const CSMI_SEMANTIC_MODEL_VERSION: &str = "0.1";
pub const CSMI_SERIALIZATION_VERSION: &str = "0.1-json";
pub const CSMI_PACK_FORMAT_VERSION: &str = "0.1";
pub const CSMI_SEMANTIC_DOCUMENT_MEDIA_TYPE: &str = "application/vnd.csmi.semantic-model.v0.1+json";
pub const CSMI_NORMATIVE_COMMIT: &str = "d0e8535fc73dc5804c191d5a2a218ef63083df64";
pub const CSMI_VALUE_TRANSFER_PROFILE_ID: &str = "csmi.value-transfer";
pub const CSMI_VALUE_TRANSFER_PROFILE_VERSION: &str = "0.1.0";
pub const CSMI_VALUE_TRANSFER_PROFILE_SCHEMA: &str =
    "https://csmi.brokk.ai/schema/profiles/value-transfer/0.1/schema.json";
pub const CSMI_C_CPP_RESOLUTION_PROFILE_ID: &str = "csmi.c-cpp-resolution";
pub const CSMI_C_CPP_RESOLUTION_PROFILE_VERSION: &str = "0.1.0";
pub const CSMI_C_CPP_RESOLUTION_PROFILE_SCHEMA: &str =
    "https://csmi.brokk.ai/schema/profiles/cpp/0.1/schema.json";
pub const CSMI_CPP_PROFILE_ID: &str = "csmi.cpp";
pub const CSMI_CPP_PROFILE_VERSION: &str = "0.1.0";
pub const CSMI_CPP_PROFILE_SCHEMA: &str =
    "https://csmi.brokk.ai/schema/profiles/cpp/0.1/schema.json";
pub const CSMI_CPP_DECLARATION_IDENTITY_SCHEME: &str = "csmi.cpp.declaration";
pub const CSMI_CPP_DECLARATION_IDENTITY_SCHEME_VERSION: &str = "0.1.0";
pub const CSMI_RUNTIME_VALUES_PROFILE_ID: &str = "csmi.runtime-values";
pub const CSMI_RUNTIME_VALUES_PROFILE_VERSION: &str = "0.1.0";
pub const CSMI_RUNTIME_VALUES_PROFILE_SCHEMA: &str =
    "https://csmi.brokk.ai/schema/profiles/runtime-values/0.1/schema.json";
pub const CSMI_COLLECTION_FLOW_PROFILE_ID: &str = "csmi.collection-flow";
pub const CSMI_COLLECTION_FLOW_PROFILE_VERSION: &str = "0.1.0";
pub const CSMI_COLLECTION_FLOW_PROFILE_SCHEMA: &str =
    "https://csmi.brokk.ai/schema/profiles/collection-flow/0.1/schema.json";

/// Typed payload for the CSMI collection-flow vocabulary.
///
/// The profile deliberately reuses core boundary roots and type expressions;
/// only collection-specific shapes, projections, and callback invocation
/// evidence are introduced here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCollectionFlowPayload {
    pub kind: CsmiCollectionFlowKind,
    pub callable: LocalId,
    #[serde(
        rename = "receiverSubstitution",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub receiver_substitution: Option<CsmiCollectionFlowSubstitution>,
    pub roots: Vec<CsmiCollectionFlowRoot>,
    pub transfers: Vec<CsmiCollectionFlowTransfer>,
    pub invocations: Vec<CsmiCollectionFlowInvocation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCollectionFlowKind {
    #[serde(rename = "collection-flow")]
    CollectionFlow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CsmiCollectionFlowSubstitution {
    ReceiverArguments { declaration: LocalId },
    Unknown { limitation: CsmiProfileLimitation },
    Unsupported { limitation: CsmiProfileLimitation },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCollectionFlowRoot {
    pub root: CsmiCollectionFlowBoundaryRoot,
    pub shape: CsmiCollectionFlowShape,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CsmiCollectionFlowBoundaryRoot {
    Input(CsmiInputBoundaryRoot),
    Output(CsmiOutputBoundaryRoot),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CsmiCollectionFlowShape {
    Value {
        #[serde(rename = "type")]
        r#type: CsmiTypeExpression,
    },
    Product {
        components: Vec<CsmiCollectionFlowShape>,
    },
    Keyed {
        key: Box<CsmiCollectionFlowShape>,
        value: Box<CsmiCollectionFlowShape>,
        #[serde(
            rename = "entryComponents",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        entry_components: Option<Vec<CsmiCollectionFlowEntryComponent>>,
    },
    Unknown {
        limitation: CsmiProfileLimitation,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiCollectionFlowEntryComponent {
    Key,
    Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCollectionFlowTransfer {
    pub source: CsmiInputLocation,
    pub destination: CsmiOutputLocation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCollectionFlowInvocation {
    pub callback: CsmiInputLocation,
    pub parameters: Vec<CsmiCollectionFlowShape>,
    pub arguments: Vec<CsmiCollectionFlowArgument>,
    pub timing: CsmiCollectionFlowTiming,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCollectionFlowArgument {
    pub source: CsmiInputLocation,
    pub parameter: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiCollectionFlowTiming {
    DuringCall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum CsmiRuntimeValuesPayload {
    #[serde(rename = "runtime-global-exposure")]
    RuntimeGlobalExposure(CsmiRuntimeGlobalExposure),
    #[serde(rename = "keyed-read-behavior")]
    KeyedReadBehavior(CsmiKeyedReadBehavior),
    #[serde(rename = "runtime-global-binding-evidence")]
    RuntimeGlobalBindingEvidence(CsmiRuntimeGlobalBindingEvidence),
    #[serde(rename = "keyed-read-observation")]
    KeyedReadObservation(CsmiKeyedReadObservation),
}

impl CsmiRuntimeValuesPayload {
    pub fn family(&self) -> &'static str {
        match self {
            Self::RuntimeGlobalExposure(_) => "runtime-global-exposures",
            Self::KeyedReadBehavior(_) => "keyed-read-behaviors",
            Self::RuntimeGlobalBindingEvidence(_) => "runtime-global-binding-evidence",
            Self::KeyedReadObservation(_) => "keyed-read-observations",
        }
    }

    pub fn record_id(&self) -> &str {
        match self {
            Self::RuntimeGlobalExposure(record) => &record.exposure_id,
            Self::KeyedReadBehavior(record) => &record.behavior_id,
            Self::RuntimeGlobalBindingEvidence(record) => &record.binding_evidence_id,
            Self::KeyedReadObservation(record) => &record.observation_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiRuntimeGlobalExposure {
    #[serde(rename = "exposureId")]
    pub exposure_id: LocalId,
    pub languages: Vec<String>,
    #[serde(rename = "bindingName")]
    pub binding_name: String,
    pub runtime: CsmiRuntimeApplicability,
    #[serde(rename = "runtimeProfileDigest")]
    pub runtime_profile_digest: String,
    #[serde(rename = "rootIdentity")]
    pub root_identity: CsmiRuntimeRootIdentity,
    pub members: Vec<LocalId>,
    pub activation: CsmiRuntimeExposureActivation,
    pub evidence: CsmiRuntimeEvidence,
    pub coverage: CsmiRuntimeCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiKeyedReadBehavior {
    #[serde(rename = "behaviorId")]
    pub behavior_id: LocalId,
    #[serde(rename = "exposureId")]
    pub exposure_id: LocalId,
    #[serde(rename = "containerMember")]
    pub container_member: LocalId,
    #[serde(rename = "acceptedKeys")]
    pub accepted_keys: CsmiRuntimeAcceptedKeys,
    #[serde(rename = "normalResult")]
    pub normal_result: CsmiRuntimeNormalResult,
    #[serde(rename = "exceptionBehavior")]
    pub exception_behavior: CsmiRuntimeExceptionBehavior,
    #[serde(rename = "mutationModel")]
    pub mutation_model: CsmiRuntimeMutationModel,
    pub materialization: CsmiRuntimeMaterialization,
    pub evidence: CsmiRuntimeEvidence,
    pub coverage: CsmiRuntimeCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiRuntimeGlobalBindingEvidence {
    #[serde(rename = "bindingEvidenceId")]
    pub binding_evidence_id: LocalId,
    #[serde(rename = "exposureId")]
    pub exposure_id: LocalId,
    pub activation: CsmiRuntimeActivationEvidence,
    pub language: String,
    pub dialect: String,
    #[serde(rename = "rootOccurrence")]
    pub root_occurrence: CsmiRuntimeSourceRange,
    #[serde(rename = "scopeIdentity")]
    pub scope_identity: CsmiRuntimeScopedIdentity,
    #[serde(rename = "lexicalBinding")]
    pub lexical_binding: CsmiRuntimeLexicalBinding,
    pub rebinding: CsmiRuntimeRebinding,
    pub evidence: CsmiRuntimeEvidence,
    pub coverage: CsmiRuntimeCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiKeyedReadObservation {
    #[serde(rename = "observationId")]
    pub observation_id: LocalId,
    #[serde(rename = "bindingEvidenceId")]
    pub binding_evidence_id: LocalId,
    #[serde(rename = "behaviorId")]
    pub behavior_id: LocalId,
    #[serde(rename = "baseValue")]
    pub base_value: CsmiRuntimeScopedIdentity,
    pub key: CsmiRuntimeStaticKey,
    #[serde(rename = "sourceForm")]
    pub source_form: CsmiRuntimeSourceForm,
    #[serde(rename = "loadOperation")]
    pub load_operation: CsmiRuntimeScopedIdentity,
    #[serde(rename = "resultValue")]
    pub result_value: CsmiRuntimeScopedIdentity,
    #[serde(rename = "observationPoint")]
    pub observation_point: CsmiRuntimeScopedIdentity,
    pub phase: CsmiRuntimeObservationPhase,
    pub expression: CsmiRuntimeSourceRange,
    #[serde(rename = "sourceOrigin")]
    pub source_origin: CsmiRuntimeSourceOrigin,
    #[serde(rename = "normalOutcome")]
    pub normal_outcome: CsmiRuntimeNormalOutcome,
    #[serde(rename = "exceptionOutcome")]
    pub exception_outcome: CsmiRuntimeExceptionOutcome,
    pub evidence: CsmiRuntimeEvidence,
    pub coverage: CsmiRuntimeCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiRuntimeEvidence {
    pub producer: AbsoluteUri,
    pub method: String,
    #[serde(rename = "inputsDigest")]
    pub inputs_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiRuntimeApplicability {
    #[serde(rename = "runtimeFamily")]
    pub runtime_family: String,
    #[serde(rename = "runtimeArtifact")]
    pub runtime_artifact: String,
    #[serde(rename = "runtimeArtifactDigest")]
    pub runtime_artifact_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    pub realm: String,
    #[serde(rename = "moduleMode")]
    pub module_mode: String,
    #[serde(rename = "initializationBoundary")]
    pub initialization_boundary: String,
    #[serde(
        rename = "hostAssumptions",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub host_assumptions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiRuntimeRootIdentity {
    pub scheme: String,
    #[serde(rename = "schemeVersion")]
    pub scheme_version: String,
    pub descriptors: Vec<CsmiRuntimeRootDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiRuntimeRootDescriptor {
    pub role: CsmiRuntimeRootRole,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeRootRole {
    Runtime,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiRuntimeSourceRange {
    pub resource: String,
    #[serde(rename = "resourceDigest")]
    pub resource_digest: String,
    #[serde(rename = "startByte")]
    pub start_byte: u64,
    #[serde(rename = "endByte")]
    pub end_byte: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiRuntimeScopedIdentity {
    #[serde(rename = "ownerDigest")]
    pub owner_digest: String,
    pub kind: CsmiRuntimeIdentityKind,
    #[serde(rename = "locatorDigest")]
    pub locator_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeIdentityKind {
    Scope,
    Value,
    Operation,
    Point,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiRuntimeActivationEvidence {
    pub outcome: CsmiRuntimeActivationOutcome,
    #[serde(rename = "runtimeProfileDigest")]
    pub runtime_profile_digest: String,
    #[serde(rename = "activeSetDigest")]
    pub active_set_digest: String,
    #[serde(rename = "activeExposureIds")]
    pub active_exposure_ids: Vec<LocalId>,
    #[serde(rename = "modelDigest")]
    pub model_digest: String,
    #[serde(rename = "activationSource")]
    pub activation_source: AbsoluteUri,
    #[serde(rename = "exposureId")]
    pub exposure_id: LocalId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeActivationOutcome {
    Matched,
    NotMatched,
    Indeterminate,
    Conflict,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiRuntimeCoverage {
    pub status: CsmiRuntimeCoverageStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<CsmiRuntimeCoverageLimitation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeCoverageStatus {
    Complete,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeCoverageLimitation {
    ActivationMissing,
    ActivationConflict,
    ActivationUnsupported,
    LexicalBindingIndeterminate,
    RebindingIndeterminate,
    MutationIncomplete,
    AccessorOrProxyIncomplete,
    MaterializationIncomplete,
    ExceptionBehaviorIndeterminate,
    DynamicKey,
    UnsupportedIndex,
    Cancelled,
    BudgetExhausted,
    StaleEvidence,
    AmbiguousOwner,
    CoverageLimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeExposureActivation {
    Enabled,
    Disabled,
    ReviewRequired,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeAcceptedKeys {
    StaticProperty,
    StaticIndex,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeNormalResult {
    ValueOrUndefined,
    Value,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeExceptionBehavior {
    Nonthrowing,
    MayThrow,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeMutationModel {
    PristineInputUntilWrite,
    OrdinaryMutable,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeMaterialization {
    Eager,
    Lazy,
    HostDefined,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeLexicalBinding {
    Absent,
    Present,
    Indeterminate,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeRebinding {
    Excluded,
    Present,
    Indeterminate,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum CsmiRuntimeStaticKey {
    Property(String),
    Index(u32),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeSourceForm {
    Dot,
    BracketString,
    BracketNumber,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeObservationPhase {
    BeforeEffects,
    AfterEffects,
    Exceptional,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeSourceOrigin {
    PristineRuntimeInput,
    Mutated,
    Indeterminate,
    NotApplicable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeNormalOutcome {
    Exact,
    Partial,
    Unsupported,
    Indeterminate,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRuntimeExceptionOutcome {
    Excluded,
    Possible,
    Unsupported,
    Indeterminate,
}

pub type LocalId = String;
pub type AbsoluteUri = String;
pub type CsmiJson = Value;

/// The two root document types accepted by the v0.1 JSON serialization.
///
/// The structs below use an untagged enum because the discriminator is a
/// serialized field rather than a Rust-only enum tag.  Validation still checks
/// the discriminator and all version/schema constants explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CsmiDocument {
    Semantic(CsmiSemanticDocument),
    Manifest(CsmiPackManifest),
}

pub type SemanticDocument = CsmiSemanticDocument;
pub type PackManifest = CsmiPackManifest;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiSemanticDocument {
    #[serde(rename = "documentType")]
    pub document_type: String,
    pub schema: String,
    #[serde(rename = "semanticModelVersion")]
    pub semantic_model_version: String,
    #[serde(rename = "serializationVersion")]
    pub serialization_version: String,
    #[serde(rename = "provenanceRecords")]
    pub provenance_records: Vec<CsmiProvenanceRecord>,
    #[serde(
        rename = "defaultProvenance",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub default_provenance: Option<LocalId>,
    #[serde(rename = "semanticModels")]
    pub semantic_models: Vec<CsmiSemanticModel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiPackManifest {
    #[serde(rename = "documentType")]
    pub document_type: String,
    pub schema: String,
    #[serde(rename = "packFormatVersion")]
    pub pack_format_version: String,
    pub assembler: CsmiProducerIdentity,
    pub license: String,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    pub resources: Vec<CsmiResourceDescriptor>,
    #[serde(rename = "derivedFrom", default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from: Vec<CsmiContentDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiSemanticModel {
    #[serde(rename = "artifactSelectors")]
    pub artifact_selectors: Vec<CsmiArtifactSelector>,
    #[serde(
        rename = "compatibilityConstraints",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub compatibility_constraints: Vec<CsmiCompatibilityConstraint>,
    #[serde(
        rename = "vocabularyUses",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub vocabulary_uses: Vec<CsmiVocabularyUse>,
    #[serde(
        rename = "consumerResolvedDependencies",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub consumer_resolved_dependencies: Vec<CsmiDeclarationDependency>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symbols: Vec<CsmiSymbolDefinition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declarations: Vec<CsmiDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<CsmiRelationship>,
    #[serde(
        rename = "procedureSummaries",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub procedure_summaries: Vec<CsmiProcedureSummary>,
    #[serde(
        rename = "extensionFacts",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub extension_facts: Vec<CsmiExtensionFact>,
    #[serde(
        rename = "completenessStatements",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub completeness_statements: Vec<CsmiCompletenessStatement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CsmiExtensionAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiProducerIdentity {
    pub identifier: AbsoluteUri,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiProvenanceRecord {
    pub id: LocalId,
    pub producer: CsmiProducerIdentity,
    #[serde(rename = "generationMethod")]
    pub generation_method: CsmiGenerationMethod,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<CsmiProvenanceInput>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(
        rename = "invocationId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub invocation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<CsmiDiagnosticMetadata>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiGenerationMethod {
    SourceAnalysis,
    BinaryAnalysis,
    MetadataConversion,
    ManualAuthoring,
    Composition,
    Mixed,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiProvenanceInput {
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<AbsoluteUri>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<CsmiArtifactDigest>,
    #[serde(
        rename = "packDigest",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pack_digest: Option<CsmiContentDigest>,
    #[serde(
        rename = "semanticDocumentDigest",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub semantic_document_digest: Option<CsmiContentDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiArtifactSelector {
    pub purl: String,
    #[serde(
        rename = "versionRange",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub version_range: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub digests: Vec<CsmiArtifactDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiArtifactDigest {
    pub algorithm: CsmiDigestAlgorithm,
    pub coverage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonicalization: Option<AbsoluteUri>,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiDigestAlgorithm {
    #[serde(rename = "sha-256")]
    Sha256,
    #[serde(rename = "sha-384")]
    Sha384,
    #[serde(rename = "sha-512")]
    Sha512,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiContentDigest {
    pub algorithm: CsmiContentDigestAlgorithm,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiContentDigestAlgorithm {
    #[serde(rename = "sha-256")]
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCompatibilityConstraint {
    pub vocabulary: String,
    pub version: String,
    pub value: CsmiJson,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiSymbolDefinition {
    pub id: LocalId,
    #[serde(
        rename = "artifactSelectors",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub artifact_selectors: Option<Vec<CsmiArtifactSelector>>,
    pub scheme: String,
    #[serde(rename = "schemeVersion")]
    pub scheme_version: String,
    pub stability: CsmiStability,
    pub descriptors: Vec<CsmiDescriptor>,
    #[serde(
        rename = "displayName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub display_name: Option<String>,
    #[serde(
        rename = "qualifiedDisplayName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub qualified_display_name: Option<String>,
    #[serde(
        rename = "nativeSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub native_signature: Option<String>,
    #[serde(
        rename = "documentationName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub documentation_name: Option<String>,
    #[serde(rename = "abiName", default, skip_serializing_if = "Option::is_none")]
    pub abi_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<CsmiSymbolOrigin>,
    #[serde(
        rename = "externalIdentities",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub external_identities: Vec<CsmiExternalIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<LocalId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CsmiExtensionAttachment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiStability {
    Portable,
    ArtifactLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiSymbolOrigin {
    Named,
    Generated,
    Synthetic,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiDescriptor {
    pub role: CsmiDescriptorRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disambiguator: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiDescriptorRole {
    Namespace,
    Type,
    Term,
    Callable,
    TypeParameter,
    ValueParameter,
    Meta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiExternalIdentity {
    pub scheme: String,
    pub version: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiDeclaration {
    pub symbol: LocalId,
    pub category: CsmiDeclarationCategory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<LocalId>,
    #[serde(
        rename = "genericParameters",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub generic_parameters: Vec<CsmiGenericParameter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callable: Option<CsmiCallableShape>,
    #[serde(
        rename = "aliasTarget",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub alias_target: Option<CsmiTypeExpression>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<LocalId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CsmiExtensionAttachment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiDeclarationCategory {
    Namespace,
    Type,
    TypeAlias,
    Value,
    Callable,
    TypeParameter,
    ValueParameter,
    Meta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiGenericParameter {
    pub position: u32,
    pub symbol: LocalId,
    pub kind: CsmiGenericParameterKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CsmiExtensionAttachment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiGenericParameterKind {
    Type,
    Value,
    Lifetime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCallableShape {
    pub kind: CsmiCallableKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<CsmiReceiver>,
    pub parameters: Vec<CsmiParameter>,
    pub results: Vec<CsmiResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CsmiExtensionAttachment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiCallableKind {
    Function,
    Method,
    Constructor,
    Accessor,
    Operator,
    Destructor,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiReceiver {
    pub kind: CsmiReceiverKind,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub receiver_type: Option<CsmiTypeExpression>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CsmiExtensionAttachment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiReceiverKind {
    Instance,
    Type,
    Extension,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiParameter {
    pub position: u32,
    pub binding: CsmiParameterBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<LocalId>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub parameter_type: Option<CsmiTypeExpression>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CsmiExtensionAttachment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiParameterBinding {
    PositionalOnly,
    PositionalOrNamed,
    NamedOnly,
    VariadicPositional,
    VariadicNamed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiResult {
    pub position: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub result_type: Option<CsmiTypeExpression>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CsmiExtensionAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CsmiTypeExpression {
    Unknown(CsmiUnknownType),
    Reference(CsmiReferenceType),
    Parameter(CsmiParameterType),
    Intrinsic(CsmiIntrinsicType),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiUnknownType {
    pub kind: CsmiUnknownTypeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiUnknownTypeKind {
    #[serde(rename = "unknown")]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiReferenceType {
    pub kind: CsmiReferenceTypeKind,
    pub symbol: LocalId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<CsmiTypeExpression>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiReferenceTypeKind {
    #[serde(rename = "reference")]
    Reference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiParameterType {
    pub kind: CsmiParameterTypeKind,
    pub symbol: LocalId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiParameterTypeKind {
    #[serde(rename = "parameter")]
    Parameter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiIntrinsicType {
    pub kind: CsmiIntrinsicTypeKind,
    pub vocabulary: String,
    pub version: String,
    pub identifier: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiIntrinsicTypeKind {
    #[serde(rename = "intrinsic")]
    Intrinsic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CsmiRelationship {
    Type(CsmiTypeRelationship),
    Member(CsmiMemberRelationship),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiTypeRelationship {
    pub subject: LocalId,
    pub predicate: CsmiTypePredicate,
    pub object: LocalId,
    #[serde(
        rename = "typeArguments",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub type_arguments: Vec<CsmiTypeExpression>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<LocalId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CsmiExtensionAttachment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiTypePredicate {
    Inherits,
    ConformsTo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiMemberRelationship {
    pub subject: LocalId,
    pub predicate: CsmiMemberPredicate,
    pub object: LocalId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<LocalId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CsmiExtensionAttachment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiMemberPredicate {
    Overrides,
    Implements,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiProcedureSummary {
    pub callable: LocalId,
    pub transfers: Vec<CsmiTransfer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CsmiExtensionAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiTransfer {
    pub source: CsmiInputLocation,
    pub destination: CsmiOutputLocation,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<LocalId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CsmiExtensionAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiInputLocation {
    pub root: CsmiInputBoundaryRoot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<CsmiProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiOutputLocation {
    pub root: CsmiOutputBoundaryRoot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<CsmiProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CsmiInputBoundaryRoot {
    Receiver(CsmiInputReceiverRoot),
    Parameter(CsmiInputParameterRoot),
    Capture(CsmiInputCaptureRoot),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CsmiOutputBoundaryRoot {
    Receiver(CsmiOutputReceiverRoot),
    Parameter(CsmiOutputParameterRoot),
    Capture(CsmiOutputCaptureRoot),
    Result(CsmiOutputResultRoot),
    Exception(CsmiOutputExceptionRoot),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiInputReceiverRoot {
    pub phase: CsmiInputPhase,
    pub role: CsmiReceiverRootRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiInputPhase {
    #[serde(rename = "input")]
    Input,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiReceiverRootRole {
    #[serde(rename = "receiver")]
    Receiver,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiInputParameterRoot {
    pub phase: CsmiInputPhase,
    pub role: CsmiParameterRootRole,
    pub position: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiParameterRootRole {
    #[serde(rename = "parameter")]
    Parameter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiInputCaptureRoot {
    pub phase: CsmiInputPhase,
    pub role: CsmiCaptureRootRole,
    pub symbol: LocalId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCaptureRootRole {
    #[serde(rename = "capture")]
    Capture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiOutputReceiverRoot {
    pub phase: CsmiOutputPhase,
    pub role: CsmiReceiverRootRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiOutputPhase {
    #[serde(rename = "output")]
    Output,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiOutputParameterRoot {
    pub phase: CsmiOutputPhase,
    pub role: CsmiParameterRootRole,
    pub position: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiOutputCaptureRoot {
    pub phase: CsmiOutputPhase,
    pub role: CsmiCaptureRootRole,
    pub symbol: LocalId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiOutputResultRoot {
    pub phase: CsmiOutputPhase,
    pub role: CsmiResultRootRole,
    pub position: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiResultRootRole {
    #[serde(rename = "result")]
    Result,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiOutputExceptionRoot {
    pub phase: CsmiOutputPhase,
    pub role: CsmiExceptionRootRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiExceptionRootRole {
    #[serde(rename = "exception")]
    Exception,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiProjection {
    pub scheme: String,
    #[serde(rename = "schemeVersion")]
    pub scheme_version: String,
    pub steps: Vec<CsmiProjectionStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiProjectionStep {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<CsmiJson>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCompletenessStatement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vocabulary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub family: String,
    pub scope: CsmiJson,
    pub status: CsmiCoverageStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<CsmiLimitation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<LocalId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CsmiExtensionAttachment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiCoverageStatus {
    Unknown,
    Partial,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiLimitation {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<CsmiDiagnosticMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiDiagnosticMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiVocabularyUse {
    pub identifier: String,
    pub version: String,
    pub schema: AbsoluteUri,
    pub requirement: CsmiVocabularyRequirement,
    pub affects: Vec<CsmiAffectedUnit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiVocabularyRequirement {
    Optional,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CsmiAffectedUnit {
    FactFamily(CsmiAffectedFactFamily),
    CoreSlot(CsmiAffectedCoreSlot),
    Attachment(CsmiAffectedAttachment),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiAffectedFactFamily {
    pub kind: CsmiAffectedFactFamilyKind,
    pub family: String,
    pub scope: CsmiJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiAffectedFactFamilyKind {
    #[serde(rename = "fact-family")]
    FactFamily,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiAffectedCoreSlot {
    pub kind: CsmiAffectedCoreSlotKind,
    pub slot: String,
    pub target: CsmiJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiAffectedCoreSlotKind {
    #[serde(rename = "core-slot")]
    CoreSlot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiAffectedAttachment {
    pub kind: CsmiAffectedAttachmentKind,
    #[serde(rename = "attachmentPoint")]
    pub attachment_point: String,
    pub target: CsmiJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiAffectedAttachmentKind {
    #[serde(rename = "attachment")]
    Attachment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiExtensionAttachment {
    pub vocabulary: String,
    pub version: String,
    pub payload: CsmiJson,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiExtensionFact {
    pub vocabulary: String,
    pub version: String,
    pub family: String,
    pub scope: CsmiJson,
    pub payload: CsmiJson,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<LocalId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<CsmiExtensionAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiDeclarationDependency {
    pub symbol: LocalId,
    pub aspect: CsmiDependencyAspect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<CsmiRelationshipPredicate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<LocalId>,
    #[serde(
        rename = "typeArguments",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub type_arguments: Vec<CsmiTypeExpression>,
    #[serde(
        rename = "completeSet",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub complete_set: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiDependencyAspect {
    Category,
    Owner,
    GenericParameters,
    CallableShape,
    AliasTarget,
    Relationships,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiRelationshipPredicate {
    Inherits,
    ConformsTo,
    Overrides,
    Implements,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiResourceDescriptor {
    pub path: String,
    pub role: CsmiResourceRole,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub size: u64,
    pub digest: CsmiContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(
        rename = "schemaIdentifier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub schema_identifier: Option<AbsoluteUri>,
    #[serde(
        rename = "licenseReference",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub license_reference: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiResourceRole {
    SemanticDocument,
    VocabularySchema,
    LicenseText,
    Notice,
    Auxiliary,
}

impl CsmiDocument {
    pub fn as_semantic_document(&self) -> Option<&CsmiSemanticDocument> {
        match self {
            Self::Semantic(document) => Some(document),
            Self::Manifest(_) => None,
        }
    }

    pub fn as_pack_manifest(&self) -> Option<&CsmiPackManifest> {
        match self {
            Self::Semantic(_) => None,
            Self::Manifest(manifest) => Some(manifest),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CsmiValueTransferProfilePayload {
    Transfer(CsmiValueTransferAttachment),
    TypeValue(CsmiTypeValueSemantics),
    ImplicitOperation(CsmiImplicitOperationFact),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiValueTransferAttachment {
    pub kind: CsmiValueTransferAttachmentKind,
    #[serde(rename = "transferKind")]
    pub transfer_kind: CsmiValueTransferKind,
    pub operation: CsmiValueTransferOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiValueTransferAttachmentKind {
    #[serde(rename = "transfer")]
    Transfer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CsmiValueTransferKind {
    Copy {},
    AggregateCopy {},
    Move { invalidation: CsmiMoveInvalidation },
    Conversion { preservation: CsmiValuePreservation },
    Boxing {},
    Unboxing {},
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiMoveInvalidation {
    Invalidated,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiValuePreservation {
    Identity,
    Preserving,
    Changing,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CsmiValueTransferOperation {
    None {},
    Implicit { symbol: LocalId },
    Unknown { limitation: CsmiProfileLimitation },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiProfileLimitation {
    pub kind: CsmiProfileLimitationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiProfileLimitationKind {
    BudgetExhausted,
    Cancelled,
    Unsupported,
    UnresolvedIdentity,
    AmbiguousIdentity,
    IncompleteInput,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiTypeValueSemantics {
    pub kind: CsmiTypeValueSemanticsKind,
    pub r#type: LocalId,
    pub aspect: CsmiTypeValueSemanticsAspect,
    pub semantics: CsmiTypeSemantics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiTypeValueSemanticsKind {
    #[serde(rename = "type-value-semantics")]
    TypeValueSemantics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiTypeValueSemanticsAspect {
    Copy,
    Move,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CsmiTypeSemantics {
    Trivial {},
    ViaMember {
        member: LocalId,
    },
    Invalidating {},
    Unknown {
        limitation: CsmiProfileLimitation,
    },
    Unsupported {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiImplicitOperationFact {
    pub kind: CsmiImplicitOperationKind,
    pub symbol: LocalId,
    pub owner: LocalId,
    pub operation: CsmiImplicitOperationRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<LocalId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiImplicitOperationKind {
    #[serde(rename = "implicit-operation")]
    ImplicitOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiImplicitOperationRole {
    CopyConstructor,
    MoveConstructor,
    CopyAssignment,
    MoveAssignment,
    ConversionOperator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CsmiCppProfilePayload {
    ResolutionContext(CsmiResolutionContext),
    TypeAlias(CsmiCppTypeAliasFact),
    SpecialMember(Box<CsmiCppSpecialMemberFact>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCppArtifactDigest {
    pub algorithm: CsmiCppDigestAlgorithm,
    pub coverage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonicalization: Option<AbsoluteUri>,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCppDigestAlgorithm {
    #[serde(rename = "sha-256")]
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCppArtifactSelector {
    pub purl: String,
    #[serde(rename = "digests")]
    pub digests: Vec<CsmiCppArtifactDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCppDescriptor {
    pub role: CsmiCppDescriptorRole,
    pub name: String,
    pub disambiguator: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiCppDescriptorRole {
    Namespace,
    Type,
    Callable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCppSymbolKey {
    #[serde(rename = "artifactSelectors")]
    pub artifact_selectors: Vec<CsmiCppArtifactSelector>,
    pub scheme: String,
    #[serde(rename = "schemeVersion")]
    pub scheme_version: String,
    pub stability: CsmiCppIdentityStability,
    pub descriptors: Vec<CsmiCppDescriptor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCppIdentityStability {
    #[serde(rename = "portable")]
    Portable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CsmiCppCanonicalType {
    Fundamental(CsmiCppFundamentalType),
    Declared(CsmiCppDeclaredType),
    TemplateSpecialization(CsmiCppTemplateSpecialization),
    Qualified(CsmiCppQualifiedType),
    Reference(CsmiCppReferenceType),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCppFundamentalType {
    pub kind: CsmiCppFundamentalTypeKind,
    pub name: CsmiCppFundamentalTypeName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCppFundamentalTypeKind {
    #[serde(rename = "fundamental")]
    Fundamental,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCppFundamentalTypeName {
    #[serde(rename = "char")]
    Char,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCppDeclaredType {
    pub kind: CsmiCppDeclaredTypeKind,
    pub symbol: CsmiCppSymbolKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCppDeclaredTypeKind {
    #[serde(rename = "declared")]
    Declared,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCppTemplateSpecialization {
    pub kind: CsmiCppTemplateSpecializationKind,
    pub primary: CsmiCppSymbolKey,
    pub arguments: Vec<CsmiCppCanonicalType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCppTemplateSpecializationKind {
    #[serde(rename = "template-specialization")]
    TemplateSpecialization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCppQualifiedType {
    pub kind: CsmiCppQualifiedTypeKind,
    pub qualifiers: Vec<CsmiCppTypeQualifier>,
    pub r#type: Box<CsmiCppCanonicalType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCppQualifiedTypeKind {
    #[serde(rename = "qualified")]
    Qualified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiCppTypeQualifier {
    Const,
    Volatile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCppReferenceType {
    pub kind: CsmiCppReferenceTypeKind,
    #[serde(rename = "referenceKind")]
    pub reference_kind: CsmiCppReferenceKind,
    pub referent: Box<CsmiCppCanonicalType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCppReferenceTypeKind {
    #[serde(rename = "reference")]
    Reference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiCppReferenceKind {
    Lvalue,
    Rvalue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCppDirectHeader {
    #[serde(rename = "includeName")]
    pub include_name: String,
    pub artifact: CsmiCppArtifactSelector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiResolutionContext {
    pub kind: CsmiResolutionContextKind,
    pub language: CsmiCppLanguage,
    #[serde(rename = "translationUnit")]
    pub translation_unit: String,
    #[serde(rename = "compileArgumentsDigest")]
    pub compile_arguments_digest: String,
    #[serde(rename = "directHeaders")]
    pub direct_headers: Vec<CsmiCppDirectHeader>,
    #[serde(rename = "headerClosure")]
    pub header_closure: CsmiCompleteHeaderClosure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiResolutionContextKind {
    #[serde(rename = "resolution-context")]
    ResolutionContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCppLanguage {
    #[serde(rename = "c")]
    C,
    #[serde(rename = "c++")]
    Cpp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCompleteHeaderClosure {
    #[serde(rename = "complete")]
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCppResolutionContext {
    pub vocabulary: CsmiCCppResolutionVocabulary,
    pub version: String,
    #[serde(rename = "contextDigest")]
    pub context_digest: String,
    pub language: CsmiCppProfileLanguage,
    #[serde(rename = "headerClosure")]
    pub header_closure: CsmiCompleteHeaderClosure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCCppResolutionVocabulary {
    #[serde(rename = "csmi.c-cpp-resolution")]
    CCppResolution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCppProfileLanguage {
    #[serde(rename = "c++")]
    Cpp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCppTypeAliasFact {
    pub kind: CsmiCppTypeAliasKind,
    pub language: CsmiCppProfileLanguage,
    pub alias: LocalId,
    pub target: CsmiCppCanonicalType,
    #[serde(rename = "resolutionContext")]
    pub resolution_context: CsmiCppResolutionContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCppTypeAliasKind {
    #[serde(rename = "type-alias")]
    TypeAlias,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCppCallableSignature {
    #[serde(rename = "callableKind")]
    pub callable_kind: CsmiCppCallableKind,
    pub owner: CsmiCppSymbolKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<CsmiCppCanonicalType>,
    pub parameters: Vec<CsmiCppCanonicalType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<CsmiCppCanonicalType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiCppCallableKind {
    Constructor,
    Method,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsmiCppSpecialMemberFact {
    pub kind: CsmiCppSpecialMemberKind,
    pub language: CsmiCppProfileLanguage,
    pub owner: LocalId,
    pub member: LocalId,
    pub operation: CsmiCppSpecialMemberOperation,
    pub signature: CsmiCppCallableSignature,
    #[serde(rename = "memberDisambiguator")]
    pub member_disambiguator: String,
    #[serde(rename = "resolutionContext")]
    pub resolution_context: CsmiCppResolutionContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsmiCppSpecialMemberKind {
    #[serde(rename = "special-member")]
    SpecialMember,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CsmiCppSpecialMemberOperation {
    CopyConstructor,
    CopyAssignment,
    MoveConstructor,
}

#[cfg(test)]
mod profile_payload_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn value_transfer_attachment_round_trips() {
        let payload = CsmiValueTransferProfilePayload::Transfer(CsmiValueTransferAttachment {
            kind: CsmiValueTransferAttachmentKind::Transfer,
            transfer_kind: CsmiValueTransferKind::Move {
                invalidation: CsmiMoveInvalidation::Invalidated,
            },
            operation: CsmiValueTransferOperation::Unknown {
                limitation: CsmiProfileLimitation {
                    kind: CsmiProfileLimitationKind::UnresolvedIdentity,
                    message: None,
                },
            },
        });
        let value = serde_json::to_value(&payload).expect("payload serializes");
        assert_eq!(
            value,
            json!({
                "kind": "transfer",
                "transferKind": {"kind": "move", "invalidation": "invalidated"},
                "operation": {
                    "kind": "unknown",
                    "limitation": {"kind": "unresolved-identity"},
                },
            })
        );
        assert_eq!(
            serde_json::from_value::<CsmiValueTransferProfilePayload>(value)
                .expect("payload parses"),
            payload
        );
    }

    #[test]
    fn cpp_type_alias_round_trips() {
        let payload = CsmiCppProfilePayload::TypeAlias(CsmiCppTypeAliasFact {
            kind: CsmiCppTypeAliasKind::TypeAlias,
            language: CsmiCppProfileLanguage::Cpp,
            alias: "alias".to_string(),
            target: CsmiCppCanonicalType::Fundamental(CsmiCppFundamentalType {
                kind: CsmiCppFundamentalTypeKind::Fundamental,
                name: CsmiCppFundamentalTypeName::Char,
            }),
            resolution_context: CsmiCppResolutionContext {
                vocabulary: CsmiCCppResolutionVocabulary::CCppResolution,
                version: "0.1.0".to_string(),
                context_digest: "0".repeat(64),
                language: CsmiCppProfileLanguage::Cpp,
                header_closure: CsmiCompleteHeaderClosure::Complete,
            },
        });
        let value = serde_json::to_value(&payload).expect("payload serializes");
        assert_eq!(value["kind"], "type-alias");
        assert_eq!(value["language"], "c++");
        assert_eq!(
            serde_json::from_value::<CsmiCppProfilePayload>(value).expect("payload parses"),
            payload
        );
    }

    #[test]
    fn collection_flow_payload_round_trips_typed_projection() {
        let payload = CsmiCollectionFlowPayload {
            kind: CsmiCollectionFlowKind::CollectionFlow,
            callable: "normalize".to_owned(),
            receiver_substitution: None,
            roots: vec![CsmiCollectionFlowRoot {
                root: CsmiCollectionFlowBoundaryRoot::Input(CsmiInputBoundaryRoot::Parameter(
                    CsmiInputParameterRoot {
                        phase: CsmiInputPhase::Input,
                        role: CsmiParameterRootRole::Parameter,
                        position: 0,
                    },
                )),
                shape: CsmiCollectionFlowShape::Keyed {
                    key: Box::new(CsmiCollectionFlowShape::Value {
                        r#type: CsmiTypeExpression::Unknown(CsmiUnknownType {
                            kind: CsmiUnknownTypeKind::Unknown,
                        }),
                    }),
                    value: Box::new(CsmiCollectionFlowShape::Value {
                        r#type: CsmiTypeExpression::Unknown(CsmiUnknownType {
                            kind: CsmiUnknownTypeKind::Unknown,
                        }),
                    }),
                    entry_components: Some(vec![
                        CsmiCollectionFlowEntryComponent::Key,
                        CsmiCollectionFlowEntryComponent::Value,
                    ]),
                },
            }],
            transfers: vec![CsmiCollectionFlowTransfer {
                source: CsmiInputLocation {
                    root: CsmiInputBoundaryRoot::Parameter(CsmiInputParameterRoot {
                        phase: CsmiInputPhase::Input,
                        role: CsmiParameterRootRole::Parameter,
                        position: 0,
                    }),
                    projection: Some(CsmiProjection {
                        scheme: CSMI_COLLECTION_FLOW_PROFILE_ID.to_owned(),
                        scheme_version: CSMI_COLLECTION_FLOW_PROFILE_VERSION.to_owned(),
                        steps: vec![
                            CsmiProjectionStep {
                                kind: "entry".to_owned(),
                                args: Some(serde_json::json!({
                                    "key": {"kind": "all"}
                                })),
                            },
                            CsmiProjectionStep {
                                kind: "entry-value".to_owned(),
                                args: None,
                            },
                        ],
                    }),
                },
                destination: CsmiOutputLocation {
                    root: CsmiOutputBoundaryRoot::Result(CsmiOutputResultRoot {
                        phase: CsmiOutputPhase::Output,
                        role: CsmiResultRootRole::Result,
                        position: 0,
                    }),
                    projection: None,
                },
            }],
            invocations: Vec::new(),
        };
        let value = serde_json::to_value(&payload).expect("payload serializes");
        assert_eq!(value["kind"], "collection-flow");
        assert_eq!(
            value["transfers"][0]["source"]["projection"]["scheme"],
            CSMI_COLLECTION_FLOW_PROFILE_ID
        );
        assert_eq!(
            serde_json::from_value::<CsmiCollectionFlowPayload>(value).expect("payload parses"),
            payload
        );
    }
}
