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
pub const CSMI_NORMATIVE_COMMIT: &str = "a4386f51fc060608da61e81aca4150d2af72f2b5";

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
