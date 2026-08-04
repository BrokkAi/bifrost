use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::analyzer::dataflow::{
    MAX_AMBIGUOUS_SUMMARY_CALLEES, MAX_EXTERNAL_SUMMARY_MODEL_ID_BYTES,
    MAX_SUMMARY_BOUNDARY_BINDINGS, MAX_SUMMARY_EFFECT_REFERENCES, MAX_SUMMARY_EFFECTS,
    MAX_SUMMARY_TRANSFERS, SUMMARY_SCHEMA_VERSION,
};

pub const SEMANTIC_MODEL_SCHEMA_VERSION: u32 = 1;
pub const PROCEDURE_SUMMARY_CONTRACT_VERSION: u32 = SUMMARY_SCHEMA_VERSION;
pub const MAX_PROCEDURE_SUMMARY_ORDINAL: u32 = 65_535;
pub const MAX_PROCEDURE_SUMMARY_LOCATIONS: usize = MAX_SUMMARY_BOUNDARY_BINDINGS;
pub const MAX_PROCEDURE_SUMMARY_TRANSFERS: usize = MAX_SUMMARY_TRANSFERS;
pub const MAX_PROCEDURE_SUMMARY_EFFECTS: usize = MAX_SUMMARY_EFFECTS;
pub const MAX_PROCEDURE_SUMMARY_AMBIGUOUS_CALLEES: usize = MAX_AMBIGUOUS_SUMMARY_CALLEES;
pub const MAX_PROCEDURE_SUMMARY_EFFECT_REFERENCES: usize = MAX_SUMMARY_EFFECT_REFERENCES;
pub const MAX_PROCEDURE_SUMMARY_MODEL_ID_BYTES: usize = MAX_EXTERNAL_SUMMARY_MODEL_ID_BYTES;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredSemanticModelPack {
    #[schemars(range(min = 1, max = 1))]
    pub schema_version: u32,
    pub pack_id: String,
    pub version: String,
    pub producer: Producer,
    pub language: String,
    pub ecosystem: String,
    pub compatibility: Compatibility,
    pub provenance: Provenance,
    pub license: String,
    pub completeness: Completeness,
    pub safety: Safety,
    pub shards: Vec<AuthoredShard>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Producer {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Compatibility {
    pub bifrost: String,
    #[serde(default)]
    pub toolchains: Vec<VersionConstraint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VersionConstraint {
    pub name: String,
    pub requirement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Partial,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Safety {
    #[serde(default)]
    pub generated_code_only: bool,
    #[serde(default)]
    pub review_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredShard {
    pub id: String,
    pub activation: Vec<ActivationSelector>,
    pub payload: AuthoredPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthoredPayload {
    DeclarationFacts {
        #[serde(default)]
        types: Vec<TypeFact>,
        #[serde(default)]
        members: Vec<MemberFact>,
        #[serde(default)]
        relations: Vec<RelationFact>,
    },
    GeneratorRules {
        rules: Vec<GeneratorRule>,
    },
    ProcedureSummaries {
        summaries: Vec<AuthoredProcedureSummary>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredProcedureSummary {
    pub id: String,
    pub target: AuthoredProcedureTarget,
    pub completeness: Completeness,
    #[serde(default)]
    pub locations: Vec<AuthoredSummaryLocation>,
    pub transfers: Vec<AuthoredSummaryTransfer>,
    #[serde(default)]
    pub effects: Vec<AuthoredSummaryEffect>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredProcedureTarget {
    pub path: String,
    pub symbol: String,
    #[serde(default)]
    pub has_receiver: bool,
    pub parameter_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredSummaryLocation {
    pub id: String,
    pub location_kind: AuthoredSummaryLocationKind,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthoredSummaryLocationKind {
    Capture,
    Heap,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthoredSummaryInput {
    Receiver {},
    Parameter {
        #[schemars(range(max = 65535))]
        ordinal: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthoredSummaryOutput {
    NormalReturn {},
    Receiver {},
    Capture { location: String },
    Heap { location: String },
    ExceptionalReturn {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredSummaryTransfer {
    pub input: AuthoredSummaryInput,
    pub exit_kind: AuthoredSummaryExitKind,
    pub output: AuthoredSummaryOutput,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthoredSummaryExitKind {
    Normal,
    Exceptional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthoredSummaryEffect {
    Allocation {
        event: String,
        output: AuthoredSummaryOutput,
    },
    Call {
        event: String,
        callee: String,
    },
    Escape {
        event: String,
        input: AuthoredSummaryInput,
    },
    UnknownCall {
        event: String,
        input: AuthoredSummaryInput,
    },
    UnknownCallBoundary {
        event: String,
    },
    AmbiguousCall {
        event: String,
        input: AuthoredSummaryInput,
        candidates: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivationSelector {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<NameSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<NameSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<NameSelector>,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub configurations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NameSelector {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeFact {
    pub id: String,
    pub name: String,
    pub type_kind: TypeKind,
    pub visibility: Visibility,
    #[serde(default)]
    pub is_abstract: bool,
    #[serde(default)]
    pub is_sealed: bool,
    #[serde(default)]
    pub has_explicit_type_terms: bool,
    #[serde(default)]
    pub type_parameters: Vec<String>,
    #[serde(default)]
    pub type_parameter_constraints: Vec<TypeParameterConstraint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub underlying_type: Option<StructuredTypeExpression>,
    #[serde(default)]
    pub embedded_types: Vec<EmbeddedTypeFact>,
    #[serde(default)]
    pub hierarchy: Vec<HierarchyFact>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub extension_surfaces: Vec<String>,
    pub locator: Locator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    Class,
    Annotation,
    Delegate,
    Interface,
    Trait,
    Struct,
    Union,
    Enum,
    Record,
    Module,
    TypeAlias,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HierarchyFact {
    pub hierarchy_kind: HierarchyKind,
    pub target: TypeRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration_ordinal: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HierarchyKind {
    Extends,
    Implements,
    UsesTrait,
    MixinInclude,
    MixinPrepend,
    MixinExtend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberFact {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub member_kind: MemberKind,
    pub visibility: Visibility,
    #[serde(default)]
    pub is_static: bool,
    #[serde(default)]
    pub is_abstract: bool,
    #[serde(default)]
    pub is_virtual: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<ReceiverFact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_receiver: Option<TypeRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extension_receiver_constraints: Vec<TypeRef>,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub locator: Locator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemberKind {
    Constructor,
    Method,
    Function,
    Field,
    Property,
    Constant,
    Static,
    Macro,
    Event,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Protected,
    Internal,
    ProtectedInternal,
    Package,
    Private,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StructuredTypeExpression {
    pub display: String,
    #[serde(default)]
    pub referenced_types: Vec<TypeRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeParameterConstraint {
    pub parameter: String,
    pub constraint: StructuredTypeExpression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedTypeFact {
    pub target: TypeRef,
    #[serde(default)]
    pub pointer: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiverFact {
    #[serde(default)]
    pub pointer: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    #[serde(default)]
    pub type_parameters: Vec<String>,
    #[serde(default)]
    pub parameters: Vec<Parameter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returns: Option<TypeRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Parameter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub r#type: TypeRef,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub variadic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypeRef {
    Named {
        name: String,
        #[serde(default)]
        arguments: Vec<TypeRef>,
        #[serde(default)]
        nullable: bool,
    },
    Declared {
        id: String,
        #[serde(default)]
        arguments: Vec<TypeRef>,
        #[serde(default)]
        nullable: bool,
    },
    TypeParameter {
        name: String,
    },
    Array {
        element: Box<TypeRef>,
    },
    ByRef {
        element: Box<TypeRef>,
    },
    Pointer {
        element: Box<TypeRef>,
    },
    Slice {
        element: Box<TypeRef>,
    },
    FixedArray {
        element: Box<TypeRef>,
        length: String,
    },
    Map {
        key: Box<TypeRef>,
        value: Box<TypeRef>,
    },
    Channel {
        element: Box<TypeRef>,
        direction: ChannelDirection,
    },
    Wildcard {
        variance: WildcardVariance,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bound: Option<Box<TypeRef>>,
    },
    Tuple {
        elements: Vec<TypeRef>,
    },
    Function {
        parameters: Vec<Parameter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Box<TypeRef>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChannelDirection {
    Bidirectional,
    Receive,
    Send,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WildcardVariance {
    Any,
    Extends,
    Super,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Locator {
    Source {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        symbol: Option<String>,
    },
    Artifact {
        path: String,
        symbol: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationFact {
    pub id: String,
    pub relation_kind: RelationKind,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    NavigatesTo,
    References,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GeneratorRule {
    pub id: String,
    pub trigger: RuleTrigger,
    #[serde(default)]
    pub captures: Vec<CaptureDeclaration>,
    pub emissions: Vec<RuleEmission>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleTrigger {
    LanguageConstruct {
        construct: String,
    },
    Annotation {
        name: String,
    },
    AnnotatedField {
        annotation: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        excluded_annotations: Vec<String>,
        owner_annotation_path: Vec<String>,
    },
    MacroInvocation {
        name: String,
    },
    GeneratorInvocation {
        name: String,
    },
    ResolvedOwner {
        owner: String,
    },
    ResolvedCall {
        owner: String,
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureDeclaration {
    pub name: String,
    pub binding: CaptureBinding,
    pub value_kind: CaptureValueKind,
    pub cardinality: CaptureCardinality,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureBinding {
    pub source: CaptureSource,
    pub projection: CaptureProjection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureSource {
    MatchedNode,
    EnclosingDeclaration,
    OwningType,
    /// Direct authored fields that supply generated members. A field-level
    /// annotation produces that field; a type-level annotation produces its
    /// direct fields.
    OwnedFields,
    OwnedMutableFields,
    ResolvedOwner,
    Argument {
        index: u32,
    },
    Arguments {
        from: u32,
    },
    AnnotationArgument {
        name: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaptureProjection {
    Name,
    StableId,
    Type,
    Text,
    Path,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaptureValueKind {
    Identifier,
    StableId,
    Type,
    String,
    Path,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaptureCardinality {
    One,
    Optional,
    Many,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleEmission {
    Declaration {
        id: TemplateExpression,
        name: TemplateExpression,
        /// A capture-backed authored location for the emitted declaration.
        /// The runtime uses a stable model URI when this expression has no
        /// exact authored anchor.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        anchor: Option<TemplateExpression>,
        declaration: EmittedDeclaration,
    },
    Alias {
        id: TemplateExpression,
        from: TemplateExpression,
        to: TemplateExpression,
    },
    Relation {
        id: TemplateExpression,
        relation_kind: RelationKind,
        from: TemplateExpression,
        to: TemplateExpression,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EmittedDeclaration {
    Type {
        type_kind: TypeKind,
        visibility: Visibility,
        #[serde(default)]
        is_abstract: bool,
        #[serde(default)]
        is_sealed: bool,
        #[serde(default)]
        type_parameters: Vec<TemplateExpression>,
        #[serde(default)]
        hierarchy: Vec<TemplateHierarchyFact>,
        #[serde(default)]
        extension_surfaces: Vec<TemplateExpression>,
    },
    Member {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner: Option<TemplateExpression>,
        member_kind: MemberKind,
        visibility: Visibility,
        #[serde(default)]
        is_static: bool,
        #[serde(default)]
        is_abstract: bool,
        #[serde(default)]
        is_virtual: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<TemplateSignature>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemplateHierarchyFact {
    pub hierarchy_kind: HierarchyKind,
    pub target: TemplateTypeRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemplateSignature {
    #[serde(default)]
    pub type_parameters: Vec<TemplateExpression>,
    #[serde(default)]
    pub parameters: Vec<TemplateParameter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returns: Option<TemplateTypeRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemplateParameter {
    pub name: TemplateExpression,
    pub r#type: TemplateTypeRef,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub variadic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TemplateTypeRef {
    Named {
        name: TemplateExpression,
        #[serde(default)]
        arguments: Vec<TemplateTypeRef>,
        #[serde(default)]
        nullable: bool,
    },
    Capture {
        name: String,
    },
    Array {
        element: Box<TemplateTypeRef>,
    },
    ByRef {
        element: Box<TemplateTypeRef>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum TemplateExpression {
    Literal {
        value: String,
    },
    Capture {
        name: String,
    },
    Concat {
        values: Vec<TemplateExpression>,
    },
    Transform {
        transform: AsciiTransform,
        value: Box<TemplateExpression>,
    },
    Conditional {
        condition: TemplateCondition,
        #[serde(rename = "then")]
        then_value: Box<TemplateExpression>,
        #[serde(rename = "else")]
        else_value: Box<TemplateExpression>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum TemplateCondition {
    Equals {
        left: Box<TemplateExpression>,
        right: Box<TemplateExpression>,
    },
    StartsWith {
        value: Box<TemplateExpression>,
        prefix: Box<TemplateExpression>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AsciiTransform {
    Lowercase,
    Uppercase,
    SnakeCase,
    KebabCase,
    PascalCase,
    CamelCase,
}

impl AuthoredPayload {
    pub(crate) fn record_count(&self) -> usize {
        match self {
            Self::DeclarationFacts {
                types,
                members,
                relations,
            } => types.len() + members.len() + relations.len(),
            Self::GeneratorRules { rules } => rules.len(),
            Self::ProcedureSummaries { summaries } => summaries.len(),
        }
    }
}

pub(crate) fn normalize_artifact_locator_paths(pack: &mut AuthoredSemanticModelPack, path: &str) {
    for shard in &mut pack.shards {
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &mut shard.payload else {
            continue;
        };
        for locator in types
            .iter_mut()
            .map(|fact| &mut fact.locator)
            .chain(members.iter_mut().map(|fact| &mut fact.locator))
        {
            if let Locator::Artifact {
                path: locator_path, ..
            } = locator
            {
                *locator_path = path.to_owned();
            }
        }
    }
}
