use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const SEMANTIC_MODEL_SCHEMA_VERSION: u32 = 1;

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
    pub type_parameters: Vec<String>,
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
    Enum,
    Record,
    Module,
    TypeAlias,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HierarchyFact {
    pub hierarchy_kind: HierarchyKind,
    pub target: TypeRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HierarchyKind {
    Extends,
    Implements,
    UsesTrait,
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
pub struct Signature {
    #[serde(default)]
    pub type_parameters: Vec<String>,
    #[serde(default)]
    pub parameters: Vec<Parameter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returns: Option<TypeRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    Wildcard {
        variance: WildcardVariance,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bound: Option<Box<TypeRef>>,
    },
    Tuple {
        elements: Vec<TypeRef>,
    },
    Function {
        parameters: Vec<TypeRef>,
        result: Box<TypeRef>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    LanguageConstruct { construct: String },
    Annotation { name: String },
    MacroInvocation { name: String },
    GeneratorInvocation { name: String },
    ResolvedOwner { owner: String },
    ResolvedCall { owner: String, name: String },
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
    ResolvedOwner,
    Argument { index: u32 },
    Arguments { from: u32 },
    AnnotationArgument { name: String },
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
        owner: TemplateExpression,
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
        }
    }
}
