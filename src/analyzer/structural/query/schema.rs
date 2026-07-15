//! Declarative metadata for the public CodeQuery/RQL vocabulary.
//!
//! The registries in this module are deliberately executable metadata: parser
//! and validator dispatch use the generated enums, while the REPL and editor
//! use the same signatures and descriptions. Adding an entry without help or
//! a value shape is therefore a macro error, and every handler must match the
//! generated enum exhaustively.

use crate::analyzer::usages::{ReferenceKind, UsageHitSurface, UsageProof};

use super::ir::{MAX_CAPTURE_LENGTH, MAX_KWARG_NAME_LENGTH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueShape {
    Query,
    QuerySteps,
    Pattern,
    PatternList,
    PatternMap,
    String,
    ParameterName,
    CaptureName,
    RegexString,
    StringList,
    StringPredicate,
    RegexPredicate,
    KindList,
    LanguageList,
    PositiveInteger,
    NonNegativeInteger,
    ResultDetail,
    SchemaVersion,
    TrueBoolean,
    ReferenceKindList,
    UsageProof,
    UsageSurface,
}

impl ValueShape {
    pub fn description(self) -> &'static str {
        match self {
            Self::Query => "a query",
            Self::QuerySteps => "an ordered list of query steps",
            Self::Pattern => "a pattern",
            Self::PatternList => "a list/vector of patterns",
            Self::PatternMap => "a map of names to patterns",
            Self::String => "a string",
            Self::ParameterName => "a non-empty parameter name",
            Self::CaptureName => "a non-empty declared capture name",
            Self::RegexString => "a regular expression string",
            Self::StringList => "one or more strings",
            Self::StringPredicate => "an exact string or regex predicate",
            Self::RegexPredicate => "a regex predicate object",
            Self::KindList => "a normalized kind or list of kinds",
            Self::LanguageList => "one or more language labels",
            Self::PositiveInteger => "a positive integer",
            Self::NonNegativeInteger => "a non-negative integer",
            Self::ResultDetail => "compact or full",
            Self::SchemaVersion => "schema version 2",
            Self::TrueBoolean => "the boolean true",
            Self::ReferenceKindList => "one or more structured reference kinds",
            Self::UsageProof => "proven or unproven",
            Self::UsageSurface => "external_usages or lsp_references",
        }
    }

    pub fn string_length_bounds(self) -> Option<(usize, usize)> {
        match self {
            Self::ParameterName => Some((1, MAX_KWARG_NAME_LENGTH)),
            Self::CaptureName => Some((1, MAX_CAPTURE_LENGTH)),
            _ => None,
        }
    }

    pub fn accepts_string(self, value: &str) -> bool {
        self.string_length_bounds()
            .is_none_or(|(minimum, maximum)| value.len() >= minimum && value.len() <= maximum)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RqlFormClass {
    Wrapper,
    Predicate,
}

macro_rules! query_step_ops {
    ($($variant:ident {
        label: $label:literal,
        signature: $signature:literal,
        description: $description:literal $(,)?
    })+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum QueryStepOp {
            $($variant,)+
        }

        pub const ALL_QUERY_STEP_OPS: &[QueryStepOp] = &[
            $(QueryStepOp::$variant,)+
        ];

        impl QueryStepOp {
            pub fn from_label(label: &str) -> Option<Self> {
                match label {
                    $($label => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                }
            }

            pub fn signature(self) -> &'static str {
                match self {
                    $(Self::$variant => $signature,)+
                }
            }

            pub fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => $description,)+
                }
            }

            pub fn allows_hierarchy_options(self) -> bool {
                matches!(self, Self::Supertypes | Self::Subtypes)
            }

            pub fn allows_reference_options(self) -> bool {
                matches!(self, Self::ReferencesOf | Self::UsedBy | Self::Uses)
            }

            pub fn allows_call_options(self) -> bool {
                matches!(self, Self::Callers | Self::Callees)
            }

            pub fn allows_call_site_options(self) -> bool {
                matches!(self, Self::CallSitesTo | Self::CallSitesFrom)
            }

            pub fn allows_receiver_options(self) -> bool {
                matches!(
                    self,
                    Self::ReceiverTargets | Self::PointsTo | Self::MemberTargets
                )
            }
        }
    };
}

query_step_ops! {
    EnclosingDecl { label: "enclosing_decl", signature: "structural_match -> declaration", description: "Map structural matches to their smallest real enclosing declarations." }
    FileOf { label: "file_of", signature: "structural_match|declaration|reference_site|call_site|expression_site -> file", description: "Map structural matches, declarations, reference sites, call sites, or expression sites to their workspace files." }
    ImportsOf { label: "imports_of", signature: "file -> file", description: "Traverse one direct project-local import edge forward." }
    ImportersOf { label: "importers_of", signature: "file -> file", description: "Traverse one direct project-local import edge backward." }
    Supertypes { label: "supertypes", signature: "declaration -> declaration", description: "Traverse indexed supertypes from supported type declarations." }
    Subtypes { label: "subtypes", signature: "declaration -> declaration", description: "Traverse indexed subtypes from supported type declarations." }
    Members { label: "members", signature: "declaration -> declaration", description: "Return direct indexed members of type declarations." }
    Owner { label: "owner", signature: "declaration -> declaration", description: "Return the exact indexed declaring type of member declarations." }
    ReferencesOf { label: "references_of", signature: "declaration -> reference_site", description: "Return resolved source reference sites for exact indexed declarations." }
    UsedBy { label: "used_by", signature: "declaration -> declaration", description: "Return exact declarations containing references to each input declaration." }
    Uses { label: "uses", signature: "declaration -> declaration", description: "Return exact declarations referenced by each input declaration." }
    Callers { label: "callers", signature: "declaration -> declaration", description: "Traverse resolved incoming call edges to caller declarations, optionally to a bounded depth." }
    Callees { label: "callees", signature: "declaration -> declaration", description: "Traverse resolved outgoing call edges to callee declarations, optionally to a bounded depth." }
    CallSitesTo { label: "call_sites_to", signature: "declaration -> call_site", description: "Return structured call sites whose resolved callee is each input declaration." }
    CallSitesFrom { label: "call_sites_from", signature: "declaration -> call_site", description: "Return structured call sites lexically owned by each input declaration." }
    CallInput { label: "call_input", signature: "call_site -> expression_site", description: "Project one direct receiver or formal-parameter input from each call site." }
    ReceiverTargets { label: "receiver_targets", signature: "structural_match|reference_site|call_site|expression_site -> receiver_analysis", description: "Analyze the bounded JS/TS receiver value at each input site." }
    PointsTo { label: "points_to", signature: "structural_match|reference_site|expression_site -> receiver_analysis", description: "Analyze the bounded JS/TS value provenance of each input expression." }
    MemberTargets { label: "member_targets", signature: "structural_match|reference_site -> receiver_analysis", description: "Resolve exact JS/TS member declarations through bounded receiver facts." }
}

macro_rules! rql_forms {
    ($($variant:ident {
        labels: [$primary:literal $(, $alias:literal)* $(,)?],
        class: $class:ident,
        shape: $shape:ident,
        signature: $signature:literal,
        description: $description:literal $(,)?
    })+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum RqlForm {
            $($variant,)+
        }

        pub const ALL_RQL_FORMS: &[RqlForm] = &[
            $(RqlForm::$variant,)+
        ];

        impl RqlForm {
            pub fn from_label(label: &str) -> Option<Self> {
                match label {
                    $($primary $(| $alias)* => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $primary,)+
                }
            }

            pub fn labels(self) -> &'static [&'static str] {
                match self {
                    $(Self::$variant => &[$primary $(, $alias)*],)+
                }
            }

            pub fn class(self) -> RqlFormClass {
                match self {
                    $(Self::$variant => RqlFormClass::$class,)+
                }
            }

            pub fn value_shape(self) -> ValueShape {
                match self {
                    $(Self::$variant => ValueShape::$shape,)+
                }
            }

            pub fn signature(self) -> &'static str {
                match self {
                    $(Self::$variant => $signature,)+
                }
            }

            pub fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => $description,)+
                }
            }

            /// Return the pattern property lowered by a predicate form.
            ///
            /// Keeping this match exhaustive makes adding a form require an
            /// explicit lowering decision rather than relying on coincidental
            /// equality between two registry labels.
            pub fn property(self) -> Option<RqlProperty> {
                match self {
                    Self::Where
                    | Self::Language
                    | Self::Limit
                    | Self::ResultDetail
                    | Self::Inside
                    | Self::NotInside
                    | Self::EnclosingDecl
                    | Self::FileOf
                    | Self::ImportsOf
                    | Self::ImportersOf
                    | Self::Supertypes
                    | Self::Subtypes
                    | Self::Members
                    | Self::Owner
                    | Self::ReferencesOf
                    | Self::UsedBy
                    | Self::Uses
                    | Self::Callers
                    | Self::Callees
                    | Self::CallSitesTo
                    | Self::CallSitesFrom
                    | Self::CallInput
                    | Self::ReceiverTargets
                    | Self::PointsTo
                    | Self::MemberTargets => None,
                    Self::Name => Some(RqlProperty::Name),
                    Self::NameRegex => Some(RqlProperty::NameRegex),
                    Self::TextRegex => Some(RqlProperty::TextRegex),
                    Self::Capture => Some(RqlProperty::Capture),
                    Self::Has => Some(RqlProperty::Has),
                    Self::NotHas => Some(RqlProperty::NotHas),
                    Self::NotKind => Some(RqlProperty::NotKind),
                }
            }
        }
    };
}

rql_forms! {
    Where {
        labels: ["where"],
        class: Wrapper,
        shape: StringList,
        signature: "(where \"glob\" ... query)",
        description: "Restrict the query to workspace-relative path globs.",
    }
    Language {
        labels: ["language", "languages"],
        class: Wrapper,
        shape: LanguageList,
        signature: "(language label ... query)",
        description: "Restrict the query to one or more analyzer languages.",
    }
    Limit {
        labels: ["limit"],
        class: Wrapper,
        shape: PositiveInteger,
        signature: "(limit count query)",
        description: "Set the maximum number of matches returned by query_code.",
    }
    ResultDetail {
        labels: ["result-detail", "result_detail"],
        class: Wrapper,
        shape: ResultDetail,
        signature: "(result-detail compact|full query)",
        description: "Choose compact output or full capture and source details.",
    }
    Inside {
        labels: ["inside"],
        class: Wrapper,
        shape: Pattern,
        signature: "(inside container-pattern query)",
        description: "Require the root match to be lexically inside a matching container.",
    }
    NotInside {
        labels: ["not-inside"],
        class: Wrapper,
        shape: Pattern,
        signature: "(not-inside container-pattern query)",
        description: "Exclude root matches lexically inside a matching container.",
    }
    EnclosingDecl {
        labels: ["enclosing-decl"],
        class: Wrapper,
        shape: Query,
        signature: "(enclosing-decl query)",
        description: "Return the smallest real declaration enclosing each structural match.",
    }
    FileOf {
        labels: ["file-of"],
        class: Wrapper,
        shape: Query,
        signature: "(file-of query)",
        description: "Return the workspace file containing each structural match, declaration, or reference site.",
    }
    ImportsOf {
        labels: ["imports-of"],
        class: Wrapper,
        shape: Query,
        signature: "(imports-of query)",
        description: "Return files directly imported by each input file.",
    }
    ImportersOf {
        labels: ["importers-of"],
        class: Wrapper,
        shape: Query,
        signature: "(importers-of query)",
        description: "Return files that directly import each input file.",
    }
    Supertypes {
        labels: ["supertypes"],
        class: Wrapper,
        shape: Query,
        signature: "(supertypes [:depth count | :transitive true] query)",
        description: "Return indexed direct, depth-bounded, or transitive supertypes.",
    }
    Subtypes {
        labels: ["subtypes"],
        class: Wrapper,
        shape: Query,
        signature: "(subtypes [:depth count | :transitive true] query)",
        description: "Return indexed direct, depth-bounded, or transitive subtypes.",
    }
    Members {
        labels: ["members"],
        class: Wrapper,
        shape: Query,
        signature: "(members query)",
        description: "Return direct indexed member declarations of each input type.",
    }
    Owner {
        labels: ["owner"],
        class: Wrapper,
        shape: Query,
        signature: "(owner query)",
        description: "Return the exact indexed declaring type of each input member.",
    }
    ReferencesOf {
        labels: ["references-of"],
        class: Wrapper,
        shape: Query,
        signature: "(references-of [:reference-kinds [...]] [:proof proven|unproven] [:surface external-usages|lsp-references] query)",
        description: "Return exact resolved reference sites for each input declaration.",
    }
    UsedBy {
        labels: ["used-by"],
        class: Wrapper,
        shape: Query,
        signature: "(used-by [:reference-kinds [...]] [:proof proven|unproven] [:surface external-usages|lsp-references] query)",
        description: "Return exact declarations containing references to each input declaration.",
    }
    Uses {
        labels: ["uses"],
        class: Wrapper,
        shape: Query,
        signature: "(uses [:reference-kinds [...]] [:proof proven|unproven] [:surface external-usages|lsp-references] query)",
        description: "Return exact indexed declarations referenced by each input declaration.",
    }
    Callers {
        labels: ["callers"],
        class: Wrapper,
        shape: Query,
        signature: "(callers [:depth count] [:proof proven|unproven] query)",
        description: "Traverse incoming calls to caller declarations with a finite depth bound.",
    }
    Callees {
        labels: ["callees"],
        class: Wrapper,
        shape: Query,
        signature: "(callees [:depth count] [:proof proven|unproven] query)",
        description: "Traverse outgoing calls to callee declarations with a finite depth bound.",
    }
    CallSitesTo {
        labels: ["call-sites-to", "call_sites_to"],
        class: Wrapper,
        shape: Query,
        signature: "(call-sites-to [:proof proven|unproven] query)",
        description: "Return structured incoming call sites for each declaration.",
    }
    CallSitesFrom {
        labels: ["call-sites-from", "call_sites_from"],
        class: Wrapper,
        shape: Query,
        signature: "(call-sites-from [:proof proven|unproven] query)",
        description: "Return structured outgoing call sites for each declaration.",
    }
    CallInput {
        labels: ["call-input", "call_input"],
        class: Wrapper,
        shape: Query,
        signature: "(call-input (:receiver true | :parameter-index index | :parameter-name name) query)",
        description: "Project the receiver or one formal parameter's direct argument expressions.",
    }
    ReceiverTargets {
        labels: ["receiver-targets", "receiver_targets"],
        class: Wrapper,
        shape: Query,
        signature: "(receiver-targets [:capture name] query)",
        description: "Analyze bounded JS/TS receiver values at structural or semantic source sites.",
    }
    PointsTo {
        labels: ["points-to", "points_to"],
        class: Wrapper,
        shape: Query,
        signature: "(points-to [:capture name] query)",
        description: "Analyze bounded JS/TS value and allocation provenance.",
    }
    MemberTargets {
        labels: ["member-targets", "member_targets"],
        class: Wrapper,
        shape: Query,
        signature: "(member-targets [:capture name] query)",
        description: "Resolve exact JS/TS member declarations through the analyzed receiver.",
    }
    Name {
        labels: ["name"],
        class: Predicate,
        shape: String,
        signature: "(name \"exactName\")",
        description: "Match a node's normalized name exactly.",
    }
    NameRegex {
        labels: ["name/regex"],
        class: Predicate,
        shape: String,
        signature: "(name/regex \"pattern\")",
        description: "Match a node's normalized name with a regular expression.",
    }
    TextRegex {
        labels: ["text/regex"],
        class: Predicate,
        shape: String,
        signature: "(text/regex \"pattern\")",
        description: "Match a node's source text with a regular expression.",
    }
    Capture {
        labels: ["capture"],
        class: Predicate,
        shape: String,
        signature: "(capture \"label\")",
        description: "Capture the matching node under a result label.",
    }
    Has {
        labels: ["has"],
        class: Predicate,
        shape: Pattern,
        signature: "(has descendant-pattern)",
        description: "Require a matching descendant somewhere below this pattern.",
    }
    NotHas {
        labels: ["not-has", "not_has"],
        class: Predicate,
        shape: Pattern,
        signature: "(not-has descendant-pattern)",
        description: "Exclude nodes that contain a matching descendant.",
    }
    NotKind {
        labels: ["not-kind", "not_kind"],
        class: Predicate,
        shape: KindList,
        signature: "(not-kind kind|[kinds...])",
        description: "Exclude one or more normalized kinds using subtype-aware matching.",
    }
}

macro_rules! rql_properties {
    ($($variant:ident {
        labels: [$primary:literal $(, $alias:literal)* $(,)?],
        shape: $shape:ident,
        signature: $signature:literal,
        description: $description:literal,
    })+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum RqlProperty {
            $($variant,)+
        }

        pub const ALL_RQL_PROPERTIES: &[RqlProperty] = &[
            $(RqlProperty::$variant,)+
        ];

        impl RqlProperty {
            pub fn from_label(label: &str) -> Option<Self> {
                match label {
                    $($primary $(| $alias)* => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $primary,)+
                }
            }

            pub fn labels(self) -> &'static [&'static str] {
                match self {
                    $(Self::$variant => &[$primary $(, $alias)*],)+
                }
            }

            pub fn value_shape(self) -> ValueShape {
                match self {
                    $(Self::$variant => ValueShape::$shape,)+
                }
            }

            pub fn signature(self) -> &'static str {
                match self {
                    $(Self::$variant => $signature,)+
                }
            }

            pub fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => $description,)+
                }
            }
        }
    };
}

rql_properties! {
    Name {
        labels: ["name"],
        shape: String,
        signature: ":name \"exactName\"",
        description: "Match the normalized name exactly.",
    }
    NameRegex {
        labels: ["name/regex"],
        shape: RegexString,
        signature: ":name/regex \"pattern\"",
        description: "Match the normalized name with a regular expression.",
    }
    TextRegex {
        labels: ["text/regex"],
        shape: RegexString,
        signature: ":text/regex \"pattern\"",
        description: "Match source text with a regular expression.",
    }
    Capture {
        labels: ["capture"],
        shape: String,
        signature: ":capture \"label\"",
        description: "Capture the matching node under a result label.",
    }
    NotKind {
        labels: ["not-kind", "not_kind"],
        shape: KindList,
        signature: ":not-kind kind|[kinds...]",
        description: "Exclude one or more normalized kinds.",
    }
    Has {
        labels: ["has"],
        shape: Pattern,
        signature: ":has pattern",
        description: "Require a matching descendant.",
    }
    NotHas {
        labels: ["not-has", "not_has"],
        shape: Pattern,
        signature: ":not-has pattern",
        description: "Exclude nodes containing a matching descendant.",
    }
}

macro_rules! json_fields {
    ($name:ident, $all:ident, $($variant:ident {
        label: $label:literal,
        shape: $shape:ident,
        signature: $signature:literal,
        description: $description:literal $(,)?
    })+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($variant,)+
        }

        pub const $all: &[$name] = &[
            $($name::$variant,)+
        ];

        impl $name {
            pub fn from_label(label: &str) -> Option<Self> {
                match label {
                    $($label => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                }
            }

            pub fn value_shape(self) -> ValueShape {
                match self {
                    $(Self::$variant => ValueShape::$shape,)+
                }
            }

            pub fn signature(self) -> &'static str {
                match self {
                    $(Self::$variant => $signature,)+
                }
            }

            pub fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => $description,)+
                }
            }
        }
    };
}

json_fields! {
    QueryField,
    ALL_QUERY_FIELDS,
    Where { label: "where", shape: StringList, signature: "\"where\": [\"glob\", ...]", description: "Restrict the query to workspace-relative path globs." }
    Languages { label: "languages", shape: LanguageList, signature: "\"languages\": [\"rust\", ...]", description: "Restrict the query to analyzer languages." }
    Match { label: "match", shape: Pattern, signature: "\"match\": { pattern }", description: "Define the required root structural pattern." }
    Inside { label: "inside", shape: Pattern, signature: "\"inside\": { pattern }", description: "Require the root match to be inside a matching container." }
    NotInside { label: "not_inside", shape: Pattern, signature: "\"not_inside\": { pattern }", description: "Exclude root matches inside a matching container." }
    Steps { label: "steps", shape: QuerySteps, signature: "\"steps\": [{ \"op\": \"file_of\" }, ...]", description: "Apply ordered typed transformations to structural matches." }
    Limit { label: "limit", shape: PositiveInteger, signature: "\"limit\": positive integer", description: "Set the maximum number of matches returned." }
    ResultDetail { label: "result_detail", shape: ResultDetail, signature: "\"result_detail\": \"compact\" | \"full\"", description: "Choose compact output or full capture and source details." }
    SchemaVersion { label: "schema_version", shape: SchemaVersion, signature: "\"schema_version\": 2", description: "Select the CodeQuery schema version." }
}

json_fields! {
    QueryStepField,
    ALL_QUERY_STEP_FIELDS,
    Op { label: "op", shape: String, signature: "\"op\": \"step_name\"", description: "Select the typed pipeline transformation." }
    Depth { label: "depth", shape: PositiveInteger, signature: "\"depth\": positive integer", description: "Traverse all hierarchy edges from distance one through this depth." }
    Transitive { label: "transitive", shape: TrueBoolean, signature: "\"transitive\": true", description: "Traverse the complete indexed hierarchy under the execution budget." }
    ReferenceKinds { label: "reference_kinds", shape: ReferenceKindList, signature: "\"reference_kinds\": [\"field_write\", ...]", description: "Restrict traversal to structured source-reference kinds." }
    Proof { label: "proof", shape: UsageProof, signature: "\"proof\": \"proven\" | \"unproven\"", description: "Restrict traversal to one usage-proof tier." }
    Surface { label: "surface", shape: UsageSurface, signature: "\"surface\": \"external_usages\" | \"lsp_references\"", description: "Choose the external-usage or editor-visible reference surface." }
    Receiver { label: "receiver", shape: TrueBoolean, signature: "\"receiver\": true", description: "Select the explicit base or receiver expression of a call site." }
    ParameterIndex { label: "parameter_index", shape: NonNegativeInteger, signature: "\"parameter_index\": non-negative integer", description: "Select a zero-based formal parameter slot, excluding receiver-bound parameters." }
    ParameterName { label: "parameter_name", shape: ParameterName, signature: "\"parameter_name\": \"name\"", description: "Select a formal parameter slot by its declared name." }
    Capture { label: "capture", shape: CaptureName, signature: "\"capture\": \"declared_name\"", description: "Analyze every unique range bound to a declared positive structural capture." }
}

pub const ALL_REFERENCE_KINDS: &[ReferenceKind] = &[
    ReferenceKind::MethodCall,
    ReferenceKind::ConstructorCall,
    ReferenceKind::FieldRead,
    ReferenceKind::FieldWrite,
    ReferenceKind::TypeReference,
    ReferenceKind::StaticReference,
    ReferenceKind::SuperCall,
    ReferenceKind::Inheritance,
];

pub fn reference_kind_label(kind: ReferenceKind) -> &'static str {
    match kind {
        ReferenceKind::MethodCall => "method_call",
        ReferenceKind::ConstructorCall => "constructor_call",
        ReferenceKind::FieldRead => "field_read",
        ReferenceKind::FieldWrite => "field_write",
        ReferenceKind::TypeReference => "type_reference",
        ReferenceKind::StaticReference => "static_reference",
        ReferenceKind::SuperCall => "super_call",
        ReferenceKind::Inheritance => "inheritance",
    }
}

pub fn reference_kind_from_label(label: &str) -> Option<ReferenceKind> {
    ALL_REFERENCE_KINDS
        .iter()
        .copied()
        .find(|kind| reference_kind_label(*kind) == label)
}

pub fn usage_proof_label(proof: UsageProof) -> &'static str {
    match proof {
        UsageProof::Proven => "proven",
        UsageProof::Unproven => "unproven",
    }
}

pub fn usage_proof_from_label(label: &str) -> Option<UsageProof> {
    match label {
        "proven" => Some(UsageProof::Proven),
        "unproven" => Some(UsageProof::Unproven),
        _ => None,
    }
}

pub fn usage_surface_label(surface: UsageHitSurface) -> &'static str {
    match surface {
        UsageHitSurface::ExternalUsages => "external_usages",
        UsageHitSurface::LspReferences => "lsp_references",
    }
}

pub fn usage_surface_from_label(label: &str) -> Option<UsageHitSurface> {
    match label {
        "external_usages" => Some(UsageHitSurface::ExternalUsages),
        "lsp_references" => Some(UsageHitSurface::LspReferences),
        _ => None,
    }
}

json_fields! {
    StringPredicateField,
    ALL_STRING_PREDICATE_FIELDS,
    Regex { label: "regex", shape: String, signature: "\"regex\": \"pattern\"", description: "Match the value with a regular expression." }
}

json_fields! {
    PatternField,
    ALL_PATTERN_FIELDS,
    Kind { label: "kind", shape: KindList, signature: "\"kind\": \"kind\" | [\"kinds\", ...]", description: "Match one or more normalized node kinds." }
    NotKind { label: "not_kind", shape: KindList, signature: "\"not_kind\": \"kind\" | [\"kinds\", ...]", description: "Exclude one or more normalized node kinds." }
    Name { label: "name", shape: StringPredicate, signature: "\"name\": \"exact\" | { \"regex\": \"pattern\" }", description: "Match the node's normalized name." }
    Text { label: "text", shape: RegexPredicate, signature: "\"text\": { \"regex\": \"pattern\" }", description: "Match the node's source text with a regular expression." }
    Capture { label: "capture", shape: String, signature: "\"capture\": \"label\"", description: "Capture the matching node under a result label." }
    Has { label: "has", shape: Pattern, signature: "\"has\": { pattern }", description: "Require a matching descendant." }
    NotHas { label: "not_has", shape: Pattern, signature: "\"not_has\": { pattern }", description: "Exclude nodes containing a matching descendant." }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn schema_metadata_has_unique_spellings_and_help() {
        let mut forms = HashSet::new();
        for form in ALL_RQL_FORMS {
            assert!(!form.signature().is_empty());
            assert!(!form.description().is_empty());
            for label in form.labels() {
                assert!(forms.insert(*label), "duplicate form label {label}");
                assert_eq!(RqlForm::from_label(label), Some(*form));
            }
        }

        let mut step_ops = HashSet::new();
        for op in ALL_QUERY_STEP_OPS {
            assert!(step_ops.insert(op.label()), "duplicate query step op");
            assert!(!op.signature().is_empty());
            assert!(!op.description().is_empty());
            assert_eq!(QueryStepOp::from_label(op.label()), Some(*op));
        }

        let mut properties = HashSet::new();
        for property in ALL_RQL_PROPERTIES {
            assert!(!property.signature().is_empty());
            assert!(!property.description().is_empty());
            for label in property.labels() {
                assert!(
                    properties.insert(*label),
                    "duplicate property label {label}"
                );
                assert_eq!(RqlProperty::from_label(label), Some(*property));
            }
        }

        for field in ALL_QUERY_FIELDS {
            assert!(!field.signature().is_empty());
            assert!(!field.description().is_empty());
            assert_eq!(QueryField::from_label(field.label()), Some(*field));
        }
        for field in ALL_QUERY_STEP_FIELDS {
            assert!(!field.signature().is_empty());
            assert!(!field.description().is_empty());
            assert_eq!(QueryStepField::from_label(field.label()), Some(*field));
        }
        for field in ALL_PATTERN_FIELDS {
            assert!(!field.signature().is_empty());
            assert!(!field.description().is_empty());
            assert_eq!(PatternField::from_label(field.label()), Some(*field));
        }
        for field in ALL_STRING_PREDICATE_FIELDS {
            assert!(!field.signature().is_empty());
            assert!(!field.description().is_empty());
            assert_eq!(
                StringPredicateField::from_label(field.label()),
                Some(*field)
            );
        }
    }
}
