use super::*;

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryFile {
    pub path: String,
    pub language: &'static str,
    /// The package or module this file belongs to, when the workspace can name
    /// one (#1474). The package clause is one row per file, so it is exposed as
    /// fields on the file row rather than as a fourth row kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_fq: Option<String>,
    /// `Some(true)` when the language spells the package in the source (Java's
    /// `package a.b;`), `Some(false)` when it is derived from the file's path,
    /// and `None` when no package could be named at all -- which is not the
    /// same as "the file is in the root package".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_syntactic: Option<bool>,
}

/// One lexical scope of a file (#1474).
///
/// `ast_id` is absent for exactly one scope per file: the synthesized whole-file
/// scope, which no grammar gives an arena node. Every other scope is a fact, so
/// its `ast_id` joins with a structural capture over the same node.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryLexicalScope {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    /// Dense per-file scope index; 0 is always the file scope.
    pub index: u32,
    /// The normalized kind of the anchoring fact, or `null` for the file scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_index: Option<u32>,
}

/// One construct that materializes declarations (#1476).
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryGenerationSite {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    pub kind: &'static str,
    /// `literal` when the generated set below is exact; `dynamic` when the
    /// site generates declarations the analyzer cannot name, so the set is
    /// explicitly not the whole answer.
    pub input: &'static str,
    pub generated_count: usize,
    pub generated: Vec<CodeQueryGeneratedDeclaration>,
}

/// One declaration a generation site materialized, with the literal naming
/// argument that produced it — the multi-location half of generation
/// evidence (#1476).
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryGeneratedDeclaration {
    pub fq_name: String,
    pub argument_start_byte: usize,
    pub argument_end_byte: usize,
    pub argument_range: CodeQueryRange,
}

/// One export declaration (#1476).
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryExport {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    pub form: &'static str,
    pub exported_name: String,
    /// The declaration the export materialized, when the analyzer models one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_fq_name: Option<String>,
}

/// The state of one declaration: where it came from and what it must not be
/// mistaken for (#1476).
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryDeclarationState {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub fq_name: String,
    pub unit_kind: &'static str,
    pub origin: &'static str,
    pub declaration_only: bool,
    pub config_gated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<CodeQueryRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_byte: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_byte: Option<usize>,
}

/// One name a scope introduces (#1474).
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryBinding {
    pub id: String,
    /// Absent when the binder's local name is not spelled by a classified
    /// token, which is how a wildcard import and an adapter without a
    /// structured import path surface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub name: String,
    pub kind: &'static str,
    pub hoisting: &'static str,
    pub namespace: &'static str,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    /// Byte interval over which the binding is in effect.
    pub activation_start_byte: usize,
    pub activation_end_byte: usize,
    /// Dense index of the declaring scope, which `scope-of` projects to a row.
    pub declaring_scope_index: u32,
    pub source_order: u32,
    pub visibility: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import: Option<CodeQueryImportBinder>,
    /// `true` when this row was emitted as a binding the reaching binding
    /// shadows rather than as the winner. Only `reaching-binding
    /// :include-shadowed` produces such rows.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub shadowed: bool,
    /// The AST identity of the occurrence this row is the reaching binding
    /// *of*, present exactly on rows the `reaching-binding` step produced.
    ///
    /// Without it the step's answer is unjoinable: a correlated consumer that
    /// captured one token cannot tell which of several returned bindings
    /// belongs to it. A binding reached from two different occurrences is two
    /// rows, because it is two answers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reached_from_ast_id: Option<String>,
}

/// What an import binder contributes, as far as the adapter can state it.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryImportBinder {
    pub local_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Empty when the adapter records no parser-derived import path. That is a
    /// stated gap, not a claim that the import has no target.
    pub target_segments: Vec<String>,
    pub wildcard: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wildcard_ambiguous: Option<bool>,
    pub boundary: &'static str,
}

/// One candidate the resolver considered for one reference (#1474).
///
/// `tier` is optional by construction: the shared outcome constructors receive
/// a bare candidate list and cannot name the tier that produced it, so an
/// absent tier means *unattributed*, never "the weakest tier".
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryResolutionCandidate {
    pub id: String,
    /// The AST identity of the *reference* the candidate was considered for,
    /// which is what a capture over that token joins on.
    pub ast_id: String,
    pub path: String,
    pub language: &'static str,
    /// The reference occurrence's source range, so a candidate row points at
    /// the position whose resolution it explains.
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    /// Ordinal of this candidate within its reference's trace, so two
    /// otherwise identical rows stay separately addressable.
    pub ordinal: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<&'static str>,
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<&'static str>,
    pub boundary: &'static str,
    pub visibility: &'static str,
    /// How much of the candidate story the language's resolver reports.
    /// `selection_only` means an absent rejection row says nothing.
    pub trace_completeness: &'static str,
    pub candidate: CodeQueryCandidateRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_target: Option<String>,
    /// The #1475 canonical identity digest of a unit-backed candidate:
    /// domain-separated over the identity's kind-tagged segments, namespace,
    /// language, and recorded generic arity -- never over a rendered FQN
    /// string. `None` for candidates without a workspace declaration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_member_id: Option<String>,
}

/// One canonical reference edge (#1479).
///
/// The same row shape whichever producer derived it: `provenance` says which
/// one did, and every classification the parity comparison depends on (kind,
/// proof, usage kind, site class, owner relation) is an explicit field, never
/// inferred from counts. `ast_id` is the site token's content-scoped AST
/// identity when the producer can address it as a facts-arena node; string
/// equality with a capture's or occurrence's `ast_id` is the correlation join.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryReferenceEdge {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    pub target: CodeQueryDeclaration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_declaration: Option<CodeQueryDeclaration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_kind: Option<&'static str>,
    pub proof: &'static str,
    pub usage_kind: &'static str,
    pub site_class: &'static str,
    pub owner_relation: &'static str,
    /// Which producer derived the row. Serialized as `edge_provenance`
    /// because the result item that flattens this row already owns the
    /// `provenance` key for its pipeline trace, and a colliding key would let
    /// the trace silently shadow the producer label under full detail.
    #[serde(rename = "edge_provenance")]
    pub provenance: &'static str,
    /// The workspace generation the edge was derived in. A parity comparison
    /// refuses to relate rows from two generations.
    pub generation: u64,
}

/// One qualified-path chain (#1475): a linear sequence of segments the
/// grammar records, anchored at its terminal segment token.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryQualifiedPath {
    pub id: String,
    /// The terminal segment token's AST identity — the equijoin key with
    /// captures and occurrence rows over the same token.
    pub ast_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    pub segment_count: u32,
}

/// One segment of one qualified path (#1475).
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryPathSegment {
    pub id: String,
    /// The segment token's AST identity; absent for a segment the kind table
    /// does not admit as a fact (Rust's `crate`/`self`/`super` path
    /// keywords), whose position in the path is real but whose structural
    /// identity is genuinely absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    /// The owning path's terminal AST identity — the group key back to its
    /// qualified-path row.
    pub path_ast_id: String,
    /// 0-based position within the path, counting every spelled segment.
    pub ordinal: u32,
    /// Decoded identifier text: a quoted or punctuation-bearing identifier is
    /// one segment and is never re-split.
    pub text: String,
    /// Stated by the adapter's classification or decided by resolution;
    /// absent means "not stated", never a guessed value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<&'static str>,
    /// The generic argument count the source spells at this segment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generic_arity: Option<u32>,
    /// Present exactly when segment resolution was derived; `null` means
    /// "not derived", never "nothing considered".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_count: Option<usize>,
}

/// What a candidate row points at. Two of the five shapes carry no workspace
/// declaration, which is why `candidate-target` is partial by construction.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "candidate_kind", rename_all = "snake_case")]
pub enum CodeQueryCandidateRef {
    Unit {
        unit: Box<CodeQueryDeclaration>,
    },
    Lexical {
        name: String,
        kind: &'static str,
        range: CodeQueryRange,
    },
    Binding {
        name: String,
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_id: Option<String>,
    },
    ImportBinder {
        name: String,
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_id: Option<String>,
        /// The parser-derived path the route pointed at. Empty when the
        /// adapter or seam recorded no structured target. That is a stated
        /// gap, not a claim that the import has no target.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        target_segments: Vec<String>,
    },
    ExternalRoute {
        name: String,
    },
}

impl CodeQueryCandidateRef {
    /// The stable label of the shape, used in rendering and in the detailed
    /// terminal key.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unit { .. } => "unit",
            Self::Lexical { .. } => "lexical",
            Self::Binding { .. } => "binding",
            Self::ImportBinder { .. } => "import_binder",
            Self::ExternalRoute { .. } => "external_route",
        }
    }

    /// The candidate's name, for rendering.
    pub fn name(&self) -> &str {
        match self {
            Self::Unit { unit } => &unit.fq_name,
            Self::Lexical { name, .. }
            | Self::Binding { name, .. }
            | Self::ImportBinder { name, .. }
            | Self::ExternalRoute { name } => name,
        }
    }
}
