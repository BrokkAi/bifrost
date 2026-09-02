//! The foundry's interchange form: the authored procedure-summary IR plus the
//! provenance and typed-gap envelope that corpus translation needs.
//!
//! `AuthoredProcedureSummary` is the shipping contract. It carries exactly what
//! the compiler and the runtime binder consume and nothing else, so it cannot
//! carry where a claim came from, which parts of a corpus row it could not
//! express, or a claim of *no* flow. A foundry entry wraps the authored form
//! with that envelope, and [`FoundryEntry::authored_summary`] projects the
//! shipping contract back out.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    AuthoredProcedureSummary, AuthoredProcedureTarget, AuthoredSummaryExitKind,
    AuthoredSummaryInput, AuthoredSummaryOutput, AuthoredSummaryTransfer, Completeness,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The maximum readable prefix of a generated summary id, in bytes.
///
/// Authored stable ids are limited to 256 bytes and the derived model id
/// (`pack_id` + `#` + id) to 512. A long erased JVM signature can exceed both,
/// so the readable part is truncated and identity is carried by the digest
/// suffix, which is a function of the untruncated target.
const MAX_READABLE_ID_BYTES: usize = 160;

/// Hex characters of the target digest appended to every generated summary id.
const ID_DIGEST_HEX_CHARS: usize = 12;

/// One external model corpus, or Bifrost's own derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundryCorpus {
    /// CodeQL Models-as-Data rows (github/codeql, MIT).
    Codeql,
    /// Joern flow semantics (joernio/joern, Apache-2.0).
    Joern,
    /// Bifrost's own generation-time derivation over the pinned sources.
    Derived,
}

impl FoundryCorpus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codeql => "codeql",
            Self::Joern => "joern",
            Self::Derived => "derived",
        }
    }
}

/// What a corpus states about one target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundryClaim {
    /// The corpus lists value flows through this target.
    Flows,
    /// The corpus states this target carries no value flow at all. Joern
    /// spells this as an empty mapping list; CodeQL spells it as a
    /// `neutralModel` row of kind `summary`.
    NoFlow,
}

/// How a corpus pins the overload a claim applies to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FoundrySignature {
    /// One overload, spelled the way the corpus spells it. CodeQL erases
    /// packages (`(String)`); Joern keeps them (`(java.lang.String)`).
    Overload { types: Vec<String> },
    /// Every overload of the member.
    AnyOverload,
}

impl FoundrySignature {
    /// The parameter count the corpus pins, when it pins one.
    pub fn arity(&self) -> Option<u32> {
        match self {
            Self::Overload { types } => Some(types.len() as u32),
            Self::AnyOverload => None,
        }
    }

    /// The `symbol` spelling of an authored procedure target.
    pub fn symbol(&self, member: &str) -> String {
        match self {
            Self::Overload { types } => format!("{member}({})", types.join(",")),
            Self::AnyOverload => member.to_owned(),
        }
    }
}

/// One external procedure as a corpus names it.
///
/// `artifact_path` is the JVM class-file path derived from the corpus's own
/// package and type columns; it is the `path` an authored target carries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FoundryTarget {
    pub artifact_path: String,
    pub member: String,
    pub signature: FoundrySignature,
}

impl FoundryTarget {
    /// The join projection: class, member, and pinned arity.
    pub fn join_key(&self) -> FoundryJoinKey {
        FoundryJoinKey {
            artifact_path: self.artifact_path.clone(),
            member: self.member.clone(),
            arity: self.signature.arity(),
        }
    }

    /// The exact identity string the generated summary id digests.
    fn identity(&self) -> String {
        format!(
            "{}|{}|{}",
            self.artifact_path,
            self.member,
            match &self.signature {
                FoundrySignature::Overload { types } => format!("({})", types.join(",")),
                FoundrySignature::AnyOverload => "*".to_owned(),
            }
        )
    }
}

/// The comparable identity of a target across corpora.
///
/// Corpora spell parameter types differently, so the arity is the only
/// signature projection that compares. `arity: None` records that the corpus
/// pinned no overload, which is a different claim from any arity and therefore
/// a distinct key rather than a wildcard.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FoundryJoinKey {
    pub artifact_path: String,
    pub member: String,
    pub arity: Option<u32>,
}

/// The receiver and parameter shape an entry declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FoundryBoundary {
    pub has_receiver: bool,
    pub parameter_count: u32,
}

/// Which pinned artifact holds the class the target names.
///
/// Milestone 1 translates corpora that name packages and types but no
/// artifact, and the foundry has no artifact index yet, so every translated
/// entry records `Unresolved` rather than guessing a jar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FoundryArtifactBinding {
    Unresolved,
    Pinned { artifact_sha256: String },
}

/// One corpus row that supports an entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FoundryEvidence {
    /// The corpus file name. Never a host path, so the report is portable.
    pub file: String,
    /// The one-based row ordinal within that file's rows of the same kind.
    pub row: u32,
    /// The row rendered back, so a reader can find it upstream.
    pub text: String,
}

/// Something a corpus row states that the authored IR cannot carry.
///
/// A note never silently changes a claim: it records that the shipped entry
/// says less than the corpus row did.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "note", rename_all = "snake_case")]
pub enum FoundryNote {
    /// The corpus applies the claim to every override in every subtype. An
    /// authored target names one exact procedure.
    SubtypeClaimNotCarried,
    /// The corpus pins no overload, so `parameter_count` is the smallest count
    /// consistent with the ordinals the rows reference, not the real arity.
    ParameterCountIsLowerBound { observed: u32 },
    /// The corpus spells parameter types without their packages, so the symbol
    /// cannot be matched against a resolved JVM descriptor as written.
    SignatureTypesUnqualified,
    /// The claim is "no value flow at all". The authored IR rejects a summary
    /// with no transfer and no effect (`summary.empty`), so nothing ships.
    NoFlowClaimNotCarried,
    /// Joern's `PASSTHROUGH` maps every parameter to itself and to the return,
    /// including parameters an unbounded signature does not name. The authored
    /// IR enumerates ordinals, so an unbounded claim cannot be carried.
    PassthroughNotCarried,
    /// Two corpus rows for one target state both flows and no flow.
    ContradictoryCorpusRows,
}

impl FoundryNote {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::SubtypeClaimNotCarried => "subtype_claim_not_carried",
            Self::ParameterCountIsLowerBound { .. } => "parameter_count_is_lower_bound",
            Self::SignatureTypesUnqualified => "signature_types_unqualified",
            Self::NoFlowClaimNotCarried => "no_flow_claim_not_carried",
            Self::PassthroughNotCarried => "passthrough_not_carried",
            Self::ContradictoryCorpusRows => "contradictory_corpus_rows",
        }
    }
}

/// Why one corpus row produced no transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundrySkipReason {
    /// A source or sink row. Milestone 1 translates flow summaries only.
    RowKindOutOfScope,
    /// The input names a port the authored IR has no input for, such as
    /// `ReturnValue` or a corpus row that reads back from the return.
    InputPortUnsupported,
    /// The output names a port the authored IR has no output for. The
    /// authored outputs are the return, the receiver, and named heap or
    /// capture cells; a write into parameter N has no authored spelling.
    OutputPortUnsupported,
    /// The row qualifies a port with an access path (`.Element`, `.MapValue`,
    /// `.SyntheticField[..]`, ...). The authored IR has no access paths.
    AccessPathUnsupported,
    /// The row carries a model qualifier in the `ext` column, which selects a
    /// different declaration than the one the row names.
    RowQualifierUnsupported,
    /// The row references a parameter ordinal its own signature does not have.
    OrdinalOutOfRange,
    /// Joern's `PASSTHROUGH` is the entry's only content. It maps every
    /// parameter to itself and to the return, including parameters an
    /// unbounded signature does not name, which the authored IR cannot spell.
    PassthroughNotRepresentable,
    /// The row does not have the column count or cell types its kind declares.
    MalformedRow,
    /// The corpus entry names a symbol the translator cannot resolve to a JVM
    /// class and member, such as a Joern operator or a C library function.
    UnresolvedName,
}

impl FoundrySkipReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RowKindOutOfScope => "row_kind_out_of_scope",
            Self::InputPortUnsupported => "input_port_unsupported",
            Self::OutputPortUnsupported => "output_port_unsupported",
            Self::AccessPathUnsupported => "access_path_unsupported",
            Self::RowQualifierUnsupported => "row_qualifier_unsupported",
            Self::OrdinalOutOfRange => "ordinal_out_of_range",
            Self::PassthroughNotRepresentable => "passthrough_not_representable",
            Self::MalformedRow => "malformed_row",
            Self::UnresolvedName => "unresolved_name",
        }
    }
}

/// One corpus row the translator read and did not turn into a transfer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FoundrySkip {
    pub file: String,
    pub row: u32,
    pub reason: FoundrySkipReason,
    pub detail: String,
}

/// How much of a target's behavior an entry accounts for.
///
/// Only a body the derivation traversed with no unresolved boundary may claim
/// `complete`. A corpus row never claims it: translation is not traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundryCompleteness {
    Partial,
    Complete,
}

/// Why a derivation stopped short of the whole body.
///
/// Each variant is a fact the derivation observed, never an inference about
/// what lies past it. An entry that carries any of these states less than the
/// target does; it never states a transfer it did not derive.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "boundary", rename_all = "snake_case")]
pub enum FoundryDerivationBoundary {
    /// The callee is declared `native`: its behavior is not in any source the
    /// pins carry, so no transfer through it can be derived.
    NativeCallee { callee: String },
    /// The callee is declared without a body and is not `native` (abstract, or
    /// an interface method with no default).
    CalleeWithoutBody { callee: String },
    /// The callee's body is outside the pinned sources this run indexed.
    ExternalCallee { callee: Option<String> },
    /// The call resumes later (async, generator), so its transfer is not one
    /// call edge.
    DeferredCallee { callee: String, kind: String },
    /// Dispatch produced no target at all.
    UnresolvedCall,
    /// The dispatch candidate set hit a bound and omitted candidates.
    TruncatedDispatch,
    /// A semantic oracle answered with something other than a complete outcome.
    /// `capability` names the unsupported capability when the oracle said which
    /// one it is, which is what routes the entry to the right repair.
    SemanticGap {
        status: String,
        capability: Option<String>,
    },
    /// A semantic or solver budget stopped the run.
    BudgetExceeded { detail: String },
    /// The solver was cancelled.
    SolverCancelled,
    /// The interprocedural closure reached the derivation's own bound.
    ClosureLimit { limit: u32 },
    /// The value-flow machinery refused the target: the plan could not be built
    /// or the solve failed. The entry states no flow at all and names the
    /// refusal, because a target the engine cannot accept is a foundry finding,
    /// not a target with no flows.
    EngineRejected { detail: String },
}

impl FoundryDerivationBoundary {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::NativeCallee { .. } => "native_callee",
            Self::CalleeWithoutBody { .. } => "callee_without_body",
            Self::ExternalCallee { .. } => "external_callee",
            Self::DeferredCallee { .. } => "deferred_callee",
            Self::UnresolvedCall => "unresolved_call",
            Self::TruncatedDispatch => "truncated_dispatch",
            Self::SemanticGap { .. } => "semantic_gap",
            Self::BudgetExceeded { .. } => "budget_exceeded",
            Self::SolverCancelled => "solver_cancelled",
            Self::ClosureLimit { .. } => "closure_limit",
            Self::EngineRejected { .. } => "engine_rejected",
        }
    }
}

/// One step of an access path, as the value-flow machinery reports it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "selector", rename_all = "snake_case")]
pub enum FoundrySelector {
    Field { name: String },
    ExactIndex,
    AnyIndex,
}

impl FoundrySelector {
    fn render(&self) -> String {
        match self {
            Self::Field { name } => format!(".Field[{name}]"),
            Self::ExactIndex => ".ExactIndex".to_owned(),
            Self::AnyIndex => ".Element".to_owned(),
        }
    }
}

/// One port with the access path the derivation observed beneath it.
///
/// The authored IR has no access paths, so a shipping transfer keeps only
/// `port`. This form keeps the whole answer, because the granularity cannot be
/// recovered once it is dropped: 3672 CodeQL rows in the milestone-1 run were
/// skipped for exactly this reason, and heap- and object-sensitive summaries
/// are the direction the IR is headed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FoundryAccessPath {
    /// The port spelling, as [`render_transfer`] spells it.
    pub port: String,
    pub selectors: Vec<FoundrySelector>,
}

impl FoundryAccessPath {
    pub fn render(&self) -> String {
        let mut rendered = self.port.clone();
        for selector in &self.selectors {
            rendered.push_str(&selector.render());
        }
        rendered
    }

    /// Whether this path says more than its port alone.
    pub fn is_qualified(&self) -> bool {
        !self.selectors.is_empty()
    }
}

/// One derived flow at the granularity the value-flow machinery reported it.
///
/// The shipping transfer is this record projected onto its two ports. A join
/// against an argument-level corpus compares the projection; this record is
/// what makes the projection visible as a projection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FoundryFineGrainedTransfer {
    pub input: FoundryAccessPath,
    pub output: FoundryAccessPath,
    pub exit_kind: String,
}

impl FoundryFineGrainedTransfer {
    pub fn render(&self) -> String {
        format!(
            "{}->{}@{}",
            self.input.render(),
            self.output.render(),
            self.exit_kind
        )
    }

    /// Whether either end says more than the shipping transfer can.
    pub fn is_qualified(&self) -> bool {
        self.input.is_qualified() || self.output.is_qualified()
    }
}

/// What one derivation run observed about one target.
///
/// The completeness *claim* the observation supports lives on the entry, not
/// here: an entry can also reach a claim through adjudication or review, and a
/// consumer must be able to read the claim without knowing where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundryDerivation {
    /// Transfers the solver reported without proven, complete evidence. They
    /// still ship: a partial summary can add a flow but can never deny one.
    pub unproven_transfers: u32,
    /// Procedures the interprocedural closure entered, including the target.
    pub closure_procedures: u32,
    pub boundaries: Vec<FoundryDerivationBoundary>,
    /// Every derived flow at full granularity. The entry's `transfers` are the
    /// argument-level projection of these.
    pub fine_grained: Vec<FoundryFineGrainedTransfer>,
}

impl FoundryDerivation {
    /// The rendered flows whose granularity the shipping transfers cannot
    /// carry, sorted.
    pub fn qualified_flows(&self) -> Vec<String> {
        let mut rendered = self
            .fine_grained
            .iter()
            .filter(|transfer| transfer.is_qualified())
            .map(FoundryFineGrainedTransfer::render)
            .collect::<Vec<_>>();
        rendered.sort();
        rendered.dedup();
        rendered
    }
}

/// One target's claim from one corpus, in the authored IR plus its envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FoundryEntry {
    pub id: String,
    pub corpus: FoundryCorpus,
    pub target: FoundryTarget,
    pub boundary: FoundryBoundary,
    pub claim: FoundryClaim,
    /// How much of the target's behavior this entry accounts for.
    ///
    /// Only a `complete` claim can deny a flow, so only a `complete` entry can
    /// carry a negative proof and only a `complete` entry can suppress. A
    /// translated corpus row is never `complete`: translation is not traversal.
    pub completeness: FoundryCompleteness,
    pub transfers: Vec<AuthoredSummaryTransfer>,
    pub artifact: FoundryArtifactBinding,
    pub evidence: Vec<FoundryEvidence>,
    pub notes: Vec<FoundryNote>,
    /// Present only on a derived entry. A corpus row is a translated claim, not
    /// a traversal, so it has nothing to say here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation: Option<FoundryDerivation>,
}

impl FoundryEntry {
    /// The shipping contract this entry carries.
    ///
    /// `None` for a [`FoundryClaim::NoFlow`] entry: the authored IR rejects a
    /// summary that declares no transfer and no effect, so the claim has no
    /// authored spelling and the entry records
    /// [`FoundryNote::NoFlowClaimNotCarried`] instead.
    pub fn authored_summary(&self) -> Option<AuthoredProcedureSummary> {
        if self.transfers.is_empty() {
            return None;
        }
        Some(AuthoredProcedureSummary {
            id: self.id.clone(),
            target: AuthoredProcedureTarget {
                path: self.target.artifact_path.clone(),
                symbol: self.target.signature.symbol(&self.target.member),
                has_receiver: self.boundary.has_receiver,
                variadic: false,
                parameter_count: self.boundary.parameter_count,
            },
            completeness: match self.completeness {
                FoundryCompleteness::Partial => Completeness::Partial,
                FoundryCompleteness::Complete => Completeness::Complete,
            },
            covers_overrides: false,
            normal_continuation_absent: false,
            normal_result_count: None,
            locations: Vec::new(),
            transfers: self.transfers.clone(),
            effects: Vec::new(),
            concurrency_effects: Vec::new(),
            declared_effects: Vec::new(),
            preconditions: None,
            result_contracts: Vec::new(),
            conditional_result_refinements: Vec::new(),
            conditional_indirect_writes: Vec::new(),
            normal_return_refinements: Vec::new(),
        })
    }

    /// The entry's transfers rendered for the join report, sorted.
    pub fn rendered_transfers(&self) -> Vec<String> {
        let mut rendered = self
            .transfers
            .iter()
            .map(render_transfer)
            .collect::<Vec<_>>();
        rendered.sort();
        rendered.dedup();
        rendered
    }
}

/// Whether an endpoint originates taint (a source) or consumes it (a sink).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundryEndpointRole {
    /// A method whose named access path becomes tainted (Models-as-Data
    /// `sourceModel`). The access path is the row's `output` column.
    Source,
    /// A method whose named access path is sensitive (Models-as-Data
    /// `sinkModel`). The access path is the row's `input` column.
    Sink,
}

impl FoundryEndpointRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Sink => "sink",
        }
    }
}

/// The root port a taint endpoint names: what becomes tainted (a source) or what
/// is sensitive (a sink).
///
/// A Models-as-Data access path can qualify the port with selectors
/// (`.Element`, `.Field[..]`); those are kept on the endpoint as a rendered
/// qualifier, and this is the root the qualifier hangs from. The root is what a
/// policy source binding or sink operand can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "port", rename_all = "snake_case")]
pub enum FoundryEndpointPort {
    /// `ReturnValue`: the call's return. Legal for a source (the return is
    /// tainted); never for a sink (a sink consumes an input, not a return).
    ReturnValue,
    /// `Argument[this]`: the receiver.
    Receiver,
    /// `Argument[N]`: the zero-based parameter.
    Parameter { ordinal: u32 },
}

impl FoundryEndpointPort {
    /// Render for a report and for a stable endpoint id.
    pub fn render(self) -> String {
        match self {
            Self::ReturnValue => "return_value".to_owned(),
            Self::Receiver => "receiver".to_owned(),
            Self::Parameter { ordinal } => format!("parameter[{ordinal}]"),
        }
    }
}

/// One Java taint endpoint translated from a Models-as-Data `sourceModel` or
/// `sinkModel` row.
///
/// A source names a method and the access path that becomes tainted (its
/// `output`); a sink names a method and the access path that is sensitive (its
/// `input`). Both are parsed structurally: the signature through
/// [`super::codeql`]'s signature parser, the access path through its access-path
/// parser, exactly as the summary-transfer translation reads them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FoundryTaintEndpoint {
    pub role: FoundryEndpointRole,
    pub target: FoundryTarget,
    /// The declaring package as the corpus spells it (`javax.servlet.http`).
    /// Slice selection derives the endpoint libraries from this column.
    pub package: String,
    /// The declaring type's simple name (`HttpServletRequest`).
    pub type_name: String,
    /// Whether the corpus applies the model to overrides in subtypes. A policy
    /// selector that matches by callee name already spans subtypes, so this is
    /// recorded rather than acted on.
    pub subtypes: bool,
    /// The root port(s) the row names, one per selected argument. A range
    /// (`Argument[0..1]`) or a set (`Argument[this,0]`) expands to one port each,
    /// mirroring the summary translator's expansion.
    pub ports: Vec<FoundryEndpointPort>,
    /// The rendered access-path qualifier when the row qualified the port
    /// (`Argument[0].Element` records `.Element`), else absent. The endpoint is
    /// still usable through its root port; the qualifier records that the row
    /// said more than the root port carries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualifier: Option<String>,
    /// The Models-as-Data `kind` column: the taint label the row assigns
    /// (`remote`, `command-injection`, `sql-injection`, `environment`, ...).
    pub kind: String,
    pub provenance: String,
    pub evidence: FoundryEvidence,
}

impl FoundryTaintEndpoint {
    /// The declaring type's fully-qualified name (`javax.servlet.http.Cookie`).
    pub fn declaring_type_fqn(&self) -> String {
        if self.package.is_empty() {
            self.type_name.clone()
        } else {
            format!("{}.{}", self.package, self.type_name)
        }
    }
}

/// A stable, validator-legal summary id for one corpus target.
///
/// Authored ids accept lowercase ASCII alphanumerics, `-`, `_`, and `.` only,
/// so a JVM signature cannot appear verbatim. The readable prefix is a
/// lossy rendering for humans and the digest suffix carries identity.
pub fn summary_id(corpus: FoundryCorpus, target: &FoundryTarget) -> String {
    let identity = target.identity();
    let mut digest = Sha256::new();
    digest.update(identity.as_bytes());
    let digest = digest.finalize();
    let mut hex = String::with_capacity(ID_DIGEST_HEX_CHARS);
    for byte in digest.iter().take(ID_DIGEST_HEX_CHARS.div_ceil(2)) {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex.truncate(ID_DIGEST_HEX_CHARS);
    format!(
        "{}.{}.{hex}",
        corpus.as_str(),
        readable_id_body(&identity, MAX_READABLE_ID_BYTES)
    )
}

/// The lossy human-readable part of a generated id.
///
/// Every byte outside the authored identifier alphabet becomes `-`, runs
/// collapse, and the result is truncated on a byte boundary. Truncation cannot
/// collide two targets because the digest suffix is a function of the whole
/// identity.
fn readable_id_body(identity: &str, max_bytes: usize) -> String {
    let mut body = String::with_capacity(identity.len().min(max_bytes));
    let mut previous_separator = false;
    for character in identity.chars() {
        let mapped = if character.is_ascii_alphanumeric() {
            character.to_ascii_lowercase()
        } else if character == '.' || character == '_' || character == '-' {
            character
        } else {
            '-'
        };
        let separator = !mapped.is_ascii_alphanumeric();
        if separator && previous_separator {
            continue;
        }
        if body.len() + mapped.len_utf8() > max_bytes {
            break;
        }
        body.push(mapped);
        previous_separator = separator;
    }
    let trimmed = body.trim_matches(|character: char| !character.is_ascii_alphanumeric());
    if trimmed.is_empty() {
        // An identity with no alphanumeric byte cannot happen for a JVM target,
        // but an empty body would produce an id that starts with `.`, which the
        // authored validator rejects. Keep the id well formed either way.
        return "target".to_owned();
    }
    trimmed.to_owned()
}

/// The JVM class-file path for a package and type as a corpus spells them.
///
/// `java.lang` + `System$Logger` is `java/lang/System$Logger.class`, which is
/// the same string both corpora reduce to, so the join key compares.
pub fn class_file_path(package: &str, type_name: &str) -> String {
    let mut path = String::with_capacity(package.len() + type_name.len() + 7);
    for character in package.chars() {
        path.push(if character == '.' { '/' } else { character });
    }
    if !path.is_empty() {
        path.push('/');
    }
    path.push_str(type_name);
    path.push_str(".class");
    path
}

/// The innermost segment of a possibly nested JVM type name.
pub fn nested_type_simple_name(type_name: &str) -> &str {
    match type_name.rfind('$') {
        Some(index) => &type_name[index + 1..],
        None => type_name,
    }
}

/// Split a parameter list on its top-level commas.
///
/// Erased JVM parameter types carry `[]` for arrays and, in a few corpora,
/// `<>` for a retained type argument. Both nest, so the split tracks depth
/// rather than scanning for every comma. Both corpus translators spell
/// parameter lists this way, so the rule lives here.
pub fn split_parameter_types(inner: &str) -> Vec<String> {
    if inner.is_empty() {
        return Vec::new();
    }
    let mut types = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (index, character) in inner.char_indices() {
        match character {
            '<' | '[' | '(' => depth += 1,
            '>' | ']' | ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                types.push(inner[start..index].trim().to_owned());
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    types.push(inner[start..].trim().to_owned());
    types
}

/// One transfer rendered as a stable comparable string.
pub fn render_transfer(transfer: &AuthoredSummaryTransfer) -> String {
    let input = match &transfer.input {
        AuthoredSummaryInput::Receiver {} => "receiver".to_owned(),
        AuthoredSummaryInput::Parameter { ordinal } => format!("parameter[{ordinal}]"),
    };
    let output = match &transfer.output {
        AuthoredSummaryOutput::NormalReturn {} => "normal_return".to_owned(),
        AuthoredSummaryOutput::IndexedNormalReturn { ordinal } => {
            format!("normal_return[{ordinal}]")
        }
        AuthoredSummaryOutput::Receiver {} => "receiver".to_owned(),
        AuthoredSummaryOutput::Capture { location } => format!("capture[{location}]"),
        AuthoredSummaryOutput::Heap { location } => format!("heap[{location}]"),
        AuthoredSummaryOutput::ExceptionalReturn {} => "exceptional_return".to_owned(),
    };
    let exit = match transfer.exit_kind {
        AuthoredSummaryExitKind::Normal => "normal",
        AuthoredSummaryExitKind::Exceptional => "exceptional",
    };
    format!("{input}->{output}@{exit}")
}

/// Accumulates one corpus's rows for one target into a single entry.
///
/// Corpora state one flow per row, so an entry is the union of its target's
/// rows. The receiver-ness and the parameter count of a target are not columns
/// in either corpus: they are the weakest shape the rows themselves require.
#[derive(Debug, Default)]
pub struct FoundryEntryBuilder {
    transfers: BTreeMap<String, AuthoredSummaryTransfer>,
    has_receiver: bool,
    max_ordinal: Option<u32>,
    evidence: Vec<FoundryEvidence>,
    notes: Vec<FoundryNote>,
    no_flow: bool,
    has_flow_rows: bool,
}

impl FoundryEntryBuilder {
    pub fn add_transfer(&mut self, transfer: AuthoredSummaryTransfer) {
        if matches!(transfer.input, AuthoredSummaryInput::Receiver {})
            || matches!(transfer.output, AuthoredSummaryOutput::Receiver {})
        {
            self.has_receiver = true;
        }
        if let AuthoredSummaryInput::Parameter { ordinal } = transfer.input {
            self.max_ordinal = Some(self.max_ordinal.map_or(ordinal, |seen| seen.max(ordinal)));
        }
        self.has_flow_rows = true;
        self.transfers.insert(render_transfer(&transfer), transfer);
    }

    pub fn add_evidence(&mut self, evidence: FoundryEvidence) {
        self.evidence.push(evidence);
    }

    pub fn add_note(&mut self, note: FoundryNote) {
        if !self.notes.contains(&note) {
            self.notes.push(note);
        }
    }

    /// Record that the corpus states this target carries no value flow.
    pub fn declare_no_flow(&mut self) {
        self.no_flow = true;
    }

    /// Finish the entry.
    ///
    /// `declared_arity` is the parameter count the corpus pins, when it pins an
    /// overload. Without it the count is the smallest one the rows require,
    /// which the entry records as a lower bound rather than a fact.
    pub fn finish(
        mut self,
        corpus: FoundryCorpus,
        target: FoundryTarget,
        declared_arity: Option<u32>,
    ) -> FoundryEntry {
        let lower_bound = self.max_ordinal.map_or(0, |ordinal| ordinal + 1);
        let parameter_count = match declared_arity {
            Some(arity) => arity.max(lower_bound),
            None => {
                self.add_note(FoundryNote::ParameterCountIsLowerBound {
                    observed: lower_bound,
                });
                lower_bound
            }
        };
        let claim = if self.no_flow && !self.has_flow_rows {
            self.add_note(FoundryNote::NoFlowClaimNotCarried);
            FoundryClaim::NoFlow
        } else {
            if self.no_flow {
                self.add_note(FoundryNote::ContradictoryCorpusRows);
            }
            FoundryClaim::Flows
        };
        self.evidence.sort();
        self.evidence.dedup();
        self.notes.sort();
        FoundryEntry {
            id: summary_id(corpus, &target),
            corpus,
            target,
            boundary: FoundryBoundary {
                has_receiver: self.has_receiver,
                parameter_count,
            },
            claim,
            // The plan defaults every unreviewed entry to `partial`: a partial
            // summary can add flows but can never prove absence, so a wrong one
            // costs a visible false positive, never a silent miss. A builder
            // accumulates corpus rows, and translation is not traversal, so a
            // built entry can never reach `complete`.
            completeness: FoundryCompleteness::Partial,
            transfers: self.transfers.into_values().collect(),
            artifact: FoundryArtifactBinding::Unresolved,
            evidence: self.evidence,
            notes: self.notes,
            derivation: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(member: &str, types: &[&str]) -> FoundryTarget {
        FoundryTarget {
            artifact_path: "java/lang/String.class".to_owned(),
            member: member.to_owned(),
            signature: FoundrySignature::Overload {
                types: types.iter().map(|value| (*value).to_owned()).collect(),
            },
        }
    }

    #[test]
    fn generated_ids_are_authoring_legal_and_distinguish_overloads() {
        let first = summary_id(FoundryCorpus::Codeql, &target("valueOf", &["char[]"]));
        let second = summary_id(FoundryCorpus::Codeql, &target("valueOf", &["Object"]));

        assert_ne!(first, second);
        for id in [&first, &second] {
            assert!(
                id.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'.'
                    || byte == b'-'
                    || byte == b'_'),
                "id {id} leaves the authored identifier alphabet"
            );
            assert!(id.as_bytes()[0].is_ascii_lowercase());
            assert!(id.as_bytes()[id.len() - 1].is_ascii_alphanumeric());
            assert!(id.len() <= 256);
        }
    }

    #[test]
    fn long_signatures_stay_within_the_authored_id_limit() {
        let types = (0..64)
            .map(|index| format!("com.example.pkg.VeryLongParameterTypeName{index}"))
            .collect::<Vec<_>>();
        let target = FoundryTarget {
            artifact_path: "com/example/pkg/Wide.class".to_owned(),
            member: "method".to_owned(),
            signature: FoundrySignature::Overload { types },
        };

        let id = summary_id(FoundryCorpus::Joern, &target);

        assert!(id.len() <= 256, "id is {} bytes", id.len());
        assert!(id.starts_with("joern."));
    }

    #[test]
    fn any_overload_entries_report_a_lower_bound_parameter_count() {
        let mut builder = FoundryEntryBuilder::default();
        builder.add_transfer(AuthoredSummaryTransfer {
            input: AuthoredSummaryInput::Parameter { ordinal: 2 },
            exit_kind: AuthoredSummaryExitKind::Normal,
            output: AuthoredSummaryOutput::NormalReturn {},
        });

        let entry = builder.finish(
            FoundryCorpus::Codeql,
            FoundryTarget {
                artifact_path: "java/lang/String.class".to_owned(),
                member: "format".to_owned(),
                signature: FoundrySignature::AnyOverload,
            },
            None,
        );

        assert_eq!(entry.boundary.parameter_count, 3);
        assert!(!entry.boundary.has_receiver);
        assert!(
            entry
                .notes
                .contains(&FoundryNote::ParameterCountIsLowerBound { observed: 3 })
        );
    }

    #[test]
    fn a_no_flow_claim_has_no_authored_spelling() {
        let mut builder = FoundryEntryBuilder::default();
        builder.declare_no_flow();

        let entry = builder.finish(FoundryCorpus::Joern, target("length", &[]), Some(0));

        assert_eq!(entry.claim, FoundryClaim::NoFlow);
        assert!(entry.authored_summary().is_none());
        assert!(entry.notes.contains(&FoundryNote::NoFlowClaimNotCarried));
    }

    #[test]
    fn class_file_paths_follow_jvm_binary_naming() {
        assert_eq!(
            class_file_path("java.lang", "System$Logger"),
            "java/lang/System$Logger.class"
        );
        assert_eq!(class_file_path("", "Root"), "Root.class");
        assert_eq!(nested_type_simple_name("System$Logger"), "Logger");
        assert_eq!(nested_type_simple_name("String"), "String");
    }
}
