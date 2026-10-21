//! Class-set type propagation adapter contract.
//!
//! The class-set engine in `brokk-bifrost-flow` propagates one class atom per
//! class-producing site through the existing value-flow solver and asks, at
//! every member access, which classes the receiver may hold. Everything the
//! engine cannot derive from the language-neutral semantic IR is answered by a
//! per-language [`TypeFlowAdapter`]: which call constructs a class, which
//! class a constant or container literal has, which class a parameter
//! declares, which member a call or load accesses, and whether a class
//! declares a member. JavaScript, Ruby, and PHP adapters are follow-on work;
//! they supply seeds and member lookup only, never a solver.

use std::cmp::Ordering;
use std::fmt;
use std::sync::Arc;

use brokk_bifrost_core::analyzer::prepared_syntax::{PreparedSyntaxSource, PreparedSyntaxTree};

use crate::analyzer::semantic_model::SemanticModelProvenance;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::hash::HashMap;
use tree_sitter::Node;

use crate::analyzer::semantic::ir::SignedIntegerMagnitude;

use crate::analyzer::semantic::oracle::CandidateCoverage;

use crate::analyzer::semantic::CallSiteId;

use crate::analyzer::semantic::LengthDelimitedDigest;

use crate::analyzer::semantic::MemoryLocation;

use crate::analyzer::semantic::MemoryLocationId;

use crate::analyzer::semantic::MemoryLocationKind;

use crate::analyzer::semantic::ProcedureHandle;

use crate::analyzer::semantic::ProcedureId;

use crate::analyzer::semantic::ProgramPointId;

use crate::analyzer::semantic::SemanticArtifactKey;

use crate::analyzer::semantic::SemanticCallSite;

use crate::analyzer::semantic::SemanticLocator;

use crate::analyzer::semantic::SourceMappingKind;

use crate::analyzer::semantic::SourcePosition;

use crate::analyzer::semantic::SourceSpan;

use crate::analyzer::semantic::StableDigest;

use crate::analyzer::semantic::ValueId;

use crate::analyzer::semantic::WorkspaceRelativePath;

#[doc(hidden)]
pub fn node_at_span(prepared: &PreparedSyntaxTree, span: SourceSpan) -> Option<Node<'_>> {
    prepared
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
}

#[doc(hidden)]
pub fn integer_offset_from_binary_operands<'tree>(
    operator: &str,
    left: Node<'tree>,
    right: Node<'tree>,
    mut integer: impl FnMut(Node<'tree>) -> Option<SignedIntegerMagnitude>,
) -> Option<(Node<'tree>, SignedIntegerMagnitude)> {
    let (operand, offset, subtract) = match (operator, left.kind(), right.kind()) {
        ("+", "identifier", _) => (left, integer(right)?, false),
        ("+", _, "identifier") => (right, integer(left)?, false),
        ("-", "identifier", _) => (left, integer(right)?, true),
        _ => return None,
    };
    let offset = if subtract {
        SignedIntegerMagnitude::new(!offset.negative(), offset.magnitude())
    } else {
        offset
    };
    Some((operand, offset))
}

/// One class a value may be an instance of, or the honest statement that
/// the engine could not classify it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClassAtom {
    Class(ClassIdentity),
    Unknown(UnknownReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClassIdentity {
    Workspace(CodeUnit),
    External {
        qualified_name: Box<str>,
        symbol_id: Box<str>,
    },
    /// A class the language itself supplies for every program, such as
    /// Python's implicit `builtins.object` root. It has no workspace
    /// declaration and no semantic-model symbol ID.
    Intrinsic {
        qualified_name: Box<str>,
    },
}

impl ClassIdentity {
    pub fn qualified_name(&self) -> &str {
        match self {
            Self::Workspace(unit) => unit.fq_name_str(),
            Self::External { qualified_name, .. } | Self::Intrinsic { qualified_name } => {
                qualified_name
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnknownReason {
    RootParameter,
    SelfReceiver,
    VariadicParameter,
    UnresolvedCall,
    Truncated,
    UnmodeledLoad,
    Await,
    Capture,
    AmbiguousCallee,
    ExternalNotModeled,
    UnresolvedBase,
    DynamicAttributes,
    PackIncomplete,
    UncertainFlow,
    /// A class field may receive a value the workspace-wide syntactic slot
    /// summary could not classify, or a write/hierarchy boundary prevents the
    /// summary from proving it observed the whole slot.
    FieldSlotIncomplete,
    DynamicFieldWrite,
    /// The dataflow solver stopped before a fixed point
    /// (`SolverTermination::ExceededBudget`): any unreached sink may have
    /// been reached with more solver work.
    SolverBudget,
    /// The semantic-work budget was exhausted for this root: a provider
    /// outcome carried a typed `ExceededBudget` during discovery or the
    /// solve, or a bounded semantic resolution (a type lookup) reported it.
    SemanticBudget,
    /// No meeting reached the sink and the root's closure does not say why:
    /// the receiver's producing call is not covered by the closure, so the
    /// root's result is incomplete for coverage reasons. Never attached to a
    /// sink the closure's coverage can name (`UnresolvedCall`, `Truncated`).
    IncompleteRoot,
    /// One named class is useful positive evidence, but the adapter cannot
    /// prove that it exhausts the runtime class set.
    OpenTypeBound,
    /// The receiver is a real scalar value, but the class-set domain does not
    /// model a nominal member-bearing class for it.
    ScalarReceiver,
    /// The value is a class object; its member surface -- its metaclass's
    /// members plus the class's own class-level attributes -- is not modeled
    /// by the class-set domain.
    ClassObject,
    /// Class creation can install members the declaration does not show: a
    /// metaclass writes them, a class-header keyword configures the same
    /// machinery, or a decorator returns a different class. The declared
    /// hierarchy therefore does not bound the class's members. A receiver that
    /// is itself a class object carries the same remainder: its members are
    /// the attributes of whatever class it is.
    ClassCreation,
    /// A language guard was recognized structurally, but its class predicate
    /// is not modeled by the adapter. The class name identifies the predicate
    /// that remained unresolved.
    UnmodeledGuard {
        class: Box<str>,
    },
    /// The guard's condition is a call on this receiver whose callee the
    /// adapter cannot model. The developer's predicate states something about
    /// the receiver on both arms of the guard, and the class-set domain cannot
    /// say what, so neither arm's set is bounded. Unlike
    /// [`UnmodeledGuard`](Self::UnmodeledGuard), no class is named: the
    /// condition spelled a callable, not a class.
    UnmodeledPredicate,
}

impl UnknownReason {
    /// Stable reason family label. Named reasons intentionally keep the same
    /// family label; use [`Display`](fmt::Display) when the payload is needed.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::RootParameter => "root_parameter",
            Self::SelfReceiver => "self_receiver",
            Self::VariadicParameter => "variadic_parameter",
            Self::UnresolvedCall => "unresolved_call",
            Self::Truncated => "truncated",
            Self::UnmodeledLoad => "unmodeled_load",
            Self::Await => "await",
            Self::Capture => "capture",
            Self::AmbiguousCallee => "ambiguous_callee",
            Self::ExternalNotModeled => "external_not_modeled",
            Self::UnresolvedBase => "unresolved_base",
            Self::DynamicAttributes => "dynamic_attributes",
            Self::PackIncomplete => "pack_incomplete",
            Self::UncertainFlow => "uncertain_flow",
            Self::FieldSlotIncomplete => "field_slot_incomplete",
            Self::DynamicFieldWrite => "dynamic_field_write",
            Self::SolverBudget => "solver_budget",
            Self::SemanticBudget => "semantic_budget",
            Self::IncompleteRoot => "incomplete_root",
            Self::OpenTypeBound => "open_type_bound",
            Self::ScalarReceiver => "scalar_receiver",
            Self::ClassObject => "class_object",
            Self::ClassCreation => "class_creation",
            Self::UnmodeledGuard { .. } => "unmodeled_guard",
            Self::UnmodeledPredicate => "unmodeled_predicate",
        }
    }

    /// Parse a persisted or diagnostic reason label, including the payload of
    /// a named unmodeled guard. This accepts only the structured reason
    /// format; it does not interpret source text.
    pub fn from_label(label: &str) -> Option<Self> {
        Some(match label {
            "root_parameter" => Self::RootParameter,
            "self_receiver" => Self::SelfReceiver,
            "variadic_parameter" => Self::VariadicParameter,
            "unresolved_call" => Self::UnresolvedCall,
            "truncated" => Self::Truncated,
            "unmodeled_load" => Self::UnmodeledLoad,
            "await" => Self::Await,
            "capture" => Self::Capture,
            "ambiguous_callee" => Self::AmbiguousCallee,
            "external_not_modeled" => Self::ExternalNotModeled,
            "unresolved_base" => Self::UnresolvedBase,
            "dynamic_attributes" => Self::DynamicAttributes,
            "pack_incomplete" => Self::PackIncomplete,
            "uncertain_flow" => Self::UncertainFlow,
            "field_slot_incomplete" => Self::FieldSlotIncomplete,
            "dynamic_field_write" => Self::DynamicFieldWrite,
            "solver_budget" => Self::SolverBudget,
            "semantic_budget" => Self::SemanticBudget,
            "incomplete_root" => Self::IncompleteRoot,
            "open_type_bound" => Self::OpenTypeBound,
            "scalar_receiver" => Self::ScalarReceiver,
            "class_object" => Self::ClassObject,
            "class_creation" => Self::ClassCreation,
            "unmodeled_predicate" => Self::UnmodeledPredicate,
            label => Self::UnmodeledGuard {
                class: label
                    .strip_prefix("unmodeled_guard:")
                    .filter(|class| !class.is_empty())?
                    .into(),
            },
        })
    }
}

impl fmt::Display for UnknownReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnmodeledGuard { class } => {
                write!(formatter, "{}:{class}", self.label())
            }
            _ => formatter.write_str(self.label()),
        }
    }
}

/// Answer of an adapter seed query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassSeed {
    Class(ClassIdentity),
    /// Several named classes are possible and no other runtime class is.
    /// Construction canonicalizes the class list; expansion emits every class
    /// in that order.
    Classes(Box<[ClassIdentity]>),
    /// The named class is possible, but other runtime classes may also flow.
    /// Expansion always emits the class first and the open remainder second.
    ClassWithOpenBound(ClassIdentity),
    /// Several named classes are possible, and other runtime classes may also
    /// flow. Construction canonicalizes the class list; expansion emits every
    /// class in that order followed by one open remainder.
    ClassesWithOpenBound(Box<[ClassIdentity]>),
    Unknown(UnknownReason),
    /// The site does not produce a class (an ordinary call, an undeclared parameter).
    NotApplicable,
}

impl ClassSeed {
    pub fn classes(classes: impl IntoIterator<Item = ClassIdentity>) -> Self {
        Self::Classes(canonical_class_list(classes))
    }

    pub fn classes_with_open_bound(classes: impl IntoIterator<Item = ClassIdentity>) -> Self {
        Self::ClassesWithOpenBound(canonical_class_list(classes))
    }

    /// Expand an adapter answer into the language-neutral facts propagated by
    /// the flow engine. The stable class-before-unknown order is part of
    /// reusable-summary event identity.
    pub fn into_atoms(self) -> impl Iterator<Item = ClassAtom> {
        let atoms = match self {
            Self::Class(class) => vec![ClassAtom::Class(class)],
            Self::Classes(classes) => canonical_class_list(classes.into_vec())
                .into_vec()
                .into_iter()
                .map(ClassAtom::Class)
                .collect(),
            Self::ClassWithOpenBound(class) => vec![
                ClassAtom::Class(class),
                ClassAtom::Unknown(UnknownReason::OpenTypeBound),
            ],
            Self::ClassesWithOpenBound(classes) => canonical_class_list(classes.into_vec())
                .into_vec()
                .into_iter()
                .map(ClassAtom::Class)
                .chain(std::iter::once(ClassAtom::Unknown(
                    UnknownReason::OpenTypeBound,
                )))
                .collect(),
            Self::Unknown(reason) => vec![ClassAtom::Unknown(reason)],
            Self::NotApplicable => Vec::new(),
        };
        atoms.into_iter()
    }
}

/// The one spelling of a multi-class seed's class list: sorted, deduplicated,
/// and non-empty. Seed identity feeds reusable-summary event identity, so two
/// adapters that name the same classes must produce the same list.
fn canonical_class_list(classes: impl IntoIterator<Item = ClassIdentity>) -> Box<[ClassIdentity]> {
    let mut classes = classes.into_iter().collect::<Vec<_>>();
    classes.sort_by(class_identity_order);
    classes.dedup();
    assert!(
        !classes.is_empty(),
        "a multi-class seed names at least one class"
    );
    classes.into_boxed_slice()
}

#[doc(hidden)]
pub type ExternalClassCache =
    HashMap<(Language, Box<str>, Option<Box<str>>), Option<ClassIdentity>>;

#[doc(hidden)]
pub fn source_span_for_node(node: tree_sitter::Node<'_>) -> SourceSpan {
    SourceSpan::new(
        SourcePosition::new(
            node.start_byte() as u32,
            node.start_position().row as u32,
            node.start_position().column as u32,
        ),
        SourcePosition::new(
            node.end_byte() as u32,
            node.end_position().row as u32,
            node.end_position().column as u32,
        ),
    )
    .expect("a tree-sitter node range is a valid source span")
}

#[doc(hidden)]
pub fn analyzer_range_for_span(span: SourceSpan) -> Range {
    Range {
        start_byte: span.start_byte() as usize,
        end_byte: span.end_byte() as usize,
        start_line: span.start().line() as usize,
        end_line: span.end().line() as usize,
    }
}

#[doc(hidden)]
pub fn current_indexed_prepared(
    prepared: Option<Arc<PreparedSyntaxTree>>,
    is_current: impl FnOnce(&PreparedSyntaxTree) -> bool,
) -> Option<Arc<PreparedSyntaxTree>> {
    let prepared = prepared?;
    (matches!(prepared.backing(), PreparedSyntaxSource::Indexed(_)) && is_current(&prepared))
        .then_some(prepared)
}

/// Where one class-carrying source was seeded, retained for findings,
/// witnesses, and receiver-driven dispatch hints.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceSite {
    pub file: ProjectFile,
    pub span: SourceSpan,
    pub kind: SourceSiteKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceSiteKind {
    ConstructorCall,
    /// A modeled attribute or subscript protocol produced this exact value.
    ExactAccessResult,
    Literal,
    ContainerLiteral,
    DeclaredParameter,
    RootReceiver,
    /// A guard arm proved this class; no syntax here produced the value. A
    /// finding witness prefers a site that did, so this kind ranks last when
    /// one class has more than one origin.
    NarrowingGuard,
    /// Membership follows from entering a guard arm, but the activating source
    /// does not independently admit this class as a value alternative.
    ConditionalNarrowingGuard,
    /// Unclassified origin syntax; independent of whether its class is known.
    Unknown,
    /// An exact callable-return claim produced this value's runtime class.
    ExactCallResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberDeclaration {
    Workspace(CodeUnit),
    External(ExternalMemberDeclaration),
}

/// The exact modeled declarations that jointly prove an external member is
/// present. More than one ID represents one complete callable family, never
/// an arbitrary choice among conflicting records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalMemberDeclaration {
    symbol_ids: Box<[Box<str>]>,
}

impl ExternalMemberDeclaration {
    pub fn new(symbol_ids: impl IntoIterator<Item = Box<str>>) -> Self {
        let mut symbol_ids = symbol_ids.into_iter().collect::<Vec<_>>();
        symbol_ids.sort_unstable();
        symbol_ids.dedup();
        assert!(
            !symbol_ids.is_empty(),
            "an external member declaration names at least one exact symbol"
        );
        Self {
            symbol_ids: symbol_ids.into_boxed_slice(),
        }
    }

    pub fn symbol_ids(&self) -> &[Box<str>] {
        &self.symbol_ids
    }
}

/// What a class declaration binds under one member name, beyond the instance
/// stores the class-set field-store survey collects.
///
/// The survey only sees writes through a receiver, so a class-level binding is
/// a value it could not have observed. Naming the binding separates two cases
/// the survey cannot tell apart: a declared procedure, which
/// [`TypeFlowAdapter::member_lookup`] already names exactly and which no
/// instance-attribute slot describes, and any other class-level binding, whose
/// value stays open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassBodyMemberBinding {
    /// The class body binds nothing under this name. The surveyed instance
    /// stores are the whole slot.
    Unbound,
    /// The class body declares this member as a plain procedure. Reading it
    /// yields that method; `member_lookup` names the declaration, and no
    /// instance-attribute value exists for a store survey to classify.
    Procedure,
    /// The class body binds a value this adapter does not classify here: a
    /// class-level assignment, a decorated definition whose result is
    /// arbitrary, or a declaration the adapter could not read.
    Unclassified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberLookup {
    Present(MemberLookupHit),
    Absent,
    /// No declaration was found, but runtime stores can extend this class.
    /// A workspace store survey must close that remainder before absence is
    /// authoritative. This result never authorizes negative narrowing alone.
    DeclarationAbsent,
    Unknown(UnknownReason),
}

/// Positive member evidence and whether its dispatch targets are complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberLookupHit {
    pub declaration: MemberDeclaration,
    pub dispatch_coverage: CandidateCoverage,
}

impl MemberLookupHit {
    pub fn new(declaration: MemberDeclaration, dispatch_coverage: CandidateCoverage) -> Self {
        Self {
            declaration,
            dispatch_coverage,
        }
    }
}

#[doc(hidden)]
pub fn present_member(declaration: MemberDeclaration) -> MemberLookup {
    MemberLookup::Present(MemberLookupHit::new(declaration, CandidateCoverage::Open))
}

/// Provenance for one uniquely reaching exact result at a receiver.
/// The value-flow solver creates this only when every reaching meeting has
/// the same proven, non-uncertain constructor source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstructorResultOrigin {
    pub classes: Box<[ClassIdentity]>,
    pub producer: ExactResultProducer,
    pub result: ValueId,
    pub source: SourceSite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactResultProducer {
    Call(CallSiteId),
    MemoryLoad {
        point: ProgramPointId,
        location: MemoryLocationId,
    },
}

/// Constructor provenance reaching one receiver call. `Ambiguous` means a
/// constructor source exists but the solver cannot prove one same-origin
/// source; adapters must not treat that receiver as a unique instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstructorResultEvidence {
    None,
    Unique(ConstructorResultOrigin),
    Ambiguous,
}

/// Durable identity of one call site across rematerializations of the same
/// semantic artifact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DispatchHintCallSiteKey {
    procedure: (SemanticArtifactKey, ProcedureId),
    call: CallSiteId,
}

impl DispatchHintCallSiteKey {
    pub fn new(procedure: (SemanticArtifactKey, ProcedureId), call: CallSiteId) -> Self {
        Self { procedure, call }
    }

    pub fn for_call(procedure: &ProcedureHandle, call: CallSiteId) -> Self {
        Self::new(procedure.durable_key(), call)
    }

    pub fn procedure(&self) -> &(SemanticArtifactKey, ProcedureId) {
        &self.procedure
    }

    pub const fn call(&self) -> CallSiteId {
        self.call
    }
}

/// One member declaration made eligible by a propagated receiver class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchHint {
    declaration: MemberDeclaration,
    receiver_class: ClassIdentity,
    origin: SourceSite,
}

impl DispatchHint {
    pub fn new(
        declaration: MemberDeclaration,
        receiver_class: ClassIdentity,
        origin: SourceSite,
    ) -> Self {
        Self {
            declaration,
            receiver_class,
            origin,
        }
    }

    pub const fn declaration(&self) -> &MemberDeclaration {
        &self.declaration
    }

    pub const fn receiver_class(&self) -> &ClassIdentity {
        &self.receiver_class
    }

    pub const fn origin(&self) -> &SourceSite {
        &self.origin
    }
}

/// The complete receiver-derived answer for one call site. `exhaustive`
/// states that the receiver class set had no Unknown or uncertain meeting;
/// the hint list may be empty when every known receiver lacks the member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchHintProof {
    Proven,
    Unproven,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchHintSet {
    call_site: DispatchHintCallSiteKey,
    hints: Box<[DispatchHint]>,
    exhaustive: bool,
    proof: DispatchHintProof,
}

impl DispatchHintSet {
    pub fn new(
        call_site: DispatchHintCallSiteKey,
        mut hints: Vec<DispatchHint>,
        exhaustive: bool,
        proof: DispatchHintProof,
    ) -> Self {
        hints.sort_by(dispatch_hint_order);
        hints.dedup();
        Self {
            call_site,
            hints: hints.into_boxed_slice(),
            exhaustive,
            proof,
        }
    }

    pub const fn call_site(&self) -> &DispatchHintCallSiteKey {
        &self.call_site
    }

    pub fn hints(&self) -> &[DispatchHint] {
        &self.hints
    }

    pub const fn exhaustive(&self) -> bool {
        self.exhaustive
    }

    pub const fn proof(&self) -> DispatchHintProof {
        self.proof
    }
}

/// Immutable, order-independent receiver-driven dispatch input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchHints {
    entries: Box<[DispatchHintSet]>,
    digest: StableDigest,
}

impl DispatchHints {
    pub fn new(mut entries: Vec<DispatchHintSet>) -> Self {
        entries.sort_by(|left, right| left.call_site.cmp(&right.call_site));
        assert!(
            entries
                .windows(2)
                .all(|pair| pair[0].call_site != pair[1].call_site),
            "one canonical dispatch hint set exists per call site"
        );
        let digest = dispatch_hints_digest(&entries);
        Self {
            entries: entries.into_boxed_slice(),
            digest,
        }
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    pub fn for_call(
        &self,
        procedure: &ProcedureHandle,
        call: CallSiteId,
    ) -> Option<&DispatchHintSet> {
        let key = DispatchHintCallSiteKey::for_call(procedure, call);
        self.entries
            .binary_search_by(|entry| entry.call_site.cmp(&key))
            .ok()
            .map(|index| &self.entries[index])
    }

    pub fn entries(&self) -> &[DispatchHintSet] {
        &self.entries
    }

    /// Replace the named call-site sets and retain every other published set.
    /// Updates may arrive in any order; construction restores canonical order.
    pub fn with_updates(&self, updates: impl IntoIterator<Item = DispatchHintSet>) -> Self {
        let mut entries = self.entries.to_vec();
        for update in updates {
            match entries.binary_search_by(|entry| entry.call_site.cmp(&update.call_site)) {
                Ok(index) => entries[index] = update,
                Err(index) => entries.insert(index, update),
            }
        }
        Self::new(entries)
    }

    pub const fn digest(&self) -> StableDigest {
        self.digest
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for DispatchHints {
    fn default() -> Self {
        Self::empty()
    }
}

fn dispatch_hint_order(left: &DispatchHint, right: &DispatchHint) -> Ordering {
    class_identity_order(&left.receiver_class, &right.receiver_class)
        .then_with(|| member_declaration_order(&left.declaration, &right.declaration))
        .then_with(|| source_site_order(&left.origin, &right.origin))
}

fn class_identity_order(left: &ClassIdentity, right: &ClassIdentity) -> Ordering {
    match (left, right) {
        (ClassIdentity::Workspace(left), ClassIdentity::Workspace(right)) => left
            .declaration_id()
            .as_str()
            .cmp(right.declaration_id().as_str()),
        (
            ClassIdentity::Workspace(_),
            ClassIdentity::External { .. } | ClassIdentity::Intrinsic { .. },
        ) => Ordering::Less,
        (
            ClassIdentity::External { .. } | ClassIdentity::Intrinsic { .. },
            ClassIdentity::Workspace(_),
        ) => Ordering::Greater,
        (ClassIdentity::External { .. }, ClassIdentity::Intrinsic { .. }) => Ordering::Less,
        (ClassIdentity::Intrinsic { .. }, ClassIdentity::External { .. }) => Ordering::Greater,
        (
            ClassIdentity::Intrinsic {
                qualified_name: left_name,
            },
            ClassIdentity::Intrinsic {
                qualified_name: right_name,
            },
        ) => left_name.cmp(right_name),
        (
            ClassIdentity::External {
                qualified_name: left_name,
                symbol_id: left_id,
            },
            ClassIdentity::External {
                qualified_name: right_name,
                symbol_id: right_id,
            },
        ) => left_name
            .cmp(right_name)
            .then_with(|| left_id.cmp(right_id)),
    }
}

fn member_declaration_order(left: &MemberDeclaration, right: &MemberDeclaration) -> Ordering {
    match (left, right) {
        (MemberDeclaration::Workspace(left), MemberDeclaration::Workspace(right)) => left
            .declaration_id()
            .as_str()
            .cmp(right.declaration_id().as_str()),
        (MemberDeclaration::Workspace(_), MemberDeclaration::External(_)) => Ordering::Less,
        (MemberDeclaration::External(_), MemberDeclaration::Workspace(_)) => Ordering::Greater,
        (MemberDeclaration::External(left), MemberDeclaration::External(right)) => {
            left.symbol_ids.cmp(&right.symbol_ids)
        }
    }
}

fn source_site_order(left: &SourceSite, right: &SourceSite) -> Ordering {
    portable_source_path(left)
        .as_str()
        .cmp(portable_source_path(right).as_str())
        .then_with(|| left.span.start_byte().cmp(&right.span.start_byte()))
        .then_with(|| left.span.end_byte().cmp(&right.span.end_byte()))
        .then_with(|| source_site_kind_tag(left.kind).cmp(&source_site_kind_tag(right.kind)))
}

fn portable_source_path(site: &SourceSite) -> WorkspaceRelativePath {
    WorkspaceRelativePath::try_from_path(site.file.rel_path())
        .expect("a semantic source site has a portable workspace-relative path")
}

/// The persisted tag of one source-site kind. A class-set summary names its
/// guard sources by a key derived from this tag, so the mapping is shared
/// rather than restated.
pub fn source_site_kind_tag(kind: SourceSiteKind) -> u8 {
    match kind {
        SourceSiteKind::ConstructorCall => 0,
        SourceSiteKind::Literal => 1,
        SourceSiteKind::ContainerLiteral => 2,
        SourceSiteKind::DeclaredParameter => 3,
        SourceSiteKind::RootReceiver => 4,
        SourceSiteKind::Unknown => 5,
        // Appended: the tags of the kinds above are persisted.
        SourceSiteKind::NarrowingGuard => 6,
        SourceSiteKind::ConditionalNarrowingGuard => 7,
        SourceSiteKind::ExactAccessResult => 8,
        SourceSiteKind::ExactCallResult => 9,
    }
}

fn dispatch_hints_digest(entries: &[DispatchHintSet]) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-type-flow-dispatch-hints/v2");
    digest.push(
        &u64::try_from(entries.len())
            .expect("the dispatch hint entry count fits in u64")
            .to_le_bytes(),
    );
    for entry in entries {
        digest.push(entry.call_site.procedure.0.public_fingerprint().as_bytes());
        digest.push(&entry.call_site.procedure.1.get().to_le_bytes());
        digest.push(&entry.call_site.call.get().to_le_bytes());
        digest.push(if entry.exhaustive {
            b"exhaustive"
        } else {
            b"open"
        });
        digest.push(match entry.proof {
            DispatchHintProof::Proven => b"proven",
            DispatchHintProof::Unproven => b"unproven",
        });
        digest.push(
            &u64::try_from(entry.hints.len())
                .expect("the per-call dispatch hint count fits in u64")
                .to_le_bytes(),
        );
        for hint in &entry.hints {
            push_class_identity(&mut digest, &hint.receiver_class);
            push_member_declaration(&mut digest, &hint.declaration);
            let path = portable_source_path(&hint.origin);
            digest.push(path.as_str().as_bytes());
            digest.push(&hint.origin.span.start_byte().to_le_bytes());
            digest.push(&hint.origin.span.end_byte().to_le_bytes());
            digest.push(&[source_site_kind_tag(hint.origin.kind)]);
        }
    }
    digest.finish()
}

fn push_class_identity(digest: &mut LengthDelimitedDigest, identity: &ClassIdentity) {
    match identity {
        ClassIdentity::Workspace(unit) => {
            digest.push(b"workspace-class");
            digest.push(unit.declaration_id().as_str().as_bytes());
        }
        ClassIdentity::External {
            qualified_name,
            symbol_id,
        } => {
            digest.push(b"external-class");
            digest.push(qualified_name.as_bytes());
            digest.push(symbol_id.as_bytes());
        }
        ClassIdentity::Intrinsic { qualified_name } => {
            digest.push(b"intrinsic-class");
            digest.push(qualified_name.as_bytes());
        }
    }
}

fn push_member_declaration(digest: &mut LengthDelimitedDigest, declaration: &MemberDeclaration) {
    match declaration {
        MemberDeclaration::Workspace(unit) => {
            digest.push(b"workspace-member");
            digest.push(unit.declaration_id().as_str().as_bytes());
        }
        MemberDeclaration::External(declaration) => {
            digest.push(b"external-member-family");
            digest.push(
                &u64::try_from(declaration.symbol_ids.len())
                    .expect("the external member family size fits in u64")
                    .to_le_bytes(),
            );
            for symbol_id in &declaration.symbol_ids {
                digest.push(symbol_id.as_bytes());
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NarrowingVerdict {
    Keep,
    Drop,
    /// The predicate result is unknown for this candidate. The candidate is
    /// retained on both edges and the caller may attach the reason only to
    /// the true edge's result.
    Incomplete(UnknownReason),
    /// A neutral, unmodeled predicate result. Keep the candidate on both
    /// edges without adding an incompleteness reason.
    Unknown,
}

/// An exactly bound, reviewed library contract on a call's normal return.
/// It constrains existing class possibilities; it never invents a class for
/// an unknown value, and says nothing about the exceptional continuation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalReturnTypeConstraint {
    pub subject: ValueId,
    pub classes: Box<[ClassIdentity]>,
    pub provenance: SemanticModelProvenance,
}

/// The workspace hierarchy facts needed to decide whether a receiver or
/// class-keyed field slot is closed under the analyzer's known world.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassHierarchy {
    pub ancestors: Vec<ClassIdentity>,
    /// `None` means the workspace descendant inventory is unavailable.
    pub descendants: Option<Vec<ClassIdentity>>,
    pub unresolved_base: bool,
    pub dynamic_attributes: bool,
}

impl ClassHierarchy {
    /// The safe default for an adapter that has not implemented hierarchy
    /// support: it cannot authorize a leaf receiver or a complete field slot.
    pub fn unknown() -> Self {
        Self {
            ancestors: Vec::new(),
            descendants: None,
            unresolved_base: true,
            dynamic_attributes: true,
        }
    }
}

/// The names a structured dynamic field mutation can install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicFieldNameSet {
    /// Every installed name is known from the source structure.
    Exact(Vec<Box<str>>),
    /// Every installed name starts with this literal prefix.
    Prefix(Box<str>),
    /// The source does not constrain the installed name.
    Any,
    /// The operation removes attributes and installs none.
    None,
}

/// A structured field mutation that does not appear as a direct Field store
/// in semantic IR. A singleton source literal keeps the legacy member spelling;
/// other writes carry their name set, receiver, and source site to the flow engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicFieldWrite {
    Member(Box<str>),
    Scoped {
        names: DynamicFieldNameSet,
        receiver: Option<ValueId>,
        span: SourceSpan,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberAccessKind {
    Call,
    Load,
}

pub enum MemberAccessQuery<'a> {
    Call(&'a SemanticCallSite),
    Load(&'a MemoryLocation),
}

#[doc(hidden)]
pub fn accessed_member_locator<'a>(
    procedure: &'a ProcedureHandle,
    site: MemberAccessQuery<'a>,
) -> Option<&'a SemanticLocator> {
    match site {
        MemberAccessQuery::Call(call) => {
            let semantics = procedure.semantics();
            let callee = semantics.value(call.callee)?;
            let mapping = semantics.source_mapping(callee.source)?;
            (mapping.kind == SourceMappingKind::Exact).then_some(&mapping.locator)
        }
        MemberAccessQuery::Load(location) => {
            let MemoryLocationKind::Field { member, .. } = &location.kind else {
                return None;
            };
            Some(member)
        }
    }
}

/// Receiver and construction evidence for a call-shaped member lookup.
#[derive(Debug, Clone, Copy)]
pub struct MemberReceiverQuery<'a> {
    pub procedure: &'a ProcedureHandle,
    pub receiver: ValueId,
    pub call: &'a SemanticCallSite,
    pub constructor: &'a ConstructorResultEvidence,
    pub class: &'a ClassIdentity,
    pub member: &'a str,
}

/// What an opaque guard condition says about a call argument.
///
/// The three cases are distinct answers, not degrees of confidence. A
/// condition that is not a predicate call on a candidate value constrains
/// nothing; a modeled callee classifies every candidate; an unmodeled callee
/// says that this value is constrained in a way the engine cannot name, which
/// holds on both arms of the guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallGuardOutcome {
    /// The condition constrains no value the engine tracks.
    NoConstraint,
    /// The callee was modeled: one verdict per candidate, in input order,
    /// with the same true/false-arm contract as `narrowing_verdicts`.
    Narrowed {
        value: ValueId,
        verdicts: Vec<NarrowingVerdict>,
    },
    /// Intersect known candidates on true and exclude them on false. An
    /// unnamed incoming value acquires the target bound only on true.
    Intersected {
        value: ValueId,
        verdicts: Vec<NarrowingVerdict>,
        target: ClassSeed,
    },
    /// Replace the incoming type on true; the false arm retains it unchanged.
    /// The replacement still requires an incoming value at the guarded point.
    Replaced { value: ValueId, target: ClassSeed },
    /// The condition is a call whose callee could not be modeled. Every
    /// directly passed argument is constrained by it, in call order: the
    /// condition says something the engine cannot name about each of them, on
    /// both arms.
    Unmodeled { values: Vec<ValueId> },
}

#[cfg(test)]
mod tests {

    use crate::analyzer::semantic::type_flow::ClassAtom;

    use crate::analyzer::semantic::type_flow::ClassIdentity;

    use crate::analyzer::semantic::type_flow::ClassSeed;

    use crate::analyzer::semantic::type_flow::ExternalMemberDeclaration;

    use crate::analyzer::semantic::type_flow::UnknownReason;

    #[test]
    fn multi_class_open_seed_is_canonical_deduplicated_and_open_last() {
        let first = ClassIdentity::External {
            qualified_name: "pkg.A".into(),
            symbol_id: "class-a".into(),
        };
        let second = ClassIdentity::External {
            qualified_name: "pkg.B".into(),
            symbol_id: "class-b".into(),
        };

        assert_eq!(
            ClassSeed::classes_with_open_bound([second.clone(), first.clone(), second.clone(),])
                .into_atoms()
                .collect::<Vec<_>>(),
            vec![
                ClassAtom::Class(first.clone()),
                ClassAtom::Class(second.clone()),
                ClassAtom::Unknown(UnknownReason::OpenTypeBound),
            ]
        );

        assert_eq!(
            ClassSeed::ClassesWithOpenBound(
                vec![second.clone(), first.clone(), second.clone()].into_boxed_slice(),
            )
            .into_atoms()
            .collect::<Vec<_>>(),
            vec![
                ClassAtom::Class(first),
                ClassAtom::Class(second),
                ClassAtom::Unknown(UnknownReason::OpenTypeBound),
            ],
            "even direct variant construction cannot perturb reusable event order"
        );
    }

    #[test]
    fn external_member_declaration_is_nonempty_canonical_and_deduplicated() {
        let declaration = ExternalMemberDeclaration::new([
            Box::from("member.z"),
            Box::from("member.a"),
            Box::from("member.z"),
        ]);

        assert_eq!(
            declaration.symbol_ids(),
            &[Box::from("member.a"), Box::from("member.z")]
        );
    }
}
