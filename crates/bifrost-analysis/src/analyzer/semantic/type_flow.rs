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
use std::path::Path;
use std::sync::Arc;

use brokk_bifrost_core::analyzer::prepared_syntax::{
    PreparedSourceOrigin, PreparedSyntaxSource, PreparedSyntaxTree,
};

use crate::analyzer::languages::language_support;
use crate::analyzer::semantic_model::{
    SemanticModelMemberTargetDisposition, SemanticModelOverlay, SemanticModelProvenance,
    SemanticModelSymbolKind,
};
use crate::analyzer::usages::get_type::TypeLookupType;
use crate::analyzer::{CodeUnit, Language, ProjectFile, Range, WorkspaceAnalyzer};
use crate::hash::HashMap;

use super::oracle::CandidateCoverage;
use super::{
    AdapterSemanticsVersion, AllocationSite, CallSiteId, ContentIdentity, GuardFact,
    LengthDelimitedDigest, MemoryLocation, OverlaySnapshotId, ProcedureHandle, ProcedureId,
    SemanticArtifactKey, SemanticCallSite, SemanticLocator, SemanticValue, SourcePosition,
    SourceRevision, SourceSpan, StableDigest, ValueId, WorkspaceMountId, WorkspaceRelativePath,
};

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
}

impl ClassIdentity {
    pub fn qualified_name(&self) -> &str {
        match self {
            Self::Workspace(unit) => unit.fq_name_str(),
            Self::External { qualified_name, .. } => qualified_name,
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

pub(crate) type ExternalClassCache =
    HashMap<(Language, Box<str>, Option<Box<str>>), Option<ClassIdentity>>;

/// Resolve one external class from the active model after filtering by the
/// requested language, owner-less class shape, and optional exact record ID.
/// Uniqueness is decided only after those filters are applied.
pub(crate) fn external_class_identity(
    overlay: Option<&SemanticModelOverlay>,
    language: Language,
    qualified_name: &str,
    semantic_model_id: Option<&str>,
    cache: &mut ExternalClassCache,
) -> Option<ClassIdentity> {
    let key = (
        language,
        qualified_name.into(),
        semantic_model_id.map(Box::from),
    );
    if let Some(cached) = cache.get(&key) {
        return cached.clone();
    }
    let resolved = overlay.and_then(|overlay| {
        let records = match semantic_model_id {
            Some(id) => overlay.symbols_with_id(id).records,
            None => overlay.symbols_named(qualified_name).records,
        }
        .into_iter()
        .filter(|symbol| {
            symbol.language == language.config_label()
                && symbol.owner_id.is_none()
                && symbol.kind == SemanticModelSymbolKind::Class
                && !symbol.provenance.ambiguous
        })
        .collect::<Vec<_>>();
        let [symbol] = records.as_slice() else {
            return None;
        };
        Some(ClassIdentity::External {
            qualified_name: symbol.qualified_name.clone().into_boxed_str(),
            symbol_id: symbol.id.clone().into_boxed_str(),
        })
    });
    cache.insert(key, resolved.clone());
    resolved
}

pub(crate) fn class_seed_from_lookup_types(
    overlay: Option<&SemanticModelOverlay>,
    language: Language,
    types: &[TypeLookupType],
) -> ClassSeed {
    let [lookup] = types else {
        return if types.is_empty() {
            ClassSeed::NotApplicable
        } else {
            ClassSeed::Unknown(UnknownReason::AmbiguousCallee)
        };
    };
    match lookup.definitions.as_slice() {
        [definition] if definition.is_class() => {
            ClassSeed::Class(ClassIdentity::Workspace(definition.clone()))
        }
        [_] => ClassSeed::NotApplicable,
        [] => {
            let mut cache = ExternalClassCache::default();
            external_class_identity(
                overlay,
                language,
                &lookup.fqn,
                lookup.semantic_model_id.as_deref(),
                &mut cache,
            )
            .map(ClassSeed::Class)
            .unwrap_or(ClassSeed::NotApplicable)
        }
        _ => ClassSeed::Unknown(UnknownReason::AmbiguousCallee),
    }
}

pub(crate) fn external_member_lookup(
    overlay: &SemanticModelOverlay,
    owner_id: &str,
    member: &str,
) -> MemberLookup {
    let matched = overlay.member_target_on_owner(owner_id, member);
    match matched.disposition {
        SemanticModelMemberTargetDisposition::Unique => {
            MemberLookup::Present(MemberLookupHit::new(
                MemberDeclaration::External(ExternalMemberDeclaration::new(
                    matched
                        .records
                        .into_iter()
                        .map(|record| Box::from(record.id.as_str())),
                )),
                CandidateCoverage::Exhaustive,
            ))
        }
        SemanticModelMemberTargetDisposition::Conflict
            if overlay.member_present_on_owner(owner_id, member) =>
        {
            MemberLookup::Present(MemberLookupHit::new(
                MemberDeclaration::External(ExternalMemberDeclaration::new(
                    matched
                        .records
                        .into_iter()
                        .map(|record| Box::from(record.id.as_str())),
                )),
                CandidateCoverage::Exhaustive,
            ))
        }
        SemanticModelMemberTargetDisposition::Absent => MemberLookup::Absent,
        SemanticModelMemberTargetDisposition::Incomplete
        | SemanticModelMemberTargetDisposition::Conflict => {
            MemberLookup::Unknown(UnknownReason::PackIncomplete)
        }
    }
}

pub(crate) fn file_for_locator(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> Option<ProjectFile> {
    workspace
        .analyzer()
        .project()
        .file_by_rel_path(Path::new(locator.path().as_str()))
}

pub(crate) fn source_span_for_node(node: tree_sitter::Node<'_>) -> SourceSpan {
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

pub(crate) fn analyzer_range_for_span(span: SourceSpan) -> Range {
    Range {
        start_byte: span.start_byte() as usize,
        end_byte: span.end_byte() as usize,
        start_line: span.start().line() as usize,
        end_line: span.end().line() as usize,
    }
}

/// Accept prepared syntax only when it is the exact indexed snapshot from
/// which `procedure` was materialized. A mismatch is typed as uncertain flow:
/// adapters must fail closed instead of reading AST fields at stale offsets.
pub fn validate_prepared_syntax_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    file: &ProjectFile,
    prepared: Arc<PreparedSyntaxTree>,
) -> Result<Arc<PreparedSyntaxTree>, UnknownReason> {
    let key = procedure.artifact().key();
    let path_matches =
        WorkspaceRelativePath::try_from_path(file.rel_path()).is_ok_and(|path| &path == key.path());
    let content = ContentIdentity::hash_bytes(prepared.source().as_bytes());
    let revision_matches = match (key.revision(), prepared.origin()) {
        (SourceRevision::Disk { content: expected }, PreparedSourceOrigin::Disk) => {
            content == expected
        }
        (
            SourceRevision::Overlay {
                content: expected,
                snapshot,
            },
            PreparedSourceOrigin::Overlay,
        ) => {
            content == expected
                && prepared.overlay_revision().is_some_and(|revision| {
                    OverlaySnapshotId::hash_bytes(revision.get().to_le_bytes()) == snapshot
                })
        }
        _ => false,
    };
    let exact = path_matches
        && key.mount() == WorkspaceMountId::from_root(file.root())
        && key.language() == prepared.dialect()
        && revision_matches
        && matches!(prepared.backing(), PreparedSyntaxSource::Indexed(_))
        && workspace
            .analyzer()
            .indexed_source_matches(file, prepared.source());
    exact
        .then_some(prepared)
        .ok_or(UnknownReason::UncertainFlow)
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
    Literal,
    ContainerLiteral,
    DeclaredParameter,
    RootReceiver,
    /// A guard arm proved this class; no syntax here produced the value. A
    /// finding witness prefers a site that did, so this kind ranks last when
    /// one class has more than one origin.
    NarrowingGuard,
    /// Unclassified origin syntax; independent of whether its class is known.
    Unknown,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchHintSet {
    call_site: DispatchHintCallSiteKey,
    hints: Box<[DispatchHint]>,
    exhaustive: bool,
    singleton: bool,
}

impl DispatchHintSet {
    pub fn new(
        call_site: DispatchHintCallSiteKey,
        mut hints: Vec<DispatchHint>,
        exhaustive: bool,
        singleton: bool,
    ) -> Self {
        hints.sort_by(dispatch_hint_order);
        hints.dedup();
        Self {
            call_site,
            hints: hints.into_boxed_slice(),
            exhaustive,
            singleton,
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

    pub const fn singleton(&self) -> bool {
        self.singleton
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
        (ClassIdentity::Workspace(_), ClassIdentity::External { .. }) => Ordering::Less,
        (ClassIdentity::External { .. }, ClassIdentity::Workspace(_)) => Ordering::Greater,
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

fn source_site_kind_tag(kind: SourceSiteKind) -> u8 {
    match kind {
        SourceSiteKind::ConstructorCall => 0,
        SourceSiteKind::Literal => 1,
        SourceSiteKind::ContainerLiteral => 2,
        SourceSiteKind::DeclaredParameter => 3,
        SourceSiteKind::RootReceiver => 4,
        SourceSiteKind::Unknown => 5,
        // Appended: the tags of the kinds above are persisted.
        SourceSiteKind::NarrowingGuard => 6,
    }
}

fn dispatch_hints_digest(entries: &[DispatchHintSet]) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-type-flow-dispatch-hints/v1");
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
        digest.push(if entry.singleton {
            b"singleton"
        } else {
            b"multiple"
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

/// A structured field mutation that does not appear as a direct Field store
/// in semantic IR. Named writes keep that spelling open. An arbitrary name
/// retains its receiver and write site for the flow engine to scope its effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicFieldWrite {
    Member(Box<str>),
    Any {
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

/// Per-language facts the class-set engine cannot derive from the IR.
/// Implementations are zero-sized and `'static`; every method receives the
/// workspace it should consult. `class_hierarchy` describes the known
/// workspace: an empty complete descendant list authorizes the engine's
/// closed-workspace leaf-receiver rule, and does not claim that external
/// subclasses cannot exist.
pub trait TypeFlowAdapter: Send + Sync {
    fn language(&self) -> Language;

    /// Stable identity of every answer this adapter can provide. Implementors
    /// must rotate it whenever any type-flow method changes behavior for
    /// unchanged semantic inputs.
    fn semantics_version(&self) -> AdapterSemanticsVersion;

    fn constructed_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        call: &SemanticCallSite,
    ) -> ClassSeed;
    fn constant_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        value: &SemanticValue,
    ) -> ClassSeed;
    /// Class of a computation whose operand dependencies do not establish
    /// class identity. An adapter may classify the result from structured
    /// language semantics; an unmodeled computation remains explicitly open.
    fn computed_class(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _value: &SemanticValue,
    ) -> ClassSeed {
        ClassSeed::Unknown(UnknownReason::UncertainFlow)
    }
    /// Classifies a retained value whose semantic kind has no built-in
    /// class-set seed. This is the adapter's fail-closed seam for structured
    /// language values such as callable expressions and literals that are
    /// neither constants nor allocation sites in semantic IR. The planner
    /// invokes this only for data origins; call-site callee values are excluded
    /// because callable targets are control-flow identities, not runtime data
    /// flowing through the call's arguments or result.
    fn retained_value_class(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _value: &SemanticValue,
    ) -> ClassSeed {
        ClassSeed::NotApplicable
    }
    fn allocation_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        allocation: &AllocationSite,
    ) -> ClassSeed;
    fn declared_parameter_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        ordinal: u32,
    ) -> ClassSeed;
    fn accessed_member(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        site: MemberAccessQuery<'_>,
    ) -> Option<Box<str>>;
    fn member_lookup(
        &self,
        workspace: &WorkspaceAnalyzer,
        kind: MemberAccessKind,
        class: &ClassIdentity,
        member: &str,
    ) -> MemberLookup;

    fn enclosing_class(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
    ) -> Option<ClassIdentity> {
        None
    }

    fn class_hierarchy(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _class: &ClassIdentity,
    ) -> ClassHierarchy {
        ClassHierarchy::unknown()
    }

    /// Whether truth testing an instance can execute user-defined effects.
    /// A true answer permits a field guard to constrain a subsequent reread.
    fn truthiness_is_pure(&self, _workspace: &WorkspaceAnalyzer, _class: &ClassIdentity) -> bool {
        false
    }

    /// Whether loading this member can execute user-defined effects.
    fn member_access_is_pure(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _class: &ClassIdentity,
        _member: &str,
    ) -> bool {
        false
    }

    fn field_slot_is_complete(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _class: &ClassIdentity,
        _member: &str,
    ) -> bool {
        false
    }

    /// Whether repeated accesses to this instance field use ordinary storage,
    /// rather than a descriptor or dynamic lookup. This proves access-path
    /// stability between effects, not global heap singleton ownership.
    fn field_access_is_plain(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _class: &ClassIdentity,
        _member: &str,
    ) -> bool {
        false
    }

    fn dynamic_field_writes(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
    ) -> Vec<DynamicFieldWrite> {
        Vec::new()
    }

    /// Classify each candidate on the guard's true arm, in input order.
    /// Resolve guard operands once for the batch. The false arm reverses
    /// Keep and Drop; Unknown remains on both arms without a reason, while
    /// Incomplete remains on both arms and contributes its reason on the true
    /// edge. Member lookup is
    /// supplied by the flow engine so declaration-only absence can consult
    /// the same workspace store survey as final member interpretation.
    fn narrowing_verdicts(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _guard: &GuardFact,
        atoms: &[&ClassIdentity],
        _member_lookup: &dyn Fn(&ClassIdentity, &str) -> MemberLookup,
    ) -> Vec<NarrowingVerdict> {
        vec![NarrowingVerdict::Unknown; atoms.len()]
    }

    /// What the guard's true arm proves about a value the class-set domain
    /// could not name.
    ///
    /// [`narrowing_verdicts`](Self::narrowing_verdicts) classifies candidates
    /// the engine already named, and an `Unknown` atom is not a class: it has
    /// no hierarchy to test, so narrowing alone carries a remainder into an
    /// arm that has already established what the value is. A predicate that
    /// does establish it answers here, in the same seed vocabulary the other
    /// adapter answers use, and the engine replaces the remainder on the true
    /// arm with this seed. Answer the exact class set only when the check is
    /// closed; a check a subclass also satisfies names its classes with an
    /// open bound, because the subclass's member surface is not the named
    /// class's. The default, `NotApplicable`, says the true arm proves no
    /// class and the remainder is carried through unchanged.
    fn guard_proves_classes(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _guard: &GuardFact,
    ) -> ClassSeed {
        ClassSeed::NotApplicable
    }

    /// Every value [`call_guard_narrowing`](Self::call_guard_narrowing) and
    /// [`normal_return_type_constraints`](Self::normal_return_type_constraints)
    /// can name as a subject in `procedure`.
    ///
    /// Binding refinement carries temporal-identity state only for the values
    /// a consumer can ask about, so an implementation that names a value
    /// outside this set asks about state that was never carried. Both methods
    /// constrain an actual argument of a call, so the default answer is every
    /// call-site argument. An adapter that recognizes fewer calls should say
    /// so here; the answer is a promise, and the consumer checks it.
    fn refinement_subjects(
        &self,
        _workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
    ) -> Vec<ValueId> {
        procedure
            .semantics()
            .call_sites()
            .iter()
            .flat_map(|call| call.arguments.iter().map(|argument| argument.value))
            .collect()
    }

    /// Derive a guard from an exactly resolved predicate call.
    /// Implementations must validate the current body and callable binding.
    /// A resolved, modeled predicate reports `Narrowed` with the constrained
    /// actual argument and one verdict per candidate. A predicate call whose
    /// callee cannot be modeled reports `Unmodeled` with that argument: the
    /// developer's condition says something about the value that the engine
    /// cannot name, which is true on both arms. Anything else reports
    /// `NoConstraint`. These query-local facts become ordinary edge kills,
    /// whose behavior is summary-keyed.
    fn call_guard_narrowing(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _guard: &GuardFact,
        _atoms: &[&ClassIdentity],
        _member_lookup: &dyn Fn(&ClassIdentity, &str) -> MemberLookup,
    ) -> CallGuardOutcome {
        CallGuardOutcome::NoConstraint
    }

    /// Return only contracts whose target, actual/formal binding, and class
    /// arguments are established from structured evidence. An unresolved,
    /// overridden, rebound, or conflicting invocation has no constraint.
    fn normal_return_type_constraints(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _call: &SemanticCallSite,
    ) -> Vec<NormalReturnTypeConstraint> {
        Vec::new()
    }

    fn instance_of_verdict(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _atom: &ClassIdentity,
        _classes: &[ClassIdentity],
    ) -> NarrowingVerdict {
        NarrowingVerdict::Unknown
    }
}

/// The class-set adapter `language` registers, or `None` when its language
/// support reports none. This is the public enumeration point for engines in
/// sibling crates; `LanguageSupport::type_flow_adapter` stays crate-internal.
pub fn type_flow_adapter(language: Language) -> Option<&'static dyn TypeFlowAdapter> {
    language_support(language).and_then(|support| support.type_flow_adapter())
}

#[cfg(test)]
mod tests {
    use super::{ClassAtom, ClassIdentity, ClassSeed, ExternalMemberDeclaration, UnknownReason};

    #[test]
    fn unknown_reason_labels_and_display_round_trip_named_guards() {
        let first = UnknownReason::UnmodeledGuard {
            class: "pkg.First".into(),
        };
        let second = UnknownReason::UnmodeledGuard {
            class: "pkg.Second".into(),
        };

        assert_eq!(
            UnknownReason::from_label(&UnknownReason::DynamicFieldWrite.to_string()),
            Some(UnknownReason::DynamicFieldWrite)
        );
        assert_eq!(first.label(), "unmodeled_guard");
        assert_eq!(first.to_string(), "unmodeled_guard:pkg.First");
        assert_eq!(
            UnknownReason::from_label(&first.to_string()),
            Some(first.clone())
        );
        assert_eq!(UnknownReason::from_label(&second.to_string()), Some(second));
        assert_ne!(
            first,
            UnknownReason::UnmodeledGuard {
                class: "pkg.Second".into(),
            }
        );
    }

    #[test]
    fn open_class_seed_expands_to_class_then_typed_unknown() {
        let class = ClassIdentity::External {
            qualified_name: "pkg.Widget".into(),
            symbol_id: "class-widget".into(),
        };

        assert_eq!(
            ClassSeed::ClassWithOpenBound(class.clone())
                .into_atoms()
                .collect::<Vec<_>>(),
            vec![
                ClassAtom::Class(class),
                ClassAtom::Unknown(UnknownReason::OpenTypeBound),
            ]
        );
    }

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
    #[should_panic(expected = "a multi-class seed names at least one class")]
    fn multi_class_open_seed_rejects_an_empty_class_set() {
        ClassSeed::classes_with_open_bound(std::iter::empty());
    }

    #[test]
    #[should_panic(expected = "a multi-class seed names at least one class")]
    fn multi_class_closed_seed_rejects_an_empty_class_set() {
        ClassSeed::classes(std::iter::empty());
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

    #[test]
    #[should_panic(expected = "an external member declaration names at least one exact symbol")]
    fn external_member_declaration_rejects_an_empty_family() {
        ExternalMemberDeclaration::new(std::iter::empty());
    }
}
