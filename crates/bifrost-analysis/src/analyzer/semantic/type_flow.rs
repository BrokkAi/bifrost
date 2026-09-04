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

use crate::analyzer::languages::language_support;
use crate::analyzer::{CodeUnit, Language, ProjectFile, WorkspaceAnalyzer};

use super::{
    AllocationSite, CallSiteId, GuardFact, LengthDelimitedDigest, MemoryLocation, ProcedureHandle,
    ProcedureId, SemanticArtifactKey, SemanticCallSite, SemanticValue, SourceSpan, StableDigest,
    WorkspaceRelativePath,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
}

impl UnknownReason {
    pub const fn label(self) -> &'static str {
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
            Self::SolverBudget => "solver_budget",
            Self::SemanticBudget => "semantic_budget",
            Self::IncompleteRoot => "incomplete_root",
        }
    }
}

/// Answer of an adapter seed query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassSeed {
    Class(ClassIdentity),
    Unknown(UnknownReason),
    /// The site does not produce a class (an ordinary call, an undeclared parameter).
    NotApplicable,
}

/// Where one class-carrying source was seeded, retained for findings,
/// witnesses, and receiver-driven dispatch hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSite {
    pub file: ProjectFile,
    pub span: SourceSpan,
    pub kind: SourceSiteKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceSiteKind {
    ConstructorCall,
    Literal,
    ContainerLiteral,
    DeclaredParameter,
    RootReceiver,
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
    Present(MemberDeclaration),
    Absent,
    Unknown(UnknownReason),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuardArmSide {
    True,
    False,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NarrowingVerdict {
    Keep,
    Drop,
    Unknown,
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
/// in semantic IR. `Member` poisons only that spelling; `Any` poisons every
/// class-keyed slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicFieldWrite {
    Member(Box<str>),
    Any,
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

/// Per-language facts the class-set engine cannot derive from the IR.
/// Implementations are zero-sized and `'static`; every method receives the
/// workspace it should consult. `class_hierarchy` describes the known
/// workspace: an empty complete descendant list authorizes the engine's
/// closed-workspace leaf-receiver rule, and does not claim that external
/// subclasses cannot exist.
pub trait TypeFlowAdapter: Send + Sync {
    fn language(&self) -> Language;
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

    fn field_slot_is_complete(
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

    fn narrowing_verdict(
        &self,
        _workspace: &WorkspaceAnalyzer,
        _procedure: &ProcedureHandle,
        _guard: &GuardFact,
        _atom: &ClassIdentity,
        _arm: GuardArmSide,
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
    use super::ExternalMemberDeclaration;

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
