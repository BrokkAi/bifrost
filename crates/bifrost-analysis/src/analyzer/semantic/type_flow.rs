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

use crate::analyzer::languages::language_support;
use crate::analyzer::{CodeUnit, Language, WorkspaceAnalyzer};

use super::{
    AllocationSite, GuardFact, MemoryLocation, ProcedureHandle, SemanticCallSite, SemanticValue,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberLookup {
    Present,
    Absent,
    Unknown(UnknownReason),
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
