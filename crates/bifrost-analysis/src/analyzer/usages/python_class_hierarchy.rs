//! Query-time Python class hierarchy facts using the ordered bases and C3.

use crate::analyzer::{CapabilityProvider, CodeUnit};
use crate::cancellation::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonHierarchyOutcome {
    Complete,
    Inconsistent,
    Incomplete,
    Unsupported,
}

impl PythonHierarchyOutcome {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Inconsistent => "inconsistent",
            Self::Incomplete => "incomplete",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonHierarchyReason {
    NotClass,
    UnresolvedBase,
    NonClassBase,
    ExternalBase,
    DuplicateBase,
    CyclicBases,
    InconsistentLinearization,
    NotEffectiveMember,
    VisitLimit,
    Cancelled,
}

impl PythonHierarchyReason {
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotClass => "not_class",
            Self::UnresolvedBase => "unresolved_base",
            Self::NonClassBase => "non_class_base",
            Self::ExternalBase => "external_base",
            Self::DuplicateBase => "duplicate_base",
            Self::CyclicBases => "cyclic_bases",
            Self::InconsistentLinearization => "inconsistent_linearization",
            Self::NotEffectiveMember => "not_effective_member",
            Self::VisitLimit => "visit_limit",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonBaseResolution {
    Resolved,
    Unresolved,
    NonClass,
    External,
}

impl PythonBaseResolution {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Unresolved => "unresolved",
            Self::NonClass => "non_class",
            Self::External => "external",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PythonBaseFact {
    pub ordinal: usize,
    pub spelling: String,
    pub resolution: PythonBaseResolution,
    pub target: Option<CodeUnit>,
}

#[derive(Debug, Clone)]
pub struct PythonClassHierarchyAnswer {
    pub outcome: PythonHierarchyOutcome,
    pub reason: Option<PythonHierarchyReason>,
    /// Resolved direct-base facts in their original order. An incomplete walk
    /// may stop before it reaches every spelling.
    pub bases: Vec<PythonBaseFact>,
    /// The selected class followed by its C3 bases. Empty unless complete.
    pub mro: Vec<CodeUnit>,
}

impl PythonClassHierarchyAnswer {
    pub fn complete(bases: Vec<PythonBaseFact>, mro: Vec<CodeUnit>) -> Self {
        Self {
            outcome: PythonHierarchyOutcome::Complete,
            reason: None,
            bases,
            mro,
        }
    }

    pub fn stopped(
        outcome: PythonHierarchyOutcome,
        reason: PythonHierarchyReason,
        bases: Vec<PythonBaseFact>,
    ) -> Self {
        debug_assert!(outcome != PythonHierarchyOutcome::Complete);
        Self {
            outcome,
            reason: Some(reason),
            bases,
            mro: Vec::new(),
        }
    }

    pub const fn coverage(&self) -> &'static str {
        match self.outcome {
            PythonHierarchyOutcome::Complete | PythonHierarchyOutcome::Inconsistent => "complete",
            PythonHierarchyOutcome::Incomplete | PythonHierarchyOutcome::Unsupported => "open",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PythonMroMember {
    pub name: String,
    pub member: CodeUnit,
    pub owner: CodeUnit,
    /// Zero is a declaration on the selected class; larger values follow the
    /// selected class's C3 linearization.
    pub rank: usize,
}

#[derive(Debug, Clone)]
pub struct PythonMroMembersAnswer {
    pub hierarchy: PythonClassHierarchyAnswer,
    pub members: Vec<PythonMroMember>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonOverrideOutcome {
    Overrides,
    NoOverride,
    Incomplete,
    Unsupported,
}

impl PythonOverrideOutcome {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Overrides => "overrides",
            Self::NoOverride => "no_override",
            Self::Incomplete => "incomplete",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PythonOverrideAnswer {
    pub outcome: PythonOverrideOutcome,
    pub reason: Option<PythonHierarchyReason>,
    pub source_owner: Option<CodeUnit>,
    pub target: Option<CodeUnit>,
    pub target_owner: Option<CodeUnit>,
    /// Rank of the target owner in the source method's class MRO.
    pub mro_rank: Option<usize>,
}

impl PythonOverrideAnswer {
    pub fn stopped(
        outcome: PythonOverrideOutcome,
        reason: Option<PythonHierarchyReason>,
        source_owner: Option<CodeUnit>,
    ) -> Self {
        debug_assert!(outcome != PythonOverrideOutcome::Overrides);
        Self {
            outcome,
            reason,
            source_owner,
            target: None,
            target_owner: None,
            mro_rank: None,
        }
    }
}

pub trait PythonClassHierarchyProvider: CapabilityProvider + Send + Sync {
    fn class_hierarchy(
        &self,
        class: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> PythonClassHierarchyAnswer;

    fn mro_members(
        &self,
        class: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> PythonMroMembersAnswer;

    fn method_override(
        &self,
        method: &CodeUnit,
        cancellation: Option<&CancellationToken>,
    ) -> PythonOverrideAnswer;
}
