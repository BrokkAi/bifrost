//! Query-time Python class hierarchy facts using the ordered bases and C3.

use crate::analyzer::semantic::type_flow::ClassIdentity;
use crate::analyzer::semantic_model::{SemanticModelProvenance, TypeRef};
use crate::analyzer::{CapabilityProvider, CodeUnit};
use crate::cancellation::CancellationToken;
use serde::{Deserialize, Serialize};

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
    MissingRuntimeBases,
    ConflictingRuntimeBases,
    AmbiguousRuntimeBase,
    UnsupportedBaseExpression,
    UnknownMemberSurface,
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
            Self::MissingRuntimeBases => "missing_runtime_bases",
            Self::ConflictingRuntimeBases => "conflicting_runtime_bases",
            Self::AmbiguousRuntimeBase => "ambiguous_runtime_base",
            Self::UnsupportedBaseExpression => "unsupported_base_expression",
            Self::UnknownMemberSurface => "unknown_member_surface",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonBaseOrigin {
    Source,
    ImplicitObject,
}

#[derive(Debug, Clone)]
pub struct PythonBaseFact {
    /// Missing evidence for a language-implied root is not failed source inference.
    pub origin: PythonBaseOrigin,
    pub ordinal: usize,
    pub spelling: String,
    pub resolution: PythonBaseResolution,
    pub target: Option<ClassIdentity>,
}

/// Canonical external identity retained independently of optional rich endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PythonModeledClassIdentity {
    pub qualified_name: String,
    pub symbol_id: String,
}

/// One active ordered runtime claim, including an explicit empty-root claim.
/// Unresolved slots remain present when derivation stops; declared references
/// are retained so a stopped answer does not erase the claiming record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PythonRuntimeBaseClaim {
    /// Authored owner identity, even when a lower-ranked claim cannot bind.
    pub declared_class: PythonModeledClassIdentity,
    pub class: Option<PythonModeledClassIdentity>,
    pub declared_bases: Vec<TypeRef>,
    pub bases: Vec<Option<PythonModeledClassIdentity>>,
    pub provenance: SemanticModelProvenance,
}

/// Query-lifetime premises of runtime C3, shared with downstream transports.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PythonAncestryBasis {
    pub claims: Vec<PythonRuntimeBaseClaim>,
}

#[derive(Debug, Clone)]
pub struct PythonClassHierarchyAnswer {
    pub outcome: PythonHierarchyOutcome,
    pub reason: Option<PythonHierarchyReason>,
    /// Resolved direct-base facts in their original order. An incomplete walk
    /// may stop before it reaches every spelling.
    pub bases: Vec<PythonBaseFact>,
    /// The selected class followed by its C3 bases. Empty unless complete.
    pub mro: Vec<ClassIdentity>,
    pub ancestry_basis: PythonAncestryBasis,
}

impl PythonClassHierarchyAnswer {
    pub fn complete(
        bases: Vec<PythonBaseFact>,
        mro: Vec<ClassIdentity>,
        ancestry_basis: PythonAncestryBasis,
    ) -> Self {
        Self {
            outcome: PythonHierarchyOutcome::Complete,
            reason: None,
            bases,
            mro,
            ancestry_basis,
        }
    }

    pub fn stopped(
        outcome: PythonHierarchyOutcome,
        reason: PythonHierarchyReason,
        bases: Vec<PythonBaseFact>,
        ancestry_basis: PythonAncestryBasis,
    ) -> Self {
        debug_assert!(outcome != PythonHierarchyOutcome::Complete);
        Self {
            outcome,
            reason: Some(reason),
            bases,
            mro: Vec::new(),
            ancestry_basis,
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
    /// Member inventory coverage is independent of complete runtime topology.
    pub outcome: PythonHierarchyOutcome,
    pub reason: Option<PythonHierarchyReason>,
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
    pub ancestry_basis: PythonAncestryBasis,
}

impl PythonOverrideAnswer {
    pub fn stopped(
        outcome: PythonOverrideOutcome,
        reason: Option<PythonHierarchyReason>,
        source_owner: Option<CodeUnit>,
        ancestry_basis: PythonAncestryBasis,
    ) -> Self {
        debug_assert!(outcome != PythonOverrideOutcome::Overrides);
        Self {
            outcome,
            reason,
            source_owner,
            target: None,
            target_owner: None,
            mro_rank: None,
            ancestry_basis,
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
