//! Normalized coverage rows supplied with immutable preload fragments.
use super::model::{BindingNodeId, SemanticId};
use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionGapKind, ResolutionSiteId};
use brokk_bifrost_core::analyzer::structural::resolution::{
    HoistingClass, ResolutionGapOriginKind,
};

/// The direction whose candidate inventory is known to be incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoweredCandidateDirection {
    Forward,
    Reverse,
}

/// One normalized read frontier contaminated by a lowering gap.
///
/// Fragment and enumeration rows affect broad negative answers. Reference,
/// candidate, and type rows stay local to the semantic dependency that the
/// producer could not model; a point query for an unrelated reference remains
/// exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoweringCoverageFrontier {
    Fragment,
    Enumeration,
    /// The producer may have omitted an endpoint in this direction entirely,
    /// so no endpoint-keyed candidate row can carry the gap. This remains
    /// separate from `Fragment`: reverse inventory can be incomplete without
    /// poisoning an unrelated point lookup whose reference node is present.
    CandidateInventory {
        direction: LoweredCandidateDirection,
    },
    Reference {
        semantic: SemanticId,
        node: BindingNodeId,
    },
    Candidate {
        direction: LoweredCandidateDirection,
        endpoint: BindingNodeId,
        /// Exact first lookup symbol whose inventory is incomplete. `None`
        /// applies to every symbol state at the endpoint. A source must apply
        /// keyed gaps conservatively to an open variable-only symbol stack,
        /// because its eventual first symbol is not known yet.
        lookup: Option<SemanticId>,
    },
    /// One actual type slot or stable site-property frontier. Site-property
    /// frontiers let a later projection evaluator attach conditional evidence
    /// (for example an implicit constructor) to the resolved declaration that
    /// owns it without poisoning unrelated type work.
    Type {
        frontier: SemanticId,
    },
}

/// Why the fact-to-fragment bridge withheld an exact claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoweringGapOrigin {
    Extracted(ResolutionGapKind),
    QualifiedReference,
    UnsupportedActivation(HoistingClass),
    MissingBinder,
}

impl LoweringGapOrigin {
    pub const fn kind(self) -> ResolutionGapOriginKind {
        match self {
            Self::Extracted(kind) => match kind {
                ResolutionGapKind::UnsupportedTypeSyntax => {
                    ResolutionGapOriginKind::UnsupportedTypeSyntax
                }
                ResolutionGapKind::UnsupportedExpression => {
                    ResolutionGapOriginKind::UnsupportedExpression
                }
                ResolutionGapKind::UnsupportedRoute => ResolutionGapOriginKind::UnsupportedRoute,
                ResolutionGapKind::UnsupportedScopeOrBinder => {
                    ResolutionGapOriginKind::UnsupportedScopeOrBinder
                }
                ResolutionGapKind::AmbiguousQualifiedType => {
                    ResolutionGapOriginKind::AmbiguousQualifiedType
                }
                ResolutionGapKind::InferredType => ResolutionGapOriginKind::InferredType,
                ResolutionGapKind::PostfixArrayDimensions => {
                    ResolutionGapOriginKind::PostfixArrayDimensions
                }
                ResolutionGapKind::AmbiguousNumericLiteral => {
                    ResolutionGapOriginKind::AmbiguousNumericLiteral
                }
                ResolutionGapKind::ImplicitConstructor => {
                    ResolutionGapOriginKind::ImplicitConstructor
                }
                ResolutionGapKind::UnsupportedHierarchyTraversal => {
                    ResolutionGapOriginKind::UnsupportedHierarchyTraversal
                }
                ResolutionGapKind::UnsupportedVisibility => {
                    ResolutionGapOriginKind::UnsupportedVisibility
                }
                ResolutionGapKind::UnsupportedImplicitReceiver => {
                    ResolutionGapOriginKind::UnsupportedImplicitReceiver
                }
                ResolutionGapKind::UnsupportedCallApplicability => {
                    ResolutionGapOriginKind::UnsupportedCallApplicability
                }
                ResolutionGapKind::UnsupportedPlacementBoundary => {
                    ResolutionGapOriginKind::UnsupportedPlacementBoundary
                }
                ResolutionGapKind::MalformedSyntax => ResolutionGapOriginKind::MalformedSyntax,
                ResolutionGapKind::UnsupportedMemberScope => {
                    ResolutionGapOriginKind::UnsupportedMemberScope
                }
            },
            Self::QualifiedReference => ResolutionGapOriginKind::QualifiedReference,
            Self::UnsupportedActivation(HoistingClass::SourceOrder) => {
                ResolutionGapOriginKind::UnsupportedActivationSourceOrder
            }
            Self::UnsupportedActivation(HoistingClass::ScopeWide) => {
                ResolutionGapOriginKind::UnsupportedActivationScopeWide
            }
            Self::UnsupportedActivation(HoistingClass::DeclaredHead) => {
                ResolutionGapOriginKind::UnsupportedActivationDeclaredHead
            }
            Self::MissingBinder => ResolutionGapOriginKind::MissingBinder,
        }
    }

    pub const fn from_kind(kind: ResolutionGapOriginKind) -> Self {
        match kind {
            ResolutionGapOriginKind::UnsupportedTypeSyntax => {
                Self::Extracted(ResolutionGapKind::UnsupportedTypeSyntax)
            }
            ResolutionGapOriginKind::UnsupportedExpression => {
                Self::Extracted(ResolutionGapKind::UnsupportedExpression)
            }
            ResolutionGapOriginKind::UnsupportedRoute => {
                Self::Extracted(ResolutionGapKind::UnsupportedRoute)
            }
            ResolutionGapOriginKind::UnsupportedScopeOrBinder => {
                Self::Extracted(ResolutionGapKind::UnsupportedScopeOrBinder)
            }
            ResolutionGapOriginKind::AmbiguousQualifiedType => {
                Self::Extracted(ResolutionGapKind::AmbiguousQualifiedType)
            }
            ResolutionGapOriginKind::InferredType => {
                Self::Extracted(ResolutionGapKind::InferredType)
            }
            ResolutionGapOriginKind::PostfixArrayDimensions => {
                Self::Extracted(ResolutionGapKind::PostfixArrayDimensions)
            }
            ResolutionGapOriginKind::AmbiguousNumericLiteral => {
                Self::Extracted(ResolutionGapKind::AmbiguousNumericLiteral)
            }
            ResolutionGapOriginKind::ImplicitConstructor => {
                Self::Extracted(ResolutionGapKind::ImplicitConstructor)
            }
            ResolutionGapOriginKind::UnsupportedHierarchyTraversal => {
                Self::Extracted(ResolutionGapKind::UnsupportedHierarchyTraversal)
            }
            ResolutionGapOriginKind::UnsupportedVisibility => {
                Self::Extracted(ResolutionGapKind::UnsupportedVisibility)
            }
            ResolutionGapOriginKind::UnsupportedImplicitReceiver => {
                Self::Extracted(ResolutionGapKind::UnsupportedImplicitReceiver)
            }
            ResolutionGapOriginKind::UnsupportedCallApplicability => {
                Self::Extracted(ResolutionGapKind::UnsupportedCallApplicability)
            }
            ResolutionGapOriginKind::UnsupportedPlacementBoundary => {
                Self::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary)
            }
            ResolutionGapOriginKind::MalformedSyntax => {
                Self::Extracted(ResolutionGapKind::MalformedSyntax)
            }
            ResolutionGapOriginKind::UnsupportedMemberScope => {
                Self::Extracted(ResolutionGapKind::UnsupportedMemberScope)
            }
            ResolutionGapOriginKind::QualifiedReference => Self::QualifiedReference,
            ResolutionGapOriginKind::UnsupportedActivationSourceOrder => {
                Self::UnsupportedActivation(HoistingClass::SourceOrder)
            }
            ResolutionGapOriginKind::UnsupportedActivationScopeWide => {
                Self::UnsupportedActivation(HoistingClass::ScopeWide)
            }
            ResolutionGapOriginKind::UnsupportedActivationDeclaredHead => {
                Self::UnsupportedActivation(HoistingClass::DeclaredHead)
            }
            ResolutionGapOriginKind::MissingBinder => Self::MissingBinder,
        }
    }
}

/// One stable normalized gap row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoweredCoverageGap {
    id: SemanticId,
    reason_semantic: SemanticId,
    site: ResolutionSiteId,
    origin: LoweringGapOrigin,
    frontier: LoweringCoverageFrontier,
}

impl LoweredCoverageGap {
    /// Construct one immutable gap row. The containing preload source validates
    /// selected fragment ownership, unique identity, and endpoint references.
    /// These caller-supplied rows do not prove producer completeness or semantic provenance.
    pub const fn new(
        id: SemanticId,
        reason_semantic: SemanticId,
        site: ResolutionSiteId,
        origin: LoweringGapOrigin,
        frontier: LoweringCoverageFrontier,
    ) -> Self {
        Self {
            id,
            reason_semantic,
            site,
            origin,
            frontier,
        }
    }

    pub const fn id(&self) -> SemanticId {
        self.id
    }

    pub const fn reason_semantic(&self) -> SemanticId {
        self.reason_semantic
    }

    pub const fn site(&self) -> ResolutionSiteId {
        self.site
    }

    pub const fn origin(&self) -> LoweringGapOrigin {
        self.origin
    }

    pub const fn frontier(&self) -> LoweringCoverageFrontier {
        self.frontier
    }
}
