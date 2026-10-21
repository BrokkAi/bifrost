use crate::analyzer::resolution::lexical_definition::LexicalDefinition;
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_core::analyzer::structural::resolution::CandidateOutcome;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::analyzer::structural::resolution::HierarchyRelation;
use brokk_bifrost_core::analyzer::structural::resolution::MemberDispatchTier;
use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;
use brokk_bifrost_core::analyzer::structural::resolution::RejectionReason;

use crate::analyzer::CodeUnit;
use crate::analyzer::ProjectFile;

use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;
use brokk_bifrost_core::analyzer::structural::callable::CallableRejectionReason;

/// What a trace row points at.
///
/// A candidate is not always a workspace declaration: a lexical binding has no
/// `CodeUnit`, and an import route that lost to a stronger tier is named by the
/// binder it introduced -- plus the parser-derived target path the route
/// pointed at, where the adapter recorded one -- rather than by a resolution
/// the resolver never performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceCandidateRef {
    /// An indexed workspace declaration.
    Unit(CodeUnit),
    /// A canonical language intrinsic identity with no source location.
    Intrinsic { name: String },
    /// An exact declaration published by an activated semantic model.
    Modeled { symbol_id: String, name: String },
    /// A binder in the referencing file itself, as the resolver reports it.
    Lexical(LexicalDefinition),
    /// A binding row of the file's lexical environment, addressed by the
    /// binder token's facts-arena node where the adapter records one. This is
    /// the shape a *losing* binder takes: the resolver stops at the winner, so
    /// a shadowed binding is named by its environment row rather than by a
    /// `LexicalDefinition` the resolver never built.
    Binding {
        file: ProjectFile,
        node: Option<u32>,
        name: String,
    },
    /// An import route. `node` is the binder token's facts-arena node where the
    /// adapter records one; `name` is the local name the import binds, or the
    /// wildcard marker for an on-demand import, which binds no single name.
    /// `target_segments` is the parser-derived path the route pointed at; an
    /// empty list is a stated gap (the adapter recorded no structured path),
    /// never a claim that the import has no target.
    ImportBinder {
        file: ProjectFile,
        node: Option<u32>,
        name: String,
        target_segments: Vec<String>,
    },
    /// The route out of the workspace a boundary outcome took, named by the
    /// reference spelling. It is a candidate in the sense that matters here:
    /// something is there, and this lookup could not see it.
    ExternalRoute { name: String },
}

/// The wildcard marker used as the `name` of an on-demand import route. It
/// matches the marker the lexical environment layer uses for the same reason:
/// a wildcard introduces an unspecified set of names, so it binds no
/// identifier and must never behave like one.
pub const WILDCARD_ROUTE_NAME: &str = "*";

/// One exact hierarchy edge on one candidate's route (#1477): hop `hop` took
/// the walk from `from` to `to`. A candidate's route is contiguous, starts at
/// the receiver's declared owner, and terminates at the candidate's owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HierarchyHopRecord {
    pub hop: usize,
    pub from: CodeUnit,
    pub to: CodeUnit,
    pub relation: HierarchyRelation,
}

/// Member-selection attribution for one candidate (#1477): the exact owner the
/// resolver found the member on, how many hierarchy hops away that owner is,
/// which language-neutral dispatch bucket the find belongs to, whether the
/// candidate is applicable to the call shape as far as this seam checked, and
/// the exact hierarchy route.
///
/// Like the tier, this is recorded where the resolver already holds the fact
/// and never reconstructed afterwards: a candidate without enrichment is
/// unattributed, not depth zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberEnrichment {
    pub owner: CodeUnit,
    pub hierarchy_depth: usize,
    pub dispatch_tier: MemberDispatchTier,
    pub applicability: ApplicabilityVerdict,
    /// Empty exactly when `hierarchy_depth` is zero: a direct member has no
    /// route to walk.
    pub route: Vec<HierarchyHopRecord>,
}

/// Callable-applicability attribution for one candidate (#1478): whether the
/// candidate's declared parameter list accepts this call site's argument shape,
/// and the typed reason it does not.
///
/// This is the callable axis, and it is deliberately separate from
/// [`MemberEnrichment`]'s `applicability`, which is the member axis #1477
/// recorded: a constructor call or a free-function call has no member walk at
/// all and still has an applicability answer. A candidate without this record
/// is unattributed on the callable axis, never applicable.
///
/// The record is produced by the same function that produced the resolver's
/// winners -- see `brokk_bifrost_core::analyzer::usages::applicability` -- so the rows and
/// the binding cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallableApplicabilityRecord {
    pub verdict: ApplicabilityVerdict,
    /// Set only when `verdict` is [`ApplicabilityVerdict::Inapplicable`].
    pub reason: Option<CallableRejectionReason>,
}

/// One candidate the resolver considered for one reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceCandidate {
    pub candidate: TraceCandidateRef,
    /// The precedence tier the candidate was considered at, or `None` when the
    /// seam that recorded it cannot name one. `None` is not a tier: a policy
    /// comparing tiers must treat it as unattributed, never as weakest.
    pub tier: Option<PrecedenceTier>,
    pub outcome: CandidateOutcome,
    pub boundary: BoundaryStatus,
    pub visibility: DeclaredVisibility,
    /// The fully-qualified external type a boundary refinement resolved, set
    /// only when `boundary` is [`BoundaryStatus::ExternalIndexed`]. That boundary
    /// covers provider-resolved targets and engine-known intrinsic external
    /// identities; intrinsic candidates carry their identity without this field.
    pub external_target: Option<String>,
    /// Member-selection attribution, present only when the seam that recorded
    /// the candidate is a member lookup that knows its owner and route.
    pub member: Option<Box<MemberEnrichment>>,
    /// Callable-applicability attribution (#1478), present only when the seam
    /// that recorded the candidate ran the language's own call-shape check.
    pub callable: Option<CallableApplicabilityRecord>,
}

impl TraceCandidate {
    /// A selected candidate with nothing further claimed. Intrinsic external
    /// identities are known without a workspace location or an external provider.
    pub fn selected(candidate: TraceCandidateRef, tier: Option<PrecedenceTier>) -> Self {
        let boundary = if matches!(&candidate, TraceCandidateRef::Intrinsic { .. }) {
            BoundaryStatus::ExternalIndexed
        } else {
            BoundaryStatus::WorkspaceLocal
        };
        Self {
            candidate,
            tier,
            outcome: CandidateOutcome::Selected,
            boundary,
            visibility: DeclaredVisibility::Unknown,
            external_target: None,
            member: None,
            callable: None,
        }
    }

    /// A candidate the resolver computed and then discarded.
    pub fn rejected(
        candidate: TraceCandidateRef,
        tier: Option<PrecedenceTier>,
        reason: RejectionReason,
    ) -> Self {
        let boundary = if matches!(&candidate, TraceCandidateRef::Intrinsic { .. }) {
            BoundaryStatus::ExternalIndexed
        } else {
            BoundaryStatus::WorkspaceLocal
        };
        Self {
            candidate,
            tier,
            outcome: CandidateOutcome::Rejected(reason),
            boundary,
            visibility: DeclaredVisibility::Unknown,
            external_target: None,
            member: None,
            callable: None,
        }
    }

    pub fn with_boundary(mut self, boundary: BoundaryStatus) -> Self {
        self.boundary = boundary;
        self
    }

    pub fn with_member(mut self, member: MemberEnrichment) -> Self {
        self.member = Some(Box::new(member));
        self
    }

    pub fn with_callable(mut self, callable: CallableApplicabilityRecord) -> Self {
        self.callable = Some(callable);
        self
    }

    pub fn is_selected(&self) -> bool {
        self.outcome.is_selected()
    }
}
