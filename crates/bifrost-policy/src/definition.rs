//! Typed, diagnostic-neutral authoring model for RQLP policy documents.
//!
//! These values describe policy source after syntactic decoding and bounded
//! validation. They deliberately contain no workspace loading, resolved
//! dependency, evaluator, finding, or renderer state.

use std::fmt;
use std::str::FromStr;

use brokk_bifrost_analysis::analyzer::dataflow::UnmodeledCallBehavior;
use brokk_bifrost_analysis::analyzer::identifier::define_identifier;
use brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath;
use brokk_bifrost_analysis::analyzer::structural::CodeQuery;
use brokk_bifrost_analysis::analyzer::structural::occurrences::{
    Namespace, OccurrenceClass, OccurrenceRole,
};
use brokk_bifrost_analysis::analyzer::structural::{
    BoundaryStatus, OwnerRelation, PrecedenceTier, RouteHopKind, SiteClass,
};
use brokk_bifrost_analysis::analyzer::usages::{ReferenceKind, UsageHitKind, UsageHitSurface};
use brokk_bifrost_analysis::schema_version::SchemaVersionResolution;

pub const POLICY_DOCUMENT_SCHEMA_VERSION: u32 = 1;

/// The one resolved-selector path an assertion policy registers. Kept beside
/// the model so the registry, the canonical projection, the loaded-model
/// validator and the evaluator all name the same string.
pub const ASSERTION_SUBJECT_SELECTOR_PATH: &str = "/analysis/subject";

pub const DEFAULT_WITNESS_MAX_STEPS: usize = 64;
pub const DEFAULT_WITNESS_MAX_BYTES: usize = 16 * 1024;
pub const DEFAULT_WITNESSES_PER_FINDING: usize = 8;
pub const DEFAULT_ORIGINS_PER_FINDING: usize = 8;

pub const MAX_WITNESS_STEPS: usize = 1_024;
pub const MAX_WITNESS_BYTES: usize = 1024 * 1024;
pub const MAX_WITNESSES_PER_FINDING: usize = 64;
pub const MAX_ORIGINS_PER_FINDING: usize = 256;

pub const MAX_POLICY_DISPLAY_TEXT_BYTES: usize = 4_096;
pub const MAX_POLICY_SET_ITEMS: usize = 64;
pub const MAX_POLICY_PREDICATE_DEPTH: usize = 16;
pub const MAX_POLICY_PREDICATE_NODES: usize = 256;

/// The resolved top-level RQLP schema version and its provenance.
pub type PolicySchemaVersion = SchemaVersionResolution;

#[derive(Debug, Clone)]
pub enum RqlpDocument {
    Policy {
        definition: Box<PolicyDefinition>,
    },
    Endpoint {
        definition: Box<MatchEndpointDefinition>,
    },
}

#[derive(Debug, Clone)]
pub struct PolicyDefinition {
    pub schema_version: PolicySchemaVersion,
    pub metadata: PolicyMetadata,
    pub analysis: PolicyAnalysis,
    pub classification: Option<PolicyClassificationSpec>,
    pub report: PolicyReportOptions,
}

#[derive(Debug, Clone)]
pub enum PolicyAnalysis {
    Match { spec: MatchPolicySpec },
    Taint { spec: TaintPolicySpec },
    Typestate { spec: TypestatePolicySpec },
    Assertion { spec: AssertionPolicySpec },
}

impl PolicyAnalysis {
    pub const fn analysis_type(&self) -> PolicyAnalysisType {
        match self {
            Self::Match { .. } => PolicyAnalysisType::Match,
            Self::Taint { .. } => PolicyAnalysisType::Taint,
            Self::Typestate { .. } => PolicyAnalysisType::Typestate,
            Self::Assertion { .. } => PolicyAnalysisType::Assertion,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyAnalysisType {
    Match,
    Taint,
    Typestate,
    Assertion,
}

impl PolicyAnalysisType {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Taint => "taint",
            Self::Typestate => "typestate",
            Self::Assertion => "assertion",
        }
    }
}

/// One subject selector plus the independent occurrence invariants evaluated at
/// every node it captures.
#[derive(Debug, Clone)]
pub struct AssertionPolicySpec {
    pub subject: PolicySelector,
    pub asserts: Vec<PolicyAssert>,
}

/// One authored invariant evaluated at every subject node.
///
/// The four families share the subject selector, the `ast_id` join, the
/// soundness accounting and the finding anchor; they differ only in which row
/// family they read and what they compare. Keeping them one sequence is what
/// keeps the evaluator's completeness accounting single.
#[derive(Debug, Clone)]
pub enum PolicyAssert {
    Occurrence(OccurrenceAssert),
    Resolution(ResolutionAssert),
    Reaching(ReachingAssert),
    Boundary(BoundaryAssert),
    EdgeParity(EdgeParityAssert),
    EdgeClass(EdgeClassAssert),
    Canonical(CanonicalAssert),
    Route(RouteAssert),
    RoundTrip(RoundTripAssert),
}

impl PolicyAssert {
    pub const fn id(&self) -> &PolicyAssertId {
        match self {
            Self::Occurrence(assertion) => &assertion.id,
            Self::Resolution(assertion) => &assertion.id,
            Self::Reaching(assertion) => &assertion.id,
            Self::Boundary(assertion) => &assertion.id,
            Self::EdgeParity(assertion) => &assertion.id,
            Self::EdgeClass(assertion) => &assertion.id,
            Self::Canonical(assertion) => &assertion.id,
            Self::Route(assertion) => &assertion.id,
            Self::RoundTrip(assertion) => &assertion.id,
        }
    }

    /// The subject capture whose AST node the rows are joined to.
    pub fn at(&self) -> &str {
        match self {
            Self::Occurrence(assertion) => &assertion.at,
            Self::Resolution(assertion) => &assertion.at,
            Self::Reaching(assertion) => &assertion.at,
            Self::Boundary(assertion) => &assertion.at,
            Self::EdgeParity(assertion) => &assertion.at,
            Self::EdgeClass(assertion) => &assertion.at,
            Self::Canonical(assertion) => &assertion.at,
            Self::Route(assertion) => &assertion.at,
            Self::RoundTrip(assertion) => &assertion.at,
        }
    }

    /// The occurrence role the joined rows must carry. Capability reporting is
    /// narrowed to exactly this role, so an adapter gap in an unrelated role
    /// does not make the run unreliable.
    pub const fn role(&self) -> OccurrenceRole {
        match self {
            Self::Occurrence(assertion) => assertion.role,
            Self::Resolution(assertion) => assertion.role,
            Self::Reaching(assertion) => assertion.role,
            Self::Boundary(assertion) => assertion.role,
            Self::EdgeParity(assertion) => assertion.role,
            Self::EdgeClass(assertion) => assertion.role,
            Self::Canonical(assertion) => assertion.role,
            Self::Route(assertion) => assertion.role,
            Self::RoundTrip(assertion) => assertion.role,
        }
    }

    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::Occurrence(_) => "occurrence",
            Self::Resolution(_) => "resolution",
            Self::Reaching(_) => "reaching",
            Self::Boundary(_) => "boundary",
            Self::EdgeParity(_) => "edge_parity",
            Self::EdgeClass(_) => "edge_class",
            Self::Canonical(_) => "canonical",
            Self::Route(_) => "route",
            Self::RoundTrip(_) => "round_trip",
        }
    }
}

/// A single correlated existence/absence/cardinality invariant.
///
/// `at` names a capture on the *identifier token* being asserted about. The
/// join is an equality on the captured facts-arena node's content-scoped AST
/// id, so a capture placed on the enclosing declaration addresses a different
/// node and correctly joins nothing.
#[derive(Debug, Clone)]
pub struct OccurrenceAssert {
    pub id: PolicyAssertId,
    pub at: String,
    pub role: OccurrenceRole,
    pub expect: ExpectedOccurrence,
    pub cardinality: AssertCardinality,
    pub namespace: Option<Namespace>,
    pub require_target: bool,
}

/// Require the resolver's selected candidate to sit at (or above) one
/// precedence tier, optionally forbidding a named tier and ambiguity.
///
/// Every field is a claim about the *selected* candidate rows joined to the
/// subject occurrence. A row whose tier the recording seam could not name
/// (`unattributed`) makes the verdict inconclusive rather than a pass or a
/// violation, because an absent tier is not a weak tier.
#[derive(Debug, Clone)]
pub struct ResolutionAssert {
    pub id: PolicyAssertId,
    pub at: String,
    pub role: OccurrenceRole,
    pub expect_tier: PrecedenceTier,
    /// `false` requires the exact tier; `true` accepts any tier at least as
    /// strong as it.
    pub at_least: bool,
    pub forbid_tier: Option<PrecedenceTier>,
    /// Require exactly one selected candidate. Ambiguity is a violation rather
    /// than a silent pick.
    pub require_unique: bool,
}

impl ResolutionAssert {
    /// Whether a selected candidate at `tier` satisfies the expectation.
    ///
    /// `PrecedenceTier` is ordered strongest first, so "at least as strong as
    /// `expect_tier`" is `tier <= expect_tier`.
    pub fn accepts(&self, tier: PrecedenceTier) -> bool {
        if self.forbid_tier == Some(tier) {
            return false;
        }
        if self.at_least {
            tier <= self.expect_tier
        } else {
            tier == self.expect_tier
        }
    }

    /// Whether any tier at all can satisfy this assert. A decoder rejects an
    /// assert for which no tier can, so the evaluator never runs a comparison
    /// whose verdict was fixed before it saw a row.
    pub fn is_satisfiable(&self) -> bool {
        brokk_bifrost_analysis::analyzer::structural::ALL_PRECEDENCE_TIERS
            .iter()
            .any(|tier| self.accepts(*tier))
    }

    /// A human-readable statement of the expectation, for finding evidence.
    pub fn expectation(&self) -> String {
        let mut text = if self.at_least {
            format!("selected tier at least {}", self.expect_tier.label())
        } else {
            format!("selected tier exactly {}", self.expect_tier.label())
        };
        if let Some(tier) = self.forbid_tier {
            text.push_str(&format!(", never {}", tier.label()));
        }
        if self.require_unique {
            text.push_str(", uniquely selected");
        }
        text
    }
}

/// Require the reaching binding of the subject occurrence to be declared inside
/// or outside a second captured node.
///
/// This is the loop-invariance predicate: capture the receiver and the loop,
/// then ask whether the binding actually in effect at the receiver is declared
/// within the loop body.
#[derive(Debug, Clone)]
pub struct ReachingAssert {
    pub id: PolicyAssertId,
    pub at: String,
    pub role: OccurrenceRole,
    pub containment: DeclaredContainment,
    /// The capture whose node interval the declaring scope is compared against.
    pub relative_to: String,
}

impl ReachingAssert {
    pub fn expectation(&self) -> String {
        format!(
            "reaching binding declared {} capture `{}`",
            self.containment.label(),
            self.relative_to
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeclaredContainment {
    Inside,
    Outside,
}

impl DeclaredContainment {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Inside => "inside",
            Self::Outside => "outside",
        }
    }

    /// Whether an observed containment satisfies the requirement.
    pub const fn satisfied_by(self, contained: bool) -> bool {
        match self {
            Self::Inside => contained,
            Self::Outside => !contained,
        }
    }
}

/// Forbid a name-only fallback selection once resolution has reached or passed
/// one authoritative boundary strength.
///
/// The contract this expresses is "do not guess by bare name after the lookup
/// left ground it can vouch for".
#[derive(Debug, Clone)]
pub struct BoundaryAssert {
    pub id: PolicyAssertId,
    pub at: String,
    pub role: OccurrenceRole,
    pub forbid_fallback_past: BoundaryStrength,
}

impl BoundaryAssert {
    pub fn expectation(&self) -> String {
        format!(
            "no name_only_fallback selection at or past {}",
            self.forbid_fallback_past.label()
        )
    }
}

/// Require two captures' resolved declarations to share (or not share) one
/// canonical identity.
///
/// This is the decoy separator: two spellings whose displays coincide but
/// whose owner segments, namespaces, or generic arities differ compare
/// unequal, and the comparison never consults a rendering.
#[derive(Debug, Clone)]
pub struct CanonicalAssert {
    pub id: PolicyAssertId,
    pub at: String,
    pub role: OccurrenceRole,
    /// The second capture whose resolved declarations are compared against.
    pub equals: String,
    /// The occurrence role of the second capture's token.
    pub equals_role: OccurrenceRole,
    /// `true` inverts the requirement: the two selections must share no
    /// canonical identity.
    pub distinct: bool,
}

impl CanonicalAssert {
    pub fn expectation(&self) -> String {
        if self.distinct {
            format!(
                "no shared canonical identity with capture `{}`",
                self.equals
            )
        } else {
            format!("a shared canonical identity with capture `{}`", self.equals)
        }
    }
}

/// Require an identity route from the subject's site to a second capture's
/// declaration, optionally requiring one hop kind on the route and excluding
/// another from the traversal.
#[derive(Debug, Clone)]
pub struct RouteAssert {
    pub id: PolicyAssertId,
    pub at: String,
    pub role: OccurrenceRole,
    /// The capture whose resolved declarations the route must terminate at.
    pub to: String,
    /// The occurrence role of the target capture's token.
    pub to_role: OccurrenceRole,
    /// When present, at least one hop of this kind must appear on the route.
    pub via: Option<RouteHopKind>,
    /// When present, the traversal never follows hops of this kind, so a
    /// route that needs one does not exist for this assert.
    pub forbid: Option<RouteHopKind>,
}

impl RouteAssert {
    pub fn expectation(&self) -> String {
        let mut text = format!("an identity route to capture `{}`", self.to);
        if let Some(via) = self.via {
            text.push_str(&format!(" via {}", via.label()));
        }
        if let Some(forbid) = self.forbid {
            text.push_str(&format!(", never via {}", forbid.label()));
        }
        text
    }
}

/// Require forward resolution and inverse enumeration to round-trip the
/// subject site: every terminal declaration the forward traversal reaches
/// must reach the site back through inverse enumeration over the involved
/// files.
#[derive(Debug, Clone)]
pub struct RoundTripAssert {
    pub id: PolicyAssertId,
    pub at: String,
    pub role: OccurrenceRole,
}

impl RoundTripAssert {
    pub fn expectation(&self) -> String {
        "forward and inverse routes round-trip the subject site".to_string()
    }
}

/// The two boundary statuses strong enough to be an authoritative boundary.
///
/// `workspace_local` and `external_indexed` are deliberately not authorable:
/// resolution that stayed inside indexed ground has not left anything, so
/// forbidding a fallback "past" them would name a boundary that was not
/// crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoundaryStrength {
    ExternalDeclaredUnindexed,
    ExternalUnknown,
}

impl BoundaryStrength {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExternalDeclaredUnindexed => "external_declared_unindexed",
            Self::ExternalUnknown => "external_unknown",
        }
    }

    pub const fn status(self) -> BoundaryStatus {
        match self {
            Self::ExternalDeclaredUnindexed => BoundaryStatus::ExternalDeclaredUnindexed,
            Self::ExternalUnknown => BoundaryStatus::ExternalUnknown,
        }
    }

    /// Whether an observed boundary status is at or past this strength.
    ///
    /// `BoundaryStatus` is declared weakest first, so "at or past" is `>=`.
    pub fn reached_by(self, observed: BoundaryStatus) -> bool {
        boundary_rank(observed) >= boundary_rank(self.status())
    }
}

/// Ordinal strength of a boundary status, stated once so the two comparisons
/// that need it cannot disagree.
const fn boundary_rank(status: BoundaryStatus) -> u8 {
    match status {
        BoundaryStatus::WorkspaceLocal => 0,
        BoundaryStatus::ExternalIndexed => 1,
        BoundaryStatus::ExternalDeclaredUnindexed => 2,
        BoundaryStatus::ExternalUnknown => 3,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpectedOccurrence {
    Declaration,
    Reference,
    Binding,
    None,
}

impl ExpectedOccurrence {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Declaration => "declaration",
            Self::Reference => "reference",
            Self::Binding => "binding",
            Self::None => "none",
        }
    }

    /// The occurrence class a joined row must carry, or `None` when the
    /// assertion forbids every row regardless of class.
    pub const fn required_class(self) -> Option<OccurrenceClass> {
        match self {
            Self::Declaration => Some(OccurrenceClass::Declaration),
            Self::Reference => Some(OccurrenceClass::Reference),
            Self::Binding => Some(OccurrenceClass::Binding),
            Self::None => None,
        }
    }
}

/// Require field-for-field agreement between the forward and inverse edge
/// projections at the subject token, within one workspace generation.
///
/// The direction follows the asserted role. A reference-class role checks the
/// forward direction: every forward edge the resolver states at the token must
/// have an inverse counterpart in its target's usage listing, with the same
/// site identity, reference kind, proof, usage kind, site class, and owner
/// relation. The `declaration_name` role checks the inverse direction: every
/// inverse edge of the declaration this token names must have a forward
/// counterpart derived from the file that spelled the site. Both provenance
/// chains are retained on every finding.
///
/// There is deliberately no field-projection narrowing and no count
/// comparison: the acceptance contract compares classifications explicitly,
/// and a narrower projection would silently weaken it.
#[derive(Debug, Clone)]
pub struct EdgeParityAssert {
    pub id: PolicyAssertId,
    pub at: String,
    pub role: OccurrenceRole,
    /// Compare only edges belonging to this usage surface. `None` compares
    /// the complete row set, editor-only rows included.
    pub surface: Option<UsageHitSurface>,
}

impl EdgeParityAssert {
    pub fn expectation(&self) -> String {
        let direction = if self.role == OccurrenceRole::DeclarationName {
            "every inverse edge has a field-identical forward counterpart"
        } else {
            "every forward edge has a field-identical inverse counterpart"
        };
        match self.surface {
            Some(surface) => format!(
                "{direction} on the {} surface",
                brokk_bifrost_analysis::analyzer::structural::query::schema::usage_surface_label(
                    surface
                )
            ),
            None => direction.to_string(),
        }
    }
}

/// Require or forbid classifications on the subject token's edge rows.
///
/// The rows follow the asserted role exactly as for the parity assert: a
/// reference-class role reads the token's forward edges, the
/// `declaration_name` role reads the inverse edges of the declaration the
/// token names.
#[derive(Debug, Clone)]
pub struct EdgeClassAssert {
    pub id: PolicyAssertId,
    pub at: String,
    pub role: OccurrenceRole,
    pub constraint: EdgeClassConstraint,
    pub surface: Option<UsageHitSurface>,
}

impl EdgeClassAssert {
    pub fn expectation(&self) -> String {
        let base = self.constraint.expectation();
        match self.surface {
            Some(surface) => format!(
                "{base} on the {} surface",
                brokk_bifrost_analysis::analyzer::structural::query::schema::usage_surface_label(
                    surface
                )
            ),
            None => base,
        }
    }
}

/// One typed classification constraint. Require and forbid are per axis so a
/// value can never be compared against the wrong vocabulary, and an empty
/// require list means "no requirement", never "require nothing".
#[derive(Debug, Clone)]
pub enum EdgeClassConstraint {
    Relation {
        require: Vec<OwnerRelation>,
        forbid: Vec<OwnerRelation>,
    },
    Usage {
        require: Vec<UsageHitKind>,
        forbid: Vec<UsageHitKind>,
    },
    SiteClass {
        require: Vec<SiteClass>,
        forbid: Vec<SiteClass>,
    },
    Kind {
        require: Vec<ReferenceKind>,
        forbid: Vec<ReferenceKind>,
    },
}

impl EdgeClassConstraint {
    pub const fn axis_label(&self) -> &'static str {
        match self {
            Self::Relation { .. } => "relation",
            Self::Usage { .. } => "usage",
            Self::SiteClass { .. } => "site_class",
            Self::Kind { .. } => "kind",
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Relation { require, forbid } => require.is_empty() && forbid.is_empty(),
            Self::Usage { require, forbid } => require.is_empty() && forbid.is_empty(),
            Self::SiteClass { require, forbid } => require.is_empty() && forbid.is_empty(),
            Self::Kind { require, forbid } => require.is_empty() && forbid.is_empty(),
        }
    }

    pub fn expectation(&self) -> String {
        fn joined<T>(values: &[T], label: impl Fn(&T) -> &'static str) -> String {
            values.iter().map(label).collect::<Vec<_>>().join(", ")
        }
        let (require, forbid) = match self {
            Self::Relation { require, forbid } => (
                joined(require, |value| value.label()),
                joined(forbid, |value| value.label()),
            ),
            Self::Usage { require, forbid } => (
                joined(require, |value| value.wire_label()),
                joined(forbid, |value| value.wire_label()),
            ),
            Self::SiteClass { require, forbid } => (
                joined(require, |value| value.label()),
                joined(forbid, |value| value.label()),
            ),
            Self::Kind { require, forbid } => (
                joined(require, |value| {
                    brokk_bifrost_analysis::analyzer::structural::query::schema::reference_kind_label(*value)
                }),
                joined(forbid, |value| {
                    brokk_bifrost_analysis::analyzer::structural::query::schema::reference_kind_label(*value)
                }),
            ),
        };
        let mut parts = Vec::new();
        if !require.is_empty() {
            parts.push(format!("every edge {} in [{require}]", self.axis_label()));
        }
        if !forbid.is_empty() {
            parts.push(format!("no edge {} in [{forbid}]", self.axis_label()));
        }
        parts.join("; ")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssertCardinality {
    Exactly(u32),
    AtLeast(u32),
    AtMost(u32),
}

impl AssertCardinality {
    pub const DEFAULT: Self = Self::Exactly(1);

    pub const fn satisfied_by(self, actual: u32) -> bool {
        match self {
            Self::Exactly(count) => actual == count,
            Self::AtLeast(count) => actual >= count,
            Self::AtMost(count) => actual <= count,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Exactly(_) => "exactly",
            Self::AtLeast(_) => "at-least",
            Self::AtMost(_) => "at-most",
        }
    }

    pub const fn count(self) -> u32 {
        match self {
            Self::Exactly(count) | Self::AtLeast(count) | Self::AtMost(count) => count,
        }
    }
}

impl fmt::Display for AssertCardinality {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "({} {})", self.label(), self.count())
    }
}

#[derive(Debug, Clone)]
pub struct PolicyMetadata {
    pub id: PolicyId,
    pub name: String,
    pub message: PolicyMessageSpec,
    pub severity: PolicySeveritySpec,
    pub description: Option<String>,
    pub help_uri: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyMessageSpec {
    Static { text: String },
    Generated { relation: GeneratedRelation },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GeneratedRelation {
    CanReach,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySeveritySpec {
    Fixed { level: PolicyLevel },
    Unrated,
    Cvss { when_unscored: FindingSeverity },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyLevel {
    Note,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingSeverity {
    Unrated,
    Note,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub struct MatchPolicySpec {
    pub selector: PolicySelector,
}

#[derive(Debug, Clone)]
pub enum PolicySelector {
    Inline {
        schema: SchemaVersionResolution,
        query: CodeQuery,
    },
    File {
        authored_schema_version: Option<u32>,
        path: WorkspaceRelativePath,
    },
}

#[derive(Debug, Clone)]
pub struct MatchEndpointDefinition {
    pub schema_version: PolicySchemaVersion,
    pub id: EndpointId,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub help_uri: Option<String>,
    pub role: EndpointRole,
    pub categories: Vec<PolicyCategoryId>,
    pub selector: PolicySelector,
    pub binding: PolicyEndpointBinding,
    pub taint: Option<EndpointTaintSemantics>,
    pub supersedes: Vec<EndpointId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointRole {
    Source,
    Sink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyEndpointBinding {
    MatchedValue,
    Receiver,
    ReturnValue,
    ArgumentIndex { index: u32 },
    ArgumentName { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointTaintSemantics {
    Source {
        labels: Vec<TaintLabel>,
        evidence: Option<TaintSourceEvidence>,
    },
    Sink {
        accepts: Vec<TaintLabel>,
        tags: Vec<TaintTag>,
        impacts: Vec<TaintImpact>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReportOptions {
    pub witness: WitnessOptions,
    pub witnesses_per_finding: usize,
    pub origins_per_finding: usize,
}

impl Default for PolicyReportOptions {
    fn default() -> Self {
        Self {
            witness: WitnessOptions::default(),
            witnesses_per_finding: DEFAULT_WITNESSES_PER_FINDING,
            origins_per_finding: DEFAULT_ORIGINS_PER_FINDING,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessOptions {
    pub max_steps: usize,
    pub max_bytes: usize,
}

impl Default for WitnessOptions {
    fn default() -> Self {
        Self {
            max_steps: DEFAULT_WITNESS_MAX_STEPS,
            max_bytes: DEFAULT_WITNESS_MAX_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MayMode {
    #[default]
    May,
}

#[derive(Debug, Clone)]
pub struct TaintPolicySpec {
    pub mode: MayMode,
    pub call_modeling: CallModelingSpec,
    pub sources: TaintEndpointSet<TaintSourceSpec>,
    pub sinks: TaintEndpointSet<TaintSinkSpec>,
    pub sanitizers: TaintEndpointSet<TaintSanitizerSpec>,
    pub transforms: TaintEndpointSet<TaintTransformSpec>,
    pub external_models: TaintEndpointSet<TaintExternalModelSpec>,
    pub finding_combinations: Vec<FindingCombinationSpec>,
}

#[derive(Debug, Clone)]
pub struct TaintEndpointSet<T> {
    pub include_sets: Vec<CatalogRef>,
    pub include_matches: Vec<MatchEndpointSetRef>,
    pub entries: Vec<T>,
}

impl<T> Default for TaintEndpointSet<T> {
    fn default() -> Self {
        Self {
            include_sets: Vec::new(),
            include_matches: Vec::new(),
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchEndpointSetRef {
    Directory { reference: MatchDirectoryRef },
    Exact { endpoint_ids: Vec<EndpointId> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchDirectoryRef {
    pub path: WorkspaceRelativePath,
    pub scope: DirectoryScope,
    pub categories: CategoryPredicate,
    pub manifest_sha256: Option<MatchSetManifestHash>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DirectoryScope {
    Direct,
    Recursive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CategoryPredicate {
    Any { categories: Vec<PolicyCategoryId> },
    All { categories: Vec<PolicyCategoryId> },
}

#[derive(Debug, Clone)]
pub struct FindingCombinationSpec {
    pub id: FindingCombinationId,
    pub source: EndpointPredicate,
    pub sink: EndpointPredicate,
    pub message: String,
    pub severity: Option<PolicySeveritySpec>,
    pub add_classifications: Vec<TaxonomyClassificationSpec>,
    pub supersedes: Vec<FindingCombinationId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointPredicate {
    Categories { predicate: CategoryPredicate },
    Exact { endpoints: Vec<EndpointRef> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointRef {
    Local {
        entry_id: TaintEntryId,
    },
    Catalog {
        catalog: CatalogRef,
        entry_id: TaintEntryId,
    },
    MatchEndpoint {
        endpoint_id: EndpointId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyPort {
    MatchedValue,
    Receiver,
    ReturnValue,
    ArgumentIndex { index: u32 },
    ArgumentName { name: String },
}

#[derive(Debug, Clone)]
pub struct TaintSourceSpec {
    pub id: TaintEntryId,
    pub display_name: String,
    pub categories: Vec<PolicyCategoryId>,
    pub selector: PolicySelector,
    pub bind: PolicyPort,
    pub labels: Vec<TaintLabel>,
    pub evidence: Option<TaintSourceEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSourceEvidence {
    pub trust_boundary: Option<TaintTrustBoundary>,
    pub system_entry: Option<TaintSystemEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintTrustBoundary {
    External,
    Internal,
    SameTrustZone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintSystemEntry {
    VulnerableSystemNetworkStack,
    DownloadedArtifact,
    LocalInput,
    AdjacentNetwork,
    Physical,
}

#[derive(Debug, Clone)]
pub struct TaintSinkSpec {
    pub id: TaintEntryId,
    pub display_name: String,
    pub categories: Vec<PolicyCategoryId>,
    pub selector: PolicySelector,
    pub dangerous_operand: PolicyPort,
    pub accepts: Vec<TaintLabel>,
    pub tags: Vec<TaintTag>,
    pub impacts: Vec<TaintImpact>,
}

#[derive(Debug, Clone)]
pub struct TaintSanitizerSpec {
    pub id: TaintEntryId,
    pub selector: PolicySelector,
    pub input: PolicyPort,
    pub output: PolicyPort,
    pub removes: Vec<TaintLabel>,
}

#[derive(Debug, Clone)]
pub struct TaintTransformSpec {
    pub id: TaintEntryId,
    pub selector: PolicySelector,
    pub input: PolicyPort,
    pub output: PolicyPort,
    pub removes: Vec<TaintLabel>,
    pub adds: Vec<TaintLabel>,
}

#[derive(Debug, Clone)]
pub struct TaintExternalModelSpec {
    pub id: TaintEntryId,
    pub selector: PolicySelector,
    pub transfers: Vec<TaintTransferSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintTransferSpec {
    pub from: PolicyPort,
    pub to: PolicyPort,
    pub labels: Vec<TaintLabel>,
    pub effect: TaintTransferEffect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintTransferEffect {
    Propagate,
    Sanitize {
        removes: Vec<TaintLabel>,
    },
    Transform {
        removes: Vec<TaintLabel>,
        adds: Vec<TaintLabel>,
    },
}

#[derive(Debug, Clone)]
pub struct TypestatePolicySpec {
    pub mode: MayMode,
    pub call_modeling: CallModelingSpec,
    pub subjects: TypestateSubjectSet,
    pub uncertainty: TypestateUncertaintySpec,
    pub automaton: TypestateAutomatonSpec,
}

#[derive(Debug, Clone, Default)]
pub struct TypestateSubjectSet {
    pub include_matches: Vec<MatchEndpointSetRef>,
    pub entries: Vec<TypestateSubjectSpec>,
}

#[derive(Debug, Clone)]
pub struct TypestateSubjectSpec {
    pub id: TaintEntryId,
    pub selector: PolicySelector,
    pub subject: TypestateSeedBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypestateSeedBinding {
    MatchedValue,
    Receiver,
    ReturnValue,
    ArgumentIndex { index: u32 },
    ArgumentName { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypestateUncertaintySpec {
    pub escape: InconclusivePolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CallModelingSpec {
    pub unmodeled: UnmodeledCallBehavior,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum InconclusivePolicy {
    #[default]
    Inconclusive,
}

#[derive(Debug, Clone)]
pub struct TypestateAutomatonSpec {
    pub states: Vec<TypestateStateId>,
    pub initial: TypestateStateId,
    pub accepting_states: Vec<TypestateStateId>,
    pub error_states: Vec<TypestateStateId>,
    pub events: Vec<TypestateEventSpec>,
    pub transitions: Vec<TypestateTransitionSpec>,
    pub terminal_expectations: Vec<TypestateTerminalExpectationSpec>,
}

#[derive(Debug, Clone)]
pub struct TypestateEventSpec {
    pub id: TypestateEventId,
    pub trigger: TypestateEventTrigger,
    pub applies_to_subjects: Option<EndpointPredicate>,
    pub supersedes: Vec<TypestateEventId>,
}

#[derive(Debug, Clone)]
pub enum TypestateEventTrigger {
    Calls {
        selector: PolicySelector,
        subject: TypestateCallBinding,
        phase: EndpointObservationPhase,
    },
    MatchEndpoints {
        set: MatchEndpointSetRef,
        role: EndpointRole,
        phase: EndpointObservationPhase,
    },
    SemanticEvent {
        event: PolicySemanticEvent,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypestateCallBinding {
    Receiver,
    ReturnValue,
    ArgumentIndex { index: u32 },
    ArgumentName { name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicySemanticEvent {
    NormalProcedureExit { scope: TypestateExitScope },
    ExceptionalProcedureExit { scope: TypestateExitScope },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypestateExitScope {
    AnalysisRoot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypestateTransitionSpec {
    pub from: TypestateStateId,
    pub on: TypestateEventId,
    pub to: TypestateStateId,
}

#[derive(Debug, Clone)]
pub struct TypestateTerminalExpectationSpec {
    pub id: TypestateExpectationId,
    pub trigger: TypestateTerminalTrigger,
    pub applies_to_subjects: Option<EndpointPredicate>,
    pub expected_states: Vec<TypestateStateId>,
    pub supersedes: Vec<TypestateExpectationId>,
}

#[derive(Debug, Clone)]
pub enum TypestateTerminalTrigger {
    MatchEndpoints {
        set: MatchEndpointSetRef,
        role: EndpointRole,
        phase: EndpointObservationPhase,
    },
    SemanticEvent {
        event: PolicySemanticEvent,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointObservationPhase {
    AtMatch,
    BeforeCall,
    AfterNormalReturn,
    AfterExceptionalReturn,
}

#[derive(Debug, Clone)]
pub struct PolicyClassificationSpec {
    pub fallback: TaxonomyClassificationSpec,
    pub refinements: Vec<ClassificationRefinementSpec>,
    pub cvss: Option<CvssPolicySpec>,
}

#[derive(Debug, Clone)]
pub struct ClassificationRefinementSpec {
    pub when: ClassificationPredicate,
    pub add: Vec<TaxonomyClassificationSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaxonomyClassificationSpec {
    pub taxonomy: String,
    pub identifier: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassificationPredicate {
    All {
        predicates: Vec<ClassificationPredicate>,
    },
    Any {
        predicates: Vec<ClassificationPredicate>,
    },
    AnalysisType {
        analysis_type: PolicyAnalysisType,
    },
    SourceCategories {
        quantifier: AnyOrAll,
        values: Vec<PolicyCategoryId>,
    },
    SinkCategories {
        quantifier: AnyOrAll,
        values: Vec<PolicyCategoryId>,
    },
    SourceLabels {
        quantifier: AnyOrAll,
        values: Vec<TaintLabel>,
    },
    SinkTags {
        quantifier: AnyOrAll,
        values: Vec<TaintTag>,
    },
    SinkImpacts {
        quantifier: AnyOrAll,
        values: Vec<TaintImpact>,
    },
    FindingCombination {
        id: FindingCombinationId,
    },
    TypestateExpectation {
        id: TypestateExpectationId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnyOrAll {
    Any,
    All,
}

#[derive(Debug, Clone)]
pub struct CvssPolicySpec {
    pub version: CvssVersion,
    pub emit: CvssEmitPolicy,
    pub metric_rules: Vec<CvssMetricRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CvssVersion {
    V4_0,
}

impl CvssVersion {
    pub const fn wire_label(self) -> &'static str {
        match self {
            Self::V4_0 => "4.0",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CvssEmitPolicy {
    WhenBaseComplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CvssMetricRule {
    metric: CvssBaseMetric,
    value: CvssMetricValue,
    when: CvssEvidencePredicate,
    basis: PolicyCvssBasis,
    scope: CvssEvidenceScope,
    evidence_refs: Vec<PolicyEvidenceRef>,
    rationale: String,
    assumptions: Vec<String>,
}

impl CvssMetricRule {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        metric: CvssBaseMetric,
        value: CvssMetricValue,
        when: CvssEvidencePredicate,
        basis: PolicyCvssBasis,
        scope: CvssEvidenceScope,
        evidence_refs: Vec<PolicyEvidenceRef>,
        rationale: String,
        assumptions: Vec<String>,
    ) -> Result<Self, InvalidCvssMetricRule> {
        let expected_value_metric = CvssMetric::Base { metric };
        if value.metric() != expected_value_metric {
            return Err(InvalidCvssMetricRule::ValueMetricMismatch {
                rule_metric: metric,
                value_metric: value.metric(),
            });
        }

        let expected_scope = metric.required_scope();
        if scope != expected_scope {
            return Err(InvalidCvssMetricRule::ScopeMismatch {
                metric,
                expected: expected_scope,
                actual: scope,
            });
        }

        validate_cvss_predicate(&when)?;
        if evidence_refs.is_empty() {
            return Err(InvalidCvssMetricRule::EmptyEvidenceReferences);
        }
        if evidence_refs.len() > MAX_POLICY_SET_ITEMS {
            return Err(InvalidCvssMetricRule::TooManyEvidenceReferences {
                max: MAX_POLICY_SET_ITEMS,
            });
        }
        if has_duplicates(&evidence_refs) {
            return Err(InvalidCvssMetricRule::DuplicateEvidenceReference);
        }
        validate_required_policy_text(&rationale).map_err(|error| match error {
            InvalidPolicyText::Empty => InvalidCvssMetricRule::EmptyRationale,
            InvalidPolicyText::TooLong => InvalidCvssMetricRule::RationaleTooLong {
                max: MAX_POLICY_DISPLAY_TEXT_BYTES,
            },
            InvalidPolicyText::ForbiddenCharacter => {
                InvalidCvssMetricRule::InvalidRationaleCharacter
            }
        })?;
        if assumptions.len() > MAX_POLICY_SET_ITEMS {
            return Err(InvalidCvssMetricRule::TooManyAssumptions {
                max: MAX_POLICY_SET_ITEMS,
            });
        }
        for (index, assumption) in assumptions.iter().enumerate() {
            validate_required_policy_text(assumption).map_err(|error| match error {
                InvalidPolicyText::Empty => InvalidCvssMetricRule::EmptyAssumption { index },
                InvalidPolicyText::TooLong => InvalidCvssMetricRule::AssumptionTooLong {
                    index,
                    max: MAX_POLICY_DISPLAY_TEXT_BYTES,
                },
                InvalidPolicyText::ForbiddenCharacter => {
                    InvalidCvssMetricRule::InvalidAssumptionCharacter { index }
                }
            })?;
        }
        if has_duplicates(&assumptions) {
            return Err(InvalidCvssMetricRule::DuplicateAssumption);
        }

        Ok(Self {
            metric,
            value,
            when,
            basis,
            scope,
            evidence_refs,
            rationale,
            assumptions,
        })
    }

    pub const fn metric(&self) -> CvssBaseMetric {
        self.metric
    }

    pub const fn value(&self) -> CvssMetricValue {
        self.value
    }

    pub const fn when(&self) -> &CvssEvidencePredicate {
        &self.when
    }

    pub const fn basis(&self) -> PolicyCvssBasis {
        self.basis
    }

    pub const fn scope(&self) -> CvssEvidenceScope {
        self.scope
    }

    pub fn evidence_refs(&self) -> &[PolicyEvidenceRef] {
        &self.evidence_refs
    }

    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    pub fn assumptions(&self) -> &[String] {
        &self.assumptions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CvssEvidencePredicate {
    All {
        predicates: Vec<CvssEvidencePredicate>,
    },
    Any {
        predicates: Vec<CvssEvidencePredicate>,
    },
    AnalysisType {
        analysis_type: PolicyAnalysisType,
    },
    SourceEvidence {
        evidence: TaintSourceEvidence,
    },
    SourceCategories {
        quantifier: AnyOrAll,
        values: Vec<PolicyCategoryId>,
    },
    SinkCategories {
        quantifier: AnyOrAll,
        values: Vec<PolicyCategoryId>,
    },
    SourceLabels {
        quantifier: AnyOrAll,
        values: Vec<TaintLabel>,
    },
    SinkTags {
        quantifier: AnyOrAll,
        values: Vec<TaintTag>,
    },
    SinkImpacts {
        quantifier: AnyOrAll,
        values: Vec<TaintImpact>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyCvssBasis {
    PolicyAssertion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CvssSystemScope {
    VulnerableSystem,
    SubsequentSystem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CvssEvidenceScope {
    Global,
    System { system: CvssSystemScope },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CvssBaseMetric {
    Av,
    Ac,
    At,
    Pr,
    Ui,
    Vc,
    Vi,
    Va,
    Sc,
    Si,
    Sa,
}

impl CvssBaseMetric {
    pub const fn first_label(self) -> &'static str {
        match self {
            Self::Av => "AV",
            Self::Ac => "AC",
            Self::At => "AT",
            Self::Pr => "PR",
            Self::Ui => "UI",
            Self::Vc => "VC",
            Self::Vi => "VI",
            Self::Va => "VA",
            Self::Sc => "SC",
            Self::Si => "SI",
            Self::Sa => "SA",
        }
    }

    pub const fn required_scope(self) -> CvssEvidenceScope {
        match self {
            Self::Av
            | Self::Ac
            | Self::At
            | Self::Pr
            | Self::Ui
            | Self::Vc
            | Self::Vi
            | Self::Va => CvssEvidenceScope::System {
                system: CvssSystemScope::VulnerableSystem,
            },
            Self::Sc | Self::Si | Self::Sa => CvssEvidenceScope::System {
                system: CvssSystemScope::SubsequentSystem,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CvssThreatMetric {
    E,
}

impl CvssThreatMetric {
    pub const fn first_label(self) -> &'static str {
        match self {
            Self::E => "E",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CvssEnvironmentalOrSupplementalMetric {
    Cr,
    Ir,
    Ar,
    Mav,
    Mac,
    Mat,
    Mpr,
    Mui,
    Mvc,
    Mvi,
    Mva,
    Msc,
    Msi,
    Msa,
    S,
    Au,
    R,
    V,
    Re,
    U,
}

impl CvssEnvironmentalOrSupplementalMetric {
    pub const fn first_label(self) -> &'static str {
        match self {
            Self::Cr => "CR",
            Self::Ir => "IR",
            Self::Ar => "AR",
            Self::Mav => "MAV",
            Self::Mac => "MAC",
            Self::Mat => "MAT",
            Self::Mpr => "MPR",
            Self::Mui => "MUI",
            Self::Mvc => "MVC",
            Self::Mvi => "MVI",
            Self::Mva => "MVA",
            Self::Msc => "MSC",
            Self::Msi => "MSI",
            Self::Msa => "MSA",
            Self::S => "S",
            Self::Au => "AU",
            Self::R => "R",
            Self::V => "V",
            Self::Re => "RE",
            Self::U => "U",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CvssMetric {
    Base {
        metric: CvssBaseMetric,
    },
    Threat {
        metric: CvssThreatMetric,
    },
    EnvironmentalOrSupplemental {
        metric: CvssEnvironmentalOrSupplementalMetric,
    },
}

impl CvssMetric {
    pub const fn first_label(self) -> &'static str {
        match self {
            Self::Base { metric } => metric.first_label(),
            Self::Threat { metric } => metric.first_label(),
            Self::EnvironmentalOrSupplemental { metric } => metric.first_label(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CvssMetricValueToken {
    X,
    N,
    A,
    L,
    P,
    H,
    M,
    U,
    S,
    Y,
    I,
    D,
    C,
    Clear,
    Green,
    Amber,
    Red,
}

impl CvssMetricValueToken {
    pub const fn first_label(self) -> &'static str {
        match self {
            Self::X => "X",
            Self::N => "N",
            Self::A => "A",
            Self::L => "L",
            Self::P => "P",
            Self::H => "H",
            Self::M => "M",
            Self::U => "U",
            Self::S => "S",
            Self::Y => "Y",
            Self::I => "I",
            Self::D => "D",
            Self::C => "C",
            Self::Clear => "Clear",
            Self::Green => "Green",
            Self::Amber => "Amber",
            Self::Red => "Red",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CvssMetricValue {
    metric: CvssMetric,
    token: CvssMetricValueToken,
}

impl CvssMetricValue {
    pub fn try_new(
        metric: CvssMetric,
        token: CvssMetricValueToken,
    ) -> Result<Self, InvalidCvssMetricValue> {
        if cvss_token_is_legal(metric, token) {
            Ok(Self { metric, token })
        } else {
            Err(InvalidCvssMetricValue { metric, token })
        }
    }

    pub const fn metric(self) -> CvssMetric {
        self.metric
    }

    pub const fn token(self) -> CvssMetricValueToken {
        self.token
    }

    pub const fn first_label(self) -> &'static str {
        self.token.first_label()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCvssMetricValue {
    pub metric: CvssMetric,
    pub token: CvssMetricValueToken,
}

impl fmt::Display for InvalidCvssMetricValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CVSS value {:?} is not legal for metric {:?}",
            self.token, self.metric
        )
    }
}

impl std::error::Error for InvalidCvssMetricValue {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidCvssMetricRule {
    ValueMetricMismatch {
        rule_metric: CvssBaseMetric,
        value_metric: CvssMetric,
    },
    ScopeMismatch {
        metric: CvssBaseMetric,
        expected: CvssEvidenceScope,
        actual: CvssEvidenceScope,
    },
    EmptyEvidenceReferences,
    TooManyEvidenceReferences {
        max: usize,
    },
    DuplicateEvidenceReference,
    EmptyRationale,
    RationaleTooLong {
        max: usize,
    },
    InvalidRationaleCharacter,
    TooManyAssumptions {
        max: usize,
    },
    EmptyAssumption {
        index: usize,
    },
    AssumptionTooLong {
        index: usize,
        max: usize,
    },
    InvalidAssumptionCharacter {
        index: usize,
    },
    DuplicateAssumption,
    EmptyPredicateSet,
    EmptyPredicateValues,
    TooManyPredicateValues {
        max: usize,
    },
    DuplicatePredicateValue,
    EmptySourceEvidence,
    PredicateDepthLimit {
        max: usize,
    },
    PredicateNodeLimit {
        max: usize,
    },
}

impl fmt::Display for InvalidCvssMetricRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueMetricMismatch {
                rule_metric,
                value_metric,
            } => write!(
                formatter,
                "CVSS rule metric {} does not match value metric {}",
                rule_metric.first_label(),
                value_metric.first_label()
            ),
            Self::ScopeMismatch {
                metric,
                expected,
                actual,
            } => write!(
                formatter,
                "CVSS rule metric {} requires scope {expected:?}, not {actual:?}",
                metric.first_label()
            ),
            Self::EmptyEvidenceReferences => {
                formatter.write_str("CVSS rule requires at least one evidence reference")
            }
            Self::TooManyEvidenceReferences { max } => {
                write!(
                    formatter,
                    "CVSS rule accepts at most {max} evidence references"
                )
            }
            Self::DuplicateEvidenceReference => {
                formatter.write_str("CVSS rule evidence references must be duplicate-free")
            }
            Self::EmptyRationale => formatter.write_str("CVSS rule rationale must not be empty"),
            Self::RationaleTooLong { max } => {
                write!(formatter, "CVSS rule rationale must be at most {max} bytes")
            }
            Self::InvalidRationaleCharacter => formatter.write_str(
                "CVSS rule rationale must not contain control or bidirectional-control characters",
            ),
            Self::TooManyAssumptions { max } => {
                write!(formatter, "CVSS rule accepts at most {max} assumptions")
            }
            Self::EmptyAssumption { index } => {
                write!(formatter, "CVSS rule assumption {index} must not be empty")
            }
            Self::AssumptionTooLong { index, max } => write!(
                formatter,
                "CVSS rule assumption {index} must be at most {max} bytes"
            ),
            Self::InvalidAssumptionCharacter { index } => write!(
                formatter,
                "CVSS rule assumption {index} contains a forbidden control character"
            ),
            Self::DuplicateAssumption => {
                formatter.write_str("CVSS rule assumptions must be duplicate-free")
            }
            Self::EmptyPredicateSet => {
                formatter.write_str("CVSS all/any predicates must contain at least one child")
            }
            Self::EmptyPredicateValues => {
                formatter.write_str("CVSS quantified predicates must contain at least one value")
            }
            Self::TooManyPredicateValues { max } => {
                write!(
                    formatter,
                    "CVSS quantified predicates accept at most {max} values"
                )
            }
            Self::DuplicatePredicateValue => formatter
                .write_str("CVSS predicate children and quantified values must be duplicate-free"),
            Self::EmptySourceEvidence => formatter
                .write_str("CVSS source evidence requires a trust boundary, system entry, or both"),
            Self::PredicateDepthLimit { max } => {
                write!(formatter, "CVSS predicate nesting depth exceeds {max}")
            }
            Self::PredicateNodeLimit { max } => {
                write!(formatter, "CVSS predicate node count exceeds {max}")
            }
        }
    }
}

impl std::error::Error for InvalidCvssMetricRule {}

fn validate_cvss_predicate(root: &CvssEvidencePredicate) -> Result<(), InvalidCvssMetricRule> {
    let mut stack = vec![(root, 0_usize)];
    let mut nodes = 0_usize;
    while let Some((predicate, depth)) = stack.pop() {
        if depth > MAX_POLICY_PREDICATE_DEPTH {
            return Err(InvalidCvssMetricRule::PredicateDepthLimit {
                max: MAX_POLICY_PREDICATE_DEPTH,
            });
        }
        nodes += 1;
        if nodes > MAX_POLICY_PREDICATE_NODES {
            return Err(InvalidCvssMetricRule::PredicateNodeLimit {
                max: MAX_POLICY_PREDICATE_NODES,
            });
        }

        match predicate {
            CvssEvidencePredicate::All { predicates }
            | CvssEvidencePredicate::Any { predicates } => {
                if predicates.is_empty() {
                    return Err(InvalidCvssMetricRule::EmptyPredicateSet);
                }
                if has_duplicates(predicates) {
                    return Err(InvalidCvssMetricRule::DuplicatePredicateValue);
                }
                stack.extend(
                    predicates
                        .iter()
                        .rev()
                        .map(|predicate| (predicate, depth + 1)),
                );
            }
            CvssEvidencePredicate::SourceEvidence { evidence }
                if evidence.trust_boundary.is_none() && evidence.system_entry.is_none() =>
            {
                return Err(InvalidCvssMetricRule::EmptySourceEvidence);
            }
            CvssEvidencePredicate::SourceCategories { values, .. }
            | CvssEvidencePredicate::SinkCategories { values, .. } => {
                validate_cvss_predicate_values(values)?;
            }
            CvssEvidencePredicate::SourceLabels { values, .. } => {
                validate_cvss_predicate_values(values)?;
            }
            CvssEvidencePredicate::SinkTags { values, .. } => {
                validate_cvss_predicate_values(values)?;
            }
            CvssEvidencePredicate::SinkImpacts { values, .. } => {
                validate_cvss_predicate_values(values)?;
            }
            CvssEvidencePredicate::AnalysisType { .. }
            | CvssEvidencePredicate::SourceEvidence { .. } => {}
        }
    }
    Ok(())
}

fn validate_cvss_predicate_values<T: PartialEq>(values: &[T]) -> Result<(), InvalidCvssMetricRule> {
    if values.is_empty() {
        return Err(InvalidCvssMetricRule::EmptyPredicateValues);
    }
    if values.len() > MAX_POLICY_SET_ITEMS {
        return Err(InvalidCvssMetricRule::TooManyPredicateValues {
            max: MAX_POLICY_SET_ITEMS,
        });
    }
    if has_duplicates(values) {
        return Err(InvalidCvssMetricRule::DuplicatePredicateValue);
    }
    Ok(())
}

fn has_duplicates<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvalidPolicyText {
    Empty,
    TooLong,
    ForbiddenCharacter,
}

fn validate_required_policy_text(value: &str) -> Result<(), InvalidPolicyText> {
    if value.is_empty() {
        return Err(InvalidPolicyText::Empty);
    }
    if value.len() > MAX_POLICY_DISPLAY_TEXT_BYTES {
        return Err(InvalidPolicyText::TooLong);
    }
    if value.chars().any(|ch| {
        ch.is_control()
            || matches!(
                ch,
                '\u{061c}'
                    | '\u{200e}'
                    | '\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            )
    }) {
        return Err(InvalidPolicyText::ForbiddenCharacter);
    }
    Ok(())
}

const fn cvss_token_is_legal(metric: CvssMetric, token: CvssMetricValueToken) -> bool {
    use CvssBaseMetric as B;
    use CvssEnvironmentalOrSupplementalMetric as ES;
    use CvssMetric::{Base, EnvironmentalOrSupplemental, Threat};
    use CvssMetricValueToken as T;

    match metric {
        Base { metric: B::Av } => matches!(token, T::N | T::A | T::L | T::P),
        Base { metric: B::Ac } => matches!(token, T::L | T::H),
        Base { metric: B::At } => matches!(token, T::N | T::P),
        Base { metric: B::Pr } => matches!(token, T::N | T::L | T::H),
        Base { metric: B::Ui } => matches!(token, T::N | T::P | T::A),
        Base {
            metric: B::Vc | B::Vi | B::Va | B::Sc | B::Si | B::Sa,
        } => matches!(token, T::H | T::L | T::N),
        Threat { .. } => matches!(token, T::X | T::A | T::P | T::U),
        EnvironmentalOrSupplemental {
            metric: ES::Cr | ES::Ir | ES::Ar,
        } => matches!(token, T::X | T::H | T::M | T::L),
        EnvironmentalOrSupplemental { metric: ES::Mav } => {
            matches!(token, T::X | T::N | T::A | T::L | T::P)
        }
        EnvironmentalOrSupplemental { metric: ES::Mac } => {
            matches!(token, T::X | T::L | T::H)
        }
        EnvironmentalOrSupplemental { metric: ES::Mat } => {
            matches!(token, T::X | T::N | T::P)
        }
        EnvironmentalOrSupplemental { metric: ES::Mpr } => {
            matches!(token, T::X | T::N | T::L | T::H)
        }
        EnvironmentalOrSupplemental { metric: ES::Mui } => {
            matches!(token, T::X | T::N | T::P | T::A)
        }
        EnvironmentalOrSupplemental {
            metric: ES::Mvc | ES::Mvi | ES::Mva | ES::Msc,
        } => matches!(token, T::X | T::H | T::L | T::N),
        EnvironmentalOrSupplemental {
            metric: ES::Msi | ES::Msa,
        } => matches!(token, T::X | T::S | T::H | T::L | T::N),
        EnvironmentalOrSupplemental { metric: ES::S } => {
            matches!(token, T::X | T::N | T::P)
        }
        EnvironmentalOrSupplemental { metric: ES::Au } => {
            matches!(token, T::X | T::N | T::Y)
        }
        EnvironmentalOrSupplemental { metric: ES::R } => {
            matches!(token, T::X | T::A | T::U | T::I)
        }
        EnvironmentalOrSupplemental { metric: ES::V } => {
            matches!(token, T::X | T::D | T::C)
        }
        EnvironmentalOrSupplemental { metric: ES::Re } => {
            matches!(token, T::X | T::L | T::M | T::H)
        }
        EnvironmentalOrSupplemental { metric: ES::U } => {
            matches!(token, T::X | T::Clear | T::Green | T::Amber | T::Red)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyEvidenceRef {
    PolicySelf,
    Endpoint { endpoint: EndpointRef },
    Selector { path: PolicySelectorPath },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicySelectorPath(Box<str>);

impl PolicySelectorPath {
    pub fn new(path: impl AsRef<str>) -> Result<Self, PolicySelectorPathError> {
        let path = path.as_ref();
        validate_selector_path(path)?;
        Ok(Self(path.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PolicySelectorPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for PolicySelectorPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for PolicySelectorPath {
    type Err = PolicySelectorPathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        Self::new(path)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySelectorPathError {
    Empty,
    MissingLeadingSlash,
    EmptySegment,
    InvalidEscape,
    ControlCharacter,
}

impl fmt::Display for PolicySelectorPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "policy selector path must not be empty",
            Self::MissingLeadingSlash => "policy selector path must begin with `/`",
            Self::EmptySegment => "policy selector path must not contain an empty segment",
            Self::InvalidEscape => {
                "policy selector path must use only JSON Pointer escapes `~0` and `~1`"
            }
            Self::ControlCharacter => "policy selector path must not contain control characters",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PolicySelectorPathError {}

fn validate_selector_path(path: &str) -> Result<(), PolicySelectorPathError> {
    if path.is_empty() {
        return Err(PolicySelectorPathError::Empty);
    }
    if !path.starts_with('/') {
        return Err(PolicySelectorPathError::MissingLeadingSlash);
    }
    for segment in path[1..].split('/') {
        if segment.is_empty() {
            return Err(PolicySelectorPathError::EmptySegment);
        }
        if segment.chars().any(char::is_control) {
            return Err(PolicySelectorPathError::ControlCharacter);
        }
        let mut bytes = segment.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
                return Err(PolicySelectorPathError::InvalidEscape);
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogRef {
    pub name: PolicyId,
    pub version: u32,
    pub sha256: Option<TaintCatalogHash>,
}

impl CatalogRef {
    pub fn new(
        name: PolicyId,
        version: u32,
        sha256: Option<TaintCatalogHash>,
    ) -> Result<Self, CatalogRefError> {
        if version == 0 {
            return Err(CatalogRefError::ZeroVersion);
        }
        Ok(Self {
            name,
            version,
            sha256,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogRefError {
    ZeroVersion,
}

impl fmt::Display for CatalogRefError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("catalog version must be at least 1")
    }
}

impl std::error::Error for CatalogRefError {}

macro_rules! define_sha256_value {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub fn from_lower_hex(value: &str) -> Result<Self, Sha256ValueError> {
                parse_lower_sha256(value).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl FromStr for $name {
            type Err = Sha256ValueError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::from_lower_hex(value)
            }
        }
    };
}

define_sha256_value!(TaintCatalogHash);
define_sha256_value!(MatchSetManifestHash);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha256ValueError {
    InvalidLength,
    Uppercase,
    InvalidCharacter { index: usize },
}

impl fmt::Display for Sha256ValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => formatter.write_str("SHA-256 value must contain 64 hex digits"),
            Self::Uppercase => formatter.write_str("SHA-256 value must use lowercase hex digits"),
            Self::InvalidCharacter { index } => {
                write!(
                    formatter,
                    "SHA-256 value has an invalid character at byte {index}"
                )
            }
        }
    }
}

impl std::error::Error for Sha256ValueError {}

pub(crate) fn parse_lower_sha256(value: &str) -> Result<[u8; 32], Sha256ValueError> {
    if value.len() != 64 {
        return Err(Sha256ValueError::InvalidLength);
    }
    let bytes = value.as_bytes();
    let mut digest = [0_u8; 32];
    let mut index = 0;
    while index < bytes.len() {
        digest[index / 2] = (lower_hex_nibble(bytes[index], index)? << 4)
            | lower_hex_nibble(bytes[index + 1], index + 1)?;
        index += 2;
    }
    Ok(digest)
}

fn lower_hex_nibble(byte: u8, index: usize) -> Result<u8, Sha256ValueError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Err(Sha256ValueError::Uppercase),
        _ => Err(Sha256ValueError::InvalidCharacter { index }),
    }
}

pub type PolicyIdentifierError = brokk_bifrost_analysis::analyzer::identifier::IdentifierError;

macro_rules! define_policy_identifier {
    ($name:ident, $max_bytes:expr, $allow_dot:expr) => {
        define_identifier! {
            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct $name {
                max_bytes: $max_bytes,
                allow_dot: $allow_dot,
                error: PolicyIdentifierError,
            }
        }
    };
}

define_policy_identifier!(PolicyId, 200, true);
define_policy_identifier!(EndpointId, 200, true);
define_policy_identifier!(PolicyCategoryId, 128, true);

define_policy_identifier!(TaintEntryId, 128, false);
define_policy_identifier!(FindingCombinationId, 128, false);
define_policy_identifier!(TaintLabel, 128, false);
define_policy_identifier!(TaintTag, 128, false);
define_policy_identifier!(TaintImpact, 128, false);
define_policy_identifier!(TypestateStateId, 128, false);
define_policy_identifier!(TypestateEventId, 128, false);
define_policy_identifier!(TypestateExpectationId, 128, false);
define_policy_identifier!(PolicyAssertId, 128, false);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_identifiers_enforce_the_two_public_grammars() {
        assert_eq!(
            PolicyId::new("bifrost.security.dynamic-eval")
                .unwrap()
                .as_str(),
            "bifrost.security.dynamic-eval"
        );
        assert!(PolicyId::new("Bifrost.security").is_err());
        assert!(PolicyId::new("bifrost.").is_err());
        assert!(TaintEntryId::new("dynamic.eval").is_err());
        assert!(TaintEntryId::new("dynamic-eval_2").is_ok());
    }

    #[test]
    fn sha256_values_accept_only_lowercase_wire_spelling() {
        let value = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let hash = MatchSetManifestHash::from_lower_hex(value).unwrap();
        assert_eq!(hash.to_string(), value);
        assert_eq!(
            MatchSetManifestHash::from_lower_hex(&value.to_ascii_uppercase()),
            Err(Sha256ValueError::Uppercase)
        );
    }

    #[test]
    fn cvss_metric_values_cover_base_and_context_only_tables() {
        assert!(
            CvssMetricValue::try_new(
                CvssMetric::Base {
                    metric: CvssBaseMetric::Av,
                },
                CvssMetricValueToken::N,
            )
            .is_ok()
        );
        assert!(
            CvssMetricValue::try_new(
                CvssMetric::Base {
                    metric: CvssBaseMetric::Av,
                },
                CvssMetricValueToken::X,
            )
            .is_err()
        );
        assert!(
            CvssMetricValue::try_new(
                CvssMetric::EnvironmentalOrSupplemental {
                    metric: CvssEnvironmentalOrSupplementalMetric::U,
                },
                CvssMetricValueToken::Amber,
            )
            .is_ok()
        );
    }

    #[test]
    fn cvss_metric_rules_keep_metric_value_and_scope_coherent() {
        let av_value = CvssMetricValue::try_new(
            CvssMetric::Base {
                metric: CvssBaseMetric::Av,
            },
            CvssMetricValueToken::N,
        )
        .unwrap();
        let predicate = CvssEvidencePredicate::AnalysisType {
            analysis_type: PolicyAnalysisType::Taint,
        };

        let valid = CvssMetricRule::try_new(
            CvssBaseMetric::Av,
            av_value,
            predicate.clone(),
            PolicyCvssBasis::PolicyAssertion,
            CvssEvidenceScope::System {
                system: CvssSystemScope::VulnerableSystem,
            },
            vec![PolicyEvidenceRef::PolicySelf],
            "Network input".to_string(),
            vec![],
        )
        .unwrap();
        assert_eq!(valid.metric(), CvssBaseMetric::Av);
        assert_eq!(valid.value(), av_value);

        assert!(matches!(
            CvssMetricRule::try_new(
                CvssBaseMetric::Ac,
                av_value,
                predicate.clone(),
                PolicyCvssBasis::PolicyAssertion,
                CvssEvidenceScope::System {
                    system: CvssSystemScope::VulnerableSystem,
                },
                vec![PolicyEvidenceRef::PolicySelf],
                "Mismatch".to_string(),
                vec![],
            ),
            Err(InvalidCvssMetricRule::ValueMetricMismatch { .. })
        ));
        assert!(matches!(
            CvssMetricRule::try_new(
                CvssBaseMetric::Av,
                av_value,
                predicate,
                PolicyCvssBasis::PolicyAssertion,
                CvssEvidenceScope::System {
                    system: CvssSystemScope::SubsequentSystem,
                },
                vec![PolicyEvidenceRef::PolicySelf],
                "Mismatch".to_string(),
                vec![],
            ),
            Err(InvalidCvssMetricRule::ScopeMismatch { .. })
        ));
    }

    #[test]
    fn cvss_metric_rule_constructor_enforces_public_schema_bounds() {
        let value = CvssMetricValue::try_new(
            CvssMetric::Base {
                metric: CvssBaseMetric::Av,
            },
            CvssMetricValueToken::N,
        )
        .unwrap();
        let scope = CvssEvidenceScope::System {
            system: CvssSystemScope::VulnerableSystem,
        };
        let leaf = || CvssEvidencePredicate::AnalysisType {
            analysis_type: PolicyAnalysisType::Taint,
        };
        let build = |when, evidence_refs, rationale, assumptions| {
            CvssMetricRule::try_new(
                CvssBaseMetric::Av,
                value,
                when,
                PolicyCvssBasis::PolicyAssertion,
                scope,
                evidence_refs,
                rationale,
                assumptions,
            )
        };

        assert!(matches!(
            build(leaf(), vec![], "reason".to_string(), vec![]),
            Err(InvalidCvssMetricRule::EmptyEvidenceReferences)
        ));
        assert!(matches!(
            build(
                leaf(),
                vec![PolicyEvidenceRef::PolicySelf; MAX_POLICY_SET_ITEMS + 1],
                "reason".to_string(),
                vec![],
            ),
            Err(InvalidCvssMetricRule::TooManyEvidenceReferences { .. })
        ));
        assert!(matches!(
            build(
                leaf(),
                vec![PolicyEvidenceRef::PolicySelf, PolicyEvidenceRef::PolicySelf,],
                "reason".to_string(),
                vec![],
            ),
            Err(InvalidCvssMetricRule::DuplicateEvidenceReference)
        ));
        assert!(matches!(
            build(
                leaf(),
                vec![PolicyEvidenceRef::PolicySelf],
                String::new(),
                vec![],
            ),
            Err(InvalidCvssMetricRule::EmptyRationale)
        ));
        assert!(matches!(
            build(
                leaf(),
                vec![PolicyEvidenceRef::PolicySelf],
                "x".repeat(MAX_POLICY_DISPLAY_TEXT_BYTES + 1),
                vec![],
            ),
            Err(InvalidCvssMetricRule::RationaleTooLong { .. })
        ));
        assert!(matches!(
            build(
                leaf(),
                vec![PolicyEvidenceRef::PolicySelf],
                "reason".to_string(),
                (0..=MAX_POLICY_SET_ITEMS)
                    .map(|index| format!("assumption-{index}"))
                    .collect(),
            ),
            Err(InvalidCvssMetricRule::TooManyAssumptions { .. })
        ));
        assert!(matches!(
            build(
                CvssEvidencePredicate::All { predicates: vec![] },
                vec![PolicyEvidenceRef::PolicySelf],
                "reason".to_string(),
                vec![],
            ),
            Err(InvalidCvssMetricRule::EmptyPredicateSet)
        ));

        let mut too_deep = leaf();
        for _ in 0..=MAX_POLICY_PREDICATE_DEPTH {
            too_deep = CvssEvidencePredicate::All {
                predicates: vec![too_deep],
            };
        }
        assert!(matches!(
            build(
                too_deep,
                vec![PolicyEvidenceRef::PolicySelf],
                "reason".to_string(),
                vec![],
            ),
            Err(InvalidCvssMetricRule::PredicateDepthLimit { .. })
        ));

        let predicates = (0..MAX_POLICY_PREDICATE_NODES)
            .map(|index| CvssEvidencePredicate::SourceCategories {
                quantifier: AnyOrAll::Any,
                values: vec![PolicyCategoryId::new(format!("category-{index}")).unwrap()],
            })
            .collect();
        assert!(matches!(
            build(
                CvssEvidencePredicate::All { predicates },
                vec![PolicyEvidenceRef::PolicySelf],
                "reason".to_string(),
                vec![],
            ),
            Err(InvalidCvssMetricRule::PredicateNodeLimit { .. })
        ));
    }

    #[test]
    fn cvss_metrics_and_values_expose_exact_first_labels() {
        let base_metrics = [
            CvssBaseMetric::Av,
            CvssBaseMetric::Ac,
            CvssBaseMetric::At,
            CvssBaseMetric::Pr,
            CvssBaseMetric::Ui,
            CvssBaseMetric::Vc,
            CvssBaseMetric::Vi,
            CvssBaseMetric::Va,
            CvssBaseMetric::Sc,
            CvssBaseMetric::Si,
            CvssBaseMetric::Sa,
        ];
        assert_eq!(
            base_metrics.map(CvssBaseMetric::first_label),
            [
                "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"
            ]
        );

        let contextual_metrics = [
            CvssEnvironmentalOrSupplementalMetric::Cr,
            CvssEnvironmentalOrSupplementalMetric::Ir,
            CvssEnvironmentalOrSupplementalMetric::Ar,
            CvssEnvironmentalOrSupplementalMetric::Mav,
            CvssEnvironmentalOrSupplementalMetric::Mac,
            CvssEnvironmentalOrSupplementalMetric::Mat,
            CvssEnvironmentalOrSupplementalMetric::Mpr,
            CvssEnvironmentalOrSupplementalMetric::Mui,
            CvssEnvironmentalOrSupplementalMetric::Mvc,
            CvssEnvironmentalOrSupplementalMetric::Mvi,
            CvssEnvironmentalOrSupplementalMetric::Mva,
            CvssEnvironmentalOrSupplementalMetric::Msc,
            CvssEnvironmentalOrSupplementalMetric::Msi,
            CvssEnvironmentalOrSupplementalMetric::Msa,
            CvssEnvironmentalOrSupplementalMetric::S,
            CvssEnvironmentalOrSupplementalMetric::Au,
            CvssEnvironmentalOrSupplementalMetric::R,
            CvssEnvironmentalOrSupplementalMetric::V,
            CvssEnvironmentalOrSupplementalMetric::Re,
            CvssEnvironmentalOrSupplementalMetric::U,
        ];
        assert_eq!(
            contextual_metrics.map(CvssEnvironmentalOrSupplementalMetric::first_label),
            [
                "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC",
                "MSI", "MSA", "S", "AU", "R", "V", "RE", "U",
            ]
        );

        assert_eq!(CvssThreatMetric::E.first_label(), "E");
        assert_eq!(CvssVersion::V4_0.wire_label(), "4.0");
        assert_eq!(CvssMetricValueToken::Clear.first_label(), "Clear");
    }

    #[test]
    fn selector_paths_use_canonical_json_pointer_escaping() {
        assert!(PolicySelectorPath::new("/analysis/selector").is_ok());
        assert!(PolicySelectorPath::new("analysis/selector").is_err());
        assert!(PolicySelectorPath::new("/analysis/~2selector").is_err());
        assert!(PolicySelectorPath::new("/analysis/~1selector").is_ok());
    }

    #[test]
    fn report_defaults_are_schema_fixed() {
        let options = PolicyReportOptions::default();
        assert_eq!(options.witness.max_steps, 64);
        assert_eq!(options.witness.max_bytes, 16 * 1024);
        assert_eq!(options.witnesses_per_finding, 8);
        assert_eq!(options.origins_per_finding, 8);
    }
}
