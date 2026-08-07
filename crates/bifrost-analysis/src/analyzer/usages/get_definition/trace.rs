//! The resolution trace: why a reference resolved the way it did (#1474,
//! Milestone 3).
//!
//! The definition resolver decides a reference by walking precedence tiers in
//! statement order and discarding every loser. This module turns that walk into
//! typed rows -- one [`TraceCandidate`] per candidate the resolver considered,
//! carrying the tier it was considered at, whether it was selected or rejected
//! and for which typed reason, how far the lookup could see, and the visibility
//! the declaration states.
//!
//! Three properties are load-bearing.
//!
//! - The trace is an *emission*, never a parallel model. Every row is recorded
//!   at a point where the resolver already computed the fact; nothing here
//!   re-derives a decision, and nothing here can change one. A resolver refactor
//!   therefore cannot silently diverge from the trace: the trace simply reports
//!   less.
//! - Recording is opt-in per batch and off by default. [`recording`] is a
//!   thread-local flag read before any row is built, so an untraced batch pays
//!   one relaxed load per outcome constructor and allocates nothing.
//! - Attribution is never invented. A tier is `None` when the seam that
//!   constructed the outcome cannot name the tier it selected at, rather than
//!   being guessed into a tier a policy would then compare against.
//!
//! Why a thread-local rather than a sink parameter: the three shared outcome
//! constructors this module instruments (`candidates_outcome`,
//! `lexical_definition_outcome` and the boundary gate) are free functions with
//! about three hundred call sites across fourteen per-language resolver modules
//! and the separate `get_type` family. Threading a sink through all of them
//! would put a tracing parameter into every language resolver's signature for a
//! feature none of them reason about. The recorder is installed by
//! [`TraceSession`] for the extent of one batch, drained per request, and
//! removed on drop, so its lifetime is exactly the batch that asked for it.

use super::{DefinitionLookupOutcome, DefinitionLookupStatus, resolve_definition_requests_traced};
use crate::analyzer::lexical_definitions::LexicalDefinition;
use crate::analyzer::structural::resolution::{
    BoundaryStatus, CandidateOutcome, DeclaredVisibility, HierarchyRelation, MemberDispatchTier,
    PrecedenceTier, RejectionReason,
};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::cancellation::CancellationToken;
use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;
use std::cell::RefCell;
use std::sync::Arc;

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
    /// only when `boundary` is [`BoundaryStatus::ExternalIndexed`].
    pub external_target: Option<String>,
    /// Member-selection attribution, present only when the seam that recorded
    /// the candidate is a member lookup that knows its owner and route.
    pub member: Option<Box<MemberEnrichment>>,
}

impl TraceCandidate {
    /// A workspace-local selected candidate with nothing further claimed.
    pub fn selected(candidate: TraceCandidateRef, tier: Option<PrecedenceTier>) -> Self {
        Self {
            candidate,
            tier,
            outcome: CandidateOutcome::Selected,
            boundary: BoundaryStatus::WorkspaceLocal,
            visibility: DeclaredVisibility::Unknown,
            external_target: None,
            member: None,
        }
    }

    /// A candidate the resolver computed and then discarded.
    pub fn rejected(
        candidate: TraceCandidateRef,
        tier: Option<PrecedenceTier>,
        reason: RejectionReason,
    ) -> Self {
        Self {
            candidate,
            tier,
            outcome: CandidateOutcome::Rejected(reason),
            boundary: BoundaryStatus::WorkspaceLocal,
            visibility: DeclaredVisibility::Unknown,
            external_target: None,
            member: None,
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

    pub fn is_selected(&self) -> bool {
        self.outcome.is_selected()
    }
}

/// How much of the candidate story a trace tells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TraceCompleteness {
    /// Only the selection axis is instrumented for this language: the selected
    /// candidates are recorded, and an absent rejection row says nothing.
    #[default]
    SelectionOnly,
    /// The language's resolver tiers report the candidates they discard, so a
    /// rejection row is present wherever a tier discarded a candidate it had
    /// computed.
    Full,
}

impl TraceCompleteness {
    pub const fn label(self) -> &'static str {
        match self {
            Self::SelectionOnly => "selection_only",
            Self::Full => "full",
        }
    }

    pub const fn covers_rejections(self) -> bool {
        matches!(self, Self::Full)
    }
}

/// Every candidate one reference's resolution considered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolutionTraceResult {
    pub candidates: Vec<TraceCandidate>,
    pub completeness: TraceCompleteness,
}

impl ResolutionTraceResult {
    pub fn selected(&self) -> impl Iterator<Item = &TraceCandidate> {
        self.candidates.iter().filter(|row| row.is_selected())
    }

    pub fn rejected(&self) -> impl Iterator<Item = &TraceCandidate> {
        self.candidates.iter().filter(|row| !row.is_selected())
    }

    /// Whether any selected row sits at `tier`.
    pub fn selects_at(&self, tier: PrecedenceTier) -> bool {
        self.selected().any(|row| row.tier == Some(tier))
    }
}

/// The consistency rule every seam that records a selection must satisfy: a
/// `Selected` row names something the outcome it accompanies actually reports.
///
/// This is checked at the construction point, where the rows and the outcome
/// are built together, rather than over an assembled request trace: a resolver
/// may resolve a receiver type through the same constructors on its way to the
/// answer, so a request-level trace legitimately contains selections that are
/// not the request's own answer, while a single constructor's emission never
/// can.
pub fn debug_assert_selection_agrees(rows: &[TraceCandidate], outcome: &DefinitionLookupOutcome) {
    if !cfg!(debug_assertions) {
        return;
    }
    for row in rows.iter().filter(|row| row.is_selected()) {
        match &row.candidate {
            TraceCandidateRef::Unit(unit) => debug_assert!(
                outcome.definitions.contains(unit),
                "trace selected {unit:?} which the outcome does not report: {:?}",
                outcome.definitions
            ),
            TraceCandidateRef::Lexical(definition) => debug_assert!(
                outcome.lexical_definition.as_ref() == Some(definition),
                "trace selected lexical {definition:?} which the outcome does not report: {:?}",
                outcome.lexical_definition
            ),
            TraceCandidateRef::Binding { .. } => debug_assert!(
                false,
                "an environment binding row is never a selection; the resolver's own \
                 lexical definition is"
            ),
            TraceCandidateRef::ImportBinder { .. } | TraceCandidateRef::ExternalRoute { .. } => {
                debug_assert!(
                    outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary,
                    "a route may only be selected at a boundary outcome, got {:?}",
                    outcome.status
                )
            }
        }
    }
}

/// A tier attribution a resolver tier has staged for the outcome constructor it
/// is about to reach.
///
/// The staged tier is consumed only by a constructor whose candidates intersect
/// the fully-qualified names the tier staged, so a tier staged for one lookup
/// can never be spent on an unrelated one further down the same request.
#[derive(Debug, Clone)]
struct PendingSelection {
    tier: PrecedenceTier,
    fq_names: Vec<String>,
}

/// Member attribution a member-lookup seam has staged for the outcome
/// constructor it is about to reach, keyed by the candidate's fully-qualified
/// name. Consumed under the same discipline as [`PendingSelection`]: only by a
/// constructor whose candidates the map names, and dropped otherwise.
#[derive(Debug, Clone, Default)]
struct PendingMemberContext {
    by_fq_name: Vec<(String, MemberEnrichment)>,
}

#[derive(Debug, Default)]
struct Recorder {
    candidates: Vec<TraceCandidate>,
    pending: Option<PendingSelection>,
    pending_member: Option<PendingMemberContext>,
    /// The reference name the currently instrumented deep path is resolving.
    /// Deep emission sites compare against it so that a nested lookup for a
    /// different name (a receiver type, an owner) cannot be attributed to this
    /// reference.
    deep_name: Option<String>,
}

thread_local! {
    static RECORDER: RefCell<Option<Recorder>> = const { RefCell::new(None) };
}

/// Whether a trace is being recorded on this thread. Every emission site reads
/// this first so an untraced resolution allocates nothing.
pub(crate) fn recording() -> bool {
    RECORDER.with(|recorder| recorder.borrow().is_some())
}

fn with_recorder<R>(action: impl FnOnce(&mut Recorder) -> R) -> Option<R> {
    RECORDER.with(|recorder| recorder.borrow_mut().as_mut().map(action))
}

/// Append one row. Callers guard with [`recording`] before building the row.
pub(crate) fn record(candidate: TraceCandidate) {
    with_recorder(|recorder| recorder.candidates.push(candidate));
}

pub(crate) fn record_all(rows: impl IntoIterator<Item = TraceCandidate>) {
    with_recorder(|recorder| recorder.candidates.extend(rows));
}

/// Stage `tier` for the next outcome constructor that reports one of
/// `fq_names`.
pub(crate) fn stage_tier(tier: PrecedenceTier, fq_names: Vec<String>) {
    with_recorder(|recorder| recorder.pending = Some(PendingSelection { tier, fq_names }));
}

/// Stage member attribution for the next outcome constructor whose candidates
/// the map names. Callers guard with [`recording`] before building the
/// entries, so an untraced lookup allocates nothing.
pub(crate) fn stage_member_context(by_fq_name: Vec<(String, MemberEnrichment)>) {
    with_recorder(|recorder| {
        recorder.pending_member = Some(PendingMemberContext { by_fq_name });
    });
}

/// The member attribution the walk that ran most recently staged, exactly as it
/// staged it.
///
/// This is a read-back of one walk's own record, never a reconstruction: a
/// language whose applicability filter runs *after* the member walk returned
/// (Scala) needs the walk's owner, depth and route to state a rejected row for
/// a candidate the walk attributed and the filter then discarded. The map is
/// the walk's record, so reading it there reports the same facts the winner's
/// row reports.
pub(crate) fn staged_member_context() -> Vec<(String, MemberEnrichment)> {
    with_recorder(|recorder| {
        recorder
            .pending_member
            .as_ref()
            .map(|pending| pending.by_fq_name.clone())
            .unwrap_or_default()
    })
    .unwrap_or_default()
}

/// Take the staged member attribution for `unit` if the staged map names it.
/// The whole map is dropped when the first consuming constructor's candidates
/// do not intersect it, mirroring [`take_tier_for`].
fn take_member_for(recorder: &mut Recorder, unit: &CodeUnit) -> Option<MemberEnrichment> {
    let pending = recorder.pending_member.as_ref()?;
    let fq = unit.fq_name();
    pending
        .by_fq_name
        .iter()
        .find(|(name, _)| *name == fq)
        .map(|(_, enrichment)| enrichment.clone())
}

/// Take the staged tier if it was staged for one of `units`. A staged tier that
/// does not match is dropped rather than reused: it belonged to a lookup that
/// did not become this outcome.
fn take_tier_for(units: &[CodeUnit]) -> Option<PrecedenceTier> {
    with_recorder(|recorder| {
        let pending = recorder.pending.take()?;
        units
            .iter()
            .any(|unit| pending.fq_names.contains(&unit.fq_name()))
            .then_some(pending.tier)
    })
    .flatten()
}

/// Mark the reference name a deep-traced resolver path is currently resolving,
/// restoring the previous name when the guard drops.
pub(crate) struct DeepScope {
    previous: Option<String>,
}

impl DeepScope {
    pub(crate) fn enter(name: &str) -> Self {
        let previous =
            with_recorder(|recorder| recorder.deep_name.replace(name.to_owned())).flatten();
        Self { previous }
    }
}

impl Drop for DeepScope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        with_recorder(|recorder| recorder.deep_name = previous);
    }
}

/// Whether the deep path currently being traced is resolving exactly `name`.
pub(crate) fn deep_scope_is(name: &str) -> bool {
    with_recorder(|recorder| recorder.deep_name.as_deref() == Some(name)).unwrap_or(false)
}

/// Install a recorder for the extent of one batch.
pub(super) struct TraceSession;

impl TraceSession {
    pub(super) fn install() -> Self {
        RECORDER.with(|recorder| *recorder.borrow_mut() = Some(Recorder::default()));
        Self
    }

    /// Drain the rows recorded for the request that just finished.
    pub(super) fn take_request(&self) -> Vec<TraceCandidate> {
        with_recorder(|recorder| {
            recorder.pending = None;
            recorder.pending_member = None;
            std::mem::take(&mut recorder.candidates)
        })
        .unwrap_or_default()
    }
}

impl Drop for TraceSession {
    fn drop(&mut self) {
        RECORDER.with(|recorder| *recorder.borrow_mut() = None);
    }
}

/// The rows the shared seam records for a selection of workspace declarations.
///
/// Ambiguity stays explicit: every reported definition becomes its own
/// `Selected` row, and the outcome's `Ambiguous` status is what says they are
/// peers rather than a single answer.
pub(super) fn record_selected_units(outcome: &DefinitionLookupOutcome) {
    if !recording() || outcome.definitions.is_empty() {
        return;
    }
    let tier = take_tier_for(&outcome.definitions);
    let rows: Vec<TraceCandidate> = with_recorder(|recorder| {
        let rows: Vec<TraceCandidate> = outcome
            .definitions
            .iter()
            .map(|unit| {
                let mut row = TraceCandidate::selected(TraceCandidateRef::Unit(unit.clone()), tier);
                if let Some(enrichment) = take_member_for(recorder, unit) {
                    row = row.with_member(enrichment);
                }
                row
            })
            .collect();
        // The staged member context belonged to this lookup whether or not it
        // matched; a stale map must never attribute a later, unrelated lookup.
        recorder.pending_member = None;
        rows
    })
    .unwrap_or_default();
    debug_assert_selection_agrees(&rows, outcome);
    record_all(rows);
}

/// The row the shared seam records for a lexical selection. The tier is not
/// staged and never guessed: a lexical binding *is* the strongest tier.
pub(super) fn record_selected_lexical(outcome: &DefinitionLookupOutcome) {
    if !recording() {
        return;
    }
    let Some(definition) = outcome.lexical_definition.as_ref() else {
        return;
    };
    let rows = vec![TraceCandidate::selected(
        TraceCandidateRef::Lexical(definition.clone()),
        Some(PrecedenceTier::LexicalBinding),
    )];
    debug_assert_selection_agrees(&rows, outcome);
    record_all(rows);
}

/// The row the boundary gate records when it draws a boundary: the reference
/// stopped at an external root, with nothing selected in the workspace.
///
/// The gate itself is handed formatted messages, not a reference name, so the
/// row is named from the deep scope when one is active and left empty
/// otherwise; [`finish_boundary`] fills an empty name from the outcome's own
/// resolved reference. The status starts at [`BoundaryStatus::ExternalUnknown`]
/// because the gate knows only that the lookup left the workspace, and
/// [`finish_boundary`] upgrades it where the analyzer holds evidence.
pub(super) fn record_boundary_gate() {
    if !recording() {
        return;
    }
    let name = with_recorder(|recorder| recorder.deep_name.clone())
        .flatten()
        .unwrap_or_default();
    record(external_route_row(name));
}

fn external_route_row(name: String) -> TraceCandidate {
    TraceCandidate::rejected(
        TraceCandidateRef::ExternalRoute { name },
        Some(PrecedenceTier::ExternalRoot),
        RejectionReason::BoundaryBlocked,
    )
    .with_boundary(BoundaryStatus::ExternalUnknown)
}

/// One definition batch, traced.
///
/// Returns one [`ResolutionTraceResult`] per request, in request order, beside
/// the outcomes the untraced entry point would have produced. Running the batch
/// with a recorder installed does not change a single resolver decision; the
/// outcomes are identical to those of
/// [`super::resolve_definition_batch_with_source_and_cancellation`].
pub fn resolve_definition_batch_with_trace(
    analyzer: &dyn IAnalyzer,
    requests: Vec<super::DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
    cancellation: &CancellationToken,
) -> Vec<(DefinitionLookupOutcome, ResolutionTraceResult)> {
    let completeness = trace_completeness_for(&file);
    let session = TraceSession::install();
    let mut context = super::DefinitionBatchContext::new(analyzer, requests.len() > 1);
    context.sources.insert(file.clone(), Ok(source));
    let mut per_request = Vec::with_capacity(requests.len());
    let outcomes = resolve_definition_requests_traced(
        analyzer,
        &mut context,
        requests,
        Some(cancellation),
        None,
        true,
        Some(&session),
        &mut per_request,
    );
    drop(session);

    outcomes
        .into_iter()
        .zip(
            per_request
                .into_iter()
                .chain(std::iter::repeat_with(Vec::new)),
        )
        .map(|(outcome, candidates)| {
            let mut trace = ResolutionTraceResult {
                candidates,
                completeness,
            };
            finish_boundary(analyzer, &file, &outcome, &mut trace);
            (outcome, trace)
        })
        .collect()
}

/// A language's trace completeness follows its adapter's declared support for
/// the rejection axis, so the claim a consumer reads is the same claim the
/// adapter table makes.
fn trace_completeness_for(file: &ProjectFile) -> TraceCompleteness {
    use crate::analyzer::common::language_for_file;
    use crate::analyzer::structural::resolution::EnvironmentAxis;
    use crate::analyzer::structural_spec_for;

    let instrumented = structural_spec_for(language_for_file(file)).is_some_and(|spec| {
        spec.lexical_environment_support()
            .is_supported(EnvironmentAxis::CandidateRejection)
    });
    if instrumented {
        TraceCompleteness::Full
    } else {
        TraceCompleteness::SelectionOnly
    }
}

/// Turn the gate's undifferentiated "outside the workspace" into the typed
/// distinction a policy needs: is the name unknown, or is it declared by a
/// dependency that nothing indexed?
///
/// Evidence, per language family:
///
/// - JVM: the external declaration index. A hit is [`BoundaryStatus::ExternalIndexed`]
///   and the candidate carries the resolved external type. A miss against an
///   index that produced truncation diagnostics is
///   [`BoundaryStatus::ExternalDeclaredUnindexed`]: the build declared artifacts
///   the producer could not finish reading, so the name may well be there.
/// - Python and JS/TS: the activated semantic-model overlay. A symbol of that
///   name is [`BoundaryStatus::ExternalIndexed`]. On an overlay miss, retained
///   dependency-discovery evidence (#1601): a name whose module the build
///   declares, or a miss against a truncated discovery, is
///   [`BoundaryStatus::ExternalDeclaredUnindexed`]. The trace never triggers
///   discovery; where none has run, nothing is retained.
///
/// Anything else stays [`BoundaryStatus::ExternalUnknown`]. This function never
/// changes an outcome; it only sharpens what the trace says about one.
fn finish_boundary(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    outcome: &DefinitionLookupOutcome,
    trace: &mut ResolutionTraceResult,
) {
    if outcome.status != DefinitionLookupStatus::UnresolvableImportBoundary {
        return;
    }
    let name = outcome.resolved_reference_target().unwrap_or_default();
    // Boundary sites that bypass the gate (`boundary_unchecked`, each of which
    // documents where its guard lives) record nothing, so the route row is
    // synthesized here from the outcome the site produced. Either way the trace
    // states the same fact: this reference left the workspace.
    if !trace
        .candidates
        .iter()
        .any(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
    {
        trace.candidates.push(external_route_row(name.to_owned()));
    }
    let (status, external_target) = boundary_evidence(analyzer, file, name);
    for row in &mut trace.candidates {
        if let TraceCandidateRef::ExternalRoute { name: route } = &mut row.candidate
            && route.is_empty()
        {
            route.push_str(name);
        }
        if row.boundary == BoundaryStatus::ExternalUnknown {
            row.boundary = status;
            row.external_target.clone_from(&external_target);
        }
    }
}

pub(in crate::analyzer::usages) fn boundary_evidence(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    name: &str,
) -> (BoundaryStatus, Option<String>) {
    use crate::analyzer::common::language_for_file;
    use crate::analyzer::{JavaAnalyzer, Language, resolve_analyzer};

    match language_for_file(file) {
        Language::Java => {
            let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
                return (BoundaryStatus::ExternalUnknown, None);
            };
            java.external_boundary_evidence(file, name)
        }
        language @ (Language::Python | Language::JavaScript | Language::TypeScript) => {
            let indexed = analyzer.semantic_model_overlay().and_then(|overlay| {
                overlay
                    .symbols_named(name)
                    .records
                    .first()
                    .map(|symbol| symbol.id.clone())
            });
            if let Some(id) = indexed {
                return (BoundaryStatus::ExternalIndexed, Some(id));
            }
            // Retained discovery evidence (#1601): the build declares the
            // module this reference routes through and nothing indexed it, or
            // discovery could not read everything the build declared, so the
            // name may well be there. Where no discovery has run, nothing is
            // retained and `ExternalUnknown` remains the honest answer.
            let declared = analyzer
                .dependency_discovery_evidence(language)
                .is_some_and(|evidence| {
                    use crate::analyzer::semantic_model::{
                        RetainedDiscoveryVerdict, retained_discovery_verdict,
                    };
                    matches!(
                        retained_discovery_verdict(Some(&evidence), name),
                        RetainedDiscoveryVerdict::Truncated | RetainedDiscoveryVerdict::Declared
                    ) || declared_import_route(analyzer, file, language, name, &evidence)
                });
            if declared {
                (BoundaryStatus::ExternalDeclaredUnindexed, None)
            } else {
                (BoundaryStatus::ExternalUnknown, None)
            }
        }
        Language::Go => {
            // Go's boundary evidence is the same pair the Python and JS/TS arm
            // reads, resolved through the shared Go package identity so a
            // trace, a definition, and a diagnostic classify one import path
            // identically. Import paths are slash-separated, so the declared
            // check walks them by segment rather than by dot.
            let overlay = analyzer.semantic_model_overlay();
            let packages =
                crate::analyzer::go::package_identity::GoOverlayPackages::new(overlay.as_deref());
            if let Some(symbol) = packages.unique_symbol(name) {
                return (BoundaryStatus::ExternalIndexed, Some(symbol.id.clone()));
            }
            let declared = analyzer
                .dependency_discovery_evidence(Language::Go)
                .is_some_and(|evidence| {
                    evidence.truncated() || evidence.declares_go_import_path(name)
                });
            if declared {
                (BoundaryStatus::ExternalDeclaredUnindexed, None)
            } else {
                (BoundaryStatus::ExternalUnknown, None)
            }
        }
        Language::Rust => {
            // Rust reads the same pair, resolved through the shared crate
            // identity so a trace, a definition, and a diagnostic classify one
            // crate path identically. A path is spelled with `::` and a pack
            // records it dotted, and a Cargo rename is published as an alias,
            // so the written spelling is the lookup key either way.
            let overlay = analyzer.semantic_model_overlay();
            let crates =
                crate::analyzer::rust::crate_identity::RustOverlayCrates::new(overlay.as_deref());
            if let Some(symbol) = crates.unique_symbol(name) {
                return (BoundaryStatus::ExternalIndexed, Some(symbol.id.clone()));
            }
            let declared = analyzer
                .dependency_discovery_evidence(Language::Rust)
                .is_some_and(|evidence| {
                    evidence.truncated() || evidence.declares_module_path(name)
                });
            if declared {
                (BoundaryStatus::ExternalDeclaredUnindexed, None)
            } else {
                (BoundaryStatus::ExternalUnknown, None)
            }
        }
        _ => (BoundaryStatus::ExternalUnknown, None),
    }
}

/// Whether the import that binds `name`'s leading segment in `file` routes
/// through a module the retained discovery evidence declares.
///
/// The routes come from the analyzer's structured import layers — Python's
/// parser-derived [`crate::analyzer::StructuredImportPath`] segments, and the
/// JS/TS usage index's per-file import binders — never from re-scanning
/// source text. JS/TS `ImportInfo` records no structured path (the same gap
/// as Java's, see #1600), which is why the two families read different
/// layers.
fn declared_import_route(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    language: crate::analyzer::Language,
    name: &str,
    evidence: &crate::analyzer::semantic_model::DependencyDiscoveryEvidence,
) -> bool {
    use crate::analyzer::Language;

    // `name` is the resolved reference site's rendered text; its leading
    // dotted segment is the local binder an import introduced.
    let Some(leading) = name.split('.').next().filter(|head| !head.is_empty()) else {
        return false;
    };
    match language {
        Language::Python => {
            let Some(provider) = analyzer.import_analysis_provider_for_file(file) else {
                return false;
            };
            provider.import_info_of(file).iter().any(|import| {
                let binds = import.is_wildcard || import.local_name() == Some(leading);
                binds
                    && import.path.as_ref().is_some_and(|path| {
                        evidence.declares_module_path(&path.render_segments("."))
                    })
            })
        }
        Language::JavaScript | Language::TypeScript => {
            let Some(index) =
                crate::analyzer::usages::js_ts_graph::cached_jsts_index(analyzer, language, None)
            else {
                return false;
            };
            index
                .import_bindings(file, leading)
                .any(|binding| evidence.declares_module_path(&binding.module_specifier))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::DeclarationKind;
    use crate::analyzer::Range;

    fn lexical(identifier: &str) -> LexicalDefinition {
        LexicalDefinition {
            identifier: identifier.to_owned(),
            kind: DeclarationKind::LocalVariable,
            name_range: Range {
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                end_line: 1,
            },
            declaration_range: Range {
                start_byte: 0,
                end_byte: 2,
                start_line: 1,
                end_line: 1,
            },
        }
    }

    fn empty_outcome() -> DefinitionLookupOutcome {
        DefinitionLookupOutcome {
            status: DefinitionLookupStatus::NoDefinition,
            reference: None,
            definitions: Vec::new(),
            lexical_definition: None,
            diagnostics: Vec::new(),
        }
    }

    /// The consistency rule is the one guard that a future emission site cannot
    /// route around: a `Selected` row must name something its outcome reports.
    #[test]
    #[should_panic(expected = "trace selected lexical")]
    fn a_selected_row_that_the_outcome_does_not_report_fails_at_the_construction_point() {
        let rows = vec![TraceCandidate::selected(
            TraceCandidateRef::Lexical(lexical("shadowed")),
            Some(PrecedenceTier::LexicalBinding),
        )];
        debug_assert_selection_agrees(&rows, &empty_outcome());
    }

    #[test]
    fn an_agreeing_selection_passes_the_same_check() {
        let definition = lexical("local");
        let mut outcome = empty_outcome();
        outcome.status = DefinitionLookupStatus::Resolved;
        outcome.lexical_definition = Some(definition.clone());
        let rows = vec![TraceCandidate::selected(
            TraceCandidateRef::Lexical(definition),
            Some(PrecedenceTier::LexicalBinding),
        )];
        debug_assert_selection_agrees(&rows, &outcome);
    }

    /// Nothing is recorded unless a session is installed, so an ordinary
    /// resolution cannot pay for a trace nobody asked for.
    #[test]
    fn emission_is_inert_without_a_session() {
        assert!(!recording());
        record(TraceCandidate::selected(
            TraceCandidateRef::Lexical(lexical("ignored")),
            None,
        ));
        stage_tier(PrecedenceTier::ExplicitImport, vec!["a.B".to_owned()]);
        assert!(!deep_scope_is("ignored"));
    }

    #[test]
    fn a_session_collects_rows_and_drains_them_per_request() {
        let session = TraceSession::install();
        assert!(recording());
        record(TraceCandidate::selected(
            TraceCandidateRef::Lexical(lexical("first")),
            Some(PrecedenceTier::LexicalBinding),
        ));
        assert_eq!(session.take_request().len(), 1);
        assert!(
            session.take_request().is_empty(),
            "draining a request must not leave rows behind for the next one"
        );
        drop(session);
        assert!(!recording());
    }

    #[test]
    fn a_deep_scope_restores_the_name_it_replaced() {
        let _session = TraceSession::install();
        let outer = DeepScope::enter("outer");
        assert!(deep_scope_is("outer"));
        {
            let _inner = DeepScope::enter("inner");
            assert!(deep_scope_is("inner"));
        }
        assert!(deep_scope_is("outer"));
        drop(outer);
        assert!(!deep_scope_is("outer"));
    }

    #[test]
    fn completeness_defaults_to_selection_only() {
        assert_eq!(
            TraceCompleteness::default(),
            TraceCompleteness::SelectionOnly
        );
        assert!(!TraceCompleteness::SelectionOnly.covers_rejections());
        assert!(TraceCompleteness::Full.covers_rejections());
    }
}
