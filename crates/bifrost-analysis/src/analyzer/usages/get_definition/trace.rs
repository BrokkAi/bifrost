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

use super::DefinitionLookupOutcome;
use super::DefinitionLookupStatus;
use super::resolve_definition_resolutions;

use crate::analyzer::QueryScope;

use crate::analyzer::structural::resolution::BoundaryStatus;
use crate::analyzer::structural::resolution::CandidateOutcome;
use crate::analyzer::structural::resolution::DeclaredVisibility;
use crate::analyzer::structural::resolution::HierarchyRelation;
use crate::analyzer::structural::resolution::MemberDispatchTier;
use crate::analyzer::structural::resolution::PrecedenceTier;
use crate::analyzer::structural::resolution::RejectionReason;

use crate::analyzer::usages::applicability::ApplicabilityOutcome;
use crate::analyzer::usages::applicability::CandidateApplicability;

use crate::analyzer::CodeUnit;
use crate::analyzer::IAnalyzer;
use crate::analyzer::ProjectFile;

use crate::cancellation::CancellationToken;

use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;

use std::cell::RefCell;

use std::sync::Arc;

#[cfg(any(test, feature = "test-support"))]
#[path = "../../../../../../test-support/declaration_facts_pack.rs"]
#[doc(hidden)]
pub mod declaration_facts_pack;

#[doc(hidden)]
pub fn hierarchy_route_from_predecessors<Key>(
    found_on: &Key,
    depth: usize,
    is_base: impl Fn(&Key, usize) -> bool,
    mut predecessor: impl FnMut(&Key) -> Option<(Key, HierarchyRelation)>,
    mut code_unit: impl FnMut(&Key) -> Option<CodeUnit>,
) -> Option<(Vec<HierarchyHopRecord>, bool)>
where
    Key: Clone + Eq,
{
    let mut reversed = Vec::with_capacity(depth);
    let mut current = found_on.clone();
    while !is_base(&current, reversed.len()) {
        let Some((parent, relation)) = predecessor(&current) else {
            break;
        };
        reversed.push((parent.clone(), current, relation));
        current = parent;
    }
    let reached_base = is_base(&current, reversed.len());
    reversed.reverse();
    let route = reversed
        .into_iter()
        .enumerate()
        .map(|(hop, (from, to, relation))| {
            Some(HierarchyHopRecord {
                hop,
                from: code_unit(&from)?,
                to: code_unit(&to)?,
                relation,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some((route, reached_base))
}

#[doc(hidden)]
pub fn member_enrichment(
    owner: CodeUnit,
    hierarchy_depth: usize,
    applicability: ApplicabilityVerdict,
    route: Vec<HierarchyHopRecord>,
) -> MemberEnrichment {
    let dispatch_tier = if hierarchy_depth == 0 {
        MemberDispatchTier::InherentOrDirect
    } else {
        MemberDispatchTier::InheritedOrPromoted
    };
    member_enrichment_with_tier(owner, hierarchy_depth, dispatch_tier, applicability, route)
}

#[doc(hidden)]
pub fn member_enrichment_with_tier(
    owner: CodeUnit,
    hierarchy_depth: usize,
    dispatch_tier: MemberDispatchTier,
    applicability: ApplicabilityVerdict,
    route: Vec<HierarchyHopRecord>,
) -> MemberEnrichment {
    MemberEnrichment {
        owner,
        hierarchy_depth,
        dispatch_tier,
        applicability,
        route,
    }
}

impl From<&CandidateApplicability> for CallableApplicabilityRecord {
    fn from(verdict: &CandidateApplicability) -> Self {
        Self {
            verdict: verdict.verdict,
            reason: verdict.reason,
        }
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
    /// The value domain the `resolution_candidate.trace_completeness` row
    /// field publishes (issue #2515).
    pub const LABELS: &'static [&'static str] = &["selection_only", "full"];

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
            TraceCandidateRef::Intrinsic { name } => debug_assert!(
                matches!(
                    outcome.status,
                    DefinitionLookupStatus::NoDefinition
                        | DefinitionLookupStatus::Ambiguous
                        | DefinitionLookupStatus::Incomplete
                ) && (outcome.status != DefinitionLookupStatus::NoDefinition
                    || outcome.resolved_reference_target() == Some(name.as_str()))
                    && outcome
                        .diagnostics
                        .iter()
                        .any(|diagnostic| diagnostic.kind == "intrinsic_type_reference"),
                "intrinsic selection must preserve its source-free identity: {outcome:?}",
            ),
            TraceCandidateRef::Modeled { symbol_id, .. } => debug_assert!(
                outcome
                    .modeled_definitions
                    .iter()
                    .any(|symbol| symbol.id == *symbol_id),
                "trace selected modeled {symbol_id:?} which the outcome does not report: {:?}",
                outcome.modeled_definitions
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

/// Callable-applicability attribution an applicability check has staged for the
/// outcome constructor it is about to reach (#1478), keyed by the candidate's
/// fully-qualified name. Consumed under the same discipline as
/// [`PendingMemberContext`].
#[derive(Debug, Clone, Default)]
struct PendingCallableContext {
    by_fq_name: Vec<(String, CallableApplicabilityRecord)>,
}

/// Rejection coverage is the conjunction of every native definition lookup
/// contributing to this request, including nested or unfinished lookups.
#[derive(Debug, Default)]
struct NativeTraceCoverage {
    begun: usize,
    projected: usize,
    uncovered: bool,
}

impl NativeTraceCoverage {
    fn completeness(self) -> TraceCompleteness {
        crate::profiling::note_with(|| format!("resolution::native_trace_coverage {self:?}"));
        if self.begun == self.projected && !self.uncovered {
            TraceCompleteness::Full
        } else {
            TraceCompleteness::SelectionOnly
        }
    }
}

#[derive(Debug, Default)]
struct Recorder {
    native_coverage: Option<NativeTraceCoverage>,
    candidates: Vec<TraceCandidate>,
    pending: Option<PendingSelection>,
    pending_member: Option<PendingMemberContext>,
    pending_callable: Option<PendingCallableContext>,
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
#[doc(hidden)]
pub fn recording() -> bool {
    RECORDER.with(|recorder| recorder.borrow().is_some())
}

fn with_recorder<R>(action: impl FnOnce(&mut Recorder) -> R) -> Option<R> {
    RECORDER.with(|recorder| recorder.borrow_mut().as_mut().map(action))
}

/// Native adapters opt into operation-local rejection evidence before resolving.
/// An unsupported, cancelled or unavailable operation cannot claim coverage.
pub(crate) fn begin_native_trace() {
    with_recorder(|recorder| {
        recorder
            .native_coverage
            .get_or_insert_with(NativeTraceCoverage::default)
            .begun += 1;
    });
}

pub(crate) fn native_rejection_projection_active() -> bool {
    with_recorder(|recorder| recorder.native_coverage.is_some()).unwrap_or(false)
}

pub(crate) fn record_native_rejection_coverage(covered: bool) {
    with_recorder(|recorder| {
        if let Some(coverage) = &mut recorder.native_coverage {
            assert!(
                coverage.projected < coverage.begun,
                "a native projection closes one begun native definition lookup"
            );
            coverage.projected += 1;
            coverage.uncovered |= !covered;
        }
    });
}

/// Append one row. Callers guard with [`recording`] before building the row.
#[doc(hidden)]
pub fn record(candidate: TraceCandidate) {
    record_all([candidate]);
}

pub(crate) fn record_all(rows: impl IntoIterator<Item = TraceCandidate>) {
    with_recorder(|recorder| recorder.candidates.extend(rows));
}

/// The current operation emits into its own tail of the request's recorder;
/// an equal candidate in an earlier nested lookup keeps its original tier.
pub(crate) fn native_projection_start() -> usize {
    with_recorder(|recorder| recorder.candidates.len()).unwrap_or(0)
}

/// Shared projection of one native operation. Preserve member and callable
/// enrichment, then attach the actual winning import tier to its selection.
pub(crate) fn record_native_provenance(
    outcome: &DefinitionLookupOutcome,
    start: usize,
    rows: Vec<TraceCandidate>,
    covered: bool,
) {
    if !native_rejection_projection_active() {
        return;
    }
    debug_assert_selection_agrees(&rows, outcome);
    with_recorder(|recorder| {
        assert!(
            start <= recorder.candidates.len(),
            "native projection retains its emission boundary"
        );
        for row in rows {
            if let Some(existing) = recorder.candidates[start..]
                .iter_mut()
                .rev()
                .find(|existing| {
                    existing.candidate == row.candidate && existing.outcome == row.outcome
                })
            {
                if existing.tier.is_none()
                    || matches!(
                        row.tier,
                        Some(
                            PrecedenceTier::ExplicitImport
                                | PrecedenceTier::WildcardImport
                                | PrecedenceTier::DefaultImport
                                | PrecedenceTier::OtherCompilationUnitPackage
                        )
                    )
                {
                    existing.tier = row.tier;
                }
            } else if row.is_selected() {
                recorder.candidates.push(row);
            } else {
                // Existing member and callable seams emit rejections before
                // the selection constructor; keep that same shared order.
                let insertion = recorder.candidates[start..]
                    .iter()
                    .position(TraceCandidate::is_selected)
                    .map_or(recorder.candidates.len(), |offset| start + offset);
                recorder.candidates.insert(insertion, row);
            }
        }
    });
    record_native_rejection_coverage(covered);
}

/// Enrich the candidate rows already emitted by one native operation.
/// Missing selected properties retain Unknown, including lexical bindings.
pub(crate) fn record_native_declared_visibilities(rows: &[(CodeUnit, DeclaredVisibility)]) {
    with_recorder(|recorder| {
        for candidate in &mut recorder.candidates {
            if let TraceCandidateRef::Unit(unit) = &candidate.candidate
                && let Some((_, visibility)) = rows.iter().find(|(target, _)| target == unit)
            {
                candidate.visibility = *visibility;
            }
        }
    });
}

/// Stage `tier` for the next outcome constructor that reports one of
/// `fq_names`.
#[doc(hidden)]
pub fn stage_tier(tier: PrecedenceTier, fq_names: Vec<String>) {
    with_recorder(|recorder| recorder.pending = Some(PendingSelection { tier, fq_names }));
}

/// Stage the least precedence tier among the candidates a member walk returned.
/// The candidate tiers come from the walk itself; names include every returned
/// candidate, even when the walk could not attribute one to a tier.
#[doc(hidden)]
pub fn stage_winner_tier(winners: &[CodeUnit], tiers: impl IntoIterator<Item = PrecedenceTier>) {
    if let Some(tier) = tiers.into_iter().min() {
        stage_tier(tier, winners.iter().map(CodeUnit::fq_name).collect());
    }
}

/// Stage the member and callable facts for a selection. The walk supplies its
/// own enrichment function; an absent callable verdict stays unknown on the
/// member axis and absent on the callable axis.
#[doc(hidden)]
pub fn stage_applicability_context(
    winners: &[CodeUnit],
    applicability: &ApplicabilityOutcome,
    enrichment: impl Fn(&CodeUnit, ApplicabilityVerdict) -> Option<MemberEnrichment>,
) {
    let verdict_of = |unit: &CodeUnit| {
        applicability
            .verdicts
            .iter()
            .find(|verdict| verdict.candidate == *unit)
    };
    stage_member_context(
        winners
            .iter()
            .filter_map(|unit| {
                let verdict = verdict_of(unit)
                    .map(|verdict| verdict.verdict)
                    .unwrap_or(ApplicabilityVerdict::Unknown);
                enrichment(unit, verdict).map(|member| (unit.fq_name(), member))
            })
            .collect(),
    );
    stage_callable_context(
        winners
            .iter()
            .filter_map(|unit| {
                verdict_of(unit)
                    .map(CallableApplicabilityRecord::from)
                    .map(|callable| (unit.fq_name(), callable))
            })
            .collect(),
    );
}

/// Record a rejected workspace candidate with the attribution the resolver
/// already knows at this discard point.
#[doc(hidden)]
pub fn record_rejected_unit(
    candidate: &CodeUnit,
    tier: Option<PrecedenceTier>,
    reason: RejectionReason,
    callable: Option<CallableApplicabilityRecord>,
    member: Option<MemberEnrichment>,
) {
    let mut row =
        TraceCandidate::rejected(TraceCandidateRef::Unit(candidate.clone()), tier, reason);
    if let Some(callable) = callable {
        row = row.with_callable(callable);
    }
    if let Some(member) = member {
        row = row.with_member(member);
    }
    record(row);
}

/// Stage member attribution for the next outcome constructor whose candidates
/// the map names. Callers guard with [`recording`] before building the
/// entries, so an untraced lookup allocates nothing.
#[doc(hidden)]
pub fn stage_member_context(by_fq_name: Vec<(String, MemberEnrichment)>) {
    with_recorder(|recorder| {
        recorder.pending_member = Some(PendingMemberContext { by_fq_name });
    });
}

/// Stage callable-applicability attribution for the next outcome constructor
/// whose candidates the map names (#1478). Callers guard with [`recording`]
/// before building the entries.
#[doc(hidden)]
pub fn stage_callable_context(by_fq_name: Vec<(String, CallableApplicabilityRecord)>) {
    with_recorder(|recorder| {
        recorder.pending_callable = Some(PendingCallableContext { by_fq_name });
    });
}

/// Take the staged callable attribution for `unit` if the staged map names it.
fn take_callable_for(
    recorder: &mut Recorder,
    unit: &CodeUnit,
) -> Option<CallableApplicabilityRecord> {
    let pending = recorder.pending_callable.as_ref()?;
    let fq = unit.fq_name();
    pending
        .by_fq_name
        .iter()
        .find(|(name, _)| *name == fq)
        .map(|(_, record)| *record)
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
pub(crate) struct TraceSession;

impl TraceSession {
    pub(crate) fn install() -> Self {
        RECORDER.with(|recorder| *recorder.borrow_mut() = Some(Recorder::default()));
        Self
    }

    /// Drain the rows recorded for the request that just finished.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn take_request(&self) -> Vec<TraceCandidate> {
        self.take_request_trace().0
    }

    pub(crate) fn take_request_trace(&self) -> (Vec<TraceCandidate>, Option<TraceCompleteness>) {
        with_recorder(|recorder| {
            recorder.pending = None;
            recorder.pending_member = None;
            recorder.pending_callable = None;
            (
                std::mem::take(&mut recorder.candidates),
                recorder
                    .native_coverage
                    .take()
                    .map(NativeTraceCoverage::completeness),
            )
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
#[doc(hidden)]
pub fn record_selected_units(outcome: &DefinitionLookupOutcome) {
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
                if let Some(record) = take_callable_for(recorder, unit) {
                    row = row.with_callable(record);
                }
                row
            })
            .collect();
        // The staged member context belonged to this lookup whether or not it
        // matched; a stale map must never attribute a later, unrelated lookup.
        recorder.pending_member = None;
        recorder.pending_callable = None;
        rows
    })
    .unwrap_or_default();
    debug_assert_selection_agrees(&rows, outcome);
    record_all(rows);
}

/// Preserve the explicit model declaration identity selected by the resolver.
#[doc(hidden)]
pub fn record_selected_modeled(outcome: &DefinitionLookupOutcome) {
    if !recording() {
        return;
    }
    let rows = outcome
        .modeled_definitions
        .iter()
        .map(|symbol| {
            TraceCandidate::selected(
                TraceCandidateRef::Modeled {
                    symbol_id: symbol.id.clone(),
                    name: symbol.qualified_name.clone(),
                },
                None,
            )
        })
        .collect::<Vec<_>>();
    debug_assert_selection_agrees(&rows, outcome);
    record_all(rows);
}

/// The row the shared seam records for a lexical selection. The tier is not
/// staged and never guessed: a lexical binding *is* the strongest tier.
#[doc(hidden)]
pub fn record_selected_lexical(outcome: &DefinitionLookupOutcome) {
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
/// [`finish_boundary`] upgrades it where the analyzer holds evidence. The row
/// starts rejected for the same reason: the gate has found nothing to resolve
/// to yet, and [`finish_boundary`] turns it into a selection where the evidence
/// names an exact external declaration.
pub(super) fn record_boundary_gate() {
    if !recording() {
        return;
    }
    let name = with_recorder(|recorder| recorder.deep_name.clone())
        .flatten()
        .unwrap_or_default();
    record(external_route_row(name));
}

#[doc(hidden)]
pub fn record_named_boundary(name: String) {
    if recording() {
        record(external_route_row(name));
    }
}

/// Record a boundary whose structured resolver already identified the exact
/// external declaration-model target. The target is carried by the trace row
/// instead of being reconstructed from the written reference later.
#[doc(hidden)]
pub fn record_named_boundary_with_target(name: String, target: String) {
    if !recording() {
        return;
    }
    let mut row = external_route_row(name);
    row.boundary = BoundaryStatus::ExternalIndexed;
    row.external_target = Some(target);
    row.outcome = CandidateOutcome::Selected;
    record(row);
}

/// Record a boundary whose structured resolver proved that the activated
/// packs publish the reference's owner but not the reference itself.
///
/// This is deliberately not [`record_named_boundary_with_target`]: there is no
/// target. The owner is published, its whole inherited surface is published
/// with no gap, and the member is not on it, so the resolver found the answer
/// "not there" rather than a declaration. The row therefore stays rejected and
/// names no external target, and [`finish_boundary`] leaves the status alone
/// because it is no longer [`BoundaryStatus::ExternalUnknown`].
#[doc(hidden)]
pub fn record_named_boundary_declared_unindexed(name: String) {
    if !recording() {
        return;
    }
    let mut row = external_route_row(name);
    row.boundary = BoundaryStatus::ExternalDeclaredUnindexed;
    record(row);
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
    let scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let mut context = super::DefinitionBatchContext::new(analyzer, scope.token());
    context.sources.insert(file.clone(), Ok(source));
    let mut per_request = Vec::with_capacity(requests.len());
    let resolutions = resolve_definition_resolutions(
        analyzer,
        token,
        &mut context,
        requests,
        Some(cancellation),
        None,
        Some(&session),
        &mut per_request,
    );
    drop(session);

    resolutions
        .into_iter()
        .map(|resolution| resolution.outcome)
        .zip(
            per_request
                .into_iter()
                .chain(std::iter::repeat_with(|| (Vec::new(), None))),
        )
        .map(|(outcome, (candidates, native_completeness))| {
            let mut trace = ResolutionTraceResult {
                candidates,
                completeness: native_completeness.unwrap_or(completeness),
            };
            finish_declared_visibility(analyzer, &mut trace);
            finish_boundary(analyzer, &file, &outcome, &mut trace);
            // An instrumented producer's proved external boundary exhausts the
            // local lookup and records its terminal route. Row shape alone does
            // not prove rejection coverage for an uninstrumented producer.
            // The dependency remains unindexed/unknown on that row; Full trace
            // coverage does not turn it into a clean pass.
            if native_completeness.is_some()
                && completeness.covers_rejections()
                && outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary
                && !trace.candidates.is_empty()
                && trace.candidates.iter().all(|row| {
                    matches!(&row.candidate, TraceCandidateRef::ExternalRoute { name } if !name.is_empty())
                        && matches!(row.outcome,
                            CandidateOutcome::Selected
                                | CandidateOutcome::Rejected(RejectionReason::BoundaryBlocked))
                })
            {
                trace.completeness = TraceCompleteness::Full;
            }
            (outcome, trace)
        })
        .collect()
}

/// Read the selected declaration's existing metadata projection. Its visibility
/// cell is backed by the same canonical source property as native selected rows.
/// Keep already-published selected facts and leave absent/conflicting rows unknown;
/// no language rule or rendered declaration spelling supplies this column.
fn finish_declared_visibility(analyzer: &dyn IAnalyzer, trace: &mut ResolutionTraceResult) {
    for candidate in &mut trace.candidates {
        if candidate.visibility != DeclaredVisibility::Unknown {
            continue;
        }
        let TraceCandidateRef::Unit(unit) = &candidate.candidate else {
            continue;
        };
        let metadata = analyzer.signature_metadata(unit);
        let Some(visibility) = metadata
            .first()
            .and_then(|row| row.callable_declared_visibility())
        else {
            continue;
        };
        if visibility != DeclaredVisibility::Unknown
            && metadata
                .iter()
                .all(|row| row.callable_declared_visibility() == Some(visibility))
        {
            candidate.visibility = visibility;
        }
    }
}

/// A language's trace completeness follows its adapter's declared support for
/// the rejection axis, so the claim a consumer reads is the same claim the
/// adapter table makes.
fn trace_completeness_for(file: &ProjectFile) -> TraceCompleteness {
    use crate::analyzer::common::language_for_file;
    use crate::analyzer::structural::resolution::EnvironmentAxis;
    use crate::analyzer::structural_spec_for;

    // The native Rust adapter projects selected bindings, but does not record
    // the rejected paths of the selected operation. The structural adapter's
    // legacy rejection capability is not evidence for this route.
    if language_for_file(file) == crate::analyzer::Language::Rust {
        return TraceCompleteness::SelectionOnly;
    }

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
/// Evidence, per language family (#1870):
///
/// - JVM (Java, Kotlin, Scala): the shared external declaration index, walked
///   through each language's own import ladder. A hit is
///   [`BoundaryStatus::ExternalIndexed`] and the candidate carries the
///   resolved external type. A miss against an index that produced truncation
///   diagnostics is [`BoundaryStatus::ExternalDeclaredUnindexed`]: the build
///   declared artifacts the producer could not finish reading, so the name may
///   well be there.
/// - C#: the assembly declaration index, resolved with the file's namespace,
///   usings and aliases; an index that could not read everything the build
///   declared refines a miss the same way the JVM one does.
/// - Python and JS/TS: the activated semantic-model overlay. A symbol of that
///   name is [`BoundaryStatus::ExternalIndexed`]. On an overlay miss, retained
///   dependency-discovery evidence (#1601): a name whose module the build
///   declares, or a miss against a truncated discovery, is
///   [`BoundaryStatus::ExternalDeclaredUnindexed`]. The trace never triggers
///   discovery; where none has run, nothing is retained.
/// - Go and Rust: the same overlay-plus-evidence pair, resolved through the
///   shared package/crate identity helpers.
/// - Ruby: the activated overlay read through `ruby::constant_identity`, plus
///   retained gem-discovery evidence.
/// - PHP: the activated overlay's postings for the written segment, plus
///   retained Composer evidence.
///
/// Every index-backed family also falls back to retained discovery evidence
/// when its index answers nothing, so a declared dependency that discovery
/// could not read to the end never collapses into "nothing is known".
///
/// C++ uses literal angle includes, compile-context agreement, and activated
/// header-pack facts. It does not infer implicit compiler include roots.
/// This function never changes an outcome; it only sharpens what the trace
/// says about one.
fn finish_boundary(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    outcome: &DefinitionLookupOutcome,
    trace: &mut ResolutionTraceResult,
) {
    if outcome.status != DefinitionLookupStatus::UnresolvableImportBoundary {
        return;
    }
    let name = trace
        .candidates
        .iter()
        .find_map(|row| match &row.candidate {
            TraceCandidateRef::ExternalRoute { name } if !name.is_empty() => Some(name.as_str()),
            _ => None,
        })
        .unwrap_or_else(|| outcome.resolved_reference_target().unwrap_or_default())
        .to_owned();
    // Boundary sites that bypass the gate (`boundary_unchecked`, each of which
    // documents where its guard lives) record nothing, so the route row is
    // synthesized here from the outcome the site produced. Either way the trace
    // states the same fact: this reference left the workspace.
    if !trace
        .candidates
        .iter()
        .any(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
    {
        trace.candidates.push(external_route_row(name.clone()));
    }
    let (status, external_target) = boundary_evidence(analyzer, file, &name);
    for row in &mut trace.candidates {
        if let TraceCandidateRef::ExternalRoute { name: route } = &mut row.candidate
            && route.is_empty()
        {
            route.push_str(&name);
        }
        if row.boundary == BoundaryStatus::ExternalUnknown {
            row.boundary = status;
            row.external_target.clone_from(&external_target);
        }
        // An external route that named an exact external declaration is the
        // answer this reference resolved to. The resolver cannot return a
        // workspace `CodeUnit` for a declaration that is not in the workspace,
        // and `external_target` is what it resolved instead, so recording the
        // row as a rejection would say the resolver discarded the only answer
        // it found. `debug_assert_selection_agrees` already admits exactly this
        // selection: a route may be selected at a boundary outcome.
        //
        // A route with no named target stays rejected, because nothing was
        // decided: either no index and no activated pack spells the name, or
        // more than one does and the reference is ambiguous.
        if matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. })
            && row.boundary == BoundaryStatus::ExternalIndexed
            && row.external_target.is_some()
        {
            row.outcome = CandidateOutcome::Selected;
        }
    }
}

pub fn boundary_evidence(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    name: &str,
) -> (BoundaryStatus, Option<String>) {
    boundary_evidence_for(analyzer, file, name, BoundaryEvidenceUse::Reference)
}

/// Resolve the boundary for a call target. Java's implicit `java.lang` root
/// supplies types, not unqualified methods, so it cannot make a bare unknown
/// callee a declared-but-unindexed target.
pub(crate) fn call_target_boundary_evidence(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    name: &str,
) -> (BoundaryStatus, Option<String>) {
    let evidence = boundary_evidence_for(analyzer, file, name, BoundaryEvidenceUse::CallTarget);
    if crate::analyzer::common::language_for_file(file) == crate::analyzer::Language::Java
        && evidence.0 == BoundaryStatus::ExternalDeclaredUnindexed
        && !analyzer
            .dependency_discovery_evidence(crate::analyzer::Language::Java)
            .as_deref()
            .is_some_and(|discovery| {
                declared_by_retained_discovery(analyzer, crate::analyzer::Language::Java, name)
                    || declared_jvm_import_or_implicit_root(
                        analyzer,
                        file,
                        crate::analyzer::Language::Java,
                        name,
                        discovery,
                        false,
                    )
            })
    {
        // The Java external index can report an unavailable inventory without
        // any build or import evidence that this call reaches it. Keep that
        // unmodeled receiver open; index diagnostics alone do not declare an
        // arbitrary method name.
        return (BoundaryStatus::ExternalUnknown, None);
    }
    evidence
}

#[derive(Clone, Copy)]
enum BoundaryEvidenceUse {
    Reference,
    CallTarget,
}

fn boundary_evidence_for(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    name: &str,
    usage: BoundaryEvidenceUse,
) -> (BoundaryStatus, Option<String>) {
    let scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    use crate::analyzer::Language;
    use crate::analyzer::common::language_for_file;
    use crate::analyzer::semantic_model::SemanticModelSymbolKind;

    match language_for_file(file) {
        language @ (Language::Java | Language::Kotlin | Language::Scala | Language::CSharp) => {
            // Each language resolves the spelling through its own import
            // ladder against its retained external declaration index (the
            // shared JVM jar index for the JVM family, the assembly index for
            // C#). When the index answers nothing -- built cleanly, name not
            // there -- retained discovery evidence still distinguishes "the
            // build declares dependencies discovery could not read to the end"
            // from "nothing is known".
            // The activated packs are the *dispatching* analyzer's, never a
            // language delegate's own: activation publishes onto the analyzer a
            // host asked, which in a mixed JVM workspace is the `MultiAnalyzer`.
            // This is the same reason `collect_java_semantic_diagnostics` takes
            // its `JvmOverlayModel` as a parameter (#1893).
            let evidence =
                crate::analyzer::languages::language_support(language).and_then(|support| {
                    support.definition_boundary_evidence(analyzer, token, file, name)
                });
            match evidence {
                Some((BoundaryStatus::ExternalUnknown, target)) => {
                    let discovery = analyzer.dependency_discovery_evidence(language);
                    if declared_by_retained_discovery(analyzer, language, name)
                        || discovery.as_deref().is_some_and(|evidence| {
                            declared_jvm_import_or_implicit_root(
                                analyzer,
                                file,
                                language,
                                name,
                                evidence,
                                !matches!(usage, BoundaryEvidenceUse::CallTarget)
                                    || language != Language::Java,
                            )
                        })
                    {
                        (BoundaryStatus::ExternalDeclaredUnindexed, None)
                    } else {
                        (BoundaryStatus::ExternalUnknown, target)
                    }
                }
                Some(refined) => refined,
                None => (BoundaryStatus::ExternalUnknown, None),
            }
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
            let evidence = analyzer.dependency_discovery_evidence(language);
            let declared = crate::analyzer::semantic_model::retained_evidence_declares(
                evidence.as_deref(),
                name,
            ) || evidence.is_some_and(|evidence| {
                declared_import_route(analyzer, file, language, name, &evidence)
            });
            if declared {
                (BoundaryStatus::ExternalDeclaredUnindexed, None)
            } else {
                (BoundaryStatus::ExternalUnknown, None)
            }
        }

        Language::Php => {
            // PHP spells qualified names with `\`, which the reference-site
            // scanner does not span, so the trace holds a single written
            // segment. The overlay posts each symbol under its terminal name
            // as well as its dotted qualified name, so the lookup matches the
            // Python arm's strength; filtering to PHP symbols keeps another
            // ecosystem's posting from answering, and a namespace scaffold is
            // not a type a reference can name.
            let indexed = analyzer.semantic_model_overlay().and_then(|overlay| {
                overlay
                    .symbols_named(name)
                    .records
                    .iter()
                    .find(|symbol| {
                        symbol.language == "php" && symbol.kind != SemanticModelSymbolKind::Module
                    })
                    .map(|symbol| symbol.id.clone())
            });
            if let Some(id) = indexed {
                return (BoundaryStatus::ExternalIndexed, Some(id));
            }
            // Composer discovery declares dotted PSR-4 prefixes; a single
            // written segment reaches them only as an exact identity, so the
            // declared refinement here is truncation plus exact matches. PHP
            // records no structured per-file import layer yet (the ImportInfo
            // gap #1600 shares), so there is no route to walk.
            if declared_by_retained_discovery(analyzer, Language::Php, name) {
                (BoundaryStatus::ExternalDeclaredUnindexed, None)
            } else {
                (BoundaryStatus::ExternalUnknown, None)
            }
        }
        Language::Go | Language::Rust | Language::Ruby | Language::Cpp => {
            crate::analyzer::languages::language_support(language_for_file(file))
                .and_then(|support| {
                    support.definition_boundary_evidence(analyzer, token, file, name)
                })
                .unwrap_or((BoundaryStatus::ExternalUnknown, None))
        }
        Language::None => (BoundaryStatus::ExternalUnknown, None),
    }
}

pub use crate::analyzer::semantic::trace::DispatchQuality;

/// The total mapping from a definition lookup's status and, at a boundary
/// outcome, its refined [`BoundaryStatus`], to the [`DispatchQuality`] that
/// status alone supports. This is the single source of truth both
/// `workspace_oracle::dispatch` (which additionally merges in
/// materialization-time quality and an ambiguity-preservation rule of its
/// own) and the external-reference probe read, so a resolver status can never
/// map to one quality in the semantic oracle and a different one in the
/// audit.
///
/// `status` is `None` for a lookup that named no status at all (for example
/// because the site was never checked); `boundary` is only consulted for
/// [`DefinitionLookupStatus::UnresolvableImportBoundary`], and its absence
/// there is as unproven as [`BoundaryStatus::ExternalUnknown`].
pub fn dispatch_quality_for_status(
    status: Option<DefinitionLookupStatus>,
    boundary: Option<BoundaryStatus>,
) -> DispatchQuality {
    match status {
        Some(DefinitionLookupStatus::Resolved) => DispatchQuality::Complete,
        Some(DefinitionLookupStatus::Ambiguous) => DispatchQuality::Ambiguous,
        Some(DefinitionLookupStatus::UnsupportedLanguage) => {
            DispatchQuality::Unsupported(crate::analyzer::semantic::SemanticCapability::Calls)
        }
        Some(
            DefinitionLookupStatus::NoDefinition
            | DefinitionLookupStatus::Unavailable
            | DefinitionLookupStatus::InvalidLocation
            | DefinitionLookupStatus::NotFound,
        )
        | None => DispatchQuality::Unknown,
        Some(DefinitionLookupStatus::Incomplete | DefinitionLookupStatus::ExceededBudget(_)) => {
            DispatchQuality::Truncated
        }
        Some(DefinitionLookupStatus::Cancelled) => DispatchQuality::Cancelled,
        // A boundary outcome is complete only when the refined evidence
        // (#1474) actually names the external target. A declared-but-
        // unindexed dependency leaves the answer partial, and an unknown
        // external root means the resolver never saw the target at all.
        Some(DefinitionLookupStatus::UnresolvableImportBoundary) => match boundary {
            Some(BoundaryStatus::WorkspaceLocal | BoundaryStatus::ExternalIndexed) => {
                DispatchQuality::Complete
            }
            Some(BoundaryStatus::ExternalDeclaredUnindexed) => DispatchQuality::Unproven,
            Some(BoundaryStatus::ExternalUnknown) | None => DispatchQuality::Unknown,
        },
    }
}

#[cfg(test)]
mod dispatch_quality_tests {
    use super::*;

    /// Pins the full status/boundary -> quality table so the shared mapping
    /// (read by both `workspace_oracle::dispatch` and the external-reference
    /// probe, #1885) cannot drift silently in either direction.
    #[test]
    fn dispatch_quality_for_status_covers_every_arm() {
        use crate::analyzer::semantic::SemanticCapability;

        assert_eq!(
            dispatch_quality_for_status(Some(DefinitionLookupStatus::Resolved), None),
            DispatchQuality::Complete
        );
        assert_eq!(
            dispatch_quality_for_status(Some(DefinitionLookupStatus::Ambiguous), None),
            DispatchQuality::Ambiguous
        );
        assert_eq!(
            dispatch_quality_for_status(Some(DefinitionLookupStatus::UnsupportedLanguage), None),
            DispatchQuality::Unsupported(SemanticCapability::Calls)
        );
        for status in [
            DefinitionLookupStatus::NoDefinition,
            DefinitionLookupStatus::InvalidLocation,
            DefinitionLookupStatus::NotFound,
        ] {
            assert_eq!(
                dispatch_quality_for_status(Some(status), None),
                DispatchQuality::Unknown
            );
        }
        assert_eq!(
            dispatch_quality_for_status(Some(DefinitionLookupStatus::Incomplete), None),
            DispatchQuality::Truncated
        );
        assert_eq!(
            dispatch_quality_for_status(
                Some(DefinitionLookupStatus::ExceededBudget(
                    crate::analyzer::usages::receiver_analysis::ReceiverBudgetLimit::ScopeNodes,
                )),
                None,
            ),
            DispatchQuality::Truncated
        );
        assert_eq!(
            dispatch_quality_for_status(Some(DefinitionLookupStatus::Cancelled), None),
            DispatchQuality::Cancelled
        );
        assert_eq!(
            dispatch_quality_for_status(None, None),
            DispatchQuality::Unknown
        );

        let boundary_status = DefinitionLookupStatus::UnresolvableImportBoundary;
        assert_eq!(
            dispatch_quality_for_status(
                Some(boundary_status),
                Some(BoundaryStatus::WorkspaceLocal)
            ),
            DispatchQuality::Complete
        );
        assert_eq!(
            dispatch_quality_for_status(
                Some(boundary_status),
                Some(BoundaryStatus::ExternalIndexed)
            ),
            DispatchQuality::Complete
        );
        assert_eq!(
            dispatch_quality_for_status(
                Some(boundary_status),
                Some(BoundaryStatus::ExternalDeclaredUnindexed)
            ),
            DispatchQuality::Unproven
        );
        assert_eq!(
            dispatch_quality_for_status(
                Some(boundary_status),
                Some(BoundaryStatus::ExternalUnknown)
            ),
            DispatchQuality::Unknown
        );
        assert_eq!(
            dispatch_quality_for_status(Some(boundary_status), None),
            DispatchQuality::Unknown
        );
    }
}

/// Whether retained dependency-discovery evidence for `language` still
/// accounts for `name`: the build declares it (or a module containing it), or
/// discovery could not read everything the build declared. Reads what the
/// analyzer already holds; never starts discovery.
#[doc(hidden)]
pub fn declared_by_retained_discovery(
    analyzer: &dyn IAnalyzer,
    language: crate::analyzer::Language,
    name: &str,
) -> bool {
    crate::analyzer::semantic_model::retained_evidence_declares(
        analyzer.dependency_discovery_evidence(language).as_deref(),
        name,
    )
}

/// Whether a JVM spelling routes through a selected import or a language
/// implicit root that retained dependency discovery declared but did not
/// index. The imports come from the analyzer's structured import provider; the
/// root packages come from the same language hook that keeps native lookup
/// completeness open.
fn declared_jvm_import_or_implicit_root(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    language: crate::analyzer::Language,
    name: &str,
    evidence: &crate::analyzer::semantic_model::DependencyDiscoveryEvidence,
    include_implicit_root: bool,
) -> bool {
    use crate::analyzer::resolution::{JvmImplicitRootProvider, language_implicit_root_providers};

    let scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let Some(leading) = name.split('.').next().filter(|head| !head.is_empty()) else {
        return false;
    };
    let imported = analyzer
        .import_analysis_provider_for_file(file)
        .is_some_and(|provider| {
            provider.import_info_of(token, file).iter().any(|import| {
                let binds = import.is_wildcard || import.local_name() == Some(leading);
                binds
                    && import.path.as_ref().is_some_and(|path| {
                        evidence.declares_module_path(&path.render_segments("."))
                    })
            })
        });
    imported
        || (include_implicit_root
            && !name.contains('.')
            && language_implicit_root_providers(language)
                .iter()
                .any(|provider| {
                    let package = match provider {
                        JvmImplicitRootProvider::Package(package) => *package,
                        JvmImplicitRootProvider::ScalaPredef => "scala.Predef",
                    };
                    evidence.declares_module_path(package)
                }))
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
    let scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    // `name` is the resolved reference site's rendered text; its leading
    // dotted segment is the local binder an import introduced.
    let Some(leading) = name.split('.').next().filter(|head| !head.is_empty()) else {
        return false;
    };
    crate::analyzer::languages::language_support(language).is_some_and(|support| {
        support.definition_declared_import_route(analyzer, token, file, leading, evidence)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::resolution::lexical_definition::LexicalDefinition;

    use crate::analyzer::DeclarationKind;

    use crate::analyzer::Range;

    use brokk_bifrost_test_macros::hardwon;

    fn lexical(identifier: &str) -> LexicalDefinition {
        LexicalDefinition {
            source_file: None,
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

    #[hardwon("#1569: a session collects rows and drains them per request")]
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

    #[hardwon("#1569: a deep scope restores the name it replaced")]
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
}

/// #1870 acceptance: every language with an evidence arm reports
/// `external_indexed` for an indexed external name and
/// `external_declared_unindexed` for a declared-but-unindexed dependency,
/// instead of the unconditional `external_unknown` the wildcard used to give.
///
/// Every arm here is driven end-to-end through
/// [`resolve_definition_batch_with_trace`], the same entry the occurrence-rows
/// acceptance tests for Python and TypeScript use underneath: the real resolver
/// draws the boundary and `finish_boundary` refines it. Each language that
/// draws one is also tested for the case it must *not* draw: a name whose
/// failing segment stays inside the workspace answers `no_definition` with no
/// route row at all (#1889).
#[cfg(test)]
mod boundary_evidence_tests {
    use super::test_support::*;

    use super::*;

    use crate::analyzer::AnalyzerConfig;
    use crate::analyzer::AnalyzerQueryScope;
    use crate::analyzer::Language;

    use crate::test_support::activation_evidence;

    use brokk_bifrost_test_macros::hardwon;

    use std::path::Path;
    use std::path::PathBuf;

    const KOTLIN_BOUNDARY_SOURCE: &str = concat!(
        "package app\n",
        "import com.acme.Gadget\n",
        "class Caller {\n",
        "  fun build(): Gadget? = null\n",
        "}\n",
    );

    const JVM_PACK_JAVA_SOURCE: &str = concat!(
        "package app;\n",
        "\n",
        "import java.util.ArrayList;\n",
        "import java.util.Collections;\n",
        "\n",
        "class Caller {\n",
        "  Collections helper() { return null; }\n",
        "  ArrayList names() { return null; }\n",
        "}\n",
    );

    const JVM_PACK_KOTLIN_SOURCE: &str = concat!(
        "package app\n",
        "import java.util.Collections\n",
        "class Caller {\n",
        "  fun helper(): Collections? = null\n",
        "}\n",
    );

    /// A discovery outcome declaring exactly `modules` for `language`; an
    /// incomplete outcome records that the build could not be read fully.
    fn write_source_jar(path: &Path, entry_name: &str, bytes: &[u8]) {
        use std::io::Write;
        let file = std::fs::File::create(path).expect("create source jar");
        let mut jar = zip::ZipWriter::new(file);
        jar.start_file(
            entry_name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .expect("start jar entry");
        jar.write_all(bytes).expect("write jar entry");
        jar.finish().expect("finish jar");
    }

    /// A JVM analyzer config whose external realm is exactly the given jar --
    /// a source jar or a class jar, whichever the caller wrote: dependency
    /// discovery and JDK discovery stay off so the index reads nothing but the
    /// fixture's own artifact.
    fn jvm_config_with_artifact_jar(jar: Option<PathBuf>) -> AnalyzerConfig {
        use crate::analyzer::{
            JvmAnalyzerConfig, JvmDependencyDiscoveryConfig, JvmDependencyDiscoveryMode,
            JvmExternalArtifact, JvmExternalDependencies, JvmStandardLibraryDiscoveryConfig,
        };
        AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    artifact_paths: jar
                        .map(|artifact_path| {
                            vec![JvmExternalArtifact {
                                artifact_path,
                                ..JvmExternalArtifact::default()
                            }]
                        })
                        .unwrap_or_default(),
                    ..JvmExternalDependencies::default()
                },
                dependency_discovery: JvmDependencyDiscoveryConfig {
                    mode: JvmDependencyDiscoveryMode::Disabled,
                    ..JvmDependencyDiscoveryConfig::default()
                },
                standard_library_discovery: JvmStandardLibraryDiscoveryConfig {
                    discover_java_home: false,
                    ..JvmStandardLibraryDiscoveryConfig::default()
                },
            },
            ..AnalyzerConfig::default()
        }
    }

    // -----------------------------------------------------------------------
    // Scala: end-to-end through the resolver's own boundary outcome.
    // -----------------------------------------------------------------------

    const SCALA_BOUNDARY_SOURCE: &str = concat!(
        "package app\n",
        "import com.acme.Gadget\n",
        "class Caller {\n",
        "  def build(): Gadget = null\n",
        "}\n",
    );

    #[test]
    fn a_scala_import_of_an_indexed_external_type_reports_external_indexed() {
        let fixture = BoundaryFixture::with_config(
            Language::Scala,
            "app/Caller.scala",
            SCALA_BOUNDARY_SOURCE,
            |root| {
                let jar = root.join("acme-lib-sources.jar");
                write_source_jar(
                    &jar,
                    "com/acme/Gadget.scala",
                    b"package com.acme\nclass Gadget\n",
                );
                jvm_config_with_artifact_jar(Some(jar))
            },
        );
        let (_, trace) = fixture.trace("Gadget = null");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("com.acme.Gadget")
            }),
            "the jar index resolves `Gadget` through the explicit import: {routes:?}"
        );
    }

    // -----------------------------------------------------------------------
    // PHP: end-to-end through the resolver's own boundary outcome.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Kotlin: end-to-end through the resolver's own boundary outcome (#1889).
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Ruby: end-to-end through the resolver's own boundary outcome (#1889).
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // JVM declaration-facts packs: the same route the source jars feed (#1893).
    // -----------------------------------------------------------------------

    /// One file whose standard-library call spells a *member*: the whole
    /// written name `Collections.sort` has a type for its head and a member for
    /// its last segment, which is the shape #1900 is about. `Collections.size`
    /// is the near miss on the same owner -- a member no pack declares.
    const JVM_PACK_JAVA_MEMBER_SOURCE: &str = concat!(
        "package app;\n",
        "\n",
        "import java.util.ArrayList;\n",
        "import java.util.Collections;\n",
        "\n",
        "class Caller {\n",
        "  int run() {\n",
        "    ArrayList<String> names = new ArrayList<>();\n",
        "    Collections.sort(names);\n",
        "    return Collections.size(names);\n",
        "  }\n",
        "}\n",
    );

    fn jdk_collections_type_id() -> String {
        use crate::analyzer::semantic_model::{TypeIdentity, type_declaration_id};

        type_declaration_id(TypeIdentity {
            ecosystem: "jdk",
            name: "java.util.Collections",
        })
    }

    /// The declaration-facts pack the JVM boundary tests activate: one public
    /// JDK class, published for `language: java`, carrying `members`, and no
    /// artifact anywhere on disk.
    fn jdk_collections_pack(members: serde_json::Value) -> serde_json::Value {
        single_type_pack(
            "fixture.jdk",
            "java",
            "jdk",
            "java.base",
            &jdk_collections_type_id(),
            "java.util.Collections",
            members,
        )
    }

    /// The one static method the member fixtures declare on
    /// `java.util.Collections`.
    fn collections_sort_member() -> serde_json::Value {
        let owner = jdk_collections_type_id();
        serde_json::json!([{
            "id": format!("member.{owner}.sort"),
            "owner": owner,
            "name": "sort",
            "member_kind": "method",
            "visibility": "public",
            "is_static": true,
            "locator": {
                "kind": "artifact",
                "path": "fixture-source",
                "symbol": "java.util.Collections.sort"
            }
        }])
    }

    // -----------------------------------------------------------------------
    // Milestone 1 (#1885): the public probe entry points read the same
    // resolver decisions as the crate-internal ones they wrap.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // JVM declaration-facts packs: member declarations (#1900).
    // -----------------------------------------------------------------------

    #[test]
    fn a_java_member_of_a_pack_declared_type_reports_external_indexed() {
        // #1900 acceptance: no source jar, no class jar, no JDK home. The
        // activated pack declares `java.util.Collections` *and* its `sort`
        // member, and the whole written name `Collections.sort` reaches the
        // member declaration from both of the sites that spell it.
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        activate_fixture_pack(
            &fixture,
            "fixture.jdk",
            &jdk_collections_pack(collections_sort_member()),
            activation_evidence("java", "jdk", "java.base"),
        );

        // Receiver position: the caret is on `Collections`, and the reference
        // site spans the whole `Collections.sort` spelling.
        let (_, trace) = fixture.trace("Collections.sort");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("java.util.Collections.sort")
            }),
            "the activated pack declares the `sort` member: {routes:?}"
        );

        // Member position: the caret is on `sort`, whose receiver names a type
        // this workspace does not index. Before #1900 that was a plain
        // unresolved-receiver miss with no route at all.
        let (outcome, trace) = fixture.trace("sort(names)");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary,
            "the member is declared past a boundary, not absent: {:?}",
            outcome.diagnostics
        );
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("java.util.Collections.sort")
            }),
            "the member caret reaches the same declaration: {routes:?}"
        );

        // The route the member named is the reference's selection, which is
        // what lets a positive tier requirement over it conclude (#1893).
        let selected: Vec<_> = trace
            .candidates
            .iter()
            .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
            .collect();
        assert!(
            !selected.is_empty()
                && selected
                    .iter()
                    .all(|row| row.is_selected() && row.tier == Some(PrecedenceTier::ExternalRoot)),
            "a named external member is the selection: {selected:?}"
        );

        // Boundary honesty on the same owner: `size` is not declared, so the
        // spelling keeps the status it had before activation even though the
        // owner type is decided.
        let (_, trace) = fixture.trace("Collections.size");
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "a member the pack does not declare must not be upgraded: {routes:?}"
        );
    }

    #[test]
    fn a_member_a_pack_does_not_declare_proves_nothing_about_it() {
        // The honesty rule #1900 names: absence of a member declaration is not
        // a declaration of absence. This pack declares the owner type and no
        // members at all, so every member spelling on it stays exactly as
        // unknown as it was before activation -- and the member-position caret
        // keeps its plain miss rather than inventing a boundary.
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        activate_fixture_pack(
            &fixture,
            "fixture.jdk",
            &jdk_collections_pack(serde_json::json!([])),
            activation_evidence("java", "jdk", "java.base"),
        );

        let (_, trace) = fixture.trace("Collections.sort");
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "a pack with no members decides no member: {routes:?}"
        );

        let (outcome, trace) = fixture.trace("sort(names)");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::NoDefinition,
            "an undeclared member is not a boundary crossing: {:?}",
            outcome.diagnostics
        );
        assert!(
            route_rows(&trace).is_empty(),
            "nothing declares the member, so no route out of the workspace: {:?}",
            trace.candidates
        );
    }

    // -----------------------------------------------------------------------
    // The artifact half of the same member surface: jar-indexed owners (#1900).
    // -----------------------------------------------------------------------

    /// One file whose calls spell members of a type a *class jar* declares.
    /// `register` is declared on the owner itself, `reset` is inherited from
    /// its base class in the same jar, and `absent` is the near miss no class
    /// file declares.
    const JVM_ARTIFACT_JAVA_MEMBER_SOURCE: &str = concat!(
        "package app;\n",
        "\n",
        "import com.example.probe.Registry;\n",
        "\n",
        "class Caller {\n",
        "  void run() {\n",
        "    Registry.register(\"x\");\n",
        "    Registry.reset();\n",
        "    Registry.absent();\n",
        "  }\n",
        "}\n",
    );

    /// A class JAR declaring `com.example.probe.Registry extends
    /// com.example.probe.BaseRegistry`, written without a JDK so the test runs
    /// everywhere.
    fn write_probe_class_jar(path: &Path) {
        let classes = crate::analyzer::jvm::external::probe_registry_base_class_files();
        crate::analyzer::jvm::external::write_test_class_jar(path, &classes);
    }

    #[test]
    fn a_java_member_of_a_class_jar_type_reports_external_indexed() {
        // #1900 acceptance for the artifact half: no pack is activated at all.
        // The jar on disk declares `com.example.probe.Registry` *and* the
        // members its class files carry, and the whole written name
        // `Registry.register` reaches the member declaration from both of the
        // sites that spell it -- the same conclusion the pack half reaches, on
        // the same route, through the same one lookup.
        let jars = tempfile::tempdir().expect("jar dir");
        let jar = jars.path().join("probe.jar");
        write_probe_class_jar(&jar);
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_ARTIFACT_JAVA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(jar.clone())),
        );

        // Receiver position: the caret is on `Registry`, and the reference site
        // spans the whole `Registry.register` spelling.
        let (_, trace) = fixture.trace("Registry.register");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("com.example.probe.Registry.register")
            }),
            "the indexed class jar declares the `register` member: {routes:?}"
        );

        // Member position: the caret is on `register`, whose receiver names a
        // type this workspace does not index.
        let (outcome, trace) = fixture.trace("register(\"x\")");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary,
            "the member is declared past a boundary, not absent: {:?}",
            outcome.diagnostics
        );
        let selected: Vec<_> = trace
            .candidates
            .iter()
            .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
            .collect();
        assert!(
            !selected.is_empty()
                && selected
                    .iter()
                    .all(|row| row.is_selected() && row.tier == Some(PrecedenceTier::ExternalRoot)),
            "a named external member is the selection: {selected:?}"
        );

        // Inherited: `reset` is declared on the base class in the same jar, and
        // the reported target names where it is declared rather than where it
        // was written.
        let (_, trace) = fixture.trace("Registry.reset");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("com.example.probe.BaseRegistry.reset")
            }),
            "an inherited member answers where it is declared: {routes:?}"
        );

        // Boundary honesty on the same owner: no class file declares `absent`,
        // so the spelling keeps the status it had. The owner is decided, which
        // is why the route exists at all, and nothing upgrades it.
        let (_, trace) = fixture.trace("Registry.absent");
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "a member no class file declares must not be upgraded: {routes:?}"
        );
    }

    /// #3466: an instance-receiver member call on an external type beside a
    /// workspace-local same-name member. The workspace receiver typing answers
    /// nothing for the servlet type, and the external declaration surface is
    /// the class jar below.
    const SERVLET_FIXTURE_SOURCE: &str = concat!(
        "package fixture;\n",
        "\n",
        "import jakarta.servlet.http.HttpServletRequest;\n",
        "\n",
        "final class SameNameRequest {\n",
        "  String getParameter(String name) { return name; }\n",
        "}\n",
        "\n",
        "final class App {\n",
        "  String positive(HttpServletRequest servletRequest) {\n",
        "    return servletRequest.getParameter(\"user\");\n",
        "  }\n",
        "\n",
        "  String sameName(SameNameRequest decoyRequest) {\n",
        "    return decoyRequest.getParameter(\"name\");\n",
        "  }\n",
        "}\n",
    );

    fn write_servlet_api_jar(path: &Path) {
        use crate::analyzer::jvm::external::{
            TestClassFile, TestClassMethod, write_test_class_jar,
        };

        write_test_class_jar(
            path,
            &[
                TestClassFile {
                    internal_name: "jakarta/servlet/ServletRequest",
                    super_internal_name: "java/lang/Object",
                    methods: &[TestClassMethod {
                        name: "getParameter",
                        descriptor: "(Ljava/lang/String;)Ljava/lang/String;",
                        is_static: false,
                    }],
                    private_nested: false,
                },
                TestClassFile {
                    internal_name: "jakarta/servlet/http/HttpServletRequest",
                    super_internal_name: "jakarta/servlet/ServletRequest",
                    methods: &[],
                    private_nested: false,
                },
            ],
        );
    }

    /// The shared publication for an instance-receiver member call on an
    /// external type: the outcome is the boundary, its resolved reference text
    /// is the canonical external identity, and the route row names that same
    /// identity with the external declaration the resolver landed on. Before
    /// #3466 the outcome stayed `NoDefinition` and the trace had no row, while
    /// `call_bindings` read the same call's canonical identity end to end.
    #[test]
    #[hardwon(
        "#3466: A real instance receiver call publishes one route row that joins the corresponding occurrence candidate"
    )]
    fn instance_receiver_member_call_publishes_the_external_route_row() {
        let jars = tempfile::tempdir().expect("jar dir");
        let jar = jars.path().join("servlet-api.jar");
        write_servlet_api_jar(&jar);
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "src/App.java",
            SERVLET_FIXTURE_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(jar.clone())),
        );

        let (outcome, trace) = fixture.trace("getParameter(\"user\")");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary,
            "an instance call on an external type is the boundary it crossed: {:?}",
            outcome.diagnostics
        );
        assert_eq!(
            outcome.resolved_reference_target(),
            Some("jakarta.servlet.ServletRequest.getParameter"),
            "the boundary names the declaration the external surface resolved: {:?}",
            outcome.diagnostics
        );
        assert_eq!(
            external_routes(&trace),
            vec![(
                BoundaryStatus::ExternalIndexed,
                Some("jakarta.servlet.ServletRequest.getParameter".to_string()),
            )],
            "the same identity is the one candidate row the trace publishes: {:#?}",
            trace.candidates
        );
        assert!(
            trace
                .selected()
                .any(|row| row.boundary == BoundaryStatus::ExternalIndexed),
            "the external declaration is the answer this reference resolved to: {:#?}",
            trace.candidates
        );
    }

    #[test]
    #[hardwon(
        "0242909d77ed: Java census G13 (2026-10-15): inherited external members lost their declaring owner"
    )]
    fn inherited_external_routes_keep_the_same_declaring_identity_for_both_receiver_types() {
        let jars = tempfile::tempdir().expect("jar dir");
        let jar = jars.path().join("servlet-api.jar");
        write_servlet_api_jar(&jar);
        for receiver in [
            "jakarta.servlet.ServletRequest",
            "jakarta.servlet.http.HttpServletRequest",
        ] {
            let source = format!(
                "class App {{ String read({receiver} request) {{ return request.getParameter(\"user\"); }} }}"
            );
            let fixture =
                BoundaryFixture::with_config(Language::Java, "src/App.java", &source, |_| {
                    jvm_config_with_artifact_jar(Some(jar.clone()))
                });
            let (outcome, trace) = fixture.trace("getParameter(\"user\")");
            assert_eq!(
                outcome.resolved_reference_target(),
                Some("jakarta.servlet.ServletRequest.getParameter"),
                "receiver {receiver}: {outcome:?}"
            );
            assert_eq!(
                external_routes(&trace),
                vec![(
                    BoundaryStatus::ExternalIndexed,
                    Some("jakarta.servlet.ServletRequest.getParameter".to_owned())
                )],
                "receiver {receiver}: {trace:?}"
            );
        }
    }

    /// The decoy half of #3466: the workspace-local member of the same name is
    /// still an ordinary in-workspace resolution. Nothing about the external
    /// call makes a same-name workspace member a boundary.
    #[test]
    #[hardwon(
        "#3466: A workspace declaration with the same member spelling wins without publishing an external route"
    )]
    fn workspace_same_name_member_decoy_stays_in_workspace() {
        let jars = tempfile::tempdir().expect("jar dir");
        let jar = jars.path().join("servlet-api.jar");
        write_servlet_api_jar(&jar);
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "src/App.java",
            SERVLET_FIXTURE_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(jar.clone())),
        );

        let (outcome, trace) = fixture.trace("getParameter(\"name\")");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "a workspace member is a resolved definition, not a boundary: {:?}",
            outcome.diagnostics
        );
        assert_eq!(
            outcome
                .definitions
                .iter()
                .map(|unit| unit.fq_name())
                .collect::<Vec<_>>(),
            vec!["fixture.SameNameRequest.getParameter".to_string()],
            "the decoy's own declaration is the answer: {:?}",
            outcome.diagnostics
        );
        assert!(
            route_rows(&trace).is_empty(),
            "a workspace resolution reports no route out of the workspace: {:#?}",
            trace.candidates
        );
    }

    #[test]
    fn a_class_jar_the_index_could_not_read_proves_nothing_about_its_members() {
        // The honesty rule #1900 names, on the artifact half: a jar the bounded
        // read could not open declares nothing, so every member spelling on it
        // stays unknown. This is the artifact counterpart of "a pack that
        // declares no members proves nothing about them", and it is what
        // separates "the member is not there" from "nothing read the class file
        // that would say".
        let jars = tempfile::tempdir().expect("jar dir");
        let jar = jars.path().join("probe.jar");
        std::fs::write(&jar, b"not a zip archive at all").expect("write the corrupt jar");
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_ARTIFACT_JAVA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(jar.clone())),
        );

        let (_, trace) = fixture.trace("Registry.register");
        let routes = route_rows(&trace);
        assert!(
            routes.iter().all(
                |(boundary, target)| *boundary != BoundaryStatus::ExternalIndexed
                    && target.is_none()
            ),
            "an unread jar names no member: {routes:?}"
        );

        let (outcome, trace) = fixture.trace("register(\"x\")");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::NoDefinition,
            "an unread jar's member is not a proven boundary crossing: {:?}",
            outcome.diagnostics
        );
        assert!(
            route_rows(&trace).is_empty(),
            "nothing declares the member, so no route out of the workspace: {:?}",
            trace.candidates
        );
    }

    // -----------------------------------------------------------------------
    // Kotlin and Scala reach the same gate through their own resolvers (#2287).
    // -----------------------------------------------------------------------

    /// A Kotlin caller of a member whose owner lives in a dependency JAR.
    const JVM_ARTIFACT_KOTLIN_MEMBER_SOURCE: &str = concat!(
        "package app\n",
        "import com.example.probe.Registry\n",
        "class Caller {\n",
        "  fun run() { Registry.register(\"x\") }\n",
        "}\n",
    );

    /// The same caller written in Scala. The owner is named through a wildcard
    /// import rather than an explicit one on purpose: an explicit Scala import
    /// whose target is unindexed already draws a boundary of its own, so a
    /// wildcard is the shape where the member surface is the only thing that
    /// can carry the claim.
    const JVM_ARTIFACT_SCALA_MEMBER_SOURCE: &str = concat!(
        "package app\n",
        "import com.example.probe.*\n",
        "class Caller {\n",
        "  def run(): Unit = Registry.register(\"x\")\n",
        "}\n",
    );

    /// A class JAR declaring `com.example.probe.Registry` and *no members at
    /// all*. The owner type is indexed exactly as it is in
    /// [`write_probe_class_jar`]; only the member surface differs, which is
    /// what makes the paired runs a discriminator about the member rather than
    /// about the type or about the JAR merely existing.
    fn write_memberless_probe_class_jar(path: &Path) {
        use crate::analyzer::jvm::external::{TestClassFile, write_test_class_jar};

        write_test_class_jar(
            path,
            &[TestClassFile {
                internal_name: "com/example/probe/Registry",
                super_internal_name: "java/lang/Object",
                methods: &[],
                private_nested: false,
            }],
        );
    }

    /// What one caret over the written `Registry.register` spelling answered.
    struct MemberSpellingAnswer {
        status: DefinitionLookupStatus,
        outcome: DefinitionLookupOutcome,
        routes: Vec<(BoundaryStatus, Option<String>)>,
    }

    /// The answers a receiver-position caret and a member-position caret each
    /// produce for the one written `Registry.register` spelling.
    fn member_spelling_answers(fixture: &BoundaryFixture) -> Vec<MemberSpellingAnswer> {
        ["Registry.register", "register(\"x\")"]
            .into_iter()
            .map(|needle| {
                let (outcome, trace) = fixture.trace(needle);
                MemberSpellingAnswer {
                    status: outcome.status,
                    routes: route_rows(&trace),
                    outcome,
                }
            })
            .collect()
    }

    /// The #1900 acceptance shape, reproduced for Kotlin (#2287): three paired
    /// runs over one workspace whose only difference is what the JAR declares.
    ///
    /// Before this change both carets died inside Kotlin's own
    /// unresolved-receiver path (`no_indexed_definition` on the receiver,
    /// `receiver_type_unknown` on the member) and no trace carried a route out
    /// of the workspace at all, so nothing downstream could tell an external
    /// member from an absent one.
    #[test]
    fn a_kotlin_member_of_a_class_jar_type_concludes_only_when_the_jar_declared_it() {
        let jars = tempfile::tempdir().expect("jar dir");

        // The JAR declares `register`: both carets report the boundary they
        // crossed, and the route names the exact external declaration.
        let declared = jars.path().join("declared.jar");
        write_probe_class_jar(&declared);
        let fixture = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            JVM_ARTIFACT_KOTLIN_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(declared.clone())),
        );
        for answer in member_spelling_answers(&fixture) {
            assert_eq!(
                answer.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "the member is declared past a boundary, not absent"
            );
            assert!(
                !answer.routes.is_empty()
                    && answer.routes.iter().all(|(boundary, target)| {
                        *boundary == BoundaryStatus::ExternalIndexed
                            && target.as_deref() == Some("com.example.probe.Registry.register")
                    }),
                "the indexed class jar declares the `register` member: {:?}",
                answer.routes
            );
        }
        let (_, trace) = fixture.trace("Registry.register");
        let selected: Vec<_> = trace
            .candidates
            .iter()
            .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
            .collect();
        assert!(
            !selected.is_empty()
                && selected
                    .iter()
                    .all(|row| row.is_selected() && row.tier == Some(PrecedenceTier::ExternalRoot)),
            "a named external member is the selection: {selected:?}"
        );

        // No JAR anywhere: nothing read a class file, so the spelling stays
        // unknown and no route is drawn.
        let absent = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            JVM_ARTIFACT_KOTLIN_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        for answer in member_spelling_answers(&absent) {
            assert_eq!(
                answer.status,
                DefinitionLookupStatus::Incomplete,
                "with no jar native resolution cannot prove member absence"
            );
            assert!(
                answer.routes.is_empty(),
                "nothing declares the member, so no route out of the workspace: {:?}",
                answer.routes
            );
        }

        // The discriminator that names the *member*: the same owner type,
        // still indexed, whose class file declares no members. The conclusion
        // above therefore rests on `register` having been read.
        let memberless = jars.path().join("memberless.jar");
        write_memberless_probe_class_jar(&memberless);
        let type_only = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            JVM_ARTIFACT_KOTLIN_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(memberless.clone())),
        );
        for answer in member_spelling_answers(&type_only) {
            assert_eq!(
                answer.status,
                DefinitionLookupStatus::NoDefinition,
                "an indexed owner that declares no members proves nothing about them: {:?}",
                answer.outcome
            );
            assert!(
                answer.routes.is_empty(),
                "a member no class file declares must not be upgraded: {:?}",
                answer.routes
            );
        }
    }

    /// The same three paired runs for Scala (#2287).
    ///
    /// Before this change the receiver caret reported `no_indexed_definition`
    /// and the member caret `unsupported_scala_receiver`, with no route out of
    /// the workspace on either.
    #[test]
    fn a_scala_member_of_a_class_jar_type_concludes_only_when_the_jar_declared_it() {
        let jars = tempfile::tempdir().expect("jar dir");

        let declared = jars.path().join("declared.jar");
        write_probe_class_jar(&declared);
        let fixture = BoundaryFixture::with_config(
            Language::Scala,
            "app/Caller.scala",
            JVM_ARTIFACT_SCALA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(declared.clone())),
        );
        for answer in member_spelling_answers(&fixture) {
            assert_eq!(
                answer.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "the member is declared past a boundary, not absent"
            );
            assert!(
                !answer.routes.is_empty()
                    && answer.routes.iter().all(|(boundary, target)| {
                        *boundary == BoundaryStatus::ExternalIndexed
                            && target.as_deref() == Some("com.example.probe.Registry.register")
                    }),
                "the indexed class jar declares the `register` member: {:?}",
                answer.routes
            );
        }
        let (_, trace) = fixture.trace("Registry.register");
        let selected: Vec<_> = trace
            .candidates
            .iter()
            .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
            .collect();
        assert!(
            !selected.is_empty()
                && selected
                    .iter()
                    .all(|row| row.is_selected() && row.tier == Some(PrecedenceTier::ExternalRoot)),
            "a named external member is the selection: {selected:?}"
        );

        let absent = BoundaryFixture::with_config(
            Language::Scala,
            "app/Caller.scala",
            JVM_ARTIFACT_SCALA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        for answer in member_spelling_answers(&absent) {
            assert_eq!(
                answer.status,
                if std::env::var_os("BIFROST_TRIAL_NATIVE_SCALA").is_some() {
                    DefinitionLookupStatus::Incomplete
                } else {
                    DefinitionLookupStatus::NoDefinition
                },
                "with no jar native resolution cannot prove member absence"
            );
            assert!(
                answer.routes.is_empty(),
                "nothing declares the member, so no route out of the workspace: {:?}",
                answer.routes
            );
        }

        let memberless = jars.path().join("memberless.jar");
        write_memberless_probe_class_jar(&memberless);
        let type_only = BoundaryFixture::with_config(
            Language::Scala,
            "app/Caller.scala",
            JVM_ARTIFACT_SCALA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(memberless.clone())),
        );
        for (caret_index, answer) in member_spelling_answers(&type_only).into_iter().enumerate() {
            let expected_status = if caret_index == 0 {
                DefinitionLookupStatus::NoDefinition
            } else {
                // under the Scala trial the given-extension frontier (#5956) keeps the memberless owner Incomplete
                if std::env::var_os("BIFROST_TRIAL_NATIVE_SCALA").is_some() {
                    DefinitionLookupStatus::Incomplete
                } else {
                    DefinitionLookupStatus::NoDefinition
                }
            };
            assert_eq!(
                answer.status, expected_status,
                "an indexed owner that declares no members proves nothing about them"
            );
            assert!(
                answer.routes.is_empty(),
                "a member no class file declares must not be upgraded: {:?}",
                answer.routes
            );
        }
    }

    /// The pack half of the same claim, once per language (#2287): an activated
    /// declaration-facts pack and no artifact anywhere on disk.
    ///
    /// Scala names the owner through an *explicit* import here, which is the
    /// shape whose unindexed-import verdict already drew a boundary of its own
    /// before this change. The route it drew named nothing, so the pair below
    /// is still the member discriminator: with the member declared the route is
    /// selected and names `java.util.Collections.sort`; with an emptied members
    /// array the same run keeps a route that names nothing and is not selected.
    #[test]
    fn a_kotlin_and_a_scala_member_of_a_pack_declared_type_report_external_indexed() {
        const KOTLIN_MEMBER_SOURCE: &str = concat!(
            "package app\n",
            "import java.util.Collections\n",
            "class Caller {\n",
            "  fun order(names: MutableList<String>) { Collections.sort(names) }\n",
            "}\n",
        );
        const SCALA_MEMBER_SOURCE: &str = concat!(
            "package app\n",
            "import java.util.Collections\n",
            "class Caller {\n",
            "  def order(names: java.util.List[String]): Unit = Collections.sort(names)\n",
            "}\n",
        );

        for (language, path, source) in [
            (Language::Kotlin, "app/Caller.kt", KOTLIN_MEMBER_SOURCE),
            (Language::Scala, "app/Caller.scala", SCALA_MEMBER_SOURCE),
        ] {
            let declared = BoundaryFixture::with_config(language, path, source, |_| {
                jvm_config_with_artifact_jar(None)
            });
            activate_fixture_pack(
                &declared,
                "fixture.jdk",
                &jdk_collections_pack(collections_sort_member()),
                activation_evidence("java", "jdk", "java.base"),
            );
            for needle in ["Collections.sort", "sort(names)"] {
                let (outcome, trace) = declared.trace(needle);
                assert_eq!(
                    outcome.status,
                    DefinitionLookupStatus::UnresolvableImportBoundary,
                    "{language:?} {needle:?}: the pack declares the member, so the \
                     reference crossed a boundary: {:?}",
                    outcome.diagnostics
                );
                let routes = external_routes(&trace);
                assert!(
                    routes.iter().all(|(boundary, target)| {
                        *boundary == BoundaryStatus::ExternalIndexed
                            && target.as_deref() == Some("java.util.Collections.sort")
                    }),
                    "{language:?} {needle:?}: the activated pack declares `sort`: {routes:?}"
                );
                let selected: Vec<_> = trace
                    .candidates
                    .iter()
                    .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
                    .collect();
                assert!(
                    selected.iter().all(|row| {
                        row.is_selected() && row.tier == Some(PrecedenceTier::ExternalRoot)
                    }),
                    "{language:?} {needle:?}: a named external member is the \
                     selection: {selected:?}"
                );
            }

            // The same pack with an emptied `members` array: the owner type is
            // still declared and still activated, and every member spelling on
            // it stays exactly as unknown as it was before activation.
            let type_only = BoundaryFixture::with_config(language, path, source, |_| {
                jvm_config_with_artifact_jar(None)
            });
            activate_fixture_pack(
                &type_only,
                "fixture.jdk",
                &jdk_collections_pack(serde_json::json!([])),
                activation_evidence("java", "jdk", "java.base"),
            );
            for needle in ["Collections.sort", "sort(names)"] {
                let (_, trace) = type_only.trace(needle);
                assert!(
                    route_rows(&trace).iter().all(|(boundary, target)| {
                        *boundary != BoundaryStatus::ExternalIndexed && target.is_none()
                    }),
                    "{language:?} {needle:?}: a pack with no members decides no \
                     member: {:?}",
                    route_rows(&trace)
                );
                assert!(
                    trace
                        .candidates
                        .iter()
                        .filter(|row| matches!(
                            row.candidate,
                            TraceCandidateRef::ExternalRoute { .. }
                        ))
                        .all(|row| !row.is_selected()),
                    "{language:?} {needle:?}: nothing named the member, so nothing \
                     was selected: {:?}",
                    trace.candidates
                );
            }
        }
    }

    #[test]
    fn a_scala_import_of_a_declared_unread_dependency_reports_declared_unindexed() {
        let fixture = BoundaryFixture::with_config(
            Language::Scala,
            "app/Caller.scala",
            SCALA_BOUNDARY_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        fixture.workspace.retain_dependency_discovery_evidence(
            &[Language::Scala],
            &crate::test_support::incomplete_discovery_declaring("scala", &["com.acme"], |_| {
                Vec::new()
            }),
        );
        let (_, trace) = fixture.trace("Gadget = null");
        let routes = external_routes(&trace);
        assert_declared_unindexed_routes(&routes);
    }

    #[hardwon("#1889: Kotlin imports failed to report the indexed external boundary")]
    #[test]
    fn a_kotlin_import_of_an_indexed_external_type_reports_external_indexed() {
        let fixture = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            KOTLIN_BOUNDARY_SOURCE,
            |root| {
                let jar = root.join("acme-lib-sources.jar");
                write_source_jar(
                    &jar,
                    "com/acme/Gadget.kt",
                    b"package com.acme\nclass Gadget\n",
                );
                jvm_config_with_artifact_jar(Some(jar))
            },
        );
        let (_, trace) = fixture.trace("Gadget? = null");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("com.acme.Gadget")
            }),
            "the jar index resolves `Gadget` through the explicit import: {routes:?}"
        );
    }
    #[hardwon("#1889: Kotlin imports failed to report declared but unread dependencies")]
    #[test]
    fn a_kotlin_import_of_a_declared_unread_dependency_reports_declared_unindexed() {
        let fixture = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            KOTLIN_BOUNDARY_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        let (_, trace) = fixture.trace("Gadget? = null");
        assert!(
            external_routes(&trace)
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "with no index and no retained discovery, nothing is known: {:?}",
            trace.candidates
        );
        fixture.workspace.retain_dependency_discovery_evidence(
            &[Language::Kotlin],
            &crate::test_support::incomplete_discovery_declaring("kotlin", &["com.acme"], |_| {
                Vec::new()
            }),
        );
        let (_, trace) = fixture.trace("Gadget? = null");
        let routes = external_routes(&trace);
        assert_declared_unindexed_routes(&routes);
    }
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[hardwon("#1889: Kotlin workspace packages were at risk of false external classification")]
    #[test]
    fn a_kotlin_import_of_a_workspace_package_stays_a_plain_miss() {
        // The import target is the workspace's own package, so the failing
        // segment never leaves it and the honest answer is `no_definition`.
        let fixture = BoundaryFixture::new(
            Language::Kotlin,
            "app/Caller.kt",
            concat!(
                "package app\n",
                "import app.Helper\n",
                "class Caller {\n",
                "  fun build(): Helper? = null\n",
                "}\n",
            ),
        );
        assert_no_boundary_was_drawn("Helper? = null", &fixture);
    }
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[hardwon(
        "#1889: Kotlin names without import evidence were at risk of false external classification"
    )]
    #[test]
    fn a_kotlin_reference_with_no_import_at_all_stays_a_plain_miss() {
        let fixture = BoundaryFixture::new(
            Language::Kotlin,
            "app/Caller.kt",
            concat!(
                "package app\n",
                "class Caller {\n",
                "  fun build(): Helper? = null\n",
                "}\n",
            ),
        );
        assert_no_boundary_was_drawn("Helper? = null", &fixture);
    }

    #[hardwon("#1893: Java resolution ignored selected declaration-facts packs")]
    #[test]
    fn a_java_import_of_a_pack_declared_type_reports_external_indexed() {
        // #1893 acceptance: no source jar, no class jar, no JDK home -- the
        // activated pack's declaration facts are the only external evidence
        // there is, and they carry the reference all the way to the same
        // `external_indexed` verdict the source-jar route produces.
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        let pack = jdk_collections_pack(serde_json::json!([]));
        activate_fixture_pack(
            &fixture,
            "fixture.jdk",
            &pack,
            activation_evidence("java", "jdk", "java.base"),
        );

        let (_, trace) = fixture.trace("Collections helper");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("java.util.Collections")
            }),
            "the activated pack declares `java.util.Collections`: {routes:?}"
        );

        // Boundary honesty: a pack decides the types it declares and nothing
        // else. `java.util.ArrayList` is imported from the same package and is
        // not in the pack, so it keeps the answer it had before activation.
        let (_, trace) = fixture.trace("ArrayList names");
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "a type the pack does not declare must not be upgraded: {routes:?}"
        );
    }
    #[hardwon(
        "#1893: Java resolution must not infer external declarations without an activated pack"
    )]
    #[test]
    fn a_java_reference_without_the_pack_stays_external_unknown() {
        // The same fixture with no activation at all: the honest answer before
        // #1893 and after it, so the test above measures the pack and not the
        // fixture.
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        let (_, trace) = fixture.trace("Collections helper");
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "with nothing activated and no artifact, nothing is known: {routes:?}"
        );
    }

    #[test]
    fn the_public_traced_batch_reports_workspace_local_for_an_in_workspace_reference() {
        // A reference that never leaves the workspace draws no boundary route
        // at all; `TraceCandidate::selected` defaults every row's boundary to
        // `WorkspaceLocal`, so that is the honest reading for a plain
        // in-workspace hit rather than a value `finish_boundary` stamped.
        let fixture = BoundaryFixture::new(
            Language::Java,
            "app/Caller.java",
            concat!(
                "package app;\n",
                "class Helper {}\n",
                "class Caller {\n",
                "  Helper helper() { return null; }\n",
                "}\n",
            ),
        );
        let (outcome, trace) = fixture.trace_via_probe_entry_point("Helper helper");
        assert_eq!(outcome.status, DefinitionLookupStatus::Resolved);
        let selected: Vec<_> = trace.selected().collect();
        assert!(
            !selected.is_empty(),
            "a resolved reference reports the candidate it selected: {:?}",
            trace.candidates
        );
        assert!(
            selected
                .iter()
                .all(|row| row.boundary == BoundaryStatus::WorkspaceLocal),
            "an in-workspace selection is workspace-local: {selected:?}"
        );
        assert_eq!(
            dispatch_quality_for_status(Some(outcome.status), None),
            DispatchQuality::Complete
        );
    }

    #[test]
    fn the_public_traced_batch_agrees_with_direct_boundary_evidence_for_a_pack_indexed_reference() {
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        let pack = jdk_collections_pack(serde_json::json!([]));
        activate_fixture_pack(
            &fixture,
            "fixture.jdk",
            &pack,
            activation_evidence("java", "jdk", "java.base"),
        );

        let (outcome, trace) = fixture.trace_via_probe_entry_point("Collections helper");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary
        );
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("java.util.Collections")
            }),
            "the activated pack declares `java.util.Collections`: {routes:?}"
        );

        // Chain-link agreement (#1885): the direct evidence call must name the
        // same boundary and target the trace already stamped on the row,
        // because both read the same `boundary_evidence` fact.
        let (direct_status, direct_target) = boundary_evidence(
            fixture.workspace.analyzer(),
            &fixture.file,
            "java.util.Collections",
        );
        assert_eq!(direct_status, BoundaryStatus::ExternalIndexed);
        assert_eq!(direct_target.as_deref(), Some("java.util.Collections"));

        assert_eq!(
            dispatch_quality_for_status(Some(outcome.status), Some(direct_status)),
            DispatchQuality::Complete
        );
    }

    #[test]
    fn the_public_traced_batch_agrees_with_direct_boundary_evidence_without_the_pack() {
        // Same reference, no pack activated: dependency discovery never ran
        // for this fixture (`jvm_config_with_artifact_jar` disables it), so
        // there is no retained evidence to refine the miss into
        // `ExternalDeclaredUnindexed`. The honest answer here is
        // `ExternalUnknown`, matching
        // `a_java_reference_without_the_pack_stays_external_unknown` above.
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );

        let (outcome, trace) = fixture.trace_via_probe_entry_point("Collections helper");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary
        );
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "with nothing activated and no artifact, nothing is known: {routes:?}"
        );

        let (direct_status, direct_target) = boundary_evidence(
            fixture.workspace.analyzer(),
            &fixture.file,
            "java.util.Collections",
        );
        assert_eq!(direct_status, BoundaryStatus::ExternalUnknown);
        assert_eq!(direct_target, None);

        assert_eq!(
            dispatch_quality_for_status(Some(outcome.status), Some(direct_status)),
            DispatchQuality::Unknown
        );
    }
    #[hardwon("#1893: Kotlin resolution ignored selected JVM declaration-facts packs")]
    #[test]
    fn a_kotlin_import_of_a_pack_declared_jvm_type_reports_external_indexed() {
        // Java, Kotlin and Scala share one classpath and therefore one external
        // declaration surface, so a pack published for `language: java` answers
        // a Kotlin reference to the same type.
        let fixture = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            JVM_PACK_KOTLIN_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        let pack = jdk_collections_pack(serde_json::json!([]));
        activate_fixture_pack(
            &fixture,
            "fixture.jdk",
            &pack,
            activation_evidence("java", "jdk", "java.base"),
        );
        let (_, trace) = fixture.trace("Collections? = null");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("java.util.Collections")
            }),
            "the activated pack declares `java.util.Collections`: {routes:?}"
        );
    }

    #[test]
    fn a_pack_for_another_language_never_answers_a_jvm_name() {
        // Near miss: an activated pack that publishes the very same qualified
        // name for a different ecosystem's language. The JVM realm is Java,
        // Kotlin and Scala, so this one is not on the classpath and must not
        // upgrade the reference.
        use crate::analyzer::semantic_model::{TypeIdentity, type_declaration_id};

        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        let type_id = type_declaration_id(TypeIdentity {
            ecosystem: "composer",
            name: "java.util.Collections",
        });
        activate_fixture_pack(
            &fixture,
            "fixture.php.impostor",
            &single_type_pack(
                "fixture.php.impostor",
                "php",
                "composer",
                "vendor/impostor",
                &type_id,
                "java.util.Collections",
                serde_json::json!([]),
            ),
            activation_evidence("php", "composer", "vendor/impostor"),
        );
        let (_, trace) = fixture.trace("Collections helper");
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "a pack for another language declares nothing on the classpath: {routes:?}"
        );
    }
    #[hardwon("#1893: indexed external routes were incorrectly recorded as rejected candidates")]
    #[test]
    fn an_indexed_external_route_is_the_selection_and_an_unknown_one_is_not() {
        // The trace's outcome column, not just its boundary column: a route
        // that named an exact external declaration is what the reference
        // resolved to, so a policy asking "did this resolve through a real
        // route" has a selection to read. A route that named nothing stays
        // rejected, so the same question is honestly unanswerable.
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        let pack = jdk_collections_pack(serde_json::json!([]));
        activate_fixture_pack(
            &fixture,
            "fixture.jdk",
            &pack,
            activation_evidence("java", "jdk", "java.base"),
        );

        let (_, trace) = fixture.trace("Collections helper");
        let declared: Vec<_> = trace
            .candidates
            .iter()
            .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
            .collect();
        assert!(
            !declared.is_empty()
                && declared.iter().all(|row| {
                    row.is_selected() && row.tier == Some(PrecedenceTier::ExternalRoot)
                }),
            "the pack named the declaration, so the route is the selection: {declared:?}"
        );

        let (_, trace) = fixture.trace("ArrayList names");
        let unknown: Vec<_> = trace
            .candidates
            .iter()
            .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
            .collect();
        assert!(
            !unknown.is_empty() && unknown.iter().all(|row| !row.is_selected()),
            "nothing named this declaration, so nothing was selected: {unknown:?}"
        );
    }

    #[hardwon(
        "#1900: Kotlin and Scala member spellings did not reach the shared JVM external member surface"
    )]
    #[test]
    fn the_shared_surface_answers_a_kotlin_and_a_scala_member_spelling() {
        // Java, Kotlin and Scala share one classpath and therefore one external
        // declaration surface, members included: a pack published for
        // `language: java` answers a member spelling written in any of them,
        // each resolved through its own language's import ladder for the owner.
        //
        // This asserts at the boundary-evidence seam; the two tests below carry
        // the same claim end to end through each resolver's own boundary gate.
        const KOTLIN_MEMBER_SOURCE: &str = concat!(
            "package app\n",
            "import java.util.Collections\n",
            "class Caller {\n",
            "  fun order(names: MutableList<String>) { Collections.sort(names) }\n",
            "}\n",
        );
        const SCALA_MEMBER_SOURCE: &str = concat!(
            "package app\n",
            "import java.util.Collections\n",
            "class Caller {\n",
            "  def order(names: java.util.List[String]): Unit = Collections.sort(names)\n",
            "}\n",
        );

        let kotlin = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            KOTLIN_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        activate_fixture_pack(
            &kotlin,
            "fixture.jdk",
            &jdk_collections_pack(collections_sort_member()),
            activation_evidence("java", "jdk", "java.base"),
        );
        let analyzer = kotlin.workspace.analyzer();
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let evidence =
            crate::analyzer::resolve_analyzer::<crate::analyzer::KotlinAnalyzer>(analyzer)
                .expect("the Kotlin fixture has a Kotlin analyzer")
                .external_boundary_evidence(
                    token,
                    analyzer.semantic_model_overlay(),
                    &kotlin.file,
                    "Collections.sort",
                );
        assert_eq!(
            evidence,
            (
                BoundaryStatus::ExternalIndexed,
                Some("java.util.Collections.sort".to_owned())
            ),
            "Kotlin's import ladder reaches the pack-declared member"
        );

        let scala = BoundaryFixture::with_config(
            Language::Scala,
            "app/Caller.scala",
            SCALA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        activate_fixture_pack(
            &scala,
            "fixture.jdk",
            &jdk_collections_pack(collections_sort_member()),
            activation_evidence("java", "jdk", "java.base"),
        );
        let analyzer = scala.workspace.analyzer();
        let evidence =
            crate::analyzer::resolve_analyzer::<crate::analyzer::ScalaAnalyzer>(analyzer)
                .expect("the Scala fixture has a Scala analyzer")
                .external_boundary_evidence(
                    token,
                    analyzer.semantic_model_overlay(),
                    &scala.file,
                    "Collections.sort",
                );
        assert_eq!(
            evidence,
            (
                BoundaryStatus::ExternalIndexed,
                Some("java.util.Collections.sort".to_owned())
            ),
            "Scala's import ladder reaches the pack-declared member"
        );
    }

    #[test]
    #[hardwon(
        "#6103: a semantic-model provider counted as a complete inventory and proved a constructor absent"
    )]
    fn kotlin_model_only_constructor_retains_external_type_boundary() {
        use crate::analyzer::semantic_model::{
            CatalogOptions, CompilerOptions, DurablePackSource, DurablePackSourceKind,
            SemanticPackCatalog, SourceFormat, compile_source,
        };

        // Match the policy fixture's workspace-installed model, without pack
        // acquisition. Merely writing this file does not activate the model.
        let model = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../semantic-packs/web-network/jvm/bifrost.web-network-jvm.json"
        ));
        let fixture = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            "package app\nimport java.net.URL\nfun use(x: String): URL = URL(x)\n",
            |root| {
                let models = root.join(".bifrost/semantic-models");
                std::fs::create_dir_all(&models).unwrap();
                std::fs::write(models.join("bifrost.web-network-jvm.json"), model).unwrap();
                jvm_config_with_artifact_jar(None)
            },
        );
        let pack = compile_source(
            SourceFormat::Json,
            model.as_bytes(),
            &CompilerOptions::default(),
        )
        .expect("compile reviewed JVM model");
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "workspace-network-model".into(),
                },
            )
            .unwrap();
        activate_fixture_catalog(
            &fixture,
            &catalog,
            "bifrost.web-network-jvm",
            activation_evidence("java", "jdk", "java.base"),
        );
        for needle in ["URL =", "URL(x)"] {
            let (outcome, trace) = fixture.trace_via_probe_entry_point(needle);
            assert_eq!(
                outcome.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "{needle}: {outcome:#?} {trace:#?}"
            );
            let routes = external_routes(&trace);
            assert!(
                routes
                    .iter()
                    .all(|(_, target)| target.as_deref() == Some("java.net.URL")),
                "{routes:#?}"
            );
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

pub use crate::analyzer::resolution::trace_vocabulary::{
    CallableApplicabilityRecord, HierarchyHopRecord, MemberEnrichment, TraceCandidate,
    TraceCandidateRef, WILDCARD_ROUTE_NAME,
};

struct EngineResolutionDiagnostics;

impl crate::analyzer::resolution::ResolutionDiagnostics for EngineResolutionDiagnostics {
    fn recording(&self) -> bool {
        recording()
    }

    fn native_rejection_projection_active(&self) -> bool {
        native_rejection_projection_active()
    }
}

pub(crate) fn resolution_diagnostics()
-> &'static dyn crate::analyzer::resolution::ResolutionDiagnostics {
    &EngineResolutionDiagnostics
}
