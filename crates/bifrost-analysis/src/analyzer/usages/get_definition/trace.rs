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
#[doc(hidden)]
pub fn begin_native_trace() {
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

#[doc(hidden)]
/// Append one row. Callers guard with [`recording`] before building the row.
pub fn record(candidate: TraceCandidate) {
    record_all([candidate]);
}

#[doc(hidden)]
pub fn record_all(rows: impl IntoIterator<Item = TraceCandidate>) {
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

#[doc(hidden)]
/// Stage the member and callable facts for a selection. The walk supplies its
/// own enrichment function; an absent callable verdict stays unknown on the
/// member axis and absent on the callable axis.
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

#[doc(hidden)]
/// Record a rejected workspace candidate with the attribution the resolver
/// already knows at this discard point.
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

#[doc(hidden)]
/// Stage callable-applicability attribution for the next outcome constructor
/// whose candidates the map names (#1478). Callers guard with [`recording`]
/// before building the entries.
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
#[doc(hidden)]
pub fn staged_member_context() -> Vec<(String, MemberEnrichment)> {
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
#[doc(hidden)]
pub struct DeepScope {
    previous: Option<String>,
}

impl DeepScope {
    #[doc(hidden)]
    pub fn enter(name: &str) -> Self {
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
#[doc(hidden)]
pub fn deep_scope_is(name: &str) -> bool {
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
            let evidence = crate::analyzer::languages::language_support_for_hook(
                language,
                "definition_boundary_evidence",
            )
            .and_then(|support| support.definition_boundary_evidence(analyzer, token, file, name));
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
            crate::analyzer::languages::language_support_for_hook(
                language_for_file(file),
                "definition_boundary_evidence",
            )
            .and_then(|support| support.definition_boundary_evidence(analyzer, token, file, name))
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
    crate::analyzer::languages::language_support_for_hook(
        language,
        "definition_declared_import_route",
    )
    .is_some_and(|support| {
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
