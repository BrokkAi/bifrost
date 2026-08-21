//! Declarative effect rows: source-derived direct effects at a call site and
//! bounded transitive effect summaries for a procedure (issue #2437, slice 2).
//!
//! Milestone 4 gave a reviewed semantic-model pack the ability to attach
//! namespaced effect identifiers to an exact procedure identity
//! (`declared_effects` on a compiled procedure summary). This module is the
//! consumption half: it turns those declarations into two addressable row
//! domains.
//!
//! - `call_effect`: one row per (call site, dispatch arm, declared effect).
//!   The call's dispatch answer is the analyzer's own — proof, completeness and
//!   the site's candidate coverage are copied from it, never re-derived — and
//!   the effect is whatever the activated pack declares for the arm's callee.
//! - `procedure_effect`: one row per (procedure, effect id), computed by a
//!   bounded deterministic fixpoint over the same call edges.
//!
//! Three rules are load-bearing and mirror the `call_binding` discipline.
//!
//! - Both reports are mandatory. A call site whose effects could not be
//!   established, and a procedure whose reachable call graph could not be
//!   walked, still produce exactly one terminal row carrying the typed reason,
//!   so zero rows can never be read as "nothing here has an effect".
//! - Coverage is a column, repeated on every row of a site or a procedure, so
//!   one row alone is enough to reject an absence claim.
//! - Certainty is the meet of what the pack claims and what dispatch proved. A
//!   possible dispatch never yields a definite effect row, and a `possible`
//!   declaration never becomes definite because dispatch happened to be proven.
//!
//! Nothing here reads source text or resolves a name. The caller supplies the
//! already-resolved callee identity, the already-computed dispatch quality, and
//! the pack's own declarations; this module is the algebra over them.

use std::collections::BTreeMap;

use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmRequest, DenseBidirectionalGraph, strongly_connected_components,
};
use crate::analyzer::semantic_model::{
    CompiledDeclaredEffect, CompiledDeclaredEffectCertainty, CompiledDeclaredEffectTiming,
};
use crate::analyzer::{CodeUnit, ProjectFile, Range};
use crate::cancellation::CancellationToken;

/// Domain separator for one direct call-effect row id.
const CALL_EFFECT_ID_DOMAIN: &[u8] = b"bifrost.code_query.call_effect.v1";
/// Domain separator for one procedure-effect summary row id.
const PROCEDURE_EFFECT_ID_DOMAIN: &[u8] = b"bifrost.code_query.procedure_effect.v1";

macro_rules! effect_enum {
    ($(#[$meta:meta])* $name:ident, $all:ident { $($variant:ident => $label:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($variant,)+
        }

        pub const $all: &[$name] = &[$($name::$variant,)+];

        impl $name {
            pub const fn label(self) -> &'static str {
                match self {
                    $($name::$variant => $label,)+
                }
            }

            pub fn from_label(label: &str) -> Option<$name> {
                $all.iter().copied().find(|value| value.label() == label)
            }
        }
    };
}

effect_enum! {
    /// How far the effect is from the row's subject.
    ///
    /// A `call_effect` row is always `Direct`: it names the exact call whose
    /// callee the pack models. A `procedure_effect` row is `Direct` when the
    /// declaring procedure is the subject itself or a callee written in the
    /// subject's own body, and `Transitive` when at least one intermediate
    /// procedure sits between them.
    EffectClassification, ALL_EFFECT_CLASSIFICATIONS {
        Direct => "direct",
        Transitive => "transitive",
    }
}

effect_enum! {
    /// When the effect happens relative to the call that establishes it.
    ///
    /// This is the pack's own claim, propagated unchanged along call edges. An
    /// effect reached only through a `Deferred` declaration stays deferred: the
    /// join below never launders `Deferred` into `Immediate`.
    EffectTiming, ALL_EFFECT_TIMINGS {
        Immediate => "immediate",
        Deferred => "deferred",
        Unknown => "unknown",
    }
}

effect_enum! {
    /// How firmly the effect is attributed.
    ///
    /// `Definite` requires both halves: the pack claims every execution
    /// performs the effect, and every dispatch step along the attributing chain
    /// was proven and exhaustive. Any weakness on either axis yields
    /// `Possible`.
    EffectCertainty, ALL_EFFECT_CERTAINTIES {
        Definite => "definite",
        Possible => "possible",
    }
}

effect_enum! {
    /// What one row states.
    ///
    /// - `Declared`: the row names one effect an activated pack declares for
    ///   the resolved callee (`call_effect`) or for a procedure reachable from
    ///   the subject (`procedure_effect`).
    /// - `None`: the terminal row of a subject whose derivation completed and
    ///   found no declared effect. This is the only row that means "no effect
    ///   here", and it only means it when `coverage` is `exhaustive`.
    /// - `Incomplete`: the terminal row of a subject whose derivation could not
    ///   be completed. `reason` says why.
    /// - `Unsupported`: the terminal row of a subject the analyzer cannot
    ///   derive effects for at all.
    EffectDerivation, ALL_EFFECT_DERIVATIONS {
        Declared => "declared",
        None => "none",
        Incomplete => "incomplete",
        Unsupported => "unsupported",
    }
}

effect_enum! {
    /// Why an effect derivation is not exhaustive. An exhaustive derivation
    /// states none.
    ///
    /// - `DispatchUnresolved`: dispatch named no target, or named a target the
    ///   workspace does not index, so a callee could carry an effect nobody
    ///   asked about.
    /// - `DispatchTruncated`: the dispatch candidate set hit a bound.
    /// - `DispatchUnsupported`: the language or the semantic provider cannot
    ///   answer dispatch here.
    /// - `DispatchInterrupted`: dispatch was cancelled or exceeded a budget.
    /// - `CalleeUnkeyable`: a target exists but no canonical procedure identity
    ///   could be built for it, so no pack declaration can be looked up.
    /// - `ModelConflict`: several activated packs disagree about the callee, so
    ///   the runtime resolved the lookup to `Conflict` and nothing is claimed.
    /// - `CalleeUnmodeled`: the callee resolves outside the workspace and no
    ///   activated pack models it, so its effects are unknown.
    /// - `ProcedureBudgetExhausted`: the fixpoint reached its procedure,
    ///   depth or iteration bound.
    /// - `EffectBudgetExhausted`: one procedure carried more distinct effects
    ///   than the per-procedure bound retains.
    /// - `ProcedureUnreadable`: the subject declaration's own body could not be
    ///   read, so its call sites were never enumerated.
    EffectReason, ALL_EFFECT_REASONS {
        DispatchUnresolved => "dispatch_unresolved",
        DispatchTruncated => "dispatch_truncated",
        DispatchUnsupported => "dispatch_unsupported",
        DispatchInterrupted => "dispatch_interrupted",
        CalleeUnkeyable => "callee_unkeyable",
        ModelConflict => "model_conflict",
        CalleeUnmodeled => "callee_unmodeled",
        ProcedureBudgetExhausted => "procedure_budget_exhausted",
        EffectBudgetExhausted => "effect_budget_exhausted",
        ProcedureUnreadable => "procedure_unreadable",
    }
}

effect_enum! {
    /// Completeness of the effect set the row's subject publishes.
    ///
    /// `Exhaustive` is the only value under which an absence of `Declared` rows
    /// is a claim that the subject has no effect. Everything else says a row
    /// could be missing.
    EffectCoverage, ALL_EFFECT_COVERAGES {
        Exhaustive => "exhaustive",
        Open => "open",
        Truncated => "truncated",
        Unsupported => "unsupported",
    }
}

effect_enum! {
    /// The dispatch proof one `call_effect` row inherited.
    ///
    /// This is the arm's own `proof` label from the dispatch answer, repeated
    /// so an effect row is self-contained: a policy never has to fetch the
    /// sibling `dispatch_target` row to know whether the callee was proven.
    EffectProof, ALL_EFFECT_PROOFS {
        Proven => "proven",
        Unproven => "unproven",
    }
}

impl EffectCoverage {
    /// The weaker of two coverages. `Unsupported` dominates, then `Truncated`,
    /// then `Open`.
    pub fn meet(self, other: Self) -> Self {
        let rank = |value: Self| match value {
            Self::Exhaustive => 0,
            Self::Open => 1,
            Self::Truncated => 2,
            Self::Unsupported => 3,
        };
        if rank(other) > rank(self) {
            other
        } else {
            self
        }
    }

    pub const fn is_exhaustive(self) -> bool {
        matches!(self, Self::Exhaustive)
    }
}

impl EffectCertainty {
    /// The weaker of two certainties: `Possible` absorbs.
    ///
    /// This is the meet the plan requires at a single attribution step — a
    /// possible dispatch never yields a definite effect row.
    pub const fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Definite, Self::Definite) => Self::Definite,
            _ => Self::Possible,
        }
    }

    /// The stronger of two certainties, used when several chains attribute one
    /// effect to one procedure: the best-evidenced chain is what the row
    /// reports, because certainty here measures attribution evidence and not
    /// execution frequency.
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Possible, Self::Possible) => Self::Possible,
            _ => Self::Definite,
        }
    }
}

impl EffectTiming {
    /// The join of two timings reaching one procedure for one effect.
    ///
    /// Equal timings survive; a disagreement becomes `Unknown`. Nothing ever
    /// becomes `Immediate` that was not already immediate on every retained
    /// path, which is what keeps a deferred callback from being laundered into
    /// a synchronous claim.
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Immediate, Self::Immediate) => Self::Immediate,
            (Self::Deferred, Self::Deferred) => Self::Deferred,
            _ => Self::Unknown,
        }
    }

    pub const fn from_compiled(timing: CompiledDeclaredEffectTiming) -> Self {
        match timing {
            CompiledDeclaredEffectTiming::Immediate => Self::Immediate,
            CompiledDeclaredEffectTiming::Deferred => Self::Deferred,
            CompiledDeclaredEffectTiming::Unknown => Self::Unknown,
        }
    }
}

impl EffectCertainty {
    pub const fn from_compiled(certainty: CompiledDeclaredEffectCertainty) -> Self {
        match certainty {
            CompiledDeclaredEffectCertainty::Definite => Self::Definite,
            CompiledDeclaredEffectCertainty::Possible => Self::Possible,
        }
    }
}

/// The canonical identity a semantic-model pack declaration is looked up by.
///
/// This is the `(language, owner FQN, member, has_receiver, parameter_count)`
/// key issue #1978 introduced for unmaterialized external callees, reused
/// verbatim so an effect declaration and a data-flow summary select the same
/// procedure by the same rule. It is a qualified identity: an owner-less name
/// never produces a key, so nothing here can degrade into unqualified
/// method-name matching.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModeledProcedureKey {
    pub language: String,
    pub owner: String,
    pub member: String,
    pub has_receiver: bool,
    pub parameter_count: u32,
}

impl ModeledProcedureKey {
    /// The human-readable spelling of this key, retained on rows as the
    /// modeled-target text identity.
    pub fn display(&self) -> String {
        format!(
            "{}.{}/{}{}",
            self.owner,
            self.member,
            self.parameter_count,
            if self.has_receiver { "+recv" } else { "" }
        )
    }
}

/// One activated declaration bound to one exact callee, with the pack
/// provenance the row publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundDeclaredEffect {
    pub effect_id: String,
    pub timing: EffectTiming,
    pub certainty: EffectCertainty,
    pub pack_id: String,
    pub model_id: String,
    pub summary_id: String,
}

impl BoundDeclaredEffect {
    pub fn new(
        effect: &CompiledDeclaredEffect,
        pack_id: impl Into<String>,
        model_id: impl Into<String>,
        summary_id: impl Into<String>,
    ) -> Self {
        Self {
            effect_id: effect.id.clone(),
            timing: EffectTiming::from_compiled(effect.timing),
            certainty: EffectCertainty::from_compiled(effect.certainty),
            pack_id: pack_id.into(),
            model_id: model_id.into(),
            summary_id: summary_id.into(),
        }
    }
}

/// What the caller established about one dispatch arm of one call site.
///
/// Everything on this struct is copied from the analyzer's own dispatch answer
/// or from the activated pack; this module re-derives none of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEffectArm {
    /// The arm's semantic target identity, equal to `dispatch_target.target_id`.
    pub target_id: String,
    /// The workspace declaration identity of the callee, when the workspace
    /// indexes one.
    pub callee_declaration_id: Option<String>,
    /// The canonical key the declaration lookup used, when one could be built.
    pub key: Option<ModeledProcedureKey>,
    pub proof: EffectProof,
    /// Whether the arm's own evidence is complete, from the dispatch answer.
    pub complete: bool,
    /// What the activated pack lookup answered for this arm.
    pub lookup: ArmLookup,
}

/// The activated-pack answer for one arm's callee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArmLookup {
    /// A unique activated summary models the callee; these are its
    /// declarations, in the compiler's canonical order.
    Declared(Vec<BoundDeclaredEffect>),
    /// No canonical key could be built for the arm's target.
    Unkeyable,
    /// Several activated summaries disagree about the callee.
    Conflict,
    /// A key exists and no activated pack declares anything for it. Whether
    /// this is a coverage gap depends on `analyzable`: a workspace procedure
    /// with a body is covered by propagation, an external callee is not.
    Unmodeled { analyzable: bool },
}

/// One direct effect row of one call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEffectRow {
    pub id: String,
    pub site_id: String,
    pub site_ast_id: String,
    pub range: Range,
    pub target_id: Option<String>,
    pub callee_declaration_id: Option<String>,
    pub callee_symbol: Option<String>,
    pub effect_id: Option<String>,
    pub classification: EffectClassification,
    pub timing: Option<EffectTiming>,
    pub certainty: Option<EffectCertainty>,
    pub proof: Option<EffectProof>,
    pub derivation: EffectDerivation,
    pub reason: Option<EffectReason>,
    pub pack_id: Option<String>,
    pub model_id: Option<String>,
    pub summary_id: Option<String>,
    pub terminal: bool,
}

/// Every direct effect row of one call site, plus the site-wide facts each row
/// repeats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEffectReport {
    pub file: ProjectFile,
    pub site_id: String,
    pub site_ast_id: String,
    /// The site's candidate coverage, met with every arm's own gaps.
    pub coverage: EffectCoverage,
    /// How many dispatch arms the site published.
    pub arm_count: usize,
    /// How many arms a unique activated summary modeled.
    pub modeled_arm_count: usize,
    pub rows: Vec<CallEffectRow>,
}

/// The site-level status the caller already knows before any arm is examined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallEffectSiteStatus {
    /// Dispatch produced an answer; `coverage` is its candidate coverage.
    Answered { coverage: EffectCoverage },
    /// Dispatch never ran to a published answer.
    Interrupted { reason: EffectReason },
}

/// Derive the direct effect rows of one call site.
///
/// The report is mandatory: a site with no modeled arm still yields exactly one
/// terminal row, so zero rows can never be read as "this call has no effect".
pub fn call_effect_report(
    file: &ProjectFile,
    site_id: &str,
    site_ast_id: &str,
    range: Range,
    status: CallEffectSiteStatus,
    arms: &[CallEffectArm],
) -> CallEffectReport {
    let mut coverage = match status {
        CallEffectSiteStatus::Answered { coverage } => coverage,
        CallEffectSiteStatus::Interrupted { .. } => EffectCoverage::Open,
    };
    let interrupted = match status {
        CallEffectSiteStatus::Answered { .. } => None,
        CallEffectSiteStatus::Interrupted { reason } => Some(reason),
    };
    if let Some(reason) = interrupted
        && reason == EffectReason::DispatchUnsupported
    {
        coverage = EffectCoverage::Unsupported;
    }

    // Definite attribution needs all three axes the dispatch answer publishes,
    // exactly as `DispatchSiteAnswer::dispatch_label` does: an exhaustive
    // candidate set with one arm in it, and that arm proven and complete. A
    // second candidate, or a set that may hold an unseen one, means this call
    // may reach a different callee, so the effect is possible even when the arm
    // itself is proven.
    let site_definite = coverage.is_exhaustive() && arms.len() == 1;
    let mut rows = Vec::new();
    let mut modeled_arm_count = 0usize;
    let mut gap: Option<EffectReason> = None;
    for arm in arms {
        if !arm.complete {
            gap = gap.or(Some(EffectReason::DispatchUnresolved));
            coverage = coverage.meet(EffectCoverage::Open);
        }
        match &arm.lookup {
            ArmLookup::Declared(effects) => {
                modeled_arm_count = modeled_arm_count.saturating_add(1);
                for effect in effects {
                    rows.push(declared_call_effect_row(
                        site_id,
                        site_ast_id,
                        range,
                        arm,
                        effect,
                        site_definite,
                    ));
                }
            }
            ArmLookup::Unkeyable => {
                gap = gap.or(Some(EffectReason::CalleeUnkeyable));
                coverage = coverage.meet(EffectCoverage::Open);
            }
            ArmLookup::Conflict => {
                gap = gap.or(Some(EffectReason::ModelConflict));
                coverage = coverage.meet(EffectCoverage::Open);
            }
            ArmLookup::Unmodeled { analyzable } => {
                if !analyzable {
                    gap = gap.or(Some(EffectReason::CalleeUnmodeled));
                    coverage = coverage.meet(EffectCoverage::Open);
                }
            }
        }
    }
    if let Some(reason) = interrupted {
        gap = Some(reason);
    }
    if arms.is_empty() && interrupted.is_none() && !coverage.is_exhaustive() {
        gap = gap.or(Some(EffectReason::DispatchUnresolved));
    }
    if coverage == EffectCoverage::Truncated {
        gap = gap.or(Some(EffectReason::DispatchTruncated));
    }

    if rows.is_empty() {
        let derivation = if interrupted == Some(EffectReason::DispatchUnsupported) {
            EffectDerivation::Unsupported
        } else if gap.is_some() {
            EffectDerivation::Incomplete
        } else {
            EffectDerivation::None
        };
        rows.push(CallEffectRow {
            id: call_effect_row_id(site_id, None, None),
            site_id: site_id.to_owned(),
            site_ast_id: site_ast_id.to_owned(),
            range,
            target_id: None,
            callee_declaration_id: None,
            callee_symbol: None,
            effect_id: None,
            classification: EffectClassification::Direct,
            timing: None,
            certainty: None,
            proof: None,
            derivation,
            reason: gap,
            pack_id: None,
            model_id: None,
            summary_id: None,
            terminal: true,
        });
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    CallEffectReport {
        file: file.clone(),
        site_id: site_id.to_owned(),
        site_ast_id: site_ast_id.to_owned(),
        coverage,
        arm_count: arms.len(),
        modeled_arm_count,
        rows,
    }
}

fn declared_call_effect_row(
    site_id: &str,
    site_ast_id: &str,
    range: Range,
    arm: &CallEffectArm,
    effect: &BoundDeclaredEffect,
    site_definite: bool,
) -> CallEffectRow {
    // The meet is the whole certainty rule: a `possible` declaration stays
    // possible under a proven dispatch, and a `definite` declaration is
    // downgraded by an unproven or incomplete arm, or by a candidate set that
    // may hold another callee.
    let dispatch_certainty = if site_definite && arm.proof == EffectProof::Proven && arm.complete {
        EffectCertainty::Definite
    } else {
        EffectCertainty::Possible
    };
    CallEffectRow {
        id: call_effect_row_id(site_id, Some(&arm.target_id), Some(&effect.effect_id)),
        site_id: site_id.to_owned(),
        site_ast_id: site_ast_id.to_owned(),
        range,
        target_id: Some(arm.target_id.clone()),
        callee_declaration_id: arm.callee_declaration_id.clone(),
        callee_symbol: arm.key.as_ref().map(ModeledProcedureKey::display),
        effect_id: Some(effect.effect_id.clone()),
        classification: EffectClassification::Direct,
        timing: Some(effect.timing),
        certainty: Some(effect.certainty.meet(dispatch_certainty)),
        proof: Some(arm.proof),
        derivation: EffectDerivation::Declared,
        reason: None,
        pack_id: Some(effect.pack_id.clone()),
        model_id: Some(effect.model_id.clone()),
        summary_id: Some(effect.summary_id.clone()),
        terminal: false,
    }
}

fn call_effect_row_id(site_id: &str, target_id: Option<&str>, effect_id: Option<&str>) -> String {
    let mut digest = LengthDelimitedDigest::new(CALL_EFFECT_ID_DOMAIN);
    digest.push(site_id.as_bytes());
    match target_id {
        Some(target) => {
            digest.push(b"target");
            digest.push(target.as_bytes());
        }
        None => digest.push(b"terminal"),
    }
    match effect_id {
        Some(effect) => {
            digest.push(b"effect");
            digest.push(effect.as_bytes());
        }
        None => digest.push(b"no_effect"),
    }
    digest.finish().to_string()
}

// ---------------------------------------------------------------------------
// Procedure effect summaries
// ---------------------------------------------------------------------------

/// Explicit bounds on the transitive fixpoint.
///
/// Every bound is stated rather than defaulted at a call site, and every one of
/// them degrades a procedure's coverage instead of silently truncating an
/// answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcedureEffectBudget {
    /// How many distinct procedures the reachable call graph may hold.
    pub max_procedures: usize,
    /// How many call edges the graph may hold in total.
    pub max_edges: usize,
    /// How many call hops the walk may take from a seed procedure.
    pub max_depth: usize,
    /// How many distinct effect ids one procedure may publish.
    pub max_effects_per_procedure: usize,
    /// How many hops one retained witness chain may hold.
    pub max_witness_steps: usize,
    /// How many fixpoint sweeps the solver may run before it declares the
    /// answer truncated. A converging graph needs at most one sweep per
    /// component in reverse topological order; the bound exists so a
    /// pathological input cannot spin.
    pub max_iterations: usize,
}

impl Default for ProcedureEffectBudget {
    fn default() -> Self {
        Self {
            max_procedures: 4_096,
            max_edges: 32_768,
            max_depth: 32,
            max_effects_per_procedure: 64,
            max_witness_steps: 16,
            max_iterations: 64,
        }
    }
}

/// One node of the reachable call graph the fixpoint runs over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectGraphProcedure {
    /// The procedure's stable declaration identity.
    pub declaration_id: String,
    /// A bounded display name, retained for the witness chain.
    pub display_name: String,
    /// Effects an activated pack declares for this procedure itself.
    pub declared: Vec<BoundDeclaredEffect>,
    /// Whether the procedure's own body was read and its call sites
    /// enumerated. A procedure nobody could read makes every absence claim
    /// through it non-exhaustive.
    pub body_read: bool,
    /// Typed gaps found while enumerating this procedure's call sites.
    pub local_gaps: Vec<EffectReason>,
}

/// One call edge of the reachable call graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectGraphEdge {
    /// Index into the procedure list.
    pub caller: usize,
    /// Index into the procedure list.
    pub callee: usize,
    /// The `call_shape` site identity of the call that creates this edge, so a
    /// witness step joins the `call_effect` and `call_shape` domains by id.
    pub site_id: String,
    /// Whether dispatch proved this exact edge and nothing else.
    pub certainty: EffectCertainty,
}

/// The reachable call graph of one query's procedures.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectGraph {
    pub procedures: Vec<EffectGraphProcedure>,
    pub edges: Vec<EffectGraphEdge>,
    /// Whether discovery itself hit a bound.
    pub truncated: bool,
}

/// One retained witness step: the call site that carries the hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectWitnessStep {
    pub site_id: String,
    pub callee_display_name: String,
}

/// One procedure-effect summary row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureEffectRow {
    pub id: String,
    pub procedure_declaration_id: String,
    pub procedure_name: String,
    pub effect_id: Option<String>,
    pub classification: Option<EffectClassification>,
    pub certainty: Option<EffectCertainty>,
    pub timing: Option<EffectTiming>,
    /// Call hops from this procedure to the procedure the pack declares the
    /// effect on. `0` means the pack declares it on this procedure itself.
    pub depth: Option<usize>,
    pub derivation: EffectDerivation,
    pub reason: Option<EffectReason>,
    pub coverage: EffectCoverage,
    /// The retained witness chain, from this procedure outward, bounded by
    /// `max_witness_steps`.
    pub witness: Vec<EffectWitnessStep>,
    pub witness_truncated: bool,
    pub pack_id: Option<String>,
    pub model_id: Option<String>,
    pub summary_id: Option<String>,
    pub terminal: bool,
}

impl ProcedureEffectRow {
    /// The call site that establishes the effect: the last retained witness
    /// step, or none when the pack declares the effect on this procedure.
    pub fn witness_effect_site_id(&self) -> Option<&str> {
        self.witness.last().map(|step| step.site_id.as_str())
    }

    /// The first hop out of this procedure, when the chain has one.
    pub fn witness_site_id(&self) -> Option<&str> {
        self.witness.first().map(|step| step.site_id.as_str())
    }

    /// The bounded rendered chain a reader sees, `A -> B -> C`.
    pub fn witness_chain(&self) -> Option<String> {
        if self.witness.is_empty() {
            return None;
        }
        let mut rendered = self.procedure_name.clone();
        for step in &self.witness {
            rendered.push_str(" -> ");
            rendered.push_str(&step.callee_display_name);
        }
        if self.witness_truncated {
            rendered.push_str(" -> …");
        }
        Some(rendered)
    }
}

/// One procedure's complete summary: at least one row, always.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureEffectReport {
    pub procedure_declaration_id: String,
    pub coverage: EffectCoverage,
    pub rows: Vec<ProcedureEffectRow>,
}

/// One effect attributed to one procedure during the fixpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AttributedEffect {
    depth: usize,
    certainty: EffectCertainty,
    timing: EffectTiming,
    witness: Vec<EffectWitnessStep>,
    witness_truncated: bool,
    pack_id: String,
    model_id: String,
    summary_id: String,
}

impl AttributedEffect {
    /// Merge another attribution of the same effect onto the same procedure.
    ///
    /// The retained witness is the shallowest chain, and ties break on the
    /// chain's own site ids, so the answer does not depend on visit order.
    /// Certainty joins to the best-evidenced chain; timing joins to `Unknown`
    /// on disagreement, which is what keeps a deferred path from being
    /// laundered into an immediate claim.
    fn merge(&mut self, other: Self) -> bool {
        let mut changed = false;
        let certainty = self.certainty.join(other.certainty);
        if certainty != self.certainty {
            self.certainty = certainty;
            changed = true;
        }
        let timing = self.timing.join(other.timing);
        if timing != self.timing {
            self.timing = timing;
            changed = true;
        }
        let better =
            (other.depth, witness_key(&other.witness)) < (self.depth, witness_key(&self.witness));
        if better {
            self.depth = other.depth;
            self.witness = other.witness;
            self.witness_truncated = other.witness_truncated;
            self.pack_id = other.pack_id;
            self.model_id = other.model_id;
            self.summary_id = other.summary_id;
            changed = true;
        }
        changed
    }
}

fn witness_key(witness: &[EffectWitnessStep]) -> Vec<&str> {
    witness.iter().map(|step| step.site_id.as_str()).collect()
}

/// The dense call graph the SCC pass runs over.
#[derive(Debug)]
struct CallGraphView {
    outgoing: Vec<Vec<usize>>,
    incoming: Vec<Vec<usize>>,
    edges: Vec<(usize, usize)>,
}

impl CallGraphView {
    fn new(node_count: usize, edges: &[EffectGraphEdge]) -> Self {
        let mut pairs = edges
            .iter()
            .map(|edge| (edge.caller, edge.callee))
            .collect::<Vec<_>>();
        pairs.sort_unstable();
        pairs.dedup();
        let mut outgoing = vec![Vec::new(); node_count];
        let mut incoming = vec![Vec::new(); node_count];
        for (index, &(caller, callee)) in pairs.iter().enumerate() {
            outgoing[caller].push(index);
            incoming[callee].push(index);
        }
        Self {
            outgoing,
            incoming,
            edges: pairs,
        }
    }
}

impl DenseBidirectionalGraph for CallGraphView {
    type Node = usize;
    type Edge = usize;

    fn node_count(&self) -> usize {
        self.outgoing.len()
    }

    fn node_at(&self, index: usize) -> Option<Self::Node> {
        (index < self.outgoing.len()).then_some(index)
    }

    fn node_index(&self, node: Self::Node) -> Option<usize> {
        (node < self.outgoing.len()).then_some(node)
    }

    fn successors(
        &self,
        node: Self::Node,
    ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_ {
        self.outgoing[node]
            .iter()
            .copied()
            .map(|edge| (edge, self.edges[edge].1))
    }

    fn predecessors(
        &self,
        node: Self::Node,
    ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_ {
        self.incoming[node]
            .iter()
            .copied()
            .map(|edge| (edge, self.edges[edge].0))
    }

    fn edge_endpoints(&self, edge: Self::Edge) -> Option<(Self::Node, Self::Node)> {
        self.edges.get(edge).copied()
    }
}

/// Run the bounded deterministic fixpoint and project one report per procedure.
///
/// The algorithm is a reverse-topological sweep over the graph's strongly
/// connected components, using the analyzer's own
/// [`strongly_connected_components`] rather than a second cycle detector, so a
/// recursive cycle converges in a bounded number of sweeps instead of
/// recursing. Effects flow from callee to caller: a caller inherits every
/// effect of every callee, one hop deeper, with the edge's certainty met into
/// the effect's own.
///
/// Every bound is a coverage degradation, never a silent loss: a truncated
/// discovery, an exhausted per-procedure effect bound and an unconverged
/// fixpoint each mark the affected procedures non-exhaustive.
pub fn summarize_procedure_effects(
    graph: &EffectGraph,
    budget: ProcedureEffectBudget,
) -> Vec<ProcedureEffectReport> {
    let node_count = graph.procedures.len();
    let view = CallGraphView::new(node_count, &graph.edges);
    let cancellation = CancellationToken::new();
    let mut algorithm_budget = CfgAlgorithmBudget::default();
    let mut request = CfgAlgorithmRequest::new(&mut algorithm_budget, &cancellation);
    let components = strongly_connected_components(&view, &mut request)
        .map(|result| result.components)
        .unwrap_or_else(|_| {
            // The SCC pass is bounded like every other analyzer graph walk. If
            // it cannot finish, treat every procedure as its own component and
            // let the iteration bound below report the truncation, rather than
            // dropping the answer.
            (0..node_count)
                .map(|node| vec![node].into_boxed_slice())
                .collect()
        });

    let mut component_by_node = vec![0usize; node_count];
    for (component, members) in components.iter().enumerate() {
        for &member in members.iter() {
            component_by_node[member] = component;
        }
    }

    let mut effects: Vec<BTreeMap<String, AttributedEffect>> = graph
        .procedures
        .iter()
        .map(|procedure| {
            procedure
                .declared
                .iter()
                .map(|declared| {
                    (
                        declared.effect_id.clone(),
                        AttributedEffect {
                            depth: 0,
                            certainty: declared.certainty,
                            timing: declared.timing,
                            witness: Vec::new(),
                            witness_truncated: false,
                            pack_id: declared.pack_id.clone(),
                            model_id: declared.model_id.clone(),
                            summary_id: declared.summary_id.clone(),
                        },
                    )
                })
                .collect()
        })
        .collect();

    let mut effect_budget_exhausted = vec![false; node_count];
    let mut depth_exhausted = vec![false; node_count];
    let mut sweeps = 0usize;
    let mut unconverged = false;
    // `strongly_connected_components` publishes components in a canonical
    // order; sweeping them in reverse propagates a callee's answer to its
    // caller within one pass on an acyclic graph, and repeats only for cycles.
    loop {
        sweeps = sweeps.saturating_add(1);
        if sweeps > budget.max_iterations {
            unconverged = true;
            break;
        }
        let mut changed = false;
        for component in components.iter().rev() {
            for &node in component.iter() {
                for edge in &graph.edges {
                    if edge.caller != node {
                        continue;
                    }
                    let callee = edge.callee;
                    let inherited = effects[callee]
                        .iter()
                        .map(|(id, effect)| (id.clone(), effect.clone()))
                        .collect::<Vec<_>>();
                    for (effect_id, source) in inherited {
                        let depth = source.depth.saturating_add(1);
                        if depth > budget.max_depth {
                            depth_exhausted[node] = true;
                            continue;
                        }
                        let mut witness = Vec::with_capacity(source.witness.len() + 1);
                        witness.push(EffectWitnessStep {
                            site_id: edge.site_id.clone(),
                            callee_display_name: graph.procedures[callee].display_name.clone(),
                        });
                        witness.extend(source.witness.iter().cloned());
                        let witness_truncated =
                            source.witness_truncated || witness.len() > budget.max_witness_steps;
                        witness.truncate(budget.max_witness_steps);
                        let candidate = AttributedEffect {
                            depth,
                            certainty: source.certainty.meet(edge.certainty),
                            timing: source.timing,
                            witness,
                            witness_truncated,
                            pack_id: source.pack_id.clone(),
                            model_id: source.model_id.clone(),
                            summary_id: source.summary_id.clone(),
                        };
                        match effects[node].get_mut(&effect_id) {
                            Some(existing) => {
                                changed |= existing.merge(candidate);
                            }
                            None => {
                                if effects[node].len() >= budget.max_effects_per_procedure {
                                    effect_budget_exhausted[node] = true;
                                    continue;
                                }
                                effects[node].insert(effect_id, candidate);
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    // Coverage flows the same direction the effects do: a procedure that cannot
    // prove its own callees' effect sets cannot prove its own.
    let mut coverage = graph
        .procedures
        .iter()
        .enumerate()
        .map(|(node, procedure)| {
            let mut value = if procedure.body_read {
                EffectCoverage::Exhaustive
            } else {
                EffectCoverage::Open
            };
            if !procedure.local_gaps.is_empty() {
                value = value.meet(EffectCoverage::Open);
            }
            if graph.truncated || effect_budget_exhausted[node] || depth_exhausted[node] {
                value = value.meet(EffectCoverage::Truncated);
            }
            if unconverged {
                value = value.meet(EffectCoverage::Truncated);
            }
            value
        })
        .collect::<Vec<_>>();
    let mut local_reason = graph
        .procedures
        .iter()
        .enumerate()
        .map(|(node, procedure)| {
            if !procedure.body_read {
                return Some(EffectReason::ProcedureUnreadable);
            }
            if let Some(reason) = procedure.local_gaps.first() {
                return Some(*reason);
            }
            if effect_budget_exhausted[node] {
                return Some(EffectReason::EffectBudgetExhausted);
            }
            if graph.truncated || depth_exhausted[node] || unconverged {
                return Some(EffectReason::ProcedureBudgetExhausted);
            }
            None
        })
        .collect::<Vec<_>>();
    for _ in 0..=components.len() {
        let mut changed = false;
        for edge in &graph.edges {
            let callee = coverage[edge.callee];
            let merged = coverage[edge.caller].meet(callee);
            if merged != coverage[edge.caller] {
                coverage[edge.caller] = merged;
                changed = true;
            }
            if local_reason[edge.caller].is_none()
                && let Some(reason) = local_reason[edge.callee]
            {
                local_reason[edge.caller] = Some(reason);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    graph
        .procedures
        .iter()
        .enumerate()
        .map(|(node, procedure)| {
            let node_coverage = coverage[node];
            let mut rows = effects[node]
                .iter()
                .map(|(effect_id, effect)| ProcedureEffectRow {
                    id: procedure_effect_row_id(&procedure.declaration_id, Some(effect_id)),
                    procedure_declaration_id: procedure.declaration_id.clone(),
                    procedure_name: procedure.display_name.clone(),
                    effect_id: Some(effect_id.clone()),
                    classification: Some(if effect.depth <= 1 {
                        EffectClassification::Direct
                    } else {
                        EffectClassification::Transitive
                    }),
                    certainty: Some(effect.certainty),
                    timing: Some(effect.timing),
                    depth: Some(effect.depth),
                    derivation: EffectDerivation::Declared,
                    reason: None,
                    coverage: node_coverage,
                    witness: effect.witness.clone(),
                    witness_truncated: effect.witness_truncated,
                    pack_id: Some(effect.pack_id.clone()),
                    model_id: Some(effect.model_id.clone()),
                    summary_id: Some(effect.summary_id.clone()),
                    terminal: false,
                })
                .collect::<Vec<_>>();
            if rows.is_empty() {
                let reason = local_reason[node];
                rows.push(ProcedureEffectRow {
                    id: procedure_effect_row_id(&procedure.declaration_id, None),
                    procedure_declaration_id: procedure.declaration_id.clone(),
                    procedure_name: procedure.display_name.clone(),
                    effect_id: None,
                    classification: None,
                    certainty: None,
                    timing: None,
                    depth: None,
                    derivation: if node_coverage == EffectCoverage::Unsupported {
                        EffectDerivation::Unsupported
                    } else if reason.is_some() {
                        EffectDerivation::Incomplete
                    } else {
                        EffectDerivation::None
                    },
                    reason,
                    coverage: node_coverage,
                    witness: Vec::new(),
                    witness_truncated: false,
                    pack_id: None,
                    model_id: None,
                    summary_id: None,
                    terminal: true,
                });
            }
            rows.sort_by(|left, right| left.id.cmp(&right.id));
            ProcedureEffectReport {
                procedure_declaration_id: procedure.declaration_id.clone(),
                coverage: node_coverage,
                rows,
            }
        })
        .collect()
}

fn procedure_effect_row_id(declaration_id: &str, effect_id: Option<&str>) -> String {
    let mut digest = LengthDelimitedDigest::new(PROCEDURE_EFFECT_ID_DOMAIN);
    digest.push(declaration_id.as_bytes());
    match effect_id {
        Some(effect) => {
            digest.push(b"effect");
            digest.push(effect.as_bytes());
        }
        None => digest.push(b"terminal"),
    }
    digest.finish().to_string()
}

/// The canonical procedure key for one workspace declaration, or `None` when
/// the declaration carries no qualified owner.
///
/// The owner and member come from the declaration's own fully-qualified name
/// and never from a rendered call-site text, and the receiver shape and
/// parameter count come from the persisted signature contract. When the adapter
/// never recorded modifiers, the receiver shape is unknown and no key is built:
/// guessing would bind a static member's declaration to an instance member's
/// summary.
pub fn modeled_procedure_key(
    language: &str,
    unit: &CodeUnit,
    has_receiver: Option<bool>,
    parameter_count: Option<u32>,
) -> Option<ModeledProcedureKey> {
    let fq_name = unit.fq_name();
    let (owner, member) = crate::analyzer::semantic::split_qualified_member(&fq_name)?;
    Some(ModeledProcedureKey {
        language: language.to_owned(),
        owner: owner.to_owned(),
        member: member.to_owned(),
        has_receiver: has_receiver?,
        parameter_count: parameter_count?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::ProjectFile;
    use std::env;

    fn file() -> ProjectFile {
        ProjectFile::new(env::temp_dir().join("bifrost-effects"), "App.java")
    }

    fn range() -> Range {
        Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 0,
            end_line: 0,
        }
    }

    fn declared(id: &str, timing: EffectTiming, certainty: EffectCertainty) -> BoundDeclaredEffect {
        BoundDeclaredEffect {
            effect_id: id.to_owned(),
            timing,
            certainty,
            pack_id: "acme.effects".to_owned(),
            model_id: "acme.effects/1.0.0".to_owned(),
            summary_id: "summary.send".to_owned(),
        }
    }

    fn arm(target: &str, proof: EffectProof, lookup: ArmLookup) -> CallEffectArm {
        CallEffectArm {
            target_id: target.to_owned(),
            callee_declaration_id: Some(format!("decl:{target}")),
            key: Some(ModeledProcedureKey {
                language: "java".to_owned(),
                owner: "com.acme.AcmeHttpClient".to_owned(),
                member: "send".to_owned(),
                has_receiver: true,
                parameter_count: 1,
            }),
            proof,
            complete: proof == EffectProof::Proven,
            lookup,
        }
    }

    #[test]
    fn a_proven_arm_and_a_definite_declaration_yield_a_definite_direct_row() {
        let report = call_effect_report(
            &file(),
            "site",
            "ast",
            range(),
            CallEffectSiteStatus::Answered {
                coverage: EffectCoverage::Exhaustive,
            },
            &[arm(
                "target",
                EffectProof::Proven,
                ArmLookup::Declared(vec![declared(
                    "acme.network_io",
                    EffectTiming::Immediate,
                    EffectCertainty::Definite,
                )]),
            )],
        );
        assert_eq!(report.rows.len(), 1);
        let row = &report.rows[0];
        assert_eq!(row.derivation, EffectDerivation::Declared);
        assert_eq!(row.certainty, Some(EffectCertainty::Definite));
        assert_eq!(row.classification, EffectClassification::Direct);
        assert_eq!(report.coverage, EffectCoverage::Exhaustive);
        assert!(!row.terminal);
    }

    #[test]
    fn an_unproven_arm_downgrades_a_definite_declaration_to_possible() {
        let report = call_effect_report(
            &file(),
            "site",
            "ast",
            range(),
            CallEffectSiteStatus::Answered {
                coverage: EffectCoverage::Open,
            },
            &[arm(
                "target",
                EffectProof::Unproven,
                ArmLookup::Declared(vec![declared(
                    "acme.network_io",
                    EffectTiming::Immediate,
                    EffectCertainty::Definite,
                )]),
            )],
        );
        assert_eq!(report.rows[0].certainty, Some(EffectCertainty::Possible));
        assert_eq!(report.coverage, EffectCoverage::Open);
    }

    #[test]
    fn a_proven_arm_never_promotes_a_possible_declaration() {
        let report = call_effect_report(
            &file(),
            "site",
            "ast",
            range(),
            CallEffectSiteStatus::Answered {
                coverage: EffectCoverage::Exhaustive,
            },
            &[arm(
                "target",
                EffectProof::Proven,
                ArmLookup::Declared(vec![declared(
                    "acme.network_io",
                    EffectTiming::Immediate,
                    EffectCertainty::Possible,
                )]),
            )],
        );
        assert_eq!(report.rows[0].certainty, Some(EffectCertainty::Possible));
    }

    #[test]
    fn a_site_with_no_declared_effect_still_states_its_status() {
        let report = call_effect_report(
            &file(),
            "site",
            "ast",
            range(),
            CallEffectSiteStatus::Answered {
                coverage: EffectCoverage::Exhaustive,
            },
            &[arm(
                "target",
                EffectProof::Proven,
                ArmLookup::Unmodeled { analyzable: true },
            )],
        );
        assert_eq!(report.rows.len(), 1);
        assert!(report.rows[0].terminal);
        assert_eq!(report.rows[0].derivation, EffectDerivation::None);
        assert_eq!(report.rows[0].reason, None);
        assert_eq!(report.coverage, EffectCoverage::Exhaustive);
    }

    #[test]
    fn an_unmodeled_external_callee_opens_the_sites_coverage() {
        let report = call_effect_report(
            &file(),
            "site",
            "ast",
            range(),
            CallEffectSiteStatus::Answered {
                coverage: EffectCoverage::Exhaustive,
            },
            &[arm(
                "target",
                EffectProof::Proven,
                ArmLookup::Unmodeled { analyzable: false },
            )],
        );
        assert_eq!(report.coverage, EffectCoverage::Open);
        assert_eq!(report.rows[0].derivation, EffectDerivation::Incomplete);
        assert_eq!(report.rows[0].reason, Some(EffectReason::CalleeUnmodeled));
    }

    #[test]
    fn an_interrupted_dispatch_states_the_typed_reason() {
        let report = call_effect_report(
            &file(),
            "site",
            "ast",
            range(),
            CallEffectSiteStatus::Interrupted {
                reason: EffectReason::DispatchUnsupported,
            },
            &[],
        );
        assert_eq!(report.coverage, EffectCoverage::Unsupported);
        assert_eq!(report.rows[0].derivation, EffectDerivation::Unsupported);
        assert_eq!(
            report.rows[0].reason,
            Some(EffectReason::DispatchUnsupported)
        );
    }

    fn procedure(name: &str, declared: Vec<BoundDeclaredEffect>) -> EffectGraphProcedure {
        EffectGraphProcedure {
            declaration_id: format!("decl:{name}"),
            display_name: name.to_owned(),
            declared,
            body_read: true,
            local_gaps: Vec::new(),
        }
    }

    fn edge(caller: usize, callee: usize, site: &str) -> EffectGraphEdge {
        EffectGraphEdge {
            caller,
            callee,
            site_id: site.to_owned(),
            certainty: EffectCertainty::Definite,
        }
    }

    #[test]
    fn a_direct_call_to_a_modeled_api_is_depth_one_and_direct() {
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.pure", Vec::new()),
                procedure(
                    "AcmeHttpClient.send",
                    vec![declared(
                        "acme.network_io",
                        EffectTiming::Immediate,
                        EffectCertainty::Definite,
                    )],
                ),
            ],
            edges: vec![edge(0, 1, "site.pure")],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        let row = &reports[0].rows[0];
        assert_eq!(row.effect_id.as_deref(), Some("acme.network_io"));
        assert_eq!(row.depth, Some(1));
        assert_eq!(row.classification, Some(EffectClassification::Direct));
        assert_eq!(row.witness.len(), 1);
        assert_eq!(row.witness_effect_site_id(), Some("site.pure"));
        assert_eq!(reports[0].coverage, EffectCoverage::Exhaustive);
    }

    #[test]
    fn a_two_hop_chain_is_transitive_and_retains_the_whole_witness() {
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.pure", Vec::new()),
                procedure("App.helper", Vec::new()),
                procedure(
                    "AcmeHttpClient.send",
                    vec![declared(
                        "acme.network_io",
                        EffectTiming::Immediate,
                        EffectCertainty::Definite,
                    )],
                ),
            ],
            edges: vec![edge(0, 1, "site.pure"), edge(1, 2, "site.helper")],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        let row = &reports[0].rows[0];
        assert_eq!(row.depth, Some(2));
        assert_eq!(row.classification, Some(EffectClassification::Transitive));
        assert_eq!(
            row.witness
                .iter()
                .map(|step| step.site_id.as_str())
                .collect::<Vec<_>>(),
            vec!["site.pure", "site.helper"]
        );
        assert_eq!(
            row.witness_chain().as_deref(),
            Some("App.pure -> App.helper -> AcmeHttpClient.send")
        );
    }

    #[test]
    fn a_recursive_cycle_converges_under_the_iteration_bound() {
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.a", Vec::new()),
                procedure("App.b", Vec::new()),
                procedure(
                    "AcmeHttpClient.send",
                    vec![declared(
                        "acme.network_io",
                        EffectTiming::Immediate,
                        EffectCertainty::Definite,
                    )],
                ),
            ],
            edges: vec![
                edge(0, 1, "site.a"),
                edge(1, 0, "site.b"),
                edge(1, 2, "site.send"),
            ],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        for report in reports.iter().take(2) {
            assert_eq!(report.rows.len(), 1);
            assert_eq!(report.rows[0].effect_id.as_deref(), Some("acme.network_io"));
            assert_eq!(report.coverage, EffectCoverage::Exhaustive);
        }
        // The whole cycle is reachable, so both procedures carry the effect and
        // neither report is truncated.
        assert_eq!(reports[0].rows[0].depth, Some(2));
        assert_eq!(reports[1].rows[0].depth, Some(1));
    }

    #[test]
    fn a_deferred_declaration_stays_deferred_through_propagation() {
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.pure", Vec::new()),
                procedure("App.helper", Vec::new()),
                procedure(
                    "AcmeScheduler.schedule",
                    vec![declared(
                        "acme.network_io",
                        EffectTiming::Deferred,
                        EffectCertainty::Definite,
                    )],
                ),
            ],
            edges: vec![edge(0, 1, "site.pure"), edge(1, 2, "site.helper")],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        assert_eq!(reports[0].rows[0].timing, Some(EffectTiming::Deferred));
    }

    #[test]
    fn an_ambiguous_call_edge_downgrades_the_inherited_certainty() {
        let mut ambiguous = edge(0, 1, "site.pure");
        ambiguous.certainty = EffectCertainty::Possible;
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.pure", Vec::new()),
                procedure(
                    "AcmeHttpClient.send",
                    vec![declared(
                        "acme.network_io",
                        EffectTiming::Immediate,
                        EffectCertainty::Definite,
                    )],
                ),
            ],
            edges: vec![ambiguous],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        assert_eq!(
            reports[0].rows[0].certainty,
            Some(EffectCertainty::Possible)
        );
    }

    #[test]
    fn an_unreadable_callee_opens_every_caller_that_reaches_it() {
        let mut opaque = procedure("App.opaque", Vec::new());
        opaque.body_read = false;
        let graph = EffectGraph {
            procedures: vec![procedure("App.pure", Vec::new()), opaque],
            edges: vec![edge(0, 1, "site.pure")],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        assert_eq!(reports[0].coverage, EffectCoverage::Open);
        assert_eq!(reports[0].rows[0].derivation, EffectDerivation::Incomplete);
        assert_eq!(
            reports[0].rows[0].reason,
            Some(EffectReason::ProcedureUnreadable)
        );
    }

    #[test]
    fn a_procedure_with_no_effect_and_a_complete_graph_states_an_exhaustive_absence() {
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.pure", Vec::new()),
                procedure("App.helper", Vec::new()),
            ],
            edges: vec![edge(0, 1, "site.pure")],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        assert_eq!(reports[0].rows.len(), 1);
        assert!(reports[0].rows[0].terminal);
        assert_eq!(reports[0].rows[0].derivation, EffectDerivation::None);
        assert_eq!(reports[0].coverage, EffectCoverage::Exhaustive);
    }

    #[test]
    fn the_depth_bound_truncates_instead_of_dropping_the_answer() {
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.a", Vec::new()),
                procedure("App.b", Vec::new()),
                procedure(
                    "AcmeHttpClient.send",
                    vec![declared(
                        "acme.network_io",
                        EffectTiming::Immediate,
                        EffectCertainty::Definite,
                    )],
                ),
            ],
            edges: vec![edge(0, 1, "site.a"), edge(1, 2, "site.b")],
            truncated: false,
        };
        let budget = ProcedureEffectBudget {
            max_depth: 1,
            ..ProcedureEffectBudget::default()
        };
        let reports = summarize_procedure_effects(&graph, budget);
        assert_eq!(reports[0].rows.len(), 1);
        assert!(reports[0].rows[0].terminal);
        assert_eq!(reports[0].coverage, EffectCoverage::Truncated);
        assert_eq!(
            reports[0].rows[0].reason,
            Some(EffectReason::ProcedureBudgetExhausted)
        );
    }

    #[test]
    fn the_fixpoint_is_deterministic_under_reordered_edges() {
        let procedures = vec![
            procedure("App.a", Vec::new()),
            procedure("App.b", Vec::new()),
            procedure(
                "AcmeHttpClient.send",
                vec![declared(
                    "acme.network_io",
                    EffectTiming::Immediate,
                    EffectCertainty::Definite,
                )],
            ),
        ];
        let forward = EffectGraph {
            procedures: procedures.clone(),
            edges: vec![
                edge(0, 1, "site.a"),
                edge(0, 2, "site.direct"),
                edge(1, 2, "site.b"),
            ],
            truncated: false,
        };
        let reversed = EffectGraph {
            procedures,
            edges: vec![
                edge(1, 2, "site.b"),
                edge(0, 2, "site.direct"),
                edge(0, 1, "site.a"),
            ],
            truncated: false,
        };
        assert_eq!(
            summarize_procedure_effects(&forward, ProcedureEffectBudget::default()),
            summarize_procedure_effects(&reversed, ProcedureEffectBudget::default())
        );
    }
}
