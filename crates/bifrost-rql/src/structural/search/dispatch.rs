//! Pipeline execution for the `dispatch_outcome` and `dispatch_targets`
//! steps (issue #1477 Milestone 4).
//!
//! Both steps bridge one exact source position to
//! [`crate::analyzer::semantic::WorkspaceSemanticOracle::dispatch_at_source`]
//! and project its answer. Neither step re-derives dispatch: every retained
//! arm keeps the proof, completeness, and candidate coverage the neutral
//! dispatch oracle attached to it.
//!
//! `dispatch_outcome` is mandatory per input site. An unknown, unsupported,
//! over-budget, or cancelled dispatch still emits exactly one row carrying the
//! typed reason, so zero target rows can never be read as a proven-empty
//! target set. `dispatch_targets` emits zero or more rows and repeats the
//! site's coverage on each arm, so an arm alone is enough to reject an
//! exact-set claim.

use super::*;

use crate::analyzer::semantic::{
    CandidateCoverage, ExactExternalProcedureTarget, SemanticLocator, UnmaterializedExternalTarget,
};

/// Domain separator for one dispatch site's stable id.
const DISPATCH_SITE_ID_DOMAIN: &[u8] = b"bifrost.code_query.dispatch_site.v1";
/// Domain separator for one dispatch target arm's stable id.
const DISPATCH_TARGET_ID_DOMAIN: &[u8] = b"bifrost.code_query.dispatch_target.v1";
/// Domain separator for one dispatch arm's semantic target identity.
const DISPATCH_TARGET_IDENTITY_DOMAIN: &[u8] = b"bifrost.code_query.dispatch_target_identity.v1";

/// One bounded-dispatch answer for one exact source position, shared by the
/// site's outcome row and each of its target rows.
#[derive(Debug, Clone)]
pub(super) struct DispatchSiteValue {
    pub(super) file: ProjectFile,
    pub(super) range: Range,
    pub(super) site_id: String,
    pub(super) site_ast_id: Option<String>,
    pub(super) answer: Arc<DispatchSiteAnswer>,
}

impl DispatchSiteValue {
    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }
}

/// One retained dispatch arm of one site.
#[derive(Debug, Clone)]
pub(super) struct DispatchTargetValue {
    pub(super) site: DispatchSiteValue,
    pub(super) ordinal: usize,
}

impl DispatchTargetValue {
    pub(super) fn file(&self) -> &ProjectFile {
        self.site.file()
    }

    pub(super) fn arm(&self) -> &DispatchArm {
        &self.site.answer.arms[self.ordinal]
    }

    pub(super) fn id(&self) -> String {
        let mut digest = LengthDelimitedDigest::new(DISPATCH_TARGET_ID_DOMAIN);
        digest.push(self.site.site_id.as_bytes());
        digest.push(&self.ordinal.to_le_bytes());
        digest.push(self.arm().target_id.as_bytes());
        digest.finish().to_string()
    }
}

/// The value domain the `dispatch_outcome.outcome` row field publishes. The
/// labels are minted by the semantic seam's own outcome match rather than by a
/// typed vocabulary, so the set is recorded here beside the field that carries
/// it (issue #2515).
pub(super) const DISPATCH_OUTCOME_LABELS: &[&str] = &[
    "resolved",
    "ambiguous",
    "unknown",
    "unsupported",
    "unproven",
    "exceeded_budget",
    "cancelled",
];

/// The value domain the `dispatch_target.dispatch` row field publishes, minted
/// by [`DispatchSiteAnswer::dispatch_label`].
pub(super) const DISPATCH_ARM_LABELS: &[&str] = &["proven_dispatch", "may_dispatch"];

/// One site's dispatch answer, already reduced to the row vocabulary.
///
/// Every field is the oracle's own statement. Nothing here is re-derived from
/// source text, and no absence is converted into a claim.
#[derive(Debug, Clone)]
pub(super) struct DispatchSiteAnswer {
    pub(super) outcome: &'static str,
    pub(super) coverage: CandidateCoverage,
    pub(super) call_site_count: usize,
    pub(super) semantic_unsupported: Option<&'static str>,
    pub(super) exceeded_limit: Option<&'static str>,
    pub(super) arms: Vec<DispatchArm>,
    /// Exact semantic owner of every source observation. Arms retain their
    /// ordinal into this list, so consumers never infer ownership from lexical
    /// containment.
    pub(super) call_contexts: Vec<DispatchCallContext>,
    /// The boundary kinds the answer published that name no target at all,
    /// in publication order.
    ///
    /// Such a boundary carries no locator, so it cannot become an arm and
    /// leaves no trace in `arms`. A consumer that reasons over the arm set
    /// would otherwise read the set as the whole answer; this is what says the
    /// oracle also found something it could not name (#2579). The kind is
    /// retained rather than a bare count because the kinds are not
    /// interchangeable: one `unresolved` residual is what an authored contract
    /// claim can discharge (#2371), while `truncated` and `external` without a
    /// locator name nothing any content can address.
    pub(super) unnamed_boundaries: Vec<&'static str>,
}

impl DispatchSiteAnswer {
    /// The answer for a site whose dispatch never ran to a published result.
    /// It states the typed reason and retains no arm.
    pub(super) fn interrupted(
        outcome: &'static str,
        semantic_unsupported: Option<&'static str>,
        exceeded_limit: Option<&'static str>,
    ) -> Self {
        Self {
            outcome,
            coverage: CandidateCoverage::Open,
            call_site_count: 0,
            semantic_unsupported,
            exceeded_limit,
            arms: Vec::new(),
            call_contexts: Vec::new(),
            // An interrupted dispatch published no boundary set at all, so it
            // states no residual either; the interruption is the reason.
            unnamed_boundaries: Vec::new(),
        }
    }

    /// `proven_dispatch` only for a proven, complete arm inside an exhaustive
    /// set. Every other combination stays `may_dispatch`; the three axes are
    /// published separately so an assertion can also read the exact one that
    /// kept the arm open.
    pub(super) fn dispatch_label(&self, arm: &DispatchArm) -> &'static str {
        if self.coverage.is_exhaustive() && arm.proof == "proven" && arm.completeness == "complete"
        {
            "proven_dispatch"
        } else {
            "may_dispatch"
        }
    }
}

/// One dispatch arm: a materialized candidate, or a boundary that names a
/// target the workspace does not materialize.
#[derive(Debug, Clone)]
pub(super) struct DispatchArm {
    pub(super) call_context: usize,
    /// Canonical execution timing for this particular target arm. A targeted
    /// deferred boundary can weaken the source call's timing without weakening
    /// ordinary or independently spawned arms at the same source site.
    pub(super) execution_timing: crate::analyzer::semantic::ExecutionTiming,
    pub(super) target_id: String,
    pub(super) target_path: String,
    pub(super) target_unit: Option<CodeUnit>,
    /// The resolver's exact semantic-pack declaration, including the
    /// structured overload contract. Retained so other call relations consume
    /// the same target answer and identity instead of repeating pack lookup or
    /// reconstructing an overload from a display symbol.
    pub(super) exact_external_target: Option<ExactExternalProcedureTarget>,
    /// The resolver's canonical identity for a fully-qualified callee that
    /// never materializes to an artifact (#1978), when this arm names one.
    ///
    /// It is the only handle a consumer has on an arm whose `target_unit` is
    /// `None`: the workspace holds no declaration to key a semantic-model
    /// lookup from, but `(language, owner FQN, member, receiver, arity)` still
    /// selects an activated authored summary for the member. Retained here
    /// rather than re-derived from `target_path`, which is a synthetic
    /// provenance path and carries no member identity at all.
    pub(super) unmaterialized_target: Option<UnmaterializedExternalTarget>,
    pub(super) proof: &'static str,
    pub(super) completeness: &'static str,
    pub(super) boundary_kind: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub(super) struct DispatchCallContext {
    /// The smallest workspace declaration containing the semantic caller.
    /// Anonymous nested callables intentionally map to their lexical parent's
    /// declaration, so consumers must also require `caller_is_exact` before
    /// attributing execution to this unit.
    pub(super) caller: Option<CodeUnit>,
    /// Whether the semantic procedure's own anchor equals a range of `caller`.
    pub(super) caller_is_exact: bool,
}

/// Derive the dispatch answer for one pipeline input position and project the
/// requested rows.
///
/// `site_ast_id` is passed in when the input already carries an exact AST
/// identity (an occurrence row); otherwise it is derived from the same facts
/// arena the receiver rows use, so a dispatch row joins to an occurrence row
/// on `site_ast_id` without comparing text or ranges.
#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_expansions_for_input(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    traces: &[PipelineTrace],
    file: &ProjectFile,
    range: Range,
    known_ast_id: Option<String>,
    targets: bool,
) -> Vec<PipelineExpansion> {
    let facts = coherent_trace_facts_for_file(traces, file);
    let (site_id, derived_ast_id) = dispatch_site_identity(analyzer, file, range, facts);
    let site = DispatchSiteValue {
        file: file.clone(),
        range,
        site_id,
        site_ast_id: known_ast_id.or(derived_ast_id),
        answer: Arc::new(semantic.dispatch_at_source(file, range)),
    };
    if !targets {
        return vec![pipeline_expansion(PipelineValue::DispatchOutcome(
            Box::new(site),
        ))];
    }
    (0..site.answer.arms.len())
        .map(|ordinal| {
            pipeline_expansion(PipelineValue::DispatchTarget(Box::new(
                DispatchTargetValue {
                    site: site.clone(),
                    ordinal,
                },
            )))
        })
        .collect()
}

/// The stable identity of one dispatch site.
///
/// The digest mirrors the receiver-site recipe -- content identity plus the
/// exact byte range under an operation-specific domain -- so the two site
/// families are addressable the same way while staying distinct values, and
/// `site_ast_id` is minted by the exact function the receiver rows use.
fn dispatch_site_identity(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    range: Range,
    facts: Option<&Arc<FileFacts>>,
) -> (String, Option<String>) {
    let content_identity = facts.map_or_else(
        || {
            analyzer
                .indexed_source(file)
                .map(|source| ContentIdentity::hash_bytes(source.as_bytes()))
        },
        |facts| Some(facts.source_identity()),
    );
    let mut digest = LengthDelimitedDigest::new(DISPATCH_SITE_ID_DOMAIN);
    match &content_identity {
        Some(identity) => digest.push(identity.as_bytes()),
        // The workspace can no longer read the file's exact bytes. Keep the id
        // total rather than dropping the mandatory row, and mark the gap so a
        // content-scoped id never collides with an unidentified one.
        None => digest.push(b"unindexed_source"),
    }
    digest.push(&range.start_byte.to_le_bytes());
    digest.push(&range.end_byte.to_le_bytes());
    let site_id = digest.finish().to_string();
    let site_ast_id = facts
        .zip(content_identity)
        .and_then(|(facts, identity)| receiver::site_ast_id_for_range(facts, identity, range));
    (site_id, site_ast_id)
}

/// The workspace declaration a dispatch target's semantic locator names, or
/// `None` when the workspace indexes no declaration covering it.
///
/// The lookup is structural. A declaration whose own range is exactly the
/// procedure's anchor span wins outright; otherwise the smallest declaration
/// whose range contains that span wins, which is the same containment rule the
/// enclosing-declaration projection uses. No name comparison happens here: a
/// span that a declaration owns is that declaration, whatever either is
/// spelled.
pub(super) fn declaration_at_locator(
    analyzer: &dyn IAnalyzer,
    locator: &SemanticLocator,
    file: &ProjectFile,
) -> Option<CodeUnit> {
    let span = locator.anchor().span();
    let start = span.start_byte() as usize;
    let end = span.end_byte() as usize;
    let mut enclosing: Option<(usize, CodeUnit)> = None;
    for unit in analyzer.get_declarations(file) {
        if unit.is_synthetic() || unit.is_file_scope() {
            continue;
        }
        for range in analyzer.ranges_of(&unit) {
            if range.start_byte == start && range.end_byte == end {
                return Some(unit);
            }
            if range.start_byte > start || range.end_byte < end {
                continue;
            }
            let width = range.end_byte - range.start_byte;
            if enclosing.as_ref().is_none_or(|(best, best_unit)| {
                width < *best || (width == *best && unit < *best_unit)
            }) {
                enclosing = Some((width, unit.clone()));
            }
        }
    }
    enclosing.map(|(_, unit)| unit)
}

/// The semantic identity of one dispatch arm's target.
///
/// The digest is over the target's artifact fingerprint (when the oracle names
/// one) and its semantic locator, never over an internal arena id.
pub(super) fn target_identity(
    artifact_fingerprint: Option<&str>,
    locator: &SemanticLocator,
) -> String {
    let mut digest = LengthDelimitedDigest::new(DISPATCH_TARGET_IDENTITY_DOMAIN);
    match artifact_fingerprint {
        Some(fingerprint) => {
            digest.push(b"artifact");
            digest.push(fingerprint.as_bytes());
        }
        None => digest.push(b"no_artifact"),
    }
    semantic::push_locator_bytes(&mut digest, locator);
    digest.finish().to_string()
}
