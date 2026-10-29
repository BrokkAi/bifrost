//! Bounded source-range projection for point-sensitive heap and dispatch
//! queries.
//!
//! Both entry points share the same bridge: materialize the file's semantic
//! artifact, select the narrowest retained source mapping that contains the
//! requested range, and delegate to the handle-keyed oracle. The value path
//! tries a wider mapping when the narrowest one has no executable observation,
//! so a selected member name can reach its enclosing field load.

use std::sync::Arc;

use brokk_bifrost_core::analyzer::usages::reference_site::node_range;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::hash::HashMap;

use crate::analyzer::semantic::workspace_oracle::common::Interruption;

use crate::analyzer::semantic::workspace_oracle::common::WorkStager;

use crate::analyzer::semantic::workspace_oracle::heap::points_to_capability_surface_is_incomplete;

use crate::analyzer::semantic::ids::push_evidence_completeness;

use crate::analyzer::semantic::ids::push_proof_status;

use crate::analyzer::semantic::AbstractObject;

use crate::analyzer::semantic::CallSiteHandle;

use crate::analyzer::semantic::CandidateCoverage;

use crate::analyzer::semantic::DispatchCandidate;

use crate::analyzer::semantic::LengthDelimitedDigest;

use crate::analyzer::semantic::ObservationPhase;

use crate::analyzer::semantic::OracleCallContext;

use crate::analyzer::semantic::OracleCandidate;

use crate::analyzer::semantic::PointsToResult;

use crate::analyzer::semantic::ProcedureHandle;

use crate::analyzer::semantic::SemanticArtifact;

use crate::analyzer::semantic::SemanticCallSite;

use crate::analyzer::semantic::SemanticBudgetExceeded;

use crate::analyzer::semantic::SemanticCapability;

use crate::analyzer::semantic::SemanticLocator;

use crate::analyzer::semantic::SemanticOutcome;

use crate::analyzer::semantic::SemanticValueKind;

use crate::analyzer::semantic::SemanticWork;

use crate::analyzer::semantic::SourceSpan;

use crate::analyzer::semantic::StableDigest;

use crate::analyzer::semantic::ValueAtPoint;

use crate::analyzer::semantic::ValueHandle;
use tree_sitter::Node;

/// Domain for the digest of one dispatch answer.
#[doc(hidden)]
pub const DISPATCH_ANSWER_DOMAIN: &[u8] = b"bifrost-read-ledger:dispatch-answer:v1";

/// The coverage a source-range dispatch answer publishes.
///
/// `truncated` is set when the located call set, or any located call's own
/// answer, was cut short; `exhaustive` when every located call answered
/// exhaustively. A quality that asserts no answer -- unknown, unsupported,
/// budgeted, cancelled -- cannot publish an exhaustive range answer even when
/// every call it did retain was itself exhaustive.
///
/// Shared with [`one_call_dispatch_answer_digest`], which is the same rule for
/// a range that located exactly one call site.
#[doc(hidden)]
pub const fn projected_source_coverage(
    quality: SourceOutcomeQuality,
    truncated: bool,
    exhaustive: bool,
) -> CandidateCoverage {
    if truncated {
        CandidateCoverage::Truncated
    } else if exhaustive
        && !matches!(
            quality,
            SourceOutcomeQuality::Unknown
                | SourceOutcomeQuality::Unsupported(_)
                | SourceOutcomeQuality::ExceededBudget(_)
                | SourceOutcomeQuality::Cancelled
        )
    {
        CandidateCoverage::Exhaustive
    } else {
        CandidateCoverage::Open
    }
}

/// The replayable question "dispatch at this range of this artifact".
///
/// The file is named by its workspace-relative path and the artifact by its
/// public fingerprint, never by the mount-bearing `SemanticArtifactKey`, so
/// the same question over the same content at two roots is the same question.
#[doc(hidden)]
pub fn dispatch_question(
    artifact: &SemanticArtifact,
    range: Range,
) -> crate::analyzer::semantic::read_ledger::LookupQuestion {
    crate::analyzer::semantic::read_ledger::LookupQuestion::call_site(
        artifact.key().path().as_str(),
        artifact.key().public_fingerprint(),
        range,
    )
}

/// The replayable question for one handle-keyed procedure-local dispatch.
///
/// Unlike [`dispatch_question`], this address excludes the artifact source
/// revision and measures the call range from the owning procedure's start.
/// That is the exact scope a procedure summary needs: another declaration in
/// the same file may move both absolute ranges without changing this call.
/// Calls that share the range are told apart by their position among the
/// procedure's call rows at it, which replay counts the same way.
#[doc(hidden)]
pub fn procedure_dispatch_question(
    call: &CallSiteHandle,
    range: Range,
) -> Option<crate::analyzer::semantic::read_ledger::LookupQuestion> {
    let procedure = call.procedure();
    let procedure_start = procedure.semantics().locator().anchor().span().start_byte() as usize;
    let start_byte = range.start_byte.checked_sub(procedure_start)?;
    let end_byte = range.end_byte.checked_sub(procedure_start)?;
    let ordinal = procedure
        .semantics()
        .call_sites()
        .iter()
        .take_while(|candidate| candidate.id != call.id())
        .filter(|candidate| {
            call_row_has_exact_bytes(procedure, candidate, range.start_byte, range.end_byte)
        })
        .count();
    Some(
        crate::analyzer::semantic::read_ledger::LookupQuestion::procedure_call_site(
            procedure.artifact().key().path().as_str(),
            procedure
                .artifact()
                .key()
                .procedure_lineage_fingerprint(procedure.semantics().locator().declaration()),
            crate::analyzer::semantic::read_ledger::ProcedureCallSiteLocator {
                start_byte,
                end_byte,
                ordinal,
            },
        ),
    )
}

/// Whether one of `procedure`'s call rows maps exactly onto these absolute
/// bytes: the test that both a recorded procedure-dispatch question and its
/// replay count call ordinals by.
#[doc(hidden)]
pub fn call_row_has_exact_bytes(
    procedure: &ProcedureHandle,
    call: &SemanticCallSite,
    start_byte: usize,
    end_byte: usize,
) -> bool {
    procedure
        .semantics()
        .source_mapping(call.source)
        .is_some_and(|mapping| {
            let span = mapping.locator.anchor().span();
            span.start_byte() as usize == start_byte && span.end_byte() as usize == end_byte
        })
}

#[doc(hidden)]
pub fn procedure_dispatch_components_digest(
    coverage: CandidateCoverage,
    complete_receiver_hint_refinable: bool,
    candidates: &mut [StableDigest],
    boundaries: &mut [StableDigest],
) -> StableDigest {
    let mut digest =
        LengthDelimitedDigest::new(b"bifrost-read-ledger:procedure-dispatch-observation:v2");
    digest.push(coverage.label().as_bytes());
    digest.push(&[u8::from(complete_receiver_hint_refinable)]);

    candidates.sort_unstable();
    digest.push(
        &u64::try_from(candidates.len())
            .expect("procedure dispatch candidate count fits in u64")
            .to_le_bytes(),
    );
    for candidate in candidates {
        digest.push(candidate.as_bytes());
    }

    boundaries.sort_unstable();
    digest.push(
        &u64::try_from(boundaries.len())
            .expect("procedure dispatch boundary count fits in u64")
            .to_le_bytes(),
    );
    for boundary in boundaries {
        digest.push(boundary.as_bytes());
    }
    digest.finish()
}

#[doc(hidden)]
pub fn procedure_dispatch_candidate_digest(candidate: &DispatchCandidate) -> StableDigest {
    let mut digest =
        LengthDelimitedDigest::new(b"bifrost-read-ledger:procedure-dispatch-candidate:v2");
    let target = candidate.target();
    digest.push(
        target
            .artifact()
            .key()
            .procedure_lineage_fingerprint(target.semantics().locator().declaration())
            .as_bytes(),
    );
    push_proof_status(&mut digest, candidate.proof());
    push_evidence_completeness(&mut digest, candidate.completeness());
    let mut excluded = candidate
        .excluded_targets()
        .iter()
        .map(|target| {
            target
                .artifact()
                .key()
                .procedure_lineage_fingerprint(target.semantics().locator().declaration())
        })
        .collect::<Vec<_>>();
    excluded.sort_unstable();
    digest.push(
        &u64::try_from(excluded.len())
            .expect("excluded dispatch target count fits in u64")
            .to_le_bytes(),
    );
    for target in excluded {
        digest.push(target.as_bytes());
    }
    digest.finish()
}

#[doc(hidden)]
pub fn push_source_outcome_quality(
    digest: &mut LengthDelimitedDigest,
    quality: SourceOutcomeQuality,
) {
    match quality {
        SourceOutcomeQuality::Complete => digest.push(b"complete"),
        SourceOutcomeQuality::Ambiguous => digest.push(b"ambiguous"),
        SourceOutcomeQuality::Unproven => digest.push(b"unproven"),
        SourceOutcomeQuality::Unknown => digest.push(b"unknown"),
        SourceOutcomeQuality::Unsupported(capability) => {
            digest.push(b"unsupported");
            digest.push(capability.label().as_bytes());
        }
        SourceOutcomeQuality::ExceededBudget(exceeded) => {
            digest.push(b"exceeded-budget");
            digest.push(exceeded.dimension().label().as_bytes());
            digest.push(
                &u64::try_from(exceeded.limit())
                    .expect("semantic budget limit fits in u64")
                    .to_le_bytes(),
            );
            digest.push(
                &u64::try_from(exceeded.attempted())
                    .expect("semantic budget attempt fits in u64")
                    .to_le_bytes(),
            );
        }
        SourceOutcomeQuality::Cancelled => digest.push(b"cancelled"),
    }
}

#[doc(hidden)]
pub fn push_optional_locator(
    digest: &mut LengthDelimitedDigest,
    locator: Option<&SemanticLocator>,
) {
    match locator {
        Some(locator) => {
            digest.push(b"locator");
            push_locator(digest, locator);
        }
        None => digest.push(b"no-locator"),
    }
}

#[doc(hidden)]
pub fn push_locator(digest: &mut LengthDelimitedDigest, locator: &SemanticLocator) {
    locator.push_anchor_free_procedure_declaration_identity(digest);
}

/// Point-sensitive points-to answers associated with one source range.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourcePointsToResult {
    #[doc(hidden)]
    pub observations: Box<[PointsToResult]>,
    #[doc(hidden)]
    pub coverage: CandidateCoverage,
    #[doc(hidden)]
    pub source_observations_complete: bool,
}

impl SourcePointsToResult {
    /// Exact value/point observations retained for the source range.
    pub fn observations(&self) -> &[PointsToResult] {
        &self.observations
    }

    /// Coverage across both source observations and their object sets.
    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    pub fn object_candidates(&self) -> impl Iterator<Item = &OracleCandidate<AbstractObject>> {
        self.observations
            .iter()
            .flat_map(|result| result.objects().candidates())
    }

    pub fn is_empty(&self) -> bool {
        self.observations
            .iter()
            .all(|result| result.objects().candidates().is_empty())
    }

    /// Whether this exact source range produced a complete observation set
    /// whose point-to candidates are locally proven even though the adapter's
    /// whole-language capability surface keeps coverage open. Consumers still
    /// need independent, syntax-scoped proof that the selected range is the
    /// value they intend to reason about.
    #[doc(hidden)]
    pub fn globally_incomplete_with_proven_candidates(&self) -> bool {
        self.coverage == CandidateCoverage::Open
            && self.source_observations_complete
            && source_points_have_globally_incomplete_proven_candidates(&self.observations)
    }
}

fn source_points_have_globally_incomplete_proven_candidates(
    observations: &[PointsToResult],
) -> bool {
    !observations.is_empty()
        && observations.iter().all(|result| {
            let query = result.query();
            let candidates = result.objects().candidates();
            result.objects().coverage() == CandidateCoverage::Open
                && points_to_capability_surface_is_incomplete(query.point().procedure())
                && !query.context().was_truncated()
                && !candidates.is_empty()
                && candidates.iter().all(OracleCandidate::is_proven_complete)
        })
}

#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub enum SourceOutcomeQuality {
    Complete,
    Ambiguous,
    Unproven,
    Unknown,
    Unsupported(SemanticCapability),
    ExceededBudget(SemanticBudgetExceeded),
    Cancelled,
}

impl SourceOutcomeQuality {
    #[doc(hidden)]
    pub fn from_outcome<T>(outcome: &SemanticOutcome<T>) -> Self {
        match outcome {
            SemanticOutcome::Complete { .. } => Self::Complete,
            SemanticOutcome::Ambiguous { .. } => Self::Ambiguous,
            SemanticOutcome::Unknown { .. } => Self::Unknown,
            SemanticOutcome::Unsupported { capability, .. } => Self::Unsupported(*capability),
            SemanticOutcome::Unproven { .. } => Self::Unproven,
            SemanticOutcome::ExceededBudget { exceeded, .. } => Self::ExceededBudget(*exceeded),
            SemanticOutcome::Cancelled { .. } => Self::Cancelled,
        }
    }

    const fn priority(self) -> u8 {
        match self {
            Self::Complete => 0,
            Self::Ambiguous => 1,
            Self::Unproven => 2,
            Self::Unknown => 3,
            Self::Unsupported(_) => 4,
            Self::ExceededBudget(_) => 5,
            Self::Cancelled => 6,
        }
    }

    #[doc(hidden)]
    pub fn absorb(&mut self, other: Self) {
        if other.priority() > self.priority() {
            *self = other;
        }
    }

    /// Publish the merged quality over an optional projected answer. A quality
    /// that asserts an available answer but has none degrades to `Unknown`,
    /// never to an empty proven set.
    #[doc(hidden)]
    pub fn publish<T>(self, result: Option<T>, work: SemanticWork) -> SemanticOutcome<T> {
        match self {
            Self::Complete => result.map_or(
                SemanticOutcome::Unknown {
                    partial: None,
                    work,
                },
                |value| SemanticOutcome::Complete { value, work },
            ),
            Self::Ambiguous => result.map_or(
                SemanticOutcome::Unknown {
                    partial: None,
                    work,
                },
                |candidates| SemanticOutcome::Ambiguous { candidates, work },
            ),
            Self::Unproven => result.map_or(
                SemanticOutcome::Unknown {
                    partial: None,
                    work,
                },
                |partial| SemanticOutcome::Unproven { partial, work },
            ),
            Self::Unknown => SemanticOutcome::Unknown {
                partial: result,
                work,
            },
            Self::Unsupported(capability) => SemanticOutcome::Unsupported {
                capability,
                partial: result,
                work,
            },
            Self::ExceededBudget(exceeded) => SemanticOutcome::ExceededBudget {
                partial: result,
                exceeded,
                work,
            },
            Self::Cancelled => SemanticOutcome::Cancelled {
                partial: result,
                work,
            },
        }
    }
}

/// The value observations at one source range, or why there are none.
#[doc(hidden)]
pub enum SourceObservation {
    Observed(ObservedSource),
    /// The range selects a parameter of a Rust signature without a body,
    /// which has no runtime value.
    BodylessParameter {
        work: SemanticWork,
    },
    /// No observation: cancelled, over budget, no artifact, or nothing at the
    /// range. The outcome holds no value.
    Settled(SemanticOutcome<()>),
}

/// The observations projected at one source range.
#[doc(hidden)]
pub struct ObservedSource {
    #[doc(hidden)]
    pub observations: Vec<ValueAtPoint>,
    /// The projection stopped at the source-observation limit.
    #[doc(hidden)]
    pub truncated: bool,
    /// The file's materialization was complete.
    #[doc(hidden)]
    pub materialization_complete: bool,
    /// The materialization's quality.
    #[doc(hidden)]
    pub quality: SourceOutcomeQuality,
    #[doc(hidden)]
    pub work: SemanticWork,
}

/// Re-type an unavailable materialization outcome for the projected answer.
/// Only the artifact's own honest failure state survives; no projection is
/// invented for a file whose semantics never materialized.
#[doc(hidden)]
pub fn source_outcome_without_value<T>(
    outcome: SemanticOutcome<Arc<SemanticArtifact>>,
) -> SemanticOutcome<T> {
    match outcome {
        SemanticOutcome::Unknown { work, .. } => SemanticOutcome::Unknown {
            partial: None,
            work,
        },
        SemanticOutcome::Unsupported {
            capability, work, ..
        } => SemanticOutcome::Unsupported {
            capability,
            partial: None,
            work,
        },
        SemanticOutcome::ExceededBudget { exceeded, work, .. } => SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work,
        },
        SemanticOutcome::Cancelled { work, .. } => SemanticOutcome::Cancelled {
            partial: None,
            work,
        },
        SemanticOutcome::Complete { .. }
        | SemanticOutcome::Ambiguous { .. }
        | SemanticOutcome::Unproven { .. } => {
            unreachable!("available semantic outcomes always retain their value")
        }
    }
}

/// Locate the call sites whose source mapping is the narrowest one containing
/// `range`, across the procedures whose call-site mappings can contain it.
/// Only those procedures are examined and charged, so one range does not cost
/// a walk of the whole procedure table.
///
/// Narrowest-span selection keeps nested calls precise: a nested call such as
/// `outer(inner())` must address `inner` when the range is inside it, never the
/// enclosing call. Returns the retained handles and whether the
/// oracle's source-observation limit omitted an equally narrow call site.
#[doc(hidden)]
pub fn source_call_sites(
    artifact: &Arc<SemanticArtifact>,
    range: Range,
    limit: usize,
    staged: &mut WorkStager,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<(Vec<CallSiteHandle>, bool), Interruption> {
    let mut best_width = None;
    let mut calls = Vec::new();
    for procedure_id in artifact.procedures_with_call_source_containing(range) {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge_work(SemanticWork {
            procedures: 1,
            ..SemanticWork::default()
        });
        let procedure = artifact
            .procedure(procedure_id)
            .expect("an indexed procedure belongs to its artifact");
        let Some(procedure_handle) = artifact.procedure_handle(procedure_id) else {
            continue;
        };
        for call in procedure.call_sites() {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled);
            }
            staged.charge_work(SemanticWork {
                call_sites: 1,
                source_mappings: 1,
                ..SemanticWork::default()
            });
            let Some(mapping) = procedure.source_mapping(call.source) else {
                continue;
            };
            let span = mapping.locator.anchor().span();
            if !span_contains_range(span, range) {
                continue;
            }
            let width = (span.end_byte() - span.start_byte()) as usize;
            if best_width.is_some_and(|best| width > best) {
                continue;
            }
            if best_width.is_none_or(|best| width < best) {
                best_width = Some(width);
                calls.clear();
            }
            let Some(call_handle) = procedure_handle.call_site_handle(call.id) else {
                continue;
            };
            staged.admit(SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            })?;
            calls.push(call_handle);
        }
    }
    let truncated = calls.len() > limit;
    calls.truncate(limit);
    Ok((calls, truncated))
}

#[doc(hidden)]
pub fn enclosing_rust_const_static<'tree>(
    mut node: Node<'tree>,
    range: Range,
) -> Option<Node<'tree>> {
    loop {
        if matches!(node.kind(), "const_item" | "static_item")
            && node.start_byte() <= range.start_byte
            && node.end_byte() >= range.end_byte
        {
            return Some(node);
        }
        node = node.parent()?;
    }
}

#[doc(hidden)]
pub fn rust_literal_initializer(node: Node<'_>) -> bool {
    match node.kind() {
        "string_literal"
        | "raw_string_literal"
        | "byte_string_literal"
        | "char_literal"
        | "integer_literal"
        | "float_literal"
        | "negative_literal"
        | "array_expression"
        | "tuple_expression" => true,
        "unary_expression" => node
            .named_child(0)
            .is_some_and(|child| matches!(child.kind(), "integer_literal" | "float_literal")),
        _ => false,
    }
}

#[doc(hidden)]
pub fn terminal_rust_name_range(node: Node<'_>) -> Range {
    let terminal = if node.kind() == "scoped_identifier" {
        node.child_by_field_name("name").unwrap_or(node)
    } else {
        node
    };
    node_range(terminal)
}

#[doc(hidden)]
pub fn source_value_observations(
    artifact: &Arc<SemanticArtifact>,
    range: Range,
    limit: usize,
    staged: &mut WorkStager,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<(Vec<ValueAtPoint>, bool), Interruption> {
    let candidate_groups = source_value_candidates(artifact, range, staged, cancellation)?;
    let mut observations = Vec::new();
    let mut selected_width = None;
    for group in candidate_groups {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        if selected_width.is_some_and(|width| group.width > width && !observations.is_empty()) {
            break;
        }
        if selected_width.is_none_or(|width| group.width > width) {
            selected_width = Some(group.width);
        }
        if project_procedure_observations(
            &group.procedure,
            &group.candidates,
            range,
            limit,
            &mut observations,
            staged,
            cancellation,
        )? {
            return Ok((observations, true));
        }
    }
    Ok((observations, false))
}

#[derive(Debug)]
struct SourceValueCandidate {
    value: ValueHandle,
    span: SourceSpan,
}

#[derive(Debug)]
struct ProcedureSourceCandidates {
    procedure: crate::analyzer::semantic::ProcedureHandle,
    width: usize,
    candidates: Vec<SourceValueCandidate>,
}

fn source_value_candidates(
    artifact: &Arc<SemanticArtifact>,
    range: Range,
    staged: &mut WorkStager,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<Vec<ProcedureSourceCandidates>, Interruption> {
    let mut groups = Vec::new();
    let range_width = range.end_byte - range.start_byte;
    for procedure in artifact.procedures() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge_work(SemanticWork {
            procedures: 1,
            ..SemanticWork::default()
        });
        let Some(procedure_handle) = artifact.procedure_handle(procedure.id()) else {
            continue;
        };
        let implicit_preparations = procedure.implicit_receiver_preparation_values();
        let mut candidates_by_width = HashMap::<usize, Vec<SourceValueCandidate>>::default();
        for value in procedure.values() {
            if implicit_preparations.contains(&value.id) {
                continue;
            }
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled);
            }
            staged.charge_work(SemanticWork {
                values: 1,
                source_mappings: 1,
                ..SemanticWork::default()
            });
            let Some(mapping) = procedure.source_mapping(value.source) else {
                continue;
            };
            let span = mapping.locator.anchor().span();
            if !span_contains_range(span, range) {
                continue;
            }
            let width = (span.end_byte() - span.start_byte()) as usize;
            let Some(value_handle) = procedure_handle.value_handle(value.id) else {
                continue;
            };
            staged.admit(SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            })?;
            candidates_by_width
                .entry(width)
                .or_default()
                .push(SourceValueCandidate {
                    value: value_handle,
                    span,
                });
        }
        let Some(min_width) = candidates_by_width.keys().copied().min() else {
            continue;
        };
        debug_assert!(min_width >= range_width);
        // An exact hit cannot have a strictly narrower boundary containing the range.
        if min_width > range_width {
            // An empty source region is still a boundary.
            // Widening past its narrowest program point can turn an identifier
            // in unevaluated syntax into the value of an enclosing call (#5267).
            let mut point_width = None;
            let mut boundary_is_empty = true;
            for point in procedure.points() {
                if cancellation.is_cancelled() {
                    return Err(Interruption::Cancelled);
                }
                staged.charge_work(SemanticWork {
                    program_points: 1,
                    source_mappings: 1,
                    ..SemanticWork::default()
                });
                if let Some(mapping) = procedure.source_mapping(point.source) {
                    let span = mapping.locator.anchor().span();
                    if span_contains_range(span, range) {
                        let width = (span.end_byte() - span.start_byte()) as usize;
                        if width >= min_width {
                            continue;
                        }
                        if point_width.is_none_or(|best| width < best) {
                            point_width = Some(width);
                            boundary_is_empty = point.events.is_empty();
                        } else if point_width == Some(width) {
                            boundary_is_empty &= point.events.is_empty();
                        }
                    }
                }
            }
            // An event-free callable point can still own a value. Preserve its
            // normal projection to the call result; only a region with neither
            // events nor mapped values is an unevaluated boundary (#5267).
            if boundary_is_empty && point_width.is_some() {
                continue;
            }
        }
        for (width, candidates) in candidates_by_width {
            groups.push(ProcedureSourceCandidates {
                procedure: procedure_handle.clone(),
                width,
                candidates,
            });
        }
    }
    groups.sort_unstable_by_key(|group| group.width);
    Ok(groups)
}

#[derive(Debug, Default)]
struct CandidateSpan {
    indexes: Vec<usize>,
    has_exact_point: bool,
}

#[allow(clippy::too_many_arguments)]
fn project_procedure_observations(
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    candidates: &[SourceValueCandidate],
    range: Range,
    limit: usize,
    observations: &mut Vec<ValueAtPoint>,
    staged: &mut WorkStager,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<bool, Interruption> {
    let mut load_points = HashMap::default();
    for point in procedure.semantics().points() {
        for event in &point.events {
            if cancellation.is_cancelled() {
                return Err(Interruption::Cancelled);
            }
            staged.charge_work(SemanticWork {
                events: 1,
                ..SemanticWork::default()
            });
            if let crate::analyzer::semantic::SemanticEffect::MemoryLoad { result, .. } =
                event.effect
            {
                load_points
                    .entry(result)
                    .or_insert_with(Vec::new)
                    .push(point.id);
            }
        }
    }
    let mut candidates_by_span = HashMap::<SourceSpan, CandidateSpan>::default();
    for (index, candidate) in candidates.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.admit(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        candidates_by_span
            .entry(candidate.span)
            .or_default()
            .indexes
            .push(index);
    }

    staged.charge_work(SemanticWork {
        procedures: 1,
        ..SemanticWork::default()
    });
    let mut fallback_width = None;
    for point in procedure.semantics().points() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge_work(SemanticWork {
            program_points: 1,
            source_mappings: 1,
            ..SemanticWork::default()
        });
        let Some(mapping) = procedure.semantics().source_mapping(point.source) else {
            continue;
        };
        let span = mapping.locator.anchor().span();
        if let Some(candidate_span) = candidates_by_span.get_mut(&span) {
            candidate_span.has_exact_point = true;
        }
        if !span_contains_range(span, range) {
            continue;
        }
        let width = (span.end_byte() - span.start_byte()) as usize;
        if fallback_width.is_none_or(|best| width < best) {
            fallback_width = Some(width);
        }
    }

    let mut fallback_candidates = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.admit(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        })?;
        if !candidates_by_span
            .get(&candidate.span)
            .is_some_and(|span| span.has_exact_point)
        {
            fallback_candidates.push(index);
        }
    }

    let parameter_candidates = candidates
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| {
            procedure
                .semantics()
                .value(candidate.value.id())
                .is_some_and(|value| matches!(value.kind, SemanticValueKind::Parameter { .. }))
                .then_some(index)
        })
        .collect::<Vec<_>>();
    if !parameter_candidates.is_empty() {
        let entry = procedure
            .point_handle(procedure.semantics().entry_point())
            .expect("semantic procedure entry has a point handle");
        if append_observations(
            &parameter_candidates,
            candidates,
            &load_points,
            procedure,
            &entry,
            limit,
            observations,
            staged,
            cancellation,
        )? {
            return Ok(true);
        }
    }

    staged.charge_work(SemanticWork {
        procedures: 1,
        ..SemanticWork::default()
    });
    for point in procedure.semantics().points() {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge_work(SemanticWork {
            program_points: 1,
            source_mappings: 1,
            ..SemanticWork::default()
        });
        let Some(mapping) = procedure.semantics().source_mapping(point.source) else {
            continue;
        };
        let span = mapping.locator.anchor().span();
        let Some(point_handle) = procedure.point_handle(point.id) else {
            continue;
        };
        if let Some(exact) = candidates_by_span
            .get(&span)
            .filter(|candidate_span| candidate_span.has_exact_point)
            && append_observations(
                &exact.indexes,
                candidates,
                &load_points,
                procedure,
                &point_handle,
                limit,
                observations,
                staged,
                cancellation,
            )?
        {
            return Ok(true);
        }
        let span_width = (span.end_byte() - span.start_byte()) as usize;
        if span_contains_range(span, range)
            && fallback_width == Some(span_width)
            && append_observations(
                &fallback_candidates,
                candidates,
                &load_points,
                procedure,
                &point_handle,
                limit,
                observations,
                staged,
                cancellation,
            )?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
fn append_observations(
    candidate_indexes: &[usize],
    candidates: &[SourceValueCandidate],
    load_points: &HashMap<
        crate::analyzer::semantic::ValueId,
        Vec<crate::analyzer::semantic::ProgramPointId>,
    >,
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    point: &crate::analyzer::semantic::ProgramPointHandle,
    limit: usize,
    observations: &mut Vec<ValueAtPoint>,
    staged: &mut WorkStager,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<bool, Interruption> {
    for index in candidate_indexes {
        if cancellation.is_cancelled() {
            return Err(Interruption::Cancelled);
        }
        staged.charge_work(SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        });
        if procedure
            .semantics()
            .call_phase_points(candidates[*index].value.id())
            .is_some_and(|points| points.binary_search(&point.id()).is_err())
        {
            continue;
        }
        // A result is observed after its defining load, not at another
        // control point with the same expression span.
        if load_points
            .get(&candidates[*index].value.id())
            .is_some_and(|points| !points.contains(&point.id()))
        {
            continue;
        }
        let Ok(observation) = ValueAtPoint::new(
            candidates[*index].value.clone(),
            point.clone(),
            ObservationPhase::AfterEffects,
            OracleCallContext::empty(),
        ) else {
            continue;
        };
        if observations.len() == limit {
            return Ok(true);
        }
        observations.push(observation);
    }
    Ok(false)
}

fn span_contains_range(span: SourceSpan, range: Range) -> bool {
    Range {
        start_byte: span.start_byte() as usize,
        end_byte: span.end_byte() as usize,
        start_line: span.start().line() as usize,
        end_line: span.end().line() as usize,
    }
    .contains(&range)
}
