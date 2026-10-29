//! Bounded source-range projection for point-sensitive heap and dispatch
//! queries.
//!
//! Both entry points share the same bridge: materialize the file's semantic
//! artifact, select the narrowest retained source mapping that contains the
//! requested range, and delegate to the handle-keyed oracle. The value path
//! tries a wider mapping when the narrowest one has no executable observation,
//! so a selected member name can reach its enclosing field load.

use crate::analyzer::semantic::ids::{
    push_evidence_completeness, push_optional_bytes, push_proof_status,
};
use crate::analyzer::semantic::workspace_oracle::{
    WorkspaceSemanticOracle, common::Interruption, common::WorkStager,
    dispatch::PreparedWorkspaceDispatchSession,
};
use crate::analyzer::semantic::{
    CallSiteHandle, CandidateCoverage, DispatchBoundary, DispatchBoundaryKind, DispatchCandidate,
    DispatchResult, HeapOracle, LengthDelimitedDigest, SemanticArtifact,
    SemanticBudgetScopeIdentity, SemanticOutcome, SemanticProviderError, SemanticRequest,
    SemanticWork, StableDigest, ValueAtPoint,
};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, parse_tree_for_language,
    resolve_definition_batch_with_source,
};
use crate::analyzer::usages::reference_site::smallest_named_node_covering;
use crate::analyzer::{CodeUnitType, Language, ProjectFile, Range};
pub use brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::source::*;
use std::sync::Arc;
/// A lazy file-window dispatch session over one immutable semantic artifact.
///
/// Source ranges need not be known up front. Each range is projected only when
/// requested, and each resulting call is dispatched serially. The first real
/// call initializes the exact-source parse session; skipped rows perform no
/// low-level work and cannot desynchronize later rows. That first demand also
/// freezes the caller source for the rest of this query-scoped file window;
/// later demands deliberately reuse it even if a live editor overlay changes.
/// Reuse is valid only inside one logical [`crate::analyzer::semantic::SemanticBudget`]
/// scope, so a fresh independent request cannot inherit work paid elsewhere.
#[doc(hidden)]
pub struct PreparedSourceDispatchSession<'a> {
    oracle: WorkspaceSemanticOracle<'a>,
    materialized: SemanticOutcome<Arc<SemanticArtifact>>,
    pending_materialization_work: SemanticWork,
    budget_scope: Option<SemanticBudgetScopeIdentity>,
    scalar_definitions:
        Option<crate::analyzer::usages::get_definition::ScalarCallTargetSession<'a>>,
    calls: Option<PreparedWorkspaceDispatchSession<'a>>,
}

impl<'a> PreparedSourceDispatchSession<'a> {
    /// Initialize this file window's scalar definition session. The
    /// resolver itself remains unopened until an uncached callee is demanded.
    #[doc(hidden)]
    pub fn enable_definition_operation_reuse(&mut self) {
        self.scalar_definitions.get_or_insert_with(|| {
            crate::analyzer::usages::get_definition::ScalarCallTargetSession::new(
                self.oracle.workspace.analyzer(),
            )
        });
    }

    #[doc(hidden)]
    pub fn has_definition_operation(&self) -> bool {
        self.scalar_definitions
            .as_ref()
            .is_some_and(|session| session.is_active())
    }

    #[doc(hidden)]
    pub fn release_definition_operation(&mut self) {
        self.scalar_definitions = None;
    }

    /// Conservative physical footprint retained only for this prepared file
    /// window. The artifact itself is accounted by its lease owner.
    #[doc(hidden)]
    pub fn retained_bytes(&self) -> usize {
        self.calls
            .as_ref()
            .map_or(0, PreparedWorkspaceDispatchSession::retained_bytes)
    }

    /// Resolve one range, then record its answer in the read ledger when one
    /// is attached. Dispatch is the channel a result contract or a task slice
    /// composes callee bodies through, so the answer, including which targets
    /// it named and whether the set was exhaustive, is an input the reader
    /// depended on.
    #[doc(hidden)]
    pub fn resolve_at_source_recorded(
        &mut self,
        range: Range,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<SourceDispatchResult>, SemanticProviderError> {
        // Only computed when a ledger will read it: the question names the
        // artifact, and an Arc bump on every dispatch is a cost runs that
        // record nothing should not pay.
        let question = (crate::analyzer::read_attribution_records_reads(|| {
            self.oracle.workspace.analyzer().read_ledger_attached()
        }))
        .then(|| {
            self.materialized
                .available_value()
                .map(|artifact| dispatch_question(artifact, range))
        })
        .flatten();
        let outcome = self.resolve_at_source(range, request)?;
        if let Some(question) = question {
            self.oracle.workspace.analyzer().record_read(
                crate::analyzer::read_ledger::ReadKey::lookup(
                    crate::analyzer::read_ledger::LookupKind::Dispatch,
                    question,
                    dispatch_answer_digest(outcome.available_value()),
                ),
            );
        }
        Ok(outcome)
    }

    #[doc(hidden)]
    pub fn resolve_at_source(
        &mut self,
        range: Range,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<SourceDispatchResult>, SemanticProviderError> {
        if !request.cancellation.is_cancelled() {
            match &self.budget_scope {
                Some(scope) if !request.budget.shares_scope_with(scope) => {
                    return Err(SemanticProviderError::invalid_identity(
                        "prepared source dispatch cannot cross semantic budget scopes",
                    ));
                }
                Some(_) => {}
                None => self.budget_scope = Some(request.budget.scope_identity()),
            }
        }
        let mut quality = SourceOutcomeQuality::from_outcome(&self.materialized);
        // Materialization happened once before this file session opened. Its
        // outcome quality applies to every projection, but its physical work
        // is reported only by the first projection that consumes the session.
        let mut work = std::mem::take(&mut self.pending_materialization_work);
        let Some(artifact) = self.materialized.available_value().cloned() else {
            return Ok(quality.publish(None, work));
        };

        let mut staged = WorkStager::new(request);
        let projection = source_call_sites(
            &artifact,
            range,
            self.oracle.limits.source_observations(),
            &mut staged,
            request.cancellation,
        );
        work = work.conservative_add(staged.work);
        let (calls, calls_truncated) = match projection {
            Ok(_) if request.cancellation.is_cancelled() => {
                request.budget.retain_performed_work(&staged.budget);
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                });
            }
            Ok(projection) => projection,
            Err(Interruption::Budget(exceeded)) => {
                request.budget.retain_performed_work(&staged.budget);
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            }
            Err(Interruption::Cancelled) => {
                request.budget.retain_performed_work(&staged.budget);
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                });
            }
        };
        *request.budget = staged.budget;
        if calls.is_empty() {
            quality.absorb(SourceOutcomeQuality::Unknown);
            return Ok(quality.publish(None, work));
        }
        if calls_truncated {
            quality.absorb(SourceOutcomeQuality::Unproven);
        }

        let mut observations = Vec::with_capacity(calls.len());
        let mut all_results_exhaustive = true;
        let mut any_result_truncated = false;
        let call_count = calls.len();
        for (index, call) in calls.into_iter().enumerate() {
            let outcome = self
                .calls
                .as_mut()
                .expect("an available artifact owns a dispatch session")
                .resolve_call_with_definition_session(
                    &call,
                    request,
                    self.scalar_definitions.as_mut(),
                )?;
            work = work.conservative_add(outcome.work());
            quality.absorb(SourceOutcomeQuality::from_outcome(&outcome));
            if let Some(result) = outcome.available_value() {
                all_results_exhaustive &= result.coverage().is_exhaustive();
                any_result_truncated |= result.coverage().is_truncated();
                observations.push(SourceDispatchObservation {
                    call,
                    dispatch: result.clone(),
                });
            } else {
                all_results_exhaustive = false;
            }
            if matches!(
                outcome,
                SemanticOutcome::Cancelled { .. } | SemanticOutcome::ExceededBudget { .. }
            ) {
                all_results_exhaustive &= index + 1 == call_count;
                break;
            }
        }

        let coverage = projected_source_coverage(
            quality,
            calls_truncated || any_result_truncated,
            all_results_exhaustive,
        );
        // Aggregate coverage does not feed back into quality. Each delegated
        // call already classified its own open or truncated answer; only
        // source-observation omission introduced by this seam is absorbed
        // above.
        let result = (!observations.is_empty()).then(|| SourceDispatchResult {
            observations: observations.into_boxed_slice(),
            coverage,
        });
        Ok(quality.publish(result, work))
    }
}

impl<'a> WorkspaceSemanticOracle<'a> {
    /// Open a source dispatch session without reading or parsing source.
    #[doc(hidden)]
    pub fn prepare_source_dispatch_session_in_artifact(
        &self,
        materialized: SemanticOutcome<Arc<SemanticArtifact>>,
    ) -> PreparedSourceDispatchSession<'a> {
        let pending_materialization_work = materialized.work();
        let calls = materialized
            .available_value()
            .cloned()
            .map(|artifact| self.prepare_call_dispatch_session(artifact));
        PreparedSourceDispatchSession {
            oracle: self.clone(),
            materialized,
            pending_materialization_work,
            budget_scope: None,
            scalar_definitions: None,
            calls,
        }
    }

    /// Resolve every retained point-sensitive value observation for the
    /// narrowest semantic source mapping that contains `range`.
    ///
    /// A single source value can occur at several path-specialized program
    /// points (for example, a duplicated cleanup path). Keeping each
    /// [`PointsToResult`] separate preserves its exact query identity and
    /// provenance. The number of retained observations is bounded by the
    /// oracle's source-observation limit; reaching that bound is reported
    /// through truncated coverage and an unproven outcome.
    pub fn pointees_at_source(
        &self,
        file: &ProjectFile,
        range: Range,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<SourcePointsToResult>, SemanticProviderError> {
        let ObservedSource {
            observations,
            truncated: observations_truncated,
            materialization_complete,
            mut quality,
            mut work,
        } = match self.observe_source(file, range, request)? {
            SourceObservation::Observed(observed) => observed,
            SourceObservation::BodylessParameter { work } => {
                return Ok(SemanticOutcome::Complete {
                    value: SourcePointsToResult {
                        observations: Vec::new().into_boxed_slice(),
                        coverage: CandidateCoverage::Exhaustive,
                        source_observations_complete: true,
                    },
                    work,
                });
            }
            SourceObservation::Settled(outcome) => {
                return Ok(outcome.map(|()| unreachable!("a settled source holds no value")));
            }
        };
        let source_observations_materialization_complete =
            materialization_complete && !observations_truncated;
        if observations_truncated {
            quality.absorb(SourceOutcomeQuality::Unproven);
        }

        let mut points_to = Vec::with_capacity(observations.len());
        let mut all_results_exhaustive = true;
        let mut any_result_truncated = false;
        let observation_count = observations.len();
        for (index, observation) in observations.iter().enumerate() {
            let outcome = self.pointees(observation, request)?;
            work = work.conservative_add(outcome.work());
            quality.absorb(SourceOutcomeQuality::from_outcome(&outcome));
            if let Some(result) = outcome.available_value() {
                all_results_exhaustive &= result.objects().coverage().is_exhaustive();
                any_result_truncated |= result.objects().coverage().is_truncated();
                points_to.push(result.clone());
            } else {
                all_results_exhaustive = false;
            }
            if matches!(
                outcome,
                SemanticOutcome::Cancelled { .. } | SemanticOutcome::ExceededBudget { .. }
            ) {
                all_results_exhaustive &= index + 1 == observation_count;
                break;
            }
        }

        let source_observations_complete =
            source_observations_materialization_complete && points_to.len() == observation_count;
        let coverage = if observations_truncated || any_result_truncated {
            CandidateCoverage::Truncated
        } else if all_results_exhaustive
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
        };
        if coverage == CandidateCoverage::Open {
            quality.absorb(SourceOutcomeQuality::Unknown);
        } else if coverage == CandidateCoverage::Truncated {
            quality.absorb(SourceOutcomeQuality::Unproven);
        }
        let result = (!points_to.is_empty()).then(|| SourcePointsToResult {
            observations: points_to.into_boxed_slice(),
            coverage,
            source_observations_complete,
        });
        Ok(quality.publish(result, work))
    }

    /// The point-sensitive value observations for the narrowest semantic
    /// source mapping that contains `range`, without their points-to sets.
    ///
    /// This is the file-local half of [`Self::pointees_at_source`]: it
    /// materializes the file, applies the bodyless-parameter rule and the
    /// literal const/static read narrowing, and projects the observations,
    /// but asks no heap question. A consumer that needs only the value and
    /// its point (the taint composition's frontier) uses it, because points-to
    /// of a formal asks for every caller of its procedure. The quality is the
    /// projection's own: a truncated set is unproven, an incomplete
    /// materialization keeps its outcome, and no observation is `Unknown`.
    pub fn value_observations_at_source(
        &self,
        file: &ProjectFile,
        range: Range,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Box<[ValueAtPoint]>>, SemanticProviderError> {
        Ok(match self.observe_source(file, range, request)? {
            SourceObservation::Observed(ObservedSource {
                observations,
                truncated,
                materialization_complete: _,
                mut quality,
                work,
            }) => {
                if truncated {
                    quality.absorb(SourceOutcomeQuality::Unproven);
                }
                quality.publish(Some(observations.into_boxed_slice()), work)
            }
            SourceObservation::BodylessParameter { work } => SemanticOutcome::Complete {
                value: Box::default(),
                work,
            },
            SourceObservation::Settled(outcome) => {
                outcome.map(|()| unreachable!("a settled source holds no value"))
            }
        })
    }

    /// Materialize `file` and project the value observations at `range`,
    /// the step [`Self::pointees_at_source`] and
    /// [`Self::value_observations_at_source`] share.
    fn observe_source(
        &self,
        file: &ProjectFile,
        range: Range,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SourceObservation, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SourceObservation::Settled(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            }));
        }
        let materialized = self
            .workspace
            .materialize_program_semantics(file, request)?;
        let work = materialized.work();

        // A declaration-only Rust signature cannot have a runtime value at
        // its parameter site. This is a structural fact independent of
        // whether the file has an executable semantic artifact.
        if self.rust_bodyless_parameter_source(file, range) {
            return Ok(SourceObservation::BodylessParameter { work });
        }

        let quality = SourceOutcomeQuality::from_outcome(&materialized);
        let Some(artifact) = materialized.available_value().cloned() else {
            return Ok(SourceObservation::Settled(source_outcome_without_value(
                materialized,
            )));
        };

        // A Rust const/static read is represented by the executable procedure
        // at the read site, while its initializer belongs to a declaration
        // outside that procedure. Resolve that origin once and narrow the
        // projection to the terminal name only after the definition proves a
        // literal initializer. All other matched-value users retain the
        // existing source-range behavior.
        let projection_range = self
            .rust_literal_const_read_range(file, range)
            .unwrap_or(range);
        let mut staged = WorkStager::new(request);
        let projection = source_value_observations(
            &artifact,
            projection_range,
            self.limits.source_observations(),
            &mut staged,
            request.cancellation,
        );
        let work = work.conservative_add(staged.work);
        let (observations, truncated) = match projection {
            Ok(_) if request.cancellation.is_cancelled() => {
                request.budget.retain_performed_work(&staged.budget);
                return Ok(SourceObservation::Settled(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                }));
            }
            Ok(projection) => projection,
            Err(Interruption::Budget(exceeded)) => {
                request.budget.retain_performed_work(&staged.budget);
                return Ok(SourceObservation::Settled(
                    SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    },
                ));
            }
            Err(Interruption::Cancelled) => {
                request.budget.retain_performed_work(&staged.budget);
                return Ok(SourceObservation::Settled(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                }));
            }
        };
        *request.budget = staged.budget;
        if observations.is_empty() {
            return Ok(SourceObservation::Settled(SemanticOutcome::Unknown {
                partial: None,
                work,
            }));
        }
        Ok(SourceObservation::Observed(ObservedSource {
            observations,
            truncated,
            materialization_complete: materialized.is_complete(),
            quality,
            work,
        }))
    }

    /// Whether `range` selects a Rust parameter on a signature without an
    /// executable body. A range in the parameter's type is not a parameter
    /// value site, even when the type is nested under the declaration.
    fn rust_bodyless_parameter_source(&self, file: &ProjectFile, range: Range) -> bool {
        if crate::analyzer::common::language_for_file(file) != Language::Rust {
            return false;
        }
        let analyzer = self.workspace.analyzer();
        let Some(source) = analyzer.indexed_source(file) else {
            return false;
        };
        let Some(tree) = parse_tree_for_language(file, Language::Rust, &source) else {
            return false;
        };
        let Some(mut node) =
            smallest_named_node_covering(tree.root_node(), range.start_byte, range.end_byte)
        else {
            return false;
        };
        let parameter = loop {
            if matches!(node.kind(), "parameter" | "self_parameter") {
                break node;
            }
            let Some(parent) = node.parent() else {
                return false;
            };
            node = parent;
        };
        let selected_parameter =
            range.start_byte == parameter.start_byte() && range.end_byte == parameter.end_byte();
        let selected_pattern = parameter
            .child_by_field_name("pattern")
            .is_some_and(|pattern| {
                range.start_byte >= pattern.start_byte() && range.end_byte <= pattern.end_byte()
            });
        if !selected_parameter && !selected_pattern {
            return false;
        }

        let mut owner = parameter.parent();
        while let Some(node) = owner {
            match node.kind() {
                "function_item" => return false,
                "function_signature_item" => {
                    return node.child_by_field_name("body").is_none();
                }
                _ => owner = node.parent(),
            }
        }
        false
    }

    /// Return the terminal name range for a Rust const/static read whose
    /// resolved declaration has a directly literal initializer.
    ///
    /// This deliberately resolves one selected reference at a time. The
    /// result is query-scoped and is used only to improve source projection;
    /// ordinary matched-value source ranges keep their established behavior.
    #[doc(hidden)]
    pub fn rust_literal_const_read_range(&self, file: &ProjectFile, range: Range) -> Option<Range> {
        if crate::analyzer::common::language_for_file(file) != Language::Rust {
            return None;
        }
        let analyzer = self.workspace.analyzer();
        let source = analyzer.indexed_source(file)?;
        let tree = parse_tree_for_language(file, Language::Rust, &source)?;
        let focus =
            smallest_named_node_covering(tree.root_node(), range.start_byte, range.end_byte)?;
        if !matches!(
            focus.kind(),
            "identifier" | "scoped_identifier" | "field_identifier"
        ) {
            return None;
        }

        let request = DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(focus.start_byte()),
            end_byte: Some(focus.end_byte()),
        };
        let outcomes = resolve_definition_batch_with_source(
            analyzer,
            vec![request],
            file.clone(),
            Arc::from(source.as_str()),
        );
        let [outcome] = outcomes.as_slice() else {
            return None;
        };
        if !matches!(outcome.status, DefinitionLookupStatus::Resolved) {
            return None;
        }
        let [definition] = outcome.definitions.as_slice() else {
            return None;
        };
        if definition.kind() != CodeUnitType::Field {
            return None;
        }
        let definition_source = analyzer.indexed_source(definition.source())?;
        let definition_tree =
            parse_tree_for_language(definition.source(), Language::Rust, &definition_source)?;
        let literal_initializer = analyzer
            .location_ranges(definition)
            .into_iter()
            .any(|range| {
                let Some(node) = smallest_named_node_covering(
                    definition_tree.root_node(),
                    range.start_byte,
                    range.end_byte,
                ) else {
                    return false;
                };
                let Some(declaration) = enclosing_rust_const_static(node, range) else {
                    return false;
                };
                declaration
                    .child_by_field_name("value")
                    .is_some_and(rust_literal_initializer)
            });
        literal_initializer.then(|| terminal_rust_name_range(focus))
    }

    /// Resolve dispatch for every semantic call site whose narrowest source
    /// mapping contains `range`.
    ///
    /// This is a bridging seam only: it locates the exact `CallSiteHandle`s at
    /// a source position and delegates each one to the handle-keyed dispatch
    /// oracle. Per-candidate proof, completeness, provenance, typed boundaries,
    /// and each call site's own [`CandidateCoverage`] are retained exactly as
    /// [`crate::analyzer::semantic::DispatchOracle::resolve_call`] reports
    /// them.
    ///
    /// One source range can address several call sites when a procedure is
    /// path-specialized or when equally narrow mappings coincide, so each
    /// answer stays separate under its own call-site identity. The number of
    /// retained call sites is bounded by the oracle's source-observation
    /// limit; reaching that bound is reported through truncated coverage and
    /// an unproven outcome.
    ///
    /// No call site at the position is [`SemanticOutcome::Unknown`], never an
    /// empty proven set: absence of a mapping is absence of evidence.
    pub fn dispatch_at_source(
        &self,
        file: &ProjectFile,
        range: Range,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<SourceDispatchResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let materialized = self
            .workspace
            .materialize_program_semantics(file, request)?;
        self.dispatch_at_source_in_artifact(materialized, range, request)
    }

    /// Resolve source dispatch from an artifact materialization the caller
    /// already charged to `request`.
    ///
    /// The complete materialization outcome is accepted, rather than only its
    /// artifact, so an ambiguous, unproven, unknown, unsupported, budgeted, or
    /// cancelled partial retains exactly the quality it would have had through
    /// [`Self::dispatch_at_source`]. Source-observation limits and every
    /// call-site dispatch budget remain active; this entry point only avoids
    /// paying for the same artifact a second time when a query context already
    /// owns its exact materialization.
    pub fn dispatch_at_source_in_artifact(
        &self,
        materialized: SemanticOutcome<Arc<SemanticArtifact>>,
        range: Range,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<SourceDispatchResult>, SemanticProviderError> {
        self.prepare_source_dispatch_session_in_artifact(materialized)
            .resolve_at_source_recorded(range, request)
    }
}

/// The answer digest the exact handle-keyed dispatch funnel records for
/// `call`.
///
/// Procedure-local replay resolves the structured relative-range address back
/// to exactly one [`CallSiteHandle`] and calls [`DispatchOracle::resolve_call`]
/// directly. Its answer therefore uses the procedure-dispatch domain and
/// stable target lineages, not the artifact-wide source projection's identity
/// terms.
///
/// The materialization quality is `Complete` by construction here: the caller
/// holds a `CallSiteHandle` into an artifact that materialized.
#[doc(hidden)]
pub fn one_call_dispatch_answer_digest(
    call: &CallSiteHandle,
    outcome: &SemanticOutcome<DispatchResult>,
) -> crate::analyzer::semantic::ids::StableDigest {
    let quality = SourceOutcomeQuality::from_outcome(outcome);
    let Some(dispatch) = outcome.available_value() else {
        return procedure_dispatch_answer_digest(quality, None);
    };
    let coverage = projected_source_coverage(
        quality,
        dispatch.coverage().is_truncated(),
        dispatch.coverage().is_exhaustive(),
    );
    procedure_dispatch_answer_digest(
        quality,
        Some(&SourceDispatchResult {
            observations: Box::new([SourceDispatchObservation {
                call: call.clone(),
                dispatch: dispatch.clone(),
            }]),
            coverage,
        }),
    )
}

/// The canonical digest of a dispatch answer: its targets by public artifact
/// fingerprint and procedure id, plus its coverage.
///
/// A target is never named by its `SemanticArtifactKey` or its
/// `SemanticLocator`: both fold the workspace mount, so the same answer at two
/// roots would digest differently and no base unit could ever verify.
pub(crate) fn dispatch_answer_digest(
    result: Option<&SourceDispatchResult>,
) -> crate::analyzer::semantic::ids::StableDigest {
    let mut hasher = crate::analyzer::canonical_hash::CanonicalHasher::new(DISPATCH_ANSWER_DOMAIN);
    let Some(result) = result else {
        hasher.value(b"unavailable");
        return crate::analyzer::semantic::ids::StableDigest::from_array(hasher.finish());
    };
    hasher.field("coverage", result.coverage().label().as_bytes());
    let mut targets = result
        .target_candidates()
        .map(|candidate| {
            let target = candidate.target();
            (
                *target.artifact().key().public_fingerprint().as_bytes(),
                target.id().index(),
            )
        })
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    for (artifact, procedure) in targets {
        hasher.value(&artifact);
        hasher.value(&(procedure as u64).to_be_bytes());
    }
    crate::analyzer::semantic::ids::StableDigest::from_array(hasher.finish())
}

/// Canonical answer for a procedure-local dispatch question.
///
/// This is the complete stable projection that can affect direct-call binding
/// or planning. Query-local provenance is deliberately absent: it certifies
/// the answer inside one oracle request but cannot be replayed across arenas.
/// Stable target lineages exclude whole-artifact source revisions; consumers
/// that enter those bodies record their semantic artifacts or summary
/// dependencies separately.
#[doc(hidden)]
pub fn procedure_dispatch_answer_digest(
    quality: SourceOutcomeQuality,
    result: Option<&SourceDispatchResult>,
) -> crate::analyzer::semantic::ids::StableDigest {
    let mut digest =
        LengthDelimitedDigest::new(b"bifrost-read-ledger:procedure-dispatch-answer:v2");
    push_source_outcome_quality(&mut digest, quality);
    let Some(result) = result else {
        digest.push(b"unavailable");
        return digest.finish();
    };
    digest.push(b"available");
    digest.push(result.coverage().label().as_bytes());
    assert_eq!(
        result.observations().len(),
        1,
        "a procedure dispatch answer belongs to exactly one procedure-local call question"
    );
    digest.push(
        &u64::try_from(result.observations().len())
            .expect("one procedure dispatch observation fits in u64")
            .to_le_bytes(),
    );
    digest.push(
        procedure_dispatch_observation_digest(result.observations()[0].dispatch()).as_bytes(),
    );
    digest.finish()
}

pub(crate) fn procedure_dispatch_observation_digest(dispatch: &DispatchResult) -> StableDigest {
    let mut candidates = dispatch
        .candidates()
        .iter()
        .map(procedure_dispatch_candidate_digest)
        .collect::<Vec<_>>();
    let mut boundaries = dispatch
        .boundaries()
        .iter()
        .map(procedure_dispatch_boundary_digest)
        .collect::<Vec<_>>();
    procedure_dispatch_components_digest(
        dispatch.coverage(),
        dispatch.complete_receiver_hint_refinable(),
        &mut candidates,
        &mut boundaries,
    )
}

#[doc(hidden)]
pub fn procedure_dispatch_boundary_digest(boundary: &DispatchBoundary) -> StableDigest {
    let mut digest =
        LengthDelimitedDigest::new(b"bifrost-read-ledger:procedure-dispatch-boundary:v2");
    digest.push(boundary.kind.label().as_bytes());
    match &boundary.kind {
        DispatchBoundaryKind::External(target) => {
            push_optional_locator(&mut digest, target.as_ref());
        }
        DispatchBoundaryKind::Unmaterialized(target) => {
            push_locator(&mut digest, target);
        }
        DispatchBoundaryKind::Deferred { target, kind } => {
            push_locator(&mut digest, target);
            digest.push(kind.label().as_bytes());
        }
        DispatchBoundaryKind::Unresolved | DispatchBoundaryKind::Truncated => {}
    }

    match boundary.external_callee_identity() {
        Some(identity) => {
            digest.push(b"external-callee-identity");
            digest.push(identity.language().config_label().as_bytes());
            digest.push(identity.owner_fqn().as_bytes());
            digest.push(identity.member().as_bytes());
        }
        None => digest.push(b"no-external-callee-identity"),
    }

    match boundary.exact_external_target() {
        Some(target) => {
            digest.push(b"exact-external-target");
            digest.push(target.artifact().public_fingerprint().as_bytes());
            push_locator(&mut digest, target.procedure());
            digest.push(target.symbol().as_bytes());
            digest.push(&[u8::from(target.has_receiver())]);
            let contract = target.formal_contract();
            digest.push(contract.label().as_bytes());
            digest.push(
                &u64::try_from(contract.parameters().len())
                    .expect("exact external formal count fits in u64")
                    .to_le_bytes(),
            );
            for parameter in contract.parameters() {
                digest.push(parameter.label().as_bytes());
                push_optional_bytes(&mut digest, parameter.declared_type().map(str::as_bytes));
                digest.push(&[u8::from(parameter.optional())]);
                digest.push(&[u8::from(parameter.repeated())]);
            }
            match contract.arity() {
                Some(arity) => {
                    digest.push(b"arity");
                    digest.push(
                        &u64::try_from(arity.required())
                            .expect("required callable arity fits in u64")
                            .to_le_bytes(),
                    );
                    digest.push(
                        &u64::try_from(arity.total())
                            .expect("total callable arity fits in u64")
                            .to_le_bytes(),
                    );
                    digest.push(&[u8::from(arity.is_repeated())]);
                }
                None => digest.push(b"no-arity"),
            }
        }
        None => digest.push(b"no-exact-external-target"),
    }

    match boundary.unmaterialized_external_target() {
        Some(target) => {
            digest.push(b"unmaterialized-external-target");
            push_locator(&mut digest, target.locator());
            digest.push(target.owner_fqn().as_bytes());
            digest.push(target.member().as_bytes());
            digest.push(&target.arity().to_le_bytes());
            digest.push(&[u8::from(target.has_receiver())]);
            digest.push(&[u8::from(target.has_resolver_owned_call_shape())]);
            push_optional_bytes(
                &mut digest,
                target.normalized_static_owner().map(str::as_bytes),
            );
        }
        None => digest.push(b"no-unmaterialized-external-target"),
    }
    push_proof_status(&mut digest, &boundary.proof);
    push_evidence_completeness(&mut digest, &boundary.completeness);
    digest.finish()
}

/// One call site addressed by a source range together with its exact dispatch
/// answer. The call-site handle is retained so consumers key rows on semantic
/// identity rather than on the source range that located it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDispatchObservation {
    #[doc(hidden)]
    pub call: CallSiteHandle,
    #[doc(hidden)]
    pub dispatch: DispatchResult,
}

impl SourceDispatchObservation {
    pub const fn call(&self) -> &CallSiteHandle {
        &self.call
    }

    pub const fn dispatch(&self) -> &DispatchResult {
        &self.dispatch
    }
}

/// Dispatch answers associated with one source range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDispatchResult {
    #[doc(hidden)]
    pub observations: Box<[SourceDispatchObservation]>,
    #[doc(hidden)]
    pub coverage: CandidateCoverage,
}

impl SourceDispatchResult {
    /// Exact call-site dispatch answers retained for the source range.
    pub fn observations(&self) -> &[SourceDispatchObservation] {
        &self.observations
    }

    /// Coverage across both the located call sites and their target sets.
    /// This is `Exhaustive` only when every retained call site was itself
    /// exhaustive and no call site was omitted.
    pub const fn coverage(&self) -> CandidateCoverage {
        self.coverage
    }

    /// Every retained target across the located call sites. Each candidate
    /// keeps the proof, completeness, and provenance the dispatch oracle
    /// attached to it.
    pub fn target_candidates(&self) -> impl Iterator<Item = &DispatchCandidate> {
        self.observations
            .iter()
            .flat_map(|observation| observation.dispatch.candidates())
    }

    pub fn is_empty(&self) -> bool {
        self.observations
            .iter()
            .all(|observation| observation.dispatch.candidates().is_empty())
    }
}

#[cfg(test)]
mod tests {

    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::CandidateCoverage;

    use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::source::procedure_dispatch_components_digest;

    #[test]
    fn procedure_dispatch_v2_is_order_independent_and_rotates_coverage_and_refinement() {
        let candidate_a = StableDigest::sha256(b"candidate-a");
        let candidate_b = StableDigest::sha256(b"candidate-b");
        let boundary_a = StableDigest::sha256(b"boundary-a");
        let boundary_b = StableDigest::sha256(b"boundary-b");
        let baseline = procedure_dispatch_components_digest(
            CandidateCoverage::Open,
            false,
            &mut [candidate_a, candidate_b],
            &mut [boundary_a, boundary_b],
        );
        assert_eq!(
            baseline,
            procedure_dispatch_components_digest(
                CandidateCoverage::Open,
                false,
                &mut [candidate_b, candidate_a],
                &mut [boundary_b, boundary_a],
            ),
            "candidate and boundary iteration order is not answer semantics"
        );
        assert_ne!(
            baseline,
            procedure_dispatch_components_digest(
                CandidateCoverage::Truncated,
                false,
                &mut [candidate_a, candidate_b],
                &mut [boundary_a, boundary_b],
            ),
            "coverage is a binding-relevant axis"
        );
        assert_ne!(
            baseline,
            procedure_dispatch_components_digest(
                CandidateCoverage::Open,
                true,
                &mut [candidate_a, candidate_b],
                &mut [boundary_a, boundary_b],
            ),
            "the typed feedback-refinement exception is a planning-relevant axis"
        );
    }
}
