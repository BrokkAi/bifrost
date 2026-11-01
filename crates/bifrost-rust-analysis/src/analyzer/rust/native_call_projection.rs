//! Selected native Rust incoming and outgoing call relation authority.
//!
//! Canonical inverse rows supply identity and proof, while structural facts
//! supply the exact call expression and its ranges.
//! Projection must run inside the selected operation's callback; only its
//! final Ready outcome authorizes publishing the projected result.
//!
//! Rich projection requests aggregate call evidence by retained SemanticId
//! within the same reverse operation. The binding-only fixture remains useful
//! for checking that call syntax never changes ordinary reference proofs.

use crate::analyzer::rust::RustAnalyzer;

use crate::analyzer::rust::selected_reverse::RustSelectedReverseOutcome;

use crate::analyzer::rust::selected_reverse::with_rust_selected_reverse_queries;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeDerivationResult;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeIncompleteReason;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLanguageRequest;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLookup;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnostic;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnosticCode;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationProvider;
use brokk_bifrost_analysis::analyzer::usages::native_incoming::{
    IncomingCallProjection, IncomingFile, IncomingFileBudget, IncomingProjectionIssue,
    finish_incoming_sites, project_selected_incoming,
};

use brokk_bifrost_analysis::analyzer::usages::call_relations::{
    CallRelationResult, CallerInventoryCoverage,
};

use brokk_bifrost_core::analyzer::usages::model::UsageProofAuthority;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashMap;

pub(crate) struct RustNativeCallRelations;

impl CallRelationProvider for RustNativeCallRelations {
    /// Canonical inverse rows carry real proof tiers, so an omission this
    /// provider reports is a gap in an inventory it claims to have enumerated.
    fn proof_authority(&self) -> UsageProofAuthority {
        UsageProofAuthority::Native
    }

    fn incoming(
        &self,
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        let fallback = CancellationToken::new();
        let cancellation = cancellation.unwrap_or(&fallback);
        if cancellation.is_cancelled() {
            return CallRelationResult {
                caller_inventory: CallerInventoryCoverage::Incomplete,
                cancelled: true,
                ..CallRelationResult::default()
            };
        }
        let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
            return unavailable(
                "native_analyzer_unavailable",
                "Rust analyzer is unavailable",
                target,
            );
        };
        let selected = with_rust_selected_reverse_queries(rust, cancellation, |queries| {
            queries.incoming_calls_for(std::slice::from_ref(target), limits)
        });
        let mut result = match selected {
            RustSelectedReverseOutcome::Ready(Some(mut results)) => {
                assert_eq!(
                    results.len(),
                    1,
                    "one requested incoming target has one result"
                );
                results.pop().expect("one incoming result")
            }
            RustSelectedReverseOutcome::Ready(None) => unavailable(
                "native_incoming_unavailable",
                "selected incoming query stopped without a result",
                target,
            ),
            RustSelectedReverseOutcome::Unavailable(reason) => {
                unavailable("native_unavailable", reason, target)
            }
            RustSelectedReverseOutcome::Stale(reason) => {
                unavailable("native_stale", reason, target)
            }
            RustSelectedReverseOutcome::StoreError(reason) => {
                unavailable("native_store_error", reason, target)
            }
            RustSelectedReverseOutcome::Cancelled => CallRelationResult {
                caller_inventory: CallerInventoryCoverage::Incomplete,
                cancelled: true,
                ..CallRelationResult::default()
            },
        };
        if cancellation.is_cancelled() {
            result.sites.clear();
            result.cancelled = true;
            result.caller_inventory = CallerInventoryCoverage::Incomplete;
        }
        result
    }

    fn outgoing(
        &self,
        analyzer: &dyn IAnalyzer,
        caller: &CodeUnit,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        let fallback = CancellationToken::new();
        let cancellation = cancellation.unwrap_or(&fallback);
        let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
            return unavailable(
                "native_analyzer_unavailable",
                "Rust analyzer is unavailable",
                caller,
            );
        };
        crate::analyzer::rust::native_outgoing::outgoing(
            rust,
            caller,
            limits,
            Default::default(),
            cancellation,
        )
    }

    fn dispatch_special_call_site(
        &self,
        request: CallDispatchLanguageRequest<'_>,
    ) -> Option<CallDispatchLookup> {
        crate::analyzer::rust::format_macro_dispatch::dispatch(request)
    }
}

fn unavailable(kind: &str, message: impl Into<String>, subject: &CodeUnit) -> CallRelationResult {
    CallRelationResult {
        caller_inventory: CallerInventoryCoverage::Incomplete,
        diagnostics: vec![diagnostic(kind, message.into(), subject.fq_name())],
        ..CallRelationResult::default()
    }
}

/// Rich incoming adapter. The paired identities are emitted together with
/// reverse rows, before any presentation sorting or non-call omission.
pub(crate) fn project_rust_rich_call_relation(
    rust: &RustAnalyzer,
    target: &CodeUnit,
    selected: &EdgeDerivationResult,
    references: &[brokk_bifrost_analysis::analyzer::resolution::model::SemanticId],
    queries: &mut dyn brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse::SelectedRustReverseQueries,
    limits: brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits,
    cancellation: &CancellationToken,
) -> brokk_bifrost_analysis::analyzer::store::Result<Option<CallRelationResult>> {
    use brokk_bifrost_analysis::analyzer::resolution::batch::MAX_REFERENCE_SEEDS_PER_BATCH;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

    assert_eq!(selected.edges.len(), references.len());
    let mut result = CallRelationResult {
        caller_inventory: if matches!(selected.completeness, EdgeCompleteness::Complete) {
            CallerInventoryCoverage::Complete
        } else {
            CallerInventoryCoverage::Incomplete
        },
        diagnostics: incomplete_diagnostics(selected, target),
        ..CallRelationResult::default()
    };
    let mut dispatch = |target: &CodeUnit| queries.unenumerable_member_dispatch(target);
    let Some(sites) = project_selected_incoming(
        &mut RustIncomingProjection(rust, &mut dispatch),
        target,
        selected.edges.iter().zip(references.iter().copied()),
        limits,
        cancellation,
        &mut result,
    )?
    else {
        return Ok(None);
    };
    let incomplete_binding_references = finish_incoming_sites(sites, &mut result);
    let mut time_budget_exhausted = false;
    let mut omitted_by_lane = HashMap::<&str, usize>::default();
    let projection_limits_exceeded = result.truncated;
    for references in incomplete_binding_references.chunks(MAX_REFERENCE_SEEDS_PER_BATCH) {
        if time_budget_exhausted {
            *omitted_by_lane.entry("time_budget").or_default() += references.len();
            result.truncated = true;
            continue;
        }
        let Some(answers) = queries.resolve_references(references)? else {
            return Ok(None);
        };
        assert_eq!(answers.len(), references.len());
        for (&reference, slot) in references.iter().zip(answers) {
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse::ReferenceOmission;

            use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse::ReferenceResolution;
            let answers = match slot {
                ReferenceResolution::Answered(answers) => answers,
                ReferenceResolution::Omitted(reason) => {
                    let (lane, is_time_budget) = match reason {
                        ReferenceOmission::ReceiverBudget(limit) => (limit.as_str(), false),
                        ReferenceOmission::TimeBudgetExceeded => ("time_budget", true),
                    };
                    *omitted_by_lane.entry(lane).or_default() += 1;
                    result.truncated = true;
                    time_budget_exhausted |= is_time_budget;
                    continue;
                }
            };
            for answer in answers {
                if answer.call_target_completion() != ResolutionCompletion::Complete {
                    result.diagnostics.push(diagnostic(
                    "native_call_resolution_incomplete",
                    format!("selected Rust call {reference} has incomplete call-target evidence: {:?}; receiver dispositions: {:?}",
                        answer.call_target_completion(), answer.callable_receiver_dispositions()),
                    reference.to_string(),
                ));
                }
                if answer.binding().targets().len() > 1 {
                    result.diagnostics.push(CallRelationDiagnostic {
                        code: CallRelationDiagnosticCode::TargetsAmbiguous,
                        message: format!(
                            "selected Rust call {reference} has ambiguous targets: {:?}",
                            answer.binding().targets()
                        ),
                        context: reference.to_string(),
                        semantic_count: Some(answer.binding().targets().len()),
                        reason_kind: None,
                    });
                }
            }
        }
    }
    for (lane, omitted) in omitted_by_lane {
        if lane == "time_budget" {
            result.diagnostics.retain(|diagnostic| {
                !(diagnostic.code == CallRelationDiagnosticCode::AnalysisFailed
                    && diagnostic.reason_kind.as_deref() == Some("time_budget"))
            });
        }
        result.diagnostics.push(CallRelationDiagnostic {
            code: CallRelationDiagnosticCode::BudgetExhausted,
            message: format!("{omitted} incoming call sites kept unproven because the {lane} budget stopped their binding recheck"),
            context: target.fq_name().to_string(),
            semantic_count: Some(omitted),
            reason_kind: None,
        });
    }
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    if projection_limits_exceeded {
        result.diagnostics.push(CallRelationDiagnostic {
            code: CallRelationDiagnosticCode::BudgetExhausted,
            message: format!("selected Rust incoming call projection exceeded limits {limits:?}"),
            context: target.fq_name().to_string(),
            semantic_count: None,
            reason_kind: None,
        });
    }
    result.diagnostics.sort();
    result.diagnostics.dedup();
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    if result.truncated {
        result.caller_inventory = CallerInventoryCoverage::Incomplete;
    }
    Ok(Some(result))
}

struct RustIncomingProjection<'a>(
    &'a RustAnalyzer,
    &'a mut dyn FnMut(&CodeUnit) -> brokk_bifrost_analysis::analyzer::store::Result<Option<bool>>,
);

impl IncomingCallProjection for RustIncomingProjection<'_> {
    type Error = brokk_bifrost_analysis::analyzer::store::StoreError;

    fn unenumerable_dispatch(&mut self, target: &CodeUnit) -> Result<bool, Self::Error> {
        // The answer reads the target blob's contract and owner rows.
        // Rust has one parse variant, independent of project configuration.
        match self.0.indexed_blob_oid(target.source()) {
            Some(oid) => self.0.record_read(self.0.inner.file_read_key(
                target.source(),
                oid,
                brokk_bifrost_core::gitblob::ParseVariant::Empty,
            )),
            None => self.0.record_unattributed_read(),
        }
        // Cancellation (None) leaves the inventory open.
        Ok(self.1(target)?.unwrap_or(true))
    }

    fn load_file(
        &mut self,
        file: &ProjectFile,
        budget: &mut IncomingFileBudget<'_>,
        _diagnostics: &mut Vec<CallRelationDiagnostic>,
    ) -> Result<IncomingFile, Self::Error> {
        let source = self.0.indexed_source(file).ok_or_else(|| {
            Self::Error::new(format!(
                "selected incoming call has no indexed source for {file}"
            ))
        })?;
        if !budget.admit_source(source.len()) {
            return Ok(IncomingFile::Rejected);
        }
        let facts = self
            .0
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(file));
        if !self
            .0
            .inner
            .source_matches_selected_native_content(file, &source)
            || facts
                .as_ref()
                .is_some_and(|facts| facts.source() != source.as_str())
        {
            return Err(Self::Error::new(format!(
                "selected Rust incoming call source authority changed for {file}",
            )));
        }
        Ok(IncomingFile::Loaded(facts))
    }

    fn report_issue(&self, issue: IncomingProjectionIssue<'_>) -> CallRelationDiagnostic {
        match issue {
            IncomingProjectionIssue::FactsUnavailable(file) => diagnostic(
                "structural_facts_unavailable",
                format!("structured Rust facts are unavailable in {file}"),
                file.to_string(),
            ),
            IncomingProjectionIssue::OwnerUnavailable(edge) => diagnostic(
                "enclosing_caller_unavailable",
                format!(
                    "selected Rust call at {:?} has no callable owner",
                    edge.site
                ),
                edge.site.file.to_string(),
            ),
        }
    }
}

/// Project one completed selected reverse result into the public call
/// relation shape without rerunning resolution.
///
/// The selected result is already the authority for source identity, caller
/// identity, target identity, and proof. This function only supplies the
/// source-level call shape needed by [`CallSite`]. It retains known rows when
/// the native inventory is incomplete and reports the incompleteness as
/// structured diagnostics instead of turning it into an empty answer or a
/// fabricated truncation.
#[cfg(test)]
pub(crate) fn project_rust_call_relation(
    rust: &RustAnalyzer,
    queries: &mut dyn crate::analyzer::rust::selected_reverse::RustSelectedReverseQueries,
    target: &CodeUnit,
    selected: &EdgeDerivationResult,
    cancellation: &CancellationToken,
) -> CallRelationResult {
    let mut result = CallRelationResult {
        caller_inventory: if selected.completeness.is_complete() {
            CallerInventoryCoverage::Complete
        } else {
            CallerInventoryCoverage::Incomplete
        },
        diagnostics: incomplete_diagnostics(selected, target),
        ..CallRelationResult::default()
    };
    let mut dispatch = |target: &CodeUnit| queries.unenumerable_member_dispatch(target);
    if let Some(sites) = project_selected_incoming(
        &mut RustIncomingProjection(rust, &mut dispatch),
        target,
        selected.edges.iter().map(|edge| (edge, ())),
        CallRelationLimits {
            max_files: usize::MAX,
            max_source_bytes: usize::MAX,
            max_candidates: usize::MAX,
        },
        cancellation,
        &mut result,
    )
    .expect("selected source authority is unchanged")
    {
        finish_incoming_sites(sites, &mut result);
    }
    result
}

fn incomplete_diagnostics(
    selected: &EdgeDerivationResult,
    target: &CodeUnit,
) -> Vec<CallRelationDiagnostic> {
    let EdgeCompleteness::Incomplete { reasons } = &selected.completeness else {
        return Vec::new();
    };
    reasons
        .iter()
        .map(|reason| {
            diagnostic(
                incomplete_reason_kind(reason),
                format!(
                    "selected Rust reverse call inventory for {} is incomplete: {reason:?}",
                    target.fq_name()
                ),
                target.fq_name().to_string(),
            )
        })
        .collect()
}

fn incomplete_reason_kind(reason: &EdgeIncompleteReason) -> &'static str {
    match reason {
        EdgeIncompleteReason::AxisUnsupported(_) => "axis_unsupported",
        EdgeIncompleteReason::NoStructuralAdapter => "no_structural_adapter",
        EdgeIncompleteReason::UsageListingTruncated => "usage_listing_truncated",
        EdgeIncompleteReason::UsageAnalysisFailed { .. } => "usage_analysis_failed",
        EdgeIncompleteReason::Cancelled => "cancelled",
        EdgeIncompleteReason::TimeBudgetExceeded => "time_budget",
        EdgeIncompleteReason::OccurrenceRowsIncomplete { .. } => "occurrence_rows_incomplete",
        EdgeIncompleteReason::ReferenceEnumerationIncomplete => "reference_enumeration_incomplete",
        EdgeIncompleteReason::ForwardResolutionIncomplete => "forward_resolution_incomplete",
        EdgeIncompleteReason::ForwardAdmissionIncomplete => "forward_admission_incomplete",
        EdgeIncompleteReason::ForwardMetadataIncomplete => "forward_metadata_incomplete",
        EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete => {
            "inverse_index_reference_enumeration_incomplete"
        }
        EdgeIncompleteReason::InverseIndexResolutionIncomplete => {
            "inverse_index_resolution_incomplete"
        }
        EdgeIncompleteReason::InverseIndexAdmissionIncomplete => {
            "inverse_index_admission_incomplete"
        }
        EdgeIncompleteReason::InverseIndexMetadataIncomplete => "inverse_index_metadata_incomplete",
        EdgeIncompleteReason::InverseIndexTargetUncovered => "inverse_index_target_uncovered",
        EdgeIncompleteReason::SelectedInverseIndexUnavailable { .. } => {
            "selected_inverse_index_unavailable"
        }
    }
}

fn diagnostic(reason_kind: &str, message: String, context: String) -> CallRelationDiagnostic {
    CallRelationDiagnostic::analysis_failed(message, context, reason_kind.to_owned())
}

#[cfg(test)]
mod tests {

    use crate::analyzer::rust::native_call_projection::*;

    use crate::analyzer::rust::selected_reverse::RustSelectedReverseOutcome;

    use crate::analyzer::rust::selected_reverse::with_rust_selected_reverse_queries;

    use brokk_bifrost_core::analyzer::structural::edges::EdgeProvenance;

    use brokk_bifrost_core::analyzer::usages::model::UsageProof;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::CallSyntaxKind;

    use crate::analyzer::rust::test_support::inline_source_project;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::model::Language;

    fn rich_limits() -> brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits
    {
        brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits {
            max_files: 16,
            max_source_bytes: 64 * 1024,
            max_candidates: 64,
        }
    }

    #[test]
    fn rich_incoming_completes_proven_bindings_without_argument_or_receiver_semantics() {
        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::reset_selected_fact_operation_construction_count_for_test;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::selected_fact_operation_construction_count_for_test;
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"rich_calls\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                // The attributed argument keeps call applicability open while
                // the generic callee binding remains exact.
                concat!(
                    "pub async fn delayed() -> usize { 1 }\n",
                    "pub fn generic<T>(value: T) -> T { value }\n",
                    "pub fn caller() { delayed(); generic(#[cfg(any())] 1); let value = delayed; }\n",
                ),
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let targets = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .filter(|unit| matches!(unit.identifier(), "delayed" | "generic"))
            .collect::<Vec<_>>();
        assert_eq!(targets.len(), 2);
        // Observe the thread-local demand counter on the same sole worker
        // that dispatches and confirms the reverse query.
        let (selected, construction_count) = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap()
            .install(|| {
                reset_selected_fact_operation_construction_count_for_test();
                let selected = with_rust_selected_reverse_queries(
                    &rust,
                    &CancellationToken::new(),
                    |queries| {
                        let bindings = queries.inverse_for(&targets)?.expect("binding rows");
                        assert!(
                            bindings
                                .iter()
                                .flat_map(|row| &row.edges)
                                .all(|edge| edge.proof == UsageProof::Proven)
                        );
                        queries.incoming_calls_for(&targets, rich_limits())
                    },
                );
                (
                    selected,
                    selected_fact_operation_construction_count_for_test(),
                )
            });
        let RustSelectedReverseOutcome::Ready(Some(results)) = selected else {
            panic!("rich incoming result must be ready: {selected:?}");
        };
        // Proven callee bindings need no semantic point operation for their
        // arguments or receivers, leaving four reverse-confirmation operations.
        assert_eq!(
            construction_count, 4,
            "reverse confirmation constructs one fact operation per candidate blob"
        );
        assert_eq!(results.len(), 2);
        for result in results {
            assert_eq!(
                result.sites.len(),
                1,
                "non-call references are omitted: {result:?}"
            );
            assert_eq!(result.sites[0].proof, UsageProof::Proven, "{result:?}");
            assert!(
                result
                    .diagnostics
                    .iter()
                    .all(|diagnostic| diagnostic.reason_kind.as_deref()
                        != Some("native_call_resolution_incomplete")),
                "a proven incoming binding must not inherit argument or receiver gaps: {result:?}"
            );
            assert!(!result.truncated, "{result:?}");
        }

        let caller = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "caller")
            .expect("caller declaration");
        let outgoing = crate::analyzer::rust::native_outgoing::outgoing(
            &rust,
            &caller,
            rich_limits(),
            Default::default(),
            &CancellationToken::new(),
        );
        assert!(
            outgoing.diagnostics.iter().all(|diagnostic| {
                diagnostic.reason_kind.as_deref() != Some("native_call_resolution_incomplete")
            }),
            "outgoing call edges must not inherit return or argument type projections: {outgoing:?}"
        );
    }

    #[test]
    fn rich_incoming_keeps_ambiguity_limits_and_terminal_publication_laws() {
        let (fixture, rust) = fixture();
        let declarations = rust.declarations(&fixture.file("src/lib.rs"));
        let target = declarations
            .iter()
            .find(|unit| unit.identifier() == "target" && unit.owner_identifier() == Some("left"))
            .expect("ambiguous target");
        let method = declarations
            .iter()
            .find(|unit| unit.identifier() == "method")
            .expect("method");
        let selected = with_rust_selected_reverse_queries(
            &rust,
            &CancellationToken::new(),
            |queries| {
                let ambiguous = queries
                    .incoming_calls_for(std::slice::from_ref(target), rich_limits())?
                    .expect("ambiguous call");
                let bounded = queries
                    .incoming_calls_for(
                        std::slice::from_ref(method),
                        brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits {
                            max_candidates: 1,
                            ..rich_limits()
                        },
                    )?
                    .expect("bounded calls");
                let empty = queries
                    .incoming_calls_for(
                        std::slice::from_ref(method),
                        brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits {
                            max_files: 0,
                            ..rich_limits()
                        },
                    )?
                    .expect("bounded empty calls");
                let omitted = queries
                    .incoming_calls_for(
                        std::slice::from_ref(method),
                        brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits {
                            max_candidates: 0,
                            ..rich_limits()
                        },
                    )?
                    .expect("zero target arm budget");
                Ok((ambiguous, bounded, empty, omitted))
            },
        );
        let RustSelectedReverseOutcome::Ready((ambiguous, bounded, empty, omitted)) = selected
        else {
            panic!("rich incoming result must be ready: {selected:?}");
        };
        assert_eq!(ambiguous[0].sites.len(), 1, "{ambiguous:?}");
        assert_eq!(ambiguous[0].sites[0].proof, UsageProof::Unproven);
        assert!(
            ambiguous[0]
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CallRelationDiagnosticCode::TargetsAmbiguous)
        );
        assert_eq!(bounded[0].sites.len(), 1, "{bounded:?}");
        assert!(bounded[0].truncated);
        assert_eq!(bounded[0].work.examined_candidates, 1);
        let limits = CallRelationLimits {
            max_candidates: 1,
            ..rich_limits()
        };
        assert!(
            bounded[0].diagnostics.iter().any(|diagnostic| {
                diagnostic.code == CallRelationDiagnosticCode::BudgetExhausted
                    && diagnostic.message
                        == format!(
                            "selected Rust incoming call projection exceeded limits {limits:?}"
                        )
            }),
            "{bounded:?}"
        );
        assert!(empty[0].sites.is_empty());
        assert!(empty[0].truncated);
        assert!(omitted[0].sites.is_empty());
        assert!(omitted[0].truncated);
        assert_eq!(omitted[0].work.examined_candidates, 0);

        let cancellation = CancellationToken::new();
        let cancelled = with_rust_selected_reverse_queries(&rust, &cancellation, |queries| {
            let staged = queries
                .incoming_calls_for(std::slice::from_ref(method), rich_limits())?
                .expect("staged calls");
            assert_eq!(staged[0].sites.len(), 2);
            cancellation.cancel();
            Ok(staged)
        });
        assert!(
            matches!(cancelled, RustSelectedReverseOutcome::Cancelled),
            "{cancelled:?}"
        );
        let unavailable =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                let staged = queries
                    .incoming_calls_for(std::slice::from_ref(method), rich_limits())?
                    .expect("staged calls");
                assert!(
                    queries
                        .incoming_calls_for(
                            &[CodeUnit::file_scope(fixture.file("src/lib.rs"))],
                            rich_limits()
                        )?
                        .is_none()
                );
                Ok(staged)
            });
        assert!(
            matches!(unavailable, RustSelectedReverseOutcome::Unavailable(_)),
            "{unavailable:?}"
        );
    }

    #[test]
    fn caller_inventory_empty_cancelled_and_truncated() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"inventory\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub fn unused() {} pub fn target() {} pub fn caller() { target(); }",
            )
            .build();
        let rust = RustAnalyzer::new(fixture.project_dyn());
        let declarations = rust.declarations(&fixture.file("src/lib.rs"));
        let unused = declarations
            .iter()
            .find(|u| u.identifier() == "unused")
            .unwrap();
        let target = declarations
            .iter()
            .find(|u| u.identifier() == "target")
            .unwrap();
        let query = |target, limits, token: &CancellationToken| {
            RustNativeCallRelations.incoming(&rust, target, limits, Some(token))
        };
        let empty = query(unused, rich_limits(), &CancellationToken::default());
        assert!(empty.sites.is_empty(), "{empty:?}");
        assert_eq!(
            empty.caller_inventory,
            CallerInventoryCoverage::Complete,
            "{empty:?}"
        );
        let uncovered = CodeUnit::new(
            fixture.file("src/missing.rs"),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
            "",
            "removed",
        );
        assert_eq!(
            query(&uncovered, rich_limits(), &CancellationToken::default()).caller_inventory,
            CallerInventoryCoverage::Incomplete
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            query(target, rich_limits(), &cancelled).caller_inventory,
            CallerInventoryCoverage::Incomplete
        );
        let mut limits = rich_limits();
        limits.max_candidates = 0;
        assert_eq!(
            query(target, limits, &CancellationToken::default()).caller_inventory,
            CallerInventoryCoverage::Incomplete
        );
    }

    #[test]
    fn rust_incoming_work_is_bounded_to_target_candidates_and_matches_selected_result() {
        let mut project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"native_call_admission\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source());
        for index in 0..8 {
            project = project.file(
                format!("src/unrelated_{index}.rs"),
                format!("pub fn unrelated_{index}() {{}}\n"),
            );
        }
        let fixture = project.build();
        let rust = RustAnalyzer::new(fixture.project_dyn());

        let target = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "target" && unit.owner_identifier() == Some("left"))
            .expect("left target declaration");
        let limits = brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits {
            max_files: 4,
            max_source_bytes: 64 * 1024,
            max_candidates: 64,
        };
        let expected =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::new(), |queries| {
                let mut results = queries
                    .incoming_calls_for(std::slice::from_ref(&target), limits)?
                    .expect("selected incoming result");
                assert_eq!(results.len(), 1);
                Ok(results.pop().expect("one target result"))
            });
        let RustSelectedReverseOutcome::Ready(expected) = expected else {
            panic!("selected incoming query must be ready: {expected:?}");
        };

        let actual = RustNativeCallRelations.incoming(&rust, &target, limits, None);
        assert_eq!(actual.sites, expected.sites);
        assert_eq!(actual.diagnostics, expected.diagnostics);
        assert_eq!(actual.truncated, expected.truncated);
        assert_eq!(actual.cancelled, expected.cancelled);
        assert_eq!(actual.proof_authority, expected.proof_authority);
        assert_eq!(
            RustNativeCallRelations.proof_authority(),
            UsageProofAuthority::Native
        );
        assert_eq!(actual.sites.len(), 1);
        assert_eq!(actual.sites[0].proof, UsageProof::Unproven);
        assert!(
            actual.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == CallRelationDiagnosticCode::TargetsAmbiguous
            })
        );
        assert_eq!(
            actual.work.scanned_files, 1,
            "only the selected edge file is scanned"
        );
        assert_eq!(
            actual.work.scanned_source_bytes,
            source().len(),
            "unrelated Rust source bytes are not charged"
        );
        assert_eq!(
            actual.work.examined_candidates,
            expected.work.examined_candidates
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#8388: composed taint trusted a native Rust reverse inventory that missed callers through a function value"
    )]
    fn caller_inventory_function_value_escape() {
        // Every way Rust names a fn item or associated fn as a value. Each
        // escaping target can be called through that value from sites the
        // selected inverse never enumerates; the direct-call control cannot.
        let (fixture, rust) = inline_source_project(
            "escaped_callers",
            concat!(
                "pub fn target() {}\n",
                "pub fn mapped(value: u8) -> u8 { value }\n",
                "pub fn pointer() {}\n",
                "pub fn shorthand() {}\n",
                "pub fn field_value() {}\n",
                "pub fn generic<T>() {}\n",
                "pub fn captured() {}\n",
                "pub fn direct() {}\n",
                "pub struct Holder { pub shorthand: fn(), pub handler: fn() }\n",
                "pub struct Service;\n",
                "impl Service { pub fn associated() {} }\n",
                "pub trait Hook { fn hooked(); }\n",
                "impl Hook for Service { fn hooked() {} }\n",
                "pub fn invoke(f: fn()) { f(); }\n",
                "pub fn caller() -> impl Fn() -> fn() {\n",
                "    let f = target; f(); invoke(target);\n",
                "    let _ = [1u8].iter().copied().map(mapped).count();\n",
                "    let p: fn() = pointer; p();\n",
                "    let _ = Holder { shorthand, handler: field_value };\n",
                "    let a: fn() = Service::associated; a();\n",
                "    let h: fn() = <Service as Hook>::hooked; h();\n",
                "    let g: fn() = generic::<u8>; g();\n",
                "    direct();\n",
                "    move || captured\n",
                "}\n",
            ),
        );
        let declarations = rust.declarations(&fixture.file("src/lib.rs"));
        let mut actual = Vec::new();
        for name in [
            "target",
            "mapped",
            "pointer",
            "shorthand",
            "field_value",
            "associated",
            "hooked",
            "generic",
            "captured",
            "direct",
        ] {
            let target = declarations
                .iter()
                .find(|unit| unit.identifier() == name && !unit.is_field())
                .unwrap_or_else(|| panic!("{name} declaration: {declarations:?}"));
            let result = RustNativeCallRelations.incoming(&rust, target, rich_limits(), None);
            actual.push((name, result.caller_inventory));
        }
        let expected = actual
            .iter()
            .map(|(name, _)| {
                let coverage = if *name == "direct" {
                    CallerInventoryCoverage::Complete
                } else {
                    CallerInventoryCoverage::Incomplete
                };
                (*name, coverage)
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#8457: a Rust trait-impl member kept a Complete caller inventory while std, operators and loops call it"
    )]
    fn caller_inventory_trait_implementation_dispatch() {
        let (fixture, rust) = inline_source_project(
            "trait_dispatch_callers",
            concat!(
                "use std::fmt;\n",
                "pub struct X;\n",
                "impl fmt::Display for X { fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result { Ok(()) } }\n",
                "pub fn show(x: &X) -> String { format!(\"{x}\") }\n",
                "pub struct Y;\n",
                "impl Iterator for Y { type Item = (); fn next(&mut self) -> Option<()> { None } }\n",
                "pub fn walk(y: Y) { for _ in y {} }\n",
                "pub struct Z;\n",
                "impl Drop for Z { fn drop(&mut self) {} }\n",
                "pub fn scope() { let _z = Z; }\n",
                "pub trait T { fn m(&self); }\n",
                "pub struct W;\n",
                "impl T for W { fn m(&self) {} }\n",
                "pub fn via_dyn(w: &W) { let d: &dyn T = w; d.m(); }\n",
                // A trait impl produced by a macro has no selected definition,
                // so its inventory is already incomplete before the hook runs.
                "pub struct M;\n",
                "macro_rules! make_display { ($item:item) => { $item }; }\n",
                "make_display! { impl fmt::Display for M { fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result { Ok(()) } } }\n",
                "pub struct Service;\n",
                "impl Service { pub fn inherent(&self) {} }\n",
                "pub fn direct(s: &Service) { s.inherent(); }\n",
            ),
        );
        let declarations = rust.declarations(&fixture.file("src/lib.rs"));
        let mut actual = Vec::new();
        for (name, owner) in [
            ("fmt", "X"),
            ("next", "Y"),
            ("drop", "Z"),
            ("m", "W"),
            ("fmt", "M"),
            ("inherent", "Service"),
        ] {
            let target = declarations
                .iter()
                .find(|unit| unit.identifier() == name && unit.owner_identifier() == Some(owner))
                .unwrap_or_else(|| panic!("{owner}::{name} declaration: {declarations:?}"));
            let result = RustNativeCallRelations.incoming(&rust, target, rich_limits(), None);
            actual.push((owner, result.caller_inventory));
        }
        assert_eq!(
            actual,
            vec![
                ("X", CallerInventoryCoverage::Incomplete),
                ("Y", CallerInventoryCoverage::Incomplete),
                ("Z", CallerInventoryCoverage::Incomplete),
                ("W", CallerInventoryCoverage::Incomplete),
                ("M", CallerInventoryCoverage::Incomplete),
                ("Service", CallerInventoryCoverage::Complete),
            ]
        );
    }

    fn source() -> &'static str {
        concat!(
            "mod left { pub fn target(value: usize) {} }\n",
            "mod right { pub fn target(value: usize) {} }\n",
            "use left::*;\n",
            "use right::*;\n",
            "pub struct Service;\n",
            "impl Service { pub fn method(&self, value: usize) {} }\n",
            "pub fn free(value: usize) {}\n",
            "pub fn caller(service: Service) {\n",
            "    free(1);\n",
            "    service.method(2);\n",
            "    service.method(3);\n",
            "    target(4);\n",
            "    let value = free;\n",
            "    let _ = value;\n",
            "}\n",
        )
    }

    #[track_caller]
    fn fixture() -> (crate::inline_project::BuiltInlineTestProject, RustAnalyzer) {
        inline_source_project("native_call_projection", source())
    }

    #[test]
    fn projection_keeps_incomplete_diagnostics_and_discards_cancelled_prefix() {
        let (fixture, rust) = fixture();
        let method = rust
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| {
                unit.identifier() == "method" && unit.owner_identifier() == Some("Service")
            })
            .expect("inherent method declaration");
        // Keep every projection inside the selected operation so its facts
        // and rows share the operation's finalized source authority.
        let selected =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::default(), |queries| {
                let mut rows = queries
                    .inverse_for(std::slice::from_ref(&method))?
                    .expect("method reverse row");
                let mut incomplete = rows.pop().expect("method reverse row");
                incomplete.completeness = EdgeCompleteness::Incomplete {
                    reasons: vec![EdgeIncompleteReason::InverseIndexResolutionIncomplete],
                };
                let projected = project_rust_call_relation(
                    &rust,
                    queries,
                    &method,
                    &incomplete,
                    &CancellationToken::default(),
                );

                let mut missing_owner = incomplete.clone();
                missing_owner.edges[0].site.enclosing = None;
                let missing_owner_projected = project_rust_call_relation(
                    &rust,
                    queries,
                    &method,
                    &missing_owner,
                    &CancellationToken::default(),
                );

                // Cancel at every check in turn, so the test does not depend on
                // how often the projector polls: entry, mid-prefix and late.
                let mut cancelled_runs = Vec::new();
                let mut completed = None;
                for checks in 1..=256 {
                    let token = CancellationToken::cancel_after_checks_for_test(checks);
                    let result =
                        project_rust_call_relation(&rust, queries, &method, &incomplete, &token);
                    if !result.cancelled {
                        completed = Some(checks);
                        break;
                    }
                    cancelled_runs.push((checks, result));
                }
                assert!(completed.is_some(), "projection never completed");
                Ok((projected, missing_owner_projected, cancelled_runs))
            });
        let RustSelectedReverseOutcome::Ready((projected, missing_owner_projected, cancelled_runs)) =
            selected
        else {
            panic!("selected reverse rows must be ready: {selected:?}");
        };
        assert_eq!(
            projected.sites.len(),
            2,
            "known rows remain visible: {projected:?}"
        );
        assert_eq!(
            projected.caller_inventory,
            CallerInventoryCoverage::Incomplete
        );
        assert!(!projected.truncated);
        assert!(projected.diagnostics.iter().any(|diagnostic| {
            diagnostic.reason_kind.as_deref() == Some("inverse_index_resolution_incomplete")
        }));

        assert!(
            missing_owner_projected
                .diagnostics
                .iter()
                .any(|diagnostic| {
                    diagnostic.reason_kind.as_deref() == Some("enclosing_caller_unavailable")
                })
        );

        // The edge loop checks once per row, so with two rows at least one
        // run cancels after a projected prefix.
        assert!(
            cancelled_runs.len() >= 2,
            "no cancellation after a projected prefix: {cancelled_runs:?}"
        );
        for (checks, cancelled) in &cancelled_runs {
            assert!(cancelled.cancelled, "after {checks} checks: {cancelled:?}");
            assert!(
                cancelled.sites.is_empty(),
                "cancelled projection published a prefix after {checks} checks: {cancelled:?}"
            );
            assert_eq!(
                cancelled.caller_inventory,
                CallerInventoryCoverage::Incomplete,
                "after {checks} checks"
            );
            assert!(!cancelled.truncated, "after {checks} checks");
        }
    }

    #[test]
    fn selected_reverse_rows_project_free_member_and_ambiguous_calls() {
        let (fixture, rust) = fixture();
        let declarations = rust.declarations(&fixture.file("src/lib.rs"));
        let free = declarations
            .iter()
            .find(|unit| unit.identifier() == "free")
            .cloned()
            .expect("free target declaration");
        let method = declarations
            .iter()
            .find(|unit| {
                unit.identifier() == "method" && unit.owner_identifier() == Some("Service")
            })
            .cloned()
            .expect("inherent method declaration");
        let left_target = declarations
            .iter()
            .find(|unit| unit.identifier() == "target" && unit.owner_identifier() == Some("left"))
            .cloned()
            .expect("left wildcard target declaration");
        let caller = declarations
            .iter()
            .find(|unit| unit.identifier() == "caller")
            .cloned()
            .expect("caller declaration");

        // Keep shape projection inside the selected operation. Its structural
        // facts must come from the same finalized source authority as rows.
        let selected =
            with_rust_selected_reverse_queries(&rust, &CancellationToken::default(), |queries| {
                let rows = queries
                    .inverse_for(&[free.clone(), method.clone(), left_target.clone()])?
                    .expect("selected target rows");
                assert_eq!(rows.len(), 3, "{rows:?}");
                assert!(
                    rows.iter()
                        .all(|row| row.provenance == EdgeProvenance::Inverse)
                );

                let row_for = |target: &CodeUnit| {
                    rows.iter()
                        .find(|row| row.edges.iter().any(|edge| edge.target == *target))
                        .expect("selected target row")
                };
                let free_result = project_rust_call_relation(
                    &rust,
                    queries,
                    &free,
                    row_for(&free),
                    &CancellationToken::default(),
                );
                let method_result = project_rust_call_relation(
                    &rust,
                    queries,
                    &method,
                    row_for(&method),
                    &CancellationToken::default(),
                );
                let mut exhaustive_ambiguous = row_for(&left_target).clone();
                exhaustive_ambiguous.completeness = EdgeCompleteness::Complete;
                let ambiguous_result = project_rust_call_relation(
                    &rust,
                    queries,
                    &left_target,
                    &exhaustive_ambiguous,
                    &CancellationToken::default(),
                );
                let mut non_call = row_for(&free).clone();
                let value_reference_start = source()
                    .find("let value = free;")
                    .expect("value-reference fixture")
                    + "let value = ".len();
                let edge = non_call
                    .edges
                    .iter_mut()
                    .find(|edge| edge.site.range.start_byte == value_reference_start)
                    .expect("selected non-call value reference");
                edge.site.enclosing = None;
                let non_call_result = project_rust_call_relation(
                    &rust,
                    queries,
                    &free,
                    &non_call,
                    &CancellationToken::default(),
                );
                Ok((
                    free_result,
                    method_result,
                    ambiguous_result,
                    non_call_result,
                ))
            });
        let RustSelectedReverseOutcome::Ready((
            free_result,
            method_result,
            ambiguous_result,
            non_call_result,
        )) = selected
        else {
            panic!("selected reverse rows must be ready: {selected:?}");
        };
        assert_eq!(free_result.sites.len(), 1, "{free_result:?}");
        let free_site = &free_result.sites[0];
        assert_eq!(free_site.caller, caller);
        assert_eq!(free_site.callee, free);
        assert_eq!(free_site.kind, CallSyntaxKind::Function);
        assert_eq!(free_site.proof, UsageProof::Proven);
        let source = source();
        assert_eq!(
            &source[free_site.range.start_byte..free_site.range.end_byte],
            "free(1)"
        );
        assert_eq!(free_site.arguments.len(), 1);
        assert_eq!(
            &source[free_site.arguments[0].range.start_byte..free_site.arguments[0].range.end_byte],
            "1"
        );

        assert_eq!(method_result.sites.len(), 2, "{method_result:?}");
        for (site, argument) in method_result.sites.iter().zip(["2", "3"]) {
            assert_eq!(site.caller, caller);
            assert_eq!(site.callee, method);
            assert_eq!(site.kind, CallSyntaxKind::Method);
            assert_eq!(site.proof, UsageProof::Proven);
            let receiver = site.receiver.expect("method receiver");
            assert_eq!(&source[receiver.start_byte..receiver.end_byte], "service");
            assert_eq!(site.arguments.len(), 1);
            assert_eq!(
                &source[site.arguments[0].range.start_byte..site.arguments[0].range.end_byte],
                argument
            );
        }

        assert_eq!(
            ambiguous_result.caller_inventory,
            CallerInventoryCoverage::Complete
        );
        assert_eq!(ambiguous_result.sites.len(), 1, "{ambiguous_result:?}");
        assert_eq!(ambiguous_result.sites[0].proof, UsageProof::Unproven);
        assert_eq!(ambiguous_result.sites[0].caller, caller);
        assert_eq!(
            free_result.caller_inventory,
            CallerInventoryCoverage::Incomplete
        );
        assert_eq!(
            non_call_result.caller_inventory,
            CallerInventoryCoverage::Incomplete
        );
        assert_eq!(
            method_result.caller_inventory,
            CallerInventoryCoverage::Complete
        );
        assert_eq!(non_call_result.sites, free_result.sites);
        assert!(!non_call_result.diagnostics.iter().any(|diagnostic| {
            diagnostic.reason_kind.as_deref() == Some("enclosing_caller_unavailable")
        }));
    }
}
