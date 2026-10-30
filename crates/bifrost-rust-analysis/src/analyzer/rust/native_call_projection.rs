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

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationResult;

#[cfg(test)]
use brokk_bifrost_analysis::analyzer::usages::call_relations::CallSite;

#[cfg(test)]
use brokk_bifrost_analysis::analyzer::usages::call_relations::is_call_relation_unit;

#[cfg(test)]
use brokk_bifrost_analysis::analyzer::usages::call_relations::raw_call_site;

#[cfg(test)]
use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::CallSiteSyntax;

#[cfg(test)]
use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::call_site_syntax_for_reference;

#[cfg(test)]
use brokk_bifrost_core::analyzer::usages::model::UsageProof;

use brokk_bifrost_core::analyzer::usages::model::UsageProofAuthority;

#[cfg(test)]
use brokk_bifrost_analysis::analyzer::usages::proof_rank;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashMap;
#[cfg(test)]
use std::sync::Arc;

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
                cancelled: true,
                ..CallRelationResult::default()
            },
        };
        if cancellation.is_cancelled() {
            result.sites.clear();
            result.cancelled = true;
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
        diagnostics: incomplete_diagnostics(selected, target),
        ..CallRelationResult::default()
    };
    let Some(sites) = project_selected_incoming(
        &mut RustIncomingProjection(rust),
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
            reason_kind: None,
        });
    }
    result.diagnostics.sort();
    result.diagnostics.dedup();
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    Ok(Some(result))
}

struct RustIncomingProjection<'a>(&'a RustAnalyzer);

impl IncomingCallProjection for RustIncomingProjection<'_> {
    type Error = brokk_bifrost_analysis::analyzer::store::StoreError;

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
    target: &CodeUnit,
    selected: &EdgeDerivationResult,
    cancellation: &CancellationToken,
) -> CallRelationResult {
    let mut diagnostics = incomplete_diagnostics(selected, target);
    let mut facts_by_file: HashMap<
        ProjectFile,
        Option<Arc<brokk_bifrost_analysis::analyzer::structural::facts::FileFacts>>,
    > = HashMap::default();
    let mut sites = Vec::with_capacity(selected.edges.len());

    if cancellation.is_cancelled() {
        return CallRelationResult {
            cancelled: true,
            diagnostics,
            ..CallRelationResult::default()
        };
    }

    for edge in &selected.edges {
        if cancellation.is_cancelled() {
            sites.clear();
            return CallRelationResult {
                cancelled: true,
                diagnostics,
                ..CallRelationResult::default()
            };
        }
        if edge.target != *target {
            diagnostics.push(diagnostic(
                "native_reverse_target_mismatch",
                format!(
                    "selected Rust reverse row targets {}, expected {}",
                    edge.target.fq_name(),
                    target.fq_name()
                ),
                target.fq_name().to_string(),
            ));
            continue;
        }

        let facts = facts_by_file
            .entry(edge.site.file.clone())
            .or_insert_with(|| {
                rust.structural_fact_providers()
                    .into_iter()
                    .find_map(|provider| provider.structural_facts(&edge.site.file))
            });
        if cancellation.is_cancelled() {
            sites.clear();
            return CallRelationResult {
                cancelled: true,
                diagnostics,
                ..CallRelationResult::default()
            };
        }
        let Some(facts) = facts.as_ref() else {
            diagnostics.push(diagnostic(
                "structural_facts_unavailable",
                format!(
                    "structured Rust facts are unavailable for selected call row in {}",
                    edge.site.file
                ),
                edge.site.file.to_string(),
            ));
            continue;
        };
        // A reference row can point at a value, import, or other non-call
        // occurrence in the same declaration. Only the structured call
        // helper can admit it as an incoming call; a missing call shape is a
        // normal non-call omission, not an authoritative empty result.
        let Some(syntax) = call_site_syntax_for_reference(
            facts,
            edge.site.range.start_byte,
            edge.site.range.end_byte,
        ) else {
            continue;
        };

        let Some(caller) = edge.site.enclosing.as_ref() else {
            diagnostics.push(diagnostic(
                "enclosing_caller_unavailable",
                format!(
                    "selected Rust call row at {}:[{}, {}) has no enclosing caller",
                    edge.site.file, edge.site.range.start_byte, edge.site.range.end_byte
                ),
                edge.site.file.to_string(),
            ));
            continue;
        };
        if !is_call_relation_unit(caller) {
            diagnostics.push(diagnostic(
                "enclosing_caller_not_callable",
                format!(
                    "selected Rust call row at {}:[{}, {}) has non-callable owner {}",
                    edge.site.file,
                    edge.site.range.start_byte,
                    edge.site.range.end_byte,
                    caller.fq_name()
                ),
                caller.fq_name().to_string(),
            ));
            continue;
        }

        sites.push(call_site(
            edge.site.file.clone(),
            caller.clone(),
            target,
            syntax,
            edge.proof,
        ));
    }

    sites.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| {
                (
                    left.range.start_byte,
                    left.range.end_byte,
                    left.range.start_line,
                    left.range.end_line,
                )
                    .cmp(&(
                        right.range.start_byte,
                        right.range.end_byte,
                        right.range.start_line,
                        right.range.end_line,
                    ))
            })
            .then_with(|| left.caller.cmp(&right.caller))
            .then_with(|| left.callee.cmp(&right.callee))
            .then_with(|| proof_rank(left.proof).cmp(&proof_rank(right.proof)))
    });
    sites.dedup();
    diagnostics.sort();
    diagnostics.dedup();
    if cancellation.is_cancelled() {
        sites.clear();
        return CallRelationResult {
            cancelled: true,
            diagnostics,
            ..CallRelationResult::default()
        };
    }
    CallRelationResult {
        sites,
        diagnostics,
        ..CallRelationResult::default()
    }
}

#[cfg(test)]
fn call_site(
    file: ProjectFile,
    caller: CodeUnit,
    target: &CodeUnit,
    syntax: CallSiteSyntax,
    proof: UsageProof,
) -> CallSite {
    raw_call_site(file, caller, target.clone(), syntax, proof)
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
                    &method,
                    &incomplete,
                    &CancellationToken::default(),
                );

                let mut missing_owner = incomplete.clone();
                missing_owner.edges[0].site.enclosing = None;
                let missing_owner_projected = project_rust_call_relation(
                    &rust,
                    &method,
                    &missing_owner,
                    &CancellationToken::default(),
                );

                let cancelled = CancellationToken::cancel_after_checks_for_test(5);
                let cancelled_projected =
                    project_rust_call_relation(&rust, &method, &incomplete, &cancelled);
                Ok((projected, missing_owner_projected, cancelled_projected))
            });
        let RustSelectedReverseOutcome::Ready((
            projected,
            missing_owner_projected,
            cancelled_projected,
        )) = selected
        else {
            panic!("selected reverse rows must be ready: {selected:?}");
        };
        assert_eq!(
            projected.sites.len(),
            2,
            "known rows remain visible: {projected:?}"
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

        assert!(cancelled_projected.cancelled);
        assert!(
            cancelled_projected.sites.is_empty(),
            "cancelled projection published a prefix: {cancelled_projected:?}"
        );
        assert!(!cancelled_projected.truncated);
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
                    &free,
                    row_for(&free),
                    &CancellationToken::default(),
                );
                let method_result = project_rust_call_relation(
                    &rust,
                    &method,
                    row_for(&method),
                    &CancellationToken::default(),
                );
                let ambiguous_result = project_rust_call_relation(
                    &rust,
                    &left_target,
                    row_for(&left_target),
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

        assert_eq!(ambiguous_result.sites.len(), 1, "{ambiguous_result:?}");
        assert_eq!(ambiguous_result.sites[0].proof, UsageProof::Unproven);
        assert_eq!(ambiguous_result.sites[0].caller, caller);
        assert_eq!(non_call_result.sites, free_result.sites);
        assert!(!non_call_result.diagnostics.iter().any(|diagnostic| {
            diagnostic.reason_kind.as_deref() == Some("enclosing_caller_unavailable")
        }));
    }
}
