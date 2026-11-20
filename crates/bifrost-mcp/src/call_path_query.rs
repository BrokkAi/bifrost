//! The call-path question of `flow_query`: can the callable that owns point A
//! reach the call selected as B through certified static calls?
//!
//! The engine is RQL `call_reachability`. It reads source and sink selections
//! as RQL plans, so each point becomes one: the source plan selects the
//! callables of A's name in A's file, the sink plan every call in B's file. The
//! selections are broader than the points. The answer keeps only the engine's
//! evidence that is exact: a root whose span contains A, and a path whose final
//! call is at B's exact span. No pattern is built from source text. The engine's
//! coverage and diagnostics pass through unchanged. The answer is callable-level:
//! it says nothing about order from the selected position (#13528).

use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_tools::site_context::{SiteAdmission, SiteAdmissionRefusal, SiteRole, view};

use crate::flow::FlowWorkspaceState;
use crate::flow_query::{
    Answer, EngineReason, FlowEngine, FlowGranularity, FlowQueryResult, FlowQuestion, PairOutcome,
    Selected, StaticCallStep, Unsupported, Witness, WitnessStep, answered_all, span_site,
};
use crate::rql::structural::search::{CallPathCoverage, CodeQueryCompletion};
use crate::rql::{
    CodeQuery, CodeQueryExecutionLimits,
    structural::search::execute_code_query_detailed_eager_index_workspace,
};

pub(crate) fn call_path(
    workspace: &WorkspaceAnalyzer,
    flow_state: &FlowWorkspaceState,
    from: &Selected,
    to: &Selected,
    cancellation: &CancellationToken,
) -> Result<FlowQueryResult, crate::flow_query::FlowQueryError> {
    let question = FlowQuestion::CallPath;
    let unsupported = |detail| {
        Ok(FlowQueryResult::Unsupported {
            question,
            reason: Unsupported::CallPathEndpoints { detail },
        })
    };
    let procedure = from.point().procedure();
    let Some(name) = procedure
        .semantics()
        .locator()
        .declaration()
        .last_segment_name()
    else {
        return unsupported("the origin point's callable has no name");
    };
    let from_site = from.span();
    let to_site = to.span();
    let query = serde_json::json!({
        "call_reachability": {
            "sources": {
                "where": [from_site.rel_path.clone()],
                "match": {"kind": "callable", "name": name}
            },
            "sinks": {
                "where": [to_site.rel_path.clone()],
                "match": {"kind": "call"}
            }
        }
    });
    let query = CodeQuery::from_json(&query).expect("the call-path plan is a valid CodeQuery");
    let detailed = execute_code_query_detailed_eager_index_workspace(
        workspace,
        flow_state,
        &query,
        CodeQueryExecutionLimits::default(),
        Some(cancellation),
    );

    // The exact root: the narrowest selected callable that contains point A.
    let mut roots: Vec<_> = detailed
        .evidence
        .iter()
        .filter(|row| {
            row.file == *from_site.path
                && row.byte_span.as_ref().is_some_and(|span| {
                    span.start <= from_site.byte_range.start && from_site.byte_range.end <= span.end
                })
        })
        .collect();
    roots.sort_by_key(|row| row.byte_span.as_ref().map(|span| span.end - span.start));
    let exact_root = roots.first().copied();

    let mut reasons: Vec<EngineReason> = Vec::new();
    let mut path_steps: Option<Vec<WitnessStep>> = None;
    if let Some(row) = exact_root {
        let evidence = row
            .call_path_evidence
            .as_ref()
            .expect("a call-reachability row carries its path evidence");
        // Dropped paths always add an ExecutionBudget gap beside `truncated`
        // (call_reachability.rs), but read the flag too: a truncated row must
        // never certify the absence of the exact path.
        if evidence.truncated {
            reasons.push(EngineReason::CallPathTruncated);
        }
        if let CallPathCoverage::Incomplete(gaps) = &evidence.coverage {
            reasons.extend(gaps.iter().map(|gap| EngineReason::CallPathGap {
                gap: format!("{gap:?}"),
            }));
        }
        let exact_path = evidence.paths.iter().find(|path| {
            path.edges.last().is_some_and(|edge| {
                edge.call_site.rel_path == to_site.rel_path
                    && edge.call_site.byte_span == to_site.byte_range
            })
        });
        if let Some(path) = exact_path {
            path_steps = Some(
                path.edges
                    .iter()
                    .map(|edge| {
                        let site = span_site(
                            workspace,
                            std::path::Path::new(&edge.call_site.rel_path),
                            edge.call_site.byte_span.clone(),
                            SiteRole::Call,
                        );
                        Ok(WitnessStep {
                            site: view(
                                &site,
                                &SiteAdmission::new(Some(workspace.retention_budget())),
                            )?,
                            step: "static_call",
                            proof: None,
                            summary: None,
                            edge_in: None,
                            static_call: Some(StaticCallStep {
                                caller: edge.caller.clone(),
                                static_target: edge.static_target.clone(),
                                proof: format!("{:?}", edge.proof),
                            }),
                        })
                    })
                    .collect::<Result<Vec<_>, SiteAdmissionRefusal>>()?,
            );
        }
    }

    // A root without a certified path produces no row, so the query's own
    // completion is what says whether the search was complete.
    let completion = detailed.result.completion();
    let label = |code: &crate::rql::CodeQueryDiagnosticCode| {
        serde_json::to_value(code)
            .expect("a diagnostic code serializes")
            .as_str()
            .expect("a diagnostic code is a string")
            .to_owned()
    };
    let (kind, codes) = match &completion {
        CodeQueryCompletion::Complete => (None, Vec::new()),
        CodeQueryCompletion::ProvenSubset { codes } => (Some("proven_subset"), codes.clone()),
        CodeQueryCompletion::Incomplete { codes } => (Some("incomplete"), codes.clone()),
        CodeQueryCompletion::Cancelled => (Some("cancelled"), Vec::new()),
        CodeQueryCompletion::Invalid { codes } => {
            panic!("the call-path plan is invalid: {codes:?}")
        }
    };
    if let Some(kind) = kind {
        // The completion itself is always a reason, even when every
        // diagnostic is advisory, so an incomplete query cannot read as
        // not_reached.
        reasons.push(EngineReason::CallReachabilityCompletion {
            completion: kind,
            codes: codes.iter().map(label).collect(),
        });
        reasons.extend(
            detailed
                .result
                .diagnostics
                .iter()
                .filter(|diagnostic| {
                    diagnostic.impact() != crate::rql::CodeQueryDiagnosticImpact::Advisory
                })
                .map(|diagnostic| EngineReason::CallReachabilityDiagnostic {
                    code: label(&diagnostic.code()),
                    incompleteness: serde_json::to_value(diagnostic.incompleteness())
                        .expect("an incompleteness serializes"),
                    message: diagnostic.message().to_owned(),
                }),
        );
    }
    let outcome = match path_steps {
        Some(steps) => PairOutcome {
            answer: Answer::Reached,
            witness: Some(Witness::Steps { steps }),
            reasons,
        },
        None if reasons.is_empty() => PairOutcome {
            answer: Answer::NotReached,
            witness: None,
            reasons,
        },
        None => PairOutcome {
            answer: Answer::Incomplete,
            witness: None,
            reasons,
        },
    };
    answered_all(
        &SiteAdmission::new(Some(workspace.retention_budget())),
        question,
        std::slice::from_ref(from),
        std::slice::from_ref(to),
        |_, _| PairOutcome {
            answer: outcome.answer,
            witness: outcome.witness.clone(),
            reasons: outcome.reasons.clone(),
        },
        FlowEngine::CallReachability,
        FlowGranularity::Callable,
    )
}
