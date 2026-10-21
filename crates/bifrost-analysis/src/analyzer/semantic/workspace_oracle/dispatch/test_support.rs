use super::*;
use crate::analyzer::semantic::SemanticBudget;
use crate::cancellation::CancellationToken;
use crate::test_support::AnalyzerFixture;
use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::SemanticArtifact;
use brokk_bifrost_analysis::analyzer::semantic::ir::model::EvidenceCompleteness;
use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProofStatus;
use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::DispatchResult;
use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::CandidateCoverage;
use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
use std::sync::Arc;

#[doc(hidden)]
pub fn semantic_call_fixture_for_language(
    language: Language,
    name: &str,
    source: &str,
) -> (AnalyzerFixture, crate::analyzer::semantic::CallSiteHandle) {
    let fixture = AnalyzerFixture::new_for_language(language, &[(name, source)]);
    let file = ProjectFile::new(fixture.project_root(), name);
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = fixture
        .analyzer
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("semantic materialization")
        .available_value()
        .cloned()
        .expect("semantic artifact");
    let call = first_call_in_artifact(&artifact);
    (fixture, call)
}

#[doc(hidden)]
pub fn first_call_in_artifact(
    artifact: &Arc<SemanticArtifact>,
) -> crate::analyzer::semantic::CallSiteHandle {
    let procedure = artifact
        .procedures()
        .iter()
        .find(|procedure| !procedure.call_sites().is_empty())
        .expect("caller procedure");
    artifact
        .procedure_handle(procedure.id())
        .and_then(|procedure| procedure.call_site_handle(procedure.semantics().call_sites()[0].id))
        .expect("scoped call handle")
}

#[doc(hidden)]
pub fn assert_proven_local_dispatch(
    result: &DispatchResult,
    declared_target: crate::analyzer::semantic::ProcedureId,
) {
    assert_eq!(result.coverage(), CandidateCoverage::Exhaustive);
    assert_eq!(result.candidates().len(), 1);
    assert_eq!(result.candidates()[0].target().id(), declared_target);
    assert_eq!(result.candidates()[0].proof(), &ProofStatus::Proven);
    assert_eq!(
        result.candidates()[0].completeness(),
        &EvidenceCompleteness::Complete
    );
}

/// A minted identity as `(owner FQN, member, arity, has_receiver)`, or
/// `None` when the call reached an external boundary that names no
/// bindable identity.
#[doc(hidden)]
pub type MintedIdentity = Option<(String, String, u32, bool)>;

#[doc(hidden)]
pub fn calls_in_source_order(
    artifact: &Arc<SemanticArtifact>,
) -> Vec<crate::analyzer::semantic::CallSiteHandle> {
    let mut calls = artifact
        .procedures()
        .iter()
        .flat_map(|procedure| {
            let handle = artifact
                .procedure_handle(procedure.id())
                .expect("artifact procedure has a scoped handle");
            procedure.call_sites().iter().map(move |call| {
                let handle = handle
                    .call_site_handle(call.id)
                    .expect("semantic call has a scoped handle");
                let range = exact_call_range(&handle).expect("semantic call has a source mapping");
                ((range.start_byte, range.end_byte), handle)
            })
        })
        .collect::<Vec<_>>();
    calls.sort_by_key(|(span, _)| *span);
    calls.into_iter().map(|(_, call)| call).collect()
}

/// The canonical external identity every call in `source` publishes, keyed
/// by the exact source text of the call.
#[doc(hidden)]
pub fn external_call_identities(
    language: Language,
    rel_path: &str,
    source: &str,
) -> Vec<(String, MintedIdentity)> {
    let fixture = AnalyzerFixture::new_for_language(language, &[(rel_path, source)]);
    external_call_identities_in(&fixture, rel_path, source)
}

/// The same identities, read through an already prepared fixture so a test
/// can activate the declaration model the resolver's identity proof needs
/// before asking.
#[doc(hidden)]
pub fn external_call_identities_in(
    fixture: &AnalyzerFixture,
    rel_path: &str,
    source: &str,
) -> Vec<(String, MintedIdentity)> {
    let file = ProjectFile::new(fixture.project_root(), rel_path);
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = fixture
        .analyzer
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("semantic materialization")
        .available_value()
        .cloned()
        .expect("semantic artifact");
    let oracle = fixture.analyzer.semantic_oracle_provider();
    let mut identities = Vec::new();
    for procedure in artifact.procedures() {
        for call in procedure.call_sites() {
            let handle = artifact
                .procedure_handle(procedure.id())
                .and_then(|procedure| procedure.call_site_handle(call.id))
                .expect("scoped call handle");
            let span = procedure
                .source_mapping(call.source)
                .expect("call source mapping")
                .locator
                .anchor()
                .span();
            let text = source[span.start_byte() as usize..span.end_byte() as usize].to_owned();
            let mut budget = SemanticBudget::default();
            let outcome = oracle
                .resolve_call(
                    &handle,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("external dispatch runs");
            let result = outcome
                .available_value()
                .expect("external dispatch retains a result");
            let target = result
                .boundaries()
                .iter()
                .find_map(DispatchBoundary::unmaterialized_external_target)
                .map(|target| {
                    (
                        target.owner_fqn().to_owned(),
                        target.member().to_owned(),
                        target.arity(),
                        target.has_receiver(),
                    )
                });
            identities.push((text, target));
        }
    }
    identities.sort();
    identities
}

#[doc(hidden)]
pub fn dispatch_target_shape(outcome: &SemanticOutcome<DispatchResult>) -> Vec<String> {
    outcome
        .available_value()
        .expect("dispatch retains an answer")
        .candidates()
        .iter()
        .map(|candidate| format!("{:?}", candidate.target().semantics().locator()))
        .collect()
}

#[doc(hidden)]
pub fn assert_declared_binding_shortcut_is_skipped(language: Language, name: &str, source: &str) {
    let (fixture, call) = semantic_call_fixture_for_language(language, name, source);
    assert!(matches!(
        call.procedure()
            .semantics()
            .call_site(call.id())
            .expect("call belongs to its procedure")
            .declared_targets,
        CallableTargetResolution::Proven(CallableTarget::Local(_))
    ));
    let artifact = Arc::clone(call.procedure().artifact());
    let mut session = fixture
        .analyzer
        .semantic_oracle_provider()
        .prepare_call_dispatch_session(artifact);
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let outcome = session
        .resolve_declared_indirect_local_call(
            &call,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("declared binding shortcut eligibility check");

    assert!(outcome.is_none());
    assert_eq!(budget.used(), SemanticWork::default());
    assert_eq!(session.retained_bytes(), 0);
}
