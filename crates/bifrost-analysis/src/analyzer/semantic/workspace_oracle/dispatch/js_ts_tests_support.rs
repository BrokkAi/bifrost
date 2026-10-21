use super::*;
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::DispatchBoundary;

use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::SemanticArtifact;

use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;

use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::exact_call_range;

use crate::analyzer::semantic::SemanticBudget;

use crate::analyzer::Language;
use crate::analyzer::ProjectFile;
use crate::cancellation::CancellationToken;
use crate::test_support::AnalyzerFixture;
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

/// A minted identity as `(owner FQN, member, arity, has_receiver)`, or
/// `None` when the call reached an external boundary that names no
/// bindable identity.
type MintedIdentity = Option<(String, String, u32, bool)>;
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
pub(super) fn external_call_identities_in(
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
