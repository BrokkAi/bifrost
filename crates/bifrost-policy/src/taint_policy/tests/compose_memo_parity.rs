//! The composition memo's hit paths record the reads their fills recorded
//! (#7262). The engine and the criterion are in
//! `brokk_bifrost_analysis::test_support::hit_parity`.
//!
//! One policy run holds one `CompositionMemo`, and each of its composed
//! batches builds its own provider over it. The first batch fills the memo's
//! entries. A second batch over the same memo is the hit: it asks the same
//! questions and must record the same reads, because every entry is a
//! `ReplayingMemoEntry` that the hit replays into the active ledger. The six
//! maps are class R rows; each is a row when the fixture exercises it and a
//! comment row, with its reason, when it cannot.
//!
//! | map | class | fixture | hit counter |
//! | --- | --- | --- | --- |
//! | matches, dispatches | R | `COMPOSED_SOURCE`, a source and a sink across one call | `CompositionMemo::hit_counts_for_test` |
//! | execution | R | the sink inside a closure, so execution roots are discovered | same |
//! | widened | R | a source selected by `callers`, which no per-file slice answers | same |
//! | std_builtins | R | a second policy over the same memo: dispatch is per policy, the builtin classification is shared | same |
//! | matches, dispatches, filled with no capture | R | `COMPOSED_SOURCE`; a fill under a capture on a fresh memo is the reference (#10647) | same |
//! | evidence | R | not a row: needs a source judged with unknown points-to evidence, which no Rust fixture here reaches | |

use super::*;
use brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use std::sync::Arc;
type PolicyFlowSignature = Vec<(
    bool,
    brokk_bifrost_analysis::analyzer::semantic::partial_flow::ProcedurePartialFlows,
)>;
use crate::taint_compose_provider::CompositionMemo;
use brokk_bifrost_analysis::test_support::hit_parity::{Class, Evidence, Head, Rows};
use brokk_bifrost_test_macros::hardwon;

const CLOSURE_SINK_SOURCE: &str = r#"fn source() -> String {
    String::new()
}

fn sink(text: String) -> usize {
    text.len()
}

pub fn run() {
    let raw = source();
    let later = move || {
        sink(raw);
    };
    later();
}
"#;

const CALLERS_SOURCE: &str = r#"fn produce() -> String {
    String::new()
}

fn sink(text: String) -> usize {
    text.len()
}

pub fn run() {
    let raw = produce();
    sink(raw);
}
"#;

/// A source selected by its callers, which no per-file slice answers.
const CALLERS_POLICY: &str = r#"(policy
      :schema-version 1
      :id "test.composed-callers"
      :name "Composed callers"
      :message "tainted data reached sink"
      :severity warning
      :analysis (analysis
        :type taint
        :mode may
        :call-modeling (call-modeling :unmodeled optimistic)
        :sources (endpoint-set :entries [
          (source :id raw-input :display-name "raw input" :categories [input.user]
            :selector (rql :schema-version 1
              (language rust (callers (enclosing-decl (function :name "produce")))))
            :bind return-value :labels [attacker-controlled])])
        :sinks (endpoint-set :entries [
          (sink :id sink :display-name "sink" :categories [data.sensitive]
            :selector (rql :schema-version 1
              (language rust (call :callee (name "sink"))))
            :dangerous-operand (argument :index 0)
            :accepts [attacker-controlled])])))"#;

/// `COMPOSED_POLICY` under another id: the dispatch memo is keyed by policy,
/// the std builtin classification is not.
fn second_composed_policy() -> String {
    COMPOSED_POLICY.replace("test.composed", "test.composed-second")
}

/// Composes each of `policies` over `source` in turn, all over one memo, as the
/// batches of one policy run do. The first run of the row's operation composes
/// `policies[0]` and fills the memo; the second composes `policies[1]`, or
/// `policies[0]` again when there is one, and hits.
fn assert_memo_hits_replay_their_fills(source: &str, policies: &[&str], maps: &[&'static str]) {
    with_composed_batches(source, policies, |rows, batch, _analyzer| {
        let memo = CompositionMemo::default();
        let counters: Vec<_> = maps.iter().map(|name| hit_counter(&memo, name)).collect();
        let evidence: Vec<(&str, &dyn Fn() -> u64)> = maps
            .iter()
            .zip(&counters)
            .map(|(name, counter)| (*name, counter as &dyn Fn() -> u64))
            .collect();
        rows.row(
            &format!("composition memo: {maps:?}"),
            Class::Replay,
            Evidence::EachHits(&evidence),
            || batch(&memo),
        );
        eprintln!("hit counts: {:?}", memo.hit_counts_for_test());
    });
}

/// The named map's hit count in `memo`.
fn hit_counter<'m>(memo: &'m CompositionMemo, name: &'static str) -> impl Fn() -> u64 + 'm {
    move || {
        memo.hit_counts_for_test()
            .into_iter()
            .find(|(map, _)| *map == name)
            .map(|(_, hits)| hits)
            .expect("a named memo map")
    }
}

/// Builds the fixture and hands `rows_for` the hit-parity rows and one composed
/// batch over a given memo: a fresh discovery cache and provider over that
/// memo, as each batch of a policy run builds them.
fn with_composed_batches(
    source: &str,
    policies: &[&str],
    rows_for: impl FnOnce(
        &mut Rows<'_>,
        &dyn Fn(&CompositionMemo) -> PolicyFlowSignature,
        &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    ),
) {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", "[package]\nname=\"memo-fixture\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nlog=\"0.4\"\n")
        .file("src/lib.rs", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig {
        parallelism: Some(1),
        ..AnalyzerConfig::default()
    });
    with_composed_project(
        &project,
        &workspace,
        None,
        policies,
        rows_for,
        compose_fixture,
    );
}

fn with_composed_project(
    project: &BuiltInlineTestProject,
    workspace: &WorkspaceAnalyzer,
    active_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    policies: &[&str],
    rows_for: impl FnOnce(
        &mut Rows<'_>,
        &dyn Fn(&CompositionMemo) -> PolicyFlowSignature,
        &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    ),
    run: impl Fn(
        &crate::taint_compose_provider::PolicyCompositionProvider<'_>,
        &brokk_bifrost_flow::taint::TaintAnalysisPlan,
        &mut SemanticRequest<'_>,
    ) -> PolicyFlowSignature,
) {
    use crate::registry::test_registry_for_workspace;
    use crate::taint_compose_provider::PolicyCompositionProvider;
    use brokk_bifrost_analysis::analyzer::semantic::SemanticExecutionBudget;

    let _models = active_snapshot.as_ref().map(|snapshot| {
        brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(), Some(std::sync::Arc::clone(snapshot)),
        )
    });
    let cancellation = CancellationToken::default();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let mut registries: Vec<_> = policies
        .iter()
        .map(|_| test_registry_for_workspace(project.root()))
        .collect();
    let loaded: Vec<_> = registries
        .iter_mut()
        .zip(policies)
        .enumerate()
        .map(|(index, (registry, text))| {
            let policy = registry
                .register_policy_bytes(
                    PolicySourceIdentity::new(format!("test:composed-{index}.rqlp")),
                    text.as_bytes(),
                )
                .expect("the policy registers");
            let spec = policy
                .resolved_taint()
                .expect("the policy is a taint policy");
            let TaintPolicyCompilation::Plans { roots, .. } = TaintPolicyCompiler::new(
                workspace,
                &flow,
                active_snapshot
                    .as_ref()
                    .map(|snapshot| std::sync::Arc::clone(snapshot.active_models())),
                CodeQueryExecutionLimits::default(),
                64,
                &cancellation,
            )
            .with_active_semantic_model_snapshot(active_snapshot.clone())
            .compile(policy, spec, None)
            .unwrap_or_else(|failure| panic!("the policy compiles: {:?}", failure.error)) else {
                panic!("the policy compiles to analysis plans");
            };
            (policy, spec, roots)
        })
        .collect();
    let runs = std::cell::Cell::new(0_usize);
    let batch = |memo: &CompositionMemo| {
        let at = runs.get();
        runs.set(at + 1);
        let (policy, spec, roots) = &loaded[at % loaded.len()];
        let [root] = roots.as_slice() else {
            panic!("the policy has one root, found {}", roots.len());
        };
        let plan = root.plan.analysis();
        let cache = DiscoveryMaterializationCache::default();
        let provider = PolicyCompositionProvider::new(
            workspace,
            SemanticExecutionBudget::new(usize::MAX),
            &cache,
            plan,
            &root.external_models,
            64,
            super::super::FrontierEndpointBinder::new(
                TaintPolicyCompiler::new(
                    workspace,
                    &flow,
                    active_snapshot
                        .as_ref()
                        .map(|snapshot| std::sync::Arc::clone(snapshot.active_models())),
                    CodeQueryExecutionLimits::default(),
                    64,
                    &cancellation,
                )
                .with_active_semantic_model_snapshot(active_snapshot.clone()),
                policy,
                spec,
                plan.universe().clone(),
            ),
            memo,
        );
        let mut budget = SemanticBudget::default();
        run(
            &provider,
            plan,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
    };

    let head = Head::of(project.project_dyn(), workspace);
    let mut rows = Rows::new(workspace.analyzer(), &head);
    rows_for(&mut rows, &batch, workspace.analyzer());
    rows.finish();
}

fn compose_fixture(
    provider: &crate::taint_compose_provider::PolicyCompositionProvider<'_>,
    plan: &brokk_bifrost_flow::taint::TaintAnalysisPlan,
    request: &mut SemanticRequest<'_>,
) -> PolicyFlowSignature {
    use brokk_bifrost_flow::taint::compose::{CompositionBudget, compose_taint_batch};
    compose_taint_batch(
        plan,
        provider,
        CompositionBudget {
            max_procedures: 64,
            max_hops: 4096,
            max_callers_per_procedure: 64,
        },
        request,
    )
    .expect("the composition runs");
    let signature = provider.assert_partial_receipts_for_test(request);
    assert!(
        provider.failure().is_none(),
        "the provider failed: {:?}",
        provider.failure()
    );
    signature
}

fn read_fixture_partials(
    provider: &crate::taint_compose_provider::PolicyCompositionProvider<'_>,
    _plan: &brokk_bifrost_flow::taint::TaintAnalysisPlan,
    request: &mut SemanticRequest<'_>,
) -> PolicyFlowSignature {
    provider.seed_partial_receipts_for_test(request);
    provider.assert_partial_receipts_for_test(request)
}

#[test]
#[hardwon("#7262: a composition memo hit recorded fewer reads than the fill that built the entry")]
fn composition_matches_and_dispatches_hits_replay_their_fills() {
    assert_memo_hits_replay_their_fills(
        COMPOSED_SOURCE,
        &[COMPOSED_POLICY],
        &["matches", "dispatches"],
    );
}

#[test]
#[hardwon("#7262: a composition memo hit recorded fewer reads than the fill that built the entry")]
fn composition_execution_discovery_hit_replays_its_fill() {
    assert_memo_hits_replay_their_fills(CLOSURE_SINK_SOURCE, &[COMPOSED_POLICY], &["execution"]);
}

#[test]
#[hardwon("#7262: a composition memo hit recorded fewer reads than the fill that built the entry")]
fn composition_widened_rows_hit_replays_its_fill() {
    assert_memo_hits_replay_their_fills(CALLERS_SOURCE, &[CALLERS_POLICY], &["widened"]);
}

#[test]
#[hardwon("#7262: a composition memo hit recorded fewer reads than the fill that built the entry")]
fn composition_std_builtin_hit_replays_its_fill() {
    let second = second_composed_policy();
    assert_memo_hits_replay_their_fills(
        COMPOSED_SOURCE,
        &[COMPOSED_POLICY, &second],
        &["std_builtins"],
    );
}

#[test]
fn composition_hit_after_an_uncaptured_fill_replays_the_fill() {
    // The policy cold fallback composes with no Output capture (#10647). An
    // entry it fills must replay, inside a later unit's capture, the reads a
    // captured fill records.
    with_composed_batches(
        COMPOSED_SOURCE,
        &[COMPOSED_POLICY],
        |rows, batch, _analyzer| {
            let reference = CompositionMemo::default();
            let memo = CompositionMemo::default();
            let (matches, dispatches) = (
                hit_counter(&memo, "matches"),
                hit_counter(&memo, "dispatches"),
            );
            let evidence: [(&str, &dyn Fn() -> u64); 2] =
                [("matches", &matches), ("dispatches", &dispatches)];
            rows.row_after_uncaptured_fill(
                "composition memo filled with no capture: [matches, dispatches]",
                Evidence::EachHits(&evidence),
                || batch(&reference),
                || batch(&memo),
            );
        },
    );
}

#[test]
fn composition_partial_flow_hit_replays_admission_reads() {
    use brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads;
    let source =
        COMPOSED_SOURCE.replace("sink(moved);", "log::info!(\"{}\", &moved); sink(moved);");
    with_composed_batches(&source, &[COMPOSED_POLICY], |_rows, batch, analyzer| {
        let memo = CompositionMemo::default();
        let (_, reads) = capture_query_reads(analyzer, || batch(&memo));
        let (_, hit_reads) = capture_query_reads(analyzer, || batch(&memo));
        assert_eq!(
            reads.digest(),
            hit_reads.digest(),
            "policy cache consumers must retain admission reads"
        );
    });
}

#[test]
fn composition_partial_flow_manifest_edit_warm_equals_cold() {
    const ORIGINAL: &str = "[package]\nname=\"memo-fixture\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nlog=\"0.4\"\n";
    let source =
        COMPOSED_SOURCE.replace("sink(moved);", "log::info!(\"{}\", &moved); sink(moved);");
    let project = InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", ORIGINAL)
        .file("src/lib.rs", &source)
        .build();
    let cold_workspace = || {
        WorkspaceAnalyzer::build_ephemeral_footgun(
            std::sync::Arc::new(
                brokk_bifrost_analysis::FilesystemProject::new(project.root()).unwrap(),
            ),
            AnalyzerConfig::default(),
        )
        .unwrap()
    };
    let mut workspace = cold_workspace();
    let mut previous = None;
    for dependency in [
        "log=\"0.4\"",
        "log={package=\"not-log\",version=\"0.4\"}",
        "log=\"0.4\"",
    ] {
        let manifest = ORIGINAL.replace("log=\"0.4\"", dependency);
        std::fs::write(project.root().join("Cargo.toml"), &manifest).unwrap();
        workspace = workspace.update(&std::collections::BTreeSet::from([
            project.file("Cargo.toml")
        ]));
        let signature = |workspace: &WorkspaceAnalyzer| {
            let mut signature = None;
            with_composed_project(
                &project,
                workspace,
                None,
                &[COMPOSED_POLICY],
                |_rows, batch, _analyzer| {
                    signature = Some(batch(&CompositionMemo::default()));
                },
                read_fixture_partials,
            );
            signature.unwrap()
        };
        let warm = signature(&workspace);
        let cold = cold_workspace();
        assert_eq!(
            warm,
            signature(&cold),
            "manifest-only edit must give the same cached policy flows as cold acquisition"
        );
        assert_eq!(
            warm.iter().any(|(alternate, _)| *alternate),
            dependency == "log=\"0.4\""
        );
        if let Some(previous) = previous {
            assert_ne!(
                warm, previous,
                "admission-only edit must invalidate the selected policy flow interpretation"
            );
        }
        previous = Some(warm);
    }
}

#[test]
fn selectors_enumerate_selected_alternate_before_binding() {
    let source =
        COMPOSED_SOURCE.replace("sink(moved);", "log::info!(\"{}\", &moved); sink(moved);");
    let project = InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", "[package]\nname=\"locator-refusal\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nlog=\"0.4\"\n")
        .file("src/lib.rs", &source).build();
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
        std::sync::Arc::new(
            brokk_bifrost_analysis::FilesystemProject::new(project.root()).unwrap(),
        ),
        AnalyzerConfig::default(),
    )
    .unwrap();
    let outcome = super::super::with_icfg_taint_engine_for_test(|| {
        evaluate_policy_source(
            project.root(),
            PolicySourceIdentity::new("test:locator-refusal"),
            COMPOSED_POLICY,
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &PolicyEvaluationOptions::new(PolicyEvaluationDate::from_ymd(2026, 11, 9).unwrap()),
            None,
            &brokk_bifrost_analysis::retention_budget::RetentionBudget::for_tests(),
        )
    })
    .unwrap();
    let [run] = outcome.report().runs() else {
        panic!("one policy run");
    };
    assert!(!run.findings().is_empty(), "{run:#?}");
    assert!(
        !run.diagnostics().iter().any(|diagnostic| diagnostic
            .message()
            .contains("candidate_alternate_locator_untranslated")),
        "{run:#?}"
    );
}

#[test]
#[hardwon("#11842: policy sweep memo must retain each interpretation gap set in both fill orders")]
fn composition_openness_sweep_interpretations() {
    use brokk_bifrost_analysis::analyzer::semantic::SemanticExecutionBudget;
    use brokk_bifrost_flow::composition::{
        LocalOpennessClient, LocalTransferDiscovery, WorkspaceCompositionDiscovery,
    };
    use brokk_bifrost_flow::value_flow::{ValueFlowCache, WorkspaceValueFlowProvider};
    let source = format!(
        "{COMPOSED_SOURCE}\nfn emit(mut target:u32, value:u32) {{ log::info!(\"{{}}\", sink(log::debug!(\"{{}}\", {{target=value;value}}))); }}"
    );
    let project = InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", "[package]\nname=\"memo-fixture\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nlog=\"0.4\"\n")
        .file("src/lib.rs", &source).build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    with_composed_project(
        &project,
        &workspace,
        None,
        &[COMPOSED_POLICY],
        |_rows, batch, _| {
            batch(&CompositionMemo::default());
        },
        |provider, _, request| {
            let artifact = workspace
                .materialize_program_semantics(&project.file("src/lib.rs"), request)
                .unwrap()
                .available_value()
                .cloned()
                .unwrap();
            let discovery = WorkspaceCompositionDiscovery::new(
                &workspace,
                WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default()),
            );
            let base = artifact
                .procedures()
                .iter()
                .filter_map(|p| artifact.procedure_handle(p.id()))
                .find(|h| {
                    h.semantics()
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|s| s.name())
                        == Some("emit")
                })
                .unwrap();
            let selected = discovery
                .selected_procedure(&base.durable_key(), request)
                .unwrap();
            assert!(selected.is_candidate_alternate());
            assert_ne!(base.durable_key(), selected.durable_key());
            let execution = SemanticExecutionBudget::new(8);
            let expected = [&base, &selected].map(|h| {
                brokk_bifrost_flow::composition::openness_sweep(&discovery, h, &execution, request)
                    .unwrap()
            });
            assert_ne!(expected[0], expected[1]);
            for order in [[0, 1], [1, 0]] {
                provider.clear_sweeps_for_test();
                for index in order {
                    assert_eq!(
                        LocalOpennessClient::openness_sweep(
                            provider,
                            [&base, &selected][index],
                            request
                        )
                        .unwrap(),
                        expected[index]
                    );
                }
            }
            Vec::new()
        },
    );
}

#[test]
#[hardwon(
    "#12107: returned-member refusal certification lacked a model-set receipt on dispatch memo hits"
)]
fn model_content_certificate_records_hits_and_invalidates_after_pack_content_changes() {
    use brokk_bifrost_analysis::analyzer::read_ledger::ReadKey;
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CatalogCoordinate, CatalogPackSourceKind, SemanticModelActivationEvidence,
        test_snapshot_from_compiled_pack,
    };
    use brokk_bifrost_analysis::analyzer::{
        ChangedFacts, HeadInputs, LookupMemo, LookupReplayLimits, NoSummaryAnswers,
        capture_query_reads, verify_read_set,
    };
    use brokk_bifrost_flow::taint::compose::{CompositionProvider, IncompleteCause};
    let evidence = SemanticModelActivationEvidence {
        language: "rust".into(),
        ecosystem: "cargo".into(),
        package: Some(CatalogCoordinate {
            name: "other".into(),
            version: Some("0.4.24".parse().unwrap()),
        }),
        module: None,
        toolchain: None,
        target: Some("x86_64-unknown-linux-gnu".into()),
        configuration: None,
        artifact_sha256: None,
    };
    // Same pack identity, different callable parameter content.
    let before = test_snapshot_from_compiled_pack(
        crate::test_support::exact_other_callable_pack(),
        evidence.clone(),
        CatalogPackSourceKind::EphemeralWorkspace,
    );
    let after = test_snapshot_from_compiled_pack(
        crate::test_support::exact_other_unary_callable_pack(),
        evidence,
        CatalogPackSourceKind::EphemeralWorkspace,
    );
    let digest = |snapshot: &brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot| {
        brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(Some(snapshot.active_models().active_model_set_hash()))
    };
    let before_digest = digest(&before);
    let after_digest = digest(&after);
    assert_ne!(before_digest, after_digest);
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname=\"model-receipt\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        )
        .file("src/lib.rs", COMPOSED_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    with_composed_project(
        &project,
        &workspace,
        Some(Arc::clone(&before)),
        &[COMPOSED_POLICY],
        |_rows, batch, analyzer| {
            let memo = CompositionMemo::default();
            let (_, fill) = capture_query_reads(analyzer, || batch(&memo));
            let hits = hit_counter(&memo, "dispatches")();
            let (_, replay) = capture_query_reads(analyzer, || batch(&memo));
            assert!(
                hit_counter(&memo, "dispatches")() > hits,
                "exercise the dispatch memo hit"
            );
            let model_key = ReadKey::Models(before_digest);
            for receipt in [&fill, &replay] {
                assert!(
                    receipt.keys().contains(&model_key),
                    "certified consult must carry the actual model publication"
                );
                // Verify this consult's certificate independently of other
                // publication views recorded by the source-absent fixture.
                let model_reads = receipt
                    .keys()
                    .into_iter()
                    .filter(|key| key == &model_key)
                    .collect::<Vec<_>>();
                let verify = |models| {
                    verify_read_set(
                        &workspace,
                        &ChangedFacts::between(&workspace, &workspace),
                        &HeadInputs {
                            models,
                            policy_semantic_hash: before_digest,
                            policy_source: before_digest,
                            configuration: before_digest,
                            epoch: before_digest,
                        },
                        &model_reads,
                        LookupReplayLimits::default(),
                        &NoSummaryAnswers,
                        &mut LookupMemo::new(),
                    )
                };
                assert!(verify(before_digest).is_unchanged());
                assert!(
                    !verify(after_digest).is_unchanged(),
                    "a changed pack payload must invalidate the consulting unit, including after a memo hit"
                );
            }
        },
        |provider, plan, request| {
            // Consult after composition so the second invocation exercises a
            // dispatch memo hit. Isolate the certificate's own receipt: model
            // lookups made elsewhere cannot stand in for this consult's read.
            let signature = compose_fixture(provider, plan, request);
            let (cause, proof) = capture_query_reads(workspace.analyzer(), || {
                provider.certify_model_content_refusal(request)
            });
            assert_eq!(cause, IncompleteCause::Content);
            assert_eq!(proof.keys(), vec![ReadKey::Models(before_digest)]);
            signature
        },
    );
    // This snapshot deliberately has no overlay, so the actual projected
    // source consult must stay Provider. Its model-set read must nevertheless
    // reach each consumer when the frontier match is replayed from the memo.
    let projected = COMPOSED_POLICY
        .replace(
            ":schema-version 1\n      :id",
            ":schema-version 2\n      :id",
        )
        .replace(
            ":bind return-value",
            ":bind (return-value :path [(tuple :index 0)])",
        );
    with_composed_project(
        &project,
        &workspace,
        Some(before),
        &[&projected],
        |_rows, batch, analyzer| {
            let memo = CompositionMemo::default();
            let (_, fill) = capture_query_reads(analyzer, || batch(&memo));
            let hits = hit_counter(&memo, "matches")();
            let (_, replay) = capture_query_reads(analyzer, || batch(&memo));
            assert!(
                hit_counter(&memo, "matches")() > hits,
                "exercise the actual projected-source frontier memo hit"
            );
            for receipt in [&fill, &replay] {
                assert!(
                    receipt.keys().contains(&ReadKey::Models(before_digest)),
                    "the projection's creation read must reach the consuming unit on fill and replay: {:?}",
                    receipt.keys()
                );
            }
        },
        |provider, plan, request| {
            let signature = compose_fixture(provider, plan, request);
            assert!(
                provider
                    .consulted_refusal_messages()
                    .iter()
                    .any(|notice| matches!(
                        &notice.record,
                        Some(crate::taint_policy::output_diagnostic::OutputDiagnosticRecord::ProviderRefusal {
                            reason: crate::taint_policy::RefusalReason::ReturnProjection { .. },
                            cause: IncompleteCause::Operational(
                                brokk_bifrost_flow::taint::compose::OperationalCause::Provider
                            ),
                            ..
                        })
                    )),
                "missing overlay must refuse the actual projected source as Provider"
            );
            signature
        },
    );
}

#[test]
#[hardwon(
    "#12986: first initialization of an uninitialized place counted as a droppable replacement"
)]
fn first_initialization_keeps_policy_execution_inventory_complete() {
    use brokk_bifrost_flow::taint::compose::CompositionProvider;
    let source = format!("{COMPOSED_SOURCE}\nfn first() {{ let x; x = 10; }}");
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname=\"first-init\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        )
        .file("src/lib.rs", &source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    with_composed_project(
        &project,
        &workspace,
        None,
        &[COMPOSED_POLICY],
        |_rows, batch, _| {
            batch(&CompositionMemo::default());
        },
        |provider, _, request| {
            let artifact = workspace
                .materialize_program_semantics(&project.file("src/lib.rs"), request)
                .unwrap()
                .available_value()
                .cloned()
                .unwrap();
            let first = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure.locator().declaration().last_segment_name() == Some("first")
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .unwrap();
            let inventory = provider.invocations(&first.durable_key(), request).unwrap();
            assert!(
                matches!(
                    inventory.coverage,
                    brokk_bifrost_flow::taint::compose::Completeness::Complete
                ),
                "{inventory:?}"
            );
            assert!(inventory.sites.is_empty());
            Vec::new()
        },
    );
}
