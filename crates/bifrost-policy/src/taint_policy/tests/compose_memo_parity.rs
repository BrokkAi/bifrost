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
    with_composed_batches(source, policies, |rows, batch| {
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
    rows_for: impl FnOnce(&mut Rows<'_>, &dyn Fn(&CompositionMemo)),
) {
    use crate::registry::test_registry_for_workspace;
    use crate::taint_compose_provider::PolicyCompositionProvider;
    use brokk_bifrost_analysis::analyzer::semantic::SemanticExecutionBudget;
    use brokk_bifrost_flow::taint::compose::{CompositionBudget, compose_taint_batch};

    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig {
        parallelism: Some(1),
        ..AnalyzerConfig::default()
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
                &workspace,
                &flow,
                None,
                CodeQueryExecutionLimits::default(),
                64,
                &cancellation,
            )
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
            &workspace,
            SemanticExecutionBudget::new(usize::MAX),
            &cache,
            plan,
            &root.external_models,
            64,
            super::super::FrontierEndpointBinder::new(
                TaintPolicyCompiler::new(
                    &workspace,
                    &flow,
                    None,
                    CodeQueryExecutionLimits::default(),
                    64,
                    &cancellation,
                ),
                policy,
                spec,
                plan.universe().clone(),
            ),
            memo,
        );
        let mut budget = SemanticBudget::default();
        compose_taint_batch(
            plan,
            &provider,
            CompositionBudget {
                max_procedures: 64,
                max_hops: 4096,
                max_callers_per_procedure: 64,
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("the composition runs");
        assert!(
            provider.failure().is_none(),
            "the provider failed: {:?}",
            provider.failure()
        );
    };

    let head = Head::of(project.project_dyn(), &workspace);
    let mut rows = Rows::new(workspace.analyzer(), &head);
    rows_for(&mut rows, &batch);
    rows.finish();
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
    with_composed_batches(COMPOSED_SOURCE, &[COMPOSED_POLICY], |rows, batch| {
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
    });
}
