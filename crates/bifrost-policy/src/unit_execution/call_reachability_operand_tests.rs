//! Retained final certificates, not merely operand-cache hits, survive edits.
use super::*;
use crate::inline_project::InlineTestProject;
use crate::units::{
    IncrementalBaseState, PersistedPolicyUnitStore, PolicyUnitStore, PolicyUnitStoreError,
    UnitSnapshots, WorkspaceUnitInputs, workspace_snapshot,
};
use brokk_bifrost_analysis::analyzer::ChangedFacts;
use brokk_bifrost_analysis::{AnalyzerConfig, FilesystemProject};
use brokk_bifrost_test_macros::hardwon;
use std::sync::{Arc, Mutex};

#[derive(Default, Debug)]
struct Events {
    continuation_reads: Vec<String>,
    continuation_writes: Vec<String>,
    certificates: Vec<PolicyUnitKey>,
    operand_writes: usize,
    scanned_files: u64,
    operand_questions: Vec<StableDigest>,
    source_questions: Vec<StableDigest>,
}

struct RecordedStore {
    inner: PersistedPolicyUnitStore,
    events: Arc<Mutex<Events>>,
}

fn certificate_seed(unit: &PolicyUnit) -> Option<String> {
    let PolicyUnitProduct::Rows(rows) = unit.product() else {
        return None;
    };
    if !rows
        .rows
        .iter()
        .any(|row| row.evidence.call_path_evidence.is_some())
    {
        return None;
    }
    match &unit.key().partition {
        UnitPartition::Seed { rel_path, .. } | UnitPartition::Prefix { rel_path, .. } => {
            Some(rel_path.to_string())
        }
        _ => None,
    }
}

impl PolicyUnitStore for RecordedStore {
    fn prefetch(
        &mut self,
        keys: &[PolicyUnitKey],
        budget: &PolicyBudget,
        nodes: Option<usize>,
    ) -> Result<(), PolicyUnitStoreError> {
        self.inner.prefetch(keys, budget, nodes)
    }
    fn lookup(&self, key: &PolicyUnitKey) -> Option<&PolicyUnit> {
        let unit = self.inner.lookup(key)?;
        if let UnitPartition::Operand { question } = key.partition {
            self.events.lock().unwrap().operand_questions.push(question);
        }
        if let UnitPartition::Prefix { cut, input, .. } = key.partition
            && cut == StableDigest::sha256("bifrost.rql.call_reachability.source.v2")
        {
            self.events.lock().unwrap().source_questions.push(input);
        }
        if let Some(seed) = certificate_seed(unit) {
            self.events.lock().unwrap().continuation_reads.push(seed);
        }
        Some(unit)
    }
    fn publish(&mut self, unit: PolicyUnit) {
        let mut events = self.events.lock().unwrap();
        if let Some(seed) = certificate_seed(&unit) {
            events.continuation_writes.push(seed);
            events.certificates.push(unit.key().clone());
        }
        if let UnitPartition::Prefix { cut, input, .. } = unit.key().partition
            && cut == StableDigest::sha256("bifrost.rql.call_reachability.source.v2")
        {
            events.source_questions.push(input);
        }
        if matches!(unit.key().partition, UnitPartition::Operand { .. }) {
            events.operand_writes += 1;
            if let UnitPartition::Operand { question } = unit.key().partition {
                events.operand_questions.push(question);
            }
        }
        drop(events);
        self.inner.publish(unit);
    }
    fn attest(
        &mut self,
        key: &PolicyUnitKey,
        verified_on: StableDigest,
        snapshots: &[StableDigest],
    ) {
        self.inner.attest(key, verified_on, snapshots);
    }
}

const QUERY: &str = r#"(call-reachability
    :sources (language rust (function :name/regex "^entry_[0-9]+$"))
    :sinks (language rust (call :callee (name/regex "^selected_sink_[0-9]+$"))))"#;

fn indexed(root: &std::path::Path) -> WorkspaceAnalyzer {
    WorkspaceAnalyzer::build_persisted(
        Arc::new(FilesystemProject::new(root).unwrap()),
        AnalyzerConfig::default(),
    )
    .unwrap()
}

fn evaluate(
    base: &WorkspaceAnalyzer,
    head: &WorkspaceAnalyzer,
    store: &Mutex<RecordedStore>,
    policy: &LoadedPolicy,
) -> serde_json::Value {
    evaluate_with(
        base,
        head,
        store,
        policy,
        QUERY,
        PolicyBudget::default(),
        true,
    )
}

fn evaluate_with(
    base: &WorkspaceAnalyzer,
    head: &WorkspaceAnalyzer,
    store: &Mutex<RecordedStore>,
    policy: &LoadedPolicy,
    query_text: &str,
    budget: PolicyBudget,
    complete: bool,
) -> serde_json::Value {
    try_evaluate_with(base, head, store, policy, query_text, budget, complete)
        .expect("the operand prefix must not widen")
}

fn try_evaluate_with(
    base: &WorkspaceAnalyzer,
    head: &WorkspaceAnalyzer,
    store: &Mutex<RecordedStore>,
    policy: &LoadedPolicy,
    query_text: &str,
    budget: PolicyBudget,
    complete: bool,
) -> Result<serde_json::Value, WidenReason> {
    let changed = ChangedFacts::between(base, head);
    assert!(changed.is_complete());
    let context = PolicyIncrementalContext::new(
        store,
        head,
        &changed,
        WorkspaceUnitInputs::of(head, None, None),
        IncrementalBaseState::Evaluated,
        UnitSnapshots {
            base: workspace_snapshot(base).unwrap(),
            head: workspace_snapshot(head).unwrap(),
        },
    );
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let query = CodeQuery::from_source(query_text).unwrap();
    let files = head.analyzer().analyzed_files();
    let limits = budget.query_limits();
    let execution = UnitQueryExecution {
        analyzer: head.analyzer(),
        flow_state: (&flow).into(),
        workspace: Some(head),
        cancellation: None,
        limits,
        depth_opt_in: false,
        workspace_files: &files,
        subject_batch: None,
        guard_identity: None,
    };
    let mut reuse = UnitReuse::new(policy, &context, &budget, &flow);
    let mut attempt = UnitAttempt::default();
    let sliced = sliced_query_units(
        policy,
        &query,
        &mut reuse,
        &execution,
        SeedPartition::seed,
        &mut attempt,
    )?;
    if complete {
        assert!(attempt.all_recomputed_published(), "{attempt:#?}");
    }
    context.commit_units(
        policy.definition().metadata.id.clone(),
        reuse.take_staged(),
        sliced.keys,
    );
    // Match the batch writer: every test publication must survive SQLite's
    // constraints and encode successfully, rather than only enter the front cache.
    store.lock().unwrap().inner.flush().unwrap();
    assert_eq!(
        sliced.merged.completion() == brokk_bifrost_rql::CodeQueryCompletion::Complete,
        complete
    );
    store.lock().unwrap().events.lock().unwrap().scanned_files = sliced.merged.work.scanned_files;
    let result =
        serde_json::json!({"items": sliced.merged.items, "evidence": sliced.merged.evidence});
    if !complete {
        return Ok(result);
    }
    let cold = execute_code_query_unit(
        head.analyzer(),
        &flow,
        Some(head),
        &query,
        limits,
        None,
        CodeQueryExecutionScope::whole_workspace(),
    );
    assert_eq!(
        cold.completion,
        brokk_bifrost_rql::CodeQueryCompletion::Complete
    );
    let items: Vec<_> = cold.rows.iter().map(|row| &row.item).collect();
    let evidence: Vec<_> = cold.rows.iter().map(|row| &row.evidence).collect();
    assert_eq!(
        result,
        serde_json::json!({"items": items, "evidence": evidence}),
        "warm versus cold certificates"
    );
    Ok(result)
}

fn sink_rows(workspace: &WorkspaceAnalyzer) -> serde_json::Value {
    let query = CodeQuery::from_source(
        r#"(language rust (call :callee (name/regex "^selected_sink_[0-9]+$")))"#,
    )
    .unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let result = execute_code_query_unit(
        workspace.analyzer(),
        &flow,
        Some(workspace),
        &query,
        Default::default(),
        None,
        CodeQueryExecutionScope::whole_workspace(),
    );
    assert_eq!(
        result.completion,
        brokk_bifrost_rql::CodeQueryCompletion::Complete
    );
    serde_json::to_value(result.rows).unwrap()
}

#[test]
#[hardwon("#11552: sink reads in each source unit defeated continuation early cutoff")]
fn call_reachability_continuations_ignore_unreached_sink_changes() {
    let mut fixture = InlineTestProject::with_language(Language::Rust)
        .with_git()
        .file(
            "app.rs",
            "mod root_0;\nmod root_1;\nmod root_2;\nmod noise;\n",
        )
        .file("noise.rs", "pub fn unrelated() { let value = 0; }\n");
    for index in 0..3 {
        fixture = fixture.file(format!("root_{index}.rs"), format!(
            "pub fn entry_{index}() {{\n let value = 0;\n selected_sink_{index}();\n}}\nfn selected_sink_{index}() {{}}\n"
        ));
    }
    let fixture = fixture.build();
    let registry = crate::test_support::registry_with_policy(
        "test:operand-paths",
        &format!(
            r#"(policy :id "test.operand-paths" :name "Paths"
        :message "Selected path" :severity warning :analysis (analysis :type match :selector (rql {QUERY})))"#
        ),
        "policy",
    );
    let policy = registry.policies().next().unwrap();
    let base = indexed(fixture.root());
    let events = Arc::new(Mutex::new(Events::default()));
    let store = Mutex::new(RecordedStore {
        inner: PersistedPolicyUnitStore::new(Arc::clone(base.store().unwrap())),
        events: Arc::clone(&events),
    });
    let original = evaluate(&base, &base, &store, policy);
    let initial_certificates = events.lock().unwrap().certificates.clone();
    assert_eq!(original["items"].as_array().unwrap().len(), 3);
    *events.lock().unwrap() = Events::default();
    // Reopen the flushed unit store so replay must load SQLite products
    // instead of succeeding only through the publisher's front cache.
    store.lock().unwrap().inner = PersistedPolicyUnitStore::new(Arc::clone(base.store().unwrap()));
    assert_eq!(evaluate(&base, &base, &store, policy), original);
    {
        let events = events.lock().unwrap();
        assert!(
            events.continuation_reads.len() >= 3,
            "replay must read retained final certificate rows"
        );
        assert!(
            events.continuation_writes.is_empty(),
            "replay must not recompute continuations"
        );
    }
    let original_sinks = sink_rows(&base);
    std::fs::write(
        fixture.root().join("root_0.rs"),
        "pub fn entry_0() {\n let value = 1;\n selected_sink_0();\n}\nfn selected_sink_0() {}\n",
    )
    .unwrap();
    let source_edit = indexed(fixture.root());
    assert_eq!(
        sink_rows(&source_edit),
        original_sinks,
        "the source-only edit must preserve the sink output"
    );
    *events.lock().unwrap() = Events::default();
    evaluate(&base, &source_edit, &store, policy);
    {
        let recorded = events.lock().unwrap();
        assert_eq!(
            recorded.continuation_writes,
            ["root_0.rs"],
            "only the changed source continuation reruns; initial={initial_certificates:#?}; now={recorded:#?}"
        );
    }

    std::fs::write(
        fixture.root().join("noise.rs"),
        "pub fn unrelated() { let value = 1; }\n",
    )
    .unwrap();
    let sink_noop = indexed(fixture.root());
    assert_eq!(
        sink_rows(&sink_noop),
        original_sinks,
        "the sink input edit changes reads, not selected output"
    );
    *events.lock().unwrap() = Events::default();
    evaluate(&source_edit, &sink_noop, &store, policy);
    {
        let events = events.lock().unwrap();
        assert_eq!(
            events.operand_writes, 0,
            "there is no global sink operand to recompute"
        );
        assert!(
            events.continuation_writes.is_empty(),
            "equal sink output must cut off invalidation"
        );
        assert!(
            events.continuation_reads.len() >= 3,
            "retained certificates, not just operands, replay"
        );
    }
    std::fs::write(
        fixture.root().join("noise.rs"),
        "pub fn unrelated() { selected_sink_99(); }\nfn selected_sink_99() {}\n",
    )
    .unwrap();
    let sink_change = indexed(fixture.root());
    assert_ne!(
        sink_rows(&sink_change),
        original_sinks,
        "exercise an actual changed sink set"
    );
    *events.lock().unwrap() = Events::default();
    evaluate(&sink_noop, &sink_change, &store, policy);
    let mut changed = events.lock().unwrap().continuation_writes.clone();
    changed.sort();
    assert_eq!(
        changed,
        Vec::<String>::new(),
        "unreached sink changes cannot invalidate reached-site membership"
    );
}

#[test]
#[hardwon("#11552: shared sink units must distinguish ordinary questions and binding budgets")]
fn call_reachability_source_units_bind_questions_and_budgets_without_global_sinks() {
    let fixture = InlineTestProject::with_language(Language::Rust)
        .with_git()
        .file(
            "app.rs",
            "fn entry_0() { selected_sink_0(); } fn selected_sink_0() {}\n",
        )
        .build();
    let registry_for = |query: &str| {
        crate::test_support::registry_with_policy(
            "test:questions",
            &format!(
                r#"(policy :id "test.questions" :name "Questions"
        :message "Selected path" :severity warning :analysis (analysis :type match :selector (rql {query})))"#
            ),
            "policy",
        )
    };
    let base = indexed(fixture.root());
    let events = Arc::new(Mutex::new(Events::default()));
    let store = Mutex::new(RecordedStore {
        inner: PersistedPolicyUnitStore::new(Arc::clone(base.store().unwrap())),
        events: Arc::clone(&events),
    });
    let source = r#"(union (language rust (function :name "entry_0")) (language rust (function :name "absent")))"#;
    let first = r#"(language rust (call :callee (name "selected_sink_0")))"#;
    let second = r#"(language rust (call :callee (name/regex "^selected_sink_")))"#;
    for sink in [first, second] {
        *events.lock().unwrap() = Events::default();
        let query = format!(
            "(union (call-reachability :sources {source} :sinks {first}) (call-reachability :sources {source} :sinks {sink}))"
        );
        let registry = registry_for(&query);
        let policy = registry.policies().next().unwrap();
        evaluate_with(
            &base,
            &base,
            &store,
            policy,
            &query,
            PolicyBudget::default(),
            true,
        );
        let mut questions = events.lock().unwrap().source_questions.clone();
        questions.sort();
        questions.dedup();
        assert_eq!(
            questions.len(),
            1,
            "equal source questions share selection independently of sink plans"
        );
    }
    let query = format!("(call-reachability :sources {source} :sinks {first})");
    let registry = registry_for(&query);
    let policy = registry.policies().next().unwrap();
    let mut questions = Vec::new();
    for files in [100, 101] {
        let budget = PolicyBudget::builder()
            .with_query_limits(CodeQueryExecutionLimits {
                max_scanned_files: files,
                ..PolicyBudget::default().query_limits()
            })
            .unwrap()
            .build()
            .unwrap();
        *events.lock().unwrap() = Events::default();
        evaluate_with(&base, &base, &store, policy, &query, budget, true);
        questions.extend(events.lock().unwrap().source_questions.clone());
    }
    questions.sort();
    questions.dedup();
    assert_eq!(
        questions.len(),
        2,
        "the source question under different binding grants has two units"
    );
}

#[test]
#[hardwon("#11552: an incomplete sink operand must not publish any certified continuation")]
fn call_reachability_budget_stopped_sink_never_caches_continuations() {
    let mut fixture = InlineTestProject::with_language(Language::Rust).with_git();
    for index in 0..4 {
        fixture = fixture.file(format!("root_{index}.rs"), format!(
            "fn entry_{index}() {{ selected_sink_{index}(); }} fn selected_sink_{index}() {{}}\n"));
    }
    let fixture = fixture.build();
    let registry = crate::test_support::registry_with_policy(
        "test:incomplete-operands",
        &format!(
            r#"(policy :id "test.incomplete-operands" :name "Incomplete operands" :message "Selected path"
        :severity warning :analysis (analysis :type match :selector (rql {QUERY})))"#
        ),
        "policy",
    );
    let policy = registry.policies().next().unwrap();
    let base = indexed(fixture.root());
    let events = Arc::new(Mutex::new(Events::default()));
    let store = Mutex::new(RecordedStore {
        inner: PersistedPolicyUnitStore::new(Arc::clone(base.store().unwrap())),
        events: Arc::clone(&events),
    });
    let budget = PolicyBudget::builder()
        .with_query_limits(CodeQueryExecutionLimits {
            max_scanned_files: 2,
            ..PolicyBudget::default().query_limits()
        })
        .unwrap()
        .build()
        .unwrap();
    for _ in 0..2 {
        *events.lock().unwrap() = Events::default();
        evaluate_with(&base, &base, &store, policy, QUERY, budget, false);
        let events = events.lock().unwrap();
        assert!(
            events.continuation_writes.is_empty(),
            "partial sink output cannot cache a continuation"
        );
        assert!(
            events.continuation_reads.is_empty(),
            "a repeat must recompute after a sink budget stop"
        );
        assert_eq!(
            events.operand_writes, 0,
            "a stopped sink operand itself is not retained"
        );
    }
}

#[test]
#[hardwon("#11552: output-bound continuations must still validate their own traversal reads")]
fn call_reachability_continuations_validate_graph_reads_with_unchanged_operands() {
    const BEFORE: &str = "pub fn hop() { mid_a(); }\nfn mid_a() { selected_sink_90(); }\nfn mid_b() { selected_sink_91(); }\nfn selected_sink_90() {}\nfn selected_sink_91() {}\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .with_git()
        .file(
            "Cargo.toml",
            "[package]\nname = \"graph-receipts\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("src/lib.rs", "mod root_0; mod root_1; mod routing;\n")
        .file(
            "src/root_0.rs",
            "use crate::routing::hop;
pub fn entry_0() { hop(); }\n",
        )
        .file(
            "src/root_1.rs",
            "pub fn entry_1() { selected_sink_1(); } fn selected_sink_1() {}\n",
        )
        .file("src/routing.rs", BEFORE)
        .build();
    let registry = crate::test_support::registry_with_policy(
        "test:graph-receipts",
        &format!(
            r#"(policy :id "test.graph-receipts" :name "Graph receipts" :message "Selected path"
        :severity warning :analysis (analysis :type match :selector (rql {QUERY})))"#
        ),
        "policy",
    );
    let policy = registry.policies().next().unwrap();
    let base = indexed(fixture.root());
    let events = Arc::new(Mutex::new(Events::default()));
    let store = Mutex::new(RecordedStore {
        inner: PersistedPolicyUnitStore::new(Arc::clone(base.store().unwrap())),
        events: Arc::clone(&events),
    });
    let original = evaluate(&base, &base, &store, policy);
    assert_eq!(original["items"].as_array().unwrap().len(), 2);
    let original_key = events.lock().unwrap().certificates.iter().find(|key| {
        matches!(&key.partition, UnitPartition::Prefix { rel_path, .. } if rel_path.as_ref() == "src/root_0.rs")
    }).unwrap().clone();
    let sinks = sink_rows(&base);
    std::fs::write(
        fixture.root().join("src/routing.rs"),
        BEFORE.replacen("hop() { mid_a();", "hop() { mid_b();", 1),
    )
    .unwrap();
    let head = indexed(fixture.root());
    assert_eq!(
        sink_rows(&head),
        sinks,
        "the graph edit preserves selected sink rows"
    );
    *events.lock().unwrap() = Events::default();
    let changed = evaluate(&base, &head, &store, policy);
    assert_ne!(
        changed, original,
        "the certified path changes through the helper"
    );
    assert_eq!(
        events.lock().unwrap().continuation_writes,
        ["src/root_0.rs"],
        "only the continuation reading the edited helper reruns"
    );
    assert_eq!(
        events.lock().unwrap().certificates,
        [original_key],
        "unchanged operands keep the key; its own traversal receipt forces recomputation"
    );
    std::fs::write(fixture.root().join("src/routing.rs"), BEFORE).unwrap();
    let restored = indexed(fixture.root());
    *events.lock().unwrap() = Events::default();
    assert_eq!(
        evaluate(&head, &restored, &store, policy),
        original,
        "restoration recovers the same stable certificate identities"
    );
    assert_eq!(
        events.lock().unwrap().continuation_writes,
        ["src/root_0.rs"]
    );
}

#[test]
#[hardwon("#11552: nested source operators must share sink operands across seed files")]
fn call_reachability_nested_source_uses_shared_sink_operands() {
    const ROOTS: usize = 8;
    let mut fixture = InlineTestProject::with_language(Language::Rust)
        .with_git()
        .file("noise.rs", "fn unrelated() {}\n");
    for index in 0..ROOTS {
        fixture = fixture.file(format!("root_{index}.rs"), format!(
            "fn entry_{index}() {{ selected_sink_{index}(); }} fn selected_sink_{index}() {{}}\n"));
    }
    let fixture = fixture.build();
    let query = format!(
        "(call-reachability :sources {QUERY} :sinks (language rust (call :callee (name/regex \"^selected_sink_[0-9]+$\"))))"
    );
    let registry = crate::test_support::registry_with_policy(
        "test:nested-operands",
        &format!(
            r#"(policy :id "test.nested-operands" :name "Nested operands" :message "Selected path"
        :severity warning :analysis (analysis :type match :selector (rql {query})))"#
        ),
        "policy",
    );
    let policy = registry.policies().next().unwrap();
    let base = indexed(fixture.root());
    let events = Arc::new(Mutex::new(Events::default()));
    let store = Mutex::new(RecordedStore {
        inner: PersistedPolicyUnitStore::new(Arc::clone(base.store().unwrap())),
        events: Arc::clone(&events),
    });
    let original = evaluate_with(
        &base,
        &base,
        &store,
        policy,
        &query,
        PolicyBudget::default(),
        true,
    );
    assert_eq!(original["items"].as_array().unwrap().len(), ROOTS);
    // F=9 and R=8: repeated workspace sinks cost at least R*F+F+2R=97.
    // Both nested operators now inventory then replay cached traversal for
    // certificates; 2F+8R+2=84 still separates their linear reached-site work.
    let bound = 2 * (ROOTS + 1) + 8 * ROOTS + 2;
    let scans = events.lock().unwrap().scanned_files;
    eprintln!("nested reached-site scans={scans}; linear bound={bound}");
    assert!(scans <= bound as u64, "{scans} > {bound}");
    *events.lock().unwrap() = Events::default();
    store.lock().unwrap().inner = PersistedPolicyUnitStore::new(Arc::clone(base.store().unwrap()));
    assert_eq!(
        evaluate_with(
            &base,
            &base,
            &store,
            policy,
            &query,
            PolicyBudget::default(),
            true
        ),
        original
    );
    let events = events.lock().unwrap();
    assert!(events.continuation_writes.is_empty());
    assert!(events.continuation_reads.len() >= ROOTS);
}

#[test]
#[hardwon("#11552: a content-incomplete sink selector is not an execution-budget cut")]
fn call_reachability_content_incomplete_sink_keeps_its_typed_cause() {
    let fixture = InlineTestProject::with_language(Language::Rust).with_git()
        .file("app.rs", "fn entry_0() { selected_sink_0(); }\nfn unrelated() { selected_sink_0(); unknown_external(); }\nfn selected_sink_0() {}\n").build();
    let query = r#"(call-reachability :sources (language rust (function :name "entry_0"))
        :sinks (call-sites-to (callees (call-reachability
            :sources (language rust (function :name "unrelated"))
            :sinks (language rust (call))))))"#;
    let registry = crate::test_support::registry_with_policy(
        "test:content-sink",
        &format!(
            r#"(policy :id "test.content-sink" :name "Content sink" :message "Selected path"
        :severity warning :analysis (analysis :type match :selector (rql {query})))"#
        ),
        "policy",
    );
    let policy = registry.policies().next().unwrap();
    let base = indexed(fixture.root());
    let events = Arc::new(Mutex::new(Events::default()));
    let store = Mutex::new(RecordedStore {
        inner: PersistedPolicyUnitStore::new(Arc::clone(base.store().unwrap())),
        events: Arc::clone(&events),
    });
    assert!(
        matches!(
            try_evaluate_with(
                &base,
                &base,
                &store,
                policy,
                query,
                PolicyBudget::default(),
                false
            ),
            Err(WidenReason::WorkspacePreparationRequired)
        ),
        "nonlocal dependencies use the whole-policy funnel"
    );
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let query = CodeQuery::from_source(query).unwrap();
    let result = execute_code_query_unit(
        base.analyzer(),
        &flow,
        Some(&base),
        &query,
        Default::default(),
        None,
        CodeQueryExecutionScope::whole_workspace(),
    );
    assert_eq!(
        result.rows.len(),
        1,
        "known positive evidence remains additive"
    );
    assert!(
        !result.rows[0]
            .evidence
            .call_path_evidence
            .as_ref()
            .unwrap()
            .truncated,
        "a content gap must not become a budget truncation"
    );
    // Preserve the producer's actual typed causes. SemanticResultsOmitted
    // currently has an inherent operational classification, even when its
    // underlying traversal gap is content-dependent; demand must not rewrite it.
    use brokk_bifrost_rql::query::CodeQueryPlanSource;
    use brokk_bifrost_rql::structural::search::{
        CallReachabilityOperands, execute_call_reachability_sink,
    };
    let CodeQueryPlanSource::CallReachability(operator) = &query.plan.source else {
        unreachable!()
    };
    let mut sink_query = query.clone();
    sink_query.plan = operator.sinks.clone();
    let product = execute_call_reachability_sink(
        base.analyzer(),
        &flow,
        Some(&base),
        &sink_query,
        Default::default(),
        None,
        CodeQueryExecutionScope::whole_workspace(),
    );
    let mut operands = CallReachabilityOperands::default();
    operands.insert_sink(&operator.sinks, Arc::new(product));
    let global = execute_code_query_unit(
        base.analyzer(),
        &flow,
        Some(&base),
        &query,
        Default::default(),
        None,
        CodeQueryExecutionScope::whole_workspace()
            .with_call_reachability_operands(Arc::new(operands)),
    );
    assert_eq!(result.completion, global.completion);
    assert_eq!(global.rows.len(), 1);
    assert_eq!(
        result.rows[0].evidence.call_path_evidence, global.rows[0].evidence.call_path_evidence,
        "known positive paths survive incomplete nonlocal dependency evaluation"
    );
    assert!(!global.diagnostics.is_empty());
    assert_eq!(result.diagnostics, global.diagnostics);
    assert_eq!(
        result
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.incompleteness)
            .collect::<Vec<_>>(),
        global
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.incompleteness)
            .collect::<Vec<_>>(),
        "encountered nonlocal dependency causes retain their producer-owned types"
    );
    assert!(events.lock().unwrap().continuation_writes.is_empty());
}

fn check_empty_sources_preserve_independent_set_branch(operator: &str) {
    let fixture = InlineTestProject::with_language(Language::Rust)
        .with_git()
        .file("app.rs", "fn keep() { marker(); } fn marker() {}\n")
        .build();
    let workspace = indexed(fixture.root());
    let reachable = r#"(call-reachability :sources (language rust (function :name "absent"))
        :sinks (language rust (call :callee (name "marker"))))"#;
    let query = match operator {
        // Union requires the same non-structural comparator family. Occurrence
        // targets are ordinary Declaration rows; no reachability source exists.
        "union" => format!(
            r#"(union {reachable}
            (occurrence-target (language rust (occurrences :class reference))))"#
        ),
        "except" => format!(
            r#"(except
            (enclosing-decl (language rust (function :name "keep"))) {reachable})"#
        ),
        _ => unreachable!(),
    };
    let registry = crate::test_support::registry_with_policy(
        "test:independent-set-branches",
        &format!(
            r#"(policy :id "test.independent-{operator}" :name "Independent branch"
            :message "Selected declaration" :severity warning
            :analysis (analysis :type match :selector (rql {query})))"#
        ),
        "policy",
    );
    let policy = registry.policies().next().unwrap();
    let events = Arc::new(Mutex::new(Events::default()));
    let store = Mutex::new(RecordedStore {
        inner: PersistedPolicyUnitStore::new(Arc::clone(workspace.store().unwrap())),
        events,
    });
    if operator == "union" {
        assert_eq!(
            try_evaluate_with(
                &workspace,
                &workspace,
                &store,
                policy,
                &query,
                PolicyBudget::default(),
                true
            ),
            Err(WidenReason::PlanCrossesSeeds),
            "an unrepresentable branch order must use exact full execution"
        );
        let events = store.lock().unwrap().events.lock().unwrap().operand_writes;
        assert_eq!(
            events, 0,
            "the refused attempt must discard its staged units"
        );
    } else {
        let result = evaluate_with(
            &workspace,
            &workspace,
            &store,
            policy,
            &query,
            PolicyBudget::default(),
            true,
        );
        assert_eq!(result["items"].as_array().unwrap().len(), 1, "{operator}");
    }
}

#[test]
#[hardwon("#11552: empty reachability sources cannot erase an independent union branch")]
fn call_reachability_empty_sources_preserve_union_branch() {
    check_empty_sources_preserve_independent_set_branch("union");
}

#[test]
#[hardwon("#11552: empty reachability sources cannot erase an independent except minuend")]
fn call_reachability_empty_sources_preserve_except_minuend() {
    check_empty_sources_preserve_independent_set_branch("except");
}

#[test]
#[hardwon(
    "#11552: new reachability inventory work must not change existing call-sites-from charges"
)]
fn legacy_call_sites_from_retained_work_matches_master_08e4() {
    let fixture = InlineTestProject::with_language(Language::Rust)
        .with_git()
        .file("app.rs", "fn entry_0() { helper(); fn nested() { helper(); } }\nfn entry_1() { helper(); helper(); }\nfn helper() {}\n")
        .build();
    let workspace = indexed(fixture.root());
    let query = CodeQuery::from_source(
        r#"(language rust (call-sites-from :proof proven (enclosing-decl (function :name/regex "^entry_[0-9]+$"))))"#,
    ).unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let result = execute_code_query_unit(
        workspace.analyzer(),
        &flow,
        Some(&workspace),
        &query,
        PolicyBudget::default().query_limits(),
        None,
        CodeQueryExecutionScope::whole_workspace(),
    );
    assert_eq!(
        result.completion,
        brokk_bifrost_rql::CodeQueryCompletion::Complete
    );
    // Captured independently from the retained seed product written by08e4dc8aa9,
    // shared measure binary SHA25692caafa43f7507df3e42477423e5ed4f26f0eb707433fb954441e80016206fed.
    let mut master_work: serde_json::Value = serde_json::from_str(
        r#"{
  "scanned_files": 1,
  "scanned_source_bytes": 105,
  "fact_nodes": 24,
  "pipeline_rows": 7,
  "examined_references": 0,
  "semantic": {
    "materialization_attempts": 1,
    "unique_materialized_files": 1,
    "request_cache_hits": 4,
    "source_bytes": 525,
    "procedures": 7,
    "blocks": 23,
    "program_points": 41,
    "values": 20,
    "allocations": 0,
    "call_sites": 12,
    "memory_locations": 0,
    "captures": 0,
    "source_mappings": 58,
    "evidence": 53,
    "gaps": 8,
    "events": 44,
    "control_edges": 37,
    "nested_entries": 392,
    "retained_bytes": 108407,
    "cumulative": {
      "source_bytes": 525,
      "procedures": 7,
      "blocks": 23,
      "program_points": 41,
      "values": 20,
      "allocations": 0,
      "call_sites": 12,
      "memory_locations": 0,
      "captures": 0,
      "source_mappings": 58,
      "evidence": 53,
      "gaps": 8,
      "events": 44,
      "control_edges": 37,
      "nested_entries": 392,
      "owned_text_bytes": 1741
    },
    "resident_peaks": {
      "source_bytes": 105,
      "procedures": 4,
      "blocks": 23,
      "program_points": 41,
      "values": 20,
      "allocations": 0,
      "call_sites": 4,
      "memory_locations": 0,
      "captures": 0,
      "source_mappings": 53,
      "evidence": 53,
      "gaps": 8,
      "events": 44,
      "control_edges": 37,
      "nested_entries": 386,
      "owned_text_bytes": 1741
    },
    "root_work_peaks": {
      "source_bytes": 315,
      "procedures": 3,
      "blocks": 0,
      "program_points": 0,
      "values": 0,
      "allocations": 0,
      "call_sites": 8,
      "memory_locations": 0,
      "captures": 0,
      "source_mappings": 5,
      "evidence": 0,
      "gaps": 0,
      "events": 0,
      "control_edges": 0,
      "nested_entries": 6,
      "owned_text_bytes": 0
    },
    "resident_nested_entries_peak": 386,
    "resident_retained_bytes_peak": 108407,
    "traversal_steps": 8,
    "budget_exhausted": false
  }
}"#,
    )
    .unwrap();
    let mut actual = serde_json::to_value(result.work).unwrap();
    // These two byte totals include owned absolute workspace paths. The CLI
    // master-warm/head-cold control compares the entire work object at the SAME
    // root; this portable golden pins every other retained work dimension.
    for key in ["retained_bytes", "resident_retained_bytes_peak"] {
        master_work["semantic"].as_object_mut().unwrap().remove(key);
        actual["semantic"].as_object_mut().unwrap().remove(key);
    }
    assert_eq!(actual, master_work);
}

#[test]
#[hardwon("#11552: callable ownership indexing must not change legacy initializer call rows")]
fn legacy_call_sites_from_keeps_non_callable_initializer_calls() {
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "app.rs",
            "static INIT: i32 = helper();\nfn helper() -> i32 { 1 }\n",
        )
        .build();
    let workspace = indexed(fixture.root());
    let query = CodeQuery::from_source(
        r#"(language rust (call-sites-from (enclosing-decl (identifier :name "INIT"))))"#,
    )
    .unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let result = execute_code_query_unit(
        workspace.analyzer(),
        &flow,
        Some(&workspace),
        &query,
        PolicyBudget::default().query_limits(),
        None,
        CodeQueryExecutionScope::whole_workspace(),
    );
    // Master08e4 emits the physical call with typed semantic incompleteness.
    // The callable-only map incorrectly returned a complete empty result.
    assert_eq!(result.rows.len(), 1);
    assert!(!result.truncated);
}

#[test]
#[hardwon("#11552: the missing-provenance refusal must retain per-seed reuse for certified unions")]
fn call_reachability_certifiable_union_replays_per_seed() {
    let fixture = InlineTestProject::with_language(Language::Rust)
        .with_git()
        .file("app.rs", "mod root_0; mod root_1; mod noise;\n")
        .file(
            "root_0.rs",
            "pub fn entry_0() { selected_sink_0(); } fn selected_sink_0() {}\n",
        )
        .file(
            "root_1.rs",
            "pub fn entry_1() { selected_sink_1(); } fn selected_sink_1() {}\n",
        )
        .file("noise.rs", "pub fn unrelated() { let value = 0; }\n")
        .build();
    let query = format!("(union {QUERY} {QUERY})");
    let registry = crate::test_support::registry_with_policy(
        "test:certifiable-union",
        &format!(
            r#"(policy :id "test.certifiable-union" :name "Certified union"
            :message "Certified path" :severity warning
            :analysis (analysis :type match :selector (rql {query})))"#
        ),
        "policy",
    );
    let policy = registry.policies().next().unwrap();
    let base = indexed(fixture.root());
    let events = Arc::new(Mutex::new(Events::default()));
    let store = Mutex::new(RecordedStore {
        inner: PersistedPolicyUnitStore::new(Arc::clone(base.store().unwrap())),
        events: Arc::clone(&events),
    });
    let original = evaluate_with(
        &base,
        &base,
        &store,
        policy,
        &query,
        PolicyBudget::default(),
        true,
    );
    assert_eq!(original["items"].as_array().unwrap().len(), 2);
    store.lock().unwrap().inner = PersistedPolicyUnitStore::new(Arc::clone(base.store().unwrap()));
    std::fs::write(
        fixture.root().join("noise.rs"),
        "pub fn unrelated() { let value = 1; }\n",
    )
    .unwrap();
    let changed = indexed(fixture.root());
    *events.lock().unwrap() = Events::default();
    assert_eq!(
        evaluate_with(
            &base,
            &changed,
            &store,
            policy,
            &query,
            PolicyBudget::default(),
            true
        ),
        original
    );
    let events = events.lock().unwrap();
    assert!(
        events.continuation_writes.is_empty(),
        "unchanged certified roots must not rerun"
    );
    assert!(
        events.continuation_reads.len() >= 2,
        "both retained seed continuations must replay"
    );
}
