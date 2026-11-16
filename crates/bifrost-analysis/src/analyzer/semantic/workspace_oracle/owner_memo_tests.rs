use super::*;
use crate::analyzer::usages::common::{QueryMemoOwner, assert_memo_owner_conformance_for_test};

pub fn concrete_dispatch_memo_completion() {
    let fixture = crate::test_support::AnalyzerFixture::new_for_language(
        Language::Java,
        &[
            (
                "Main.java",
                "class Main { static void target() {} static void run() { target(); } }",
            ),
            (
                "Other.java",
                "class Other { static void target() {} static void run() { target(); } }",
            ),
        ],
    );
    let [call, independent_call] = ["Main.java", "Other.java"].map(|name| {
        let file = ProjectFile::new(fixture.project_root(), name);
        let cancellation = crate::cancellation::CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("semantic materialization")
            .available_value()
            .cloned()
            .expect("semantic artifact");
        test_support::first_call_in_artifact(&artifact)
    });
    let analyzer = fixture.analyzer.analyzer();
    let oracle = WorkspaceSemanticOracle::new(&fixture.analyzer);
    let cancellation = crate::cancellation::CancellationToken::default();
    let key = call.procedure().artifact().key().fingerprint();
    let resolve = |pool: &PreparedWorkspaceDispatchPool<'_>, call: &CallSiteHandle| {
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let outcome = pool
            .resolve_call(call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("dispatch answer");
        let result = outcome.available_value().expect("available dispatch");
        assert_eq!(result.candidates().len(), 1);
        result
            .candidates()
            .iter()
            .map(|candidate| candidate.target().id())
            .collect::<Vec<_>>()
    };
    assert_memo_owner_conformance_for_test(
        QueryMemoOwner::DispatchSession,
        analyzer,
        || oracle.prepare_workspace_dispatch_pool(),
        |pool| resolve(pool, &call),
        |pool| {
            let Some((_, entry)) = pool.sessions.get(&key) else {
                return false;
            };
            assert!(entry.source.lock().unwrap().is_some());
            assert!(entry.reads.lock().unwrap().is_some());
            true
        },
    );

    // Pool entries own aggregate state for one artifact. An unrelated artifact
    // must not replay that entry's receipt even while the first entry is live.
    use crate::analyzer::usages::common::with_memo_fill_reason_for_test;
    use crate::analyzer::{AnalyzerQueryScope, QueryReadIncomplete};
    let pool = oracle.prepare_workspace_dispatch_pool();
    let gap = QueryReadIncomplete::SemanticEvidenceGap("first artifact retained gap".into());
    {
        let _attempt = AnalyzerQueryScope::for_advisory_read(analyzer);
        let completion = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
        with_memo_fill_reason_for_test(QueryMemoOwner::DispatchSession, gap.clone(), || {
            resolve(&pool, &call)
        });
        assert!(completion.captured_read_incompleteness().contains(&gap));
    }
    let (_, first_entry) = pool.sessions.get(&key).expect("first artifact retained");
    let first_reads = first_entry
        .reads
        .lock()
        .unwrap()
        .as_ref()
        .cloned()
        .expect("first receipt");
    let independent_key = independent_call.procedure().artifact().key().fingerprint();
    assert_ne!(key, independent_key);
    for _ in 0..2 {
        let _attempt = AnalyzerQueryScope::for_advisory_read(analyzer);
        let completion = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
        resolve(&pool, &independent_call);
        assert!(completion.captured_read_incompleteness().is_empty());
        let (_, independent_entry) = pool
            .sessions
            .get(&independent_key)
            .expect("independent artifact retained");
        assert!(!Arc::ptr_eq(&first_entry, &independent_entry));
        let independent_reads = independent_entry
            .reads
            .lock()
            .unwrap()
            .as_ref()
            .cloned()
            .expect("independent receipt");
        assert!(!Arc::ptr_eq(&first_reads, &independent_reads));
    }
    let _attempt = AnalyzerQueryScope::for_advisory_read(analyzer);
    let completion = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
    resolve(&pool, &call);
    assert!(completion.captured_read_incompleteness().contains(&gap));
}
