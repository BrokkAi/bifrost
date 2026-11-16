use super::*;
use crate::analyzer::usages::common::{QueryMemoOwner, assert_memo_owner_conformance_for_test};

pub fn concrete_call_binding_memo_completion() {
    let fixture = crate::test_support::AnalyzerFixture::new_for_language(
        Language::Java,
        &[(
            "Main.java",
            "class Main { static void target(int value) {} }",
        )],
    );
    let analyzer = fixture.analyzer.analyzer();
    let unit = analyzer
        .search_definitions("target", false)
        .into_iter()
        .next()
        .expect("target declaration");
    assert_memo_owner_conformance_for_test(
        QueryMemoOwner::CallBinding,
        analyzer,
        CallBindingCache::default,
        |cache| {
            let answer = cache
                .formal_layout(analyzer, &unit, 1)
                .expect("formal layout");
            assert_eq!(answer.slots.len(), 1);
            answer
        },
        |cache| {
            if cache.reads.is_none() {
                assert!(cache.formals.is_empty());
                assert!(cache.source_layouts.is_empty());
                assert!(cache.source_trees.is_empty());
                assert!(cache.python_receiver_is_class.is_empty());
                assert!(cache.call_targets.is_empty());
                assert!(cache.call_dispatch_sessions.is_empty());
                assert!(cache.call_dispatches.is_empty());
                false
            } else {
                assert_eq!(cache.formals.len(), 1);
                true
            }
        },
    );
}
