use super::*;
use crate::analyzer::usages::common::{QueryMemoOwner, assert_memo_owner_conformance_for_test};

pub fn concrete_scalar_definition_memo_completion() {
    let source: Arc<str> = Arc::from(
        "package main
func target() {}
func run() { target() }",
    );
    let fixture = crate::test_support::AnalyzerFixture::new_for_language(
        Language::Go,
        &[("main.go", &source)],
    );
    let analyzer = fixture.analyzer.analyzer();
    let file = ProjectFile::new(fixture.project_root(), "main.go");
    let tree = parse_tree_for_language(&file, Language::Go, &source).expect("tree");
    let start = source.rfind("target()").unwrap();
    let request = DefinitionLookupRequest {
        file: file.clone(),
        line: Some(1),
        column: Some(start),
        start_byte: Some(start),
        end_byte: Some(start + 6),
    };
    let run = |session: &mut ScalarCallTargetSession<'_>| {
        let scope = AnalyzerQueryScope::new(analyzer);
        session.resolve(
            scope.token(),
            vec![request.clone()],
            file.clone(),
            source.clone(),
            &tree,
            None,
        )
    };
    assert_memo_owner_conformance_for_test(
        QueryMemoOwner::ScalarDefinition,
        analyzer,
        || ScalarCallTargetSession::new(analyzer),
        |session| {
            let answers = run(session);
            assert_eq!(answers.len(), 1);
            let answer = &answers[0].outcome;
            assert!(!answer.definitions.is_empty(), "{answer:?}");
            answer.definitions.clone()
        },
        |session| {
            if let Some(memo) = &session.memo {
                assert!(memo.reads.is_some());
                true
            } else {
                assert!(session.resolver.is_none());
                assert!(!session.initialized);
                assert!(!session.disabled);
                false
            }
        },
    );
}
