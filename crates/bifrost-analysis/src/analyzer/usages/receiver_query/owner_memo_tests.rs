use super::*;
use crate::analyzer::usages::common::{QueryMemoOwner, assert_memo_owner_conformance_for_test};

pub fn concrete_receiver_memo_completion() {
    let source = "class Main { void run() { String value = new String(); value.length(); } }";
    let fixture = crate::test_support::AnalyzerFixture::new_for_language(
        Language::Java,
        &[("Main.java", source)],
    );
    let analyzer = fixture.analyzer.analyzer();
    let file = ProjectFile::new(fixture.project_root(), "Main.java");
    let start = source.rfind("value.length").unwrap();
    let range = Range {
        start_byte: start,
        end_byte: start + 5,
        start_line: 0,
        end_line: 0,
    };
    let run = |service: &ReceiverQueryService<'_>| {
        service
            .analyze(
                ReceiverQueryOperation::PointsTo,
                &file,
                range,
                ReceiverQueryInput::Expression,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("receiver answer")
    };
    assert_memo_owner_conformance_for_test(
        QueryMemoOwner::ReceiverQuery,
        analyzer,
        || ReceiverQueryService::from_workspace(&fixture.analyzer),
        |service| run(service).analysis,
        |service| {
            if service.reads.borrow().is_none() {
                assert!(service.prepared_files.borrow().is_empty());
                assert!(service.prepared_java_files.borrow().is_empty());
                assert!(service.prepared_structural_files.borrow().is_empty());
                assert!(service.receiver_request.borrow().is_none());
                false
            } else {
                assert!(!service.prepared_java_files.borrow().is_empty());
                true
            }
        },
    );
}
