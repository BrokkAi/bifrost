use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnitType, CppAnalyzer, IAnalyzer, Language};
use std::collections::BTreeSet;
use std::sync::Arc;

fn token_range(source: &str, line: &str, token: &str) -> (usize, usize) {
    let line_start = source.find(line).expect("fixture line");
    let token_start = line.find(token).expect("fixture token");
    let start = line_start + token_start;
    (start, start + token.len())
}

#[test]
fn authoritative_cpp_return_tag_does_not_shadow_body_type_reference() {
    let source = r#"struct Foo {};
extern "C" {
static struct Foo *use_global() {
    struct Foo *body_reference;
    return body_reference;
}

static struct Foo *use_local() {
    struct Foo;
    struct Foo *local_reference;
    return nullptr;
}
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("fixture.cc", source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let caller = project.file("fixture.cc");
    let target = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class && unit.fq_name() == "Foo" && !unit.is_synthetic()
        })
        .collect::<Vec<_>>();
    assert_eq!(target.len(), 1, "expected one file-scope Foo target");

    let provider = ExplicitCandidateProvider::new(Arc::new(std::iter::once(caller).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(&analyzer, &target, Some(&provider), 1, 1000);
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!("expected authoritative C++ success");
    };
    let ranges = hits_by_overload
        .values()
        .flatten()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    let body_reference = token_range(source, "struct Foo *body_reference;", "Foo");
    let local_reference = token_range(source, "struct Foo *local_reference;", "Foo");

    assert!(
        ranges.contains(&body_reference),
        "a function return tag must not shadow the global target in its body: {ranges:?}"
    );
    assert!(
        !ranges.contains(&local_reference),
        "a true block-scope tag declaration must shadow the global target: {ranges:?}"
    );
}
