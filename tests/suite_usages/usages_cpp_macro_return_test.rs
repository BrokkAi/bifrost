use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnitType, CppAnalyzer, IAnalyzer, Language};
use std::collections::BTreeSet;
use std::sync::Arc;

const FIXTURE: &str = include_str!("../fixtures/cpp_macro_sentinel_beta_return.h");

#[test]
fn macro_return_type_is_not_a_phantom_field() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("beta_return.h", FIXTURE)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("beta_return.h");
    let source = file.read_to_string().expect("beta return fixture source");
    let declarations = analyzer.get_all_declarations();

    assert!(
        !declarations.iter().any(|unit| {
            unit.kind() == CodeUnitType::Field
                && unit.fq_name() == "absl.beta_distribution$param_type.result_type"
        }),
        "macro return type must not be indexed as a param_type field: {declarations:#?}"
    );
    assert!(
        declarations.iter().any(|unit| {
            unit.kind() == CodeUnitType::Field
                && unit.fq_name() == "absl.beta_distribution$param_type.preserved_field"
        }),
        "an omitted-semicolon field before a normally typed function must remain indexed: {declarations:#?}"
    );
    for helper in ["ThresholdForSmallA", "ThresholdForLargeA"] {
        assert!(
            declarations.iter().any(|unit| {
                unit.kind() == CodeUnitType::Function
                    && unit
                        .short_name()
                        .ends_with(&format!("$param_type.{helper}"))
                    && unit.fq_name().starts_with("absl.")
            }),
            "helper {helper} should remain an indexed param_type method: {declarations:#?}"
        );
    }

    let result_type = declarations
        .iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "absl.beta_distribution$result_type"
        })
        .cloned()
        .expect("outer beta_distribution::result_type alias");
    let expected = token_ranges(
        &source,
        "    static ABSL_RANDOM_INTERNAL_LOG_EXP_CONSTEXPR result_type",
        "result_type",
    );
    assert_eq!(
        expected.len(),
        2,
        "both macro return declarations are present"
    );
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(file.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&result_type),
            Some(&provider),
            1,
            1000,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!("expected authoritative query for {}", result_type.fq_name());
    };
    let hits = hits_by_overload
        .values()
        .flatten()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect::<BTreeSet<_>>();
    assert!(
        expected.iter().all(|range| hits.contains(range)),
        "both macro return-type tokens must resolve to the outer alias: expected={expected:?} hits={hits:?}"
    );
}

fn token_ranges(source: &str, line: &str, token: &str) -> Vec<(usize, usize)> {
    source
        .match_indices(line)
        .map(|(line_start, _)| {
            let token_start = line
                .find(token)
                .unwrap_or_else(|| panic!("missing token {token:?} in fixture line {line:?}"));
            let start = line_start + token_start;
            (start, start + token.len())
        })
        .collect()
}
