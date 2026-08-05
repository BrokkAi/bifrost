use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, Language};
use std::collections::BTreeSet;
use std::sync::Arc;

const DISTRIBUTION_FIXTURE: &str =
    include_str!("../fixtures/cpp_macro_sentinel_distribution_aliases.h");

#[test]
fn authoritative_cpp_random_aliases_survive_sentinel_and_out_of_line_templates() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("distribution_aliases.h", DISTRIBUTION_FIXTURE)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let file = project.file("distribution_aliases.h");
    let source = file.read_to_string().expect("distribution fixture source");

    let beta_result = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class && unit.fq_name() == "absl.beta_distribution$result_type"
    });
    let uniform_unsigned = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl.uniform_int_distribution$unsigned_type"
    });
    let discrete_result = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl.discrete_distribution$result_type"
    });
    let discrete_param = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl.discrete_distribution$param_type"
    });
    let log_uniform_unsigned = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl.log_uniform_int_distribution$unsigned_type"
    });

    let beta_positive = token_range(
        &source,
        "      result_type(1.3862943611198906);  // positive-beta-result-type",
        "result_type",
    );
    let uniform_positive = token_range(
        &source,
        "      random_internal::wide_multiply<unsigned_type>;  // positive-uniform-unsigned-type",
        "unsigned_type",
    );
    let discrete_positive = token_range(
        &source,
        "      uniform_int_distribution<result_type>(0, 0);  // positive-discrete-result-type",
        "result_type",
    );
    let discrete_param_positive = token_range(
        &source,
        "      typename discrete_distribution<IntType>::param_type;  // positive-discrete-param-type",
        "param_type",
    );
    let discrete_inline_param_positive = token_range(
        &source,
        "  void param(const param_type& p) { (void)p; }  // positive-discrete-inline-param-type",
        "param_type",
    );
    let log_uniform_positive = token_range(
        &source,
        "  return static_cast<unsigned_type>(1);  // positive-log-uniform-unsigned-type",
        "unsigned_type",
    );

    let discrete_param_hits = authoritative_exact_ranges(&analyzer, &discrete_param, &file);
    assert!(
        discrete_param_hits.contains(&discrete_param_positive),
        "the dependent nested type must emit its terminal token exactly: hits={discrete_param_hits:#?}"
    );
    assert!(
        discrete_param_hits.contains(&discrete_inline_param_positive),
        "the inline owner-local nested type must resolve to its enclosing distribution: hits={discrete_param_hits:#?}"
    );
    assert!(
        discrete_param_hits.iter().all(|hit| {
            *hit == discrete_param_positive
                || !(hit.0 <= discrete_param_positive.0 && discrete_param_positive.1 <= hit.1)
        }),
        "the exact nested-type hit must not be duplicated by a wider qualified range: hits={discrete_param_hits:#?}"
    );

    let beta_sibling = token_range(
        &source,
        "  typename other::beta_distribution<T>::result_type beta = {};",
        "result_type",
    );
    let uniform_sibling = token_range(
        &source,
        "  typename other::uniform_int_distribution<T>::unsigned_type uniform = {};",
        "unsigned_type",
    );
    let discrete_sibling = token_range(
        &source,
        "  typename other::discrete_distribution<T>::result_type discrete = {};",
        "result_type",
    );

    let cases = [
        (
            "beta out-of-line body result_type",
            beta_result,
            beta_positive,
            Some(beta_sibling),
        ),
        (
            "uniform out-of-line template argument",
            uniform_unsigned,
            uniform_positive,
            Some(uniform_sibling),
        ),
        (
            "discrete out-of-line template argument",
            discrete_result,
            discrete_positive,
            Some(discrete_sibling),
        ),
        (
            "discrete dependent param_type",
            discrete_param,
            discrete_param_positive,
            None,
        ),
        (
            "log-uniform out-of-line body unsigned_type",
            log_uniform_unsigned,
            log_uniform_positive,
            Some(uniform_sibling),
        ),
    ];

    let mut failures = Vec::new();
    for (label, target, positive, sibling) in cases {
        let hits = authoritative_exact_ranges(&analyzer, &target, &file);
        if !hits
            .iter()
            .any(|hit| hit.0 <= positive.0 && positive.1 <= hit.1)
        {
            failures.push(format!(
                "{label} missing authoritative hit {positive:?}; hits={hits:#?}"
            ));
        }
        if sibling.is_some_and(|sibling| {
            hits.iter()
                .any(|hit| hit.0 <= sibling.0 && sibling.1 <= hit.1)
        }) {
            failures.push(format!(
                "{label} included same-spelled sibling {sibling:?}; hits={hits:#?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn definition_by<F>(analyzer: &CppAnalyzer, mut predicate: F) -> CodeUnit
where
    F: FnMut(&CodeUnit) -> bool,
{
    let declarations = analyzer.get_all_declarations();
    declarations
        .iter()
        .find(|unit| predicate(unit))
        .cloned()
        .unwrap_or_else(|| panic!("missing matching C++ declaration in {declarations:#?}"))
}

fn authoritative_exact_ranges(
    analyzer: &CppAnalyzer,
    target: &CodeUnit,
    candidate: &brokk_bifrost::ProjectFile,
) -> BTreeSet<(usize, usize)> {
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(candidate.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            1,
            1000,
        );
    assert_eq!(
        query.candidate_files,
        std::iter::once(candidate.clone()).collect(),
        "authoritative query must stay on the random-alias fixture"
    );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = query.result
    else {
        panic!(
            "expected authoritative C++ success for {}",
            target.fq_name()
        );
    };
    hits_by_overload
        .values()
        .flatten()
        .map(|hit| {
            assert_eq!(&hit.file, candidate);
            (hit.start_offset, hit.end_offset)
        })
        .collect()
}

fn token_range(source: &str, line: &str, token: &str) -> (usize, usize) {
    let line_start = source
        .find(line)
        .unwrap_or_else(|| panic!("missing fixture line {line:?}"));
    let token_start = line
        .find(token)
        .unwrap_or_else(|| panic!("missing token {token:?} in fixture line {line:?}"));
    let start = line_start + token_start;
    (start, start + token.len())
}
