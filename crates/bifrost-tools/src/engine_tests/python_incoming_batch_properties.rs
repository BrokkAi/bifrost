#[cfg(test)]
mod incoming_batch_properties {
    use brokk_bifrost_analysis::analyzer::usages::{CallRelationLimits, CallRelationService};

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_python_analysis::analyzer::PythonAnalyzer;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::query_token::QueryScope;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4))]
        #[test]
        fn incoming_batch_matches_independent_singletons(
            calls in prop::collection::vec((0usize..4, 0u8..7), 1..12),
            selection in prop::collection::vec(0usize..10, 0..7),
            limit in 1usize..4,
        ) {
            let mut definitions = [String::new(), String::new()];
            let mut imports = String::new();
            let mut body = String::from("def caller(receiver, hint: \"models.First\" = None) -> \"more.Second\":\n");
            for index in 0..4 {
                let class = if index < 2 { "First" } else { "Second" };
                definitions[index / 2].push_str(&format!("def f{index}(value: \"{class}\" = None) -> \"{class}\":\n    note = \"{class}\"\n    return value\n"));
                imports.push_str(&format!("from exports import alias{index} as local{index}\n"));
            }
            definitions[0].push_str("class First:\n    def __init__(self):\n        pass\n    def send(self):\n        pass\n");
            definitions[1].push_str("class Second:\n    def __init__(self):\n        pass\n    def send(self):\n        pass\n");
            for (target, shape) in calls {
                body.push_str(&match shape {
                    0 => format!("    local{target}()\n"),
                    1 => format!("    {}.f{target}()\n", if target < 2 { "models" } else { "more" }),
                    2 => "    receiver.send()\n".to_owned(),
                    3 => "    models.First().send()\n".to_owned(),
                    4 => format!("    exports.alias{target}()\n"),
                    5 => format!("    pkg.exports.alias{target}()\n"),
                    _ => "    Constructed().send()\n".to_owned(),
                });
            }
            let exports: String = (0..4).map(|index| format!("from {} import f{index} as alias{index}\n", if index < 2 { "models" } else { "more" })).collect();
            let project = InlineTestProject::with_language(Language::Python)
                .file("models.py", &definitions[0])
                .file("more.py", &definitions[1])
                .file("exports.py", &exports)
                .file("pkg/__init__.py", "")
                .file("pkg/exports.py", &exports)
                .file("caller.py", format!("import models\nimport more\nfrom models import First as Constructed\nimport exports\nimport pkg.exports\n{imports}\n{body}"))
                .build();
            let analyzer = PythonAnalyzer::from_project(project.project().clone());
            let target_files = [project.file("models.py"), project.file("more.py")];
            let mut declarations: Vec<_> = analyzer.get_all_declarations().into_iter()
                .filter(|unit| target_files.contains(unit.source()) && (unit.is_callable() || unit.is_class())).collect();
            declarations.sort();
            prop_assert_eq!(declarations.len(), 10);
            let targets: Vec<_> = selection.into_iter().map(|index| declarations[index].clone()).collect();
            let limits = CallRelationLimits { max_files: usize::MAX, max_source_bytes: usize::MAX, max_candidates: limit };
            // Non-overlapping analyzer/query lifetimes keep the singleton
            // oracle independent and exercise cold frontier replay.
            let actual = {
                let scope = AnalyzerQueryScope::new(&analyzer);
                CallRelationService::incoming_batch_with_unproven_limit(
                    &analyzer, scope.token(), &targets, limits, limit, None,
                )
            };
            drop(analyzer);
            let oracle = PythonAnalyzer::from_project(project.project().clone());
            let expected: Vec<_> = targets.iter().map(|target| {
                let oracle_scope = AnalyzerQueryScope::new(&oracle);
                CallRelationService::incoming_with_unproven_limit(
                    &oracle, oracle_scope.token(), target, limits, limit, None,
                )
            }).collect();
            prop_assert_eq!(actual.len(), expected.len());
            for (actual, expected) in actual.into_iter().zip(expected) {
                prop_assert_eq!(actual.sites, expected.sites);
                prop_assert_eq!(actual.truncated, expected.truncated);
                prop_assert_eq!(actual.cancelled, expected.cancelled);
                prop_assert_eq!(actual.diagnostics, expected.diagnostics);
                prop_assert_eq!(actual.proof_authority, expected.proof_authority);
                prop_assert_eq!(actual.work, expected.work);
            }
        }
    }
}
