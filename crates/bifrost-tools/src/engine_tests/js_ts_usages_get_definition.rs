#[cfg(test)]
mod js_ts_extraction_tests {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::QueryScope;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::resolve_call_target_batch_with_source;

    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon("#3496: the general call-target route discarded resolver-owned proof evidence")]
    fn call_target_batch_keeps_every_resolver_proof() {
        struct Case {
            language: Language,
            files: &'static [(&'static str, &'static str)],
            caller: &'static str,
            callee: &'static str,
            canonical_callee: Option<&'static str>,
        }

        let cases = [
            Case {
                language: Language::Python,
                files: &[(
                    "app.py",
                    "import httpx\n\n\ndef fetch(url):\n    return httpx.get(url)\n",
                )],
                caller: "app.py",
                callee: "get",
                canonical_callee: Some("httpx.get"),
            },
            Case {
                language: Language::JavaScript,
                files: &[(
                    "app.js",
                    "import { get } from \"axios\";\n\nexport function fetch(url) {\n  return get(url);\n}\n",
                )],
                caller: "app.js",
                callee: "get",
                canonical_callee: Some("axios.get"),
            },
            Case {
                language: Language::Java,
                files: &[(
                    "App.java",
                    "class App { void run(java.util.List<String> values) { values.size(); } }",
                )],
                caller: "App.java",
                callee: "size",
                canonical_callee: None,
            },
        ];

        for case in cases {
            let mut project = InlineTestProject::with_language(case.language);
            for (path, contents) in case.files {
                project = project.file(*path, *contents);
            }
            let project = project.build();
            let workspace = project.workspace_analyzer(
                brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
            );
            let analyzer = workspace.analyzer();
            let file = project.file(case.caller);
            let source = Arc::<str>::from(
                case.files
                    .iter()
                    .find(|(path, _)| *path == case.caller)
                    .expect("the caller is one of the case files")
                    .1,
            );
            let start_byte = source
                .rfind(case.callee)
                .expect("the callee token appears in the caller");
            let scope = AnalyzerQueryScope::new(analyzer);
            let outcomes = resolve_call_target_batch_with_source(
                analyzer,
                scope.token(),
                vec![DefinitionLookupRequest {
                    file: file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(start_byte),
                    end_byte: Some(start_byte + case.callee.len()),
                }],
                file,
                source,
                None,
            );

            let [outcome] = outcomes.as_slice() else {
                panic!("one request answers once, got {outcomes:?}");
            };
            match case.canonical_callee {
                Some(canonical) => {
                    let proof = outcome.exact_external_call.as_ref().unwrap_or_else(|| {
                        panic!(
                            "{:?} published an exact external call proof the batch must carry: {outcome:?}",
                            case.language
                        )
                    });
                    assert_eq!(proof.canonical_callee(), canonical, "{outcome:?}");
                    assert_ne!(
                        outcome.call_application,
                        CallApplicationKind::Unknown,
                        "the proof's call shape travels with it: {outcome:?}"
                    );
                    // `call_target_boundary_evidence` reads the proof against
                    // the reference text, so the two must name one callee.
                    assert_eq!(
                        outcome.outcome.resolved_reference_target(),
                        Some(canonical),
                        "{outcome:?}"
                    );
                }
                None => {
                    assert!(
                        outcome.exact_external_call.is_none()
                            && outcome.external_callee_identity.is_none(),
                        "{:?} publishes no call proof, so the batch has none to carry: {outcome:?}",
                        case.language
                    );
                }
            }
        }
    }
}
