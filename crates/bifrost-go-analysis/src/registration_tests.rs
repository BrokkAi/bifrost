//! Found-defect pins that require this binary's registered language rules.
use brokk_bifrost_analysis::analyzer::resolution::fact_source;
mod fact_resolution {
    mod tests {

        use brokk_bifrost_analysis::{
            CancellationToken,
            analyzer::resolution::{
                fact_lowering::{LoweredSemanticRole, LoweringGapOrigin},
                fact_resolution::go_failure_fixture_support::*,
                *,
            },
        };
        use brokk_bifrost_core::analyzer::resolution_facts::*;
        use brokk_bifrost_test_macros::hardwon;

        #[cfg(test)]
        #[test]
        #[hardwon(
            "3e3665db0b32: corpus files such as zshellcheck pkg/katas/katas.go exposed missing interface and function-typed-field support"
        )]
        fn go_embedded_interface_methods_and_function_typed_fields_resolve_natively() {
            use super::super::fact_source::{
                GoMemberDeclaration, GoMemberDeclarationKind, GoStructField,
            };

            let source = r#"package p
type Base interface { Run() Result }
type Embedded interface { Base }
type Result struct{}
type Kata struct { Check func(int) Result }
func use(e Embedded, k Kata) { e.Run(); _ = k.Check(1) }
"#;
            let mut fixture = parsed_go_service_fixture(source, b"go-embedded-and-function-field");
            let type_definition = |spelling: &str| {
                let position = source
                    .find(&format!("type {spelling}"))
                    .expect("type declaration spelling")
                    + "type ".len();
                let site = positioned_site_at(
                    &fixture.facts,
                    position,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                );
                lowered_semantic_at(&fixture.lexical, site, LoweredSemanticRole::Definition)
            };
            let base = type_definition("Base");
            let embedded = type_definition("Embedded");
            let result = type_definition("Result");
            let kata = type_definition("Kata");
            let run = go_callable_definition_at(
                &fixture,
                source.find("Run() Result").expect("interface method"),
            )
            .1;
            let field_position = source.find("Check func").expect("function field");
            let field_site = positioned_site_at(
                &fixture.facts,
                field_position,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
            );
            let field = lowered_semantic_at(
                &fixture.lexical,
                field_site,
                LoweredSemanticRole::Definition,
            );
            let call = fixture
                .facts
                .calls
                .iter()
                .find(|call| {
                    fixture.facts.sites[call.call.index()].start_byte
                        == source.find("k.Check(1)").expect("function field call")
                })
                .expect("function-typed field call fact");
            let call_reference = lowered_semantic_at(
                &fixture.lexical,
                call.callee,
                LoweredSemanticRole::Reference,
            );
            let callable_lookup = fixture
                .typed
                .qualified_routes()
                .iter()
                .find(|route| {
                    route.reference() == call_reference
                        && route.namespace() == ResolutionNamespace::Callable
                })
                .expect("function field call's callable lookup route")
                .lookup();
            fixture.service.set_go_member_declarations([
                GoMemberDeclaration {
                    definition: base,
                    kind: GoMemberDeclarationKind::Interface {
                        methods: Vec::new(),
                    },
                },
                GoMemberDeclaration {
                    definition: embedded,
                    kind: GoMemberDeclarationKind::Interface {
                        methods: Vec::new(),
                    },
                },
                GoMemberDeclaration {
                    definition: kata,
                    kind: GoMemberDeclarationKind::Struct {
                        fields: vec![GoStructField {
                            callable_lookup,
                            embedded: false,
                            field: Some(field),
                            value_type: None,
                        }],
                    },
                },
            ]);

            let run_position = source.find("e.Run").expect("embedded method call") + "e.".len();
            let run_reference = go_reference_at(&fixture, run_position);
            let run_answer = fixture
                .service
                .resolve_reference(run_reference, &CancellationToken::new())
                .expect("embedded interface method lookup");
            assert_eq!(run_answer.binding().targets(), &[run]);
            assert!(matches!(
                run_answer.binding().completion(),
                ResolutionCompletion::Incomplete(_)
            ));

            let (call_answer, _) = resolve_go_call_expression_at(
                &fixture,
                source.find("k.Check(1)").expect("function field call"),
            );
            assert_eq!(
                call_answer.binding().targets(),
                &[field],
                "{call_answer:#?}"
            );
            let result_projection = call_answer
                .projections()
                .iter()
                .find(|projection| projection.kind().is_callable_result())
                .expect("function-typed field result projection");
            let result_frontier = call_answer
                .projected_frontiers()
                .iter()
                .find(|frontier| frontier.slot() == result_projection.output_slot())
                .expect("function-typed field result frontier");
            assert_eq!(
                result_frontier.completion(),
                &ResolutionCompletion::Complete
            );
            assert_eq!(
                result_frontier
                    .possible_values()
                    .iter()
                    .map(|value| value.ty().identity())
                    .collect::<Vec<_>>(),
                vec![result]
            );
        }

        #[cfg(test)]
        #[brokk_bifrost_test_macros::hardwon(
            "a05d3a95e9d5: Go call signatures dropped the slot of an unnamed parameter"
        )]
        #[test]
        fn go_unnamed_and_variadic_parameters_preserve_inventory_and_partial_applicability() {
            let source = r#"package p

func F(int) {}
func V(values ...int) {}
func use(x int) {
    F(x)
    V(x)
}
"#;
            let fixture = parsed_go_service_fixture(source, b"go-omitted-call-parameters");
            for (declaration_text, call_text) in [("F(int)", "F(x)"), ("V(values", "V(x)")] {
                let (callable_site, callable) = go_callable_definition_at(
                    &fixture,
                    source
                        .find(declaration_text)
                        .unwrap_or_else(|| panic!("missing Go declaration {declaration_text}")),
                );
                let signature_reason = fixture
                    .lexical
                    .gaps()
                    .iter()
                    .find(|gap| {
                        gap.site() == callable_site
                            && gap.origin()
                                == LoweringGapOrigin::Extracted(
                                    ResolutionGapKind::UnsupportedCallApplicability,
                                )
                    })
                    .map(|gap| gap.reason_semantic());
                let signature = fixture
                    .typed
                    .callable_signatures()
                    .iter()
                    .find(|signature| signature.definition() == callable)
                    .unwrap_or_else(|| panic!("missing signature header for {declaration_text}"));
                if declaration_text == "F(int)" {
                    assert_eq!(signature.parameters().len(), 1);
                    assert!(signature_reason.is_none());
                    assert_eq!(signature.completion(), &ResolutionCompletion::Complete);
                } else {
                    assert_eq!(signature.parameters().len(), 1);
                    assert!(signature.parameters()[0].repeated());
                    assert!(
                        signature_reason.is_none(),
                        "variadic value-shape uncertainty does not poison callable binding"
                    );
                    assert_eq!(
                        signature.completion(),
                        &ResolutionCompletion::Complete,
                        "the variadic slice parameter has a complete typed signature"
                    );
                }

                let (answer, applicability_reason) = resolve_go_call_at(
                    &fixture,
                    source
                        .rfind(call_text)
                        .unwrap_or_else(|| panic!("missing Go call {call_text}")),
                );
                assert_eq!(answer.binding().targets(), &[callable]);
                assert_eq!(
                    answer.binding().completion(),
                    &ResolutionCompletion::Complete,
                    "Go call name binding is argument-independent"
                );
                if declaration_text == "F(int)" {
                    assert_eq!(
                        answer.completion(),
                        &ResolutionCompletion::Complete,
                        "a uniquely bound, fully typed call is complete: {answer:#?}"
                    );
                } else {
                    assert_eq!(
                        answer.completion(),
                        &ResolutionCompletion::Complete,
                        "{call_text} has fully typed variadic applicability: {answer:#?}"
                    );
                }
                assert!(
                    !answer.completion().contains_reason(
                        ResolutionIncompleteReason::UnsupportedSemantic(applicability_reason)
                    ),
                    "the Go name-binding rule discharges only call applicability: {answer:?}"
                );
            }
        }
        #[cfg(test)]
        #[test]
        fn go_universe_binds_only_after_source_scopes_and_source_names_shadow_it() {
            let builtin_source = r#"package p

func use(values []int) int { _ = new(int); return len(values) }
"#;
            let builtin = parsed_go_service_fixture(builtin_source, b"go-universe-len");
            let builtin_reference = go_reference_at(
                &builtin,
                builtin_source
                    .find("len(values)")
                    .expect("builtin call site"),
            );
            let cancellation = CancellationToken::new();
            let seed = BatchResolutionFragmentSource::reference_seed(
                &builtin.service,
                ResolutionQuery::new(builtin_reference),
                &cancellation,
            )
            .expect("Go source seed read succeeds")
            .expect("the Go reference has a source seed");
            assert_eq!(
                seed.site_metadata()
                    .and_then(FactReferenceSiteMetadata::go_spelling_namespace),
                Some(ResolutionNamespace::TypeOrValue)
            );
            assert_eq!(
                seed.site_metadata()
                    .map(FactReferenceSiteMetadata::site_kind),
                Some(ResolutionSiteKind::CallableReference)
            );
            let builtin_site = positioned_site_at(
                &builtin.facts,
                builtin_source
                    .find("len(values)")
                    .expect("builtin call site"),
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::TypeOrValue,
            );
            assert!(builtin.facts.gaps.iter().any(|gap| {
                gap.site == builtin_site
                    && gap.kind == ResolutionGapKind::UnsupportedCallApplicability
            }));
            assert_eq!(
                BatchResolutionFragmentSource::universe_entry(
                    &builtin.service,
                    builtin_reference,
                    ResolutionNamespace::TypeOrValue,
                    &cancellation,
                )
                .expect("Go universe read succeeds")
                .map(|entry| entry.spelling),
                Some("len")
            );
            assert!(BatchResolutionFragmentSource::supports_go_universe(
                &builtin.service
            ));
            let direct_binding = BatchResolutionEngine::new(&builtin.service)
                .resolve_reference(ResolutionQuery::new(builtin_reference), &cancellation)
                .expect("Go universe lexical binding resolves without storage errors");
            let intrinsic_len = go_intrinsic_identity(ResolutionNamespace::Callable, "len");
            assert_eq!(
                direct_binding.targets(),
                &[intrinsic_len],
                "Go universe binding failed: seed={seed:?}; answer={direct_binding:?}; facts gaps={:?}; lexical gaps={:?}",
                builtin.facts.gaps,
                builtin.lexical.gaps()
            );
            assert_eq!(direct_binding.completion(), &ResolutionCompletion::Complete);
            let new_reference = go_reference_at(
                &builtin,
                builtin_source
                    .find("new(int)")
                    .expect("unshadowed builtin new"),
            );
            let new_answer = builtin
                .service
                .resolve_reference(new_reference, &cancellation)
                .expect("Go universe new resolves without storage errors");
            assert_eq!(
                new_answer.binding().targets(),
                &[go_intrinsic_identity(ResolutionNamespace::Callable, "new")]
            );
            assert_eq!(
                new_answer.binding().completion(),
                &ResolutionCompletion::Complete
            );
            assert_eq!(new_answer.callable_receiver_dispositions().len(), 1);
            assert_eq!(
                new_answer.callable_receiver_dispositions()[0].target(),
                new_answer.binding().targets()[0]
            );
            assert_eq!(
                new_answer.callable_receiver_dispositions()[0]
                    .disposition()
                    .channels(),
                FactCallableReceiverChannels::External
            );
            assert_eq!(
                new_answer.callable_receiver_dispositions()[0]
                    .disposition()
                    .gap(),
                None
            );
            let builtin_answer = builtin
                .service
                .resolve_reference(builtin_reference, &cancellation)
                .expect("Go universe binding resolves without storage errors");
            assert_eq!(
                builtin_answer.binding().targets(),
                &[intrinsic_len],
                "Go universe binding answer: {builtin_answer:?}; lexical gaps={:?}",
                builtin.lexical.gaps()
            );
            assert_eq!(
                builtin_answer.callable_receiver_dispositions().len(),
                1,
                "an unqualified Go function has one closed graph disposition: {builtin_answer:?}"
            );
            assert_eq!(
                builtin_answer.callable_receiver_dispositions()[0].target(),
                builtin_answer.binding().targets()[0]
            );
            assert_eq!(
                builtin_answer.callable_receiver_dispositions()[0]
                    .disposition()
                    .channels(),
                FactCallableReceiverChannels::External
            );
            assert_eq!(
                builtin_answer.callable_receiver_dispositions()[0]
                    .disposition()
                    .gap(),
                None
            );
            assert_eq!(
                builtin_answer.binding().completion(),
                &ResolutionCompletion::Complete,
                "the predeclared callable is a complete FactResolution binding: {builtin_answer:?}; gaps={:?}; lexical gaps={:?}",
                builtin.facts.gaps,
                builtin.lexical.gaps()
            );

            let shadowed_source = r#"package p

func len(values []int) int { return 1 }
func new(value int) *int { return &value }
func use(values []int) { _ = len(values); _ = new(1) }
"#;
            let shadowed = parsed_go_service_fixture(shadowed_source, b"go-universe-shadowed-len");
            let declaration = go_callable_definition_at(
                &shadowed,
                shadowed_source
                    .find("func len")
                    .expect("shadowing function declaration")
                    + "func ".len(),
            )
            .1;
            let call = go_reference_at(
                &shadowed,
                shadowed_source
                    .rfind("len(values)")
                    .expect("shadowing function call"),
            );
            let answer = shadowed
                .service
                .resolve_reference(call, &CancellationToken::new())
                .expect("source shadow resolution succeeds");
            assert_eq!(answer.binding().targets(), &[declaration]);
            // The source declaration must win lexical lookup even though the
            // separate invocation-applicability gap can keep the call partial.
            assert_ne!(answer.binding().targets(), &[intrinsic_len]);
            let new_declaration = go_callable_definition_at(
                &shadowed,
                shadowed_source
                    .find("func new")
                    .expect("user new declaration")
                    + "func ".len(),
            )
            .1;
            let shadowed_new = go_reference_at(
                &shadowed,
                shadowed_source.rfind("new(1)").expect("shadowed new call"),
            );
            let new_answer = shadowed
                .service
                .resolve_reference(shadowed_new, &CancellationToken::new())
                .expect("source new shadow resolution succeeds");
            assert_eq!(new_answer.binding().targets(), &[new_declaration]);
        }
    }
}
