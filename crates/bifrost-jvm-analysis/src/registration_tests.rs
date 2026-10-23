//! Found-defect pins that require this binary's registered language rules.
mod fact_resolution {
    mod tests {
        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::*;
        use std::collections::{BTreeSet, HashSet};

        use brokk_bifrost_analysis::{
            CancellationToken,
            analyzer::resolution::{
                fact_lowering::{LoweredSemanticRole, LoweringGapOrigin},
                fact_resolution::fixture_support::*,
                *,
            },
        };
        use brokk_bifrost_core::analyzer::resolution_facts::*;
        use brokk_bifrost_test_macros::hardwon;

        #[cfg(test)]
        #[brokk_bifrost_test_macros::hardwon(
            "532ab4ced3c0: Java integer literal typing must produce complete runtime integer evidence"
        )]
        #[test]
        fn generated_changed_integer_arguments_reach_applicability_as_complete_runtime_ints() {
            let source = "class A { int changed(int value) { return value; } int use() { changed(0); changed(1); changed(2); changed(3); return changed(4); } }";
            let fixture =
                parsed_java_service_fixture(source, b"java-changed-integer-applicability");
            let declaration = java_callable_definition_at(
                &fixture,
                source.find("changed(int").expect("changed declaration"),
            );
            let literal_facts = fixture
                .facts
                .intrinsic_type_seeds
                .iter()
                .filter(|seed| {
                    let slot = fixture.facts.type_slots[seed.output.get() as usize];
                    fixture.facts.sites[slot.site.get() as usize].kind
                        == ResolutionSiteKind::Literal
                })
                .collect::<Vec<_>>();
            assert_eq!(literal_facts.len(), 5);
            assert!(literal_facts.iter().all(|seed| {
                seed.kind == IntrinsicTypeKind::Primitive
                    && fixture.facts.names[seed.name.get() as usize].spelling == "int"
            }));
            let runtime_literal_values = fixture
                .typed
                .intrinsic_seeds()
                .iter()
                .filter(|seed| seed.kind() == IntrinsicTypeKind::Primitive)
                .filter_map(|seed| match seed.frontier().possible_values() {
                    [value @ ResolutionSlotValue::Runtime { .. }]
                        if seed.frontier().completion() == &ResolutionCompletion::Complete =>
                    {
                        Some(*value)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(runtime_literal_values.len(), 5);
            assert!(
                runtime_literal_values
                    .windows(2)
                    .all(|pair| pair[0] == pair[1]),
                "all five generated integer literals must carry the same runtime int identity"
            );
            let runtime_int = runtime_literal_values[0];

            for literal in 0..=4 {
                let call = format!("changed({literal})");
                let position = source.find(&call).expect("changed call");
                let site = positioned_site_at(
                    &fixture.facts,
                    position,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Callable,
                );
                let reference =
                    lowered_semantic_at(&fixture.lexical, site, LoweredSemanticRole::Reference);
                let obligation = fixture
                    .typed
                    .call_obligations()
                    .iter()
                    .find(|obligation| obligation.callee_reference() == reference)
                    .expect("changed call applicability obligation");
                assert_eq!(obligation.argument_slots().len(), 1);
                let states = stable_typed_states_for_reference(&fixture, reference);
                let argument = states
                    .get(&obligation.argument_slots()[0])
                    .expect("changed call argument frontier");
                assert_eq!(argument.possible_values(), &[runtime_int]);
                assert_eq!(argument.completion(), &ResolutionCompletion::Complete);

                let answer = fixture
                    .service
                    .resolve_reference(reference, &CancellationToken::new())
                    .expect("preload reads are infallible");
                assert_eq!(answer.binding().targets(), &[declaration]);
                assert!(!answer.completion().contains_reason(
                    ResolutionIncompleteReason::UnsupportedSemantic(
                        obligation.applicability_reason(),
                    )
                ));
            }
        }

        #[cfg(test)]
        #[test]
        #[brokk_bifrost_test_macros::hardwon(
            "#2771: SB census resource activation leaked into its initializer and catch/finally"
        )]
        fn java_try_resource_excludes_own_initializer_and_catch_finally() {
            let source = "class A { static AutoCloseable r; static void f() { try (AutoCloseable r = r; AutoCloseable s = r) { use(r); } catch (Exception ex) { use(r); } finally { use(r); } use(r); } static void use(AutoCloseable x) {} }";
            let fixture =
                parsed_java_service_fixture(source, b"java-resource-activation-boundaries");
            let declaration = |position| {
                let site = positioned_site_at(
                    &fixture.facts,
                    position,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                );
                lowered_semantic_at(&fixture.lexical, site, LoweredSemanticRole::Definition)
            };
            let field =
                declaration(source.find("AutoCloseable r").unwrap() + "AutoCloseable ".len());
            let resource = declaration(
                source.find("try (AutoCloseable r").unwrap() + "try (AutoCloseable ".len(),
            );
            // The preload supplies no selected JVM context for the field owner.
            // An outside-try control pins that independent completion boundary.
            let control_site = positioned_site_at(
                &fixture.facts,
                source.rfind("use(r)").unwrap() + "use(".len(),
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Value,
            );
            let control_reference = lowered_semantic_at(
                &fixture.lexical,
                control_site,
                LoweredSemanticRole::Reference,
            );
            let control = fixture
                .service
                .resolve_reference(control_reference, &CancellationToken::new())
                .unwrap();
            assert_eq!(control.binding().targets(), &[field]);
            for (marker, offset, target) in [
                ("r = r", "r = ".len(), field),
                ("s = r", "s = ".len(), resource),
                ("{ use(r); } catch", "{ use(".len(), resource),
                (
                    "catch (Exception ex) { use(r)",
                    "catch (Exception ex) { use(".len(),
                    field,
                ),
                ("finally { use(r)", "finally { use(".len(), field),
            ] {
                let position = source.find(marker).expect("boundary reference") + offset;
                let site = positioned_site_at(
                    &fixture.facts,
                    position,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                );
                let reference =
                    lowered_semantic_at(&fixture.lexical, site, LoweredSemanticRole::Reference);
                let answer = fixture
                    .service
                    .resolve_reference(reference, &CancellationToken::new())
                    .unwrap();
                assert_eq!(answer.binding().targets(), &[target], "{marker}");
                if target == field {
                    assert_eq!(
                        answer.binding().completion().kind(),
                        control.binding().completion().kind(),
                        "{marker}"
                    );
                    assert_eq!(
                        answer.completion().kind(),
                        control.completion().kind(),
                        "{marker}"
                    );
                } else {
                    assert_eq!(
                        answer.binding().completion(),
                        &ResolutionCompletion::Complete,
                        "{marker}"
                    );
                    assert_eq!(
                        answer.completion(),
                        &ResolutionCompletion::Complete,
                        "{marker}"
                    );
                }
            }
        }

        #[cfg(test)]
        #[test]
        #[brokk_bifrost_test_macros::hardwon(
            "#2771: SB census resource shadowing selected an outer field"
        )]
        fn java_try_resource_binds_body_reference_to_resource_instead_of_outer_field() {
            let source = "class A { AutoCloseable r; void f() { try (AutoCloseable r = make()) { use(r); } } AutoCloseable make() { return null; } void use(AutoCloseable x) {} }";
            let fixture = parsed_java_service_fixture(source, b"java-try-resource-binder");
            let resource_site = positioned_site_at(
                &fixture.facts,
                source.find("try (AutoCloseable r").expect("resource r")
                    + "try (AutoCloseable ".len(),
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
            );
            let reference_site = positioned_site_at(
                &fixture.facts,
                source.rfind("use(r)").expect("body resource reference") + "use(".len(),
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Value,
            );
            let resource = lowered_semantic_at(
                &fixture.lexical,
                resource_site,
                LoweredSemanticRole::Definition,
            );
            let reference = lowered_semantic_at(
                &fixture.lexical,
                reference_site,
                LoweredSemanticRole::Reference,
            );
            let answer = fixture
                .service
                .resolve_reference(reference, &CancellationToken::new())
                .expect("preload reads are infallible");
            assert_eq!(answer.binding().targets(), &[resource]);
            assert_eq!(
                answer.binding().completion(),
                &ResolutionCompletion::Complete
            );
            assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
        }

        #[cfg(test)]
        #[test]
        #[hardwon(
            "0fc00ac3e3b9: lSP constructor_new_type returned no target because native default construction could never reach unindexed Object; publish the class constructor site"
        )]
        fn java_default_constructor_is_the_applicable_candidate_whatever_the_superclass() {
            // `Product` supplies its own default constructor. Its superclass is
            // not consulted for a constructor, so an abstract superclass or a
            // superclass with a written constructor does not change the target.
            for (label, source) in [
                (
                    b"abstract-superclass".as_slice(),
                    "public abstract class Base {} public class Product extends Base { static Product make() { return new Product(); } }",
                ),
                (
                    b"explicit-super-constructor".as_slice(),
                    "public class Base { public Base() {} } public class Product extends Base { static Product make() { return new Product(); } }",
                ),
            ] {
                let fixture = parsed_java_service_fixture(source, label);
                let constructor_position =
                    source.rfind("new Product").expect("Product construction") + "new ".len();
                let (answer, applicability_reason) =
                    resolve_java_constructor_call_at(&fixture, constructor_position);
                assert_eq!(answer.binding().targets().len(), 1, "{answer:?}");
                assert!(
                    !answer.completion().contains_reason(
                        ResolutionIncompleteReason::UnsupportedSemantic(applicability_reason)
                    ),
                    "the supplied constructor takes no arguments: {answer:?}"
                );
            }
        }

        #[cfg(test)]
        #[test]
        #[hardwon(
            "8bed514d5e5d: a proven incompatible field qualifier incorrectly manufactured incomplete evidence; preserve the complete post-shadow negative"
        )]
        fn post_shadow_field_qualifier_rejection_preserves_complete_negative() {
            let source = "public class Fixture { public static class Base { public static int x; } public static class Child extends Base { public int x; } public static class Use extends Unindexed { public int y = Child.x; } }";
            let fixture = parsed_java_service_fixture(source, b"post-shadow-qualifier-rejection");
            let reference = lowered_semantics_named(
                &fixture.facts,
                &fixture.lexical,
                "x",
                ResolutionIdentifierRole::Reference,
            )[0];
            let definitions = lowered_semantics_named(
                &fixture.facts,
                &fixture.lexical,
                "x",
                ResolutionIdentifierRole::Declaration,
            );
            assert_eq!(definitions.len(), 2);
            let answer = fixture
                .service
                .resolve_reference(reference, &CancellationToken::new())
                .expect("preloaded hierarchy resolution is infallible");
            assert!(answer.binding().targets().is_empty());
            let oracle = hierarchy_qualifier_completion_oracle(&fixture, reference);
            let expected = oracle.transferred.clone();
            assert_eq!(
                hierarchy_property_completion_quotient(answer.binding().completion(), &oracle),
                expected
            );
            assert_eq!(
                hierarchy_property_completion_quotient(answer.completion(), &oracle),
                expected
            );
        }

        #[cfg(test)]
        #[test]
        #[hardwon(
            "87975ac9e3b6: static method references retained false receiver gaps; this negative control ensures the repair does not discharge instance targets"
        )]
        fn java_static_call_keeps_implicit_receiver_gap_for_instance_target() {
            // javac rejects this call: a static method has no current instance.
            let source =
                "class A { int target() { return 1; } static int caller() { return target(); } }";
            let fixture = parsed_java_service_fixture(source, b"java-static-call-instance-target");
            let reference_site = positioned_site_at(
                &fixture.facts,
                source.rfind("target()").expect("target call"),
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Callable,
            );
            let reference = lowered_semantic_at(
                &fixture.lexical,
                reference_site,
                LoweredSemanticRole::Reference,
            );
            let reason = fixture
                .lexical
                .gaps()
                .iter()
                .find(|gap| {
                    gap.site() == reference_site
                        && gap.origin()
                            == LoweringGapOrigin::Extracted(
                                ResolutionGapKind::UnsupportedImplicitReceiver,
                            )
                })
                .expect("instance target retains the static-context receiver gap")
                .reason_semantic();
            let answer = fixture
                .service
                .resolve_reference(reference, &CancellationToken::new())
                .expect("preload reads are infallible");

            assert!(
                answer
                    .completion()
                    .contains_reason(ResolutionIncompleteReason::UnsupportedSemantic(reason))
            );
        }
        #[cfg(test)]
        #[test]
        fn compact_record_constructor_retains_target_and_exact_applicability() {
            let source = "record R(int x) { R { } R make() { return new R(1); } }";
            let fixture = parsed_java_service_fixture(source, b"compact-constructor-applicability");
            let constructor_site = positioned_site_at(
                &fixture.facts,
                source.find("R {").expect("compact constructor name"),
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Constructor,
            );
            let constructor = lowered_semantic_at(
                &fixture.lexical,
                constructor_site,
                LoweredSemanticRole::Definition,
            );
            let signature_reason = fixture
                .lexical
                .gaps()
                .iter()
                .find(|gap| {
                    gap.site() == constructor_site
                        && gap.origin()
                            == LoweringGapOrigin::Extracted(
                                ResolutionGapKind::UnsupportedCallApplicability,
                            )
                })
                .expect("compact constructor signature inventory gap")
                .reason_semantic();
            let signature = fixture
                .typed
                .callable_signatures()
                .iter()
                .find(|signature| signature.definition() == constructor)
                .expect("compact constructor signature header");
            assert!(signature.parameters().is_empty());
            assert_incomplete_with_reason(signature.completion(), signature_reason);

            let constructor_reference =
                source.rfind("new R(1)").expect("compact constructor call") + "new ".len();
            let (answer, applicability_reason) =
                resolve_java_constructor_call_at(&fixture, constructor_reference);
            assert_eq!(answer.binding().targets(), &[constructor]);
            assert_incomplete_with_reason(answer.completion(), applicability_reason);
        }
        #[cfg(test)]
        #[test]
        fn generic_headers_and_explicit_type_arguments_remain_unresolved() {
            let source = "class A { <T> void generic() {} void plain() {} void g(A a) { generic(); a.<String>plain(); } }";
            let fixture = parsed_java_service_fixture(source, b"fixed-call-generic-unknown");
            for (call, declaration) in [("generic();", "generic"), ("plain();", "plain")] {
                let declaration = java_callable_definition_at(
                    &fixture,
                    source.find(declaration).expect("callable declaration name"),
                );
                let (answer, reason) =
                    resolve_java_call_at(&fixture, source.rfind(call).expect("generic call"));
                assert_eq!(answer.binding().targets(), &[declaration]);
                assert_incomplete_with_reason(answer.completion(), reason);
            }
        }
        #[cfg(test)]
        #[test]
        fn java_private_qualified_field_retains_visibility_incompleteness() {
            let source = "class A { private int x; } class B { int f(A a) { return a.x; } }";
            let fixture = parsed_java_service_fixture(source, b"java-private-field-visibility");
            let field_site = positioned_site_at(
                &fixture.facts,
                source.find("int x").expect("field x") + "int ".len(),
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
            );
            let reference_site = positioned_site_at(
                &fixture.facts,
                source.rfind("a.x").expect("qualified field x") + "a.".len(),
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::TypeOrValue,
            );
            let field = lowered_semantic_at(
                &fixture.lexical,
                field_site,
                LoweredSemanticRole::Definition,
            );
            let reference = lowered_semantic_at(
                &fixture.lexical,
                reference_site,
                LoweredSemanticRole::Reference,
            );
            let reason = fixture
                .typed
                .property_gaps()
                .iter()
                .find(|gap| {
                    gap.definition() == field
                        && gap.kind() == ResolutionGapKind::UnsupportedVisibility
                })
                .expect("declaration-owned Java visibility gap")
                .reason_semantic();
            let answer = fixture
                .service
                .resolve_reference(reference, &CancellationToken::new())
                .expect("preload reads are infallible");
            assert_eq!(answer.binding().targets(), &[field]);
            assert_incomplete_with_reason(answer.completion(), reason);
        }

        #[cfg(test)]
        #[test]
        fn multiple_proven_candidates_do_not_discharge_applicability() {
            let source = "class A { void f() {} void f() {} void g() { f(); } }";
            let fixture = parsed_java_service_fixture(source, b"fixed-call-multiple-proven");
            let (answer, reason) =
                resolve_java_call_at(&fixture, source.rfind("f();").expect("call f"));
            assert_eq!(answer.binding().targets().len(), 2);
            assert_incomplete_with_reason(answer.completion(), reason);
        }
        #[cfg(test)]
        #[test]
        fn repeated_parameter_retains_exact_applicability_obligation() {
            let source = "class A { void f(boolean... values) {} void g() { f(true); } }";
            let fixture = parsed_java_service_fixture(source, b"fixed-call-varargs-unknown");
            let declaration = java_callable_definition_at(
                &fixture,
                source.find("void f").expect("method f") + "void ".len(),
            );
            let (answer, reason) =
                resolve_java_call_at(&fixture, source.rfind("f(true)").expect("call f"));
            assert_eq!(answer.binding().targets(), &[declaration]);
            assert_incomplete_with_reason(answer.completion(), reason);
        }
        #[cfg(test)]
        #[test]
        fn route_free_java_cycle_evidence_obeys_the_global_candidate_cutoff() {
            let same_depth_source = "public class Fixture { public interface A extends C {} public interface C extends A {} public interface Good { int x = 1; } public static class Leaf implements A, Good {} public static class Use extends Unindexed { public int f(Leaf v) { return v.x; } } }";
            let same_depth =
                parsed_java_service_fixture(same_depth_source, b"route-free-same-depth-cycle");
            let same_depth_target = lowered_semantics_named(
                &same_depth.facts,
                &same_depth.lexical,
                "x",
                ResolutionIdentifierRole::Declaration,
            )[0];
            let same_depth_reference = lowered_semantics_named(
                &same_depth.facts,
                &same_depth.lexical,
                "x",
                ResolutionIdentifierRole::Reference,
            )[0];
            let same_depth_answer = same_depth
                .service
                .resolve_reference(same_depth_reference, &CancellationToken::new())
                .expect("preloaded hierarchy resolution is infallible");
            assert_eq!(same_depth_answer.binding().targets(), &[same_depth_target]);
            assert_eq!(
                same_depth_answer.binding().completion(),
                same_depth_answer.completion()
            );
            let same_depth_reasons = match same_depth_answer.completion() {
                ResolutionCompletion::Complete => panic!("the same-depth SCC is retained"),
                ResolutionCompletion::Incomplete(reasons) => reasons,
            };
            let cycle_owners = ["A", "C"]
                .into_iter()
                .flat_map(|name| {
                    lowered_semantics_named(
                        &same_depth.facts,
                        &same_depth.lexical,
                        name,
                        ResolutionIdentifierRole::Declaration,
                    )
                })
                .collect::<HashSet<_>>();
            let internal_gap_reasons = same_depth
                .typed
                .property_gaps()
                .iter()
                .filter(|gap| {
                    cycle_owners.contains(&gap.definition())
                        && gap.kind() == ResolutionGapKind::UnsupportedHierarchyTraversal
                })
                .map(|gap| ResolutionIncompleteReason::UnsupportedSemantic(gap.reason_semantic()))
                .collect::<BTreeSet<_>>();
            assert_eq!(internal_gap_reasons.len(), 2);
            assert!(
                internal_gap_reasons
                    .iter()
                    .all(|reason| same_depth_reasons.contains(reason))
            );
            assert_eq!(
                same_depth_reasons
                    .iter()
                    .filter(|reason| matches!(
                        reason,
                        ResolutionIncompleteReason::CyclicExpansion(_)
                    ))
                    .count(),
                1
            );
            let cycle_completion = ResolutionCompletion::incomplete([*same_depth_reasons
                .iter()
                .find(|reason| matches!(reason, ResolutionIncompleteReason::CyclicExpansion(_)))
                .expect("the same-depth SCC has one exact terminal marker")]);
            let same_depth_oracle =
                hierarchy_qualifier_completion_oracle(&same_depth, same_depth_reference);
            let expected_same_depth = same_depth_oracle.transferred.combine(&cycle_completion);
            assert_eq!(
                hierarchy_property_completion_quotient(
                    same_depth_answer.binding().completion(),
                    &same_depth_oracle,
                ),
                expected_same_depth
            );
            assert_eq!(
                hierarchy_property_completion_quotient(
                    same_depth_answer.completion(),
                    &same_depth_oracle,
                ),
                expected_same_depth
            );
            let same_depth_plural = same_depth
                .service
                .references_to_many(&[same_depth_target], &CancellationToken::new())
                .expect("the incomplete unique reverse binding is source-readable");
            assert_eq!(same_depth_plural.answers().len(), 1);
            let same_depth_target_answer = &same_depth_plural.answers()[0];
            assert_eq!(
                same_depth_target_answer.answer().references(),
                &[same_depth_reference]
            );
            assert_eq!(same_depth_target_answer.bindings().len(), 1);
            assert_eq!(
                same_depth_target_answer.bindings()[0].definitions(),
                &[same_depth_target]
            );
            assert_eq!(
                cross_operation_completion(same_depth_target_answer.bindings()[0].completion()),
                cross_operation_completion(same_depth_answer.completion()),
                "a unique binding still retains its incomplete forward-site completion"
            );

            let deeper_source = "public class Fixture { public interface A extends C {} public interface C extends A {} public interface Mid extends A {} public interface Good { int x = 1; } public static class Leaf implements Mid, Good {} public static class Use extends Unindexed { public int f(Leaf v) { return v.x; } } }";
            let deeper =
                parsed_java_service_fixture(deeper_source, b"route-free-deeper-cycle-cutoff");
            let deeper_target = lowered_semantics_named(
                &deeper.facts,
                &deeper.lexical,
                "x",
                ResolutionIdentifierRole::Declaration,
            )[0];
            let deeper_reference = lowered_semantics_named(
                &deeper.facts,
                &deeper.lexical,
                "x",
                ResolutionIdentifierRole::Reference,
            )[0];
            let deeper_answer = deeper
                .service
                .resolve_reference(deeper_reference, &CancellationToken::new())
                .expect("preloaded hierarchy resolution is infallible");
            assert_eq!(deeper_answer.binding().targets(), &[deeper_target]);
            let deeper_oracle = hierarchy_qualifier_completion_oracle(&deeper, deeper_reference);
            assert_hierarchy_success_transfers_qualifier_evidence(&deeper_answer, &deeper_oracle);
        }
        #[cfg(test)]
        #[test]
        fn route_free_java_cycle_is_terminal_but_direct_root_still_wins() {
            let source = "public class Fixture { public static class A extends B {} public static class B extends A { public int x; } public static class Use extends Unindexed { public int inherited(A v) { return v.x; } public int direct(B v) { return v.x; } } }";
            let fixture = parsed_java_service_fixture(source, b"route-free-cycle-terminal");
            let references = lowered_semantics_named(
                &fixture.facts,
                &fixture.lexical,
                "x",
                ResolutionIdentifierRole::Reference,
            );
            let target = lowered_semantics_named(
                &fixture.facts,
                &fixture.lexical,
                "x",
                ResolutionIdentifierRole::Declaration,
            )[0];
            assert_eq!(references.len(), 2);

            let cancellation = CancellationToken::new();
            let mut operation = FactResolutionOperation::new(
                &fixture.service.source,
                &fixture.service,
                &cancellation,
            );
            let inherited = operation
                .resolve_reference(references[0])
                .expect("preloaded hierarchy resolution is infallible");
            assert!(inherited.binding().targets().is_empty());
            let reasons = match inherited.completion() {
                ResolutionCompletion::Complete => {
                    panic!("the reached class cycle must be terminal")
                }
                ResolutionCompletion::Incomplete(reasons) => reasons,
            };
            let cycle_reasons = reasons
                .iter()
                .filter(|reason| matches!(reason, ResolutionIncompleteReason::CyclicExpansion(_)))
                .count();
            assert_eq!(cycle_reasons, 1);
            let cycle_owners = ["A", "B"]
                .into_iter()
                .flat_map(|name| {
                    lowered_semantics_named(
                        &fixture.facts,
                        &fixture.lexical,
                        name,
                        ResolutionIdentifierRole::Declaration,
                    )
                })
                .collect::<HashSet<_>>();
            let internal_gap_reasons = fixture
                .typed
                .property_gaps()
                .iter()
                .filter(|gap| {
                    cycle_owners.contains(&gap.definition())
                        && gap.kind() == ResolutionGapKind::UnsupportedHierarchyTraversal
                })
                .map(|gap| ResolutionIncompleteReason::UnsupportedSemantic(gap.reason_semantic()))
                .collect::<BTreeSet<_>>();
            assert_eq!(internal_gap_reasons.len(), 2);
            assert!(
                internal_gap_reasons
                    .iter()
                    .all(|reason| reasons.contains(reason))
            );
            // Fixture's only supertype is the implicit java.lang.Object, which
            // declares no member types, so its operand cannot reach these type
            // lookups. Use's authored unresolved superclass is a genuine one.
            let unrelated_owners = ["Use"]
                .map(|name| {
                    let definitions = lowered_semantics_named(
                        &fixture.facts,
                        &fixture.lexical,
                        name,
                        ResolutionIdentifierRole::Declaration,
                    );
                    assert_eq!(
                        definitions.len(),
                        1,
                        "the cycle fixture has one exact {name} declaration"
                    );
                    definitions[0]
                })
                .into_iter()
                .collect::<HashSet<_>>();
            let unrelated_gap_rows = fixture
                .typed
                .property_gaps()
                .iter()
                .filter(|gap| {
                    unrelated_owners.contains(&gap.definition())
                        && gap.kind() == ResolutionGapKind::UnsupportedHierarchyTraversal
                })
                .collect::<Vec<_>>();
            assert_eq!(
                unrelated_gap_rows.len(),
                1,
                "Use retains its exact unresolved-superclass property operand"
            );
            let unrelated_gap_reasons = unrelated_gap_rows
                .iter()
                .map(|gap| {
                    assert_eq!(
                        fixture.service.typed.gap_reason_provenance_by_reason
                            [&gap.reason_semantic()]
                            .origin(),
                        LoweringGapOrigin::Extracted(
                            ResolutionGapKind::UnsupportedHierarchyTraversal
                        )
                    );
                    ResolutionIncompleteReason::UnsupportedSemantic(gap.reason_semantic())
                })
                .collect::<BTreeSet<_>>();
            assert_eq!(unrelated_gap_reasons.len(), 1);
            for reason in internal_gap_reasons.iter().chain(&unrelated_gap_reasons) {
                assert_eq!(
                    reasons.iter().filter(|actual| *actual == reason).count(),
                    1,
                    "each exact hierarchy property operand occurs once"
                );
            }
            let cycle_completion = ResolutionCompletion::incomplete([*reasons
                .iter()
                .find(|reason| matches!(reason, ResolutionIncompleteReason::CyclicExpansion(_)))
                .expect("the terminal cycle has one exact marker")]);
            let internal_completion =
                ResolutionCompletion::incomplete(internal_gap_reasons.iter().copied());
            let unrelated_completion =
                ResolutionCompletion::incomplete(unrelated_gap_reasons.iter().copied());
            let inherited_oracle = hierarchy_qualifier_completion_oracle(&fixture, references[0]);
            let expected_inherited = inherited_oracle
                .transferred
                .combine(&internal_completion)
                .combine(&unrelated_completion)
                .combine(&cycle_completion);
            assert_eq!(inherited.binding().completion(), &expected_inherited);
            assert_eq!(inherited.completion(), &expected_inherited);

            let direct = operation
                .resolve_reference(references[1])
                .expect("preloaded hierarchy resolution is infallible");
            assert_eq!(direct.binding().targets(), &[target]);
            let direct_oracle = hierarchy_qualifier_completion_oracle(&fixture, references[1]);
            assert_hierarchy_success_transfers_qualifier_evidence(&direct, &direct_oracle);
            let inherited_again = operation
                .resolve_reference(references[0])
                .expect("the same-operation A-B-A hierarchy cache order is source-readable");
            assert_eq!(
                inherited_again, inherited,
                "a direct-root query between identical inherited queries cannot leak its cutoff or transfer authority into the cached A result"
            );

            let reverse = fixture
                .service
                .references_to(target, &CancellationToken::new())
                .expect("cyclic reverse hierarchy resolution is infallible");
            assert_eq!(reverse.references(), &[references[1]]);
            assert!(
                !reverse.references().contains(&references[0]),
                "a cyclic inherited branch never exposes the SCC member target"
            );
            let reverse_reasons = match reverse.completion() {
                ResolutionCompletion::Complete => {
                    panic!("the suppressed inherited SCC contributes exact terminal evidence")
                }
                ResolutionCompletion::Incomplete(reasons) => reasons,
            };
            assert_eq!(
                reverse_reasons
                    .iter()
                    .filter(|reason| matches!(
                        reason,
                        ResolutionIncompleteReason::CyclicExpansion(_)
                    ))
                    .count(),
                1,
                "reverse retains one SCC terminal, not one marker per member/path"
            );
            assert!(
                internal_gap_reasons
                    .iter()
                    .all(|reason| reverse_reasons.contains(reason)),
                "reverse retains both exact internal hierarchy-edge operands"
            );
            assert!(
                unrelated_gap_reasons
                    .iter()
                    .all(|reason| reverse_reasons.contains(reason)),
                "structural transfer of the A-B edges cannot consume the unrelated Use operand"
            );
            let inherited_implicit_reasons = fixture
                .lexical
                .gaps()
                .iter()
                .filter(|gap| {
                    gap.origin()
                        == LoweringGapOrigin::Extracted(
                            ResolutionGapKind::UnsupportedImplicitReceiver,
                        )
                        && inherited_oracle.transferred.contains_reason(
                            ResolutionIncompleteReason::UnsupportedSemantic(gap.reason_semantic()),
                        )
                })
                .map(|gap| ResolutionIncompleteReason::UnsupportedSemantic(gap.reason_semantic()))
                .collect::<BTreeSet<_>>();
            assert!(
                inherited_implicit_reasons.is_empty(),
                "an explicit, locally bound receiver has no implicit-receiver gap"
            );
            assert!(inherited_implicit_reasons.iter().all(|reason| {
                reverse_reasons
                    .iter()
                    .filter(|actual| *actual == reason)
                    .count()
                    == 1
            }));
            let expected_reverse = direct
                .completion()
                .combine(&inherited_oracle.transferred)
                .combine(&internal_completion)
                .combine(&unrelated_completion)
                .combine(&cycle_completion)
                .combine(&reverse_inventory_boundary_completion(&fixture));
            assert_eq!(
                cross_operation_completion(reverse.completion()),
                cross_operation_completion(&expected_reverse),
                "reverse publishes the direct answer plus the suppressed inherited qualifier, internal-edge, unrelated-inventory, and terminal operands"
            );
        }
        #[cfg(test)]
        #[test]
        fn route_free_java_hierarchy_inherits_nested_types_but_not_callables() {
            let nested_source = "public class Fixture { public static class Base { public static class X {} } public static class Leaf extends Base {} public static class Use extends Unindexed { public Object value = Leaf.X; } }";
            let nested = parsed_java_service_fixture(nested_source, b"route-free-nested-type");
            let nested_target = lowered_semantics_named(
                &nested.facts,
                &nested.lexical,
                "X",
                ResolutionIdentifierRole::Declaration,
            )[0];
            let nested_reference = lowered_semantics_named(
                &nested.facts,
                &nested.lexical,
                "X",
                ResolutionIdentifierRole::Reference,
            )[0];
            let nested_answer = nested
                .service
                .resolve_reference(nested_reference, &CancellationToken::new())
                .expect("preloaded hierarchy resolution is infallible");
            assert_eq!(nested_answer.binding().targets(), &[nested_target]);
            let nested_oracle = hierarchy_qualifier_completion_oracle(&nested, nested_reference);
            assert_hierarchy_success_transfers_qualifier_evidence(&nested_answer, &nested_oracle);
            let nested_reverse = nested
                .service
                .references_to(nested_target, &CancellationToken::new())
                .expect("preloaded nested-type reverse hierarchy resolution is infallible");
            assert_eq!(nested_reverse.references(), &[nested_reference]);

            let callable_source = "public class Fixture { public static class Base { public int x; public int m() { return 1; } } public static class Leaf extends Base {} public static class Use extends Unindexed { public int field(Leaf v) { return v.x; } public int call(Leaf v) { return v.m(); } } }";
            let callable =
                parsed_java_service_fixture(callable_source, b"route-free-callable-not-inherited");
            let field_target = lowered_semantics_named(
                &callable.facts,
                &callable.lexical,
                "x",
                ResolutionIdentifierRole::Declaration,
            )[0];
            let field_reference = lowered_semantics_named(
                &callable.facts,
                &callable.lexical,
                "x",
                ResolutionIdentifierRole::Reference,
            )[0];
            let callable_target = lowered_semantics_named(
                &callable.facts,
                &callable.lexical,
                "m",
                ResolutionIdentifierRole::Declaration,
            )[0];
            let callable_reference = lowered_semantics_named(
                &callable.facts,
                &callable.lexical,
                "m",
                ResolutionIdentifierRole::Reference,
            )[0];
            let leaf = lowered_semantics_named(
                &callable.facts,
                &callable.lexical,
                "Leaf",
                ResolutionIdentifierRole::Declaration,
            )[0];
            let leaf_hierarchy_reason = callable
                .typed
                .property_gaps()
                .iter()
                .find(|gap| {
                    gap.definition() == leaf
                        && gap.kind() == ResolutionGapKind::UnsupportedHierarchyTraversal
                })
                .map(|gap| ResolutionIncompleteReason::UnsupportedSemantic(gap.reason_semantic()))
                .expect("Leaf has one explicit hierarchy obligation");
            let cancellation = CancellationToken::new();
            let mut operation = FactResolutionOperation::new(
                &callable.service.source,
                &callable.service,
                &cancellation,
            );
            let field_answer = operation
                .resolve_reference(field_reference)
                .expect("preloaded field hierarchy resolution is infallible");
            assert_eq!(field_answer.binding().targets(), &[field_target]);
            let field_oracle = hierarchy_qualifier_completion_oracle(&callable, field_reference);
            assert_hierarchy_success_transfers_qualifier_evidence(&field_answer, &field_oracle);
            let field_reverse = callable
                .service
                .references_to(field_target, &CancellationToken::new())
                .expect("preloaded field reverse hierarchy resolution is infallible");
            assert_eq!(field_reverse.references(), &[field_reference]);

            let callable_answer = operation
                .resolve_reference(callable_reference)
                .expect("preloaded callable resolution is infallible");
            assert!(
                !callable_answer
                    .binding()
                    .targets()
                    .contains(&callable_target)
            );
            assert!(
                callable_answer
                    .completion()
                    .contains_reason(leaf_hierarchy_reason)
            );
            let mut callable_metrics = FactReverseResolutionMetrics::default();
            let callable_reverse = callable
                .service
                .references_to_with_metrics(
                    callable_target,
                    &CancellationToken::new(),
                    &mut callable_metrics,
                )
                .expect("non-inherited callable reverse resolution is infallible");
            assert!(!callable_reverse.references().contains(&callable_reference));
            assert!(
                callable_reverse
                    .completion()
                    .contains_reason(leaf_hierarchy_reason)
            );
            // A lexical source-coordinate match is only a candidate. Its full
            // binding evaluation retains the unsupported callable hierarchy;
            // a negative typed branch cannot suppress this independent route.
            assert_eq!(callable_metrics.issued_reference_seed_count(), 1);
            assert_eq!(callable_metrics.full_fact_evaluation_count(), 1);

            let constructor_source = "public class Fixture { public static class Base { public Base() {} } public static class Leaf extends Base {} public static class Use extends Unindexed { public Object make() { return new Leaf(); } } }";
            let constructor = parsed_java_service_fixture(
                constructor_source,
                b"route-free-constructor-not-inherited",
            );
            let base_constructor_site = positioned_site_at(
                &constructor.facts,
                constructor_source
                    .find("Base()")
                    .expect("the fixture declares Base()"),
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Constructor,
            );
            let base_constructor = lowered_semantic_at(
                &constructor.lexical,
                base_constructor_site,
                LoweredSemanticRole::Definition,
            );
            let leaf_constructor_site = positioned_site_at(
                &constructor.facts,
                constructor_source
                    .rfind("Leaf()")
                    .expect("the fixture constructs Leaf"),
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Constructor,
            );
            let leaf_construction = lowered_semantic_at(
                &constructor.lexical,
                leaf_constructor_site,
                LoweredSemanticRole::Reference,
            );
            let mut constructor_metrics = FactReverseResolutionMetrics::default();
            let constructor_reverse = constructor
                .service
                .references_to_with_metrics(
                    base_constructor,
                    &CancellationToken::new(),
                    &mut constructor_metrics,
                )
                .expect("a constructor reverse query is source-readable");
            assert!(
                !constructor_reverse
                    .references()
                    .contains(&leaf_construction),
                "constructing a descendant never inherits its base constructor"
            );
            assert_eq!(constructor_metrics.issued_reference_seed_count(), 0);
            assert_eq!(constructor_metrics.full_fact_evaluation_count(), 0);
        }

        #[cfg(test)]
        #[test]
        fn type_or_value_hierarchy_discharge_respects_route_precedence() {
            let source = "public class Fixture { public static class A { public static class x {} public static int x; } public static class Use extends Unindexed { public Object y = A.x; } }";
            let fixture =
                parsed_java_service_fixture(source, b"type-or-value-hierarchy-precedence");
            let reference = lowered_semantics_named(
                &fixture.facts,
                &fixture.lexical,
                "x",
                ResolutionIdentifierRole::Reference,
            )[0];
            let mut field = None;
            let mut nested_type = None;
            for definition in lowered_semantics_named(
                &fixture.facts,
                &fixture.lexical,
                "x",
                ResolutionIdentifierRole::Declaration,
            ) {
                let property = &fixture.service.typed.member_owners_by_definition[&definition][0];
                match property.kind() {
                    ResolutionMemberKind::Field => field = Some(definition),
                    ResolutionMemberKind::NestedType => nested_type = Some(definition),
                    other => panic!("unexpected same-name member kind {other:?}"),
                }
            }
            let field = field.expect("the fixture has one same-name field");
            let nested_type = nested_type.expect("the fixture has one same-name nested type");
            let route_ids = &fixture.service.typed.qualified_route_ids_by_reference[&reference];
            let mut routes = route_ids
                .iter()
                .map(|&route_id| fixture.service.typed.qualified_routes[route_id].row)
                .collect::<Vec<_>>();
            routes.sort_unstable_by_key(LoweredQualifiedSeededRoute::precedence_ordinal);
            assert_eq!(routes.len(), 2);
            assert_eq!(routes[0].namespace(), ResolutionNamespace::Value);
            assert_eq!(routes[0].precedence_ordinal(), 0);
            assert_eq!(routes[1].namespace(), ResolutionNamespace::Type);
            assert_eq!(routes[1].precedence_ordinal(), 1);
            let answer = fixture
                .service
                .resolve_reference(reference, &CancellationToken::new())
                .expect("preloaded route resolution is infallible");
            assert_eq!(answer.binding().targets(), &[field]);
            assert!(!answer.binding().targets().contains(&nested_type));
            let oracle = hierarchy_qualifier_completion_oracle(&fixture, reference);
            assert_hierarchy_success_transfers_qualifier_evidence(&answer, &oracle);
        }
    }
}
