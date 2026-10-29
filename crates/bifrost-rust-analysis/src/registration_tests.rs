//! Found-defect pins that require this binary's registered language rules.
mod fact_resolution {
    mod tests {

        use brokk_bifrost_analysis::{
            CancellationToken,
            analyzer::{
                lexical_definitions::resolve_lexical_binding_from_focus,
                resolution::{
                    fact_lowering::fixture_names::gap_reason_semantic,
                    fact_lowering::{LoweredSemanticRole, LoweringGapOrigin},
                    fact_resolution::fixture_support::*,
                    *,
                },
                test_support::first_named_kind,
            },
        };
        use brokk_bifrost_core::analyzer::{Language, resolution_facts::*};
        use brokk_bifrost_test_macros::hardwon;
        use tree_sitter::Parser;

        fn crate_receiver_outcome(
            analyzer: &crate::analyzer::rust::RustAnalyzer,
            source: &str,
            marker: &str,
        ) -> brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome
        {
            use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;
            use brokk_bifrost_core::analyzer::{
                model::Range,
                usages::{
                    receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
                    reference_site::ResolvedReferenceSite, resolution_session::BoundedResolution,
                },
            };
            let position = source.find(marker).expect("fixture call marker")
                + marker.rfind('.').expect("member marker")
                + 1;
            let line = source[..position]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                + 1;
            let site = ResolvedReferenceSite {
                path: marker.to_owned(),
                text: "run".to_owned(),
                range: Range {
                    start_byte: position,
                    end_byte: position + 3,
                    start_line: line,
                    end_line: line,
                },
                focus_start_byte: position,
                focus_end_byte: position + 3,
            };
            let file = crate::analyzer::rust::test_support::analyzed_file(analyzer, "src/lib.rs");
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            let BoundedResolution::Complete { value, .. } =
                crate::analyzer::rust::native_points::resolve_rust_definition_bounded(
                    BoundedReceiverQuery {
                        analyzer,
                        file: &file,
                        source,
                        tree: Some(&tree),
                        site: &site,
                        budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
                        cancellation: None,
                    },
                )
            else {
                panic!("fixture query must complete");
            };
            value
        }

        #[test]
        #[hardwon("955f6461cafc: a unit struct value is an instance of its struct")]
        fn a_unit_struct_value_is_an_instance_of_its_struct() {
            let fixture = parsed_rust_fixture(RUST_UNIT_VALUES, b"rust-unit-values");
            let side = definition_after(&fixture, "impl Square { pub fn side", "side");
            for marker in ["unit.side", "identity(Square).side"] {
                let answer = resolved(&fixture, marker, "side");
                assert_eq!(answer.binding().targets(), &[side], "{marker}: {answer:?}");
                assert_eq!(
                    answer.binding().completion(),
                    &ResolutionCompletion::Complete,
                    "{marker}: {answer:?}"
                );
            }
            let answer = resolved(&fixture, "constructor.side", "side");
            assert!(answer.binding().targets().is_empty(), "{answer:?}");
            assert!(
                matches!(
                    answer.binding().completion(),
                    ResolutionCompletion::Incomplete(_)
                ),
                "a tuple struct's constructor function is not an instance: {answer:?}"
            );

            let reverse = fixture
                .service
                .references_to(side, &CancellationToken::new())
                .unwrap();
            let mut expected = ["unit.side", "identity(Square).side"]
                .map(|marker| callable_reference_named_at(&fixture, marker, "side"));
            expected.sort_unstable();
            let mut references = reverse.references().to_vec();
            references.sort_unstable();
            assert_eq!(references, expected, "{reverse:?}");
            assert!(
                reverse
                    .witnesses()
                    .iter()
                    .all(|witness| witness.completion() == &ResolutionCompletion::Complete),
                "{reverse:?}"
            );
        }

        #[test]
        #[hardwon(
            "5526963ec2a3: reproduced function-only macro uncertainty required a sound mixed closed/open invocation control"
        )]
        fn a_closed_macro_does_not_hide_another_macro_member_frontier() {
            let source = r#"
pub struct Service;
impl Service { pub fn run(&self) {} }
macro_rules! closed { () => { pub fn generated() {} }; }
macro_rules! open { () => { pub fn other() {} impl Service { pub fn extra(&self) {} } }; }
closed!();
open!();
fn invoke(service: Service) { service.run(); }
"#;
            let fixture = parsed_rust_fixture(source, b"rust-mixed-macro-member-surfaces");
            let run = definition_after(&fixture, "impl Service", "run");
            let answer = resolved(&fixture, "service.run", "run");
            assert_eq!(answer.binding().targets(), &[run], "{answer:?}");
            let ResolutionCompletion::Incomplete(reasons) = answer.binding().completion() else {
                panic!("the other macro can still introduce members: {answer:?}");
            };
            assert_eq!(
                reasons.len(),
                1,
                "only the open macro affects members: {answer:?}"
            );
        }

        #[test]
        #[hardwon("#3828: recursive generic aliases escaped the structured type frontier")]
        fn generic_alias_cycle_stops_at_the_structured_type_frontier() {
            let source = r#"
pub struct Square;
pub type First<T> = Second<T>;
pub type Second<T> = First<T>;
fn caller(value: First<Square>) { value.missing(); }
"#;
            let fixture = parsed_rust_fixture(source, b"rust-generic-alias-cycle");
            let reference = callable_reference_named_at(&fixture, "value.missing()", "missing");
            let answer = fixture
                .service
                .resolve_reference(reference, &CancellationToken::new())
                .unwrap();
            assert!(answer.binding().targets().is_empty(), "{answer:?}");
            assert_incomplete(&answer);
        }

        /// A path's type segment writes its alias's arguments in the alias's order.
        /// Substitution follows both a parameter permutation and an alias-of-alias;
        /// nested target syntax retains the formal occurrence used by `second`.
        #[test]
        #[hardwon(
            "#3828: generic alias type arguments were not substituted through nested aliases"
        )]
        fn generic_alias_type_segments_substitute_concrete_and_nested_arguments() {
            let fixture =
                parsed_rust_fixture(RUST_ALIASED_TYPE_SEGMENTS, b"rust-aliased-type-segments");
            let square = definition_after(&fixture, "pub struct Square", "Square");
            let circle = definition_after(&fixture, "pub struct Circle", "Circle");
            for (marker, result, expected) in [
                (
                    "Pair::<Square, Circle>::first()",
                    call_result(&fixture, "Pair::<Square, Circle>::first()", "first"),
                    square,
                ),
                (
                    "Swap::<Square, Circle>::first()",
                    call_result(&fixture, "Swap::<Square, Circle>::first()", "first"),
                    circle,
                ),
                (
                    "Reversed::<Square, Circle>::first()",
                    call_result(&fixture, "Reversed::<Square, Circle>::first()", "first"),
                    circle,
                ),
                (
                    "Nested::<Square>::second()",
                    call_result(&fixture, "Nested::<Square>::second()", "second"),
                    square,
                ),
            ] {
                assert_eq!(
                    result.possible_values(),
                    &[ResolutionSlotValue::runtime(
                        ResolutionTypeRef::new(expected, 0),
                        false
                    )],
                    "{marker}: {result:?}"
                );
                assert_eq!(
                    result.completion(),
                    &ResolutionCompletion::Complete,
                    "{marker}: {result:?}"
                );
            }

            let side = definition_after(&fixture, "pub fn side", "side");
            let radius = definition_after(&fixture, "pub fn radius", "radius");
            for (marker, name, expected) in [
                ("Pair::<Square, Circle>::first().side", "side", side),
                ("Swap::<Square, Circle>::first().radius", "radius", radius),
                (
                    "Reversed::<Square, Circle>::first().radius",
                    "radius",
                    radius,
                ),
                ("Nested::<Square>::second().side", "side", side),
            ] {
                let answer = resolved(&fixture, marker, name);
                assert_eq!(
                    answer.binding().targets(),
                    &[expected],
                    "{marker}: {answer:?}"
                );
                assert_eq!(
                    answer.binding().completion(),
                    &ResolutionCompletion::Complete,
                    "{marker}: {answer:?}"
                );
            }

            for (target, expected_markers, name) in [
                (
                    side,
                    vec![
                        "Pair::<Square, Circle>::first().side",
                        "Nested::<Square>::second().side",
                    ],
                    "side",
                ),
                (
                    radius,
                    vec![
                        "Swap::<Square, Circle>::first().radius",
                        "Reversed::<Square, Circle>::first().radius",
                    ],
                    "radius",
                ),
            ] {
                let reverse = fixture
                    .service
                    .references_to(target, &CancellationToken::new())
                    .unwrap();
                let mut expected = expected_markers
                    .iter()
                    .map(|marker| callable_reference_named_at(&fixture, marker, name))
                    .collect::<Vec<_>>();
                expected.sort_unstable();
                let mut references = reverse.references().to_vec();
                references.sort_unstable();
                assert_eq!(references, expected, "{reverse:?}");
                assert_eq!(
                    reverse.completion(),
                    &ResolutionCompletion::Complete,
                    "{reverse:?}"
                );
                assert!(
                    reverse
                        .witnesses()
                        .iter()
                        .all(|witness| witness.completion() == &ResolutionCompletion::Complete),
                    "{reverse:?}"
                );
            }
        }

        #[test]
        #[hardwon("#3828: nested generic aliases failed to substitute member call targets")]
        fn generic_alias_nested_generic_target_substitutes_for_member_calls() {
            let source = r#"
pub struct Square;
impl Square { pub fn side(&self) {} }
pub struct Circle;
impl Circle { pub fn radius(&self) {} }
pub struct Pair<A, B>(A, B);
impl<A, B> Pair<A, B> { pub fn first() -> A { loop {} } }
pub type Swap<X, Y> = Pair<Y, X>;
pub type Reversed<X, Y> = Swap<X, Y>;
pub struct Wrapper<T>(pub T);
impl<T> Wrapper<Vec<T>> { pub fn only_nested(&self) {} }
pub type Nested<X> = Wrapper<Vec<X>>;
fn caller() {
    Reversed::<Square, Circle>::first().radius();
    let value: Nested<Square> = Wrapper(Vec::new());
    value.only_nested();
}
"#;
            let fixture = parsed_rust_fixture(source, b"rust-generic-alias-substitution");
            let radius = definition_after(&fixture, "impl Circle", "radius");
            let radius_reference = callable_reference_named_at(
                &fixture,
                "Reversed::<Square, Circle>::first().radius()",
                "radius",
            );
            let radius_answer = fixture
                .service
                .resolve_reference(radius_reference, &CancellationToken::new())
                .unwrap();
            assert_eq!(
                radius_answer.binding().targets(),
                &[radius],
                "{radius_answer:?}"
            );
            assert_eq!(
                radius_answer.binding().completion(),
                &ResolutionCompletion::Complete,
                "{radius_answer:?}"
            );

            let nested = definition_after(&fixture, "impl<T> Wrapper<Vec<T>>", "only_nested");
            let nested_reference =
                callable_reference_named_at(&fixture, "value.only_nested()", "only_nested");
            let nested_answer = fixture
                .service
                .resolve_reference(nested_reference, &CancellationToken::new())
                .unwrap();
            assert_eq!(
                nested_answer.binding().targets(),
                &[nested],
                "{nested_answer:?}"
            );
            let reverse = fixture
                .service
                .references_to(nested, &CancellationToken::new())
                .unwrap();
            assert!(
                reverse.references().contains(&nested_reference),
                "{reverse:?}"
            );
        }

        #[test]
        #[hardwon("ed722fa56803: impl or nested item macro expansions falsely closed type members")]
        fn item_macros_with_impl_or_nested_expansion_keep_type_members_open() {
            for expansion in [
                "pub fn generated() {} impl Service { pub fn run(&self) {} }",
                "pub fn generated() { unknown!(); }",
                "#[unknown_attribute] pub fn generated() {}",
                "pub fn generated() { impl Service { pub fn run(&self) {} } }",
                "pub mod more;",
                "use elsewhere::Extension;",
            ] {
                let source = format!(
                    "pub struct Service;\n\
             impl Service {{ pub fn run(&self) {{}} }}\n\
             macro_rules! maker {{ () => {{ {expansion} }}; }}\n\
             maker!();\n\
             fn invoke(service: Service) {{ service.run(); }}"
                );
                let fixture = parsed_rust_fixture(&source, b"rust-open-macro-members");
                let run = definition_after(&fixture, "impl Service", "run");
                let answer = resolved(&fixture, "service.run", "run");
                assert_eq!(
                    answer.binding().targets(),
                    &[run],
                    "{expansion}: {answer:?}"
                );
                assert_incomplete(&answer);
            }
        }

        #[test]
        #[hardwon(
            "985c255966c6: recorded generic calls returned their bound instead of the instantiated argument type; reverse flow must follow the repaired instantiation"
        )]
        fn instantiated_generic_results_keep_the_reverse_in_step() {
            let fixture =
                parsed_rust_fixture(RUST_BOUNDED_GENERICS, b"rust-generic-instantiation-reverse");
            let sorted = |markers: &[(&str, &str)]| {
                let mut references = markers
                    .iter()
                    .map(|(marker, name)| callable_reference_named_at(&fixture, marker, name))
                    .collect::<Vec<_>>();
                references.sort_unstable();
                references
            };
            let references = |target: SemanticId| {
                let reverse = fixture
                    .service
                    .references_to(target, &CancellationToken::new())
                    .unwrap();
                let mut references = reverse.references().to_vec();
                references.sort_unstable();
                (references, reverse)
            };

            let (found, reverse) = references(definition_after(&fixture, "pub fn side", "side"));
            assert_eq!(
                found,
                sorted(&[
                    ("picked.side", "side"),
                    ("copied.side", "side"),
                    ("value.side", "side")
                ]),
                "{reverse:?}"
            );
            let unproven = callable_reference_named_at(&fixture, "value.side", "side");
            for witness in reverse.witnesses() {
                assert_eq!(
                    witness.completion() == &ResolutionCompletion::Complete,
                    witness.reference() != unproven,
                    "{reverse:?}"
                );
            }

            let (found, reverse) = references(definition_after(&fixture, "pub fn name", "name"));
            assert_eq!(
                found,
                sorted(&[
                    ("picked.name", "name"),
                    ("make::<Square>().name", "name"),
                    ("square.name", "name"),
                    ("Square::name(&square)", "name"),
                ]),
                "{reverse:?}"
            );
            assert!(
                reverse
                    .witnesses()
                    .iter()
                    .all(|witness| witness.completion() == &ResolutionCompletion::Complete),
                "every inherent `name` call is proven: {reverse:?}"
            );

            let (found, reverse) = references(definition_after(
                &fixture,
                "fn name(&self) -> u8; }",
                "name",
            ));
            assert_eq!(
                found,
                sorted(&[("make::<U>().name", "name")]),
                "{reverse:?}"
            );
            assert!(
                reverse
                    .witnesses()
                    .iter()
                    .all(|witness| witness.completion() == &ResolutionCompletion::Complete),
                "{reverse:?}"
            );
        }

        #[test]
        #[hardwon("7a00192bb238: a generic call result was treated as an exact type parameter")]
        fn a_generic_call_result_is_not_an_exact_type_parameter() {
            for (source, marker) in [
                (
                    "pub fn generic<T>(value: T) -> T { value }\npub fn caller() { generic(1); }\n",
                    "generic(1)",
                ),
                (
                    "pub fn generic<T>() -> T { loop {} }\npub fn caller() { generic(); }\n",
                    "generic()",
                ),
            ] {
                let fixture = parsed_rust_fixture(source, b"rust-generic-call-result");
                let reference = callable_reference_named_at(&fixture, marker, "generic");
                let obligation = fixture
                    .typed
                    .call_obligations()
                    .iter()
                    .find(|obligation| obligation.callee_reference() == reference)
                    .expect("Rust call applicability obligation");
                let answer = fixture
                    .service
                    .resolve_reference(reference, &CancellationToken::new())
                    .expect("Rust generic call evaluation succeeds");
                let result = answer
                    .projected_frontiers()
                    .iter()
                    .find(|frontier| frontier.slot() == obligation.result_slot())
                    .expect("Rust call result frontier");
                // The type parameter names why: its type is inferred.
                let parameter = fixture
                    .facts
                    .gaps
                    .iter()
                    .find(|gap| gap.kind == ResolutionGapKind::InferredType)
                    .expect("the unbounded type parameter's inferred-type gap")
                    .site;
                let inferred = gap_reason_semantic(
                    fixture.typed.fragment(),
                    parameter,
                    LoweringGapOrigin::Extracted(ResolutionGapKind::InferredType),
                );
                assert!(
                    result.possible_values().is_empty()
                        && result.completion().contains_reason(
                            ResolutionIncompleteReason::UnsupportedSemantic(inferred)
                        ),
                    "{marker}: the result is not an exact type: {result:?}"
                );
                assert_eq!(
                    answer.binding().completion(),
                    &ResolutionCompletion::Complete,
                    "{marker}: the callee still binds exactly: {answer:?}"
                );
            }
        }

        /// An impl item of a trait the rows cannot name (`Display` here names nothing
        /// in the fixture) answers alone and complete when the receiver's nameable
        /// traits are enumerated and none supplies the method. When the rows cannot
        /// place the receiver's traits, another trait could supply it too (E0034), so
        /// the item stays the target and the answer says why it is not complete.
        #[test]
        #[hardwon(
            "21a0f8b34f4a: recorded receiver selected one external-trait impl Complete while rustc reported E0034 with an in-scope competing trait"
        )]
        fn an_unnameable_trait_item_is_complete_only_where_the_nameable_traits_are_enumerated() {
            let fixture =
                parsed_rust_fixture(RUST_UNNAMEABLE_TRAIT_ITEM, b"rust-unnameable-trait-item");
            let fmt = definition_after(&fixture, "impl Display for Service { fn fmt", "fmt");
            let answer = resolved(&fixture, "service.fmt", "fmt");
            assert_eq!(answer.binding().targets(), &[fmt], "{answer:?}");
            assert_eq!(
                answer.binding().completion(),
                &ResolutionCompletion::Complete,
                "{answer:?}"
            );

            let mut fixture = parsed_rust_fixture(
                RUST_UNNAMEABLE_TRAIT_ITEM,
                b"rust-unnameable-trait-item-unplaced",
            );
            fixture.service.rust_implemented_traits_unplaced = true;
            let fmt = definition_after(&fixture, "impl Display for Service { fn fmt", "fmt");
            let answer = resolved(&fixture, "service.fmt", "fmt");
            assert_eq!(answer.binding().targets(), &[fmt], "{answer:?}");
            assert!(
                matches!(
                    answer.binding().completion(),
                    ResolutionCompletion::Incomplete(_)
                ),
                "{answer:?}"
            );
        }

        #[cfg(test)]
        #[brokk_bifrost_test_macros::hardwon(
            "5d885dfd460b: Rust Self tuple construction must resolve the enclosing type before reverse lookup"
        )]
        #[test]
        fn self_tuple_constructor_matches_explicit_type_and_reverse_lookup() {
            let source = "pub struct Record(pub u32); impl Record { fn new() -> Self { Self(1) } fn explicit() -> Self { Record(1) } }";
            let fixture = parsed_rust_fixture(source, b"self-tuple-constructor");
            let definition = definition_after(&fixture, "pub struct", "Record");
            let implicit = callable_reference_named_at(&fixture, "Self(1)", "Self");
            let explicit = callable_reference_named_at(&fixture, "Record(1)", "Record");
            let mut result_values = Vec::new();
            for reference in [implicit, explicit] {
                let answer = fixture
                    .service
                    .resolve_reference(reference, &CancellationToken::new())
                    .unwrap();
                assert_eq!(answer.binding().targets(), &[definition], "{answer:?}");
                assert_eq!(
                    answer.binding().completion(),
                    &ResolutionCompletion::Complete,
                    "{answer:?}"
                );
                let projection = answer
                    .projections()
                    .iter()
                    .find(|projection| projection.kind().is_callable_result())
                    .unwrap();
                let result = answer
                    .projected_frontiers()
                    .iter()
                    .find(|frontier| frontier.slot() == projection.output_slot())
                    .unwrap();
                // Tuple-call result inference is already incomplete for the
                // explicit Record spelling. Self must preserve that honest
                // result uncertainty while resolving the same declaration.
                assert!(matches!(
                    result.completion(),
                    ResolutionCompletion::Incomplete(_)
                ));
                result_values.push(result.possible_values().to_vec());
                assert_experimental_call_matches_eager(&fixture.service, reference);
            }
            assert_eq!(result_values[0], result_values[1]);
            let reverse = fixture
                .service
                .references_to(definition, &CancellationToken::new())
                .unwrap();
            assert!(reverse.references().contains(&implicit), "{reverse:?}");
            assert!(reverse.references().contains(&explicit), "{reverse:?}");
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            let answer = fixture
                .service
                .resolve_reference(implicit, &cancelled)
                .unwrap();
            assert!(
                answer
                    .completion()
                    .contains_reason(ResolutionIncompleteReason::Cancelled)
            );
        }

        #[test]
        #[hardwon("985c255966c6: a same-form trait method outranked the matching inherent method")]
        fn an_inherent_method_outranks_a_same_form_trait_method() {
            let fixture = parsed_rust_fixture(RUST_BOUNDED_GENERICS, b"rust-inherent-precedence");
            let inherent_name = definition_after(&fixture, "pub fn name", "name");
            for marker in ["square.name", "Square::name(&square)"] {
                let answer = resolved(&fixture, marker, "name");
                assert_eq!(
                    answer.binding().targets(),
                    &[inherent_name],
                    "{marker}: {answer:?}"
                );
                assert_eq!(
                    answer.binding().completion(),
                    &ResolutionCompletion::Complete,
                    "{marker}: {answer:?}"
                );
            }
            let mut takes = [
                definition_after(&fixture, "impl Consume for Square { fn take", "take"),
                definition_after(&fixture, "impl Square { pub fn take", "take"),
            ];
            takes.sort_unstable();
            let answer = resolved(&fixture, "square.take", "take");
            assert_eq!(answer.binding().targets(), takes.as_slice(), "{answer:?}");
        }

        #[test]
        #[hardwon(
            "4b818a2d36c1: Rust unwrap transfers failed to retain the payload for member resolution"
        )]
        fn parsed_rust_unwrapped_initializers_reach_the_payload_and_wrapped_ones_do_not() {
            let source = r#"
use std::result::Result;
use std::option::Option;
pub struct Service;
pub struct Failure;

impl Service {
    pub fn run(&self) {}
}

pub fn make() -> Result<Service, Failure> { loop {} }

fn use_expect() {
    let expected = make().expect("service");
    expected.run();
}

fn use_try() {
    let tried = make()?;
    tried.run();
}

fn use_option(opt: Option<Service>) {
    let taken = opt.unwrap();
    taken.run();
}

fn use_wrapped() {
    let wrapped = make();
    wrapped.run();
}
"#;
            let (_project, analyzer) = crate::analyzer::rust::test_support::project(&[
                (
                    "Cargo.toml",
                    "[package]\nname=\"payload_fixture\"\nversion=\"0.1.0\"\nedition=\"2024\"\n",
                ),
                ("src/lib.rs", source),
            ]);
            use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;
            use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
            let run = analyzer.get_definitions("payload_fixture.Service.run");
            assert_eq!(run.len(), 1, "the fixture has one payload member");
            for marker in ["expected.run", "tried.run", "taken.run"] {
                let answer = crate_receiver_outcome(&analyzer, source, marker);
                assert_eq!(answer.definitions, run, "{marker}: {answer:?}");
                assert_eq!(
                    answer.status,
                    DefinitionLookupStatus::Resolved,
                    "{marker}: {answer:?}"
                );
            }
            let wrapped = crate_receiver_outcome(&analyzer, source, "wrapped.run");
            assert!(wrapped.definitions.is_empty(), "{wrapped:?}");
            assert_ne!(
                wrapped.status,
                DefinitionLookupStatus::Resolved,
                "{wrapped:?}"
            );
        }

        #[test]
        #[hardwon("#3746: generic type alias member calls lost their declaration owner")]
        fn parsed_rust_generic_type_alias_preserves_associated_member_owner() {
            let source = r#"
enum EitherWriter<A, B> { A(A), B(B) }
type OptionalWriter<T> = EitherWriter<T, ()>;
impl<T> OptionalWriter<T> {
    fn some(value: T) -> Self { EitherWriter::A(value) }
}
fn make() { let _ = OptionalWriter::some(1usize); }
"#;
            let fixture = parsed_rust_fixture(source, b"rust-generic-alias-member-owner");
            let expected = definition_after(&fixture, "impl<T> OptionalWriter<T>", "some");
            let reference = callable_reference_named_at(&fixture, "OptionalWriter::some", "some");
            let answer = fixture
                .service
                .resolve_reference(reference, &CancellationToken::new())
                .unwrap();

            assert_eq!(answer.binding().targets(), &[expected], "{answer:?}");
        }

        #[test]
        #[hardwon("ed722fa56803: a function-only item macro opened existing type members")]
        fn a_function_only_item_macro_does_not_open_existing_type_members() {
            let source = r#"
pub trait Runner { type Output; }
pub struct Service;
impl Runner for Service { type Output = u8; }
impl Service { pub fn run(&self) {} }
macro_rules! maker { ($name:ident) => { pub fn $name() -> u8 { 0 } }; }
maker!(generated);
fn invoke(service: Service) { service.run(); }
type Selected = <Service as Runner>::Output;
fn unknown() { generated(); }
"#;
            let fixture = parsed_rust_fixture(source, b"rust-function-only-macro-members");
            let run = definition_after(&fixture, "impl Service", "run");
            let answer = resolved(&fixture, "service.run", "run");
            assert_eq!(answer.binding().targets(), &[run], "{answer:?}");
            assert_eq!(
                answer.binding().completion(),
                &ResolutionCompletion::Complete,
                "{answer:?}"
            );

            let expected = definition_after(&fixture, "impl Runner for Service", "Output");
            let marker = "<Service as Runner>::Output";
            let position = source.find(marker).unwrap() + marker.rfind("Output").unwrap();
            let identifier = fixture
                .facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && fixture.facts.sites[identifier.site.index()].start_byte == position
                })
                .expect("associated type reference");
            let reference = lowered_semantic_at(
                &fixture.lexical,
                identifier.site,
                LoweredSemanticRole::Reference,
            );
            let answer = fixture
                .service
                .resolve_reference(reference, &CancellationToken::new())
                .unwrap();
            assert_eq!(answer.binding().targets(), &[expected], "{answer:?}");
            assert_eq!(
                answer.binding().completion(),
                &ResolutionCompletion::Complete,
                "{answer:?}"
            );

            // The generated declaration is still outside declaration replay. Its
            // unresolved lexical lookup must retain the original macro frontier.
            let answer = resolved(&fixture, "generated();", "generated");
            assert!(answer.binding().targets().is_empty(), "{answer:?}");
            assert_incomplete(&answer);
        }

        #[test]
        #[hardwon("#3828: smart pointer member references lost complete receiver resolution")]
        fn parsed_rust_owning_smart_pointer_receivers_reach_their_payload_members() {
            let source = r#"
use std::boxed::Box;
use std::sync::Arc;
use std::rc::Rc;
pub struct Service;

impl Service {
    pub fn run(&self) {}
}

fn use_boxed(boxed: Box<Service>) {
    boxed.run();
}

fn use_shared(shared: Arc<Service>) {
    shared.run();
}

fn use_counted(counted: Rc<Service>) {
    counted.run();
}

fn use_opaque(opaque: Wrapper<Service>) {
    opaque.run();
}

fn use_plain(plain: Wrapper) {
    plain.run();
}
"#;
            let (_project, analyzer) = crate::analyzer::rust::test_support::project(&[
                (
                    "Cargo.toml",
                    "[package]\nname=\"pointer_fixture\"\nversion=\"0.1.0\"\nedition=\"2024\"\n",
                ),
                ("src/lib.rs", source),
            ]);
            use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;
            use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
            let run = analyzer.get_definitions("pointer_fixture.Service.run");
            assert_eq!(run.len(), 1, "the fixture has one payload member");
            for marker in ["boxed.run", "shared.run", "counted.run"] {
                let answer = crate_receiver_outcome(&analyzer, source, marker);
                assert_eq!(answer.definitions, run, "{marker}: {answer:?}");
                assert_eq!(
                    answer.status,
                    DefinitionLookupStatus::Resolved,
                    "{marker}: {answer:?}"
                );
            }
            let opaque = crate_receiver_outcome(&analyzer, source, "opaque.run");
            let plain = crate_receiver_outcome(&analyzer, source, "plain.run");
            assert!(opaque.definitions.is_empty(), "{opaque:?}");
            assert!(plain.definitions.is_empty(), "{plain:?}");
            assert_eq!(
                opaque.status, plain.status,
                "opaque={opaque:?} plain={plain:?}"
            );
        }

        #[test]
        #[hardwon(
            "4be28bcdec18: the commit explicitly unpins the sibling Self regression by projecting a generic impl through its nominal owner"
        )]
        fn parsed_rust_generic_impl_self_reaches_sibling_nominal_member() {
            let fixture = parsed_rust_fixture(
                r#"
pub struct Wrapper<T> { value: T }
impl<T> Wrapper<T> { pub fn first(&self) { self.second(); } }
impl<T> Wrapper<T> { pub fn second(&self) {} }
"#,
                b"rust-generic-impl-self",
            );
            let reference = callable_reference_named_at(&fixture, "self.second", "second");
            let definition = definition_after(&fixture, "pub fn second", "second");
            let answer = fixture
                .service
                .resolve_reference(reference, &CancellationToken::new())
                .unwrap();
            assert_eq!(answer.binding().targets(), &[definition], "{answer:?}");
            assert_eq!(
                answer.binding().completion(),
                &ResolutionCompletion::Complete,
                "{answer:?}"
            );
            let reverse = fixture
                .service
                .references_to(definition, &CancellationToken::new())
                .unwrap();
            assert_eq!(reverse.references(), &[reference], "{reverse:?}");
            assert_eq!(
                reverse.completion(),
                &ResolutionCompletion::Complete,
                "{reverse:?}"
            );
        }

        #[test]
        #[hardwon(
            "eb9926938572: a let tuple-struct pattern bound its constructor, so the shared resolver found Some inside a closure"
        )]
        fn a_tuple_struct_pattern_constructor_is_not_a_binding() {
            let source = concat!(
                "fn f(o: Option<i32>) {\n",
                "    let Some(_x) = o;\n",
                "    let c = || Some(1);\n",
                "    c();\n",
                "}\n",
            );
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .expect("load Rust grammar");
            let tree = parser.parse(source, None).expect("parse Rust source");
            let closure = first_named_kind(tree.root_node(), "closure_expression");
            let some = crate::analyzer::test_support::first_named_node_matching_reverse_preorder(
                closure,
                |node| node.kind() == "identifier" && source.get(node.byte_range()) == Some("Some"),
            )
            .expect("closure names Some");
            let resolution = resolve_lexical_binding_from_focus(
                Language::Rust,
                some,
                source,
                some.start_byte(),
                "Some",
            );
            assert!(resolution.is_none(), "Some is not a local binding");
        }
        #[test]
        fn parsed_rust_ambiguous_bound_head_is_not_a_proven_union() {
            let fixture = parsed_rust_fixture(
                r#"
pub trait Store { fn get(&self); }
pub trait Store { fn get(&self); }
fn ambiguous<T: Store>(value: &T) { value.get(); }
"#,
                b"rust-ambiguous-bound",
            );
            let reference = callable_reference_named_at(&fixture, "value.get", "get");
            let answer = fixture
                .service
                .resolve_reference(reference, &CancellationToken::new())
                .unwrap();
            assert_eq!(answer.binding().targets().len(), 2, "{answer:?}");
            assert!(
                !answer.type_bound_receiver,
                "ambiguous lexical alternatives are not independent bounds"
            );
        }

        #[test]
        fn parsed_rust_private_member_keeps_visibility_uncertainty() {
            let source = r#"
pub struct Service;

impl Service {
    fn hidden(&self) {}
}

fn use_service(service: Service) {
    service.hidden();
}
"#;
            let fixture = parsed_rust_fixture(source, b"rust-inherent-private");
            let reference = callable_reference_named_at(&fixture, "service.hidden", "hidden");
            let target = definition_after(&fixture, "impl Service", "hidden");
            let answer = fixture
                .service
                .resolve_reference(reference, &CancellationToken::new())
                .expect("Rust private inherent member evaluation succeeds");
            assert!(answer.binding().targets().contains(&target));
            assert_incomplete(&answer);
        }
        #[test]
        fn parsed_rust_self_receiver_keeps_owner_frontier_and_current_instance_origin() {
            let source = r#"
pub struct Service;

impl Service {
    pub fn target(&self) {}
    pub fn caller(&self) { self.target(); }
}
"#;
            let fixture = parsed_rust_fixture(source, b"rust-inherent-self-receiver");
            let reference = callable_reference_named_at(&fixture, "self.target", "target");
            let reference_site = fixture
                .facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && identifier.namespace == ResolutionNamespace::Callable
                        && fixture.facts.sites[identifier.site.index()].start_byte
                            == fixture.source.find("self.target").unwrap() + 5
                })
                .expect("self target callable reference");
            assert_eq!(
                fixture.facts.sites[reference_site.site.index()].kind,
                ResolutionSiteKind::MemberReference
            );
            assert_eq!(
                fixture
                    .facts
                    .callable_receiver_origins
                    .iter()
                    .find(|origin| origin.reference == reference_site.site)
                    .map(|origin| origin.origin),
                Some(ResolutionCallableReceiverOrigin::CurrentInstance)
            );
            let self_declarations = fixture
                .facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && identifier.namespace == ResolutionNamespace::Value
                        && fixture.facts.names[identifier.name.index()].spelling == "self"
                })
                .collect::<Vec<_>>();
            assert_eq!(self_declarations.len(), 2);
            for declaration in self_declarations {
                assert!(fixture.facts.binders.iter().any(|binder| {
                    binder.declaration == declaration.site
                        && binder.kind == ResolutionBinderKind::Parameter
                }));
                assert!(fixture.facts.declaration_type_slots.iter().any(|property| {
                    property.declaration == declaration.site
                        && property.role == DeclarationTypeRole::Parameter
                }));
            }

            let qualifier = reference_site
                .qualifier
                .expect("self member callable retains a receiver qualifier");
            let owner_type = fixture
                .facts
                .declared_type_relations
                .iter()
                .find(|relation| {
                    relation.kind == ResolutionDeclaredTypeRelationKind::InherentImplementation
                })
                .map(|relation| relation.subject)
                .expect("inherent impl owner frontier");
            let nominal = fixture
                .facts
                .binding_projections
                .iter()
                .find(|projection| {
                    projection.output == owner_type
                        && projection.kind == BindingProjectionKind::TargetNominalTypeIdentity
                })
                .expect("impl owner uses the nominal output");
            let receiver_type = fixture
                .facts
                .binding_projections
                .iter()
                .find(|projection| {
                    projection.reference == nominal.reference
                        && projection.kind == BindingProjectionKind::TargetTypeIdentity
                })
                .expect("impl receiver uses the paired payload output")
                .output;
            assert_ne!(owner_type, receiver_type);
            assert!(fixture.facts.type_transfers.iter().any(|transfer| {
                transfer.input == receiver_type
                    && transfer.output == qualifier
                    && transfer.kind == ResolutionTypeTransferKind::Receiver
                    && transfer.indirection_delta == 0
                    && transfer.value_transform
                        == ResolutionTypeTransferValueTransform::ToRuntime { addressable: false }
            }));
            let target = definition_after(&fixture, "pub fn target", "target");
            let forward = fixture
                .service
                .resolve_reference(reference, &CancellationToken::new())
                .expect("self member forward evaluation");
            assert_eq!(forward.binding().targets(), &[target]);
            assert_eq!(
                forward.binding().completion(),
                &ResolutionCompletion::Complete
            );
            let reverse = fixture
                .service
                .references_to_many(&[target], &CancellationToken::new())
                .expect("self member reverse evaluation");
            let bindings = reverse.answers()[0].bindings();
            assert_eq!(bindings.len(), 1);
            assert_eq!(bindings[0].reference(), reference);
            assert_eq!(bindings[0].definitions(), &[target]);
            assert_eq!(bindings[0].completion(), &ResolutionCompletion::Complete);
        }

        #[test]
        fn parsed_rust_associated_types_follow_the_impl_owner() {
            let source = r#"
pub trait Runner { type Output; }
pub struct Service;
pub struct Payload;
impl Payload { pub fn run(&self) {} }
impl Runner for Service {
    type Output = Payload;
    fn own(value: Self::Output) { value.run(); }
}
type Selected = <Service as Runner>::Output;
fn invoke(value: Selected) { value.run(); }
"#;
            let fixture = parsed_rust_fixture(source, b"rust-associated-type-owner");
            let expected = definition_after(&fixture, "impl Runner for Service", "Output");
            for marker in ["Self::Output", "<Service as Runner>::Output"] {
                let position = source.find(marker).unwrap() + marker.rfind("Output").unwrap();
                let identifier = fixture
                    .facts
                    .identifiers
                    .iter()
                    .find(|identifier| {
                        identifier.role == ResolutionIdentifierRole::Reference
                            && fixture.facts.sites[identifier.site.index()].start_byte == position
                    })
                    .expect("associated type reference");
                let reference = lowered_semantic_at(
                    &fixture.lexical,
                    identifier.site,
                    LoweredSemanticRole::Reference,
                );
                let answer = fixture
                    .service
                    .resolve_reference(reference, &CancellationToken::new())
                    .unwrap();
                assert_eq!(
                    answer.binding().targets(),
                    &[expected],
                    "{marker}: {answer:?}"
                );
                assert_eq!(
                    answer.binding().completion(),
                    &ResolutionCompletion::Complete,
                    "{marker}: {answer:?}"
                );
            }
            let method = definition_after(&fixture, "impl Payload", "run");
            let calls = fixture
                .facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && fixture.facts.names[identifier.name.index()].spelling == "run"
                })
                .map(|identifier| {
                    lowered_semantic_at(
                        &fixture.lexical,
                        identifier.site,
                        LoweredSemanticRole::Reference,
                    )
                });
            for reference in calls {
                let answer = fixture
                    .service
                    .resolve_reference(reference, &CancellationToken::new())
                    .unwrap();
                assert_eq!(answer.binding().targets(), &[method], "{answer:?}");
            }
            let contract = definition_after(&fixture, "pub trait Runner", "Output");
            let reverse = fixture
                .service
                .references_to(contract, &CancellationToken::new())
                .unwrap();
            assert_eq!(reverse.references().len(), 2, "{reverse:?}");
        }
    }
}
