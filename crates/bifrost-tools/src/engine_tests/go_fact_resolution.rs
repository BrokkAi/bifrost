#[cfg(test)]
mod tests {
    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredSemanticRole;
    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::go_failure_fixture_support::*;
    use brokk_bifrost_analysis::analyzer::resolution::{
        BatchResolutionFragmentSource, ResolutionCompletion, ResolutionIncompleteReason,
        ResolutionQuery,
    };
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionIdentifierRole, ResolutionNamespace,
    };
    use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;
    use brokk_bifrost_core::cancellation::CancellationToken;
    #[test]
    fn go_range_projection_uses_sequence_string_and_integer_rules() {
        let source = r#"package p

type Count int
type Text string
type Item struct{}
type itemStorage []Item
type Items itemStorage
type Mapping map[string]Item
type Feed chan Item

func use(count Count, text Text, items Items, mapping Mapping, feed Feed) {
	for integerIndex := range count { _ = integerIndex }
	for stringIndex, character := range text { _, _ = stringIndex, character }
	for sequenceIndex, element := range items { _, _ = sequenceIndex, element }
	for mapKey, mapValue := range mapping { _, _ = mapKey, mapValue }
	for channelValue := range feed { _ = channelValue }
}
"#;
        let fixture = parsed_go_service_fixture(source, b"go-range-universe-projections");
        let count_definition = lowered_semantic_at(
            &fixture.lexical,
            positioned_site_at(
                &fixture.facts,
                source.find("Count int").expect("Count declaration"),
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Type,
            ),
            LoweredSemanticRole::Definition,
        );
        let item_definition = lowered_semantic_at(
            &fixture.lexical,
            positioned_site_at(
                &fixture.facts,
                source.find("Item struct").expect("Item declaration"),
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Type,
            ),
            LoweredSemanticRole::Definition,
        );
        let int_reference = go_reference_at(
            &fixture,
            source.find("Count int").expect("Count underlying int") + "Count ".len(),
        );
        let cancellation = CancellationToken::new();
        let int_seed = BatchResolutionFragmentSource::reference_seed(
            &fixture.service,
            ResolutionQuery::new(int_reference),
            &cancellation,
        )
        .expect("Go type-name seed read succeeds")
        .expect("the predeclared int has a source seed");
        let int_spelling = BatchResolutionFragmentSource::universe_entry(
            &fixture.service,
            int_reference,
            ResolutionNamespace::Type,
            &cancellation,
        )
        .expect("Go type spelling read succeeds")
        .map(|entry| entry.spelling);
        let int_answer = fixture
            .service
            .resolve_reference(int_reference, &cancellation)
            .expect("predeclared int resolves without storage errors");
        assert_eq!(
            int_answer.binding().targets(),
            &[go_intrinsic_identity(ResolutionNamespace::Type, "int")],
            "the Count underlying type binds to Go's intrinsic int; seed={int_seed:?}, spelling={int_spelling:?}, gaps={:?}, answer={int_answer:?}",
            fixture.lexical.gaps()
        );
        assert_eq!(
            int_answer.binding().completion(),
            &ResolutionCompletion::Complete
        );
        for (spelling, expected) in [
            ("integerIndex", count_definition),
            (
                "stringIndex",
                go_intrinsic_identity(ResolutionNamespace::Type, "int"),
            ),
            (
                "character",
                go_intrinsic_identity(ResolutionNamespace::Type, "rune"),
            ),
            (
                "sequenceIndex",
                go_intrinsic_identity(ResolutionNamespace::Type, "int"),
            ),
            ("element", item_definition),
            (
                "mapKey",
                go_intrinsic_identity(ResolutionNamespace::Type, "string"),
            ),
            ("mapValue", item_definition),
            ("channelValue", item_definition),
        ] {
            let position = source
                .rmatch_indices(spelling)
                .next()
                .unwrap_or_else(|| panic!("missing Go range use {spelling}"))
                .0;
            assert_eq!(
                go_value_type_at(&fixture, position),
                expected,
                "range binder {spelling} has the Go spec type"
            );
        }
    }
    #[test]
    fn go_generic_interface_invocation_uses_receiver_actuals_for_applicability() {
        let source = r#"package p

type Loader[K comparable, V any] interface {
    Load(cache *Cache[K, V], key K) *Item[K, V]
}
type options[K comparable, V any] struct { loader Loader[K, V] }
type Item[K comparable, V any] struct{}
type Cache[K comparable, V any] struct{}
func applyOptions[K comparable, V any](value options[K, V]) options[K, V] { return value }
func use[K comparable, V any](getOpts options[K, V], cache *Cache[K, V], key K) *Item[K, V] {
    getOpts = applyOptions(getOpts)
    return getOpts.loader.Load(cache, key)
}
"#;
        let fixture = parsed_go_service_fixture(source, b"go-generic-interface-call-applicability");
        let load = go_callable_definition_at(
            &fixture,
            source
                .find("Load(cache")
                .expect("Loader.Load interface method"),
        )
        .1;
        let (answer, applicability_reason) = resolve_go_call_expression_at(
            &fixture,
            source
                .find("getOpts.loader.Load(cache, key)")
                .expect("generic interface method invocation"),
        );
        assert_eq!(answer.binding().targets(), &[load], "{answer:?}");
        let [candidate] = answer.callable_candidate_applicability() else {
            panic!("the selected Go method has one applicability assessment: {answer:?}");
        };
        assert_eq!(candidate.target(), load);
        assert_eq!(
            candidate.verdict(),
            ApplicabilityVerdict::Applicable,
            "receiver actuals substitute Loader's K,V into Load's parameters before positional mapping"
        );
        assert!(
            !answer.binding().completion().contains_reason(
                ResolutionIncompleteReason::UnsupportedSemantic(applicability_reason)
            ),
            "proven Go invocation applicability retires its call-local gap"
        );
    }
}
