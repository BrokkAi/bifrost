use super::*;
use crate::analyzer::Language;
use crate::analyzer::semantic::{SemanticRole, SourcePosition, SourceSpan};

#[test]
fn distinct_binding_ordinals_keep_distinct_checkout_independent_fingerprints() {
    let keys = |mount| {
        let locator = crate::test_support::function_locator(
            mount,
            "src/cell.py",
            Language::Python,
            SemanticRole::Value,
            "binding",
            SourceSpan::new(SourcePosition::new(4, 1, 0), SourcePosition::new(8, 1, 4)).unwrap(),
        );
        [None, Some(0), Some(1), Some(u32::MAX - 1), Some(u32::MAX)].map(|ordinal| {
            ValueFlowCarrierKey::LexicalCell {
                locator: locator.clone(),
                binding: DurableValueIdentity {
                    locator: locator.clone(),
                    role: "local".into(),
                    ordinal,
                },
            }
        })
    };
    let first = keys("first");
    let second = keys("second");
    for (index, key) in first.iter().enumerate() {
        assert_eq!(key.stable_fingerprint(), second[index].stable_fingerprint());
        for other in &first[index + 1..] {
            assert_ne!(key, other);
            assert_ne!(key.stable_fingerprint(), other.stable_fingerprint());
        }
    }
}
