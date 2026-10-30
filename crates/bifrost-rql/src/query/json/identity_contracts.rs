use super::*;

#[test]
fn occurrence_identity_retains_independent_scope_axes() {
    let inputs = [
        json!({"where": ["src/a.rs"], "occurrences": {"class": ["reference"]}}),
        json!({"where": ["src/b.rs"], "occurrences": {"class": ["reference"]}}),
        json!({"where": ["src/a.rs"], "occurrences": {"class": ["declaration"]}}),
        json!({"where": ["src/a.rs"], "languages": ["rust"], "occurrences": {"class": ["reference"]}}),
    ];
    let keys: Vec<_> = inputs
        .iter()
        .map(|input| {
            let query = CodeQuery::from_json(input).unwrap();
            let CodeQueryPlanSource::Occurrences(seed) = query.plan.source else {
                panic!("expected occurrence seed");
            };
            seed.canonical_cache_key()
        })
        .collect();
    for (index, key) in keys.iter().enumerate() {
        assert!(!keys[..index].contains(key), "{keys:?}");
    }
}
