//! The structural vocabulary a language spec is written against.
//!
//! `kinds` is the normalized kind/role registry; `occurrences`, `resolution`,
//! `edges`, `routes` and `materialization` the identifier-role,
//! lexical-resolution, reference-edge, identity-route and
//! declaration-materialization vocabularies; `spec` the trait each language
//! implements to normalize its grammar; `facts` the two values a spec
//! produces; `code` the integer-code mapping every vocabulary carries; and
//! `adapter_helpers` the small node-arithmetic mechanics every adapter uses to
//! write one. The extraction engine, matcher, planner and RQL
//! query layer that consume them stay in `brokk-bifrost-analysis`.

pub(super) fn support_is_empty(supports: impl IntoIterator<Item = bool>) -> bool {
    supports.into_iter().all(|supported| !supported)
}

pub(super) fn support_iter<'a, Axis: Copy + 'a, Support: 'a>(
    axes: &'a [Axis],
    support: impl Fn(Axis) -> Support + 'a,
) -> impl ExactSizeIterator<Item = (Axis, Support)> + 'a {
    axes.iter().copied().map(move |axis| (axis, support(axis)))
}

#[cfg(test)]
macro_rules! assert_vocabulary_round_trip {
    ($all:expr, $type:ty) => {{
        let mut labels = ::std::collections::HashSet::new();
        for &value in $all {
            assert!(labels.insert(value.label()), "duplicate label {value:?}");
            assert_eq!(<$type>::from_label(value.label()), Some(value));
            let json = ::serde_json::to_value(value).expect("serialize");
            assert_eq!(
                json,
                ::serde_json::Value::String(value.label().to_owned()),
                "serde label diverges from label() for {value:?}"
            );
            let back: $type = ::serde_json::from_value(json).expect("deserialize");
            assert_eq!(back, value);
        }
        assert_eq!(labels.len(), $all.len());
    }};
}

#[cfg(test)]
pub(crate) use assert_vocabulary_round_trip;

pub mod adapter_helpers;
pub mod body_relations;
pub mod callable;
pub mod code;
pub mod collector;
pub mod control_relation;
pub mod edges;
pub mod facts;
pub mod flow_state;
pub mod kinds;
pub mod materialization;
pub mod native_obligation;
pub mod occurrences;
pub mod resolution;
pub mod result_use;
pub mod rewrite_path;
pub mod routes;
pub mod spec;
