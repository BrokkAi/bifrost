//! The structural vocabulary a language spec is written against.
//!
//! `kinds` is the normalized kind/role registry; `occurrences`, `resolution`,
//! `edges`, `routes` and `materialization` the identifier-role,
//! lexical-resolution, reference-edge, identity-route and
//! declaration-materialization vocabularies; `spec` the trait each language
//! implements to normalize its grammar; and `facts` the two values a spec
//! produces. The extraction engine, matcher, planner and RQL query layer that
//! consume them stay in `brokk-bifrost-analysis`.

pub mod callable;
pub mod edges;
pub mod facts;
pub mod kinds;
pub mod materialization;
pub mod occurrences;
pub mod resolution;
pub mod routes;
pub mod spec;
