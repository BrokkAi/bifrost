//! The structural vocabulary a language spec is written against.
//!
//! `kinds` is the normalized kind/role registry; `occurrences`, `resolution`,
//! `edges` and `routes` the identifier-role, lexical-resolution,
//! reference-edge and identity-route vocabularies; `spec` the trait each
//! language implements to normalize its grammar; and `facts` the two values a
//! spec produces. The extraction engine, matcher, planner and RQL query layer
//! that consume them stay in `brokk-bifrost-analysis`.

pub mod edges;
pub mod facts;
pub mod kinds;
pub mod occurrences;
pub mod resolution;
pub mod routes;
pub mod spec;
