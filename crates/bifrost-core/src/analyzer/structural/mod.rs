//! The structural vocabulary a language spec is written against.
//!
//! `kinds` is the normalized kind/role registry, `occurrences` and `resolution`
//! the identifier-role and lexical-resolution vocabularies, `spec` the trait
//! each language implements to normalize its grammar, `facts` the two values a
//! spec produces, and `adapter_helpers` the small node-arithmetic mechanics
//! every adapter uses to write one. The extraction engine, matcher, planner and
//! RQL query layer that consume them stay in `brokk-bifrost-analysis`.

pub mod adapter_helpers;
pub mod facts;
pub mod kinds;
pub mod occurrences;
pub mod resolution;
pub mod spec;
