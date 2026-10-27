//! Java language knowledge.

pub mod adapter;
pub mod clones;
pub mod conversion;
pub mod declarations;
pub mod diagnostics;
pub mod exceptions;
pub mod graph;
pub mod graph_support;
pub mod hierarchy;
pub mod import_split;
pub mod imports;
pub mod javadoc;
pub mod primitives;
mod resolution;
pub mod source_facts;
pub(crate) mod source_types;
pub mod structural;
pub mod test_detection;

#[cfg(test)]
mod coordinated_source_tests;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod source_properties;
