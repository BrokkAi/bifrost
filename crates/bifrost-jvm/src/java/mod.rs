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
mod regex;
mod regex_syntax;
mod resolution;
pub mod source_facts;
pub(crate) mod source_types;
mod string_literal;
pub use string_literal::decoded_string_literal_value;
pub mod structural;
pub mod test_detection;

#[cfg(test)]
mod coordinated_source_tests;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod source_properties;
