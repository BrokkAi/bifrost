//! The analyzer's language-blind model layer.
//!
//! Only the four names every module here needs are re-exported at this root;
//! `brokk-bifrost-analysis` re-exports the full historical surface from its own
//! `analyzer` module, which is where the analyzer registry, the store, the
//! usages framework and the language implementations live.

pub mod canonical_hash;
pub mod capabilities;
pub mod code_unit_index;
pub mod cognitive_complexity;
pub mod common;
pub mod config;
pub mod definition_lookup;
pub mod dense_id;
pub mod fq_name;
pub mod identifier;
pub mod model;
pub mod parsed_file;
pub mod pool_memo;
pub mod prepared_syntax;
pub mod project;
pub mod query_batch;
pub mod semantic_diagnostics;
pub mod source_content;
pub mod structural;
pub mod symbol_path;
pub mod test_assertions;
pub mod test_paths;
pub mod tree_walk;
pub mod type_relations;
pub mod usages;

pub use code_unit_index::{CodeUnitIndex, default_parent_fq_name};
pub use definition_lookup::BoundedDefinitionLookup;
pub use model::{CodeUnit, Language, ProjectFile, Range};
