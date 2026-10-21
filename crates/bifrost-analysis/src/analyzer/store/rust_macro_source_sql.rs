// The Rust crate's source storage and the planner pins share these queries.
#[doc(hidden)]
pub const RUST_MACRO_INPUT_EXISTS_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM source_rust_macro_inputs WHERE blob_id = ?1)";
#[doc(hidden)]
pub const RUST_MACRO_INVOCATION_INPUT_SQL: &str = "SELECT invocation_occurrence_id, macro_name, start_byte, source, native_gap_site, native_scope, cfg_condition FROM source_rust_macro_inputs WHERE blob_id = ?1 AND start_byte = ?2 ORDER BY invocation_occurrence_id LIMIT 1";
#[doc(hidden)]
pub const RUST_MACRO_INVOCATION_TOKENS_SQL: &str = "SELECT invocation_occurrence_id, ordinal, parent_ordinal, syntax_kind, start_byte, end_byte, source_occurrence_id FROM source_rust_macro_input_tokens WHERE blob_id = ?1 AND invocation_occurrence_id = ?2 ORDER BY ordinal";
