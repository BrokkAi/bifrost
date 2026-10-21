-- Qualified expression macros have no source_rust_macro_invocations row,
-- because that table owns item macros. Keep the written invocation path with
-- the macro input so reverse inventory can bound an expression frontier
-- without reparsing source text. Existing rows stay NULL until the Rust
-- source epoch republishes them.
ALTER TABLE source_rust_macro_inputs ADD COLUMN macro_name TEXT;
