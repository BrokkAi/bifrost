-- Positional JSONB array of start bytes for the attributes in each Rust source
-- context that may expand to code. NULL is a row published before this
-- producer and proves nothing; the Rust source epoch republishes it. An empty
-- array is a proof that the context has no expanding attribute.
-- The migration runner supplies the atomic transaction with foreign keys enabled.

ALTER TABLE source_rust_item_contexts ADD COLUMN expanding_attribute_starts BLOB CHECK(expanding_attribute_starts IS NULL OR (json_valid(expanding_attribute_starts, 8) AND json_type(expanding_attribute_starts) = 'array'));
