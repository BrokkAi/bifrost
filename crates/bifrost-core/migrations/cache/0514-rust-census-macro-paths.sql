-- #13259: a Rust impl census macro boundary records the invoked path and whether
-- a visible import may shadow its terminal name, so a reader can certify an
-- item-free standard macro (`format!`, `vec!`, `println!`) and drop it from the
-- crate's open boundaries. The path is a JSONB array of segment spellings; a
-- pre-existing boundary keeps NULL columns, which no reader can certify, so it
-- stays open until its file is extracted again. Readers of older binaries do not
-- see these columns; the versioned store file fences them as for 0420.
ALTER TABLE source_rust_impl_census_boundaries ADD COLUMN macro_absolute INTEGER
  CHECK(macro_absolute IS NULL OR macro_absolute IN (0, 1));
ALTER TABLE source_rust_impl_census_boundaries ADD COLUMN macro_shadow_possible INTEGER
  CHECK(macro_shadow_possible IS NULL OR macro_shadow_possible IN (0, 1));
ALTER TABLE source_rust_impl_census_boundaries ADD COLUMN macro_path BLOB
  CHECK(macro_path IS NULL OR (json_valid(macro_path, 8) AND json_type(macro_path) = 'array'));
