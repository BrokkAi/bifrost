-- Preserve whether an `extern crate` binding imports the target crate's
-- exported macros through `#[macro_use]`.
--
-- The attribute is a source-derived part of Rust name resolution. Without it,
-- a query can resolve the extern crate's namespace but cannot prove that an
-- unqualified macro came through that crate. Existing rows default to false;
-- the Rust analyzer epoch rotates with the new producer semantics, so live
-- Rust blobs are republished before a true value is required.
ALTER TABLE rust_import_targets
  ADD COLUMN is_macro_use INTEGER NOT NULL DEFAULT 0
    CHECK(is_macro_use IN (0, 1));
