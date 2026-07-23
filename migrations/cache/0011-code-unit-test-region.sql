-- Per-declaration test-region taint (issue #1102).
--
-- `search_symbols` with `include_tests = false` previously gated whole files on
-- the file-level `blob_meta.contains_tests` boolean. The dominant Rust idiom
-- (a production module plus an inline `#[cfg(test)] mod tests`) therefore hid
-- the module's entire production API behind "No files matched". The gate is now
-- symbol-level: a declaration is test-filtered only when it is itself inside a
-- structurally-evidenced test region (a test-attributed item, or any
-- declaration nested under a `#[cfg(test)]`/test-attributed module or item),
-- while production declarations in the same file continue to surface.
--
-- The taint is recorded per declaration at extraction time and persisted here.
-- Existing rows default to 0 (untainted); the Rust analyzer epoch salt is
-- bumped alongside this migration so persisted Rust blobs re-extract and
-- populate real taint. Other languages never populate the taint, so their
-- existing rows are already correct at the default and need no re-extraction.
ALTER TABLE code_units
  ADD COLUMN in_test_region INTEGER NOT NULL DEFAULT 0
    CHECK (in_test_region IN (0, 1));
