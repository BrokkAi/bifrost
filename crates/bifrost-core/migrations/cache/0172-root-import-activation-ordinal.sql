-- A positional root import (Scala) takes effect at the byte its producer
-- records, and the selected import context consumes one blob's imports in that
-- order. Producers without positional imports store NULL, because their import
-- order does not change meaning. The column has no index: the order is applied
-- per blob, in Rust, after a blob's import rows are already selected.
ALTER TABLE resolution_paths ADD COLUMN activation_ordinal INTEGER
  CHECK(activation_ordinal IS NULL OR activation_ordinal >= 0);
