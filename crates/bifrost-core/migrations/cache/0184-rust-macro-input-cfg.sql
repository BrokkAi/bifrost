-- An unsupported item macro still owns a frontier inside a cfg_if arm. Its
-- source predicate is independent of the selected crate context. Old inputs
-- have no proof of activation, so they remain unknown until reparsed.
ALTER TABLE source_rust_macro_inputs ADD COLUMN cfg_condition TEXT NOT NULL DEFAULT 'unknown';

-- The selected source-gap condition query seeks just the requested blob's
-- conditional frontiers, rather than reading all of its ordinary macro inputs.
CREATE INDEX source_rust_macro_inputs_conditional_frontier
  ON source_rust_macro_inputs(blob_id, native_gap_site)
  WHERE cfg_condition <> 'always' AND native_gap_site IS NOT NULL;
