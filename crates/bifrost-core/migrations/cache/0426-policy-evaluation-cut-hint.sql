-- Migration 0426 (#12413): condition evaluator-cut replay on acceptance hints.
-- compatible: nullable column; engine domain v6 fences rows from older binaries in both directions
-- INSERTs name their columns (policy_units.rs:682-699 and :818-824).
-- The UPSERT conflict target includes engine_epoch (policy_units.rs:700-701).
ALTER TABLE policy_evaluations ADD COLUMN cut_hint_digest BLOB;
