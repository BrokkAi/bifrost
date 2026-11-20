-- Final version 0512 assigned by 5992a in Ready order.
-- Compatible additive: old values retain Unknown actual borrowing.
-- Actual expression borrowing is independent of declaration passing modes.
-- Existing address rows make no affirmative borrowing claim.
ALTER TABLE semantic_ir_values ADD COLUMN actual_borrow INTEGER NOT NULL DEFAULT 0
  CHECK(actual_borrow BETWEEN 0 AND 3);
ALTER TABLE candidate_macro_semantic_ir_values ADD COLUMN actual_borrow INTEGER NOT NULL DEFAULT 0
  CHECK(actual_borrow BETWEEN 0 AND 3);
