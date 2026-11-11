-- Compatible: additive scalar/child rows; versioned store filenames prevent mixed-version writers.
ALTER TABLE semantic_ir_values ADD COLUMN static_type_class INTEGER NOT NULL DEFAULT 0 CHECK(static_type_class BETWEEN 0 AND 4);
ALTER TABLE semantic_ir_procedures ADD COLUMN has_declared_results INTEGER NOT NULL DEFAULT 0 CHECK(has_declared_results IN (0, 1));
-- Selected-callee signature lookup reads classes by result ordinal, including Unknown.
CREATE TABLE semantic_ir_result_type_classes(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  class INTEGER NOT NULL CHECK(class BETWEEN 0 AND 4),
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id, procedure) REFERENCES semantic_ir_procedures(blob_id, procedure) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
ALTER TABLE semantic_ir_values ADD COLUMN static_origin_call INTEGER;
ALTER TABLE semantic_ir_values ADD COLUMN static_origin_ordinal INTEGER CHECK(
  (static_origin_call IS NULL AND static_origin_ordinal IS NULL) OR
  (static_origin_call IS NOT NULL AND static_origin_ordinal IS NOT NULL AND static_origin_ordinal >= 0));
