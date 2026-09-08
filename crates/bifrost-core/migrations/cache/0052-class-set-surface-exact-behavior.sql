-- Procedure surfaces are semantic certificates, but fast replay also needs to
-- know which exact current provider behavior produced each certificate.
-- Version 51 did not retain that provenance. These derived rows are not a
-- durable source of truth, so discard them (and their dependent summaries)
-- before making the exact behavior digest and its provenance integrity digest
-- mandatory.

DELETE FROM class_set_summaries;
DELETE FROM class_set_procedure_surfaces;

ALTER TABLE class_set_procedure_surfaces
  ADD COLUMN exact_behavior_digest BLOB NOT NULL
    CHECK(length(exact_behavior_digest) = 32);

ALTER TABLE class_set_procedure_surfaces
  ADD COLUMN exact_provenance_digest BLOB NOT NULL
    CHECK(length(exact_provenance_digest) = 32);
