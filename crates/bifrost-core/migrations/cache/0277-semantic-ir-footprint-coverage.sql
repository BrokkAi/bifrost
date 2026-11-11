-- One lowering witness per procedure. Boundary 1 is complete, 3 is refused.
-- Reason codes follow FootprintRefusal::code.
CREATE TABLE semantic_ir_footprint_coverage(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  contract_version INTEGER NOT NULL CHECK(contract_version > 0),
  boundary_disposition INTEGER NOT NULL CHECK(boundary_disposition IN (1, 3)),
  boundary_reason INTEGER CHECK(boundary_reason IN (1, 2, 3, 4, 5)),
  PRIMARY KEY(blob_id, procedure),
  CHECK((boundary_disposition = 1 AND boundary_reason IS NULL) OR
        (boundary_disposition = 3 AND boundary_reason IS NOT NULL)),
  FOREIGN KEY(blob_id, procedure) REFERENCES semantic_ir_procedures(blob_id, procedure) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- Every contract-1 procedure has one row for each FootprintClass code 1..15.
-- Disposition 1 is represented, 2 excluded, 3 refused. Exclusion and refusal
-- reasons occupy separate code spaces selected by disposition.
CREATE TABLE semantic_ir_footprint_coverage_classes(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  class INTEGER NOT NULL CHECK(class BETWEEN 1 AND 15),
  disposition INTEGER NOT NULL CHECK(disposition IN (1, 2, 3)),
  reason INTEGER,
  PRIMARY KEY(blob_id, procedure, class),
  CHECK((disposition = 1 AND reason IS NULL) OR
        (disposition = 2 AND reason IN (1, 2)) OR
        (disposition = 3 AND reason IN (1, 2, 3, 4, 5))),
  FOREIGN KEY(blob_id, procedure) REFERENCES semantic_ir_footprint_coverage(blob_id, procedure) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- A target-only gap may be discharged only for this exact call site.
CREATE TABLE semantic_ir_footprint_call_target_obligations(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  call_site INTEGER NOT NULL,
  gap INTEGER NOT NULL,
  impacts INTEGER NOT NULL CHECK(impacts BETWEEN 0 AND 127),
  PRIMARY KEY(blob_id, procedure, call_site, gap),
  FOREIGN KEY(blob_id, procedure) REFERENCES semantic_ir_footprint_coverage(blob_id, procedure) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure, call_site) REFERENCES semantic_ir_call_sites(blob_id, procedure, call_site),
  FOREIGN KEY(blob_id, procedure, gap) REFERENCES semantic_ir_gaps(blob_id, procedure, gap)
) WITHOUT ROWID, STRICT;
