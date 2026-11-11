-- Scoped call/control coverage is independent of full-footprint admission.
-- Contract 1 requires a separate source-boundary proof and all eight classes.
CREATE TABLE semantic_ir_call_control_coverage(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  contract_version INTEGER NOT NULL CHECK(contract_version > 0),
  source_boundary INTEGER NOT NULL CHECK(source_boundary IN (1, 3)),
  source_reason INTEGER CHECK(source_reason BETWEEN 1 AND 5),
  admission INTEGER NOT NULL CHECK(admission IN (1, 3)),
  admission_reason INTEGER CHECK(admission_reason BETWEEN 1 AND 5),
  obligation_count INTEGER NOT NULL CHECK(obligation_count >= 0),
  PRIMARY KEY(blob_id, procedure),
  CHECK((source_boundary = 1 AND source_reason IS NULL) OR
        (source_boundary = 3 AND source_reason IS NOT NULL)),
  CHECK((admission = 1 AND admission_reason IS NULL) OR
        (admission = 3 AND admission_reason IS NOT NULL)),
  FOREIGN KEY(blob_id, procedure) REFERENCES semantic_ir_procedures(blob_id, procedure) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- Kind codes are CallControlKind 1..8. A class with no source branch uses
-- exclusion reason 3 (no instance); branch exclusions retain their reason.
CREATE TABLE semantic_ir_call_control_classes(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  class INTEGER NOT NULL CHECK(class BETWEEN 1 AND 8),
  disposition INTEGER NOT NULL CHECK(disposition IN (1, 2, 3)),
  reason INTEGER,
  PRIMARY KEY(blob_id, procedure, class),
  CHECK((disposition = 1 AND reason IS NULL) OR
        (disposition = 2 AND reason BETWEEN 1 AND 3) OR
        (disposition = 3 AND reason BETWEEN 1 AND 5)),
  FOREIGN KEY(blob_id, procedure) REFERENCES semantic_ir_call_control_coverage(blob_id, procedure) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE semantic_ir_call_control_obligations(
  blob_id INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  call_site INTEGER NOT NULL,
  gap INTEGER NOT NULL,
  impacts INTEGER NOT NULL CHECK(impacts BETWEEN 0 AND 127),
  PRIMARY KEY(blob_id, procedure, call_site, gap),
  FOREIGN KEY(blob_id, procedure) REFERENCES semantic_ir_call_control_coverage(blob_id, procedure) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, procedure, call_site) REFERENCES semantic_ir_call_sites(blob_id, procedure, call_site),
  FOREIGN KEY(blob_id, procedure, gap) REFERENCES semantic_ir_gaps(blob_id, procedure, gap)
) WITHOUT ROWID, STRICT;
