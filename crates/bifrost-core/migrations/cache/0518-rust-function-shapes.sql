-- BREAKING: older readers do not know that a type slot can carry a written
-- function-family bound, or that a closure argument publishes binder slots
-- whose types a contextual signature fills. They would ignore both and could
-- reuse a binder answer that a newer reader derives from them, so rows written
-- by this version must not be read by an older one.
CREATE TABLE resolution_function_shapes(
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  owner_slot INTEGER NOT NULL CHECK(owner_slot >= 0),
  trait_slot INTEGER NOT NULL CHECK(trait_slot >= 0),
  parameter_count INTEGER NOT NULL CHECK(parameter_count >= 0),
  result_slot INTEGER CHECK(result_slot IS NULL OR result_slot >= 0),
  result_indirection INTEGER CHECK(result_indirection IS NULL OR result_indirection >= 0),
  result_reference_indirection INTEGER CHECK(result_reference_indirection IS NULL OR result_reference_indirection >= 0),
  CHECK((result_slot IS NULL) = (result_indirection IS NULL)),
  CHECK((result_slot IS NULL) = (result_reference_indirection IS NULL)),
  PRIMARY KEY(blob_id, owner_slot),
  FOREIGN KEY(blob_id, owner_slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, trait_slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, result_slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE resolution_function_shape_parameters(
  blob_id INTEGER NOT NULL,
  owner_slot INTEGER NOT NULL CHECK(owner_slot >= 0),
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  parameter_slot INTEGER NOT NULL CHECK(parameter_slot >= 0),
  indirection INTEGER NOT NULL CHECK(indirection >= 0),
  reference_indirection INTEGER NOT NULL CHECK(reference_indirection >= 0),
  PRIMARY KEY(blob_id, owner_slot, ordinal),
  FOREIGN KEY(blob_id, owner_slot) REFERENCES resolution_function_shapes(blob_id, owner_slot) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, parameter_slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- A closure written as a call argument. It is not a declaration: no definition,
-- catalog node or callable signature exists for it, and only the evaluator step
-- that reads a formal's function shape reads these rows. complete = 0 means a
-- parameter is not an identifier binder (a pattern, `_`, a macro or malformed
-- syntax), so no member row of kind 0 exists and nothing may be filled.
CREATE TABLE resolution_closure_literals(
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  value_slot INTEGER NOT NULL CHECK(value_slot >= 0),
  complete INTEGER NOT NULL CHECK(complete IN (0,1)),
  parameter_count INTEGER NOT NULL CHECK(parameter_count >= 0 AND (complete = 1 OR parameter_count = 0)),
  return_count INTEGER NOT NULL CHECK(return_count >= 0),
  result_slot INTEGER CHECK(result_slot IS NULL OR result_slot >= 0),
  PRIMARY KEY(blob_id, value_slot),
  FOREIGN KEY(blob_id, value_slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, result_slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
-- kind 0 is an identifier binder (binder_site, annotated and a declared-value
-- slot); kind 1 is a ReturnValue slot. binder_site is the binder's value
-- declaration site: a plain number, because it is read only to name the slot's
-- site and no declaration row depends on it.
CREATE TABLE resolution_closure_members(
  blob_id INTEGER NOT NULL,
  value_slot INTEGER NOT NULL CHECK(value_slot >= 0),
  kind INTEGER NOT NULL CHECK(kind IN (0,1)),
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  slot INTEGER NOT NULL CHECK(slot >= 0),
  binder_site INTEGER CHECK(binder_site IS NULL OR binder_site >= 0),
  annotated INTEGER CHECK(annotated IS NULL OR annotated IN (0,1)),
  CHECK((kind = 0) = (binder_site IS NOT NULL)),
  CHECK((kind = 0) = (annotated IS NOT NULL)),
  PRIMARY KEY(blob_id, value_slot, kind, ordinal),
  FOREIGN KEY(blob_id, value_slot) REFERENCES resolution_closure_literals(blob_id, value_slot) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- Catalog deletion must seek the entire composite child key, not scan a blob.
CREATE INDEX resolution_function_shapes_trait
  ON resolution_function_shapes(blob_id, trait_slot);
CREATE INDEX resolution_function_shapes_result
  ON resolution_function_shapes(blob_id, result_slot);
CREATE INDEX resolution_function_shape_parameters_parameter
  ON resolution_function_shape_parameters(blob_id, parameter_slot);
CREATE INDEX resolution_closure_literals_result
  ON resolution_closure_literals(blob_id, result_slot);
CREATE INDEX resolution_closure_members_slot
  ON resolution_closure_members(blob_id, slot);
