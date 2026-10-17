-- Store generic owner formals as language-neutral declaration rows. Go is the
-- first producer to populate this family; Java, Kotlin, Scala, and Rust may
-- publish the same owner/ordinal/declaration relation later.
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_generic_formal_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_generic_formal_count >= 0);

-- Preserve the distinction between arrays and slices in the shared structural
-- type relation. Existing Sequence rows keep code 0; Go is the first producer
-- to emit Slice (3) and Array (4), and other producers can adopt them later.
CREATE TABLE resolution_type_components_v2 (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  container_slot INTEGER NOT NULL,
  constructor INTEGER NOT NULL CHECK(constructor IN (0,1,2,3,4)),
  kind INTEGER NOT NULL CHECK(kind IN (0,1,2)),
  component_slot INTEGER NOT NULL,
  PRIMARY KEY(blob_id, container_slot, kind),
  CHECK((constructor IN (0,2,3,4) AND kind=0) OR (constructor=1 AND kind IN (1,2))),
  FOREIGN KEY(blob_id, container_slot)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, component_slot)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

INSERT INTO resolution_type_components_v2(
  blob_id, container_slot, constructor, kind, component_slot
)
SELECT blob_id, container_slot, constructor, kind, component_slot
FROM resolution_type_components;
DROP TABLE resolution_type_components;
ALTER TABLE resolution_type_components_v2 RENAME TO resolution_type_components;
CREATE INDEX resolution_type_components_component
  ON resolution_type_components(blob_id, component_slot, container_slot);

CREATE TABLE resolution_generic_formals (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  owner_definition INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  parameter_definition INTEGER NOT NULL,
  PRIMARY KEY(blob_id, owner_definition, ordinal),
  UNIQUE(blob_id, parameter_definition),
  FOREIGN KEY(blob_id, owner_definition)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, parameter_definition)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_generic_formals_parameter
  ON resolution_generic_formals(blob_id, parameter_definition, owner_definition);
