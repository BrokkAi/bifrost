-- Persist language-neutral structural type components and named underlying
-- type syntax so query-local resolution can project container element types.
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_type_component_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_type_component_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_underlying_type_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_underlying_type_count >= 0);

CREATE TABLE resolution_type_components (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  container_slot INTEGER NOT NULL,
  constructor INTEGER NOT NULL CHECK(constructor IN (0,1,2)),
  kind INTEGER NOT NULL CHECK(kind IN (0,1,2)),
  component_slot INTEGER NOT NULL,
  PRIMARY KEY(blob_id, container_slot, kind),
  CHECK((constructor IN (0,2) AND kind=0) OR (constructor=1 AND kind IN (1,2))),
  FOREIGN KEY(blob_id, container_slot)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, component_slot)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_type_components_component
  ON resolution_type_components(blob_id, component_slot, container_slot);

CREATE TABLE resolution_underlying_types (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  definition INTEGER NOT NULL,
  slot INTEGER NOT NULL,
  PRIMARY KEY(blob_id, definition),
  FOREIGN KEY(blob_id, definition)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, slot)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_underlying_types_slot
  ON resolution_underlying_types(blob_id, slot, definition);
