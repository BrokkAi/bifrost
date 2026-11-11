-- Direction-bearing Go channels use constructor codes 5, 6 and 7. Legacy
-- Channel code 2 remains admissible as direction-unknown historical evidence.
CREATE TABLE resolution_type_components_v3 (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  container_slot INTEGER NOT NULL,
  constructor INTEGER NOT NULL CHECK(constructor IN (0,1,2,3,4,5,6,7)),
  kind INTEGER NOT NULL CHECK(kind IN (0,1,2)),
  component_slot INTEGER NOT NULL,
  PRIMARY KEY(blob_id, container_slot, kind),
  CHECK((constructor IN (0,2,3,4,5,6,7) AND kind=0) OR (constructor=1 AND kind IN (1,2))),
  FOREIGN KEY(blob_id, container_slot)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, component_slot)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

INSERT INTO resolution_type_components_v3(
  blob_id, container_slot, constructor, kind, component_slot
)
SELECT blob_id, container_slot, constructor, kind, component_slot
FROM resolution_type_components;
DROP TABLE resolution_type_components;
ALTER TABLE resolution_type_components_v3 RENAME TO resolution_type_components;
CREATE INDEX resolution_type_components_component
  ON resolution_type_components(blob_id, component_slot, container_slot);
