-- BREAKING: older readers cannot enforce the identity and all-element
-- obligations of macro type candidates. They must not reuse new inferred rows.
CREATE TABLE resolution_macro_type_candidates(
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  output_slot INTEGER NOT NULL CHECK(output_slot >= 0),
  reference_site INTEGER NOT NULL CHECK(reference_site >= 0),
  invocation_site INTEGER NOT NULL CHECK(invocation_site >= 0),
  lexical_import_shadow INTEGER NOT NULL CHECK(lexical_import_shadow IN (0,1)),
  element_count INTEGER NOT NULL CHECK(element_count >= 0),
  segment_count INTEGER NOT NULL CHECK(segment_count > 0),
  PRIMARY KEY(blob_id, output_slot),
  FOREIGN KEY(blob_id, output_slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, reference_site) REFERENCES resolution_semantic_sites(blob_id, source_site) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE resolution_macro_type_elements(
  blob_id INTEGER NOT NULL,
  output_slot INTEGER NOT NULL CHECK(output_slot >= 0),
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  element_slot INTEGER NOT NULL CHECK(element_slot >= 0),
  PRIMARY KEY(blob_id, output_slot, ordinal),
  FOREIGN KEY(blob_id, output_slot) REFERENCES resolution_macro_type_candidates(blob_id, output_slot) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, element_slot) REFERENCES resolution_semantic_catalog(blob_id, local_key) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE TABLE resolution_macro_type_segments(
  blob_id INTEGER NOT NULL,
  output_slot INTEGER NOT NULL CHECK(output_slot >= 0),
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  spelling TEXT NOT NULL CHECK(length(spelling) > 0),
  PRIMARY KEY(blob_id, output_slot, ordinal),
  FOREIGN KEY(blob_id, output_slot) REFERENCES resolution_macro_type_candidates(blob_id, output_slot) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- Parent deletion must seek the entire composite child key, not scan a blob.
CREATE INDEX resolution_macro_type_candidates_reference
  ON resolution_macro_type_candidates(blob_id, reference_site);
CREATE INDEX resolution_macro_type_elements_element
  ON resolution_macro_type_elements(blob_id, element_slot);
