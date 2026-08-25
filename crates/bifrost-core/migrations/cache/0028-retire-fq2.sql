-- Retire the redundant binary FQ2 identity envelope.
--
-- Migration 0026 began writing the authoritative ordered segment relation for
-- every complete code unit. Carry its row count onto the parent so readers can
-- prove that a bounded child read is complete, then remove the opaque copy.

ALTER TABLE code_units ADD COLUMN fq_segment_count INTEGER NOT NULL DEFAULT 0
  CHECK(fq_segment_count >= 0);

ALTER TABLE code_units ADD COLUMN fq_segment_bytes INTEGER NOT NULL DEFAULT 0
  CHECK(fq_segment_bytes >= 0);

UPDATE code_units
SET fq_segment_count = (
  SELECT COUNT(*)
  FROM code_unit_fq_segments AS segments
  WHERE segments.blob_oid = code_units.blob_oid
    AND segments.lang = code_units.lang
    AND segments.unit_key = code_units.unit_key
);

UPDATE code_units
SET fq_segment_bytes = COALESCE((
  SELECT SUM(
    length(CAST(segments.seg_kind AS BLOB))
    + length(CAST(segments.segment AS BLOB))
  )
  FROM code_unit_fq_segments AS segments
  WHERE segments.blob_oid = code_units.blob_oid
    AND segments.lang = code_units.lang
    AND segments.unit_key = code_units.unit_key
), 0);

ALTER TABLE code_units DROP COLUMN fq_segments;

-- Rendered-name lookup decomposes a request into bounded `(prefix, tail)`
-- alternatives. Put the known request values first so SQLite seeks the two
-- authoritative components instead of enumerating every live unit that shares
-- the terminal short name and constructing mounted strings for each one.
CREATE INDEX idx_workspace_file_anchors_by_package
  ON workspace_file_anchors(
    lang, generation, package_name, anchor_kind, anchor_pop, file_id
  );

CREATE INDEX idx_code_units_stable_exact_tail
  ON code_units(lang, COALESCE(exact_fqn_tail, ''), blob_oid, unit_key)
  WHERE fq_anchor_kind IS NULL
    AND exact_fqn_tail IS NOT NULL
    AND (in_declarations = 1 OR in_definition_lookup = 1);

-- Prefix-first anchored lookup resolves the package to a file/blob, then seeks
-- the content-derived identity tail within that blob and anchor vocabulary.
CREATE INDEX idx_code_units_anchored_blob_exact_tail
  ON code_units(
    blob_oid, lang, fq_anchor_kind, fq_anchor_pop, exact_fqn_tail, unit_key
  )
  WHERE fq_anchor_kind IS NOT NULL
    AND exact_fqn_tail IS NOT NULL
    AND (in_declarations = 1 OR in_definition_lookup = 1);
