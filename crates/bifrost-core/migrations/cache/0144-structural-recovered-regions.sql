-- Record the regions tree-sitter error recovery produced in each blob (#3777).
--
-- A node inside an ERROR region may have produced no structural fact, so a
-- structural selection that finds no row is complete only when no recovered
-- region could hold a node it selects. One row per outermost ERROR node and
-- per MISSING token; a MISSING token is zero-width. Rows are in source order.
--
-- The one reader is structural-fact hydration, which asks for one blob's
-- regions in order together with whether a callable fact's range contains
-- each one. It answers containment in SQL against the blob's
-- source_structural_facts nodes, so the primary key's blob_id prefix is the
-- only access path it needs.
CREATE TABLE source_structural_recovered_regions(
  blob_id    INTEGER NOT NULL,
  ordinal    INTEGER NOT NULL CHECK(ordinal >= 0),
  start_byte INTEGER NOT NULL CHECK(start_byte >= 0),
  end_byte   INTEGER NOT NULL CHECK(end_byte >= start_byte),
  PRIMARY KEY(blob_id, ordinal),
  FOREIGN KEY(blob_id)
    REFERENCES source_fact_manifests(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
