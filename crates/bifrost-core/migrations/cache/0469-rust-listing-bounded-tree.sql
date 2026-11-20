-- Compatible additive: nullable columns and one new table; older readers
-- ignore them. A certificate without the columns is an exact-rows certificate.
-- A bounded revision image records the Git tree it was cut from, a digest of
-- the materialized path set, and the paths themselves, in place of the one
-- synthetic Unknown failure row. The two columns are both NULL or both set.
ALTER TABLE rust_source_listing_certificates ADD COLUMN bounded_tree_oid BLOB
  CHECK(bounded_tree_oid IS NULL OR (typeof(bounded_tree_oid)='blob' AND length(bounded_tree_oid) IN (20,32)));
ALTER TABLE rust_source_listing_certificates ADD COLUMN materialized_digest BLOB
  CHECK(materialized_digest IS NULL OR (typeof(materialized_digest)='blob' AND length(materialized_digest)=32));
CREATE TABLE rust_source_listing_materialized(
  workspace_id TEXT NOT NULL,
  lang TEXT NOT NULL CHECK(lang = 'rust'),
  generation INTEGER NOT NULL,
  revision INTEGER NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('materialized','overlay_present','overlay_absent')),
  path TEXT NOT NULL,
  PRIMARY KEY(workspace_id,lang,generation,revision,role,path),
  FOREIGN KEY(workspace_id,lang,generation,revision)
    REFERENCES rust_source_listing_certificates(workspace_id,lang,generation,revision) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
