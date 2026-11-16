-- #11183 M2-key: a Go or Python unit summary records, per member, the input its
-- key hashed: the fingerprint of the member blob's current-list surface set, or
-- the blob OID when the blob has no admitted facts. A summary is live only while
-- every member's recorded input still equals the input of the blob now selected
-- for that member, so a same-OID repair that changes a surface can neither mix
-- old summaries with the new surface set nor leave them readable at historical
-- revisions. Rust members keep blob_id and record neither column. A legacy row
-- (both NULL, no blob_id) never matches, so its summary is stale until re-derived.
ALTER TABLE resolution_unit_summary_members
  ADD COLUMN member_surface_fingerprint BLOB
    CHECK(member_surface_fingerprint IS NULL OR length(member_surface_fingerprint) = 32);
ALTER TABLE resolution_unit_summary_members
  ADD COLUMN member_no_facts_oid TEXT
    CHECK(member_no_facts_oid IS NULL OR (
      length(member_no_facts_oid) > 0
      AND member_surface_fingerprint IS NULL
      AND blob_id IS NULL));
