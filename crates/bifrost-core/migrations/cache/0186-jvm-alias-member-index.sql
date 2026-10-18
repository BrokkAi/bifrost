-- SELECTED_JVM_ALIAS_BY_BLOB_AND_MEMBER probes one authored member in one
-- selected blob. Include member_name in the seek, including empty results.
CREATE INDEX resolution_jvm_aliases_member_name
  ON resolution_jvm_aliases(blob_id, member_name);
