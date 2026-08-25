-- Seed-directed reverse import lookup starts from a small set of declaration
-- names. These access paths let it seek parser-derived facts before hydrating
-- any file state. The blob identity remains in the key so a connection-local
-- live-workspace relation can discard historical content rows immediately.

CREATE INDEX idx_import_path_segments_by_segment
  ON import_path_segments(lang, segment, blob_oid, ordinal, seg_ordinal);

CREATE INDEX idx_type_identifiers_by_identifier
  ON type_identifiers(lang, type_identifier, blob_oid);
