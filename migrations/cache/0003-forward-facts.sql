CREATE TABLE path_symbol_snapshots(
  lang         TEXT PRIMARY KEY,
  fingerprint  TEXT NOT NULL CHECK(length(fingerprint) = 64)
) WITHOUT ROWID, STRICT;

-- Scala supertype lookup paths changed from display text to a JSON-encoded,
-- parser-derived segment vector. The cache is rebuildable, so invalidate old
-- rows instead of attempting to infer structure from persisted strings.
DELETE FROM blobs;
