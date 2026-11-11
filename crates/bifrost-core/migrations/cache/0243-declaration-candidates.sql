-- #9177: Preserve existing read keys while adding declaration candidates.
-- Preserve read IDs and every child relation while widening the declaration family.
CREATE TABLE class_set_summary_reads_new(
  summary_id   INTEGER NOT NULL,
  read_ordinal INTEGER NOT NULL CHECK(read_ordinal >= 0),
  key_digest   BLOB    NOT NULL CHECK(length(key_digest) = 32),
  kind         TEXT    NOT NULL CHECK(kind IN (
    'file', 'path_absent', 'index', 'lookup', 'artifact', 'scope', 'models',
    'policy', 'configuration', 'epoch'
  )),
  family       TEXT,
  languages    TEXT,
  rel_path     TEXT,
  name         TEXT,
  index_key    BLOB,
  blob_oid     TEXT CHECK(blob_oid IS NULL OR
    (length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*')),
  subject      BLOB CHECK(subject IS NULL OR length(subject) = 32),
  start_byte   INTEGER CHECK(start_byte IS NULL OR start_byte >= 0),
  end_byte     INTEGER CHECK(end_byte IS NULL OR end_byte >= start_byte),
  digest       BLOB CHECK(digest IS NULL OR length(digest) = 32), site_ordinal INTEGER
  CHECK((site_ordinal IS NOT NULL) = (kind = 'lookup' AND family IS 'procedure_dispatch')
        AND (site_ordinal IS NULL OR site_ordinal >= 0)), decl_kind TEXT
  CHECK((decl_kind IS NOT NULL) = (kind = 'lookup' AND
        (family IS 'declaration_candidates' OR family IS 'declaration_facts' OR family IS 'signature_metadata'
         OR family IS 'callers' OR family IS 'callees' OR family IS 'usages'
         OR family IS 'reference_candidates' OR family IS 'descendants'))), decl_signature TEXT
  CHECK(decl_signature IS NULL OR decl_kind IS NOT NULL), workspace_fact_family TEXT
  CHECK((workspace_fact_family IS NOT NULL) =
        (kind = 'lookup' AND family IS 'workspace_fact')
        AND (workspace_fact_family IS NULL OR
             (length(workspace_fact_family) > 0 AND languages IS NOT NULL
              AND start_byte IS NULL AND end_byte IS NULL))),
  fact_member TEXT,
  fact_names BLOB
  CHECK(fact_names IS NULL OR (json_valid(fact_names, 8)
    AND json_type(fact_names) = 'array' AND json_array_length(fact_names) > 0))
  CHECK(CASE WHEN kind = 'lookup' AND family IS 'workspace_fact' THEN
        languages IS NOT NULL AND index_key IS NULL AND blob_oid IS NULL
        AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
        AND site_ordinal IS NULL AND decl_kind IS NULL AND decl_signature IS NULL
        AND (
          -- Whole / Class (subject distinguishes them).
          (rel_path IS NULL AND name IS NULL AND fact_member IS NULL AND fact_names IS NULL)
          -- File.
          OR (rel_path IS NOT NULL AND name IS NULL AND subject IS NULL AND fact_member IS NULL AND fact_names IS NULL)
          -- Named / NamedMember (fact_member distinguishes them).
          OR (rel_path IS NULL AND name IS NOT NULL AND subject IS NULL AND fact_names IS NULL)
          -- ClassMember.
          OR (rel_path IS NULL AND name IS NULL AND subject IS NOT NULL AND fact_member IS NOT NULL AND fact_names IS NULL)
          -- NameGroupMember.
          OR (rel_path IS NULL AND name IS NULL AND subject IS NULL AND fact_member IS NOT NULL AND fact_names IS NOT NULL)
          -- FileNamedMember; subject is its optional environment identity.
          OR (rel_path IS NOT NULL AND name IS NOT NULL AND fact_member IS NOT NULL AND fact_names IS NULL)
        )
      ELSE fact_member IS NULL AND fact_names IS NULL END),
  PRIMARY KEY(summary_id, read_ordinal),
  UNIQUE(summary_id, key_digest),
  FOREIGN KEY(summary_id) REFERENCES class_set_summaries(summary_id) ON DELETE CASCADE,
  CHECK((kind = 'file') = (blob_oid IS NOT NULL)),
  CHECK((kind = 'index') = (index_key IS NOT NULL)),
  CHECK(start_byte IS NULL OR kind = 'lookup'),
  CHECK(kind <> 'lookup' OR digest IS NOT NULL),
  CHECK(kind <> 'scope' OR (languages IS NOT NULL AND digest IS NOT NULL)),
  CHECK(kind <> 'artifact' OR subject IS NOT NULL),
  CHECK(kind NOT IN ('models', 'configuration', 'epoch') OR digest IS NOT NULL),
  CHECK(kind <> 'policy' OR (subject IS NOT NULL AND digest IS NOT NULL)),
  CHECK((start_byte IS NULL) = (end_byte IS NULL)),
  CHECK(CASE kind
    WHEN 'file' THEN
      family IS NULL AND languages IS NOT NULL AND rel_path IS NOT NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NOT NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NULL
    WHEN 'path_absent' THEN
      family IS NULL AND languages IS NOT NULL AND rel_path IS NOT NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NULL
    WHEN 'index' THEN
      family IS NOT NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NOT NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NULL
    WHEN 'lookup' THEN
      family IS NOT NULL AND (languages IS NULL OR family IS 'workspace_fact')
      AND index_key IS NULL AND blob_oid IS NULL
      AND digest IS NOT NULL AND (
        (family IS 'workspace_fact' AND languages IS NOT NULL
          AND start_byte IS NULL AND end_byte IS NULL)
        OR (rel_path IS NOT NULL AND name IS NOT NULL AND subject IS NULL
          AND start_byte IS NULL AND end_byte IS NULL)
        OR (rel_path IS NOT NULL AND name IS NULL AND subject IS NULL
          AND start_byte IS NULL AND end_byte IS NULL)
        OR (rel_path IS NOT NULL AND name IS NULL AND subject IS NOT NULL
          AND start_byte IS NOT NULL AND end_byte IS NOT NULL)
        OR (rel_path IS NULL AND name IS NULL AND subject IS NOT NULL
          AND start_byte IS NULL AND end_byte IS NULL)
      )
    WHEN 'artifact' THEN
      family IS NOT NULL AND languages IS NULL AND name IS NULL AND index_key IS NULL
      AND blob_oid IS NULL AND subject IS NOT NULL AND start_byte IS NULL
      AND end_byte IS NULL AND digest IS NULL
    WHEN 'scope' THEN
      family IS NULL AND languages IS NOT NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'policy' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NOT NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'models' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'configuration' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'epoch' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    ELSE 0
  END)
) WITHOUT ROWID, STRICT;
INSERT INTO class_set_summary_reads_new SELECT * FROM class_set_summary_reads;
DROP TABLE class_set_summary_reads;
ALTER TABLE class_set_summary_reads_new RENAME TO class_set_summary_reads;
CREATE INDEX class_set_summary_reads_by_key ON class_set_summary_reads(key_digest, summary_id);
CREATE TABLE policy_read_keys_new(
  read_id     INTEGER PRIMARY KEY,
  key_digest  BLOB    NOT NULL CHECK(length(key_digest) = 32),
  kind        TEXT    NOT NULL CHECK(kind IN (
    'file', 'path_absent', 'index', 'lookup', 'artifact', 'scope', 'models',
    'policy', 'configuration', 'epoch'
  )),
  -- The index family, the lookup kind, or the derived-artifact kind.
  family      TEXT,
  -- The languages this key was folded over, as sorted configuration labels: one
  -- for a file read, the whole scope for a scope read.
  languages   TEXT,
  rel_path    TEXT,
  -- The qualified name a declaration question asks about.
  name        TEXT,
  -- The exact bytes of a name-keyed index probe.
  index_key   BLOB,
  blob_oid    TEXT
    CHECK(blob_oid IS NULL
          OR (length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*')),
  -- The 32-byte identity this key names: an artifact fingerprint, a call
  -- site's artifact, a summary identity, a content identity, or a policy's
  -- semantic hash.
  subject     BLOB    CHECK(subject IS NULL OR length(subject) = 32),
  start_byte  INTEGER CHECK(start_byte IS NULL OR start_byte >= 0),
  end_byte    INTEGER CHECK(end_byte IS NULL OR end_byte >= start_byte),
  -- The digest of the answer a lookup returned, or the non-source input a
  -- models, policy, configuration or epoch key names.
  digest      BLOB    CHECK(digest IS NULL OR length(digest) = 32), site_ordinal INTEGER
  CHECK((site_ordinal IS NOT NULL) = (kind = 'lookup' AND family IS 'procedure_dispatch')
        AND (site_ordinal IS NULL OR site_ordinal >= 0)), decl_kind TEXT
  CHECK((decl_kind IS NOT NULL) = (kind = 'lookup' AND
        (family IS 'declaration_candidates' OR family IS 'declaration_facts' OR family IS 'signature_metadata'
         OR family IS 'callers' OR family IS 'callees' OR family IS 'usages'
         OR family IS 'reference_candidates' OR family IS 'descendants'))), decl_signature TEXT
  CHECK(decl_signature IS NULL OR decl_kind IS NOT NULL), workspace_fact_family TEXT
  CHECK((workspace_fact_family IS NOT NULL) =
        (kind = 'lookup' AND family IS 'workspace_fact')
        AND (workspace_fact_family IS NULL OR
             (length(workspace_fact_family) > 0 AND languages IS NOT NULL
              AND start_byte IS NULL AND end_byte IS NULL))), fact_member TEXT, fact_names BLOB
  CHECK(fact_names IS NULL OR (json_valid(fact_names, 8)
    AND json_type(fact_names) = 'array' AND json_array_length(fact_names) > 0))
  CHECK(CASE WHEN kind = 'lookup' AND family IS 'workspace_fact' THEN
        languages IS NOT NULL AND index_key IS NULL AND blob_oid IS NULL
        AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
        AND site_ordinal IS NULL AND decl_kind IS NULL AND decl_signature IS NULL
        AND (
          -- Whole / Class (subject distinguishes them).
          (rel_path IS NULL AND name IS NULL AND fact_member IS NULL AND fact_names IS NULL)
          -- File.
          OR (rel_path IS NOT NULL AND name IS NULL AND subject IS NULL AND fact_member IS NULL AND fact_names IS NULL)
          -- Named / NamedMember (fact_member distinguishes them).
          OR (rel_path IS NULL AND name IS NOT NULL AND subject IS NULL AND fact_names IS NULL)
          -- ClassMember.
          OR (rel_path IS NULL AND name IS NULL AND subject IS NOT NULL AND fact_member IS NOT NULL AND fact_names IS NULL)
          -- NameGroupMember.
          OR (rel_path IS NULL AND name IS NULL AND subject IS NULL AND fact_member IS NOT NULL AND fact_names IS NOT NULL)
          -- FileNamedMember; subject is its optional environment identity.
          OR (rel_path IS NOT NULL AND name IS NOT NULL AND fact_member IS NOT NULL AND fact_names IS NULL)
        )
      ELSE fact_member IS NULL AND fact_names IS NULL END),
  CHECK((kind = 'file') = (blob_oid IS NOT NULL)),
  CHECK((kind = 'index') = (index_key IS NOT NULL)),
  -- Only a call-site question locates itself inside its file.
  CHECK(start_byte IS NULL OR kind = 'lookup'),
  CHECK(kind <> 'lookup' OR digest IS NOT NULL),
  CHECK(kind <> 'scope' OR (languages IS NOT NULL AND digest IS NOT NULL)),
  CHECK(kind <> 'artifact' OR subject IS NOT NULL),
  CHECK(kind NOT IN ('models', 'configuration', 'epoch') OR digest IS NOT NULL),
  CHECK(kind <> 'policy' OR (subject IS NOT NULL AND digest IS NOT NULL)),
  CHECK((start_byte IS NULL) = (end_byte IS NULL))
) STRICT;
INSERT INTO policy_read_keys_new SELECT * FROM policy_read_keys;
DROP TABLE policy_read_keys;
ALTER TABLE policy_read_keys_new RENAME TO policy_read_keys;
CREATE UNIQUE INDEX policy_read_keys_identity ON policy_read_keys(key_digest);
