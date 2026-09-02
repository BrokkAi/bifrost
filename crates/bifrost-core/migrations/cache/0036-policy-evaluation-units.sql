-- Persisted policy evaluation units and base evaluations.
--
-- A policy evaluation unit is one policy evaluated over one partition of a
-- workspace, together with the exact set of inputs that execution read
-- (`.agents/plans/impact-sliced-diff-base.md`). Persisting units is what lets
-- a second `--diff-base` run reuse the first run's work: a unit whose recorded
-- reads still denote the same content in the head workspace answers the head's
-- question without being recomputed, and a whole base evaluation whose key is
-- unchanged is not evaluated at all.
--
-- Everything a lookup needs is an ordinary column: the unit key, the read keys
-- and their membership, and the evaluation key. Only the product -- the
-- rendered rows one unit produced -- is JSON, because it is one heterogeneous
-- shape per row family that no query inspects, exactly the exception
-- `.agents/docs/architecture-and-analyzer-store.md` allows.
--
-- Blob ids are re-minted on every publication, so a unit's key columns carry
-- the seed blob's oid rather than its id; `seed_blob_id` exists only to make
-- the row follow its blob through `ON DELETE CASCADE`, which is exactly the
-- moment the unit went stale.

CREATE TABLE policy_units(
  unit_id                   INTEGER PRIMARY KEY,
  policy_semantic_hash      TEXT    NOT NULL
    CHECK(length(policy_semantic_hash) = 64
          AND policy_semantic_hash NOT GLOB '*[^0-9a-f]*'),
  family                    TEXT    NOT NULL CHECK(family IN (
    'match', 'assertion', 'taint', 'flow', 'typestate'
  )),
  partition_kind            TEXT    NOT NULL CHECK(partition_kind IN ('seed', 'whole')),
  seed_rel_path             TEXT    NOT NULL,
  seed_blob_oid             TEXT    NOT NULL
    CHECK(seed_blob_oid = ''
          OR (length(seed_blob_oid) = 40 AND seed_blob_oid NOT GLOB '*[^0-9a-f]*')),
  seed_blob_id              INTEGER,
  lang                      TEXT,
  configuration_fingerprint TEXT    NOT NULL
    CHECK(length(configuration_fingerprint) = 64
          AND configuration_fingerprint NOT GLOB '*[^0-9a-f]*'),
  active_model_set_hash     TEXT    NOT NULL
    CHECK(length(active_model_set_hash) = 64
          AND active_model_set_hash NOT GLOB '*[^0-9a-f]*'),
  engine_epoch              TEXT    NOT NULL
    CHECK(length(engine_epoch) = 64 AND engine_epoch NOT GLOB '*[^0-9a-f]*'),
  -- Only an exhaustive, complete unit may be published: a truncated or
  -- diagnostic-bearing execution is not a partition of a whole one, so a
  -- reader must never find one here to reject at load time.
  completion                TEXT    NOT NULL CHECK(completion = 'complete'),
  budget_mode               TEXT    NOT NULL CHECK(budget_mode = 'exhaustive'),
  product_kind              TEXT    NOT NULL CHECK(product_kind = 'rows'),
  product                   TEXT    NOT NULL CHECK(json_valid(product)),
  read_set_digest           BLOB    NOT NULL CHECK(length(read_set_digest) = 32),
  published_at              INTEGER NOT NULL CHECK(published_at >= 0),
  FOREIGN KEY(seed_blob_id, lang) REFERENCES blobs(id, lang) ON DELETE CASCADE,
  -- A seed unit names the file it covers and the blob that path resolved to; a
  -- whole-policy unit covers the workspace and names neither.
  CHECK((partition_kind = 'seed') = (seed_rel_path <> '')),
  CHECK((partition_kind = 'seed') = (seed_blob_oid <> '')),
  CHECK((seed_blob_id IS NULL) = (lang IS NULL)),
  CHECK(partition_kind = 'seed' OR seed_blob_id IS NULL)
) STRICT;

-- The unit key. Every column of it is equality-tested by a lookup, and the
-- leading columns are the ones one policy's whole batch shares, so a batch
-- lookup seeks once per requested partition instead of scanning the table.
CREATE UNIQUE INDEX policy_units_key ON policy_units(
  policy_semantic_hash,
  family,
  configuration_fingerprint,
  active_model_set_hash,
  engine_epoch,
  partition_kind,
  seed_rel_path,
  seed_blob_oid
);

-- The age sweep retires units by publication time, and the blob cascade needs
-- to find a blob's units when the blob is re-minted.
CREATE INDEX policy_units_published_at ON policy_units(published_at);
CREATE INDEX policy_units_seed_blob ON policy_units(seed_blob_id, lang);

-- One input a unit read, interned so a file read by forty units is one row.
--
-- `kind` says which of the read vocabulary's shapes this is, and each shape
-- fills exactly the columns its identity needs; the table-level checks below
-- are that statement in the schema. `key_digest` is the canonical digest of
-- the whole key, which is both the interning identity and the round-trip proof
-- a reader checks after rebuilding the key from these columns.
CREATE TABLE policy_read_keys(
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
  digest      BLOB    CHECK(digest IS NULL OR length(digest) = 32),
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

CREATE UNIQUE INDEX policy_read_keys_identity ON policy_read_keys(key_digest);

-- Which inputs one unit read. The membership is the unit's whole read set, so
-- a reader loads it by one seek on `unit_id`.
CREATE TABLE policy_unit_reads(
  unit_id INTEGER NOT NULL,
  read_id INTEGER NOT NULL,
  PRIMARY KEY(unit_id, read_id),
  FOREIGN KEY(unit_id) REFERENCES policy_units(unit_id) ON DELETE CASCADE,
  FOREIGN KEY(read_id) REFERENCES policy_read_keys(read_id)
) WITHOUT ROWID, STRICT;

CREATE INDEX policy_unit_reads_by_read ON policy_unit_reads(read_id);

-- One completed base evaluation of one policy set over one committed subtree.
--
-- The tree oid determines the base bytes exactly, including a subdirectory
-- root; the other key columns carry the inputs a tree id does not: which
-- policies were evaluated, under which options, analyzer configuration, active
-- semantic-model set, and analysis epoch. A row exists only for an evaluation
-- that was reliable and whose units cover every policy it ran, because that is
-- the only kind a later run may substitute for evaluating the base again.
--
-- `analyzed_source_bytes` and `analyzed_file_count` are the volume that scaled
-- the base's per-policy budget. A later run reconstructs the base's findings
-- from its units and must scale the same budget from the same volume, which it
-- cannot measure without building the base workspace it is avoiding.
CREATE TABLE policy_evaluations(
  evaluation_id             INTEGER PRIMARY KEY,
  base_tree_oid             TEXT    NOT NULL
    CHECK(length(base_tree_oid) = 40 AND base_tree_oid NOT GLOB '*[^0-9a-f]*'),
  policy_set_digest         TEXT    NOT NULL
    CHECK(length(policy_set_digest) = 64 AND policy_set_digest NOT GLOB '*[^0-9a-f]*'),
  options_digest            TEXT    NOT NULL
    CHECK(length(options_digest) = 64 AND options_digest NOT GLOB '*[^0-9a-f]*'),
  configuration_fingerprint TEXT    NOT NULL
    CHECK(length(configuration_fingerprint) = 64
          AND configuration_fingerprint NOT GLOB '*[^0-9a-f]*'),
  active_model_set_hash     TEXT    NOT NULL
    CHECK(length(active_model_set_hash) = 64
          AND active_model_set_hash NOT GLOB '*[^0-9a-f]*'),
  engine_epoch              TEXT    NOT NULL
    CHECK(length(engine_epoch) = 64 AND engine_epoch NOT GLOB '*[^0-9a-f]*'),
  resolved_commit           TEXT    NOT NULL
    CHECK(length(resolved_commit) = 40 AND resolved_commit NOT GLOB '*[^0-9a-f]*'),
  analyzed_source_bytes     INTEGER NOT NULL CHECK(analyzed_source_bytes >= 0),
  analyzed_file_count       INTEGER NOT NULL CHECK(analyzed_file_count >= 0),
  -- How many unit memberships this evaluation published. A membership whose
  -- unit followed its blob out of the cache leaves this count above the rows
  -- that remain, which is how a reader detects a partial evaluation instead of
  -- reconstructing findings from a subset of the base's work.
  unit_count                INTEGER NOT NULL CHECK(unit_count >= 0),
  published_at              INTEGER NOT NULL CHECK(published_at >= 0)
) STRICT;

CREATE UNIQUE INDEX policy_evaluations_key ON policy_evaluations(
  base_tree_oid,
  policy_set_digest,
  options_digest,
  configuration_fingerprint,
  active_model_set_hash,
  engine_epoch
);

CREATE INDEX policy_evaluations_published_at ON policy_evaluations(published_at);

-- The units one evaluation published, per policy, in the order that
-- evaluation merged them. The order is persisted rather than re-derived,
-- because the merge reproduces a whole execution's row vector only in the seed
-- order the run that produced it walked.
CREATE TABLE policy_evaluation_units(
  evaluation_id INTEGER NOT NULL,
  policy_id     TEXT    NOT NULL CHECK(length(policy_id) > 0),
  ordinal       INTEGER NOT NULL CHECK(ordinal >= 0),
  unit_id       INTEGER NOT NULL,
  PRIMARY KEY(evaluation_id, policy_id, ordinal),
  FOREIGN KEY(evaluation_id) REFERENCES policy_evaluations(evaluation_id) ON DELETE CASCADE,
  FOREIGN KEY(unit_id) REFERENCES policy_units(unit_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX policy_evaluation_units_by_unit ON policy_evaluation_units(unit_id);
