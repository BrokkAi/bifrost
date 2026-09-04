-- Assertion evaluation units: one policy, one subject file, one product.
--
-- Migration 0036 admitted exactly one partition ("one seed file") and exactly
-- one product ("the rendered rows a query produced"), because the match family
-- was the only one sliced. The assertion family has two unit kinds
-- (`.agents/plans/impact-sliced-diff-base.md`, Milestone 4): its subject query
-- is a seed unit like any other, and each subject file is an assert unit whose
-- product is the findings that file's asserts produced, its verdict, its row
-- completions and its work.
--
-- An assert unit is keyed by the file it covers, the blob that path resolved
-- to, and the digest of that file's subject rows. The third component is what
-- makes the key honest: two runs whose subject selector bound different rows in
-- the same bytes are asking different questions of the same file, and a unit
-- keyed by the file alone would answer the second with the first's findings.
-- `partition_digest` carries it, empty for the two partitions that have no such
-- component, and it joins the unique index because it is part of the key rather
-- than a payload.
--
-- The table is recreated rather than altered. `partition_digest` belongs inside
-- the unique index, and SQLite cannot add a column to an existing index; and a
-- unit written before this migration is content-keyed, so the next run
-- republishes whatever is still true without recomputing anything it does not
-- have to. `policy_unit_reads` and `policy_evaluation_units` are recreated with
-- it because both reference `policy_units(unit_id)` and a row of either that
-- named a dropped unit would name work no evaluation did.
--
-- Children before parents: the migration chain runs with `PRAGMA foreign_keys`
-- ON, under which `DROP TABLE` fires the cascades of the rows it removes.

DROP TABLE policy_unit_reads;
DROP TABLE policy_evaluation_units;
DROP TABLE policy_units;

CREATE TABLE policy_units(
  unit_id                   INTEGER PRIMARY KEY,
  policy_semantic_hash      TEXT    NOT NULL
    CHECK(length(policy_semantic_hash) = 64
          AND policy_semantic_hash NOT GLOB '*[^0-9a-f]*'),
  family                    TEXT    NOT NULL CHECK(family IN (
    'match', 'assertion', 'taint', 'flow', 'typestate'
  )),
  partition_kind            TEXT    NOT NULL CHECK(partition_kind IN (
    'seed', 'assert_file', 'whole'
  )),
  seed_rel_path             TEXT    NOT NULL,
  seed_blob_oid             TEXT    NOT NULL
    CHECK(seed_blob_oid = ''
          OR (length(seed_blob_oid) = 40 AND seed_blob_oid NOT GLOB '*[^0-9a-f]*')),
  -- The digest of the rows this partition covers within its file, for a
  -- partition whose question is narrower than the file: an assert unit's
  -- subject rows. Empty for the partitions that cover a whole file or the whole
  -- workspace.
  partition_digest          TEXT    NOT NULL
    CHECK(partition_digest = ''
          OR (length(partition_digest) = 64 AND partition_digest NOT GLOB '*[^0-9a-f]*')),
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
  product_kind              TEXT    NOT NULL CHECK(product_kind IN ('rows', 'assert_file')),
  product                   TEXT    NOT NULL CHECK(json_valid(product)),
  read_set_digest           BLOB    NOT NULL CHECK(length(read_set_digest) = 32),
  published_at              INTEGER NOT NULL CHECK(published_at >= 0),
  FOREIGN KEY(seed_blob_id, lang) REFERENCES blobs(id, lang) ON DELETE CASCADE,
  -- A file-covering unit names the file it covers and the blob that path
  -- resolved to; a whole-policy unit covers the workspace and names neither.
  CHECK((partition_kind = 'whole') = (seed_rel_path = '')),
  CHECK((partition_kind = 'whole') = (seed_blob_oid = '')),
  -- Only an assert unit's question is narrower than the file it covers.
  CHECK((partition_kind = 'assert_file') = (partition_digest <> '')),
  CHECK((seed_blob_id IS NULL) = (lang IS NULL)),
  CHECK(partition_kind <> 'whole' OR seed_blob_id IS NULL),
  -- Rendered rows are a query's product; a file's findings are an assert's.
  CHECK((partition_kind = 'assert_file') = (product_kind = 'assert_file'))
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
  seed_blob_oid,
  partition_digest
);

-- The age sweep retires units by publication time, and the blob cascade needs
-- to find a blob's units when the blob is re-minted.
CREATE INDEX policy_units_published_at ON policy_units(published_at);
CREATE INDEX policy_units_seed_blob ON policy_units(seed_blob_id, lang);

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

-- The units one evaluation published, per policy.
--
-- A membership is how the age sweep tells a unit that belongs to a live base
-- evaluation from one no evaluation names. A policy that published no unit --
-- a whole-policy family, a widened evaluation -- simply has no row here.
CREATE TABLE policy_evaluation_units(
  evaluation_id INTEGER NOT NULL,
  policy_id     TEXT    NOT NULL CHECK(length(policy_id) > 0),
  unit_id       INTEGER NOT NULL,
  PRIMARY KEY(evaluation_id, policy_id, unit_id),
  FOREIGN KEY(evaluation_id) REFERENCES policy_evaluations(evaluation_id) ON DELETE CASCADE,
  FOREIGN KEY(unit_id) REFERENCES policy_units(unit_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX policy_evaluation_units_by_unit ON policy_evaluation_units(unit_id);
