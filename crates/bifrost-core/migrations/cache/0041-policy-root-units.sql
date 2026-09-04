-- Typestate root units: one policy, one solver root.
--
-- Migrations 0038 and 0039 admitted three file-covering partitions: a seed
-- unit (one query's rows for one seed file), an assert unit (one subject
-- file's findings) and a binding unit (one row binding's rows for one seed
-- file). A typestate policy has a fourth
-- (`.agents/plans/impact-sliced-diff-base.md`, Milestone 5): its work is one
-- interprocedural solve per root procedure, and one file declares many
-- procedures, so the root's own mount-free semantic locator names the
-- partition beside the file and the blob and `partition_digest` carries it.
--
-- Its product is new too. A root unit publishes what one iteration of the
-- per-root loop appended -- that root's projected violations, the reasons its
-- own analysis was incomplete, and what it added to the run's counters -- which
-- is neither rendered rows nor a file's findings, so `product_kind` admits
-- `root` and is tied to the root partition exactly as `assert_file` is tied to
-- the assert partition.
--
-- The table is recreated rather than altered because every change is a CHECK
-- constraint -- the admitted partition kinds, the admitted product kinds, which
-- kinds carry a narrowing digest, and which product belongs to which partition
-- -- and SQLite cannot alter a CHECK in place. Units are content-keyed, so a
-- run after this migration republishes whatever is still true; nothing that is
-- still true is lost. `policy_unit_reads` and `policy_evaluation_units` are
-- recreated with it because both reference `policy_units(unit_id)`, and a row
-- of either that named a dropped unit would name work no evaluation did.
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
    'seed', 'binding', 'assert_file', 'root', 'whole'
  )),
  seed_rel_path             TEXT    NOT NULL,
  seed_blob_oid             TEXT    NOT NULL
    CHECK(seed_blob_oid = ''
          OR (length(seed_blob_oid) = 40 AND seed_blob_oid NOT GLOB '*[^0-9a-f]*')),
  -- The digest of what this partition covers within its file, for a partition
  -- whose question is narrower than the file: an assert unit's subject rows,
  -- the name of the row binding a relational unit executed, or the semantic
  -- locator of the procedure a typestate root unit solved. Empty for the
  -- partitions that cover a whole file or the whole workspace.
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
  product_kind              TEXT    NOT NULL CHECK(product_kind IN (
    'rows', 'assert_file', 'root'
  )),
  product                   TEXT    NOT NULL CHECK(json_valid(product)),
  read_set_digest           BLOB    NOT NULL CHECK(length(read_set_digest) = 32),
  published_at              INTEGER NOT NULL CHECK(published_at >= 0),
  FOREIGN KEY(seed_blob_id, lang) REFERENCES blobs(id, lang) ON DELETE CASCADE,
  -- A file-covering unit names the file it covers and the blob that path
  -- resolved to; a whole-policy unit covers the workspace and names neither.
  CHECK((partition_kind = 'whole') = (seed_rel_path = '')),
  CHECK((partition_kind = 'whole') = (seed_blob_oid = '')),
  -- An assert unit's, a binding unit's and a root unit's questions are all
  -- narrower than the file they cover; a seed unit's is the file.
  CHECK((partition_kind IN ('assert_file', 'binding', 'root')) = (partition_digest <> '')),
  CHECK((seed_blob_id IS NULL) = (lang IS NULL)),
  CHECK(partition_kind <> 'whole' OR seed_blob_id IS NULL),
  -- Rendered rows are a query's product, whether the query is a policy's own
  -- selector or one binding of a relational plan; a file's findings are an
  -- assert's, and one root's projected violations are a root's.
  CHECK((partition_kind = 'assert_file') = (product_kind = 'assert_file')),
  CHECK((partition_kind = 'root') = (product_kind = 'root'))
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
