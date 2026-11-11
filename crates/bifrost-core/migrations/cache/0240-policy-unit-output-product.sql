-- Retire old output partitions, whose rows product cannot be decoded as a native output.
-- Foreign keys are disabled by the migration runner, so remove each child link first.
DELETE FROM policy_unit_reads WHERE unit_id IN (SELECT unit_id FROM policy_units WHERE partition_kind = 'output');
DELETE FROM policy_unit_snapshots WHERE unit_id IN (SELECT unit_id FROM policy_units WHERE partition_kind = 'output');
DELETE FROM policy_evaluation_units WHERE unit_id IN (SELECT unit_id FROM policy_units WHERE partition_kind = 'output');
DELETE FROM policy_units WHERE partition_kind = 'output';
CREATE TABLE policy_units_new(
  unit_id                   INTEGER PRIMARY KEY,
  policy_semantic_hash      TEXT    NOT NULL
    CHECK(length(policy_semantic_hash) = 64
          AND policy_semantic_hash NOT GLOB '*[^0-9a-f]*'),
  family                    TEXT    NOT NULL CHECK(family IN (
    'match', 'assertion', 'taint', 'flow', 'typestate'
  )),
  partition_kind            TEXT    NOT NULL CHECK(partition_kind IN (
    'seed', 'binding', 'assert_file', 'root', 'selector', 'whole', 'prefix', 'output'
  )),
  seed_rel_path             TEXT    NOT NULL,
  seed_blob_oid             TEXT    NOT NULL
    CHECK(seed_blob_oid = ''
          OR (length(seed_blob_oid) = 40 AND seed_blob_oid NOT GLOB '*[^0-9a-f]*')),
  binding_digest TEXT NOT NULL DEFAULT '' CHECK(binding_digest = '' OR (length(binding_digest) = 64 AND binding_digest NOT GLOB '*[^0-9a-f]*')),
  subjects_digest TEXT NOT NULL DEFAULT '' CHECK(subjects_digest = '' OR (length(subjects_digest) = 64 AND subjects_digest NOT GLOB '*[^0-9a-f]*')),
  root_locator TEXT NOT NULL DEFAULT '' CHECK(root_locator = '' OR (length(root_locator) = 64 AND root_locator NOT GLOB '*[^0-9a-f]*')),
  root_compilation TEXT NOT NULL DEFAULT '' CHECK(root_compilation = '' OR (length(root_compilation) = 64 AND root_compilation NOT GLOB '*[^0-9a-f]*')),
  selector_digest TEXT NOT NULL DEFAULT '' CHECK(selector_digest = '' OR (length(selector_digest) = 64 AND selector_digest NOT GLOB '*[^0-9a-f]*')),
  prefix_cut_digest TEXT NOT NULL DEFAULT '' CHECK(prefix_cut_digest = '' OR (length(prefix_cut_digest) = 64 AND prefix_cut_digest NOT GLOB '*[^0-9a-f]*')),
  prefix_input_digest TEXT NOT NULL DEFAULT '' CHECK(prefix_input_digest = '' OR (length(prefix_input_digest) = 64 AND prefix_input_digest NOT GLOB '*[^0-9a-f]*')),
  anchor_locator TEXT NOT NULL DEFAULT '' CHECK(anchor_locator = '' OR (length(anchor_locator) = 64 AND anchor_locator NOT GLOB '*[^0-9a-f]*')),
  compilation_digest TEXT NOT NULL DEFAULT '' CHECK(compilation_digest = '' OR (length(compilation_digest) = 64 AND compilation_digest NOT GLOB '*[^0-9a-f]*')),
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
    'rows', 'assert_file', 'root', 'selector', 'prefix', 'output'
  )),
  read_set_digest           BLOB    NOT NULL CHECK(length(read_set_digest) = 32),
  published_at              INTEGER NOT NULL CHECK(published_at >= 0), product BLOB NOT NULL DEFAULT X'0C'
  CHECK(json_valid(product, 8)),
  FOREIGN KEY(seed_blob_id, lang) REFERENCES blobs(id, lang) ON DELETE CASCADE,
  -- A file-covering unit names the file it covers and the blob that path
  -- resolved to; a whole-policy unit covers the workspace and names neither.
  CHECK((partition_kind = 'whole') = (seed_rel_path = '')),
  CHECK((partition_kind = 'whole') = (seed_blob_oid = '')),
  CHECK(
    (partition_kind = 'whole' AND binding_digest = '' AND subjects_digest = '' AND root_locator = '' AND root_compilation = '' AND selector_digest = '' AND prefix_cut_digest = '' AND prefix_input_digest = '' AND anchor_locator = '' AND compilation_digest = '') OR
    (partition_kind = 'seed' AND binding_digest = '' AND subjects_digest = '' AND root_locator = '' AND root_compilation = '' AND selector_digest = '' AND prefix_cut_digest = '' AND prefix_input_digest = '' AND anchor_locator = '' AND compilation_digest = '') OR
    (partition_kind = 'binding' AND binding_digest <> '' AND subjects_digest = '' AND root_locator = '' AND root_compilation = '' AND selector_digest = '' AND prefix_cut_digest = '' AND prefix_input_digest = '' AND anchor_locator = '' AND compilation_digest = '') OR
    (partition_kind = 'assert_file' AND binding_digest = '' AND subjects_digest <> '' AND root_locator = '' AND root_compilation = '' AND selector_digest = '' AND prefix_cut_digest = '' AND prefix_input_digest = '' AND anchor_locator = '' AND compilation_digest = '') OR
    (partition_kind = 'root' AND binding_digest = '' AND subjects_digest = '' AND root_locator <> '' AND root_compilation <> '' AND selector_digest = '' AND prefix_cut_digest = '' AND prefix_input_digest = '' AND anchor_locator = '' AND compilation_digest = '') OR
    (partition_kind = 'selector' AND binding_digest = '' AND subjects_digest = '' AND root_locator = '' AND root_compilation = '' AND selector_digest <> '' AND prefix_cut_digest = '' AND prefix_input_digest = '' AND anchor_locator = '' AND compilation_digest = '') OR
    (partition_kind = 'prefix' AND binding_digest = '' AND subjects_digest = '' AND root_locator = '' AND root_compilation = '' AND selector_digest = '' AND prefix_cut_digest <> '' AND prefix_input_digest <> '' AND anchor_locator = '' AND compilation_digest = '') OR
    (partition_kind = 'output' AND binding_digest = '' AND subjects_digest = '' AND root_locator = '' AND root_compilation = '' AND selector_digest = '' AND prefix_cut_digest = '' AND prefix_input_digest = '' AND anchor_locator <> '' AND compilation_digest <> '')
  ),
  CHECK((seed_blob_id IS NULL) = (lang IS NULL)),
  CHECK(partition_kind <> 'whole' OR seed_blob_id IS NULL),
  -- Rendered rows are a query's product, whether the query is a policy's own
  -- selector or one binding of a relational plan; a file's findings are an
  -- assert's, one root's projected violations are a root's, and one seed
  -- file's selected sites are a selector unit's.
  CHECK((partition_kind = 'assert_file') = (product_kind = 'assert_file')),
  CHECK((partition_kind = 'root') = (product_kind = 'root')),
  CHECK((partition_kind = 'selector') = (product_kind = 'selector')),
  CHECK((partition_kind = 'prefix') = (product_kind = 'prefix')),
  CHECK((partition_kind = 'output') = (product_kind = 'output'))
) STRICT;
INSERT INTO policy_units_new SELECT * FROM policy_units;
DROP TABLE policy_units;
ALTER TABLE policy_units_new RENAME TO policy_units;
CREATE UNIQUE INDEX policy_units_key ON policy_units(policy_semantic_hash, family, configuration_fingerprint, active_model_set_hash, engine_epoch, partition_kind, seed_rel_path, seed_blob_oid, binding_digest, subjects_digest, root_locator, root_compilation, selector_digest, prefix_cut_digest, prefix_input_digest, anchor_locator, compilation_digest);
CREATE INDEX policy_units_published_at ON policy_units(published_at);
