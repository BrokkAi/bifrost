-- The reverse qualified-import read joins each import's dependency unit key to
-- the package row it names. The key was computed from the package's import path,
-- test variant and source role for every package row in the context, so each
-- candidate scanned the whole context. The Go producer now stores the key on
-- the package row and indexes it. Derived Go contexts are cleared so no row is
-- left without a key; the producer republishes them on demand.
DELETE FROM go_context_selections;

-- The zero default only satisfies NOT NULL on the emptied table. The CHECK
-- rejects it, so a writer that omits the key fails at insert time.
ALTER TABLE go_package_instances ADD COLUMN unit_key BLOB NOT NULL
  DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
  CHECK(typeof(unit_key) = 'blob' AND length(unit_key) = 32 AND unit_key != zeroblob(32));

CREATE INDEX go_package_instances_unit_key
  ON go_package_instances(context_id, unit_key);

-- The candidate target read seeks the test variants of a target by their
-- for-test path.
CREATE INDEX go_package_instances_for_test
  ON go_package_instances(context_id, for_test);
