-- #11173 slice 1: two-phase unit summary identity and the consumed-unit set.
--
-- Compatible: additive. `lookup_digest` is the digest the summary had before
-- this migration (the unit's own inputs and its direct dependencies' output
-- digests); `summary_digest` stays UNIQUE and from now on also covers the
-- recorded consumed set. Every existing summary consumed no unit beyond its
-- direct dependencies, so its lookup digest equals its summary digest and its
-- consumed set is empty; no summary is withdrawn and every one stays reusable.
-- SQLite has no SHA-256, so existing rows keep their old `summary_digest`
-- instead of being rewritten to H(lookup, empty set). A new derivation writes
-- the two-phase form, and the old row is collected with its version history.
-- The writer supplies `lookup_digest` on every insert. The all-zero column
-- default exists only because ALTER TABLE ADD COLUMN ... NOT NULL requires a
-- constant default.
ALTER TABLE resolution_unit_summaries ADD COLUMN lookup_digest BLOB NOT NULL
  DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
  CHECK(typeof(lookup_digest) = 'blob' AND length(lookup_digest) = 32);

UPDATE resolution_unit_summaries SET lookup_digest = summary_digest;

-- The candidate seek: not unique, because summaries that read different
-- foreign units under the same own inputs share a lookup digest.
CREATE INDEX resolution_unit_summaries_lookup
  ON resolution_unit_summaries(lookup_digest);

-- Units a derivation read beyond its direct dependencies, with the output
-- digest each had when read. A candidate summary is valid now when every
-- recorded unit's current settled live output digest equals the recorded one.
-- `consumed_summary_id` is provenance only: NULL when the unit had no live
-- summary at derive time, or once that summary was collected. The read kinds
-- are one flag column each, so SQL can select on them and no list is serialized.
CREATE TABLE resolution_unit_summary_consumed_units (
  summary_id             INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
  consumed_unit_key      BLOB NOT NULL
    CHECK(typeof(consumed_unit_key) = 'blob' AND length(consumed_unit_key) = 32),
  consumed_output_digest BLOB NOT NULL
    CHECK(typeof(consumed_output_digest) = 'blob' AND length(consumed_output_digest) = 32),
  consumed_summary_id    INTEGER REFERENCES resolution_unit_summaries(summary_id) ON DELETE SET NULL,
  read_reexport_hop      INTEGER NOT NULL CHECK(read_reexport_hop IN (0, 1)),
  read_module_hop        INTEGER NOT NULL CHECK(read_module_hop IN (0, 1)),
  read_endpoint          INTEGER NOT NULL CHECK(read_endpoint IN (0, 1)),
  read_absence           INTEGER NOT NULL CHECK(read_absence IN (0, 1)),
  read_closure_bindings  INTEGER NOT NULL CHECK(read_closure_bindings IN (0, 1)),
  read_trait_endpoint    INTEGER NOT NULL CHECK(read_trait_endpoint IN (0, 1)),
  PRIMARY KEY(summary_id, consumed_unit_key),
  CHECK(read_reexport_hop + read_module_hop + read_endpoint + read_absence
        + read_closure_bindings + read_trait_endpoint > 0)
) WITHOUT ROWID, STRICT;
