-- Whether a signature row's `type_parameters` list is an answer or a default.
--
-- `type_parameters` has always defaulted to '[]', so an empty list meant both
-- "this declaration declares no type parameters" and "the adapter that wrote
-- this row never read the list". Callable rows could live with that, because
-- nothing derived identity from the count. Declaration-side generic arity does
-- (#1651): `CanonicalIdentity::generic_arity` separates `None` ("not recorded")
-- from `Some(0)` ("recorded, and there are none"), and a recorded absence has
-- no way to reach it through an empty list alone.
--
-- This follows the rule `0023-signature-metadata-columns.sql` states for every
-- future signature fact: one additive column with a DEFAULT, in a new
-- migration. Existing rows read back as 0, which is exactly right for them --
-- they were written by producers that did not read the list. The languages
-- whose type declarations now do record it bump their own per-language epoch
-- salt in `crates/bifrost-analysis/src/analyzer/store/epoch.rs`, so a warm
-- workspace does not mix recorded and unrecorded readings of the same source.
ALTER TABLE unit_signature_metadata
  ADD COLUMN type_parameters_recorded INTEGER NOT NULL DEFAULT 0
    CHECK(type_parameters_recorded IN (0, 1));
