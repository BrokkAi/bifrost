-- One structured identity per declared parameter of a callable.
--
-- `parameters` records a label and a byte range per parameter and no type at
-- all. A consumer deciding whether binding a parameter preserves the caller's
-- object identity cannot answer from that: Go copies an argument, so a `*T`
-- parameter still reaches the caller's object while a `T` parameter reaches a
-- copy. The concurrency solver therefore refused every parameter binding that
-- lacked a proven runtime identity, which silently dropped the race in
-- `eachOf(s, func(x *st) { x.bump() })` and, in bbolt, the whole chain through
-- `b.ForEach(func(k, v []byte) error { ... })` to `bucket.go:84`. A receiver
-- can already be asked, through `extension_receiver_type_identity`; this gives
-- parameters the same footing.
--
-- Additive column with a DEFAULT, in its own migration, per the rule
-- `0023-signature-metadata-columns.sql` states: never add a field to a
-- serialized struct, and `parameters` is one. Existing rows read as the empty
-- list, which means no adapter recorded parameter types, and every consumer
-- keeps its previous behavior on that value.
--
-- JSON text for the same reason the other identity columns are: it is a
-- recursive shape no SQL query wants to look inside today. The byte cap is
-- `MAX_SIGNATURE_METADATA_BLOB_BYTES`, matching its siblings.
--
-- '[]' means no parameter types were recorded. A non-empty list holds one
-- entry per declared parameter in declaration order, `null` where the adapter
-- read the parameter but could not type it.
ALTER TABLE unit_signature_metadata
  ADD COLUMN parameter_type_identities TEXT NOT NULL DEFAULT '[]'
    CHECK(json_valid(parameter_type_identities)
          AND length(CAST(parameter_type_identities AS BLOB)) <= 8388608);
