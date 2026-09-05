-- One structured identity per declared result of a multi-result callable.
--
-- `return_type_identity` holds a single identity, so it cannot describe
-- `func f() (T, error)`. The Go adapter had to drop the whole result type for
-- any such declaration, which left every binding made from a multi-result call
-- untyped: `b, _ := newBox()` gave dispatch nothing to resolve `b.method()`
-- against, so the call stayed `UnresolvedTarget` and, for the concurrency
-- solver, the method body was never compared at all. That is bbolt's
-- `tx, err := readOnlyDB.Begin(false)`.
--
-- Additive column with a DEFAULT, in its own migration, per the rule
-- `0023-signature-metadata-columns.sql` states: never add a field to a
-- serialized struct. Existing rows read as the empty list and keep answering
-- ordinal zero from `return_type_identity`, so a single-result declaration is
-- unaffected and nothing is invalidated.
--
-- JSON text for the same reason the other identity columns are: it is a
-- recursive shape no SQL query wants to look inside today. The byte cap is
-- `MAX_SIGNATURE_METADATA_BLOB_BYTES`, matching its siblings.
--
-- '[]' means the declaration states one result or none, and ordinal zero comes
-- from `return_type_identity`. A non-empty list means the adapter proved one
-- identity per declared result, in declaration order.
ALTER TABLE unit_signature_metadata
  ADD COLUMN result_type_identities TEXT NOT NULL DEFAULT '[]'
    CHECK(json_valid(result_type_identities)
          AND length(CAST(result_type_identities AS BLOB)) <= 8388608);
