-- #12385: project external JVM generic declarations for shared call selection.
-- COMPATIBLE: clears a derived cache and adds nullable columns.
-- Publications go first: seal triggers abort inventory deletes while a certificate exists.
-- Clear every inventory table explicitly, with foreign keys enabled or disabled.
DELETE FROM jvm_external_provider_publications;
DELETE FROM jvm_external_owner_members;
DELETE FROM jvm_external_owner_supertypes;
DELETE FROM jvm_external_owners;

-- Type parameters are declaration-ordered named-key objects:
-- [{"name":"T","bounds":{"state":"unknown"}}] or
-- [{"name":"T","bounds":{"state":"known","types":[]}}].
-- Known types are TypeRef JSON; only explicit known-empty bounds mean unbounded.
-- NULL means not projected (unknown); [] means no declared type parameters.
ALTER TABLE jvm_external_owners ADD COLUMN type_parameters_jsonb BLOB
  CHECK(type_parameters_jsonb IS NULL OR json_valid(type_parameters_jsonb, 8));
ALTER TABLE jvm_external_owner_members ADD COLUMN type_parameters_jsonb BLOB
  CHECK(type_parameters_jsonb IS NULL OR json_valid(type_parameters_jsonb, 8));
-- Declaration-ordered TypeRef JSON arguments; NULL means not projected.
-- Projected edges always contain an explicit array, including [].
ALTER TABLE jvm_external_owner_supertypes ADD COLUMN type_arguments_jsonb BLOB
  CHECK(type_arguments_jsonb IS NULL OR json_valid(type_arguments_jsonb, 8));
