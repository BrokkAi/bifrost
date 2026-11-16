-- #11148: absent declaration kind is unknown, never an implicit concrete flag.
-- Retire certificates before changing their sealed projections. The source
-- declaration facts survive and republish with the selected abstract scalar.
DELETE FROM jvm_external_provider_publications;

CREATE TABLE jvm_external_owner_members_0315 (
    provider_id TEXT NOT NULL,
    owner_fqn TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    member_name TEXT NOT NULL,
    member_kind TEXT NOT NULL CHECK(member_kind IN (
        'constructor', 'method', 'function', 'field', 'property',
        'constant', 'static', 'macro', 'event', 'nested_type'
    )),
    visibility TEXT NOT NULL CHECK(visibility IN (
        'public', 'protected', 'internal', 'package_private', 'private'
    )),
    is_static INTEGER NOT NULL CHECK(is_static IN (0, 1)),
    signature_present INTEGER NOT NULL CHECK(signature_present IN (0, 1)),
    callable_family_complete INTEGER NOT NULL CHECK(callable_family_complete IN (0, 1)),
    non_overridable TEXT,
    parameters_jsonb BLOB NOT NULL CHECK(json_valid(parameters_jsonb, 8)),
    return_type_jsonb BLOB CHECK(return_type_jsonb IS NULL OR json_valid(return_type_jsonb, 8)),
    is_abstract INTEGER CHECK(is_abstract IS NULL OR is_abstract IN (0, 1)),
    PRIMARY KEY(provider_id, owner_fqn, ordinal),
    FOREIGN KEY(provider_id, owner_fqn)
        REFERENCES jvm_external_owners(provider_id, owner_fqn) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO jvm_external_owner_members_0315
SELECT provider_id, owner_fqn, ordinal, member_name, member_kind,
       visibility,
       is_static, signature_present, callable_family_complete, non_overridable,
       parameters_jsonb, return_type_jsonb, NULL
FROM jvm_external_owner_members;

DROP TABLE jvm_external_owner_members;
ALTER TABLE jvm_external_owner_members_0315 RENAME TO jvm_external_owner_members;
CREATE INDEX jvm_external_owner_members_by_name
    ON jvm_external_owner_members(provider_id, owner_fqn, member_name);

CREATE TRIGGER jvm_external_owner_members_no_insert_after_seal
BEFORE INSERT ON jvm_external_owner_members
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id = NEW.provider_id)
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;
CREATE TRIGGER jvm_external_owner_members_no_update_after_seal
BEFORE UPDATE ON jvm_external_owner_members
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id IN (OLD.provider_id, NEW.provider_id))
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;
CREATE TRIGGER jvm_external_owner_members_no_delete_after_seal
BEFORE DELETE ON jvm_external_owner_members
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id = OLD.provider_id)
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;

-- Every old owner publication omitted declaration kind. Withdraw the derived
-- inventory so the owner-membership fast path cannot skip its reprojection.
-- The migration runner disables foreign keys during table rebuilds, so remove
-- the dependent rows explicitly rather than relying on ON DELETE CASCADE.
DELETE FROM jvm_external_owner_members;
DELETE FROM jvm_external_owner_supertypes;
DELETE FROM jvm_external_owners;
