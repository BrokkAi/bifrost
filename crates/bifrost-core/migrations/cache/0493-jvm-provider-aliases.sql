-- BREAKING #12245: withdraw JVM projections; old binaries cannot read scoped provider ids.
-- Durable inputs survive and the catalog republishes inventory on demand.

DELETE FROM jvm_external_provider_publications;
DELETE FROM jvm_external_owner_members;
DELETE FROM jvm_external_owner_supertypes;
DELETE FROM jvm_external_owners;
DROP TABLE jvm_external_owner_members;
DROP TABLE jvm_external_owner_supertypes;
DROP TABLE jvm_external_owners;
DROP TABLE jvm_external_provider_publications;

CREATE TABLE jvm_external_provider_publications (
    publication_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id TEXT NOT NULL UNIQUE,
    semantic_sha256 TEXT NOT NULL,
    source_identity TEXT NOT NULL,
    publication_state TEXT NOT NULL CHECK(publication_state IN ('uncertified', 'sealed')),
    projection_identity BLOB NOT NULL CHECK(typeof(projection_identity)='blob' AND length(projection_identity)=32),
    projected_rows_sha256 BLOB CHECK(length(projected_rows_sha256) = 32),
    owner_count INTEGER CHECK(owner_count >= 0),
    member_count INTEGER CHECK(member_count >= 0),
    supertype_count INTEGER CHECK(supertype_count >= 0),
    CHECK((publication_state = 'sealed' AND projected_rows_sha256 IS NOT NULL
        AND owner_count IS NOT NULL AND member_count IS NOT NULL AND supertype_count IS NOT NULL)
      OR (publication_state = 'uncertified' AND projected_rows_sha256 IS NULL
        AND owner_count IS NULL AND member_count IS NULL AND supertype_count IS NULL)),
    UNIQUE(semantic_sha256, projection_identity)
) STRICT;

CREATE TABLE jvm_external_owners (
    provider_id TEXT NOT NULL,
    owner_fqn TEXT NOT NULL,
    callables_complete INTEGER NOT NULL CHECK(callables_complete IN (0, 1)),
    values_complete INTEGER NOT NULL CHECK(values_complete IN (0, 1)),
    types_complete INTEGER NOT NULL CHECK(types_complete IN (0, 1)),
    supertypes_complete INTEGER NOT NULL CHECK(supertypes_complete IN (0, 1)),
    type_parameters_jsonb BLOB CHECK(type_parameters_jsonb IS NULL OR json_valid(type_parameters_jsonb, 8)),
    PRIMARY KEY(provider_id, owner_fqn),
    FOREIGN KEY(provider_id) REFERENCES jvm_external_provider_publications(provider_id) ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID;

CREATE TABLE jvm_external_owner_supertypes (
    provider_id TEXT NOT NULL,
    owner_fqn TEXT NOT NULL,
    supertype_fqn TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    type_arguments_jsonb BLOB CHECK(type_arguments_jsonb IS NULL OR json_valid(type_arguments_jsonb, 8)),
    PRIMARY KEY(provider_id, owner_fqn, ordinal),
    FOREIGN KEY(provider_id, owner_fqn)
        REFERENCES jvm_external_owners(provider_id, owner_fqn) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE "jvm_external_owner_members" (
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
    type_parameters_jsonb BLOB CHECK(type_parameters_jsonb IS NULL OR json_valid(type_parameters_jsonb, 8)),
    PRIMARY KEY(provider_id, owner_fqn, ordinal),
    FOREIGN KEY(provider_id, owner_fqn)
        REFERENCES jvm_external_owners(provider_id, owner_fqn) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TRIGGER jvm_external_owner_members_generation_insert
AFTER INSERT ON jvm_external_owner_members
BEGIN
  UPDATE jvm_external_inventory_generation SET generation = generation + 1 WHERE id = 0;
END;

CREATE TRIGGER jvm_external_owner_members_generation_update
AFTER UPDATE ON jvm_external_owner_members
BEGIN
  UPDATE jvm_external_inventory_generation SET generation = generation + 1 WHERE id = 0;
END;

CREATE TRIGGER jvm_external_owner_members_generation_delete
AFTER DELETE ON jvm_external_owner_members
BEGIN
  UPDATE jvm_external_inventory_generation SET generation = generation + 1 WHERE id = 0;
END;

CREATE TRIGGER jvm_external_owner_supertypes_generation_insert
AFTER INSERT ON jvm_external_owner_supertypes
BEGIN
  UPDATE jvm_external_inventory_generation SET generation = generation + 1 WHERE id = 0;
END;

CREATE TRIGGER jvm_external_owner_supertypes_generation_update
AFTER UPDATE ON jvm_external_owner_supertypes
BEGIN
  UPDATE jvm_external_inventory_generation SET generation = generation + 1 WHERE id = 0;
END;

CREATE TRIGGER jvm_external_owner_supertypes_generation_delete
AFTER DELETE ON jvm_external_owner_supertypes
BEGIN
  UPDATE jvm_external_inventory_generation SET generation = generation + 1 WHERE id = 0;
END;

CREATE TRIGGER jvm_external_owners_generation_insert
AFTER INSERT ON jvm_external_owners
BEGIN
  UPDATE jvm_external_inventory_generation SET generation = generation + 1 WHERE id = 0;
END;

CREATE TRIGGER jvm_external_owners_generation_update
AFTER UPDATE ON jvm_external_owners
BEGIN
  UPDATE jvm_external_inventory_generation SET generation = generation + 1 WHERE id = 0;
END;

CREATE TRIGGER jvm_external_owners_generation_delete
AFTER DELETE ON jvm_external_owners
BEGIN
  UPDATE jvm_external_inventory_generation SET generation = generation + 1 WHERE id = 0;
END;

CREATE TRIGGER jvm_external_provider_publications_generation_insert
AFTER INSERT ON jvm_external_provider_publications
BEGIN
  UPDATE jvm_external_inventory_generation SET generation = generation + 1 WHERE id = 0;
END;

CREATE TRIGGER jvm_external_provider_publications_generation_update
AFTER UPDATE ON jvm_external_provider_publications
BEGIN
  UPDATE jvm_external_inventory_generation SET generation = generation + 1 WHERE id = 0;
END;

CREATE TRIGGER jvm_external_provider_publications_generation_delete
AFTER DELETE ON jvm_external_provider_publications
BEGIN
  UPDATE jvm_external_inventory_generation SET generation = generation + 1 WHERE id = 0;
END;

CREATE TRIGGER jvm_external_owner_members_no_delete_after_seal
BEFORE DELETE ON jvm_external_owner_members
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id = OLD.provider_id AND publication_state='sealed')
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;

CREATE TRIGGER jvm_external_owner_members_no_insert_after_seal
BEFORE INSERT ON jvm_external_owner_members
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id = NEW.provider_id AND publication_state='sealed')
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;

CREATE TRIGGER jvm_external_owner_members_no_update_after_seal
BEFORE UPDATE ON jvm_external_owner_members
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id IN (OLD.provider_id, NEW.provider_id) AND publication_state='sealed')
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;

CREATE TRIGGER jvm_external_owner_supertypes_no_delete_after_seal
BEFORE DELETE ON jvm_external_owner_supertypes
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id = OLD.provider_id AND publication_state='sealed')
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;

CREATE TRIGGER jvm_external_owner_supertypes_no_insert_after_seal
BEFORE INSERT ON jvm_external_owner_supertypes
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id = NEW.provider_id AND publication_state='sealed')
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;

CREATE TRIGGER jvm_external_owner_supertypes_no_update_after_seal
BEFORE UPDATE ON jvm_external_owner_supertypes
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id IN (OLD.provider_id, NEW.provider_id) AND publication_state='sealed')
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;

CREATE TRIGGER jvm_external_owners_no_delete_after_seal
BEFORE DELETE ON jvm_external_owners
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id = OLD.provider_id AND publication_state='sealed')
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;

CREATE TRIGGER jvm_external_owners_no_insert_after_seal
BEFORE INSERT ON jvm_external_owners
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id = NEW.provider_id AND publication_state='sealed')
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;

CREATE TRIGGER jvm_external_owners_no_update_after_seal
BEFORE UPDATE ON jvm_external_owners
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id IN (OLD.provider_id, NEW.provider_id) AND publication_state='sealed')
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;

CREATE TRIGGER jvm_external_provider_publications_no_update_after_seal
BEFORE UPDATE ON jvm_external_provider_publications
BEGIN SELECT RAISE(ABORT, 'sealed JVM provider certificate is immutable'); END;

CREATE INDEX jvm_external_owner_members_by_name
    ON jvm_external_owner_members(provider_id, owner_fqn, member_name);

CREATE INDEX jvm_external_publications_by_artifact_sequence
    ON jvm_external_provider_publications(semantic_sha256, publication_sequence DESC);
