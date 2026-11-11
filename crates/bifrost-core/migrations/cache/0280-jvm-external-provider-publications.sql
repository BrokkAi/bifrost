-- #9559: a certificate describes an exact projection, not semantic completeness.
CREATE TABLE jvm_external_provider_publications (
    provider_id TEXT PRIMARY KEY NOT NULL,
    source_identity TEXT NOT NULL,
    projection_version INTEGER NOT NULL CHECK(projection_version > 0),
    projected_rows_sha256 BLOB NOT NULL CHECK(length(projected_rows_sha256) = 32),
    owner_count INTEGER NOT NULL CHECK(owner_count >= 0),
    member_count INTEGER NOT NULL CHECK(member_count >= 0),
    supertype_count INTEGER NOT NULL CHECK(supertype_count >= 0)
) WITHOUT ROWID, STRICT;

-- Deleting the certificate explicitly invalidates it before collection or repair.
-- Rewriting a live certificate would make its original proof unverifiable.
CREATE TRIGGER jvm_external_provider_publications_no_update_after_seal
BEFORE UPDATE ON jvm_external_provider_publications
BEGIN SELECT RAISE(ABORT, 'sealed JVM provider certificate is immutable'); END;

CREATE TRIGGER jvm_external_owners_no_insert_after_seal
BEFORE INSERT ON jvm_external_owners
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id = NEW.provider_id)
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;
CREATE TRIGGER jvm_external_owners_no_update_after_seal
BEFORE UPDATE ON jvm_external_owners
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id IN (OLD.provider_id, NEW.provider_id))
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;
CREATE TRIGGER jvm_external_owners_no_delete_after_seal
BEFORE DELETE ON jvm_external_owners
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id = OLD.provider_id)
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;

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

CREATE TRIGGER jvm_external_owner_supertypes_no_insert_after_seal
BEFORE INSERT ON jvm_external_owner_supertypes
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id = NEW.provider_id)
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;
CREATE TRIGGER jvm_external_owner_supertypes_no_update_after_seal
BEFORE UPDATE ON jvm_external_owner_supertypes
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id IN (OLD.provider_id, NEW.provider_id))
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;
CREATE TRIGGER jvm_external_owner_supertypes_no_delete_after_seal
BEFORE DELETE ON jvm_external_owner_supertypes
WHEN EXISTS (SELECT 1 FROM jvm_external_provider_publications WHERE provider_id = OLD.provider_id)
BEGIN SELECT RAISE(ABORT, 'sealed JVM external inventory is immutable'); END;
