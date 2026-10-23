CREATE TABLE jvm_external_owner_members_0197 (
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
    PRIMARY KEY(provider_id, owner_fqn, ordinal),
    FOREIGN KEY(provider_id, owner_fqn)
        REFERENCES jvm_external_owners(provider_id, owner_fqn) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO jvm_external_owner_members_0197
SELECT provider_id, owner_fqn, ordinal, member_name, member_kind,
       CASE visibility WHEN 'package' THEN 'package_private' ELSE visibility END,
       is_static, signature_present, callable_family_complete, non_overridable,
       parameters_jsonb, return_type_jsonb
FROM jvm_external_owner_members;

DROP TABLE jvm_external_owner_members;
ALTER TABLE jvm_external_owner_members_0197 RENAME TO jvm_external_owner_members;
CREATE INDEX jvm_external_owner_members_by_name
    ON jvm_external_owner_members(provider_id, owner_fqn, member_name);
