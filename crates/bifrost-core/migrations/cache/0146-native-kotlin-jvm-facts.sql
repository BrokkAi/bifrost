-- Persist language-neutral facts shared by Kotlin and Scala source producers,
-- plus the JVM aliases that project authored declarations to binary names.
-- These rows carry source-site ids, including call, pattern, package and
-- import nodes that are not semantic reference/definition rows in
-- resolution_sites. Their source producers validate site ownership before
-- lowering; the database keeps their ids scoped to the fragment interior.
-- Import provenance is shared by Java and Scala producers. Java contributes
-- its type/static-specific route kinds; Scala contributes named/star routes.
-- Rebuild the catalog so schema-145 stores retain existing identities while
-- accepting both source languages' structured import facts.
DROP TRIGGER resolution_catalog_authority_seal;
DROP TRIGGER resolution_fragment_interiors_validate_node_payloads;
CREATE TABLE resolution_semantic_catalog_0145 (
  blob_id INTEGER NOT NULL,
  local_key INTEGER NOT NULL CHECK(local_key >= 0),
  identity_digest BLOB CHECK(identity_digest IS NULL OR (typeof(identity_digest)='blob' AND length(identity_digest)=32)),
  shared_identity INTEGER REFERENCES resolution_identities(id),
  import_source_site INTEGER CHECK(import_source_site IS NULL OR import_source_site BETWEEN 0 AND 4294967295),
  import_start_byte INTEGER CHECK(import_start_byte IS NULL OR import_start_byte>=0),
  import_end_byte INTEGER CHECK(import_end_byte IS NULL OR import_end_byte>=import_start_byte),
  import_route_kind TEXT,
  CHECK((identity_digest IS NULL) <> (shared_identity IS NULL)),
  CHECK((import_source_site IS NULL AND import_start_byte IS NULL
         AND import_end_byte IS NULL AND import_route_kind IS NULL)
    OR (import_source_site IS NOT NULL AND import_start_byte IS NOT NULL
        AND import_end_byte IS NOT NULL AND import_route_kind IS NOT NULL
        AND shared_identity IS NULL
        AND import_route_kind IN (
          'single_type','type_on_demand','single_static','static_on_demand','named','star'))),
  PRIMARY KEY(blob_id, local_key),
  UNIQUE(blob_id, identity_digest),
  UNIQUE(blob_id, shared_identity),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
INSERT INTO resolution_semantic_catalog_0145(
  blob_id, local_key, identity_digest, shared_identity,
  import_source_site, import_start_byte, import_end_byte, import_route_kind
)
SELECT blob_id, local_key, identity_digest, shared_identity,
       import_source_site, import_start_byte, import_end_byte, import_route_kind
FROM resolution_semantic_catalog;
DROP TABLE resolution_semantic_catalog;
ALTER TABLE resolution_semantic_catalog_0145 RENAME TO resolution_semantic_catalog;
CREATE TRIGGER resolution_catalog_authority_seal
BEFORE UPDATE OF publication_state ON resolution_fragment_interiors
WHEN NEW.publication_state='complete' AND (
  NEW.expected_rust_reference_context_count <> (SELECT COUNT(*) FROM resolution_rust_reference_contexts WHERE blob_id=NEW.blob_id)
  OR NEW.expected_rust_declaration_authority_count <> (SELECT COUNT(*) FROM resolution_rust_declaration_authorities WHERE blob_id=NEW.blob_id)
  OR
  NEW.expected_semantic_catalog_count <> (SELECT COUNT(*) FROM resolution_semantic_catalog WHERE blob_id=NEW.blob_id)
  OR NEW.expected_node_catalog_count <> (SELECT COUNT(*) FROM resolution_node_catalog WHERE blob_id=NEW.blob_id)
  OR NEW.expected_contract_reference_count <> (SELECT COUNT(*) FROM resolution_contract_references WHERE blob_id=NEW.blob_id)
)
BEGIN SELECT RAISE(ABORT, 'resolution catalog authority is incomplete'); END;

CREATE TRIGGER resolution_fragment_interiors_validate_node_payloads
BEFORE UPDATE OF publication_state ON resolution_fragment_interiors
WHEN OLD.publication_state='building' AND NEW.publication_state='complete'
 AND EXISTS (
   SELECT 1 FROM resolution_node_catalog AS node WHERE node.blob_id=NEW.blob_id
     AND (
       (node.semantic_local_key IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM resolution_semantic_catalog AS semantic
         WHERE semantic.blob_id=node.blob_id AND semantic.local_key=node.semantic_local_key
           AND semantic.shared_identity IS NULL
       ))
       OR (node.semantic_shared_identity IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM resolution_semantic_catalog AS semantic
         WHERE semantic.blob_id=node.blob_id AND semantic.shared_identity=node.semantic_shared_identity
       ))
       OR (node.target_local_key IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM resolution_node_catalog AS target
         WHERE target.blob_id=node.blob_id AND target.local_key=node.target_local_key
       ))
       OR (node.kind IN (8,9) AND NOT EXISTS (
         SELECT 1 FROM resolution_sites AS site
         JOIN resolution_semantic_catalog AS semantic
           ON semantic.blob_id=site.blob_id AND semantic.local_key=site.site
         WHERE site.blob_id=node.blob_id AND site.site=node.local_key
           AND site.role=CASE node.kind WHEN 8 THEN 0 ELSE 1 END
           AND ((node.semantic_local_key=semantic.local_key AND semantic.shared_identity IS NULL)
             OR node.semantic_shared_identity=semantic.shared_identity)
       ))
     )
 )
BEGIN
  SELECT RAISE(ABORT, 'resolution node payload is inconsistent');
END;

ALTER TABLE resolution_supertypes ADD COLUMN parent_ordinal
  INTEGER NOT NULL DEFAULT 0 CHECK(parent_ordinal >= 0);
CREATE INDEX resolution_supertypes_parent_order
  ON resolution_supertypes(blob_id, definition, parent_ordinal, reference);

ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_call_argument_list_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_call_argument_list_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_call_argument_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_call_argument_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_callable_parameter_list_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_callable_parameter_list_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_callable_parameter_semantics_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_callable_parameter_semantics_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_extension_receiver_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_extension_receiver_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_import_selector_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_import_selector_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_invocation_role_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_invocation_role_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_jvm_alias_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_jvm_alias_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_jvm_alias_owner_segment_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_jvm_alias_owner_segment_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_package_object_export_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_package_object_export_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_package_route_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_package_route_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_package_route_segment_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_package_route_segment_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_singleton_relation_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_singleton_relation_count >= 0);

CREATE TABLE resolution_call_argument_lists (
  blob_id       INTEGER NOT NULL,
  call_site     INTEGER NOT NULL CHECK(call_site >= 0),
  list_ordinal  INTEGER NOT NULL CHECK(list_ordinal >= 0),
  PRIMARY KEY(blob_id, call_site, list_ordinal),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE resolution_call_arguments (
  blob_id             INTEGER NOT NULL,
  call_site           INTEGER NOT NULL CHECK(call_site >= 0),
  list_ordinal        INTEGER NOT NULL CHECK(list_ordinal >= 0),
  ordinal             INTEGER NOT NULL CHECK(ordinal >= 0),
  value_semantic_key  INTEGER NOT NULL CHECK(value_semantic_key >= 0),
  label               TEXT CHECK(label IS NULL OR length(label) > 0),
  PRIMARY KEY(blob_id, call_site, list_ordinal, ordinal),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, call_site, list_ordinal)
    REFERENCES resolution_call_argument_lists(blob_id, call_site, list_ordinal)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, value_semantic_key)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

-- Bound parent-side FK probes for each referenced semantic-catalog row.
CREATE INDEX resolution_call_arguments_value_semantic_key
  ON resolution_call_arguments(blob_id, value_semantic_key);

CREATE TABLE resolution_callable_parameter_lists (
  blob_id        INTEGER NOT NULL,
  callable_site  INTEGER NOT NULL CHECK(callable_site >= 0),
  list_ordinal   INTEGER NOT NULL CHECK(list_ordinal >= 0),
  PRIMARY KEY(blob_id, callable_site, list_ordinal),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE resolution_callable_parameter_semantics (
  blob_id        INTEGER NOT NULL,
  callable_site  INTEGER NOT NULL CHECK(callable_site >= 0),
  parameter_site INTEGER NOT NULL CHECK(parameter_site >= 0),
  list_ordinal   INTEGER NOT NULL CHECK(list_ordinal >= 0),
  ordinal        INTEGER NOT NULL CHECK(ordinal >= 0),
  label          TEXT NOT NULL CHECK(length(label) > 0),
  has_default    INTEGER NOT NULL CHECK(has_default IN (0, 1)),
  PRIMARY KEY(blob_id, callable_site, list_ordinal, ordinal),
  UNIQUE(blob_id, parameter_site),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, callable_site, list_ordinal)
    REFERENCES resolution_callable_parameter_lists(blob_id, callable_site, list_ordinal)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, parameter_site) REFERENCES resolution_sites(blob_id, site)
    DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE resolution_extension_receivers (
  blob_id                   INTEGER NOT NULL,
  callable_site             INTEGER NOT NULL CHECK(callable_site >= 0),
  receiver_type_semantic_key INTEGER NOT NULL CHECK(receiver_type_semantic_key >= 0),
  PRIMARY KEY(blob_id, callable_site),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, callable_site) REFERENCES resolution_sites(blob_id, site)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, receiver_type_semantic_key)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_extension_receivers_receiver_type_semantic_key
  ON resolution_extension_receivers(blob_id, receiver_type_semantic_key);

CREATE TABLE resolution_import_selectors (
  blob_id     INTEGER NOT NULL,
  site        INTEGER NOT NULL CHECK(site >= 0),
  kind        TEXT NOT NULL CHECK(kind IN ('named', 'star', 'receiver_member')),
  source_name TEXT CHECK(source_name IS NULL OR length(source_name) > 0),
  local_name  TEXT CHECK(local_name IS NULL OR length(local_name) > 0),
  PRIMARY KEY(blob_id, site),
  CHECK((kind = 'named' AND source_name IS NOT NULL)
     OR (kind = 'star' AND source_name IS NULL AND local_name IS NULL)
     OR (kind = 'receiver_member' AND source_name IS NOT NULL)),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE resolution_invocation_roles (
  blob_id                INTEGER NOT NULL,
  site                   INTEGER NOT NULL CHECK(site >= 0),
  role                   TEXT NOT NULL CHECK(role IN ('direct', 'apply', 'unapply', 'unapply_seq')),
  receiver_semantic_key  INTEGER CHECK(receiver_semantic_key IS NULL OR receiver_semantic_key >= 0),
  result_semantic_key    INTEGER CHECK(result_semantic_key IS NULL OR result_semantic_key >= 0),
  PRIMARY KEY(blob_id, site),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, receiver_semantic_key)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, result_semantic_key)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_invocation_roles_receiver_semantic_key
  ON resolution_invocation_roles(blob_id, receiver_semantic_key);
CREATE INDEX resolution_invocation_roles_result_semantic_key
  ON resolution_invocation_roles(blob_id, result_semantic_key);

-- Keep rowid on the parent because the owner-segment family references it by
-- the composite blob-local alias identity.
CREATE TABLE resolution_jvm_aliases (
  blob_id          INTEGER NOT NULL,
  alias            INTEGER NOT NULL CHECK(alias >= 0),
  declaration_site INTEGER NOT NULL CHECK(declaration_site >= 0),
  member_name      TEXT NOT NULL CHECK(length(member_name) > 0),
  kind             TEXT NOT NULL CHECK(kind IN (
                     'field', 'getter', 'setter', 'method', 'constructor',
                     'companion_object', 'singleton_instance')),
  is_static        INTEGER NOT NULL CHECK(is_static IN (0, 1)),
  parameter_count  INTEGER NOT NULL CHECK(parameter_count >= 0),
  status           TEXT NOT NULL CHECK(status IN ('source_proven', 'compiler_mode_dependent')),
  PRIMARY KEY(blob_id, alias),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, declaration_site) REFERENCES resolution_sites(blob_id, site)
    DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE INDEX resolution_jvm_aliases_declaration_site
  ON resolution_jvm_aliases(blob_id, declaration_site);

CREATE TABLE resolution_jvm_alias_owner_segments (
  blob_id  INTEGER NOT NULL,
  alias    INTEGER NOT NULL CHECK(alias >= 0),
  ordinal  INTEGER NOT NULL CHECK(ordinal >= 0),
  spelling TEXT NOT NULL CHECK(length(spelling) > 0),
  PRIMARY KEY(blob_id, alias, ordinal),
  FOREIGN KEY(blob_id, alias) REFERENCES resolution_jvm_aliases(blob_id, alias)
    ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE TABLE resolution_package_object_exports (
  blob_id                INTEGER NOT NULL,
  package_object_site    INTEGER NOT NULL CHECK(package_object_site >= 0),
  member_site            INTEGER NOT NULL CHECK(member_site >= 0),
  package_scope_node_key INTEGER NOT NULL CHECK(package_scope_node_key >= 0),
  PRIMARY KEY(blob_id, package_object_site, member_site),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, package_object_site) REFERENCES resolution_sites(blob_id, site)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, member_site) REFERENCES resolution_sites(blob_id, site)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, package_scope_node_key)
    REFERENCES resolution_node_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_package_object_exports_member_site
  ON resolution_package_object_exports(blob_id, member_site);
CREATE INDEX resolution_package_object_exports_package_scope_node_key
  ON resolution_package_object_exports(blob_id, package_scope_node_key);

CREATE TABLE resolution_package_routes (
  blob_id                INTEGER NOT NULL,
  package_scope_node_key INTEGER NOT NULL CHECK(package_scope_node_key >= 0),
  declaration_site       INTEGER CHECK(declaration_site IS NULL OR declaration_site >= 0),
  placement_gap_site     INTEGER NOT NULL CHECK(placement_gap_site >= 0),
  PRIMARY KEY(blob_id, package_scope_node_key),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, package_scope_node_key)
    REFERENCES resolution_node_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE TABLE resolution_package_route_segments (
  blob_id                INTEGER NOT NULL,
  package_scope_node_key INTEGER NOT NULL CHECK(package_scope_node_key >= 0),
  ordinal                INTEGER NOT NULL CHECK(ordinal >= 0),
  spelling               TEXT NOT NULL CHECK(length(spelling) > 0),
  PRIMARY KEY(blob_id, package_scope_node_key, ordinal),
  FOREIGN KEY(blob_id, package_scope_node_key)
    REFERENCES resolution_package_routes(blob_id, package_scope_node_key)
    ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE TABLE resolution_singleton_relations (
  blob_id             INTEGER NOT NULL,
  declaration_site    INTEGER NOT NULL CHECK(declaration_site >= 0),
  enclosing_type_site INTEGER CHECK(enclosing_type_site IS NULL OR enclosing_type_site >= 0),
  kind                TEXT NOT NULL CHECK(kind IN ('object', 'companion')),
  PRIMARY KEY(blob_id, declaration_site),
  CHECK(enclosing_type_site IS NULL OR enclosing_type_site <> declaration_site),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id, declaration_site) REFERENCES resolution_sites(blob_id, site)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, enclosing_type_site) REFERENCES resolution_sites(blob_id, site)
    DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE INDEX resolution_singleton_relations_enclosing_type_site
  ON resolution_singleton_relations(blob_id, enclosing_type_site);

CREATE TRIGGER resolution_fragment_interiors_validate_shared_language_facts
BEFORE UPDATE OF publication_state ON resolution_fragment_interiors
WHEN OLD.publication_state = 'building' AND NEW.publication_state = 'complete'
 AND (
   EXISTS (
     SELECT 1 FROM resolution_jvm_aliases AS alias
     JOIN resolution_sites AS declaration
       ON declaration.blob_id = alias.blob_id
      AND declaration.site = alias.declaration_site
     WHERE alias.blob_id = NEW.blob_id AND declaration.role <> 1
   )
   OR EXISTS (
     SELECT 1 FROM resolution_jvm_aliases AS alias
     LEFT JOIN resolution_jvm_alias_owner_segments AS segment
       ON segment.blob_id = alias.blob_id AND segment.alias = alias.alias
     WHERE alias.blob_id = NEW.blob_id
     GROUP BY alias.alias
     HAVING count(segment.ordinal) = 0
        OR min(segment.ordinal) <> 0
        OR max(segment.ordinal) <> count(segment.ordinal) - 1
   )
   OR EXISTS (
     SELECT 1 FROM resolution_callable_parameter_semantics AS parameter
     JOIN resolution_sites AS callable
       ON callable.blob_id = parameter.blob_id AND callable.site = parameter.callable_site
     JOIN resolution_sites AS declaration
       ON declaration.blob_id = parameter.blob_id AND declaration.site = parameter.parameter_site
     WHERE parameter.blob_id = NEW.blob_id
       AND (callable.role <> 1 OR declaration.role <> 1)
   )
   OR EXISTS (
     SELECT 1 FROM resolution_call_argument_lists AS list
     WHERE list.blob_id = NEW.blob_id
     GROUP BY list.call_site
     HAVING min(list.list_ordinal) <> 0
        OR max(list.list_ordinal) <> count(*) - 1
   )
   OR EXISTS (
     SELECT 1 FROM resolution_callable_parameter_lists AS list
     WHERE list.blob_id = NEW.blob_id
     GROUP BY list.callable_site
     HAVING min(list.list_ordinal) <> 0
        OR max(list.list_ordinal) <> count(*) - 1
   )
   OR EXISTS (
     SELECT 1 FROM resolution_package_route_segments AS segment
     JOIN resolution_package_routes AS route
       ON route.blob_id = segment.blob_id
      AND route.package_scope_node_key = segment.package_scope_node_key
     WHERE segment.blob_id = NEW.blob_id
     GROUP BY segment.package_scope_node_key
     HAVING route.declaration_site IS NULL
        OR min(segment.ordinal) <> 0
        OR max(segment.ordinal) <> count(*) - 1
   )
   OR EXISTS (
     SELECT 1 FROM resolution_package_routes AS route
     JOIN resolution_sites AS declaration
       ON declaration.blob_id = route.blob_id
      AND declaration.site = route.declaration_site
     WHERE route.blob_id = NEW.blob_id AND declaration.role <> 1
   )
   OR EXISTS (
     SELECT 1 FROM resolution_package_object_exports AS export
     JOIN resolution_sites AS package_object
       ON package_object.blob_id = export.blob_id
      AND package_object.site = export.package_object_site
     JOIN resolution_sites AS member
       ON member.blob_id = export.blob_id
      AND member.site = export.member_site
     WHERE export.blob_id = NEW.blob_id
       AND (package_object.role <> 1 OR member.role <> 1)
   )
   OR EXISTS (
     SELECT 1 FROM resolution_extension_receivers AS receiver
     JOIN resolution_sites AS callable
       ON callable.blob_id = receiver.blob_id AND callable.site = receiver.callable_site
     WHERE receiver.blob_id = NEW.blob_id AND callable.role <> 1
   )
   OR EXISTS (
     SELECT 1 FROM resolution_singleton_relations AS relation
     JOIN resolution_sites AS declaration
       ON declaration.blob_id = relation.blob_id AND declaration.site = relation.declaration_site
     WHERE relation.blob_id = NEW.blob_id AND declaration.role <> 1
   )
 )
BEGIN
  SELECT RAISE(ABORT, 'resolution shared language fact rows are inconsistent');
END;
