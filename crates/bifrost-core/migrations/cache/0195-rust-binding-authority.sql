-- Own-binding authority, separate from request-time lexical inheritance and access.
-- Readers ask for one logical owner, then one namespace/name certificate and
-- its alternatives/reasons. Persistent owner ids compress child keys; they are
-- assigned here, never copied from the derivation's TEMP owner ids.
CREATE TABLE rust_crate_binding_owners(
  owner_id INTEGER PRIMARY KEY,
  topology_id INTEGER NOT NULL,
  module_path TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('module','local')),
  rel_path TEXT NOT NULL,
  scope_identity BLOB NOT NULL,
  blob_id INTEGER REFERENCES blobs(id),
  native_scope INTEGER CHECK(native_scope >= 0),
  parent_owner_id INTEGER REFERENCES rust_crate_binding_owners(owner_id),
  closed INTEGER NOT NULL CHECK(closed IN (0,1)),
  UNIQUE(topology_id,module_path,rel_path,scope_identity),
  CHECK((kind='module' AND rel_path='' AND length(scope_identity)=0
         AND blob_id IS NULL AND native_scope IS NULL)
     OR (kind='local' AND length(rel_path)>0 AND length(scope_identity)=32
         AND blob_id IS NOT NULL AND native_scope IS NOT NULL)),
  FOREIGN KEY(topology_id,module_path)
    REFERENCES rust_crate_containers(topology_id,container_path) ON DELETE CASCADE
) STRICT;

CREATE TABLE rust_crate_binding_names(
  owner_id INTEGER NOT NULL REFERENCES rust_crate_binding_owners(owner_id) ON DELETE CASCADE,
  namespace TEXT NOT NULL CHECK(namespace IN ('type','value','macro')),
  name TEXT NOT NULL CHECK(length(name)>0),
  complete INTEGER NOT NULL CHECK(complete IN (0,1)),
  PRIMARY KEY(owner_id,namespace,name)
) WITHOUT ROWID, STRICT;

-- Alternatives include distinct access witnesses to the same endpoint. The
-- endpoint alone cannot describe the visibility of a mixed glob group.
CREATE TABLE rust_crate_binding_alternatives(
  alternative_id INTEGER PRIMARY KEY,
  owner_id INTEGER NOT NULL,
  namespace TEXT NOT NULL,
  name TEXT NOT NULL,
  target_crate_key BLOB NOT NULL CHECK(length(target_crate_key)=32),
  target_module_path TEXT NOT NULL,
  target_name TEXT NOT NULL CHECK(length(target_name)>0),
  target_container_path TEXT,
  origin TEXT NOT NULL CHECK(origin IN ('declaration','named_import','glob')),
  declaration_blob_id INTEGER REFERENCES blobs(id),
  declaration_site INTEGER CHECK(declaration_site >= 0),
  generated_declaration_id INTEGER CHECK(generated_declaration_id >= 0),
  visibility TEXT NOT NULL CHECK(visibility IN ('public','crate','restricted','private')),
  restricted_module_path TEXT,
  provider_crate_key BLOB CHECK(provider_crate_key IS NULL OR length(provider_crate_key)=32),
  provider_module_path TEXT,
  provider_rel_path TEXT,
  provider_scope_identity BLOB,
  glob_visibility TEXT CHECK(glob_visibility IN ('public','crate','restricted','private')),
  glob_restricted_module_path TEXT,
  CHECK((origin='glob')=(provider_crate_key IS NOT NULL)),
  CHECK((origin='glob')=(provider_module_path IS NOT NULL)),
  CHECK((origin='glob')=(provider_rel_path IS NOT NULL)),
  CHECK((origin='glob')=(provider_scope_identity IS NOT NULL)),
  CHECK((origin='glob')=(glob_visibility IS NOT NULL)),
  CHECK((glob_visibility='restricted') IS (glob_restricted_module_path IS NOT NULL)
        OR glob_visibility IS NULL),
  -- A crate/module anchor has neither a declaration site nor a generated id.
  CHECK(declaration_site IS NULL OR generated_declaration_id IS NULL),
  CHECK(declaration_site IS NULL OR declaration_blob_id IS NOT NULL),
  CHECK(generated_declaration_id IS NULL OR declaration_blob_id IS NOT NULL),
  CHECK((visibility='restricted')=(restricted_module_path IS NOT NULL)),
  FOREIGN KEY(owner_id,namespace,name)
    REFERENCES rust_crate_binding_names(owner_id,namespace,name) ON DELETE CASCADE
) STRICT;
-- One exact-name read loads all endpoint/access alternatives together.
CREATE INDEX rust_crate_binding_alternatives_name
  ON rust_crate_binding_alternatives(owner_id,namespace,name);

-- name='' is an owner-wide blocker for every unlisted name in this namespace.
-- Evidence is a logical source or endpoint, never a fixpoint component number.
CREATE TABLE rust_crate_binding_blockers(
  owner_id INTEGER NOT NULL REFERENCES rust_crate_binding_owners(owner_id) ON DELETE CASCADE,
  namespace TEXT NOT NULL CHECK(namespace IN ('type','value','macro')),
  name TEXT NOT NULL,
  reason TEXT NOT NULL CHECK(length(reason)>0),
  boundary TEXT NOT NULL,
  evidence_crate_key BLOB NOT NULL CHECK(length(evidence_crate_key)=32),
  evidence_module_path TEXT NOT NULL,
  evidence_rel_path TEXT NOT NULL,
  evidence_kind TEXT NOT NULL,
  evidence_key INTEGER NOT NULL CHECK(evidence_key >= 0),
  PRIMARY KEY(owner_id,namespace,name,reason,boundary,evidence_crate_key,evidence_module_path,
              evidence_rel_path,evidence_kind,evidence_key)
) WITHOUT ROWID, STRICT;
