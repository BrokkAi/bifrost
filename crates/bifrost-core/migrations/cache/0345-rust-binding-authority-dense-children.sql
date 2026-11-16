-- #11173 M2b slice 2: the four binding-authority tables of 0323 follow the Rust child
-- convention (per-blob dense ids plus member_ordinal, compared directly with
-- resolution_unit_summary_members.blob_id) instead of surface ordinals, and a foreign
-- declaration is a name-form reference without a rank.
-- Compatible: no writer or reader of these tables exists before this migration, so the
-- tables are empty and nothing reads them by their old column names; a build of an older
-- version keeps its own version-suffixed store file. They are dropped and recreated
-- because SQLite cannot drop a column that table CHECKs name.
DROP TABLE rust_resolution_unit_summary_binding_blockers;
DROP TABLE rust_resolution_unit_summary_binding_alternatives;
DROP TABLE rust_resolution_unit_summary_binding_names;
DROP TABLE rust_resolution_unit_summary_binding_owners;

CREATE TABLE rust_resolution_unit_summary_binding_owners (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 -- Summary-local handle in canonical (module path, kind, member, scope) order.
 -- Never hashed into a digest or stored by another unit.
 owner_handle INTEGER NOT NULL CHECK(owner_handle>=0),
 module_path TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('module','local')),
 member_ordinal INTEGER CHECK(member_ordinal>=0),
 -- Dense source scope of the member's blob (members.blob_id).
 native_scope INTEGER CHECK(native_scope>=0),
 parent_owner_handle INTEGER CHECK(parent_owner_handle>=0),
 closed INTEGER NOT NULL CHECK(closed IN (0,1)),
 PRIMARY KEY(summary_id,owner_handle),
 CHECK((kind='module' AND member_ordinal IS NULL AND native_scope IS NULL) OR (kind='local' AND member_ordinal IS NOT NULL AND native_scope IS NOT NULL)),
 FOREIGN KEY(summary_id,member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,parent_owner_handle) REFERENCES rust_resolution_unit_summary_binding_owners(summary_id,owner_handle) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE UNIQUE INDEX rust_summary_module_owner ON rust_resolution_unit_summary_binding_owners(summary_id,module_path) WHERE kind='module';

CREATE UNIQUE INDEX rust_summary_local_owner ON rust_resolution_unit_summary_binding_owners(summary_id,module_path,member_ordinal,native_scope) WHERE kind='local';

CREATE TABLE rust_resolution_unit_summary_binding_names (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 owner_handle INTEGER NOT NULL CHECK(owner_handle>=0),
 namespace TEXT NOT NULL CHECK(namespace IN ('type','value','macro')),
 name TEXT NOT NULL CHECK(length(name)>0),
 complete INTEGER NOT NULL CHECK(complete IN (0,1)),
 PRIMARY KEY(summary_id,owner_handle,namespace,name),
 FOREIGN KEY(summary_id,owner_handle) REFERENCES rust_resolution_unit_summary_binding_owners(summary_id,owner_handle) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- A target or provider in this unit is a member plus the blob's dense ids. One in another
-- unit is the NAME form (unit key, module path, kind, namespace, name): it names every
-- declaration of that name in that module, so a consumer must treat a name-form reference
-- that matches more than one declaration (cfg alternatives, macro textual scope, producer
-- duplicates) as ambiguous and unproven, never as its first match.
-- target_kind of a foreign target is 'declaration' (a source declaration), 'generated' (a
-- macro-generated declaration) or 'module' (a module or crate anchor); target_origin is
-- 'declaration' because a binding endpoint is always a terminal declaration or anchor.
CREATE TABLE rust_resolution_unit_summary_binding_alternatives (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 alternative_handle INTEGER NOT NULL CHECK(alternative_handle>=0),
 owner_handle INTEGER NOT NULL CHECK(owner_handle>=0),
 namespace TEXT NOT NULL CHECK(namespace IN ('type','value','macro')),
 name TEXT NOT NULL CHECK(length(name)>0),
 -- The unit and module that declare the target, in every form: this unit's own key for
 -- 'anchor', 'local_site' and 'local_generated', another unit's for 'foreign'. One pair,
 -- so a foreign target is not stored twice.
 target_unit_key BLOB NOT NULL CHECK(length(target_unit_key)=32),
 target_module_path TEXT NOT NULL,
 target_name TEXT NOT NULL CHECK(length(target_name)>0),
 target_container_path TEXT,
 origin TEXT NOT NULL CHECK(origin IN ('declaration','named_import','glob')),
 target_form TEXT NOT NULL CHECK(target_form IN ('anchor','local_site','local_generated','foreign')),
 target_member_ordinal INTEGER CHECK(target_member_ordinal>=0),
 -- Dense native definition site of the member's blob.
 target_site INTEGER CHECK(target_site>=0),
 -- Dense replay declaration id of the member's blob.
 target_declaration_id INTEGER CHECK(target_declaration_id>=0),
 target_kind TEXT,
 target_namespace TEXT,
 target_origin TEXT,
 visibility TEXT NOT NULL CHECK(visibility IN ('public','crate','restricted','private')),
 restricted_module_path TEXT,
 provider_form TEXT NOT NULL CHECK(provider_form IN ('none','module','local','foreign')),
 provider_member_ordinal INTEGER CHECK(provider_member_ordinal>=0),
 provider_native_scope INTEGER CHECK(provider_native_scope>=0),
 provider_unit_key BLOB CHECK(length(provider_unit_key)=32),
 provider_module_path TEXT,
 provider_kind TEXT,
 provider_namespace TEXT,
 provider_name TEXT,
 provider_origin TEXT,
 glob_visibility TEXT CHECK(glob_visibility IN ('public','crate','restricted','private')),
 glob_restricted_module_path TEXT,
 PRIMARY KEY(summary_id,alternative_handle),
 FOREIGN KEY(summary_id,owner_handle,namespace,name) REFERENCES rust_resolution_unit_summary_binding_names(summary_id,owner_handle,namespace,name) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,target_member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,provider_member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE,
 CHECK((target_form='anchor' AND target_member_ordinal IS NULL AND target_site IS NULL AND target_declaration_id IS NULL AND target_kind IS NULL AND target_namespace IS NULL AND target_origin IS NULL) OR (target_form='local_site' AND target_member_ordinal IS NOT NULL AND target_site IS NOT NULL AND target_declaration_id IS NULL AND target_kind IS NULL AND target_namespace IS NULL AND target_origin IS NULL) OR (target_form='local_generated' AND target_member_ordinal IS NOT NULL AND target_declaration_id IS NOT NULL AND target_site IS NULL AND target_kind IS NULL AND target_namespace IS NULL AND target_origin IS NULL) OR (target_form='foreign' AND target_member_ordinal IS NULL AND target_site IS NULL AND target_declaration_id IS NULL AND target_kind IS NOT NULL AND target_namespace IS NOT NULL AND target_origin IS NOT NULL)),
 CHECK((visibility='restricted')=(restricted_module_path IS NOT NULL)),
 CHECK((provider_form='none' AND provider_member_ordinal IS NULL AND provider_native_scope IS NULL AND provider_unit_key IS NULL AND provider_module_path IS NULL AND provider_kind IS NULL AND provider_namespace IS NULL AND provider_name IS NULL AND provider_origin IS NULL) OR (provider_form='module' AND provider_member_ordinal IS NULL AND provider_native_scope IS NULL AND provider_unit_key IS NOT NULL AND provider_module_path IS NOT NULL AND provider_kind IS NULL AND provider_namespace IS NULL AND provider_name IS NULL AND provider_origin IS NULL) OR (provider_form='local' AND provider_member_ordinal IS NOT NULL AND provider_native_scope IS NOT NULL AND provider_unit_key IS NOT NULL AND provider_module_path IS NOT NULL AND provider_kind IS NULL AND provider_namespace IS NULL AND provider_name IS NULL AND provider_origin IS NULL) OR (provider_form='foreign' AND provider_member_ordinal IS NULL AND provider_native_scope IS NULL AND provider_unit_key IS NOT NULL AND provider_module_path IS NOT NULL AND provider_kind IS NOT NULL AND provider_namespace IS NOT NULL AND provider_name IS NOT NULL AND provider_origin IS NOT NULL)),
 CHECK((origin='glob')=(provider_form<>'none')),
 CHECK((origin='glob')=(glob_visibility IS NOT NULL)),
 CHECK(glob_visibility IS NULL OR ((glob_visibility='restricted')=(glob_restricted_module_path IS NOT NULL)))
) WITHOUT ROWID, STRICT;

CREATE INDEX rust_summary_alternatives_owner ON rust_resolution_unit_summary_binding_alternatives(summary_id,owner_handle,namespace,name);

-- Blocker evidence is explanatory provenance, not a reference anything resolves. Evidence
-- from this unit also carries its own dense ids (member plus declaration id, invocation
-- occurrence id or import ordinal of the member's blob); evidence from another unit is
-- (evidence_unit_key, evidence_module_path, evidence_kind) alone.
--
-- evidence_form 'unplaced': the evidence is in this unit but the topology recorded no file
-- for it (an empty evidence rel_path), so a dense id is meaningless without its blob and
-- only evidence_unit_key, evidence_module_path and evidence_kind remain. All three are NOT
-- NULL, so an unplaced row always names its unit, module and kind. A reader that needs a
-- placement must treat 'unplaced' as "no location": never fabricate a member or path for
-- it, and never treat the row as absent, because the blocker still holds.
CREATE TABLE rust_resolution_unit_summary_binding_blockers (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 owner_handle INTEGER NOT NULL CHECK(owner_handle>=0),
 namespace TEXT NOT NULL CHECK(namespace IN ('type','value','macro')),
 name TEXT NOT NULL,
 reason TEXT NOT NULL CHECK(length(reason)>0),
 boundary TEXT NOT NULL,
 -- The unit and module of the evidence, in every form: this unit's own key for 'local',
 -- 'owner' and 'unplaced', another unit's for 'foreign'. One pair, so a foreign
 -- evidence row is not stored twice.
 evidence_unit_key BLOB NOT NULL CHECK(length(evidence_unit_key)=32),
 evidence_module_path TEXT NOT NULL,
 evidence_kind TEXT NOT NULL CHECK(evidence_kind IN ('declaration','macro','import','owner')),
 blocker_ordinal INTEGER NOT NULL CHECK(blocker_ordinal>=0),
 -- 'unplaced' means "no location recorded", not "no evidence": see the table comment.
 evidence_form TEXT NOT NULL CHECK(evidence_form IN ('local','owner','unplaced','foreign')),
 evidence_member_ordinal INTEGER CHECK(evidence_member_ordinal>=0),
 evidence_declaration_id INTEGER CHECK(evidence_declaration_id>=0),
 evidence_invocation_occurrence_id INTEGER CHECK(evidence_invocation_occurrence_id>=0),
 evidence_import_ordinal INTEGER CHECK(evidence_import_ordinal>=0),
 evidence_owner_handle INTEGER CHECK(evidence_owner_handle>=0),
 CHECK((evidence_form='local' AND evidence_kind='declaration' AND evidence_member_ordinal IS NOT NULL AND evidence_declaration_id IS NOT NULL AND evidence_invocation_occurrence_id IS NULL AND evidence_import_ordinal IS NULL AND evidence_owner_handle IS NULL) OR (evidence_form='local' AND evidence_kind='macro' AND evidence_member_ordinal IS NOT NULL AND evidence_invocation_occurrence_id IS NOT NULL AND evidence_declaration_id IS NULL AND evidence_import_ordinal IS NULL AND evidence_owner_handle IS NULL) OR (evidence_form='local' AND evidence_kind='import' AND evidence_member_ordinal IS NOT NULL AND evidence_import_ordinal IS NOT NULL AND evidence_declaration_id IS NULL AND evidence_invocation_occurrence_id IS NULL AND evidence_owner_handle IS NULL) OR (evidence_form='owner' AND evidence_kind='owner' AND evidence_owner_handle IS NOT NULL AND evidence_member_ordinal IS NULL AND evidence_declaration_id IS NULL AND evidence_invocation_occurrence_id IS NULL AND evidence_import_ordinal IS NULL) OR (evidence_form='unplaced' AND evidence_kind<>'owner' AND evidence_member_ordinal IS NULL AND evidence_declaration_id IS NULL AND evidence_invocation_occurrence_id IS NULL AND evidence_import_ordinal IS NULL AND evidence_owner_handle IS NULL) OR (evidence_form='foreign' AND evidence_member_ordinal IS NULL AND evidence_declaration_id IS NULL AND evidence_invocation_occurrence_id IS NULL AND evidence_import_ordinal IS NULL AND evidence_owner_handle IS NULL)),
 PRIMARY KEY(summary_id,owner_handle,namespace,name,blocker_ordinal),
 FOREIGN KEY(summary_id,owner_handle) REFERENCES rust_resolution_unit_summary_binding_owners(summary_id,owner_handle) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,evidence_member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,evidence_owner_handle) REFERENCES rust_resolution_unit_summary_binding_owners(summary_id,owner_handle) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
