-- #11173 M2b: summary-owned representations; writers follow in slice 1b.
CREATE TABLE resolution_unit_summary_input_files (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 input_ordinal INTEGER NOT NULL CHECK(input_ordinal>=0),
 rel_path TEXT NOT NULL CHECK(length(rel_path)>0),
 source_role TEXT NOT NULL CHECK(length(source_role)>0),
 PRIMARY KEY(summary_id,input_ordinal),
 UNIQUE(summary_id,source_role,rel_path)
) WITHOUT ROWID, STRICT;

CREATE TABLE rust_resolution_unit_summary_binding_owners (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 owner_handle INTEGER NOT NULL CHECK(owner_handle>=0),
 module_path TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('module','local')),
 member_ordinal INTEGER CHECK(member_ordinal>=0),
 scope_surface_ordinal INTEGER CHECK(scope_surface_ordinal>=0),
 parent_owner_handle INTEGER CHECK(parent_owner_handle>=0),
 closed INTEGER NOT NULL CHECK(closed IN (0,1)),
 PRIMARY KEY(summary_id,owner_handle),
 CHECK((kind='module' AND member_ordinal IS NULL AND scope_surface_ordinal IS NULL) OR (kind='local' AND member_ordinal IS NOT NULL AND scope_surface_ordinal IS NOT NULL)),
 FOREIGN KEY(summary_id,member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,parent_owner_handle) REFERENCES rust_resolution_unit_summary_binding_owners(summary_id,owner_handle) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE UNIQUE INDEX rust_summary_module_owner ON rust_resolution_unit_summary_binding_owners(summary_id,module_path) WHERE kind='module';

CREATE UNIQUE INDEX rust_summary_local_owner ON rust_resolution_unit_summary_binding_owners(summary_id,module_path,member_ordinal,scope_surface_ordinal) WHERE kind='local';

CREATE TABLE rust_resolution_unit_summary_binding_names (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 owner_handle INTEGER NOT NULL CHECK(owner_handle>=0),
 namespace TEXT NOT NULL CHECK(namespace IN ('type','value','macro')),
 name TEXT NOT NULL CHECK(length(name)>0),
 complete INTEGER NOT NULL CHECK(complete IN (0,1)),
 PRIMARY KEY(summary_id,owner_handle,namespace,name),
 FOREIGN KEY(summary_id,owner_handle) REFERENCES rust_resolution_unit_summary_binding_owners(summary_id,owner_handle) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE rust_resolution_unit_summary_binding_alternatives (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 alternative_handle INTEGER NOT NULL CHECK(alternative_handle>=0),
 owner_handle INTEGER NOT NULL CHECK(owner_handle>=0),
 namespace TEXT NOT NULL CHECK(namespace IN ('type','value','macro')),
 name TEXT NOT NULL CHECK(length(name)>0),
 target_owner_unit_key BLOB NOT NULL CHECK(length(target_owner_unit_key)=32),
 target_owner_module_path TEXT NOT NULL,
 target_name TEXT NOT NULL CHECK(length(target_name)>0),
 target_container_path TEXT,
 origin TEXT NOT NULL CHECK(origin IN ('declaration','named_import','glob')),
 target_form TEXT NOT NULL CHECK(target_form IN ('anchor','local_site','local_generated','foreign')),
 target_member_ordinal INTEGER CHECK(target_member_ordinal>=0),
 target_site_surface_ordinal INTEGER CHECK(target_site_surface_ordinal>=0),
 target_declaration_surface_ordinal INTEGER CHECK(target_declaration_surface_ordinal>=0),
 target_unit_key BLOB CHECK(length(target_unit_key)=32),
 target_module_path TEXT,
 target_kind TEXT,
 target_namespace TEXT,
 target_origin TEXT,
 target_rank INTEGER CHECK(target_rank>=0),
 visibility TEXT NOT NULL CHECK(visibility IN ('public','crate','restricted','private')),
 restricted_module_path TEXT,
 provider_form TEXT NOT NULL CHECK(provider_form IN ('none','module','local','foreign')),
 provider_member_ordinal INTEGER CHECK(provider_member_ordinal>=0),
 provider_scope_surface_ordinal INTEGER CHECK(provider_scope_surface_ordinal>=0),
 provider_unit_key BLOB CHECK(length(provider_unit_key)=32),
 provider_module_path TEXT,
 provider_kind TEXT,
 provider_namespace TEXT,
 provider_name TEXT,
 provider_origin TEXT,
 provider_rank INTEGER CHECK(provider_rank>=0),
 glob_visibility TEXT CHECK(glob_visibility IN ('public','crate','restricted','private')),
 glob_restricted_module_path TEXT,
 PRIMARY KEY(summary_id,alternative_handle),
 FOREIGN KEY(summary_id,owner_handle,namespace,name) REFERENCES rust_resolution_unit_summary_binding_names(summary_id,owner_handle,namespace,name) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,target_member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,provider_member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE,
 CHECK((target_form='anchor' AND target_member_ordinal IS NULL AND target_site_surface_ordinal IS NULL AND target_declaration_surface_ordinal IS NULL AND target_unit_key IS NULL AND target_module_path IS NULL AND target_kind IS NULL AND target_namespace IS NULL AND target_origin IS NULL AND target_rank IS NULL) OR (target_form='local_site' AND target_member_ordinal IS NOT NULL AND target_site_surface_ordinal IS NOT NULL AND target_declaration_surface_ordinal IS NULL AND target_unit_key IS NULL AND target_module_path IS NULL AND target_kind IS NULL AND target_namespace IS NULL AND target_origin IS NULL AND target_rank IS NULL) OR (target_form='local_generated' AND target_member_ordinal IS NOT NULL AND target_declaration_surface_ordinal IS NOT NULL AND target_site_surface_ordinal IS NULL AND target_unit_key IS NULL AND target_module_path IS NULL AND target_kind IS NULL AND target_namespace IS NULL AND target_origin IS NULL AND target_rank IS NULL) OR (target_form='foreign' AND target_member_ordinal IS NULL AND target_site_surface_ordinal IS NULL AND target_declaration_surface_ordinal IS NULL AND target_unit_key IS NOT NULL AND target_module_path IS NOT NULL AND target_kind IS NOT NULL AND target_namespace IS NOT NULL AND target_name IS NOT NULL AND target_origin IS NOT NULL AND target_rank IS NOT NULL)),
 CHECK((visibility='restricted')=(restricted_module_path IS NOT NULL)),
 CHECK((provider_form='none' AND provider_member_ordinal IS NULL AND provider_scope_surface_ordinal IS NULL AND provider_unit_key IS NULL AND provider_module_path IS NULL AND provider_kind IS NULL AND provider_namespace IS NULL AND provider_name IS NULL AND provider_origin IS NULL AND provider_rank IS NULL) OR (provider_form='module' AND provider_member_ordinal IS NULL AND provider_scope_surface_ordinal IS NULL AND provider_unit_key IS NOT NULL AND provider_module_path IS NOT NULL AND provider_kind IS NULL AND provider_namespace IS NULL AND provider_name IS NULL AND provider_origin IS NULL AND provider_rank IS NULL) OR (provider_form='local' AND provider_member_ordinal IS NOT NULL AND provider_scope_surface_ordinal IS NOT NULL AND provider_unit_key IS NOT NULL AND provider_module_path IS NOT NULL AND provider_kind IS NULL AND provider_namespace IS NULL AND provider_name IS NULL AND provider_origin IS NULL AND provider_rank IS NULL) OR (provider_form='foreign' AND provider_member_ordinal IS NULL AND provider_scope_surface_ordinal IS NULL AND provider_unit_key IS NOT NULL AND provider_module_path IS NOT NULL AND provider_kind IS NOT NULL AND provider_namespace IS NOT NULL AND provider_name IS NOT NULL AND provider_origin IS NOT NULL AND provider_rank IS NOT NULL)),
 CHECK((origin='glob')=(provider_form<>'none')),
 CHECK((origin='glob')=(glob_visibility IS NOT NULL)),
 CHECK(glob_visibility IS NULL OR ((glob_visibility='restricted')=(glob_restricted_module_path IS NOT NULL)))
) WITHOUT ROWID, STRICT;

CREATE INDEX rust_summary_alternatives_owner ON rust_resolution_unit_summary_binding_alternatives(summary_id,owner_handle,namespace,name);

CREATE TABLE rust_resolution_unit_summary_binding_blockers (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 owner_handle INTEGER NOT NULL CHECK(owner_handle>=0),
 namespace TEXT NOT NULL CHECK(namespace IN ('type','value','macro')),
 name TEXT NOT NULL,
 reason TEXT NOT NULL CHECK(length(reason)>0),
 boundary TEXT NOT NULL,
 evidence_owner_unit_key BLOB NOT NULL CHECK(length(evidence_owner_unit_key)=32),
 evidence_owner_module_path TEXT NOT NULL,
 evidence_kind TEXT NOT NULL CHECK(evidence_kind IN ('declaration','macro','import','owner')),
 blocker_ordinal INTEGER NOT NULL CHECK(blocker_ordinal>=0),
 evidence_form TEXT NOT NULL CHECK(evidence_form IN ('local','owner','foreign')),
 evidence_member_ordinal INTEGER CHECK(evidence_member_ordinal>=0),
 evidence_declaration_surface_ordinal INTEGER CHECK(evidence_declaration_surface_ordinal>=0),
 evidence_occurrence_surface_ordinal INTEGER CHECK(evidence_occurrence_surface_ordinal>=0),
 evidence_import_surface_ordinal INTEGER CHECK(evidence_import_surface_ordinal>=0),
 evidence_owner_handle INTEGER CHECK(evidence_owner_handle>=0),
 evidence_unit_key BLOB CHECK(length(evidence_unit_key)=32),
 evidence_module_path TEXT,
 CHECK((evidence_form='local' AND evidence_kind='declaration' AND evidence_member_ordinal IS NOT NULL AND evidence_declaration_surface_ordinal IS NOT NULL AND evidence_occurrence_surface_ordinal IS NULL AND evidence_import_surface_ordinal IS NULL AND evidence_owner_handle IS NULL AND evidence_unit_key IS NULL AND evidence_module_path IS NULL) OR (evidence_form='local' AND evidence_kind='macro' AND evidence_member_ordinal IS NOT NULL AND evidence_occurrence_surface_ordinal IS NOT NULL AND evidence_declaration_surface_ordinal IS NULL AND evidence_import_surface_ordinal IS NULL AND evidence_owner_handle IS NULL AND evidence_unit_key IS NULL AND evidence_module_path IS NULL) OR (evidence_form='local' AND evidence_kind='import' AND evidence_member_ordinal IS NOT NULL AND evidence_import_surface_ordinal IS NOT NULL AND evidence_declaration_surface_ordinal IS NULL AND evidence_occurrence_surface_ordinal IS NULL AND evidence_owner_handle IS NULL AND evidence_unit_key IS NULL AND evidence_module_path IS NULL) OR (evidence_form='owner' AND evidence_kind='owner' AND evidence_owner_handle IS NOT NULL AND evidence_member_ordinal IS NULL AND evidence_declaration_surface_ordinal IS NULL AND evidence_occurrence_surface_ordinal IS NULL AND evidence_import_surface_ordinal IS NULL AND evidence_unit_key IS NULL AND evidence_module_path IS NULL) OR (evidence_form='foreign' AND evidence_unit_key IS NOT NULL AND evidence_module_path IS NOT NULL AND evidence_member_ordinal IS NULL AND evidence_declaration_surface_ordinal IS NULL AND evidence_occurrence_surface_ordinal IS NULL AND evidence_import_surface_ordinal IS NULL AND evidence_owner_handle IS NULL)),
 PRIMARY KEY(summary_id,owner_handle,namespace,name,blocker_ordinal),
 FOREIGN KEY(summary_id,owner_handle) REFERENCES rust_resolution_unit_summary_binding_owners(summary_id,owner_handle) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,evidence_member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,evidence_owner_handle) REFERENCES rust_resolution_unit_summary_binding_owners(summary_id,owner_handle) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE rust_resolution_unit_summary_inherent_impls (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 impl_member_ordinal INTEGER NOT NULL CHECK(impl_member_ordinal>=0),
 impl_site_surface_ordinal INTEGER NOT NULL CHECK(impl_site_surface_ordinal>=0),
 impl_declaration_surface_ordinal INTEGER NOT NULL CHECK(impl_declaration_surface_ordinal>=0),
 subject_ordinal INTEGER NOT NULL CHECK(subject_ordinal>=0),
 subject_form TEXT NOT NULL CHECK(subject_form IN ('local_site','foreign')),
 subject_member_ordinal INTEGER CHECK(subject_member_ordinal>=0),
 subject_site_surface_ordinal INTEGER CHECK(subject_site_surface_ordinal>=0),
 subject_declaration_surface_ordinal INTEGER CHECK(subject_declaration_surface_ordinal>=0),
 subject_unit_key BLOB CHECK(length(subject_unit_key)=32),
 subject_module_path TEXT,
 subject_kind TEXT,
 subject_namespace TEXT,
 subject_name TEXT,
 subject_origin TEXT,
 subject_rank INTEGER CHECK(subject_rank>=0),
 PRIMARY KEY(summary_id,impl_member_ordinal,impl_site_surface_ordinal,subject_ordinal),
 FOREIGN KEY(summary_id,impl_member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,subject_member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE,
 CHECK((subject_form='local_site' AND subject_member_ordinal IS NOT NULL AND subject_site_surface_ordinal IS NOT NULL AND subject_declaration_surface_ordinal IS NULL AND subject_unit_key IS NULL AND subject_module_path IS NULL AND subject_kind IS NULL AND subject_namespace IS NULL AND subject_name IS NULL AND subject_origin IS NULL AND subject_rank IS NULL) OR (subject_form='foreign' AND subject_member_ordinal IS NULL AND subject_site_surface_ordinal IS NULL AND subject_declaration_surface_ordinal IS NULL AND subject_unit_key IS NOT NULL AND subject_module_path IS NOT NULL AND subject_kind IS NOT NULL AND subject_namespace IS NOT NULL AND subject_name IS NOT NULL AND subject_origin IS NOT NULL AND subject_rank IS NOT NULL))
) WITHOUT ROWID, STRICT;

CREATE INDEX rust_summary_inherent_subject ON rust_resolution_unit_summary_inherent_impls(subject_unit_key,subject_module_path,subject_kind,subject_namespace,subject_name,subject_origin,subject_rank,summary_id) WHERE subject_form='foreign';

CREATE INDEX rust_summary_inherent_local_subject ON rust_resolution_unit_summary_inherent_impls(summary_id,subject_member_ordinal,subject_site_surface_ordinal) WHERE subject_form='local_site';

CREATE INDEX rust_summary_inherent_declaration ON rust_resolution_unit_summary_inherent_impls(summary_id,impl_member_ordinal,impl_declaration_surface_ordinal);

CREATE TABLE rust_resolution_unit_summary_unresolved_inherent_impls (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 spelling TEXT CHECK(spelling IS NULL OR length(spelling)>0),
 impl_member_ordinal INTEGER NOT NULL CHECK(impl_member_ordinal>=0),
 impl_site_surface_ordinal INTEGER NOT NULL CHECK(impl_site_surface_ordinal>=0),
 impl_declaration_surface_ordinal INTEGER CHECK(impl_declaration_surface_ordinal>=0),
 reason TEXT NOT NULL CHECK(reason IN ('unbound','bound_without_declaration','impl_item_unbridged')),
 target_module_path TEXT CHECK(target_module_path IS NULL OR length(target_module_path)>0),
 PRIMARY KEY(summary_id,impl_member_ordinal,impl_site_surface_ordinal,reason),
 FOREIGN KEY(summary_id,impl_member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX rust_summary_unresolved_inherent_declaration ON rust_resolution_unit_summary_unresolved_inherent_impls(summary_id,impl_member_ordinal,impl_declaration_surface_ordinal);

CREATE TABLE rust_resolution_unit_summary_public_surface_gaps (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 gap_kind TEXT NOT NULL CHECK(gap_kind IN ('external_dependency','unsupported_manifest','inactive_placement','unknown_activation','unplaced_module','duplicate_placement','unresolved_import','unresolved_reexport','open_export_inventory','unresolved_visibility','unresolved_trait_impl')),
 subject TEXT NOT NULL CHECK(subject LIKE 'public-module-surface:%'),
 PRIMARY KEY(summary_id,gap_kind,subject)
) WITHOUT ROWID, STRICT;

CREATE VIEW rust_resolution_unit_summary_all_gaps AS SELECT summary_id,gap_kind,subject FROM rust_resolution_unit_summary_gaps UNION ALL SELECT summary_id,gap_kind,subject FROM rust_resolution_unit_summary_public_surface_gaps;

CREATE TABLE rust_resolution_unit_summary_inactive_placements (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 -- Summary-local handle: canonical mapped-tuple order (NULL scope first).
 -- Never hashed into a digest or stored by another unit.
 placement_ordinal INTEGER NOT NULL CHECK(placement_ordinal>=0),
 module_path TEXT NOT NULL,
 input_file_ordinal INTEGER NOT NULL CHECK(input_file_ordinal>=0),
 placement TEXT NOT NULL,
 module_scope_surface_ordinal INTEGER CHECK(module_scope_surface_ordinal>=0),
 activation INTEGER NOT NULL CHECK(activation IN (-1,0)),
 PRIMARY KEY(summary_id,placement_ordinal),
 -- NULL scopes are deduplicated by the writer before canonical numbering.
 UNIQUE(summary_id,module_path,input_file_ordinal,placement,module_scope_surface_ordinal,activation),
 FOREIGN KEY(summary_id,input_file_ordinal) REFERENCES resolution_unit_summary_input_files(summary_id,input_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX rust_summary_inactive_input ON rust_resolution_unit_summary_inactive_placements(summary_id,input_file_ordinal);

CREATE INDEX resolution_unit_summary_input_files_path ON resolution_unit_summary_input_files(rel_path,summary_id,input_ordinal);


-- Legacy rows have no broad-placement completeness proof.
ALTER TABLE rust_resolution_unit_summary_contexts ADD COLUMN broad_complete INTEGER NOT NULL DEFAULT 0 CHECK(broad_complete IN (0,1));
ALTER TABLE rust_crate_inherent_impls ADD COLUMN subject_unit_key BLOB CHECK(length(subject_unit_key)=32);
ALTER TABLE rust_crate_inherent_impls ADD COLUMN subject_module_path TEXT;
ALTER TABLE rust_crate_inherent_impls ADD COLUMN subject_kind TEXT;
ALTER TABLE rust_crate_inherent_impls ADD COLUMN subject_namespace TEXT;
ALTER TABLE rust_crate_inherent_impls ADD COLUMN subject_name TEXT;
ALTER TABLE rust_crate_inherent_impls ADD COLUMN subject_origin TEXT;
ALTER TABLE rust_crate_inherent_impls ADD COLUMN subject_rank INTEGER CHECK(subject_rank>=0) CHECK((subject_unit_key IS NULL AND subject_module_path IS NULL AND subject_kind IS NULL AND subject_namespace IS NULL AND subject_name IS NULL AND subject_origin IS NULL AND subject_rank IS NULL) OR (subject_unit_key IS NOT NULL AND subject_module_path IS NOT NULL AND subject_kind IS NOT NULL AND subject_namespace IS NOT NULL AND subject_name IS NOT NULL AND subject_origin IS NOT NULL AND subject_rank IS NOT NULL));
