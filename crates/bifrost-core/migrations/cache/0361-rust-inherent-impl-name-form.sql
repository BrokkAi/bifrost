-- #11173 M2b slice 3: inherent-impl subjects are stored in the Rust child NAME form, with no
-- rank, and the two inherent-impl summary tables follow the Rust child convention (per-blob
-- dense ids plus member_ordinal, compared directly with resolution_unit_summary_members.blob_id).
-- Compatible: no build before this one reads the removed topology column subject_rank (it was
-- never filled) and the two summary tables have no writer or reader before it (empty, unread);
-- a build of an older version keeps its own version-suffixed store file.

-- The topology row keeps the all-or-none guard on its six name-form columns. SQLite drops a
-- column's own CHECKs with the column, so the guard moves to subject_origin, which is dropped and
-- added again. Existing rows have no name form yet (every column is NULL); a topology derived
-- under the new RUST_CRATE_DERIVATION_VERSION fills all six.
ALTER TABLE rust_crate_inherent_impls DROP COLUMN subject_rank;
ALTER TABLE rust_crate_inherent_impls DROP COLUMN subject_origin;
ALTER TABLE rust_crate_inherent_impls ADD COLUMN subject_origin TEXT CHECK((subject_unit_key IS NULL AND subject_module_path IS NULL AND subject_kind IS NULL AND subject_namespace IS NULL AND subject_name IS NULL AND subject_origin IS NULL) OR (subject_unit_key IS NOT NULL AND subject_module_path IS NOT NULL AND subject_kind IS NOT NULL AND subject_namespace IS NOT NULL AND subject_name IS NOT NULL AND subject_origin IS NOT NULL));

DROP TABLE rust_resolution_unit_summary_unresolved_inherent_impls;
DROP TABLE rust_resolution_unit_summary_inherent_impls;

-- A subject in this unit is a member plus the blob's dense definition site. One in another
-- unit is the NAME form (unit key, module path, kind, namespace, name, origin): it names every
-- declaration of that name in that module, so a consumer must treat a name-form subject that
-- matches more than one declaration (cfg alternatives, macro textual scope, producer
-- duplicates) as ambiguous and unproven, never as its first match.
-- subject_kind of a foreign subject is 'declaration' (a source declaration), its namespace is
-- 'type', and subject_origin is 'declaration': an inherent impl names a nominal type
-- declaration, never a re-export.
-- One row per impl placement member and per subject the impl resolved to. The topology
-- coalesces the module placements of one physical impl, so a file that is a member in more
-- than one role (declared and included) yields one row for each member.
CREATE TABLE rust_resolution_unit_summary_inherent_impls (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 impl_member_ordinal INTEGER NOT NULL CHECK(impl_member_ordinal>=0),
 -- Dense reference site of the impl header in the impl member's blob.
 impl_site INTEGER NOT NULL CHECK(impl_site BETWEEN 0 AND 4294967295),
 -- Dense replay declaration id of the impl in the impl member's blob.
 impl_declaration_id INTEGER NOT NULL CHECK(impl_declaration_id BETWEEN 0 AND 4294967295),
 -- Summary-local position among the subjects of one impl site, in canonical order.
 subject_ordinal INTEGER NOT NULL CHECK(subject_ordinal>=0),
 subject_form TEXT NOT NULL CHECK(subject_form IN ('local_site','foreign')),
 subject_member_ordinal INTEGER CHECK(subject_member_ordinal>=0),
 -- Dense native definition site of the subject member's blob.
 subject_site INTEGER CHECK(subject_site BETWEEN 0 AND 4294967295),
 subject_unit_key BLOB CHECK(length(subject_unit_key)=32),
 subject_module_path TEXT,
 subject_kind TEXT,
 subject_namespace TEXT,
 subject_name TEXT,
 subject_origin TEXT,
 PRIMARY KEY(summary_id,impl_member_ordinal,impl_site,subject_ordinal),
 FOREIGN KEY(summary_id,impl_member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE,
 FOREIGN KEY(summary_id,subject_member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE,
 CHECK((subject_form='local_site' AND subject_member_ordinal IS NOT NULL AND subject_site IS NOT NULL AND subject_unit_key IS NULL AND subject_module_path IS NULL AND subject_kind IS NULL AND subject_namespace IS NULL AND subject_name IS NULL AND subject_origin IS NULL) OR (subject_form='foreign' AND subject_member_ordinal IS NULL AND subject_site IS NULL AND subject_unit_key IS NOT NULL AND subject_module_path IS NOT NULL AND subject_kind IS NOT NULL AND subject_namespace IS NOT NULL AND subject_name IS NOT NULL AND subject_origin IS NOT NULL))
) WITHOUT ROWID, STRICT;

CREATE INDEX rust_summary_inherent_subject ON rust_resolution_unit_summary_inherent_impls(subject_unit_key,subject_module_path,subject_kind,subject_namespace,subject_name,subject_origin,summary_id) WHERE subject_form='foreign';

CREATE INDEX rust_summary_inherent_local_subject ON rust_resolution_unit_summary_inherent_impls(summary_id,subject_member_ordinal,subject_site) WHERE subject_form='local_site';

CREATE INDEX rust_summary_inherent_declaration ON rust_resolution_unit_summary_inherent_impls(summary_id,impl_member_ordinal,impl_declaration_id);

-- An inherent impl whose subject names no single declaration. The impl is always in this unit.
-- spelling, impl_declaration_id and target_module_path stay NULL where the topology row has none.
CREATE TABLE rust_resolution_unit_summary_unresolved_inherent_impls (
 summary_id INTEGER NOT NULL REFERENCES resolution_unit_summaries(summary_id) ON DELETE CASCADE,
 spelling TEXT CHECK(spelling IS NULL OR length(spelling)>0),
 impl_member_ordinal INTEGER NOT NULL CHECK(impl_member_ordinal>=0),
 impl_site INTEGER NOT NULL CHECK(impl_site BETWEEN 0 AND 4294967295),
 impl_declaration_id INTEGER CHECK(impl_declaration_id IS NULL OR impl_declaration_id BETWEEN 0 AND 4294967295),
 reason TEXT NOT NULL CHECK(reason IN ('unbound','bound_without_declaration','impl_item_unbridged')),
 target_module_path TEXT CHECK(target_module_path IS NULL OR length(target_module_path)>0),
 PRIMARY KEY(summary_id,impl_member_ordinal,impl_site,reason),
 FOREIGN KEY(summary_id,impl_member_ordinal) REFERENCES resolution_unit_summary_members(summary_id,member_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX rust_summary_unresolved_inherent_declaration ON rust_resolution_unit_summary_unresolved_inherent_impls(summary_id,impl_member_ordinal,impl_declaration_id);
