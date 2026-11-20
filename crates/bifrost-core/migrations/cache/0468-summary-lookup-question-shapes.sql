-- WORKING migration 0441; final slot is allocated in landing order.
-- Compatible summary-ledger constraint relaxation: rows and the new Drop receipt
-- columns survive unchanged. Version-suffixed cache files and the transactional
-- user_version check exclude older readers and writers from the relaxed shape.
-- Compatible JVM inventory generation: additive table and triggers preserve
-- existing inventory rows; old binaries use their separate versioned stores.
CREATE TABLE "class_set_summary_reads_new"(
  summary_id   INTEGER NOT NULL,
  read_ordinal INTEGER NOT NULL CHECK(read_ordinal >= 0),
  key_digest   BLOB    NOT NULL CHECK(length(key_digest) = 32),
  kind         TEXT    NOT NULL CHECK(kind IN (
    'file', 'path_absent', 'index', 'lookup', 'artifact', 'scope', 'models',
    'policy', 'configuration', 'epoch'
  )),
  family       TEXT,
  languages    TEXT,
  rel_path     TEXT,
  name         TEXT,
  structural_role TEXT,
  structural_keyword INTEGER CHECK(structural_keyword IN (0,1)),
  index_key    BLOB,
  blob_oid     TEXT CHECK(blob_oid IS NULL OR
    (length(blob_oid) = 40 AND blob_oid NOT GLOB '*[^0-9a-f]*')),
  subject      BLOB CHECK(subject IS NULL OR length(subject) = 32),
  parse_variant_kind TEXT CHECK(parse_variant_kind IS NULL OR parse_variant_kind IN ('empty', 'digest')),
  parse_variant_digest BLOB CHECK(parse_variant_digest IS NULL OR length(parse_variant_digest) = 32),
  start_byte   INTEGER CHECK(start_byte IS NULL OR start_byte >= 0),
  end_byte     INTEGER CHECK(end_byte IS NULL OR end_byte >= start_byte),
  digest       BLOB CHECK(digest IS NULL OR length(digest) = 32), site_ordinal INTEGER
  CHECK((site_ordinal IS NOT NULL) = (kind = 'lookup' AND family IS 'procedure_dispatch')
        AND (site_ordinal IS NULL OR site_ordinal >= 0)), decl_kind TEXT
  CHECK((decl_kind IS NOT NULL) = (kind = 'lookup' AND
        (family IS 'declaration_candidates' OR family IS 'declaration_facts' OR family IS 'signature_metadata'
         OR family IS 'callers' OR family IS 'callees' OR family IS 'usages'
         OR family IS 'reference_candidates' OR family IS 'descendants'))), decl_signature TEXT
  CHECK(decl_signature IS NULL OR decl_kind IS NOT NULL), workspace_fact_family TEXT
  CHECK((workspace_fact_family IS NOT NULL) =
        (kind = 'lookup' AND family IS 'workspace_fact')
        AND (workspace_fact_family IS NULL OR
             (length(workspace_fact_family) > 0 AND languages IS NOT NULL
              AND start_byte IS NULL AND end_byte IS NULL))),
  fact_member TEXT,
  fact_names BLOB
  CHECK(fact_names IS NULL OR (json_valid(fact_names, 8)
    AND json_type(fact_names) = 'array' AND json_array_length(fact_names) > 0))
  CHECK(CASE WHEN kind = 'lookup' AND family IS 'workspace_fact' THEN
        languages IS NOT NULL AND index_key IS NULL AND blob_oid IS NULL
        AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
        AND site_ordinal IS NULL AND decl_kind IS NULL AND decl_signature IS NULL
        AND (
          -- Whole / Class (subject distinguishes them).
          (rel_path IS NULL AND name IS NULL AND fact_member IS NULL AND fact_names IS NULL)
          -- File.
          OR (rel_path IS NOT NULL AND name IS NULL AND subject IS NULL AND fact_member IS NULL AND fact_names IS NULL)
          -- Named / NamedMember (fact_member distinguishes them).
          OR (rel_path IS NULL AND name IS NOT NULL AND subject IS NULL AND fact_names IS NULL)
          -- ClassMember.
          OR (rel_path IS NULL AND name IS NULL AND subject IS NOT NULL AND fact_member IS NOT NULL AND fact_names IS NULL)
          -- NameGroupMember.
          OR (rel_path IS NULL AND name IS NULL AND subject IS NULL AND fact_member IS NOT NULL AND fact_names IS NOT NULL)
          -- FileNamedMember; subject is its optional environment identity.
          OR (rel_path IS NOT NULL AND name IS NOT NULL AND fact_member IS NOT NULL AND fact_names IS NULL)
        )
      ELSE fact_member IS NULL AND fact_names IS NULL END),
drop_owning_unit BLOB CHECK(drop_owning_unit IS NULL OR length(drop_owning_unit) = 32),
 drop_module_path TEXT,
 drop_identity_digest BLOB CHECK(drop_identity_digest IS NULL OR length(drop_identity_digest) = 32),
 drop_config_digest BLOB CHECK(drop_config_digest IS NULL OR length(drop_config_digest) = 32),
 drop_proof_version INTEGER CHECK(drop_proof_version IS NULL OR drop_proof_version = 1),
 CHECK((family IS 'rust_drop_inventory') = (drop_owning_unit IS NOT NULL AND drop_module_path IS NOT NULL AND drop_identity_digest IS NOT NULL AND drop_config_digest IS NOT NULL AND drop_proof_version IS NOT NULL)),
 CHECK(family IS NOT 'rust_drop_inventory' OR kind = 'lookup'),
 CHECK(family NOT IN ('rust_drop_subject', 'rust_drop_inventory') OR
   (kind = 'lookup' AND languages IS NULL AND rel_path IS NOT NULL
    AND blob_oid IS NOT NULL AND start_byte IS NOT NULL AND end_byte IS NOT NULL
    AND digest IS NOT NULL AND name IS NULL AND subject IS NULL
    AND structural_role IS NULL AND structural_keyword IS NULL AND index_key IS NULL
    AND site_ordinal IS NULL AND decl_kind IS NULL AND decl_signature IS NULL
    AND workspace_fact_family IS NULL AND fact_member IS NULL AND fact_names IS NULL)),
 CHECK(family IS 'rust_drop_inventory' OR (drop_owning_unit IS NULL AND drop_module_path IS NULL AND drop_identity_digest IS NULL AND drop_config_digest IS NULL AND drop_proof_version IS NULL)),
  PRIMARY KEY(summary_id, read_ordinal),
  UNIQUE(summary_id, key_digest),
  FOREIGN KEY(summary_id) REFERENCES class_set_summaries(summary_id) ON DELETE CASCADE,
  CHECK(CASE WHEN kind = 'lookup' AND family IS 'stored_semantic_ir_publication' THEN
    languages IS NOT NULL AND length(languages) > 0 AND languages NOT LIKE '%,%'
    AND rel_path IS NOT NULL AND length(rel_path) > 0 AND subject IS NOT NULL
    AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
    AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    AND site_ordinal IS NULL AND decl_kind IS NULL AND decl_signature IS NULL
    AND workspace_fact_family IS NULL AND fact_member IS NULL AND fact_names IS NULL
    AND parse_variant_kind IS NOT NULL AND parse_variant_kind IN ('empty', 'digest')
    AND ((parse_variant_kind = 'empty' AND parse_variant_digest IS NULL)
      OR (parse_variant_kind = 'digest' AND parse_variant_digest IS NOT NULL))
  ELSE parse_variant_kind IS NULL AND parse_variant_digest IS NULL END),
  CHECK((kind = 'file' OR (kind = 'lookup' AND family IN ('rust_bound_trait_impl_inventory', 'rust_traits_implemented_by_inventory', 'rust_drop_subject', 'rust_drop_inventory'))) = (blob_oid IS NOT NULL)),
  CHECK((kind = 'index') = (index_key IS NOT NULL)),
  CHECK(start_byte IS NULL OR kind = 'lookup'),
  CHECK(kind <> 'lookup' OR digest IS NOT NULL),
  CHECK(kind <> 'scope' OR (languages IS NOT NULL AND digest IS NOT NULL)),
  CHECK(kind <> 'artifact' OR subject IS NOT NULL),
  CHECK(kind NOT IN ('models', 'configuration', 'epoch') OR digest IS NOT NULL),
  CHECK(kind <> 'policy' OR (subject IS NOT NULL AND digest IS NOT NULL)),
  CHECK((start_byte IS NULL) = (end_byte IS NULL)),
  CHECK(CASE kind
    WHEN 'file' THEN
      family IS NULL AND languages IS NOT NULL AND rel_path IS NOT NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NOT NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NULL
    WHEN 'path_absent' THEN
      family IS NULL AND languages IS NOT NULL AND rel_path IS NOT NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NULL
    WHEN 'index' THEN
      family IS NOT NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NOT NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NULL
    WHEN 'lookup' THEN 1
    WHEN 'artifact' THEN
      family IS NOT NULL AND languages IS NULL AND name IS NULL AND index_key IS NULL
      AND blob_oid IS NULL AND subject IS NOT NULL AND start_byte IS NULL
      AND end_byte IS NULL AND digest IS NULL
    WHEN 'scope' THEN
      family IS NULL AND languages IS NOT NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'policy' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NOT NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'models' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'configuration' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    WHEN 'epoch' THEN
      family IS NULL AND languages IS NULL AND rel_path IS NULL
      AND name IS NULL AND index_key IS NULL AND blob_oid IS NULL
      AND subject IS NULL AND start_byte IS NULL AND end_byte IS NULL AND digest IS NOT NULL
    ELSE 0
  END),
  CHECK((kind = 'lookup' AND family IS 'structural_role_name_inventory') =
        (structural_role IS NOT NULL)
    AND (kind = 'lookup' AND family IS 'structural_role_name_inventory') =
        (structural_keyword IS NOT NULL)),
  CHECK(family NOT IN ('rust_bound_trait_impl_inventory', 'rust_traits_implemented_by_inventory') OR (kind = 'lookup' AND languages IS 'rust' AND rel_path IS NOT NULL AND blob_oid IS NOT NULL AND start_byte IS NOT NULL AND start_byte <= 4294967295 AND end_byte IS start_byte AND digest IS NOT NULL AND name IS NULL AND subject IS NULL AND structural_role IS NULL AND structural_keyword IS NULL AND index_key IS NULL AND parse_variant_kind IS NULL AND parse_variant_digest IS NULL AND site_ordinal IS NULL AND decl_kind IS NULL AND decl_signature IS NULL AND workspace_fact_family IS NULL AND fact_member IS NULL AND fact_names IS NULL)),
  CHECK(family NOT IN ('rust_unresolved_trait_impl_inventory', 'rust_module_import_candidate_inventory', 'rust_identifier_occurrence_inventory', 'rust_alias_blob_inventory', 'rust_macro_expansion_inventory') OR (kind = 'lookup' AND languages IS 'rust' AND name IS NOT NULL AND digest IS NOT NULL AND rel_path IS NULL AND structural_role IS NULL AND structural_keyword IS NULL AND index_key IS NULL AND blob_oid IS NULL AND subject IS NULL AND parse_variant_kind IS NULL AND parse_variant_digest IS NULL AND start_byte IS NULL AND end_byte IS NULL AND site_ordinal IS NULL AND decl_kind IS NULL AND decl_signature IS NULL AND workspace_fact_family IS NULL AND fact_member IS NULL AND fact_names IS NULL))
) WITHOUT ROWID, STRICT;
INSERT INTO class_set_summary_reads_new(summary_id,read_ordinal,key_digest,kind,family,languages,rel_path,name,structural_role,structural_keyword,index_key,blob_oid,subject,parse_variant_kind,parse_variant_digest,start_byte,end_byte,digest,site_ordinal,decl_kind,decl_signature,workspace_fact_family,fact_member,fact_names,drop_owning_unit,drop_module_path,drop_identity_digest,drop_config_digest,drop_proof_version) SELECT summary_id,read_ordinal,key_digest,kind,family,languages,rel_path,name,structural_role,structural_keyword,index_key,blob_oid,subject,parse_variant_kind,parse_variant_digest,start_byte,end_byte,digest,site_ordinal,decl_kind,decl_signature,workspace_fact_family,fact_member,fact_names,drop_owning_unit,drop_module_path,drop_identity_digest,drop_config_digest,drop_proof_version FROM class_set_summary_reads;
DROP TABLE class_set_summary_reads;
ALTER TABLE class_set_summary_reads_new RENAME TO class_set_summary_reads;
CREATE INDEX class_set_summary_reads_by_key ON class_set_summary_reads(key_digest, summary_id);

-- Persistent cross-process invalidation for retained JVM inventory reads.
CREATE TABLE jvm_external_inventory_generation(
  id INTEGER PRIMARY KEY CHECK(id = 0),
  generation INTEGER NOT NULL CHECK(generation >= 0)
) WITHOUT ROWID, STRICT;
INSERT INTO jvm_external_inventory_generation VALUES(0, 0);

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
