-- Keep semantic language and the adapter-specific owner blob identity distinct.
-- The migration runner disables foreign-key actions and checks all references
-- before committing, preserving children and stable parent row identifiers.

DROP TRIGGER class_set_summaries_require_root_surface_insert;

DROP TRIGGER class_set_summaries_require_root_surface_update;

CREATE TABLE class_set_finding_free_root_results_0178 (
  result_id                  INTEGER PRIMARY KEY,
  generation_id              INTEGER NOT NULL,
  root_public_digest         BLOB    NOT NULL CHECK(length(root_public_digest) = 32),
  owner_rel_path             TEXT    NOT NULL CHECK(length(owner_rel_path) > 0),
  owner_blob_id              INTEGER NOT NULL,
  lang                       TEXT    NOT NULL,
  completion                 TEXT    NOT NULL CHECK(completion = 'complete'),
  finding_count              INTEGER NOT NULL CHECK(finding_count = 0),
  row_count                  INTEGER NOT NULL CHECK(row_count >= 0),
  payload_text_bytes         INTEGER NOT NULL CHECK(payload_text_bytes >= 0),
  content_digest             BLOB    NOT NULL CHECK(length(content_digest) = 32),
  published_at               INTEGER NOT NULL CHECK(published_at >= 0),
  UNIQUE(generation_id, root_public_digest),
  FOREIGN KEY(generation_id, lang)
    REFERENCES class_set_root_result_generations(generation_id, lang) ON DELETE CASCADE,
  FOREIGN KEY(owner_blob_id) REFERENCES blobs(id) ON DELETE CASCADE
) STRICT;

INSERT INTO class_set_finding_free_root_results_0178(result_id, generation_id, root_public_digest, owner_rel_path, owner_blob_id, lang, completion, finding_count, row_count, payload_text_bytes, content_digest, published_at)
  SELECT result_id, generation_id, root_public_digest, owner_rel_path, owner_blob_id, lang, completion, finding_count, row_count, payload_text_bytes, content_digest, published_at FROM class_set_finding_free_root_results;

DROP TABLE class_set_finding_free_root_results;

ALTER TABLE class_set_finding_free_root_results_0178 RENAME TO class_set_finding_free_root_results;

-- The exact physical key is retained once in each root result attachment.
UPDATE class_set_finding_free_root_results AS results
SET payload_text_bytes = payload_text_bytes + length(CAST(blobs.lang AS BLOB))
FROM blobs
WHERE blobs.id = results.owner_blob_id;

CREATE TABLE class_set_procedure_surfaces_0178(
  surface_id                 INTEGER PRIMARY KEY,
  surface_digest             BLOB    NOT NULL CHECK(length(surface_digest) = 32),
  procedure_lineage          BLOB    NOT NULL CHECK(length(procedure_lineage) = 32),
  owner_rel_path             TEXT    NOT NULL CHECK(length(owner_rel_path) > 0),
  owner_blob_id              INTEGER NOT NULL,
  lang                       TEXT    NOT NULL,
  artifact_public_identity   BLOB    NOT NULL CHECK(length(artifact_public_identity) = 32),
  artifact_content_identity  BLOB    NOT NULL CHECK(length(artifact_content_identity) = 32),
  schema_version             INTEGER NOT NULL CHECK(schema_version > 0),
  local_structure_digest     BLOB    NOT NULL CHECK(length(local_structure_digest) = 32),
  behavior_read_digest       BLOB    NOT NULL CHECK(length(behavior_read_digest) = 32),
  carrier_semantics_digest   BLOB    NOT NULL CHECK(length(carrier_semantics_digest) = 32),
  direct_calls_digest        BLOB    NOT NULL CHECK(length(direct_calls_digest) = 32),
  call_count                 INTEGER NOT NULL CHECK(call_count >= 0 AND call_count <= 100000),
  binding_count              INTEGER NOT NULL CHECK(binding_count >= 0 AND binding_count <= 1000000),
  entered_count              INTEGER NOT NULL CHECK(entered_count >= 0 AND entered_count <= 1000000),
  lexical_child_count        INTEGER NOT NULL CHECK(lexical_child_count >= 0 AND lexical_child_count <= 100000),
  read_count                 INTEGER NOT NULL CHECK(read_count >= 0 AND read_count <= 100000),
  completion                 TEXT    NOT NULL CHECK(completion = 'complete'),
  published_at               INTEGER NOT NULL CHECK(published_at >= 0), exact_behavior_digest BLOB NOT NULL
    CHECK(length(exact_behavior_digest) = 32), exact_provenance_digest BLOB NOT NULL
    CHECK(length(exact_provenance_digest) = 32),
  UNIQUE(surface_digest),
  CHECK(entered_count <= binding_count),
  FOREIGN KEY(owner_blob_id) REFERENCES blobs(id) ON DELETE CASCADE
) STRICT;

INSERT INTO class_set_procedure_surfaces_0178(surface_id, surface_digest, procedure_lineage, owner_rel_path, owner_blob_id, lang, artifact_public_identity, artifact_content_identity, schema_version, local_structure_digest, behavior_read_digest, carrier_semantics_digest, direct_calls_digest, call_count, binding_count, entered_count, lexical_child_count, read_count, completion, published_at, exact_behavior_digest, exact_provenance_digest)
  SELECT surface_id, surface_digest, procedure_lineage, owner_rel_path, owner_blob_id, lang, artifact_public_identity, artifact_content_identity, schema_version, local_structure_digest, behavior_read_digest, carrier_semantics_digest, direct_calls_digest, call_count, binding_count, entered_count, lexical_child_count, read_count, completion, published_at, exact_behavior_digest, exact_provenance_digest FROM class_set_procedure_surfaces;

DROP TABLE class_set_procedure_surfaces;

ALTER TABLE class_set_procedure_surfaces_0178 RENAME TO class_set_procedure_surfaces;

CREATE TABLE class_set_summaries_0178(
  summary_id                  INTEGER PRIMARY KEY,
  lookup_digest               BLOB    NOT NULL CHECK(length(lookup_digest) = 32),
  procedure_lineage           BLOB    NOT NULL CHECK(length(procedure_lineage) = 32),
  owner_rel_path              TEXT    NOT NULL CHECK(length(owner_rel_path) > 0),
  owner_blob_id               INTEGER NOT NULL,
  lang                        TEXT    NOT NULL,
  artifact_public_identity    BLOB    NOT NULL CHECK(length(artifact_public_identity) = 32),
  artifact_content_identity   BLOB    NOT NULL CHECK(length(artifact_content_identity) = 32),
  schema_version              INTEGER NOT NULL CHECK(schema_version > 0),
  semantics_digest            BLOB    NOT NULL CHECK(length(semantics_digest) = 32),
  context_digest              BLOB    NOT NULL CHECK(length(context_digest) = 32),
  behavior_read_digest        BLOB    NOT NULL CHECK(length(behavior_read_digest) = 32),
  dependency_digest           BLOB    NOT NULL CHECK(length(dependency_digest) = 32),
  carrier_digest              BLOB    NOT NULL CHECK(length(carrier_digest) = 32),
  field_slots_digest          BLOB    NOT NULL CHECK(length(field_slots_digest) = 32),
  entry_fact_ordinal          INTEGER NOT NULL CHECK(entry_fact_ordinal >= 0),
  fact_count                  INTEGER NOT NULL CHECK(fact_count >= 1),
  exit_count                  INTEGER NOT NULL CHECK(exit_count >= 1),
  reached_count               INTEGER NOT NULL CHECK(reached_count >= 0),
  dependency_count            INTEGER NOT NULL CHECK(dependency_count >= 0),
  read_count                  INTEGER NOT NULL CHECK(read_count >= 0),
  charge_count                INTEGER NOT NULL CHECK(charge_count >= 1),
  completion                  TEXT    NOT NULL CHECK(completion = 'complete'),
  budget_mode                 TEXT    NOT NULL CHECK(budget_mode = 'exhaustive'),
  output_digest               BLOB    NOT NULL CHECK(length(output_digest) = 32),
  content_digest              BLOB    NOT NULL CHECK(length(content_digest) = 32),
  published_at                INTEGER NOT NULL CHECK(published_at >= 0), root_surface_digest BLOB
    REFERENCES class_set_procedure_surfaces(surface_digest) ON DELETE CASCADE
    CHECK(length(root_surface_digest) = 32), direct_calls_digest BLOB CHECK(length(direct_calls_digest) = 32),
  FOREIGN KEY(owner_blob_id) REFERENCES blobs(id) ON DELETE CASCADE
) STRICT;

INSERT INTO class_set_summaries_0178(summary_id, lookup_digest, procedure_lineage, owner_rel_path, owner_blob_id, lang, artifact_public_identity, artifact_content_identity, schema_version, semantics_digest, context_digest, behavior_read_digest, dependency_digest, carrier_digest, field_slots_digest, entry_fact_ordinal, fact_count, exit_count, reached_count, dependency_count, read_count, charge_count, completion, budget_mode, output_digest, content_digest, published_at, root_surface_digest, direct_calls_digest)
  SELECT summary_id, lookup_digest, procedure_lineage, owner_rel_path, owner_blob_id, lang, artifact_public_identity, artifact_content_identity, schema_version, semantics_digest, context_digest, behavior_read_digest, dependency_digest, carrier_digest, field_slots_digest, entry_fact_ordinal, fact_count, exit_count, reached_count, dependency_count, read_count, charge_count, completion, budget_mode, output_digest, content_digest, published_at, root_surface_digest, direct_calls_digest FROM class_set_summaries;

DROP TABLE class_set_summaries;

ALTER TABLE class_set_summaries_0178 RENAME TO class_set_summaries;

CREATE INDEX class_set_finding_free_root_results_owner_blob
  ON class_set_finding_free_root_results(owner_blob_id, lang);

CREATE INDEX class_set_procedure_surfaces_exact_family
  ON class_set_procedure_surfaces(
    procedure_lineage, owner_rel_path, lang, schema_version,
    local_structure_digest, behavior_read_digest, surface_digest
  );

CREATE INDEX class_set_procedure_surfaces_owner_blob
  ON class_set_procedure_surfaces(owner_blob_id, lang);

CREATE INDEX class_set_summaries_exact_family
  ON class_set_summaries(
    procedure_lineage, owner_rel_path, lang, schema_version, semantics_digest,
    context_digest, behavior_read_digest, carrier_digest, field_slots_digest,
    root_surface_digest, lookup_digest
  );

CREATE INDEX class_set_summaries_lineage
  ON class_set_summaries(procedure_lineage);

CREATE UNIQUE INDEX class_set_summaries_lookup
  ON class_set_summaries(lookup_digest);

CREATE INDEX class_set_summaries_owner_blob
  ON class_set_summaries(owner_blob_id, lang);

CREATE INDEX class_set_summaries_root_surface
  ON class_set_summaries(root_surface_digest);

CREATE TRIGGER class_set_summaries_require_root_surface_insert
BEFORE INSERT ON class_set_summaries
WHEN NEW.root_surface_digest IS NULL OR NEW.direct_calls_digest IS NULL
BEGIN
  SELECT RAISE(ABORT, 'class-set summary structural surface contract is required');
END;

CREATE TRIGGER class_set_summaries_require_root_surface_update
BEFORE UPDATE OF root_surface_digest, direct_calls_digest ON class_set_summaries
WHEN NEW.root_surface_digest IS NULL OR NEW.direct_calls_digest IS NULL
BEGIN
  SELECT RAISE(ABORT, 'class-set summary structural surface contract is required');
END;
