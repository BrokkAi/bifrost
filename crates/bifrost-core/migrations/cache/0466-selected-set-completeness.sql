-- #13066; final migration 0466, COMPATIBLE (landing order rechecked pre-Ready).
-- Triggers only invalidate certificates and never refuse writes. Upgrades start
-- with zero certificates; no persisted answer reads them. The Bifrost fence
-- applies: versioned filename plus TooFarAhead.
CREATE TABLE workspace_selected_set_completeness (
 workspace_id TEXT NOT NULL,
 lang TEXT NOT NULL,
 generation INTEGER NOT NULL,
 revision INTEGER NOT NULL,
 PRIMARY KEY(workspace_id, lang, generation, revision),
 FOREIGN KEY(workspace_id, lang, generation, revision)
 REFERENCES workspace_revisions(workspace_id, lang, generation, revision) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
-- The primary key serves every invalidation's workspace/language/generation
-- prefix and revision range. No source-path relation or maintained counter.

CREATE TRIGGER selected_set_completeness_workspace_file_versions_insert
BEFORE INSERT ON workspace_file_versions
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=NEW.workspace_id AND lang=NEW.lang AND generation=NEW.generation AND revision>=NEW.valid_from AND (NEW.valid_until IS NULL OR revision<NEW.valid_until);
 DELETE FROM workspace_selected_set_completeness WHERE (workspace_id,lang,generation) IN (SELECT v.workspace_id,v.lang,v.generation FROM workspace_file_versions AS v WHERE (v.file_version_id=NEW.file_version_id OR (v.workspace_id=NEW.workspace_id AND v.lang=NEW.lang AND v.generation=NEW.generation AND v.input_kind=NEW.input_kind AND v.rel_path=NEW.rel_path AND v.valid_from=NEW.valid_from))) AND EXISTS (
 SELECT 1 FROM workspace_file_versions AS v WHERE (v.file_version_id=NEW.file_version_id OR (v.workspace_id=NEW.workspace_id AND v.lang=NEW.lang AND v.generation=NEW.generation AND v.input_kind=NEW.input_kind AND v.rel_path=NEW.rel_path AND v.valid_from=NEW.valid_from))
 AND workspace_selected_set_completeness.workspace_id=v.workspace_id AND workspace_selected_set_completeness.lang=v.lang AND workspace_selected_set_completeness.generation=v.generation
 AND workspace_selected_set_completeness.revision>=v.valid_from AND (v.valid_until IS NULL OR workspace_selected_set_completeness.revision<v.valid_until));
END;

CREATE TRIGGER selected_set_completeness_workspace_file_versions_delete
BEFORE DELETE ON workspace_file_versions
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=OLD.workspace_id AND lang=OLD.lang AND generation=OLD.generation AND revision>=OLD.valid_from AND (OLD.valid_until IS NULL OR revision<OLD.valid_until);
END;

-- definition_inventory_state is explicitly exempt: publication refills it after
-- insertion, and neither ChangedFacts nor the C# completeness census reads it.
-- All other columns are identity (including the selected validity interval).
-- The column-classification test guards additions against silent exemptions.
CREATE TRIGGER selected_set_completeness_workspace_file_versions_update
BEFORE UPDATE ON workspace_file_versions
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=OLD.workspace_id AND lang=OLD.lang AND generation=OLD.generation AND revision>=OLD.valid_from AND (OLD.valid_until IS NULL OR revision<OLD.valid_until) AND (NOT (OLD.file_version_id IS NEW.file_version_id AND OLD.workspace_id IS NEW.workspace_id AND OLD.lang IS NEW.lang AND OLD.generation IS NEW.generation AND OLD.rel_path IS NEW.rel_path AND OLD.blob_oid IS NEW.blob_oid AND OLD.input_kind IS NEW.input_kind AND OLD.projection_digest IS NEW.projection_digest AND OLD.file_present IS NEW.file_present) OR NOT (workspace_id=NEW.workspace_id AND lang=NEW.lang AND generation=NEW.generation AND revision>=NEW.valid_from AND (NEW.valid_until IS NULL OR revision<NEW.valid_until)));
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=NEW.workspace_id AND lang=NEW.lang AND generation=NEW.generation AND revision>=NEW.valid_from AND (NEW.valid_until IS NULL OR revision<NEW.valid_until) AND (NOT (OLD.file_version_id IS NEW.file_version_id AND OLD.workspace_id IS NEW.workspace_id AND OLD.lang IS NEW.lang AND OLD.generation IS NEW.generation AND OLD.rel_path IS NEW.rel_path AND OLD.blob_oid IS NEW.blob_oid AND OLD.input_kind IS NEW.input_kind AND OLD.projection_digest IS NEW.projection_digest AND OLD.file_present IS NEW.file_present) OR NOT (workspace_id=OLD.workspace_id AND lang=OLD.lang AND generation=OLD.generation AND revision>=OLD.valid_from AND (OLD.valid_until IS NULL OR revision<OLD.valid_until)));
END;

CREATE TRIGGER selected_set_completeness_workspace_source_refusals_insert
BEFORE INSERT ON workspace_source_refusals
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=NEW.workspace_id AND lang=NEW.lang AND generation=NEW.generation AND revision>=NEW.valid_from AND (NEW.valid_until IS NULL OR revision<NEW.valid_until);
 DELETE FROM workspace_selected_set_completeness WHERE (workspace_id,lang,generation) IN (SELECT v.workspace_id,v.lang,v.generation FROM workspace_source_refusals AS v WHERE ((v.workspace_id=NEW.workspace_id AND v.lang=NEW.lang AND v.generation=NEW.generation AND v.rel_path=NEW.rel_path AND v.valid_from=NEW.valid_from))) AND EXISTS (
 SELECT 1 FROM workspace_source_refusals AS v WHERE ((v.workspace_id=NEW.workspace_id AND v.lang=NEW.lang AND v.generation=NEW.generation AND v.rel_path=NEW.rel_path AND v.valid_from=NEW.valid_from))
 AND workspace_selected_set_completeness.workspace_id=v.workspace_id AND workspace_selected_set_completeness.lang=v.lang AND workspace_selected_set_completeness.generation=v.generation
 AND workspace_selected_set_completeness.revision>=v.valid_from AND (v.valid_until IS NULL OR workspace_selected_set_completeness.revision<v.valid_until));
END;

CREATE TRIGGER selected_set_completeness_workspace_source_refusals_delete
BEFORE DELETE ON workspace_source_refusals
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=OLD.workspace_id AND lang=OLD.lang AND generation=OLD.generation AND revision>=OLD.valid_from AND (OLD.valid_until IS NULL OR revision<OLD.valid_until);
END;

CREATE TRIGGER selected_set_completeness_workspace_source_refusals_update
BEFORE UPDATE ON workspace_source_refusals
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=OLD.workspace_id AND lang=OLD.lang AND generation=OLD.generation AND revision>=OLD.valid_from AND (OLD.valid_until IS NULL OR revision<OLD.valid_until) AND (NOT (OLD.workspace_id IS NEW.workspace_id AND OLD.lang IS NEW.lang AND OLD.generation IS NEW.generation AND OLD.rel_path IS NEW.rel_path AND OLD.blob_oid IS NEW.blob_oid AND OLD.reason IS NEW.reason) OR NOT (workspace_id=NEW.workspace_id AND lang=NEW.lang AND generation=NEW.generation AND revision>=NEW.valid_from AND (NEW.valid_until IS NULL OR revision<NEW.valid_until)));
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=NEW.workspace_id AND lang=NEW.lang AND generation=NEW.generation AND revision>=NEW.valid_from AND (NEW.valid_until IS NULL OR revision<NEW.valid_until) AND (NOT (OLD.workspace_id IS NEW.workspace_id AND OLD.lang IS NEW.lang AND OLD.generation IS NEW.generation AND OLD.rel_path IS NEW.rel_path AND OLD.blob_oid IS NEW.blob_oid AND OLD.reason IS NEW.reason) OR NOT (workspace_id=OLD.workspace_id AND lang=OLD.lang AND generation=OLD.generation AND revision>=OLD.valid_from AND (OLD.valid_until IS NULL OR revision<OLD.valid_until)));
END;

CREATE TRIGGER selected_set_completeness_csharp_file_version_decisions_insert
BEFORE INSERT ON csharp_file_version_decisions
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE
 (workspace_id,lang,generation)=(SELECT workspace_id,lang,generation FROM workspace_file_versions WHERE file_version_id=NEW.file_version_id)
 AND revision>=(SELECT valid_from FROM workspace_file_versions WHERE file_version_id=NEW.file_version_id)
 AND ((SELECT valid_until FROM workspace_file_versions WHERE file_version_id=NEW.file_version_id) IS NULL
 OR revision<(SELECT valid_until FROM workspace_file_versions WHERE file_version_id=NEW.file_version_id));
END;

CREATE TRIGGER selected_set_completeness_csharp_file_version_decisions_update
BEFORE UPDATE ON csharp_file_version_decisions
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE
 (workspace_id,lang,generation)=(SELECT workspace_id,lang,generation FROM workspace_file_versions WHERE file_version_id=OLD.file_version_id)
 AND revision>=(SELECT valid_from FROM workspace_file_versions WHERE file_version_id=OLD.file_version_id)
 AND ((SELECT valid_until FROM workspace_file_versions WHERE file_version_id=OLD.file_version_id) IS NULL
 OR revision<(SELECT valid_until FROM workspace_file_versions WHERE file_version_id=OLD.file_version_id));
 DELETE FROM workspace_selected_set_completeness WHERE
 (workspace_id,lang,generation)=(SELECT workspace_id,lang,generation FROM workspace_file_versions WHERE file_version_id=NEW.file_version_id)
 AND revision>=(SELECT valid_from FROM workspace_file_versions WHERE file_version_id=NEW.file_version_id)
 AND ((SELECT valid_until FROM workspace_file_versions WHERE file_version_id=NEW.file_version_id) IS NULL
 OR revision<(SELECT valid_until FROM workspace_file_versions WHERE file_version_id=NEW.file_version_id));
END;

CREATE TRIGGER selected_set_completeness_csharp_file_version_decisions_delete
BEFORE DELETE ON csharp_file_version_decisions
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE
 (workspace_id,lang,generation)=(SELECT workspace_id,lang,generation FROM workspace_file_versions WHERE file_version_id=OLD.file_version_id)
 AND revision>=(SELECT valid_from FROM workspace_file_versions WHERE file_version_id=OLD.file_version_id)
 AND ((SELECT valid_until FROM workspace_file_versions WHERE file_version_id=OLD.file_version_id) IS NULL
 OR revision<(SELECT valid_until FROM workspace_file_versions WHERE file_version_id=OLD.file_version_id));
END;

CREATE TRIGGER selected_set_completeness_workspace_heads_insert
BEFORE INSERT ON workspace_heads
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=NEW.workspace_id AND lang=NEW.lang AND generation=NEW.generation AND (revision=NEW.revision);
END;

CREATE TRIGGER selected_set_completeness_workspace_heads_update
BEFORE UPDATE ON workspace_heads
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=NEW.workspace_id AND lang=NEW.lang AND generation=NEW.generation AND (revision=NEW.revision);
END;

CREATE TRIGGER selected_set_completeness_workspace_heads_delete
BEFORE DELETE ON workspace_heads
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=OLD.workspace_id AND lang=OLD.lang AND generation=OLD.generation AND (revision=OLD.revision);
END;

CREATE TRIGGER selected_set_completeness_workspace_revisions_insert
BEFORE INSERT ON workspace_revisions
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=NEW.workspace_id AND lang=NEW.lang AND generation=NEW.generation AND (revision=NEW.revision);
END;

CREATE TRIGGER selected_set_completeness_workspace_revisions_update
BEFORE UPDATE ON workspace_revisions
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=OLD.workspace_id AND lang=OLD.lang AND generation=OLD.generation AND (revision=OLD.revision);
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=NEW.workspace_id AND lang=NEW.lang AND generation=NEW.generation AND (revision=NEW.revision);
END;

CREATE TRIGGER selected_set_completeness_workspace_revisions_delete
BEFORE DELETE ON workspace_revisions
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=OLD.workspace_id AND lang=OLD.lang AND generation=OLD.generation AND (revision=OLD.revision);
END;

CREATE TRIGGER selected_set_completeness_csharp_compilation_selections_insert
BEFORE INSERT ON csharp_compilation_selections
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=NEW.workspace_id AND lang=NEW.lang AND generation=NEW.generation AND (revision=NEW.revision);
END;

CREATE TRIGGER selected_set_completeness_csharp_compilation_selections_update
BEFORE UPDATE ON csharp_compilation_selections
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=OLD.workspace_id AND lang=OLD.lang AND generation=OLD.generation AND (revision=OLD.revision);
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=NEW.workspace_id AND lang=NEW.lang AND generation=NEW.generation AND (revision=NEW.revision);
END;

CREATE TRIGGER selected_set_completeness_csharp_compilation_selections_delete
BEFORE DELETE ON csharp_compilation_selections
BEGIN
 DELETE FROM workspace_selected_set_completeness WHERE workspace_id=OLD.workspace_id AND lang=OLD.lang AND generation=OLD.generation AND (revision=OLD.revision);
END;
