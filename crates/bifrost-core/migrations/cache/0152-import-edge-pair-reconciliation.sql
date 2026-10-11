CREATE INDEX workspace_import_edge_facts_source_target_idx
    ON workspace_import_edge_facts (
        workspace_id, importer_path, target_path
    );
