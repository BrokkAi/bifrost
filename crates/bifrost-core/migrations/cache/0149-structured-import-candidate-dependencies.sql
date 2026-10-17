-- Candidate dependencies are derived graph state. Existing graph rows have no
-- structured negative lookups, so discard them and let the next request rebuild.
DELETE FROM workspace_import_route_dependencies;
DELETE FROM workspace_import_edges;
DELETE FROM workspace_import_sources;
DELETE FROM workspace_import_graphs;

CREATE TABLE workspace_import_source_modules (
    workspace_id TEXT NOT NULL,
    source_path TEXT NOT NULL,
    module_path_key TEXT NOT NULL CHECK (length(module_path_key) > 0),
    PRIMARY KEY (workspace_id, source_path, module_path_key),
    FOREIGN KEY (workspace_id, source_path)
        REFERENCES workspace_import_sources (workspace_id, source_path)
        ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE workspace_import_candidate_file_dependencies (
    workspace_id TEXT NOT NULL,
    importer_path TEXT NOT NULL,
    import_ordinal INTEGER NOT NULL CHECK (import_ordinal >= 0),
    consulted_path TEXT NOT NULL CHECK (length(consulted_path) > 0),
    name TEXT NOT NULL CHECK (length(name) > 0),
    PRIMARY KEY (workspace_id, importer_path, import_ordinal, consulted_path, name),
    FOREIGN KEY (workspace_id, importer_path)
        REFERENCES workspace_import_sources (workspace_id, source_path)
        ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX workspace_import_candidate_file_dependencies_consulted_idx
    ON workspace_import_candidate_file_dependencies (
        workspace_id, consulted_path, importer_path
    );

CREATE TABLE workspace_import_missing_module_dependencies (
    workspace_id TEXT NOT NULL,
    importer_path TEXT NOT NULL,
    import_ordinal INTEGER NOT NULL CHECK (import_ordinal >= 0),
    module_path_key TEXT NOT NULL CHECK (length(module_path_key) > 0),
    PRIMARY KEY (workspace_id, importer_path, import_ordinal, module_path_key),
    FOREIGN KEY (workspace_id, importer_path)
        REFERENCES workspace_import_sources (workspace_id, source_path)
        ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX workspace_import_missing_module_dependencies_key_idx
    ON workspace_import_missing_module_dependencies (
        workspace_id, module_path_key, importer_path
    );
