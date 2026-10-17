-- Keep one query-facing adjacency row per source/target pair, but retain each
-- contributing source import separately so incremental refresh can replace
-- only the ordinals whose resolution candidates changed.
DELETE FROM workspace_import_graphs;

ALTER TABLE workspace_import_sources
    ADD COLUMN complete_resolution_dependencies INTEGER NOT NULL DEFAULT 0
    CHECK (complete_resolution_dependencies IN (0, 1));

DROP TABLE workspace_import_route_dependencies;
DROP TABLE workspace_import_edges;

CREATE TABLE workspace_import_edges (
    edge_id INTEGER PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    importer_path TEXT NOT NULL CHECK (length(importer_path) > 0),
    target_path TEXT NOT NULL CHECK (length(target_path) > 0),
    UNIQUE (workspace_id, importer_path, target_path),
    UNIQUE (workspace_id, edge_id),
    FOREIGN KEY (workspace_id, importer_path)
        REFERENCES workspace_import_sources (workspace_id, source_path)
        ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, target_path)
        REFERENCES workspace_import_sources (workspace_id, source_path)
        ON DELETE CASCADE
);

CREATE INDEX workspace_import_edges_reverse_idx
    ON workspace_import_edges (workspace_id, target_path, importer_path);

CREATE TABLE workspace_import_edge_facts (
    workspace_id TEXT NOT NULL,
    importer_path TEXT NOT NULL,
    import_ordinal INTEGER NOT NULL CHECK (import_ordinal >= 0),
    target_path TEXT NOT NULL,
    provenance_json TEXT NOT NULL CHECK (
        json_valid(provenance_json) AND json_type(provenance_json) = 'array'
    ),
    PRIMARY KEY (workspace_id, importer_path, import_ordinal, target_path),
    FOREIGN KEY (workspace_id, importer_path)
        REFERENCES workspace_import_sources (workspace_id, source_path)
        ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX workspace_import_edge_facts_target_idx
    ON workspace_import_edge_facts (
        workspace_id, target_path, importer_path, import_ordinal
    );

DROP INDEX workspace_import_candidate_file_dependencies_consulted_idx;
CREATE INDEX workspace_import_candidate_file_dependencies_consulted_idx
    ON workspace_import_candidate_file_dependencies (
        workspace_id, consulted_path, importer_path, import_ordinal
    );

DROP INDEX workspace_import_missing_module_dependencies_key_idx;
CREATE INDEX workspace_import_missing_module_dependencies_key_idx
    ON workspace_import_missing_module_dependencies (
        workspace_id, module_path_key, importer_path, import_ordinal
    );
