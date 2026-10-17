-- Import dependency invalidation now follows binding names. Existing graph
-- rows used file-wide route markers, so rebuild the disposable graph once.
DELETE FROM workspace_import_graphs;

DROP INDEX workspace_import_candidate_file_dependencies_consulted_idx;
CREATE INDEX workspace_import_candidate_file_dependencies_consulted_idx
    ON workspace_import_candidate_file_dependencies (
        workspace_id, consulted_path, name, importer_path, import_ordinal
    );

CREATE TABLE workspace_import_route_dependencies (
    workspace_id TEXT NOT NULL,
    importer_path TEXT NOT NULL,
    import_ordinal INTEGER NOT NULL CHECK (import_ordinal >= 0),
    traversed_path TEXT NOT NULL CHECK (length(traversed_path) > 0),
    name TEXT NOT NULL CHECK (length(name) > 0),
    PRIMARY KEY (
        workspace_id, importer_path, import_ordinal, traversed_path, name
    ),
    FOREIGN KEY (workspace_id, importer_path)
        REFERENCES workspace_import_sources (workspace_id, source_path)
        ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX workspace_import_route_dependencies_name_idx
    ON workspace_import_route_dependencies (
        workspace_id, traversed_path, name, importer_path, import_ordinal
    );

CREATE TABLE workspace_import_source_bindings (
    workspace_id TEXT NOT NULL,
    source_path TEXT NOT NULL,
    module_path TEXT NOT NULL CHECK (length(module_path) > 0),
    name TEXT NOT NULL CHECK (length(name) > 0),
    namespace TEXT NOT NULL CHECK (length(namespace) > 0),
    visibility_kind TEXT NOT NULL CHECK (length(visibility_kind) > 0),
    visibility_scope TEXT NOT NULL,
    origin_path TEXT NOT NULL CHECK (length(origin_path) > 0),
    origin_module_path TEXT NOT NULL CHECK (length(origin_module_path) > 0),
    origin_name TEXT NOT NULL CHECK (length(origin_name) > 0),
    route_path TEXT NOT NULL CHECK (length(route_path) > 0),
    PRIMARY KEY (
        workspace_id, source_path, module_path, name, namespace,
        visibility_kind, visibility_scope, origin_path, origin_module_path,
        origin_name, route_path
    ),
    FOREIGN KEY (workspace_id, source_path)
        REFERENCES workspace_import_sources (workspace_id, source_path)
        ON DELETE CASCADE
) WITHOUT ROWID;
