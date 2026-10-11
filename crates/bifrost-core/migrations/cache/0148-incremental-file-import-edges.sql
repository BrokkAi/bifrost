-- The resolved import graph is disposable derived state. Recreate it with
-- source identities and route dependencies so a new snapshot can replace only
-- the affected importer rows.
DROP TABLE workspace_import_edges;
DROP TABLE workspace_import_sources;
DROP TABLE workspace_import_graphs;

CREATE TABLE workspace_import_graphs (
    workspace_id TEXT PRIMARY KEY,
    content_identity BLOB NOT NULL CHECK (length(content_identity) = 32),
    resolver_identity BLOB NOT NULL CHECK (length(resolver_identity) = 32),
    source_count INTEGER NOT NULL CHECK (source_count >= 0),
    edge_count INTEGER NOT NULL CHECK (edge_count >= 0)
);

CREATE TABLE workspace_import_sources (
    source_id INTEGER PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    source_path TEXT NOT NULL CHECK (length(source_path) > 0),
    source_identity BLOB NOT NULL CHECK (length(source_identity) = 32),
    UNIQUE (workspace_id, source_path),
    FOREIGN KEY (workspace_id)
        REFERENCES workspace_import_graphs (workspace_id)
        ON DELETE CASCADE
);

CREATE TABLE workspace_import_edges (
    edge_id INTEGER PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    importer_path TEXT NOT NULL CHECK (length(importer_path) > 0),
    target_path TEXT NOT NULL CHECK (length(target_path) > 0),
    provenance_json TEXT NOT NULL CHECK (
        json_valid(provenance_json) AND json_type(provenance_json) = 'array'
    ),
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

CREATE TABLE workspace_import_route_dependencies (
    workspace_id TEXT NOT NULL,
    edge_id INTEGER NOT NULL,
    traversed_path TEXT NOT NULL CHECK (length(traversed_path) > 0),
    PRIMARY KEY (workspace_id, edge_id, traversed_path),
    FOREIGN KEY (workspace_id, edge_id)
        REFERENCES workspace_import_edges (workspace_id, edge_id)
        ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX workspace_import_route_dependencies_traversed_idx
    ON workspace_import_route_dependencies (workspace_id, traversed_path, edge_id);
