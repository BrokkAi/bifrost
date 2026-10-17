CREATE TABLE workspace_import_graphs (
    workspace_id TEXT PRIMARY KEY,
    content_identity BLOB NOT NULL CHECK (length(content_identity) = 32),
    source_count INTEGER NOT NULL CHECK (source_count >= 0),
    edge_count INTEGER NOT NULL CHECK (edge_count >= 0),
    UNIQUE (workspace_id, content_identity)
);

CREATE TABLE workspace_import_sources (
    workspace_id TEXT NOT NULL,
    content_identity BLOB NOT NULL CHECK (length(content_identity) = 32),
    source_path TEXT NOT NULL CHECK (length(source_path) > 0),
    PRIMARY KEY (workspace_id, content_identity, source_path),
    FOREIGN KEY (workspace_id, content_identity)
        REFERENCES workspace_import_graphs (workspace_id, content_identity)
        ON DELETE CASCADE
);

CREATE TABLE workspace_import_edges (
    workspace_id TEXT NOT NULL,
    content_identity BLOB NOT NULL CHECK (length(content_identity) = 32),
    importer_path TEXT NOT NULL CHECK (length(importer_path) > 0),
    target_path TEXT NOT NULL CHECK (length(target_path) > 0),
    provenance_json TEXT NOT NULL CHECK (
        json_valid(provenance_json) AND json_type(provenance_json) = 'array'
    ),
    PRIMARY KEY (workspace_id, content_identity, importer_path, target_path),
    FOREIGN KEY (workspace_id, content_identity, importer_path)
        REFERENCES workspace_import_sources (workspace_id, content_identity, source_path)
        ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, content_identity, target_path)
        REFERENCES workspace_import_sources (workspace_id, content_identity, source_path)
        ON DELETE CASCADE
);

CREATE INDEX workspace_import_edges_reverse_idx
    ON workspace_import_edges (
        workspace_id,
        content_identity,
        target_path,
        importer_path
    );
