-- Derivation v2 rebuilds these sets from retained configuration inputs.
-- Foreign keys are disabled while migrations run, so delete children before
-- their parents. No old row receives defaulted metadata that could masquerade
-- as a complete derivation.
DELETE FROM csharp_project_references;
DELETE FROM csharp_compilation_items;
DELETE FROM csharp_compilations;
DELETE FROM csharp_compilation_selections;
DELETE FROM csharp_compilation_sets;
DROP TABLE csharp_compilations;

CREATE TABLE csharp_compilations (
    compilation_id INTEGER PRIMARY KEY,
    set_id INTEGER NOT NULL REFERENCES csharp_compilation_sets(set_id) ON DELETE CASCADE,
    project_path TEXT,
    -- 1 only when the edges below are all of this project's direct
    -- references: every ProjectReference resolved to a compilation in this
    -- set and no unsupported reference shape or metadata appeared.
    references_complete INTEGER NOT NULL CHECK(references_complete IN (0,1)),
    -- 1 only when this project is an SDK project that receives its
    -- references' references by the SDK default, so its edges may be walked
    -- transitively.
    transitive_flow INTEGER NOT NULL CHECK(transitive_flow IN (0,1)),
    -- NULL means the name is not statically known, or this is a loose compilation.
    assembly_name TEXT,
    global_usings_complete INTEGER NOT NULL CHECK(global_usings_complete IN (0,1)),
    internals_visible_to_complete INTEGER NOT NULL CHECK(internals_visible_to_complete IN (0,1)),
    -- Read whole for one compilation: positional [kind, segments, alias, origin]
    -- entries. Segments is a string array; alias is a string or null.
    -- No identity references or separately constrained values live in this array.
    global_usings BLOB NOT NULL CHECK(json_valid(global_usings, 8)),
    -- Read whole for one compilation: an ordered array of friend assembly names.
    internals_visible_to BLOB NOT NULL CHECK(json_valid(internals_visible_to, 8)),
    UNIQUE(set_id, project_path)
);
