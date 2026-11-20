-- Compatible additive resolution families. Existing rows retain their meaning;
-- H's C# resolution bundle excludes older interiors without these source facts.
CREATE TABLE resolution_implicit_root_candidates (
 blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
 definition INTEGER NOT NULL CHECK(definition >= 0),
 reference INTEGER NOT NULL CHECK(reference >= 0),
 frontier INTEGER NOT NULL CHECK(frontier >= 0),
 PRIMARY KEY(blob_id,definition),
 UNIQUE(blob_id,reference),
 UNIQUE(blob_id,frontier)
) WITHOUT ROWID, STRICT;
CREATE TABLE resolution_declaration_modifiers (
 blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
 definition INTEGER NOT NULL CHECK(definition >= 0),
 partial INTEGER NOT NULL CHECK(partial IN (0,1)),
 PRIMARY KEY(blob_id,definition)
) WITHOUT ROWID, STRICT;
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_implicit_root_candidate_count INTEGER NOT NULL DEFAULT 0 CHECK(expected_implicit_root_candidate_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_declaration_modifier_count INTEGER NOT NULL DEFAULT 0 CHECK(expected_declaration_modifier_count >= 0);
