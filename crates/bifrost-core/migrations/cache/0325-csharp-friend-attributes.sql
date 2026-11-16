-- Compatible additive source family, isolated by the C# v62 bundle.
-- F records assembly attributes without deciding their identity; A resolves
-- aliases and the Attribute suffix through selected-compilation type routes.
-- The future reader asks for all attributes of a selected member blob. The
-- (blob_id, site) primary key serves that query; no additional index is needed.
-- Name segments are read whole by that one reader, so one JSON array avoids
-- one statement per attribute's segment sequence. SQL can read each segment.
CREATE TABLE resolution_csharp_friend_attributes (
 blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
 site INTEGER NOT NULL CHECK(site BETWEEN 0 AND 4294967295),
 scope INTEGER NOT NULL CHECK(scope BETWEEN 0 AND 4294967295),
 name_segments TEXT NOT NULL CHECK(json_valid(name_segments) AND json_type(name_segments)='array'),
 identity_state TEXT NOT NULL CHECK(identity_state='unresolved'),
 argument TEXT,
 parse_state TEXT NOT NULL CHECK(parse_state IN ('complete','non_constant','invalid_display_name')),
 friend_name TEXT,
 has_public_key INTEGER NOT NULL CHECK(has_public_key IN (0,1)),
 CHECK((parse_state='non_constant')=(argument IS NULL)),
 CHECK((parse_state='complete')=(friend_name IS NOT NULL)),
 PRIMARY KEY(blob_id,site)
) WITHOUT ROWID, STRICT;
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_csharp_friend_attribute_count INTEGER NOT NULL DEFAULT 0 CHECK(expected_csharp_friend_attribute_count>=0);
