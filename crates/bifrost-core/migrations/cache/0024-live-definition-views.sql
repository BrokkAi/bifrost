-- Reusable live-definition query shapes.
--
-- Analyzer rows are content addressed, so a query is live only when its blob
-- has a complete publication and belongs to the storage language's active
-- generation. Keep those invariants in the schema instead of repeating them
-- in each Rust caller.
CREATE VIEW live_parsed_blobs AS
SELECT blobs.blob_oid,
       blobs.lang,
       blobs.generation,
       blob_meta.content_package
FROM blobs
JOIN blob_meta
  ON blob_meta.blob_oid = blobs.blob_oid
 AND blob_meta.lang = blobs.lang
LEFT JOIN analysis_epochs
  ON analysis_epochs.lang = blobs.lang
WHERE blob_meta.is_complete = 1
  AND blobs.generation = COALESCE(analysis_epochs.generation, 0);

CREATE VIEW live_code_units AS
SELECT units.*
FROM code_units AS units
JOIN live_parsed_blobs AS live
  ON live.blob_oid = units.blob_oid
 AND live.lang = units.lang;

CREATE VIEW live_declarations AS
SELECT *
FROM live_code_units
WHERE in_declarations = 1;

CREATE VIEW live_definition_units AS
SELECT *
FROM live_code_units
WHERE in_declarations = 1 OR in_definition_lookup = 1;
