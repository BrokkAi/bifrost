-- Legacy empty blobs do not prove whether a configuration probe was present.
ALTER TABLE workspace_file_versions ADD COLUMN file_present INTEGER
 CHECK(file_present IS NULL OR
       (input_kind = 'configuration' AND file_present IN (0, 1) AND
        (file_present = 1 OR blob_oid = 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391')));
UPDATE workspace_file_versions SET file_present = 1
 WHERE input_kind = 'configuration'
   AND blob_oid <> 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391';
CREATE TRIGGER workspace_file_versions_configuration_presence_insert
 BEFORE INSERT ON workspace_file_versions
 WHEN NEW.input_kind = 'configuration' AND NEW.file_present IS NULL
BEGIN
 SELECT RAISE(ABORT, 'configuration input presence required');
END;
CREATE TRIGGER workspace_file_versions_configuration_presence_update
 BEFORE UPDATE OF file_present ON workspace_file_versions
 WHEN NEW.input_kind = 'configuration' AND NEW.file_present IS NULL
BEGIN
 SELECT RAISE(ABORT, 'configuration input presence required');
END;
