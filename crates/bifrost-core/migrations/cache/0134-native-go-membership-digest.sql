-- Record, per Go blob, the digest of every input the Go tool reads to place
-- the file in a package: the bytes through the package clause and the import
-- declarations. An unsaved replacement whose digest equals its predecessor's
-- keeps that predecessor's selected package membership. Existing rows keep
-- NULL, which never matches, so their unsaved replacements stay unplaced
-- until the blob is produced again.
ALTER TABLE source_go_manifests ADD COLUMN membership_digest BLOB
  CHECK(membership_digest IS NULL
        OR (typeof(membership_digest) = 'blob' AND length(membership_digest) = 32));
