CREATE TABLE catalog_exact_go_source_sets(
  manifest_digest TEXT NOT NULL,
  artifact_sha256 TEXT NOT NULL
    CHECK(length(artifact_sha256) = 64
      AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'),
  PRIMARY KEY(manifest_digest, artifact_sha256),
  FOREIGN KEY(manifest_digest)
    REFERENCES catalog_packs(manifest_digest) ON DELETE CASCADE
) STRICT;

CREATE INDEX catalog_exact_go_source_sets_artifact_lookup
  ON catalog_exact_go_source_sets(artifact_sha256, manifest_digest);

CREATE TABLE catalog_exact_go_source_files(
  manifest_digest TEXT NOT NULL,
  artifact_sha256 TEXT NOT NULL,
  relative_path TEXT NOT NULL,
  source_text TEXT NOT NULL,
  PRIMARY KEY(manifest_digest, artifact_sha256, relative_path),
  FOREIGN KEY(manifest_digest, artifact_sha256)
    REFERENCES catalog_exact_go_source_sets(manifest_digest, artifact_sha256)
    ON DELETE CASCADE
) STRICT;

CREATE INDEX catalog_exact_go_source_files_read
  ON catalog_exact_go_source_files(manifest_digest, artifact_sha256, relative_path);

CREATE TABLE catalog_exact_go_packages(
  manifest_digest TEXT NOT NULL,
  artifact_sha256 TEXT NOT NULL,
  package_ordinal INTEGER NOT NULL CHECK(package_ordinal >= 0),
  import_path TEXT NOT NULL CHECK(length(import_path) > 0),
  package_name TEXT NOT NULL CHECK(length(package_name) > 0),
  PRIMARY KEY(manifest_digest, artifact_sha256, package_ordinal),
  FOREIGN KEY(manifest_digest, artifact_sha256)
    REFERENCES catalog_exact_go_source_sets(manifest_digest, artifact_sha256)
    ON DELETE CASCADE
) STRICT;

CREATE INDEX catalog_exact_go_packages_import_lookup
  ON catalog_exact_go_packages(
    manifest_digest, artifact_sha256, import_path, package_ordinal
  );

CREATE INDEX catalog_exact_go_packages_read
  ON catalog_exact_go_packages(
    manifest_digest, artifact_sha256, package_ordinal,
    import_path, package_name
  );

CREATE TABLE catalog_exact_go_package_files(
  manifest_digest TEXT NOT NULL,
  artifact_sha256 TEXT NOT NULL,
  package_ordinal INTEGER NOT NULL CHECK(package_ordinal >= 0),
  file_ordinal INTEGER NOT NULL CHECK(file_ordinal >= 0),
  relative_path TEXT NOT NULL,
  PRIMARY KEY(
    manifest_digest, artifact_sha256, package_ordinal, file_ordinal
  ),
  FOREIGN KEY(manifest_digest, artifact_sha256, package_ordinal)
    REFERENCES catalog_exact_go_packages(
      manifest_digest, artifact_sha256, package_ordinal
    ) ON DELETE CASCADE,
  FOREIGN KEY(manifest_digest, artifact_sha256, relative_path)
    REFERENCES catalog_exact_go_source_files(
      manifest_digest, artifact_sha256, relative_path
    ) ON DELETE CASCADE
) STRICT;

CREATE INDEX catalog_exact_go_package_files_read
  ON catalog_exact_go_package_files(
    manifest_digest, artifact_sha256, relative_path, package_ordinal
  );

CREATE INDEX catalog_exact_go_package_files_ordered_read
  ON catalog_exact_go_package_files(
    manifest_digest, artifact_sha256, package_ordinal, file_ordinal
  );
