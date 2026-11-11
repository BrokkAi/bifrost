-- #9737: seek selected Rust route questions by file, package, and crate name.
CREATE INDEX resolution_unit_summary_members_path
  ON resolution_unit_summary_members(rel_path, summary_id);

-- Rebuild to make the derived package key mandatory for historical rows too.
CREATE TABLE rust_resolution_unit_summary_file_naming_new (
  summary_id INTEGER NOT NULL,
  member_ordinal INTEGER NOT NULL CHECK(member_ordinal >= 0),
  package_components BLOB NOT NULL
    CHECK(json_valid(package_components, 8) AND json_type(package_components) = 'array'),
  package_path TEXT NOT NULL,
  root_components BLOB NOT NULL
    CHECK(json_valid(root_components, 8) AND json_type(root_components) = 'array'),
  PRIMARY KEY(summary_id, member_ordinal),
  FOREIGN KEY(summary_id, member_ordinal)
    REFERENCES resolution_unit_summary_members(summary_id, member_ordinal) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

INSERT INTO rust_resolution_unit_summary_file_naming_new(
  summary_id, member_ordinal, package_components, package_path, root_components)
SELECT summary_id, member_ordinal, package_components,
       COALESCE((SELECT group_concat(value, '.') FROM (
         SELECT value FROM json_each(old.package_components) ORDER BY CAST(key AS INTEGER)
       )), ''),
       root_components
FROM rust_resolution_unit_summary_file_naming AS old;

DROP TABLE rust_resolution_unit_summary_file_naming;
ALTER TABLE rust_resolution_unit_summary_file_naming_new
  RENAME TO rust_resolution_unit_summary_file_naming;

CREATE INDEX rust_resolution_unit_summary_file_naming_package
  ON rust_resolution_unit_summary_file_naming(package_path, summary_id, member_ordinal);

CREATE INDEX rust_crate_topologies_name_kind
  ON rust_crate_topologies(crate_name, target_kind, topology_id);
