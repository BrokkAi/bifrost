-- Persist Rust generic type-alias formals, target expressions, and ordered
-- application arguments as rows so query-local substitution can follow the
-- declared type graph without serialized syntax payloads.
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_type_argument_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_type_argument_count >= 0);
ALTER TABLE resolution_fragment_interiors ADD COLUMN expected_generic_type_alias_parameter_count
  INTEGER NOT NULL DEFAULT 0 CHECK(expected_generic_type_alias_parameter_count >= 0);

CREATE TABLE resolution_type_arguments (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  application_slot INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  argument_slot INTEGER NOT NULL,
  indirection_delta INTEGER NOT NULL CHECK(indirection_delta BETWEEN -128 AND 127),
  reference_indirection_delta INTEGER NOT NULL CHECK(reference_indirection_delta BETWEEN -128 AND 127),
  PRIMARY KEY(blob_id, application_slot, ordinal),
  FOREIGN KEY(blob_id, application_slot)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, argument_slot)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

CREATE TABLE resolution_generic_type_alias_parameters (
  blob_id INTEGER NOT NULL REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  alias_definition INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  parameter_definition INTEGER NOT NULL,
  target_slot INTEGER NOT NULL,
  indirection_delta INTEGER NOT NULL CHECK(indirection_delta BETWEEN -128 AND 127),
  reference_indirection_delta INTEGER NOT NULL CHECK(reference_indirection_delta BETWEEN -128 AND 127),
  PRIMARY KEY(blob_id, alias_definition, ordinal),
  UNIQUE(blob_id, parameter_definition),
  FOREIGN KEY(blob_id, alias_definition)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, parameter_definition)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(blob_id, target_slot)
    REFERENCES resolution_semantic_catalog(blob_id, local_key) DEFERRABLE INITIALLY DEFERRED
) WITHOUT ROWID, STRICT;

-- Alias expansion reads formal rows by alias_definition; the primary key
-- covers that query. This reverse index supports target-slot ownership checks.
CREATE INDEX resolution_generic_type_alias_parameters_target
  ON resolution_generic_type_alias_parameters(blob_id, target_slot, alias_definition);
