-- #12967: Ruby method signatures declared in workspace RBS files
-- (sig/**/*.rbs), one head per signature file blob and producer identity.
-- Rows exist only for the leading required positionals of single-overload
-- methods whose declared type is a plain class type. A constant path is
-- stored '::'-joined; Ruby constant names cannot contain ':'.
CREATE TABLE ruby_signature_files(
  signature_file_id INTEGER PRIMARY KEY,
  content_oid TEXT NOT NULL
    CHECK(length(content_oid) = 40 AND content_oid NOT GLOB '*[^0-9a-f]*'),
  producer_identity BLOB NOT NULL
    CHECK(typeof(producer_identity) = 'blob' AND length(producer_identity) = 32),
  parse_state TEXT NOT NULL CHECK(parse_state IN ('complete', 'parse_error', 'over_limit')),
  UNIQUE(content_oid, producer_identity)
) STRICT;
CREATE TABLE ruby_signature_methods(
  signature_file_id INTEGER NOT NULL
    REFERENCES ruby_signature_files(signature_file_id) ON DELETE CASCADE,
  method_ordinal INTEGER NOT NULL CHECK(method_ordinal >= 0),
  owner TEXT NOT NULL CHECK(length(owner) > 0),
  member TEXT NOT NULL CHECK(length(member) > 0),
  is_singleton INTEGER NOT NULL CHECK(is_singleton IN (0, 1)),
  overload_count INTEGER NOT NULL CHECK(overload_count >= 0),
  leading_required INTEGER NOT NULL CHECK(leading_required >= 0),
  PRIMARY KEY(signature_file_id, method_ordinal)
) WITHOUT ROWID, STRICT;
CREATE TABLE ruby_signature_positionals(
  signature_file_id INTEGER NOT NULL,
  method_ordinal INTEGER NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  receiver_absolute INTEGER NOT NULL CHECK(receiver_absolute IN (0, 1)),
  receiver_name TEXT NOT NULL CHECK(length(receiver_name) > 0),
  argument_count INTEGER NOT NULL CHECK(argument_count >= 0),
  element_absolute INTEGER CHECK(element_absolute IN (0, 1)),
  element_name TEXT CHECK(element_name IS NULL OR length(element_name) > 0),
  PRIMARY KEY(signature_file_id, method_ordinal, ordinal),
  FOREIGN KEY(signature_file_id, method_ordinal)
    REFERENCES ruby_signature_methods(signature_file_id, method_ordinal) ON DELETE CASCADE,
  CHECK((element_name IS NULL) = (element_absolute IS NULL)),
  CHECK(element_name IS NULL OR argument_count = 1)
) WITHOUT ROWID, STRICT;

-- Every class or module constant a signature file declares, '::'-joined. A
-- relative RBS type name one of these could name is not typed.
CREATE TABLE ruby_signature_types(
  signature_file_id INTEGER NOT NULL
    REFERENCES ruby_signature_files(signature_file_id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK(length(name) > 0),
  PRIMARY KEY(signature_file_id, name)
) WITHOUT ROWID, STRICT;
CREATE INDEX ruby_signature_types_name ON ruby_signature_types(name);

-- Garbage collection bumps this epoch whenever it deletes a head, so a
-- reader that checked its heads once can tell that one may have gone since.
CREATE TABLE ruby_signature_collection_epoch(
  id INTEGER PRIMARY KEY CHECK(id = 1),
  epoch INTEGER NOT NULL CHECK(epoch >= 0)
) STRICT;
INSERT INTO ruby_signature_collection_epoch(id, epoch) VALUES (1, 0);

-- The typer asks for one (owner, member) at a time.
CREATE INDEX ruby_signature_methods_name ON ruby_signature_methods(owner, member);
