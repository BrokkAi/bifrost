-- Add Kotlin's package-scope choice identity while preserving earlier package rows.
-- Rows written before Kotlin S1 remain valid with a NULL choice_key.
CREATE TABLE resolution_package_references_0147 (
  blob_id INTEGER NOT NULL,
  token_key INTEGER NOT NULL CHECK(token_key>=0),
  domain_key INTEGER NOT NULL CHECK(domain_key>=0),
  reference_key INTEGER NOT NULL CHECK(reference_key>=0),
  choice_key INTEGER CHECK(choice_key IS NULL OR choice_key>=0),
  source_site INTEGER NOT NULL CHECK(source_site BETWEEN 0 AND 4294967295),
  root_scope_key INTEGER NOT NULL CHECK(root_scope_key>=0),
  namespace TEXT NOT NULL CHECK(namespace IN ('type','value','callable','package')),
  lookup_key INTEGER NOT NULL CHECK(lookup_key>=0),
  PRIMARY KEY(blob_id,token_key),
  UNIQUE(blob_id,reference_key,namespace),
  FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE,
  FOREIGN KEY(blob_id,token_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,domain_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,reference_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,choice_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,lookup_key) REFERENCES resolution_semantic_catalog(blob_id,local_key),
  FOREIGN KEY(blob_id,root_scope_key) REFERENCES resolution_node_catalog(blob_id,local_key)
) WITHOUT ROWID, STRICT;

INSERT INTO resolution_package_references_0147(
  blob_id,token_key,domain_key,reference_key,choice_key,source_site,
  root_scope_key,namespace,lookup_key
)
SELECT blob_id,token_key,domain_key,reference_key,NULL,source_site,
       root_scope_key,namespace,lookup_key
FROM resolution_package_references;

DROP TABLE resolution_package_references;
ALTER TABLE resolution_package_references_0147 RENAME TO resolution_package_references;
CREATE INDEX resolution_package_references_domain ON resolution_package_references(blob_id,domain_key);
CREATE INDEX resolution_package_references_lookup ON resolution_package_references(blob_id,lookup_key);
CREATE INDEX resolution_package_references_scope ON resolution_package_references(blob_id,root_scope_key);
