-- Source observation: `<root>.modules[__name__] = <value>`. top_level=1 when
-- the statement is a direct child of the module. Registry authority, key
-- binding and value identity are proved at demand time; an unproven row
-- opens the module object for importers.
CREATE TABLE python_module_registry_writes(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 registry_reference INTEGER NOT NULL,
 key_reference INTEGER NOT NULL,
 value_reference INTEGER,
 top_level INTEGER NOT NULL CHECK(top_level IN (0,1)),
 PRIMARY KEY(blob_id, registry_reference),
 FOREIGN KEY(blob_id, registry_reference) REFERENCES resolution_sites(blob_id, site),
 FOREIGN KEY(blob_id, key_reference) REFERENCES resolution_sites(blob_id, site),
 FOREIGN KEY(blob_id, value_reference) REFERENCES resolution_sites(blob_id, site)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_module_registry_writes_key ON python_module_registry_writes(blob_id,key_reference);
CREATE INDEX python_module_registry_writes_value ON python_module_registry_writes(blob_id,value_reference);
