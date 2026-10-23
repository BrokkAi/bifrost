-- Direct alias source observations for dormant Python reverse nomination.
CREATE TEMP TABLE saved_python_binding_imports AS SELECT * FROM python_binding_imports;
DROP TABLE python_binding_imports;
CREATE TABLE resolution_binding_events_new(
 blob_id INTEGER NOT NULL,
 event INTEGER NOT NULL,
 slot INTEGER NOT NULL,
 target INTEGER NOT NULL,
 kind INTEGER NOT NULL,
 authored INTEGER,
 value_slot INTEGER,
 execution_scope INTEGER NOT NULL,
 entry_byte INTEGER NOT NULL CHECK(entry_byte>=0),
 commit_byte INTEGER NOT NULL CHECK(commit_byte>=entry_byte),
 phase INTEGER NOT NULL CHECK(phase>=0),
 source_reference INTEGER,
 PRIMARY KEY(blob_id,event),
 FOREIGN KEY(blob_id,source_reference) REFERENCES resolution_sites(blob_id,site),
 FOREIGN KEY(blob_id,slot) REFERENCES resolution_binding_slots(blob_id,slot) ON DELETE CASCADE,
 FOREIGN KEY(blob_id,target) REFERENCES resolution_sites(blob_id,site),
 FOREIGN KEY(blob_id,authored) REFERENCES resolution_sites(blob_id,site),
 FOREIGN KEY(blob_id,execution_scope) REFERENCES resolution_binding_scopes(blob_id,scope)
) WITHOUT ROWID, STRICT;
INSERT INTO resolution_binding_events_new SELECT *,NULL FROM resolution_binding_events;
DROP TABLE resolution_binding_events;
ALTER TABLE resolution_binding_events_new RENAME TO resolution_binding_events;
CREATE INDEX resolution_binding_events_cell ON resolution_binding_events(blob_id,slot,execution_scope,commit_byte,phase,event);
CREATE INDEX resolution_binding_events_target ON resolution_binding_events(blob_id,target);
CREATE INDEX resolution_binding_events_authored ON resolution_binding_events(blob_id,authored);
CREATE INDEX resolution_binding_events_execution ON resolution_binding_events(blob_id,execution_scope);
CREATE INDEX resolution_binding_events_source ON resolution_binding_events(blob_id,source_reference,event);
CREATE TABLE python_binding_imports(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 import_site INTEGER NOT NULL,
 form INTEGER NOT NULL CHECK(form BETWEEN 0 AND 2),
 relative_level INTEGER NOT NULL CHECK(relative_level>=0),
 module_segments INTEGER NOT NULL CHECK(module_segments>=0),
 binding_event INTEGER,
 PRIMARY KEY(blob_id,import_site),
 FOREIGN KEY(blob_id,binding_event) REFERENCES resolution_binding_events(blob_id,event)
) WITHOUT ROWID, STRICT;
INSERT INTO python_binding_imports SELECT * FROM temp.saved_python_binding_imports;
DROP TABLE temp.saved_python_binding_imports;
CREATE INDEX python_binding_imports_event ON python_binding_imports(blob_id,binding_event);
CREATE INDEX python_unit_summary_imports_reverse ON python_unit_summary_imports(summary_id,target_container,requested_name,form,member_ordinal,import_site);
