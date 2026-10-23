-- Dormant temporal inputs. These are source occurrences, never query answers.
CREATE TABLE resolution_binding_scopes(
 blob_id INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
 scope INTEGER NOT NULL,
 parent_scope INTEGER,
 PRIMARY KEY(blob_id,scope),
 FOREIGN KEY(blob_id,parent_scope) REFERENCES resolution_binding_scopes(blob_id,scope)
) WITHOUT ROWID, STRICT;
CREATE INDEX resolution_binding_scopes_parent ON resolution_binding_scopes(blob_id,parent_scope);
CREATE TABLE resolution_binding_slots(
 blob_id INTEGER NOT NULL,
 slot INTEGER NOT NULL,
 scope INTEGER NOT NULL,
 name TEXT NOT NULL,
 whole_scope INTEGER NOT NULL CHECK(whole_scope IN (0,1)),
 PRIMARY KEY(blob_id,slot),
 FOREIGN KEY(blob_id,scope) REFERENCES resolution_binding_scopes(blob_id,scope) ON DELETE CASCADE,
 FOREIGN KEY(blob_id,slot) REFERENCES resolution_sites(blob_id,site) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX resolution_binding_slots_name ON resolution_binding_slots(blob_id,scope,name);
CREATE TABLE resolution_binding_events(
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
 PRIMARY KEY(blob_id,event),
 FOREIGN KEY(blob_id,slot) REFERENCES resolution_binding_slots(blob_id,slot) ON DELETE CASCADE,
 FOREIGN KEY(blob_id,target) REFERENCES resolution_sites(blob_id,site),
 FOREIGN KEY(blob_id,authored) REFERENCES resolution_sites(blob_id,site),
 FOREIGN KEY(blob_id,execution_scope) REFERENCES resolution_binding_scopes(blob_id,scope)
) WITHOUT ROWID, STRICT;
CREATE INDEX resolution_binding_events_cell ON resolution_binding_events(blob_id,slot,execution_scope,commit_byte,phase,event);
CREATE INDEX resolution_binding_events_target ON resolution_binding_events(blob_id,target);
CREATE INDEX resolution_binding_events_authored ON resolution_binding_events(blob_id,authored);
CREATE INDEX resolution_binding_events_execution ON resolution_binding_events(blob_id,execution_scope);
CREATE TABLE resolution_binding_observations(
 blob_id INTEGER NOT NULL,
 reference INTEGER NOT NULL,
 execution_scope INTEGER NOT NULL,
 point_byte INTEGER NOT NULL CHECK(point_byte>=0),
 deferred INTEGER NOT NULL CHECK(deferred IN (0,1)),
 PRIMARY KEY(blob_id,reference),
 FOREIGN KEY(blob_id,reference) REFERENCES resolution_sites(blob_id,site) ON DELETE CASCADE,
 FOREIGN KEY(blob_id,execution_scope) REFERENCES resolution_binding_scopes(blob_id,scope)
) WITHOUT ROWID, STRICT;
CREATE TABLE resolution_binding_directives(
 blob_id INTEGER NOT NULL,
 reference INTEGER NOT NULL,
 kind INTEGER NOT NULL CHECK(kind IN (0,1)),
 name TEXT NOT NULL,
 target INTEGER,
 PRIMARY KEY(blob_id,reference),
 FOREIGN KEY(blob_id,reference) REFERENCES resolution_sites(blob_id,site) ON DELETE CASCADE,
 FOREIGN KEY(blob_id,target) REFERENCES resolution_binding_slots(blob_id,slot)
) WITHOUT ROWID, STRICT;
CREATE INDEX resolution_binding_observations_execution ON resolution_binding_observations(blob_id,execution_scope);
CREATE INDEX resolution_binding_directives_target ON resolution_binding_directives(blob_id,target);
CREATE TABLE python_binding_source(
 blob_id INTEGER PRIMARY KEY REFERENCES blobs(id) ON DELETE CASCADE,
 format INTEGER NOT NULL CHECK(format>0)
) STRICT;
CREATE TABLE python_binding_guards(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 guard INTEGER NOT NULL,
 parent INTEGER,
 site INTEGER NOT NULL,
 execution_scope INTEGER NOT NULL,
 kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 9),
 arm INTEGER NOT NULL,
 predicate INTEGER,
 PRIMARY KEY(blob_id,guard),
 FOREIGN KEY(blob_id,parent) REFERENCES python_binding_guards(blob_id,guard),
 FOREIGN KEY(blob_id,execution_scope) REFERENCES resolution_binding_scopes(blob_id,scope)
) WITHOUT ROWID, STRICT;
CREATE TABLE python_binding_site_guards(
 blob_id INTEGER NOT NULL,
 site INTEGER NOT NULL,
 guard INTEGER NOT NULL,
 PRIMARY KEY(blob_id,site),
 FOREIGN KEY(blob_id,guard) REFERENCES python_binding_guards(blob_id,guard) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
CREATE INDEX python_binding_guards_parent ON python_binding_guards(blob_id,parent);
CREATE INDEX python_binding_guards_execution ON python_binding_guards(blob_id,execution_scope);
CREATE INDEX python_binding_site_guards_guard ON python_binding_site_guards(blob_id,guard);
CREATE TABLE python_binding_predicates(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 predicate INTEGER NOT NULL,
 kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 4),
 operand INTEGER,
 PRIMARY KEY(blob_id,predicate),
 FOREIGN KEY(blob_id,operand) REFERENCES resolution_sites(blob_id,site)
) WITHOUT ROWID, STRICT;
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
CREATE INDEX python_binding_predicates_operand ON python_binding_predicates(blob_id,operand);
CREATE INDEX python_binding_imports_event ON python_binding_imports(blob_id,binding_event);
