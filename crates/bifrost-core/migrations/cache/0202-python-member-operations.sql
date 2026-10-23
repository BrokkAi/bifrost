-- Source observations only. Callee spelling never proves builtin/model authority.
CREATE TABLE python_member_operations(
 id INTEGER PRIMARY KEY,
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 site INTEGER NOT NULL, name_site INTEGER NOT NULL,
 form INTEGER NOT NULL CHECK(form BETWEEN 0 AND 6),
 effect INTEGER NOT NULL CHECK(effect BETWEEN 0 AND 2),
 name_kind INTEGER NOT NULL CHECK(name_kind BETWEEN 0 AND 2),
 callee_reference INTEGER, receiver_reference INTEGER, receiver_slot INTEGER,
 UNIQUE(blob_id,site,form),
 CHECK(effect=CASE form WHEN 0 THEN 0 WHEN 2 THEN 2 ELSE 1 END),
 FOREIGN KEY(blob_id,site) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,name_site) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,callee_reference) REFERENCES resolution_sites(blob_id,site),
 FOREIGN KEY(blob_id,receiver_reference) REFERENCES resolution_sites(blob_id,site),
 FOREIGN KEY(blob_id,receiver_slot) REFERENCES python_member_type_slots(blob_id,slot)
) STRICT;
CREATE INDEX python_member_operations_name_site ON python_member_operations(blob_id,name_site);
CREATE INDEX python_member_operations_callee ON python_member_operations(blob_id,callee_reference);
CREATE INDEX python_member_operations_receiver ON python_member_operations(blob_id,receiver_reference);
CREATE INDEX python_member_operations_slot ON python_member_operations(blob_id,receiver_slot);
CREATE INDEX python_member_operations_inventory ON python_member_operations(blob_id,name_kind,effect,site);
CREATE TABLE python_member_operation_names(
 operation INTEGER NOT NULL REFERENCES python_member_operations(id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL CHECK(ordinal>=0), spelling TEXT NOT NULL,
 PRIMARY KEY(operation,ordinal), UNIQUE(operation,spelling)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_operation_names_spelling ON python_member_operation_names(spelling,operation);
