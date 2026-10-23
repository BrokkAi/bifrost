-- Dormant native member inputs. Candidate roles require selected identity proof.
CREATE TABLE python_member_sites(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 site INTEGER NOT NULL CHECK(site>=0),
 scope INTEGER NOT NULL,
 start_byte INTEGER NOT NULL CHECK(start_byte>=0),
 end_byte INTEGER NOT NULL CHECK(end_byte>=start_byte),
 PRIMARY KEY(blob_id,site),
 FOREIGN KEY(blob_id,scope) REFERENCES resolution_binding_scopes(blob_id,scope)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_sites_scope ON python_member_sites(blob_id,scope);
CREATE TABLE python_member_type_slots(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 slot INTEGER NOT NULL CHECK(slot>=0),
 site INTEGER NOT NULL,
 PRIMARY KEY(blob_id,slot),
 FOREIGN KEY(blob_id,site) REFERENCES python_member_sites(blob_id,site)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_type_slots_site ON python_member_type_slots(blob_id,site);
CREATE TABLE python_member_classes(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 class INTEGER NOT NULL,
 metaclass INTEGER,
 bases_complete INTEGER NOT NULL CHECK(bases_complete IN (0,1)),
 PRIMARY KEY(blob_id,class),
 FOREIGN KEY(blob_id,class) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,metaclass) REFERENCES python_member_sites(blob_id,site)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_classes_metaclass ON python_member_classes(blob_id,metaclass);
CREATE TABLE python_member_base_operands(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 class INTEGER NOT NULL,
 ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 expression_site INTEGER NOT NULL,
 slot INTEGER NOT NULL,
 kind INTEGER NOT NULL CHECK(kind>=0),
 PRIMARY KEY(blob_id,class,ordinal),
 FOREIGN KEY(blob_id,class) REFERENCES python_member_classes(blob_id,class),
 FOREIGN KEY(blob_id,expression_site) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,slot) REFERENCES python_member_type_slots(blob_id,slot)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_base_operands_expression_site ON python_member_base_operands(blob_id,expression_site);
CREATE INDEX python_member_base_operands_slot ON python_member_base_operands(blob_id,slot);
CREATE TABLE python_member_class_keywords(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 class INTEGER NOT NULL,
 ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 expression_site INTEGER NOT NULL,
 value INTEGER NOT NULL,
 name TEXT,
 PRIMARY KEY(blob_id,class,ordinal),
 FOREIGN KEY(blob_id,class) REFERENCES python_member_classes(blob_id,class),
 FOREIGN KEY(blob_id,expression_site) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,value) REFERENCES python_member_type_slots(blob_id,slot)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_class_keywords_expression_site ON python_member_class_keywords(blob_id,expression_site);
CREATE INDEX python_member_class_keywords_value ON python_member_class_keywords(blob_id,value);
CREATE TABLE python_member_member_roles(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 owner INTEGER NOT NULL,
 member INTEGER NOT NULL,
 kind INTEGER NOT NULL CHECK(kind>=0),
 callable INTEGER,
 receiver_parameter INTEGER,
 PRIMARY KEY(blob_id,owner,member),
 FOREIGN KEY(blob_id,owner) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,member) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,callable) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,receiver_parameter) REFERENCES python_member_sites(blob_id,site)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_member_roles_member ON python_member_member_roles(blob_id,member);
CREATE INDEX python_member_member_roles_callable ON python_member_member_roles(blob_id,callable);
CREATE INDEX python_member_member_roles_receiver_parameter ON python_member_member_roles(blob_id,receiver_parameter);
CREATE TABLE python_member_decorators(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 declaration INTEGER NOT NULL,
 ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 expression_site INTEGER NOT NULL,
 value_slot INTEGER NOT NULL,
 role INTEGER NOT NULL CHECK(role>=0),
 PRIMARY KEY(blob_id,declaration,ordinal),
 FOREIGN KEY(blob_id,declaration) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,expression_site) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,value_slot) REFERENCES python_member_type_slots(blob_id,slot)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_decorators_expression_site ON python_member_decorators(blob_id,expression_site);
CREATE INDEX python_member_decorators_value_slot ON python_member_decorators(blob_id,value_slot);
CREATE TABLE python_member_parameters(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 callable INTEGER NOT NULL,
 parameter INTEGER NOT NULL,
 ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 kind INTEGER NOT NULL CHECK(kind>=0),
 PRIMARY KEY(blob_id,callable,ordinal),
 FOREIGN KEY(blob_id,callable) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,parameter) REFERENCES python_member_sites(blob_id,site)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_parameters_parameter ON python_member_parameters(blob_id,parameter);
CREATE TABLE python_member_call_arguments(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 call INTEGER NOT NULL,
 ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 kind INTEGER NOT NULL CHECK(kind>=0),
 value INTEGER NOT NULL,
 PRIMARY KEY(blob_id,call,ordinal),
 FOREIGN KEY(blob_id,call) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,value) REFERENCES python_member_type_slots(blob_id,slot)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_call_arguments_value ON python_member_call_arguments(blob_id,value);
CREATE TABLE python_member_annotations(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 owner INTEGER NOT NULL,
 syntax_site INTEGER NOT NULL,
 type_slot INTEGER NOT NULL,
 mode INTEGER NOT NULL CHECK(mode>=0),
 PRIMARY KEY(blob_id,owner,syntax_site),
 FOREIGN KEY(blob_id,owner) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,syntax_site) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,type_slot) REFERENCES python_member_type_slots(blob_id,slot)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_annotations_syntax_site ON python_member_annotations(blob_id,syntax_site);
CREATE INDEX python_member_annotations_type_slot ON python_member_annotations(blob_id,type_slot);
CREATE TABLE python_member_receiver_writes(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 site INTEGER NOT NULL,
 receiver INTEGER NOT NULL,
 value INTEGER,
 PRIMARY KEY(blob_id,site),
 FOREIGN KEY(blob_id,site) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,receiver) REFERENCES python_member_type_slots(blob_id,slot),
 FOREIGN KEY(blob_id,value) REFERENCES python_member_type_slots(blob_id,slot)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_receiver_writes_receiver ON python_member_receiver_writes(blob_id,receiver);
CREATE INDEX python_member_receiver_writes_value ON python_member_receiver_writes(blob_id,value);

CREATE TABLE python_member_super_contexts(
 blob_id INTEGER NOT NULL REFERENCES python_binding_source(blob_id) ON DELETE CASCADE,
 call INTEGER NOT NULL, callee INTEGER NOT NULL, callable INTEGER, class_cell INTEGER, first_parameter INTEGER,
 PRIMARY KEY(blob_id,call),
 FOREIGN KEY(blob_id,call) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,callee) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,callable) REFERENCES python_member_sites(blob_id,site),
 FOREIGN KEY(blob_id,class_cell) REFERENCES python_member_classes(blob_id,class),
 FOREIGN KEY(blob_id,first_parameter) REFERENCES python_member_sites(blob_id,site)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_super_contexts_callee ON python_member_super_contexts(blob_id,callee);
CREATE INDEX python_member_super_contexts_callable ON python_member_super_contexts(blob_id,callable);
CREATE INDEX python_member_super_contexts_class_cell ON python_member_super_contexts(blob_id,class_cell);
CREATE INDEX python_member_super_contexts_first_parameter ON python_member_super_contexts(blob_id,first_parameter);

CREATE TABLE python_member_super_members(
 blob_id INTEGER NOT NULL, call INTEGER NOT NULL, member INTEGER NOT NULL,
 PRIMARY KEY(blob_id,member),
 FOREIGN KEY(blob_id,call) REFERENCES python_member_super_contexts(blob_id,call) ON DELETE CASCADE,
 FOREIGN KEY(blob_id,member) REFERENCES python_member_sites(blob_id,site)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_super_members_call ON python_member_super_members(blob_id,call);
CREATE TABLE python_member_decorator_receivers(
 blob_id INTEGER NOT NULL, declaration INTEGER NOT NULL, ordinal INTEGER NOT NULL, receiver INTEGER NOT NULL,
 PRIMARY KEY(blob_id,declaration,ordinal),
 FOREIGN KEY(blob_id,declaration,ordinal) REFERENCES python_member_decorators(blob_id,declaration,ordinal) ON DELETE CASCADE,
 FOREIGN KEY(blob_id,receiver) REFERENCES python_member_sites(blob_id,site)
) WITHOUT ROWID, STRICT;
CREATE INDEX python_member_decorator_receivers_receiver ON python_member_decorator_receivers(blob_id,receiver);
