//! Indexed active-stage row families. Runtime semantics keep their domain in
//! exclusive nullable key/shared columns; index sentinels never enter rows.

use crate::analyzer::resolution::BindingNodeId;
use std::sync::OnceLock;

fn semantic_columns(name: &str) -> String {
    format!(
        "{name}_key INTEGER CHECK({name}_key IS NULL OR {name}_key>=0), \
             {name}_shared INTEGER CHECK({name}_shared IS NULL OR {name}_shared>0)"
    )
}

fn semantic_index(name: &str) -> String {
    format!("COALESCE({name}_key,-1),COALESCE({name}_shared,-1)")
}

struct TypedFamily {
    name: &'static str,
    semantics: &'static [&'static str],
    columns: &'static str,
    unique: &'static [&'static [&'static str]],
    seeks: &'static [&'static [&'static str]],
}

const TYPED_FAMILIES: &[TypedFamily] = &[
    TypedFamily {
        name: "type_frontiers",
        semantics: &["slot"],
        columns: "role INTEGER NOT NULL, identity_reference_key INTEGER, identity_reference_shared INTEGER, identity_reference_node INTEGER, CHECK((identity_reference_key IS NULL AND identity_reference_shared IS NULL AND identity_reference_node IS NULL) OR (((identity_reference_key IS NULL)<>(identity_reference_shared IS NULL)) AND identity_reference_node IS NOT NULL)), CHECK(identity_reference_key IS NULL OR identity_reference_key>=0), CHECK(identity_reference_shared IS NULL OR identity_reference_shared>0)",
        unique: &[&["slot"]],
        seeks: &[&["slot"]],
    },
    TypedFamily {
        name: "type_transfers",
        semantics: &["source_slot", "rule", "target_slot"],
        columns: "kind INTEGER NOT NULL, indirection_delta INTEGER NOT NULL, reference_indirection_delta INTEGER NOT NULL, value_transform INTEGER NOT NULL, completion BLOB CHECK(completion IS NULL OR json_valid(completion,8))",
        unique: &[&["rule"]],
        seeks: &[&["source_slot"], &["target_slot"], &["rule"]],
    },
    TypedFamily {
        name: "type_components",
        semantics: &["container_slot", "component_slot"],
        columns: "constructor INTEGER NOT NULL, kind INTEGER NOT NULL",
        unique: &[&["container_slot", "kind"]],
        seeks: &[&["container_slot"], &["component_slot"]],
    },
    TypedFamily {
        name: "underlying_types",
        semantics: &["definition", "slot"],
        columns: "",
        unique: &[&["definition"]],
        seeks: &[&["definition"], &["slot"]],
    },
    TypedFamily {
        name: "intrinsic_seeds",
        semantics: &["slot"],
        columns: "kind INTEGER NOT NULL, spelling TEXT NOT NULL, possible_values BLOB NOT NULL CHECK(json_valid(possible_values,8)), completion BLOB CHECK(completion IS NULL OR json_valid(completion,8))",
        unique: &[&["slot", "kind"]],
        seeks: &[&["slot"]],
    },
    TypedFamily {
        name: "intrinsic_seed_identities",
        semantics: &["identity", "slot"],
        columns: "",
        unique: &[&["identity", "slot"]],
        seeks: &[&["identity"]],
    },
    TypedFamily {
        name: "binding_projections",
        semantics: &["reference", "output_slot"],
        columns: "kind INTEGER NOT NULL",
        unique: &[&["reference", "output_slot"]],
        seeks: &[&["reference"], &["output_slot"]],
    },
    TypedFamily {
        name: "qualified_routes",
        semantics: &[
            "reference",
            "qualifier_slot",
            "lookup",
            "source_lookup",
            "projection_output_slot",
            "coarse_gap_reason",
        ],
        columns: "precedence_ordinal INTEGER NOT NULL CHECK(precedence_ordinal>=0), namespace INTEGER NOT NULL, projection_kind INTEGER NOT NULL, open_member_surface INTEGER NOT NULL DEFAULT 0 CHECK(open_member_surface IN (0,1))",
        unique: &[&["reference", "precedence_ordinal", "projection_output_slot"]],
        seeks: &[
            &["reference"],
            &["qualifier_slot", "lookup"],
            &["source_lookup", "qualifier_slot"],
            &["lookup"],
            &["coarse_gap_reason"],
        ],
    },
    TypedFamily {
        name: "declaration_types",
        semantics: &["definition", "slot"],
        columns: "role INTEGER NOT NULL",
        unique: &[&["definition", "role"]],
        seeks: &[&["definition"], &["slot"]],
    },
    TypedFamily {
        name: "declaration_visibilities",
        semantics: &["definition"],
        columns: "visibility TEXT NOT NULL",
        unique: &[&["definition"]],
        seeks: &[&["definition"]],
    },
    TypedFamily {
        name: "member_scopes",
        semantics: &["definition"],
        columns: "scope_head_node INTEGER NOT NULL CHECK(scope_head_node>=0)",
        unique: &[&["definition"], &["scope_head_node"]],
        seeks: &[&["definition"], &["scope_head_node"]],
    },
    TypedFamily {
        name: "member_owners",
        semantics: &["definition", "owner_definition"],
        columns: "owner_scope_head_node INTEGER NOT NULL CHECK(owner_scope_head_node>=0), member_kind TEXT NOT NULL, member_access TEXT NOT NULL, qualifier_compatibility TEXT NOT NULL",
        unique: &[&[
            "definition",
            "member_kind",
            "member_access",
            "qualifier_compatibility",
            "owner_definition",
            "owner_scope_head_node",
        ]],
        seeks: &[&["definition"], &["owner_definition"]],
    },
    TypedFamily {
        name: "deferred_member_owners",
        semantics: &["definition", "lookup"],
        columns: "body BLOB NOT NULL CHECK(json_valid(body,8))",
        unique: &[&["definition"]],
        seeks: &[&["definition"], &["lookup"]],
    },
    TypedFamily {
        name: "construction_requirements",
        semantics: &["definition", "required_owner_definition"],
        columns: "kind INTEGER NOT NULL",
        unique: &[&["definition", "kind", "required_owner_definition"]],
        seeks: &[&["definition"]],
    },
    TypedFamily {
        name: "supertypes",
        semantics: &["definition", "reference", "frontier"],
        columns: "kind INTEGER NOT NULL",
        unique: &[&["definition", "kind", "reference", "frontier"]],
        seeks: &[&["definition"], &["reference"], &["frontier"]],
    },
    TypedFamily {
        name: "definition_property_gaps",
        semantics: &["definition", "frontier", "reason"],
        columns: "kind INTEGER NOT NULL, source_site INTEGER NOT NULL CHECK(source_site>=0)",
        unique: &[&["definition", "reason", "frontier"]],
        seeks: &[&["definition"], &["reason"]],
    },
    TypedFamily {
        name: "call_obligations",
        semantics: &[
            "callee_reference",
            "call",
            "result_slot",
            "applicability_reason",
        ],
        columns: "receiver_slot_key INTEGER CHECK(receiver_slot_key IS NULL OR receiver_slot_key>=0), receiver_slot_shared INTEGER CHECK(receiver_slot_shared IS NULL OR receiver_slot_shared>0), explicit_type_argument_count INTEGER NOT NULL CHECK(explicit_type_argument_count>=0), argument_slots BLOB NOT NULL CHECK(json_valid(argument_slots,8)), type_argument_slots BLOB NOT NULL CHECK(json_valid(type_argument_slots,8)), eligible_rules BLOB NOT NULL CHECK(json_valid(eligible_rules,8)), completion BLOB CHECK(completion IS NULL OR json_valid(completion,8)), CHECK(receiver_slot_key IS NULL OR receiver_slot_shared IS NULL)",
        unique: &[&["call"], &["callee_reference"]],
        seeks: &[&["callee_reference"], &["applicability_reason"]],
    },
    TypedFamily {
        name: "callable_parameters",
        semantics: &["parameter_definition", "signature_definition", "slot"],
        columns: "",
        unique: &[&["parameter_definition"]],
        seeks: &[&["parameter_definition"]],
    },
    TypedFamily {
        name: "callable_signatures",
        semantics: &["definition"],
        columns: "body BLOB NOT NULL CHECK(json_valid(body,8))",
        unique: &[&["definition"]],
        seeks: &[&["definition"]],
    },
];

pub(super) fn schema_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let sql = {
        let root = BindingNodeId::universal_root().get();
        let mut sql = format!(r#"
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_nodes(
 node INTEGER PRIMARY KEY CHECK(node>=0), kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 9),
 kind_semantic_key INTEGER CHECK(kind_semantic_key IS NULL OR kind_semantic_key>=0),
 kind_shared_id INTEGER CHECK(kind_shared_id IS NULL OR kind_shared_id>0),
 kind_target_node INTEGER CHECK(kind_target_node IS NULL OR kind_target_node>=0),
 CHECK((kind IN (0,1,6) AND kind_semantic_key IS NULL AND kind_shared_id IS NULL AND kind_target_node IS NULL)
    OR (kind IN (2,3,4,5,8,9) AND ((kind_semantic_key IS NULL)<>(kind_shared_id IS NULL)) AND kind_target_node IS NULL)
    OR (kind=7 AND kind_semantic_key IS NULL AND kind_shared_id IS NULL AND kind_target_node IS NOT NULL))
) STRICT;
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_nodes_semantic ON selected_resolution_stage_nodes(kind,kind_semantic_key,kind_shared_id,node) WHERE kind IN(8,9);
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_node_owners(
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 node INTEGER NOT NULL REFERENCES selected_resolution_stage_nodes(node),
 PRIMARY KEY(producer_id,node)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_node_owners_node ON selected_resolution_stage_node_owners(node,producer_id);
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_paths(
 host_ordinal INTEGER NOT NULL,
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 path INTEGER NOT NULL CHECK(path>=0),
 start_node INTEGER NOT NULL CHECK(start_node>=0), end_node INTEGER NOT NULL CHECK(end_node>=0),
 start_lead_key INTEGER CHECK(start_lead_key IS NULL OR start_lead_key>=0),
 start_lead_shared INTEGER CHECK(start_lead_shared IS NULL OR start_lead_shared>0),
 start_lead_scoped INTEGER NOT NULL CHECK(start_lead_scoped IN (0,1)),
 end_lead_key INTEGER CHECK(end_lead_key IS NULL OR end_lead_key>=0),
 end_lead_shared INTEGER CHECK(end_lead_shared IS NULL OR end_lead_shared>0),
 end_lead_scoped INTEGER NOT NULL CHECK(end_lead_scoped IN (0,1)),
 end_fixed_key TEXT, end_open_tail INTEGER CHECK(end_open_tail IN (0,1)),
 root_terminal_shared INTEGER,
 body BLOB NOT NULL CHECK(json_valid(body,8)),
 CHECK(start_lead_key IS NULL OR start_lead_shared IS NULL),
 CHECK(end_lead_key IS NULL OR end_lead_shared IS NULL),
 CHECK((end_node={root} AND end_fixed_key IS NOT NULL AND end_open_tail IS NOT NULL)
    OR (end_node<>{root} AND end_fixed_key IS NULL AND end_open_tail IS NULL)),
 PRIMARY KEY(host_ordinal,path)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_paths_producer ON selected_resolution_stage_paths(producer_id);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_paths_forward ON selected_resolution_stage_paths(start_node,start_lead_shared,start_lead_key,start_lead_scoped,host_ordinal,path);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_paths_reverse ON selected_resolution_stage_paths(end_node,end_lead_shared,end_lead_key,end_lead_scoped,host_ordinal,path);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_paths_reverse_root_prefix ON selected_resolution_stage_paths(end_fixed_key COLLATE BINARY,end_open_tail,host_ordinal,path) WHERE end_node={root};
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_paths_root_terminal ON selected_resolution_stage_paths(root_terminal_shared,host_ordinal,path) WHERE end_node={root} AND root_terminal_shared IS NOT NULL;
"#);
        sql.push_str(r#"
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_semantic_coordinates(
 host_ordinal INTEGER NOT NULL,
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 dense_key INTEGER NOT NULL CHECK(dense_key>=0),
 runtime_key INTEGER CHECK(runtime_key IS NULL OR runtime_key>=0),
 shared_id INTEGER CHECK(shared_id IS NULL OR shared_id>0),
 identity_digest BLOB NOT NULL CHECK(length(identity_digest)=32),
 import_source_site INTEGER CHECK(import_source_site IS NULL OR import_source_site BETWEEN 0 AND 4294967295),
 import_start_byte INTEGER CHECK(import_start_byte IS NULL OR import_start_byte>=0),
 import_end_byte INTEGER CHECK(import_end_byte IS NULL OR import_end_byte>=import_start_byte),
 import_route_kind TEXT,
 CHECK((import_source_site IS NULL AND import_start_byte IS NULL AND import_end_byte IS NULL AND import_route_kind IS NULL)
    OR (import_source_site IS NOT NULL AND import_start_byte IS NOT NULL AND import_end_byte IS NOT NULL
        AND shared_id IS NULL AND import_route_kind IS NOT NULL
        AND import_route_kind IN ('single_type','type_on_demand','single_static','static_on_demand'))),
 CHECK((runtime_key IS NULL)<>(shared_id IS NULL)),
 PRIMARY KEY(producer_id,dense_key)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_semantic_identity ON selected_resolution_stage_semantic_coordinates(host_ordinal,identity_digest);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_semantic_runtime ON selected_resolution_stage_semantic_coordinates(runtime_key,shared_id,host_ordinal);
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_node_coordinates(
 host_ordinal INTEGER NOT NULL,
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 dense_key INTEGER NOT NULL CHECK(dense_key>=0), runtime_key INTEGER NOT NULL CHECK(runtime_key>=0),
 identity_digest BLOB NOT NULL CHECK(length(identity_digest)=32), source_scope INTEGER,
 PRIMARY KEY(producer_id,dense_key)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_node_identity ON selected_resolution_stage_node_coordinates(host_ordinal,identity_digest);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_node_runtime ON selected_resolution_stage_node_coordinates(runtime_key,host_ordinal);
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_path_coordinates(
 host_ordinal INTEGER NOT NULL,
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 dense_key INTEGER NOT NULL CHECK(dense_key>=0), runtime_key INTEGER NOT NULL CHECK(runtime_key>=0),
 identity_digest BLOB NOT NULL CHECK(length(identity_digest)=32),
 PRIMARY KEY(producer_id,dense_key)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_path_identity ON selected_resolution_stage_path_coordinates(host_ordinal,identity_digest);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_path_runtime ON selected_resolution_stage_path_coordinates(host_ordinal,runtime_key);
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_allocation_counters(
 host_ordinal INTEGER NOT NULL CHECK(host_ordinal>=0),
 domain INTEGER NOT NULL CHECK(domain BETWEEN 0 AND 4),
 next_key INTEGER NOT NULL CHECK(next_key BETWEEN 2147483648 AND 4294967296),
 PRIMARY KEY(host_ordinal,domain)
) WITHOUT ROWID, STRICT;
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_variable_coordinates(
 host_ordinal INTEGER NOT NULL CHECK(host_ordinal>=0),
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 dense_key INTEGER NOT NULL CHECK(dense_key>=0), runtime_key INTEGER NOT NULL CHECK(runtime_key>=0),
 identity_digest BLOB NOT NULL CHECK(length(identity_digest)=32),
 PRIMARY KEY(producer_id,dense_key)
) WITHOUT ROWID, STRICT;
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_package_references(
 host_ordinal INTEGER NOT NULL,
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 token_key INTEGER NOT NULL CHECK(token_key>=0),
 domain_shared INTEGER NOT NULL CHECK(domain_shared>0),
 reference_key INTEGER NOT NULL CHECK(reference_key>=0),
 source_site INTEGER NOT NULL CHECK(source_site BETWEEN 0 AND 4294967295),
 root_scope_key INTEGER NOT NULL CHECK(root_scope_key>=0),
 namespace TEXT NOT NULL CHECK(namespace IN ('type','value','callable','package')),
 lookup_shared INTEGER NOT NULL CHECK(lookup_shared>0),
 PRIMARY KEY(producer_id,token_key)
) WITHOUT ROWID, STRICT;
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_package_members(
 host_ordinal INTEGER NOT NULL,
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 token_key INTEGER NOT NULL CHECK(token_key>=0),
 domain_shared INTEGER NOT NULL CHECK(domain_shared>0),
 definition_key INTEGER NOT NULL CHECK(definition_key>=0),
 source_site INTEGER NOT NULL CHECK(source_site BETWEEN 0 AND 4294967295),
 root_scope_key INTEGER NOT NULL CHECK(root_scope_key>=0),
 namespace TEXT NOT NULL CHECK(namespace IN ('type','value','callable','package')),
 lookup_shared INTEGER NOT NULL CHECK(lookup_shared>0),
 PRIMARY KEY(producer_id,token_key,definition_key)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_package_references_host ON selected_resolution_stage_package_references(host_ordinal,token_key);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_package_references_reference ON selected_resolution_stage_package_references(reference_key,host_ordinal);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_package_members_definition ON selected_resolution_stage_package_members(definition_key,host_ordinal,namespace);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_package_members_lookup ON selected_resolution_stage_package_members(lookup_shared,host_ordinal);
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_go_package_imports(
 host_ordinal INTEGER NOT NULL,
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 definition_key INTEGER NOT NULL CHECK(definition_key>=0),
 source_site INTEGER NOT NULL CHECK(source_site BETWEEN 0 AND 4294967295),
 file_scope_key INTEGER NOT NULL CHECK(file_scope_key>=0),
 spelling_choice_key INTEGER NOT NULL CHECK(spelling_choice_key>=0),
 start_byte INTEGER NOT NULL CHECK(start_byte>=0),
 end_byte INTEGER NOT NULL CHECK(end_byte>=start_byte),
 kind TEXT NOT NULL CHECK(kind IN ('named','blank')),
 PRIMARY KEY(producer_id,definition_key),
 UNIQUE(producer_id,source_site)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_go_package_imports_host ON selected_resolution_stage_go_package_imports(host_ordinal,definition_key);
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_semantics(
 host_ordinal INTEGER NOT NULL,
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 sequence INTEGER NOT NULL CHECK(sequence>=0),
 semantic_key INTEGER CHECK(semantic_key IS NULL OR semantic_key>=0),
 semantic_shared INTEGER CHECK(semantic_shared IS NULL OR semantic_shared>0),
 node INTEGER NOT NULL CHECK(node>=0), source_site INTEGER NOT NULL CHECK(source_site>=0),
 role INTEGER NOT NULL, namespace INTEGER NOT NULL, site_kind INTEGER,
 start_byte INTEGER CHECK(start_byte IS NULL OR start_byte>=0),
 end_byte INTEGER CHECK(end_byte IS NULL OR end_byte>=start_byte), unqualified INTEGER,
 owner_kind INTEGER NOT NULL CHECK(owner_kind IN (0,1,2)), owner_key INTEGER CHECK(owner_key IS NULL OR owner_key>=0), owner_shared INTEGER CHECK(owner_shared IS NULL OR owner_shared>0),
 receiver_origin INTEGER,
 go_spelling_namespace INTEGER CHECK(go_spelling_namespace IS NULL OR (role=0 AND unqualified IS 1 AND go_spelling_namespace=namespace AND go_spelling_namespace IN (0,1,2,6))),
 go_definition_namespaces INTEGER CHECK(go_definition_namespaces IS NULL OR (role=1 AND go_definition_namespaces BETWEEN 1 AND 15)),
 go_package_qualifier INTEGER NOT NULL DEFAULT 0 CHECK(go_package_qualifier IN (0,1) AND (go_package_qualifier=0 OR (role=0 AND unqualified IS 1 AND namespace=6 AND go_spelling_namespace IS 6))),
 CHECK((semantic_key IS NULL)<>(semantic_shared IS NULL)),
 CHECK((owner_kind IN (0,1) AND owner_key IS NULL AND owner_shared IS NULL)
    OR (owner_kind=2 AND ((owner_key IS NULL)<>(owner_shared IS NULL)))),
 PRIMARY KEY(producer_id,sequence)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_semantics_key ON selected_resolution_stage_semantics(semantic_key,semantic_shared,host_ordinal,producer_id,sequence);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_semantics_node ON selected_resolution_stage_semantics(node,host_ordinal,producer_id,sequence);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_semantics_site ON selected_resolution_stage_semantics(host_ordinal,source_site,role,producer_id,sequence);
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_declarations(
 host_ordinal INTEGER NOT NULL,
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 semantic_key INTEGER CHECK(semantic_key IS NULL OR semantic_key>=0),
 semantic_shared INTEGER CHECK(semantic_shared IS NULL OR semantic_shared>0),
 identifier TEXT NOT NULL, kind TEXT NOT NULL,
 name_start_byte INTEGER NOT NULL,name_end_byte INTEGER NOT NULL,name_start_line INTEGER NOT NULL,name_end_line INTEGER NOT NULL,
 declaration_start_byte INTEGER NOT NULL,declaration_end_byte INTEGER NOT NULL,declaration_start_line INTEGER NOT NULL,declaration_end_line INTEGER NOT NULL,
 CHECK((semantic_key IS NULL)<>(semantic_shared IS NULL))
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS temp.selected_resolution_stage_declarations_identity ON selected_resolution_stage_declarations(producer_id,COALESCE(semantic_key,-1),COALESCE(semantic_shared,-1));
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_declarations_key ON selected_resolution_stage_declarations(host_ordinal,semantic_key,semantic_shared);
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_reference_contexts(
 host_ordinal INTEGER NOT NULL,
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 semantic_key INTEGER CHECK(semantic_key IS NULL OR semantic_key>=0),
 semantic_shared INTEGER CHECK(semantic_shared IS NULL OR semantic_shared>0),
 source_site INTEGER NOT NULL,host_occurrence INTEGER NOT NULL,module_context INTEGER NOT NULL,module_declaration INTEGER,
 cfg BLOB NOT NULL CHECK(json_valid(cfg,8)),
 owner_kind INTEGER NOT NULL CHECK(owner_kind IN (0,1,2)),owner_key INTEGER CHECK(owner_key IS NULL OR owner_key>=0),owner_shared INTEGER CHECK(owner_shared IS NULL OR owner_shared>0),
 CHECK((semantic_key IS NULL)<>(semantic_shared IS NULL)),
 CHECK((owner_kind IN (0,1) AND owner_key IS NULL AND owner_shared IS NULL)
    OR (owner_kind=2 AND ((owner_key IS NULL)<>(owner_shared IS NULL))))
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS temp.selected_resolution_stage_reference_context_identity ON selected_resolution_stage_reference_contexts(producer_id,COALESCE(semantic_key,-1),COALESCE(semantic_shared,-1));
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_reference_context_key ON selected_resolution_stage_reference_contexts(host_ordinal,semantic_key,semantic_shared);
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_gaps(
 host_ordinal INTEGER NOT NULL,
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 covers INTEGER NOT NULL,
 gap_key INTEGER NOT NULL CHECK(gap_key>=0),
 reason_key INTEGER NOT NULL CHECK(reason_key>=0),
 subject_key INTEGER CHECK(subject_key IS NULL OR subject_key>=0),subject_shared INTEGER CHECK(subject_shared IS NULL OR subject_shared>0),
 endpoint_node INTEGER CHECK(endpoint_node IS NULL OR endpoint_node>=0),
 lookup_key INTEGER CHECK(lookup_key IS NULL OR lookup_key>=0),lookup_shared INTEGER CHECK(lookup_shared IS NULL OR lookup_shared>0),
 source_site INTEGER NOT NULL,origin INTEGER NOT NULL,
  CHECK(subject_key IS NULL OR subject_shared IS NULL),CHECK(lookup_key IS NULL OR lookup_shared IS NULL)
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS temp.selected_resolution_stage_gap_tuple ON selected_resolution_stage_gaps(host_ordinal,covers,reason_key,COALESCE(subject_key,-1),COALESCE(subject_shared,-1),COALESCE(endpoint_node,-1),COALESCE(lookup_key,-1),COALESCE(lookup_shared,-1),source_site,origin);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_gap_producer ON selected_resolution_stage_gaps(producer_id);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_gap_subject ON selected_resolution_stage_gaps(subject_key,subject_shared,covers,host_ordinal);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_gap_endpoint ON selected_resolution_stage_gaps(covers,endpoint_node,lookup_key,lookup_shared,host_ordinal);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_gap_reason ON selected_resolution_stage_gaps(reason_key,host_ordinal);
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_closed_reasons(
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 semantic_key INTEGER CHECK(semantic_key IS NULL OR semantic_key>=0),semantic_shared INTEGER CHECK(semantic_shared IS NULL OR semantic_shared>0),
 CHECK((semantic_key IS NULL)<>(semantic_shared IS NULL))
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS temp.selected_resolution_stage_closed_reason_identity ON selected_resolution_stage_closed_reasons(producer_id,COALESCE(semantic_key,-1),COALESCE(semantic_shared,-1));
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_closed_reason_key ON selected_resolution_stage_closed_reasons(semantic_key,semantic_shared);
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_recipes(
 host_ordinal INTEGER NOT NULL,
 producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE,
 semantic_key INTEGER CHECK(semantic_key IS NULL OR semantic_key>=0),semantic_shared INTEGER CHECK(semantic_shared IS NULL OR semantic_shared>0),
 semantic_language INTEGER NOT NULL,namespace INTEGER NOT NULL,spelling TEXT NOT NULL,
 CHECK((semantic_key IS NULL)<>(semantic_shared IS NULL))
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS temp.selected_resolution_stage_recipe_identity ON selected_resolution_stage_recipes(producer_id,COALESCE(semantic_key,-1),COALESCE(semantic_shared,-1));
CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_recipe_key ON selected_resolution_stage_recipes(host_ordinal,semantic_key,semantic_shared);
"#);
        for family in TYPED_FAMILIES {
            let mut columns = family.semantics.iter().map(|name| semantic_columns(name)).collect::<Vec<_>>();
            if !family.columns.is_empty() { columns.push(family.columns.to_owned()); }
            columns.extend(family.semantics.iter().map(|name| format!("CHECK(({name}_key IS NULL)<>({name}_shared IS NULL))")));
            sql.push_str(&format!("CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_{}(host_ordinal INTEGER NOT NULL CHECK(host_ordinal>=0), producer_id INTEGER NOT NULL REFERENCES selected_resolution_stage_producers(producer_id) ON DELETE CASCADE, sequence INTEGER NOT NULL CHECK(sequence>=0), {}, PRIMARY KEY(producer_id,sequence)) WITHOUT ROWID, STRICT;\n", family.name, columns.join(",")));
            for (ordinal, keys) in family.unique.iter().enumerate() {
                let keys = keys.iter().map(|name| if family.semantics.contains(name) { semantic_index(name) } else { (*name).to_owned() }).collect::<Vec<_>>().join(",");
                sql.push_str(&format!("CREATE UNIQUE INDEX IF NOT EXISTS temp.selected_resolution_stage_{}_unique_{ordinal} ON selected_resolution_stage_{}(host_ordinal,{keys});\n",family.name,family.name));
            }
            for (ordinal, keys) in family.seeks.iter().enumerate() {
                let keys = keys.iter().map(|name| if family.semantics.contains(name) { format!("{name}_key,{name}_shared") } else { (*name).to_owned() }).collect::<Vec<_>>().join(",");
                sql.push_str(&format!("CREATE INDEX IF NOT EXISTS temp.selected_resolution_stage_{}_seek_{ordinal} ON selected_resolution_stage_{}({keys},host_ordinal,producer_id,sequence);\n",family.name,family.name));
            }
        }
        // Observation reference identity is independent of its identity node.
        sql.push_str("CREATE UNIQUE INDEX IF NOT EXISTS temp.selected_resolution_stage_observation_reference ON selected_resolution_stage_type_frontiers(COALESCE(identity_reference_key,-1),COALESCE(identity_reference_shared,-1),host_ordinal) WHERE identity_reference_node IS NOT NULL;\n");
        sql
    };
        #[cfg(test)]
        crate::analyzer::store::resolution_selection::note_selected_static_sql_capacity(9, sql.capacity());
        sql
    })
}
