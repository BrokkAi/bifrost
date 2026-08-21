use crate::analyzer::structural::{
    ALL_KINDS, ALL_OWNER_RELATIONS, ALL_SITE_CLASSES, DEFAULT_LIMIT, MAX_BINDING_NAME_LENGTH,
    MAX_CAPTURE_LENGTH, MAX_GLOB_LENGTH, MAX_KWARG_NAME_LENGTH, MAX_KWARGS, MAX_LANGUAGE_FILTERS,
    MAX_LIMIT, MAX_PATTERN_DEPTH, MAX_PATTERN_NODES, MAX_QUERY_BRANCHES, MAX_QUERY_STEPS,
    MAX_ROLE_LIST_ENTRIES, MAX_STRING_PREDICATE_LENGTH, MAX_WHERE_GLOBS, SCHEMA_VERSION,
};
use crate::mcp_common::{McpRenderOptions, run_stdio_server, tool_descriptor};
use brokk_bifrost_rql::schema::{
    ALL_CODE_QUERY_EXECUTION_MODES, ALL_QUERY_STEP_OPS, ALL_REFERENCE_KINDS, ALL_USAGE_KINDS,
    QueryField, QueryStepField, environment_filter_labels, flow_state_filter_labels,
    occurrence_filter_labels, reference_kind_label, rewrite_path_filter_labels,
    supported_query_schema_versions,
};
use serde_json::{Value, json};
use std::path::PathBuf;

pub const EXTENDED_TOOL_NAMES: &[&str] = &[
    "query_code",
    "list_policies",
    "run_policy",
    "explain_policy",
    "get_symbol_locations",
    "get_symbol_ancestors",
    "most_relevant_files",
];

/// The longest `explain_policy` finding identity: a policy finding id renders
/// as 32 lowercase hex bytes.
pub(crate) const EXPLAIN_POLICY_FINDING_ID_LENGTH: usize = 64;

pub(crate) const MAX_RUN_POLICY_PATH_BYTES: usize = 1_024;
pub(crate) const MAX_RUN_POLICY_SELECTOR_BYTES: usize = 256;
pub(crate) const MAX_RUN_POLICY_DIFF_BASE_BYTES: usize = 256;

pub fn run_extended_stdio_server(
    root: PathBuf,
    render_options: McpRenderOptions,
) -> Result<(), String> {
    let spec = crate::mcp_registry::resolve_server_spec("extended")?;
    run_stdio_server(Some(root), render_options, &spec, None)
}

fn query_step_input_variants() -> Vec<Value> {
    let (parameter_name_minimum, parameter_name_maximum) = QueryStepField::ParameterName
        .value_shape()
        .string_length_bounds()
        .expect("parameter-name shape has string bounds");
    let (capture_name_minimum, capture_name_maximum) = QueryStepField::Capture
        .value_shape()
        .string_length_bounds()
        .expect("capture-name shape has string bounds");
    let (protocol_ref_minimum, protocol_ref_maximum) = QueryStepField::ProtocolRef
        .value_shape()
        .string_length_bounds()
        .expect("protocol-ref shape has string bounds");
    let (plan_ref_minimum, plan_ref_maximum) = QueryStepField::PlanRef
        .value_shape()
        .string_length_bounds()
        .expect("plan-ref shape has string bounds");
    let (taint_ref_minimum, taint_ref_maximum) = QueryStepField::TaintRef
        .value_shape()
        .string_length_bounds()
        .expect("taint-ref shape has string bounds");
    let plain = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| {
            !op.allows_hierarchy_options()
                && !op.allows_reference_options()
                && !op.allows_call_options()
                && !op.allows_call_site_options()
                && !op.allows_receiver_options()
                && !op.allows_typestate_options()
                && !op.allows_value_flow_options()
                && !op.allows_taint_options()
                && !op.allows_witness_options()
                && !op.allows_occurrence_options()
                && !op.allows_binding_options()
                && !op.allows_candidate_options()
                && !op.allows_binding_of_options()
                && !op.allows_edge_options()
                && !op.allows_state_event_options()
                && !op.allows_flow_relation_options()
                && !op.allows_rewrite_path_options()
                && !op.allows_segment_options()
                && op.label() != "call_input"
        })
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let hierarchy = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_hierarchy_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let references = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_reference_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let calls = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_call_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let call_sites = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_call_site_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let receiver_steps = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_receiver_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let typestate_steps = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_typestate_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let value_flow_steps = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_value_flow_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let witness_steps = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_witness_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let taint_steps = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_taint_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let occurrence_steps = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_occurrence_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let binding_steps = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_binding_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let candidate_steps = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_candidate_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let binding_of_steps = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_binding_of_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let edge_steps = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_edge_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let state_event_steps = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_state_event_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let flow_relation_steps = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_flow_relation_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let rewrite_path_steps = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_rewrite_path_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let segment_steps = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| op.allows_segment_options())
        .map(|op| op.label())
        .collect::<Vec<_>>();
    let occurrence_classes = occurrence_filter_labels(QueryStepField::OccurrenceClasses);
    let occurrence_roles = occurrence_filter_labels(QueryStepField::OccurrenceRoles);
    let occurrence_namespaces = occurrence_filter_labels(QueryStepField::OccurrenceNamespaces);
    let reference_kinds = ALL_REFERENCE_KINDS
        .iter()
        .copied()
        .map(reference_kind_label)
        .collect::<Vec<_>>();
    vec![
        json!({
            "type": "object",
            "properties": { "op": { "type": "string", "enum": plain } },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": { "op": { "type": "string", "enum": hierarchy.clone() } },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": hierarchy.clone() },
                "depth": { "type": "integer", "minimum": 1 }
            },
            "required": ["op", "depth"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": hierarchy },
                "transitive": { "const": true }
            },
            "required": ["op", "transitive"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": references },
                "reference_kinds": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": true,
                    "items": { "type": "string", "enum": reference_kinds.clone() }
                },
                "proof": { "type": "string", "enum": ["proven", "unproven"] },
                "surface": { "type": "string", "enum": ["external_usages", "lsp_references"] }
            },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": calls },
                "depth": { "type": "integer", "minimum": 1 },
                "proof": { "type": "string", "enum": ["proven", "unproven"] }
            },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": call_sites },
                "proof": { "type": "string", "enum": ["proven", "unproven"] }
            },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "const": "call_input" },
                "receiver": { "const": true }
            },
            "required": ["op", "receiver"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "const": "call_input" },
                "parameter_index": { "type": "integer", "minimum": 0 }
            },
            "required": ["op", "parameter_index"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "const": "call_input" },
                "parameter_name": {
                    "type": "string",
                    "minLength": parameter_name_minimum,
                    "maxLength": parameter_name_maximum
                }
            },
            "required": ["op", "parameter_name"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": receiver_steps },
                "capture": {
                    "type": "string",
                    "minLength": capture_name_minimum,
                    "maxLength": capture_name_maximum
                }
            },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": typestate_steps },
                "protocol_ref": {
                    "type": "string",
                    "minLength": protocol_ref_minimum,
                    "maxLength": protocol_ref_maximum,
                    "description": QueryStepField::ProtocolRef.description()
                }
            },
            "required": ["op", "protocol_ref"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": value_flow_steps },
                "plan_ref": {
                    "type": "string",
                    "minLength": plan_ref_minimum,
                    "maxLength": plan_ref_maximum,
                    "description": QueryStepField::PlanRef.description()
                }
            },
            "required": ["op", "plan_ref"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": taint_steps },
                "taint_ref": {
                    "type": "string",
                    "minLength": taint_ref_minimum,
                    "maxLength": taint_ref_maximum,
                    "description": QueryStepField::TaintRef.description()
                }
            },
            "required": ["op", "taint_ref"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": witness_steps },
                "max_steps": {
                    "type": "integer",
                    "minimum": 0,
                    "description": QueryStepField::MaxSteps.description()
                },
                "max_bytes": {
                    "type": "integer",
                    "minimum": 0,
                    "description": QueryStepField::MaxBytes.description()
                }
            },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": occurrence_steps },
                "class": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": true,
                    "items": { "type": "string", "enum": occurrence_classes.clone() }
                },
                "role": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": true,
                    "items": { "type": "string", "enum": occurrence_roles.clone() }
                },
                "namespace": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": true,
                    "items": { "type": "string", "enum": occurrence_namespaces.clone() }
                }
            },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": binding_steps },
                "kind": binding_kind_array(),
                "name": binding_name_array(),
                "hoisting": binding_hoisting_array()
            },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": candidate_steps },
                "tier": candidate_tier_array(),
                "outcome": candidate_outcome_array(),
                "boundary": candidate_boundary_array()
            },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": binding_of_steps },
                "include_shadowed": {
                    "type": "boolean",
                    "const": true,
                    "description": QueryStepField::IncludeShadowed.description()
                }
            },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": edge_steps },
                "reference_kinds": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": true,
                    "items": { "type": "string", "enum": reference_kinds },
                    "description": QueryStepField::ReferenceKinds.description()
                },
                "proof": {
                    "type": "string",
                    "enum": ["proven", "unproven"],
                    "description": QueryStepField::Proof.description()
                },
                "surface": {
                    "type": "string",
                    "enum": ["external_usages", "lsp_references"],
                    // Unlike references_of, the edge surface has no default:
                    // the canonical edge answer includes editor-only rows, so
                    // omitting the field must not silently narrow the set.
                    "description": QueryStepField::Surface.description()
                },
                "usage": edge_usage_kind_array(),
                "relation": edge_relation_array(),
                "site_class": edge_site_class_array()
            },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": state_event_steps },
                "event_class": flow_state_label_array(QueryStepField::StateEventClasses),
                "subject": flow_state_label_array(QueryStepField::StateEventSubjects)
            },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": flow_relation_steps },
                "flow_relation": flow_state_label_array(QueryStepField::FlowRelations),
                "certainty": flow_state_label_array(QueryStepField::FlowCertainties)
            },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": rewrite_path_steps },
                "domain": rewrite_path_label_array(QueryStepField::RewriteDomains),
                "rewrite_outcome": rewrite_path_label_array(QueryStepField::RewriteOutcomes)
            },
            "required": ["op"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": segment_steps },
                "resolved": {
                    "type": "boolean",
                    "const": true,
                    "description": QueryStepField::Resolved.description()
                }
            },
            "required": ["op"],
            "additionalProperties": false
        }),
    ]
}

fn constrained_label_array(labels: Vec<&'static str>, description: &str) -> Value {
    json!({
        "type": "array",
        "minItems": 1,
        "uniqueItems": true,
        "items": { "type": "string", "enum": labels },
        "description": description
    })
}

fn binding_kind_array() -> Value {
    constrained_label_array(
        environment_filter_labels(QueryStepField::BindingKinds),
        QueryStepField::BindingKinds.description(),
    )
}

fn binding_name_array() -> Value {
    json!({
        "type": "array",
        "minItems": 1,
        "uniqueItems": true,
        "items": { "type": "string", "minLength": 1, "maxLength": MAX_BINDING_NAME_LENGTH },
        "description": QueryStepField::BindingNames.description()
    })
}

fn binding_hoisting_array() -> Value {
    constrained_label_array(
        environment_filter_labels(QueryStepField::BindingHoisting),
        QueryStepField::BindingHoisting.description(),
    )
}

fn candidate_tier_array() -> Value {
    constrained_label_array(
        environment_filter_labels(QueryStepField::CandidateTiers),
        QueryStepField::CandidateTiers.description(),
    )
}

fn candidate_outcome_array() -> Value {
    constrained_label_array(
        environment_filter_labels(QueryStepField::CandidateOutcomes),
        QueryStepField::CandidateOutcomes.description(),
    )
}

fn candidate_boundary_array() -> Value {
    constrained_label_array(
        environment_filter_labels(QueryStepField::CandidateBoundaries),
        QueryStepField::CandidateBoundaries.description(),
    )
}

/// One flow-state constrained-value axis, read from the schema registry so the
/// MCP surface cannot drift from the parser's vocabulary (#1480).
fn flow_state_label_array(field: QueryStepField) -> Value {
    constrained_label_array(flow_state_filter_labels(field), field.description())
}

/// One bounded-rewrite constrained-value axis, read from the schema registry
/// so the MCP surface cannot drift from the parser's vocabulary (#1480).
fn rewrite_path_label_array(field: QueryStepField) -> Value {
    constrained_label_array(rewrite_path_filter_labels(field), field.description())
}

fn edge_usage_kind_array() -> Value {
    constrained_label_array(
        ALL_USAGE_KINDS
            .iter()
            .map(|kind| kind.wire_label())
            .collect(),
        QueryStepField::EdgeUsageKinds.description(),
    )
}

fn edge_relation_array() -> Value {
    constrained_label_array(
        ALL_OWNER_RELATIONS
            .iter()
            .map(|relation| relation.label())
            .collect(),
        QueryStepField::EdgeRelations.description(),
    )
}

fn edge_site_class_array() -> Value {
    constrained_label_array(
        ALL_SITE_CLASSES.iter().map(|class| class.label()).collect(),
        QueryStepField::EdgeSiteClasses.description(),
    )
}

/// The `scopes` seed's filter object.
fn scope_seed_filter_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "kind": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": true,
                "items": { "type": "string" },
                "description": "Normalized kinds a scope's anchoring fact may carry. The synthesized whole-file scope has no anchoring fact, so a non-empty kind filter never selects it."
            }
        },
        "additionalProperties": false,
        "description": "Seed lexical scope rows straight from workspace facts. Every file contributes a synthesized whole-file scope plus one row per scope-forming node, parent-linked so scope-ancestors is a chain walk."
    })
}

/// The `paths` seed's filter object.
fn path_seed_filter_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "min_segments": {
                "type": "integer",
                "minimum": 1,
                "description": "Keep only paths with at least this many segments. A path always has at least two; one segment is a bare identifier, not a path."
            }
        },
        "additionalProperties": false,
        "description": "Seed qualified-path rows straight from workspace facts: one row per linear chain (a.b.C, a::b::C), anchored at its terminal segment. segments_of returns the ordered decoded segments; with resolved: true each segment carries its own prefix resolution."
    })
}

/// The `bindings` seed's filter object, shared with the `bindings_in` step.
fn binding_seed_filter_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "kind": binding_kind_array(),
            "name": binding_name_array(),
            "hoisting": binding_hoisting_array()
        },
        "additionalProperties": false,
        "description": "Seed lexical binding rows straight from workspace facts. Each row carries the interval over which the binding is in effect, its declaring scope, and its hoisting class; filters are conjunctive across axes and disjunctive within one."
    })
}

/// The `occurrences` seed's filter object, shared with the two occurrence
/// steps so an author spells the same filter the same way everywhere.
fn occurrence_filter_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "class": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": true,
                "items": { "type": "string", "enum": occurrence_filter_labels(QueryStepField::OccurrenceClasses) }
            },
            "role": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": true,
                "items": { "type": "string", "enum": occurrence_filter_labels(QueryStepField::OccurrenceRoles) }
            },
            "namespace": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": true,
                "items": { "type": "string", "enum": occurrence_filter_labels(QueryStepField::OccurrenceNamespaces) }
            }
        },
        "additionalProperties": false,
        "description": "Seed classified identifier occurrences straight from workspace facts. Filters are conjunctive across class/role/namespace and disjunctive within one axis; an empty object selects every occurrence the adapters classify."
    })
}

fn query_plan_properties(
    pattern_schema_description: &str,
    query_step_variants: &[Value],
) -> serde_json::Map<String, Value> {
    json!({
        "match": {
            "type": "object",
            "description": pattern_schema_description
        },
        "inside": {
            "type": "object",
            "description": "Optional containment constraint: the match must be lexically inside a node matching this pattern (same shape as match)."
        },
        "inside_decl": {
            "type": "object",
            "description": "Optional declaration-bounded containment: the match must be inside a node matching this pattern without crossing a callable declaration (same shape as match)."
        },
        "not_inside": {
            "type": "object",
            "description": "Optional negative containment: the match must NOT be inside a node matching this pattern."
        },
        "where": {
            "type": "array",
            "maxItems": MAX_WHERE_GLOBS,
            "items": { "type": "string", "maxLength": MAX_GLOB_LENGTH },
            "description": "Optional project-relative path globs limiting which files are searched. Absolute paths/globs inside the active workspace are normalized before execution."
        },
        "languages": {
            "type": "array",
            "maxItems": MAX_LANGUAGE_FILTERS,
            "items": { "type": "string" },
            "description": "Optional language filter (e.g. \"python\"). Languages without structural support are reported in diagnostics."
        },
        "union": {
            "type": "array",
            "minItems": 2,
            "maxItems": MAX_QUERY_BRANCHES,
            "items": { "$ref": "#/$defs/queryPlan" },
            "description": "Compatible typed query branches combined by endpoint union."
        },
        "intersect": {
            "type": "array",
            "minItems": 2,
            "maxItems": MAX_QUERY_BRANCHES,
            "items": { "$ref": "#/$defs/queryPlan" },
            "description": "Compatible typed query branches combined by endpoint intersection."
        },
        "except": {
            "type": "array",
            "minItems": 2,
            "maxItems": MAX_QUERY_BRANCHES,
            "items": { "$ref": "#/$defs/queryPlan" },
            "description": "First compatible typed branch minus every later branch."
        },
        "occurrences": occurrence_filter_schema(),
        "scopes": scope_seed_filter_schema(),
        "bindings": binding_seed_filter_schema(),
        "paths": path_seed_filter_schema(),
        "steps": {
            "type": "array",
            "maxItems": MAX_QUERY_STEPS,
            "items": { "oneOf": query_step_variants },
            "description": "Ordered typed transformations. Hierarchy/member/owner steps consume and produce exact indexed declarations; import steps consume files; schema-v3 CFG steps consume and produce source-backed procedures, program points, and control edges; schema-v4 typestate consumes a host registration and witness projects retained evidence."
        }
    })
    .as_object()
    .expect("query plan properties are an object")
    .clone()
}

fn query_plan_source_variants() -> Vec<Value> {
    let seed_scope_fields = ["inside", "inside_decl", "not_inside", "where", "languages"];
    let sources = [
        "match",
        "occurrences",
        "scopes",
        "bindings",
        "paths",
        "union",
        "intersect",
        "except",
    ];
    sources
        .into_iter()
        .map(|source| {
            let mut excluded = sources
                .into_iter()
                .filter(|candidate| *candidate != source)
                .collect::<Vec<_>>();
            // `where` and `languages` scope an occurrence seed exactly as they
            // scope a structural one; only the pattern-containment fields are
            // structural-seed-only.
            match source {
                "match" => {}
                "occurrences" | "scopes" | "bindings" | "paths" => {
                    excluded.extend(["inside", "inside_decl", "not_inside"]);
                }
                _ => excluded.extend(seed_scope_fields),
            }
            json!({
                "required": [source],
                "not": {
                        "anyOf": excluded
                            .into_iter()
                            .map(|field| json!({ "required": [field] }))
                            .collect::<Vec<_>>()
                }
            })
        })
        .collect()
}

fn query_plan_schema(pattern_schema_description: &str, query_step_variants: &[Value]) -> Value {
    json!({
        "type": "object",
        "properties": query_plan_properties(pattern_schema_description, query_step_variants),
        "oneOf": query_plan_source_variants(),
        "additionalProperties": false
    })
}

pub(crate) fn extended_tool_descriptors() -> Vec<Value> {
    let max_policy_files = crate::policy::PolicyBatchBudget::default().max_policies();
    let kind_vocabulary = ALL_KINDS
        .iter()
        .map(|kind| kind.label())
        .collect::<Vec<_>>()
        .join(", ");
    let role_vocabulary = crate::analyzer::structural::kinds::ALL_ROLES
        .iter()
        .map(|role| role.label())
        .collect::<Vec<_>>()
        .join(", ");
    let pattern_schema_description = format!(
        "A structural pattern object. Fields are optional: kind (one normalized kind or an array forming a subtype-aware union; vocabulary: {kind_vocabulary}), not_kind (kind or array to exclude), name (string for exact match or {{\"regex\": ...}}, max {MAX_STRING_PREDICATE_LENGTH} bytes), text ({{\"regex\": ...}}, max {MAX_STRING_PREDICATE_LENGTH} bytes), capture (max {MAX_CAPTURE_LENGTH} bytes), has / not_has (descendant patterns), and role sub-patterns valid for the declared kind: {role_vocabulary}. Query budget: max {MAX_PATTERN_NODES} pattern nodes, max depth {MAX_PATTERN_DEPTH}, max {MAX_ROLE_LIST_ENTRIES} role-list entries per list, max {MAX_KWARGS} kwargs, max keyword length {MAX_KWARG_NAME_LENGTH} bytes."
    );
    let step_vocabulary = ALL_QUERY_STEP_OPS
        .iter()
        .map(|op| op.label())
        .collect::<Vec<_>>()
        .join(", ");
    let query_code_description = format!(
        "Query normalized code structure with CodeQuery or RQL. Match declarations and syntax, compose compatible typed branches with union, intersect, or except, and apply typed semantic steps. Schema version 1 supports {step_vocabulary}. Set branches must produce the same terminal domain. A common steps suffix can continue from that domain. Use execution_mode explain to plan without workspace execution. Use profile for ordinary results with operator measurements. Procedure-local CFG steps return procedures, program points, and control edges. Typestate, value-flow, and taint steps use host-registered references and return retained production evidence. The taint step projects existing findings; it does not compile selectors or run propagation. It does not imply policy classification. Example: {{\"schema_version\":1,\"match\":{{\"kind\":\"method\",\"name\":\"run\"}}}}. Guide: https://bifrost.brokk.ai/code-querying/"
    );
    let query_step_variants = query_step_input_variants();
    let query_plan_schema = query_plan_schema(&pattern_schema_description, &query_step_variants);
    let mut query_code_properties =
        query_plan_properties(&pattern_schema_description, &query_step_variants);
    let execution_modes = ALL_CODE_QUERY_EXECUTION_MODES
        .iter()
        .map(|mode| mode.label())
        .collect::<Vec<_>>();
    let schema_versions = supported_query_schema_versions();
    query_code_properties.extend(
        json!({
            "limit": {
                "type": "integer",
                "default": DEFAULT_LIMIT,
                "minimum": 1,
                "maximum": MAX_LIMIT,
                "description": "Maximum number of terminal results to return after pipeline deduplication."
            },
            "result_detail": {
                "type": "string",
                "enum": ["compact", "full"],
                "default": "compact",
                "description": "Use compact for context-efficient snippets and line ranges. Use full when follow-up tools need deterministic match IDs, line/column ranges, decorator ranges, and capture ranges."
            },
            "execution_mode": {
                "type": "string",
                "enum": execution_modes,
                "default": "results",
                "description": QueryField::ExecutionMode.description()
            },
            "schema_version": {
                "type": "integer",
                "default": SCHEMA_VERSION,
                "enum": schema_versions,
                "description": "Optional query schema version. Version 1 is the only supported version; omit it or pin it explicitly."
            },
            "query_file": {
                "type": "string",
                "description": "Workspace-relative query file. Use .rql for an RQL S-expression or .json for a complete canonical CodeQuery. Exclusive with inline query fields."
            }
        })
        .as_object()
        .expect("root query properties are an object")
        .clone(),
    );
    let inline_query_variants = query_plan_source_variants()
        .into_iter()
        .map(|variant| {
            json!({
                "allOf": [
                    variant,
                    { "not": { "required": ["query_file"] } }
                ]
            })
        })
        .collect::<Vec<_>>();
    let query_file_exclusions = query_code_properties
        .keys()
        .filter(|field| field.as_str() != "query_file")
        .map(|field| json!({ "required": [field] }))
        .collect::<Vec<_>>();
    vec![
        tool_descriptor(
            "query_code",
            &query_code_description,
            json!({
                "type": "object",
                "properties": query_code_properties,
                "oneOf": [
                    {
                        "oneOf": inline_query_variants
                    },
                    {
                        "required": ["query_file"],
                        "not": {
                            "anyOf": query_file_exclusions
                        }
                    }
                ],
                "$defs": { "queryPlan": query_plan_schema }
            }),
        ),
        tool_descriptor(
            "list_policies",
            "List the deterministic built-in policy-pack manifest, including stable policy ids, categories, supported languages, capabilities, and semantic hashes. Does not construct or query a workspace analyzer.",
            json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        ),
        tool_descriptor(
            "run_policy",
            // The report schema version is read from the policy crate rather
            // than written out, so a schema bump cannot leave this text stale
            // the way "schema-2" did through versions 3 and 4.
            &format!(
                "Evaluate built-in policy selections and/or explicit workspace-relative .rqlp \
                 files against the active immutable workspace snapshot. Returns the canonical \
                 schema-{} report and computed policy status.",
                brokk_bifrost_policy::PolicyReportDocument::SCHEMA_VERSION,
            ),
            json!({
                "type": "object",
                "properties": {
                    "policy_files": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_RUN_POLICY_PATH_BYTES,
                            "description": "One workspace-relative .rqlp policy path."
                        },
                        "minItems": 1,
                        "maxItems": max_policy_files,
                        "uniqueItems": true,
                        "description": "Optional explicit workspace policy roots to evaluate together."
                    },
                    "policy_packs": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_RUN_POLICY_SELECTOR_BYTES
                        },
                        "minItems": 1,
                        "maxItems": max_policy_files,
                        "uniqueItems": true,
                        "description": "Optional built-in pack ids."
                    },
                    "policy_categories": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_RUN_POLICY_SELECTOR_BYTES
                        },
                        "minItems": 1,
                        "maxItems": max_policy_files,
                        "uniqueItems": true,
                        "description": "Optional built-in policy categories."
                    },
                    "policy_ids": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_RUN_POLICY_SELECTOR_BYTES
                        },
                        "minItems": 1,
                        "maxItems": max_policy_files,
                        "uniqueItems": true,
                        "description": "Optional stable built-in policy ids."
                    },
                    "suppression_file": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": crate::policy::MAX_POLICY_SUPPRESSION_PATH_BYTES,
                        "description": "Optional workspace-relative suppression JSON path. Defaults to .bifrost/suppressions.json."
                    },
                    "scope_file": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": crate::policy::MAX_POLICY_SCOPE_PATH_BYTES,
                        "description": "Optional workspace-relative directory-scope JSON path. Defaults to .bifrost/policy-scope.json."
                    },
                    "baseline_file": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": crate::policy::MAX_POLICY_BASELINE_PATH_BYTES,
                        "description": "Optional workspace-relative bulk-acceptance baseline JSON path. Defaults to .bifrost/baseline.json."
                    },
                    "evaluation_date": {
                        "type": "string",
                        "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
                        "description": "Explicit UTC calendar date used for suppression expiration."
                    },
                    "fail_on": {
                        "type": "string",
                        "enum": ["never", "finding", "note", "warning", "error"],
                        "default": "warning",
                        "description": "Finding threshold used to compute the returned policy status."
                    },
                    "diff_base": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_RUN_POLICY_DIFF_BASE_BYTES,
                        "description": "Optional git revision to diff against: the same policies also evaluate that commit's content, each finding is classified new or persisting, and only new findings gate. Any revision git rev-parse accepts."
                    }
                },
                "required": ["evaluation_date"],
                "anyOf": [
                    { "required": ["policy_files"] },
                    { "required": ["policy_packs"] },
                    { "required": ["policy_categories"] },
                    { "required": ["policy_ids"] }
                ],
                "additionalProperties": false
            }),
        ),
        tool_descriptor(
            "explain_policy",
            // The format tag is read from the policy crate so a schema bump
            // cannot leave this text stale.
            &format!(
                "Explain one policy's verdict about one exact subject against the active \
                 immutable workspace snapshot. Pass `finding_id` to ask why a retained finding \
                 exists, or `candidate` to ask why one explicit source position produced none. \
                 Returns a bounded, deterministic {} document: a node tree whose every node \
                 carries an outcome of satisfied, failed, or unknown, where unknown means the \
                 analyzer could not decide and is never evidence of absence. This is a query \
                 about a policy, not a gate: it returns no status and no exit code. The \
                 selection must resolve to exactly one policy. Adapters exist for match and \
                 assertion policies; taint, flow, and typestate policies report an explicit \
                 adapter-unavailable condition. Candidates are not scanned for: supply the \
                 position you want explained.",
                brokk_bifrost_policy::POLICY_EXPLANATION_FORMAT,
            ),
            json!({
                "type": "object",
                "properties": {
                    "policy_files": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_RUN_POLICY_PATH_BYTES,
                            "description": "One workspace-relative .rqlp policy path."
                        },
                        "minItems": 1,
                        "maxItems": 1,
                        "uniqueItems": true,
                        "description": "The workspace policy file to explain."
                    },
                    "policy_packs": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_RUN_POLICY_SELECTOR_BYTES
                        },
                        "minItems": 1,
                        "maxItems": 1,
                        "uniqueItems": true,
                        "description": "A built-in pack id that selects exactly one policy."
                    },
                    "policy_categories": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_RUN_POLICY_SELECTOR_BYTES
                        },
                        "minItems": 1,
                        "maxItems": 1,
                        "uniqueItems": true,
                        "description": "A built-in policy category that selects exactly one policy."
                    },
                    "policy_ids": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_RUN_POLICY_SELECTOR_BYTES
                        },
                        "minItems": 1,
                        "maxItems": 1,
                        "uniqueItems": true,
                        "description": "One stable built-in policy id."
                    },
                    "finding_id": {
                        "type": "string",
                        "minLength": EXPLAIN_POLICY_FINDING_ID_LENGTH,
                        "maxLength": EXPLAIN_POLICY_FINDING_ID_LENGTH,
                        "pattern": "^[0-9a-f]{64}$",
                        "description": "Ask why: the stable identity of a finding the policy's own run retains, as run_policy reports it."
                    },
                    "candidate": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": MAX_RUN_POLICY_PATH_BYTES,
                                "description": "Workspace-relative path of the candidate position."
                            },
                            "byte_start": {
                                "type": "integer",
                                "minimum": 0,
                                "description": "Byte offset of the candidate position."
                            },
                            "byte_end": {
                                "type": "integer",
                                "minimum": 0,
                                "description": "Exclusive end byte offset. Omit for a point candidate at byte_start."
                            }
                        },
                        "required": ["path", "byte_start"],
                        "additionalProperties": false,
                        "description": "Ask why-not: one explicit source position the policy did not report."
                    }
                },
                "oneOf": [
                    { "required": ["finding_id"], "not": { "required": ["candidate"] } },
                    { "required": ["candidate"], "not": { "required": ["finding_id"] } }
                ],
                "anyOf": [
                    { "required": ["policy_files"] },
                    { "required": ["policy_packs"] },
                    { "required": ["policy_categories"] },
                    { "required": ["policy_ids"] }
                ],
                "additionalProperties": false
            }),
        ),
        tool_descriptor(
            "get_symbol_locations",
            "Get project-relative file paths and line ranges for known symbols after search_symbols; use before opening exact definitions.",
            crate::mcp_common::symbol_names_schema(),
        ),
        tool_descriptor(
            "get_symbol_ancestors",
            "Get nearest-parent-first ancestor class symbols for known classes after search_symbols; use when class inheritance context matters.",
            crate::mcp_common::symbol_names_schema(),
        ),
        tool_descriptor(
            "most_relevant_files",
            "Given seed source files, rank related code by imports and git history; use after finding one relevant file to expand context. Every returned file carries a `test` classification (test, test_support, production, ambiguous); filter client-side when you want non-test files (usually by dropping test and test_support, since a project without a src/main convention never reports production) and raise `limit` to cover what you will drop.",
            json!({
                "type": "object",
                "properties": {
                    "seed_file_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Project-relative seed files used to rank related files, or absolute paths inside the active workspace."
                    },
                    "seed_weights": {
                        "type": "array",
                        "items": { "type": "number", "exclusiveMinimum": 0.0 },
                        "description": "Optional raw per-seed weights aligned by index with seed_file_paths. When omitted, every seed uses weight 1.0."
                    },
                    "recency_half_life": {
                        "type": ["number", "null"],
                        "default": 250.0,
                        "exclusiveMinimum": 0.0,
                        "description": "Optional git recency half-life in commits. Omit for the default 250-commit exponential decay, or pass null for uniform weighting."
                    },
                    "ranking_mode": {
                        "type": "string",
                        "enum": ["cascade", "history_imports", "usage_graph", "usage_graph_exact"],
                        "default": "cascade",
                        "description": "Ranking source. cascade is the default: priority tiers over test/source mirrors, shared basenames, git co-edit, directory membership and import adjacency, and it still ranks in a repository with no usable history. history_imports is the git-first/import-fill ranking; usage_graph runs PageRank on the fast structured file graph; usage_graph_exact ranks the exact symbol-level caller-to-callee graph. Both usage modes use the history/import ranking to fill remaining slots. If graph construction is cancelled or exceeds the interactive budget, the response is marked incomplete and returns deterministic history/import ranking instead."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 20,
                        "minimum": 0,
                        "description": "Maximum number of related files to return."
                    }
                },
                "required": ["seed_file_paths"]
            }),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_code_schema_exposes_typed_pipeline_steps() {
        let query_code = extended_tool_descriptors()
            .into_iter()
            .find(|descriptor| descriptor["name"] == "query_code")
            .expect("query_code descriptor");
        let steps = &query_code["inputSchema"]["properties"]["steps"];
        assert_eq!(steps["maxItems"], MAX_QUERY_STEPS);
        assert_eq!(
            steps["items"]["oneOf"][0]["properties"]["op"]["enum"],
            json!([
                "enclosing_decl",
                "procedure_of",
                "cfg_entry",
                "cfg_exits",
                "cfg_successor_edges",
                "cfg_predecessor_edges",
                "cfg_edge_source",
                "cfg_edge_target",
                "file_of",
                "imports_of",
                "importers_of",
                "members",
                "owner",
                "receiver_outcome",
                "receiver_evidence",
                "call_shape",
                "call_argument_groups",
                "call_arguments",
                "call_effects",
                "procedure_effects",
                "call_bindings",
                "callable_signature",
                "signature_parameters",
                "callable_applicability",
                "overload_selection",
                "member_selection",
                "dispatch_outcome",
                "dispatch_targets",
                "member_family",
                "family_edges",
                "occurrence_target",
                "scope_of",
                "scope_ancestors",
                "binding_occurrence",
                "candidate_hierarchy",
                "candidate_target",
                "edge_target",
                "flow_source",
                "flow_target",
                "segment_target",
                "generates",
                "generated_by",
                "declaration_state_of",
                "implementation_of",
                "stubs_of",
                "export_target"
            ])
        );
        assert_eq!(
            steps["items"]["oneOf"][2]["properties"]["depth"]["minimum"],
            1
        );
        let receiver_variant = steps["items"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"]["op"]["enum"]
                    == json!(["receiver_targets", "points_to", "member_targets"])
            })
            .expect("receiver traversal schema");
        assert_eq!(receiver_variant["properties"]["capture"]["minLength"], 1);
        let typestate_variant = steps["items"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"]["op"]["enum"]
                    .as_array()
                    .is_some_and(|ops| ops.iter().any(|op| op == "typestate"))
            })
            .expect("typestate traversal schema");
        assert_eq!(typestate_variant["required"], json!(["op", "protocol_ref"]));
        let value_flow_variant = steps["items"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"]["op"]["enum"]
                    .as_array()
                    .is_some_and(|ops| ops.iter().any(|op| op == "value_flow"))
            })
            .expect("value-flow traversal completion schema");
        assert_eq!(value_flow_variant["required"], json!(["op", "plan_ref"]));
        assert_eq!(value_flow_variant["properties"]["plan_ref"]["minLength"], 3);
        let taint_variant = steps["items"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"]["op"]["enum"]
                    .as_array()
                    .is_some_and(|ops| ops.iter().any(|op| op == "taint"))
            })
            .expect("taint traversal completion schema");
        assert_eq!(taint_variant["required"], json!(["op", "taint_ref"]));
        assert_eq!(taint_variant["properties"]["taint_ref"]["minLength"], 3);
        let witness_variant = steps["items"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"]["op"]["enum"]
                    .as_array()
                    .is_some_and(|ops| ops.iter().any(|op| op == "witness"))
            })
            .expect("witness traversal schema");
        assert_eq!(witness_variant["properties"]["max_steps"]["minimum"], 0);
        assert_eq!(witness_variant["properties"]["max_bytes"]["minimum"], 0);
        assert_eq!(
            receiver_variant["properties"]["capture"]["maxLength"],
            MAX_CAPTURE_LENGTH
        );
        assert_eq!(receiver_variant["required"], json!(["op"]));
        let advertised = steps["items"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|variant| {
                variant["properties"]["op"]["enum"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .chain(variant["properties"]["op"]["const"].as_str())
            })
            .collect::<std::collections::BTreeSet<_>>();
        let registered = ALL_QUERY_STEP_OPS
            .iter()
            .map(|op| op.label())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(advertised, registered);
        let occurrence_variant = steps["items"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"]["op"]["enum"]
                    .as_array()
                    .is_some_and(|ops| ops.iter().any(|op| op == "occurrences_in"))
            })
            .expect("occurrence traversal schema");
        assert_eq!(occurrence_variant["required"], json!(["op"]));
        assert!(
            occurrence_variant["properties"]["role"]["items"]["enum"]
                .as_array()
                .is_some_and(|roles| roles.iter().any(|role| role == "binder")),
            "occurrence steps advertise the role vocabulary"
        );
        let edge_variant = steps["items"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"]["op"]["enum"]
                    .as_array()
                    .is_some_and(|ops| ops.iter().any(|op| op == "edges_of"))
            })
            .expect("reference-edge traversal schema");
        assert_eq!(
            edge_variant["properties"]["op"]["enum"],
            json!(["edges_of", "edges_from"])
        );
        let state_event_variant = steps["items"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"]["op"]["enum"]
                    .as_array()
                    .is_some_and(|ops| ops.iter().any(|op| op == "state_events_of"))
            })
            .expect("state-event traversal schema");
        assert_eq!(
            state_event_variant["properties"]["event_class"]["items"]["enum"],
            json!(["establish", "kill", "read"])
        );
        assert_eq!(
            state_event_variant["properties"]["subject"]["items"]["enum"],
            json!(["binding", "property"])
        );
        assert_eq!(state_event_variant["required"], json!(["op"]));

        let flow_relation_variant = steps["items"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"]["op"]["enum"]
                    .as_array()
                    .is_some_and(|ops| ops.iter().any(|op| op == "flow_relations_of"))
            })
            .expect("flow-relation traversal schema");
        assert_eq!(
            flow_relation_variant["properties"]["flow_relation"]["items"]["enum"],
            json!(["reaching", "dominates", "same_evaluation"])
        );
        assert_eq!(
            flow_relation_variant["properties"]["certainty"]["items"]["enum"],
            json!(["exact", "may"])
        );
        // The projections take no options, so they ride in the plain variant
        // exactly like `edge_target` does.
        assert!(
            steps["items"]["oneOf"][0]["properties"]["op"]["enum"]
                .as_array()
                .is_some_and(|ops| ops.iter().any(|op| op == "flow_source")
                    && ops.iter().any(|op| op == "flow_target")),
            "the flow projections must be advertised as option-free steps"
        );

        let rewrite_path_variant = steps["items"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| {
                variant["properties"]["op"]["enum"]
                    .as_array()
                    .is_some_and(|ops| ops.iter().any(|op| op == "rewrite_paths_of"))
            })
            .expect("rewrite-path traversal schema");
        assert_eq!(
            rewrite_path_variant["properties"]["domain"]["items"]["enum"],
            json!(["rust_import_alias"])
        );
        assert_eq!(
            rewrite_path_variant["properties"]["rewrite_outcome"]["items"]["enum"],
            json!(["converged", "cycle", "exceeded_budget"])
        );
        assert_eq!(rewrite_path_variant["required"], json!(["op"]));

        // The edge filter's `surface` is optional with no default, because the
        // canonical edge answer includes editor-only rows.
        assert_eq!(edge_variant["required"], json!(["op"]));
        assert!(
            edge_variant["properties"]["surface"]
                .get("default")
                .is_none(),
            "the edge surface axis must not advertise a default"
        );
        assert_eq!(
            edge_variant["properties"]["site_class"]["items"]["enum"],
            json!(["use_site", "declaration_site"])
        );
        assert_eq!(
            query_code["inputSchema"]["properties"]["schema_version"]["enum"],
            json!([1])
        );
        assert_eq!(
            query_code["inputSchema"]["properties"]["execution_mode"]["enum"],
            json!(["results", "explain", "profile"])
        );
        assert_eq!(
            query_code["inputSchema"]["properties"]["execution_mode"]["default"],
            "results"
        );
        for op in ["union", "intersect", "except"] {
            let composition = &query_code["inputSchema"]["properties"][op];
            assert_eq!(composition["minItems"], 2);
            assert_eq!(composition["maxItems"], MAX_QUERY_BRANCHES);
            assert_eq!(composition["items"]["$ref"], "#/$defs/queryPlan");
        }
        assert_eq!(
            query_code["inputSchema"]["$defs"]["queryPlan"]["additionalProperties"],
            false
        );
        let nested_plan = &query_code["inputSchema"]["$defs"]["queryPlan"];
        assert!(
            nested_plan["properties"].get("execution_mode").is_none(),
            "execution mode is a root-only query control"
        );
        for field in [
            "match",
            "inside",
            "inside_decl",
            "not_inside",
            "occurrences",
            "where",
            "languages",
            "union",
            "intersect",
            "except",
            "steps",
        ] {
            assert_eq!(
                query_code["inputSchema"]["properties"][field], nested_plan["properties"][field],
                "root and nested plan schemas drifted for {field}"
            );
        }
        for op in ["union", "intersect", "except"] {
            let variant = nested_plan["oneOf"]
                .as_array()
                .unwrap()
                .iter()
                .find(|variant| variant["required"] == json!([op]))
                .expect("set source variant");
            let excluded = variant["not"]["anyOf"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["required"][0].as_str().unwrap())
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                excluded,
                [
                    "match",
                    "occurrences",
                    "scopes",
                    "bindings",
                    "paths",
                    "union",
                    "intersect",
                    "except",
                    "inside",
                    "inside_decl",
                    "languages",
                    "not_inside",
                    "where",
                ]
                .into_iter()
                .filter(|field| *field != op)
                .collect()
            );
        }
        let query_file_variant = &query_code["inputSchema"]["oneOf"][1];
        let excluded = query_file_variant["not"]["anyOf"]
            .as_array()
            .expect("query_file exclusions")
            .iter()
            .map(|entry| entry["required"][0].as_str().expect("excluded field name"))
            .collect::<std::collections::BTreeSet<_>>();
        let inline_properties = query_code["inputSchema"]["properties"]
            .as_object()
            .expect("query_code properties")
            .keys()
            .map(String::as_str)
            .filter(|field| *field != "query_file")
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(excluded, inline_properties);
    }

    #[test]
    fn most_relevant_files_schema_exposes_ranking_modes() {
        let descriptor = extended_tool_descriptors()
            .into_iter()
            .find(|descriptor| descriptor["name"] == "most_relevant_files")
            .expect("most_relevant_files descriptor");
        let mode = &descriptor["inputSchema"]["properties"]["ranking_mode"];
        assert_eq!(
            mode["enum"],
            json!([
                "cascade",
                "history_imports",
                "usage_graph",
                "usage_graph_exact"
            ])
        );
        assert_eq!(mode["default"], "cascade");
        // #1575: the boolean test filter is gone; each result carries its own
        // classification and the caller applies the policy.
        assert!(
            descriptor["inputSchema"]["properties"]
                .get("include_tests")
                .is_none(),
            "{descriptor:#}"
        );
        assert!(
            descriptor["description"]
                .as_str()
                .expect("description")
                .contains("test_support"),
            "{descriptor:#}"
        );
    }

    /// Issue 2439 slice 3: the explanation surface is a separate tool, not a
    /// `run_policy` mode, and its input schema is bounded and mutually
    /// exclusive by construction.
    #[test]
    fn explain_policy_schema_is_bounded_to_one_policy_and_one_question() {
        let descriptor = extended_tool_descriptors()
            .into_iter()
            .find(|descriptor| descriptor["name"] == "explain_policy")
            .expect("explain_policy descriptor");
        let schema = &descriptor["inputSchema"];
        assert_eq!(schema["additionalProperties"], false);

        // One policy: every selector accepts exactly one entry.
        for selector in [
            "policy_files",
            "policy_packs",
            "policy_categories",
            "policy_ids",
        ] {
            let property = &schema["properties"][selector];
            assert_eq!(property["minItems"], 1, "{selector}");
            assert_eq!(property["maxItems"], 1, "{selector}");
            assert_eq!(property["uniqueItems"], true, "{selector}");
        }
        assert_eq!(
            schema["properties"]["policy_files"]["items"]["maxLength"],
            MAX_RUN_POLICY_PATH_BYTES
        );
        assert_eq!(
            schema["properties"]["policy_ids"]["items"]["maxLength"],
            MAX_RUN_POLICY_SELECTOR_BYTES
        );
        assert_eq!(
            schema["anyOf"].as_array().map(Vec::len),
            Some(4),
            "at least one selector is required"
        );

        // One question: `finding_id` and `candidate` exclude each other.
        assert_eq!(
            schema["oneOf"],
            json!([
                { "required": ["finding_id"], "not": { "required": ["candidate"] } },
                { "required": ["candidate"], "not": { "required": ["finding_id"] } }
            ])
        );
        let finding_id = &schema["properties"]["finding_id"];
        assert_eq!(finding_id["pattern"], "^[0-9a-f]{64}$");
        assert_eq!(finding_id["minLength"], EXPLAIN_POLICY_FINDING_ID_LENGTH);
        assert_eq!(finding_id["maxLength"], EXPLAIN_POLICY_FINDING_ID_LENGTH);
        let candidate = &schema["properties"]["candidate"];
        assert_eq!(candidate["required"], json!(["path", "byte_start"]));
        assert_eq!(candidate["additionalProperties"], false);
        assert_eq!(candidate["properties"]["byte_end"]["type"], "integer");
        assert_eq!(candidate["properties"]["byte_start"]["minimum"], 0);

        // Nothing gate-shaped: an explanation is a query.
        for gating in ["fail_on", "diff_base", "baseline_file", "evaluation_date"] {
            assert!(
                schema["properties"].get(gating).is_none(),
                "`{gating}` has no meaning for an explanation: {descriptor:#}"
            );
        }

        let description = descriptor["description"]
            .as_str()
            .expect("explain_policy description");
        assert!(
            description.contains(brokk_bifrost_policy::POLICY_EXPLANATION_FORMAT),
            "the versioned format is interpolated, never written out: {description}"
        );
        assert!(
            description.contains("never evidence of absence"),
            "the unknown-is-not-failed contract is stated: {description}"
        );
        assert!(
            description.contains("not a gate"),
            "the exit-status contract is stated: {description}"
        );
    }

    #[test]
    fn run_policy_schema_requires_bounded_mixed_inputs() {
        let descriptor = extended_tool_descriptors()
            .into_iter()
            .find(|descriptor| descriptor["name"] == "run_policy")
            .expect("run_policy descriptor");
        let schema = &descriptor["inputSchema"];
        let policy_files = &schema["properties"]["policy_files"];
        assert_eq!(schema["required"], json!(["evaluation_date"]));
        assert_eq!(schema["anyOf"].as_array().map(Vec::len), Some(4));
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(policy_files["minItems"], 1);
        assert_eq!(
            policy_files["maxItems"],
            crate::policy::PolicyBatchBudget::default().max_policies()
        );
        assert_eq!(policy_files["uniqueItems"], true);
        assert_eq!(
            policy_files["items"]["maxLength"],
            MAX_RUN_POLICY_PATH_BYTES
        );
        for selector in ["policy_packs", "policy_categories", "policy_ids"] {
            let property = &schema["properties"][selector];
            assert_eq!(property["minItems"], 1);
            assert_eq!(
                property["maxItems"],
                crate::policy::PolicyBatchBudget::default().max_policies()
            );
            assert_eq!(property["uniqueItems"], true);
            assert_eq!(
                property["items"]["maxLength"],
                MAX_RUN_POLICY_SELECTOR_BYTES
            );
        }
        assert_eq!(
            schema["properties"]["evaluation_date"]["pattern"],
            "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
        );
        assert_eq!(
            schema["properties"]["suppression_file"]["maxLength"],
            crate::policy::MAX_POLICY_SUPPRESSION_PATH_BYTES
        );
        assert_eq!(
            schema["properties"]["scope_file"]["maxLength"],
            crate::policy::MAX_POLICY_SCOPE_PATH_BYTES
        );
        assert_eq!(schema["properties"]["baseline_file"]["type"], "string");
        assert_eq!(schema["properties"]["baseline_file"]["minLength"], 1);
        assert_eq!(
            schema["properties"]["baseline_file"]["maxLength"],
            crate::policy::MAX_POLICY_BASELINE_PATH_BYTES
        );
        assert_eq!(
            schema["properties"]["fail_on"]["enum"],
            json!(["never", "finding", "note", "warning", "error"])
        );
        assert_eq!(schema["properties"]["fail_on"]["default"], "warning");
        assert_eq!(schema["properties"]["diff_base"]["type"], "string");
        assert_eq!(schema["properties"]["diff_base"]["minLength"], 1);
        assert_eq!(
            schema["properties"]["diff_base"]["maxLength"],
            MAX_RUN_POLICY_DIFF_BASE_BYTES
        );
    }
}
