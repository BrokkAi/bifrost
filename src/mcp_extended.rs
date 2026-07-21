use crate::analyzer::structural::query::schema::{
    ALL_QUERY_STEP_OPS, ALL_REFERENCE_KINDS, QueryStepField, reference_kind_label,
};
use crate::analyzer::structural::{
    ALL_KINDS, DEFAULT_LIMIT, MAX_CAPTURE_LENGTH, MAX_GLOB_LENGTH, MAX_KWARG_NAME_LENGTH,
    MAX_KWARGS, MAX_LANGUAGE_FILTERS, MAX_LIMIT, MAX_PATTERN_DEPTH, MAX_PATTERN_NODES,
    MAX_QUERY_BRANCHES, MAX_QUERY_STEPS, MAX_ROLE_LIST_ENTRIES, MAX_STRING_PREDICATE_LENGTH,
    MAX_WHERE_GLOBS, SCHEMA_VERSION,
};
use crate::mcp_common::{McpRenderOptions, run_stdio_server, tool_descriptor};
use serde_json::{Value, json};
use std::path::PathBuf;

pub const EXTENDED_TOOL_NAMES: &[&str] = &[
    "query_code",
    "get_symbol_locations",
    "get_symbol_ancestors",
    "find_filenames",
    "list_files",
    "most_relevant_files",
    "search_git_commit_messages",
    "get_git_log",
    "get_commit_diff",
    "jq",
    "xml_skim",
    "xml_select",
];

pub fn run_extended_stdio_server(
    root: PathBuf,
    render_options: McpRenderOptions,
) -> Result<(), String> {
    let spec = crate::mcp_registry::resolve_server_spec("extended")?;
    run_stdio_server(Some(root), render_options, &spec)
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
    let plain = ALL_QUERY_STEP_OPS
        .iter()
        .copied()
        .filter(|op| {
            !op.allows_hierarchy_options()
                && !op.allows_reference_options()
                && !op.allows_call_options()
                && !op.allows_call_site_options()
                && !op.allows_receiver_options()
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
                    "items": { "type": "string", "enum": reference_kinds }
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
    ]
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
        "steps": {
            "type": "array",
            "maxItems": MAX_QUERY_STEPS,
            "items": { "oneOf": query_step_variants },
            "description": "Ordered typed transformations. Hierarchy/member/owner steps consume and produce exact indexed declarations; import steps consume files."
        }
    })
    .as_object()
    .expect("query plan properties are an object")
    .clone()
}

fn query_plan_source_variants() -> Vec<Value> {
    let seed_scope_fields = ["inside", "not_inside", "where", "languages"];
    let sources = ["match", "union", "intersect", "except"];
    sources
        .into_iter()
        .map(|source| {
            let mut excluded = sources
                .into_iter()
                .filter(|candidate| *candidate != source)
                .collect::<Vec<_>>();
            if source != "match" {
                excluded.extend(seed_scope_fields);
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
        "Query normalized code structure, compose compatible typed branches with union, intersect, or except, then optionally apply typed semantic steps. Version 2 supports {step_vocabulary}. Set branches must produce the same terminal domain; a common steps suffix may continue from that domain. Hierarchy steps are direct by default and accept either a positive depth or transitive: true. Call traversal is direct by default, accepts only finite positive depth, and can expose call sites plus one direct receiver or formal-parameter input. Reference and call steps preserve proof-bearing exact indexed targets and sites. JavaScript and TypeScript receiver_targets, points_to, and member_targets expose bounded demand-driven receiver provenance; other languages return explicit unsupported analysis rows. Results include only declarations indexed by the workspace analyzer; observing library usages does not imply that library declarations are queryable. Terminal values are tagged structural_match, declaration, file, reference_site, call_site, expression_site, or receiver_analysis results with provenance. This is not whole-program points-to, general alias, control-flow, taint, or data-flow analysis. Minimal query: {{\"match\":{{\"kind\":\"call\",\"callee\":{{\"name\":\"eval\"}}}}}}. Set example: {{\"union\":[{{\"match\":{{\"kind\":\"class\",\"name\":\"Legacy\"}}}},{{\"match\":{{\"kind\":\"class\",\"name\":\"Replacement\"}}}}]}}. Guide: https://brokkai.github.io/bifrost/code-querying/"
    );
    let query_step_variants = query_step_input_variants();
    let query_plan_schema = query_plan_schema(&pattern_schema_description, &query_step_variants);
    let mut query_code_properties =
        query_plan_properties(&pattern_schema_description, &query_step_variants);
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
            "schema_version": {
                "type": "integer",
                "default": SCHEMA_VERSION,
                "enum": [SCHEMA_VERSION],
                "description": "Optional query schema version. Omit for v2; other versions are rejected so callers do not accidentally rely on an incompatible query shape."
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
                            "anyOf": [
                                { "required": ["where"] },
                                { "required": ["languages"] },
                                { "required": ["match"] },
                                { "required": ["union"] },
                                { "required": ["intersect"] },
                                { "required": ["except"] },
                                { "required": ["inside"] },
                                { "required": ["not_inside"] },
                                { "required": ["steps"] },
                                { "required": ["limit"] },
                                { "required": ["result_detail"] },
                                { "required": ["schema_version"] }
                            ]
                        }
                    }
                ],
                "$defs": { "queryPlan": query_plan_schema }
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
            "find_filenames",
            "Find files in the workspace whose path matches any of the given glob patterns. Patterns without '/' match against the file basename; patterns with '/' match against the full project-relative path. Absolute patterns inside the active workspace are converted to project-relative patterns before matching.",
            json!({
                "type": "object",
                "properties": {
                    "patterns": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Glob patterns to match against file paths."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 100,
                        "minimum": 1,
                        "description": "Maximum number of matching files to return."
                    }
                },
                "required": ["patterns"]
            }),
        ),
        tool_descriptor(
            "list_files",
            "Return a recursive listing of files under a workspace-relative directory. Respects .gitignore via the project's walker.",
            json!({
                "type": "object",
                "properties": {
                    "directory_path": {
                        "type": "string",
                        "description": "Project-relative directory to list, or an absolute directory inside the active workspace. Empty string lists the workspace root."
                    },
                    "max_entries": {
                        "type": "integer",
                        "default": 500,
                        "minimum": 1,
                        "description": "Maximum number of entries to return."
                    }
                },
                "required": ["directory_path"]
            }),
        ),
        tool_descriptor(
            "most_relevant_files",
            "Given seed source files, rank related code by imports and git history; use after finding one relevant file to expand context.",
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
                        "enum": ["history_imports", "usage_graph"],
                        "default": "history_imports",
                        "description": "Ranking source. history_imports preserves git-first/import-fill behavior; usage_graph ranks resolved caller-to-callee relationships first and uses the legacy ranking to fill remaining slots."
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
        tool_descriptor(
            "search_git_commit_messages",
            "Regex search across the workspace's git commit messages. Returns matching commits as a sequence of <commit id=\"...\"> blocks, each containing <message> and <edited_files>.",
            json!({
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regular expression to match against commit messages."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 20,
                        "minimum": 1,
                        "maximum": 100,
                        "description": "Maximum number of matching commits to return (capped at 100)."
                    }
                },
                "required": ["pattern"]
            }),
        ),
        tool_descriptor(
            "get_git_log",
            "Return recent commits, optionally filtered to those that touch a given path. Output is a <git_log> wrapper containing <entry> elements with hash, author, date and the commit message body.",
            json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Optional project-relative file or directory path to filter by, or an absolute path inside the active workspace."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 20,
                        "minimum": 1,
                        "maximum": 100,
                        "description": "Maximum number of commits to return (capped at 100)."
                    }
                }
            }),
        ),
        tool_descriptor(
            "get_commit_diff",
            "Return the unified diff for a single commit versus its parent (or the empty tree for root commits), wrapped in a <commit_diff> element with revision, short_hash, files_total, files_included and truncated attributes. Truncated by file count and lines per file.",
            json!({
                "type": "object",
                "properties": {
                    "revision": {
                        "type": "string",
                        "description": "Commit reference (short hash, full hash, branch, tag)."
                    },
                    "max_files": {
                        "type": "integer",
                        "default": 10,
                        "minimum": 1,
                        "maximum": 100,
                        "description": "Maximum number of files to include in the diff (capped at 100)."
                    },
                    "lines_per_file": {
                        "type": "integer",
                        "default": 1000,
                        "minimum": 1,
                        "maximum": 5000,
                        "description": "Maximum number of diff lines per file (capped at 5000)."
                    }
                },
                "required": ["revision"]
            }),
        ),
        tool_descriptor(
            "jq",
            "Run a jq expression against one or more JSON files matched by a glob (or a literal path).",
            json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Project-relative glob or literal path to JSON file(s), or an absolute path/glob inside the active workspace."
                    },
                    "filter": {
                        "type": "string",
                        "description": "jq filter expression."
                    },
                    "max_files": {
                        "type": "integer",
                        "default": 25,
                        "minimum": 1,
                        "description": "Maximum number of files to process."
                    },
                    "matches_per_file": {
                        "type": "integer",
                        "default": 100,
                        "minimum": 1,
                        "description": "Maximum number of filter outputs to collect per file."
                    }
                },
                "required": ["file_path", "filter"]
            }),
        ),
        tool_descriptor(
            "xml_skim",
            "Return an element-hierarchy outline (tag name, depth, attribute count) for one or more XML files. HTML is not supported in this revision; well-formed XML only.",
            json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Project-relative glob or literal path to XML file(s), or an absolute path/glob inside the active workspace."
                    },
                    "max_files": {
                        "type": "integer",
                        "default": 25,
                        "minimum": 1,
                        "description": "Maximum number of files to process."
                    }
                },
                "required": ["file_path"]
            }),
        ),
        tool_descriptor(
            "xml_select",
            "Run an XPath 3.1 expression against one or more XML files. Returns matched node text, attribute value, or outer XML depending on output mode. HTML is not supported in this revision.",
            json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Project-relative glob or literal path to XML file(s), or an absolute path/glob inside the active workspace."
                    },
                    "xpath": {
                        "type": "string",
                        "description": "XPath 3.1 expression."
                    },
                    "output": {
                        "type": "string",
                        "enum": ["text", "attribute", "outer-xml"],
                        "default": "text",
                        "description": "Output mode for matched nodes."
                    },
                    "attr_name": {
                        "type": "string",
                        "description": "Required when output is \"attribute\"."
                    },
                    "max_files": {
                        "type": "integer",
                        "default": 25,
                        "minimum": 1,
                        "description": "Maximum number of files to process."
                    }
                },
                "required": ["file_path", "xpath"]
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
                "file_of",
                "imports_of",
                "importers_of",
                "members",
                "owner"
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
        assert_eq!(
            query_code["inputSchema"]["properties"]["schema_version"]["enum"],
            json!([2])
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
        for field in [
            "match",
            "inside",
            "not_inside",
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
                    "union",
                    "intersect",
                    "except",
                    "inside",
                    "languages",
                    "not_inside",
                    "where",
                ]
                .into_iter()
                .filter(|field| *field != op)
                .collect()
            );
        }
    }

    #[test]
    fn most_relevant_files_schema_exposes_ranking_modes() {
        let descriptor = extended_tool_descriptors()
            .into_iter()
            .find(|descriptor| descriptor["name"] == "most_relevant_files")
            .expect("most_relevant_files descriptor");
        let mode = &descriptor["inputSchema"]["properties"]["ranking_mode"];
        assert_eq!(mode["enum"], json!(["history_imports", "usage_graph"]));
        assert_eq!(mode["default"], "history_imports");
    }
}
