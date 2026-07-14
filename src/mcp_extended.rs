use crate::analyzer::structural::{
    ALL_KINDS, DEFAULT_LIMIT, MAX_CAPTURE_LENGTH, MAX_GLOB_LENGTH, MAX_KWARG_NAME_LENGTH,
    MAX_KWARGS, MAX_LANGUAGE_FILTERS, MAX_LIMIT, MAX_PATTERN_DEPTH, MAX_PATTERN_NODES,
    MAX_QUERY_STEPS, MAX_ROLE_LIST_ENTRIES, MAX_STRING_PREDICATE_LENGTH, MAX_WHERE_GLOBS,
    SCHEMA_VERSION,
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
    run_stdio_server(root, render_options, &spec)
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
    vec![
        tool_descriptor(
            "query_code",
            "Query normalized code structure, then optionally apply typed semantic steps. Version 2 supports enclosing_decl, file_of, imports_of, importers_of, supertypes, subtypes, members, and owner. Hierarchy steps are direct by default and accept either a positive depth or transitive: true. Results include only declarations indexed by the workspace analyzer; observing library usages does not imply that library declarations are queryable. Terminal values are tagged structural_match, declaration, or file results with provenance. It does not traverse call graphs or perform control-flow or data-flow analysis. Minimal query: {\"match\":{\"kind\":\"call\",\"callee\":{\"name\":\"eval\"}}}. Pipeline example: {\"match\":{\"kind\":\"class\",\"name\":\"Service\"},\"steps\":[{\"op\":\"enclosing_decl\"},{\"op\":\"subtypes\",\"transitive\":true},{\"op\":\"members\"}]}. Guide: https://brokkai.github.io/bifrost/code-querying/",
            json!({
                "type": "object",
                "properties": {
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
                    "steps": {
                        "type": "array",
                        "maxItems": MAX_QUERY_STEPS,
                        "items": {
                            "oneOf": [
                                {
                                    "type": "object",
                                    "properties": { "op": { "type": "string", "enum": ["enclosing_decl", "file_of", "imports_of", "importers_of", "members", "owner"] } },
                                    "required": ["op"],
                                    "additionalProperties": false
                                },
                                {
                                    "type": "object",
                                    "properties": { "op": { "type": "string", "enum": ["supertypes", "subtypes"] } },
                                    "required": ["op"],
                                    "additionalProperties": false
                                },
                                {
                                    "type": "object",
                                    "properties": {
                                        "op": { "type": "string", "enum": ["supertypes", "subtypes"] },
                                        "depth": { "type": "integer", "minimum": 1 }
                                    },
                                    "required": ["op", "depth"],
                                    "additionalProperties": false
                                },
                                {
                                    "type": "object",
                                    "properties": {
                                        "op": { "type": "string", "enum": ["supertypes", "subtypes"] },
                                        "transitive": { "const": true }
                                    },
                                    "required": ["op", "transitive"],
                                    "additionalProperties": false
                                }
                            ]
                        },
                        "description": "Ordered typed transformations. Hierarchy/member/owner steps consume and produce exact indexed declarations; import steps consume files."
                    },
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
                },
                "oneOf": [
                    {
                        "required": ["match"],
                        "not": { "required": ["query_file"] }
                    },
                    {
                        "required": ["query_file"],
                        "not": {
                            "anyOf": [
                                { "required": ["where"] },
                                { "required": ["languages"] },
                                { "required": ["match"] },
                                { "required": ["inside"] },
                                { "required": ["not_inside"] },
                                { "required": ["steps"] },
                                { "required": ["limit"] },
                                { "required": ["result_detail"] },
                                { "required": ["schema_version"] }
                            ]
                        }
                    }
                ]
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
        assert_eq!(
            query_code["inputSchema"]["properties"]["schema_version"]["enum"],
            json!([2])
        );
    }
}
