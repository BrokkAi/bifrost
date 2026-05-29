use crate::mcp_common::tool_descriptor;
use serde_json::{Value, json};

pub(crate) fn text_tool_descriptors() -> Vec<Value> {
    vec![
        tool_descriptor(
            "get_file_contents",
            "Return the raw text contents of one or more files in the workspace, given project-relative paths or absolute paths inside the active workspace.",
            json!({
                "type": "object",
                "properties": {
                    "file_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Project-relative paths of files to read, or absolute paths inside the active workspace."
                    }
                },
                "required": ["file_paths"]
            }),
        ),
        tool_descriptor(
            "search_file_contents",
            "Search file contents with regular expressions, returning matching lines with surrounding context. Optionally restrict the search to files matching a glob or absolute glob inside the active workspace.",
            json!({
                "type": "object",
                "properties": {
                    "patterns": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Regular expressions to search for in file contents."
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Optional glob to restrict the search to matching paths, or an absolute path/glob inside the active workspace."
                    },
                    "context_lines": {
                        "type": "integer",
                        "default": 2,
                        "minimum": 0,
                        "description": "Number of context lines to include before and after each match."
                    },
                    "case_insensitive": {
                        "type": "boolean",
                        "default": false,
                        "description": "Whether to ignore case when matching."
                    }
                },
                "required": ["patterns"]
            }),
        ),
        tool_descriptor(
            "find_files_containing",
            "Find files whose contents match any of the given regular expressions. Binary files and files outside the workspace's gitignore-respecting walk are skipped.",
            json!({
                "type": "object",
                "properties": {
                    "patterns": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Regular expressions to match against file contents."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                        "minimum": 1,
                        "description": "Maximum number of matching files to return."
                    },
                    "case_insensitive": {
                        "type": "boolean",
                        "default": false,
                        "description": "Whether to ignore case when matching."
                    }
                },
                "required": ["patterns"]
            }),
        ),
    ]
}
