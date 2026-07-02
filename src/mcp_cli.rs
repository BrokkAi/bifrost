use crate::mcp_common::tool_descriptor;
use serde_json::{Value, json};

pub(crate) fn cli_tool_descriptors() -> Vec<Value> {
    vec![tool_descriptor(
        "contains_tests",
        "Return whether each requested workspace file contains test code according to Bifrost's language analyzer test detection.",
        json!({
            "type": "object",
            "properties": {
                "file_paths": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Project-relative paths of files to classify."
                }
            },
            "required": ["file_paths"]
        }),
    )]
}
