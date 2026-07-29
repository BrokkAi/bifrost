use crate::mcp_common::tool_descriptor;
use serde_json::{Value, json};

pub(crate) fn cli_tool_descriptors() -> Vec<Value> {
    vec![tool_descriptor(
        "classify_test_files",
        "Classify each workspace file as test, test_support, production, or ambiguous for test-surface identification. Combines path conventions with semantic test detection; ambiguous means path conventions were inconclusive - consult contains_test_code.",
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
