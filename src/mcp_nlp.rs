use serde_json::Value;

#[cfg(feature = "nlp")]
pub(crate) fn nlp_tool_descriptors(git_repo: bool) -> Vec<Value> {
    use crate::mcp_common::tool_descriptor;
    use serde_json::json;

    // Semantic search is git-only (the cache is keyed by blob OID) and needs a
    // CUDA/Metal accelerator for voyage-4-nano; on a non-git root or a CPU-only
    // host the tool is omitted entirely (the latter unless --force-semantic-cpu).
    if !git_repo || !crate::nlp::semantic_search_available() {
        return Vec::new();
    }

    vec![tool_descriptor(
        "semantic_search",
        "Search source code by meaning: returns the files whose functions or summaries best match a natural-language description, each with a summary of the file. Searches CODE ONLY (functions, classes, file structure) - it does not index prose, markdown, or other documentation. Complements exact-match tools like search_symbols and search_file_contents. May block while the background semantic index finishes building after startup or large file changes.",
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural-language description of the code you are looking for (a behavior, bug report, or feature)."
                },
                "k": {
                    "type": "integer",
                    "default": 10,
                    "minimum": 1,
                    "description": "Number of files to return."
                }
            },
            "required": ["query"]
        }),
    )]
}

/// Builds without the `nlp` feature expose no nlp tools; toolset expressions
/// that mention "nlp" (including "core") still resolve.
#[cfg(not(feature = "nlp"))]
pub(crate) fn nlp_tool_descriptors(_git_repo: bool) -> Vec<Value> {
    Vec::new()
}
