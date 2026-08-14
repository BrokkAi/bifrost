use serde_json::Value;

#[cfg(feature = "nlp")]
pub(crate) fn nlp_tool_descriptors(git_repo: bool) -> Vec<Value> {
    use crate::mcp_common::tool_descriptor;
    use serde_json::json;

    // Semantic search is git-only (the cache is keyed by blob OID) and needs a
    // CUDA/Metal accelerator for Muninn; on a non-git root or a CPU-only
    // host the tool is omitted entirely (the latter unless --force-semantic-cpu).
    if !git_repo
        || !crate::searchtools_service::semantic_indexing_enabled()
        || !crate::nlp::semantic_search_available()
    {
        return Vec::new();
    }

    vec![tool_descriptor(
        "semantic_search",
        "Find code by meaning when you cannot name what you are looking for. Returns function and method declarations ranked against a natural-language description, plus files that git history shows are edited alongside them. \
This is not a symbol lookup tool. If you know a symbol name or part of one, call search_symbols instead: it is exact, it is faster, and it also finds classes, interfaces, fields, and modules. If you know a distinctive string or error message, call search_file_contents. \
The semantic index holds functions and methods only. It cannot return a class, struct, interface, enum, or constant declaration, so a query that names one returns that type's methods and callers instead. It indexes code, not prose, markdown, or documentation. \
May block while the background semantic index finishes building after startup or large file changes.",
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural-language description of what the code does: a behavior, a bug report, or a feature. Do not put a symbol name here; use search_symbols for a name."
                },
                "k": {
                    "type": "integer",
                    "default": 10,
                    "minimum": 1,
                    "description": "Number of ranked functions to return."
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
