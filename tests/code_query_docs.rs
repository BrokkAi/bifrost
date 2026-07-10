use brokk_bifrost::analyzer::structural::CodeQuery;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const DOCS: &[&str] = &[
    "docs/src/content/docs/code-querying.md",
    "docs/src/content/docs/code-query-json.md",
    "docs/src/content/docs/rune-query-language.md",
    "docs/src/content/docs/code-query-tutorials/index.md",
    "docs/src/content/docs/code-query-tutorials/python.md",
    "docs/src/content/docs/code-query-tutorials/java.md",
    "docs/src/content/docs/code-query-tutorials/javascript.md",
    "docs/src/content/docs/code-query-tutorials/typescript.md",
    "docs/src/content/docs/code-query-tutorials/go.md",
    "docs/src/content/docs/code-query-tutorials/cpp.md",
];

const PUBLIC_QUERY_SURFACES: &[&str] = &[
    "README.md",
    "bifrost_searchtools/README.md",
    "bifrost_searchtools/__init__.py",
    "bifrost_searchtools/client.py",
    "bifrost_searchtools/models.py",
    "docs/astro.config.mjs",
    "docs/src/content/docs/code-querying.md",
    "docs/src/content/docs/code-query-json.md",
    "docs/src/content/docs/rune-query-language.md",
    "docs/src/content/docs/mcp.md",
    "docs/src/content/docs/python-client.md",
    "src/mcp_extended.rs",
    "src/bin/bifrost.rs",
    "src/bin/bifrost/code_query_repl.rs",
    "plugins/bifrost-agent/skills/bifrost-codebase-search/SKILL.md",
    "plugins/bifrost-agent/codex-skills/bifrost-codebase-search/SKILL.md",
    "plugins/bifrost-agent/amp-skills/bifrost-code-intelligence/SKILL.md",
    "plugins/bifrost-agent/amp-skills/bifrost-code-intelligence/mcp.json",
];

const REQUIRED_JSON_EXAMPLES: &[&str] = &[
    "minimal-call",
    "receiver-args-kwargs",
    "import",
    "assignment",
    "decorator",
    "containment",
    "negative-descendant",
    "kind-union",
    "scope",
];

#[derive(Debug)]
struct MarkedExample {
    format: String,
    label: String,
    body: String,
    marker_line: usize,
}

#[test]
fn documented_code_queries_parse() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut seen = BTreeSet::new();

    for relative in DOCS {
        let path = root.join(relative);
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for example in marked_examples(&path, &contents) {
            assert!(
                seen.insert((example.format.clone(), example.label.clone())),
                "duplicate code-query example marker {}:{} in {}:{}",
                example.format,
                example.label,
                path.display(),
                example.marker_line
            );
            match example.format.as_str() {
                "json" => {
                    let value: serde_json::Value = serde_json::from_str(&example.body)
                        .unwrap_or_else(|error| example_panic(&path, &example, error));
                    CodeQuery::from_json(&value)
                        .unwrap_or_else(|error| example_panic(&path, &example, error));
                }
                "rql" => {
                    CodeQuery::from_sexp(&example.body)
                        .unwrap_or_else(|error| example_panic(&path, &example, error));
                }
                other => panic!(
                    "unknown code-query example format {other:?} in {}:{}",
                    path.display(),
                    example.marker_line
                ),
            }
        }
    }

    for label in REQUIRED_JSON_EXAMPLES {
        assert!(
            seen.contains(&("json".to_string(), (*label).to_string())),
            "missing required JSON code-query example marker: {label}"
        );
    }
    assert!(
        seen.contains(&("rql".to_string(), "complete".to_string())),
        "missing complete RQL code-query example"
    );
}

#[test]
fn current_public_query_surfaces_use_the_new_name() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative in PUBLIC_QUERY_SURFACES {
        let path = root.join(relative);
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for stale in [
            "search_ast",
            "AstQuery",
            "SearchAst",
            "search-ast-json",
            "search-ast-repl",
        ] {
            assert!(
                !contents.contains(stale),
                "{} still contains stale public query name {stale:?}",
                path.display()
            );
        }
    }
}

fn marked_examples(path: &Path, contents: &str) -> Vec<MarkedExample> {
    let lines = contents.lines().collect::<Vec<_>>();
    let mut examples = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index].trim();
        let Some(marker) = line
            .strip_prefix("<!-- code-query-test:")
            .and_then(|value| value.strip_suffix(" -->"))
        else {
            index += 1;
            continue;
        };
        let (format, label) = marker.split_once(':').unwrap_or_else(|| {
            panic!(
                "malformed code-query example marker in {}:{}",
                path.display(),
                index + 1
            )
        });
        let expected_fence = match format {
            "json" => "```json",
            "rql" => "```lisp",
            _ => panic!(
                "unknown code-query example format {format:?} in {}:{}",
                path.display(),
                index + 1
            ),
        };
        let fence_index = index + 1;
        assert_eq!(
            lines.get(fence_index).map(|value| value.trim()),
            Some(expected_fence),
            "marker in {}:{} must be immediately followed by {expected_fence}",
            path.display(),
            index + 1
        );
        let mut body = Vec::new();
        index = fence_index + 1;
        while index < lines.len() && lines[index].trim() != "```" {
            body.push(lines[index]);
            index += 1;
        }
        assert!(
            index < lines.len(),
            "unterminated marked example in {}:{}",
            path.display(),
            fence_index + 1
        );
        examples.push(MarkedExample {
            format: format.to_string(),
            label: label.to_string(),
            body: body.join("\n"),
            marker_line: fence_index,
        });
        index += 1;
    }
    examples
}

fn example_panic(path: &Path, example: &MarkedExample, error: impl std::fmt::Display) -> ! {
    panic!(
        "invalid {} code-query example {} in {}:{}: {error}\n{}",
        example.format,
        example.label,
        display_path(path),
        example.marker_line,
        example.body
    )
}

fn display_path(path: &Path) -> String {
    path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
        .unwrap_or(path)
        .display()
        .to_string()
}
