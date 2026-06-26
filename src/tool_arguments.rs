use serde_json::Value;
use std::path::Path;

pub fn normalize_tool_arguments(
    tool_name: &str,
    mut arguments: Value,
    workspace_root: &Path,
) -> Result<Value, String> {
    match tool_name {
        "get_summaries" => normalize_string_array_field(&mut arguments, "targets", workspace_root)?,
        "list_symbols" => {
            normalize_string_array_field(&mut arguments, "file_patterns", workspace_root)?
        }
        "scan_usages" => {
            normalize_string_array_field(&mut arguments, "paths", workspace_root)?;
            normalize_object_array_string_field(&mut arguments, "targets", "path", workspace_root)?;
        }
        "most_relevant_files" => {
            normalize_string_array_field(&mut arguments, "seed_file_paths", workspace_root)?
        }
        "rename_symbol" => normalize_optional_string_field(&mut arguments, "path", workspace_root)?,
        "get_file_contents" => {
            normalize_string_array_field(&mut arguments, "file_paths", workspace_root)?
        }
        "find_filenames" => {
            normalize_string_array_field(&mut arguments, "patterns", workspace_root)?
        }
        "search_file_contents" | "jq" | "xml_skim" | "xml_select" => {
            normalize_optional_string_field(&mut arguments, "file_path", workspace_root)?
        }
        "list_files" => {
            normalize_optional_string_field(&mut arguments, "directory_path", workspace_root)?
        }
        "compute_cyclomatic_complexity"
        | "compute_cognitive_complexity"
        | "report_comment_density_for_files"
        | "report_exception_handling_smells"
        | "report_test_assertion_smells"
        | "report_structural_clone_smells"
        | "report_long_method_and_god_object_smells"
        | "report_dead_code_and_unused_abstraction_smells" => {
            normalize_string_array_field(&mut arguments, "file_paths", workspace_root)?
        }
        "get_git_log" => {
            normalize_optional_string_field(&mut arguments, "file_path", workspace_root)?
        }
        _ => {}
    }
    Ok(arguments)
}

fn normalize_string_array_field(
    arguments: &mut Value,
    field: &str,
    workspace_root: &Path,
) -> Result<(), String> {
    let Some(array) = arguments.get_mut(field).and_then(Value::as_array_mut) else {
        return Ok(());
    };

    for item in array {
        let Some(raw) = item.as_str() else {
            continue;
        };
        if let Some(normalized) = normalize_mcp_path_argument(raw, workspace_root)? {
            *item = Value::String(normalized);
        }
    }
    Ok(())
}

fn normalize_optional_string_field(
    arguments: &mut Value,
    field: &str,
    workspace_root: &Path,
) -> Result<(), String> {
    let Some(value) = arguments.get_mut(field) else {
        return Ok(());
    };
    let Some(raw) = value.as_str() else {
        return Ok(());
    };
    if let Some(normalized) = normalize_mcp_path_argument(raw, workspace_root)? {
        *value = Value::String(normalized);
    }
    Ok(())
}

fn normalize_object_array_string_field(
    arguments: &mut Value,
    array_field: &str,
    string_field: &str,
    workspace_root: &Path,
) -> Result<(), String> {
    let Some(array) = arguments.get_mut(array_field).and_then(Value::as_array_mut) else {
        return Ok(());
    };

    for item in array {
        normalize_optional_string_field(item, string_field, workspace_root)?;
    }
    Ok(())
}

fn normalize_mcp_path_argument(raw: &str, workspace_root: &Path) -> Result<Option<String>, String> {
    let trimmed = raw.trim();
    if !looks_like_absolute_path(trimmed) {
        return Ok(None);
    }

    if contains_glob_syntax(trimmed) {
        return normalize_absolute_glob(trimmed, workspace_root).map(Some);
    }

    normalize_absolute_literal_path(trimmed, workspace_root).map(Some)
}

fn normalize_absolute_literal_path(raw: &str, workspace_root: &Path) -> Result<String, String> {
    let path = Path::new(raw);
    if let Ok(canonical_path) = path.canonicalize() {
        let canonical_root = workspace_root
            .canonicalize()
            .unwrap_or_else(|_| workspace_root.to_path_buf());
        return canonical_path
            .strip_prefix(&canonical_root)
            .map(path_to_slash_string)
            .map_err(|_| outside_workspace_error(raw, workspace_root));
    }

    normalize_absolute_path_lexically(raw, workspace_root)
}

fn normalize_absolute_glob(raw: &str, workspace_root: &Path) -> Result<String, String> {
    normalize_absolute_path_lexically(raw, workspace_root)
}

fn normalize_absolute_path_lexically(raw: &str, workspace_root: &Path) -> Result<String, String> {
    let raw_norm = slash_string(raw);
    let root_norm = slash_string(&workspace_root.display().to_string());
    let root_trimmed = root_norm.trim_end_matches('/');

    let relative = if raw_norm == root_trimmed {
        ""
    } else if let Some(rest) = raw_norm.strip_prefix(&format!("{root_trimmed}/")) {
        rest
    } else {
        return Err(outside_workspace_error(raw, workspace_root));
    };

    normalize_relative_slash_path(relative)
        .map_err(|_| outside_workspace_error(raw, workspace_root))
}

fn normalize_relative_slash_path(relative: &str) -> Result<String, String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in relative.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err("path escapes active workspace".to_string());
                }
            }
            _ => parts.push(part),
        }
    }
    Ok(parts.join("/"))
}

fn looks_like_absolute_path(raw: &str) -> bool {
    Path::new(raw).is_absolute() || is_windows_absolute_path(raw)
}

fn is_windows_absolute_path(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn contains_glob_syntax(raw: &str) -> bool {
    raw.contains(['*', '?', '['])
}

fn path_to_slash_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn slash_string(path: &str) -> String {
    path.replace('\\', "/")
}

fn outside_workspace_error(raw: &str, workspace_root: &Path) -> String {
    format!(
        "absolute path is outside active workspace: {} (workspace: {})",
        raw,
        workspace_root.display()
    )
}

#[cfg(test)]
mod tests {
    use super::normalize_tool_arguments;
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn normalizes_absolute_literal_paths_for_tool_fields() {
        let root = TempDir::new().expect("temp dir");
        let src = root.path().join("src");
        fs::create_dir(&src).expect("src dir");
        let file = src.join("A.java");
        fs::write(&file, "class A {}\n").expect("write file");

        let normalized = normalize_tool_arguments(
            "get_file_contents",
            json!({ "file_paths": [file.display().to_string()] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["file_paths"][0], "src/A.java");
    }

    #[test]
    fn normalizes_absolute_globs_lexically() {
        let root = TempDir::new().expect("temp dir");
        let raw = format!("{}/src/**/*.rs", root.path().display());

        let normalized = normalize_tool_arguments(
            "list_symbols",
            json!({ "file_patterns": [raw] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["file_patterns"][0], "src/**/*.rs");
    }

    #[test]
    fn rejects_existing_absolute_paths_outside_workspace() {
        let root = TempDir::new().expect("root dir");
        let outside = TempDir::new().expect("outside dir");
        let file = outside.path().join("secret.txt");
        fs::write(&file, "secret").expect("write outside");

        let err = normalize_tool_arguments(
            "get_file_contents",
            json!({ "file_paths": [file.display().to_string()] }),
            root.path(),
        )
        .expect_err("outside path should fail");

        assert!(err.contains("outside active workspace"), "{err}");
        assert!(err.contains(&file.display().to_string()), "{err}");
    }

    #[test]
    fn normalizes_nonexistent_absolute_paths_inside_workspace() {
        let root = TempDir::new().expect("temp dir");
        let missing = root.path().join("src").join("Missing.java");

        let normalized = normalize_tool_arguments(
            "get_file_contents",
            json!({ "file_paths": [missing.display().to_string()] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["file_paths"][0], "src/Missing.java");
    }

    #[test]
    fn rejects_nonexistent_parent_dir_escapes() {
        let root = TempDir::new().expect("temp dir");
        let raw = format!("{}/../outside/Missing.java", root.path().display());

        let err = normalize_tool_arguments(
            "get_file_contents",
            json!({ "file_paths": [raw] }),
            root.path(),
        )
        .expect_err("escaping path should fail");

        assert!(err.contains("outside active workspace"), "{err}");
    }

    #[test]
    fn leaves_non_path_fields_untouched() {
        let root = TempDir::new().expect("temp dir");
        let absolute_looking_symbol = format!("{}/src/A.java", root.path().display());

        let normalized = normalize_tool_arguments(
            "scan_usages",
            json!({ "symbols": [absolute_looking_symbol] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["symbols"][0], absolute_looking_symbol);
    }

    #[test]
    fn normalizes_scan_usages_paths_field() {
        let root = TempDir::new().expect("temp dir");
        let src = root.path().join("src");
        fs::create_dir(&src).expect("src dir");
        let file = src.join("lib.rs");
        fs::write(&file, "fn helper() {}\n").expect("write file");

        let normalized = normalize_tool_arguments(
            "scan_usages",
            json!({
                "symbols": ["pkg.helper"],
                "paths": [file.display().to_string()]
            }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["paths"][0], "src/lib.rs");
    }

    #[test]
    fn normalizes_scan_usages_target_paths_field() {
        let root = TempDir::new().expect("temp dir");
        let src = root.path().join("src");
        fs::create_dir(&src).expect("src dir");
        let file = src.join("lib.rs");
        fs::write(&file, "fn helper() {}\n").expect("write file");

        let normalized = normalize_tool_arguments(
            "scan_usages",
            json!({
                "targets": [{
                    "path": file.display().to_string(),
                    "line": 1,
                    "column": 4
                }]
            }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["targets"][0]["path"], "src/lib.rs");
        assert_eq!(normalized["targets"][0]["line"], 1);
        assert_eq!(normalized["targets"][0]["column"], 4);
    }

    #[test]
    fn normalizes_only_path_fields_for_mixed_argument_tools() {
        let root = TempDir::new().expect("temp dir");
        let src = root.path().join("src");
        fs::create_dir(&src).expect("src dir");
        let file = src.join("lib.rs");
        fs::write(&file, "fn helper() {}\n").expect("write file");
        let fq_name = format!("{}/src/lib.rs", root.path().display());

        let normalized = normalize_tool_arguments(
            "report_dead_code_and_unused_abstraction_smells",
            json!({
                "file_paths": [file.display().to_string()],
                "fq_names": [fq_name]
            }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["file_paths"][0], "src/lib.rs");
        assert_eq!(normalized["fq_names"][0], fq_name);
    }
}
