use brokk_bifrost::{
    AnalyzerConfig, FilesystemProject, Project, SearchToolsService, SearchToolsServiceErrorCode,
    WorkspaceAnalyzer, searchtools_render::RenderOptions,
};
use git2::{Repository, Signature};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{MAIN_SEPARATOR, PathBuf};
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java")
}

fn array_len(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0)
}

#[test]
fn service_allows_concurrent_read_only_calls() {
    let service = Arc::new(SearchToolsService::new_without_semantic_index(fixture_root()).unwrap());
    let calls = [
        (
            "search_symbols",
            r#"{"patterns":["A"],"include_tests":true,"limit":5}"#,
        ),
        ("get_symbol_sources", r#"{"symbols":["A.method2"]}"#),
        ("get_summaries", r#"{"targets":["A.java"]}"#),
        (
            "most_relevant_files",
            r#"{"seed_file_paths":["A.java"],"limit":5}"#,
        ),
    ];

    let handles: Vec<_> = (0..16)
        .map(|index| {
            let service = Arc::clone(&service);
            let (tool, args) = calls[index % calls.len()];
            thread::spawn(move || {
                let payload = service.call_tool_json(tool, args).unwrap();
                serde_json::from_str::<Value>(&payload).unwrap()
            })
        })
        .collect();

    for handle in handles {
        let value = handle.join().unwrap();
        assert!(value.is_object(), "payload: {value}");
    }
}

#[test]
fn workspace_update_publishes_new_snapshot_without_mutating_old_snapshot() {
    let temp = TempDir::new().unwrap();
    let file_path = temp.path().join("Thing.java");
    fs::write(&file_path, "public class First {}\n").unwrap();

    let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(temp.path()).unwrap());
    let old_snapshot = WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default());
    assert!(
        old_snapshot
            .analyzer()
            .search_definitions("First", true)
            .iter()
            .any(|unit| unit.fq_name() == "First")
    );

    fs::write(&file_path, "public class Second {}\n").unwrap();
    let changed_file = project
        .file_by_rel_path(std::path::Path::new("Thing.java"))
        .unwrap();
    let new_snapshot = old_snapshot.update(&BTreeSet::from([changed_file]));

    assert!(
        old_snapshot
            .analyzer()
            .search_definitions("First", true)
            .iter()
            .any(|unit| unit.fq_name() == "First"),
        "old snapshot should retain First"
    );
    assert!(
        old_snapshot
            .analyzer()
            .search_definitions("Second", true)
            .is_empty(),
        "old snapshot should not see Second"
    );
    assert!(
        new_snapshot
            .analyzer()
            .search_definitions("Second", true)
            .iter()
            .any(|unit| unit.fq_name() == "Second"),
        "new snapshot should see Second"
    );
}

#[test]
fn python_boundary_returns_structured_json() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json("get_summaries", r#"{"targets":["A.java"]}"#)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["summaries"][0]["path"], "A.java");
    assert_eq!(value["summaries"][0]["elements"][0]["start_line"], 3);
}

#[test]
fn get_summaries_directory_target_returns_skim_symbol_inventory() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_summaries",
            r#"{"targets":["."]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(false, value["structured"]["degraded"]);
    assert!(value["structured"]["degradation"].is_null());
    let compact_symbols = &value["structured"]["compact_symbols"];
    assert!(compact_symbols["files"].as_array().unwrap().len() <= 20);
    assert!(
        compact_symbols["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "A.java"),
        "{compact_symbols}"
    );
    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("A.java ("), "{rendered}");
}

#[test]
fn get_summaries_mixed_targets_return_summaries_and_directory_inventory() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_summaries",
            r#"{"targets":["A.java","."]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["structured"]["summaries"][0]["path"], "A.java");
    assert_eq!(false, value["structured"]["degraded"]);
    let compact_symbols = &value["structured"]["compact_symbols"];
    assert!(
        compact_symbols["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "A.java"),
        "{compact_symbols}"
    );
    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("A.java"), "{rendered}");
    assert!(rendered.contains("A.java ("), "{rendered}");
}

#[test]
fn get_summaries_large_file_glob_degrades_to_compact_symbols() {
    let temp = TempDir::new().unwrap();
    for class_idx in 0..18 {
        let mut source = format!("public class Caller{class_idx} {{\n");
        for method_idx in 0..12 {
            source.push_str(&format!(
                "    public int method{method_idx}(int input) {{ return input + {class_idx} + {method_idx}; }}\n"
            ));
        }
        source.push_str("}\n");
        fs::write(temp.path().join(format!("Caller{class_idx}.java")), source).unwrap();
    }

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json("get_summaries", r#"{"targets":["*.java"]}"#)
        .unwrap();
    assert!(
        payload.len() <= 4096,
        "payload should stay within get_summaries budget, got {} bytes: {payload}",
        payload.len()
    );

    let value: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(true, value["degraded"]);
    assert_eq!("response_budget_exceeded", value["degradation"]["reason"]);
    assert_eq!("summaries", value["degradation"]["requested_format"]);
    assert_eq!("compact_symbols", value["degradation"]["returned_format"]);
    assert!(value["summaries"].as_array().unwrap().is_empty());
    let compact = &value["compact_symbols"];
    assert!(compact["truncated"].as_bool().unwrap());
    assert!(
        compact["files"].as_array().unwrap().len() < 18,
        "compact fallback should drop files until it fits: {compact}"
    );
}

#[test]
fn python_boundary_returns_canonical_rendered_text_payload() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_symbol_sources",
            r#"{"symbols":["A.method2"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["structured"]["sources"][0]["start_line"], 8);
    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("## A.method2"), "{rendered}");
    assert!(rendered.contains("- Location: A.java:8..10"), "{rendered}");
    assert!(
        rendered.contains("8: public String method2(String input)"),
        "{rendered}"
    );
}

#[test]
fn get_symbol_sources_file_input_returns_top_level_outline_payload() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("src").join("pkg")).unwrap();
    fs::write(
        temp.path().join("src").join("pkg").join("Thing.java"),
        r#"package pkg;
class Thing {
    void method() {}
    static class Inner {}
}
"#,
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_symbol_sources",
            r#"{"symbols":["src/pkg/Thing.java"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let source = &value["structured"]["sources"][0];
    assert_eq!("src/pkg/Thing.java", source["label"]);
    assert_eq!("src/pkg/Thing.java", source["path"]);
    assert_eq!(1, source["start_line"]);
    assert_eq!(2, source["end_line"]);
    let source_text = source["text"].as_str().expect("source text");
    assert!(source_text.contains("# pkg"), "{source_text}");
    assert!(source_text.contains("- Thing"), "{source_text}");
    assert!(!source_text.contains("method"), "{source_text}");
    assert!(!source_text.contains("Inner"), "{source_text}");

    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(rendered.contains("## src/pkg/Thing.java"), "{rendered}");
    assert!(
        rendered.contains("- Location: src/pkg/Thing.java:1..2"),
        "{rendered}"
    );
    assert!(
        rendered.contains("```text\n1: # pkg\n2: - Thing\n```"),
        "{rendered}"
    );
}

#[test]
fn get_symbol_sources_file_input_uses_include_and_sample_fallbacks() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::write(
        temp.path().join("src").join("only_includes.h"),
        "#pragma once\n#include \"only/include.h\"\n#include <stdint.h>\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("src").join("emptyish_large.h"),
        (1..=60)
            .map(|line| format!("// line {line}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_symbol_sources",
            r#"{"symbols":["src/only_includes.h","src/emptyish_large.h"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let sources = value["structured"]["sources"].as_array().unwrap();
    let include_source = sources
        .iter()
        .find(|source| source["path"] == "src/only_includes.h")
        .unwrap();
    assert_eq!(2, include_source["start_line"]);
    assert_eq!(3, include_source["end_line"]);
    assert_eq!(
        "#include \"only/include.h\"\n#include <stdint.h>",
        include_source["text"]
    );

    let sampled_source = sources
        .iter()
        .find(|source| source["path"] == "src/emptyish_large.h")
        .unwrap();
    assert_eq!(1, sampled_source["start_line"]);
    assert_eq!(60, sampled_source["end_line"]);
    assert_eq!("sampled_excerpt", sampled_source["presentation"]);
    let sampled_text = sampled_source["text"].as_str().expect("sampled text");
    assert!(sampled_text.contains("// line 1"), "{sampled_text}");
    assert!(
        sampled_text.contains("----- OMITTED 10 LINES -----"),
        "{sampled_text}"
    );
    assert!(sampled_text.contains("// line 60"), "{sampled_text}");

    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(
        rendered.contains("- Location: src/only_includes.h:2..3"),
        "{rendered}"
    );
    assert!(
        rendered.contains("#include \"only/include.h\""),
        "{rendered}"
    );
    assert!(
        rendered.contains("- Location: src/emptyish_large.h:1..60"),
        "{rendered}"
    );
    assert!(
        rendered.contains("----- OMITTED 10 LINES -----"),
        "{rendered}"
    );
}

#[test]
fn legacy_kind_filter_is_ignored_for_symbol_sources_and_locations() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();

    let source_payload = service
        .call_tool_json(
            "get_symbol_sources",
            r#"{"symbols":["A.method2"],"kind_filter":"function"}"#,
        )
        .unwrap();
    let source_value: Value = serde_json::from_str(&source_payload).unwrap();
    assert_eq!("A.method2", source_value["sources"][0]["label"]);

    let location_payload = service
        .call_tool_json(
            "get_symbol_locations",
            r#"{"symbols":["A.method2"],"kind_filter":"function"}"#,
        )
        .unwrap();
    let location_value: Value = serde_json::from_str(&location_payload).unwrap();
    assert_eq!("A.method2", location_value["locations"][0]["symbol"]);
}

#[test]
fn get_symbol_ancestors_rejects_non_type_targets() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Thing.java"),
        "class Base {}\nclass Thing extends Base { void run() {} }\n",
    )
    .unwrap();
    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();

    let err = service
        .call_tool_json("get_symbol_ancestors", r#"{"symbols":["Thing.run"]}"#)
        .unwrap_err();

    assert_eq!(SearchToolsServiceErrorCode::InvalidParams, err.code);
    assert!(
        err.message
            .contains("only accepts class/module/type symbols")
    );
}

#[test]
fn get_summaries_renders_include_and_excerpt_fallbacks() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::write(
        temp.path().join("src").join("only_includes.h"),
        "#pragma once\n#include \"only/include.h\"\n#include <stdint.h>\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("src").join("emptyish.h"),
        (1..=25)
            .map(|line| format!("// line {line}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_payload_json(
            "get_summaries",
            r#"{"targets":["src/only_includes.h","src/emptyish.h"]}"#,
            RenderOptions::default(),
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let summaries = value["structured"]["summaries"].as_array().unwrap();
    let include_summary = summaries
        .iter()
        .find(|summary| summary["path"] == "src/only_includes.h")
        .unwrap();
    assert_eq!(
        "no indexed declarations found; showing top-level includes",
        include_summary["fallback_reason"]
    );
    assert_eq!("include", include_summary["elements"][0]["kind"]);
    assert_eq!("only/include.h", include_summary["elements"][0]["symbol"]);

    let excerpt_summary = summaries
        .iter()
        .find(|summary| summary["path"] == "src/emptyish.h")
        .unwrap();
    assert_eq!(
        "no indexed declarations or top-level includes found; showing head/tail sample",
        excerpt_summary["fallback_reason"]
    );
    assert_eq!("excerpt", excerpt_summary["elements"][0]["kind"]);
    assert_eq!(25, excerpt_summary["elements"][0]["end_line"]);
    assert_eq!(
        "sampled_excerpt",
        excerpt_summary["elements"][0]["presentation"]
    );

    let rendered = value["rendered_text"].as_str().expect("rendered text");
    assert!(
        rendered.contains("Note: no indexed declarations found; showing top-level includes"),
        "{rendered}"
    );
    assert!(
        rendered.contains("#include \"only/include.h\""),
        "{rendered}"
    );
    assert!(
        rendered.contains(
            "Note: no indexed declarations or top-level includes found; showing head/tail sample"
        ),
        "{rendered}"
    );
    assert!(rendered.contains("// line 1"), "{rendered}");
}

#[test]
fn python_boundary_returns_structural_clone_report_json() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Alpha.java"),
        "class Alpha { int compute(int input) { int total = input + 1; if (total > 10) { return total * 2; } return total - 3; } }\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("Beta.java"),
        "class Beta { int calculate(int seed) { int amount = seed + 1; if (amount > 10) { return amount * 2; } return amount - 3; } }\n",
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "report_structural_clone_smells",
            r#"{"file_paths":["Alpha.java","Beta.java"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert!(
        value["report"]
            .as_str()
            .expect("report string")
            .starts_with("## Structural clone smells"),
        "payload: {value}"
    );
}

#[test]
fn python_boundary_returns_dead_code_smell_report_json() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("helpers.rs"), "fn helper() {}\n").unwrap();
    fs::write(temp.path().join("main.rs"), "fn main() {}\n").unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "report_dead_code_and_unused_abstraction_smells",
            r#"{"file_paths":["helpers.rs","main.rs"],"fq_names":["helpers.helper"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let report = value["report"].as_str().expect("report string");
    assert!(
        report.starts_with("## Dead code and unused abstraction smells"),
        "payload: {value}"
    );
    assert!(report.contains("helpers.helper"), "payload: {value}");
}

#[test]
fn python_boundary_returns_secret_scan_report_json() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("config.properties"),
        "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    let mut index = repo.index().unwrap();
    index
        .add_path(std::path::Path::new("config.properties"))
        .unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let signature = Signature::now("Test User", "test@example.com").unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .unwrap();
    repo.reference_symbolic(
        "refs/remotes/origin/HEAD",
        "refs/heads/master",
        true,
        "set remote default",
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "report_secret_like_code",
            r#"{"max_findings":10,"max_commits":10}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert!(
        value["report"]
            .as_str()
            .expect("report string")
            .starts_with("## brokk-secret-scan"),
        "payload: {value}"
    );
    assert!(
        !value["report"]
            .as_str()
            .unwrap()
            .contains("AKIAIOSFODNN7EXAMPLE"),
        "payload: {value}"
    );
}

#[test]
fn python_boundary_returns_git_hotspot_report_json() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::write(
        temp.path().join("src").join("ComplexService.java"),
        "public class ComplexService { void hotspot(int x) { if (x > 0) {} if (x > 1) {} if (x > 2) {} if (x > 3) {} if (x > 4) {} if (x > 5) {} if (x > 6) {} if (x > 7) {} if (x > 8) {} if (x > 9) {} if (x > 10) {} if (x > 11) {} if (x > 12) {} if (x > 13) {} if (x > 14) {} } }\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["src/ComplexService.java"], "initial");
    for i in 0..11 {
        fs::write(
            temp.path().join("src").join("ComplexService.java"),
            format!("public class ComplexService {{ void hotspot(int x) {{ int marker = {i}; if (x > 0) {{}} if (x > 1) {{}} if (x > 2) {{}} if (x > 3) {{}} if (x > 4) {{}} if (x > 5) {{}} if (x > 6) {{}} if (x > 7) {{}} if (x > 8) {{}} if (x > 9) {{}} if (x > 10) {{}} if (x > 11) {{}} if (x > 12) {{}} if (x > 13) {{}} if (x > 14) {{}} }} }}\n"),
        )
        .unwrap();
        commit_paths(&repo, &["src/ComplexService.java"], &format!("update {i}"));
    }

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "analyze_git_hotspots",
            r#"{"since_iso":"2020-01-01T00:00:00Z","max_commits":500,"max_files":75}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    let report = value["report"].as_str().expect("report string");
    assert_eq!(
        report,
        format!(
            "## Git hotspots\n\n- Repository: `{}`\n- Timeframe: since 2020-01-01T00:00:00Z\n- Analyzed commits: 12\n- Unique files (before cap): 1\n- Truncated: false\n\n| Path | Churn | Complexity | Category | Authors |\n|------|-------|------------|----------|---------|\n| `src{sep}ComplexService.java` | 12 | 16 | HOTSPOT | Test User(12) |",
            temp.path().canonicalize().unwrap().display(),
            sep = MAIN_SEPARATOR
        )
    );
}

#[test]
fn python_boundary_returns_list_symbols_json() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json("list_symbols", r#"{"file_patterns":["A.java"]}"#)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["files"][0]["path"], "A.java");
    let lines = value["files"][0]["lines"].as_array().unwrap();
    assert!(lines.iter().any(|line| line.as_str() == Some("  - AInner")));
    assert!(
        lines
            .iter()
            .any(|line| line.as_str() == Some("    - AInnerInner"))
    );
    assert!(
        lines
            .iter()
            .any(|line| line.as_str() == Some("      - method7"))
    );
}

#[test]
fn python_boundary_surfaces_invalid_params() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let err = service
        .call_tool_json("search_symbols", r#"{"patterns":1}"#)
        .unwrap_err();

    assert_eq!(err.code, SearchToolsServiceErrorCode::InvalidParams);
    assert!(err.message.contains("Invalid tool arguments"));
}

#[test]
fn python_boundary_returns_most_relevant_files_json() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("A.java"), "public class A { }\n").unwrap();
    fs::write(temp.path().join("B.java"), "public class B { }\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(std::path::Path::new("A.java")).unwrap();
    index.add_path(std::path::Path::new("B.java")).unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let signature = Signature::now("Test User", "test@example.com").unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "most_relevant_files",
            r#"{"seed_file_paths":["A.java"],"limit":5}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let files = value["files"].as_array().unwrap();
    assert!(
        files.iter().any(|item| item == "B.java"),
        "payload: {value}"
    );
    assert_eq!(0, value["not_found"].as_array().unwrap().len());
}

#[test]
fn search_symbols_limit_selects_git_important_file_then_renders_alphabetically() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("a_low.java"), "class ALow {}\n").unwrap();
    fs::write(temp.path().join("z_high.java"), "class ZHigh {}\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["a_low.java"], "add low");
    commit_paths(&repo, &["z_high.java"], "add high");
    fs::write(
        temp.path().join("z_high.java"),
        "class ZHigh { int value; }\n",
    )
    .unwrap();
    commit_paths(&repo, &["z_high.java"], "update high");

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":[".*"],"include_tests":true,"limit":1}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(true, value["truncated"]);
    let files = value["files"].as_array().unwrap();
    assert_eq!(1, files.len(), "payload: {value}");
    assert_eq!("z_high.java", files[0]["path"]);
    assert_eq!("class ZHigh", files[0]["classes"][0]["signature"]);
    assert_eq!(1, files[0]["classes"][0]["line"]);
}

#[test]
fn search_symbols_prefers_exact_match_over_hot_partial_match_file() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("BootmgrApple.java"),
        "class BootmgrApple { void ffDetectBootmgr() {} }\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("BootmgrUtility.java"),
        "class BootmgrUtility {\n    void ffDetectBootmgrFallback() {}\n}\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["BootmgrApple.java"], "add exact match");
    commit_paths(&repo, &["BootmgrUtility.java"], "add utility");
    fs::write(
        temp.path().join("BootmgrUtility.java"),
        "class BootmgrUtility {\n    void ffDetectBootmgrFallback() {}\n    void ffDetectBootmgrTelemetry() {}\n}\n",
    )
    .unwrap();
    commit_paths(&repo, &["BootmgrUtility.java"], "heat utility");

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":["ffDetectBootmgr"],"include_tests":true,"limit":1}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(true, value["truncated"]);
    let files = value["files"].as_array().unwrap();
    assert_eq!(1, files.len(), "payload: {value}");
    assert_eq!("BootmgrApple.java", files[0]["path"], "payload: {value}");
    assert_eq!(
        "void ffDetectBootmgr()",
        files[0]["functions"][0]["signature"]
    );
}

#[test]
fn get_active_workspace_returns_initial_root() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json("get_active_workspace", "{}")
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let expected = fixture_root().canonicalize().unwrap();
    assert_eq!(value["workspace_path"], expected.display().to_string());
}

#[test]
fn activate_workspace_rejects_relative_path() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let err = service
        .call_tool_json(
            "activate_workspace",
            r#"{"workspace_path":"relative/path"}"#,
        )
        .unwrap_err();

    assert_eq!(err.code, SearchToolsServiceErrorCode::InvalidParams);
    assert!(
        err.message.contains("must be absolute"),
        "unexpected message: {}",
        err.message
    );
}

#[test]
fn activate_workspace_rejects_nonexistent_path() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let err = service
        .call_tool_json(
            "activate_workspace",
            r#"{"workspace_path":"/this/path/should/not/exist/bifrost-test"}"#,
        )
        .unwrap_err();

    assert_eq!(err.code, SearchToolsServiceErrorCode::InvalidParams);
}

#[test]
fn activate_workspace_idempotent_for_same_root() {
    // Use a fresh git repo as a self-contained root so resolve_workspace_root
    // returns the same path that was passed in.
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("Same.java"), "public class Same {}\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["Same.java"], "initial");
    let same_root = temp.path().canonicalize().unwrap();

    let service = SearchToolsService::new_without_semantic_index(same_root.clone()).unwrap();
    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&same_root.display().to_string()).unwrap()
    );
    let payload = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(value["workspace_path"], same_root.display().to_string());
}

#[test]
fn activate_workspace_switches_to_new_root() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Switched.java"),
        "public class Switched {}\n",
    )
    .unwrap();
    let new_root = temp.path().canonicalize().unwrap();

    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&new_root.display().to_string()).unwrap()
    );
    let activate_payload = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap();
    let activate_value: Value = serde_json::from_str(&activate_payload).unwrap();
    assert_eq!(
        activate_value["workspace_path"],
        new_root.display().to_string()
    );

    let get_payload = service
        .call_tool_json("get_active_workspace", "{}")
        .unwrap();
    let get_value: Value = serde_json::from_str(&get_payload).unwrap();
    assert_eq!(get_value["workspace_path"], new_root.display().to_string());

    // The new workspace should index files from the new root, not the old one.
    let summary_payload = service
        .call_tool_json("list_symbols", r#"{"file_patterns":["Switched.java"]}"#)
        .unwrap();
    let summary_value: Value = serde_json::from_str(&summary_payload).unwrap();
    assert_eq!(summary_value["files"][0]["path"], "Switched.java");
}

#[test]
fn activate_workspace_failure_preserves_existing_workspace() {
    // Pointing activate at a regular file (not a directory) makes
    // FilesystemProject::new reject the path. The existing workspace must
    // still answer queries afterwards.
    let temp = TempDir::new().unwrap();
    let bad_path = temp.path().join("not_a_dir.txt");
    fs::write(&bad_path, "not a directory").unwrap();
    let bad_path = bad_path.canonicalize().unwrap();

    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();

    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&bad_path.display().to_string()).unwrap()
    );
    let err = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap_err();
    assert_eq!(err.code, SearchToolsServiceErrorCode::InvalidParams);

    // Original workspace must remain queryable.
    let active_payload = service
        .call_tool_json("get_active_workspace", "{}")
        .unwrap();
    let active_value: Value = serde_json::from_str(&active_payload).unwrap();
    let expected = fixture_root().canonicalize().unwrap();
    assert_eq!(
        active_value["workspace_path"],
        expected.display().to_string()
    );

    let summary_payload = service
        .call_tool_json("get_summaries", r#"{"targets":["A.java"]}"#)
        .unwrap();
    let summary_value: Value = serde_json::from_str(&summary_payload).unwrap();
    assert_eq!(summary_value["summaries"][0]["path"], "A.java");
}

#[test]
fn scan_usages_returns_call_sites_grouped_by_file() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["E.iMethod"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let usages = value["usages"].as_array().unwrap();
    assert_eq!(1, usages.len(), "payload: {value}");
    assert_eq!("E.iMethod", usages[0]["symbol"]);
    assert!(
        usages[0]["total_hits"].as_u64().unwrap() >= 1,
        "expected >=1 hit, payload: {value}"
    );
    assert!(
        usages[0]["candidate_files_truncated"].is_null(),
        "candidate_files_truncated should be omitted when false: {value}"
    );

    let files = usages[0]["files"].as_array().unwrap();
    let use_e = files
        .iter()
        .find(|file| file["path"] == "UseE.java")
        .unwrap_or_else(|| panic!("expected UseE.java in files: {value}"));
    let hits = use_e["hits"].as_array().unwrap();
    assert!(
        hits.iter().any(|hit| hit["snippet"]
            .as_str()
            .unwrap_or_default()
            .contains("e.iMethod()")),
        "expected snippet to contain `e.iMethod()`: {value}"
    );

    assert_eq!(0, array_len(&value, "not_found"));
    assert_eq!(0, array_len(&value, "ambiguous"));
    assert_eq!(0, array_len(&value, "fallbacks"));
    assert_eq!(0, array_len(&value, "failures"));
    assert_eq!(0, array_len(&value, "too_many_callsites"));
}

#[test]
fn scan_usages_reports_unknown_symbol_as_not_found() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["does.not.Exist"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, array_len(&value, "usages"));
    let not_found = value["not_found"].as_array().unwrap();
    assert_eq!(1, not_found.len());
    assert_eq!("does.not.Exist", not_found[0]);
    assert_eq!(0, array_len(&value, "fallbacks"));
    assert_eq!(0, array_len(&value, "failures"));
}

#[test]
fn scan_usages_reports_graph_fallback_reason() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("Domain")).unwrap();
    fs::write(
        temp.path().join("Domain").join("Target.cs"),
        r#"
namespace Domain {
    public class Target {
        public void Run() {}
        public void Execute() {
            Run();
        }
    }
}
"#,
    )
    .unwrap();
    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["Domain.Target.Run"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(
        1,
        value["usages"].as_array().unwrap().len(),
        "payload: {value}"
    );
    let fallbacks = value["fallbacks"].as_array().unwrap();
    assert_eq!(1, fallbacks.len(), "payload: {value}");
    assert_eq!("Domain.Target.Run", fallbacks[0]["symbol"]);
    assert_eq!("CSharpUsageGraphStrategy", fallbacks[0]["strategy"]);
    assert_eq!("unsafe_inference", fallbacks[0]["reason_kind"]);
    assert_eq!("regex", fallbacks[0]["fallback_policy"]);
    assert_eq!(0, array_len(&value, "not_found"));
    assert_eq!(0, array_len(&value, "failures"));
}

#[test]
fn scan_usages_skips_blank_symbols_without_error() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["", "   "],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(0, array_len(&value, "usages"));
    assert_eq!(0, array_len(&value, "not_found"));
    assert_eq!(0, array_len(&value, "fallbacks"));
    assert_eq!(0, array_len(&value, "failures"));
}

#[test]
fn scan_usages_excludes_test_files_when_include_tests_is_false() {
    // Two callers of `Greeter.hello`: one in production code, one in a JUnit test
    // file. With include_tests=false, the test caller must be filtered before the
    // regex scan so that test hits do not eat into DEFAULT_MAX_USAGES and do not
    // appear in the result. With include_tests=true, both callers must show up.
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Greeter.java"),
        "public class Greeter {\n    public String hello() { return \"hi\"; }\n}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("ProdCaller.java"),
        "public class ProdCaller {\n    public String run() { return new Greeter().hello(); }\n}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("GreeterTest.java"),
        "import org.junit.Test;\npublic class GreeterTest {\n    @Test\n    public void greets() { new Greeter().hello(); }\n}\n",
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();

    let production_only = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["Greeter.hello"],"include_tests":false}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&production_only).unwrap();
    let usages = value["usages"].as_array().unwrap();
    assert_eq!(1, usages.len(), "payload: {value}");
    let files = usages[0]["files"].as_array().unwrap();
    let paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert!(
        paths.contains(&"ProdCaller.java"),
        "ProdCaller.java should be in results: {value}"
    );
    assert!(
        !paths.contains(&"GreeterTest.java"),
        "GreeterTest.java must be filtered when include_tests=false: {value}"
    );

    let with_tests = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["Greeter.hello"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&with_tests).unwrap();
    let files = value["usages"][0]["files"].as_array().unwrap();
    let paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert!(
        paths.contains(&"ProdCaller.java"),
        "ProdCaller.java missing with include_tests=true: {value}"
    );
    assert!(
        paths.contains(&"GreeterTest.java"),
        "GreeterTest.java missing with include_tests=true: {value}"
    );
}

#[test]
fn scan_usages_paths_filter_limits_candidate_files() {
    let temp = TempDir::new().unwrap();
    fs::create_dir_all(temp.path().join("nested")).unwrap();
    fs::write(
        temp.path().join("Greeter.java"),
        "public class Greeter {\n    public String hello() { return \"hi\"; }\n}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("ProdCaller.java"),
        "public class ProdCaller {\n    public String run() { return new Greeter().hello(); }\n}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("nested").join("NestedCaller.java"),
        "public class NestedCaller {\n    public String run() { return new Greeter().hello(); }\n}\n",
    )
    .unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["Greeter.hello"],"include_tests":true,"paths":["nested/*.java"]}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let files = value["usages"][0]["files"].as_array().unwrap();
    let paths: Vec<&str> = files
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    assert_eq!(vec!["nested/NestedCaller.java"], paths, "payload: {value}");
}

#[test]
fn scan_usages_demotes_large_result_to_summary_within_budget() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Target.java"),
        "public class Target {\n    public void hit() {}\n}\n",
    )
    .unwrap();
    for idx in 0..150 {
        fs::write(
            temp.path().join(format!("Caller{idx}.java")),
            format!(
                "public class Caller{idx} {{\n    public void run() {{ new Target().hit(); }}\n}}\n"
            ),
        )
        .unwrap();
    }

    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["Target.hit"],"include_tests":true}"#,
        )
        .unwrap();
    assert!(
        payload.len() <= 8_192,
        "payload should stay within scan_usages budget, got {} bytes",
        payload.len()
    );

    let value: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(1, value["summary"]["requested_symbols"].as_u64().unwrap());
    assert_eq!(1, value["summary"]["resolved_symbols"].as_u64().unwrap());
    assert_eq!(150, value["summary"]["total_hits"].as_u64().unwrap());
    assert_eq!(
        "scan_usages",
        value["summary"]["recommended_next_call"]["tool"]
            .as_str()
            .unwrap()
    );
    let usage = &value["usages"][0];
    assert_eq!("summary", usage["rendering"]);
    assert_eq!(150, usage["total_hits"].as_u64().unwrap());
    assert!(
        usage["top_enclosing"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "payload: {value}"
    );
}

#[test]
fn scan_usages_resolved_symbol_with_no_hits_is_emitted_with_zero_total() {
    // method7 lives on A.AInner.AInnerInner and has no callers in the fixture.
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let payload = service
        .call_tool_json(
            "scan_usages",
            r#"{"symbols":["A.AInner.AInnerInner.method7"],"include_tests":true}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let usages = value["usages"].as_array().unwrap();
    assert_eq!(1, usages.len(), "payload: {value}");
    assert_eq!("A.AInner.AInnerInner.method7", usages[0]["symbol"]);
    assert_eq!(0, usages[0]["total_hits"].as_u64().unwrap());
    assert_eq!(0, array_len(&usages[0], "files"));
    assert_eq!(0, array_len(&value, "not_found"));
    assert_eq!(0, array_len(&value, "fallbacks"));
    assert_eq!(0, array_len(&value, "failures"));
}

#[test]
fn activate_workspace_normalizes_to_git_root() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("Top.java"), "public class Top {}\n").unwrap();
    fs::create_dir_all(temp.path().join("nested")).unwrap();
    fs::write(
        temp.path().join("nested").join("Inner.java"),
        "public class Inner {}\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["Top.java", "nested/Inner.java"], "initial");

    let repo_root = temp.path().canonicalize().unwrap();
    let nested = repo_root.join("nested");

    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&nested.display().to_string()).unwrap()
    );
    let payload = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["workspace_path"], repo_root.display().to_string());
}

#[test]
fn service_initializes_generated_large_workspace_with_deep_java_shape() {
    let temp = generated_java_workspace(1_000, 256, false);
    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":["DeepRoot"],"include_tests":true,"limit":5}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    assert!(
        value["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "DeepRoot.java"),
        "payload: {value}"
    );
}

#[test]
#[ignore = "expensive 10k-file smoke test for issue #175"]
fn service_initializes_ten_thousand_tracked_java_files_without_stack_overflow() {
    let temp = generated_java_workspace(10_000, 512, true);
    let service =
        SearchToolsService::new_without_semantic_index(temp.path().to_path_buf()).unwrap();

    let payload = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":["Generated9999"],"include_tests":true,"limit":5}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    assert!(
        value["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "Generated9999.java"),
        "payload: {value}"
    );
}

fn generated_java_workspace(file_count: usize, nested_depth: usize, tracked: bool) -> TempDir {
    let temp = TempDir::new().unwrap();
    let mut paths = Vec::with_capacity(file_count + 1);

    let deep_path = temp.path().join("DeepRoot.java");
    fs::write(&deep_path, deep_java_source(nested_depth)).unwrap();
    paths.push(PathBuf::from("DeepRoot.java"));

    for index in 0..file_count {
        let rel = PathBuf::from(format!("Generated{index}.java"));
        fs::write(
            temp.path().join(&rel),
            format!("public class Generated{index} {{ int value() {{ return {index}; }} }}\n"),
        )
        .unwrap();
        paths.push(rel);
    }

    if tracked {
        let repo = Repository::init(temp.path()).unwrap();
        let mut index = repo.index().unwrap();
        for path in &paths {
            index.add_path(path).unwrap();
        }
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let signature = Signature::now("Test User", "test@example.com").unwrap();
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "generated",
            &tree,
            &[],
        )
        .unwrap();
    }

    temp
}

fn deep_java_source(depth: usize) -> String {
    let mut source = String::from("public class DeepRoot {\n");
    for index in 0..depth {
        source.push_str(&format!("static class Nested{index} {{\n"));
    }
    source.push_str("int value() { return 1; }\n");
    for _ in 0..depth {
        source.push_str("}\n");
    }
    source.push_str("}\n");
    source
}

fn commit_paths(repo: &Repository, paths: &[&str], message: &str) {
    let mut index = repo.index().unwrap();
    for path in paths {
        index.add_path(std::path::Path::new(path)).unwrap();
    }
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let signature = Signature::now("Test User", "test@example.com").unwrap();
    let parent = repo
        .head()
        .ok()
        .and_then(|head| head.target())
        .and_then(|oid| repo.find_commit(oid).ok());
    let parents = parent.iter().collect::<Vec<_>>();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &parents,
    )
    .unwrap();
}

#[test]
fn semantic_search_reports_disabled_without_indexer() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let err = service
        .call_tool_value(
            "semantic_search",
            serde_json::json!({ "query": "anything", "k": 1 }),
        )
        .expect_err("semantic_search must fail without an indexer");
    assert!(
        err.message.contains("disabled") || err.message.contains("not available"),
        "unexpected error message: {}",
        err.message
    );
}

#[test]
fn semantic_search_status_reports_disabled_without_indexer() {
    let service = SearchToolsService::new_without_semantic_index(fixture_root()).unwrap();
    let err = service
        .call_tool_value("semantic_search_status", serde_json::json!({}))
        .expect_err("semantic_search_status must fail without an indexer");
    assert!(
        err.message.contains("disabled") || err.message.contains("not available"),
        "unexpected error message: {}",
        err.message
    );
}
