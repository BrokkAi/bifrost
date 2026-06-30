use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use glob::Pattern;
use lsp_types::{DocumentFormattingParams, TextEdit};
use serde::Deserialize;

use crate::analyzer::common::language_for_file;
use crate::analyzer::{Language, Project, ProjectFile, Range as ByteRange};
use crate::lsp::conversion::byte_range_to_lsp_range;
use crate::lsp::handlers::util::read_document_for_uri;

const MAX_ERROR_OUTPUT_CHARS: usize = 1_000;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FormatterCommandRule {
    #[serde(default)]
    pub(crate) include: Vec<String>,
    #[serde(default)]
    pub(crate) exclude: Vec<String>,
    pub(crate) language: Option<String>,
    pub(crate) command: String,
    #[serde(default)]
    pub(crate) args: Vec<String>,
    pub(crate) cwd: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FormatterCommand {
    pub(crate) command: String,
    pub(crate) args: Vec<String>,
    pub(crate) cwd: PathBuf,
}

struct FormatContext<'a> {
    project: &'a dyn Project,
    file: &'a ProjectFile,
    language: Language,
}

pub(crate) fn handle(
    project: &dyn Project,
    params: &DocumentFormattingParams,
    rules: &[FormatterCommandRule],
) -> Result<Option<Vec<TextEdit>>, String> {
    let Some((file, content, line_starts)) =
        read_document_for_uri(project, &params.text_document.uri)
    else {
        return Ok(None);
    };
    let language = language_for_file(&file);
    if language == Language::None {
        return Ok(None);
    }
    let context = FormatContext {
        project,
        file: &file,
        language,
    };
    let Some(command) = resolve_formatter_command(&context, rules)? else {
        return Ok(None);
    };
    let formatted = run_formatter_command(&command, &content)?;
    if formatted == content {
        return Ok(Some(Vec::new()));
    }
    let range = byte_range_to_lsp_range(
        &content,
        &line_starts,
        &ByteRange {
            start_byte: 0,
            end_byte: content.len(),
            start_line: 0,
            end_line: line_starts.len().saturating_sub(1),
        },
    );
    Ok(Some(vec![TextEdit::new(range, formatted)]))
}

fn resolve_formatter_command(
    context: &FormatContext<'_>,
    rules: &[FormatterCommandRule],
) -> Result<Option<FormatterCommand>, String> {
    for rule in rules {
        if rule_matches(rule, context) {
            return formatter_command_from_rule(rule, context).map(Some);
        }
    }
    Ok(discover_builtin_formatter(context))
}

fn formatter_command_from_rule(
    rule: &FormatterCommandRule,
    context: &FormatContext<'_>,
) -> Result<FormatterCommand, String> {
    let command = rule.command.trim();
    if command.is_empty() {
        return Err(format!(
            "formatter rule for {} has an empty command",
            context.file.rel_path().display()
        ));
    }
    let cwd = rule
        .cwd
        .as_ref()
        .map(|cwd| expand_placeholders(cwd, context))
        .map(|cwd| resolve_cwd(&cwd, context.project.root()))
        .unwrap_or_else(|| context.project.root().to_path_buf());
    let args = rule
        .args
        .iter()
        .map(|arg| expand_placeholders(arg, context))
        .collect();
    Ok(FormatterCommand {
        command: command.to_string(),
        args,
        cwd,
    })
}

fn rule_matches(rule: &FormatterCommandRule, context: &FormatContext<'_>) -> bool {
    if let Some(language) = rule.language.as_deref()
        && parse_language(language) != Some(context.language)
    {
        return false;
    }
    let rel = normalized_rel_path(context.file);
    if !rule.include.is_empty()
        && !rule
            .include
            .iter()
            .any(|pattern| glob_matches(pattern, &rel))
    {
        return false;
    }
    !rule
        .exclude
        .iter()
        .any(|pattern| glob_matches(pattern, &rel))
}

fn discover_builtin_formatter(context: &FormatContext<'_>) -> Option<FormatterCommand> {
    match context.language {
        Language::Rust => Some(standard_command(context, "rustfmt", ["--emit", "stdout"])),
        Language::Go => Some(standard_command(context, "gofmt", [])),
        Language::Cpp => Some(standard_command(
            context,
            "clang-format",
            ["--assume-filename", "{file}"],
        )),
        Language::Python => Some(standard_command(
            context,
            "black",
            ["--quiet", "--stdin-filename", "{file}", "-"],
        )),
        Language::JavaScript | Language::TypeScript => discover_package_script(context),
        Language::Java
        | Language::Php
        | Language::Scala
        | Language::CSharp
        | Language::Ruby
        | Language::None => None,
    }
}

fn standard_command<const N: usize>(
    context: &FormatContext<'_>,
    command: &str,
    args: [&str; N],
) -> FormatterCommand {
    FormatterCommand {
        command: command.to_string(),
        args: args
            .into_iter()
            .map(|arg| expand_placeholders(arg, context))
            .collect(),
        cwd: context.project.root().to_path_buf(),
    }
}

fn discover_package_script(context: &FormatContext<'_>) -> Option<FormatterCommand> {
    let package_json = nearest_manifest(context.file.abs_path().parent()?, "package.json")?;
    let package_root = package_json.parent()?.to_path_buf();
    let raw = std::fs::read_to_string(&package_json).ok()?;
    let json: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let scripts = json.get("scripts")?.as_object()?;
    let script_name = [
        "format:stdin",
        "format-stdin",
        "format:document",
        "format-document",
    ]
    .into_iter()
    .find(|name| scripts.get(*name).and_then(|value| value.as_str()).is_some())?;
    Some(FormatterCommand {
        command: "npm".to_string(),
        args: vec!["run".to_string(), script_name.to_string(), "--".to_string()],
        cwd: package_root,
    })
}

fn nearest_manifest(start: &Path, name: &str) -> Option<PathBuf> {
    for dir in start.ancestors() {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn run_formatter_command(command: &FormatterCommand, input: &str) -> Result<String, String> {
    let mut child = Command::new(&command.command)
        .args(&command.args)
        .current_dir(&command.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            format!(
                "failed to start formatter `{}` in {}: {err}",
                command_line_for_message(command),
                command.cwd.display()
            )
        })?;
    {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            format!(
                "failed to open stdin for formatter `{}`",
                command_line_for_message(command)
            )
        })?;
        stdin.write_all(input.as_bytes()).map_err(|err| {
            format!(
                "failed to write document to formatter `{}`: {err}",
                command_line_for_message(command)
            )
        })?;
    }
    let output = child.wait_with_output().map_err(|err| {
        format!(
            "failed to wait for formatter `{}`: {err}",
            command_line_for_message(command)
        )
    })?;
    if !output.status.success() {
        return Err(format!(
            "formatter `{}` exited with status {}: {}",
            command_line_for_message(command),
            output.status,
            truncate_for_error(&String::from_utf8_lossy(&output.stderr))
        ));
    }
    String::from_utf8(output.stdout).map_err(|err| {
        format!(
            "formatter `{}` emitted non-UTF-8 stdout: {err}",
            command_line_for_message(command)
        )
    })
}

fn parse_language(input: &str) -> Option<Language> {
    let normalized = input
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase()
        .replace(['_', '-'], "");
    match normalized.as_str() {
        "java" => Some(Language::Java),
        "go" => Some(Language::Go),
        "c" | "cc" | "cpp" | "cxx" | "c++" => Some(Language::Cpp),
        "javascript" | "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
        "typescript" | "ts" | "tsx" => Some(Language::TypeScript),
        "python" | "py" => Some(Language::Python),
        "rust" | "rs" => Some(Language::Rust),
        "php" => Some(Language::Php),
        "scala" => Some(Language::Scala),
        "csharp" | "c#" | "cs" => Some(Language::CSharp),
        "ruby" | "rb" => Some(Language::Ruby),
        _ => None,
    }
}

fn expand_placeholders(value: &str, context: &FormatContext<'_>) -> String {
    value
        .replace("{file}", &context.file.abs_path().display().to_string())
        .replace(
            "{relativeFile}",
            &context.file.rel_path().to_string_lossy().replace('\\', "/"),
        )
        .replace(
            "{workspaceRoot}",
            &context.project.root().display().to_string(),
        )
        .replace("{language}", language_label(context.language))
}

fn resolve_cwd(value: &str, workspace_root: &Path) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        workspace_root.join(path)
    }
}

fn glob_matches(pattern: &str, rel: &str) -> bool {
    Pattern::new(pattern)
        .map(|pattern| pattern.matches(rel))
        .unwrap_or(false)
}

fn normalized_rel_path(file: &ProjectFile) -> String {
    file.rel_path().to_string_lossy().replace('\\', "/")
}

fn language_label(language: Language) -> &'static str {
    match language {
        Language::None => "none",
        Language::Java => "java",
        Language::Go => "go",
        Language::Cpp => "cpp",
        Language::JavaScript => "javascript",
        Language::TypeScript => "typescript",
        Language::Python => "python",
        Language::Rust => "rust",
        Language::Php => "php",
        Language::Scala => "scala",
        Language::CSharp => "csharp",
        Language::Ruby => "ruby",
    }
}

fn command_line_for_message(command: &FormatterCommand) -> String {
    std::iter::once(command.command.as_str())
        .chain(command.args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate_for_error(value: &str) -> String {
    let trimmed = value.trim();
    let mut out = String::new();
    for (idx, ch) in trimmed.chars().enumerate() {
        if idx >= MAX_ERROR_OUTPUT_CHARS {
            out.push_str("...");
            return out;
        }
        out.push(ch);
    }
    out
}

#[cfg(all(test, unix))]
fn stub_command(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, body).expect("write stub command");
    let mut permissions = std::fs::metadata(path)
        .expect("stub metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("chmod stub");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{FilesystemProject, Project};

    fn project(root: &Path) -> FilesystemProject {
        FilesystemProject::new(root).expect("filesystem project")
    }

    fn project_file(project: &dyn Project, rel_path: &str) -> ProjectFile {
        project
            .file_by_rel_path(Path::new(rel_path))
            .expect("project file")
    }

    #[test]
    fn formatter_rule_matches_language_include_and_exclude() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("src/generated")).unwrap();
        std::fs::write(root.join("src/app.ts"), "let x=1;").unwrap();
        std::fs::write(root.join("src/generated/app.ts"), "let x=1;").unwrap();
        let project = project(&root);
        let file = project_file(&project, "src/app.ts");
        let ctx = FormatContext {
            project: &project,
            file: &file,
            language: Language::TypeScript,
        };
        let rule = FormatterCommandRule {
            include: vec!["src/**/*.ts".to_string()],
            exclude: vec!["src/generated/**".to_string()],
            language: Some("typescript".to_string()),
            command: "fmt".to_string(),
            args: Vec::new(),
            cwd: None,
        };
        assert!(rule_matches(&rule, &ctx));

        let generated_file = project_file(&project, "src/generated/app.ts");
        let generated_ctx = FormatContext {
            project: &project,
            file: &generated_file,
            language: Language::TypeScript,
        };
        assert!(!rule_matches(&rule, &generated_ctx));
    }

    #[test]
    fn formatter_rule_expands_args_and_cwd_placeholders() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("pkg/src")).unwrap();
        std::fs::write(root.join("pkg/src/lib.rs"), "fn main(){}").unwrap();
        let project = project(&root);
        let file = project_file(&project, "pkg/src/lib.rs");
        let ctx = FormatContext {
            project: &project,
            file: &file,
            language: Language::Rust,
        };
        let rule = FormatterCommandRule {
            include: Vec::new(),
            exclude: Vec::new(),
            language: None,
            command: "rustfmt".to_string(),
            args: vec![
                "--stdin-filename".to_string(),
                "{file}".to_string(),
                "{relativeFile}".to_string(),
                "{language}".to_string(),
            ],
            cwd: Some("{workspaceRoot}/pkg".to_string()),
        };
        let command = formatter_command_from_rule(&rule, &ctx).unwrap();
        assert_eq!(command.command, "rustfmt");
        assert_eq!(
            command.args,
            vec![
                "--stdin-filename",
            &root.join("pkg/src/lib.rs").display().to_string(),
                "pkg/src/lib.rs",
                "rust",
            ]
        );
        assert_eq!(command.cwd, root.join("pkg"));
    }

    #[test]
    fn configured_rule_wins_before_builtin_formatter() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("main.go"), "package main\n").unwrap();
        let project = project(&root);
        let file = project_file(&project, "main.go");
        let ctx = FormatContext {
            project: &project,
            file: &file,
            language: Language::Go,
        };
        let rules = vec![FormatterCommandRule {
            include: vec!["*.go".to_string()],
            exclude: Vec::new(),
            language: Some("go".to_string()),
            command: "custom-gofmt".to_string(),
            args: Vec::new(),
            cwd: None,
        }];
        let command = resolve_formatter_command(&ctx, &rules).unwrap().unwrap();
        assert_eq!(command.command, "custom-gofmt");
    }

    #[test]
    fn builtin_formatter_uses_standard_stdout_commands() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("lib.rs"), "fn main(){}").unwrap();
        let project = project(&root);
        let file = project_file(&project, "lib.rs");
        let ctx = FormatContext {
            project: &project,
            file: &file,
            language: Language::Rust,
        };
        let command = discover_builtin_formatter(&ctx).unwrap();
        assert_eq!(command.command, "rustfmt");
        assert_eq!(command.args, vec!["--emit", "stdout"]);
        assert_eq!(command.cwd, root);
    }

    #[test]
    fn package_script_discovery_requires_explicit_stdin_script() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("web/src")).unwrap();
        std::fs::write(
            root.join("web/package.json"),
            r#"{"scripts":{"format:stdin":"prettier --stdin-filepath src/app.ts"}}"#,
        )
        .unwrap();
        std::fs::write(root.join("web/src/app.ts"), "const x=1;").unwrap();
        let project = project(&root);
        let file = project_file(&project, "web/src/app.ts");
        let ctx = FormatContext {
            project: &project,
            file: &file,
            language: Language::TypeScript,
        };
        let command = discover_builtin_formatter(&ctx).unwrap();
        assert_eq!(command.command, "npm");
        assert_eq!(command.args, vec!["run", "format:stdin", "--"]);
        assert_eq!(command.cwd, root.join("web"));
    }

    #[test]
    fn ambiguous_languages_require_override_rules() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("main.rb"), "puts 'hi'\n").unwrap();
        let project = project(&root);
        let file = project_file(&project, "main.rb");
        let ctx = FormatContext {
            project: &project,
            file: &file,
            language: Language::Ruby,
        };
        assert!(discover_builtin_formatter(&ctx).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn formatter_executor_passes_stdin_and_returns_stdout() {
        let temp = tempfile::tempdir().unwrap();
        let stub = temp.path().join("stub-format");
        stub_command(&stub, "#!/bin/sh\ntr '[:lower:]' '[:upper:]'\n");
        let command = FormatterCommand {
            command: stub.display().to_string(),
            args: Vec::new(),
            cwd: temp.path().to_path_buf(),
        };
        let output = run_formatter_command(&command, "hello\n").unwrap();
        assert_eq!(output, "HELLO\n");
    }

    #[cfg(unix)]
    #[test]
    fn formatter_executor_reports_failure_stderr() {
        let temp = tempfile::tempdir().unwrap();
        let stub = temp.path().join("stub-fail");
        stub_command(&stub, "#!/bin/sh\necho nope >&2\nexit 7\n");
        let command = FormatterCommand {
            command: stub.display().to_string(),
            args: Vec::new(),
            cwd: temp.path().to_path_buf(),
        };
        let error = run_formatter_command(&command, "hello\n").unwrap_err();
        assert!(error.contains("exited with status"), "{error}");
        assert!(error.contains("nope"), "{error}");
    }

    #[test]
    #[ignore = "requires BIFROST_FORMATTER_INTEGRATION_TESTS=1 and rustfmt on PATH"]
    fn formatter_integration_rustfmt_stdout_contract() {
        if std::env::var("BIFROST_FORMATTER_INTEGRATION_TESTS").ok().as_deref() != Some("1") {
            eprintln!("set BIFROST_FORMATTER_INTEGRATION_TESTS=1 to run real formatter tests");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let command = FormatterCommand {
            command: "rustfmt".to_string(),
            args: vec!["--emit".to_string(), "stdout".to_string()],
            cwd: temp.path().to_path_buf(),
        };
        let output = run_formatter_command(&command, "fn main(){println!(\"hi\");}\n").unwrap();
        assert!(output.contains("fn main()"), "{output}");
        assert!(output.contains("println!"), "{output}");
    }
}
