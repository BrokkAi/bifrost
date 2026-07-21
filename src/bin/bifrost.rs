use std::env;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[path = "bifrost/code_query_repl.rs"]
mod code_query_repl;

use brokk_bifrost::ToolOutput;
use brokk_bifrost::lsp::run_lsp_stdio_server;
use brokk_bifrost::mcp_common::{McpRenderOptions, run_stdio_server};
use brokk_bifrost::mcp_registry::{
    resolve_server_spec, resolve_server_spec_for_render_options, searchtools_toolset_order,
};
use brokk_bifrost::policy::{
    HumanRenderColor, HumanRenderDetail, HumanRenderOptions, POLICY_EXIT_UNRELIABLE,
    PolicyBatchOutcome, PolicyFailOn, PolicyRenderError, PolicyReportDocument, SarifToolIdentity,
    escape_terminal_text, evaluate_policy_files, write_policy_human, write_policy_json,
    write_policy_sarif,
};
use brokk_bifrost::scoped_project::create_cli_tool_service;
use brokk_bifrost::searchtools_render::RenderOptions;
use brokk_bifrost::skill_install::{
    InstallMode, InstallSkillsOptions, InstallTarget, SkillSet, install_skills,
};
use brokk_bifrost::tool_arguments::normalize_tool_arguments_for_cli;
use code_query_repl::run_code_query_repl;
use serde_json::{Value, json};
use tempfile::NamedTempFile;

enum CliRunResult {
    Complete,
    PolicyStatus(u8),
}

struct CliRunError {
    message: String,
    policy_invocation: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyOutputFormat {
    Human,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyColorMode {
    Auto,
    Always,
    Never,
}

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(CliRunResult::Complete) => ExitCode::SUCCESS,
        Ok(CliRunResult::PolicyStatus(status)) => ExitCode::from(status),
        Err(err) => {
            eprintln!("{}", escape_terminal_text(&err.message));
            if err.policy_invocation {
                ExitCode::from(POLICY_EXIT_UNRELIABLE)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run(args: impl Iterator<Item = String>) -> Result<CliRunResult, CliRunError> {
    let args = args.collect::<Vec<_>>();
    let policy_invocation = has_policy_syntax(&args);
    run_inner(args.into_iter(), policy_invocation).map_err(|message| CliRunError {
        message,
        policy_invocation,
    })
}

fn has_policy_syntax(args: &[String]) -> bool {
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        if matches!(
            argument,
            "--policy-file"
                | "--format"
                | "--fail-on"
                | "--output"
                | "--color"
                | "--verbose"
                | "--require-explicit-schema-versions"
        ) {
            return true;
        }

        index += 1;
        if option_requires_value(argument) && index < args.len() {
            index += 1;
        }
    }
    false
}

fn option_requires_value(argument: &str) -> bool {
    matches!(
        argument,
        "--root"
            | "--mcp"
            | "--target"
            | "--skills-root"
            | "--mode"
            | "--skill-set"
            | "--server"
            | "--tool"
            | "--args"
            | "--query-file"
            | "--sources"
            | "--policy-file"
            | "--format"
            | "--fail-on"
            | "--output"
            | "--color"
    )
}

fn run_inner(
    mut args: impl Iterator<Item = String>,
    policy_invocation: bool,
) -> Result<CliRunResult, String> {
    let mut root =
        env::current_dir().map_err(|err| format!("Failed to get current directory: {err}"))?;
    let mut root_explicit = false;
    let mut mcp_mode: Option<String> = None;
    let mut run_lsp = false;
    let mut run_repl = false;
    let mut run_skill_install = false;
    let mut install_option_seen = false;
    let mut install_target: Option<InstallTarget> = None;
    let mut skills_root: Option<PathBuf> = None;
    let mut install_mode = InstallMode::Auto;
    let mut skill_set = SkillSet::Code;
    let mut force_install = false;
    let mut dry_run_install = false;
    let mut tool_name: Option<String> = None;
    let mut tool_args = json!({});
    let mut tool_args_seen = false;
    let mut tool_sources = Vec::new();
    let mut query_file: Option<String> = None;
    let mut render_options = McpRenderOptions::default();
    let mut no_line_numbers_seen = false;
    let mut force_semantic_cpu_seen = false;
    let mut policy_files = Vec::new();
    let mut policy_format = PolicyOutputFormat::Human;
    let mut policy_format_seen = false;
    let mut policy_fail_on = PolicyFailOn::Warning;
    let mut policy_fail_on_seen = false;
    let mut policy_output: Option<PathBuf> = None;
    let mut policy_verbose = false;
    let mut policy_verbose_seen = false;
    let mut policy_color = PolicyColorMode::Auto;
    let mut policy_color_seen = false;
    let mut require_explicit_schema_versions = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--root requires a path".to_string())?;
                root = value.into();
                root_explicit = true;
            }
            "--mcp" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--mcp requires a toolset expression".to_string())?;
                mcp_mode = Some(value);
            }
            "--lsp" => {
                run_lsp = true;
            }
            "--repl" => {
                run_repl = true;
            }
            "--install-skills" => {
                run_skill_install = true;
            }
            "--target" => {
                install_option_seen = true;
                let value = args
                    .next()
                    .ok_or_else(|| "--target requires project or global".to_string())?;
                install_target = Some(parse_install_target(&value)?);
            }
            "--skills-root" => {
                install_option_seen = true;
                let value = args
                    .next()
                    .ok_or_else(|| "--skills-root requires a directory".to_string())?;
                skills_root = Some(value.into());
            }
            "--mode" => {
                install_option_seen = true;
                let value = args
                    .next()
                    .ok_or_else(|| "--mode requires auto, symlink, or copy".to_string())?;
                install_mode = parse_install_mode(&value)?;
            }
            "--skill-set" => {
                install_option_seen = true;
                let value = args
                    .next()
                    .ok_or_else(|| "--skill-set requires code or all".to_string())?;
                skill_set = parse_skill_set(&value)?;
            }
            "--force" => {
                install_option_seen = true;
                force_install = true;
            }
            "--dry-run" => {
                install_option_seen = true;
                dry_run_install = true;
            }
            // DEPRECATED: superseded by `--mcp <toolsets>` and `--lsp`. Kept as a
            // backwards-compatible alias and intentionally undocumented in --help.
            // `--server lsp` maps to `--lsp`; any other value maps to `--mcp <value>`.
            "--server" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--server requires a mode".to_string())?;
                eprintln!("bifrost: --server is deprecated; use --mcp <toolsets> or --lsp");
                if value == "lsp" {
                    run_lsp = true;
                } else {
                    mcp_mode = Some(value);
                }
            }
            "--tool" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--tool requires a name".to_string())?;
                if tool_name.replace(value).is_some() {
                    return Err("--tool may only be provided once".to_string());
                }
            }
            "--args" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--args requires inline JSON".to_string())?;
                tool_args = serde_json::from_str(&value)
                    .map_err(|err| format!("--args must be valid JSON: {err}"))?;
                tool_args_seen = true;
            }
            "--query-file" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--query-file requires a path".to_string())?;
                if query_file.replace(value).is_some() {
                    return Err("--query-file may only be provided once".to_string());
                }
            }
            "--sources" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--sources requires a path".to_string())?;
                tool_sources.push(value);
            }
            "--policy-file" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--policy-file requires a path".to_string())?;
                policy_files.push(PathBuf::from(value));
            }
            "--format" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--format requires human, json, or sarif".to_string())?;
                if policy_format_seen {
                    return Err("--format may only be provided once".to_string());
                }
                policy_format = parse_policy_format(&value)?;
                policy_format_seen = true;
            }
            "--fail-on" => {
                let value = args.next().ok_or_else(|| {
                    "--fail-on requires never, finding, note, warning, or error".to_string()
                })?;
                if policy_fail_on_seen {
                    return Err("--fail-on may only be provided once".to_string());
                }
                policy_fail_on = parse_policy_fail_on(&value)?;
                policy_fail_on_seen = true;
            }
            "--output" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--output requires a path".to_string())?;
                if policy_output.replace(PathBuf::from(value)).is_some() {
                    return Err("--output may only be provided once".to_string());
                }
            }
            "--verbose" => {
                if policy_verbose_seen {
                    return Err("--verbose may only be provided once".to_string());
                }
                policy_verbose = true;
                policy_verbose_seen = true;
            }
            "--color" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--color requires auto, always, or never".to_string())?;
                if policy_color_seen {
                    return Err("--color may only be provided once".to_string());
                }
                policy_color = parse_policy_color(&value)?;
                policy_color_seen = true;
            }
            "--require-explicit-schema-versions" => {
                require_explicit_schema_versions = true;
            }
            "--no-line-numbers" => {
                no_line_numbers_seen = true;
                render_options.render_line_numbers = false;
            }
            "--force-semantic-cpu" => {
                force_semantic_cpu_seen = true;
                // Lets semantic_search run (and be advertised) on hosts without a
                // CUDA/Metal accelerator. Consumed via env by the registry + service.
                unsafe { env::set_var("BIFROST_FORCE_SEMANTIC_CPU", "1") };
            }
            "--help" | "-h" => {
                // Optional positional topic: `--help <tool>` shows that tool's
                // description and parameters. Ignore a following flag.
                let topic = args.next().filter(|a| !a.starts_with('-'));
                return print_help(topic.as_deref()).map(|()| CliRunResult::Complete);
            }
            "--version" | "-V" => {
                println!("bifrost {}", env!("CARGO_PKG_VERSION"));
                return Ok(CliRunResult::Complete);
            }
            other => {
                return Err(format!("Unknown argument: {other}"));
            }
        }
    }

    if policy_invocation {
        if policy_files.is_empty() {
            return Err("policy mode requires at least one --policy-file".to_string());
        }
        if query_file.is_some()
            || tool_name.is_some()
            || tool_args_seen
            || !tool_sources.is_empty()
            || run_lsp
            || run_repl
            || run_skill_install
            || install_option_seen
            || mcp_mode.is_some()
            || no_line_numbers_seen
            || force_semantic_cpu_seen
        {
            return Err(
                "--policy-file and policy output options cannot be combined with --query-file, --tool, --args, --sources, --mcp, --lsp, --repl, skill-install options, --no-line-numbers, or --force-semantic-cpu"
                    .to_string(),
            );
        }
        if policy_format != PolicyOutputFormat::Human && (policy_verbose_seen || policy_color_seen)
        {
            return Err("--verbose and --color are only valid with --format human".to_string());
        }
        let status = run_policy_mode(
            root,
            &policy_files,
            policy_format,
            policy_fail_on,
            policy_output.as_deref(),
            policy_verbose,
            policy_color,
            require_explicit_schema_versions,
        );
        return Ok(CliRunResult::PolicyStatus(status));
    }

    if let Some(query_file) = query_file {
        if tool_name.is_some()
            || tool_args_seen
            || run_lsp
            || run_repl
            || run_skill_install
            || install_option_seen
            || mcp_mode.is_some()
        {
            return Err(
                "--query-file cannot be combined with --tool, --args, --mcp, --lsp, --repl, or skill-install options"
                    .to_string(),
            );
        }
        if !tool_sources.is_empty() {
            return Err("--query-file cannot be combined with --sources".to_string());
        }
        return run_tool(
            root,
            "query_code",
            json!({ "query_file": query_file }),
            &[],
            render_options,
        )
        .map(|()| CliRunResult::Complete);
    }

    if let Some(tool_name) = tool_name {
        if run_lsp || run_repl || run_skill_install || mcp_mode.is_some() {
            return Err(
                "--tool cannot be combined with --mcp, --lsp, or --repl; it also cannot be combined with --install-skills"
                    .to_string(),
            );
        }
        return run_tool(root, &tool_name, tool_args, &tool_sources, render_options)
            .map(|()| CliRunResult::Complete);
    }

    if !tool_sources.is_empty() {
        return Err("--sources may only be used with --tool".to_string());
    }

    if run_skill_install {
        if run_lsp || run_repl || mcp_mode.is_some() {
            return Err(
                "--install-skills cannot be combined with --mcp, --lsp, or --repl".to_string(),
            );
        }
        return install_skills(InstallSkillsOptions {
            root,
            target: install_target,
            skills_root,
            mode: install_mode,
            skill_set,
            force: force_install,
            dry_run: dry_run_install,
        })
        .map(|()| CliRunResult::Complete);
    }

    if install_option_seen {
        return Err(
            "--target, --skills-root, --mode, --skill-set, --force, and --dry-run require --install-skills"
                .to_string(),
        );
    }

    if run_lsp && mcp_mode.is_some() {
        return Err("--lsp cannot be combined with --mcp".to_string());
    }

    if run_repl && (run_lsp || mcp_mode.is_some()) {
        return Err("--repl cannot be combined with --mcp or --lsp".to_string());
    }

    if !root_explicit && mcp_mode.is_none() {
        eprintln!(
            "bifrost: no --root supplied, using current directory: {}",
            escape_terminal_text(root.to_string_lossy().as_ref())
        );
    }

    if run_lsp {
        return run_lsp_stdio_server(root).map(|()| CliRunResult::Complete);
    }

    if run_repl {
        return run_code_query_repl(root).map(|()| CliRunResult::Complete);
    }

    let mode = mcp_mode.as_deref().unwrap_or("searchtools");
    // The no-argument compatibility mode still analyzes cwd. An explicit MCP
    // launch without a root starts unbound so package-local command cwd never
    // becomes analyzer scope.
    let initial_root = if root_explicit || mcp_mode.is_none() {
        Some(root)
    } else {
        None
    };
    // A rootless MCP server does not know whether the client-selected root will
    // be a Git repository yet. Advertise the potential NLP surface up front;
    // runtime availability is checked after roots negotiation.
    let git_repo = initial_root
        .as_deref()
        .is_none_or(brokk_bifrost::mcp_registry::workspace_is_git);
    let spec = resolve_server_spec_for_render_options(mode, render_options, git_repo)?;
    run_stdio_server(initial_root, render_options, &spec).map(|()| CliRunResult::Complete)
}

fn parse_policy_format(value: &str) -> Result<PolicyOutputFormat, String> {
    match value {
        "human" => Ok(PolicyOutputFormat::Human),
        "json" => Ok(PolicyOutputFormat::Json),
        "sarif" => Ok(PolicyOutputFormat::Sarif),
        other => Err(format!(
            "Invalid --format value: {other}. Expected human, json, or sarif."
        )),
    }
}

fn parse_policy_fail_on(value: &str) -> Result<PolicyFailOn, String> {
    match value {
        "never" => Ok(PolicyFailOn::Never),
        "finding" => Ok(PolicyFailOn::Finding),
        "note" => Ok(PolicyFailOn::Note),
        "warning" => Ok(PolicyFailOn::Warning),
        "error" => Ok(PolicyFailOn::Error),
        other => Err(format!(
            "Invalid --fail-on value: {other}. Expected never, finding, note, warning, or error."
        )),
    }
}

fn parse_policy_color(value: &str) -> Result<PolicyColorMode, String> {
    match value {
        "auto" => Ok(PolicyColorMode::Auto),
        "always" => Ok(PolicyColorMode::Always),
        "never" => Ok(PolicyColorMode::Never),
        other => Err(format!(
            "Invalid --color value: {other}. Expected auto, always, or never."
        )),
    }
}

fn run_policy_mode(
    root: PathBuf,
    policy_files: &[PathBuf],
    format: PolicyOutputFormat,
    fail_on: PolicyFailOn,
    output_path: Option<&Path>,
    verbose: bool,
    color_mode: PolicyColorMode,
    require_explicit_schema_versions: bool,
) -> u8 {
    let outcome = match evaluate_policy_files(
        root,
        policy_files,
        require_explicit_schema_versions,
        fail_on,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            eprintln!(
                "bifrost: policy evaluation failed: {}",
                escape_terminal_text(&error.to_string())
            );
            return POLICY_EXIT_UNRELIABLE;
        }
    };
    let human_options = HumanRenderOptions::new(
        if verbose {
            HumanRenderDetail::Verbose
        } else {
            HumanRenderDetail::Concise
        },
        resolve_policy_color(color_mode, output_path.is_none()),
    );
    let status = outcome.exit_status();
    let write_result = match output_path {
        Some(path) => write_policy_output_file(path, format, &human_options, &outcome),
        None => write_policy_stdout(format, &human_options, &outcome),
    };
    if let Err(error) = write_result {
        eprintln!(
            "bifrost: policy report output failed: {}",
            escape_terminal_text(&error)
        );
        return POLICY_EXIT_UNRELIABLE;
    }
    if status == POLICY_EXIT_UNRELIABLE {
        eprintln!(
            "bifrost: policy evaluation was incomplete or invalid; see the emitted report for details"
        );
    }
    status
}

fn resolve_policy_color(mode: PolicyColorMode, writing_stdout: bool) -> HumanRenderColor {
    match mode {
        PolicyColorMode::Always => HumanRenderColor::Ansi,
        PolicyColorMode::Never => HumanRenderColor::Plain,
        PolicyColorMode::Auto
            if writing_stdout
                && io::stdout().is_terminal()
                && env::var_os("NO_COLOR").is_none() =>
        {
            HumanRenderColor::Ansi
        }
        PolicyColorMode::Auto => HumanRenderColor::Plain,
    }
}

fn write_policy_stdout(
    format: PolicyOutputFormat,
    human_options: &HumanRenderOptions,
    outcome: &PolicyBatchOutcome,
) -> Result<(), String> {
    // Buffer the bounded encoding before touching stdout so size/serialization
    // failures cannot emit a partial machine document and remain stderr-only.
    let mut encoded = Vec::new();
    render_policy_report(
        format,
        human_options,
        outcome.report(),
        &mut encoded,
        outcome.max_serialized_report_bytes(),
    )
    .map_err(|error| error.to_string())?;
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout
        .write_all(&encoded)
        .and_then(|()| stdout.flush())
        .map_err(|error| error.to_string())
}

fn write_policy_output_file(
    destination: &Path,
    format: PolicyOutputFormat,
    human_options: &HumanRenderOptions,
    outcome: &PolicyBatchOutcome,
) -> Result<(), String> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = NamedTempFile::new_in(parent).map_err(|error| {
        format!(
            "failed to create a temporary output beside {}: {error}",
            destination.display()
        )
    })?;
    render_policy_report(
        format,
        human_options,
        outcome.report(),
        &mut temporary,
        outcome.max_serialized_report_bytes(),
    )
    .map_err(|error| error.to_string())?;
    temporary.flush().map_err(|error| {
        format!(
            "failed to flush temporary output for {}: {error}",
            destination.display()
        )
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        format!(
            "failed to sync temporary output for {}: {error}",
            destination.display()
        )
    })?;
    let temporary_path = temporary.into_temp_path();
    temporary_path.persist(destination).map_err(|error| {
        format!(
            "failed to atomically replace {}: {error}",
            destination.display()
        )
    })
}

fn render_policy_report<W: Write>(
    format: PolicyOutputFormat,
    human_options: &HumanRenderOptions,
    report: &PolicyReportDocument,
    output: W,
    max_serialized_bytes: usize,
) -> Result<u64, PolicyRenderError> {
    match format {
        PolicyOutputFormat::Human => {
            write_policy_human(report, human_options, output, max_serialized_bytes)
        }
        PolicyOutputFormat::Json => write_policy_json(report, output, max_serialized_bytes),
        PolicyOutputFormat::Sarif => write_policy_sarif(
            report,
            &SarifToolIdentity::default(),
            output,
            max_serialized_bytes,
        ),
    }
}

fn parse_install_target(value: &str) -> Result<InstallTarget, String> {
    match value {
        "project" => Ok(InstallTarget::Project),
        "global" => Ok(InstallTarget::Global),
        other => Err(format!(
            "Invalid --target value: {other}. Expected project or global."
        )),
    }
}

fn parse_install_mode(value: &str) -> Result<InstallMode, String> {
    match value {
        "auto" => Ok(InstallMode::Auto),
        "symlink" => Ok(InstallMode::Symlink),
        "copy" => Ok(InstallMode::Copy),
        other => Err(format!(
            "Invalid --mode value: {other}. Expected auto, symlink, or copy."
        )),
    }
}

fn parse_skill_set(value: &str) -> Result<SkillSet, String> {
    match value {
        "code" => Ok(SkillSet::Code),
        "all" => Ok(SkillSet::All),
        other => Err(format!(
            "Invalid --skill-set value: {other}. Expected code or all."
        )),
    }
}

fn run_tool(
    root: PathBuf,
    tool_name: &str,
    tool_args: Value,
    tool_sources: &[String],
    render_options: McpRenderOptions,
) -> Result<(), String> {
    let canonical_root = root
        .canonicalize()
        .map_err(|err| format!("Failed to resolve project root {}: {err}", root.display()))?;
    let (arguments, overlays) =
        normalize_tool_arguments_for_cli(tool_name, tool_args, &canonical_root)?;
    let service = create_cli_tool_service(canonical_root, tool_sources, overlays)?;
    let output = service
        .call_tool_output(
            tool_name,
            arguments,
            RenderOptions {
                render_line_numbers: render_options.render_line_numbers,
            },
        )
        .map_err(|err| err.to_string())?;

    let result = match output {
        // Mirror the MCP tool result shape, but omit `content` so one-shot CLI
        // stdout stays machine-only.
        ToolOutput::Text(_) => json!({
            "isError": false,
        }),
        ToolOutput::Structured {
            structured,
            rendered_text: _,
        } => json!({
            "structuredContent": structured,
            "isError": false,
        }),
    };
    let encoded = serde_json::to_string(&result)
        .map_err(|err| format!("Failed to serialize tool result: {err}"))?;
    println!("{encoded}");
    Ok(())
}

fn print_help(topic: Option<&str>) -> Result<(), String> {
    // Help reflects the tools this binary actually advertises (same surface as
    // tools/list). `semantic_search` therefore appears only in an nlp-enabled
    // build whose host can run the embedder; the shipped CLI is built without
    // the nlp feature, so it never advertises it.
    match topic {
        Some(name) => print_tool_help(name),
        None => {
            print_general_help();
            Ok(())
        }
    }
}

fn print_general_help() {
    println!(
        "bifrost {} — Tree-sitter-backed code analyzer with MCP search-tool and LSP servers (stdio).",
        env!("CARGO_PKG_VERSION")
    );
    // Static sections, printed via variables so the JSON braces in the examples
    // stay literal. The toolset → tool-name listing between them is generated
    // from the registry so it never drifts.
    let top = r#"
USAGE:
    bifrost                  Run an MCP server over stdio (default: --mcp searchtools)
    bifrost --mcp TOOLSETS     Run an MCP server over stdio (e.g. --mcp core)
    bifrost --lsp              Run a Language Server (LSP) over stdio
    bifrost --repl             Run the interactive code-query REPL
    bifrost --tool NAME        Run a single tool once, print JSON result, and exit
    bifrost --query-file PATH  Run a .rql or .json code query once, print JSON result, and exit
    bifrost --policy-file PATH Evaluate one or more static-analysis policy files and exit
    bifrost --install-skills   Install Bifrost Agent Skills into a .agents/skills root
    bifrost --version | --help [TOOL]

OPTIONS:
    --root DIR             Project root to analyze (default: current directory)
    --args JSON            Inline JSON arguments for --tool, e.g. '{"patterns":["MyClass"]}'.
                           File path arguments may use <commit-ish>:<path> in --tool mode.
                           Required for tools that take arguments; omit for those that don't
                           (defaults to {}, which suits e.g. get_active_workspace).
    --query-file PATH      Run a workspace-relative .rql or .json CodeQuery directly.
    --sources PATH         Restrict one-shot --tool workspace construction to selected files,
                           directories, or globs. Repeatable; valid only with --tool.
    --policy-file PATH     Evaluate a workspace-relative .rqlp policy. Repeatable.
    --format FORMAT        Policy output: human, json, or sarif (default: human)
    --verbose              Include complete evidence, provenance, and rule details in human output
    --color MODE           Human output color: auto, always, or never (default: auto)
    --fail-on THRESHOLD    Policy finding threshold: never, finding, note, warning, or error
                           (default: warning; finding includes unrated findings)
    --require-explicit-schema-versions
                           Reject inferred policy and RQL schema versions
    --output PATH          Atomically write policy output to PATH instead of stdout
    --no-line-numbers      Render source output without leading line numbers
    --target project|global
                           Skill install destination for --install-skills
                           (project: <root>/.agents/skills, global: ~/.agents/skills)
    --skills-root DIR      Explicit .agents-compatible skills root for --install-skills
    --mode auto|symlink|copy
                           Skill install mode (default: auto)
    --skill-set code|all   Skills to install (default: code)
    --force                Replace drifted Bifrost-managed copied skills
    --dry-run              Show planned skill install actions without writing files
    --force-semantic-cpu   Allow semantic_search without a CUDA/Metal accelerator (run the embedder on CPU)
    -h, --help [TOOL]      Show this help, or a single tool's description and parameters
    -V, --version          Show version and exit

MCP TOOLSETS (--mcp):
    searchtools   every toolset below
    core          symbol + workspace + nlp (the set agents typically connect to)
"#;
    print!("{top}");

    for toolset in searchtools_toolset_order() {
        let Ok(spec) = resolve_server_spec(toolset) else {
            continue;
        };
        let names: Vec<&str> = spec
            .tool_descriptors
            .iter()
            .filter_map(|descriptor| descriptor.get("name").and_then(Value::as_str))
            .collect();
        if !names.is_empty() {
            print_toolset_line(toolset, &names);
        }
    }

    let bottom = r#"    Combine toolsets with '|', e.g. --mcp symbol|workspace
    Run `bifrost --help <tool>` for a tool's description and parameters.

EXAMPLES:
    # MCP server from the current directory, using the compatibility searchtools set:
    bifrost

    # MCP server an agent connects to (core toolset), speaking MCP over stdio:
    bifrost --root /path/to/project --mcp core

    # One-shot: run a single tool and print its JSON result, then exit:
    bifrost --root /path/to/project --tool search_symbols --args '{"patterns":["MyClass"]}'

    # Run a saved RQL or JSON code query (current directory is the default root):
    bifrost --query-file queries/audit.rql

    # Evaluate two policy roots together and emit one canonical JSON report:
    bifrost --root /path/to/project --policy-file policies/security.rqlp --policy-file policies/correctness.rqlp --format json

    # Human code-query exploration with S-expressions, completion, docs, and history:
    bifrost --root /path/to/project --repl

    # Install generic Agent Skills for Zed/Antigravity-style hosts:
    bifrost --install-skills --target project

    # One-shot against a subset workspace built from a directory and a glob:
    bifrost --root /path/to/project --tool get_symbol_sources --sources src --sources 'tests/**/*.rs' --args '{"symbols":["src/main.rs"]}'

    # Language server over stdio:
    bifrost --root /path/to/project --lsp

Servers speak their protocol over stdio (no network port). The workspace index is built
in the background: the server is ready immediately and the first request waits for indexing.
Skills provide agent instructions only; configure MCP separately for analyzer tools.
"#;
    print!("{bottom}");
}

/// Print `    <toolset>   name, name, ...`, wrapping the comma-separated names
/// with a hanging indent aligned under the first name.
fn print_toolset_line(toolset: &str, names: &[&str]) {
    const LABEL_WIDTH: usize = 14;
    const WRAP: usize = 96;
    let indent = " ".repeat(4 + LABEL_WIDTH);
    let mut line = format!("    {toolset:<LABEL_WIDTH$}");
    for (i, name) in names.iter().enumerate() {
        if i == 0 {
            line.push_str(name);
        } else if line.chars().count() + 2 + name.chars().count() > WRAP {
            line.push(',');
            println!("{line}");
            line = format!("{indent}{name}");
        } else {
            line.push_str(", ");
            line.push_str(name);
        }
    }
    println!("{line}");
}

fn print_tool_help(name: &str) -> Result<(), String> {
    // `searchtools` advertises every tool, so it is the lookup surface.
    let spec = resolve_server_spec("searchtools")?;
    let descriptor = spec
        .tool_descriptors
        .iter()
        .find(|descriptor| descriptor.get("name").and_then(Value::as_str) == Some(name))
        .ok_or_else(|| {
            format!("unknown tool: {name}\nRun `bifrost --help` to list available tools.")
        })?;

    match toolset_of(name) {
        Some(toolset) => println!("{name}  (toolset: {toolset})"),
        None => println!("{name}"),
    }
    if let Some(description) = descriptor.get("description").and_then(Value::as_str) {
        println!("\n{description}");
    }

    let schema = descriptor.get("inputSchema");
    let properties = schema
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object);
    let required: std::collections::HashSet<&str> = schema
        .and_then(|schema| schema.get("required"))
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    match properties {
        Some(properties) if !properties.is_empty() => {
            println!("\nPARAMETERS:");
            for (param, param_schema) in properties {
                let summary = param_summary(param_schema, required.contains(param.as_str()));
                println!("    {param}  ({summary})");
                if let Some(description) = param_schema.get("description").and_then(Value::as_str) {
                    println!("        {description}");
                }
            }
        }
        _ => println!("\nPARAMETERS: none"),
    }
    Ok(())
}

/// A human-readable type/constraint summary for one parameter, built entirely
/// from its JSON-Schema, e.g. `array of strings, required` or
/// `integer, optional, default 20, minimum 1`.
fn param_summary(schema: &Value, required: bool) -> String {
    let mut parts = vec![type_phrase(schema)];
    parts.push(if required { "required" } else { "optional" }.to_string());
    if let Some(default) = schema.get("default") {
        parts.push(format!("default {}", scalar(default)));
    }
    if let Some(minimum) = schema.get("minimum") {
        parts.push(format!("minimum {}", scalar(minimum)));
    }
    if let Some(maximum) = schema.get("maximum") {
        parts.push(format!("maximum {}", scalar(maximum)));
    }
    if let Some(min_items) = schema.get("minItems") {
        parts.push(format!("min items {}", scalar(min_items)));
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        let rendered: Vec<String> = values.iter().map(scalar).collect();
        parts.push(format!("one of: {}", rendered.join(", ")));
    }
    parts.join(", ")
}

/// The base type phrase, naming the element type for arrays (`array of strings`)
/// and collapsing `anyOf`/untyped schemas to `value`.
fn type_phrase(schema: &Value) -> String {
    match schema.get("type").and_then(Value::as_str) {
        Some("array") => {
            let items = schema.get("items").map(array_item_noun).unwrap_or("items");
            format!("array of {items}")
        }
        Some(other) => other.to_string(),
        None => "value".to_string(),
    }
}

/// Plural noun for an array's element type; `items` when the element schema is
/// a composite (e.g. `anyOf`) with no single `type`.
fn array_item_noun(items: &Value) -> &'static str {
    match items.get("type").and_then(Value::as_str) {
        Some("string") => "strings",
        Some("integer") => "integers",
        Some("number") => "numbers",
        Some("boolean") => "booleans",
        Some("object") => "objects",
        Some("array") => "arrays",
        _ => "items",
    }
}

/// Render a scalar schema value (default/min/max/enum) without JSON quoting.
fn scalar(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// The first toolset (in registry order) that advertises `name`, for the
/// tool-detail header.
fn toolset_of(name: &str) -> Option<&'static str> {
    searchtools_toolset_order().iter().copied().find(|toolset| {
        resolve_server_spec(toolset).is_ok_and(|spec| {
            spec.tool_descriptors
                .iter()
                .any(|descriptor| descriptor.get("name").and_then(Value::as_str) == Some(name))
        })
    })
}
