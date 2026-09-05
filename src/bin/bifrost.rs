use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chrono::{Datelike, Utc};
#[path = "bifrost/code_query_repl.rs"]
mod code_query_repl;

use brokk_bifrost::lsp::run_lsp_stdio_server;
use brokk_bifrost::mcp_common::McpRenderOptions;
use brokk_bifrost::mcp_install::install_mcp_hosts;
use brokk_bifrost::mcp_registry::{
    resolve_server_spec, resolve_server_spec_for_render_options, searchtools_toolset_order,
    single_shot_only_tool_descriptors,
};
use brokk_bifrost::policy::{
    BuiltInPolicyCatalogManifest, BuiltInPolicySelection, ExplanationCandidate, ExplanationLimits,
    ExplanationTarget, HumanRenderColor, HumanRenderDetail, HumanRenderOptions, NearMissCandidates,
    POLICY_EXIT_CLEAN, POLICY_EXIT_UNRELIABLE, PolicyBaselineDocument, PolicyBaselineOptions,
    PolicyBaselineSource, PolicyBatchOutcome, PolicyEvaluationDate, PolicyEvaluationInput,
    PolicyEvaluationOptions, PolicyFailOn, PolicyFindingId, PolicyRenderError,
    PolicyReportDocument, PolicyScopeOptions, PolicyScopeSource, PolicySuppressionOptions,
    PolicySuppressionSource, SarifToolIdentity, built_in_policy_catalog, escape_terminal_text,
    evaluate_policy_inputs, explain_policy_inputs, rank_policy_near_misses,
    relation_schema_catalog, write_policy_human, write_policy_json, write_policy_sarif,
};
use brokk_bifrost::rmcp_host::{
    NamedWorkspace, run_named_workspace_stdio_server_with_build_identity,
    run_stdio_server_with_build_identity,
};
use brokk_bifrost::scoped_project::{create_cli_tool_service, create_scoped_service};
use brokk_bifrost::searchtools_render::RenderOptions;
use brokk_bifrost::tool_arguments::normalize_tool_arguments_for_cli;
use brokk_bifrost::{CancellationToken, ToolOutput};
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

/// A listing flag answers a question about a shipped catalog instead of
/// running a gate, so it refuses every option that selects or shapes an
/// evaluation, and the listings refuse each other: two catalogs on one stdout
/// would be neither document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyListing {
    Policies,
    RowSchemas,
}

impl PolicyListing {
    const fn flag(self) -> &'static str {
        match self {
            Self::Policies => "--list-policies",
            Self::RowSchemas => "--list-row-schemas",
        }
    }
}

/// Record the one listing this invocation asks for.
fn select_listing(
    current: &mut Option<PolicyListing>,
    requested: PolicyListing,
) -> Result<(), String> {
    match *current {
        Some(existing) if existing == requested => {
            Err(format!("{} may only be provided once", requested.flag()))
        }
        Some(existing) => Err(format!(
            "{} cannot be combined with {}",
            requested.flag(),
            existing.flag()
        )),
        None => {
            *current = Some(requested);
            Ok(())
        }
    }
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
    brokk_bifrost::ensure_global_rayon_pool();
    if let Err(error) = brokk_bifrost::install_bifrost_semantic_model_packs() {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }
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
    // `scan` is a subcommand, recognized only in the first position so the
    // flag surface stays untouched: everywhere else the word remains an
    // unknown argument exactly as before the subcommand existed.
    if args.first().map(String::as_str) == Some("scan") {
        return run_scan(args.into_iter().skip(1)).map_err(|message| CliRunError {
            message,
            // A scan failure reports through the policy exit contract: its
            // run is a policy evaluation, so its errors are unreliable runs.
            policy_invocation: true,
        });
    }
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
            "--policy"
                | "--no-builtin-policies"
                | "--policy-file"
                | "--policy-pack"
                | "--policy-category"
                | "--policy-id"
                | "--list-policies"
                | "--list-row-schemas"
                | "--format"
                | "--fail-on"
                | "--suppressions-file"
                | "--scope-file"
                | "--baseline-file"
                | "--accept-current"
                | "--evaluation-date"
                | "--diff-base"
                | "--no-incremental"
                | "--output"
                | "--color"
                | "--verbose"
                | "--require-explicit-schema-versions"
                | "--explain-finding"
                | "--explain-candidate"
                | "--explain-near-misses"
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
            | "--workspace"
            | "--mcp"
            | "--server"
            | "--tool"
            | "--args"
            | "--diff-snapshot-object-dir"
            | "--query-file"
            | "--sources"
            | "--policy-file"
            | "--policy-pack"
            | "--policy-category"
            | "--policy-id"
            | "--format"
            | "--fail-on"
            | "--suppressions-file"
            | "--scope-file"
            | "--baseline-file"
            | "--evaluation-date"
            | "--diff-base"
            | "--output"
            | "--color"
            | "--explain-finding"
            | "--explain-candidate"
            | "--explain-near-misses"
    )
}

/// One `--explain-candidate` value: `PATH:BYTE_START` or
/// `PATH:BYTE_START-BYTE_END`.
///
/// The separator is the *last* colon before the offset, so a Windows-style
/// drive letter or a path containing a colon still parses. The offsets are
/// bytes, not lines or columns, because that is the domain key the explanation
/// library takes and inventing a second one would need a source read.
fn parse_explain_candidate(value: &str) -> Result<(String, u64, Option<u64>), String> {
    let (path, span) = value.rsplit_once(':').ok_or_else(|| {
        format!("Invalid --explain-candidate `{value}`: expected PATH:BYTE_START[-BYTE_END]")
    })?;
    if path.is_empty() {
        return Err(format!("Invalid --explain-candidate `{value}`: empty path"));
    }
    let parse_offset = |text: &str| -> Result<u64, String> {
        text.parse::<u64>().map_err(|error| {
            format!("Invalid --explain-candidate byte offset `{text}` in `{value}`: {error}")
        })
    };
    match span.split_once('-') {
        Some((start, end)) => Ok((
            path.to_string(),
            parse_offset(start)?,
            Some(parse_offset(end)?),
        )),
        None => Ok((path.to_string(), parse_offset(span)?, None)),
    }
}

fn run_inner(
    mut args: impl Iterator<Item = String>,
    policy_invocation: bool,
) -> Result<CliRunResult, String> {
    let mut root =
        env::current_dir().map_err(|err| format!("Failed to get current directory: {err}"))?;
    let mut root_explicit = false;
    let mut install = false;
    let mut named_workspaces = Vec::new();
    let mut mcp_mode: Option<String> = None;
    let mut run_lsp = false;
    let mut run_repl = false;
    let mut tool_name: Option<String> = None;
    let mut tool_args = json!({});
    let mut tool_args_seen = false;
    let mut tool_sources = Vec::new();
    let mut diff_snapshot_object_dir: Option<PathBuf> = None;
    let mut query_file: Option<String> = None;
    let mut workspace_scaled_limits = false;
    let mut render_options = McpRenderOptions::default();
    let mut no_line_numbers_seen = false;
    let mut policy_files = Vec::new();
    let mut policy_selection = BuiltInPolicySelection::default();
    let mut policy_flag = false;
    let mut no_builtin_policies = false;
    let mut listing: Option<PolicyListing> = None;
    let mut policy_format = PolicyOutputFormat::Human;
    let mut policy_format_seen = false;
    let mut policy_fail_on = PolicyFailOn::Warning;
    let mut policy_fail_on_seen = false;
    let mut policy_suppressions = PolicySuppressionOptions::default();
    let mut policy_suppressions_seen = false;
    let mut policy_scope = PolicyScopeOptions::default();
    let mut policy_scope_seen = false;
    let mut policy_baseline = PolicyBaselineOptions::default();
    let mut policy_baseline_seen = false;
    let mut accept_current = false;
    let mut policy_evaluation_date = None;
    let mut policy_diff_base: Option<String> = None;
    // Reuse is on by default; the switch exists to take it away for a run that
    // needs to compare against the full dual-snapshot evaluation.
    let mut policy_incremental = true;
    let mut policy_output: Option<PathBuf> = None;
    let mut policy_verbose = false;
    let mut policy_verbose_seen = false;
    let mut policy_color = PolicyColorMode::Auto;
    let mut policy_color_seen = false;
    let mut require_explicit_schema_versions = false;
    let mut explain_finding: Option<String> = None;
    let mut explain_candidate: Option<(String, u64, Option<u64>)> = None;
    let mut explain_near_misses: Option<usize> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--install" => {
                if install {
                    return Err("--install may only be provided once".to_string());
                }
                install = true;
            }
            "--root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--root requires a path".to_string())?;
                root = value.into();
                root_explicit = true;
            }
            "--workspace" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--workspace requires NAME=PATH".to_string())?;
                let (name, path) = value.split_once('=').ok_or_else(|| {
                    "--workspace requires NAME=PATH with a non-empty name and path".to_string()
                })?;
                if name.is_empty() || path.is_empty() {
                    return Err(
                        "--workspace requires NAME=PATH with a non-empty name and path".to_string(),
                    );
                }
                named_workspaces.push(NamedWorkspace::new(name.to_string(), path.into()));
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
            "--diff-snapshot-object-dir" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--diff-snapshot-object-dir requires a path".to_string())?;
                diff_snapshot_object_dir = Some(value.into());
            }
            "--query-file" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--query-file requires a path".to_string())?;
                if query_file.replace(value).is_some() {
                    return Err("--query-file may only be provided once".to_string());
                }
            }
            "--workspace-scaled-limits" => {
                if workspace_scaled_limits {
                    return Err("--workspace-scaled-limits may only be provided once".to_string());
                }
                workspace_scaled_limits = true;
            }
            "--sources" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--sources requires a path".to_string())?;
                tool_sources.push(value);
            }
            "--policy" => {
                if policy_flag {
                    return Err("--policy may only be provided once".to_string());
                }
                policy_flag = true;
            }
            "--no-builtin-policies" => {
                if no_builtin_policies {
                    return Err("--no-builtin-policies may only be provided once".to_string());
                }
                no_builtin_policies = true;
            }
            "--policy-file" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--policy-file requires a path".to_string())?;
                policy_files.push(PathBuf::from(value));
            }
            "--policy-pack" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--policy-pack requires an id".to_string())?;
                policy_selection.packs.push(value);
            }
            "--policy-category" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--policy-category requires a category".to_string())?;
                policy_selection.categories.push(value);
            }
            "--policy-id" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--policy-id requires an id".to_string())?;
                policy_selection.policy_ids.push(value);
            }
            "--list-policies" => select_listing(&mut listing, PolicyListing::Policies)?,
            "--list-row-schemas" => select_listing(&mut listing, PolicyListing::RowSchemas)?,
            "--explain-finding" => {
                let value = args.next().ok_or_else(|| {
                    "--explain-finding requires a finding id as run_policy reports it".to_string()
                })?;
                if explain_finding.is_some() {
                    return Err("--explain-finding may only be provided once".to_string());
                }
                explain_finding = Some(value);
            }
            "--explain-candidate" => {
                let value = args.next().ok_or_else(|| {
                    "--explain-candidate requires PATH:BYTE_START[-BYTE_END]".to_string()
                })?;
                if explain_candidate.is_some() {
                    return Err("--explain-candidate may only be provided once".to_string());
                }
                explain_candidate = Some(parse_explain_candidate(&value)?);
            }
            "--explain-near-misses" => {
                let value = args.next().ok_or_else(|| {
                    format!(
                        "--explain-near-misses requires how many ranked subjects to retain,                          between 1 and {MAX_EXPLAIN_NEAR_MISSES}"
                    )
                })?;
                if explain_near_misses.is_some() {
                    return Err("--explain-near-misses may only be provided once".to_string());
                }
                explain_near_misses = Some(parse_explain_near_misses(&value)?);
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
            "--suppressions-file" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--suppressions-file requires a path".to_string())?;
                if policy_suppressions_seen {
                    return Err("--suppressions-file may only be provided once".to_string());
                }
                let source = PolicySuppressionSource::explicit_portable(&value)
                    .map_err(|error| format!("Invalid --suppressions-file path: {error}"))?;
                policy_suppressions = PolicySuppressionOptions::new(source);
                policy_suppressions_seen = true;
            }
            "--scope-file" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--scope-file requires a path".to_string())?;
                if policy_scope_seen {
                    return Err("--scope-file may only be provided once".to_string());
                }
                let source = PolicyScopeSource::explicit_portable(&value)
                    .map_err(|error| format!("Invalid --scope-file path: {error}"))?;
                policy_scope = PolicyScopeOptions::new(source);
                policy_scope_seen = true;
            }
            "--baseline-file" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--baseline-file requires a path".to_string())?;
                if policy_baseline_seen {
                    return Err("--baseline-file may only be provided once".to_string());
                }
                let source = PolicyBaselineSource::explicit_portable(&value)
                    .map_err(|error| format!("Invalid --baseline-file path: {error}"))?;
                policy_baseline = PolicyBaselineOptions::new(source);
                policy_baseline_seen = true;
            }
            "--accept-current" => {
                if accept_current {
                    return Err("--accept-current may only be provided once".to_string());
                }
                accept_current = true;
            }
            "--no-incremental" => {
                if !policy_incremental {
                    return Err("--no-incremental may only be provided once".to_string());
                }
                policy_incremental = false;
            }
            "--evaluation-date" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--evaluation-date requires YYYY-MM-DD".to_string())?;
                if policy_evaluation_date.is_some() {
                    return Err("--evaluation-date may only be provided once".to_string());
                }
                policy_evaluation_date =
                    Some(value.parse::<PolicyEvaluationDate>().map_err(|error| {
                        format!("Invalid --evaluation-date value: {value}. {error}.")
                    })?);
            }
            "--diff-base" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--diff-base requires a git revision".to_string())?;
                if policy_diff_base.replace(value).is_some() {
                    return Err("--diff-base may only be provided once".to_string());
                }
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
            "--help" | "-h" => {
                // Optional positional topic: `--help <tool>` shows that tool's
                // description and parameters. Ignore a following flag.
                let topic = args.next().filter(|a| !a.starts_with('-'));
                return print_help(topic.as_deref()).map(|()| CliRunResult::Complete);
            }
            "--version" | "-V" => {
                println!("bifrost {}", env!("CARGO_PKG_VERSION"));
                // The shipped policy catalog is part of the behavior a version
                // names, so a catalog change must surface here as a version
                // event rather than a silent behavior change. The first line
                // keeps its exact historical shape for existing parsers.
                let catalog = built_in_policy_catalog().map_err(|error| error.to_string())?;
                for line in builtin_pack_witness_lines(catalog.document(), catalog.digest()) {
                    println!("{line}");
                }
                return Ok(CliRunResult::Complete);
            }
            "--build-identity" => {
                println!("{}", brokk_bifrost::BIFROST_BUILD_IDENTITY);
                return Ok(CliRunResult::Complete);
            }
            other => {
                return Err(format!("Unknown argument: {other}"));
            }
        }
    }

    if !named_workspaces.is_empty() {
        if root_explicit {
            return Err("--workspace cannot be combined with --root".to_string());
        }
        if mcp_mode.is_none() {
            return Err("--workspace requires --mcp".to_string());
        }
        if diff_snapshot_object_dir.is_some() {
            return Err("--diff-snapshot-object-dir is not available with --workspace".to_string());
        }
    }

    if policy_invocation {
        if query_file.is_some()
            || tool_name.is_some()
            || tool_args_seen
            || run_lsp
            || run_repl
            || mcp_mode.is_some()
            || no_line_numbers_seen
            || diff_snapshot_object_dir.is_some()
            || workspace_scaled_limits
            || install
        {
            return Err(
                "policy options cannot be combined with --install, --query-file, --tool, --args, --mcp, --lsp, --repl, --no-line-numbers, --workspace-scaled-limits, or --diff-snapshot-object-dir"
                    .to_string(),
            );
        }
        if let Some(listing) = listing {
            let flag = listing.flag();
            if explain_finding.is_some()
                || explain_candidate.is_some()
                || explain_near_misses.is_some()
            {
                return Err(format!(
                    "{flag} cannot be combined with --explain-finding, --explain-candidate, or --explain-near-misses"
                ));
            }
            if !policy_files.is_empty()
                || !policy_selection.is_empty()
                || policy_flag
                || no_builtin_policies
                || policy_format_seen
                || policy_fail_on_seen
                || policy_suppressions_seen
                || policy_scope_seen
                || policy_baseline_seen
                || accept_current
                || policy_evaluation_date.is_some()
                || policy_diff_base.is_some()
                || !policy_incremental
                || policy_output.is_some()
                || policy_verbose_seen
                || policy_color_seen
                || require_explicit_schema_versions
                || !tool_sources.is_empty()
            {
                return Err(format!(
                    "{flag} cannot be combined with policy selection or evaluation options"
                ));
            }
            let encoded = match listing {
                PolicyListing::Policies => {
                    let catalog = built_in_policy_catalog().map_err(|error| error.to_string())?;
                    serde_json::to_string_pretty(catalog.document()).map_err(|error| {
                        format!("failed to serialize built-in policy catalog: {error}")
                    })?
                }
                PolicyListing::RowSchemas => {
                    serde_json::to_string_pretty(&relation_schema_catalog()).map_err(|error| {
                        format!("failed to serialize relation schema catalog: {error}")
                    })?
                }
            };
            println!("{encoded}");
            return Ok(CliRunResult::Complete);
        }
        if no_builtin_policies {
            if !policy_selection.is_empty() {
                return Err(
                    "--no-builtin-policies cannot be combined with --policy-pack, --policy-category, or --policy-id"
                        .to_string(),
                );
            }
            if policy_files.is_empty() {
                return Err("--no-builtin-policies requires at least one --policy-file".to_string());
            }
        }
        if policy_format != PolicyOutputFormat::Human && (policy_verbose_seen || policy_color_seen)
        {
            return Err("--verbose and --color are only valid with --format human".to_string());
        }
        if accept_current {
            // Findings are the expected input of an acceptance run, so a
            // gating threshold is meaningless; and a baseline is defined by a
            // full run, never by a diff classification.
            if policy_fail_on_seen {
                return Err("--accept-current cannot be combined with --fail-on".to_string());
            }
            if policy_diff_base.is_some() {
                return Err("--accept-current cannot be combined with --diff-base".to_string());
            }
            policy_fail_on = PolicyFailOn::Never;
        }
        let explain_mode =
            explanation_mode(explain_finding, explain_candidate, explain_near_misses)?;
        if explain_mode.is_some() {
            // An explanation is a query about one policy, not a gate over a
            // workspace, so every option that shapes a gate is refused rather
            // than silently ignored.
            if policy_format_seen
                || policy_fail_on_seen
                || policy_suppressions_seen
                || policy_scope_seen
                || policy_baseline_seen
                || accept_current
                || policy_evaluation_date.is_some()
                || policy_diff_base.is_some()
                || policy_verbose_seen
                || policy_color_seen
                || !tool_sources.is_empty()
            {
                return Err(
                    "--explain-finding, --explain-candidate, and --explain-near-misses cannot be combined with --format, --fail-on, --suppressions-file, --scope-file, --baseline-file, --accept-current, --evaluation-date, --diff-base, --verbose, --color, or --sources"
                        .to_string(),
                );
            }
        }
        // An explicit selection of any kind replaces the zero-configuration
        // default; --no-builtin-policies asserts a controlled run stays free
        // of shipped policies even when no explicit input survived.
        let use_builtin_default =
            policy_files.is_empty() && policy_selection.is_empty() && !no_builtin_policies;
        if use_builtin_default && explain_mode.is_some() {
            // An explanation is about exactly one policy, so the multi-policy
            // shipped catalog can never be its implicit subject.
            return Err(
                "policy explanation requires an explicit --policy-file or built-in policy selector"
                    .to_string(),
            );
        }
        let catalog = built_in_policy_catalog().map_err(|error| error.to_string())?;
        let effective_selection = if use_builtin_default {
            BuiltInPolicySelection {
                packs: catalog
                    .document()
                    .packs
                    .iter()
                    .map(|pack| pack.id.clone())
                    .collect(),
                ..BuiltInPolicySelection::default()
            }
        } else {
            policy_selection
        };
        let mut policy_inputs = catalog
            .select(&effective_selection)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|policy| {
                PolicyEvaluationInput::embedded(policy.source_identity(), policy.source())
            })
            .collect::<Vec<_>>();
        policy_inputs.extend(
            policy_files
                .into_iter()
                .map(PolicyEvaluationInput::workspace_file),
        );
        if let Some(mode) = explain_mode {
            let status = match mode {
                ExplanationMode::Explanation(target) => {
                    run_policy_explain_mode(&root, &policy_inputs, &target, policy_output)
                }
                ExplanationMode::NearMiss(max_candidates) => {
                    run_policy_near_miss_mode(&root, &policy_inputs, max_candidates, policy_output)
                }
            };
            return Ok(CliRunResult::PolicyStatus(status));
        }
        let status = run_policy_mode(
            PolicyModeRequest {
                root,
                format: policy_format,
                fail_on: policy_fail_on,
                evaluation_date: policy_evaluation_date,
                suppressions: policy_suppressions,
                scope: policy_scope,
                baseline: policy_baseline,
                accept_current,
                diff_base: policy_diff_base,
                incremental: policy_incremental,
                output: policy_output,
                verbose: policy_verbose,
                color: policy_color,
                require_explicit_schema_versions,
                sources: tool_sources,
            },
            &policy_inputs,
        );
        return Ok(CliRunResult::PolicyStatus(status));
    }

    if install {
        if root_explicit
            || !named_workspaces.is_empty()
            || mcp_mode.is_some()
            || run_lsp
            || run_repl
            || tool_name.is_some()
            || tool_args_seen
            || !tool_sources.is_empty()
            || diff_snapshot_object_dir.is_some()
            || query_file.is_some()
            || no_line_numbers_seen
            || workspace_scaled_limits
        {
            return Err("--install cannot be combined with other options".to_string());
        }
        install_mcp_hosts()?;
        return Ok(CliRunResult::Complete);
    }

    if let Some(query_file) = query_file {
        if tool_name.is_some()
            || tool_args_seen
            || run_lsp
            || run_repl
            || mcp_mode.is_some()
            || diff_snapshot_object_dir.is_some()
        {
            return Err(
                "--query-file cannot be combined with --tool, --args, --mcp, --lsp, --repl, or --diff-snapshot-object-dir"
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
            None,
            workspace_scaled_limits,
        )
        .map(|()| CliRunResult::Complete);
    }

    if workspace_scaled_limits {
        return Err("--workspace-scaled-limits requires --query-file".to_string());
    }

    if let Some(tool_name) = tool_name {
        if run_lsp || run_repl || mcp_mode.is_some() {
            return Err("--tool cannot be combined with --mcp, --lsp, or --repl".to_string());
        }
        let diff_snapshot_object_dir = diff_snapshot_object_dir
            .map(validate_diff_snapshot_object_dir)
            .transpose()?;
        return run_tool(
            root,
            &tool_name,
            tool_args,
            &tool_sources,
            render_options,
            diff_snapshot_object_dir,
            false,
        )
        .map(|()| CliRunResult::Complete);
    }

    if !tool_sources.is_empty() {
        return Err("--sources may only be used with --tool".to_string());
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
        if diff_snapshot_object_dir.is_some() {
            return Err("--diff-snapshot-object-dir is only valid with --tool or MCP server mode; it cannot be combined with --lsp".to_string());
        }
        return run_lsp_stdio_server(root).map(|()| CliRunResult::Complete);
    }

    if run_repl {
        if diff_snapshot_object_dir.is_some() {
            return Err("--diff-snapshot-object-dir is only valid with --tool or MCP server mode; it cannot be combined with --repl".to_string());
        }
        return run_code_query_repl(root).map(|()| CliRunResult::Complete);
    }

    let mode = mcp_mode.as_deref().unwrap_or("searchtools");
    // The no-argument compatibility mode still analyzes cwd. An explicit MCP
    // launch without a root starts unbound so package-local command cwd never
    // becomes analyzer scope.
    let initial_root = if !named_workspaces.is_empty() {
        None
    } else if root_explicit || mcp_mode.is_none() {
        Some(root)
    } else {
        None
    };
    let spec = resolve_server_spec_for_render_options(mode, render_options)?;
    let diff_snapshot_object_dir = diff_snapshot_object_dir
        .map(validate_diff_snapshot_object_dir)
        .transpose()?;
    if named_workspaces.is_empty() {
        run_stdio_server_with_build_identity(
            initial_root,
            render_options,
            &spec,
            diff_snapshot_object_dir,
            brokk_bifrost::BIFROST_BUILD_IDENTITY,
        )
    } else {
        run_named_workspace_stdio_server_with_build_identity(
            named_workspaces,
            render_options,
            &spec,
            brokk_bifrost::BIFROST_BUILD_IDENTITY,
        )
    }
    .map(|()| CliRunResult::Complete)
}

/// The `bifrost scan [PATH]` subcommand: the zero-configuration
/// shipped-product entry point (issue #2882).
///
/// A scan activates every built-in policy pack the build ships against one
/// project path -- no `--policy-file`, no selectors -- and witnesses the
/// activated pack set on stderr in the same line shape `--version` prints, so
/// an external evaluation can record exactly which shipped catalog decided.
/// The subcommand is additive: the flag-based policy surface, which
/// benchmark-controlled runs configure explicitly, is untouched.
///
/// A build that ships no packs is reported honestly: the witness records an
/// empty activated pack set, the run evaluates nothing, and the exit status
/// is clean rather than an error, so the surface exists before the shipped
/// content does.
fn run_scan(mut args: impl Iterator<Item = String>) -> Result<CliRunResult, String> {
    let mut path: Option<PathBuf> = None;
    let mut list_builtin = false;
    let mut format = PolicyOutputFormat::Human;
    let mut format_seen = false;
    let mut fail_on = PolicyFailOn::Warning;
    let mut fail_on_seen = false;
    let mut evaluation_date = None;
    let mut output: Option<PathBuf> = None;
    let mut verbose = false;
    let mut color = PolicyColorMode::Auto;
    let mut color_seen = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--list-builtin-policies" => {
                if list_builtin {
                    return Err("--list-builtin-policies may only be provided once".to_string());
                }
                list_builtin = true;
            }
            "--format" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--format requires human, json, or sarif".to_string())?;
                if format_seen {
                    return Err("--format may only be provided once".to_string());
                }
                format = parse_policy_format(&value)?;
                format_seen = true;
            }
            "--fail-on" => {
                let value = args.next().ok_or_else(|| {
                    "--fail-on requires never, finding, note, warning, or error".to_string()
                })?;
                if fail_on_seen {
                    return Err("--fail-on may only be provided once".to_string());
                }
                fail_on = parse_policy_fail_on(&value)?;
                fail_on_seen = true;
            }
            "--evaluation-date" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--evaluation-date requires YYYY-MM-DD".to_string())?;
                if evaluation_date.is_some() {
                    return Err("--evaluation-date may only be provided once".to_string());
                }
                evaluation_date = Some(value.parse::<PolicyEvaluationDate>().map_err(|error| {
                    format!("Invalid --evaluation-date value: {value}. {error}.")
                })?);
            }
            "--output" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--output requires a path".to_string())?;
                if output.replace(PathBuf::from(value)).is_some() {
                    return Err("--output may only be provided once".to_string());
                }
            }
            "--verbose" => {
                if verbose {
                    return Err("--verbose may only be provided once".to_string());
                }
                verbose = true;
            }
            "--color" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--color requires auto, always, or never".to_string())?;
                if color_seen {
                    return Err("--color may only be provided once".to_string());
                }
                color = parse_policy_color(&value)?;
                color_seen = true;
            }
            "--help" | "-h" => {
                print_scan_help();
                return Ok(CliRunResult::Complete);
            }
            positional if !positional.starts_with('-') => {
                if path.replace(PathBuf::from(positional)).is_some() {
                    return Err("scan accepts at most one project path".to_string());
                }
            }
            other => {
                return Err(format!(
                    "Unknown scan argument: {other}. Run `bifrost scan --help` for the scan options."
                ));
            }
        }
    }

    if list_builtin {
        // A listing answers what ships without running anything, so it
        // refuses every option that would shape a run -- the same discipline
        // the top-level catalog listings follow.
        if path.is_some()
            || format_seen
            || fail_on_seen
            || evaluation_date.is_some()
            || output.is_some()
            || verbose
            || color_seen
        {
            return Err(
                "--list-builtin-policies cannot be combined with a project path or evaluation options"
                    .to_string(),
            );
        }
        let catalog = built_in_policy_catalog().map_err(|error| error.to_string())?;
        let encoded = serde_json::to_string_pretty(catalog.document())
            .map_err(|error| format!("failed to serialize built-in policy catalog: {error}"))?;
        println!("{encoded}");
        return Ok(CliRunResult::Complete);
    }

    if format != PolicyOutputFormat::Human && (verbose || color_seen) {
        return Err("--verbose and --color are only valid with --format human".to_string());
    }

    let root = match path {
        Some(path) => path,
        None => {
            let current = env::current_dir()
                .map_err(|error| format!("Failed to get current directory: {error}"))?;
            eprintln!(
                "bifrost scan: no project path supplied, scanning current directory: {}",
                escape_terminal_text(current.to_string_lossy().as_ref())
            );
            current
        }
    };
    if !root.is_dir() {
        return Err(format!("scan path is not a directory: {}", root.display()));
    }

    let catalog = built_in_policy_catalog().map_err(|error| error.to_string())?;
    let document = catalog.document();
    // The witness surface: which shipped packs this run activates, in the
    // exact line shape `--version` prints, followed by one activation
    // summary. It goes to stderr so stdout stays a single machine document.
    for line in builtin_pack_witness_lines(document, catalog.digest()) {
        eprintln!("{line}");
    }
    eprintln!("{}", scan_activation_summary(document));

    if document.packs.is_empty() {
        // The honest empty-catalog run: the surface ships ahead of the pack
        // wave, so a packless build completes cleanly with zero findings
        // instead of erroring or fabricating a report it cannot evaluate.
        return Ok(CliRunResult::PolicyStatus(POLICY_EXIT_CLEAN));
    }

    let selection = BuiltInPolicySelection {
        packs: document.packs.iter().map(|pack| pack.id.clone()).collect(),
        ..BuiltInPolicySelection::default()
    };
    let policy_inputs = catalog
        .select(&selection)
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|policy| PolicyEvaluationInput::embedded(policy.source_identity(), policy.source()))
        .collect::<Vec<_>>();
    let status = run_policy_mode(
        PolicyModeRequest {
            root,
            format,
            fail_on,
            evaluation_date,
            suppressions: PolicySuppressionOptions::default(),
            scope: PolicyScopeOptions::default(),
            baseline: PolicyBaselineOptions::default(),
            accept_current: false,
            diff_base: None,
            // The scan entry point has no --no-incremental flag; the incremental
            // diff-base review is on by default, as on the policy path.
            incremental: true,
            output,
            verbose,
            color,
            require_explicit_schema_versions: false,
            sources: Vec::new(),
        },
        &policy_inputs,
    );
    Ok(CliRunResult::PolicyStatus(status))
}

/// The pack-identity witness lines shared by `--version` and `scan`: one
/// `builtin-policy-pack <id>@<version> policies=<count>` line per shipped
/// pack, then the catalog digest. One shape on both surfaces, so a parser of
/// either cannot drift from the other and a shipped-catalog change is the
/// same visible event everywhere.
fn builtin_pack_witness_lines(
    document: &BuiltInPolicyCatalogManifest,
    digest: &str,
) -> Vec<String> {
    let mut lines = Vec::with_capacity(document.packs.len() + 1);
    for pack in &document.packs {
        lines.push(format!(
            "builtin-policy-pack {}@{} policies={}",
            pack.id,
            pack.version,
            pack.policies.len()
        ));
    }
    lines.push(format!("builtin-policy-catalog sha256={digest}"));
    lines
}

/// One stderr summary of what a scan activated, honest about a build that
/// ships nothing.
fn scan_activation_summary(document: &BuiltInPolicyCatalogManifest) -> String {
    let policies: usize = document.packs.iter().map(|pack| pack.policies.len()).sum();
    if document.packs.is_empty() {
        "bifrost scan: this build ships no built-in policy packs; nothing was evaluated and there are no findings"
            .to_string()
    } else {
        format!(
            "bifrost scan: activated {} built-in policy packs ({} policies)",
            document.packs.len(),
            policies
        )
    }
}

fn print_scan_help() {
    println!(
        "bifrost scan {} — evaluate every built-in policy pack on a project with zero configuration.",
        env!("CARGO_PKG_VERSION")
    );
    let body = r#"
USAGE:
    bifrost scan [PATH] [OPTIONS]
    bifrost scan --list-builtin-policies

    PATH is the project root to scan (default: current directory).

    A scan activates the complete shipped policy catalog -- no --policy-file,
    no selectors -- and prints the activated pack identities, versions, and
    the catalog SHA-256 to stderr before the report, in the same line shape
    `bifrost --version` prints. Exit status follows the policy contract:
    0 clean, 1 findings at or above the --fail-on threshold, 2 unreliable.
    A build that ships no packs scans to a clean, empty result and says so.

OPTIONS:
    --list-builtin-policies
                           Print the shipped built-in policy catalog as JSON and exit
                           without scanning anything. Cannot be combined with a project
                           path or evaluation options.
    --format FORMAT        Report output: human, json, or sarif (default: human)
    --fail-on THRESHOLD    Finding threshold: never, finding, note, warning, or error
                           (default: warning; finding includes unrated findings)
    --evaluation-date YYYY-MM-DD
                           Evaluate suppression expiration on this UTC date (default: today)
    --output PATH          Atomically write the report to PATH instead of stdout
    --verbose              Include complete evidence and rule details in human output
    --color MODE           Human output color: auto, always, or never (default: auto)
    -h, --help             Show this help

EXAMPLES:
    # The shipped product, out of the box:
    bifrost scan /path/to/project

    # Machine-readable report with the pack witness on stderr:
    bifrost scan /path/to/project --format json

    # Discover what ships without running anything:
    bifrost scan --list-builtin-policies

For explicit policy selection, suppressions, baselines, and diff gating, use
the policy options on the flag surface: see `bifrost --help`.
"#;
    print!("{body}");
}

fn validate_diff_snapshot_object_dir(path: PathBuf) -> Result<PathBuf, String> {
    let path = path.canonicalize().map_err(|err| {
        format!(
            "Failed to resolve --diff-snapshot-object-dir {}: {err}",
            path.display()
        )
    })?;
    if !path.is_dir() {
        return Err(format!(
            "--diff-snapshot-object-dir must name a directory: {}",
            path.display()
        ));
    }
    Ok(path)
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

/// The largest ranking `--explain-near-misses` will retain. The same ceiling
/// the MCP tool's input schema publishes, so the two surfaces cannot drift.
const MAX_EXPLAIN_NEAR_MISSES: usize = 64;

/// One `--explain-near-misses` value: how many ranked subjects to retain.
fn parse_explain_near_misses(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|error| format!("Invalid --explain-near-misses count `{value}`: {error}"))?;
    if parsed == 0 || parsed > MAX_EXPLAIN_NEAR_MISSES {
        return Err(format!(
            "Invalid --explain-near-misses count `{value}`: expected between 1 and \
             {MAX_EXPLAIN_NEAR_MISSES}"
        ));
    }
    Ok(parsed)
}

/// Which explanation question the invocation asked.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ExplanationMode {
    /// Why, or why-not, about one exact subject.
    Explanation(ExplanationTarget),
    /// Which subjects came closest, retaining at most this many.
    NearMiss(usize),
}

/// Resolve the three explanation flags into at most one question.
///
/// The questions exclude each other: a request carrying two would have two
/// answers, and this is stated at parse time rather than at evaluation time so
/// a mistyped invocation fails before a workspace is built.
fn explanation_mode(
    finding: Option<String>,
    candidate: Option<(String, u64, Option<u64>)>,
    near_misses: Option<usize>,
) -> Result<Option<ExplanationMode>, String> {
    let asked = usize::from(finding.is_some())
        + usize::from(candidate.is_some())
        + usize::from(near_misses.is_some());
    if asked > 1 {
        return Err(
            "--explain-finding, --explain-candidate, and --explain-near-misses exclude each other"
                .to_string(),
        );
    }
    if let Some(finding) = finding {
        let parsed = finding
            .parse::<PolicyFindingId>()
            .map_err(|error| format!("Invalid --explain-finding id `{finding}`: {error}"))?;
        return Ok(Some(ExplanationMode::Explanation(
            ExplanationTarget::Finding(parsed),
        )));
    }
    if let Some((path, byte_start, byte_end)) = candidate {
        let parsed = match byte_end {
            Some(byte_end) => ExplanationCandidate::in_range(&path, byte_start, byte_end),
            None => ExplanationCandidate::at_offset(&path, byte_start),
        }
        .map_err(|error| format!("Invalid --explain-candidate: {error}"))?;
        return Ok(Some(ExplanationMode::Explanation(
            ExplanationTarget::Candidate(parsed),
        )));
    }
    Ok(near_misses.map(ExplanationMode::NearMiss))
}

/// Print one bounded policy explanation as JSON.
///
/// # Exit status
///
/// An explanation is a query about a policy, not a gate over a workspace, so a
/// produced explanation always exits `0` -- including when its outcome is
/// `failed` or `unknown`, which are answers rather than verdicts. Only a
/// failure to produce one at all (an unloadable policy, a selection that is
/// not exactly one policy, a family with no adapter, an unknown finding
/// identity, or an output write failure) exits `POLICY_EXIT_UNRELIABLE`.
fn run_policy_explain_mode(
    root: &Path,
    policy_inputs: &[PolicyEvaluationInput],
    target: &ExplanationTarget,
    output: Option<PathBuf>,
) -> u8 {
    let explanation = match explain_policy_inputs(
        root,
        policy_inputs,
        target,
        None,
        None,
        None,
        &ExplanationLimits::default(),
    ) {
        Ok(explanation) => explanation,
        Err(error) => {
            eprintln!(
                "bifrost: policy explanation failed: {}",
                escape_terminal_text(&error.to_string())
            );
            return POLICY_EXIT_UNRELIABLE;
        }
    };
    write_explanation_json(&explanation.to_json(), output)
}

/// Print one bounded near-miss ranking as JSON.
///
/// # Enumeration
///
/// The CLI form always asks for the seed-scoped search, because a shell
/// invocation that already knew the exact positions it wanted measured would
/// have used `--explain-candidate` on each of them. The search is bounded by
/// the policy's own kind, language and path pruning, and a policy whose seed
/// declares no such scope is refused rather than scanned.
///
/// # Exit status
///
/// A ranking is a query about a policy, not a gate, so a produced ranking
/// always exits `0` -- including an empty one, which is the answer "nothing in
/// the policy's own scope came close" rather than a failure. Only a failure to
/// produce one at all exits `POLICY_EXIT_UNRELIABLE`, exactly as the two
/// explanation flags behave.
fn run_policy_near_miss_mode(
    root: &Path,
    policy_inputs: &[PolicyEvaluationInput],
    max_candidates: usize,
    output: Option<PathBuf>,
) -> u8 {
    let ranking = match rank_policy_near_misses(
        root,
        policy_inputs,
        &NearMissCandidates::PolicySeedSearch,
        None,
        None,
        None,
        &ExplanationLimits::default().with_max_near_miss_candidates(max_candidates),
    ) {
        Ok(ranking) => ranking,
        Err(error) => {
            eprintln!(
                "bifrost: policy near-miss ranking failed: {}",
                escape_terminal_text(&error.to_string())
            );
            return POLICY_EXIT_UNRELIABLE;
        }
    };
    write_explanation_json(&ranking.to_json(), output)
}

/// Emit one explanation or ranking document, to a file or to stdout.
fn write_explanation_json(encoded: &str, output: Option<PathBuf>) -> u8 {
    let written = match output.as_deref() {
        Some(path) => write_explanation_output_file(path, encoded),
        None => {
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "{encoded}")
                .and_then(|()| stdout.flush())
                .map_err(|error| error.to_string())
        }
    };
    if let Err(error) = written {
        eprintln!(
            "bifrost: policy explanation output failed: {}",
            escape_terminal_text(&error)
        );
        return POLICY_EXIT_UNRELIABLE;
    }
    POLICY_EXIT_CLEAN
}

/// Atomically replace `destination` with one rendered explanation, following
/// the same temporary-file discipline the report writer uses.
fn write_explanation_output_file(destination: &Path, encoded: &str) -> Result<(), String> {
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
    temporary
        .write_all(encoded.as_bytes())
        .and_then(|()| temporary.write_all(b"\n"))
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| {
            format!(
                "failed to write the temporary explanation for {}: {error}",
                destination.display()
            )
        })?;
    temporary
        .into_temp_path()
        .persist(destination)
        .map_err(|error| {
            format!(
                "failed to atomically replace {}: {error}",
                destination.display()
            )
        })
}

/// Resolved policy-mode invocation state, beyond the policy inputs themselves.
struct PolicyModeRequest {
    root: PathBuf,
    format: PolicyOutputFormat,
    fail_on: PolicyFailOn,
    evaluation_date: Option<PolicyEvaluationDate>,
    suppressions: PolicySuppressionOptions,
    scope: PolicyScopeOptions,
    baseline: PolicyBaselineOptions,
    accept_current: bool,
    diff_base: Option<String>,
    incremental: bool,
    output: Option<PathBuf>,
    verbose: bool,
    color: PolicyColorMode,
    require_explicit_schema_versions: bool,
    sources: Vec<String>,
}

fn run_policy_mode(request: PolicyModeRequest, policy_inputs: &[PolicyEvaluationInput]) -> u8 {
    let evaluation_date = match request.evaluation_date {
        Some(date) => date,
        None => {
            let today = Utc::now().date_naive();
            match PolicyEvaluationDate::from_ymd(today.year(), today.month(), today.day()) {
                Ok(date) => date,
                Err(error) => {
                    eprintln!(
                        "bifrost: failed to determine the policy evaluation date: {}",
                        escape_terminal_text(&error.to_string())
                    );
                    return POLICY_EXIT_UNRELIABLE;
                }
            }
        }
    };
    let mut options =
        PolicyEvaluationOptions::with_suppressions(evaluation_date, request.suppressions.clone())
            .with_scope(request.scope.clone())
            .with_baseline(request.baseline.clone())
            .with_required_schema_versions(request.require_explicit_schema_versions)
            .with_fail_on(request.fail_on)
            .with_incremental(request.incremental);
    if let Some(revision) = request.diff_base.clone() {
        options = options.with_diff_base(revision);
    }
    let evaluation = if request.sources.is_empty() {
        evaluate_policy_inputs(&request.root, policy_inputs, &options)
            .map_err(|error| error.to_string())
    } else {
        create_scoped_service(request.root.clone(), &request.sources, None).and_then(|service| {
            service.evaluate_policy_inputs(&request.root, policy_inputs, &options)
        })
    };
    let outcome = match evaluation {
        Ok(outcome) => outcome,
        Err(error) => {
            eprintln!(
                "bifrost: policy evaluation failed: {}",
                escape_terminal_text(&error.to_string())
            );
            return POLICY_EXIT_UNRELIABLE;
        }
    };
    if brokk_bifrost::profiling::enabled() {
        for timing in outcome.stage_attribution() {
            brokk_bifrost::profiling::duration(
                format!("policy.stage.{:?}", timing.stage()),
                std::time::Duration::from_millis(timing.elapsed_ms()),
            );
        }
    }
    if request.accept_current {
        // Only a clean status (reliable, exhaustive, nothing gating under the
        // forced fail-on Never) may define a baseline; an unreliable run is
        // refused and nothing is written.
        if outcome.exit_status() == POLICY_EXIT_CLEAN {
            if let Err(error) = write_accepted_baseline(&request, &outcome, evaluation_date) {
                eprintln!(
                    "bifrost: baseline write failed: {}",
                    escape_terminal_text(&error)
                );
                return POLICY_EXIT_UNRELIABLE;
            }
        } else {
            eprintln!(
                "bifrost: the policy run was not reliable and exhaustive; no baseline was written"
            );
        }
    }
    let output_path = request.output.as_deref();
    let human_options = HumanRenderOptions::new(
        if request.verbose {
            HumanRenderDetail::Verbose
        } else {
            HumanRenderDetail::Concise
        },
        resolve_policy_color(request.color, output_path.is_none()),
    );
    let status = outcome.exit_status();
    let write_result = match output_path {
        Some(path) => write_policy_output_file(path, request.format, &human_options, &outcome),
        None => write_policy_stdout(request.format, &human_options, &outcome),
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

/// Build the baseline document from one clean run's report and atomically
/// replace the configured baseline file beneath the analyzed root.
fn write_accepted_baseline(
    request: &PolicyModeRequest,
    outcome: &PolicyBatchOutcome,
    accepted_at: PolicyEvaluationDate,
) -> Result<(), String> {
    let (document, weak_excluded) = PolicyBaselineDocument::from_completed_report(
        outcome.report(),
        "Bulk baseline acceptance of existing findings via --accept-current",
        None,
        accepted_at,
    )
    .map_err(|error| format!("failed to build the baseline document: {error}"))?;
    let relative = request.baseline.source().relative_path();
    let destination = request.root.join(relative);
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|error| {
        format!(
            "failed to create a temporary baseline beside {}: {error}",
            destination.display()
        )
    })?;
    temporary
        .write_all(document.to_canonical_json().as_bytes())
        .and_then(|()| temporary.flush())
        .map_err(|error| {
            format!(
                "failed to write the temporary baseline for {}: {error}",
                destination.display()
            )
        })?;
    temporary.as_file().sync_all().map_err(|error| {
        format!(
            "failed to sync the temporary baseline for {}: {error}",
            destination.display()
        )
    })?;
    temporary
        .into_temp_path()
        .persist(&destination)
        .map_err(|error| {
            format!(
                "failed to atomically replace {}: {error}",
                destination.display()
            )
        })?;
    eprintln!(
        "bifrost: baseline accepted {} findings into {} ({} weak-identity findings excluded)",
        document.entry_count(),
        escape_terminal_text(relative),
        weak_excluded,
    );
    Ok(())
}

fn resolve_policy_color(mode: PolicyColorMode, writing_stdout: bool) -> HumanRenderColor {
    match mode {
        PolicyColorMode::Always => HumanRenderColor::Ansi,
        PolicyColorMode::Never => HumanRenderColor::Plain,
        PolicyColorMode::Auto if writing_stdout && stdout_supports_color() => {
            HumanRenderColor::Ansi
        }
        PolicyColorMode::Auto => HumanRenderColor::Plain,
    }
}

fn stdout_supports_color() -> bool {
    auto_color_enabled(
        io::stdout().is_terminal(),
        env::var_os("NO_COLOR").is_some(),
        terminal_supports_ansi(),
    )
}

const fn auto_color_enabled(
    is_terminal: bool,
    no_color_present: bool,
    ansi_supported: bool,
) -> bool {
    is_terminal && !no_color_present && ansi_supported
}

#[cfg(unix)]
const fn terminal_supports_ansi() -> bool {
    true
}

#[cfg(windows)]
const fn terminal_supports_ansi() -> bool {
    // Do not assume that a Windows console has virtual-terminal processing
    // enabled. `--color always` remains the explicit opt-in for ANSI-capable
    // terminals; auto mode chooses the safe plain representation.
    false
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

/// Cancel this one-shot run, and eventually exit, when the parent process
/// dies — public issue #11.
///
/// The npm launcher forwards catchable signals, but a kill-on-drop SIGKILL of
/// the launcher delivers nothing here and orphans this process mid-analysis:
/// observed as a native `analyze_diff` burning a full core for over an hour
/// after its caller timed out. Reparenting is the reliable, signal-free
/// indicator of parent death on Unix, so poll it. Stdin EOF is not usable as
/// the signal because a detached caller may hand this process `/dev/null`.
/// After cancelling, allow a bounded grace for the cooperative walks to
/// unwind, then exit: an orphaned one-shot has no reader left for its stdout.
#[cfg(unix)]
fn spawn_orphan_watchdog(cancellation: CancellationToken) {
    let initial_parent = unsafe { libc::getppid() };
    std::thread::Builder::new()
        .name("orphan-watchdog".into())
        .spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(2));
                if unsafe { libc::getppid() } != initial_parent {
                    eprintln!("bifrost: parent process exited; cancelling one-shot tool run");
                    cancellation.cancel();
                    std::thread::sleep(std::time::Duration::from_secs(20));
                    eprintln!("bifrost: exiting after the orphaned-run grace period");
                    std::process::exit(3);
                }
            }
        })
        .expect("spawn orphan watchdog");
}

fn run_tool(
    root: PathBuf,
    tool_name: &str,
    tool_args: Value,
    tool_sources: &[String],
    render_options: McpRenderOptions,
    diff_snapshot_object_dir: Option<PathBuf>,
    workspace_scaled_limits: bool,
) -> Result<(), String> {
    let canonical_root = root
        .canonicalize()
        .map_err(|err| format!("Failed to resolve project root {}: {err}", root.display()))?;
    let (arguments, overlays) =
        normalize_tool_arguments_for_cli(tool_name, tool_args, &canonical_root)?;
    let service = create_cli_tool_service(canonical_root, tool_name, tool_sources, overlays)?;
    let service = match diff_snapshot_object_dir {
        Some(dir) => service.with_diff_snapshot_object_dir(dir),
        None => service,
    };
    // The one-shot CLI is the trusted host of its own query file, so it may
    // grant the audited workspace's budget. An MCP client never can.
    let service = if workspace_scaled_limits {
        service.with_workspace_scaled_query_limits()
    } else {
        service
    };
    let cancellation = CancellationToken::new();
    #[cfg(unix)]
    spawn_orphan_watchdog(cancellation.clone());
    let output = service
        .call_tool_output_with_cancellation(
            tool_name,
            arguments,
            RenderOptions {
                render_line_numbers: render_options.render_line_numbers,
            },
            Some(&cancellation),
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
    bifrost scan [PATH]        Evaluate every built-in policy pack on a project with zero
                               configuration, witnessing the activated pack set on stderr.
                               Run `bifrost scan --help` for the scan options.
    bifrost                  Run an MCP server over stdio (default: --mcp searchtools)
    bifrost --mcp TOOLSETS     Run an MCP server over stdio (e.g. --mcp core)
    bifrost --lsp              Run a Language Server (LSP) over stdio
    bifrost --repl             Run the interactive code-query REPL
    bifrost --tool NAME        Run a single tool once, print JSON result, and exit
    bifrost --query-file PATH  Run a .rql or .json code query once, print JSON result, and exit
    bifrost --install          Register brokk with installed coding hosts and exit
    bifrost --policy           Evaluate the built-in policy packs on the project and exit
    bifrost --policy-file PATH Evaluate workspace or built-in static-analysis policies and exit
    bifrost --list-policies    Print the built-in policy catalog and exit
    bifrost --list-row-schemas Print the row-relation field catalog and exit
    bifrost --version | --help [TOOL]

OPTIONS:
    --install              Register a user-scoped brokk MCP server with Codex, Claude Code,
                           OpenCode, Kimi Code, Hermes, and Oh My Pi. This option does not
                           install host applications, skills, instructions, or Pi extensions.
    --root DIR             Project root to analyze (default: current directory)
    --workspace NAME=PATH  Named project root for MCP mode; repeat as needed.
                           Cannot be combined with --root. Requires --mcp.
                           Root and nested .bifrostignore files exclude matching tracked or
                           untracked files from code intelligence, but not file-level tools.
    --diff-snapshot-object-dir DIR
                           Trusted Git objects directory for immutable diff-tool endpoints;
                           valid only with --tool and MCP server modes.
    --args JSON            Inline JSON arguments for --tool, e.g. '{"patterns":["MyClass"]}'.
                           File path arguments may use <commit-ish>:<path> in --tool mode.
                           Optional; omission supplies {}, which suits get_active_workspace and
                           the default diff-tool worktree comparison.
    --query-file PATH      Run a workspace-relative .rql or .json CodeQuery directly.
    --workspace-scaled-limits
                           Run --query-file with the source-volume-scaled execution limits
                           policy evaluation uses, instead of the interactive defaults. Only
                           for a host that trusts its own query file: it is a CLI option, not
                           a field the query document can set.
    --sources PATH         Restrict one-shot --tool or policy workspace construction to selected
                           files, directories, or globs. Repeatable. Explicit sources override
                           .bifrostignore.
    --policy               Enter policy mode explicitly. A policy invocation with no
                           --policy-file and no built-in selector evaluates every built-in
                           policy pack; any explicit selection replaces that default.
    --no-builtin-policies  Refuse the built-in default: evaluate only explicit --policy-file
                           inputs. Requires at least one --policy-file and cannot be combined
                           with --policy-pack, --policy-category, or --policy-id.
    --policy-file PATH     Evaluate a workspace-relative .rqlp policy. Repeatable.
    --policy-pack ID       Evaluate every built-in policy in a pack. Repeatable.
    --policy-category NAME Evaluate built-in policies in a category. Repeatable.
    --policy-id ID         Evaluate one built-in policy by stable id. Repeatable.
                           Repeating one selector widens it; combining different
                           selectors narrows: --policy-pack P --policy-id I runs I
                           only, and errors when I is not in P.
    --list-policies        Print the deterministic built-in policy catalog as JSON
    --list-row-schemas     Print the deterministic bifrost_relation_schema/v1 catalog as JSON:
                           every row domain a relational policy may bind, each field's scalar
                           type, nullability, join-key status, and enum values, and the
                           expansions admitted from the domain. The REPL's :doc <row-domain>
                           prints one domain of the same catalog.
    --format FORMAT        Policy output: human, json, or sarif (default: human)
    --verbose              Include complete evidence, provenance, and rule details in human output
    --color MODE           Human output color: auto, always, or never (default: auto)
    --fail-on THRESHOLD    Policy finding threshold: never, finding, note, warning, or error
                           (default: warning; finding includes unrated findings)
    --suppressions-file PATH
                           Load accepted findings from this workspace-relative JSON file
                           (default: .bifrost/suppressions.json)
    --scope-file PATH      Load accepted directory scopes from this workspace-relative JSON file
                           (default: .bifrost/policy-scope.json)
    --baseline-file PATH   Load bulk-accepted finding identities from this workspace-relative
                           JSON file (default: .bifrost/baseline.json)
    --accept-current       Run the selected policies and write the baseline document accepting
                           every current strong unclaimed finding, then exit 0. An unreliable
                           run refuses to define a baseline and exits 2 without writing.
                           Cannot be combined with --fail-on or --diff-base
    --evaluation-date YYYY-MM-DD
                           Evaluate suppression expiration on this UTC date (default: today)
    --diff-base REV        Also evaluate the committed content of this git revision, classify
                           each finding as new or persisting against it, and fail only on new
                           findings. REV is any revision git rev-parse accepts; pass the pull
                           request's merge base in CI. An unresolvable base is unreliable (exit 2)
    --no-incremental       Evaluate every policy in full instead of reusing per-unit results a
                           previous run published in this repository's analyzer cache. Reuse is on
                           by default and produces the same findings; this switch is for comparing
                           against the full dual-snapshot evaluation when diagnosing a difference
    --require-explicit-schema-versions
                           Reject inferred policy and RQL schema versions
    --explain-finding ID   Explain why the selected policy's run produced the finding with this
                           stable id, and print the bounded explanation JSON. The selection must
                           resolve to exactly one policy
    --explain-candidate PATH:BYTE_START[-BYTE_END]
                           Explain why the selected policy did not report this exact position,
                           and print the bounded explanation JSON. Nothing is scanned for: the
                           position you pass is the one explained
    --explain-near-misses N
                           Rank the N subjects that came closest to satisfying the selected
                           policy, and print the bounded ranking JSON. Each entry says how many
                           of the policy's own declared predicates it missed and names the first
                           one it failed. Candidates come from the policy's own seed scope --
                           its kind union, language filter and path globs -- so a policy whose
                           seed declares no such scope is refused rather than scanned; the
                           repository is never walked
                           All three explanation flags are queries, not gates: a produced answer
                           exits 0 even when its outcome is failed or unknown and even when a
                           ranking is empty, and only a failure to produce one exits 2. They
                           exclude each other, and none can be combined with --format,
                           --fail-on, --suppressions-file, --scope-file, --baseline-file,
                           --accept-current, --evaluation-date, --diff-base, --verbose, or --color
    --output PATH          Atomically write policy output to PATH instead of stdout
    --no-line-numbers      Render source output without leading line numbers
    -h, --help [TOOL]      Show this help, or a single tool's description and parameters
    -V, --version          Show version and exit
        --build-identity   Show the exact embedded source identity and exit

MCP TOOLSETS (--mcp):
    searchtools   every toolset below
    core          symbol + workspace + diff (the set agents typically connect to)
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
    classify_test_files is programmatic-only: no toolset above exposes it to MCP
    agents, but `bifrost --tool classify_test_files` and the Rust/Python API still
    run it.

EXAMPLES:
    # MCP server from the current directory, using the compatibility searchtools set:
    bifrost

    # MCP server an agent connects to (core toolset), speaking MCP over stdio:
    bifrost --root /path/to/project --mcp core

    # One server with two fixed named workspaces:
    bifrost --workspace api=/src/api --workspace ui=/src/ui --mcp core

    # One-shot: run a single tool and print its JSON result, then exit:
    bifrost --root /path/to/project --tool search_symbols --args '{"patterns":["MyClass"]}'

    # Run a saved RQL or JSON code query (current directory is the default root):
    bifrost --query-file queries/audit.rql

    # Evaluate two policy roots together and emit one canonical JSON report:
    bifrost --root /path/to/project --policy-file policies/security.rqlp --policy-file policies/correctness.rqlp --evaluation-date 2026-07-27 --format json

    # Iterate on one policy against a small source subset:
    bifrost --root /path/to/project --policy-file policies/security.rqlp --sources src/auth --sources 'tests/auth/**/*.rs'

    # Evaluate every built-in policy pack with zero configuration:
    bifrost --root /path/to/project --policy

    # Discover the row domains, fields, and expansions a relational policy may bind:
    bifrost --list-row-schemas

    # Discover and run the built-in code-smell pack:
    bifrost --list-policies
    bifrost --root /path/to/project --policy-pack bifrost.code-smells --evaluation-date 2026-07-28 --format json

    # Human code-query exploration with S-expressions, completion, docs, and history:
    bifrost --root /path/to/project --repl

    # One-shot against a subset workspace built from a directory and a glob:
    bifrost --root /path/to/project --tool get_symbol_sources --sources src --sources 'tests/**/*.rs' --args '{"symbols":["src/main.rs"]}'

    # Language server over stdio:
    bifrost --root /path/to/project --lsp

Servers speak their protocol over stdio (no network port). The workspace index is built
in the background: the server is ready immediately and the first request waits for indexing.
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
    // `searchtools` advertises every agent-facing tool, so it is the primary
    // lookup surface. A handful of tools are programmatic-only and never in
    // an MCP toolset (`classify_test_files`, issue #1116); their descriptors
    // live in `single_shot_only_tool_descriptors` instead, so `--help
    // classify_test_files` and `--tool classify_test_files` still document
    // and run it even though no `--mcp` mode exposes it.
    let spec = resolve_server_spec("searchtools")?;
    let descriptor = spec
        .tool_descriptors
        .into_iter()
        .chain(single_shot_only_tool_descriptors())
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
                    // A parameter whose schema documents a generated vocabulary
                    // -- `query_code`'s `steps` carries the RQL step reference,
                    // one line per step -- keeps that shape here instead of
                    // collapsing onto one unreadable line.
                    for line in description.lines() {
                        println!("        {line}");
                    }
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

#[cfg(test)]
mod policy_color_tests {
    use super::auto_color_enabled;

    #[test]
    fn auto_color_requires_an_ansi_terminal_and_respects_no_color() {
        assert!(auto_color_enabled(true, false, true));
        assert!(!auto_color_enabled(false, false, true));
        assert!(!auto_color_enabled(true, true, true));
        assert!(!auto_color_enabled(true, false, false));
    }
}

#[cfg(test)]
mod named_workspace_cli_tests {
    use super::run;

    #[test]
    fn named_workspace_requires_mcp_mode() {
        let error = match run(["--workspace".to_string(), "api=/repo/api".to_string()].into_iter())
        {
            Err(error) => error,
            Ok(_) => panic!("workspace without MCP must fail"),
        };
        assert_eq!(error.message, "--workspace requires --mcp");
    }

    #[test]
    fn named_workspace_and_root_are_mutually_exclusive() {
        let error = match run([
            "--root",
            "/repo",
            "--workspace",
            "api=/repo/api",
            "--mcp",
            "core",
        ]
        .into_iter()
        .map(str::to_string))
        {
            Err(error) => error,
            Ok(_) => panic!("root and workspace must fail"),
        };
        assert_eq!(error.message, "--workspace cannot be combined with --root");
    }
}

/// Flag-level coverage for the three policy explanation flags (issue 2439
/// slice 3, issue 2500).
///
/// These exercise parsing and the mutual-exclusion discipline without building
/// a workspace: every case here is decided before any analyzer exists, which is
/// exactly the property that makes a mistyped invocation cheap.
#[cfg(test)]
mod policy_explain_cli_tests {
    use super::{
        ExplanationMode, ExplanationTarget, MAX_EXPLAIN_NEAR_MISSES, explanation_mode,
        has_policy_syntax, parse_explain_candidate, parse_explain_near_misses, run,
    };

    fn run_error(args: &[&str]) -> String {
        match run(args.iter().map(|argument| (*argument).to_string())) {
            Err(error) => {
                assert!(
                    error.policy_invocation,
                    "an explanation flag is a policy invocation, so its failure exits 2"
                );
                error.message
            }
            Ok(_) => panic!("expected {args:?} to fail"),
        }
    }

    #[test]
    fn the_explanation_flags_are_policy_syntax() {
        for flag in [
            "--explain-finding",
            "--explain-candidate",
            "--explain-near-misses",
        ] {
            assert!(has_policy_syntax(&[flag.to_string(), "x".to_string()]));
        }
    }

    #[test]
    fn a_candidate_parses_a_point_and_a_range() {
        assert_eq!(
            parse_explain_candidate("src/app.ts:42").expect("a point candidate"),
            (String::from("src/app.ts"), 42, None)
        );
        assert_eq!(
            parse_explain_candidate("src/app.ts:42-50").expect("a range candidate"),
            (String::from("src/app.ts"), 42, Some(50))
        );
        // The separator is the last colon, so a path containing one survives.
        assert_eq!(
            parse_explain_candidate("a:b/app.ts:7").expect("a colon in the path"),
            (String::from("a:b/app.ts"), 7, None)
        );
        assert!(parse_explain_candidate("src/app.ts").is_err());
        assert!(parse_explain_candidate("src/app.ts:notanumber").is_err());
        assert!(parse_explain_candidate(":7").is_err());
    }

    #[test]
    fn a_near_miss_count_is_bounded_on_both_sides() {
        assert_eq!(parse_explain_near_misses("5").expect("a count"), 5);
        assert_eq!(
            parse_explain_near_misses(&MAX_EXPLAIN_NEAR_MISSES.to_string()).expect("the ceiling"),
            MAX_EXPLAIN_NEAR_MISSES
        );
        for rejected in [
            "0",
            &(MAX_EXPLAIN_NEAR_MISSES + 1).to_string(),
            "-1",
            "many",
        ] {
            assert!(
                parse_explain_near_misses(rejected).is_err(),
                "{rejected} is not a ranking size"
            );
        }
    }

    #[test]
    fn a_mode_refuses_more_than_one_question_and_validates_each_one() {
        assert_eq!(
            explanation_mode(None, None, None).expect("no question"),
            None
        );
        for (finding, candidate, near_misses) in [
            (
                Some("0".repeat(64)),
                Some((String::from("app.ts"), 0, None)),
                None,
            ),
            (Some("0".repeat(64)), None, Some(4)),
            (None, Some((String::from("app.ts"), 0, None)), Some(4)),
        ] {
            assert_eq!(
                explanation_mode(finding, candidate, near_misses)
                    .expect_err("two questions have two answers"),
                "--explain-finding, --explain-candidate, and --explain-near-misses exclude each \
                 other"
            );
        }
        assert!(matches!(
            explanation_mode(Some("0".repeat(64)), None, None).expect("a valid identity"),
            Some(ExplanationMode::Explanation(ExplanationTarget::Finding(_)))
        ));
        assert!(
            explanation_mode(Some(String::from("nope")), None, None)
                .expect_err("a finding id is a lowercase sha-256")
                .contains("Invalid --explain-finding")
        );
        assert!(matches!(
            explanation_mode(None, Some((String::from("app.ts"), 3, Some(9))), None)
                .expect("a valid candidate"),
            Some(ExplanationMode::Explanation(ExplanationTarget::Candidate(
                _
            )))
        ));
        assert_eq!(
            explanation_mode(None, None, Some(7)).expect("a valid ranking size"),
            Some(ExplanationMode::NearMiss(7))
        );
        // A path outside the workspace and a reversed range are both refused.
        assert!(
            explanation_mode(None, Some((String::from("../outside.ts"), 0, None)), None)
                .expect_err("a candidate stays inside the workspace")
                .contains("Invalid --explain-candidate")
        );
        assert!(
            explanation_mode(None, Some((String::from("app.ts"), 9, Some(4))), None)
                .expect_err("a range does not end before it starts")
                .contains("exceeds end")
        );
    }

    #[test]
    fn an_explanation_cannot_be_combined_with_a_gate() {
        for gate in [
            vec!["--format", "json"],
            vec!["--fail-on", "error"],
            vec!["--suppressions-file", "s.json"],
            vec!["--scope-file", "s.json"],
            vec!["--baseline-file", "b.json"],
            vec!["--accept-current"],
            vec!["--evaluation-date", "2026-08-20"],
            vec!["--diff-base", "HEAD~1"],
            vec!["--verbose"],
            vec!["--color", "never"],
        ] {
            for question in [
                vec!["--explain-candidate", "app.ts:0"],
                vec!["--explain-near-misses", "5"],
            ] {
                let mut args = vec!["--policy-file", "policies/p.rqlp"];
                args.extend(question.iter().copied());
                args.extend(gate.iter().copied());
                let message = run_error(&args);
                assert!(
                    message.contains(
                        "--explain-finding, --explain-candidate, and --explain-near-misses cannot \
                         be combined"
                    ),
                    "{gate:?} must be refused beside {question:?}: {message}"
                );
            }
        }
    }

    #[test]
    fn an_explanation_cannot_be_combined_with_listing_or_the_other_question() {
        for question in [
            vec!["--explain-candidate", "app.ts:0"],
            vec!["--explain-near-misses", "5"],
        ] {
            let mut args = vec!["--list-policies"];
            args.extend(question.iter().copied());
            let message = run_error(&args);
            assert!(
                message.contains("--list-policies cannot be combined"),
                "{message}"
            );
        }

        let message = run_error(&[
            "--policy-file",
            "policies/p.rqlp",
            "--explain-finding",
            &"0".repeat(64),
            "--explain-candidate",
            "app.ts:0",
        ]);
        assert_eq!(
            message,
            "--explain-finding, --explain-candidate, and --explain-near-misses exclude each other"
        );
    }

    #[test]
    fn each_explanation_flag_may_be_given_once_and_requires_a_value() {
        let message = run_error(&[
            "--policy-file",
            "policies/p.rqlp",
            "--explain-candidate",
            "app.ts:0",
            "--explain-candidate",
            "app.ts:1",
        ]);
        assert_eq!(message, "--explain-candidate may only be provided once");

        let message = run_error(&["--policy-file", "policies/p.rqlp", "--explain-finding"]);
        assert!(message.contains("--explain-finding requires"), "{message}");

        let message = run_error(&[
            "--policy-file",
            "policies/p.rqlp",
            "--explain-near-misses",
            "5",
            "--explain-near-misses",
            "6",
        ]);
        assert_eq!(message, "--explain-near-misses may only be provided once");

        let message = run_error(&["--policy-file", "policies/p.rqlp", "--explain-near-misses"]);
        assert!(
            message.contains("--explain-near-misses requires"),
            "{message}"
        );

        let message = run_error(&[
            "--policy-file",
            "policies/p.rqlp",
            "--explain-near-misses",
            "0",
        ]);
        assert!(
            message.contains("Invalid --explain-near-misses count"),
            "{message}"
        );
    }

    #[test]
    fn an_explanation_still_requires_a_policy_selection() {
        for question in [
            vec!["--explain-candidate", "app.ts:0"],
            vec!["--explain-near-misses", "5"],
        ] {
            let message = run_error(&question);
            assert!(
                message.contains(
                    "policy explanation requires an explicit --policy-file or built-in policy \
                     selector"
                ),
                "{message}"
            );
        }
    }
}

/// Flag-level coverage for the zero-configuration built-in default (issue
/// 2853): the explicit policy-mode entry and the controlled-run opt-out.
///
/// Only refusals are exercised in-process; the default catalog run itself
/// builds a workspace and lives in the workspace-level CLI suite.
#[cfg(test)]
mod builtin_default_cli_tests {
    use super::{has_policy_syntax, run};

    fn run_error(args: &[&str]) -> String {
        match run(args.iter().map(|argument| (*argument).to_string())) {
            Err(error) => {
                assert!(error.policy_invocation, "{args:?} is a policy invocation");
                error.message
            }
            Ok(_) => panic!("expected {args:?} to fail"),
        }
    }

    #[test]
    fn the_policy_entry_and_the_opt_out_are_policy_syntax() {
        assert!(has_policy_syntax(&["--policy".to_string()]));
        assert!(has_policy_syntax(&["--no-builtin-policies".to_string()]));
    }

    #[test]
    fn the_opt_out_refuses_builtin_selectors_and_requires_a_policy_file() {
        for selector in [
            vec!["--policy-pack", "bifrost.code-smells"],
            vec!["--policy-category", "correctness"],
            vec!["--policy-id", "bifrost.correctness.dynamic-evaluation"],
        ] {
            let mut args = vec!["--no-builtin-policies"];
            args.extend(selector.iter().copied());
            let message = run_error(&args);
            assert_eq!(
                message,
                "--no-builtin-policies cannot be combined with --policy-pack, \
                 --policy-category, or --policy-id"
            );
        }
        for args in [
            vec!["--no-builtin-policies"],
            vec!["--policy", "--no-builtin-policies"],
        ] {
            let message = run_error(&args);
            assert_eq!(
                message,
                "--no-builtin-policies requires at least one --policy-file"
            );
        }
    }

    #[test]
    fn listing_refuses_the_policy_entry_flags() {
        for flag in ["--policy", "--no-builtin-policies"] {
            let message = run_error(&["--list-policies", flag]);
            assert!(
                message.contains("--list-policies cannot be combined"),
                "{message}"
            );
        }
    }
}

/// Flag-level coverage for the row-schema listing (issue #2517).
///
/// The printed catalog itself is asserted end to end in the policy CLI suite,
/// which can read the process's stdout; these cases pin the refusals, which is
/// the part a caller cannot discover from the output.
#[cfg(test)]
mod row_schema_listing_cli_tests {
    use super::{CliRunResult, has_policy_syntax, run};

    fn run_error(args: &[&str]) -> String {
        match run(args.iter().map(|argument| (*argument).to_string())) {
            Err(error) => {
                assert!(
                    error.policy_invocation,
                    "a listing flag is a policy invocation, so its failure exits 2"
                );
                error.message
            }
            Ok(_) => panic!("expected {args:?} to fail"),
        }
    }

    #[test]
    fn the_listing_flag_is_policy_syntax_and_needs_no_workspace() {
        assert!(has_policy_syntax(&["--list-row-schemas".to_string()]));
        match run(["--list-row-schemas".to_string()].into_iter()) {
            Ok(CliRunResult::Complete) => {}
            Ok(CliRunResult::PolicyStatus(status)) => {
                panic!("a listing completes rather than gating, got status {status}")
            }
            Err(error) => panic!("{}", error.message),
        }
    }

    #[test]
    fn the_two_listings_exclude_each_other_and_repeat_once() {
        assert_eq!(
            run_error(&["--list-row-schemas", "--list-policies"]),
            "--list-policies cannot be combined with --list-row-schemas"
        );
        assert_eq!(
            run_error(&["--list-policies", "--list-row-schemas"]),
            "--list-row-schemas cannot be combined with --list-policies"
        );
        assert_eq!(
            run_error(&["--list-row-schemas", "--list-row-schemas"]),
            "--list-row-schemas may only be provided once"
        );
        assert_eq!(
            run_error(&["--list-policies", "--list-policies"]),
            "--list-policies may only be provided once"
        );
    }

    #[test]
    fn the_listing_refuses_selection_evaluation_and_explanation_options() {
        for options in [
            vec!["--policy-file", "policies/p.rqlp"],
            vec!["--policy-pack", "bifrost.code-smells"],
            vec!["--policy"],
            vec!["--format", "json"],
            vec!["--fail-on", "error"],
            vec!["--accept-current"],
            vec!["--diff-base", "HEAD"],
        ] {
            let mut args = vec!["--list-row-schemas"];
            args.extend(options.iter().copied());
            assert_eq!(
                run_error(&args),
                "--list-row-schemas cannot be combined with policy selection or evaluation options",
                "{options:?} must be refused beside the listing"
            );
        }
        for question in [
            vec!["--explain-candidate", "app.ts:0"],
            vec!["--explain-near-misses", "5"],
        ] {
            let mut args = vec!["--list-row-schemas"];
            args.extend(question.iter().copied());
            assert_eq!(
                run_error(&args),
                "--list-row-schemas cannot be combined with --explain-finding, \
                 --explain-candidate, or --explain-near-misses",
                "{question:?} must be refused beside the listing"
            );
        }
    }
}

/// Exit-status coverage for policy explanation mode.
///
/// The workspace-level CLI suite exercises the flags end to end; these two
/// cases pin the documented exit contract itself, which is the part a caller
/// scripts against.
#[cfg(test)]
mod policy_explain_exit_status_tests {
    use super::{
        ExplanationCandidate, ExplanationTarget, POLICY_EXIT_CLEAN, POLICY_EXIT_UNRELIABLE,
        PolicyEvaluationInput, run_policy_explain_mode, run_policy_near_miss_mode,
    };
    use serde_json::Value;

    const POLICY: &str = r#"(policy
  :id "test.cli.explain"
  :name "Widget"
  :message "Widget is reported"
  :severity warning
  :analysis (analysis :type match :selector (rql (class :name "Widget"))))"#;

    fn workspace() -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("temp dir");
        std::fs::write(
            temp.path().join("Widget.java"),
            "class Widget {\n  int render() { return 1; }\n}\n",
        )
        .expect("write source");
        std::fs::create_dir_all(temp.path().join("policies")).expect("policy directory");
        std::fs::write(temp.path().join("policies/explain.rqlp"), POLICY).expect("write policy");
        temp
    }

    #[test]
    fn a_produced_explanation_exits_clean_and_writes_the_versioned_json() {
        let temp = workspace();
        let root = temp.path().canonicalize().expect("canonical root");
        let destination = root.join("explanation.json");
        // A candidate the selector definitely drops: the outcome is `failed`,
        // and a failed answer is still an answer, so the status stays 0.
        let candidate =
            ExplanationCandidate::at_offset("Widget.java", 0).expect("a workspace candidate");
        let status = run_policy_explain_mode(
            &root,
            &[PolicyEvaluationInput::workspace_file(
                "policies/explain.rqlp",
            )],
            &ExplanationTarget::Candidate(candidate),
            Some(destination.clone()),
        );
        assert_eq!(status, POLICY_EXIT_CLEAN);

        let written = std::fs::read_to_string(&destination).expect("the explanation was written");
        let value: Value = serde_json::from_str(&written).expect("the explanation is JSON");
        assert_eq!(
            value["format"],
            brokk_bifrost::policy::POLICY_EXPLANATION_FORMAT
        );
        assert_eq!(value["question"], "why_not");
        assert_eq!(value["policy_id"], "test.cli.explain");
    }

    #[test]
    fn a_failure_to_produce_an_explanation_exits_unreliable() {
        let temp = workspace();
        let root = temp.path().canonicalize().expect("canonical root");
        let candidate =
            ExplanationCandidate::at_offset("Widget.java", 0).expect("a workspace candidate");
        let status = run_policy_explain_mode(
            &root,
            &[PolicyEvaluationInput::workspace_file(
                "policies/absent.rqlp",
            )],
            &ExplanationTarget::Candidate(candidate),
            None,
        );
        assert_eq!(status, POLICY_EXIT_UNRELIABLE);
    }

    #[test]
    fn a_produced_ranking_exits_clean_and_writes_the_versioned_json() {
        let temp = workspace();
        let root = temp.path().canonicalize().expect("canonical root");
        let destination = root.join("near-misses.json");
        let status = run_policy_near_miss_mode(
            &root,
            &[PolicyEvaluationInput::workspace_file(
                "policies/explain.rqlp",
            )],
            4,
            Some(destination.clone()),
        );
        assert_eq!(status, POLICY_EXIT_CLEAN);

        let written = std::fs::read_to_string(&destination).expect("the ranking was written");
        let value: Value = serde_json::from_str(&written).expect("the ranking is JSON");
        assert_eq!(
            value["format"],
            brokk_bifrost::policy::POLICY_NEAR_MISS_FORMAT
        );
        assert_eq!(value["question"], "near_miss");
        assert_eq!(value["policy_id"], "test.cli.explain");
        assert_eq!(
            value["conjuncts"],
            serde_json::json!(["scope", "root.name"])
        );
        // The fixture holds one class, which the selector selects, so the
        // ranking holds exactly that subject at distance 0.
        assert_eq!(value["entries"][0]["unsatisfied_conjuncts"], 0);
        assert_eq!(value["entries"][0]["outcome"], "satisfied");
    }

    #[test]
    fn a_failure_to_produce_a_ranking_exits_unreliable() {
        let temp = workspace();
        let root = temp.path().canonicalize().expect("canonical root");
        let status = run_policy_near_miss_mode(
            &root,
            &[PolicyEvaluationInput::workspace_file(
                "policies/absent.rqlp",
            )],
            4,
            None,
        );
        assert_eq!(status, POLICY_EXIT_UNRELIABLE);
    }
}

/// Flag-level coverage for the `scan` subcommand (issue #2882): parsing
/// refusals, the witness/summary shape including the honest empty-catalog
/// case, and the isolation of the flag surface. The zero-configuration run
/// itself builds a workspace and lives in the workspace-level CLI suite.
#[cfg(test)]
mod scan_cli_tests {
    use super::{
        BuiltInPolicyCatalogManifest, built_in_policy_catalog, builtin_pack_witness_lines, run,
        scan_activation_summary,
    };

    fn run_error(args: &[&str]) -> (String, bool) {
        match run(args.iter().map(|argument| (*argument).to_string())) {
            Err(error) => (error.message, error.policy_invocation),
            Ok(_) => panic!("expected {args:?} to fail"),
        }
    }

    fn empty_manifest() -> BuiltInPolicyCatalogManifest {
        BuiltInPolicyCatalogManifest {
            schema_version: 1,
            packs: Vec::new(),
        }
    }

    #[test]
    fn a_scan_failure_reports_through_the_policy_exit_contract() {
        let (message, policy_invocation) = run_error(&["scan", "--format", "yaml"]);
        assert!(message.contains("Invalid --format value"), "{message}");
        assert!(
            policy_invocation,
            "a scan error is an unreliable policy run"
        );
    }

    #[test]
    fn scan_is_a_subcommand_only_in_the_first_position() {
        // The flag surface is untouched: everywhere else `scan` and the
        // scan-only listing flag remain unknown arguments, so no existing
        // invocation can change behavior.
        let (message, policy_invocation) = run_error(&["--root", "/tmp", "scan"]);
        assert_eq!(message, "Unknown argument: scan");
        assert!(!policy_invocation);
        let (message, _) = run_error(&["--list-builtin-policies"]);
        assert_eq!(message, "Unknown argument: --list-builtin-policies");
    }

    #[test]
    fn scan_parsing_refuses_ambiguous_and_repeated_input() {
        assert_eq!(
            run_error(&["scan", "a", "b"]).0,
            "scan accepts at most one project path"
        );
        assert_eq!(
            run_error(&["scan", "--fail-on", "never", "--fail-on", "error"]).0,
            "--fail-on may only be provided once"
        );
        let (message, _) = run_error(&["scan", "--policy-file", "p.rqlp"]);
        assert!(
            message.contains("Unknown scan argument: --policy-file"),
            "explicit selection belongs to the flag surface, not to scan: {message}"
        );
        assert_eq!(
            run_error(&["scan", "--format", "json", "--verbose"]).0,
            "--verbose and --color are only valid with --format human"
        );
    }

    #[test]
    fn the_builtin_listing_answers_without_running_anything() {
        for options in [
            vec!["--list-builtin-policies", "some/path"],
            vec!["--list-builtin-policies", "--format", "json"],
            vec!["--list-builtin-policies", "--fail-on", "never"],
            vec!["--list-builtin-policies", "--output", "out.json"],
        ] {
            let mut args = vec!["scan"];
            args.extend(options.iter().copied());
            assert_eq!(
                run_error(&args).0,
                "--list-builtin-policies cannot be combined with a project path or evaluation \
                 options",
                "{options:?} must be refused beside the listing"
            );
        }
    }

    #[test]
    fn a_nonexistent_scan_path_is_refused_before_evaluation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let missing = temp.path().join("absent");
        let missing = missing.to_string_lossy().into_owned();
        let (message, policy_invocation) = run_error(&["scan", &missing]);
        assert!(
            message.starts_with("scan path is not a directory:"),
            "{message}"
        );
        assert!(policy_invocation);
    }

    #[test]
    fn the_witness_records_an_empty_pack_set_honestly() {
        let manifest = empty_manifest();
        assert_eq!(
            builtin_pack_witness_lines(&manifest, "0".repeat(64).as_str()),
            vec![format!("builtin-policy-catalog sha256={}", "0".repeat(64))]
        );
        assert_eq!(
            scan_activation_summary(&manifest),
            "bifrost scan: this build ships no built-in policy packs; nothing was evaluated and \
             there are no findings"
        );
    }

    #[test]
    fn the_witness_shares_the_version_line_shape_for_the_shipped_catalog() {
        let catalog = built_in_policy_catalog().expect("valid built-in catalog");
        let lines = builtin_pack_witness_lines(catalog.document(), catalog.digest());
        assert_eq!(lines.len(), catalog.document().packs.len() + 1);
        for (line, pack) in lines.iter().zip(&catalog.document().packs) {
            assert_eq!(
                line,
                &format!(
                    "builtin-policy-pack {}@{} policies={}",
                    pack.id,
                    pack.version,
                    pack.policies.len()
                )
            );
        }
        assert_eq!(
            lines.last().expect("digest line"),
            &format!("builtin-policy-catalog sha256={}", catalog.digest())
        );
        let summary = scan_activation_summary(catalog.document());
        assert!(
            summary.starts_with("bifrost scan: activated ")
                && summary.contains("built-in policy packs"),
            "{summary}"
        );
    }
}
