use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    CatalogCoordinate, CatalogOpenMode, CatalogOptions, CompilerOptions,
    SemanticModelActivationControl, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelControlAction, SemanticModelControlScope,
    SemanticModelPackSelector, SemanticModelResolutionOutcome, SemanticModelRuntimeLimits,
    SemanticPackCatalog, SourceFormat, WorkspaceSemanticModelOptions, compile_source,
    discover_workspace_semantic_models, lint_semantic_model_source, resolve_active_semantic_models,
    semantic_model_inventory, validate_semantic_model_source, write_compiled_semantic_model_pack,
};
use brokk_bifrost_semantic_packs::release_bundle::{
    BundleInput, ReleaseBundleRejects, generate_release_bundle, install_release_bundle,
    verify_release_bundle,
};
use brokk_bifrost_semantic_packs::summary_foundry::framework_pack::{
    convert_framework_candidates, write_framework_packs,
};
use brokk_bifrost_semantic_packs::summary_foundry::golden_pack::{
    convert_golden_candidates, realm_by_name, write_golden_packs,
};
use brokk_bifrost_semantic_packs::summary_foundry::sanitizer_pack::{
    convert_sanitizer_candidates, write_sanitizer_packs,
};
use brokk_bifrost_semantic_packs::summary_foundry::{
    FoundryPins, FoundryRunInputs, run_foundry_join,
};
use semver::{Version, VersionReq};
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;

const CLI_ERROR_FORMAT: &str = "bifrost_semantic_model_cli_error/v1";
const MAX_INVENTORY_PACKS: usize = 65_536;

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Human,
    Json,
}

struct CommandFailure {
    code: u8,
    message: String,
    format: OutputFormat,
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1).collect()) {
        Ok(code) => ExitCode::from(code),
        Err(failure) => {
            match failure.format {
                OutputFormat::Human => eprintln!("error: {}", failure.message),
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "format": CLI_ERROR_FORMAT,
                        "code": "command.failed",
                        "exit_status": failure.code,
                        "error": failure.message,
                    }))
                    .expect("CLI error JSON is serializable")
                ),
            }
            ExitCode::from(failure.code)
        }
    }
}

fn run(mut arguments: Vec<OsString>) -> Result<u8, CommandFailure> {
    let format = remove_format(&mut arguments)?;
    let Some(command) = take_utf8(&mut arguments, 0)? else {
        return Err(failure(2, usage(), format));
    };
    match command.as_str() {
        "validate" => validate_command(arguments, format),
        "lint" => lint_command(arguments, format),
        "compile" => compile_command(arguments, format),
        "list" => list_command(arguments, format),
        "workspace-check" => workspace_check_command(arguments, format),
        "generate" => generate_command(arguments, format),
        "verify" => verify_command(arguments, format),
        "install" => install_command(arguments, format),
        "summary-corpus-join" => summary_corpus_join_command(arguments, format),
        "sanitizer-pack" => sanitizer_pack_command(arguments, format),
        "framework-decl-pack" => framework_decl_pack_command(arguments, format),
        "golden-summary-pack" => golden_summary_pack_command(arguments, format),
        _ => Err(failure(2, usage(), format)),
    }
}

fn validate_command(arguments: Vec<OsString>, format: OutputFormat) -> Result<u8, CommandFailure> {
    let (source_format, bytes) = read_source_argument(arguments, format)?;
    let report = validate_semantic_model_source(source_format, &bytes, &CompilerOptions::default());
    print_source_report(&report, format);
    Ok(u8::from(!report.valid || !report.diagnostics.is_empty()))
}

fn lint_command(arguments: Vec<OsString>, format: OutputFormat) -> Result<u8, CommandFailure> {
    let (source_format, bytes) = read_source_argument(arguments, format)?;
    let report = lint_semantic_model_source(source_format, &bytes, &CompilerOptions::default());
    print_source_report(&report, format);
    Ok(u8::from(!report.valid || !report.diagnostics.is_empty()))
}

fn read_source_argument(
    arguments: Vec<OsString>,
    format: OutputFormat,
) -> Result<(SourceFormat, Vec<u8>), CommandFailure> {
    let [source] = arguments.as_slice() else {
        return Err(failure(2, usage(), format));
    };
    let path = PathBuf::from(source);
    Ok((source_format(&path, format)?, read(&path, format)?))
}

fn compile_command(arguments: Vec<OsString>, format: OutputFormat) -> Result<u8, CommandFailure> {
    let [source, output] = arguments.as_slice() else {
        return Err(failure(2, usage(), format));
    };
    let source = PathBuf::from(source);
    let output = PathBuf::from(output);
    let source_format = source_format(&source, format)?;
    let bytes = read(&source, format)?;
    let compiled = match compile_source(source_format, &bytes, &CompilerOptions::default()) {
        Ok(compiled) => compiled,
        Err(_) => {
            let report =
                validate_semantic_model_source(source_format, &bytes, &CompilerOptions::default());
            print_source_report(&report, format);
            return Ok(1);
        }
    };
    let report = write_compiled_semantic_model_pack(&output, &compiled).map_err(|error_value| {
        failure(
            2,
            format!("cannot write {}: {error_value}", output.display()),
            format,
        )
    })?;
    match format {
        OutputFormat::Json => print_json(&report),
        OutputFormat::Human => println!(
            "compiled {} shard(s) to {} ({})",
            report.shard_paths.len(),
            output.display(),
            report.manifest_content_sha256
        ),
    }
    Ok(0)
}

fn list_command(arguments: Vec<OsString>, format: OutputFormat) -> Result<u8, CommandFailure> {
    let (catalog_root, activation_path) = match arguments.as_slice() {
        [catalog_root] => (PathBuf::from(catalog_root), None),
        [catalog_root, activation_path] => (
            PathBuf::from(catalog_root),
            Some(PathBuf::from(activation_path)),
        ),
        _ => return Err(failure(2, usage(), format)),
    };
    let catalog = SemanticPackCatalog::open(
        &catalog_root,
        CatalogOpenMode::ReadOnly,
        CatalogOptions::default(),
    )
    .map_err(|error_value| failure(2, error_value.to_string(), format))?;
    let active = if let Some(path) = activation_path {
        let input: ActivationInput = serde_json::from_slice(&read(&path, format)?)
            .map_err(|error_value| failure(2, error_value.to_string(), format))?;
        let request = input.into_request(format)?;
        match resolve_active_semantic_models(&catalog, &request, &CancellationToken::default()) {
            SemanticModelResolutionOutcome::Ready(active) => Some(active),
            SemanticModelResolutionOutcome::Incomplete { .. }
            | SemanticModelResolutionOutcome::Cancelled(_)
            | SemanticModelResolutionOutcome::Unavailable(_) => {
                return Err(failure(
                    2,
                    "activation did not produce a complete active model set",
                    format,
                ));
            }
        }
    } else {
        None
    };
    let report = semantic_model_inventory(&catalog, active.as_ref(), MAX_INVENTORY_PACKS)
        .map_err(|error_value| failure(2, error_value.to_string(), format))?;
    match format {
        OutputFormat::Json => print_json(&report),
        OutputFormat::Human => {
            for pack in &report.installed {
                let sources = pack
                    .sources
                    .iter()
                    .map(|source| format!("{}:{}", source.source_kind, source.source_id))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "installed {} {} [{}] sources=[{}]",
                    pack.pack_id, pack.pack_version, pack.state, sources
                );
            }
            for pack in &report.active {
                println!(
                    "active {} {} {} via {}:{}; {}",
                    pack.pack_id,
                    pack.pack_version,
                    pack.shard_id,
                    pack.source_kind,
                    pack.source_id,
                    pack.activation_reason
                );
            }
            for explanation in &report.activation_explanations {
                println!(
                    "{} {} {} via {}:{}; {}",
                    explanation.status,
                    explanation.pack_id.as_deref().unwrap_or("<unknown>"),
                    explanation.shard_id,
                    explanation.source_kind,
                    explanation.source_id,
                    explanation.reason
                );
            }
        }
    }
    Ok(if report.complete { 0 } else { 2 })
}

fn workspace_check_command(
    arguments: Vec<OsString>,
    format: OutputFormat,
) -> Result<u8, CommandFailure> {
    let [workspace] = arguments.as_slice() else {
        return Err(failure(2, usage(), format));
    };
    let report = discover_workspace_semantic_models(
        Path::new(workspace),
        WorkspaceSemanticModelOptions::default(),
    );
    match format {
        OutputFormat::Json => print_json(&report),
        OutputFormat::Human => {
            println!(
                "workspace rules: {} ({})",
                if report.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                report.directory
            );
            for file in &report.files {
                println!(
                    "{} {} sha256={} pack={}",
                    if file.valid { "valid" } else { "invalid" },
                    file.path,
                    file.source_sha256,
                    file.pack_id.as_deref().unwrap_or("<unknown>")
                );
                for diagnostic in &file.diagnostics {
                    println!(
                        "  {:?} {} {}: {}",
                        diagnostic.severity, diagnostic.code, diagnostic.path, diagnostic.message
                    );
                }
            }
            for diagnostic in &report.diagnostics {
                println!(
                    "{:?} {} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.path, diagnostic.message
                );
            }
        }
    }
    if !report.complete && report.files.iter().all(|file| file.valid) {
        Ok(2)
    } else {
        Ok(u8::from(!report.complete))
    }
}

fn generate_command(arguments: Vec<OsString>, format: OutputFormat) -> Result<u8, CommandFailure> {
    require_human_release_output(format)?;
    let Some(output_root) = arguments.first().map(PathBuf::from) else {
        return Err(failure(2, usage(), format));
    };
    let remaining = &arguments[1..];
    if remaining.is_empty() || !remaining.len().is_multiple_of(2) {
        return Err(failure(2, usage(), format));
    }
    let inputs = remaining
        .chunks_exact(2)
        .map(|pair| BundleInput {
            spec_path: PathBuf::from(&pair[0]),
            artifact_path: PathBuf::from(&pair[1]),
        })
        .collect::<Vec<_>>();
    let bundle = generate_release_bundle(&output_root, &inputs)
        .map_err(|error_value| failure(2, error_value.to_string(), format))?;
    println!(
        "generated {} pinned semantic packs in {}",
        bundle.index.packs.len(),
        output_root.display()
    );
    print_release_rejects(&bundle.rejects);
    Ok(0)
}

fn verify_command(arguments: Vec<OsString>, format: OutputFormat) -> Result<u8, CommandFailure> {
    require_human_release_output(format)?;
    let [output_root] = arguments.as_slice() else {
        return Err(failure(2, usage(), format));
    };
    let output_root = PathBuf::from(output_root);
    let bundle = verify_release_bundle(&output_root)
        .map_err(|error_value| failure(2, error_value.to_string(), format))?;
    println!(
        "verified {} pinned semantic packs in {}",
        bundle.index.packs.len(),
        output_root.display()
    );
    print_release_rejects(&bundle.rejects);
    Ok(0)
}

/// Print the structured extraction burn-down report: one summary line per
/// pack, then every rejected entry with its reject reason.
fn print_release_rejects(rejects: &ReleaseBundleRejects) {
    for pack in &rejects.packs {
        println!(
            "rejects {}@{}: {} rejected entries, {} suppressed",
            pack.pack_id,
            pack.pack_version,
            pack.rejects.len(),
            pack.suppressed_rejects
        );
        for reject in &pack.rejects {
            println!(
                "  {} {} {}: {}",
                reject.severity,
                reject.code,
                reject.location.as_deref().unwrap_or("<pack>"),
                reject.message
            );
        }
    }
}

fn install_command(arguments: Vec<OsString>, format: OutputFormat) -> Result<u8, CommandFailure> {
    require_human_release_output(format)?;
    let [bundle_root, catalog_root] = arguments.as_slice() else {
        return Err(failure(2, usage(), format));
    };
    let bundle_root = PathBuf::from(bundle_root);
    let catalog_root = PathBuf::from(catalog_root);
    let catalog = SemanticPackCatalog::open(
        &catalog_root,
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .map_err(|error_value| failure(2, error_value.to_string(), format))?;
    let installed = install_release_bundle(&bundle_root, &catalog)
        .map_err(|error_value| failure(2, error_value.to_string(), format))?;
    println!(
        "installed {} pinned semantic packs from {} into {}",
        installed.len(),
        bundle_root.display(),
        catalog_root.display()
    );
    Ok(0)
}

/// Translate both pinned summary corpora, round-trip them, and join them.
///
/// The report is written to a file rather than to stdout because it carries
/// every dispute, gap, and skipped row, which is the point of the artifact.
fn summary_corpus_join_command(
    arguments: Vec<OsString>,
    format: OutputFormat,
) -> Result<u8, CommandFailure> {
    require_human_release_output(format)?;
    let (pins, codeql_models, joern_source, report, jvm_sources) = match arguments.as_slice() {
        [pins, codeql_models, joern_source, report] => {
            (pins, codeql_models, joern_source, report, None)
        }
        [pins, codeql_models, joern_source, report, jvm_sources] => (
            pins,
            codeql_models,
            joern_source,
            report,
            Some(PathBuf::from(jvm_sources)),
        ),
        _ => return Err(failure(2, usage(), format)),
    };
    let report_path = PathBuf::from(report);
    let pins = FoundryPins::read(Path::new(pins))
        .map_err(|error_value| failure(2, error_value.to_string(), format))?;
    let mut inputs = FoundryRunInputs::from_pins(
        &pins,
        PathBuf::from(codeql_models),
        PathBuf::from(joern_source),
    )
    .map_err(|error_value| failure(2, error_value.to_string(), format))?;
    inputs.jvm_sources = jvm_sources;
    let joined = run_foundry_join(&inputs)
        .map_err(|error_value| failure(2, error_value.to_string(), format))?;
    if let Some(parent) = report_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error_value| {
            failure(
                2,
                format!("cannot create {}: {error_value}", parent.display()),
                format,
            )
        })?;
    }
    fs::write(&report_path, joined.to_json()).map_err(|error_value| {
        failure(
            2,
            format!("cannot write {}: {error_value}", report_path.display()),
            format,
        )
    })?;
    for translation in &joined.translation {
        println!(
            "{} entries={} ({} flow, {} no-flow) transfers={} rows={} skipped={}",
            translation.corpus.as_str(),
            translation.entries,
            translation.flow_entries,
            translation.no_flow_entries,
            translation.transfers,
            translation.rows_read,
            translation.skipped_rows
        );
        for (reason, count) in &translation.skips_by_reason {
            println!("  skipped {reason}: {count}");
        }
        for (note, count) in &translation.notes_by_kind {
            println!("  note {note}: {count}");
        }
    }
    if let Some(derivation) = &joined.derivation {
        println!(
            "derived entries={} ({} flow, {} no-flow, {} complete) transfers={} files={} procedures={}",
            derivation.entries,
            derivation.flow_entries,
            derivation.no_flow_entries,
            derivation.complete_entries,
            derivation.transfers,
            derivation.files_read,
            derivation.procedures_read
        );
        println!(
            "  flows finer than the shipped projection: {}",
            derivation.qualified_flows
        );
        for (boundary, count) in &derivation.boundaries_by_kind {
            println!("  boundary {boundary}: {count}");
        }
        for unavailable in &derivation.unavailable_files {
            println!("  unavailable {unavailable}");
        }
    }
    for round_trip in &joined.round_trip {
        println!(
            "{} round-trip entries={} shards={} manifest={}",
            round_trip.corpus.as_str(),
            round_trip.entries,
            round_trip.shards,
            round_trip
                .manifest_content_sha256
                .as_deref()
                .unwrap_or("<failed>")
        );
        for diagnostic in &round_trip.diagnostics {
            println!("  {diagnostic}");
        }
    }
    println!(
        "join agreements={} ({} at the argument-level projection only) disputes={} gaps={}",
        joined.join.agreement_count,
        joined.join.agreements_at_projection_only,
        joined.join.dispute_count,
        joined.join.gap_count
    );
    for (corpus, count) in &joined.join.gaps_by_missing_slot {
        println!("  gaps missing from {corpus}: {count}");
    }
    println!("wrote {}", report_path.display());
    Ok(u8::from(!joined.round_trip_is_clean()))
}

/// Convert the audited k3 sanitizer candidates into `procedure_summaries` packs,
/// gate every entry through the adversarial mechanism gate, and write the pack
/// sources plus the audit report. The conversion is deterministic, so re-running
/// over unchanged candidates rewrites identical bytes.
fn sanitizer_pack_command(
    arguments: Vec<OsString>,
    format: OutputFormat,
) -> Result<u8, CommandFailure> {
    require_human_release_output(format)?;
    let [candidates_dir, output_root] = arguments.as_slice() else {
        return Err(failure(2, usage(), format));
    };
    let conversion = convert_sanitizer_candidates(Path::new(candidates_dir))
        .map_err(|error_value| failure(2, error_value.to_string(), format))?;
    let written = write_sanitizer_packs(&conversion, Path::new(output_root))
        .map_err(|error_value| failure(2, error_value.to_string(), format))?;

    let audit = &conversion.audit;
    println!(
        "gated {} candidates: {} shipped summaries, {} gate-rejected, {} overloads folded, {} adversarial probes",
        audit.candidates_total,
        audit.shipped_summaries,
        audit.gate_rejected,
        audit.folded_overloads,
        audit.adversarial_probes,
    );
    for pack in &audit.packs {
        println!(
            "  {} [{}] {} summaries, {} probes, artifact={}",
            pack.pack_id,
            if pack.pinned { "pinned" } else { "staged" },
            pack.shipped_summaries,
            pack.adversarial_probes,
            pack.artifact,
        );
    }
    for reject in &audit.gate_rejects {
        println!(
            "  reject {} {}: {}",
            reject.reason, reject.target_symbol, reject.message
        );
    }
    for path in &written {
        println!("wrote {}", path.display());
    }
    Ok(0)
}

/// Convert the framework declaration candidates into `declaration_facts` packs
/// so the framework types resolve `external_indexed`, and write the pack sources
/// plus the audit report. The conversion is deterministic.
fn framework_decl_pack_command(
    arguments: Vec<OsString>,
    format: OutputFormat,
) -> Result<u8, CommandFailure> {
    require_human_release_output(format)?;
    let [candidates_dir, output_root] = arguments.as_slice() else {
        return Err(failure(2, usage(), format));
    };
    let conversion = convert_framework_candidates(Path::new(candidates_dir))
        .map_err(|error_value| failure(2, error_value.to_string(), format))?;
    let written = write_framework_packs(&conversion, Path::new(output_root))
        .map_err(|error_value| failure(2, error_value.to_string(), format))?;

    let audit = &conversion.audit;
    println!(
        "converted {} types and {} members into {} declaration pack(s)",
        audit.types_total,
        audit.members_total,
        audit.packs.len(),
    );
    for pack in &audit.packs {
        println!(
            "  {} [{}] {} types, {} members, artifact={}",
            pack.pack_id,
            if pack.pinned { "pinned" } else { "staged" },
            pack.types,
            pack.members,
            pack.artifact,
        );
        if let Some(reason) = &pack.staged_reason {
            println!("    staged: {reason}");
        }
    }
    for path in &written {
        println!("wrote {}", path.display());
    }
    Ok(0)
}

/// Convert one realm's golden-core flow-through summaries into a
/// `procedure_summaries` pack, drop the duplicate-target candidates, and write
/// the pack source plus the audit report. The conversion is deterministic.
fn golden_summary_pack_command(
    arguments: Vec<OsString>,
    format: OutputFormat,
) -> Result<u8, CommandFailure> {
    require_human_release_output(format)?;
    let [candidates_dir, output_root, realm_name] = arguments.as_slice() else {
        return Err(failure(2, usage(), format));
    };
    let realm = realm_name
        .to_str()
        .and_then(realm_by_name)
        .ok_or_else(|| failure(2, usage(), format))?;
    let conversion = convert_golden_candidates(Path::new(candidates_dir), realm)
        .map_err(|error_value| failure(2, error_value.to_string(), format))?;
    let written = write_golden_packs(&conversion, Path::new(output_root))
        .map_err(|error_value| failure(2, error_value.to_string(), format))?;

    let audit = &conversion.audit;
    println!(
        "converted {} candidates: {} shipped summaries, {} rejected",
        audit.candidates_total, audit.shipped_summaries, audit.rejected,
    );
    for pack in &audit.packs {
        println!(
            "  {} [{}] {} summaries, artifact={}",
            pack.pack_id,
            if pack.pinned { "pinned" } else { "staged" },
            pack.shipped_summaries,
            pack.artifact,
        );
    }
    for reject in &audit.rejects {
        println!(
            "  reject {} {}: {}",
            reject.reason, reject.target_symbol, reject.message
        );
    }
    for path in &written {
        println!("wrote {}", path.display());
    }
    Ok(0)
}

fn require_human_release_output(format: OutputFormat) -> Result<(), CommandFailure> {
    if format == OutputFormat::Json {
        Err(failure(
            2,
            "release commands do not support --format json",
            format,
        ))
    } else {
        Ok(())
    }
}

fn remove_format(arguments: &mut Vec<OsString>) -> Result<OutputFormat, CommandFailure> {
    let Some(index) = arguments.iter().position(|argument| argument == "--format") else {
        return Ok(OutputFormat::Human);
    };
    if index + 1 >= arguments.len() {
        return Err(failure(2, usage(), OutputFormat::Human));
    }
    let value = arguments.remove(index + 1);
    arguments.remove(index);
    let value = value
        .into_string()
        .map_err(|_| failure(2, "output format is not UTF-8", OutputFormat::Human))?;
    match value.as_str() {
        "human" => Ok(OutputFormat::Human),
        "json" => Ok(OutputFormat::Json),
        _ => Err(failure(
            2,
            "output format must be human or json",
            OutputFormat::Human,
        )),
    }
}

fn take_utf8(
    arguments: &mut Vec<OsString>,
    index: usize,
) -> Result<Option<String>, CommandFailure> {
    if index >= arguments.len() {
        return Ok(None);
    }
    arguments
        .remove(index)
        .into_string()
        .map(Some)
        .map_err(|_| failure(2, "command is not UTF-8", OutputFormat::Human))
}

fn source_format(path: &Path, format: OutputFormat) -> Result<SourceFormat, CommandFailure> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => Ok(SourceFormat::Json),
        Some("yaml" | "yml") => Ok(SourceFormat::Yaml),
        _ => Err(failure(
            2,
            "source file must have a .json, .yaml, or .yml suffix",
            format,
        )),
    }
}

fn read(path: &Path, format: OutputFormat) -> Result<Vec<u8>, CommandFailure> {
    fs::read(path).map_err(|error_value| {
        failure(
            2,
            format!("cannot read {}: {error_value}", path.display()),
            format,
        )
    })
}

fn print_source_report(
    report: &brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSourceReport,
    format: OutputFormat,
) {
    match format {
        OutputFormat::Json => print_json(report),
        OutputFormat::Human => {
            println!(
                "{} source sha256={} pack={} version={}",
                if report.valid { "valid" } else { "invalid" },
                report.source_sha256,
                report.pack_id.as_deref().unwrap_or("<unknown>"),
                report.pack_version.as_deref().unwrap_or("<unknown>")
            );
            for diagnostic in &report.diagnostics {
                println!(
                    "{:?} {} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.path, diagnostic.message
                );
            }
        }
    }
}

fn print_json(value: &impl Serialize) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("report JSON is serializable")
    );
}

fn failure(code: u8, message: impl Into<String>, format: OutputFormat) -> CommandFailure {
    CommandFailure {
        code,
        message: message.into(),
        format,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationInput {
    schema_version: u32,
    bifrost_version: String,
    evidence: Vec<ActivationEvidenceInput>,
    #[serde(default)]
    controls: Vec<ActivationControlInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationEvidenceInput {
    language: String,
    ecosystem: String,
    package: Option<CoordinateInput>,
    module: Option<CoordinateInput>,
    toolchain: Option<CoordinateInput>,
    target: Option<String>,
    configuration: Option<String>,
    artifact_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinateInput {
    name: String,
    version: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
struct ActivationControlInput {
    scope: ControlScopeInput,
    action: ControlActionInput,
    pack_id: String,
    version: Option<String>,
    manifest_digest: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ControlScopeInput {
    User,
    Workspace,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ControlActionInput {
    Enable,
    Disable,
}

impl ActivationInput {
    fn into_request(
        self,
        format: OutputFormat,
    ) -> Result<SemanticModelActivationRequest, CommandFailure> {
        if self.schema_version != 1 {
            return Err(failure(2, "activation schema_version must be 1", format));
        }
        let bifrost_version = Version::parse(&self.bifrost_version)
            .map_err(|error_value| failure(2, error_value.to_string(), format))?;
        let evidence = self
            .evidence
            .into_iter()
            .map(|evidence| evidence.into_evidence(format))
            .collect::<Result<Vec<_>, _>>()?;
        let controls = self
            .controls
            .into_iter()
            .map(|control| control.into_control(format))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SemanticModelActivationRequest {
            bifrost_version,
            evidence,
            controls,
            limits: SemanticModelRuntimeLimits::default(),
        })
    }
}

impl ActivationEvidenceInput {
    fn into_evidence(
        self,
        format: OutputFormat,
    ) -> Result<SemanticModelActivationEvidence, CommandFailure> {
        Ok(SemanticModelActivationEvidence {
            language: self.language,
            ecosystem: self.ecosystem,
            package: self
                .package
                .map(|value| value.into_coordinate(format))
                .transpose()?,
            module: self
                .module
                .map(|value| value.into_coordinate(format))
                .transpose()?,
            toolchain: self
                .toolchain
                .map(|value| value.into_coordinate(format))
                .transpose()?,
            target: self.target,
            configuration: self.configuration,
            artifact_sha256: self.artifact_sha256,
        })
    }
}

impl CoordinateInput {
    fn into_coordinate(self, format: OutputFormat) -> Result<CatalogCoordinate, CommandFailure> {
        let version = self
            .version
            .map(|version| Version::parse(&version))
            .transpose()
            .map_err(|error_value| failure(2, error_value.to_string(), format))?;
        Ok(CatalogCoordinate {
            name: self.name,
            version,
        })
    }
}

impl ActivationControlInput {
    fn into_control(
        self,
        format: OutputFormat,
    ) -> Result<SemanticModelActivationControl, CommandFailure> {
        let version = self
            .version
            .map(|version| VersionReq::parse(&version))
            .transpose()
            .map_err(|error_value| failure(2, error_value.to_string(), format))?;
        Ok(SemanticModelActivationControl {
            scope: match self.scope {
                ControlScopeInput::User => SemanticModelControlScope::User,
                ControlScopeInput::Workspace => SemanticModelControlScope::Workspace,
            },
            action: match self.action {
                ControlActionInput::Enable => SemanticModelControlAction::Enable,
                ControlActionInput::Disable => SemanticModelControlAction::Disable,
            },
            selector: SemanticModelPackSelector {
                pack_id: self.pack_id,
                version,
                manifest_digest: self.manifest_digest,
            },
        })
    }
}

fn usage() -> &'static str {
    "usage:\n  bifrost-semantic-pack validate SOURCE [--format human|json]\n  bifrost-semantic-pack lint SOURCE [--format human|json]\n  bifrost-semantic-pack compile SOURCE OUTPUT [--format human|json]\n  bifrost-semantic-pack list CATALOG [ACTIVATION.json] [--format human|json]\n  bifrost-semantic-pack workspace-check WORKSPACE [--format human|json]\n  bifrost-semantic-pack generate OUTPUT SPEC ARTIFACT [SPEC ARTIFACT ...]\n  bifrost-semantic-pack verify OUTPUT\n  bifrost-semantic-pack install BUNDLE CATALOG\n  bifrost-semantic-pack summary-corpus-join PINS CODEQL_MODELS JOERN_SOURCE REPORT.json [JVM_SOURCES]\n  bifrost-semantic-pack sanitizer-pack CANDIDATES_DIR OUTPUT_ROOT\n  bifrost-semantic-pack framework-decl-pack CANDIDATES_DIR OUTPUT_ROOT\n  bifrost-semantic-pack golden-summary-pack CANDIDATES_DIR OUTPUT_ROOT REALM"
}
