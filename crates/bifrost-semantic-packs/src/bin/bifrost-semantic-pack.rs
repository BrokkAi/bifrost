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
    BundleInput, generate_release_bundle, install_release_bundle, verify_release_bundle,
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
    let index = generate_release_bundle(&output_root, &inputs)
        .map_err(|error_value| failure(2, error_value.to_string(), format))?;
    println!(
        "generated {} pinned semantic packs in {}",
        index.packs.len(),
        output_root.display()
    );
    Ok(0)
}

fn verify_command(arguments: Vec<OsString>, format: OutputFormat) -> Result<u8, CommandFailure> {
    require_human_release_output(format)?;
    let [output_root] = arguments.as_slice() else {
        return Err(failure(2, usage(), format));
    };
    let output_root = PathBuf::from(output_root);
    let index = verify_release_bundle(&output_root)
        .map_err(|error_value| failure(2, error_value.to_string(), format))?;
    println!(
        "verified {} pinned semantic packs in {}",
        index.packs.len(),
        output_root.display()
    );
    Ok(0)
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
    "usage:\n  bifrost-semantic-pack validate SOURCE [--format human|json]\n  bifrost-semantic-pack lint SOURCE [--format human|json]\n  bifrost-semantic-pack compile SOURCE OUTPUT [--format human|json]\n  bifrost-semantic-pack list CATALOG [ACTIVATION.json] [--format human|json]\n  bifrost-semantic-pack workspace-check WORKSPACE [--format human|json]\n  bifrost-semantic-pack generate OUTPUT SPEC ARTIFACT [SPEC ARTIFACT ...]\n  bifrost-semantic-pack verify OUTPUT\n  bifrost-semantic-pack install BUNDLE CATALOG"
}
