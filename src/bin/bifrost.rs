use brokk_analyzer::{
    AnalyzerConfig, FilesystemProject, WorkspaceAnalyzer,
    searchtools::{
        FilePatternsParams, RefreshParams, SearchSymbolsParams, SearchtoolsError,
        SearchtoolsFailure, SearchtoolsRequest, SearchtoolsSuccess, SymbolNamesParams,
        get_file_summaries, get_symbol_locations, get_symbol_sources, get_symbol_summaries,
        refresh_result, search_symbols, skim_files,
    },
};
use serde::Serialize;
use std::env;
use std::io::{self, BufRead, Write};
use std::process::ExitCode;
use std::sync::Arc;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let mut root =
        env::current_dir().map_err(|err| format!("Failed to get current directory: {err}"))?;
    let mut server_mode = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--root requires a path".to_string())?;
                root = value.into();
            }
            "--server" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--server requires a mode".to_string())?;
                server_mode = Some(value);
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => {
                return Err(format!("Unknown argument: {other}"));
            }
        }
    }

    match server_mode.as_deref() {
        Some("searchtools") => run_searchtools_server(root),
        Some(other) => Err(format!("Unsupported server mode: {other}")),
        None => {
            print_help();
            Err("No mode selected".to_string())
        }
    }
}

fn run_searchtools_server(root: std::path::PathBuf) -> Result<(), String> {
    let project = Arc::new(
        FilesystemProject::new(root)
            .map_err(|err| format!("Failed to initialize project root: {err}"))?,
    );
    let mut workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => return Err(format!("Failed to read request: {err}")),
        };

        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<SearchtoolsRequest>(&line) {
            Ok(request) => dispatch_request(&mut workspace, request),
            Err(err) => {
                let failure = SearchtoolsFailure {
                    id: String::new(),
                    ok: false,
                    error: SearchtoolsError {
                        code: "invalid_request".to_string(),
                        message: format!("Invalid request JSON: {err}"),
                    },
                };
                serde_json::to_string(&failure).map_err(|serialize_err| {
                    format!("Failed to serialize error: {serialize_err}")
                })?
            }
        };

        writeln!(stdout, "{response}")
            .and_then(|_| stdout.flush())
            .map_err(|err| format!("Failed to write response: {err}"))?;
    }

    Ok(())
}

fn dispatch_request(workspace: &mut WorkspaceAnalyzer, request: SearchtoolsRequest) -> String {
    let response = match request.method.as_str() {
        "refresh" => decode_and_handle::<RefreshParams, _>(&request, |_| {
            *workspace = workspace.update_all();
            refresh_result(workspace.analyzer())
        }),
        "search_symbols" => decode_and_handle::<SearchSymbolsParams, _>(&request, |params| {
            search_symbols(workspace.analyzer(), params)
        }),
        "get_symbol_locations" => decode_and_handle::<SymbolNamesParams, _>(&request, |params| {
            get_symbol_locations(workspace.analyzer(), params)
        }),
        "get_symbol_summaries" => decode_and_handle::<SymbolNamesParams, _>(&request, |params| {
            get_symbol_summaries(workspace.analyzer(), params)
        }),
        "get_symbol_sources" => decode_and_handle::<SymbolNamesParams, _>(&request, |params| {
            get_symbol_sources(workspace.analyzer(), params)
        }),
        "get_file_summaries" => decode_and_handle::<FilePatternsParams, _>(&request, |params| {
            get_file_summaries(workspace.analyzer(), params)
        }),
        "skim_files" => decode_and_handle::<FilePatternsParams, _>(&request, |params| {
            skim_files(workspace.analyzer(), params)
        }),
        _ => serialize_failure(
            &request.id,
            "unknown_method",
            format!("Unknown method: {}", request.method),
        ),
    };

    response.unwrap_or_else(|err| {
        serialize_failure(&request.id, "internal_error", err).unwrap_or_else(|fallback| fallback)
    })
}

fn decode_and_handle<P, R>(
    request: &SearchtoolsRequest,
    handler: impl FnOnce(P) -> R,
) -> Result<String, String>
where
    P: serde::de::DeserializeOwned,
    R: Serialize,
{
    let params = serde_json::from_value::<P>(request.params.clone())
        .map_err(|err| format!("Invalid params for method {}: {err}", request.method))?;

    serialize_success(&request.id, handler(params))
}

fn serialize_success<T: Serialize>(id: &str, result: T) -> Result<String, String> {
    serde_json::to_string(&SearchtoolsSuccess {
        id: id.to_string(),
        ok: true,
        result,
    })
    .map_err(|err| format!("Failed to serialize success response: {err}"))
}

fn serialize_failure(id: &str, code: &str, message: String) -> Result<String, String> {
    serde_json::to_string(&SearchtoolsFailure {
        id: id.to_string(),
        ok: false,
        error: SearchtoolsError {
            code: code.to_string(),
            message,
        },
    })
    .map_err(|err| format!("Failed to serialize error response: {err}"))
}

fn print_help() {
    println!("Usage: bifrost --root PROJECT_ROOT --server searchtools");
}
