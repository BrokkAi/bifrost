use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use glob::Pattern;
use lsp_types::{DocumentFormattingParams, TextEdit};
use serde::Deserialize;

#[cfg(windows)]
use crate::analyzer::NormalizePath;
use crate::analyzer::common::language_for_file;
use crate::analyzer::{Language, Project, ProjectFile, Range as ByteRange};
use crate::cancellation::CancellationToken;
use crate::lsp::conversion::byte_range_to_lsp_range;
use crate::lsp::handlers::util::read_document_for_uri;

const MAX_ERROR_OUTPUT_CHARS: usize = 1_000;
const MAX_FORMATTER_STDERR_BYTES: usize = 64 * 1024;
const MAX_FORMATTER_STDOUT_BYTES: usize = 32 * 1024 * 1024;
const FORMATTER_READER_GRACE: Duration = Duration::from_secs(1);
#[cfg(unix)]
const FORMATTER_SPAWN_RETRIES: usize = 5;
#[cfg(unix)]
const FORMATTER_SPAWN_RETRY_DELAY: Duration = Duration::from_millis(10);
const FORMATTER_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(all(test, unix))]
const TEST_HUNG_FORMATTER_TIMEOUT: Duration = Duration::from_secs(2);

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

impl FormatterCommandRule {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.command.trim().is_empty() {
            return Err("command must not be empty".to_string());
        }
        if let Some(language) = self.language.as_deref()
            && Language::from_config_label(language).is_none()
        {
            return Err(format!("unknown language `{language}`"));
        }
        for (field, patterns) in [("include", &self.include), ("exclude", &self.exclude)] {
            for (index, pattern) in patterns.iter().enumerate() {
                Pattern::new(pattern)
                    .map_err(|err| format!("{field}[{index}] is not a valid glob: {err}"))?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FormatterCommand {
    pub(crate) command: String,
    pub(crate) args: Vec<String>,
    pub(crate) cwd: PathBuf,
}

pub(crate) struct PreparedFormatting {
    command: FormatterCommand,
    content: String,
    line_starts: Vec<usize>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FormatterCancellation {
    cancellation: CancellationToken,
    pid: Arc<AtomicU32>,
}

impl FormatterCancellation {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn cancel(&self) {
        self.cancellation.cancel();
        let pid = self.pid.load(Ordering::Acquire);
        if pid != 0 {
            terminate_process_id(pid);
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn set_pid(&self, pid: u32) {
        self.pid.store(pid, Ordering::Release);
        if self.is_cancelled() {
            terminate_process_id(pid);
        }
    }

    fn clear_pid(&self) {
        self.pid.store(0, Ordering::Release);
    }
}

struct FormatContext<'a> {
    file: &'a ProjectFile,
    workspace_root: PathBuf,
    relative_file: PathBuf,
    language: Language,
}

pub(crate) fn prepare(
    project: &dyn Project,
    params: &DocumentFormattingParams,
    rules: &[FormatterCommandRule],
) -> Result<Option<PreparedFormatting>, String> {
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
        file: &file,
        workspace_root: project.workspace_root_for_file(&file),
        relative_file: formatter_relative_file(project, &file),
        language,
    };
    let Some(command) = resolve_formatter_command(&context, rules)? else {
        return Ok(None);
    };
    Ok(Some(PreparedFormatting {
        command,
        content,
        line_starts,
    }))
}

pub(crate) fn run_prepared_with_cancellation(
    prepared: PreparedFormatting,
    cancellation: &FormatterCancellation,
) -> Result<Vec<TextEdit>, String> {
    let PreparedFormatting {
        command,
        content,
        line_starts,
    } = prepared;
    let formatted = run_formatter_command(&command, &content, cancellation)?;
    if formatted == content {
        return Ok(Vec::new());
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
    Ok(vec![TextEdit::new(range, formatted)])
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
        .map(|cwd| resolve_cwd(&cwd, &context.workspace_root))
        .unwrap_or_else(|| context.workspace_root.clone());
    let args = rule
        .args
        .iter()
        .map(|arg| expand_placeholders(arg, context))
        .collect();
    let command = configured_command_path(command, &cwd)?;
    Ok(FormatterCommand { command, args, cwd })
}

fn rule_matches(rule: &FormatterCommandRule, context: &FormatContext<'_>) -> bool {
    if let Some(language) = rule.language.as_deref()
        && Language::from_config_label(language) != Some(context.language)
    {
        return false;
    }
    let rel = normalized_rel_path(context);
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
        Language::Rust => standard_command(
            context,
            "rustfmt",
            ["--edition", &rust_edition(context), "--emit", "stdout"],
        ),
        Language::Go => standard_command(context, "gofmt", []),
        Language::Cpp => standard_command(context, "clang-format", ["--assume-filename", "{file}"]),
        Language::Python => standard_command(
            context,
            "black",
            ["--quiet", "--stdin-filename", "{file}", "-"],
        ),
        Language::JavaScript | Language::TypeScript => None,
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
) -> Option<FormatterCommand> {
    let cwd = standard_command_cwd(context);
    Some(FormatterCommand {
        command: builtin_command_path(command, &cwd)?,
        args: args
            .into_iter()
            .map(|arg| expand_placeholders(arg, context))
            .collect(),
        cwd,
    })
}

#[cfg(not(windows))]
fn builtin_command_path(command: &str, _cwd: &Path) -> Option<String> {
    Some(command.to_string())
}

#[cfg(windows)]
fn builtin_command_path(command: &str, cwd: &Path) -> Option<String> {
    resolve_windows_command_outside_cwd(command, cwd)
}

#[cfg(not(windows))]
fn configured_command_path(command: &str, _cwd: &Path) -> Result<String, String> {
    Ok(command.to_string())
}

#[cfg(windows)]
fn configured_command_path(command: &str, cwd: &Path) -> Result<String, String> {
    if Path::new(command).components().count() > 1 {
        return Ok(command.to_string());
    }
    resolve_windows_command_outside_cwd(command, cwd).ok_or_else(|| {
        format!(
            "formatter command `{command}` was not found outside formatter cwd {}",
            cwd.display()
        )
    })
}

#[cfg(windows)]
fn resolve_windows_command_outside_cwd(command: &str, cwd: &Path) -> Option<String> {
    let paths = std::env::var_os("PATH")?;
    let extensions = std::env::var_os("PATHEXT")
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string());
    let command_path = Path::new(command);
    if command_path.components().count() > 1 {
        return command_path.is_absolute().then(|| command.to_string());
    }
    let candidates: Vec<String> = if command_path.extension().is_some() {
        vec![command.to_string()]
    } else {
        extensions
            .split(';')
            .filter(|extension| !extension.is_empty())
            .map(|extension| format!("{command}{extension}"))
            .collect()
    };
    std::env::split_paths(&paths)
        .filter(|path| !path.as_os_str().is_empty())
        .filter(|path| !path_is_same_or_within(path, cwd))
        .find_map(|dir| {
            candidates
                .iter()
                .map(|candidate| dir.join(candidate))
                .find(|candidate| candidate.is_file())
        })
        .map(|path| path.display().to_string())
}

#[cfg(windows)]
fn path_is_same_or_within(path: &Path, root: &Path) -> bool {
    let path = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .normalize();
    let root = root
        .canonicalize()
        .unwrap_or_else(|_| root.to_path_buf())
        .normalize();
    path == root || path.starts_with(root)
}

fn nearest_manifest(start: &Path, stop_at: &Path, name: &str) -> Option<PathBuf> {
    for dir in start.ancestors() {
        if !dir.starts_with(stop_at) {
            break;
        }
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
        if dir == stop_at {
            break;
        }
    }
    None
}

fn run_formatter_command(
    command: &FormatterCommand,
    input: &str,
    cancellation: &FormatterCancellation,
) -> Result<String, String> {
    run_formatter_command_with_timeout(command, input, cancellation, FORMATTER_TIMEOUT)
}

fn run_formatter_command_with_timeout(
    command: &FormatterCommand,
    input: &str,
    cancellation: &FormatterCancellation,
    timeout: Duration,
) -> Result<String, String> {
    if cancellation.is_cancelled() {
        return Err(format!(
            "formatter `{}` was cancelled",
            command_line_for_message(command)
        ));
    }
    let mut child = spawn_formatter(command)?;
    cancellation.set_pid(child.id());
    let stdin = child.stdin.take().ok_or_else(|| {
        format!(
            "failed to open stdin for formatter `{}`",
            command_line_for_message(command)
        )
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        format!(
            "failed to open stdout for formatter `{}`",
            command_line_for_message(command)
        )
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        format!(
            "failed to open stderr for formatter `{}`",
            command_line_for_message(command)
        )
    })?;
    let stdout_reader = spawn_pipe_reader(stdout, max_stdout_bytes(input.len()));
    let stderr_reader = spawn_pipe_reader(stderr, MAX_FORMATTER_STDERR_BYTES);
    let stdin_writer = spawn_stdin_writer(stdin, input.as_bytes().to_vec());
    let status = wait_for_formatter(&mut child, command, cancellation, timeout);
    cancellation.clear_pid();
    let status = status?;
    let stdout = collect_pipe("stdout", stdout_reader, command, Some(&mut child))?;
    let stderr = collect_pipe("stderr", stderr_reader, command, Some(&mut child))?;
    let stdin_result = collect_stdin_writer(stdin_writer, command);
    if !status.success() {
        return Err(format!(
            "formatter `{}` exited with status {}: {}",
            command_line_for_message(command),
            status,
            truncate_for_error(&String::from_utf8_lossy(&stderr))
        ));
    }
    stdin_result?;
    String::from_utf8(stdout).map_err(|err| {
        format!(
            "formatter `{}` emitted non-UTF-8 stdout: {err}",
            command_line_for_message(command)
        )
    })
}

fn wait_for_formatter(
    child: &mut std::process::Child,
    command: &FormatterCommand,
    cancellation: &FormatterCancellation,
    timeout: Duration,
) -> Result<std::process::ExitStatus, String> {
    let started = Instant::now();
    loop {
        if cancellation.is_cancelled() {
            terminate_formatter(child);
            let _ = child.wait();
            return Err(format!(
                "formatter `{}` was cancelled",
                command_line_for_message(command)
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if started.elapsed() >= timeout => {
                terminate_formatter(child);
                let _ = child.wait();
                return Err(format!(
                    "formatter `{}` timed out after {}",
                    command_line_for_message(command),
                    format_duration(timeout)
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(err) => {
                return Err(format!(
                    "failed to wait for formatter `{}`: {err}",
                    command_line_for_message(command)
                ));
            }
        }
    }
}

fn spawn_formatter(command: &FormatterCommand) -> Result<std::process::Child, String> {
    #[cfg(unix)]
    {
        for attempt in 0..=FORMATTER_SPAWN_RETRIES {
            match spawn_formatter_once(command) {
                Ok(child) => return Ok(child),
                Err(err) if is_text_file_busy(&err) && attempt < FORMATTER_SPAWN_RETRIES => {
                    thread::sleep(FORMATTER_SPAWN_RETRY_DELAY);
                }
                Err(err) => return Err(format_formatter_spawn_error(command, err)),
            }
        }
        unreachable!("formatter spawn retry loop must return");
    }

    #[cfg(not(unix))]
    {
        spawn_formatter_once(command).map_err(|err| format_formatter_spawn_error(command, err))
    }
}

fn spawn_formatter_once(command: &FormatterCommand) -> std::io::Result<std::process::Child> {
    let mut builder = Command::new(&command.command);
    builder
        .args(&command.args)
        .current_dir(&command.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_formatter_process(&mut builder);
    builder.spawn()
}

fn format_formatter_spawn_error(command: &FormatterCommand, err: std::io::Error) -> String {
    format!(
        "failed to start formatter `{}` in {}: {err}",
        command_line_for_message(command),
        command.cwd.display()
    )
}

#[cfg(unix)]
fn is_text_file_busy(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::ETXTBSY)
}

#[cfg(unix)]
fn configure_formatter_process(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_formatter_process(_command: &mut Command) {}

#[cfg(unix)]
fn terminate_formatter(child: &mut std::process::Child) {
    terminate_process_id(child.id());
    let _ = child.kill();
}

#[cfg(unix)]
fn terminate_process_id(pid: u32) {
    let pid = pid as libc::pid_t;
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
        libc::kill(pid, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn terminate_formatter(child: &mut std::process::Child) {
    terminate_process_id(child.id());
    let _ = child.kill();
}

#[cfg(not(unix))]
fn terminate_process_id(pid: u32) {
    terminate_process_tree(pid);
}

#[cfg(windows)]
fn terminate_process_tree(pid: u32) {
    let taskkill = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join("taskkill.exe");
    let _ = Command::new(taskkill)
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(all(not(unix), not(windows)))]
fn terminate_process_tree(_pid: u32) {}

type PipeReadResult = Result<Vec<u8>, String>;
type StdinWriteResult = Result<(), String>;

fn spawn_stdin_writer(
    mut stdin: impl Write + Send + 'static,
    input: Vec<u8>,
) -> mpsc::Receiver<StdinWriteResult> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let result = stdin.write_all(&input).map_err(|err| err.to_string());
        let _ = sender.send(result);
    });
    receiver
}

fn collect_stdin_writer(
    receiver: mpsc::Receiver<StdinWriteResult>,
    command: &FormatterCommand,
) -> Result<(), String> {
    match receiver.recv_timeout(FORMATTER_READER_GRACE) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(format!(
            "failed to write document to formatter `{}`: {err}",
            command_line_for_message(command)
        )),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "formatter `{}` did not finish reading stdin",
            command_line_for_message(command)
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(format!(
            "formatter `{}` stdin writer stopped unexpectedly",
            command_line_for_message(command)
        )),
    }
}

fn spawn_pipe_reader(
    pipe: impl Read + Send + 'static,
    limit: usize,
) -> mpsc::Receiver<PipeReadResult> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(read_pipe_limited(pipe, limit));
    });
    receiver
}

fn collect_pipe(
    name: &str,
    receiver: mpsc::Receiver<PipeReadResult>,
    command: &FormatterCommand,
    child: Option<&mut std::process::Child>,
) -> Result<Vec<u8>, String> {
    match receiver.recv_timeout(FORMATTER_READER_GRACE) {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(err)) => Err(format!(
            "failed to read formatter `{}` {name}: {err}",
            command_line_for_message(command)
        )),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            if let Some(child) = child {
                terminate_formatter(child);
                let _ = child.wait();
            }
            Err(format!(
                "formatter `{}` did not close {name}",
                command_line_for_message(command)
            ))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(format!(
            "formatter `{}` {name} reader stopped unexpectedly",
            command_line_for_message(command)
        )),
    }
}

fn read_pipe_limited(mut pipe: impl Read, limit: usize) -> PipeReadResult {
    let mut bytes = Vec::new();
    let mut buf = [0; 8192];
    loop {
        let read = pipe.read(&mut buf).map_err(|err| err.to_string())?;
        if read == 0 {
            return Ok(bytes);
        }
        if bytes.len().saturating_add(read) > limit {
            return Err(format!("output exceeded {} bytes", limit));
        }
        bytes.extend_from_slice(&buf[..read]);
    }
}

fn max_stdout_bytes(input_len: usize) -> usize {
    input_len
        .saturating_mul(4)
        .saturating_add(1024 * 1024)
        .min(MAX_FORMATTER_STDOUT_BYTES)
}

fn standard_command_cwd(context: &FormatContext<'_>) -> PathBuf {
    let start = context.file.abs_path();
    let start_dir = start.parent().unwrap_or(start.as_path());
    match context.language {
        Language::Rust => nearest_manifest(start_dir, &context.workspace_root, "Cargo.toml")
            .and_then(|manifest| manifest.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| context.workspace_root.clone()),
        Language::Go => nearest_manifest(start_dir, &context.workspace_root, "go.mod")
            .and_then(|manifest| manifest.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| context.workspace_root.clone()),
        Language::Python => ["pyproject.toml", "setup.cfg"]
            .into_iter()
            .find_map(|name| {
                nearest_manifest(start_dir, &context.workspace_root, name)
                    .and_then(|manifest| manifest.parent().map(Path::to_path_buf))
            })
            .unwrap_or_else(|| context.workspace_root.clone()),
        Language::Cpp => nearest_manifest(start_dir, &context.workspace_root, ".clang-format")
            .and_then(|manifest| manifest.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| context.workspace_root.clone()),
        _ => context.workspace_root.clone(),
    }
}

fn rust_edition(context: &FormatContext<'_>) -> String {
    let abs_path = context.file.abs_path();
    let Some(manifest) = nearest_manifest(
        abs_path.parent().unwrap_or(abs_path.as_path()),
        &context.workspace_root,
        "Cargo.toml",
    ) else {
        return "2024".to_string();
    };
    let Ok(raw) = std::fs::read_to_string(manifest) else {
        return "2024".to_string();
    };
    toml::from_str::<toml::Value>(&raw)
        .ok()
        .and_then(|value| {
            value
                .get("package")
                .and_then(|package| package.get("edition"))
                .and_then(toml::Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "2024".to_string())
}

fn formatter_relative_file(project: &dyn Project, file: &ProjectFile) -> PathBuf {
    let workspace_root = project.workspace_root_for_file(file);
    file.abs_path()
        .strip_prefix(&workspace_root)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| file.rel_path().to_path_buf())
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() > 0 {
        format!("{} seconds", duration.as_secs())
    } else {
        format!("{} milliseconds", duration.as_millis())
    }
}

fn expand_placeholders(value: &str, context: &FormatContext<'_>) -> String {
    value
        .replace("{file}", &context.file.abs_path().display().to_string())
        .replace(
            "{relativeFile}",
            &context.relative_file.to_string_lossy().replace('\\', "/"),
        )
        .replace(
            "{workspaceRoot}",
            &context.workspace_root.display().to_string(),
        )
        .replace("{language}", context.language.config_label())
}

fn resolve_cwd(value: &str, workspace_root: &Path) -> PathBuf {
    let path = PathBuf::from(normalize_cwd_value(value));
    if path.is_absolute() {
        path
    } else {
        workspace_root.join(path)
    }
}

#[cfg(not(windows))]
fn normalize_cwd_value(value: &str) -> String {
    value.to_string()
}

#[cfg(windows)]
fn normalize_cwd_value(value: &str) -> String {
    value.replace('/', "\\")
}

fn glob_matches(pattern: &str, rel: &str) -> bool {
    Pattern::new(pattern)
        .map(|pattern| pattern.matches(rel))
        .unwrap_or(false)
}

fn normalized_rel_path(context: &FormatContext<'_>) -> String {
    context.relative_file.to_string_lossy().replace('\\', "/")
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
    use crate::analyzer::{FilesystemProject, MultiRootProject, Project};
    use crate::path_normalization::NormalizePath;

    fn project(root: &Path) -> FilesystemProject {
        FilesystemProject::new(root).expect("filesystem project")
    }

    fn project_file(project: &dyn Project, rel_path: &str) -> ProjectFile {
        project
            .file_by_rel_path(Path::new(rel_path))
            .expect("project file")
    }

    fn context<'a>(
        project: &'a dyn Project,
        file: &'a ProjectFile,
        language: Language,
    ) -> FormatContext<'a> {
        FormatContext {
            file,
            workspace_root: project.workspace_root_for_file(file),
            relative_file: formatter_relative_file(project, file),
            language,
        }
    }

    #[cfg(not(windows))]
    fn assert_command_invokes(actual: &str, expected: &str) {
        assert_eq!(actual, expected);
    }

    #[cfg(windows)]
    fn assert_command_invokes(actual: &str, expected: &str) {
        let stem = Path::new(actual)
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or(actual);
        assert_eq!(stem.to_ascii_lowercase(), expected.to_ascii_lowercase());
    }

    #[cfg(not(windows))]
    fn configured_test_command(_root: &Path, command: &str) -> String {
        command.to_string()
    }

    #[cfg(windows)]
    fn configured_test_command(root: &Path, command: &str) -> String {
        root.join(format!("{command}.exe")).display().to_string()
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
        let ctx = context(&project, &file, Language::TypeScript);
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
        let generated_ctx = context(&project, &generated_file, Language::TypeScript);
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
        let ctx = context(&project, &file, Language::Rust);
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
        assert_command_invokes(&command.command, "rustfmt");
        assert_eq!(
            command.args,
            vec![
                "--stdin-filename",
                &file.abs_path().display().to_string(),
                "pkg/src/lib.rs",
                "rust",
            ]
        );
        assert_eq!(command.cwd, root.clone().normalize().join("pkg"));
    }

    #[test]
    fn configured_rule_wins_before_builtin_formatter() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("main.go"), "package main\n").unwrap();
        let project = project(&root);
        let file = project_file(&project, "main.go");
        let ctx = context(&project, &file, Language::Go);
        let rules = vec![FormatterCommandRule {
            include: vec!["*.go".to_string()],
            exclude: Vec::new(),
            language: Some("go".to_string()),
            command: configured_test_command(&root, "custom-gofmt"),
            args: Vec::new(),
            cwd: None,
        }];
        let command = resolve_formatter_command(&ctx, &rules).unwrap().unwrap();
        assert_command_invokes(&command.command, "custom-gofmt");
    }

    #[test]
    fn builtin_formatter_uses_standard_stdout_commands() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("lib.rs"), "fn main(){}").unwrap();
        let project = project(&root);
        let file = project_file(&project, "lib.rs");
        let ctx = context(&project, &file, Language::Rust);
        let command = discover_builtin_formatter(&ctx).unwrap();
        assert_command_invokes(&command.command, "rustfmt");
        assert_eq!(command.args, vec!["--edition", "2024", "--emit", "stdout"]);
        assert_eq!(command.cwd, root.normalize());
    }

    #[test]
    fn rust_builtin_uses_nearest_cargo_manifest_edition_and_cwd() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("crate/src")).unwrap();
        std::fs::write(
            root.join("crate/Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(root.join("crate/src/lib.rs"), "async fn f() {}\n").unwrap();
        let project = project(&root);
        let file = project_file(&project, "crate/src/lib.rs");
        let ctx = context(&project, &file, Language::Rust);
        let command = discover_builtin_formatter(&ctx).unwrap();
        assert_eq!(command.args, vec!["--edition", "2021", "--emit", "stdout"]);
        assert_eq!(command.cwd, root.normalize().join("crate"));
    }

    #[test]
    fn javascript_typescript_requires_override_rule() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("web/src")).unwrap();
        std::fs::write(
            root.join("web/package.json"),
            r#"{"scripts":{"format:stdin":"prettier"}}"#,
        )
        .unwrap();
        std::fs::write(root.join("web/src/app.ts"), "const x=1;").unwrap();
        let project = project(&root);
        let file = project_file(&project, "web/src/app.ts");
        let ctx = context(&project, &file, Language::TypeScript);
        assert!(discover_builtin_formatter(&ctx).is_none());
    }

    #[test]
    fn formatter_rules_use_owning_workspace_root_in_multi_root_project() {
        let temp = tempfile::tempdir().unwrap();
        let outer = temp.path().canonicalize().unwrap();
        let service_a = outer.join("service-a");
        let service_b = outer.join("service-b");
        std::fs::create_dir_all(service_a.join("src")).unwrap();
        std::fs::create_dir_all(service_b.join("src")).unwrap();
        std::fs::write(service_a.join("src/app.ts"), "const x=1;").unwrap();
        std::fs::write(service_b.join("src/app.ts"), "const x=1;").unwrap();
        let project =
            MultiRootProject::new([service_a.clone(), service_b]).expect("multi root project");
        let file = project
            .file_by_abs_path(&service_a.join("src/app.ts"))
            .expect("project file");
        let ctx = context(&project, &file, Language::TypeScript);
        let rule = FormatterCommandRule {
            include: vec!["src/**/*.ts".to_string()],
            exclude: Vec::new(),
            language: Some("typescript".to_string()),
            command: "fmt".to_string(),
            args: vec!["{relativeFile}".to_string(), "{workspaceRoot}".to_string()],
            cwd: Some("tools".to_string()),
        };

        assert!(rule_matches(&rule, &ctx));
        let command = formatter_command_from_rule(&rule, &ctx).unwrap();
        assert_eq!(command.cwd, service_a.clone().normalize().join("tools"));
        assert_eq!(
            command.args,
            vec![
                "src/app.ts".to_string(),
                service_a.clone().normalize().display().to_string()
            ]
        );
    }

    #[test]
    fn formatter_rules_use_deepest_workspace_root_in_nested_multi_root_project() {
        let temp = tempfile::tempdir().unwrap();
        let outer = temp.path().canonicalize().unwrap();
        let parent = outer.join("repo");
        let nested = parent.join("frontend");
        std::fs::create_dir_all(nested.join("src")).unwrap();
        std::fs::write(nested.join("src/app.ts"), "const x=1;").unwrap();
        let project =
            MultiRootProject::new([parent.clone(), nested.clone()]).expect("multi root project");
        let file = project
            .file_by_abs_path(&nested.join("src/app.ts"))
            .expect("project file");
        let ctx = context(&project, &file, Language::TypeScript);
        let rule = FormatterCommandRule {
            include: vec!["src/**/*.ts".to_string()],
            exclude: Vec::new(),
            language: Some("typescript".to_string()),
            command: "fmt".to_string(),
            args: vec!["{relativeFile}".to_string(), "{workspaceRoot}".to_string()],
            cwd: Some("tools".to_string()),
        };

        assert!(rule_matches(&rule, &ctx));
        let command = formatter_command_from_rule(&rule, &ctx).unwrap();
        assert_eq!(command.cwd, nested.clone().normalize().join("tools"));
        assert_eq!(
            command.args,
            vec![
                "src/app.ts".to_string(),
                nested.clone().normalize().display().to_string()
            ]
        );
    }

    #[test]
    fn ambiguous_languages_require_override_rules() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("main.rb"), "puts 'hi'\n").unwrap();
        let project = project(&root);
        let file = project_file(&project, "main.rb");
        let ctx = context(&project, &file, Language::Ruby);
        assert!(discover_builtin_formatter(&ctx).is_none());
    }

    fn run_test_formatter(command: &FormatterCommand, input: &str) -> Result<String, String> {
        run_formatter_command(command, input, &FormatterCancellation::new())
    }

    #[cfg(unix)]
    fn run_test_formatter_with_timeout(
        command: &FormatterCommand,
        input: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        run_formatter_command_with_timeout(command, input, &FormatterCancellation::new(), timeout)
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
        let output = run_test_formatter(&command, "hello\n").unwrap();
        assert_eq!(output, "HELLO\n");
    }

    #[cfg(unix)]
    #[test]
    fn formatter_executor_drains_stdout_while_writing_large_stdin() {
        let temp = tempfile::tempdir().unwrap();
        let stub = temp.path().join("stub-cat");
        stub_command(&stub, "#!/bin/sh\ncat\n");
        let command = FormatterCommand {
            command: stub.display().to_string(),
            args: Vec::new(),
            cwd: temp.path().to_path_buf(),
        };
        let input = "x".repeat(256 * 1024);
        let output = run_test_formatter(&command, &input).unwrap();
        assert_eq!(output, input);
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
        let error = run_test_formatter(&command, "hello\n").unwrap_err();
        assert!(error.contains("exited with status"), "{error}");
        assert!(error.contains("nope"), "{error}");
    }

    #[test]
    fn formatter_pipe_reader_rejects_oversized_output() {
        let error = read_pipe_limited(&b"abcdef"[..], 5).unwrap_err();
        assert!(error.contains("exceeded 5 bytes"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn formatter_executor_times_out_hung_formatter() {
        let temp = tempfile::tempdir().unwrap();
        let stub = temp.path().join("stub-hang");
        stub_command(&stub, "#!/bin/sh\nwhile true; do :; done\n");
        let command = FormatterCommand {
            command: stub.display().to_string(),
            args: Vec::new(),
            cwd: temp.path().to_path_buf(),
        };
        let error =
            run_test_formatter_with_timeout(&command, "hello\n", TEST_HUNG_FORMATTER_TIMEOUT)
                .unwrap_err();
        assert!(error.contains("timed out"), "{error}");
    }

    #[test]
    #[ignore = "requires BIFROST_FORMATTER_INTEGRATION_TESTS=1 and rustfmt on PATH"]
    fn formatter_integration_rustfmt_stdout_contract() {
        if std::env::var("BIFROST_FORMATTER_INTEGRATION_TESTS")
            .ok()
            .as_deref()
            != Some("1")
        {
            eprintln!("set BIFROST_FORMATTER_INTEGRATION_TESTS=1 to run real formatter tests");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let command = FormatterCommand {
            command: "rustfmt".to_string(),
            args: vec![
                "--edition".to_string(),
                "2024".to_string(),
                "--emit".to_string(),
                "stdout".to_string(),
            ],
            cwd: temp.path().to_path_buf(),
        };
        let output = run_test_formatter(&command, "fn main(){println!(\"hi\");}\n").unwrap();
        assert!(output.contains("fn main()"), "{output}");
        assert!(output.contains("println!"), "{output}");
    }
}
