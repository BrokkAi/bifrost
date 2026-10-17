use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const READER_GRACE: Duration = Duration::from_secs(1);
#[cfg(unix)]
const SPAWN_RETRIES: usize = 5;
#[cfg(unix)]
const SPAWN_RETRY_DELAY: Duration = Duration::from_millis(10);

pub struct BoundedProcessRequest {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub clear_env: bool,
    pub cwd: PathBuf,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
    pub description: String,
}

#[derive(Debug)]
pub struct BoundedProcessOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub fn run_bounded_process(
    request: &BoundedProcessRequest,
    is_cancelled: impl Fn() -> bool,
) -> Result<BoundedProcessOutput, String> {
    if is_cancelled() {
        return Err(format!("{} was cancelled", request.description));
    }
    let mut child = spawn_process(request)?;
    let stdin_writer = match request.stdin.as_ref() {
        Some(input) => {
            let stdin = child
                .take_stdin()
                .ok_or_else(|| format!("failed to open stdin for {}", request.description))?;
            Some(spawn_stdin_writer(stdin, input.clone()))
        }
        None => None,
    };
    let stdout = child
        .take_stdout()
        .ok_or_else(|| format!("failed to open stdout for {}", request.description))?;
    let stderr = child
        .take_stderr()
        .ok_or_else(|| format!("failed to open stderr for {}", request.description))?;
    let stdout_reader = spawn_pipe_reader(stdout, request.stdout_limit);
    let stderr_reader = spawn_pipe_reader(stderr, request.stderr_limit);
    let status = wait_for_process(&mut child, request, &is_cancelled);

    // Always join all pipe workers. Callers may hold concurrency or lifecycle
    // guards around this function, and no inherited process handle may outlive
    // those guards.
    let stdout = collect_pipe("stdout", stdout_reader, request, &mut child);
    let stderr = collect_pipe("stderr", stderr_reader, request, &mut child);
    let stdin_result = stdin_writer.map(|worker| collect_stdin_writer(worker, &mut child));
    let status = status?;
    let stdout = stdout?;
    let stderr = stderr?;
    if let Some(Err(error)) = stdin_result
        && (status.success() || !error.is_broken_pipe())
    {
        return Err(error.message(request));
    }
    Ok(BoundedProcessOutput {
        status,
        stdout,
        stderr,
    })
}

/// A spawned child together with the process tree it owns.
///
/// Windows gives every process its own handle table, and `CreateProcessW`
/// duplicates every inheritable handle into the new process unless the caller
/// passes an explicit handle list. Rust's std marks the child ends of the
/// pipes it creates as inheritable and passes no handle list, so a process
/// this value spawned hands whatever inheritable handle it holds to every
/// process *it* spawns in turn. Killing the direct child therefore does not
/// close a pipe whose write end a descendant inherited, and a reader waiting
/// for end-of-file waits forever (#5377).
///
/// This value closes that gap by making the direct child the root of a tree it
/// owns: on Windows the child is created suspended, assigned to a job object
/// with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and resumed, so every descendant
/// stays in the job; on Unix the child is a session leader (`setsid`), so
/// every descendant shares its process group. [`Self::terminate_tree_and_wait`]
/// then kills the whole tree, and callers may join pipe readers afterwards:
/// no writer survives the termination.
///
/// Descendants stay in the tree unless they break away themselves
/// (`CREATE_BREAKAWAY_FROM_JOB` on Windows, `setsid` on Unix).
pub struct OwnedProcess {
    child: Child,
    #[cfg(windows)]
    job: WindowsJob,
}

impl OwnedProcess {
    /// Spawn `command` as the root of a process tree this value owns.
    ///
    /// `command` must not set `creation_flags` on Windows; the suspended
    /// start and job assignment are what keeps descendants in the tree.
    pub fn spawn(command: &mut Command) -> std::io::Result<Self> {
        #[cfg(windows)]
        {
            Self::spawn_windows(command)
        }
        #[cfg(not(windows))]
        {
            configure_process(command);
            command.spawn().map(Self::new)
        }
    }

    #[cfg(not(windows))]
    fn new(child: Child) -> Self {
        Self { child }
    }

    /// The child's stdin, or `None` unless the command asked for a pipe.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    /// The child's stdout, or `None` unless the command asked for a pipe.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    /// The child's stderr, or `None` unless the command asked for a pipe.
    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }

    /// The direct child's exit status once it has exited.
    ///
    /// On Windows this reports `None` while any process of the owned tree is
    /// still running, so a caller that polls it cannot observe "finished"
    /// before the tree has drained.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        #[cfg(windows)]
        if status.is_some() && !self.job.try_wait()? {
            return Ok(None);
        }
        Ok(status)
    }

    /// Reap the direct child, and on Windows wait for the whole owned tree.
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        let status = self.child.wait()?;
        #[cfg(windows)]
        self.job.wait()?;
        Ok(status)
    }

    /// Kill every process of the owned tree, not only the direct child.
    #[cfg(windows)]
    pub fn terminate(&mut self) -> std::io::Result<()> {
        self.job.terminate()
    }

    /// Kill every process of the owned tree, not only the direct child.
    #[cfg(unix)]
    pub fn terminate(&mut self) -> std::io::Result<()> {
        terminate_process_id(self.child.id());
        match self.child.kill() {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Kill every process of the owned tree, not only the direct child.
    #[cfg(all(not(unix), not(windows)))]
    pub fn terminate(&mut self) -> std::io::Result<()> {
        self.child.kill()
    }

    /// Terminate the owned tree and reap it, reporting what could not be done.
    pub fn terminate_tree_and_wait(&mut self) -> Result<(), String> {
        let terminate = self.terminate();
        let wait = self.wait();
        match (terminate, wait) {
            (Ok(()), Ok(_)) => Ok(()),
            (Err(terminate), Ok(_)) => Err(format!("termination failed: {terminate}")),
            (Ok(()), Err(wait)) => Err(format!("group wait failed: {wait}")),
            (Err(terminate), Err(wait)) => Err(format!(
                "termination failed: {terminate}; group wait failed: {wait}"
            )),
        }
    }
}

#[cfg(windows)]
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let _ = self.job.terminate();
        let _ = self.child.wait();
        let _ = self.job.wait();
    }
}

#[cfg(windows)]
impl OwnedProcess {
    fn spawn_windows(command: &mut Command) -> std::io::Result<Self> {
        use std::os::windows::{io::AsRawHandle, process::CommandExt};
        use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

        let job = WindowsJob::new()?;
        command.creation_flags(CREATE_SUSPENDED);
        let mut child = command.spawn()?;
        let process = child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        if let Err(err) = job.assign(process) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }
        if let Err(err) = resume_process(process) {
            let _ = job.terminate();
            let _ = child.wait();
            let _ = job.wait();
            return Err(err);
        }
        Ok(Self { child, job })
    }
}

fn spawn_process(request: &BoundedProcessRequest) -> Result<OwnedProcess, String> {
    #[cfg(unix)]
    {
        for attempt in 0..=SPAWN_RETRIES {
            match spawn_process_once(request) {
                Ok(child) => return Ok(child),
                Err(err) if is_text_file_busy(&err) && attempt < SPAWN_RETRIES => {
                    thread::sleep(SPAWN_RETRY_DELAY);
                }
                Err(err) => return Err(format_spawn_error(request, err)),
            }
        }
        unreachable!("bounded process spawn retry loop must return");
    }

    #[cfg(not(unix))]
    {
        spawn_process_once(request).map_err(|err| format_spawn_error(request, err))
    }
}

fn spawn_process_once(request: &BoundedProcessRequest) -> std::io::Result<OwnedProcess> {
    let mut builder = Command::new(&request.program);
    if request.clear_env {
        builder.env_clear();
    }
    builder
        .args(&request.args)
        .envs(request.env.iter().cloned())
        .current_dir(&request.cwd)
        .stdin(if request.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    OwnedProcess::spawn(&mut builder)
}

fn format_spawn_error(request: &BoundedProcessRequest, err: std::io::Error) -> String {
    format!(
        "failed to start {} in {}: {err}",
        request.description,
        request.cwd.display()
    )
}

fn wait_for_process(
    child: &mut OwnedProcess,
    request: &BoundedProcessRequest,
    is_cancelled: &impl Fn() -> bool,
) -> Result<ExitStatus, String> {
    let started = Instant::now();
    loop {
        if is_cancelled() {
            let cleanup = child.terminate_tree_and_wait();
            return Err(format!(
                "{} was cancelled{}",
                request.description,
                cleanup_error_suffix(cleanup)
            ));
        }
        match child.try_wait() {
            Ok(Some(_)) => {
                return child.wait().map_err(|err| {
                    format!("failed to wait for {} group: {err}", request.description)
                });
            }
            Ok(None) if started.elapsed() >= request.timeout => {
                let cleanup = child.terminate_tree_and_wait();
                return Err(format!(
                    "{} timed out after {}{}",
                    request.description,
                    format_duration(request.timeout),
                    cleanup_error_suffix(cleanup)
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(err) => {
                let cleanup = child.terminate_tree_and_wait();
                return Err(format!(
                    "failed to poll {}: {err}{}",
                    request.description,
                    cleanup_error_suffix(cleanup)
                ));
            }
        }
    }
}

fn cleanup_error_suffix(cleanup: Result<(), String>) -> String {
    cleanup
        .err()
        .map(|err| format!(" (cleanup error: {err})"))
        .unwrap_or_default()
}

type PipeReadResult = Result<Vec<u8>, String>;
type StdinWriteResult = std::io::Result<()>;

enum StdinWriteFailure {
    TimedOut { cleanup: Result<(), String> },
    Write(std::io::Error),
    Panicked,
}

impl StdinWriteFailure {
    fn is_broken_pipe(&self) -> bool {
        matches!(self, Self::Write(error) if error.kind() == std::io::ErrorKind::BrokenPipe)
    }

    fn message(self, request: &BoundedProcessRequest) -> String {
        match self {
            Self::TimedOut { cleanup } => format!(
                "{} did not finish reading stdin{}",
                request.description,
                cleanup_error_suffix(cleanup)
            ),
            Self::Write(error) => {
                format!("failed to write stdin for {}: {error}", request.description)
            }
            Self::Panicked => format!("{} stdin writer panicked", request.description),
        }
    }
}

fn spawn_stdin_writer(
    mut stdin: impl Write + Send + 'static,
    input: Vec<u8>,
) -> JoinHandle<StdinWriteResult> {
    thread::spawn(move || stdin.write_all(&input))
}

fn collect_stdin_writer(
    worker: JoinHandle<StdinWriteResult>,
    child: &mut OwnedProcess,
) -> Result<(), StdinWriteFailure> {
    let timed_out = !worker_finished_within(&worker, READER_GRACE);
    let cleanup = timed_out.then(|| child.terminate_tree_and_wait());
    match worker.join() {
        Ok(Ok(())) if !timed_out => Ok(()),
        Ok(Ok(())) => Err(StdinWriteFailure::TimedOut {
            cleanup: cleanup.expect("timeout cleanup must exist"),
        }),
        Ok(Err(error)) => Err(StdinWriteFailure::Write(error)),
        Err(_) => Err(StdinWriteFailure::Panicked),
    }
}

fn spawn_pipe_reader(pipe: impl Read + Send + 'static, limit: usize) -> JoinHandle<PipeReadResult> {
    thread::spawn(move || read_pipe_limited(pipe, limit))
}

fn collect_pipe(
    name: &str,
    worker: JoinHandle<PipeReadResult>,
    request: &BoundedProcessRequest,
    child: &mut OwnedProcess,
) -> Result<Vec<u8>, String> {
    let timed_out = !worker_finished_within(&worker, READER_GRACE);
    let cleanup = timed_out.then(|| child.terminate_tree_and_wait());
    match worker.join() {
        Ok(Ok(bytes)) if !timed_out => Ok(bytes),
        Ok(Ok(_)) => Err(format!(
            "{} did not close {name}{}",
            request.description,
            cleanup_error_suffix(cleanup.expect("timeout cleanup must exist"))
        )),
        Ok(Err(err)) => Err(format!(
            "failed to read {} {name}: {err}",
            request.description
        )),
        Err(_) => Err(format!("{} {name} reader panicked", request.description)),
    }
}

fn worker_finished_within<T>(worker: &JoinHandle<T>, timeout: Duration) -> bool {
    let started = Instant::now();
    while !worker.is_finished() && started.elapsed() < timeout {
        thread::sleep(Duration::from_millis(10));
    }
    worker.is_finished()
}

pub fn read_limited(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut exceeded = false;
    let mut buf = [0; 8192];
    loop {
        let read = reader.read(&mut buf).map_err(|err| err.to_string())?;
        if read == 0 {
            return if exceeded {
                Err(format!("output exceeded {limit} bytes"))
            } else {
                Ok(bytes)
            };
        }
        if exceeded || bytes.len().saturating_add(read) > limit {
            exceeded = true;
        } else {
            bytes.extend_from_slice(&buf[..read]);
        }
    }
}

fn read_pipe_limited(pipe: impl Read, limit: usize) -> PipeReadResult {
    read_limited(pipe, limit)
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() > 0 {
        format!("{} seconds", duration.as_secs())
    } else {
        format!("{} milliseconds", duration.as_millis())
    }
}

#[cfg(unix)]
fn is_text_file_busy(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::ETXTBSY)
}

#[cfg(unix)]
fn configure_process(command: &mut Command) {
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

#[cfg(all(not(unix), not(windows)))]
fn configure_process(_command: &mut Command) {}

#[cfg(unix)]
fn terminate_process_id(pid: u32) {
    let pid = pid as libc::pid_t;
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
        libc::kill(pid, libc::SIGKILL);
    }
}

#[cfg(windows)]
struct WindowsJob(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl WindowsJob {
    fn new() -> std::io::Result<Self> {
        use std::mem::size_of;
        use std::ptr;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let job = Self(handle);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(job)
    }

    fn assign(&self, process: windows_sys::Win32::Foundation::HANDLE) -> std::io::Result<()> {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        if unsafe { AssignProcessToJobObject(self.0, process) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn terminate(&self) -> std::io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        if unsafe { TerminateJobObject(self.0, 1) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn wait(&self) -> std::io::Result<()> {
        while !self.try_wait()? {
            thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    fn try_wait(&self) -> std::io::Result<bool> {
        use std::mem::size_of;
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
            QueryInformationJobObject,
        };
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let queried = unsafe {
            QueryInformationJobObject(
                self.0,
                JobObjectBasicAccountingInformation,
                &mut accounting as *mut _ as *mut _,
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if queried == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(accounting.ActiveProcesses == 0)
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsJob {
    fn drop(&mut self) {
        close_windows_handle(self.0);
    }
}

#[cfg(windows)]
fn close_windows_handle(handle: windows_sys::Win32::Foundation::HANDLE) {
    use windows_sys::Win32::Foundation::CloseHandle;
    unsafe { CloseHandle(handle) };
}

#[cfg(windows)]
fn resume_process(process: windows_sys::Win32::Foundation::HANDLE) -> std::io::Result<()> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessId, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
    };

    let process_id = unsafe { GetProcessId(process) };
    if process_id == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let snapshot = WindowsHandle(snapshot);
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    if unsafe { Thread32First(snapshot.0, &mut entry) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut resumed = false;
    loop {
        if entry.th32OwnerProcessID == process_id {
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if thread.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let thread = WindowsHandle(thread);
            if unsafe { ResumeThread(thread.0) } == u32::MAX {
                return Err(std::io::Error::last_os_error());
            }
            resumed = true;
        }
        if unsafe { Thread32Next(snapshot.0, &mut entry) } == 0 {
            break;
        }
    }
    if resumed {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "process primary thread was not found",
        ))
    }
}

#[cfg(windows)]
struct WindowsHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for WindowsHandle {
    fn drop(&mut self) {
        close_windows_handle(self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELPER_ROLE: &str = "BIFROST_BOUNDED_PROCESS_HELPER_ROLE";
    const HELPER_MARKER: &str = "BIFROST_BOUNDED_PROCESS_HELPER_MARKER";

    #[test]
    fn bounded_process_timeout_cleans_up_descendants() {
        let temporary = tempfile::tempdir().unwrap();
        let marker = temporary.path().join("escaped-descendant");
        let executable = std::env::current_exe().unwrap();
        let request = BoundedProcessRequest {
            program: executable.into_os_string(),
            args: vec![
                OsString::from("--exact"),
                OsString::from("process::tests::bounded_process_descendant_helper"),
                OsString::from("--nocapture"),
            ],
            env: vec![
                (OsString::from(HELPER_ROLE), OsString::from("parent")),
                (
                    OsString::from(HELPER_MARKER),
                    marker.as_os_str().to_os_string(),
                ),
            ],
            clear_env: false,
            cwd: temporary.path().to_path_buf(),
            stdin: None,
            timeout: Duration::from_millis(100),
            stdout_limit: 64 * 1024,
            stderr_limit: 64 * 1024,
            description: "bounded process cleanup test".to_string(),
        };
        let error = run_bounded_process(&request, || false).unwrap_err();
        assert!(error.contains("timed out"), "{error}");
        thread::sleep(Duration::from_millis(700));
        assert!(!marker.exists(), "descendant escaped timeout cleanup");
    }

    #[test]
    fn bounded_process_descendant_helper() {
        match std::env::var(HELPER_ROLE).ok().as_deref() {
            Some("parent") => {
                let executable = std::env::current_exe().unwrap();
                let mut child = Command::new(executable)
                    .args([
                        "--exact",
                        "process::tests::bounded_process_descendant_helper",
                        "--nocapture",
                    ])
                    .env(HELPER_ROLE, "child")
                    .spawn()
                    .unwrap();
                loop {
                    let _ = child.try_wait();
                    thread::sleep(Duration::from_millis(50));
                }
            }
            Some("child") => {
                thread::sleep(Duration::from_millis(500));
                std::fs::write(std::env::var_os(HELPER_MARKER).unwrap(), b"escaped").unwrap();
            }
            _ => {}
        }
    }
}
