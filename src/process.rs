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

pub(crate) struct BoundedProcessRequest {
    pub(crate) program: OsString,
    pub(crate) args: Vec<OsString>,
    pub(crate) env: Vec<(OsString, OsString)>,
    pub(crate) cwd: PathBuf,
    pub(crate) stdin: Option<Vec<u8>>,
    pub(crate) timeout: Duration,
    pub(crate) stdout_limit: usize,
    pub(crate) stderr_limit: usize,
    pub(crate) description: String,
}

#[derive(Debug)]
pub(crate) struct BoundedProcessOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

pub(crate) fn run_bounded_process(
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

struct OwnedProcess {
    child: Child,
    #[cfg(windows)]
    job: WindowsJob,
}

impl OwnedProcess {
    #[cfg(not(windows))]
    fn new(child: Child) -> Self {
        Self { child }
    }

    fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        #[cfg(windows)]
        if status.is_some() && !self.job.try_wait()? {
            return Ok(None);
        }
        Ok(status)
    }

    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        let status = self.child.wait()?;
        #[cfg(windows)]
        self.job.wait()?;
        Ok(status)
    }

    #[cfg(windows)]
    fn terminate(&mut self) -> std::io::Result<()> {
        self.job.terminate()
    }

    #[cfg(unix)]
    fn terminate(&mut self) -> std::io::Result<()> {
        terminate_process_id(self.child.id());
        match self.child.kill() {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
            Err(err) => Err(err),
        }
    }

    #[cfg(all(not(unix), not(windows)))]
    fn terminate(&mut self) -> std::io::Result<()> {
        self.child.kill()
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
    fn spawn_windows(mut command: Command) -> std::io::Result<Self> {
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

    #[cfg(windows)]
    {
        OwnedProcess::spawn_windows(builder)
    }

    #[cfg(not(windows))]
    {
        configure_process(&mut builder);
        builder.spawn().map(OwnedProcess::new)
    }
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
            let cleanup = terminate_and_wait(child);
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
                let cleanup = terminate_and_wait(child);
                return Err(format!(
                    "{} timed out after {}{}",
                    request.description,
                    format_duration(request.timeout),
                    cleanup_error_suffix(cleanup)
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(err) => {
                let cleanup = terminate_and_wait(child);
                return Err(format!(
                    "failed to poll {}: {err}{}",
                    request.description,
                    cleanup_error_suffix(cleanup)
                ));
            }
        }
    }
}

fn terminate_and_wait(child: &mut OwnedProcess) -> Result<(), String> {
    let terminate = child.terminate();
    let wait = child.wait();
    match (terminate, wait) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(terminate), Ok(_)) => Err(format!("termination failed: {terminate}")),
        (Ok(()), Err(wait)) => Err(format!("group wait failed: {wait}")),
        (Err(terminate), Err(wait)) => Err(format!(
            "termination failed: {terminate}; group wait failed: {wait}"
        )),
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
    let cleanup = timed_out.then(|| terminate_and_wait(child));
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
    let cleanup = timed_out.then(|| terminate_and_wait(child));
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

pub(crate) fn read_limited(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, String> {
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
        use windows_sys::Win32::Foundation::CloseHandle;
        unsafe { CloseHandle(self.0) };
    }
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
        use windows_sys::Win32::Foundation::CloseHandle;
        unsafe { CloseHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELPER_ROLE: &str = "BIFROST_BOUNDED_PROCESS_HELPER_ROLE";
    const HELPER_MARKER: &str = "BIFROST_BOUNDED_PROCESS_HELPER_MARKER";

    #[test]
    fn bounded_reader_rejects_oversized_output_after_draining_it() {
        let error = read_limited(&b"abcdef"[..], 5).unwrap_err();
        assert!(error.contains("exceeded 5 bytes"), "{error}");
    }

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
