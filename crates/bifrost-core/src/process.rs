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
/// stays in the job; on Unix the child leads its own process group, so
/// every descendant shares its process group. [`Self::terminate_tree_and_wait`]
/// then kills the whole tree, and callers may join pipe readers afterwards:
/// no writer survives the termination.
///
/// Descendants stay in the tree unless they break away themselves
/// (`CREATE_BREAKAWAY_FROM_JOB` on Windows, `setsid` or `setpgid` on Unix).
/// On Unix the child keeps the parent's session and controlling terminal; it
/// does not call `setsid`. A tool opening `/dev/tty` can therefore block on a
/// prompt until the bounded timeout kills it, where `setsid` made it fail at
/// once. Descendants that need to break away must do so themselves.
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
        // A process group can outlive its leader. Only std's guarded kill may
        // target the direct pid, since wait() may already have reaped it.
        unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL) };
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

    /// Whether a process of the owned tree may still be running.
    ///
    /// Once no such process remains, nothing the tree spawned holds the end of
    /// a pipe that the caller's workers read or write, so those workers are
    /// bound to finish. Only a probe that proves the tree empty answers
    /// `false`; on Unix the unreaped direct child still counts as running.
    #[cfg(unix)]
    fn tree_may_be_running(&self) -> bool {
        // The child leads its own process group, so signal 0 to the group
        // probes whether any member remains.
        let probe = unsafe { libc::kill(-(self.child.id() as libc::pid_t), 0) };
        probe == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }

    /// Whether a process of the owned tree may still be running.
    #[cfg(windows)]
    fn tree_may_be_running(&self) -> bool {
        !matches!(self.job.try_wait(), Ok(true))
    }

    /// Whether a process of the owned tree may still be running.
    #[cfg(all(not(unix), not(windows)))]
    fn tree_may_be_running(&mut self) -> bool {
        !matches!(self.child.try_wait(), Ok(Some(_)))
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

#[cfg(unix)]
fn wait_for_process(
    child: &mut OwnedProcess,
    request: &BoundedProcessRequest,
    is_cancelled: &impl Fn() -> bool,
) -> Result<ExitStatus, String> {
    use std::sync::mpsc::{self, RecvTimeoutError};

    let started = Instant::now();
    let pid = child.child.id();
    // The worker observes exit without reaping. The controller retains the
    // Child and keeps its pid reserved until termination and joining finish.
    let result = thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = scope.spawn(move || {
            let status = observe_process_exit(pid);
            sender
                .send(status)
                .expect("process wait controller is alive");
        });
        let result = loop {
            if is_cancelled() {
                break Err(format!("{} was cancelled", request.description));
            }
            let remaining = request.timeout.saturating_sub(started.elapsed());
            match receiver.recv_timeout(remaining.min(Duration::from_millis(10))) {
                Ok(status) => {
                    break status.map_err(|err| {
                        format!("failed to wait for {} group: {err}", request.description)
                    });
                }
                Err(RecvTimeoutError::Timeout) if started.elapsed() >= request.timeout => {
                    break Err(format!(
                        "{} timed out after {}",
                        request.description,
                        format_duration(request.timeout)
                    ));
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    break Err(format!("{} wait worker disconnected", request.description));
                }
            }
        };
        let result = result.map_err(|error| {
            let cleanup = child
                .terminate()
                .map_err(|err| format!("termination failed: {err}"));
            format!("{error}{}", cleanup_error_suffix(cleanup))
        });
        // Keep the receiver alive until the worker has sent its result, even
        // when cancellation or the deadline wins the race with completion.
        match worker.join() {
            Ok(()) => result,
            Err(_) => Err(format!("{} wait worker panicked", request.description)),
        }
    });
    // No signal to the direct pid can race with this reap: the worker has
    // joined and any cancellation/deadline termination already happened.
    let status = child
        .wait()
        .map_err(|err| format!("failed to wait for {} group: {err}", request.description));
    match result {
        Ok(()) => status,
        Err(error) => Err(format!(
            "{error}{}",
            cleanup_error_suffix(status.map(|_| ()))
        )),
    }
}

#[cfg(not(unix))]
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
    let timed_out = worker_outlived_grace(&worker, child);
    let cleanup = timed_out.then(|| child.terminate_tree_and_wait());
    let joined = worker.join();
    // A writer still blocked at the deadline fails with a broken pipe once
    // the cleanup kills the reader, so the timeout decides the outcome.
    if let Some(cleanup) = cleanup {
        return Err(StdinWriteFailure::TimedOut { cleanup });
    }
    match joined {
        Ok(Ok(())) => Ok(()),
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
    let timed_out = worker_outlived_grace(&worker, child);
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

/// Whether `worker` is still running after the grace while a process of the
/// owned tree survives to hold the other end of its pipe. A worker that is
/// only late to be scheduled, as under a fully loaded test run, finishes on
/// its own once the tree is gone, so it is joined rather than failing a child
/// that succeeded (#7981).
fn worker_outlived_grace<T>(worker: &JoinHandle<T>, child: &mut OwnedProcess) -> bool {
    !worker_finished_within(worker, READER_GRACE) && child.tree_may_be_running()
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
    // Unlike a pre-exec closure, this preserves std's posix_spawn fast path.
    command.process_group(0);
}

#[cfg(all(not(unix), not(windows)))]
fn configure_process(_command: &mut Command) {}

#[cfg(unix)]
fn observe_process_exit(pid: u32) -> std::io::Result<()> {
    loop {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
        // WNOWAIT leaves the child unreaped, reserving its pid until the
        // controller has finished signalling the process tree.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::ECHILD) => return Ok(()),
            _ => return Err(error),
        }
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
        let mut request = descendant_request(temporary.path(), &marker);
        request.timeout = Duration::from_millis(100);
        let error = run_bounded_process(&request, || false).unwrap_err();
        assert!(error.contains("timed out"), "{error}");
        thread::sleep(Duration::from_millis(700));
        assert!(!marker.exists(), "descendant escaped timeout cleanup");
    }

    #[test]
    fn bounded_process_cancellation_cleans_up_descendants() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let temporary = tempfile::tempdir().unwrap();
        let marker = temporary.path().join("escaped-descendant");
        let ready = temporary.path().join("descendant-ready");
        let mut request = descendant_request(temporary.path(), &marker);
        request.env.push((
            OsString::from("BIFROST_BOUNDED_PROCESS_HELPER_READY"),
            ready.clone().into_os_string(),
        ));
        let cancelled = AtomicBool::new(false);
        let error = thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(50));
                cancelled.store(true, Ordering::Relaxed);
            });
            run_bounded_process(&request, || {
                cancelled.load(Ordering::Relaxed) && ready.exists()
            })
            .unwrap_err()
        });
        assert!(error.contains("was cancelled"), "{error}");
        assert!(
            ready.exists(),
            "descendant must have started before cancellation"
        );
        thread::sleep(Duration::from_millis(700));
        assert!(!marker.exists(), "descendant escaped cancellation cleanup");
    }

    fn descendant_request(
        directory: &std::path::Path,
        marker: &std::path::Path,
    ) -> BoundedProcessRequest {
        let executable = std::env::current_exe().unwrap();
        BoundedProcessRequest {
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
            cwd: directory.to_path_buf(),
            stdin: None,
            timeout: Duration::from_secs(30),
            stdout_limit: 64 * 1024,
            stderr_limit: 64 * 1024,
            description: "bounded process cleanup test".to_string(),
        }
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
                if let Some(ready) = std::env::var_os("BIFROST_BOUNDED_PROCESS_HELPER_READY") {
                    std::fs::write(ready, b"running").unwrap();
                }
                thread::sleep(Duration::from_millis(500));
                std::fs::write(std::env::var_os(HELPER_MARKER).unwrap(), b"escaped").unwrap();
            }
            _ => {}
        }
    }

    // Real-process tests for the Unix process tree. The Windows job-object
    // paths are not compiled on Unix.
    #[cfg(unix)]
    mod unix {
        use super::*;
        use brokk_bifrost_test_macros::hardwon;
        use std::io::BufRead;
        use std::path::Path;
        use std::process::Stdio;

        /// A payload far larger than a pipe buffer (64 KiB on Linux), so a
        /// writer to a child that never reads must block or fail.
        const LARGE_PAYLOAD: usize = 1 << 20;

        fn shell_request(
            script: &str,
            stdin: Option<Vec<u8>>,
            cwd: &Path,
        ) -> BoundedProcessRequest {
            BoundedProcessRequest {
                program: OsString::from("sh"),
                args: vec![OsString::from("-c"), OsString::from(script)],
                env: Vec::new(),
                clear_env: false,
                cwd: cwd.to_path_buf(),
                stdin,
                timeout: Duration::from_secs(30),
                stdout_limit: 1 << 20,
                stderr_limit: 1 << 20,
                description: "shell test child".to_string(),
            }
        }

        fn spawn_shell(script: &str, stdin: Stdio) -> OwnedProcess {
            OwnedProcess::spawn(
                Command::new("sh")
                    .args(["-c", script])
                    .stdin(stdin)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null()),
            )
            .unwrap()
        }

        /// Spawn a shell whose background `sleep` is a grandchild, and return
        /// the shell with the grandchild's pid.
        fn spawn_with_grandchild() -> (OwnedProcess, libc::pid_t) {
            let mut process = spawn_shell("sleep 60 & echo $!; wait", Stdio::null());
            let stdout = process.take_stdout().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(stdout)
                .read_line(&mut line)
                .unwrap();
            let pid: libc::pid_t = line.trim().parse().unwrap();
            assert!(process_is_alive(pid), "grandchild {pid} must start alive");
            (process, pid)
        }

        fn process_is_alive(pid: libc::pid_t) -> bool {
            if unsafe { libc::kill(pid, 0) } != 0 {
                return false;
            }
            // A killed orphan stays a zombie until its new parent reaps it,
            // and a container without a reaper never does. A zombie is dead.
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(stat) => !stat
                    .rsplit_once(')')
                    .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z')),
                Err(_) => true,
            }
        }

        fn dies_within(pid: libc::pid_t, bound: Duration) -> bool {
            let started = Instant::now();
            while process_is_alive(pid) {
                if started.elapsed() >= bound {
                    return false;
                }
                thread::sleep(Duration::from_millis(10));
            }
            true
        }

        /// The environment `env` prints for `clear_env` with one explicit
        /// variable, one `NAME=value` line per entry.
        fn printed_environment(clear_env: bool) -> Vec<String> {
            let temporary = tempfile::tempdir().unwrap();
            let request = BoundedProcessRequest {
                program: OsString::from("/usr/bin/env"),
                args: Vec::new(),
                env: vec![(
                    OsString::from("BIFROST_BOUNDED_PROCESS_ENV_PROBE"),
                    OsString::from("1"),
                )],
                clear_env,
                ..shell_request("", None, temporary.path())
            };
            let output = run_bounded_process(&request, || false).unwrap();
            assert!(output.status.success(), "{output:?}");
            String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .map(str::to_string)
                .collect()
        }

        #[test]
        fn clear_env_passes_only_the_explicit_environment() {
            assert_eq!(
                printed_environment(true),
                ["BIFROST_BOUNDED_PROCESS_ENV_PROBE=1"]
            );

            let inherited = printed_environment(false);
            assert!(
                inherited.contains(&"BIFROST_BOUNDED_PROCESS_ENV_PROBE=1".to_string()),
                "{inherited:?}"
            );
            let path = std::env::var("PATH").expect("the test runner has a PATH");
            assert!(inherited.contains(&format!("PATH={path}")), "{inherited:?}");
        }

        #[test]
        #[hardwon(
            "#7002: the bounded runner's pre_exec setsid forced an ordinary fork and 10 ms polling, doubling Gson dead_code_smells wall time"
        )]
        fn bounded_child_uses_a_process_group_and_not_a_pre_exec_hook() {
            let mut process = spawn_shell("exit 0", Stdio::null());
            let pid = process.child.id() as libc::pid_t;
            // The child may already have exited, but it stays unreaped until wait().
            assert_eq!(unsafe { libc::getsid(pid) }, unsafe { libc::getsid(0) });
            assert_eq!(unsafe { libc::getpgid(pid) }, pid);
            assert_ne!(unsafe { libc::getpgid(0) }, pid);
            process.wait().unwrap();

            let temporary = tempfile::tempdir().unwrap();
            let output =
                run_bounded_process(&shell_request("exit 0", None, temporary.path()), || false)
                    .unwrap();
            assert!(output.status.success());
        }

        #[test]
        fn terminate_tree_and_wait_kills_the_grandchild() {
            let (mut process, grandchild) = spawn_with_grandchild();
            process.terminate_tree_and_wait().unwrap();
            assert!(
                dies_within(grandchild, Duration::from_secs(5)),
                "grandchild {grandchild} survived terminate_tree_and_wait"
            );
        }

        #[test]
        fn terminate_on_an_exited_child_succeeds() {
            let mut process = spawn_shell("exit 0", Stdio::null());
            assert!(process.wait().unwrap().success());
            process.terminate().unwrap();
            process.terminate().unwrap();
            process.terminate_tree_and_wait().unwrap();
        }

        #[test]
        fn large_stdin_to_a_child_that_exits_unread_is_a_broken_pipe() {
            let temporary = tempfile::tempdir().unwrap();
            let mut process = spawn_shell("exit 0", Stdio::piped());
            let stdin = process.take_stdin().unwrap();
            let worker = spawn_stdin_writer(stdin, vec![b'x'; LARGE_PAYLOAD]);
            let failure = collect_stdin_writer(worker, &mut process)
                .expect_err("an unread large payload must fail");
            assert!(failure.is_broken_pipe());
            assert!(matches!(failure, StdinWriteFailure::Write(_)));
            let message = failure.message(&shell_request("exit 0", None, temporary.path()));
            assert!(
                message.contains("failed to write stdin for shell test child"),
                "{message}"
            );
            process.wait().unwrap();
        }

        #[test]
        fn run_bounded_process_reports_unread_stdin_only_when_the_child_succeeded() {
            let temporary = tempfile::tempdir().unwrap();
            let payload = vec![b'x'; LARGE_PAYLOAD];

            let error = run_bounded_process(
                &shell_request("exit 0", Some(payload.clone()), temporary.path()),
                || false,
            )
            .unwrap_err();
            assert!(error.contains("failed to write stdin"), "{error}");

            // A child that fails without reading its input is the child's failure, not ours.
            let output = run_bounded_process(
                &shell_request("exit 3", Some(payload), temporary.path()),
                || false,
            )
            .unwrap();
            assert_eq!(output.status.code(), Some(3));
        }

        /// Block a writer on a child that sleeps without reading, and collect it.
        /// Returns the failure, the elapsed time and whether the child survived.
        fn collect_writer_blocked_on_a_sleeping_child() -> (StdinWriteFailure, Duration, bool) {
            let mut process = spawn_shell("sleep 60", Stdio::piped());
            let pid = process.child.id() as libc::pid_t;
            let stdin = process.take_stdin().unwrap();
            let worker = spawn_stdin_writer(stdin, vec![b'x'; LARGE_PAYLOAD]);
            let started = Instant::now();
            let failure = collect_stdin_writer(worker, &mut process)
                .expect_err("a writer blocked on a sleeping child must fail");
            (failure, started.elapsed(), process_is_alive(pid))
        }

        #[test]
        #[hardwon("7fc8ced1d0e0: a stdin writer that timed out was reported as a broken pipe")]
        fn stdin_writer_blocked_on_a_stuck_child_fails_after_the_grace_and_kills_it() {
            let (failure, elapsed, child_alive) = collect_writer_blocked_on_a_sleeping_child();
            // The cleanup kills the reader, so the blocked write ends with a
            // broken pipe; the timeout must still be what is reported.
            assert!(
                matches!(failure, StdinWriteFailure::TimedOut { cleanup: Ok(()) }),
                "broken_pipe={}",
                failure.is_broken_pipe()
            );
            assert!(elapsed >= READER_GRACE, "gave up after only {elapsed:?}");
            assert!(elapsed < READER_GRACE * 5, "took {elapsed:?}");
            assert!(!child_alive, "timeout must terminate the child");
        }

        #[test]
        #[hardwon("#7981: a pipe reader scheduled after the grace failed a child that had exited")]
        fn a_reader_finishing_after_the_grace_is_joined_once_the_tree_has_exited() {
            let temporary = tempfile::tempdir().unwrap();
            let request = shell_request("exit 0", None, temporary.path());
            let mut process = spawn_shell("exit 0", Stdio::null());
            assert!(process.wait().unwrap().success());
            // Stands in for a reader that load kept off the CPU past the grace.
            let worker = thread::spawn(|| -> PipeReadResult {
                thread::sleep(READER_GRACE * 2);
                Ok(b"late".to_vec())
            });
            assert_eq!(
                collect_pipe("stderr", worker, &request, &mut process),
                Ok(b"late".to_vec())
            );

            // A descendant that still holds the pipe is a leak, not a late reader.
            let started = Instant::now();
            let error = run_bounded_process(
                &shell_request("sleep 60 & echo $!", None, temporary.path()),
                || false,
            )
            .unwrap_err();
            assert_eq!(error, "shell test child did not close stdout");
            assert!(
                started.elapsed() < READER_GRACE * 5,
                "took {:?}",
                started.elapsed()
            );
        }

        #[test]
        fn stdin_writer_panic_is_reported_without_a_broken_pipe() {
            let temporary = tempfile::tempdir().unwrap();
            let mut process = spawn_shell("exit 0", Stdio::null());
            // resume_unwind unwinds without running the panic hook, so the test log stays quiet.
            let worker = thread::spawn(|| -> StdinWriteResult {
                std::panic::resume_unwind(Box::new("stdin writer test panic"))
            });
            let failure = collect_stdin_writer(worker, &mut process)
                .expect_err("a panicked writer must fail");
            assert!(!failure.is_broken_pipe());
            let message = failure.message(&shell_request("exit 0", None, temporary.path()));
            assert_eq!(message, "shell test child stdin writer panicked");
            process.wait().unwrap();
        }

        #[test]
        fn spawn_failures_name_the_command_and_directory() {
            let temporary = tempfile::tempdir().unwrap();
            let mut request = shell_request("exit 0", None, temporary.path());
            request.program = OsString::from("bifrost-no-such-program-for-process-test");
            let error = run_bounded_process(&request, || false).unwrap_err();
            assert!(
                error.contains("failed to start shell test child"),
                "{error}"
            );
            assert!(
                error.contains(&temporary.path().display().to_string()),
                "{error}"
            );
            assert!(error.contains("No such file or directory"), "{error}");
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn a_text_file_busy_spawn_is_retried_then_reported() {
            use std::os::unix::fs::OpenOptionsExt;

            let temporary = tempfile::tempdir().unwrap();
            let script = temporary.path().join("busy.sh");
            // Linux refuses to exec a file that any process holds open for writing.
            let mut writer = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o755)
                .open(&script)
                .unwrap();
            writer.write_all(b"#!/bin/sh\nexit 0\n").unwrap();

            let mut request = shell_request("exit 0", None, temporary.path());
            request.program = script.clone().into_os_string();
            request.args = Vec::new();
            let started = Instant::now();
            let error = run_bounded_process(&request, || false).unwrap_err();
            assert!(error.contains("Text file busy"), "{error}");
            assert!(
                started.elapsed() >= SPAWN_RETRY_DELAY * SPAWN_RETRIES as u32,
                "ETXTBSY must be retried {SPAWN_RETRIES} times before it is reported: {:?}",
                started.elapsed()
            );

            drop(writer);
            let output = run_bounded_process(&request, || false).unwrap();
            assert!(output.status.success());
        }
    }

    #[cfg(unix)]
    mod stdin_roundtrip_properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(16))]

            /// `cat` is the identity function on bytes, so whatever the
            /// concurrent stdin writer sends must come back on stdout. Payloads
            /// straddle the 64 KiB pipe buffer to force writer and readers to overlap.
            #[test]
            fn stdin_reaches_the_child_intact(
                payload in prop_oneof![
                    prop::collection::vec(any::<u8>(), 0..512),
                    prop::collection::vec(any::<u8>(), 60_000..200_000),
                ],
            ) {
                let temporary = tempfile::tempdir().unwrap();
                let request = BoundedProcessRequest {
                    program: OsString::from("cat"),
                    args: Vec::new(),
                    env: Vec::new(),
                    clear_env: false,
                    cwd: temporary.path().to_path_buf(),
                    stdin: Some(payload.clone()),
                    timeout: Duration::from_secs(30),
                    stdout_limit: 1 << 20,
                    stderr_limit: 1 << 20,
                    description: "cat round trip".to_string(),
                };
                let output = run_bounded_process(&request, || false).unwrap();
                prop_assert!(output.status.success());
                prop_assert_eq!(output.stdout, payload);
            }
        }
    }
}
