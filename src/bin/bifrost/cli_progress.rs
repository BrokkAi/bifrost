//! Delayed stderr progress for CLI hosts. MCP uses its own notification channel.

use std::io::Write;
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use brokk_bifrost::CancellationToken;
use brokk_bifrost::policy::escape_terminal_text;

// Below two seconds silence is harmless, and fast calls keep quiet stderr.
const FIRST_NOTICE: Duration = Duration::from_secs(2);
// One unchanged phase never looks hung; half an hour prints about thirty lines.
const STILL_NOTICE: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
// Allow final display without delaying a result for a reader that never drains stderr.
// This bounds exit latency; it is not a delivery guarantee.
const FINAL_DRAIN_WAIT: Duration = Duration::from_millis(200);

#[derive(Default)]
struct State {
    pending: Option<String>,
    dropped: usize,
    last_phase: Option<String>,
    finished: Option<Instant>,
}

type SharedState = Arc<(Mutex<State>, Condvar)>;

pub(super) struct CliProgress {
    state: SharedState,
    watcher: Option<JoinHandle<()>>,
    done: mpsc::Receiver<()>,
}

/// The sink only records phases; its watcher never holds Rust's stderr lock.
pub(super) fn start() -> (CancellationToken, Option<CliProgress>) {
    match clone_stderr() {
        Ok(output) => {
            let (token, progress) = start_with_output(output, Instant::now());
            (token, Some(progress))
        }
        // Progress is display-only. If the output cannot be cloned, keep the
        // host token but do not start a watcher.
        Err(_) => (CancellationToken::new(), None),
    }
}

fn clone_stderr() -> std::io::Result<std::fs::File> {
    // A blocked File write never holds Rust's process-wide stderr lock.
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        std::io::stderr()
            .as_fd()
            .try_clone_to_owned()
            .map(Into::into)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        std::io::stderr()
            .as_handle()
            .try_clone_to_owned()
            .map(Into::into)
    }
}

fn start_with_output(
    output: impl Write + Send + 'static,
    started: Instant,
) -> (CancellationToken, CliProgress) {
    let state = Arc::new((Mutex::new(State::default()), Condvar::new()));
    let sink_state = Arc::clone(&state);
    let cancellation = CancellationToken::new().with_phase_sink(move |phase| {
        let mut state = sink_state.0.lock().expect("CLI progress lock poisoned");
        if state.last_phase.as_deref() != Some(phase) {
            if state.pending.replace(phase.to_owned()).is_some() {
                state.dropped += 1;
            }
            state.last_phase = Some(phase.to_owned());
        }
    });
    let watcher_state = Arc::clone(&state);
    let (done_tx, done) = mpsc::channel();
    let watcher = std::thread::Builder::new()
        .name("cli-progress".to_owned())
        .spawn(move || {
            // A closed or broken progress stream disables display only.
            // Do not report the error back through that same stream.
            watch(Arc::clone(&watcher_state), started, output).unwrap_or(());
            if done_tx.send(()).is_err() {
                // The host timed out and detached this display thread.
                assert!(
                    watcher_state
                        .0
                        .lock()
                        .expect("CLI progress lock poisoned")
                        .finished
                        .is_some()
                );
            }
        })
        .expect("start CLI progress watcher");
    (
        cancellation,
        CliProgress {
            state,
            watcher: Some(watcher),
            done,
        },
    )
}

fn watch(shared: SharedState, started: Instant, mut output: impl Write) -> std::io::Result<()> {
    let mut previous = None;
    let mut last_notice = started;
    let mut dropped = 0;
    loop {
        let state = shared.0.lock().expect("CLI progress lock poisoned");
        let (mut state, _) = shared
            .1
            .wait_timeout_while(state, POLL_INTERVAL, |state| state.finished.is_none())
            .expect("CLI progress wait poisoned");
        let finished = state.finished.is_some();
        let elapsed = state
            .finished
            .unwrap_or_else(Instant::now)
            .duration_since(started);
        if elapsed < FIRST_NOTICE {
            if finished {
                return Ok(());
            }
            continue;
        }
        let waiting_for_lock = state.last_phase.as_deref().is_some_and(is_build_lock_wait);
        let phase = state.pending.take();
        dropped += std::mem::take(&mut state.dropped);
        drop(state);
        // cache_gc::wait_for_lock already writes its own delayed stderr
        // notices (#13147), even when that build's token carries this sink.
        if let Some(phase) = phase
            && !is_build_lock_wait(&phase)
            && (previous.as_ref() != Some(&phase) || dropped > 0)
        {
            report_dropped(&mut output, &mut dropped, started)?;
            output.write_all(
                format!(
                    "bifrost: [{:.1}s] {}\n",
                    started.elapsed().as_secs_f64(),
                    escape_terminal_text(&phase)
                )
                .as_bytes(),
            )?;
            previous = Some(phase);
            last_notice = Instant::now();
        }
        if !waiting_for_lock
            && last_notice.elapsed() >= STILL_NOTICE
            && let Some(phase) = &previous
        {
            report_dropped(&mut output, &mut dropped, started)?;
            output.write_all(
                format!(
                    "bifrost: [{:.1}s] still {}\n",
                    started.elapsed().as_secs_f64(),
                    escape_terminal_text(phase)
                )
                .as_bytes(),
            )?;
            last_notice = Instant::now();
        }
        if finished {
            return Ok(());
        }
    }
}

fn report_dropped(
    output: &mut impl Write,
    dropped: &mut usize,
    started: Instant,
) -> std::io::Result<()> {
    if *dropped > 0 {
        output.write_all(
            format!(
                "bifrost: [{:.1}s] ({} earlier phases not shown)\n",
                started.elapsed().as_secs_f64(),
                std::mem::take(dropped)
            )
            .as_bytes(),
        )?;
    }
    Ok(())
}

fn is_build_lock_wait(phase: &str) -> bool {
    phase.starts_with("waiting for the analyzer cache build lock")
}

impl Drop for CliProgress {
    fn drop(&mut self) {
        self.state
            .0
            .lock()
            .expect("CLI progress lock poisoned")
            .finished = Some(Instant::now());
        self.state.1.notify_one();
        let watcher = self
            .watcher
            .take()
            .expect("CLI progress watcher is stopped once");
        match self.done.recv_timeout(FINAL_DRAIN_WAIT) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                // A display-thread failure must not change the result.
                watcher.join().unwrap_or(());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // A caller may wait for stdout without reading stderr. Only
                // this display thread may remain blocked; exit ends it and
                // discards any unprinted phases.
                drop(watcher);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    struct BlockedOutput {
        entered: mpsc::SyncSender<()>,
        never: mpsc::Receiver<()>,
        _keep_channel_open: mpsc::Sender<()>,
    }

    impl Write for BlockedOutput {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            self.entered
                .send(())
                .expect("test waits for the blocked write");
            self.never
                .recv()
                .expect("the test never signals this channel");
            unreachable!("the progress output remains blocked until process exit")
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn completed_calls_before_first_notice_keep_stderr_quiet() {
        let started = Instant::now();
        let state = State {
            pending: Some("quick operation".to_owned()),
            finished: Some(started + FIRST_NOTICE - Duration::from_nanos(1)),
            ..State::default()
        };
        let shared = Arc::new((Mutex::new(state), Condvar::new()));
        let mut output = Vec::new();
        watch(shared, started, &mut output).expect("quiet progress output");
        assert!(output.is_empty());
    }

    #[test]
    #[hardwon("#13216: an unread stderr pipe could hang the CLI before it printed its result")]
    fn blocked_output_retains_only_the_latest_phase_and_does_not_delay_the_result() {
        let (entered_tx, entered) = mpsc::sync_channel(1);
        let (keep_open, never) = mpsc::channel();
        let (token, progress) = start_with_output(
            BlockedOutput {
                entered: entered_tx,
                never,
                _keep_channel_open: keep_open,
            },
            Instant::now() - Duration::from_secs(3),
        );
        let phase = token.enter_phase("initial phase");
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("watcher reached the blocked output");
        // The watcher cannot drain while blocked. Every later update replaces
        // the one pending phase, independent of test-thread scheduling.
        let updates = 128;
        for index in 0..updates {
            phase.update(format!("pending phase {index}"));
        }
        {
            let state = progress.state.0.lock().expect("CLI progress lock");
            assert_eq!(
                state.pending,
                Some(format!("pending phase {}", updates - 1))
            );
            assert_eq!(state.dropped, updates - 1);
        }
        let (finished_tx, finished) = mpsc::channel();
        let finisher = std::thread::spawn(move || {
            drop(progress);
            finished_tx.send(()).expect("test waits for bounded finish");
        });
        finished
            .recv_timeout(FINAL_DRAIN_WAIT + Duration::from_secs(1))
            .expect("an unread progress output must not delay the result");
        finisher.join().expect("progress finisher panicked");
    }
    struct BrokenOutput(mpsc::SyncSender<()>);

    impl Write for BrokenOutput {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            self.0.send(()).expect("test waits for the failed write");
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    #[hardwon("#13216: a closed progress pipe aborted the command before its result")]
    fn broken_output_stops_display_without_failing_the_result() {
        let (entered_tx, entered) = mpsc::sync_channel(1);
        let (token, progress) = start_with_output(
            BrokenOutput(entered_tx),
            Instant::now() - Duration::from_secs(3),
        );
        let phase = token.enter_phase("running the policy");
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("watcher attempted progress output");
        progress
            .done
            .recv_timeout(Duration::from_secs(1))
            .expect("a broken output stops the watcher normally");
        // Analysis may continue after display fails; retain only its newest phase.
        let updates = 128;
        for index in 0..updates {
            phase.update(format!("later phase {index}"));
        }
        {
            let state = progress.state.0.lock().expect("CLI progress lock");
            assert_eq!(state.pending, Some(format!("later phase {}", updates - 1)));
            assert_eq!(state.dropped, updates - 1);
        }
        drop(progress);
    }
    #[test]
    #[hardwon("#13216: a restored phase hid overwritten CLI progress")]
    fn restored_phase_reports_overwritten_work_before_repeating_its_text() {
        struct RecordingOutput {
            writes: mpsc::Sender<String>,
            resume: Option<mpsc::Receiver<()>>,
        }
        impl Write for RecordingOutput {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.writes
                    .send(String::from_utf8(bytes.to_vec()).expect("UTF-8 progress"))
                    .expect("test reads progress");
                if let Some(resume) = self.resume.take() {
                    resume.recv().expect("test releases the first write");
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (writes_tx, writes) = mpsc::channel();
        let (resume, resume_rx) = mpsc::channel();
        let (token, progress) = start_with_output(
            RecordingOutput {
                writes: writes_tx,
                resume: Some(resume_rx),
            },
            Instant::now() - Duration::from_secs(3),
        );
        let phase = token.enter_phase("A");
        assert!(
            writes
                .recv_timeout(Duration::from_secs(5))
                .expect("first phase")
                .ends_with("] A\n")
        );
        phase.update("B");
        phase.update("A");
        {
            let state = progress.state.0.lock().expect("CLI progress lock");
            assert_eq!(state.pending.as_deref(), Some("A"));
            assert_eq!(state.dropped, 1);
        }
        resume.send(()).expect("release the printed phase");
        drop(progress);
        assert!(
            writes
                .recv_timeout(Duration::from_secs(1))
                .expect("omission notice")
                .ends_with("] (1 earlier phases not shown)\n")
        );
        assert!(
            writes
                .recv_timeout(Duration::from_secs(1))
                .expect("restored phase")
                .ends_with("] A\n")
        );
        assert!(
            writes.try_recv().is_err(),
            "only the newest phase is printed"
        );
    }
}
