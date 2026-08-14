#[cfg(test)]
use std::sync::Barrier;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Instant;

use serde::Serialize;

use crate::cancellation::CancellationToken;

/// Measurements for one bounded dispatch of dependency-ready query tasks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct SchedulerRunProfile {
    pub(crate) worker_limit: usize,
    pub(crate) workers_spawned: usize,
    pub(crate) tasks_enqueued: usize,
    pub(crate) tasks_started: usize,
    pub(crate) tasks_completed: usize,
    /// Tasks whose closure was still invoked so it could construct the
    /// operator's cancellation-safe result.
    pub(crate) tasks_observed_cancelled_before_start: usize,
    pub(crate) queue_wait_ns: u64,
    /// Elapsed time inside task closures. This includes any separately
    /// reported cooperative budget wait performed by the task.
    pub(crate) worker_task_elapsed_ns: u64,
    pub(crate) budget_wait_ns: u64,
    pub(crate) coordinator_wait_ns: u64,
    pub(crate) dispatch_overhead_ns: u64,
    pub(crate) peak_concurrency: usize,
}

impl SchedulerRunProfile {
    pub(crate) fn saturating_add(self, other: Self) -> Self {
        Self {
            worker_limit: self.worker_limit.max(other.worker_limit),
            workers_spawned: self.workers_spawned.max(other.workers_spawned),
            tasks_enqueued: self.tasks_enqueued.saturating_add(other.tasks_enqueued),
            tasks_started: self.tasks_started.saturating_add(other.tasks_started),
            tasks_completed: self.tasks_completed.saturating_add(other.tasks_completed),
            tasks_observed_cancelled_before_start: self
                .tasks_observed_cancelled_before_start
                .saturating_add(other.tasks_observed_cancelled_before_start),
            queue_wait_ns: self.queue_wait_ns.saturating_add(other.queue_wait_ns),
            worker_task_elapsed_ns: self
                .worker_task_elapsed_ns
                .saturating_add(other.worker_task_elapsed_ns),
            budget_wait_ns: self.budget_wait_ns.saturating_add(other.budget_wait_ns),
            coordinator_wait_ns: self
                .coordinator_wait_ns
                .saturating_add(other.coordinator_wait_ns),
            dispatch_overhead_ns: self
                .dispatch_overhead_ns
                .saturating_add(other.dispatch_overhead_ns),
            peak_concurrency: self.peak_concurrency.max(other.peak_concurrency),
        }
    }
}

pub(crate) struct SchedulerRun<T> {
    pub(crate) results: Vec<T>,
    pub(crate) profile: SchedulerRunProfile,
}

/// A request-local scheduler with a fixed worker budget.
///
/// Operators submit only dependency-ready work. Workers never enqueue more
/// work and never wait for a task that is queued to this scheduler, avoiding
/// recursive pool growth and bounded-pool dependency starvation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BoundedReadyScheduler {
    worker_limit: usize,
}

#[derive(Debug, Default)]
struct WorkerStartState {
    ready_workers: usize,
    released: bool,
    aborted: bool,
}

impl BoundedReadyScheduler {
    pub(crate) fn new(worker_limit: usize) -> Self {
        Self {
            worker_limit: worker_limit.max(1),
        }
    }

    pub(crate) fn run<T, F>(
        self,
        task_count: usize,
        cancellation: Option<&CancellationToken>,
        run_task: F,
    ) -> SchedulerRun<T>
    where
        T: Send,
        F: Fn(usize) -> T + Sync,
    {
        assert!(
            task_count > 0,
            "scheduler dispatch requires at least one task"
        );
        let workers_spawned = self.worker_limit.min(task_count);
        let next_task = AtomicUsize::new(0);
        let tasks_started = AtomicUsize::new(0);
        let tasks_completed = AtomicUsize::new(0);
        let tasks_observed_cancelled_before_start = AtomicUsize::new(0);
        let active = AtomicUsize::new(0);
        let peak_concurrency = AtomicUsize::new(0);
        let queue_wait_ns = AtomicU64::new(0);
        let worker_task_elapsed_ns = AtomicU64::new(0);
        let start_gate = (Mutex::new(WorkerStartState::default()), Condvar::new());
        let mut dispatch_overhead_ns = 0;
        let mut coordinator_wait_ns = 0;

        let mut indexed_results = std::thread::scope(|scope| {
            let spawn_started = Instant::now();
            let mut handles = Vec::with_capacity(workers_spawned);
            for _ in 0..workers_spawned {
                let spawned = std::thread::Builder::new().spawn_scoped(scope, || {
                    let mut worker_results = Vec::new();
                    // Announce readiness, then remain blocked until the
                    // coordinator closes setup accounting and releases every
                    // successfully created worker together.
                    let (start_lock, start_changed) = &start_gate;
                    let mut start = start_lock.lock().expect("worker start gate poisoned");
                    start.ready_workers = start.ready_workers.saturating_add(1);
                    start_changed.notify_all();
                    while !start.released {
                        start = start_changed
                            .wait(start)
                            .expect("worker start gate poisoned while waiting");
                    }
                    if start.aborted {
                        return worker_results;
                    }
                    drop(start);
                    let queue_epoch = Instant::now();
                    loop {
                        let task = next_task.fetch_add(1, Ordering::AcqRel);
                        if task >= task_count {
                            break;
                        }
                        queue_wait_ns.fetch_add(elapsed_ns(queue_epoch), Ordering::Relaxed);
                        if cancellation.is_some_and(CancellationToken::is_cancelled) {
                            tasks_observed_cancelled_before_start.fetch_add(1, Ordering::Relaxed);
                        }
                        tasks_started.fetch_add(1, Ordering::Relaxed);
                        let now_active = active.fetch_add(1, Ordering::AcqRel).saturating_add(1);
                        peak_concurrency.fetch_max(now_active, Ordering::AcqRel);
                        let task_started = Instant::now();
                        let result = run_task(task);
                        worker_task_elapsed_ns
                            .fetch_add(elapsed_ns(task_started), Ordering::Relaxed);
                        active.fetch_sub(1, Ordering::AcqRel);
                        tasks_completed.fetch_add(1, Ordering::Relaxed);
                        worker_results.push((task, result));
                    }
                    worker_results
                });
                match spawned {
                    Ok(handle) => handles.push(handle),
                    Err(error) => {
                        let (start_lock, start_changed) = &start_gate;
                        let mut start = start_lock
                            .lock()
                            .expect("worker start gate poisoned after spawn failure");
                        start.aborted = true;
                        start.released = true;
                        start_changed.notify_all();
                        drop(start);
                        for handle in handles {
                            let _ = handle.join();
                        }
                        panic!("failed to spawn bounded query worker: {error}");
                    }
                }
            }
            let (start_lock, start_changed) = &start_gate;
            let mut start = start_lock
                .lock()
                .expect("worker start gate poisoned before release");
            while start.ready_workers < workers_spawned {
                start = start_changed
                    .wait(start)
                    .expect("worker start gate poisoned while awaiting readiness");
            }
            dispatch_overhead_ns = elapsed_ns(spawn_started);
            let wait_started = Instant::now();
            start.released = true;
            start_changed.notify_all();
            drop(start);
            let mut results = Vec::with_capacity(task_count);
            for handle in handles {
                results.extend(handle.join().expect("query scheduler worker panicked"));
            }
            coordinator_wait_ns = elapsed_ns(wait_started);
            results
        });
        let sort_started = Instant::now();
        indexed_results.sort_unstable_by_key(|(task, _)| *task);
        dispatch_overhead_ns = dispatch_overhead_ns.saturating_add(elapsed_ns(sort_started));

        SchedulerRun {
            results: indexed_results
                .into_iter()
                .map(|(_, result)| result)
                .collect(),
            profile: SchedulerRunProfile {
                worker_limit: self.worker_limit,
                workers_spawned,
                tasks_enqueued: task_count,
                tasks_started: tasks_started.load(Ordering::Acquire),
                tasks_completed: tasks_completed.load(Ordering::Acquire),
                tasks_observed_cancelled_before_start: tasks_observed_cancelled_before_start
                    .load(Ordering::Acquire),
                queue_wait_ns: queue_wait_ns.load(Ordering::Acquire),
                worker_task_elapsed_ns: worker_task_elapsed_ns.load(Ordering::Acquire),
                budget_wait_ns: 0,
                coordinator_wait_ns,
                dispatch_overhead_ns,
                peak_concurrency: peak_concurrency.load(Ordering::Acquire),
            },
        }
    }
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_is_bounded_and_results_are_in_task_order() {
        let barrier = Barrier::new(2);
        let run = BoundedReadyScheduler::new(2).run(4, None, |task| {
            if task < 2 {
                barrier.wait();
            }
            task * 10
        });

        assert_eq!(run.results, [0, 10, 20, 30]);
        assert_eq!(run.profile.worker_limit, 2);
        assert_eq!(run.profile.workers_spawned, 2);
        assert_eq!(run.profile.tasks_started, 4);
        assert_eq!(run.profile.tasks_completed, 4);
        assert_eq!(run.profile.peak_concurrency, 2);
    }

    #[test]
    fn cancellation_is_visible_before_queued_tasks_start() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let run = BoundedReadyScheduler::new(1)
            .run(3, Some(&cancellation), |_| cancellation.is_cancelled());

        assert_eq!(run.results, [true, true, true]);
        assert_eq!(run.profile.tasks_observed_cancelled_before_start, 3);
        assert_eq!(run.profile.tasks_started, 3);
        assert_eq!(run.profile.peak_concurrency, 1);
    }
}
