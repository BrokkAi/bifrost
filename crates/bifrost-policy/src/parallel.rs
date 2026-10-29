//! Worker-pool sizing for concurrent policy evaluation.
//!
//! Memory per worker is bounded at its sources, not by the worker count
//! (#7116): reads are recorded only on the ledgers of the request that made
//! them, and concurrent queries share one live copy of each file's structural
//! facts. The default width is still capped, for a measured reason: past eight
//! workers a cold scan got no faster and used more CPU, because the longest
//! single policy sets the floor (#7110). Measured on 2026-10-27 on a 32-vCPU
//! host: apache/cassandra took 3,637 s wall and 6,480 s CPU at width 8, and
//! 3,692 s wall and 7,335 s CPU at width 32; pallets/flask took 388 s and
//! 1,487 s at width 8, and 392 s and 1,550 s at width 32. Raise the cap when
//! longest-first dispatch (#7110) or parallelism inside a policy (#3710)
//! lowers that floor. `BIFROST_POLICY_PARALLELISM` overrides the width, and a
//! width of one selects the strictly serial evaluation path.

use std::sync::atomic::{AtomicUsize, Ordering};

use brokk_bifrost_analysis::analyzer::AnalyzerConfig;

/// Environment variable that overrides the concurrent-policy worker count.
///
/// A positive integer wins. `0` or a non-integer is ignored and the default
/// applies, matching how `BIFROST_PARALLELISM` is read for the analyzer pools.
pub const POLICY_PARALLELISM_ENV: &str = "BIFROST_POLICY_PARALLELISM";

/// Widest default concurrent-policy worker pool; see the module documentation
/// for the measurement behind it.
pub const MAX_DEFAULT_POLICY_PARALLELISM: usize = 8;

/// Worker-pool width for concurrent policy evaluation.
///
/// [`POLICY_PARALLELISM_ENV`] wins when it holds a positive integer. Otherwise
/// the width is the analyzer pool width (`BIFROST_PARALLELISM`, otherwise the
/// number of available logical CPUs), at most
/// [`MAX_DEFAULT_POLICY_PARALLELISM`]. Either way it is at least one, so a
/// caller can treat it as a divisor.
pub fn policy_evaluation_parallelism() -> usize {
    if let Ok(raw) = std::env::var(POLICY_PARALLELISM_ENV)
        && let Ok(value) = raw.trim().parse::<usize>()
        && value > 0
    {
        return value;
    }
    AnalyzerConfig::default()
        .parallelism()
        .min(MAX_DEFAULT_POLICY_PARALLELISM)
}

/// Run `work` over `items` on at most `parallelism` workers, returning one
/// result per item in input order.
///
/// The worker count bounds how many policies are in flight at once. `work` must
/// be callable from several threads at once, so every captured value is either
/// owned by the closure or a shared reference to something `Sync`. A panic in
/// any worker resumes in the caller rather than being swallowed.
pub(crate) fn map_bounded<T, R>(
    parallelism: usize,
    items: &[T],
    work: impl Fn(T) -> R + Sync,
) -> Vec<R>
where
    T: Copy + Sync,
    R: Send,
{
    let workers = parallelism.max(1).min(items.len());
    if workers <= 1 {
        return items.iter().copied().map(&work).collect();
    }
    let next = AtomicUsize::new(0);
    // Workers record reads for the caller's request, exactly as the serial
    // path does on the caller's own thread.
    let context = brokk_bifrost_analysis::analyzer::CarriedContext::current();
    let mut collected = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let next = &next;
            let work = &work;
            let context = &context;
            handles.push(scope.spawn(move || {
                context.run(|| {
                    let mut local = Vec::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        if index >= items.len() {
                            break;
                        }
                        local.push((index, work(items[index])));
                    }
                    local
                })
            }));
        }
        handles
            .into_iter()
            .flat_map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
            })
            .collect::<Vec<_>>()
    });
    collected.sort_by_key(|(index, _)| *index);
    collected.into_iter().map(|(_, result)| result).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_override_parses_like_the_analyzer_parallelism_variable() {
        // One test mutates the process environment for the whole module so the
        // cases cannot race each other under a threaded test runner.
        let prior = std::env::var(POLICY_PARALLELISM_ENV).ok();
        // SAFETY: single-threaded test mutation of the process environment.
        unsafe { std::env::set_var(POLICY_PARALLELISM_ENV, "3") };
        assert_eq!(policy_evaluation_parallelism(), 3);

        // SAFETY: single-threaded test mutation of the process environment.
        unsafe { std::env::set_var(POLICY_PARALLELISM_ENV, "0") };
        assert!(policy_evaluation_parallelism() >= 1);

        // SAFETY: single-threaded test mutation of the process environment.
        unsafe { std::env::set_var(POLICY_PARALLELISM_ENV, "not-a-number") };
        assert!(policy_evaluation_parallelism() >= 1);

        match prior {
            Some(value) => unsafe { std::env::set_var(POLICY_PARALLELISM_ENV, value) },
            None => unsafe { std::env::remove_var(POLICY_PARALLELISM_ENV) },
        }
    }
}
