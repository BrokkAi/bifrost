//! Worker-pool sizing for concurrent policy evaluation.
//!
//! Evaluating several policies at once multiplies the peak in-flight query
//! materialization by the number of workers, so the width is an explicit,
//! operator-tunable cap rather than the host's core count. An unset override
//! takes half the analyzer pool width, clamped to one through eight workers, so
//! a wider host does not scale peak in-flight materialization without bound. A
//! width of one selects the strictly serial evaluation path.

use std::sync::atomic::{AtomicUsize, Ordering};

use brokk_bifrost_analysis::analyzer::AnalyzerConfig;

/// Environment variable that overrides the concurrent-policy worker count.
///
/// A positive integer wins. `0` or a non-integer is ignored and the default
/// applies, matching how `BIFROST_PARALLELISM` is read for the analyzer pools.
pub const POLICY_PARALLELISM_ENV: &str = "BIFROST_POLICY_PARALLELISM";

/// Widest default concurrent-policy worker pool.
///
/// The derived default never exceeds this, so a host with many cores cannot
/// multiply the peak in-flight query materialization past eight policies'
/// worth of results.
pub const MAX_DEFAULT_POLICY_PARALLELISM: usize = 8;

/// Worker-pool width for concurrent policy evaluation.
///
/// [`POLICY_PARALLELISM_ENV`] wins when it holds a positive integer. Otherwise
/// the width is half the analyzer pool width, which already resolves
/// `BIFROST_PARALLELISM` and otherwise the number of available logical CPUs.
/// The derived default never exceeds [`MAX_DEFAULT_POLICY_PARALLELISM`], and the
/// result is always at least one, so a caller can treat it as a divisor.
pub fn policy_evaluation_parallelism() -> usize {
    if let Ok(raw) = std::env::var(POLICY_PARALLELISM_ENV)
        && let Ok(value) = raw.trim().parse::<usize>()
        && value > 0
    {
        return value;
    }
    default_policy_evaluation_parallelism(AnalyzerConfig::default().parallelism())
}

/// The unset-variable width: half the analyzer pool width, one through eight.
fn default_policy_evaluation_parallelism(analyzer_parallelism: usize) -> usize {
    (analyzer_parallelism / 2).clamp(1, MAX_DEFAULT_POLICY_PARALLELISM)
}

/// Run `work` over `items` on at most `parallelism` workers, returning one
/// result per item in input order.
///
/// The worker count is the whole point: it bounds how many policies are in
/// flight at once, which is what keeps the peak memory the parallel evaluation
/// can hold from growing with the host's core count. `work` must be callable
/// from several threads at once, so every captured value is either owned by the
/// closure or a shared reference to something `Sync`. A panic in any worker
/// resumes in the caller rather than being swallowed.
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
    let mut collected = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let next = &next;
            let work = &work;
            handles.push(scope.spawn(move || {
                let mut local = Vec::new();
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= items.len() {
                        break;
                    }
                    local.push((index, work(items[index])));
                }
                local
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

    #[test]
    fn the_unset_default_is_half_the_analyzer_width_within_one_through_eight() {
        assert_eq!(default_policy_evaluation_parallelism(1), 1);
        assert_eq!(default_policy_evaluation_parallelism(2), 1);
        assert_eq!(default_policy_evaluation_parallelism(3), 1);
        assert_eq!(default_policy_evaluation_parallelism(4), 2);
        assert_eq!(default_policy_evaluation_parallelism(16), 8);
        assert_eq!(default_policy_evaluation_parallelism(32), 8);
        assert_eq!(default_policy_evaluation_parallelism(128), 8);
    }
}
