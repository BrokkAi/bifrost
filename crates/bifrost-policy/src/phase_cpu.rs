//! Opt-in, same-thread policy CPU accounting. Policy workers own their state.
use std::{cell::RefCell, time::Duration};

use brokk_bifrost_analysis::profiling;

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    Compilation,
    Selector,
    OutputRecompute,
    RefusalFallback,
}

#[derive(Default, Clone, Copy)]
pub(crate) struct Totals {
    pub compilation: Duration,
    pub selector: Duration,
    pub output_recompute: Duration,
    pub refusal_fallback: Duration,
    selector_depth: usize,
    compilation_depth: usize,
    pub compilation_samples: u64,
    pub selector_samples: u64,
    pub output_samples: u64,
    pub fallback_samples: u64,
}

thread_local! { static TOTALS: RefCell<Totals> = RefCell::new(Totals::default()); }

pub(crate) fn reset() {
    TOTALS.with(|totals| *totals.borrow_mut() = Totals::default());
}

pub(crate) fn totals() -> Option<Totals> {
    profiling::enabled().then(|| TOTALS.with(|totals| *totals.borrow()))
}

pub(crate) struct Scope {
    phase: Phase,
    started: Option<Duration>,
}

impl Scope {
    pub(crate) fn new(phase: Phase) -> Self {
        let started = profiling::enabled().then(profiling::thread_cpu_time);
        if started.is_some() {
            TOTALS.with(|totals| {
                let mut totals = totals.borrow_mut();
                match phase {
                    Phase::Compilation => totals.compilation_depth += 1,
                    Phase::Selector => totals.selector_depth += 1,
                    _ => {}
                }
            });
        }
        Self { phase, started }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let Some(started) = self.started else { return };
        let elapsed = profiling::thread_cpu_time().saturating_sub(started);
        TOTALS.with(|totals| {
            let mut totals = totals.borrow_mut();
            match self.phase {
                Phase::Compilation => {
                    totals.compilation_depth -= 1;
                    totals.compilation += elapsed;
                    totals.compilation_samples += 1;
                }
                Phase::Selector => {
                    totals.selector_depth -= 1;
                    if totals.selector_depth == 0 && totals.compilation_depth > 0 {
                        totals.selector += elapsed;
                        totals.selector_samples += 1;
                    }
                }
                Phase::OutputRecompute => {
                    totals.output_recompute += elapsed;
                    totals.output_samples += 1;
                }
                Phase::RefusalFallback => {
                    totals.refusal_fallback += elapsed;
                    totals.fallback_samples += 1;
                }
            }
        });
    }
}
