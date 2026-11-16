//! Linux-only System allocator oracle for single-test diagnostic binaries.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, Ordering};

static REQUESTED: AtomicI64 = AtomicI64::new(0);
static USABLE: AtomicI64 = AtomicI64::new(0);
unsafe extern "C" {
    fn malloc_usable_size(pointer: *const std::ffi::c_void) -> usize;
}

pub struct CountingSystem;
unsafe impl GlobalAlloc for CountingSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            REQUESTED.fetch_add(layout.size() as i64, Ordering::Relaxed);
            USABLE.fetch_add(
                unsafe { malloc_usable_size(pointer.cast()) } as i64,
                Ordering::Relaxed,
            );
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        REQUESTED.fetch_sub(layout.size() as i64, Ordering::Relaxed);
        USABLE.fetch_sub(
            unsafe { malloc_usable_size(pointer.cast()) } as i64,
            Ordering::Relaxed,
        );
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let old_usable = unsafe { malloc_usable_size(pointer.cast()) };
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            REQUESTED.fetch_add(size as i64 - layout.size() as i64, Ordering::Relaxed);
            USABLE.fetch_add(
                unsafe { malloc_usable_size(result.cast()) } as i64 - old_usable as i64,
                Ordering::Relaxed,
            );
        }
        result
    }
}
pub fn live_requested_bytes() -> i64 {
    REQUESTED.load(Ordering::Relaxed)
}
pub fn live_usable_bytes() -> i64 {
    USABLE.load(Ordering::Relaxed)
}

use crate::retention_budget::{RetainedBytes, RetentionBudget};
pub fn check_region<V: RetainedBytes + Send + Sync + 'static>(
    name: &'static str,
    build: impl Fn() -> V,
) {
    // Budget-owner setup is shared by all regions, not charged once per entry.
    let budget = RetentionBudget::for_test_capacity(512 * 1024 * 1024);
    let before = live_usable_bytes();
    let region = budget.region::<usize, V>(name, None);
    drop(region.insert(0, build()));
    let fixed = (live_usable_bytes() - before) - (budget.accounted_bytes() as i64);
    // Empty namespace + first table setup is separately measured, not hidden
    // in the marginal assertion. Representative runs measured at most 9460
    // unfunded setup bytes; the independent fixed-setup allowance is 64 KiB.
    assert!(
        fixed <= 64 * 1024,
        "{name} fixed setup {fixed} exceeds64KiB"
    );
    for key in 1..1000 {
        drop(region.insert(key, build()));
    }
    let caps_before = region.allocation_index_capacities();
    let charged_before = budget.accounted_bytes();
    let usable_before = live_usable_bytes();
    let requested_before = live_requested_bytes();
    for key in 1000..2001 {
        drop(region.insert(key, build()));
    }
    let requested = live_requested_bytes() - requested_before;
    let usable = live_usable_bytes() - usable_before;
    let charged = budget.accounted_bytes() - charged_before;
    let caps_after = region.allocation_index_capacities();
    assert!(
        caps_after.0 > caps_before.0 && caps_after.1 > caps_before.1,
        "{name}: no table growth {caps_before:?}->{caps_after:?}"
    );
    assert!(
        usable <= charged as i64,
        "{name}: usable={usable} requested={requested} charge={charged}, {caps_before:?}->{caps_after:?}"
    );
    println!(
        "ALLOCATED_REGION {name} fixed={fixed} requested={requested} usable={usable} charged={charged} growth={caps_before:?}->{caps_after:?}"
    );
}
