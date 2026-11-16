#![cfg(all(feature = "test-support", target_os = "linux"))]
use brokk_bifrost_test_macros::hardwon;
#[global_allocator]
static ALLOCATOR: brokk_bifrost_core::allocation_size::counting::CountingSystem =
    brokk_bifrost_core::allocation_size::counting::CountingSystem;

#[test]
#[hardwon("#12817: retained allocations exceeded the budget charge")]
fn allocated_regions_cover_live_system_allocations() {
    brokk_bifrost_store::analyzer::store::cache_budget::allocation_tests::run();
}
