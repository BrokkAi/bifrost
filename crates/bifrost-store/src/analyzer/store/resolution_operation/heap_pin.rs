// Shared allocation accounting for engine and relocated tools fixtures.
#[doc(hidden)]
pub struct HeapPinAllocator;
thread_local! {
    static HEAP_PIN_BYTES: std::cell::Cell<i64> = const { std::cell::Cell::new(0) };
    static HEAP_PIN_PEAK_BYTES: std::cell::Cell<i64> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
#[global_allocator]
static HEAP_PIN_ALLOCATOR: HeapPinAllocator = HeapPinAllocator;

unsafe impl std::alloc::GlobalAlloc for HeapPinAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let pointer = unsafe { std::alloc::System.alloc(layout) };
        if !pointer.is_null() {
            HEAP_PIN_BYTES.with(|bytes| {
                let current = bytes.get() + layout.size() as i64;
                bytes.set(current);
                HEAP_PIN_PEAK_BYTES.with(|peak| peak.set(peak.get().max(current)));
            });
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        HEAP_PIN_BYTES.with(|bytes| bytes.set(bytes.get() - layout.size() as i64));
        unsafe { std::alloc::System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(
        &self,
        pointer: *mut u8,
        layout: std::alloc::Layout,
        new_size: usize,
    ) -> *mut u8 {
        let result = unsafe { std::alloc::System.realloc(pointer, layout, new_size) };
        if !result.is_null() {
            HEAP_PIN_BYTES.with(|bytes| {
                let current = bytes.get() + new_size as i64 - layout.size() as i64;
                bytes.set(current);
                HEAP_PIN_PEAK_BYTES.with(|peak| peak.set(peak.get().max(current)));
            });
        }
        result
    }
}

#[doc(hidden)]
pub fn heap_pin_bytes() -> i64 {
    HEAP_PIN_BYTES.with(std::cell::Cell::get)
}

#[doc(hidden)]
/// Run `operation` and return its result and this thread's peak outstanding-bytes growth.
pub fn heap_pin_peak_growth<T>(operation: impl FnOnce() -> T) -> (T, i64) {
    let saved_peak = HEAP_PIN_PEAK_BYTES.with(std::cell::Cell::get);
    let start = heap_pin_bytes();
    HEAP_PIN_PEAK_BYTES.with(|peak| peak.set(start));
    let result = operation();
    let measured_peak = HEAP_PIN_PEAK_BYTES.with(std::cell::Cell::get);
    HEAP_PIN_PEAK_BYTES.with(|peak| peak.set(saved_peak.max(measured_peak)));
    (result, measured_peak.saturating_sub(start))
}
