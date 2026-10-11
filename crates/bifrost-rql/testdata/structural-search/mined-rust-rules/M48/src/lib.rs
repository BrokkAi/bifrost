use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;
use std::sync::Mutex;

pub async fn mutex_guard_across_await(lock: &Mutex<u32>, wait: impl Future<Output = ()>) {
    let guard = lock.lock().unwrap();
    wait.await;
    std::hint::black_box(&guard);
}

pub async fn refcell_borrow_across_await(cell: &RefCell<u32>, wait: impl Future<Output = ()>) {
    let borrow = cell.borrow();
    wait.await;
    std::hint::black_box(&borrow);
}

pub async fn rc_across_await(value: Rc<()>, wait: impl Future<Output = ()>) {
    let held = Rc::clone(&value);
    wait.await;
    std::hint::black_box(&held);
}

pub async fn mutex_guard_dropped_before_await(lock: &Mutex<u32>, wait: impl Future<Output = ()>) {
    {
        let guard = lock.lock().unwrap();
        std::hint::black_box(&guard);
    }
    wait.await;
}

pub async fn refcell_borrow_dropped_before_await(cell: &RefCell<u32>, wait: impl Future<Output = ()>) {
    {
        let borrow = cell.borrow();
        std::hint::black_box(&borrow);
    }
    wait.await;
}

pub async fn send_value_across_await(value: u32, wait: impl Future<Output = ()>) {
    let held = value;
    wait.await;
    std::hint::black_box(held);
}
