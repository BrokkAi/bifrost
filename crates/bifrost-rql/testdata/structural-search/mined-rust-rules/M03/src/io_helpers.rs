pub fn read_file() {
    let _ = std::fs::read("input");
}

pub fn pause_thread() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}

pub fn take_lock() {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock();
}

pub async fn cooperative() {}
