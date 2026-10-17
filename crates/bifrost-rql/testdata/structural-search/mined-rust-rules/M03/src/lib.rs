mod io_helpers;

pub async fn async_entry() {
    io_helpers::read_file();
    io_helpers::pause_thread();
    io_helpers::take_lock();
}

pub fn sync_entry() {
    io_helpers::read_file();
}

pub async fn async_near_miss() {
    io_helpers::cooperative().await;
}
