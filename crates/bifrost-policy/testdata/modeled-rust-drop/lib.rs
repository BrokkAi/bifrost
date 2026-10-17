// Test-only #5236 witness. No production pack registrations.
pub fn string_view(password: String) {
    let message = password.as_str();
    println!("{}", message);
}
pub fn byte_view(password: String) {
    let message = password.as_bytes();
    println!("{:?}", message);
}
pub fn scalar_and_pointer(password: String) {
    let count = password.capacity();
    let pointer = password.as_ptr();
    println!("{} {:p}", count, pointer);
}
