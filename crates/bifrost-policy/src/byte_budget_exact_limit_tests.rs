#[test]
fn exact_u64_byte_limit_is_admitted_and_next_byte_is_refused() {
    assert!(!crate::is_over_u64_byte_limit("é", 2));
    assert!(crate::is_over_u64_byte_limit("éx", 2));
    assert!(!crate::is_over_byte_limit("é", 2));
    assert!(crate::is_over_byte_limit("éx", 2));
}
