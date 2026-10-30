use super::query_step_reference;

#[test]
fn file_projection_reference_promises_file_rows() {
    let reference = query_step_reference();
    let file_projection = reference
        .lines()
        .find(|line| line.starts_with("file_of ("))
        .expect("file projection is documented");
    assert!(file_projection.contains(" -> file):"), "{file_projection}");
}
