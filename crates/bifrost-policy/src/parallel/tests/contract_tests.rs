use super::*;

#[test]
fn bounded_parallel_mapping_preserves_input_positions() {
    let items = [11usize, 29, 37, 43, 59];
    let serial = map_bounded(1, &items, |item| item * item);
    let parallel = map_bounded(3, &items, |item| item * item);
    assert_eq!(parallel, serial);
    assert_eq!(parallel, items.map(|item| item * item));
}
