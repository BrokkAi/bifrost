//! Payload fixtures and region accounting checks for the System allocator oracle.
use super::{RetainedBytes, RetainedHeap};
use brokk_bifrost_core::allocation_size::counting::check_region as check;
use std::mem::size_of;

// PR-a2's types are not on master yet. These preserve their allocation shapes:
// keyed strings + digest buffers, and a header with nested footprint buffers.
struct RustWitness {
    keys: Vec<(String, String, String)>,
    digests: Vec<[u8; 32]>,
    digest: [u8; 32],
}
impl RetainedBytes for RustWitness {
    fn retained_bytes(&self) -> usize {
        let _ = self.digest;
        size_of::<Self>() + self.keys.retained_bytes() - size_of_val(&self.keys)
            + self.digests.retained_bytes()
            - size_of_val(&self.digests)
    }
}
type FootprintName = (Option<String>, Option<String>);
type FrontierFootprint = (u8, [u8; 32], Option<Vec<FootprintName>>);

struct RustFrontier {
    workspace: String,
    identities: Vec<([u8; 32], Option<[u8; 32]>)>,
    availability: Vec<([u8; 32], u8, u8)>,
    footprints: Vec<FrontierFootprint>,
    readers: Vec<([u8; 32], u8, [u8; 32])>,
}
impl RetainedBytes for RustFrontier {
    fn retained_bytes(&self) -> usize {
        size_of::<Self>() + self.workspace.retained_bytes() - size_of_val(&self.workspace)
            + self.identities.retained_bytes()
            - size_of_val(&self.identities)
            + self.availability.retained_bytes()
            - size_of_val(&self.availability)
            + self.footprints.retained_bytes()
            - size_of_val(&self.footprints)
            + self.readers.retained_bytes()
            - size_of_val(&self.readers)
    }
}
fn size_of_val<T>(v: &T) -> usize {
    std::mem::size_of_val(v)
}

pub fn run() {
    // This validates the fallback against actual System size classes, not an
    // assumption that requested capacity equals usable allocator storage.
    for bytes in (1..=1024).chain([2047, 2048, 2049, 4095, 4096, 4097, 16383, 16384, 16385]) {
        let before = brokk_bifrost_core::allocation_size::counting::live_usable_bytes();
        let buffer = std::hint::black_box(Vec::<u8>::with_capacity(bytes));
        let usable = brokk_bifrost_core::allocation_size::counting::live_usable_bytes() - before;
        assert!(
            usable
                <= brokk_bifrost_core::allocation_size::fallback_allocation_size(buffer.capacity())
                    as i64
        );
        drop(buffer);
    }
    assert_eq!(brokk_bifrost_core::allocation_size::allocation_size(0), 0);
    check("store.rust-foreign-witnesses.shape", || RustWitness {
        keys: (0..12)
            .map(|i| (format!("crate::module{i}"), "value".into(), "item".into()))
            .collect(),
        digests: vec![[1; 32]; 12],
        digest: [2; 32],
    });
    check("store.rust-content-frontiers.shape", || RustFrontier {
        workspace: "workspace-fixture".into(),
        identities: vec![([1; 32], Some([2; 32])); 8],
        availability: vec![([1; 32], 1, 1); 8],
        footprints: vec![
            (
                1,
                [2; 32],
                Some(vec![(Some("crate::module".into()), Some("item".into())); 6])
            );
            4
        ],
        readers: vec![([1; 32], 1, [2; 32]); 8],
    });
    check("store.python-binding-rows", || {
        use super::super::python_binding_rows::{BindingSlot, PythonBindingRows};
        let mut rows = PythonBindingRows::default();
        rows.slots = (0..12)
            .map(|i| BindingSlot {
                slot: i,
                scope: 0,
                name: format!("binding_{i}"),
                whole_scope: false,
            })
            .collect();
        rows
    });
    check(
        "store.rust-macro-include-overlays",
        super::super::resolution_operation::allocation_test_macro_overlay,
    );
    check(
        "store.selected-macro-inputs",
        super::super::resolution_operation::allocation_test_selected_macro_inputs,
    );
    brokk_bifrost_rust::lexical_scope::check_allocated_lexical_regions();
    brokk_bifrost_rust::cache::check_allocated_fact_regions();
    // semantic.complete_artifact is deliberately excluded: its payload remains
    // an aggregate row model, converted with the refusing artifact paths later.
    let mut raw = RetainedHeap::default();
    raw.add(size_of::<Vec<u64>>() + size_of::<String>());
    raw.vec(&Vec::<u64>::with_capacity(7));
    raw.add_allocation(4);
    #[cfg(target_pointer_width = "64")]
    assert_eq!(raw.total(), 108, "master refusing census byte pin");
}
