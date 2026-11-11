# rustdoc converter fixture

The source crate is Apache-2.0 licensed. `native-61.json` was generated from `src/lib.rs` with rustdoc 1.99.1 (format 61), using:

```sh
RUSTC_BOOTSTRAP=1 rustdoc --crate-name rustdoc_converter_small --edition 2024 --output-format json -Z unstable-options src/lib.rs -o /tmp/rustdoc-converter-small/native
```

The converter tests project older schemas from this exact source tuple and validate them with the pinned `rustdoc-types` releases. No format-54/56/57 rustdoc toolchain is installed, so these are schema projections, not native old-toolchain builds. The test compares overlapping fields of the projected format-57 conversion with this native format-61 output. The fixture source has no dependencies and no build script.
