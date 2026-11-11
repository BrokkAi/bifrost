# Inlined re-export fixture

The source crate is Apache-2.0 licensed. `native-61.json` was generated with rustdoc 1.99.1 and `RUSTC_BOOTSTRAP=1 rustdoc --crate-name rustdoc_converter_inline --edition 2024 --output-format json -Z unstable-options src/lib.rs -o /tmp/rustdoc-converter-inline`.

This toolchain emits a local `Use` item and no non-local index item for the small `#[doc(inline)]` example. The converter test therefore injects one non-local index item into a legacy-schema projection to exercise the reviewer-required certification path. It does not claim that the injected item is native rustdoc output.
