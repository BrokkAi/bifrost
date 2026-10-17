//! Records the target triple this crate is compiled for.
//!
//! Rust analysis models the host as the machine bifrost runs on. Cargo applies
//! `[target.<triple>]` configuration for the host triple when a build names no
//! target, and `std::env::consts` does not spell the full triple.

fn main() {
    let target = std::env::var("TARGET").expect("Cargo sets TARGET for build scripts");
    println!("cargo:rustc-env=BROKK_BIFROST_RUST_HOST_TRIPLE={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
