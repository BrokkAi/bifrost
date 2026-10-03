//! Fixed Rust workspace used to design the common native-resolution vocabulary.
//!
//! The bytes live in the language crate so the fixture can evolve with Rust's
//! structured parser facts without making this crate depend on the analysis
//! layer. Analyzer tests construct an inline project from these rows.

/// One workspace root plus two member crates that exercise the Rust constructs
/// required by the Milestone 6a vocabulary spike.
pub const M6A_RUST_WORKSPACE_FILES: &[(&str, &str)] = &[
    (
        "Cargo.toml",
        r#"[workspace]
members = ["engine", "app"]
resolver = "2"
"#,
    ),
    (
        "engine/Cargo.toml",
        r#"[package]
name = "engine"
version = "0.1.0"
edition = "2024"
"#,
    ),
    (
        "engine/src/lib.rs",
        r#"pub mod model;

pub use model::Widget as PublicWidget;
pub use model::*;

macro_rules! local_value {
    () => { 7usize };
}

#[macro_export]
macro_rules! exported_value {
    () => { 11usize };
}

pub fn local_macro_value() -> usize {
    local_value!()
}
"#,
    ),
    (
        "engine/src/model.rs",
        r#"pub trait Base {
    type Item;
    const LIMIT: usize;
}

pub trait View<'a>: Base
where
    Self::Item: 'a,
{
    fn view(&'a self) -> &'a Self::Item;
}

pub struct Widget<T: Clone> {
    value: T,
}

impl<T: Clone> Widget<T> {
    pub fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T: Clone> Base for Widget<T> {
    type Item = T;
    const LIMIT: usize = 1;
}

impl<'a, T: Clone + 'a> View<'a> for Widget<T> {
    fn view(&'a self) -> &'a Self::Item {
        &self.value
    }
}
"#,
    ),
    (
        "app/Cargo.toml",
        r#"[package]
name = "app"
version = "0.1.0"
edition = "2024"

[features]
left = []

[dependencies]
engine = { path = "../engine" }
"#,
    ),
    (
        "app/src/main.rs",
        r#"use engine::PublicWidget as WidgetAlias;
use engine::model::Widget as DirectWidget;
use engine::local_macro_value as direct_value;
use engine::model::*;
use engine::*;

#[cfg(feature = "left")]
mod selected {
    pub const VALUE: usize = 1;
}

#[cfg(not(feature = "left"))]
mod selected {
    pub const VALUE: usize = 2;
}

include!("included.rs");

#[cfg(test)]
mod tests;

fn main() {
    let widget = WidgetAlias::new(exported_value!());
    let _direct: Option<DirectWidget<usize>> = None;
    let _ = widget.view();
    let _ = selected::VALUE + included_value() + direct_value();
}
"#,
    ),
    (
        "app/src/included.rs",
        r#"pub fn included_value() -> usize {
    13
}
"#,
    ),
    (
        "app/src/tests.rs",
        r#"#[test]
fn selected_value_is_nonzero() {
    assert_ne!(super::selected::VALUE, 0);
}
"#,
    ),
];
