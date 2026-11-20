// Test-only source for the per-impl selection hook. No product packs.
pub trait Draw {
    fn draw(&self) {}
    fn tick(&self) {}
}

pub struct A;
pub struct B;
pub struct Inherits;
pub struct Empty;
pub struct Macro;
pub struct Conditional;
pub struct Transformed;
pub union MyUnion {
    pub value: u32,
}
impl Draw for MyUnion {}

mod overrides;

pub struct Foo;
pub type Alias = &'static Foo;
impl Draw for Alias {}

#[transform]
mod transformed {
    use super::{Draw, Transformed};
    impl Draw for Transformed {}
}

#[transform]
pub mod transformed_contract {
    pub trait Wrapped {
        fn run(&self) {}
    }
}
impl transformed_contract::Wrapped for A {}

impl Draw for B {
    fn draw(&self) {}
}
impl Draw for Inherits {
    fn tick(&self) {}
}
impl Draw for Empty {}

macro_rules! draw_method {
    () => { fn draw(&self) {} };
}
impl Draw for Macro {
    draw_method!();
}
impl Draw for Conditional {
    #[cfg(feature = "custom")]
    fn draw(&self) {}
}

pub trait Marker {}
impl<T: Marker> Draw for T {}

pub trait Required {
    fn required(&self);
}
impl Required for A {
    fn required(&self) {}
}
// A workspace during an edit can contain an unfinished required impl. An
// empty item table proves absence, but cannot invent a nonexistent default.
impl Required for Empty {}

pub trait Namespaced {
    type Item;
    fn Item(&self) {}
}
impl Namespaced for A {
    type Item = u8;
}

pub fn dynamic(value: &dyn Draw) {
    value.draw();
}
