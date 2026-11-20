// Test-only source exercising the declaration/import projection boundary.
use std::{collections::HashMap as Map, fmt};
extern crate core as core_alias;
pub struct Container<T> { pub value: T }
impl<T> Container<T> {
    pub fn new(value: T) -> Self { Self { value } }
    pub fn read(&self) -> &T { use std::mem; &self.value }
}
mod nested {
    use super::Container as Local;
    impl Local<u32> { fn extra(&self) -> u32 { self.value } }
    pub const LIMIT: usize = 4;
}
macro_rules! passthrough { ($($item:item)*) => { $($item)* }; }
passthrough! {
    use std::path::Path;
    pub struct Embedded { pub member: u32 }
    impl Embedded { pub fn read(&self) -> u32 { self.member } }
    mod child { use std::fmt::Debug; pub fn child() {} }
}
macro_rules! hidden { ($($item:item)*) => {} }
hidden! { pub fn not_emitted() {} }
external_wrapper! { pub fn external_argument() {} }
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn direct() {}
    passthrough! { pub fn embedded_test() {} }
}
