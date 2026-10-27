pub mod outer {
    pub mod inner { pub struct Item; }
    mod empty {}include!("part.rs");
}
mod empty {}include!("root_part.rs");
pub mod branch;
#[cfg(test)] mod test_only;
mod consumer { use crate::outer::inner::Item as Chosen; }
pub fn dependencies() { dep_alias::api(); noise::api(); }
mod shadowed;
