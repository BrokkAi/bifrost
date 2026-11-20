// Keep the authored impl in a different source file from its trait contract.
use super::{A, Draw};

impl Draw for A {
    fn draw(&self) {}
}
