#[doc(hidden)]
pub const SOURCE: &str = r#"interface Contract {}
class Plain {}
class Explicit { Explicit(int value) {} }
class Odd { Odd {} }
record Pair(int value, String... labels) {}
class Host {
    void body() {
        class Local {}
        Object anonymous = new Object() {};
    }
}
"#;
