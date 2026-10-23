#[doc(hidden)]
pub const SOURCE: &str = r#"package example;
import java.util.List;
class Types<T extends Number & Comparable<T>> {
    T value;
    List<?> unknownArgument() { return null; }
    T[][] arrays() { return null; }
    Runnable anonymous() { return new Runnable() { public void run() {} }; }
    void local() { class Local<U extends T> {} }
}
"#;
