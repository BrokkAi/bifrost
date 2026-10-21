#[doc(hidden)]
pub const CPP_CALL_SITE_SOURCE: &str = r#"
namespace ns {
template <typename T> void make(T) {}
template <typename T> struct Box {};
struct Widget {
  template <typename T> void run(T) {}
  Widget& operator+(int) { return *this; }
  ~Widget() {}
};
}
void caller(ns::Widget& receiver) {
  ns::make<int>(1);
  receiver.run<int>(1);
  new ns::Box<int>();
  receiver.operator+(1);
  receiver.~Widget();
}
"#;
