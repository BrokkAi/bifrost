// Test-only macro contract inputs; these deliberately undefined macros are parsed, not compiled.
#[derive(Fx)]
#[fx(rename = "a", default)]
#[cfg_attr(feature = "f", fx(crate = "c"))]
#[fx("lit", true)]
#[marker]
#[fx = "value"]
#[cfg_attr(feature = "f", fx = "v")]
struct Data {
    #[fx(skip)]
    value: String,
}
#[derive(Fx)]
enum Choice {
    #[fx(rename = "variant")]
    Named { #[fx(skip)] value: String },
    Tuple(#[fx(default)] String),
}
#[fixture::test(flavor = "x", start)]
fn run() {}
#[derive(Fx)]
struct Tuple(#[fx(skip)] String);
#[fixture::test()]
fn empty() {}
