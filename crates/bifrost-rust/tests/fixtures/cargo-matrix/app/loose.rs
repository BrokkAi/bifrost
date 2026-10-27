#[cfg(feature="default")] mod enabled {}
#[cfg(test)] mod tests {}
#[cfg(target_feature = "sse2")] mod vector {}
macro_rules! relay { ($($item:item)*) => { $($item)* }; }
#[cfg(feature = "outer")]
relay! {
    #[cfg(feature = "inner")]
    use crate::branch::leaf::Leaf as Selected;
}
#[cfg(custom_feature_probe)]
use crate::branch::leaf::Leaf as BuildScriptSelected;
