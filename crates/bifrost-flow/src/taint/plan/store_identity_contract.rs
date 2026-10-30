use crate::taint::{TaintStoreChannel, TaintStoreDimension};

#[test]
fn declared_store_names_are_case_sensitive() {
    for left in ["Cache", "cache", "CACHE"] {
        for right in ["Cache", "cache", "CACHE"] {
            let channel = |name: &str| {
                TaintStoreChannel::new(
                    name,
                    TaintStoreDimension::Undeclared,
                    TaintStoreDimension::Undeclared,
                )
            };
            assert_eq!(channel(left).may_alias(&channel(right)), left == right);
        }
    }
}
