//! Recorded selected Rust declaration kinds; the SQL remains owned by resolution_operation.
use super::super::{NonEmpty, RecordedContent, SelectedDependency};
use rusqlite::{OptionalExtension, params};
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SourceSemantic {
    pub content: RecordedContent,
    pub key: i64,
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DeclarationKindKey {
    pub source: SourceSemantic,
    pub mount_ordinal: u32,
}
fn path_dependency(content: &RecordedContent) -> NonEmpty<SelectedDependency> {
    NonEmpty::one(SelectedDependency::Path {
        language: content.mount.language,
        rel_path: content.mount.path.clone(),
        selected: Some((content.mount.oid, content.mount.variant)),
    })
}
fn content_bytes(content: &RecordedContent) -> usize {
    std::mem::size_of::<RecordedContent>() + content.mount.path.len() + content.receipt_bytes
}

selected_queries! {
    selection DeclarationKind {
        params:DeclarationKindKey, answer:Option<brokk_bifrost_core::analyzer::rust_facts::RustDeclarationKind>,
        sql:crate::analyzer::store::resolution_operation::RUST_RECEIVER_KIND_SQL,
        read:|statement:&mut rusqlite::Statement<'_>,key:&DeclarationKindKey| {
            let kind=statement.query_row(params![key.mount_ordinal,key.source.key],|row|row.get::<_,Option<i64>>(0)).optional()?.flatten();
            kind.map(crate::analyzer::store::source_facts::decode_rust_declaration_kind).transpose()
        },
        bytes:|_:&Option<brokk_bifrost_core::analyzer::rust_facts::RustDeclarationKind>|std::mem::size_of::<Option<brokk_bifrost_core::analyzer::rust_facts::RustDeclarationKind>>(),
        params_bytes:|key:&DeclarationKindKey|content_bytes(&key.source.content)+std::mem::size_of::<i64>()+std::mem::size_of::<u32>(),
        contract:|key:&DeclarationKindKey,_:&Option<brokk_bifrost_core::analyzer::rust_facts::RustDeclarationKind>|path_dependency(&key.source.content)
    }

}
