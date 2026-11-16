//! Recorded mount selection. Existing materialization callers remain unchanged.
use super::super::{MountContent, NonEmpty, RecordedContent, SelectedDependency};
use crate::analyzer::Language;
use rusqlite::{OptionalExtension, params};
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MountPath {
    pub language: Language,
    pub path: Box<str>,
}
fn decode_mount(row: &rusqlite::Row<'_>) -> rusqlite::Result<MountContent> {
    let label: String = row.get(1)?;
    let language = Language::from_config_label(&label)
        .ok_or_else(|| rusqlite::Error::InvalidParameterName(label))?;
    let oid: String = row.get(3)?;
    let oid = git2::Oid::from_str(&oid).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(MountContent {
        blob_id: row.get(0)?,
        language,
        path: row.get(2)?,
        oid,
        variant: row.get(4)?,
    })
}
fn dependency(mount: &MountContent) -> SelectedDependency {
    SelectedDependency::Path {
        language: mount.language,
        rel_path: mount.path.clone(),
        selected: Some((mount.oid, mount.variant)),
    }
}
selected_queries! {
    selection MountByPath {
        params:MountPath, answer:Option<MountContent>,
        sql:"SELECT m.blob_id,m.semantic_language,m.persisted_relative_path,m.blob_oid,b.parse_variant FROM temp.selected_resolution_mounts m JOIN main.blobs b ON b.id=m.blob_id WHERE m.semantic_language=?1 AND m.persisted_relative_path=?2",
        read:|statement:&mut rusqlite::Statement<'_>,params:&MountPath| Ok(statement.query_row(params![params.language.config_label(),params.path.as_ref()],decode_mount).optional()?),
        bytes:|answer:&Option<MountContent>| answer.as_ref().map_or(0,|mount|std::mem::size_of::<MountContent>()+mount.path.len()),
        params_bytes:|params:&MountPath|std::mem::size_of::<MountPath>()+params.path.len(),
        contract:|params:&MountPath,answer:&Option<MountContent>| NonEmpty::one(answer.as_ref().map_or_else(||SelectedDependency::Path {language:params.language,rel_path:params.path.clone(),selected:None},dependency))
    }
    content BlobOid {
        params:RecordedContent, answer:String,
        sql:"SELECT blob_oid FROM main.blobs WHERE id=?1",
        read:|statement:&mut rusqlite::Statement<'_>,content:&RecordedContent|Ok(statement.query_row([content.mount.blob_id],|row|row.get(0))?),
        bytes:|answer:&String|answer.capacity(), params_bytes:|content:&RecordedContent|std::mem::size_of::<RecordedContent>()+content.mount.path.len()+content.receipt_bytes, contract:()
    }
    #[cfg(test)]
    selection SelectedViewCount {
        params:(), answer:i64, sql:"SELECT count(blob_id) FROM main.live_code_units",
        read:|statement:&mut rusqlite::Statement<'_>,_:&()|Ok(statement.query_row([],|row|row.get(0))?),
        bytes:|_:&i64|std::mem::size_of::<i64>(),
        params_bytes:|_:&()|0,
        contract:|_:&(),_:&i64|NonEmpty::one(SelectedDependency::Scope {languages:vec![Language::Rust].into_boxed_slice()})
    }

    #[cfg(test)]
    selection SelectedTempViewCount {
        params:(), answer:i64, sql:"SELECT count(blob_id) FROM temp.selected_read_authorizer_view",
        read:|statement:&mut rusqlite::Statement<'_>,_:&()|Ok(statement.query_row([],|row|row.get(0))?),
        bytes:|_:&i64|std::mem::size_of::<i64>(),
        params_bytes:|_:&()|0,
        contract:|_:&(),_:&i64|NonEmpty::one(SelectedDependency::Scope {languages:vec![Language::Rust].into_boxed_slice()})
    }

    #[cfg(test)]
    selection SelectedCteCount {
        params:(), answer:i64, sql:"WITH content AS (SELECT id FROM main.blobs) SELECT count(*) FROM content",
        read:|statement:&mut rusqlite::Statement<'_>,_:&()|Ok(statement.query_row([],|row|row.get(0))?),
        bytes:|_:&i64|std::mem::size_of::<i64>(),
        params_bytes:|_:&()|0,
        contract:|_:&(),_:&i64|NonEmpty::one(SelectedDependency::Scope {languages:vec![Language::Rust].into_boxed_slice()})
    }

    #[cfg(test)]
    selection SelectedRecursiveCount {
        params:(), answer:i64, sql:"WITH RECURSIVE ids(id) AS (SELECT min(id) FROM main.blobs UNION ALL SELECT id+1 FROM ids WHERE id<(SELECT max(id) FROM main.blobs)) SELECT count(*) FROM ids",
        read:|statement:&mut rusqlite::Statement<'_>,_:&()|Ok(statement.query_row([],|row|row.get(0))?),
        bytes:|_:&i64|std::mem::size_of::<i64>(),
        params_bytes:|_:&()|0,
        contract:|_:&(),_:&i64|NonEmpty::one(SelectedDependency::Scope {languages:vec![Language::Rust].into_boxed_slice()})
    }

    #[cfg(test)]
    selection SelectedExists {
        params:(), answer:i64, sql:"SELECT EXISTS(SELECT 1 FROM temp.selected_resolution_mounts)",
        read:|statement:&mut rusqlite::Statement<'_>,_:&()|Ok(statement.query_row([],|row|row.get(0))?),
        bytes:|_:&i64|std::mem::size_of::<i64>(),
        params_bytes:|_:&()|0,
        contract:|_:&(),_:&i64|NonEmpty::one(SelectedDependency::Scope {languages:vec![Language::Rust].into_boxed_slice()})
    }

}
