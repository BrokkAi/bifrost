use super::SourceImportFact;
use crate::analyzer::model::{ImportInfo, Range, StructuredImportPath, StructuredImportScope};
use crate::analyzer::source_facts::{
    SourceFactRows, SourceOccurrence, SourceOccurrenceId, SourceOccurrenceProvenance,
};
use crate::analyzer::structural::facts::Span;

fn source_rows() -> SourceFactRows {
    SourceFactRows::new(
        vec![
            SourceOccurrence {
                range: Range {
                    start_byte: 10,
                    end_byte: 20,
                    start_line: 1,
                    end_line: 1,
                },
                provenance: SourceOccurrenceProvenance::PrimaryNode,
            },
            SourceOccurrence {
                range: Range {
                    start_byte: 30,
                    end_byte: 35,
                    start_line: 1,
                    end_line: 1,
                },
                provenance: SourceOccurrenceProvenance::ExplicitSubspan,
            },
            SourceOccurrence {
                range: Range {
                    start_byte: 40,
                    end_byte: 45,
                    start_line: 1,
                    end_line: 1,
                },
                provenance: SourceOccurrenceProvenance::ExplicitSubspan,
            },
        ],
        Vec::new(),
    )
}

#[test]
fn unavailable_path_round_trip_retains_source_identity() {
    let rows = source_rows();
    let declaration = SourceOccurrenceId::new(0);
    let target = SourceOccurrenceId::new(1);
    let alias = SourceOccurrenceId::new(2);
    let fact = SourceImportFact::from_import(
        ImportInfo {
            raw_snippet: "malformed import".to_owned(),
            is_wildcard: false,
            is_global: false,
            identifier: Some("name".to_owned()),
            alias: Some("local".to_owned()),
            path: None,
            binder_span: Some(Span {
                start_byte: 900,
                end_byte: 901,
            }),
        },
        declaration,
        Some(target),
        Some(alias),
        Vec::new(),
    );

    assert_eq!(fact.declaration, declaration);
    assert_eq!(fact.target, Some(target));
    assert_eq!(fact.alias_occurrence, Some(alias));
    assert_eq!(fact.path, None);

    let materialized = fact.import_info(&rows);
    assert_eq!(materialized.path, None);
    assert_eq!(
        materialized.binder_span,
        Some(Span {
            start_byte: 40,
            end_byte: 45,
        })
    );
}

#[test]
fn empty_structured_path_round_trip_uses_canonical_spans() {
    let rows = source_rows();
    let fact = SourceImportFact::from_import(
        ImportInfo {
            raw_snippet: "empty path".to_owned(),
            is_wildcard: true,
            is_global: true,
            identifier: None,
            alias: None,
            path: Some(StructuredImportPath {
                segments: Vec::new(),
                kind: None,
                lexical_prefixes: Vec::new(),
                lexical_scopes: vec![StructuredImportScope {
                    start_byte: 700,
                    end_byte: 701,
                }],
                declaration_start_byte: 800,
            }),
            binder_span: Some(Span {
                start_byte: 900,
                end_byte: 901,
            }),
        },
        SourceOccurrenceId::new(0),
        Some(SourceOccurrenceId::new(1)),
        None,
        Vec::new(),
    );

    let materialized = fact.import_info(&rows);
    let path = materialized
        .path
        .expect("an empty structured path remains present");
    assert!(path.segments.is_empty());
    assert_eq!(path.kind, None);
    assert!(path.lexical_prefixes.is_empty());
    assert!(path.lexical_scopes.is_empty());
    assert_eq!(path.declaration_start_byte, 10);
    assert_eq!(
        materialized.binder_span,
        Some(Span {
            start_byte: 30,
            end_byte: 35,
        })
    );
}
