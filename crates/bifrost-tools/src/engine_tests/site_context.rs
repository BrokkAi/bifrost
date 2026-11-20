use brokk_bifrost_analysis::analyzer::semantic::{
    SemanticBudgetDimension, SemanticBudgetExceeded, SemanticCapability,
};
use brokk_bifrost_core::analyzer::model::ProjectFile;

use crate::site_context::{
    KnownValue, NotAnalyzedCause, SiteAdmission, SiteContext, SiteLocation, SiteRole, SiteValue,
    UnknownValueCause, UnrenderedReason, view,
};

fn json(context: &SiteContext) -> String {
    let owner =
        brokk_bifrost_core::retention_budget::RetentionBudget::for_test_capacity(1024 * 1024);
    let admitted = view(context, &SiteAdmission::new(Some(&owner))).expect("site admission");
    serde_json::to_string(&admitted).expect("a site view serializes")
}

/// Pins the one wire form of a site that RQL rows and flow tools embed.
#[test]
fn site_context_view_wire_form() {
    let root = tempfile::tempdir().expect("temp root");
    let source = SiteContext {
        site: SiteLocation::Source {
            path: ProjectFile::new(root.path(), "src/lib.rs"),
            byte_range: 10..15,
            start_line: 2,
            start_column: 3,
            end_line: 2,
            end_column: 8,
            text: "\"abc\"".to_string(),
        },
        role: SiteRole::Argument {
            index: 1,
            name: Some("key".to_string()),
        },
        value: SiteValue::Known(KnownValue::Str("abc".to_string())),
    };
    assert_eq!(
        json(&source),
        r#"{"site":{"kind":"source","path":"src/lib.rs","start_byte":10,"end_byte":15,"start_line":2,"start_column":3,"end_line":2,"end_column":8,"text":"\"abc\""},"role":{"kind":"argument","index":1,"name":"key"},"value":{"kind":"known","value":{"kind":"str","value":"abc"}}}"#
    );

    let unrendered = SiteContext {
        site: SiteLocation::Unrendered {
            path: ProjectFile::new(root.path(), "src/lib.rs"),
            byte_range: 10..15,
            reason: UnrenderedReason::RenderBudget,
        },
        role: SiteRole::Argument {
            index: 1,
            name: None,
        },
        value: SiteValue::Known(KnownValue::Str("abc".to_string())),
    };
    assert_eq!(
        json(&unrendered),
        r#"{"site":{"kind":"unrendered","path":"src/lib.rs","start_byte":10,"end_byte":15,"reason":"render_budget"},"role":{"kind":"argument","index":1},"value":{"kind":"known","value":{"kind":"str","value":"abc"}}}"#
    );

    let external = SiteContext {
        site: SiteLocation::External {
            declaration: "java.lang.String.trim".to_string(),
        },
        role: SiteRole::Call,
        value: SiteValue::Unknown(UnknownValueCause::NoSourceNode),
    };
    assert_eq!(
        json(&external),
        r#"{"site":{"kind":"external","declaration":"java.lang.String.trim"},"role":{"kind":"call"},"value":{"kind":"unknown","cause":{"kind":"no_source_node"}}}"#
    );

    let not_analyzed = |cause| SiteContext {
        site: SiteLocation::Summary {
            procedure: "pkg.run".to_string(),
        },
        role: SiteRole::FieldRead {
            member: "x".to_string(),
        },
        value: SiteValue::Unknown(UnknownValueCause::NotAnalyzed(cause)),
    };
    assert_eq!(
        json(&not_analyzed(NotAnalyzedCause::Unsupported(
            SemanticCapability::Calls
        ))),
        r#"{"site":{"kind":"summary","procedure":"pkg.run"},"role":{"kind":"field_read","member":"x"},"value":{"kind":"unknown","cause":{"kind":"not_analyzed","cause":{"kind":"unsupported","capability":"calls"}}}}"#
    );
    assert_eq!(
        json(&not_analyzed(NotAnalyzedCause::ExceededBudget(
            SemanticBudgetExceeded::new(SemanticBudgetDimension::SourceBytes, 5, 9)
        ))),
        r#"{"site":{"kind":"summary","procedure":"pkg.run"},"role":{"kind":"field_read","member":"x"},"value":{"kind":"unknown","cause":{"kind":"not_analyzed","cause":{"kind":"exceeded_budget","lane":"source","limit":5,"attempted":9}}}}"#
    );
}

/// The shared wire constructor cannot allocate a mandatory literal without an
/// owner; a refused row does not silently turn a constant into an unknown.
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#14068: mandatory site values were copied before output admission"
)]
fn refused_site_values_are_atomic_and_admitted_clones_share_backing() {
    use crate::site_context::{KnownValueView, SiteAdmissionRefusal, SiteValueView};
    use brokk_bifrost_core::retention_budget::RetentionBudget;
    let context = SiteContext {
        site: SiteLocation::External {
            declaration: "external".to_owned(),
        },
        role: SiteRole::Value,
        value: SiteValue::Known(KnownValue::Str("value".repeat(1024))),
    };
    assert_eq!(
        view(&context, &SiteAdmission::new(None)),
        Err(SiteAdmissionRefusal::OwnerUnavailable)
    );
    let refusing = RetentionBudget::for_test_capacity(0);
    assert_eq!(
        view(&context, &SiteAdmission::new(Some(&refusing))),
        Err(SiteAdmissionRefusal::RetainedBytes)
    );
    assert_eq!(refusing.accounted_bytes(), 0);
    let owner = RetentionBudget::for_test_capacity(1024 * 1024);
    let site = view(&context, &SiteAdmission::new(Some(&owner))).unwrap();
    let extracted = match &site.value {
        SiteValueView::Known {
            value: KnownValueView::Str { value },
        } => value.clone(),
        other => panic!("expected the exact known string: {other:?}"),
    };
    let clone = site.clone();
    let clone_value = clone.value.known_str().unwrap();
    assert_eq!(clone_value.as_ptr(), extracted.as_ptr());
    let charged = owner.accounted_bytes();
    drop(site);
    assert_eq!(owner.accounted_bytes(), charged);
    drop(clone);
    assert!(owner.accounted_bytes() >= extracted.len() as u64);
    assert_eq!(extracted.as_ref(), context.value.known_str().unwrap());
    drop(extracted);
    assert_eq!(owner.accounted_bytes(), 0);
    let root = tempfile::tempdir().unwrap();
    let source = SiteContext {
        site: SiteLocation::Source {
            path: ProjectFile::new(root.path(), "large.py"),
            byte_range: 0..65536,
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 65537,
            text: "a".repeat(65536),
        },
        role: SiteRole::Value,
        value: SiteValue::Known(KnownValue::Int("-16".to_owned())),
    };
    let owner = RetentionBudget::for_test_capacity(4096);
    let admitted = view(&source, &SiteAdmission::new(Some(&owner))).unwrap();
    assert!(matches!(
        admitted.site,
        crate::site_context::SiteLocationView::Unrendered {
            reason: UnrenderedReason::RenderBudget,
            ..
        }
    ));
    assert!(
        matches!(&admitted.value, SiteValueView::Known { value: KnownValueView::Int { value } } if value.as_ref() == "-16")
    );
    drop(admitted);
    assert_eq!(owner.accounted_bytes(), 0);
}
