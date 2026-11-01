use super::*;
use crate::searchtools_render::{RenderOptions, RenderText};

#[test]
fn interrupted_absence_renders_scan_incomplete_caveat() {
    // This checks rendering of an incomplete status produced by the real scanner.
    let (_fixture, analyzer) = soft_deadline_partial_fixture();
    let result = scan_with(
        &analyzer,
        CancellationToken::soft_deadline_after_checks_for_test(0),
    );
    let entry = &result.results[0];
    assert_eq!(
        entry.status,
        ScanUsagesStatus::UnverifiedAbsent,
        "{result:#?}"
    );
    assert!(
        entry
            .absence_caveats
            .contains(&ScanUsagesAbsenceCaveat::ScanIncomplete)
    );
    let rendered = result.render_text(RenderOptions::default());
    assert!(
        rendered.contains("absence caveat(s): scan_incomplete"),
        "{rendered}"
    );
}
