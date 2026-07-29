mod common;

use common::normalize_line_endings;
use std::fs;
use std::path::Path;

const DOC: &str = "docs/src/content/docs/semantic-model-packs.md";
const MARKER: &str = "<!-- semantic-model-doc-test:";

#[test]
fn documented_source_examples_match_checked_fixtures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let document = normalize_line_endings(
        &fs::read_to_string(root.join(DOC)).expect("read semantic-model docs"),
    );
    let mut found = Vec::new();
    let mut remainder = document.as_str();

    while let Some(marker_start) = remainder.find(MARKER) {
        remainder = &remainder[marker_start + MARKER.len()..];
        let marker_end = remainder.find(" -->").expect("closed docs marker");
        let fixture = &remainder[..marker_end];
        remainder = &remainder[marker_end + 4..];
        let fence_start = remainder
            .find("```yaml\n")
            .expect("YAML fence after marker")
            + 8;
        remainder = &remainder[fence_start..];
        let fence_end = remainder.find("\n```").expect("closed YAML fence");
        let documented = &remainder[..fence_end];
        let checked = normalize_line_endings(
            &fs::read_to_string(root.join(fixture)).expect("read checked fixture"),
        );
        assert_eq!(
            documented.trim_end(),
            checked.trim_end(),
            "docs drifted from {fixture}"
        );
        found.push(fixture.to_owned());
        remainder = &remainder[fence_end + 4..];
    }

    assert_eq!(
        found,
        [
            "tests/fixtures/semantic-model-packs/declarations-v1.yaml",
            "tests/fixtures/semantic-model-packs/generator-rules-v1.yaml",
        ]
    );
    assert!(document.contains("does not install, store, match, or activate"));
    assert!(document.contains("Every source pack must contain `schema_version: 1`"));
}
