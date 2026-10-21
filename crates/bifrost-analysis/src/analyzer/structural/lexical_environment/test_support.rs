use super::*;

use crate::test_support::AnalyzerFixture;
#[doc(hidden)]
pub struct Fixture {
    pub(super) analyzer: AnalyzerFixture,
    pub(super) file: ProjectFile,
    pub(super) source: String,
}
impl Fixture {
    #[doc(hidden)]
    pub fn new(language: Language, relative_path: &str, source: &str) -> Self {
        let analyzer = AnalyzerFixture::new_for_language(language, &[(relative_path, source)]);
        let file = ProjectFile::new(analyzer.project_root(), relative_path);
        Self {
            analyzer,
            file,
            source: source.to_owned(),
        }
    }

    #[doc(hidden)]
    pub fn environment(&self) -> EnvironmentFileResult {
        environment_for_file(self.analyzer.analyzer().analyzer(), &self.file)
    }

    /// Byte offset of `needle`; the marker keeps a position assertion
    /// readable without re-scanning the fixture.
    #[doc(hidden)]
    pub fn at(&self, needle: &str) -> usize {
        crate::test_support::fixture_marker(&self.source, needle)
    }
}
#[doc(hidden)]
pub fn binding<'env>(env: &'env EnvironmentFileResult, name: &str) -> &'env BindingRow {
    let mut matches = env.bindings.iter().filter(|row| row.name == name);
    let found = matches
        .next()
        .unwrap_or_else(|| panic!("no binding named {name:?}; bindings: {:?}", env.bindings));
    assert!(
        matches.next().is_none(),
        "more than one binding named {name:?}; bindings: {:?}",
        env.bindings
    );
    found
}
/// The single binding in effect at `position`, failing with the whole
/// environment when the answer is anything else.
#[doc(hidden)]
pub fn reached<'env>(
    env: &'env EnvironmentFileResult,
    name: &str,
    position: usize,
) -> &'env BindingRow {
    match binding_of(env, name, position, None) {
        BindingOfOutcome::Reached(index) => &env.bindings[index],
        BindingOfOutcome::Shadowed { winner, .. } => &env.bindings[winner],
        other => panic!(
            "expected {name:?} to reach a binding at byte {position}, got {other:?}; \
                 bindings: {:?}",
            env.bindings
        ),
    }
}
