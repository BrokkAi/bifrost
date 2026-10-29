//! Durable semantic identities and artifact-local dense IDs.

pub use crate::analyzer::LanguageDialect as SemanticLanguage;
pub use crate::analyzer::dense_id::DenseIdOverflow;
pub use brokk_bifrost_semantic::analyzer::semantic::ids::*;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::path::Path;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationLocator;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationSegment;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationSegmentKind;

    use brokk_bifrost_analysis::analyzer::semantic::ids::LengthDelimitedDigest;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SEMANTIC_IR_SCHEMA_VERSION;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SemanticArtifactKey;

    use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SemanticLocator;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SemanticRole;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SourceAnchor;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SourcePosition;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SourceRevision;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SourceSpan;

    use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;

    use brokk_bifrost_analysis::analyzer::semantic::ids::WorkspaceRelativePath;

    use brokk_bifrost_analysis::analyzer::semantic::ids::WorkspaceRelativePathError;

    use brokk_bifrost_core::analyzer::model::Language;

    #[test]
    fn native_paths_use_platform_components_without_aliasing_unix_backslashes() {
        let native = Path::new("src").join("nested").join("main.ts");
        assert_eq!(
            WorkspaceRelativePath::try_from_path(&native)
                .unwrap()
                .as_str(),
            "src/nested/main.ts"
        );

        #[cfg(windows)]
        assert_eq!(
            WorkspaceRelativePath::try_from_path(Path::new(r"src\nested\main.ts"))
                .unwrap()
                .as_str(),
            "src/nested/main.ts"
        );
        #[cfg(not(windows))]
        assert_eq!(
            WorkspaceRelativePath::try_from_path(Path::new(r"src\nested\main.ts")),
            Err(WorkspaceRelativePathError::InvalidCharacter)
        );
    }

    #[test]
    fn workspace_paths_reject_windows_unsafe_components() {
        for (invalid, expected) in [
            (
                "src/main.ts:stream",
                WorkspaceRelativePathError::InvalidCharacter,
            ),
            ("src/name?.ts", WorkspaceRelativePathError::InvalidCharacter),
            ("src/name*.ts", WorkspaceRelativePathError::InvalidCharacter),
            (
                "src/name|pipe.ts",
                WorkspaceRelativePathError::InvalidCharacter,
            ),
            (
                "src/control\u{1f}.ts",
                WorkspaceRelativePathError::InvalidCharacter,
            ),
            (
                "src/trailing.",
                WorkspaceRelativePathError::TrailingDotOrSpace,
            ),
            (
                "src/trailing ",
                WorkspaceRelativePathError::TrailingDotOrSpace,
            ),
            ("src/CON", WorkspaceRelativePathError::ReservedDeviceName),
            (
                "src/con.txt",
                WorkspaceRelativePathError::ReservedDeviceName,
            ),
            (
                "src/AUX .md",
                WorkspaceRelativePathError::ReservedDeviceName,
            ),
            (
                "src/lPt9.log",
                WorkspaceRelativePathError::ReservedDeviceName,
            ),
            (
                "src/COM¹.log",
                WorkspaceRelativePathError::ReservedDeviceName,
            ),
        ] {
            assert_eq!(
                WorkspaceRelativePath::new(invalid),
                Err(expected),
                "{invalid:?}"
            );
        }

        for valid in [
            "src/console.rs",
            "src/com10.txt",
            "src/auxiliary",
            "src/trailing .txt",
        ] {
            assert!(WorkspaceRelativePath::new(valid).is_ok(), "{valid:?}");
        }
    }

    #[test]
    fn current_semantic_ir_version_is_stable_and_nonzero() {
        let current = SemanticIrVersion::current();
        assert_eq!(
            current.to_string(),
            "bf73c1a83d7de89ff7d04d104295114e4142cf0b785a68d141c25df11d0532ff"
        );
        assert_ne!(current.as_bytes(), &[0_u8; 32]);
        assert_eq!(SEMANTIC_IR_SCHEMA_VERSION, 46);
    }

    fn digest(label: &str) -> StableDigest {
        StableDigest::sha256(label)
    }

    #[allow(clippy::too_many_arguments)]
    fn key(
        mount: &str,
        path: &str,
        language: SemanticLanguage,
        revision: SourceRevision,
        adapter_name: &str,
        adapter: &str,
        ir: &str,
        configuration: &str,
        dependencies: &str,
    ) -> SemanticArtifactKey {
        brokk_bifrost_analysis::test_support::semantic_artifact_key_fixture(
            mount,
            path,
            language,
            revision,
            adapter_name,
            adapter,
            ir,
            configuration,
            dependencies,
        )
    }

    #[test]
    fn procedure_environment_ignores_mount_and_revision_only() {
        let disk = |content: &str| SourceRevision::Disk {
            content: ContentIdentity::from_digest(digest(content)),
        };
        let base = key(
            "mount-a",
            "src/main.ts",
            SemanticLanguage::Standard(Language::TypeScript),
            disk("content-a"),
            "typescript",
            "adapter-a",
            "ir-a",
            "config-a",
            "deps-a",
        );
        let sibling_edit = key(
            "mount-b",
            "src/main.ts",
            base.language(),
            disk("content-b"),
            "typescript",
            "adapter-a",
            "ir-a",
            "config-a",
            "deps-a",
        );
        assert_eq!(
            base.procedure_environment_fingerprint(),
            sibling_edit.procedure_environment_fingerprint()
        );
        let changed_adapter = key(
            "mount-b",
            "src/main.ts",
            base.language(),
            disk("content-b"),
            "typescript",
            "adapter-b",
            "ir-a",
            "config-a",
            "deps-a",
        );
        assert_ne!(
            base.procedure_environment_fingerprint(),
            changed_adapter.procedure_environment_fingerprint()
        );

        let declaration = |start_byte, name: &str| {
            let span = SourceSpan::new(
                SourcePosition::new(start_byte, 1, 0),
                SourcePosition::new(start_byte + 10, 1, 10),
            )
            .unwrap();
            DeclarationLocator::new(vec![
                DeclarationSegment::named(
                    DeclarationSegmentKind::Function,
                    name,
                    SourceAnchor::new(span, 0),
                    0,
                )
                .unwrap(),
            ])
            .unwrap()
        };
        let base_declaration = declaration(10, "wrapper");
        let moved_declaration = declaration(100, "wrapper");
        assert_eq!(
            base.procedure_lineage_fingerprint(&base_declaration),
            sibling_edit.procedure_lineage_fingerprint(&moved_declaration),
            "mount, revision, and absolute declaration anchor are excluded"
        );
        assert_ne!(
            base.procedure_lineage_fingerprint(&base_declaration),
            sibling_edit.procedure_lineage_fingerprint(&declaration(100, "renamed")),
            "declaration shape remains part of the lineage"
        );
        assert_ne!(
            base.procedure_lineage_fingerprint(&base_declaration),
            changed_adapter.procedure_lineage_fingerprint(&moved_declaration),
            "semantic environment remains part of the lineage"
        );
    }

    #[test]
    fn semantic_locator_distinguishes_duplicate_paths_across_mounts() {
        let span =
            SourceSpan::new(SourcePosition::new(0, 0, 0), SourcePosition::new(1, 0, 1)).unwrap();
        let anchor = SourceAnchor::new(span, 0);
        let declaration = || {
            DeclarationLocator::new(vec![
                DeclarationSegment::named(DeclarationSegmentKind::Function, "run", anchor, 0)
                    .unwrap(),
            ])
            .unwrap()
        };
        let locator = |mount: &str| {
            SemanticLocator::new(
                WorkspaceMountId::hash_bytes(mount),
                WorkspaceRelativePath::new("src/main.ts").unwrap(),
                SemanticLanguage::Standard(Language::TypeScript),
                declaration(),
                SemanticRole::Procedure,
                anchor,
            )
        };

        assert_ne!(locator("mount-a"), locator("mount-b"));
    }

    #[test]
    fn procedure_local_locator_identity_survives_preceding_source_movement() {
        fn locator(
            mount: &str,
            procedure_start: u32,
            local_start: u32,
        ) -> (SemanticLocator, SemanticLocator) {
            let span = |start: u32, end: u32| {
                SourceAnchor::new(
                    SourceSpan::new(
                        SourcePosition::new(start, 0, start),
                        SourcePosition::new(end, 0, end),
                    )
                    .unwrap(),
                    0,
                )
            };
            let procedure_anchor = span(procedure_start, procedure_start + 40);
            let declaration = DeclarationLocator::new(vec![
                DeclarationSegment::named(
                    DeclarationSegmentKind::Function,
                    "leaf",
                    procedure_anchor,
                    0,
                )
                .unwrap(),
            ])
            .unwrap();
            let make = |role, anchor| {
                SemanticLocator::new(
                    WorkspaceMountId::hash_bytes(mount),
                    WorkspaceRelativePath::new("src/main.ts").unwrap(),
                    SemanticLanguage::Standard(Language::TypeScript),
                    declaration.clone(),
                    role,
                    anchor,
                )
            };
            (
                make(SemanticRole::Procedure, procedure_anchor),
                make(SemanticRole::Value, span(local_start, local_start + 5)),
            )
        }

        let (first_procedure, first_value) = locator("first", 10, 22);
        let (shifted_procedure, shifted_value) = locator("second", 110, 122);
        let mut first = LengthDelimitedDigest::new(b"test-procedure-local-locator");
        first_value.push_procedure_local_identity(&mut first, &first_procedure);
        let mut shifted = LengthDelimitedDigest::new(b"test-procedure-local-locator");
        shifted_value.push_procedure_local_identity(&mut shifted, &shifted_procedure);
        let first = first.finish();
        assert_eq!(first, shifted.finish());

        let (_, changed_value) = locator("second", 110, 123);
        let mut changed = LengthDelimitedDigest::new(b"test-procedure-local-locator");
        changed_value.push_procedure_local_identity(&mut changed, &shifted_procedure);
        assert_ne!(first, changed.finish());

        let mut first = LengthDelimitedDigest::new(b"test-procedure-lineage-locator");
        first_procedure.push_anchor_free_procedure_declaration_identity(&mut first);
        let mut shifted = LengthDelimitedDigest::new(b"test-procedure-lineage-locator");
        shifted_procedure.push_anchor_free_procedure_declaration_identity(&mut shifted);
        assert_eq!(
            first.finish(),
            shifted.finish(),
            "procedure lineage excludes mount and source anchors"
        );
    }
}
