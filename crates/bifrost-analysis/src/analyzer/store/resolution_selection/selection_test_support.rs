use super::*;
use crate::analyzer::store_bridge::AnalyzerStoreEngineExt;

use crate::analyzer::ProjectFile;

use crate::analyzer::java::JavaAdapter;

use crate::analyzer::store::file_state::FileState;
use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;
use crate::analyzer::tree_sitter_analyzer::ParsedFile;
use crate::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

use tree_sitter::Parser;

pub(super) const WORKSPACE_ID: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub fn parsed_fixture_state<A: LanguageAdapter>(
    adapter: &A,
    relative_path: &str,
    source: &str,
) -> FileState {
    let file = ProjectFile::new(
        std::env::current_dir()
            .expect("resolve selection fixture root")
            .join("selected-resolution-context-does-not-touch-disk"),
        relative_path,
    );
    let mut parser = Parser::new();
    parser
        .set_language(&adapter.parser_language_for_file(&file))
        .expect("configure fixture grammar");
    let tree = parser.parse(source, None).expect("parse fixture source");
    let mut parsed: ParsedFile = adapter.parse_file(&file, source, &tree);
    parsed.add_file_scope(&file, source);
    let contains_tests = adapter.contains_tests(&file, source, &tree, &parsed);
    TreeSitterAnalyzer::<A>::file_state_from_parsed(
        source.to_owned(),
        parsed,
        contains_tests,
        Some(Vec::new()),
        true,
    )
}
#[doc(hidden)]
pub fn write_fixture_blob(
    store: &AnalyzerStore,
    oid: &str,
    storage_language: &str,
    semantic_language: Language,
    generation: GenerationId,
) {
    let (relative_path, source) = match semantic_language {
        Language::Java => ("src/Model.java", "package demo; class Model {}\n"),

        _ => panic!("selection fixture adapter is not defined for {semantic_language:?}"),
    };
    let result = match semantic_language {
        Language::Java => {
            let state = parsed_fixture_state(&JavaAdapter, relative_path, source);
            store.write_parsed_blob_at_generation(
                &crate::analyzer::store::test_blob_file(),
                Oid::from_str(oid).unwrap(),
                storage_language,
                generation,
                &JavaAdapter,
                &state,
            )
        }

        _ => unreachable!(),
    };
    result.expect("persist selected-resolution fixture blob");
}
#[doc(hidden)]
pub struct SelectionFixture {
    #[doc(hidden)]
    pub store: AnalyzerStore,
    #[doc(hidden)]
    pub workspace_id: WorkspaceId,
    pub(super) snapshots: WorkspaceSnapshots,
    pub(super) storage_language: String,
    pub(super) semantic_language: Language,
}
impl SelectionFixture {
    pub(in crate::analyzer::store) fn retain_one_reader(&mut self) {
        self.store.active_readers.capacity = 1;
    }

    pub(super) fn content_witness(
        &self,
        oid: &str,
    ) -> crate::analyzer::store::resolution_publication::ResolutionContentWitness {
        use crate::analyzer::store::resolution_publication::{
            ResolutionContentInput, ResolutionContentPublicationOutcome,
        };
        let oid = Oid::from_str(oid).unwrap();
        let outcome = self
            .store
            .admit_cached_selected_content(
                &self.snapshots[&self.storage_language],
                "src/cached.java",
                oid,
                &ResolutionContentInput::Parsed {
                    content_oid: oid,
                    semantic_language: self.semantic_language,
                },
                &CancellationToken::default(),
            )
            .unwrap();
        let ResolutionContentPublicationOutcome::Ready(content) = outcome else {
            panic!("real fixture publication: {outcome:?}");
        };
        content.into_parts().0
    }

    #[doc(hidden)]
    pub fn new(mount_count: usize) -> Self {
        Self::with_language(mount_count, "java", Language::Java, false)
    }

    #[doc(hidden)]
    pub fn shared_blob(mount_count: usize) -> Self {
        Self::with_language(mount_count, "java", Language::Java, true)
    }

    #[doc(hidden)]
    pub fn custom_source(mount_count: usize, source: &str) -> Self {
        Self::custom_language_source(mount_count, source, "java", Language::Java)
    }

    pub(super) fn custom_language_source(
        mount_count: usize,
        source: &str,
        storage_language: &str,
        semantic_language: Language,
    ) -> Self {
        Self::with_store(
            AnalyzerStore::open_ephemeral().unwrap(),
            mount_count,
            storage_language,
            semantic_language,
            false,
            false,
            Some(source),
        )
    }

    pub(super) fn bootstrap(mount_count: usize) -> Self {
        Self::with_authority(mount_count, "java", Language::Java, false, true)
    }

    pub fn with_language(
        mount_count: usize,
        storage_language: &str,
        semantic_language: Language,
        shared_blob: bool,
    ) -> Self {
        Self::with_authority(
            mount_count,
            storage_language,
            semantic_language,
            shared_blob,
            false,
        )
    }

    pub(super) fn with_authority(
        mount_count: usize,
        storage_language: &str,
        semantic_language: Language,
        shared_blob: bool,
        bootstrap: bool,
    ) -> Self {
        Self::with_store(
            AnalyzerStore::open_ephemeral().unwrap(),
            mount_count,
            storage_language,
            semantic_language,
            shared_blob,
            bootstrap,
            None,
        )
    }

    pub(super) fn persistent(mount_count: usize) -> (tempfile::TempDir, Self) {
        let temp = tempfile::tempdir().unwrap();
        let store = AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap();
        let fixture = Self::with_store(
            store,
            mount_count,
            "java",
            Language::Java,
            false,
            false,
            None,
        );
        (temp, fixture)
    }

    pub(super) fn with_store(
        store: AnalyzerStore,
        mount_count: usize,
        storage_language: &str,
        semantic_language: Language,
        shared_blob: bool,
        bootstrap: bool,
        source: Option<&str>,
    ) -> Self {
        Self::with_blob_writer(
            store,
            mount_count,
            storage_language,
            semantic_language,
            shared_blob,
            bootstrap,
            |store, oid, storage_language, semantic_language, generation| {
                if let Some(source) = source {
                    let result = match semantic_language {
                        Language::Java => {
                            let state =
                                parsed_fixture_state(&JavaAdapter, "src/Model.java", source);
                            store.write_parsed_blob_at_generation(
                                &crate::analyzer::store::test_blob_file(),
                                Oid::from_str(oid).unwrap(),
                                storage_language,
                                generation,
                                &JavaAdapter,
                                &state,
                            )
                        }
                        _ => panic!(
                            "custom selection fixture adapter is not defined for {semantic_language:?}"
                        ),
                    };
                    result.expect("persist custom selected-resolution fixture blob");
                } else {
                    write_fixture_blob(store, oid, storage_language, semantic_language, generation);
                }
            },
        )
    }

    #[doc(hidden)]
    pub fn with_blob_writer(
        store: AnalyzerStore,
        mount_count: usize,
        storage_language: &str,
        semantic_language: Language,
        shared_blob: bool,
        bootstrap: bool,
        write_blob: impl Fn(&AnalyzerStore, &str, &str, Language, GenerationId),
    ) -> Self {
        let generation = if bootstrap {
            GenerationId::BOOTSTRAP
        } else {
            store
                .ensure_language_epoch_value(storage_language, "selection-test-v1")
                .unwrap()
        };
        store
            .ensure_resolution_producer_epoch(storage_language, semantic_language)
            .unwrap();
        let workspace_id = WorkspaceId(WORKSPACE_ID.to_owned());
        let storage_language_owned = storage_language.to_owned();
        let blob_count = if shared_blob && mount_count > 0 {
            1
        } else {
            mount_count
        };
        let blob_oids = (0..blob_count)
            .map(|index| format!("{:040x}", index + 1))
            .collect::<Vec<_>>();
        let writer_workspace_id = workspace_id.as_str().to_owned();
        let writer_language = storage_language_owned.clone();
        let writer_blob_oids = blob_oids.clone();
        store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                     VALUES(?1, ?2, ?3, 1)",
                params![writer_workspace_id, writer_language, generation.0],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_heads(workspace_id, lang, generation, revision)
                     VALUES(?1, ?2, ?3, 1)",
                params![writer_workspace_id, writer_language, generation.0],
            )
            .unwrap();
            for index in 0..mount_count {
                let oid = if shared_blob {
                    &writer_blob_oids[0]
                } else {
                    &writer_blob_oids[index]
                };
                tx.execute(
                    "INSERT INTO workspace_file_versions(
                           workspace_id, lang, generation, rel_path, blob_oid,
                           projection_digest, valid_from
                         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1)",
                    params![
                        writer_workspace_id,
                        writer_language,
                        generation.0,
                        match semantic_language {
                            Language::Rust => format!("src/{index:04}.rs"),
                            _ => format!("src/{index:04}.java"),
                        },
                        oid,
                        format!("{:064x}", index + 1),
                    ],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        });

        for oid in &blob_oids {
            write_blob(&store, oid, storage_language, semantic_language, generation);
        }

        let mut snapshots = WorkspaceSnapshots::default();
        snapshots.insert(
            storage_language_owned.clone(),
            WorkspaceSnapshotId {
                workspace_id: workspace_id.clone(),
                lang: storage_language_owned.clone(),
                generation,
                revision: 1,
            },
        );
        Self {
            store,
            workspace_id,
            snapshots,
            storage_language: storage_language_owned,
            semantic_language,
        }
    }

    #[doc(hidden)]
    pub fn language(&self) -> SelectedResolutionLanguage {
        SelectedResolutionLanguage::new(self.storage_language.clone(), self.semantic_language)
    }

    pub fn open_ready<'a>(
        &'a self,
        masks: &[SelectedResolutionOverlayMask],
    ) -> Box<SelectedResolutionMountInventory<'a>> {
        match self
            .store
            .open_selected_resolution_mount_inventory(
                &self.workspace_id,
                &self.snapshots,
                &[self.language()],
                masks,
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(ready) => ready,
            _ => panic!("complete fixture must open Ready"),
        }
    }
}
