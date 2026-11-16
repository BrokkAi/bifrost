//! Configuration-only answers for targets whose existence the selection proved.
use brokk_bifrost_analysis::analyzer::derivation_host;
use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_core::allocation_size::allocation_size;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_core::retention_budget::RetainedBytes;
use brokk_bifrost_rust::cargo_config::{
    RustCargoConfigDocument, RustCargoConfiguration, is_cargo_configuration_path,
};
use brokk_bifrost_rust::selected_context::{
    RustCallerTargetKind, RustSelectedManifestMount, RustTargetConfiguration,
    rust_target_configuration,
};
use brokk_bifrost_semantic::analyzer::semantic::derivation::*;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RustUnitConfigurationKey {
    pub manifest_path: String,
    pub target_kind: String,
    pub target_name: String,
}

impl RetainedBytes for RustUnitConfigurationKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + allocation_size(self.manifest_path.capacity())
            + allocation_size(self.target_kind.capacity())
            + allocation_size(self.target_name.capacity())
    }
}

fn target_kind(kind: &str) -> Option<RustCallerTargetKind> {
    Some(match kind {
        "lib" => RustCallerTargetKind::Library,
        "bin" => RustCallerTargetKind::Binary,
        "test" => RustCallerTargetKind::Test,
        "example" => RustCallerTargetKind::Example,
        "bench" => RustCallerTargetKind::Bench,
        "build" => RustCallerTargetKind::Build,
        _ => return None,
    })
}

#[derive(Clone, Debug)]
pub struct RustUnitConfigurationFacts(pub RustTargetConfiguration);
impl RetainedBytes for RustUnitConfigurationFacts {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self
                .0
                .cfg_atoms
                .iter()
                .chain(&self.0.features)
                .chain(&self.0.extern_names)
                .map(|s| {
                    allocation_size(s.capacity())
                        + std::mem::size_of::<String>()
                        + 4 * std::mem::size_of::<usize>()
                })
                .sum::<usize>()
    }
}

pub struct RustUnitConfiguration;
impl DerivationKind for RustUnitConfiguration {
    type Key = RustUnitConfigurationKey;
    type Output = RustUnitConfigurationFacts;
    const ID: DerivationKindId = DerivationKindId("derivation:rust_unit_configuration:v1");
    const QUESTION_SHAPE:
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily =
        brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::new(
            Self::ID,
            true,
            false,
            true,
            true,
        );
    const STRATUM: u16 = 0;
    const VERIFY: Verification = Verification::Recompute;
    const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
    fn question(key: &Self::Key) -> DerivationQuestion {
        DerivationQuestion {
            language: Some(Language::Rust),
            subject: None,
            rel_path: Some(key.manifest_path.clone().into()),
            name: Some(
                serde_json::to_string(&(&key.target_kind, &key.target_name))
                    .expect("target key serializes")
                    .into(),
            ),
        }
    }
    fn key_from_question(q: &DerivationQuestion) -> Option<Self::Key> {
        if q.language != Some(Language::Rust) || q.subject.is_some() {
            return None;
        }
        let (kind, name): (String, String) = serde_json::from_str(q.name.as_deref()?).ok()?;
        target_kind(&kind)?;
        let manifest_path = q.rel_path.as_deref()?;
        if Path::new(manifest_path).file_name()? != "Cargo.toml" {
            return None;
        }
        Some(RustUnitConfigurationKey {
            manifest_path: manifest_path.into(),
            target_kind: kind,
            target_name: name,
        })
    }
    fn compute<R: DerivationRevision, A: DerivationAuthority>(
        &self,
        _: &mut DerivationFrame<'_, R, A>,
        key: &Self::Key,
    ) -> Computed<Self::Output> {
        let _scope = brokk_bifrost_core::attribution::enter_scope(
            "rust_unit_configuration",
            brokk_bifrost_core::attribution::CoverageClass::RecomputeOnCurrency,
        );
        let result = derivation_host::with_bound_inventory(|inventory| {
            if !inventory
                .proves_configuration_only_selection()
                .map_err(|error| error.to_string())?
            {
                return Ok(None);
            }
            let snapshot = derivation_host::selected_rust_snapshot(inventory)?;
            let inputs = AnalyzerStore::rust_configuration_inputs_on_connection(
                inventory.connection(),
                &snapshot,
            )
            .map_err(|e| e.to_string())?;
            configuration_from_inputs(key, &inputs).map(Some)
        });
        match result {
            Ok(None) => Computed::Unavailable(UnavailableCause::ConfigurationOverlaid),
            Ok(Some(facts)) => Computed::Available {
                complete: facts.complete,
                value: RustUnitConfigurationFacts(facts),
                validity: ReuseValidity::Reusable,
                reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
            },
            Err(error) => Computed::Unavailable(UnavailableCause::Failed(error.into())),
        }
    }
    fn output_projection(value: &Self::Output, hash: &mut CanonicalHasher) {
        let facts = &value.0;
        for (label, values) in [
            ("cfg", &facts.cfg_atoms),
            ("features", &facts.features),
            ("extern", &facts.extern_names),
        ] {
            hash.sequence(label, &values.iter().collect::<Vec<_>>(), |h, value| {
                h.value(value.as_bytes())
            });
        }
        hash.value(format!("{:?}", facts.edition).as_bytes());
        hash.value(&[u8::from(facts.rustflags_extern), u8::from(facts.complete)]);
    }
}

fn configuration_from_inputs(
    key: &RustUnitConfigurationKey,
    inputs: &[(String, String, Vec<u8>)],
) -> Result<RustTargetConfiguration, String> {
    let mut manifests = Vec::new();
    let mut config = Vec::new();
    for read in configuration_input_reads(inputs)? {
        derivation_host::with_current_analyzer(|analyzer| analyzer.record_read(read));
    }
    for (path, _, bytes) in inputs {
        let path = Path::new(path);
        if path.file_name().is_some_and(|name| name == "Cargo.toml") {
            manifests.push(RustSelectedManifestMount::from_source_bytes(
                path,
                bytes.clone().into_boxed_slice(),
            )?);
        } else if is_cargo_configuration_path(path) {
            config.push((
                PathBuf::from(path),
                RustCargoConfigDocument::from_source_bytes(bytes)?,
            ));
        }
    }
    rust_target_configuration(
        Path::new(&key.manifest_path),
        target_kind(&key.target_kind).ok_or("invalid target kind")?,
        manifests,
        &RustCargoConfiguration::from_files(config),
    )
}

/// The complete recorded read set; the input golden uses this same boundary.
fn configuration_input_reads(
    inputs: &[(String, String, Vec<u8>)],
) -> Result<Vec<brokk_bifrost_analysis::analyzer::ReadKey>, String> {
    inputs.iter().map(|(path, oid, _)| {
        assert!(brokk_bifrost_analysis::analyzer::store::WorkspaceConfigurationInput::is_native_input(Language::Rust, Path::new(path)));
        let oid = git2::Oid::from_str(oid).map_err(|e| e.to_string())?;
        Ok(brokk_bifrost_analysis::analyzer::ReadKey::file(Language::Rust, path.clone(), oid, brokk_bifrost_core::gitblob::ParseVariant::Empty))
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::CodeUnitIndex;
    use brokk_bifrost_analysis::analyzer::derivation_host::AnalyzerDerivations;
    use brokk_bifrost_analysis::analyzer::resolve_analyzer;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
        SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
    };
    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_core::retention_budget::RetentionBudget;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#12304: local glob proof on a narrowed operation added persistence refusals")]
    fn certified_local_glob_bridge_reuses_and_refuses_changed_target() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::{
            AnalyzerQueryScope, IAnalyzer, capture_query_reads,
        };
        use brokk_bifrost_rust::graph_support::RustGlobNameAbsence;
        use std::collections::HashSet;
        let source = "mod exports;\nuse crate::exports::*;\npub fn consume(_: &str) {}\n";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname=\"glob_bridge\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file("src/lib.rs", source)
            .file("src/exports.rs", "pub struct Other;\n")
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let analyzer =
            resolve_analyzer::<super::super::RustAnalyzer>(workspace.analyzer()).unwrap();
        let cancellation = CancellationToken::default();
        let _outer = AnalyzerQueryScope::new(analyzer);
        let snapshots = analyzer.inner.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
        let input = SelectedResolutionOperationInput::new(
            analyzer.project(),
            analyzer.inner.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &[],
        );
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
            .analyzer_store()
            .open_selected_resolution_operation(input, &cancellation)
            .unwrap()
        else {
            panic!("operation unavailable");
        };
        let keys = operation
            .rust_crate_keys_for_file(Path::new("src/lib.rs"), &cancellation)
            .unwrap();
        assert!(!keys.is_empty());
        let key = (
            "src/lib.rs".to_owned(),
            serde_json::to_string(&(
                source.find("use crate").unwrap(),
                ["crate", "exports"],
                "type",
                "str",
            ))
            .unwrap(),
        );
        operation.with_rust_forward_crate_scope(&keys,&cancellation,|operation| {
            analyzer.operation_read_frame(operation)
        }, || {
            assert!(!operation.ready.inventory.reader_binding()?.proves_main_selection());
            let read = || analyzer.local_glob_name_absence_question(&key).expect("certified local-glob bridge");
            let (cold, first) = capture_query_reads(analyzer,read);
            assert_eq!(cold,RustGlobNameAbsence::ClosedAbsent);
            assert_eq!(first.persistence_refusals(),0,"{:?}",first.keys());
            assert_eq!(first.execution_dependences(),0,"{:?}",first.keys());
            let first_keys = first.publishable_keys().expect("local-glob receipt is publishable").into_iter().collect::<HashSet<_>>();
            let kind = super::super::route_kinds::RustLocalGlobNameAbsence::ID;
            let host = analyzer.inner.derivations().unwrap();
            let before = host.counters(kind);
            let (warm,second) = capture_query_reads(analyzer,read);
            assert_eq!(warm,cold);
            assert_eq!(second.persistence_refusals(),0,"{:?}",second.keys());
            assert_eq!(second.execution_dependences(),0,"{:?}",second.keys());
            assert_eq!(first_keys,second.publishable_keys().unwrap().into_iter().collect::<HashSet<_>>());
            let after = host.counters(kind);
            assert!(after.current_hits+after.verified_unchanged > before.current_hits+before.verified_unchanged,
                "unchanged question must reuse its recorded answer: {before:?} -> {after:?}");
            let changed = git2::Oid::hash_object(git2::ObjectType::Blob,b"pub struct Other;\npub struct str;\n").unwrap();
            operation.ready.inventory.with_owned_temp_write(|conn| {
                conn.execute("INSERT INTO temp.selected_resolution_content_mounts(storage_language,generation,persisted_relative_path,blob_oid,publication_digest,projection_digest) VALUES('rust',?1,'src/exports.rs',?2,zeroblob(32),zeroblob(32))",rusqlite::params![snapshots.get("rust").unwrap().generation.get(),changed.to_string()])?;
                Ok(())
            })?;
            assert!(analyzer.local_glob_name_absence_question(&key).is_err(),"changed target cannot borrow Main absence");
            Ok(())
        }).unwrap();
    }

    #[test]
    #[hardwon(
        "#12304: an overlay outside the glob's closure refused the name-absence question that a fresh analysis answers"
    )]
    fn local_glob_bridge_answers_across_an_overlay_outside_its_closure() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
        use brokk_bifrost_rust::graph_support::RustGlobNameAbsence;
        const UNRELATED: &str = "pub fn unrelated() {}\n";
        const EDITED: &str = "pub fn unrelated() { let _ = 1; }\n";
        const EXPORTS: &str = "pub struct Other;\n";
        // Crate `b` is a workspace member that neither imports nor is imported
        // by `a`, so no file of `b` is in the closure of the glob in `a`.
        let answer = |unrelated: &str, overlay: Option<(&str, &str)>| {
            let source = "mod exports;\nuse crate::exports::*;\npub fn consume(_: &str) {}\n";
            let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[workspace]\nmembers=['a','b']\nresolver='2'\n",
                )
                .file(
                    "a/Cargo.toml",
                    "[package]\nname=\"glob_a\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
                )
                .file("a/src/lib.rs", source)
                .file("a/src/exports.rs", EXPORTS)
                .file(
                    "b/Cargo.toml",
                    "[package]\nname=\"glob_b\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
                )
                .file("b/src/lib.rs", unrelated)
                .build();
            let workspace = project.certified_workspace_analyzer(Default::default());
            let analyzer =
                resolve_analyzer::<super::super::RustAnalyzer>(workspace.analyzer()).unwrap();
            let cancellation = CancellationToken::default();
            let _outer = AnalyzerQueryScope::new(analyzer);
            let snapshots = analyzer.inner.selected_workspace_snapshots();
            let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
            let input = SelectedResolutionOperationInput::new(
                analyzer.project(),
                analyzer.inner.workspace_id(),
                snapshots.as_ref(),
                &languages,
                &[],
            );
            let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
                .analyzer_store()
                .open_selected_resolution_operation(input, &cancellation)
                .unwrap()
            else {
                panic!("operation unavailable");
            };
            let keys = operation
                .rust_crate_keys_for_file(Path::new("a/src/lib.rs"), &cancellation)
                .unwrap();
            assert!(!keys.is_empty());
            let key = (
                "a/src/lib.rs".to_owned(),
                serde_json::to_string(&(
                    source.find("use crate").unwrap(),
                    ["crate", "exports"],
                    "type",
                    "str",
                ))
                .unwrap(),
            );
            let mut result = None;
            operation
                .with_rust_forward_crate_scope(&keys, &cancellation, |operation| {
                    analyzer.operation_read_frame(operation)
                }, || {
                    if let Some((path, content)) = overlay {
                        let changed =
                            git2::Oid::hash_object(git2::ObjectType::Blob, content.as_bytes())
                                .unwrap();
                        operation.ready.inventory.with_owned_temp_write(|conn| {
                            conn.execute("INSERT INTO temp.selected_resolution_content_mounts(storage_language,generation,persisted_relative_path,blob_oid,publication_digest,projection_digest) VALUES('rust',?1,?2,?3,zeroblob(32),zeroblob(32))",rusqlite::params![snapshots.get("rust").unwrap().generation.get(),path,changed.to_string()])?;
                            Ok(())
                        })?;
                    }
                    result = analyzer.local_glob_name_absence_question(&key).ok();
                    Ok(())
                })
                .unwrap();
            result
        };
        let fresh_edited = answer(EDITED, None);
        assert_eq!(fresh_edited, Some(RustGlobNameAbsence::ClosedAbsent));
        assert_eq!(
            answer(UNRELATED, Some(("b/src/lib.rs", EDITED))),
            fresh_edited,
            "an overlay of a file the glob's closure does not list agrees with a fresh analysis of the same files"
        );
        assert_eq!(
            answer(
                UNRELATED,
                Some(("a/src/exports.rs", "pub struct Other;\npub struct str;\n"))
            ),
            None,
            "an overlay of a closure file cannot borrow Main's absence"
        );
    }

    #[test]
    #[hardwon("#12015: package topology read under a narrowed frame added persistence refusals")]
    fn certified_package_topology_bridge_reuses_and_refuses_changed_inputs() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads;
        use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, IAnalyzer};
        use std::collections::HashSet;
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"package_test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub fn f() {}\n")
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let analyzer =
            resolve_analyzer::<super::super::RustAnalyzer>(workspace.analyzer()).unwrap();
        let cancellation = CancellationToken::default();
        let file = project.file("src/lib.rs");
        let _outer = AnalyzerQueryScope::new(analyzer);
        let snapshots = analyzer.inner.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
        let input = SelectedResolutionOperationInput::new(
            analyzer.project(),
            analyzer.inner.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &[],
        );
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
            .analyzer_store()
            .open_selected_resolution_operation(input, &cancellation)
            .unwrap()
        else {
            panic!("operation unavailable")
        };
        let keys = operation
            .rust_crate_keys_for_file(Path::new("src/lib.rs"), &cancellation)
            .unwrap();
        assert!(!keys.is_empty());
        operation.with_rust_forward_crate_scope(&keys, &cancellation, |operation| {
            analyzer.operation_read_frame(operation)
        }, || {
            assert!(!operation.ready.inventory.reader_binding()?.proves_main_selection());
            let read = || {
                let files = analyzer.package_view().certified_files_in_package("package_test", None).unwrap();
                let member = analyzer.package_view().certified_contains(&file, None).unwrap();
                assert!(files.complete && member.complete);
                assert!(member.value);
                assert_eq!(files.value, vec![file.clone()]);
                files.value
            };
            let (cold, first) = capture_query_reads(analyzer, read);
            assert_eq!(first.persistence_refusals(), 0, "{:?}", first.keys());
            assert_eq!(first.execution_dependences(), 0, "{:?}", first.keys());
            let first_keys = first.publishable_keys().expect("package proof must be persistable")
                .into_iter().collect::<HashSet<_>>();
            let host = analyzer.inner.derivations().unwrap();
            let kind = super::super::route_kinds::RustPackageUnits::ID;
            let before = host.counters(kind);
            let (warm, second) = capture_query_reads(analyzer, read);
            assert_eq!(cold, warm);
            assert_eq!(second.persistence_refusals(), 0, "{:?}", second.keys());
            assert_eq!(second.execution_dependences(), 0, "{:?}", second.keys());
            assert_eq!(first_keys, second.publishable_keys().unwrap().into_iter().collect::<HashSet<_>>());
            let after = host.counters(kind);
            assert_eq!(
                (before.current_hits, before.verified_unchanged, before.recomputed),
                (after.current_hits, after.verified_unchanged, after.recomputed),
                "unchanged certified package query must replay its memo, without demanding again",
            );
            // The admission gate runs before hitting that same package memo.
            // Include a non-.rs path: it is outside the old source predicate.
            for (path, source) in [
                ("src/lib.rs", "mod hidden; pub fn f() {}\n"),
                ("Cargo.toml", "[package]\nname='changed'\nversion='0.1.0'\n"),
                ("target-source.txt", "pub fn extra_root() {}\n"),
            ] {
                let oid = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
                operation.ready.inventory.with_owned_temp_write(|conn| {
                    conn.execute("INSERT OR REPLACE INTO temp.selected_resolution_content_mounts(storage_language,generation,persisted_relative_path,blob_oid,publication_digest,projection_digest) VALUES('rust',1,?1,?2,zeroblob(32),zeroblob(32))", rusqlite::params![path, oid.to_string()])?;
                    Ok(())
                })?;
                assert!(analyzer.package_view().certified_files_in_package("package_test", None).is_err(), "changed input admitted: {path}");
                assert!(analyzer.package_view().certified_contains(&file, None).is_err(), "changed input admitted: {path}");
                operation.ready.inventory.with_owned_temp_write(|conn| {
                    conn.execute("DELETE FROM temp.selected_resolution_content_mounts WHERE persisted_relative_path=?1", [path])?;
                    Ok(())
                })?;
            }
            Ok(())
        }).unwrap();
    }

    #[test]
    #[hardwon("#11825: narrowed policy units could not replay Main-only route membership")]
    fn main_route_prefill_replays_cold_scoped_configuration_and_external_calls() {
        use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, IAnalyzer, ReadLedger};
        use std::sync::Arc;
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"route_test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub fn f() {}\n")
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let analyzer =
            resolve_analyzer::<super::super::RustAnalyzer>(workspace.analyzer()).unwrap();
        let cancellation = CancellationToken::default();
        let file = brokk_bifrost_analysis::analyzer::ProjectFile::new(
            analyzer.project().root(),
            "src/lib.rs",
        );
        let _outer = AnalyzerQueryScope::new(analyzer);

        let ledger = Arc::new(ReadLedger::new());
        let _consumer = AnalyzerQueryScope::with_read_ledger(analyzer, ledger.clone());
        let snapshots = analyzer.inner.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
        let input = SelectedResolutionOperationInput::new(
            analyzer.project(),
            analyzer.inner.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &[],
        );
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
            .analyzer_store()
            .open_selected_resolution_operation(input, &cancellation)
            .unwrap()
        else {
            panic!("operation unavailable")
        };
        let keys = operation
            .rust_crate_keys_for_file(Path::new("src/lib.rs"), &cancellation)
            .unwrap();
        operation
            .with_rust_forward_crate_scope(&keys, &cancellation, |operation| {
                analyzer.operation_read_frame(operation)
            }, || {
                assert!(analyzer.file_routes(&file, None).unwrap().is_complete());
                let key = RustUnitConfigurationKey {
                    manifest_path: "Cargo.toml".into(),
                    target_kind: "lib".into(),
                    target_name: "route_test".into(),
                };
                let answer = analyzer
                    .inner
                    .derivations()
                    .unwrap()
                    .demand_in_operation::<RustUnitConfiguration>(analyzer, &operation, &key);
                assert!(matches!(
                    answer,
                    Demanded::Available {
                        value: Handle::Retained(_),
                        ..
                    }
                ));
                assert!(matches!(super::super::external_calls::selected_absolute_root(
                        analyzer,
                        &operation,
                        &file,
                        "std",
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type,
                        Some(&cancellation)
                    ), Some(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_rows::RustAbsoluteRoot::External(path)) if path == ["std"]));
                Ok(())
            })
            .unwrap();
        let reads = ledger
            .publishable_keys()
            .expect("cold narrowed consumer must publish reusable reads");
        assert!(
            reads
                .iter()
                .any(|read| format!("{read:?}").contains("rust_unit_configuration")),
            "configuration read absent: {reads:?}"
        );
    }

    #[test]
    #[hardwon("#11825: an existing Main route memo replayed under changed source or configuration")]
    fn route_content_oid_comparison_rejects_replacements_and_allows_identical_stage() {
        use brokk_bifrost_analysis::analyzer::AnalyzerQueryScope;
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"route_test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub fn f() {}\n")
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let analyzer =
            resolve_analyzer::<super::super::RustAnalyzer>(workspace.analyzer()).unwrap();
        let cancellation = CancellationToken::default();
        let file = brokk_bifrost_analysis::analyzer::ProjectFile::new(
            analyzer.project().root(),
            "src/lib.rs",
        );
        let _outer = AnalyzerQueryScope::new(analyzer);
        analyzer
            .file_routes(&file, Some(&|| !cancellation.is_cancelled()))
            .unwrap();
        let snapshots = analyzer.inner.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
        let input = SelectedResolutionOperationInput::new(
            analyzer.project(),
            analyzer.inner.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &[],
        );
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
            .analyzer_store()
            .open_selected_resolution_operation(input, &cancellation)
            .unwrap()
        else {
            panic!("operation unavailable")
        };
        let inventory = &operation.ready.inventory;
        assert!(analyzer.route_replay_content(inventory).is_ok());
        let stage_before = inventory.staged_read_epoch();
        inventory.with_owned_temp_transaction(|conn| {
            conn.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) SELECT mount_ordinal,zeroblob(32),zeroblob(32) FROM temp.selected_resolution_mounts WHERE persisted_relative_path='src/lib.rs'", [])?;
            Ok(brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction::Commit(()))
        }).unwrap();
        assert_eq!(
            inventory.staged_read_epoch(),
            stage_before,
            "producer-only metadata does not publish fact content"
        );
        let replay = analyzer.route_replay_content(inventory);
        assert!(
            replay.is_ok(),
            "same-content producer metadata must admit: {replay:?}"
        );
        let recorded = replay.unwrap();
        inventory.with_owned_temp_transaction(|conn| {
            conn.execute("DELETE FROM temp.selected_resolution_stage_producers", [])?;
            Ok(brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionTempTransaction::Commit(()))
        }).unwrap();
        assert_eq!(inventory.staged_read_epoch(), stage_before);
        assert!(
            inventory
                .selected_content_comparisons(
                    &[],
                    brokk_bifrost_rust::cargo_routes::is_rust_source_path
                )
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            analyzer.route_replay_content(inventory).unwrap(),
            recorded,
            "a disappearing producer must not erase its recorded comparison path"
        );
        let mut absent = recorded[0].clone();
        absent.path = Some("src/not-in-main.rs".into());
        let absent_rows = inventory
            .selected_content_comparisons(
                &[absent],
                brokk_bifrost_rust::cargo_routes::is_rust_source_path,
            )
            .unwrap();
        assert!(
            absent_rows
                .iter()
                .any(|row| row.main_oid.is_none() && !row.unchanged()),
            "a recorded path absent from current rows must still re-read Main: {absent_rows:?}"
        );
        let mut unknown = recorded[0].clone();
        unknown.selected_oid = None;
        let unknown_rows = inventory
            .selected_content_comparisons(
                &[unknown],
                brokk_bifrost_rust::cargo_routes::is_rust_source_path,
            )
            .unwrap();
        assert!(
            unknown_rows.iter().any(|row| !row.unchanged()),
            "recorded unknown OIDs fail closed: {unknown_rows:?}"
        );

        // An extension-style freeze overlays every selected file with its Main OID.
        inventory.with_owned_temp_write(|conn| {
            conn.execute("INSERT INTO temp.selected_resolution_content_mounts(storage_language,generation,persisted_relative_path,blob_oid,publication_digest,projection_digest) SELECT lang,generation,rel_path,blob_oid,zeroblob(32),zeroblob(32) FROM main.workspace_file_versions WHERE workspace_id=?1 AND lang='rust' AND (input_kind='source' OR file_present=1) AND valid_until IS NULL", [analyzer.inner.workspace_id().as_str()])?;

            Ok(())
        }).unwrap();
        assert!(analyzer.route_replay_content(inventory).is_ok());
        assert!(inventory.proves_configuration_only_selection().unwrap());
        assert!(
            matches!(super::super::external_calls::selected_absolute_root(
                analyzer,
                &operation,
                &file,
                "std",
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type,
                Some(&cancellation)
            ), Some(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_rows::RustAbsoluteRoot::External(path)) if path == ["std"])
        );
        // A non-Rust overlay does not change the Main route answer.
        inventory.with_owned_temp_write(|conn| {
            conn.execute("INSERT INTO temp.selected_resolution_overlay_masks(storage_language,persisted_relative_path,intent) VALUES('rust','README.md','removal')", [])?;
            Ok(())
        }).unwrap();
        assert!(
            matches!(super::super::external_calls::selected_absolute_root(
                analyzer,
                &operation,
                &file,
                "std",
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type,
                Some(&cancellation)
            ), Some(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_rows::RustAbsoluteRoot::External(path)) if path == ["std"])
        );
        for (path, source, expected) in [
            (
                "Cargo.toml",
                "[package]\nname='route_test'\nversion='0.1.0'\nedition='2015'\n",
                UnavailableCause::ConfigurationOverlaid,
            ),
            (
                "src/lib.rs",
                "mod newly_added; pub fn f() {}\n",
                UnavailableCause::RustMembershipOverlaid,
            ),
            (
                "src/added.rs",
                "pub fn added() {}\n",
                UnavailableCause::RustMembershipOverlaid,
            ),
        ] {
            let oid = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
            inventory.with_owned_temp_write(|conn| {
                conn.execute("UPDATE temp.selected_resolution_content_mounts SET blob_oid=?2 WHERE persisted_relative_path=?1", rusqlite::params![path, oid.to_string()])?;
                conn.execute("INSERT OR IGNORE INTO temp.selected_resolution_content_mounts(storage_language,generation,persisted_relative_path,blob_oid,publication_digest,projection_digest) VALUES('rust',1,?1,?2,zeroblob(32),zeroblob(32))", rusqlite::params![path,oid.to_string()])?;
                Ok(())
            }).unwrap();
            let hits_before = analyzer.walk_caches.route_memo_hits();
            assert_eq!(analyzer.route_replay_content(inventory), Err(expected));
            assert!(
                super::super::external_calls::selected_absolute_root(
                    analyzer,
                    &operation,
                    &file,
                    "std",
                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type,
                    Some(&cancellation)
                )
                .is_none()
            );
            assert_eq!(
                analyzer.walk_caches.route_memo_hits(),
                hits_before,
                "changed content must not replay the existing Main memo"
            );
            inventory.with_owned_temp_write(|conn| {
                conn.execute("DELETE FROM temp.selected_resolution_content_mounts WHERE persisted_relative_path=?1", [path])?;
                Ok(())
            }).unwrap();
        }
        // A replacement mask without a source OID cannot certify membership.
        inventory.with_owned_temp_write(|conn| {
            conn.execute("INSERT INTO temp.selected_resolution_overlay_masks(storage_language,persisted_relative_path,intent) VALUES('rust','src/lib.rs','replacement')", [])?;
            Ok(())
        }).unwrap();
        assert_eq!(
            analyzer.route_replay_content(inventory),
            Err(UnavailableCause::RustMembershipOverlaid)
        );
    }

    #[test]
    #[hardwon("#11825: narrowed policy units could not replay Main-only route membership")]
    fn route_replay_real_editor_buffers_compare_source_and_configuration_oids() {
        use brokk_bifrost_analysis::analyzer::AnalyzerQueryScope;
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome;
        use brokk_bifrost_core::analyzer::project::OverlayProject;
        use std::sync::Arc;
        let manifest =
            "[package]\nname = \"route_test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";
        let source = "pub fn f() {}\n";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", manifest)
            .file("src/lib.rs", source)
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let base = resolve_analyzer::<super::super::RustAnalyzer>(workspace.analyzer()).unwrap();
        let cancellation = CancellationToken::default();
        for (path, changed, expected) in [
            ("src/lib.rs", source, None),
            (
                "Cargo.toml",
                "[package]\nname='route_test'\nversion='0.1.0'\nedition='2015'\n",
                Some(UnavailableCause::ConfigurationOverlaid),
            ),
            (
                "src/lib.rs",
                "mod new_child; pub fn f() {}\n",
                Some(UnavailableCause::RustMembershipOverlaid),
            ),
            (
                "src/added.rs",
                "pub fn added() {}\n",
                Some(UnavailableCause::RustMembershipOverlaid),
            ),
        ] {
            let overlay = OverlayProject::new(project.project_dyn());
            assert!(overlay.set(project.file("Cargo.toml").abs_path(), manifest.to_owned()));
            assert!(overlay.set(project.file("src/lib.rs").abs_path(), source.to_owned()));
            assert!(overlay.set(project.file(path).abs_path(), changed.to_owned()));
            let analyzer = base.clone_with_project(Arc::new(overlay.snapshot()));
            let _scope = AnalyzerQueryScope::new(&analyzer);
            let inventory = match analyzer
                .open_selected_rust_inventory(&cancellation)
                .unwrap()
            {
                SelectedResolutionMountInventoryOutcome::Ready(inventory) => inventory,
                _ => panic!("editor buffer inventory unavailable for {path}"),
            };
            if path == "src/added.rs" {
                let compared = inventory
                    .selected_content_comparisons(
                        &[],
                        brokk_bifrost_rust::cargo_routes::is_rust_source_path,
                    )
                    .unwrap();
                assert!(
                    compared
                        .iter()
                        .any(|input| input.path.as_deref() == Some(path)
                            && input.main_oid.is_none()
                            && input.selected_oid.is_some()),
                    "an added buffer must have no Main source row: {compared:?}"
                );
            }
            let actual = analyzer.route_replay_content(&inventory).map(|_| ());
            assert_eq!(
                actual,
                expected.clone().map_or(Ok(()), Err),
                "buffer {path}"
            );
            if expected.is_none() {
                assert!(inventory.proves_configuration_only_selection().unwrap());
                drop(inventory);
                analyzer
                    .file_routes(
                        &project.file("src/lib.rs"),
                        Some(&|| !cancellation.is_cancelled()),
                    )
                    .unwrap();
            }
        }
    }

    thread_local! { static REPLAY_CONFIGURATION_OVERLAY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

    fn scoped_replay_opener(
        analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
        visit: &mut dyn FnMut(&brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountInventory<'_>),
    ) -> Result<(), UnavailableCause> {
        let analyzer =
            resolve_analyzer::<super::super::RustAnalyzer>(analyzer).expect("Rust replay analyzer");
        let cancellation = CancellationToken::default();
        let snapshots = analyzer.inner.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
        let input = SelectedResolutionOperationInput::new(
            analyzer.inner.project(),
            analyzer.inner.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &[],
        );
        let failed = |error: brokk_bifrost_analysis::analyzer::store::StoreError| {
            UnavailableCause::Failed(error.to_string().into())
        };
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
            .analyzer_store()
            .open_selected_resolution_operation(input, &cancellation)
            .map_err(failed)?
        else {
            return Err(UnavailableCause::ValidationFailed);
        };
        let keys = operation
            .rust_crate_keys_for_file(Path::new("src/lib.rs"), &cancellation)
            .map_err(failed)?;
        // Stamps the route recipe and visits the inventory. It asks no route
        // question, so it deliberately enters no read frame.
        operation.with_rust_forward_crate_scope(&keys, &cancellation, |_| Ok(()), || {
            let inventory = &operation.ready.inventory;
            if REPLAY_CONFIGURATION_OVERLAY.get() {
                inventory.with_owned_temp_write(|conn| {
                    conn.execute("INSERT INTO temp.selected_resolution_overlay_masks(storage_language,persisted_relative_path,intent) VALUES('rust','Cargo.toml','removal')", [])?;
                    Ok(())
                })?;
            }
            inventory.stamp_declared_rust_route_recipe();
            visit(inventory);
            Ok(())
        }).map_err(failed)
    }

    #[test]
    #[hardwon("#13102: an equal reader binding skipped live configuration File verification")]
    fn configuration_current_hits_recheck_live_files_in_one_binding() {
        use brokk_bifrost_analysis::analyzer::AnalyzerQueryScope;
        use brokk_bifrost_core::analyzer::project_reads::measure_project_io;
        let config = "[build]\nrustflags = [\"--cfg\", \"configuration_test\"]\n";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"config_test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub fn f() {}")
            .file(".cargo/config.toml", config)
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let analyzer =
            resolve_analyzer::<super::super::RustAnalyzer>(workspace.analyzer()).unwrap();
        let _scope = AnalyzerQueryScope::new(analyzer);
        let cancellation = CancellationToken::default();
        let snapshots = analyzer.inner.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
        let input = SelectedResolutionOperationInput::new(
            analyzer.project(),
            analyzer.inner.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &[],
        );
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
            .analyzer_store()
            .open_selected_resolution_operation(input, &cancellation)
            .unwrap()
        else {
            panic!("operation unavailable")
        };
        let keys = operation
            .rust_crate_keys_for_file(Path::new("src/lib.rs"), &cancellation)
            .unwrap();
        assert!(!keys.is_empty());
        let host = AnalyzerDerivations::without_declared_recipes(
            &RetentionBudget::for_test_capacity(1_000_000),
        );
        operation.with_rust_forward_crate_scope(&keys, &cancellation, |_| Ok(()), || {
            let inventory = &operation.ready.inventory;
            let _lease = inventory.derivation_read()?;
            assert!(_lease.is_some());
            let binding = inventory.reader_binding()?;
            let key = RustUnitConfigurationKey {
                manifest_path: "Cargo.toml".into(),
                target_kind: "lib".into(),
                target_name: "config_test".into(),
            };
            let demand = || host.demand_in_operation::<RustUnitConfiguration>(analyzer, &operation, &key);
            assert!(matches!(demand(), Demanded::Available { value: Handle::Retained(_), .. }));
            let before = host.counters(RustUnitConfiguration::ID);
            let snapshot = derivation_host::selected_rust_snapshot(inventory).unwrap();
            let inputs = AnalyzerStore::rust_configuration_inputs_on_connection(inventory.connection(), &snapshot)?;
            assert!(inputs.iter().any(|(path, _, _)| path == ".cargo/config.toml"));
            let expected_bytes: usize = inputs.iter().map(|(_, _, bytes)| bytes.len()).sum();
            let (answer, io) = measure_project_io(demand);
            assert!(matches!(answer, Demanded::Available { value: Handle::Retained(_), .. }));
            let warm = host.counters(RustUnitConfiguration::ID);
            assert_eq!(warm.current_hits, before.current_hits + 1);
            assert_eq!(warm.recomputed, before.recomputed);
            assert_eq!(io.source_reads, inputs.len(), "{io:?}; inputs={inputs:?}");
            std::fs::write(analyzer.project().root().join(".cargo/config.toml"), config).unwrap();
            assert_eq!(inventory.reader_binding()?, binding);
            let (answer, equal_io) = measure_project_io(demand);
            assert!(matches!(answer, Demanded::Available { value: Handle::Retained(_), .. }));
            let equal = host.counters(RustUnitConfiguration::ID);
            assert_eq!(equal.current_hits, warm.current_hits + 1);
            assert_eq!(equal.recomputed, warm.recomputed);
            assert_eq!(equal_io.source_reads, inputs.len(), "{equal_io:?}; inputs={inputs:?}");
            println!("config_test: verified_hits=2, inputs_per_hit={}, bytes_per_hit={expected_bytes}, live_file_checks={}, verified_input_bytes={}", inputs.len(), io.source_reads + equal_io.source_reads, 2 * expected_bytes);

            // A disk-only change moves neither selected SQL nor the read lease.
            std::fs::write(analyzer.project().root().join(".cargo/config.toml"), "[build]\nrustflags = [\"--cfg\", \"changed_configuration\"]\n").unwrap();
            assert_eq!(inventory.reader_binding()?, binding);
            let (answer, changed_io) = measure_project_io(demand);
            assert!(matches!(answer, Demanded::Available { .. }));
            assert!(changed_io.source_reads > 0);
            let changed = host.counters(RustUnitConfiguration::ID);
            assert_eq!(changed.current_hits, equal.current_hits);
            assert_eq!(changed.recomputed, equal.recomputed + 1);
            assert_eq!(inventory.reader_binding()?, binding);
            // Recompute still reads the pinned SQL snapshot. Its output may be
            // identical, but it cannot mint a current proof for stale file OIDs.
            assert!(matches!(demand(), Demanded::Available { .. }));
            assert_eq!(host.counters(RustUnitConfiguration::ID).recomputed, changed.recomputed + 1);
            Ok(())
        }).unwrap();
    }

    // Real selected operation, narrowed by the same scope guard as policy consumers.
    fn scoped_configuration_case(path: &str, reusable: bool) {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"config_test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "pub fn f() {}")
            .file("build.rs", "fn main() {}")
            .file("Cargo.lock", "version = 3\n")
            .file(
                ".cargo/config.toml",
                "[build]\nrustflags = [\"--cfg\", \"configuration_test\"]\n",
            )
            .build();
        let workspace = project.certified_workspace_analyzer(Default::default());
        let analyzer =
            resolve_analyzer::<super::super::RustAnalyzer>(workspace.analyzer()).unwrap();
        let cancellation = CancellationToken::default();
        let snapshots = analyzer.inner.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
        let input = SelectedResolutionOperationInput::new(
            analyzer.inner.project(),
            analyzer.inner.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &[],
        );
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
            .analyzer_store()
            .open_selected_resolution_operation(input, &cancellation)
            .unwrap()
        else {
            panic!("operation unavailable")
        };
        let keys = operation
            .rust_crate_keys_for_file(Path::new("src/lib.rs"), &cancellation)
            .unwrap();
        assert!(!keys.is_empty());
        let host = AnalyzerDerivations::without_declared_recipes(
            &RetentionBudget::for_test_capacity(1_000_000),
        );
        host.register_declared_route_recipe_opener(Language::Rust, scoped_replay_opener);
        // Holds its own derivation-read lease and then demands configuration.
        // It asks no route question, so it deliberately enters no read frame.
        operation.with_rust_forward_crate_scope(&keys, &cancellation, |_| Ok(()), || {
            let inventory = &operation.ready.inventory;
            let _lease = inventory.derivation_read()?;
            assert!(!inventory.reader_binding()?.proves_main_selection(), "test must be scoped");
            inventory.stamp_declared_rust_route_recipe();
            let membership = operation.rust_file_configuration_targets(Path::new("src/lib.rs"), &cancellation)?;
            assert!(!membership.targets.is_empty());
            assert!(membership.targets.iter().all(|target| target.cfg_authority == brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::RustCfgAuthority::IncompleteBuildScript));
            let key = RustUnitConfigurationKey { manifest_path: "Cargo.toml".into(), target_kind: "lib".into(), target_name: "config_test".into() };
            let answer = host.demand_in_operation::<RustUnitConfiguration>(analyzer, &operation, &key);
            assert!(matches!(answer, Demanded::Available { value: Handle::Retained(_), .. }));
            let mut hashed_inputs = Vec::new();
            let snapshot = derivation_host::selected_rust_snapshot(inventory).unwrap();
            let inputs = AnalyzerStore::rust_configuration_inputs_on_connection(inventory.connection(), &snapshot)?;
            for read in configuration_input_reads(&inputs).unwrap() {
                if let brokk_bifrost_analysis::analyzer::ReadKey::File { rel_path, blob, .. } = read {
                    assert!(brokk_bifrost_analysis::analyzer::store::WorkspaceConfigurationInput::is_native_input(Language::Rust, Path::new(rel_path.as_ref())));
                    hashed_inputs.push(format!("{rel_path} {blob}"));
                }
            }
            hashed_inputs.sort();
            let actual = format!("{}\n", hashed_inputs.join("\n"));
            let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unit-configuration/expected.txt");
            if std::env::var_os("BIFROST_BLESS").is_some_and(|value| value == "1") { std::fs::write(&golden, &actual).unwrap(); }
            assert_eq!(std::fs::read_to_string(golden).unwrap(), actual, "configuration input golden");
            inventory.with_owned_temp_write(|conn| {
                if path == ".cargo/config.toml" {
                    let changed = git2::Oid::hash_object(git2::ObjectType::Blob, b"[build]\nrustflags = [\"--cfg\", \"changed_configuration\"]\n").unwrap();
                    conn.execute("INSERT INTO temp.selected_resolution_content_mounts(storage_language,generation,persisted_relative_path,blob_oid,publication_digest,projection_digest) VALUES('rust',?1,?2,?3,zeroblob(32),zeroblob(32))", rusqlite::params![snapshot.generation.get(), path, changed.to_string()])?;
                } else {
                    conn.execute("INSERT INTO temp.selected_resolution_overlay_masks(storage_language,persisted_relative_path,intent) VALUES('rust',?1,'removal')", [path])?;
                }
                Ok(())
            })?;
            inventory.stamp_declared_rust_route_recipe();
            let binding = inventory.reader_binding()?;
            assert_eq!(inventory.proves_configuration_route_recipe(&binding), reusable);
            let answer = host.demand_in_operation::<RustUnitConfiguration>(analyzer, &operation, &key);
            if reusable {
                assert!(matches!(answer, Demanded::Available { value: Handle::Retained(_), .. }));
            } else {
                assert!(matches!(answer, Demanded::Unavailable(UnavailableCause::ConfigurationOverlaid)), "configuration overlays must not return stale configuration");
            }
            Ok(())
        }).unwrap();
        drop(operation);
        let key = RustUnitConfigurationKey {
            manifest_path: "Cargo.toml".into(),
            target_kind: "lib".into(),
            target_name: "config_test".into(),
        };
        use brokk_bifrost_analysis::analyzer::derivation_host::ReplayResult;
        REPLAY_CONFIGURATION_OVERLAY.set(false);
        assert!(matches!(
            host.replay(
                analyzer,
                RustUnitConfiguration::ID,
                &RustUnitConfiguration::question(&key)
            ),
            ReplayResult::Identity(_)
        ));
        REPLAY_CONFIGURATION_OVERLAY.set(true);
        let replay = host.replay(
            analyzer,
            RustUnitConfiguration::ID,
            &RustUnitConfiguration::question(&key),
        );
        REPLAY_CONFIGURATION_OVERLAY.set(false);
        assert!(
            matches!(replay, ReplayResult::Missing(_)),
            "new configuration overlay must refuse replay"
        );
    }

    #[test]
    #[hardwon("#11825: scoped operations refused configuration-only derivations as UnprovedStage")]
    fn scoped_source_overlay_reuses_configuration() {
        scoped_configuration_case("src/lib.rs", true);
    }
    #[test]
    #[hardwon("#11825: scoped operations refused configuration-only derivations as UnprovedStage")]
    fn scoped_manifest_overlay_refuses_configuration() {
        scoped_configuration_case("Cargo.toml", false);
    }
    #[test]
    #[hardwon("#11825: scoped operations refused configuration-only derivations as UnprovedStage")]
    fn scoped_cargo_config_overlay_refuses_configuration() {
        scoped_configuration_case(".cargo/config", false);
    }
    #[test]
    #[hardwon("#11825: scoped operations refused configuration-only derivations as UnprovedStage")]
    fn scoped_cargo_config_toml_overlay_refuses_configuration() {
        scoped_configuration_case(".cargo/config.toml", false);
    }
    #[test]
    #[hardwon("#11825: scoped operations refused configuration-only derivations as UnprovedStage")]
    fn scoped_build_script_cfg_is_incomplete() {
        scoped_configuration_case("src/lib.rs", true);
    }
    #[test]
    #[hardwon("#11825: scoped operations refused configuration-only derivations as UnprovedStage")]
    fn scoped_replay_new_configuration_overlay_refuses() {
        scoped_configuration_case("src/lib.rs", true);
    }
}
