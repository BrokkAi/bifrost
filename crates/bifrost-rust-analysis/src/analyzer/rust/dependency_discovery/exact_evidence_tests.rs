mod exact_evidence_tests {
    use super::*;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13320: exact presence guard retained a second full metadata tree"
    )]
    fn exact_presence_skips_large_ignored_values_without_document_allocation() {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::heap_pin::heap_pin_peak_growth;
        let fixture = EvidenceFixture::new();
        let prefix = br#"{"ignored":{"escaped":""#;
        let suffix = br#""},"packages":[{"id":"observed","source":null}],"resolve":{"nodes":[{"id":"observed","features":[],"deps":[]}]}}"#;
        let repetitions = 16 * 1024 * 1024;
        let mut bytes = Vec::with_capacity(prefix.len() + repetitions * 2 + suffix.len());
        bytes.extend_from_slice(prefix);
        for _ in 0..repetitions {
            bytes.extend_from_slice(br#"\n"#);
        }
        bytes.extend_from_slice(suffix);
        // HeapPinAllocator tracks this thread's peak, so concurrent tests and
        // page refaults cannot contribute to the measured growth.
        let (result, growth) = heap_pin_peak_growth(|| {
            validate_exact_cargo_metadata_field_presence(&bytes, &fixture.evidence)
        });
        result.unwrap();
        println!(
            "presence_peak_alloc_growth_bytes={growth} input_bytes={}",
            bytes.len()
        );
        // A full Value parse retains the unescaped 16 MiB string plus scratch.
        // Presence decoding needs neither, irrespective of ignored value size.
        // Peak allocated bytes, unlike process VmHWM, exclude page-refault and
        // first-touch paging (#13451).
        assert!(
            growth < 4 * 1024 * 1024,
            "presence decoding allocated {growth} bytes"
        );
        let omitted = br#"{"packages":[{"id":"observed","source":null}],"resolve":{"nodes":[{"id":"observed","deps":[]}]}}"#;
        let error =
            validate_exact_cargo_metadata_field_presence(omitted, &fixture.evidence).unwrap_err();
        assert_eq!(error.code, "rust.evidence.metadata_field_missing");
        assert!(error.message.contains("features"));
    }

    #[test]
    fn existing_fixture_activation_transport_snapshot() {
        let fixture = EvidenceFixture::new();
        fixture.write_exact_toolchain();
        // Reuse the existing format-61 converter fixture, changing only its
        // selected crate identity to the existing dependency fixture's widget.
        let mut rustdoc: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/rustdoc-converter-small/native-61.json"
        ))
        .unwrap();
        rustdoc["crate_version"] = json!("1.2.3");
        rustdoc["index"]["1"]["name"] = json!("widget");
        rustdoc["paths"]["0"]["path"] = json!(["widget", "echo"]);
        // `item_names` reads the persisted paths before the item table, so the
        // root module's path must move with its index name.
        rustdoc["paths"]["1"]["path"] = json!(["widget"]);
        rustdoc["target"]["triple"] = json!(host_target());
        fs::write(&fixture.rustdoc_path, serde_json::to_vec(&rustdoc).unwrap()).unwrap();
        let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
        let config = RustAnalyzerConfig {
            dependency_api_evidence: vec![fixture.evidence.clone()],
        };
        let outcome = resolve_rust_semantic_pack_dependencies(
            &config,
            &project,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(outcome.complete, "{:?}", outcome.diagnostics);
        let catalog = crate::analyzer::semantic_model::SemanticPackCatalog::open_ephemeral(
            crate::analyzer::semantic_model::CatalogOptions::default(),
        )
        .unwrap();
        let artifact_dependencies = outcome
            .dependencies
            .iter()
            .filter(|dependency| !dependency.artifacts.is_empty())
            .cloned()
            .collect::<Vec<_>>();
        let prepared = crate::analyzer::semantic_model::prepare_dependency_semantic_packs(
            &catalog,
            &crate::analyzer::rust::RustDependencyPackAdapter,
            &artifact_dependencies,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(prepared.complete, "{:?}", prepared.diagnostics);
        let analyzer = crate::analyzer::rust::RustAnalyzer::new_with_config(
            std::sync::Arc::new(project),
            crate::analyzer::AnalyzerConfig {
                rust: config,
                ..Default::default()
            },
        );
        let request = prepared
            .compose_activation_request(
                crate::analyzer::semantic_model::SemanticModelActivationRequest {
                    host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
                    approximate_standard_libraries: Vec::new(),
                    bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                    evidence: Vec::new(),
                    controls: Vec::new(),
                    limits: Default::default(),
                },
            )
            .unwrap();
        let activation = crate::analyzer::semantic_model::acquire_active_semantic_models(
            &analyzer,
            &catalog,
            None,
            &request,
            &CancellationToken::new(),
        );
        assert!(matches!(
            activation,
            crate::analyzer::semantic_model::SemanticModelRuntimeOutcome::Ready { .. }
        ));
        let overlay = analyzer.semantic_model_overlay_read().published().unwrap();
        let (mut symbols, complete) = overlay.symbols();
        assert!(
            complete,
            "exact evidence activation must enumerate every symbol"
        );
        symbols.sort_by(|left, right| left.id.cmp(&right.id));
        assert!(!symbols.is_empty());
        let snapshot = format!(
            "{outcome:#?}\nactive_model_set_hash={}\ncomplete={complete}\n{:#?}",
            overlay.active_model_set_hash(),
            symbols
        )
        .replace(fixture._root.path().to_str().unwrap(), "<fixture>");
        if let Ok(path) = std::env::var("BIFROST_EXACT_EVIDENCE_SNAPSHOT") {
            fs::write(path, snapshot).unwrap();
        }
    }
    fn exact(
        fixture: &EvidenceFixture,
    ) -> Result<ExactRustDependencyEvidence, DependencyPackDiagnostic> {
        resolve_exact_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            None,
        )
    }

    fn mutate_json(path: &Path, change: impl FnOnce(&mut serde_json::Value)) {
        let mut value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        change(&mut value);
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }

    #[test]
    fn passive_exact_source_absent_preserves_alias_authority_without_read_publication() {
        use brokk_bifrost_analysis::analyzer::dependency_support::capture_external_discovery_reads;
        let fixture = EvidenceFixture::new();
        assert!(!fixture._root.path().join("src").exists());
        assert!(!fixture._root.path().join("Cargo.toml").exists());
        let (result, reads) = capture_external_discovery_reads(|| exact(&fixture));
        let result = result.unwrap();
        assert!(reads.keys.is_empty());
        assert!(!reads.complete);
        assert_eq!(result.dependencies.len(), 1);
        let dependency = &result.dependencies[0];
        let package = result
            .cargo_graph
            .package_for_evidence(&dependency.evidence)
            .unwrap();
        assert_eq!(package.package_id.as_str(), PACKAGE_ID);
        assert_eq!(
            result.cargo_graph.incoming_dependency_names(package),
            ["renamed_widget"]
        );
        let tuple = result.cargo_graph.artifact_tuple(package).unwrap();
        assert!(tuple.exact);
        assert_eq!(tuple.resolved_features, ["derive"]);
        assert_eq!(tuple.artifact_features, ["derive"]);
        // Discovery never manufactures preparation's verified artifact identity.
        assert!(dependency.evidence.production_input_digest.is_none());
        assert!(dependency.evidence.verified_raw_artifacts.is_empty());
    }

    #[test]
    fn passive_exact_rejects_wrong_identity_and_malformed_evidence_with_typed_causes() {
        for (case, expected) in [
            ("version", "rust.rustdoc.approximation_record_required"),
            ("features_narrow", "rust.evidence.features_not_exact"),
            ("features_wide", "rust.evidence.features_not_exact"),
            ("target", "rust.rustdoc.target_mismatch"),
            ("package", "rust.metadata.missing_package"),
            ("library", "rust.rustdoc.crate_name_mismatch"),
            ("selected_target", "rust.metadata.missing_selected_target"),
            ("metadata", "rust.metadata.invalid_json"),
            ("rustdoc", "rust.rustdoc.invalid_json"),
            ("format", "rust.rustdoc.unsupported_version"),
            ("lock", "rust.lockfile.missing_package"),
            ("missing", "artifact.metadata"),
        ] {
            let mut fixture = EvidenceFixture::new();
            match case {
                "version" => mutate_json(&fixture.rustdoc_path, |value| {
                    value["crate_version"] = json!("1.2.2")
                }),
                "features_narrow" => fixture.evidence.packages[0].enabled_features.clear(),
                "features_wide" => fixture.evidence.packages[0]
                    .enabled_features
                    .push("extra".into()),
                "target" => fixture.write_rustdoc(non_host_target()),
                "package" => fixture.evidence.packages[0].package_id = "missing".into(),
                "library" => fixture.evidence.packages[0].crate_name = "missing".into(),
                "selected_target" => {
                    fixture.evidence.selected_targets[0].target_name = "missing".into()
                }
                "metadata" => fs::write(&fixture.evidence.metadata_path, "{").unwrap(),
                "rustdoc" => fs::write(&fixture.rustdoc_path, "{").unwrap(),
                "format" => mutate_json(&fixture.rustdoc_path, |value| {
                    value["format_version"] = json!(60)
                }),
                "lock" => fs::write(&fixture.evidence.lockfile_path, "version = 4\n").unwrap(),
                "missing" => fs::remove_file(&fixture.rustdoc_path).unwrap(),
                _ => unreachable!(),
            }
            assert_eq!(exact(&fixture).unwrap_err().code, expected, "{case}");
        }
    }

    #[test]
    fn passive_exact_requires_observed_features_but_accepts_explicit_empty() {
        let mut fixture = EvidenceFixture::new();
        fixture.evidence.packages[0].enabled_features.clear();
        mutate_json(&fixture.evidence.metadata_path, |value| {
            value["resolve"]["nodes"][1]["features"] = json!([]);
        });
        assert!(exact(&fixture).is_ok(), "explicit empty features are exact");
        mutate_json(&fixture.evidence.metadata_path, |value| {
            value["resolve"]["nodes"][1]
                .as_object_mut()
                .unwrap()
                .remove("features");
        });
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();
        assert!(
            resolve_rust_dependency_evidence(&fixture.evidence, decoded).is_ok(),
            "runtime partial discovery retains its existing interpretation"
        );
        assert_eq!(
            exact(&fixture).unwrap_err().code,
            "rust.evidence.metadata_field_missing"
        );
    }

    #[test]
    fn passive_exact_requires_observed_edges_and_nullable_package_source() {
        let fixture = EvidenceFixture::new();
        mutate_json(&fixture.evidence.metadata_path, |value| {
            value["resolve"]["nodes"][1]
                .as_object_mut()
                .unwrap()
                .remove("deps");
        });
        let error = exact(&fixture).unwrap_err();
        assert_eq!(error.code, "rust.evidence.metadata_field_missing");
        assert!(error.message.contains("deps"));

        let fixture = EvidenceFixture::new();
        mutate_json(&fixture.evidence.metadata_path, |value| {
            value["packages"][1]["source"] = serde_json::Value::Null;
        });
        let lock = fs::read_to_string(&fixture.evidence.lockfile_path).unwrap();
        let lock = lock
            .lines()
            .filter(|line| !line.starts_with("source = "))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&fixture.evidence.lockfile_path, lock).unwrap();
        assert!(
            exact(&fixture).is_ok(),
            "explicit nullable Cargo source remains supported"
        );
        mutate_json(&fixture.evidence.metadata_path, |value| {
            value["packages"][1]
                .as_object_mut()
                .unwrap()
                .remove("source");
        });
        let error = exact(&fixture).unwrap_err();
        assert_eq!(error.code, "rust.evidence.metadata_field_missing");
        assert!(error.message.contains("source"));
    }

    #[test]
    fn passive_exact_rejects_approximation_even_with_matching_version_and_features() {
        let mut fixture = EvidenceFixture::new();
        fixture.evidence.packages[0].approximation = Some(RustArtifactApproximationClaim {
            artifact_version: "1.2.3".into(),
            artifact_features: vec!["derive".into()],
            artifact_cfgs: Vec::new(),
            docsrs_build: false,
            artifact_sha256: "unused".into(),
            activation_version_requirement: "=1.2.3".into(),
            selection_rule_id: "cargo-compatible-nearest".into(),
            selection_rule_version: 1,
        });
        assert_eq!(
            exact(&fixture).unwrap_err().code,
            "rust.evidence.approximation_not_exact"
        );
    }

    #[test]
    fn passive_exact_preserves_typed_ambiguity_refusals() {
        let fixture = EvidenceFixture::new();
        mutate_json(&fixture.evidence.metadata_path, |value| {
            let duplicate = value["resolve"]["nodes"][1].clone();
            value["resolve"]["nodes"]
                .as_array_mut()
                .unwrap()
                .push(duplicate);
        });
        assert_eq!(
            exact(&fixture).unwrap_err().code,
            "rust.metadata.duplicate_node_id"
        );
        let mut fixture = EvidenceFixture::new();
        let mut conflicting = fixture.evidence.packages[0].clone();
        conflicting.rustdoc_toolchain = "another-observed-toolchain".into();
        fixture.evidence.packages.push(conflicting);
        assert_eq!(
            exact(&fixture).unwrap_err().code,
            "rust.metadata.ambiguous_cargo_graph"
        );
    }

    #[test]
    fn passive_exact_honors_cancellation_and_existing_resource_limits() {
        let fixture = EvidenceFixture::new();
        let token = CancellationToken::new();
        token.cancel();
        assert_eq!(
            resolve_exact_rust_dependency_evidence(
                &fixture.evidence,
                &DependencyPackLimits::default(),
                Some(&token)
            )
            .unwrap_err()
            .code,
            "rust.evidence.cancelled"
        );
        for (limits, expected) in [
            (
                DependencyPackLimits {
                    max_dependencies: 0,
                    ..Default::default()
                },
                "limit.dependencies",
            ),
            (
                DependencyPackLimits {
                    max_total_artifact_bytes: 1,
                    ..Default::default()
                },
                "limit.total_artifact_bytes",
            ),
        ] {
            assert_eq!(
                resolve_exact_rust_dependency_evidence(&fixture.evidence, &limits, None)
                    .unwrap_err()
                    .code,
                expected
            );
        }
    }

    #[test]
    fn passive_exact_back_to_back_calls_keep_graphs_independent_even_after_failure() {
        let first = EvidenceFixture::new();
        let first_result = exact(&first).unwrap();
        let mut second = EvidenceFixture::new();
        second.evidence.configuration = "independent".into();
        mutate_json(&second.evidence.metadata_path, |value| {
            value["resolve"]["nodes"][0]["deps"][0]["name"] = json!("second_alias");
        });
        let second_result = exact(&second).unwrap();
        let package = second_result
            .cargo_graph
            .package_for_evidence(&second_result.dependencies[0].evidence)
            .unwrap();
        assert_eq!(
            second_result.cargo_graph.incoming_dependency_names(package),
            ["second_alias"]
        );
        assert!(
            second_result
                .cargo_graph
                .package_for_evidence(&first_result.dependencies[0].evidence)
                .is_none()
        );
        second.write_metadata(false);
        assert_eq!(
            exact(&second).unwrap_err().code,
            "rust.metadata.unreachable_package"
        );
        let repeated = exact(&first).unwrap();
        assert_eq!(first_result.dependencies, repeated.dependencies);
        assert_eq!(first_result.cargo_graph, repeated.cargo_graph);
    }
}
