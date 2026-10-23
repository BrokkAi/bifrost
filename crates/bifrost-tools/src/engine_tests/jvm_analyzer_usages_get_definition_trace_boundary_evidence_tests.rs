/// #1870 acceptance: every language with an evidence arm reports
/// `external_indexed` for an indexed external name and
/// `external_declared_unindexed` for a declared-but-unindexed dependency,
/// instead of the unconditional `external_unknown` the wildcard used to give.
///
/// Every arm here is driven end-to-end through
/// [`resolve_definition_batch_with_trace`], the same entry the occurrence-rows
/// acceptance tests for Python and TypeScript use underneath: the real resolver
/// draws the boundary and `finish_boundary` refines it. Each language that
/// draws one is also tested for the case it must *not* draw: a name whose
/// failing segment stays inside the workspace answers `no_definition` with no
/// route row at all (#1889).
#[cfg(test)]
mod boundary_evidence_tests {

    use brokk_bifrost_analysis::analyzer::QueryScope;
    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::BoundaryFixture;

    use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_semantic::analyzer::semantic::trace::DispatchQuality;

    use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::TraceCandidateRef;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::activate_fixture_catalog;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::activate_fixture_pack;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::assert_declared_unindexed_routes;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::assert_no_boundary_was_drawn;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::boundary_evidence;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::dispatch_quality_for_status;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::external_routes;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::route_rows;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::single_type_pack;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::test_support::activation_evidence;

    use brokk_bifrost_test_macros::hardwon;

    use std::path::Path;
    use std::path::PathBuf;

    const KOTLIN_BOUNDARY_SOURCE: &str = concat!(
        "package app\n",
        "import com.acme.Gadget\n",
        "class Caller {\n",
        "  fun build(): Gadget? = null\n",
        "}\n",
    );

    const JVM_PACK_JAVA_SOURCE: &str = concat!(
        "package app;\n",
        "\n",
        "import java.util.ArrayList;\n",
        "import java.util.Collections;\n",
        "\n",
        "class Caller {\n",
        "  Collections helper() { return null; }\n",
        "  ArrayList names() { return null; }\n",
        "}\n",
    );

    const JVM_PACK_KOTLIN_SOURCE: &str = concat!(
        "package app\n",
        "import java.util.Collections\n",
        "class Caller {\n",
        "  fun helper(): Collections? = null\n",
        "}\n",
    );

    /// A discovery outcome declaring exactly `modules` for `language`; an
    /// incomplete outcome records that the build could not be read fully.
    fn write_source_jar(path: &Path, entry_name: &str, bytes: &[u8]) {
        use std::io::Write;
        let file = std::fs::File::create(path).expect("create source jar");
        let mut jar = zip::ZipWriter::new(file);
        jar.start_file(
            entry_name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .expect("start jar entry");
        jar.write_all(bytes).expect("write jar entry");
        jar.finish().expect("finish jar");
    }

    /// A JVM analyzer config whose external realm is exactly the given jar --
    /// a source jar or a class jar, whichever the caller wrote: dependency
    /// discovery and JDK discovery stay off so the index reads nothing but the
    /// fixture's own artifact.
    fn jvm_config_with_artifact_jar(jar: Option<PathBuf>) -> AnalyzerConfig {
        use brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig;

        use brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryConfig;

        use brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryMode;

        use brokk_bifrost_core::analyzer::config::JvmExternalArtifact;

        use brokk_bifrost_core::analyzer::config::JvmExternalDependencies;

        use brokk_bifrost_core::analyzer::config::JvmStandardLibraryDiscoveryConfig;
        AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    artifact_paths: jar
                        .map(|artifact_path| {
                            vec![JvmExternalArtifact {
                                artifact_path,
                                ..JvmExternalArtifact::default()
                            }]
                        })
                        .unwrap_or_default(),
                    ..JvmExternalDependencies::default()
                },
                dependency_discovery: JvmDependencyDiscoveryConfig {
                    mode: JvmDependencyDiscoveryMode::Disabled,
                    ..JvmDependencyDiscoveryConfig::default()
                },
                standard_library_discovery: JvmStandardLibraryDiscoveryConfig {
                    discover_java_home: false,
                    ..JvmStandardLibraryDiscoveryConfig::default()
                },
            },
            ..AnalyzerConfig::default()
        }
    }

    // -----------------------------------------------------------------------
    // Scala: end-to-end through the resolver's own boundary outcome.
    // -----------------------------------------------------------------------

    const SCALA_BOUNDARY_SOURCE: &str = concat!(
        "package app\n",
        "import com.acme.Gadget\n",
        "class Caller {\n",
        "  def build(): Gadget = null\n",
        "}\n",
    );

    #[test]
    fn a_scala_import_of_an_indexed_external_type_reports_external_indexed() {
        let fixture = BoundaryFixture::with_config(
            Language::Scala,
            "app/Caller.scala",
            SCALA_BOUNDARY_SOURCE,
            |root| {
                let jar = root.join("acme-lib-sources.jar");
                write_source_jar(
                    &jar,
                    "com/acme/Gadget.scala",
                    b"package com.acme\nclass Gadget\n",
                );
                jvm_config_with_artifact_jar(Some(jar))
            },
        );
        let (_, trace) = fixture.trace("Gadget = null");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("com.acme.Gadget")
            }),
            "the jar index resolves `Gadget` through the explicit import: {routes:?}"
        );
    }

    // BEGIN PRIVATE CSHARP EXTERNAL FIXTURE TRACE TEST
    // -----------------------------------------------------------------------
    // C#: end-to-end through the resolver's own boundary outcome.
    // -----------------------------------------------------------------------

    // END PRIVATE CSHARP EXTERNAL FIXTURE TRACE TEST

    // -----------------------------------------------------------------------
    // PHP: end-to-end through the resolver's own boundary outcome.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Kotlin: end-to-end through the resolver's own boundary outcome (#1889).
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Ruby: end-to-end through the resolver's own boundary outcome (#1889).
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // JVM declaration-facts packs: the same route the source jars feed (#1893).
    // -----------------------------------------------------------------------

    /// One file whose standard-library call spells a *member*: the whole
    /// written name `Collections.sort` has a type for its head and a member for
    /// its last segment, which is the shape #1900 is about. `Collections.size`
    /// is the near miss on the same owner -- a member no pack declares.
    const JVM_PACK_JAVA_MEMBER_SOURCE: &str = concat!(
        "package app;\n",
        "\n",
        "import java.util.ArrayList;\n",
        "import java.util.Collections;\n",
        "\n",
        "class Caller {\n",
        "  int run() {\n",
        "    ArrayList<String> names = new ArrayList<>();\n",
        "    Collections.sort(names);\n",
        "    return Collections.size(names);\n",
        "  }\n",
        "}\n",
    );

    fn jdk_collections_type_id() -> String {
        use brokk_bifrost_semantic::analyzer::semantic_model::identity::TypeIdentity;

        use brokk_bifrost_semantic::analyzer::semantic_model::identity::type_declaration_id;

        type_declaration_id(TypeIdentity {
            ecosystem: "jdk",
            name: "java.util.Collections",
        })
    }

    /// The declaration-facts pack the JVM boundary tests activate: one public
    /// JDK class, published for `language: java`, carrying `members`, and no
    /// artifact anywhere on disk.
    fn jdk_collections_pack(members: serde_json::Value) -> serde_json::Value {
        single_type_pack(
            "fixture.jdk",
            "java",
            "jdk",
            "java.base",
            &jdk_collections_type_id(),
            "java.util.Collections",
            members,
        )
    }

    /// The one static method the member fixtures declare on
    /// `java.util.Collections`.
    fn collections_sort_member() -> serde_json::Value {
        let owner = jdk_collections_type_id();
        serde_json::json!([{
            "id": format!("member.{owner}.sort"),
            "owner": owner,
            "name": "sort",
            "member_kind": "method",
            "visibility": "public",
            "is_static": true,
            "locator": {
                "kind": "artifact",
                "path": "fixture-source",
                "symbol": "java.util.Collections.sort"
            }
        }])
    }

    // -----------------------------------------------------------------------
    // Milestone 1 (#1885): the public probe entry points read the same
    // resolver decisions as the crate-internal ones they wrap.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // JVM declaration-facts packs: member declarations (#1900).
    // -----------------------------------------------------------------------

    #[test]
    fn a_java_member_of_a_pack_declared_type_reports_external_indexed() {
        // #1900 acceptance: no source jar, no class jar, no JDK home. The
        // activated pack declares `java.util.Collections` *and* its `sort`
        // member, and the whole written name `Collections.sort` reaches the
        // member declaration from both of the sites that spell it.
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        activate_fixture_pack(
            &fixture,
            "fixture.jdk",
            &jdk_collections_pack(collections_sort_member()),
            activation_evidence("java", "jdk", "java.base"),
        );

        // Receiver position: the caret is on `Collections`, and the reference
        // site spans the whole `Collections.sort` spelling.
        let (_, trace) = fixture.trace("Collections.sort");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("java.util.Collections.sort")
            }),
            "the activated pack declares the `sort` member: {routes:?}"
        );

        // Member position: the caret is on `sort`, whose receiver names a type
        // this workspace does not index. Before #1900 that was a plain
        // unresolved-receiver miss with no route at all.
        let (outcome, trace) = fixture.trace("sort(names)");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary,
            "the member is declared past a boundary, not absent: {:?}",
            outcome.diagnostics
        );
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("java.util.Collections.sort")
            }),
            "the member caret reaches the same declaration: {routes:?}"
        );

        // The route the member named is the reference's selection, which is
        // what lets a positive tier requirement over it conclude (#1893).
        let selected: Vec<_> = trace
            .candidates
            .iter()
            .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
            .collect();
        assert!(
            !selected.is_empty()
                && selected
                    .iter()
                    .all(|row| row.is_selected() && row.tier == Some(PrecedenceTier::ExternalRoot)),
            "a named external member is the selection: {selected:?}"
        );

        // Boundary honesty on the same owner: `size` is not declared, so the
        // spelling keeps the status it had before activation even though the
        // owner type is decided.
        let (_, trace) = fixture.trace("Collections.size");
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "a member the pack does not declare must not be upgraded: {routes:?}"
        );
    }

    #[test]
    fn a_member_a_pack_does_not_declare_proves_nothing_about_it() {
        // The honesty rule #1900 names: absence of a member declaration is not
        // a declaration of absence. This pack declares the owner type and no
        // members at all, so every member spelling on it stays exactly as
        // unknown as it was before activation -- and the member-position caret
        // keeps its plain miss rather than inventing a boundary.
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        activate_fixture_pack(
            &fixture,
            "fixture.jdk",
            &jdk_collections_pack(serde_json::json!([])),
            activation_evidence("java", "jdk", "java.base"),
        );

        let (_, trace) = fixture.trace("Collections.sort");
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "a pack with no members decides no member: {routes:?}"
        );

        let (outcome, trace) = fixture.trace("sort(names)");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::NoDefinition,
            "an undeclared member is not a boundary crossing: {:?}",
            outcome.diagnostics
        );
        assert!(
            route_rows(&trace).is_empty(),
            "nothing declares the member, so no route out of the workspace: {:?}",
            trace.candidates
        );
    }

    // -----------------------------------------------------------------------
    // The artifact half of the same member surface: jar-indexed owners (#1900).
    // -----------------------------------------------------------------------

    /// One file whose calls spell members of a type a *class jar* declares.
    /// `register` is declared on the owner itself, `reset` is inherited from
    /// its base class in the same jar, and `absent` is the near miss no class
    /// file declares.
    const JVM_ARTIFACT_JAVA_MEMBER_SOURCE: &str = concat!(
        "package app;\n",
        "\n",
        "import com.example.probe.Registry;\n",
        "\n",
        "class Caller {\n",
        "  void run() {\n",
        "    Registry.register(\"x\");\n",
        "    Registry.reset();\n",
        "    Registry.absent();\n",
        "  }\n",
        "}\n",
    );

    /// A class JAR declaring `com.example.probe.Registry extends
    /// com.example.probe.BaseRegistry`, written without a JDK so the test runs
    /// everywhere.
    fn write_probe_class_jar(path: &Path) {
        let classes =
            brokk_bifrost_jvm_analysis::analyzer::jvm::external::probe_registry_base_class_files();
        brokk_bifrost_jvm_analysis::analyzer::jvm::external::write_test_class_jar(path, &classes);
    }

    #[test]
    fn a_java_member_of_a_class_jar_type_reports_external_indexed() {
        // #1900 acceptance for the artifact half: no pack is activated at all.
        // The jar on disk declares `com.example.probe.Registry` *and* the
        // members its class files carry, and the whole written name
        // `Registry.register` reaches the member declaration from both of the
        // sites that spell it -- the same conclusion the pack half reaches, on
        // the same route, through the same one lookup.
        let jars = tempfile::tempdir().expect("jar dir");
        let jar = jars.path().join("probe.jar");
        write_probe_class_jar(&jar);
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_ARTIFACT_JAVA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(jar.clone())),
        );

        // Receiver position: the caret is on `Registry`, and the reference site
        // spans the whole `Registry.register` spelling.
        let (_, trace) = fixture.trace("Registry.register");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("com.example.probe.Registry.register")
            }),
            "the indexed class jar declares the `register` member: {routes:?}"
        );

        // Member position: the caret is on `register`, whose receiver names a
        // type this workspace does not index.
        let (outcome, trace) = fixture.trace("register(\"x\")");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary,
            "the member is declared past a boundary, not absent: {:?}",
            outcome.diagnostics
        );
        let selected: Vec<_> = trace
            .candidates
            .iter()
            .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
            .collect();
        assert!(
            !selected.is_empty()
                && selected
                    .iter()
                    .all(|row| row.is_selected() && row.tier == Some(PrecedenceTier::ExternalRoot)),
            "a named external member is the selection: {selected:?}"
        );

        // Inherited: `reset` is declared on the base class in the same jar, and
        // the reported target names where it is declared rather than where it
        // was written.
        let (_, trace) = fixture.trace("Registry.reset");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("com.example.probe.BaseRegistry.reset")
            }),
            "an inherited member answers where it is declared: {routes:?}"
        );

        // Boundary honesty on the same owner: no class file declares `absent`,
        // so the spelling keeps the status it had. The owner is decided, which
        // is why the route exists at all, and nothing upgrades it.
        let (_, trace) = fixture.trace("Registry.absent");
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "a member no class file declares must not be upgraded: {routes:?}"
        );
    }

    /// #3466: an instance-receiver member call on an external type beside a
    /// workspace-local same-name member. The workspace receiver typing answers
    /// nothing for the servlet type, and the external declaration surface is
    /// the class jar below.
    const SERVLET_FIXTURE_SOURCE: &str = concat!(
        "package fixture;\n",
        "\n",
        "import jakarta.servlet.http.HttpServletRequest;\n",
        "\n",
        "final class SameNameRequest {\n",
        "  String getParameter(String name) { return name; }\n",
        "}\n",
        "\n",
        "final class App {\n",
        "  String positive(HttpServletRequest servletRequest) {\n",
        "    return servletRequest.getParameter(\"user\");\n",
        "  }\n",
        "\n",
        "  String sameName(SameNameRequest decoyRequest) {\n",
        "    return decoyRequest.getParameter(\"name\");\n",
        "  }\n",
        "}\n",
    );

    fn write_servlet_api_jar(path: &Path) {
        use brokk_bifrost_jvm_analysis::analyzer::jvm::external::TestClassFile;

        use brokk_bifrost_jvm_analysis::analyzer::jvm::external::TestClassMethod;

        use brokk_bifrost_jvm_analysis::analyzer::jvm::external::write_test_class_jar;

        write_test_class_jar(
            path,
            &[
                TestClassFile {
                    internal_name: "jakarta/servlet/ServletRequest",
                    super_internal_name: "java/lang/Object",
                    methods: &[TestClassMethod {
                        name: "getParameter",
                        descriptor: "(Ljava/lang/String;)Ljava/lang/String;",
                        is_static: false,
                    }],
                    private_nested: false,
                },
                TestClassFile {
                    internal_name: "jakarta/servlet/http/HttpServletRequest",
                    super_internal_name: "jakarta/servlet/ServletRequest",
                    methods: &[],
                    private_nested: false,
                },
            ],
        );
    }

    /// The shared publication for an instance-receiver member call on an
    /// external type: the outcome is the boundary, its resolved reference text
    /// is the canonical external identity, and the route row names that same
    /// identity with the external declaration the resolver landed on. Before
    /// #3466 the outcome stayed `NoDefinition` and the trace had no row, while
    /// `call_bindings` read the same call's canonical identity end to end.
    #[test]
    #[hardwon(
        "#3466: A real instance receiver call publishes one route row that joins the corresponding occurrence candidate"
    )]
    fn instance_receiver_member_call_publishes_the_external_route_row() {
        let jars = tempfile::tempdir().expect("jar dir");
        let jar = jars.path().join("servlet-api.jar");
        write_servlet_api_jar(&jar);
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "src/App.java",
            SERVLET_FIXTURE_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(jar.clone())),
        );

        let (outcome, trace) = fixture.trace("getParameter(\"user\")");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary,
            "an instance call on an external type is the boundary it crossed: {:?}",
            outcome.diagnostics
        );
        assert_eq!(
            outcome.resolved_reference_target(),
            Some("jakarta.servlet.ServletRequest.getParameter"),
            "the boundary names the declaration the external surface resolved: {:?}",
            outcome.diagnostics
        );
        assert_eq!(
            external_routes(&trace),
            vec![(
                BoundaryStatus::ExternalIndexed,
                Some("jakarta.servlet.ServletRequest.getParameter".to_string()),
            )],
            "the same identity is the one candidate row the trace publishes: {:#?}",
            trace.candidates
        );
        assert!(
            trace
                .selected()
                .any(|row| row.boundary == BoundaryStatus::ExternalIndexed),
            "the external declaration is the answer this reference resolved to: {:#?}",
            trace.candidates
        );
    }

    #[test]
    #[hardwon(
        "0242909d77ed: Java census G13 (2026-10-15): inherited external members lost their declaring owner"
    )]
    fn inherited_external_routes_keep_the_same_declaring_identity_for_both_receiver_types() {
        let jars = tempfile::tempdir().expect("jar dir");
        let jar = jars.path().join("servlet-api.jar");
        write_servlet_api_jar(&jar);
        for receiver in [
            "jakarta.servlet.ServletRequest",
            "jakarta.servlet.http.HttpServletRequest",
        ] {
            let source = format!(
                "class App {{ String read({receiver} request) {{ return request.getParameter(\"user\"); }} }}"
            );
            let fixture =
                BoundaryFixture::with_config(Language::Java, "src/App.java", &source, |_| {
                    jvm_config_with_artifact_jar(Some(jar.clone()))
                });
            let (outcome, trace) = fixture.trace("getParameter(\"user\")");
            assert_eq!(
                outcome.resolved_reference_target(),
                Some("jakarta.servlet.ServletRequest.getParameter"),
                "receiver {receiver}: {outcome:?}"
            );
            assert_eq!(
                external_routes(&trace),
                vec![(
                    BoundaryStatus::ExternalIndexed,
                    Some("jakarta.servlet.ServletRequest.getParameter".to_owned())
                )],
                "receiver {receiver}: {trace:?}"
            );
        }
    }

    /// The decoy half of #3466: the workspace-local member of the same name is
    /// still an ordinary in-workspace resolution. Nothing about the external
    /// call makes a same-name workspace member a boundary.
    #[test]
    #[hardwon(
        "#3466: A workspace declaration with the same member spelling wins without publishing an external route"
    )]
    fn workspace_same_name_member_decoy_stays_in_workspace() {
        let jars = tempfile::tempdir().expect("jar dir");
        let jar = jars.path().join("servlet-api.jar");
        write_servlet_api_jar(&jar);
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "src/App.java",
            SERVLET_FIXTURE_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(jar.clone())),
        );

        let (outcome, trace) = fixture.trace("getParameter(\"name\")");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "a workspace member is a resolved definition, not a boundary: {:?}",
            outcome.diagnostics
        );
        assert_eq!(
            outcome
                .definitions
                .iter()
                .map(|unit| unit.fq_name())
                .collect::<Vec<_>>(),
            vec!["fixture.SameNameRequest.getParameter".to_string()],
            "the decoy's own declaration is the answer: {:?}",
            outcome.diagnostics
        );
        assert!(
            route_rows(&trace).is_empty(),
            "a workspace resolution reports no route out of the workspace: {:#?}",
            trace.candidates
        );
    }

    #[test]
    fn a_class_jar_the_index_could_not_read_proves_nothing_about_its_members() {
        // The honesty rule #1900 names, on the artifact half: a jar the bounded
        // read could not open declares nothing, so every member spelling on it
        // stays unknown. This is the artifact counterpart of "a pack that
        // declares no members proves nothing about them", and it is what
        // separates "the member is not there" from "nothing read the class file
        // that would say".
        let jars = tempfile::tempdir().expect("jar dir");
        let jar = jars.path().join("probe.jar");
        std::fs::write(&jar, b"not a zip archive at all").expect("write the corrupt jar");
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_ARTIFACT_JAVA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(jar.clone())),
        );

        let (_, trace) = fixture.trace("Registry.register");
        let routes = route_rows(&trace);
        assert!(
            routes.iter().all(
                |(boundary, target)| *boundary != BoundaryStatus::ExternalIndexed
                    && target.is_none()
            ),
            "an unread jar names no member: {routes:?}"
        );

        let (outcome, trace) = fixture.trace("register(\"x\")");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::NoDefinition,
            "an unread jar's member is not a proven boundary crossing: {:?}",
            outcome.diagnostics
        );
        assert!(
            route_rows(&trace).is_empty(),
            "nothing declares the member, so no route out of the workspace: {:?}",
            trace.candidates
        );
    }

    // -----------------------------------------------------------------------
    // Kotlin and Scala reach the same gate through their own resolvers (#2287).
    // -----------------------------------------------------------------------

    /// A Kotlin caller of a member whose owner lives in a dependency JAR.
    const JVM_ARTIFACT_KOTLIN_MEMBER_SOURCE: &str = concat!(
        "package app\n",
        "import com.example.probe.Registry\n",
        "class Caller {\n",
        "  fun run() { Registry.register(\"x\") }\n",
        "}\n",
    );

    /// The same caller written in Scala. The owner is named through a wildcard
    /// import rather than an explicit one on purpose: an explicit Scala import
    /// whose target is unindexed already draws a boundary of its own, so a
    /// wildcard is the shape where the member surface is the only thing that
    /// can carry the claim.
    const JVM_ARTIFACT_SCALA_MEMBER_SOURCE: &str = concat!(
        "package app\n",
        "import com.example.probe.*\n",
        "class Caller {\n",
        "  def run(): Unit = Registry.register(\"x\")\n",
        "}\n",
    );

    /// A class JAR declaring `com.example.probe.Registry` and *no members at
    /// all*. The owner type is indexed exactly as it is in
    /// [`write_probe_class_jar`]; only the member surface differs, which is
    /// what makes the paired runs a discriminator about the member rather than
    /// about the type or about the JAR merely existing.
    fn write_memberless_probe_class_jar(path: &Path) {
        use brokk_bifrost_jvm_analysis::analyzer::jvm::external::TestClassFile;

        use brokk_bifrost_jvm_analysis::analyzer::jvm::external::write_test_class_jar;

        write_test_class_jar(
            path,
            &[TestClassFile {
                internal_name: "com/example/probe/Registry",
                super_internal_name: "java/lang/Object",
                methods: &[],
                private_nested: false,
            }],
        );
    }

    /// What one caret over the written `Registry.register` spelling answered.
    struct MemberSpellingAnswer {
        status: DefinitionLookupStatus,
        outcome: DefinitionLookupOutcome,
        routes: Vec<(BoundaryStatus, Option<String>)>,
    }

    /// The answers a receiver-position caret and a member-position caret each
    /// produce for the one written `Registry.register` spelling.
    fn member_spelling_answers(fixture: &BoundaryFixture) -> Vec<MemberSpellingAnswer> {
        ["Registry.register", "register(\"x\")"]
            .into_iter()
            .map(|needle| {
                let (outcome, trace) = fixture.trace(needle);
                MemberSpellingAnswer {
                    status: outcome.status,
                    routes: route_rows(&trace),
                    outcome,
                }
            })
            .collect()
    }

    /// The #1900 acceptance shape, reproduced for Kotlin (#2287): three paired
    /// runs over one workspace whose only difference is what the JAR declares.
    ///
    /// Before this change both carets died inside Kotlin's own
    /// unresolved-receiver path (`no_indexed_definition` on the receiver,
    /// `receiver_type_unknown` on the member) and no trace carried a route out
    /// of the workspace at all, so nothing downstream could tell an external
    /// member from an absent one.
    #[test]
    fn a_kotlin_member_of_a_class_jar_type_concludes_only_when_the_jar_declared_it() {
        let jars = tempfile::tempdir().expect("jar dir");

        // The JAR declares `register`: both carets report the boundary they
        // crossed, and the route names the exact external declaration.
        let declared = jars.path().join("declared.jar");
        write_probe_class_jar(&declared);
        let fixture = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            JVM_ARTIFACT_KOTLIN_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(declared.clone())),
        );
        for answer in member_spelling_answers(&fixture) {
            assert_eq!(
                answer.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "the member is declared past a boundary, not absent"
            );
            assert!(
                !answer.routes.is_empty()
                    && answer.routes.iter().all(|(boundary, target)| {
                        *boundary == BoundaryStatus::ExternalIndexed
                            && target.as_deref() == Some("com.example.probe.Registry.register")
                    }),
                "the indexed class jar declares the `register` member: {:?}",
                answer.routes
            );
        }
        let (_, trace) = fixture.trace("Registry.register");
        let selected: Vec<_> = trace
            .candidates
            .iter()
            .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
            .collect();
        assert!(
            !selected.is_empty()
                && selected
                    .iter()
                    .all(|row| row.is_selected() && row.tier == Some(PrecedenceTier::ExternalRoot)),
            "a named external member is the selection: {selected:?}"
        );

        // No JAR anywhere: nothing read a class file, so the spelling stays
        // unknown and no route is drawn.
        let absent = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            JVM_ARTIFACT_KOTLIN_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        for answer in member_spelling_answers(&absent) {
            assert_eq!(
                answer.status,
                DefinitionLookupStatus::Incomplete,
                "with no jar native resolution cannot prove member absence"
            );
            assert!(
                answer.routes.is_empty(),
                "nothing declares the member, so no route out of the workspace: {:?}",
                answer.routes
            );
        }

        // The discriminator that names the *member*: the same owner type,
        // still indexed, whose class file declares no members. The conclusion
        // above therefore rests on `register` having been read.
        let memberless = jars.path().join("memberless.jar");
        write_memberless_probe_class_jar(&memberless);
        let type_only = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            JVM_ARTIFACT_KOTLIN_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(memberless.clone())),
        );
        for answer in member_spelling_answers(&type_only) {
            assert_eq!(
                answer.status,
                DefinitionLookupStatus::NoDefinition,
                "an indexed owner that declares no members proves nothing about them: {:?}",
                answer.outcome
            );
            assert!(
                answer.routes.is_empty(),
                "a member no class file declares must not be upgraded: {:?}",
                answer.routes
            );
        }
    }

    /// The same three paired runs for Scala (#2287).
    ///
    /// Before this change the receiver caret reported `no_indexed_definition`
    /// and the member caret `unsupported_scala_receiver`, with no route out of
    /// the workspace on either.
    #[test]
    fn a_scala_member_of_a_class_jar_type_concludes_only_when_the_jar_declared_it() {
        let jars = tempfile::tempdir().expect("jar dir");

        let declared = jars.path().join("declared.jar");
        write_probe_class_jar(&declared);
        let fixture = BoundaryFixture::with_config(
            Language::Scala,
            "app/Caller.scala",
            JVM_ARTIFACT_SCALA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(declared.clone())),
        );
        for answer in member_spelling_answers(&fixture) {
            assert_eq!(
                answer.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "the member is declared past a boundary, not absent"
            );
            assert!(
                !answer.routes.is_empty()
                    && answer.routes.iter().all(|(boundary, target)| {
                        *boundary == BoundaryStatus::ExternalIndexed
                            && target.as_deref() == Some("com.example.probe.Registry.register")
                    }),
                "the indexed class jar declares the `register` member: {:?}",
                answer.routes
            );
        }
        let (_, trace) = fixture.trace("Registry.register");
        let selected: Vec<_> = trace
            .candidates
            .iter()
            .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
            .collect();
        assert!(
            !selected.is_empty()
                && selected
                    .iter()
                    .all(|row| row.is_selected() && row.tier == Some(PrecedenceTier::ExternalRoot)),
            "a named external member is the selection: {selected:?}"
        );

        let absent = BoundaryFixture::with_config(
            Language::Scala,
            "app/Caller.scala",
            JVM_ARTIFACT_SCALA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        for answer in member_spelling_answers(&absent) {
            assert_eq!(
                answer.status,
                if std::env::var_os("BIFROST_TRIAL_NATIVE_SCALA").is_some() {
                    DefinitionLookupStatus::Incomplete
                } else {
                    DefinitionLookupStatus::NoDefinition
                },
                "with no jar native resolution cannot prove member absence"
            );
            assert!(
                answer.routes.is_empty(),
                "nothing declares the member, so no route out of the workspace: {:?}",
                answer.routes
            );
        }

        let memberless = jars.path().join("memberless.jar");
        write_memberless_probe_class_jar(&memberless);
        let type_only = BoundaryFixture::with_config(
            Language::Scala,
            "app/Caller.scala",
            JVM_ARTIFACT_SCALA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(Some(memberless.clone())),
        );
        for (caret_index, answer) in member_spelling_answers(&type_only).into_iter().enumerate() {
            let expected_status = if caret_index == 0 {
                DefinitionLookupStatus::NoDefinition
            } else {
                // under the Scala trial the given-extension frontier (#5956) keeps the memberless owner Incomplete
                if std::env::var_os("BIFROST_TRIAL_NATIVE_SCALA").is_some() {
                    DefinitionLookupStatus::Incomplete
                } else {
                    DefinitionLookupStatus::NoDefinition
                }
            };
            assert_eq!(
                answer.status, expected_status,
                "an indexed owner that declares no members proves nothing about them"
            );
            assert!(
                answer.routes.is_empty(),
                "a member no class file declares must not be upgraded: {:?}",
                answer.routes
            );
        }
    }

    /// The pack half of the same claim, once per language (#2287): an activated
    /// declaration-facts pack and no artifact anywhere on disk.
    ///
    /// Scala names the owner through an *explicit* import here, which is the
    /// shape whose unindexed-import verdict already drew a boundary of its own
    /// before this change. The route it drew named nothing, so the pair below
    /// is still the member discriminator: with the member declared the route is
    /// selected and names `java.util.Collections.sort`; with an emptied members
    /// array the same run keeps a route that names nothing and is not selected.
    #[test]
    fn a_kotlin_and_a_scala_member_of_a_pack_declared_type_report_external_indexed() {
        const KOTLIN_MEMBER_SOURCE: &str = concat!(
            "package app\n",
            "import java.util.Collections\n",
            "class Caller {\n",
            "  fun order(names: MutableList<String>) { Collections.sort(names) }\n",
            "}\n",
        );
        const SCALA_MEMBER_SOURCE: &str = concat!(
            "package app\n",
            "import java.util.Collections\n",
            "class Caller {\n",
            "  def order(names: java.util.List[String]): Unit = Collections.sort(names)\n",
            "}\n",
        );

        for (language, path, source) in [
            (Language::Kotlin, "app/Caller.kt", KOTLIN_MEMBER_SOURCE),
            (Language::Scala, "app/Caller.scala", SCALA_MEMBER_SOURCE),
        ] {
            let declared = BoundaryFixture::with_config(language, path, source, |_| {
                jvm_config_with_artifact_jar(None)
            });
            activate_fixture_pack(
                &declared,
                "fixture.jdk",
                &jdk_collections_pack(collections_sort_member()),
                activation_evidence("java", "jdk", "java.base"),
            );
            for needle in ["Collections.sort", "sort(names)"] {
                let (outcome, trace) = declared.trace(needle);
                assert_eq!(
                    outcome.status,
                    DefinitionLookupStatus::UnresolvableImportBoundary,
                    "{language:?} {needle:?}: the pack declares the member, so the \
                     reference crossed a boundary: {:?}",
                    outcome.diagnostics
                );
                let routes = external_routes(&trace);
                assert!(
                    routes.iter().all(|(boundary, target)| {
                        *boundary == BoundaryStatus::ExternalIndexed
                            && target.as_deref() == Some("java.util.Collections.sort")
                    }),
                    "{language:?} {needle:?}: the activated pack declares `sort`: {routes:?}"
                );
                let selected: Vec<_> = trace
                    .candidates
                    .iter()
                    .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
                    .collect();
                assert!(
                    selected.iter().all(|row| {
                        row.is_selected() && row.tier == Some(PrecedenceTier::ExternalRoot)
                    }),
                    "{language:?} {needle:?}: a named external member is the \
                     selection: {selected:?}"
                );
            }

            // The same pack with an emptied `members` array: the owner type is
            // still declared and still activated, and every member spelling on
            // it stays exactly as unknown as it was before activation.
            let type_only = BoundaryFixture::with_config(language, path, source, |_| {
                jvm_config_with_artifact_jar(None)
            });
            activate_fixture_pack(
                &type_only,
                "fixture.jdk",
                &jdk_collections_pack(serde_json::json!([])),
                activation_evidence("java", "jdk", "java.base"),
            );
            for needle in ["Collections.sort", "sort(names)"] {
                let (_, trace) = type_only.trace(needle);
                assert!(
                    route_rows(&trace).iter().all(|(boundary, target)| {
                        *boundary != BoundaryStatus::ExternalIndexed && target.is_none()
                    }),
                    "{language:?} {needle:?}: a pack with no members decides no \
                     member: {:?}",
                    route_rows(&trace)
                );
                assert!(
                    trace
                        .candidates
                        .iter()
                        .filter(|row| matches!(
                            row.candidate,
                            TraceCandidateRef::ExternalRoute { .. }
                        ))
                        .all(|row| !row.is_selected()),
                    "{language:?} {needle:?}: nothing named the member, so nothing \
                     was selected: {:?}",
                    trace.candidates
                );
            }
        }
    }

    #[test]
    fn a_scala_import_of_a_declared_unread_dependency_reports_declared_unindexed() {
        let fixture = BoundaryFixture::with_config(
            Language::Scala,
            "app/Caller.scala",
            SCALA_BOUNDARY_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        fixture.workspace.retain_dependency_discovery_evidence(
            &[Language::Scala],
            &brokk_bifrost_analysis::test_support::incomplete_discovery_declaring(
                "scala",
                &["com.acme"],
                |_| Vec::new(),
            ),
        );
        let (_, trace) = fixture.trace("Gadget = null");
        let routes = external_routes(&trace);
        assert_declared_unindexed_routes(&routes);
    }

    #[hardwon("#1889: Kotlin imports failed to report the indexed external boundary")]
    #[test]
    fn a_kotlin_import_of_an_indexed_external_type_reports_external_indexed() {
        let fixture = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            KOTLIN_BOUNDARY_SOURCE,
            |root| {
                let jar = root.join("acme-lib-sources.jar");
                write_source_jar(
                    &jar,
                    "com/acme/Gadget.kt",
                    b"package com.acme\nclass Gadget\n",
                );
                jvm_config_with_artifact_jar(Some(jar))
            },
        );
        let (_, trace) = fixture.trace("Gadget? = null");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("com.acme.Gadget")
            }),
            "the jar index resolves `Gadget` through the explicit import: {routes:?}"
        );
    }
    #[hardwon("#1889: Kotlin imports failed to report declared but unread dependencies")]
    #[test]
    fn a_kotlin_import_of_a_declared_unread_dependency_reports_declared_unindexed() {
        let fixture = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            KOTLIN_BOUNDARY_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        let (_, trace) = fixture.trace("Gadget? = null");
        assert!(
            external_routes(&trace)
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "with no index and no retained discovery, nothing is known: {:?}",
            trace.candidates
        );
        fixture.workspace.retain_dependency_discovery_evidence(
            &[Language::Kotlin],
            &brokk_bifrost_analysis::test_support::incomplete_discovery_declaring(
                "kotlin",
                &["com.acme"],
                |_| Vec::new(),
            ),
        );
        let (_, trace) = fixture.trace("Gadget? = null");
        let routes = external_routes(&trace);
        assert_declared_unindexed_routes(&routes);
    }
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[hardwon("#1889: Kotlin workspace packages were at risk of false external classification")]
    #[test]
    fn a_kotlin_import_of_a_workspace_package_stays_a_plain_miss() {
        // The import target is the workspace's own package, so the failing
        // segment never leaves it and the honest answer is `no_definition`.
        let fixture = BoundaryFixture::new(
            Language::Kotlin,
            "app/Caller.kt",
            concat!(
                "package app\n",
                "import app.Helper\n",
                "class Caller {\n",
                "  fun build(): Helper? = null\n",
                "}\n",
            ),
        );
        assert_no_boundary_was_drawn("Helper? = null", &fixture);
    }
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[hardwon(
        "#1889: Kotlin names without import evidence were at risk of false external classification"
    )]
    #[test]
    fn a_kotlin_reference_with_no_import_at_all_stays_a_plain_miss() {
        let fixture = BoundaryFixture::new(
            Language::Kotlin,
            "app/Caller.kt",
            concat!(
                "package app\n",
                "class Caller {\n",
                "  fun build(): Helper? = null\n",
                "}\n",
            ),
        );
        assert_no_boundary_was_drawn("Helper? = null", &fixture);
    }

    #[hardwon("#1893: Java resolution ignored selected declaration-facts packs")]
    #[test]
    fn a_java_import_of_a_pack_declared_type_reports_external_indexed() {
        // #1893 acceptance: no source jar, no class jar, no JDK home -- the
        // activated pack's declaration facts are the only external evidence
        // there is, and they carry the reference all the way to the same
        // `external_indexed` verdict the source-jar route produces.
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        let pack = jdk_collections_pack(serde_json::json!([]));
        activate_fixture_pack(
            &fixture,
            "fixture.jdk",
            &pack,
            activation_evidence("java", "jdk", "java.base"),
        );

        let (_, trace) = fixture.trace("Collections helper");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("java.util.Collections")
            }),
            "the activated pack declares `java.util.Collections`: {routes:?}"
        );

        // Boundary honesty: a pack decides the types it declares and nothing
        // else. `java.util.ArrayList` is imported from the same package and is
        // not in the pack, so it keeps the answer it had before activation.
        let (_, trace) = fixture.trace("ArrayList names");
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "a type the pack does not declare must not be upgraded: {routes:?}"
        );
    }
    #[hardwon(
        "#1893: Java resolution must not infer external declarations without an activated pack"
    )]
    #[test]
    fn a_java_reference_without_the_pack_stays_external_unknown() {
        // The same fixture with no activation at all: the honest answer before
        // #1893 and after it, so the test above measures the pack and not the
        // fixture.
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        let (_, trace) = fixture.trace("Collections helper");
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "with nothing activated and no artifact, nothing is known: {routes:?}"
        );
    }

    #[test]
    #[hardwon(
        "#6103: a semantic-model provider counted as a complete inventory and proved a constructor absent"
    )]
    fn kotlin_model_only_constructor_retains_external_type_boundary() {
        use crate::analyzer::semantic_model::CatalogOptions;

        use brokk_bifrost_semantic::analyzer::semantic_model::compiler::CompilerOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::DurablePackSource;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::DurablePackSourceKind;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_semantic::analyzer::semantic_model::source::SourceFormat;

        use brokk_bifrost_semantic::analyzer::semantic_model::compiler::compile_source;

        // Match the policy fixture's workspace-installed model, without pack
        // acquisition. Merely writing this file does not activate the model.
        let model = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../semantic-packs/web-network/jvm/bifrost.web-network-jvm.json"
        ));
        let fixture = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            "package app\nimport java.net.URL\nfun use(x: String): URL = URL(x)\n",
            |root| {
                let models = root.join(".bifrost/semantic-models");
                std::fs::create_dir_all(&models).unwrap();
                std::fs::write(models.join("bifrost.web-network-jvm.json"), model).unwrap();
                jvm_config_with_artifact_jar(None)
            },
        );
        let pack = compile_source(
            SourceFormat::Json,
            model.as_bytes(),
            &CompilerOptions::default(),
        )
        .expect("compile reviewed JVM model");
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "workspace-network-model".into(),
                },
            )
            .unwrap();
        activate_fixture_catalog(
            &fixture,
            &catalog,
            "bifrost.web-network-jvm",
            activation_evidence("java", "jdk", "java.base"),
        );
        for needle in ["URL =", "URL(x)"] {
            let (outcome, trace) = fixture.trace_via_probe_entry_point(needle);
            assert_eq!(
                outcome.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "{needle}: {outcome:#?} {trace:#?}"
            );
            let routes = external_routes(&trace);
            assert!(
                routes
                    .iter()
                    .all(|(_, target)| target.as_deref() == Some("java.net.URL")),
                "{routes:#?}"
            );
        }
    }

    #[test]
    fn the_public_traced_batch_reports_workspace_local_for_an_in_workspace_reference() {
        // A reference that never leaves the workspace draws no boundary route
        // at all; `TraceCandidate::selected` defaults every row's boundary to
        // `WorkspaceLocal`, so that is the honest reading for a plain
        // in-workspace hit rather than a value `finish_boundary` stamped.
        let fixture = BoundaryFixture::new(
            Language::Java,
            "app/Caller.java",
            concat!(
                "package app;\n",
                "class Helper {}\n",
                "class Caller {\n",
                "  Helper helper() { return null; }\n",
                "}\n",
            ),
        );
        let (outcome, trace) = fixture.trace_via_probe_entry_point("Helper helper");
        assert_eq!(outcome.status, DefinitionLookupStatus::Resolved);
        let selected: Vec<_> = trace.selected().collect();
        assert!(
            !selected.is_empty(),
            "a resolved reference reports the candidate it selected: {:?}",
            trace.candidates
        );
        assert!(
            selected
                .iter()
                .all(|row| row.boundary == BoundaryStatus::WorkspaceLocal),
            "an in-workspace selection is workspace-local: {selected:?}"
        );
        assert_eq!(
            dispatch_quality_for_status(Some(outcome.status), None),
            DispatchQuality::Complete
        );
    }

    #[test]
    fn the_public_traced_batch_agrees_with_direct_boundary_evidence_for_a_pack_indexed_reference() {
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        let pack = jdk_collections_pack(serde_json::json!([]));
        activate_fixture_pack(
            &fixture,
            "fixture.jdk",
            &pack,
            activation_evidence("java", "jdk", "java.base"),
        );

        let (outcome, trace) = fixture.trace_via_probe_entry_point("Collections helper");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary
        );
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("java.util.Collections")
            }),
            "the activated pack declares `java.util.Collections`: {routes:?}"
        );

        // Chain-link agreement (#1885): the direct evidence call must name the
        // same boundary and target the trace already stamped on the row,
        // because both read the same `boundary_evidence` fact.
        let (direct_status, direct_target) = boundary_evidence(
            fixture.workspace.analyzer(),
            &fixture.file,
            "java.util.Collections",
        );
        assert_eq!(direct_status, BoundaryStatus::ExternalIndexed);
        assert_eq!(direct_target.as_deref(), Some("java.util.Collections"));

        assert_eq!(
            dispatch_quality_for_status(Some(outcome.status), Some(direct_status)),
            DispatchQuality::Complete
        );
    }

    #[test]
    fn the_public_traced_batch_agrees_with_direct_boundary_evidence_without_the_pack() {
        // Same reference, no pack activated: dependency discovery never ran
        // for this fixture (`jvm_config_with_artifact_jar` disables it), so
        // there is no retained evidence to refine the miss into
        // `ExternalDeclaredUnindexed`. The honest answer here is
        // `ExternalUnknown`, matching
        // `a_java_reference_without_the_pack_stays_external_unknown` above.
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );

        let (outcome, trace) = fixture.trace_via_probe_entry_point("Collections helper");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary
        );
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "with nothing activated and no artifact, nothing is known: {routes:?}"
        );

        let (direct_status, direct_target) = boundary_evidence(
            fixture.workspace.analyzer(),
            &fixture.file,
            "java.util.Collections",
        );
        assert_eq!(direct_status, BoundaryStatus::ExternalUnknown);
        assert_eq!(direct_target, None);

        assert_eq!(
            dispatch_quality_for_status(Some(outcome.status), Some(direct_status)),
            DispatchQuality::Unknown
        );
    }
    #[hardwon("#1893: Kotlin resolution ignored selected JVM declaration-facts packs")]
    #[test]
    fn a_kotlin_import_of_a_pack_declared_jvm_type_reports_external_indexed() {
        // Java, Kotlin and Scala share one classpath and therefore one external
        // declaration surface, so a pack published for `language: java` answers
        // a Kotlin reference to the same type.
        let fixture = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            JVM_PACK_KOTLIN_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        let pack = jdk_collections_pack(serde_json::json!([]));
        activate_fixture_pack(
            &fixture,
            "fixture.jdk",
            &pack,
            activation_evidence("java", "jdk", "java.base"),
        );
        let (_, trace) = fixture.trace("Collections? = null");
        let routes = external_routes(&trace);
        assert!(
            routes.iter().all(|(boundary, target)| {
                *boundary == BoundaryStatus::ExternalIndexed
                    && target.as_deref() == Some("java.util.Collections")
            }),
            "the activated pack declares `java.util.Collections`: {routes:?}"
        );
    }

    #[test]
    fn a_pack_for_another_language_never_answers_a_jvm_name() {
        // Near miss: an activated pack that publishes the very same qualified
        // name for a different ecosystem's language. The JVM realm is Java,
        // Kotlin and Scala, so this one is not on the classpath and must not
        // upgrade the reference.

        use brokk_bifrost_semantic::analyzer::semantic_model::identity::TypeIdentity;

        use brokk_bifrost_semantic::analyzer::semantic_model::identity::type_declaration_id;

        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        let type_id = type_declaration_id(TypeIdentity {
            ecosystem: "composer",
            name: "java.util.Collections",
        });
        activate_fixture_pack(
            &fixture,
            "fixture.php.impostor",
            &single_type_pack(
                "fixture.php.impostor",
                "php",
                "composer",
                "vendor/impostor",
                &type_id,
                "java.util.Collections",
                serde_json::json!([]),
            ),
            activation_evidence("php", "composer", "vendor/impostor"),
        );
        let (_, trace) = fixture.trace("Collections helper");
        let routes = external_routes(&trace);
        assert!(
            routes
                .iter()
                .all(|(boundary, _)| *boundary == BoundaryStatus::ExternalUnknown),
            "a pack for another language declares nothing on the classpath: {routes:?}"
        );
    }
    #[hardwon("#1893: indexed external routes were incorrectly recorded as rejected candidates")]
    #[test]
    fn an_indexed_external_route_is_the_selection_and_an_unknown_one_is_not() {
        // The trace's outcome column, not just its boundary column: a route
        // that named an exact external declaration is what the reference
        // resolved to, so a policy asking "did this resolve through a real
        // route" has a selection to read. A route that named nothing stays
        // rejected, so the same question is honestly unanswerable.
        let fixture = BoundaryFixture::with_config(
            Language::Java,
            "app/Caller.java",
            JVM_PACK_JAVA_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        let pack = jdk_collections_pack(serde_json::json!([]));
        activate_fixture_pack(
            &fixture,
            "fixture.jdk",
            &pack,
            activation_evidence("java", "jdk", "java.base"),
        );

        let (_, trace) = fixture.trace("Collections helper");
        let declared: Vec<_> = trace
            .candidates
            .iter()
            .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
            .collect();
        assert!(
            !declared.is_empty()
                && declared.iter().all(|row| {
                    row.is_selected() && row.tier == Some(PrecedenceTier::ExternalRoot)
                }),
            "the pack named the declaration, so the route is the selection: {declared:?}"
        );

        let (_, trace) = fixture.trace("ArrayList names");
        let unknown: Vec<_> = trace
            .candidates
            .iter()
            .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
            .collect();
        assert!(
            !unknown.is_empty() && unknown.iter().all(|row| !row.is_selected()),
            "nothing named this declaration, so nothing was selected: {unknown:?}"
        );
    }

    #[hardwon(
        "#1900: Kotlin and Scala member spellings did not reach the shared JVM external member surface"
    )]
    #[test]
    fn the_shared_surface_answers_a_kotlin_and_a_scala_member_spelling() {
        // Java, Kotlin and Scala share one classpath and therefore one external
        // declaration surface, members included: a pack published for
        // `language: java` answers a member spelling written in any of them,
        // each resolved through its own language's import ladder for the owner.
        //
        // This asserts at the boundary-evidence seam; the two tests below carry
        // the same claim end to end through each resolver's own boundary gate.
        const KOTLIN_MEMBER_SOURCE: &str = concat!(
            "package app\n",
            "import java.util.Collections\n",
            "class Caller {\n",
            "  fun order(names: MutableList<String>) { Collections.sort(names) }\n",
            "}\n",
        );
        const SCALA_MEMBER_SOURCE: &str = concat!(
            "package app\n",
            "import java.util.Collections\n",
            "class Caller {\n",
            "  def order(names: java.util.List[String]): Unit = Collections.sort(names)\n",
            "}\n",
        );

        let kotlin = BoundaryFixture::with_config(
            Language::Kotlin,
            "app/Caller.kt",
            KOTLIN_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        activate_fixture_pack(
            &kotlin,
            "fixture.jdk",
            &jdk_collections_pack(collections_sort_member()),
            activation_evidence("java", "jdk", "java.base"),
        );
        let analyzer = kotlin.workspace.analyzer();
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let evidence = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            brokk_bifrost_jvm_analysis::analyzer::KotlinAnalyzer,
        >(analyzer)
        .expect("the Kotlin fixture has a Kotlin analyzer")
        .external_boundary_evidence(
            token,
            analyzer.semantic_model_overlay(),
            &kotlin.file,
            "Collections.sort",
        );
        assert_eq!(
            evidence,
            (
                BoundaryStatus::ExternalIndexed,
                Some("java.util.Collections.sort".to_owned())
            ),
            "Kotlin's import ladder reaches the pack-declared member"
        );

        let scala = BoundaryFixture::with_config(
            Language::Scala,
            "app/Caller.scala",
            SCALA_MEMBER_SOURCE,
            |_| jvm_config_with_artifact_jar(None),
        );
        activate_fixture_pack(
            &scala,
            "fixture.jdk",
            &jdk_collections_pack(collections_sort_member()),
            activation_evidence("java", "jdk", "java.base"),
        );
        let analyzer = scala.workspace.analyzer();
        let evidence = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            brokk_bifrost_jvm_analysis::analyzer::ScalaAnalyzer,
        >(analyzer)
        .expect("the Scala fixture has a Scala analyzer")
        .external_boundary_evidence(
            token,
            analyzer.semantic_model_overlay(),
            &scala.file,
            "Collections.sort",
        );
        assert_eq!(
            evidence,
            (
                BoundaryStatus::ExternalIndexed,
                Some("java.util.Collections.sort".to_owned())
            ),
            "Scala's import ladder reaches the pack-declared member"
        );
    }
}
