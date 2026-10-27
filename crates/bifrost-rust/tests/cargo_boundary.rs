//! Cargo manifest/path boundary tests. The oracle is the authored workspace,
//! independently checked with `cargo metadata --offline --no-deps`.
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use brokk_bifrost_rust::cargo_config::RustCargoConfiguration;
use brokk_bifrost_rust::cargo_manifest::RustCargoManifestDocument;
use brokk_bifrost_rust::selected_context::{
    RustSelectedManifestMount, RustSelectedTopologySourceMount,
    prepare_rust_selected_topology_input, rust_crate_targets,
};
use git2::Oid;

fn fixture_files() -> Vec<(PathBuf, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cargo-matrix");
    let mut pending = vec![root.clone()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(std::fs::read_dir(path).unwrap().map(|e| e.unwrap().path()));
        } else if path.file_name().unwrap() != "expected.txt"
            && path.file_name().unwrap() != "Cargo.lock"
        {
            files.push((
                path.strip_prefix(&root).unwrap().to_owned(),
                std::fs::read_to_string(path).unwrap(),
            ));
        }
    }
    files.sort();
    files
}

#[test]
fn cargo_boundary_workspace_matrix() {
    let files = fixture_files();
    // Input ordering must not decide target ownership or feature unification.
    for reverse in [false, true] {
        let mut manifests = Vec::new();
        let mut paths = Vec::new();
        for (path, source) in &files {
            if path.file_name().unwrap() == "Cargo.toml" {
                manifests.push(RustSelectedManifestMount::from_source(path, source).unwrap());
            } else {
                paths.push((path.clone(), Oid::zero()));
            }
        }
        if reverse {
            manifests.reverse();
            paths.reverse();
        }
        let naming =
            brokk_bifrost_rust::crate_naming::RustSelectedCargoNaming::from_selected_inputs(
                paths.iter().map(|(path, _)| path.clone()),
                &manifests,
            )
            .unwrap();
        let anchor = naming
            .resolve_package_anchor(
                brokk_bifrost_core::analyzer::PackageAnchor::CrateRoot,
                "",
                Path::new("nested/src/bin/deep/inner/child.rs"),
            )
            .unwrap();
        assert_eq!(
            anchor
                .display(brokk_bifrost_core::analyzer::fq_name::segment_interner())
                .to_string(),
            "nested.bin.deep"
        );
        let without_member = manifests
            .iter()
            .filter(|m| m.relative_path != Path::new("member/Cargo.toml"))
            .cloned()
            .collect();
        let reduced = rust_crate_targets(
            paths.clone(),
            without_member,
            &RustCargoConfiguration::default(),
        )
        .unwrap();
        let dep = reduced
            .iter()
            .find(|t| t.manifest_path == Path::new("dep/Cargo.toml"))
            .unwrap();
        assert_eq!(
            dep.features,
            ["leaf_feature".to_string()].into_iter().collect(),
            "workspace dependency features apply only through the inheriting member"
        );
        let targets =
            rust_crate_targets(paths, manifests, &RustCargoConfiguration::default()).unwrap();
        let mut rows = Vec::new();
        for target in targets {
            let mut row = format!(
                "{} | {} | {:?} | {} | {:?} | {:?} | complete={}",
                target.manifest_path.to_string_lossy().replace('\\', "/"),
                target.root_path.to_string_lossy().replace('\\', "/"),
                target.kind,
                target.name,
                target.edition,
                target.features,
                target.inventory_complete
            );
            for dep in target.dependencies {
                write!(
                    row,
                    " | {}:{:?}:{}",
                    dep.extern_name,
                    dep.kind,
                    dep.manifest_path
                        .map(|p| p.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_else(|| "external".into())
                )
                .unwrap();
            }
            rows.push(row);
        }
        rows.sort();
        let actual = rows.join("\n") + "\n";
        let expected = include_str!("fixtures/cargo-matrix/expected.txt");
        assert_eq!(expected, actual);
    }
}

#[test]
fn cargo_boundary_target_edits_invalidate_topology_identity() {
    // Each edit changes Cargo metadata's target inventory or test selection;
    // comments, whitespace and table-key order do not.
    let source = "[package]\nname='app'\nversion='0.1.0'\n[[bin]]\nname='tool'\npath='custom/a.rs'\ntest=true\n";
    let digest = |s: &str| {
        RustCargoManifestDocument::from_source(s)
            .unwrap()
            .topology_digest()
    };
    for edited in [
        source.replace("tool", "other"),
        source.replace("a.rs", "b.rs"),
        source.replace("test=true", "test=false"),
    ] {
        assert_ne!(digest(source), digest(&edited), "{edited}");
    }
    for edited in [
        format!("# comment\n{source}"),
        source.replace(
            "name='tool'\npath='custom/a.rs'",
            "path = 'custom/a.rs'\nname = 'tool'",
        ),
    ] {
        assert_eq!(digest(source), digest(&edited));
    }
}

#[test]
fn cargo_boundary_mounts_reject_escaping_and_noncanonical_paths() {
    for path in ["../escape.rs", "a/../b.rs"] {
        let source = RustSelectedTopologySourceMount {
            relative_path: path.into(),
            content_oid: Oid::zero(),
            facts: Default::default(),
        };
        let error = prepare_rust_selected_topology_input([source], [])
            .err()
            .expect("reject an invalid mount");
        assert!(
            error.contains("source mount path is not normalized"),
            "reject at the mount boundary before source materialization: {error}"
        );
    }
    let source = RustSelectedTopologySourceMount {
        relative_path: "b.rs".into(),
        content_oid: Oid::zero(),
        facts: Default::default(),
    };
    assert!(prepare_rust_selected_topology_input([source.clone()], []).is_ok());
    assert!(prepare_rust_selected_topology_input([source.clone(), source], []).is_err());
}

fn parsed_fixture() -> (
    Vec<brokk_bifrost_rust::selected_context::RustSelectedSourceMount>,
    Vec<RustSelectedManifestMount>,
) {
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_rust::declarations::parse_rust_file;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .unwrap();
    let mut sources = Vec::new();
    let mut manifests = Vec::new();
    for (path, text) in fixture_files() {
        if path.file_name().unwrap() == "Cargo.toml" {
            manifests.push(RustSelectedManifestMount::from_source(path, &text).unwrap());
        } else if path.extension().is_some_and(|s| s == "rs") {
            let file = ProjectFile::new(root.clone(), path.clone());
            let tree = parser.parse(&text, None).unwrap();
            assert!(!tree.root_node().has_error(), "{path:?}");
            let parsed = parse_rust_file(&file, &text, &tree);
            sources.push(
                brokk_bifrost_rust::selected_context::RustSelectedSourceMount {
                    relative_path: path,
                    content_oid: git2::Oid::hash_object(git2::ObjectType::Blob, text.as_bytes())
                        .unwrap(),
                    facts: parsed.rust_usage_facts,
                    resolution_facts: parsed.resolution_facts,
                },
            );
        }
    }
    (sources, manifests)
}

#[test]
fn cargo_boundary_structured_module_ownership() {
    use brokk_bifrost_rust::selected_context::{
        RustCallerTargetKind, build_rust_selected_context, rust_selected_workspace_profiles,
    };
    let (sources, manifests) = parsed_fixture();
    let topology = sources
        .iter()
        .map(|s| RustSelectedTopologySourceMount {
            relative_path: s.relative_path.clone(),
            content_oid: s.content_oid,
            facts: s.facts.clone(),
        })
        .collect::<Vec<_>>();
    let inventory = rust_selected_workspace_profiles(&topology, &manifests).unwrap();
    for test in [false, true] {
        let profile = inventory
            .profiles
            .iter()
            .find(|p| {
                p.manifest_path == Path::new("app/Cargo.toml")
                    && p.target_kind == RustCallerTargetKind::Library
                    && p.test == test
            })
            .unwrap();
        let context =
            build_rust_selected_context(sources.clone(), manifests.clone(), profile.clone())
                .unwrap();
        let mut memberships = context
            .target_memberships
            .iter()
            .filter(|m| m.crate_root == Path::new("app/src/lib.rs"))
            .map(|m| {
                format!(
                    "{}:{}",
                    m.file.to_string_lossy().replace('\\', "/"),
                    m.module_segments.join("::")
                )
            })
            .collect::<Vec<_>>();
        memberships.sort();
        let mut expected = vec![
            "app/src/lib.rs:",
            "app/src/lib.rs:consumer",
            "app/src/lib.rs:empty",
            "app/src/lib.rs:outer",
            "app/src/lib.rs:outer::empty",
            "app/src/lib.rs:outer::inner",
            "app/src/branch.rs:branch",
            "app/src/branch/leaf.rs:branch::leaf",
            "app/src/part.rs:outer",
            "app/src/shadowed.rs:shadowed",
            "app/src/root_part.rs:",
        ];
        // Selected profiles use the host cfg inventory, including cfg(test),
        // independently of their dependency-routing test flag.
        expected.push("app/src/test_only.rs:test_only");
        expected.sort();
        assert_eq!(expected, memberships);
        assert!(
            !context
                .root_bridges
                .iter()
                .any(|b| b.source_name == "Incorrect"),
            "a type import shadows the extern crate spelling"
        );
        let chosen = context
            .root_bridges
            .iter()
            .filter(|b| b.source_name == "Chosen")
            .map(|b| b.target_file.as_path())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            chosen,
            [Path::new("app/src/lib.rs")].into_iter().collect(),
            "the selected crate owns outer::inner::Item"
        );
        let mut placements = context
            .include_splices
            .iter()
            .map(|s| {
                (
                    s.included_file.to_string_lossy().replace('\\', "/"),
                    s.host_module.clone(),
                )
            })
            .collect::<Vec<_>>();
        placements.sort();
        assert_eq!(
            placements,
            vec![
                ("app/src/part.rs".into(), "outer".into()),
                ("app/src/root_part.rs".into(), "".into())
            ]
        );
    }
}

#[test]
fn cargo_boundary_detached_cfg_has_test_but_no_cargo_features() {
    use brokk_bifrost_rust::selected_context::{
        RustSelectedActivation, RustSelectedLibraryContextOutcome,
        build_rust_selected_library_context_for_caller,
    };
    let (sources, manifests) = parsed_fixture();
    let topology = sources
        .into_iter()
        .map(|s| RustSelectedTopologySourceMount {
            relative_path: s.relative_path,
            content_oid: s.content_oid,
            facts: s.facts,
        })
        .collect::<Vec<_>>();
    let RustSelectedLibraryContextOutcome::Ready(context) =
        build_rust_selected_library_context_for_caller(
            &topology,
            &manifests,
            Path::new("app/loose.rs"),
        )
        .unwrap()
    else {
        panic!("detached context");
    };
    assert!(
        context.profile.test,
        "detached files admit test declarations"
    );
    assert!(
        context.profile.features.is_empty(),
        "no Cargo target owns this file"
    );
    let activations = context
        .module_activations
        .iter()
        .filter(|m| m.file == Path::new("app/loose.rs") && !m.module_name.is_empty())
        .map(|m| (m.module_name.as_str(), m.activation))
        .collect::<Vec<_>>();
    assert_eq!(
        activations,
        vec![
            ("enabled", RustSelectedActivation::Unknown),
            ("tests", RustSelectedActivation::Active),
            ("vector", RustSelectedActivation::Unknown)
        ]
    );
}

#[test]
fn cargo_boundary_legacy_module_graph_matches_reachability() {
    use brokk_bifrost_core::{analyzer::ProjectFile, hash::HashMap};
    use brokk_bifrost_rust::cargo_routes::RustCargoRouteIndex;
    use brokk_bifrost_rust::declarations::parse_rust_file;
    // A diamond shared by two Cargo roots. A separate cfg(test) branch has
    // a child without its own cfg; neither belongs to production reachability.
    let root = tempfile::tempdir().unwrap();
    let definitions = [
        (
            "Cargo.toml",
            "[package]\nname='graph'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nexternal-package='1'\ndirect={path='direct'}\n[patch.crates-io]\nexternal-package={path='patched'}\n",
        ),
        (
            "patched/Cargo.toml",
            "[package]\nname='external-package'\nversion='1.0.0'\nedition='2021'\n[lib]\nname='external_api'\n",
        ),
        ("patched/src/lib.rs", "pub struct Patched;"),
        (
            "direct/Cargo.toml",
            "[package]\nname='direct'\nversion='0.1.0'\nedition='2021'\n",
        ),
        ("direct/src/lib.rs", "pub struct Direct;"),
        (
            "nested-app/Cargo.toml",
            "[package]\nname='nested-app'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nescape={path='../../..'}\n",
        ),
        ("nested-app/src/lib.rs", "pub struct Nested;"),
        ("src/lib.rs", "mod left; mod right; #[cfg(test)] mod tests;"),
        ("src/main.rs", "mod left; mod bin_only; fn main() {}"),
        ("src/left.rs", "#[path=\"shared.rs\"] mod shared;"),
        (
            "src/right.rs",
            "#[path=\"shared.rs\"] mod shared; mod tail;",
        ),
        (
            "src/shared.rs",
            "pub struct Shared; #[path=\"left.rs\"] mod back;",
        ),
        ("src/right/tail.rs", "pub struct Tail; mod deep;"),
        ("src/right/tail/deep.rs", "pub struct Deep; mod terminal;"),
        ("src/right/tail/deep/terminal.rs", "pub struct Terminal;"),
        ("src/bin_only.rs", "pub struct BinaryOnly;"),
        ("src/tests.rs", "mod helper;"),
        ("src/tests/helper.rs", "pub struct Helper;"),
    ];
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .unwrap();
    let mut files = Vec::new();
    let mut facts = HashMap::default();
    for (path, source) in definitions {
        let destination = root.path().join(path);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::write(destination, source).unwrap();
        if path.ends_with(".rs") {
            let file = ProjectFile::new(root.path().to_owned(), path);
            let tree = parser.parse(source, None).unwrap();
            facts.insert(
                file.clone(),
                parse_rust_file(&file, source, &tree)
                    .rust_usage_facts
                    .module_routes,
            );
            files.push(file);
        }
    }
    // This table is the finite graph's independently derived transitive closure.
    let expected = [
        ("direct/src/lib.rs", &["direct/src/lib.rs"][..], false),
        (
            "nested-app/src/lib.rs",
            &["nested-app/src/lib.rs"][..],
            false,
        ),
        ("patched/src/lib.rs", &["patched/src/lib.rs"][..], false),
        ("src/lib.rs", &["src/lib.rs"][..], false),
        ("src/main.rs", &["src/main.rs"][..], false),
        ("src/left.rs", &["src/lib.rs", "src/main.rs"][..], false),
        ("src/right.rs", &["src/lib.rs"][..], false),
        ("src/shared.rs", &["src/lib.rs", "src/main.rs"][..], false),
        ("src/right/tail.rs", &["src/lib.rs"][..], false),
        ("src/right/tail/deep.rs", &["src/lib.rs"][..], false),
        (
            "src/right/tail/deep/terminal.rs",
            &["src/lib.rs"][..],
            false,
        ),
        ("src/bin_only.rs", &["src/main.rs"][..], false),
        ("src/tests.rs", &["src/lib.rs"][..], true),
        ("src/tests/helper.rs", &["src/lib.rs"][..], true),
    ];
    for _ in 0..8 {
        files.rotate_left(1);
        let index = RustCargoRouteIndex::build_while(&files, &facts, &|| true).unwrap();
        let caller = ProjectFile::new(root.path().to_owned(), "src/lib.rs");
        assert_eq!(
            index.resolve_crate_root_file(&caller, "external_api"),
            Some(ProjectFile::new(
                root.path().to_owned(),
                "patched/src/lib.rs"
            ))
        );
        assert_eq!(
            index.resolve_crate_root_file(&caller, "external_package"),
            None
        );
        assert_eq!(
            index.resolve_crate_root_file(
                &ProjectFile::new(root.path().to_owned(), "nested-app/src/lib.rs"),
                "graph"
            ),
            None,
            "an escaping dependency path cannot resolve to the workspace root"
        );
        let partial = files
            .iter()
            .filter(|f| !f.rel_path().starts_with("patched") && !f.rel_path().starts_with("direct"))
            .cloned()
            .collect::<Vec<_>>();
        let partial_index = RustCargoRouteIndex::build_while(&partial, &facts, &|| true).unwrap();
        assert_eq!(
            partial_index.resolve_crate_root_file(&caller, "external_api"),
            Some(ProjectFile::new(
                root.path().to_owned(),
                "patched/src/lib.rs"
            )),
            "patch discovery must find manifests outside the analyzed inventory"
        );
        assert_eq!(
            partial_index.resolve_crate_root_file(&caller, "direct"),
            Some(ProjectFile::new(
                root.path().to_owned(),
                "direct/src/lib.rs"
            )),
            "path-dependency discovery must find manifests outside the analyzed inventory"
        );
        for (path, roots, test_only) in expected {
            let file = ProjectFile::new(root.path().to_owned(), path);
            let mut actual = index
                .target_roots_for_file(&file)
                .iter()
                .map(|f| f.rel_path().to_string_lossy().replace('\\', "/"))
                .collect::<Vec<_>>();
            actual.sort();
            assert_eq!(roots, actual, "{path}");
            assert_eq!(test_only, index.file_is_test_only(&file), "{path}");
        }
    }
}

#[test]
fn cargo_boundary_discovered_routes_follow_manifest_dependency_kinds() {
    use brokk_bifrost_core::{analyzer::ProjectFile, hash::HashMap};
    use brokk_bifrost_rust::cargo_routes::RustCargoRouteIndex;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cargo-matrix")
        .canonicalize()
        .unwrap();
    let (sources, _) = parsed_fixture();
    let files = sources
        .iter()
        .map(|s| ProjectFile::new(root.clone(), s.relative_path.clone()))
        .collect::<Vec<_>>();
    let facts = sources
        .into_iter()
        .map(|s| {
            (
                ProjectFile::new(root.clone(), s.relative_path),
                s.facts.module_routes,
            )
        })
        .collect::<HashMap<_, _>>();
    let index = RustCargoRouteIndex::build_while(&files, &facts, &|| true).unwrap();
    for (caller, alias, target) in [
        ("app/src/lib.rs", "dep_alias", Some("dep/src/lib.rs")),
        ("app/src/lib.rs", "noise", Some("noise/src/lib.rs")),
        ("app/custom/build.rs", "noise", Some("noise/src/lib.rs")),
        ("app/custom/build.rs", "dep_alias", None),
        ("member/src/lib.rs", "dep_alias", Some("dep/src/lib.rs")),
        (
            "nested/src/bin/deep/main.rs",
            "nested",
            Some("nested/src/lib.rs"),
        ),
    ] {
        assert_eq!(
            index.resolve_crate_root_file(&ProjectFile::new(root.clone(), caller), alias),
            target.map(|p| ProjectFile::new(root.clone(), p)),
            "{caller}: {alias}"
        );
    }
    for omitted in ["app/src/main.rs", "app/custom/tool.rs"] {
        let partial = files
            .iter()
            .filter(|f| f.rel_path() != Path::new(omitted))
            .cloned()
            .collect::<Vec<_>>();
        let selected = if omitted == "app/src/main.rs" {
            "app/custom/tool.rs"
        } else {
            "app/src/main.rs"
        };
        let selected = ProjectFile::new(root.clone(), selected);
        let partial_index = RustCargoRouteIndex::build_while(&partial, &facts, &|| true).unwrap();
        assert!(
            partial_index
                .target_roots_for_file(&selected)
                .contains(&selected),
            "an unselected explicit target cannot hide a selected sibling"
        );
    }
    for line in include_str!("fixtures/cargo-matrix/expected.txt").lines() {
        let fields = line.split(" | ").collect::<Vec<_>>();
        let file = ProjectFile::new(root.clone(), fields[1]);
        assert!(
            index.target_roots_for_file(&file).contains(&file),
            "explicit or inferred Cargo root: {}",
            fields[1]
        );
    }
}

#[test]
fn cargo_boundary_selected_units_keep_disjoint_dependency_routes() {
    use brokk_bifrost_core::{analyzer::ProjectFile, hash::HashMap};
    use brokk_bifrost_rust::cargo_routes::{
        RustCargoDependencyKind, RustCargoRouteIndex, RustCargoRouteSummaryRow,
    };
    let root = tempfile::tempdir().unwrap();
    let file = |p: &str| ProjectFile::new(root.path().to_owned(), p);
    let a = file("app/first.rs");
    let b = file("app/second.rs");
    let left = file("left/lib.rs");
    let right = file("right/lib.rs");
    let row = |unit, source: &ProjectFile, dependency: &ProjectFile, dep_unit, alias: &str| {
        RustCargoRouteSummaryRow {
            unit_key: [unit; 32],
            manifest_directory: Some("app".into()),
            target_kind: "bin".into(),
            crate_name: alias.into(),
            edition: "2021".into(),
            development_capable: false,
            root_file: Some(source.clone()),
            root_package: Some(alias.into()),
            dependency_extern_name: Some(alias.into()),
            dependency_kind: Some(RustCargoDependencyKind::Normal),
            dependency_boundary: Some("workspace".into()),
            dependency_unit_key: Some([dep_unit; 32]),
            dependency_target_kind: Some("lib".into()),
            dependency_root_file: Some(dependency.clone()),
            dependency_root_package: Some(alias.into()),
            dependency_manifest_directory: Some(alias.into()),
        }
    };
    let first = row(1, &a, &left, 3, "left");
    let second = row(2, &b, &right, 4, "right");
    let library = |unit, file: &ProjectFile, name: &str| RustCargoRouteSummaryRow {
        unit_key: [unit; 32],
        manifest_directory: Some(name.into()),
        target_kind: "lib".into(),
        crate_name: name.into(),
        root_file: Some(file.clone()),
        root_package: Some(name.into()),
        dependency_extern_name: None,
        dependency_kind: None,
        dependency_boundary: None,
        dependency_unit_key: None,
        dependency_target_kind: None,
        dependency_root_file: None,
        dependency_root_package: None,
        dependency_manifest_directory: None,
        ..first.clone()
    };
    let rows = [
        first.clone(),
        second,
        library(3, &left, "left"),
        library(4, &right, "right"),
    ];
    let index = RustCargoRouteIndex::build_from_summary_rows_while(
        &[a.clone(), b.clone(), left.clone(), right.clone()],
        &HashMap::default(),
        &rows,
        &|| true,
    )
    .unwrap();
    // Explicit input unit edges, rather than package/manifest names, define
    // this four-cell reachability matrix.
    for (source, dependency, permitted) in [
        (&a, &left, true),
        (&a, &right, false),
        (&b, &left, false),
        (&b, &right, true),
    ] {
        assert_eq!(
            index.file_can_reference_target_of(source, dependency),
            permitted,
            "{source:?} -> {dependency:?}"
        );
    }
}

#[test]
fn cargo_boundary_embedded_import_cfg_matches_authored_conjunction() {
    use brokk_bifrost_rust::{cfg::crate_activation, selected_context::RustSelectedActivation};
    let (sources, _) = parsed_fixture();
    let facts = &sources
        .iter()
        .find(|s| s.relative_path == Path::new("app/loose.rs"))
        .unwrap()
        .facts;
    let imports = facts
        .import_targets
        .iter()
        .filter(|i| i.bound_name.as_deref() == Some("Selected"))
        .collect::<Vec<_>>();
    assert_eq!(imports.len(), 1, "the macro must produce an import");
    let custom = facts
        .import_targets
        .iter()
        .find(|i| i.bound_name.as_deref() == Some("BuildScriptSelected"))
        .unwrap();
    assert_eq!(
        crate_activation(&Default::default(), &custom.cfg_condition),
        RustSelectedActivation::Unknown,
        "a custom build-script cfg is not a Cargo feature"
    );
    for outer in [false, true] {
        for inner in [false, true] {
            let atoms = [("outer", outer), ("inner", inner)]
                .into_iter()
                .filter(|(_, enabled)| *enabled)
                .map(|(feature, _)| format!("feature = {feature:?}"))
                .collect();
            assert_eq!(
                crate_activation(&atoms, &imports[0].cfg_condition),
                if outer && inner {
                    RustSelectedActivation::Active
                } else {
                    RustSelectedActivation::Inactive
                }
            );
        }
    }
}

#[test]
fn cargo_boundary_invalid_manifest_flags_report_incomplete_inventory() {
    for key in [
        "autobins",
        "autoexamples",
        "autotests",
        "autobenches",
        "autolib",
    ] {
        let manifest = RustSelectedManifestMount::from_source(
            "Cargo.toml",
            &format!("[package]\nname='bad'\nversion='0.1.0'\nedition='2021'\n{key}='invalid'\n"),
        )
        .unwrap();
        let targets = rust_crate_targets(
            [("src/lib.rs".into(), Oid::zero())],
            vec![manifest],
            &RustCargoConfiguration::default(),
        )
        .unwrap();
        assert!(!targets.is_empty(), "exercise inventory construction");
        assert!(
            targets.iter().all(|t| !t.inventory_complete),
            "invalid {key} cannot certify completeness: {targets:?}"
        );
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "d5446be541d9: quicksilver round 3 survivor review: a cancelled selected-scope walk resumed when later progress calls returned true"
)]
fn cargo_boundary_selected_scope_cancellation_is_not_swallowed() {
    use brokk_bifrost_rust::selected_context::{
        RustCallerTargetKind, RustSelectedBuildOutcome,
        build_rust_selected_topology_context_from_prepared_with_progress,
        rust_selected_workspace_profiles_from_prepared,
    };
    let (sources, manifests) = parsed_fixture();
    let sources = sources
        .into_iter()
        .filter(|s| s.relative_path == Path::new("app/src/lib.rs"))
        .map(|s| RustSelectedTopologySourceMount {
            relative_path: s.relative_path,
            content_oid: s.content_oid,
            facts: s.facts,
        });
    let manifests = manifests.into_iter().filter(|m| {
        m.relative_path == Path::new("app/Cargo.toml") || m.relative_path == Path::new("Cargo.toml")
    });
    let prepared = prepare_rust_selected_topology_input(sources, manifests).unwrap();
    let profile = rust_selected_workspace_profiles_from_prepared(&prepared)
        .unwrap()
        .profiles
        .into_iter()
        .find(|p| p.target_kind == RustCallerTargetKind::Library && !p.test)
        .unwrap();
    let mut work = 0;
    let ready = build_rust_selected_topology_context_from_prepared_with_progress(
        &prepared,
        profile.clone(),
        &mut |_| {
            work += 1;
            true
        },
    )
    .unwrap();
    assert!(matches!(ready, RustSelectedBuildOutcome::Ready(_)));
    assert!(work > 1);
    for stop_at in 0..work {
        let mut visited = 0;
        let mut cancellation_observed = false;
        let result = build_rust_selected_topology_context_from_prepared_with_progress(
            &prepared,
            profile.clone(),
            &mut |_| {
                let live = visited != stop_at;
                cancellation_observed |= !live;
                visited += 1;
                live
            },
        )
        .unwrap();
        assert!(
            cancellation_observed,
            "exercise the cancellation at work event {stop_at}"
        );
        assert!(
            matches!(result, RustSelectedBuildOutcome::Stopped),
            "a rejected work event must stop construction: {stop_at}"
        );
        assert_eq!(
            visited,
            stop_at + 1,
            "stop at the first rejected work event"
        );
    }
}

#[test]
fn cargo_boundary_workspace_ownership_uses_nearest_ancestor() {
    // Literal exclusions only: this intentionally does not settle glob semantics.
    // vendor/deep cannot exclude its parent vendor. The later, deeper z/deep
    // workspace cannot claim unrelated app or vendor packages.
    let documents = [
        (
            "Cargo.toml",
            "[workspace]\nmembers=['app','vendor','other/vendor']\nexclude=['vendor/deep','../vendor','island','z']\n[workspace.package]\nedition='2021'\n",
        ),
        (
            "app/Cargo.toml",
            "[package]\nname='app'\nversion='0.1.0'\nedition.workspace=true\n",
        ),
        (
            "vendor/Cargo.toml",
            "[package]\nname='vendor'\nversion='0.1.0'\nedition.workspace=true\n",
        ),
        (
            "other/vendor/Cargo.toml",
            "[package]\nname='other-vendor'\nversion='0.1.0'\nedition.workspace=true\n",
        ),
        (
            "island/Cargo.toml",
            "[workspace]\nmembers=['member']\n[workspace.package]\nedition='2024'\n",
        ),
        (
            "island/member/Cargo.toml",
            "[package]\nname='island-member'\nversion='0.1.0'\nedition.workspace=true\n",
        ),
        (
            "z/deep/Cargo.toml",
            "[workspace]\nmembers=['member']\n[workspace.package]\nedition='2018'\n",
        ),
        (
            "z/deep/member/Cargo.toml",
            "[package]\nname='z-member'\nversion='0.1.0'\nedition.workspace=true\n",
        ),
    ];
    let manifests = documents
        .into_iter()
        .map(|(path, text)| RustSelectedManifestMount::from_source(path, text).unwrap())
        .collect();
    let targets = rust_crate_targets(
        [
            "app/src/lib.rs",
            "vendor/src/lib.rs",
            "other/vendor/src/lib.rs",
            "island/member/src/lib.rs",
            "z/deep/member/src/lib.rs",
        ]
        .into_iter()
        .map(|p| (PathBuf::from(p), Oid::zero())),
        manifests,
        &RustCargoConfiguration::default(),
    )
    .unwrap();
    let rows = targets
        .into_iter()
        .map(|t| (t.root_path.to_string_lossy().replace('\\', "/"), t.edition))
        .collect::<std::collections::BTreeSet<_>>();
    use brokk_bifrost_rust::selected_context::RustCargoEdition::*;
    assert_eq!(
        rows,
        [
            ("app/src/lib.rs".into(), Rust2021),
            ("vendor/src/lib.rs".into(), Rust2021),
            ("other/vendor/src/lib.rs".into(), Rust2021),
            ("island/member/src/lib.rs".into(), Rust2024),
            ("z/deep/member/src/lib.rs".into(), Rust2018),
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn cargo_boundary_visibility_grammar_agrees_with_requester_permissions() {
    use brokk_bifrost_rust::selected_context::rust_declaration_visibility_reaches;
    let (sources, _) = parsed_fixture();
    let facts = &sources
        .iter()
        .find(|s| s.relative_path == Path::new("app/visibility.rs"))
        .unwrap()
        .facts
        .module_routes;
    let declaring = ["a".to_string(), "b".to_string(), "c".to_string()];
    for (name, allowed) in [
        ("up_two", &["a", "a::b", "a::b::c", "a::sibling"][..]),
        ("in_a", &["a", "a::b", "a::b::c", "a::sibling"][..]),
        ("parent", &["a::b", "a::b::c"][..]),
        ("own", &["a::b::c"][..]),
    ] {
        let scope = facts.scopes.iter().find(|s| s.module_name == name).unwrap();
        for (requester, segments) in [
            ("", vec![]),
            ("a", vec!["a"]),
            ("a::b", vec!["a", "b"]),
            ("a::b::c", vec!["a", "b", "c"]),
            ("a::sibling", vec!["a", "sibling"]),
            ("other", vec!["other"]),
        ] {
            let segments = segments.into_iter().map(str::to_string).collect::<Vec<_>>();
            assert_eq!(
                rust_declaration_visibility_reaches(&scope.visibility, true, &segments, &declaring),
                allowed.contains(&requester),
                "{name}: {requester}"
            );
            assert!(
                !rust_declaration_visibility_reaches(
                    &scope.visibility,
                    false,
                    &segments,
                    &declaring
                ),
                "restricted visibility cannot cross crate boundaries"
            );
        }
    }
}

#[test]
fn cargo_boundary_config_debug_selector_controls_rustflag_precedence() {
    use brokk_bifrost_rust::cargo_config::RustCargoConfigDocument;
    // Independently checked with Cargo's verbose rustc invocation: the
    // positive built-in selector replaces build.rustflags; its negation does not.
    for (selector, selected) in [("debug_assertions", true), ("not(debug_assertions)", false)] {
        let text = format!(
            "[build]\nrustflags=['--cfg','fallback']\n[target.'cfg({selector})']\nrustflags=['--cfg','selected_debug']\n"
        );
        let config = RustCargoConfiguration::from_files([(
            ".cargo/config.toml".into(),
            RustCargoConfigDocument::from_source_bytes(text.as_bytes()).unwrap(),
        )]);
        let atoms = config.cfg_atoms(Path::new(""));
        assert_eq!(
            atoms.contains("selected_debug"),
            selected,
            "{selector}: {atoms:?}"
        );
        assert_eq!(
            atoms.contains("fallback"),
            !selected,
            "{selector}: {atoms:?}"
        );
    }
}

#[test]
fn cargo_boundary_canonical_item_capsule_preserves_lexical_and_member_scope() {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;
    use brokk_bifrost_rust::macro_matcher::{
        RustMacroItemContainer, capture_macro_input, lower_selected_macro_input,
        match_local_macro_invocation,
    };
    // The producer's canonical token snapshot crosses into the selected
    // consumer without the source transcriber. Rust's lexical/associated
    // namespace rule is the independent oracle for the same captured item.
    let source =
        "macro_rules! keep { ($item:item) => { $item }; } keep! { pub const Captured: u8 = 1; }";
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(source, None).unwrap();
    let mut pending = vec![tree.root_node()];
    let mut invocation = None;
    while let Some(node) = pending.pop() {
        if node.kind() == "macro_invocation" {
            invocation = Some(node);
            break;
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    let invocation = invocation.unwrap();
    let arguments =
        brokk_bifrost_rust::declarations::rust_macro_invocation_arguments(invocation).unwrap();
    let input = capture_macro_input(arguments, source, &|| true).unwrap();
    let arm = match_local_macro_invocation(invocation, source)
        .unwrap()
        .unwrap();
    for (container, lexical_names) in [
        (RustMacroItemContainer::Lexical, vec!["Captured"]),
        (RustMacroItemContainer::Associated, vec![]),
    ] {
        let facts = lower_selected_macro_input(&input, &arm, container);
        let names = facts
            .identifiers
            .iter()
            .filter(|i| i.role == ResolutionIdentifierRole::Declaration)
            .map(|i| facts.name(i.name))
            .collect::<Vec<_>>();
        assert_eq!(names, lexical_names, "{container:?}");
    }
}
