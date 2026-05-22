mod common;

use brokk_bifrost::usages::{FuzzyResult, GoUsageGraphStrategy, UsageAnalyzer, UsageFinder};
use brokk_bifrost::{CodeUnit, GoAnalyzer, IAnalyzer, Language};
use common::InlineTestProject;

fn go_analyzer_with_files(files: &[(&str, &str)]) -> (common::BuiltInlineTestProject, GoAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Go);
    for (path, contents) in files {
        builder = builder.file(path, *contents);
    }
    let project = builder.build();
    let analyzer = GoAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition(analyzer: &GoAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

#[test]
fn usage_finder_routes_go_targets_through_graph_strategy() {
    let (project, analyzer) = go_analyzer_with_files(&[
        ("util/util.go", "package util\nfunc Helper() {}\n"),
        (
            "main.go",
            r#"
package main

import "example.com/app/util"

func run() {
    util.Helper()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "util.Helper");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("go graph success");

    assert_eq!(1, hits.len());
    assert!(hits.iter().all(|hit| hit.file == project.file("main.go")));
}

#[test]
fn go_graph_strategy_finds_same_package_references_without_imports() {
    let (project, analyzer) = go_analyzer_with_files(&[
        ("helper.go", "package main\nfunc helper() {}\n"),
        (
            "consumer.go",
            r#"
package main

func run() {
    helper()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "main.helper");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("same-package go graph success");

    assert_eq!(1, hits.len());
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("consumer.go"))
    );
}

#[test]
fn go_graph_strategy_resolves_qualified_and_aliased_import_selectors() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "config/config.go",
            r#"
package config

const Flag = "on"
var Count = 1
func Build() {}
"#,
        ),
        (
            "main.go",
            r#"
package main

import cfg "example.com/app/config"

func run() {
    cfg.Build()
    _ = cfg.Flag
    cfg.Count = cfg.Count + 1
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = GoUsageGraphStrategy::new();
    for fq_name in [
        "config.Build",
        "config._module_.Flag",
        "config._module_.Count",
    ] {
        let target = definition(&analyzer, fq_name);
        let hits = strategy
            .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
            .into_either()
            .unwrap_or_else(|err| panic!("{fq_name} should resolve through alias: {err}"));
        assert!(!hits.is_empty(), "{fq_name} should have graph hits");
    }
}

#[test]
fn go_graph_strategy_resolves_dot_imports_and_ignores_blank_imports() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        ("util/util.go", "package util\nfunc Helper() {}\n"),
        ("sidefx/sidefx.go", "package sidefx\nfunc Helper() {}\n"),
        (
            "main.go",
            r#"
package main

import . "example.com/app/util"
import _ "example.com/app/sidefx"

func run() {
    Helper()
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = GoUsageGraphStrategy::new();
    let util_helper = definition(&analyzer, "util.Helper");
    let sidefx_helper = definition(&analyzer, "sidefx.Helper");

    let util_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&util_helper),
            &candidates,
            1000,
        )
        .into_either()
        .expect("dot import should resolve direct helper usage");
    assert_eq!(1, util_hits.len());

    let sidefx_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&sidefx_helper),
            &candidates,
            1000,
        )
        .into_either()
        .expect("blank import query should succeed with no proven hits");
    assert!(
        sidefx_hits.is_empty(),
        "blank imports should not seed direct usages"
    );
}

#[test]
fn go_graph_strategy_resolves_versioned_module_suffix_imports() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "vendor/gopkg.in/yaml.v3/yaml.go",
            "package yaml\nfunc Marshal(in any) []byte { return nil }\n",
        ),
        (
            "main.go",
            r#"
package main

import "gopkg.in/yaml.v3"

func run() {
    _ = yaml.Marshal(nil)
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "yaml.Marshal");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("versioned import path should resolve");

    assert_eq!(1, hits.len());
}

#[test]
fn go_graph_strategy_does_not_match_unrelated_same_name_packages() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        ("alpha/service.go", "package alpha\ntype Service struct{}\n"),
        ("beta/service.go", "package beta\ntype Service struct{}\n"),
        (
            "main.go",
            r#"
package main

import "example.com/app/beta"

func run() {
    _ = beta.Service{}
}
"#,
        ),
    ]);

    let alpha = definition(&analyzer, "alpha.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&alpha), &candidates, 1000)
        .into_either()
        .expect("negative query should still succeed");

    assert!(hits.is_empty());
}

#[test]
fn go_graph_strategy_respects_explicit_candidate_file_boundaries() {
    let (project, analyzer) = go_analyzer_with_files(&[
        ("util/util.go", "package util\nfunc Helper() {}\n"),
        (
            "a.go",
            r#"
package main

import "example.com/app/util"

func a() {
    util.Helper()
}
"#,
        ),
        (
            "b.go",
            r#"
package main

import "example.com/app/util"

func b() {
    util.Helper()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "util.Helper");
    let candidates = [project.file("a.go")].into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("candidate-limited query should succeed");

    assert_eq!(1, hits.len());
    assert!(hits.iter().all(|hit| hit.file == project.file("a.go")));
}

#[test]
fn go_graph_strategy_finds_type_references_in_common_type_positions() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "model/album.go",
            r#"
package model

type Album struct{}
type Box[T any] struct{ Item T }
"#,
        ),
        (
            "core/reader.go",
            r#"
package core

import "example.com/app/model"

type Holder struct {
    Field model.Album
    Items []model.Album
}

type Reader interface {
    Read(model.Album) model.Album
}

func Build(album model.Album) model.Album {
    _ = model.Box[model.Album]{}
    return model.Album{}
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "model.Album");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("type references should resolve");

    assert!(
        hits.len() >= 5,
        "expected multiple type-position hits: {hits:?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("core/reader.go"))
    );
}

#[test]
fn go_graph_strategy_finds_type_references_in_pointer_map_channel_and_embedded_fields() {
    let (project, analyzer) = go_analyzer_with_files(&[
        ("model/album.go", "package model\ntype Album struct{}\n"),
        (
            "core/types.go",
            r#"
package core

import "example.com/app/model"

type Holder struct {
    *model.Album
    ByName map[string]model.Album
    Stream chan model.Album
    Receive <-chan *model.Album
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "model.Album");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("expanded type positions should resolve");

    assert!(
        hits.len() >= 4,
        "expected map/channel/pointer/embedded type-position hits: {hits:?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("core/types.go"))
    );
}

#[test]
fn go_graph_strategy_finds_methods_and_fields_through_local_receiver_inference() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "model/album.go",
            r#"
package model

type Album struct {
    ImageFiles string
}

func (a Album) Title() string { return "" }
"#,
        ),
        (
            "core/reader.go",
            r#"
package core

import "example.com/app/model"

func Read(album model.Album) string {
    var ptr *model.Album
    album.ImageFiles = "cover.jpg"
    _ = album.ImageFiles
    _ = album.Title()
    _ = ptr.Title()
    return ""
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let field = definition(&analyzer, "model.Album.ImageFiles");
    let method = definition(&analyzer, "model.Album.Title");
    let strategy = GoUsageGraphStrategy::new();

    let field_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&field), &candidates, 1000)
        .into_either()
        .expect("field references should resolve");
    assert_eq!(2, field_hits.len());
    assert!(
        field_hits
            .iter()
            .all(|hit| hit.file == project.file("core/reader.go"))
    );

    let method_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&method), &candidates, 1000)
        .into_either()
        .expect("method references should resolve");
    assert_eq!(2, method_hits.len());
}

#[test]
fn go_graph_strategy_seeds_members_from_pointer_params_constructors_and_alias_chains() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "model/album.go",
            r#"
package model

type Album struct {
    ImageFiles string
}

func (a *Album) Title() string { return "" }
"#,
        ),
        (
            "core/reader.go",
            r#"
package core

import "example.com/app/model"

func FromPointerParam(album *model.Album) string {
    return album.Title()
}

func FromVar() string {
    var album model.Album
    return album.Title()
}

func FromConstructors() string {
    album := model.Album{}
    ptr := &model.Album{}
    copy := album
    next := copy
    return album.Title() + ptr.Title() + next.Title()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "model.Album.Title");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("receiver seed forms should resolve");

    assert_eq!(5, hits.len(), "receiver seed hits: {hits:?}");
}

#[test]
fn go_graph_strategy_keeps_member_receiver_proofs_conservative() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "model/album.go",
            r#"
package model

type Album struct {
    ImageFiles string
}

func (a Album) Title() string { return "" }
"#,
        ),
        (
            "other/album.go",
            r#"
package other

type Album struct {
    ImageFiles string
}

func (a Album) Title() string { return "" }
"#,
        ),
        (
            "core/reader.go",
            r#"
package core

import "example.com/app/model"
import "example.com/app/other"

type Wrapper struct {
    model.Album
}

func readUnknown(album any) string {
    return album.Title()
}

func readOther(otherAlbum other.Album) string {
    return otherAlbum.ImageFiles + otherAlbum.Title()
}

func readInterface() string {
    var x interface{ Title() string }
    return x.Title()
}

func readEmbedded(wrapper Wrapper) string {
    return wrapper.ImageFiles + wrapper.Title()
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let field = definition(&analyzer, "model.Album.ImageFiles");
    let method = definition(&analyzer, "model.Album.Title");
    let strategy = GoUsageGraphStrategy::new();

    let field_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&field), &candidates, 1000)
        .into_either()
        .expect("field negative query should succeed");
    assert!(
        field_hits.is_empty(),
        "unproven, unrelated, and embedded-promoted fields should not count"
    );

    let method_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&method), &candidates, 1000)
        .into_either()
        .expect("method negative query should succeed");
    assert!(
        method_hits.is_empty(),
        "dynamic interface, unrelated owner, and embedded-promoted methods should not count"
    );
}

#[test]
fn go_graph_strategy_respects_local_shadowing_of_imported_package_aliases_and_dot_imports() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        ("model/model.go", "package model\nfunc Helper() {}\n"),
        (
            "core/reader.go",
            r#"
package core

import model "example.com/app/model"
import . "example.com/app/model"

type local struct{}
func (local) Helper() {}

func shadowPackageAlias() {
    model := local{}
    model.Helper()
}

func shadowDotImport() {
    Helper := func() {}
    Helper()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "model.Helper");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("shadowing query should succeed");

    assert!(
        hits.is_empty(),
        "local shadows should block imported package and dot-import proofs"
    );
}

#[test]
fn go_graph_strategy_enforces_max_usages_limit() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        ("helper.go", "package main\nfunc helper() {}\n"),
        (
            "consumer.go",
            r#"
package main

func run() {
    helper()
    helper()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "main.helper");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = GoUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1,
    );

    assert!(matches!(
        result,
        FuzzyResult::TooManyCallsites {
            total_callsites: 2,
            limit: 1,
            ..
        }
    ));
}
