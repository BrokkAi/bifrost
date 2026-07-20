mod common;

use brokk_bifrost::IAnalyzer;
use brokk_bifrost::usages::{FuzzyResult, GoUsageGraphStrategy, UsageAnalyzer, UsageFinder};
use common::{definition, go_analyzer_with_files};
use std::collections::BTreeSet;

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

    let target = definition(&analyzer, "example.com/app/util.Helper");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("go graph success");

    assert_eq!(1, hits.len());
    assert!(hits.iter().all(|hit| hit.file == project.file("main.go")));
}

#[test]
fn go_inverse_keeps_package_variable_reads_and_ordinary_writes() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "state.go",
        r#"package app

var uiServerPort int

func packageAccess(port int) int {
    _ = uiServerPort
    uiServerPort = port
    _ = uiServerPort
    return uiServerPort
}

func shortShadow() int {
    uiServerPort := 1
    uiServerPort = uiServerPort + 1
    return uiServerPort
}

func localShadow() int {
    var uiServerPort = 1
    uiServerPort = uiServerPort + 1
    return uiServerPort
}

func parameterShadow(uiServerPort int) int {
    uiServerPort = uiServerPort + 1
    return uiServerPort
}
"#,
    )]);
    let target = definition(&analyzer, "example.com/app._module_.uiServerPort");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let targeted = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("targeted package-variable lookup should resolve");
    let targeted_lines: BTreeSet<_> = targeted.iter().map(|hit| hit.line).collect();
    assert_eq!(
        BTreeSet::from([6, 7, 8, 9]),
        targeted_lines,
        "targeted inverse lookup should retain only the package reads and ordinary write: {targeted:#?}"
    );

    let whole_workspace = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("whole-workspace package-variable lookup should resolve");
    let whole_workspace_lines: BTreeSet<_> = whole_workspace.iter().map(|hit| hit.line).collect();
    assert_eq!(
        BTreeSet::from([6, 7, 8, 9]),
        whole_workspace_lines,
        "whole-workspace inverse lookup should retain the package sites and exclude :=, var, and parameter shadows: {whole_workspace:#?}"
    );
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

    let target = definition(&analyzer, "example.com/app.helper");
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
        "example.com/app/config.Build",
        "example.com/app/config._module_.Flag",
        "example.com/app/config._module_.Count",
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
    let util_helper = definition(&analyzer, "example.com/app/util.Helper");
    let sidefx_helper = definition(&analyzer, "example.com/app/sidefx.Helper");

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

    let target = definition(&analyzer, "example.com/app/vendor/gopkg.in/yaml.v3.Marshal");
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

    let alpha = definition(&analyzer, "example.com/app/alpha.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&alpha), &candidates, 1000)
        .into_either()
        .expect("negative query should still succeed");

    assert!(hits.is_empty());
}

#[test]
fn go_graph_strategy_does_not_resolve_external_same_tail_imports_to_local_packages() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        ("model/model.go", "package model\nfunc Helper() {}\n"),
        (
            "main.go",
            r#"
package main

import "github.com/other/model"

func run() {
    model.Helper()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/model.Helper");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("external same-tail import query should succeed");

    assert!(
        hits.is_empty(),
        "external same-tail imports must not resolve to local packages: {hits:?}"
    );
}

#[test]
fn go_graph_strategy_resolves_go_mod_module_imports() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        ("model/model.go", "package model\nfunc Helper() {}\n"),
        (
            "main.go",
            r#"
package main

import "example.com/app/model"

func run() {
    model.Helper()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/model.Helper");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("module import should resolve");

    assert_eq!(1, hits.len(), "module import hits: {hits:?}");
}

#[test]
fn go_graph_strategy_resolves_root_and_nested_go_modules_without_crossing_siblings() {
    let (project, analyzer) = go_analyzer_with_files(&[
        ("go.mod", "module example.com/root\n\ngo 1.22\n"),
        (
            "pb/message.go",
            r#"
package pb

type Message struct{}

func (Message) Render() {}
"#,
        ),
        ("nested/go.mod", "module example.com/nested/v2\n\ngo 1.22\n"),
        (
            "nested/pb/message.go",
            r#"
package pb

type Message struct{}

func (Message) Render() {}
"#,
        ),
        (
            "root_use.go",
            r#"
package root

import wire "example.com/nested/v2/pb"

func rootUse(value wire.Message) {
    value.Render()
}
"#,
        ),
        (
            "nested/client/use.go",
            r#"
package client

import inner "example.com/nested/v2/pb"

func nestedUse(value inner.Message) {
    value.Render()
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = GoUsageGraphStrategy::new();
    let expected_usage_files = BTreeSet::from([
        project.file("root_use.go"),
        project.file("nested/client/use.go"),
    ]);

    for (fq_name, expected_files) in [
        (
            "example.com/nested/v2/pb.Message",
            BTreeSet::from([
                project.file("root_use.go"),
                project.file("nested/client/use.go"),
                project.file("nested/pb/message.go"),
            ]),
        ),
        (
            "example.com/nested/v2/pb.Message.Render",
            expected_usage_files.clone(),
        ),
    ] {
        let target = definition(&analyzer, fq_name);
        let hits = strategy
            .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
            .into_either()
            .unwrap_or_else(|err| panic!("nested-module target {fq_name} should resolve: {err}"));
        assert_eq!(
            expected_files,
            hits.iter()
                .map(|hit| hit.file.clone())
                .collect::<BTreeSet<_>>(),
            "qualified types and their receiver members should follow the aliased nested-module import: {hits:#?}"
        );
    }

    for (fq_name, expected_files) in [
        (
            "example.com/root/pb.Message",
            BTreeSet::from([project.file("pb/message.go")]),
        ),
        ("example.com/root/pb.Message.Render", BTreeSet::new()),
    ] {
        let target = definition(&analyzer, fq_name);
        let hits = strategy
            .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
            .into_either()
            .unwrap_or_else(|err| panic!("root-module sibling query should succeed: {err}"));
        assert_eq!(
            expected_files,
            hits.iter()
                .map(|hit| hit.file.clone())
                .collect::<BTreeSet<_>>(),
            "same-named root-module siblings must not capture nested-module usages: {hits:#?}"
        );
    }
}

#[test]
fn go_graph_strategy_uses_resolved_package_clause_for_unaliased_imports() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "vendor/github.com/go-chi/chi/v5/router.go",
            "package chi\nfunc NewRouter() {}\n",
        ),
        ("internal/foo/foo.go", "package bar\nfunc Helper() {}\n"),
        (
            "main.go",
            r#"
package main

import "github.com/go-chi/chi/v5"
import "example.com/app/internal/foo"

func run() {
    chi.NewRouter()
    bar.Helper()
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = GoUsageGraphStrategy::new();

    let router = definition(
        &analyzer,
        "example.com/app/vendor/github.com/go-chi/chi/v5.NewRouter",
    );
    let router_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&router), &candidates, 1000)
        .into_either()
        .expect("semantic import version package clause should resolve");
    assert_eq!(1, router_hits.len(), "router hits: {router_hits:?}");

    let helper = definition(&analyzer, "example.com/app/internal/foo.Helper");
    let helper_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&helper), &candidates, 1000)
        .into_either()
        .expect("directory/package name mismatch should resolve");
    assert_eq!(1, helper_hits.len(), "helper hits: {helper_hits:?}");
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

    let target = definition(&analyzer, "example.com/app/util.Helper");
    let candidates = [project.file("a.go")].into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("candidate-limited query should succeed");

    assert_eq!(1, hits.len());
    assert!(hits.iter().all(|hit| hit.file == project.file("a.go")));
}

#[test]
fn go_graph_strategy_builds_from_target_and_candidates_not_unrelated_project_files() {
    let mut files = vec![
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
    ];
    for index in 0..40 {
        let path = Box::leak(format!("unrelated/pkg{index}/noise.go").into_boxed_str());
        let contents =
            Box::leak(format!("package pkg{index}\nfunc Noise{index}() {{}}\n").into_boxed_str());
        files.push((path, contents));
    }
    let (project, analyzer) = go_analyzer_with_files(&files);

    let target = definition(&analyzer, "example.com/app/util.Helper");
    let candidates = [project.file("main.go")].into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("candidate-bounded go graph query should succeed");

    assert_eq!(1, hits.len(), "bounded graph hits: {hits:?}");
    assert!(hits.iter().all(|hit| hit.file == project.file("main.go")));
}

#[test]
fn go_graph_strategy_finds_struct_literal_field_labels_for_exact_owner() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "model.go",
            r#"
package main

type Wanted struct {
    Field string
}

type Other struct {
    Field string
}

const BareMapKey = "Field"
"#,
        ),
        (
            "keys/keys.go",
            r#"
package keys

const MapKey = "Field"
"#,
        ),
        (
            "consumer.go",
            r#"
package main

import "example.com/app/keys"

func build() {
    _ = Wanted{Field: "value"}
    _ = &Wanted{Field: "pointer"}
    _ = Other{Field: "wrong owner"}
    Field := "local"
    _ = map[string]string{Field: "map key"}
    _ = map[string]string{BareMapKey: "bare map expression"}
    _ = map[string]string{keys.MapKey: "map expression"}
    _ = Field
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app.Wanted.Field");
    let candidates = [project.file("consumer.go")].into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("struct literal field labels should resolve through their literal owner");

    assert_eq!(2, hits.len(), "exact-owner field-label hits: {hits:?}");
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("consumer.go"))
    );

    let map_key = definition(&analyzer, "example.com/app/keys._module_.MapKey");
    let map_key_hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&map_key), &candidates, 1000)
        .into_either()
        .expect("a qualified map-key expression remains an ordinary reference");
    assert_eq!(1, map_key_hits.len(), "map-key hits: {map_key_hits:?}");

    let bare_map_key = definition(&analyzer, "example.com/app._module_.BareMapKey");
    let bare_map_key_hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, &[bare_map_key], &candidates, 1000)
        .into_either()
        .expect("a bare map-key expression remains an ordinary reference");
    assert_eq!(
        1,
        bare_map_key_hits.len(),
        "bare map-key hits: {bare_map_key_hits:?}"
    );
}

#[test]
fn go_graph_strategy_propagates_owner_through_elided_composite_values() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "model/model.go",
            r#"
package model

type Wanted struct {
    Field string
}
"#,
        ),
        (
            "other/other.go",
            r#"
package other

type Other struct {
    Field string
}
"#,
        ),
        (
            "consumer.go",
            r#"
package main

import (
    "example.com/app/model"
    "example.com/app/other"
)

var keyedArray = [1]model.Wanted{0: {Field: "array-keyed"}}
var positionalArray = [1]model.Wanted{{Field: "array-positional"}}
var sliceValues = []model.Wanted{{Field: "slice"}}
var mapValues = map[string]model.Wanted{"key": {Field: "map-value"}}
var nestedArrays = [1][1]model.Wanted{{{Field: "nested-array"}}}
var wrongOwner = []other.Other{{Field: "wrong"}}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/model.Wanted.Field");
    let candidates = [project.file("consumer.go")].into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("elided composite values should retain their container element/value owner");

    assert_eq!(5, hits.len(), "elided field-label hits: {hits:?}");
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("consumer.go"))
    );
}

#[test]
fn usage_finder_go_graph_respects_file_filters_as_result_scope() {
    let (project, analyzer) = go_analyzer_with_files(&[
        ("helper.go", "package main\nfunc helper() {}\n"),
        (
            "allowed.go",
            r#"
package main

func allowed() {
    helper()
}
"#,
        ),
        (
            "blocked.go",
            r#"
package main

func blocked() {
    helper()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app.helper");
    let allowed = project.file("allowed.go");
    let hits = UsageFinder::new()
        .with_file_filter(move |file| file == &allowed)
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("filtered go graph query should succeed");

    assert_eq!(1, hits.len(), "filtered hits: {hits:?}");
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("allowed.go"))
    );
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

    let target = definition(&analyzer, "example.com/app/model.Album");
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

    let target = definition(&analyzer, "example.com/app/model.Album");
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
    let field = definition(&analyzer, "example.com/app/model.Album.ImageFiles");
    let method = definition(&analyzer, "example.com/app/model.Album.Title");
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
fn go_graph_strategy_reports_unproven_selector_when_receiver_type_is_unknown() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "model/service.go",
            r#"
package model

type Service struct{}

func (s Service) Run() {}
"#,
        ),
        (
            "core/caller.go",
            r#"
package core

func Call(value any) {
    value.Run()
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let method = definition(&analyzer, "example.com/app/model.Service.Run");
    let result = GoUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&method),
        &candidates,
        1000,
    );

    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
        } => {
            assert!(
                hits_by_overload
                    .get(&method)
                    .is_none_or(|hits| hits.is_empty()),
                "unknown receiver must not be a proven hit: {hits_by_overload:#?}"
            );
            assert_eq!(
                Some(&1),
                unproven_total_by_overload.get(&method),
                "unknown receiver selector should be counted as unproven"
            );
            let unproven = unproven_by_overload
                .get(&method)
                .expect("capped unproven sites");
            assert!(
                unproven.iter().any(|hit| {
                    hit.file == project.file("core/caller.go")
                        && hit.snippet.contains("value.Run()")
                }),
                "expected value.Run() to render as unproven: {unproven:#?}"
            );
        }
        other => panic!("expected success with unproven selector, got {other:#?}"),
    }
}

#[test]
fn go_graph_strategy_finds_promoted_go_embedded_member_usages() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "example/audit.go",
        r#"
package example

type AuditLog struct {
    Last string
}

func (a *AuditLog) Record(message string) string {
    a.Last = message
    return a.Last
}

type Worker struct {
    *AuditLog
}

func NewWorker() *Worker {
    return &Worker{AuditLog: &AuditLog{}}
}

type Unrelated struct{}

func (u Unrelated) Record(message string) string {
    return message
}

func Run() {
    worker := NewWorker()
    worker.Record("start")
    _ = worker.Last

    unrelated := Unrelated{}
    _ = unrelated.Record("skip")
}
"#,
    )]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = GoUsageGraphStrategy::new();

    let method = definition(&analyzer, "example.com/app/example.AuditLog.Record");
    let method_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&method), &candidates, 1000)
        .into_either()
        .expect("promoted embedded method usage should resolve");
    assert_eq!(1, method_hits.len(), "method hits: {method_hits:?}");
    assert!(
        method_hits
            .iter()
            .any(|hit| hit.snippet.contains("worker.Record(\"start\")")),
        "worker.Record should resolve to AuditLog.Record: {method_hits:?}",
    );
    assert!(
        method_hits
            .iter()
            .all(|hit| !hit.snippet.contains("unrelated.Record")),
        "same-name method on unrelated receiver must not match: {method_hits:?}",
    );

    let field = definition(&analyzer, "example.com/app/example.AuditLog.Last");
    let field_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&field), &candidates, 1000)
        .into_either()
        .expect("promoted embedded field usage should resolve");
    assert_eq!(3, field_hits.len(), "field hits: {field_hits:?}");
    assert!(
        field_hits
            .iter()
            .any(|hit| hit.snippet.contains("a.Last = message")),
        "internal assignment should still resolve: {field_hits:?}",
    );
    assert!(
        field_hits
            .iter()
            .any(|hit| hit.snippet.contains("return a.Last")),
        "internal return should still resolve: {field_hits:?}",
    );
    assert!(
        field_hits
            .iter()
            .any(|hit| hit.snippet.contains("_ = worker.Last")),
        "worker.Last should resolve to AuditLog.Last: {field_hits:?}",
    );
}

#[test]
fn go_graph_strategy_respects_go_embedded_promotion_precedence_and_ambiguity() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "example/promotion.go",
        r#"
package example

type Base struct {
    ID string
}

type Service struct {
    Base
    ID int
}

func readOuter(service Service) int {
    return service.ID
}

type BaseWrapper struct {
    Base
}

func NewBaseWrapper() BaseWrapper {
    return BaseWrapper{}
}

func readBaseWrapper(wrapper BaseWrapper) string {
    return wrapper.ID
}

func readBaseWrapperFactory() string {
    wrapper := NewBaseWrapper()
    return wrapper.ID
}

type C struct {
    Code string
}

type B struct {
    C
}

type A struct {
    Code string
}

type Wrapper struct {
    A
    B
}

func readShallow(wrapper Wrapper) string {
    return wrapper.Code
}

type Left struct {
    Name string
}

type Right struct {
    Name string
}

type Ambiguous struct {
    Left
    Right
}

func readAmbiguous(value Ambiguous) string {
    return value.Name
}

type Shared struct {
    Token string
}

type PathA struct {
    Shared
}

type PathB struct {
    Shared
}

type SharedAmbiguous struct {
    PathA
    PathB
}

func readSharedAmbiguous(value SharedAmbiguous) string {
    return value.Token
}

type MLeft struct{}
func (MLeft) Run() {}

type MRight struct{}
func (MRight) Run() {}

type MethodAmbiguous struct {
    MLeft
    MRight
}

func runAmbiguous(value MethodAmbiguous) {
    value.Run()
}

type NamedBase struct {
    Hidden string
}

type NamedWrapper struct {
    NamedBase NamedBase
}

func readNamedWrapper(value NamedWrapper) string {
    return value.Hidden
}
"#,
    )]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = GoUsageGraphStrategy::new();

    let base_id = definition(&analyzer, "example.com/app/example.Base.ID");
    let base_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&base_id), &candidates, 1000)
        .into_either()
        .expect("base ID query should succeed");
    assert_eq!(2, base_hits.len(), "base ID hits: {base_hits:?}");
    assert!(
        base_hits
            .iter()
            .any(|hit| hit.snippet.contains("return wrapper.ID")),
        "non-shadowed promoted Base.ID should count: {base_hits:?}"
    );
    assert!(
        !base_hits
            .iter()
            .any(|hit| hit.snippet.contains("return service.ID")),
        "outer direct ID must shadow promoted Base.ID: {base_hits:?}"
    );

    let service_id = definition(&analyzer, "example.com/app/example.Service.ID");
    let service_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&service_id),
            &candidates,
            1000,
        )
        .into_either()
        .expect("service ID query should succeed");
    assert_eq!(1, service_hits.len(), "service ID hits: {service_hits:?}");
    assert!(
        service_hits
            .iter()
            .any(|hit| hit.snippet.contains("return service.ID")),
        "direct outer ID should count: {service_hits:?}"
    );

    let deep_code = definition(&analyzer, "example.com/app/example.C.Code");
    let deep_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&deep_code),
            &candidates,
            1000,
        )
        .into_either()
        .expect("deep code query should succeed");
    assert!(
        deep_hits.is_empty(),
        "shallower A.Code must shadow deeper C.Code: {deep_hits:?}"
    );

    let shallow_code = definition(&analyzer, "example.com/app/example.A.Code");
    let shallow_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&shallow_code),
            &candidates,
            1000,
        )
        .into_either()
        .expect("shallow code query should succeed");
    assert_eq!(1, shallow_hits.len(), "shallow code hits: {shallow_hits:?}");
    assert!(
        shallow_hits
            .iter()
            .any(|hit| hit.snippet.contains("return wrapper.Code")),
        "shallower promoted field should count: {shallow_hits:?}"
    );

    for fqn in [
        "example.com/app/example.Left.Name",
        "example.com/app/example.Right.Name",
        "example.com/app/example.Shared.Token",
        "example.com/app/example.MLeft.Run",
        "example.com/app/example.MRight.Run",
    ] {
        let target = definition(&analyzer, fqn);
        let hits = strategy
            .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
            .into_either()
            .unwrap_or_else(|err| panic!("{fqn} query should succeed: {err}"));
        assert!(
            hits.is_empty(),
            "ambiguous promoted selector must not count for {fqn}: {hits:?}"
        );
    }

    let named_hidden = definition(&analyzer, "example.com/app/example.NamedBase.Hidden");
    let named_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&named_hidden),
            &candidates,
            1000,
        )
        .into_either()
        .expect("named hidden query should succeed");
    assert!(
        named_hits.is_empty(),
        "named same-name fields must not promote nested fields: {named_hits:?}"
    );
}

#[test]
fn go_graph_strategy_respects_imported_embedded_field_promotion_precedence() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "service/audit.go",
            r#"
package service

type AuditLog struct {
    ID string
}

type Base struct {
    ID string
}

type Wrapper struct {
    Base
}

type Service struct {
    Base
    ID string
}

type Worker struct {
    AuditLog
    Wrapper
}

func NewWorker() *Worker { return &Worker{} }
func NewService() *Service { return &Service{} }
"#,
        ),
        (
            "main.go",
            r#"
package main

import "example.com/app/service"

func use() {
    worker := service.NewWorker()
    _ = worker.ID

    wrapper := service.Wrapper{}
    _ = wrapper.ID

    svc := service.NewService()
    _ = svc.ID
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = GoUsageGraphStrategy::new();

    let base_id = definition(&analyzer, "example.com/app/service.Base.ID");
    let base_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&base_id), &candidates, 1000)
        .into_either()
        .expect("base ID query should succeed");
    assert_eq!(1, base_hits.len(), "base ID hits: {base_hits:?}");
    assert!(
        base_hits
            .iter()
            .any(|hit| hit.file == project.file("main.go") && hit.snippet.contains("wrapper.ID")),
        "only non-shadowed wrapper.ID should count for Base.ID: {base_hits:?}"
    );
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

    let target = definition(&analyzer, "example.com/app/model.Album.Title");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("receiver seed forms should resolve");

    assert_eq!(5, hits.len(), "receiver seed hits: {hits:?}");
}

#[test]
fn go_graph_strategy_classifies_concrete_method_calls_through_interface_fields_as_unproven() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "example/service.go",
            r#"
package example

type Repository interface {
    Save(value string) string
}

const DefaultPrefix = "job"

var DefaultRepository Repository = MemoryRepository{}

type MemoryRepository struct {
    Last string
}

func (m *MemoryRepository) Save(value string) string {
    m.Last = value
    return value
}

type Service struct {
    repository Repository
}

func NewService(repository Repository) Service {
    return Service{repository: repository}
}

func (s Service) Execute(name string) string {
    stored := s.repository.Save(name)
    return DefaultPrefix + ":" + stored
}
"#,
        ),
        (
            "example/service_test.go",
            r#"
package example

func ExampleService() {
    repository := &MemoryRepository{}
    service := NewService(repository)
    result := service.Execute("Ada")
    _ = DefaultRepository
    _ = DefaultPrefix + result
    repository.Save("Grace")
    _ = repository.Last
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/example.MemoryRepository.Save");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = GoUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );

    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
        } => {
            let hits = hits_by_overload
                .get(&target)
                .expect("concrete receiver call should remain proven");
            assert_eq!(1, hits.len(), "proven hits: {hits:?}");
            assert!(
                hits.iter()
                    .all(|hit| hit.file == project.file("example/service_test.go")),
                "only the concrete pointer receiver should be proven: {hits:?}",
            );
            assert_eq!(
                Some(&1),
                unproven_total_by_overload.get(&target),
                "interface dispatch must be counted as unproven",
            );
            assert!(
                unproven_by_overload
                    .get(&target)
                    .is_some_and(|hits| hits.iter().any(|hit| {
                        hit.file == project.file("example/service.go")
                            && hit.snippet.contains("s.repository.Save(name)")
                    })),
                "expected the interface-dispatch call to be unproven: {unproven_by_overload:#?}",
            );
        }
        other => panic!("expected proof-tier result, got {other:#?}"),
    }
}

#[test]
fn go_graph_strategy_finds_interface_receiver_method_calls() {
    let (project, analyzer) = go_analyzer_with_files(&[(
        "pkg/extensions/manager.go",
        r#"
package extensions

import "io"

type ExtensionManager interface {
    Dispatch(args []string, stdin io.Reader, stdout, stderr io.Writer) (bool, error)
}

type IOStreams struct {
    In io.Reader
    Out io.Writer
    ErrOut io.Writer
}

func Run(m ExtensionManager, args []string, streams IOStreams) error {
    if found, err := m.Dispatch(args, streams.In, streams.Out, streams.ErrOut); !found {
        return err
    } else {
        return err
    }
}
"#,
    )]);

    let target = definition(
        &analyzer,
        "example.com/app/pkg/extensions.ExtensionManager.Dispatch",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("interface receiver dispatch should resolve");

    assert_eq!(1, hits.len(), "expected the m.Dispatch call: {hits:?}");
    assert!(hits.iter().all(|hit| {
        hit.file == project.file("pkg/extensions/manager.go")
            && hit
                .snippet
                .contains("m.Dispatch(args, streams.In, streams.Out, streams.ErrOut)")
    }));
}

#[test]
fn go_graph_strategy_excludes_concrete_receivers_from_interface_method_usages() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "worker/worker.go",
            r#"
package worker

type Worker struct{}

func (Worker) Record() {}

type Recorder interface {
    Record()
}

type RecorderAlias = Recorder

func NewWorker() Worker { return Worker{} }
"#,
        ),
        (
            "factory/factory.go",
            r#"
package factory

import "example.com/app/worker"

type Recorder = worker.Recorder

func NewRecorder() Recorder { return worker.NewWorker() }
"#,
        ),
        (
            "cmd/app/main.go",
            r#"
package main

import . "example.com/app/worker"
import factory "example.com/app/factory"

func main() {
    worker := NewWorker()
    worker.Record()
    _, paired := 0, NewWorker()
    paired.Record()
    literal := Worker{}
    literal.Record()
    var recorder Recorder = worker
    recorder.Record()
    var aliased RecorderAlias = worker
    aliased.Record()
    viaFactory := factory.NewRecorder()
    viaFactory.Record()
}
"#,
        ),
        (
            "cmd/qualified/main.go",
            r#"
package main

import worker "example.com/app/worker"

func main() {
    constructed := worker.NewWorker()
    constructed.Record()
    literal := worker.Worker{}
    literal.Record()
    var recorder worker.RecorderAlias = literal
    recorder.Record()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/worker.Recorder.Record");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = GoUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );

    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
            ..
        } => {
            let hits = hits_by_overload
                .get(&target)
                .expect("interface receiver call should be proven");
            assert_eq!(
                4,
                hits.len(),
                "only interface and interface-alias receivers should be proven: {hits:#?}"
            );
            assert_eq!(
                BTreeSet::from([
                    (project.file("cmd/app/main.go"), 15),
                    (project.file("cmd/app/main.go"), 17),
                    (project.file("cmd/app/main.go"), 19),
                    (project.file("cmd/qualified/main.go"), 12),
                ]),
                hits.iter()
                    .map(|hit| (hit.file.clone(), hit.line))
                    .collect::<BTreeSet<_>>()
            );
            assert_eq!(
                None,
                unproven_total_by_overload.get(&target),
                "known concrete receivers must not be interface-method candidates: {:#?}",
                unproven_by_overload.get(&target)
            );
        }
        other => panic!("expected interface proof-tier result, got {other:#?}"),
    }
}

#[test]
fn go_graph_strategy_does_not_match_interface_fields_by_method_name_only() {
    let (_project, analyzer) = go_analyzer_with_files(&[(
        "example/service.go",
        r#"
package example

type StringSaver interface {
    Save(value string) string
}

type IntSaver interface {
    Save(value int) int
}

type MemoryRepository struct{}

func (m *MemoryRepository) Save(value string) string {
    return value
}

type Worker struct {
    saver IntSaver
}

func (w Worker) Run(value int) int {
    return w.saver.Save(value)
}
"#,
    )]);

    let target = definition(&analyzer, "example.com/app/example.MemoryRepository.Save");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("same-name interface methods should be resolved structurally");

    assert!(
        hits.is_empty(),
        "IntSaver.Save(int) must not count as MemoryRepository.Save(string): {hits:?}",
    );
}

#[test]
fn go_graph_strategy_finds_imported_interface_method_calls_through_struct_fields() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "registry/app/pkg/base/base.go",
            r#"
package base

type LocalBase interface {
    MoveTempFileAndCreateArtifact(ctx string) error
}

type localBase struct{}

func NewLocalBase() LocalBase {
    return &localBase{}
}

func (l *localBase) MoveTempFileAndCreateArtifact(ctx string) error {
    return nil
}
"#,
        ),
        (
            "registry/app/pkg/npm/local.go",
            r#"
package npm

import "example.com/app/registry/app/pkg/base"

type Client struct {
    localBase base.LocalBase
}

func (c *Client) Publish(ctx string) error {
    return c.localBase.MoveTempFileAndCreateArtifact(ctx)
}
"#,
        ),
    ]);

    let target = definition(
        &analyzer,
        "example.com/app/registry/app/pkg/base.LocalBase.MoveTempFileAndCreateArtifact",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("imported interface field method usage should resolve");

    assert_eq!(
        1,
        hits.len(),
        "expected imported interface field hit: {hits:?}"
    );
    assert!(hits.iter().all(|hit| {
        hit.file == project.file("registry/app/pkg/npm/local.go")
            && hit
                .snippet
                .contains("c.localBase.MoveTempFileAndCreateArtifact")
    }));
}

#[test]
fn go_graph_strategy_classifies_imported_interface_calls_to_unexported_impls_as_unproven() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "registry/app/pkg/base/base.go",
            r#"
package base

type LocalBase interface {
    MoveTempFileAndCreateArtifact(ctx string) error
}

type localBase struct{}

func NewLocalBase() LocalBase {
    return &localBase{}
}

func (l *localBase) MoveTempFileAndCreateArtifact(ctx string) error {
    return nil
}
"#,
        ),
        (
            "registry/app/pkg/npm/local.go",
            r#"
package npm

import "example.com/app/registry/app/pkg/base"

type Client struct {
    localBase base.LocalBase
}

func (c *Client) Publish(ctx string) error {
    return c.localBase.MoveTempFileAndCreateArtifact(ctx)
}
"#,
        ),
    ]);

    let target = definition(
        &analyzer,
        "example.com/app/registry/app/pkg/base.localBase.MoveTempFileAndCreateArtifact",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = GoUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );

    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
        } => {
            assert!(
                hits_by_overload
                    .get(&target)
                    .is_none_or(|hits| hits.is_empty()),
                "interface dispatch must not be a proven implementation hit: {hits_by_overload:#?}",
            );
            assert_eq!(
                Some(&1),
                unproven_total_by_overload.get(&target),
                "imported interface dispatch must be counted as unproven",
            );
            assert!(
                unproven_by_overload
                    .get(&target)
                    .is_some_and(|hits| hits.iter().any(|hit| {
                        hit.file == project.file("registry/app/pkg/npm/local.go")
                            && hit
                                .snippet
                                .contains("c.localBase.MoveTempFileAndCreateArtifact")
                    })),
                "expected the imported interface dispatch to be unproven: {unproven_by_overload:#?}",
            );
        }
        other => panic!("expected proof-tier result, got {other:#?}"),
    }
}

#[test]
fn go_graph_strategy_classifies_gocache_style_interface_wrappers_as_unproven() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "cache/chain.go",
            r#"
package cache

type CacheInterface interface {
    Set(key string) error
}

type ChainCache struct{}

func (c *ChainCache) Set(key string) error {
    return nil
}
"#,
        ),
        (
            "cache/wrappers.go",
            r#"
package cache

type LoadableCache struct {
    cache CacheInterface
}

func (c *LoadableCache) Set(key string) error {
    return c.cache.Set(key)
}

type MetricCache struct {
    cache CacheInterface
}

func (c *MetricCache) Set(key string) error {
    return c.cache.Set(key)
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/cache.ChainCache.Set");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = GoUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );

    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
        } => {
            assert!(
                hits_by_overload
                    .get(&target)
                    .is_none_or(|hits| hits.is_empty()),
                "interface wrappers must not be proven concrete-method calls: {hits_by_overload:#?}",
            );
            assert_eq!(
                Some(&2),
                unproven_total_by_overload.get(&target),
                "both interface wrapper calls should be unproven",
            );
            let unproven = unproven_by_overload
                .get(&target)
                .expect("capped unproven wrapper hits");
            assert!(
                unproven.iter().any(|hit| {
                    hit.file == project.file("cache/wrappers.go")
                        && hit.snippet.contains("return c.cache.Set(key)")
                        && hit.enclosing.fq_name().ends_with("LoadableCache.Set")
                }),
                "expected LoadableCache.Set to be unproven: {unproven:#?}",
            );
            assert!(
                unproven.iter().any(|hit| {
                    hit.file == project.file("cache/wrappers.go")
                        && hit.snippet.contains("return c.cache.Set(key)")
                        && hit.enclosing.fq_name().ends_with("MetricCache.Set")
                }),
                "expected MetricCache.Set to be unproven: {unproven:#?}",
            );
        }
        other => panic!("expected proof-tier result, got {other:#?}"),
    }
}

// Regression for #232: a value-receiver method called on a local that is bound to
// a constructor's return value (`service := NewService()`) must resolve on the
// graph path. Before the constructor-return seeding it returned zero hits and the
// regex fallback masked the gap.
#[test]
fn go_graph_strategy_finds_value_receiver_calls_on_constructor_locals() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "example/service.go",
            r#"
package example

type Service struct {
    Name string
}

func (s Service) Execute() string {
    return s.Name
}

func NewService() Service {
    return Service{Name: "demo"}
}
"#,
        ),
        (
            "example/service_test.go",
            r#"
package example

import "testing"

func TestExecute(t *testing.T) {
    service := NewService()
    if service.Execute() != "demo" {
        t.Fatal("unexpected result")
    }
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/example.Service.Execute");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect(
            "value-receiver call on a constructor-returned local should resolve on the graph path",
        );

    assert_eq!(
        1,
        hits.len(),
        "expected the service.Execute() call: {hits:?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("example/service_test.go")),
        "hit should be the test-file call site: {hits:?}",
    );
}

// A value-receiver constructor returning the common `(Owner, error)` tuple should
// also seed the receiver from its first result.
#[test]
fn go_graph_strategy_finds_value_receiver_calls_on_tuple_constructor_locals() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "example/service.go",
            r#"
package example

type Service struct {
    Name string
}

func (s Service) Execute() string {
    return s.Name
}

func NewService() (Service, error) {
    return Service{Name: "demo"}, nil
}
"#,
        ),
        (
            "consumer/consumer.go",
            r#"
package consumer

import "example.com/app/example"

func Run() string {
    service, _ := example.NewService()
    return service.Execute()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/example.Service.Execute");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect(
            "value-receiver call on a tuple-constructor local should resolve on the graph path",
        );

    assert_eq!(
        1,
        hits.len(),
        "expected the service.Execute() call: {hits:?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("consumer/consumer.go")),
        "hit should be the consumer call site: {hits:?}",
    );
}

// A local/parameter that shadows the package constructor name is not the package
// constructor, so a method call on a local bound to it must not be a hit.
#[test]
fn go_graph_strategy_does_not_seed_local_shadowing_a_constructor_name() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "example/service.go",
            r#"
package example

type Service struct {
    Name string
}

func (s Service) Execute() string {
    return s.Name
}

func NewService() Service {
    return Service{Name: "demo"}
}
"#,
        ),
        (
            "example/consumer.go",
            r#"
package example

func Run(NewService func() string) {
    x := NewService()
    _ = x.Execute()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/example.Service.Execute");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should resolve");

    assert!(
        hits.is_empty(),
        "x.Execute() where NewService is a shadowing parameter must not be a hit: {hits:?}",
    );
}

#[test]
fn go_graph_strategy_keeps_blank_lhs_constructor_seeds_positional() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "example/service.go",
            r#"
package example

type Service struct{}

func (s Service) Execute() string { return "service" }

func NewService() Service { return Service{} }
"#,
        ),
        (
            "example/other.go",
            r#"
package example

type Other struct{}

func (o Other) Execute() string { return "other" }

func NewOther() Other { return Other{} }
"#,
        ),
        (
            "example/consumer.go",
            r#"
package example

func Run() string {
    _, other := NewService(), NewOther()
    return other.Execute()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/example.Service.Execute");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should resolve");

    assert!(
        hits.is_empty(),
        "blank LHS must not shift NewService's receiver proof onto other: {hits:?}",
    );
}

#[test]
fn go_graph_strategy_resolves_constructor_before_short_var_lhs_scope() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "example/service.go",
            r#"
package example

type Service struct{}

func (s Service) Execute() string { return "service" }

func NewService() Service { return Service{} }
"#,
        ),
        (
            "example/consumer.go",
            r#"
package example

func Run() string {
    NewService, service := 0, NewService()
    _ = NewService
    return service.Execute()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/example.Service.Execute");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should resolve");

    assert_eq!(
        1,
        hits.len(),
        "short-var LHS names should not shadow RHS constructor calls: {hits:?}",
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("example/consumer.go")),
        "hit should be the consumer call site: {hits:?}",
    );
}

#[test]
fn go_graph_strategy_respects_grouped_var_spec_constructor_shadowing() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "example/service.go",
            r#"
package example

type Service struct{}

func (s Service) Execute() string { return "service" }

func NewService() Service { return Service{} }
"#,
        ),
        (
            "example/other.go",
            r#"
package example

type Other struct{}

func (o Other) Execute() string { return "other" }
"#,
        ),
        (
            "example/consumer.go",
            r#"
package example

func Run() string {
    var (
        NewService = func() Other { return Other{} }
        service = NewService()
    )
    return service.Execute()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/example.Service.Execute");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should resolve");

    assert!(
        hits.is_empty(),
        "later grouped var specs must see earlier constructor-shadowing specs: {hits:?}",
    );
}

#[test]
fn go_graph_strategy_keeps_mixed_multi_assignment_receiver_proofs_positional() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "model/album.go",
            r#"
package model

type Album struct{}

func (a Album) Title() string { return "" }
"#,
        ),
        (
            "other/album.go",
            r#"
package other

type Album struct{}

func (a Album) Title() string { return "" }
"#,
        ),
        (
            "core/reader.go",
            r#"
package core

import "example.com/app/model"
import "example.com/app/other"

func Read() string {
    album, otherAlbum := model.Album{}, other.Album{}
    return album.Title() + otherAlbum.Title()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/model.Album.Title");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("mixed multi-assignment receiver query should succeed");

    assert_eq!(
        1,
        hits.len(),
        "only the positionally matched model receiver should count: {hits:?}"
    );
}

#[test]
fn go_graph_strategy_seeds_members_from_grouped_and_multi_name_var_declarations() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "model/album.go",
            r#"
package model

type Album struct{}

func (a Album) Title() string { return "" }
"#,
        ),
        (
            "core/reader.go",
            r#"
package core

import "example.com/app/model"

func Read() string {
    var (
        album model.Album
        first,
            second /* receiver type comment */ model.Album
    )
    return album.Title() + first.Title() + second.Title()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/model.Album.Title");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("grouped and multi-name var receivers should resolve");

    assert_eq!(3, hits.len(), "var receiver hits: {hits:?}");
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
    let field = definition(&analyzer, "example.com/app/model.Album.ImageFiles");
    let method = definition(&analyzer, "example.com/app/model.Album.Title");
    let strategy = GoUsageGraphStrategy::new();

    let field_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&field), &candidates, 1000)
        .into_either()
        .expect("field negative query should succeed");
    assert_eq!(
        1,
        field_hits.len(),
        "only embedded-promoted fields should count: {field_hits:?}"
    );
    assert!(
        field_hits
            .iter()
            .any(|hit| hit.snippet.contains("wrapper.ImageFiles")),
        "promoted wrapper.ImageFiles should count: {field_hits:?}",
    );

    let method_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&method), &candidates, 1000)
        .into_either()
        .expect("method negative query should succeed");
    assert_eq!(
        1,
        method_hits.len(),
        "only embedded-promoted methods should count: {method_hits:?}"
    );
    assert!(
        method_hits
            .iter()
            .any(|hit| hit.snippet.contains("wrapper.Title()")),
        "promoted wrapper.Title should count: {method_hits:?}",
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

    let target = definition(&analyzer, "example.com/app/model.Helper");
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
fn go_graph_strategy_finds_function_usage_forms_across_call_contexts() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        ("util/util.go", "package util\nfunc Helper() {}\n"),
        (
            "local.go",
            r#"
package main

func helper() {}

func samePackage() {
    helper()
    f := helper
    f()
}
"#,
        ),
        (
            "main.go",
            r#"
package main

import "example.com/app/util"
import . "example.com/app/util"

func callForms() {
    util.Helper()
    Helper()
    deferred := func() {
        util.Helper()
    }
    deferred()
    defer util.Helper()
    go util.Helper()
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = GoUsageGraphStrategy::new();

    let imported = definition(&analyzer, "example.com/app/util.Helper");
    let imported_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&imported),
            &candidates,
            1000,
        )
        .into_either()
        .expect("imported function forms should resolve");
    assert_eq!(5, imported_hits.len(), "imported hits: {imported_hits:?}");

    let local = definition(&analyzer, "example.com/app.helper");
    let local_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&local), &candidates, 1000)
        .into_either()
        .expect("same-package function values should resolve");
    assert_eq!(2, local_hits.len(), "local function hits: {local_hits:?}");
}

#[test]
fn go_graph_strategy_keeps_function_usage_shadowing_conservative() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        ("util/util.go", "package util\nfunc Helper() {}\n"),
        (
            "main.go",
            r#"
package main

import util "example.com/app/util"
import . "example.com/app/util"

func shadowPackageAlias() {
    util := struct{ Helper func() }{Helper: func() {}}
    util.Helper()
}

func shadowDotImport() {
    Helper := func() {}
    Helper()
}

func shadowParameter(Helper func()) {
    Helper()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/util.Helper");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("shadowed function query should succeed");

    assert!(
        hits.is_empty(),
        "local shadows should block imported function proofs: {hits:?}"
    );
}

#[test]
fn go_graph_strategy_keeps_same_package_top_level_shadowing_conservative() {
    let (_project, analyzer) = go_analyzer_with_files(&[
        (
            "defs.go",
            r#"
package main

const Flag = "global"

func helper() {}
"#,
        ),
        (
            "consumer.go",
            r#"
package main

func localShadows() {
    helper := func() {}
    helper()
    Flag := "local"
    _ = Flag
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = GoUsageGraphStrategy::new();

    let helper = definition(&analyzer, "example.com/app.helper");
    let helper_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&helper), &candidates, 1000)
        .into_either()
        .expect("same-package function shadowing query should succeed");
    assert!(
        helper_hits.is_empty(),
        "same-package function shadows should not count: {helper_hits:?}"
    );

    let flag = definition(&analyzer, "example.com/app._module_.Flag");
    let flag_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&flag), &candidates, 1000)
        .into_either()
        .expect("same-package const shadowing query should succeed");
    assert!(
        flag_hits.is_empty(),
        "same-package const shadows should not count: {flag_hits:?}"
    );
}

#[test]
fn go_graph_strategy_finds_top_level_var_and_const_usage_forms() {
    let (project, analyzer) = go_analyzer_with_files(&[
        (
            "config/config.go",
            r#"
package config

const Flag = "on"
var Count = 1
"#,
        ),
        (
            "config/internal.go",
            r#"
package config

func samePackage() {
    _ = Flag
    Count += 1
}
"#,
        ),
        (
            "other/config.go",
            r#"
package other

const Flag = "other"
var Count = 99
"#,
        ),
        (
            "main.go",
            r#"
package main

import cfg "example.com/app/config"
import other "example.com/app/other"

func external() {
    _ = cfg.Flag
    cfg.Count = cfg.Count + 1
    _ = &cfg.Count
    _ = other.Flag
    other.Count += 1
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = GoUsageGraphStrategy::new();

    let flag = definition(&analyzer, "example.com/app/config._module_.Flag");
    let flag_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&flag), &candidates, 1000)
        .into_either()
        .expect("const usages should resolve");
    assert_eq!(2, flag_hits.len(), "flag hits: {flag_hits:?}");
    assert!(
        flag_hits
            .iter()
            .all(|hit| hit.file == project.file("config/internal.go")
                || hit.file == project.file("main.go"))
    );

    let count = definition(&analyzer, "example.com/app/config._module_.Count");
    let count_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&count), &candidates, 1000)
        .into_either()
        .expect("var usages should resolve");
    assert_eq!(4, count_hits.len(), "count hits: {count_hits:?}");
    assert!(
        count_hits
            .iter()
            .all(|hit| hit.file == project.file("config/internal.go")
                || hit.file == project.file("main.go"))
    );
}

#[test]
fn go_graph_strategy_finds_type_references_in_advanced_type_positions() {
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
            "core/types.go",
            r#"
package core

import "example.com/app/model"

type Alias = model.Album
type Constraint interface {
    ~[]model.Album
    Accept(model.Album) *model.Album
}
type Handler func(model.Album) model.Album
type Uses struct {
    Fixed [2]model.Album
    Boxed model.Box[model.Album]
}

func Check(v any) {
    _ = v.(model.Album)
    switch v.(type) {
    case model.Album:
    }
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/model.Album");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("advanced type positions should resolve");

    assert!(
        hits.len() >= 9,
        "expected alias, constraint, function, array, generic, assertion, and switch hits: {hits:?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("core/types.go"))
    );
}

#[test]
fn go_graph_strategy_finds_member_usages_in_nested_receiver_contexts() {
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
            "core/reader.go",
            r#"
package core

import "example.com/app/model"

func NamedReturn() (album model.Album) {
    _ = album.Title()
    album.ImageFiles = "cover.jpg"
    return
}

func Nested(album model.Album) {
    func() {
        alias := album
        _ = alias.Title()
        _ = alias.ImageFiles
    }()
    {
        next := album
        _ = next.Title()
        next.ImageFiles = "back.jpg"
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = GoUsageGraphStrategy::new();

    let method = definition(&analyzer, "example.com/app/model.Album.Title");
    let method_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&method), &candidates, 1000)
        .into_either()
        .expect("nested method receiver usages should resolve");
    assert_eq!(3, method_hits.len(), "method hits: {method_hits:?}");

    let field = definition(&analyzer, "example.com/app/model.Album.ImageFiles");
    let field_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&field), &candidates, 1000)
        .into_either()
        .expect("nested field receiver usages should resolve");
    assert_eq!(3, field_hits.len(), "field hits: {field_hits:?}");
}

#[test]
fn go_graph_strategy_finds_member_usages_through_pointer_dereference_receivers() {
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

func Read(album *model.Album) string {
    _ = (*album).Title()
    (*album).ImageFiles = "cover.jpg"
    return album.Title()
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = GoUsageGraphStrategy::new();

    let method = definition(&analyzer, "example.com/app/model.Album.Title");
    let method_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&method), &candidates, 1000)
        .into_either()
        .expect("dereferenced method receiver usages should resolve");
    assert_eq!(2, method_hits.len(), "method hits: {method_hits:?}");

    let field = definition(&analyzer, "example.com/app/model.Album.ImageFiles");
    let field_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&field), &candidates, 1000)
        .into_either()
        .expect("dereferenced field receiver usages should resolve");
    assert_eq!(1, field_hits.len(), "field hits: {field_hits:?}");
}

#[test]
fn go_graph_strategy_keeps_interprocedural_member_assignment_out_of_scope() {
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
            "core/reader.go",
            r#"
package core

import "example.com/app/model"

var saved any

func Save(album model.Album) {
    saved = album
}

func Later() string {
    return saved.Title()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "example.com/app/model.Album.Title");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = GoUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("interprocedural negative query should succeed");

    assert!(
        hits.is_empty(),
        "interprocedural data-flow should remain out of scope: {hits:?}"
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

    let target = definition(&analyzer, "example.com/app.helper");
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
