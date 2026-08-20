//! Round-trip contract for summary spellings: every symbol a summary lists
//! must be addressable by the exact spelling the summary printed for it, and
//! the answer must lead back to the declaration the summary listed.
//!
//! Concretely, for each `SummaryElement { path, symbol, .. }` of a file
//! summary, `get_summaries([symbol])` must either
//!
//!  * return a summary block whose `path` is the listed file (other blocks
//!    for same-spelling twins are fine — the listed declaration just has to
//!    be among them), or
//!  * report the spelling ambiguous with requestable selectors, at least one
//!    of which resolves back to a block for the listed file.
//!
//! A `not_found` verdict is the I3(a) shape (a summary listed a spelling its
//! own resolver cannot address); an answer that only names *other* files is
//! the I2 shape (the spelling silently resolves to a different declaration).
//! The fixtures reproduce the duplicate-FQN and decorated-qualifier shapes
//! from real repositories: a generic C# owner (starsky), Scala companion
//! nesting (http4s), C macro twins with colliding basenames (git), JS
//! prod/mock twins (angular), Go build-tag twins, C# partial classes, and
//! Scala 2/3 cross-built trees.

use super::summaries::{SummariesParams, get_summaries, summarize_files};
use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::test_support::AnalyzerFixture;

fn summaries_for(analyzer: &dyn IAnalyzer, target: &str) -> super::SummaryResult {
    get_summaries(
        analyzer,
        SummariesParams {
            targets: vec![target.to_string()],
        },
    )
}

/// `Ok(())` when `spelling` leads back to a declaration in `listed_path`,
/// directly or through one hop of the ambiguity selectors the tool returned.
fn spelling_covers(
    analyzer: &dyn IAnalyzer,
    spelling: &str,
    listed_path: &str,
) -> Result<(), String> {
    let result = summaries_for(analyzer, spelling);
    if result
        .summaries
        .iter()
        .any(|block| block.path == listed_path)
    {
        return Ok(());
    }
    if result.summaries.is_empty() && result.ambiguous.is_empty() {
        let notes: Vec<_> = result
            .not_found
            .iter()
            .map(|item| item.note.clone().unwrap_or_default())
            .collect();
        return Err(format!("not_found ({})", notes.join("; ")));
    }
    for item in &result.ambiguous {
        for selector in &item.matches {
            let retry = summaries_for(analyzer, selector);
            if retry
                .summaries
                .iter()
                .any(|block| block.path == listed_path)
            {
                return Ok(());
            }
        }
    }
    let resolved_paths: Vec<_> = result
        .summaries
        .iter()
        .map(|block| block.path.clone())
        .collect();
    let selectors: Vec<_> = result
        .ambiguous
        .iter()
        .flat_map(|item| item.matches.iter().cloned())
        .collect();
    Err(format!(
        "does not lead back to `{listed_path}`; resolved paths {resolved_paths:?}, ambiguity selectors {selectors:?}"
    ))
}

/// Round-trip every element of every file summary; return one line per
/// violation.
fn roundtrip_failures(analyzer: &dyn IAnalyzer, files: Vec<ProjectFile>) -> Vec<String> {
    let base = summarize_files(analyzer, files);
    assert!(
        !base.summaries.is_empty(),
        "fixture produced no file summaries at all: {:?}",
        base.not_found
    );
    let mut failures = Vec::new();
    for block in &base.summaries {
        for element in &block.elements {
            if element.symbol.is_empty() {
                continue;
            }
            if let Err(reason) = spelling_covers(analyzer, &element.symbol, &element.path) {
                failures.push(format!(
                    "{} listed `{}` [{}]: {}",
                    element.path, element.symbol, element.kind, reason
                ));
            }
        }
    }
    failures.sort();
    failures.dedup();
    failures
}

fn assert_roundtrip(fixture: &AnalyzerFixture, rel_paths: &[&str]) {
    let root = fixture.project_root();
    let files = rel_paths
        .iter()
        .map(|rel| ProjectFile::new(root.clone(), *rel))
        .collect();
    let failures = roundtrip_failures(fixture.analyzer.analyzer(), files);
    assert!(
        failures.is_empty(),
        "summary spellings that do not round-trip:\n{}",
        failures.join("\n")
    );
}

/// The starsky shape behind #1063's regression: a generic owner means every
/// member spelling carries an arity-decorated *qualifier* segment
/// (``FilenameDatetimeRepairRequest`1.FilePaths``), which the arity-free
/// display spelling must still address. The second file makes the bare
/// member name ambiguous, so a resolver that loses the qualifier degrades
/// to not_found instead of resolving.
const STARSKY_REQUEST: (&str, &str) = (
    "Models/FilenameDatetimeRepairRequest.cs",
    r#"using System.Collections.Generic;

namespace starsky.feature.rename.Models;

public class FilenameDatetimeRepairRequest<T> where T : IExifTimeCorrectionRequest
{
	public required List<string> FilePaths { get; set; } = [];

	public bool Collections { get; set; } = true;

	public required T CorrectionRequest { get; set; }
}
"#,
);

const STARSKY_SIBLING: (&str, &str) = (
    "Models/BatchRenameRequest.cs",
    r#"using System.Collections.Generic;

namespace starsky.feature.rename.Models;

public class BatchRenameRequest
{
	public List<string> FilePaths { get; set; } = new();
}
"#,
);

#[test]
fn csharp_generic_owner_member_spellings_roundtrip() {
    let fixture = AnalyzerFixture::new(&[STARSKY_REQUEST, STARSKY_SIBLING]);
    let analyzer = fixture.analyzer.analyzer();

    let base = summarize_files(
        analyzer,
        vec![ProjectFile::new(fixture.project_root(), STARSKY_REQUEST.0)],
    );
    let listed: Vec<_> = base
        .summaries
        .iter()
        .flat_map(|block| block.elements.iter().map(|element| element.symbol.clone()))
        .collect();
    assert!(
        listed.iter().any(|symbol| symbol.ends_with(".FilePaths")),
        "the generic owner's property must be listed; got {listed:?}"
    );

    assert_roundtrip(&fixture, &[STARSKY_REQUEST.0, STARSKY_SIBLING.0]);
}

/// The literal #1063 campaign probe: the arity-free owner-qualified member
/// spelling (no namespace prefix) must resolve while the bare member name is
/// ambiguous.
#[test]
fn csharp_arity_free_owner_qualified_member_resolves() {
    let fixture = AnalyzerFixture::new(&[STARSKY_REQUEST, STARSKY_SIBLING]);
    let analyzer = fixture.analyzer.analyzer();

    let bare = summaries_for(analyzer, "FilePaths");
    assert!(
        !bare.ambiguous.is_empty() || bare.summaries.len() > 1,
        "two classes declare `FilePaths`, so the bare name must not resolve to one silently: {bare:?}"
    );

    for spelling in [
        "FilenameDatetimeRepairRequest.FilePaths",
        "starsky.feature.rename.Models.FilenameDatetimeRepairRequest.FilePaths",
    ] {
        let result = summaries_for(analyzer, spelling);
        assert!(
            result
                .summaries
                .iter()
                .any(|block| block.path == STARSKY_REQUEST.0),
            "`{spelling}` must lead to the declaring file; got summaries for {:?}, not_found {:?}, ambiguous {:?}",
            result
                .summaries
                .iter()
                .map(|block| block.path.clone())
                .collect::<Vec<_>>(),
            result.not_found,
            result.ambiguous
        );
    }
}

/// The http4s shape behind the Scala leg of #2451: `Atom` is a case class
/// nested in `object CharsetRange`, so its indexed qualifier segment carries
/// the companion `$` (`CharsetRange$.Atom`) while the summary spells it
/// `CharsetRange.Atom`.
const HTTP4S_CHARSET_RANGE: (&str, &str) = (
    "core/src/main/scala/org/http4s/CharsetRange.scala",
    r#"package org.http4s

sealed abstract class CharsetRange {
  def qValue: Int
  def withQValue(q: Int): CharsetRange

  final def matches(charset: String): Boolean =
    this match {
      case CharsetRange.`*`(_) => true
      case CharsetRange.Atom(cs, _) => charset == cs
    }
}

object CharsetRange {
  sealed case class `*`(qValue: Int) extends CharsetRange {
    override final def withQValue(q: Int): CharsetRange.`*` = copy(qValue = q)
  }

  object `*` extends `*`(1)

  final case class Atom private (
      charset: String,
      qValue: Int = 1,
  ) extends CharsetRange {
    override def withQValue(q: Int): CharsetRange.Atom = copy(qValue = q)
  }

  object Atom {
    def apply(charset: String, qValue: Int = 1): Atom = new Atom(charset, qValue)
  }
}
"#,
);

#[test]
fn scala_companion_nested_type_spellings_roundtrip() {
    let fixture = AnalyzerFixture::new(&[HTTP4S_CHARSET_RANGE]);
    assert_roundtrip(&fixture, &[HTTP4S_CHARSET_RANGE.0]);
}

#[test]
fn scala_companion_nested_type_qualified_spelling_resolves() {
    let fixture = AnalyzerFixture::new(&[HTTP4S_CHARSET_RANGE]);
    let analyzer = fixture.analyzer.analyzer();
    for spelling in ["org.http4s.CharsetRange.Atom", "CharsetRange.Atom"] {
        let result = summaries_for(analyzer, spelling);
        assert!(
            result
                .summaries
                .iter()
                .any(|block| block.path == HTTP4S_CHARSET_RANGE.0),
            "`{spelling}` must lead to the declaring file; got summaries for {:?}, not_found {:?}, ambiguous {:?}",
            result
                .summaries
                .iter()
                .map(|block| block.path.clone())
                .collect::<Vec<_>>(),
            result.not_found,
            result.ambiguous
        );
    }
}

/// The git shape behind the C leg of #2451: one macro spelled identically in
/// a root-level header/source pair, with a second `path.c` deeper in the
/// tree so the root file's basename is ambiguous. The ambiguity selectors
/// the tool prints (`path.c#VEC`) must themselves resolve.
const GIT_PATH_C: (&str, &str) = (
    "path.c",
    "#include \"path.h\"\n\n#define VEC(x) ((x) + 1)\n\nint normalize_path(int value) { return VEC(value); }\n",
);
const GIT_PATH_H: (&str, &str) = (
    "path.h",
    "#define VEC(x) ((x) + 1)\n\nint normalize_path(int value);\n",
);
const GIT_COMPAT_PATH_C: (&str, &str) = (
    "compat/path.c",
    "static int compat_only(int value) { return value; }\n",
);

#[test]
fn c_macro_twin_spellings_roundtrip() {
    let fixture = AnalyzerFixture::new(&[GIT_PATH_C, GIT_PATH_H, GIT_COMPAT_PATH_C]);
    assert_roundtrip(&fixture, &[GIT_PATH_C.0, GIT_PATH_H.0]);
}

/// The angular shape from #1057: the prod `$LogProvider` function and the
/// mock's `angular.mock.$LogProvider` assignment share a terminal name in
/// one concatenated global scope.
const ANGULAR_LOG: (&str, &str) = (
    "src/ng/log.js",
    r#"function $LogProvider() {
  var debug = true;
  this.debugEnabled = function(flag) {
    if (typeof flag !== 'undefined') {
      debug = flag;
      return this;
    }
    return debug;
  };
}
"#,
);
const ANGULAR_MOCKS: (&str, &str) = (
    "src/ngMock/angular-mocks.js",
    r#"angular.mock = {};

angular.mock.$LogProvider = function() {
  var debug = false;
  this.debugEnabled = function(flag) {
    if (typeof flag !== 'undefined') {
      debug = flag;
      return this;
    }
    return debug;
  };
};
"#,
);

#[test]
fn js_prod_and_mock_twin_spellings_roundtrip() {
    let fixture = AnalyzerFixture::new(&[ANGULAR_LOG, ANGULAR_MOCKS]);
    assert_roundtrip(&fixture, &[ANGULAR_LOG.0, ANGULAR_MOCKS.0]);
}

/// Go build-tag twins: the same function declared in two files of one
/// package, each guarded by a build constraint Bifrost does not evaluate.
const GO_CONN_LINUX: (&str, &str) = (
    "netx/conn_linux.go",
    "//go:build linux\n\npackage netx\n\nfunc dial(address string) error { return nil }\n",
);
const GO_CONN_WINDOWS: (&str, &str) = (
    "netx/conn_windows.go",
    "//go:build windows\n\npackage netx\n\nfunc dial(address string) error { return nil }\n",
);

#[test]
fn go_build_tag_twin_spellings_roundtrip() {
    let fixture = AnalyzerFixture::new(&[GO_CONN_LINUX, GO_CONN_WINDOWS]);
    assert_roundtrip(&fixture, &[GO_CONN_LINUX.0, GO_CONN_WINDOWS.0]);
}

/// C# partial classes: one logical type, two physical parts.
const CSHARP_PARTIAL_ONE: (&str, &str) = (
    "Service.One.cs",
    "namespace Alpha;\n\npublic partial class Service\n{\n    public int ComputeA(int value) => value;\n}\n",
);
const CSHARP_PARTIAL_TWO: (&str, &str) = (
    "Service.Two.cs",
    "namespace Alpha;\n\npublic partial class Service\n{\n    public int ComputeB(int value) => value;\n}\n",
);

#[test]
fn csharp_partial_class_spellings_roundtrip() {
    let fixture = AnalyzerFixture::new(&[CSHARP_PARTIAL_ONE, CSHARP_PARTIAL_TWO]);
    assert_roundtrip(&fixture, &[CSHARP_PARTIAL_ONE.0, CSHARP_PARTIAL_TWO.0]);
}

/// The real angular-mocks shape: the mock provider is a dotted property
/// assignment inside an IIFE, so its indexed identifier is the whole dotted
/// spelling. The #1057 contract says a bare terminal name must still see it:
/// a lone top-level namesake must not silently win over a same-named member.
const ANGULAR_LOG_REAL: (&str, &str) = (
    "src/ng/log.js",
    r#"'use strict';

function $LogProvider() {
  var debug = true,
      self = this;

  this.debugEnabled = function(flag) {
    if (typeof flag !== 'undefined') {
      debug = flag;
      return this;
    }
    return debug;
  };
}
"#,
);
const ANGULAR_MOCKS_REAL: (&str, &str) = (
    "src/ngMock/angular-mocks.js",
    r#"(function(window, angular) {

'use strict';

angular.mock = {};

angular.mock.$LogProvider = function() {
  var debug = false;

  this.debugEnabled = function(flag) {
    if (typeof flag !== 'undefined') {
      debug = flag;
      return this;
    }
    return debug;
  };
};

})(window, window.angular);
"#,
);

#[test]
fn js_bare_name_sees_the_dotted_member_namesake() {
    let fixture = AnalyzerFixture::new(&[ANGULAR_LOG_REAL, ANGULAR_MOCKS_REAL]);
    let analyzer = fixture.analyzer.analyzer();

    let result = summaries_for(analyzer, "$LogProvider");
    let mut covered: Vec<_> = result
        .summaries
        .iter()
        .map(|block| block.path.clone())
        .collect();
    for item in &result.ambiguous {
        for selector in &item.matches {
            let retry = summaries_for(analyzer, selector);
            covered.extend(retry.summaries.iter().map(|block| block.path.clone()));
        }
    }
    covered.sort();
    covered.dedup();
    assert_eq!(
        covered,
        vec![
            ANGULAR_LOG_REAL.0.to_string(),
            ANGULAR_MOCKS_REAL.0.to_string()
        ],
        "bare `$LogProvider` must lead to the prod function and the mock member, \
         not silently pick one; got summaries {:?}, ambiguous {:?}",
        result
            .summaries
            .iter()
            .map(|block| block.path.clone())
            .collect::<Vec<_>>(),
        result.ambiguous
    );
}

/// `parent_symbol` must never be produced by mis-reading a `$` inside a
/// terminal identifier as a hierarchy separator: the real angular mock's
/// parent used to render as `angular.mock.` (trailing dot).
#[test]
fn js_dollar_prefixed_terminal_does_not_corrupt_parent_symbol() {
    let fixture = AnalyzerFixture::new(&[ANGULAR_LOG_REAL, ANGULAR_MOCKS_REAL]);
    let base = summarize_files(
        fixture.analyzer.analyzer(),
        vec![
            ProjectFile::new(fixture.project_root(), ANGULAR_LOG_REAL.0),
            ProjectFile::new(fixture.project_root(), ANGULAR_MOCKS_REAL.0),
        ],
    );
    let mut violations = Vec::new();
    for block in &base.summaries {
        for element in &block.elements {
            let Some(parent) = &element.parent_symbol else {
                continue;
            };
            if parent.ends_with(['.', '$']) || parent == &element.symbol {
                violations.push(format!(
                    "`{}` [{}] has corrupt parent_symbol `{parent}`",
                    element.symbol, element.kind
                ));
            }
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

/// A unique basename must anchor a nested file: `path.c#VEC` is the selector
/// shape the ambiguity note teaches (`refine with path#name`), and
/// `resolve_literal` already accepts the bare basename for plain file
/// targets.
#[test]
fn basename_anchor_of_nested_file_resolves() {
    let fixture = AnalyzerFixture::new(&[
        (
            "src/util/path.c",
            "#define VEC(x) ((x) + 1)\n\nint normalize_path(int value) { return VEC(value); }\n",
        ),
        ("src/other.c", "int other(void) { return 0; }\n"),
    ]);
    let analyzer = fixture.analyzer.analyzer();
    let result = summaries_for(analyzer, "path.c#VEC");
    assert!(
        result
            .summaries
            .iter()
            .any(|block| block.path == "src/util/path.c"),
        "a unique basename anchor must resolve like a plain file target; got summaries for {:?}, not_found {:?}",
        result
            .summaries
            .iter()
            .map(|block| block.path.clone())
            .collect::<Vec<_>>(),
        result.not_found
    );
}

/// An anchor whose basename matches several files must say so, naming the
/// candidate paths, instead of degrading into a bare-symbol miss.
#[test]
fn ambiguous_basename_anchor_names_the_candidate_paths() {
    let fixture = AnalyzerFixture::new(&[
        ("a/path.c", "#define VEC(x) ((x) + 1)\n"),
        ("b/path.c", "#define VEC(x) ((x) + 2)\n"),
    ]);
    let analyzer = fixture.analyzer.analyzer();
    let result = summaries_for(analyzer, "path.c#VEC");
    assert!(
        result.summaries.is_empty(),
        "an ambiguous anchor must not silently pick a file: {result:?}"
    );
    let notes: Vec<_> = result
        .not_found
        .iter()
        .map(|item| item.note.clone().unwrap_or_default())
        .chain(
            result
                .ambiguous_paths
                .iter()
                .map(|item| item.matches.join(", ")),
        )
        .collect();
    assert!(
        notes
            .iter()
            .any(|note| note.contains("a/path.c") && note.contains("b/path.c")),
        "the answer must name both candidate files; got not_found {:?}, ambiguous_paths {:?}",
        result.not_found,
        result.ambiguous_paths
    );
}

/// `parent_symbol` must name the enclosing scope, never the element itself,
/// and must be absent for a top-level declaration. A Scala object's trailing
/// companion `$` used to swallow the cut point.
#[test]
fn scala_parent_symbols_name_the_enclosing_scope() {
    let fixture = AnalyzerFixture::new(&[HTTP4S_CHARSET_RANGE]);
    let base = summarize_files(
        fixture.analyzer.analyzer(),
        vec![ProjectFile::new(
            fixture.project_root(),
            HTTP4S_CHARSET_RANGE.0,
        )],
    );
    let mut violations = Vec::new();
    for block in &base.summaries {
        for element in &block.elements {
            let Some(parent) = &element.parent_symbol else {
                continue;
            };
            if parent == &element.symbol {
                violations.push(format!(
                    "`{}` [{}] is its own parent_symbol",
                    element.symbol, element.kind
                ));
            }
        }
        let top_level: Vec<_> = block
            .elements
            .iter()
            .filter(|element| element.symbol == "org.http4s.CharsetRange")
            .filter_map(|element| element.parent_symbol.clone())
            .collect();
        if !top_level.is_empty() {
            violations.push(format!(
                "top-level `org.http4s.CharsetRange` must have no parent_symbol; got {top_level:?}"
            ));
        }
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

/// Scala 2/3 cross-built replicas: one logical symbol declared once per
/// source tree (#2021's shape).
const SCALA2_PROBE: (&str, &str) = (
    "src/main/scala-2/com/example/Probe.scala",
    "package com.example\n\nobject Probe {\n  def run(input: String): String = input\n}\n",
);
const SCALA3_PROBE: (&str, &str) = (
    "src/main/scala-3/com/example/Probe.scala",
    "package com.example\n\nobject Probe {\n  def run(input: String): String = input\n}\n",
);

#[test]
fn scala_cross_built_twin_spellings_roundtrip() {
    let fixture = AnalyzerFixture::new(&[SCALA2_PROBE, SCALA3_PROBE]);
    assert_roundtrip(&fixture, &[SCALA2_PROBE.0, SCALA3_PROBE.0]);
}
