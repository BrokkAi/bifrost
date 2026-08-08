//! Issue #1844: forward navigation answered a declaration the reference cannot
//! see. log4cxx declares `LevelPtr` identically in `level.h` and in
//! `helpers/optionconverter.h`. `logger.cpp` includes only `<log4cxx/level.h>`
//! and reaches `optionconverter.h` through no include closure, yet
//! `get_definitions_by_location` answered the `optionconverter.h` twin as the
//! only definition - so the one navigation target was a file the reference
//! cannot reach, and the inverse on that target covered none of the 21 real
//! sites.
//!
//! Same-FQN declarations are alternate spellings of one entity, so the answer
//! must not become ambiguous when several are reachable. What it must do is
//! prefer the declarations the reference file's include closure reaches, and
//! stay unchanged when the closure reaches none of them.

use crate::common::{BuiltInlineTestProject, InlineTestProject, call_tool};
use brokk_bifrost::searchtools::{
    ScanUsagesByLocationParams, ScanUsagesTarget, scan_usages_by_location,
};
use brokk_bifrost::{CppAnalyzer, Language};
use serde_json::{Value, json};

const LEVEL_H: &str = r#"#ifndef LEVEL_H
#define LEVEL_H
#include <memory>
namespace LOG4CXX_NS
{
class Level;
typedef std::shared_ptr<Level> LevelPtr;

class Level
{
	public:
		int value;
};
}
#endif
"#;

const OPTIONCONVERTER_H: &str = r#"#ifndef OPT_H
#define OPT_H
#include <memory>
namespace LOG4CXX_NS
{
class Level;
typedef std::shared_ptr<Level> LevelPtr;

namespace helpers
{
class OptionConverter
{
	public:
		static LevelPtr toLevel();
};
}
}
#endif
"#;

const LOGGER_CPP: &str = r#"#include <log4cxx/level.h>

namespace LOG4CXX_NS
{
void use(const LevelPtr& level)
{
	(void) level;
}
}
"#;

fn definition_paths(
    project: &BuiltInlineTestProject,
    path: &str,
    source: &str,
    needle: &str,
) -> Value {
    let start = source
        .find(needle)
        .unwrap_or_else(|| panic!("`{needle}` is not present in {path}"));
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current_line)| current_line)
        .chars()
        .count()
        + 1;
    let args = json!({"references": [{"path": path, "line": line, "column": column}]}).to_string();
    call_tool(project, "get_definitions_by_location", &args)["results"][0].clone()
}

fn paths_of(result: &Value) -> Vec<String> {
    result["definitions"]
        .as_array()
        .map(|definitions| {
            definitions
                .iter()
                .filter_map(|definition| definition["path"].as_str())
                .map(|path| path.replace('\\', "/"))
                .collect()
        })
        .unwrap_or_default()
}

/// The census shape: two identical `LevelPtr` typedefs, and a consumer whose
/// include closure reaches exactly one of them.
#[test]
fn definition_prefers_the_reachable_same_fqn_twin() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("src/main/include/log4cxx/level.h", LEVEL_H)
        .file(
            "src/main/include/log4cxx/helpers/optionconverter.h",
            OPTIONCONVERTER_H,
        )
        .file("src/main/cpp/logger.cpp", LOGGER_CPP)
        .build();
    let result = definition_paths(
        &project,
        "src/main/cpp/logger.cpp",
        LOGGER_CPP,
        "LevelPtr& level",
    );
    let paths = paths_of(&result);
    assert!(
        paths.iter().any(|path| path.ends_with("log4cxx/level.h")),
        "the declaration the reference's include closure reaches must be a \
         navigation target: {result:#}"
    );
    assert!(
        !paths
            .iter()
            .any(|path| path.ends_with("helpers/optionconverter.h")),
        "a declaration outside the reference's include closure must not be \
         offered instead: {result:#}"
    );

    // The point of the preference: the answered target's inverse must cover
    // the reference it was answered for.
    let definition = &result["definitions"][0];
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let mut scan = scan_usages_by_location(
        &analyzer,
        ScanUsagesByLocationParams {
            targets: vec![ScanUsagesTarget {
                path: definition["path"]
                    .as_str()
                    .expect("definition path")
                    .to_string(),
                line: definition["start_line"].as_u64().expect("definition line") as usize,
                column: None,
                symbol: None,
            }],
            include_tests: true,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    let entry = scan.results.remove(0);
    assert!(
        entry
            .files
            .iter()
            .any(|group| group.path.replace('\\', "/").ends_with("logger.cpp")),
        "the answered definition must be the one whose inverse covers the \
         reference: {entry:#?}"
    );
}

/// Control: when the closure reaches *no* declaration of the name, the answer
/// must not get worse than it is today - the twins stay available.
#[test]
fn unreachable_twins_still_answer() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("src/main/include/log4cxx/level.h", LEVEL_H)
        .file(
            "src/main/include/log4cxx/helpers/optionconverter.h",
            OPTIONCONVERTER_H,
        )
        .file(
            "src/main/cpp/orphan.cpp",
            r#"namespace LOG4CXX_NS
{
void useOrphan(const LevelPtr& level)
{
	(void) level;
}
}
"#,
        )
        .build();
    let source = r#"namespace LOG4CXX_NS
{
void useOrphan(const LevelPtr& level)
{
	(void) level;
}
}
"#;
    let result = definition_paths(
        &project,
        "src/main/cpp/orphan.cpp",
        source,
        "LevelPtr& level",
    );
    assert_ne!(
        result["status"], "ambiguous",
        "identical same-FQN declarations are alternate spellings of one \
         entity, never an ambiguity: {result:#}"
    );
}

/// Control: when the closure reaches *both* twins, they stay one answer rather
/// than becoming an ambiguity.
#[test]
fn reachable_twins_do_not_become_ambiguous() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("src/main/include/log4cxx/level.h", LEVEL_H)
        .file(
            "src/main/include/log4cxx/helpers/optionconverter.h",
            OPTIONCONVERTER_H,
        )
        .file(
            "src/main/cpp/both.cpp",
            r#"#include <log4cxx/level.h>
#include <log4cxx/helpers/optionconverter.h>

namespace LOG4CXX_NS
{
void useBoth(const LevelPtr& level)
{
	(void) level;
}
}
"#,
        )
        .build();
    let source = r#"#include <log4cxx/level.h>
#include <log4cxx/helpers/optionconverter.h>

namespace LOG4CXX_NS
{
void useBoth(const LevelPtr& level)
{
	(void) level;
}
}
"#;
    let result = definition_paths(&project, "src/main/cpp/both.cpp", source, "LevelPtr& level");
    assert_ne!(
        result["status"], "ambiguous",
        "two reachable identical declarations are one entity: {result:#}"
    );
    assert!(
        !paths_of(&result).is_empty(),
        "a reachable declaration must be answered: {result:#}"
    );
}

/// Control: a forward declaration inside the closure must not hide the real
/// definition in a header the reference file does not include.
#[test]
fn forward_declaration_in_closure_still_reaches_the_definition() {
    let user = r#"#include <n/fwd.h>

namespace n
{
void use(Level* level)
{
	(void) level;
}
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "include/n/fwd.h",
            "#ifndef FWD_H\n#define FWD_H\nnamespace n { class Level; }\n#endif\n",
        )
        .file(
            "include/n/level.h",
            "#ifndef LVL_H\n#define LVL_H\nnamespace n { class Level { public: int value; }; }\n#endif\n",
        )
        .file("src/user.cpp", user)
        .build();
    let result = definition_paths(&project, "src/user.cpp", user, "Level* level");
    assert!(
        paths_of(&result)
            .iter()
            .any(|path| path.ends_with("n/level.h")),
        "the class definition must stay reachable: {result:#}"
    );
}
