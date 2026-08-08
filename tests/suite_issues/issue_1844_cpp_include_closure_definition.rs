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
//!
//! The corpus reaches the reference through the shape
//! `out_of_line_member_reaches_the_reachable_twin` reproduces: a file-scope
//! `using namespace` plus an out-of-line member definition. The enclosing
//! lexical scope is then just the class (`Logger`), the namespace-qualified
//! tier is never tried, and the visibility-aware resolvers all report missing -
//! so the answer came from the scope-blind `resolve_in_enclosing_scopes`
//! fallback, which took the first indexed declaration of the composed name with
//! no reachability test at all.

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

/// The corpus's `Logger` header, reduced to the three properties that matter.
/// Its class head is macro-decorated and has a virtual base, which is why the
/// index classifies even this body as a *forward* declaration - the corpus has
/// six declarations of `LOG4CXX_NS.Logger` and not one of them is full.
const LOGGER_H: &str = r#"#ifndef LOGGER_H
#define LOGGER_H
#include <log4cxx/level.h>
#include <log4cxx/spi/location/locationinfo.h>
namespace LOG4CXX_NS
{

namespace spi
{
class AppenderAttachable;
}

class Logger;

class LOG4CXX_EXPORT Logger
	: public virtual spi::AppenderAttachable
{
	public:
		void addEvent(const LevelPtr& level, const spi::LocationInfo& location) const;
};
}
#endif
"#;

/// A second header that forward-declares `Logger`, as `logmanager.h` does in
/// the corpus. `logger.cpp` includes both, so the owner lookup sees two forward
/// declarations and no full one.
const LOGMANAGER_H: &str = r#"#ifndef LOGMANAGER_H
#define LOGMANAGER_H
namespace LOG4CXX_NS
{
class Logger;

class LogManager
{
	public:
		static int count;
};
}
#endif
"#;

const LOCATIONINFO_H: &str = r#"#ifndef LOCATIONINFO_H
#define LOCATIONINFO_H
namespace LOG4CXX_NS
{
namespace spi
{
class LocationInfo
{
	public:
		int line;
};
}
}
#endif
"#;

/// The corpus shape, reproduced from the real repository by reduction. Four
/// properties must hold together, and dropping any one of them makes the answer
/// correct again:
///
/// 1. the owner class's body is not indexed as a full declaration (a
///    macro-decorated head with a virtual base - `class LOG4CXX_EXPORT Logger :
///    public virtual spi::AppenderAttachable`);
/// 2. two headers the file *directly* includes forward-declare that owner, so
///    the single-forward escape hatch in the owner lookup cannot fire and
///    `precise_parent_of` answers nothing;
/// 3. the member is defined out of line under a file-scope `using namespace`,
///    so the parser supplies no namespace ancestor and, with no indexed owner
///    to recover it from, the enclosing scope loses its namespace entirely;
/// 4. the referenced type has same-FQN declarations in two headers, only one of
///    which the file includes.
///
/// Every namespace-qualified tier then misses and resolution falls through to
/// the scope-blind `resolve_in_enclosing_scopes` walk, which answered the first
/// indexed declaration of `LOG4CXX_NS.LevelPtr` with no reachability test at
/// all - and `helpers/optionconverter.h` sorts before `level.h`.
#[test]
fn out_of_line_member_reaches_the_reachable_twin() {
    let logger_cpp = r#"#include <log4cxx/logger.h>
#include <log4cxx/logmanager.h>
#include <log4cxx/level.h>

using namespace LOG4CXX_NS;
using namespace LOG4CXX_NS::spi;

void Logger::addEvent(const LevelPtr& level, const LocationInfo& location) const
{
	(void) level;
	(void) location;
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("src/main/include/log4cxx/level.h", LEVEL_H)
        .file("src/main/include/log4cxx/logger.h", LOGGER_H)
        .file("src/main/include/log4cxx/logmanager.h", LOGMANAGER_H)
        .file(
            "src/main/include/log4cxx/spi/location/locationinfo.h",
            LOCATIONINFO_H,
        )
        .file(
            "src/main/include/log4cxx/helpers/optionconverter.h",
            OPTIONCONVERTER_H,
        )
        .file("src/main/cpp/logger.cpp", logger_cpp)
        .build();
    let result = definition_paths(
        &project,
        "src/main/cpp/logger.cpp",
        logger_cpp,
        "LevelPtr& level",
    );
    let paths = paths_of(&result);
    assert!(
        !paths
            .iter()
            .any(|path| path.ends_with("helpers/optionconverter.h")),
        "a declaration the include closure never reaches must not be the \
         navigation target: {result:#}"
    );
    assert!(
        paths.iter().any(|path| path.ends_with("log4cxx/level.h")),
        "the reachable declaration must be answered: {result:#}"
    );

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

/// Control for the same shape: when the closure reaches no declaration of the
/// name, the scope-blind answer stays. An out-of-closure target beats none.
#[test]
fn out_of_line_member_keeps_an_unreachable_answer() {
    let logger_cpp = r#"#include <log4cxx/logger.h>

using namespace LOG4CXX_NS;

void Logger::describe(const OnlyPtr& only) const
{
	(void) only;
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "src/main/include/log4cxx/logger.h",
            r#"#ifndef LOGGER_H
#define LOGGER_H
namespace LOG4CXX_NS
{
class Logger
{
	public:
		void describe(const int& only) const;
};
}
#endif
"#,
        )
        .file(
            "src/main/include/log4cxx/helpers/only.h",
            r#"#ifndef ONLY_H
#define ONLY_H
#include <memory>
namespace LOG4CXX_NS
{
class Only;
typedef std::shared_ptr<Only> OnlyPtr;
}
#endif
"#,
        )
        .file("src/main/cpp/logger.cpp", logger_cpp)
        .build();
    let result = definition_paths(
        &project,
        "src/main/cpp/logger.cpp",
        logger_cpp,
        "OnlyPtr& only",
    );
    assert!(
        paths_of(&result)
            .iter()
            .any(|path| path.ends_with("helpers/only.h")),
        "the only declaration of the name must still answer even though the \
         include closure does not reach it: {result:#}"
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
