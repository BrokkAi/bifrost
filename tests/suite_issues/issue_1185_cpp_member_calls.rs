//! Issue #1185: C++ member-call inverse lookup must admit the specific visible
//! declaration/body owner peer for production-shaped receivers and out-of-line
//! owner recovery, without widening to wrong owners, callable shadows, or
//! namespace free functions that merely share the terminal name.

use crate::common::InlineTestProject;
use crate::common::usage_graph::{has_edge, usage_graph_at};
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitType, CppAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;
use std::sync::Arc;

fn cpp_analyzer_with_files(
    files: &[(&str, &str)],
) -> (crate::common::BuiltInlineTestProject, CppAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Cpp);
    for (path, contents) in files {
        builder = builder.file(*path, *contents);
    }
    let project = builder.build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn slash_path(file: &ProjectFile) -> String {
    file.rel_path().to_string_lossy().replace('\\', "/")
}

fn definition_by<F>(analyzer: &CppAnalyzer, mut predicate: F) -> CodeUnit
where
    F: FnMut(&CodeUnit) -> bool,
{
    analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| predicate(unit))
        .unwrap_or_else(|| panic!("missing matching C++ declaration"))
}

fn function_target(
    analyzer: &CppAnalyzer,
    source: &str,
    owner_identifier: &str,
    identifier: &str,
) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == identifier
            && slash_path(unit.source()) == source
            && analyzer
                .parent_of(unit)
                .is_some_and(|owner| owner.identifier() == owner_identifier)
    })
}

fn function_target_with_signature(
    analyzer: &CppAnalyzer,
    source: &str,
    owner_identifier: &str,
    identifier: &str,
    signature_fragment: &str,
) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == identifier
            && slash_path(unit.source()) == source
            && analyzer
                .parent_of(unit)
                .is_some_and(|owner| owner.identifier() == owner_identifier)
            && unit
                .signature()
                .is_some_and(|signature| signature.contains(signature_fragment))
    })
}

fn function_definition_target(
    analyzer: &CppAnalyzer,
    source: &str,
    identifier: &str,
    signature_fragment: &str,
) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == identifier
            && slash_path(unit.source()) == source
            && unit
                .signature()
                .is_some_and(|signature| signature.contains(signature_fragment))
    })
}

fn fixture_token_range(source: &str, labeled_line: &str, token: &str) -> (usize, usize) {
    let line_start = source
        .find(labeled_line)
        .unwrap_or_else(|| panic!("missing fixture line {labeled_line:?}"));
    let token_start = labeled_line
        .find(token)
        .unwrap_or_else(|| panic!("missing token {token:?} in fixture line {labeled_line:?}"));
    let start = line_start + token_start;
    (start, start + token.len())
}

fn authoritative_result(
    analyzer: &CppAnalyzer,
    target: &CodeUnit,
    candidate: &ProjectFile,
) -> (BTreeSet<(usize, usize)>, usize) {
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(candidate.clone()).collect()));
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            1,
            1000,
        )
        .result
    else {
        panic!("expected authoritative C++ success");
    };
    (
        hits_by_overload
            .values()
            .flatten()
            .filter(|hit| &hit.file == candidate)
            .map(|hit| (hit.start_offset, hit.end_offset))
            .collect(),
        unproven_total_by_overload.values().sum(),
    )
}

fn editor_ranges(
    analyzer: &CppAnalyzer,
    target: &CodeUnit,
    candidate: &ProjectFile,
) -> BTreeSet<(usize, usize)> {
    UsageFinder::new()
        .find_usages_default(analyzer, std::slice::from_ref(target))
        .all_hits_including_imports()
        .into_iter()
        .filter(|hit| &hit.file == candidate)
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect()
}

#[test]
fn qpid_style_peer_receivers_and_out_of_line_member_calls_stay_exact() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "proactor_container_impl.hpp",
            r#"
#pragma once
namespace proton {
class session {
public:
    int error() const;
    bool uninitialized() const;
};

class wrong_session {
public:
    int error() const;
    bool uninitialized() const;
};

class container {
public:
    class impl {
    public:
        int make_connection_lh(int);
        int listen_common_lh(const char*);
        void setup_reconnect(int*);
        void clear();
        void on_session_error(session& s, wrong_session& wrong);
        void dispatch();
    };
};
}
"#,
        ),
        (
            "proactor_container_impl.cpp",
            r#"
#include "proactor_container_impl.hpp"
namespace proton {
int session::error() const { return 1; }
bool session::uninitialized() const { return false; }
int wrong_session::error() const { return 2; }
bool wrong_session::uninitialized() const { return true; }

int container::impl::make_connection_lh(int) { return 1; }
int container::impl::listen_common_lh(const char*) { return 2; }
void container::impl::setup_reconnect(int*) {}
void container::impl::clear() {}

void container::impl::on_session_error(session& s, wrong_session& wrong) {
    int ec = s.error(); // positive-session-error
    bool pending = s.uninitialized(); // positive-session-uninitialized
    int wrong_ec = wrong.error(); // negative-wrong-owner-explicit
    bool wrong_pending = wrong.uninitialized(); // negative-wrong-owner-explicit
    (void) ec;
    (void) pending;
    (void) wrong_ec;
    (void) wrong_pending;
}

class wrong_impl {
public:
    int make_connection_lh(int);
    int listen_common_lh(const char*);
    void setup_reconnect(int*);
    void clear();
    void dispatch();
};

int wrong_impl::make_connection_lh(int) { return -1; }
int wrong_impl::listen_common_lh(const char*) { return -2; }
void wrong_impl::setup_reconnect(int*) {}
void wrong_impl::clear() {}

void container::impl::dispatch() {
    int* p = nullptr;
    int c = make_connection_lh(7); // positive-implicit-self-make
    int l = listen_common_lh("x"); // positive-implicit-self-listen
    setup_reconnect(p); // positive-implicit-self-reconnect
    clear(); // positive-implicit-self-clear
    auto setup_reconnect = +[](int*) {}; // negative-shadow
    setup_reconnect(p); // negative-shadow-call
    (void) c;
    (void) l;
}

void wrong_impl::dispatch() {
    int* p = nullptr;
    int c = make_connection_lh(11); // negative-wrong-owner-implicit-self
    int l = listen_common_lh("wrong"); // negative-wrong-owner-implicit-self
    setup_reconnect(p); // negative-wrong-owner-implicit-self
    clear(); // negative-wrong-owner-implicit-self
    (void) c;
    (void) l;
}

int make_connection_lh(double) { return 0; }
void clear() {}

int call_free_make() {
    return make_connection_lh(3.14); // negative-free-function
}

void call_free_clear() {
    clear(); // negative-free-function
}
}
"#,
        ),
    ]);

    let impl_file = project.file("proactor_container_impl.cpp");
    let source = impl_file.read_to_string().expect("impl source");

    let session_error =
        function_target(&analyzer, "proactor_container_impl.hpp", "session", "error");
    let session_error_definition = function_target_with_signature(
        &analyzer,
        "proactor_container_impl.cpp",
        "session",
        "error",
        "() const",
    );
    let session_uninitialized = function_target(
        &analyzer,
        "proactor_container_impl.hpp",
        "session",
        "uninitialized",
    );
    let session_uninitialized_definition = function_target_with_signature(
        &analyzer,
        "proactor_container_impl.cpp",
        "session",
        "uninitialized",
        "() const",
    );
    let make_connection = function_target(
        &analyzer,
        "proactor_container_impl.hpp",
        "impl",
        "make_connection_lh",
    );
    let listen_common = function_target(
        &analyzer,
        "proactor_container_impl.hpp",
        "impl",
        "listen_common_lh",
    );
    let setup_reconnect = function_target(
        &analyzer,
        "proactor_container_impl.hpp",
        "impl",
        "setup_reconnect",
    );
    let clear = function_target(&analyzer, "proactor_container_impl.hpp", "impl", "clear");
    let clear_definition = function_target_with_signature(
        &analyzer,
        "proactor_container_impl.cpp",
        "impl",
        "clear",
        "()",
    );

    let explicit_cases = [
        (
            session_error,
            BTreeSet::from([fixture_token_range(
                &source,
                "    int ec = s.error(); // positive-session-error",
                "error",
            )]),
            [fixture_token_range(
                &source,
                "    int wrong_ec = wrong.error(); // negative-wrong-owner-explicit",
                "error",
            )]
            .into_iter()
            .collect::<Vec<_>>(),
        ),
        (
            session_error_definition,
            BTreeSet::from([fixture_token_range(
                &source,
                "    int ec = s.error(); // positive-session-error",
                "error",
            )]),
            [fixture_token_range(
                &source,
                "    int wrong_ec = wrong.error(); // negative-wrong-owner-explicit",
                "error",
            )]
            .into_iter()
            .collect::<Vec<_>>(),
        ),
        (
            session_uninitialized,
            BTreeSet::from([fixture_token_range(
                &source,
                "    bool pending = s.uninitialized(); // positive-session-uninitialized",
                "uninitialized",
            )]),
            [fixture_token_range(
                &source,
                "    bool wrong_pending = wrong.uninitialized(); // negative-wrong-owner-explicit",
                "uninitialized",
            )]
            .into_iter()
            .collect::<Vec<_>>(),
        ),
        (
            session_uninitialized_definition,
            BTreeSet::from([fixture_token_range(
                &source,
                "    bool pending = s.uninitialized(); // positive-session-uninitialized",
                "uninitialized",
            )]),
            [fixture_token_range(
                &source,
                "    bool wrong_pending = wrong.uninitialized(); // negative-wrong-owner-explicit",
                "uninitialized",
            )]
            .into_iter()
            .collect::<Vec<_>>(),
        ),
    ];

    for (target, expected, negatives) in explicit_cases {
        let (targeted, unproven) = authoritative_result(&analyzer, &target, &impl_file);
        assert!(
            expected.is_subset(&targeted),
            "authoritative explicit receiver ranges must contain every required production call: targeted={targeted:?} expected={expected:?}"
        );
        assert_eq!(
            unproven, 0,
            "explicit receiver negatives must be proven exclusions"
        );
        let editor = editor_ranges(&analyzer, &target, &impl_file);
        assert!(
            expected.is_subset(&editor),
            "editor surface explicit receiver ranges must contain every required production call: editor={editor:?} expected={expected:?}"
        );
        for negative in negatives {
            assert!(
                !targeted.contains(&negative) && !editor.contains(&negative),
                "wrong-owner explicit receiver must stay excluded",
            );
        }
    }

    let implicit_cases = [
        (
            make_connection,
            BTreeSet::from([fixture_token_range(
                &source,
                "    int c = make_connection_lh(7); // positive-implicit-self-make",
                "make_connection_lh",
            )]),
            vec![
                fixture_token_range(
                    &source,
                    "    int c = make_connection_lh(11); // negative-wrong-owner-implicit-self",
                    "make_connection_lh",
                ),
                fixture_token_range(
                    &source,
                    "    return make_connection_lh(3.14); // negative-free-function",
                    "make_connection_lh",
                ),
            ],
        ),
        (
            listen_common,
            BTreeSet::from([fixture_token_range(
                &source,
                "    int l = listen_common_lh(\"x\"); // positive-implicit-self-listen",
                "listen_common_lh",
            )]),
            vec![fixture_token_range(
                &source,
                "    int l = listen_common_lh(\"wrong\"); // negative-wrong-owner-implicit-self",
                "listen_common_lh",
            )],
        ),
        (
            setup_reconnect,
            BTreeSet::from([fixture_token_range(
                &source,
                "    setup_reconnect(p); // positive-implicit-self-reconnect",
                "setup_reconnect",
            )]),
            vec![
                fixture_token_range(
                    &source,
                    "    setup_reconnect(p); // negative-shadow-call",
                    "setup_reconnect",
                ),
                fixture_token_range(
                    &source,
                    "    setup_reconnect(p); // negative-wrong-owner-implicit-self",
                    "setup_reconnect",
                ),
            ],
        ),
        (
            clear,
            BTreeSet::from([fixture_token_range(
                &source,
                "    clear(); // positive-implicit-self-clear",
                "clear",
            )]),
            vec![
                fixture_token_range(
                    &source,
                    "    clear(); // negative-wrong-owner-implicit-self",
                    "clear",
                ),
                fixture_token_range(&source, "    clear(); // negative-free-function", "clear"),
            ],
        ),
        (
            clear_definition,
            BTreeSet::from([fixture_token_range(
                &source,
                "    clear(); // positive-implicit-self-clear",
                "clear",
            )]),
            vec![
                fixture_token_range(
                    &source,
                    "    clear(); // negative-wrong-owner-implicit-self",
                    "clear",
                ),
                fixture_token_range(&source, "    clear(); // negative-free-function", "clear"),
            ],
        ),
    ];

    for (target, expected, negatives) in implicit_cases {
        let (targeted, unproven) = authoritative_result(&analyzer, &target, &impl_file);
        assert!(
            expected.is_subset(&targeted),
            "authoritative implicit-self ranges must contain every required production call: targeted={targeted:?} expected={expected:?}"
        );
        assert_eq!(
            unproven, 0,
            "implicit-self negatives must be proven exclusions"
        );
        let editor = editor_ranges(&analyzer, &target, &impl_file);
        assert!(
            expected.is_subset(&editor),
            "editor surface implicit-self ranges must contain every required production call: editor={editor:?} expected={expected:?}"
        );
        for negative in negatives {
            assert!(
                !targeted.contains(&negative) && !editor.contains(&negative),
                "wrong-owner/shadow/free-function implicit call must stay excluded",
            );
        }
    }

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &graph,
            "proton.container$impl.on_session_error",
            "proton.session.error"
        ) && has_edge(
            &graph,
            "proton.container$impl.on_session_error",
            "proton.session.uninitialized"
        ),
        "complete inverted graph must retain typed peer-receiver calls: {}",
        graph["edges"]
    );
}

#[test]
fn qpid_style_cpp_definition_uses_unique_visible_forward_owner() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "container.hpp",
            r#"
#pragma once
namespace proton {
class container {
public:
    class impl;
};
}
"#,
        ),
        (
            "proactor_container_impl.hpp",
            r#"
#pragma once
#include "container.hpp"
namespace proton {
class container::impl {
public:
    void setup_reconnect(int*);
    void dispatch();
};
}
"#,
        ),
        (
            "proactor_container_impl.cpp",
            r#"
#include "proactor_container_impl.hpp"
namespace proton {
void container::impl::setup_reconnect(int*) {}

void container::impl::dispatch() {
    int* connection = nullptr;
    setup_reconnect(connection); // positive-definition-target
    auto setup_reconnect = +[](int*) {};
    setup_reconnect(connection); // negative-local-shadow
}
}
"#,
        ),
    ]);

    let implementation = project.file("proactor_container_impl.cpp");
    let source = implementation.read_to_string().expect("impl source");
    let target = function_definition_target(
        &analyzer,
        "proactor_container_impl.cpp",
        "setup_reconnect",
        "int",
    );
    let expected = fixture_token_range(
        &source,
        "    setup_reconnect(connection); // positive-definition-target",
        "setup_reconnect",
    );
    let shadow = fixture_token_range(
        &source,
        "    setup_reconnect(connection); // negative-local-shadow",
        "setup_reconnect",
    );

    let (targeted, unproven) = authoritative_result(&analyzer, &target, &implementation);
    assert!(
        targeted.contains(&expected),
        "the .cpp definition target must recover its unique include-visible forward owner: {targeted:?}"
    );
    assert_eq!(unproven, 0, "the local callable shadow must be proven");
    assert!(
        !targeted.contains(&shadow),
        "the recovered owner must not admit a local callable shadow"
    );
}

#[test]
fn log4cxx_style_qualified_static_calls_stay_exact() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "helpers.hpp",
            r#"
#pragma once
#define LOG4CXX_NS log4cxx
namespace LOG4CXX_NS::helpers {
struct Transcoder {
    static const char* encodeCharsetName(const char*);
};

struct System {
    static const char* getProperty(const char*);
};

struct CharsetEncoder {
    static int getDefaultEncoder();
};
}
"#,
        ),
        (
            "helpers.cpp",
            r#"
#include "helpers.hpp"
namespace log4cxx::helpers {
const char* Transcoder::encodeCharsetName(const char*) { return "utf8"; }
const char* System::getProperty(const char*) { return "value"; }
int CharsetEncoder::getDefaultEncoder() { return 1; }
}
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "helpers.hpp"
using namespace log4cxx::helpers;

namespace wrong {
struct System {
    static const char* getProperty(const char*);
};
const char* System::getProperty(const char*) { return "wrong"; }
}

void consume() {
    using LogString = const char*;
    const char* key = "key";
    auto encoded = Transcoder::encodeCharsetName("utf8"); // positive-transcoder
    auto option = System::getProperty("key"); // positive-system
    LogString value(System::getProperty(key)); // positive-system-recovered-direct-init
    auto encoder = CharsetEncoder::getDefaultEncoder(); // positive-encoder
    auto wrong = wrong::System::getProperty("nope"); // negative-wrong-owner-qualified-static
    (void) encoded;
    (void) option;
    (void) encoder;
    (void) wrong;
}
"#,
        ),
    ]);

    let consumer = project.file("consumer.cpp");
    let source = consumer.read_to_string().expect("consumer source");

    let transcoder = function_target(&analyzer, "helpers.hpp", "Transcoder", "encodeCharsetName");
    let system = function_target(&analyzer, "helpers.hpp", "System", "getProperty");
    let encoder = function_target(
        &analyzer,
        "helpers.hpp",
        "CharsetEncoder",
        "getDefaultEncoder",
    );

    let cases = [
        (
            transcoder,
            BTreeSet::from([fixture_token_range(
                &source,
                "    auto encoded = Transcoder::encodeCharsetName(\"utf8\"); // positive-transcoder",
                "encodeCharsetName",
            )]),
            Vec::new(),
        ),
        (
            system,
            BTreeSet::from([
                fixture_token_range(
                    &source,
                    "    auto option = System::getProperty(\"key\"); // positive-system",
                    "getProperty",
                ),
                fixture_token_range(
                    &source,
                    "    LogString value(System::getProperty(key)); // positive-system-recovered-direct-init",
                    "getProperty",
                ),
            ]),
            vec![fixture_token_range(
                &source,
                "    auto wrong = wrong::System::getProperty(\"nope\"); // negative-wrong-owner-qualified-static",
                "getProperty",
            )],
        ),
        (
            encoder,
            BTreeSet::from([fixture_token_range(
                &source,
                "    auto encoder = CharsetEncoder::getDefaultEncoder(); // positive-encoder",
                "getDefaultEncoder",
            )]),
            Vec::new(),
        ),
    ];

    for (target, expected, negatives) in cases {
        let (targeted, unproven) = authoritative_result(&analyzer, &target, &consumer);
        assert!(
            expected.is_subset(&targeted),
            "qualified static call ranges must contain every required production call: targeted={targeted:?} expected={expected:?}"
        );
        assert_eq!(
            unproven, 0,
            "qualified static negatives must be proven exclusions"
        );
        let editor = editor_ranges(&analyzer, &target, &consumer);
        assert!(
            expected.is_subset(&editor),
            "editor surface qualified static ranges must contain every required production call: editor={editor:?} expected={expected:?}"
        );
        for negative in negatives {
            assert!(
                !targeted.contains(&negative) && !editor.contains(&negative),
                "wrong-owner qualified static call must stay excluded",
            );
        }
    }
}

#[test]
fn proton_qualified_free_function_does_not_hit_same_named_method_targets() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "value.hpp",
            r#"
#pragma once
namespace proton {
struct value {
    int get() const;
    void get(int&) const;
};

template <class T> T get(const value&);
template <class T> void get(const value&, T&);
}
"#,
        ),
        (
            "value.cpp",
            r#"
#include "value.hpp"
namespace proton {
int value::get() const { return 1; }
void value::get(int&) const {}

template <class T>
T get(const value&) { return T(); }

template <class T>
void get(const value&, T&) {}

template int get<int>(const value&);
template void get<int>(const value&, int&);
}
"#,
        ),
        (
            "consumer.cpp",
            r#"
#include "value.hpp"
void consume(proton::value& v, int& x) {
    proton::get(v, x); // negative-qualified-free-function
}
"#,
        ),
    ]);

    let consumer = project.file("consumer.cpp");
    let source = consumer.read_to_string().expect("consumer source");
    let negative = fixture_token_range(
        &source,
        "    proton::get(v, x); // negative-qualified-free-function",
        "get",
    );

    let zero_arg_get =
        function_target_with_signature(&analyzer, "value.hpp", "value", "get", "() const");
    let out_arg_get =
        function_target_with_signature(&analyzer, "value.hpp", "value", "get", "(int &)");

    for target in [zero_arg_get, out_arg_get] {
        let (targeted, unproven) = authoritative_result(&analyzer, &target, &consumer);
        assert!(
            targeted.is_empty(),
            "qualified namespace free function must not hit same-named method target: {targeted:?}"
        );
        assert_eq!(
            unproven, 0,
            "qualified free function false premise must be proven negative"
        );
        let editor = editor_ranges(&analyzer, &target, &consumer);
        assert!(
            !editor.contains(&negative),
            "editor surface must not misclassify qualified free function as a method call"
        );
    }
}

#[test]
fn qpid_production_shaped_session_overrides_and_value_operator_body_stay_exact() {
    let (project, analyzer) = cpp_analyzer_with_files(&[
        (
            "cpp/include/proton/error_condition.hpp",
            r#"
#pragma once
namespace proton {
class error_condition {};
}
"#,
        ),
        (
            "cpp/include/proton/endpoint.hpp",
            r#"
#pragma once
#include "error_condition.hpp"
namespace proton {
class endpoint {
  public:
    virtual ~endpoint() {}
    virtual bool uninitialized() const = 0;
    virtual class error_condition error() const = 0;
};
}
"#,
        ),
        (
            "cpp/include/proton/session.hpp",
            r#"
#pragma once
#include "endpoint.hpp"
namespace proton {
class session : public endpoint {
  public:
    bool uninitialized() const override;
    class error_condition error() const override;
};
class wrong_endpoint : public endpoint {
  public:
    bool uninitialized() const override;
    class error_condition error() const override;
};
}
"#,
        ),
        (
            "cpp/include/proton/value.hpp",
            r#"
#pragma once
namespace proton {
namespace internal {
class data {
  public:
    void clear();
    void copy(const data&);
};
class value_base {
  protected:
    internal::data& data();
    internal::data data_;
};
}
class value : public internal::value_base {
  public:
    value& operator=(const value&);
    bool empty() const;
    void clear();
};
void clear();
}
"#,
        ),
        (
            "cpp/src/endpoint.cpp",
            r#"
#include "proton/session.hpp"
namespace proton {
bool session::uninitialized() const { return false; }
bool wrong_endpoint::uninitialized() const { return true; }
}
"#,
        ),
        (
            "cpp/src/session.cpp",
            r#"
#include "proton/session.hpp"
namespace proton {
error_condition session::error() const { return error_condition(); }
error_condition wrong_endpoint::error() const { return error_condition(); }
}
"#,
        ),
        (
            "cpp/src/session_options.cpp",
            r#"
#include "proton/session.hpp"
namespace proton {
void apply(session& s, wrong_endpoint& wrong) {
    if (s.uninitialized()) { } // positive-session-uninitialized-body
    if (wrong.uninitialized()) { } // negative-wrong-owner-uninitialized
}
}
"#,
        ),
        (
            "cpp/examples/tx_recv.cpp",
            r#"
#include "proton/session.hpp"
namespace proton {
void on_session_error(session& s, wrong_endpoint& wrong) {
    s.error(); // positive-session-error-body
    wrong.error(); // negative-wrong-owner-error
}
}
"#,
        ),
        (
            "cpp/src/value.cpp",
            r#"
#include "proton/value.hpp"
namespace proton {
value& value::operator=(const value& x) {
    if (this != &x) {
        if (x.empty())
            clear(); // positive-value-clear-operator
        else
            data().copy(x.data_);
    }
    return *this;
}
bool value::empty() const { return false; }
void value::clear() {}
void clear() {}
namespace internal {
data& value_base::data() { return data_; }
void data::clear() {}
void data::copy(const data&) {}
}
void consume(value& value_ref) {
    value_ref.data().clear(); // negative-other-owner-clear
    clear(); // negative-free-clear
}
}
"#,
        ),
    ]);

    let tx_recv = project.file("cpp/examples/tx_recv.cpp");
    let tx_recv_source = tx_recv.read_to_string().expect("tx_recv source");
    let session_options = project.file("cpp/src/session_options.cpp");
    let session_options_source = session_options
        .read_to_string()
        .expect("session_options source");
    let value_source_file = project.file("cpp/src/value.cpp");
    let value_source = value_source_file.read_to_string().expect("value source");

    let session_error_definition = function_target_with_signature(
        &analyzer,
        "cpp/src/session.cpp",
        "session",
        "error",
        "() const",
    );
    let session_uninitialized_definition = function_target_with_signature(
        &analyzer,
        "cpp/src/endpoint.cpp",
        "session",
        "uninitialized",
        "() const",
    );
    let clear_definition =
        function_target_with_signature(&analyzer, "cpp/src/value.cpp", "value", "clear", "()");

    let error_positive = fixture_token_range(
        &tx_recv_source,
        "    s.error(); // positive-session-error-body",
        "error",
    );
    let error_negative = fixture_token_range(
        &tx_recv_source,
        "    wrong.error(); // negative-wrong-owner-error",
        "error",
    );
    let (error_targeted, error_unproven) =
        authoritative_result(&analyzer, &session_error_definition, &tx_recv);
    assert!(
        error_targeted.contains(&error_positive),
        "session body target must recover explicit receiver override call: {error_targeted:?}"
    );
    assert!(
        !error_targeted.contains(&error_negative),
        "wrong owner explicit receiver must stay excluded: {error_targeted:?}"
    );
    assert_eq!(error_unproven, 0, "session error negatives must be proven");

    let uninitialized_positive = fixture_token_range(
        &session_options_source,
        "    if (s.uninitialized()) { } // positive-session-uninitialized-body",
        "uninitialized",
    );
    let uninitialized_negative = fixture_token_range(
        &session_options_source,
        "    if (wrong.uninitialized()) { } // negative-wrong-owner-uninitialized",
        "uninitialized",
    );
    let (uninitialized_targeted, uninitialized_unproven) = authoritative_result(
        &analyzer,
        &session_uninitialized_definition,
        &session_options,
    );
    assert!(
        uninitialized_targeted.contains(&uninitialized_positive),
        "session body target must recover explicit receiver override call from endpoint.cpp: {uninitialized_targeted:?}"
    );
    assert!(
        !uninitialized_targeted.contains(&uninitialized_negative),
        "wrong owner explicit receiver must stay excluded: {uninitialized_targeted:?}"
    );
    assert_eq!(
        uninitialized_unproven, 0,
        "session uninitialized negatives must be proven"
    );

    let clear_positive = fixture_token_range(
        &value_source,
        "            clear(); // positive-value-clear-operator",
        "clear",
    );
    let clear_other_owner_negative = fixture_token_range(
        &value_source,
        "    value_ref.data().clear(); // negative-other-owner-clear",
        "clear",
    );
    let clear_free_negative = fixture_token_range(
        &value_source,
        "    clear(); // negative-free-clear",
        "clear",
    );
    let (clear_targeted, clear_unproven) =
        authoritative_result(&analyzer, &clear_definition, &value_source_file);
    assert!(
        clear_targeted.contains(&clear_positive),
        "value::operator= must recover bare clear() as an implicit self call: {clear_targeted:?}"
    );
    assert!(
        !clear_targeted.contains(&clear_other_owner_negative)
            && !clear_targeted.contains(&clear_free_negative),
        "non-target clear calls must stay excluded: {clear_targeted:?}"
    );
    let clear_editor = editor_ranges(&analyzer, &clear_definition, &value_source_file);
    assert!(
        !clear_editor.contains(&clear_other_owner_negative)
            && !clear_editor.contains(&clear_free_negative),
        "editor surface must not misclassify non-target clear calls: {clear_editor:?}"
    );
    assert!(
        clear_unproven <= 1,
        "at most one control call may remain unproven while the operator-body target stays exact"
    );
}
