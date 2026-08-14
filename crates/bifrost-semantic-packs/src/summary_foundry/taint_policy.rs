//! Build a `require-model` Java taint policy from translated CodeQL taint
//! endpoints (#1871 milestone 4.6).
//!
//! The demand sweep needs a taint policy whose source and sink selectors match
//! real Java call sites. Milestone 4.5 could only supply the checked-in toy
//! Python policy, whose selectors match no Java, so the sweep concluded every
//! repo Clean with an empty blocker ranking. This module closes that gap: it
//! turns a set of [`FoundryTaintEndpoint`]s -- translated from the CodeQL
//! `sourceModel` and `sinkModel` rows the milestone-1 translator skipped -- into
//! a policy that names the real APIs (`HttpServletRequest.getParameter` as a
//! source, `Statement.executeQuery` and `Runtime.exec` as sinks).
//!
//! Two properties are load-bearing and are documented rather than hidden:
//!
//! * The policy runs in `require-model` mode. An unmodeled call on a tainted
//!   path abstains instead of guessing, which is what turns an unmodeled callee
//!   into an `Inconclusive` conclusion with an attributable boundary -- the
//!   signal the sweep exists to measure.
//! * The selectors are name-based. The RQL `call` match constrains only the
//!   callee's spelled name; it cannot constrain the receiver's type, so a
//!   selector for `getParameter` matches every call to a method of that name
//!   regardless of receiver. This is an over-approximation: a match identifies a
//!   call site of interest, not a proven servlet call. The sweep reports its
//!   number under that caveat.

use std::collections::BTreeSet;

use super::ir::{FoundryEndpointPort, FoundryEndpointRole, FoundryTaintEndpoint};

/// The stable policy id the builder stamps. The sweep pins it so two runs name
/// the same policy.
pub const POLICY_ID: &str = "bifrost.summary-foundry.attacker-controlled-injection.require-model";

/// The single taint label every source carries and every sink accepts. One
/// label makes any matched source reach any matched sink, which is what the
/// demand sweep wants: the widest attacker-controlled-to-sink reachability the
/// endpoint set can express.
const TAINT_LABEL: &str = "attacker-controlled";

/// `java.lang` types are imported implicitly, so no `import` line names them and
/// slice selection cannot detect their use by scanning imports. The rest of the
/// endpoint packages require an explicit import, so a repo that uses them can be
/// found by its import declarations.
const IMPLICITLY_IMPORTED_PACKAGE: &str = "java.lang";

/// One deduplicated policy selector: a role, the callee name to match, and the
/// port the binding or operand names. Endpoints that reduce to the same triple
/// (many `Runtime.exec` overloads, for example) collapse to one entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PolicySelector {
    role: FoundryEndpointRole,
    /// The spelling that appears at the call site: the member name for a method,
    /// the type name for a constructor (`new ProcessBuilder(..)` spells
    /// `ProcessBuilder`, not `<init>`).
    callee_name: String,
    port: FoundryEndpointPort,
    /// The declaring type, kept for the human-readable display name only.
    display_type: String,
}

impl PolicySelector {
    /// The RQL spelling of the port, shared by a source `:bind` and a sink
    /// `:dangerous-operand` because both parse through the same port domain.
    fn port_spelling(&self) -> String {
        match self.port {
            FoundryEndpointPort::ReturnValue => "return-value".to_owned(),
            FoundryEndpointPort::Receiver => "receiver".to_owned(),
            FoundryEndpointPort::Parameter { ordinal } => {
                format!("(argument :index {ordinal})")
            }
        }
    }
}

/// The callee spelling a policy selector must match for this endpoint.
fn selector_callee_name(endpoint: &FoundryTaintEndpoint) -> &str {
    if endpoint.target.member == "<init>" {
        &endpoint.type_name
    } else {
        &endpoint.target.member
    }
}

/// Collapse an endpoint set into the deterministic, deduplicated selector set,
/// one selector per (role, callee name, port).
fn selectors(endpoints: &[FoundryTaintEndpoint]) -> Vec<PolicySelector> {
    let mut set: BTreeSet<PolicySelector> = BTreeSet::new();
    for endpoint in endpoints {
        // A source cannot bind a sink's receiver-only ports differently, but the
        // port set is already role-correct from translation, so every port maps.
        for port in &endpoint.ports {
            set.insert(PolicySelector {
                role: endpoint.role,
                callee_name: selector_callee_name(endpoint).to_owned(),
                port: *port,
                display_type: endpoint.type_name.clone(),
            });
        }
    }
    set.into_iter().collect()
}

/// A bare-identifier id for one selector, unique within its role's endpoint set.
///
/// Inline `(source :id ..)` / `(sink :id ..)` ids must be bare identifiers, so
/// the dotted CodeQL member spelling cannot be used verbatim. The id is the
/// sanitized callee name plus the sequence number that makes it unique when two
/// selectors share a callee name but differ in port.
fn selector_id(prefix: &str, callee_name: &str, sequence: usize) -> String {
    let mut sanitized = String::with_capacity(callee_name.len());
    for character in callee_name.chars() {
        if character.is_ascii_alphanumeric() {
            sanitized.push(character.to_ascii_lowercase());
        } else {
            sanitized.push('-');
        }
    }
    let trimmed = sanitized.trim_matches('-');
    let body = if trimmed.is_empty() { "call" } else { trimmed };
    format!("{prefix}-{body}-{sequence}")
}

/// Render one source or sink entry in the inline endpoint-set form.
fn render_entry(selector: &PolicySelector, id: &str) -> String {
    let display = format!("{}.{}", selector.display_type, selector.callee_name);
    let port = selector.port_spelling();
    match selector.role {
        FoundryEndpointRole::Source => format!(
            "      (source :id {id} :display-name \"{display}\"\n        \
             :categories [input.user-controlled io.external]\n        \
             :selector (rql :schema-version 1\n          \
             (language java (call :callee (name \"{name}\"))))\n        \
             :bind {port} :labels [{TAINT_LABEL}])",
            name = selector.callee_name,
        ),
        FoundryEndpointRole::Sink => format!(
            "      (sink :id {id} :display-name \"{display}\"\n        \
             :categories [data.sensitive]\n        \
             :selector (rql :schema-version 1\n          \
             (language java (call :callee (name \"{name}\"))))\n        \
             :dangerous-operand {port} :accepts [{TAINT_LABEL}])",
            name = selector.callee_name,
        ),
    }
}

/// The number of source and sink selectors a built policy carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyShape {
    pub sources: usize,
    pub sinks: usize,
}

/// Build the `require-model` Java taint policy for an endpoint set, and report
/// how many source and sink selectors it carries.
///
/// The result is deterministic: selectors are sorted and deduplicated, so the
/// same endpoint set yields byte-identical policy text.
pub fn build_require_model_java_taint_policy(
    endpoints: &[FoundryTaintEndpoint],
) -> (String, PolicyShape) {
    let selectors = selectors(endpoints);
    let mut source_entries = Vec::new();
    let mut sink_entries = Vec::new();
    for selector in &selectors {
        match selector.role {
            FoundryEndpointRole::Source => {
                let id = selector_id("src", &selector.callee_name, source_entries.len());
                source_entries.push(render_entry(selector, &id));
            }
            FoundryEndpointRole::Sink => {
                let id = selector_id("snk", &selector.callee_name, sink_entries.len());
                sink_entries.push(render_entry(selector, &id));
            }
        }
    }
    let shape = PolicyShape {
        sources: source_entries.len(),
        sinks: sink_entries.len(),
    };
    let policy = format!(
        r#"(policy
  :schema-version 1
  :id "{POLICY_ID}"
  :name "Attacker-controlled data reaches an injection sink (require-model)"
  :message "attacker-controlled data reached an injection sink"
  :severity warning
  :analysis (analysis
    :type taint
    :mode may
    :call-modeling (call-modeling :unmodeled require-model)
    :sources (endpoint-set :entries [
{sources}])
    :sinks (endpoint-set :entries [
{sinks}]))
  :classification (classification
    :fallback (classification-id :taxonomy "Foundry" :id "SUMMARY-INJECTION")))
"#,
        sources = source_entries.join("\n"),
        sinks = sink_entries.join("\n"),
    );
    (policy, shape)
}

/// The distinct packages a slice-selection scan can detect by import, sorted.
///
/// `java.lang` is implicitly imported, so it is excluded: a repo that calls
/// `Runtime.exec` names no `import java.lang.Runtime`. The remaining endpoint
/// packages (`java.sql`, `javax.servlet.http`, ...) are named by an explicit
/// import, so a repo that uses them is found by scanning its import declarations.
pub fn import_detectable_packages(endpoints: &[FoundryTaintEndpoint]) -> Vec<String> {
    let mut packages: BTreeSet<String> = BTreeSet::new();
    for endpoint in endpoints {
        if endpoint.package != IMPLICITLY_IMPORTED_PACKAGE && !endpoint.package.is_empty() {
            packages.insert(endpoint.package.clone());
        }
    }
    packages.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary_foundry::codeql::translate_codeql_taint_endpoints;
    use crate::summary_foundry::ir::{
        FoundryEvidence, FoundrySignature, FoundryTaintEndpoint, FoundryTarget,
    };

    fn endpoint(
        role: FoundryEndpointRole,
        package: &str,
        type_name: &str,
        member: &str,
        ports: Vec<FoundryEndpointPort>,
    ) -> FoundryTaintEndpoint {
        FoundryTaintEndpoint {
            role,
            target: FoundryTarget {
                artifact_path: format!("{}/{type_name}.class", package.replace('.', "/")),
                member: member.to_owned(),
                signature: FoundrySignature::AnyOverload,
            },
            package: package.to_owned(),
            type_name: type_name.to_owned(),
            subtypes: false,
            ports,
            qualifier: None,
            kind: "test".to_owned(),
            provenance: "manual".to_owned(),
            evidence: FoundryEvidence {
                file: "test.yml".to_owned(),
                row: 1,
                text: String::new(),
            },
        }
    }

    #[test]
    fn a_source_binds_its_output_port_and_a_sink_names_its_operand() {
        let endpoints = vec![
            endpoint(
                FoundryEndpointRole::Source,
                "javax.servlet.http",
                "HttpServletRequest",
                "getParameter",
                vec![FoundryEndpointPort::ReturnValue],
            ),
            endpoint(
                FoundryEndpointRole::Sink,
                "java.sql",
                "Statement",
                "executeQuery",
                vec![FoundryEndpointPort::Parameter { ordinal: 0 }],
            ),
        ];
        let (policy, shape) = build_require_model_java_taint_policy(&endpoints);

        assert_eq!(
            shape,
            PolicyShape {
                sources: 1,
                sinks: 1
            }
        );
        assert!(policy.contains("(call-modeling :unmodeled require-model)"));
        assert!(policy.contains("(language java (call :callee (name \"getParameter\"))))"));
        assert!(policy.contains(":bind return-value :labels [attacker-controlled]"));
        assert!(policy.contains("(language java (call :callee (name \"executeQuery\"))))"));
        assert!(
            policy
                .contains(":dangerous-operand (argument :index 0) :accepts [attacker-controlled]")
        );
    }

    #[test]
    fn a_constructor_endpoint_matches_the_type_name_at_the_call_site() {
        let endpoints = vec![endpoint(
            FoundryEndpointRole::Sink,
            "java.lang",
            "ProcessBuilder",
            "<init>",
            vec![FoundryEndpointPort::Parameter { ordinal: 0 }],
        )];
        let (policy, _) = build_require_model_java_taint_policy(&endpoints);

        // `new ProcessBuilder(cmd)` spells the callee `ProcessBuilder`, not
        // `<init>`, so the selector matches the type name.
        assert!(policy.contains("(call :callee (name \"ProcessBuilder\"))"));
        assert!(!policy.contains("<init>"));
    }

    #[test]
    fn overloads_collapse_to_one_selector_per_callee_and_port() {
        // Two `exec` overloads with the same port produce one selector; a second
        // port produces a second.
        let endpoints = vec![
            endpoint(
                FoundryEndpointRole::Sink,
                "java.lang",
                "Runtime",
                "exec",
                vec![FoundryEndpointPort::Parameter { ordinal: 0 }],
            ),
            endpoint(
                FoundryEndpointRole::Sink,
                "java.lang",
                "Runtime",
                "exec",
                vec![FoundryEndpointPort::Parameter { ordinal: 0 }],
            ),
            endpoint(
                FoundryEndpointRole::Sink,
                "java.lang",
                "Runtime",
                "exec",
                vec![FoundryEndpointPort::Parameter { ordinal: 2 }],
            ),
        ];
        let (_, shape) = build_require_model_java_taint_policy(&endpoints);
        assert_eq!(
            shape,
            PolicyShape {
                sources: 0,
                sinks: 2
            }
        );
    }

    #[test]
    fn import_detectable_packages_drop_java_lang() {
        let endpoints = vec![
            endpoint(
                FoundryEndpointRole::Source,
                "javax.servlet.http",
                "HttpServletRequest",
                "getParameter",
                vec![FoundryEndpointPort::ReturnValue],
            ),
            endpoint(
                FoundryEndpointRole::Sink,
                "java.lang",
                "Runtime",
                "exec",
                vec![FoundryEndpointPort::Parameter { ordinal: 0 }],
            ),
            endpoint(
                FoundryEndpointRole::Sink,
                "java.sql",
                "Statement",
                "executeQuery",
                vec![FoundryEndpointPort::Parameter { ordinal: 0 }],
            ),
        ];
        assert_eq!(
            import_detectable_packages(&endpoints),
            vec!["java.sql".to_owned(), "javax.servlet.http".to_owned()]
        );
    }

    #[test]
    fn the_policy_is_deterministic_and_id_stable() {
        let endpoints = vec![
            endpoint(
                FoundryEndpointRole::Sink,
                "java.sql",
                "Statement",
                "executeQuery",
                vec![FoundryEndpointPort::Parameter { ordinal: 0 }],
            ),
            endpoint(
                FoundryEndpointRole::Source,
                "javax.servlet.http",
                "HttpServletRequest",
                "getParameter",
                vec![FoundryEndpointPort::ReturnValue],
            ),
        ];
        let (first, _) = build_require_model_java_taint_policy(&endpoints);
        let (second, _) = build_require_model_java_taint_policy(&endpoints);
        assert_eq!(first, second);
        assert!(first.contains(POLICY_ID));
    }

    /// The translator and the builder compose: real CodeQL rows become a policy
    /// that names the real APIs.
    #[test]
    fn real_injection_rows_translate_and_build_into_a_policy() {
        const SLICE: &str = r#"
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: sourceModel
    data:
      - ["javax.servlet.http", "HttpServletRequest", False, "getParameter", "(String)", "", "ReturnValue", "remote", "manual"]
  - addsTo:
      pack: codeql/java-all
      extensible: sinkModel
    data:
      - ["java.sql", "Statement", True, "executeQuery", "", "", "Argument[0]", "sql-injection", "manual"]
      - ["java.lang", "Runtime", True, "exec", "(String)", "", "Argument[0]", "command-injection", "ai-manual"]
"#;
        let files = vec![("slice.model.yml".to_owned(), SLICE.as_bytes().to_vec())];
        let translation = translate_codeql_taint_endpoints(&files).expect("slice parses");
        let (policy, shape) = build_require_model_java_taint_policy(&translation.endpoints);

        assert_eq!(
            shape,
            PolicyShape {
                sources: 1,
                sinks: 2
            }
        );
        assert!(policy.contains("(call :callee (name \"getParameter\"))"));
        assert!(policy.contains("(call :callee (name \"executeQuery\"))"));
        assert!(policy.contains("(call :callee (name \"exec\"))"));
    }
}
