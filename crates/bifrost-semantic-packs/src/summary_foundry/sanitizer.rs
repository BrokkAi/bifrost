//! The fixture engine's sanitizer path: the per-vocabulary-token breakout
//! metacharacter table and the adversarial-fixture generator built on it.
//!
//! A sanitizer entry claims that a method neutralizes taint for a named
//! injection context. A benign fixture would rubber-stamp a wrong claim: the
//! first sanitizer batch proposed six URL and URI percent-encoders as
//! `sql`/`shell`/`ldap`/`xpath` sanitizers because their surviving unreserved
//! characters (`-`, `*`, `~`, and the `%` and `_` of percent output) are
//! metacharacters in those grammars, while a benign string would have encoded
//! cleanly and confirmed every wrong entry. The gate here forecloses that: for
//! every context an entry claims to neutralize, it injects that context's ACTUAL
//! breakout metacharacter and demands the method encode or remove it; for every
//! context under `does_not_neutralize`, it injects the breakout and demands it
//! still flow. A context with no table metacharacter cannot be proven, so the
//! entry is rejected rather than shipped on the author's assertion.
//!
//! This module is the gate the held `foundry/k3-sanitizers` content passes
//! through. What is wired: parsing the held sanitizer shape, the metacharacter
//! table, adversarial probe generation, and the reject-unless-provable check.
//! What is a seam: executing an adversarial probe against a real library body to
//! confirm the encoding, and shipping a sanitizer as a bound summary, because
//! the authored procedure-summary IR carries transfers and effects but no
//! sanitizer/neutralize shape, so a sanitizer has no shipping representation to
//! bind yet. Proving a real escaper encodes a metacharacter also needs the real
//! body, which the synthetic-declaration fixture model of stage 4 cannot hold.

use serde::{Deserialize, Serialize};

/// The fixed injection-context vocabulary a sanitizer entry may name.
///
/// This is the vocabulary the held sanitizer content uses. A token outside it
/// fails to deserialize, which is the first line of the gate: an entry can only
/// claim a context the table knows how to attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionContext {
    Sql,
    Shell,
    Ldap,
    Xpath,
    Html,
    HtmlAttr,
    Xml,
    Css,
    Js,
    Log,
    Path,
    Url,
}

impl InjectionContext {
    /// Every context, for exhaustive checks over the vocabulary.
    pub const ALL: [Self; 12] = [
        Self::Sql,
        Self::Shell,
        Self::Ldap,
        Self::Xpath,
        Self::Html,
        Self::HtmlAttr,
        Self::Xml,
        Self::Css,
        Self::Js,
        Self::Log,
        Self::Path,
        Self::Url,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sql => "sql",
            Self::Shell => "shell",
            Self::Ldap => "ldap",
            Self::Xpath => "xpath",
            Self::Html => "html",
            Self::HtmlAttr => "html_attr",
            Self::Xml => "xml",
            Self::Css => "css",
            Self::Js => "js",
            Self::Log => "log",
            Self::Path => "path",
            Self::Url => "url",
        }
    }

    /// The breakout metacharacter a correct sanitizer for this context must
    /// neutralize. One entry per vocabulary token, chosen as the character whose
    /// survival most directly opens a break in that grammar:
    ///
    /// * `sql` and `xpath`: the single quote closes a string literal;
    /// * `shell`: the semicolon terminates a command;
    /// * `ldap`: the close paren ends a filter component (the `*)(` breakout);
    /// * `html`, `xml`: the left angle bracket opens a tag;
    /// * `html_attr`: the double quote closes a quoted attribute value;
    /// * `css`: the right brace closes a declaration block;
    /// * `js`: the single quote closes a string literal;
    /// * `log`: the newline forges a new log line (CR/LF injection);
    /// * `path`: the forward slash adds a path component;
    /// * `url`: the ampersand opens a new query parameter.
    ///
    /// A token with no metacharacter returns `None`, which the gate treats as
    /// unprovable and rejects, so a new vocabulary token can never ship on a
    /// benign payload by omission.
    pub const fn breakout_metacharacter(self) -> Option<&'static str> {
        Some(match self {
            Self::Sql => "'",
            Self::Shell => ";",
            Self::Ldap => ")",
            Self::Xpath => "'",
            Self::Html => "<",
            Self::HtmlAttr => "\"",
            Self::Xml => "<",
            Self::Css => "}",
            Self::Js => "'",
            Self::Log => "\n",
            Self::Path => "/",
            Self::Url => "&",
        })
    }
}

/// The input port a sanitizer neutralizes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SanitizerPort {
    Receiver,
    Parameter { ordinal: u32 },
}

/// The completeness a sanitizer entry claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SanitizerCompleteness {
    Partial,
    Complete,
}

/// The target of a sanitizer entry, in the held content's shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizerTarget {
    pub path: String,
    pub symbol: String,
    #[serde(default)]
    pub has_receiver: bool,
    pub parameter_count: u32,
}

/// One sanitizer entry, parsed from the held candidate shape.
///
/// Unknown fields are permitted because these are external candidate files that
/// carry review metadata (rationale, confidence, citations) beside the
/// load-bearing claim; the gate reads the claim and preserves the rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizerEntry {
    pub target: SanitizerTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    pub sanitized_input: SanitizerPort,
    pub output: serde_json::Value,
    pub neutralizes: Vec<InjectionContext>,
    #[serde(default)]
    pub does_not_neutralize: Vec<InjectionContext>,
    pub completeness: SanitizerCompleteness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub citations: Option<String>,
}

/// What one adversarial probe demands of the sanitizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SanitizerExpectation {
    /// The method must encode or remove the metacharacter: no finding.
    Neutralized,
    /// The method leaves the metacharacter live: the breakout still flows.
    Survives,
}

/// One adversarial probe: inject a context's breakout metacharacter and state
/// what must happen to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SanitizerProbe {
    pub context: InjectionContext,
    /// The exact breakout metacharacter injected. Never a benign payload: this
    /// is the character whose fate the claim stands or falls on.
    pub metacharacter: String,
    pub expectation: SanitizerExpectation,
}

/// The adversarial suite for one gated sanitizer entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SanitizerAdversarialSuite {
    pub target: String,
    pub sanitized_input: SanitizerPort,
    pub probes: Vec<SanitizerProbe>,
}

/// Why a sanitizer entry is rejected, never shipped on the author's assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum SanitizerRejection {
    /// The entry neutralizes nothing, so it is not a sanitizer.
    NoNeutralizedContext,
    /// The entry both neutralizes and does not neutralize one context.
    ContradictoryContext { context: String },
    /// A claimed context has no breakout metacharacter in the table, so the
    /// claim cannot be proven adversarially.
    UnprovableContext { context: String },
}

impl std::fmt::Display for SanitizerRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoNeutralizedContext => {
                formatter.write_str("the entry neutralizes no context, so it is not a sanitizer")
            }
            Self::ContradictoryContext { context } => write!(
                formatter,
                "the entry both neutralizes and does not neutralize `{context}`"
            ),
            Self::UnprovableContext { context } => write!(
                formatter,
                "context `{context}` has no breakout metacharacter, so the claim is unprovable"
            ),
        }
    }
}

impl std::error::Error for SanitizerRejection {}

/// Gate one sanitizer entry into its adversarial suite, or reject it.
///
/// Every claimed context becomes a `Neutralized` probe over its breakout
/// metacharacter, and every `does_not_neutralize` context becomes a `Survives`
/// probe over its metacharacter. A context the table cannot attack is rejected.
pub fn gate_sanitizer(
    entry: &SanitizerEntry,
) -> Result<SanitizerAdversarialSuite, SanitizerRejection> {
    if entry.neutralizes.is_empty() {
        return Err(SanitizerRejection::NoNeutralizedContext);
    }
    for context in &entry.neutralizes {
        if entry.does_not_neutralize.contains(context) {
            return Err(SanitizerRejection::ContradictoryContext {
                context: context.as_str().to_owned(),
            });
        }
    }

    let mut probes = Vec::new();
    for &context in &entry.neutralizes {
        probes.push(probe(context, SanitizerExpectation::Neutralized)?);
    }
    for &context in &entry.does_not_neutralize {
        probes.push(probe(context, SanitizerExpectation::Survives)?);
    }
    Ok(SanitizerAdversarialSuite {
        target: format!("{}#{}", entry.target.path, entry.target.symbol),
        sanitized_input: entry.sanitized_input.clone(),
        probes,
    })
}

fn probe(
    context: InjectionContext,
    expectation: SanitizerExpectation,
) -> Result<SanitizerProbe, SanitizerRejection> {
    let metacharacter =
        context
            .breakout_metacharacter()
            .ok_or_else(|| SanitizerRejection::UnprovableContext {
                context: context.as_str().to_owned(),
            })?;
    Ok(SanitizerProbe {
        context,
        metacharacter: metacharacter.to_owned(),
        expectation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guava HtmlEscapers entry, in the exact held shape.
    const GUAVA_HTML_ESCAPER: &str = r#"{
      "target": {
        "path": "com/google/common/html/HtmlEscapers.java",
        "symbol": "com.google.common.html.HtmlEscapers.htmlEscaper().escape",
        "has_receiver": true,
        "parameter_count": 1
      },
      "artifact": "com.google.guava:guava:33.6.0-jre",
      "sanitized_input": {"kind": "parameter", "ordinal": 0},
      "output": {"kind": "normal_return"},
      "neutralizes": ["html", "html_attr", "xml"],
      "does_not_neutralize": ["css", "js", "ldap", "log", "path", "shell", "sql", "url", "xpath"],
      "completeness": "partial",
      "rationale": "escapes the five HTML metacharacters",
      "confidence": "medium",
      "citations": "Javadoc of HtmlEscapers"
    }"#;

    #[test]
    fn every_vocabulary_token_has_a_breakout_metacharacter() {
        for context in InjectionContext::ALL {
            assert!(
                context.breakout_metacharacter().is_some(),
                "{} has no breakout metacharacter",
                context.as_str()
            );
        }
    }

    #[test]
    fn the_held_sanitizer_shape_parses_and_gates_to_adversarial_probes() {
        let entry: SanitizerEntry =
            serde_json::from_str(GUAVA_HTML_ESCAPER).expect("the held shape parses");
        let suite = gate_sanitizer(&entry).expect("a well-formed sanitizer gates");

        // Three neutralized contexts, nine does-not-neutralize contexts.
        assert_eq!(suite.probes.len(), 12);
        let neutralized = suite
            .probes
            .iter()
            .filter(|probe| probe.expectation == SanitizerExpectation::Neutralized)
            .map(|probe| (probe.context, probe.metacharacter.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            neutralized,
            vec![
                (InjectionContext::Html, "<"),
                (InjectionContext::HtmlAttr, "\""),
                (InjectionContext::Xml, "<"),
            ]
        );
        // No probe injects a benign payload: every payload is a known breakout
        // metacharacter for its context.
        for probe in &suite.probes {
            assert_eq!(
                Some(probe.metacharacter.as_str()),
                probe.context.breakout_metacharacter(),
                "probe for {} does not inject its context metacharacter",
                probe.context.as_str()
            );
        }
    }

    /// The exact failure the Decision Log records: a URL percent-encoder claimed
    /// as a `sql` sanitizer. The gate injects the SQL breakout metacharacter
    /// (`'`), not a benign payload, so the eventual execution can catch that the
    /// encoder leaves the quote live. Without this, a benign string would encode
    /// cleanly and confirm the wrong claim.
    #[test]
    fn a_percent_encoder_claiming_sql_is_attacked_with_the_sql_metacharacter() {
        let entry = SanitizerEntry {
            target: SanitizerTarget {
                path: "com/google/common/net/UrlEscapers.java".to_owned(),
                symbol: "com.google.common.net.UrlEscapers.urlFormParameterEscaper().escape"
                    .to_owned(),
                has_receiver: true,
                parameter_count: 1,
            },
            artifact: Some("com.google.guava:guava:33.6.0-jre".to_owned()),
            sanitized_input: SanitizerPort::Parameter { ordinal: 0 },
            output: serde_json::json!({"kind": "normal_return"}),
            neutralizes: vec![InjectionContext::Sql],
            does_not_neutralize: Vec::new(),
            completeness: SanitizerCompleteness::Partial,
            rationale: None,
            confidence: None,
            citations: None,
        };

        let suite = gate_sanitizer(&entry).expect("the entry gates");
        let sql = &suite.probes[0];
        assert_eq!(sql.context, InjectionContext::Sql);
        assert_eq!(sql.metacharacter, "'");
        assert_eq!(sql.expectation, SanitizerExpectation::Neutralized);
        // The payload is a grammar metacharacter, not an alphanumeric benign
        // string that the encoder would pass unchanged.
        assert!(!sql.metacharacter.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn a_sanitizer_that_neutralizes_nothing_is_rejected() {
        let entry = SanitizerEntry {
            target: SanitizerTarget {
                path: "p/Q.java".to_owned(),
                symbol: "p.Q.m".to_owned(),
                has_receiver: false,
                parameter_count: 1,
            },
            artifact: None,
            sanitized_input: SanitizerPort::Parameter { ordinal: 0 },
            output: serde_json::json!({"kind": "normal_return"}),
            neutralizes: Vec::new(),
            does_not_neutralize: vec![InjectionContext::Sql],
            completeness: SanitizerCompleteness::Partial,
            rationale: None,
            confidence: None,
            citations: None,
        };

        assert_eq!(
            gate_sanitizer(&entry),
            Err(SanitizerRejection::NoNeutralizedContext)
        );
    }

    #[test]
    fn a_contradictory_context_is_rejected() {
        let entry = SanitizerEntry {
            target: SanitizerTarget {
                path: "p/Q.java".to_owned(),
                symbol: "p.Q.m".to_owned(),
                has_receiver: false,
                parameter_count: 1,
            },
            artifact: None,
            sanitized_input: SanitizerPort::Parameter { ordinal: 0 },
            output: serde_json::json!({"kind": "normal_return"}),
            neutralizes: vec![InjectionContext::Html],
            does_not_neutralize: vec![InjectionContext::Html],
            completeness: SanitizerCompleteness::Partial,
            rationale: None,
            confidence: None,
            citations: None,
        };

        assert_eq!(
            gate_sanitizer(&entry),
            Err(SanitizerRejection::ContradictoryContext {
                context: "html".to_owned()
            })
        );
    }

    #[test]
    fn an_out_of_vocabulary_context_fails_to_parse() {
        let source = r#"{
          "target": {"path": "p/Q.java", "symbol": "p.Q.m", "parameter_count": 1},
          "sanitized_input": {"kind": "parameter", "ordinal": 0},
          "output": {"kind": "normal_return"},
          "neutralizes": ["smtp"],
          "completeness": "partial"
        }"#;
        assert!(serde_json::from_str::<SanitizerEntry>(source).is_err());
    }
}
