use super::nfa::{NfaBuilder, NfaState};
use super::*;

struct LiteralSyntax;
impl RegexSyntax for LiteralSyntax {
    fn group_prefix(&self, chars: &[char], start: usize) -> GroupPrefix {
        if chars.get(start + 1) == Some(&':') {
            GroupPrefix::Noncapturing
        } else {
            GroupPrefix::Unsupported
        }
    }
    fn incomplete_group_end(&self, _: &[char], _: usize) -> Option<usize> {
        None
    }
    fn inline_flags(&self, _: &[char], _: usize, _: RegexFlags) -> Option<(usize, RegexFlags)> {
        None
    }
    fn escape(&self, _: &[char], _: usize, _: bool, _: RegexFlags) -> Option<EscapeValue> {
        None
    }
    fn class_atom(&self, chars: &[char], start: usize, _: RegexFlags) -> Option<ClassAtom> {
        let value = *chars.get(start)?;
        assert_ne!(value, '\\', "literal-only test syntax");
        Some(ClassAtom {
            start,
            end: start + 1,
            value: Some(value),
            set: Some(CharacterSet::one(value)),
            kind: NormalizedKind::RegexLiteral,
            construct: Some(value.to_string()),
            backspace: false,
            incomplete: None,
        })
    }
    fn wildcard(&self, _: RegexFlags) -> CharacterSet {
        unreachable!("literal corpus has no wildcards")
    }
    fn fold_case(&self, set: CharacterSet, _: RegexFlags) -> CharacterSet {
        set
    }
    fn case_folding_is_complete(&self, _: RegexFlags) -> bool {
        true
    }
    fn verbose_whitespace(&self, _: char) -> bool {
        false
    }
    fn verbose_comment_terminator(&self, _: char) -> bool {
        false
    }
    fn supports_possessive_quantifiers(&self) -> bool {
        true
    }
    fn analyze(&self, _: &mut RegexAnalysis<'_>) {}
}
fn qs6_parse(pattern: &str) -> Vec<Fact> {
    RegexParser::new(
        pattern,
        RegexFlags {
            dialect_flags: 0,
            dotall: false,
            multiline: false,
            ignorecase: false,
            ascii: false,
            verbose: false,
            complete: true,
        },
        false,
        &LiteralSyntax,
    )
    .parse()
}

#[test]
fn qs6_finite_language_relations() {
    let patterns = ["a?", "b?", "a", "aa", "aaa", "ab", "ba", "(?:a|aa)"];
    let nfas = patterns.map(|p| RegexNfa::compile(&qs6_parse(p), 0, None).unwrap());
    // These finite languages are independently enumerated by CPython fullmatch.
    let languages: [&[&str]; 8] = [
        &["", "a"],
        &["", "b"],
        &["a"],
        &["aa"],
        &["aaa"],
        &["ab"],
        &["ba"],
        &["a", "aa"],
    ];
    for (i, left) in nfas.iter().enumerate() {
        for (j, right) in nfas.iter().enumerate() {
            let expected = languages[i]
                .iter()
                .any(|w| !w.is_empty() && languages[j].contains(w));
            assert_eq!(
                left.intersects_on_nonempty_string(right, &mut 65536)
                    .unwrap(),
                expected,
                "{i}, {j}"
            );
            for (k, pattern) in patterns.iter().enumerate() {
                let repeated = RegexNfa::compile(&qs6_parse(pattern), 0, None)
                    .unwrap()
                    .positive_closure()
                    .unwrap();
                let expected = languages[j].iter().any(|w| {
                    (1..w.len()).any(|split| {
                        if !languages[i].contains(&&w[..split]) {
                            return false;
                        }
                        // Independent word-break oracle for a positive closure.
                        let suffix = &w[split..];
                        let mut reachable = vec![false; suffix.len() + 1];
                        reachable[0] = true;
                        for offset in 0..suffix.len() {
                            if reachable[offset] {
                                for part in languages[k].iter().filter(|w| !w.is_empty()) {
                                    if suffix[offset..].starts_with(part) {
                                        reachable[offset + part.len()] = true;
                                    }
                                }
                            }
                        }
                        reachable[suffix.len()]
                    })
                });
                assert_eq!(
                    left.has_repartitioned_prefix(right, &repeated, &mut 65536)
                        .unwrap(),
                    expected,
                    "{i}, {j}, {k}"
                );
            }
        }
    }
}

#[test]
fn qs6_nfa_fork_and_resource_boundaries() {
    // Two one-character paths either reconverge on the same letter or
    // cannot synchronize. Starting at the fork itself also reaches it.
    for right in ['a', 'b'] {
        let nfa = RegexNfa {
            start: 0,
            end: 2,
            states: vec![
                NfaState {
                    transitions: vec![(CharacterSet::one('a'), 2)],
                    ..Default::default()
                },
                NfaState {
                    transitions: vec![(CharacterSet::one(right), 2)],
                    ..Default::default()
                },
                NfaState::default(),
            ],
        };
        let closures = nfa.epsilon_closures();
        assert_eq!(
            nfa.product_reaches_fork((0, 1), 2, &closures, &mut 65536)
                .unwrap(),
            right == 'a'
        );
        assert!(
            nfa.product_reaches_fork((2, 2), 2, &closures, &mut 65536)
                .unwrap()
        );
    }
    for count in [31, 32, 33] {
        let facts = qs6_parse(&format!("a{{{count}}}"));
        assert_eq!(RegexNfa::compile(&facts, 0, None).is_ok(), count <= 32);
    }
    // A linear 256-character language uses exactly the 512-state budget.
    // Redundant alternation wrappers must not consume its remaining states.
    for length in [255, 256, 257] {
        let facts = qs6_parse(&"a".repeat(length));
        assert_eq!(RegexNfa::compile(&facts, 0, None).is_ok(), length <= 256);
    }
    let mut builder = NfaBuilder {
        facts: &[],
        children: Vec::new(),
        selected_branch: None,
        capture_ids: &[],
        states: Vec::new(),
    };
    for _ in 0..512 {
        builder.new_state().unwrap();
    }
    assert!(matches!(builder.new_state(), Err(NfaError::Budget)));
    for depth in [126, 127, 128] {
        let facts = qs6_parse(&format!("{}a{}", "(".repeat(depth), ")".repeat(depth)));
        assert_eq!(
            facts
                .iter()
                .any(|f| f.kind == NormalizedKind::RegexIncomplete),
            depth >= 128
        );
    }
}

#[test]
fn qs6_multiple_repeat_is_incomplete() {
    for pattern in ["a**", "a*+*", "(ab){2}{3}"] {
        let facts = qs6_parse(pattern);
        assert!(
            facts
                .iter()
                .any(|f| f.construct.as_deref() == Some("nested-quantifier")),
            "{pattern}: {facts:?}"
        );
    }
}

#[test]
fn qs6_pending_fact_budget_reserves_incomplete_slot() {
    // Every repeated class member queues a diagnostic. Exercise the point
    // where parsed facts plus pending diagnostics exhaust the shared cap.
    for members in [2044, 2045, 2046, 2047, 2048] {
        let facts = qs6_parse(&format!("[{}]", "a".repeat(members)));
        assert!(facts.len() <= 4096, "members={members}: {}", facts.len());
        if members >= 2047 {
            assert!(
                facts
                    .iter()
                    .any(|f| f.construct.as_deref() == Some("regex-fact-budget")),
                "members={members}: {}",
                facts.len()
            );
        }
    }
}
