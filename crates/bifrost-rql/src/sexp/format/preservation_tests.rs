use super::*;
use brokk_bifrost_test_macros::hardwon;

#[test]
#[hardwon("63e7ce2b798b: formatting discarded comments in empty containers")]
fn empty_container_comments_survive_formatting() {
    for source in ["(call :args [ ;keep\n])", "( ;first\n ;second\n)"] {
        let options = SexpFormatOptions {
            line_width: 120,
            indent: "  ",
        };
        let formatted = format_sexp_document(source, options).unwrap();
        let expected = if source.contains(";keep") {
            "(call\n  :args\n  [\n    ;keep\n  ]\n)"
        } else {
            "(\n  ;first\n  ;second\n)"
        };
        assert_eq!(formatted, expected);
        assert_eq!(
            format_sexp_document(&formatted, options).unwrap(),
            formatted
        );
        let before = parse_sexp_document(source).unwrap();
        let after = parse_sexp_document(&formatted).unwrap();
        let atoms = |exprs: &[Expr]| {
            let mut pending: Vec<_> = exprs.iter().collect();
            let mut values = Vec::new();
            while let Some(expr) = pending.pop() {
                match &expr.kind {
                    ExprKind::List(items) | ExprKind::Vector(items) => {
                        values.push(if matches!(expr.kind, ExprKind::List(_)) {
                            "list".to_string()
                        } else {
                            "vector".to_string()
                        });
                        pending.extend(items.iter().rev());
                    }
                    atom => values.push(format!("{atom:?}")),
                }
            }
            values
        };
        assert_eq!(atoms(&before.exprs), atoms(&after.exprs));
        let comments = |s: &str| {
            s.lines()
                .filter_map(|line| line.find(';').map(|i| line[i..].trim_end().to_string()))
                .collect::<Vec<_>>()
        };
        assert_eq!(comments(source), comments(&formatted));
    }
}

#[test]
fn exact_character_width_stays_flat() {
    let options = SexpFormatOptions {
        line_width: 6,
        indent: "  ",
    };
    assert_eq!(format_sexp_document("(call)", options).unwrap(), "(call)");
}

#[test]
fn unicode_character_width_stays_flat() {
    let source = "(call :name \"\u{e9}\")";
    let options = SexpFormatOptions {
        line_width: 16,
        indent: "  ",
    };
    assert_eq!(format_sexp_document(source, options).unwrap(), source);
}
