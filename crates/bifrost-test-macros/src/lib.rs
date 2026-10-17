use proc_macro::{Delimiter, Group, Ident, Literal, Punct, Spacing, Span, TokenStream, TokenTree};

const ERROR_MESSAGE: &str = "expected one string literal: `#<issue>` or a 12-character commit hash (several joined by `+`), then `: ` and the defect, e.g. #[hardwon(\"#3297: a forward declaration hid the class definition\")]";

/// Marks a test that pins behavior found wrong or missing after its surface
/// was believed done. See the "What tests to write" section in AGENTS.md.
#[proc_macro_attribute]
pub fn hardwon(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut tokens = attr.into_iter();
    if let Some(TokenTree::Literal(literal)) = tokens.next()
        && tokens.next().is_none()
        && is_reference_and_defect(&literal)
    {
        return item;
    }

    let mut error = TokenStream::new();
    error.extend([
        TokenTree::Ident(Ident::new("compile_error", Span::call_site())),
        TokenTree::Punct(Punct::new('!', Spacing::Alone)),
        TokenTree::Group(Group::new(
            Delimiter::Parenthesis,
            TokenStream::from(TokenTree::Literal(Literal::string(ERROR_MESSAGE))),
        )),
        TokenTree::Punct(Punct::new(';', Spacing::Alone)),
    ]);
    error.extend(item);
    error
}

fn is_reference_and_defect(literal: &Literal) -> bool {
    let text = literal.to_string();
    // Strip a raw-string prefix and its hashes; byte and C strings stay rejected.
    let quoted = text.trim_start_matches('r').trim_matches('#');
    let Some(mut rest) = quoted
        .strip_prefix('"')
        .and_then(|quoted| quoted.strip_suffix('"'))
    else {
        return false;
    };
    loop {
        let Some(after) = strip_reference(rest) else {
            return false;
        };
        match after.strip_prefix('+') {
            Some(next) => rest = next,
            None => {
                rest = after;
                break;
            }
        }
    }
    rest.strip_prefix(": ")
        .is_some_and(|defect| !defect.trim().is_empty())
}

/// Strips one leading `#<digits>` issue or 12-character lowercase commit hash.
fn strip_reference(text: &str) -> Option<&str> {
    if let Some(digits) = text.strip_prefix('#') {
        let len = digits.bytes().take_while(u8::is_ascii_digit).count();
        return (len > 0).then(|| &digits[len..]);
    }
    let len = text
        .bytes()
        .take_while(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        .count();
    (len == 12).then(|| &text[len..])
}
