# Provisional Go source identity mapping

`ai.brokk.csmi.go-source-symbol` version `0.1` is a local, provisional recipe
for CSMI core symbol descriptors. It is not a normative CSMI publication or a
claim that another implementation recognizes this scheme.

Every mapped symbol is `artifact-local` and carries exactly one exact,
versioned `pkg:golang` selector with one SHA-256 digest. The selector and
ordered descriptors determine the local symbol handle. The exporter reads
type and member identity components directly from native declaration facts:
the artifact locator path and source-symbol field, the native declaration ID,
the native owner relation, member kind, and structured signature. It does not
split or rewrite a rendered qualified name. Missing or non-artifact locators
remain unsupported.

Named type descriptors retain the exact source file and source-symbol value.
The source-file value uses a `meta` descriptor; a module declaration uses a
`namespace` descriptor for its exact locator symbol. Named member descriptors retain the member file, exact owner locator, member
token, member kind, and signature digest. Go functions preserve parameter and
result arity, variadic status, and receiver ownership in the CSMI callable
shape. Parameter and result types remain CSMI `unknown` because this mapping
does not claim resolver proof for their semantic type identities. Fields map
to CSMI value declarations so structured callable-value projections can refer
to the exact member symbol. Pointer receivers retain their method owner and
signature identity, while the CSMI receiver type remains `unknown` because the
core shape cannot distinguish a pointer receiver from a value receiver.
Go type aliases retain the `type-alias` declaration category with an unknown
target when the native structured expression cannot be mapped exactly.

Anonymous function literals use the language-neutral native
`AnonymousCallableIdentity` carrier. The Go source adapter interprets its
opaque package identity as the exact package import path and rebinds its file
and byte ranges, lexical owner anchors, and AST-backed signature against the
selected artifact. Its source type anchors remain provenance; they do not
become invented CSMI type names.

Callable-values facts are emitted as separate alternatives, with every native
fact retained as its own extension fact. Each native coverage record becomes
its own completeness statement scoped to one mapped callable and one family.
The CSMI profile schema validates this transport, while Bifrost's executable
callable-values support remains disabled until an interpreter can prove the
required runtime field and closure state.
