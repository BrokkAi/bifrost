# Reviewed Python standard-library sink and credential models

> Legacy transition copy: product pack authoring belongs in `bifrost-packs`
> or the private premium pack repository. Follow [the placement policy](../../CONTRIBUTING.md#release-process).
> Sources here are frozen pending verified v0.13.0 release and dependency migration.
> The technical notes below describe retained contracts and test tooling.

`security-sinks/bifrost.python-security-sink-summaries.json` publishes
procedure summaries for the standard-library APIs used by the Python
socket-bind, XML-bomb, polynomial-regex, clear-text logging/storage, and
hard-coded-credential policies. Exact callable identity and signatures come
from the bundled `bifrost.python-security-sink-declarations` and
`bifrost.python-stdlib-api-declarations` packs; this pack adds only reviewed
effects that inputs reach an external operation, logging sink, file write, or
credential exchange.

The logging summaries cover `logging.debug`, `info`, `warning`, `error`,
`critical`, `exception`, and `log`, including the matching `logging.Logger`
methods. They mark the fixed message formal as externally visible; the summary
effect remains scoped to that formal. The authored signatures retain the
pinned Typeshed positional `*args` and defaulted keyword-only parameters.
The end-to-end taint fixture remains pinned because its matched source row has
no point-sensitive value observation. Variadic formatting arguments are not
added to the modeled logging effect.

The `builtins.print` summary marks its variadic `*objects` formal as externally
visible. Its optional `sep`, `end`, `file`, and `flush` formals retain their
Typeshed keyword-only binding modes.

The storage summaries cover module-level `json.dump`, `pickle.dump`, and
`marshal.dump`, which write their object/value formal to the supplied output.
The `json.dump` summary models its fixed formals, defaulted keyword-only
options, and keyword-rest formal. The runtime selects this summary uniquely
with exact actual-to-formal mapping `[0, 1]`; the end-to-end taint probe remains
pinned because taint discovery still reports unknown call resolution at that
site. The current call-binding query reports `PartialModel` and unknown formal
coverage for `pickle.dump` and `marshal.dump` even with complete reviewed
declarations; those exact policy tests remain pinned pending a resolver fix.
The pack also declares `io.TextIOWrapper.write` and `pathlib.Path.write_text`
and `write_bytes`. Credential summaries cover `hmac.new`, `smtplib.SMTP.login`,
and `ftplib.FTP.login`. Exact HMAC key-formal identity passes an assertion
fixture, but taint evaluation reports unknown call resolution for its external
call. Bound-instance selectors also fail first on partial stdlib receiver-type
identities; after that model-completeness gap is resolved, constructor-result
dispatch remains subject to #4411.

The socket surface is `socket.socket.bind(address)`. Its policy reports an
address tuple whose first element is the empty host, `0.0.0.0`, or `::`; it
does not report loopback addresses, Unix-domain paths, or unrelated methods
named `bind`. The summary is grounded in CPython 3.13.5's
`Doc/library/socket.rst`.

The regex summaries cover `re.match`, `search`, `fullmatch`, `sub`, `split`,
`findall`, `finditer`, and `compile`, plus `re.Pattern.search` and
`textwrap.shorten`. They transfer the selected input to the returned regex
result or shortened string as reviewed by the polynomial ReDoS tests. The
matching declarations are authored once in
`stdlib-apis/bifrost.python-stdlib-api-declarations.json`.

The XML surface covers `xml.etree.ElementTree.fromstring`,
`xml.sax.parseString`, and `xml.dom.minidom.parseString`. The rule tracks
untrusted text in argument zero. lxml and defusedxml remain outside this pack
because their behavior and package identity require distribution evidence
(#3658). The summaries are grounded in CPython 3.13.5's
`Doc/library/xml.etree.elementtree.rst`, `Doc/library/xml.sax.rst`, and
`Doc/library/xml.dom.minidom.rst`.

The summary pack targets CPython 3.13.5, matching its source provenance. It
contains no XML parser-safety model; safe parser options and third-party parser
distinctions remain explicit policy coverage work.

Compile the authored summary pack with:

```console
cargo run --locked --features release-tooling -p brokk-bifrost-semantic-packs \
  --bin bifrost-semantic-pack -- compile \
  semantic-packs/python/security-sinks/bifrost.python-security-sink-summaries.json \
  /path/to/test-output/python-security-sink-summaries
```

Compile its exact stdlib declaration pack with:

```console
cargo run --locked --features release-tooling -p brokk-bifrost-semantic-packs \
  --bin bifrost-semantic-pack -- compile \
  semantic-packs/python/security-sinks/bifrost.python-security-sink-declarations.json \
  /path/to/test-output/python-security-sink-declarations
```
