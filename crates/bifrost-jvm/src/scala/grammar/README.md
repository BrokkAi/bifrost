# Scala grammar

Vendored from the MIT-licensed `tree-sitter-scala` 0.26.2 crates.io release
(<https://github.com/tree-sitter/tree-sitter-scala>). The upstream LICENSE is
preserved here. The crates.io archive checksum is
`24e0ab4505990bfe30051761d40a7bf4033ce5a81c9eda9e20e987a5cdc84826`.
This is the same grammar previously used as a crate dependency.

Bifrost issue #3499 adds `alias("export", $.identifier)` as a field-expression
selector. Scala 2 code such as `Export.export(project, file)` must retain its
call and enclosing class rather than recover as a Scala 3 export declaration.
Scala 3 export declarations retain their original rule.

Regenerate from this directory with:

```
npx --yes tree-sitter-cli@0.26.3 generate --abi 15
```

The checked-in parser is built by the JVM crate; users do not need Node or the
generator to build Bifrost. Keep this local correction until an upstream release
contains it, then restore the released grammar dependency.
