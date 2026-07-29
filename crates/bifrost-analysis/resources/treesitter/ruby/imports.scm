; Ruby "imports" are runtime load calls. The visitor in
; `src/analyzer/ruby/imports.rs` recognizes them by method name; this query
; documents the shape and feeds the analysis epoch.
(call
  method: (identifier) @import.method
  (#match? @import.method "^(require|require_relative|load|autoload)$")) @import.declaration
