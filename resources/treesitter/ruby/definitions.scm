; Ruby declaration captures.
;
; NOTE: bifrost extracts Ruby symbols with the hand-written visitor in
; `src/analyzer/ruby/declarations.rs`, not by running this query. These
; patterns mirror the upstream tree-sitter-ruby `queries/tags.scm` and exist so
; the file participates in the per-language analysis epoch (see
; `src/analyzer/persistence/epoch.rs`) and documents the node shapes the visitor
; walks.

; Class definitions (plain name or namespaced `A::B`)
(class
  name: [
    (constant) @class.name
    (scope_resolution name: (_) @class.name)
  ]) @class.definition

(singleton_class) @class.definition

; Module definitions
(module
  name: [
    (constant) @class.name
    (scope_resolution name: (_) @class.name)
  ]) @class.definition

; Superclass for inheritance resolution
(class
  superclass: (superclass (_) @type.super)) @type.decl

; Method definitions
(method name: (_) @function.name) @function.definition
(singleton_method name: (_) @function.name) @function.definition

; Constant assignments (fields)
(assignment
  left: (constant) @field.name) @field.definition

; Mixins / attribute macros are plain calls; the visitor matches them by name.
(call method: (identifier) @call.name) @call.expression
