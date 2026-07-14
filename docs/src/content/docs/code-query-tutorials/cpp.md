---
title: C and C++
description: Query C and C++ together through the cpp structural adapter and language filter.
---

> Last verified end to end: 2026-07-14 (`query_code` schema version 2).

For exact inbound and outbound symbol edges, proof tiers, and adapter-specific caveats, see [Reference Traversal](../reference-traversal/).

C and C++ files share the `cpp` analyzer, structural adapter, and language-filter label. Use `languages: ["cpp"]` for `.c`, `.cc`, `.cpp`, and the supported C-family header extensions; use `where` when source syntax or directory layout needs a narrower boundary.

## Fixtures

<!-- code-query-fixture:c-family/main.c -->
```c
#include <stdio.h>

void audit(const char *value) {}

int main(void) {
    int retries = 3;
    audit("c");
    return retries;
}
```

<!-- code-query-fixture:c-family/service.cpp -->
```cpp
#include <vector>

class Service {
public:
    Service();
    void run(int value) {}
};

Service::Service() {}

void audit(const char *value) {}

int main() {
    auto retries = 5;
    Service service;
    service.run(retries);
    audit("cpp");
    return 0;
}
```

## One Query Across C And C++

<!-- code-query-case:both-audits:rql -->
```lisp
(where "c-family/**/*" (language cpp (call :callee "audit" :args [(capture "value")])))
```

<!-- code-query-case:both-audits:json -->
```json
{
  "where": ["c-family/**/*"],
  "languages": ["cpp"],
  "match": {
    "kind": "call",
    "callee": {"name": "audit"},
    "args": [{"capture": "value"}]
  }
}
```

<!-- code-query-case:both-audits:expected -->
```json
{
  "results": [
    {"result_type":"structural_match","path":"c-family/main.c","language":"cpp","kind":"call","start_line":7,"end_line":7,"text":"audit(\"c\")","captures":[{"name":"value","text":"\"c\"","start_line":7}],"enclosing_symbol":"main"},
    {"result_type":"structural_match","path":"c-family/service.cpp","language":"cpp","kind":"call","start_line":17,"end_line":17,"text":"audit(\"cpp\")","captures":[{"name":"value","text":"\"cpp\"","start_line":17}],"enclosing_symbol":"main"}
  ],
  "truncated": false
}
```

## Query Initializer Assignments

The same assignment query matches C's explicit type and C++'s `auto`. `left` and `right` target normalized facts instead of parsing declaration text.

<!-- code-query-case:retry-assignments:rql -->
```lisp
(language cpp
  (assignment
    :left (identifier :name "retries")
    :right (numeric_literal :capture "count")))
```

<!-- code-query-case:retry-assignments:json -->
```json
{
  "languages": ["cpp"],
  "match": {
    "kind": "assignment",
    "left": {"kind": "identifier", "name": "retries"},
    "right": {"kind": "numeric_literal", "capture": "count"}
  }
}
```

<!-- code-query-case:retry-assignments:expected -->
```json
{
  "results": [
    {"result_type":"structural_match","path":"c-family/main.c","language":"cpp","kind":"assignment","start_line":6,"end_line":6,"text":"retries = 3","captures":[{"name":"count","text":"3","start_line":6}],"enclosing_symbol":"main"},
    {"result_type":"structural_match","path":"c-family/service.cpp","language":"cpp","kind":"assignment","start_line":14,"end_line":14,"text":"retries = 5","captures":[{"name":"count","text":"5","start_line":14}],"enclosing_symbol":"main"}
  ],
  "truncated": false
}
```

## Isolate C++ Member Syntax

The path glob excludes the C fixture. Receiver, callee, and argument roles identify the member call without relying on `.` punctuation.

<!-- code-query-case:service-run:rql -->
```lisp
(where "c-family/**/*.cpp"
  (language cpp
    (call :callee "run" :receiver "service" :args [(capture "retries")])))
```

<!-- code-query-case:service-run:json -->
```json
{
  "where": ["c-family/**/*.cpp"],
  "languages": ["cpp"],
  "match": {
    "kind": "call",
    "callee": {"name": "run"},
    "receiver": {"name": "service"},
    "args": [{"capture": "retries"}]
  }
}
```

<!-- code-query-case:service-run:expected -->
```json
{
  "results": [
    {"result_type":"structural_match","path":"c-family/service.cpp","language":"cpp","kind":"call","start_line":16,"end_line":16,"text":"service.run(retries)","captures":[{"name":"retries","text":"retries","start_line":16}],"enclosing_symbol":"main"}
  ],
  "truncated": false
}
```

## Out-Of-Line Constructor And Include

<!-- code-query-case:constructor:rql -->
```lisp
(language cpp (constructor :name "Service"))
```

<!-- code-query-case:constructor:json -->
```json
{"languages":["cpp"],"match":{"kind":"constructor","name":"Service"}}
```

<!-- code-query-case:constructor:expected -->
```json
{
  "results": [
    {"result_type":"structural_match","path":"c-family/service.cpp","language":"cpp","kind":"constructor","start_line":9,"end_line":9,"text":"Service::Service() {}","enclosing_symbol":"Service.Service"}
  ],
  "truncated": false
}
```

<!-- code-query-case:vector-include:rql -->
```lisp
(language cpp (import :module "vector"))
```

<!-- code-query-case:vector-include:json -->
```json
{"languages":["cpp"],"match":{"kind":"import","module":{"name":"vector"}}}
```

<!-- code-query-case:vector-include:expected -->
```json
{
  "results": [
    {"result_type":"structural_match","path":"c-family/service.cpp","language":"cpp","kind":"import","start_line":1,"end_line":2,"text":"#include <vector>…"}
  ],
  "truncated": false
}
```

## Precision Boundary

C naturally produces only the subset of normalized facts its syntax supports. Neither C nor C++ models `kwargs` or decorators, and version 2 does not resolve the static type of `service`.

## Traverse Indexed Types And Members

<!-- code-query-fixture:cpp/hierarchy.cpp -->
```cpp
class QueryRoot {
public:
    virtual void root_member() {}
};

class QueryLeaf : public QueryRoot {
public:
    void leaf_member() {}
};
```

<!-- code-query-case:hierarchy-supertypes:rql -->
```lisp
(supertypes :depth 2 (enclosing-decl (language cpp (class :name "QueryLeaf"))))
```

<!-- code-query-case:hierarchy-supertypes:json -->
```json
{"languages":["cpp"],"match":{"kind":"class","name":"QueryLeaf"},"steps":[{"op":"enclosing_decl"},{"op":"supertypes","depth":2}]}
```

<!-- code-query-case:hierarchy-supertypes:expected -->
```json
{
  "results": [
    {
      "end_line": 4,
      "fq_name": "QueryRoot",
      "kind": "class",
      "language": "cpp",
      "path": "cpp/hierarchy.cpp",
      "provenance": [
        {
          "seed": {
            "end_line": 9,
            "kind": "class",
            "path": "cpp/hierarchy.cpp",
            "result_type": "structural_match",
            "start_line": 6
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 9,
                "fq_name": "QueryLeaf",
                "kind": "class",
                "path": "cpp/hierarchy.cpp",
                "result_type": "declaration",
                "start_line": 6
              }
            },
            {
              "op": "supertypes",
              "result": {
                "end_line": 4,
                "fq_name": "QueryRoot",
                "kind": "class",
                "path": "cpp/hierarchy.cpp",
                "result_type": "declaration",
                "start_line": 1
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "class QueryRoot {",
      "start_line": 1
    }
  ],
  "truncated": false
}
```

<!-- code-query-case:hierarchy-subtype-members-owner:rql -->
```lisp
(owner (members (subtypes (enclosing-decl (language cpp (class :name "QueryRoot"))))))
```

<!-- code-query-case:hierarchy-subtype-members-owner:json -->
```json
{"languages":["cpp"],"match":{"kind":"class","name":"QueryRoot"},"steps":[{"op":"enclosing_decl"},{"op":"subtypes"},{"op":"members"},{"op":"owner"}]}
```

<!-- code-query-case:hierarchy-subtype-members-owner:expected -->
```json
{
  "results": [
    {
      "end_line": 9,
      "fq_name": "QueryLeaf",
      "kind": "class",
      "language": "cpp",
      "path": "cpp/hierarchy.cpp",
      "provenance": [
        {
          "seed": {
            "end_line": 4,
            "kind": "class",
            "path": "cpp/hierarchy.cpp",
            "result_type": "structural_match",
            "start_line": 1
          },
          "steps": [
            {
              "op": "enclosing_decl",
              "result": {
                "end_line": 4,
                "fq_name": "QueryRoot",
                "kind": "class",
                "path": "cpp/hierarchy.cpp",
                "result_type": "declaration",
                "start_line": 1
              }
            },
            {
              "op": "subtypes",
              "result": {
                "end_line": 9,
                "fq_name": "QueryLeaf",
                "kind": "class",
                "path": "cpp/hierarchy.cpp",
                "result_type": "declaration",
                "start_line": 6
              }
            },
            {
              "op": "members",
              "result": {
                "end_line": 8,
                "fq_name": "QueryLeaf.leaf_member",
                "kind": "function",
                "path": "cpp/hierarchy.cpp",
                "result_type": "declaration",
                "start_line": 8
              }
            },
            {
              "op": "owner",
              "result": {
                "end_line": 9,
                "fq_name": "QueryLeaf",
                "kind": "class",
                "path": "cpp/hierarchy.cpp",
                "result_type": "declaration",
                "start_line": 6
              }
            }
          ]
        }
      ],
      "result_type": "declaration",
      "signature": "class QueryLeaf : public QueryRoot {",
      "start_line": 6
    }
  ],
  "truncated": false
}
```
