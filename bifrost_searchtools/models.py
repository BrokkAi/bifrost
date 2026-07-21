from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import ClassVar


def _render_numbered_block(text: str, start_line: int) -> str:
    return "\n".join(
        f"{start_line + index}: {line}" for index, line in enumerate(text.splitlines())
    )


def _render_block(text: str, start_line: int, render_line_numbers: bool) -> str:
    if not render_line_numbers:
        return text
    return _render_numbered_block(text, start_line)


@dataclass(frozen=True)
class SearchSymbolHit:
    symbol: str
    signature: str
    line: int
    render_line_numbers: bool = True

    @classmethod
    def from_dict(cls, data: dict, render_line_numbers: bool = True) -> SearchSymbolHit:
        return cls(
            symbol=data["symbol"],
            signature=data["signature"],
            line=int(data["line"]),
            render_line_numbers=render_line_numbers,
        )

    def render_text(self) -> str:
        if self.render_line_numbers and self.line > 0:
            return f"{self.line}: {self.signature}"
        return self.signature


@dataclass(frozen=True)
class SearchSymbolsFile:
    path: str
    loc: int
    classes: list[SearchSymbolHit]
    functions: list[SearchSymbolHit]
    fields: list[SearchSymbolHit]
    modules: list[SearchSymbolHit]
    render_line_numbers: bool = True

    @classmethod
    def from_dict(
        cls, data: dict, render_line_numbers: bool = True
    ) -> SearchSymbolsFile:
        return cls(
            path=data["path"],
            loc=data["loc"],
            classes=[
                SearchSymbolHit.from_dict(item, render_line_numbers)
                for item in data["classes"]
            ],
            functions=[
                SearchSymbolHit.from_dict(item, render_line_numbers)
                for item in data["functions"]
            ],
            fields=[
                SearchSymbolHit.from_dict(item, render_line_numbers)
                for item in data["fields"]
            ],
            modules=[
                SearchSymbolHit.from_dict(item, render_line_numbers)
                for item in data["modules"]
            ],
            render_line_numbers=render_line_numbers,
        )

    def render_text(self) -> str:
        lines = [f"{self.path} ({self.loc} lines)"]
        if self.classes:
            lines.extend(
                [
                    "  classes:",
                    *[f"    {hit.render_text()}" for hit in self.classes],
                ]
            )
        if self.functions:
            lines.extend(
                [
                    "  functions:",
                    *[f"    {hit.render_text()}" for hit in self.functions],
                ]
            )
        if self.fields:
            lines.extend(
                [
                    "  fields:",
                    *[f"    {hit.render_text()}" for hit in self.fields],
                ]
            )
        if self.modules:
            lines.extend(
                [
                    "  modules:",
                    *[f"    {hit.render_text()}" for hit in self.modules],
                ]
            )
        return "\n".join(lines)


@dataclass(frozen=True)
class SearchSymbolsResult:
    patterns: list[str]
    truncated: bool
    total_files: int
    files: list[SearchSymbolsFile]
    render_line_numbers: bool = True
    rendered_text: str | None = None

    @classmethod
    def from_dict(
        cls, data: dict, render_line_numbers: bool = True, rendered_text: str | None = None
    ) -> SearchSymbolsResult:
        return cls(
            patterns=list(data["patterns"]),
            truncated=bool(data["truncated"]),
            total_files=int(data.get("total_files", len(data["files"]))),
            files=[
                SearchSymbolsFile.from_dict(item, render_line_numbers)
                for item in data["files"]
            ],
            render_line_numbers=render_line_numbers,
            rendered_text=rendered_text,
        )

    @property
    def count(self) -> int:
        return len(self.files)

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        blocks = [file.render_text() for file in self.files]
        if not blocks:
            return "No matching symbols found."
        text = "\n\n".join(blocks)
        if self.truncated:
            text += (
                f"\n\nResults truncated: showing {len(self.files)} of {self.total_files} "
                "files selected by recent activity when available. Results are displayed alphabetically."
            )
        return text


@dataclass(frozen=True)
class CodeQueryRange:
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryRange:
        return cls(
            start_line=int(data["start_line"]),
            start_column=int(data["start_column"]),
            end_line=int(data["end_line"]),
            end_column=int(data["end_column"]),
        )


@dataclass(frozen=True)
class CodeQueryCapture:
    name: str
    text: str
    start_line: int
    range: CodeQueryRange | None = None
    kind: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryCapture:
        return cls(
            name=data["name"],
            text=data["text"],
            start_line=int(data["start_line"]),
            range=CodeQueryRange.from_dict(data["range"]) if "range" in data else None,
            kind=data.get("kind"),
        )

    def render_text(self) -> str:
        return f"${self.name} = `{self.text}` (line {self.start_line})"


@dataclass(frozen=True)
class CodeQueryResultRef:
    result_type: str
    path: str
    kind: str | None = None
    fq_name: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    id: str | None = None
    node_range: CodeQueryRange | None = None
    range: CodeQueryRange | None = None
    target_fq_name: str | None = None
    target_id: str | None = None
    proof: str | None = None
    reference_kind: str | None = None
    caller_fq_name: str | None = None
    callee_fq_name: str | None = None
    input_kind: str | None = None
    parameter_index: int | None = None
    parameter_name: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryResultRef:
        return cls(
            result_type=data["result_type"],
            path=data["path"],
            kind=data.get("kind"),
            fq_name=data.get("fq_name"),
            start_line=int(data["start_line"]) if "start_line" in data else None,
            end_line=int(data["end_line"]) if "end_line" in data else None,
            id=data.get("id"),
            node_range=CodeQueryRange.from_dict(data["node_range"])
            if "node_range" in data
            else None,
            range=CodeQueryRange.from_dict(data["range"])
            if "range" in data
            else None,
            target_fq_name=data.get("target_fq_name"),
            target_id=data.get("target_id"),
            proof=data.get("proof"),
            reference_kind=data.get("reference_kind"),
            caller_fq_name=data.get("caller_fq_name"),
            callee_fq_name=data.get("callee_fq_name"),
            input_kind=data.get("input_kind"),
            parameter_index=int(data["parameter_index"])
            if "parameter_index" in data
            else None,
            parameter_name=data.get("parameter_name"),
        )


@dataclass(frozen=True)
class CodeQueryProvenanceStep:
    op: str
    result: CodeQueryResultRef
    via: CodeQueryResultRef | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryProvenanceStep:
        return cls(
            op=data["op"],
            result=CodeQueryResultRef.from_dict(data["result"]),
            via=CodeQueryResultRef.from_dict(data["via"]) if "via" in data else None,
        )


@dataclass(frozen=True)
class CodeQueryProvenance:
    seed: CodeQueryResultRef
    steps: list[CodeQueryProvenanceStep]
    branch: list[int] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryProvenance:
        return cls(
            seed=CodeQueryResultRef.from_dict(data["seed"]),
            steps=[
                CodeQueryProvenanceStep.from_dict(item)
                for item in data.get("steps", [])
            ],
            branch=[int(index) for index in data.get("branch", [])],
        )


def _query_provenance(data: dict) -> list[CodeQueryProvenance]:
    return [CodeQueryProvenance.from_dict(item) for item in data.get("provenance", [])]


@dataclass(frozen=True)
class CodeQueryMatch:
    path: str
    language: str
    kind: str
    start_line: int
    end_line: int
    text: str
    captures: list[CodeQueryCapture]
    id: str | None = None
    node_range: CodeQueryRange | None = None
    decorated_range: CodeQueryRange | None = None
    decorator_ranges: list[CodeQueryRange] = field(default_factory=list)
    enclosing_symbol: str | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryMatch:
        return cls(
            path=data["path"],
            language=data["language"],
            kind=data["kind"],
            start_line=int(data["start_line"]),
            end_line=int(data["end_line"]),
            text=data["text"],
            captures=[
                CodeQueryCapture.from_dict(item) for item in data.get("captures", [])
            ],
            id=data.get("id"),
            node_range=CodeQueryRange.from_dict(data["node_range"])
            if "node_range" in data
            else None,
            decorated_range=CodeQueryRange.from_dict(data["decorated_range"])
            if "decorated_range" in data
            else None,
            decorator_ranges=[
                CodeQueryRange.from_dict(item)
                for item in data.get("decorator_ranges", [])
            ],
            enclosing_symbol=data.get("enclosing_symbol"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        if self.start_line == self.end_line:
            lines = str(self.start_line)
        else:
            lines = f"{self.start_line}-{self.end_line}"
        rendered = f"{self.path}:{lines} [{self.kind}] `{self.text}`"
        if self.enclosing_symbol is not None:
            rendered += f" in {self.enclosing_symbol}"
        if self.captures:
            rendered += "\n" + "\n".join(
                f"  {capture.render_text()}" for capture in self.captures
            )
        return rendered


@dataclass(frozen=True)
class CodeQueryDeclaration:
    path: str
    language: str
    kind: str
    fq_name: str
    start_line: int
    end_line: int
    signature: str | None = None
    id: str | None = None
    node_range: CodeQueryRange | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryDeclaration:
        return cls(
            path=data["path"],
            language=data["language"],
            kind=data["kind"],
            fq_name=data["fq_name"],
            start_line=int(data["start_line"]),
            end_line=int(data["end_line"]),
            signature=data.get("signature"),
            id=data.get("id"),
            node_range=CodeQueryRange.from_dict(data["node_range"])
            if "node_range" in data
            else None,
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        lines = (
            str(self.start_line)
            if self.start_line == self.end_line
            else f"{self.start_line}-{self.end_line}"
        )
        rendered = f"{self.path}:{lines} [{self.kind}] {self.fq_name}"
        if self.signature is not None:
            rendered += f" `{self.signature}`"
        return rendered


@dataclass(frozen=True)
class CodeQueryFile:
    path: str
    language: str
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryFile:
        return cls(
            path=data["path"],
            language=data["language"],
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        return f"{self.path} [file; {self.language}]"


@dataclass(frozen=True)
class CodeQueryReferenceSite:
    path: str
    language: str
    range: CodeQueryRange
    target: CodeQueryDeclaration
    enclosing_declaration: CodeQueryDeclaration | None
    usage_kind: str
    proof: str
    reference_kind: str | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryReferenceSite:
        return cls(
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            target=CodeQueryDeclaration.from_dict(data["target"]),
            enclosing_declaration=CodeQueryDeclaration.from_dict(
                data["enclosing_declaration"]
            )
            if "enclosing_declaration" in data
            else None,
            usage_kind=data["usage_kind"],
            proof=data["proof"],
            reference_kind=data.get("reference_kind"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        return (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[reference; {self.usage_kind}; {self.proof}] -> {self.target.fq_name}"
        )


@dataclass(frozen=True)
class CodeQueryCallArgument:
    range: CodeQueryRange
    name: str | None = None
    position: int | None = None
    formal_index: int | None = None
    formal_name: str | None = None
    variadic: bool = False
    spread: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryCallArgument:
        return cls(
            range=CodeQueryRange.from_dict(data["range"]),
            name=data.get("name"),
            position=int(data["position"]) if "position" in data else None,
            formal_index=int(data["formal_index"])
            if "formal_index" in data
            else None,
            formal_name=data.get("formal_name"),
            variadic=bool(data.get("variadic", False)),
            spread=bool(data.get("spread", False)),
        )


@dataclass(frozen=True)
class CodeQueryCallSite:
    path: str
    language: str
    range: CodeQueryRange
    callee_range: CodeQueryRange
    caller: CodeQueryDeclaration
    callee: CodeQueryDeclaration
    call_kind: str
    proof: str
    receiver: CodeQueryRange | None = None
    arguments: list[CodeQueryCallArgument] = field(default_factory=list)
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryCallSite:
        return cls(
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            callee_range=CodeQueryRange.from_dict(data["callee_range"]),
            caller=CodeQueryDeclaration.from_dict(data["caller"]),
            callee=CodeQueryDeclaration.from_dict(data["callee"]),
            call_kind=data["call_kind"],
            proof=data["proof"],
            receiver=CodeQueryRange.from_dict(data["receiver"])
            if "receiver" in data
            else None,
            arguments=[
                CodeQueryCallArgument.from_dict(item)
                for item in data.get("arguments", [])
            ],
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        return (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[call; {self.call_kind}; {self.proof}] "
            f"{self.caller.fq_name} -> {self.callee.fq_name}"
        )


@dataclass(frozen=True)
class CodeQueryExpressionSite:
    path: str
    language: str
    range: CodeQueryRange
    text: str
    input_kind: str
    caller_fq_name: str
    callee_fq_name: str
    call_range: CodeQueryRange
    parameter_index: int | None = None
    parameter_name: str | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryExpressionSite:
        return cls(
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            text=data["text"],
            input_kind=data["input_kind"],
            caller_fq_name=data["caller_fq_name"],
            callee_fq_name=data["callee_fq_name"],
            call_range=CodeQueryRange.from_dict(data["call_range"]),
            parameter_index=int(data["parameter_index"])
            if "parameter_index" in data
            else None,
            parameter_name=data.get("parameter_name"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        return (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[call input; {self.input_kind}] `{self.text}` -> {self.callee_fq_name}"
        )


CodeQueryResultItem = (
    CodeQueryMatch
    | CodeQueryDeclaration
    | CodeQueryFile
    | CodeQueryReferenceSite
    | CodeQueryCallSite
    | CodeQueryExpressionSite
)


def _code_query_result_item(data: dict) -> CodeQueryResultItem:
    result_type = data.get("result_type")
    if result_type == "structural_match":
        return CodeQueryMatch.from_dict(data)
    if result_type == "declaration":
        return CodeQueryDeclaration.from_dict(data)
    if result_type == "file":
        return CodeQueryFile.from_dict(data)
    if result_type == "reference_site":
        return CodeQueryReferenceSite.from_dict(data)
    if result_type == "call_site":
        return CodeQueryCallSite.from_dict(data)
    if result_type == "expression_site":
        return CodeQueryExpressionSite.from_dict(data)
    raise ValueError(f"unknown code query result_type: {result_type!r}")


class CodeQueryDiagnosticCode(StrEnum):
    INVALID_PLAN = "invalid_plan"
    CANCELLED = "cancelled"
    UNSUPPORTED_STRUCTURAL_FEATURE = "unsupported_structural_feature"
    MISSING_STRUCTURAL_ADAPTER = "missing_structural_adapter"
    UNSUPPORTED_IMPORT_ANALYSIS = "unsupported_import_analysis"
    SEMANTIC_RESULTS_OMITTED = "semantic_results_omitted"
    RECEIVER_ANALYSIS_PARTIAL = "receiver_analysis_partial"
    CALL_RELATION_BUDGET_EXHAUSTED = "call_relation_budget_exhausted"
    CALL_RELATION_PARSE_FAILED = "call_relation_parse_failed"
    CALL_RELATION_CANDIDATES_OMITTED = "call_relation_candidates_omitted"
    CALL_RELATION_TARGETS_AMBIGUOUS = "call_relation_targets_ambiguous"
    CALL_RELATION_CANDIDATE_LIMIT = "call_relation_candidate_limit"
    CALL_RELATION_ANALYSIS_FAILED = "call_relation_analysis_failed"
    REFERENCE_SOURCE_BYTES_TRUNCATED = "reference_source_bytes_truncated"
    REFERENCE_CANDIDATE_FILES_TRUNCATED = "reference_candidate_files_truncated"
    REFERENCE_CANDIDATES_OMITTED = "reference_candidates_omitted"
    REFERENCE_TARGETS_AMBIGUOUS = "reference_targets_ambiguous"
    REFERENCE_CALLSITE_LIMIT = "reference_callsite_limit"
    REFERENCE_ANALYSIS_FAILED = "reference_analysis_failed"
    USES_PARSER_UNSUPPORTED = "uses_parser_unsupported"
    USES_CANDIDATE_LIMIT = "uses_candidate_limit"
    USES_TARGETS_AMBIGUOUS = "uses_targets_ambiguous"
    USES_CANDIDATES_OMITTED = "uses_candidates_omitted"
    EXECUTION_BUDGET_EXHAUSTED = "execution_budget_exhausted"
    PIPELINE_BUDGET_EXHAUSTED = "pipeline_budget_exhausted"
    IMPORT_GRAPH_BUDGET_EXHAUSTED = "import_graph_budget_exhausted"
    RESULT_LIMIT_REACHED = "result_limit_reached"
    BROAD_QUERY = "broad_query"


class CodeQueryDiagnosticImpact(StrEnum):
    ADVISORY = "advisory"
    INCOMPLETE = "incomplete"
    INVALID = "invalid"


class CodeQueryCompletionKind(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    CANCELLED = "cancelled"
    INVALID = "invalid"


@dataclass(frozen=True)
class CodeQueryCompletion:
    kind: CodeQueryCompletionKind
    codes: tuple[CodeQueryDiagnosticCode, ...] = ()


@dataclass(frozen=True)
class CodeQueryDiagnostic:
    code: CodeQueryDiagnosticCode
    impact: CodeQueryDiagnosticImpact
    language: str
    message: str
    branch: list[int] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryDiagnostic:
        return cls(
            code=CodeQueryDiagnosticCode(data["code"]),
            impact=CodeQueryDiagnosticImpact(data["impact"]),
            language=data["language"],
            message=data["message"],
            branch=[int(index) for index in data.get("branch", [])],
        )

    def render_text(self) -> str:
        branch = f" [branch {'.'.join(map(str, self.branch))}]" if self.branch else ""
        return f"{self.impact.value} [{self.code.value}]{branch}: {self.message}"


@dataclass(frozen=True)
class CodeQueryResult:
    results: list[CodeQueryResultItem]
    truncated: bool
    diagnostics: list[CodeQueryDiagnostic] = field(default_factory=list)
    rendered_text: str | None = None

    @classmethod
    def from_dict(cls, data: dict, rendered_text: str | None = None) -> CodeQueryResult:
        return cls(
            results=[
                _code_query_result_item(item) for item in data.get("results", [])
            ],
            truncated=bool(data["truncated"]),
            diagnostics=[
                CodeQueryDiagnostic.from_dict(item)
                for item in data.get("diagnostics", [])
            ],
            rendered_text=rendered_text,
        )

    @property
    def count(self) -> int:
        return len(self.results)

    @property
    def completion(self) -> CodeQueryCompletion:
        invalid = self._codes_with_impact(CodeQueryDiagnosticImpact.INVALID)
        if invalid:
            return CodeQueryCompletion(CodeQueryCompletionKind.INVALID, invalid)
        if any(
            diagnostic.code is CodeQueryDiagnosticCode.CANCELLED
            for diagnostic in self.diagnostics
        ):
            return CodeQueryCompletion(CodeQueryCompletionKind.CANCELLED)
        incomplete = self._codes_with_impact(CodeQueryDiagnosticImpact.INCOMPLETE)
        if self.truncated or incomplete:
            return CodeQueryCompletion(CodeQueryCompletionKind.INCOMPLETE, incomplete)
        return CodeQueryCompletion(CodeQueryCompletionKind.COMPLETE)

    def _codes_with_impact(
        self, impact: CodeQueryDiagnosticImpact
    ) -> tuple[CodeQueryDiagnosticCode, ...]:
        codes: list[CodeQueryDiagnosticCode] = []
        for diagnostic in self.diagnostics:
            if diagnostic.impact is impact and diagnostic.code not in codes:
                codes.append(diagnostic.code)
        return tuple(codes)

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        if self.results:
            suffix = " (truncated; refine the query or raise limit)" if self.truncated else ""
            lines = [
                f"{len(self.results)} result{'s' if len(self.results) != 1 else ''}{suffix}",
                "",
            ]
            lines.extend(result.render_text() for result in self.results)
        else:
            lines = ["No query results."]
        lines.extend(diagnostic.render_text() for diagnostic in self.diagnostics)
        return "\n".join(lines).strip()


@dataclass(frozen=True)
class SymbolLocation:
    symbol: str
    path: str
    loc: int
    start_line: int
    end_line: int
    render_line_numbers: bool = True

    @classmethod
    def from_dict(cls, data: dict, render_line_numbers: bool = True) -> SymbolLocation:
        return cls(
            symbol=data["symbol"],
            path=data["path"],
            loc=data["loc"],
            start_line=data["start_line"],
            end_line=data["end_line"],
            render_line_numbers=render_line_numbers,
        )

    def render_text(self) -> str:
        if self.render_line_numbers:
            return f"{self.symbol}: {self.path}:{self.start_line}..{self.end_line}"
        return f"{self.symbol}: {self.path}"


@dataclass(frozen=True)
class SymbolLocationsResult:
    locations: list[SymbolLocation]
    not_found: list[str]
    render_line_numbers: bool = True
    rendered_text: str | None = None

    @classmethod
    def from_dict(
        cls, data: dict, render_line_numbers: bool = True, rendered_text: str | None = None
    ) -> SymbolLocationsResult:
        return cls(
            locations=[
                SymbolLocation.from_dict(item, render_line_numbers)
                for item in data["locations"]
            ],
            not_found=list(data["not_found"]),
            render_line_numbers=render_line_numbers,
            rendered_text=rendered_text,
        )

    @property
    def count(self) -> int:
        return len(self.locations)

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        lines = [location.render_text() for location in self.locations]
        if self.not_found:
            lines.append(f"Not found: {', '.join(self.not_found)}")
        return "\n".join(lines) if lines else "No matching symbols found."


@dataclass(frozen=True)
class SymbolAncestors:
    symbol: str
    ancestors: list[str]

    @classmethod
    def from_dict(cls, data: dict) -> SymbolAncestors:
        return cls(
            symbol=data["symbol"],
            ancestors=list(data["ancestors"]),
        )

    def render_text(self) -> str:
        if not self.ancestors:
            return f"{self.symbol}: <none>"
        return "\n".join([self.symbol, *[f"  - {ancestor}" for ancestor in self.ancestors]])


@dataclass(frozen=True)
class SymbolAncestorsResult:
    ancestors: list[SymbolAncestors]
    not_found: list[str]
    ambiguous: list[AmbiguousSymbol]
    rendered_text: str | None = None

    @classmethod
    def from_dict(
        cls, data: dict, rendered_text: str | None = None
    ) -> SymbolAncestorsResult:
        return cls(
            ancestors=[SymbolAncestors.from_dict(item) for item in data["ancestors"]],
            not_found=list(data["not_found"]),
            ambiguous=[AmbiguousSymbol.from_dict(item) for item in data.get("ambiguous", [])],
            rendered_text=rendered_text,
        )

    @property
    def count(self) -> int:
        return len(self.ancestors)

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        blocks = [item.render_text() for item in self.ancestors]
        if self.not_found:
            blocks.append(f"Not found: {', '.join(self.not_found)}")
        if self.ambiguous:
            blocks.extend(item.render_text() for item in self.ambiguous)
        return "\n\n".join(blocks) if blocks else "No matching ancestors found."


@dataclass(frozen=True)
class AmbiguousSymbol:
    target: str
    matches: list[str]

    @classmethod
    def from_dict(cls, data: dict) -> AmbiguousSymbol:
        return cls(target=data["target"], matches=list(data["matches"]))

    def render_text(self) -> str:
        return f"Ambiguous {self.target}: {', '.join(self.matches)}"


@dataclass(frozen=True)
class DefinitionDiagnostic:
    kind: str
    message: str

    @classmethod
    def from_dict(cls, data: dict) -> DefinitionDiagnostic:
        return cls(kind=data["kind"], message=data["message"])

    def render_text(self) -> str:
        return f"{self.kind}: {self.message}"


class NavigationOperation(StrEnum):
    DECLARATION = "declaration"
    DEFINITION = "definition"


@dataclass(frozen=True)
class DefinitionCandidate:
    name: str
    fqn: str | None
    path: str
    start_line: int
    start_column: int | None
    end_line: int
    end_column: int | None
    kind: str
    signature: str | None
    language: str

    @classmethod
    def from_dict(cls, data: dict) -> DefinitionCandidate:
        return cls(
            name=data["name"],
            fqn=data.get("fqn"),
            path=data["path"],
            start_line=int(data["start_line"]),
            start_column=(
                int(data["start_column"])
                if data.get("start_column") is not None
                else None
            ),
            end_line=int(data["end_line"]),
            end_column=(
                int(data["end_column"])
                if data.get("end_column") is not None
                else None
            ),
            kind=data["kind"],
            signature=data.get("signature"),
            language=data["language"],
        )

    def render_text(self) -> str:
        if self.start_column is not None and self.end_column is not None:
            location = (
                f"{self.path}:{self.start_line}:{self.start_column}-"
                f"{self.end_line}:{self.end_column}"
            )
        else:
            location = f"{self.path}:{self.start_line}..{self.end_line}"
        signature = f" {self.signature}" if self.signature else ""
        return (
            f"{self.fqn or self.name} ({self.kind}, {self.language}) "
            f"at {location}{signature}"
        )


@dataclass(frozen=True)
class DefinitionReferenceSite:
    path: str
    target: str

    @classmethod
    def from_dict(cls, data: dict) -> DefinitionReferenceSite:
        return cls(path=data["path"], target=data["target"])


@dataclass(frozen=True)
class DefinitionLookupResult:
    query: dict
    operation: NavigationOperation
    status: str
    reference: DefinitionReferenceSite | None
    definitions: list[DefinitionCandidate]
    diagnostics: list[DefinitionDiagnostic]

    @classmethod
    def from_dict(cls, data: dict) -> DefinitionLookupResult:
        return cls(
            query=dict(data["query"]),
            operation=NavigationOperation(data["operation"]),
            status=data["status"],
            reference=(
                DefinitionReferenceSite.from_dict(data["reference"])
                if data.get("reference") is not None
                else None
            ),
            definitions=[
                DefinitionCandidate.from_dict(item)
                for item in data.get("definitions", [])
            ],
            diagnostics=[
                DefinitionDiagnostic.from_dict(item)
                for item in data.get("diagnostics", [])
            ],
        )

    def render_text(self) -> str:
        lines = [f"operation: {self.operation.value}", f"status: {self.status}"]
        if self.reference is not None:
            lines.append(f"reference: {self.reference.path} -> {self.reference.target}")
        lines.extend(definition.render_text() for definition in self.definitions)
        lines.extend(diagnostic.render_text() for diagnostic in self.diagnostics)
        return "\n".join(lines)


@dataclass(frozen=True)
class DeclarationLookupResult:
    query: dict
    operation: NavigationOperation
    status: str
    reference: DefinitionReferenceSite | None
    declarations: list[DefinitionCandidate]
    diagnostics: list[DefinitionDiagnostic]

    @classmethod
    def from_dict(cls, data: dict) -> DeclarationLookupResult:
        return cls(
            query=dict(data["query"]),
            operation=NavigationOperation(data["operation"]),
            status=data["status"],
            reference=(
                DefinitionReferenceSite.from_dict(data["reference"])
                if data.get("reference") is not None
                else None
            ),
            declarations=[
                DefinitionCandidate.from_dict(item)
                for item in data.get("declarations", [])
            ],
            diagnostics=[
                DefinitionDiagnostic.from_dict(item)
                for item in data.get("diagnostics", [])
            ],
        )

    def render_text(self) -> str:
        lines = [f"operation: {self.operation.value}", f"status: {self.status}"]
        if self.reference is not None:
            lines.append(f"reference: {self.reference.path} -> {self.reference.target}")
        lines.extend(declaration.render_text() for declaration in self.declarations)
        lines.extend(diagnostic.render_text() for diagnostic in self.diagnostics)
        return "\n".join(lines)


@dataclass(frozen=True)
class TypeLookupCandidate:
    fqn: str
    kind: str | None
    language: str | None
    definitions: list[DefinitionCandidate]

    @classmethod
    def from_dict(cls, data: dict) -> TypeLookupCandidate:
        return cls(
            fqn=data["fqn"],
            kind=data.get("kind"),
            language=data.get("language"),
            definitions=[
                DefinitionCandidate.from_dict(item)
                for item in data.get("definitions", [])
            ],
        )

    def render_text(self) -> str:
        details = ", ".join(
            part for part in [self.kind, self.language] if part is not None
        )
        suffix = f" ({details})" if details else ""
        lines = [f"{self.fqn}{suffix}"]
        lines.extend(definition.render_text() for definition in self.definitions)
        return "\n".join(lines)


@dataclass(frozen=True)
class TypeLookupResult:
    query: dict
    status: str
    reference: DefinitionReferenceSite | None
    types: list[TypeLookupCandidate]
    diagnostics: list[DefinitionDiagnostic]

    @classmethod
    def from_dict(cls, data: dict) -> TypeLookupResult:
        return cls(
            query=dict(data["query"]),
            status=data["status"],
            reference=(
                DefinitionReferenceSite.from_dict(data["reference"])
                if data.get("reference") is not None
                else None
            ),
            types=[
                TypeLookupCandidate.from_dict(item) for item in data.get("types", [])
            ],
            diagnostics=[
                DefinitionDiagnostic.from_dict(item)
                for item in data.get("diagnostics", [])
            ],
        )

    def render_text(self) -> str:
        lines = [f"status: {self.status}"]
        if self.reference is not None:
            lines.append(f"reference: {self.reference.path} -> {self.reference.target}")
        lines.extend(item.render_text() for item in self.types)
        lines.extend(diagnostic.render_text() for diagnostic in self.diagnostics)
        return "\n".join(lines)


@dataclass(frozen=True)
class RenameSymbolTarget:
    symbol: str
    kind: str
    path: str

    @classmethod
    def from_dict(cls, data: dict) -> RenameSymbolTarget:
        return cls(symbol=data["symbol"], kind=data["kind"], path=data["path"])

    def render_text(self) -> str:
        return f"{self.symbol} ({self.kind}) at {self.path}"


@dataclass(frozen=True)
class RenameTextEdit:
    old_text: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    new_text: str

    @classmethod
    def from_dict(cls, data: dict) -> RenameTextEdit:
        return cls(
            old_text=data["old_text"],
            start_line=int(data["start_line"]),
            start_column=int(data["start_column"]),
            end_line=int(data["end_line"]),
            end_column=int(data["end_column"]),
            new_text=data["new_text"],
        )

    def render_text(self) -> str:
        return (
            f"{self.start_line}:{self.start_column}-{self.end_line}:{self.end_column} "
            f"{self.old_text} -> {self.new_text}"
        )


@dataclass(frozen=True)
class RenameFileEdits:
    path: str
    edits: list[RenameTextEdit]

    @classmethod
    def from_dict(cls, data: dict) -> RenameFileEdits:
        return cls(
            path=data["path"],
            edits=[RenameTextEdit.from_dict(item) for item in data.get("edits", [])],
        )

    def render_text(self) -> str:
        lines = [self.path]
        lines.extend(f"  {edit.render_text()}" for edit in self.edits)
        return "\n".join(lines)


@dataclass(frozen=True)
class RenameSymbolResult:
    query: dict
    status: str
    target: RenameSymbolTarget | None
    old_name: str | None
    edits: list[RenameFileEdits]
    diagnostics: list[DefinitionDiagnostic]

    @classmethod
    def from_dict(cls, data: dict) -> RenameSymbolResult:
        return cls(
            query=dict(data["query"]),
            status=data["status"],
            target=(
                RenameSymbolTarget.from_dict(data["target"])
                if data.get("target") is not None
                else None
            ),
            old_name=data.get("old_name"),
            edits=[RenameFileEdits.from_dict(item) for item in data.get("edits", [])],
            diagnostics=[
                DefinitionDiagnostic.from_dict(item)
                for item in data.get("diagnostics", [])
            ],
        )

    def render_text(self) -> str:
        lines = [f"status: {self.status}"]
        if self.target is not None:
            lines.append(f"target: {self.target.render_text()}")
        if self.old_name is not None:
            lines.append(f"old_name: {self.old_name}")
        lines.extend(file_edits.render_text() for file_edits in self.edits)
        lines.extend(diagnostic.render_text() for diagnostic in self.diagnostics)
        return "\n".join(lines)


@dataclass(frozen=True)
class DefinitionByReferenceLookupResult:
    query: dict
    status: str
    definitions: list[DefinitionCandidate]
    diagnostics: list[DefinitionDiagnostic]

    @classmethod
    def from_dict(cls, data: dict) -> DefinitionByReferenceLookupResult:
        return cls(
            query=dict(data["query"]),
            status=data["status"],
            definitions=[
                DefinitionCandidate.from_dict(item)
                for item in data.get("definitions", [])
            ],
            diagnostics=[
                DefinitionDiagnostic.from_dict(item)
                for item in data.get("diagnostics", [])
            ],
        )

    def render_text(self) -> str:
        lines = [f"status: {self.status}"]
        lines.extend(definition.render_text() for definition in self.definitions)
        lines.extend(diagnostic.render_text() for diagnostic in self.diagnostics)
        return "\n".join(lines)


@dataclass(frozen=True)
class SummaryElement:
    path: str
    symbol: str
    kind: str
    start_line: int
    end_line: int
    text: str
    parent_symbol: str | None = None
    render_line_numbers: bool = True

    @classmethod
    def from_dict(cls, data: dict, render_line_numbers: bool = True) -> SummaryElement:
        return cls(
            path=data["path"],
            symbol=data["symbol"],
            kind=data["kind"],
            start_line=data["start_line"],
            end_line=data["end_line"],
            text=data["text"],
            parent_symbol=data.get("parent_symbol"),
            render_line_numbers=render_line_numbers,
        )

    def render_text(self) -> str:
        lines = self.text.splitlines()
        if not lines:
            return ""
        if not self.render_line_numbers:
            return self.text
        if self.start_line == self.end_line:
            prefix = f"{self.start_line}: {lines[0]}"
        else:
            prefix = f"{self.start_line}..{self.end_line}: {lines[0]}"
        return "\n".join([prefix, *lines[1:]])


@dataclass(frozen=True)
class SummaryBlock:
    label: str
    path: str
    preamble: str
    elements: list[SummaryElement]
    render_line_numbers: bool = True

    @classmethod
    def from_dict(cls, data: dict, render_line_numbers: bool = True) -> SummaryBlock:
        return cls(
            label=data["label"],
            path=data["path"],
            preamble=data.get("preamble", ""),
            elements=[
                SummaryElement.from_dict(item, render_line_numbers)
                for item in data["elements"]
            ],
            render_line_numbers=render_line_numbers,
        )

    def render_text(self) -> str:
        blocks: list[str] = [self.path]
        rendered_elements = [
            element.render_text() for element in self.elements if element.text
        ]
        blocks.extend(rendered_elements)
        return "\n".join(blocks).strip()


class ContainerKind(StrEnum):
    DIRECTORY = "directory"
    PACKAGE = "package"


@dataclass(frozen=True)
class DirectoryListingEntry:
    kind: ClassVar[str] = "directory"
    name: str
    path: str

    def render_text(self, _render_line_numbers: bool = True) -> str:
        return f"[directory] {self.path}"


@dataclass(frozen=True)
class FileListingEntry:
    kind: ClassVar[str] = "file"
    name: str
    path: str

    def render_text(self, _render_line_numbers: bool = True) -> str:
        return f"[file] {self.path}"


@dataclass(frozen=True)
class PackageListingEntry:
    kind: ClassVar[str] = "package"
    name: str
    qualified_name: str
    languages: list[str]

    def render_text(self, _render_line_numbers: bool = True) -> str:
        suffix = f"; {', '.join(self.languages)}" if self.languages else ""
        return f"[package{suffix}] {self.qualified_name}"


@dataclass(frozen=True)
class TypeListingEntry:
    kind: ClassVar[str] = "type"
    name: str
    symbol: str
    language: str
    path: str
    start_line: int
    end_line: int

    def render_text(self, render_line_numbers: bool = True) -> str:
        location = (
            f"{self.path}:{self.start_line}..{self.end_line}"
            if render_line_numbers
            else self.path
        )
        return f"[type; {self.language}] {self.symbol}: {location}"


ContainerListingEntry = (
    DirectoryListingEntry
    | FileListingEntry
    | PackageListingEntry
    | TypeListingEntry
)


def _container_listing_entry_from_dict(data: dict) -> ContainerListingEntry:
    kind = data["kind"]
    if kind == "directory":
        return DirectoryListingEntry(name=data["name"], path=data["path"])
    if kind == "file":
        return FileListingEntry(name=data["name"], path=data["path"])
    if kind == "package":
        return PackageListingEntry(
            name=data["name"],
            qualified_name=data["qualified_name"],
            languages=list(data.get("languages", [])),
        )
    if kind == "type":
        return TypeListingEntry(
            name=data["name"],
            symbol=data["symbol"],
            language=data["language"],
            path=data["path"],
            start_line=int(data["start_line"]),
            end_line=int(data["end_line"]),
        )
    raise ValueError(f"unknown container listing entry kind: {kind}")


@dataclass(frozen=True)
class ContainerListing:
    target: str
    kind: ContainerKind
    languages: list[str]
    entries: list[ContainerListingEntry]
    total_entries: int
    truncated: bool
    render_line_numbers: bool = True

    @classmethod
    def from_dict(
        cls, data: dict, render_line_numbers: bool = True
    ) -> ContainerListing:
        return cls(
            target=data["target"],
            kind=ContainerKind(data["kind"]),
            languages=list(data.get("languages", [])),
            entries=[
                _container_listing_entry_from_dict(item)
                for item in data.get("entries", [])
            ],
            total_entries=int(data.get("total_entries", len(data.get("entries", [])))),
            truncated=bool(data.get("truncated", False)),
            render_line_numbers=render_line_numbers,
        )

    def render_text(self) -> str:
        label = "Directory" if self.kind is ContainerKind.DIRECTORY else "Package"
        suffix = f" ({', '.join(self.languages)})" if self.languages else ""
        lines = [f"{label} {self.target}{suffix}"]
        lines.extend(
            entry.render_text(self.render_line_numbers) for entry in self.entries
        )
        if not self.entries:
            lines.append("(empty)")
        if self.truncated:
            lines.append(
                f"[showing {len(self.entries)} of {self.total_entries} entries]"
            )
        return "\n".join(lines)


@dataclass(frozen=True)
class SymbolSummariesResult:
    summaries: list[SummaryBlock]
    listings: list[ContainerListing]
    compact_symbols: SkimFilesResult | None
    not_found: list[str]
    ambiguous: list[AmbiguousSymbol]
    render_line_numbers: bool = True
    rendered_text: str | None = None

    @classmethod
    def from_dict(
        cls, data: dict, render_line_numbers: bool = True, rendered_text: str | None = None
    ) -> SymbolSummariesResult:
        return cls(
            summaries=[
                SummaryBlock.from_dict(item, render_line_numbers)
                for item in data["summaries"]
            ],
            listings=[
                ContainerListing.from_dict(item, render_line_numbers)
                for item in data.get("listings", [])
            ],
            compact_symbols=(
                SkimFilesResult.from_dict(data["compact_symbols"], render_line_numbers)
                if data.get("compact_symbols") is not None
                else None
            ),
            not_found=list(data["not_found"]),
            ambiguous=[
                AmbiguousSymbol.from_dict(item) for item in data.get("ambiguous", [])
            ],
            render_line_numbers=render_line_numbers,
            rendered_text=rendered_text,
        )

    @property
    def count(self) -> int:
        compact_count = self.compact_symbols.count if self.compact_symbols is not None else 0
        listing_count = sum(len(listing.entries) for listing in self.listings)
        return len(self.summaries) + listing_count + compact_count

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        blocks = [summary.render_text() for summary in self.summaries]
        blocks.extend(listing.render_text() for listing in self.listings)
        if self.compact_symbols is not None:
            blocks.append(self.compact_symbols.render_text())
        if self.not_found:
            blocks.append(f"Not found: {', '.join(self.not_found)}")
        blocks.extend(item.render_text() for item in self.ambiguous)
        return "\n\n".join(blocks) if blocks else "No matching summaries found."


FileSummariesResult = SymbolSummariesResult


@dataclass(frozen=True)
class SourceBlock:
    label: str
    path: str
    start_line: int
    end_line: int
    text: str
    render_line_numbers: bool = True

    @classmethod
    def from_dict(cls, data: dict, render_line_numbers: bool = True) -> SourceBlock:
        return cls(
            label=data["label"],
            path=data["path"],
            start_line=data["start_line"],
            end_line=data["end_line"],
            text=data["text"],
            render_line_numbers=render_line_numbers,
        )

    def render_text(self) -> str:
        header = (
            f"{self.label} ({self.path}:{self.start_line}..{self.end_line})"
            if self.render_line_numbers
            else f"{self.label} ({self.path})"
        )
        return "\n".join(
            [header, _render_block(self.text, self.start_line, self.render_line_numbers)]
        )


@dataclass(frozen=True)
class SymbolSourcesResult:
    sources: list[SourceBlock]
    not_found: list[str]
    ambiguous: list[AmbiguousSymbol]
    render_line_numbers: bool = True
    rendered_text: str | None = None

    @classmethod
    def from_dict(
        cls, data: dict, render_line_numbers: bool = True, rendered_text: str | None = None
    ) -> SymbolSourcesResult:
        return cls(
            sources=[
                SourceBlock.from_dict(item, render_line_numbers)
                for item in data["sources"]
            ],
            not_found=list(data["not_found"]),
            ambiguous=[
                AmbiguousSymbol.from_dict(item) for item in data.get("ambiguous", [])
            ],
            render_line_numbers=render_line_numbers,
            rendered_text=rendered_text,
        )

    @property
    def count(self) -> int:
        return len(self.sources)

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        blocks = [source.render_text() for source in self.sources]
        if self.not_found:
            blocks.append(f"Not found: {', '.join(self.not_found)}")
        blocks.extend(item.render_text() for item in self.ambiguous)
        return "\n\n".join(blocks) if blocks else "No matching sources found."


@dataclass(frozen=True)
class ScanUsagesResult:
    structured: dict
    rendered_text: str | None = None

    @classmethod
    def from_dict(
        cls,
        data: dict,
        rendered_text: str | None = None,
    ) -> ScanUsagesResult:
        return cls(structured=data, rendered_text=rendered_text)

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        tool_name = _scan_usages_tool_name(self.structured)
        usages = self.structured.get("usages", [])
        blocks: list[str] = []
        for usage in usages:
            symbol = str(usage.get("symbol", "<unknown>"))
            total_hits = int(usage.get("total_hits", 0))
            lines = [f"{symbol}: {total_hits} usage(s)"]
            note = usage.get("note")
            if note:
                lines.append(f"  note: {note}")
            elif total_hits == 0 and usage.get("verified_absent"):
                lines.append(
                    "  note: resolved symbol; no external usage sites found under current filters."
                )
            if usage.get("candidate_files_truncated"):
                lines.append(
                    f"  note: candidate file set was truncated; re-call {tool_name} with narrower paths."
                )
            if usage.get("definition_sites_excluded") is not None:
                lines.append(
                    f"  note: {usage['definition_sites_excluded']} definition-site hit(s) were excluded from external usages."
                )
            if usage.get("files_truncated") is not None:
                lines.append(
                    f"  note: {usage['files_truncated']} file group(s) omitted from rendered output; re-call with narrower paths for detail."
                )
            for file_group in usage.get("files", []):
                path = str(file_group.get("path", "<unknown>"))
                lines.append(path)
                _append_usage_hits(lines, file_group, "  ")
            unproven_files = usage.get("unproven_files", [])
            if unproven_files:
                lines.append("unproven matches:")
                for file_group in unproven_files:
                    path = str(file_group.get("path", "<unknown>"))
                    lines.append(f"  {path}")
                    _append_usage_hits(lines, file_group, "    ")
            blocks.append("\n".join(lines))
        not_found = self.structured.get("not_found", [])
        if not_found:
            blocks.append(
                "## Not found\n\n"
                + "\n".join(
                    f"- `{item.get('input', '<unknown>')}`"
                    + (f": {item['note']}" if item.get("note") else "")
                    for item in not_found
                )
            )
        failures = self.structured.get("failures", [])
        if failures:
            lines = ["## Usage analysis failures", ""]
            for failure in failures:
                line = (
                    f"- `{failure.get('symbol', '<unknown>')}`: "
                    f"{failure.get('reason', '<no reason>')} "
                    f"({failure.get('reason_kind', '<unknown>')})"
                )
                if failure.get("hint"):
                    line += f"; {failure['hint']}"
                if failure.get("candidate_files_truncated"):
                    line += "; candidate file set was truncated"
                lines.append(line)
            blocks.append("\n".join(lines))
        ambiguous = self.structured.get("ambiguous", [])
        if ambiguous:
            lines = [
                "## Ambiguous usage symbols",
                "",
                "| Target | Matches | Note |",
                "| --- | --- | --- |",
            ]
            for item in ambiguous:
                matches = ", ".join(item.get("candidate_targets", []))
                note = item.get(
                    "note",
                    (
                        "Ambiguous; re-call scan_usages_by_location with a refined "
                        "line/column target from candidate_details."
                        if tool_name == "scan_usages_by_location"
                        else "Ambiguous; re-call scan_usages_by_reference with one "
                        "symbolic selector from candidate_targets."
                    ),
                )
                lines.append(
                    f"| `{item.get('symbol', '<unknown>')}` | {matches} | {note} |"
                )
            blocks.append("\n".join(lines))
        too_many = self.structured.get("too_many_callsites", [])
        if too_many:
            lines = ["## Too many callsites", ""]
            for item in too_many:
                note = item.get(
                    "note",
                    f"Re-call {tool_name} with narrower paths to reduce the scan scope.",
                )
                lines.append(
                    f"- `{item.get('symbol', '<unknown>')}`: {item.get('total_callsites', '?')} "
                    f"callsites exceeded limit {item.get('limit', '?')}; {note}"
                )
            blocks.append("\n".join(lines))
        if not blocks:
            warnings = self.structured.get("summary", {}).get("warnings", [])
            if warnings:
                return "## Warnings\n\n" + "\n".join(
                    f"- {warning}" for warning in warnings
                )
            return "No usages found."
        return "\n\n".join(blocks)


def _scan_usages_tool_name(structured: dict) -> str:
    for result in structured.get("results", []):
        if result.get("input_kind") == "target":
            return "scan_usages_by_location"
    return "scan_usages_by_reference"


def _append_usage_hits(lines: list[str], file_group: dict, prefix: str) -> None:
    hits = file_group.get("hits", [])
    if not hits and file_group.get("hit_count") is not None:
        lines.append(f"{prefix}{file_group['hit_count']} hit(s)")
        return
    for hit in hits:
        line = hit.get("line_range") or hit.get("line")
        enclosing = hit.get("enclosing")
        if (
            hit.get("line") is not None
            and hit.get("column") is not None
            and hit.get("end_line") is not None
            and hit.get("end_column") is not None
        ):
            location = (
                f"{prefix}line {hit['line']}:{hit['column']}-"
                f"{hit['end_line']}:{hit['end_column']}"
            )
        else:
            location = f"{prefix}line {line}" if line is not None else f"{prefix}hit"
        if enclosing:
            location += f" in {enclosing}"
        if hit.get("hit_count") is not None:
            location += f" ({hit['hit_count']} hit(s))"
        if float(hit.get("confidence", 1.0)) < 1.0:
            location += f" [confidence {float(hit['confidence']):.2f}]"
        lines.append(location)
        snippet = str(hit.get("snippet", "")).rstrip()
        if snippet:
            lines.extend(f"{prefix}  {snippet_line}" for snippet_line in snippet.splitlines())


@dataclass(frozen=True)
class SkimFile:
    path: str
    loc: int
    lines: list[str]
    render_line_numbers: bool = True

    @classmethod
    def from_dict(cls, data: dict, render_line_numbers: bool = True) -> SkimFile:
        return cls(
            path=data["path"],
            loc=data["loc"],
            lines=list(data["lines"]),
            render_line_numbers=render_line_numbers,
        )

    def render_text(self) -> str:
        return "\n".join([f"{self.path} ({self.loc} lines)", *self.lines])


@dataclass(frozen=True)
class SkimFilesResult:
    truncated: bool
    total_files: int
    files: list[SkimFile]
    render_line_numbers: bool = True
    rendered_text: str | None = None

    @classmethod
    def from_dict(
        cls, data: dict, render_line_numbers: bool = True, rendered_text: str | None = None
    ) -> SkimFilesResult:
        return cls(
            truncated=bool(data["truncated"]),
            total_files=int(data.get("total_files", len(data["files"]))),
            files=[
                SkimFile.from_dict(item, render_line_numbers)
                for item in data["files"]
            ],
            render_line_numbers=render_line_numbers,
            rendered_text=rendered_text,
        )

    @property
    def count(self) -> int:
        return len(self.files)

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        blocks = [file.render_text() for file in self.files]
        if not blocks:
            return "No matching files found."
        text = "\n\n".join(blocks)
        if self.truncated:
            text += (
                f"\n\nResults truncated: showing {len(self.files)} of {self.total_files} "
                "files selected by recent activity when available. Results are displayed alphabetically."
            )
        return text


@dataclass(frozen=True)
class MostRelevantFilesResult:
    files: list[str]
    not_found: list[str]
    duplicates: list[str]
    render_line_numbers: bool = True
    rendered_text: str | None = None

    @classmethod
    def from_dict(
        cls, data: dict, render_line_numbers: bool = True, rendered_text: str | None = None
    ) -> MostRelevantFilesResult:
        return cls(
            files=list(data["files"]),
            not_found=list(data["not_found"]),
            duplicates=list(data.get("duplicates", [])),
            render_line_numbers=render_line_numbers,
            rendered_text=rendered_text,
        )

    @property
    def count(self) -> int:
        return len(self.files)

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        if not self.files and not self.not_found and not self.duplicates:
            return "No related files found."

        lines = list(self.files)
        if self.not_found:
            lines.append(f"Not found: {', '.join(self.not_found)}")
        if self.duplicates:
            lines.append(f"Duplicate seeds: {', '.join(self.duplicates)}")
        return "\n".join(lines)


@dataclass(frozen=True)
class RankedSymbol:
    fqfn: str
    score: float

    @classmethod
    def from_dict(cls, data: dict) -> RankedSymbol:
        return cls(fqfn=data["fqfn"], score=float(data["score"]))


@dataclass(frozen=True)
class RankedFile:
    path: str
    score: float

    @classmethod
    def from_dict(cls, data: dict) -> RankedFile:
        return cls(path=data["path"], score=float(data["score"]))


@dataclass(frozen=True)
class SemanticSearchResult:
    """The three independent retrieval signals over function chunks. Reranking/fusing
    them is the caller's job."""

    vector_ranked: list[RankedSymbol]
    bm25_ranked: list[RankedSymbol]
    coedit_ranked: list[RankedFile]
    notes: list[str]
    render_line_numbers: bool = True
    rendered_text: str | None = None

    @classmethod
    def from_dict(
        cls, data: dict, render_line_numbers: bool = True, rendered_text: str | None = None
    ) -> SemanticSearchResult:
        return cls(
            vector_ranked=[RankedSymbol.from_dict(item) for item in data.get("vector_ranked", [])],
            bm25_ranked=[RankedSymbol.from_dict(item) for item in data.get("bm25_ranked", [])],
            coedit_ranked=[RankedFile.from_dict(item) for item in data.get("coedit_ranked", [])],
            notes=list(data.get("notes", [])),
            render_line_numbers=render_line_numbers,
            rendered_text=rendered_text,
        )

    @property
    def count(self) -> int:
        return len(self.vector_ranked)

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        lines = [f"note: {note}" for note in self.notes]
        if self.vector_ranked:
            lines.append("=== vector ===")
            lines.extend(f"{r.fqfn} (score {r.score:.3f})" for r in self.vector_ranked)
        if self.bm25_ranked:
            lines.append("=== bm25 ===")
            lines.extend(f"{r.fqfn} (score {r.score:.3f})" for r in self.bm25_ranked)
        if self.coedit_ranked:
            lines.append("=== co-edit ===")
            lines.extend(f"{r.path} (score {r.score:.3f})" for r in self.coedit_ranked)
        return "\n".join(lines) if lines else "No semantically similar code found."


@dataclass(frozen=True)
class SemanticSearchStatus:
    indexed_chunks: int
    pending_batches: int
    phase: str
    materialized_files: int
    materialize_total_files: int

    @classmethod
    def from_dict(cls, data: dict) -> SemanticSearchStatus:
        return cls(
            indexed_chunks=int(data["indexed_chunks"]),
            pending_batches=int(data["pending_batches"]),
            phase=str(data["phase"]),
            materialized_files=int(data["materialized_files"]),
            materialize_total_files=int(data["materialize_total_files"]),
        )


@dataclass(frozen=True)
class UsageGraphNode:
    """A class or function definition in the workspace usage graph.

    Node identity is ``(language, fqn)``: ``fqn`` matches the fully qualified
    names returned by ``search_symbols``, and ``language`` is the ecosystem it
    belongs to (e.g. ``"python"``, ``"go"``, ``"rust"``, with JavaScript and
    TypeScript sharing ``"js_ts"``), so a name shared across
    languages stays as distinct nodes. For file-scoped ecosystems
    (JavaScript/TypeScript) ``path`` also participates in identity, so two files
    exporting the same name remain distinct nodes that share ``fqn``.
    """

    fqn: str
    language: str
    path: str
    start_line: int
    kind: str
    signature: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> UsageGraphNode:
        return cls(
            fqn=data["fqn"],
            language=data["language"],
            path=data["path"],
            start_line=data["start_line"],
            kind=data["kind"],
            signature=data.get("signature"),
        )


@dataclass(frozen=True)
class UsageGraphCallSite:
    """One concrete reference site behind a :class:`UsageGraphEdge`.

    ``path`` is workspace-relative and ``line`` is 1-based, matching the
    ``line`` of a scan-usages hit and a node's ``start_line``.
    """

    path: str
    line: int

    @classmethod
    def from_dict(cls, data: dict) -> UsageGraphCallSite:
        return cls(path=data["path"], line=data["line"])


@dataclass(frozen=True)
class UsageGraphEdge:
    """A weighted caller -> callee reference edge.

    ``from_fqn`` is the enclosing definition of the reference and ``to_fqn`` is
    the symbol being referenced; both endpoints are nodes in ``language``'s
    ecosystem. ``weight`` is the number of distinct ``(file, line, caller)``
    reference sites (two references to the same callee on one line count once).
    (The JSON keys are ``from``/``to``, renamed here because ``from`` is a
    Python keyword.)

    ``sites`` lists those reference locations (``{path, line}``), one per
    distinct ``(file, line, caller)`` site, so ``len(sites) == weight``.
    """

    from_fqn: str
    to_fqn: str
    language: str
    weight: int
    sites: list[UsageGraphCallSite] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> UsageGraphEdge:
        return cls(
            from_fqn=data["from"],
            to_fqn=data["to"],
            language=data["language"],
            weight=data["weight"],
            sites=[
                UsageGraphCallSite.from_dict(item)
                for item in data.get("sites", [])
            ],
        )


@dataclass(frozen=True)
class UsageGraphTruncatedSymbol:
    """A symbol whose call sites exceeded the analyzer's enumeration guardrail.

    It still appears in ``nodes``; only its inbound edges are omitted.
    """

    fqn: str
    language: str
    total_callsites: int
    limit: int

    @classmethod
    def from_dict(cls, data: dict) -> UsageGraphTruncatedSymbol:
        return cls(
            fqn=data["fqn"],
            language=data["language"],
            total_callsites=data["total_callsites"],
            limit=data["limit"],
        )


@dataclass(frozen=True)
class UsageGraphResult:
    """The whole-workspace resolved usage graph.

    Feed ``nodes`` and ``edges`` straight into a graph library (e.g. build a
    ``networkx.DiGraph`` and run ``pagerank``) to rank symbols for a code map.
    """

    nodes: list[UsageGraphNode]
    edges: list[UsageGraphEdge]
    truncated_symbols: list[UsageGraphTruncatedSymbol]
    rendered_text: str | None = None

    @classmethod
    def from_dict(
        cls, data: dict, rendered_text: str | None = None
    ) -> UsageGraphResult:
        return cls(
            nodes=[UsageGraphNode.from_dict(item) for item in data.get("nodes", [])],
            edges=[UsageGraphEdge.from_dict(item) for item in data.get("edges", [])],
            truncated_symbols=[
                UsageGraphTruncatedSymbol.from_dict(item)
                for item in data.get("truncated_symbols", [])
            ],
            rendered_text=rendered_text,
        )

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        summary = f"{len(self.nodes)} nodes, {len(self.edges)} edges"
        if self.truncated_symbols:
            summary += f", {len(self.truncated_symbols)} truncated"
        return summary


@dataclass(frozen=True)
class CommitPair:
    hash: str
    parent_hash: str

    @classmethod
    def from_dict(cls, data: dict) -> CommitPair:
        return cls(hash=data["hash"], parent_hash=data["parent_hash"])


@dataclass(frozen=True)
class FileChange:
    old_path: str | None
    path: str | None
    status: str
    loc_changed: int
    is_test: bool
    is_parseable: bool

    @classmethod
    def from_dict(cls, data: dict) -> FileChange:
        return cls(
            old_path=data.get("old_path"),
            path=data.get("path"),
            status=data["status"],
            loc_changed=int(data["loc_changed"]),
            is_test=bool(data["is_test"]),
            is_parseable=bool(data["is_parseable"]),
        )


@dataclass(frozen=True)
class CommitSymbol:
    fqn: str
    name: str
    kind: str
    signature: str
    path: str
    start_line: int
    end_line: int
    language: str
    is_test: bool

    @classmethod
    def from_dict(cls, data: dict) -> CommitSymbol:
        return cls(
            fqn=data["fqn"],
            name=data["name"],
            kind=data["kind"],
            signature=data.get("signature", ""),
            path=data["path"],
            start_line=int(data["start_line"]),
            end_line=int(data["end_line"]),
            language=data["language"],
            is_test=bool(data["is_test"]),
        )


@dataclass(frozen=True)
class PatchTouchedSymbol:
    fqn: str
    name: str
    kind: str
    signature: str
    path: str
    start_line: int
    end_line: int
    language: str
    is_test: bool
    touched_old_lines: list[int]
    touched_new_lines: list[int]
    change_reason: str

    @classmethod
    def from_dict(cls, data: dict) -> PatchTouchedSymbol:
        return cls(
            fqn=data["fqn"],
            name=data["name"],
            kind=data["kind"],
            signature=data.get("signature", ""),
            path=data["path"],
            start_line=int(data["start_line"]),
            end_line=int(data["end_line"]),
            language=data["language"],
            is_test=bool(data["is_test"]),
            touched_old_lines=[int(item) for item in data.get("touched_old_lines", [])],
            touched_new_lines=[int(item) for item in data.get("touched_new_lines", [])],
            change_reason=data["change_reason"],
        )


@dataclass(frozen=True)
class PreimagePatchSymbols:
    edited: list[PatchTouchedSymbol]
    deleted: list[PatchTouchedSymbol]

    @classmethod
    def from_dict(cls, data: dict) -> PreimagePatchSymbols:
        return cls(
            edited=[PatchTouchedSymbol.from_dict(item) for item in data.get("edited", [])],
            deleted=[PatchTouchedSymbol.from_dict(item) for item in data.get("deleted", [])],
        )


@dataclass(frozen=True)
class PostimagePatchSymbols:
    edited: list[PatchTouchedSymbol]
    introduced: list[PatchTouchedSymbol]

    @classmethod
    def from_dict(cls, data: dict) -> PostimagePatchSymbols:
        return cls(
            edited=[PatchTouchedSymbol.from_dict(item) for item in data.get("edited", [])],
            introduced=[
                PatchTouchedSymbol.from_dict(item) for item in data.get("introduced", [])
            ],
        )


@dataclass(frozen=True)
class PatchSymbols:
    preimage: PreimagePatchSymbols
    postimage: PostimagePatchSymbols

    @classmethod
    def from_dict(cls, data: dict) -> PatchSymbols:
        return cls(
            preimage=PreimagePatchSymbols.from_dict(data.get("preimage", {})),
            postimage=PostimagePatchSymbols.from_dict(data.get("postimage", {})),
        )


@dataclass(frozen=True)
class MovedSymbol:
    before: CommitSymbol
    after: CommitSymbol

    @classmethod
    def from_dict(cls, data: dict) -> MovedSymbol:
        return cls(
            before=CommitSymbol.from_dict(data["before"]),
            after=CommitSymbol.from_dict(data["after"]),
        )


@dataclass(frozen=True)
class SignatureChange:
    before: CommitSymbol
    after: CommitSymbol

    @classmethod
    def from_dict(cls, data: dict) -> SignatureChange:
        return cls(
            before=CommitSymbol.from_dict(data["before"]),
            after=CommitSymbol.from_dict(data["after"]),
        )


@dataclass(frozen=True)
class ImportChange:
    path: str
    added: list[str]
    removed: list[str]

    @classmethod
    def from_dict(cls, data: dict) -> ImportChange:
        return cls(
            path=data["path"],
            added=list(data.get("added", [])),
            removed=list(data.get("removed", [])),
        )


@dataclass(frozen=True)
class CallEdgeChange:
    change: str
    from_fqn: str
    to_fqn: str
    language: str
    weight: int
    sites: list[UsageGraphCallSite]

    @classmethod
    def from_dict(cls, data: dict) -> CallEdgeChange:
        return cls(
            change=data["change"],
            from_fqn=data["from"],
            to_fqn=data["to"],
            language=data["language"],
            weight=int(data["weight"]),
            sites=[UsageGraphCallSite.from_dict(item) for item in data.get("sites", [])],
        )


@dataclass(frozen=True)
class ChangedTestSymbols:
    introduced: list[PatchTouchedSymbol]
    edited: list[PatchTouchedSymbol]
    deleted: list[PatchTouchedSymbol]
    moved: list[MovedSymbol]
    signature_changes: list[SignatureChange]

    @classmethod
    def from_dict(cls, data: dict) -> ChangedTestSymbols:
        return cls(
            introduced=[
                PatchTouchedSymbol.from_dict(item) for item in data.get("introduced", [])
            ],
            edited=[PatchTouchedSymbol.from_dict(item) for item in data.get("edited", [])],
            deleted=[PatchTouchedSymbol.from_dict(item) for item in data.get("deleted", [])],
            moved=[MovedSymbol.from_dict(item) for item in data.get("moved", [])],
            signature_changes=[
                SignatureChange.from_dict(item) for item in data.get("signature_changes", [])
            ],
        )


@dataclass(frozen=True)
class LargeCallsiteSymbol:
    fqn: str
    language: str
    total_callsites: int
    limit: int

    @classmethod
    def from_dict(cls, data: dict) -> LargeCallsiteSymbol:
        return cls(
            fqn=data["fqn"],
            language=data["language"],
            total_callsites=int(data["total_callsites"]),
            limit=int(data["limit"]),
        )


@dataclass(frozen=True)
class CommitAnalysisResult:
    commit: CommitPair
    file_changes: list[FileChange]
    patch_symbols: PatchSymbols
    moved_symbols: list[MovedSymbol]
    dependency_symbols: list[CommitSymbol]
    signature_changes: list[SignatureChange]
    import_changes: list[ImportChange]
    call_edge_changes: list[CallEdgeChange]
    changed_test_symbols: ChangedTestSymbols
    large_callsite_symbols: list[LargeCallsiteSymbol]

    @classmethod
    def from_dict(cls, data: dict) -> CommitAnalysisResult:
        return cls(
            commit=CommitPair.from_dict(data["commit"]),
            file_changes=[FileChange.from_dict(item) for item in data.get("file_changes", [])],
            patch_symbols=PatchSymbols.from_dict(data["patch_symbols"]),
            moved_symbols=[MovedSymbol.from_dict(item) for item in data.get("moved_symbols", [])],
            dependency_symbols=[
                CommitSymbol.from_dict(item) for item in data.get("dependency_symbols", [])
            ],
            signature_changes=[
                SignatureChange.from_dict(item) for item in data.get("signature_changes", [])
            ],
            import_changes=[ImportChange.from_dict(item) for item in data.get("import_changes", [])],
            call_edge_changes=[
                CallEdgeChange.from_dict(item) for item in data.get("call_edge_changes", [])
            ],
            changed_test_symbols=ChangedTestSymbols.from_dict(
                data.get("changed_test_symbols", {})
            ),
            large_callsite_symbols=[
                LargeCallsiteSymbol.from_dict(item)
                for item in data.get("large_callsite_symbols", [])
            ],
        )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AmbiguousPath:
    """A path input that resolved to more than one workspace file.

    The file, structured-data, and code-quality tools report these instead of
    guessing which file a non-unique path meant.
    """

    input: str
    matches: list[str]

    @classmethod
    def from_dict(cls, data: dict) -> AmbiguousPath:
        return cls(input=data["input"], matches=list(data["matches"]))

    def render_text(self) -> str:
        return f"Ambiguous {self.input}: {', '.join(self.matches)}"


def _ambiguous_paths(data: dict) -> list[AmbiguousPath]:
    # Rust omits ambiguous_paths entirely when empty (skip_serializing_if).
    return [AmbiguousPath.from_dict(item) for item in data.get("ambiguous_paths", [])]


# ---------------------------------------------------------------------------
# Workspace lifecycle
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RefreshResult:
    """Index metrics returned by ``refresh`` and ``update_paths``."""

    languages: list[str]
    analyzed_files: int
    declarations: int

    @classmethod
    def from_dict(cls, data: dict) -> RefreshResult:
        return cls(
            languages=list(data.get("languages", [])),
            analyzed_files=int(data["analyzed_files"]),
            declarations=int(data["declarations"]),
        )

    def render_text(self) -> str:
        languages = ", ".join(self.languages) if self.languages else "none"
        return (
            f"{self.analyzed_files} files, {self.declarations} declarations "
            f"({languages})"
        )


@dataclass(frozen=True)
class WorkspaceResult:
    """The active workspace root (``activate_workspace`` / ``get_active_workspace``)."""

    workspace_path: str

    @classmethod
    def from_dict(cls, data: dict) -> WorkspaceResult:
        return cls(workspace_path=data["workspace_path"])

    def render_text(self) -> str:
        return self.workspace_path


# ---------------------------------------------------------------------------
# File tools
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FileContent:
    path: str
    content: str
    truncated: bool
    total_lines: int | None = None
    head_lines: int | None = None
    tail_lines: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> FileContent:
        return cls(
            path=data["path"],
            content=data["content"],
            truncated=bool(data.get("truncated", False)),
            total_lines=data.get("total_lines"),
            head_lines=data.get("head_lines"),
            tail_lines=data.get("tail_lines"),
        )


@dataclass(frozen=True)
class GetFileContentsResult:
    files: list[FileContent]
    not_found: list[str]
    ambiguous_paths: list[AmbiguousPath] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> GetFileContentsResult:
        return cls(
            files=[FileContent.from_dict(item) for item in data.get("files", [])],
            not_found=list(data.get("not_found", [])),
            ambiguous_paths=_ambiguous_paths(data),
        )

    @property
    def count(self) -> int:
        return len(self.files)


@dataclass(frozen=True)
class FindFilenamesResult:
    files: list[str]
    truncated: bool

    @classmethod
    def from_dict(cls, data: dict) -> FindFilenamesResult:
        return cls(
            files=list(data.get("files", [])),
            truncated=bool(data.get("truncated", False)),
        )

    @property
    def count(self) -> int:
        return len(self.files)


@dataclass(frozen=True)
class LineMatch:
    line: int
    text: str
    before: list[str]
    after: list[str]

    @classmethod
    def from_dict(cls, data: dict) -> LineMatch:
        return cls(
            line=int(data["line"]),
            text=data["text"],
            before=list(data.get("before", [])),
            after=list(data.get("after", [])),
        )


@dataclass(frozen=True)
class FileMatchGroup:
    path: str
    matches: list[LineMatch]
    truncated: bool

    @classmethod
    def from_dict(cls, data: dict) -> FileMatchGroup:
        return cls(
            path=data["path"],
            matches=[LineMatch.from_dict(item) for item in data.get("matches", [])],
            truncated=bool(data.get("truncated", False)),
        )


@dataclass(frozen=True)
class SearchFileContentsResult:
    matches: list[FileMatchGroup]
    truncated: bool
    invalid_patterns: list[str]
    ambiguous_paths: list[AmbiguousPath] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> SearchFileContentsResult:
        return cls(
            matches=[
                FileMatchGroup.from_dict(item) for item in data.get("matches", [])
            ],
            truncated=bool(data.get("truncated", False)),
            invalid_patterns=list(data.get("invalid_patterns", [])),
            ambiguous_paths=_ambiguous_paths(data),
        )

    @property
    def count(self) -> int:
        return len(self.matches)


@dataclass(frozen=True)
class FindFilesContainingResult:
    files: list[str]
    truncated: bool
    invalid_patterns: list[str]

    @classmethod
    def from_dict(cls, data: dict) -> FindFilesContainingResult:
        return cls(
            files=list(data.get("files", [])),
            truncated=bool(data.get("truncated", False)),
            invalid_patterns=list(data.get("invalid_patterns", [])),
        )

    @property
    def count(self) -> int:
        return len(self.files)


@dataclass(frozen=True)
class ListFilesResult:
    directory: str
    files: list[str]
    truncated: bool

    @classmethod
    def from_dict(cls, data: dict) -> ListFilesResult:
        return cls(
            directory=data["directory"],
            files=list(data.get("files", [])),
            truncated=bool(data.get("truncated", False)),
        )

    @property
    def count(self) -> int:
        return len(self.files)


# ---------------------------------------------------------------------------
# Git tools
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GitTextResult:
    """A git tool result.

    The Rust git tools (``get_git_log``, ``get_commit_diff``,
    ``search_git_commit_messages``) render their own XML-shaped text rather than
    structured JSON, so the payload is surfaced verbatim as ``text``.
    """

    text: str

    @classmethod
    def from_text(cls, text: str) -> GitTextResult:
        return cls(text=text)

    def render_text(self) -> str:
        return self.text

    def __str__(self) -> str:
        return self.text


# ---------------------------------------------------------------------------
# Structured data tools
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JqFileResult:
    path: str
    matches: list[str]
    truncated: bool
    error: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> JqFileResult:
        return cls(
            path=data["path"],
            matches=list(data.get("matches", [])),
            truncated=bool(data.get("truncated", False)),
            error=data.get("error"),
        )


@dataclass(frozen=True)
class JqResult:
    files: list[JqFileResult]
    truncated_files: bool
    error: str | None = None
    ambiguous_paths: list[AmbiguousPath] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> JqResult:
        return cls(
            files=[JqFileResult.from_dict(item) for item in data.get("files", [])],
            truncated_files=bool(data.get("truncated_files", False)),
            error=data.get("error"),
            ambiguous_paths=_ambiguous_paths(data),
        )


@dataclass(frozen=True)
class XmlSkimElement:
    tag: str
    depth: int
    attribute_count: int

    @classmethod
    def from_dict(cls, data: dict) -> XmlSkimElement:
        return cls(
            tag=data["tag"],
            depth=int(data["depth"]),
            attribute_count=int(data["attribute_count"]),
        )


@dataclass(frozen=True)
class XmlSkimFile:
    path: str
    elements: list[XmlSkimElement]
    error: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> XmlSkimFile:
        return cls(
            path=data["path"],
            elements=[
                XmlSkimElement.from_dict(item) for item in data.get("elements", [])
            ],
            error=data.get("error"),
        )


@dataclass(frozen=True)
class XmlSkimResult:
    files: list[XmlSkimFile]
    truncated_files: bool
    ambiguous_paths: list[AmbiguousPath] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> XmlSkimResult:
        return cls(
            files=[XmlSkimFile.from_dict(item) for item in data.get("files", [])],
            truncated_files=bool(data.get("truncated_files", False)),
            ambiguous_paths=_ambiguous_paths(data),
        )


@dataclass(frozen=True)
class XmlSelectFile:
    path: str
    matches: list[str]
    error: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> XmlSelectFile:
        return cls(
            path=data["path"],
            matches=list(data.get("matches", [])),
            error=data.get("error"),
        )


@dataclass(frozen=True)
class XmlSelectResult:
    files: list[XmlSelectFile]
    truncated_files: bool
    error: str | None = None
    ambiguous_paths: list[AmbiguousPath] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> XmlSelectResult:
        return cls(
            files=[XmlSelectFile.from_dict(item) for item in data.get("files", [])],
            truncated_files=bool(data.get("truncated_files", False)),
            error=data.get("error"),
            ambiguous_paths=_ambiguous_paths(data),
        )


# ---------------------------------------------------------------------------
# Code quality (slopcop) tools
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CodeQualityReport:
    """Result of a code-quality (slopcop) tool.

    The Rust analyzers render their own report text, surfaced verbatim as
    ``report``. ``truncated`` is omitted by the git-backed tools and defaults to
    ``False``; ``ambiguous_paths`` is present only for the file-based tools.
    """

    report: str
    truncated: bool = False
    ambiguous_paths: list[AmbiguousPath] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> CodeQualityReport:
        return cls(
            report=data["report"],
            truncated=bool(data.get("truncated", False)),
            ambiguous_paths=_ambiguous_paths(data),
        )

    def render_text(self) -> str:
        return self.report

    def __str__(self) -> str:
        return self.report
