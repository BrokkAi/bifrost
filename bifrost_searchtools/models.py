from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar, Literal, cast, get_args


CodeQueryExecutionMode = Literal["results", "explain", "profile"]
MostRelevantFilesRankingModeValue = Literal[
    "history_imports", "usage_graph", "usage_graph_exact"
]
MostRelevantFilesIncompleteReasonValue = Literal["cancelled", "time_budget"]
TestFileKindValue = Literal["test", "test_support", "production", "ambiguous"]
_CODE_QUERY_EXECUTION_MODES = get_args(CodeQueryExecutionMode)
_MOST_RELEVANT_FILES_RANKING_MODES = get_args(MostRelevantFilesRankingModeValue)
_MOST_RELEVANT_FILES_INCOMPLETE_REASONS = get_args(MostRelevantFilesIncompleteReasonValue)
_TEST_FILE_KINDS = get_args(TestFileKindValue)
_MISSING = object()


def _strict_bool(data: dict, key: str, default: object = _MISSING) -> bool:
    value = data[key] if default is _MISSING else data.get(key, default)
    if type(value) is not bool:
        raise TypeError(f"{key} must be a boolean")
    return value


def _strict_nonnegative_int(data: dict, key: str) -> int:
    value = data[key]
    if type(value) is not int or value < 0:
        raise TypeError(f"{key} must be a non-negative integer")
    return value


def _strict_list(data: dict, key: str, default: object = _MISSING) -> list[Any]:
    value = data[key] if default is _MISSING else data.get(key, default)
    if not isinstance(value, list):
        raise TypeError(f"{key} must be a list")
    return value


def _strict_string_list(data: dict, key: str) -> list[str]:
    values = _strict_list(data, key)
    if any(not isinstance(value, str) for value in values):
        raise TypeError(f"{key} must contain only strings")
    return values


def _code_query_execution_mode(value: Any) -> CodeQueryExecutionMode | None:
    if value is None:
        return None
    if value not in _CODE_QUERY_EXECUTION_MODES:
        expected = ", ".join(repr(mode) for mode in _CODE_QUERY_EXECUTION_MODES)
        raise ValueError(f"execution_mode must be one of {expected}, got {value!r}")
    return cast(CodeQueryExecutionMode, value)


def _most_relevant_files_ranking_mode(value: Any) -> MostRelevantFilesRankingModeValue:
    if value not in _MOST_RELEVANT_FILES_RANKING_MODES:
        expected = ", ".join(repr(mode) for mode in _MOST_RELEVANT_FILES_RANKING_MODES)
        raise ValueError(f"ranking_mode_used must be one of {expected}, got {value!r}")
    return cast(MostRelevantFilesRankingModeValue, value)


def _most_relevant_files_incomplete_reason(
    value: Any,
) -> MostRelevantFilesIncompleteReasonValue | None:
    if value is None:
        return None
    if value not in _MOST_RELEVANT_FILES_INCOMPLETE_REASONS:
        expected = ", ".join(
            repr(reason) for reason in _MOST_RELEVANT_FILES_INCOMPLETE_REASONS
        )
        raise ValueError(f"incomplete_reason must be one of {expected}, got {value!r}")
    return cast(MostRelevantFilesIncompleteReasonValue, value)


def _test_file_kind(value: Any) -> TestFileKindValue:
    if value not in _TEST_FILE_KINDS:
        expected = ", ".join(repr(kind) for kind in _TEST_FILE_KINDS)
        raise ValueError(f"test must be one of {expected}, got {value!r}")
    return cast(TestFileKindValue, value)


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
    procedure_id: str | None = None
    procedure_kind: str | None = None
    boundary: str | None = None
    edge_kind: str | None = None
    source_id: str | None = None
    analysis_kind: str | None = None
    outcome: str | None = None
    capture: str | None = None
    protocol_ref: str | None = None
    finding_id: str | None = None

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
            procedure_id=data.get("procedure_id"),
            procedure_kind=data.get("procedure_kind"),
            boundary=data.get("boundary"),
            edge_kind=data.get("edge_kind"),
            source_id=data.get("source_id"),
            analysis_kind=data.get("analysis_kind"),
            outcome=data.get("outcome"),
            capture=data.get("capture"),
            protocol_ref=data.get("protocol_ref"),
            finding_id=data.get("finding_id"),
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


class CodeQuerySemanticProof(StrEnum):
    PROVEN = "proven"
    UNPROVEN = "unproven"


class CodeQuerySemanticCompleteness(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"


class CodeQueryProgramPointBoundary(StrEnum):
    ENTRY = "entry"
    NORMAL_EXIT = "normal_exit"
    EXCEPTIONAL_EXIT = "exceptional_exit"


@dataclass(frozen=True)
class CodeQuerySemanticEvidence:
    proof: CodeQuerySemanticProof
    completeness: CodeQuerySemanticCompleteness
    proof_reason: str | None = None
    completeness_reason: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQuerySemanticEvidence:
        return cls(
            proof=CodeQuerySemanticProof(data["proof"]),
            completeness=CodeQuerySemanticCompleteness(data["completeness"]),
            proof_reason=data.get("proof_reason"),
            completeness_reason=data.get("completeness_reason"),
        )

    @property
    def status(self) -> str:
        return f"{self.proof.value}/{self.completeness.value}"


@dataclass(frozen=True)
class CodeQueryProgramPointRef:
    id: str
    procedure_id: str
    path: str
    range: CodeQueryRange
    boundary: CodeQueryProgramPointBoundary | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryProgramPointRef:
        return cls(
            id=data["id"],
            procedure_id=data["procedure_id"],
            path=data["path"],
            range=CodeQueryRange.from_dict(data["range"]),
            boundary=(
                CodeQueryProgramPointBoundary(data["boundary"])
                if data.get("boundary") is not None
                else None
            ),
        )


@dataclass(frozen=True)
class CodeQueryProcedure:
    id: str
    artifact_id: str
    path: str
    language: str
    procedure_kind: str
    range: CodeQueryRange
    evidence: CodeQuerySemanticEvidence
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryProcedure:
        return cls(
            id=data["id"],
            artifact_id=data["artifact_id"],
            path=data["path"],
            language=data["language"],
            procedure_kind=data["procedure_kind"],
            range=CodeQueryRange.from_dict(data["range"]),
            evidence=CodeQuerySemanticEvidence.from_dict(data["evidence"]),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        return (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[procedure; {self.procedure_kind}; {self.evidence.status}]"
        )


@dataclass(frozen=True)
class CodeQueryProgramPoint:
    id: str
    procedure_id: str
    path: str
    language: str
    range: CodeQueryRange
    boundary: CodeQueryProgramPointBoundary | None
    event_count: int
    evidence: CodeQuerySemanticEvidence
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryProgramPoint:
        return cls(
            id=data["id"],
            procedure_id=data["procedure_id"],
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            boundary=(
                CodeQueryProgramPointBoundary(data["boundary"])
                if data.get("boundary") is not None
                else None
            ),
            event_count=int(data["event_count"]),
            evidence=CodeQuerySemanticEvidence.from_dict(data["evidence"]),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        boundary = self.boundary.value if self.boundary is not None else "ordinary"
        return (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[program point; {boundary}; {self.event_count} events; "
            f"{self.evidence.status}]"
        )


@dataclass(frozen=True)
class CodeQueryControlEdge:
    id: str
    procedure_id: str
    path: str
    language: str
    range: CodeQueryRange
    edge_kind: str
    source: CodeQueryProgramPointRef
    target: CodeQueryProgramPointRef
    evidence: CodeQuerySemanticEvidence
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryControlEdge:
        return cls(
            id=data["id"],
            procedure_id=data["procedure_id"],
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            edge_kind=data["edge_kind"],
            source=CodeQueryProgramPointRef.from_dict(data["source"]),
            target=CodeQueryProgramPointRef.from_dict(data["target"]),
            evidence=CodeQuerySemanticEvidence.from_dict(data["evidence"]),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        return (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[control edge; {self.edge_kind}; {self.evidence.status}] "
            f"{self.source.id} -> {self.target.id}"
        )


@dataclass(frozen=True)
class CodeQueryTypestateSubject:
    class_name: str
    identity: str

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryTypestateSubject:
        return cls(class_name=data["class"], identity=data["identity"])


class CodeQueryTypestateFindingKindType(StrEnum):
    ERROR_TRANSITION = "error_transition"
    TERMINAL_EXPECTATION = "terminal_expectation"


@dataclass(frozen=True)
class CodeQueryTypestateFindingKind:
    type: CodeQueryTypestateFindingKindType
    event: str | None = None
    from_state: str | None = None
    to_state: str | None = None
    expectation: str | None = None
    actual_states: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryTypestateFindingKind:
        kind = CodeQueryTypestateFindingKindType(data["type"])
        if kind is CodeQueryTypestateFindingKindType.ERROR_TRANSITION:
            return cls(
                type=kind,
                event=data["event"],
                from_state=data["from_state"],
                to_state=data["to_state"],
            )
        return cls(
            type=kind,
            expectation=data["expectation"],
            actual_states=tuple(_strict_string_list(data, "actual_states")),
        )

    def render_text(self) -> str:
        if self.type is CodeQueryTypestateFindingKindType.ERROR_TRANSITION:
            return f"{self.event}: {self.from_state} -> {self.to_state}"
        return f"{self.expectation}: actual {', '.join(self.actual_states)}"


class CodeQueryTypestateCertainty(StrEnum):
    MAY = "may"
    MUST = "must"
    INCONCLUSIVE = "inconclusive"


class CodeQueryTypestateUncertainty(StrEnum):
    AMBIGUOUS_DISPATCH = "ambiguous_dispatch"
    UNKNOWN_CALL = "unknown_call"
    EXTERNAL_CALL = "external_call"
    ESCAPE = "escape"
    INCOMPLETE_ANALYSIS = "incomplete_analysis"
    UNMATCHED_EVENT = "unmatched_event"


@dataclass(frozen=True)
class CodeQueryTypestateFinding:
    id: str
    protocol_ref: str
    protocol_hash: str
    binding_plan_hash: str
    subject: CodeQueryTypestateSubject
    finding_kind: CodeQueryTypestateFindingKind
    certainty: CodeQueryTypestateCertainty
    path: str
    language: str
    range: CodeQueryRange
    path_proven: bool
    path_complete: bool
    analysis_complete: bool
    retained_witnesses: int
    omitted_witnesses: int
    uncertainty: tuple[CodeQueryTypestateUncertainty, ...] = ()
    abstained: bool = False
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryTypestateFinding:
        return cls(
            id=data["id"],
            protocol_ref=data["protocol_ref"],
            protocol_hash=data["protocol_hash"],
            binding_plan_hash=data["binding_plan_hash"],
            subject=CodeQueryTypestateSubject.from_dict(data["subject"]),
            finding_kind=CodeQueryTypestateFindingKind.from_dict(data["finding_kind"]),
            certainty=CodeQueryTypestateCertainty(data["certainty"]),
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            path_proven=_strict_bool(data, "path_proven"),
            path_complete=_strict_bool(data, "path_complete"),
            analysis_complete=_strict_bool(data, "analysis_complete"),
            retained_witnesses=_strict_nonnegative_int(data, "retained_witnesses"),
            omitted_witnesses=_strict_nonnegative_int(data, "omitted_witnesses"),
            uncertainty=tuple(
                CodeQueryTypestateUncertainty(value)
                for value in _strict_list(data, "uncertainty", [])
            ),
            abstained=_strict_bool(data, "abstained", False),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        return (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[typestate finding; {self.certainty}; {self.protocol_ref}] "
            f"{self.finding_kind.render_text()}"
        )


class CodeQueryTypestateWitnessStepKindType(StrEnum):
    SEED = "seed"
    EDGE = "edge"
    END_SUMMARY_GAP = "end_summary_gap"


@dataclass(frozen=True)
class CodeQueryTypestateWitnessStepKind:
    type: CodeQueryTypestateWitnessStepKindType
    edge_kind: str | None = None
    return_kind: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryTypestateWitnessStepKind:
        kind = CodeQueryTypestateWitnessStepKindType(data["type"])
        if kind is CodeQueryTypestateWitnessStepKindType.EDGE:
            return cls(type=kind, edge_kind=data["edge_kind"])
        if kind is CodeQueryTypestateWitnessStepKindType.END_SUMMARY_GAP:
            return cls(type=kind, return_kind=data["return_kind"])
        return cls(type=kind)


@dataclass(frozen=True)
class CodeQueryTypestateWitnessStep:
    kind: CodeQueryTypestateWitnessStepKind
    source: CodeQuerySourceSite
    evidence: CodeQuerySemanticEvidence
    target: CodeQuerySourceSite | None = None
    origin: CodeQuerySourceSite | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryTypestateWitnessStep:
        return cls(
            kind=CodeQueryTypestateWitnessStepKind.from_dict(data["kind"]),
            source=CodeQuerySourceSite.from_dict(data["source"]),
            evidence=CodeQuerySemanticEvidence.from_dict(data["evidence"]),
            target=(
                CodeQuerySourceSite.from_dict(data["target"])
                if "target" in data
                else None
            ),
            origin=(
                CodeQuerySourceSite.from_dict(data["origin"])
                if "origin" in data
                else None
            ),
        )


@dataclass(frozen=True)
class CodeQueryTypestateWitness:
    id: str
    finding_id: str
    protocol_ref: str
    protocol_hash: str
    binding_plan_hash: str
    subject: CodeQueryTypestateSubject
    witness_index: int
    path: str
    language: str
    range: CodeQueryRange
    quality: CodeQuerySemanticEvidence
    steps: tuple[CodeQueryTypestateWitnessStep, ...]
    retained_bytes: int
    omitted_steps_lower_bound: int
    observed_state: str | None = None
    uncertainty: tuple[CodeQueryTypestateUncertainty, ...] = ()
    abstained: bool = False
    truncated: bool = False
    alternatives_truncated: bool = False
    retention_truncated: bool = False
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryTypestateWitness:
        return cls(
            id=data["id"],
            finding_id=data["finding_id"],
            protocol_ref=data["protocol_ref"],
            protocol_hash=data["protocol_hash"],
            binding_plan_hash=data["binding_plan_hash"],
            subject=CodeQueryTypestateSubject.from_dict(data["subject"]),
            witness_index=_strict_nonnegative_int(data, "witness_index"),
            observed_state=data.get("observed_state"),
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            quality=CodeQuerySemanticEvidence.from_dict(data["quality"]),
            uncertainty=tuple(
                CodeQueryTypestateUncertainty(value)
                for value in _strict_list(data, "uncertainty", [])
            ),
            abstained=_strict_bool(data, "abstained", False),
            steps=tuple(
                CodeQueryTypestateWitnessStep.from_dict(step)
                for step in _strict_list(data, "steps")
            ),
            retained_bytes=_strict_nonnegative_int(data, "retained_bytes"),
            truncated=_strict_bool(data, "truncated", False),
            omitted_steps_lower_bound=_strict_nonnegative_int(
                data, "omitted_steps_lower_bound"
            ),
            alternatives_truncated=_strict_bool(
                data, "alternatives_truncated", False
            ),
            retention_truncated=_strict_bool(data, "retention_truncated", False),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        suffix = "; truncated" if self.truncated else ""
        return (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[typestate witness; {len(self.steps)} steps{suffix}; {self.protocol_ref}]"
        )


class CodeQueryFlowReachability(StrEnum):
    REACHED = "reached"
    NOT_REACHED = "not_reached"
    INCONCLUSIVE = "inconclusive"


class CodeQueryFlowCertainty(StrEnum):
    EXACT = "exact"
    MAY = "may"


class CodeQueryFlowCompletion(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CANCELLED = "cancelled"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class CodeQueryFlowEvent:
    id: str
    site: CodeQueryFlowSymbolSite
    path: str
    range: CodeQueryRange
    phase: str
    ordinal: int
    carrier: CodeQueryFlowCarrierSymbol

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryFlowEvent:
        return cls(
            id=data["id"],
            site=CodeQueryFlowSymbolSite.from_dict(data["site"]),
            path=data["path"],
            range=CodeQueryRange.from_dict(data["range"]),
            phase=data["phase"],
            ordinal=_strict_nonnegative_int(data, "ordinal"),
            carrier=CodeQueryFlowCarrierSymbol.from_dict(data["carrier"]),
        )


CodeQueryFlowPortKind = Literal[
    "receiver", "parameter", "normal_return", "exceptional_return", "capture"
]


@dataclass(frozen=True)
class CodeQueryFlowDeclarationSegment:
    kind: str
    name: str | None
    start_byte: int
    end_byte: int
    occurrence: int
    sibling_ordinal: int

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryFlowDeclarationSegment:
        return cls(
            kind=data["kind"],
            name=data.get("name"),
            start_byte=_strict_nonnegative_int(data, "start_byte"),
            end_byte=_strict_nonnegative_int(data, "end_byte"),
            occurrence=_strict_nonnegative_int(data, "occurrence"),
            sibling_ordinal=_strict_nonnegative_int(data, "sibling_ordinal"),
        )


@dataclass(frozen=True)
class CodeQueryFlowSymbolSite:
    id: str
    path: str
    language: str
    declaration: tuple[CodeQueryFlowDeclarationSegment, ...]
    role: str
    start_byte: int
    end_byte: int
    occurrence: int
    range: CodeQueryRange

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryFlowSymbolSite:
        return cls(
            id=data["id"],
            path=data["path"],
            language=data["language"],
            declaration=tuple(
                CodeQueryFlowDeclarationSegment.from_dict(segment)
                for segment in _strict_list(data, "declaration")
            ),
            role=data["role"],
            start_byte=_strict_nonnegative_int(data, "start_byte"),
            end_byte=_strict_nonnegative_int(data, "end_byte"),
            occurrence=_strict_nonnegative_int(data, "occurrence"),
            range=CodeQueryRange.from_dict(data["range"]),
        )


@dataclass(frozen=True)
class CodeQueryFlowPortSymbol:
    kind: CodeQueryFlowPortKind
    ordinal: int | None = None
    slot: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryFlowPortSymbol:
        kind = data.get("kind")
        if kind == "parameter":
            return cls(kind=kind, ordinal=_strict_nonnegative_int(data, "ordinal"))
        if kind == "capture":
            return cls(kind=kind, slot=_strict_nonnegative_int(data, "slot"))
        if kind in {"receiver", "normal_return", "exceptional_return"}:
            return cls(kind=cast(CodeQueryFlowPortKind, kind))
        raise ValueError(f"unknown value-flow port kind: {kind!r}")


CodeQueryFlowSelectorKind = Literal["field", "exact_index", "any_index"]


@dataclass(frozen=True)
class CodeQueryFlowSelectorSymbol:
    kind: CodeQueryFlowSelectorKind
    field: CodeQueryFlowSymbolSite | None = None
    index: CodeQueryFlowCarrierSymbol | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryFlowSelectorSymbol:
        kind = data.get("kind")
        if kind == "field":
            return cls(kind=kind, field=CodeQueryFlowSymbolSite.from_dict(data["field"]))
        if kind == "exact_index":
            return cls(kind=kind, index=CodeQueryFlowCarrierSymbol.from_dict(data["index"]))
        if kind == "any_index":
            return cls(kind=kind)
        raise ValueError(f"unknown value-flow selector kind: {kind!r}")


CodeQueryFlowCarrierKind = Literal[
    "value", "port", "allocation", "call_result", "scoped_root", "location"
]


@dataclass(frozen=True)
class CodeQueryFlowCarrierSymbol:
    kind: CodeQueryFlowCarrierKind
    id: str
    site: CodeQueryFlowSymbolSite | None = None
    role: str | None = None
    ordinal: int | None = None
    procedure: CodeQueryFlowSymbolSite | None = None
    port: CodeQueryFlowPortSymbol | None = None
    call: CodeQueryFlowSymbolSite | None = None
    result: CodeQueryFlowCarrierSymbol | None = None
    callee: CodeQueryFlowSymbolSite | None = None
    root_kind: str | None = None
    root: CodeQueryFlowCarrierSymbol | None = None
    selectors: tuple[CodeQueryFlowSelectorSymbol, ...] = ()
    exact: bool | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryFlowCarrierSymbol:
        kind = data.get("kind")
        common = {"kind": kind, "id": data["id"]}
        if kind == "value":
            ordinal = data.get("ordinal")
            if ordinal is not None:
                ordinal = _strict_nonnegative_int(data, "ordinal")
            return cls(
                **common,
                site=CodeQueryFlowSymbolSite.from_dict(data["site"]),
                role=data["role"],
                ordinal=ordinal,
            )
        if kind == "port":
            return cls(
                **common,
                procedure=CodeQueryFlowSymbolSite.from_dict(data["procedure"]),
                port=CodeQueryFlowPortSymbol.from_dict(data["port"]),
            )
        if kind == "allocation":
            return cls(
                **common, site=CodeQueryFlowSymbolSite.from_dict(data["site"])
            )
        if kind == "call_result":
            return cls(
                **common,
                call=CodeQueryFlowSymbolSite.from_dict(data["call"]),
                result=cls.from_dict(data["result"]),
                callee=CodeQueryFlowSymbolSite.from_dict(data["callee"]),
            )
        if kind == "scoped_root":
            return cls(
                **common,
                root_kind=data["root_kind"],
                site=CodeQueryFlowSymbolSite.from_dict(data["site"]),
            )
        if kind == "location":
            return cls(
                **common,
                root=cls.from_dict(data["root"]),
                selectors=tuple(
                    CodeQueryFlowSelectorSymbol.from_dict(selector)
                    for selector in _strict_list(data, "selectors")
                ),
                exact=_strict_bool(data, "exact"),
            )
        raise ValueError(f"unknown value-flow carrier kind: {kind!r}")


CodeQueryFlowFactKind = Literal["zero", "carrier", "meeting"]


@dataclass(frozen=True)
class CodeQueryFlowFactSymbol:
    kind: CodeQueryFlowFactKind
    source: CodeQueryFlowEvent | None = None
    carrier: CodeQueryFlowCarrierSymbol | None = None
    sink: CodeQueryFlowEvent | None = None
    uncertain: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryFlowFactSymbol:
        kind = data.get("kind")
        if kind == "zero":
            return cls(kind=kind)
        if kind == "carrier":
            return cls(
                kind=kind,
                source=CodeQueryFlowEvent.from_dict(data["source"]),
                carrier=CodeQueryFlowCarrierSymbol.from_dict(data["carrier"]),
                uncertain=_strict_bool(data, "uncertain", False),
            )
        if kind == "meeting":
            return cls(
                kind=kind,
                source=CodeQueryFlowEvent.from_dict(data["source"]),
                sink=CodeQueryFlowEvent.from_dict(data["sink"]),
                uncertain=_strict_bool(data, "uncertain", False),
            )
        raise ValueError(f"unknown value-flow fact kind: {kind!r}")


@dataclass(frozen=True)
class CodeQueryFlowEndpoint:
    id: str
    plan_ref: str
    sink: CodeQueryFlowEvent
    reachability: CodeQueryFlowReachability
    must: str
    ambiguous: bool
    completion: CodeQueryFlowCompletion
    semantic_status: str
    solver_termination: str
    path: str
    language: str
    range: CodeQueryRange
    retained_witnesses: int
    omitted_witnesses: int
    source: CodeQueryFlowEvent | None = None
    certainty: CodeQueryFlowCertainty | None = None
    path_qualities: tuple[CodeQuerySemanticEvidence, ...] = ()
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryFlowEndpoint:
        certainty = data.get("certainty")
        return cls(
            id=data["id"],
            plan_ref=data["plan_ref"],
            source=(
                CodeQueryFlowEvent.from_dict(data["source"])
                if data.get("source") is not None
                else None
            ),
            sink=CodeQueryFlowEvent.from_dict(data["sink"]),
            reachability=CodeQueryFlowReachability(data["reachability"]),
            certainty=(
                CodeQueryFlowCertainty(certainty) if certainty is not None else None
            ),
            must=data["must"],
            ambiguous=_strict_bool(data, "ambiguous", False),
            completion=CodeQueryFlowCompletion(data["completion"]),
            semantic_status=data["semantic_status"],
            solver_termination=data["solver_termination"],
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            path_qualities=tuple(
                CodeQuerySemanticEvidence.from_dict(value)
                for value in _strict_list(data, "path_qualities", [])
            ),
            retained_witnesses=_strict_nonnegative_int(data, "retained_witnesses"),
            omitted_witnesses=_strict_nonnegative_int(data, "omitted_witnesses"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        certainty = self.certainty.value if self.certainty is not None else "n/a"
        return (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[flow endpoint; {self.reachability}; {certainty}; {self.completion}]"
        )


@dataclass(frozen=True)
class CodeQueryFlowWitnessStep:
    kind: CodeQueryTypestateWitnessStepKind
    source: CodeQuerySourceSite
    evidence: CodeQuerySemanticEvidence
    target: CodeQuerySourceSite | None = None
    origin: CodeQuerySourceSite | None = None
    boundary: str | None = None
    source_symbol: CodeQueryFlowSymbolSite | None = None
    target_symbol: CodeQueryFlowSymbolSite | None = None
    origin_symbol: CodeQueryFlowSymbolSite | None = None
    input: CodeQueryFlowFactSymbol | None = None
    output: CodeQueryFlowFactSymbol | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryFlowWitnessStep:
        return cls(
            kind=CodeQueryTypestateWitnessStepKind.from_dict(data["kind"]),
            source=CodeQuerySourceSite.from_dict(data["source"]),
            evidence=CodeQuerySemanticEvidence.from_dict(data["evidence"]),
            target=(
                CodeQuerySourceSite.from_dict(data["target"])
                if "target" in data
                else None
            ),
            origin=(
                CodeQuerySourceSite.from_dict(data["origin"])
                if "origin" in data
                else None
            ),
            boundary=data.get("boundary"),
            source_symbol=(
                CodeQueryFlowSymbolSite.from_dict(data["source_symbol"])
                if "source_symbol" in data
                else None
            ),
            target_symbol=(
                CodeQueryFlowSymbolSite.from_dict(data["target_symbol"])
                if "target_symbol" in data
                else None
            ),
            origin_symbol=(
                CodeQueryFlowSymbolSite.from_dict(data["origin_symbol"])
                if "origin_symbol" in data
                else None
            ),
            input=(
                CodeQueryFlowFactSymbol.from_dict(data["input"])
                if "input" in data
                else None
            ),
            output=(
                CodeQueryFlowFactSymbol.from_dict(data["output"])
                if "output" in data
                else None
            ),
        )


@dataclass(frozen=True)
class CodeQueryFlowWitness:
    id: str
    endpoint_id: str
    plan_ref: str
    witness_index: int
    path: str
    language: str
    range: CodeQueryRange
    quality: CodeQuerySemanticEvidence
    steps: tuple[CodeQueryFlowWitnessStep, ...]
    retained_bytes: int
    omitted_steps_lower_bound: int
    truncated: bool = False
    alternatives_truncated: bool = False
    retention_truncated: bool = False
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryFlowWitness:
        return cls(
            id=data["id"],
            endpoint_id=data["endpoint_id"],
            plan_ref=data["plan_ref"],
            witness_index=_strict_nonnegative_int(data, "witness_index"),
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            quality=CodeQuerySemanticEvidence.from_dict(data["quality"]),
            steps=tuple(
                CodeQueryFlowWitnessStep.from_dict(step)
                for step in _strict_list(data, "steps")
            ),
            retained_bytes=_strict_nonnegative_int(data, "retained_bytes"),
            omitted_steps_lower_bound=_strict_nonnegative_int(
                data, "omitted_steps_lower_bound"
            ),
            truncated=_strict_bool(data, "truncated", False),
            alternatives_truncated=_strict_bool(
                data, "alternatives_truncated", False
            ),
            retention_truncated=_strict_bool(data, "retention_truncated", False),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        suffix = "; truncated" if self.truncated else ""
        return (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[flow witness; {len(self.steps)} steps{suffix}; {self.plan_ref}]"
        )


@dataclass(frozen=True)
class CodeQueryTaintOrigin:
    id: str
    event_id: str
    labels: tuple[str, ...]
    site: CodeQuerySourceSite

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryTaintOrigin:
        return cls(
            id=data["id"],
            event_id=data["event_id"],
            labels=tuple(_strict_list(data, "labels")),
            site=CodeQuerySourceSite.from_dict(data["site"]),
        )


@dataclass(frozen=True)
class CodeQueryTaintWitness:
    id: str
    finding_id: str
    witness_index: int
    path: str
    language: str
    range: CodeQueryRange
    quality: CodeQuerySemanticEvidence
    steps: tuple[CodeQueryFlowWitnessStep, ...]
    retained_bytes: int
    omitted_steps_lower_bound: int
    truncated: bool = False
    alternatives_truncated: bool = False
    retention_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryTaintWitness:
        return cls(
            id=data["id"],
            finding_id=data["finding_id"],
            witness_index=_strict_nonnegative_int(data, "witness_index"),
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            quality=CodeQuerySemanticEvidence.from_dict(data["quality"]),
            steps=tuple(
                CodeQueryFlowWitnessStep.from_dict(step)
                for step in _strict_list(data, "steps")
            ),
            retained_bytes=_strict_nonnegative_int(data, "retained_bytes"),
            omitted_steps_lower_bound=_strict_nonnegative_int(
                data, "omitted_steps_lower_bound"
            ),
            truncated=_strict_bool(data, "truncated", False),
            alternatives_truncated=_strict_bool(
                data, "alternatives_truncated", False
            ),
            retention_truncated=_strict_bool(data, "retention_truncated", False),
        )


@dataclass(frozen=True)
class CodeQueryTaintFinding:
    id: str
    path: str
    language: str
    range: CodeQueryRange
    sink_event_id: str
    sink: CodeQuerySourceSite
    reached_labels: tuple[str, ...]
    origins: tuple[CodeQueryTaintOrigin, ...]
    witnesses: tuple[CodeQueryTaintWitness, ...]
    evidence: CodeQuerySemanticEvidence
    origins_truncated: bool = False
    witnesses_truncated: bool = False
    ambiguous: bool = False
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryTaintFinding:
        return cls(
            id=data["id"],
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            sink_event_id=data["sink_event_id"],
            sink=CodeQuerySourceSite.from_dict(data["sink"]),
            reached_labels=tuple(_strict_list(data, "reached_labels")),
            origins=tuple(
                CodeQueryTaintOrigin.from_dict(origin)
                for origin in _strict_list(data, "origins")
            ),
            witnesses=tuple(
                CodeQueryTaintWitness.from_dict(witness)
                for witness in _strict_list(data, "witnesses")
            ),
            evidence=CodeQuerySemanticEvidence.from_dict(data["evidence"]),
            origins_truncated=_strict_bool(data, "origins_truncated", False),
            witnesses_truncated=_strict_bool(data, "witnesses_truncated", False),
            ambiguous=_strict_bool(data, "ambiguous", False),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        return (
            f"{self.sink.path}:{self.sink.range.start_line}:"
            f"{self.sink.range.start_column} [taint finding; "
            f"{len(self.reached_labels)} labels; {len(self.origins)} origins]"
        )


@dataclass(frozen=True)
class CodeQueryFile:
    """One workspace file, with the package or module clause it belongs to.

    ``package_fq`` and ``package_syntactic`` appear and disappear together.
    ``package_syntactic`` is ``True`` when the language spells the package in
    the source and ``False`` when it is derived from the file's path; both
    being absent means no package could be named at all, which is not the same
    as "the file is in the root package".
    """

    path: str
    language: str
    package_fq: str | None = None
    package_syntactic: bool | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryFile:
        return cls(
            path=data["path"],
            language=data["language"],
            package_fq=data.get("package_fq"),
            package_syntactic=data.get("package_syntactic"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        header = f"{self.path} [file; {self.language}]"
        if self.package_fq is not None:
            origin = "syntactic" if self.package_syntactic else "path-derived"
            header += f" in {self.package_fq} ({origin})"
        return header


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


@dataclass(frozen=True)
class CodeQuerySourceSite:
    path: str
    range: CodeQueryRange

    @classmethod
    def from_dict(cls, data: dict) -> CodeQuerySourceSite:
        return cls(path=data["path"], range=CodeQueryRange.from_dict(data["range"]))


@dataclass(frozen=True)
class CodeQueryReceiverValue:
    receiver_value_kind: str
    declaration: CodeQueryDeclaration | None = None
    type_declaration: CodeQueryDeclaration | None = None
    allocation_site: CodeQuerySourceSite | None = None
    factory: CodeQueryDeclaration | None = None
    returned_value: CodeQueryReceiverValue | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryReceiverValue:
        return cls(
            receiver_value_kind=data["receiver_value_kind"],
            declaration=(
                CodeQueryDeclaration.from_dict(data["declaration"])
                if "declaration" in data
                else None
            ),
            type_declaration=(
                CodeQueryDeclaration.from_dict(data["type_declaration"])
                if "type_declaration" in data
                else None
            ),
            allocation_site=(
                CodeQuerySourceSite.from_dict(data["allocation_site"])
                if "allocation_site" in data
                else None
            ),
            factory=(
                CodeQueryDeclaration.from_dict(data["factory"])
                if "factory" in data
                else None
            ),
            returned_value=(
                CodeQueryReceiverValue.from_dict(data["returned_value"])
                if "returned_value" in data
                else None
            ),
        )

    def render_text(self) -> str:
        if self.receiver_value_kind == "allocation_site":
            assert self.type_declaration is not None
            assert self.allocation_site is not None
            site = self.allocation_site
            return (
                f"allocation {self.type_declaration.fq_name} at "
                f"{site.path}:{site.range.start_line}:{site.range.start_column}"
            )
        labels = {
            "instance_type": "instance",
            "class_or_static_object": "class/static",
            "module_or_export_object": "module/export",
            "current_receiver": "current receiver",
        }
        if self.receiver_value_kind in labels:
            assert self.declaration is not None
            return f"{labels[self.receiver_value_kind]} {self.declaration.fq_name}"
        if self.receiver_value_kind == "factory_return":
            assert self.factory is not None
            assert self.returned_value is not None
            return (
                f"factory {self.factory.fq_name} -> "
                f"{self.returned_value.render_text()}"
            )
        return self.receiver_value_kind


@dataclass(frozen=True)
class CodeQueryReceiverAnalysis:
    analysis_kind: str
    path: str
    language: str
    range: CodeQueryRange
    text: str
    input_kind: str
    outcome: str
    capture: str | None = None
    values: list[CodeQueryReceiverValue] = field(default_factory=list)
    member_targets: list[CodeQueryDeclaration] = field(default_factory=list)
    reason: str | None = None
    limit: str | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryReceiverAnalysis:
        return cls(
            analysis_kind=data["analysis_kind"],
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            text=data["text"],
            input_kind=data["input_kind"],
            outcome=data["outcome"],
            capture=data.get("capture"),
            values=[
                CodeQueryReceiverValue.from_dict(item)
                for item in data.get("values", [])
            ],
            member_targets=[
                CodeQueryDeclaration.from_dict(item)
                for item in data.get("member_targets", [])
            ],
            reason=data.get("reason"),
            limit=data.get("limit"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        lines = [
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[receiver analysis; {self.analysis_kind}; {self.outcome}] `{self.text}`"
        ]
        lines.extend(f"  value -> {value.render_text()}" for value in self.values)
        lines.extend(
            f"  member -> {target.fq_name}" for target in self.member_targets
        )
        if self.reason is not None:
            lines.append(f"  reason -> {self.reason}")
        if self.limit is not None:
            lines.append(f"  limit -> {self.limit}")
        return "\n".join(lines)


@dataclass(frozen=True)
class CodeQueryOccurrenceTarget:
    """What a reference-class occurrence resolves to.

    ``target_kind`` is always present: a non-reference row is ``none`` and a
    reference row never is, so an empty target is never ambiguous between
    "nothing to resolve" and "resolution was skipped".
    """

    target_kind: str
    units: list[CodeQueryDeclaration] = field(default_factory=list)
    name: str | None = None
    kind: str | None = None
    range: CodeQueryRange | None = None
    status: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryOccurrenceTarget:
        range_data = data.get("range")
        return cls(
            target_kind=data["target_kind"],
            units=[
                CodeQueryDeclaration.from_dict(item) for item in data.get("units", [])
            ],
            name=data.get("name"),
            kind=data.get("kind"),
            range=CodeQueryRange.from_dict(range_data) if range_data else None,
            status=data.get("status"),
        )

    def render_text(self) -> list[str]:
        if self.target_kind == "resolved":
            return [f"-> {unit.fq_name} [{unit.kind}] {unit.path}" for unit in self.units]
        if self.target_kind == "lexical":
            line = self.range.start_line if self.range else 0
            return [f"-> lexical binder `{self.name}` [{self.kind}] at line {line}"]
        if self.target_kind == "unresolved":
            return [f"-> unresolved ({self.status})"]
        return []


@dataclass(frozen=True)
class CodeQueryOccurrence:
    """One classified identifier position.

    ``ast_id`` is the content-scoped identity of the underlying AST node and is
    equal to the ``ast_id`` a structural capture over the same node reports.
    That string equality is the correlation join; do not compare ranges or
    spellings instead. ``id`` additionally distinguishes the role.
    """

    id: str
    ast_id: str
    path: str
    language: str
    occurrence_class: str
    role: str
    namespace: str
    range: CodeQueryRange
    start_byte: int
    end_byte: int
    raw_spelling: str
    target: CodeQueryOccurrenceTarget
    enclosing_symbol: str | None = None
    decoded_spelling: str | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryOccurrence:
        return cls(
            id=data["id"],
            ast_id=data["ast_id"],
            path=data["path"],
            language=data["language"],
            occurrence_class=data["class"],
            role=data["role"],
            namespace=data["namespace"],
            range=CodeQueryRange.from_dict(data["range"]),
            start_byte=data["start_byte"],
            end_byte=data["end_byte"],
            raw_spelling=data["raw_spelling"],
            target=CodeQueryOccurrenceTarget.from_dict(data["target"]),
            enclosing_symbol=data.get("enclosing_symbol"),
            decoded_spelling=data.get("decoded_spelling"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    @property
    def effective_spelling(self) -> str:
        """The spelling to compare against a declared name."""
        return self.decoded_spelling or self.raw_spelling

    def render_text(self) -> str:
        header = (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[occurrence; {self.occurrence_class}; {self.role}; {self.namespace}] "
            f"`{self.raw_spelling}`"
        )
        if self.decoded_spelling is not None:
            header += f" (decodes to `{self.decoded_spelling}`)"
        if self.enclosing_symbol is not None:
            header += f" in {self.enclosing_symbol}"
        return "\n".join([header, *(f"  {line}" for line in self.target.render_text())])


@dataclass(frozen=True)
class CodeQueryLexicalScope:
    """One lexical scope of a file.

    ``ast_id`` is absent for exactly one scope per file: the synthesized
    whole-file scope, which no grammar gives an AST node. Every other scope
    joins with a structural capture over the same node by ``ast_id`` equality.
    """

    id: str
    path: str
    language: str
    index: int
    range: CodeQueryRange
    start_byte: int
    end_byte: int
    ast_id: str | None = None
    kind: str | None = None
    parent_index: int | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryLexicalScope:
        return cls(
            id=data["id"],
            path=data["path"],
            language=data["language"],
            index=data["index"],
            range=CodeQueryRange.from_dict(data["range"]),
            start_byte=data["start_byte"],
            end_byte=data["end_byte"],
            ast_id=data.get("ast_id"),
            kind=data.get("kind"),
            parent_index=data.get("parent_index"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        header = (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[lexical_scope #{self.index}; {self.kind or 'file'}]"
        )
        if self.parent_index is not None:
            return f"{header}\n  inside scope #{self.parent_index}"
        return header


@dataclass(frozen=True)
class CodeQueryImportBinder:
    """What an import binder contributes, as far as the adapter can state it.

    ``target_segments`` is empty when the adapter records no parser-derived
    import path. That is a stated gap, not a claim that the import has no
    target.
    """

    local_name: str
    target_segments: list[str]
    wildcard: bool
    boundary: str
    alias: str | None = None
    wildcard_ambiguous: bool | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryImportBinder:
        return cls(
            local_name=data["local_name"],
            target_segments=list(data.get("target_segments", [])),
            wildcard=bool(data["wildcard"]),
            boundary=data["boundary"],
            alias=data.get("alias"),
            wildcard_ambiguous=data.get("wildcard_ambiguous"),
        )


@dataclass(frozen=True)
class CodeQueryBinding:
    """One name a lexical scope introduces.

    ``ast_id`` is absent when the binder's local name is not spelled by a
    classified token, which is how a wildcard import and an adapter without a
    structured import path surface. ``shadowed`` is ``True`` only for rows a
    ``reaching_binding`` step with ``include_shadowed`` emitted as losers.
    ``reached_from_ast_id`` is present exactly on rows a ``reaching_binding``
    step produced and names the occurrence the row is the reaching binding of,
    so a correlated consumer can join the answer back to its own capture.
    """

    id: str
    path: str
    language: str
    name: str
    kind: str
    hoisting: str
    namespace: str
    range: CodeQueryRange
    start_byte: int
    end_byte: int
    activation_start_byte: int
    activation_end_byte: int
    declaring_scope_index: int
    source_order: int
    visibility: str
    ast_id: str | None = None
    import_binder: CodeQueryImportBinder | None = None
    shadowed: bool = False
    reached_from_ast_id: str | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryBinding:
        import_data = data.get("import")
        return cls(
            id=data["id"],
            path=data["path"],
            language=data["language"],
            name=data["name"],
            kind=data["kind"],
            hoisting=data["hoisting"],
            namespace=data["namespace"],
            range=CodeQueryRange.from_dict(data["range"]),
            start_byte=data["start_byte"],
            end_byte=data["end_byte"],
            activation_start_byte=data["activation_start_byte"],
            activation_end_byte=data["activation_end_byte"],
            declaring_scope_index=data["declaring_scope_index"],
            source_order=data["source_order"],
            visibility=data["visibility"],
            ast_id=data.get("ast_id"),
            import_binder=(
                CodeQueryImportBinder.from_dict(import_data) if import_data else None
            ),
            shadowed=bool(data.get("shadowed", False)),
            reached_from_ast_id=data.get("reached_from_ast_id"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        suffix = " (shadowed)" if self.shadowed else ""
        header = (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[binding; {self.kind}; {self.hoisting}] `{self.name}`{suffix}"
        )
        detail = (
            f"  declared in scope #{self.declaring_scope_index}, "
            f"active over bytes {self.activation_start_byte}.."
            f"{self.activation_end_byte}"
        )
        return f"{header}\n{detail}"


@dataclass(frozen=True)
class CodeQueryCandidateRef:
    """What a resolution candidate points at.

    Two of the five shapes (``binding`` and ``external_route``) carry no
    workspace declaration, which is why ``candidate_target`` is partial by
    construction: it can answer only for ``unit`` candidates.
    """

    candidate_kind: str
    name: str
    unit: CodeQueryDeclaration | None = None
    kind: str | None = None
    range: CodeQueryRange | None = None
    path: str | None = None
    ast_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryCandidateRef:
        candidate_kind = data["candidate_kind"]
        unit = data.get("unit")
        range_data = data.get("range")
        return cls(
            candidate_kind=candidate_kind,
            name=(
                CodeQueryDeclaration.from_dict(unit).fq_name
                if unit
                else data.get("name", "")
            ),
            unit=CodeQueryDeclaration.from_dict(unit) if unit else None,
            kind=data.get("kind"),
            range=CodeQueryRange.from_dict(range_data) if range_data else None,
            path=data.get("path"),
            ast_id=data.get("ast_id"),
        )


@dataclass(frozen=True)
class CodeQueryResolutionCandidate:
    """One candidate the resolver considered for one reference.

    ``tier`` is ``None`` when the recording seam could not name a precedence
    tier. That is *unattributed*, never "the weakest tier": a policy comparing
    tiers must treat it as inconclusive. ``trace_completeness`` of
    ``selection_only`` likewise means an absent rejection row says nothing.
    """

    id: str
    ast_id: str
    path: str
    language: str
    range: CodeQueryRange
    start_byte: int
    end_byte: int
    ordinal: int
    outcome: str
    boundary: str
    visibility: str
    trace_completeness: str
    candidate: CodeQueryCandidateRef
    tier: str | None = None
    rejection_reason: str | None = None
    external_target: str | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryResolutionCandidate:
        return cls(
            id=data["id"],
            ast_id=data["ast_id"],
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            start_byte=data["start_byte"],
            end_byte=data["end_byte"],
            ordinal=data["ordinal"],
            outcome=data["outcome"],
            boundary=data["boundary"],
            visibility=data["visibility"],
            trace_completeness=data["trace_completeness"],
            candidate=CodeQueryCandidateRef.from_dict(data["candidate"]),
            tier=data.get("tier"),
            rejection_reason=data.get("rejection_reason"),
            external_target=data.get("external_target"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        header = (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[resolution_candidate; {self.tier or 'unattributed'}; {self.outcome}] "
            f"{self.candidate.candidate_kind} `{self.candidate.name}`"
        )
        lines = [header]
        if self.rejection_reason is not None:
            lines.append(f"  rejected: {self.rejection_reason}")
        lines.append(
            f"  boundary {self.boundary}, trace {self.trace_completeness}"
        )
        return "\n".join(lines)


@dataclass(frozen=True)
class CodeQueryReferenceEdge:
    """One canonical reference edge from a use site to a target declaration.

    The row shape is the same whichever producer derived it, and
    ``provenance`` says which one did: ``forward`` for the resolver's own
    resolved targets of one token, ``inverse`` for the sites the usage index
    enumerates for one declaration. Every classification a parity comparison
    depends on is an explicit field, never inferred from counts.

    ``ast_id`` is absent when the producer cannot address the site token as a
    facts-arena node; where it is present, string equality with a capture's or
    an occurrence's ``ast_id`` is the correlation join.
    ``enclosing_declaration`` is absent when no indexed declaration encloses
    the site, and ``reference_kind`` is absent when the producer classified no
    structured kind -- neither absence means the edge is weaker.
    ``generation`` is the workspace generation the edge was derived in; a
    comparison must refuse to relate rows from two generations.

    ``provenance_direction`` is the wire's ``edge_provenance`` key: the
    producer that derived the row, renamed on the wire so the result item's
    branch-trace ``provenance`` list cannot shadow it under full detail.
    """

    id: str
    path: str
    language: str
    range: CodeQueryRange
    start_byte: int
    end_byte: int
    target: CodeQueryDeclaration
    proof: str
    usage_kind: str
    site_class: str
    owner_relation: str
    provenance_direction: str
    generation: int
    ast_id: str | None = None
    enclosing_declaration: CodeQueryDeclaration | None = None
    reference_kind: str | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryReferenceEdge:
        return cls(
            id=data["id"],
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            start_byte=data["start_byte"],
            end_byte=data["end_byte"],
            target=CodeQueryDeclaration.from_dict(data["target"]),
            proof=data["proof"],
            usage_kind=data["usage_kind"],
            site_class=data["site_class"],
            owner_relation=data["owner_relation"],
            provenance_direction=data["edge_provenance"],
            generation=int(data["generation"]),
            ast_id=data.get("ast_id"),
            enclosing_declaration=CodeQueryDeclaration.from_dict(
                data["enclosing_declaration"]
            )
            if "enclosing_declaration" in data
            else None,
            reference_kind=data.get("reference_kind"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        header = (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[reference_edge; {self.provenance_direction or 'unstated'}; {self.proof}; "
            f"{self.usage_kind}] -> {self.target.fq_name} [{self.target.kind}]"
        )
        detail = (
            f"  kind {self.reference_kind or 'unclassified'}, "
            f"site {self.site_class}, relation {self.owner_relation}, "
            f"generation {self.generation}"
        )
        return f"{header}\n{detail}"


CodeQueryResultItem = (
    CodeQueryMatch
    | CodeQueryDeclaration
    | CodeQueryProcedure
    | CodeQueryProgramPoint
    | CodeQueryControlEdge
    | CodeQueryTypestateFinding
    | CodeQueryTypestateWitness
    | CodeQueryFlowEndpoint
    | CodeQueryFlowWitness
    | CodeQueryTaintFinding
    | CodeQueryFile
    | CodeQueryReferenceSite
    | CodeQueryCallSite
    | CodeQueryExpressionSite
    | CodeQueryReceiverAnalysis
    | CodeQueryOccurrence
    | CodeQueryLexicalScope
    | CodeQueryBinding
    | CodeQueryResolutionCandidate
    | CodeQueryReferenceEdge
)


@dataclass(frozen=True)
class CodeQueryQualifiedPath:
    """One qualified-path chain: a linear sequence of segments (#1475).

    ``ast_id`` is the terminal segment token's AST identity, the equijoin key
    with captures and occurrence rows over the same token.
    """

    id: str
    ast_id: str
    path: str
    language: str
    range: CodeQueryRange
    start_byte: int
    end_byte: int
    segment_count: int
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryQualifiedPath:
        return cls(
            id=data["id"],
            ast_id=data["ast_id"],
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            start_byte=data["start_byte"],
            end_byte=data["end_byte"],
            segment_count=data["segment_count"],
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        return (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[qualified_path; {self.segment_count} segments]"
        )


@dataclass(frozen=True)
class CodeQueryPathSegment:
    """One segment of one qualified path (#1475).

    ``ast_id`` is absent for a segment whose token is not a fact (Rust's
    ``crate``/``self``/``super`` path keywords): its position in the path is
    real, its structural identity is genuinely absent. ``namespace`` is absent
    when neither the adapter's classification nor resolution states one --
    never a guessed value. ``resolution_status`` is absent when resolution was
    not derived, which is different from "nothing considered".
    """

    id: str
    path: str
    language: str
    range: CodeQueryRange
    start_byte: int
    end_byte: int
    path_ast_id: str
    ordinal: int
    text: str
    ast_id: str | None = None
    namespace: str | None = None
    generic_arity: int | None = None
    resolution_status: str | None = None
    target_count: int | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryPathSegment:
        return cls(
            id=data["id"],
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            start_byte=data["start_byte"],
            end_byte=data["end_byte"],
            path_ast_id=data["path_ast_id"],
            ordinal=data["ordinal"],
            text=data["text"],
            ast_id=data.get("ast_id"),
            namespace=data.get("namespace"),
            generic_arity=data.get("generic_arity"),
            resolution_status=data.get("resolution_status"),
            target_count=data.get("target_count"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        header = (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[path_segment #{self.ordinal}] `{self.text}`"
        )
        details = []
        if self.namespace is not None:
            details.append(f"namespace {self.namespace}")
        if self.generic_arity is not None:
            details.append(f"{self.generic_arity} generic args")
        if self.resolution_status is not None:
            suffix = ""
            if self.target_count:
                suffix = f" ({self.target_count} target(s))"
            details.append(f"resolves: {self.resolution_status}{suffix}")
        if details:
            return "\n".join([header, *(f"  {line}" for line in details)])
        return header


CodeQueryResultItem = (
    CodeQueryMatch
    | CodeQueryDeclaration
    | CodeQueryProcedure
    | CodeQueryProgramPoint
    | CodeQueryControlEdge
    | CodeQueryTypestateFinding
    | CodeQueryTypestateWitness
    | CodeQueryFlowEndpoint
    | CodeQueryFlowWitness
    | CodeQueryTaintFinding
    | CodeQueryFile
    | CodeQueryReferenceSite
    | CodeQueryCallSite
    | CodeQueryExpressionSite
    | CodeQueryReceiverAnalysis
    | CodeQueryOccurrence
    | CodeQueryLexicalScope
    | CodeQueryBinding
    | CodeQueryResolutionCandidate
    | CodeQueryQualifiedPath
    | CodeQueryPathSegment
)


@dataclass(frozen=True)
class CodeQueryGeneratedDeclaration:
    """One declaration a generation site materialized, with the literal
    naming argument that produced it."""

    fq_name: str
    argument_start_byte: int
    argument_end_byte: int
    argument_range: CodeQueryRange

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryGeneratedDeclaration:
        return cls(
            fq_name=data["fq_name"],
            argument_start_byte=data["argument_start_byte"],
            argument_end_byte=data["argument_end_byte"],
            argument_range=CodeQueryRange.from_dict(data["argument_range"]),
        )


@dataclass(frozen=True)
class CodeQueryGenerationSite:
    """One construct that materializes declarations.

    ``input`` is ``literal`` when ``generated`` is the exact set, and
    ``dynamic`` when the site generates declarations the analyzer cannot
    name, so the set is explicitly not the whole answer.
    """

    id: str
    path: str
    language: str
    range: CodeQueryRange
    start_byte: int
    end_byte: int
    kind: str
    input: str
    generated_count: int
    generated: list[CodeQueryGeneratedDeclaration]
    ast_id: str | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryGenerationSite:
        return cls(
            id=data["id"],
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            start_byte=data["start_byte"],
            end_byte=data["end_byte"],
            kind=data["kind"],
            input=data["input"],
            generated_count=data["generated_count"],
            generated=[
                CodeQueryGeneratedDeclaration.from_dict(entry)
                for entry in data.get("generated", [])
            ],
            ast_id=data.get("ast_id"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        header = (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[generation_site {self.kind}; {self.input}] "
            f"generates {self.generated_count} declaration(s)"
        )
        lines = [header]
        lines.extend(f"  -> {entry.fq_name}" for entry in self.generated)
        return "\n".join(lines)


@dataclass(frozen=True)
class CodeQueryExport:
    """One export declaration."""

    id: str
    path: str
    language: str
    range: CodeQueryRange
    start_byte: int
    end_byte: int
    form: str
    exported_name: str
    ast_id: str | None = None
    target_fq_name: str | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryExport:
        return cls(
            id=data["id"],
            path=data["path"],
            language=data["language"],
            range=CodeQueryRange.from_dict(data["range"]),
            start_byte=data["start_byte"],
            end_byte=data["end_byte"],
            form=data["form"],
            exported_name=data["exported_name"],
            ast_id=data.get("ast_id"),
            target_fq_name=data.get("target_fq_name"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        header = (
            f"{self.path}:{self.range.start_line}:{self.range.start_column} "
            f"[export {self.form}] {self.exported_name}"
        )
        if self.target_fq_name is not None:
            return f"{header} -> {self.target_fq_name}"
        return header


@dataclass(frozen=True)
class CodeQueryDeclarationState:
    """The state of one declaration: where it came from and what it must not
    be mistaken for."""

    id: str
    path: str
    language: str
    fq_name: str
    unit_kind: str
    origin: str
    declaration_only: bool
    config_gated: bool
    ast_id: str | None = None
    range: CodeQueryRange | None = None
    start_byte: int | None = None
    end_byte: int | None = None
    provenance: list[CodeQueryProvenance] = field(default_factory=list)
    provenance_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> CodeQueryDeclarationState:
        range_data = data.get("range")
        return cls(
            id=data["id"],
            path=data["path"],
            language=data["language"],
            fq_name=data["fq_name"],
            unit_kind=data["unit_kind"],
            origin=data["origin"],
            declaration_only=bool(data["declaration_only"]),
            config_gated=bool(data["config_gated"]),
            ast_id=data.get("ast_id"),
            range=CodeQueryRange.from_dict(range_data) if range_data else None,
            start_byte=data.get("start_byte"),
            end_byte=data.get("end_byte"),
            provenance=_query_provenance(data),
            provenance_truncated=bool(data.get("provenance_truncated", False)),
        )

    def render_text(self) -> str:
        header = (
            f"{self.path} [declaration_state {self.origin}] "
            f"{self.fq_name} ({self.unit_kind})"
        )
        flags = []
        if self.declaration_only:
            flags.append("declaration-only")
        if self.config_gated:
            flags.append("config-gated")
        if flags:
            return f"{header} {' '.join(flags)}"
        return header


def _code_query_result_item(data: dict) -> CodeQueryResultItem:
    result_type = data.get("result_type")
    if result_type == "structural_match":
        return CodeQueryMatch.from_dict(data)
    if result_type == "declaration":
        return CodeQueryDeclaration.from_dict(data)
    if result_type == "procedure":
        return CodeQueryProcedure.from_dict(data)
    if result_type == "program_point":
        return CodeQueryProgramPoint.from_dict(data)
    if result_type == "control_edge":
        return CodeQueryControlEdge.from_dict(data)
    if result_type == "typestate_finding":
        return CodeQueryTypestateFinding.from_dict(data)
    if result_type == "typestate_witness":
        return CodeQueryTypestateWitness.from_dict(data)
    if result_type == "flow_endpoint":
        return CodeQueryFlowEndpoint.from_dict(data)
    if result_type == "flow_witness":
        return CodeQueryFlowWitness.from_dict(data)
    if result_type == "taint_finding":
        return CodeQueryTaintFinding.from_dict(data)
    if result_type == "file":
        return CodeQueryFile.from_dict(data)
    if result_type == "reference_site":
        return CodeQueryReferenceSite.from_dict(data)
    if result_type == "call_site":
        return CodeQueryCallSite.from_dict(data)
    if result_type == "expression_site":
        return CodeQueryExpressionSite.from_dict(data)
    if result_type == "receiver_analysis":
        return CodeQueryReceiverAnalysis.from_dict(data)
    if result_type == "occurrence":
        return CodeQueryOccurrence.from_dict(data)
    if result_type == "lexical_scope":
        return CodeQueryLexicalScope.from_dict(data)
    if result_type == "binding":
        return CodeQueryBinding.from_dict(data)
    if result_type == "resolution_candidate":
        return CodeQueryResolutionCandidate.from_dict(data)
    if result_type == "generation_site":
        return CodeQueryGenerationSite.from_dict(data)
    if result_type == "export":
        return CodeQueryExport.from_dict(data)
    if result_type == "declaration_state":
        return CodeQueryDeclarationState.from_dict(data)
    if result_type == "reference_edge":
        return CodeQueryReferenceEdge.from_dict(data)
    if result_type == "qualified_path":
        return CodeQueryQualifiedPath.from_dict(data)
    if result_type == "path_segment":
        return CodeQueryPathSegment.from_dict(data)
    raise ValueError(f"unknown code query result_type: {result_type!r}")


class CodeQueryDiagnosticCode(StrEnum):
    INVALID_PLAN = "invalid_plan"
    CANCELLED = "cancelled"
    UNSUPPORTED_STRUCTURAL_FEATURE = "unsupported_structural_feature"
    MISSING_STRUCTURAL_ADAPTER = "missing_structural_adapter"
    UNSUPPORTED_IMPORT_ANALYSIS = "unsupported_import_analysis"
    SEMANTIC_RESULTS_OMITTED = "semantic_results_omitted"
    SEMANTIC_WORKSPACE_REQUIRED = "semantic_workspace_required"
    NO_ENCLOSING_PROCEDURE = "no_enclosing_procedure"
    SEMANTIC_CAPABILITY_UNSUPPORTED = "semantic_capability_unsupported"
    SEMANTIC_ANALYSIS_PARTIAL = "semantic_analysis_partial"
    SEMANTIC_BUDGET_EXHAUSTED = "semantic_budget_exhausted"
    SEMANTIC_PROVIDER_FAILED = "semantic_provider_failed"
    UNRESOLVED_PROTOCOL_REFERENCE = "unresolved_protocol_reference"
    TYPESTATE_REGISTRATION_STALE = "typestate_registration_stale"
    TYPESTATE_HANDLE_STALE = "typestate_handle_stale"
    TYPESTATE_ROOT_MISMATCH = "typestate_root_mismatch"
    TYPESTATE_CAPABILITY_UNSUPPORTED = "typestate_capability_unsupported"
    TYPESTATE_ANALYSIS_PARTIAL = "typestate_analysis_partial"
    TYPESTATE_PROVIDER_FAILED = "typestate_provider_failed"
    TYPESTATE_SOLVER_BUDGET_EXHAUSTED = "typestate_solver_budget_exhausted"
    TYPESTATE_FINDING_BUDGET_EXHAUSTED = "typestate_finding_budget_exhausted"
    TYPESTATE_WITNESS_TRUNCATED = "typestate_witness_truncated"
    UNRESOLVED_VALUE_FLOW_PLAN_REFERENCE = "unresolved_value_flow_plan_reference"
    VALUE_FLOW_REGISTRATION_STALE = "value_flow_registration_stale"
    VALUE_FLOW_HANDLE_STALE = "value_flow_handle_stale"
    VALUE_FLOW_ROOT_MISMATCH = "value_flow_root_mismatch"
    VALUE_FLOW_CAPABILITY_UNSUPPORTED = "value_flow_capability_unsupported"
    VALUE_FLOW_ANALYSIS_PARTIAL = "value_flow_analysis_partial"
    VALUE_FLOW_PROVIDER_FAILED = "value_flow_provider_failed"
    VALUE_FLOW_SOLVER_BUDGET_EXHAUSTED = "value_flow_solver_budget_exhausted"
    VALUE_FLOW_WITNESS_TRUNCATED = "value_flow_witness_truncated"
    RECEIVER_ANALYSIS_PARTIAL = "receiver_analysis_partial"
    RECEIVER_ANALYSIS_FAILED = "receiver_analysis_failed"
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
    OCCURRENCE_ROLE_UNSUPPORTED = "occurrence_role_unsupported"
    OCCURRENCE_RESOLUTION_INCOMPLETE = "occurrence_resolution_incomplete"
    OCCURRENCE_ROW_BUDGET_EXHAUSTED = "occurrence_row_budget_exhausted"
    ENVIRONMENT_AXIS_UNSUPPORTED = "environment_axis_unsupported"
    MATERIALIZATION_AXIS_UNSUPPORTED = "materialization_axis_unsupported"
    MATERIALIZATION_DERIVATION_INCOMPLETE = "materialization_derivation_incomplete"
    MATERIALIZATION_ROW_BUDGET_EXHAUSTED = "materialization_row_budget_exhausted"
    ENVIRONMENT_DERIVATION_INCOMPLETE = "environment_derivation_incomplete"
    ENVIRONMENT_ROW_BUDGET_EXHAUSTED = "environment_row_budget_exhausted"
    RESOLUTION_TRACE_INCOMPLETE = "resolution_trace_incomplete"
    EDGE_AXIS_UNSUPPORTED = "edge_axis_unsupported"
    EDGE_DERIVATION_INCOMPLETE = "edge_derivation_incomplete"
    IDENTITY_AXIS_UNSUPPORTED = "identity_axis_unsupported"
    PATH_DERIVATION_INCOMPLETE = "path_derivation_incomplete"
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


def _extra_fields(data: dict[str, Any], known: set[str]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if key not in known}


def _optional_int(data: dict[str, Any], key: str) -> int | None:
    value = data.get(key)
    return int(value) if value is not None else None


@dataclass(frozen=True)
class CodeQueryParsedQuery:
    """The normalized query accepted by the planner.

    ``source_kind`` and ``source`` preserve the typed query-plan root while the
    common root controls and structural seed scope remain directly accessible.
    ``extra`` intentionally retains future normalized fields without making the
    top-level explain response untyped.
    """

    schema_version: int | None
    source_kind: str | None
    source: Any | None
    steps: list[dict[str, Any]] = field(default_factory=list)
    where: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    inside: dict[str, Any] | None = None
    inside_decl: dict[str, Any] | None = None
    not_inside: dict[str, Any] | None = None
    limit: int | None = None
    result_detail: str | None = None
    execution_mode: CodeQueryExecutionMode | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryParsedQuery:
        source_kind = next(
            (
                candidate
                for candidate in ("match", "union", "intersect", "except")
                if candidate in data
            ),
            data.get("source_kind"),
        )
        source = data.get(source_kind) if source_kind is not None else data.get("source")
        known = {
            "schema_version",
            "source_kind",
            "source",
            "match",
            "union",
            "intersect",
            "except",
            "steps",
            "where",
            "languages",
            "inside",
            "inside_decl",
            "not_inside",
            "limit",
            "result_detail",
            "execution_mode",
        }
        return cls(
            schema_version=_optional_int(data, "schema_version"),
            source_kind=str(source_kind) if source_kind is not None else None,
            source=source,
            steps=[dict(step) for step in data.get("steps", [])],
            where=[str(path) for path in data.get("where", [])],
            languages=[str(language) for language in data.get("languages", [])],
            inside=dict(data["inside"]) if data.get("inside") is not None else None,
            inside_decl=(
                dict(data["inside_decl"])
                if data.get("inside_decl") is not None
                else None
            ),
            not_inside=(
                dict(data["not_inside"])
                if data.get("not_inside") is not None
                else None
            ),
            limit=_optional_int(data, "limit"),
            result_detail=data.get("result_detail"),
            execution_mode=_code_query_execution_mode(data.get("execution_mode")),
            extra=_extra_fields(data, known),
        )


@dataclass(frozen=True)
class CodeQueryLogicalOperation:
    kind: CodeQueryLogicalOperationKind
    seed: CodeQueryParsedQuery | None = None
    step: dict[str, Any] | None = None
    set_operator: str | None = None
    count: int | None = None
    final_in_authored_suffix: bool | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryLogicalOperation:
        kind = CodeQueryLogicalOperationKind(data["kind"])
        seed = data.get("seed")
        step = data.get("step")
        known = {
            "kind",
            "seed",
            "step",
            "op",
            "count",
            "final_in_authored_suffix",
        }
        return cls(
            kind=kind,
            seed=(
                CodeQueryParsedQuery.from_dict(dict(seed))
                if isinstance(seed, dict)
                else None
            ),
            step=dict(step) if isinstance(step, dict) else None,
            set_operator=str(data["op"]) if data.get("op") is not None else None,
            count=_optional_int(data, "count"),
            final_in_authored_suffix=(
                bool(data["final_in_authored_suffix"])
                if data.get("final_in_authored_suffix") is not None
                else None
            ),
            extra=_extra_fields(data, known),
        )


class CodeQueryLogicalOperationKind(StrEnum):
    SEED = "seed"
    STEP = "step"
    SET = "set"
    LIMIT = "limit"


@dataclass(frozen=True)
class CodeQueryLogicalNode:
    id: int
    operation: CodeQueryLogicalOperation
    output_kind: str
    dependencies: list[int] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryLogicalNode:
        return cls(
            id=int(data["id"]),
            operation=CodeQueryLogicalOperation.from_dict(data["operation"]),
            output_kind=str(data["output_kind"]),
            dependencies=[int(node) for node in data.get("dependencies", [])],
        )


@dataclass(frozen=True)
class CodeQueryLogicalPlan:
    root: int
    nodes: list[CodeQueryLogicalNode]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryLogicalPlan:
        return cls(
            root=int(data["root"]),
            nodes=[
                CodeQueryLogicalNode.from_dict(node)
                for node in data.get("nodes", [])
            ],
        )


@dataclass(frozen=True)
class CodeQuerySemanticRequest:
    procedures: bool
    program_points: bool
    control_edges: bool
    typestate: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQuerySemanticRequest:
        return cls(
            procedures=bool(data["procedures"]),
            program_points=bool(data["program_points"]),
            control_edges=bool(data["control_edges"]),
            typestate=bool(data.get("typestate", False)),
        )


@dataclass(frozen=True)
class CodeQueryPhysicalNode:
    id: int
    logical_node: int
    operator: CodeQueryPhysicalOperator
    output_kind: str
    dependencies: list[int] = field(default_factory=list)
    semantic_request: CodeQuerySemanticRequest | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryPhysicalNode:
        known = {
            "id",
            "logical_node",
            "operator",
            "output_kind",
            "dependencies",
            "semantic_request",
        }
        return cls(
            id=int(data["id"]),
            logical_node=int(data["logical_node"]),
            operator=CodeQueryPhysicalOperator(data["operator"]),
            output_kind=str(data["output_kind"]),
            dependencies=[int(node) for node in data.get("dependencies", [])],
            semantic_request=(
                CodeQuerySemanticRequest.from_dict(data["semantic_request"])
                if data.get("semantic_request") is not None
                else None
            ),
            extra=_extra_fields(data, known),
        )


class CodeQueryPhysicalOperator(StrEnum):
    SEED_SCAN = "seed_scan"
    PIPELINE_STEP = "pipeline_step"
    SEQUENTIAL_UNION = "sequential_union"
    PARALLEL_UNION = "parallel_union"
    SEQUENTIAL_INTERSECTION = "sequential_intersection"
    SEQUENTIAL_EXCEPT = "sequential_except"
    LIMIT = "limit"


@dataclass(frozen=True)
class CodeQueryPhysicalPlan:
    root: int
    nodes: list[CodeQueryPhysicalNode]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryPhysicalPlan:
        return cls(
            root=int(data["root"]),
            nodes=[
                CodeQueryPhysicalNode.from_dict(node)
                for node in data.get("nodes", [])
            ],
        )


@dataclass(frozen=True)
class CodeQueryExplainScheduling:
    policy: CodeQuerySchedulingPolicy
    selected: CodeQuerySelectedScheduling
    max_concurrency: int
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryExplainScheduling:
        known = {"policy", "selected", "max_concurrency"}
        return cls(
            policy=CodeQuerySchedulingPolicy(data["policy"]),
            selected=CodeQuerySelectedScheduling(data["selected"]),
            max_concurrency=int(data["max_concurrency"]),
            extra=_extra_fields(data, known),
        )


class CodeQuerySchedulingPolicy(StrEnum):
    AUTO = "auto"


class CodeQuerySelectedScheduling(StrEnum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"


@dataclass(frozen=True)
class CodeQueryExplain:
    FORMAT: ClassVar[str] = "bifrost_code_query_explain/v1"

    format: str
    query_schema_version: int
    parsed_query: CodeQueryParsedQuery
    logical_plan: CodeQueryLogicalPlan
    physical_plan: CodeQueryPhysicalPlan
    scheduling: CodeQueryExplainScheduling
    rendered_text: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(
        cls, data: dict[str, Any], rendered_text: str | None = None
    ) -> CodeQueryExplain:
        if data.get("format") != cls.FORMAT:
            raise ValueError(f"unsupported code-query explain format: {data.get('format')!r}")
        known = {
            "format",
            "query_schema_version",
            "parsed_query",
            "logical_plan",
            "physical_plan",
            "scheduling",
        }
        return cls(
            format=cls.FORMAT,
            query_schema_version=int(data["query_schema_version"]),
            parsed_query=CodeQueryParsedQuery.from_dict(data["parsed_query"]),
            logical_plan=CodeQueryLogicalPlan.from_dict(data["logical_plan"]),
            physical_plan=CodeQueryPhysicalPlan.from_dict(data["physical_plan"]),
            scheduling=CodeQueryExplainScheduling.from_dict(data["scheduling"]),
            rendered_text=rendered_text,
            extra=_extra_fields(data, known),
        )

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        return (
            f"Code query plan: {len(self.logical_plan.nodes)} logical node(s), "
            f"{len(self.physical_plan.nodes)} physical node(s); "
            f"selected {self.scheduling.selected}."
        )


@dataclass(frozen=True)
class CodeQueryProfileTimings:
    planning: int
    execution: int
    rendering: int
    total: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryProfileTimings:
        return cls(
            planning=int(data.get("planning", 0)),
            execution=int(data.get("execution", 0)),
            rendering=int(data.get("rendering", 0)),
            total=int(data.get("total", 0)),
        )


@dataclass(frozen=True)
class CodeQueryTypestateWork:
    solves: int = 0
    cache_hits: int = 0
    summary_hits: int = 0
    summary_misses: int = 0
    summary_rejections: int = 0
    summary_evictions: int = 0
    summary_recomputations: int = 0
    reached_rows: int = 0
    findings: int = 0
    omitted_findings: int = 0
    witnesses: int = 0
    omitted_witnesses: int = 0
    witness_steps: int = 0
    witness_bytes: int = 0
    fixed_point_solves: int = 0
    cancelled_solves: int = 0
    budget_exhausted_solves: int = 0
    failed_solves: int = 0
    finding_budget_exhausted: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryTypestateWork:
        return cls(
            solves=int(data.get("solves", 0)),
            cache_hits=int(data.get("cache_hits", 0)),
            summary_hits=int(data.get("summary_hits", 0)),
            summary_misses=int(data.get("summary_misses", 0)),
            summary_rejections=int(data.get("summary_rejections", 0)),
            summary_evictions=int(data.get("summary_evictions", 0)),
            summary_recomputations=int(data.get("summary_recomputations", 0)),
            reached_rows=int(data.get("reached_rows", 0)),
            findings=int(data.get("findings", 0)),
            omitted_findings=int(data.get("omitted_findings", 0)),
            witnesses=int(data.get("witnesses", 0)),
            omitted_witnesses=int(data.get("omitted_witnesses", 0)),
            witness_steps=int(data.get("witness_steps", 0)),
            witness_bytes=int(data.get("witness_bytes", 0)),
            fixed_point_solves=int(data.get("fixed_point_solves", 0)),
            cancelled_solves=int(data.get("cancelled_solves", 0)),
            budget_exhausted_solves=int(data.get("budget_exhausted_solves", 0)),
            failed_solves=int(data.get("failed_solves", 0)),
            finding_budget_exhausted=bool(data.get("finding_budget_exhausted", False)),
        )


@dataclass(frozen=True)
class CodeQueryValueFlowWork:
    solves: int = 0
    cache_hits: int = 0
    reached_rows: int = 0
    meetings: int = 0
    sink_outcomes: int = 0
    omitted_endpoints: int = 0
    witnesses: int = 0
    omitted_witnesses: int = 0
    witness_expansions: int = 0
    witness_steps: int = 0
    witness_bytes: int = 0
    fixed_point_solves: int = 0
    cancelled_solves: int = 0
    budget_exhausted_solves: int = 0
    failed_solves: int = 0
    endpoint_truncated: bool = False
    witness_truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryValueFlowWork:
        numeric = {
            "solves",
            "cache_hits",
            "reached_rows",
            "meetings",
            "sink_outcomes",
            "omitted_endpoints",
            "witnesses",
            "omitted_witnesses",
            "witness_expansions",
            "witness_steps",
            "witness_bytes",
            "fixed_point_solves",
            "cancelled_solves",
            "budget_exhausted_solves",
            "failed_solves",
        }
        return cls(
            **{key: int(data.get(key, 0)) for key in numeric},
            endpoint_truncated=bool(data.get("endpoint_truncated", False)),
            witness_truncated=bool(data.get("witness_truncated", False)),
        )


@dataclass(frozen=True)
class CodeQuerySemanticWork:
    materialization_attempts: int = 0
    unique_materialized_files: int = 0
    request_cache_hits: int = 0
    source_bytes: int = 0
    procedures: int = 0
    program_points: int = 0
    control_edges: int = 0
    retained_bytes: int = 0
    traversal_steps: int = 0
    budget_exhausted: bool = False
    typestate: CodeQueryTypestateWork = field(default_factory=CodeQueryTypestateWork)
    value_flow: CodeQueryValueFlowWork = field(default_factory=CodeQueryValueFlowWork)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQuerySemanticWork:
        return cls(
            materialization_attempts=int(data.get("materialization_attempts", 0)),
            unique_materialized_files=int(data.get("unique_materialized_files", 0)),
            request_cache_hits=int(data.get("request_cache_hits", 0)),
            source_bytes=int(data.get("source_bytes", 0)),
            procedures=int(data.get("procedures", 0)),
            program_points=int(data.get("program_points", 0)),
            control_edges=int(data.get("control_edges", 0)),
            retained_bytes=int(data.get("retained_bytes", 0)),
            traversal_steps=int(data.get("traversal_steps", 0)),
            budget_exhausted=bool(data.get("budget_exhausted", False)),
            typestate=CodeQueryTypestateWork.from_dict(data.get("typestate", {})),
            value_flow=CodeQueryValueFlowWork.from_dict(data.get("value_flow", {})),
        )


@dataclass(frozen=True)
class CodeQueryProfileWork:
    scanned_files: int = 0
    scanned_source_bytes: int = 0
    fact_nodes: int = 0
    pipeline_rows: int = 0
    examined_references: int = 0
    provenance_steps: int = 0
    import_files_resolved: int = 0
    import_edges_resolved: int = 0
    semantic: CodeQuerySemanticWork = field(default_factory=CodeQuerySemanticWork)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryProfileWork:
        return cls(
            scanned_files=int(data.get("scanned_files", 0)),
            scanned_source_bytes=int(data.get("scanned_source_bytes", 0)),
            fact_nodes=int(data.get("fact_nodes", 0)),
            pipeline_rows=int(data.get("pipeline_rows", 0)),
            examined_references=int(data.get("examined_references", 0)),
            provenance_steps=int(data.get("provenance_steps", 0)),
            import_files_resolved=int(data.get("import_files_resolved", 0)),
            import_edges_resolved=int(data.get("import_edges_resolved", 0)),
            semantic=CodeQuerySemanticWork.from_dict(data.get("semantic", {})),
        )


class CodeQueryCacheMetricsKind(StrEnum):
    COMPLETE_VALUE = "complete_value"
    STRUCTURAL_FACTS = "structural_facts"


@dataclass(frozen=True)
class CodeQueryProfileCacheCounters:
    kind: CodeQueryCacheMetricsKind = CodeQueryCacheMetricsKind.COMPLETE_VALUE
    lookups: int = 0
    hits: int = 0
    misses: int = 0
    builds: int = 0
    waits: int = 0
    wait_ns: int = 0
    complete_hits: int = 0
    incomplete_hits: int = 0
    complete_builds: int = 0
    incomplete_builds: int = 0
    unknown_outcomes: int = 0
    replayed_items: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryProfileCacheCounters:
        counters = {
            "lookups",
            "hits",
            "misses",
            "builds",
            "waits",
            "wait_ns",
            "complete_hits",
            "incomplete_hits",
            "complete_builds",
            "incomplete_builds",
            "unknown_outcomes",
            "replayed_items",
        }
        return cls(
            kind=CodeQueryCacheMetricsKind(data["kind"]),
            **{key: int(data.get(key, 0)) for key in counters},
            extra=_extra_fields(data, {"kind", *counters}),
        )


@dataclass(frozen=True)
class CodeQueryDerivedLayerCacheCounters(CodeQueryProfileCacheCounters):
    cancelled: int = 0
    unavailable: int = 0
    over_budget: int = 0
    fallbacks: int = 0
    build_files: int = 0
    build_edges: int = 0
    build_ns: int = 0
    retained_bytes: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryDerivedLayerCacheCounters:
        common = {
            "lookups",
            "hits",
            "misses",
            "builds",
            "waits",
            "wait_ns",
            "complete_hits",
            "incomplete_hits",
            "complete_builds",
            "incomplete_builds",
            "unknown_outcomes",
            "replayed_items",
        }
        derived = {
            "cancelled",
            "unavailable",
            "over_budget",
            "fallbacks",
            "build_files",
            "build_edges",
            "build_ns",
            "retained_bytes",
        }
        counters = common | derived
        return cls(
            kind=CodeQueryCacheMetricsKind(data["kind"]),
            **{key: int(data.get(key, 0)) for key in counters},
            extra=_extra_fields(data, {"kind", *counters}),
        )


@dataclass(frozen=True)
class CodeQueryStructuralFactsCacheCounters:
    kind: CodeQueryCacheMetricsKind = CodeQueryCacheMetricsKind.STRUCTURAL_FACTS
    lookups: int = 0
    memory_hits: int = 0
    persisted_hydrations: int = 0
    extractions: int = 0
    unavailable: int = 0
    unknown_outcomes: int = 0
    replayed_files: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(
        cls, data: dict[str, Any]
    ) -> CodeQueryStructuralFactsCacheCounters:
        counters = {
            "lookups",
            "memory_hits",
            "persisted_hydrations",
            "extractions",
            "unavailable",
            "unknown_outcomes",
            "replayed_files",
        }
        return cls(
            kind=CodeQueryCacheMetricsKind(data["kind"]),
            **{key: int(data.get(key, 0)) for key in counters},
            extra=_extra_fields(data, {"kind", *counters}),
        )


CodeQueryCacheMetrics = (
    CodeQueryProfileCacheCounters
    | CodeQueryDerivedLayerCacheCounters
    | CodeQueryStructuralFactsCacheCounters
)


class CodeQueryCacheLayerKind(StrEnum):
    SEED_RESULT = "seed_result"
    SEED_STRUCTURAL_FACTS = "seed_structural_facts"
    INBOUND_REFERENCE = "inbound_reference"
    OUTBOUND_REFERENCE = "outbound_reference"
    INCOMING_CALL = "incoming_call"
    OUTGOING_CALL = "outgoing_call"
    IMPORT_FORWARD = "import_forward"
    IMPORT_REVERSE = "import_reverse"
    DIRECT_IMPORT_TOPOLOGY = "direct_import_topology"


@dataclass(frozen=True)
class CodeQueryProfileCacheLayer:
    layer: CodeQueryCacheLayerKind
    metrics: CodeQueryCacheMetrics
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryProfileCacheLayer:
        layer = CodeQueryCacheLayerKind(data["layer"])
        metrics_data = data.get("metrics")
        if not isinstance(metrics_data, dict):
            raise ValueError("cache layer metrics must be a nested object")
        metrics_kind = CodeQueryCacheMetricsKind(metrics_data.get("kind"))
        expected_kind = (
            CodeQueryCacheMetricsKind.STRUCTURAL_FACTS
            if layer is CodeQueryCacheLayerKind.SEED_STRUCTURAL_FACTS
            else CodeQueryCacheMetricsKind.COMPLETE_VALUE
        )
        if metrics_kind is not expected_kind:
            raise ValueError(
                f"cache layer {layer.value!r} requires metrics kind "
                f"{expected_kind.value!r}, got {metrics_kind.value!r}"
            )
        metrics: CodeQueryCacheMetrics
        if metrics_kind is CodeQueryCacheMetricsKind.STRUCTURAL_FACTS:
            metrics = CodeQueryStructuralFactsCacheCounters.from_dict(metrics_data)
        elif layer is CodeQueryCacheLayerKind.DIRECT_IMPORT_TOPOLOGY:
            metrics = CodeQueryDerivedLayerCacheCounters.from_dict(metrics_data)
        else:
            metrics = CodeQueryProfileCacheCounters.from_dict(metrics_data)
        return cls(
            layer=layer,
            metrics=metrics,
            extra=_extra_fields(data, {"layer", "metrics"}),
        )


def _code_query_cache_layers(
    data: dict[str, Any],
) -> list[CodeQueryProfileCacheLayer]:
    if "cache_layers" not in data:
        raise ValueError("cache_layers is required")
    value = data["cache_layers"]
    if not isinstance(value, list):
        raise ValueError("cache_layers must be a list")
    layers: list[CodeQueryProfileCacheLayer] = []
    for index, layer in enumerate(value):
        if not isinstance(layer, dict):
            raise ValueError(f"cache_layers[{index}] must be an object")
        try:
            layers.append(CodeQueryProfileCacheLayer.from_dict(layer))
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"invalid cache_layers[{index}]: {error}") from error
    return layers


@dataclass(frozen=True)
class CodeQueryBoundedDispatchProfile:
    worker_limit: int = 0
    workers_spawned: int = 0
    tasks_enqueued: int = 0
    tasks_started: int = 0
    tasks_completed: int = 0
    tasks_observed_cancelled_before_start: int = 0
    queue_wait_ns: int = 0
    budget_wait_ns: int = 0
    coordinator_wait_ns: int = 0
    dispatch_overhead_ns: int = 0
    peak_concurrency: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryBoundedDispatchProfile:
        fields = {
            "worker_limit",
            "workers_spawned",
            "tasks_enqueued",
            "tasks_started",
            "tasks_completed",
            "tasks_observed_cancelled_before_start",
            "queue_wait_ns",
            "budget_wait_ns",
            "coordinator_wait_ns",
            "dispatch_overhead_ns",
            "peak_concurrency",
        }
        return cls(
            **{key: int(data.get(key, 0)) for key in fields},
            extra=_extra_fields(data, fields),
        )


@dataclass(frozen=True)
class CodeQueryProfileScheduling:
    peak_concurrency: int
    bounded_dispatch: CodeQueryBoundedDispatchProfile | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryProfileScheduling:
        bounded_dispatch = data.get("bounded_dispatch")
        return cls(
            peak_concurrency=int(data.get("peak_concurrency", 0)),
            bounded_dispatch=(
                CodeQueryBoundedDispatchProfile.from_dict(bounded_dispatch)
                if isinstance(bounded_dispatch, dict)
                else None
            ),
            extra=_extra_fields(data, {"peak_concurrency", "bounded_dispatch"}),
        )


@dataclass(frozen=True)
class CodeQueryOperatorTimings:
    elapsed: int = 0
    total: int = 0
    dependency_execution: int = 0
    dependency_wait: int = 0
    merge: int = 0
    scheduling_overhead: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryOperatorTimings:
        fields = {
            "elapsed",
            "total",
            "dependency_execution",
            "dependency_wait",
            "merge",
            "scheduling_overhead",
        }
        return cls(
            **{key: int(data.get(key, 0)) for key in fields},
            extra=_extra_fields(data, fields),
        )


@dataclass(frozen=True)
class CodeQueryOperatorObservation:
    node: int
    branch: list[int]
    operator: CodeQueryPhysicalOperator
    disposition: CodeQueryOperatorDisposition
    timings_ns: CodeQueryOperatorTimings
    input_rows: int
    rows_visited: int
    relation_expansions: int
    rows_discarded: int | None
    output_rows: int
    temporary_capacity_bytes_lower_bound: int
    work: CodeQueryProfileWork
    cache_layers: list[CodeQueryProfileCacheLayer]
    terminations: list[CodeQueryOperatorTermination]
    operator_truncated: bool
    result_truncated: bool
    result_cancelled: bool
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryOperatorObservation:
        known = {
            "node",
            "branch",
            "operator",
            "disposition",
            "timings_ns",
            "input_rows",
            "rows_visited",
            "relation_expansions",
            "rows_discarded",
            "temporary_capacity_bytes_lower_bound",
            "work",
            "cache_layers",
            "terminations",
            "output_rows",
            "operator_truncated",
            "result_truncated",
            "result_cancelled",
        }
        return cls(
            node=int(data["node"]),
            branch=[int(index) for index in data.get("branch", [])],
            operator=CodeQueryPhysicalOperator(data["operator"]),
            disposition=CodeQueryOperatorDisposition(data["disposition"]),
            timings_ns=CodeQueryOperatorTimings.from_dict(data["timings_ns"]),
            input_rows=int(data.get("input_rows", 0)),
            rows_visited=int(data.get("rows_visited", 0)),
            relation_expansions=int(data.get("relation_expansions", 0)),
            rows_discarded=_optional_int(data, "rows_discarded"),
            output_rows=int(data.get("output_rows", 0)),
            temporary_capacity_bytes_lower_bound=int(
                data.get("temporary_capacity_bytes_lower_bound", 0)
            ),
            work=CodeQueryProfileWork.from_dict(data.get("work", {})),
            cache_layers=_code_query_cache_layers(data),
            terminations=[
                CodeQueryOperatorTermination(reason)
                for reason in data.get("terminations", [])
            ],
            operator_truncated=bool(data.get("operator_truncated", False)),
            result_truncated=bool(data.get("result_truncated", False)),
            result_cancelled=bool(data.get("result_cancelled", False)),
            extra=_extra_fields(data, known),
        )


class CodeQueryOperatorDisposition(StrEnum):
    COMPLETED = "completed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class CodeQueryOperatorTermination(StrEnum):
    CANCELLATION_BEFORE_WORK = "cancellation_before_work"
    CANCELLATION_DURING_WORK = "cancellation_during_work"
    DEPENDENCY_CANCELLED = "dependency_cancelled"
    DEPENDENCY_PIPELINE_HALTED = "dependency_pipeline_halted"
    TERMINAL_CAP = "terminal_cap"
    RESULT_LIMIT = "result_limit"
    EXECUTION_BUDGET = "execution_budget"
    PIPELINE_BUDGET = "pipeline_budget"
    IMPORT_GRAPH_BUDGET = "import_graph_budget"
    ANALYSIS_LIMIT = "analysis_limit"
    UNSUPPORTED_ANALYSIS = "unsupported_analysis"
    ANALYSIS_INCOMPLETE = "analysis_incomplete"


@dataclass(frozen=True)
class CodeQueryAccessPathTermProfile:
    label: str
    candidate_facts: int

    @classmethod
    def from_dict(
        cls, data: dict[str, Any]
    ) -> CodeQueryAccessPathTermProfile:
        return cls(
            label=str(data["label"]),
            candidate_facts=int(data["candidate_facts"]),
        )


@dataclass(frozen=True)
class CodeQueryAccessPathProfile:
    selected: str
    representation_version: int
    estimated_provider_files: int
    scoped_files: int
    scoped_fact_nodes: int
    admitted_fact_nodes: int
    candidate_files: int
    candidate_facts: int
    selected_terms: list[CodeQueryAccessPathTermProfile]
    source_verification_required: bool
    cache_ready_lookups: int
    materialized_files: int
    materialized_fact_nodes: int
    inspected_source_bytes: int
    examined_fact_nodes: int
    index_lookups: int
    index_hits: int
    index_misses: int
    index_builds: int
    index_waits: int
    index_wait_ns: int
    index_cancelled: int
    index_unavailable: int
    index_over_budget: int
    scan_fallbacks: int
    index_build_files: int
    index_build_source_bytes: int
    index_build_fact_nodes: int
    index_build_facts_bytes: int
    index_build_ns: int
    retained_bytes: int
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CodeQueryAccessPathProfile:
        known = {
            "selected",
            "representation_version",
            "estimated_provider_files",
            "scoped_files",
            "scoped_fact_nodes",
            "admitted_fact_nodes",
            "candidate_files",
            "candidate_facts",
            "selected_terms",
            "source_verification_required",
            "cache_ready_lookups",
            "materialized_files",
            "materialized_fact_nodes",
            "inspected_source_bytes",
            "examined_fact_nodes",
            "index_lookups",
            "index_hits",
            "index_misses",
            "index_builds",
            "index_waits",
            "index_wait_ns",
            "index_cancelled",
            "index_unavailable",
            "index_over_budget",
            "scan_fallbacks",
            "index_build_files",
            "index_build_source_bytes",
            "index_build_fact_nodes",
            "index_build_facts_bytes",
            "index_build_ns",
            "retained_bytes",
        }
        return cls(
            selected=str(data.get("selected", "scan_only")),
            representation_version=int(data.get("representation_version", 0)),
            estimated_provider_files=int(data.get("estimated_provider_files", 0)),
            scoped_files=int(data.get("scoped_files", 0)),
            scoped_fact_nodes=int(data.get("scoped_fact_nodes", 0)),
            admitted_fact_nodes=int(data.get("admitted_fact_nodes", 0)),
            candidate_files=int(data.get("candidate_files", 0)),
            candidate_facts=int(data.get("candidate_facts", 0)),
            selected_terms=[
                CodeQueryAccessPathTermProfile.from_dict(term)
                for term in data.get("selected_terms", [])
            ],
            source_verification_required=bool(
                data.get("source_verification_required", False)
            ),
            cache_ready_lookups=int(data.get("cache_ready_lookups", 0)),
            materialized_files=int(data.get("materialized_files", 0)),
            materialized_fact_nodes=int(data.get("materialized_fact_nodes", 0)),
            inspected_source_bytes=int(data.get("inspected_source_bytes", 0)),
            examined_fact_nodes=int(data.get("examined_fact_nodes", 0)),
            index_lookups=int(data.get("index_lookups", 0)),
            index_hits=int(data.get("index_hits", 0)),
            index_misses=int(data.get("index_misses", 0)),
            index_builds=int(data.get("index_builds", 0)),
            index_waits=int(data.get("index_waits", 0)),
            index_wait_ns=int(data.get("index_wait_ns", 0)),
            index_cancelled=int(data.get("index_cancelled", 0)),
            index_unavailable=int(data.get("index_unavailable", 0)),
            index_over_budget=int(data.get("index_over_budget", 0)),
            scan_fallbacks=int(data.get("scan_fallbacks", 0)),
            index_build_files=int(data.get("index_build_files", 0)),
            index_build_source_bytes=int(data.get("index_build_source_bytes", 0)),
            index_build_fact_nodes=int(data.get("index_build_fact_nodes", 0)),
            index_build_facts_bytes=int(data.get("index_build_facts_bytes", 0)),
            index_build_ns=int(data.get("index_build_ns", 0)),
            retained_bytes=int(data.get("retained_bytes", 0)),
            extra=_extra_fields(data, known),
        )


@dataclass(frozen=True)
class CodeQueryProfile:
    FORMAT: ClassVar[str] = "bifrost_code_query_profile/v2"

    format: str
    result: CodeQueryResult
    explain: CodeQueryExplain
    timings_ns: CodeQueryProfileTimings
    work: CodeQueryProfileWork
    cache_layers: list[CodeQueryProfileCacheLayer]
    access_path: CodeQueryAccessPathProfile
    scheduling: CodeQueryProfileScheduling
    operators: list[CodeQueryOperatorObservation]
    rendered_text: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(
        cls, data: dict[str, Any], rendered_text: str | None = None
    ) -> CodeQueryProfile:
        if data.get("format") != cls.FORMAT:
            raise ValueError(f"unsupported code-query profile format: {data.get('format')!r}")
        known = {
            "format",
            "result",
            "explain",
            "timings_ns",
            "work",
            "cache_layers",
            "access_path",
            "scheduling",
            "operators",
        }
        return cls(
            format=cls.FORMAT,
            result=CodeQueryResult.from_dict(data["result"]),
            explain=CodeQueryExplain.from_dict(data["explain"]),
            timings_ns=CodeQueryProfileTimings.from_dict(data.get("timings_ns", {})),
            work=CodeQueryProfileWork.from_dict(data.get("work", {})),
            cache_layers=_code_query_cache_layers(data),
            access_path=CodeQueryAccessPathProfile.from_dict(data["access_path"]),
            scheduling=CodeQueryProfileScheduling.from_dict(
                data.get("scheduling", {})
            ),
            operators=[
                CodeQueryOperatorObservation.from_dict(operator)
                for operator in data.get("operators", [])
            ],
            rendered_text=rendered_text,
            extra=_extra_fields(data, known),
        )

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        return (
            f"{self.result.render_text()}\n\n"
            f"Profile: {len(self.operators)} operator(s), "
            f"{self.timings_ns.total} ns total, "
            f"peak concurrency {self.scheduling.peak_concurrency}."
        )


CodeQueryResponse = CodeQueryResult | CodeQueryExplain | CodeQueryProfile


def parse_code_query_response(
    data: dict[str, Any], rendered_text: str | None = None
) -> CodeQueryResponse:
    format_name = data.get("format")
    if format_name is None:
        return CodeQueryResult.from_dict(data, rendered_text=rendered_text)
    if format_name == CodeQueryExplain.FORMAT:
        return CodeQueryExplain.from_dict(data, rendered_text=rendered_text)
    if format_name == CodeQueryProfile.FORMAT:
        return CodeQueryProfile.from_dict(data, rendered_text=rendered_text)
    raise ValueError(f"unsupported code-query response format: {format_name!r}")


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
class MostRelevantFile:
    """A ranked file and the test verdict the caller filters on.

    Ranking applies no test policy of its own (issue #1575): a project without
    a src/main convention can never report "production", so the caller decides
    which kinds to keep.
    """

    path: str
    test: TestFileKindValue

    @classmethod
    def from_dict(cls, data: dict) -> MostRelevantFile:
        return cls(path=data["path"], test=_test_file_kind(data["test"]))


@dataclass(frozen=True)
class MostRelevantFilesResult:
    files: list[MostRelevantFile]
    not_found: list[str]
    duplicates: list[str]
    complete: bool = True
    ranking_mode_used: MostRelevantFilesRankingModeValue = "history_imports"
    incomplete_reason: MostRelevantFilesIncompleteReasonValue | None = None
    render_line_numbers: bool = True
    rendered_text: str | None = None

    @classmethod
    def from_dict(
        cls, data: dict, render_line_numbers: bool = True, rendered_text: str | None = None
    ) -> MostRelevantFilesResult:
        return cls(
            files=[MostRelevantFile.from_dict(item) for item in data["files"]],
            not_found=list(data["not_found"]),
            duplicates=list(data.get("duplicates", [])),
            complete=_strict_bool(data, "complete", True),
            ranking_mode_used=_most_relevant_files_ranking_mode(
                data.get("ranking_mode_used", "history_imports")
            ),
            incomplete_reason=_most_relevant_files_incomplete_reason(
                data.get("incomplete_reason")
            ),
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

        lines = [f"{file.path} [{file.test}]" for file in self.files]
        if self.not_found:
            lines.append(f"Not found: {', '.join(self.not_found)}")
        if self.duplicates:
            lines.append(f"Duplicate seeds: {', '.join(self.duplicates)}")
        if not self.complete:
            reason = {
                "time_budget": "the usage-graph ranking exceeded its time budget",
                "cancelled": "the usage-graph ranking was cancelled",
            }.get(self.incomplete_reason, "the requested ranking did not complete")
            lines.extend(
                [
                    "",
                    f"Incomplete: {reason}; returned deterministic history/import ranking instead.",
                ]
            )
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
class DiffEndpoints:
    """Resolved diff endpoints.

    Each field is a full commit hash, or the literal ``"worktree"`` when that
    endpoint is the uncommitted working tree.
    """

    base: str
    target: str

    @classmethod
    def from_dict(cls, data: dict) -> DiffEndpoints:
        return cls(base=data["base"], target=data["target"])


@dataclass(frozen=True)
class FileChange:
    """One file's entry in a diff.

    ``status`` is one of ``added``, ``deleted``, ``modified``, ``renamed``,
    ``copied``, ``typechange``, ``conflicted`` or ``unknown``. ``insertions``
    and ``deletions`` follow ``git diff --numstat``; binary content has no line
    hunks, so ``is_binary`` is True and both counts are 0.
    """

    old_path: str | None
    path: str | None
    status: str
    insertions: int
    deletions: int
    is_binary: bool
    is_test: bool
    is_parseable: bool

    @classmethod
    def from_dict(cls, data: dict) -> FileChange:
        return cls(
            old_path=data.get("old_path"),
            path=data.get("path"),
            status=data["status"],
            insertions=int(data["insertions"]),
            deletions=int(data["deletions"]),
            is_binary=bool(data["is_binary"]),
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
class CalleeChange:
    """One outgoing call edge a patch symbol gained or lost.

    This is :class:`CallEdgeChange` without ``from_fqn`` and ``change``: the
    caller is the record holding the list, and the direction is which of the
    record's lists it lands in.
    """

    to_fqn: str
    language: str
    weight: int
    sites: list[UsageGraphCallSite]

    @classmethod
    def from_dict(cls, data: dict) -> CalleeChange:
        return cls(
            to_fqn=data["to"],
            language=data["language"],
            weight=int(data["weight"]),
            sites=[UsageGraphCallSite.from_dict(item) for item in data.get("sites", [])],
        )


@dataclass(frozen=True)
class EditedSymbolPair:
    """A symbol present at both endpoints that some hunk touched.

    The two line lists say how: an empty ``touched_old_lines`` means the hunk
    only inserted, an empty ``touched_new_lines`` means it only deleted, and
    both non-empty means it replaced. At least one is always non-empty.
    """

    before: CommitSymbol
    after: CommitSymbol
    touched_old_lines: list[int]
    touched_new_lines: list[int]
    added_calls: list[CalleeChange]
    removed_calls: list[CalleeChange]

    @classmethod
    def from_dict(cls, data: dict) -> EditedSymbolPair:
        return cls(
            before=CommitSymbol.from_dict(data["before"]),
            after=CommitSymbol.from_dict(data["after"]),
            touched_old_lines=[int(item) for item in data.get("touched_old_lines", [])],
            touched_new_lines=[int(item) for item in data.get("touched_new_lines", [])],
            added_calls=[CalleeChange.from_dict(item) for item in data.get("added_calls", [])],
            removed_calls=[
                CalleeChange.from_dict(item) for item in data.get("removed_calls", [])
            ],
        )


@dataclass(frozen=True)
class IntroducedSymbol:
    """A symbol the postimage has and the preimage does not."""

    after: CommitSymbol
    touched_new_lines: list[int]
    calls: list[CalleeChange]
    """Everything the new symbol calls; a symbol the preimage lacks can only add edges."""

    @classmethod
    def from_dict(cls, data: dict) -> IntroducedSymbol:
        return cls(
            after=CommitSymbol.from_dict(data["after"]),
            touched_new_lines=[int(item) for item in data.get("touched_new_lines", [])],
            calls=[CalleeChange.from_dict(item) for item in data.get("calls", [])],
        )


@dataclass(frozen=True)
class DeletedSymbol:
    """A symbol the preimage has and the postimage does not."""

    before: CommitSymbol
    touched_old_lines: list[int]
    called: list[CalleeChange]
    """Everything the symbol used to call; the mirror of :attr:`IntroducedSymbol.calls`."""

    @classmethod
    def from_dict(cls, data: dict) -> DeletedSymbol:
        return cls(
            before=CommitSymbol.from_dict(data["before"]),
            touched_old_lines=[int(item) for item in data.get("touched_old_lines", [])],
            called=[CalleeChange.from_dict(item) for item in data.get("called", [])],
        )


@dataclass(frozen=True)
class MovedSymbol:
    """A symbol both endpoints hold at a different location, or under a
    different fully-qualified name because its file moved.

    A pure move reports both call lists empty: the preimage graph is compared
    under the postimage names, so relocating a symbol is not a call-edge change.
    """

    before: CommitSymbol
    after: CommitSymbol
    added_calls: list[CalleeChange]
    removed_calls: list[CalleeChange]

    @classmethod
    def from_dict(cls, data: dict) -> MovedSymbol:
        return cls(
            before=CommitSymbol.from_dict(data["before"]),
            after=CommitSymbol.from_dict(data["after"]),
            added_calls=[CalleeChange.from_dict(item) for item in data.get("added_calls", [])],
            removed_calls=[
                CalleeChange.from_dict(item) for item in data.get("removed_calls", [])
            ],
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
class PatchSymbols:
    """Symbol-level effects, partitioned by which endpoints hold the symbol.

    A symbol appears in at most one of ``edited``, ``introduced`` and
    ``deleted``. ``moved`` and ``signature_changes`` describe matched symbols
    independently of whether a hunk touched them.
    """

    edited: list[EditedSymbolPair]
    introduced: list[IntroducedSymbol]
    deleted: list[DeletedSymbol]
    moved: list[MovedSymbol]
    signature_changes: list[SignatureChange]

    @classmethod
    def from_dict(cls, data: dict) -> PatchSymbols:
        return cls(
            edited=[EditedSymbolPair.from_dict(item) for item in data.get("edited", [])],
            introduced=[IntroducedSymbol.from_dict(item) for item in data.get("introduced", [])],
            deleted=[DeletedSymbol.from_dict(item) for item in data.get("deleted", [])],
            moved=[MovedSymbol.from_dict(item) for item in data.get("moved", [])],
            signature_changes=[
                SignatureChange.from_dict(item) for item in data.get("signature_changes", [])
            ],
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
    """A call edge the patch added or removed whose caller is no patch symbol."""

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
class DiffAnalysisResult:
    endpoints: DiffEndpoints
    file_changes: list[FileChange]
    patch_symbols: PatchSymbols
    dependency_symbols: list[CommitSymbol]
    import_changes: list[ImportChange]
    unattributed_call_edge_changes: list[CallEdgeChange]
    """Call-edge changes left over after every patch symbol took the edges it calls."""

    large_callsite_symbols: list[LargeCallsiteSymbol]

    @classmethod
    def from_dict(cls, data: dict) -> DiffAnalysisResult:
        return cls(
            endpoints=DiffEndpoints.from_dict(data["endpoints"]),
            file_changes=[FileChange.from_dict(item) for item in data.get("file_changes", [])],
            patch_symbols=PatchSymbols.from_dict(data["patch_symbols"]),
            dependency_symbols=[
                CommitSymbol.from_dict(item) for item in data.get("dependency_symbols", [])
            ],
            import_changes=[ImportChange.from_dict(item) for item in data.get("import_changes", [])],
            unattributed_call_edge_changes=[
                CallEdgeChange.from_dict(item)
                for item in data.get("unattributed_call_edge_changes", [])
            ],
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
