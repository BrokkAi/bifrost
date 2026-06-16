from __future__ import annotations

from dataclasses import dataclass


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
class SummaryElement:
    path: str
    symbol: str
    kind: str
    start_line: int
    end_line: int
    text: str
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
        if self.preamble:
            blocks.append(self.preamble)
        rendered_elements = [
            element.render_text() for element in self.elements if element.text
        ]
        blocks.extend(rendered_elements)
        return "\n".join(blocks).strip()


@dataclass(frozen=True)
class SymbolSummariesResult:
    summaries: list[SummaryBlock]
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
        return len(self.summaries) + compact_count

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        blocks = [summary.render_text() for summary in self.summaries]
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
        usages = self.structured.get("usages", [])
        if not usages:
            return "No usages found."
        blocks: list[str] = []
        for usage in usages:
            symbol = str(usage.get("symbol", "<unknown>"))
            total_hits = int(usage.get("total_hits", 0))
            lines = [f"{symbol}: {total_hits} usage(s)"]
            for file_group in usage.get("files", []):
                path = str(file_group.get("path", "<unknown>"))
                lines.append(path)
                for hit in file_group.get("hits", []):
                    line = hit.get("line")
                    enclosing = hit.get("enclosing")
                    prefix = f"  line {line}" if line is not None else "  hit"
                    if enclosing:
                        prefix += f" in {enclosing}"
                    lines.append(prefix)
                    snippet = str(hit.get("snippet", "")).rstrip()
                    if snippet:
                        lines.extend(f"    {snippet_line}" for snippet_line in snippet.splitlines())
            blocks.append("\n".join(lines))
        return "\n\n".join(blocks)


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
class SemanticSearchHit:
    path: str
    score: float
    summary: str

    @classmethod
    def from_dict(cls, data: dict) -> SemanticSearchHit:
        return cls(
            path=data["path"],
            score=float(data["score"]),
            summary=data["summary"],
        )

    def render_text(self) -> str:
        return f"=== {self.path} (score {self.score:.3f}) ===\n{self.summary}"


@dataclass(frozen=True)
class SemanticSearchResult:
    hits: list[SemanticSearchHit]
    notes: list[str]
    render_line_numbers: bool = True
    rendered_text: str | None = None

    @classmethod
    def from_dict(
        cls, data: dict, render_line_numbers: bool = True, rendered_text: str | None = None
    ) -> SemanticSearchResult:
        return cls(
            hits=[SemanticSearchHit.from_dict(item) for item in data["hits"]],
            notes=list(data.get("notes", [])),
            render_line_numbers=render_line_numbers,
            rendered_text=rendered_text,
        )

    @property
    def count(self) -> int:
        return len(self.hits)

    def render_text(self) -> str:
        if self.rendered_text is not None:
            return self.rendered_text
        lines = [f"note: {note}" for note in self.notes]
        lines.extend(hit.render_text() for hit in self.hits)
        return "\n\n".join(lines) if lines else "No semantic search results found."


@dataclass(frozen=True)
class SemanticSearchStatus:
    indexed_files: int
    waiting_files: int
    pending_batches: int
    phase: str

    @classmethod
    def from_dict(cls, data: dict) -> SemanticSearchStatus:
        return cls(
            indexed_files=int(data["indexed_files"]),
            waiting_files=int(data["waiting_files"]),
            pending_batches=int(data["pending_batches"]),
            phase=str(data["phase"]),
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
class UsageGraphEdge:
    """A weighted caller -> callee reference edge.

    ``from_fqn`` is the enclosing definition of the reference and ``to_fqn`` is
    the symbol being referenced; both endpoints are nodes in ``language``'s
    ecosystem. ``weight`` is the number of distinct ``(file, line, caller)``
    reference sites (two references to the same callee on one line count once).
    (The JSON keys are ``from``/``to``, renamed here because ``from`` is a
    Python keyword.)
    """

    from_fqn: str
    to_fqn: str
    language: str
    weight: int

    @classmethod
    def from_dict(cls, data: dict) -> UsageGraphEdge:
        return cls(
            from_fqn=data["from"],
            to_fqn=data["to"],
            language=data["language"],
            weight=data["weight"],
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
