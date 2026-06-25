from __future__ import annotations

from dataclasses import dataclass, field


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
class DefinitionDiagnostic:
    kind: str
    message: str

    @classmethod
    def from_dict(cls, data: dict) -> DefinitionDiagnostic:
        return cls(kind=data["kind"], message=data["message"])

    def render_text(self) -> str:
        return f"{self.kind}: {self.message}"


@dataclass(frozen=True)
class DefinitionCandidate:
    fqn: str
    path: str
    start_line: int
    end_line: int
    kind: str
    signature: str | None
    language: str

    @classmethod
    def from_dict(cls, data: dict) -> DefinitionCandidate:
        return cls(
            fqn=data["fqn"],
            path=data["path"],
            start_line=int(data["start_line"]),
            end_line=int(data["end_line"]),
            kind=data["kind"],
            signature=data.get("signature"),
            language=data["language"],
        )

    def render_text(self) -> str:
        location = f"{self.path}:{self.start_line}..{self.end_line}"
        signature = f" {self.signature}" if self.signature else ""
        return f"{self.fqn} ({self.kind}, {self.language}) at {location}{signature}"


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
    status: str
    reference: DefinitionReferenceSite | None
    definitions: list[DefinitionCandidate]
    diagnostics: list[DefinitionDiagnostic]

    @classmethod
    def from_dict(cls, data: dict) -> DefinitionLookupResult:
        return cls(
            query=dict(data["query"]),
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
        lines = [f"status: {self.status}"]
        if self.reference is not None:
            lines.append(f"reference: {self.reference.path} -> {self.reference.target}")
        lines.extend(definition.render_text() for definition in self.definitions)
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

    @classmethod
    def from_dict(cls, data: dict) -> SemanticSearchStatus:
        return cls(
            indexed_chunks=int(data["indexed_chunks"]),
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
class UsageGraphCallSite:
    """One concrete reference site behind a :class:`UsageGraphEdge`.

    ``path`` is workspace-relative and ``line`` is 1-based, matching the
    ``line`` of a ``scan_usages`` hit and a node's ``start_line``.
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
