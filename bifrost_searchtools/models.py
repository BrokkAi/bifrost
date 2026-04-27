from __future__ import annotations

from dataclasses import dataclass


def _render_numbered_block(text: str, start_line: int) -> str:
    return "\n".join(
        f"{start_line + index}: {line}" for index, line in enumerate(text.splitlines())
    )


@dataclass(frozen=True)
class SearchSymbolHit:
    symbol: str
    signature: str
    line: int

    @classmethod
    def from_dict(cls, data: dict) -> SearchSymbolHit:
        return cls(
            symbol=data["symbol"],
            signature=data["signature"],
            line=int(data["line"]),
        )

    def render_text(self) -> str:
        return f"{self.line}: {self.signature}" if self.line > 0 else self.signature


@dataclass(frozen=True)
class SearchSymbolsFile:
    path: str
    loc: int
    classes: list[SearchSymbolHit]
    functions: list[SearchSymbolHit]
    fields: list[SearchSymbolHit]
    modules: list[SearchSymbolHit]

    @classmethod
    def from_dict(cls, data: dict) -> SearchSymbolsFile:
        return cls(
            path=data["path"],
            loc=data["loc"],
            classes=[SearchSymbolHit.from_dict(item) for item in data["classes"]],
            functions=[SearchSymbolHit.from_dict(item) for item in data["functions"]],
            fields=[SearchSymbolHit.from_dict(item) for item in data["fields"]],
            modules=[SearchSymbolHit.from_dict(item) for item in data["modules"]],
        )

    def render_text(self) -> str:
        lines = [f"{self.path} ({self.loc} lines)"]
        if self.classes:
            lines.extend(["  classes:", *[f"    {hit.render_text()}" for hit in self.classes]])
        if self.functions:
            lines.extend(["  functions:", *[f"    {hit.render_text()}" for hit in self.functions]])
        if self.fields:
            lines.extend(["  fields:", *[f"    {hit.render_text()}" for hit in self.fields]])
        if self.modules:
            lines.extend(["  modules:", *[f"    {hit.render_text()}" for hit in self.modules]])
        return "\n".join(lines)


@dataclass(frozen=True)
class SearchSymbolsResult:
    patterns: list[str]
    truncated: bool
    total_files: int
    files: list[SearchSymbolsFile]

    @classmethod
    def from_dict(cls, data: dict) -> SearchSymbolsResult:
        return cls(
            patterns=list(data["patterns"]),
            truncated=bool(data["truncated"]),
            total_files=int(data.get("total_files", len(data["files"]))),
            files=[SearchSymbolsFile.from_dict(item) for item in data["files"]],
        )

    @property
    def count(self) -> int:
        return len(self.files)

    def render_text(self) -> str:
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

    @classmethod
    def from_dict(cls, data: dict) -> SymbolLocation:
        return cls(
            symbol=data["symbol"],
            path=data["path"],
            loc=data["loc"],
            start_line=data["start_line"],
            end_line=data["end_line"],
        )

    def render_text(self) -> str:
        return f"{self.symbol}: {self.path}:{self.start_line}..{self.end_line}"


@dataclass(frozen=True)
class SymbolLocationsResult:
    locations: list[SymbolLocation]
    not_found: list[str]

    @classmethod
    def from_dict(cls, data: dict) -> SymbolLocationsResult:
        return cls(
            locations=[SymbolLocation.from_dict(item) for item in data["locations"]],
            not_found=list(data["not_found"]),
        )

    @property
    def count(self) -> int:
        return len(self.locations)

    def render_text(self) -> str:
        lines = [location.render_text() for location in self.locations]
        if self.not_found:
            lines.append(f"Not found: {', '.join(self.not_found)}")
        return "\n".join(lines) if lines else "No matching symbols found."


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

    @classmethod
    def from_dict(cls, data: dict) -> SummaryElement:
        return cls(
            path=data["path"],
            symbol=data["symbol"],
            kind=data["kind"],
            start_line=data["start_line"],
            end_line=data["end_line"],
            text=data["text"],
        )

    def render_text(self) -> str:
        lines = self.text.splitlines()
        if not lines:
            return ""
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

    @classmethod
    def from_dict(cls, data: dict) -> SummaryBlock:
        return cls(
            label=data["label"],
            path=data["path"],
            preamble=data.get("preamble", ""),
            elements=[SummaryElement.from_dict(item) for item in data["elements"]],
        )

    def render_text(self) -> str:
        blocks: list[str] = [self.path]
        if self.preamble:
            blocks.append(self.preamble)
        rendered_elements = [element.render_text() for element in self.elements if element.text]
        blocks.extend(rendered_elements)
        return "\n".join(blocks).strip()


@dataclass(frozen=True)
class SymbolSummariesResult:
    summaries: list[SummaryBlock]
    not_found: list[str]
    ambiguous: list[AmbiguousSymbol]

    @classmethod
    def from_dict(cls, data: dict) -> SymbolSummariesResult:
        return cls(
            summaries=[SummaryBlock.from_dict(item) for item in data["summaries"]],
            not_found=list(data["not_found"]),
            ambiguous=[
                AmbiguousSymbol.from_dict(item) for item in data.get("ambiguous", [])
            ],
        )

    @property
    def count(self) -> int:
        return len(self.summaries)

    def render_text(self) -> str:
        blocks = [summary.render_text() for summary in self.summaries]
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

    @classmethod
    def from_dict(cls, data: dict) -> SourceBlock:
        return cls(
            label=data["label"],
            path=data["path"],
            start_line=data["start_line"],
            end_line=data["end_line"],
            text=data["text"],
        )

    def render_text(self) -> str:
        header = f"{self.label} ({self.path}:{self.start_line}..{self.end_line})"
        return "\n".join([header, _render_numbered_block(self.text, self.start_line)])


@dataclass(frozen=True)
class SymbolSourcesResult:
    sources: list[SourceBlock]
    not_found: list[str]
    ambiguous: list[AmbiguousSymbol]

    @classmethod
    def from_dict(cls, data: dict) -> SymbolSourcesResult:
        return cls(
            sources=[SourceBlock.from_dict(item) for item in data["sources"]],
            not_found=list(data["not_found"]),
            ambiguous=[
                AmbiguousSymbol.from_dict(item) for item in data.get("ambiguous", [])
            ],
        )

    @property
    def count(self) -> int:
        return len(self.sources)

    def render_text(self) -> str:
        blocks = [source.render_text() for source in self.sources]
        if self.not_found:
            blocks.append(f"Not found: {', '.join(self.not_found)}")
        blocks.extend(item.render_text() for item in self.ambiguous)
        return "\n\n".join(blocks) if blocks else "No matching sources found."


@dataclass(frozen=True)
class SkimFile:
    path: str
    loc: int
    lines: list[str]

    @classmethod
    def from_dict(cls, data: dict) -> SkimFile:
        return cls(path=data["path"], loc=data["loc"], lines=list(data["lines"]))

    def render_text(self) -> str:
        return "\n".join([f"{self.path} ({self.loc} lines)", *self.lines])


@dataclass(frozen=True)
class SkimFilesResult:
    truncated: bool
    total_files: int
    files: list[SkimFile]

    @classmethod
    def from_dict(cls, data: dict) -> SkimFilesResult:
        return cls(
            truncated=bool(data["truncated"]),
            total_files=int(data.get("total_files", len(data["files"]))),
            files=[SkimFile.from_dict(item) for item in data["files"]],
        )

    @property
    def count(self) -> int:
        return len(self.files)

    def render_text(self) -> str:
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

    @classmethod
    def from_dict(cls, data: dict) -> MostRelevantFilesResult:
        return cls(files=list(data["files"]), not_found=list(data["not_found"]))

    @property
    def count(self) -> int:
        return len(self.files)

    def render_text(self) -> str:
        if not self.files and not self.not_found:
            return "No related files found."

        lines = list(self.files)
        if self.not_found:
            lines.append(f"Not found: {', '.join(self.not_found)}")
        return "\n".join(lines)
