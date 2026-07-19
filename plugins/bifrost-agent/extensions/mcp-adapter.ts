import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_LINES,
  formatSize,
  keyHint,
  truncateHead,
  truncateToVisualLines,
  type AgentToolResult,
  type Theme,
  type ToolRenderResultOptions,
  type TruncationResult,
} from "@earendil-works/pi-coding-agent";
import { Container, type Component, Text, truncateToWidth } from "@earendil-works/pi-tui";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { Type, type TSchema } from "typebox";

const TUI_PREVIEW_LINES = 5;

export interface BifrostToolDetails {
  truncation?: TruncationResult;
  fullOutputPath?: string;
}

export function toolParameters(tool: Tool) {
  return Type.Unsafe<Record<string, unknown>>(tool.inputSchema as TSchema);
}

export function toolLabel(tool: Tool): string {
  return tool.annotations?.title?.trim() || tool.name
    .split("_")
    .filter(Boolean)
    .map((part) => part[0]!.toUpperCase() + part.slice(1))
    .join(" ");
}

export async function mapToolResult(
  toolName: string,
  result: CallToolResult,
): Promise<AgentToolResult<BifrostToolDetails>> {
  if (result.isError) {
    throw await createBoundedToolError(`Bifrost tool ${toolName} failed: ${errorMessage(result)}`);
  }

  const textParts: string[] = [];
  const images: Array<{ type: "image"; data: string; mimeType: string }> = [];
  for (const item of result.content ?? []) {
    if (item.type === "text" && typeof item.text === "string") {
      textParts.push(item.text);
    } else if (item.type === "image" && typeof item.data === "string" && typeof item.mimeType === "string") {
      images.push({ type: "image", data: item.data, mimeType: item.mimeType });
    }
  }

  if (result.structuredContent !== undefined) {
    textParts.push(`Structured content:\n${JSON.stringify(result.structuredContent, null, 2)}`);
  }
  if (textParts.length === 0 && images.length === 0) {
    textParts.push("Bifrost returned no model-visible content.");
  }

  const visibleContent: Array<{ type: "text"; text: string } | { type: "image"; data: string; mimeType: string }> = [];
  let details: BifrostToolDetails = {};
  if (textParts.length > 0) {
    const bounded = await boundModelText(textParts.join("\n\n"));
    visibleContent.push({ type: "text", text: bounded.text });
    details = bounded.details;
  }
  visibleContent.push(...images);

  return { content: visibleContent, details };
}

export async function createBoundedToolError(message: string, cause?: unknown): Promise<Error> {
  const bounded = await boundModelText(message);
  return new Error(bounded.text, { cause });
}

export function renderToolResult(
  result: AgentToolResult<BifrostToolDetails>,
  options: ToolRenderResultOptions,
  theme: Theme,
): Component {
  const container = new Container();
  const details = result.details;
  let output = textContent(result).trim();
  if (details?.fullOutputPath) {
    const notice = modelTruncationNotice(details.fullOutputPath);
    const suffix = `\n\n${notice}`;
    if (output.endsWith(suffix)) {
      output = output.slice(0, -suffix.length).trimEnd();
    } else if (output === notice) {
      output = "";
    }
  }

  if (output) {
    const styledOutput = output
      .split("\n")
      .map((line) => theme.fg("toolOutput", line))
      .join("\n");
    if (options.expanded) {
      container.addChild(new Text(styledOutput, 0, 0));
    } else {
      container.addChild(collapsedOutput(styledOutput, theme));
    }
  }

  if (details?.truncation?.truncated || details?.fullOutputPath) {
    const warnings: string[] = [];
    if (details.fullOutputPath) {
      warnings.push(`Full output: ${details.fullOutputPath}`);
    }
    const truncation = details.truncation;
    if (truncation?.truncated) {
      warnings.push(
        truncation.truncatedBy === "lines"
          ? `Truncated: showing ${truncation.outputLines} of ${truncation.totalLines} lines`
          : `Truncated: showing ${formatSize(truncation.outputBytes)} of ${formatSize(truncation.totalBytes)}`,
      );
    }
    container.addChild(new Text(theme.fg("warning", `[${warnings.join(". ")}]`), 0, 0));
  }

  return container;
}

async function boundModelText(text: string): Promise<{ text: string; details: BifrostToolDetails }> {
  const initial = truncateHead(text);
  if (!initial.truncated) {
    return { text, details: {} };
  }

  const fullOutputPath = await saveFullOutput(text);
  const notice = modelTruncationNotice(fullOutputPath);
  const suffix = `\n\n${notice}`;
  const truncation = truncateHead(text, {
    maxBytes: DEFAULT_MAX_BYTES - Buffer.byteLength(suffix, "utf8"),
    maxLines: DEFAULT_MAX_LINES - 2,
  });
  return {
    text: `${truncation.content}${truncation.content ? suffix : notice}`,
    details: { truncation, fullOutputPath },
  };
}

async function saveFullOutput(text: string): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "pi-bifrost-"));
  const outputPath = join(directory, "output.txt");
  await writeFile(outputPath, text, "utf8");
  return outputPath;
}

function modelTruncationNotice(fullOutputPath: string): string {
  return `[Output truncated at Pi's ${DEFAULT_MAX_LINES.toLocaleString("en-US")}-line/${DEFAULT_MAX_BYTES / 1024}KB model limit. Full output: ${fullOutputPath}]`;
}

function collapsedOutput(output: string, theme: Theme): Component {
  let cachedWidth: number | undefined;
  let cachedLines: string[] | undefined;
  let cachedSkipped: number | undefined;
  return {
    render(width: number): string[] {
      if (cachedLines === undefined || cachedWidth !== width) {
        const preview = truncateToVisualLines(output, TUI_PREVIEW_LINES, width);
        cachedLines = preview.visualLines;
        cachedSkipped = preview.skippedCount;
        cachedWidth = width;
      }
      if (cachedSkipped && cachedSkipped > 0) {
        const hint = theme.fg("muted", `... (${cachedSkipped} earlier lines,`)
          + ` ${keyHint("app.tools.expand", "to expand")}${theme.fg("muted", ")")}`;
        return [truncateToWidth(hint, width, "..."), ...(cachedLines ?? [])];
      }
      return cachedLines ?? [];
    },
    invalidate(): void {
      cachedWidth = undefined;
      cachedLines = undefined;
      cachedSkipped = undefined;
    },
  };
}

function textContent(result: AgentToolResult<BifrostToolDetails>): string {
  return result.content
    .filter((item): item is { type: "text"; text: string } => item.type === "text")
    .map((item) => item.text)
    .join("\n\n");
}

function errorMessage(result: CallToolResult): string {
  const textParts: string[] = [];
  for (const item of result.content ?? []) {
    if (item.type === "text" && typeof item.text === "string") {
      textParts.push(item.text);
    }
  }
  const text = textParts.join("\n").trim();
  if (text) {
    return text;
  }
  if (result.structuredContent !== undefined) {
    return JSON.stringify(result.structuredContent);
  }
  return "the MCP server returned an error without a message";
}
