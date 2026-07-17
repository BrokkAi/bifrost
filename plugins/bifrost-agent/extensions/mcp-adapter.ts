import {
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_LINES,
  truncateHead,
  type AgentToolResult,
} from "@earendil-works/pi-coding-agent";
import { Type, type TSchema } from "typebox";

export interface McpToolDescription {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  annotations?: { title?: string };
}

export interface McpContent {
  type: string;
  text?: string;
  data?: string;
  mimeType?: string;
  [key: string]: unknown;
}

export interface McpToolResult {
  content?: McpContent[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
  [key: string]: unknown;
}

export interface BifrostToolDetails {
  mcpResult: McpToolResult;
  truncated: boolean;
}

export function toolParameters(tool: McpToolDescription) {
  const inputSchema = tool.inputSchema ?? {
    type: "object",
    properties: {},
    additionalProperties: false,
  };
  return Type.Unsafe<Record<string, unknown>>(inputSchema as TSchema);
}

export function toolLabel(tool: McpToolDescription): string {
  return tool.annotations?.title?.trim() || tool.name
    .split("_")
    .filter(Boolean)
    .map((part) => part[0]!.toUpperCase() + part.slice(1))
    .join(" ");
}

export function mapToolResult(toolName: string, result: McpToolResult): AgentToolResult<BifrostToolDetails> {
  if (result.isError) {
    throw new Error(`Bifrost tool ${toolName} failed: ${errorMessage(result)}`);
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

  const bounded = truncateModelText(textParts.join("\n\n"));
  const visibleContent: Array<{ type: "text"; text: string } | { type: "image"; data: string; mimeType: string }> = [];
  if (textParts.length > 0) {
    visibleContent.push({ type: "text", text: bounded.text });
  }
  visibleContent.push(...images);

  return {
    content: visibleContent,
    details: { mcpResult: result, truncated: bounded.truncated },
  };
}

function truncateModelText(text: string): { text: string; truncated: boolean } {
  const initial = truncateHead(text);
  if (!initial.truncated) {
    return { text, truncated: false };
  }

  const reserved = truncateHead(text, {
    maxBytes: DEFAULT_MAX_BYTES - 256,
    maxLines: DEFAULT_MAX_LINES - 2,
  });
  const notice = `[Output truncated: showing ${reserved.outputLines} of ${reserved.totalLines} lines and ${reserved.outputBytes} of ${reserved.totalBytes} bytes. Full output is retained in tool details.]`;
  const separator = reserved.content ? "\n\n" : "";
  return { text: `${reserved.content}${separator}${notice}`, truncated: true };
}

function errorMessage(result: McpToolResult): string {
  const text = (result.content ?? [])
    .filter((item) => item.type === "text" && typeof item.text === "string")
    .map((item) => item.text)
    .join("\n")
    .trim();
  if (text) {
    return text;
  }
  if (result.structuredContent !== undefined) {
    return JSON.stringify(result.structuredContent);
  }
  return "the MCP server returned an error without a message";
}
