interface CapabilityShape {
  id: string;
  label: string;
  description: string;
  serverToolset: "symbol" | "extended" | "slopcop" | "text" | "nlp";
  toolNames: readonly string[];
}

export const BIFROST_CAPABILITIES = [
  {
    id: "symbols",
    label: "Symbols",
    description: "Navigation, definitions, usages, graphs, and commit analysis",
    serverToolset: "symbol",
    toolNames: [
      "search_symbols",
      "get_symbol_sources",
      "get_summaries",
      "scan_usages_by_location",
      "scan_usages_by_reference",
      "get_definitions_by_location",
      "get_definitions_by_reference",
      "get_type_by_location",
      "rename_symbol",
      "usage_graph",
      "analyze_commit",
    ],
  },
  {
    id: "query",
    label: "Structural queries",
    description: "RQL, CodeQuery, symbol locations, and symbol ancestry",
    serverToolset: "extended",
    toolNames: ["query_code", "get_symbol_locations", "get_symbol_ancestors"],
  },
  {
    id: "files",
    label: "File discovery",
    description: "Filename matching, workspace listings, and related-file ranking",
    serverToolset: "extended",
    toolNames: ["find_filenames", "list_files", "most_relevant_files"],
  },
  {
    id: "quality",
    label: "Code quality",
    description: "Complexity, hotspots, clones, smells, dead code, and secrets",
    serverToolset: "slopcop",
    toolNames: [
      "compute_cyclomatic_complexity",
      "compute_cognitive_complexity",
      "report_comment_density_for_code_unit",
      "report_exception_handling_smells",
      "report_comment_density_for_files",
      "analyze_git_hotspots",
      "report_test_assertion_smells",
      "report_structural_clone_smells",
      "report_long_method_and_god_object_smells",
      "report_dead_code_and_unused_abstraction_smells",
      "report_secret_like_code",
    ],
  },
  {
    id: "git",
    label: "Git history",
    description: "Commit-message search, history, and commit diffs",
    serverToolset: "extended",
    toolNames: ["search_git_commit_messages", "get_git_log", "get_commit_diff"],
  },
  {
    id: "text",
    label: "Text search",
    description: "Raw file reads and regular-expression content search",
    serverToolset: "text",
    toolNames: ["get_file_contents", "search_file_contents", "find_files_containing"],
  },
  {
    id: "transforms",
    label: "JSON and XML",
    description: "jq filters, XML outlines, and XPath selection",
    serverToolset: "extended",
    toolNames: ["jq", "xml_skim", "xml_select"],
  },
  {
    id: "semantic",
    label: "Semantic search",
    description: "Accelerator-backed natural-language search over source code",
    serverToolset: "nlp",
    toolNames: ["semantic_search"],
  },
] as const satisfies readonly CapabilityShape[];

export type BifrostCapability = (typeof BIFROST_CAPABILITIES)[number]["id"];
export type BifrostCapabilityDefinition = (typeof BIFROST_CAPABILITIES)[number];

export const BIFROST_CAPABILITY_IDS: readonly BifrostCapability[] =
  BIFROST_CAPABILITIES.map((capability) => capability.id);

export const DEFAULT_BIFROST_CAPABILITIES: readonly BifrostCapability[] = [
  "symbols",
  "query",
  "files",
];

const CAPABILITIES_BY_ID = new Map<BifrostCapability, BifrostCapabilityDefinition>(
  BIFROST_CAPABILITIES.map((capability) => [capability.id, capability]),
);
const CAPABILITY_BY_TOOL = new Map<string, BifrostCapability>(
  BIFROST_CAPABILITIES.flatMap((capability) =>
    capability.toolNames.map((toolName) => [toolName, capability.id] as const),
  ),
);

export function normalizeCapabilities(values: Iterable<string>): BifrostCapability[] {
  const selected = new Set(values);
  return BIFROST_CAPABILITY_IDS.filter((id) => selected.has(id));
}

export function serverToolsetExpression(capabilities: readonly BifrostCapability[]): string {
  const toolsets = new Set(capabilities.map((id) => CAPABILITIES_BY_ID.get(id)!.serverToolset));
  return ["symbol", "extended", "slopcop", "text", "nlp"]
    .filter((toolset) => toolsets.has(toolset as CapabilityShape["serverToolset"]))
    .join("|");
}

export function capabilityForTool(toolName: string): BifrostCapability | undefined {
  return CAPABILITY_BY_TOOL.get(toolName);
}

export function toolBelongsToSelection(
  toolName: string,
  capabilities: readonly BifrostCapability[],
): boolean {
  const capability = capabilityForTool(toolName);
  return capability !== undefined && capabilities.includes(capability);
}

export function piToolName(mcpToolName: string): string {
  return `bifrost_${mcpToolName}`;
}
