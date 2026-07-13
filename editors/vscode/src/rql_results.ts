import * as vscode from "vscode";
import {
  groupRqlQueryResults,
  RqlQueryFileGroup,
  RqlQueryResultItem,
  RqlQueryResult
} from "./rql_query";

type RqlQueryTreeItem = RqlQueryFileItem | RqlQueryValueItem;

export class RqlQueryResultsProvider implements vscode.TreeDataProvider<RqlQueryTreeItem> {
  private readonly changeEmitter = new vscode.EventEmitter<RqlQueryTreeItem | undefined>();
  private groups: RqlQueryFileGroup[] = [];

  readonly onDidChangeTreeData = this.changeEmitter.event;

  update(response: RqlQueryResult): void {
    this.groups = groupRqlQueryResults(response.results);
    this.changeEmitter.fire(undefined);
  }

  getTreeItem(element: RqlQueryTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: RqlQueryTreeItem): vscode.ProviderResult<RqlQueryTreeItem[]> {
    if (element instanceof RqlQueryFileItem) {
      return element.results.map((result) => new RqlQueryValueItem(result));
    }
    if (element) {
      return [];
    }
    return this.groups.map((group) => new RqlQueryFileItem(group));
  }

  dispose(): void {
    this.changeEmitter.dispose();
  }
}

class RqlQueryFileItem extends vscode.TreeItem {
  constructor(readonly group: RqlQueryFileGroup) {
    super(group.path, vscode.TreeItemCollapsibleState.Expanded);
    this.description = `${group.results.length} ${group.results.length === 1 ? "result" : "results"}`;
    this.iconPath = new vscode.ThemeIcon("file");
  }

  get results(): readonly RqlQueryResultItem[] {
    return this.group.results;
  }
}

class RqlQueryValueItem extends vscode.TreeItem {
  constructor(readonly result: RqlQueryResultItem) {
    super(compactText(resultLabel(result)), vscode.TreeItemCollapsibleState.None);
    this.description = resultDescription(result);
    this.tooltip = new vscode.MarkdownString(resultTooltip(result));
    this.iconPath = new vscode.ThemeIcon(resultIcon(result));
    this.command = {
      command: "bifrost.openRqlQueryResult",
      title: "Open Bifrost Query Result",
      arguments: [result]
    };
  }
}

function resultLabel(result: RqlQueryResultItem): string {
  switch (result.result_type) {
    case "structural_match":
      return result.text;
    case "declaration":
      return result.fq_name;
    case "file":
      return result.path;
  }
}

function resultDescription(result: RqlQueryResultItem): string {
  if (result.result_type === "file") {
    return `file · ${result.language}`;
  }
  return `${result.kind} · ${result.start_line}-${result.end_line}`;
}

function resultTooltip(result: RqlQueryResultItem): string {
  switch (result.result_type) {
    case "structural_match":
      return (
        `**${result.kind}** at ${result.path}:${result.start_line}-${result.end_line}` +
        (result.enclosing_symbol ? `\n\nInside \`${result.enclosing_symbol}\`` : "")
      );
    case "declaration":
      return (
        `**${result.kind}** at ${result.path}:${result.start_line}-${result.end_line}` +
        (result.signature ? `\n\n\`${result.signature}\`` : "")
      );
    case "file":
      return `**file** at ${result.path}\n\nLanguage: ${result.language}`;
  }
}

function resultIcon(result: RqlQueryResultItem): string {
  switch (result.result_type) {
    case "structural_match":
      return "symbol-method";
    case "declaration":
      return "symbol-class";
    case "file":
      return "file-code";
  }
}

function compactText(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}
