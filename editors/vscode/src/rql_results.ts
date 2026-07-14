import * as vscode from "vscode";
import {
  groupRqlQueryResults,
  queryResultDescription,
  queryResultIcon,
  queryResultLabel,
  queryResultTooltip,
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
    super(compactText(queryResultLabel(result)), vscode.TreeItemCollapsibleState.None);
    this.description = queryResultDescription(result);
    this.tooltip = new vscode.MarkdownString(queryResultTooltip(result));
    this.iconPath = new vscode.ThemeIcon(queryResultIcon(result));
    this.command = {
      command: "bifrost.openRqlQueryResult",
      title: "Open Bifrost Query Result",
      arguments: [result]
    };
  }
}

function compactText(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}
