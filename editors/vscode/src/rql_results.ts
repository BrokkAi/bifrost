import * as vscode from "vscode";
import {
  groupRqlQueryMatches,
  RqlQueryFileGroup,
  RqlQueryMatch,
  RqlQueryResult
} from "./rql_query";

type RqlQueryTreeItem = RqlQueryFileItem | RqlQueryMatchItem;

export class RqlQueryResultsProvider implements vscode.TreeDataProvider<RqlQueryTreeItem> {
  private readonly changeEmitter = new vscode.EventEmitter<RqlQueryTreeItem | undefined>();
  private groups: RqlQueryFileGroup[] = [];

  readonly onDidChangeTreeData = this.changeEmitter.event;

  update(response: RqlQueryResult): void {
    this.groups = groupRqlQueryMatches(response.matches);
    this.changeEmitter.fire(undefined);
  }

  getTreeItem(element: RqlQueryTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: RqlQueryTreeItem): vscode.ProviderResult<RqlQueryTreeItem[]> {
    if (element instanceof RqlQueryFileItem) {
      return element.matches.map((match) => new RqlQueryMatchItem(match));
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
    this.description = `${group.matches.length} ${group.matches.length === 1 ? "match" : "matches"}`;
    this.iconPath = new vscode.ThemeIcon("file");
  }

  get matches(): readonly RqlQueryMatch[] {
    return this.group.matches;
  }
}

class RqlQueryMatchItem extends vscode.TreeItem {
  constructor(readonly match: RqlQueryMatch) {
    super(compactText(match.text), vscode.TreeItemCollapsibleState.None);
    this.description = `${match.kind} · ${match.startLine}-${match.endLine}`;
    this.tooltip = new vscode.MarkdownString(
      `**${match.kind}** at ${match.path}:${match.startLine}-${match.endLine}` +
        (match.enclosingSymbol ? `\n\nInside \`${match.enclosingSymbol}\`` : "")
    );
    this.iconPath = new vscode.ThemeIcon("symbol-method");
    this.command = {
      command: "bifrost.openRqlQueryMatch",
      title: "Open Bifrost Query Match",
      arguments: [match]
    };
  }
}

function compactText(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}
