import * as vscode from "vscode";
import type {
  RqlQueryFileGroup,
  RqlQueryResultItem,
  RqlQueryResult,
  RqlTypestateWitnessStepTarget
} from "./rql_query";
import {
  groupRqlQueryResults,
  flowWitnessStepTargets,
  queryResultDescription,
  queryResultIcon,
  queryResultLabel,
  queryResultTooltip,
  typestateWitnessStepTargets
} from "./rql_query";

type RqlQueryTreeItem = RqlQueryFileItem | RqlQueryValueItem | RqlQueryWitnessStepItem;

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
    if (
      element instanceof RqlQueryValueItem &&
      element.result.result_type === "typestate_witness"
    ) {
      return typestateWitnessStepTargets(element.result).map(
        (target) => new RqlQueryWitnessStepItem(target)
      );
    }
    if (element instanceof RqlQueryValueItem && element.result.result_type === "flow_witness") {
      return flowWitnessStepTargets(element.result).map(
        (target) => new RqlQueryWitnessStepItem(target)
      );
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
    super(
      compactText(queryResultLabel(result)),
      (result.result_type === "typestate_witness" || result.result_type === "flow_witness") &&
        result.steps.length > 0
        ? vscode.TreeItemCollapsibleState.Collapsed
        : vscode.TreeItemCollapsibleState.None
    );
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

class RqlQueryWitnessStepItem extends vscode.TreeItem {
  constructor(readonly target: RqlTypestateWitnessStepTarget) {
    super(compactText(target.label), vscode.TreeItemCollapsibleState.None);
    this.description = target.description;
    this.tooltip = new vscode.MarkdownString(target.tooltip);
    this.iconPath = new vscode.ThemeIcon("debug-breakpoint");
    this.command = {
      command: "bifrost.openRqlQueryResult",
      title: "Open Bifrost Typestate Witness Step",
      arguments: [target]
    };
  }
}

function compactText(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}
