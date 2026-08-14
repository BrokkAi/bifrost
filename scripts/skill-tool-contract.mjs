export function toolInventoryFromMarkdown(markdown) {
  const tools = [];
  const lines = markdown.split(/\r?\n/u);
  for (let index = 0; index < lines.length - 2; index += 1) {
    const header = markdownTableCells(lines[index]);
    const toolColumn = header.indexOf("Tool");
    if (toolColumn < 0 || !isMarkdownTableSeparator(lines[index + 1], header.length)) {
      continue;
    }
    for (index += 2; index < lines.length; index += 1) {
      const cells = markdownTableCells(lines[index]);
      if (cells.length !== header.length) {
        index -= 1;
        break;
      }
      const match = /^`([a-z][a-z0-9_]*)`$/u.exec(cells[toolColumn]);
      if (match) {
        tools.push(match[1]);
      }
    }
  }
  return [...new Set(tools)].sort();
}

export function unavailableSkillTools(skillToolNames, advertisedToolNames) {
  return skillToolNames.filter((name) => !advertisedToolNames.has(name));
}

function markdownTableCells(line) {
  const trimmed = line.trim();
  if (!trimmed.startsWith("|") || !trimmed.endsWith("|")) {
    return [];
  }
  return trimmed.slice(1, -1).split("|").map((cell) => cell.trim());
}

function isMarkdownTableSeparator(line, columnCount) {
  const cells = markdownTableCells(line);
  return cells.length === columnCount && cells.every((cell) => /^:?-{3,}:?$/u.test(cell));
}
