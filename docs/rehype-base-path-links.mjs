function normalizeBase(base) {
  if (!base || base === '/') return '/';

  return `/${base.replace(/^\/+|\/+$/g, '')}`;
}

function prefixBasePath(value, base) {
  if (
    typeof value !== 'string' ||
    base === '/' ||
    !value.startsWith('/') ||
    value.startsWith('//') ||
    value === base ||
    value.startsWith(`${base}/`)
  ) {
    return value;
  }

  return `${base}${value}`;
}

/**
 * Make root-relative links in Markdown and MDX respect Astro's deployment base.
 *
 * Authors can use stable site-root URLs such as `/install/`. Local development
 * keeps `/` as its base, while production and versioned builds transparently
 * emit `/bifrost/...` or `/bifrost/versions/<tag>/...` URLs.
 */
export default function rehypeBasePathLinks(options = {}) {
  const base = normalizeBase(options.base);

  return (tree) => {
    const stack = [tree];

    while (stack.length > 0) {
      const node = stack.pop();
      if (!node || typeof node !== 'object') continue;

      if (node.properties) {
        for (const property of ['href', 'src']) {
          node.properties[property] = prefixBasePath(node.properties[property], base);
        }

        if (typeof node.properties.srcSet === 'string') {
          node.properties.srcSet = node.properties.srcSet
            .split(',')
            .map((candidate) => {
              const match = candidate.trim().match(/^(\S+)(\s+.*)?$/);
              if (!match) return candidate;
              return `${prefixBasePath(match[1], base)}${match[2] ?? ''}`;
            })
            .join(', ');
        }
      }

      if (Array.isArray(node.children)) stack.push(...node.children);
    }
  };
}

export { normalizeBase, prefixBasePath };
