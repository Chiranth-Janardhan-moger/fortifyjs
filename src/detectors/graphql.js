'use strict';

function hasDeepNesting(value) {
  let depth = 0;
  let maxDepth = 0;
  for (let i = 0; i < value.length; i++) {
    if (value[i] === '{') {
      depth++;
      if (depth > maxDepth) maxDepth = depth;
    } else if (value[i] === '}') {
      depth--;
    }
  }
  return maxDepth > 10;
}

function hasAliasBatching(value) {
  const aliasPattern = /[a-zA-Z_][a-zA-Z0-9_]*\s*:\s*[a-zA-Z_][a-zA-Z0-9_]*/g;
  const matches = value.match(aliasPattern);
  return matches !== null && matches.length >= 100;
}

function hasFragmentSpreadAbuse(value) {
  const spreadPattern = /\.\.\.[a-zA-Z0-9_]+/g;
  const matches = value.match(spreadPattern);
  return matches !== null && matches.length >= 10;
}

module.exports = {
  name: 'graphql',
  label: 'graphql',
  getSignals() {
    return [
      {
        id: 'graphql-introspection',
        confidence: 0.9,
        pattern: /\b(__schema|__type)\b/i
      },
      {
        id: 'graphql-deep-nesting',
        confidence: 0.8,
        test: hasDeepNesting
      },
      {
        id: 'graphql-alias-batching',
        confidence: 0.85,
        test: hasAliasBatching
      },
      {
        id: 'graphql-fragment-spread-abuse',
        confidence: 0.7,
        test: hasFragmentSpreadAbuse
      }
    ];
  }
};
