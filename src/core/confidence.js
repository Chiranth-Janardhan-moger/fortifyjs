'use strict';

function matchSignals(variants, signalDefinitions, label) {
    const matchesById = new Map();
    for (const variant of variants) {
      for (const signal of signalDefinitions) {
        const matched = signal.pattern ? signal.pattern.test(variant) : signal.test(variant);
        if (!matched || matchesById.has(signal.id)) continue;
        matchesById.set(signal.id, {
          id: signal.id,
          label,
          confidence: signal.confidence
        });
      }
    }
    return [...matchesById.values()];
}

function combineConfidence(matches) {
    return matches.reduce((total, match) => total + match.confidence * (1 - total), 0);
}

module.exports = { matchSignals, combineConfidence };
