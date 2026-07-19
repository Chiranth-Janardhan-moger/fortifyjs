'use strict';

module.exports = {
  name: 'prototype-pollution',
  label: 'prototype-pollution',
  
  detectObject(obj, maxDepth = 20) {
    const signals = [];
    if (!obj || typeof obj !== 'object') return signals;
    
    function walk(node, depth) {
      if (depth > maxDepth) return;
      if (!node || typeof node !== 'object') return;
      
      if (Array.isArray(node)) {
        for (const item of node) {
          walk(item, depth + 1);
        }
        return;
      }
      
      for (const key of Object.keys(node)) {
        if (key === '__proto__') {
          signals.push({ id: 'proto-key', confidence: 0.90, label: 'prototype-pollution' });
        } else if (key === 'constructor') {
          signals.push({ id: 'constructor-key', confidence: 0.70, label: 'prototype-pollution' });
        }
        walk(node[key], depth + 1);
      }
    }
    
    walk(obj, 0);
    return signals;
  },

  getSignals() {
    return [
      {
        id: 'proto-key',
        confidence: 0.90,
        pattern: /"__proto__"\s*:/
      },
      {
        id: 'constructor-prototype',
        confidence: 0.85,
        pattern: /constructor\.prototype/
      },
      {
        id: 'constructor-key',
        confidence: 0.70,
        pattern: /"constructor"\s*:/
      },
      {
        id: 'proto-in-url',
        confidence: 0.80,
        pattern: /(?:\?|&)[^=]*__proto__/
      },
      {
        id: 'prototype-in-brackets',
        confidence: 0.80,
        pattern: /\[(?:'|")?__proto__(?:'|")?\]|\[(?:'|")?constructor(?:'|")?\]\s*\[(?:'|")?prototype(?:'|")?\]/
      }
    ];
  }
};
