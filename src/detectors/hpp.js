'use strict';

module.exports = {
  name: 'hpp',
  label: 'hpp',

  detectQuery(query, allowedArrayParams = []) {
    const signals = [];
    if (!query || typeof query !== 'object') return signals;
    
    for (const [key, value] of Object.entries(query)) {
      if (Array.isArray(value) && !allowedArrayParams.includes(key)) {
        signals.push({
          id: 'array-param-unexpected',
          confidence: 0.55,
          label: 'hpp'
        });
        
        signals.push({
          id: 'duplicate-query-param',
          confidence: 0.60,
          label: 'hpp'
        });
      }
    }
    return signals;
  },

  getSignals() {
    return [
      {
        id: 'duplicate-query-param-string',
        confidence: 0.60,
        pattern: /(?:\?|&)([^=&]+)=.*&\1=/
      }
    ];
  }
};
