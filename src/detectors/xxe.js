'use strict';

module.exports = {
  name: 'xxe',
  label: 'xxe',
  getSignals() {
    return [
      {
        id: 'xml-entity-declaration',
        confidence: 0.85,
        pattern: /<!ENTITY\s+/i
      },
      {
        id: 'xml-system-entity',
        confidence: 0.90,
        pattern: /<!ENTITY\s+[^>]+SYSTEM\s+["'](?:file|http|https|expect):\/\//i
      },
      {
        id: 'xml-public-entity',
        confidence: 0.80,
        pattern: /<!ENTITY\s+[^>]+PUBLIC\s+["']/i
      },
      {
        id: 'xml-parameter-entity',
        confidence: 0.80,
        pattern: /<!ENTITY\s+%\s+[^>]+>/i
      },
      {
        id: 'xml-entity-expansion',
        confidence: 0.85,
        pattern: /<!ENTITY\s+[^>]+>\s*<!ENTITY\s+[^>]+&(?:[a-zA-Z0-9_]+);/i
      },
      {
        id: 'xml-doctype',
        confidence: 0.50,
        pattern: /<!DOCTYPE\s+/i
      },
      {
        id: 'xml-cdata-injection',
        confidence: 0.60,
        pattern: /<!\[CDATA\[.*(?:<script|javascript:|on[a-z]+(?:=>|=)).*]]>/i
      }
    ];
  }
};
