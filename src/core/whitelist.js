'use strict';

class Whitelist {
  constructor() {
    this.patterns = [];
    this.exacts = new Set();
    this.prefixes = [];
  }

  addPattern(regex) {
    this.patterns.push(regex);
  }

  addExact(str) {
    this.exacts.add(str);
  }

  addPrefix(str) {
    this.prefixes.push(str);
  }

  isWhitelisted(payload) {
    if (this.exacts.has(payload)) {
      return true;
    }
    for (const prefix of this.prefixes) {
      if (payload.startsWith(prefix)) {
        return true;
      }
    }
    for (const pattern of this.patterns) {
      if (pattern.test(payload)) {
        return true;
      }
    }
    return false;
  }
}

module.exports = { Whitelist };
